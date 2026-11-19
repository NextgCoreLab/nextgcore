//! #1876: the AMF's Network Slice Admission Control counts, out as well as in.
//!
//! TS 23.502 §4.2.11.2: the AMF counts a UE in at the NSACF
//! (Nnsacf_NSAC_NumOfUEsUpdate, INCREASE) for each S-NSSAI subject to NSAC when it
//! accepts the UE's registration on it, and counts it out (DECREASE) when the UE
//! deregisters or the S-NSSAI is removed from its Allowed NSSAI. amfd only ever sent
//! the INCREASE, so every deregistration left the UE counted and the slice's maximum
//! number of UEs filled up for good; and a registration denied on a later S-NSSAI
//! kept the earlier S-NSSAIs' grants for a UE that was rejected.
//!
//! What this module holds:
//!
//! - **The admissions** the NSACF granted, keyed by (SUPI, access type, S-NSSAI),
//!   each with the NSACF that granted it and the nfId it was granted to, so the
//!   DECREASE goes to the same place under the same identity. Only an admission
//!   the NSACF actually answered is recorded: an INCREASE that degraded open
//!   because no NSACF answered counted nothing, so there is nothing to undo (one
//!   that got no answer at all is reconciled with a precautionary DECREASE, as
//!   smfd does).
//! - **The reconciler** for a DECREASE that fails: parked and retried every
//!   [`RECONCILE_PERIOD`] until the NSACF accepts it, the shape of smfd's #1875 and
//!   #1817's reconcilers. Bounded at [`MAX_PENDING`] (the oldest is evicted, counted
//!   `abandoned`); a pass sends for at most [`MAX_PASS`]. A parked DECREASE whose
//!   (SUPI, access type, S-NSSAI) has been admitted again since is `superseded` and
//!   not sent: the NSACF counts a UE once, so it would count the live registration
//!   out. No NSACF starves the others (#1961, the #1954 / #1972 pattern): once a
//!   DECREASE to an NSACF fails it backs off ([`BACKOFF_BASE`], doubling to
//!   [`BACKOFF_MAX`]) and its other DECREASEs wait, in this pass and later ones; one
//!   tried and failed goes to the BACK of the queue, one not reached keeps its place
//!   at the front; one parked longer than [`MAX_AGE`] ends as `expired`.
//!
//! Ceiling: memory-only. amfd has no durable store for its UE contexts either, so a
//! restart forgets both the registrations and the DECREASEs they owe; the NSACF's
//! own supervision of its UE lists is what covers that case.

use crate::context::SNssai;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Records parked before the oldest is abandoned.
pub const MAX_PENDING: usize = 4096;

/// How often the parked DECREASEs are retried.
#[cfg(not(test))]
pub const RECONCILE_PERIOD: Duration = Duration::from_secs(30);
#[cfg(test)]
pub const RECONCILE_PERIOD: Duration = Duration::from_millis(20);

/// The longest one pass sends for.
#[cfg(not(test))]
pub const MAX_PASS: Duration = Duration::from_secs(30);
#[cfg(test)]
pub const MAX_PASS: Duration = Duration::from_secs(2);

/// One UE's admission on one S-NSSAI, as the NSACF granted it.
#[derive(Debug, Clone, PartialEq)]
pub struct Admission {
    pub supi: String,
    /// `3GPP_ACCESS` or `NON_3GPP_ACCESS` (TS 29.571 AccessType).
    pub access_type: String,
    pub snssai: SNssai,
    /// The nfId the INCREASE carried.
    pub nf_id: String,
    /// The NSACF that granted it.
    pub nsacf_host: String,
    pub nsacf_port: u16,
}

type Key = (String, String, u8, Option<u32>);

fn key_of(supi: &str, access_type: &str, snssai: &SNssai) -> Key {
    (
        supi.to_string(),
        access_type.to_string(),
        snssai.sst,
        snssai.sd,
    )
}

/// The admissions held now.
///
/// Tests that read or write it, or [`pending`], hold [`NSAC_TEST_LOCK`], declared
/// beside them.
fn admissions() -> &'static Mutex<HashMap<Key, Admission>> {
    static ADMISSIONS: std::sync::LazyLock<Mutex<HashMap<Key, Admission>>> =
        std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));
    &ADMISSIONS
}

/// R27 #1940: the DECREASEs on the wire and the INCREASEs being decided, per key.
/// Read and written only with [`admissions`] locked first, so a DECREASE's check
/// ("is the key admitted, or being admitted?") and its registration as in flight
/// are one step against an INCREASE's registration and its look for one in flight.
#[derive(Default)]
struct Ops {
    /// DECREASEs registered before their check and still on the wire.
    in_flight: HashMap<Key, Vec<Arc<Flight>>>,
    /// INCREASEs being decided, with the DECREASEs they superseded: those are
    /// owed again unless one of them ends up counting the UE at that NSACF.
    admitting: HashMap<Key, Admitting>,
}

/// #2036: the INCREASEs (and re-counts) of one key being decided. Overlapping
/// ones share the entry; each holds it through an [`AdmittingSlot`], and the
/// last to leave settles what is owed.
#[derive(Default)]
struct Admitting {
    /// How many INCREASEs of the key are being decided.
    deciding: usize,
    /// The DECREASEs superseded meanwhile.
    owed: Vec<Admission>,
    /// The NSACFs at which a settled INCREASE of the entry counted the UE.
    counted_at: Vec<(String, u16)>,
}

/// #2036: one INCREASE's hold on its key's [`Admitting`] entry. Settled when its
/// answer is in; dropped unsettled (the task panicked, or was cancelled, as at a
/// shutdown) it still leaves the entry, so later DECREASEs of the key are not
/// swallowed for good, and it parks what is owed: the superseded DECREASEs and,
/// for an INCREASE, a precautionary DECREASE of its own admission (it may have
/// landed; a DECREASE of a UE the NSACF does not hold is a no-op, and one of a key
/// admitted again is superseded).
struct AdmittingSlot {
    key: Key,
    own: Option<Admission>,
    settled: bool,
}

impl AdmittingSlot {
    /// Hold `key`'s entry. The caller holds the admissions lock, then `ops`.
    fn enter(ops: &mut Ops, key: &Key, own: Option<Admission>) -> Self {
        ops.admitting.entry(key.clone()).or_default().deciding += 1;
        Self {
            key: key.clone(),
            own,
            settled: false,
        }
    }

    /// The INCREASE is settled, having counted the UE at `counted_at` or not.
    /// Returns the DECREASEs owed now: none while another INCREASE of the key is
    /// still being decided; once the last one leaves, every superseded DECREASE
    /// except those at an NSACF where one of them counted the UE.
    fn settle(mut self, counted_at: Option<(String, u16)>) -> Vec<Admission> {
        self.settled = true;
        let _admitted = lock(admissions());
        leave(&mut lock(ops()), &self.key, counted_at)
    }
}

impl Drop for AdmittingSlot {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        let owed = {
            let _admitted = lock(admissions());
            leave(&mut lock(ops()), &self.key, None)
        };
        log::warn!(
            "NSAC admission of {:?} ended unsettled (a panic or a shutdown); parking \
             {} owed DECREASE(s)",
            self.key,
            owed.len() + usize::from(self.own.is_some())
        );
        for a in owed.into_iter().chain(self.own.take()) {
            park(a);
        }
    }
}

/// Leave `key`'s entry; see [`AdmittingSlot::settle`].
fn leave(ops: &mut Ops, key: &Key, counted_at: Option<(String, u16)>) -> Vec<Admission> {
    let Some(entry) = ops.admitting.get_mut(key) else {
        return Vec::new();
    };
    entry.counted_at.extend(counted_at);
    entry.deciding = entry.deciding.saturating_sub(1);
    if entry.deciding > 0 {
        return Vec::new();
    }
    let entry = ops.admitting.remove(key).unwrap_or_default();
    entry
        .owed
        .into_iter()
        .filter(|old| {
            !entry
                .counted_at
                .iter()
                .any(|(host, port)| *host == old.nsacf_host && *port == old.nsacf_port)
        })
        .collect()
}

/// One DECREASE on the wire, which an INCREASE for its key waits for.
#[derive(Default)]
struct Flight {
    done: std::sync::atomic::AtomicBool,
    changed: tokio::sync::Notify,
    /// #1945: an INCREASE for the key stopped waiting for this DECREASE and was
    /// sent anyway, so the NSACF may apply this DECREASE after it.
    overtaken: std::sync::atomic::AtomicBool,
}

impl Flight {
    fn finish(&self) {
        self.done.store(true, std::sync::atomic::Ordering::SeqCst);
        self.changed.notify_waiters();
    }

    /// Wait for this DECREASE until `until`. Gave up: marked overtaken, so the
    /// DECREASE re-counts the key when it lands (#1945).
    async fn wait(&self, until: tokio::time::Instant) {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.done.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            if tokio::time::timeout_at(until, notified).await.is_err() {
                self.overtaken
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                return;
            }
        }
    }
}

fn ops() -> &'static Mutex<Ops> {
    static OPS: std::sync::LazyLock<Mutex<Ops>> = std::sync::LazyLock::new(Default::default);
    &OPS
}

/// How long a DECREASE may take to connect, then to be answered (#1945): its own
/// client is bounded by these, rather than by the SBI client's 30 s default, so
/// the INCREASE's wait below covers it.
pub const DECREASE_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
pub const DECREASE_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// #2005 (R32 on #2002): the whole DECREASE call, its OAuth2 token fetch
/// included, finishes within this, so an INCREASE's [`DECREASE_WAIT`] covers it.
pub const DECREASE_BOUND: Duration =
    Duration::from_secs(DECREASE_CONNECT_TIMEOUT.as_secs() + DECREASE_REQUEST_TIMEOUT.as_secs());

/// The longest an INCREASE waits for a DECREASE of its key on the wire. #1945: it
/// covers the DECREASE's own bound (connect, then request), so in the ordinary
/// case the DECREASE has landed or given up before the INCREASE goes. A DECREASE
/// the NSACF still applies after that (it got the request and was slow) is caught
/// by the overtaken re-count in [`decrease_once`].
#[cfg(not(test))]
const DECREASE_WAIT: Duration = Duration::from_secs(10);
#[cfg(test)]
const DECREASE_WAIT: Duration = Duration::from_secs(1);

#[cfg(not(test))]
const _: () = assert!(
    DECREASE_WAIT.as_millis() > DECREASE_BOUND.as_millis(),
    "an INCREASE's wait must cover a DECREASE's own timeout (#1945)"
);

/// The parked DECREASEs, oldest first.
fn pending() -> &'static Mutex<VecDeque<Parked>> {
    static PENDING: Mutex<VecDeque<Parked>> = Mutex::new(VecDeque::new());
    &PENDING
}

/// One parked DECREASE, and when it was first parked (#1961).
#[derive(Debug, Clone)]
struct Parked {
    a: Admission,
    /// Wall-clock, so a test can set it back past [`MAX_AGE`].
    since: std::time::SystemTime,
}

/// #1961: how long an entry stays parked before it is given up (`expired`): a
/// peer that has not answered for a day is gone (decommissioned), not
/// restarting, so its entries end rather than wait to be evicted.
pub const MAX_AGE: Duration = Duration::from_secs(24 * 3600);

/// #1961 (the #1954 / #1972 pattern): the first wait before a peer whose
/// request failed is tried again, doubled after each further failure up to
/// [`BACKOFF_MAX`], and cleared by a success. A peer that is backing off is
/// skipped for the rest of the pass and for later passes until its wait ends,
/// so a blackholed peer costs one request timeout per backoff period and
/// cannot starve the entries for healthy peers behind it.
#[cfg(not(test))]
pub const BACKOFF_BASE: Duration = Duration::from_secs(30);
#[cfg(test)]
pub const BACKOFF_BASE: Duration = Duration::from_millis(300);
/// The longest a failing peer is left alone between attempts.
pub const BACKOFF_MAX: Duration = Duration::from_secs(600);

type Backoff = std::collections::HashMap<String, (tokio::time::Instant, Duration)>;

/// Per peer: when it may next be tried, and the current backoff.
fn backoff() -> &'static Mutex<Backoff> {
    static BACKOFF: std::sync::LazyLock<Mutex<Backoff>> =
        std::sync::LazyLock::new(Default::default);
    &BACKOFF
}

fn backing_off(peer: &str) -> bool {
    backoff()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(peer)
        .is_some_and(|(next, _)| tokio::time::Instant::now() < *next)
}

fn note_failure(peer: &str) {
    let mut map = backoff().lock().unwrap_or_else(|e| e.into_inner());
    let wait = map
        .get(peer)
        .map_or(BACKOFF_BASE, |(_, current)| (*current * 2).min(BACKOFF_MAX));
    map.insert(peer.to_string(), (tokio::time::Instant::now() + wait, wait));
}

fn note_success(peer: &str) {
    backoff()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(peer);
}

/// The peer a DECREASE goes to: the NSACF that granted the admission.
fn peer_of(a: &Admission) -> String {
    format!("{}:{}", a.nsacf_host, a.nsacf_port)
}

/// Serialises the tests that touch [`admissions`] and [`pending`]: one test's
/// deregistration would otherwise count out, or reconcile, another's admission.
#[cfg(test)]
pub static NSAC_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `amf_nsac_ue_decreases_total{result}`: DECREASEs sent at once, by outcome.
pub static DECREASES: nextgcore_metrics::nf::CounterFamily =
    nextgcore_metrics::nf::CounterFamily::new(
        "amf_nsac_ue_decreases_total",
        "Nnsacf_NSAC_NumOfUEsUpdate DECREASEs sent on deregistration, S-NSSAI removal or a \
         denied registration's rollback, by outcome (accepted, refused, failed = parked, superseded = admitted again)",
        &["result"],
    );

/// `amf_nsac_ue_recounts_total`: INCREASEs re-sent because a DECREASE of the same
/// key landed after a re-registration's INCREASE (#1945).
pub static RECOUNTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// `amf_nsac_ue_decreases_reconciled_total{result}`: parked DECREASEs the
/// reconciler ended: `delivered`, `superseded` (admitted again since), `refused`
/// (a 4xx a retry cannot change), `abandoned` (evicted at the bound) or `expired`
/// (parked longer than [`MAX_AGE`], #1961).
pub static RECONCILED: nextgcore_metrics::nf::CounterFamily =
    nextgcore_metrics::nf::CounterFamily::new(
        "amf_nsac_ue_decreases_reconciled_total",
        "Parked Nnsacf_NSAC_NumOfUEsUpdate DECREASEs, by how the reconciler ended them",
        &["result"],
    );

fn lock<T>(m: &'static Mutex<T>) -> std::sync::MutexGuard<'static, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Record an admission the NSACF granted.
pub fn record(admission: Admission) {
    let key = key_of(&admission.supi, &admission.access_type, &admission.snssai);
    lock(admissions()).insert(key, admission);
}

/// Whether (SUPI, access type, S-NSSAI) is admitted now.
pub fn is_admitted(supi: &str, access_type: &str, snssai: &SNssai) -> bool {
    lock(admissions()).contains_key(&key_of(supi, access_type, snssai))
}

/// Take the UE's admissions on `access_type` that are NOT in `keep`, so they can be
/// counted out: every one for a deregistration or a rejection (`keep` empty), the
/// removed S-NSSAIs for a registration whose Allowed NSSAI shrank.
pub fn take(supi: &str, access_type: &str, keep: &[SNssai]) -> Vec<Admission> {
    let mut map = lock(admissions());
    let gone: Vec<Key> = map
        .iter()
        .filter(|(_, a)| {
            a.supi == supi && a.access_type == access_type && !keep.contains(&a.snssai)
        })
        .map(|(k, _)| k.clone())
        .collect();
    gone.into_iter().filter_map(|k| map.remove(&k)).collect()
}

/// What [`admit_registration`] decided.
#[derive(Debug, Clone, PartialEq)]
pub struct Admitted {
    /// Whether any S-NSSAI was admitted (`AmfUe::slice_admission_granted`).
    pub granted: bool,
    /// #1942: the S-NSSAIs the NSACF denied (maximum number of UEs reached), or
    /// whose admission could not be performed. They are rejected, the rest of the
    /// registration goes on (TS 23.502 §4.2.11.2, TS 24.501 §5.5.1.2.4); only when
    /// every one is rejected is the registration.
    pub rejected: Vec<SNssai>,
}

impl Admitted {
    /// Every S-NSSAI of `allowed` was rejected: the registration is.
    pub fn all_rejected(&self, allowed: &[SNssai]) -> bool {
        allowed.iter().all(|s| self.rejected.contains(s))
    }
}

/// Count a registering UE in at the NSACF on each S-NSSAI of `allowed`, in order
/// (TS 23.502 §4.2.11.2, TS 29.536 §5.2.2.2). #1942: a denial rejects that
/// S-NSSAI only; the others are still asked for.
///
/// #1876:
/// - each count the NSACF took is [`record`]ed, so a deregistration undoes it;
/// - an INCREASE that got no answer at all is reconciled with a precautionary
///   DECREASE, not parked (a DECREASE of a UE the NSACF does not hold is a no-op);
/// - when every S-NSSAI is rejected the UE is, so EVERY admission it holds on this
///   access is counted out again;
/// - otherwise an S-NSSAI it held and no longer has in its Allowed NSSAI (`allowed`
///   less the rejected ones) is counted out ("removed from the Allowed NSSAI").
pub async fn admit_registration(
    supi: &str,
    access_type: &str,
    allowed: &[SNssai],
    nsacf_host: &str,
    nsacf_port: u16,
    nf_id: &str,
) -> Admitted {
    let mut granted = false;
    let mut rejected = Vec::new();
    let mut unanswered = Vec::new();
    for snssai in allowed {
        let admission = Admission {
            supi: supi.to_string(),
            access_type: access_type.to_string(),
            snssai: snssai.clone(),
            nf_id: nf_id.to_string(),
            nsacf_host: nsacf_host.to_string(),
            nsacf_port,
        };
        // R27 #1940: registered as being admitted BEFORE looking for a DECREASE of
        // the key on the wire, under the admissions lock a DECREASE checks under. A
        // DECREASE that registered first is waited for (so it lands before this
        // INCREASE); one that checks after sees this one and is superseded, its
        // count handed to this INCREASE.
        let key = key_of(supi, access_type, snssai);
        let (slot, flights) = {
            let _admitted = lock(admissions());
            let mut ops = lock(ops());
            let slot = AdmittingSlot::enter(&mut ops, &key, Some(admission.clone()));
            (slot, ops.in_flight.get(&key).cloned().unwrap_or_default())
        };
        let until = tokio::time::Instant::now() + DECREASE_WAIT;
        for f in flights {
            f.wait(until).await;
        }
        let answer = crate::sbi_path::call_nsacf_ue_admission(
            nsacf_host,
            nsacf_port,
            nf_id,
            supi,
            snssai.sst,
            snssai.sd,
            access_type,
            true,
        )
        .await;
        // The DECREASEs superseded while this INCREASE was out: still owed unless
        // it (or an overlapping one, #2036) counts the UE at the same NSACF (it
        // counts a UE once).
        let counted_here = matches!(&answer, Ok(res) if res.counted);
        spawn_decreases(
            slot.settle(counted_here.then(|| (admission.nsacf_host.clone(), admission.nsacf_port))),
        );
        match answer {
            Ok(res) => {
                granted |= res.admitted;
                if res.counted {
                    record(admission);
                } else if res.unanswered {
                    unanswered.push(admission);
                }
                if !res.admitted {
                    rejected.push(snssai.clone());
                }
            }
            Err(e) => {
                // TS 23.501 §5.15.11: admission control could not be performed, so
                // the slice is treated as not admitted rather than over quota.
                log::error!(
                    "[{supi}] NSACF UE admission query failed for SST={}: {e}",
                    snssai.sst
                );
                rejected.push(snssai.clone());
            }
        }
    }
    for a in unanswered {
        // R27 #1940: through the same check-and-send as every DECREASE, so a next
        // registration's INCREASE neither overtakes it nor is counted out by it.
        // Not parked: it reconciles an INCREASE that may never have landed.
        tokio::spawn(async move {
            let _ = decrease_once(a).await;
        });
    }
    let kept: Vec<SNssai> = allowed
        .iter()
        .filter(|s| !rejected.contains(s))
        .cloned()
        .collect();
    spawn_decreases(take(supi, access_type, &kept));
    Admitted { granted, rejected }
}

/// How a DECREASE ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// 2xx, or 404 (the NSACF does not hold the UE).
    Accepted,
    /// A 4xx a retry cannot change.
    Refused,
    /// No answer, a 5xx, or a refused token: worth retrying.
    Failed,
    /// Not sent: the key is admitted again, or being admitted (its INCREASE takes
    /// the count over, and owes this DECREASE back if it does not count the UE).
    Superseded,
}

/// R27 #1940: one DECREASE, its check and its send atomic against an INCREASE for
/// the same key. Registered as in flight under the admissions lock, in the same
/// step as the check, and finished when the NSACF answers; nothing is parked.
async fn decrease_once(a: Admission) -> Outcome {
    let key = key_of(&a.supi, &a.access_type, &a.snssai);
    let flight = {
        let admitted = lock(admissions());
        let mut ops = lock(ops());
        if admitted.contains_key(&key) {
            return Outcome::Superseded;
        }
        if let Some(entry) = ops.admitting.get_mut(&key) {
            entry.owed.push(a);
            return Outcome::Superseded;
        }
        let flight = Arc::new(Flight::default());
        ops.in_flight
            .entry(key.clone())
            .or_default()
            .push(flight.clone());
        flight
    };
    let outcome = send(&a).await;
    {
        let mut ops = lock(ops());
        if let Some(list) = ops.in_flight.get_mut(&key) {
            list.retain(|f| !Arc::ptr_eq(f, &flight));
            if list.is_empty() {
                ops.in_flight.remove(&key);
            }
        }
    }
    flight.finish();
    // #1945: an INCREASE for the key went before this DECREASE landed, so the NSACF
    // may have applied this one last and counted the re-registered UE out. Once the
    // INCREASE is settled, a key admitted again is counted in once more (an INCREASE
    // of a UE the NSACF holds is idempotent).
    if outcome != Outcome::Failed && flight.overtaken.load(std::sync::atomic::Ordering::SeqCst) {
        spawn_recount(key);
    }
    outcome
}

/// #1945: once no INCREASE for `key` is being decided (bounded), re-send the
/// INCREASE for its live admission, if it has one.
fn spawn_recount(key: Key) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    handle.spawn(async move {
        let deadline = tokio::time::Instant::now() + DECREASE_WAIT + DECREASE_REQUEST_TIMEOUT;
        while lock(ops()).admitting.contains_key(&key) && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // #2005 (R32 on #2002): the re-count is an INCREASE like any other, so it
        // registers as being admitted under the admissions lock, in the same step
        // as reading the live admission. A deregistration in the window then
        // finds it, and its DECREASE is handed to the re-count and sent once the
        // re-count's INCREASE is settled, instead of possibly landing first and
        // leaving the NSACF counting a UE the AMF has already dropped.
        let (live, slot, flights) = {
            let admitted = lock(admissions());
            let Some(live) = admitted.get(&key).cloned() else {
                return;
            };
            let mut ops = lock(ops());
            if ops.admitting.contains_key(&key) {
                // Another INCREASE of the key is being decided: it counts the UE.
                return;
            }
            let slot = AdmittingSlot::enter(&mut ops, &key, None);
            (
                live,
                slot,
                ops.in_flight.get(&key).cloned().unwrap_or_default(),
            )
        };
        let until = tokio::time::Instant::now() + DECREASE_WAIT;
        for f in flights {
            f.wait(until).await;
        }
        log::warn!(
            "[{}] NSACF DECREASE for SST={} SD={:?} may have landed after its \
             re-registration's INCREASE; counting the UE in again",
            live.supi,
            live.snssai.sst,
            live.snssai.sd
        );
        RECOUNTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let _ = crate::sbi_path::call_nsacf_ue_admission(
            &live.nsacf_host,
            live.nsacf_port,
            &live.nf_id,
            &live.supi,
            live.snssai.sst,
            live.snssai.sd,
            &live.access_type,
            true,
        )
        .await;
        // The DECREASEs superseded while the re-count was out (the UE
        // deregistered, or its S-NSSAI was removed): the re-count does not own
        // the admission, so every one is still owed and is sent now, after it.
        spawn_decreases(slot.settle(None));
    });
}

/// Count `admissions` out, off the caller's path; a failure is parked.
pub fn spawn_decreases(admissions: Vec<Admission>) {
    if admissions.is_empty() {
        return;
    }
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        for a in admissions {
            park(a);
        }
        return;
    };
    handle.spawn(async move {
        for a in admissions {
            decrease_now(a).await;
        }
    });
}

/// One DECREASE now, parked on failure. Not sent when the slice has been admitted
/// for the UE again meanwhile (it would count the live registration out).
pub async fn decrease_now(a: Admission) -> Outcome {
    let outcome = decrease_once(a.clone()).await;
    let label = match outcome {
        Outcome::Accepted => "accepted",
        Outcome::Refused => "refused",
        Outcome::Failed => "failed",
        Outcome::Superseded => "superseded",
    };
    DECREASES.inc(&[label]);
    if outcome == Outcome::Failed {
        park(a);
    }
    outcome
}

async fn send(a: &Admission) -> Outcome {
    crate::sbi_path::call_nsacf_ue_decrease(
        &a.nsacf_host,
        a.nsacf_port,
        &a.nf_id,
        &a.supi,
        a.snssai.sst,
        a.snssai.sd,
        &a.access_type,
    )
    .await
}

fn evict(set: &mut VecDeque<Parked>) {
    while set.len() > MAX_PENDING {
        if let Some(Parked { a: old, .. }) = set.pop_front() {
            log::error!(
                "[{}] NSACF DECREASE for SST={} SD={:?} abandoned: {MAX_PENDING} are already \
                 pending; the UE stays counted at the NSACF",
                old.supi,
                old.snssai.sst,
                old.snssai.sd
            );
            RECONCILED.inc(&["abandoned"]);
        }
    }
}

/// Park a DECREASE that failed. One already parked is not parked twice.
pub fn park(a: Admission) {
    let mut set = lock(pending());
    if set.iter().any(|p| p.a == a) {
        return;
    }
    log::warn!(
        "[{}] NSACF DECREASE for SST={} SD={:?} failed; parked, retried every \
         {RECONCILE_PERIOD:?}",
        a.supi,
        a.snssai.sst,
        a.snssai.sd
    );
    set.push_back(Parked {
        a,
        since: std::time::SystemTime::now(),
    });
    evict(&mut set);
}

/// How many DECREASEs are parked.
pub fn pending_count() -> usize {
    lock(pending()).len()
}

/// The parked DECREASEs, for tests.
#[cfg(test)]
pub fn parked() -> Vec<Admission> {
    lock(pending()).iter().map(|p| p.a.clone()).collect()
}

/// One reconcile pass over the parked DECREASEs, oldest first, for at most
/// [`MAX_PASS`]. One older than [`MAX_AGE`] ends as `expired`.
///
/// #1961: once a DECREASE to an NSACF fails, that NSACF backs off and its other
/// DECREASEs are not tried this pass (nor until the backoff ends); one tried and
/// failed goes to the BACK of the queue, one not reached keeps its place at the
/// FRONT. Returns how many ended.
pub async fn reconcile_once() -> usize {
    let batch: Vec<Parked> = lock(pending()).drain(..).collect();
    let deadline = tokio::time::Instant::now() + MAX_PASS;
    let mut ended = 0;
    let mut untried = Vec::new();
    let mut failed = Vec::new();
    for p in batch {
        let a = &p.a;
        if p.since.elapsed().unwrap_or_default() > MAX_AGE {
            log::error!(
                "[{}] parked NSACF DECREASE for SST={} SD={:?} expired after {MAX_AGE:?}",
                a.supi,
                a.snssai.sst,
                a.snssai.sd
            );
            RECONCILED.inc(&["expired"]);
            ended += 1;
            continue;
        }
        let peer = peer_of(a);
        if tokio::time::Instant::now() >= deadline || backing_off(&peer) {
            untried.push(p);
            continue;
        }
        let result = match decrease_once(a.clone()).await {
            Outcome::Superseded => "superseded",
            Outcome::Accepted => "delivered",
            Outcome::Refused => "refused",
            Outcome::Failed => {
                note_failure(&peer);
                failed.push(p);
                continue;
            }
        };
        note_success(&peer);
        log::info!(
            "[{}] parked NSACF DECREASE for SST={} SD={:?}: {result}",
            a.supi,
            a.snssai.sst,
            a.snssai.sd
        );
        RECONCILED.inc(&[result]);
        ended += 1;
    }
    let mut set = lock(pending());
    for p in untried.into_iter().rev() {
        if !set.iter().any(|q| q.a == p.a) {
            set.push_front(p);
        }
    }
    for p in failed {
        if !set.iter().any(|q| q.a == p.a) {
            set.push_back(p);
        }
    }
    evict(&mut set);
    ended
}

/// Run [`reconcile_once`] every [`RECONCILE_PERIOD`] for the life of the process.
pub fn spawn_reconciler() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async {
        let mut timer = tokio::time::interval(RECONCILE_PERIOD);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        timer.tick().await;
        loop {
            timer.tick().await;
            reconcile_once().await;
        }
    })
}

/// The NSAC families, for `/metrics`.
pub fn render(out: &mut String) {
    use std::fmt::Write as _;
    nextgcore_metrics::nf::write_header(
        out,
        "amf_nsac_ue_admissions",
        "gauge",
        "UE admissions (SUPI, access type, S-NSSAI) the NSACF granted and the AMF holds",
    );
    let _ = writeln!(out, "amf_nsac_ue_admissions {}", lock(admissions()).len());
    nextgcore_metrics::nf::write_header(
        out,
        "amf_nsac_ue_decreases_pending",
        "gauge",
        "Nnsacf_NSAC_NumOfUEsUpdate DECREASEs parked for the reconciler",
    );
    let _ = writeln!(out, "amf_nsac_ue_decreases_pending {}", pending_count());
    DECREASES.render(out);
    RECONCILED.render(out);
    nextgcore_metrics::nf::write_metric(
        out,
        "amf_nsac_ue_recounts_total",
        "counter",
        "NSAC INCREASEs re-sent because a DECREASE of the same UE and S-NSSAI may have landed \
         after a re-registration's INCREASE",
        RECOUNTS.load(std::sync::atomic::Ordering::Relaxed),
    );
}

/// Forget every admission and parked DECREASE (a test's own, before and after it).
#[cfg(test)]
pub fn clear_for_test() {
    lock(admissions()).clear();
    lock(pending()).clear();
    lock(backoff()).clear();
    let mut ops = lock(ops());
    ops.in_flight.clear();
    ops.admitting.clear();
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use nextgcore_sbi::message::{SbiRequest, SbiResponse};
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::sync::Arc;

    type Seen = Arc<Mutex<Vec<(String, u8)>>>;

    /// A stand-in NSACF recording (updateFlag, SST). An INCREASE for an SST in
    /// `deny` is refused 403 with a ProblemDetails (the quota is full); every other
    /// INCREASE is admitted 204; a DECREASE is answered with `decrease` as it stands.
    pub(crate) async fn nsacf(
        deny: &'static [u8],
        decrease: Arc<AtomicU16>,
    ) -> (nextgcore_sbi::server::SbiServer, u16, Seen) {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let (srv, addr) =
            nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
                let sink = sink.clone();
                let decrease = decrease.load(Ordering::SeqCst);
                async move {
                    let body: serde_json::Value = req
                        .http
                        .content
                        .as_deref()
                        .and_then(|c| serde_json::from_str(c).ok())
                        .unwrap_or_default();
                    let op = &body["ueACRequestInfo"][0]["acuOperationList"][0];
                    let flag = op["updateFlag"].as_str().unwrap_or_default().to_string();
                    let sst = op["snssai"]["sst"].as_u64().unwrap_or(0) as u8;
                    sink.lock().unwrap().push((flag.clone(), sst));
                    if flag == "DECREASE" {
                        return SbiResponse::with_status(decrease);
                    }
                    if deny.contains(&sst) {
                        return SbiResponse::with_status(403)
                            .with_json_body(&serde_json::json!({
                                "status": 403, "cause": "UE_NOT_ALLOWED" }))
                            .unwrap();
                    }
                    SbiResponse::with_status(204)
                }
            })
            .await;
        (srv, addr.port(), seen)
    }

    pub(crate) fn snssai(sst: u8) -> SNssai {
        SNssai { sst, sd: None }
    }

    /// Wait (bounded) until `seen` holds `n` DECREASEs, then a settle window.
    pub(crate) async fn decreases(seen: &Seen, n: usize) -> Vec<u8> {
        let get = || -> Vec<u8> {
            seen.lock()
                .unwrap()
                .iter()
                .filter(|(f, _)| f == "DECREASE")
                .map(|(_, s)| *s)
                .collect()
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while get().len() < n && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        get()
    }

    fn admission_2036(port: u16) -> Admission {
        Admission {
            supi: "imsi-001010000020361".to_string(),
            access_type: "3GPP_ACCESS".to_string(),
            snssai: snssai(1),
            nf_id: "amf-2036".to_string(),
            nsacf_host: "127.0.0.1".to_string(),
            nsacf_port: port,
        }
    }

    fn key_2036() -> Key {
        key_of("imsi-001010000020361", "3GPP_ACCESS", &snssai(1))
    }

    fn admitting_2036() -> bool {
        lock(ops()).admitting.contains_key(&key_2036())
    }

    /// #2036: a registration cancelled while its INCREASE is out (as at a
    /// shutdown) leaves the key's admitting entry, so a later DECREASE of the key
    /// is sent rather than swallowed, and parks what it owed: the DECREASE it
    /// superseded and a precautionary one of its own INCREASE.
    ///
    /// REVERT-VERIFIED: with `AdmittingSlot`'s `Drop` doing nothing, this fails:
    /// the key stays admitting and nothing is parked.
    #[tokio::test]
    async fn a_cancelled_admission_leaves_its_slot_and_parks_what_it_owed_2036() {
        let _g = NSAC_TEST_LOCK.lock().await;
        clear_for_test();
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        // An NSACF that accepts the INCREASE's connection and never answers.
        let hole = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hole_port = hole.local_addr().unwrap().port();
        let held = tokio::spawn(async move {
            let mut conns = Vec::new();
            while let Ok((c, _)) = hole.accept().await {
                conns.push(c);
            }
        });
        let admitting = tokio::spawn(async move {
            admit_registration(
                "imsi-001010000020361",
                "3GPP_ACCESS",
                &[snssai(1)],
                "127.0.0.1",
                hole_port,
                "amf-2036",
            )
            .await
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !admitting_2036() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // An earlier registration's DECREASE (at another NSACF) is superseded.
        let earlier = admission_2036(1);
        let superseded = decrease_once(earlier.clone()).await;
        admitting.abort();
        let cancelled = admitting.await.is_err();
        let still_admitting = admitting_2036();
        let parked = parked();
        // A later DECREASE of the key is sent (port 1 refuses it: Failed).
        let later = decrease_once(earlier.clone()).await;
        clear_for_test();
        held.abort();

        assert_eq!(superseded, Outcome::Superseded);
        assert!(cancelled);
        assert!(!still_admitting, "the slot is left");
        assert!(parked.contains(&earlier), "the owed DECREASE is parked");
        assert!(
            parked.contains(&admission_2036(hole_port)),
            "and a precautionary one of its own INCREASE: {parked:?}"
        );
        assert_eq!(later, Outcome::Failed, "not swallowed");
    }

    /// #2036: a task that panics while it holds the key's admitting entry leaves
    /// it, and parks the DECREASE it superseded.
    ///
    /// REVERT-VERIFIED: with `AdmittingSlot`'s `Drop` doing nothing, this fails:
    /// the key stays admitting for good.
    #[tokio::test]
    async fn a_panic_while_admitting_leaves_the_slot_2036() {
        let _g = NSAC_TEST_LOCK.lock().await;
        clear_for_test();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _slot = {
                let _admitted = lock(admissions());
                AdmittingSlot::enter(&mut lock(ops()), &key_2036(), None)
            };
            let _ = entered_tx.send(());
            let _ = go_rx.await;
            panic!("#2036: a panic while admitting");
        });
        entered_rx.await.unwrap();
        let earlier = admission_2036(1);
        let superseded = decrease_once(earlier.clone()).await;
        let _ = go_tx.send(());
        let panicked = task.await.is_err_and(|e| e.is_panic());
        let still_admitting = admitting_2036();
        let parked = parked();
        clear_for_test();

        assert_eq!(superseded, Outcome::Superseded);
        assert!(panicked);
        assert!(!still_admitting, "the slot is left");
        assert_eq!(parked, vec![earlier], "the owed DECREASE is parked");
    }

    /// #2036: overlapping INCREASEs of a key each hold its admitting entry. The
    /// first to settle does not end it: a DECREASE meanwhile is still superseded,
    /// and the last to settle returns it owed, unless one of them counted the UE
    /// at its NSACF.
    ///
    /// REVERT-VERIFIED: with `leave` ending the entry whatever `deciding` is (one
    /// shared slot, as before), this fails: the first settle ends it.
    #[tokio::test]
    async fn overlapping_increases_each_hold_the_slot_2036() {
        let _g = NSAC_TEST_LOCK.lock().await;
        clear_for_test();
        let enter = || {
            let _admitted = lock(admissions());
            AdmittingSlot::enter(&mut lock(ops()), &key_2036(), None)
        };
        let earlier = admission_2036(1);

        let (first, second) = (enter(), enter());
        let after_first = first.settle(None);
        let held = admitting_2036();
        let superseded = decrease_once(earlier.clone()).await;
        let after_second = second.settle(Some(("127.0.0.1".to_string(), 2)));
        let ended = !admitting_2036();

        // One of them counted the UE at the superseded DECREASE's NSACF.
        let (first, second) = (enter(), enter());
        let _ = decrease_once(earlier.clone()).await;
        let counted_one = first.settle(Some(("127.0.0.1".to_string(), 1)));
        let counted_last = second.settle(None);
        clear_for_test();

        assert!(after_first.is_empty(), "the first settle owes nothing yet");
        assert!(held, "the second still holds the entry");
        assert_eq!(superseded, Outcome::Superseded);
        assert_eq!(after_second, vec![earlier], "owed once the last settles");
        assert!(ended);
        assert!(
            counted_one.is_empty() && counted_last.is_empty(),
            "counted: not owed"
        );
    }

    /// #1942: a registration denied on its second S-NSSAI rejects that S-NSSAI
    /// only: the first stays admitted and counted, and the NSACF is asked about the
    /// third as well (TS 23.502 §4.2.11.2).
    ///
    /// REVERT-VERIFIED: with the loop stopping at the first denial again, this
    /// fails: SST 3 is never asked for.
    #[tokio::test]
    async fn a_denied_snssai_is_rejected_and_the_others_kept_1942() {
        let _g = NSAC_TEST_LOCK.lock().await;
        clear_for_test();
        let (srv, port, seen) = nsacf(&[2], Arc::new(AtomicU16::new(204))).await;
        let supi = "imsi-001010000019421";
        let allowed = [snssai(1), snssai(2), snssai(3)];

        let out =
            admit_registration(supi, "3GPP_ACCESS", &allowed, "127.0.0.1", port, "amf-1942").await;
        let decreased = decreases(&seen, 0).await;
        let asked: Vec<u8> = seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(f, _)| f == "INCREASE")
            .map(|(_, s)| *s)
            .collect();
        let held = (
            is_admitted(supi, "3GPP_ACCESS", &snssai(1)),
            is_admitted(supi, "3GPP_ACCESS", &snssai(3)),
        );
        clear_for_test();
        srv.stop().await.ok();

        assert_eq!(out.rejected, vec![snssai(2)], "only SST 2 is rejected");
        assert!(!out.all_rejected(&allowed));
        assert_eq!(asked, vec![1, 2, 3], "every S-NSSAI is asked for");
        assert_eq!(held, (true, true), "SST 1 and 3 stay admitted");
        assert!(
            decreased.is_empty(),
            "nothing is counted out: {decreased:?}"
        );
    }

    /// #1876, #1942: a registration whose every S-NSSAI is rejected is rejected, so
    /// whatever the UE was admitted to before is counted out.
    ///
    /// REVERT-VERIFIED: with nothing taken back when all are rejected, this fails:
    /// no DECREASE for the earlier SST 3.
    #[tokio::test]
    async fn every_snssai_rejected_counts_the_ue_out_1876() {
        let _g = NSAC_TEST_LOCK.lock().await;
        clear_for_test();
        let (srv, port, seen) = nsacf(&[1, 2], Arc::new(AtomicU16::new(204))).await;
        let supi = "imsi-001010000018761";
        admit_registration(
            supi,
            "3GPP_ACCESS",
            &[snssai(3)],
            "127.0.0.1",
            port,
            "amf-1876",
        )
        .await;
        let allowed = [snssai(1), snssai(2)];

        let out =
            admit_registration(supi, "3GPP_ACCESS", &allowed, "127.0.0.1", port, "amf-1876").await;
        let decreased = decreases(&seen, 1).await;
        let held = is_admitted(supi, "3GPP_ACCESS", &snssai(3));
        clear_for_test();
        srv.stop().await.ok();

        assert!(out.all_rejected(&allowed));
        assert_eq!(decreased, vec![3], "the earlier SST 3 is counted out");
        assert!(!held);
    }

    #[tokio::test]
    async fn an_snssai_removed_from_the_allowed_nssai_is_counted_out_1876() {
        let _g = NSAC_TEST_LOCK.lock().await;
        clear_for_test();
        let (srv, port, seen) = nsacf(&[], Arc::new(AtomicU16::new(204))).await;
        let supi = "imsi-001010000018762";
        let admit = |allowed: Vec<SNssai>| async move {
            admit_registration(supi, "3GPP_ACCESS", &allowed, "127.0.0.1", port, "amf-1876").await
        };

        admit(vec![snssai(1), snssai(2)]).await;
        let both = (
            is_admitted(supi, "3GPP_ACCESS", &snssai(1)),
            is_admitted(supi, "3GPP_ACCESS", &snssai(2)),
        );
        admit(vec![snssai(1)]).await;
        let decreased = decreases(&seen, 1).await;
        let after = (
            is_admitted(supi, "3GPP_ACCESS", &snssai(1)),
            is_admitted(supi, "3GPP_ACCESS", &snssai(2)),
        );
        clear_for_test();
        srv.stop().await.ok();

        assert_eq!(both, (true, true), "both counted in");
        assert_eq!(decreased, vec![2], "SST 2 counted out");
        assert_eq!(after, (true, false), "SST 1 kept");
    }

    /// #1876: an INCREASE that degraded open (no NSACF answered) counted nothing,
    /// so nothing is recorded and a deregistration parks nothing.
    ///
    /// REVERT-VERIFIED: with every admitted answer recorded (not only `counted`),
    /// this fails: the degrade-open admission is held, to be counted out of an NSACF
    /// that never counted it.
    #[tokio::test]
    async fn a_degraded_open_admission_is_not_recorded_1876() {
        let _g = NSAC_TEST_LOCK.lock().await;
        clear_for_test();
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let supi = "imsi-001010000018763";
        let out = admit_registration(
            supi,
            "3GPP_ACCESS",
            &[snssai(1)],
            "127.0.0.1",
            1,
            "amf-1876",
        )
        .await;
        let held = is_admitted(supi, "3GPP_ACCESS", &snssai(1));
        tokio::time::sleep(Duration::from_millis(200)).await;
        let parked_now = pending_count();
        clear_for_test();

        assert!(
            out.granted && out.rejected.is_empty(),
            "degrade-open admits"
        );
        assert!(!held, "but counted nothing to undo");
        assert_eq!(
            parked_now, 0,
            "and its precautionary DECREASE is not parked"
        );
    }

    /// #1876: a DECREASE that fails is parked, retried while the NSACF fails, and
    /// delivered once it recovers. One whose slice was admitted again meanwhile is
    /// superseded and not sent.
    ///
    /// REVERT-VERIFIED: with `decrease_now` not parking a failure, this fails:
    /// nothing is parked.
    #[tokio::test]
    async fn a_failed_decrease_is_reconciled_or_superseded_1876() {
        let _g = NSAC_TEST_LOCK.lock().await;
        clear_for_test();
        let status = Arc::new(AtomicU16::new(503));
        let (srv, port, seen) = nsacf(&[], status.clone()).await;
        let admission = |supi: &str, sst: u8| Admission {
            supi: supi.to_string(),
            access_type: "3GPP_ACCESS".to_string(),
            snssai: snssai(sst),
            nf_id: "amf-1876".to_string(),
            nsacf_host: "127.0.0.1".to_string(),
            nsacf_port: port,
        };
        let (gone, back) = ("imsi-001010000018764", "imsi-001010000018765");
        let delivered = || RECONCILED.get(&["delivered"]);
        let superseded = || RECONCILED.get(&["superseded"]);
        let before = (delivered(), superseded());

        let first = decrease_now(admission(gone, 1)).await;
        decrease_now(admission(back, 1)).await;
        let parked_after_failure = pending_count();
        // `back` registers again before the reconciler runs.
        record(admission(back, 1));
        status.store(204, Ordering::SeqCst);
        reconcile_once().await;
        let left = pending_count();
        let sent_for_back = seen.lock().unwrap().len();
        let after = (delivered(), superseded());
        clear_for_test();
        srv.stop().await.ok();

        assert_eq!(first, Outcome::Failed);
        assert_eq!(parked_after_failure, 2, "both parked");
        assert_eq!(left, 0, "both ended");
        assert_eq!(
            sent_for_back, 3,
            "two failures, then one delivered; none for `back`"
        );
        assert_eq!((after.0 - before.0, after.1 - before.1), (1, 1));
    }

    /// #1961: a peer that accepts the connection and never answers, so each
    /// request to it costs the client's whole timeout. Returns its port; the
    /// accepted sockets are held for the life of the test process.
    fn blackhole_1961() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming().flatten() {
                held.push(stream);
            }
        });
        port
    }

    fn admission_toward_1961(port: u16, supi: &str) -> Admission {
        Admission {
            supi: supi.to_string(),
            access_type: "3GPP_ACCESS".to_string(),
            snssai: snssai(1),
            nf_id: "amf-1961".to_string(),
            nsacf_host: "127.0.0.1".to_string(),
            nsacf_port: port,
        }
    }

    /// #1961: DECREASEs toward a blackholed NSACF ahead of one toward a healthy
    /// NSACF no longer starve it: the healthy one is delivered within two passes,
    /// and the blackholed ones stay parked.
    /// REVERT-VERIFIED: with the old order restored (every not-ended DECREASE
    /// re-parked at the front, no backoff), the healthy DECREASE is never reached
    /// and "the healthy NSACF gets its DECREASE" fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_blackholed_nsacf_does_not_starve_a_healthy_one_1961() {
        let _g = NSAC_TEST_LOCK.lock().await;
        clear_for_test();
        let status = Arc::new(AtomicU16::new(204));
        let (srv, port, seen) = nsacf(&[], status).await;
        let dead = blackhole_1961();
        for n in 0..3 {
            park(admission_toward_1961(
                dead,
                &format!("imsi-00101000001961{n}"),
            ));
        }
        park(admission_toward_1961(port, "imsi-001010000019619"));
        let before = RECONCILED.get(&["delivered"]);
        for _ in 0..2 {
            reconcile_once().await;
        }
        let delivered = RECONCILED.get(&["delivered"]) - before;
        let left = pending_count();
        let hits = seen.lock().unwrap().len();
        clear_for_test();
        srv.stop().await.ok();
        assert_eq!(delivered, 1, "the healthy NSACF gets its DECREASE");
        assert_eq!(hits, 1);
        assert_eq!(left, 3, "the blackholed ones stay parked");
    }

    /// #1961: a DECREASE parked longer than [`MAX_AGE`] ends as `expired`.
    /// REVERT-VERIFIED: with the age check removed it is attempted and stays
    /// parked.
    #[tokio::test]
    async fn a_decrease_older_than_max_age_expires_1961() {
        let _g = NSAC_TEST_LOCK.lock().await;
        clear_for_test();
        park(admission_toward_1961(9, "imsi-001010000019618"));
        lock(pending())[0].since = std::time::SystemTime::now() - MAX_AGE - Duration::from_secs(1);
        let before = RECONCILED.get(&["expired"]);
        reconcile_once().await;
        let expired = RECONCILED.get(&["expired"]) - before;
        let left = pending_count();
        clear_for_test();
        assert_eq!((expired, left), (1, 0));
    }

    /// A stand-in NSACF that APPLIES each request `delay` after it arrives, then
    /// records "<FLAG>-applied". An INCREASE for an SST in `deny` is refused 403.
    async fn slow_nsacf(
        increase_delay: Duration,
        decrease_delay: Duration,
        deny: &'static [u8],
    ) -> (
        nextgcore_sbi::server::SbiServer,
        u16,
        Arc<Mutex<Vec<String>>>,
    ) {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let applied = Arc::new(Mutex::new(Vec::new()));
        let sink = applied.clone();
        let (srv, addr) =
            nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
                let sink = sink.clone();
                async move {
                    let body: serde_json::Value = req
                        .http
                        .content
                        .as_deref()
                        .and_then(|c| serde_json::from_str(c).ok())
                        .unwrap_or_default();
                    let op = &body["ueACRequestInfo"][0]["acuOperationList"][0];
                    let flag = op["updateFlag"].as_str().unwrap_or_default().to_string();
                    let sst = op["snssai"]["sst"].as_u64().unwrap_or(0) as u8;
                    let increase = flag == "INCREASE";
                    tokio::time::sleep(if increase {
                        increase_delay
                    } else {
                        decrease_delay
                    })
                    .await;
                    sink.lock().unwrap().push(format!("{flag}-applied"));
                    if increase && deny.contains(&sst) {
                        return SbiResponse::with_status(403)
                            .with_json_body(&serde_json::json!({ "status": 403 }))
                            .unwrap();
                    }
                    SbiResponse::with_status(204)
                }
            })
            .await;
        (srv, addr.port(), applied)
    }

    fn admission_at(supi: &str, sst: u8, port: u16) -> Admission {
        Admission {
            supi: supi.to_string(),
            access_type: "3GPP_ACCESS".to_string(),
            snssai: snssai(sst),
            nf_id: "amf-1940".to_string(),
            nsacf_host: "127.0.0.1".to_string(),
            nsacf_port: port,
        }
    }

    async fn applied_n(applied: &Arc<Mutex<Vec<String>>>, n: usize) -> Vec<String> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while applied.lock().unwrap().len() < n && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        applied.lock().unwrap().clone()
    }

    /// R27 #1940: a de-registration's DECREASE that the NSACF applies late, and a
    /// re-registration 30 ms after it. The INCREASE waits for the DECREASE on the
    /// wire, so the NSACF applies DECREASE then INCREASE and the UE stays counted.
    ///
    /// REVERT-VERIFIED: with the INCREASE not waiting for a DECREASE in flight,
    /// this fails: INCREASE-applied, DECREASE-applied (R27's probe, 3 of 3).
    #[tokio::test]
    async fn a_reregistration_waits_for_the_deregistrations_decrease_1940() {
        let _g = NSAC_TEST_LOCK.lock().await;
        clear_for_test();
        let (srv, port, applied) =
            slow_nsacf(Duration::ZERO, Duration::from_millis(300), &[]).await;
        let supi = "imsi-001010000019401";
        record(admission_at(supi, 1, port));

        spawn_decreases(take(supi, "3GPP_ACCESS", &[]));
        tokio::time::sleep(Duration::from_millis(30)).await;
        let out = admit_registration(
            supi,
            "3GPP_ACCESS",
            &[snssai(1)],
            "127.0.0.1",
            port,
            "amf-1940",
        )
        .await;
        let order = applied_n(&applied, 2).await;
        let held = is_admitted(supi, "3GPP_ACCESS", &snssai(1));
        clear_for_test();
        srv.stop().await.ok();

        assert!(out.rejected.is_empty());
        assert_eq!(
            order,
            ["DECREASE-applied", "INCREASE-applied"],
            "the DECREASE lands first"
        );
        assert!(held, "and the re-registered UE is counted");
    }

    /// #1945: a DECREASE the NSACF is slower to apply than the INCREASE's wait. The
    /// re-registration's INCREASE goes after its wait and is applied first, then the
    /// DECREASE counts the UE out; the AMF counts it in again once the DECREASE has
    /// landed, so the UE ends counted.
    ///
    /// REVERT-VERIFIED: without the overtaken re-count, this fails: the NSACF's last
    /// word is the DECREASE.
    #[tokio::test]
    async fn a_decrease_that_lands_after_the_increase_is_counted_in_again_1945() {
        let _g = NSAC_TEST_LOCK.lock().await;
        clear_for_test();
        let (srv, port, applied) =
            slow_nsacf(Duration::ZERO, Duration::from_millis(1500), &[]).await;
        let supi = "imsi-001010000019451";
        record(admission_at(supi, 1, port));

        spawn_decreases(take(supi, "3GPP_ACCESS", &[]));
        tokio::time::sleep(Duration::from_millis(30)).await;
        let out = admit_registration(
            supi,
            "3GPP_ACCESS",
            &[snssai(1)],
            "127.0.0.1",
            port,
            "amf-1945",
        )
        .await;
        let order = applied_n(&applied, 3).await;
        clear_for_test();
        srv.stop().await.ok();

        assert!(out.granted, "admitted");
        assert_eq!(
            order,
            ["INCREASE-applied", "DECREASE-applied", "INCREASE-applied"],
            "counted in again after the late DECREASE"
        );
    }

    /// #2005 (R32 on #2002): a UE that deregisters while the late-DECREASE
    /// re-count's INCREASE is on the wire ends counted OUT. Its deregistration's
    /// DECREASE is handed to the re-count and sent after it, instead of being
    /// sent at once and landing before the slower re-count INCREASE, which left
    /// the NSACF counting a UE the AMF had dropped.
    ///
    /// Timeline (INCREASE 2 s, DECREASE 1.1 s): the first DECREASE lands at
    /// 1.1 s, after the registration's 1 s wait, so it is overtaken; the
    /// registration's INCREASE lands at 3 s; the re-count's INCREASE goes at 3 s
    /// and lands at 5 s; the UE deregisters during it.
    ///
    /// REVERT-VERIFIED: without the re-count registering as being admitted, the
    /// deregistration's DECREASE lands at about 4.3 s and the re-count INCREASE
    /// at 5 s, so the NSACF's last word is an INCREASE and this fails.
    #[tokio::test]
    async fn a_deregistration_during_the_recount_is_counted_out_after_it_2005() {
        let _g = NSAC_TEST_LOCK.lock().await;
        clear_for_test();
        let (srv, port, applied) = slow_nsacf(
            Duration::from_millis(2000),
            Duration::from_millis(1100),
            &[],
        )
        .await;
        let supi = "imsi-001010000020051";
        record(admission_at(supi, 1, port));
        let before = RECOUNTS.load(std::sync::atomic::Ordering::Relaxed);

        spawn_decreases(take(supi, "3GPP_ACCESS", &[]));
        tokio::time::sleep(Duration::from_millis(30)).await;
        let out = admit_registration(
            supi,
            "3GPP_ACCESS",
            &[snssai(1)],
            "127.0.0.1",
            port,
            "amf-2005",
        )
        .await;
        assert!(out.granted);
        // The re-count's INCREASE is on the wire once the counter moves.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while RECOUNTS.load(std::sync::atomic::Ordering::Relaxed) == before
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        // The UE deregisters during the re-count.
        spawn_decreases(take(supi, "3GPP_ACCESS", &[]));
        let order = applied_n(&applied, 4).await;
        clear_for_test();
        srv.stop().await.ok();

        assert_eq!(order.len(), 4, "{order:?}");
        assert_eq!(
            order.last().map(String::as_str),
            Some("DECREASE-applied"),
            "the NSACF's last word is the deregistration: {order:?}"
        );
    }

    /// R27 #1940: a DECREASE that finds an INCREASE for its key being decided is
    /// not sent while it is out; the INCREASE takes it over. Here the INCREASE is
    /// denied, so it did not count the UE, and the DECREASE it took over is sent
    /// after it.
    ///
    /// REVERT-VERIFIED: with the DECREASE ignoring an INCREASE being decided, this
    /// fails: the DECREASE is applied before the INCREASE.
    #[tokio::test]
    async fn a_decrease_during_an_increase_is_taken_over_1940() {
        let _g = NSAC_TEST_LOCK.lock().await;
        clear_for_test();
        let (srv, port, applied) =
            slow_nsacf(Duration::from_millis(300), Duration::ZERO, &[1]).await;
        let supi = "imsi-001010000019402";

        let registering = tokio::spawn(async move {
            admit_registration(
                supi,
                "3GPP_ACCESS",
                &[snssai(1)],
                "127.0.0.1",
                port,
                "amf-1940",
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let during = decrease_now(admission_at(supi, 1, port)).await;
        let out = registering.await.unwrap();
        let order = applied_n(&applied, 2).await;
        clear_for_test();
        srv.stop().await.ok();

        assert_eq!(
            during,
            Outcome::Superseded,
            "not sent while the INCREASE is out"
        );
        assert_eq!(out.rejected, vec![snssai(1)]);
        assert_eq!(
            order,
            ["INCREASE-applied", "DECREASE-applied"],
            "sent after it"
        );
    }

    /// #1876: bounded. Parking past [`MAX_PENDING`] evicts the oldest.
    ///
    /// REVERT-VERIFIED: with `evict` a no-op, this fails: MAX_PENDING + 1 are held.
    #[tokio::test]
    async fn the_parked_set_is_bounded_1876() {
        let _g = NSAC_TEST_LOCK.lock().await;
        clear_for_test();
        let before = RECONCILED.get(&["abandoned"]);
        for n in 0..=MAX_PENDING {
            park(Admission {
                supi: format!("imsi-bound-{n}"),
                access_type: "3GPP_ACCESS".to_string(),
                snssai: snssai(1),
                nf_id: "amf-1876".to_string(),
                nsacf_host: "127.0.0.1".to_string(),
                nsacf_port: 1,
            });
        }
        let held = parked();
        clear_for_test();

        assert_eq!(held.len(), MAX_PENDING);
        assert_eq!(held[0].supi, "imsi-bound-1", "the oldest went");
        assert_eq!(RECONCILED.get(&["abandoned"]) - before, 1);
    }
}
