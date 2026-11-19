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
//!   out.
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
    /// INCREASEs being decided, each with the DECREASEs it superseded: they are
    /// owed again if this INCREASE does not end up counting the UE.
    admitting: HashMap<Key, Vec<Admission>>,
}

/// One DECREASE on the wire, which an INCREASE for its key waits for.
#[derive(Default)]
struct Flight {
    done: std::sync::atomic::AtomicBool,
    changed: tokio::sync::Notify,
}

impl Flight {
    fn finish(&self) {
        self.done.store(true, std::sync::atomic::Ordering::SeqCst);
        self.changed.notify_waiters();
    }

    async fn wait(&self, until: tokio::time::Instant) {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.done.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            if tokio::time::timeout_at(until, notified).await.is_err() {
                return;
            }
        }
    }
}

fn ops() -> &'static Mutex<Ops> {
    static OPS: std::sync::LazyLock<Mutex<Ops>> = std::sync::LazyLock::new(Default::default);
    &OPS
}

/// The longest an INCREASE waits for a DECREASE of its key on the wire: the SBI
/// client's request timeout bounds the DECREASE, with room to spare.
const DECREASE_WAIT: Duration = Duration::from_secs(10);

/// The parked DECREASEs, oldest first.
fn pending() -> &'static Mutex<VecDeque<Admission>> {
    static PENDING: Mutex<VecDeque<Admission>> = Mutex::new(VecDeque::new());
    &PENDING
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

/// `amf_nsac_ue_decreases_reconciled_total{result}`: parked DECREASEs the
/// reconciler ended: `delivered`, `superseded` (admitted again since), `refused`
/// (a 4xx a retry cannot change) or `abandoned` (evicted at the bound).
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
        let flights = {
            let _admitted = lock(admissions());
            let mut ops = lock(ops());
            ops.admitting.entry(key.clone()).or_default();
            ops.in_flight.get(&key).cloned().unwrap_or_default()
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
        // this INCREASE counts the UE at the same NSACF (it counts a UE once).
        let inherited = {
            let _admitted = lock(admissions());
            lock(ops()).admitting.remove(&key).unwrap_or_default()
        };
        let counted_here = matches!(&answer, Ok(res) if res.counted);
        let owed: Vec<Admission> = inherited
            .into_iter()
            .filter(|old| {
                !(counted_here
                    && old.nsacf_host == admission.nsacf_host
                    && old.nsacf_port == admission.nsacf_port)
            })
            .collect();
        spawn_decreases(owed);
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
        if let Some(owed) = ops.admitting.get_mut(&key) {
            owed.push(a);
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
    outcome
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

fn evict(set: &mut VecDeque<Admission>) {
    while set.len() > MAX_PENDING {
        if let Some(old) = set.pop_front() {
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
    if set.contains(&a) {
        return;
    }
    log::warn!(
        "[{}] NSACF DECREASE for SST={} SD={:?} failed; parked, retried every \
         {RECONCILE_PERIOD:?}",
        a.supi,
        a.snssai.sst,
        a.snssai.sd
    );
    set.push_back(a);
    evict(&mut set);
}

/// How many DECREASEs are parked.
pub fn pending_count() -> usize {
    lock(pending()).len()
}

/// The parked DECREASEs, for tests.
#[cfg(test)]
pub fn parked() -> Vec<Admission> {
    lock(pending()).iter().cloned().collect()
}

/// One reconcile pass over the parked DECREASEs, oldest first, for at most
/// [`MAX_PASS`]. Returns how many ended.
pub async fn reconcile_once() -> usize {
    let batch: Vec<Admission> = lock(pending()).drain(..).collect();
    let deadline = tokio::time::Instant::now() + MAX_PASS;
    let mut ended = 0;
    let mut still = Vec::new();
    for a in batch {
        if tokio::time::Instant::now() >= deadline {
            still.push(a);
            continue;
        }
        let result = match decrease_once(a.clone()).await {
            Outcome::Superseded => "superseded",
            Outcome::Accepted => "delivered",
            Outcome::Refused => "refused",
            Outcome::Failed => {
                still.push(a);
                continue;
            }
        };
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
    for a in still.into_iter().rev() {
        if !set.contains(&a) {
            set.push_front(a);
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
}

/// Forget every admission and parked DECREASE (a test's own, before and after it).
#[cfg(test)]
pub fn clear_for_test() {
    lock(admissions()).clear();
    lock(pending()).clear();
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
        assert!(decreased.is_empty(), "nothing is counted out: {decreased:?}");
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
        admit_registration(supi, "3GPP_ACCESS", &[snssai(3)], "127.0.0.1", port, "amf-1876").await;
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

        assert!(out.granted && out.rejected.is_empty(), "degrade-open admits");
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
