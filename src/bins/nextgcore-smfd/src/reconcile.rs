//! #1875: the reconciler for release-side cleanups that failed.
//!
//! A released (or rolled-back) PDU session owes four peers a cleanup: the NSACF a
//! DECREASE (TS 23.502 §4.2.11.4, TS 29.536 §5.2.2.2), the PCF an SM Policy
//! Association termination (TS 29.512 §4.2.5), and the UDM a
//! Nudm_UECM_Deregistration and a Nudm_SDM_Unsubscribe (TS 23.502 §4.3.4.2 steps
//! 14-15). Each was tried once (the SM policy delete twice, 500 ms apart) and then
//! only logged, so a peer that was down for a moment kept the record for ever: every
//! failed DECREASE permanently shrank the slice's PDU session quota, a stale
//! serving-SMF record resolved a released session to this SMF, and an orphaned SDM
//! subscription notified a callback whose session was gone.
//!
//! Now a cleanup that fails is parked here and retried on [`RECONCILE_PERIOD`]
//! until its peer accepts it (a 404 counts: the peer does not hold the record).
//! Same shape as #1817's mbsmfd and tsctsf reconcilers.
//!
//! - Bounded: at most [`MAX_PENDING`] records. Parking one more evicts the oldest,
//!   logged at error and counted `abandoned`, so a peer that never comes back cannot
//!   grow the set without limit. One pass sends for at most [`MAX_PASS`].
//! - Durable: the set is written into the SMF state snapshot (`pendingCleanups`)
//!   whenever it changes, and restored from it at boot, so a restart does not forget
//!   a cleanup it still owes. Like the sessions, only when the durable state is
//!   configured (`--state-file` / `NEXTGCORE_SMF_STATE_FILE`).
//! - No peer starves the others (#1961, the #1954 / #1972 pattern): once a cleanup
//!   to a peer (an NSACF, the PCF, the UDM) fails, that peer backs off
//!   ([`BACKOFF_BASE`], doubling to [`BACKOFF_MAX`]) and its other cleanups wait, in
//!   this pass and later ones; one tried and failed goes to the BACK of the queue,
//!   one not reached (or deferred) keeps its place at the front. One parked longer
//!   than [`MAX_AGE`] ends as `expired`; the age is counted from when this process
//!   parked or restored it.
//! - Safe against re-use: a NSACF DECREASE or a UECM deregistration names a
//!   (SUPI, PSI), not a session. A new session for the same pair supersedes it (its
//!   INCREASE or registration is the live one), and one still being created defers
//!   it to the next pass, so the reconciler never removes a live session's record.

use crate::context::PolicyBinding;
use crate::policy;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

/// Records parked before the oldest is abandoned.
pub const MAX_PENDING: usize = 4096;

/// How often the parked cleanups are retried.
#[cfg(not(test))]
pub const RECONCILE_PERIOD: Duration = Duration::from_secs(30);
#[cfg(test)]
pub const RECONCILE_PERIOD: Duration = Duration::from_millis(20);

/// The longest one pass sends for. A pass against a blackholed peer costs a client
/// timeout per record, so past this the rest wait for the next pass.
#[cfg(not(test))]
pub const MAX_PASS: Duration = Duration::from_secs(30);
#[cfg(test)]
pub const MAX_PASS: Duration = Duration::from_secs(2);

/// One cleanup a release still owes a peer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Cleanup {
    /// Nnsacf_NSAC_NumOfPDUsUpdate DECREASE for (SUPI, PSI) on the S-NSSAI, naming
    /// the nfId the INCREASE carried, at the NSACF it went to when known.
    #[serde(rename_all = "camelCase")]
    NsacDecrease {
        supi: String,
        psi: u8,
        sst: u8,
        sd: Option<String>,
        nf_id: Option<String>,
        nsacf: Option<policy::NsacfEndpoint>,
        plmn: Option<(String, String)>,
    },
    /// Npcf_SMPolicyControl_Delete of the SM Policy Association.
    #[serde(rename_all = "camelCase")]
    SmPolicyDelete { sm_policy_id: String },
    /// Nudm_UECM_Deregistration of the serving-SMF record for (SUPI, PSI).
    #[serde(rename_all = "camelCase")]
    UecmDeregister { supi: String, psi: u8 },
    /// Nudm_SDM_Unsubscribe of the session's SDM subscription.
    #[serde(rename_all = "camelCase")]
    SdmUnsubscribe {
        supi: String,
        subscription_id: String,
    },
}

impl Cleanup {
    /// The metric label for this kind.
    pub fn kind(&self) -> &'static str {
        match self {
            Cleanup::NsacDecrease { .. } => "nsac_decrease",
            Cleanup::SmPolicyDelete { .. } => "sm_policy_delete",
            Cleanup::UecmDeregister { .. } => "uecm_deregister",
            Cleanup::SdmUnsubscribe { .. } => "sdm_unsubscribe",
        }
    }

    /// The NSACF DECREASE a binding's admission owes.
    pub fn nsac_of(binding: &PolicyBinding) -> Self {
        Cleanup::NsacDecrease {
            supi: binding.supi.clone(),
            psi: binding.psi,
            sst: binding.sst,
            sd: binding.sd.clone(),
            nf_id: binding.nsac_nf_id.clone(),
            nsacf: binding.nsac_nsacf.clone(),
            plmn: binding.nsac_plmn.clone(),
        }
    }

    fn describe(&self) -> String {
        match self {
            Cleanup::NsacDecrease {
                supi, psi, sst, sd, ..
            } => {
                format!("[{supi}] NSACF DECREASE for PSI {psi} S-NSSAI[SST:{sst} SD:{sd:?}]")
            }
            Cleanup::SmPolicyDelete { sm_policy_id } => {
                format!("SM policy association {sm_policy_id} delete")
            }
            Cleanup::UecmDeregister { supi, psi } => {
                format!("[{supi}] Nudm_UECM_Deregistration for PSI {psi}")
            }
            Cleanup::SdmUnsubscribe {
                supi,
                subscription_id,
            } => format!("[{supi}] Nudm_SDM_Unsubscribe({subscription_id})"),
        }
    }
}

const KINDS: [&str; 4] = [
    "nsac_decrease",
    "sm_policy_delete",
    "uecm_deregister",
    "sdm_unsubscribe",
];

/// `smf_release_cleanups_reconciled_total{kind,result}`: parked cleanups the
/// reconciler ended: `delivered` (the peer accepted, or no longer held the record),
/// `superseded` (a new session for the same SUPI and PSI holds it), `refused` (the
/// peer answered a 4xx a retry cannot change), `abandoned` (evicted at the bound), or
/// `expired` (parked longer than [`MAX_AGE`], #1961).
pub static RECONCILED: nextgcore_metrics::nf::CounterFamily =
    nextgcore_metrics::nf::CounterFamily::new(
        "smf_release_cleanups_reconciled_total",
        "Release-side cleanups (NSACF DECREASE, SM policy delete, UECM deregistration, SDM \
         unsubscribe) that failed and were parked, by how the reconciler ended them",
        &["kind", "result"],
    );

/// `smf_release_cleanups_parked_total{kind}`: cleanups that failed and were parked.
pub static PARKED: nextgcore_metrics::nf::CounterFamily = nextgcore_metrics::nf::CounterFamily::new(
    "smf_release_cleanups_parked_total",
    "Release-side cleanups that failed and were parked for the reconciler",
    &["kind"],
);

/// The parked cleanups, oldest first.
///
/// Tests that read or write it hold `crate::context::PROCESS_STATE_TEST_LOCK`: the
/// set is SMF process state, written by every release a test drives, and it is
/// snapshotted with the rest of that state.
fn pending() -> &'static Mutex<VecDeque<Parked>> {
    static PENDING: Mutex<VecDeque<Parked>> = Mutex::new(VecDeque::new());
    &PENDING
}

/// One parked cleanup, and when this process parked (or restored) it (#1961).
#[derive(Debug, Clone)]
struct Parked {
    cleanup: Cleanup,
    /// Wall-clock, so a test can set it back past [`MAX_AGE`].
    since: std::time::SystemTime,
}

impl Parked {
    fn new(cleanup: Cleanup) -> Self {
        Parked {
            cleanup,
            since: std::time::SystemTime::now(),
        }
    }
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

/// The peer a cleanup goes to: the NSACF it names (else the resolved one), the
/// PCF, or the UDM.
fn peer_of(c: &Cleanup) -> String {
    match c {
        Cleanup::NsacDecrease { nsacf: Some(e), .. } => format!("nsacf {}:{}", e.host, e.port),
        Cleanup::NsacDecrease { nsacf: None, .. } => "nsacf".to_string(),
        Cleanup::SmPolicyDelete { .. } => "pcf".to_string(),
        Cleanup::UecmDeregister { .. } | Cleanup::SdmUnsubscribe { .. } => "udm".to_string(),
    }
}

fn lock() -> std::sync::MutexGuard<'static, VecDeque<Parked>> {
    pending().lock().unwrap_or_else(|e| e.into_inner())
}

fn holds(set: &VecDeque<Parked>, c: &Cleanup) -> bool {
    set.iter().any(|p| p.cleanup == *c)
}

/// Evict down to [`MAX_PENDING`], oldest first.
fn evict(set: &mut VecDeque<Parked>) {
    while set.len() > MAX_PENDING {
        if let Some(Parked { cleanup: old, .. }) = set.pop_front() {
            log::error!(
                "{}: abandoned; {MAX_PENDING} release cleanups are already pending",
                old.describe()
            );
            RECONCILED.inc(&[old.kind(), "abandoned"]);
        }
    }
}

/// Write the set into the durable snapshot (a no-op when no state file is set).
fn persist() {
    if let Ok(ctx) = crate::smf_self().read() {
        ctx.persist();
    }
}

/// Park `cleanup` for the reconciler. One already parked is not added twice.
pub fn park(cleanup: Cleanup) {
    {
        let mut set = lock();
        if holds(&set, &cleanup) {
            return;
        }
        log::warn!(
            "{} failed; parked, retried every {RECONCILE_PERIOD:?}",
            cleanup.describe()
        );
        PARKED.inc(&[cleanup.kind()]);
        set.push_back(Parked::new(cleanup));
        evict(&mut set);
    }
    persist();
}

/// The parked set, for the durable snapshot.
pub fn snapshot() -> Vec<Cleanup> {
    lock().iter().map(|p| p.cleanup.clone()).collect()
}

/// Restore parked cleanups from a snapshot (boot). Not counted as parked again.
pub fn restore(cleanups: Vec<Cleanup>) {
    let mut set = lock();
    for c in cleanups {
        if !holds(&set, &c) {
            set.push_back(Parked::new(c));
        }
    }
    evict(&mut set);
}

/// How many cleanups of `kind` are parked.
pub fn pending_count(kind: &str) -> usize {
    lock().iter().filter(|p| p.cleanup.kind() == kind).count()
}

/// What a live session for (SUPI, PSI) means for a cleanup naming that pair.
#[derive(Debug, PartialEq, Eq)]
enum Holder {
    /// No session for the pair: send.
    None,
    /// A session is being created for it (registered, no binding yet): wait.
    Creating,
    /// An established session holds it, on this S-NSSAI.
    Established {
        nsac_admitted: bool,
        sst: u8,
        sd: Option<String>,
    },
}

fn holder(supi: &str, psi: u8) -> Holder {
    let smf = crate::smf_self();
    let Ok(ctx) = smf.read() else {
        return Holder::Creating;
    };
    let bound = ctx.policy_bindings.read().ok().and_then(|m| {
        m.values()
            .find(|b| b.supi == supi && b.psi == psi)
            .map(|b| Holder::Established {
                nsac_admitted: b.nsac_admitted,
                sst: b.sst,
                sd: b.sd.clone(),
            })
    });
    if let Some(established) = bound {
        return established;
    }
    let registered = ctx
        .ue_find_by_supi(supi)
        .and_then(|ue| ctx.sess_find_by_psi(ue.id, psi))
        .is_some();
    if registered {
        Holder::Creating
    } else {
        Holder::None
    }
}

/// How one attempt ended.
#[derive(Debug, PartialEq, Eq)]
enum Attempt {
    Delivered,
    Superseded,
    Refused,
    /// Not sent this pass (a create for the same pair is in flight).
    Deferred,
    Failed,
}

async fn attempt(c: &Cleanup) -> Attempt {
    match c {
        Cleanup::NsacDecrease {
            supi,
            psi,
            sst,
            sd,
            nf_id,
            nsacf,
            plmn,
        } => {
            // R27: in flight FIRST, then the check, then the send. A create for the
            // pair that registers after the check finds this entry and takes the
            // admission over or waits for the DECREASE (`await_release_in_flight_on`),
            // and one that registered before it is seen by the check, so no INCREASE
            // can slip between the two and be counted out.
            let in_flight =
                crate::ReleaseInFlight::begin_with(supi, *psi, Some((*sst, sd.clone())));
            match holder(supi, *psi) {
                // A live session on the SAME S-NSSAI is counted under the entry this
                // would remove (the NSACF keys by UE, PSI and S-NSSAI). One on another
                // slice is not, and the old slice's DECREASE still goes (R27).
                Holder::Established {
                    nsac_admitted: true,
                    sst: live_sst,
                    sd: live_sd,
                } if crate::same_snssai((live_sst, live_sd.as_deref()), (*sst, sd.as_deref())) => {
                    return Attempt::Superseded
                }
                Holder::Creating => return Attempt::Deferred,
                Holder::Established { .. } | Holder::None => {}
            }
            if !in_flight.entry.begin_nsac_decrease() {
                // A create took the admission over meanwhile.
                return Attempt::Superseded;
            }
            let sent = tokio::time::timeout(
                crate::UDM_RELEASE_TIMEOUT,
                crate::nsac_decrease_once(
                    nf_id.as_deref(),
                    nsacf.as_ref(),
                    policy::plmn_ref(plmn),
                    supi,
                    *psi,
                    *sst,
                    sd.as_deref(),
                ),
            )
            .await;
            drop(in_flight);
            if matches!(sent, Ok(true)) {
                Attempt::Delivered
            } else {
                Attempt::Failed
            }
        }
        Cleanup::SmPolicyDelete { sm_policy_id } => {
            let Some(pcf) = policy::resolve_pcf_endpoint().await else {
                return Attempt::Failed;
            };
            match policy::sm_policy_delete(&pcf, sm_policy_id).await {
                Ok(()) => Attempt::Delivered,
                Err(policy::PolicyError::Rejected { status: 404, .. }) => Attempt::Delivered,
                Err(policy::PolicyError::Rejected { status, .. }) if status < 500 => {
                    Attempt::Refused
                }
                Err(_) => Attempt::Failed,
            }
        }
        Cleanup::UecmDeregister { supi, psi } => {
            // As the DECREASE: in flight, check, then send. The serving-SMF record is
            // per PSI, so any session for the pair supersedes it.
            let in_flight = crate::ReleaseInFlight::begin(supi, *psi);
            match holder(supi, *psi) {
                // Its registration replaced the record this would delete.
                Holder::Established { .. } => return Attempt::Superseded,
                Holder::Creating => return Attempt::Deferred,
                Holder::None => {}
            }
            if !crate::udm::enabled() {
                return Attempt::Refused;
            }
            if !in_flight.entry.begin_deregistration() {
                return Attempt::Superseded;
            }
            match tokio::time::timeout(
                crate::UDM_RELEASE_TIMEOUT,
                crate::udm::deregister_serving_smf(supi, *psi),
            )
            .await
            {
                Ok(true) => Attempt::Delivered,
                _ => Attempt::Failed,
            }
        }
        Cleanup::SdmUnsubscribe {
            supi,
            subscription_id,
        } => {
            if !crate::udm::enabled() {
                return Attempt::Refused;
            }
            match tokio::time::timeout(
                crate::UDM_RELEASE_TIMEOUT,
                crate::udm::unsubscribe_sm_data(supi, subscription_id),
            )
            .await
            {
                Ok(true) => Attempt::Delivered,
                _ => Attempt::Failed,
            }
        }
    }
}

/// One reconcile pass: retry the parked cleanups, oldest first, for at most
/// [`MAX_PASS`]. One older than [`MAX_AGE`] ends as `expired`.
///
/// #1961: once a cleanup to a peer fails, that peer backs off and its other
/// cleanups are not tried this pass (nor until the backoff ends); one tried and
/// failed goes to the BACK of the queue, one deferred or not reached keeps its
/// place at the FRONT. Returns how many ended.
pub async fn reconcile_once() -> usize {
    let batch: Vec<Parked> = lock().drain(..).collect();
    if batch.is_empty() {
        return 0;
    }
    let deadline = tokio::time::Instant::now() + MAX_PASS;
    let mut ended = 0;
    let mut untried = Vec::new();
    let mut failed = Vec::new();
    for p in batch {
        let c = &p.cleanup;
        if p.since.elapsed().unwrap_or_default() > MAX_AGE {
            log::error!("{}: expired after {MAX_AGE:?}", c.describe());
            RECONCILED.inc(&[c.kind(), "expired"]);
            ended += 1;
            continue;
        }
        let peer = peer_of(c);
        if tokio::time::Instant::now() >= deadline || backing_off(&peer) {
            untried.push(p);
            continue;
        }
        let result = match attempt(c).await {
            Attempt::Delivered => "delivered",
            Attempt::Superseded => "superseded",
            Attempt::Refused => "refused",
            Attempt::Deferred => {
                untried.push(p);
                continue;
            }
            Attempt::Failed => {
                note_failure(&peer);
                failed.push(p);
                continue;
            }
        };
        note_success(&peer);
        log::info!("{}: reconciled ({result})", c.describe());
        RECONCILED.inc(&[c.kind(), result]);
        ended += 1;
    }
    {
        let mut set = lock();
        // Not reached or deferred: back at the FRONT, in order (older than anything
        // parked while this pass ran, and eviction takes the oldest). Tried and
        // failed: at the BACK.
        for p in untried.into_iter().rev() {
            if !holds(&set, &p.cleanup) {
                set.push_front(p);
            }
        }
        for p in failed {
            if !holds(&set, &p.cleanup) {
                set.push_back(p);
            }
        }
        evict(&mut set);
    }
    if ended > 0 {
        persist();
    }
    ended
}

/// Run [`reconcile_once`] every [`RECONCILE_PERIOD`] for the life of the process.
pub fn spawn_reconciler() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async {
        let mut timer = tokio::time::interval(RECONCILE_PERIOD);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick is immediate; consume it so the first pass is a period in.
        timer.tick().await;
        loop {
            timer.tick().await;
            reconcile_once().await;
        }
    })
}

/// The reconciler's families, for `/metrics`.
pub fn render(out: &mut String) {
    use std::fmt::Write as _;
    nextgcore_metrics::nf::write_header(
        out,
        "smf_release_cleanups_pending",
        "gauge",
        "Release-side cleanups parked for the reconciler, by kind",
    );
    for kind in KINDS {
        let _ = writeln!(
            out,
            "smf_release_cleanups_pending{{kind=\"{kind}\"}} {}",
            pending_count(kind)
        );
    }
    PARKED.render(out);
    RECONCILED.render(out);
}

/// Forget every parked cleanup (a test's own, before and after it).
#[cfg(test)]
pub fn clear_for_test() {
    lock().clear();
    backoff().lock().unwrap_or_else(|e| e.into_inner()).clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_delete(n: usize) -> Cleanup {
        Cleanup::SmPolicyDelete {
            sm_policy_id: format!("pol-bound-1875-{n}"),
        }
    }

    /// #1875: the set is bounded. Parking past [`MAX_PENDING`] evicts the OLDEST,
    /// counted `abandoned`; a record already parked is not parked twice.
    ///
    /// REVERT-VERIFIED: with `evict` a no-op, this fails: the set holds
    /// MAX_PENDING + 1 and nothing is abandoned.
    #[tokio::test]
    async fn the_parked_set_is_bounded_and_evicts_the_oldest_1875() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        clear_for_test();
        let abandoned = || RECONCILED.get(&["sm_policy_delete", "abandoned"]);
        let before = abandoned();

        for n in 0..=MAX_PENDING {
            park(policy_delete(n));
        }
        park(policy_delete(MAX_PENDING));
        let held = snapshot();
        clear_for_test();

        assert_eq!(held.len(), MAX_PENDING, "bounded");
        assert_eq!(abandoned() - before, 1, "one abandoned");
        assert!(!held.contains(&policy_delete(0)), "the oldest went");
        assert_eq!(held.first(), Some(&policy_delete(1)));
        assert_eq!(
            held.last(),
            Some(&policy_delete(MAX_PENDING)),
            "parked once"
        );
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

    fn decrease_at(port: u16, n: usize) -> Cleanup {
        Cleanup::NsacDecrease {
            supi: format!("imsi-00101000001961{n}"),
            psi: 5,
            sst: 1,
            sd: None,
            nf_id: Some("smf-1961".into()),
            nsacf: Some(policy::NsacfEndpoint {
                host: "127.0.0.1".into(),
                port,
            }),
            plmn: None,
        }
    }

    /// #1961: DECREASEs toward a blackholed NSACF ahead of one toward a healthy
    /// NSACF no longer starve it: the healthy one is delivered within two passes,
    /// and the blackholed ones stay parked.
    /// REVERT-VERIFIED: with the old order restored (every not-ended cleanup
    /// re-parked at the front, no backoff), the healthy DECREASE is never reached
    /// and "the healthy NSACF gets its DECREASE" fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_blackholed_nsacf_does_not_starve_a_healthy_one_1961() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        clear_for_test();
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = hits.clone();
        let (srv, addr) = nextgcore_sbi::test_support::sbi_server_on_free_port(
            move |_req: nextgcore_sbi::message::SbiRequest| {
                let seen = seen.clone();
                async move {
                    seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    nextgcore_sbi::message::SbiResponse::with_status(204)
                }
            },
        )
        .await;
        let dead = blackhole_1961();
        for n in 0..3 {
            park(decrease_at(dead, n));
        }
        park(decrease_at(addr.port(), 9));
        let delivered = || RECONCILED.get(&["nsac_decrease", "delivered"]);
        let before = delivered();
        for _ in 0..2 {
            reconcile_once().await;
        }
        let got = delivered() - before;
        let left = snapshot();
        clear_for_test();
        let _ = tokio::time::timeout(Duration::from_secs(1), srv.stop()).await;
        assert_eq!(got, 1, "the healthy NSACF gets its DECREASE");
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(left.len(), 3, "the blackholed ones stay parked: {left:?}");
    }

    /// #1961: a cleanup parked longer than [`MAX_AGE`] ends as `expired`.
    /// REVERT-VERIFIED: with the age check removed it is attempted instead and
    /// stays parked.
    #[tokio::test]
    async fn a_cleanup_older_than_max_age_expires_1961() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        clear_for_test();
        park(decrease_at(9, 7));
        lock()[0].since = std::time::SystemTime::now() - MAX_AGE - Duration::from_secs(1);
        let expired = || RECONCILED.get(&["nsac_decrease", "expired"]);
        let before = expired();
        reconcile_once().await;
        let got = expired() - before;
        let left = snapshot().len();
        clear_for_test();
        assert_eq!((got, left), (1, 0));
    }

    /// #1875: every kind survives a JSON round trip in the shape the snapshot
    /// writes, tagged by kind.
    #[test]
    fn a_cleanup_round_trips_through_the_snapshot_shape_1875() {
        let all = vec![
            Cleanup::NsacDecrease {
                supi: "imsi-1".into(),
                psi: 5,
                sst: 1,
                sd: Some("010203".into()),
                nf_id: Some("smf-1".into()),
                nsacf: Some(policy::NsacfEndpoint {
                    host: "127.0.0.1".into(),
                    port: 7777,
                }),
                plmn: Some(("001".into(), "01".into())),
            },
            Cleanup::SmPolicyDelete {
                sm_policy_id: "pol-1".into(),
            },
            Cleanup::UecmDeregister {
                supi: "imsi-1".into(),
                psi: 5,
            },
            Cleanup::SdmUnsubscribe {
                supi: "imsi-1".into(),
                subscription_id: "sub-1".into(),
            },
        ];
        let json = serde_json::to_value(&all).unwrap();
        assert_eq!(json[0]["kind"], "nsacDecrease");
        assert_eq!(json[3]["subscriptionId"], "sub-1");
        let back: Vec<Cleanup> = serde_json::from_value(json).unwrap();
        assert_eq!(back, all);
    }
}
