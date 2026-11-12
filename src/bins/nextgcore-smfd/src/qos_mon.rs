//! `QOS_MON` event exposure through per QoS flow QoS monitoring (#1390).
//!
//! A consumer subscribing to `QOS_MON` (TS 29.508 §4.2.2.2) for a UE gets the
//! packet delays of the QoS flow of its PDU session's default QoS rule measured
//! between the PSA UPF and the UE (TS 23.501 §5.33.3.2):
//! - **N4.** One SRR per subscription and session (TS 29.244 §5.39.2: separate
//!   SRRs for separate requesters), with one QoS Monitoring per QoS flow Control
//!   Information (IE 242) for the default QFI: DL, UL and round-trip packet
//!   delay, Periodic, Measurement Period = the subscription's `repPeriod` (or
//!   [`DEFAULT_PERIOD_SECS`]). Only toward a UPF that advertised QFQM (§5.24.4.1).
//! - **N2.** The flow's QoS Monitoring Request (TS 38.413 §9.3.1.12, id 181)
//!   `both` in a PDU Session Resource Modify Request Transfer (TS 23.502 §4.3.3.2
//!   step 3b, with the N1 PDU SESSION MODIFICATION COMMAND restating the
//!   Session-AMBR, as every SMF-requested modification here does), and `stop`
//!   when the last subscription goes. While monitored, every Setup Request
//!   Transfer of the session (re-activation, handover) carries `both` again.
//! - **Reports.** A Session Report Request with SESR (§5.24.4.3) is mapped, by
//!   SRR ID, to its subscription and sent as an `Nsmf_EventExposure_Notify`
//!   QOS_MON with `ulDelays` / `dlDelays` / `rtDelays` (one element each,
//!   §4.2.3.2 item 12 NOTE 8), or `pdmf` for a measurement failure.
//!
//! No `QOS_MON` subscription, or one that did not negotiate the QoSMonitoring
//! feature (TS 29.508 Table 5.8-1): nothing is requested on N4 or N2.
//!
//! Lifecycle (#1390 review): an SRR is reserved before its Create is awaited, so
//! concurrent installs on a session take distinct SRR IDs; the task with an N4
//! request in flight for an SRR owns it and, when the request returns, settles it
//! against the subscription as stored then (Update SRR on a new `repPeriod`,
//! Remove SRR when the subscription is gone or no longer covers the session). A
//! PUT reconciles the SRRs it holds the same way.
//! The RAN leg is serialised per session: one task sends the QoS Monitoring
//! Requests, awaiting each N1N2MessageTransfer (with its 409 retries) and
//! re-deciding when it returns, and sends T3591's retransmissions too, so the
//! last request the AMF receives matches the session's SRRs.
//!
//! Not modelled, stated: the PCC-rule path (TS 29.512 QosMonitoringData, the
//! UPEAS `appIds` / `defQosSupp` matching), Event Triggered reporting with
//! thresholds (they come with that path), and direct UPF reporting (DRQOS).

use std::collections::HashMap;
use std::sync::Mutex;

use crate::event_exposure::{self, EventSubscription, QosMonResult};
use crate::n2_transfer::QosMonitoringRequest;
use nextgcore_pfcp::qos_monitoring::{
    QosMonitoringMeasurement, QosMonitoringPerQosFlowControlInformation, QosMonitoringReport,
    ReportingFrequency, RequestedQosMonitoring, TypedIe,
};

/// The Measurement Period when the subscription names no `repPeriod`.
pub const DEFAULT_PERIOD_SECS: u32 = 10;

/// How long the SMF waits after the user plane activates before the
/// SMF-requested modification that turns monitoring on, so the AMF has finished
/// the PDU Session Resource Setup it is in the middle of.
const AFTER_ACTIVATION: std::time::Duration = std::time::Duration::from_millis(500);

/// Where an SRR is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SrrState {
    /// Reserved: a task owns it and has an N4 request for it in flight (Create,
    /// Update or Remove). When that returns, the owner reconciles it with the
    /// subscription as it is then ([`settle`]); nobody else sends N4 for it.
    Pending,
    /// At the UPF with `period`; no N4 request in flight.
    Installed,
    /// Its Remove SRR is in flight (#1390 review round 2). The entry keeps its
    /// SRR ID until the Remove returns, so no install can reuse the ID and have
    /// its Create overtaken by this Remove at the UPF. It serves nobody.
    Removing,
}

/// One SRR of a session: the subscription it serves.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Srr {
    sub: String,
    id: u8,
    /// The Measurement Period last sent to the UPF, in seconds.
    period: u32,
    state: SrrState,
    /// The subscription changed (PUT, DELETE) while the SRR was [`Pending`]:
    /// its owner looks again before settling it.
    ///
    /// [`Pending`]: SrrState::Pending
    recheck: bool,
}

/// The monitoring of one session: its SRRs, one per subscription.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SessionMon {
    srrs: Vec<Srr>,
    /// The NG-RAN was last asked to measure (`both`), not to stop.
    ran_on: bool,
    /// An N2 QoS Monitoring Request was held back by another 5GSM procedure:
    /// sent when the session is idle again ([`on_gsm_idle`]).
    n2_deferred: bool,
    /// A task owns the session's RAN leg ([`drive_ran`]): it alone sends the
    /// QoS Monitoring Requests, one awaited N1N2MessageTransfer at a time, so
    /// they reach the AMF in the order they were decided (#1390 review round 3).
    n2_busy: bool,
    /// `both` must be sent even if the NG-RAN was last asked for it: a new gNB
    /// (Xn path switch), or a request held back.
    n2_force: bool,
    /// T3591 expired at this attempt (#1390 review round 4): [`drive_ran`]
    /// resends the armed request, unless a newer one goes out first.
    n2_retransmit: Option<u32>,
}

impl SessionMon {
    fn installed(&self) -> bool {
        self.srrs.iter().any(|e| e.state == SrrState::Installed)
    }

    /// Whether an SRR is installed or being installed: the NG-RAN must not be
    /// told to stop.
    fn live(&self) -> bool {
        self.srrs.iter().any(|e| e.state != SrrState::Removing)
    }

    /// Whether `sub` holds an SRR that is not being removed.
    fn serves(&self, sub: &str) -> bool {
        self.srrs
            .iter()
            .any(|e| e.sub == sub && e.state != SrrState::Removing)
    }

    fn position(&self, sub: &str, id: u8) -> Option<usize> {
        self.srrs.iter().position(|e| e.sub == sub && e.id == id)
    }
}

/// Monitored sessions, by SM context reference. Its lock is the mutex itself;
/// tests that touch it hold [`TEST_LOCK`], declared beside it.
static SESSIONS: Mutex<Option<HashMap<String, SessionMon>>> = Mutex::new(None);

/// Serialises tests that touch [`SESSIONS`] (one lock per process-global).
#[cfg(test)]
pub(crate) static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn with<T>(f: impl FnOnce(&mut HashMap<String, SessionMon>) -> T) -> T {
    let mut g = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(HashMap::new))
}

/// Drop a session's entry once it holds nothing.
fn tidy(m: &mut HashMap<String, SessionMon>, r: &str) {
    if m.get(r).is_some_and(|s| {
        s.srrs.is_empty() && !s.ran_on && !s.n2_deferred && !s.n2_busy && s.n2_retransmit.is_none()
    }) {
        m.remove(r);
    }
}

/// Whether the session's default flow is monitored: its Setup Request Transfers
/// then carry the QoS Monitoring Request.
pub fn active_on(sm_context_ref: &str) -> bool {
    with(|m| m.get(sm_context_ref).is_some_and(SessionMon::installed))
}

/// The session is released: its SRRs went with the N4 session.
pub fn forget(sm_context_ref: &str) {
    with(|m| m.remove(sm_context_ref));
}

/// The [`drive_ran`] tasks running, for tests: one must not outlive its test,
/// whose locks guard the 5GSM timers it arms (#723).
#[cfg(test)]
static DRIVES_FOR_TEST: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Wait until no [`drive_ran`] task runs, for tests to call before they
/// release their locks. Panics after 15 s: a drive that hangs is a failure, not
/// something to wait out (#1390 review round 4).
#[cfg(test)]
pub(crate) async fn quiesce_for_test() {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while DRIVES_FOR_TEST.load(std::sync::atomic::Ordering::SeqCst) > 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "a qos_mon RAN-leg task still runs after 15 s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// Whether no task is sending the session's QoS Monitoring Requests, for tests.
#[cfg(test)]
pub(crate) fn ran_idle_for_test(sm_context_ref: &str) -> bool {
    with(|m| m.get(sm_context_ref).is_none_or(|s| !s.n2_busy))
}

#[cfg(test)]
pub(crate) fn clear_for_test() {
    with(|m| m.clear());
}

/// The SRR IDs installed on a session (sorted), for tests and logs.
pub fn srr_ids(sm_context_ref: &str) -> Vec<u8> {
    let mut v: Vec<u8> = with(|m| {
        m.get(sm_context_ref)
            .map(|s| {
                s.srrs
                    .iter()
                    .filter(|e| e.state == SrrState::Installed)
                    .map(|e| e.id)
                    .collect()
            })
            .unwrap_or_default()
    });
    v.sort_unstable();
    v
}

/// The subscription an SRR of a session reports for.
fn subscription_of(sm_context_ref: &str, srr_id: u8) -> Option<String> {
    with(|m| {
        m.get(sm_context_ref)?
            .srrs
            .iter()
            .find(|e| e.id == srr_id && e.state != SrrState::Removing)
            .map(|e| e.sub.clone())
    })
}

/// The IE 242 of a subscription's SRR for the session's default `qfi`.
pub fn control_for(qfi: u8, period_secs: u32) -> QosMonitoringPerQosFlowControlInformation {
    QosMonitoringPerQosFlowControlInformation {
        qfis: vec![qfi],
        requested_qos_monitoring: RequestedQosMonitoring {
            dlpd: true,
            ulpd: true,
            rppd: true,
            ..Default::default()
        },
        reporting_frequency: ReportingFrequency {
            evett: false,
            perio: true,
        },
        packet_delay_thresholds: None,
        minimum_wait_time: None,
        measurement_period: Some(period_secs),
        extra: Vec::new(),
    }
}

/// Whether `sub` asks for QoS monitoring this SMF can report: QOS_MON, with
/// the QoSMonitoring feature negotiated (TS 29.508 §4.2.3.2 item 12: the delays
/// are reported "if the QoSMonitoring feature is supported").
fn monitors(sub: &EventSubscription) -> bool {
    sub.events
        .iter()
        .any(|e| e == event_exposure::event::QOS_MON)
        && sub.supports(event_exposure::feature::QOS_MONITORING)
}

/// Whether `sub` monitors the session `r` (its SUPI / PDU session filters).
fn covers(sub: &EventSubscription, r: &str) -> bool {
    monitors(sub)
        && crate::lookup_policy_binding(r)
            .is_some_and(|b| sub.matches(event_exposure::event::QOS_MON, &b.supi, b.psi))
}

/// The Measurement Period `sub` asks for.
fn period_of(sub: &EventSubscription) -> u32 {
    event_exposure::periodic_rep_period(sub).unwrap_or(DEFAULT_PERIOD_SECS)
}

/// What the SRR serving `sub_id` on `r` should be now: its Measurement Period,
/// or `None` when it should not exist (the subscription is gone, no longer asks
/// for QoS monitoring, or no longer covers the session).
fn desired(sub_id: &str, r: &str) -> Option<u32> {
    event_exposure::find(sub_id)
        .filter(|sub| covers(sub, r))
        .map(|sub| period_of(&sub))
}

/// The sessions (SM context references, sorted) a QOS_MON subscription covers.
fn sessions_for(sub: &EventSubscription) -> Vec<String> {
    let mut v: Vec<String> = crate::context::smf_self()
        .read()
        .ok()
        .and_then(|ctx| {
            ctx.policy_bindings.read().ok().map(|b| {
                b.iter()
                    .filter(|(_, pb)| sub.matches(event_exposure::event::QOS_MON, &pb.supi, pb.psi))
                    .map(|(r, _)| r.clone())
                    .collect()
            })
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// A new QOS_MON subscription: monitoring on every session it covers that has
/// its user plane.
pub async fn subscribed(sub: &EventSubscription) {
    if !sub
        .events
        .iter()
        .any(|e| e == event_exposure::event::QOS_MON)
    {
        return;
    }
    if !monitors(sub) {
        log::info!(
            "QOS_MON subscription {} did not negotiate the QoSMonitoring feature (TS 29.508 \
             §4.2.3.2 item 12, Table 5.8-1): stored, but nothing can be reported to it",
            sub.id
        );
        return;
    }
    for r in sessions_for(sub) {
        install(&r, sub).await;
        want_ran(&r, false);
    }
}

/// A QOS_MON subscription was replaced (PUT, #1390 review M2): the SRRs it holds
/// are reconciled with the new document (removed where it no longer covers the
/// session or asks for QOS_MON, updated where the period changed), and the
/// sessions it newly covers are installed.
pub async fn replaced(sub: &EventSubscription) {
    reconcile(&sub.id).await;
    subscribed(sub).await;
}

/// A QOS_MON subscription is gone (DELETE): its SRRs are removed, and the
/// NG-RAN is told to stop where no other remains.
pub async fn unsubscribed(sub_id: &str) {
    reconcile(sub_id).await;
}

/// Bring every SRR serving `sub_id` in line with the subscription as stored now.
/// An SRR another task owns ([`SrrState::Pending`]) is flagged for its owner to
/// look again; the rest are taken over and settled here.
async fn reconcile(sub_id: &str) {
    let mine: Vec<(String, u8, u32)> = with(|m| {
        let mut out = Vec::new();
        for (r, s) in m.iter_mut() {
            for e in s.srrs.iter_mut().filter(|e| e.sub == sub_id) {
                match e.state {
                    SrrState::Pending => e.recheck = true,
                    SrrState::Installed => {
                        e.state = SrrState::Pending;
                        out.push((r.clone(), e.id, e.period));
                    }
                    SrrState::Removing => {}
                }
            }
        }
        out
    });
    for (r, id, period) in mine {
        settle(&r, sub_id, id, period).await;
    }
}

/// The session's user plane is active (a PDU Session Resource Setup Response):
/// QOS_MON subscriptions covering it that it is not monitored for yet are
/// installed, and the NG-RAN told.
pub fn on_user_plane_active(sm_context_ref: &str) {
    let Some(b) = crate::lookup_policy_binding(sm_context_ref) else {
        return;
    };
    let subs: Vec<EventSubscription> =
        event_exposure::matching(event_exposure::event::QOS_MON, &b.supi, b.psi)
            .into_iter()
            .filter(monitors)
            .collect();
    if subs.is_empty() {
        return;
    }
    let r = sm_context_ref.to_string();
    tokio::spawn(async move {
        tokio::time::sleep(AFTER_ACTIVATION).await;
        let mut any = false;
        for sub in &subs {
            any |= install(&r, sub).await;
        }
        want_ran(&r, any);
    });
}

/// An Xn handover moved the session to another gNB (PATH_SWITCH_REQ, #1390
/// review m6). The Path Switch Request Acknowledge Transfer carries no QoS flow
/// parameters, and the target learns the source's QoS Monitoring Request only if
/// its XnAP carried it, so a monitored session asks the new gNB again (after
/// [`AFTER_ACTIVATION`], so the AMF has finished the path switch).
pub fn on_path_switch(sm_context_ref: &str) {
    if !active_on(sm_context_ref) {
        return;
    }
    let r = sm_context_ref.to_string();
    tokio::spawn(async move {
        tokio::time::sleep(AFTER_ACTIVATION).await;
        want_ran(&r, true);
    });
}

/// The QoS Monitoring Request the session's NG-RAN needs now, from its SRRs
/// under the lock: `both` while one is installed (unless the NG-RAN was last
/// asked for it, and nothing forces a resend), `stop` once none is installed or
/// being installed and the NG-RAN was measuring, else nothing. An SRR still
/// being installed asks again when it settles.
fn ran_wanted(s: &mut SessionMon) -> Option<QosMonitoringRequest> {
    if s.installed() {
        let force = std::mem::take(&mut s.n2_force);
        (force || !s.ran_on).then_some(QosMonitoringRequest::Both)
    } else {
        s.n2_force = false;
        (s.ran_on && !s.live()).then_some(QosMonitoringRequest::Stop)
    }
}

/// The session's SRRs changed (or its gNB did, `force`): bring the NG-RAN in
/// line (#1390 review round 3). One task per session sends, awaiting each
/// N1N2MessageTransfer and looking again when it returns, so a `stop` decided
/// before a `both` cannot reach the AMF after it, and the last request sent
/// always matches [`active_on`].
fn want_ran(r: &str, force: bool) {
    claim_ran(r, |s| s.n2_force |= force);
}

/// T3591 expired for the session's QoS Monitoring Request at `attempt` (#1390
/// review round 4): its owner resends it, after the transfer it may have in
/// flight, so a retransmission of an older request cannot reach the AMF after a
/// newer one.
pub fn retransmit_due(r: &str, attempt: u32) {
    claim_ran(r, |s| s.n2_retransmit = Some(attempt));
}

/// Note what the session's RAN leg needs (`note`) and start its owner,
/// [`drive_ran`], unless one runs: it sees the note on its next pass.
fn claim_ran(r: &str, note: impl FnOnce(&mut SessionMon)) {
    let start = with(|m| {
        let s = m.entry(r.to_string()).or_default();
        note(s);
        let start = !s.n2_busy;
        s.n2_busy = true;
        start
    });
    if start {
        let r = r.to_string();
        #[cfg(test)]
        DRIVES_FOR_TEST.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        tokio::spawn(async move {
            drive_ran(&r).await;
            #[cfg(test)]
            DRIVES_FOR_TEST.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        });
    }
}

/// One step of [`drive_ran`].
enum RanStep {
    /// Decide and send this request.
    Send(QosMonitoringRequest),
    /// Resend T3591's armed request at this attempt.
    Resend(u32),
}

/// The task owning a session's RAN leg (see [`want_ran`]).
async fn drive_ran(r: &str) {
    loop {
        let step = with(|m| {
            let s = m.get_mut(r)?;
            // A new request supersedes a due retransmission: it re-arms T3591.
            if let Some(want) = ran_wanted(s) {
                s.n2_retransmit = None;
                return Some(RanStep::Send(want));
            }
            if let Some(attempt) = s.n2_retransmit.take() {
                return Some(RanStep::Resend(attempt));
            }
            s.n2_busy = false;
            tidy(m, r);
            None
        });
        let want = match step {
            None => return,
            Some(RanStep::Resend(attempt)) => {
                crate::retransmit_qos_monitoring(r, attempt).await;
                continue;
            }
            Some(RanStep::Send(want)) => want,
        };
        let outcome = crate::signal_qos_monitoring(r, want).await;
        let stop = with(|m| {
            let Some(s) = m.get_mut(r) else {
                return true;
            };
            match outcome {
                crate::QosMonitoringSignal::Sent => {
                    s.ran_on = want == QosMonitoringRequest::Both;
                    s.n2_deferred = false;
                    false
                }
                // m5: sent from `on_gsm_idle` once the procedure ends.
                crate::QosMonitoringSignal::Deferred | crate::QosMonitoringSignal::NotSent => {
                    s.n2_deferred |= outcome == crate::QosMonitoringSignal::Deferred;
                    // A retransmission that fell due meanwhile is dropped with
                    // the owner: Deferred means another procedure replaced T3591,
                    // and otherwise its next expiry asks again.
                    s.n2_retransmit = None;
                    s.n2_busy = false;
                    tidy(m, r);
                    true
                }
            }
        });
        if stop {
            // Review round 4 m3: the procedure that held the request back may
            // have ended before `n2_deferred` was set, its `on_gsm_idle` finding
            // nothing to send. Looked at again now it is set: either that call
            // or this one sends it.
            if outcome == crate::QosMonitoringSignal::Deferred
                && !crate::qos_monitoring_held_back(r)
            {
                on_gsm_idle(r);
            }
            return;
        }
    }
}

/// The session's 5GSM procedure ended (its T3591 / T3592 stopped or was
/// exhausted, #1390 review m5): an N2 QoS Monitoring Request it held back is
/// sent now, for what the session needs then: `both` while an SRR is installed,
/// `stop` if the NG-RAN was measuring and none is.
pub fn on_gsm_idle(sm_context_ref: &str) {
    let deferred = with(|m| {
        m.get_mut(sm_context_ref)
            .is_some_and(|s| std::mem::take(&mut s.n2_deferred))
    });
    if deferred {
        log::info!(
            "ref={sm_context_ref}: the 5GSM procedure ended; sending the QoS Monitoring \
             Request it held back"
        );
        want_ran(sm_context_ref, true);
    }
}

/// Install `sub`'s SRR on the session, unless it has one already. Returns
/// whether it was newly installed.
async fn install(sm_context_ref: &str, sub: &EventSubscription) -> bool {
    if with(|m| m.get(sm_context_ref).is_some_and(|s| s.serves(&sub.id))) {
        return false;
    }
    let Some(b) = crate::lookup_policy_binding(sm_context_ref) else {
        return false;
    };
    let Some(upf_seid) = crate::lookup_upf_seid(sm_context_ref) else {
        log::info!("ref={sm_context_ref}: no N4 session yet; QoS monitoring waits for it");
        return false;
    };
    let smf_seid = crate::smf_n4_seid_for(sm_context_ref);
    let Some(client) = crate::pfcp_path::client_for_session(smf_seid) else {
        return false;
    };
    if !client
        .association()
        .await
        .up_function_features
        .is_some_and(|f| f.qfqm)
    {
        log::warn!(
            "ref={sm_context_ref}: QOS_MON subscription {} but {} did not advertise QFQM \
             (TS 29.244 §5.24.4.1): no QoS monitoring requested",
            sub.id,
            client.peer()
        );
        return false;
    }
    let period = period_of(sub);
    // #1390 review M1: the SRR ID is reserved under the lock, before the N4
    // request is awaited, so a concurrent install on the session (another
    // subscription, or the same one from a PDU_RES_SETUP_RSP) picks another.
    let reserved = with(|m| {
        let s = m.entry(sm_context_ref.to_string()).or_default();
        if s.serves(&sub.id) {
            return Err(None);
        }
        // An ID whose Remove SRR is still in flight (Removing) is not free.
        let id = (1..=u8::MAX)
            .find(|id| !s.srrs.iter().any(|e| e.id == *id))
            .ok_or(Some(()))?;
        s.srrs.push(Srr {
            sub: sub.id.clone(),
            id,
            period,
            state: SrrState::Pending,
            recheck: false,
        });
        Ok(id)
    });
    let srr_id = match reserved {
        Ok(id) => id,
        Err(None) => return false,
        Err(Some(())) => {
            log::warn!(
                "ref={sm_context_ref}: no free SRR ID for subscription {}",
                sub.id
            );
            return false;
        }
    };
    let params = crate::n4_build::SessionModificationParams {
        create_srrs: vec![(srr_id, vec![control_for(b.qfi, period)])],
        ..Default::default()
    };
    match crate::pfcp_modify_with(smf_seid, upf_seid, &params).await {
        Ok(_) => {
            log::info!(
                "ref={sm_context_ref}: QoS monitoring of QFI {} requested from the UPF: SRR \
                 {srr_id}, Periodic every {period} s (QOS_MON subscription {})",
                b.qfi,
                sub.id
            );
            // #1390 review M3: a DELETE (or a PUT) may have come while the Create
            // was in flight: settle against the subscription as it is now.
            settle(sm_context_ref, &sub.id, srr_id, period).await
        }
        Err(e) => {
            log::warn!(
                "ref={sm_context_ref}: Create SRR for QOS_MON subscription {} failed: {e}",
                sub.id
            );
            // The reservation is rolled back.
            with(|m| {
                if let Some(s) = m.get_mut(sm_context_ref) {
                    if let Some(i) = s.position(&sub.id, srr_id) {
                        s.srrs.remove(i);
                    }
                }
                tidy(m, sm_context_ref);
            });
            // Another removal may have held back its `stop` for this install.
            if with(|m| m.get(sm_context_ref).is_some_and(|s| s.ran_on)) {
                want_ran(sm_context_ref, false);
            }
            false
        }
    }
}

/// What [`settle`] does next with an SRR it owns.
enum Next {
    /// It matches the subscription: installed.
    Done,
    /// The subscription wants another period.
    Update(u32),
    /// The subscription no longer wants it: Remove SRR (the entry is
    /// [`SrrState::Removing`] until it returns).
    Remove,
    /// The session forgot it (released): nothing to send.
    Gone,
}

/// How many Updates [`settle`] follows before it stops chasing a subscription
/// replaced faster than the UPF answers.
const SETTLE_PASSES: usize = 8;

/// Settle the SRR `id` serving `sub_id` on `r`, owned by the caller (state
/// [`SrrState::Pending`]) with `sent` the period the UPF holds: Update SRR
/// while the subscription wants another period, Remove SRR (and `stop` to the
/// NG-RAN when the session has no other SRR installed or being installed) when
/// it wants none. Returns whether the SRR ends installed.
async fn settle(r: &str, sub_id: &str, id: u8, mut sent: u32) -> bool {
    for pass in 0..=SETTLE_PASSES {
        let want = desired(sub_id, r);
        let last_pass = pass == SETTLE_PASSES;
        let next = with(|m| {
            let Some(s) = m.get_mut(r) else {
                return Next::Gone;
            };
            let Some(i) = s.position(sub_id, id) else {
                return Next::Gone;
            };
            let e = &mut s.srrs[i];
            if std::mem::take(&mut e.recheck) && !last_pass {
                // The subscription changed after `want` was read: read it again.
                return Next::Update(sent);
            }
            match want {
                // The last pass settles on what the UPF holds (review round 2
                // minor: but never keeps an SRR nobody wants).
                Some(p) if p == sent || last_pass => {
                    e.state = SrrState::Installed;
                    e.period = sent;
                    Next::Done
                }
                Some(p) => Next::Update(p),
                None => {
                    e.state = SrrState::Removing;
                    Next::Remove
                }
            }
        });
        match next {
            Next::Done => return true,
            Next::Gone => return false,
            Next::Update(p) if p == sent => continue,
            Next::Update(p) => {
                if send_update(r, id, p).await {
                    log::info!(
                        "ref={r}: QoS monitoring SRR {id} now Periodic every {p} s \
                         (subscription {sub_id} replaced)"
                    );
                    sent = p;
                }
                // A failed Update leaves the UPF on `sent`: settled there, and the
                // next PUT tries again.
                else if with(|m| {
                    m.get_mut(r)
                        .and_then(|s| {
                            let i = s.position(sub_id, id)?;
                            s.srrs[i].period = sent;
                            s.srrs[i].state = SrrState::Installed;
                            Some(())
                        })
                        .is_some()
                }) {
                    return true;
                }
            }
            Next::Remove => {
                send_remove(r, id, sub_id).await;
                // #1390 review round 2: only now is the SRR ID free, and `stop`
                // is decided now, counting SRRs installed or being installed.
                let known = with(|m| {
                    let Some(s) = m.get_mut(r) else {
                        return false;
                    };
                    if let Some(i) = s.position(sub_id, id) {
                        s.srrs.remove(i);
                    }
                    true
                });
                // `stop` if this was the last SRR installed or being installed.
                if known {
                    want_ran(r, false);
                }
                return false;
            }
        }
    }
    unreachable!("the last pass always settles")
}

/// Update SRR `id` on `r` to `period` (TS 29.244 Table 7.5.4.20-1).
async fn send_update(r: &str, id: u8, period: u32) -> bool {
    let (Some(b), Some(upf_seid)) = (crate::lookup_policy_binding(r), crate::lookup_upf_seid(r))
    else {
        return false;
    };
    let params = crate::n4_build::SessionModificationParams {
        update_srrs: vec![(id, vec![control_for(b.qfi, period)])],
        ..Default::default()
    };
    match crate::pfcp_modify_with(crate::smf_n4_seid_for(r), upf_seid, &params).await {
        Ok(_) => true,
        Err(e) => {
            log::warn!("ref={r}: Update SRR {id} failed: {e}");
            false
        }
    }
}

/// Remove SRR `id` on `r` (TS 29.244 Table 7.5.4.19-1).
async fn send_remove(r: &str, id: u8, sub_id: &str) {
    let params = crate::n4_build::SessionModificationParams {
        remove_srr_ids: vec![id],
        ..Default::default()
    };
    let Some(upf_seid) = crate::lookup_upf_seid(r) else {
        return;
    };
    match crate::pfcp_modify_with(crate::smf_n4_seid_for(r), upf_seid, &params).await {
        Ok(_) => log::info!("ref={r}: QoS monitoring SRR {id} removed (subscription {sub_id})"),
        Err(e) => {
            log::warn!("ref={r}: Remove SRR {id} (QOS_MON subscription {sub_id}) failed: {e}")
        }
    }
}

/// The QoS Monitoring Reports of a Session Report Request with SESR (Table
/// 7.5.8.6-1): (SRR ID, report), in order. A malformed one is skipped.
pub fn reports_in(payload: &[u8]) -> Vec<(u8, QosMonitoringReport)> {
    let mut out = Vec::new();
    for sr in ies(payload, crate::n4_build::pfcp_ie::SESSION_REPORT) {
        let Some(srr_id) = ies(&sr, crate::n4_build::pfcp_ie::SRR_ID)
            .first()
            .and_then(|v| v.first().copied())
        else {
            log::warn!("Session Report IE without an SRR ID: skipped");
            continue;
        };
        for v in ies(&sr, QosMonitoringReport::IE_TYPE as u16) {
            match QosMonitoringReport::decode_value(&v) {
                Ok(r) => out.push((srr_id, r)),
                Err(e) => log::warn!("SRR {srr_id}: malformed QoS Monitoring Report: {e}"),
            }
        }
    }
    out
}

/// The values of every top-level IE of `ie_type` in `data`.
fn ies(data: &[u8], ie_type: u16) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 4 <= data.len() {
        let t = u16::from_be_bytes([data[at], data[at + 1]]);
        let l = u16::from_be_bytes([data[at + 2], data[at + 3]]) as usize;
        let end = at + 4 + l;
        if end > data.len() {
            break;
        }
        if t == ie_type {
            out.push(data[at + 4..end].to_vec());
        }
        at = end;
    }
    out
}

/// A report's measurement as a QOS_MON result.
pub fn result_of(m: &QosMonitoringMeasurement) -> QosMonResult {
    QosMonResult {
        ul_delay: m.uplink_packet_delay,
        dl_delay: m.downlink_packet_delay,
        rt_delay: m.round_trip_packet_delay,
        failure: m.packet_delay_measurement_failure,
    }
}

/// A Session Report Request with SESR for the session `smf_seid`: each QoS
/// Monitoring Report goes to the subscription its SRR serves.
pub async fn on_session_report(smf_seid: u64, payload: &[u8]) {
    let reports = reports_in(payload);
    if reports.is_empty() {
        log::warn!("Session Report for SEID 0x{smf_seid:016x} set SESR but carried no QoS Monitoring Report");
        return;
    }
    // The SEID the UPF echoes is the CP F-SEID the PFCP session was established
    // with, `smf_n4_seid_for(ref)`, not what `sess_find_by_seid` indexes (as #540
    // found for Downlink Data Reports).
    let refs: Vec<String> = crate::context::smf_self()
        .read()
        .ok()
        .and_then(|ctx| {
            ctx.pfcp_sessions
                .read()
                .ok()
                .map(|m| m.keys().cloned().collect())
        })
        .unwrap_or_default();
    let Some(r) = refs
        .into_iter()
        .find(|r| crate::smf_n4_seid_for(r) == smf_seid)
    else {
        log::info!("QoS monitoring report for SEID 0x{smf_seid:016x}: no SM context");
        return;
    };
    let Some(b) = crate::lookup_policy_binding(&r) else {
        return;
    };
    for (srr_id, rep) in reports {
        let result = result_of(&rep.qos_monitoring_measurement);
        log::info!(
            "QoS monitoring report ref={r} SRR {srr_id} QFI {}: DL {:?} ms UL {:?} ms RTT {:?} ms{}",
            rep.qfi,
            result.dl_delay,
            result.ul_delay,
            result.rt_delay,
            if result.failure { " (measurement failure)" } else { "" }
        );
        // #1390 review M2: the subscription as it is now must still cover the
        // session (a PUT may have narrowed it while the SRR was being removed).
        let Some(sub) = subscription_of(&r, srr_id)
            .and_then(|id| event_exposure::find(&id))
            .filter(|sub| {
                monitors(sub) && sub.matches(event_exposure::event::QOS_MON, &b.supi, b.psi)
            })
        else {
            log::info!("ref={r}: SRR {srr_id} serves no live QOS_MON subscription covering the session: not notified");
            continue;
        };
        let Some(body) = event_exposure::build_qos_mon_notification(&sub, &b.supi, b.psi, &result)
        else {
            log::info!(
                "ref={r}: SRR {srr_id}: a measurement failure, but subscription {} did not \
                 negotiate PacketDelayFailureReport: not notified",
                sub.id
            );
            continue;
        };
        event_exposure::deliver(&sub, &body, event_exposure::event::QOS_MON, &b.supi, b.psi).await;
    }
}

#[cfg(test)]
#[path = "qos_mon_tests.rs"]
pub(crate) mod tests;
