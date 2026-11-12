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
//! No `QOS_MON` subscription: nothing is requested on N4 or N2.
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

/// The monitoring of one session: its SRRs, one per subscription.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SessionMon {
    /// (subscription id, SRR ID).
    srrs: Vec<(String, u8)>,
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

/// Whether the session's default flow is monitored: its Setup Request Transfers
/// then carry the QoS Monitoring Request.
pub fn active_on(sm_context_ref: &str) -> bool {
    with(|m| m.get(sm_context_ref).is_some_and(|s| !s.srrs.is_empty()))
}

/// The session is released: its SRRs went with the N4 session.
pub fn forget(sm_context_ref: &str) {
    with(|m| m.remove(sm_context_ref));
}

#[cfg(test)]
pub(crate) fn clear_for_test() {
    with(|m| m.clear());
}

/// The SRR IDs installed on a session (sorted), for tests and logs.
pub fn srr_ids(sm_context_ref: &str) -> Vec<u8> {
    let mut v: Vec<u8> = with(|m| {
        m.get(sm_context_ref)
            .map(|s| s.srrs.iter().map(|(_, id)| *id).collect())
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
            .find(|(_, id)| *id == srr_id)
            .map(|(sub, _)| sub.clone())
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

/// A new (or replaced) QOS_MON subscription: monitoring on every session it
/// covers that has its user plane.
pub async fn subscribed(sub: &EventSubscription) {
    if !sub
        .events
        .iter()
        .any(|e| e == event_exposure::event::QOS_MON)
    {
        return;
    }
    for r in sessions_for(sub) {
        if install(&r, sub).await {
            crate::signal_qos_monitoring(&r, QosMonitoringRequest::Both);
        }
    }
}

/// A QOS_MON subscription is gone (DELETE, or a PUT without QOS_MON): its SRRs
/// are removed, and the NG-RAN is told to stop where no other remains.
pub async fn unsubscribed(sub_id: &str) {
    let affected: Vec<(String, u8)> = with(|m| {
        m.iter()
            .filter_map(|(r, s)| {
                s.srrs
                    .iter()
                    .find(|(sub, _)| sub == sub_id)
                    .map(|(_, id)| (r.clone(), *id))
            })
            .collect()
    });
    for (r, srr_id) in affected {
        let params = crate::n4_build::SessionModificationParams {
            remove_srr_ids: vec![srr_id],
            ..Default::default()
        };
        if let Some(upf_seid) = crate::lookup_upf_seid(&r) {
            if let Err(e) =
                crate::pfcp_modify_with(crate::smf_n4_seid_for(&r), upf_seid, &params).await
            {
                log::warn!(
                    "ref={r}: Remove SRR {srr_id} (QOS_MON subscription {sub_id}) failed: {e}"
                );
            }
        }
        let last = with(|m| {
            let s = m.entry(r.clone()).or_default();
            s.srrs.retain(|(sub, _)| sub != sub_id);
            let empty = s.srrs.is_empty();
            if empty {
                m.remove(&r);
            }
            empty
        });
        log::info!("ref={r}: QoS monitoring SRR {srr_id} removed (subscription {sub_id})");
        if last {
            crate::signal_qos_monitoring(&r, QosMonitoringRequest::Stop);
        }
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
        event_exposure::matching(event_exposure::event::QOS_MON, &b.supi, b.psi);
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
        if any {
            crate::signal_qos_monitoring(&r, QosMonitoringRequest::Both);
        }
    });
}

/// Install `sub`'s SRR on the session, unless it is there already. Returns
/// whether it was newly installed.
async fn install(sm_context_ref: &str, sub: &EventSubscription) -> bool {
    if with(|m| {
        m.get(sm_context_ref)
            .is_some_and(|s| s.srrs.iter().any(|(id, _)| *id == sub.id))
    }) {
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
    let srr_id = with(|m| {
        let used: Vec<u8> = m
            .get(sm_context_ref)
            .map(|s| s.srrs.iter().map(|(_, id)| *id).collect())
            .unwrap_or_default();
        (1..=u8::MAX).find(|id| !used.contains(id))
    });
    let Some(srr_id) = srr_id else {
        log::warn!(
            "ref={sm_context_ref}: no free SRR ID for subscription {}",
            sub.id
        );
        return false;
    };
    let period = event_exposure::periodic_rep_period(sub).unwrap_or(DEFAULT_PERIOD_SECS);
    let params = crate::n4_build::SessionModificationParams {
        create_srrs: vec![(srr_id, vec![control_for(b.qfi, period)])],
        ..Default::default()
    };
    match crate::pfcp_modify_with(smf_seid, upf_seid, &params).await {
        Ok(_) => {
            with(|m| {
                m.entry(sm_context_ref.to_string())
                    .or_default()
                    .srrs
                    .push((sub.id.clone(), srr_id))
            });
            log::info!(
                "ref={sm_context_ref}: QoS monitoring of QFI {} requested from the UPF: SRR \
                 {srr_id}, Periodic every {period} s (QOS_MON subscription {})",
                b.qfi,
                sub.id
            );
            true
        }
        Err(e) => {
            log::warn!(
                "ref={sm_context_ref}: Create SRR for QOS_MON subscription {} failed: {e}",
                sub.id
            );
            false
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
        let Some(sub) = subscription_of(&r, srr_id).and_then(|id| event_exposure::find(&id)) else {
            log::info!("ref={r}: SRR {srr_id} serves no live QOS_MON subscription: not notified");
            continue;
        };
        let body = event_exposure::build_qos_mon_notification(&sub, &b.supi, b.psi, &result);
        event_exposure::deliver(&sub, &body, event_exposure::event::QOS_MON, &b.supi, b.psi).await;
    }
}

#[cfg(test)]
#[path = "qos_mon_tests.rs"]
pub(crate) mod tests;
