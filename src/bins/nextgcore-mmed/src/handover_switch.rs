//! Handover completion towards the Serving GW (#730).
//!
//! After an X2 handover (PATH SWITCH REQUEST, TS 23.401 §5.5.1.1.2) or an S1
//! handover (HANDOVER NOTIFY, §5.5.1.2.2) the Serving GW still sends downlink to
//! the source eNB until a Modify Bearer Request gives it the target eNB's S1-U
//! F-TEIDs (X2 steps 2-4, S1 steps 16-17). This module owns what happens around
//! that request:
//!
//! - which bearers it switches, and which the handover already lost;
//! - the PATH SWITCH REQUEST ACKNOWLEDGE, sent only once the response arrives
//!   (X2 step 5), or the PATH SWITCH REQUEST FAILURE;
//! - releasing the bearers that were not switched (TS 23.401 §5.5.1.1.2 step 2 /
//!   §5.5.1.2.2 step 16 by the procedure of §5.4.4.2, TS 36.413 §8.4.4.2);
//! - the explicit detach when no default bearer survives, or the Serving GW
//!   refuses or does not answer (§5.5.1.1.2: "the MME performs explicit detach of
//!   the UE as described in the explicit detach procedure in clause 5.3.8.3").

use crate::context::MmeContext;
use crate::gtp_path::{HandoverModifyKind, PendingHandoverModification, SwitchedBearer};
use crate::s11_build::{GtpCause, GtpDeleteAction};
use crate::s11_handler::ModifyBearerResponseData;
use crate::s1ap_handler::S1apSend;
use nextgcore_s1ap::{Cause, CauseRadioNetwork, CauseTransport, ErabItem};

/// The S1AP cause for an E-RAB, or a whole path switch, the Serving GW did not
/// switch: the user-plane resource behind it is not available.
pub const CORE_NOT_SWITCHED: Cause = Cause::Transport(CauseTransport::TransportResourceUnavailable);

/// The EBI of each PDN connection's default bearer for `mme_ue_id`, with the
/// session id: the lowest EBI of the session, as the E-RAB Release Indication
/// handler identifies it.
fn default_bearers(ctx: &MmeContext, mme_ue_id: u64) -> Vec<(u64, u8)> {
    let Some(ue) = ctx.mme_ue_find_by_id(mme_ue_id) else {
        return Vec::new();
    };
    ue.sess_list
        .iter()
        .filter_map(|sess_id| {
            let sess = ctx.sess_find_by_id(*sess_id)?;
            let ebi = sess
                .bearer_list
                .iter()
                .filter_map(|id| ctx.bearer_find_by_id(*id))
                .map(|b| b.ebi)
                .min()?;
            Some((*sess_id, ebi))
        })
        .collect()
}

/// Whether at least one PDN connection of `mme_ue_id` has its default bearer
/// among `switched` (TS 23.401 §5.5.1.1.2: "If none of the default EPS bearers
/// have been switched successfully ... the MME shall send a Path Switch Request
/// Failure"). A default bearer that is merely not lost, for example one of a PDN
/// connection whose E-RAB setup has not completed, does not count (#730 review m5).
pub fn a_default_bearer_switched(ctx: &MmeContext, mme_ue_id: u64, switched: &[u8]) -> bool {
    default_bearers(ctx, mme_ue_id)
        .iter()
        .any(|(_, ebi)| switched.contains(ebi))
}

/// TS 23.401 §5.5.1.1.2 step 2: the Modify Bearer Request is sent "for each PDN
/// connection where the default bearer has been accepted". A dedicated bearer of
/// a PDN connection whose default bearer is not switched leaves the request and
/// joins the omitted (lost) bearers; that connection is then released whole
/// (#730 review m4). Returns the (switched, omitted) pair to send.
pub fn only_pdns_with_a_switched_default(
    ctx: &MmeContext,
    mme_ue_id: u64,
    switched: Vec<SwitchedBearer>,
    mut omitted: Vec<u8>,
) -> (Vec<SwitchedBearer>, Vec<u8>) {
    let defaults = default_bearers(ctx, mme_ue_id);
    let switched_ebis: Vec<u8> = switched.iter().map(|s| s.ebi).collect();
    let session_of = |ebi: u8| -> Option<u64> {
        let bearer_id = ctx.bearer_find_by_ebi(mme_ue_id, ebi)?;
        Some(ctx.bearer_find_by_id(bearer_id)?.sess_id)
    };
    let mut kept = Vec::new();
    for bearer in switched {
        let default_switched = session_of(bearer.ebi)
            .and_then(|sess_id| defaults.iter().find(|(id, _)| *id == sess_id))
            .is_some_and(|(_, default)| switched_ebis.contains(default));
        if default_switched {
            kept.push(bearer);
        } else if !omitted.contains(&bearer.ebi) {
            omitted.push(bearer.ebi);
        }
    }
    (kept, omitted)
}

/// The UE-AMBR the MME signals for `mme_ue_id`: the sum of the APN-AMBRs of its
/// active PDN connections, up to the subscribed UE-AMBR (TS 23.401 §4.7.3). A
/// zero APN-AMBR sum (not known) falls back to the subscribed value.
pub fn ue_ambr(ctx: &MmeContext, mme_ue_id: u64) -> Option<nextgcore_s1ap::UeAmbr> {
    let ue = ctx.mme_ue_find_by_id(mme_ue_id)?;
    Some(crate::s1ap_build::ue_ambr_of(ctx, &ue))
}

/// Handover failures in the core, by reason, for operators (#730 review m7).
/// Exported through [`handover_failures`].
static HANDOVER_FAILURES: std::sync::Mutex<Vec<(&'static str, u64)>> =
    std::sync::Mutex::new(Vec::new());

/// Count one handover the core could not complete, by `reason`.
pub fn count_handover_failure(reason: &'static str) {
    {
        let mut counts = HANDOVER_FAILURES.lock().unwrap_or_else(|e| e.into_inner());
        match counts.iter_mut().find(|(r, _)| *r == reason) {
            Some((_, n)) => *n += 1,
            None => counts.push((reason, 1)),
        }
    }
    log::warn!(
        "metric mme_handover_core_failures_total{{reason=\"{reason}\"}} incremented (TS 23.401 \
         §5.5.1.1.2 / §5.5.1.2.2)"
    );
}

/// The handover failure counter in Prometheus text format, one sample per
/// reason (every reason present, zero until counted), for mmed's `/metrics`.
pub fn render_metrics() -> String {
    let counts = handover_failures();
    let mut out = String::from(
        "# HELP mme_handover_core_failures_total Handovers the core could not complete, by \
         reason (TS 23.401 5.5.1.1.2 / 5.5.1.2.2)\n\
         # TYPE mme_handover_core_failures_total counter\n",
    );
    for reason in failure_reason::ALL {
        let n = counts
            .iter()
            .find(|(r, _)| r == reason)
            .map_or(0, |(_, n)| *n);
        out.push_str(&format!(
            "mme_handover_core_failures_total{{reason=\"{reason}\"}} {n}\n"
        ));
    }
    out
}

/// The handover failures counted so far: (reason, count).
pub fn handover_failures() -> Vec<(&'static str, u64)> {
    HANDOVER_FAILURES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// Reasons [`count_handover_failure`] is called with.
pub mod failure_reason {
    /// The handover switched no default bearer.
    pub const NO_DEFAULT_BEARER: &str = "no_default_bearer";
    /// The Serving GW refused the Modify Bearer Request.
    pub const SGW_REFUSED: &str = "sgw_refused";
    /// The Serving GW never answered it (N3 exhausted).
    pub const SGW_NO_ANSWER: &str = "sgw_no_answer";
    /// The Modify Bearer Request could not be sent.
    pub const NOT_SENT: &str = "not_sent";
    /// A second Path Switch Request while one is outstanding.
    pub const ALREADY_PENDING: &str = "already_pending";
    /// The request named one E-RAB twice (TS 36.413 §8.4.4.4).
    pub const DUPLICATE_ERAB: &str = "duplicate_erab";
    /// Every reason, in the order `/metrics` lists them.
    pub const ALL: &[&str] = &[
        NO_DEFAULT_BEARER,
        SGW_REFUSED,
        SGW_NO_ANSWER,
        NOT_SENT,
        ALREADY_PENDING,
        DUPLICATE_ERAB,
    ];
}

/// Split the request's bearers into those the Serving GW switched and those it
/// did not, from a response whose message-level cause accepted the request.
///
/// A bearer's own Cause decides it (Table 7.2.8-1). A bearer marked for removal
/// was not switched. A bearer the response does not mention is switched only on
/// "Request accepted" (16): on "Request accepted partially" (17) nothing says it
/// was.
pub fn split_by_response(
    switched: &[SwitchedBearer],
    data: &ModifyBearerResponseData,
) -> (Vec<SwitchedBearer>, Vec<u8>) {
    let accepted = GtpCause::RequestAccepted as u8;
    let mut ok = Vec::new();
    let mut failed = Vec::new();
    for bearer in switched {
        let switched_here = if data.bearers_marked_for_removal.contains(&bearer.ebi) {
            false
        } else {
            match data.bearer_contexts.iter().find(|bc| bc.ebi == bearer.ebi) {
                Some(bc) => bc.cause.unwrap_or(data.cause) == accepted,
                None => data.cause == accepted,
            }
        };
        if switched_here {
            ok.push(bearer.clone());
        } else {
            failed.push(bearer.ebi);
        }
    }
    (ok, failed)
}

/// Whether the response's message-level cause accepted the request at all.
fn message_accepted(cause: u8) -> bool {
    cause == GtpCause::RequestAccepted as u8 || cause == GtpCause::RequestAcceptedPartially as u8
}

/// Write the switched endpoints to the MME's bearer contexts. Done only once the
/// Serving GW has accepted them, so the MME never names an eNB endpoint the SGW
/// does not use.
fn apply_switched(ctx: &MmeContext, mme_ue_id: u64, switched: &[SwitchedBearer]) {
    for s in switched {
        let Some(bearer_id) = ctx.bearer_find_by_ebi(mme_ue_id, s.ebi) else {
            continue;
        };
        if let Some(b) = ctx.bearer_pool.write().unwrap().get_mut(&bearer_id) {
            b.enb_s1u_teid = s.teid;
            b.enb_s1u_ip = s.ip.clone();
        }
    }
}

/// Release, in the core, the bearers `lost` by a handover whose UE keeps at least
/// one default bearer (TS 23.401 §5.5.1.1.2 step 2 / §5.5.1.2.2 step 16):
///
/// - a dedicated bearer by the bearer release procedure of §5.4.4.2: a Delete
///   Bearer Command per PDN connection. It is marked released by the eNB, so the
///   Serving GW's Delete Bearer Request is answered without radio signalling;
/// - a PDN connection whose default bearer is lost, whole: a Delete Session
///   Request, and the connection removed here. The UE is not told by ESM, the gap
///   the network-initiated bearer deletion (#688) already has.
///
/// Returns every EBI released, including the dedicated bearers of a released PDN
/// connection, so the caller can tell the eNB.
pub fn release_lost_bearers(ctx: &MmeContext, mme_ue_id: u64, lost: &[u8]) -> Vec<u8> {
    let Some(ue) = ctx.mme_ue_find_by_id(mme_ue_id) else {
        return Vec::new();
    };
    let mut released = Vec::new();
    for (sess_id, default_ebi) in default_bearers(ctx, mme_ue_id) {
        let Some(sess) = ctx.sess_find_by_id(sess_id) else {
            continue;
        };
        let ebis: Vec<(u64, u8)> = sess
            .bearer_list
            .iter()
            .filter_map(|id| ctx.bearer_find_by_id(*id))
            .map(|b| (b.id, b.ebi))
            .collect();
        if lost.contains(&default_ebi) {
            match crate::gtp_path::send_delete_session_request(
                ctx,
                None,
                ue.sgw_ue_id,
                sess_id,
                GtpDeleteAction::NoAction,
            ) {
                Ok(_) => log::warn!(
                    "[{}] handover lost the default bearer {default_ebi} of a PDN connection: \
                     Delete Session Request sent and the connection removed (TS 23.401 \
                     §5.5.1.1.2 step 2). The UE is not told by ESM",
                    ue.imsi_bcd
                ),
                Err(e) => log::error!(
                    "[{}] handover lost the default bearer {default_ebi}: Delete Session \
                     Request not sent ({e}); the connection is removed here regardless",
                    ue.imsi_bcd
                ),
            }
            for (bearer_id, ebi) in &ebis {
                ctx.bearer_remove(*bearer_id);
                released.push(*ebi);
            }
            ctx.sess_remove(sess_id);
            if let Some(ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
                ue.sess_list.retain(|id| *id != sess_id);
            }
            continue;
        }
        let dedicated: Vec<u8> = ebis
            .iter()
            .filter(|(_, ebi)| lost.contains(ebi))
            .map(|(bearer_id, ebi)| {
                if let Some(b) = ctx.bearer_pool.write().unwrap().get_mut(bearer_id) {
                    b.released_by_enb = true;
                    b.enb_s1u_teid = 0;
                    b.enb_s1u_ip = Default::default();
                }
                *ebi
            })
            .collect();
        if dedicated.is_empty() {
            continue;
        }
        match crate::gtp_path::send_delete_bearer_command(ctx, mme_ue_id, &dedicated) {
            Ok(seq) => log::info!(
                "[{}] handover did not switch dedicated bearers {dedicated:?}: Delete Bearer \
                 Command (seq={seq}) sent (TS 23.401 §5.4.4.2)",
                ue.imsi_bcd
            ),
            Err(e) => log::error!(
                "[{}] handover did not switch dedicated bearers {dedicated:?}: Delete Bearer \
                 Command not sent ({e})",
                ue.imsi_bcd
            ),
        }
        released.extend_from_slice(&dedicated);
    }
    released
}

/// The explicit detach of TS 23.401 §5.5.1.1.2 (clause 5.3.8.3) after a
/// handover the core could not complete: every PDN connection is deleted at the
/// Serving GW, and the UE is told to re-attach.
pub fn detach_after_failed_handover(ctx: &MmeContext, mme_ue_id: u64, why: &str) {
    if let Err(e) =
        crate::gtp_path::send_delete_all_sessions(ctx, None, mme_ue_id, GtpDeleteAction::NoAction)
    {
        log::error!("UE {mme_ue_id}: Delete Session Requests after {why} not all sent: {e}");
    }
    crate::network_detach::mme_initiated_detach(
        ctx,
        mme_ue_id,
        crate::emm_build::DetachTypeToUe::ReAttachRequired,
        why,
    );
}

/// A PATH SWITCH REQUEST FAILURE (TS 36.413 §8.4.4.3) with `cause`.
pub fn path_switch_failure(
    enb_id: u64,
    mme_ue_s1ap_id: u32,
    enb_ue_s1ap_id: u32,
    cause: Cause,
) -> Option<S1apSend> {
    let failure = nextgcore_s1ap::PathSwitchRequestFailure {
        mme_ue_s1ap_id,
        enb_ue_s1ap_id,
        cause,
    };
    match crate::s1ap_gen::build_path_switch_request_failure(&failure, &[]) {
        Ok(pdu) => Some(S1apSend { enb_id, pdu }),
        Err(e) => {
            log::error!("Failed to build Path Switch Request Failure: {e}");
            None
        }
    }
}

/// The handover failed in the core: answer a waiting Path Switch Request with a
/// failure, then detach the UE explicitly.
fn fail(ctx: &MmeContext, pending: &PendingHandoverModification, why: &str) {
    if let HandoverModifyKind::PathSwitch {
        enb_id,
        mme_ue_s1ap_id,
        enb_ue_s1ap_id,
        ..
    } = &pending.kind
    {
        if let Some(send) =
            path_switch_failure(*enb_id, *mme_ue_s1ap_id, *enb_ue_s1ap_id, CORE_NOT_SWITCHED)
        {
            crate::s1ap_path::s1ap_send(send);
        }
    }
    detach_after_failed_handover(ctx, pending.mme_ue_id, why);
}

/// N3 exhaustion of a handover's Modify Bearer Request: the Serving GW never
/// answered (TS 29.274 §7.6), so nothing was switched.
pub fn on_modify_bearer_unanswered(ctx: &MmeContext, pending: PendingHandoverModification) {
    count_handover_failure(failure_reason::SGW_NO_ANSWER);
    log::error!(
        "UE {}: the Serving GW did not answer the handover's Modify Bearer Request; failing \
         the handover and detaching the UE (TS 23.401 §5.5.1.1.2)",
        pending.mme_ue_id
    );
    fail(
        ctx,
        &pending,
        "a handover whose Modify Bearer Request the Serving GW never answered",
    );
}

/// Whether the S1 association a pending handover answers on still exists and
/// still serves the UE: the eNB UE context with the recorded (eNB, MME UE S1AP
/// ID, eNB UE S1AP ID), which the UE context points at.
fn association_alive(ctx: &MmeContext, pending: &PendingHandoverModification) -> bool {
    let (enb_id, mme_ue_s1ap_id, enb_ue_s1ap_id) = match &pending.kind {
        HandoverModifyKind::PathSwitch {
            enb_id,
            mme_ue_s1ap_id,
            enb_ue_s1ap_id,
            ..
        }
        | HandoverModifyKind::HandoverNotify {
            enb_id,
            mme_ue_s1ap_id,
            enb_ue_s1ap_id,
            ..
        } => (*enb_id, *mme_ue_s1ap_id, *enb_ue_s1ap_id),
    };
    let Some(enb_ue_id) = ctx.enb_ue_find_by_mme_ue_s1ap_id(mme_ue_s1ap_id) else {
        return false;
    };
    let Some(enb_ue) = ctx.enb_ue_find_by_id(enb_ue_id) else {
        return false;
    };
    enb_ue.enb_id == enb_id
        && enb_ue.enb_ue_s1ap_id == enb_ue_s1ap_id
        && enb_ue.mme_ue_id == pending.mme_ue_id
        && ctx
            .mme_ue_find_by_id(pending.mme_ue_id)
            .is_some_and(|ue| ue.enb_ue_id == enb_ue_id)
}

/// The Modify Bearer Response a handover waited on (TS 23.401 §5.5.1.1.2 step 4
/// / §5.5.1.2.2 step 17).
pub fn on_modify_bearer_response(
    ctx: &MmeContext,
    pending: PendingHandoverModification,
    data: &ModifyBearerResponseData,
) {
    let mme_ue_id = pending.mme_ue_id;
    if ctx.mme_ue_find_by_id(mme_ue_id).is_none() {
        log::warn!(
            "Modify Bearer Response for a handover of UE {mme_ue_id}, which is gone; nothing \
             to switch"
        );
        if let HandoverModifyKind::PathSwitch {
            enb_id,
            mme_ue_s1ap_id,
            enb_ue_s1ap_id,
            ..
        } = &pending.kind
        {
            if let Some(send) = path_switch_failure(
                *enb_id,
                *mme_ue_s1ap_id,
                *enb_ue_s1ap_id,
                Cause::RadioNetwork(CauseRadioNetwork::UnknownMmeUeS1apId),
            ) {
                crate::s1ap_path::s1ap_send(send);
            }
        }
        return;
    }
    if !message_accepted(data.cause) {
        count_handover_failure(failure_reason::SGW_REFUSED);
        log::error!(
            "UE {mme_ue_id}: the Serving GW refused the handover's Modify Bearer Request (cause \
             {}); failing the handover and detaching the UE (TS 23.401 §5.5.1.1.2)",
            data.cause
        );
        fail(
            ctx,
            &pending,
            &format!(
                "a handover whose Modify Bearer Request the Serving GW refused (cause {})",
                data.cause
            ),
        );
        return;
    }
    let (switched, failed) = split_by_response(&pending.switched, data);
    let mut lost = pending.omitted.clone();
    lost.extend_from_slice(&failed);
    let accepted: Vec<u8> = switched.iter().map(|s| s.ebi).collect();
    if !a_default_bearer_switched(ctx, mme_ue_id, &accepted) {
        count_handover_failure(failure_reason::NO_DEFAULT_BEARER);
        log::error!(
            "UE {mme_ue_id}: the Serving GW switched no default bearer (not switched: \
             {failed:?}); failing the handover and detaching the UE (TS 23.401 §5.5.1.1.2)"
        );
        fail(
            ctx,
            &pending,
            "a handover in which the Serving GW switched no default bearer",
        );
        return;
    }
    // #730 review m1: the S1 association the answer is for may have been released
    // while the request was outstanding (a UE CONTEXT RELEASE REQUEST racing the
    // response). Then there is no eNB to answer, and the endpoints it named are
    // not the UE's any more: the bearers are not switched and nothing is sent on
    // S1. The lost bearers are still released in the core.
    let association = association_alive(ctx, &pending);
    if association {
        apply_switched(ctx, mme_ue_id, &switched);
    }
    let sessions_before = ctx
        .mme_ue_find_by_id(mme_ue_id)
        .map_or(0, |ue| ue.sess_list.len());
    let released = release_lost_bearers(ctx, mme_ue_id, &lost);
    let sessions_after = ctx
        .mme_ue_find_by_id(mme_ue_id)
        .map_or(0, |ue| ue.sess_list.len());
    if !association {
        log::warn!(
            "UE {mme_ue_id}: the S1 association of the handover is gone; the Modify Bearer \
             Response is not acted on towards the eNB (released in the core: {released:?})"
        );
        return;
    }
    log::info!(
        "UE {mme_ue_id}: Serving GW switched EBIs {:?} to the target eNB (TS 23.401 \
         §5.5.1.1.2 / §5.5.1.2.2); released {released:?}",
        switched.iter().map(|s| s.ebi).collect::<Vec<_>>()
    );
    // E-RABs the target eNB holds (it named or admitted them) that the core has
    // now released: for the eNB to release too. A dedicated bearer of a released
    // PDN connection counts, even if the Serving GW switched it.
    // On S1 that is every E-RAB the target admitted, including a dedicated
    // bearer dropped from the request with its PDN connection (N1); on X2 the
    // bearers named and switched (the dropped ones are already in the To Be
    // Released List).
    let held_by_enb: Vec<u8> = match &pending.kind {
        HandoverModifyKind::HandoverNotify { admitted, .. } => admitted.clone(),
        HandoverModifyKind::PathSwitch { .. } => pending.switched.iter().map(|s| s.ebi).collect(),
    };
    let held_by_enb_released: Vec<ErabItem> = held_by_enb
        .into_iter()
        .filter(|ebi| released.contains(ebi))
        .map(|erab_id| ErabItem {
            erab_id,
            cause: CORE_NOT_SWITCHED,
        })
        .collect();

    match pending.kind {
        HandoverModifyKind::PathSwitch {
            enb_id,
            mme_ue_s1ap_id,
            enb_ue_s1ap_id,
            ncc,
            nh,
            released: mut to_release,
            notify,
        } => {
            for item in held_by_enb_released {
                if !to_release.iter().any(|r| r.erab_id == item.erab_id) {
                    to_release.push(item);
                }
            }
            let erab_switched_ul_list = switched
                .iter()
                .filter(|s| !released.contains(&s.ebi))
                .filter_map(|s| {
                    let bearer_id = ctx.bearer_find_by_ebi(mme_ue_id, s.ebi)?;
                    let bearer = ctx.bearer_find_by_id(bearer_id)?;
                    (bearer.sgw_s1u_teid != 0).then(|| nextgcore_s1ap::ErabSwitchedItem {
                        erab_id: bearer.ebi,
                        transport_layer_address: crate::s1ap_build::ip_to_transport_address(
                            &bearer.sgw_s1u_ip,
                        ),
                        gtp_teid: bearer.sgw_s1u_teid,
                    })
                })
                .collect();
            // TS 23.401 §5.5.1.1.2 step 6: a released PDN connection changes
            // the UE-AMBR, which the acknowledge then carries.
            let new_ambr = (sessions_after < sessions_before)
                .then(|| ue_ambr(ctx, mme_ue_id))
                .flatten();
            let ack = nextgcore_s1ap::PathSwitchRequestAcknowledge {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id,
                erab_switched_ul_list,
                security_context: nextgcore_s1ap::SecurityContext {
                    next_hop_chaining_count: ncc,
                    next_hop_parameter: nh,
                },
            };
            match crate::s1ap_gen::build_path_switch_request_acknowledge_releasing(
                &ack,
                new_ambr.as_ref(),
                &to_release,
                &notify,
            ) {
                Ok(pdu) => {
                    crate::s1ap_path::s1ap_send(S1apSend { enb_id, pdu });
                }
                Err(e) => log::error!("Failed to build Path Switch Request Acknowledge: {e}"),
            }
        }
        HandoverModifyKind::HandoverNotify {
            enb_id,
            mme_ue_s1ap_id,
            enb_ue_s1ap_id,
            ..
        } => {
            if held_by_enb_released.is_empty() {
                return;
            }
            let cmd = nextgcore_s1ap::ErabReleaseCommand {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id,
                // TS 36.413 §8.2.3.2: the eNB applies a UE-AMBR carried here; a
                // released PDN connection changes it (TS 23.401 §4.7.3).
                ue_ambr: (sessions_after < sessions_before)
                    .then(|| ue_ambr(ctx, mme_ue_id))
                    .flatten(),
                erab_list: held_by_enb_released,
                nas_pdu: None,
            };
            match crate::s1ap_gen::build_erab_release_command(&cmd) {
                Ok(pdu) => {
                    crate::s1ap_path::s1ap_send(S1apSend { enb_id, pdu });
                }
                Err(e) => log::error!("Failed to build E-RAB Release Command: {e}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Each test drives the REAL S1AP handler (`handle_s1ap_message`) against the
    //! global context, with a real S11 socket (`GtpcServer`, its receive and T3/N3
    //! threads) and a stand-in Serving GW socket that reads the Modify Bearer
    //! Request off the wire and answers it. The eNB side is the S1AP egress queue,
    //! read through `s1ap_path`'s tap: the default build has no SCTP backend.
    use super::*;
    use crate::gtp_path::{lock_s11, route_s11_for_test, GtpcServer};
    use crate::s1ap_gen::test_codec::builder;
    use nextgcore_gtp::v2::xact::Gtp2XactConfig;
    use nextgcore_gtp::v2::{
        Gtp2BearerContextIe, Gtp2CauseIe, Gtp2Header, Gtp2Ie, Gtp2IeType, Gtp2Message,
    };
    use nextgcore_s1ap::{
        ErabSwitchedItem, EutranCgi, HandoverNotify, PathSwitchRequest, Tai, UeSecurityCapabilities,
    };
    use nextgcore_s1ap_gen::generated as g;
    use std::net::UdpSocket;
    use std::time::{Duration, Instant};

    const SGW_S11_TEID: u32 = 0x5730_0001;
    const SGW_S1U_TEID: u32 = 0x0000_5555;

    /// One attached UE on the global context: one PDN connection whose default
    /// bearer is `ebis[0]`, plus dedicated bearers, each active on the source
    /// eNB (TEID 0x1000 + EBI at 10.0.0.1).
    struct Ue {
        mme_ue_id: u64,
        mme_ue_s1ap_id: u32,
        local_teid: u32,
        source_enb_id: u64,
        source_ue_id: u64,
        sess_id: u64,
        sgw_ue_id: u64,
    }

    /// A unique eNB address: the pool is the process-global one.
    fn enb_addr() -> std::net::SocketAddr {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap()
    }

    fn seed(ebis: &[u8]) -> Ue {
        let ctx = crate::context::mme_self();
        let source_enb_id = ctx.enb_add(enb_addr());
        let source_ue_id = ctx.enb_ue_add(source_enb_id, 100);
        let mme_ue_id = ctx.mme_ue_add(source_ue_id);
        ctx.enb_ue_associate_mme_ue(source_ue_id, mme_ue_id);
        let mme_ue_s1ap_id = ctx.enb_ue_find_by_id(source_ue_id).unwrap().mme_ue_s1ap_id;
        let sgw_ue_id = ctx.sgw_ue_add(mme_ue_id);
        ctx.sgw_ue_pool
            .write()
            .unwrap()
            .get_mut(&sgw_ue_id)
            .unwrap()
            .sgw_s11_teid = SGW_S11_TEID;
        let sess_id = ctx.sess_add(mme_ue_id, 9);
        let local_teid = {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let ue = pool.get_mut(&mme_ue_id).unwrap();
            ue.sgw_ue_id = sgw_ue_id;
            ue.imsi_bcd = format!("99970000073{mme_ue_id:04}");
            ue.sess_list.push(sess_id);
            ue.kasme = [0x11; 32];
            ue.kenb = [0x22; 32];
            ue.mme_s11_teid
        };
        for ebi in ebis {
            let bearer_id = ctx.bearer_add(sess_id, mme_ue_id);
            let mut pool = ctx.bearer_pool.write().unwrap();
            let b = pool.get_mut(&bearer_id).unwrap();
            b.ebi = *ebi;
            b.qos.qci = 9;
            b.enb_s1u_teid = 0x1000 + u32::from(*ebi);
            b.enb_s1u_ip.ipv4 = Some([10, 0, 0, 1]);
            b.sgw_s1u_teid = SGW_S1U_TEID + u32::from(*ebi);
            b.sgw_s1u_ip.ipv4 = Some([10, 0, 0, 2]);
            drop(pool);
            ctx.sess_pool
                .write()
                .unwrap()
                .get_mut(&sess_id)
                .unwrap()
                .bearer_list
                .push(bearer_id);
        }
        Ue {
            mme_ue_id,
            mme_ue_s1ap_id,
            local_teid,
            source_enb_id,
            source_ue_id,
            sess_id,
            sgw_ue_id,
        }
    }

    fn release(ue: &Ue) {
        let ctx = crate::context::mme_self();
        ctx.bearer_pool
            .write()
            .unwrap()
            .retain(|_, b| b.mme_ue_id != ue.mme_ue_id);
        ctx.sess_remove(ue.sess_id);
        ctx.mme_ue_remove(ue.mme_ue_id);
        ctx.sgw_ue_pool.write().unwrap().remove(&ue.sgw_ue_id);
        ctx.enb_ue_remove(ue.source_ue_id);
    }

    fn bearer(ue: &Ue, ebi: u8) -> Option<crate::context::MmeBearer> {
        let ctx = crate::context::mme_self();
        ctx.bearer_find_by_id(ctx.bearer_find_by_ebi(ue.mme_ue_id, ebi)?)
    }

    /// A stand-in SGW socket and the MME's real S11 server, routed for the
    /// global context.
    fn sgw(config: Gtp2XactConfig) -> (UdpSocket, crate::gtp_path::S11TestRoute) {
        let sgw = UdpSocket::bind("127.0.0.1:0").unwrap();
        sgw.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let server = GtpcServer::open("127.0.0.1:0", config, 7).unwrap();
        let route = route_s11_for_test(server, sgw.local_addr().unwrap());
        (sgw, route)
    }

    /// The next GTPv2-C message of `msg_type` the stand-in SGW receives.
    fn recv(sgw: &UdpSocket, msg_type: u8) -> (Gtp2Message, std::net::SocketAddr) {
        let mut buf = [0u8; 4096];
        loop {
            let (len, from) = sgw
                .recv_from(&mut buf)
                .unwrap_or_else(|e| panic!("the SGW must receive message type {msg_type}: {e}"));
            let mut bytes = bytes::Bytes::copy_from_slice(&buf[..len]);
            let msg = Gtp2Message::decode(&mut bytes).expect("a conformant GTPv2-C message");
            if msg.header.message_type == msg_type {
                return (msg, from);
            }
        }
    }

    /// (EBI, eNB S1-U F-TEID) of each Bearer Context to be modified.
    fn bearer_contexts(mbr: &Gtp2Message) -> Vec<(u8, u8, u32, Option<[u8; 4]>)> {
        mbr.get_ies(Gtp2IeType::BearerContext as u8)
            .into_iter()
            .filter(|ie| ie.instance == 0)
            .map(|ie| {
                let bc = Gtp2BearerContextIe::decode(&ie.value).unwrap();
                let ft = bc.fteid(0).unwrap().expect("an S1-U eNB F-TEID");
                (bc.ebi().unwrap(), ft.interface_type, ft.teid, ft.ipv4_addr)
            })
            .collect()
    }

    /// A Modify Bearer Response with message `cause` and, per bearer, its cause.
    fn mbr_response(local_teid: u32, seq: u32, cause: u8, bearers: &[(u8, u8)]) -> Vec<u8> {
        let mut rsp = Gtp2Message::new(Gtp2Header::new(35, local_teid, seq));
        rsp.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Cause as u8, 0, &[cause, 0]));
        for (ebi, c) in bearers {
            let mut bc = Gtp2BearerContextIe::new();
            bc.set_ebi(*ebi);
            bc.set_cause(&Gtp2CauseIe::new(*c));
            rsp.add_bearer_context(0, &bc);
        }
        rsp.encode().to_vec()
    }

    /// Wait for the first tapped PDU for `enb_id` that `pick` accepts.
    fn wait_pdu<T>(enb_id: u64, mut pick: impl FnMut(&g::S1AP_PDU) -> Option<T>) -> T {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            for pdu in crate::s1ap_path::take_tapped_for_test(enb_id) {
                if let Ok(decoded) = nextgcore_s1ap_gen::decode(&pdu) {
                    if let Some(t) = pick(&decoded) {
                        return t;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("no matching S1AP PDU reached eNB {enb_id}");
    }

    fn path_switch_ack(pdu: &g::S1AP_PDU) -> Option<g::PathSwitchRequestAcknowledge> {
        match pdu {
            g::S1AP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
                value: g::SuccessfulOutcomeValue::Id_PathSwitchRequest(a),
                ..
            }) => Some(a.clone()),
            _ => None,
        }
    }

    fn path_switch_failure_cause(pdu: &g::S1AP_PDU) -> Option<g::Cause> {
        match pdu {
            g::S1AP_PDU::UnsuccessfulOutcome(g::UnsuccessfulOutcome {
                value: g::UnsuccessfulOutcomeValue::Id_PathSwitchRequest(f),
                ..
            }) => f.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
                g::PathSwitchRequestFailureProtocolIEs_EntryValue::Id_Cause(c) => Some(c.clone()),
                _ => None,
            }),
            _ => None,
        }
    }

    fn is_transport_resource_unavailable(cause: &g::Cause) -> bool {
        matches!(cause, g::Cause::Transport(t) if t.0 == 0)
    }

    /// The ack's E-RAB To Be Switched UL (EBI, TEID) and To Be Released EBIs.
    fn ack_lists(ack: &g::PathSwitchRequestAcknowledge) -> (Vec<(u8, u32)>, Vec<u8>) {
        use g::PathSwitchRequestAcknowledgeProtocolIEs_EntryValue as V;
        let mut ul = Vec::new();
        let mut released = Vec::new();
        for ie in &ack.protocol_i_es.0 {
            match &ie.value {
                V::Id_E_RABToBeSwitchedULList(l) => {
                    for e in &l.0 {
                        let g::E_RABToBeSwitchedULList_EntryValue::Id_E_RABToBeSwitchedULItem(i) =
                            &e.value;
                        let teid = u32::from_be_bytes(i.gtp_teid.0[..4].try_into().unwrap());
                        ul.push((i.e_rab_id.0, teid));
                    }
                }
                V::Id_E_RABToBeReleasedList(l) => {
                    for e in &l.0 {
                        let g::E_RABList_EntryValue::Id_E_RABItem(i) = &e.value;
                        released.push(i.e_rab_id.0);
                    }
                }
                _ => {}
            }
        }
        (ul, released)
    }

    /// Send a PATH SWITCH REQUEST from `target_enb_id` through the real handler,
    /// switching `ebis` to TEID 0x9000 + EBI at 10.0.0.9.
    fn path_switch(ue: &Ue, target_enb_id: u64, ebis: &[u8]) -> Vec<S1apSend> {
        let psr = PathSwitchRequest {
            enb_ue_s1ap_id: 200,
            erab_switched_dl_list: ebis
                .iter()
                .map(|ebi| ErabSwitchedItem {
                    erab_id: *ebi,
                    transport_layer_address: vec![10, 0, 0, 9],
                    gtp_teid: 0x9000 + u32::from(*ebi),
                })
                .collect(),
            source_mme_ue_s1ap_id: ue.mme_ue_s1ap_id,
            eutran_cgi: EutranCgi {
                plmn_identity: [0x13, 0x00, 0x14],
                cell_identity: 0x42,
            },
            tai: Tai {
                plmn_identity: [0x13, 0x00, 0x14],
                tac: 2,
            },
            ue_security_capabilities: UeSecurityCapabilities {
                encryption_algorithms: 0,
                integrity_algorithms: 0,
            },
        };
        let bytes = builder::build_path_switch_request(&psr).unwrap();
        crate::s1ap_handler::handle_s1ap_message(crate::context::mme_self(), target_enb_id, &bytes)
    }

    /// #730, TS 23.401 §5.5.1.1.2 steps 2-5: the Path Switch Request makes a
    /// Modify Bearer Request carrying the target eNB's S1-U F-TEID reach the SGW,
    /// nothing is sent to the eNB until it is answered, and the answer is a PATH
    /// SWITCH REQUEST ACKNOWLEDGE with a fresh {NCC, NH}.
    #[test]
    fn a_path_switch_is_acknowledged_only_after_the_modify_bearer_response() {
        let _guard = lock_s11();
        let (sgw, _route) = sgw(Gtp2XactConfig::default());
        let ue = seed(&[5]);
        let target = crate::context::mme_self().enb_add(enb_addr());
        crate::s1ap_path::tap_enb_for_test(target);

        let out = path_switch(&ue, target, &[5]);
        assert!(out.is_empty(), "the acknowledge must wait for the SGW");

        let (mbr, from) = recv(&sgw, 34);
        assert_eq!(
            mbr.header.teid,
            Some(SGW_S11_TEID),
            "addressed to the SGW's S11 TEID"
        );
        assert_eq!(
            bearer_contexts(&mbr),
            vec![(5, 0, 0x9005, Some([10, 0, 0, 9]))],
            "the target eNB's S1-U F-TEID (interface type 0, S1-U eNodeB)"
        );
        assert!(
            crate::s1ap_path::take_tapped_for_test(target).is_empty(),
            "no PATH SWITCH REQUEST ACKNOWLEDGE before the Modify Bearer Response"
        );
        assert_eq!(
            bearer(&ue, 5).unwrap().enb_s1u_teid,
            0x1005,
            "the bearer keeps the source endpoint until the SGW accepts the new one"
        );

        sgw.send_to(
            &mbr_response(ue.local_teid, mbr.header.sequence_number, 16, &[(5, 16)]),
            from,
        )
        .unwrap();
        let ack = wait_pdu(target, path_switch_ack);
        let (ul, released) = ack_lists(&ack);
        assert_eq!(ul, vec![(5, SGW_S1U_TEID + 5)]);
        assert!(released.is_empty());
        let nh = ack
            .protocol_i_es
            .0
            .iter()
            .find_map(|ie| match &ie.value {
                g::PathSwitchRequestAcknowledgeProtocolIEs_EntryValue::Id_SecurityContext(s) => {
                    Some(s.clone())
                }
                _ => None,
            })
            .expect("Security Context");
        assert_eq!(nh.next_hop_chaining_count.0, 1);
        let b = bearer(&ue, 5).unwrap();
        assert_eq!(b.enb_s1u_teid, 0x9005);
        assert_eq!(b.enb_s1u_ip.ipv4, Some([10, 0, 0, 9]));
        assert!(!crate::gtp_path::handover_modification_pending(
            ue.mme_ue_id
        ));
        release(&ue);
    }

    /// #730: an SGW that refuses the Modify Bearer Request gets the eNB a PATH
    /// SWITCH REQUEST FAILURE, and the UE an explicit detach whose Delete Session
    /// Request reaches the SGW (TS 23.401 §5.5.1.1.2, §5.3.8.3).
    #[test]
    fn a_refused_modify_bearer_request_fails_the_path_switch() {
        let _guard = lock_s11();
        let (sgw, _route) = sgw(Gtp2XactConfig::default());
        let ue = seed(&[5]);
        let target = crate::context::mme_self().enb_add(enb_addr());
        crate::s1ap_path::tap_enb_for_test(target);

        assert!(path_switch(&ue, target, &[5]).is_empty());
        let (mbr, from) = recv(&sgw, 34);
        // 73: "No resources available".
        sgw.send_to(
            &mbr_response(ue.local_teid, mbr.header.sequence_number, 73, &[]),
            from,
        )
        .unwrap();
        let cause = wait_pdu(target, path_switch_failure_cause);
        assert!(is_transport_resource_unavailable(&cause), "{cause:?}");
        let (dsr, _) = recv(&sgw, 36);
        assert_eq!(dsr.header.teid, Some(SGW_S11_TEID));
        assert!(
            bearer(&ue, 5).is_none_or(|b| b.enb_s1u_teid != 0x9005),
            "a refused endpoint is never written to the bearer"
        );
        release(&ue);
    }

    /// #730: the SGW switches the default bearer but not the dedicated one. The
    /// acknowledge lists the dedicated E-RAB To Be Released and only the default
    /// one To Be Switched in UL, and the dedicated bearer is released in the core
    /// by a Delete Bearer Command (TS 23.401 §5.5.1.1.2 step 2, §5.4.4.2;
    /// TS 36.413 §8.4.4.2).
    #[test]
    fn a_bearer_the_sgw_does_not_switch_is_released() {
        let _guard = lock_s11();
        let (sgw, _route) = sgw(Gtp2XactConfig::default());
        let ue = seed(&[5, 6]);
        let target = crate::context::mme_self().enb_add(enb_addr());
        crate::s1ap_path::tap_enb_for_test(target);

        assert!(path_switch(&ue, target, &[5, 6]).is_empty());
        let (mbr, from) = recv(&sgw, 34);
        assert_eq!(bearer_contexts(&mbr).len(), 2);
        sgw.send_to(
            &mbr_response(
                ue.local_teid,
                mbr.header.sequence_number,
                17,
                &[(5, 16), (6, 73)],
            ),
            from,
        )
        .unwrap();
        let ack = wait_pdu(target, path_switch_ack);
        assert_eq!(ack_lists(&ack), (vec![(5, SGW_S1U_TEID + 5)], vec![6]));
        let (dbc, _) = recv(&sgw, 66);
        let ebis: Vec<u8> = dbc
            .get_ies(Gtp2IeType::BearerContext as u8)
            .into_iter()
            .filter_map(|ie| Gtp2BearerContextIe::decode(&ie.value).ok()?.ebi().ok())
            .collect();
        assert_eq!(
            ebis,
            vec![6],
            "a Delete Bearer Command for the dedicated bearer"
        );
        assert_eq!(bearer(&ue, 5).unwrap().enb_s1u_teid, 0x9005);
        let b6 = bearer(&ue, 6).unwrap();
        assert!(b6.released_by_enb);
        assert_eq!(b6.enb_s1u_teid, 0);
        release(&ue);
    }

    /// #730: an SGW that never answers runs the request out of its N3 budget,
    /// and the Path Switch Request is then answered with a failure rather than
    /// never (TS 29.274 §7.6).
    #[test]
    fn an_unanswered_modify_bearer_request_fails_the_path_switch() {
        let _guard = lock_s11();
        let (sgw, _route) = sgw(Gtp2XactConfig {
            t3_response: Duration::from_millis(100),
            n3_requests: 2,
            response_hold: Duration::from_secs(1),
        });
        let ue = seed(&[5]);
        let target = crate::context::mme_self().enb_add(enb_addr());
        crate::s1ap_path::tap_enb_for_test(target);

        assert!(path_switch(&ue, target, &[5]).is_empty());
        recv(&sgw, 34);
        let cause = wait_pdu(target, path_switch_failure_cause);
        assert!(is_transport_resource_unavailable(&cause), "{cause:?}");
        assert!(!crate::gtp_path::handover_modification_pending(
            ue.mme_ue_id
        ));
        release(&ue);
    }

    /// Seed an S1 handover whose target admitted every bearer in `admitted`
    /// (TEID 0x8800 + EBI at 10.0.0.8) and send its HANDOVER NOTIFY through the
    /// real handler. Returns (target eNB, target UE).
    fn notify_handover(ue: &Ue, admitted: &[u8]) -> (u64, u64) {
        let ctx = crate::context::mme_self();
        let target_enb = ctx.enb_add(enb_addr());
        let target_ue_id = ctx.enb_ue_add(target_enb, 300);
        {
            let mut pool = ctx.enb_ue_pool.write().unwrap();
            let t = pool.get_mut(&target_ue_id).unwrap();
            t.mme_ue_id = ue.mme_ue_id;
            t.source_ue_id = ue.source_ue_id;
            // Armed by HANDOVER REQUIRED: the preparation is outstanding.
            t.handover_prep_deadline = Some(Instant::now() + Duration::from_secs(10));
        }
        for ebi in admitted {
            let bearer_id = ctx.bearer_find_by_ebi(ue.mme_ue_id, *ebi).unwrap();
            let mut pool = ctx.bearer_pool.write().unwrap();
            let b = pool.get_mut(&bearer_id).unwrap();
            b.target_s1u_teid = 0x8800 + u32::from(*ebi);
            b.target_s1u_ip.ipv4 = Some([10, 0, 0, 8]);
        }
        crate::s1ap_path::tap_enb_for_test(target_enb);
        let target_mme_ue_s1ap_id = ctx.enb_ue_find_by_id(target_ue_id).unwrap().mme_ue_s1ap_id;
        let notify = HandoverNotify {
            mme_ue_s1ap_id: target_mme_ue_s1ap_id,
            enb_ue_s1ap_id: 300,
            eutran_cgi: EutranCgi {
                plmn_identity: [0x13, 0x00, 0x14],
                cell_identity: 0x99,
            },
            tai: Tai {
                plmn_identity: [0x13, 0x00, 0x14],
                tac: 2,
            },
        };
        let out = crate::s1ap_handler::handle_s1ap_message(
            ctx,
            target_enb,
            &builder::build_handover_notify(&notify).unwrap(),
        );
        assert_eq!(out.len(), 1, "the source is released as before");
        assert_eq!(out[0].enb_id, ue.source_enb_id);
        (target_enb, target_ue_id)
    }

    /// #730, TS 23.401 §5.5.1.2.2 step 16: after an S1 handover the SGW refuses
    /// the dedicated bearer. The target eNB is told to release that E-RAB, and
    /// the core releases the bearer by a Delete Bearer Command.
    #[test]
    fn a_dedicated_bearer_refused_after_handover_notify_is_released() {
        let _guard = lock_s11();
        let (sgw, _route) = sgw(Gtp2XactConfig::default());
        let ue = seed(&[5, 6]);
        let (target_enb, target_ue_id) = notify_handover(&ue, &[5, 6]);

        let (mbr, from) = recv(&sgw, 34);
        assert_eq!(bearer_contexts(&mbr).len(), 2);
        sgw.send_to(
            &mbr_response(
                ue.local_teid,
                mbr.header.sequence_number,
                17,
                &[(5, 16), (6, 73)],
            ),
            from,
        )
        .unwrap();
        let released = wait_pdu(target_enb, |pdu| match pdu {
            g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
                value: g::InitiatingMessageValue::Id_E_RABRelease(cmd),
                ..
            }) => cmd.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
                g::E_RABReleaseCommandProtocolIEs_EntryValue::Id_E_RABToBeReleasedList(l) => Some(
                    l.0.iter()
                        .map(|e| {
                            let g::E_RABList_EntryValue::Id_E_RABItem(i) = &e.value;
                            i.e_rab_id.0
                        })
                        .collect::<Vec<u8>>(),
                ),
                _ => None,
            }),
            _ => None,
        });
        assert_eq!(released, vec![6], "an E-RAB RELEASE COMMAND for E-RAB 6");
        let (dbc, _) = recv(&sgw, 66);
        assert_eq!(dbc.header.teid, Some(SGW_S11_TEID));
        assert_eq!(bearer(&ue, 5).unwrap().enb_s1u_teid, 0x8805);
        assert!(bearer(&ue, 6).unwrap().released_by_enb);
        crate::context::mme_self().enb_ue_remove(target_ue_id);
        release(&ue);
    }

    /// #730, TS 23.401 §5.5.1.2.2 steps 16-17: HANDOVER NOTIFY makes the MME
    /// send the SGW a Modify Bearer Request with the S1-U F-TEID the target eNB
    /// admitted, and the bearer takes that endpoint once the SGW accepts it.
    #[test]
    fn a_handover_notify_sends_the_target_f_teid_to_the_sgw() {
        let _guard = lock_s11();
        let (sgw, _route) = sgw(Gtp2XactConfig::default());
        let ue = seed(&[5]);
        let ctx = crate::context::mme_self();
        let (_, target_ue_id) = notify_handover(&ue, &[5]);

        let (mbr, from) = recv(&sgw, 34);
        assert_eq!(mbr.header.teid, Some(SGW_S11_TEID));
        assert_eq!(
            bearer_contexts(&mbr),
            vec![(5, 0, 0x8805, Some([10, 0, 0, 8]))]
        );
        sgw.send_to(
            &mbr_response(ue.local_teid, mbr.header.sequence_number, 16, &[(5, 16)]),
            from,
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while bearer(&ue, 5).unwrap().enb_s1u_teid != 0x8805 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let b = bearer(&ue, 5).unwrap();
        assert_eq!(b.enb_s1u_teid, 0x8805);
        assert_eq!(b.enb_s1u_ip.ipv4, Some([10, 0, 0, 8]));
        assert_eq!(b.target_s1u_teid, 0);
        assert!(!crate::gtp_path::handover_modification_pending(
            ue.mme_ue_id
        ));
        ctx.enb_ue_remove(target_ue_id);
        release(&ue);
    }

    /// The message types the stand-in SGW receives within `window`.
    fn drain(sgw: &UdpSocket, window: Duration) -> Vec<Gtp2Message> {
        let mut out = Vec::new();
        let deadline = Instant::now() + window;
        let mut buf = [0u8; 4096];
        sgw.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        while Instant::now() < deadline {
            if let Ok((len, _)) = sgw.recv_from(&mut buf) {
                let mut bytes = bytes::Bytes::copy_from_slice(&buf[..len]);
                if let Ok(msg) = Gtp2Message::decode(&mut bytes) {
                    out.push(msg);
                }
            }
        }
        sgw.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        out
    }

    fn types(msgs: &[Gtp2Message]) -> Vec<u8> {
        msgs.iter().map(|m| m.header.message_type).collect()
    }

    /// EBIs of the instance-`instance` Bearer Contexts of `msg`.
    fn bearer_context_ebis(msg: &Gtp2Message, instance: u8) -> Vec<u8> {
        msg.get_ies(Gtp2IeType::BearerContext as u8)
            .into_iter()
            .filter(|ie| ie.instance == instance)
            .filter_map(|ie| Gtp2BearerContextIe::decode(&ie.value).ok()?.ebi().ok())
            .collect()
    }

    /// A Modify Bearer Response that also marks `removed` for removal (instance 1).
    fn mbr_response_removing(
        local_teid: u32,
        seq: u32,
        cause: u8,
        bearers: &[(u8, u8)],
        removed: &[u8],
    ) -> Vec<u8> {
        let mut bytes = bytes::Bytes::from(mbr_response(local_teid, seq, cause, bearers));
        let mut rsp = Gtp2Message::decode(&mut bytes).unwrap();
        for ebi in removed {
            let mut bc = Gtp2BearerContextIe::new();
            bc.set_ebi(*ebi);
            bc.set_cause(&Gtp2CauseIe::new(16));
            rsp.add_bearer_context(1, &bc);
        }
        rsp.encode().to_vec()
    }

    fn detach_pending(ue: &Ue) -> bool {
        crate::context::mme_self()
            .mme_ue_find_by_id(ue.mme_ue_id)
            .is_some_and(|u| u.nas_eps.type_ == crate::context::MmeEpsType::DetachRequestToUe)
    }

    fn send_notify(enb_id: u64, mme_ue_s1ap_id: u32, enb_ue_s1ap_id: u32) -> Vec<S1apSend> {
        let notify = HandoverNotify {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id,
            eutran_cgi: EutranCgi {
                plmn_identity: [0x13, 0x00, 0x14],
                cell_identity: 0x77,
            },
            tai: Tai {
                plmn_identity: [0x13, 0x00, 0x14],
                tac: 7,
            },
        };
        crate::s1ap_handler::handle_s1ap_message(
            crate::context::mme_self(),
            enb_id,
            &builder::build_handover_notify(&notify).unwrap(),
        )
    }

    fn is_error_indication(send: &S1apSend) -> bool {
        matches!(
            nextgcore_s1ap_gen::decode(&send.pdu),
            Ok(g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
                value: g::InitiatingMessageValue::Id_ErrorIndication(_),
                ..
            }))
        )
    }

    /// #730 review B1: a HANDOVER NOTIFY from an eNB the UE is not on, naming
    /// an attached UE's MME UE S1AP ID, is answered with ERROR INDICATION and
    /// changes nothing: no Modify Bearer or Delete Session Request, no detach.
    /// A notify from the UE's own eNB when no handover is in progress only
    /// updates the location.
    #[test]
    fn a_stray_handover_notify_detaches_nobody() {
        let _guard = lock_s11();
        let (sgw, _route) = sgw(Gtp2XactConfig::default());
        let ue = seed(&[5]);
        let ctx = crate::context::mme_self();
        let intruder = ctx.enb_add(enb_addr());

        let out = send_notify(intruder, ue.mme_ue_s1ap_id, 100);
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].enb_id, intruder);
        assert!(
            is_error_indication(&out[0]),
            "ERROR INDICATION to the sender"
        );

        // The UE's own eNB and pair, but no handover in progress.
        let out = send_notify(ue.source_enb_id, ue.mme_ue_s1ap_id, 100);
        assert!(out.is_empty(), "{out:?}");
        assert_eq!(
            ctx.mme_ue_find_by_id(ue.mme_ue_id).unwrap().e_cgi.cell_id,
            0x77,
            "the location is updated, as before #730"
        );

        assert!(
            drain(&sgw, Duration::from_millis(400)).is_empty(),
            "nothing reaches the SGW"
        );
        assert!(!detach_pending(&ue));
        assert_eq!(bearer(&ue, 5).unwrap().enb_s1u_teid, 0x1005);
        assert_eq!(
            ctx.mme_ue_find_by_id(ue.mme_ue_id).unwrap().enb_ue_id,
            ue.source_ue_id
        );
        release(&ue);
    }

    /// #730 review B1: the target's HANDOVER NOTIFY repeated while its Modify
    /// Bearer Request is outstanding, and again after it is answered, sends no
    /// second request and detaches nobody.
    #[test]
    fn a_duplicate_handover_notify_is_ignored() {
        let _guard = lock_s11();
        let (sgw, _route) = sgw(Gtp2XactConfig::default());
        let ue = seed(&[5]);
        let ctx = crate::context::mme_self();
        let (target_enb, target_ue_id) = notify_handover(&ue, &[5]);
        let target_mme_ue_s1ap_id = ctx.enb_ue_find_by_id(target_ue_id).unwrap().mme_ue_s1ap_id;
        let (mbr, from) = recv(&sgw, 34);

        // Repeated while the request is outstanding.
        assert!(send_notify(target_enb, target_mme_ue_s1ap_id, 300).is_empty());
        assert!(drain(&sgw, Duration::from_millis(300)).is_empty());

        sgw.send_to(
            &mbr_response(ue.local_teid, mbr.header.sequence_number, 16, &[(5, 16)]),
            from,
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while crate::gtp_path::handover_modification_pending(ue.mme_ue_id)
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        // Repeated after it completed.
        assert!(send_notify(target_enb, target_mme_ue_s1ap_id, 300).is_empty());
        assert!(drain(&sgw, Duration::from_millis(300)).is_empty());
        assert!(!detach_pending(&ue));
        assert_eq!(bearer(&ue, 5).unwrap().enb_s1u_teid, 0x8805);
        ctx.enb_ue_remove(target_ue_id);
        release(&ue);
    }

    /// #730 review M1, TS 29.274 Table 7.2.7-1 NOTE 3: a bearer the target left
    /// out of the DL list goes in the Modify Bearer Request as a Bearer Context
    /// to be removed (instance 1); it is not in the To Be Released List (TS
    /// 36.413 §8.4.4.2: it is already implicitly released).
    #[test]
    fn an_omitted_bearer_is_a_bearer_context_to_be_removed() {
        let _guard = lock_s11();
        let (sgw, _route) = sgw(Gtp2XactConfig::default());
        let ue = seed(&[5, 6]);
        let target = crate::context::mme_self().enb_add(enb_addr());
        crate::s1ap_path::tap_enb_for_test(target);

        assert!(path_switch(&ue, target, &[5]).is_empty());
        let (mbr, from) = recv(&sgw, 34);
        assert_eq!(bearer_context_ebis(&mbr, 0), vec![5]);
        assert_eq!(
            bearer_context_ebis(&mbr, 1),
            vec![6],
            "Bearer Contexts to be removed"
        );
        sgw.send_to(
            &mbr_response(ue.local_teid, mbr.header.sequence_number, 16, &[(5, 16)]),
            from,
        )
        .unwrap();
        let ack = wait_pdu(target, path_switch_ack);
        assert_eq!(ack_lists(&ack), (vec![(5, SGW_S1U_TEID + 5)], vec![]));
        let (dbc, _) = recv(&sgw, 66);
        assert_eq!(bearer_context_ebis(&dbc, 0), vec![6]);
        assert!(
            nextgcore_gtp::v2::is_command_sequence(dbc.header.sequence_number),
            "a Command's number has the MSB set (TS 29.274 §7.6, #727)"
        );
        release(&ue);
    }

    /// #730 review M2(a), TS 36.413 §8.4.4.4: an E-RAB ID twice in the DL list is
    /// answered with PATH SWITCH REQUEST FAILURE before any state changes.
    #[test]
    fn a_duplicate_erab_id_fails_the_path_switch_unchanged() {
        let _guard = lock_s11();
        let (sgw, _route) = sgw(Gtp2XactConfig::default());
        let ue = seed(&[5]);
        let ctx = crate::context::mme_self();
        let target = ctx.enb_add(enb_addr());

        let out = path_switch(&ue, target, &[5, 5]);
        assert_eq!(out.len(), 1);
        let cause = path_switch_failure_cause(&nextgcore_s1ap_gen::decode(&out[0].pdu).unwrap())
            .expect("PATH SWITCH REQUEST FAILURE");
        // CauseRadioNetwork multiple-E-RAB-ID-instances.
        assert!(
            matches!(&cause, g::Cause::RadioNetwork(r) if r.0 == 31),
            "{cause:?}"
        );
        let enb_ue = ctx.enb_ue_find_by_id(ue.source_ue_id).unwrap();
        assert_eq!(enb_ue.enb_id, ue.source_enb_id, "not re-anchored");
        assert_eq!(enb_ue.enb_ue_s1ap_id, 100);
        assert_eq!(bearer(&ue, 5).unwrap().enb_s1u_teid, 0x1005);
        assert!(drain(&sgw, Duration::from_millis(300)).is_empty());
        assert!(!detach_pending(&ue));
        release(&ue);
    }

    /// #730 review M2(b): a second PATH SWITCH REQUEST while the first one's
    /// Modify Bearer Request is outstanding is refused, and the first is still
    /// acknowledged.
    #[test]
    fn a_second_path_switch_while_one_is_pending_is_refused() {
        let _guard = lock_s11();
        let (sgw, _route) = sgw(Gtp2XactConfig::default());
        let ue = seed(&[5]);
        let target = crate::context::mme_self().enb_add(enb_addr());
        crate::s1ap_path::tap_enb_for_test(target);

        assert!(path_switch(&ue, target, &[5]).is_empty());
        let (mbr, from) = recv(&sgw, 34);
        let second = path_switch(&ue, target, &[5]);
        assert_eq!(second.len(), 1);
        assert!(
            path_switch_failure_cause(&nextgcore_s1ap_gen::decode(&second[0].pdu).unwrap())
                .is_some(),
            "the second request is refused"
        );
        assert!(
            !types(&drain(&sgw, Duration::from_millis(300))).contains(&34),
            "no second Modify Bearer Request"
        );
        sgw.send_to(
            &mbr_response(ue.local_teid, mbr.header.sequence_number, 16, &[(5, 16)]),
            from,
        )
        .unwrap();
        let ack = wait_pdu(target, path_switch_ack);
        assert_eq!(ack_lists(&ack).0, vec![(5, SGW_S1U_TEID + 5)]);
        assert!(!detach_pending(&ue));
        release(&ue);
    }

    /// #730 review M2(c), TS 23.401 §5.5.1.1.2: a DL list without the default
    /// bearer gets PATH SWITCH REQUEST FAILURE and an explicit detach, and no
    /// Modify Bearer Request is sent.
    #[test]
    fn a_path_switch_without_the_default_bearer_fails_before_any_mbr() {
        let _guard = lock_s11();
        let (sgw, _route) = sgw(Gtp2XactConfig::default());
        let ue = seed(&[5, 6]);
        let target = crate::context::mme_self().enb_add(enb_addr());

        let count = || {
            handover_failures()
                .iter()
                .find(|(r, _)| *r == failure_reason::NO_DEFAULT_BEARER)
                .map_or(0, |(_, n)| *n)
        };
        let before = count();
        let out = path_switch(&ue, target, &[6]);
        assert_eq!(out.len(), 1);
        let cause = path_switch_failure_cause(&nextgcore_s1ap_gen::decode(&out[0].pdu).unwrap())
            .expect("PATH SWITCH REQUEST FAILURE");
        assert!(
            matches!(&cause, g::Cause::RadioNetwork(r) if r.0 == 0),
            "radio network unspecified, the no-default-bearer refusal: {cause:?}"
        );
        assert_eq!(
            count(),
            before + 1,
            "counted as a no-default-bearer failure"
        );
        let seen = types(&drain(&sgw, Duration::from_millis(500)));
        assert!(seen.contains(&36), "Delete Session Request: {seen:?}");
        assert!(!seen.contains(&34), "no Modify Bearer Request: {seen:?}");
        assert!(detach_pending(&ue), "explicit detach (§5.3.8.3)");
        release(&ue);
    }

    /// Path switch for `ebis`, then answer the MBR with `rsp`; expect a
    /// failure at the target plus the explicit detach.
    fn expect_failure_and_detach(ue: &Ue, ebis: &[u8], rsp: impl Fn(u32) -> Vec<u8>) {
        let (sgw, _route) = sgw(Gtp2XactConfig::default());
        let target = crate::context::mme_self().enb_add(enb_addr());
        crate::s1ap_path::tap_enb_for_test(target);
        assert!(path_switch(ue, target, ebis).is_empty());
        let (mbr, from) = recv(&sgw, 34);
        sgw.send_to(&rsp(mbr.header.sequence_number), from).unwrap();
        let cause = wait_pdu(target, path_switch_failure_cause);
        assert!(is_transport_resource_unavailable(&cause), "{cause:?}");
        let (dsr, _) = recv(&sgw, 36);
        assert_eq!(dsr.header.teid, Some(SGW_S11_TEID));
        assert!(detach_pending(ue));
        assert!(bearer(ue, 5).is_none_or(|b| b.enb_s1u_teid != 0x9005));
    }

    /// #730 review M2(d): Request accepted, but the default bearer is marked for
    /// removal (Table 7.2.8-1 instance 1): the handover fails and the UE is
    /// detached.
    #[test]
    fn a_default_bearer_marked_for_removal_fails_the_path_switch() {
        let _guard = lock_s11();
        let ue = seed(&[5, 6]);
        expect_failure_and_detach(&ue, &[5, 6], |seq| {
            mbr_response_removing(ue.local_teid, seq, 16, &[(6, 16)], &[5])
        });
        release(&ue);
    }

    /// #730 review M2(e): Request accepted partially, with the default bearer's
    /// own cause a refusal: failure and detach.
    #[test]
    fn a_refused_default_bearer_under_partial_acceptance_fails_the_path_switch() {
        let _guard = lock_s11();
        let ue = seed(&[5, 6]);
        expect_failure_and_detach(&ue, &[5, 6], |seq| {
            mbr_response(ue.local_teid, seq, 17, &[(5, 73), (6, 16)])
        });
        release(&ue);
    }

    /// #730 review M2(f), m2, m3, m4: two PDN connections, and the target omits
    /// the default bearer (6) of the second, naming its dedicated bearer (7).
    /// The MBR carries only the first PDN's bearer, with 6 and 7 to be removed;
    /// the second PDN gets a Delete Session Request; the acknowledge lists 7
    /// (named, not switched) To Be Released but not 6 (implicitly released),
    /// and carries the UE-AMBR of the remaining PDN (TS 23.401 §5.5.1.1.2 step
    /// 6, §4.7.3).
    #[test]
    fn a_pdn_whose_default_bearer_is_omitted_is_released_and_the_rest_acknowledged() {
        let _guard = lock_s11();
        let (sgw, _route) = sgw(Gtp2XactConfig::default());
        let ue = seed(&[5]);
        let ctx = crate::context::mme_self();
        let sess2 = ctx.sess_add(ue.mme_ue_id, 10);
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let u = pool.get_mut(&ue.mme_ue_id).unwrap();
            u.sess_list.push(sess2);
            u.ambr.downlink = 10_000;
            u.ambr.uplink = 10_000;
        }
        {
            let mut pool = ctx.sess_pool.write().unwrap();
            let s1 = pool.get_mut(&ue.sess_id).unwrap();
            s1.ambr.downlink = 1_000;
            s1.ambr.uplink = 500;
            let s2 = pool.get_mut(&sess2).unwrap();
            s2.ambr.downlink = 2_000;
            s2.ambr.uplink = 1_000;
        }
        for ebi in [6u8, 7] {
            let bearer_id = ctx.bearer_add(sess2, ue.mme_ue_id);
            let mut pool = ctx.bearer_pool.write().unwrap();
            let b = pool.get_mut(&bearer_id).unwrap();
            b.ebi = ebi;
            b.enb_s1u_teid = 0x1000 + u32::from(ebi);
            b.enb_s1u_ip.ipv4 = Some([10, 0, 0, 1]);
            b.sgw_s1u_teid = SGW_S1U_TEID + u32::from(ebi);
            b.sgw_s1u_ip.ipv4 = Some([10, 0, 0, 2]);
            drop(pool);
            ctx.sess_pool
                .write()
                .unwrap()
                .get_mut(&sess2)
                .unwrap()
                .bearer_list
                .push(bearer_id);
        }
        let target = ctx.enb_add(enb_addr());
        crate::s1ap_path::tap_enb_for_test(target);

        assert!(path_switch(&ue, target, &[5, 7]).is_empty());
        let (mbr, from) = recv(&sgw, 34);
        assert_eq!(bearer_context_ebis(&mbr, 0), vec![5]);
        let mut removed = bearer_context_ebis(&mbr, 1);
        removed.sort();
        assert_eq!(removed, vec![6, 7]);
        sgw.send_to(
            &mbr_response(ue.local_teid, mbr.header.sequence_number, 16, &[(5, 16)]),
            from,
        )
        .unwrap();
        let ack = wait_pdu(target, path_switch_ack);
        assert_eq!(ack_lists(&ack), (vec![(5, SGW_S1U_TEID + 5)], vec![7]));
        let ambr = ack
            .protocol_i_es
            .0
            .iter()
            .find_map(|ie| match &ie.value {
                g::PathSwitchRequestAcknowledgeProtocolIEs_EntryValue::Id_uEaggregateMaximumBitrate(a) => {
                    Some(a.clone())
                }
                _ => None,
            })
            .expect("the UE-AMBR changed, so the acknowledge carries it");
        assert_eq!(ambr.u_eaggregate_maximum_bit_rate_dl.0, 1_000);
        assert_eq!(ambr.u_eaggregate_maximum_bit_rate_ul.0, 500);
        let (dsr, _) = recv(&sgw, 36);
        let lbi = dsr
            .get_ie(Gtp2IeType::Ebi as u8, 0)
            .and_then(|ie| ie.value.first().copied());
        assert_eq!(
            lbi,
            Some(6),
            "the Delete Session Request is for the second PDN"
        );
        assert!(ctx.sess_find_by_id(sess2).is_none());
        assert!(!detach_pending(&ue));
        ctx.bearer_pool
            .write()
            .unwrap()
            .retain(|_, b| b.mme_ue_id != ue.mme_ue_id);
        release(&ue);
    }

    /// #730 review m1: the S1 association is released while the Modify Bearer
    /// Request is outstanding. The late response sends no acknowledge to the
    /// released association and does not write the target endpoints.
    #[test]
    fn a_response_after_the_s1_release_does_not_acknowledge() {
        let _guard = lock_s11();
        let (sgw, _route) = sgw(Gtp2XactConfig::default());
        let ue = seed(&[5]);
        let ctx = crate::context::mme_self();
        let target = ctx.enb_add(enb_addr());
        crate::s1ap_path::tap_enb_for_test(target);

        assert!(path_switch(&ue, target, &[5]).is_empty());
        let (mbr, from) = recv(&sgw, 34);
        // UE CONTEXT RELEASE: the eNB UE context goes, the UE keeps its EMM state.
        ctx.enb_ue_deassociate_mme_ue(ue.source_ue_id, ue.mme_ue_id);
        ctx.enb_ue_remove(ue.source_ue_id);
        sgw.send_to(
            &mbr_response(ue.local_teid, mbr.header.sequence_number, 16, &[(5, 16)]),
            from,
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while crate::gtp_path::handover_modification_pending(ue.mme_ue_id)
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            crate::s1ap_path::take_tapped_for_test(target).is_empty(),
            "no acknowledge to a released association"
        );
        assert_eq!(bearer(&ue, 5).unwrap().enb_s1u_teid, 0x1005);
        release(&ue);
    }

    /// Add a second PDN connection to `ue`: default bearer `ebis[0]`, then
    /// dedicated ones, all active on the source eNB.
    fn add_pdn(ue: &Ue, ebis: &[u8]) -> u64 {
        let ctx = crate::context::mme_self();
        let sess = ctx.sess_add(ue.mme_ue_id, 10);
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&ue.mme_ue_id)
            .unwrap()
            .sess_list
            .push(sess);
        for ebi in ebis {
            let bearer_id = ctx.bearer_add(sess, ue.mme_ue_id);
            let mut pool = ctx.bearer_pool.write().unwrap();
            let b = pool.get_mut(&bearer_id).unwrap();
            b.ebi = *ebi;
            b.enb_s1u_teid = 0x1000 + u32::from(*ebi);
            b.enb_s1u_ip.ipv4 = Some([10, 0, 0, 1]);
            b.sgw_s1u_teid = SGW_S1U_TEID + u32::from(*ebi);
            b.sgw_s1u_ip.ipv4 = Some([10, 0, 0, 2]);
            drop(pool);
            ctx.sess_pool
                .write()
                .unwrap()
                .get_mut(&sess)
                .unwrap()
                .bearer_list
                .push(bearer_id);
        }
        sess
    }

    /// #730 re-review N1, TS 23.401 §5.5.1.2.2 step 16: on S1, the target admits
    /// the first PDN's default bearer (5) and the second PDN's dedicated bearer
    /// (7) but not its default bearer (6). The second PDN is released, and the
    /// target is told to release E-RAB 7, which it holds for a deleted bearer.
    #[test]
    fn s1_a_dedicated_bearer_admitted_with_its_pdn_dropped_is_released_at_the_target() {
        let _guard = lock_s11();
        let (sgw, _route) = sgw(Gtp2XactConfig::default());
        let ue = seed(&[5]);
        let sess2 = add_pdn(&ue, &[6, 7]);
        let ctx = crate::context::mme_self();
        let (target_enb, target_ue_id) = notify_handover(&ue, &[5, 7]);

        let (mbr, from) = recv(&sgw, 34);
        assert_eq!(bearer_context_ebis(&mbr, 0), vec![5]);
        let mut removed = bearer_context_ebis(&mbr, 1);
        removed.sort();
        assert_eq!(removed, vec![6, 7]);
        sgw.send_to(
            &mbr_response(ue.local_teid, mbr.header.sequence_number, 16, &[(5, 16)]),
            from,
        )
        .unwrap();
        let released = wait_pdu(target_enb, |pdu| match pdu {
            g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
                value: g::InitiatingMessageValue::Id_E_RABRelease(cmd),
                ..
            }) => cmd.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
                g::E_RABReleaseCommandProtocolIEs_EntryValue::Id_E_RABToBeReleasedList(l) => Some(
                    l.0.iter()
                        .map(|e| {
                            let g::E_RABList_EntryValue::Id_E_RABItem(i) = &e.value;
                            i.e_rab_id.0
                        })
                        .collect::<Vec<u8>>(),
                ),
                _ => None,
            }),
            _ => None,
        });
        assert_eq!(released, vec![7], "E-RAB 7 is released at the target");
        let (dsr, _) = recv(&sgw, 36);
        assert_eq!(
            dsr.get_ie(Gtp2IeType::Ebi as u8, 0)
                .and_then(|ie| ie.value.first().copied()),
            Some(6)
        );
        assert!(ctx.sess_find_by_id(sess2).is_none());
        ctx.enb_ue_remove(target_ue_id);
        release(&ue);
    }

    /// #730 re-review m-a: one mobility procedure at a time. HANDOVER REQUIRED
    /// while a Path Switch's Modify Bearer Request is outstanding gets HANDOVER
    /// PREPARATION FAILURE (interaction with other procedure), and a PATH SWITCH
    /// REQUEST while an S1 preparation is outstanding gets PATH SWITCH REQUEST
    /// FAILURE, so one UE never has two Serving GW switches in flight.
    #[test]
    fn a_second_mobility_procedure_is_refused_while_one_is_in_flight() {
        let _guard = lock_s11();
        let (sgw, _route) = sgw(Gtp2XactConfig::default());
        let ue = seed(&[5]);
        let ctx = crate::context::mme_self();
        let target = ctx.enb_add(enb_addr());
        ctx.enb_set_enb_id(target, 0x7301);
        crate::s1ap_path::tap_enb_for_test(target);

        // X2 first: its MBR is outstanding.
        assert!(path_switch(&ue, target, &[5]).is_empty());
        let (mbr, from) = recv(&sgw, 34);
        let required = nextgcore_s1ap::HandoverRequired {
            mme_ue_s1ap_id: ue.mme_ue_s1ap_id,
            enb_ue_s1ap_id: 200,
            handover_type: nextgcore_s1ap::HandoverType::IntraLte,
            cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
            target_id: nextgcore_s1ap::TargetId::TargetEnbId {
                global_enb_id: nextgcore_s1ap::GlobalEnbId {
                    plmn_identity: [0x13, 0x00, 0x14],
                    enb_id: nextgcore_s1ap::EnbId::Macro(0x7301),
                },
                selected_tai: Tai {
                    plmn_identity: [0x13, 0x00, 0x14],
                    tac: 2,
                },
            },
            direct_forwarding_path_availability: None,
            source_to_target_container: vec![0x00],
        };
        let out =
            crate::s1ap_handler::handle_handover_required_reporting(ctx, target, &required, &[]);
        assert_eq!(out.len(), 1);
        let refused = matches!(
            nextgcore_s1ap_gen::decode(&out[0].pdu),
            Ok(g::S1AP_PDU::UnsuccessfulOutcome(g::UnsuccessfulOutcome {
                value: g::UnsuccessfulOutcomeValue::Id_HandoverPreparation(_),
                ..
            }))
        );
        assert!(
            refused,
            "HANDOVER PREPARATION FAILURE: {:?}",
            nextgcore_s1ap_gen::decode(&out[0].pdu)
        );
        assert!(
            !ctx.enb_ue_pool
                .read()
                .unwrap()
                .values()
                .any(|t| t.mme_ue_id == ue.mme_ue_id && t.handover_prep_deadline.is_some()),
            "no S1 preparation was started"
        );
        // The Path Switch still completes.
        sgw.send_to(
            &mbr_response(ue.local_teid, mbr.header.sequence_number, 16, &[(5, 16)]),
            from,
        )
        .unwrap();
        wait_pdu(target, path_switch_ack);

        // The other order: an S1 preparation outstanding refuses a Path Switch.
        let prep_target = ctx.enb_ue_add(target, 400);
        {
            let mut pool = ctx.enb_ue_pool.write().unwrap();
            let t = pool.get_mut(&prep_target).unwrap();
            t.mme_ue_id = ue.mme_ue_id;
            t.source_ue_id = ue.source_ue_id;
            t.handover_prep_deadline = Some(Instant::now() + Duration::from_secs(10));
        }
        let out = path_switch(&ue, target, &[5]);
        assert_eq!(out.len(), 1);
        let cause = path_switch_failure_cause(&nextgcore_s1ap_gen::decode(&out[0].pdu).unwrap())
            .expect("PATH SWITCH REQUEST FAILURE");
        assert!(
            matches!(&cause, g::Cause::RadioNetwork(r) if r.0 == 29),
            "interaction-with-other-procedure: {cause:?}"
        );
        assert!(!types(&drain(&sgw, Duration::from_millis(300))).contains(&34));
        ctx.enb_ue_remove(prep_target);
        release(&ue);
    }

    /// #730 re-review m-b: the failure counter is rendered for `/metrics` with
    /// every reason present.
    #[test]
    fn the_failure_counter_is_rendered_for_prometheus() {
        let _guard = lock_s11();
        count_handover_failure(failure_reason::SGW_NO_ANSWER);
        let text = render_metrics();
        assert!(text.contains("# TYPE mme_handover_core_failures_total counter"));
        for reason in failure_reason::ALL {
            assert!(
                text.contains(&format!(
                    "mme_handover_core_failures_total{{reason=\"{reason}\"}}"
                )),
                "{reason}"
            );
        }
        let n: u64 = text
            .lines()
            .find(|l| l.contains("reason=\"sgw_no_answer\""))
            .and_then(|l| l.rsplit(' ').next())
            .and_then(|v| v.parse().ok())
            .unwrap();
        assert!(n >= 1);
    }

    /// #736, TS 36.413 §8.2.4 / TS 29.274 §7.6: an E-RAB MODIFICATION
    /// INDICATION whose Modify Bearer Request the Serving GW never answers still
    /// gets its E-RAB MODIFICATION CONFIRM, with every E-RAB failed, once N3 is
    /// spent; the pending record is gone and no endpoint was written. Before
    /// #736 the eNB never got a confirm and one record leaked per indication.
    #[test]
    fn an_unanswered_erab_modification_is_confirmed_failed() {
        let _guard = lock_s11();
        let (sgw, _route) = sgw(Gtp2XactConfig {
            t3_response: Duration::from_millis(100),
            n3_requests: 2,
            response_hold: Duration::from_secs(1),
        });
        let ue = seed(&[5]);
        let ctx = crate::context::mme_self();
        crate::s1ap_path::tap_enb_for_test(ue.source_enb_id);
        let indication = crate::s1ap_gen::ErabModificationIndication {
            mme_ue_s1ap_id: ue.mme_ue_s1ap_id,
            enb_ue_s1ap_id: 100,
            to_be_modified: vec![ErabSwitchedItem {
                erab_id: 5,
                transport_layer_address: vec![10, 0, 0, 7],
                gtp_teid: 0x7365,
            }],
            not_to_be_modified: vec![],
            location: None,
        };
        let out = crate::s1ap_handler::handle_erab_modification_indication(
            ctx,
            ue.source_enb_id,
            &indication,
            &[],
        );
        assert!(out.is_empty(), "the confirm waits for the Serving GW");
        let (mbr, _) = recv(&sgw, 34);
        assert_eq!(
            bearer_contexts(&mbr),
            vec![(5, 0, 0x7365, Some([10, 0, 0, 7]))],
            "the new endpoint goes to the SGW"
        );
        assert_eq!(
            bearer(&ue, 5).unwrap().enb_s1u_teid,
            0x1005,
            "not written yet"
        );
        let failed = wait_pdu(ue.source_enb_id, |pdu| {
            match pdu {
            g::S1AP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
                value: g::SuccessfulOutcomeValue::Id_E_RABModificationIndication(c),
                ..
            }) => Some(
                c.protocol_i_es
                    .0
                    .iter()
                    .filter_map(|ie| match &ie.value {
                        g::E_RABModificationConfirmProtocolIEs_EntryValue::Id_E_RABFailedToModifyListBearerModConf(l) => Some(
                            l.0.iter()
                                .map(|e| {
                                    let g::E_RABList_EntryValue::Id_E_RABItem(i) = &e.value;
                                    i.e_rab_id.0
                                })
                                .collect::<Vec<u8>>(),
                        ),
                        _ => None,
                    })
                    .flatten()
                    .collect::<Vec<u8>>(),
            ),
            _ => None,
        }
        });
        assert_eq!(failed, vec![5], "every E-RAB failed to modify");
        assert!(
            crate::gtp_path::take_pending_erab_modification(mbr.header.sequence_number).is_none()
        );
        assert_eq!(
            bearer(&ue, 5).unwrap().enb_s1u_teid,
            0x1005,
            "the unconfirmed endpoint is never written"
        );
        release(&ue);
    }
}
