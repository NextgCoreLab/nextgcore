//! S1AP Message Handling
//!
//! Port of src/mme/s1ap-handler.c - S1AP message handling functions.
//!
//! Incoming PDUs are decoded with the generated codec (`crate::s1ap_gen`; real APER per
//! TS 36.413) and dispatched by message type. Each handler updates the MME
//! context and returns the S1AP PDUs to transmit (responses may target a
//! different eNB than the origin, e.g. during S1 handover).

use crate::context::{
    ECgi, EpsTai, MmeContext, PagingType, S1apCause, S1apCauseGroup, UeCtxRelAction,
    INVALID_UE_S1AP_ID, NEXTGCORE_INVALID_POOL_ID,
};
use crate::nas_dispatch;
use crate::s1ap_build::{
    self, cause_from_s1ap, decode_plmn_id, ecgi_from_s1ap, misc_cause, protocol_cause,
    radio_network_cause, tai_from_s1ap, transport_address_to_ip, ue_security_capabilities_from,
};
use nextgcore_s1ap::{
    BroadcastCancelledAreaList, BroadcastCompletedAreaList, Cause, CauseRadioNetwork,
    CriticalityDiagnostics, EnbConfigurationUpdate, EnbStatusTransfer, ErabDataForwardingItem,
    ErabToBeSetupItemHoReq, ErrorIndication, HandoverCancel, HandoverCancelAcknowledge,
    HandoverCommand, HandoverFailure, HandoverNotify, HandoverPreparationFailure, HandoverRequest,
    HandoverRequestAcknowledge, HandoverRequired, HandoverType as S1apHandoverType,
    InitialContextSetupFailure, InitialContextSetupResponse, InitialUeMessage, KillResponse,
    MmeStatusTransfer, NasNonDeliveryIndication, PathSwitchRequest, PathSwitchRequestFailure,
    Reset, ResetAcknowledge, ResetType, S1SetupRequest, S1apMessage, SecurityContext, TargetId,
    TimeToWait, UeCapabilityInfoIndication, UeContextReleaseComplete, UeContextReleaseRequest,
    UlNasTransport, WriteReplaceWarningResponse,
};

// ============================================================================
// S1AP Error Types
// ============================================================================

/// S1AP error types
#[derive(Debug)]
pub enum S1apError {
    /// Invalid message format
    InvalidMessage(String),
    /// Missing mandatory IE
    MissingMandatoryIe(String),
    /// Unknown procedure
    UnknownProcedure(u8),
    /// Unknown eNB
    UnknownEnb,
    /// Unknown UE
    UnknownUe,
    /// Decoding error
    DecodingError(String),
    /// Encoding error
    EncodingError(String),
    /// Protocol error
    ProtocolError(String),
}

impl std::fmt::Display for S1apError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            S1apError::InvalidMessage(msg) => write!(f, "Invalid message: {msg}"),
            S1apError::MissingMandatoryIe(ie) => write!(f, "Missing mandatory IE: {ie}"),
            S1apError::UnknownProcedure(code) => write!(f, "Unknown procedure: {code}"),
            S1apError::UnknownEnb => write!(f, "Unknown eNB"),
            S1apError::UnknownUe => write!(f, "Unknown UE"),
            S1apError::DecodingError(msg) => write!(f, "Decoding error: {msg}"),
            S1apError::EncodingError(msg) => write!(f, "Encoding error: {msg}"),
            S1apError::ProtocolError(msg) => write!(f, "Protocol error: {msg}"),
        }
    }
}

impl std::error::Error for S1apError {}

impl From<nextgcore_s1ap::S1apError> for S1apError {
    fn from(e: nextgcore_s1ap::S1apError) -> Self {
        match e {
            nextgcore_s1ap::S1apError::MissingMandatoryIe(ie) => {
                S1apError::MissingMandatoryIe(ie.to_string())
            }
            other => S1apError::DecodingError(other.to_string()),
        }
    }
}

/// S1AP result type
pub type S1apResult<T> = Result<T, S1apError>;

// ============================================================================
// Outgoing PDU Wrapper
// ============================================================================

/// An S1AP PDU queued for transmission to an eNB
#[derive(Debug, Clone)]
pub struct S1apSend {
    /// eNB pool ID the PDU must be sent to
    pub enb_id: u64,
    /// APER-encoded S1AP PDU
    pub pdu: Vec<u8>,
}

impl S1apSend {
    fn to_origin(enb_id: u64, pdu: Vec<u8>) -> Vec<S1apSend> {
        vec![S1apSend { enb_id, pdu }]
    }
}

/// How long a prepared handover may stay outstanding before the MME releases the
/// target eNB's resources (#48).
///
/// TS 36.413 names TS1RELOCprep and TS1RELOCoverall for the SOURCE eNB and leaves the
/// MME's own supervision to implementation, so this value is a local choice, not a
/// specified one. 10 s is comfortably longer than the source's own TS1RELOCprep (a few
/// seconds in practice) so the source's failure handling runs first and this only fires
/// when the source went away too -- which is exactly the case that used to leak the
/// context forever. `cause = tS1relocoverall-expiry` (TS 36.413 §9.2.1.3, value 8) is
/// the cause that says so on the wire.
pub const HANDOVER_PREPARATION_SUPERVISION: std::time::Duration =
    std::time::Duration::from_secs(10);

// ============================================================================
// Top-Level Dispatch
// ============================================================================

/// UE CONTEXT MODIFICATION FAILUREs received, for a UE-AMBR modification and for
/// any other (#869 review).
static UE_CONTEXT_MODIFICATION_FAILURES: [std::sync::atomic::AtomicU64; 2] = [
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
];

fn count_ue_context_modification_failure(what: &'static str) {
    let i = usize::from(what != "ue_ambr");
    UE_CONTEXT_MODIFICATION_FAILURES[i].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// The UE Context Modification failure counter in Prometheus text format.
pub fn render_metrics() -> String {
    let n =
        |i: usize| UE_CONTEXT_MODIFICATION_FAILURES[i].load(std::sync::atomic::Ordering::Relaxed);
    format!(
        "# HELP mme_s1ap_ue_context_modification_failures_total UE CONTEXT MODIFICATION \
         FAILUREs received, by what the request carried (TS 36.413 8.3.4.3)\n\
         # TYPE mme_s1ap_ue_context_modification_failures_total counter\n\
         mme_s1ap_ue_context_modification_failures_total{{carried=\"ue_ambr\"}} {}\n\
         mme_s1ap_ue_context_modification_failures_total{{carried=\"other\"}} {}\n",
        n(0),
        n(1)
    )
}

/// Whether the UE Context Modification answered on `enb_id` for
/// `mme_ue_s1ap_id` carried a UE-AMBR; the outstanding mark is cleared.
fn take_ue_ambr_modification(ctx: &MmeContext, enb_id: u64, mme_ue_s1ap_id: u32) -> bool {
    let Some(mme_ue_id) = ctx
        .enb_ue_find_by_mme_ue_s1ap_id(mme_ue_s1ap_id)
        .and_then(|id| ctx.enb_ue_find_by_id(id))
        .filter(|e| e.enb_id == enb_id)
        .map(|e| e.mme_ue_id)
    else {
        return false;
    };
    ctx.mme_ue_pool
        .write()
        .unwrap()
        .get_mut(&mme_ue_id)
        .is_some_and(|ue| std::mem::take(&mut ue.ue_ambr_modification_pending))
}

/// Decode an incoming S1AP PDU from `enb_id` and dispatch it to the matching
/// procedure handler. Returns the PDUs to transmit in response.
pub fn handle_s1ap_message(ctx: &MmeContext, enb_id: u64, data: &[u8]) -> Vec<S1apSend> {
    let mut out = handle_s1ap_message_inner(ctx, enb_id, data);
    // #869 review: a UE-AMBR change deferred behind an Initial Context Setup or
    // S1 handover is signalled once the procedure has ended.
    out.extend(crate::s6a_handler::deferred_ue_ambr_sends(ctx));
    out
}

fn handle_s1ap_message_inner(ctx: &MmeContext, enb_id: u64, data: &[u8]) -> Vec<S1apSend> {
    // S1 Setup is decoded with the generated codec, which applies TS 36.413
    // §10.3.4 / §10.3.5 to unknown and missing IEs (#514 stage 2).
    if crate::s1ap_gen::is_s1_setup_request(data) {
        match crate::s1ap_gen::decode_s1_setup_request(data) {
            crate::s1ap_gen::SetupRequestDecode::Proceed { request, notify } => {
                return handle_s1_setup_request_reporting(ctx, enb_id, &request, &notify);
            }
            crate::s1ap_gen::SetupRequestDecode::Reject(ies) => {
                log::error!(
                    "S1 Setup Request from eNB {enb_id} rejected (TS 36.413 §10.3.4/§10.3.5): {ies:?}"
                );
                return match s1ap_build::build_setup_failure_with_diagnostics(
                    S1apCauseGroup::Protocol,
                    protocol_cause::ABSTRACT_SYNTAX_ERROR_REJECT,
                    None,
                    &ies,
                ) {
                    Ok(pdu) => S1apSend::to_origin(enb_id, pdu),
                    Err(e) => {
                        log::error!("Failed to build S1 Setup Failure: {e}");
                        Vec::new()
                    }
                };
            }
            // Fall through: the generic path below answers a PDU that does not
            // decode with an Error Indication (transfer syntax error).
            crate::s1ap_gen::SetupRequestDecode::Undecodable => {}
        }
    }
    // NAS transport is decoded with the generated codec (#514 stage 3).
    // Both are Class 2 (no response message): §10.3.4.2 answers `notify` and
    // `reject` IEs with an ERROR INDICATION.
    if crate::s1ap_gen::is_initiating(data, crate::s1ap_gen::PROC_INITIAL_UE_MESSAGE) {
        use crate::s1ap_gen::Class2Decode;
        match crate::s1ap_gen::decode_initial_ue_message(data) {
            Class2Decode::Proceed { msg, notify } => {
                let mut out = class2_notify(
                    enb_id,
                    crate::s1ap_gen::PROC_INITIAL_UE_MESSAGE,
                    Some(msg.enb_ue_s1ap_id),
                    None,
                    &notify,
                );
                if let Some(enb_ue_id) = handle_initial_ue_message(ctx, enb_id, &msg) {
                    nas_dispatch::nas_eps_handle_uplink(
                        ctx,
                        nas_dispatch::UplinkNas {
                            enb_ue_id,
                            nas_pdu: &msg.nas_pdu,
                            s_tmsi: msg.s_tmsi.as_ref().map(|s| (s.mmec, s.m_tmsi)),
                        },
                    );
                }
                return std::mem::take(&mut out);
            }
            Class2Decode::Reject {
                ies,
                enb_ue_s1ap_id,
                mme_ue_s1ap_id,
            } => {
                return class2_reject(
                    enb_id,
                    crate::s1ap_gen::PROC_INITIAL_UE_MESSAGE,
                    enb_ue_s1ap_id,
                    mme_ue_s1ap_id,
                    &ies,
                );
            }
            Class2Decode::Undecodable => {}
        }
    }
    // Initial Context Setup responses are decoded with the generated codec
    // (#514 stage 4). They are response messages: §10.3.4.2 handles a `reject`
    // IE locally (nothing sent) and reports `notify` IEs in an ERROR INDICATION.
    for successful in [true, false] {
        if !crate::s1ap_gen::is_outcome(
            data,
            successful,
            crate::s1ap_gen::PROC_INITIAL_CONTEXT_SETUP,
        ) {
            continue;
        }
        use crate::s1ap_gen::ResponseDecode;
        let trigger = if successful {
            nextgcore_s1ap::triggering_message::SUCCESSFUL_OUTCOME
        } else {
            nextgcore_s1ap::triggering_message::UNSUCCESSFUL_OUTCOME
        };
        let report = |mme: u32, enb: u32, notify: &[crate::s1ap_gen::DiagnosedIe]| {
            if notify.is_empty() {
                return Vec::new();
            }
            error_indication_with_diagnostics(
                enb_id,
                Some(enb),
                Some(mme),
                S1apCauseGroup::Protocol,
                protocol_cause::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
                Some(crate::s1ap_gen::error_indication_diagnostics_for(
                    crate::s1ap_gen::PROC_INITIAL_CONTEXT_SETUP,
                    trigger,
                    0,
                    notify,
                )),
            )
        };
        if successful {
            match crate::s1ap_gen::decode_initial_context_setup_response(data) {
                ResponseDecode::Decoded { msg, notify } => {
                    let out = report(msg.mme_ue_s1ap_id, msg.enb_ue_s1ap_id, &notify);
                    handle_initial_context_setup_response(ctx, enb_id, &msg);
                    return out;
                }
                ResponseDecode::Failed(ies) => {
                    log::error!(
                        "Initial Context Setup Response from eNB {enb_id} carries a reject IE \
                         (TS 36.413 §10.3.4.2); procedure unsuccessfully terminated: {ies:?}"
                    );
                    return Vec::new();
                }
                ResponseDecode::Undecodable => {}
            }
        } else {
            match crate::s1ap_gen::decode_initial_context_setup_failure(data) {
                ResponseDecode::Decoded { msg, notify } => {
                    let mut out = report(msg.mme_ue_s1ap_id, msg.enb_ue_s1ap_id, &notify);
                    out.extend(handle_initial_context_setup_failure(ctx, enb_id, &msg));
                    return out;
                }
                ResponseDecode::Failed(ies) => {
                    log::error!(
                        "Initial Context Setup Failure from eNB {enb_id} carries a reject IE \
                         (TS 36.413 §10.3.4.2); handled locally: {ies:?}"
                    );
                    return Vec::new();
                }
                ResponseDecode::Undecodable => {}
            }
        }
    }
    if crate::s1ap_gen::is_initiating(data, crate::s1ap_gen::PROC_UPLINK_NAS_TRANSPORT) {
        use crate::s1ap_gen::Class2Decode;
        match crate::s1ap_gen::decode_uplink_nas_transport(data) {
            Class2Decode::Proceed { msg, notify } => {
                let mut out = class2_notify(
                    enb_id,
                    crate::s1ap_gen::PROC_UPLINK_NAS_TRANSPORT,
                    Some(msg.enb_ue_s1ap_id),
                    Some(msg.mme_ue_s1ap_id),
                    &notify,
                );
                match handle_uplink_nas(ctx, enb_id, &msg) {
                    Ok(enb_ue_id) => nas_dispatch::nas_eps_handle_uplink(
                        ctx,
                        nas_dispatch::UplinkNas {
                            enb_ue_id,
                            nas_pdu: &msg.nas_pdu,
                            s_tmsi: None,
                        },
                    ),
                    Err(error) => out.extend(error),
                }
                return out;
            }
            Class2Decode::Reject {
                ies,
                enb_ue_s1ap_id,
                mme_ue_s1ap_id,
            } => {
                return class2_reject(
                    enb_id,
                    crate::s1ap_gen::PROC_UPLINK_NAS_TRANSPORT,
                    enb_ue_s1ap_id,
                    mme_ue_s1ap_id,
                    &ies,
                );
            }
            Class2Decode::Undecodable => {}
        }
    }
    // UE Context Release is decoded with the generated codec (#514 stage 5).
    // The Request is a Class 2 initiating message; the Complete is a response.
    if crate::s1ap_gen::is_initiating(data, crate::s1ap_gen::PROC_UE_CONTEXT_RELEASE_REQUEST) {
        use crate::s1ap_gen::Class2Decode;
        match crate::s1ap_gen::decode_ue_context_release_request(data) {
            Class2Decode::Proceed { msg, notify } => {
                let mut out = class2_notify(
                    enb_id,
                    crate::s1ap_gen::PROC_UE_CONTEXT_RELEASE_REQUEST,
                    Some(msg.enb_ue_s1ap_id),
                    Some(msg.mme_ue_s1ap_id),
                    &notify,
                );
                out.extend(handle_ue_context_release_request(ctx, enb_id, &msg));
                return out;
            }
            Class2Decode::Reject {
                ies,
                enb_ue_s1ap_id,
                mme_ue_s1ap_id,
            } => {
                return class2_reject(
                    enb_id,
                    crate::s1ap_gen::PROC_UE_CONTEXT_RELEASE_REQUEST,
                    enb_ue_s1ap_id,
                    mme_ue_s1ap_id,
                    &ies,
                );
            }
            Class2Decode::Undecodable => {}
        }
    }
    if crate::s1ap_gen::is_outcome(data, true, crate::s1ap_gen::PROC_UE_CONTEXT_RELEASE) {
        use crate::s1ap_gen::ResponseDecode;
        match crate::s1ap_gen::decode_ue_context_release_complete(data) {
            ResponseDecode::Decoded { msg, notify } => {
                let out = if notify.is_empty() {
                    Vec::new()
                } else {
                    error_indication_with_diagnostics(
                        enb_id,
                        msg.enb_ue_s1ap_id,
                        msg.mme_ue_s1ap_id,
                        S1apCauseGroup::Protocol,
                        protocol_cause::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
                        Some(crate::s1ap_gen::error_indication_diagnostics_for(
                            crate::s1ap_gen::PROC_UE_CONTEXT_RELEASE,
                            nextgcore_s1ap::triggering_message::SUCCESSFUL_OUTCOME,
                            0,
                            &notify,
                        )),
                    )
                };
                handle_release_complete(ctx, enb_id, &msg);
                return out;
            }
            ResponseDecode::Failed(ies) => {
                log::error!(
                    "UE Context Release Complete from eNB {enb_id} carries a reject IE \
                     (TS 36.413 §10.3.4.2); handled locally: {ies:?}"
                );
                return Vec::new();
            }
            ResponseDecode::Undecodable => {}
        }
    }
    // E-RAB responses are decoded with the generated codec (#514 stage 6).
    // Response messages: a `reject` IE is handled locally, `notify` IEs are
    // reported in an ERROR INDICATION.
    for (proc_code, name) in [
        (crate::s1ap_gen::PROC_E_RAB_SETUP, "E-RAB Setup Response"),
        (crate::s1ap_gen::PROC_E_RAB_MODIFY, "E-RAB Modify Response"),
        (
            crate::s1ap_gen::PROC_E_RAB_RELEASE,
            "E-RAB Release Response",
        ),
    ] {
        if !crate::s1ap_gen::is_outcome(data, true, proc_code) {
            continue;
        }
        use crate::s1ap_gen::ResponseDecode;
        let report = |mme: u32, enb: u32, notify: &[crate::s1ap_gen::DiagnosedIe]| {
            if notify.is_empty() {
                return Vec::new();
            }
            error_indication_with_diagnostics(
                enb_id,
                Some(enb),
                Some(mme),
                S1apCauseGroup::Protocol,
                protocol_cause::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
                Some(crate::s1ap_gen::error_indication_diagnostics_for(
                    proc_code,
                    nextgcore_s1ap::triggering_message::SUCCESSFUL_OUTCOME,
                    0,
                    notify,
                )),
            )
        };
        let failed = |ies: Vec<crate::s1ap_gen::DiagnosedIe>| {
            log::error!(
                "{name} from eNB {enb_id} carries a reject IE (TS 36.413 §10.3.4.2); \
                 handled locally: {ies:?}"
            );
            Vec::new()
        };
        match proc_code {
            crate::s1ap_gen::PROC_E_RAB_SETUP => {
                match crate::s1ap_gen::decode_erab_setup_response(data) {
                    ResponseDecode::Decoded { msg, notify } => {
                        let out = report(msg.mme_ue_s1ap_id, msg.enb_ue_s1ap_id, &notify);
                        handle_erab_setup_response(
                            ctx,
                            enb_id,
                            msg.mme_ue_s1ap_id,
                            msg.enb_ue_s1ap_id,
                            &msg.erab_setup_list,
                        );
                        log_erab_failures(enb_id, &msg.erab_failed_list);
                        return out;
                    }
                    ResponseDecode::Failed(ies) => return failed(ies),
                    ResponseDecode::Undecodable => {}
                }
            }
            crate::s1ap_gen::PROC_E_RAB_MODIFY => {
                match crate::s1ap_gen::decode_erab_modify_response(data) {
                    ResponseDecode::Decoded { msg, notify } => {
                        log_erab_failures(enb_id, &msg.erab_failed_list);
                        return report(msg.mme_ue_s1ap_id, msg.enb_ue_s1ap_id, &notify);
                    }
                    ResponseDecode::Failed(ies) => return failed(ies),
                    ResponseDecode::Undecodable => {}
                }
            }
            _ => match crate::s1ap_gen::decode_erab_release_response(data) {
                ResponseDecode::Decoded { msg, notify } => {
                    log_erab_failures(enb_id, &msg.erab_failed_list);
                    return report(msg.mme_ue_s1ap_id, msg.enb_ue_s1ap_id, &notify);
                }
                ResponseDecode::Failed(ies) => return failed(ies),
                ResponseDecode::Undecodable => {}
            },
        }
    }
    // Handover, part 1, is decoded with the generated codec (#514 stage 8a).
    {
        use crate::s1ap_gen::{Class2Decode, ResponseDecode};
        if crate::s1ap_gen::is_initiating(data, crate::s1ap_gen::PROC_HANDOVER_NOTIFICATION) {
            match crate::s1ap_gen::decode_handover_notify(data) {
                Class2Decode::Proceed { msg, notify } => {
                    let mut out = class2_notify(
                        enb_id,
                        crate::s1ap_gen::PROC_HANDOVER_NOTIFICATION,
                        Some(msg.enb_ue_s1ap_id),
                        Some(msg.mme_ue_s1ap_id),
                        &notify,
                    );
                    out.extend(handle_handover_notify_at(
                        ctx,
                        enb_id,
                        msg.mme_ue_s1ap_id,
                        msg.enb_ue_s1ap_id,
                        msg.location.as_ref().map(|(t, c)| (t, c)),
                    ));
                    return out;
                }
                Class2Decode::Reject {
                    ies,
                    enb_ue_s1ap_id,
                    mme_ue_s1ap_id,
                } => {
                    return class2_reject(
                        enb_id,
                        crate::s1ap_gen::PROC_HANDOVER_NOTIFICATION,
                        enb_ue_s1ap_id,
                        mme_ue_s1ap_id,
                        &ies,
                    );
                }
                Class2Decode::Undecodable => {}
            }
        }
        if crate::s1ap_gen::is_initiating(data, crate::s1ap_gen::PROC_ENB_STATUS_TRANSFER) {
            match crate::s1ap_gen::decode_enb_status_transfer(data) {
                Class2Decode::Proceed { msg, notify } => {
                    let mut out = class2_notify(
                        enb_id,
                        crate::s1ap_gen::PROC_ENB_STATUS_TRANSFER,
                        Some(msg.enb_ue_s1ap_id),
                        Some(msg.mme_ue_s1ap_id),
                        &notify,
                    );
                    out.extend(handle_enb_status_transfer(ctx, enb_id, &msg));
                    return out;
                }
                Class2Decode::Reject {
                    ies,
                    enb_ue_s1ap_id,
                    mme_ue_s1ap_id,
                } => {
                    return class2_reject(
                        enb_id,
                        crate::s1ap_gen::PROC_ENB_STATUS_TRANSFER,
                        enb_ue_s1ap_id,
                        mme_ue_s1ap_id,
                        &ies,
                    );
                }
                Class2Decode::Undecodable => {}
            }
        }
        if crate::s1ap_gen::is_initiating(data, crate::s1ap_gen::PROC_HANDOVER_CANCEL) {
            // Class 1 with a response: `notify` IEs go in the acknowledge's
            // diagnostics; a `reject` IE stops the procedure. HANDOVER CANCEL
            // has no failure message, so that is reported by ERROR INDICATION.
            match crate::s1ap_gen::decode_handover_cancel(data) {
                Class2Decode::Proceed { msg, notify } => {
                    return handle_handover_cancel_reporting(ctx, enb_id, &msg, &notify);
                }
                Class2Decode::Reject {
                    ies,
                    enb_ue_s1ap_id,
                    mme_ue_s1ap_id,
                } => {
                    return class2_reject(
                        enb_id,
                        crate::s1ap_gen::PROC_HANDOVER_CANCEL,
                        enb_ue_s1ap_id,
                        mme_ue_s1ap_id,
                        &ies,
                    );
                }
                Class2Decode::Undecodable => {}
            }
        }
        // Handover, part 2 (#514 stage 8b). HANDOVER REQUIRED is Class 1 with
        // both a response and a failure: `notify` IEs go in the HANDOVER
        // COMMAND (or the HANDOVER PREPARATION FAILURE), a missing or not
        // understood `reject` IE is answered by HANDOVER PREPARATION FAILURE.
        if crate::s1ap_gen::is_initiating(data, crate::s1ap_gen::PROC_HANDOVER_PREPARATION) {
            use crate::s1ap_gen::HandoverRequiredDecode as D;
            match crate::s1ap_gen::decode_handover_required(data) {
                D::Proceed { msg, notify } => {
                    return handle_handover_required_reporting(ctx, enb_id, &msg, &notify);
                }
                D::ToFivegs { msg, notify } => {
                    return handle_handover_required_to_5gs(ctx, enb_id, &msg, &notify);
                }
                D::UnsupportedTarget {
                    mme_ue_s1ap_id,
                    enb_ue_s1ap_id,
                } => {
                    log::warn!(
                        "Handover Required from eNB {enb_id} names a target this MME cannot \
                         serve (NG-RAN node or short/long macro eNB ID)"
                    );
                    return handover_preparation_failure(
                        enb_id,
                        mme_ue_s1ap_id,
                        enb_ue_s1ap_id,
                        radio_network_cause::UNKNOWN_TARGET_ID,
                        &[],
                    );
                }
                D::Reject {
                    ies,
                    enb_ue_s1ap_id,
                    mme_ue_s1ap_id,
                } => {
                    log::error!(
                        "Handover Required from eNB {enb_id} rejected (TS 36.413 §10.3.4/§10.3.5): {ies:?}"
                    );
                    let failure = HandoverPreparationFailure {
                        mme_ue_s1ap_id: mme_ue_s1ap_id.unwrap_or(0),
                        enb_ue_s1ap_id: enb_ue_s1ap_id.unwrap_or(0),
                        cause: s1ap_build::cause_to_s1ap(
                            S1apCauseGroup::Protocol,
                            protocol_cause::ABSTRACT_SYNTAX_ERROR_REJECT,
                        ),
                    };
                    return match crate::s1ap_gen::build_handover_preparation_failure_with_diagnostics(
                        &failure, &ies,
                    ) {
                        Ok(pdu) => S1apSend::to_origin(enb_id, pdu),
                        Err(e) => {
                            log::error!("Failed to build Handover Preparation Failure: {e}");
                            Vec::new()
                        }
                    };
                }
                D::Undecodable => {}
            }
        }
        // HANDOVER REQUEST ACKNOWLEDGE is a response: a `reject` IE (or the
        // missing Target-to-Source container) is handled locally; `notify` IEs
        // are reported by ERROR INDICATION.
        if crate::s1ap_gen::is_outcome(
            data,
            true,
            crate::s1ap_gen::PROC_HANDOVER_RESOURCE_ALLOCATION,
        ) {
            match crate::s1ap_gen::decode_handover_request_acknowledge(data) {
                ResponseDecode::Decoded { msg, notify } => {
                    let mut out = if notify.is_empty() {
                        Vec::new()
                    } else {
                        error_indication_with_diagnostics(
                            enb_id,
                            Some(msg.enb_ue_s1ap_id),
                            Some(msg.mme_ue_s1ap_id),
                            S1apCauseGroup::Protocol,
                            protocol_cause::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
                            Some(crate::s1ap_gen::error_indication_diagnostics_for(
                                crate::s1ap_gen::PROC_HANDOVER_RESOURCE_ALLOCATION,
                                nextgcore_s1ap::triggering_message::SUCCESSFUL_OUTCOME,
                                0,
                                &notify,
                            )),
                        )
                    };
                    out.extend(handle_handover_request_acknowledge(ctx, enb_id, &msg));
                    return out;
                }
                ResponseDecode::Failed(ies) => {
                    log::error!(
                        "Handover Request Acknowledge from eNB {enb_id} carries a reject IE or \
                         lacks one (TS 36.413 §10.3.4.2/§10.3.5); handled locally, the \
                         preparation supervision releases the target: {ies:?}"
                    );
                    return Vec::new();
                }
                ResponseDecode::Undecodable => {}
            }
        }
        if crate::s1ap_gen::is_outcome(
            data,
            false,
            crate::s1ap_gen::PROC_HANDOVER_RESOURCE_ALLOCATION,
        ) {
            match crate::s1ap_gen::decode_handover_failure(data) {
                ResponseDecode::Decoded { msg, notify } => {
                    let mut out = if notify.is_empty() {
                        Vec::new()
                    } else {
                        error_indication_with_diagnostics(
                            enb_id,
                            None,
                            Some(msg.mme_ue_s1ap_id),
                            S1apCauseGroup::Protocol,
                            protocol_cause::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
                            Some(crate::s1ap_gen::error_indication_diagnostics_for(
                                crate::s1ap_gen::PROC_HANDOVER_RESOURCE_ALLOCATION,
                                nextgcore_s1ap::triggering_message::UNSUCCESSFUL_OUTCOME,
                                0,
                                &notify,
                            )),
                        )
                    };
                    out.extend(handle_handover_failure(ctx, enb_id, &msg));
                    return out;
                }
                ResponseDecode::Failed(ies) => {
                    log::error!(
                        "Handover Failure from eNB {enb_id} carries a reject IE \
                         (TS 36.413 §10.3.4.2); handled locally: {ies:?}"
                    );
                    return Vec::new();
                }
                ResponseDecode::Undecodable => {}
            }
        }
    }
    // Reset and Error Indication are decoded with the generated codec (#514
    // stage 9).
    if crate::s1ap_gen::is_initiating(data, crate::s1ap_gen::PROC_RESET) {
        use crate::s1ap_gen::Class2Decode;
        // Class 1 with a response: `notify` IEs go in the acknowledge; a
        // `reject` IE or a missing ResetType stops the procedure, reported by
        // ERROR INDICATION since RESET has no failure message.
        match crate::s1ap_gen::decode_reset(data) {
            Class2Decode::Proceed { msg, notify } => {
                return handle_reset_reporting(ctx, enb_id, &msg, &notify);
            }
            Class2Decode::Reject { ies, .. } => {
                return class2_reject(enb_id, crate::s1ap_gen::PROC_RESET, None, None, &ies);
            }
            Class2Decode::Undecodable => {}
        }
    }
    if crate::s1ap_gen::is_initiating(data, crate::s1ap_gen::PROC_ERROR_INDICATION) {
        // Every IE is optional and ignore. An ERROR INDICATION is never answered
        // with another (TS 36.413 §10.1: no ping-pong), so unknown IEs are only
        // logged, whatever their criticality.
        if let Some((msg, unknown)) = crate::s1ap_gen::decode_error_indication(data) {
            if !unknown.is_empty() {
                log::warn!(
                    "Error Indication from eNB {enb_id} carries unknown IEs, not answered: {unknown:?}"
                );
            }
            handle_error_indication(ctx, enb_id, &msg);
            return Vec::new();
        }
    }
    // Path Switch is decoded with the generated codec (#514 stage 10). Class 1
    // with both a response and a failure: `notify` IEs go in the acknowledge,
    // a `reject` IE or a missing reject IE is answered by PATH SWITCH REQUEST
    // FAILURE naming it.
    if crate::s1ap_gen::is_initiating(data, crate::s1ap_gen::PROC_PATH_SWITCH_REQUEST) {
        use crate::s1ap_gen::Class2Decode;
        match crate::s1ap_gen::decode_path_switch_request(data) {
            Class2Decode::Proceed { msg, notify } => {
                return handle_path_switch_request_reporting(ctx, enb_id, &msg, &notify);
            }
            Class2Decode::Reject {
                ies,
                enb_ue_s1ap_id,
                mme_ue_s1ap_id,
            } => {
                log::error!(
                    "Path Switch Request from eNB {enb_id} rejected (TS 36.413 §10.3.4/§10.3.5): {ies:?}"
                );
                let failure = nextgcore_s1ap::PathSwitchRequestFailure {
                    mme_ue_s1ap_id: mme_ue_s1ap_id.unwrap_or(0),
                    enb_ue_s1ap_id: enb_ue_s1ap_id.unwrap_or(0),
                    cause: s1ap_build::cause_to_s1ap(
                        S1apCauseGroup::Protocol,
                        protocol_cause::ABSTRACT_SYNTAX_ERROR_REJECT,
                    ),
                };
                return match crate::s1ap_gen::build_path_switch_request_failure(&failure, &ies) {
                    Ok(pdu) => S1apSend::to_origin(enb_id, pdu),
                    Err(e) => {
                        log::error!("Failed to build Path Switch Request Failure: {e}");
                        Vec::new()
                    }
                };
            }
            Class2Decode::Undecodable => {}
        }
    }
    // #584: E-RAB Release Indication, E-RAB Modification Indication and the
    // Location Reporting indications. Class 2 initiating messages (and E-RAB
    // Modification Indication, Class 1 with no failure message) whose reject
    // IEs are missing are answered with ERROR INDICATION (§10.3.4.2).
    {
        use crate::s1ap_gen::Class2Decode;
        macro_rules! class2 {
            ($decode:expr, $proc:expr, |$msg:ident, $notify:ident| $body:expr) => {
                match $decode {
                    Class2Decode::Proceed {
                        msg: $msg,
                        notify: $notify,
                    } => return $body,
                    Class2Decode::Reject {
                        ies,
                        enb_ue_s1ap_id,
                        mme_ue_s1ap_id,
                    } => {
                        return class2_reject(enb_id, $proc, enb_ue_s1ap_id, mme_ue_s1ap_id, &ies);
                    }
                    Class2Decode::Undecodable => {}
                }
            };
        }
        if crate::s1ap_gen::is_initiating(data, crate::s1ap_gen::PROC_E_RAB_RELEASE_INDICATION) {
            class2!(
                crate::s1ap_gen::decode_erab_release_indication(data),
                crate::s1ap_gen::PROC_E_RAB_RELEASE_INDICATION,
                |msg, notify| {
                    let mut out = class2_notify(
                        enb_id,
                        crate::s1ap_gen::PROC_E_RAB_RELEASE_INDICATION,
                        Some(msg.enb_ue_s1ap_id),
                        Some(msg.mme_ue_s1ap_id),
                        &notify,
                    );
                    out.extend(handle_erab_release_indication(ctx, enb_id, &msg).0);
                    out
                }
            );
        }
        if crate::s1ap_gen::is_initiating(data, crate::s1ap_gen::PROC_E_RAB_MODIFICATION_INDICATION)
        {
            class2!(
                crate::s1ap_gen::decode_erab_modification_indication(data),
                crate::s1ap_gen::PROC_E_RAB_MODIFICATION_INDICATION,
                |msg, notify| handle_erab_modification_indication(ctx, enb_id, &msg, &notify)
            );
        }
        if crate::s1ap_gen::is_initiating(data, crate::s1ap_gen::PROC_LOCATION_REPORT) {
            class2!(
                crate::s1ap_gen::decode_location_report(data),
                crate::s1ap_gen::PROC_LOCATION_REPORT,
                |msg, notify| {
                    let mut out = class2_notify(
                        enb_id,
                        crate::s1ap_gen::PROC_LOCATION_REPORT,
                        Some(msg.enb_ue_s1ap_id),
                        Some(msg.mme_ue_s1ap_id),
                        &notify,
                    );
                    out.extend(handle_location_report(ctx, enb_id, &msg));
                    out
                }
            );
        }
        if crate::s1ap_gen::is_initiating(
            data,
            crate::s1ap_gen::PROC_LOCATION_REPORTING_FAILURE_INDICATION,
        ) {
            class2!(
                crate::s1ap_gen::decode_location_reporting_failure_indication(data),
                crate::s1ap_gen::PROC_LOCATION_REPORTING_FAILURE_INDICATION,
                |msg, notify| {
                    let mut out = class2_notify(
                        enb_id,
                        crate::s1ap_gen::PROC_LOCATION_REPORTING_FAILURE_INDICATION,
                        Some(msg.enb_ue_s1ap_id),
                        Some(msg.mme_ue_s1ap_id),
                        &notify,
                    );
                    out.extend(handle_location_reporting_failure(ctx, enb_id, &msg));
                    out
                }
            );
        }
    }
    // The rest of mmed's S1AP (#514 stage 12) is decoded with the generated
    // codec; each decode is mapped back onto the handler's existing types and
    // dispatched through the arms below. Class 2 initiating messages answer
    // `notify` / `reject` IEs with ERROR INDICATION; responses report `notify`
    // by ERROR INDICATION and handle a `reject` IE locally.
    let mut reported: Vec<S1apSend> = Vec::new();
    let generated: Option<S1apMessage> = {
        use crate::s1ap_gen::{Class2Decode, ResponseDecode};
        let response_notify =
            |reported: &mut Vec<S1apSend>,
             proc_code: u8,
             successful: bool,
             mme_ue_s1ap_id: Option<u32>,
             notify: &[crate::s1ap_gen::DiagnosedIe]| {
                if !notify.is_empty() {
                    reported.extend(error_indication_with_diagnostics(
                        enb_id,
                        None,
                        mme_ue_s1ap_id,
                        S1apCauseGroup::Protocol,
                        protocol_cause::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
                        Some(crate::s1ap_gen::error_indication_diagnostics_for(
                            proc_code,
                            if successful {
                                nextgcore_s1ap::triggering_message::SUCCESSFUL_OUTCOME
                            } else {
                                nextgcore_s1ap::triggering_message::UNSUCCESSFUL_OUTCOME
                            },
                            0,
                            notify,
                        )),
                    ));
                }
            };
        macro_rules! response {
            ($decode:expr, $proc:expr, $successful:expr, $mme:expr, $wrap:expr, $what:literal) => {
                match $decode {
                    ResponseDecode::Decoded { msg, notify } => {
                        response_notify(&mut reported, $proc, $successful, $mme(&msg), &notify);
                        Some($wrap(msg))
                    }
                    ResponseDecode::Failed(ies) => {
                        log::error!(
                            concat!($what, " from eNB {} carries a reject IE (TS 36.413 §10.3.4.2); handled locally: {:?}"),
                            enb_id,
                            ies
                        );
                        return Vec::new();
                    }
                    ResponseDecode::Undecodable => None,
                }
            };
        }
        if crate::s1ap_gen::is_initiating(data, crate::s1ap_gen::PROC_ENB_CONFIGURATION_UPDATE) {
            // Class 1 with a response and a failure: `notify` IEs go in the
            // acknowledge, a `reject` IE is answered by the failure.
            match crate::s1ap_gen::decode_enb_configuration_update(data) {
                crate::s1ap_gen::ConfigUpdateDecode::Proceed { msg, notify } => {
                    return handle_enb_configuration_update_reporting(ctx, enb_id, &msg, &notify);
                }
                crate::s1ap_gen::ConfigUpdateDecode::Reject(ies) => {
                    log::error!(
                        "eNB Configuration Update from eNB {enb_id} rejected (TS 36.413 §10.3.4): {ies:?}"
                    );
                    return config_update_failure_with(
                        enb_id,
                        S1apCauseGroup::Protocol,
                        protocol_cause::ABSTRACT_SYNTAX_ERROR_REJECT,
                        None,
                        &ies,
                    );
                }
                crate::s1ap_gen::ConfigUpdateDecode::Undecodable => None,
            }
        } else if crate::s1ap_gen::is_initiating(
            data,
            crate::s1ap_gen::PROC_NAS_NON_DELIVERY_INDICATION,
        ) {
            match crate::s1ap_gen::decode_nas_non_delivery_indication(data) {
                Class2Decode::Proceed { msg, notify } => {
                    reported.extend(class2_notify(
                        enb_id,
                        crate::s1ap_gen::PROC_NAS_NON_DELIVERY_INDICATION,
                        Some(msg.enb_ue_s1ap_id),
                        Some(msg.mme_ue_s1ap_id),
                        &notify,
                    ));
                    Some(S1apMessage::NasNonDeliveryIndication(msg))
                }
                Class2Decode::Reject {
                    ies,
                    enb_ue_s1ap_id,
                    mme_ue_s1ap_id,
                } => {
                    return class2_reject(
                        enb_id,
                        crate::s1ap_gen::PROC_NAS_NON_DELIVERY_INDICATION,
                        enb_ue_s1ap_id,
                        mme_ue_s1ap_id,
                        &ies,
                    );
                }
                Class2Decode::Undecodable => None,
            }
        } else if crate::s1ap_gen::is_initiating(
            data,
            crate::s1ap_gen::PROC_UE_CAPABILITY_INFO_INDICATION,
        ) {
            match crate::s1ap_gen::decode_ue_capability_info_indication(data) {
                Class2Decode::Proceed { msg, notify } => {
                    reported.extend(class2_notify(
                        enb_id,
                        crate::s1ap_gen::PROC_UE_CAPABILITY_INFO_INDICATION,
                        Some(msg.enb_ue_s1ap_id),
                        Some(msg.mme_ue_s1ap_id),
                        &notify,
                    ));
                    Some(S1apMessage::UeCapabilityInfoIndication(msg))
                }
                Class2Decode::Reject {
                    ies,
                    enb_ue_s1ap_id,
                    mme_ue_s1ap_id,
                } => {
                    return class2_reject(
                        enb_id,
                        crate::s1ap_gen::PROC_UE_CAPABILITY_INFO_INDICATION,
                        enb_ue_s1ap_id,
                        mme_ue_s1ap_id,
                        &ies,
                    );
                }
                Class2Decode::Undecodable => None,
            }
        } else if crate::s1ap_gen::is_outcome(data, true, crate::s1ap_gen::PROC_RESET) {
            response!(
                crate::s1ap_gen::decode_reset_acknowledge(data),
                crate::s1ap_gen::PROC_RESET,
                true,
                |_: &nextgcore_s1ap::ResetAcknowledge| None,
                S1apMessage::ResetAcknowledge,
                "Reset Acknowledge"
            )
        } else if crate::s1ap_gen::is_outcome(
            data,
            true,
            crate::s1ap_gen::PROC_MME_CONFIGURATION_UPDATE,
        ) {
            response!(
                crate::s1ap_gen::decode_mme_configuration_update_acknowledge(data),
                crate::s1ap_gen::PROC_MME_CONFIGURATION_UPDATE,
                true,
                |_: &()| None,
                |()| S1apMessage::MmeConfigurationUpdateAcknowledge(
                    nextgcore_s1ap::MmeConfigurationUpdateAcknowledge {
                        criticality_diagnostics: None,
                    }
                ),
                "MME Configuration Update Acknowledge"
            )
        } else if crate::s1ap_gen::is_outcome(
            data,
            false,
            crate::s1ap_gen::PROC_MME_CONFIGURATION_UPDATE,
        ) {
            response!(
                crate::s1ap_gen::decode_mme_configuration_update_failure(data),
                crate::s1ap_gen::PROC_MME_CONFIGURATION_UPDATE,
                false,
                |_: &nextgcore_s1ap::MmeConfigurationUpdateFailure| None,
                S1apMessage::MmeConfigurationUpdateFailure,
                "MME Configuration Update Failure"
            )
        } else if crate::s1ap_gen::is_outcome(
            data,
            true,
            crate::s1ap_gen::PROC_UE_CONTEXT_MODIFICATION,
        ) {
            response!(
                crate::s1ap_gen::decode_ue_context_modification_response(data),
                crate::s1ap_gen::PROC_UE_CONTEXT_MODIFICATION,
                true,
                |m: &nextgcore_s1ap::UeContextModificationResponse| Some(m.mme_ue_s1ap_id),
                S1apMessage::UeContextModificationResponse,
                "UE Context Modification Response"
            )
        } else if crate::s1ap_gen::is_outcome(
            data,
            false,
            crate::s1ap_gen::PROC_UE_CONTEXT_MODIFICATION,
        ) {
            response!(
                crate::s1ap_gen::decode_ue_context_modification_failure(data),
                crate::s1ap_gen::PROC_UE_CONTEXT_MODIFICATION,
                false,
                |m: &nextgcore_s1ap::UeContextModificationFailure| Some(m.mme_ue_s1ap_id),
                S1apMessage::UeContextModificationFailure,
                "UE Context Modification Failure"
            )
        } else if crate::s1ap_gen::is_outcome(
            data,
            true,
            crate::s1ap_gen::PROC_WRITE_REPLACE_WARNING,
        ) {
            response!(
                crate::s1ap_gen::decode_write_replace_warning_response(data),
                crate::s1ap_gen::PROC_WRITE_REPLACE_WARNING,
                true,
                |_: &nextgcore_s1ap::WriteReplaceWarningResponse| None,
                S1apMessage::WriteReplaceWarningResponse,
                "Write-Replace Warning Response"
            )
        } else if crate::s1ap_gen::is_outcome(data, true, crate::s1ap_gen::PROC_KILL) {
            response!(
                crate::s1ap_gen::decode_kill_response(data),
                crate::s1ap_gen::PROC_KILL,
                true,
                |_: &nextgcore_s1ap::KillResponse| None,
                S1apMessage::KillResponse,
                "Kill Response"
            )
        } else {
            None
        }
    };
    // A PDU none of the generated family decodes took (#514 stage 13; this
    // was the hand-written decoder's job until it was deleted).
    let message = match generated {
        Some(message) => message,
        None => {
            reported.extend(answer_unmatched(
                enb_id,
                crate::s1ap_gen::classify_unmatched(data),
            ));
            return reported;
        }
    };

    reported.extend(match message {
        S1apMessage::S1SetupRequest(msg) => handle_s1_setup_request(ctx, enb_id, &msg),
        S1apMessage::InitialUeMessage(msg) => {
            // TS 36.413 §8.6.2.1: the NAS-PDU IE carries the UE's initial
            // uplink NAS message and must reach the NAS layer (issue #43).
            if let Some(enb_ue_id) = handle_initial_ue_message(ctx, enb_id, &msg) {
                nas_dispatch::nas_eps_handle_uplink(
                    ctx,
                    nas_dispatch::UplinkNas {
                        enb_ue_id,
                        nas_pdu: &msg.nas_pdu,
                        s_tmsi: msg
                            .s_tmsi
                            .as_ref()
                            .map(|s_tmsi| (s_tmsi.mmec, s_tmsi.m_tmsi)),
                    },
                );
            }
            Vec::new()
        }
        S1apMessage::UplinkNasTransport(msg) => {
            // TS 36.413 §8.6.2.2 for the NAS-PDU, §10.6 for the unknown-id case.
            match handle_uplink_nas_transport(ctx, enb_id, &msg) {
                Ok(enb_ue_id) => {
                    nas_dispatch::nas_eps_handle_uplink(
                        ctx,
                        nas_dispatch::UplinkNas {
                            enb_ue_id,
                            nas_pdu: &msg.nas_pdu,
                            s_tmsi: None,
                        },
                    );
                    Vec::new()
                }
                Err(error) => error,
            }
        }
        S1apMessage::NasNonDeliveryIndication(msg) => {
            handle_nas_non_delivery_indication(ctx, enb_id, &msg);
            Vec::new()
        }
        S1apMessage::UeContextReleaseRequest(msg) => {
            handle_ue_context_release_request(ctx, enb_id, &msg)
        }
        S1apMessage::UeContextReleaseComplete(msg) => {
            handle_ue_context_release_complete(ctx, enb_id, &msg);
            Vec::new()
        }
        S1apMessage::Reset(msg) => handle_reset(ctx, enb_id, &msg),
        S1apMessage::ResetAcknowledge(msg) => {
            log::info!(
                "Reset Acknowledge from eNB {enb_id} ({} UE associations)",
                msg.ue_associated_connections.len()
            );
            Vec::new()
        }
        S1apMessage::ErrorIndication(msg) => {
            handle_error_indication(ctx, enb_id, &msg);
            Vec::new()
        }
        S1apMessage::UeCapabilityInfoIndication(msg) => {
            handle_ue_capability_info_indication(ctx, enb_id, &msg);
            Vec::new()
        }
        S1apMessage::HandoverRequired(msg) => handle_handover_required(ctx, enb_id, &msg),
        S1apMessage::HandoverRequestAcknowledge(msg) => {
            handle_handover_request_acknowledge(ctx, enb_id, &msg)
        }
        S1apMessage::HandoverFailure(msg) => handle_handover_failure(ctx, enb_id, &msg),
        S1apMessage::HandoverNotify(msg) => handle_handover_notify(ctx, enb_id, &msg),
        S1apMessage::HandoverCancel(msg) => handle_handover_cancel(ctx, enb_id, &msg),
        S1apMessage::EnbStatusTransfer(msg) => handle_enb_status_transfer(ctx, enb_id, &msg),
        S1apMessage::PathSwitchRequest(msg) => handle_path_switch_request(ctx, enb_id, &msg),
        S1apMessage::InitialContextSetupResponse(msg) => {
            handle_initial_context_setup_response(ctx, enb_id, &msg);
            Vec::new()
        }
        S1apMessage::InitialContextSetupFailure(msg) => {
            handle_initial_context_setup_failure(ctx, enb_id, &msg)
        }
        S1apMessage::ErabSetupResponse(msg) => {
            handle_erab_setup_response(
                ctx,
                enb_id,
                msg.mme_ue_s1ap_id,
                msg.enb_ue_s1ap_id,
                &msg.erab_setup_list,
            );
            log_erab_failures(enb_id, &msg.erab_failed_list);
            Vec::new()
        }
        S1apMessage::ErabModifyResponse(msg) => {
            log_erab_failures(enb_id, &msg.erab_failed_list);
            Vec::new()
        }
        S1apMessage::ErabReleaseResponse(msg) => {
            log_erab_failures(enb_id, &msg.erab_failed_list);
            Vec::new()
        }
        S1apMessage::EnbConfigurationUpdate(msg) => {
            handle_enb_configuration_update(ctx, enb_id, &msg)
        }
        S1apMessage::MmeConfigurationUpdateAcknowledge(_) => {
            log::info!("MME Configuration Update accepted by eNB {enb_id}");
            Vec::new()
        }
        S1apMessage::MmeConfigurationUpdateFailure(msg) => {
            log::warn!(
                "eNB {enb_id} rejected the MME Configuration Update: cause={:?} \
                 time_to_wait={:?}",
                msg.cause,
                msg.time_to_wait
            );
            Vec::new()
        }
        S1apMessage::UeContextModificationResponse(msg) => {
            log::debug!(
                "UE Context Modification accepted by eNB {enb_id} for mme_ue_s1ap_id={}",
                msg.mme_ue_s1ap_id
            );
            take_ue_ambr_modification(ctx, enb_id, msg.mme_ue_s1ap_id);
            Vec::new()
        }
        S1apMessage::UeContextModificationFailure(msg) => {
            // TS 36.413 §8.3.4.3: the UE context is unchanged by a rejected
            // modification, so there is nothing to roll back — but a failed MT
            // CSFB modification means the call cannot fall back, which is worth
            // an error rather than a debug line.
            log::error!(
                "eNB {enb_id} rejected the UE Context Modification for mme_ue_s1ap_id={}: \
                 cause={:?} diagnostics={:?}",
                msg.mme_ue_s1ap_id,
                msg.cause,
                msg.criticality_diagnostics
            );
            // #869 review: a rejected UE-AMBR leaves the eNB enforcing the old
            // value while the MME holds the new one; counted, and named. The
            // next Initial Context Setup or E-RAB Setup carries the current one.
            let what = if take_ue_ambr_modification(ctx, enb_id, msg.mme_ue_s1ap_id) {
                log::error!(
                    "UE-AMBR NOT applied by eNB {enb_id} for mme_ue_s1ap_id={}: the eNB keeps the \
                     previous value until the next Initial Context Setup or E-RAB Setup",
                    msg.mme_ue_s1ap_id
                );
                "ue_ambr"
            } else {
                "other"
            };
            count_ue_context_modification_failure(what);
            Vec::new()
        }
        S1apMessage::WriteReplaceWarningResponse(msg) => {
            handle_write_replace_warning_response(enb_id, &msg);
            Vec::new()
        }
        S1apMessage::KillResponse(msg) => {
            handle_kill_response(enb_id, &msg);
            Vec::new()
        }
        other => {
            // Every variant the generated dispatch above produces has an arm;
            // anything else was classified by `answer_unmatched` first.
            log::error!("S1AP message from eNB {enb_id} has no handler: {other:?}");
            Vec::new()
        }
    });
    reported
}

/// Answers a PDU none of the generated family decodes took (TS 36.413 §10).
fn answer_unmatched(enb_id: u64, unmatched: crate::s1ap_gen::Unmatched) -> Vec<S1apSend> {
    use crate::s1ap_gen::Unmatched;
    match unmatched {
        Unmatched::TransferSyntaxError => {
            log::error!("Failed to decode the S1AP-PDU header from eNB {enb_id}");
            // The header did not decode, so the procedure code is unknown; the
            // diagnostics can still say an initiating message was what failed.
            error_indication_with_diagnostics(
                enb_id,
                None,
                None,
                S1apCauseGroup::Protocol,
                protocol_cause::TRANSFER_SYNTAX_ERROR,
                Some(CriticalityDiagnostics {
                    triggering_message: Some(
                        nextgcore_s1ap::triggering_message::INITIATING_MESSAGE,
                    ),
                    ..Default::default()
                }),
            )
        }
        Unmatched::Undecodable {
            procedure_code,
            triggering_message,
        } => {
            log::error!(
                "Failed to decode S1AP procedure {procedure_code} (triggering message {triggering_message}) from eNB {enb_id}"
            );
            error_indication_with_diagnostics(
                enb_id,
                None,
                None,
                S1apCauseGroup::Protocol,
                protocol_cause::TRANSFER_SYNTAX_ERROR,
                Some(CriticalityDiagnostics {
                    procedure_code: Some(procedure_code),
                    triggering_message: Some(triggering_message),
                    ..Default::default()
                }),
            )
        }
        Unmatched::MmeOriginated { procedure_code } => {
            log::error!(
                "MME-originated S1AP message (procedure {procedure_code}) received from eNB {enb_id}"
            );
            error_indication(
                enb_id,
                None,
                None,
                S1apCauseGroup::Protocol,
                protocol_cause::MESSAGE_NOT_COMPATIBLE_WITH_RECEIVER_STATE,
            )
        }
        Unmatched::UnknownProcedure {
            procedure_code,
            triggering_message,
            criticality,
        } => {
            // TS 36.413 §10.3.4.1: reject -> reject the procedure by Error
            // Indication; ignore-and-notify -> ignore it and send one; ignore
            // -> ignore it. The Error Indication names the procedure code,
            // triggering message and procedure criticality.
            log::warn!(
                "S1AP procedure {procedure_code} (criticality {criticality}) from eNB {enb_id} is not comprehended"
            );
            let cause = match criticality {
                0 => protocol_cause::ABSTRACT_SYNTAX_ERROR_REJECT,
                2 => protocol_cause::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
                _ => return Vec::new(),
            };
            error_indication_with_diagnostics(
                enb_id,
                None,
                None,
                S1apCauseGroup::Protocol,
                cause,
                Some(CriticalityDiagnostics {
                    procedure_code: Some(procedure_code),
                    triggering_message: Some(triggering_message),
                    procedure_criticality: Some(criticality),
                    ..Default::default()
                }),
            )
        }
    }
}

fn error_indication(
    enb_id: u64,
    enb_ue_s1ap_id: Option<u32>,
    mme_ue_s1ap_id: Option<u32>,
    group: S1apCauseGroup,
    value: i64,
) -> Vec<S1apSend> {
    error_indication_with_diagnostics(enb_id, enb_ue_s1ap_id, mme_ue_s1ap_id, group, value, None)
}

/// Error Indication carrying Criticality Diagnostics (TS 36.413 §9.2.1.21), so the
/// peer learns which procedure and which IEs were at fault rather than only that
/// something was rejected.
/// TS 36.413 §10.3.4.2 for an initiating message of a Class 2 procedure: the
/// procedure runs, and `notify` IEs are reported in an ERROR INDICATION.
fn class2_notify(
    enb_id: u64,
    procedure_code: u8,
    enb_ue_s1ap_id: Option<u32>,
    mme_ue_s1ap_id: Option<u32>,
    notify: &[crate::s1ap_gen::DiagnosedIe],
) -> Vec<S1apSend> {
    if notify.is_empty() {
        return Vec::new();
    }
    error_indication_with_diagnostics(
        enb_id,
        enb_ue_s1ap_id,
        mme_ue_s1ap_id,
        S1apCauseGroup::Protocol,
        protocol_cause::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY,
        Some(crate::s1ap_gen::error_indication_diagnostics(
            procedure_code,
            notify,
        )),
    )
}

/// TS 36.413 §10.3.4.2 / §10.3.5 for an initiating message of a Class 2
/// procedure: the procedure is not run, and the offending IEs are reported in
/// an ERROR INDICATION.
fn class2_reject(
    enb_id: u64,
    procedure_code: u8,
    enb_ue_s1ap_id: Option<u32>,
    mme_ue_s1ap_id: Option<u32>,
    ies: &[crate::s1ap_gen::DiagnosedIe],
) -> Vec<S1apSend> {
    log::error!(
        "S1AP procedure {procedure_code} from eNB {enb_id} not run (TS 36.413 §10.3.4/§10.3.5): {ies:?}"
    );
    // §10.3.4.2 / §10.3.5 name no cause; abstract-syntax-error-reject is the
    // §9.2.1.3 value for an IE the receiver rejected, missing ones included
    // (the diagnostics' TypeOfError says which).
    error_indication_with_diagnostics(
        enb_id,
        enb_ue_s1ap_id,
        mme_ue_s1ap_id,
        S1apCauseGroup::Protocol,
        protocol_cause::ABSTRACT_SYNTAX_ERROR_REJECT,
        Some(crate::s1ap_gen::error_indication_diagnostics(
            procedure_code,
            ies,
        )),
    )
}

fn error_indication_with_diagnostics(
    enb_id: u64,
    enb_ue_s1ap_id: Option<u32>,
    mme_ue_s1ap_id: Option<u32>,
    group: S1apCauseGroup,
    value: i64,
    diagnostics: Option<CriticalityDiagnostics>,
) -> Vec<S1apSend> {
    match s1ap_build::build_error_indication(
        enb_ue_s1ap_id,
        mme_ue_s1ap_id,
        group,
        value,
        diagnostics,
    ) {
        Ok(pdu) => S1apSend::to_origin(enb_id, pdu),
        Err(e) => {
            log::error!("Failed to build Error Indication: {e}");
            Vec::new()
        }
    }
}

// ============================================================================
// S1 Setup (§8.7.3)
// ============================================================================

/// Handle S1 Setup Request: register the eNB and answer with S1 Setup
/// Response, or S1 Setup Failure with the spec-defined cause.
pub fn handle_s1_setup_request(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &S1SetupRequest,
) -> Vec<S1apSend> {
    handle_s1_setup_request_reporting(ctx, enb_id, msg, &[])
}

/// Handle an S1 SETUP REQUEST, reporting `notify` (its unknown
/// ignore-and-notify IEs) in the response's Criticality Diagnostics
/// (TS 36.413 §10.3.4.2).
pub fn handle_s1_setup_request_reporting(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &S1SetupRequest,
    notify: &[crate::s1ap_gen::DiagnosedIe],
) -> Vec<S1apSend> {
    let (enb_id_value, enb_id_bits) = (
        msg.global_enb_id.enb_id.value(),
        msg.global_enb_id.enb_id.bit_len(),
    );

    // Convert the supported TA list into context TAIs
    let mut supported_tais = Vec::new();
    for ta in &msg.supported_tas {
        for plmn in &ta.broadcast_plmns {
            supported_tais.push(EpsTai {
                plmn_id: decode_plmn_id(plmn),
                tac: ta.tac,
            });
        }
    }

    if supported_tais.is_empty() {
        log::error!("S1 Setup Request from eNB 0x{enb_id_value:x} carries no supported TAs");
        return setup_failure(
            enb_id,
            S1apCauseGroup::Misc,
            misc_cause::UNSPECIFIED,
            Some(TimeToWait::V10s),
        );
    }

    // At least one broadcast TAI must be served by this MME (TS 36.413 §8.7.3.4)
    if ctx.num_of_served_tai > 0
        && !supported_tais
            .iter()
            .any(|tai| ctx.find_served_tai(tai).is_some())
    {
        log::error!("S1 Setup Request from eNB 0x{enb_id_value:x}: no served TAI matches");
        return setup_failure(
            enb_id,
            S1apCauseGroup::Misc,
            misc_cause::UNKNOWN_PLMN,
            Some(TimeToWait::V10s),
        );
    }

    if ctx.served_gummei.is_empty() {
        log::error!("No served GUMMEI configured; rejecting S1 Setup");
        return setup_failure(
            enb_id,
            S1apCauseGroup::Misc,
            misc_cause::UNSPECIFIED,
            Some(TimeToWait::V10s),
        );
    }

    // TS 23.007 §17: a second S1 SETUP REQUEST from an eNB we have already set up
    // means that eNB restarted, so every UE context we hold for it is stale. They
    // are released before the setup is accepted, otherwise they linger until
    // something else happens to clear them and their MME-UE-S1AP-IDs collide with
    // the ids the restarted eNB is about to use.
    let already_setup = ctx
        .enb_find_by_id(enb_id)
        .is_some_and(|enb| enb.state.s1_setup_success);
    if already_setup {
        let released = release_all_s1_connections(ctx, enb_id);
        log::warn!(
            "eNB 0x{enb_id_value:x} restarted (repeat S1 Setup); released {released} stale UE \
             context(s)"
        );
    }

    ctx.enb_set_enb_id(enb_id, enb_id_value);
    if let Some(enb) = ctx.enb_pool.write().unwrap().get_mut(&enb_id) {
        enb.plmn_id = decode_plmn_id(&msg.global_enb_id.plmn_identity);
        enb.enb_id_bits = enb_id_bits;
        enb.supported_ta_list = supported_tais;
        enb.state.s1_setup_success = true;
    }

    log::info!(
        "S1 Setup: eNB 0x{enb_id_value:x} ({}) accepted",
        msg.enb_name.as_deref().unwrap_or("unnamed")
    );

    match s1ap_build::build_setup_response_with_diagnostics(ctx, notify) {
        Ok(pdu) => S1apSend::to_origin(enb_id, pdu),
        Err(e) => {
            log::error!("Failed to build S1 Setup Response: {e}");
            Vec::new()
        }
    }
}

fn setup_failure(
    enb_id: u64,
    group: S1apCauseGroup,
    value: i64,
    ttw: Option<TimeToWait>,
) -> Vec<S1apSend> {
    match s1ap_build::build_setup_failure(group, value, ttw) {
        Ok(pdu) => S1apSend::to_origin(enb_id, pdu),
        Err(e) => {
            log::error!("Failed to build S1 Setup Failure: {e}");
            Vec::new()
        }
    }
}

// ============================================================================
// eNB Configuration Update (§8.7.4)
// ============================================================================

/// Handle eNB Configuration Update (TS 36.413 §8.7.4.2).
///
/// A conforming eNB sends this after a TAC or cell reconfiguration and expects
/// an ACKNOWLEDGE (or FAILURE). Before this it fell through the dispatcher's
/// `Unknown` arm to an Error Indication with `ABSTRACT_SYNTAX_ERROR_REJECT`,
/// which is an interop break, and the MME's `supported_ta_list` for that eNB
/// went stale.
///
/// Every IE is optional. An update that omits SupportedTAs leaves the stored TA
/// list **alone** rather than clearing it: absent means unchanged, and treating
/// it as "serves nothing" would strand every UE in those tracking areas.
pub fn handle_enb_configuration_update(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &EnbConfigurationUpdate,
) -> Vec<S1apSend> {
    handle_enb_configuration_update_reporting(ctx, enb_id, msg, &[])
}

/// [`handle_enb_configuration_update`] for an update decoded with the
/// generated codec (#514 stage 12): `notify` IEs (TS 36.413 §10.3.4.2) are
/// reported in the acknowledge's Criticality Diagnostics.
pub fn handle_enb_configuration_update_reporting(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &EnbConfigurationUpdate,
    notify: &[crate::s1ap_gen::DiagnosedIe],
) -> Vec<S1apSend> {
    // An update from an eNB that never completed S1 Setup has no configuration
    // to update (TS 36.413 §8.7.4.4).
    if !ctx
        .enb_find_by_id(enb_id)
        .is_some_and(|enb| enb.state.s1_setup_success)
    {
        log::warn!("eNB Configuration Update from eNB {enb_id} before S1 Setup completed");
        return config_update_failure(
            enb_id,
            S1apCauseGroup::Protocol,
            protocol_cause::MESSAGE_NOT_COMPATIBLE_WITH_RECEIVER_STATE,
            None,
        );
    }

    let supported_tais = msg.supported_tas.as_ref().map(|tas| {
        let mut tais = Vec::new();
        for ta in tas {
            for plmn in &ta.broadcast_plmns {
                tais.push(EpsTai {
                    plmn_id: decode_plmn_id(plmn),
                    tac: ta.tac,
                });
            }
        }
        tais
    });

    // Same admission rule as S1 Setup: a TA list this MME does not serve is
    // rejected rather than stored, so the two paths cannot disagree about which
    // eNBs are servable (TS 36.413 §8.7.3.4).
    if let Some(ref tais) = supported_tais {
        if tais.is_empty() {
            log::error!("eNB Configuration Update from eNB {enb_id} carries an empty TA list");
            return config_update_failure(
                enb_id,
                S1apCauseGroup::Misc,
                misc_cause::UNSPECIFIED,
                Some(TimeToWait::V10s),
            );
        }
        if ctx.num_of_served_tai > 0 && !tais.iter().any(|tai| ctx.find_served_tai(tai).is_some()) {
            log::error!("eNB Configuration Update from eNB {enb_id}: no served TAI matches");
            return config_update_failure(
                enb_id,
                S1apCauseGroup::Misc,
                misc_cause::UNKNOWN_PLMN,
                Some(TimeToWait::V10s),
            );
        }
    }

    if let Some(enb) = ctx.enb_pool.write().unwrap().get_mut(&enb_id) {
        if let Some(tais) = supported_tais {
            log::info!(
                "eNB Configuration Update from eNB 0x{:x}: TA list replaced ({} -> {} entries)",
                enb.enb_id,
                enb.supported_ta_list.len(),
                tais.len()
            );
            enb.supported_ta_list = tais;
        }
    }

    if let Some(ref name) = msg.enb_name {
        log::info!("eNB {enb_id} reports name \"{name}\"");
    }

    match crate::s1ap_gen::build_enb_configuration_update_acknowledge(notify) {
        Ok(pdu) => S1apSend::to_origin(enb_id, pdu),
        Err(e) => {
            log::error!("Failed to build eNB Configuration Update Acknowledge: {e}");
            Vec::new()
        }
    }
}

fn config_update_failure(
    enb_id: u64,
    group: S1apCauseGroup,
    value: i64,
    ttw: Option<TimeToWait>,
) -> Vec<S1apSend> {
    config_update_failure_with(enb_id, group, value, ttw, &[])
}

fn config_update_failure_with(
    enb_id: u64,
    group: S1apCauseGroup,
    value: i64,
    ttw: Option<TimeToWait>,
    reject: &[crate::s1ap_gen::DiagnosedIe],
) -> Vec<S1apSend> {
    match crate::s1ap_gen::build_enb_configuration_update_failure(
        s1ap_build::cause_to_s1ap(group, value),
        ttw,
        reject,
    ) {
        Ok(pdu) => S1apSend::to_origin(enb_id, pdu),
        Err(e) => {
            log::error!("Failed to build eNB Configuration Update Failure: {e}");
            Vec::new()
        }
    }
}

// ============================================================================
// PWS responses (§8.12)
// ============================================================================

/// Handle Write-Replace Warning Response (TS 36.413 §8.12.1.2).
///
/// The Broadcast Completed Area List is where the warning *actually* went, which
/// is the only evidence the MME has that an ETWS/CMAS alert reached the air. An
/// eNB that answers with no completed area accepted the message but broadcast
/// nowhere, and that is logged as a warning rather than treated as success.
fn handle_write_replace_warning_response(enb_id: u64, msg: &WriteReplaceWarningResponse) {
    match &msg.broadcast_completed_area {
        Some(area) => log::info!(
            "Write-Replace Warning Response from eNB {enb_id}: message {:#06x}/{:#06x} \
             broadcast in {}",
            msg.message_identifier,
            msg.serial_number,
            describe_completed_area(area)
        ),
        None => log::warn!(
            "eNB {enb_id} acknowledged warning {:#06x}/{:#06x} without a Broadcast Completed \
             Area List: nothing is known to have reached the air",
            msg.message_identifier,
            msg.serial_number
        ),
    }
}

/// Handle Kill Response (TS 36.413 §8.12.2.2).
fn handle_kill_response(enb_id: u64, msg: &KillResponse) {
    log::info!(
        "Kill Response from eNB {enb_id}: message {:#06x}/{:#06x} cancelled{}",
        msg.message_identifier,
        msg.serial_number,
        match &msg.broadcast_cancelled_area {
            Some(BroadcastCancelledAreaList::CellIdCancelled(cells)) =>
                format!(" in {} cell(s)", cells.len()),
            Some(BroadcastCancelledAreaList::TaiCancelled(tais)) =>
                format!(" in {} tracking area(s)", tais.len()),
            Some(BroadcastCancelledAreaList::EmergencyAreaIdCancelled(areas)) =>
                format!(" in {} emergency area(s)", areas.len()),
            None => String::new(),
        }
    );
}

fn describe_completed_area(area: &BroadcastCompletedAreaList) -> String {
    match area {
        BroadcastCompletedAreaList::CellIdBroadcast(cells) => format!("{} cell(s)", cells.len()),
        BroadcastCompletedAreaList::TaiBroadcast(tais) => {
            let cells: usize = tais.iter().map(|item| item.completed_cells.len()).sum();
            format!("{} tracking area(s), {cells} cell(s)", tais.len())
        }
        BroadcastCompletedAreaList::EmergencyAreaIdBroadcast(areas) => {
            let cells: usize = areas.iter().map(|item| item.completed_cells.len()).sum();
            format!("{} emergency area(s), {cells} cell(s)", areas.len())
        }
    }
}

// ============================================================================
// NAS Transport (§8.6)
// ============================================================================

/// Handle Initial UE Message: allocate the eNB UE context and record the
/// UE's location. Returns the eNB UE pool ID for the NAS layer.
pub fn handle_initial_ue_message(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &InitialUeMessage,
) -> Option<u64> {
    // #846, TS 36.413 §10.6 (first message): an eNB UE S1AP ID this MME already
    // holds for another connection of the same eNB is erroneous. ERROR
    // INDICATION with only that ID, and every connection having it is released
    // locally; the eNB releases its side too, so the message is not processed.
    let stale = EnbConnections::of(ctx, enb_id).holding(msg.enb_ue_s1ap_id);
    if !stale.is_empty() {
        log::warn!(
            "Initial UE Message from eNB {enb_id} reuses enb_ue_s1ap_id={} held by S1 \
             connection(s) {stale:?}; releasing them locally and answering ERROR INDICATION \
             (TS 36.413 §10.6)",
            msg.enb_ue_s1ap_id
        );
        for id in stale {
            release_s1_connection(ctx, id);
        }
        for send in error_indication(
            enb_id,
            Some(msg.enb_ue_s1ap_id),
            None,
            S1apCauseGroup::RadioNetwork,
            radio_network_cause::UNKNOWN_ENB_UE_S1AP_ID,
        ) {
            crate::s1ap_path::s1ap_send(send);
        }
        return None;
    }
    let enb_ue_id = ctx.enb_ue_add(enb_id, msg.enb_ue_s1ap_id);
    let tai = tai_from_s1ap(&msg.tai);
    let e_cgi = ecgi_from_s1ap(&msg.eutran_cgi);

    if let Some(enb_ue) = ctx.enb_ue_pool.write().unwrap().get_mut(&enb_ue_id) {
        enb_ue.saved.tai = tai.clone();
        enb_ue.saved.e_cgi = e_cgi;
    }

    log::debug!(
        "Initial UE Message: enb_ue_s1ap_id={} tac={} nas_len={} s_tmsi={:?}",
        msg.enb_ue_s1ap_id,
        tai.tac,
        msg.nas_pdu.len(),
        msg.s_tmsi
    );
    Some(enb_ue_id)
}

/// Handle Uplink NAS Transport: refresh the UE's location and return the eNB UE
/// pool ID so the NAS layer can be handed the PDU.
///
/// `None` means the `MME-UE-S1AP-ID` names no S1 connection, which the caller
/// answers with an Error Indication (TS 36.413 §10.6). A *known* connection
/// that has no MME UE context yet still returns its id: resolving or creating
/// that context belongs to the NAS layer, not here.
pub fn handle_uplink_nas_transport(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &UlNasTransport,
) -> Result<u64, Vec<S1apSend>> {
    handle_uplink_nas(
        ctx,
        enb_id,
        &crate::s1ap_gen::UplinkNas {
            mme_ue_s1ap_id: msg.mme_ue_s1ap_id,
            enb_ue_s1ap_id: msg.enb_ue_s1ap_id,
            nas_pdu: msg.nas_pdu.clone(),
            eutran_cgi: Some(msg.eutran_cgi.clone()),
            tai: Some(msg.tai.clone()),
        },
    )
}

/// Handle an UPLINK NAS TRANSPORT whose `ignore`-criticality location IEs may
/// be missing (TS 36.413 §10.3.5): a missing TAI or EUTRAN-CGI leaves the
/// stored location as it is.
pub fn handle_uplink_nas(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &crate::s1ap_gen::UplinkNas,
) -> Result<u64, Vec<S1apSend>> {
    // #846, TS 36.413 §10.6: only a connection of the sending eNB with both
    // IDs. Before #846 a NAS PDU from another eNB was processed on whichever
    // UE the MME UE S1AP ID named, after only a log line.
    let enb_ue_id = ue_associated_target(ctx, enb_id, msg.mme_ue_s1ap_id, msg.enb_ue_s1ap_id)?;
    let Some(enb_ue) = ctx.enb_ue_find_by_id(enb_ue_id) else {
        return Err(Vec::new());
    };

    if let (Some(tai), Some(cgi)) = (&msg.tai, &msg.eutran_cgi) {
        update_ue_location(
            ctx,
            enb_ue.mme_ue_id,
            &tai_from_s1ap(tai),
            &ecgi_from_s1ap(cgi),
        );
    }

    log::debug!(
        "Uplink NAS Transport: mme_ue_s1ap_id={} nas_len={}",
        msg.mme_ue_s1ap_id,
        msg.nas_pdu.len()
    );
    Ok(enb_ue_id)
}

/// Handle NAS Non Delivery Indication (TS 36.413 §8.6.4).
///
/// The NAS PDU could not be delivered over the radio. The MME logs the cause
/// and, when the failed PDU was paging-triggered, marks the paging procedure
/// failed so it is re-attempted on the next downlink trigger.
/// Handle Initial Context Setup Failure (TS 36.413 §8.3.1.3).
///
/// The eNB could not set up the UE context, so the MME must not go on believing
/// the UE is being served: the UE-associated logical S1 connection is released
/// with the cause the eNB reported. Previously this only logged, leaving the
/// context and the connection in place for a UE that has no radio bearers.
pub fn handle_initial_context_setup_failure(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &InitialContextSetupFailure,
) -> Vec<S1apSend> {
    log::error!(
        "Initial Context Setup Failure from eNB {enb_id}: mme_ue={} cause={:?}",
        msg.mme_ue_s1ap_id,
        msg.cause
    );

    // #731 / #847 review: on this eNB only; an inconsistent pair releases the
    // connections carrying either ID locally and gets ERROR INDICATION.
    let enb_ue_id = match teardown_target(ctx, enb_id, msg.mme_ue_s1ap_id, msg.enb_ue_s1ap_id) {
        Ok(id) => id,
        Err(out) => return out,
    };

    // #869/#961: the setup is over, whichever kind it was.
    if let Some(mme_ue_id) = ctx.enb_ue_find_by_id(enb_ue_id).map(|e| e.mme_ue_id) {
        if let Some(ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
            ue.ics_pending_on = 0;
            // #916 review: the S1 connection is being released; a UE-AMBR
            // change deferred behind this setup is carried by the next one,
            // not sent to a context on its way out.
            ue.ue_ambr_deferred = false;
        }
    }
    // #956: a failed Initial Context Setup of a SERVICE REQUEST releases S1
    // only; the UE stays registered and ECM-IDLE (TS 23.401 §5.3.4.1).
    let service_request = ctx
        .enb_ue_find_by_id(enb_ue_id)
        .map(|e| e.mme_ue_id)
        .and_then(|id| {
            ctx.mme_ue_pool
                .write()
                .unwrap()
                .get_mut(&id)
                .map(|ue| std::mem::take(&mut ue.service_request_ics_pending))
        })
        .unwrap_or(false);
    // #961 review: the Serving GW still buffers for a SERVICE REQUEST whose user
    // plane did not come up. Release Access Bearers returns it to the idle
    // state, so the next downlink packet is notified afresh.
    if service_request {
        if let Some(mme_ue_id) = ctx.enb_ue_find_by_id(enb_ue_id).map(|e| e.mme_ue_id) {
            if let Err(e) = crate::gtp_path::send_release_access_bearers_request(
                ctx,
                enb_ue_id,
                mme_ue_id,
                crate::s11_build::GtpReleaseAction::S1ContextRemove,
            ) {
                log::error!("UE {mme_ue_id}: Release Access Bearers Request not sent: {e}");
            }
            crate::gtp_path::clear_enb_endpoints(ctx, mme_ue_id);
        }
    }
    let cause = cause_from_s1ap(&msg.cause);
    if let Some(enb_ue) = ctx.enb_ue_pool.write().unwrap().get_mut(&enb_ue_id) {
        enb_ue.relcause.group = cause.group;
        enb_ue.relcause.cause = cause.cause;
        enb_ue.ue_ctx_rel_action = if service_request {
            UeCtxRelAction::S1ContextRemove
        } else {
            UeCtxRelAction::UeContextRemove
        };
    }

    match s1ap_build::build_ue_context_release_command(
        Some(msg.enb_ue_s1ap_id),
        msg.mme_ue_s1ap_id,
        cause.group,
        cause.cause,
    ) {
        Ok(pdu) => S1apSend::to_origin(enb_id, pdu),
        Err(e) => {
            log::error!("Failed to build UE Context Release Command: {e}");
            Vec::new()
        }
    }
}

/// Handle Error Indication (TS 36.413 §8.7.5, §10.6).
///
/// An indication naming one of our UE S1AP ids with an unknown-id cause is the eNB
/// telling us *our* context is stale: it is released locally, with no release
/// command, because the eNB already has nothing to release. Any other cause is
/// informational. Previously every indication was logged and dropped, so a stale
/// context survived until something else happened to clear it.
pub fn handle_error_indication(ctx: &MmeContext, enb_id: u64, msg: &ErrorIndication) {
    log::warn!(
        "Error Indication from eNB {enb_id}: mme_ue={:?} enb_ue={:?} cause={:?} diagnostics={:?}",
        msg.mme_ue_s1ap_id,
        msg.enb_ue_s1ap_id,
        msg.cause,
        msg.criticality_diagnostics
    );

    let stale = matches!(
        msg.cause,
        Some(Cause::RadioNetwork(CauseRadioNetwork::UnknownMmeUeS1apId))
            | Some(Cause::RadioNetwork(CauseRadioNetwork::UnknownEnbUeS1apId))
            | Some(Cause::RadioNetwork(CauseRadioNetwork::UnknownPairUeS1apId))
    );
    if !stale {
        return;
    }

    // #731: only a context on the sending eNB, and only if every ID present
    // matches. A stale ERROR INDICATION from an X2 source eNB names a context
    // that now lives on the target, which must not be released.
    //
    // TS 36.413 §10.6: the connections of THIS S1 interface carrying the
    // erroneous ID(s) are released locally, whichever ID the indication gives
    // (it may give only the eNB UE S1AP ID: both are optional, criticality
    // ignore). A context the IDs name on another eNB is not this interface's.
    let (found, _) =
        EnbConnections::of(ctx, enb_id).carrying(msg.mme_ue_s1ap_id, msg.enb_ue_s1ap_id);
    if found.is_empty() {
        log::info!(
            "Error Indication from eNB {enb_id} names no S1 context on that eNB (mme_ue={:?}, \
             enb_ue={:?}); nothing released",
            msg.mme_ue_s1ap_id,
            msg.enb_ue_s1ap_id
        );
        return;
    }
    for enb_ue_id in found {
        log::info!(
            "eNB {enb_id} does not know mme_ue={:?} / enb_ue={:?}; releasing the local S1 \
             connection {enb_ue_id}",
            msg.mme_ue_s1ap_id,
            msg.enb_ue_s1ap_id
        );
        release_s1_connection(ctx, enb_ue_id);
    }
}

pub fn handle_nas_non_delivery_indication(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &NasNonDeliveryIndication,
) {
    log::warn!(
        "NAS Non Delivery Indication from eNB {enb_id}: mme_ue_s1ap_id={} nas_len={} cause={:?}",
        msg.mme_ue_s1ap_id,
        msg.nas_pdu.len(),
        msg.cause
    );

    // #846: the sending eNB's pair, else ERROR INDICATION (TS 36.413 §10.6).
    let Some(enb_ue_id) =
        ue_associated_target_or_answer(ctx, enb_id, msg.mme_ue_s1ap_id, msg.enb_ue_s1ap_id)
    else {
        return;
    };
    let Some(enb_ue) = ctx.enb_ue_find_by_id(enb_ue_id) else {
        return;
    };

    if let Some(mme_ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&enb_ue.mme_ue_id) {
        if mme_ue.paging.type_ != PagingType::None {
            mme_ue.paging.failed = true;
        }
    }
}

// ============================================================================
// UE Context Release (§8.3.2-8.3.3)
// ============================================================================

/// Handle eNB-initiated UE Context Release Request: store the release cause
/// and answer with a UE Context Release Command.
pub fn handle_ue_context_release_request(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &UeContextReleaseRequest,
) -> Vec<S1apSend> {
    // #731 / #847 review: on this eNB only; an inconsistent pair releases the
    // connections carrying either ID locally and gets ERROR INDICATION.
    let enb_ue_id = match teardown_target(ctx, enb_id, msg.mme_ue_s1ap_id, msg.enb_ue_s1ap_id) {
        Ok(id) => id,
        Err(out) => return out,
    };

    let cause = cause_from_s1ap(&msg.cause);
    let mme_ue_id = {
        let mut pool = ctx.enb_ue_pool.write().unwrap();
        let Some(enb_ue) = pool.get_mut(&enb_ue_id) else {
            return Vec::new();
        };
        enb_ue.relcause.group = cause.group;
        enb_ue.relcause.cause = cause.cause;
        enb_ue.ue_ctx_rel_action = UeCtxRelAction::S1ContextRemove;
        enb_ue.mme_ue_id
    };

    // #956, TS 23.401 §5.3.5 step 2: a UE with PDN connections at a Serving GW
    // goes ECM-IDLE. Its S1-U bearers are released at the Serving GW first, so
    // downlink is buffered and notified (§5.3.4.3) rather than tunnelled to an
    // eNB that has dropped the UE. The UE CONTEXT RELEASE COMMAND (step 5)
    // follows the Release Access Bearers Response.
    let has_session = ctx
        .mme_ue_find_by_id(mme_ue_id)
        .filter(|ue| ue.enb_ue_id == enb_ue_id)
        .and_then(|ue| ctx.sgw_ue_find_by_id(ue.sgw_ue_id))
        .is_some_and(|sgw| sgw.sgw_s11_teid != 0);
    if has_session {
        match crate::gtp_path::release_access_bearers_for_s1_release(ctx, enb_ue_id, mme_ue_id) {
            Ok(seq) => {
                log::info!(
                    "UE Context Release Request (cause {:?}): Release Access Bearers Request \
                     (seq={seq}) to the Serving GW; the UE goes ECM-IDLE (TS 23.401 §5.3.5)",
                    msg.cause
                );
                return Vec::new();
            }
            Err(e) => log::error!(
                "UE Context Release Request: Release Access Bearers Request not sent ({e}); \
                 releasing S1 now"
            ),
        }
    }
    s1_release_command(ctx, enb_ue_id)
}

/// The UE CONTEXT RELEASE COMMAND of an S1 release for `enb_ue_id`, with the
/// cause recorded from the request (TS 23.401 §5.3.5 step 5, TS 36.413 §8.3.3).
/// Empty when the context is gone.
pub fn s1_release_command(ctx: &MmeContext, enb_ue_id: u64) -> Vec<S1apSend> {
    let Some(enb_ue) = ctx.enb_ue_find_by_id(enb_ue_id) else {
        return Vec::new();
    };
    match s1ap_build::build_ue_context_release_command(
        Some(enb_ue.enb_ue_s1ap_id),
        enb_ue.mme_ue_s1ap_id,
        enb_ue.relcause.group,
        enb_ue.relcause.cause,
    ) {
        Ok(pdu) => S1apSend::to_origin(enb_ue.enb_id, pdu),
        Err(e) => {
            log::error!("Failed to build UE Context Release Command: {e}");
            Vec::new()
        }
    }
}

/// Handle UE Context Release Complete: tear down the eNB UE context.
pub fn handle_ue_context_release_complete(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &UeContextReleaseComplete,
) {
    let (found, consistent) = EnbConnections::of(ctx, enb_id)
        .carrying(Some(msg.mme_ue_s1ap_id), Some(msg.enb_ue_s1ap_id));
    if !consistent {
        for id in &found {
            log::warn!("UE Context Release Complete with an inconsistent pair; releasing {id}");
            release_s1_connection(ctx, *id);
        }
    }
    let Some(enb_ue_id) = found.first().copied().filter(|_| consistent) else {
        log::warn!(
            "UE Context Release Complete for unknown mme_ue_s1ap_id={}",
            msg.mme_ue_s1ap_id
        );
        return;
    };
    release_s1_connection(ctx, enb_ue_id);
    log::debug!("UE Context released: mme_ue_s1ap_id={}", msg.mme_ue_s1ap_id);
}

/// Handle a UE Context Release Complete decoded by the generated codec (#514
/// stage 5). Both UE S1AP IDs are criticality `ignore` (§10.3.5): with no
/// MME-UE-S1AP-ID the UE is found by its eNB-UE-S1AP-ID on this association.
pub fn handle_release_complete(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &crate::s1ap_gen::ReleaseComplete,
) {
    // #731: on this eNB only. It is the procedure's last message, so an
    // inconsistent pair releases every connection carrying either ID (§10.6).
    let (found, consistent) =
        EnbConnections::of(ctx, enb_id).carrying(msg.mme_ue_s1ap_id, msg.enb_ue_s1ap_id);
    if !consistent {
        for id in &found {
            log::warn!("UE Context Release Complete with an inconsistent pair; releasing {id}");
            release_s1_connection(ctx, *id);
        }
    }
    let enb_ue_id = found.first().copied().filter(|_| consistent);
    let Some(enb_ue_id) = enb_ue_id else {
        log::warn!(
            "UE Context Release Complete for unknown UE (mme_ue_s1ap_id={:?}, enb_ue_s1ap_id={:?})",
            msg.mme_ue_s1ap_id,
            msg.enb_ue_s1ap_id
        );
        return;
    };
    release_s1_connection(ctx, enb_ue_id);
    log::debug!("UE Context released: {msg:?}");
}

// ============================================================================
// Reset (§8.7.1)
// ============================================================================

/// Handle Reset: clear the affected UE-associated logical S1 connections and
/// answer with Reset Acknowledge (echoing the partial connection list).
pub fn handle_reset(ctx: &MmeContext, enb_id: u64, msg: &Reset) -> Vec<S1apSend> {
    handle_reset_reporting(ctx, enb_id, msg, &[])
}

/// [`handle_reset`], reporting `notify` (unknown ignore-and-notify IEs of the
/// RESET, a Class 1 initiating message) in the acknowledge's Criticality
/// Diagnostics (TS 36.413 §10.3.4.2).
pub fn handle_reset_reporting(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &Reset,
    notify: &[crate::s1ap_gen::DiagnosedIe],
) -> Vec<S1apSend> {
    log::warn!("Reset from eNB {enb_id}: cause={:?}", msg.cause);

    let acked_connections = match &msg.reset_type {
        ResetType::S1Interface => {
            release_all_s1_connections(ctx, enb_id);
            Vec::new()
        }
        ResetType::PartOfS1Interface(connections) => {
            // #731: only connections of the resetting eNB. §8.7.1.2.1: each
            // item names its connection by the MME UE S1AP ID and/or the eNB
            // UE S1AP ID, so a connection carrying either is reset (an
            // inconsistent pair releases both, §10.6).
            let index = EnbConnections::of(ctx, enb_id);
            for conn in connections {
                let (found, _) = index.carrying(conn.mme_ue_s1ap_id, conn.enb_ue_s1ap_id);
                for enb_ue_id in found {
                    if let Some(enb_ue) = ctx.enb_ue_pool.write().unwrap().get_mut(&enb_ue_id) {
                        enb_ue.part_of_s1_reset_requested = true;
                    }
                    release_s1_connection(ctx, enb_ue_id);
                }
            }
            // §8.7.1.2.2: the Ack echoes the received connection list,
            // including any connections unknown to the MME
            connections.clone()
        }
    };

    match crate::s1ap_gen::build_reset_acknowledge(
        &ResetAcknowledge {
            ue_associated_connections: acked_connections,
        },
        notify,
    ) {
        Ok(pdu) => S1apSend::to_origin(enb_id, pdu),
        Err(e) => {
            log::error!("Failed to build Reset Acknowledge: {e}");
            Vec::new()
        }
    }
}

/// Release one UE-associated logical S1 connection: detach it from the MME
/// UE context (the UE moves to idle) and free the eNB UE context. The MME UE
/// association is only cleared when it still points at this connection (it
/// may already have moved to a handover target).
/// Release every UE-associated logical S1 connection on `enb_id`, returning how
/// many there were.
///
/// Shared by Reset with `ResetType::S1Interface` (TS 36.413 §8.7.1) and by eNB
/// restart detection (TS 23.007 §17): both mean every UE context the MME holds for
/// that eNB is stale.
fn release_all_s1_connections(ctx: &MmeContext, enb_id: u64) -> usize {
    let affected: Vec<u64> = ctx
        .enb_ue_pool
        .read()
        .unwrap()
        .iter()
        .filter(|(_, ue)| ue.enb_id == enb_id)
        .map(|(id, _)| *id)
        .collect();
    let count = affected.len();
    for enb_ue_id in affected {
        release_s1_connection(ctx, enb_ue_id);
    }
    count
}

fn release_s1_connection(ctx: &MmeContext, enb_ue_id: u64) {
    let mut idle_ue = None;
    if let Some(enb_ue) = ctx.enb_ue_find_by_id(enb_ue_id) {
        if enb_ue.mme_ue_id != NEXTGCORE_INVALID_POOL_ID {
            let still_attached = ctx
                .mme_ue_find_by_id(enb_ue.mme_ue_id)
                .is_some_and(|mme_ue| mme_ue.enb_ue_id == enb_ue_id);
            if still_attached {
                ctx.enb_ue_deassociate_mme_ue(enb_ue_id, enb_ue.mme_ue_id);
                idle_ue = Some(enb_ue.mme_ue_id);
            }
        }
    }
    ctx.enb_ue_remove(enb_ue_id);
    let Some(mme_ue_id) = idle_ue else {
        return;
    };
    // #961 review: the UE is ECM-IDLE now. An Initial Context Setup of a
    // SERVICE REQUEST that was still outstanding is void, and a Downlink Data
    // Notification that arrived during the release pages the UE now.
    let page = ctx
        .mme_ue_pool
        .write()
        .unwrap()
        .get_mut(&mme_ue_id)
        .is_some_and(|ue| {
            ue.service_request_ics_pending = false;
            ue.ics_pending_on = 0;
            std::mem::take(&mut ue.ddn_pending_after_release)
        });
    if page
        && crate::paging::page_ue(
            ctx,
            mme_ue_id,
            crate::context::PagingType::DownlinkDataNotification,
        ) == 0
    {
        if let Err(e) = crate::gtp_path::send_downlink_data_notification_failure_indication(
            ctx,
            mme_ue_id,
            crate::s11_build::GtpCause::UeNotResponding,
        ) {
            log::error!("UE {mme_ue_id}: DDN Failure Indication not sent: {e}");
        }
    }
}

// ============================================================================
// UE Capability Info Indication (§8.10)
// ============================================================================

/// Handle UE Capability Info Indication: store the UE radio capability in
/// the MME UE context for later Handover Requests / context transfers.
pub fn handle_ue_capability_info_indication(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &UeCapabilityInfoIndication,
) {
    // #846: the sending eNB's pair, else ERROR INDICATION (TS 36.413 §10.6):
    // another UE's radio capability must not be overwritten.
    let Some(enb_ue_id) =
        ue_associated_target_or_answer(ctx, enb_id, msg.mme_ue_s1ap_id, msg.enb_ue_s1ap_id)
    else {
        return;
    };
    let Some(enb_ue) = ctx.enb_ue_find_by_id(enb_ue_id) else {
        return;
    };
    if let Some(mme_ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&enb_ue.mme_ue_id) {
        mme_ue.ue_radio_capability = msg.ue_radio_capability.clone();
        log::debug!(
            "Stored UE radio capability ({} bytes) for mme_ue_s1ap_id={}",
            msg.ue_radio_capability.len(),
            msg.mme_ue_s1ap_id
        );
    }
}

// ============================================================================
// Handover Signalling (§8.4)
// ============================================================================

/// Handle Handover Required (S1 handover preparation): allocate a target eNB
/// UE context and send Handover Request to the target eNB, or answer the
/// source eNB with Handover Preparation Failure.
pub fn handle_handover_required(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &HandoverRequired,
) -> Vec<S1apSend> {
    handle_handover_required_reporting(ctx, enb_id, msg, &[])
}

/// [`handle_handover_required`] for a HANDOVER REQUIRED decoded with the
/// generated codec (#514 stage 8b): `notify` IEs (TS 36.413 §10.3.4.2) are
/// reported in the Criticality Diagnostics of whichever answer the source eNB
/// gets -- the HANDOVER COMMAND (kept on the source context until it is built)
/// or the HANDOVER PREPARATION FAILURE.
pub fn handle_handover_required_reporting(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &HandoverRequired,
    notify: &[crate::s1ap_gen::DiagnosedIe],
) -> Vec<S1apSend> {
    let Some(source_ue_id) = ctx.enb_ue_find_by_mme_ue_s1ap_id(msg.mme_ue_s1ap_id) else {
        return handover_preparation_failure(
            enb_id,
            msg.mme_ue_s1ap_id,
            msg.enb_ue_s1ap_id,
            radio_network_cause::UNKNOWN_MME_UE_S1AP_ID,
            notify,
        );
    };
    let Some(source_ue) = ctx.enb_ue_find_by_id(source_ue_id) else {
        return handover_preparation_failure(
            enb_id,
            msg.mme_ue_s1ap_id,
            msg.enb_ue_s1ap_id,
            radio_network_cause::UNKNOWN_MME_UE_S1AP_ID,
            notify,
        );
    };
    // #731: the source must send it under the pair it holds.
    if let Err(out) = ue_by_pair(ctx, enb_id, msg.mme_ue_s1ap_id, msg.enb_ue_s1ap_id) {
        return out;
    }

    // Resolve the target eNB (only intra-LTE targets are supported)
    let target_enb_pool_id = match &msg.target_id {
        // #741/#882: by the whole Global eNB ID -- PLMN, ENB-ID alternative and value --
        // because a macro and a home eNB, or eNBs of two PLMNs, can share an id value.
        TargetId::TargetEnbId { global_enb_id, .. } => ctx.enb_find_by_global_enb_id(
            &decode_plmn_id(&global_enb_id.plmn_identity),
            global_enb_id.enb_id,
        ),
        TargetId::TargetRncId { .. } | TargetId::Cgi { .. } => None,
    };
    let Some(target_enb_pool_id) = target_enb_pool_id else {
        return handover_preparation_failure(
            enb_id,
            msg.mme_ue_s1ap_id,
            msg.enb_ue_s1ap_id,
            radio_network_cause::UNKNOWN_TARGET_ID,
            notify,
        );
    };

    let Some(mme_ue) = ctx.mme_ue_find_by_id(source_ue.mme_ue_id) else {
        return handover_preparation_failure(
            enb_id,
            msg.mme_ue_s1ap_id,
            msg.enb_ue_s1ap_id,
            radio_network_cause::UNKNOWN_MME_UE_S1AP_ID,
            notify,
        );
    };

    // #730 review m-a: one mobility procedure at a time. While the Serving GW
    // switch of a previous handover (its Modify Bearer Request) is outstanding,
    // the core has not completed it (TS 23.401 §5.5.1.1.2 step 4, §5.5.1.2.2
    // step 17), so a new preparation is refused (TS 36.413 §8.4.1.4,
    // interaction-with-other-procedure).
    if crate::gtp_path::handover_modification_pending(source_ue.mme_ue_id) {
        log::warn!(
            "Handover Required for mme_ue_s1ap_id={} while a handover's Modify Bearer Request \
             is outstanding; refused",
            msg.mme_ue_s1ap_id
        );
        return handover_preparation_failure(
            enb_id,
            msg.mme_ue_s1ap_id,
            msg.enb_ue_s1ap_id,
            radio_network_cause::INTERACTION_WITH_OTHER_PROCEDURE,
            notify,
        );
    }

    // Allocate the target eNB UE context (eNB UE S1AP ID arrives in the Ack)
    let target_ue_id = ctx.enb_ue_add(target_enb_pool_id, INVALID_UE_S1AP_ID);
    // #48: the source eNB's own statement about its transport to the target
    // (TS 36.413 §8.4.1.2). ABSENT means no direct path, which is what selects
    // indirect forwarding through the Serving GW -- so the default is `false` and the
    // IE's presence is the only thing that turns direct forwarding on.
    let direct_forwarding_available = msg.direct_forwarding_path_availability.is_some();

    let target_mme_ue_s1ap_id = {
        let mut pool = ctx.enb_ue_pool.write().unwrap();
        if let Some(source) = pool.get_mut(&source_ue_id) {
            source.target_ue_id = target_ue_id;
            source.handover_type = ho_type_from_s1ap(msg.handover_type);
            source.direct_forwarding_available = direct_forwarding_available;
            source.handover_required_notify = notify.to_vec();
        }
        if let Some(target) = pool.get_mut(&target_ue_id) {
            target.source_ue_id = source_ue_id;
            target.mme_ue_id = source_ue.mme_ue_id;
            target.handover_type = ho_type_from_s1ap(msg.handover_type);
            // #48: arm the preparation supervision. Without this a UE that never
            // arrives at the target leaks this context for the life of the process.
            target.handover_prep_deadline =
                Some(std::time::Instant::now() + HANDOVER_PREPARATION_SUPERVISION);
            target.mme_ue_s1ap_id
        } else {
            return handover_preparation_failure(
                enb_id,
                msg.mme_ue_s1ap_id,
                msg.enb_ue_s1ap_id,
                radio_network_cause::UNSPECIFIED,
                notify,
            );
        }
    };

    // Fresh {NCC, NH} pair for the target cell (TS 33.401 §7.2.8.4.2)
    let Some((ncc, nh)) = next_hop_advance(ctx, source_ue.mme_ue_id) else {
        return handover_preparation_failure(
            enb_id,
            msg.mme_ue_s1ap_id,
            msg.enb_ue_s1ap_id,
            radio_network_cause::UNSPECIFIED,
            notify,
        );
    };

    let erab_list: Vec<ErabToBeSetupItemHoReq> = ue_bearers(ctx, source_ue.mme_ue_id)
        .iter()
        .map(|bearer| ErabToBeSetupItemHoReq {
            erab_id: bearer.ebi,
            transport_layer_address: s1ap_build::ip_to_transport_address(&bearer.sgw_s1u_ip),
            gtp_teid: bearer.sgw_s1u_teid,
            erab_qos: s1ap_build::erab_qos_from_bearer(bearer),
        })
        .collect();
    if erab_list.is_empty() {
        return handover_preparation_failure(
            enb_id,
            msg.mme_ue_s1ap_id,
            msg.enb_ue_s1ap_id,
            radio_network_cause::UNKNOWN_E_RAB_ID,
            notify,
        );
    }

    let request = HandoverRequest {
        mme_ue_s1ap_id: target_mme_ue_s1ap_id,
        handover_type: msg.handover_type,
        cause: msg.cause,
        // #811: the UE-AMBR of the active APNs (TS 23.401 §4.7.3).
        ue_ambr: s1ap_build::ue_ambr_of(ctx, &mme_ue),
        erab_list,
        source_to_target_container: msg.source_to_target_container.clone(),
        ue_security_capabilities: ue_security_capabilities_from(&mme_ue),
        security_context: SecurityContext {
            next_hop_chaining_count: ncc,
            next_hop_parameter: nh,
        },
    };

    match crate::s1ap_gen::build_handover_request(&request) {
        Ok(pdu) => vec![S1apSend {
            enb_id: target_enb_pool_id,
            pdu,
        }],
        Err(e) => {
            log::error!("Failed to build Handover Request: {e}");
            handover_preparation_failure(
                enb_id,
                msg.mme_ue_s1ap_id,
                msg.enb_ue_s1ap_id,
                radio_network_cause::UNSPECIFIED,
                notify,
            )
        }
    }
}

// ============================================================================
// EPS→5GS handover, the MME as SOURCE (#584, TS 23.502 §4.11.1.2.2)
// ============================================================================

/// Handle a HANDOVER REQUIRED towards a gNB (TS 23.502 §4.11.1.2.2.2 steps
/// 1-3): build the Forward Relocation Request for the target AMF over N26 --
/// the UE's EPS security context with a fresh {NH, NCC} pair (TS 33.501 §8.4.2
/// step 2), its PDN connections, the source eNB's Source to Target container
/// as an F-Container of type 3 and the gNB as Target Identification type 5 --
/// and send it. Nothing goes back to the eNB until the AMF answers: the
/// HANDOVER COMMAND is built from its Forward Relocation Response
/// ([`eps_to_5gs_handover_command`]).
///
/// HANDOVER PREPARATION FAILURE when it cannot be prepared: the Handover Type
/// is not eps-to-5gs, N26 is off or unconfigured (unknown-targetID, as before
/// #584), the UE is unknown, or it has no bearer to move (TS 29.274 §7.3.1:
/// the source "shall not proceed ... if the UE does not have any EPS bearer
/// context(s)").
pub fn handle_handover_required_to_5gs(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &crate::s1ap_gen::HandoverRequiredTo5gs,
    notify: &[crate::s1ap_gen::DiagnosedIe],
) -> Vec<S1apSend> {
    let fail = |cause: i64| {
        handover_preparation_failure(
            enb_id,
            msg.mme_ue_s1ap_id,
            msg.enb_ue_s1ap_id,
            cause,
            notify,
        )
    };
    if msg.handover_type != S1apHandoverType::EpsTo5gs {
        log::warn!(
            "Handover Required from eNB {enb_id} names a gNB target with Handover Type {:?}, \
             not eps-to-5gs",
            msg.handover_type
        );
        return fail(radio_network_cause::UNKNOWN_TARGET_ID);
    }
    if !crate::n26_path::enabled() {
        log::warn!(
            "Handover Required from eNB {enb_id} to gNB {:#x}: N26 interworking is off, so this \
             MME cannot reach a 5GS target",
            msg.target.gnb_id
        );
        return fail(radio_network_cause::UNKNOWN_TARGET_ID);
    }
    let Some(source_ue) = ctx
        .enb_ue_find_by_mme_ue_s1ap_id(msg.mme_ue_s1ap_id)
        .and_then(|id| ctx.enb_ue_find_by_id(id))
        .filter(|ue| ue.enb_id == enb_id)
    else {
        return fail(radio_network_cause::UNKNOWN_MME_UE_S1AP_ID);
    };
    if source_ue.enb_ue_s1ap_id != msg.enb_ue_s1ap_id {
        return fail(radio_network_cause::UNKNOWN_PAIR_UE_S1AP_ID);
    }
    let mme_ue_id = source_ue.mme_ue_id;
    let Some(mme_ue_before) = ctx.mme_ue_find_by_id(mme_ue_id) else {
        return fail(radio_network_cause::UNKNOWN_MME_UE_S1AP_ID);
    };
    let pdn_connections: Vec<_> = mme_ue_before
        .sess_list
        .iter()
        .filter_map(|sess_id| ctx.sess_find_by_id(*sess_id))
        .filter_map(|sess| {
            let mut bearers: Vec<_> = sess
                .bearer_list
                .iter()
                .filter_map(|id| ctx.bearer_find_by_id(*id))
                .collect();
            bearers.sort_by_key(|b| b.ebi);
            crate::n26_build::handover_pdn_connection(&sess, &bearers)
        })
        .collect();
    if pdn_connections.is_empty() {
        return fail(radio_network_cause::UNKNOWN_E_RAB_ID);
    }
    let Some((ncc, nh)) = next_hop_advance(ctx, mme_ue_id) else {
        return fail(radio_network_cause::UNSPECIFIED);
    };
    let Some(mme_ue) = ctx.mme_ue_find_by_id(mme_ue_id) else {
        return fail(radio_network_cause::UNSPECIFIED);
    };
    let mm_context = crate::n26_build::handover_mm_context(&mme_ue, nh, ncc);
    let sent =
        crate::n26_path::send_eps_to_5gs_relocation(ctx, mme_ue_id, source_ue.id, |seq, fteid| {
            crate::n26_build::build_eps_to_5gs_forward_relocation_request(
                seq,
                &mme_ue.imsi_bcd,
                fteid,
                &mm_context,
                &pdn_connections,
                &msg.source_to_target_container,
                &msg.target,
                msg.direct_forwarding,
            )
        });
    if let Err(e) = sent {
        log::error!(
            "Handover Required from eNB {enb_id} to gNB {:#x}: no Forward Relocation Request \
             sent ({e})",
            msg.target.gnb_id
        );
        return fail(radio_network_cause::UNKNOWN_TARGET_ID);
    }
    if let Some(source) = ctx.enb_ue_pool.write().unwrap().get_mut(&source_ue.id) {
        source.handover_type = crate::context::HandoverType::EpsTo5gs;
        source.handover_required_notify = notify.to_vec();
        source.direct_forwarding_available = msg.direct_forwarding;
    }
    Vec::new()
}

/// The HANDOVER COMMAND an accepted EPS→5GS Forward Relocation Response gets
/// (TS 23.502 §4.11.1.2.2.3 steps 1-2, TS 23.401 §5.5.1.2.2 step 9): Handover
/// Type eps-to-5gs, the target NG-RAN's Target to Source container verbatim,
/// and every bearer the AMF did not list as set up in E-RABs to Release
/// (partial-handover). No E-RABs Subject to Data Forwarding: this MME sets up
/// no indirect forwarding tunnel for the move, and the AMF's response offers
/// no forwarding endpoint. Empty (the caller then fails the preparation) when
/// the source context is gone or the response has no container.
pub fn eps_to_5gs_handover_command(
    ctx: &MmeContext,
    record: &crate::n26_path::EpsTo5gsRelocation,
    response: &crate::n26_build::EpsTo5gsRelocationResponse,
) -> Vec<S1apSend> {
    let Some(source_ue) = ctx.enb_ue_find_by_id(record.source_enb_ue_id) else {
        log::warn!(
            "Forward Relocation Response for UE {}: its source eNB UE context is gone",
            record.mme_ue_id
        );
        return Vec::new();
    };
    let Some(container) = response.target_to_source_container.clone() else {
        log::error!(
            "Forward Relocation Response for UE {} accepted with no E-UTRAN Transparent \
             Container: there is no Target to Source container for the HANDOVER COMMAND",
            record.mme_ue_id
        );
        return Vec::new();
    };
    let erab_to_release_list = match &response.set_up_ebis {
        Some(set_up) => ue_bearers(ctx, record.mme_ue_id)
            .iter()
            .filter(|b| !set_up.contains(&b.ebi))
            .map(|b| nextgcore_s1ap::ErabItem {
                erab_id: b.ebi,
                cause: Cause::RadioNetwork(CauseRadioNetwork::PartialHandover),
            })
            .collect(),
        None => Vec::new(),
    };
    let command = HandoverCommand {
        mme_ue_s1ap_id: source_ue.mme_ue_s1ap_id,
        enb_ue_s1ap_id: source_ue.enb_ue_s1ap_id,
        handover_type: S1apHandoverType::EpsTo5gs,
        erab_subject_to_forwarding_list: Vec::new(),
        erab_to_release_list,
        target_to_source_container: container,
    };
    match crate::s1ap_gen::build_handover_command(&command, &source_ue.handover_required_notify) {
        Ok(pdu) => vec![S1apSend {
            enb_id: source_ue.enb_id,
            pdu,
        }],
        Err(e) => {
            log::error!("Failed to build Handover Command: {e}");
            Vec::new()
        }
    }
}

/// The HANDOVER PREPARATION FAILURE for an EPS→5GS relocation the target
/// refused or never answered (ho-failure-in-target-EPC-eNB-or-target-system).
pub fn eps_to_5gs_preparation_failed(
    ctx: &MmeContext,
    record: &crate::n26_path::EpsTo5gsRelocation,
) -> Vec<S1apSend> {
    let Some(source_ue) = ctx.enb_ue_find_by_id(record.source_enb_ue_id) else {
        return Vec::new();
    };
    if let Some(source) = ctx.enb_ue_pool.write().unwrap().get_mut(&source_ue.id) {
        source.handover_type = Default::default();
    }
    handover_preparation_failure(
        source_ue.enb_id,
        source_ue.mme_ue_s1ap_id,
        source_ue.enb_ue_s1ap_id,
        radio_network_cause::HO_FAILURE_IN_TARGET_EPC_ENB_OR_TARGET_SYSTEM,
        &source_ue.handover_required_notify,
    )
}

/// Release the source side once the UE is in NG-RAN (TS 23.502
/// §4.11.1.2.2.3 step 13 = TS 23.401 §5.5.1.2.2 steps 19-20): the source
/// Serving GW's sessions are deleted with Operation Indication NOT set (the
/// SMF+PGW-C keeps them as PDU sessions), the source eNB gets UE CONTEXT
/// RELEASE COMMAND (successful-handover), and the MME's EPS context for the
/// UE -- now served by the AMF -- is removed.
pub fn release_after_eps_to_5gs(
    ctx: &MmeContext,
    record: &crate::n26_path::EpsTo5gsRelocation,
) -> Vec<S1apSend> {
    let mme_ue = ctx.mme_ue_find_by_id(record.mme_ue_id);
    if let Some(mme_ue) = &mme_ue {
        for sess_id in &mme_ue.sess_list {
            if let Err(e) = crate::gtp_path::send_delete_session_request(
                ctx,
                Some(record.source_enb_ue_id),
                mme_ue.sgw_ue_id,
                *sess_id,
                crate::s11_build::GtpDeleteAction::InEpsTo5gsHandover,
            ) {
                log::warn!(
                    "[{}] EPS to 5GS handover complete, but the source Serving GW session {} \
                     was not deleted: {e:?}",
                    mme_ue.imsi_bcd,
                    sess_id
                );
            }
        }
    }
    let mut out = Vec::new();
    if let Some(source_ue) = ctx.enb_ue_find_by_id(record.source_enb_ue_id) {
        if let Some(source) = ctx.enb_ue_pool.write().unwrap().get_mut(&source_ue.id) {
            source.ue_ctx_rel_action = UeCtxRelAction::UeContextRemove;
        }
        match s1ap_build::build_ue_context_release_command(
            Some(source_ue.enb_ue_s1ap_id),
            source_ue.mme_ue_s1ap_id,
            S1apCauseGroup::RadioNetwork,
            radio_network_cause::SUCCESSFUL_HANDOVER,
        ) {
            Ok(pdu) => out.push(S1apSend {
                enb_id: source_ue.enb_id,
                pdu,
            }),
            Err(e) => log::error!("Failed to build UE Context Release Command: {e}"),
        }
    }
    if let Some(mme_ue) = mme_ue {
        for sess_id in &mme_ue.sess_list {
            if let Some(sess) = ctx.sess_find_by_id(*sess_id) {
                for bearer_id in &sess.bearer_list {
                    ctx.bearer_remove(*bearer_id);
                }
            }
            ctx.sess_remove(*sess_id);
        }
        ctx.mme_ue_remove(record.mme_ue_id);
        log::info!(
            "[{}] EPS to 5GS handover complete: the UE is served by the AMF; its EPS context \
             is released",
            mme_ue.imsi_bcd
        );
    }
    out
}

fn handover_preparation_failure(
    enb_id: u64,
    mme_ue_s1ap_id: u32,
    enb_ue_s1ap_id: u32,
    cause_value: i64,
    notify: &[crate::s1ap_gen::DiagnosedIe],
) -> Vec<S1apSend> {
    let failure = HandoverPreparationFailure {
        mme_ue_s1ap_id,
        enb_ue_s1ap_id,
        cause: s1ap_build::cause_to_s1ap(S1apCauseGroup::RadioNetwork, cause_value),
    };
    match crate::s1ap_gen::build_handover_preparation_failure_with_diagnostics(&failure, notify) {
        Ok(pdu) => S1apSend::to_origin(enb_id, pdu),
        Err(e) => {
            log::error!("Failed to build Handover Preparation Failure: {e}");
            Vec::new()
        }
    }
}

/// Handle Handover Request Acknowledge from the target eNB: record the
/// admitted E-RABs and send Handover Command to the source eNB.
pub fn handle_handover_request_acknowledge(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &HandoverRequestAcknowledge,
) -> Vec<S1apSend> {
    // #731: from the recorded target eNB, for a preparation outstanding, before
    // anything (the eNB UE S1AP ID included) is written.
    let target_ue_id =
        match handover_target_from(ctx, enb_id, msg.mme_ue_s1ap_id, Some(msg.enb_ue_s1ap_id)) {
            Ok(target) => target.id,
            Err(out) => return out,
        };

    let target_ue = {
        let mut pool = ctx.enb_ue_pool.write().unwrap();
        let Some(target) = pool.get_mut(&target_ue_id) else {
            return Vec::new();
        };
        target.enb_ue_s1ap_id = msg.enb_ue_s1ap_id;
        target.clone()
    };

    // Record the admitted S1-U endpoint AND the data-forwarding endpoints on the
    // bearer contexts.
    //
    // #48: the forwarding endpoints used to be decoded by `nextgcore-s1ap` and then
    // DROPPED here -- only `gtp_teid`/`transport_layer_address` were stored -- so the
    // target's answer to "where should the source forward my buffered downlink data?"
    // was thrown away and the Handover Command's forwarding list was always empty.
    // §9.1.5.2's E-RABs Subject to Forwarding List is built from exactly these.
    let mut admitted_forwarding = false;
    for item in &msg.erab_admitted_list {
        if let Some(bearer_id) = ctx.bearer_find_by_ebi(target_ue.mme_ue_id, item.erab_id) {
            if let Some(bearer) = ctx.bearer_pool.write().unwrap().get_mut(&bearer_id) {
                bearer.target_s1u_teid = item.gtp_teid;
                bearer.target_s1u_ip = transport_address_to_ip(&item.transport_layer_address);
                if let Some(teid) = item.dl_gtp_teid {
                    bearer.enb_dl_teid = teid;
                    admitted_forwarding = true;
                }
                if let Some(addr) = &item.dl_transport_layer_address {
                    bearer.enb_dl_ip = transport_address_to_ip(addr);
                }
                if let Some(teid) = item.ul_gtp_teid {
                    bearer.enb_ul_teid = teid;
                    admitted_forwarding = true;
                }
                if let Some(addr) = &item.ul_transport_layer_address {
                    bearer.enb_ul_ip = transport_address_to_ip(addr);
                }
            }
        }
    }

    let Some(source_ue) = ctx.enb_ue_find_by_id(target_ue.source_ue_id) else {
        log::error!("Handover Request Acknowledge without a linked source UE");
        return Vec::new();
    };

    // #48: choose the forwarding path (TS 23.401 §5.5.1.1.2 vs §5.5.1.2).
    //
    // Indirect forwarding needs a Serving GW round trip BEFORE the Handover Command
    // can be built, because the endpoints the source must forward to are the SGW's and
    // the SGW allocates them in the CIDFT response. So the command is DEFERRED in that
    // case and sent from `s11_handler`'s CIDFT-response path -- deferring is not an
    // optimisation, it is the only order in which the command can carry real
    // endpoints. Sending it now with an empty list is what this used to do.
    //
    // The target admitting no forwarding endpoints at all means it does not want
    // forwarding, so neither path applies and the command goes out immediately with an
    // empty list -- which §9.1.5.2 permits, the IE being optional.
    if !source_ue.direct_forwarding_available && admitted_forwarding {
        // Park what the command will need before the request goes out: the
        // target-to-source container is opaque and produced once, so it cannot be
        // re-derived when the response lands.
        {
            let mut pool = ctx.enb_ue_pool.write().unwrap();
            if let Some(target) = pool.get_mut(&target_ue.id) {
                target.pending_handover_command = Some(crate::context::PendingHandoverCommand {
                    handover_type: ho_type_to_s1ap(target_ue.handover_type),
                    erab_to_release_list: msg
                        .erab_failed_list
                        .iter()
                        .map(|item| nextgcore_s1ap::ErabItem {
                            erab_id: item.erab_id,
                            cause: item.cause,
                        })
                        .collect(),
                    target_to_source_container: msg.target_to_source_container.clone(),
                });
            }
        }
        match crate::gtp_path::send_create_indirect_data_forwarding_tunnel_request(
            ctx,
            target_ue.id,
            target_ue.mme_ue_id,
        ) {
            Ok(_) => {
                log::info!(
                    "No direct forwarding path for mme_ue_s1ap_id={}: requested indirect \
                     forwarding tunnels from the SGW, Handover Command deferred until the \
                     response",
                    msg.mme_ue_s1ap_id
                );
                return Vec::new();
            }
            Err(e) => {
                // Falling through with the TARGET's endpoints would tell the source to
                // forward straight to the target over a path the source just said it
                // does not have. An empty list loses the buffered data; a wrong list
                // sends it into a black hole. So: empty, and say so.
                log::error!(
                    "Indirect forwarding tunnel request failed ({e:?}); continuing the handover \
                     WITHOUT data forwarding, so buffered downlink data for \
                     mme_ue_s1ap_id={} is lost",
                    msg.mme_ue_s1ap_id
                );
                // The command is about to be sent synchronously below, so the parked
                // copy must go: a late CIDFT response finding it would send a SECOND
                // Handover Command for the same handover.
                let mut pool = ctx.enb_ue_pool.write().unwrap();
                if let Some(target) = pool.get_mut(&target_ue.id) {
                    target.pending_handover_command = None;
                }
            }
        }
    }

    let forwarding_list = if source_ue.direct_forwarding_available && admitted_forwarding {
        target_forwarding_list(ctx, target_ue.mme_ue_id)
    } else {
        Vec::new()
    };

    match build_handover_command_pdu(ctx, &source_ue, &target_ue, msg, forwarding_list) {
        Some(send) => vec![send],
        None => Vec::new(),
    }
}

/// Build the Handover Command for a prepared handover.
///
/// Shared by the direct-forwarding path (which returns it from the S1AP handler) and
/// the indirect path (which sends it from the CIDFT response, once the SGW's endpoints
/// are known). One builder rather than two because the only difference between the two
/// cases is which endpoints are in the forwarding list, and a second copy of the
/// release-list and container plumbing is a second copy that can drift.
pub(crate) fn build_handover_command_pdu(
    _ctx: &MmeContext,
    source_ue: &crate::context::EnbUe,
    target_ue: &crate::context::EnbUe,
    ack: &HandoverRequestAcknowledge,
    erab_subject_to_forwarding_list: Vec<ErabDataForwardingItem>,
) -> Option<S1apSend> {
    let command = HandoverCommand {
        mme_ue_s1ap_id: source_ue.mme_ue_s1ap_id,
        enb_ue_s1ap_id: source_ue.enb_ue_s1ap_id,
        handover_type: ho_type_to_s1ap(target_ue.handover_type),
        erab_subject_to_forwarding_list,
        erab_to_release_list: ack
            .erab_failed_list
            .iter()
            .map(|item| nextgcore_s1ap::ErabItem {
                erab_id: item.erab_id,
                cause: item.cause,
            })
            .collect(),
        target_to_source_container: ack.target_to_source_container.clone(),
    };

    match crate::s1ap_gen::build_handover_command(&command, &source_ue.handover_required_notify) {
        Ok(pdu) => Some(S1apSend {
            enb_id: source_ue.enb_id,
            pdu,
        }),
        Err(e) => {
            log::error!("Failed to build Handover Command: {e}");
            None
        }
    }
}

/// E-RABs Subject to Forwarding List pointing at the TARGET eNB's endpoints, for
/// DIRECT forwarding (TS 23.401 §5.5.1.1.2).
pub(crate) fn target_forwarding_list(
    ctx: &MmeContext,
    mme_ue_id: u64,
) -> Vec<ErabDataForwardingItem> {
    forwarding_list_from(ctx, mme_ue_id, |bearer| {
        (
            bearer.enb_dl_teid,
            &bearer.enb_dl_ip,
            bearer.enb_ul_teid,
            &bearer.enb_ul_ip,
        )
    })
}

/// E-RABs Subject to Forwarding List pointing at the SERVING GW's endpoints, for
/// INDIRECT forwarding (TS 23.401 §5.5.1.2).
pub(crate) fn sgw_forwarding_list(ctx: &MmeContext, mme_ue_id: u64) -> Vec<ErabDataForwardingItem> {
    forwarding_list_from(ctx, mme_ue_id, |bearer| {
        (
            bearer.sgw_dl_teid,
            &bearer.sgw_dl_ip,
            bearer.sgw_ul_teid,
            &bearer.sgw_ul_ip,
        )
    })
}

/// Build the forwarding list from whichever endpoint pair `pick` selects.
///
/// A bearer with a zero TEID contributes NOTHING for that direction rather than an
/// item with `teid: 0`: §9.1.5.2's DL/UL members are optional, and a zero TEID is a
/// valid-looking instruction to forward into nowhere. A bearer with neither direction
/// is left out of the list entirely.
fn forwarding_list_from<F>(ctx: &MmeContext, mme_ue_id: u64, pick: F) -> Vec<ErabDataForwardingItem>
where
    F: Fn(
        &crate::context::MmeBearer,
    ) -> (u32, &crate::context::IpAddr, u32, &crate::context::IpAddr),
{
    ue_bearers(ctx, mme_ue_id)
        .iter()
        .filter_map(|bearer| {
            let (dl_teid, dl_ip, ul_teid, ul_ip) = pick(bearer);
            if dl_teid == 0 && ul_teid == 0 {
                return None;
            }
            Some(ErabDataForwardingItem {
                erab_id: bearer.ebi,
                dl_transport_layer_address: (dl_teid != 0)
                    .then(|| s1ap_build::ip_to_transport_address(dl_ip)),
                dl_gtp_teid: (dl_teid != 0).then_some(dl_teid),
                ul_transport_layer_address: (ul_teid != 0)
                    .then(|| s1ap_build::ip_to_transport_address(ul_ip)),
                ul_gtp_teid: (ul_teid != 0).then_some(ul_teid),
            })
        })
        .collect()
}

/// Handle eNB Status Transfer from the source eNB (TS 36.413 §8.4.6) by relaying the
/// transparent container to the target eNB as an MME Status Transfer (§8.4.7).
///
/// The container carries the uplink PDCP-SN/HFN receiver status and the downlink
/// PDCP-SN/HFN transmitter status per E-RAB, and §8.4.6 says it is transferred "from
/// the source to the target eNB via the MME". This message used to decode to
/// `S1apMessage::Unknown` and be answered with an Error Indication carrying
/// `abstract-syntax-error-reject`, so every S1 handover with RLC-AM bearers lost PDCP
/// continuity AND the source eNB was told the MME could not parse a message it had
/// sent correctly (#48).
///
/// The relay is byte-for-byte: the container is not decoded on the way through. See
/// `nextgcore_s1ap::EnbStatusTransfer::status_transfer_container` for why.
pub fn handle_enb_status_transfer(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &EnbStatusTransfer,
) -> Vec<S1apSend> {
    // #731: the source eNB, under the pair it holds.
    let source_ue = match ue_by_pair(ctx, enb_id, msg.mme_ue_s1ap_id, msg.enb_ue_s1ap_id) {
        Ok(ue) => ue,
        Err(out) => return out,
    };

    // No prepared target means there is no handover to carry the status into. §8.4.6
    // defines no failure message for this procedure, so an Error Indication is the
    // only conformant way to say so -- and "message not compatible with receiver
    // state" is the accurate cause, unlike the abstract-syntax-error this used to get.
    let target_ue_id = source_ue.target_ue_id;
    if target_ue_id == NEXTGCORE_INVALID_POOL_ID {
        log::warn!(
            "eNB Status Transfer for mme_ue_s1ap_id={} with no handover in preparation",
            msg.mme_ue_s1ap_id
        );
        return error_indication(
            enb_id,
            Some(msg.enb_ue_s1ap_id),
            Some(msg.mme_ue_s1ap_id),
            S1apCauseGroup::Protocol,
            protocol_cause::MESSAGE_NOT_COMPATIBLE_WITH_RECEIVER_STATE,
        );
    }
    let Some(target_ue) = ctx.enb_ue_find_by_id(target_ue_id) else {
        return error_indication(
            enb_id,
            Some(msg.enb_ue_s1ap_id),
            Some(msg.mme_ue_s1ap_id),
            S1apCauseGroup::Protocol,
            protocol_cause::MESSAGE_NOT_COMPATIBLE_WITH_RECEIVER_STATE,
        );
    };

    // Addressed with the TARGET association's ids, not the source's: the container is
    // the only thing that crosses unchanged.
    let relay = MmeStatusTransfer {
        mme_ue_s1ap_id: target_ue.mme_ue_s1ap_id,
        enb_ue_s1ap_id: target_ue.enb_ue_s1ap_id,
        status_transfer_container: msg.status_transfer_container.clone(),
    };
    match crate::s1ap_gen::build_mme_status_transfer(&relay) {
        Ok(pdu) => {
            log::info!(
                "Relaying eNB Status Transfer ({} bytes) to target eNB {} as MME Status Transfer",
                msg.status_transfer_container.len(),
                target_ue.enb_id
            );
            vec![S1apSend {
                enb_id: target_ue.enb_id,
                pdu,
            }]
        }
        Err(e) => {
            log::error!("Failed to build MME Status Transfer: {e}");
            Vec::new()
        }
    }
}

/// Handle Handover Failure from the target eNB: free the target context and
/// answer the source eNB with Handover Preparation Failure.
pub fn handle_handover_failure(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &HandoverFailure,
) -> Vec<S1apSend> {
    // #731: a stray HANDOVER FAILURE (another eNB, or a UE in no handover) must
    // not delete a live UE's eNB context.
    let target_ue = match handover_target_from(ctx, enb_id, msg.mme_ue_s1ap_id, None) {
        Ok(target) => target,
        Err(out) => return out,
    };
    let target_ue_id = target_ue.id;
    // #48: the target reported the failure itself, so it is releasing its own
    // resources -- no release command, but the supervision must be disarmed before the
    // context goes, or the sweep would try to release an id that no longer exists.
    {
        let mut pool = ctx.enb_ue_pool.write().unwrap();
        if let Some(target) = pool.get_mut(&target_ue_id) {
            target.handover_prep_deadline = None;
        }
    }
    ctx.enb_ue_remove(target_ue_id);

    let Some(source_ue) = ctx.enb_ue_find_by_id(target_ue.source_ue_id) else {
        return Vec::new();
    };
    if let Some(source) = ctx.enb_ue_pool.write().unwrap().get_mut(&source_ue.id) {
        source.target_ue_id = NEXTGCORE_INVALID_POOL_ID;
        source.direct_forwarding_available = false;
    }

    let failure = HandoverPreparationFailure {
        mme_ue_s1ap_id: source_ue.mme_ue_s1ap_id,
        enb_ue_s1ap_id: source_ue.enb_ue_s1ap_id,
        cause: msg.cause,
    };
    match crate::s1ap_gen::build_handover_preparation_failure(&failure) {
        Ok(pdu) => vec![S1apSend {
            enb_id: source_ue.enb_id,
            pdu,
        }],
        Err(e) => {
            log::error!("Failed to build Handover Preparation Failure: {e}");
            Vec::new()
        }
    }
}

/// Handle Handover Notify from the target eNB: complete the handover by
/// switching the UE onto the target context and releasing the source.
pub fn handle_handover_notify(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &HandoverNotify,
) -> Vec<S1apSend> {
    handle_handover_notify_at(
        ctx,
        enb_id,
        msg.mme_ue_s1ap_id,
        msg.enb_ue_s1ap_id,
        Some((&msg.tai, &msg.eutran_cgi)),
    )
}

/// [`handle_handover_notify`] for a notify whose EUTRAN-CGI / TAI (both
/// criticality `ignore`, TS 36.413 §10.3.5) may be missing: without them the
/// UE's stored location is left as it is (#514 stage 8a).
pub fn handle_handover_notify_at(
    ctx: &MmeContext,
    enb_id: u64,
    mme_ue_s1ap_id: u32,
    enb_ue_s1ap_id: u32,
    location: Option<(&nextgcore_s1ap::Tai, &nextgcore_s1ap::EutranCgi)>,
) -> Vec<S1apSend> {
    let Some(target_ue_id) = ctx.enb_ue_find_by_mme_ue_s1ap_id(mme_ue_s1ap_id) else {
        log::error!("Handover Notify for unknown mme_ue_s1ap_id={mme_ue_s1ap_id}");
        return error_indication(
            enb_id,
            Some(enb_ue_s1ap_id),
            Some(mme_ue_s1ap_id),
            S1apCauseGroup::RadioNetwork,
            radio_network_cause::UNKNOWN_MME_UE_S1AP_ID,
        );
    };
    let Some(target_ue) = ctx.enb_ue_find_by_id(target_ue_id) else {
        return Vec::new();
    };

    // #730 review B1: the notify must come from the eNB the context lives on,
    // under the pair it holds (TS 36.413 §10.6: an inconsistent pair is answered
    // with ERROR INDICATION, unknown-pair-ue-s1ap-id, and nothing changes). Any
    // other eNB naming this MME UE S1AP ID reaches a UE it does not serve.
    if target_ue.enb_id != enb_id || target_ue.enb_ue_s1ap_id != enb_ue_s1ap_id {
        log::warn!(
            "Handover Notify from eNB {enb_id} for mme_ue_s1ap_id={mme_ue_s1ap_id}, \
             enb_ue_s1ap_id={enb_ue_s1ap_id}: the context belongs to eNB {} with \
             enb_ue_s1ap_id={}; ignored",
            target_ue.enb_id,
            target_ue.enb_ue_s1ap_id
        );
        return error_indication(
            enb_id,
            Some(enb_ue_s1ap_id),
            Some(mme_ue_s1ap_id),
            S1apCauseGroup::RadioNetwork,
            radio_network_cause::UNKNOWN_PAIR_UE_S1AP_ID,
        );
    }

    if let Some((tai, cgi)) = location {
        let tai = tai_from_s1ap(tai);
        let e_cgi = ecgi_from_s1ap(cgi);
        update_ue_location(ctx, target_ue.mme_ue_id, &tai, &e_cgi);
    }

    // #730 review B1: only the TARGET of a handover in progress completes one:
    // an S1 target whose preparation is outstanding (armed by HANDOVER REQUIRED,
    // cleared by the first notify), or a 5GS-to-EPS arrival whose N26 relocation
    // is recorded. A duplicate notify, or one for a UE that is not handing over,
    // only updates the location, as before #730: running the Serving GW switch
    // for it would detach a UE that is not moving.
    let s1_target = target_ue.handover_prep_deadline.is_some()
        && ctx
            .enb_ue_find_by_id(target_ue.source_ue_id)
            .is_some_and(|source| source.mme_ue_id == target_ue.mme_ue_id);
    let n26_arrival = crate::n26_path::forward_relocation_in_flight(target_ue.mme_ue_id);
    // A Serving GW switch of another procedure cannot be pending here: HANDOVER
    // REQUIRED is refused while one is (and a PATH SWITCH REQUEST while an S1
    // preparation is outstanding), so one UE never has two (#730 review m-a).
    if !(s1_target || n26_arrival) {
        log::warn!(
            "Handover Notify for mme_ue_s1ap_id={mme_ue_s1ap_id}: no handover to this eNB is in \
             progress (a duplicate, or a UE that is not handing over); only the location is \
             updated"
        );
        return Vec::new();
    }

    // The endpoints the target admitted (HANDOVER REQUEST ACKNOWLEDGE). They move
    // out of the bearers' target fields into the Modify Bearer Request below and
    // become the bearers' eNB endpoints once the Serving GW accepts them (#730).
    let mut switched = Vec::new();
    let mut omitted = Vec::new();
    for bearer in ue_bearers(ctx, target_ue.mme_ue_id) {
        if bearer.target_s1u_teid != 0 && bearer.target_s1u_ip.ipv4.is_some() {
            switched.push(crate::gtp_path::SwitchedBearer {
                ebi: bearer.ebi,
                teid: bearer.target_s1u_teid,
                ip: bearer.target_s1u_ip.clone(),
            });
        } else if bearer.enb_s1u_teid != 0 {
            // Active on the source and not admitted by the target (it was in
            // the Handover Command's E-RABs To Release List).
            omitted.push(bearer.ebi);
        }
        if let Some(b) = ctx.bearer_pool.write().unwrap().get_mut(&bearer.id) {
            b.target_s1u_teid = 0;
            b.target_s1u_ip = Default::default();
        }
    }

    // The UE now lives on the target context
    if let Some(mme_ue) = ctx
        .mme_ue_pool
        .write()
        .unwrap()
        .get_mut(&target_ue.mme_ue_id)
    {
        mme_ue.enb_ue_id = target_ue_id;
    }

    // #48: the UE arrived, so the preparation is no longer outstanding. Disarming here
    // rather than letting the deadline lapse harmlessly matters because the sweep would
    // otherwise release a target that is now SERVING the UE.
    {
        let mut pool = ctx.enb_ue_pool.write().unwrap();
        if let Some(target) = pool.get_mut(&target_ue_id) {
            target.handover_prep_deadline = None;
        }
    }

    // #408: if this UE arrived over N26 from a source AMF, that AMF must be told. TS 23.502
    // §4.11.1.2.1 step 12d has it answer with a Complete Acknowledge and only THEN start the
    // timer that releases its NG-RAN resources (step 21), so an MME that stays silent leaves
    // the source gNB holding radio resources for a UE that has left.
    //
    // Answers `false` for an intra-LTE handover, which is the common case and reaches here too
    // -- the record is what distinguishes them, because S1AP's HandoverNotify carries nothing
    // that says where the UE came from. Fired BEFORE the source-context release below, because
    // an N26 arrival has no LOCAL source eNB context: its source is an NG-RAN node this MME
    // never spoke to, so the `enb_ue_find_by_id` below returns None and takes an early exit
    // that would skip this notification entirely.
    //
    // This is also the PRODUCTION caller of
    // `n26_build::build_forward_relocation_complete_notification`. Without it that builder would
    // have only a test caller, which is the "correct but unreachable" defect this tree keeps
    // growing -- and the first draft of #408 had exactly that.
    if crate::n26_path::notify_forward_relocation_complete(target_ue.mme_ue_id) {
        log::info!(
            "UE {} completed a 5GS-to-EPS handover: its source AMF has been notified over N26 \
             (TS 29.274 §7.3.3)",
            target_ue.mme_ue_id
        );
    }

    // TS 23.401 §5.5.1.2.2 step 16: tell the Serving GW the target eNB's S1-U
    // F-TEIDs (#730). Without this the SGW keeps sending downlink to the source.
    switch_serving_gw_after_handover_notify(ctx, &target_ue, switched, omitted);

    // Release the source eNB context (TS 36.413 §8.4.3: successful handover)
    let Some(source_ue) = ctx.enb_ue_find_by_id(target_ue.source_ue_id) else {
        return Vec::new();
    };
    if let Some(source) = ctx.enb_ue_pool.write().unwrap().get_mut(&source_ue.id) {
        source.ue_ctx_rel_action = UeCtxRelAction::S1HandoverComplete;
    }
    match s1ap_build::build_ue_context_release_command(
        Some(source_ue.enb_ue_s1ap_id),
        source_ue.mme_ue_s1ap_id,
        S1apCauseGroup::RadioNetwork,
        radio_network_cause::SUCCESSFUL_HANDOVER,
    ) {
        Ok(pdu) => vec![S1apSend {
            enb_id: source_ue.enb_id,
            pdu,
        }],
        Err(e) => {
            log::error!("Failed to build UE Context Release Command: {e}");
            Vec::new()
        }
    }
}

/// Send the Modify Bearer Request of an S1 handover (TS 23.401 §5.5.1.2.2 step
/// 16) for the bearers the target admitted. No default bearer admitted, or a
/// request that cannot be sent, ends in the explicit detach a failed X2 handover
/// gets (§5.5.1.1.2), because the UE would otherwise have no downlink.
fn switch_serving_gw_after_handover_notify(
    ctx: &MmeContext,
    target_ue: &crate::context::EnbUe,
    switched: Vec<crate::gtp_path::SwitchedBearer>,
    omitted: Vec<u8>,
) {
    let mme_ue_id = target_ue.mme_ue_id;
    if ctx.mme_ue_find_by_id(mme_ue_id).is_none() {
        return;
    }
    let admitted: Vec<u8> = switched.iter().map(|b| b.ebi).collect();
    let (switched, omitted) = crate::handover_switch::only_pdns_with_a_switched_default(
        ctx, mme_ue_id, switched, omitted,
    );
    let switched_ebis: Vec<u8> = switched.iter().map(|b| b.ebi).collect();
    if !crate::handover_switch::a_default_bearer_switched(ctx, mme_ue_id, &switched_ebis) {
        crate::handover_switch::count_handover_failure(
            crate::handover_switch::failure_reason::NO_DEFAULT_BEARER,
        );
        log::error!(
            "UE {mme_ue_id}: the S1 handover target admitted no default bearer; detaching the \
             UE"
        );
        crate::handover_switch::detach_after_failed_handover(
            ctx,
            mme_ue_id,
            "an S1 handover whose target admitted no default bearer",
        );
        return;
    }
    let pending = crate::gtp_path::PendingHandoverModification {
        mme_ue_id,
        switched,
        omitted,
        kind: crate::gtp_path::HandoverModifyKind::HandoverNotify {
            enb_id: target_ue.enb_id,
            mme_ue_s1ap_id: target_ue.mme_ue_s1ap_id,
            enb_ue_s1ap_id: target_ue.enb_ue_s1ap_id,
            admitted,
        },
    };
    match crate::gtp_path::send_modify_bearer_request_for_handover(ctx, pending) {
        Ok(seq) => log::info!(
            "UE {mme_ue_id}: Handover Notify: Modify Bearer Request (seq={seq}) sent with the \
             target eNB's S1-U F-TEIDs (TS 23.401 §5.5.1.2.2 step 16)"
        ),
        Err(e) => {
            crate::handover_switch::count_handover_failure(
                crate::handover_switch::failure_reason::NOT_SENT,
            );
            log::error!(
                "UE {mme_ue_id}: Handover Notify: Modify Bearer Request not sent ({e}); \
                 detaching the UE"
            );
            crate::handover_switch::detach_after_failed_handover(
                ctx,
                mme_ue_id,
                "an S1 handover whose Modify Bearer Request could not be sent",
            );
        }
    }
}

/// Handle Handover Cancel from the source eNB: free the target context and
/// answer with Handover Cancel Acknowledge.
pub fn handle_handover_cancel(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &HandoverCancel,
) -> Vec<S1apSend> {
    handle_handover_cancel_reporting(ctx, enb_id, msg, &[])
}

/// [`handle_handover_cancel`], reporting `cancel_notify` (unknown
/// ignore-and-notify IEs of the HANDOVER CANCEL, a Class 1 initiating message)
/// in the acknowledge's Criticality Diagnostics (TS 36.413 §10.3.4.2).
pub fn handle_handover_cancel_reporting(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &HandoverCancel,
    cancel_notify: &[crate::s1ap_gen::DiagnosedIe],
) -> Vec<S1apSend> {
    // #731: the source eNB, under the pair it holds.
    let source_ue_id = match ue_by_pair(ctx, enb_id, msg.mme_ue_s1ap_id, msg.enb_ue_s1ap_id) {
        Ok(ue) => ue.id,
        Err(out) => return out,
    };

    // #584: a cancelled EPS to 5GS preparation must not be finished by a late
    // Forward Relocation Response (TS 23.502 §4.11.1.2.3). #592: and the target
    // AMF is told, with a Relocation Cancel Request (step 2), so it releases the
    // target NG-RAN resources and the SM contexts it prepared.
    if let Some(source) = ctx.enb_ue_find_by_id(source_ue_id) {
        if let Some(record) = crate::n26_path::take_eps_to_5gs_relocation(source.mme_ue_id) {
            match crate::n26_path::send_relocation_cancel(ctx, &record) {
                Ok(_) => log::info!(
                    "Handover Cancel: the EPS to 5GS relocation of UE {} is abandoned and the \
                     target AMF {} told",
                    source.mme_ue_id,
                    record.amf_peer
                ),
                Err(e) => log::warn!(
                    "Handover Cancel: the EPS to 5GS relocation of UE {} is abandoned, but the \
                     Relocation Cancel Request could not be sent: {e}",
                    source.mme_ue_id
                ),
            }
        }
    }

    let target_ue_id = {
        let mut pool = ctx.enb_ue_pool.write().unwrap();
        match pool.get_mut(&source_ue_id) {
            Some(source) => {
                let target = source.target_ue_id;
                source.target_ue_id = NEXTGCORE_INVALID_POOL_ID;
                source.direct_forwarding_available = false;
                target
            }
            None => NEXTGCORE_INVALID_POOL_ID,
        }
    };

    // #48: tell the TARGET to release before dropping our own record of it.
    //
    // §8.4.5.2 says the MME/target "release any resources associated with the handover
    // preparation", and the target's resources are reserved from the Handover Request
    // Acknowledge onwards -- radio, an S1-U endpoint, a UE context. Freeing only the
    // MME's copy (what this used to do) leaves the target holding all of it with
    // nothing left that could ever ask for it back, since the ids that addressed it
    // are gone.
    let mut sends = Vec::new();
    if target_ue_id != NEXTGCORE_INVALID_POOL_ID {
        if let Some(release) = release_prepared_target(ctx, target_ue_id, "handover cancelled") {
            sends.push(release);
        }
        ctx.enb_ue_remove(target_ue_id);
    }

    log::info!(
        "Handover Cancel: mme_ue_s1ap_id={} cause={:?}",
        msg.mme_ue_s1ap_id,
        msg.cause
    );

    match crate::s1ap_gen::build_handover_cancel_acknowledge(
        &HandoverCancelAcknowledge {
            mme_ue_s1ap_id: msg.mme_ue_s1ap_id,
            enb_ue_s1ap_id: msg.enb_ue_s1ap_id,
        },
        cancel_notify,
    ) {
        Ok(pdu) => {
            sends.push(S1apSend { enb_id, pdu });
            sends
        }
        Err(e) => {
            log::error!("Failed to build Handover Cancel Acknowledge: {e}");
            sends
        }
    }
}

/// Tell a prepared target eNB to release the resources it reserved for a handover that
/// is not going to complete, and disarm the preparation supervision.
///
/// `HANDOVER_CANCELLED` on an explicit cancel and `TS1_RELOCOVERALL_EXPIRY` on a
/// timeout, since those are what §9.2.1.3 provides and they tell the target which of
/// the two happened -- a distinction it needs for its own counters.
fn release_prepared_target(ctx: &MmeContext, target_ue_id: u64, reason: &str) -> Option<S1apSend> {
    let target_ue = ctx.enb_ue_find_by_id(target_ue_id)?;
    {
        let mut pool = ctx.enb_ue_pool.write().unwrap();
        if let Some(target) = pool.get_mut(&target_ue_id) {
            target.handover_prep_deadline = None;
        }
    }

    // A target that never answered the Handover Request has no eNB-UE-S1AP-ID yet, so
    // there is nothing to address a release to; the reservation is the target's own to
    // time out. Passing INVALID_UE_S1AP_ID on the wire would name a context the target
    // does not have.
    if target_ue.enb_ue_s1ap_id == INVALID_UE_S1AP_ID {
        log::info!(
            "Prepared target for mme_ue_s1ap_id={} never acknowledged ({reason}); no release to \
             send",
            target_ue.mme_ue_s1ap_id
        );
        return None;
    }

    let cause_value = if reason == "handover cancelled" {
        radio_network_cause::HANDOVER_CANCELLED
    } else {
        radio_network_cause::TS1_RELOCOVERALL_EXPIRY
    };
    match s1ap_build::build_ue_context_release_command(
        Some(target_ue.enb_ue_s1ap_id),
        target_ue.mme_ue_s1ap_id,
        S1apCauseGroup::RadioNetwork,
        cause_value,
    ) {
        Ok(pdu) => {
            log::info!(
                "Releasing prepared target eNB {} for mme_ue_s1ap_id={} ({reason})",
                target_ue.enb_id,
                target_ue.mme_ue_s1ap_id
            );
            Some(S1apSend {
                enb_id: target_ue.enb_id,
                pdu,
            })
        }
        Err(e) => {
            log::error!("Failed to build UE Context Release Command for prepared target: {e}");
            None
        }
    }
}

/// Sweep the eNB-UE pool for handover preparations that ran out of time, releasing the
/// target and freeing the context (#48).
///
/// Rides `MmeApp::run`'s existing 100 ms tick, the same way `nas_timer::expire_nas_timers`
/// does: no extra task, no channel, and it cannot silently stop firing. Cheap when
/// idle -- a walk of the pool that does nothing unless a deadline passed.
///
/// RETURNS the release commands rather than sending them, so the DECISION (which target
/// to release, and freeing the context) is separable from the TRANSMISSION (which needs
/// the process-global S1AP queue and a live SCTP association). A test can then assert
/// the decision; asserting the send would need an eNB.
#[must_use]
pub fn expire_handover_preparations(ctx: &MmeContext, now: std::time::Instant) -> Vec<S1apSend> {
    let mut sends = Vec::new();
    let expired: Vec<u64> = ctx
        .enb_ue_pool
        .read()
        .unwrap()
        .values()
        .filter(|ue| ue.handover_prep_deadline.is_some_and(|at| now >= at))
        .map(|ue| ue.id)
        .collect();

    for target_ue_id in expired {
        let source_ue_id = ctx
            .enb_ue_find_by_id(target_ue_id)
            .map(|ue| ue.source_ue_id)
            .unwrap_or(NEXTGCORE_INVALID_POOL_ID);

        log::warn!(
            "Handover preparation supervision expired for target enb_ue_id={target_ue_id} after \
             {}s; releasing the target",
            HANDOVER_PREPARATION_SUPERVISION.as_secs()
        );
        if let Some(send) = release_prepared_target(ctx, target_ue_id, "preparation timed out") {
            sends.push(send);
        }
        if source_ue_id != NEXTGCORE_INVALID_POOL_ID {
            let mut pool = ctx.enb_ue_pool.write().unwrap();
            if let Some(source) = pool.get_mut(&source_ue_id) {
                source.target_ue_id = NEXTGCORE_INVALID_POOL_ID;
                source.direct_forwarding_available = false;
            }
        }
        ctx.enb_ue_remove(target_ue_id);
    }

    sends
}

/// Handle Path Switch Request (X2 handover, TS 36.413 §8.4.4): move the UE's
/// S1 connection to the new eNB, switch the DL bearers, derive a fresh
/// {NCC, NH} pair (TS 33.401 §7.2.8.4) and answer with Path Switch Request
/// Acknowledge.
pub fn handle_path_switch_request(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &PathSwitchRequest,
) -> Vec<S1apSend> {
    handle_path_switch_request_reporting(ctx, enb_id, &msg.into(), &[])
}

/// [`handle_path_switch_request`], reporting `notify` (unknown
/// ignore-and-notify IEs of the PATH SWITCH REQUEST) in the acknowledge's
/// Criticality Diagnostics (TS 36.413 §10.3.4.2).
///
/// EUTRAN-CGI, TAI and UE Security Capabilities are `ignore` (§9.1.5.8), so
/// any of them may be absent (§10.3.5, #584): a missing location leaves the
/// stored one as it is, and missing capabilities leave nothing to compare.
pub fn handle_path_switch_request_reporting(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &crate::s1ap_gen::PathSwitchRequestAt,
    notify: &[crate::s1ap_gen::DiagnosedIe],
) -> Vec<S1apSend> {
    let Some(enb_ue_id) = ctx.enb_ue_find_by_mme_ue_s1ap_id(msg.source_mme_ue_s1ap_id) else {
        return path_switch_failure(
            enb_id,
            msg.source_mme_ue_s1ap_id,
            msg.enb_ue_s1ap_id,
            radio_network_cause::UNKNOWN_MME_UE_S1AP_ID,
        );
    };

    // TS 36.413 §8.4.4.4: the same E-RAB ID twice in the E-RAB To Be Switched DL
    // List is answered with a failure. Checked before anything changes.
    let mut seen = std::collections::HashSet::new();
    if !msg
        .erab_switched_dl_list
        .iter()
        .all(|item| seen.insert(item.erab_id))
    {
        crate::handover_switch::count_handover_failure(
            crate::handover_switch::failure_reason::DUPLICATE_ERAB,
        );
        return path_switch_failure(
            enb_id,
            msg.source_mme_ue_s1ap_id,
            msg.enb_ue_s1ap_id,
            radio_network_cause::MULTIPLE_E_RAB_ID_INSTANCES,
        );
    }
    // #730: one handover at a time. A second Path Switch Request while the first
    // one's Modify Bearer Request is outstanding would race it for the bearers.
    if let Some(ue) = ctx.enb_ue_find_by_id(enb_ue_id) {
        // #730 review m-a: and not while an S1 handover preparation of the same
        // UE is outstanding (a target context armed by HANDOVER REQUIRED).
        let s1_preparation = ctx
            .enb_ue_pool
            .read()
            .unwrap()
            .values()
            .any(|t| t.mme_ue_id == ue.mme_ue_id && t.handover_prep_deadline.is_some());
        if s1_preparation {
            log::warn!(
                "Path Switch Request for mme_ue_s1ap_id={} while an S1 handover preparation \
                 is outstanding; refused",
                msg.source_mme_ue_s1ap_id
            );
            crate::handover_switch::count_handover_failure(
                crate::handover_switch::failure_reason::ALREADY_PENDING,
            );
            return path_switch_failure(
                enb_id,
                msg.source_mme_ue_s1ap_id,
                msg.enb_ue_s1ap_id,
                radio_network_cause::INTERACTION_WITH_OTHER_PROCEDURE,
            );
        }
        if crate::gtp_path::handover_modification_pending(ue.mme_ue_id) {
            log::warn!(
                "Path Switch Request for mme_ue_s1ap_id={} while a handover's Modify Bearer \
                 Request is outstanding; refused",
                msg.source_mme_ue_s1ap_id
            );
            crate::handover_switch::count_handover_failure(
                crate::handover_switch::failure_reason::ALREADY_PENDING,
            );
            return path_switch_failure(
                enb_id,
                msg.source_mme_ue_s1ap_id,
                msg.enb_ue_s1ap_id,
                radio_network_cause::UNSPECIFIED,
            );
        }
    }

    let tai = msg.tai.as_ref().map(tai_from_s1ap);
    let e_cgi = msg.eutran_cgi.as_ref().map(ecgi_from_s1ap);

    // Re-anchor the eNB UE context on the new eNB
    let mme_ue_id = {
        let mut pool = ctx.enb_ue_pool.write().unwrap();
        let Some(enb_ue) = pool.get_mut(&enb_ue_id) else {
            return path_switch_failure(
                enb_id,
                msg.source_mme_ue_s1ap_id,
                msg.enb_ue_s1ap_id,
                radio_network_cause::UNKNOWN_MME_UE_S1AP_ID,
            );
        };
        enb_ue.enb_ue_s1ap_id = msg.enb_ue_s1ap_id;
        enb_ue.enb_id = enb_id;
        if let Some(tai) = &tai {
            enb_ue.saved.tai = tai.clone();
        }
        if let Some(e_cgi) = &e_cgi {
            enb_ue.saved.e_cgi = e_cgi.clone();
        }
        enb_ue.mme_ue_id
    };

    let Some(mme_ue) = ctx.mme_ue_find_by_id(mme_ue_id) else {
        return path_switch_failure(
            enb_id,
            msg.source_mme_ue_s1ap_id,
            msg.enb_ue_s1ap_id,
            radio_network_cause::UNKNOWN_MME_UE_S1AP_ID,
        );
    };

    // TS 33.401 §7.2.4.3.2: verify the replayed UE security capabilities
    let expected = ue_security_capabilities_from(&mme_ue);
    match msg.ue_security_capabilities {
        Some(got) if got != expected => log::warn!(
            "[{}] Path Switch Request: UE security capabilities mismatch \
             (got enc=0x{:04x}/int=0x{:04x}, expected enc=0x{:04x}/int=0x{:04x})",
            mme_ue.imsi_bcd,
            got.encryption_algorithms,
            got.integrity_algorithms,
            expected.encryption_algorithms,
            expected.integrity_algorithms
        ),
        Some(_) => {}
        None => log::info!(
            "[{}] Path Switch Request carries no UE Security Capabilities (criticality \
             ignore, TS 36.413 §10.3.5): nothing to compare with the stored ones",
            mme_ue.imsi_bcd
        ),
    }

    match (&tai, &e_cgi) {
        (Some(tai), Some(e_cgi)) => update_ue_location(ctx, mme_ue_id, tai, e_cgi),
        _ => {
            // A partial or absent location is applied field by field: the IE
            // that is present is current, the one that is missing is not news.
            if let Some(mme_ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
                if let Some(tai) = &tai {
                    mme_ue.tai = tai.clone();
                }
                if let Some(e_cgi) = &e_cgi {
                    mme_ue.e_cgi = e_cgi.clone();
                }
            }
        }
    }

    // TS 23.401 §5.5.1.1.2 step 2: the Serving GW is told the new eNB's S1-U
    // F-TEIDs by a Modify Bearer Request, and the acknowledge waits for its
    // response (step 5). The bearers keep their old endpoints until the SGW
    // accepts the new ones (#730).
    let bearers = ue_bearers(ctx, mme_ue_id);
    let mut switched = Vec::new();
    let mut released = Vec::new();
    for item in &msg.erab_switched_dl_list {
        let ip = transport_address_to_ip(&item.transport_layer_address);
        if !bearers.iter().any(|b| b.ebi == item.erab_id) {
            log::warn!(
                "[{}] Path Switch Request for unknown E-RAB {}",
                mme_ue.imsi_bcd,
                item.erab_id
            );
            released.push(nextgcore_s1ap::ErabItem {
                erab_id: item.erab_id,
                cause: Cause::RadioNetwork(CauseRadioNetwork::UnknownERabId),
            });
        } else if item.gtp_teid == 0 || ip.ipv4.is_none() {
            // The S11 builder carries an IPv4 S1-U F-TEID only; a bearer it
            // cannot describe to the SGW cannot be switched.
            log::warn!(
                "[{}] Path Switch Request: E-RAB {} has no usable IPv4 S1-U endpoint; it is \
                 released",
                mme_ue.imsi_bcd,
                item.erab_id
            );
            released.push(nextgcore_s1ap::ErabItem {
                erab_id: item.erab_id,
                cause: crate::handover_switch::CORE_NOT_SWITCHED,
            });
        } else {
            switched.push(crate::gtp_path::SwitchedBearer {
                ebi: item.erab_id,
                teid: item.gtp_teid,
                ip,
            });
        }
    }
    // TS 36.413 §8.4.4.2: E-RABs of the UE context missing from the list are
    // implicitly released by the eNB. Bearers never set up on the radio side
    // (no eNB endpoint yet) are not E-RABs of the context and stay as they are.
    let mut omitted: Vec<u8> = bearers
        .iter()
        .filter(|b| b.enb_s1u_teid != 0 && !switched.iter().any(|s| s.ebi == b.ebi))
        .map(|b| b.ebi)
        .collect();
    for item in &released {
        if bearers.iter().any(|b| b.ebi == item.erab_id) && !omitted.contains(&item.erab_id) {
            omitted.push(item.erab_id);
        }
    }
    // §5.5.1.1.2 step 2: only PDN connections whose default bearer is switched
    // are in the Modify Bearer Request; their other bearers are lost with them.
    let named_in_dl_list: Vec<u8> = msg
        .erab_switched_dl_list
        .iter()
        .map(|item| item.erab_id)
        .collect();
    let (switched, omitted) = crate::handover_switch::only_pdns_with_a_switched_default(
        ctx, mme_ue_id, switched, omitted,
    );
    // TS 36.413 §8.4.4.2: the To Be Released List names E-RABs that WERE in the
    // DL list and are not switched. Those absent from it are already implicitly
    // released by the eNB (#730 review m3).
    for ebi in &omitted {
        if named_in_dl_list.contains(ebi) && !released.iter().any(|r| r.erab_id == *ebi) {
            released.push(nextgcore_s1ap::ErabItem {
                erab_id: *ebi,
                cause: crate::handover_switch::CORE_NOT_SWITCHED,
            });
        }
    }

    // TS 23.401 §5.5.1.1.2: no default bearer switched means failure and an
    // explicit detach.
    let switched_ebis: Vec<u8> = switched.iter().map(|b| b.ebi).collect();
    if !crate::handover_switch::a_default_bearer_switched(ctx, mme_ue_id, &switched_ebis) {
        crate::handover_switch::count_handover_failure(
            crate::handover_switch::failure_reason::NO_DEFAULT_BEARER,
        );
        log::error!(
            "[{}] Path Switch Request switches no default bearer; failing it and detaching the \
             UE (TS 23.401 §5.5.1.1.2)",
            mme_ue.imsi_bcd
        );
        let out = path_switch_failure(
            enb_id,
            msg.source_mme_ue_s1ap_id,
            msg.enb_ue_s1ap_id,
            radio_network_cause::UNSPECIFIED,
        );
        crate::handover_switch::detach_after_failed_handover(
            ctx,
            mme_ue_id,
            "a Path Switch Request that switched no default bearer",
        );
        return out;
    }

    // Fresh {NCC, NH} pair (TS 33.401 §7.2.8.4.4)
    let Some((ncc, nh)) = next_hop_advance(ctx, mme_ue_id) else {
        return path_switch_failure(
            enb_id,
            msg.source_mme_ue_s1ap_id,
            msg.enb_ue_s1ap_id,
            radio_network_cause::UNSPECIFIED,
        );
    };
    let pending = crate::gtp_path::PendingHandoverModification {
        mme_ue_id,
        switched,
        omitted,
        kind: crate::gtp_path::HandoverModifyKind::PathSwitch {
            enb_id,
            mme_ue_s1ap_id: msg.source_mme_ue_s1ap_id,
            enb_ue_s1ap_id: msg.enb_ue_s1ap_id,
            ncc,
            nh,
            released,
            notify: notify.to_vec(),
        },
    };
    match crate::gtp_path::send_modify_bearer_request_for_handover(ctx, pending) {
        Ok(seq) => {
            log::info!(
                "[{}] Path Switch Request: Modify Bearer Request (seq={seq}) sent; the \
                 acknowledge waits for its response (TS 23.401 §5.5.1.1.2 steps 2-5)",
                mme_ue.imsi_bcd
            );
            Vec::new()
        }
        Err(e) => {
            crate::handover_switch::count_handover_failure(
                crate::handover_switch::failure_reason::NOT_SENT,
            );
            log::error!(
                "[{}] Path Switch Request: Modify Bearer Request not sent ({e}); failing it and \
                 detaching the UE",
                mme_ue.imsi_bcd
            );
            let out = path_switch_failure_with(
                enb_id,
                msg.source_mme_ue_s1ap_id,
                msg.enb_ue_s1ap_id,
                crate::handover_switch::CORE_NOT_SWITCHED,
            );
            crate::handover_switch::detach_after_failed_handover(
                ctx,
                mme_ue_id,
                "a Path Switch Request whose Modify Bearer Request could not be sent",
            );
            out
        }
    }
}

fn path_switch_failure_with(
    enb_id: u64,
    mme_ue_s1ap_id: u32,
    enb_ue_s1ap_id: u32,
    cause: Cause,
) -> Vec<S1apSend> {
    crate::handover_switch::path_switch_failure(enb_id, mme_ue_s1ap_id, enb_ue_s1ap_id, cause)
        .into_iter()
        .collect()
}

fn path_switch_failure(
    enb_id: u64,
    mme_ue_s1ap_id: u32,
    enb_ue_s1ap_id: u32,
    cause_value: i64,
) -> Vec<S1apSend> {
    let failure = PathSwitchRequestFailure {
        mme_ue_s1ap_id,
        enb_ue_s1ap_id,
        cause: s1ap_build::cause_to_s1ap(S1apCauseGroup::RadioNetwork, cause_value),
    };
    match crate::s1ap_gen::build_path_switch_request_failure(&failure, &[]) {
        Ok(pdu) => S1apSend::to_origin(enb_id, pdu),
        Err(e) => {
            log::error!("Failed to build Path Switch Request Failure: {e}");
            Vec::new()
        }
    }
}

// ============================================================================
// E-RAB Release Indication, E-RAB Modification Indication, Location Reporting
// (TS 36.413 §8.2.3.2, §8.2.4, §8.11) -- #584
// ============================================================================

/// The eNB UE context and MME UE id an indication names, if the UE S1AP ID
/// pair is one this MME holds for that eNB (TS 36.413 §10.6: an unknown or
/// inconsistent pair is answered with ERROR INDICATION).
fn ue_by_pair(
    ctx: &MmeContext,
    enb_id: u64,
    mme_ue_s1ap_id: u32,
    enb_ue_s1ap_id: u32,
) -> Result<crate::context::EnbUe, Vec<S1apSend>> {
    let found = ctx
        .enb_ue_find_by_mme_ue_s1ap_id(mme_ue_s1ap_id)
        .and_then(|id| ctx.enb_ue_find_by_id(id));
    match found {
        Some(ue) if ue.enb_ue_s1ap_id == enb_ue_s1ap_id && ue.enb_id == enb_id => Ok(ue),
        Some(_) => Err(error_indication(
            enb_id,
            Some(enb_ue_s1ap_id),
            Some(mme_ue_s1ap_id),
            S1apCauseGroup::RadioNetwork,
            radio_network_cause::UNKNOWN_PAIR_UE_S1AP_ID,
        )),
        None => Err(error_indication(
            enb_id,
            Some(enb_ue_s1ap_id),
            Some(mme_ue_s1ap_id),
            S1apCauseGroup::RadioNetwork,
            radio_network_cause::UNKNOWN_MME_UE_S1AP_ID,
        )),
    }
}

/// The UE-associated connections of one eNB, indexed by each UE S1AP ID, built
/// in one pass over the pool (#847 review: a partial Reset of N connections is
/// O(N + UEs), not O(N x UEs)).
///
/// The eNB UE S1AP ID index is a multimap (#846): when an eNB reuses an ID while
/// the MME still holds a stale connection under it, two connections carry it,
/// and a map keeping one of them would make the consistency check depend on
/// iteration order.
struct EnbConnections {
    /// MME UE S1AP ID (unique in the MME) -> (connection, its eNB UE S1AP ID).
    by_mme: std::collections::HashMap<u32, (u64, u32)>,
    /// eNB UE S1AP ID -> every connection holding it.
    by_enb: std::collections::HashMap<u32, Vec<u64>>,
}

impl EnbConnections {
    fn of(ctx: &MmeContext, enb_id: u64) -> Self {
        let mut by_mme = std::collections::HashMap::new();
        let mut by_enb: std::collections::HashMap<u32, Vec<u64>> = std::collections::HashMap::new();
        for (id, ue) in ctx.enb_ue_pool.read().unwrap().iter() {
            if ue.enb_id == enb_id {
                by_mme.insert(ue.mme_ue_s1ap_id, (*id, ue.enb_ue_s1ap_id));
                by_enb.entry(ue.enb_ue_s1ap_id).or_default().push(*id);
            }
        }
        Self { by_mme, by_enb }
    }

    /// The connections on this eNB carrying EITHER ID, and whether the IDs name
    /// one consistent connection (TS 36.413 §10.6; §8.7.1.2.1: a RESET item
    /// names its connection by "the MME UE S1AP ID IE and/or the eNB UE S1AP ID
    /// IE").
    ///
    /// Consistency is decided by the MME UE S1AP ID's own entry: the
    /// connection it names is consistent when its eNB UE S1AP ID is the one
    /// given (or none is given). An eNB UE S1AP ID alone is consistent only
    /// when one connection holds it. When inconsistent, every holder of either
    /// ID is returned, for release.
    fn carrying(&self, mme: Option<u32>, enb: Option<u32>) -> (Vec<u64>, bool) {
        let by_mme = mme.and_then(|id| self.by_mme.get(&id).copied());
        let holders: &[u64] = enb
            .and_then(|id| self.by_enb.get(&id))
            .map_or(&[], |v| v.as_slice());
        match by_mme {
            Some((id, its_enb)) if enb.is_none_or(|e| e == its_enb) => (vec![id], true),
            Some((id, _)) => {
                let mut all = vec![id];
                all.extend(holders.iter().copied().filter(|h| *h != id));
                (all, false)
            }
            None if mme.is_none() && holders.len() == 1 => (holders.to_vec(), true),
            None => (holders.to_vec(), false),
        }
    }

    /// Every connection holding eNB UE S1AP ID `enb`.
    fn holding(&self, enb: u32) -> Vec<u64> {
        self.by_enb.get(&enb).cloned().unwrap_or_default()
    }
}

/// What a teardown message (UE CONTEXT RELEASE REQUEST, INITIAL CONTEXT SETUP
/// FAILURE) from `enb_id` names (#847 review, TS 36.413 §10.6):
/// - `Ok(id)`: the one connection on that eNB with both IDs;
/// - `Err(out)`: no consistent connection. Every connection ON THAT eNB that
///   carries either ID is released locally (§10.6: "shall initiate a local
///   release of any established UE-associated logical connection (for the same
///   S1 interface) having the erroneous AP ID(s)"), and `out` is the ERROR
///   INDICATION (unknown-pair, or unknown-mme when neither ID is known).
///   Contexts on other eNBs are never touched (#731).
fn teardown_target(
    ctx: &MmeContext,
    enb_id: u64,
    mme_ue_s1ap_id: u32,
    enb_ue_s1ap_id: u32,
) -> Result<u64, Vec<S1apSend>> {
    let (found, consistent) =
        EnbConnections::of(ctx, enb_id).carrying(Some(mme_ue_s1ap_id), Some(enb_ue_s1ap_id));
    if consistent {
        return Ok(found[0]);
    }
    let cause = if found.is_empty() {
        radio_network_cause::UNKNOWN_MME_UE_S1AP_ID
    } else {
        radio_network_cause::UNKNOWN_PAIR_UE_S1AP_ID
    };
    for id in &found {
        log::warn!(
            "eNB {enb_id}: inconsistent UE S1AP ID pair (mme={mme_ue_s1ap_id}, \
             enb={enb_ue_s1ap_id}); releasing S1 connection {id} locally (TS 36.413 §10.6)"
        );
        release_s1_connection(ctx, *id);
    }
    Err(error_indication(
        enb_id,
        Some(enb_ue_s1ap_id),
        Some(mme_ue_s1ap_id),
        S1apCauseGroup::RadioNetwork,
        cause,
    ))
}

/// The connection a UE-associated message other than a teardown (UPLINK NAS
/// TRANSPORT, NAS NON DELIVERY INDICATION, UE CAPABILITY INFO INDICATION,
/// INITIAL CONTEXT SETUP RESPONSE, E-RAB SETUP RESPONSE) from `enb_id` names
/// (#846). The §10.6 rule is the same as for a teardown message: a consistent
/// pair on the sending eNB, or an ERROR INDICATION with the connections of that
/// eNB carrying either ID released locally.
fn ue_associated_target_or_answer(
    ctx: &MmeContext,
    enb_id: u64,
    mme_ue_s1ap_id: u32,
    enb_ue_s1ap_id: u32,
) -> Option<u64> {
    match ue_associated_target(ctx, enb_id, mme_ue_s1ap_id, enb_ue_s1ap_id) {
        Ok(id) => Some(id),
        Err(out) => {
            for send in out {
                crate::s1ap_path::s1ap_send(send);
            }
            None
        }
    }
}

fn ue_associated_target(
    ctx: &MmeContext,
    enb_id: u64,
    mme_ue_s1ap_id: u32,
    enb_ue_s1ap_id: u32,
) -> Result<u64, Vec<S1apSend>> {
    teardown_target(ctx, enb_id, mme_ue_s1ap_id, enb_ue_s1ap_id)
}

/// The TARGET context of a handover a target-side message (HANDOVER REQUEST
/// ACKNOWLEDGE, HANDOVER FAILURE) from `enb_id` names (#731): it must be on that
/// eNB, a preparation must be outstanding for it (an S1 target armed by
/// HANDOVER REQUIRED, or a 5GS-to-EPS arrival), and an eNB UE S1AP ID the
/// target already gave must match. Anything else is answered with ERROR
/// INDICATION (TS 36.413 §10.6) and changes nothing.
fn handover_target_from(
    ctx: &MmeContext,
    enb_id: u64,
    mme_ue_s1ap_id: u32,
    enb_ue_s1ap_id: Option<u32>,
) -> Result<crate::context::EnbUe, Vec<S1apSend>> {
    let found = ctx
        .enb_ue_find_by_mme_ue_s1ap_id(mme_ue_s1ap_id)
        .and_then(|id| ctx.enb_ue_find_by_id(id));
    let Some(target) = found else {
        return Err(error_indication(
            enb_id,
            enb_ue_s1ap_id,
            Some(mme_ue_s1ap_id),
            S1apCauseGroup::RadioNetwork,
            radio_network_cause::UNKNOWN_MME_UE_S1AP_ID,
        ));
    };
    let preparing = target.handover_prep_deadline.is_some()
        || crate::n26_path::forward_relocation_in_flight(target.mme_ue_id);
    let enb_ue_id_fits = match enb_ue_s1ap_id {
        Some(id) => target.enb_ue_s1ap_id == INVALID_UE_S1AP_ID || target.enb_ue_s1ap_id == id,
        None => true,
    };
    if target.enb_id == enb_id && preparing && enb_ue_id_fits {
        return Ok(target);
    }
    log::warn!(
        "target-side handover message from eNB {enb_id} for mme_ue_s1ap_id={mme_ue_s1ap_id}: \
         the context is on eNB {} (preparation outstanding: {preparing}, enb_ue_s1ap_id {} vs \
         {enb_ue_s1ap_id:?}); ignored (TS 36.413 §10.6)",
        target.enb_id,
        target.enb_ue_s1ap_id
    );
    Err(error_indication(
        enb_id,
        enb_ue_s1ap_id,
        Some(mme_ue_s1ap_id),
        S1apCauseGroup::RadioNetwork,
        radio_network_cause::UNKNOWN_PAIR_UE_S1AP_ID,
    ))
}

fn store_location(
    ctx: &MmeContext,
    enb_ue_id: u64,
    mme_ue_id: u64,
    tai: Option<&nextgcore_s1ap::Tai>,
    cgi: Option<&nextgcore_s1ap::EutranCgi>,
) {
    let tai = tai.map(tai_from_s1ap);
    let e_cgi = cgi.map(ecgi_from_s1ap);
    if let Some(enb_ue) = ctx.enb_ue_pool.write().unwrap().get_mut(&enb_ue_id) {
        if let Some(tai) = &tai {
            enb_ue.saved.tai = tai.clone();
        }
        if let Some(e_cgi) = &e_cgi {
            enb_ue.saved.e_cgi = e_cgi.clone();
        }
    }
    if let Some(mme_ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
        if let Some(tai) = tai {
            mme_ue.tai = tai;
        }
        if let Some(e_cgi) = e_cgi {
            mme_ue.e_cgi = e_cgi;
        }
        mme_ue.ue_location_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
    }
}

/// Handle an E-RAB RELEASE INDICATION (TS 36.413 §8.2.3.2): the eNB has
/// already released the E-RABs, so nothing is answered on S1. Each released
/// **dedicated** bearer is marked `released_by_enb` and, per PDN connection,
/// deleted towards the core with a Delete Bearer Command (TS 23.401 §5.4.4.2
/// step 2); the Delete Bearer Request that follows is answered without NAS
/// signalling (step 7 is omitted for an eNB-triggered release).
///
/// A **default** bearer is not released this way: §5.4.4.2 "deactivates
/// dedicated bearers. Default bearers are not affected", and the eNB "is not
/// expected" to release non-GBR bearers except in error situations. It is
/// logged and kept; tearing the PDN connection down is the UE's or MME's
/// PDN disconnection procedure (§5.10.3), not this one.
///
/// Returns what this MME transmits on S1 (only ERROR INDICATIONs); the
/// returned EBIs are the bearers a Delete Bearer Command was built for.
pub fn handle_erab_release_indication(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &crate::s1ap_gen::ErabReleaseIndication,
) -> (Vec<S1apSend>, Vec<u8>) {
    let enb_ue = match ue_by_pair(ctx, enb_id, msg.mme_ue_s1ap_id, msg.enb_ue_s1ap_id) {
        Ok(ue) => ue,
        Err(out) => return (out, Vec::new()),
    };
    let mme_ue_id = enb_ue.mme_ue_id;
    if let Some((tai, cgi)) = &msg.location {
        store_location(ctx, enb_ue.id, mme_ue_id, Some(tai), Some(cgi));
    }
    // Group the released dedicated bearers by PDN connection: one Delete
    // Bearer Command per PDN connection (§5.4.4.2 step 2).
    let mut per_sess: std::collections::BTreeMap<u64, Vec<u8>> = Default::default();
    for item in &msg.released {
        let Some(bearer_id) = ctx.bearer_find_by_ebi(mme_ue_id, item.erab_id) else {
            log::warn!(
                "E-RAB Release Indication from eNB {enb_id} names E-RAB {} the UE does not \
                 hold; ignored",
                item.erab_id
            );
            continue;
        };
        let Some(bearer) = ctx.bearer_find_by_id(bearer_id) else {
            continue;
        };
        let is_default = ctx.sess_find_by_id(bearer.sess_id).and_then(|sess| {
            sess.bearer_list
                .iter()
                .filter_map(|id| ctx.bearer_find_by_id(*id))
                .map(|b| b.ebi)
                .min()
        }) == Some(bearer.ebi);
        if is_default {
            log::warn!(
                "E-RAB Release Indication from eNB {enb_id} releases E-RAB {}, the DEFAULT bearer \
                 of its PDN connection (cause {:?}). TS 23.401 §5.4.4.2 releases dedicated bearers \
                 only, so the PDN connection is kept; it ends by PDN disconnection (§5.10.3)",
                item.erab_id,
                item.cause
            );
            continue;
        }
        if let Some(b) = ctx.bearer_pool.write().unwrap().get_mut(&bearer_id) {
            b.released_by_enb = true;
            // The radio side is gone: there is no eNB S1-U endpoint to send to.
            b.enb_s1u_teid = 0;
            b.enb_s1u_ip = Default::default();
        }
        per_sess
            .entry(bearer.sess_id)
            .or_default()
            .push(item.erab_id);
    }
    let mut commanded = Vec::new();
    for ebis in per_sess.values() {
        match crate::gtp_path::send_delete_bearer_command(ctx, mme_ue_id, ebis) {
            Ok(seq) => log::info!(
                "E-RAB Release Indication: Delete Bearer Command (seq={seq}) for EBIs {ebis:?} \
                 sent to the Serving GW (TS 23.401 §5.4.4.2 step 2)"
            ),
            Err(e) => log::error!(
                "E-RAB Release Indication: Delete Bearer Command for EBIs {ebis:?} not sent: {e}. \
                 The bearers stay marked released by the eNB, so a later Delete Bearer Request \
                 for them is still answered."
            ),
        }
        commanded.extend_from_slice(ebis);
    }
    (Vec::new(), commanded)
}

/// Handle an E-RAB MODIFICATION INDICATION (TS 36.413 §8.2.4, TS 23.401
/// §5.4.7): store each E-RAB's new downlink endpoint, ask the Serving GW to
/// switch it with a Modify Bearer Request, and confirm once it answers (step
/// 5). E-RABs the UE does not hold are confirmed as failed, unknown-E-RAB-ID.
///
/// When no Modify Bearer Request can be sent (no Serving GW path), the confirm
/// goes now, with every E-RAB in the failed list: the core did not switch
/// them, and §5.4.7 step 5 has the confirm say so.
pub fn handle_erab_modification_indication(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &crate::s1ap_gen::ErabModificationIndication,
    notify: &[crate::s1ap_gen::DiagnosedIe],
) -> Vec<S1apSend> {
    let enb_ue = match ue_by_pair(ctx, enb_id, msg.mme_ue_s1ap_id, msg.enb_ue_s1ap_id) {
        Ok(ue) => ue,
        Err(out) => return out,
    };
    let mme_ue_id = enb_ue.mme_ue_id;
    if let Some((tai, cgi)) = &msg.location {
        store_location(ctx, enb_ue.id, mme_ue_id, Some(tai), Some(cgi));
    }
    // TS 36.413 §8.2.4.4: several E-RAB ID IEs set to the same value, or a list
    // that leaves out an E-RAB of the UE context, and "the MME shall trigger the
    // UE Context Release procedure" (#852 review). Before, a duplicate was
    // switched twice and listed twice in the confirm.
    if let Some(why) = erab_modification_abnormal(ctx, mme_ue_id, msg) {
        log::warn!(
            "E-RAB Modification Indication for UE {mme_ue_id}: {why}; releasing the UE context \
             (TS 36.413 §8.2.4.4)"
        );
        let cause_value = if why.starts_with("duplicate") {
            radio_network_cause::MULTIPLE_E_RAB_ID_INSTANCES
        } else {
            radio_network_cause::UNSPECIFIED
        };
        if let Some(ue) = ctx.enb_ue_pool.write().unwrap().get_mut(&enb_ue.id) {
            ue.relcause.group = S1apCauseGroup::RadioNetwork;
            ue.relcause.cause = cause_value;
            ue.ue_ctx_rel_action = UeCtxRelAction::S1ContextRemove;
        }
        return match s1ap_build::build_ue_context_release_command(
            Some(msg.enb_ue_s1ap_id),
            msg.mme_ue_s1ap_id,
            S1apCauseGroup::RadioNetwork,
            cause_value,
        ) {
            Ok(pdu) => S1apSend::to_origin(enb_id, pdu),
            Err(e) => {
                log::error!("Failed to build UE Context Release Command: {e}");
                Vec::new()
            }
        };
    }
    let mut confirm = crate::s1ap_gen::ErabModificationConfirm {
        mme_ue_s1ap_id: msg.mme_ue_s1ap_id,
        enb_ue_s1ap_id: msg.enb_ue_s1ap_id,
        ..Default::default()
    };
    // #736: the new endpoints travel in the pending record and reach the
    // bearer contexts only once the Serving GW accepts them.
    let mut switched = Vec::new();
    for item in &msg.to_be_modified {
        let ip = transport_address_to_ip(&item.transport_layer_address);
        match ctx.bearer_find_by_ebi(mme_ue_id, item.erab_id) {
            Some(_) if item.gtp_teid == 0 || ip.ipv4.is_none() => {
                // The S11 builder carries IPv4 S1-U F-TEIDs only.
                confirm.failed.push(nextgcore_s1ap::ErabItem {
                    erab_id: item.erab_id,
                    cause: Cause::Transport(
                        nextgcore_s1ap::CauseTransport::TransportResourceUnavailable,
                    ),
                });
            }
            Some(_) => switched.push(crate::gtp_path::SwitchedBearer {
                ebi: item.erab_id,
                teid: item.gtp_teid,
                ip,
            }),
            None => confirm.failed.push(nextgcore_s1ap::ErabItem {
                erab_id: item.erab_id,
                cause: Cause::RadioNetwork(CauseRadioNetwork::UnknownERabId),
            }),
        }
    }
    let ebis: Vec<u8> = switched.iter().map(|s| s.ebi).collect();
    confirm.modified = ebis.clone();
    if ebis.is_empty() {
        return erab_modification_confirm_now(enb_id, &confirm, notify);
    }
    let pending = crate::gtp_path::PendingErabModification {
        enb_id,
        confirm: confirm.clone(),
        notify: notify.to_vec(),
        mme_ue_id,
        switched,
    };
    match crate::gtp_path::send_modify_bearer_request_for_erab_modification(ctx, pending) {
        Ok(seq) => {
            log::info!(
                "E-RAB Modification Indication: Modify Bearer Request (seq={seq}) for EBIs \
                 {ebis:?}; the confirm waits for its response (TS 23.401 §5.4.7 steps 2-5)"
            );
            Vec::new()
        }
        Err(e) => {
            log::error!(
                "E-RAB Modification Indication: Modify Bearer Request for EBIs {ebis:?} not \
                 sent ({e}); confirming them as failed"
            );
            erab_modification_confirm_now(
                enb_id,
                &switch_failed(
                    confirm,
                    Cause::Transport(nextgcore_s1ap::CauseTransport::Unspecified),
                ),
                notify,
            )
        }
    }
}

/// The TS 36.413 §8.2.4.4 condition an E-RAB MODIFICATION INDICATION meets, if
/// any: an E-RAB ID listed twice (across the to-be-modified and not-to-be-modified
/// lists), or an E-RAB of the UE context (a bearer with an eNB endpoint the eNB
/// has not released) in neither list.
fn erab_modification_abnormal(
    ctx: &MmeContext,
    mme_ue_id: u64,
    msg: &crate::s1ap_gen::ErabModificationIndication,
) -> Option<String> {
    let mut listed = std::collections::BTreeSet::new();
    for item in msg.to_be_modified.iter().chain(&msg.not_to_be_modified) {
        if !listed.insert(item.erab_id) {
            return Some(format!("duplicate E-RAB ID {}", item.erab_id));
        }
    }
    let missing: Vec<u8> = ctx
        .bearer_pool
        .read()
        .unwrap()
        .values()
        .filter(|b| b.mme_ue_id == mme_ue_id && b.enb_s1u_teid != 0 && !b.released_by_enb)
        .map(|b| b.ebi)
        .filter(|ebi| !listed.contains(ebi))
        .collect();
    (!missing.is_empty()).then(|| format!("E-RABs {missing:?} of the UE context are not listed"))
}

/// Move every "modified" E-RAB of `confirm` into its failed list with `cause`.
fn switch_failed(
    mut confirm: crate::s1ap_gen::ErabModificationConfirm,
    cause: Cause,
) -> crate::s1ap_gen::ErabModificationConfirm {
    for erab_id in std::mem::take(&mut confirm.modified) {
        confirm
            .failed
            .push(nextgcore_s1ap::ErabItem { erab_id, cause });
    }
    confirm
}

fn erab_modification_confirm_now(
    enb_id: u64,
    confirm: &crate::s1ap_gen::ErabModificationConfirm,
    notify: &[crate::s1ap_gen::DiagnosedIe],
) -> Vec<S1apSend> {
    match crate::s1ap_gen::build_erab_modification_confirm(confirm, notify) {
        Ok(pdu) => S1apSend::to_origin(enb_id, pdu),
        Err(e) => {
            log::error!("Failed to build E-RAB Modification Confirm: {e}");
            Vec::new()
        }
    }
}

/// The E-RAB MODIFICATION CONFIRM a parked modification gets once the Modify
/// Bearer Response arrives (TS 23.401 §5.4.7 step 5, TS 36.413 §8.2.4.2).
///
/// Each E-RAB is decided by the Serving GW's answer for its bearer (Table
/// 7.2.8-1, the rule the handover path uses): on Request accepted or accepted
/// partially, a bearer the SGW accepted is written with its new eNB endpoint
/// and listed modified, and every other one is listed failed; any other
/// message cause fails them all. Nothing is written for a failed one (#736),
/// and nothing is sent when the S1 association is gone.
pub fn erab_modification_confirm(
    ctx: &MmeContext,
    pending: crate::gtp_path::PendingErabModification,
    data: &crate::s11_handler::ModifyBearerResponseData,
) -> Option<S1apSend> {
    use crate::s11_build::GtpCause;
    let accepted_at_all = data.cause == GtpCause::RequestAccepted as u8
        || data.cause == GtpCause::RequestAcceptedPartially as u8;
    let (accepted, refused) = if accepted_at_all {
        crate::handover_switch::split_by_response(&pending.switched, data)
    } else {
        log::warn!(
            "Modify Bearer Response cause {} refused the E-RAB modification; the confirm lists \
             every E-RAB as failed to modify",
            data.cause
        );
        (
            Vec::new(),
            pending.switched.iter().map(|s| s.ebi).collect::<Vec<_>>(),
        )
    };
    // #852 review: nothing is written for an S1 association that no longer
    // serves the UE (an X2 path switch or a release overtook the Modify Bearer
    // Request): its late answer would overwrite the newer endpoint.
    if !association_live(ctx, &pending, &pending.confirm) {
        log::warn!(
            "UE {}: the S1 association of the E-RAB modification is gone; its Modify Bearer \
             Response changes nothing and no confirm is sent",
            pending.mme_ue_id
        );
        return None;
    }
    let mut released = Vec::new();
    for s in &accepted {
        if let Some(bearer_id) = ctx.bearer_find_by_ebi(pending.mme_ue_id, s.ebi) {
            if let Some(b) = ctx.bearer_pool.write().unwrap().get_mut(&bearer_id) {
                // An E-RAB RELEASE INDICATION for it arrived meanwhile: it stays
                // released, not revived with the eNB TEID it had.
                if b.released_by_enb {
                    released.push(s.ebi);
                    continue;
                }
                b.enb_s1u_teid = s.teid;
                b.enb_s1u_ip = s.ip.clone();
            }
        }
    }
    let accepted: Vec<_> = accepted
        .into_iter()
        .filter(|s| !released.contains(&s.ebi))
        .collect();
    let refused: Vec<u8> = refused.into_iter().chain(released).collect();
    let mut confirm = pending.confirm.clone();
    confirm.modified = accepted.iter().map(|s| s.ebi).collect();
    for erab_id in refused {
        confirm.failed.push(nextgcore_s1ap::ErabItem {
            erab_id,
            cause: Cause::Transport(nextgcore_s1ap::CauseTransport::TransportResourceUnavailable),
        });
    }
    confirm_on_live_association(ctx, &pending, &confirm)
}

/// N3 exhaustion of the Modify Bearer Request of an E-RAB modification: the
/// Serving GW never answered, so nothing was switched. The eNB gets its
/// E-RAB MODIFICATION CONFIRM with every E-RAB failed (#736, TS 36.413
/// §8.2.4.2), and no endpoint is written.
pub fn erab_modification_unanswered(
    ctx: &MmeContext,
    pending: crate::gtp_path::PendingErabModification,
) -> Option<S1apSend> {
    log::error!(
        "UE {}: the Serving GW never answered the E-RAB modification's Modify Bearer Request; \
         confirming every E-RAB as failed",
        pending.mme_ue_id
    );
    let confirm = switch_failed(
        pending.confirm.clone(),
        Cause::Transport(nextgcore_s1ap::CauseTransport::TransportResourceUnavailable),
    );
    confirm_on_live_association(ctx, &pending, &confirm)
}

/// Whether the S1 association `confirm` answers still serves the UE.
fn association_live(
    ctx: &MmeContext,
    pending: &crate::gtp_path::PendingErabModification,
    confirm: &crate::s1ap_gen::ErabModificationConfirm,
) -> bool {
    ctx.enb_ue_find_by_mme_ue_s1ap_id(confirm.mme_ue_s1ap_id)
        .and_then(|id| ctx.enb_ue_find_by_id(id))
        .is_some_and(|ue| {
            ue.enb_id == pending.enb_id
                && ue.enb_ue_s1ap_id == confirm.enb_ue_s1ap_id
                && ue.mme_ue_id == pending.mme_ue_id
        })
}

/// Send `confirm` only if the S1 association it answers still serves the UE.
fn confirm_on_live_association(
    ctx: &MmeContext,
    pending: &crate::gtp_path::PendingErabModification,
    confirm: &crate::s1ap_gen::ErabModificationConfirm,
) -> Option<S1apSend> {
    if !association_live(ctx, pending, confirm) {
        log::warn!(
            "UE {}: the S1 association of the E-RAB modification is gone; no confirm sent",
            pending.mme_ue_id
        );
        return None;
    }
    erab_modification_confirm_now(pending.enb_id, confirm, &pending.notify)
        .into_iter()
        .next()
}

/// Start (`start = true`, change-of-serve-cell) or stop
/// (stop-change-of-serve-cell) location reporting for `mme_ue_id` at its
/// serving eNB: the LOCATION REPORTING CONTROL (TS 36.413 §8.11.1). `None` when
/// the UE has no S1 connection.
pub fn location_reporting_control(
    ctx: &MmeContext,
    mme_ue_id: u64,
    start: bool,
) -> Option<S1apSend> {
    let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id)?;
    let enb_ue = ctx.enb_ue_find_by_id(mme_ue.enb_ue_id)?;
    let event = if start {
        nextgcore_s1ap_gen::generated::EventType::CHANGE_OF_SERVE_CELL
    } else {
        nextgcore_s1ap_gen::generated::EventType::STOP_CHANGE_OF_SERVE_CELL
    };
    let pdu = crate::s1ap_gen::build_location_reporting_control(
        enb_ue.mme_ue_s1ap_id,
        enb_ue.enb_ue_s1ap_id,
        event,
    )
    .map_err(|e| log::error!("Failed to build Location Reporting Control: {e}"))
    .ok()?;
    if let Some(ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
        ue.location_reporting_active = start;
    }
    Some(S1apSend {
        enb_id: enb_ue.enb_id,
        pdu,
    })
}

/// Handle a LOCATION REPORT (TS 36.413 §8.11.3): the reported cell and TA
/// become the UE's stored location.
pub fn handle_location_report(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &crate::s1ap_gen::LocationReport,
) -> Vec<S1apSend> {
    let enb_ue = match ue_by_pair(ctx, enb_id, msg.mme_ue_s1ap_id, msg.enb_ue_s1ap_id) {
        Ok(ue) => ue,
        Err(out) => return out,
    };
    let before = ctx
        .mme_ue_find_by_id(enb_ue.mme_ue_id)
        .map(|ue| (ue.tai, ue.e_cgi));
    store_location(
        ctx,
        enb_ue.id,
        enb_ue.mme_ue_id,
        msg.tai.as_ref(),
        msg.eutran_cgi.as_ref(),
    );
    log::info!(
        "Location Report from eNB {enb_id} for UE {} (event type {:?}): TAI {:?}, ECGI {:?}",
        enb_ue.mme_ue_id,
        msg.event_type,
        msg.tai,
        msg.eutran_cgi
    );
    // #593, TS 23.401 §5.9.2: a PDN GW that asked for location change reporting
    // is told with a Change Notification Request, via the Serving GW.
    let after = ctx
        .mme_ue_find_by_id(enb_ue.mme_ue_id)
        .map(|ue| (ue.tai, ue.e_cgi));
    if let (Some((tai0, cgi0)), Some((tai1, cgi1))) = (before, after) {
        let tai_changed = tai0 != tai1;
        let ecgi_changed = cgi0.plmn_id != cgi1.plmn_id || cgi0.cell_id != cgi1.cell_id;
        let notify = crate::s11_handler::sessions_to_notify(
            ctx,
            enb_ue.mme_ue_id,
            tai_changed,
            ecgi_changed,
        );
        if !notify.is_empty() {
            crate::gtp_path::send_change_notifications(ctx, enb_ue.mme_ue_id, &notify);
        }
    }
    Vec::new()
}

/// Handle a LOCATION REPORTING FAILURE INDICATION (TS 36.413 §8.11.2): the
/// eNB cannot report, so reporting is no longer active for the UE.
pub fn handle_location_reporting_failure(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &crate::s1ap_gen::LocationReportingFailure,
) -> Vec<S1apSend> {
    let enb_ue = match ue_by_pair(ctx, enb_id, msg.mme_ue_s1ap_id, msg.enb_ue_s1ap_id) {
        Ok(ue) => ue,
        Err(out) => return out,
    };
    if let Some(ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&enb_ue.mme_ue_id) {
        ue.location_reporting_active = false;
    }
    log::warn!(
        "Location Reporting Failure Indication from eNB {enb_id} for UE {} (cause {:?}): \
         location reporting is no longer active",
        enb_ue.mme_ue_id,
        msg.cause
    );
    Vec::new()
}

// ============================================================================
// Class-1 Response Consumption
// ============================================================================

/// Handle Initial Context Setup Response: record the eNB S1-U endpoints.
pub fn handle_initial_context_setup_response(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &InitialContextSetupResponse,
) {
    // #846: the sending eNB's pair, else ERROR INDICATION (TS 36.413 §10.6):
    // eNB S1-U endpoints must not be written onto another UE's bearers.
    let Some(enb_ue_id) =
        ue_associated_target_or_answer(ctx, enb_id, msg.mme_ue_s1ap_id, msg.enb_ue_s1ap_id)
    else {
        return;
    };
    let Some(enb_ue) = ctx.enb_ue_find_by_id(enb_ue_id) else {
        return;
    };
    if let Some(ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&enb_ue.mme_ue_id) {
        ue.ics_pending_on = 0;
    }

    for item in &msg.erab_setup_list {
        if let Some(bearer_id) = ctx.bearer_find_by_ebi(enb_ue.mme_ue_id, item.erab_id) {
            if let Some(bearer) = ctx.bearer_pool.write().unwrap().get_mut(&bearer_id) {
                bearer.enb_s1u_teid = item.gtp_teid;
                bearer.enb_s1u_ip = transport_address_to_ip(&item.transport_layer_address);
            }
        }
    }
    log_erab_failures(enb_id, &msg.erab_failed_list);

    // #956, TS 23.401 §5.3.4.1 steps 7-8: the Initial Context Setup of a SERVICE
    // REQUEST. The Serving GW gets the eNB S1-U endpoints of the E-RABs set up;
    // the ones the eNB failed are deactivated at the core (Delete Bearer
    // Command, the E-RAB release path of §5.4.4.2).
    let service_request = ctx
        .mme_ue_pool
        .write()
        .unwrap()
        .get_mut(&enb_ue.mme_ue_id)
        .is_some_and(|ue| std::mem::take(&mut ue.service_request_ics_pending));
    if service_request {
        service_request_context_set_up(ctx, enb_ue.mme_ue_id, &msg.erab_failed_list);
        return;
    }

    // TS 23.401 §5.3.2.1 step 23 needs this response AND the ATTACH COMPLETE (#495).
    crate::nas_dispatch::modify_bearer_after_attach(ctx, enb_ue_id, enb_ue.mme_ue_id);
}

/// The Initial Context Setup of a SERVICE REQUEST succeeded (TS 23.401
/// §5.3.4.1 steps 7-8, #956): Modify Bearer Request for the E-RABs set up, and a
/// Delete Bearer Command for those the eNB failed.
fn service_request_context_set_up(
    ctx: &MmeContext,
    mme_ue_id: u64,
    failed: &[nextgcore_s1ap::ErabFailedItem],
) {
    let failed_ebis: Vec<u8> = failed.iter().map(|f| f.erab_id).collect();
    if !failed_ebis.is_empty() {
        for ebi in &failed_ebis {
            if let Some(id) = ctx.bearer_find_by_ebi(mme_ue_id, *ebi) {
                if let Some(b) = ctx.bearer_pool.write().unwrap().get_mut(&id) {
                    b.enb_s1u_teid = 0;
                    b.released_by_enb = true;
                }
            }
        }
        match crate::gtp_path::send_delete_bearer_command(ctx, mme_ue_id, &failed_ebis) {
            Ok(seq) => log::warn!(
                "UE {mme_ue_id}: the eNB did not set up E-RABs {failed_ebis:?} of the SERVICE \
                 REQUEST; Delete Bearer Command (seq={seq}) for them (TS 23.401 §5.3.4.1)"
            ),
            Err(e) => log::error!(
                "UE {mme_ue_id}: Delete Bearer Command for the failed E-RABs {failed_ebis:?} not \
                 sent: {e}"
            ),
        }
    }
    match crate::gtp_path::send_modify_bearer_request_for_service_request(ctx, mme_ue_id) {
        Ok(seq) => log::info!(
            "UE {mme_ue_id}: SERVICE REQUEST user plane up; Modify Bearer Request (seq={seq}) \
             with the eNB S1-U F-TEIDs (TS 23.401 §5.3.4.1 step 8)"
        ),
        Err(e) => log::error!(
            "UE {mme_ue_id}: SERVICE REQUEST Modify Bearer Request not sent ({e}); the Serving \
             GW keeps buffering downlink"
        ),
    }
}

fn handle_erab_setup_response(
    ctx: &MmeContext,
    enb_id: u64,
    mme_ue_s1ap_id: u32,
    enb_ue_s1ap_id: u32,
    erab_setup_list: &[nextgcore_s1ap::ErabSetupItem],
) {
    // #846: the sending eNB's pair, else ERROR INDICATION (TS 36.413 §10.6).
    let Some(enb_ue_id) =
        ue_associated_target_or_answer(ctx, enb_id, mme_ue_s1ap_id, enb_ue_s1ap_id)
    else {
        return;
    };
    let Some(enb_ue) = ctx.enb_ue_find_by_id(enb_ue_id) else {
        return;
    };
    for item in erab_setup_list {
        if let Some(bearer_id) = ctx.bearer_find_by_ebi(enb_ue.mme_ue_id, item.erab_id) {
            if let Some(bearer) = ctx.bearer_pool.write().unwrap().get_mut(&bearer_id) {
                bearer.enb_s1u_teid = item.gtp_teid;
                bearer.enb_s1u_ip = transport_address_to_ip(&item.transport_layer_address);
            }
        }
    }
}

fn log_erab_failures(enb_id: u64, failures: &[nextgcore_s1ap::ErabFailedItem]) {
    for item in failures {
        log::error!(
            "E-RAB {} failed on eNB {enb_id} with cause {:?}",
            item.erab_id,
            item.cause
        );
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Map the S1AP Handover Type into the context representation
fn ho_type_from_s1ap(handover_type: S1apHandoverType) -> crate::context::HandoverType {
    match handover_type {
        S1apHandoverType::IntraLte => crate::context::HandoverType::IntraLte,
        S1apHandoverType::LteToUtran => crate::context::HandoverType::LteToUtran,
        S1apHandoverType::LteToGeran => crate::context::HandoverType::LteToGeran,
        S1apHandoverType::UtranToLte => crate::context::HandoverType::UtranToLte,
        S1apHandoverType::GeranToLte => crate::context::HandoverType::GeranToLte,
        // #62: the inbound direction too. An eNB that supports the extension can send
        // either of these, and mapping them to `IntraLte` on the way in would record
        // the UE as doing an intra-LTE handover — so every later decision about it
        // (bearer handling, target selection) would be made about the wrong procedure.
        S1apHandoverType::EpsTo5gs => crate::context::HandoverType::EpsTo5gs,
        S1apHandoverType::FiveGsToEps => crate::context::HandoverType::FiveGsToEps,
    }
}

/// Map the context Handover Type onto the S1AP representation.
fn ho_type_to_s1ap(handover_type: crate::context::HandoverType) -> S1apHandoverType {
    match handover_type {
        crate::context::HandoverType::IntraLte => S1apHandoverType::IntraLte,
        // #62: these two used to collapse into `IntraLte` under the comment "5GS
        // interworking types never reach the S1AP handover path". They are no longer
        // unrepresentable: TS 36.413 defines `eps-to-5gs` and `fivegs-to-eps` as the
        // two extension additions of `HandoverType` (`36413-j20.txt:30619`), and the
        // wire enum now carries them.
        //
        // Collapsing was worse than the comment suggested. If one of them DID reach
        // this path, the eNB was told "intra-LTE handover" about an inter-system move
        // and would admit it as an ordinary LTE handover — the eNB acting on a wrong
        // wire value, rather than an unused branch. Mapping them truthfully means an
        // eNB that does not support the extension can reject a value it does not
        // recognise, which is what the extension marker is for.
        crate::context::HandoverType::EpsTo5gs => S1apHandoverType::EpsTo5gs,
        crate::context::HandoverType::FiveGsToEps => S1apHandoverType::FiveGsToEps,
        crate::context::HandoverType::LteToUtran => S1apHandoverType::LteToUtran,
        crate::context::HandoverType::LteToGeran => S1apHandoverType::LteToGeran,
        crate::context::HandoverType::UtranToLte => S1apHandoverType::UtranToLte,
        crate::context::HandoverType::GeranToLte => S1apHandoverType::GeranToLte,
    }
}

/// Collect all bearer contexts belonging to a UE
fn ue_bearers(ctx: &MmeContext, mme_ue_id: u64) -> Vec<crate::context::MmeBearer> {
    let mut bearers: Vec<crate::context::MmeBearer> = ctx
        .bearer_pool
        .read()
        .unwrap()
        .values()
        .filter(|bearer| bearer.mme_ue_id == mme_ue_id)
        .cloned()
        .collect();
    bearers.sort_by_key(|bearer| bearer.ebi);
    bearers
}

/// Update the UE's last known location
fn update_ue_location(ctx: &MmeContext, mme_ue_id: u64, tai: &EpsTai, e_cgi: &ECgi) {
    if let Some(mme_ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
        mme_ue.tai = tai.clone();
        mme_ue.e_cgi = e_cgi.clone();
        mme_ue.ue_location_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
    }
}

/// Advance the UE's {NH, NCC} pair per TS 33.401 Annex A.4 / §7.2.8.4.
///
/// The first derivation (NCC 0 -> 1) uses KeNB as the SYNC input; every
/// subsequent derivation chains on the previous NH. NCC is a 3-bit counter.
fn next_hop_advance(ctx: &MmeContext, mme_ue_id: u64) -> Option<(u8, [u8; 32])> {
    let mut pool = ctx.mme_ue_pool.write().unwrap();
    let mme_ue = pool.get_mut(&mme_ue_id)?;
    let sync_input = if mme_ue.nhcc == 0 {
        mme_ue.kenb
    } else {
        mme_ue.nh
    };
    mme_ue.nh = nextgcore_crypt::kdf::nextgcore_kdf_nh_enb(&mme_ue.kasme, &sync_input);
    mme_ue.nhcc = (mme_ue.nhcc + 1) & 0x07;
    Some((mme_ue.nhcc, mme_ue.nh))
}

/// Expose the cause as a context-level S1apCause (for FSM consumers)
pub fn s1ap_cause(cause: &Cause) -> S1apCause {
    cause_from_s1ap(cause)
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{Bitrate, MmeUe, PlmnId, ServedGummei};
    use crate::s1ap_gen::test_codec::{builder, decode_s1ap_pdu};
    use nextgcore_s1ap::EnbId;
    use nextgcore_s1ap::{
        CauseRadioNetwork, ErabSwitchedItem, GlobalEnbId, STmsi, SupportedTaItem,
        UeAssociatedLogicalS1Connection, UeSecurityCapabilities,
    };

    fn test_ctx() -> MmeContext {
        let ctx = MmeContext::new();
        ctx.init();
        ctx
    }

    /// #811: the HANDOVER REQUEST signals the UE-AMBR of the active APNs
    /// (TS 23.401 §4.7.3), not the subscribed value as such.
    #[test]
    fn the_handover_request_carries_the_ue_ambr_of_the_active_apns() {
        use nextgcore_s1ap_gen::generated as g;
        let ctx = test_ctx();
        let (_enb_id, enb_ue_id, mme_ue_id, mme_ue_s1ap_id) = add_ue(&ctx);
        let source_enb = ctx.enb_ue_find_by_id(enb_ue_id).unwrap().enb_id;
        let sess_id = ctx.sess_add(mme_ue_id, 1);
        let bearer_id = ctx.bearer_add(sess_id, mme_ue_id);
        {
            let mut pool = ctx.bearer_pool.write().unwrap();
            let b = pool.get_mut(&bearer_id).unwrap();
            b.ebi = 5;
            b.qos.qci = 9;
            b.sgw_s1u_teid = 0x811;
            b.sgw_s1u_ip.ipv4 = Some([10, 0, 0, 2]);
            b.enb_s1u_teid = 0x118;
        }
        {
            let mut pool = ctx.sess_pool.write().unwrap();
            let sess = pool.get_mut(&sess_id).unwrap();
            sess.bearer_list.push(bearer_id);
            sess.ambr.downlink = 300_000;
            sess.ambr.uplink = 200_000;
        }
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&mme_ue_id)
            .unwrap()
            .sess_list
            .push(sess_id);
        let target = ctx.enb_add("127.0.0.1:36481".parse().unwrap());
        // #858: the target is found by its full Global eNB ID, S1 Setup complete.
        ctx.enb_set_s1_connected_for_test(target, &[0x13, 0x00, 0x14], EnbId::Macro(0x811));
        let required = HandoverRequired {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: 100,
            handover_type: nextgcore_s1ap::HandoverType::IntraLte,
            cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
            target_id: TargetId::TargetEnbId {
                global_enb_id: GlobalEnbId {
                    plmn_identity: [0x13, 0x00, 0x14],
                    enb_id: EnbId::Macro(0x811),
                },
                selected_tai: nextgcore_s1ap::Tai {
                    plmn_identity: [0x13, 0x00, 0x14],
                    tac: 1,
                },
            },
            direct_forwarding_path_availability: None,
            source_to_target_container: vec![0],
        };
        let out = handle_handover_required(&ctx, source_enb, &required);
        let ambr = out
            .iter()
            .filter(|o| o.enb_id == target)
            .find_map(|o| match nextgcore_s1ap_gen::decode(&o.pdu) {
                Ok(g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
                    value: g::InitiatingMessageValue::Id_HandoverResourceAllocation(req),
                    ..
                })) => req
                    .protocol_i_es
                    .0
                    .into_iter()
                    .find_map(|ie| match ie.value {
                        g::HandoverRequestProtocolIEs_EntryValue::Id_uEaggregateMaximumBitrate(
                            a,
                        ) => Some((
                            a.u_eaggregate_maximum_bit_rate_dl.0,
                            a.u_eaggregate_maximum_bit_rate_ul.0,
                        )),
                        _ => None,
                    }),
                _ => None,
            })
            .unwrap_or_else(|| panic!("a HANDOVER REQUEST to the target: {out:?}"));
        // add_ue subscribes 1 Gbit/s / 500 Mbit/s; the one active APN is lower.
        assert_eq!(ambr, (300_000, 200_000));
    }

    /// Whether `out` is exactly one ERROR INDICATION to `enb_id` with the
    /// radio-network cause `cause`.
    fn is_error_indication_to(out: &[S1apSend], enb_id: u64, cause: CauseRadioNetwork) -> bool {
        use nextgcore_s1ap_gen::generated as g;
        out.len() == 1
            && out[0].enb_id == enb_id
            && matches!(
                nextgcore_s1ap_gen::decode(&out[0].pdu),
                Ok(g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
                    value: g::InitiatingMessageValue::Id_ErrorIndication(ref e),
                    ..
                })) if e.protocol_i_es.0.iter().any(|ie| matches!(
                    &ie.value,
                    g::ErrorIndicationProtocolIEs_EntryValue::Id_Cause(g::Cause::RadioNetwork(r))
                        if r.0 == cause as u8
                ))
            )
    }

    /// #731, TS 36.413 §10.6: a HANDOVER FAILURE naming a UE that is in no
    /// handover, or sent by an eNB that is not its target, deletes nothing and
    /// gets ERROR INDICATION (unknown-pair-ue-s1ap-id). Before #731 the UE's
    /// eNB context was removed and nothing was sent.
    #[test]
    fn a_stray_handover_failure_deletes_no_live_ue() {
        let ctx = test_ctx();
        let (enb_id, enb_ue_id, mme_ue_id, mme_ue_s1ap_id) = add_ue(&ctx);
        let other_enb = ctx.enb_add("127.0.0.1:36499".parse().unwrap());
        let failure = HandoverFailure {
            mme_ue_s1ap_id,
            cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
        };
        for from in [enb_id, other_enb] {
            let out = handle_handover_failure(&ctx, from, &failure);
            assert!(
                is_error_indication_to(&out, from, CauseRadioNetwork::UnknownPairUeS1apId),
                "{out:?}"
            );
            assert!(
                ctx.enb_ue_find_by_id(enb_ue_id).is_some(),
                "the live context stays"
            );
            assert_eq!(
                ctx.mme_ue_find_by_id(mme_ue_id).unwrap().enb_ue_id,
                enb_ue_id
            );
        }
    }

    /// #731: a HANDOVER REQUEST ACKNOWLEDGE from an eNB that is not the
    /// recorded target changes nothing (the eNB UE S1AP ID is not overwritten)
    /// and gets ERROR INDICATION.
    #[test]
    fn a_handover_request_ack_from_another_enb_changes_nothing() {
        let ctx = test_ctx();
        let (_enb_id, source_ue_id, mme_ue_id, _) = add_ue(&ctx);
        let target_enb = ctx.enb_add("127.0.0.1:36498".parse().unwrap());
        let intruder = ctx.enb_add("127.0.0.1:36497".parse().unwrap());
        let target_ue_id = ctx.enb_ue_add(target_enb, INVALID_UE_S1AP_ID);
        {
            let mut pool = ctx.enb_ue_pool.write().unwrap();
            let t = pool.get_mut(&target_ue_id).unwrap();
            t.mme_ue_id = mme_ue_id;
            t.source_ue_id = source_ue_id;
            t.handover_prep_deadline =
                Some(std::time::Instant::now() + std::time::Duration::from_secs(10));
        }
        let target_mme_id = ctx.enb_ue_find_by_id(target_ue_id).unwrap().mme_ue_s1ap_id;
        let ack = HandoverRequestAcknowledge {
            mme_ue_s1ap_id: target_mme_id,
            enb_ue_s1ap_id: 0x731,
            erab_admitted_list: Vec::new(),
            erab_failed_list: Vec::new(),
            target_to_source_container: vec![0],
        };
        let out = handle_handover_request_acknowledge(&ctx, intruder, &ack);
        assert!(
            is_error_indication_to(&out, intruder, CauseRadioNetwork::UnknownPairUeS1apId),
            "{out:?}"
        );
        let target = ctx.enb_ue_find_by_id(target_ue_id).unwrap();
        assert_eq!(target.enb_ue_s1ap_id, INVALID_UE_S1AP_ID, "not overwritten");
        assert!(target.handover_prep_deadline.is_some());
        // The real target is accepted (it gets past the validation and writes
        // its eNB UE S1AP ID).
        handle_handover_request_acknowledge(&ctx, target_enb, &ack);
        assert_eq!(
            ctx.enb_ue_find_by_id(target_ue_id).unwrap().enb_ue_s1ap_id,
            0x731
        );
    }

    /// #731 scenario 2: after an X2 handover the context lives on eNB B under
    /// the same MME UE S1AP ID. A stale ERROR INDICATION or partial RESET from
    /// the old eNB A, carrying the old pair, must not release it.
    #[test]
    fn a_stale_error_indication_or_partial_reset_from_the_x2_source_releases_nothing() {
        let ctx = test_ctx();
        let (enb_a, enb_ue_id, mme_ue_id, mme_ue_s1ap_id) = add_ue(&ctx);
        let enb_b = ctx.enb_add("127.0.0.1:36496".parse().unwrap());
        // The Path Switch re-anchored the context on B.
        {
            let mut pool = ctx.enb_ue_pool.write().unwrap();
            let ue = pool.get_mut(&enb_ue_id).unwrap();
            ue.enb_id = enb_b;
            ue.enb_ue_s1ap_id = 200;
        }
        handle_error_indication(
            &ctx,
            enb_a,
            &ErrorIndication {
                mme_ue_s1ap_id: Some(mme_ue_s1ap_id),
                enb_ue_s1ap_id: Some(100),
                cause: Some(Cause::RadioNetwork(CauseRadioNetwork::UnknownMmeUeS1apId)),
                criticality_diagnostics: None,
            },
        );
        assert!(
            ctx.enb_ue_find_by_id(enb_ue_id).is_some(),
            "Error Indication"
        );
        // The eNB UE S1AP ID is optional (criticality ignore): with the MME UE
        // S1AP ID alone, the sending eNB decides.
        handle_error_indication(
            &ctx,
            enb_a,
            &ErrorIndication {
                mme_ue_s1ap_id: Some(mme_ue_s1ap_id),
                enb_ue_s1ap_id: None,
                cause: Some(Cause::RadioNetwork(CauseRadioNetwork::UnknownMmeUeS1apId)),
                criticality_diagnostics: None,
            },
        );
        assert!(
            ctx.enb_ue_find_by_id(enb_ue_id).is_some(),
            "Error Indication without an eNB UE S1AP ID"
        );
        handle_reset(
            &ctx,
            enb_a,
            &Reset {
                cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
                reset_type: ResetType::PartOfS1Interface(vec![UeAssociatedLogicalS1Connection {
                    mme_ue_s1ap_id: Some(mme_ue_s1ap_id),
                    enb_ue_s1ap_id: Some(100),
                }]),
            },
        );
        assert!(ctx.enb_ue_find_by_id(enb_ue_id).is_some(), "partial Reset");
        assert_eq!(
            ctx.mme_ue_find_by_id(mme_ue_id).unwrap().enb_ue_id,
            enb_ue_id
        );
        // From B, with B's pair, the same Error Indication does release it.
        handle_error_indication(
            &ctx,
            enb_b,
            &ErrorIndication {
                mme_ue_s1ap_id: Some(mme_ue_s1ap_id),
                enb_ue_s1ap_id: Some(200),
                cause: Some(Cause::RadioNetwork(CauseRadioNetwork::UnknownMmeUeS1apId)),
                criticality_diagnostics: None,
            },
        );
        assert!(
            ctx.enb_ue_find_by_id(enb_ue_id).is_none(),
            "the real eNB's indication acts"
        );
    }

    /// #731: source-side messages (HANDOVER CANCEL, eNB STATUS TRANSFER,
    /// HANDOVER REQUIRED) and UE CONTEXT RELEASE REQUEST with a pair this eNB
    /// does not hold get ERROR INDICATION and change nothing.
    #[test]
    fn source_side_messages_with_a_foreign_pair_are_refused() {
        let ctx = test_ctx();
        let (enb_id, enb_ue_id, _mme_ue_id, mme_ue_s1ap_id) = add_ue(&ctx);
        let intruder = ctx.enb_add("127.0.0.1:36495".parse().unwrap());
        let pair_cause = CauseRadioNetwork::UnknownPairUeS1apId;

        let cancel = HandoverCancel {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: 100,
            cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
        };
        let out = handle_handover_cancel(&ctx, intruder, &cancel);
        assert!(
            is_error_indication_to(&out, intruder, pair_cause),
            "cancel {out:?}"
        );

        let transfer = EnbStatusTransfer {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: 100,
            status_transfer_container: vec![0],
        };
        let out = handle_enb_status_transfer(&ctx, intruder, &transfer);
        assert!(
            is_error_indication_to(&out, intruder, pair_cause),
            "status {out:?}"
        );

        // UE CONTEXT RELEASE REQUEST and ICS FAILURE from another eNB.
        let release = UeContextReleaseRequest {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: 100,
            cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
        };
        let out = handle_ue_context_release_request(&ctx, intruder, &release);
        assert!(
            is_error_indication_to(&out, intruder, CauseRadioNetwork::UnknownMmeUeS1apId),
            "release request {out:?}"
        );
        let failure = InitialContextSetupFailure {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: 100,
            cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
        };
        let out = handle_initial_context_setup_failure(&ctx, intruder, &failure);
        assert!(
            is_error_indication_to(&out, intruder, CauseRadioNetwork::UnknownMmeUeS1apId),
            "ICS failure {out:?}"
        );
        let ue = ctx.enb_ue_find_by_id(enb_ue_id).unwrap();
        assert_eq!(ue.ue_ctx_rel_action, UeCtxRelAction::default(), "untouched");

        // HANDOVER REQUIRED from another eNB (or with the wrong eNB UE S1AP ID
        // on the right one): ERROR INDICATION, no preparation started.
        for (from, enb_ue_s1ap_id) in [(intruder, 100), (enb_id, 999)] {
            let required = HandoverRequired {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id,
                handover_type: nextgcore_s1ap::HandoverType::IntraLte,
                cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
                target_id: TargetId::TargetEnbId {
                    global_enb_id: GlobalEnbId {
                        plmn_identity: [0x13, 0x00, 0x14],
                        enb_id: nextgcore_s1ap::EnbId::Macro(0x731),
                    },
                    selected_tai: nextgcore_s1ap::Tai {
                        plmn_identity: [0x13, 0x00, 0x14],
                        tac: 1,
                    },
                },
                direct_forwarding_path_availability: None,
                source_to_target_container: vec![0],
            };
            let out = handle_handover_required(&ctx, from, &required);
            assert!(
                is_error_indication_to(&out, from, pair_cause),
                "handover required from {from}: {out:?}"
            );
            assert_eq!(
                ctx.enb_ue_find_by_id(enb_ue_id).unwrap().target_ue_id,
                NEXTGCORE_INVALID_POOL_ID,
                "no preparation"
            );
        }

        // UE CONTEXT RELEASE COMPLETE from another eNB removes nothing.
        handle_ue_context_release_complete(
            &ctx,
            intruder,
            &UeContextReleaseComplete {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id: 100,
            },
        );
        assert!(
            ctx.enb_ue_find_by_id(enb_ue_id).is_some(),
            "release complete"
        );
    }

    /// #847 review MAJOR, TS 36.413 §10.6: an inconsistent pair on the SAME
    /// S1 interface releases the connections carrying either ID locally (and a
    /// non-last message gets ERROR INDICATION), so the MME does not keep an
    /// ECM-CONNECTED UE on a connection the eNB has released.
    #[test]
    fn an_inconsistent_pair_on_the_same_enb_releases_locally() {
        let ctx = test_ctx();
        let (enb_id, enb_ue_id, mme_ue_id, mme_ue_s1ap_id) = add_ue(&ctx);
        let out = handle_ue_context_release_request(
            &ctx,
            enb_id,
            &UeContextReleaseRequest {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id: 999,
                cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
            },
        );
        assert!(
            is_error_indication_to(&out, enb_id, CauseRadioNetwork::UnknownPairUeS1apId),
            "{out:?}"
        );
        assert!(
            ctx.enb_ue_find_by_id(enb_ue_id).is_none(),
            "released locally"
        );
        assert_ne!(
            ctx.mme_ue_find_by_id(mme_ue_id).unwrap().enb_ue_id,
            enb_ue_id
        );

        // ICS FAILURE likewise.
        let ctx = test_ctx();
        let (enb_id, enb_ue_id, _, mme_ue_s1ap_id) = add_ue(&ctx);
        let out = handle_initial_context_setup_failure(
            &ctx,
            enb_id,
            &InitialContextSetupFailure {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id: 999,
                cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
            },
        );
        assert!(is_error_indication_to(
            &out,
            enb_id,
            CauseRadioNetwork::UnknownPairUeS1apId
        ));
        assert!(ctx.enb_ue_find_by_id(enb_ue_id).is_none());
    }

    /// #847 review MAJOR, §8.7.1.2.1: a partial RESET item names its connection
    /// by the MME UE S1AP ID and/or the eNB UE S1AP ID. An item with only the
    /// eNB UE S1AP ID, or with an inconsistent pair, resets the connections of
    /// this eNB carrying either ID; ERROR INDICATION with only the eNB UE S1AP
    /// ID releases that connection (§10.6).
    #[test]
    fn a_partial_reset_and_an_error_indication_match_either_id() {
        let ctx = test_ctx();
        let (enb_id, enb_ue_id, _, _) = add_ue(&ctx);
        handle_reset(
            &ctx,
            enb_id,
            &Reset {
                cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
                reset_type: ResetType::PartOfS1Interface(vec![UeAssociatedLogicalS1Connection {
                    mme_ue_s1ap_id: None,
                    enb_ue_s1ap_id: Some(100),
                }]),
            },
        );
        assert!(
            ctx.enb_ue_find_by_id(enb_ue_id).is_none(),
            "eNB UE S1AP ID only"
        );

        let ctx = test_ctx();
        let (enb_id, enb_ue_id, _, mme_ue_s1ap_id) = add_ue(&ctx);
        handle_reset(
            &ctx,
            enb_id,
            &Reset {
                cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
                reset_type: ResetType::PartOfS1Interface(vec![UeAssociatedLogicalS1Connection {
                    mme_ue_s1ap_id: Some(mme_ue_s1ap_id),
                    enb_ue_s1ap_id: Some(999),
                }]),
            },
        );
        assert!(
            ctx.enb_ue_find_by_id(enb_ue_id).is_none(),
            "inconsistent pair"
        );

        let ctx = test_ctx();
        let (enb_id, enb_ue_id, _, _) = add_ue(&ctx);
        handle_error_indication(
            &ctx,
            enb_id,
            &ErrorIndication {
                mme_ue_s1ap_id: None,
                enb_ue_s1ap_id: Some(100),
                cause: Some(Cause::RadioNetwork(CauseRadioNetwork::UnknownMmeUeS1apId)),
                criticality_diagnostics: None,
            },
        );
        assert!(
            ctx.enb_ue_find_by_id(enb_ue_id).is_none(),
            "Error Indication with only the eNB UE S1AP ID"
        );
    }

    /// #847 review MINOR 1-2: HANDOVER REQUIRED towards 5GS with the right
    /// MME UE S1AP ID but another eNB UE S1AP ID gets HANDOVER PREPARATION
    /// FAILURE with unknown-pair-ue-s1ap-id, and nothing is prepared.
    #[test]
    fn a_handover_to_5gs_with_a_foreign_pair_is_refused_unknown_pair() {
        use nextgcore_s1ap_gen::generated as g;
        let _guard = crate::gtp_path::lock_s11();
        crate::n26_path::set_for_test(true);
        let ctx = test_ctx();
        let (enb_id, _, mme_ue_id, mme_ue_s1ap_id) = add_ue(&ctx);
        let msg = crate::s1ap_gen::HandoverRequiredTo5gs {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: 999,
            handover_type: S1apHandoverType::EpsTo5gs,
            cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
            target: crate::n26_build::GnbTarget {
                plmn: [0x13, 0x00, 0x14],
                gnb_id: 1,
                gnb_id_len: 24,
                tac: [0, 0, 1],
            },
            direct_forwarding: false,
            source_to_target_container: vec![0],
        };
        let out = handle_handover_required_to_5gs(&ctx, enb_id, &msg, &[]);
        crate::n26_path::set_for_test(false);
        assert_eq!(out.len(), 1);
        let cause = match nextgcore_s1ap_gen::decode(&out[0].pdu) {
            Ok(g::S1AP_PDU::UnsuccessfulOutcome(g::UnsuccessfulOutcome {
                value: g::UnsuccessfulOutcomeValue::Id_HandoverPreparation(f),
                ..
            })) => f.protocol_i_es.0.into_iter().find_map(|ie| match ie.value {
                g::HandoverPreparationFailureProtocolIEs_EntryValue::Id_Cause(c) => Some(c),
                _ => None,
            }),
            _ => None,
        };
        assert!(
            matches!(&cause, Some(g::Cause::RadioNetwork(r)) if r.0 == CauseRadioNetwork::UnknownPairUeS1apId as u8),
            "{cause:?}"
        );
        assert!(crate::n26_path::eps_to_5gs_relocation(mme_ue_id).is_none());
    }

    /// Two connections of one eNB sharing eNB UE S1AP ID 100 (a reused ID
    /// while the stale one is still held): (enb, stale, live, live MME UE S1AP ID).
    fn reused_enb_ue_id(ctx: &MmeContext) -> (u64, u64, u64, u32, u32) {
        let (enb_id, stale, _, stale_mme) = add_ue(ctx);
        let live = ctx.enb_ue_add(enb_id, 100);
        let live_mme = ctx.enb_ue_find_by_id(live).unwrap().mme_ue_s1ap_id;
        (enb_id, stale, live, stale_mme, live_mme)
    }

    /// #846 follow-up 1: with two connections holding the reused eNB UE S1AP
    /// ID, a Release Request with the LIVE connection's pair is consistent on
    /// every run (consistency comes from the MME UE S1AP ID's own entry, not
    /// from which holder a map kept); an inconsistent one releases every holder.
    #[test]
    fn a_reused_enb_ue_id_does_not_make_the_pair_check_random() {
        for _ in 0..40 {
            let ctx = test_ctx();
            let (enb_id, stale, live, _, live_mme) = reused_enb_ue_id(&ctx);
            let out = handle_ue_context_release_request(
                &ctx,
                enb_id,
                &UeContextReleaseRequest {
                    mme_ue_s1ap_id: live_mme,
                    enb_ue_s1ap_id: 100,
                    cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
                },
            );
            assert!(
                !is_error_indication_to(&out, enb_id, CauseRadioNetwork::UnknownPairUeS1apId),
                "the live pair is consistent: {out:?}"
            );
            assert_eq!(
                ctx.enb_ue_find_by_id(live).unwrap().ue_ctx_rel_action,
                UeCtxRelAction::S1ContextRemove
            );
            assert!(ctx.enb_ue_find_by_id(stale).is_some());
        }
        // Inconsistent: (an MME UE S1AP ID of nobody here, the reused ID).
        let ctx = test_ctx();
        let (enb_id, stale, live, _, _) = reused_enb_ue_id(&ctx);
        let out = handle_ue_context_release_request(
            &ctx,
            enb_id,
            &UeContextReleaseRequest {
                mme_ue_s1ap_id: 0x846,
                enb_ue_s1ap_id: 100,
                cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
            },
        );
        assert!(is_error_indication_to(
            &out,
            enb_id,
            CauseRadioNetwork::UnknownPairUeS1apId
        ));
        assert!(
            ctx.enb_ue_find_by_id(stale).is_none(),
            "every holder released"
        );
        assert!(
            ctx.enb_ue_find_by_id(live).is_none(),
            "every holder released"
        );
    }

    /// #846 follow-up 1, TS 36.413 §10.6 (first message): an INITIAL UE
    /// MESSAGE reusing an eNB UE S1AP ID this MME still holds gets ERROR
    /// INDICATION with only that ID, the stale connection is released locally,
    /// and the message is not processed.
    #[test]
    fn an_initial_ue_message_reusing_a_held_enb_ue_id_releases_the_stale_one() {
        use nextgcore_s1ap_gen::generated as g;
        let _guard = crate::gtp_path::lock_s11();
        let ctx = test_ctx();
        let (enb_id, stale, _, _) = add_ue(&ctx);
        crate::s1ap_path::tap_enb_for_test(enb_id);
        let _ = crate::s1ap_path::take_tapped_for_test(enb_id);
        let msg = InitialUeMessage {
            enb_ue_s1ap_id: 100,
            nas_pdu: vec![0x07, 0x41, 0x71],
            tai: nextgcore_s1ap::Tai {
                plmn_identity: [0x13, 0x00, 0x14],
                tac: 1,
            },
            eutran_cgi: nextgcore_s1ap::EutranCgi {
                plmn_identity: [0x13, 0x00, 0x14],
                cell_identity: 0x100,
            },
            rrc_establishment_cause: nextgcore_s1ap::RrcEstablishmentCause::MoSignalling,
            s_tmsi: None,
        };
        let pool_before = ctx.enb_ue_pool.read().unwrap().len();
        assert!(handle_initial_ue_message(&ctx, enb_id, &msg).is_none());
        assert!(
            ctx.enb_ue_find_by_id(stale).is_none(),
            "the stale one is released"
        );
        assert_eq!(
            ctx.enb_ue_pool.read().unwrap().len(),
            pool_before - 1,
            "none created"
        );
        let ei = crate::s1ap_path::take_tapped_for_test(enb_id)
            .into_iter()
            .find_map(|pdu| match nextgcore_s1ap_gen::decode(&pdu) {
                Ok(g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
                    value: g::InitiatingMessageValue::Id_ErrorIndication(e),
                    ..
                })) => Some(e),
                _ => None,
            })
            .expect("ERROR INDICATION");
        let ids: Vec<u16> = ei.protocol_i_es.0.iter().map(|ie| ie.id.0).collect();
        assert!(ids.contains(&8), "eNB UE S1AP ID present");
        assert!(
            !ids.contains(&0),
            "only the previously received AP ID (no MME UE S1AP ID)"
        );
        // The eNB, now released too, can bring the UE back under that ID.
        assert!(handle_initial_ue_message(&ctx, enb_id, &msg).is_some());
    }

    /// #846 follow-up 2: UE CONTEXT RELEASE COMPLETE (the last message) with an
    /// inconsistent pair releases the connections carrying either ID, without
    /// an ERROR INDICATION.
    #[test]
    fn a_release_complete_with_an_inconsistent_pair_releases_locally() {
        let ctx = test_ctx();
        let (enb_id, enb_ue_id, _, mme_ue_s1ap_id) = add_ue(&ctx);
        handle_ue_context_release_complete(
            &ctx,
            enb_id,
            &UeContextReleaseComplete {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id: 999,
            },
        );
        assert!(ctx.enb_ue_find_by_id(enb_ue_id).is_none());
    }

    /// #846: UPLINK NAS TRANSPORT, UE CAPABILITY INFO INDICATION and INITIAL
    /// CONTEXT SETUP RESPONSE from an eNB the UE is not on change nothing and get
    /// ERROR INDICATION. Before #846 the NAS PDU was processed (after a log
    /// line), the capability overwritten and the S1-U endpoints written.
    #[test]
    fn data_messages_from_another_enb_change_nothing() {
        let _guard = crate::gtp_path::lock_s11();
        let ctx = test_ctx();
        let (_, enb_ue_id, mme_ue_id, mme_ue_s1ap_id) = add_ue(&ctx);
        let intruder = ctx.enb_add("127.0.0.1:36846".parse().unwrap());
        let out = handle_uplink_nas(
            &ctx,
            intruder,
            &crate::s1ap_gen::UplinkNas {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id: 100,
                nas_pdu: vec![0x07, 0x45],
                eutran_cgi: None,
                tai: None,
            },
        );
        assert!(
            matches!(out, Err(ref e) if is_error_indication_to(e, intruder, CauseRadioNetwork::UnknownMmeUeS1apId)),
            "{out:?}"
        );

        crate::s1ap_path::tap_enb_for_test(intruder);
        handle_ue_capability_info_indication(
            &ctx,
            intruder,
            &UeCapabilityInfoIndication {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id: 100,
                ue_radio_capability: vec![0xaa; 4],
            },
        );
        assert!(ctx
            .mme_ue_find_by_id(mme_ue_id)
            .unwrap()
            .ue_radio_capability
            .is_empty());
        let sid = ctx.sess_add(mme_ue_id, 1);
        let bid = ctx.bearer_add(sid, mme_ue_id);
        ctx.bearer_pool.write().unwrap().get_mut(&bid).unwrap().ebi = 5;
        handle_initial_context_setup_response(
            &ctx,
            intruder,
            &InitialContextSetupResponse {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id: 100,
                erab_setup_list: vec![nextgcore_s1ap::ErabSetupItem {
                    erab_id: 5,
                    transport_layer_address: vec![10, 0, 0, 66],
                    gtp_teid: 0x846,
                }],
                erab_failed_list: vec![],
            },
        );
        assert_eq!(ctx.bearer_find_by_id(bid).unwrap().enb_s1u_teid, 0);

        // #880 review: E-RAB SETUP RESPONSE from the other eNB writes none of its
        // S1-U endpoints onto this UE's bearers.
        handle_erab_setup_response(
            &ctx,
            intruder,
            mme_ue_s1ap_id,
            100,
            &[nextgcore_s1ap::ErabSetupItem {
                erab_id: 5,
                transport_layer_address: vec![10, 0, 0, 67],
                gtp_teid: 0x847,
            }],
        );
        assert_eq!(
            ctx.bearer_find_by_id(bid).unwrap().enb_s1u_teid,
            0,
            "E-RAB SETUP RESPONSE"
        );

        // #880 review: NAS NON DELIVERY INDICATION from the other eNB leaves
        // this UE's paging state alone.
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&mme_ue_id)
            .unwrap()
            .paging
            .type_ = PagingType::DownlinkDataNotification;
        handle_nas_non_delivery_indication(
            &ctx,
            intruder,
            &NasNonDeliveryIndication {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id: 100,
                nas_pdu: vec![0x07],
                cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
            },
        );
        assert!(
            !ctx.mme_ue_find_by_id(mme_ue_id).unwrap().paging.failed,
            "NAS NON DELIVERY INDICATION"
        );

        let eis = crate::s1ap_path::take_tapped_for_test(intruder).len();
        assert_eq!(eis, 4, "an ERROR INDICATION for each");
        assert!(
            ctx.enb_ue_find_by_id(enb_ue_id).is_some(),
            "the real one stays"
        );
    }

    fn ctx_with_gummei() -> MmeContext {
        let mut ctx = test_ctx();
        ctx.mme_name = Some("test-mme".to_string());
        ctx.served_gummei = vec![ServedGummei {
            num_of_plmn_id: 1,
            plmn_id: vec![PlmnId::new("310", "410")],
            num_of_mme_gid: 1,
            mme_gid: vec![2],
            num_of_mme_code: 1,
            mme_code: vec![1],
        }];
        ctx.num_of_served_gummei = 1;
        ctx
    }

    /// Register a UE with an attached eNB UE context; returns
    /// (enb pool id, enb_ue pool id, mme_ue pool id, mme_ue_s1ap_id).
    fn add_ue(ctx: &MmeContext) -> (u64, u64, u64, u32) {
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        let enb_ue_id = ctx.enb_ue_add(enb_id, 100);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
        let mme_ue_s1ap_id = ctx.enb_ue_find_by_id(enb_ue_id).unwrap().mme_ue_s1ap_id;
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let mme_ue: &mut MmeUe = pool.get_mut(&mme_ue_id).unwrap();
            mme_ue.imsi_bcd = "001010123456789".to_string();
            mme_ue.kasme = [0x11; 32];
            mme_ue.kenb = [0x22; 32];
            mme_ue.ambr = Bitrate {
                downlink: 1_000_000,
                uplink: 500_000,
            };
            mme_ue.ue_network_capability.eea = 0x70;
            mme_ue.ue_network_capability.eia = 0x70;
        }
        (enb_id, enb_ue_id, mme_ue_id, mme_ue_s1ap_id)
    }

    #[test]
    fn test_s1_setup_succeeds_on_the_shipped_configuration() {
        // Configuration alone must be enough for an eNB to associate. Before
        // #157 mmed parsed no config, so `served_gummei` was empty and this
        // request was answered with S1 Setup Failure in every deployment.
        let mut ctx = MmeContext::new();
        assert!(crate::config::load_config(
            &mut ctx,
            "../../../docker/rust/configs/epc/mme.yaml"
        ));
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());

        // An eNB broadcasting the PLMN and TAC the shipped file declares.
        let plmn = PlmnId::new("999", "70");
        let request = S1SetupRequest {
            global_enb_id: GlobalEnbId {
                plmn_identity: s1ap_build::encode_plmn_id(&plmn),
                enb_id: nextgcore_s1ap::EnbId::Macro(0x1234),
            },
            enb_name: Some("configured-enb".to_string()),
            supported_tas: vec![SupportedTaItem {
                tac: 1,
                broadcast_plmns: vec![s1ap_build::encode_plmn_id(&plmn)],
            }],
            default_paging_drx: nextgcore_s1ap::PagingDrx::V64,
        };

        let out = handle_s1ap_message(
            &ctx,
            enb_id,
            &builder::build_s1_setup_request(&request).unwrap(),
        );

        assert_eq!(out.len(), 1);
        match decode_s1ap_pdu(&out[0].pdu).unwrap() {
            S1apMessage::S1SetupResponse(rsp) => {
                assert_eq!(rsp.relative_mme_capacity, ctx.relative_capacity);
                assert!(
                    !rsp.served_gummeis.is_empty(),
                    "the response must carry the configured GUMMEI"
                );
            }
            other => panic!("expected S1SetupResponse, got {other:?}"),
        }
        assert!(ctx.enb_find_by_id(enb_id).unwrap().state.s1_setup_success);
        assert_eq!(
            ctx.enb_find_by_id(enb_id).unwrap().enb_id_bits,
            20,
            "#741: a macro eNB's id is recorded as 20 bits"
        );

        // #741: a home eNB's id is recorded as 28 bits, so an N26 target lookup by a
        // macro id of equal value cannot land on it.
        let home_enb = ctx.enb_add("127.0.0.3:36412".parse().unwrap());
        let home = S1SetupRequest {
            global_enb_id: GlobalEnbId {
                plmn_identity: s1ap_build::encode_plmn_id(&plmn),
                enb_id: nextgcore_s1ap::EnbId::Home(0x1234),
            },
            ..request.clone()
        };
        handle_s1ap_message(
            &ctx,
            home_enb,
            &builder::build_s1_setup_request(&home).unwrap(),
        );
        assert_eq!(ctx.enb_find_by_id(home_enb).unwrap().enb_id_bits, 28);

        // An eNB in a tracking area the file does not declare is still rejected.
        let other_enb = ctx.enb_add("127.0.0.2:36412".parse().unwrap());
        let elsewhere = S1SetupRequest {
            supported_tas: vec![SupportedTaItem {
                tac: 999,
                broadcast_plmns: vec![s1ap_build::encode_plmn_id(&PlmnId::new("310", "410"))],
            }],
            ..request
        };
        let out = handle_s1ap_message(
            &ctx,
            other_enb,
            &builder::build_s1_setup_request(&elsewhere).unwrap(),
        );
        assert_eq!(out.len(), 1);
        assert!(matches!(
            decode_s1ap_pdu(&out[0].pdu).unwrap(),
            S1apMessage::S1SetupFailure(_)
        ));
    }

    #[test]
    fn test_s1_setup_request_accept_and_reject() {
        let ctx = ctx_with_gummei();
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());

        let request = S1SetupRequest {
            global_enb_id: GlobalEnbId {
                plmn_identity: s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
                enb_id: nextgcore_s1ap::EnbId::Macro(0x1234),
            },
            enb_name: Some("test-enb".to_string()),
            supported_tas: vec![SupportedTaItem {
                tac: 1,
                broadcast_plmns: vec![s1ap_build::encode_plmn_id(&PlmnId::new("310", "410"))],
            }],
            default_paging_drx: nextgcore_s1ap::PagingDrx::V64,
        };
        let bytes = builder::build_s1_setup_request(&request).unwrap();

        let out = handle_s1ap_message(&ctx, enb_id, &bytes);
        assert_eq!(out.len(), 1);
        match decode_s1ap_pdu(&out[0].pdu).unwrap() {
            S1apMessage::S1SetupResponse(rsp) => {
                assert_eq!(rsp.relative_mme_capacity, ctx.relative_capacity);
            }
            other => panic!("expected S1SetupResponse, got {other:?}"),
        }
        let enb = ctx.enb_find_by_id(enb_id).unwrap();
        assert!(enb.state.s1_setup_success);
        assert_eq!(enb.enb_id, 0x1234);
        assert_eq!(enb.supported_ta_list.len(), 1);

        // Without a served GUMMEI the MME must reject with S1 Setup Failure
        let bare_ctx = test_ctx();
        let bare_enb = bare_ctx.enb_add("127.0.0.2:36412".parse().unwrap());
        let out = handle_s1ap_message(&bare_ctx, bare_enb, &bytes);
        assert_eq!(out.len(), 1);
        match decode_s1ap_pdu(&out[0].pdu).unwrap() {
            S1apMessage::S1SetupFailure(failure) => {
                assert_eq!(failure.time_to_wait, Some(TimeToWait::V10s));
            }
            other => panic!("expected S1SetupFailure, got {other:?}"),
        }
    }

    #[test]
    fn test_reset_s1_interface_clears_ue_contexts_and_acks() {
        let ctx = ctx_with_gummei();
        let (enb_id, enb_ue_id, mme_ue_id, _) = add_ue(&ctx);

        let bytes = builder::build_reset(&Reset {
            cause: Cause::Misc(nextgcore_s1ap::CauseMisc::OmIntervention),
            reset_type: ResetType::S1Interface,
        })
        .unwrap();

        let out = handle_s1ap_message(&ctx, enb_id, &bytes);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].enb_id, enb_id);
        match decode_s1ap_pdu(&out[0].pdu).unwrap() {
            S1apMessage::ResetAcknowledge(ack) => {
                assert!(ack.ue_associated_connections.is_empty());
            }
            other => panic!("expected ResetAcknowledge, got {other:?}"),
        }

        // The S1 connection is gone; the MME UE survives (idle)
        assert!(ctx.enb_ue_find_by_id(enb_ue_id).is_none());
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(mme_ue.enb_ue_id, NEXTGCORE_INVALID_POOL_ID);
    }

    #[test]
    fn test_reset_partial_echoes_connection_list() {
        let ctx = ctx_with_gummei();
        let (enb_id, enb_ue_id, _, mme_ue_s1ap_id) = add_ue(&ctx);

        let connections = vec![
            UeAssociatedLogicalS1Connection {
                mme_ue_s1ap_id: Some(mme_ue_s1ap_id),
                enb_ue_s1ap_id: Some(100),
            },
            // Unknown connection: still echoed in the Ack per §8.7.1.2.2
            UeAssociatedLogicalS1Connection {
                mme_ue_s1ap_id: Some(0xDEAD),
                enb_ue_s1ap_id: None,
            },
        ];
        let bytes = builder::build_reset(&Reset {
            cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
            reset_type: ResetType::PartOfS1Interface(connections.clone()),
        })
        .unwrap();

        let out = handle_s1ap_message(&ctx, enb_id, &bytes);
        assert_eq!(out.len(), 1);
        match decode_s1ap_pdu(&out[0].pdu).unwrap() {
            S1apMessage::ResetAcknowledge(ack) => {
                assert_eq!(ack.ue_associated_connections, connections);
            }
            other => panic!("expected ResetAcknowledge, got {other:?}"),
        }
        assert!(ctx.enb_ue_find_by_id(enb_ue_id).is_none());
    }

    #[test]
    fn test_ue_capability_info_indication_stores_capability() {
        let ctx = ctx_with_gummei();
        let (enb_id, _, mme_ue_id, mme_ue_s1ap_id) = add_ue(&ctx);

        let capability = vec![0x01, 0x02, 0x03, 0x04];
        let bytes = builder::build_ue_capability_info_indication(&UeCapabilityInfoIndication {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: 100,
            ue_radio_capability: capability.clone(),
        })
        .unwrap();

        let out = handle_s1ap_message(&ctx, enb_id, &bytes);
        assert!(out.is_empty());
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(mme_ue.ue_radio_capability, capability);
    }

    #[test]
    fn test_nas_non_delivery_indication_marks_paging_failed() {
        let ctx = ctx_with_gummei();
        let (enb_id, _, mme_ue_id, mme_ue_s1ap_id) = add_ue(&ctx);
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            pool.get_mut(&mme_ue_id).unwrap().paging.type_ = PagingType::DownlinkDataNotification;
        }

        let bytes = builder::build_nas_non_delivery_indication(&NasNonDeliveryIndication {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: 100,
            nas_pdu: vec![0x07, 0x55],
            cause: Cause::RadioNetwork(CauseRadioNetwork::RadioConnectionWithUeLost),
        })
        .unwrap();

        let out = handle_s1ap_message(&ctx, enb_id, &bytes);
        assert!(out.is_empty());
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(mme_ue.paging.failed);
    }

    // The acknowledged Path Switch is in `handover_switch`'s tests (#730): it
    // waits for the Serving GW, so it needs the global context and a real S11
    // socket.

    #[test]
    fn test_path_switch_request_unknown_ue_fails() {
        let ctx = ctx_with_gummei();
        let enb_id = ctx.enb_add("127.0.0.9:36412".parse().unwrap());

        let psr = PathSwitchRequest {
            enb_ue_s1ap_id: 200,
            erab_switched_dl_list: vec![ErabSwitchedItem {
                erab_id: 5,
                transport_layer_address: vec![10, 0, 0, 9],
                gtp_teid: 0x9999,
            }],
            source_mme_ue_s1ap_id: 0xBEEF,
            eutran_cgi: nextgcore_s1ap::EutranCgi {
                plmn_identity: [0x13, 0x00, 0x14],
                cell_identity: 1,
            },
            tai: nextgcore_s1ap::Tai {
                plmn_identity: [0x13, 0x00, 0x14],
                tac: 1,
            },
            ue_security_capabilities: UeSecurityCapabilities {
                encryption_algorithms: 0,
                integrity_algorithms: 0,
            },
        };
        let bytes = builder::build_path_switch_request(&psr).unwrap();

        let out = handle_s1ap_message(&ctx, enb_id, &bytes);
        assert_eq!(out.len(), 1);
        match decode_s1ap_pdu(&out[0].pdu).unwrap() {
            S1apMessage::PathSwitchRequestFailure(failure) => {
                assert_eq!(
                    failure.cause,
                    Cause::RadioNetwork(CauseRadioNetwork::UnknownMmeUeS1apId)
                );
            }
            other => panic!("expected PathSwitchRequestFailure, got {other:?}"),
        }
    }

    #[test]
    fn test_handover_required_builds_handover_request_to_target() {
        let ctx = ctx_with_gummei();
        let (source_enb_id, _, mme_ue_id, mme_ue_s1ap_id) = add_ue(&ctx);
        let bearer_id = ctx.bearer_add(0, mme_ue_id);
        {
            let mut pool = ctx.bearer_pool.write().unwrap();
            let bearer = pool.get_mut(&bearer_id).unwrap();
            bearer.ebi = 5;
            bearer.sgw_s1u_teid = 0x5555;
            bearer.sgw_s1u_ip.ipv4 = Some([10, 0, 0, 2]);
            bearer.qos.qci = 9;
            bearer.qos.arp.priority_level = 8;
        }

        // Target eNB registered with eNB ID 0x2222
        let target_enb_id = ctx.enb_add("127.0.0.8:36412".parse().unwrap());
        ctx.enb_set_s1_connected_for_test(
            target_enb_id,
            &s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
            nextgcore_s1ap::EnbId::Macro(0x2222),
        );
        // #882: a home eNB and an eNB of another PLMN with the same id value, set up
        // AFTER the target, so a lookup by value alone (the old `enb_id_hash`) finds one
        // of them instead.
        let home_twin = ctx.enb_add("127.0.0.9:36412".parse().unwrap());
        ctx.enb_set_s1_connected_for_test(
            home_twin,
            &s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
            nextgcore_s1ap::EnbId::Home(0x2222),
        );
        let plmn_twin = ctx.enb_add("127.0.0.10:36412".parse().unwrap());
        ctx.enb_set_s1_connected_for_test(
            plmn_twin,
            &s1ap_build::encode_plmn_id(&PlmnId::new("001", "01")),
            nextgcore_s1ap::EnbId::Macro(0x2222),
        );

        let ho = HandoverRequired {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: 100,
            handover_type: S1apHandoverType::IntraLte,
            cause: Cause::RadioNetwork(CauseRadioNetwork::HandoverDesirableForRadioReason),
            target_id: TargetId::TargetEnbId {
                global_enb_id: GlobalEnbId {
                    plmn_identity: s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
                    enb_id: nextgcore_s1ap::EnbId::Macro(0x2222),
                },
                selected_tai: nextgcore_s1ap::Tai {
                    plmn_identity: s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
                    tac: 2,
                },
            },
            // #48: ABSENT, which means no direct path and therefore INDIRECT
            // forwarding -- the behaviour these tests were written against.
            direct_forwarding_path_availability: None,
            source_to_target_container: vec![0xDE, 0xAD],
        };
        let bytes = builder::build_handover_required(&ho).unwrap();

        let out = handle_s1ap_message(&ctx, source_enb_id, &bytes);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].enb_id, target_enb_id);
        match decode_s1ap_pdu(&out[0].pdu).unwrap() {
            S1apMessage::HandoverRequest(req) => {
                assert_eq!(req.handover_type, S1apHandoverType::IntraLte);
                assert_eq!(req.erab_list.len(), 1);
                assert_eq!(req.erab_list[0].erab_id, 5);
                assert_eq!(req.erab_list[0].gtp_teid, 0x5555);
                assert_eq!(req.source_to_target_container, vec![0xDE, 0xAD]);
                assert_eq!(req.security_context.next_hop_chaining_count, 1);
            }
            other => panic!("expected HandoverRequest, got {other:?}"),
        }
    }

    #[test]
    fn test_handover_required_unknown_target_fails() {
        let ctx = ctx_with_gummei();
        let (source_enb_id, _, _, mme_ue_s1ap_id) = add_ue(&ctx);

        let ho = HandoverRequired {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: 100,
            handover_type: S1apHandoverType::IntraLte,
            cause: Cause::RadioNetwork(CauseRadioNetwork::HandoverDesirableForRadioReason),
            target_id: TargetId::TargetEnbId {
                global_enb_id: GlobalEnbId {
                    plmn_identity: [0x13, 0x00, 0x14],
                    enb_id: nextgcore_s1ap::EnbId::Macro(0x7777),
                },
                selected_tai: nextgcore_s1ap::Tai {
                    plmn_identity: [0x13, 0x00, 0x14],
                    tac: 2,
                },
            },
            // #48: ABSENT, which means no direct path and therefore INDIRECT
            // forwarding -- the behaviour these tests were written against.
            direct_forwarding_path_availability: None,
            source_to_target_container: vec![0x01],
        };
        let bytes = builder::build_handover_required(&ho).unwrap();

        let out = handle_s1ap_message(&ctx, source_enb_id, &bytes);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].enb_id, source_enb_id);
        match decode_s1ap_pdu(&out[0].pdu).unwrap() {
            S1apMessage::HandoverPreparationFailure(failure) => {
                assert_eq!(
                    failure.cause,
                    Cause::RadioNetwork(CauseRadioNetwork::UnknownTargetId)
                );
            }
            other => panic!("expected HandoverPreparationFailure, got {other:?}"),
        }
    }

    #[test]
    fn test_handover_notify_completes_handover_and_releases_source() {
        let ctx = ctx_with_gummei();
        let (source_enb_id, source_ue_id, mme_ue_id, mme_ue_s1ap_id) = add_ue(&ctx);
        let bearer_id = ctx.bearer_add(0, mme_ue_id);
        {
            let mut pool = ctx.bearer_pool.write().unwrap();
            let bearer = pool.get_mut(&bearer_id).unwrap();
            bearer.ebi = 5;
            bearer.sgw_s1u_teid = 0x5555;
            bearer.sgw_s1u_ip.ipv4 = Some([10, 0, 0, 2]);
            bearer.qos.qci = 9;
            bearer.qos.arp.priority_level = 8;
        }
        let target_enb_id = ctx.enb_add("127.0.0.8:36412".parse().unwrap());
        ctx.enb_set_s1_connected_for_test(
            target_enb_id,
            &s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
            nextgcore_s1ap::EnbId::Macro(0x2222),
        );

        // Run the preparation phase to create the target context
        let ho = HandoverRequired {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: 100,
            handover_type: S1apHandoverType::IntraLte,
            cause: Cause::RadioNetwork(CauseRadioNetwork::HandoverDesirableForRadioReason),
            target_id: TargetId::TargetEnbId {
                global_enb_id: GlobalEnbId {
                    plmn_identity: s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
                    enb_id: nextgcore_s1ap::EnbId::Macro(0x2222),
                },
                selected_tai: nextgcore_s1ap::Tai {
                    plmn_identity: s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
                    tac: 2,
                },
            },
            // #48: ABSENT, which means no direct path and therefore INDIRECT
            // forwarding -- the behaviour these tests were written against.
            direct_forwarding_path_availability: None,
            source_to_target_container: vec![0x01],
        };
        let out = handle_s1ap_message(
            &ctx,
            source_enb_id,
            &builder::build_handover_required(&ho).unwrap(),
        );
        let target_mme_ue_s1ap_id = match decode_s1ap_pdu(&out[0].pdu).unwrap() {
            S1apMessage::HandoverRequest(req) => req.mme_ue_s1ap_id,
            other => panic!("expected HandoverRequest, got {other:?}"),
        };

        // Target eNB acknowledges (admits the E-RAB) -> Handover Command to source
        let ack = HandoverRequestAcknowledge {
            mme_ue_s1ap_id: target_mme_ue_s1ap_id,
            enb_ue_s1ap_id: 300,
            erab_admitted_list: vec![nextgcore_s1ap::ErabAdmittedItem {
                erab_id: 5,
                transport_layer_address: vec![10, 0, 0, 8],
                gtp_teid: 0x8888,
                dl_transport_layer_address: None,
                dl_gtp_teid: None,
                ul_transport_layer_address: None,
                ul_gtp_teid: None,
            }],
            erab_failed_list: Vec::new(),
            target_to_source_container: vec![0xBE, 0xEF],
        };
        let out = handle_s1ap_message(
            &ctx,
            target_enb_id,
            &builder::build_handover_request_acknowledge(&ack).unwrap(),
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].enb_id, source_enb_id);
        match decode_s1ap_pdu(&out[0].pdu).unwrap() {
            S1apMessage::HandoverCommand(cmd) => {
                assert_eq!(cmd.mme_ue_s1ap_id, mme_ue_s1ap_id);
                assert_eq!(cmd.target_to_source_container, vec![0xBE, 0xEF]);
            }
            other => panic!("expected HandoverCommand, got {other:?}"),
        }

        // Handover Notify from the target completes the procedure
        let notify = HandoverNotify {
            mme_ue_s1ap_id: target_mme_ue_s1ap_id,
            enb_ue_s1ap_id: 300,
            eutran_cgi: nextgcore_s1ap::EutranCgi {
                plmn_identity: s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
                cell_identity: 0x99,
            },
            tai: nextgcore_s1ap::Tai {
                plmn_identity: s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
                tac: 2,
            },
        };
        let out = handle_s1ap_message(
            &ctx,
            target_enb_id,
            &builder::build_handover_notify(&notify).unwrap(),
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].enb_id, source_enb_id);
        match decode_s1ap_pdu(&out[0].pdu).unwrap() {
            S1apMessage::UeContextReleaseCommand(cmd) => {
                assert_eq!(
                    cmd.cause,
                    Cause::RadioNetwork(CauseRadioNetwork::SuccessfulHandover)
                );
            }
            other => panic!("expected UeContextReleaseCommand, got {other:?}"),
        }

        // #730: the admitted endpoint becomes the bearer's only once the Serving
        // GW accepts it (`handover_switch`'s tests drive that with a real S11
        // socket). This context has no PDN connection and no S11 path, so the
        // core cannot complete the handover and the UE is detached rather than
        // left without downlink (TS 23.401 §5.5.1.1.2).
        assert_eq!(
            ctx.bearer_find_by_id(bearer_id).map(|b| b.target_s1u_teid),
            None
        );
        assert!(ctx.mme_ue_find_by_id(mme_ue_id).is_none_or(|ue| {
            ue.enb_ue_id != source_ue_id
                && ue.nas_eps.type_ == crate::context::MmeEpsType::DetachRequestToUe
        }));
        // Source release action recorded for the release procedure
        let source_ue = ctx.enb_ue_find_by_id(source_ue_id).unwrap();
        assert_eq!(
            source_ue.ue_ctx_rel_action,
            UeCtxRelAction::S1HandoverComplete
        );
    }

    /// Set up a prepared handover: source UE, one bearer, a registered target eNB, and a
    /// Handover Required already processed. Returns
    /// `(source_enb_id, source_ue_id, target_enb_id, mme_ue_s1ap_id, target_mme_ue_s1ap_id, bearer_id)`.
    ///
    /// `direct` decides whether the Handover Required carries Direct Forwarding Path
    /// Availability, which is what selects direct over indirect forwarding.
    fn prepared_handover(ctx: &MmeContext, direct: bool) -> (u64, u64, u64, u32, u32, u64) {
        let (source_enb_id, source_ue_id, mme_ue_id, mme_ue_s1ap_id) = add_ue(ctx);
        let bearer_id = ctx.bearer_add(0, mme_ue_id);
        {
            let mut pool = ctx.bearer_pool.write().unwrap();
            let bearer = pool.get_mut(&bearer_id).unwrap();
            bearer.ebi = 5;
            bearer.sgw_s1u_teid = 0x5555;
            bearer.sgw_s1u_ip.ipv4 = Some([10, 0, 0, 2]);
            bearer.qos.qci = 9;
            bearer.qos.arp.priority_level = 8;
        }
        let target_enb_id = ctx.enb_add("127.0.0.8:36412".parse().unwrap());
        ctx.enb_set_s1_connected_for_test(
            target_enb_id,
            &s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
            nextgcore_s1ap::EnbId::Macro(0x2222),
        );

        let ho = HandoverRequired {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: 100,
            handover_type: S1apHandoverType::IntraLte,
            cause: Cause::RadioNetwork(CauseRadioNetwork::HandoverDesirableForRadioReason),
            target_id: TargetId::TargetEnbId {
                global_enb_id: GlobalEnbId {
                    plmn_identity: s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
                    enb_id: nextgcore_s1ap::EnbId::Macro(0x2222),
                },
                selected_tai: nextgcore_s1ap::Tai {
                    plmn_identity: s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
                    tac: 2,
                },
            },
            direct_forwarding_path_availability: direct
                .then_some(nextgcore_s1ap::DirectForwardingPathAvailability::DirectPathAvailable),
            source_to_target_container: vec![0x01],
        };
        let out = handle_s1ap_message(
            ctx,
            source_enb_id,
            &builder::build_handover_required(&ho).unwrap(),
        );
        let target_mme_ue_s1ap_id = match decode_s1ap_pdu(&out[0].pdu).unwrap() {
            S1apMessage::HandoverRequest(req) => req.mme_ue_s1ap_id,
            other => panic!("expected HandoverRequest, got {other:?}"),
        };
        (
            source_enb_id,
            source_ue_id,
            target_enb_id,
            mme_ue_s1ap_id,
            target_mme_ue_s1ap_id,
            bearer_id,
        )
    }

    /// A Handover Request Acknowledge admitting DL and UL data-forwarding endpoints.
    fn ack_with_forwarding(target_mme_ue_s1ap_id: u32) -> HandoverRequestAcknowledge {
        HandoverRequestAcknowledge {
            mme_ue_s1ap_id: target_mme_ue_s1ap_id,
            enb_ue_s1ap_id: 300,
            erab_admitted_list: vec![nextgcore_s1ap::ErabAdmittedItem {
                erab_id: 5,
                transport_layer_address: vec![10, 0, 0, 8],
                gtp_teid: 0x8888,
                dl_transport_layer_address: Some(vec![10, 0, 0, 9]),
                dl_gtp_teid: Some(0xDDDD),
                ul_transport_layer_address: Some(vec![10, 0, 0, 10]),
                ul_gtp_teid: Some(0xEEEE),
            }],
            erab_failed_list: Vec::new(),
            target_to_source_container: vec![0xBE, 0xEF],
        }
    }

    /// #48 criterion 4: the admitted DL/UL forwarding TEIDs reach the Handover Command's
    /// E-RABs Subject to Forwarding List.
    ///
    /// Both halves are asserted, because they failed for different reasons before: the
    /// TEIDs were decoded by `nextgcore-s1ap` and DROPPED in
    /// `handle_handover_request_acknowledge` (so the bearer never held them), and the
    /// list was hard-coded to `Vec::new()` (so even a populated bearer could not reach
    /// the wire).
    #[test]
    fn direct_forwarding_populates_the_handover_command_forwarding_list() {
        let ctx = ctx_with_gummei();
        let (source_enb_id, _, target_enb_id, mme_ue_s1ap_id, target_mme_ue_s1ap_id, bearer_id) =
            prepared_handover(&ctx, true);

        let out = handle_s1ap_message(
            &ctx,
            target_enb_id,
            &builder::build_handover_request_acknowledge(&ack_with_forwarding(
                target_mme_ue_s1ap_id,
            ))
            .unwrap(),
        );

        // The endpoints were recorded on the bearer.
        let bearer = ctx.bearer_find_by_id(bearer_id).unwrap();
        assert_eq!(bearer.enb_dl_teid, 0xDDDD, "admitted DL forwarding TEID");
        assert_eq!(bearer.enb_dl_ip.ipv4, Some([10, 0, 0, 9]));
        assert_eq!(bearer.enb_ul_teid, 0xEEEE, "admitted UL forwarding TEID");
        assert_eq!(bearer.enb_ul_ip.ipv4, Some([10, 0, 0, 10]));

        // And they reached the Handover Command.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].enb_id, source_enb_id);
        match decode_s1ap_pdu(&out[0].pdu).unwrap() {
            S1apMessage::HandoverCommand(cmd) => {
                assert_eq!(cmd.mme_ue_s1ap_id, mme_ue_s1ap_id);
                assert_eq!(
                    cmd.erab_subject_to_forwarding_list.len(),
                    1,
                    "a direct-forwarding handover must carry a forwarding list, not the empty \
                     one this used to send"
                );
                let item = &cmd.erab_subject_to_forwarding_list[0];
                assert_eq!(item.erab_id, 5);
                assert_eq!(item.dl_gtp_teid, Some(0xDDDD));
                assert_eq!(item.dl_transport_layer_address, Some(vec![10, 0, 0, 9]));
                assert_eq!(item.ul_gtp_teid, Some(0xEEEE));
                assert_eq!(item.ul_transport_layer_address, Some(vec![10, 0, 0, 10]));
            }
            other => panic!("expected HandoverCommand, got {other:?}"),
        }
    }

    /// #48 criteria 1 and 2: an eNB Status Transfer is dispatched (not answered with an
    /// Error Indication) and relayed to the target under the TARGET's ids with the
    /// container byte for byte.
    #[test]
    fn enb_status_transfer_is_relayed_to_the_target_unchanged() {
        let ctx = ctx_with_gummei();
        let (source_enb_id, _, target_enb_id, mme_ue_s1ap_id, target_mme_ue_s1ap_id, _) =
            prepared_handover(&ctx, true);
        let _ = handle_s1ap_message(
            &ctx,
            target_enb_id,
            &builder::build_handover_request_acknowledge(&ack_with_forwarding(
                target_mme_ue_s1ap_id,
            ))
            .unwrap(),
        );

        // A real ENB-StatusTransfer-TransparentContainer: since #514 stage 8a
        // the relay re-encodes it with the generated codec, which requires the
        // ASN.1 type rather than arbitrary octets.
        let payload = crate::s1ap_gen::handover_tests::sample_container();
        let status = nextgcore_s1ap::EnbStatusTransfer {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: 100,
            status_transfer_container: payload.clone(),
        };
        let out = handle_s1ap_message(
            &ctx,
            source_enb_id,
            &builder::build_enb_status_transfer(&status).unwrap(),
        );

        assert_eq!(out.len(), 1, "the status must be relayed, not dropped");
        assert_eq!(
            out[0].enb_id, target_enb_id,
            "the relay goes to the TARGET eNB"
        );
        match decode_s1ap_pdu(&out[0].pdu).unwrap() {
            S1apMessage::MmeStatusTransfer(relay) => {
                assert_eq!(
                    relay.status_transfer_container, payload,
                    "the PDCP SN/HFN status must cross unchanged"
                );
                assert_eq!(
                    relay.mme_ue_s1ap_id, target_mme_ue_s1ap_id,
                    "addressed with the target association's MME-UE-S1AP-ID"
                );
                assert_eq!(relay.enb_ue_s1ap_id, 300, "and the target's eNB-UE-S1AP-ID");
            }
            // This is the pre-#48 behaviour: proc 24 fell through to Unknown and was
            // answered with abstract-syntax-error-reject.
            S1apMessage::ErrorIndication(e) => {
                panic!("status transfer answered with an Error Indication: {e:?}")
            }
            other => panic!("expected MmeStatusTransfer, got {other:?}"),
        }
    }

    /// #48 criterion 6, first half: a cancelled handover tells the prepared target to
    /// release, with cause `handover-cancelled`.
    #[test]
    fn handover_cancel_releases_the_prepared_target() {
        let ctx = ctx_with_gummei();
        let (source_enb_id, source_ue_id, target_enb_id, mme_ue_s1ap_id, target_mme_ue_s1ap_id, _) =
            prepared_handover(&ctx, true);
        let _ = handle_s1ap_message(
            &ctx,
            target_enb_id,
            &builder::build_handover_request_acknowledge(&ack_with_forwarding(
                target_mme_ue_s1ap_id,
            ))
            .unwrap(),
        );
        let target_ue_id = ctx.enb_ue_find_by_id(source_ue_id).unwrap().target_ue_id;
        assert_ne!(target_ue_id, NEXTGCORE_INVALID_POOL_ID);

        let cancel = HandoverCancel {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: 100,
            cause: Cause::RadioNetwork(CauseRadioNetwork::HandoverCancelled),
        };
        let out = handle_s1ap_message(
            &ctx,
            source_enb_id,
            &builder::build_handover_cancel(&cancel).unwrap(),
        );

        let release = out.iter().find(|send| send.enb_id == target_enb_id).expect(
            "the prepared target must be told to release; freeing only the MME's copy \
                     strands the target's radio and S1-U reservation",
        );
        match decode_s1ap_pdu(&release.pdu).unwrap() {
            S1apMessage::UeContextReleaseCommand(cmd) => assert_eq!(
                cmd.cause,
                Cause::RadioNetwork(CauseRadioNetwork::HandoverCancelled)
            ),
            other => panic!("expected UeContextReleaseCommand to the target, got {other:?}"),
        }

        // The source still gets its acknowledge, and the target context is gone.
        assert!(
            out.iter().any(|send| send.enb_id == source_enb_id),
            "the source must still be acknowledged"
        );
        assert!(ctx.enb_ue_find_by_id(target_ue_id).is_none());
    }

    /// #48 criterion 6, second half: a preparation that never completes is released by
    /// the supervision sweep instead of leaking the target context.
    ///
    /// Asserts the DECISION (which target, and that the context is freed), not the
    /// transmission: `expire_handover_preparations` returns the sends precisely so this
    /// is assertable without an eNB on the other end of an SCTP association.
    #[test]
    fn handover_preparation_supervision_releases_a_target_that_never_completes() {
        let ctx = ctx_with_gummei();
        let (_, source_ue_id, target_enb_id, _, target_mme_ue_s1ap_id, _) =
            prepared_handover(&ctx, true);
        let _ = handle_s1ap_message(
            &ctx,
            target_enb_id,
            &builder::build_handover_request_acknowledge(&ack_with_forwarding(
                target_mme_ue_s1ap_id,
            ))
            .unwrap(),
        );
        let target_ue_id = ctx.enb_ue_find_by_id(source_ue_id).unwrap().target_ue_id;

        // Nothing has expired yet, so the sweep is a no-op. Asserted so the expiry below
        // cannot pass merely because the sweep releases everything it sees.
        assert!(
            expire_handover_preparations(&ctx, std::time::Instant::now()).is_empty(),
            "a live preparation must not be released"
        );
        assert!(ctx.enb_ue_find_by_id(target_ue_id).is_some());

        let past = std::time::Instant::now() + HANDOVER_PREPARATION_SUPERVISION;
        let sends = expire_handover_preparations(&ctx, past);

        assert_eq!(sends.len(), 1, "the expired target must be released");
        assert_eq!(sends[0].enb_id, target_enb_id);
        match decode_s1ap_pdu(&sends[0].pdu).unwrap() {
            S1apMessage::UeContextReleaseCommand(cmd) => assert_eq!(
                cmd.cause,
                Cause::RadioNetwork(CauseRadioNetwork::TS1relocoverallExpiry),
                "the cause must say the relocation supervision expired, not that it was \
                 cancelled"
            ),
            other => panic!("expected UeContextReleaseCommand, got {other:?}"),
        }
        assert!(
            ctx.enb_ue_find_by_id(target_ue_id).is_none(),
            "the leaked context is the defect; the release alone does not fix it"
        );
        assert_eq!(
            ctx.enb_ue_find_by_id(source_ue_id).unwrap().target_ue_id,
            NEXTGCORE_INVALID_POOL_ID,
            "the source must no longer point at a context that is gone"
        );
    }

    #[test]
    fn test_handover_cancel_acknowledged() {
        let ctx = ctx_with_gummei();
        let (source_enb_id, _, _, mme_ue_s1ap_id) = add_ue(&ctx);

        let cancel = HandoverCancel {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: 100,
            cause: Cause::RadioNetwork(CauseRadioNetwork::HandoverCancelled),
        };
        let out = handle_s1ap_message(
            &ctx,
            source_enb_id,
            &builder::build_handover_cancel(&cancel).unwrap(),
        );
        assert_eq!(out.len(), 1);
        match decode_s1ap_pdu(&out[0].pdu).unwrap() {
            S1apMessage::HandoverCancelAcknowledge(ack) => {
                assert_eq!(ack.mme_ue_s1ap_id, mme_ue_s1ap_id);
            }
            other => panic!("expected HandoverCancelAcknowledge, got {other:?}"),
        }
    }

    #[test]
    fn test_ue_context_release_request_answered_with_command() {
        let ctx = ctx_with_gummei();
        let (enb_id, enb_ue_id, _, mme_ue_s1ap_id) = add_ue(&ctx);

        let request = UeContextReleaseRequest {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: 100,
            cause: Cause::RadioNetwork(CauseRadioNetwork::UserInactivity),
        };
        let out = handle_s1ap_message(
            &ctx,
            enb_id,
            &builder::build_ue_context_release_request(&request).unwrap(),
        );
        assert_eq!(out.len(), 1);
        match decode_s1ap_pdu(&out[0].pdu).unwrap() {
            S1apMessage::UeContextReleaseCommand(cmd) => {
                assert_eq!(
                    cmd.cause,
                    Cause::RadioNetwork(CauseRadioNetwork::UserInactivity)
                );
            }
            other => panic!("expected UeContextReleaseCommand, got {other:?}"),
        }
        let enb_ue = ctx.enb_ue_find_by_id(enb_ue_id).unwrap();
        assert_eq!(enb_ue.ue_ctx_rel_action, UeCtxRelAction::S1ContextRemove);

        // Complete tears the S1 context down
        let complete = UeContextReleaseComplete {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: 100,
        };
        let out = handle_s1ap_message(
            &ctx,
            enb_id,
            &builder::build_ue_context_release_complete(&complete).unwrap(),
        );
        assert!(out.is_empty());
        assert!(ctx.enb_ue_find_by_id(enb_ue_id).is_none());
    }

    #[test]
    fn test_initial_ue_message_creates_context() {
        let ctx = ctx_with_gummei();
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());

        let msg = InitialUeMessage {
            enb_ue_s1ap_id: 55,
            nas_pdu: vec![0x07, 0x41, 0x71],
            tai: nextgcore_s1ap::Tai {
                plmn_identity: s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
                tac: 1,
            },
            eutran_cgi: nextgcore_s1ap::EutranCgi {
                plmn_identity: s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
                cell_identity: 0x100,
            },
            rrc_establishment_cause: nextgcore_s1ap::RrcEstablishmentCause::MoSignalling,
            s_tmsi: Some(STmsi {
                mmec: 1,
                m_tmsi: 0x1234,
            }),
        };
        let enb_ue_id = handle_initial_ue_message(&ctx, enb_id, &msg).unwrap();
        let enb_ue = ctx.enb_ue_find_by_id(enb_ue_id).unwrap();
        assert_eq!(enb_ue.enb_ue_s1ap_id, 55);
        assert_eq!(enb_ue.saved.tai.tac, 1);
        assert_eq!(enb_ue.saved.e_cgi.cell_id, 0x100);
    }

    /// Plain EPS ATTACH REQUEST for IMSI 001010123456789 with a piggybacked PDN
    /// CONNECTIVITY REQUEST for APN "inet" (TS 24.301 §8.2.4).
    fn attach_request_pdu() -> Vec<u8> {
        vec![
            0x07, 0x41, // EMM protocol discriminator (plain), Attach Request
            0x71, // EPS attach type 1, KSI 7 (no key available)
            0x08, // EPS mobile identity length
            0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, // IMSI
            0x02, 0xf0, 0xf0, // UE network capability: EEA/EIA
            0x00, 0x0b, // ESM message container length
            0x02, 0x01, 0xd0, // ESM: EBI 0, PTI 1, PDN Connectivity Request
            0x11, // request type 1 (initial), PDN type 1 (IPv4)
            0x28, 0x05, 0x04, b'i', b'n', b'e', b't', // APN
        ]
    }

    #[test]
    fn test_initial_ue_message_dispatches_attach_request_into_emm() {
        let ctx = ctx_with_gummei();
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());

        let msg = InitialUeMessage {
            enb_ue_s1ap_id: 77,
            nas_pdu: attach_request_pdu(),
            tai: nextgcore_s1ap::Tai {
                plmn_identity: s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
                tac: 1,
            },
            eutran_cgi: nextgcore_s1ap::EutranCgi {
                plmn_identity: s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
                cell_identity: 0x100,
            },
            rrc_establishment_cause: nextgcore_s1ap::RrcEstablishmentCause::MoSignalling,
            s_tmsi: None,
        };

        let out = handle_s1ap_message(
            &ctx,
            enb_id,
            &builder::build_initial_ue_message(&msg).unwrap(),
        );
        assert!(out.is_empty(), "no S1AP-level response is due");

        // The EMM attach handler ran: the NAS PDU was decoded, the subscriber
        // identity parsed onto a UE context, and that context indexed by IMSI.
        // Before issue #43 the PDU was logged and dropped here.
        let mme_ue_id = ctx
            .mme_ue_find_by_imsi("001010123456789")
            .expect("the Attach Request must reach emm_handler");
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(mme_ue.nas_eps.attach_type, 1);
        assert_eq!(mme_ue.tai.tac, 1);
        assert_eq!(mme_ue.e_cgi.cell_id, 0x100);
        // The piggybacked ESM container is held until a security context exists
        // (TS 24.301 §5.5.1.2.2).
        assert_eq!(mme_ue.pdn_connectivity_request.len(), 11);
    }

    #[test]
    fn test_uplink_nas_transport_unknown_ue_id_triggers_error_indication() {
        let ctx = ctx_with_gummei();
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());

        let msg = UlNasTransport {
            mme_ue_s1ap_id: 4242,
            enb_ue_s1ap_id: 77,
            nas_pdu: attach_request_pdu(),
            eutran_cgi: nextgcore_s1ap::EutranCgi {
                plmn_identity: s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
                cell_identity: 0x100,
            },
            tai: nextgcore_s1ap::Tai {
                plmn_identity: s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
                tac: 1,
            },
        };

        let out = handle_s1ap_message(
            &ctx,
            enb_id,
            &builder::build_uplink_nas_transport(&msg).unwrap(),
        );

        // TS 36.413 §10.6: the unknown MME-UE-S1AP-ID must be reported so the
        // eNB can release its stale S1 context.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].enb_id, enb_id);
        match decode_s1ap_pdu(&out[0].pdu).unwrap() {
            S1apMessage::ErrorIndication(ind) => {
                assert_eq!(ind.mme_ue_s1ap_id, Some(4242));
                assert_eq!(ind.enb_ue_s1ap_id, Some(77));
                assert_eq!(
                    ind.cause,
                    Some(Cause::RadioNetwork(CauseRadioNetwork::UnknownMmeUeS1apId))
                );
            }
            other => panic!("expected ErrorIndication, got {other:?}"),
        }
        assert!(ctx.mme_ue_pool.read().unwrap().is_empty());
    }

    #[test]
    fn test_uplink_nas_transport_dispatches_into_emm() {
        let ctx = ctx_with_gummei();
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        let enb_ue_id = ctx.enb_ue_add(enb_id, 77);
        let mme_ue_s1ap_id = ctx.enb_ue_find_by_id(enb_ue_id).unwrap().mme_ue_s1ap_id;

        let msg = UlNasTransport {
            mme_ue_s1ap_id,
            enb_ue_s1ap_id: 77,
            nas_pdu: attach_request_pdu(),
            eutran_cgi: nextgcore_s1ap::EutranCgi {
                plmn_identity: s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
                cell_identity: 0x100,
            },
            tai: nextgcore_s1ap::Tai {
                plmn_identity: s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
                tac: 1,
            },
        };

        let out = handle_s1ap_message(
            &ctx,
            enb_id,
            &builder::build_uplink_nas_transport(&msg).unwrap(),
        );
        assert!(out.is_empty());
        assert!(
            ctx.mme_ue_find_by_imsi("001010123456789").is_some(),
            "a known S1 connection must have its NAS PDU dispatched"
        );
    }

    #[test]
    fn test_initial_context_setup_failure_releases_the_ue() {
        let ctx = ctx_with_gummei();
        let (enb_id, enb_ue_id, _, mme_ue_s1ap_id) = add_ue(&ctx);

        let out = handle_initial_context_setup_failure(
            &ctx,
            enb_id,
            &InitialContextSetupFailure {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id: 100,
                cause: Cause::RadioNetwork(CauseRadioNetwork::RadioResourcesNotAvailable),
            },
        );

        // TS 36.413 §8.3.1.3: the setup failed, so the connection is released
        // rather than left in place for a UE with no radio bearers.
        assert_eq!(out.len(), 1, "a UE Context Release Command is due");
        assert!(matches!(
            decode_s1ap_pdu(&out[0].pdu).unwrap(),
            S1apMessage::UeContextReleaseCommand(_)
        ));
        let enb_ue = ctx.enb_ue_find_by_id(enb_ue_id).unwrap();
        assert_eq!(enb_ue.ue_ctx_rel_action, UeCtxRelAction::UeContextRemove);
        assert_eq!(enb_ue.relcause.group, S1apCauseGroup::RadioNetwork);
    }

    #[test]
    fn test_initial_context_setup_failure_for_unknown_ue_reports_it() {
        let ctx = ctx_with_gummei();
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());

        let out = handle_initial_context_setup_failure(
            &ctx,
            enb_id,
            &InitialContextSetupFailure {
                mme_ue_s1ap_id: 4242,
                enb_ue_s1ap_id: 7,
                cause: Cause::RadioNetwork(CauseRadioNetwork::RadioResourcesNotAvailable),
            },
        );

        assert_eq!(out.len(), 1);
        assert!(matches!(
            decode_s1ap_pdu(&out[0].pdu).unwrap(),
            S1apMessage::ErrorIndication(_)
        ));
    }

    #[test]
    fn test_error_indication_with_unknown_id_releases_the_stale_context() {
        let ctx = ctx_with_gummei();
        let (enb_id, enb_ue_id, mme_ue_id, mme_ue_s1ap_id) = add_ue(&ctx);

        // The eNB says it does not know this id: OUR context is the stale one.
        handle_error_indication(
            &ctx,
            enb_id,
            &ErrorIndication {
                mme_ue_s1ap_id: Some(mme_ue_s1ap_id),
                enb_ue_s1ap_id: Some(100),
                cause: Some(Cause::RadioNetwork(CauseRadioNetwork::UnknownMmeUeS1apId)),
                criticality_diagnostics: None,
            },
        );

        assert!(
            ctx.enb_ue_find_by_id(enb_ue_id).is_none(),
            "the S1 connection is released locally"
        );
        // The UE context survives, idle, as it does for any S1 release.
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(mme_ue.enb_ue_id, NEXTGCORE_INVALID_POOL_ID);
    }

    #[test]
    fn test_error_indication_with_another_cause_is_informational() {
        let ctx = ctx_with_gummei();
        let (enb_id, enb_ue_id, _, mme_ue_s1ap_id) = add_ue(&ctx);

        handle_error_indication(
            &ctx,
            enb_id,
            &ErrorIndication {
                mme_ue_s1ap_id: Some(mme_ue_s1ap_id),
                enb_ue_s1ap_id: Some(100),
                cause: Some(Cause::Protocol(
                    nextgcore_s1ap::CauseProtocol::SemanticError,
                )),
                criticality_diagnostics: None,
            },
        );

        assert!(
            ctx.enb_ue_find_by_id(enb_ue_id).is_some(),
            "a semantic error says nothing about our context being stale"
        );
    }

    #[test]
    fn test_repeat_s1_setup_releases_the_restarted_enbs_contexts() {
        let ctx = ctx_with_gummei();
        let (enb_id, enb_ue_id, _, _) = add_ue(&ctx);
        // Mark the eNB as already set up, as its first S1 Setup would have.
        if let Some(enb) = ctx.enb_pool.write().unwrap().get_mut(&enb_id) {
            enb.state.s1_setup_success = true;
        }

        let request = S1SetupRequest {
            global_enb_id: GlobalEnbId {
                plmn_identity: s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
                enb_id: nextgcore_s1ap::EnbId::Macro(0x1234),
            },
            enb_name: Some("restarted-enb".to_string()),
            supported_tas: vec![SupportedTaItem {
                tac: 1,
                broadcast_plmns: vec![s1ap_build::encode_plmn_id(&PlmnId::new("310", "410"))],
            }],
            default_paging_drx: nextgcore_s1ap::PagingDrx::V64,
        };
        let out = handle_s1ap_message(
            &ctx,
            enb_id,
            &builder::build_s1_setup_request(&request).unwrap(),
        );

        // TS 23.007 §17: the setup is still accepted, but the stale contexts are
        // gone — otherwise their MME-UE-S1AP-IDs collide with the ids the
        // restarted eNB is about to allocate.
        assert!(matches!(
            decode_s1ap_pdu(&out[0].pdu).unwrap(),
            S1apMessage::S1SetupResponse(_)
        ));
        assert!(
            ctx.enb_ue_find_by_id(enb_ue_id).is_none(),
            "the restarted eNB's stale UE context must be released"
        );
    }

    #[test]
    fn test_protocol_errors_carry_criticality_diagnostics() {
        let ctx = ctx_with_gummei();
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());

        let out = handle_s1ap_message(&ctx, enb_id, &[0xff, 0x00, 0xff]);

        assert_eq!(out.len(), 1);
        match decode_s1ap_pdu(&out[0].pdu).unwrap() {
            S1apMessage::ErrorIndication(ind) => {
                let diag = ind
                    .criticality_diagnostics
                    .expect("a protocol error must say what it was about");
                assert_eq!(
                    diag.triggering_message,
                    Some(nextgcore_s1ap::triggering_message::INITIATING_MESSAGE)
                );
            }
            other => panic!("expected ErrorIndication, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // eNB Configuration Update (§8.7.4) — #49
    // ------------------------------------------------------------------

    /// Register an eNB with S1 Setup complete, serving TAC 1.
    fn setup_enb(ctx: &MmeContext) -> u64 {
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        ctx.enb_set_enb_id(enb_id, 0x1234);
        if let Some(enb) = ctx.enb_pool.write().unwrap().get_mut(&enb_id) {
            enb.state.s1_setup_success = true;
            enb.supported_ta_list = vec![EpsTai {
                plmn_id: PlmnId::new("310", "410"),
                tac: 1,
            }];
        }
        enb_id
    }

    fn config_update_pdu(msg: &nextgcore_s1ap::EnbConfigurationUpdate) -> Vec<u8> {
        builder::build_enb_configuration_update(msg).unwrap()
    }

    /// The headline interop fix: a conforming eNB that reconfigures its tracking
    /// areas gets an ACKNOWLEDGE, and the MME's stored TA list is *replaced* by
    /// the update's — not left at the value S1 Setup wrote.
    #[test]
    fn test_enb_configuration_update_replaces_the_ta_list_and_acks() {
        let ctx = ctx_with_gummei();
        let enb_id = setup_enb(&ctx);
        assert_eq!(
            ctx.enb_find_by_id(enb_id).unwrap().supported_ta_list[0].tac,
            1,
            "S1 Setup wrote TAC 1"
        );

        let update = nextgcore_s1ap::EnbConfigurationUpdate {
            enb_name: Some("reconfigured".to_string()),
            supported_tas: Some(vec![SupportedTaItem {
                tac: 7,
                broadcast_plmns: vec![s1ap_build::encode_plmn_id(&PlmnId::new("310", "410"))],
            }]),
            default_paging_drx: None,
        };
        let out = handle_s1ap_message(&ctx, enb_id, &config_update_pdu(&update));

        assert_eq!(out.len(), 1, "an Acknowledge is due");
        assert_eq!(out[0].enb_id, enb_id);
        assert!(
            matches!(
                decode_s1ap_pdu(&out[0].pdu).unwrap(),
                S1apMessage::EnbConfigurationUpdateAcknowledge(_)
            ),
            "before #49 this was answered with an Error Indication, which is an \
             interoperability failure"
        );

        let enb = ctx.enb_find_by_id(enb_id).unwrap();
        assert_eq!(enb.supported_ta_list.len(), 1);
        assert_eq!(
            enb.supported_ta_list[0].tac, 7,
            "the TA list must be the update's, not S1 Setup's"
        );
    }

    /// An update carrying only a new name must leave the TA list alone. Treating
    /// an absent SupportedTAs as an empty one would strand every UE in the
    /// tracking areas the eNB still serves.
    #[test]
    fn test_enb_configuration_update_without_ta_list_preserves_it() {
        let ctx = ctx_with_gummei();
        let enb_id = setup_enb(&ctx);

        let update = nextgcore_s1ap::EnbConfigurationUpdate {
            enb_name: Some("renamed-only".to_string()),
            supported_tas: None,
            default_paging_drx: Some(nextgcore_s1ap::PagingDrx::V256),
        };
        let out = handle_s1ap_message(&ctx, enb_id, &config_update_pdu(&update));

        assert_eq!(out.len(), 1);
        assert!(matches!(
            decode_s1ap_pdu(&out[0].pdu).unwrap(),
            S1apMessage::EnbConfigurationUpdateAcknowledge(_)
        ));
        let enb = ctx.enb_find_by_id(enb_id).unwrap();
        assert_eq!(
            enb.supported_ta_list.len(),
            1,
            "an omitted TA list means unchanged"
        );
        assert_eq!(enb.supported_ta_list[0].tac, 1);
    }

    /// A TA list this MME does not serve is refused with a FAILURE, using the
    /// same admission rule as S1 Setup so the two cannot disagree about which
    /// eNBs are servable.
    #[test]
    fn test_enb_configuration_update_with_unserved_tai_fails() {
        let mut ctx = MmeContext::new();
        assert!(crate::config::load_config(
            &mut ctx,
            "../../../docker/rust/configs/epc/mme.yaml"
        ));
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        if let Some(enb) = ctx.enb_pool.write().unwrap().get_mut(&enb_id) {
            enb.state.s1_setup_success = true;
        }

        let update = nextgcore_s1ap::EnbConfigurationUpdate {
            enb_name: None,
            supported_tas: Some(vec![SupportedTaItem {
                tac: 999,
                broadcast_plmns: vec![s1ap_build::encode_plmn_id(&PlmnId::new("310", "410"))],
            }]),
            default_paging_drx: None,
        };
        let out = handle_s1ap_message(&ctx, enb_id, &config_update_pdu(&update));

        assert_eq!(out.len(), 1);
        match decode_s1ap_pdu(&out[0].pdu).unwrap() {
            S1apMessage::EnbConfigurationUpdateFailure(failure) => {
                assert_eq!(
                    failure.cause,
                    Cause::Misc(nextgcore_s1ap::CauseMisc::UnknownPlmn)
                );
                assert_eq!(failure.time_to_wait, Some(TimeToWait::V10s));
            }
            other => panic!("expected EnbConfigurationUpdateFailure, got {other:?}"),
        }
    }

    /// An update from an eNB that never completed S1 Setup has no configuration
    /// to update (TS 36.413 §8.7.4.4).
    #[test]
    fn test_enb_configuration_update_before_s1_setup_fails() {
        let ctx = ctx_with_gummei();
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());

        let out = handle_s1ap_message(
            &ctx,
            enb_id,
            &config_update_pdu(&nextgcore_s1ap::EnbConfigurationUpdate::default()),
        );

        assert_eq!(out.len(), 1);
        match decode_s1ap_pdu(&out[0].pdu).unwrap() {
            S1apMessage::EnbConfigurationUpdateFailure(failure) => {
                assert_eq!(
                    failure.cause,
                    Cause::Protocol(
                        nextgcore_s1ap::CauseProtocol::MessageNotCompatibleWithReceiverState
                    )
                );
            }
            other => panic!("expected EnbConfigurationUpdateFailure, got {other:?}"),
        }
    }

    /// An eNB-originated UE Context Modification (an MME-only message) is a
    /// protocol error, not a procedure to run.
    #[test]
    fn test_mme_originated_ue_context_modification_is_rejected() {
        let ctx = ctx_with_gummei();
        let (enb_id, _, _, mme_ue_s1ap_id) = add_ue(&ctx);

        let bytes = builder::build_ue_context_modification_request(
            &nextgcore_s1ap::UeContextModificationRequest {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id: 100,
                security_key: None,
                subscriber_profile_id_for_rfp: None,
                ue_ambr: None,
                cs_fallback_indicator: Some(
                    nextgcore_s1ap::CsFallbackIndicator::CsFallbackRequired,
                ),
                ue_security_capabilities: None,
            },
        )
        .unwrap();

        let out = handle_s1ap_message(&ctx, enb_id, &bytes);
        assert_eq!(out.len(), 1);
        match decode_s1ap_pdu(&out[0].pdu).unwrap() {
            S1apMessage::ErrorIndication(ind) => {
                assert_eq!(
                    ind.cause,
                    Some(Cause::Protocol(
                        nextgcore_s1ap::CauseProtocol::MessageNotCompatibleWithReceiverState
                    ))
                );
            }
            other => panic!("expected ErrorIndication, got {other:?}"),
        }
    }

    /// The Write-Replace Warning Response is consumed rather than falling through
    /// to the `Unknown` arm's Error Indication, and answers nothing.
    #[test]
    fn test_pws_responses_are_consumed_without_a_reply() {
        let ctx = ctx_with_gummei();
        let enb_id = setup_enb(&ctx);

        let warning_response = builder::build_write_replace_warning_response(
            &nextgcore_s1ap::WriteReplaceWarningResponse {
                message_identifier: 0x1100,
                serial_number: 0x3000,
                broadcast_completed_area: Some(
                    nextgcore_s1ap::BroadcastCompletedAreaList::TaiBroadcast(vec![
                        nextgcore_s1ap::TaiBroadcastItem {
                            tai: nextgcore_s1ap::Tai {
                                plmn_identity: s1ap_build::encode_plmn_id(&PlmnId::new(
                                    "310", "410",
                                )),
                                tac: 1,
                            },
                            completed_cells: vec![nextgcore_s1ap::EutranCgi {
                                plmn_identity: s1ap_build::encode_plmn_id(&PlmnId::new(
                                    "310", "410",
                                )),
                                cell_identity: 0x42,
                            }],
                        },
                    ]),
                ),
                criticality_diagnostics: None,
            },
        )
        .unwrap();
        assert!(handle_s1ap_message(&ctx, enb_id, &warning_response).is_empty());

        let kill_response = builder::build_kill_response(&nextgcore_s1ap::KillResponse {
            message_identifier: 0x1100,
            serial_number: 0x3000,
            broadcast_cancelled_area: Some(
                nextgcore_s1ap::BroadcastCancelledAreaList::CellIdCancelled(vec![
                    nextgcore_s1ap::CellIdCancelledItem {
                        ecgi: nextgcore_s1ap::EutranCgi {
                            plmn_identity: s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
                            cell_identity: 0x42,
                        },
                        number_of_broadcasts: 3,
                    },
                ]),
            ),
            criticality_diagnostics: None,
        })
        .unwrap();
        assert!(handle_s1ap_message(&ctx, enb_id, &kill_response).is_empty());
    }

    #[test]
    fn test_garbage_pdu_triggers_error_indication() {
        let ctx = ctx_with_gummei();
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        let out = handle_s1ap_message(&ctx, enb_id, &[0xff, 0x00, 0xff]);
        assert_eq!(out.len(), 1);
        match decode_s1ap_pdu(&out[0].pdu).unwrap() {
            S1apMessage::ErrorIndication(ind) => {
                assert_eq!(
                    ind.cause,
                    Some(Cause::Protocol(
                        nextgcore_s1ap::CauseProtocol::TransferSyntaxError
                    ))
                );
            }
            other => panic!("expected ErrorIndication, got {other:?}"),
        }
    }
    /// #62 criterion 6: the 5GS interworking handover types are no longer collapsed
    /// onto `IntraLte`, in either direction.
    ///
    /// The old mapping's comment said these "never reach the S1AP handover path", which
    /// made it look like a harmless placeholder. It was not: if one DID reach it, the
    /// eNB was handed `intralte` for an inter-system move and would admit it as an
    /// ordinary LTE handover — a wrong value acted on, not an unused branch. Now they
    /// map onto the two extension additions TS 36.413 defines
    /// (`36413-j20.txt:30619`), so an eNB that does not implement the extension can
    /// reject a value it does not recognise, which is what the `...` marker is for.
    #[test]
    fn interworking_handover_types_are_not_collapsed_onto_intra_lte() {
        use crate::context::HandoverType as Ctx;

        assert_eq!(
            ho_type_to_s1ap(Ctx::EpsTo5gs),
            S1apHandoverType::EpsTo5gs,
            "EpsTo5gs must go on the wire as eps-to-5gs, not as intralte"
        );
        assert_eq!(
            ho_type_to_s1ap(Ctx::FiveGsToEps),
            S1apHandoverType::FiveGsToEps,
            "FiveGsToEps must go on the wire as fivegs-to-eps, not as intralte"
        );

        // The inbound direction too: mapping these to IntraLte on the way IN would
        // record the UE as doing an intra-LTE handover, so every later decision about
        // it would be made about the wrong procedure.
        assert_eq!(ho_type_from_s1ap(S1apHandoverType::EpsTo5gs), Ctx::EpsTo5gs);
        assert_eq!(
            ho_type_from_s1ap(S1apHandoverType::FiveGsToEps),
            Ctx::FiveGsToEps
        );

        // Every OTHER mapping is unchanged -- the point of the guard is that adding the
        // two extension values did not disturb the five root ones.
        for (ctx, wire) in [
            (Ctx::IntraLte, S1apHandoverType::IntraLte),
            (Ctx::LteToUtran, S1apHandoverType::LteToUtran),
            (Ctx::LteToGeran, S1apHandoverType::LteToGeran),
            (Ctx::UtranToLte, S1apHandoverType::UtranToLte),
            (Ctx::GeranToLte, S1apHandoverType::GeranToLte),
        ] {
            assert_eq!(ho_type_to_s1ap(ctx), wire, "{ctx:?} must be unchanged");
            assert_eq!(ho_type_from_s1ap(wire), ctx, "{wire:?} must be unchanged");
        }
    }
    /// #869 review: a UE CONTEXT MODIFICATION FAILURE for a UE-AMBR modification
    /// is counted as such (the eNB keeps the old UE-AMBR) and rendered for
    /// `/metrics`; one for anything else is counted apart.
    #[test]
    fn a_failed_ue_ambr_modification_is_counted() {
        let ctx = MmeContext::new();
        ctx.init();
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        let enb_ue_id = ctx.enb_ue_add(enb_id, 869);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
        let mme_ue_s1ap_id = ctx.enb_ue_find_by_id(enb_ue_id).unwrap().mme_ue_s1ap_id;
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&mme_ue_id)
            .unwrap()
            .ue_ambr_modification_pending = true;
        let count = |carried: &str| -> u64 {
            render_metrics()
                .lines()
                .find(|l| l.contains(&format!("carried=\"{carried}\"")))
                .and_then(|l| l.rsplit(' ').next())
                .and_then(|n| n.parse().ok())
                .unwrap()
        };
        let (ambr0, other0) = (count("ue_ambr"), count("other"));
        assert!(take_ue_ambr_modification(&ctx, enb_id, mme_ue_s1ap_id));
        count_ue_context_modification_failure("ue_ambr");
        assert!(
            !take_ue_ambr_modification(&ctx, enb_id, mme_ue_s1ap_id),
            "the mark is taken once"
        );
        count_ue_context_modification_failure("other");
        assert!(count("ue_ambr") > ambr0);
        assert!(count("other") > other0);
        assert!(
            !take_ue_ambr_modification(&ctx, enb_id + 1, mme_ue_s1ap_id),
            "only from the eNB serving the UE"
        );
    }
    /// #869 review: the Initial Context Setup Response ends the "setup in
    /// progress" that defers a UE-AMBR change.
    #[test]
    fn the_initial_context_setup_response_ends_the_setup_in_progress() {
        let ctx = MmeContext::new();
        ctx.init();
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        let enb_ue_id = ctx.enb_ue_add(enb_id, 870);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
        let mme_ue_s1ap_id = ctx.enb_ue_find_by_id(enb_ue_id).unwrap().mme_ue_s1ap_id;
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&mme_ue_id)
            .unwrap()
            .ics_pending_on = enb_ue_id;
        handle_initial_context_setup_response(
            &ctx,
            enb_id,
            &InitialContextSetupResponse {
                mme_ue_s1ap_id,
                enb_ue_s1ap_id: 870,
                erab_setup_list: vec![],
                erab_failed_list: vec![],
            },
        );
        assert_eq!(ctx.mme_ue_find_by_id(mme_ue_id).unwrap().ics_pending_on, 0);
    }
}
