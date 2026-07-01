//! S1AP Message Handling
//!
//! Port of src/mme/s1ap-handler.c - S1AP message handling functions.
//!
//! Incoming PDUs are decoded with `nextgcore_s1ap::decode_s1ap_pdu` (real APER per
//! TS 36.413) and dispatched by message type. Each handler updates the MME
//! context and returns the S1AP PDUs to transmit (responses may target a
//! different eNB than the origin, e.g. during S1 handover).

use crate::context::{
    ECgi, EpsTai, MmeContext, PagingType, S1apCause, S1apCauseGroup, UeCtxRelAction,
    INVALID_UE_S1AP_ID, NEXTGCORE_INVALID_POOL_ID,
};
use crate::s1ap_build::{
    self, cause_from_s1ap, decode_plmn_id, ecgi_from_s1ap, misc_cause, protocol_cause,
    radio_network_cause, tai_from_s1ap, transport_address_to_ip, ue_security_capabilities_from,
};
use nextgcore_s1ap::{
    builder, decode_s1ap_pdu, Cause, EnbId, ErabSwitchedItem, ErabToBeSetupItemHoReq,
    HandoverCancel, HandoverCancelAcknowledge, HandoverCommand, HandoverFailure, HandoverNotify,
    HandoverPreparationFailure, HandoverRequest, HandoverRequestAcknowledge, HandoverRequired,
    HandoverType as S1apHandoverType, InitialContextSetupResponse, InitialUeMessage,
    NasNonDeliveryIndication, PathSwitchRequest, PathSwitchRequestAcknowledge,
    PathSwitchRequestFailure, Reset, ResetAcknowledge, ResetType, S1SetupRequest, S1apMessage,
    SecurityContext, TargetId, TimeToWait, UeAmbr, UeCapabilityInfoIndication,
    UeContextReleaseComplete, UeContextReleaseRequest, UlNasTransport,
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

// ============================================================================
// Top-Level Dispatch
// ============================================================================

/// Decode an incoming S1AP PDU from `enb_id` and dispatch it to the matching
/// procedure handler. Returns the PDUs to transmit in response.
pub fn handle_s1ap_message(ctx: &MmeContext, enb_id: u64, data: &[u8]) -> Vec<S1apSend> {
    let message = match decode_s1ap_pdu(data) {
        Ok(message) => message,
        Err(e) => {
            log::error!("Failed to decode S1AP PDU from eNB {enb_id}: {e}");
            return error_indication(
                enb_id,
                None,
                None,
                S1apCauseGroup::Protocol,
                protocol_cause::TRANSFER_SYNTAX_ERROR,
            );
        }
    };

    match message {
        S1apMessage::S1SetupRequest(msg) => handle_s1_setup_request(ctx, enb_id, &msg),
        S1apMessage::InitialUeMessage(msg) => {
            handle_initial_ue_message(ctx, enb_id, &msg);
            Vec::new()
        }
        S1apMessage::UplinkNasTransport(msg) => {
            handle_uplink_nas_transport(ctx, enb_id, &msg);
            Vec::new()
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
            log::warn!(
                "Error Indication from eNB {enb_id}: mme_ue={:?} enb_ue={:?} cause={:?}",
                msg.mme_ue_s1ap_id,
                msg.enb_ue_s1ap_id,
                msg.cause
            );
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
        S1apMessage::PathSwitchRequest(msg) => handle_path_switch_request(ctx, enb_id, &msg),
        S1apMessage::InitialContextSetupResponse(msg) => {
            handle_initial_context_setup_response(ctx, enb_id, &msg);
            Vec::new()
        }
        S1apMessage::InitialContextSetupFailure(msg) => {
            log::error!(
                "Initial Context Setup Failure from eNB {enb_id}: mme_ue={} cause={:?}",
                msg.mme_ue_s1ap_id,
                msg.cause
            );
            Vec::new()
        }
        S1apMessage::ErabSetupResponse(msg) => {
            handle_erab_setup_response(ctx, enb_id, msg.mme_ue_s1ap_id, &msg.erab_setup_list);
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
        // MME-originated messages arriving at the MME are a protocol error
        S1apMessage::DownlinkNasTransport(_)
        | S1apMessage::InitialContextSetupRequest(_)
        | S1apMessage::UeContextReleaseCommand(_)
        | S1apMessage::ErabSetupRequest(_)
        | S1apMessage::ErabModifyRequest(_)
        | S1apMessage::ErabReleaseCommand(_)
        | S1apMessage::Paging(_)
        | S1apMessage::S1SetupResponse(_)
        | S1apMessage::S1SetupFailure(_)
        | S1apMessage::HandoverRequest(_)
        | S1apMessage::HandoverCommand(_)
        | S1apMessage::HandoverPreparationFailure(_)
        | S1apMessage::PathSwitchRequestAcknowledge(_)
        | S1apMessage::PathSwitchRequestFailure(_)
        | S1apMessage::HandoverCancelAcknowledge(_) => {
            log::error!("MME-originated S1AP message received from eNB {enb_id}");
            error_indication(
                enb_id,
                None,
                None,
                S1apCauseGroup::Protocol,
                protocol_cause::MESSAGE_NOT_COMPATIBLE_WITH_RECEIVER_STATE,
            )
        }
        S1apMessage::Unknown {
            procedure_code,
            message_type,
        } => {
            log::error!(
                "Unknown S1AP {message_type} (procedure code {procedure_code}) from eNB {enb_id}"
            );
            error_indication(
                enb_id,
                None,
                None,
                S1apCauseGroup::Protocol,
                protocol_cause::ABSTRACT_SYNTAX_ERROR_REJECT,
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
    match s1ap_build::build_error_indication(enb_ue_s1ap_id, mme_ue_s1ap_id, group, value) {
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
    let enb_id_value = match msg.global_enb_id.enb_id {
        EnbId::Macro(id) => id,
        EnbId::Home(id) => id,
    };

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

    ctx.enb_set_enb_id(enb_id, enb_id_value);
    if let Some(enb) = ctx.enb_pool.write().unwrap().get_mut(&enb_id) {
        enb.plmn_id = decode_plmn_id(&msg.global_enb_id.plmn_identity);
        enb.supported_ta_list = supported_tais;
        enb.state.s1_setup_success = true;
    }

    log::info!(
        "S1 Setup: eNB 0x{enb_id_value:x} ({}) accepted",
        msg.enb_name.as_deref().unwrap_or("unnamed")
    );

    match s1ap_build::build_setup_response(ctx) {
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
// NAS Transport (§8.6)
// ============================================================================

/// Handle Initial UE Message: allocate the eNB UE context and record the
/// UE's location. Returns the eNB UE pool ID for the NAS layer.
pub fn handle_initial_ue_message(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &InitialUeMessage,
) -> Option<u64> {
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

/// Handle Uplink NAS Transport: refresh the UE's location and hand the NAS
/// PDU to the NAS layer. Returns the MME UE pool ID when the UE is known.
pub fn handle_uplink_nas_transport(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &UlNasTransport,
) -> Option<u64> {
    let enb_ue_id = ctx.enb_ue_find_by_mme_ue_s1ap_id(msg.mme_ue_s1ap_id)?;
    let enb_ue = ctx.enb_ue_find_by_id(enb_ue_id)?;
    if enb_ue.enb_id != enb_id {
        log::warn!(
            "Uplink NAS Transport for mme_ue_s1ap_id={} arrived from unexpected eNB {enb_id}",
            msg.mme_ue_s1ap_id
        );
    }

    let tai = tai_from_s1ap(&msg.tai);
    let e_cgi = ecgi_from_s1ap(&msg.eutran_cgi);
    update_ue_location(ctx, enb_ue.mme_ue_id, &tai, &e_cgi);

    log::debug!(
        "Uplink NAS Transport: mme_ue_s1ap_id={} nas_len={}",
        msg.mme_ue_s1ap_id,
        msg.nas_pdu.len()
    );
    (enb_ue.mme_ue_id != NEXTGCORE_INVALID_POOL_ID).then_some(enb_ue.mme_ue_id)
}

/// Handle NAS Non Delivery Indication (TS 36.413 §8.6.4).
///
/// The NAS PDU could not be delivered over the radio. The MME logs the cause
/// and, when the failed PDU was paging-triggered, marks the paging procedure
/// failed so it is re-attempted on the next downlink trigger.
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

    let Some(enb_ue_id) = ctx.enb_ue_find_by_mme_ue_s1ap_id(msg.mme_ue_s1ap_id) else {
        log::warn!(
            "NAS Non Delivery Indication for unknown mme_ue_s1ap_id={}",
            msg.mme_ue_s1ap_id
        );
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
    let Some(enb_ue_id) = ctx.enb_ue_find_by_mme_ue_s1ap_id(msg.mme_ue_s1ap_id) else {
        return error_indication(
            enb_id,
            Some(msg.enb_ue_s1ap_id),
            Some(msg.mme_ue_s1ap_id),
            S1apCauseGroup::RadioNetwork,
            radio_network_cause::UNKNOWN_MME_UE_S1AP_ID,
        );
    };

    let cause = cause_from_s1ap(&msg.cause);
    if let Some(enb_ue) = ctx.enb_ue_pool.write().unwrap().get_mut(&enb_ue_id) {
        enb_ue.relcause.group = cause.group;
        enb_ue.relcause.cause = cause.cause;
        enb_ue.ue_ctx_rel_action = UeCtxRelAction::S1ContextRemove;
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

/// Handle UE Context Release Complete: tear down the eNB UE context.
pub fn handle_ue_context_release_complete(
    ctx: &MmeContext,
    _enb_id: u64,
    msg: &UeContextReleaseComplete,
) {
    let Some(enb_ue_id) = ctx.enb_ue_find_by_mme_ue_s1ap_id(msg.mme_ue_s1ap_id) else {
        log::warn!(
            "UE Context Release Complete for unknown mme_ue_s1ap_id={}",
            msg.mme_ue_s1ap_id
        );
        return;
    };
    release_s1_connection(ctx, enb_ue_id);
    log::debug!("UE Context released: mme_ue_s1ap_id={}", msg.mme_ue_s1ap_id);
}

// ============================================================================
// Reset (§8.7.1)
// ============================================================================

/// Handle Reset: clear the affected UE-associated logical S1 connections and
/// answer with Reset Acknowledge (echoing the partial connection list).
pub fn handle_reset(ctx: &MmeContext, enb_id: u64, msg: &Reset) -> Vec<S1apSend> {
    log::warn!("Reset from eNB {enb_id}: cause={:?}", msg.cause);

    let acked_connections = match &msg.reset_type {
        ResetType::S1Interface => {
            // Release every UE-associated logical S1 connection on this eNB
            let affected: Vec<u64> = ctx
                .enb_ue_pool
                .read()
                .unwrap()
                .iter()
                .filter(|(_, ue)| ue.enb_id == enb_id)
                .map(|(id, _)| *id)
                .collect();
            for enb_ue_id in affected {
                release_s1_connection(ctx, enb_ue_id);
            }
            Vec::new()
        }
        ResetType::PartOfS1Interface(connections) => {
            for conn in connections {
                let enb_ue_id = conn
                    .mme_ue_s1ap_id
                    .and_then(|id| ctx.enb_ue_find_by_mme_ue_s1ap_id(id))
                    .or_else(|| {
                        conn.enb_ue_s1ap_id.and_then(|id| {
                            ctx.enb_ue_pool
                                .read()
                                .unwrap()
                                .iter()
                                .find(|(_, ue)| ue.enb_id == enb_id && ue.enb_ue_s1ap_id == id)
                                .map(|(pool_id, _)| *pool_id)
                        })
                    });
                if let Some(enb_ue_id) = enb_ue_id {
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

    match builder::build_reset_acknowledge(&ResetAcknowledge {
        ue_associated_connections: acked_connections,
    }) {
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
fn release_s1_connection(ctx: &MmeContext, enb_ue_id: u64) {
    if let Some(enb_ue) = ctx.enb_ue_find_by_id(enb_ue_id) {
        if enb_ue.mme_ue_id != NEXTGCORE_INVALID_POOL_ID {
            let still_attached = ctx
                .mme_ue_find_by_id(enb_ue.mme_ue_id)
                .is_some_and(|mme_ue| mme_ue.enb_ue_id == enb_ue_id);
            if still_attached {
                ctx.enb_ue_deassociate_mme_ue(enb_ue_id, enb_ue.mme_ue_id);
            }
        }
    }
    ctx.enb_ue_remove(enb_ue_id);
}

// ============================================================================
// UE Capability Info Indication (§8.10)
// ============================================================================

/// Handle UE Capability Info Indication: store the UE radio capability in
/// the MME UE context for later Handover Requests / context transfers.
pub fn handle_ue_capability_info_indication(
    ctx: &MmeContext,
    _enb_id: u64,
    msg: &UeCapabilityInfoIndication,
) {
    let Some(enb_ue_id) = ctx.enb_ue_find_by_mme_ue_s1ap_id(msg.mme_ue_s1ap_id) else {
        log::warn!(
            "UE Capability Info Indication for unknown mme_ue_s1ap_id={}",
            msg.mme_ue_s1ap_id
        );
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
    let Some(source_ue_id) = ctx.enb_ue_find_by_mme_ue_s1ap_id(msg.mme_ue_s1ap_id) else {
        return handover_preparation_failure(
            enb_id,
            msg.mme_ue_s1ap_id,
            msg.enb_ue_s1ap_id,
            radio_network_cause::UNKNOWN_MME_UE_S1AP_ID,
        );
    };
    let Some(source_ue) = ctx.enb_ue_find_by_id(source_ue_id) else {
        return handover_preparation_failure(
            enb_id,
            msg.mme_ue_s1ap_id,
            msg.enb_ue_s1ap_id,
            radio_network_cause::UNKNOWN_MME_UE_S1AP_ID,
        );
    };

    // Resolve the target eNB (only intra-LTE targets are supported)
    let target_enb_pool_id = match &msg.target_id {
        TargetId::TargetEnbId { global_enb_id, .. } => {
            let id = match global_enb_id.enb_id {
                EnbId::Macro(id) => id,
                EnbId::Home(id) => id,
            };
            ctx.enb_find_by_enb_id(id)
        }
        TargetId::TargetRncId { .. } | TargetId::Cgi { .. } => None,
    };
    let Some(target_enb_pool_id) = target_enb_pool_id else {
        return handover_preparation_failure(
            enb_id,
            msg.mme_ue_s1ap_id,
            msg.enb_ue_s1ap_id,
            radio_network_cause::UNKNOWN_TARGET_ID,
        );
    };

    let Some(mme_ue) = ctx.mme_ue_find_by_id(source_ue.mme_ue_id) else {
        return handover_preparation_failure(
            enb_id,
            msg.mme_ue_s1ap_id,
            msg.enb_ue_s1ap_id,
            radio_network_cause::UNKNOWN_MME_UE_S1AP_ID,
        );
    };

    // Allocate the target eNB UE context (eNB UE S1AP ID arrives in the Ack)
    let target_ue_id = ctx.enb_ue_add(target_enb_pool_id, INVALID_UE_S1AP_ID);
    let target_mme_ue_s1ap_id = {
        let mut pool = ctx.enb_ue_pool.write().unwrap();
        if let Some(source) = pool.get_mut(&source_ue_id) {
            source.target_ue_id = target_ue_id;
            source.handover_type = ho_type_from_s1ap(msg.handover_type);
        }
        if let Some(target) = pool.get_mut(&target_ue_id) {
            target.source_ue_id = source_ue_id;
            target.mme_ue_id = source_ue.mme_ue_id;
            target.handover_type = ho_type_from_s1ap(msg.handover_type);
            target.mme_ue_s1ap_id
        } else {
            return handover_preparation_failure(
                enb_id,
                msg.mme_ue_s1ap_id,
                msg.enb_ue_s1ap_id,
                radio_network_cause::UNSPECIFIED,
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
        );
    }

    let request = HandoverRequest {
        mme_ue_s1ap_id: target_mme_ue_s1ap_id,
        handover_type: msg.handover_type,
        cause: msg.cause,
        ue_ambr: UeAmbr {
            dl: mme_ue.ambr.downlink,
            ul: mme_ue.ambr.uplink,
        },
        erab_list,
        source_to_target_container: msg.source_to_target_container.clone(),
        ue_security_capabilities: ue_security_capabilities_from(&mme_ue),
        security_context: SecurityContext {
            next_hop_chaining_count: ncc,
            next_hop_parameter: nh,
        },
    };

    match builder::build_handover_request(&request) {
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
            )
        }
    }
}

fn handover_preparation_failure(
    enb_id: u64,
    mme_ue_s1ap_id: u32,
    enb_ue_s1ap_id: u32,
    cause_value: i64,
) -> Vec<S1apSend> {
    let failure = HandoverPreparationFailure {
        mme_ue_s1ap_id,
        enb_ue_s1ap_id,
        cause: s1ap_build::cause_to_s1ap(S1apCauseGroup::RadioNetwork, cause_value),
    };
    match builder::build_handover_preparation_failure(&failure) {
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
    _enb_id: u64,
    msg: &HandoverRequestAcknowledge,
) -> Vec<S1apSend> {
    let Some(target_ue_id) = ctx.enb_ue_find_by_mme_ue_s1ap_id(msg.mme_ue_s1ap_id) else {
        log::error!(
            "Handover Request Acknowledge for unknown mme_ue_s1ap_id={}",
            msg.mme_ue_s1ap_id
        );
        return Vec::new();
    };

    let target_ue = {
        let mut pool = ctx.enb_ue_pool.write().unwrap();
        let Some(target) = pool.get_mut(&target_ue_id) else {
            return Vec::new();
        };
        target.enb_ue_s1ap_id = msg.enb_ue_s1ap_id;
        target.clone()
    };

    // Record the admitted DL endpoints on the bearer contexts
    for item in &msg.erab_admitted_list {
        if let Some(bearer_id) = ctx.bearer_find_by_ebi(target_ue.mme_ue_id, item.erab_id) {
            if let Some(bearer) = ctx.bearer_pool.write().unwrap().get_mut(&bearer_id) {
                bearer.target_s1u_teid = item.gtp_teid;
                bearer.target_s1u_ip = transport_address_to_ip(&item.transport_layer_address);
            }
        }
    }

    let Some(source_ue) = ctx.enb_ue_find_by_id(target_ue.source_ue_id) else {
        log::error!("Handover Request Acknowledge without a linked source UE");
        return Vec::new();
    };

    let command = HandoverCommand {
        mme_ue_s1ap_id: source_ue.mme_ue_s1ap_id,
        enb_ue_s1ap_id: source_ue.enb_ue_s1ap_id,
        handover_type: ho_type_to_s1ap(target_ue.handover_type),
        erab_subject_to_forwarding_list: Vec::new(),
        erab_to_release_list: msg
            .erab_failed_list
            .iter()
            .map(|item| nextgcore_s1ap::ErabItem {
                erab_id: item.erab_id,
                cause: item.cause,
            })
            .collect(),
        target_to_source_container: msg.target_to_source_container.clone(),
    };

    match builder::build_handover_command(&command) {
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

/// Handle Handover Failure from the target eNB: free the target context and
/// answer the source eNB with Handover Preparation Failure.
pub fn handle_handover_failure(
    ctx: &MmeContext,
    _enb_id: u64,
    msg: &HandoverFailure,
) -> Vec<S1apSend> {
    let Some(target_ue_id) = ctx.enb_ue_find_by_mme_ue_s1ap_id(msg.mme_ue_s1ap_id) else {
        log::error!(
            "Handover Failure for unknown mme_ue_s1ap_id={}",
            msg.mme_ue_s1ap_id
        );
        return Vec::new();
    };
    let Some(target_ue) = ctx.enb_ue_find_by_id(target_ue_id) else {
        return Vec::new();
    };
    ctx.enb_ue_remove(target_ue_id);

    let Some(source_ue) = ctx.enb_ue_find_by_id(target_ue.source_ue_id) else {
        return Vec::new();
    };
    if let Some(source) = ctx.enb_ue_pool.write().unwrap().get_mut(&source_ue.id) {
        source.target_ue_id = NEXTGCORE_INVALID_POOL_ID;
    }

    let failure = HandoverPreparationFailure {
        mme_ue_s1ap_id: source_ue.mme_ue_s1ap_id,
        enb_ue_s1ap_id: source_ue.enb_ue_s1ap_id,
        cause: msg.cause,
    };
    match builder::build_handover_preparation_failure(&failure) {
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
    _enb_id: u64,
    msg: &HandoverNotify,
) -> Vec<S1apSend> {
    let Some(target_ue_id) = ctx.enb_ue_find_by_mme_ue_s1ap_id(msg.mme_ue_s1ap_id) else {
        log::error!(
            "Handover Notify for unknown mme_ue_s1ap_id={}",
            msg.mme_ue_s1ap_id
        );
        return Vec::new();
    };
    let Some(target_ue) = ctx.enb_ue_find_by_id(target_ue_id) else {
        return Vec::new();
    };

    let tai = tai_from_s1ap(&msg.tai);
    let e_cgi = ecgi_from_s1ap(&msg.eutran_cgi);
    update_ue_location(ctx, target_ue.mme_ue_id, &tai, &e_cgi);

    // Switch the bearers onto the target eNB endpoints
    for bearer_id in ue_bearers(ctx, target_ue.mme_ue_id).iter().map(|b| b.id) {
        if let Some(bearer) = ctx.bearer_pool.write().unwrap().get_mut(&bearer_id) {
            if bearer.target_s1u_teid != 0 {
                bearer.enb_s1u_teid = bearer.target_s1u_teid;
                bearer.enb_s1u_ip = bearer.target_s1u_ip.clone();
                bearer.target_s1u_teid = 0;
                bearer.target_s1u_ip = Default::default();
            }
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

/// Handle Handover Cancel from the source eNB: free the target context and
/// answer with Handover Cancel Acknowledge.
pub fn handle_handover_cancel(
    ctx: &MmeContext,
    enb_id: u64,
    msg: &HandoverCancel,
) -> Vec<S1apSend> {
    let Some(source_ue_id) = ctx.enb_ue_find_by_mme_ue_s1ap_id(msg.mme_ue_s1ap_id) else {
        return error_indication(
            enb_id,
            Some(msg.enb_ue_s1ap_id),
            Some(msg.mme_ue_s1ap_id),
            S1apCauseGroup::RadioNetwork,
            radio_network_cause::UNKNOWN_MME_UE_S1AP_ID,
        );
    };

    let target_ue_id = {
        let mut pool = ctx.enb_ue_pool.write().unwrap();
        match pool.get_mut(&source_ue_id) {
            Some(source) => {
                let target = source.target_ue_id;
                source.target_ue_id = NEXTGCORE_INVALID_POOL_ID;
                target
            }
            None => NEXTGCORE_INVALID_POOL_ID,
        }
    };
    if target_ue_id != NEXTGCORE_INVALID_POOL_ID {
        ctx.enb_ue_remove(target_ue_id);
    }

    log::info!(
        "Handover Cancel: mme_ue_s1ap_id={} cause={:?}",
        msg.mme_ue_s1ap_id,
        msg.cause
    );

    match builder::build_handover_cancel_acknowledge(&HandoverCancelAcknowledge {
        mme_ue_s1ap_id: msg.mme_ue_s1ap_id,
        enb_ue_s1ap_id: msg.enb_ue_s1ap_id,
    }) {
        Ok(pdu) => S1apSend::to_origin(enb_id, pdu),
        Err(e) => {
            log::error!("Failed to build Handover Cancel Acknowledge: {e}");
            Vec::new()
        }
    }
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
    let Some(enb_ue_id) = ctx.enb_ue_find_by_mme_ue_s1ap_id(msg.source_mme_ue_s1ap_id) else {
        return path_switch_failure(
            enb_id,
            msg.source_mme_ue_s1ap_id,
            msg.enb_ue_s1ap_id,
            radio_network_cause::UNKNOWN_MME_UE_S1AP_ID,
        );
    };

    let tai = tai_from_s1ap(&msg.tai);
    let e_cgi = ecgi_from_s1ap(&msg.eutran_cgi);

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
        enb_ue.saved.tai = tai.clone();
        enb_ue.saved.e_cgi = e_cgi.clone();
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
    if msg.ue_security_capabilities != expected {
        log::warn!(
            "[{}] Path Switch Request: UE security capabilities mismatch \
             (got enc=0x{:04x}/int=0x{:04x}, expected enc=0x{:04x}/int=0x{:04x})",
            mme_ue.imsi_bcd,
            msg.ue_security_capabilities.encryption_algorithms,
            msg.ue_security_capabilities.integrity_algorithms,
            expected.encryption_algorithms,
            expected.integrity_algorithms
        );
    }

    update_ue_location(ctx, mme_ue_id, &tai, &e_cgi);

    // Switch the downlink endpoints to the new eNB
    for item in &msg.erab_switched_dl_list {
        if let Some(bearer_id) = ctx.bearer_find_by_ebi(mme_ue_id, item.erab_id) {
            if let Some(bearer) = ctx.bearer_pool.write().unwrap().get_mut(&bearer_id) {
                bearer.enb_s1u_teid = item.gtp_teid;
                bearer.enb_s1u_ip = transport_address_to_ip(&item.transport_layer_address);
            }
        } else {
            log::warn!(
                "[{}] Path Switch Request for unknown E-RAB {}",
                mme_ue.imsi_bcd,
                item.erab_id
            );
        }
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

    let erab_switched_ul_list: Vec<ErabSwitchedItem> = ue_bearers(ctx, mme_ue_id)
        .iter()
        .filter(|bearer| bearer.sgw_s1u_teid != 0)
        .map(|bearer| ErabSwitchedItem {
            erab_id: bearer.ebi,
            transport_layer_address: s1ap_build::ip_to_transport_address(&bearer.sgw_s1u_ip),
            gtp_teid: bearer.sgw_s1u_teid,
        })
        .collect();

    let ack = PathSwitchRequestAcknowledge {
        mme_ue_s1ap_id: msg.source_mme_ue_s1ap_id,
        enb_ue_s1ap_id: msg.enb_ue_s1ap_id,
        erab_switched_ul_list,
        security_context: SecurityContext {
            next_hop_chaining_count: ncc,
            next_hop_parameter: nh,
        },
    };

    match builder::build_path_switch_request_acknowledge(&ack) {
        Ok(pdu) => S1apSend::to_origin(enb_id, pdu),
        Err(e) => {
            log::error!("Failed to build Path Switch Request Acknowledge: {e}");
            Vec::new()
        }
    }
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
    match builder::build_path_switch_request_failure(&failure) {
        Ok(pdu) => S1apSend::to_origin(enb_id, pdu),
        Err(e) => {
            log::error!("Failed to build Path Switch Request Failure: {e}");
            Vec::new()
        }
    }
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
    let Some(enb_ue_id) = ctx.enb_ue_find_by_mme_ue_s1ap_id(msg.mme_ue_s1ap_id) else {
        log::warn!(
            "Initial Context Setup Response for unknown mme_ue_s1ap_id={}",
            msg.mme_ue_s1ap_id
        );
        return;
    };
    let Some(enb_ue) = ctx.enb_ue_find_by_id(enb_ue_id) else {
        return;
    };

    for item in &msg.erab_setup_list {
        if let Some(bearer_id) = ctx.bearer_find_by_ebi(enb_ue.mme_ue_id, item.erab_id) {
            if let Some(bearer) = ctx.bearer_pool.write().unwrap().get_mut(&bearer_id) {
                bearer.enb_s1u_teid = item.gtp_teid;
                bearer.enb_s1u_ip = transport_address_to_ip(&item.transport_layer_address);
            }
        }
    }
    log_erab_failures(enb_id, &msg.erab_failed_list);
}

fn handle_erab_setup_response(
    ctx: &MmeContext,
    _enb_id: u64,
    mme_ue_s1ap_id: u32,
    erab_setup_list: &[nextgcore_s1ap::ErabSetupItem],
) {
    let Some(enb_ue_id) = ctx.enb_ue_find_by_mme_ue_s1ap_id(mme_ue_s1ap_id) else {
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
    }
}

/// Map the context Handover Type onto the S1AP representation.
/// 5GS interworking types never reach the S1AP handover path.
fn ho_type_to_s1ap(handover_type: crate::context::HandoverType) -> S1apHandoverType {
    match handover_type {
        crate::context::HandoverType::IntraLte
        | crate::context::HandoverType::EpsTo5gs
        | crate::context::HandoverType::FiveGsToEps => S1apHandoverType::IntraLte,
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
    use nextgcore_s1ap::{
        CauseRadioNetwork, GlobalEnbId, STmsi, SupportedTaItem, UeAssociatedLogicalS1Connection,
        UeSecurityCapabilities,
    };

    fn test_ctx() -> MmeContext {
        let ctx = MmeContext::new();
        ctx.init();
        ctx
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

    #[test]
    fn test_path_switch_request_acknowledged_with_fresh_security_context() {
        let ctx = ctx_with_gummei();
        let (_, _, mme_ue_id, mme_ue_s1ap_id) = add_ue(&ctx);
        // Provision one bearer with the SGW UL endpoint
        let bearer_id = ctx.bearer_add(0, mme_ue_id);
        {
            let mut pool = ctx.bearer_pool.write().unwrap();
            let bearer = pool.get_mut(&bearer_id).unwrap();
            bearer.ebi = 5;
            bearer.sgw_s1u_teid = 0x5555;
            bearer.sgw_s1u_ip.ipv4 = Some([10, 0, 0, 2]);
        }
        // The UE moved to a new eNB via X2
        let new_enb_id = ctx.enb_add("127.0.0.9:36412".parse().unwrap());

        let psr = PathSwitchRequest {
            enb_ue_s1ap_id: 200,
            erab_switched_dl_list: vec![ErabSwitchedItem {
                erab_id: 5,
                transport_layer_address: vec![10, 0, 0, 9],
                gtp_teid: 0x9999,
            }],
            source_mme_ue_s1ap_id: mme_ue_s1ap_id,
            eutran_cgi: nextgcore_s1ap::EutranCgi {
                plmn_identity: s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
                cell_identity: 0x42,
            },
            tai: nextgcore_s1ap::Tai {
                plmn_identity: s1ap_build::encode_plmn_id(&PlmnId::new("310", "410")),
                tac: 2,
            },
            ue_security_capabilities: UeSecurityCapabilities {
                encryption_algorithms: 0xE000,
                integrity_algorithms: 0xE000,
            },
        };
        let bytes = builder::build_path_switch_request(&psr).unwrap();

        let out = handle_s1ap_message(&ctx, new_enb_id, &bytes);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].enb_id, new_enb_id);
        match decode_s1ap_pdu(&out[0].pdu).unwrap() {
            S1apMessage::PathSwitchRequestAcknowledge(ack) => {
                assert_eq!(ack.mme_ue_s1ap_id, mme_ue_s1ap_id);
                assert_eq!(ack.enb_ue_s1ap_id, 200);
                // Fresh security context: NCC advanced from 0 to 1, NH
                // derived from KeNB per TS 33.401 Annex A.4
                assert_eq!(ack.security_context.next_hop_chaining_count, 1);
                let expected_nh =
                    nextgcore_crypt::kdf::nextgcore_kdf_nh_enb(&[0x11; 32], &[0x22; 32]);
                assert_eq!(ack.security_context.next_hop_parameter, expected_nh);
                assert_eq!(ack.erab_switched_ul_list.len(), 1);
                assert_eq!(ack.erab_switched_ul_list[0].gtp_teid, 0x5555);
            }
            other => panic!("expected PathSwitchRequestAcknowledge, got {other:?}"),
        }

        // DL bearer switched onto the new eNB endpoint
        let bearer = ctx.bearer_find_by_id(bearer_id).unwrap();
        assert_eq!(bearer.enb_s1u_teid, 0x9999);
        assert_eq!(bearer.enb_s1u_ip.ipv4, Some([10, 0, 0, 9]));

        // NCC state persisted on the UE context
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(mme_ue.nhcc, 1);

        // Location updated
        assert_eq!(mme_ue.tai.tac, 2);
        assert_eq!(mme_ue.e_cgi.cell_id, 0x42);
    }

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
        ctx.enb_set_enb_id(target_enb_id, 0x2222);

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
        ctx.enb_set_enb_id(target_enb_id, 0x2222);

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

        // Bearer switched onto the admitted target endpoint
        let bearer = ctx.bearer_find_by_id(bearer_id).unwrap();
        assert_eq!(bearer.enb_s1u_teid, 0x8888);
        assert_eq!(bearer.enb_s1u_ip.ipv4, Some([10, 0, 0, 8]));
        assert_eq!(bearer.target_s1u_teid, 0);

        // The UE now lives on the target connection
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_ne!(mme_ue.enb_ue_id, source_ue_id);
        // Source release action recorded for the release procedure
        let source_ue = ctx.enb_ue_find_by_id(source_ue_id).unwrap();
        assert_eq!(
            source_ue.ue_ctx_rel_action,
            UeCtxRelAction::S1HandoverComplete
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
}
