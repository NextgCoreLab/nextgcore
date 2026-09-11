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
use crate::nas_dispatch;
use crate::s1ap_build::{
    self, cause_from_s1ap, decode_plmn_id, ecgi_from_s1ap, misc_cause, protocol_cause,
    radio_network_cause, tai_from_s1ap, transport_address_to_ip, ue_security_capabilities_from,
};
use nextgcore_s1ap::{
    builder, decode_s1ap_pdu, BroadcastCancelledAreaList, BroadcastCompletedAreaList, Cause,
    CauseRadioNetwork, CriticalityDiagnostics, EnbConfigurationUpdate, EnbId, EnbStatusTransfer,
    ErabDataForwardingItem, ErabSwitchedItem, ErabToBeSetupItemHoReq, ErrorIndication,
    HandoverCancel, HandoverCancelAcknowledge, HandoverCommand, HandoverFailure, HandoverNotify,
    HandoverPreparationFailure, HandoverRequest, HandoverRequestAcknowledge, HandoverRequired,
    HandoverType as S1apHandoverType, InitialContextSetupFailure, InitialContextSetupResponse,
    InitialUeMessage, KillResponse, MmeStatusTransfer, NasNonDeliveryIndication, PathSwitchRequest,
    PathSwitchRequestAcknowledge, PathSwitchRequestFailure, Reset, ResetAcknowledge, ResetType,
    S1SetupRequest, S1apMessage, SecurityContext, TargetId, TimeToWait, UeAmbr,
    UeCapabilityInfoIndication, UeContextReleaseComplete, UeContextReleaseRequest, UlNasTransport,
    WriteReplaceWarningResponse,
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

/// Decode an incoming S1AP PDU from `enb_id` and dispatch it to the matching
/// procedure handler. Returns the PDUs to transmit in response.
pub fn handle_s1ap_message(ctx: &MmeContext, enb_id: u64, data: &[u8]) -> Vec<S1apSend> {
    let message = match decode_s1ap_pdu(data) {
        Ok(message) => message,
        Err(e) => {
            log::error!("Failed to decode S1AP PDU from eNB {enb_id}: {e}");
            // The PDU did not decode, so its procedure code is unknown; the
            // diagnostics can still say that an initiating message was what
            // failed, which is more than the bare cause conveys.
            return error_indication_with_diagnostics(
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
            );
        }
    };

    match message {
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
                Some(enb_ue_id) => {
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
                None => error_indication(
                    enb_id,
                    Some(msg.enb_ue_s1ap_id),
                    Some(msg.mme_ue_s1ap_id),
                    S1apCauseGroup::RadioNetwork,
                    radio_network_cause::UNKNOWN_MME_UE_S1AP_ID,
                ),
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
        | S1apMessage::HandoverCancelAcknowledge(_)
        | S1apMessage::MmeStatusTransfer(_)
        | S1apMessage::MmeConfigurationUpdate(_)
        | S1apMessage::EnbConfigurationUpdateAcknowledge(_)
        | S1apMessage::EnbConfigurationUpdateFailure(_)
        | S1apMessage::UeContextModificationRequest(_)
        | S1apMessage::OverloadStart(_)
        | S1apMessage::OverloadStop(_)
        | S1apMessage::WriteReplaceWarningRequest(_)
        | S1apMessage::KillRequest(_) => {
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
            error_indication_with_diagnostics(
                enb_id,
                None,
                None,
                S1apCauseGroup::Protocol,
                protocol_cause::ABSTRACT_SYNTAX_ERROR_REJECT,
                Some(CriticalityDiagnostics {
                    procedure_code: Some(procedure_code),
                    triggering_message: Some(
                        nextgcore_s1ap::triggering_message::INITIATING_MESSAGE,
                    ),
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

    match s1ap_build::build_enb_configuration_update_acknowledge() {
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
    match s1ap_build::build_enb_configuration_update_failure(group, value, ttw) {
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
    Some(enb_ue_id)
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

    let Some(enb_ue_id) = ctx.enb_ue_find_by_mme_ue_s1ap_id(msg.mme_ue_s1ap_id) else {
        // Nothing of ours to release; tell the eNB its id means nothing here.
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
        enb_ue.ue_ctx_rel_action = UeCtxRelAction::UeContextRemove;
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

    let Some(mme_ue_s1ap_id) = msg.mme_ue_s1ap_id else {
        return;
    };
    let Some(enb_ue_id) = ctx.enb_ue_find_by_mme_ue_s1ap_id(mme_ue_s1ap_id) else {
        return;
    };

    log::info!(
        "eNB {enb_id} does not know mme_ue_s1ap_id={mme_ue_s1ap_id}; releasing the local S1 context"
    );
    release_s1_connection(ctx, enb_ue_id);
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
            release_all_s1_connections(ctx, enb_id);
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

    match builder::build_handover_command(&command) {
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
    let Some(source_ue_id) = ctx.enb_ue_find_by_mme_ue_s1ap_id(msg.mme_ue_s1ap_id) else {
        return error_indication(
            enb_id,
            Some(msg.enb_ue_s1ap_id),
            Some(msg.mme_ue_s1ap_id),
            S1apCauseGroup::RadioNetwork,
            radio_network_cause::UNKNOWN_MME_UE_S1AP_ID,
        );
    };
    let Some(source_ue) = ctx.enb_ue_find_by_id(source_ue_id) else {
        return error_indication(
            enb_id,
            Some(msg.enb_ue_s1ap_id),
            Some(msg.mme_ue_s1ap_id),
            S1apCauseGroup::RadioNetwork,
            radio_network_cause::UNKNOWN_MME_UE_S1AP_ID,
        );
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
    match builder::build_mme_status_transfer(&relay) {
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

    // #48: the UE arrived, so the preparation is no longer outstanding. Disarming here
    // rather than letting the deadline lapse harmlessly matters because the sweep would
    // otherwise release a target that is now SERVING the UE.
    {
        let mut pool = ctx.enb_ue_pool.write().unwrap();
        if let Some(target) = pool.get_mut(&target_ue_id) {
            target.handover_prep_deadline = None;
        }
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

    match builder::build_handover_cancel_acknowledge(&HandoverCancelAcknowledge {
        mme_ue_s1ap_id: msg.mme_ue_s1ap_id,
        enb_ue_s1ap_id: msg.enb_ue_s1ap_id,
    }) {
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

        let payload = vec![0x00, 0x01, 0xF0, 0x0D, 0x7F, 0x80, 0x2A];
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
}
