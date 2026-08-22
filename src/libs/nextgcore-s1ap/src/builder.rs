//! S1AP Message Builders
//!
//! Functions for building S1AP PDU messages from high-level types.
//! Each function constructs the IE container, wraps it in the appropriate
//! PDU wrapper (InitiatingMessage, SuccessfulOutcome, UnsuccessfulOutcome),
//! and APER-encodes it to bytes per 3GPP TS 36.413.

use nextgcore_asn1c::per::{AperEncode, AperEncoder};
use nextgcore_asn1c::s1ap::ies::ProtocolIeContainer;
use nextgcore_asn1c::s1ap::pdu::*;
use nextgcore_asn1c::s1ap::types::{Criticality, ProcedureCode, ProtocolIeId};

use crate::error::S1apResult;
use crate::ie;
use crate::types::*;

/// Encode an S1apPdu to APER bytes
fn encode_pdu(pdu: &S1apPdu) -> S1apResult<Vec<u8>> {
    let mut encoder = AperEncoder::new();
    pdu.encode_aper(&mut encoder)?;
    encoder.align();
    Ok(encoder.into_bytes().to_vec())
}

fn initiating(
    procedure_code: ProcedureCode,
    criticality: Criticality,
    value: InitiatingMessageValue,
) -> S1apPdu {
    S1apPdu::InitiatingMessage(InitiatingMessage {
        procedure_code,
        criticality,
        value,
    })
}

fn successful(
    procedure_code: ProcedureCode,
    criticality: Criticality,
    value: SuccessfulOutcomeValue,
) -> S1apPdu {
    S1apPdu::SuccessfulOutcome(SuccessfulOutcome {
        procedure_code,
        criticality,
        value,
    })
}

fn unsuccessful(
    procedure_code: ProcedureCode,
    criticality: Criticality,
    value: UnsuccessfulOutcomeValue,
) -> S1apPdu {
    S1apPdu::UnsuccessfulOutcome(UnsuccessfulOutcome {
        procedure_code,
        criticality,
        value,
    })
}

// ============================================================================
// S1 Setup Procedure (§8.7.3)
// ============================================================================

/// Build an S1 Setup Request PDU
pub fn build_s1_setup_request(msg: &S1SetupRequest) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: Global-ENB-ID (mandatory)
    ie::encode_global_enb_id(&mut container, &msg.global_enb_id)?;

    // IE: eNBname (optional)
    if let Some(ref name) = msg.enb_name {
        ie::encode_enb_name(&mut container, name)?;
    }

    // IE: SupportedTAs (mandatory)
    ie::encode_supported_tas(&mut container, &msg.supported_tas)?;

    // IE: DefaultPagingDRX (mandatory)
    ie::encode_default_paging_drx(&mut container, msg.default_paging_drx)?;

    encode_pdu(&initiating(
        ProcedureCode::S1_SETUP,
        Criticality::Reject,
        InitiatingMessageValue::S1SetupRequest(container),
    ))
}

/// Build an S1 Setup Response PDU
pub fn build_s1_setup_response(msg: &S1SetupResponse) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: MMEname (optional)
    if let Some(ref name) = msg.mme_name {
        ie::encode_mme_name(&mut container, name)?;
    }

    // IE: ServedGUMMEIs (mandatory)
    ie::encode_served_gummeis(&mut container, &msg.served_gummeis)?;

    // IE: RelativeMMECapacity (mandatory)
    ie::encode_relative_mme_capacity(&mut container, msg.relative_mme_capacity)?;

    encode_pdu(&successful(
        ProcedureCode::S1_SETUP,
        Criticality::Reject,
        SuccessfulOutcomeValue::S1SetupResponse(container),
    ))
}

/// Build an S1 Setup Failure PDU
pub fn build_s1_setup_failure(msg: &S1SetupFailure) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: Cause (mandatory)
    ie::encode_cause(&mut container, &msg.cause)?;

    // IE: TimeToWait (optional)
    if let Some(ttw) = msg.time_to_wait {
        ie::encode_time_to_wait(&mut container, ttw)?;
    }

    encode_pdu(&unsuccessful(
        ProcedureCode::S1_SETUP,
        Criticality::Reject,
        UnsuccessfulOutcomeValue::S1SetupFailure(container),
    ))
}

// ============================================================================
// NAS Transport Procedures (§8.6)
// ============================================================================

/// Build an Initial UE Message PDU
pub fn build_initial_ue_message(msg: &InitialUeMessage) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: eNB-UE-S1AP-ID (mandatory)
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Reject)?;

    // IE: NAS-PDU (mandatory)
    ie::encode_nas_pdu(&mut container, &msg.nas_pdu, Criticality::Reject)?;

    // IE: TAI (mandatory)
    ie::encode_tai(&mut container, &msg.tai, Criticality::Reject)?;

    // IE: EUTRAN-CGI (mandatory)
    ie::encode_eutran_cgi(&mut container, &msg.eutran_cgi)?;

    // IE: RRC-Establishment-Cause (mandatory)
    ie::encode_rrc_establishment_cause(&mut container, msg.rrc_establishment_cause)?;

    // IE: S-TMSI (optional)
    if let Some(ref s_tmsi) = msg.s_tmsi {
        ie::encode_s_tmsi(&mut container, s_tmsi)?;
    }

    encode_pdu(&initiating(
        ProcedureCode::INITIAL_UE_MESSAGE,
        Criticality::Ignore,
        InitiatingMessageValue::InitialUeMessage(container),
    ))
}

/// Build a Downlink NAS Transport PDU
pub fn build_downlink_nas_transport(msg: &DlNasTransport) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_nas_pdu(&mut container, &msg.nas_pdu, Criticality::Reject)?;

    encode_pdu(&initiating(
        ProcedureCode::DOWNLINK_NAS_TRANSPORT,
        Criticality::Ignore,
        InitiatingMessageValue::DownlinkNasTransport(container),
    ))
}

/// Build an Uplink NAS Transport PDU
pub fn build_uplink_nas_transport(msg: &UlNasTransport) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_nas_pdu(&mut container, &msg.nas_pdu, Criticality::Reject)?;
    ie::encode_eutran_cgi(&mut container, &msg.eutran_cgi)?;
    ie::encode_tai(&mut container, &msg.tai, Criticality::Ignore)?;

    encode_pdu(&initiating(
        ProcedureCode::UPLINK_NAS_TRANSPORT,
        Criticality::Ignore,
        InitiatingMessageValue::UplinkNasTransport(container),
    ))
}

/// Build a NAS Non Delivery Indication PDU
pub fn build_nas_non_delivery_indication(msg: &NasNonDeliveryIndication) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_nas_pdu(&mut container, &msg.nas_pdu, Criticality::Ignore)?;
    ie::encode_cause(&mut container, &msg.cause)?;

    encode_pdu(&initiating(
        ProcedureCode::NAS_NON_DELIVERY_INDICATION,
        Criticality::Ignore,
        InitiatingMessageValue::Other(container),
    ))
}

// ============================================================================
// Initial Context Setup Procedure (§8.3.1)
// ============================================================================

/// Build an Initial Context Setup Request PDU
pub fn build_initial_context_setup_request(
    msg: &InitialContextSetupRequest,
) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Reject)?;

    // IE: uEaggregateMaximumBitrate (mandatory)
    ie::encode_ue_ambr(&mut container, &msg.ue_ambr, Criticality::Reject)?;

    // IE: E-RABToBeSetupListCtxtSUReq (mandatory)
    ie::encode_erab_to_be_setup_list_ctxt(&mut container, &msg.erab_list)?;

    // IE: UESecurityCapabilities (mandatory)
    ie::encode_ue_security_capabilities(
        &mut container,
        &msg.ue_security_capabilities,
        Criticality::Reject,
    )?;

    // IE: SecurityKey (mandatory)
    ie::encode_security_key(&mut container, &msg.security_key)?;

    encode_pdu(&initiating(
        ProcedureCode::INITIAL_CONTEXT_SETUP,
        Criticality::Reject,
        InitiatingMessageValue::InitialContextSetupRequest(container),
    ))
}

/// Build an Initial Context Setup Response PDU
pub fn build_initial_context_setup_response(
    msg: &InitialContextSetupResponse,
) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Ignore)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Ignore)?;

    // IE: E-RABSetupListCtxtSURes (mandatory)
    ie::encode_erab_setup_list_ctxt_res(&mut container, &msg.erab_setup_list)?;

    // IE: E-RABFailedToSetupListCtxtSURes (optional)
    if !msg.erab_failed_list.is_empty() {
        let items: Vec<(u8, Cause)> = msg
            .erab_failed_list
            .iter()
            .map(|item| (item.erab_id, item.cause))
            .collect();
        ie::encode_erab_item_list(
            &mut container,
            ProtocolIeId::E_RAB_FAILED_TO_SETUP_LIST_CTXT_SU_RES,
            Criticality::Ignore,
            &items,
        )?;
    }

    encode_pdu(&successful(
        ProcedureCode::INITIAL_CONTEXT_SETUP,
        Criticality::Reject,
        SuccessfulOutcomeValue::InitialContextSetupResponse(container),
    ))
}

/// Build an Initial Context Setup Failure PDU
pub fn build_initial_context_setup_failure(
    msg: &InitialContextSetupFailure,
) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Ignore)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Ignore)?;
    ie::encode_cause(&mut container, &msg.cause)?;

    encode_pdu(&unsuccessful(
        ProcedureCode::INITIAL_CONTEXT_SETUP,
        Criticality::Reject,
        UnsuccessfulOutcomeValue::InitialContextSetupFailure(container),
    ))
}

// ============================================================================
// UE Context Release Procedures (§8.3.2-8.3.3)
// ============================================================================

/// Build a UE Context Release Request PDU (eNB-initiated)
pub fn build_ue_context_release_request(msg: &UeContextReleaseRequest) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_cause(&mut container, &msg.cause)?;

    encode_pdu(&initiating(
        ProcedureCode::UE_CONTEXT_RELEASE_REQUEST,
        Criticality::Ignore,
        InitiatingMessageValue::UeContextReleaseRequest(container),
    ))
}

/// Build a UE Context Release Command PDU
pub fn build_ue_context_release_command(msg: &UeContextReleaseCommand) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: UE-S1AP-IDs (mandatory)
    ie::encode_ue_s1ap_ids(&mut container, &msg.ue_s1ap_ids)?;

    // IE: Cause (mandatory)
    ie::encode_cause(&mut container, &msg.cause)?;

    encode_pdu(&initiating(
        ProcedureCode::UE_CONTEXT_RELEASE,
        Criticality::Reject,
        InitiatingMessageValue::UeContextReleaseCommand(container),
    ))
}

/// Build a UE Context Release Complete PDU
pub fn build_ue_context_release_complete(msg: &UeContextReleaseComplete) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Ignore)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Ignore)?;

    encode_pdu(&successful(
        ProcedureCode::UE_CONTEXT_RELEASE,
        Criticality::Reject,
        SuccessfulOutcomeValue::UeContextReleaseComplete(container),
    ))
}

// ============================================================================
// E-RAB Management Procedures (§8.2)
// ============================================================================

/// Build an E-RAB Setup Request PDU
pub fn build_erab_setup_request(msg: &ErabSetupRequest) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Reject)?;

    // IE: uEaggregateMaximumBitrate (optional)
    if let Some(ref ambr) = msg.ue_ambr {
        ie::encode_ue_ambr(&mut container, ambr, Criticality::Reject)?;
    }

    // IE: E-RABToBeSetupListBearerSUReq (mandatory; NAS-PDU mandatory per item)
    ie::encode_erab_to_be_setup_list_bearer(&mut container, &msg.erab_list)?;

    encode_pdu(&initiating(
        ProcedureCode::E_RAB_SETUP,
        Criticality::Reject,
        InitiatingMessageValue::ERabSetupRequest(container),
    ))
}

/// Build an E-RAB Setup Response PDU
pub fn build_erab_setup_response(msg: &ErabSetupResponse) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Ignore)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Ignore)?;

    // IE: E-RABSetupListBearerSURes (optional)
    if !msg.erab_setup_list.is_empty() {
        ie::encode_erab_setup_list_bearer_res(&mut container, &msg.erab_setup_list)?;
    }

    // IE: E-RABFailedToSetupListBearerSURes (optional)
    if !msg.erab_failed_list.is_empty() {
        let items: Vec<(u8, Cause)> = msg
            .erab_failed_list
            .iter()
            .map(|item| (item.erab_id, item.cause))
            .collect();
        ie::encode_erab_item_list(
            &mut container,
            ProtocolIeId::E_RAB_FAILED_TO_SETUP_LIST_BEARER_SU_RES,
            Criticality::Ignore,
            &items,
        )?;
    }

    encode_pdu(&successful(
        ProcedureCode::E_RAB_SETUP,
        Criticality::Reject,
        SuccessfulOutcomeValue::ERabSetupResponse(container),
    ))
}

/// Build an E-RAB Modify Request PDU
pub fn build_erab_modify_request(msg: &ErabModifyRequest) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Reject)?;

    if let Some(ref ambr) = msg.ue_ambr {
        ie::encode_ue_ambr(&mut container, ambr, Criticality::Reject)?;
    }

    // IE: E-RABToBeModifiedListBearerModReq (mandatory)
    ie::encode_erab_to_be_modified_list(&mut container, &msg.erab_list)?;

    encode_pdu(&initiating(
        ProcedureCode::E_RAB_MODIFY,
        Criticality::Reject,
        InitiatingMessageValue::ERabModifyRequest(container),
    ))
}

/// Build an E-RAB Modify Response PDU
pub fn build_erab_modify_response(msg: &ErabModifyResponse) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Ignore)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Ignore)?;

    // IE: E-RABModifyListBearerModRes (optional)
    if !msg.erab_modify_list.is_empty() {
        ie::encode_erab_modify_list_res(&mut container, &msg.erab_modify_list)?;
    }

    // IE: E-RABFailedToModifyList (optional)
    if !msg.erab_failed_list.is_empty() {
        let items: Vec<(u8, Cause)> = msg
            .erab_failed_list
            .iter()
            .map(|item| (item.erab_id, item.cause))
            .collect();
        ie::encode_erab_item_list(
            &mut container,
            ProtocolIeId::E_RAB_FAILED_TO_MODIFY_LIST,
            Criticality::Ignore,
            &items,
        )?;
    }

    encode_pdu(&successful(
        ProcedureCode::E_RAB_MODIFY,
        Criticality::Reject,
        SuccessfulOutcomeValue::ERabModifyResponse(container),
    ))
}

/// Build an E-RAB Release Command PDU
pub fn build_erab_release_command(msg: &ErabReleaseCommand) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Reject)?;

    if let Some(ref ambr) = msg.ue_ambr {
        ie::encode_ue_ambr(&mut container, ambr, Criticality::Reject)?;
    }

    // IE: E-RABToBeReleasedList (mandatory)
    let items: Vec<(u8, Cause)> = msg
        .erab_list
        .iter()
        .map(|item| (item.erab_id, item.cause))
        .collect();
    ie::encode_erab_item_list(
        &mut container,
        ProtocolIeId::E_RAB_TO_BE_RELEASED_LIST,
        Criticality::Ignore,
        &items,
    )?;

    // IE: NAS-PDU (optional)
    if let Some(ref nas_pdu) = msg.nas_pdu {
        ie::encode_nas_pdu(&mut container, nas_pdu, Criticality::Ignore)?;
    }

    encode_pdu(&initiating(
        ProcedureCode::E_RAB_RELEASE,
        Criticality::Reject,
        InitiatingMessageValue::ERabReleaseCommand(container),
    ))
}

/// Build an E-RAB Release Response PDU
pub fn build_erab_release_response(msg: &ErabReleaseResponse) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Ignore)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Ignore)?;

    // IE: E-RABReleaseListBearerRelComp (optional)
    if !msg.erab_release_list.is_empty() {
        ie::encode_erab_release_list_rel_comp(&mut container, &msg.erab_release_list)?;
    }

    // IE: E-RABFailedToReleaseList (optional)
    if !msg.erab_failed_list.is_empty() {
        let items: Vec<(u8, Cause)> = msg
            .erab_failed_list
            .iter()
            .map(|item| (item.erab_id, item.cause))
            .collect();
        ie::encode_erab_item_list(
            &mut container,
            ProtocolIeId::E_RAB_FAILED_TO_RELEASE_LIST,
            Criticality::Ignore,
            &items,
        )?;
    }

    encode_pdu(&successful(
        ProcedureCode::E_RAB_RELEASE,
        Criticality::Reject,
        SuccessfulOutcomeValue::ERabReleaseResponse(container),
    ))
}

// ============================================================================
// Paging Procedure (§8.5)
// ============================================================================

/// Build a Paging PDU
pub fn build_paging(msg: &Paging) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: UEIdentityIndexValue (mandatory)
    ie::encode_ue_identity_index(&mut container, msg.ue_identity_index)?;

    // IE: UEPagingID (mandatory)
    ie::encode_ue_paging_id(&mut container, &msg.ue_paging_id)?;

    // IE: pagingDRX (optional)
    if let Some(drx) = msg.paging_drx {
        ie::encode_paging_drx(&mut container, drx)?;
    }

    // IE: CNDomain (mandatory)
    ie::encode_cn_domain(&mut container, msg.cn_domain)?;

    // IE: TAIList (mandatory)
    ie::encode_tai_list(&mut container, &msg.tai_list)?;

    encode_pdu(&initiating(
        ProcedureCode::PAGING,
        Criticality::Ignore,
        InitiatingMessageValue::Paging(container),
    ))
}

// ============================================================================
// Reset Procedure (§8.7.1)
// ============================================================================

/// Build a Reset PDU
pub fn build_reset(msg: &Reset) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: Cause (mandatory)
    ie::encode_cause(&mut container, &msg.cause)?;

    // IE: ResetType (mandatory)
    ie::encode_reset_type(&mut container, &msg.reset_type)?;

    encode_pdu(&initiating(
        ProcedureCode::RESET,
        Criticality::Reject,
        InitiatingMessageValue::Reset(container),
    ))
}

/// Build a Reset Acknowledge PDU
pub fn build_reset_acknowledge(msg: &ResetAcknowledge) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: UE-associatedLogicalS1-ConnectionListResAck (optional)
    if !msg.ue_associated_connections.is_empty() {
        ie::encode_ue_associated_connection_list_ack(
            &mut container,
            &msg.ue_associated_connections,
        )?;
    }

    encode_pdu(&successful(
        ProcedureCode::RESET,
        Criticality::Reject,
        SuccessfulOutcomeValue::ResetAcknowledge(container),
    ))
}

// ============================================================================
// Error Indication Procedure (§8.7.2)
// ============================================================================

/// Build an Error Indication PDU
pub fn build_error_indication(msg: &ErrorIndication) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: MME-UE-S1AP-ID (optional)
    if let Some(id) = msg.mme_ue_s1ap_id {
        ie::encode_mme_ue_s1ap_id(&mut container, id, Criticality::Ignore)?;
    }

    // IE: eNB-UE-S1AP-ID (optional)
    if let Some(id) = msg.enb_ue_s1ap_id {
        ie::encode_enb_ue_s1ap_id(&mut container, id, Criticality::Ignore)?;
    }

    // IE: Cause (optional)
    if let Some(ref cause) = msg.cause {
        ie::encode_cause(&mut container, cause)?;
    }

    // IE: Criticality Diagnostics (optional) — tells the peer which procedure and
    // which IEs the error was about (TS 36.413 §9.2.1.21).
    if let Some(ref diag) = msg.criticality_diagnostics {
        ie::encode_criticality_diagnostics(&mut container, diag)?;
    }

    encode_pdu(&initiating(
        ProcedureCode::ERROR_INDICATION,
        Criticality::Ignore,
        InitiatingMessageValue::ErrorIndication(container),
    ))
}

// ============================================================================
// Handover Signalling (§8.4)
// ============================================================================

/// Build a Handover Required PDU
pub fn build_handover_required(msg: &HandoverRequired) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_handover_type(&mut container, msg.handover_type)?;
    ie::encode_cause(&mut container, &msg.cause)?;
    ie::encode_target_id(&mut container, &msg.target_id)?;
    ie::encode_source_to_target_container(&mut container, &msg.source_to_target_container)?;

    encode_pdu(&initiating(
        ProcedureCode::HANDOVER_PREPARATION,
        Criticality::Reject,
        InitiatingMessageValue::HandoverRequired(container),
    ))
}

/// Build a Handover Command PDU
pub fn build_handover_command(msg: &HandoverCommand) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_handover_type(&mut container, msg.handover_type)?;

    // IE: E-RABSubjecttoDataForwardingList (optional)
    if !msg.erab_subject_to_forwarding_list.is_empty() {
        ie::encode_erab_data_forwarding_list(&mut container, &msg.erab_subject_to_forwarding_list)?;
    }

    // IE: E-RABtoReleaseListHOCmd (optional)
    if !msg.erab_to_release_list.is_empty() {
        let items: Vec<(u8, Cause)> = msg
            .erab_to_release_list
            .iter()
            .map(|item| (item.erab_id, item.cause))
            .collect();
        ie::encode_erab_item_list(
            &mut container,
            ProtocolIeId::E_RAB_TO_RELEASE_LIST_HO_CMD,
            Criticality::Ignore,
            &items,
        )?;
    }

    ie::encode_target_to_source_container(&mut container, &msg.target_to_source_container)?;

    encode_pdu(&successful(
        ProcedureCode::HANDOVER_PREPARATION,
        Criticality::Reject,
        SuccessfulOutcomeValue::HandoverCommand(container),
    ))
}

/// Build a Handover Preparation Failure PDU
pub fn build_handover_preparation_failure(msg: &HandoverPreparationFailure) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_cause(&mut container, &msg.cause)?;

    encode_pdu(&unsuccessful(
        ProcedureCode::HANDOVER_PREPARATION,
        Criticality::Reject,
        UnsuccessfulOutcomeValue::HandoverPreparationFailure(container),
    ))
}

/// Build a Handover Request PDU
pub fn build_handover_request(msg: &HandoverRequest) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_handover_type(&mut container, msg.handover_type)?;
    ie::encode_cause(&mut container, &msg.cause)?;
    ie::encode_ue_ambr(&mut container, &msg.ue_ambr, Criticality::Reject)?;

    // IE: E-RABToBeSetupListHOReq (mandatory)
    ie::encode_erab_to_be_setup_list_ho_req(&mut container, &msg.erab_list)?;

    ie::encode_source_to_target_container(&mut container, &msg.source_to_target_container)?;
    ie::encode_ue_security_capabilities(
        &mut container,
        &msg.ue_security_capabilities,
        Criticality::Reject,
    )?;
    ie::encode_security_context(&mut container, &msg.security_context)?;

    encode_pdu(&initiating(
        ProcedureCode::HANDOVER_RESOURCE_ALLOCATION,
        Criticality::Reject,
        InitiatingMessageValue::HandoverRequest(container),
    ))
}

/// Build a Handover Request Acknowledge PDU
pub fn build_handover_request_acknowledge(msg: &HandoverRequestAcknowledge) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Ignore)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Ignore)?;

    // IE: E-RABAdmittedList (mandatory)
    ie::encode_erab_admitted_list(&mut container, &msg.erab_admitted_list)?;

    // IE: E-RABFailedToSetupListHOReqAck (optional)
    if !msg.erab_failed_list.is_empty() {
        let items: Vec<(u8, Cause)> = msg
            .erab_failed_list
            .iter()
            .map(|item| (item.erab_id, item.cause))
            .collect();
        ie::encode_erab_failed_to_setup_list_ho_req_ack(&mut container, &items)?;
    }

    ie::encode_target_to_source_container(&mut container, &msg.target_to_source_container)?;

    encode_pdu(&successful(
        ProcedureCode::HANDOVER_RESOURCE_ALLOCATION,
        Criticality::Reject,
        SuccessfulOutcomeValue::HandoverRequestAcknowledge(container),
    ))
}

/// Build a Handover Failure PDU
pub fn build_handover_failure(msg: &HandoverFailure) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Ignore)?;
    ie::encode_cause(&mut container, &msg.cause)?;

    encode_pdu(&unsuccessful(
        ProcedureCode::HANDOVER_RESOURCE_ALLOCATION,
        Criticality::Reject,
        UnsuccessfulOutcomeValue::HandoverFailure(container),
    ))
}

/// Build a Handover Notify PDU
pub fn build_handover_notify(msg: &HandoverNotify) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_eutran_cgi(&mut container, &msg.eutran_cgi)?;
    ie::encode_tai(&mut container, &msg.tai, Criticality::Ignore)?;

    encode_pdu(&initiating(
        ProcedureCode::HANDOVER_NOTIFICATION,
        Criticality::Ignore,
        InitiatingMessageValue::Other(container),
    ))
}

/// Build a Path Switch Request PDU
pub fn build_path_switch_request(msg: &PathSwitchRequest) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Reject)?;

    // IE: E-RABToBeSwitchedDLList (mandatory)
    ie::encode_erab_switched_dl_list(&mut container, &msg.erab_switched_dl_list)?;

    // IE: SourceMME-UE-S1AP-ID (mandatory)
    ie::encode_source_mme_ue_s1ap_id(&mut container, msg.source_mme_ue_s1ap_id)?;

    ie::encode_eutran_cgi(&mut container, &msg.eutran_cgi)?;
    ie::encode_tai(&mut container, &msg.tai, Criticality::Ignore)?;
    ie::encode_ue_security_capabilities(
        &mut container,
        &msg.ue_security_capabilities,
        Criticality::Ignore,
    )?;

    encode_pdu(&initiating(
        ProcedureCode::PATH_SWITCH_REQUEST,
        Criticality::Reject,
        InitiatingMessageValue::PathSwitchRequest(container),
    ))
}

/// Build a Path Switch Request Acknowledge PDU
pub fn build_path_switch_request_acknowledge(
    msg: &PathSwitchRequestAcknowledge,
) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Reject)?;

    // IE: E-RABToBeSwitchedULList (optional)
    if !msg.erab_switched_ul_list.is_empty() {
        ie::encode_erab_switched_ul_list(&mut container, &msg.erab_switched_ul_list)?;
    }

    // IE: SecurityContext (mandatory)
    ie::encode_security_context(&mut container, &msg.security_context)?;

    encode_pdu(&successful(
        ProcedureCode::PATH_SWITCH_REQUEST,
        Criticality::Reject,
        SuccessfulOutcomeValue::PathSwitchRequestAcknowledge(container),
    ))
}

/// Build a Path Switch Request Failure PDU
pub fn build_path_switch_request_failure(msg: &PathSwitchRequestFailure) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Ignore)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Ignore)?;
    ie::encode_cause(&mut container, &msg.cause)?;

    encode_pdu(&unsuccessful(
        ProcedureCode::PATH_SWITCH_REQUEST,
        Criticality::Reject,
        UnsuccessfulOutcomeValue::PathSwitchRequestFailure(container),
    ))
}

/// Build a Handover Cancel PDU
pub fn build_handover_cancel(msg: &HandoverCancel) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_cause(&mut container, &msg.cause)?;

    encode_pdu(&initiating(
        ProcedureCode::HANDOVER_CANCEL,
        Criticality::Reject,
        InitiatingMessageValue::Other(container),
    ))
}

/// Build a Handover Cancel Acknowledge PDU
pub fn build_handover_cancel_acknowledge(msg: &HandoverCancelAcknowledge) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Ignore)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Ignore)?;

    encode_pdu(&successful(
        ProcedureCode::HANDOVER_CANCEL,
        Criticality::Reject,
        SuccessfulOutcomeValue::Other(container),
    ))
}

// ============================================================================
// Configuration Update Procedures (§8.7.4-8.7.5)
// ============================================================================

/// Build an eNB Configuration Update PDU (TS 36.413 §9.1.8.7).
///
/// Every IE is optional, so an update carrying nothing is valid: it asks the
/// peer to re-confirm the configuration it already holds.
pub fn build_enb_configuration_update(msg: &EnbConfigurationUpdate) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    if let Some(ref name) = msg.enb_name {
        ie::encode_enb_name(&mut container, name)?;
    }
    if let Some(ref tas) = msg.supported_tas {
        ie::encode_supported_tas(&mut container, tas)?;
    }
    if let Some(drx) = msg.default_paging_drx {
        ie::encode_default_paging_drx(&mut container, drx)?;
    }

    encode_pdu(&initiating(
        ProcedureCode::ENB_CONFIGURATION_UPDATE,
        Criticality::Reject,
        InitiatingMessageValue::Other(container),
    ))
}

/// Build an eNB Configuration Update Acknowledge PDU (TS 36.413 §9.1.8.8)
pub fn build_enb_configuration_update_acknowledge(
    msg: &EnbConfigurationUpdateAcknowledge,
) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    if let Some(ref diag) = msg.criticality_diagnostics {
        ie::encode_criticality_diagnostics(&mut container, diag)?;
    }

    encode_pdu(&successful(
        ProcedureCode::ENB_CONFIGURATION_UPDATE,
        Criticality::Reject,
        SuccessfulOutcomeValue::Other(container),
    ))
}

/// Build an eNB Configuration Update Failure PDU (TS 36.413 §9.1.8.9)
pub fn build_enb_configuration_update_failure(
    msg: &EnbConfigurationUpdateFailure,
) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_cause(&mut container, &msg.cause)?;
    if let Some(ttw) = msg.time_to_wait {
        ie::encode_time_to_wait(&mut container, ttw)?;
    }
    if let Some(ref diag) = msg.criticality_diagnostics {
        ie::encode_criticality_diagnostics(&mut container, diag)?;
    }

    encode_pdu(&unsuccessful(
        ProcedureCode::ENB_CONFIGURATION_UPDATE,
        Criticality::Reject,
        UnsuccessfulOutcomeValue::Other(container),
    ))
}

/// Build an MME Configuration Update PDU (TS 36.413 §9.1.8.10)
pub fn build_mme_configuration_update(msg: &MmeConfigurationUpdate) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    if let Some(ref name) = msg.mme_name {
        ie::encode_mme_name(&mut container, name)?;
    }
    if let Some(ref gummeis) = msg.served_gummeis {
        ie::encode_served_gummeis(&mut container, gummeis)?;
    }
    if let Some(capacity) = msg.relative_mme_capacity {
        ie::encode_relative_mme_capacity(&mut container, capacity)?;
    }

    encode_pdu(&initiating(
        ProcedureCode::MME_CONFIGURATION_UPDATE,
        Criticality::Reject,
        InitiatingMessageValue::Other(container),
    ))
}

/// Build an MME Configuration Update Acknowledge PDU (TS 36.413 §9.1.8.11)
pub fn build_mme_configuration_update_acknowledge(
    msg: &MmeConfigurationUpdateAcknowledge,
) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    if let Some(ref diag) = msg.criticality_diagnostics {
        ie::encode_criticality_diagnostics(&mut container, diag)?;
    }

    encode_pdu(&successful(
        ProcedureCode::MME_CONFIGURATION_UPDATE,
        Criticality::Reject,
        SuccessfulOutcomeValue::Other(container),
    ))
}

/// Build an MME Configuration Update Failure PDU (TS 36.413 §9.1.8.12)
pub fn build_mme_configuration_update_failure(
    msg: &MmeConfigurationUpdateFailure,
) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_cause(&mut container, &msg.cause)?;
    if let Some(ttw) = msg.time_to_wait {
        ie::encode_time_to_wait(&mut container, ttw)?;
    }
    if let Some(ref diag) = msg.criticality_diagnostics {
        ie::encode_criticality_diagnostics(&mut container, diag)?;
    }

    encode_pdu(&unsuccessful(
        ProcedureCode::MME_CONFIGURATION_UPDATE,
        Criticality::Reject,
        UnsuccessfulOutcomeValue::Other(container),
    ))
}

// ============================================================================
// UE Context Modification Procedure (§8.3.4)
// ============================================================================

/// Build a UE Context Modification Request PDU (TS 36.413 §9.1.4.8).
///
/// Note the criticalities differ from Initial Context Setup for the same IEs:
/// `uEaggregateMaximumBitrate` is `ignore` here and `reject` there.
pub fn build_ue_context_modification_request(
    msg: &UeContextModificationRequest,
) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Reject)?;

    if let Some(ref key) = msg.security_key {
        ie::encode_security_key(&mut container, key)?;
    }
    if let Some(id) = msg.subscriber_profile_id_for_rfp {
        ie::encode_subscriber_profile_id_for_rfp(&mut container, id)?;
    }
    if let Some(ref ambr) = msg.ue_ambr {
        ie::encode_ue_ambr(&mut container, ambr, Criticality::Ignore)?;
    }
    if let Some(indicator) = msg.cs_fallback_indicator {
        ie::encode_cs_fallback_indicator(&mut container, indicator)?;
    }
    if let Some(ref caps) = msg.ue_security_capabilities {
        ie::encode_ue_security_capabilities(&mut container, caps, Criticality::Reject)?;
    }

    encode_pdu(&initiating(
        ProcedureCode::UE_CONTEXT_MODIFICATION,
        Criticality::Reject,
        InitiatingMessageValue::Other(container),
    ))
}

/// Build a UE Context Modification Response PDU (TS 36.413 §9.1.4.9)
pub fn build_ue_context_modification_response(
    msg: &UeContextModificationResponse,
) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Ignore)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Ignore)?;
    if let Some(ref diag) = msg.criticality_diagnostics {
        ie::encode_criticality_diagnostics(&mut container, diag)?;
    }

    encode_pdu(&successful(
        ProcedureCode::UE_CONTEXT_MODIFICATION,
        Criticality::Reject,
        SuccessfulOutcomeValue::Other(container),
    ))
}

/// Build a UE Context Modification Failure PDU (TS 36.413 §9.1.4.10)
pub fn build_ue_context_modification_failure(
    msg: &UeContextModificationFailure,
) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Ignore)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Ignore)?;
    ie::encode_cause(&mut container, &msg.cause)?;
    if let Some(ref diag) = msg.criticality_diagnostics {
        ie::encode_criticality_diagnostics(&mut container, diag)?;
    }

    encode_pdu(&unsuccessful(
        ProcedureCode::UE_CONTEXT_MODIFICATION,
        Criticality::Reject,
        UnsuccessfulOutcomeValue::Other(container),
    ))
}

// ============================================================================
// Overload Procedures (§8.7.6)
// ============================================================================

/// Build an Overload Start PDU (TS 36.413 §9.1.8.13)
pub fn build_overload_start(msg: &OverloadStart) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: OverloadResponse (mandatory)
    ie::encode_overload_response(&mut container, msg.overload_action)?;

    encode_pdu(&initiating(
        ProcedureCode::OVERLOAD_START,
        Criticality::Ignore,
        InitiatingMessageValue::Other(container),
    ))
}

/// Build an Overload Stop PDU (TS 36.413 §9.1.8.14).
///
/// The message has no mandatory IE, so the container is deliberately empty.
pub fn build_overload_stop(_msg: &OverloadStop) -> S1apResult<Vec<u8>> {
    encode_pdu(&initiating(
        ProcedureCode::OVERLOAD_STOP,
        Criticality::Reject,
        InitiatingMessageValue::Other(ProtocolIeContainer::new()),
    ))
}

// ============================================================================
// PWS Procedures (§8.12)
// ============================================================================

/// Build a Write-Replace Warning Request PDU (TS 36.413 §9.1.13.1).
///
/// This is the ETWS/CMAS broadcast order. IE order follows the ASN.1
/// declaration order, which is also ascending protocol IE id.
pub fn build_write_replace_warning_request(
    msg: &WriteReplaceWarningRequest,
) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_message_identifier(&mut container, msg.message_identifier)?;
    ie::encode_serial_number(&mut container, msg.serial_number)?;
    if let Some(ref area) = msg.warning_area {
        ie::encode_warning_area_list(&mut container, area)?;
    }
    ie::encode_repetition_period(&mut container, msg.repetition_period)?;
    ie::encode_number_of_broadcast_request(&mut container, msg.number_of_broadcast_request)?;
    if let Some(ref warning_type) = msg.warning_type {
        ie::encode_warning_type(&mut container, warning_type)?;
    }
    if let Some(ref info) = msg.warning_security_info {
        ie::encode_warning_security_info(&mut container, info)?;
    }
    if let Some(scheme) = msg.data_coding_scheme {
        ie::encode_data_coding_scheme(&mut container, scheme)?;
    }
    if let Some(ref contents) = msg.warning_message_contents {
        ie::encode_warning_message_contents(&mut container, contents)?;
    }
    if msg.concurrent_warning_message_indicator {
        ie::encode_concurrent_warning_message_indicator(&mut container)?;
    }

    encode_pdu(&initiating(
        ProcedureCode::WRITE_REPLACE_WARNING,
        Criticality::Reject,
        InitiatingMessageValue::Other(container),
    ))
}

/// Build a Write-Replace Warning Response PDU (TS 36.413 §9.1.13.2)
pub fn build_write_replace_warning_response(
    msg: &WriteReplaceWarningResponse,
) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_message_identifier(&mut container, msg.message_identifier)?;
    ie::encode_serial_number(&mut container, msg.serial_number)?;
    if let Some(ref area) = msg.broadcast_completed_area {
        ie::encode_broadcast_completed_area_list(&mut container, area)?;
    }
    if let Some(ref diag) = msg.criticality_diagnostics {
        ie::encode_criticality_diagnostics(&mut container, diag)?;
    }

    encode_pdu(&successful(
        ProcedureCode::WRITE_REPLACE_WARNING,
        Criticality::Reject,
        SuccessfulOutcomeValue::Other(container),
    ))
}

/// Build a Kill Request PDU (TS 36.413 §9.1.13.3).
///
/// Cancels a warning the eNBs may still be broadcasting.
pub fn build_kill_request(msg: &KillRequest) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_message_identifier(&mut container, msg.message_identifier)?;
    ie::encode_serial_number(&mut container, msg.serial_number)?;
    if let Some(ref area) = msg.warning_area {
        ie::encode_warning_area_list(&mut container, area)?;
    }
    if msg.kill_all_warning_messages {
        ie::encode_kill_all_warning_messages(&mut container)?;
    }

    encode_pdu(&initiating(
        ProcedureCode::KILL,
        Criticality::Reject,
        InitiatingMessageValue::Other(container),
    ))
}

/// Build a Kill Response PDU (TS 36.413 §9.1.13.4)
pub fn build_kill_response(msg: &KillResponse) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_message_identifier(&mut container, msg.message_identifier)?;
    ie::encode_serial_number(&mut container, msg.serial_number)?;
    if let Some(ref area) = msg.broadcast_cancelled_area {
        ie::encode_broadcast_cancelled_area_list(&mut container, area)?;
    }
    if let Some(ref diag) = msg.criticality_diagnostics {
        ie::encode_criticality_diagnostics(&mut container, diag)?;
    }

    encode_pdu(&successful(
        ProcedureCode::KILL,
        Criticality::Reject,
        SuccessfulOutcomeValue::Other(container),
    ))
}

// ============================================================================
// UE Capability Info Indication (§8.10)
// ============================================================================

/// Build a UE Capability Info Indication PDU
pub fn build_ue_capability_info_indication(
    msg: &UeCapabilityInfoIndication,
) -> S1apResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_mme_ue_s1ap_id(&mut container, msg.mme_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_enb_ue_s1ap_id(&mut container, msg.enb_ue_s1ap_id, Criticality::Reject)?;
    ie::encode_ue_radio_capability(&mut container, &msg.ue_radio_capability)?;

    encode_pdu(&initiating(
        ProcedureCode::UE_CAPABILITY_INFO_INDICATION,
        Criticality::Ignore,
        InitiatingMessageValue::Other(container),
    ))
}
