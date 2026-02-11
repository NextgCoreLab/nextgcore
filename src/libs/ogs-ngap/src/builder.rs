//! NGAP Message Builders
//!
//! Functions for building NGAP PDU messages from high-level types.
//! Each function constructs the IE container, wraps it in the appropriate
//! PDU wrapper (InitiatingMessage, SuccessfulOutcome, UnsuccessfulOutcome),
//! and APER-encodes it to bytes.

use ogs_asn1c::ngap::ies::ProtocolIeContainer;
use ogs_asn1c::ngap::pdu::*;
use ogs_asn1c::ngap::types::{Criticality, ProcedureCode};
use ogs_asn1c::per::{AperEncode, AperEncoder};

use crate::error::NgapResult;
use crate::ie;
use crate::types::*;

/// Encode an NgapPdu to APER bytes
fn encode_pdu(pdu: &NgapPdu) -> NgapResult<Vec<u8>> {
    let mut encoder = AperEncoder::new();
    pdu.encode_aper(&mut encoder)?;
    encoder.align();
    Ok(encoder.into_bytes().to_vec())
}

// ============================================================================
// B10.2: NG Setup Procedure
// ============================================================================

/// Build an NG Setup Request PDU
pub fn build_ng_setup_request(msg: &NgSetupRequest) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: GlobalRANNodeID (mandatory)
    ie::encode_global_ran_node_id(&mut container, &msg.global_ran_node_id)?;

    // IE: RANNodeName (optional)
    if let Some(ref name) = msg.ran_node_name {
        ie::encode_ran_node_name(&mut container, name)?;
    }

    // IE: SupportedTAList (mandatory)
    ie::encode_supported_ta_list(&mut container, &msg.supported_ta_list)?;

    // IE: DefaultPagingDRX (mandatory)
    ie::encode_default_paging_drx(&mut container, msg.default_paging_drx)?;

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::NG_SETUP,
        criticality: Criticality::Reject,
        value: InitiatingMessageValue::NgSetupRequest(container),
    });

    encode_pdu(&pdu)
}

/// Build an NG Setup Response PDU
pub fn build_ng_setup_response(msg: &NgSetupResponse) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMFName (mandatory)
    ie::encode_amf_name(&mut container, &msg.amf_name)?;

    // IE: ServedGUAMIList (mandatory)
    ie::encode_served_guami_list(&mut container, &msg.served_guami_list)?;

    // IE: RelativeAMFCapacity (mandatory)
    ie::encode_relative_amf_capacity(&mut container, msg.relative_amf_capacity)?;

    // IE: PLMNSupportList (mandatory)
    ie::encode_plmn_support_list(&mut container, &msg.plmn_support_list)?;

    let pdu = NgapPdu::SuccessfulOutcome(SuccessfulOutcome {
        procedure_code: ProcedureCode::NG_SETUP,
        criticality: Criticality::Reject,
        value: SuccessfulOutcomeValue::NgSetupResponse(container),
    });

    encode_pdu(&pdu)
}

/// Build an NG Setup Failure PDU
pub fn build_ng_setup_failure(msg: &NgSetupFailure) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: Cause (mandatory)
    ie::encode_cause(&mut container, &msg.cause)?;

    // IE: TimeToWait (optional)
    if let Some(ttw) = msg.time_to_wait {
        ie::encode_time_to_wait(&mut container, ttw)?;
    }

    let pdu = NgapPdu::UnsuccessfulOutcome(UnsuccessfulOutcome {
        procedure_code: ProcedureCode::NG_SETUP,
        criticality: Criticality::Reject,
        value: UnsuccessfulOutcomeValue::NgSetupFailure(container),
    });

    encode_pdu(&pdu)
}

// ============================================================================
// B10.3: NAS Transport Procedures
// ============================================================================

/// Build an Initial UE Message PDU
pub fn build_initial_ue_message(msg: &InitialUeMessage) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: RAN-UE-NGAP-ID (mandatory)
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    // IE: NAS-PDU (mandatory)
    ie::encode_nas_pdu(&mut container, &msg.nas_pdu)?;

    // IE: UserLocationInformation (mandatory)
    ie::encode_user_location_info(&mut container, &msg.user_location_info)?;

    // IE: RRCEstablishmentCause (mandatory)
    ie::encode_rrc_establishment_cause(&mut container, msg.rrc_establishment_cause)?;

    // IE: UEContextRequest (optional)
    if let Some(true) = msg.ue_context_request {
        ie::encode_ue_context_request(&mut container, true)?;
    }

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::INITIAL_UE_MESSAGE,
        criticality: Criticality::Ignore,
        value: InitiatingMessageValue::InitialUeMessage(container),
    });

    encode_pdu(&pdu)
}

/// Build a Downlink NAS Transport PDU
pub fn build_downlink_nas_transport(msg: &DownlinkNasTransport) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;

    // IE: RAN-UE-NGAP-ID (mandatory)
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    // IE: NAS-PDU (mandatory)
    ie::encode_nas_pdu(&mut container, &msg.nas_pdu)?;

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::DOWNLINK_NAS_TRANSPORT,
        criticality: Criticality::Ignore,
        value: InitiatingMessageValue::DownlinkNasTransport(container),
    });

    encode_pdu(&pdu)
}

/// Build an Uplink NAS Transport PDU
pub fn build_uplink_nas_transport(msg: &UplinkNasTransport) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;

    // IE: RAN-UE-NGAP-ID (mandatory)
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    // IE: NAS-PDU (mandatory)
    ie::encode_nas_pdu(&mut container, &msg.nas_pdu)?;

    // IE: UserLocationInformation (mandatory)
    ie::encode_user_location_info(&mut container, &msg.user_location_info)?;

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::UPLINK_NAS_TRANSPORT,
        criticality: Criticality::Ignore,
        value: InitiatingMessageValue::UplinkNasTransport(container),
    });

    encode_pdu(&pdu)
}

// ============================================================================
// B10.4: Initial Context Setup
// ============================================================================

/// Build an Initial Context Setup Request PDU
pub fn build_initial_context_setup_request(
    msg: &InitialContextSetupRequest,
) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;

    // IE: RAN-UE-NGAP-ID (mandatory)
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    // IE: GUAMI (mandatory)
    ie::encode_guami_ie(&mut container, &msg.guami)?;

    // IE: AllowedNSSAI (mandatory)
    ie::encode_allowed_nssai(&mut container, &msg.allowed_nssai)?;

    // IE: UESecurityCapabilities (mandatory)
    ie::encode_ue_security_capabilities(&mut container, &msg.ue_security_capabilities)?;

    // IE: SecurityKey (mandatory)
    ie::encode_security_key(&mut container, &msg.security_key)?;

    // IE: NAS-PDU (optional)
    if let Some(ref nas_pdu) = msg.nas_pdu {
        ie::encode_nas_pdu(&mut container, nas_pdu)?;
    }

    // IE: UEAggregateMaximumBitRate (optional)
    if let Some(ref ambr) = msg.ue_ambr {
        ie::encode_ue_ambr(&mut container, ambr)?;
    }

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::INITIAL_CONTEXT_SETUP,
        criticality: Criticality::Reject,
        value: InitiatingMessageValue::InitialContextSetupRequest(container),
    });

    encode_pdu(&pdu)
}

/// Build an Initial Context Setup Response PDU
pub fn build_initial_context_setup_response(
    msg: &InitialContextSetupResponse,
) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;

    // IE: RAN-UE-NGAP-ID (mandatory)
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    let pdu = NgapPdu::SuccessfulOutcome(SuccessfulOutcome {
        procedure_code: ProcedureCode::INITIAL_CONTEXT_SETUP,
        criticality: Criticality::Reject,
        value: SuccessfulOutcomeValue::InitialContextSetupResponse(container),
    });

    encode_pdu(&pdu)
}

/// Build an Initial Context Setup Failure PDU
pub fn build_initial_context_setup_failure(
    msg: &InitialContextSetupFailure,
) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;

    // IE: RAN-UE-NGAP-ID (mandatory)
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    // IE: Cause (mandatory)
    ie::encode_cause(&mut container, &msg.cause)?;

    let pdu = NgapPdu::UnsuccessfulOutcome(UnsuccessfulOutcome {
        procedure_code: ProcedureCode::INITIAL_CONTEXT_SETUP,
        criticality: Criticality::Reject,
        value: UnsuccessfulOutcomeValue::InitialContextSetupFailure(container),
    });

    encode_pdu(&pdu)
}

// ============================================================================
// B10.5: PDU Session Resource Procedures
// ============================================================================

/// Build a PDU Session Resource Setup Request PDU
pub fn build_pdu_session_resource_setup_request(
    msg: &PduSessionResourceSetupRequest,
) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;

    // IE: RAN-UE-NGAP-ID (mandatory)
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    // IE: PDUSessionResourceSetupListSUReq (mandatory)
    ie::encode_pdu_session_setup_list_su_req(&mut container, &msg.pdu_session_list)?;

    // IE: NAS-PDU (optional)
    if let Some(ref nas_pdu) = msg.nas_pdu {
        ie::encode_nas_pdu(&mut container, nas_pdu)?;
    }

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::PDU_SESSION_RESOURCE_SETUP,
        criticality: Criticality::Reject,
        value: InitiatingMessageValue::PduSessionResourceSetupRequest(container),
    });

    encode_pdu(&pdu)
}

/// Build a PDU Session Resource Setup Response PDU
pub fn build_pdu_session_resource_setup_response(
    msg: &PduSessionResourceSetupResponse,
) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;

    // IE: RAN-UE-NGAP-ID (mandatory)
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    // IE: PDUSessionResourceSetupListSURes (optional)
    if !msg.setup_list.is_empty() {
        ie::encode_pdu_session_setup_list_su_res(&mut container, &msg.setup_list)?;
    }

    // IE: PDUSessionResourceFailedToSetupListSURes (optional)
    if !msg.failed_list.is_empty() {
        ie::encode_pdu_session_failed_list(
            &mut container,
            ie::IE_ID_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_SU_RES,
            &msg.failed_list,
        )?;
    }

    let pdu = NgapPdu::SuccessfulOutcome(SuccessfulOutcome {
        procedure_code: ProcedureCode::PDU_SESSION_RESOURCE_SETUP,
        criticality: Criticality::Reject,
        value: SuccessfulOutcomeValue::PduSessionResourceSetupResponse(container),
    });

    encode_pdu(&pdu)
}

/// Build a PDU Session Resource Modify Request PDU
pub fn build_pdu_session_resource_modify_request(
    msg: &PduSessionResourceModifyRequest,
) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;
    ie::encode_pdu_session_modify_list_req(&mut container, &msg.pdu_session_list)?;

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::PDU_SESSION_RESOURCE_MODIFY,
        criticality: Criticality::Reject,
        value: InitiatingMessageValue::Other(container),
    });

    encode_pdu(&pdu)
}

/// Build a PDU Session Resource Modify Response PDU
pub fn build_pdu_session_resource_modify_response(
    msg: &PduSessionResourceModifyResponse,
) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    if !msg.modify_list.is_empty() {
        ie::encode_pdu_session_modify_list_res(&mut container, &msg.modify_list)?;
    }

    if !msg.failed_list.is_empty() {
        ie::encode_pdu_session_failed_list(
            &mut container,
            ie::IE_ID_PDU_SESSION_RESOURCE_FAILED_TO_MODIFY_LIST_MOD_RES,
            &msg.failed_list,
        )?;
    }

    let pdu = NgapPdu::SuccessfulOutcome(SuccessfulOutcome {
        procedure_code: ProcedureCode::PDU_SESSION_RESOURCE_MODIFY,
        criticality: Criticality::Reject,
        value: SuccessfulOutcomeValue::Other(container),
    });

    encode_pdu(&pdu)
}

/// Build a PDU Session Resource Release Command PDU
pub fn build_pdu_session_resource_release_command(
    msg: &PduSessionResourceReleaseCommand,
) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    if let Some(ref nas_pdu) = msg.nas_pdu {
        ie::encode_nas_pdu(&mut container, nas_pdu)?;
    }

    ie::encode_pdu_session_release_list(&mut container, &msg.pdu_session_list)?;

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::PDU_SESSION_RESOURCE_RELEASE,
        criticality: Criticality::Reject,
        value: InitiatingMessageValue::PduSessionResourceReleaseCommand(container),
    });

    encode_pdu(&pdu)
}

/// Build a PDU Session Resource Release Response PDU
pub fn build_pdu_session_resource_release_response(
    msg: &PduSessionResourceReleaseResponse,
) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;
    ie::encode_pdu_session_released_list(&mut container, &msg.released_list)?;

    let pdu = NgapPdu::SuccessfulOutcome(SuccessfulOutcome {
        procedure_code: ProcedureCode::PDU_SESSION_RESOURCE_RELEASE,
        criticality: Criticality::Reject,
        value: SuccessfulOutcomeValue::PduSessionResourceReleaseResponse(container),
    });

    encode_pdu(&pdu)
}

// ============================================================================
// B10.6: UE Context Release
// ============================================================================

/// Build a UE Context Release Command PDU
pub fn build_ue_context_release_command(msg: &UeContextReleaseCommand) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: UE-NGAP-IDs (mandatory)
    ie::encode_ue_ngap_ids(&mut container, &msg.ue_ngap_ids)?;

    // IE: Cause (mandatory)
    ie::encode_cause(&mut container, &msg.cause)?;

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::UE_CONTEXT_RELEASE,
        criticality: Criticality::Reject,
        value: InitiatingMessageValue::UeContextReleaseCommand(container),
    });

    encode_pdu(&pdu)
}

/// Build a UE Context Release Complete PDU
pub fn build_ue_context_release_complete(
    msg: &UeContextReleaseComplete,
) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;

    // IE: RAN-UE-NGAP-ID (mandatory)
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    let pdu = NgapPdu::SuccessfulOutcome(SuccessfulOutcome {
        procedure_code: ProcedureCode::UE_CONTEXT_RELEASE,
        criticality: Criticality::Reject,
        value: SuccessfulOutcomeValue::UeContextReleaseComplete(container),
    });

    encode_pdu(&pdu)
}

/// Build a UE Context Release Request PDU
pub fn build_ue_context_release_request(msg: &UeContextReleaseRequest) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;

    // IE: RAN-UE-NGAP-ID (mandatory)
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    // IE: Cause (mandatory)
    ie::encode_cause(&mut container, &msg.cause)?;

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::UE_CONTEXT_RELEASE_REQUEST,
        criticality: Criticality::Ignore,
        value: InitiatingMessageValue::UeContextReleaseRequest(container),
    });

    encode_pdu(&pdu)
}

// ============================================================================
// B10.7: Handover Procedures
// ============================================================================

/// Build a Handover Required PDU
pub fn build_handover_required(msg: &HandoverRequired) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;

    // IE: RAN-UE-NGAP-ID (mandatory)
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    // IE: HandoverType (mandatory)
    ie::encode_handover_type(&mut container, msg.handover_type)?;

    // IE: Cause (mandatory)
    ie::encode_cause(&mut container, &msg.cause)?;

    // IE: TargetID (mandatory)
    ie::encode_target_id(&mut container, &msg.target_id)?;

    // IE: PDUSessionResourceListHORqd (optional)
    if let Some(ref list) = msg.pdu_session_list {
        ie::encode_pdu_session_ho_required_list(&mut container, list)?;
    }

    // IE: SourceToTarget-TransparentContainer (mandatory)
    ie::encode_source_to_target_container(&mut container, &msg.source_to_target_container)?;

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::HANDOVER_PREPARATION,
        criticality: Criticality::Reject,
        value: InitiatingMessageValue::Other(container),
    });

    encode_pdu(&pdu)
}

/// Build a Handover Request PDU
pub fn build_handover_request(msg: &HandoverRequest) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;

    // IE: HandoverType (mandatory)
    ie::encode_handover_type(&mut container, msg.handover_type)?;

    // IE: Cause (mandatory)
    ie::encode_cause(&mut container, &msg.cause)?;

    // IE: UEAggregateMaximumBitRate (mandatory)
    ie::encode_ue_ambr(&mut container, &msg.ue_ambr)?;

    // IE: UESecurityCapabilities (mandatory)
    ie::encode_ue_security_capabilities(&mut container, &msg.ue_security_capabilities)?;

    // IE: SecurityContext (mandatory)
    ie::encode_security_context(&mut container, &msg.security_context)?;

    // IE: PDUSessionResourceSetupListHOReq (mandatory)
    ie::encode_pdu_session_ho_request_list(&mut container, &msg.pdu_session_list)?;

    // IE: AllowedNSSAI (mandatory)
    ie::encode_allowed_nssai(&mut container, &msg.allowed_nssai)?;

    // IE: SourceToTarget-TransparentContainer (mandatory)
    ie::encode_source_to_target_container(&mut container, &msg.source_to_target_container)?;

    // IE: GUAMI (mandatory)
    ie::encode_guami_ie(&mut container, &msg.guami)?;

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::HANDOVER_RESOURCE_ALLOCATION,
        criticality: Criticality::Reject,
        value: InitiatingMessageValue::Other(container),
    });

    encode_pdu(&pdu)
}

/// Build a Handover Request Acknowledge PDU
pub fn build_handover_request_acknowledge(msg: &HandoverRequestAcknowledge) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;

    // IE: RAN-UE-NGAP-ID (mandatory)
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    // IE: PDUSessionResourceAdmittedList (mandatory)
    ie::encode_pdu_session_admitted_list(&mut container, &msg.admitted_list)?;

    // IE: PDUSessionResourceFailedToSetupListHOAck (optional)
    if let Some(ref failed) = msg.failed_list {
        ie::encode_pdu_session_failed_list(
            &mut container,
            ie::IE_ID_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_HO_ACK,
            failed,
        )?;
    }

    // IE: TargetToSource-TransparentContainer (mandatory)
    ie::encode_target_to_source_container(&mut container, &msg.target_to_source_container)?;

    let pdu = NgapPdu::SuccessfulOutcome(SuccessfulOutcome {
        procedure_code: ProcedureCode::HANDOVER_RESOURCE_ALLOCATION,
        criticality: Criticality::Reject,
        value: SuccessfulOutcomeValue::Other(container),
    });

    encode_pdu(&pdu)
}

/// Build a Handover Failure PDU
pub fn build_handover_failure(msg: &HandoverFailure) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;

    // IE: Cause (mandatory)
    ie::encode_cause(&mut container, &msg.cause)?;

    // IE: CriticalityDiagnostics (optional)
    if let Some(ref diag) = msg.criticality_diagnostics {
        ie::encode_criticality_diagnostics(&mut container, diag)?;
    }

    let pdu = NgapPdu::UnsuccessfulOutcome(UnsuccessfulOutcome {
        procedure_code: ProcedureCode::HANDOVER_RESOURCE_ALLOCATION,
        criticality: Criticality::Reject,
        value: UnsuccessfulOutcomeValue::Other(container),
    });

    encode_pdu(&pdu)
}

/// Build a Handover Command PDU
pub fn build_handover_command(msg: &HandoverCommand) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;

    // IE: RAN-UE-NGAP-ID (mandatory)
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    // IE: HandoverType (mandatory)
    ie::encode_handover_type(&mut container, msg.handover_type)?;

    // IE: NAS-PDU (optional)
    if let Some(ref nas_pdu) = msg.nas_pdu {
        ie::encode_nas_pdu(&mut container, nas_pdu)?;
    }

    // IE: PDUSessionResourceHandoverList (mandatory)
    ie::encode_pdu_session_handover_list(&mut container, &msg.pdu_session_list)?;

    // IE: PDUSessionResourceToReleaseListHOCmd (optional)
    if let Some(ref release_list) = msg.release_list {
        ie::encode_pdu_session_release_list(&mut container, release_list)?;
    }

    // IE: TargetToSource-TransparentContainer (mandatory)
    ie::encode_target_to_source_container(&mut container, &msg.target_to_source_container)?;

    let pdu = NgapPdu::SuccessfulOutcome(SuccessfulOutcome {
        procedure_code: ProcedureCode::HANDOVER_PREPARATION,
        criticality: Criticality::Reject,
        value: SuccessfulOutcomeValue::Other(container),
    });

    encode_pdu(&pdu)
}

/// Build a Handover Notify PDU
pub fn build_handover_notify(msg: &HandoverNotify) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;

    // IE: RAN-UE-NGAP-ID (mandatory)
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    // IE: UserLocationInformation (mandatory)
    ie::encode_user_location_info(&mut container, &msg.user_location_info)?;

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::HANDOVER_NOTIFICATION,
        criticality: Criticality::Ignore,
        value: InitiatingMessageValue::Other(container),
    });

    encode_pdu(&pdu)
}

// ============================================================================
// B10.8: Paging Procedure
// ============================================================================

/// Build a Paging PDU
pub fn build_paging(msg: &Paging) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: UEPagingIdentity (mandatory)
    ie::encode_ue_paging_identity(&mut container, &msg.ue_paging_identity)?;

    // IE: PagingDRX (optional)
    if let Some(drx) = msg.paging_drx {
        ie::encode_paging_drx(&mut container, drx)?;
    }

    // IE: TAIListForPaging (mandatory)
    ie::encode_tai_list_for_paging(&mut container, &msg.tai_list)?;

    // IE: PagingPriority (optional)
    if let Some(priority) = msg.paging_priority {
        ie::encode_paging_priority(&mut container, priority)?;
    }

    // IE: UERadioCapabilityForPaging (optional)
    if let Some(ref radio_cap) = msg.ue_radio_capability {
        ie::encode_ue_radio_capability_for_paging(&mut container, radio_cap)?;
    }

    // IE: PagingOrigin (optional)
    if let Some(origin) = msg.paging_origin {
        ie::encode_paging_origin(&mut container, origin)?;
    }

    // IE: AssistanceDataForPaging (optional)
    if let Some(ref assistance) = msg.assistance_data {
        ie::encode_assistance_data_for_paging(&mut container, assistance)?;
    }

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::PAGING,
        criticality: Criticality::Ignore,
        value: InitiatingMessageValue::Other(container),
    });

    encode_pdu(&pdu)
}
