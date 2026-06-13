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
pub fn build_ue_context_release_complete(msg: &UeContextReleaseComplete) -> NgapResult<Vec<u8>> {
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

    // IE: PDUSessionResourceListHORqd (mandatory)
    ie::encode_pdu_session_ho_required_list(&mut container, &msg.pdu_session_list)?;

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

// ============================================================================
// NG Reset Procedure (Section 8.7.4)
// ============================================================================

/// Build an NG Reset PDU
pub fn build_ng_reset(msg: &NgReset) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: Cause (mandatory)
    ie::encode_cause(&mut container, &msg.cause)?;

    // IE: ResetType (mandatory)
    ie::encode_reset_type(&mut container, &msg.reset_type)?;

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::NG_RESET,
        criticality: Criticality::Reject,
        value: InitiatingMessageValue::Other(container),
    });

    encode_pdu(&pdu)
}

/// Build an NG Reset Acknowledge PDU
pub fn build_ng_reset_acknowledge(msg: &NgResetAcknowledge) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: UE-associatedLogicalNG-connectionList (optional)
    if let Some(ref connections) = msg.connections {
        ie::encode_ng_connection_list(&mut container, connections)?;
    }

    // IE: CriticalityDiagnostics (optional)
    if let Some(ref diag) = msg.criticality_diagnostics {
        ie::encode_criticality_diagnostics(&mut container, diag)?;
    }

    let pdu = NgapPdu::SuccessfulOutcome(SuccessfulOutcome {
        procedure_code: ProcedureCode::NG_RESET,
        criticality: Criticality::Reject,
        value: SuccessfulOutcomeValue::Other(container),
    });

    encode_pdu(&pdu)
}

// ============================================================================
// Error Indication Procedure (Section 8.7.5)
// ============================================================================

/// Build an Error Indication PDU
pub fn build_error_indication(msg: &ErrorIndication) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMF-UE-NGAP-ID (optional)
    if let Some(amf_id) = msg.amf_ue_ngap_id {
        ie::encode_amf_ue_ngap_id(&mut container, amf_id)?;
    }

    // IE: RAN-UE-NGAP-ID (optional)
    if let Some(ran_id) = msg.ran_ue_ngap_id {
        ie::encode_ran_ue_ngap_id(&mut container, ran_id)?;
    }

    // IE: Cause (optional)
    if let Some(ref cause) = msg.cause {
        ie::encode_cause(&mut container, cause)?;
    }

    // IE: CriticalityDiagnostics (optional)
    if let Some(ref diag) = msg.criticality_diagnostics {
        ie::encode_criticality_diagnostics(&mut container, diag)?;
    }

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::ERROR_INDICATION,
        criticality: Criticality::Ignore,
        value: InitiatingMessageValue::Other(container),
    });

    encode_pdu(&pdu)
}

// ============================================================================
// RAN Configuration Update Procedure (Section 8.7.2)
// ============================================================================

/// Build a RAN Configuration Update PDU
pub fn build_ran_configuration_update(msg: &RanConfigurationUpdate) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: RANNodeName (optional)
    if let Some(ref name) = msg.ran_node_name {
        ie::encode_ran_node_name(&mut container, name)?;
    }

    // IE: SupportedTAList (optional)
    if let Some(ref ta_list) = msg.supported_ta_list {
        ie::encode_supported_ta_list(&mut container, ta_list)?;
    }

    // IE: DefaultPagingDRX (optional)
    if let Some(drx) = msg.default_paging_drx {
        ie::encode_default_paging_drx(&mut container, drx)?;
    }

    // IE: GlobalRANNodeID (optional)
    if let Some(ref ran_node_id) = msg.global_ran_node_id {
        ie::encode_global_ran_node_id(&mut container, ran_node_id)?;
    }

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::RAN_CONFIGURATION_UPDATE,
        criticality: Criticality::Reject,
        value: InitiatingMessageValue::Other(container),
    });

    encode_pdu(&pdu)
}

/// Build a RAN Configuration Update Acknowledge PDU
pub fn build_ran_configuration_update_acknowledge(
    msg: &RanConfigurationUpdateAcknowledge,
) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: CriticalityDiagnostics (optional)
    if let Some(ref diag) = msg.criticality_diagnostics {
        ie::encode_criticality_diagnostics(&mut container, diag)?;
    }

    let pdu = NgapPdu::SuccessfulOutcome(SuccessfulOutcome {
        procedure_code: ProcedureCode::RAN_CONFIGURATION_UPDATE,
        criticality: Criticality::Reject,
        value: SuccessfulOutcomeValue::Other(container),
    });

    encode_pdu(&pdu)
}

/// Build a RAN Configuration Update Failure PDU
pub fn build_ran_configuration_update_failure(
    msg: &RanConfigurationUpdateFailure,
) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: Cause (mandatory)
    ie::encode_cause(&mut container, &msg.cause)?;

    // IE: TimeToWait (optional)
    if let Some(ttw) = msg.time_to_wait {
        ie::encode_time_to_wait(&mut container, ttw)?;
    }

    // IE: CriticalityDiagnostics (optional)
    if let Some(ref diag) = msg.criticality_diagnostics {
        ie::encode_criticality_diagnostics(&mut container, diag)?;
    }

    let pdu = NgapPdu::UnsuccessfulOutcome(UnsuccessfulOutcome {
        procedure_code: ProcedureCode::RAN_CONFIGURATION_UPDATE,
        criticality: Criticality::Reject,
        value: UnsuccessfulOutcomeValue::Other(container),
    });

    encode_pdu(&pdu)
}

// ============================================================================
// AMF Configuration Update Procedure (Section 8.7.3)
// ============================================================================

/// Build an AMF Configuration Update PDU
pub fn build_amf_configuration_update(msg: &AmfConfigurationUpdate) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMFName (optional)
    if let Some(ref name) = msg.amf_name {
        ie::encode_amf_name(&mut container, name)?;
    }

    // IE: ServedGUAMIList (optional)
    if let Some(ref guami_list) = msg.served_guami_list {
        ie::encode_served_guami_list(&mut container, guami_list)?;
    }

    // IE: RelativeAMFCapacity (optional)
    if let Some(capacity) = msg.relative_amf_capacity {
        ie::encode_relative_amf_capacity(&mut container, capacity)?;
    }

    // IE: PLMNSupportList (optional)
    if let Some(ref plmn_list) = msg.plmn_support_list {
        ie::encode_plmn_support_list(&mut container, plmn_list)?;
    }

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::AMF_CONFIGURATION_UPDATE,
        criticality: Criticality::Reject,
        value: InitiatingMessageValue::Other(container),
    });

    encode_pdu(&pdu)
}

/// Build an AMF Configuration Update Acknowledge PDU
pub fn build_amf_configuration_update_acknowledge(
    msg: &AmfConfigurationUpdateAcknowledge,
) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: CriticalityDiagnostics (optional)
    if let Some(ref diag) = msg.criticality_diagnostics {
        ie::encode_criticality_diagnostics(&mut container, diag)?;
    }

    let pdu = NgapPdu::SuccessfulOutcome(SuccessfulOutcome {
        procedure_code: ProcedureCode::AMF_CONFIGURATION_UPDATE,
        criticality: Criticality::Reject,
        value: SuccessfulOutcomeValue::Other(container),
    });

    encode_pdu(&pdu)
}

/// Build an AMF Configuration Update Failure PDU
pub fn build_amf_configuration_update_failure(
    msg: &AmfConfigurationUpdateFailure,
) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: Cause (mandatory)
    ie::encode_cause(&mut container, &msg.cause)?;

    // IE: TimeToWait (optional)
    if let Some(ttw) = msg.time_to_wait {
        ie::encode_time_to_wait(&mut container, ttw)?;
    }

    // IE: CriticalityDiagnostics (optional)
    if let Some(ref diag) = msg.criticality_diagnostics {
        ie::encode_criticality_diagnostics(&mut container, diag)?;
    }

    let pdu = NgapPdu::UnsuccessfulOutcome(UnsuccessfulOutcome {
        procedure_code: ProcedureCode::AMF_CONFIGURATION_UPDATE,
        criticality: Criticality::Reject,
        value: UnsuccessfulOutcomeValue::Other(container),
    });

    encode_pdu(&pdu)
}

// ============================================================================
// AMF Status Indication Procedure (Section 8.7.6)
// ============================================================================

/// Build an AMF Status Indication PDU
pub fn build_amf_status_indication(msg: &AmfStatusIndication) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: UnavailableGUAMIList (mandatory)
    ie::encode_unavailable_guami_list(&mut container, &msg.unavailable_guami_list)?;

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::AMF_STATUS_INDICATION,
        criticality: Criticality::Ignore,
        value: InitiatingMessageValue::Other(container),
    });

    encode_pdu(&pdu)
}

// ============================================================================
// PDU Session Resource Notify Procedure (Section 8.2.5)
// ============================================================================

/// Build a PDU Session Resource Notify PDU
pub fn build_pdu_session_resource_notify(msg: &PduSessionResourceNotify) -> NgapResult<Vec<u8>> {
    if msg.notify_list.is_empty() && msg.released_list.is_empty() {
        return Err(crate::error::NgapError::EncodingError(
            "PDUSessionResourceNotify requires at least one of notify/released lists".to_string(),
        ));
    }

    let mut container = ProtocolIeContainer::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;

    // IE: RAN-UE-NGAP-ID (mandatory)
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    // IE: PDUSessionResourceNotifyList (optional)
    if !msg.notify_list.is_empty() {
        ie::encode_pdu_session_notify_list(&mut container, &msg.notify_list)?;
    }

    // IE: PDUSessionResourceReleasedListNot (optional)
    if !msg.released_list.is_empty() {
        ie::encode_pdu_session_released_list_with_id(
            &mut container,
            ie::IE_ID_PDU_SESSION_RESOURCE_RELEASED_LIST_NOT,
            &msg.released_list,
        )?;
    }

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::PDU_SESSION_RESOURCE_NOTIFY,
        criticality: Criticality::Ignore,
        value: InitiatingMessageValue::Other(container),
    });

    encode_pdu(&pdu)
}

// ============================================================================
// PDU Session Resource Modify Indication Procedure (Section 8.2.4)
// ============================================================================

/// Build a PDU Session Resource Modify Indication PDU
pub fn build_pdu_session_resource_modify_indication(
    msg: &PduSessionResourceModifyIndication,
) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;

    // IE: RAN-UE-NGAP-ID (mandatory)
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    // IE: PDUSessionResourceModifyListModInd (mandatory)
    ie::encode_pdu_session_modify_list_mod_ind(&mut container, &msg.modify_list)?;

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::PDU_SESSION_RESOURCE_MODIFY_INDICATION,
        criticality: Criticality::Reject,
        value: InitiatingMessageValue::Other(container),
    });

    encode_pdu(&pdu)
}

/// Build a PDU Session Resource Modify Confirm PDU
pub fn build_pdu_session_resource_modify_confirm(
    msg: &PduSessionResourceModifyConfirm,
) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;

    // IE: RAN-UE-NGAP-ID (mandatory)
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    // IE: PDUSessionResourceModifyListModCfm (optional)
    if !msg.confirm_list.is_empty() {
        ie::encode_pdu_session_modify_list_mod_cfm(&mut container, &msg.confirm_list)?;
    }

    // IE: PDUSessionResourceFailedToModifyListModCfm (optional)
    if !msg.failed_list.is_empty() {
        ie::encode_pdu_session_failed_list(
            &mut container,
            ie::IE_ID_PDU_SESSION_RESOURCE_FAILED_TO_MODIFY_LIST_MOD_CFM,
            &msg.failed_list,
        )?;
    }

    let pdu = NgapPdu::SuccessfulOutcome(SuccessfulOutcome {
        procedure_code: ProcedureCode::PDU_SESSION_RESOURCE_MODIFY_INDICATION,
        criticality: Criticality::Reject,
        value: SuccessfulOutcomeValue::Other(container),
    });

    encode_pdu(&pdu)
}

// ============================================================================
// NAS Non Delivery Indication Procedure (Section 8.6.5)
// ============================================================================

/// Build a NAS Non Delivery Indication PDU
pub fn build_nas_non_delivery_indication(msg: &NasNonDeliveryIndication) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;

    // IE: RAN-UE-NGAP-ID (mandatory)
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    // IE: NAS-PDU (mandatory)
    ie::encode_nas_pdu(&mut container, &msg.nas_pdu)?;

    // IE: Cause (mandatory)
    ie::encode_cause(&mut container, &msg.cause)?;

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::NAS_NON_DELIVERY_INDICATION,
        criticality: Criticality::Ignore,
        value: InitiatingMessageValue::Other(container),
    });

    encode_pdu(&pdu)
}

// ============================================================================
// Path Switch Request Procedure (Section 8.4.4)
// ============================================================================

/// Build a Path Switch Request PDU
pub fn build_path_switch_request(msg: &PathSwitchRequest) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: RAN-UE-NGAP-ID (mandatory)
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    // IE: SourceAMF-UE-NGAP-ID (mandatory)
    ie::encode_source_amf_ue_ngap_id(&mut container, msg.source_amf_ue_ngap_id)?;

    // IE: UserLocationInformation (mandatory)
    ie::encode_user_location_info(&mut container, &msg.user_location_info)?;

    // IE: UESecurityCapabilities (mandatory)
    ie::encode_ue_security_capabilities(&mut container, &msg.ue_security_capabilities)?;

    // IE: PDUSessionResourceToBeSwitchedDLList (mandatory)
    ie::encode_pdu_session_to_be_switched_list(&mut container, &msg.pdu_session_list)?;

    // IE: PDUSessionResourceFailedToSetupListPSReq (optional)
    if let Some(ref failed) = msg.failed_list {
        ie::encode_pdu_session_failed_list(
            &mut container,
            ie::IE_ID_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_PS_REQ,
            failed,
        )?;
    }

    let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::PATH_SWITCH_REQUEST,
        criticality: Criticality::Reject,
        value: InitiatingMessageValue::Other(container),
    });

    encode_pdu(&pdu)
}

/// Build a Path Switch Request Acknowledge PDU
pub fn build_path_switch_request_acknowledge(
    msg: &PathSwitchRequestAcknowledge,
) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;

    // IE: RAN-UE-NGAP-ID (mandatory)
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    // IE: UESecurityCapabilities (optional)
    if let Some(ref caps) = msg.ue_security_capabilities {
        ie::encode_ue_security_capabilities(&mut container, caps)?;
    }

    // IE: SecurityContext (mandatory)
    ie::encode_security_context(&mut container, &msg.security_context)?;

    // IE: PDUSessionResourceSwitchedList (mandatory)
    ie::encode_pdu_session_switched_list(&mut container, &msg.switched_list)?;

    // IE: PDUSessionResourceReleasedListPSAck (optional)
    if let Some(ref released) = msg.released_list {
        ie::encode_pdu_session_released_list_with_id(
            &mut container,
            ie::IE_ID_PDU_SESSION_RESOURCE_RELEASED_LIST_PS_ACK,
            released,
        )?;
    }

    // IE: AllowedNSSAI (mandatory)
    ie::encode_allowed_nssai(&mut container, &msg.allowed_nssai)?;

    let pdu = NgapPdu::SuccessfulOutcome(SuccessfulOutcome {
        procedure_code: ProcedureCode::PATH_SWITCH_REQUEST,
        criticality: Criticality::Reject,
        value: SuccessfulOutcomeValue::Other(container),
    });

    encode_pdu(&pdu)
}

/// Build a Path Switch Request Failure PDU
pub fn build_path_switch_request_failure(msg: &PathSwitchRequestFailure) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;

    // IE: RAN-UE-NGAP-ID (mandatory)
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    // IE: Cause (mandatory)
    ie::encode_cause(&mut container, &msg.cause)?;

    // IE: PDUSessionResourceReleasedListPSFail (optional)
    if let Some(ref released) = msg.released_list {
        ie::encode_pdu_session_released_list_with_id(
            &mut container,
            ie::IE_ID_PDU_SESSION_RESOURCE_RELEASED_LIST_PS_FAIL,
            released,
        )?;
    }

    // IE: CriticalityDiagnostics (optional)
    if let Some(ref diag) = msg.criticality_diagnostics {
        ie::encode_criticality_diagnostics(&mut container, diag)?;
    }

    let pdu = NgapPdu::UnsuccessfulOutcome(UnsuccessfulOutcome {
        procedure_code: ProcedureCode::PATH_SWITCH_REQUEST,
        criticality: Criticality::Reject,
        value: UnsuccessfulOutcomeValue::Other(container),
    });

    encode_pdu(&pdu)
}

/// Build a Handover Preparation Failure PDU
pub fn build_handover_preparation_failure(msg: &HandoverPreparationFailure) -> NgapResult<Vec<u8>> {
    let mut container = ProtocolIeContainer::new();

    // IE: AMF-UE-NGAP-ID (mandatory)
    ie::encode_amf_ue_ngap_id(&mut container, msg.amf_ue_ngap_id)?;

    // IE: RAN-UE-NGAP-ID (mandatory)
    ie::encode_ran_ue_ngap_id(&mut container, msg.ran_ue_ngap_id)?;

    // IE: Cause (mandatory)
    ie::encode_cause(&mut container, &msg.cause)?;

    // IE: CriticalityDiagnostics (optional)
    if let Some(ref diag) = msg.criticality_diagnostics {
        ie::encode_criticality_diagnostics(&mut container, diag)?;
    }

    let pdu = NgapPdu::UnsuccessfulOutcome(UnsuccessfulOutcome {
        procedure_code: ProcedureCode::HANDOVER_PREPARATION,
        criticality: Criticality::Reject,
        value: UnsuccessfulOutcomeValue::Other(container),
    });

    encode_pdu(&pdu)
}

#[cfg(test)]
mod ng_setup_cross_codec {
    //! Cross-codec NG Setup regression guards (W5 E2E NGAP reconciliation).
    //!
    //! These pin the wire bytes ogs-ngap produces for the NG Setup Request and
    //! Response against the byte vectors that the independent nextgsim-ngap
    //! codec produces and accepts. The matching test on the nextgsim side
    //! (`nextgsim-ngap/src/capture_tests.rs::ng_setup_cross_codec`) decodes the
    //! same vectors with the generated APER codec; together they guarantee both
    //! directions round-trip across the two stacks.
    //!
    //! Root cause they guard against (both X.691 violations on the ogs side):
    //!
    //! 1. AMFName/RANNodeName were encoded as bare unconstrained OCTET STRINGs
    //!    instead of extensible constrained-size PrintableString (SIZE(1..150,
    //!    ...)) — missing the size-extension bit + constrained length.
    //! 2. NGAP message values (NGSetupRequest/Response = extensible SEQUENCE
    //!    `{ protocolIEs, ... }`) omitted the SEQUENCE extension-marker bit
    //!    before the IE container.
    //!
    //! Either misalignment shifts a downstream CHOICE index so it decodes as 256.

    use super::*;

    fn sample_response() -> NgSetupResponse {
        NgSetupResponse {
            amf_name: "nextgcore-amf".to_string(),
            served_guami_list: vec![ServedGuamiItem {
                guami: Guami {
                    plmn_identity: [0x00, 0xF1, 0x10],
                    amf_region_id: 0x02,
                    amf_set_id: 0x001,
                    amf_pointer: 0x01,
                },
                backup_amf_name: None,
            }],
            relative_amf_capacity: 255,
            plmn_support_list: vec![PlmnSupportItem {
                plmn_identity: [0x00, 0xF1, 0x10],
                slice_support_list: vec![SNssai { sst: 1, sd: None }],
            }],
        }
    }

    /// The bytes nextgsim-ngap's generated APER codec produces (and accepts)
    /// for the identical NG Setup Response. Captured from the sim and pinned
    /// here as the cross-stack conformance vector.
    const SIM_NG_SETUP_RESPONSE: [u8; 55] = [
        0x20, 0x15, 0x00, 0x33, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x0f, 0x06, 0x00, 0x6e, 0x65,
        0x78, 0x74, 0x67, 0x63, 0x6f, 0x72, 0x65, 0x2d, 0x61, 0x6d, 0x66, 0x00, 0x60, 0x00, 0x08,
        0x00, 0x00, 0x00, 0xf1, 0x10, 0x02, 0x00, 0x41, 0x00, 0x56, 0x40, 0x01, 0xff, 0x00, 0x50,
        0x00, 0x08, 0x00, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x00, 0x08,
    ];

    #[test]
    fn ng_setup_response_matches_sim_wire_bytes() {
        let bytes = build_ng_setup_response(&sample_response()).unwrap();
        assert_eq!(
            bytes, SIM_NG_SETUP_RESPONSE,
            "ogs NG Setup Response must be byte-identical to the nextgsim codec"
        );
    }

    #[test]
    fn ng_setup_request_amf_name_uses_printable_string() {
        // RANNodeName is the same extensible PrintableString as AMFName; a
        // round-trip through the ogs codec must preserve it and the bytes must
        // contain the extension-bit + constrained-length framing (0x05 0x80 ...
        // for "nextgsim-gnb"), not a bare octet-string length.
        let msg = NgSetupRequest {
            global_ran_node_id: GlobalRanNodeId::GlobalGnbId {
                plmn_identity: [0x00, 0xF1, 0x10],
                gnb_id: 1,
                gnb_id_len: 32,
            },
            ran_node_name: Some("nextgsim-gnb".to_string()),
            supported_ta_list: vec![SupportedTaItem {
                tac: [0x00, 0x00, 0x01],
                broadcast_plmn_list: vec![BroadcastPlmnItem {
                    plmn_identity: [0x00, 0xF1, 0x10],
                    tai_slice_support_list: vec![SNssai { sst: 1, sd: None }],
                }],
            }],
            default_paging_drx: PagingDrx::V128,
        };
        let bytes = build_ng_setup_request(&msg).unwrap();
        // The message-SEQUENCE extension-marker bit shifts the container count
        // into the 00 00 04 form (vs the pre-fix 00 04).
        assert_eq!(&bytes[4..7], &[0x00, 0x00, 0x04]);
        let parsed = crate::parser::decode_ngap_pdu(&bytes).unwrap();
        match parsed {
            crate::parser::NgapMessage::NgSetupRequest(req) => {
                assert_eq!(req.ran_node_name.as_deref(), Some("nextgsim-gnb"));
            }
            other => panic!("expected NgSetupRequest, got {other:?}"),
        }
    }

    #[test]
    fn ng_setup_response_self_roundtrip() {
        let bytes = build_ng_setup_response(&sample_response()).unwrap();
        match crate::parser::decode_ngap_pdu(&bytes).unwrap() {
            crate::parser::NgapMessage::NgSetupResponse(resp) => {
                assert_eq!(resp.amf_name, "nextgcore-amf");
                assert_eq!(resp.relative_amf_capacity, 255);
                assert_eq!(resp.served_guami_list.len(), 1);
                assert_eq!(resp.plmn_support_list.len(), 1);
            }
            other => panic!("expected NgSetupResponse, got {other:?}"),
        }
    }

    /// Downlink NAS Transport (AMF → gNB) — the first procedure after NG Setup.
    /// Verified to round-trip through the sim's nextgsim-ngap decoder during the
    /// W5 reconciliation; pinned here as a self round-trip so the core side does
    /// not regress the framing the sim depends on.
    #[test]
    fn downlink_nas_transport_self_roundtrip() {
        let bytes = build_downlink_nas_transport(&DownlinkNasTransport {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 1,
            nas_pdu: vec![0x7e, 0x00, 0x56],
        })
        .unwrap();
        match crate::parser::decode_ngap_pdu(&bytes).unwrap() {
            crate::parser::NgapMessage::DownlinkNasTransport(dl) => {
                assert_eq!(dl.amf_ue_ngap_id, 1);
                assert_eq!(dl.ran_ue_ngap_id, 1);
                assert_eq!(dl.nas_pdu, vec![0x7e, 0x00, 0x56]);
            }
            other => panic!("expected DownlinkNasTransport, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // ICS Request cross-codec guard (W5 ICS reconciliation)
    // ------------------------------------------------------------------
    //
    // Pins the wire bytes ogs-ngap produces for an InitialContextSetupRequest
    // against the vector the independent nextgsim-ngap codec decodes. The
    // matching sim test (capture_tests.rs::ics_request_from_core_decodes)
    // decodes the same vector. Guards three X.691 fixes on the ogs side:
    //   1. BitRate (UE-AMBR) must be an extensible-constrained INTEGER
    //      (0..4000000000000, ...), not an unconstrained whole number.
    //   2. Each UESecurityCapabilities algorithm field is BIT STRING
    //      (SIZE(16, ...)) — size-extensible, so a 1-bit extension marker
    //      precedes each 16-bit value.
    //   3. AllowedNSSAI-Item carries a bare S-NSSAI (no SliceSupportItem
    //      preamble; that wrapper is only for SliceSupportList items).

    fn sample_ics_request() -> InitialContextSetupRequest {
        InitialContextSetupRequest {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 1,
            guami: Guami {
                plmn_identity: [0x00, 0xF1, 0x10],
                amf_region_id: 0x02,
                amf_set_id: 0x001,
                amf_pointer: 0x01,
            },
            allowed_nssai: vec![SNssai { sst: 1, sd: None }],
            ue_security_capabilities: UeSecurityCapabilities {
                nr_encryption_algorithms: 0x8000,
                nr_integrity_algorithms: 0x8000,
                eutra_encryption_algorithms: 0,
                eutra_integrity_algorithms: 0,
            },
            security_key: [0x11; 32],
            nas_pdu: None,
            ue_ambr: Some(UeAmbrInfo {
                dl: 1_000_000_000,
                ul: 500_000_000,
            }),
        }
    }

    /// Bytes the sim's nextgsim-ngap codec produces/accepts for the identical
    /// ICS Request. Pinned as the cross-stack conformance vector.
    const SIM_ICS_REQUEST: [u8; 99] = [
        0x00, 0x0e, 0x00, 0x5f, 0x00, 0x00, 0x07, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, 0x00, 0x55,
        0x00, 0x02, 0x00, 0x01, 0x00, 0x1c, 0x00, 0x07, 0x00, 0x00, 0xf1, 0x10, 0x02, 0x00, 0x41,
        0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x77, 0x00, 0x09, 0x10, 0x00, 0x08, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x5e, 0x00, 0x20, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x00, 0x6e, 0x00, 0x0a, 0x0c,
        0x3b, 0x9a, 0xca, 0x00, 0x30, 0x1d, 0xcd, 0x65, 0x00,
    ];

    #[test]
    fn ics_request_matches_sim_wire_bytes() {
        let bytes = build_initial_context_setup_request(&sample_ics_request()).unwrap();
        assert_eq!(
            bytes,
            SIM_ICS_REQUEST.to_vec(),
            "ogs ICS Request must be byte-identical to the nextgsim codec"
        );
    }

    #[test]
    fn ics_request_self_roundtrip() {
        let bytes = build_initial_context_setup_request(&sample_ics_request()).unwrap();
        match crate::parser::decode_ngap_pdu(&bytes).unwrap() {
            crate::parser::NgapMessage::InitialContextSetupRequest(req) => {
                assert_eq!(req.ue_ambr.as_ref().unwrap().dl, 1_000_000_000);
                assert_eq!(req.ue_ambr.as_ref().unwrap().ul, 500_000_000);
                assert_eq!(
                    req.ue_security_capabilities.nr_encryption_algorithms,
                    0x8000
                );
                assert_eq!(req.allowed_nssai.len(), 1);
                assert_eq!(req.allowed_nssai[0].sst, 1);
            }
            other => panic!("expected InitialContextSetupRequest, got {other:?}"),
        }
    }

    /// Uplink NAS Transport (gNB → AMF): the core must decode the sim's encode.
    /// Pinned vector is the sim's nextgsim-ngap output; also checked as a core
    /// self round-trip so the framing the sim relies on does not regress.
    #[test]
    fn uplink_nas_transport_from_sim_decodes() {
        const SIM_UPLINK_NAS: [u8; 46] = [
            0x00, 0x2e, 0x40, 0x2a, 0x00, 0x00, 0x04, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, 0x00,
            0x55, 0x00, 0x02, 0x00, 0x01, 0x00, 0x26, 0x00, 0x04, 0x03, 0x7e, 0x00, 0x57, 0x00,
            0x79, 0x40, 0x0f, 0x40, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0xf1,
            0x10, 0x00, 0x00, 0x01,
        ];
        match crate::parser::decode_ngap_pdu(&SIM_UPLINK_NAS).unwrap() {
            crate::parser::NgapMessage::UplinkNasTransport(ul) => {
                assert_eq!(ul.amf_ue_ngap_id, 1);
                assert_eq!(ul.ran_ue_ngap_id, 1);
                assert_eq!(ul.nas_pdu, vec![0x7e, 0x00, 0x57]);
            }
            other => panic!("expected UplinkNasTransport, got {other:?}"),
        }
        // Core's own encode of the same logical message must be byte-identical.
        let core = build_uplink_nas_transport(&UplinkNasTransport {
            amf_ue_ngap_id: 1,
            ran_ue_ngap_id: 1,
            nas_pdu: vec![0x7e, 0x00, 0x57],
            user_location_info: UserLocationInformation::Nr {
                nr_cgi_plmn: [0x00, 0xF1, 0x10],
                nr_cell_identity: 1,
                tai_plmn: [0x00, 0xF1, 0x10],
                tai_tac: [0x00, 0x00, 0x01],
            },
        })
        .unwrap();
        assert_eq!(core, SIM_UPLINK_NAS.to_vec());
    }

    /// Initial Context Setup Response (gNB → AMF): the core must decode the
    /// sim's encode. (The sim marks the NGAP-ID IEs Criticality::Ignore vs the
    /// core's Reject — both are valid per spec and decode identically.)
    #[test]
    fn ics_response_from_sim_decodes() {
        const SIM_ICS_RESPONSE: [u8; 19] = [
            0x20, 0x0e, 0x00, 0x0f, 0x00, 0x00, 0x02, 0x00, 0x0a, 0x40, 0x02, 0x00, 0x01, 0x00,
            0x55, 0x40, 0x02, 0x00, 0x01,
        ];
        match crate::parser::decode_ngap_pdu(&SIM_ICS_RESPONSE).unwrap() {
            crate::parser::NgapMessage::InitialContextSetupResponse(r) => {
                assert_eq!(r.amf_ue_ngap_id, 1);
                assert_eq!(r.ran_ue_ngap_id, 1);
            }
            other => panic!("expected InitialContextSetupResponse, got {other:?}"),
        }
    }
}
