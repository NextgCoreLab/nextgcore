//! S1AP Message Parsers
//!
//! Functions for decoding S1AP PDU messages from APER bytes into high-level
//! types per 3GPP TS 36.413. The top-level entry point decodes the S1AP-PDU
//! CHOICE (initiatingMessage / successfulOutcome / unsuccessfulOutcome) and
//! dispatches on the procedure code.

use ogs_asn1c::per::{AperDecode, AperDecoder};
use ogs_asn1c::s1ap::ies::ProtocolIeContainer;
use ogs_asn1c::s1ap::pdu::*;
use ogs_asn1c::s1ap::types::{ProcedureCode, ProtocolIeId};

use crate::error::{S1apError, S1apResult};
use crate::ie;
use crate::types::*;

/// Decoded S1AP message - discriminated union of all supported message types
#[derive(Debug, Clone)]
pub enum S1apMessage {
    S1SetupRequest(S1SetupRequest),
    S1SetupResponse(S1SetupResponse),
    S1SetupFailure(S1SetupFailure),
    InitialUeMessage(InitialUeMessage),
    DownlinkNasTransport(DlNasTransport),
    UplinkNasTransport(UlNasTransport),
    NasNonDeliveryIndication(NasNonDeliveryIndication),
    InitialContextSetupRequest(InitialContextSetupRequest),
    InitialContextSetupResponse(InitialContextSetupResponse),
    InitialContextSetupFailure(InitialContextSetupFailure),
    UeContextReleaseRequest(UeContextReleaseRequest),
    UeContextReleaseCommand(UeContextReleaseCommand),
    UeContextReleaseComplete(UeContextReleaseComplete),
    ErabSetupRequest(ErabSetupRequest),
    ErabSetupResponse(ErabSetupResponse),
    ErabModifyRequest(ErabModifyRequest),
    ErabModifyResponse(ErabModifyResponse),
    ErabReleaseCommand(ErabReleaseCommand),
    ErabReleaseResponse(ErabReleaseResponse),
    Paging(Paging),
    Reset(Reset),
    ResetAcknowledge(ResetAcknowledge),
    ErrorIndication(ErrorIndication),
    HandoverRequired(HandoverRequired),
    HandoverCommand(HandoverCommand),
    HandoverPreparationFailure(HandoverPreparationFailure),
    HandoverRequest(HandoverRequest),
    HandoverRequestAcknowledge(HandoverRequestAcknowledge),
    HandoverFailure(HandoverFailure),
    HandoverNotify(HandoverNotify),
    PathSwitchRequest(PathSwitchRequest),
    PathSwitchRequestAcknowledge(PathSwitchRequestAcknowledge),
    PathSwitchRequestFailure(PathSwitchRequestFailure),
    HandoverCancel(HandoverCancel),
    HandoverCancelAcknowledge(HandoverCancelAcknowledge),
    UeCapabilityInfoIndication(UeCapabilityInfoIndication),
    /// Unknown/unsupported message
    Unknown {
        procedure_code: u8,
        message_type: &'static str,
    },
}

/// Decode an S1AP PDU from APER bytes into a high-level S1apMessage
pub fn decode_s1ap_pdu(data: &[u8]) -> S1apResult<S1apMessage> {
    let mut decoder = AperDecoder::new(data);
    let pdu = S1apPdu::decode_aper(&mut decoder)?;
    decode_s1ap_pdu_raw(pdu)
}

/// Decode the raw S1apPdu (without re-decoding from bytes)
pub fn decode_s1ap_pdu_raw(pdu: S1apPdu) -> S1apResult<S1apMessage> {
    match pdu {
        S1apPdu::InitiatingMessage(msg) => {
            let procedure_code = msg.procedure_code;
            let ies = initiating_container(msg.value);
            decode_initiating(procedure_code, ies)
        }
        S1apPdu::SuccessfulOutcome(msg) => {
            let procedure_code = msg.procedure_code;
            let ies = successful_container(msg.value);
            decode_successful(procedure_code, ies)
        }
        S1apPdu::UnsuccessfulOutcome(msg) => {
            let procedure_code = msg.procedure_code;
            let ies = unsuccessful_container(msg.value);
            decode_unsuccessful(procedure_code, ies)
        }
    }
}

fn initiating_container(value: InitiatingMessageValue) -> ProtocolIeContainer {
    match value {
        InitiatingMessageValue::S1SetupRequest(ies)
        | InitiatingMessageValue::InitialUeMessage(ies)
        | InitiatingMessageValue::UplinkNasTransport(ies)
        | InitiatingMessageValue::DownlinkNasTransport(ies)
        | InitiatingMessageValue::InitialContextSetupRequest(ies)
        | InitiatingMessageValue::UeContextReleaseCommand(ies)
        | InitiatingMessageValue::UeContextReleaseRequest(ies)
        | InitiatingMessageValue::ERabSetupRequest(ies)
        | InitiatingMessageValue::ERabModifyRequest(ies)
        | InitiatingMessageValue::ERabReleaseCommand(ies)
        | InitiatingMessageValue::HandoverRequired(ies)
        | InitiatingMessageValue::HandoverRequest(ies)
        | InitiatingMessageValue::PathSwitchRequest(ies)
        | InitiatingMessageValue::Reset(ies)
        | InitiatingMessageValue::ErrorIndication(ies)
        | InitiatingMessageValue::Paging(ies)
        | InitiatingMessageValue::Other(ies) => ies,
    }
}

fn successful_container(value: SuccessfulOutcomeValue) -> ProtocolIeContainer {
    match value {
        SuccessfulOutcomeValue::S1SetupResponse(ies)
        | SuccessfulOutcomeValue::InitialContextSetupResponse(ies)
        | SuccessfulOutcomeValue::UeContextReleaseComplete(ies)
        | SuccessfulOutcomeValue::ERabSetupResponse(ies)
        | SuccessfulOutcomeValue::ERabModifyResponse(ies)
        | SuccessfulOutcomeValue::ERabReleaseResponse(ies)
        | SuccessfulOutcomeValue::HandoverCommand(ies)
        | SuccessfulOutcomeValue::HandoverRequestAcknowledge(ies)
        | SuccessfulOutcomeValue::PathSwitchRequestAcknowledge(ies)
        | SuccessfulOutcomeValue::ResetAcknowledge(ies)
        | SuccessfulOutcomeValue::Other(ies) => ies,
    }
}

fn unsuccessful_container(value: UnsuccessfulOutcomeValue) -> ProtocolIeContainer {
    match value {
        UnsuccessfulOutcomeValue::S1SetupFailure(ies)
        | UnsuccessfulOutcomeValue::InitialContextSetupFailure(ies)
        | UnsuccessfulOutcomeValue::HandoverPreparationFailure(ies)
        | UnsuccessfulOutcomeValue::HandoverFailure(ies)
        | UnsuccessfulOutcomeValue::PathSwitchRequestFailure(ies)
        | UnsuccessfulOutcomeValue::Other(ies) => ies,
    }
}

fn decode_initiating(
    procedure_code: ProcedureCode,
    ies: ProtocolIeContainer,
) -> S1apResult<S1apMessage> {
    match procedure_code {
        ProcedureCode::S1_SETUP => Ok(S1apMessage::S1SetupRequest(parse_s1_setup_request(ies)?)),
        ProcedureCode::INITIAL_UE_MESSAGE => Ok(S1apMessage::InitialUeMessage(
            parse_initial_ue_message(ies)?,
        )),
        ProcedureCode::DOWNLINK_NAS_TRANSPORT => Ok(S1apMessage::DownlinkNasTransport(
            parse_downlink_nas_transport(ies)?,
        )),
        ProcedureCode::UPLINK_NAS_TRANSPORT => Ok(S1apMessage::UplinkNasTransport(
            parse_uplink_nas_transport(ies)?,
        )),
        ProcedureCode::NAS_NON_DELIVERY_INDICATION => Ok(S1apMessage::NasNonDeliveryIndication(
            parse_nas_non_delivery_indication(ies)?,
        )),
        ProcedureCode::INITIAL_CONTEXT_SETUP => Ok(S1apMessage::InitialContextSetupRequest(
            parse_initial_context_setup_request(ies)?,
        )),
        ProcedureCode::UE_CONTEXT_RELEASE_REQUEST => Ok(S1apMessage::UeContextReleaseRequest(
            parse_ue_context_release_request(ies)?,
        )),
        ProcedureCode::UE_CONTEXT_RELEASE => Ok(S1apMessage::UeContextReleaseCommand(
            parse_ue_context_release_command(ies)?,
        )),
        ProcedureCode::E_RAB_SETUP => Ok(S1apMessage::ErabSetupRequest(parse_erab_setup_request(
            ies,
        )?)),
        ProcedureCode::E_RAB_MODIFY => Ok(S1apMessage::ErabModifyRequest(
            parse_erab_modify_request(ies)?,
        )),
        ProcedureCode::E_RAB_RELEASE => Ok(S1apMessage::ErabReleaseCommand(
            parse_erab_release_command(ies)?,
        )),
        ProcedureCode::PAGING => Ok(S1apMessage::Paging(parse_paging(ies)?)),
        ProcedureCode::RESET => Ok(S1apMessage::Reset(parse_reset(ies)?)),
        ProcedureCode::ERROR_INDICATION => {
            Ok(S1apMessage::ErrorIndication(parse_error_indication(ies)?))
        }
        ProcedureCode::HANDOVER_PREPARATION => {
            Ok(S1apMessage::HandoverRequired(parse_handover_required(ies)?))
        }
        ProcedureCode::HANDOVER_RESOURCE_ALLOCATION => {
            Ok(S1apMessage::HandoverRequest(parse_handover_request(ies)?))
        }
        ProcedureCode::HANDOVER_NOTIFICATION => {
            Ok(S1apMessage::HandoverNotify(parse_handover_notify(ies)?))
        }
        ProcedureCode::PATH_SWITCH_REQUEST => Ok(S1apMessage::PathSwitchRequest(
            parse_path_switch_request(ies)?,
        )),
        ProcedureCode::HANDOVER_CANCEL => {
            Ok(S1apMessage::HandoverCancel(parse_handover_cancel(ies)?))
        }
        ProcedureCode::UE_CAPABILITY_INFO_INDICATION => Ok(
            S1apMessage::UeCapabilityInfoIndication(parse_ue_capability_info_indication(ies)?),
        ),
        _ => Ok(S1apMessage::Unknown {
            procedure_code: procedure_code.0,
            message_type: "InitiatingMessage",
        }),
    }
}

fn decode_successful(
    procedure_code: ProcedureCode,
    ies: ProtocolIeContainer,
) -> S1apResult<S1apMessage> {
    match procedure_code {
        ProcedureCode::S1_SETUP => Ok(S1apMessage::S1SetupResponse(parse_s1_setup_response(ies)?)),
        ProcedureCode::INITIAL_CONTEXT_SETUP => Ok(S1apMessage::InitialContextSetupResponse(
            parse_initial_context_setup_response(ies)?,
        )),
        ProcedureCode::UE_CONTEXT_RELEASE => Ok(S1apMessage::UeContextReleaseComplete(
            parse_ue_context_release_complete(ies)?,
        )),
        ProcedureCode::E_RAB_SETUP => Ok(S1apMessage::ErabSetupResponse(
            parse_erab_setup_response(ies)?,
        )),
        ProcedureCode::E_RAB_MODIFY => Ok(S1apMessage::ErabModifyResponse(
            parse_erab_modify_response(ies)?,
        )),
        ProcedureCode::E_RAB_RELEASE => Ok(S1apMessage::ErabReleaseResponse(
            parse_erab_release_response(ies)?,
        )),
        ProcedureCode::RESET => Ok(S1apMessage::ResetAcknowledge(parse_reset_acknowledge(ies)?)),
        ProcedureCode::HANDOVER_PREPARATION => {
            Ok(S1apMessage::HandoverCommand(parse_handover_command(ies)?))
        }
        ProcedureCode::HANDOVER_RESOURCE_ALLOCATION => Ok(S1apMessage::HandoverRequestAcknowledge(
            parse_handover_request_acknowledge(ies)?,
        )),
        ProcedureCode::PATH_SWITCH_REQUEST => Ok(S1apMessage::PathSwitchRequestAcknowledge(
            parse_path_switch_request_acknowledge(ies)?,
        )),
        ProcedureCode::HANDOVER_CANCEL => Ok(S1apMessage::HandoverCancelAcknowledge(
            parse_handover_cancel_acknowledge(ies)?,
        )),
        _ => Ok(S1apMessage::Unknown {
            procedure_code: procedure_code.0,
            message_type: "SuccessfulOutcome",
        }),
    }
}

fn decode_unsuccessful(
    procedure_code: ProcedureCode,
    ies: ProtocolIeContainer,
) -> S1apResult<S1apMessage> {
    match procedure_code {
        ProcedureCode::S1_SETUP => Ok(S1apMessage::S1SetupFailure(parse_s1_setup_failure(ies)?)),
        ProcedureCode::INITIAL_CONTEXT_SETUP => Ok(S1apMessage::InitialContextSetupFailure(
            parse_initial_context_setup_failure(ies)?,
        )),
        ProcedureCode::HANDOVER_PREPARATION => Ok(S1apMessage::HandoverPreparationFailure(
            parse_handover_preparation_failure(ies)?,
        )),
        ProcedureCode::HANDOVER_RESOURCE_ALLOCATION => {
            Ok(S1apMessage::HandoverFailure(parse_handover_failure(ies)?))
        }
        ProcedureCode::PATH_SWITCH_REQUEST => Ok(S1apMessage::PathSwitchRequestFailure(
            parse_path_switch_request_failure(ies)?,
        )),
        _ => Ok(S1apMessage::Unknown {
            procedure_code: procedure_code.0,
            message_type: "UnsuccessfulOutcome",
        }),
    }
}

// ============================================================================
// S1 Setup parsers
// ============================================================================

fn parse_s1_setup_request(container: ProtocolIeContainer) -> S1apResult<S1SetupRequest> {
    let mut global_enb_id = None;
    let mut enb_name = None;
    let mut supported_tas = None;
    let mut default_paging_drx = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::GLOBAL_ENB_ID => {
                global_enb_id = Some(ie::decode_global_enb_id(field)?);
            }
            ProtocolIeId::ENB_NAME => {
                enb_name = Some(ie::decode_enb_name(field)?);
            }
            ProtocolIeId::SUPPORTED_TAS => {
                supported_tas = Some(ie::decode_supported_tas(field)?);
            }
            ProtocolIeId::DEFAULT_PAGING_DRX => {
                default_paging_drx = Some(ie::decode_default_paging_drx(field)?);
            }
            _ => {} // Skip unknown IEs
        }
    }

    Ok(S1SetupRequest {
        global_enb_id: global_enb_id.ok_or(S1apError::MissingMandatoryIe("Global-ENB-ID"))?,
        enb_name,
        supported_tas: supported_tas.ok_or(S1apError::MissingMandatoryIe("SupportedTAs"))?,
        default_paging_drx: default_paging_drx
            .ok_or(S1apError::MissingMandatoryIe("DefaultPagingDRX"))?,
    })
}

fn parse_s1_setup_response(container: ProtocolIeContainer) -> S1apResult<S1SetupResponse> {
    let mut mme_name = None;
    let mut served_gummeis = None;
    let mut relative_mme_capacity = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::MME_NAME => {
                mme_name = Some(ie::decode_mme_name(field)?);
            }
            ProtocolIeId::SERVED_GUMMEIS => {
                served_gummeis = Some(ie::decode_served_gummeis(field)?);
            }
            ProtocolIeId::RELATIVE_MME_CAPACITY => {
                relative_mme_capacity = Some(ie::decode_relative_mme_capacity(field)?);
            }
            _ => {}
        }
    }

    Ok(S1SetupResponse {
        mme_name,
        served_gummeis: served_gummeis.ok_or(S1apError::MissingMandatoryIe("ServedGUMMEIs"))?,
        relative_mme_capacity: relative_mme_capacity
            .ok_or(S1apError::MissingMandatoryIe("RelativeMMECapacity"))?,
    })
}

fn parse_s1_setup_failure(container: ProtocolIeContainer) -> S1apResult<S1SetupFailure> {
    let mut cause = None;
    let mut time_to_wait = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::CAUSE => {
                cause = Some(ie::decode_cause(field)?);
            }
            ProtocolIeId::TIME_TO_WAIT => {
                time_to_wait = Some(ie::decode_time_to_wait(field)?);
            }
            _ => {}
        }
    }

    Ok(S1SetupFailure {
        cause: cause.ok_or(S1apError::MissingMandatoryIe("Cause"))?,
        time_to_wait,
    })
}

// ============================================================================
// NAS Transport parsers
// ============================================================================

fn parse_initial_ue_message(container: ProtocolIeContainer) -> S1apResult<InitialUeMessage> {
    let mut enb_ue_s1ap_id = None;
    let mut nas_pdu = None;
    let mut tai = None;
    let mut eutran_cgi = None;
    let mut rrc_establishment_cause = None;
    let mut s_tmsi = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = Some(ie::decode_enb_ue_s1ap_id(field)?);
            }
            ProtocolIeId::NAS_PDU => {
                nas_pdu = Some(ie::decode_nas_pdu(field)?);
            }
            ProtocolIeId::TAI => {
                tai = Some(ie::decode_tai(field)?);
            }
            ProtocolIeId::EUTRAN_CGI => {
                eutran_cgi = Some(ie::decode_eutran_cgi(field)?);
            }
            ProtocolIeId::RRC_ESTABLISHMENT_CAUSE => {
                rrc_establishment_cause = Some(ie::decode_rrc_establishment_cause(field)?);
            }
            ProtocolIeId::S_TMSI => {
                s_tmsi = Some(ie::decode_s_tmsi(field)?);
            }
            _ => {}
        }
    }

    Ok(InitialUeMessage {
        enb_ue_s1ap_id: enb_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("eNB-UE-S1AP-ID"))?,
        nas_pdu: nas_pdu.ok_or(S1apError::MissingMandatoryIe("NAS-PDU"))?,
        tai: tai.ok_or(S1apError::MissingMandatoryIe("TAI"))?,
        eutran_cgi: eutran_cgi.ok_or(S1apError::MissingMandatoryIe("EUTRAN-CGI"))?,
        rrc_establishment_cause: rrc_establishment_cause
            .ok_or(S1apError::MissingMandatoryIe("RRC-Establishment-Cause"))?,
        s_tmsi,
    })
}

fn parse_downlink_nas_transport(container: ProtocolIeContainer) -> S1apResult<DlNasTransport> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut nas_pdu = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = Some(ie::decode_mme_ue_s1ap_id(field)?);
            }
            ProtocolIeId::ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = Some(ie::decode_enb_ue_s1ap_id(field)?);
            }
            ProtocolIeId::NAS_PDU => {
                nas_pdu = Some(ie::decode_nas_pdu(field)?);
            }
            _ => {}
        }
    }

    Ok(DlNasTransport {
        mme_ue_s1ap_id: mme_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("MME-UE-S1AP-ID"))?,
        enb_ue_s1ap_id: enb_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("eNB-UE-S1AP-ID"))?,
        nas_pdu: nas_pdu.ok_or(S1apError::MissingMandatoryIe("NAS-PDU"))?,
    })
}

fn parse_uplink_nas_transport(container: ProtocolIeContainer) -> S1apResult<UlNasTransport> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut nas_pdu = None;
    let mut eutran_cgi = None;
    let mut tai = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = Some(ie::decode_mme_ue_s1ap_id(field)?);
            }
            ProtocolIeId::ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = Some(ie::decode_enb_ue_s1ap_id(field)?);
            }
            ProtocolIeId::NAS_PDU => {
                nas_pdu = Some(ie::decode_nas_pdu(field)?);
            }
            ProtocolIeId::EUTRAN_CGI => {
                eutran_cgi = Some(ie::decode_eutran_cgi(field)?);
            }
            ProtocolIeId::TAI => {
                tai = Some(ie::decode_tai(field)?);
            }
            _ => {}
        }
    }

    Ok(UlNasTransport {
        mme_ue_s1ap_id: mme_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("MME-UE-S1AP-ID"))?,
        enb_ue_s1ap_id: enb_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("eNB-UE-S1AP-ID"))?,
        nas_pdu: nas_pdu.ok_or(S1apError::MissingMandatoryIe("NAS-PDU"))?,
        eutran_cgi: eutran_cgi.ok_or(S1apError::MissingMandatoryIe("EUTRAN-CGI"))?,
        tai: tai.ok_or(S1apError::MissingMandatoryIe("TAI"))?,
    })
}

fn parse_nas_non_delivery_indication(
    container: ProtocolIeContainer,
) -> S1apResult<NasNonDeliveryIndication> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut nas_pdu = None;
    let mut cause = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = Some(ie::decode_mme_ue_s1ap_id(field)?);
            }
            ProtocolIeId::ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = Some(ie::decode_enb_ue_s1ap_id(field)?);
            }
            ProtocolIeId::NAS_PDU => {
                nas_pdu = Some(ie::decode_nas_pdu(field)?);
            }
            ProtocolIeId::CAUSE => {
                cause = Some(ie::decode_cause(field)?);
            }
            _ => {}
        }
    }

    Ok(NasNonDeliveryIndication {
        mme_ue_s1ap_id: mme_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("MME-UE-S1AP-ID"))?,
        enb_ue_s1ap_id: enb_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("eNB-UE-S1AP-ID"))?,
        nas_pdu: nas_pdu.ok_or(S1apError::MissingMandatoryIe("NAS-PDU"))?,
        cause: cause.ok_or(S1apError::MissingMandatoryIe("Cause"))?,
    })
}

// ============================================================================
// Initial Context Setup parsers
// ============================================================================

fn parse_initial_context_setup_request(
    container: ProtocolIeContainer,
) -> S1apResult<InitialContextSetupRequest> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut ue_ambr = None;
    let mut erab_list = None;
    let mut ue_security_capabilities = None;
    let mut security_key = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = Some(ie::decode_mme_ue_s1ap_id(field)?);
            }
            ProtocolIeId::ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = Some(ie::decode_enb_ue_s1ap_id(field)?);
            }
            ProtocolIeId::UE_AGGREGATE_MAXIMUM_BITRATE => {
                ue_ambr = Some(ie::decode_ue_ambr(field)?);
            }
            ProtocolIeId::E_RAB_TO_BE_SETUP_LIST_CTXT_SU_REQ => {
                erab_list = Some(ie::decode_erab_to_be_setup_list_ctxt(field)?);
            }
            ProtocolIeId::UE_SECURITY_CAPABILITIES => {
                ue_security_capabilities = Some(ie::decode_ue_security_capabilities(field)?);
            }
            ProtocolIeId::SECURITY_KEY => {
                security_key = Some(ie::decode_security_key(field)?);
            }
            _ => {}
        }
    }

    Ok(InitialContextSetupRequest {
        mme_ue_s1ap_id: mme_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("MME-UE-S1AP-ID"))?,
        enb_ue_s1ap_id: enb_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("eNB-UE-S1AP-ID"))?,
        ue_ambr: ue_ambr.ok_or(S1apError::MissingMandatoryIe("uEaggregateMaximumBitrate"))?,
        erab_list: erab_list.ok_or(S1apError::MissingMandatoryIe("E-RABToBeSetupListCtxtSUReq"))?,
        ue_security_capabilities: ue_security_capabilities
            .ok_or(S1apError::MissingMandatoryIe("UESecurityCapabilities"))?,
        security_key: security_key.ok_or(S1apError::MissingMandatoryIe("SecurityKey"))?,
    })
}

fn parse_initial_context_setup_response(
    container: ProtocolIeContainer,
) -> S1apResult<InitialContextSetupResponse> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut erab_setup_list = None;
    let mut erab_failed_list = Vec::new();

    for field in &container.ies {
        match field.id {
            ProtocolIeId::MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = Some(ie::decode_mme_ue_s1ap_id(field)?);
            }
            ProtocolIeId::ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = Some(ie::decode_enb_ue_s1ap_id(field)?);
            }
            ProtocolIeId::E_RAB_SETUP_LIST_CTXT_SU_RES => {
                erab_setup_list = Some(ie::decode_erab_setup_list_ctxt_res(field)?);
            }
            ProtocolIeId::E_RAB_FAILED_TO_SETUP_LIST_CTXT_SU_RES => {
                erab_failed_list = erab_items_to_failed(ie::decode_erab_item_list(field)?);
            }
            _ => {}
        }
    }

    Ok(InitialContextSetupResponse {
        mme_ue_s1ap_id: mme_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("MME-UE-S1AP-ID"))?,
        enb_ue_s1ap_id: enb_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("eNB-UE-S1AP-ID"))?,
        erab_setup_list: erab_setup_list
            .ok_or(S1apError::MissingMandatoryIe("E-RABSetupListCtxtSURes"))?,
        erab_failed_list,
    })
}

fn parse_initial_context_setup_failure(
    container: ProtocolIeContainer,
) -> S1apResult<InitialContextSetupFailure> {
    let (mme_ue_s1ap_id, enb_ue_s1ap_id, cause) = parse_ids_and_cause(&container)?;
    Ok(InitialContextSetupFailure {
        mme_ue_s1ap_id,
        enb_ue_s1ap_id,
        cause,
    })
}

// ============================================================================
// UE Context Release parsers
// ============================================================================

fn parse_ue_context_release_request(
    container: ProtocolIeContainer,
) -> S1apResult<UeContextReleaseRequest> {
    let (mme_ue_s1ap_id, enb_ue_s1ap_id, cause) = parse_ids_and_cause(&container)?;
    Ok(UeContextReleaseRequest {
        mme_ue_s1ap_id,
        enb_ue_s1ap_id,
        cause,
    })
}

fn parse_ue_context_release_command(
    container: ProtocolIeContainer,
) -> S1apResult<UeContextReleaseCommand> {
    let mut ue_s1ap_ids = None;
    let mut cause = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::UE_S1AP_IDS => {
                ue_s1ap_ids = Some(ie::decode_ue_s1ap_ids(field)?);
            }
            ProtocolIeId::CAUSE => {
                cause = Some(ie::decode_cause(field)?);
            }
            _ => {}
        }
    }

    Ok(UeContextReleaseCommand {
        ue_s1ap_ids: ue_s1ap_ids.ok_or(S1apError::MissingMandatoryIe("UE-S1AP-IDs"))?,
        cause: cause.ok_or(S1apError::MissingMandatoryIe("Cause"))?,
    })
}

fn parse_ue_context_release_complete(
    container: ProtocolIeContainer,
) -> S1apResult<UeContextReleaseComplete> {
    let (mme_ue_s1ap_id, enb_ue_s1ap_id) = parse_ue_id_pair(&container)?;
    Ok(UeContextReleaseComplete {
        mme_ue_s1ap_id,
        enb_ue_s1ap_id,
    })
}

// ============================================================================
// E-RAB Management parsers
// ============================================================================

fn parse_erab_setup_request(container: ProtocolIeContainer) -> S1apResult<ErabSetupRequest> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut ue_ambr = None;
    let mut erab_list = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = Some(ie::decode_mme_ue_s1ap_id(field)?);
            }
            ProtocolIeId::ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = Some(ie::decode_enb_ue_s1ap_id(field)?);
            }
            ProtocolIeId::UE_AGGREGATE_MAXIMUM_BITRATE => {
                ue_ambr = Some(ie::decode_ue_ambr(field)?);
            }
            ProtocolIeId::E_RAB_TO_BE_SETUP_LIST_BEARER_SU_REQ => {
                erab_list = Some(ie::decode_erab_to_be_setup_list_bearer(field)?);
            }
            _ => {}
        }
    }

    Ok(ErabSetupRequest {
        mme_ue_s1ap_id: mme_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("MME-UE-S1AP-ID"))?,
        enb_ue_s1ap_id: enb_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("eNB-UE-S1AP-ID"))?,
        ue_ambr,
        erab_list: erab_list.ok_or(S1apError::MissingMandatoryIe(
            "E-RABToBeSetupListBearerSUReq",
        ))?,
    })
}

fn parse_erab_setup_response(container: ProtocolIeContainer) -> S1apResult<ErabSetupResponse> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut erab_setup_list = Vec::new();
    let mut erab_failed_list = Vec::new();

    for field in &container.ies {
        match field.id {
            ProtocolIeId::MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = Some(ie::decode_mme_ue_s1ap_id(field)?);
            }
            ProtocolIeId::ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = Some(ie::decode_enb_ue_s1ap_id(field)?);
            }
            ProtocolIeId::E_RAB_SETUP_LIST_BEARER_SU_RES => {
                erab_setup_list = ie::decode_erab_setup_list_bearer_res(field)?;
            }
            ProtocolIeId::E_RAB_FAILED_TO_SETUP_LIST_BEARER_SU_RES => {
                erab_failed_list = erab_items_to_failed(ie::decode_erab_item_list(field)?);
            }
            _ => {}
        }
    }

    Ok(ErabSetupResponse {
        mme_ue_s1ap_id: mme_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("MME-UE-S1AP-ID"))?,
        enb_ue_s1ap_id: enb_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("eNB-UE-S1AP-ID"))?,
        erab_setup_list,
        erab_failed_list,
    })
}

fn parse_erab_modify_request(container: ProtocolIeContainer) -> S1apResult<ErabModifyRequest> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut ue_ambr = None;
    let mut erab_list = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = Some(ie::decode_mme_ue_s1ap_id(field)?);
            }
            ProtocolIeId::ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = Some(ie::decode_enb_ue_s1ap_id(field)?);
            }
            ProtocolIeId::UE_AGGREGATE_MAXIMUM_BITRATE => {
                ue_ambr = Some(ie::decode_ue_ambr(field)?);
            }
            ProtocolIeId::E_RAB_TO_BE_MODIFIED_LIST_BEARER_MOD_REQ => {
                erab_list = Some(ie::decode_erab_to_be_modified_list(field)?);
            }
            _ => {}
        }
    }

    Ok(ErabModifyRequest {
        mme_ue_s1ap_id: mme_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("MME-UE-S1AP-ID"))?,
        enb_ue_s1ap_id: enb_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("eNB-UE-S1AP-ID"))?,
        ue_ambr,
        erab_list: erab_list.ok_or(S1apError::MissingMandatoryIe(
            "E-RABToBeModifiedListBearerModReq",
        ))?,
    })
}

fn parse_erab_modify_response(container: ProtocolIeContainer) -> S1apResult<ErabModifyResponse> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut erab_modify_list = Vec::new();
    let mut erab_failed_list = Vec::new();

    for field in &container.ies {
        match field.id {
            ProtocolIeId::MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = Some(ie::decode_mme_ue_s1ap_id(field)?);
            }
            ProtocolIeId::ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = Some(ie::decode_enb_ue_s1ap_id(field)?);
            }
            ProtocolIeId::E_RAB_MODIFY_LIST_BEARER_MOD_RES => {
                erab_modify_list = ie::decode_erab_modify_list_res(field)?;
            }
            ProtocolIeId::E_RAB_FAILED_TO_MODIFY_LIST => {
                erab_failed_list = erab_items_to_failed(ie::decode_erab_item_list(field)?);
            }
            _ => {}
        }
    }

    Ok(ErabModifyResponse {
        mme_ue_s1ap_id: mme_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("MME-UE-S1AP-ID"))?,
        enb_ue_s1ap_id: enb_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("eNB-UE-S1AP-ID"))?,
        erab_modify_list,
        erab_failed_list,
    })
}

fn parse_erab_release_command(container: ProtocolIeContainer) -> S1apResult<ErabReleaseCommand> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut ue_ambr = None;
    let mut erab_list = None;
    let mut nas_pdu = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = Some(ie::decode_mme_ue_s1ap_id(field)?);
            }
            ProtocolIeId::ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = Some(ie::decode_enb_ue_s1ap_id(field)?);
            }
            ProtocolIeId::UE_AGGREGATE_MAXIMUM_BITRATE => {
                ue_ambr = Some(ie::decode_ue_ambr(field)?);
            }
            ProtocolIeId::E_RAB_TO_BE_RELEASED_LIST => {
                erab_list = Some(erab_items_to_list(ie::decode_erab_item_list(field)?));
            }
            ProtocolIeId::NAS_PDU => {
                nas_pdu = Some(ie::decode_nas_pdu(field)?);
            }
            _ => {}
        }
    }

    Ok(ErabReleaseCommand {
        mme_ue_s1ap_id: mme_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("MME-UE-S1AP-ID"))?,
        enb_ue_s1ap_id: enb_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("eNB-UE-S1AP-ID"))?,
        ue_ambr,
        erab_list: erab_list.ok_or(S1apError::MissingMandatoryIe("E-RABToBeReleasedList"))?,
        nas_pdu,
    })
}

fn parse_erab_release_response(container: ProtocolIeContainer) -> S1apResult<ErabReleaseResponse> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut erab_release_list = Vec::new();
    let mut erab_failed_list = Vec::new();

    for field in &container.ies {
        match field.id {
            ProtocolIeId::MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = Some(ie::decode_mme_ue_s1ap_id(field)?);
            }
            ProtocolIeId::ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = Some(ie::decode_enb_ue_s1ap_id(field)?);
            }
            ProtocolIeId::E_RAB_RELEASE_LIST_BEARER_REL_COMP => {
                erab_release_list = ie::decode_erab_release_list_rel_comp(field)?;
            }
            ProtocolIeId::E_RAB_FAILED_TO_RELEASE_LIST => {
                erab_failed_list = erab_items_to_failed(ie::decode_erab_item_list(field)?);
            }
            _ => {}
        }
    }

    Ok(ErabReleaseResponse {
        mme_ue_s1ap_id: mme_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("MME-UE-S1AP-ID"))?,
        enb_ue_s1ap_id: enb_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("eNB-UE-S1AP-ID"))?,
        erab_release_list,
        erab_failed_list,
    })
}

// ============================================================================
// Paging / Reset / Error Indication parsers
// ============================================================================

fn parse_paging(container: ProtocolIeContainer) -> S1apResult<Paging> {
    let mut ue_identity_index = None;
    let mut ue_paging_id = None;
    let mut paging_drx = None;
    let mut cn_domain = None;
    let mut tai_list = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::UE_IDENTITY_INDEX_VALUE => {
                ue_identity_index = Some(ie::decode_ue_identity_index(field)?);
            }
            ProtocolIeId::UE_PAGING_ID => {
                ue_paging_id = Some(ie::decode_ue_paging_id(field)?);
            }
            ProtocolIeId::PAGING_DRX => {
                paging_drx = Some(ie::decode_paging_drx(field)?);
            }
            ProtocolIeId::CN_DOMAIN => {
                cn_domain = Some(ie::decode_cn_domain(field)?);
            }
            ProtocolIeId::TAI_LIST => {
                tai_list = Some(ie::decode_tai_list(field)?);
            }
            _ => {}
        }
    }

    Ok(Paging {
        ue_identity_index: ue_identity_index
            .ok_or(S1apError::MissingMandatoryIe("UEIdentityIndexValue"))?,
        ue_paging_id: ue_paging_id.ok_or(S1apError::MissingMandatoryIe("UEPagingID"))?,
        paging_drx,
        cn_domain: cn_domain.ok_or(S1apError::MissingMandatoryIe("CNDomain"))?,
        tai_list: tai_list.ok_or(S1apError::MissingMandatoryIe("TAIList"))?,
    })
}

fn parse_reset(container: ProtocolIeContainer) -> S1apResult<Reset> {
    let mut cause = None;
    let mut reset_type = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::CAUSE => {
                cause = Some(ie::decode_cause(field)?);
            }
            ProtocolIeId::RESET_TYPE => {
                reset_type = Some(ie::decode_reset_type(field)?);
            }
            _ => {}
        }
    }

    Ok(Reset {
        cause: cause.ok_or(S1apError::MissingMandatoryIe("Cause"))?,
        reset_type: reset_type.ok_or(S1apError::MissingMandatoryIe("ResetType"))?,
    })
}

fn parse_reset_acknowledge(container: ProtocolIeContainer) -> S1apResult<ResetAcknowledge> {
    let mut ue_associated_connections = Vec::new();

    for field in &container.ies {
        if field.id == ProtocolIeId::UE_ASSOCIATED_LOGICAL_S1_CONNECTION_LIST_RES_ACK {
            ue_associated_connections = ie::decode_ue_associated_connection_list_ack(field)?;
        }
    }

    Ok(ResetAcknowledge {
        ue_associated_connections,
    })
}

fn parse_error_indication(container: ProtocolIeContainer) -> S1apResult<ErrorIndication> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut cause = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = Some(ie::decode_mme_ue_s1ap_id(field)?);
            }
            ProtocolIeId::ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = Some(ie::decode_enb_ue_s1ap_id(field)?);
            }
            ProtocolIeId::CAUSE => {
                cause = Some(ie::decode_cause(field)?);
            }
            _ => {}
        }
    }

    Ok(ErrorIndication {
        mme_ue_s1ap_id,
        enb_ue_s1ap_id,
        cause,
    })
}

// ============================================================================
// Handover parsers
// ============================================================================

fn parse_handover_required(container: ProtocolIeContainer) -> S1apResult<HandoverRequired> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut handover_type = None;
    let mut cause = None;
    let mut target_id = None;
    let mut source_to_target_container = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = Some(ie::decode_mme_ue_s1ap_id(field)?);
            }
            ProtocolIeId::ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = Some(ie::decode_enb_ue_s1ap_id(field)?);
            }
            ProtocolIeId::HANDOVER_TYPE => {
                handover_type = Some(ie::decode_handover_type(field)?);
            }
            ProtocolIeId::CAUSE => {
                cause = Some(ie::decode_cause(field)?);
            }
            ProtocolIeId::TARGET_ID => {
                target_id = Some(ie::decode_target_id(field)?);
            }
            ProtocolIeId::SOURCE_TO_TARGET_TRANSPARENT_CONTAINER => {
                source_to_target_container = Some(ie::decode_source_to_target_container(field)?);
            }
            _ => {}
        }
    }

    Ok(HandoverRequired {
        mme_ue_s1ap_id: mme_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("MME-UE-S1AP-ID"))?,
        enb_ue_s1ap_id: enb_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("eNB-UE-S1AP-ID"))?,
        handover_type: handover_type.ok_or(S1apError::MissingMandatoryIe("HandoverType"))?,
        cause: cause.ok_or(S1apError::MissingMandatoryIe("Cause"))?,
        target_id: target_id.ok_or(S1apError::MissingMandatoryIe("TargetID"))?,
        source_to_target_container: source_to_target_container.ok_or(
            S1apError::MissingMandatoryIe("Source-ToTarget-TransparentContainer"),
        )?,
    })
}

fn parse_handover_command(container: ProtocolIeContainer) -> S1apResult<HandoverCommand> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut handover_type = None;
    let mut erab_subject_to_forwarding_list = Vec::new();
    let mut erab_to_release_list = Vec::new();
    let mut target_to_source_container = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = Some(ie::decode_mme_ue_s1ap_id(field)?);
            }
            ProtocolIeId::ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = Some(ie::decode_enb_ue_s1ap_id(field)?);
            }
            ProtocolIeId::HANDOVER_TYPE => {
                handover_type = Some(ie::decode_handover_type(field)?);
            }
            ProtocolIeId::E_RAB_SUBJECT_TO_DATA_FORWARDING_LIST => {
                erab_subject_to_forwarding_list = ie::decode_erab_data_forwarding_list(field)?;
            }
            ProtocolIeId::E_RAB_TO_RELEASE_LIST_HO_CMD => {
                erab_to_release_list = erab_items_to_list(ie::decode_erab_item_list(field)?);
            }
            ProtocolIeId::TARGET_TO_SOURCE_TRANSPARENT_CONTAINER => {
                target_to_source_container = Some(ie::decode_target_to_source_container(field)?);
            }
            _ => {}
        }
    }

    Ok(HandoverCommand {
        mme_ue_s1ap_id: mme_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("MME-UE-S1AP-ID"))?,
        enb_ue_s1ap_id: enb_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("eNB-UE-S1AP-ID"))?,
        handover_type: handover_type.ok_or(S1apError::MissingMandatoryIe("HandoverType"))?,
        erab_subject_to_forwarding_list,
        erab_to_release_list,
        target_to_source_container: target_to_source_container.ok_or(
            S1apError::MissingMandatoryIe("Target-ToSource-TransparentContainer"),
        )?,
    })
}

fn parse_handover_preparation_failure(
    container: ProtocolIeContainer,
) -> S1apResult<HandoverPreparationFailure> {
    let (mme_ue_s1ap_id, enb_ue_s1ap_id, cause) = parse_ids_and_cause(&container)?;
    Ok(HandoverPreparationFailure {
        mme_ue_s1ap_id,
        enb_ue_s1ap_id,
        cause,
    })
}

fn parse_handover_request(container: ProtocolIeContainer) -> S1apResult<HandoverRequest> {
    let mut mme_ue_s1ap_id = None;
    let mut handover_type = None;
    let mut cause = None;
    let mut ue_ambr = None;
    let mut erab_list = None;
    let mut source_to_target_container = None;
    let mut ue_security_capabilities = None;
    let mut security_context = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = Some(ie::decode_mme_ue_s1ap_id(field)?);
            }
            ProtocolIeId::HANDOVER_TYPE => {
                handover_type = Some(ie::decode_handover_type(field)?);
            }
            ProtocolIeId::CAUSE => {
                cause = Some(ie::decode_cause(field)?);
            }
            ProtocolIeId::UE_AGGREGATE_MAXIMUM_BITRATE => {
                ue_ambr = Some(ie::decode_ue_ambr(field)?);
            }
            ProtocolIeId::E_RAB_TO_BE_SETUP_LIST_HO_REQ => {
                erab_list = Some(ie::decode_erab_to_be_setup_list_ho_req(field)?);
            }
            ProtocolIeId::SOURCE_TO_TARGET_TRANSPARENT_CONTAINER => {
                source_to_target_container = Some(ie::decode_source_to_target_container(field)?);
            }
            ProtocolIeId::UE_SECURITY_CAPABILITIES => {
                ue_security_capabilities = Some(ie::decode_ue_security_capabilities(field)?);
            }
            ProtocolIeId::SECURITY_CONTEXT => {
                security_context = Some(ie::decode_security_context(field)?);
            }
            _ => {}
        }
    }

    Ok(HandoverRequest {
        mme_ue_s1ap_id: mme_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("MME-UE-S1AP-ID"))?,
        handover_type: handover_type.ok_or(S1apError::MissingMandatoryIe("HandoverType"))?,
        cause: cause.ok_or(S1apError::MissingMandatoryIe("Cause"))?,
        ue_ambr: ue_ambr.ok_or(S1apError::MissingMandatoryIe("uEaggregateMaximumBitrate"))?,
        erab_list: erab_list.ok_or(S1apError::MissingMandatoryIe("E-RABToBeSetupListHOReq"))?,
        source_to_target_container: source_to_target_container.ok_or(
            S1apError::MissingMandatoryIe("Source-ToTarget-TransparentContainer"),
        )?,
        ue_security_capabilities: ue_security_capabilities
            .ok_or(S1apError::MissingMandatoryIe("UESecurityCapabilities"))?,
        security_context: security_context
            .ok_or(S1apError::MissingMandatoryIe("SecurityContext"))?,
    })
}

fn parse_handover_request_acknowledge(
    container: ProtocolIeContainer,
) -> S1apResult<HandoverRequestAcknowledge> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut erab_admitted_list = None;
    let mut erab_failed_list = Vec::new();
    let mut target_to_source_container = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = Some(ie::decode_mme_ue_s1ap_id(field)?);
            }
            ProtocolIeId::ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = Some(ie::decode_enb_ue_s1ap_id(field)?);
            }
            ProtocolIeId::E_RAB_ADMITTED_LIST => {
                erab_admitted_list = Some(ie::decode_erab_admitted_list(field)?);
            }
            ProtocolIeId::E_RAB_FAILED_TO_SETUP_LIST_HO_REQ_ACK => {
                erab_failed_list =
                    erab_items_to_failed(ie::decode_erab_failed_to_setup_list_ho_req_ack(field)?);
            }
            ProtocolIeId::TARGET_TO_SOURCE_TRANSPARENT_CONTAINER => {
                target_to_source_container = Some(ie::decode_target_to_source_container(field)?);
            }
            _ => {}
        }
    }

    Ok(HandoverRequestAcknowledge {
        mme_ue_s1ap_id: mme_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("MME-UE-S1AP-ID"))?,
        enb_ue_s1ap_id: enb_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("eNB-UE-S1AP-ID"))?,
        erab_admitted_list: erab_admitted_list
            .ok_or(S1apError::MissingMandatoryIe("E-RABAdmittedList"))?,
        erab_failed_list,
        target_to_source_container: target_to_source_container.ok_or(
            S1apError::MissingMandatoryIe("Target-ToSource-TransparentContainer"),
        )?,
    })
}

fn parse_handover_failure(container: ProtocolIeContainer) -> S1apResult<HandoverFailure> {
    let mut mme_ue_s1ap_id = None;
    let mut cause = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = Some(ie::decode_mme_ue_s1ap_id(field)?);
            }
            ProtocolIeId::CAUSE => {
                cause = Some(ie::decode_cause(field)?);
            }
            _ => {}
        }
    }

    Ok(HandoverFailure {
        mme_ue_s1ap_id: mme_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("MME-UE-S1AP-ID"))?,
        cause: cause.ok_or(S1apError::MissingMandatoryIe("Cause"))?,
    })
}

fn parse_handover_notify(container: ProtocolIeContainer) -> S1apResult<HandoverNotify> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut eutran_cgi = None;
    let mut tai = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = Some(ie::decode_mme_ue_s1ap_id(field)?);
            }
            ProtocolIeId::ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = Some(ie::decode_enb_ue_s1ap_id(field)?);
            }
            ProtocolIeId::EUTRAN_CGI => {
                eutran_cgi = Some(ie::decode_eutran_cgi(field)?);
            }
            ProtocolIeId::TAI => {
                tai = Some(ie::decode_tai(field)?);
            }
            _ => {}
        }
    }

    Ok(HandoverNotify {
        mme_ue_s1ap_id: mme_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("MME-UE-S1AP-ID"))?,
        enb_ue_s1ap_id: enb_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("eNB-UE-S1AP-ID"))?,
        eutran_cgi: eutran_cgi.ok_or(S1apError::MissingMandatoryIe("EUTRAN-CGI"))?,
        tai: tai.ok_or(S1apError::MissingMandatoryIe("TAI"))?,
    })
}

fn parse_path_switch_request(container: ProtocolIeContainer) -> S1apResult<PathSwitchRequest> {
    let mut enb_ue_s1ap_id = None;
    let mut erab_switched_dl_list = None;
    let mut source_mme_ue_s1ap_id = None;
    let mut eutran_cgi = None;
    let mut tai = None;
    let mut ue_security_capabilities = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = Some(ie::decode_enb_ue_s1ap_id(field)?);
            }
            ProtocolIeId::E_RAB_TO_BE_SWITCHED_DL_LIST => {
                erab_switched_dl_list = Some(ie::decode_erab_switched_dl_list(field)?);
            }
            ProtocolIeId::SOURCE_MME_UE_S1AP_ID => {
                source_mme_ue_s1ap_id = Some(ie::decode_source_mme_ue_s1ap_id(field)?);
            }
            ProtocolIeId::EUTRAN_CGI => {
                eutran_cgi = Some(ie::decode_eutran_cgi(field)?);
            }
            ProtocolIeId::TAI => {
                tai = Some(ie::decode_tai(field)?);
            }
            ProtocolIeId::UE_SECURITY_CAPABILITIES => {
                ue_security_capabilities = Some(ie::decode_ue_security_capabilities(field)?);
            }
            _ => {}
        }
    }

    Ok(PathSwitchRequest {
        enb_ue_s1ap_id: enb_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("eNB-UE-S1AP-ID"))?,
        erab_switched_dl_list: erab_switched_dl_list
            .ok_or(S1apError::MissingMandatoryIe("E-RABToBeSwitchedDLList"))?,
        source_mme_ue_s1ap_id: source_mme_ue_s1ap_id
            .ok_or(S1apError::MissingMandatoryIe("SourceMME-UE-S1AP-ID"))?,
        eutran_cgi: eutran_cgi.ok_or(S1apError::MissingMandatoryIe("EUTRAN-CGI"))?,
        tai: tai.ok_or(S1apError::MissingMandatoryIe("TAI"))?,
        ue_security_capabilities: ue_security_capabilities
            .ok_or(S1apError::MissingMandatoryIe("UESecurityCapabilities"))?,
    })
}

fn parse_path_switch_request_acknowledge(
    container: ProtocolIeContainer,
) -> S1apResult<PathSwitchRequestAcknowledge> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut erab_switched_ul_list = Vec::new();
    let mut security_context = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = Some(ie::decode_mme_ue_s1ap_id(field)?);
            }
            ProtocolIeId::ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = Some(ie::decode_enb_ue_s1ap_id(field)?);
            }
            ProtocolIeId::E_RAB_TO_BE_SWITCHED_UL_LIST => {
                erab_switched_ul_list = ie::decode_erab_switched_ul_list(field)?;
            }
            ProtocolIeId::SECURITY_CONTEXT => {
                security_context = Some(ie::decode_security_context(field)?);
            }
            _ => {}
        }
    }

    Ok(PathSwitchRequestAcknowledge {
        mme_ue_s1ap_id: mme_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("MME-UE-S1AP-ID"))?,
        enb_ue_s1ap_id: enb_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("eNB-UE-S1AP-ID"))?,
        erab_switched_ul_list,
        security_context: security_context
            .ok_or(S1apError::MissingMandatoryIe("SecurityContext"))?,
    })
}

fn parse_path_switch_request_failure(
    container: ProtocolIeContainer,
) -> S1apResult<PathSwitchRequestFailure> {
    let (mme_ue_s1ap_id, enb_ue_s1ap_id, cause) = parse_ids_and_cause(&container)?;
    Ok(PathSwitchRequestFailure {
        mme_ue_s1ap_id,
        enb_ue_s1ap_id,
        cause,
    })
}

fn parse_handover_cancel(container: ProtocolIeContainer) -> S1apResult<HandoverCancel> {
    let (mme_ue_s1ap_id, enb_ue_s1ap_id, cause) = parse_ids_and_cause(&container)?;
    Ok(HandoverCancel {
        mme_ue_s1ap_id,
        enb_ue_s1ap_id,
        cause,
    })
}

fn parse_handover_cancel_acknowledge(
    container: ProtocolIeContainer,
) -> S1apResult<HandoverCancelAcknowledge> {
    let (mme_ue_s1ap_id, enb_ue_s1ap_id) = parse_ue_id_pair(&container)?;
    Ok(HandoverCancelAcknowledge {
        mme_ue_s1ap_id,
        enb_ue_s1ap_id,
    })
}

// ============================================================================
// UE Capability Info Indication parser
// ============================================================================

fn parse_ue_capability_info_indication(
    container: ProtocolIeContainer,
) -> S1apResult<UeCapabilityInfoIndication> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut ue_radio_capability = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = Some(ie::decode_mme_ue_s1ap_id(field)?);
            }
            ProtocolIeId::ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = Some(ie::decode_enb_ue_s1ap_id(field)?);
            }
            ProtocolIeId::UE_RADIO_CAPABILITY => {
                ue_radio_capability = Some(ie::decode_ue_radio_capability(field)?);
            }
            _ => {}
        }
    }

    Ok(UeCapabilityInfoIndication {
        mme_ue_s1ap_id: mme_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("MME-UE-S1AP-ID"))?,
        enb_ue_s1ap_id: enb_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("eNB-UE-S1AP-ID"))?,
        ue_radio_capability: ue_radio_capability
            .ok_or(S1apError::MissingMandatoryIe("UERadioCapability"))?,
    })
}

// ============================================================================
// Shared field extraction helpers
// ============================================================================

fn parse_ue_id_pair(container: &ProtocolIeContainer) -> S1apResult<(u32, u32)> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = Some(ie::decode_mme_ue_s1ap_id(field)?);
            }
            ProtocolIeId::ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = Some(ie::decode_enb_ue_s1ap_id(field)?);
            }
            _ => {}
        }
    }

    Ok((
        mme_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("MME-UE-S1AP-ID"))?,
        enb_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("eNB-UE-S1AP-ID"))?,
    ))
}

fn parse_ids_and_cause(container: &ProtocolIeContainer) -> S1apResult<(u32, u32, Cause)> {
    let mut mme_ue_s1ap_id = None;
    let mut enb_ue_s1ap_id = None;
    let mut cause = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::MME_UE_S1AP_ID => {
                mme_ue_s1ap_id = Some(ie::decode_mme_ue_s1ap_id(field)?);
            }
            ProtocolIeId::ENB_UE_S1AP_ID => {
                enb_ue_s1ap_id = Some(ie::decode_enb_ue_s1ap_id(field)?);
            }
            ProtocolIeId::CAUSE => {
                cause = Some(ie::decode_cause(field)?);
            }
            _ => {}
        }
    }

    Ok((
        mme_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("MME-UE-S1AP-ID"))?,
        enb_ue_s1ap_id.ok_or(S1apError::MissingMandatoryIe("eNB-UE-S1AP-ID"))?,
        cause.ok_or(S1apError::MissingMandatoryIe("Cause"))?,
    ))
}

fn erab_items_to_failed(items: Vec<(u8, Cause)>) -> Vec<ErabFailedItem> {
    items
        .into_iter()
        .map(|(erab_id, cause)| ErabFailedItem { erab_id, cause })
        .collect()
}

fn erab_items_to_list(items: Vec<(u8, Cause)>) -> Vec<ErabItem> {
    items
        .into_iter()
        .map(|(erab_id, cause)| ErabItem { erab_id, cause })
        .collect()
}
