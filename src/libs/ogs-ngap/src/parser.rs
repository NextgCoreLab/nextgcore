//! NGAP Message Parsers
//!
//! Functions for decoding NGAP PDU messages from APER bytes into high-level types.
//! Each function decodes the PDU wrapper, extracts the IE container, and maps
//! the IEs to their strongly-typed representations.

use ogs_asn1c::ngap::ies::ProtocolIeContainer;
use ogs_asn1c::ngap::pdu::*;
use ogs_asn1c::ngap::types::ProtocolIeId;
use ogs_asn1c::per::{AperDecode, AperDecoder};

use crate::error::{NgapError, NgapResult};
use crate::ie;
use crate::types::*;

/// Decoded NGAP message - discriminated union of all supported message types
#[derive(Debug, Clone)]
pub enum NgapMessage {
    NgSetupRequest(NgSetupRequest),
    NgSetupResponse(NgSetupResponse),
    NgSetupFailure(NgSetupFailure),
    InitialUeMessage(InitialUeMessage),
    DownlinkNasTransport(DownlinkNasTransport),
    UplinkNasTransport(UplinkNasTransport),
    InitialContextSetupRequest(InitialContextSetupRequest),
    InitialContextSetupResponse(InitialContextSetupResponse),
    InitialContextSetupFailure(InitialContextSetupFailure),
    PduSessionResourceSetupRequest(PduSessionResourceSetupRequest),
    PduSessionResourceSetupResponse(PduSessionResourceSetupResponse),
    PduSessionResourceReleaseCommand(PduSessionResourceReleaseCommand),
    PduSessionResourceReleaseResponse(PduSessionResourceReleaseResponse),
    UeContextReleaseCommand(UeContextReleaseCommand),
    UeContextReleaseComplete(UeContextReleaseComplete),
    UeContextReleaseRequest(UeContextReleaseRequest),
    /// Unknown/unsupported message
    Unknown {
        procedure_code: u8,
        message_type: &'static str,
    },
}

/// Decode an NGAP PDU from APER bytes into a high-level NgapMessage
pub fn decode_ngap_pdu(data: &[u8]) -> NgapResult<NgapMessage> {
    let mut decoder = AperDecoder::new(data);
    let pdu = NgapPdu::decode_aper(&mut decoder)?;

    match pdu {
        NgapPdu::InitiatingMessage(msg) => decode_initiating_message(msg),
        NgapPdu::SuccessfulOutcome(msg) => decode_successful_outcome(msg),
        NgapPdu::UnsuccessfulOutcome(msg) => decode_unsuccessful_outcome(msg),
    }
}

/// Decode the raw NgapPdu (without re-decoding from bytes)
pub fn decode_ngap_pdu_raw(pdu: NgapPdu) -> NgapResult<NgapMessage> {
    match pdu {
        NgapPdu::InitiatingMessage(msg) => decode_initiating_message(msg),
        NgapPdu::SuccessfulOutcome(msg) => decode_successful_outcome(msg),
        NgapPdu::UnsuccessfulOutcome(msg) => decode_unsuccessful_outcome(msg),
    }
}

// ============================================================================
// Initiating Message dispatch
// ============================================================================

fn decode_initiating_message(msg: InitiatingMessage) -> NgapResult<NgapMessage> {
    match msg.value {
        InitiatingMessageValue::NgSetupRequest(ies) => {
            Ok(NgapMessage::NgSetupRequest(parse_ng_setup_request(ies)?))
        }
        InitiatingMessageValue::InitialUeMessage(ies) => {
            Ok(NgapMessage::InitialUeMessage(parse_initial_ue_message(ies)?))
        }
        InitiatingMessageValue::DownlinkNasTransport(ies) => {
            Ok(NgapMessage::DownlinkNasTransport(parse_downlink_nas_transport(ies)?))
        }
        InitiatingMessageValue::UplinkNasTransport(ies) => {
            Ok(NgapMessage::UplinkNasTransport(parse_uplink_nas_transport(ies)?))
        }
        InitiatingMessageValue::InitialContextSetupRequest(ies) => {
            Ok(NgapMessage::InitialContextSetupRequest(
                parse_initial_context_setup_request(ies)?,
            ))
        }
        InitiatingMessageValue::UeContextReleaseCommand(ies) => {
            Ok(NgapMessage::UeContextReleaseCommand(
                parse_ue_context_release_command(ies)?,
            ))
        }
        InitiatingMessageValue::UeContextReleaseRequest(ies) => {
            Ok(NgapMessage::UeContextReleaseRequest(
                parse_ue_context_release_request(ies)?,
            ))
        }
        InitiatingMessageValue::PduSessionResourceSetupRequest(ies) => {
            Ok(NgapMessage::PduSessionResourceSetupRequest(
                parse_pdu_session_resource_setup_request(ies)?,
            ))
        }
        InitiatingMessageValue::PduSessionResourceReleaseCommand(ies) => {
            Ok(NgapMessage::PduSessionResourceReleaseCommand(
                parse_pdu_session_resource_release_command(ies)?,
            ))
        }
        _ => Ok(NgapMessage::Unknown {
            procedure_code: msg.procedure_code.0,
            message_type: "InitiatingMessage",
        }),
    }
}

// ============================================================================
// Successful Outcome dispatch
// ============================================================================

fn decode_successful_outcome(msg: SuccessfulOutcome) -> NgapResult<NgapMessage> {
    match msg.value {
        SuccessfulOutcomeValue::NgSetupResponse(ies) => {
            Ok(NgapMessage::NgSetupResponse(parse_ng_setup_response(ies)?))
        }
        SuccessfulOutcomeValue::InitialContextSetupResponse(ies) => {
            Ok(NgapMessage::InitialContextSetupResponse(
                parse_initial_context_setup_response(ies)?,
            ))
        }
        SuccessfulOutcomeValue::UeContextReleaseComplete(ies) => {
            Ok(NgapMessage::UeContextReleaseComplete(
                parse_ue_context_release_complete(ies)?,
            ))
        }
        SuccessfulOutcomeValue::PduSessionResourceSetupResponse(ies) => {
            Ok(NgapMessage::PduSessionResourceSetupResponse(
                parse_pdu_session_resource_setup_response(ies)?,
            ))
        }
        SuccessfulOutcomeValue::PduSessionResourceReleaseResponse(ies) => {
            Ok(NgapMessage::PduSessionResourceReleaseResponse(
                parse_pdu_session_resource_release_response(ies)?,
            ))
        }
        // Handle messages that the low-level decoder maps to Other
        SuccessfulOutcomeValue::Other(ies) => {
            use ogs_asn1c::ngap::types::ProcedureCode;
            match msg.procedure_code {
                ProcedureCode::PDU_SESSION_RESOURCE_SETUP => {
                    Ok(NgapMessage::PduSessionResourceSetupResponse(
                        parse_pdu_session_resource_setup_response(ies)?,
                    ))
                }
                ProcedureCode::PDU_SESSION_RESOURCE_RELEASE => {
                    Ok(NgapMessage::PduSessionResourceReleaseResponse(
                        parse_pdu_session_resource_release_response(ies)?,
                    ))
                }
                _ => Ok(NgapMessage::Unknown {
                    procedure_code: msg.procedure_code.0,
                    message_type: "SuccessfulOutcome",
                }),
            }
        }
        _ => Ok(NgapMessage::Unknown {
            procedure_code: msg.procedure_code.0,
            message_type: "SuccessfulOutcome",
        }),
    }
}

// ============================================================================
// Unsuccessful Outcome dispatch
// ============================================================================

fn decode_unsuccessful_outcome(msg: UnsuccessfulOutcome) -> NgapResult<NgapMessage> {
    match msg.value {
        UnsuccessfulOutcomeValue::NgSetupFailure(ies) => {
            Ok(NgapMessage::NgSetupFailure(parse_ng_setup_failure(ies)?))
        }
        UnsuccessfulOutcomeValue::InitialContextSetupFailure(ies) => {
            Ok(NgapMessage::InitialContextSetupFailure(
                parse_initial_context_setup_failure(ies)?,
            ))
        }
        _ => Ok(NgapMessage::Unknown {
            procedure_code: msg.procedure_code.0,
            message_type: "UnsuccessfulOutcome",
        }),
    }
}

// ============================================================================
// B10.2: NG Setup parsers
// ============================================================================

fn parse_ng_setup_request(container: ProtocolIeContainer) -> NgapResult<NgSetupRequest> {
    let mut global_ran_node_id = None;
    let mut ran_node_name = None;
    let mut supported_ta_list = None;
    let mut default_paging_drx = PagingDrx::default();

    for field in &container.ies {
        match field.id.0 {
            ie::IE_ID_GLOBAL_RAN_NODE_ID => {
                global_ran_node_id = Some(ie::decode_global_ran_node_id(field)?);
            }
            ie::IE_ID_RAN_NODE_NAME => {
                ran_node_name = Some(ie::decode_ran_node_name(field)?);
            }
            ie::IE_ID_SUPPORTED_TA_LIST => {
                supported_ta_list = Some(ie::decode_supported_ta_list(field)?);
            }
            ie::IE_ID_DEFAULT_PAGING_DRX => {
                default_paging_drx = ie::decode_default_paging_drx(field)?;
            }
            _ => {} // Skip unknown IEs
        }
    }

    Ok(NgSetupRequest {
        global_ran_node_id: global_ran_node_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "GlobalRANNodeID",
            ie_id: ie::IE_ID_GLOBAL_RAN_NODE_ID,
        })?,
        ran_node_name,
        supported_ta_list: supported_ta_list.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "SupportedTAList",
            ie_id: ie::IE_ID_SUPPORTED_TA_LIST,
        })?,
        default_paging_drx,
    })
}

fn parse_ng_setup_response(container: ProtocolIeContainer) -> NgapResult<NgSetupResponse> {
    let mut amf_name = None;
    let mut served_guami_list = None;
    let mut relative_amf_capacity = None;
    let mut plmn_support_list = None;

    for field in &container.ies {
        match field.id.0 {
            ie::IE_ID_AMF_NAME => {
                amf_name = Some(ie::decode_amf_name(field)?);
            }
            ie::IE_ID_SERVED_GUAMI_LIST => {
                // TODO: Implement decode_served_guami_list for full round-trip
                // For now, we'll leave this as empty and populate from raw bytes
                served_guami_list = Some(Vec::new());
            }
            86 => {
                // RelativeAMFCapacity
                relative_amf_capacity = Some(ie::decode_relative_amf_capacity(field)?);
            }
            ie::IE_ID_PLMN_SUPPORT_LIST => {
                // TODO: Implement decode_plmn_support_list for full round-trip
                plmn_support_list = Some(Vec::new());
            }
            _ => {}
        }
    }

    Ok(NgSetupResponse {
        amf_name: amf_name.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMFName",
            ie_id: ie::IE_ID_AMF_NAME,
        })?,
        served_guami_list: served_guami_list.unwrap_or_default(),
        relative_amf_capacity: relative_amf_capacity.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RelativeAMFCapacity",
            ie_id: 86,
        })?,
        plmn_support_list: plmn_support_list.unwrap_or_default(),
    })
}

fn parse_ng_setup_failure(container: ProtocolIeContainer) -> NgapResult<NgSetupFailure> {
    let mut cause = None;
    let mut time_to_wait = None;
    let mut criticality_diagnostics = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::CAUSE => {
                cause = Some(ie::decode_cause(field)?);
            }
            ProtocolIeId::TIME_TO_WAIT => {
                time_to_wait = Some(ie::decode_time_to_wait(field)?);
            }
            ProtocolIeId::CRITICALITY_DIAGNOSTICS => {
                // Minimal parse for now
                criticality_diagnostics = Some(CriticalityDiagnostics {
                    procedure_code: None,
                    triggering_message: None,
                    procedure_criticality: None,
                });
            }
            _ => {}
        }
    }

    Ok(NgSetupFailure {
        cause: cause.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "Cause",
            ie_id: ProtocolIeId::CAUSE.0,
        })?,
        time_to_wait,
        criticality_diagnostics,
    })
}

// ============================================================================
// B10.3: NAS Transport parsers
// ============================================================================

fn parse_initial_ue_message(container: ProtocolIeContainer) -> NgapResult<InitialUeMessage> {
    let mut ran_ue_ngap_id = None;
    let mut nas_pdu = None;
    let mut user_location_info = None;
    let mut rrc_establishment_cause = RrcEstablishmentCause::default();
    let mut ue_context_request = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            ProtocolIeId::NAS_PDU => {
                nas_pdu = Some(ie::decode_nas_pdu(field)?);
            }
            ProtocolIeId::USER_LOCATION_INFORMATION => {
                user_location_info = Some(ie::decode_user_location_info(field)?);
            }
            _ if field.id.0 == ie::IE_ID_RRC_ESTABLISHMENT_CAUSE => {
                rrc_establishment_cause = ie::decode_rrc_establishment_cause(field)?;
            }
            _ if field.id.0 == ie::IE_ID_UE_CONTEXT_REQUEST => {
                ue_context_request = Some(true);
            }
            _ => {}
        }
    }

    Ok(InitialUeMessage {
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
        nas_pdu: nas_pdu.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "NAS-PDU",
            ie_id: ProtocolIeId::NAS_PDU.0,
        })?,
        user_location_info: user_location_info.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "UserLocationInformation",
            ie_id: ProtocolIeId::USER_LOCATION_INFORMATION.0,
        })?,
        rrc_establishment_cause,
        ue_context_request,
    })
}

fn parse_downlink_nas_transport(
    container: ProtocolIeContainer,
) -> NgapResult<DownlinkNasTransport> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut nas_pdu = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            ProtocolIeId::NAS_PDU => {
                nas_pdu = Some(ie::decode_nas_pdu(field)?);
            }
            _ => {}
        }
    }

    Ok(DownlinkNasTransport {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
        nas_pdu: nas_pdu.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "NAS-PDU",
            ie_id: ProtocolIeId::NAS_PDU.0,
        })?,
    })
}

fn parse_uplink_nas_transport(
    container: ProtocolIeContainer,
) -> NgapResult<UplinkNasTransport> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut nas_pdu = None;
    let mut user_location_info = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            ProtocolIeId::NAS_PDU => {
                nas_pdu = Some(ie::decode_nas_pdu(field)?);
            }
            ProtocolIeId::USER_LOCATION_INFORMATION => {
                user_location_info = Some(ie::decode_user_location_info(field)?);
            }
            _ => {}
        }
    }

    Ok(UplinkNasTransport {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
        nas_pdu: nas_pdu.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "NAS-PDU",
            ie_id: ProtocolIeId::NAS_PDU.0,
        })?,
        user_location_info: user_location_info.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "UserLocationInformation",
            ie_id: ProtocolIeId::USER_LOCATION_INFORMATION.0,
        })?,
    })
}

// ============================================================================
// B10.4: Initial Context Setup parsers
// ============================================================================

fn parse_initial_context_setup_request(
    container: ProtocolIeContainer,
) -> NgapResult<InitialContextSetupRequest> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut guami = None;
    let allowed_nssai = Vec::new();
    let mut ue_security_capabilities = None;
    let mut security_key = None;
    let mut nas_pdu = None;
    let mut ue_ambr = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            ProtocolIeId::NAS_PDU => {
                nas_pdu = Some(ie::decode_nas_pdu(field)?);
            }
            _ if field.id.0 == ie::IE_ID_GUAMI => {
                guami = Some(ie::decode_guami_ie(field)?);
            }
            _ if field.id.0 == ie::IE_ID_UE_SECURITY_CAPABILITIES => {
                ue_security_capabilities = Some(ie::decode_ue_security_capabilities(field)?);
            }
            _ if field.id.0 == ie::IE_ID_SECURITY_KEY => {
                security_key = Some(ie::decode_security_key(field)?);
            }
            _ if field.id.0 == ie::IE_ID_UE_AGGREGATE_MAXIMUM_BIT_RATE => {
                ue_ambr = Some(ie::decode_ue_ambr(field)?);
            }
            _ => {}
        }
    }

    Ok(InitialContextSetupRequest {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
        guami: guami.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "GUAMI",
            ie_id: ie::IE_ID_GUAMI,
        })?,
        allowed_nssai,
        ue_security_capabilities: ue_security_capabilities.ok_or(
            NgapError::MissingMandatoryIe {
                ie_name: "UESecurityCapabilities",
                ie_id: ie::IE_ID_UE_SECURITY_CAPABILITIES,
            },
        )?,
        security_key: security_key.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "SecurityKey",
            ie_id: ie::IE_ID_SECURITY_KEY,
        })?,
        nas_pdu,
        ue_ambr,
    })
}

fn parse_initial_context_setup_response(
    container: ProtocolIeContainer,
) -> NgapResult<InitialContextSetupResponse> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            _ => {}
        }
    }

    Ok(InitialContextSetupResponse {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
    })
}

fn parse_initial_context_setup_failure(
    container: ProtocolIeContainer,
) -> NgapResult<InitialContextSetupFailure> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut cause = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            ProtocolIeId::CAUSE => {
                cause = Some(ie::decode_cause(field)?);
            }
            _ => {}
        }
    }

    Ok(InitialContextSetupFailure {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
        cause: cause.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "Cause",
            ie_id: ProtocolIeId::CAUSE.0,
        })?,
    })
}

// ============================================================================
// B10.5: PDU Session Resource parsers
// ============================================================================

fn parse_pdu_session_resource_setup_request(
    container: ProtocolIeContainer,
) -> NgapResult<PduSessionResourceSetupRequest> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut pdu_session_list = None;
    let mut nas_pdu = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            ProtocolIeId::NAS_PDU => {
                nas_pdu = Some(ie::decode_nas_pdu(field)?);
            }
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_SETUP_LIST_SU_REQ => {
                pdu_session_list = Some(ie::decode_pdu_session_setup_list_su_req(field)?);
            }
            _ => {}
        }
    }

    Ok(PduSessionResourceSetupRequest {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
        pdu_session_list: pdu_session_list.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "PDUSessionResourceSetupListSUReq",
            ie_id: ie::IE_ID_PDU_SESSION_RESOURCE_SETUP_LIST_SU_REQ,
        })?,
        nas_pdu,
    })
}

fn parse_pdu_session_resource_setup_response(
    container: ProtocolIeContainer,
) -> NgapResult<PduSessionResourceSetupResponse> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let setup_list = Vec::new();
    let failed_list = Vec::new();

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            _ => {}
        }
    }

    Ok(PduSessionResourceSetupResponse {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
        setup_list,
        failed_list,
    })
}

fn parse_pdu_session_resource_release_command(
    container: ProtocolIeContainer,
) -> NgapResult<PduSessionResourceReleaseCommand> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut nas_pdu = None;
    let pdu_session_list = Vec::new();

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            ProtocolIeId::NAS_PDU => {
                nas_pdu = Some(ie::decode_nas_pdu(field)?);
            }
            _ => {}
        }
    }

    Ok(PduSessionResourceReleaseCommand {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
        nas_pdu,
        pdu_session_list,
    })
}

fn parse_pdu_session_resource_release_response(
    container: ProtocolIeContainer,
) -> NgapResult<PduSessionResourceReleaseResponse> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let released_list = Vec::new();

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            _ => {}
        }
    }

    Ok(PduSessionResourceReleaseResponse {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
        released_list,
    })
}

// ============================================================================
// B10.6: UE Context Release parsers
// ============================================================================

fn parse_ue_context_release_command(
    container: ProtocolIeContainer,
) -> NgapResult<UeContextReleaseCommand> {
    let mut ue_ngap_ids = None;
    let mut cause = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::CAUSE => {
                cause = Some(ie::decode_cause(field)?);
            }
            _ if field.id.0 == ie::IE_ID_UE_NGAP_IDS => {
                ue_ngap_ids = Some(ie::decode_ue_ngap_ids(field)?);
            }
            _ => {}
        }
    }

    Ok(UeContextReleaseCommand {
        ue_ngap_ids: ue_ngap_ids.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "UE-NGAP-IDs",
            ie_id: ie::IE_ID_UE_NGAP_IDS,
        })?,
        cause: cause.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "Cause",
            ie_id: ProtocolIeId::CAUSE.0,
        })?,
    })
}

fn parse_ue_context_release_complete(
    container: ProtocolIeContainer,
) -> NgapResult<UeContextReleaseComplete> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            _ => {}
        }
    }

    Ok(UeContextReleaseComplete {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
    })
}

fn parse_ue_context_release_request(
    container: ProtocolIeContainer,
) -> NgapResult<UeContextReleaseRequest> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut cause = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            ProtocolIeId::CAUSE => {
                cause = Some(ie::decode_cause(field)?);
            }
            _ => {}
        }
    }

    Ok(UeContextReleaseRequest {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
        cause: cause.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "Cause",
            ie_id: ProtocolIeId::CAUSE.0,
        })?,
    })
}
