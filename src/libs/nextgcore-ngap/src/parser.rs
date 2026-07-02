//! NGAP Message Parsers
//!
//! Functions for decoding NGAP PDU messages from APER bytes into high-level types.
//! Each function decodes the PDU wrapper, extracts the IE container, and maps
//! the IEs to their strongly-typed representations.

use nextgcore_asn1c::ngap::ies::ProtocolIeContainer;
use nextgcore_asn1c::ngap::pdu::*;
use nextgcore_asn1c::ngap::types::ProtocolIeId;
use nextgcore_asn1c::per::{AperDecode, AperDecoder};

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
    PduSessionResourceModifyRequest(PduSessionResourceModifyRequest),
    PduSessionResourceModifyResponse(PduSessionResourceModifyResponse),
    PduSessionResourceReleaseCommand(PduSessionResourceReleaseCommand),
    PduSessionResourceReleaseResponse(PduSessionResourceReleaseResponse),
    PduSessionResourceNotify(PduSessionResourceNotify),
    PduSessionResourceModifyIndication(PduSessionResourceModifyIndication),
    PduSessionResourceModifyConfirm(PduSessionResourceModifyConfirm),
    UeContextReleaseCommand(UeContextReleaseCommand),
    UeContextReleaseComplete(UeContextReleaseComplete),
    UeContextReleaseRequest(UeContextReleaseRequest),
    NgReset(NgReset),
    NgResetAcknowledge(NgResetAcknowledge),
    ErrorIndication(ErrorIndication),
    RanConfigurationUpdate(RanConfigurationUpdate),
    RanConfigurationUpdateAcknowledge(RanConfigurationUpdateAcknowledge),
    RanConfigurationUpdateFailure(RanConfigurationUpdateFailure),
    AmfConfigurationUpdate(AmfConfigurationUpdate),
    AmfConfigurationUpdateAcknowledge(AmfConfigurationUpdateAcknowledge),
    AmfConfigurationUpdateFailure(AmfConfigurationUpdateFailure),
    AmfStatusIndication(AmfStatusIndication),
    NasNonDeliveryIndication(NasNonDeliveryIndication),
    HandoverRequired(HandoverRequired),
    HandoverRequest(HandoverRequest),
    HandoverRequestAcknowledge(HandoverRequestAcknowledge),
    HandoverFailure(HandoverFailure),
    HandoverCommand(HandoverCommand),
    HandoverPreparationFailure(HandoverPreparationFailure),
    HandoverNotify(HandoverNotify),
    HandoverCancel(HandoverCancel),
    HandoverCancelAcknowledge(HandoverCancelAcknowledge),
    OverloadStart(OverloadStart),
    OverloadStop(OverloadStop),
    PathSwitchRequest(PathSwitchRequest),
    PathSwitchRequestAcknowledge(PathSwitchRequestAcknowledge),
    PathSwitchRequestFailure(PathSwitchRequestFailure),
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
        InitiatingMessageValue::InitialUeMessage(ies) => Ok(NgapMessage::InitialUeMessage(
            parse_initial_ue_message(ies)?,
        )),
        InitiatingMessageValue::DownlinkNasTransport(ies) => Ok(NgapMessage::DownlinkNasTransport(
            parse_downlink_nas_transport(ies)?,
        )),
        InitiatingMessageValue::UplinkNasTransport(ies) => Ok(NgapMessage::UplinkNasTransport(
            parse_uplink_nas_transport(ies)?,
        )),
        InitiatingMessageValue::InitialContextSetupRequest(ies) => Ok(
            NgapMessage::InitialContextSetupRequest(parse_initial_context_setup_request(ies)?),
        ),
        InitiatingMessageValue::UeContextReleaseCommand(ies) => Ok(
            NgapMessage::UeContextReleaseCommand(parse_ue_context_release_command(ies)?),
        ),
        InitiatingMessageValue::UeContextReleaseRequest(ies) => Ok(
            NgapMessage::UeContextReleaseRequest(parse_ue_context_release_request(ies)?),
        ),
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
        InitiatingMessageValue::NgReset(ies) => Ok(NgapMessage::NgReset(parse_ng_reset(ies)?)),
        InitiatingMessageValue::ErrorIndication(ies) => {
            Ok(NgapMessage::ErrorIndication(parse_error_indication(ies)?))
        }
        InitiatingMessageValue::HandoverRequired(ies) => {
            Ok(NgapMessage::HandoverRequired(parse_handover_required(ies)?))
        }
        InitiatingMessageValue::PathSwitchRequest(ies) => Ok(NgapMessage::PathSwitchRequest(
            parse_path_switch_request(ies)?,
        )),
        // Procedures the low-level decoder maps to the generic container
        InitiatingMessageValue::Other(ies) => {
            use nextgcore_asn1c::ngap::types::ProcedureCode;
            match msg.procedure_code {
                ProcedureCode::NG_RESET => Ok(NgapMessage::NgReset(parse_ng_reset(ies)?)),
                ProcedureCode::ERROR_INDICATION => {
                    Ok(NgapMessage::ErrorIndication(parse_error_indication(ies)?))
                }
                ProcedureCode::RAN_CONFIGURATION_UPDATE => Ok(NgapMessage::RanConfigurationUpdate(
                    parse_ran_configuration_update(ies)?,
                )),
                ProcedureCode::AMF_CONFIGURATION_UPDATE => Ok(NgapMessage::AmfConfigurationUpdate(
                    parse_amf_configuration_update(ies)?,
                )),
                ProcedureCode::AMF_STATUS_INDICATION => Ok(NgapMessage::AmfStatusIndication(
                    parse_amf_status_indication(ies)?,
                )),
                ProcedureCode::PDU_SESSION_RESOURCE_NOTIFY => Ok(
                    NgapMessage::PduSessionResourceNotify(parse_pdu_session_resource_notify(ies)?),
                ),
                ProcedureCode::PDU_SESSION_RESOURCE_MODIFY => {
                    Ok(NgapMessage::PduSessionResourceModifyRequest(
                        parse_pdu_session_resource_modify_request(ies)?,
                    ))
                }
                ProcedureCode::PDU_SESSION_RESOURCE_MODIFY_INDICATION => {
                    Ok(NgapMessage::PduSessionResourceModifyIndication(
                        parse_pdu_session_resource_modify_indication(ies)?,
                    ))
                }
                ProcedureCode::NAS_NON_DELIVERY_INDICATION => Ok(
                    NgapMessage::NasNonDeliveryIndication(parse_nas_non_delivery_indication(ies)?),
                ),
                ProcedureCode::HANDOVER_PREPARATION => {
                    Ok(NgapMessage::HandoverRequired(parse_handover_required(ies)?))
                }
                ProcedureCode::HANDOVER_RESOURCE_ALLOCATION => {
                    Ok(NgapMessage::HandoverRequest(parse_handover_request(ies)?))
                }
                ProcedureCode::HANDOVER_NOTIFICATION => {
                    Ok(NgapMessage::HandoverNotify(parse_handover_notify(ies)?))
                }
                ProcedureCode::HANDOVER_CANCEL => {
                    Ok(NgapMessage::HandoverCancel(parse_handover_cancel(ies)?))
                }
                ProcedureCode::OVERLOAD_START => {
                    Ok(NgapMessage::OverloadStart(parse_overload_start(ies)?))
                }
                ProcedureCode::OVERLOAD_STOP => Ok(NgapMessage::OverloadStop(OverloadStop {})),
                ProcedureCode::PATH_SWITCH_REQUEST => Ok(NgapMessage::PathSwitchRequest(
                    parse_path_switch_request(ies)?,
                )),
                _ => Ok(NgapMessage::Unknown {
                    procedure_code: msg.procedure_code.0,
                    message_type: "InitiatingMessage",
                }),
            }
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
        SuccessfulOutcomeValue::InitialContextSetupResponse(ies) => Ok(
            NgapMessage::InitialContextSetupResponse(parse_initial_context_setup_response(ies)?),
        ),
        SuccessfulOutcomeValue::UeContextReleaseComplete(ies) => Ok(
            NgapMessage::UeContextReleaseComplete(parse_ue_context_release_complete(ies)?),
        ),
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
        SuccessfulOutcomeValue::NgResetAcknowledge(ies) => Ok(NgapMessage::NgResetAcknowledge(
            parse_ng_reset_acknowledge(ies)?,
        )),
        SuccessfulOutcomeValue::PathSwitchRequestAcknowledge(ies) => Ok(
            NgapMessage::PathSwitchRequestAcknowledge(parse_path_switch_request_acknowledge(ies)?),
        ),
        // Handle messages that the low-level decoder maps to Other
        SuccessfulOutcomeValue::Other(ies) => {
            use nextgcore_asn1c::ngap::types::ProcedureCode;
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
                ProcedureCode::PDU_SESSION_RESOURCE_MODIFY => {
                    Ok(NgapMessage::PduSessionResourceModifyResponse(
                        parse_pdu_session_resource_modify_response(ies)?,
                    ))
                }
                ProcedureCode::PDU_SESSION_RESOURCE_MODIFY_INDICATION => {
                    Ok(NgapMessage::PduSessionResourceModifyConfirm(
                        parse_pdu_session_resource_modify_confirm(ies)?,
                    ))
                }
                ProcedureCode::NG_RESET => Ok(NgapMessage::NgResetAcknowledge(
                    parse_ng_reset_acknowledge(ies)?,
                )),
                ProcedureCode::RAN_CONFIGURATION_UPDATE => {
                    Ok(NgapMessage::RanConfigurationUpdateAcknowledge(
                        parse_ran_configuration_update_acknowledge(ies)?,
                    ))
                }
                ProcedureCode::AMF_CONFIGURATION_UPDATE => {
                    Ok(NgapMessage::AmfConfigurationUpdateAcknowledge(
                        parse_amf_configuration_update_acknowledge(ies)?,
                    ))
                }
                ProcedureCode::PATH_SWITCH_REQUEST => {
                    Ok(NgapMessage::PathSwitchRequestAcknowledge(
                        parse_path_switch_request_acknowledge(ies)?,
                    ))
                }
                ProcedureCode::HANDOVER_PREPARATION => {
                    Ok(NgapMessage::HandoverCommand(parse_handover_command(ies)?))
                }
                ProcedureCode::HANDOVER_RESOURCE_ALLOCATION => {
                    Ok(NgapMessage::HandoverRequestAcknowledge(
                        parse_handover_request_acknowledge(ies)?,
                    ))
                }
                ProcedureCode::HANDOVER_CANCEL => Ok(NgapMessage::HandoverCancelAcknowledge(
                    parse_handover_cancel_acknowledge(ies)?,
                )),
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
        UnsuccessfulOutcomeValue::InitialContextSetupFailure(ies) => Ok(
            NgapMessage::InitialContextSetupFailure(parse_initial_context_setup_failure(ies)?),
        ),
        UnsuccessfulOutcomeValue::HandoverPreparationFailure(ies) => Ok(
            NgapMessage::HandoverPreparationFailure(parse_handover_preparation_failure(ies)?),
        ),
        UnsuccessfulOutcomeValue::PathSwitchRequestFailure(ies) => Ok(
            NgapMessage::PathSwitchRequestFailure(parse_path_switch_request_failure(ies)?),
        ),
        UnsuccessfulOutcomeValue::Other(ies) => {
            use nextgcore_asn1c::ngap::types::ProcedureCode;
            match msg.procedure_code {
                ProcedureCode::RAN_CONFIGURATION_UPDATE => {
                    Ok(NgapMessage::RanConfigurationUpdateFailure(
                        parse_ran_configuration_update_failure(ies)?,
                    ))
                }
                ProcedureCode::AMF_CONFIGURATION_UPDATE => {
                    Ok(NgapMessage::AmfConfigurationUpdateFailure(
                        parse_amf_configuration_update_failure(ies)?,
                    ))
                }
                ProcedureCode::HANDOVER_PREPARATION => Ok(NgapMessage::HandoverPreparationFailure(
                    parse_handover_preparation_failure(ies)?,
                )),
                ProcedureCode::HANDOVER_RESOURCE_ALLOCATION => {
                    Ok(NgapMessage::HandoverFailure(parse_handover_failure(ies)?))
                }
                ProcedureCode::PATH_SWITCH_REQUEST => Ok(NgapMessage::PathSwitchRequestFailure(
                    parse_path_switch_request_failure(ies)?,
                )),
                _ => Ok(NgapMessage::Unknown {
                    procedure_code: msg.procedure_code.0,
                    message_type: "UnsuccessfulOutcome",
                }),
            }
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
            _ => ie::handle_unknown_ie(field)?,
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
                served_guami_list = Some(ie::decode_served_guami_list(field)?);
            }
            86 => {
                // RelativeAMFCapacity
                relative_amf_capacity = Some(ie::decode_relative_amf_capacity(field)?);
            }
            ie::IE_ID_PLMN_SUPPORT_LIST => {
                plmn_support_list = Some(ie::decode_plmn_support_list(field)?);
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(NgSetupResponse {
        amf_name: amf_name.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMFName",
            ie_id: ie::IE_ID_AMF_NAME,
        })?,
        served_guami_list: served_guami_list.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "ServedGUAMIList",
            ie_id: ie::IE_ID_SERVED_GUAMI_LIST,
        })?,
        relative_amf_capacity: relative_amf_capacity.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RelativeAMFCapacity",
            ie_id: 86,
        })?,
        plmn_support_list: plmn_support_list.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "PLMNSupportList",
            ie_id: ie::IE_ID_PLMN_SUPPORT_LIST,
        })?,
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
                criticality_diagnostics = Some(ie::decode_criticality_diagnostics(field)?);
            }
            _ => ie::handle_unknown_ie(field)?,
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
            _ => ie::handle_unknown_ie(field)?,
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
            _ => ie::handle_unknown_ie(field)?,
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

fn parse_uplink_nas_transport(container: ProtocolIeContainer) -> NgapResult<UplinkNasTransport> {
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
            _ => ie::handle_unknown_ie(field)?,
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
    let mut allowed_nssai = None;
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
            _ if field.id.0 == ie::IE_ID_ALLOWED_NSSAI => {
                allowed_nssai = Some(ie::decode_allowed_nssai(field)?);
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
            _ => ie::handle_unknown_ie(field)?,
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
        allowed_nssai: allowed_nssai.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AllowedNSSAI",
            ie_id: ie::IE_ID_ALLOWED_NSSAI,
        })?,
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
            _ => ie::handle_unknown_ie(field)?,
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
            _ => ie::handle_unknown_ie(field)?,
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
            _ => ie::handle_unknown_ie(field)?,
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
    let mut setup_list = Vec::new();
    let mut failed_list = Vec::new();

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_SETUP_LIST_SU_RES => {
                setup_list = ie::decode_pdu_session_setup_list_su_res(field)?;
            }
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_SU_RES => {
                failed_list = ie::decode_pdu_session_failed_list(field)?;
            }
            _ => ie::handle_unknown_ie(field)?,
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
    let mut pdu_session_list = Vec::new();

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
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_TO_RELEASE_LIST_REL_CMD => {
                pdu_session_list = ie::decode_pdu_session_release_list(field)?;
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    if pdu_session_list.is_empty() {
        return Err(NgapError::MissingMandatoryIe {
            ie_name: "PDUSessionResourceToReleaseListRelCmd",
            ie_id: ie::IE_ID_PDU_SESSION_RESOURCE_TO_RELEASE_LIST_REL_CMD,
        });
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
    let mut released_list = Vec::new();

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_RELEASED_LIST_REL_RES => {
                released_list = ie::decode_pdu_session_released_list(field)?;
            }
            _ => ie::handle_unknown_ie(field)?,
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
            _ => ie::handle_unknown_ie(field)?,
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
            _ => ie::handle_unknown_ie(field)?,
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
            _ => ie::handle_unknown_ie(field)?,
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

// ============================================================================
// PDU Session Resource Modify parsers
// ============================================================================

fn parse_pdu_session_resource_modify_request(
    container: ProtocolIeContainer,
) -> NgapResult<PduSessionResourceModifyRequest> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut pdu_session_list = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_REQ => {
                pdu_session_list = Some(ie::decode_pdu_session_modify_list_req(field)?);
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(PduSessionResourceModifyRequest {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
        pdu_session_list: pdu_session_list.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "PDUSessionResourceModifyListModReq",
            ie_id: ie::IE_ID_PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_REQ,
        })?,
    })
}

fn parse_pdu_session_resource_modify_response(
    container: ProtocolIeContainer,
) -> NgapResult<PduSessionResourceModifyResponse> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut modify_list = Vec::new();
    let mut failed_list = Vec::new();

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_RES => {
                modify_list = ie::decode_pdu_session_modify_list_res(field)?;
            }
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_FAILED_TO_MODIFY_LIST_MOD_RES => {
                failed_list = ie::decode_pdu_session_failed_list(field)?;
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(PduSessionResourceModifyResponse {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
        modify_list,
        failed_list,
    })
}

fn parse_pdu_session_resource_notify(
    container: ProtocolIeContainer,
) -> NgapResult<PduSessionResourceNotify> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut notify_list = Vec::new();
    let mut released_list = Vec::new();

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_NOTIFY_LIST => {
                notify_list = ie::decode_pdu_session_notify_list(field)?;
            }
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_RELEASED_LIST_NOT => {
                released_list = ie::decode_pdu_session_released_list(field)?;
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    if notify_list.is_empty() && released_list.is_empty() {
        return Err(NgapError::MissingMandatoryIe {
            ie_name: "PDUSessionResourceNotifyList",
            ie_id: ie::IE_ID_PDU_SESSION_RESOURCE_NOTIFY_LIST,
        });
    }

    Ok(PduSessionResourceNotify {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
        notify_list,
        released_list,
    })
}

fn parse_pdu_session_resource_modify_indication(
    container: ProtocolIeContainer,
) -> NgapResult<PduSessionResourceModifyIndication> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut modify_list = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_IND => {
                modify_list = Some(ie::decode_pdu_session_modify_list_mod_ind(field)?);
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(PduSessionResourceModifyIndication {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
        modify_list: modify_list.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "PDUSessionResourceModifyListModInd",
            ie_id: ie::IE_ID_PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_IND,
        })?,
    })
}

fn parse_pdu_session_resource_modify_confirm(
    container: ProtocolIeContainer,
) -> NgapResult<PduSessionResourceModifyConfirm> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut confirm_list = Vec::new();
    let mut failed_list = Vec::new();

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_CFM => {
                confirm_list = ie::decode_pdu_session_modify_list_mod_cfm(field)?;
            }
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_FAILED_TO_MODIFY_LIST_MOD_CFM => {
                failed_list = ie::decode_pdu_session_failed_list(field)?;
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(PduSessionResourceModifyConfirm {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
        confirm_list,
        failed_list,
    })
}

// ============================================================================
// NG Reset parsers
// ============================================================================

fn parse_ng_reset(container: ProtocolIeContainer) -> NgapResult<NgReset> {
    let mut cause = None;
    let mut reset_type = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::CAUSE => {
                cause = Some(ie::decode_cause(field)?);
            }
            _ if field.id.0 == ie::IE_ID_RESET_TYPE => {
                reset_type = Some(ie::decode_reset_type(field)?);
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(NgReset {
        cause: cause.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "Cause",
            ie_id: ProtocolIeId::CAUSE.0,
        })?,
        reset_type: reset_type.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "ResetType",
            ie_id: ie::IE_ID_RESET_TYPE,
        })?,
    })
}

fn parse_ng_reset_acknowledge(container: ProtocolIeContainer) -> NgapResult<NgResetAcknowledge> {
    let mut connections = None;
    let mut criticality_diagnostics = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::CRITICALITY_DIAGNOSTICS => {
                criticality_diagnostics = Some(ie::decode_criticality_diagnostics(field)?);
            }
            _ if field.id.0 == ie::IE_ID_UE_ASSOCIATED_LOGICAL_NG_CONNECTION_LIST => {
                connections = Some(ie::decode_ng_connection_list(field)?);
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(NgResetAcknowledge {
        connections,
        criticality_diagnostics,
    })
}

// ============================================================================
// Error Indication parser
// ============================================================================

fn parse_error_indication(container: ProtocolIeContainer) -> NgapResult<ErrorIndication> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut cause = None;
    let mut criticality_diagnostics = None;

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
            ProtocolIeId::CRITICALITY_DIAGNOSTICS => {
                criticality_diagnostics = Some(ie::decode_criticality_diagnostics(field)?);
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(ErrorIndication {
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        cause,
        criticality_diagnostics,
    })
}

// ============================================================================
// RAN/AMF Configuration Update parsers
// ============================================================================

fn parse_ran_configuration_update(
    container: ProtocolIeContainer,
) -> NgapResult<RanConfigurationUpdate> {
    let mut ran_node_name = None;
    let mut supported_ta_list = None;
    let mut default_paging_drx = None;
    let mut global_ran_node_id = None;

    for field in &container.ies {
        match field.id.0 {
            ie::IE_ID_RAN_NODE_NAME => {
                ran_node_name = Some(ie::decode_ran_node_name(field)?);
            }
            ie::IE_ID_SUPPORTED_TA_LIST => {
                supported_ta_list = Some(ie::decode_supported_ta_list(field)?);
            }
            ie::IE_ID_DEFAULT_PAGING_DRX => {
                default_paging_drx = Some(ie::decode_default_paging_drx(field)?);
            }
            ie::IE_ID_GLOBAL_RAN_NODE_ID => {
                global_ran_node_id = Some(ie::decode_global_ran_node_id(field)?);
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(RanConfigurationUpdate {
        ran_node_name,
        supported_ta_list,
        default_paging_drx,
        global_ran_node_id,
    })
}

fn parse_ran_configuration_update_acknowledge(
    container: ProtocolIeContainer,
) -> NgapResult<RanConfigurationUpdateAcknowledge> {
    let mut criticality_diagnostics = None;

    for field in &container.ies {
        if field.id == ProtocolIeId::CRITICALITY_DIAGNOSTICS {
            criticality_diagnostics = Some(ie::decode_criticality_diagnostics(field)?);
        }
    }

    Ok(RanConfigurationUpdateAcknowledge {
        criticality_diagnostics,
    })
}

fn parse_ran_configuration_update_failure(
    container: ProtocolIeContainer,
) -> NgapResult<RanConfigurationUpdateFailure> {
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
                criticality_diagnostics = Some(ie::decode_criticality_diagnostics(field)?);
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(RanConfigurationUpdateFailure {
        cause: cause.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "Cause",
            ie_id: ProtocolIeId::CAUSE.0,
        })?,
        time_to_wait,
        criticality_diagnostics,
    })
}

fn parse_amf_configuration_update(
    container: ProtocolIeContainer,
) -> NgapResult<AmfConfigurationUpdate> {
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
                served_guami_list = Some(ie::decode_served_guami_list(field)?);
            }
            86 => {
                relative_amf_capacity = Some(ie::decode_relative_amf_capacity(field)?);
            }
            ie::IE_ID_PLMN_SUPPORT_LIST => {
                plmn_support_list = Some(ie::decode_plmn_support_list(field)?);
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(AmfConfigurationUpdate {
        amf_name,
        served_guami_list,
        relative_amf_capacity,
        plmn_support_list,
    })
}

fn parse_amf_configuration_update_acknowledge(
    container: ProtocolIeContainer,
) -> NgapResult<AmfConfigurationUpdateAcknowledge> {
    let mut criticality_diagnostics = None;

    for field in &container.ies {
        if field.id == ProtocolIeId::CRITICALITY_DIAGNOSTICS {
            criticality_diagnostics = Some(ie::decode_criticality_diagnostics(field)?);
        }
    }

    Ok(AmfConfigurationUpdateAcknowledge {
        criticality_diagnostics,
    })
}

fn parse_amf_configuration_update_failure(
    container: ProtocolIeContainer,
) -> NgapResult<AmfConfigurationUpdateFailure> {
    let failure = parse_ran_configuration_update_failure(container)?;
    Ok(AmfConfigurationUpdateFailure {
        cause: failure.cause,
        time_to_wait: failure.time_to_wait,
        criticality_diagnostics: failure.criticality_diagnostics,
    })
}

// ============================================================================
// AMF Status Indication parser
// ============================================================================

fn parse_amf_status_indication(container: ProtocolIeContainer) -> NgapResult<AmfStatusIndication> {
    let mut unavailable_guami_list = None;

    for field in &container.ies {
        if field.id.0 == ie::IE_ID_UNAVAILABLE_GUAMI_LIST {
            unavailable_guami_list = Some(ie::decode_unavailable_guami_list(field)?);
        }
    }

    Ok(AmfStatusIndication {
        unavailable_guami_list: unavailable_guami_list.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "UnavailableGUAMIList",
            ie_id: ie::IE_ID_UNAVAILABLE_GUAMI_LIST,
        })?,
    })
}

// ============================================================================
// NAS Non Delivery Indication parser
// ============================================================================

fn parse_nas_non_delivery_indication(
    container: ProtocolIeContainer,
) -> NgapResult<NasNonDeliveryIndication> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut nas_pdu = None;
    let mut cause = None;

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
            ProtocolIeId::CAUSE => {
                cause = Some(ie::decode_cause(field)?);
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(NasNonDeliveryIndication {
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
        cause: cause.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "Cause",
            ie_id: ProtocolIeId::CAUSE.0,
        })?,
    })
}

// ============================================================================
// Handover / Path Switch parsers
// ============================================================================

fn parse_handover_required(container: ProtocolIeContainer) -> NgapResult<HandoverRequired> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut handover_type = None;
    let mut cause = None;
    let mut target_id = None;
    let mut pdu_session_list = None;
    let mut source_to_target_container = None;

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
            _ if field.id.0 == ie::IE_ID_HANDOVER_TYPE => {
                handover_type = Some(ie::decode_handover_type(field)?);
            }
            _ if field.id.0 == ie::IE_ID_TARGET_ID => {
                target_id = Some(ie::decode_target_id(field)?);
            }
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_LIST_HO_RQD => {
                pdu_session_list = Some(ie::decode_pdu_session_ho_required_list(field)?);
            }
            _ if field.id.0 == ie::IE_ID_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER => {
                source_to_target_container = Some(ie::decode_raw_octet_ie(field)?);
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(HandoverRequired {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
        handover_type: handover_type.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "HandoverType",
            ie_id: ie::IE_ID_HANDOVER_TYPE,
        })?,
        cause: cause.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "Cause",
            ie_id: ProtocolIeId::CAUSE.0,
        })?,
        target_id: target_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "TargetID",
            ie_id: ie::IE_ID_TARGET_ID,
        })?,
        pdu_session_list: pdu_session_list.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "PDUSessionResourceListHORqd",
            ie_id: ie::IE_ID_PDU_SESSION_RESOURCE_LIST_HO_RQD,
        })?,
        source_to_target_container: source_to_target_container.ok_or(
            NgapError::MissingMandatoryIe {
                ie_name: "SourceToTarget-TransparentContainer",
                ie_id: ie::IE_ID_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER,
            },
        )?,
    })
}

fn parse_handover_preparation_failure(
    container: ProtocolIeContainer,
) -> NgapResult<HandoverPreparationFailure> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut cause = None;
    let mut criticality_diagnostics = None;

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
            ProtocolIeId::CRITICALITY_DIAGNOSTICS => {
                criticality_diagnostics = Some(ie::decode_criticality_diagnostics(field)?);
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(HandoverPreparationFailure {
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
        criticality_diagnostics,
    })
}

fn parse_path_switch_request(container: ProtocolIeContainer) -> NgapResult<PathSwitchRequest> {
    let mut ran_ue_ngap_id = None;
    let mut source_amf_ue_ngap_id = None;
    let mut user_location_info = None;
    let mut ue_security_capabilities = None;
    let mut pdu_session_list = None;
    let mut failed_list = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            ProtocolIeId::USER_LOCATION_INFORMATION => {
                user_location_info = Some(ie::decode_user_location_info(field)?);
            }
            _ if field.id.0 == ie::IE_ID_SOURCE_AMF_UE_NGAP_ID => {
                source_amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            _ if field.id.0 == ie::IE_ID_UE_SECURITY_CAPABILITIES => {
                ue_security_capabilities = Some(ie::decode_ue_security_capabilities(field)?);
            }
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_TO_BE_SWITCHED_DL_LIST => {
                pdu_session_list = Some(ie::decode_pdu_session_to_be_switched_list(field)?);
            }
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_PS_REQ => {
                failed_list = Some(ie::decode_pdu_session_failed_list(field)?);
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(PathSwitchRequest {
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
        source_amf_ue_ngap_id: source_amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "SourceAMF-UE-NGAP-ID",
            ie_id: ie::IE_ID_SOURCE_AMF_UE_NGAP_ID,
        })?,
        user_location_info: user_location_info.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "UserLocationInformation",
            ie_id: ProtocolIeId::USER_LOCATION_INFORMATION.0,
        })?,
        ue_security_capabilities: ue_security_capabilities.ok_or(
            NgapError::MissingMandatoryIe {
                ie_name: "UESecurityCapabilities",
                ie_id: ie::IE_ID_UE_SECURITY_CAPABILITIES,
            },
        )?,
        pdu_session_list: pdu_session_list.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "PDUSessionResourceToBeSwitchedDLList",
            ie_id: ie::IE_ID_PDU_SESSION_RESOURCE_TO_BE_SWITCHED_DL_LIST,
        })?,
        failed_list,
    })
}

fn parse_path_switch_request_acknowledge(
    container: ProtocolIeContainer,
) -> NgapResult<PathSwitchRequestAcknowledge> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut ue_security_capabilities = None;
    let mut security_context = None;
    let mut switched_list = None;
    let mut released_list = None;
    let mut allowed_nssai = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            _ if field.id.0 == ie::IE_ID_UE_SECURITY_CAPABILITIES => {
                ue_security_capabilities = Some(ie::decode_ue_security_capabilities(field)?);
            }
            _ if field.id.0 == ie::IE_ID_SECURITY_CONTEXT => {
                security_context = Some(ie::decode_security_context(field)?);
            }
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_SWITCHED_LIST => {
                switched_list = Some(ie::decode_pdu_session_switched_list(field)?);
            }
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_RELEASED_LIST_PS_ACK => {
                released_list = Some(ie::decode_pdu_session_released_list(field)?);
            }
            _ if field.id.0 == ie::IE_ID_ALLOWED_NSSAI => {
                allowed_nssai = Some(ie::decode_allowed_nssai(field)?);
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(PathSwitchRequestAcknowledge {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
        ue_security_capabilities,
        security_context: security_context.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "SecurityContext",
            ie_id: ie::IE_ID_SECURITY_CONTEXT,
        })?,
        switched_list: switched_list.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "PDUSessionResourceSwitchedList",
            ie_id: ie::IE_ID_PDU_SESSION_RESOURCE_SWITCHED_LIST,
        })?,
        released_list,
        allowed_nssai: allowed_nssai.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AllowedNSSAI",
            ie_id: ie::IE_ID_ALLOWED_NSSAI,
        })?,
    })
}

fn parse_path_switch_request_failure(
    container: ProtocolIeContainer,
) -> NgapResult<PathSwitchRequestFailure> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut cause = None;
    let mut released_list = None;
    let mut criticality_diagnostics = None;

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
            ProtocolIeId::CRITICALITY_DIAGNOSTICS => {
                criticality_diagnostics = Some(ie::decode_criticality_diagnostics(field)?);
            }
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_RELEASED_LIST_PS_FAIL => {
                released_list = Some(ie::decode_pdu_session_released_list(field)?);
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(PathSwitchRequestFailure {
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
        released_list,
        criticality_diagnostics,
    })
}

// ============================================================================
// N2 Handover resource-allocation / notification / cancel parsers
// (TS 38.413 Section 9.2.3)
// ============================================================================

/// Parse a HandoverRequest (HANDOVER_RESOURCE_ALLOCATION, InitiatingMessage).
fn parse_handover_request(container: ProtocolIeContainer) -> NgapResult<HandoverRequest> {
    let mut amf_ue_ngap_id = None;
    let mut handover_type = None;
    let mut cause = None;
    let mut ue_ambr = None;
    let mut ue_security_capabilities = None;
    let mut security_context = None;
    let mut pdu_session_list = None;
    let mut allowed_nssai = None;
    let mut source_to_target_container = None;
    let mut guami = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::CAUSE => {
                cause = Some(ie::decode_cause(field)?);
            }
            _ if field.id.0 == ie::IE_ID_HANDOVER_TYPE => {
                handover_type = Some(ie::decode_handover_type(field)?);
            }
            _ if field.id.0 == ie::IE_ID_UE_AGGREGATE_MAXIMUM_BIT_RATE => {
                ue_ambr = Some(ie::decode_ue_ambr(field)?);
            }
            _ if field.id.0 == ie::IE_ID_UE_SECURITY_CAPABILITIES => {
                ue_security_capabilities = Some(ie::decode_ue_security_capabilities(field)?);
            }
            _ if field.id.0 == ie::IE_ID_SECURITY_CONTEXT => {
                security_context = Some(ie::decode_security_context(field)?);
            }
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_SETUP_LIST_HO_REQ => {
                pdu_session_list = Some(ie::decode_pdu_session_ho_request_list(field)?);
            }
            _ if field.id.0 == ie::IE_ID_ALLOWED_NSSAI => {
                allowed_nssai = Some(ie::decode_allowed_nssai(field)?);
            }
            _ if field.id.0 == ie::IE_ID_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER => {
                source_to_target_container = Some(ie::decode_raw_octet_ie(field)?);
            }
            _ if field.id.0 == ie::IE_ID_GUAMI => {
                guami = Some(ie::decode_guami_ie(field)?);
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(HandoverRequest {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        handover_type: handover_type.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "HandoverType",
            ie_id: ie::IE_ID_HANDOVER_TYPE,
        })?,
        cause: cause.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "Cause",
            ie_id: ProtocolIeId::CAUSE.0,
        })?,
        ue_ambr: ue_ambr.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "UEAggregateMaximumBitRate",
            ie_id: ie::IE_ID_UE_AGGREGATE_MAXIMUM_BIT_RATE,
        })?,
        ue_security_capabilities: ue_security_capabilities.ok_or(
            NgapError::MissingMandatoryIe {
                ie_name: "UESecurityCapabilities",
                ie_id: ie::IE_ID_UE_SECURITY_CAPABILITIES,
            },
        )?,
        security_context: security_context.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "SecurityContext",
            ie_id: ie::IE_ID_SECURITY_CONTEXT,
        })?,
        pdu_session_list: pdu_session_list.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "PDUSessionResourceSetupListHOReq",
            ie_id: ie::IE_ID_PDU_SESSION_RESOURCE_SETUP_LIST_HO_REQ,
        })?,
        allowed_nssai: allowed_nssai.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AllowedNSSAI",
            ie_id: ie::IE_ID_ALLOWED_NSSAI,
        })?,
        source_to_target_container: source_to_target_container.ok_or(
            NgapError::MissingMandatoryIe {
                ie_name: "SourceToTarget-TransparentContainer",
                ie_id: ie::IE_ID_SOURCE_TO_TARGET_TRANSPARENT_CONTAINER,
            },
        )?,
        guami: guami.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "GUAMI",
            ie_id: ie::IE_ID_GUAMI,
        })?,
    })
}

/// Parse a HandoverRequestAcknowledge (HANDOVER_RESOURCE_ALLOCATION, SuccessfulOutcome).
fn parse_handover_request_acknowledge(
    container: ProtocolIeContainer,
) -> NgapResult<HandoverRequestAcknowledge> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut admitted_list = None;
    let mut failed_list = None;
    let mut target_to_source_container = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_ADMITTED_LIST => {
                admitted_list = Some(ie::decode_pdu_session_admitted_list(field)?);
            }
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_HO_ACK => {
                failed_list = Some(ie::decode_pdu_session_failed_list(field)?);
            }
            _ if field.id.0 == ie::IE_ID_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER => {
                target_to_source_container = Some(ie::decode_raw_octet_ie(field)?);
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(HandoverRequestAcknowledge {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
        admitted_list: admitted_list.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "PDUSessionResourceAdmittedList",
            ie_id: ie::IE_ID_PDU_SESSION_RESOURCE_ADMITTED_LIST,
        })?,
        failed_list,
        target_to_source_container: target_to_source_container.ok_or(
            NgapError::MissingMandatoryIe {
                ie_name: "TargetToSource-TransparentContainer",
                ie_id: ie::IE_ID_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER,
            },
        )?,
    })
}

/// Parse a HandoverFailure (HANDOVER_RESOURCE_ALLOCATION, UnsuccessfulOutcome).
fn parse_handover_failure(container: ProtocolIeContainer) -> NgapResult<HandoverFailure> {
    let mut amf_ue_ngap_id = None;
    let mut cause = None;
    let mut criticality_diagnostics = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::CAUSE => {
                cause = Some(ie::decode_cause(field)?);
            }
            ProtocolIeId::CRITICALITY_DIAGNOSTICS => {
                criticality_diagnostics = Some(ie::decode_criticality_diagnostics(field)?);
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(HandoverFailure {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        cause: cause.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "Cause",
            ie_id: ProtocolIeId::CAUSE.0,
        })?,
        criticality_diagnostics,
    })
}

/// Parse a HandoverCommand (HANDOVER_PREPARATION, SuccessfulOutcome).
fn parse_handover_command(container: ProtocolIeContainer) -> NgapResult<HandoverCommand> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut handover_type = None;
    let mut nas_pdu = None;
    let mut pdu_session_list = None;
    let mut release_list = None;
    let mut target_to_source_container = None;

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
            _ if field.id.0 == ie::IE_ID_HANDOVER_TYPE => {
                handover_type = Some(ie::decode_handover_type(field)?);
            }
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_HANDOVER_LIST => {
                pdu_session_list = Some(
                    ie::decode_id_transfer_list(field)?
                        .into_iter()
                        .map(
                            |(pdu_session_id, transfer)| PduSessionResourceHandoverItem {
                                pdu_session_id,
                                transfer,
                            },
                        )
                        .collect(),
                );
            }
            _ if field.id.0 == ie::IE_ID_PDU_SESSION_RESOURCE_TO_RELEASE_LIST_REL_CMD => {
                release_list = Some(ie::decode_pdu_session_release_list(field)?);
            }
            _ if field.id.0 == ie::IE_ID_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER => {
                target_to_source_container = Some(ie::decode_raw_octet_ie(field)?);
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(HandoverCommand {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
        handover_type: handover_type.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "HandoverType",
            ie_id: ie::IE_ID_HANDOVER_TYPE,
        })?,
        nas_pdu,
        pdu_session_list: pdu_session_list.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "PDUSessionResourceHandoverList",
            ie_id: ie::IE_ID_PDU_SESSION_RESOURCE_HANDOVER_LIST,
        })?,
        release_list,
        target_to_source_container: target_to_source_container.ok_or(
            NgapError::MissingMandatoryIe {
                ie_name: "TargetToSource-TransparentContainer",
                ie_id: ie::IE_ID_TARGET_TO_SOURCE_TRANSPARENT_CONTAINER,
            },
        )?,
    })
}

/// Parse a HandoverNotify (HANDOVER_NOTIFICATION, InitiatingMessage).
fn parse_handover_notify(container: ProtocolIeContainer) -> NgapResult<HandoverNotify> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut user_location_info = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            ProtocolIeId::USER_LOCATION_INFORMATION => {
                user_location_info = Some(ie::decode_user_location_info(field)?);
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(HandoverNotify {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
        user_location_info: user_location_info.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "UserLocationInformation",
            ie_id: ProtocolIeId::USER_LOCATION_INFORMATION.0,
        })?,
    })
}

/// Parse a HandoverCancel (HANDOVER_CANCEL, InitiatingMessage).
fn parse_handover_cancel(container: ProtocolIeContainer) -> NgapResult<HandoverCancel> {
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
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(HandoverCancel {
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

/// Parse a HandoverCancelAcknowledge (HANDOVER_CANCEL, SuccessfulOutcome).
fn parse_handover_cancel_acknowledge(
    container: ProtocolIeContainer,
) -> NgapResult<HandoverCancelAcknowledge> {
    let mut amf_ue_ngap_id = None;
    let mut ran_ue_ngap_id = None;
    let mut criticality_diagnostics = None;

    for field in &container.ies {
        match field.id {
            ProtocolIeId::AMF_UE_NGAP_ID => {
                amf_ue_ngap_id = Some(ie::decode_amf_ue_ngap_id(field)?);
            }
            ProtocolIeId::RAN_UE_NGAP_ID => {
                ran_ue_ngap_id = Some(ie::decode_ran_ue_ngap_id(field)?);
            }
            ProtocolIeId::CRITICALITY_DIAGNOSTICS => {
                criticality_diagnostics = Some(ie::decode_criticality_diagnostics(field)?);
            }
            _ => ie::handle_unknown_ie(field)?,
        }
    }

    Ok(HandoverCancelAcknowledge {
        amf_ue_ngap_id: amf_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "AMF-UE-NGAP-ID",
            ie_id: ProtocolIeId::AMF_UE_NGAP_ID.0,
        })?,
        ran_ue_ngap_id: ran_ue_ngap_id.ok_or(NgapError::MissingMandatoryIe {
            ie_name: "RAN-UE-NGAP-ID",
            ie_id: ProtocolIeId::RAN_UE_NGAP_ID.0,
        })?,
        criticality_diagnostics,
    })
}

/// Parse an OverloadStart (OVERLOAD_START, InitiatingMessage). All IEs optional.
fn parse_overload_start(container: ProtocolIeContainer) -> NgapResult<OverloadStart> {
    let mut traffic_load_reduction = None;
    for field in &container.ies {
        if field.id.0 == ie::IE_ID_TRAFFIC_LOAD_REDUCTION_INDICATION {
            traffic_load_reduction = Some(ie::decode_traffic_load_reduction(field)?);
        }
    }
    Ok(OverloadStart {
        traffic_load_reduction,
    })
}
