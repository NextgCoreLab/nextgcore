//! S1AP PDU Types
//!
//! Top-level PDU structures from S1AP-PDU-Descriptions (3GPP TS 36.413)

use crate::per::{AperDecode, AperDecoder, AperEncode, AperEncoder, PerResult, PerError};
use super::types::{Criticality, ProcedureCode};
use super::ies::ProtocolIeContainer;

/// S1AP-PDU - Top-level PDU for all S1AP messages
/// ASN.1: S1AP-PDU ::= CHOICE { initiatingMessage, successfulOutcome, unsuccessfulOutcome }
#[derive(Debug, Clone, PartialEq)]
pub enum S1apPdu {
    InitiatingMessage(InitiatingMessage),
    SuccessfulOutcome(SuccessfulOutcome),
    UnsuccessfulOutcome(UnsuccessfulOutcome),
}

impl S1apPdu {
    pub const NUM_ALTERNATIVES: usize = 3;
    pub const EXTENSIBLE: bool = true;
}

impl AperEncode for S1apPdu {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        match self {
            S1apPdu::InitiatingMessage(msg) => {
                encoder.encode_choice_index(0, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                msg.encode_aper(encoder)
            }
            S1apPdu::SuccessfulOutcome(msg) => {
                encoder.encode_choice_index(1, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                msg.encode_aper(encoder)
            }
            S1apPdu::UnsuccessfulOutcome(msg) => {
                encoder.encode_choice_index(2, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                msg.encode_aper(encoder)
            }
        }
    }
}

impl AperDecode for S1apPdu {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let index = decoder.decode_choice_index(Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
        match index {
            0 => Ok(S1apPdu::InitiatingMessage(InitiatingMessage::decode_aper(decoder)?)),
            1 => Ok(S1apPdu::SuccessfulOutcome(SuccessfulOutcome::decode_aper(decoder)?)),
            2 => Ok(S1apPdu::UnsuccessfulOutcome(UnsuccessfulOutcome::decode_aper(decoder)?)),
            _ => Err(PerError::InvalidChoiceIndex {
                index,
                max: Self::NUM_ALTERNATIVES - 1,
            }),
        }
    }
}

/// InitiatingMessage - Request/indication messages
/// ASN.1: InitiatingMessage ::= SEQUENCE { procedureCode, criticality, value }
#[derive(Debug, Clone, PartialEq)]
pub struct InitiatingMessage {
    pub procedure_code: ProcedureCode,
    pub criticality: Criticality,
    pub value: InitiatingMessageValue,
}

/// Value types for InitiatingMessage
#[derive(Debug, Clone, PartialEq)]
pub enum InitiatingMessageValue {
    S1SetupRequest(ProtocolIeContainer),
    InitialUeMessage(ProtocolIeContainer),
    UplinkNasTransport(ProtocolIeContainer),
    DownlinkNasTransport(ProtocolIeContainer),
    InitialContextSetupRequest(ProtocolIeContainer),
    UeContextReleaseCommand(ProtocolIeContainer),
    UeContextReleaseRequest(ProtocolIeContainer),
    ERabSetupRequest(ProtocolIeContainer),
    ERabModifyRequest(ProtocolIeContainer),
    ERabReleaseCommand(ProtocolIeContainer),
    HandoverRequired(ProtocolIeContainer),
    HandoverRequest(ProtocolIeContainer),
    PathSwitchRequest(ProtocolIeContainer),
    Reset(ProtocolIeContainer),
    ErrorIndication(ProtocolIeContainer),
    Paging(ProtocolIeContainer),
    // Generic container for other message types
    Other(ProtocolIeContainer),
}

impl AperEncode for InitiatingMessage {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        // SEQUENCE with no extension marker in root
        self.procedure_code.encode_aper(encoder)?;
        self.criticality.encode_aper(encoder)?;
        
        // Value is encoded as OPEN TYPE (length + content)
        let mut value_encoder = AperEncoder::new();
        self.value.encode_aper(&mut value_encoder)?;
        value_encoder.align();
        let value_bytes = value_encoder.into_bytes();
        
        encoder.encode_length_determinant(value_bytes.len())?;
        encoder.write_bytes(&value_bytes);
        
        Ok(())
    }
}

impl AperDecode for InitiatingMessage {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let procedure_code = ProcedureCode::decode_aper(decoder)?;
        let criticality = Criticality::decode_aper(decoder)?;
        
        // Decode OPEN TYPE
        let value_len = decoder.decode_length_determinant()?;
        let value_bytes = decoder.read_bytes(value_len)?;
        let mut value_decoder = AperDecoder::new(&value_bytes);
        
        let value = match procedure_code {
            ProcedureCode::S1_SETUP => {
                InitiatingMessageValue::S1SetupRequest(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::INITIAL_UE_MESSAGE => {
                InitiatingMessageValue::InitialUeMessage(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::UPLINK_NAS_TRANSPORT => {
                InitiatingMessageValue::UplinkNasTransport(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::DOWNLINK_NAS_TRANSPORT => {
                InitiatingMessageValue::DownlinkNasTransport(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::INITIAL_CONTEXT_SETUP => {
                InitiatingMessageValue::InitialContextSetupRequest(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::UE_CONTEXT_RELEASE => {
                InitiatingMessageValue::UeContextReleaseCommand(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::UE_CONTEXT_RELEASE_REQUEST => {
                InitiatingMessageValue::UeContextReleaseRequest(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::E_RAB_SETUP => {
                InitiatingMessageValue::ERabSetupRequest(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::E_RAB_MODIFY => {
                InitiatingMessageValue::ERabModifyRequest(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::E_RAB_RELEASE => {
                InitiatingMessageValue::ERabReleaseCommand(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::HANDOVER_PREPARATION => {
                InitiatingMessageValue::HandoverRequired(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::HANDOVER_RESOURCE_ALLOCATION => {
                InitiatingMessageValue::HandoverRequest(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::PATH_SWITCH_REQUEST => {
                InitiatingMessageValue::PathSwitchRequest(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::RESET => {
                InitiatingMessageValue::Reset(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::ERROR_INDICATION => {
                InitiatingMessageValue::ErrorIndication(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::PAGING => {
                InitiatingMessageValue::Paging(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            _ => {
                InitiatingMessageValue::Other(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
        };
        
        Ok(InitiatingMessage {
            procedure_code,
            criticality,
            value,
        })
    }
}

impl AperEncode for InitiatingMessageValue {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        match self {
            InitiatingMessageValue::S1SetupRequest(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::InitialUeMessage(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::UplinkNasTransport(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::DownlinkNasTransport(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::InitialContextSetupRequest(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::UeContextReleaseCommand(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::UeContextReleaseRequest(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::ERabSetupRequest(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::ERabModifyRequest(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::ERabReleaseCommand(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::HandoverRequired(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::HandoverRequest(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::PathSwitchRequest(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::Reset(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::ErrorIndication(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::Paging(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::Other(ies) => ies.encode_aper(encoder),
        }
    }
}


/// SuccessfulOutcome - Response messages for successful procedures
/// ASN.1: SuccessfulOutcome ::= SEQUENCE { procedureCode, criticality, value }
#[derive(Debug, Clone, PartialEq)]
pub struct SuccessfulOutcome {
    pub procedure_code: ProcedureCode,
    pub criticality: Criticality,
    pub value: SuccessfulOutcomeValue,
}

/// Value types for SuccessfulOutcome
#[derive(Debug, Clone, PartialEq)]
pub enum SuccessfulOutcomeValue {
    S1SetupResponse(ProtocolIeContainer),
    InitialContextSetupResponse(ProtocolIeContainer),
    UeContextReleaseComplete(ProtocolIeContainer),
    ERabSetupResponse(ProtocolIeContainer),
    ERabModifyResponse(ProtocolIeContainer),
    ERabReleaseResponse(ProtocolIeContainer),
    HandoverCommand(ProtocolIeContainer),
    HandoverRequestAcknowledge(ProtocolIeContainer),
    PathSwitchRequestAcknowledge(ProtocolIeContainer),
    ResetAcknowledge(ProtocolIeContainer),
    Other(ProtocolIeContainer),
}

impl AperEncode for SuccessfulOutcome {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        self.procedure_code.encode_aper(encoder)?;
        self.criticality.encode_aper(encoder)?;
        
        let mut value_encoder = AperEncoder::new();
        self.value.encode_aper(&mut value_encoder)?;
        value_encoder.align();
        let value_bytes = value_encoder.into_bytes();
        
        encoder.encode_length_determinant(value_bytes.len())?;
        encoder.write_bytes(&value_bytes);
        
        Ok(())
    }
}

impl AperDecode for SuccessfulOutcome {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let procedure_code = ProcedureCode::decode_aper(decoder)?;
        let criticality = Criticality::decode_aper(decoder)?;
        
        let value_len = decoder.decode_length_determinant()?;
        let value_bytes = decoder.read_bytes(value_len)?;
        let mut value_decoder = AperDecoder::new(&value_bytes);
        
        let value = match procedure_code {
            ProcedureCode::S1_SETUP => {
                SuccessfulOutcomeValue::S1SetupResponse(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::INITIAL_CONTEXT_SETUP => {
                SuccessfulOutcomeValue::InitialContextSetupResponse(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::UE_CONTEXT_RELEASE => {
                SuccessfulOutcomeValue::UeContextReleaseComplete(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::E_RAB_SETUP => {
                SuccessfulOutcomeValue::ERabSetupResponse(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::E_RAB_MODIFY => {
                SuccessfulOutcomeValue::ERabModifyResponse(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::E_RAB_RELEASE => {
                SuccessfulOutcomeValue::ERabReleaseResponse(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::HANDOVER_PREPARATION => {
                SuccessfulOutcomeValue::HandoverCommand(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::HANDOVER_RESOURCE_ALLOCATION => {
                SuccessfulOutcomeValue::HandoverRequestAcknowledge(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::PATH_SWITCH_REQUEST => {
                SuccessfulOutcomeValue::PathSwitchRequestAcknowledge(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::RESET => {
                SuccessfulOutcomeValue::ResetAcknowledge(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            _ => {
                SuccessfulOutcomeValue::Other(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
        };
        
        Ok(SuccessfulOutcome {
            procedure_code,
            criticality,
            value,
        })
    }
}

impl AperEncode for SuccessfulOutcomeValue {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        match self {
            SuccessfulOutcomeValue::S1SetupResponse(ies) => ies.encode_aper(encoder),
            SuccessfulOutcomeValue::InitialContextSetupResponse(ies) => ies.encode_aper(encoder),
            SuccessfulOutcomeValue::UeContextReleaseComplete(ies) => ies.encode_aper(encoder),
            SuccessfulOutcomeValue::ERabSetupResponse(ies) => ies.encode_aper(encoder),
            SuccessfulOutcomeValue::ERabModifyResponse(ies) => ies.encode_aper(encoder),
            SuccessfulOutcomeValue::ERabReleaseResponse(ies) => ies.encode_aper(encoder),
            SuccessfulOutcomeValue::HandoverCommand(ies) => ies.encode_aper(encoder),
            SuccessfulOutcomeValue::HandoverRequestAcknowledge(ies) => ies.encode_aper(encoder),
            SuccessfulOutcomeValue::PathSwitchRequestAcknowledge(ies) => ies.encode_aper(encoder),
            SuccessfulOutcomeValue::ResetAcknowledge(ies) => ies.encode_aper(encoder),
            SuccessfulOutcomeValue::Other(ies) => ies.encode_aper(encoder),
        }
    }
}

/// UnsuccessfulOutcome - Response messages for failed procedures
/// ASN.1: UnsuccessfulOutcome ::= SEQUENCE { procedureCode, criticality, value }
#[derive(Debug, Clone, PartialEq)]
pub struct UnsuccessfulOutcome {
    pub procedure_code: ProcedureCode,
    pub criticality: Criticality,
    pub value: UnsuccessfulOutcomeValue,
}

/// Value types for UnsuccessfulOutcome
#[derive(Debug, Clone, PartialEq)]
pub enum UnsuccessfulOutcomeValue {
    S1SetupFailure(ProtocolIeContainer),
    InitialContextSetupFailure(ProtocolIeContainer),
    HandoverPreparationFailure(ProtocolIeContainer),
    HandoverFailure(ProtocolIeContainer),
    PathSwitchRequestFailure(ProtocolIeContainer),
    Other(ProtocolIeContainer),
}

impl AperEncode for UnsuccessfulOutcome {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        self.procedure_code.encode_aper(encoder)?;
        self.criticality.encode_aper(encoder)?;
        
        let mut value_encoder = AperEncoder::new();
        self.value.encode_aper(&mut value_encoder)?;
        value_encoder.align();
        let value_bytes = value_encoder.into_bytes();
        
        encoder.encode_length_determinant(value_bytes.len())?;
        encoder.write_bytes(&value_bytes);
        
        Ok(())
    }
}

impl AperDecode for UnsuccessfulOutcome {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let procedure_code = ProcedureCode::decode_aper(decoder)?;
        let criticality = Criticality::decode_aper(decoder)?;
        
        let value_len = decoder.decode_length_determinant()?;
        let value_bytes = decoder.read_bytes(value_len)?;
        let mut value_decoder = AperDecoder::new(&value_bytes);
        
        let value = match procedure_code {
            ProcedureCode::S1_SETUP => {
                UnsuccessfulOutcomeValue::S1SetupFailure(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::INITIAL_CONTEXT_SETUP => {
                UnsuccessfulOutcomeValue::InitialContextSetupFailure(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::HANDOVER_PREPARATION => {
                UnsuccessfulOutcomeValue::HandoverPreparationFailure(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::HANDOVER_RESOURCE_ALLOCATION => {
                UnsuccessfulOutcomeValue::HandoverFailure(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::PATH_SWITCH_REQUEST => {
                UnsuccessfulOutcomeValue::PathSwitchRequestFailure(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            _ => {
                UnsuccessfulOutcomeValue::Other(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
        };
        
        Ok(UnsuccessfulOutcome {
            procedure_code,
            criticality,
            value,
        })
    }
}

impl AperEncode for UnsuccessfulOutcomeValue {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        match self {
            UnsuccessfulOutcomeValue::S1SetupFailure(ies) => ies.encode_aper(encoder),
            UnsuccessfulOutcomeValue::InitialContextSetupFailure(ies) => ies.encode_aper(encoder),
            UnsuccessfulOutcomeValue::HandoverPreparationFailure(ies) => ies.encode_aper(encoder),
            UnsuccessfulOutcomeValue::HandoverFailure(ies) => ies.encode_aper(encoder),
            UnsuccessfulOutcomeValue::PathSwitchRequestFailure(ies) => ies.encode_aper(encoder),
            UnsuccessfulOutcomeValue::Other(ies) => ies.encode_aper(encoder),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::per::{AperEncoder, AperDecoder};
    use super::super::ies::ProtocolIeField;
    use super::super::types::{Criticality, ProtocolIeId};

    #[test]
    fn test_s1ap_pdu_initiating_message_roundtrip() {
        let mut container = ProtocolIeContainer::new();
        container.push(ProtocolIeField {
            id: ProtocolIeId::GLOBAL_ENB_ID,
            criticality: Criticality::Reject,
            value: vec![0x00, 0x01, 0x02, 0x03],
        });
        
        let pdu = S1apPdu::InitiatingMessage(InitiatingMessage {
            procedure_code: ProcedureCode::S1_SETUP,
            criticality: Criticality::Reject,
            value: InitiatingMessageValue::S1SetupRequest(container),
        });
        
        let mut encoder = AperEncoder::new();
        pdu.encode_aper(&mut encoder).unwrap();
        encoder.align();
        
        let bytes = encoder.into_bytes();
        let mut decoder = AperDecoder::new(&bytes);
        let decoded = S1apPdu::decode_aper(&mut decoder).unwrap();
        
        match decoded {
            S1apPdu::InitiatingMessage(msg) => {
                assert_eq!(msg.procedure_code, ProcedureCode::S1_SETUP);
                assert_eq!(msg.criticality, Criticality::Reject);
            }
            _ => panic!("Expected InitiatingMessage"),
        }
    }

    #[test]
    fn test_s1ap_pdu_successful_outcome_roundtrip() {
        let container = ProtocolIeContainer::new();
        
        let pdu = S1apPdu::SuccessfulOutcome(SuccessfulOutcome {
            procedure_code: ProcedureCode::S1_SETUP,
            criticality: Criticality::Reject,
            value: SuccessfulOutcomeValue::S1SetupResponse(container),
        });
        
        let mut encoder = AperEncoder::new();
        pdu.encode_aper(&mut encoder).unwrap();
        encoder.align();
        
        let bytes = encoder.into_bytes();
        let mut decoder = AperDecoder::new(&bytes);
        let decoded = S1apPdu::decode_aper(&mut decoder).unwrap();
        
        match decoded {
            S1apPdu::SuccessfulOutcome(msg) => {
                assert_eq!(msg.procedure_code, ProcedureCode::S1_SETUP);
            }
            _ => panic!("Expected SuccessfulOutcome"),
        }
    }

    #[test]
    fn test_s1ap_pdu_unsuccessful_outcome_roundtrip() {
        let container = ProtocolIeContainer::new();
        
        let pdu = S1apPdu::UnsuccessfulOutcome(UnsuccessfulOutcome {
            procedure_code: ProcedureCode::S1_SETUP,
            criticality: Criticality::Reject,
            value: UnsuccessfulOutcomeValue::S1SetupFailure(container),
        });
        
        let mut encoder = AperEncoder::new();
        pdu.encode_aper(&mut encoder).unwrap();
        encoder.align();
        
        let bytes = encoder.into_bytes();
        let mut decoder = AperDecoder::new(&bytes);
        let decoded = S1apPdu::decode_aper(&mut decoder).unwrap();
        
        match decoded {
            S1apPdu::UnsuccessfulOutcome(msg) => {
                assert_eq!(msg.procedure_code, ProcedureCode::S1_SETUP);
            }
            _ => panic!("Expected UnsuccessfulOutcome"),
        }
    }
}
