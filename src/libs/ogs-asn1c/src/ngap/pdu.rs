//! NGAP PDU Types
//!
//! Top-level PDU structures from NGAP-PDU-Descriptions (3GPP TS 38.413)

use crate::per::{AperDecode, AperDecoder, AperEncode, AperEncoder, PerResult, PerError};
use super::types::{Criticality, ProcedureCode};
use super::ies::ProtocolIeContainer;

/// NGAP-PDU - Top-level PDU for all NGAP messages
/// ASN.1: NGAP-PDU ::= CHOICE { initiatingMessage, successfulOutcome, unsuccessfulOutcome }
#[derive(Debug, Clone, PartialEq)]
pub enum NgapPdu {
    InitiatingMessage(InitiatingMessage),
    SuccessfulOutcome(SuccessfulOutcome),
    UnsuccessfulOutcome(UnsuccessfulOutcome),
}

impl NgapPdu {
    pub const NUM_ALTERNATIVES: usize = 3;
    pub const EXTENSIBLE: bool = true;
}

impl AperEncode for NgapPdu {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        match self {
            NgapPdu::InitiatingMessage(msg) => {
                encoder.encode_choice_index(0, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                msg.encode_aper(encoder)
            }
            NgapPdu::SuccessfulOutcome(msg) => {
                encoder.encode_choice_index(1, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                msg.encode_aper(encoder)
            }
            NgapPdu::UnsuccessfulOutcome(msg) => {
                encoder.encode_choice_index(2, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                msg.encode_aper(encoder)
            }
        }
    }
}

impl AperDecode for NgapPdu {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let index = decoder.decode_choice_index(Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
        match index {
            0 => Ok(NgapPdu::InitiatingMessage(InitiatingMessage::decode_aper(decoder)?)),
            1 => Ok(NgapPdu::SuccessfulOutcome(SuccessfulOutcome::decode_aper(decoder)?)),
            2 => Ok(NgapPdu::UnsuccessfulOutcome(UnsuccessfulOutcome::decode_aper(decoder)?)),
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
    NgSetupRequest(ProtocolIeContainer),
    InitialUeMessage(ProtocolIeContainer),
    UplinkNasTransport(ProtocolIeContainer),
    DownlinkNasTransport(ProtocolIeContainer),
    InitialContextSetupRequest(ProtocolIeContainer),
    UeContextReleaseCommand(ProtocolIeContainer),
    UeContextReleaseRequest(ProtocolIeContainer),
    PduSessionResourceSetupRequest(ProtocolIeContainer),
    PduSessionResourceReleaseCommand(ProtocolIeContainer),
    HandoverRequired(ProtocolIeContainer),
    HandoverRequest(ProtocolIeContainer),
    PathSwitchRequest(ProtocolIeContainer),
    NgReset(ProtocolIeContainer),
    ErrorIndication(ProtocolIeContainer),
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
            ProcedureCode::NG_SETUP => {
                InitiatingMessageValue::NgSetupRequest(
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
            InitiatingMessageValue::NgSetupRequest(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::InitialUeMessage(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::UplinkNasTransport(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::DownlinkNasTransport(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::InitialContextSetupRequest(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::UeContextReleaseCommand(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::UeContextReleaseRequest(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::PduSessionResourceSetupRequest(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::PduSessionResourceReleaseCommand(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::HandoverRequired(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::HandoverRequest(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::PathSwitchRequest(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::NgReset(ies) => ies.encode_aper(encoder),
            InitiatingMessageValue::ErrorIndication(ies) => ies.encode_aper(encoder),
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
    NgSetupResponse(ProtocolIeContainer),
    InitialContextSetupResponse(ProtocolIeContainer),
    UeContextReleaseComplete(ProtocolIeContainer),
    PduSessionResourceSetupResponse(ProtocolIeContainer),
    PduSessionResourceReleaseResponse(ProtocolIeContainer),
    HandoverCommand(ProtocolIeContainer),
    HandoverRequestAcknowledge(ProtocolIeContainer),
    PathSwitchRequestAcknowledge(ProtocolIeContainer),
    NgResetAcknowledge(ProtocolIeContainer),
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
            ProcedureCode::NG_SETUP => {
                SuccessfulOutcomeValue::NgSetupResponse(
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
            SuccessfulOutcomeValue::NgSetupResponse(ies) => ies.encode_aper(encoder),
            SuccessfulOutcomeValue::InitialContextSetupResponse(ies) => ies.encode_aper(encoder),
            SuccessfulOutcomeValue::UeContextReleaseComplete(ies) => ies.encode_aper(encoder),
            SuccessfulOutcomeValue::PduSessionResourceSetupResponse(ies) => ies.encode_aper(encoder),
            SuccessfulOutcomeValue::PduSessionResourceReleaseResponse(ies) => ies.encode_aper(encoder),
            SuccessfulOutcomeValue::HandoverCommand(ies) => ies.encode_aper(encoder),
            SuccessfulOutcomeValue::HandoverRequestAcknowledge(ies) => ies.encode_aper(encoder),
            SuccessfulOutcomeValue::PathSwitchRequestAcknowledge(ies) => ies.encode_aper(encoder),
            SuccessfulOutcomeValue::NgResetAcknowledge(ies) => ies.encode_aper(encoder),
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
    NgSetupFailure(ProtocolIeContainer),
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
            ProcedureCode::NG_SETUP => {
                UnsuccessfulOutcomeValue::NgSetupFailure(
                    ProtocolIeContainer::decode_aper(&mut value_decoder)?
                )
            }
            ProcedureCode::INITIAL_CONTEXT_SETUP => {
                UnsuccessfulOutcomeValue::InitialContextSetupFailure(
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
            UnsuccessfulOutcomeValue::NgSetupFailure(ies) => ies.encode_aper(encoder),
            UnsuccessfulOutcomeValue::InitialContextSetupFailure(ies) => ies.encode_aper(encoder),
            UnsuccessfulOutcomeValue::HandoverPreparationFailure(ies) => ies.encode_aper(encoder),
            UnsuccessfulOutcomeValue::HandoverFailure(ies) => ies.encode_aper(encoder),
            UnsuccessfulOutcomeValue::PathSwitchRequestFailure(ies) => ies.encode_aper(encoder),
            UnsuccessfulOutcomeValue::Other(ies) => ies.encode_aper(encoder),
        }
    }
}
