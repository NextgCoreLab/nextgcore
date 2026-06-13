//! NGAP PDU Types
//!
//! Top-level PDU structures from NGAP-PDU-Descriptions (3GPP TS 38.413)

use super::ies::ProtocolIeContainer;
use super::types::{Criticality, ProcedureCode};
use crate::per::{AperDecode, AperDecoder, AperEncode, AperEncoder, PerError, PerResult};

/// Read the OPEN TYPE value of a PDU wrapper, reassembling fragmented
/// lengths per X.691 Section 11.9.3 (message values can exceed 16383
/// octets when they carry large NAS-PDUs or transparent containers).
fn read_open_type_value(decoder: &mut AperDecoder) -> PerResult<Vec<u8>> {
    let mut value = Vec::new();
    loop {
        let (len, fragmented) = decoder.decode_length_fragment()?;
        value.extend_from_slice(&decoder.read_bytes(len)?);
        if !fragmented {
            return Ok(value);
        }
    }
}

/// Encode the body of an NGAP elementary-procedure message value.
///
/// Every NGAP message is defined as an extensible SEQUENCE
/// `{ protocolIEs ProtocolIE-Container {...}, ... }` (TS 38.413). Per X.691
/// the extensible SEQUENCE prepends a single extension-marker bit (0 = no
/// extension present) before its root field — the IE container. The open-type
/// framing then octet-aligns the content.
fn encode_message_value<F>(encode_ies: F) -> PerResult<Vec<u8>>
where
    F: FnOnce(&mut AperEncoder) -> PerResult<()>,
{
    let mut value_encoder = AperEncoder::new();
    // SEQUENCE extension marker: no extension additions present
    value_encoder.write_bit(false);
    encode_ies(&mut value_encoder)?;
    value_encoder.align();
    Ok(value_encoder.into_bytes().to_vec())
}

/// Decode the body of an NGAP elementary-procedure message value, consuming the
/// extensible-SEQUENCE extension-marker bit before the IE container.
fn decode_message_container(value_bytes: &[u8]) -> PerResult<ProtocolIeContainer> {
    let mut value_decoder = AperDecoder::new(value_bytes);
    // SEQUENCE extension marker (ignored: NGAP messages carry their additions
    // as further ProtocolIE-Container entries, not SEQUENCE extension fields)
    let _ext = value_decoder.read_bit()?;
    ProtocolIeContainer::decode_aper(&mut value_decoder)
}

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
            0 => Ok(NgapPdu::InitiatingMessage(InitiatingMessage::decode_aper(
                decoder,
            )?)),
            1 => Ok(NgapPdu::SuccessfulOutcome(SuccessfulOutcome::decode_aper(
                decoder,
            )?)),
            2 => Ok(NgapPdu::UnsuccessfulOutcome(
                UnsuccessfulOutcome::decode_aper(decoder)?,
            )),
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

        // Value is encoded as OPEN TYPE (length + content); the inner message
        // SEQUENCE carries its own extension-marker preamble bit.
        let value_bytes = encode_message_value(|enc| self.value.encode_aper(enc))?;
        encoder.encode_fragmented_octets(&value_bytes)?;

        Ok(())
    }
}

impl AperDecode for InitiatingMessage {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let procedure_code = ProcedureCode::decode_aper(decoder)?;
        let criticality = Criticality::decode_aper(decoder)?;

        // Decode OPEN TYPE; the inner message SEQUENCE carries its own
        // extension-marker preamble bit before the IE container.
        let value_bytes = read_open_type_value(decoder)?;
        let ies = decode_message_container(&value_bytes)?;

        let value = match procedure_code {
            ProcedureCode::NG_SETUP => InitiatingMessageValue::NgSetupRequest(ies),
            ProcedureCode::INITIAL_UE_MESSAGE => InitiatingMessageValue::InitialUeMessage(ies),
            ProcedureCode::UPLINK_NAS_TRANSPORT => InitiatingMessageValue::UplinkNasTransport(ies),
            ProcedureCode::DOWNLINK_NAS_TRANSPORT => {
                InitiatingMessageValue::DownlinkNasTransport(ies)
            }
            ProcedureCode::INITIAL_CONTEXT_SETUP => {
                InitiatingMessageValue::InitialContextSetupRequest(ies)
            }
            ProcedureCode::UE_CONTEXT_RELEASE => {
                InitiatingMessageValue::UeContextReleaseCommand(ies)
            }
            ProcedureCode::UE_CONTEXT_RELEASE_REQUEST => {
                InitiatingMessageValue::UeContextReleaseRequest(ies)
            }
            _ => InitiatingMessageValue::Other(ies),
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
            InitiatingMessageValue::PduSessionResourceReleaseCommand(ies) => {
                ies.encode_aper(encoder)
            }
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

        let value_bytes = encode_message_value(|enc| self.value.encode_aper(enc))?;
        encoder.encode_fragmented_octets(&value_bytes)?;

        Ok(())
    }
}

impl AperDecode for SuccessfulOutcome {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let procedure_code = ProcedureCode::decode_aper(decoder)?;
        let criticality = Criticality::decode_aper(decoder)?;

        let value_bytes = read_open_type_value(decoder)?;
        let ies = decode_message_container(&value_bytes)?;

        let value = match procedure_code {
            ProcedureCode::NG_SETUP => SuccessfulOutcomeValue::NgSetupResponse(ies),
            ProcedureCode::INITIAL_CONTEXT_SETUP => {
                SuccessfulOutcomeValue::InitialContextSetupResponse(ies)
            }
            ProcedureCode::UE_CONTEXT_RELEASE => {
                SuccessfulOutcomeValue::UeContextReleaseComplete(ies)
            }
            _ => SuccessfulOutcomeValue::Other(ies),
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
            SuccessfulOutcomeValue::PduSessionResourceSetupResponse(ies) => {
                ies.encode_aper(encoder)
            }
            SuccessfulOutcomeValue::PduSessionResourceReleaseResponse(ies) => {
                ies.encode_aper(encoder)
            }
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

        let value_bytes = encode_message_value(|enc| self.value.encode_aper(enc))?;
        encoder.encode_fragmented_octets(&value_bytes)?;

        Ok(())
    }
}

impl AperDecode for UnsuccessfulOutcome {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let procedure_code = ProcedureCode::decode_aper(decoder)?;
        let criticality = Criticality::decode_aper(decoder)?;

        let value_bytes = read_open_type_value(decoder)?;
        let ies = decode_message_container(&value_bytes)?;

        let value = match procedure_code {
            ProcedureCode::NG_SETUP => UnsuccessfulOutcomeValue::NgSetupFailure(ies),
            ProcedureCode::INITIAL_CONTEXT_SETUP => {
                UnsuccessfulOutcomeValue::InitialContextSetupFailure(ies)
            }
            _ => UnsuccessfulOutcomeValue::Other(ies),
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
