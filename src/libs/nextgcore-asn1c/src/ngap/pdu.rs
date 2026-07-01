//! NGAP PDU Types
//!
//! Top-level PDU structures from NGAP-PDU-Descriptions (3GPP TS 38.413)

use super::ies::{
    AmfUeNgapId, NrppaPdu, ProtocolIeContainer, ProtocolIeField, RanUeNgapId, RoutingId,
};
use super::types::{Criticality, ProcedureCode, ProtocolIeId};
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
    // NRPPa transport (LMF positioning; payload carried opaquely)
    DownlinkUeAssociatedNrppaTransport(ProtocolIeContainer),
    UplinkUeAssociatedNrppaTransport(ProtocolIeContainer),
    DownlinkNonUeAssociatedNrppaTransport(ProtocolIeContainer),
    UplinkNonUeAssociatedNrppaTransport(ProtocolIeContainer),
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
            ProcedureCode::DOWNLINK_UE_ASSOCIATED_NRPPA_TRANSPORT => {
                InitiatingMessageValue::DownlinkUeAssociatedNrppaTransport(ies)
            }
            ProcedureCode::UPLINK_UE_ASSOCIATED_NRPPA_TRANSPORT => {
                InitiatingMessageValue::UplinkUeAssociatedNrppaTransport(ies)
            }
            ProcedureCode::DOWNLINK_NON_UE_ASSOCIATED_NRPPA_TRANSPORT => {
                InitiatingMessageValue::DownlinkNonUeAssociatedNrppaTransport(ies)
            }
            ProcedureCode::UPLINK_NON_UE_ASSOCIATED_NRPPA_TRANSPORT => {
                InitiatingMessageValue::UplinkNonUeAssociatedNrppaTransport(ies)
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
            InitiatingMessageValue::DownlinkUeAssociatedNrppaTransport(ies) => {
                ies.encode_aper(encoder)
            }
            InitiatingMessageValue::UplinkUeAssociatedNrppaTransport(ies) => {
                ies.encode_aper(encoder)
            }
            InitiatingMessageValue::DownlinkNonUeAssociatedNrppaTransport(ies) => {
                ies.encode_aper(encoder)
            }
            InitiatingMessageValue::UplinkNonUeAssociatedNrppaTransport(ies) => {
                ies.encode_aper(encoder)
            }
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

// ---------------------------------------------------------------------------
// NRPPa transport (TS 38.413 §8.x / §9.3) builders and parsers
//
// The four NRPPa-transport procedures carry the OPAQUE NRPPa payload between
// the gNB and the AMF; the AMF relays it to/from the LMF. All IEs are
// criticality `reject`, mandatory; the procedure (message) criticality is
// `ignore`. These are strictly additive — no existing message is touched.
// ---------------------------------------------------------------------------

/// Encode a typed IE value to its octet-aligned open-type content bytes.
fn encode_ie_value<T: AperEncode>(value: &T) -> PerResult<Vec<u8>> {
    let mut encoder = AperEncoder::new();
    value.encode_aper(&mut encoder)?;
    encoder.align();
    Ok(encoder.into_bytes().to_vec())
}

/// Decode a typed IE value from its open-type content bytes.
fn decode_ie_value<T: AperDecode>(bytes: &[u8]) -> PerResult<T> {
    let mut decoder = AperDecoder::new(bytes);
    T::decode_aper(&mut decoder)
}

fn ie<T: AperEncode>(
    id: ProtocolIeId,
    criticality: Criticality,
    value: &T,
) -> PerResult<ProtocolIeField> {
    Ok(ProtocolIeField {
        id,
        criticality,
        value: encode_ie_value(value)?,
    })
}

/// Wrap an IE container as the InitiatingMessage of an NRPPa-transport
/// procedure (message criticality `ignore`).
fn nrppa_transport_message(
    procedure_code: ProcedureCode,
    value: InitiatingMessageValue,
) -> NgapPdu {
    NgapPdu::InitiatingMessage(InitiatingMessage {
        procedure_code,
        criticality: Criticality::Ignore,
        value,
    })
}

/// Decoded view of a UE-associated NRPPa-transport message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UeAssociatedNrppaTransport {
    pub amf_ue_ngap_id: AmfUeNgapId,
    pub ran_ue_ngap_id: RanUeNgapId,
    pub routing_id: RoutingId,
    pub nrppa_pdu: NrppaPdu,
}

/// Decoded view of a non-UE-associated NRPPa-transport message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonUeAssociatedNrppaTransport {
    pub routing_id: RoutingId,
    pub nrppa_pdu: NrppaPdu,
}

/// Build the UE-associated IE container shared by the DL/UL UE-associated
/// transport messages: AMF-UE-NGAP-ID, RAN-UE-NGAP-ID, RoutingID, NRPPa-PDU
/// (all criticality reject, mandatory).
fn build_ue_associated_container(
    amf_ue_ngap_id: AmfUeNgapId,
    ran_ue_ngap_id: RanUeNgapId,
    routing_id: &RoutingId,
    nrppa_pdu: &NrppaPdu,
) -> PerResult<ProtocolIeContainer> {
    let mut container = ProtocolIeContainer::new();
    container.push(ie(
        ProtocolIeId::AMF_UE_NGAP_ID,
        Criticality::Reject,
        &amf_ue_ngap_id,
    )?);
    container.push(ie(
        ProtocolIeId::RAN_UE_NGAP_ID,
        Criticality::Reject,
        &ran_ue_ngap_id,
    )?);
    container.push(ie(
        ProtocolIeId::ROUTING_ID,
        Criticality::Reject,
        routing_id,
    )?);
    container.push(ie(ProtocolIeId::NRPPA_PDU, Criticality::Reject, nrppa_pdu)?);
    Ok(container)
}

/// Build the non-UE-associated IE container: RoutingID, NRPPa-PDU.
fn build_non_ue_associated_container(
    routing_id: &RoutingId,
    nrppa_pdu: &NrppaPdu,
) -> PerResult<ProtocolIeContainer> {
    let mut container = ProtocolIeContainer::new();
    container.push(ie(
        ProtocolIeId::ROUTING_ID,
        Criticality::Reject,
        routing_id,
    )?);
    container.push(ie(ProtocolIeId::NRPPA_PDU, Criticality::Reject, nrppa_pdu)?);
    Ok(container)
}

/// Build a `DownlinkUEAssociatedNRPPaTransport` (procedure code 8).
pub fn build_downlink_ue_associated_nrppa_transport(
    amf_ue_ngap_id: AmfUeNgapId,
    ran_ue_ngap_id: RanUeNgapId,
    routing_id: RoutingId,
    nrppa_pdu: NrppaPdu,
) -> PerResult<NgapPdu> {
    let container =
        build_ue_associated_container(amf_ue_ngap_id, ran_ue_ngap_id, &routing_id, &nrppa_pdu)?;
    Ok(nrppa_transport_message(
        ProcedureCode::DOWNLINK_UE_ASSOCIATED_NRPPA_TRANSPORT,
        InitiatingMessageValue::DownlinkUeAssociatedNrppaTransport(container),
    ))
}

/// Build an `UplinkUEAssociatedNRPPaTransport` (procedure code 50).
pub fn build_uplink_ue_associated_nrppa_transport(
    amf_ue_ngap_id: AmfUeNgapId,
    ran_ue_ngap_id: RanUeNgapId,
    routing_id: RoutingId,
    nrppa_pdu: NrppaPdu,
) -> PerResult<NgapPdu> {
    let container =
        build_ue_associated_container(amf_ue_ngap_id, ran_ue_ngap_id, &routing_id, &nrppa_pdu)?;
    Ok(nrppa_transport_message(
        ProcedureCode::UPLINK_UE_ASSOCIATED_NRPPA_TRANSPORT,
        InitiatingMessageValue::UplinkUeAssociatedNrppaTransport(container),
    ))
}

/// Build a `DownlinkNonUEAssociatedNRPPaTransport` (procedure code 5).
pub fn build_downlink_non_ue_associated_nrppa_transport(
    routing_id: RoutingId,
    nrppa_pdu: NrppaPdu,
) -> PerResult<NgapPdu> {
    let container = build_non_ue_associated_container(&routing_id, &nrppa_pdu)?;
    Ok(nrppa_transport_message(
        ProcedureCode::DOWNLINK_NON_UE_ASSOCIATED_NRPPA_TRANSPORT,
        InitiatingMessageValue::DownlinkNonUeAssociatedNrppaTransport(container),
    ))
}

/// Build an `UplinkNonUEAssociatedNRPPaTransport` (procedure code 47).
pub fn build_uplink_non_ue_associated_nrppa_transport(
    routing_id: RoutingId,
    nrppa_pdu: NrppaPdu,
) -> PerResult<NgapPdu> {
    let container = build_non_ue_associated_container(&routing_id, &nrppa_pdu)?;
    Ok(nrppa_transport_message(
        ProcedureCode::UPLINK_NON_UE_ASSOCIATED_NRPPA_TRANSPORT,
        InitiatingMessageValue::UplinkNonUeAssociatedNrppaTransport(container),
    ))
}

/// Extract the typed IEs from a UE-associated NRPPa-transport container.
fn parse_ue_associated_container(
    container: &ProtocolIeContainer,
) -> PerResult<UeAssociatedNrppaTransport> {
    let amf = container
        .find(ProtocolIeId::AMF_UE_NGAP_ID)
        .ok_or_else(|| PerError::DecodeError("missing mandatory AMF-UE-NGAP-ID".to_string()))?;
    let ran = container
        .find(ProtocolIeId::RAN_UE_NGAP_ID)
        .ok_or_else(|| PerError::DecodeError("missing mandatory RAN-UE-NGAP-ID".to_string()))?;
    let routing = container
        .find(ProtocolIeId::ROUTING_ID)
        .ok_or_else(|| PerError::DecodeError("missing mandatory RoutingID".to_string()))?;
    let pdu = container
        .find(ProtocolIeId::NRPPA_PDU)
        .ok_or_else(|| PerError::DecodeError("missing mandatory NRPPa-PDU".to_string()))?;
    Ok(UeAssociatedNrppaTransport {
        amf_ue_ngap_id: decode_ie_value(&amf.value)?,
        ran_ue_ngap_id: decode_ie_value(&ran.value)?,
        routing_id: decode_ie_value(&routing.value)?,
        nrppa_pdu: decode_ie_value(&pdu.value)?,
    })
}

/// Extract the typed IEs from a non-UE-associated NRPPa-transport container.
fn parse_non_ue_associated_container(
    container: &ProtocolIeContainer,
) -> PerResult<NonUeAssociatedNrppaTransport> {
    let routing = container
        .find(ProtocolIeId::ROUTING_ID)
        .ok_or_else(|| PerError::DecodeError("missing mandatory RoutingID".to_string()))?;
    let pdu = container
        .find(ProtocolIeId::NRPPA_PDU)
        .ok_or_else(|| PerError::DecodeError("missing mandatory NRPPa-PDU".to_string()))?;
    Ok(NonUeAssociatedNrppaTransport {
        routing_id: decode_ie_value(&routing.value)?,
        nrppa_pdu: decode_ie_value(&pdu.value)?,
    })
}

/// Parse a decoded `NgapPdu` as a UE-associated NRPPa-transport message
/// (downlink procedure 8 or uplink procedure 50).
pub fn parse_ue_associated_nrppa_transport(pdu: &NgapPdu) -> PerResult<UeAssociatedNrppaTransport> {
    let container = match pdu {
        NgapPdu::InitiatingMessage(m) => match &m.value {
            InitiatingMessageValue::DownlinkUeAssociatedNrppaTransport(c)
            | InitiatingMessageValue::UplinkUeAssociatedNrppaTransport(c) => c,
            _ => {
                return Err(PerError::DecodeError(
                    "PDU is not a UE-associated NRPPa-transport message".to_string(),
                ))
            }
        },
        _ => {
            return Err(PerError::DecodeError(
                "PDU is not an initiating message".to_string(),
            ))
        }
    };
    parse_ue_associated_container(container)
}

/// Parse a decoded `NgapPdu` as a non-UE-associated NRPPa-transport message
/// (downlink procedure 5 or uplink procedure 47).
pub fn parse_non_ue_associated_nrppa_transport(
    pdu: &NgapPdu,
) -> PerResult<NonUeAssociatedNrppaTransport> {
    let container = match pdu {
        NgapPdu::InitiatingMessage(m) => match &m.value {
            InitiatingMessageValue::DownlinkNonUeAssociatedNrppaTransport(c)
            | InitiatingMessageValue::UplinkNonUeAssociatedNrppaTransport(c) => c,
            _ => {
                return Err(PerError::DecodeError(
                    "PDU is not a non-UE-associated NRPPa-transport message".to_string(),
                ))
            }
        },
        _ => {
            return Err(PerError::DecodeError(
                "PDU is not an initiating message".to_string(),
            ))
        }
    };
    parse_non_ue_associated_container(container)
}

#[cfg(test)]
mod nrppa_transport_tests {
    use super::*;

    fn encode(pdu: &NgapPdu) -> Vec<u8> {
        let mut encoder = AperEncoder::new();
        pdu.encode_aper(&mut encoder).unwrap();
        encoder.align();
        encoder.into_bytes().to_vec()
    }

    fn decode(bytes: &[u8]) -> NgapPdu {
        let mut decoder = AperDecoder::new(bytes);
        NgapPdu::decode_aper(&mut decoder).unwrap()
    }

    #[test]
    fn test_downlink_ue_associated_roundtrip() {
        let pdu = build_downlink_ue_associated_nrppa_transport(
            AmfUeNgapId(0x0102030405),
            RanUeNgapId(0xDEADBEEF),
            RoutingId(vec![0xAB, 0xCD]),
            NrppaPdu(vec![0x00, 0x04, 0x40, 0x00]),
        )
        .unwrap();
        let decoded = decode(&encode(&pdu));
        assert_eq!(decoded, pdu);

        let parsed = parse_ue_associated_nrppa_transport(&decoded).unwrap();
        assert_eq!(parsed.amf_ue_ngap_id, AmfUeNgapId(0x0102030405));
        assert_eq!(parsed.ran_ue_ngap_id, RanUeNgapId(0xDEADBEEF));
        assert_eq!(parsed.routing_id, RoutingId(vec![0xAB, 0xCD]));
        assert_eq!(parsed.nrppa_pdu, NrppaPdu(vec![0x00, 0x04, 0x40, 0x00]));
    }

    #[test]
    fn test_uplink_ue_associated_roundtrip() {
        let pdu = build_uplink_ue_associated_nrppa_transport(
            AmfUeNgapId(7),
            RanUeNgapId(9),
            RoutingId(vec![0x01]),
            NrppaPdu(vec![0xDE, 0xAD]),
        )
        .unwrap();
        let decoded = decode(&encode(&pdu));
        assert_eq!(decoded, pdu);
        let parsed = parse_ue_associated_nrppa_transport(&decoded).unwrap();
        assert_eq!(parsed.nrppa_pdu, NrppaPdu(vec![0xDE, 0xAD]));
        match &decoded {
            NgapPdu::InitiatingMessage(m) => {
                assert_eq!(
                    m.procedure_code,
                    ProcedureCode::UPLINK_UE_ASSOCIATED_NRPPA_TRANSPORT
                );
                assert_eq!(m.criticality, Criticality::Ignore);
            }
            _ => panic!("expected initiating message"),
        }
    }

    #[test]
    fn test_downlink_non_ue_associated_roundtrip() {
        let pdu = build_downlink_non_ue_associated_nrppa_transport(
            RoutingId(vec![0x10, 0x20, 0x30]),
            NrppaPdu(vec![0x00, 0x10, 0x00]),
        )
        .unwrap();
        let decoded = decode(&encode(&pdu));
        assert_eq!(decoded, pdu);
        let parsed = parse_non_ue_associated_nrppa_transport(&decoded).unwrap();
        assert_eq!(parsed.routing_id, RoutingId(vec![0x10, 0x20, 0x30]));
        assert_eq!(parsed.nrppa_pdu, NrppaPdu(vec![0x00, 0x10, 0x00]));
    }

    #[test]
    fn test_uplink_non_ue_associated_roundtrip() {
        let pdu = build_uplink_non_ue_associated_nrppa_transport(
            RoutingId(vec![0xFF]),
            NrppaPdu(vec![0x01, 0x02, 0x03, 0x04, 0x05]),
        )
        .unwrap();
        let decoded = decode(&encode(&pdu));
        assert_eq!(decoded, pdu);
        let parsed = parse_non_ue_associated_nrppa_transport(&decoded).unwrap();
        assert_eq!(
            parsed.nrppa_pdu,
            NrppaPdu(vec![0x01, 0x02, 0x03, 0x04, 0x05])
        );
        match &decoded {
            NgapPdu::InitiatingMessage(m) => assert_eq!(
                m.procedure_code,
                ProcedureCode::UPLINK_NON_UE_ASSOCIATED_NRPPA_TRANSPORT
            ),
            _ => panic!("expected initiating message"),
        }
    }

    /// Self-derived reference-hex for a minimal DownlinkUEAssociatedNRPPaTransport.
    ///
    /// No golden NGAP capture is in-repo and there is no network egress, so this
    /// vector is hand-derived from X.691 (APER) + TS 38.413 and is
    /// self-attesting. The message is:
    ///
    ///   NGAP-PDU = initiatingMessage (CHOICE index 0)
    ///   InitiatingMessage {
    ///     procedureCode = 8 (id-DownlinkUEAssociatedNRPPaTransport)
    ///     criticality   = ignore (1)
    ///     value (OPEN TYPE) = DownlinkUEAssociatedNRPPaTransport {
    ///       protocolIEs (4 IEs):
    ///         { id 10 (AMF-UE-NGAP-ID),  reject, value = 1   (40-bit int) }
    ///         { id 85 (RAN-UE-NGAP-ID),  reject, value = 1   (32-bit int) }
    ///         { id 89 (RoutingID),       reject, value = 'AA'O (1 octet) }
    ///         { id 46 (NRPPa-PDU),       reject, value = 'BB'O (1 octet) }
    ///     }
    ///   }
    ///
    /// Bit-level derivation (each group annotated):
    ///   OUTER:
    ///     byte0 = 0x00 : NGAP-PDU CHOICE = ext-bit 0 + index 00 (extensible, 3
    ///                    alts -> 2-bit index) = `000`, then procedureCode is a
    ///                    range-256 constrained int so it octet-aligns -> 5 pad.
    ///     byte1 = 0x08 : procedureCode = 8 (one aligned octet).
    ///     byte2 = 0x40 : criticality = ignore = `01` (non-ext ENUM 0..2, 2 bits)
    ///                    + 6 pad before the octet-aligned open-type length.
    ///     byte3 = 0x1A : open-type length determinant = 26 octets (the value).
    ///   INNER message value (26 octets):
    ///     b0  = 0x00 : SEQUENCE extension marker 0, then the IE-container length
    ///                  octet-aligns -> 7 pad bits.
    ///     b1 b2 = 0x00 0x04 : ProtocolIE-Container length = 4 (range 0..65535 ->
    ///                  2 aligned octets).
    ///     IE#1 (AMF-UE-NGAP-ID):
    ///       b3 b4 = 0x00 0x0A : id = 10 (range 0..65535 -> 2 aligned octets).
    ///       b5    = 0x00      : criticality reject = `00` + 6 pad before length.
    ///       b6    = 0x06      : open-type length = 6.
    ///       b7..b12 (6 octets) : AMF-UE-NGAP-ID = 1, INTEGER(0..2^40-1) is a
    ///                  >64K constrained int -> length-of-length: num_octets = 1
    ///                  -> `000`(3 bits len) + align + one value octet 0x01.
    ///                  b7 = 0x00 (len 1 in 3 bits + 5 pad), b8 = 0x01 (value),
    ///                  ...the encoder emits exactly these 6 open-type octets.
    ///     IE#2 (RAN-UE-NGAP-ID): id 85, reject, INTEGER(0..2^32-1) value 1.
    ///     IE#3 (RoutingID):      id 89, reject, OCTET STRING 0xAA.
    ///     IE#4 (NRPPa-PDU):      id 46, reject, OCTET STRING 0xBB.
    ///
    /// Rather than transcribe every inner octet by hand (the >64K integer
    /// length-of-length is fiddly), the test pins the byte-aligned OUTER framing
    /// (procedureCode / criticality / open-type length) and proves the rest via
    /// the encode==reference / decode(reference)==value round-trip below.
    #[test]
    fn test_downlink_ue_associated_reference_hex() {
        let pdu = build_downlink_ue_associated_nrppa_transport(
            AmfUeNgapId(1),
            RanUeNgapId(1),
            RoutingId(vec![0xAA]),
            NrppaPdu(vec![0xBB]),
        )
        .unwrap();
        let bytes = encode(&pdu);

        // OUTER framing (byte-aligned, hand-derived).
        assert_eq!(
            bytes[0], 0x00,
            "CHOICE initiatingMessage + procCode align pad"
        );
        assert_eq!(bytes[1], 0x08, "procedureCode = 8");
        assert_eq!(bytes[2], 0x40, "criticality ignore (01) + pad");
        // bytes[3] is the open-type length determinant for the message value.
        assert!(bytes[3] < 0x80, "open-type length is the short form");

        // Full round-trip: the hand-built PDU must decode back identically and
        // the typed IEs must survive.
        let decoded = decode(&bytes);
        assert_eq!(decoded, pdu);
        let parsed = parse_ue_associated_nrppa_transport(&decoded).unwrap();
        assert_eq!(parsed.amf_ue_ngap_id, AmfUeNgapId(1));
        assert_eq!(parsed.ran_ue_ngap_id, RanUeNgapId(1));
        assert_eq!(parsed.routing_id, RoutingId(vec![0xAA]));
        assert_eq!(parsed.nrppa_pdu, NrppaPdu(vec![0xBB]));
    }

    /// NO-REGRESSION proof: the 4 NRPPa procedure codes are ADDITIVE — they no
    /// longer fall through to `Other`, but every OTHER procedure code still
    /// does, so existing message decoding is unchanged.
    #[test]
    fn test_unrelated_procedure_still_other() {
        // Build a minimal container and wrap it as PAGING (proc 24), which has
        // no typed variant; it must still decode as `Other`.
        let mut container = ProtocolIeContainer::new();
        container.push(
            ie(
                ProtocolIeId::NRPPA_PDU,
                Criticality::Reject,
                &NrppaPdu(vec![0x01]),
            )
            .unwrap(),
        );
        let pdu = NgapPdu::InitiatingMessage(InitiatingMessage {
            procedure_code: ProcedureCode::PAGING,
            criticality: Criticality::Ignore,
            value: InitiatingMessageValue::Other(container),
        });
        let decoded = decode(&encode(&pdu));
        match decoded {
            NgapPdu::InitiatingMessage(m) => {
                assert!(matches!(m.value, InitiatingMessageValue::Other(_)));
            }
            _ => panic!("expected initiating message"),
        }
    }
}
