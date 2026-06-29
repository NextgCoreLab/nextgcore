//! NRPPa PDU types
//!
//! Top-level PDU structures from NRPPA-PDU-Descriptions (3GPP TS 38.455 §9.3.3,
//! ASN.1 L10352+) plus the E-CID procedure builders/parser.
//!
//! KEY DIVERGENCE from NGAP: each NRPPa InitiatingMessage / SuccessfulOutcome /
//! UnsuccessfulOutcome SEQUENCE carries FOUR root fields —
//! `procedureCode, criticality, nrppatransactionID, value` — versus NGAP's
//! three. The 15-bit `NRPPATransactionID` is encoded between `criticality` and
//! the open-type `value`.

use bytes::Bytes;

use super::ies::{
    CellPortionId, ECidMeasurementResult, MeasurementPeriodicity, MeasurementQuantities,
    ProtocolIeContainer, ProtocolIeField, ReportCharacteristics, UeMeasurementId,
};
use super::trp::{TrpId, TrpInformation, TrpInformationListTrpResp, TrpInformationTypeListTrpReq, TrpInformationTypeItem, TrpItem, TrpList};
use super::types::{Criticality, NrppaTransactionId, ProcedureCode, ProtocolIeId};
use crate::per::{AperDecode, AperDecoder, AperEncode, AperEncoder, PerError, PerResult};

// ---------------------------------------------------------------------------
// Open-type / message-value framing (mirrors ngap/pdu.rs)
// ---------------------------------------------------------------------------

/// Read the OPEN TYPE value of a PDU wrapper, reassembling fragmented lengths
/// per X.691 §11.9.3.
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

/// Encode the body of an NRPPa elementary-procedure message value.
///
/// Every NRPPa message is an extensible SEQUENCE
/// `{ protocolIEs ProtocolIE-Container {...}, ... }`. Per X.691 the extensible
/// SEQUENCE prepends a single extension-marker bit (0 = no extension present)
/// before its root field — the IE container. The open-type framing then
/// octet-aligns the content.
fn encode_message_value<F>(encode_ies: F) -> PerResult<Vec<u8>>
where
    F: FnOnce(&mut AperEncoder) -> PerResult<()>,
{
    let mut value_encoder = AperEncoder::new();
    value_encoder.write_bit(false); // SEQUENCE extension marker: none present
    encode_ies(&mut value_encoder)?;
    value_encoder.align();
    Ok(value_encoder.into_bytes().to_vec())
}

/// Decode the body of an NRPPa elementary-procedure message value, consuming the
/// extensible-SEQUENCE extension-marker bit before the IE container.
fn decode_message_container(value_bytes: &[u8]) -> PerResult<ProtocolIeContainer> {
    let mut value_decoder = AperDecoder::new(value_bytes);
    let _ext = value_decoder.read_bit()?;
    ProtocolIeContainer::decode_aper(&mut value_decoder)
}

// ---------------------------------------------------------------------------
// NRPPA-PDU
// ---------------------------------------------------------------------------

/// NRPPA-PDU ::= CHOICE { initiatingMessage, successfulOutcome,
///        unsuccessfulOutcome, ... }
#[derive(Debug, Clone, PartialEq)]
pub enum NrppaPdu {
    InitiatingMessage(InitiatingMessage),
    SuccessfulOutcome(SuccessfulOutcome),
    UnsuccessfulOutcome(UnsuccessfulOutcome),
}

impl NrppaPdu {
    pub const NUM_ALTERNATIVES: usize = 3;
    pub const EXTENSIBLE: bool = true;

    /// Encode this PDU to octet-aligned APER bytes.
    pub fn encode(&self) -> PerResult<Bytes> {
        let mut encoder = AperEncoder::new();
        self.encode_aper(&mut encoder)?;
        encoder.align();
        Ok(encoder.into_bytes())
    }

    /// Decode an NRPPa PDU from APER bytes.
    pub fn decode(bytes: &[u8]) -> PerResult<Self> {
        let mut decoder = AperDecoder::new(bytes);
        Self::decode_aper(&mut decoder)
    }
}

impl AperEncode for NrppaPdu {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        match self {
            NrppaPdu::InitiatingMessage(msg) => {
                encoder.encode_choice_index(0, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                msg.encode_aper(encoder)
            }
            NrppaPdu::SuccessfulOutcome(msg) => {
                encoder.encode_choice_index(1, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                msg.encode_aper(encoder)
            }
            NrppaPdu::UnsuccessfulOutcome(msg) => {
                encoder.encode_choice_index(2, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                msg.encode_aper(encoder)
            }
        }
    }
}

impl AperDecode for NrppaPdu {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let index = decoder.decode_choice_index(Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
        match index {
            0 => Ok(NrppaPdu::InitiatingMessage(InitiatingMessage::decode_aper(
                decoder,
            )?)),
            1 => Ok(NrppaPdu::SuccessfulOutcome(SuccessfulOutcome::decode_aper(
                decoder,
            )?)),
            2 => Ok(NrppaPdu::UnsuccessfulOutcome(
                UnsuccessfulOutcome::decode_aper(decoder)?,
            )),
            _ => Err(PerError::InvalidChoiceIndex {
                index,
                max: Self::NUM_ALTERNATIVES - 1,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// InitiatingMessage
// ---------------------------------------------------------------------------

/// InitiatingMessage ::= SEQUENCE { procedureCode, criticality,
///        nrppatransactionID, value }
#[derive(Debug, Clone, PartialEq)]
pub struct InitiatingMessage {
    pub procedure_code: ProcedureCode,
    pub criticality: Criticality,
    pub nrppa_transaction_id: NrppaTransactionId,
    pub value: InitiatingMessageValue,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InitiatingMessageValue {
    ECidMeasurementInitiationRequest(ProtocolIeContainer),
    ECidMeasurementFailureIndication(ProtocolIeContainer),
    ECidMeasurementReport(ProtocolIeContainer),
    ECidMeasurementTerminationCommand(ProtocolIeContainer),
    ErrorIndication(ProtocolIeContainer),
    TrpInformationRequest(ProtocolIeContainer),
    /// Any other procedure: carried as an opaque container.
    Other(ProtocolIeContainer),
}

impl InitiatingMessageValue {
    fn container(&self) -> &ProtocolIeContainer {
        match self {
            InitiatingMessageValue::ECidMeasurementInitiationRequest(c)
            | InitiatingMessageValue::ECidMeasurementFailureIndication(c)
            | InitiatingMessageValue::ECidMeasurementReport(c)
            | InitiatingMessageValue::ECidMeasurementTerminationCommand(c)
            | InitiatingMessageValue::ErrorIndication(c)
            | InitiatingMessageValue::TrpInformationRequest(c)
            | InitiatingMessageValue::Other(c) => c,
        }
    }
}

impl AperEncode for InitiatingMessage {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        // InitiatingMessage SEQUENCE has no extension marker in its root.
        self.procedure_code.encode_aper(encoder)?;
        self.criticality.encode_aper(encoder)?;
        // *** Divergence from NGAP: transaction ID between criticality and value.
        self.nrppa_transaction_id.encode_aper(encoder)?;

        let value_bytes = encode_message_value(|enc| self.value.container().encode_aper(enc))?;
        encoder.encode_fragmented_octets(&value_bytes)?;
        Ok(())
    }
}

impl AperDecode for InitiatingMessage {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let procedure_code = ProcedureCode::decode_aper(decoder)?;
        let criticality = Criticality::decode_aper(decoder)?;
        let nrppa_transaction_id = NrppaTransactionId::decode_aper(decoder)?;

        let value_bytes = read_open_type_value(decoder)?;
        let ies = decode_message_container(&value_bytes)?;

        let value = match procedure_code {
            ProcedureCode::E_CID_MEASUREMENT_INITIATION => {
                InitiatingMessageValue::ECidMeasurementInitiationRequest(ies)
            }
            ProcedureCode::E_CID_MEASUREMENT_FAILURE_INDICATION => {
                InitiatingMessageValue::ECidMeasurementFailureIndication(ies)
            }
            ProcedureCode::E_CID_MEASUREMENT_REPORT => {
                InitiatingMessageValue::ECidMeasurementReport(ies)
            }
            ProcedureCode::E_CID_MEASUREMENT_TERMINATION => {
                InitiatingMessageValue::ECidMeasurementTerminationCommand(ies)
            }
            ProcedureCode::ERROR_INDICATION => InitiatingMessageValue::ErrorIndication(ies),
            ProcedureCode::TRP_INFORMATION_EXCHANGE => {
                InitiatingMessageValue::TrpInformationRequest(ies)
            }
            _ => InitiatingMessageValue::Other(ies),
        };

        Ok(InitiatingMessage {
            procedure_code,
            criticality,
            nrppa_transaction_id,
            value,
        })
    }
}

// ---------------------------------------------------------------------------
// SuccessfulOutcome
// ---------------------------------------------------------------------------

/// SuccessfulOutcome ::= SEQUENCE { procedureCode, criticality,
///        nrppatransactionID, value }
#[derive(Debug, Clone, PartialEq)]
pub struct SuccessfulOutcome {
    pub procedure_code: ProcedureCode,
    pub criticality: Criticality,
    pub nrppa_transaction_id: NrppaTransactionId,
    pub value: SuccessfulOutcomeValue,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SuccessfulOutcomeValue {
    ECidMeasurementInitiationResponse(ProtocolIeContainer),
    TrpInformationResponse(ProtocolIeContainer),
    Other(ProtocolIeContainer),
}

impl SuccessfulOutcomeValue {
    fn container(&self) -> &ProtocolIeContainer {
        match self {
            SuccessfulOutcomeValue::ECidMeasurementInitiationResponse(c)
            | SuccessfulOutcomeValue::TrpInformationResponse(c)
            | SuccessfulOutcomeValue::Other(c) => c,
        }
    }
}

impl AperEncode for SuccessfulOutcome {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        self.procedure_code.encode_aper(encoder)?;
        self.criticality.encode_aper(encoder)?;
        self.nrppa_transaction_id.encode_aper(encoder)?;

        let value_bytes = encode_message_value(|enc| self.value.container().encode_aper(enc))?;
        encoder.encode_fragmented_octets(&value_bytes)?;
        Ok(())
    }
}

impl AperDecode for SuccessfulOutcome {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let procedure_code = ProcedureCode::decode_aper(decoder)?;
        let criticality = Criticality::decode_aper(decoder)?;
        let nrppa_transaction_id = NrppaTransactionId::decode_aper(decoder)?;

        let value_bytes = read_open_type_value(decoder)?;
        let ies = decode_message_container(&value_bytes)?;

        let value = match procedure_code {
            ProcedureCode::E_CID_MEASUREMENT_INITIATION => {
                SuccessfulOutcomeValue::ECidMeasurementInitiationResponse(ies)
            }
            ProcedureCode::TRP_INFORMATION_EXCHANGE => {
                SuccessfulOutcomeValue::TrpInformationResponse(ies)
            }
            _ => SuccessfulOutcomeValue::Other(ies),
        };

        Ok(SuccessfulOutcome {
            procedure_code,
            criticality,
            nrppa_transaction_id,
            value,
        })
    }
}

// ---------------------------------------------------------------------------
// UnsuccessfulOutcome
// ---------------------------------------------------------------------------

/// UnsuccessfulOutcome ::= SEQUENCE { procedureCode, criticality,
///        nrppatransactionID, value }
#[derive(Debug, Clone, PartialEq)]
pub struct UnsuccessfulOutcome {
    pub procedure_code: ProcedureCode,
    pub criticality: Criticality,
    pub nrppa_transaction_id: NrppaTransactionId,
    pub value: UnsuccessfulOutcomeValue,
}

#[derive(Debug, Clone, PartialEq)]
pub enum UnsuccessfulOutcomeValue {
    ECidMeasurementInitiationFailure(ProtocolIeContainer),
    TrpInformationFailure(ProtocolIeContainer),
    Other(ProtocolIeContainer),
}

impl UnsuccessfulOutcomeValue {
    fn container(&self) -> &ProtocolIeContainer {
        match self {
            UnsuccessfulOutcomeValue::ECidMeasurementInitiationFailure(c)
            | UnsuccessfulOutcomeValue::TrpInformationFailure(c)
            | UnsuccessfulOutcomeValue::Other(c) => c,
        }
    }
}

impl AperEncode for UnsuccessfulOutcome {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        self.procedure_code.encode_aper(encoder)?;
        self.criticality.encode_aper(encoder)?;
        self.nrppa_transaction_id.encode_aper(encoder)?;

        let value_bytes = encode_message_value(|enc| self.value.container().encode_aper(enc))?;
        encoder.encode_fragmented_octets(&value_bytes)?;
        Ok(())
    }
}

impl AperDecode for UnsuccessfulOutcome {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let procedure_code = ProcedureCode::decode_aper(decoder)?;
        let criticality = Criticality::decode_aper(decoder)?;
        let nrppa_transaction_id = NrppaTransactionId::decode_aper(decoder)?;

        let value_bytes = read_open_type_value(decoder)?;
        let ies = decode_message_container(&value_bytes)?;

        let value = match procedure_code {
            ProcedureCode::E_CID_MEASUREMENT_INITIATION => {
                UnsuccessfulOutcomeValue::ECidMeasurementInitiationFailure(ies)
            }
            ProcedureCode::TRP_INFORMATION_EXCHANGE => {
                UnsuccessfulOutcomeValue::TrpInformationFailure(ies)
            }
            _ => UnsuccessfulOutcomeValue::Other(ies),
        };

        Ok(UnsuccessfulOutcome {
            procedure_code,
            criticality,
            nrppa_transaction_id,
            value,
        })
    }
}

// ---------------------------------------------------------------------------
// Typed IE encode/decode helpers
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

fn ie<T: AperEncode>(id: ProtocolIeId, criticality: Criticality, value: &T) -> PerResult<ProtocolIeField> {
    Ok(ProtocolIeField {
        id,
        criticality,
        value: encode_ie_value(value)?,
    })
}

// ---------------------------------------------------------------------------
// E-CID procedure builders / parser
// ---------------------------------------------------------------------------

/// Build an `E-CIDMeasurementInitiationRequest` (procedure code 2,
/// initiating message), per TS 38.455 §9.3.5 (ASN.1 L11357+).
pub fn build_ecid_measurement_initiation_request(
    nrppa_transaction_id: NrppaTransactionId,
    lmf_ue_measurement_id: UeMeasurementId,
    report_characteristics: ReportCharacteristics,
    measurement_periodicity: Option<MeasurementPeriodicity>,
    measurement_quantities: &MeasurementQuantities,
) -> PerResult<NrppaPdu> {
    let mut container = ProtocolIeContainer::new();
    container.push(ie(
        ProtocolIeId::LMF_UE_MEASUREMENT_ID,
        Criticality::Reject,
        &lmf_ue_measurement_id,
    )?);
    container.push(ie(
        ProtocolIeId::REPORT_CHARACTERISTICS,
        Criticality::Reject,
        &report_characteristics,
    )?);
    if let Some(periodicity) = measurement_periodicity {
        container.push(ie(
            ProtocolIeId::MEASUREMENT_PERIODICITY,
            Criticality::Reject,
            &periodicity,
        )?);
    }
    container.push(ie(
        ProtocolIeId::MEASUREMENT_QUANTITIES,
        Criticality::Reject,
        measurement_quantities,
    )?);

    Ok(NrppaPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::E_CID_MEASUREMENT_INITIATION,
        criticality: Criticality::Reject,
        nrppa_transaction_id,
        value: InitiatingMessageValue::ECidMeasurementInitiationRequest(container),
    }))
}

/// Build an `E-CIDMeasurementReport` (procedure code 4, initiating message),
/// per TS 38.455 §9.3.5 (ASN.1 L11522+).
pub fn build_ecid_measurement_report(
    nrppa_transaction_id: NrppaTransactionId,
    lmf_ue_measurement_id: UeMeasurementId,
    ran_ue_measurement_id: UeMeasurementId,
    e_cid_measurement_result: &ECidMeasurementResult,
    cell_portion_id: Option<CellPortionId>,
) -> PerResult<NrppaPdu> {
    let mut container = ProtocolIeContainer::new();
    container.push(ie(
        ProtocolIeId::LMF_UE_MEASUREMENT_ID,
        Criticality::Reject,
        &lmf_ue_measurement_id,
    )?);
    container.push(ie(
        ProtocolIeId::RAN_UE_MEASUREMENT_ID,
        Criticality::Reject,
        &ran_ue_measurement_id,
    )?);
    container.push(ie(
        ProtocolIeId::E_CID_MEASUREMENT_RESULT,
        Criticality::Ignore,
        e_cid_measurement_result,
    )?);
    if let Some(cpid) = cell_portion_id {
        container.push(ie(
            ProtocolIeId::CELL_PORTION_ID,
            Criticality::Ignore,
            &cpid,
        )?);
    }

    Ok(NrppaPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::E_CID_MEASUREMENT_REPORT,
        criticality: Criticality::Ignore,
        nrppa_transaction_id,
        value: InitiatingMessageValue::ECidMeasurementReport(container),
    }))
}

/// Decoded view of an `E-CIDMeasurementReport`.
#[derive(Debug, Clone, PartialEq)]
pub struct EcidMeasurementReport {
    pub nrppa_transaction_id: NrppaTransactionId,
    pub lmf_ue_measurement_id: UeMeasurementId,
    pub ran_ue_measurement_id: UeMeasurementId,
    pub e_cid_measurement_result: ECidMeasurementResult,
    pub cell_portion_id: Option<CellPortionId>,
}

/// Parse a decoded `NrppaPdu` as an `E-CIDMeasurementReport`, decoding the
/// typed mandatory/optional IEs out of the opaque container.
pub fn parse_ecid_measurement_report(pdu: &NrppaPdu) -> PerResult<EcidMeasurementReport> {
    let msg = match pdu {
        NrppaPdu::InitiatingMessage(m)
            if m.procedure_code == ProcedureCode::E_CID_MEASUREMENT_REPORT =>
        {
            m
        }
        _ => {
            return Err(PerError::DecodeError(
                "PDU is not an E-CIDMeasurementReport initiating message".to_string(),
            ))
        }
    };

    let container = match &msg.value {
        InitiatingMessageValue::ECidMeasurementReport(c) => c,
        _ => {
            return Err(PerError::DecodeError(
                "E-CIDMeasurementReport value mismatch".to_string(),
            ))
        }
    };

    let find = |id: ProtocolIeId| -> Option<&ProtocolIeField> { container.find(id) };

    let lmf = find(ProtocolIeId::LMF_UE_MEASUREMENT_ID).ok_or_else(|| {
        PerError::DecodeError("missing mandatory LMF-UE-Measurement-ID".to_string())
    })?;
    let ran = find(ProtocolIeId::RAN_UE_MEASUREMENT_ID).ok_or_else(|| {
        PerError::DecodeError("missing mandatory RAN-UE-Measurement-ID".to_string())
    })?;
    let result = find(ProtocolIeId::E_CID_MEASUREMENT_RESULT).ok_or_else(|| {
        PerError::DecodeError("missing mandatory E-CID-MeasurementResult".to_string())
    })?;

    let cell_portion_id = match find(ProtocolIeId::CELL_PORTION_ID) {
        Some(field) => Some(decode_ie_value::<CellPortionId>(&field.value)?),
        None => None,
    };

    Ok(EcidMeasurementReport {
        nrppa_transaction_id: msg.nrppa_transaction_id,
        lmf_ue_measurement_id: decode_ie_value(&lmf.value)?,
        ran_ue_measurement_id: decode_ie_value(&ran.value)?,
        e_cid_measurement_result: decode_ie_value(&result.value)?,
        cell_portion_id,
    })
}

// ---------------------------------------------------------------------------
// TRP Information Exchange procedure builders / parser
// ---------------------------------------------------------------------------

/// Build a `TRPInformationRequest` (procedure code 16, initiating message),
/// per TS 38.455 §9.3.5 (ASN.1 L12272+).
///
/// `trp_list` is the OPTIONAL id-TRPList IE (criticality ignore); `info_types`
/// is the MANDATORY id-TRPInformationTypeListTRPReq IE (criticality reject).
pub fn build_trp_information_request(
    nrppa_transaction_id: NrppaTransactionId,
    trp_list: Option<Vec<TrpId>>,
    info_types: Vec<TrpInformationTypeItem>,
) -> PerResult<NrppaPdu> {
    let mut container = ProtocolIeContainer::new();
    if let Some(ids) = trp_list {
        let list = TrpList {
            items: ids.into_iter().map(|trp_id| TrpItem { trp_id }).collect(),
        };
        container.push(ie(ProtocolIeId::TRP_LIST, Criticality::Ignore, &list)?);
    }
    let info_list = TrpInformationTypeListTrpReq { items: info_types };
    container.push(ie(
        ProtocolIeId::TRP_INFORMATION_TYPE_LIST_TRP_REQ,
        Criticality::Reject,
        &info_list,
    )?);

    Ok(NrppaPdu::InitiatingMessage(InitiatingMessage {
        procedure_code: ProcedureCode::TRP_INFORMATION_EXCHANGE,
        criticality: Criticality::Reject,
        nrppa_transaction_id,
        value: InitiatingMessageValue::TrpInformationRequest(container),
    }))
}

/// Build a `TRPInformationResponse` (procedure code 16, successful outcome),
/// per TS 38.455 §9.3.5 (ASN.1 L12301+).
///
/// Carries the MANDATORY id-TRPInformationListTRPResp IE (criticality ignore);
/// the optional id-CriticalityDiagnostics IE is not emitted in v1.
pub fn build_trp_information_response(
    nrppa_transaction_id: NrppaTransactionId,
    trp_info_list: Vec<TrpInformation>,
) -> PerResult<NrppaPdu> {
    let mut container = ProtocolIeContainer::new();
    let list = TrpInformationListTrpResp {
        items: trp_info_list,
    };
    container.push(ie(
        ProtocolIeId::TRP_INFORMATION_LIST_TRP_RESP,
        Criticality::Ignore,
        &list,
    )?);

    Ok(NrppaPdu::SuccessfulOutcome(SuccessfulOutcome {
        procedure_code: ProcedureCode::TRP_INFORMATION_EXCHANGE,
        criticality: Criticality::Reject,
        nrppa_transaction_id,
        value: SuccessfulOutcomeValue::TrpInformationResponse(container),
    }))
}

/// Parse a decoded `NrppaPdu` as a `TRPInformationResponse`, decoding the typed
/// `TRPInformation` list out of the opaque container.
pub fn parse_trp_information_response(pdu: &NrppaPdu) -> PerResult<Vec<TrpInformation>> {
    let msg = match pdu {
        NrppaPdu::SuccessfulOutcome(m)
            if m.procedure_code == ProcedureCode::TRP_INFORMATION_EXCHANGE =>
        {
            m
        }
        _ => {
            return Err(PerError::DecodeError(
                "PDU is not a TRPInformationResponse successful outcome".to_string(),
            ))
        }
    };

    let container = match &msg.value {
        SuccessfulOutcomeValue::TrpInformationResponse(c) => c,
        _ => {
            return Err(PerError::DecodeError(
                "TRPInformationResponse value mismatch".to_string(),
            ))
        }
    };

    let field = container
        .find(ProtocolIeId::TRP_INFORMATION_LIST_TRP_RESP)
        .ok_or_else(|| {
            PerError::DecodeError("missing mandatory TRPInformationListTRPResp".to_string())
        })?;
    let list: TrpInformationListTrpResp = decode_ie_value(&field.value)?;
    Ok(list.items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nrppa::cause::{Cause, CauseRadioNetwork};
    use crate::nrppa::ies::{
        MeasurementQuantitiesItem, MeasurementQuantitiesValue, NgRanAccessPointPosition, NgRanCell,
        NgRanCgi, PlmnIdentity, Tac,
    };
    use crate::nrppa::trp::{
        GeographicalCoordinates, TrpId, TrpInformation, TrpInformationTypeItem,
        TrpInformationTypeListTrpReq, TrpInformationTypeResponseItem,
        TrpInformationTypeResponseList, TrpPositionDefinitionType, TrpPositionDirect,
        TrpPositionDirectAccuracy,
    };

    fn sample_result() -> ECidMeasurementResult {
        ECidMeasurementResult {
            serving_cell_id: NgRanCgi {
                plmn_identity: PlmnIdentity([0x00, 0x01, 0x02]),
                ng_ran_cell: NgRanCell::NrCellId(1),
            },
            serving_cell_tac: Tac::from_u24(1),
            ng_ran_access_point_position: None,
            measured_results: None,
        }
    }

    #[test]
    fn test_ecid_measurement_initiation_request_roundtrip() {
        let quantities = MeasurementQuantities {
            items: vec![MeasurementQuantitiesItem {
                measurement_quantities_value: MeasurementQuantitiesValue::Rsrp,
            }],
        };
        let pdu = build_ecid_measurement_initiation_request(
            NrppaTransactionId(7),
            UeMeasurementId(3),
            ReportCharacteristics::Periodic,
            Some(MeasurementPeriodicity::Ms1024),
            &quantities,
        )
        .unwrap();

        let bytes = pdu.encode().unwrap();
        let decoded = NrppaPdu::decode(&bytes).unwrap();
        assert_eq!(decoded, pdu);

        // Transaction ID survives the header round-trip.
        match &decoded {
            NrppaPdu::InitiatingMessage(m) => {
                assert_eq!(m.nrppa_transaction_id, NrppaTransactionId(7));
                assert_eq!(
                    m.procedure_code,
                    ProcedureCode::E_CID_MEASUREMENT_INITIATION
                );
            }
            _ => panic!("expected initiating message"),
        }
    }

    #[test]
    fn test_ecid_measurement_initiation_response_roundtrip() {
        // Response carries LMF + RAN measurement IDs (mandatory) and an optional
        // E-CID-MeasurementResult; the typed values ride inside the container.
        let mut container = ProtocolIeContainer::new();
        container.push(ie(
            ProtocolIeId::LMF_UE_MEASUREMENT_ID,
            Criticality::Reject,
            &UeMeasurementId(3),
        ).unwrap());
        container.push(ie(
            ProtocolIeId::RAN_UE_MEASUREMENT_ID,
            Criticality::Reject,
            &UeMeasurementId(9),
        ).unwrap());
        container.push(ie(
            ProtocolIeId::E_CID_MEASUREMENT_RESULT,
            Criticality::Ignore,
            &sample_result(),
        ).unwrap());

        let pdu = NrppaPdu::SuccessfulOutcome(SuccessfulOutcome {
            procedure_code: ProcedureCode::E_CID_MEASUREMENT_INITIATION,
            criticality: Criticality::Reject,
            nrppa_transaction_id: NrppaTransactionId(42),
            value: SuccessfulOutcomeValue::ECidMeasurementInitiationResponse(container),
        });

        let bytes = pdu.encode().unwrap();
        let decoded = NrppaPdu::decode(&bytes).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn test_ecid_measurement_initiation_failure_roundtrip() {
        let mut container = ProtocolIeContainer::new();
        container.push(ie(
            ProtocolIeId::LMF_UE_MEASUREMENT_ID,
            Criticality::Reject,
            &UeMeasurementId(3),
        ).unwrap());
        container.push(ie(
            ProtocolIeId::CAUSE,
            Criticality::Ignore,
            &Cause::RadioNetwork(CauseRadioNetwork::RequestedItemNotSupported),
        ).unwrap());

        let pdu = NrppaPdu::UnsuccessfulOutcome(UnsuccessfulOutcome {
            procedure_code: ProcedureCode::E_CID_MEASUREMENT_INITIATION,
            criticality: Criticality::Reject,
            nrppa_transaction_id: NrppaTransactionId(99),
            value: UnsuccessfulOutcomeValue::ECidMeasurementInitiationFailure(container),
        });

        let bytes = pdu.encode().unwrap();
        let decoded = NrppaPdu::decode(&bytes).unwrap();
        assert_eq!(decoded, pdu);
    }

    #[test]
    fn test_ecid_measurement_report_roundtrip_and_parse() {
        let pdu = build_ecid_measurement_report(
            NrppaTransactionId(0),
            UeMeasurementId(1),
            UeMeasurementId(1),
            &sample_result(),
            None,
        )
        .unwrap();

        let bytes = pdu.encode().unwrap();
        let decoded = NrppaPdu::decode(&bytes).unwrap();
        assert_eq!(decoded, pdu);

        let report = parse_ecid_measurement_report(&decoded).unwrap();
        assert_eq!(report.nrppa_transaction_id, NrppaTransactionId(0));
        assert_eq!(report.lmf_ue_measurement_id, UeMeasurementId(1));
        assert_eq!(report.ran_ue_measurement_id, UeMeasurementId(1));
        assert_eq!(report.e_cid_measurement_result, sample_result());
        assert_eq!(report.cell_portion_id, None);
    }

    #[test]
    fn test_ecid_measurement_report_with_cell_portion_id() {
        let pdu = build_ecid_measurement_report(
            NrppaTransactionId(5),
            UeMeasurementId(2),
            UeMeasurementId(4),
            &sample_result(),
            Some(CellPortionId(100)),
        )
        .unwrap();

        let bytes = pdu.encode().unwrap();
        let decoded = NrppaPdu::decode(&bytes).unwrap();
        let report = parse_ecid_measurement_report(&decoded).unwrap();
        assert_eq!(report.cell_portion_id, Some(CellPortionId(100)));
    }

    /// Self-derived reference-hex decode test for an E-CID Measurement Report.
    ///
    /// There is no golden NRPPa capture in-repo and no network egress, so this
    /// vector is hand-derived from X.691 (APER) + TS 38.455 and is therefore
    /// self-attesting. The message is:
    ///
    ///   NRPPA-PDU = initiatingMessage (CHOICE index 0)
    ///   InitiatingMessage {
    ///     procedureCode        = 4  (id-e-CIDMeasurementReport)
    ///     criticality          = ignore (1)
    ///     nrppatransactionID   = 0
    ///     value (OPEN TYPE) = E-CIDMeasurementReport {
    ///       protocolIEs (3 IEs):
    ///         { id 2  (LMF-UE-Measurement-ID), reject, UE-Measurement-ID = 1 }
    ///         { id 6  (RAN-UE-Measurement-ID), reject, UE-Measurement-ID = 1 }
    ///         { id 7  (E-CID-MeasurementResult), ignore, E-CID-MeasurementResult {
    ///             servingCell-ID = NG-RAN-CGI { PLMN 00 01 02, nR-CellID(BIT STRING 36)=1 },
    ///             servingCellTAC = 00 00 01,
    ///             (nG-RANAccessPointPosition / measuredResults / iE-Extensions absent) } }
    ///     }
    ///   }
    ///
    /// Bit-level derivation (each group annotated):
    ///   OUTER:
    ///     byte0 = 0x00 : NRPPA-PDU CHOICE = ext-bit 0 + index 00 (extensible,
    ///                    3 alts -> 2-bit index) = `000`, then procedureCode is a
    ///                    range-256 constrained int so it octet-aligns -> 5 pad bits.
    ///     byte1 = 0x04 : procedureCode = 4 (one aligned octet).
    ///     byte2 = 0x40 : criticality = ignore = `01` (non-ext ENUM 0..2, 2 bits)
    ///                    + 6 pad bits before the octet-aligned transactionID.
    ///     byte3 byte4 = 0x00 0x00 : nrppatransactionID = 0 (range 32768 -> 2
    ///                    octets, aligned).
    ///     byte5 = 0x1E : open-type length determinant = 30 octets (the message
    ///                    value below).
    ///   INNER message value (30 octets):
    ///     b0  = 0x00 : E-CIDMeasurementReport SEQUENCE ext-bit 0, then the IE
    ///                  container length octet-aligns -> 7 pad bits.
    ///     b1 b2 = 0x00 0x03 : ProtocolIE-Container length = 3 (range 0..65535 ->
    ///                  2 octets aligned).
    ///     IE#1 (LMF-UE-Measurement-ID):
    ///       b3 b4 = 0x00 0x02 : id = 2 (range 0..65535 -> 2 octets aligned).
    ///       b5    = 0x00      : criticality reject = `00` + 6 pad before length.
    ///       b6    = 0x01      : open-type length = 1.
    ///       b7    = 0x00      : UE-Measurement-ID = 1: ext-bit 0 + constrained
    ///                           (1..15, 4 bits) offset 0 = `0 0000` -> 0x00 padded.
    ///     IE#2 (RAN-UE-Measurement-ID):
    ///       b8 b9 = 0x00 0x06 : id = 6.
    ///       b10   = 0x00      : criticality reject + pad.
    ///       b11   = 0x01      : open-type length = 1.
    ///       b12   = 0x00      : UE-Measurement-ID = 1.
    ///     IE#3 (E-CID-MeasurementResult):
    ///       b13 b14 = 0x00 0x07 : id = 7.
    ///       b15     = 0x40      : criticality ignore = `01` + 6 pad before length.
    ///       b16     = 0x0D      : open-type length = 13 octets.
    ///       E-CID-MeasurementResult (13 octets, b17..b29):
    ///         b17 = 0x00 : ECMR SEQ ext-bit 0 + 3 optional-absent bits (000) +
    ///                      NG-RAN-CGI SEQ ext-bit 0 + iE-Ext-absent bit 0 +
    ///                      2 pad bits before the PLMN octet string.
    ///         b18 b19 b20 = 0x00 0x01 0x02 : PLMN-Identity (OCTET STRING SIZE 3).
    ///         b21 = 0x40 : NG-RANCell CHOICE index = nR-CellID = `01` (non-ext,
    ///                      3 alts, 2 bits) + 6 pad bits before the BIT STRING(36).
    ///         b22..b25 = 0x00 0x00 0x00 0x00 + high nibble of b26 : nRcellID = 1
    ///                      as 36 bits (35 zero bits then 1).
    ///         b26 = 0x10 : low nibble = `0001` (cell-id LSBs) + 4 pad bits before
    ///                      the TAC octet string.
    ///         b27 b28 b29 = 0x00 0x00 0x01 : servingCellTAC (OCTET STRING SIZE 3).
    #[test]
    fn test_ecid_measurement_report_reference_hex() {
        let reference: [u8; 36] = [
            0x00, 0x04, 0x40, 0x00, 0x00, 0x1E, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x01, 0x00,
            0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x07, 0x40, 0x0D, 0x00, 0x00, 0x01, 0x02, 0x40,
            0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x01,
        ];

        let decoded = NrppaPdu::decode(&reference).expect("reference hex must decode");
        let report = parse_ecid_measurement_report(&decoded).unwrap();

        assert_eq!(report.nrppa_transaction_id, NrppaTransactionId(0));
        assert_eq!(report.lmf_ue_measurement_id, UeMeasurementId(1));
        assert_eq!(report.ran_ue_measurement_id, UeMeasurementId(1));
        assert_eq!(
            report.e_cid_measurement_result.serving_cell_id,
            NgRanCgi {
                plmn_identity: PlmnIdentity([0x00, 0x01, 0x02]),
                ng_ran_cell: NgRanCell::NrCellId(1),
            }
        );
        assert_eq!(
            report.e_cid_measurement_result.serving_cell_tac,
            Tac([0x00, 0x00, 0x01])
        );
        assert!(report
            .e_cid_measurement_result
            .ng_ran_access_point_position
            .is_none());
        assert!(report.e_cid_measurement_result.measured_results.is_none());

        // The hand-derived vector must equal what our own encoder produces.
        let reencoded = decoded.encode().unwrap();
        assert_eq!(reencoded.as_ref(), &reference[..]);
    }

    // ---- TRP Information Exchange -------------------------------------------

    fn sample_trp_position() -> NgRanAccessPointPosition {
        NgRanAccessPointPosition {
            latitude_sign_south: false,
            latitude: 1_234_567,
            longitude: -1_000_000,
            direction_of_altitude_depth: false,
            altitude: 12_345,
            uncertainty_semi_major: 10,
            uncertainty_semi_minor: 20,
            orientation_of_major_axis: 90,
            uncertainty_altitude: 30,
            confidence: 95,
        }
    }

    #[test]
    fn test_trp_information_request_roundtrip() {
        let pdu = build_trp_information_request(
            NrppaTransactionId(7),
            Some(vec![TrpId(1), TrpId(2)]),
            vec![TrpInformationTypeItem::NrPci, TrpInformationTypeItem::GeoCoord],
        )
        .unwrap();

        let bytes = pdu.encode().unwrap();
        let decoded = NrppaPdu::decode(&bytes).unwrap();
        assert_eq!(decoded, pdu);

        match &decoded {
            NrppaPdu::InitiatingMessage(m) => {
                assert_eq!(m.procedure_code, ProcedureCode::TRP_INFORMATION_EXCHANGE);
                assert_eq!(m.nrppa_transaction_id, NrppaTransactionId(7));
                assert!(matches!(
                    m.value,
                    InitiatingMessageValue::TrpInformationRequest(_)
                ));
            }
            _ => panic!("expected initiating message"),
        }
    }

    #[test]
    fn test_trp_information_request_without_trp_list_roundtrip() {
        let pdu = build_trp_information_request(
            NrppaTransactionId(0),
            None,
            vec![TrpInformationTypeItem::NrPci],
        )
        .unwrap();
        let bytes = pdu.encode().unwrap();
        assert_eq!(NrppaPdu::decode(&bytes).unwrap(), pdu);
    }

    #[test]
    fn test_trp_information_response_roundtrip_and_parse() {
        let info = vec![
            TrpInformation {
                trp_id: TrpId(1),
                response_list: TrpInformationTypeResponseList {
                    items: vec![
                        TrpInformationTypeResponseItem::PciNr(500),
                        TrpInformationTypeResponseItem::Arfcn(640_000),
                    ],
                },
            },
            TrpInformation {
                trp_id: TrpId(2),
                response_list: TrpInformationTypeResponseList {
                    items: vec![TrpInformationTypeResponseItem::GeographicalCoordinates(
                        GeographicalCoordinates {
                            position_definition_type: TrpPositionDefinitionType::Direct(
                                TrpPositionDirect {
                                    accuracy: TrpPositionDirectAccuracy::TrpPosition(
                                        sample_trp_position(),
                                    ),
                                },
                            ),
                        },
                    )],
                },
            },
        ];

        let pdu = build_trp_information_response(NrppaTransactionId(42), info.clone()).unwrap();
        let bytes = pdu.encode().unwrap();
        let decoded = NrppaPdu::decode(&bytes).unwrap();
        assert_eq!(decoded, pdu);

        let parsed = parse_trp_information_response(&decoded).unwrap();
        assert_eq!(parsed, info);
    }

    /// Self-derived reference-hex test for a minimal TRPInformationRequest.
    ///
    /// No golden NRPPa capture exists in-repo and there is no network egress, so
    /// this vector is hand-derived from X.691 (APER) + TS 38.455 §9.3.5. The PDU:
    ///
    ///   NRPPA-PDU = initiatingMessage (CHOICE index 0)
    ///   InitiatingMessage {
    ///     procedureCode      = 16 (id-tRPInformationExchange)
    ///     criticality        = reject (0)
    ///     nrppatransactionID = 0
    ///     value (OPEN TYPE) = TRPInformationRequest {
    ///       protocolIEs (1 IE):
    ///         { id 29 (TRPInformationTypeListTRPReq), reject,
    ///           SEQUENCE(SIZE 1) OF single-container:
    ///             { id 57 (TRPInformationTypeItem), reject,
    ///               TRPInformationTypeItem = nrPCI(0) } }
    ///     }
    ///   }
    ///
    /// Bit-level derivation (each group annotated):
    ///   OUTER PDU:
    ///     byte0 = 0x00 : NRPPA-PDU CHOICE = ext-bit 0 + 2-bit index `00` = `000`,
    ///                    then procedureCode (range-256 INTEGER) octet-aligns ->
    ///                    5 pad bits.
    ///     byte1 = 0x10 : procedureCode = 16 (one aligned octet).
    ///     byte2 = 0x00 : criticality reject = `00` (2-bit ENUM 0..2) + 6 pad
    ///                    before the octet-aligned transactionID.
    ///     byte3 byte4 = 0x00 0x00 : nrppatransactionID = 0 (range 32768 -> 2
    ///                    aligned octets).
    ///     byte5 = 0x0D : open-type length determinant = 13 octets.
    ///   INNER message value (13 octets, b0..b12):
    ///     b0  = 0x00 : TRPInformationRequest SEQUENCE ext-bit 0, then the IE
    ///                  container length octet-aligns -> 7 pad bits.
    ///     b1 b2 = 0x00 0x01 : ProtocolIE-Container length = 1 (range 0..65535 ->
    ///                  2 aligned octets).
    ///     IE (TRPInformationTypeListTRPReq):
    ///       b3 b4 = 0x00 0x1D : id = 29 (range 0..65535 -> 2 aligned octets).
    ///       b5    = 0x00      : criticality reject `00` + 6 pad before length.
    ///       b6    = 0x06      : open-type length = 6 octets.
    ///       TRPInformationTypeListTRPReq value (6 octets, b7..b12):
    ///         b7  = 0x00 : SEQUENCE-OF length(1..64) = 1 -> offset 0 in 6 bits
    ///                      `000000`, then the single-container id octet-aligns ->
    ///                      2 pad bits.
    ///         b8 b9 = 0x00 0x39 : id = 57 (range 0..65535 -> 2 aligned octets).
    ///         b10 = 0x00 : criticality reject `00` + 6 pad before length.
    ///         b11 = 0x01 : open-type length = 1 octet.
    ///         b12 = 0x00 : TRPInformationTypeItem = nrPCI: ext-bit 0 + 3-bit
    ///                      root index `000` (0..7) = `0000` -> padded 0x00.
    #[test]
    fn test_trp_information_request_reference_hex() {
        let reference: [u8; 19] = [
            0x00, 0x10, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x01, 0x00, 0x1D, 0x00, 0x06, 0x00,
            0x00, 0x39, 0x00, 0x01, 0x00,
        ];

        let pdu = build_trp_information_request(
            NrppaTransactionId(0),
            None,
            vec![TrpInformationTypeItem::NrPci],
        )
        .unwrap();

        // Encode must equal the hand-derived vector...
        assert_eq!(pdu.encode().unwrap().as_ref(), &reference[..]);

        // ...and the vector must decode back to the same PDU, with the typed
        // info-type list recovered out of the opaque container.
        let decoded = NrppaPdu::decode(&reference).expect("reference hex must decode");
        assert_eq!(decoded, pdu);
        match &decoded {
            NrppaPdu::InitiatingMessage(m) => match &m.value {
                InitiatingMessageValue::TrpInformationRequest(c) => {
                    let field = c
                        .find(ProtocolIeId::TRP_INFORMATION_TYPE_LIST_TRP_REQ)
                        .unwrap();
                    let list: TrpInformationTypeListTrpReq =
                        decode_ie_value(&field.value).unwrap();
                    assert_eq!(list.items, vec![TrpInformationTypeItem::NrPci]);
                }
                _ => panic!("expected TrpInformationRequest"),
            },
            _ => panic!("expected initiating message"),
        }
    }
}
