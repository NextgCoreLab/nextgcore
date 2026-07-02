//! NRPPa Basic Types
//!
//! Basic types from NRPPA-CommonDataTypes and NRPPA-Constants (3GPP TS 38.455).
//!
//! These mirror the NGAP common-data-types layout (per-type `CONSTRAINT` const
//! plus hand-written `AperEncode`/`AperDecode`) with one structural divergence:
//! NRPPa additionally defines `NRPPATransactionID ::= INTEGER (0..32767)`, a
//! 15-bit constrained whole number carried in every message header between
//! `criticality` and the open-type `value`.

use crate::per::{AperDecode, AperDecoder, AperEncode, AperEncoder, Constraint, PerResult};

// TRP-related size bounds (TS 38.455 §9.4 / NRPPA-Constants).
/// maxnoTRPs — upper bound of TRP lists and the TRP-ID root range.
pub const MAX_NO_TRPS: usize = 65535;
/// maxnoTRPInfoTypes — upper bound of TRP information-type lists.
pub const MAX_NO_TRP_INFO_TYPES: usize = 64;

/// Criticality - indicates how to handle unrecognized IEs
/// ASN.1 (TS 38.455 §9.3.6): Criticality ::= ENUMERATED { reject, ignore, notify }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Criticality {
    Reject = 0,
    Ignore = 1,
    Notify = 2,
}

impl Criticality {
    pub const CONSTRAINT: Constraint = Constraint::new(0, 2);
}

impl AperEncode for Criticality {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_enumerated(*self as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for Criticality {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let value = decoder.decode_enumerated(&Self::CONSTRAINT)?;
        match value {
            0 => Ok(Criticality::Reject),
            1 => Ok(Criticality::Ignore),
            2 => Ok(Criticality::Notify),
            _ => Err(crate::per::PerError::DecodeError(format!(
                "Invalid Criticality value: {value}"
            ))),
        }
    }
}

/// ProcedureCode - identifies the NRPPa elementary procedure
/// ASN.1 (TS 38.455 §9.3.6): ProcedureCode ::= INTEGER (0..255)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcedureCode(pub u8);

impl ProcedureCode {
    pub const CONSTRAINT: Constraint = Constraint::new(0, 255);

    // Procedure-code constants from TS 38.455 §9.4 (NRPPA-Constants L19651+)
    pub const ERROR_INDICATION: Self = Self(0);
    pub const PRIVATE_MESSAGE: Self = Self(1);
    pub const E_CID_MEASUREMENT_INITIATION: Self = Self(2);
    pub const E_CID_MEASUREMENT_FAILURE_INDICATION: Self = Self(3);
    pub const E_CID_MEASUREMENT_REPORT: Self = Self(4);
    pub const E_CID_MEASUREMENT_TERMINATION: Self = Self(5);
    pub const OTDOA_INFORMATION_EXCHANGE: Self = Self(6);
    pub const ASSISTANCE_INFORMATION_CONTROL: Self = Self(7);
    pub const ASSISTANCE_INFORMATION_FEEDBACK: Self = Self(8);
    pub const POSITIONING_INFORMATION_EXCHANGE: Self = Self(9);
    pub const POSITIONING_INFORMATION_UPDATE: Self = Self(10);
    pub const MEASUREMENT: Self = Self(11);
    pub const MEASUREMENT_REPORT: Self = Self(12);
    pub const MEASUREMENT_UPDATE: Self = Self(13);
    pub const MEASUREMENT_ABORT: Self = Self(14);
    pub const MEASUREMENT_FAILURE_INDICATION: Self = Self(15);
    pub const TRP_INFORMATION_EXCHANGE: Self = Self(16);
    pub const POSITIONING_ACTIVATION: Self = Self(17);
    pub const POSITIONING_DEACTIVATION: Self = Self(18);
    pub const PRS_CONFIGURATION_EXCHANGE: Self = Self(19);
    pub const MEASUREMENT_PRECONFIGURATION: Self = Self(20);
    pub const MEASUREMENT_ACTIVATION: Self = Self(21);
    pub const SRS_INFORMATION_RESERVATION_NOTIFICATION: Self = Self(22);
    pub const POSITIONING_DATA_COLLECTION_REPORT: Self = Self(23);
}

impl AperEncode for ProcedureCode {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_constrained_whole_number(self.0 as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for ProcedureCode {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let value = decoder.decode_constrained_whole_number(&Self::CONSTRAINT)?;
        Ok(ProcedureCode(value as u8))
    }
}

/// ProtocolIE-ID - identifies an NRPPa Information Element
/// ASN.1 (TS 38.455 §9.3.6): ProtocolIE-ID ::= INTEGER (0..maxProtocolIEs=65535)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtocolIeId(pub u16);

impl ProtocolIeId {
    pub const CONSTRAINT: Constraint = Constraint::new(0, 65535);

    // IE-ID constants from TS 38.455 §9.4 (NRPPA-Constants L19843+).
    // Only the E-CID-relevant subset is typed in this v1; everything else is
    // still carried as an opaque ProtocolIE-Field.
    pub const CAUSE: Self = Self(0);
    pub const CRITICALITY_DIAGNOSTICS: Self = Self(1);
    pub const LMF_UE_MEASUREMENT_ID: Self = Self(2);
    pub const REPORT_CHARACTERISTICS: Self = Self(3);
    pub const MEASUREMENT_PERIODICITY: Self = Self(4);
    pub const MEASUREMENT_QUANTITIES: Self = Self(5);
    pub const RAN_UE_MEASUREMENT_ID: Self = Self(6);
    pub const E_CID_MEASUREMENT_RESULT: Self = Self(7);
    pub const MEASUREMENT_QUANTITIES_ITEM: Self = Self(11);
    pub const CELL_PORTION_ID: Self = Self(14);
    pub const OTHER_RAT_MEASUREMENT_QUANTITIES: Self = Self(15);
    pub const OTHER_RAT_MEASUREMENT_RESULT: Self = Self(17);
    pub const WLAN_MEASUREMENT_QUANTITIES: Self = Self(19);
    pub const WLAN_MEASUREMENT_RESULT: Self = Self(21);
    // TRP Information Exchange (TS 38.455 §9.4).
    pub const TRP_INFORMATION_TYPE_LIST_TRP_REQ: Self = Self(29);
    pub const TRP_INFORMATION_LIST_TRP_RESP: Self = Self(30);
    pub const TRP_LIST: Self = Self(47);
    pub const TRP_INFORMATION_TYPE_ITEM: Self = Self(57);
    pub const CGI_NR: Self = Self(58);
    pub const NR_PCI: Self = Self(155);
}

impl AperEncode for ProtocolIeId {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_constrained_whole_number(self.0 as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for ProtocolIeId {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let value = decoder.decode_constrained_whole_number(&Self::CONSTRAINT)?;
        Ok(ProtocolIeId(value as u16))
    }
}

/// NRPPATransactionID - transaction identifier present in every NRPPa message
/// header (the structural divergence from NGAP).
/// ASN.1 (TS 38.455 §9.3.6): NRPPATransactionID ::= INTEGER (0..32767)
///
/// Encoded as a 15-bit constrained whole number; because the range (32768) is
/// `<= 65536`, APER octet-aligns and writes it as two octets (X.691 §13.2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NrppaTransactionId(pub u16);

impl NrppaTransactionId {
    pub const CONSTRAINT: Constraint = Constraint::new(0, 32767);
}

impl AperEncode for NrppaTransactionId {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_constrained_whole_number(self.0 as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for NrppaTransactionId {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let value = decoder.decode_constrained_whole_number(&Self::CONSTRAINT)?;
        Ok(NrppaTransactionId(value as u16))
    }
}

/// TriggeringMessage - used by CriticalityDiagnostics
/// ASN.1: TriggeringMessage ::= ENUMERATED { initiating-message, successful-outcome, unsuccessful-outcome }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TriggeringMessage {
    InitiatingMessage = 0,
    SuccessfulOutcome = 1,
    UnsuccessfulOutcome = 2,
}

impl TriggeringMessage {
    pub const CONSTRAINT: Constraint = Constraint::new(0, 2);
}

impl AperEncode for TriggeringMessage {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_enumerated(*self as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for TriggeringMessage {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let value = decoder.decode_enumerated(&Self::CONSTRAINT)?;
        match value {
            0 => Ok(TriggeringMessage::InitiatingMessage),
            1 => Ok(TriggeringMessage::SuccessfulOutcome),
            2 => Ok(TriggeringMessage::UnsuccessfulOutcome),
            _ => Err(crate::per::PerError::DecodeError(format!(
                "Invalid TriggeringMessage value: {value}"
            ))),
        }
    }
}

/// Presence - declared presence of an IE in a procedure
/// ASN.1: Presence ::= ENUMERATED { optional, conditional, mandatory }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Presence {
    Optional = 0,
    Conditional = 1,
    Mandatory = 2,
}

impl Presence {
    pub const CONSTRAINT: Constraint = Constraint::new(0, 2);
}

impl AperEncode for Presence {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_enumerated(*self as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for Presence {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let value = decoder.decode_enumerated(&Self::CONSTRAINT)?;
        match value {
            0 => Ok(Presence::Optional),
            1 => Ok(Presence::Conditional),
            2 => Ok(Presence::Mandatory),
            _ => Err(crate::per::PerError::DecodeError(format!(
                "Invalid Presence value: {value}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nrppa_transaction_id_roundtrip() {
        for v in [0u16, 1, 255, 256, 32767] {
            let id = NrppaTransactionId(v);
            let mut encoder = AperEncoder::new();
            id.encode_aper(&mut encoder).unwrap();
            encoder.align();
            let bytes = encoder.into_bytes();
            let mut decoder = AperDecoder::new(&bytes);
            assert_eq!(NrppaTransactionId::decode_aper(&mut decoder).unwrap(), id);
        }
    }

    #[test]
    fn test_nrppa_transaction_id_is_two_octets_aligned() {
        // Range 32768 (<= 65536) -> APER octet-aligns and emits exactly 2 octets.
        let mut encoder = AperEncoder::new();
        NrppaTransactionId(0x0102)
            .encode_aper(&mut encoder)
            .unwrap();
        encoder.align();
        assert_eq!(encoder.into_bytes().as_ref(), &[0x01, 0x02]);
    }

    #[test]
    fn test_procedure_code_roundtrip() {
        let pc = ProcedureCode::E_CID_MEASUREMENT_REPORT;
        let mut encoder = AperEncoder::new();
        pc.encode_aper(&mut encoder).unwrap();
        encoder.align();
        let bytes = encoder.into_bytes();
        let mut decoder = AperDecoder::new(&bytes);
        assert_eq!(ProcedureCode::decode_aper(&mut decoder).unwrap(), pc);
    }
}
