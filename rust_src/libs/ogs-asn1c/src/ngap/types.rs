//! NGAP Basic Types
//!
//! Basic types from NGAP-CommonDataTypes (3GPP TS 38.413)

use crate::per::{AperDecode, AperDecoder, AperEncode, AperEncoder, Constraint, PerResult};

/// Criticality - indicates how to handle unrecognized IEs
/// ASN.1: Criticality ::= ENUMERATED { reject, ignore, notify }
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
            _ => Err(crate::per::PerError::DecodeError(
                format!("Invalid Criticality value: {}", value)
            )),
        }
    }
}


/// ProcedureCode - identifies the NGAP procedure
/// ASN.1: ProcedureCode ::= INTEGER (0..255)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcedureCode(pub u8);

impl ProcedureCode {
    pub const CONSTRAINT: Constraint = Constraint::new(0, 255);

    // Procedure code constants from 3GPP TS 38.413
    pub const AMF_CONFIGURATION_UPDATE: Self = Self(0);
    pub const AMF_STATUS_INDICATION: Self = Self(1);
    pub const CELL_TRAFFIC_TRACE: Self = Self(2);
    pub const DEACTIVATE_TRACE: Self = Self(3);
    pub const DOWNLINK_NAS_TRANSPORT: Self = Self(4);
    pub const DOWNLINK_NON_UE_ASSOCIATED_NRPPA_TRANSPORT: Self = Self(5);
    pub const DOWNLINK_RAN_CONFIGURATION_TRANSFER: Self = Self(6);
    pub const DOWNLINK_RAN_STATUS_TRANSFER: Self = Self(7);
    pub const DOWNLINK_UE_ASSOCIATED_NRPPA_TRANSPORT: Self = Self(8);
    pub const ERROR_INDICATION: Self = Self(9);
    pub const HANDOVER_CANCEL: Self = Self(10);
    pub const HANDOVER_NOTIFICATION: Self = Self(11);
    pub const HANDOVER_PREPARATION: Self = Self(12);
    pub const HANDOVER_RESOURCE_ALLOCATION: Self = Self(13);
    pub const INITIAL_CONTEXT_SETUP: Self = Self(14);
    pub const INITIAL_UE_MESSAGE: Self = Self(15);
    pub const LOCATION_REPORTING_CONTROL: Self = Self(16);
    pub const LOCATION_REPORTING_FAILURE_INDICATION: Self = Self(17);
    pub const LOCATION_REPORT: Self = Self(18);
    pub const NAS_NON_DELIVERY_INDICATION: Self = Self(19);
    pub const NG_RESET: Self = Self(20);
    pub const NG_SETUP: Self = Self(21);
    pub const OVERLOAD_START: Self = Self(22);
    pub const OVERLOAD_STOP: Self = Self(23);
    pub const PAGING: Self = Self(24);
    pub const PATH_SWITCH_REQUEST: Self = Self(25);
    pub const PDU_SESSION_RESOURCE_MODIFY: Self = Self(26);
    pub const PDU_SESSION_RESOURCE_MODIFY_INDICATION: Self = Self(27);
    pub const PDU_SESSION_RESOURCE_RELEASE: Self = Self(28);
    pub const PDU_SESSION_RESOURCE_SETUP: Self = Self(29);
    pub const PDU_SESSION_RESOURCE_NOTIFY: Self = Self(30);
    pub const PRIVATE_MESSAGE: Self = Self(31);
    pub const PWS_CANCEL: Self = Self(32);
    pub const PWS_FAILURE_INDICATION: Self = Self(33);
    pub const PWS_RESTART_INDICATION: Self = Self(34);
    pub const RAN_CONFIGURATION_UPDATE: Self = Self(35);
    pub const REROUTE_NAS_REQUEST: Self = Self(36);
    pub const RRC_INACTIVE_TRANSITION_REPORT: Self = Self(37);
    pub const TRACE_FAILURE_INDICATION: Self = Self(38);
    pub const TRACE_START: Self = Self(39);
    pub const UE_CONTEXT_MODIFICATION: Self = Self(40);
    pub const UE_CONTEXT_RELEASE: Self = Self(41);
    pub const UE_CONTEXT_RELEASE_REQUEST: Self = Self(42);
    pub const UE_RADIO_CAPABILITY_CHECK: Self = Self(43);
    pub const UE_RADIO_CAPABILITY_INFO_INDICATION: Self = Self(44);
    pub const UE_TNLA_BINDING_RELEASE: Self = Self(45);
    pub const UPLINK_NAS_TRANSPORT: Self = Self(46);
    pub const UPLINK_NON_UE_ASSOCIATED_NRPPA_TRANSPORT: Self = Self(47);
    pub const UPLINK_RAN_CONFIGURATION_TRANSFER: Self = Self(48);
    pub const UPLINK_RAN_STATUS_TRANSFER: Self = Self(49);
    pub const UPLINK_UE_ASSOCIATED_NRPPA_TRANSPORT: Self = Self(50);
    pub const WRITE_REPLACE_WARNING: Self = Self(51);
    pub const SECONDARY_RAT_DATA_USAGE_REPORT: Self = Self(52);
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

/// ProtocolIE-ID - identifies the Information Element
/// ASN.1: ProtocolIE-ID ::= INTEGER (0..65535)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtocolIeId(pub u16);

impl ProtocolIeId {
    pub const CONSTRAINT: Constraint = Constraint::new(0, 65535);

    // Common IE IDs from 3GPP TS 38.413
    pub const ALLOWED_NSSAI: Self = Self(0);
    pub const AMF_NAME: Self = Self(1);
    pub const AMF_OVERLOAD_RESPONSE: Self = Self(2);
    pub const AMF_SET_ID: Self = Self(3);
    pub const AMF_UE_NGAP_ID: Self = Self(10);
    pub const CAUSE: Self = Self(15);
    pub const CRITICALITY_DIAGNOSTICS: Self = Self(19);
    pub const GLOBAL_RAN_NODE_ID: Self = Self(27);
    pub const GUAMI: Self = Self(28);
    pub const NAS_PDU: Self = Self(38);
    pub const PLMN_SUPPORT_LIST: Self = Self(80);
    pub const RAN_NODE_NAME: Self = Self(82);
    pub const RAN_UE_NGAP_ID: Self = Self(85);
    pub const RELATIVE_AMF_CAPACITY: Self = Self(86);
    pub const SERVED_GUAMI_LIST: Self = Self(96);
    pub const SUPPORTED_TA_LIST: Self = Self(102);
    pub const TIME_TO_WAIT: Self = Self(107);
    pub const UE_AGGREGATE_MAXIMUM_BIT_RATE: Self = Self(110);
    pub const UE_CONTEXT_REQUEST: Self = Self(112);
    pub const UE_SECURITY_CAPABILITIES: Self = Self(119);
    pub const USER_LOCATION_INFORMATION: Self = Self(121);
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


/// TriggeringMessage - indicates which message triggered the error
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
            _ => Err(crate::per::PerError::DecodeError(
                format!("Invalid TriggeringMessage value: {}", value)
            )),
        }
    }
}

/// Presence - indicates whether an IE is optional, conditional, or mandatory
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
            _ => Err(crate::per::PerError::DecodeError(
                format!("Invalid Presence value: {}", value)
            )),
        }
    }
}
