//! S1AP Basic Types
//!
//! Basic types from S1AP-CommonDataTypes (3GPP TS 36.413)

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
                format!("Invalid Criticality value: {value}")
            )),
        }
    }
}

/// ProcedureCode - identifies the S1AP procedure
/// ASN.1: ProcedureCode ::= INTEGER (0..255)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcedureCode(pub u8);

impl ProcedureCode {
    pub const CONSTRAINT: Constraint = Constraint::new(0, 255);

    // Procedure code constants from 3GPP TS 36.413
    pub const HANDOVER_PREPARATION: Self = Self(0);
    pub const HANDOVER_RESOURCE_ALLOCATION: Self = Self(1);
    pub const HANDOVER_NOTIFICATION: Self = Self(2);
    pub const PATH_SWITCH_REQUEST: Self = Self(3);
    pub const HANDOVER_CANCEL: Self = Self(4);
    pub const E_RAB_SETUP: Self = Self(5);
    pub const E_RAB_MODIFY: Self = Self(6);
    pub const E_RAB_RELEASE: Self = Self(7);
    pub const E_RAB_RELEASE_INDICATION: Self = Self(8);
    pub const INITIAL_CONTEXT_SETUP: Self = Self(9);
    pub const PAGING: Self = Self(10);
    pub const DOWNLINK_NAS_TRANSPORT: Self = Self(11);
    pub const INITIAL_UE_MESSAGE: Self = Self(12);
    pub const UPLINK_NAS_TRANSPORT: Self = Self(13);
    pub const RESET: Self = Self(14);
    pub const ERROR_INDICATION: Self = Self(15);
    pub const NAS_NON_DELIVERY_INDICATION: Self = Self(16);
    pub const S1_SETUP: Self = Self(17);
    pub const UE_CONTEXT_RELEASE_REQUEST: Self = Self(18);
    pub const DOWNLINK_S1_CDMA2000_TUNNELLING: Self = Self(19);
    pub const UPLINK_S1_CDMA2000_TUNNELLING: Self = Self(20);
    pub const UE_CONTEXT_MODIFICATION: Self = Self(21);
    pub const UE_CAPABILITY_INFO_INDICATION: Self = Self(22);
    pub const UE_CONTEXT_RELEASE: Self = Self(23);
    pub const ENB_STATUS_TRANSFER: Self = Self(24);
    pub const MME_STATUS_TRANSFER: Self = Self(25);
    pub const DEACTIVATE_TRACE: Self = Self(26);
    pub const TRACE_START: Self = Self(27);
    pub const TRACE_FAILURE_INDICATION: Self = Self(28);
    pub const ENB_CONFIGURATION_UPDATE: Self = Self(29);
    pub const MME_CONFIGURATION_UPDATE: Self = Self(30);
    pub const LOCATION_REPORTING_CONTROL: Self = Self(31);
    pub const LOCATION_REPORTING_FAILURE_INDICATION: Self = Self(32);
    pub const LOCATION_REPORT: Self = Self(33);
    pub const OVERLOAD_START: Self = Self(34);
    pub const OVERLOAD_STOP: Self = Self(35);
    pub const WRITE_REPLACE_WARNING: Self = Self(36);
    pub const ENB_DIRECT_INFORMATION_TRANSFER: Self = Self(37);
    pub const MME_DIRECT_INFORMATION_TRANSFER: Self = Self(38);
    pub const PRIVATE_MESSAGE: Self = Self(39);
    pub const ENB_CONFIGURATION_TRANSFER: Self = Self(40);
    pub const MME_CONFIGURATION_TRANSFER: Self = Self(41);
    pub const CELL_TRAFFIC_TRACE: Self = Self(42);
    pub const KILL: Self = Self(43);
    pub const DOWNLINK_UE_ASSOCIATED_LPPA_TRANSPORT: Self = Self(44);
    pub const UPLINK_UE_ASSOCIATED_LPPA_TRANSPORT: Self = Self(45);
    pub const DOWNLINK_NON_UE_ASSOCIATED_LPPA_TRANSPORT: Self = Self(46);
    pub const UPLINK_NON_UE_ASSOCIATED_LPPA_TRANSPORT: Self = Self(47);
    pub const UE_RADIO_CAPABILITY_MATCH: Self = Self(48);
    pub const PWS_RESTART_INDICATION: Self = Self(49);
    pub const E_RAB_MODIFICATION_INDICATION: Self = Self(50);
    pub const PWS_FAILURE_INDICATION: Self = Self(51);
    pub const REROUTE_NAS_REQUEST: Self = Self(52);
    pub const UE_CONTEXT_MODIFICATION_INDICATION: Self = Self(53);
    pub const CONNECTION_ESTABLISHMENT_INDICATION: Self = Self(54);
    pub const UE_CONTEXT_SUSPEND: Self = Self(55);
    pub const UE_CONTEXT_RESUME: Self = Self(56);
    pub const NAS_DELIVERY_INDICATION: Self = Self(57);
    pub const RETRIEVE_UE_INFORMATION: Self = Self(58);
    pub const UE_INFORMATION_TRANSFER: Self = Self(59);
    pub const ENB_CP_RELOCATION_INDICATION: Self = Self(60);
    pub const MME_CP_RELOCATION_INDICATION: Self = Self(61);
    pub const SECONDARY_RAT_DATA_USAGE_REPORT: Self = Self(62);
    pub const UE_RADIO_CAPABILITY_ID_MAPPING: Self = Self(63);
    pub const HANDOVER_SUCCESS: Self = Self(64);
    pub const ENB_EARLY_STATUS_TRANSFER: Self = Self(65);
    pub const MME_EARLY_STATUS_TRANSFER: Self = Self(66);
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

    // Common IE IDs from 3GPP TS 36.413
    pub const MME_UE_S1AP_ID: Self = Self(0);
    pub const HANDOVER_TYPE: Self = Self(1);
    pub const CAUSE: Self = Self(2);
    pub const SOURCE_ID: Self = Self(3);
    pub const TARGET_ID: Self = Self(4);
    pub const ENB_UE_S1AP_ID: Self = Self(8);
    pub const E_RAB_SUBJECT_TO_DATA_FORWARDING_LIST: Self = Self(12);
    pub const E_RAB_TO_RELEASE_LIST_HO_CMD: Self = Self(13);
    pub const E_RAB_DATA_FORWARDING_ITEM: Self = Self(14);
    pub const E_RAB_RELEASE_ITEM_BEARER_REL_COMP: Self = Self(15);
    pub const E_RAB_TO_BE_SETUP_LIST_BEARER_SU_REQ: Self = Self(16);
    pub const E_RAB_TO_BE_SETUP_ITEM_BEARER_SU_REQ: Self = Self(17);
    pub const E_RAB_ADMITTED_LIST: Self = Self(18);
    pub const E_RAB_FAILED_TO_SETUP_LIST_HO_REQ_ACK: Self = Self(19);
    pub const E_RAB_ADMITTED_ITEM: Self = Self(20);
    pub const E_RAB_FAILED_TO_SETUP_ITEM_HO_REQ_ACK: Self = Self(21);
    pub const E_RAB_TO_BE_SWITCHED_DL_LIST: Self = Self(22);
    pub const E_RAB_TO_BE_SWITCHED_DL_ITEM: Self = Self(23);
    pub const E_RAB_TO_BE_SETUP_LIST_CTXT_SU_REQ: Self = Self(24);
    pub const TRACE_ACTIVATION: Self = Self(25);
    pub const NAS_PDU: Self = Self(26);
    pub const E_RAB_TO_BE_SETUP_ITEM_HO_REQ: Self = Self(27);
    pub const E_RAB_SETUP_LIST_BEARER_SU_RES: Self = Self(28);
    pub const E_RAB_FAILED_TO_SETUP_LIST_BEARER_SU_RES: Self = Self(29);
    pub const E_RAB_TO_BE_MODIFIED_LIST_BEARER_MOD_REQ: Self = Self(30);
    pub const E_RAB_MODIFY_LIST_BEARER_MOD_RES: Self = Self(31);
    pub const E_RAB_FAILED_TO_MODIFY_LIST: Self = Self(32);
    pub const E_RAB_TO_BE_RELEASED_LIST: Self = Self(33);
    pub const E_RAB_FAILED_TO_RELEASE_LIST: Self = Self(34);
    pub const E_RAB_ITEM: Self = Self(35);
    pub const E_RAB_TO_BE_MODIFIED_ITEM_BEARER_MOD_REQ: Self = Self(36);
    pub const E_RAB_MODIFY_ITEM_BEARER_MOD_RES: Self = Self(37);
    pub const E_RAB_RELEASE_ITEM: Self = Self(38);
    pub const E_RAB_SETUP_ITEM_BEARER_SU_RES: Self = Self(39);
    pub const SECURITY_CONTEXT: Self = Self(40);
    pub const HANDOVER_RESTRICTION_LIST: Self = Self(41);
    pub const UE_PAGING_ID: Self = Self(43);
    pub const PAGING_DRX: Self = Self(44);
    pub const TAI_LIST: Self = Self(46);
    pub const TAI_ITEM: Self = Self(47);
    pub const E_RAB_FAILED_TO_SETUP_LIST_CTXT_SU_RES: Self = Self(48);
    pub const E_RAB_RELEASE_ITEM_HO_CMD: Self = Self(49);
    pub const E_RAB_SETUP_ITEM_CTXT_SU_RES: Self = Self(50);
    pub const E_RAB_SETUP_LIST_CTXT_SU_RES: Self = Self(51);
    pub const E_RAB_TO_BE_SETUP_ITEM_CTXT_SU_REQ: Self = Self(52);
    pub const E_RAB_TO_BE_SETUP_LIST_HO_REQ: Self = Self(53);
    pub const CRITICALITY_DIAGNOSTICS: Self = Self(58);
    pub const GLOBAL_ENB_ID: Self = Self(59);
    pub const ENB_NAME: Self = Self(60);
    pub const MME_NAME: Self = Self(61);
    pub const SERVED_PLMNS: Self = Self(63);
    pub const SUPPORTED_TAS: Self = Self(64);
    pub const TIME_TO_WAIT: Self = Self(65);
    pub const UE_AGGREGATE_MAXIMUM_BITRATE: Self = Self(66);
    pub const TAI: Self = Self(67);
    pub const E_RAB_RELEASE_LIST_BEARER_REL_COMP: Self = Self(69);
    pub const SECURITY_KEY: Self = Self(73);
    pub const UE_RADIO_CAPABILITY: Self = Self(74);
    pub const GUMMEI_ID: Self = Self(75);
    pub const UE_IDENTITY_INDEX_VALUE: Self = Self(80);
    pub const RELATIVE_MME_CAPACITY: Self = Self(87);
    pub const SOURCE_MME_UE_S1AP_ID: Self = Self(88);
    pub const BEARERS_SUBJECT_TO_STATUS_TRANSFER_ITEM: Self = Self(89);
    pub const ENB_STATUS_TRANSFER_TRANSPARENT_CONTAINER: Self = Self(90);
    pub const UE_ASSOCIATED_LOGICAL_S1_CONNECTION_ITEM: Self = Self(91);
    pub const RESET_TYPE: Self = Self(92);
    pub const UE_ASSOCIATED_LOGICAL_S1_CONNECTION_LIST_RES_ACK: Self = Self(93);
    pub const S_TMSI: Self = Self(96);
    pub const UE_S1AP_IDS: Self = Self(99);
    pub const EUTRAN_CGI: Self = Self(100);
    pub const OVERLOAD_RESPONSE: Self = Self(101);
    pub const SOURCE_TO_TARGET_TRANSPARENT_CONTAINER: Self = Self(104);
    pub const SERVED_GUMMEIS: Self = Self(105);
    pub const SUBSCRIBER_PROFILE_ID_FOR_RFP: Self = Self(106);
    pub const UE_SECURITY_CAPABILITIES: Self = Self(107);
    pub const CS_FALLBACK_INDICATOR: Self = Self(108);
    pub const CN_DOMAIN: Self = Self(109);
    pub const E_RAB_RELEASED_LIST: Self = Self(110);
    pub const MESSAGE_IDENTIFIER: Self = Self(111);
    pub const SERIAL_NUMBER: Self = Self(112);
    pub const WARNING_AREA_LIST: Self = Self(113);
    pub const REPETITION_PERIOD: Self = Self(114);
    pub const NUMBER_OF_BROADCAST_REQUEST: Self = Self(115);
    pub const WARNING_TYPE: Self = Self(116);
    pub const WARNING_SECURITY_INFO: Self = Self(117);
    pub const DATA_CODING_SCHEME: Self = Self(118);
    pub const WARNING_MESSAGE_CONTENTS: Self = Self(119);
    pub const BROADCAST_COMPLETED_AREA_LIST: Self = Self(120);
    pub const TARGET_TO_SOURCE_TRANSPARENT_CONTAINER: Self = Self(123);
    pub const SRVCC_OPERATION_POSSIBLE: Self = Self(124);
    pub const SRVCC_HO_INDICATION: Self = Self(125);
    pub const NAS_DOWNLINK_COUNT: Self = Self(126);
    pub const CSG_ID: Self = Self(127);
    pub const CSG_ID_LIST: Self = Self(128);
    pub const RRC_ESTABLISHMENT_CAUSE: Self = Self(134);
    pub const DEFAULT_PAGING_DRX: Self = Self(137);
    pub const USER_LOCATION_INFORMATION: Self = Self(189);
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
                format!("Invalid TriggeringMessage value: {value}")
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
                format!("Invalid Presence value: {value}")
            )),
        }
    }
}
