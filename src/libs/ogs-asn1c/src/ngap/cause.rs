//! NGAP Cause Types
//!
//! Cause types from NGAP-IEs (3GPP TS 38.413)

use crate::per::{AperDecode, AperDecoder, AperEncode, AperEncoder, Constraint, PerResult, PerError};

/// CauseRadioNetwork - Radio network layer cause values
/// ASN.1: CauseRadioNetwork ::= ENUMERATED { ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CauseRadioNetwork {
    Unspecified = 0,
    TxnrelocoverallExpiry = 1,
    SuccessfulHandover = 2,
    ReleaseDueToNgranGeneratedReason = 3,
    ReleaseDueTo5gcGeneratedReason = 4,
    HandoverCancelled = 5,
    PartialHandover = 6,
    HoFailureInTarget5gcNgranNodeOrTargetSystem = 7,
    HoTargetNotAllowed = 8,
    TngrelocoverallExpiry = 9,
    TngrelocprepExpiry = 10,
    CellNotAvailable = 11,
    UnknownTargetId = 12,
    NoRadioResourcesAvailableInTargetCell = 13,
    UnknownLocalUeNgapId = 14,
    InconsistentRemoteUeNgapId = 15,
    HandoverDesirableForRadioReason = 16,
    TimeCriticalHandover = 17,
    ResourceOptimisationHandover = 18,
    ReduceLoadInServingCell = 19,
    UserInactivity = 20,
    RadioConnectionWithUeLost = 21,
    RadioResourcesNotAvailable = 22,
    InvalidQosCombination = 23,
    FailureInRadioInterfaceProcedure = 24,
    InteractionWithOtherProcedure = 25,
    UnknownPduSessionId = 26,
    UnknownQosFlowId = 27,
    MultiplePduSessionIdInstances = 28,
    MultipleQosFlowIdInstances = 29,
    EncryptionAndOrIntegrityProtectionAlgorithmsNotSupported = 30,
    NgIntraSystemHandoverTriggered = 31,
    NgInterSystemHandoverTriggered = 32,
    XnHandoverTriggered = 33,
    NotSupported5qiValue = 34,
    UeContextTransfer = 35,
    ImsVoiceEpsFallbackOrRatFallbackTriggered = 36,
    UpIntegrityProtectionNotPossible = 37,
    UpConfidentialityProtectionNotPossible = 38,
    SliceNotSupported = 39,
    UeInRrcInactiveStateNotReachable = 40,
    Redirection = 41,
    ResourcesNotAvailableForTheSlice = 42,
    UeMaxIntegrityProtectedDataRateReason = 43,
    ReleaseDueToCnDetectedMobility = 44,
    // Extension values (45+)
    N26InterfaceNotAvailable = 45,
    ReleaseDueToPreEmption = 46,
}


impl CauseRadioNetwork {
    // Root enumeration has 45 values (0-44), extensible
    pub const CONSTRAINT: Constraint = Constraint::extensible(0, 44);
}

impl AperEncode for CauseRadioNetwork {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_enumerated(*self as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for CauseRadioNetwork {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let value = decoder.decode_enumerated(&Self::CONSTRAINT)?;
        // For simplicity, we handle known values; unknown extension values return error
        if value <= 46 {
            // Safe because we've validated the range
            Ok(unsafe { std::mem::transmute(value as u8) })
        } else {
            Err(PerError::DecodeError(format!(
                "Unknown CauseRadioNetwork value: {value}"
            )))
        }
    }
}

/// CauseTransport - Transport layer cause values
/// ASN.1: CauseTransport ::= ENUMERATED { transport-resource-unavailable, unspecified, ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CauseTransport {
    TransportResourceUnavailable = 0,
    Unspecified = 1,
}

impl CauseTransport {
    pub const CONSTRAINT: Constraint = Constraint::extensible(0, 1);
}

impl AperEncode for CauseTransport {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_enumerated(*self as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for CauseTransport {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let value = decoder.decode_enumerated(&Self::CONSTRAINT)?;
        match value {
            0 => Ok(CauseTransport::TransportResourceUnavailable),
            1 => Ok(CauseTransport::Unspecified),
            _ => Err(PerError::DecodeError(format!(
                "Unknown CauseTransport value: {value}"
            ))),
        }
    }
}


/// CauseNas - NAS layer cause values
/// ASN.1: CauseNas ::= ENUMERATED { normal-release, authentication-failure, deregister, unspecified, ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CauseNas {
    NormalRelease = 0,
    AuthenticationFailure = 1,
    Deregister = 2,
    Unspecified = 3,
    // Extension
    UeNotInPlmnServingArea = 4,
}

impl CauseNas {
    pub const CONSTRAINT: Constraint = Constraint::extensible(0, 3);
}

impl AperEncode for CauseNas {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_enumerated(*self as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for CauseNas {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let value = decoder.decode_enumerated(&Self::CONSTRAINT)?;
        match value {
            0 => Ok(CauseNas::NormalRelease),
            1 => Ok(CauseNas::AuthenticationFailure),
            2 => Ok(CauseNas::Deregister),
            3 => Ok(CauseNas::Unspecified),
            4 => Ok(CauseNas::UeNotInPlmnServingArea),
            _ => Err(PerError::DecodeError(format!(
                "Unknown CauseNas value: {value}"
            ))),
        }
    }
}

/// CauseProtocol - Protocol layer cause values
/// ASN.1: CauseProtocol ::= ENUMERATED { ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CauseProtocol {
    TransferSyntaxError = 0,
    AbstractSyntaxErrorReject = 1,
    AbstractSyntaxErrorIgnoreAndNotify = 2,
    MessageNotCompatibleWithReceiverState = 3,
    SemanticError = 4,
    AbstractSyntaxErrorFalselyConstructedMessage = 5,
    Unspecified = 6,
}

impl CauseProtocol {
    pub const CONSTRAINT: Constraint = Constraint::extensible(0, 6);
}

impl AperEncode for CauseProtocol {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_enumerated(*self as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for CauseProtocol {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let value = decoder.decode_enumerated(&Self::CONSTRAINT)?;
        if value <= 6 {
            Ok(unsafe { std::mem::transmute(value as u8) })
        } else {
            Err(PerError::DecodeError(format!(
                "Unknown CauseProtocol value: {value}"
            )))
        }
    }
}


/// CauseMisc - Miscellaneous cause values
/// ASN.1: CauseMisc ::= ENUMERATED { ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CauseMisc {
    ControlProcessingOverload = 0,
    NotEnoughUserPlaneProcessingResources = 1,
    HardwareFailure = 2,
    OmIntervention = 3,
    UnknownPlmnOrSnpn = 4,
    Unspecified = 5,
}

impl CauseMisc {
    pub const CONSTRAINT: Constraint = Constraint::extensible(0, 5);
}

impl AperEncode for CauseMisc {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_enumerated(*self as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for CauseMisc {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let value = decoder.decode_enumerated(&Self::CONSTRAINT)?;
        if value <= 5 {
            Ok(unsafe { std::mem::transmute(value as u8) })
        } else {
            Err(PerError::DecodeError(format!(
                "Unknown CauseMisc value: {value}"
            )))
        }
    }
}

/// Cause - CHOICE type for all cause categories
/// ASN.1: Cause ::= CHOICE { radioNetwork, transport, nas, protocol, misc, choice-Extensions }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    RadioNetwork(CauseRadioNetwork),
    Transport(CauseTransport),
    Nas(CauseNas),
    Protocol(CauseProtocol),
    Misc(CauseMisc),
}

impl Cause {
    // 5 alternatives in root, extensible
    pub const NUM_ALTERNATIVES: usize = 5;
    pub const EXTENSIBLE: bool = true;
}

impl AperEncode for Cause {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        match self {
            Cause::RadioNetwork(v) => {
                encoder.encode_choice_index(0, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                v.encode_aper(encoder)
            }
            Cause::Transport(v) => {
                encoder.encode_choice_index(1, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                v.encode_aper(encoder)
            }
            Cause::Nas(v) => {
                encoder.encode_choice_index(2, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                v.encode_aper(encoder)
            }
            Cause::Protocol(v) => {
                encoder.encode_choice_index(3, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                v.encode_aper(encoder)
            }
            Cause::Misc(v) => {
                encoder.encode_choice_index(4, Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
                v.encode_aper(encoder)
            }
        }
    }
}


impl AperDecode for Cause {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let index = decoder.decode_choice_index(Self::NUM_ALTERNATIVES, Self::EXTENSIBLE)?;
        match index {
            0 => Ok(Cause::RadioNetwork(CauseRadioNetwork::decode_aper(decoder)?)),
            1 => Ok(Cause::Transport(CauseTransport::decode_aper(decoder)?)),
            2 => Ok(Cause::Nas(CauseNas::decode_aper(decoder)?)),
            3 => Ok(Cause::Protocol(CauseProtocol::decode_aper(decoder)?)),
            4 => Ok(Cause::Misc(CauseMisc::decode_aper(decoder)?)),
            _ => Err(PerError::InvalidChoiceIndex {
                index,
                max: Self::NUM_ALTERNATIVES - 1,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::per::{AperEncoder, AperDecoder};

    #[test]
    fn test_cause_radio_network_roundtrip() {
        let cause = Cause::RadioNetwork(CauseRadioNetwork::UserInactivity);
        
        let mut encoder = AperEncoder::new();
        cause.encode_aper(&mut encoder).unwrap();
        encoder.align();
        
        let bytes = encoder.into_bytes();
        let mut decoder = AperDecoder::new(&bytes);
        let decoded = Cause::decode_aper(&mut decoder).unwrap();
        
        assert_eq!(cause, decoded);
    }

    #[test]
    fn test_cause_misc_roundtrip() {
        let cause = Cause::Misc(CauseMisc::HardwareFailure);
        
        let mut encoder = AperEncoder::new();
        cause.encode_aper(&mut encoder).unwrap();
        encoder.align();
        
        let bytes = encoder.into_bytes();
        let mut decoder = AperDecoder::new(&bytes);
        let decoded = Cause::decode_aper(&mut decoder).unwrap();
        
        assert_eq!(cause, decoded);
    }
}
