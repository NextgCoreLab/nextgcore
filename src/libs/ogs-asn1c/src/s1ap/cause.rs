//! S1AP Cause Types
//!
//! Cause types from S1AP-IEs (3GPP TS 36.413)

use crate::per::{AperDecode, AperDecoder, AperEncode, AperEncoder, Constraint, PerResult, PerError};

/// CauseRadioNetwork - Radio network layer cause values
/// ASN.1: CauseRadioNetwork ::= ENUMERATED { ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CauseRadioNetwork {
    Unspecified = 0,
    Tx2relocoverallExpiry = 1,
    SuccessfulHandover = 2,
    ReleaseDueToEutranGeneratedReason = 3,
    HandoverCancelled = 4,
    PartialHandover = 5,
    HoFailureInTargetEpcEnbOrTargetSystem = 6,
    HoTargetNotAllowed = 7,
    TS1relocoverallExpiry = 8,
    TS1relocprepExpiry = 9,
    CellNotAvailable = 10,
    UnknownTargetId = 11,
    NoRadioResourcesAvailableInTargetCell = 12,
    UnknownMmeUeS1apId = 13,
    UnknownEnbUeS1apId = 14,
    UnknownPairUeS1apId = 15,
    HandoverDesirableForRadioReason = 16,
    TimeCriticalHandover = 17,
    ResourceOptimisationHandover = 18,
    ReduceLoadInServingCell = 19,
    UserInactivity = 20,
    RadioConnectionWithUeLost = 21,
    LoadBalancingTauRequired = 22,
    CsFallbackTriggered = 23,
    UeNotAvailableForPsService = 24,
    RadioResourcesNotAvailable = 25,
    FailureInRadioInterfaceProcedure = 26,
    InvalidQosCombination = 27,
    InterratRedirection = 28,
    InteractionWithOtherProcedure = 29,
    UnknownERabId = 30,
    MultipleERabIdInstances = 31,
    EncryptionAndOrIntegrityProtectionAlgorithmsNotSupported = 32,
    S1IntraSystemHandoverTriggered = 33,
    S1InterSystemHandoverTriggered = 34,
    X2HandoverTriggered = 35,
    // Extension values (36+)
    RedirectionTowards1xRtt = 36,
    NotSupportedQciValue = 37,
    InvalidCsgId = 38,
    ReleaseDueToPreEmption = 39,
    N26InterfaceNotAvailable = 40,
    InsufficientUeCapabilities = 41,
    MaximumBearerPreEmptionRateExceeded = 42,
    UpIntegrityProtectionNotPossible = 43,
}

impl CauseRadioNetwork {
    // Root enumeration has 36 values (0-35), extensible
    pub const CONSTRAINT: Constraint = Constraint::extensible(0, 35);
}

impl AperEncode for CauseRadioNetwork {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_enumerated(*self as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for CauseRadioNetwork {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let value = decoder.decode_enumerated(&Self::CONSTRAINT)?;
        if value <= 43 {
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
/// ASN.1: CauseNas ::= ENUMERATED { normal-release, authentication-failure, detach, unspecified, ... }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CauseNas {
    NormalRelease = 0,
    AuthenticationFailure = 1,
    Detach = 2,
    Unspecified = 3,
    // Extension values
    CsgSubscriptionExpiry = 4,
    UeNotInPlmnServingArea = 5,
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
            2 => Ok(CauseNas::Detach),
            3 => Ok(CauseNas::Unspecified),
            4 => Ok(CauseNas::CsgSubscriptionExpiry),
            5 => Ok(CauseNas::UeNotInPlmnServingArea),
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
    Unspecified = 4,
    UnknownPlmn = 5,
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

    #[test]
    fn test_cause_nas_roundtrip() {
        let cause = Cause::Nas(CauseNas::Detach);
        
        let mut encoder = AperEncoder::new();
        cause.encode_aper(&mut encoder).unwrap();
        encoder.align();
        
        let bytes = encoder.into_bytes();
        let mut decoder = AperDecoder::new(&bytes);
        let decoded = Cause::decode_aper(&mut decoder).unwrap();
        
        assert_eq!(cause, decoded);
    }

    #[test]
    fn test_cause_transport_roundtrip() {
        let cause = Cause::Transport(CauseTransport::TransportResourceUnavailable);
        
        let mut encoder = AperEncoder::new();
        cause.encode_aper(&mut encoder).unwrap();
        encoder.align();
        
        let bytes = encoder.into_bytes();
        let mut decoder = AperDecoder::new(&bytes);
        let decoded = Cause::decode_aper(&mut decoder).unwrap();
        
        assert_eq!(cause, decoded);
    }

    #[test]
    fn test_cause_protocol_roundtrip() {
        let cause = Cause::Protocol(CauseProtocol::SemanticError);
        
        let mut encoder = AperEncoder::new();
        cause.encode_aper(&mut encoder).unwrap();
        encoder.align();
        
        let bytes = encoder.into_bytes();
        let mut decoder = AperDecoder::new(&bytes);
        let decoded = Cause::decode_aper(&mut decoder).unwrap();
        
        assert_eq!(cause, decoded);
    }
}
