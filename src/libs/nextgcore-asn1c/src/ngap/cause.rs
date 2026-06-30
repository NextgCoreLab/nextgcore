//! NGAP Cause Types
//!
//! Cause types from NGAP-IEs (3GPP TS 38.413)

use crate::per::{
    AperDecode, AperDecoder, AperEncode, AperEncoder, Constraint, PerError, PerResult,
};

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

impl TryFrom<i64> for CauseRadioNetwork {
    type Error = PerError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Unspecified),
            1 => Ok(Self::TxnrelocoverallExpiry),
            2 => Ok(Self::SuccessfulHandover),
            3 => Ok(Self::ReleaseDueToNgranGeneratedReason),
            4 => Ok(Self::ReleaseDueTo5gcGeneratedReason),
            5 => Ok(Self::HandoverCancelled),
            6 => Ok(Self::PartialHandover),
            7 => Ok(Self::HoFailureInTarget5gcNgranNodeOrTargetSystem),
            8 => Ok(Self::HoTargetNotAllowed),
            9 => Ok(Self::TngrelocoverallExpiry),
            10 => Ok(Self::TngrelocprepExpiry),
            11 => Ok(Self::CellNotAvailable),
            12 => Ok(Self::UnknownTargetId),
            13 => Ok(Self::NoRadioResourcesAvailableInTargetCell),
            14 => Ok(Self::UnknownLocalUeNgapId),
            15 => Ok(Self::InconsistentRemoteUeNgapId),
            16 => Ok(Self::HandoverDesirableForRadioReason),
            17 => Ok(Self::TimeCriticalHandover),
            18 => Ok(Self::ResourceOptimisationHandover),
            19 => Ok(Self::ReduceLoadInServingCell),
            20 => Ok(Self::UserInactivity),
            21 => Ok(Self::RadioConnectionWithUeLost),
            22 => Ok(Self::RadioResourcesNotAvailable),
            23 => Ok(Self::InvalidQosCombination),
            24 => Ok(Self::FailureInRadioInterfaceProcedure),
            25 => Ok(Self::InteractionWithOtherProcedure),
            26 => Ok(Self::UnknownPduSessionId),
            27 => Ok(Self::UnknownQosFlowId),
            28 => Ok(Self::MultiplePduSessionIdInstances),
            29 => Ok(Self::MultipleQosFlowIdInstances),
            30 => Ok(Self::EncryptionAndOrIntegrityProtectionAlgorithmsNotSupported),
            31 => Ok(Self::NgIntraSystemHandoverTriggered),
            32 => Ok(Self::NgInterSystemHandoverTriggered),
            33 => Ok(Self::XnHandoverTriggered),
            34 => Ok(Self::NotSupported5qiValue),
            35 => Ok(Self::UeContextTransfer),
            36 => Ok(Self::ImsVoiceEpsFallbackOrRatFallbackTriggered),
            37 => Ok(Self::UpIntegrityProtectionNotPossible),
            38 => Ok(Self::UpConfidentialityProtectionNotPossible),
            39 => Ok(Self::SliceNotSupported),
            40 => Ok(Self::UeInRrcInactiveStateNotReachable),
            41 => Ok(Self::Redirection),
            42 => Ok(Self::ResourcesNotAvailableForTheSlice),
            43 => Ok(Self::UeMaxIntegrityProtectedDataRateReason),
            44 => Ok(Self::ReleaseDueToCnDetectedMobility),
            45 => Ok(Self::N26InterfaceNotAvailable),
            46 => Ok(Self::ReleaseDueToPreEmption),
            _ => Err(PerError::DecodeError(format!(
                "Unknown CauseRadioNetwork value: {value}"
            ))),
        }
    }
}

impl AperEncode for CauseRadioNetwork {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_enumerated(*self as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for CauseRadioNetwork {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let value = decoder.decode_enumerated(&Self::CONSTRAINT)?;
        Self::try_from(value)
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

impl TryFrom<i64> for CauseProtocol {
    type Error = PerError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::TransferSyntaxError),
            1 => Ok(Self::AbstractSyntaxErrorReject),
            2 => Ok(Self::AbstractSyntaxErrorIgnoreAndNotify),
            3 => Ok(Self::MessageNotCompatibleWithReceiverState),
            4 => Ok(Self::SemanticError),
            5 => Ok(Self::AbstractSyntaxErrorFalselyConstructedMessage),
            6 => Ok(Self::Unspecified),
            _ => Err(PerError::DecodeError(format!(
                "Unknown CauseProtocol value: {value}"
            ))),
        }
    }
}

impl AperEncode for CauseProtocol {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_enumerated(*self as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for CauseProtocol {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let value = decoder.decode_enumerated(&Self::CONSTRAINT)?;
        Self::try_from(value)
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

impl TryFrom<i64> for CauseMisc {
    type Error = PerError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ControlProcessingOverload),
            1 => Ok(Self::NotEnoughUserPlaneProcessingResources),
            2 => Ok(Self::HardwareFailure),
            3 => Ok(Self::OmIntervention),
            4 => Ok(Self::UnknownPlmnOrSnpn),
            5 => Ok(Self::Unspecified),
            _ => Err(PerError::DecodeError(format!(
                "Unknown CauseMisc value: {value}"
            ))),
        }
    }
}

impl AperEncode for CauseMisc {
    fn encode_aper(&self, encoder: &mut AperEncoder) -> PerResult<()> {
        encoder.encode_enumerated(*self as i64, &Self::CONSTRAINT)
    }
}

impl AperDecode for CauseMisc {
    fn decode_aper(decoder: &mut AperDecoder) -> PerResult<Self> {
        let value = decoder.decode_enumerated(&Self::CONSTRAINT)?;
        Self::try_from(value)
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
    // TS 38.413 §9.3.1.2: Cause is a NON-extensible CHOICE (no `...`) with 6
    // alternatives — radioNetwork, transport, nas, protocol, misc and
    // choice-Extensions. The index is therefore a constrained whole number
    // 0..5 (3 bits) with NO leading extension bit. `Cause-ExtIEs` is an empty
    // extension set, so a conformant peer never selects alternative 5.
    pub const NUM_ALTERNATIVES: usize = 6;
    pub const EXTENSIBLE: bool = false;
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
            0 => Ok(Cause::RadioNetwork(CauseRadioNetwork::decode_aper(
                decoder,
            )?)),
            1 => Ok(Cause::Transport(CauseTransport::decode_aper(decoder)?)),
            2 => Ok(Cause::Nas(CauseNas::decode_aper(decoder)?)),
            3 => Ok(Cause::Protocol(CauseProtocol::decode_aper(decoder)?)),
            4 => Ok(Cause::Misc(CauseMisc::decode_aper(decoder)?)),
            5 => Err(PerError::DecodeError(
                "Cause choice-Extensions selected but Cause-ExtIEs is empty in TS 38.413"
                    .to_string(),
            )),
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
    use crate::per::{AperDecoder, AperEncoder};

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
    fn test_cause_choice_index_non_extensible_3bit() {
        // TS 38.413 §9.3.1.2: non-extensible CHOICE → 3-bit index in the top
        // bits with NO leading extension bit. Transport = index 1 must appear
        // as `001` in the high 3 bits of octet 0 (== 1 when shifted), which
        // would be impossible if a spurious extension bit preceded the index.
        let mut encoder = AperEncoder::new();
        Cause::Transport(CauseTransport::TransportResourceUnavailable)
            .encode_aper(&mut encoder)
            .unwrap();
        encoder.align();
        let bytes = encoder.into_bytes();
        assert_eq!(
            bytes[0] >> 5,
            1,
            "Transport choice index must occupy the top 3 bits with no extension bit"
        );
    }

    #[test]
    fn test_cause_all_alternatives_roundtrip() {
        let cases = [
            Cause::RadioNetwork(CauseRadioNetwork::UserInactivity),
            Cause::Transport(CauseTransport::Unspecified),
            Cause::Nas(CauseNas::Unspecified),
            Cause::Protocol(CauseProtocol::Unspecified),
            Cause::Misc(CauseMisc::HardwareFailure),
        ];
        for cause in cases {
            let mut encoder = AperEncoder::new();
            cause.encode_aper(&mut encoder).unwrap();
            encoder.align();
            let bytes = encoder.into_bytes();
            let mut decoder = AperDecoder::new(&bytes);
            assert_eq!(Cause::decode_aper(&mut decoder).unwrap(), cause);
        }
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
