//! S1AP Cause and Criticality values (3GPP TS 36.413 §9.2.1.3, §9.3.1.x).
//!
//! Domain types only: encoding and decoding is done by the generated codec
//! (`nextgcore-s1ap-gen`, #514). The values are the ASN.1 enumeration indices.

/// A cause or criticality value the receiving side does not define.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub String);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DecodeError {}
/// Criticality - indicates how to handle unrecognized IEs
/// ASN.1: Criticality ::= ENUMERATED { reject, ignore, notify }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Criticality {
    Reject = 0,
    Ignore = 1,
    Notify = 2,
}

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

impl TryFrom<i64> for CauseRadioNetwork {
    type Error = DecodeError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Unspecified),
            1 => Ok(Self::Tx2relocoverallExpiry),
            2 => Ok(Self::SuccessfulHandover),
            3 => Ok(Self::ReleaseDueToEutranGeneratedReason),
            4 => Ok(Self::HandoverCancelled),
            5 => Ok(Self::PartialHandover),
            6 => Ok(Self::HoFailureInTargetEpcEnbOrTargetSystem),
            7 => Ok(Self::HoTargetNotAllowed),
            8 => Ok(Self::TS1relocoverallExpiry),
            9 => Ok(Self::TS1relocprepExpiry),
            10 => Ok(Self::CellNotAvailable),
            11 => Ok(Self::UnknownTargetId),
            12 => Ok(Self::NoRadioResourcesAvailableInTargetCell),
            13 => Ok(Self::UnknownMmeUeS1apId),
            14 => Ok(Self::UnknownEnbUeS1apId),
            15 => Ok(Self::UnknownPairUeS1apId),
            16 => Ok(Self::HandoverDesirableForRadioReason),
            17 => Ok(Self::TimeCriticalHandover),
            18 => Ok(Self::ResourceOptimisationHandover),
            19 => Ok(Self::ReduceLoadInServingCell),
            20 => Ok(Self::UserInactivity),
            21 => Ok(Self::RadioConnectionWithUeLost),
            22 => Ok(Self::LoadBalancingTauRequired),
            23 => Ok(Self::CsFallbackTriggered),
            24 => Ok(Self::UeNotAvailableForPsService),
            25 => Ok(Self::RadioResourcesNotAvailable),
            26 => Ok(Self::FailureInRadioInterfaceProcedure),
            27 => Ok(Self::InvalidQosCombination),
            28 => Ok(Self::InterratRedirection),
            29 => Ok(Self::InteractionWithOtherProcedure),
            30 => Ok(Self::UnknownERabId),
            31 => Ok(Self::MultipleERabIdInstances),
            32 => Ok(Self::EncryptionAndOrIntegrityProtectionAlgorithmsNotSupported),
            33 => Ok(Self::S1IntraSystemHandoverTriggered),
            34 => Ok(Self::S1InterSystemHandoverTriggered),
            35 => Ok(Self::X2HandoverTriggered),
            36 => Ok(Self::RedirectionTowards1xRtt),
            37 => Ok(Self::NotSupportedQciValue),
            38 => Ok(Self::InvalidCsgId),
            39 => Ok(Self::ReleaseDueToPreEmption),
            40 => Ok(Self::N26InterfaceNotAvailable),
            41 => Ok(Self::InsufficientUeCapabilities),
            42 => Ok(Self::MaximumBearerPreEmptionRateExceeded),
            43 => Ok(Self::UpIntegrityProtectionNotPossible),
            _ => Err(DecodeError(format!(
                "Unknown CauseRadioNetwork value: {value}"
            ))),
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

impl TryFrom<i64> for CauseTransport {
    type Error = DecodeError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::TransportResourceUnavailable),
            1 => Ok(Self::Unspecified),
            _ => Err(DecodeError(format!(
                "Unknown CauseTransport value: {value}"
            ))),
        }
    }
}

impl TryFrom<i64> for CauseNas {
    type Error = DecodeError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NormalRelease),
            1 => Ok(Self::AuthenticationFailure),
            2 => Ok(Self::Detach),
            3 => Ok(Self::Unspecified),
            4 => Ok(Self::CsgSubscriptionExpiry),
            5 => Ok(Self::UeNotInPlmnServingArea),
            _ => Err(DecodeError(format!("Unknown CauseNas value: {value}"))),
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

impl TryFrom<i64> for CauseProtocol {
    type Error = DecodeError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::TransferSyntaxError),
            1 => Ok(Self::AbstractSyntaxErrorReject),
            2 => Ok(Self::AbstractSyntaxErrorIgnoreAndNotify),
            3 => Ok(Self::MessageNotCompatibleWithReceiverState),
            4 => Ok(Self::SemanticError),
            5 => Ok(Self::AbstractSyntaxErrorFalselyConstructedMessage),
            6 => Ok(Self::Unspecified),
            _ => Err(DecodeError(format!("Unknown CauseProtocol value: {value}"))),
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

impl TryFrom<i64> for CauseMisc {
    type Error = DecodeError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ControlProcessingOverload),
            1 => Ok(Self::NotEnoughUserPlaneProcessingResources),
            2 => Ok(Self::HardwareFailure),
            3 => Ok(Self::OmIntervention),
            4 => Ok(Self::Unspecified),
            5 => Ok(Self::UnknownPlmn),
            _ => Err(DecodeError(format!("Unknown CauseMisc value: {value}"))),
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
