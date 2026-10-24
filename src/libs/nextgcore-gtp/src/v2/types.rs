//! GTPv2 Types
//!
//! Types and constants for GTPv2 protocol as specified in 3GPP TS 29.274.

use crate::error::{GtpError, GtpResult};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Maximum indirect tunnel count
pub const GTP2_MAX_INDIRECT_TUNNEL: usize = 8;

/// Number of extension headers
pub const GTP2_NUM_OF_EXTENSION_HEADER: usize = 8;

/// Maximum extension header length
pub const GTP2_MAX_EXTENSION_HEADER_LEN: usize = 4;

/// Extension Header Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Gtp2ExtensionHeaderType {
    NoMoreExtensionHeaders = 0x00,
    UdpPort = 0x40,
    PduSessionContainer = 0x85,
    PdcpNumber = 0xc0,
}

impl TryFrom<u8> for Gtp2ExtensionHeaderType {
    type Error = GtpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::NoMoreExtensionHeaders),
            0x40 => Ok(Self::UdpPort),
            0x85 => Ok(Self::PduSessionContainer),
            0xc0 => Ok(Self::PdcpNumber),
            _ => Err(GtpError::InvalidFormat(format!(
                "Unknown extension header type: {value:#x}"
            ))),
        }
    }
}

/// PDU Type for Extension Header
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Gtp2PduType {
    DlPduSessionInformation = 0,
    UlPduSessionInformation = 1,
}

/// GTPv2 Cause Values (TS 29.274 §8.4, Table 8.4-1).
///
/// The one table every nextgcore GTPv2 node uses (#1024, #1037): sgwcd, smfd and
/// mmed each kept their own, and each had values off the table. Every value is
/// pinned against Table 8.4-1 in `tests::every_cause_is_its_table_8_4_1_value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Gtp2Cause {
    /// 0 is reserved (Table 8.4-1); also what [`Gtp2Cause::from_wire`] gives a
    /// value the table does not define.
    #[default]
    UndefinedValue = 0,
    LocalDetach = 2,
    CompleteDetach = 3,
    RatChangedFrom3gppToNon3gpp = 4,
    IsrDeactivation = 5,
    ErrorIndicationReceived = 6,
    ImsiDetachOnly = 7,
    ReactivationRequested = 8,
    PdnReconnectionToThisApnDisallowed = 9,
    AccessChangedFromNon3gppTo3gpp = 10,
    PdnConnectionInactivityTimerExpires = 11,
    PgwNotResponding = 12,
    NetworkFailure = 13,
    QosParameterMismatch = 14,
    EpsTo5gsMobility = 15,
    RequestAccepted = 16,
    RequestAcceptedPartially = 17,
    NewPdnTypeDueToNetworkPreference = 18,
    NewPdnTypeDueToSingleAddressBearerOnly = 19,
    ContextNotFound = 64,
    InvalidMessageFormat = 65,
    VersionNotSupportedByNextPeer = 66,
    InvalidLength = 67,
    ServiceNotSupported = 68,
    MandatoryIeIncorrect = 69,
    MandatoryIeMissing = 70,
    SystemFailure = 72,
    NoResourcesAvailable = 73,
    SemanticErrorInTheTftOperation = 74,
    SyntacticErrorInTheTftOperation = 75,
    SemanticErrorsInPacketFilter = 76,
    SyntacticErrorsInPacketFilter = 77,
    MissingOrUnknownApn = 78,
    GreKeyNotFound = 80,
    RelocationFailure = 81,
    DeniedInRat = 82,
    PreferredPdnTypeNotSupported = 83,
    AllDynamicAddressesAreOccupied = 84,
    UeContextWithoutTftAlreadyActivated = 85,
    ProtocolTypeNotSupported = 86,
    UeNotResponding = 87,
    UeRefuses = 88,
    ServiceDenied = 89,
    UnableToPageUe = 90,
    NoMemoryAvailable = 91,
    UserAuthenticationFailed = 92,
    ApnAccessDeniedNoSubscription = 93,
    RequestRejectedReasonNotSpecified = 94,
    PTmsiSignatureMismatch = 95,
    ImsiImeiNotKnown = 96,
    SemanticErrorInTheTadOperation = 97,
    SyntacticErrorInTheTadOperation = 98,
    RemotePeerNotResponding = 100,
    CollisionWithNetworkInitiatedRequest = 101,
    UnableToPageUeDueToSuspension = 102,
    ConditionalIeMissing = 103,
    ApnRestrictionTypeIncompatible = 104,
    InvalidOverallLength = 105,
    DataForwardingNotSupported = 106,
    InvalidReplyFromRemotePeer = 107,
    FallbackToGtpv1 = 108,
    InvalidPeer = 109,
    TemporarilyRejectedDueToHandoverInProgress = 110,
    ModificationsNotLimitedToS1uBearers = 111,
    RequestRejectedForAPmipv6Reason = 112,
    ApnCongestion = 113,
    BearerHandlingNotSupported = 114,
    UeAlreadyReAttached = 115,
    MultiplePdnConnectionsForAGivenApnNotAllowed = 116,
    TargetAccessRestrictedForTheSubscriber = 117,
    MmeSgsnRefusesDueToVplmnPolicy = 119,
    GtpCEntityCongestion = 120,
    LateOverlappingRequest = 121,
    TimedOutRequest = 122,
    UeIsTemporarilyNotReachableDueToPowerSaving = 123,
    RelocationFailureDueToNasMessageRedirection = 124,
    UeNotAuthorisedByOcsOrExternalAaaServer = 125,
    MultipleAccessesToAPdnConnectionNotAllowed = 126,
    RequestRejectedDueToUeCapability = 127,
    S1uPathFailure = 128,
    FiveGcNotAllowed = 129,
    PgwMismatchWithNetworkSliceSubscribedByTheUe = 130,
    RejectionDueToPagingRestriction = 131,
}

/// The [`Gtp2Cause`] values as octets, for match patterns and for code that
/// carries the cause as a `u8` (#1024, #1037). Derived from the enum, so the two
/// cannot disagree; nodes import this rather than keeping their own table.
pub mod cause {
    use super::Gtp2Cause;

    pub const UNDEFINED_VALUE: u8 = Gtp2Cause::UndefinedValue as u8;
    pub const LOCAL_DETACH: u8 = Gtp2Cause::LocalDetach as u8;
    pub const COMPLETE_DETACH: u8 = Gtp2Cause::CompleteDetach as u8;
    pub const RAT_CHANGED_FROM_3GPP_TO_NON_3GPP: u8 = Gtp2Cause::RatChangedFrom3gppToNon3gpp as u8;
    pub const ISR_DEACTIVATION: u8 = Gtp2Cause::IsrDeactivation as u8;
    pub const ERROR_INDICATION_RECEIVED: u8 = Gtp2Cause::ErrorIndicationReceived as u8;
    pub const IMSI_DETACH_ONLY: u8 = Gtp2Cause::ImsiDetachOnly as u8;
    pub const REACTIVATION_REQUESTED: u8 = Gtp2Cause::ReactivationRequested as u8;
    pub const PDN_RECONNECTION_TO_THIS_APN_DISALLOWED: u8 =
        Gtp2Cause::PdnReconnectionToThisApnDisallowed as u8;
    pub const ACCESS_CHANGED_FROM_NON_3GPP_TO_3GPP: u8 =
        Gtp2Cause::AccessChangedFromNon3gppTo3gpp as u8;
    pub const PDN_CONNECTION_INACTIVITY_TIMER_EXPIRES: u8 =
        Gtp2Cause::PdnConnectionInactivityTimerExpires as u8;
    pub const PGW_NOT_RESPONDING: u8 = Gtp2Cause::PgwNotResponding as u8;
    pub const NETWORK_FAILURE: u8 = Gtp2Cause::NetworkFailure as u8;
    pub const QOS_PARAMETER_MISMATCH: u8 = Gtp2Cause::QosParameterMismatch as u8;
    pub const EPS_TO_5GS_MOBILITY: u8 = Gtp2Cause::EpsTo5gsMobility as u8;
    pub const REQUEST_ACCEPTED: u8 = Gtp2Cause::RequestAccepted as u8;
    pub const REQUEST_ACCEPTED_PARTIALLY: u8 = Gtp2Cause::RequestAcceptedPartially as u8;
    pub const NEW_PDN_TYPE_DUE_TO_NETWORK_PREFERENCE: u8 =
        Gtp2Cause::NewPdnTypeDueToNetworkPreference as u8;
    pub const NEW_PDN_TYPE_DUE_TO_SINGLE_ADDRESS_BEARER_ONLY: u8 =
        Gtp2Cause::NewPdnTypeDueToSingleAddressBearerOnly as u8;
    pub const CONTEXT_NOT_FOUND: u8 = Gtp2Cause::ContextNotFound as u8;
    pub const INVALID_MESSAGE_FORMAT: u8 = Gtp2Cause::InvalidMessageFormat as u8;
    pub const VERSION_NOT_SUPPORTED_BY_NEXT_PEER: u8 =
        Gtp2Cause::VersionNotSupportedByNextPeer as u8;
    pub const INVALID_LENGTH: u8 = Gtp2Cause::InvalidLength as u8;
    pub const SERVICE_NOT_SUPPORTED: u8 = Gtp2Cause::ServiceNotSupported as u8;
    pub const MANDATORY_IE_INCORRECT: u8 = Gtp2Cause::MandatoryIeIncorrect as u8;
    pub const MANDATORY_IE_MISSING: u8 = Gtp2Cause::MandatoryIeMissing as u8;
    pub const SYSTEM_FAILURE: u8 = Gtp2Cause::SystemFailure as u8;
    pub const NO_RESOURCES_AVAILABLE: u8 = Gtp2Cause::NoResourcesAvailable as u8;
    pub const SEMANTIC_ERROR_IN_THE_TFT_OPERATION: u8 =
        Gtp2Cause::SemanticErrorInTheTftOperation as u8;
    pub const SYNTACTIC_ERROR_IN_THE_TFT_OPERATION: u8 =
        Gtp2Cause::SyntacticErrorInTheTftOperation as u8;
    pub const SEMANTIC_ERRORS_IN_PACKET_FILTER: u8 = Gtp2Cause::SemanticErrorsInPacketFilter as u8;
    pub const SYNTACTIC_ERRORS_IN_PACKET_FILTER: u8 =
        Gtp2Cause::SyntacticErrorsInPacketFilter as u8;
    pub const MISSING_OR_UNKNOWN_APN: u8 = Gtp2Cause::MissingOrUnknownApn as u8;
    pub const GRE_KEY_NOT_FOUND: u8 = Gtp2Cause::GreKeyNotFound as u8;
    pub const RELOCATION_FAILURE: u8 = Gtp2Cause::RelocationFailure as u8;
    pub const DENIED_IN_RAT: u8 = Gtp2Cause::DeniedInRat as u8;
    pub const PREFERRED_PDN_TYPE_NOT_SUPPORTED: u8 = Gtp2Cause::PreferredPdnTypeNotSupported as u8;
    pub const ALL_DYNAMIC_ADDRESSES_ARE_OCCUPIED: u8 =
        Gtp2Cause::AllDynamicAddressesAreOccupied as u8;
    pub const UE_CONTEXT_WITHOUT_TFT_ALREADY_ACTIVATED: u8 =
        Gtp2Cause::UeContextWithoutTftAlreadyActivated as u8;
    pub const PROTOCOL_TYPE_NOT_SUPPORTED: u8 = Gtp2Cause::ProtocolTypeNotSupported as u8;
    pub const UE_NOT_RESPONDING: u8 = Gtp2Cause::UeNotResponding as u8;
    pub const UE_REFUSES: u8 = Gtp2Cause::UeRefuses as u8;
    pub const SERVICE_DENIED: u8 = Gtp2Cause::ServiceDenied as u8;
    pub const UNABLE_TO_PAGE_UE: u8 = Gtp2Cause::UnableToPageUe as u8;
    pub const NO_MEMORY_AVAILABLE: u8 = Gtp2Cause::NoMemoryAvailable as u8;
    pub const USER_AUTHENTICATION_FAILED: u8 = Gtp2Cause::UserAuthenticationFailed as u8;
    pub const APN_ACCESS_DENIED_NO_SUBSCRIPTION: u8 =
        Gtp2Cause::ApnAccessDeniedNoSubscription as u8;
    pub const REQUEST_REJECTED_REASON_NOT_SPECIFIED: u8 =
        Gtp2Cause::RequestRejectedReasonNotSpecified as u8;
    pub const P_TMSI_SIGNATURE_MISMATCH: u8 = Gtp2Cause::PTmsiSignatureMismatch as u8;
    pub const IMSI_IMEI_NOT_KNOWN: u8 = Gtp2Cause::ImsiImeiNotKnown as u8;
    pub const SEMANTIC_ERROR_IN_THE_TAD_OPERATION: u8 =
        Gtp2Cause::SemanticErrorInTheTadOperation as u8;
    pub const SYNTACTIC_ERROR_IN_THE_TAD_OPERATION: u8 =
        Gtp2Cause::SyntacticErrorInTheTadOperation as u8;
    pub const REMOTE_PEER_NOT_RESPONDING: u8 = Gtp2Cause::RemotePeerNotResponding as u8;
    pub const COLLISION_WITH_NETWORK_INITIATED_REQUEST: u8 =
        Gtp2Cause::CollisionWithNetworkInitiatedRequest as u8;
    pub const UNABLE_TO_PAGE_UE_DUE_TO_SUSPENSION: u8 =
        Gtp2Cause::UnableToPageUeDueToSuspension as u8;
    pub const CONDITIONAL_IE_MISSING: u8 = Gtp2Cause::ConditionalIeMissing as u8;
    pub const APN_RESTRICTION_TYPE_INCOMPATIBLE: u8 =
        Gtp2Cause::ApnRestrictionTypeIncompatible as u8;
    pub const INVALID_OVERALL_LENGTH: u8 = Gtp2Cause::InvalidOverallLength as u8;
    pub const DATA_FORWARDING_NOT_SUPPORTED: u8 = Gtp2Cause::DataForwardingNotSupported as u8;
    pub const INVALID_REPLY_FROM_REMOTE_PEER: u8 = Gtp2Cause::InvalidReplyFromRemotePeer as u8;
    pub const FALLBACK_TO_GTPV1: u8 = Gtp2Cause::FallbackToGtpv1 as u8;
    pub const INVALID_PEER: u8 = Gtp2Cause::InvalidPeer as u8;
    pub const TEMPORARILY_REJECTED_DUE_TO_HANDOVER_IN_PROGRESS: u8 =
        Gtp2Cause::TemporarilyRejectedDueToHandoverInProgress as u8;
    pub const MODIFICATIONS_NOT_LIMITED_TO_S1U_BEARERS: u8 =
        Gtp2Cause::ModificationsNotLimitedToS1uBearers as u8;
    pub const REQUEST_REJECTED_FOR_A_PMIPV6_REASON: u8 =
        Gtp2Cause::RequestRejectedForAPmipv6Reason as u8;
    pub const APN_CONGESTION: u8 = Gtp2Cause::ApnCongestion as u8;
    pub const BEARER_HANDLING_NOT_SUPPORTED: u8 = Gtp2Cause::BearerHandlingNotSupported as u8;
    pub const UE_ALREADY_RE_ATTACHED: u8 = Gtp2Cause::UeAlreadyReAttached as u8;
    pub const MULTIPLE_PDN_CONNECTIONS_FOR_A_GIVEN_APN_NOT_ALLOWED: u8 =
        Gtp2Cause::MultiplePdnConnectionsForAGivenApnNotAllowed as u8;
    pub const TARGET_ACCESS_RESTRICTED_FOR_THE_SUBSCRIBER: u8 =
        Gtp2Cause::TargetAccessRestrictedForTheSubscriber as u8;
    pub const MME_SGSN_REFUSES_DUE_TO_VPLMN_POLICY: u8 =
        Gtp2Cause::MmeSgsnRefusesDueToVplmnPolicy as u8;
    pub const GTP_C_ENTITY_CONGESTION: u8 = Gtp2Cause::GtpCEntityCongestion as u8;
    pub const LATE_OVERLAPPING_REQUEST: u8 = Gtp2Cause::LateOverlappingRequest as u8;
    pub const TIMED_OUT_REQUEST: u8 = Gtp2Cause::TimedOutRequest as u8;
    pub const UE_IS_TEMPORARILY_NOT_REACHABLE_DUE_TO_POWER_SAVING: u8 =
        Gtp2Cause::UeIsTemporarilyNotReachableDueToPowerSaving as u8;
    pub const RELOCATION_FAILURE_DUE_TO_NAS_MESSAGE_REDIRECTION: u8 =
        Gtp2Cause::RelocationFailureDueToNasMessageRedirection as u8;
    pub const UE_NOT_AUTHORISED_BY_OCS_OR_EXTERNAL_AAA_SERVER: u8 =
        Gtp2Cause::UeNotAuthorisedByOcsOrExternalAaaServer as u8;
    pub const MULTIPLE_ACCESSES_TO_A_PDN_CONNECTION_NOT_ALLOWED: u8 =
        Gtp2Cause::MultipleAccessesToAPdnConnectionNotAllowed as u8;
    pub const REQUEST_REJECTED_DUE_TO_UE_CAPABILITY: u8 =
        Gtp2Cause::RequestRejectedDueToUeCapability as u8;
    pub const S1U_PATH_FAILURE: u8 = Gtp2Cause::S1uPathFailure as u8;
    pub const FIVE_GC_NOT_ALLOWED: u8 = Gtp2Cause::FiveGcNotAllowed as u8;
    pub const PGW_MISMATCH_WITH_NETWORK_SLICE_SUBSCRIBED_BY_THE_UE: u8 =
        Gtp2Cause::PgwMismatchWithNetworkSliceSubscribedByTheUe as u8;
    pub const REJECTION_DUE_TO_PAGING_RESTRICTION: u8 =
        Gtp2Cause::RejectionDueToPagingRestriction as u8;
}

impl TryFrom<u8> for Gtp2Cause {
    type Error = GtpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::UndefinedValue),
            2 => Ok(Self::LocalDetach),
            3 => Ok(Self::CompleteDetach),
            4 => Ok(Self::RatChangedFrom3gppToNon3gpp),
            5 => Ok(Self::IsrDeactivation),
            6 => Ok(Self::ErrorIndicationReceived),
            7 => Ok(Self::ImsiDetachOnly),
            8 => Ok(Self::ReactivationRequested),
            9 => Ok(Self::PdnReconnectionToThisApnDisallowed),
            10 => Ok(Self::AccessChangedFromNon3gppTo3gpp),
            11 => Ok(Self::PdnConnectionInactivityTimerExpires),
            12 => Ok(Self::PgwNotResponding),
            13 => Ok(Self::NetworkFailure),
            14 => Ok(Self::QosParameterMismatch),
            15 => Ok(Self::EpsTo5gsMobility),
            16 => Ok(Self::RequestAccepted),
            17 => Ok(Self::RequestAcceptedPartially),
            18 => Ok(Self::NewPdnTypeDueToNetworkPreference),
            19 => Ok(Self::NewPdnTypeDueToSingleAddressBearerOnly),
            64 => Ok(Self::ContextNotFound),
            65 => Ok(Self::InvalidMessageFormat),
            66 => Ok(Self::VersionNotSupportedByNextPeer),
            67 => Ok(Self::InvalidLength),
            68 => Ok(Self::ServiceNotSupported),
            69 => Ok(Self::MandatoryIeIncorrect),
            70 => Ok(Self::MandatoryIeMissing),
            72 => Ok(Self::SystemFailure),
            73 => Ok(Self::NoResourcesAvailable),
            74 => Ok(Self::SemanticErrorInTheTftOperation),
            75 => Ok(Self::SyntacticErrorInTheTftOperation),
            76 => Ok(Self::SemanticErrorsInPacketFilter),
            77 => Ok(Self::SyntacticErrorsInPacketFilter),
            78 => Ok(Self::MissingOrUnknownApn),
            80 => Ok(Self::GreKeyNotFound),
            81 => Ok(Self::RelocationFailure),
            82 => Ok(Self::DeniedInRat),
            83 => Ok(Self::PreferredPdnTypeNotSupported),
            84 => Ok(Self::AllDynamicAddressesAreOccupied),
            85 => Ok(Self::UeContextWithoutTftAlreadyActivated),
            86 => Ok(Self::ProtocolTypeNotSupported),
            87 => Ok(Self::UeNotResponding),
            88 => Ok(Self::UeRefuses),
            89 => Ok(Self::ServiceDenied),
            90 => Ok(Self::UnableToPageUe),
            91 => Ok(Self::NoMemoryAvailable),
            92 => Ok(Self::UserAuthenticationFailed),
            93 => Ok(Self::ApnAccessDeniedNoSubscription),
            94 => Ok(Self::RequestRejectedReasonNotSpecified),
            95 => Ok(Self::PTmsiSignatureMismatch),
            96 => Ok(Self::ImsiImeiNotKnown),
            97 => Ok(Self::SemanticErrorInTheTadOperation),
            98 => Ok(Self::SyntacticErrorInTheTadOperation),
            100 => Ok(Self::RemotePeerNotResponding),
            101 => Ok(Self::CollisionWithNetworkInitiatedRequest),
            102 => Ok(Self::UnableToPageUeDueToSuspension),
            103 => Ok(Self::ConditionalIeMissing),
            104 => Ok(Self::ApnRestrictionTypeIncompatible),
            105 => Ok(Self::InvalidOverallLength),
            106 => Ok(Self::DataForwardingNotSupported),
            107 => Ok(Self::InvalidReplyFromRemotePeer),
            108 => Ok(Self::FallbackToGtpv1),
            109 => Ok(Self::InvalidPeer),
            110 => Ok(Self::TemporarilyRejectedDueToHandoverInProgress),
            111 => Ok(Self::ModificationsNotLimitedToS1uBearers),
            112 => Ok(Self::RequestRejectedForAPmipv6Reason),
            113 => Ok(Self::ApnCongestion),
            114 => Ok(Self::BearerHandlingNotSupported),
            115 => Ok(Self::UeAlreadyReAttached),
            116 => Ok(Self::MultiplePdnConnectionsForAGivenApnNotAllowed),
            117 => Ok(Self::TargetAccessRestrictedForTheSubscriber),
            119 => Ok(Self::MmeSgsnRefusesDueToVplmnPolicy),
            120 => Ok(Self::GtpCEntityCongestion),
            121 => Ok(Self::LateOverlappingRequest),
            122 => Ok(Self::TimedOutRequest),
            123 => Ok(Self::UeIsTemporarilyNotReachableDueToPowerSaving),
            124 => Ok(Self::RelocationFailureDueToNasMessageRedirection),
            125 => Ok(Self::UeNotAuthorisedByOcsOrExternalAaaServer),
            126 => Ok(Self::MultipleAccessesToAPdnConnectionNotAllowed),
            127 => Ok(Self::RequestRejectedDueToUeCapability),
            128 => Ok(Self::S1uPathFailure),
            129 => Ok(Self::FiveGcNotAllowed),
            130 => Ok(Self::PgwMismatchWithNetworkSliceSubscribedByTheUe),
            131 => Ok(Self::RejectionDueToPagingRestriction),
            _ => Err(GtpError::InvalidCause(value)),
        }
    }
}

impl Gtp2Cause {
    /// The cause a received octet names, or [`Gtp2Cause::UndefinedValue`] for one
    /// the table leaves spare or reserved.
    pub fn from_wire(value: u8) -> Self {
        Self::try_from(value).unwrap_or(Self::UndefinedValue)
    }

    /// The octet this cause is sent as.
    pub const fn value(self) -> u8 {
        self as u8
    }

    /// Check if cause indicates success
    pub fn is_success(&self) -> bool {
        matches!(
            self,
            Gtp2Cause::RequestAccepted | Gtp2Cause::RequestAcceptedPartially
        )
    }
}

/// GTPv2 Cause IE structure
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gtp2CauseIe {
    /// Cause value
    pub value: u8,
    /// PCE (PDN Connection Error) flag
    pub pce: bool,
    /// BCE (Bearer Context Error) flag
    pub bce: bool,
    /// CS (Cause Source) flag
    pub cs: bool,
}

impl Gtp2CauseIe {
    /// Create new Cause IE
    pub fn new(value: u8) -> Self {
        Self {
            value,
            pce: false,
            bce: false,
            cs: false,
        }
    }

    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.value);
        let flags = ((self.pce as u8) << 2) | ((self.bce as u8) << 1) | (self.cs as u8);
        buf.put_u8(flags);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> GtpResult<Self> {
        if buf.remaining() < 2 {
            return Err(GtpError::BufferTooShort {
                needed: 2,
                available: buf.remaining(),
            });
        }
        let value = buf.get_u8();
        let flags = buf.get_u8();
        Ok(Self {
            value,
            pce: (flags >> 2) & 0x01 != 0,
            bce: (flags >> 1) & 0x01 != 0,
            cs: flags & 0x01 != 0,
        })
    }
}

/// Aggregate Maximum Bit Rate (AMBR)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Gtp2Ambr {
    pub uplink: u32,
    pub downlink: u32,
}

impl Gtp2Ambr {
    pub fn new(uplink: u32, downlink: u32) -> Self {
        Self { uplink, downlink }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.uplink);
        buf.put_u32(self.downlink);
    }

    pub fn decode(buf: &mut Bytes) -> GtpResult<Self> {
        if buf.remaining() < 8 {
            return Err(GtpError::BufferTooShort {
                needed: 8,
                available: buf.remaining(),
            });
        }
        Ok(Self {
            uplink: buf.get_u32(),
            downlink: buf.get_u32(),
        })
    }
}

/// RAT Type values (TS 29.274 Section 8.17)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Gtp2RatType {
    Utran = 1,
    Geran = 2,
    Wlan = 3,
    Gan = 4,
    HspaEvolution = 5,
    Eutran = 6,
    Virtual = 7,
    EutranNbIot = 8,
}

impl TryFrom<u8> for Gtp2RatType {
    type Error = GtpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Utran),
            2 => Ok(Self::Geran),
            3 => Ok(Self::Wlan),
            4 => Ok(Self::Gan),
            5 => Ok(Self::HspaEvolution),
            6 => Ok(Self::Eutran),
            7 => Ok(Self::Virtual),
            8 => Ok(Self::EutranNbIot),
            _ => Err(GtpError::InvalidFormat(format!(
                "Unknown RAT type: {value}"
            ))),
        }
    }
}

/// APN Restriction values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Gtp2ApnRestriction {
    NoRestriction = 0,
    Public1 = 1,
    Public2 = 2,
    Private1 = 3,
    Private2 = 4,
}

/// Selection Mode values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Gtp2SelectionMode {
    MsOrNetworkProvidedApn = 0,
    MsProvidedApn = 1,
    NetworkProvidedApn = 2,
}

/// Node Type values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Gtp2NodeType {
    Mme = 0,
    Sgsn = 1,
}

/// PLMN ID (3 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Gtp2PlmnId {
    pub bytes: [u8; 3],
}

impl Gtp2PlmnId {
    /// Create from MCC and MNC
    pub fn new(mcc: u16, mnc: u16) -> Self {
        let mut bytes = [0u8; 3];
        bytes[0] = ((mcc / 10 % 10) << 4) as u8 | (mcc % 10) as u8;
        let mnc3 = if mnc > 99 { mnc / 100 } else { 0x0F };
        bytes[1] = ((mnc3 as u8) << 4) | ((mcc / 100) as u8);
        bytes[2] = ((mnc / 10 % 10) << 4) as u8 | (mnc % 10) as u8;
        Self { bytes }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(&self.bytes);
    }

    pub fn decode(buf: &mut Bytes) -> GtpResult<Self> {
        if buf.remaining() < 3 {
            return Err(GtpError::BufferTooShort {
                needed: 3,
                available: buf.remaining(),
            });
        }
        let mut bytes = [0u8; 3];
        buf.copy_to_slice(&mut bytes);
        Ok(Self { bytes })
    }
}

/// User Location Information - TAI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Gtp2UliTai {
    pub plmn_id: Gtp2PlmnId,
    pub tac: u16,
}

/// User Location Information - E-CGI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Gtp2UliEcgi {
    pub plmn_id: Gtp2PlmnId,
    pub cell_id: u32,
}

/// User Location Information flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Gtp2UliFlags {
    pub cgi: bool,
    pub sai: bool,
    pub rai: bool,
    pub tai: bool,
    pub e_cgi: bool,
    pub lai: bool,
    pub enodeb_id: bool,
    pub ext_enodeb_id: bool,
}

impl Gtp2UliFlags {
    pub fn encode(&self) -> u8 {
        ((self.ext_enodeb_id as u8) << 7)
            | ((self.enodeb_id as u8) << 6)
            | ((self.lai as u8) << 5)
            | ((self.e_cgi as u8) << 4)
            | ((self.tai as u8) << 3)
            | ((self.rai as u8) << 2)
            | ((self.sai as u8) << 1)
            | (self.cgi as u8)
    }

    pub fn decode(byte: u8) -> Self {
        Self {
            cgi: byte & 0x01 != 0,
            sai: (byte >> 1) & 0x01 != 0,
            rai: (byte >> 2) & 0x01 != 0,
            tai: (byte >> 3) & 0x01 != 0,
            e_cgi: (byte >> 4) & 0x01 != 0,
            lai: (byte >> 5) & 0x01 != 0,
            enodeb_id: (byte >> 6) & 0x01 != 0,
            ext_enodeb_id: (byte >> 7) & 0x01 != 0,
        }
    }
}

/// F-TEID Interface Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Gtp2FTeidInterfaceType {
    S1uEnodebGtpU = 0,
    S1uSgwGtpU = 1,
    S12RncGtpU = 2,
    S12SgwGtpU = 3,
    S5S8SgwGtpU = 4,
    S5S8PgwGtpU = 5,
    S5S8SgwGtpC = 6,
    S5S8PgwGtpC = 7,
    S5S8SgwPmipv6 = 8,
    S5S8PgwPmipv6 = 9,
    S11MmeGtpC = 10,
    S11S4SgwGtpC = 11,
    S10MmeGtpC = 12,
    S3MmeGtpC = 13,
    S3SgsnGtpC = 14,
    S4SgsnGtpU = 15,
    S4SgwGtpU = 16,
    S4SgsnGtpC = 17,
    S16SgsnGtpC = 18,
    EnodebGtpUForDlDataForwarding = 19,
    EnodebGtpUForUlDataForwarding = 20,
    RncGtpUForDataForwarding = 21,
    SgsnGtpUForDataForwarding = 22,
    SgwGtpUForDlDataForwarding = 23,
    SmMbmsGwGtpC = 24,
    SnMbmsGwGtpC = 25,
    SmMmeGtpC = 26,
    SnSgsnGtpC = 27,
    SgwGtpUForUlDataForwarding = 28,
    SnSgsnGtpU = 29,
    S2bEpdgGtpC = 30,
    S2bUEpdgGtpU = 31,
    S2bPgwGtpC = 32,
    S2bUPgwGtpU = 33,
    S2aTwanGtpU = 34,
    S2aTwanGtpC = 35,
    S2aPgwGtpC = 36,
    S2aPgwGtpU = 37,
    S11MmeGtpU = 38,
    S11SgwGtpU = 39,
}

/// F-TEID header length
pub const GTP2_F_TEID_HDR_LEN: usize = 5;
/// F-TEID IPv4 length
pub const GTP2_F_TEID_IPV4_LEN: usize = 4 + GTP2_F_TEID_HDR_LEN;
/// F-TEID IPv6 length
pub const GTP2_F_TEID_IPV6_LEN: usize = 16 + GTP2_F_TEID_HDR_LEN;
/// F-TEID IPv4v6 length
pub const GTP2_F_TEID_IPV4V6_LEN: usize = 20 + GTP2_F_TEID_HDR_LEN;

/// Fully Qualified TEID (F-TEID)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtp2FTeid {
    pub ipv4: bool,
    pub ipv6: bool,
    pub interface_type: u8,
    pub teid: u32,
    pub ipv4_addr: Option<[u8; 4]>,
    pub ipv6_addr: Option<[u8; 16]>,
}

impl Gtp2FTeid {
    pub fn new_ipv4(interface_type: u8, teid: u32, addr: [u8; 4]) -> Self {
        Self {
            ipv4: true,
            ipv6: false,
            interface_type,
            teid,
            ipv4_addr: Some(addr),
            ipv6_addr: None,
        }
    }

    pub fn new_ipv6(interface_type: u8, teid: u32, addr: [u8; 16]) -> Self {
        Self {
            ipv4: false,
            ipv6: true,
            interface_type,
            teid,
            ipv4_addr: None,
            ipv6_addr: Some(addr),
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let flags =
            ((self.ipv4 as u8) << 7) | ((self.ipv6 as u8) << 6) | (self.interface_type & 0x3F);
        buf.put_u8(flags);
        buf.put_u32(self.teid);
        if let Some(addr) = &self.ipv4_addr {
            buf.put_slice(addr);
        }
        if let Some(addr) = &self.ipv6_addr {
            buf.put_slice(addr);
        }
    }

    pub fn decode(buf: &mut Bytes) -> GtpResult<Self> {
        if buf.remaining() < 5 {
            return Err(GtpError::BufferTooShort {
                needed: 5,
                available: buf.remaining(),
            });
        }
        let flags = buf.get_u8();
        let ipv4 = (flags >> 7) & 0x01 != 0;
        let ipv6 = (flags >> 6) & 0x01 != 0;
        let interface_type = flags & 0x3F;
        let teid = buf.get_u32();

        let ipv4_addr = if ipv4 {
            if buf.remaining() < 4 {
                return Err(GtpError::BufferTooShort {
                    needed: 4,
                    available: buf.remaining(),
                });
            }
            let mut addr = [0u8; 4];
            buf.copy_to_slice(&mut addr);
            Some(addr)
        } else {
            None
        };

        let ipv6_addr = if ipv6 {
            if buf.remaining() < 16 {
                return Err(GtpError::BufferTooShort {
                    needed: 16,
                    available: buf.remaining(),
                });
            }
            let mut addr = [0u8; 16];
            buf.copy_to_slice(&mut addr);
            Some(addr)
        } else {
            None
        };

        Ok(Self {
            ipv4,
            ipv6,
            interface_type,
            teid,
            ipv4_addr,
            ipv6_addr,
        })
    }
}

/// UE Time Zone
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Gtp2UeTimeZone {
    pub timezone: u8,
    pub daylight_saving_time: u8,
}

/// Daylight Saving Time values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Gtp2DaylightSavingTime {
    NoAdjustment = 0,
    OneHour = 1,
    TwoHours = 2,
}

/// Allocation/Retention Priority (ARP)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Gtp2Arp {
    pub pre_emption_vulnerability: bool,
    pub priority_level: u8,
    pub pre_emption_capability: bool,
}

impl Gtp2Arp {
    pub fn encode(&self) -> u8 {
        ((self.pre_emption_vulnerability as u8) << 6)
            | ((self.priority_level & 0x0F) << 2)
            | (self.pre_emption_capability as u8)
    }

    pub fn decode(byte: u8) -> Self {
        Self {
            pre_emption_vulnerability: (byte >> 6) & 0x01 != 0,
            priority_level: (byte >> 2) & 0x0F,
            pre_emption_capability: byte & 0x01 != 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Gtp2Cause as C;

    /// #1024 / #1037: every cause against TS 29.274 Table 8.4-1, as the literal
    /// octet the table gives it; and every defined octet decodes to its cause.
    #[test]
    fn every_cause_is_its_table_8_4_1_value() {
        let table: &[(C, u8)] = &[
            (C::UndefinedValue, 0),
            (C::LocalDetach, 2),
            (C::CompleteDetach, 3),
            (C::RatChangedFrom3gppToNon3gpp, 4),
            (C::IsrDeactivation, 5),
            (C::ErrorIndicationReceived, 6),
            (C::ImsiDetachOnly, 7),
            (C::ReactivationRequested, 8),
            (C::PdnReconnectionToThisApnDisallowed, 9),
            (C::AccessChangedFromNon3gppTo3gpp, 10),
            (C::PdnConnectionInactivityTimerExpires, 11),
            (C::PgwNotResponding, 12),
            (C::NetworkFailure, 13),
            (C::QosParameterMismatch, 14),
            (C::EpsTo5gsMobility, 15),
            (C::RequestAccepted, 16),
            (C::RequestAcceptedPartially, 17),
            (C::NewPdnTypeDueToNetworkPreference, 18),
            (C::NewPdnTypeDueToSingleAddressBearerOnly, 19),
            (C::ContextNotFound, 64),
            (C::InvalidMessageFormat, 65),
            (C::VersionNotSupportedByNextPeer, 66),
            (C::InvalidLength, 67),
            (C::ServiceNotSupported, 68),
            (C::MandatoryIeIncorrect, 69),
            (C::MandatoryIeMissing, 70),
            (C::SystemFailure, 72),
            (C::NoResourcesAvailable, 73),
            (C::SemanticErrorInTheTftOperation, 74),
            (C::SyntacticErrorInTheTftOperation, 75),
            (C::SemanticErrorsInPacketFilter, 76),
            (C::SyntacticErrorsInPacketFilter, 77),
            (C::MissingOrUnknownApn, 78),
            (C::GreKeyNotFound, 80),
            (C::RelocationFailure, 81),
            (C::DeniedInRat, 82),
            (C::PreferredPdnTypeNotSupported, 83),
            (C::AllDynamicAddressesAreOccupied, 84),
            (C::UeContextWithoutTftAlreadyActivated, 85),
            (C::ProtocolTypeNotSupported, 86),
            (C::UeNotResponding, 87),
            (C::UeRefuses, 88),
            (C::ServiceDenied, 89),
            (C::UnableToPageUe, 90),
            (C::NoMemoryAvailable, 91),
            (C::UserAuthenticationFailed, 92),
            (C::ApnAccessDeniedNoSubscription, 93),
            (C::RequestRejectedReasonNotSpecified, 94),
            (C::PTmsiSignatureMismatch, 95),
            (C::ImsiImeiNotKnown, 96),
            (C::SemanticErrorInTheTadOperation, 97),
            (C::SyntacticErrorInTheTadOperation, 98),
            (C::RemotePeerNotResponding, 100),
            (C::CollisionWithNetworkInitiatedRequest, 101),
            (C::UnableToPageUeDueToSuspension, 102),
            (C::ConditionalIeMissing, 103),
            (C::ApnRestrictionTypeIncompatible, 104),
            (C::InvalidOverallLength, 105),
            (C::DataForwardingNotSupported, 106),
            (C::InvalidReplyFromRemotePeer, 107),
            (C::FallbackToGtpv1, 108),
            (C::InvalidPeer, 109),
            (C::TemporarilyRejectedDueToHandoverInProgress, 110),
            (C::ModificationsNotLimitedToS1uBearers, 111),
            (C::RequestRejectedForAPmipv6Reason, 112),
            (C::ApnCongestion, 113),
            (C::BearerHandlingNotSupported, 114),
            (C::UeAlreadyReAttached, 115),
            (C::MultiplePdnConnectionsForAGivenApnNotAllowed, 116),
            (C::TargetAccessRestrictedForTheSubscriber, 117),
            (C::MmeSgsnRefusesDueToVplmnPolicy, 119),
            (C::GtpCEntityCongestion, 120),
            (C::LateOverlappingRequest, 121),
            (C::TimedOutRequest, 122),
            (C::UeIsTemporarilyNotReachableDueToPowerSaving, 123),
            (C::RelocationFailureDueToNasMessageRedirection, 124),
            (C::UeNotAuthorisedByOcsOrExternalAaaServer, 125),
            (C::MultipleAccessesToAPdnConnectionNotAllowed, 126),
            (C::RequestRejectedDueToUeCapability, 127),
            (C::S1uPathFailure, 128),
            (C::FiveGcNotAllowed, 129),
            (C::PgwMismatchWithNetworkSliceSubscribedByTheUe, 130),
            (C::RejectionDueToPagingRestriction, 131),
        ];
        for (cause, octet) in table {
            assert_eq!(cause.value(), *octet, "{cause:?}");
            assert_eq!(C::from_wire(*octet), *cause, "octet {octet}");
        }
        // Spare / "shall not be used" values read as undefined.
        for spare in [1u8, 20, 63, 71, 79, 99, 118, 132, 255] {
            assert_eq!(C::from_wire(spare), C::UndefinedValue, "octet {spare}");
        }
    }
}
