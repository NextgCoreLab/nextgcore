//! GTPv2 Types
//!
//! Types and constants for GTPv2 protocol as specified in 3GPP TS 29.274.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::error::{GtpError, GtpResult};

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

/// GTPv2 Cause Values (TS 29.274 Section 8.4)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Gtp2Cause {
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
            _ => Err(GtpError::InvalidCause(value)),
        }
    }
}

impl Gtp2Cause {
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
            _ => Err(GtpError::InvalidFormat(format!("Unknown RAT type: {value}"))),
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
        let flags = ((self.ipv4 as u8) << 7) | ((self.ipv6 as u8) << 6) | (self.interface_type & 0x3F);
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
