//! GTPv1 Types
//!
//! Types and constants for GTPv1 protocol as specified in 3GPP TS 29.060.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::error::{GtpError, GtpResult};

/// GTPv1 Extension Header Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExtensionHeaderType {
    /// No more extension headers
    NoMoreExtensionHeaders = 0x00,
    /// UDP Port
    UdpPort = 0x40,
    /// PDU Session Container
    PduSessionContainer = 0x85,
}

impl TryFrom<u8> for ExtensionHeaderType {
    type Error = GtpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(ExtensionHeaderType::NoMoreExtensionHeaders),
            0x40 => Ok(ExtensionHeaderType::UdpPort),
            0x85 => Ok(ExtensionHeaderType::PduSessionContainer),
            _ => Err(GtpError::InvalidFormat(format!("Unknown extension header type: {value:#x}"))),
        }
    }
}

/// PDU Type for Extension Header
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PduType {
    /// DL PDU Session Information
    DlPduSessionInformation = 0,
    /// UL PDU Session Information
    UlPduSessionInformation = 1,
}

impl TryFrom<u8> for PduType {
    type Error = GtpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PduType::DlPduSessionInformation),
            1 => Ok(PduType::UlPduSessionInformation),
            _ => Err(GtpError::InvalidFormat(format!("Unknown PDU type: {value}"))),
        }
    }
}

/// GTPv1 Extension Header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionHeader {
    /// Sequence number
    pub sequence_number: u16,
    /// N-PDU number
    pub n_pdu_number: u8,
    /// Extension header type
    pub header_type: u8,
    /// Extension header length (in 4-byte units)
    pub length: u8,
    /// PDU type (4 bits)
    pub pdu_type: u8,
    /// Paging policy presence (1 bit)
    pub paging_policy_presence: bool,
    /// Reflective QoS indicator (1 bit)
    pub reflective_qos_indicator: bool,
    /// QoS Flow Identifier (6 bits)
    pub qos_flow_identifier: u8,
    /// Next extension header type
    pub next_type: u8,
}

impl Default for ExtensionHeader {
    fn default() -> Self {
        Self {
            sequence_number: 0,
            n_pdu_number: 0,
            header_type: ExtensionHeaderType::NoMoreExtensionHeaders as u8,
            length: 0,
            pdu_type: 0,
            paging_policy_presence: false,
            reflective_qos_indicator: false,
            qos_flow_identifier: 0,
            next_type: 0,
        }
    }
}

impl ExtensionHeader {
    /// Encode extension header to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u16(self.sequence_number);
        buf.put_u8(self.n_pdu_number);
        buf.put_u8(self.header_type);
        buf.put_u8(self.length);
        
        // PDU type (4 bits) | spare (4 bits)
        buf.put_u8((self.pdu_type & 0x0F) << 4);
        
        // Paging policy presence (1 bit) | Reflective QoS indicator (1 bit) | QFI (6 bits)
        let byte = ((self.paging_policy_presence as u8) << 7)
            | ((self.reflective_qos_indicator as u8) << 6)
            | (self.qos_flow_identifier & 0x3F);
        buf.put_u8(byte);
        
        buf.put_u8(self.next_type);
    }

    /// Decode extension header from bytes
    pub fn decode(buf: &mut Bytes) -> GtpResult<Self> {
        if buf.remaining() < 8 {
            return Err(GtpError::BufferTooShort {
                needed: 8,
                available: buf.remaining(),
            });
        }

        let sequence_number = buf.get_u16();
        let n_pdu_number = buf.get_u8();
        let header_type = buf.get_u8();
        let length = buf.get_u8();
        
        let pdu_byte = buf.get_u8();
        let pdu_type = (pdu_byte >> 4) & 0x0F;
        
        let qfi_byte = buf.get_u8();
        let paging_policy_presence = (qfi_byte >> 7) & 0x01 != 0;
        let reflective_qos_indicator = (qfi_byte >> 6) & 0x01 != 0;
        let qos_flow_identifier = qfi_byte & 0x3F;
        
        let next_type = buf.get_u8();

        Ok(Self {
            sequence_number,
            n_pdu_number,
            header_type,
            length,
            pdu_type,
            paging_policy_presence,
            reflective_qos_indicator,
            qos_flow_identifier,
            next_type,
        })
    }
}

impl ExtensionHeader {
    /// Map QFI to DSCP value per 3GPP TS 23.501 Table 5.7.4-1 (Rel-18).
    ///
    /// Maps QoS Flow Identifier to DiffServ Code Point for transport-level
    /// QoS enforcement in outer IP header of GTP-U tunnel.
    pub fn qfi_to_dscp(qfi: u8) -> u8 {
        match qfi {
            // GBR flows: Conversational voice/video
            1 => 46, // EF (Expedited Forwarding)
            2 => 34, // AF41
            3 => 26, // AF31
            4 => 24, // AF21 (non-conversational video)
            // Non-GBR flows
            5 => 0,  // Best Effort (IMS signaling uses CS0)
            6 => 18, // AF21 (buffered video streaming)
            7 => 10, // AF11 (interactive gaming)
            8 => 10, // AF11 (TCP-based)
            9 => 0,  // BE (default)
            // Rel-18 XR 5QI values mapped to QFI ranges
            82 => 46, // XR cloud rendering DL -> EF
            83 => 46, // XR pose/control UL -> EF
            84 => 34, // XR split rendering DL -> AF41
            85 => 46, // XR haptic feedback -> EF
            _ => 0,   // Unknown -> Best Effort
        }
    }

    /// Map 5QI to QFI→DSCP (convenience for SMF/PCF use).
    pub fn five_qi_to_dscp(five_qi: u8) -> u8 {
        Self::qfi_to_dscp(five_qi)
    }
}

/// GTPv1 Cause Values (TS 29.060 Table 38)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Cause {
    // Request causes (0-127)
    RequestImsi = 0,
    RequestImei = 1,
    RequestImsiImei = 2,
    NoIdNeeded = 3,
    MsRefuses = 4,
    MsNotGprsResponding = 5,
    ReactivationRequested = 6,
    PdpAddressInactivityTimerExp = 7,
    NetworkFailure = 8,
    QosParameterMismatch = 9,
    
    // Acceptance causes (128-191)
    RequestAccepted = 128,
    NewPdpTypeDueToNetworkPreference = 129,
    NewPdpTypeDueToSingleAddressBearerOnly = 130,
    
    // Rejection causes (192-255)
    NonExistent = 192,
    InvalidMessageFormat = 193,
    ImsiImeiNotKnown = 194,
    MsGprsDetached = 195,
    RejMsNotGprsResponding = 196,
    RejMsRefuses = 197,
    VersionNotSupported = 198,
    NoResourcesAvailable = 199,
    ServiceNotSupported = 200,
    MandatoryIeIncorrect = 201,
    MandatoryIeMissing = 202,
    OptionalIeIncorrect = 203,
    SystemFailure = 204,
    RoamingRestriction = 205,
    PTmsiSignatureMismatch = 206,
    GprsConnSuspended = 207,
    AuthenticationFailure = 208,
    UserAuthenticationFailed = 209,
    ContextNotFound = 210,
    AllDynamicPdpAddrsOccupied = 211,
    NoMemoryAvailable = 212,
    RelocationFailure = 213,
    UnknownMandatoryExtensionHeader = 214,
    SemanticErrTftOperation = 215,
    SyntacticErrTftOperation = 216,
    SemanticErrPktFilter = 217,
    SyntacticErrPktFilter = 218,
    MissingOrUnknownApn = 219,
    UnknownPdpAddrOrType = 220,
    PdpContextWithoutTftActivated = 221,
    ApnAccessDenied = 222,
    ApnIncompatibleWithActivePdpContexts = 223,
    MsMbmsCapInsufficient = 224,
    InvalidCorrelationId = 225,
    MbmsBearerContextSuperseded = 226,
    BearerControlModeViolation = 227,
    CollisionWithNetInitiatedReq = 228,
    ApnCongestion = 229,
    BearerHandlingNotSupported = 230,
    TgtAccRestrictedSubscriber = 231,
    UeTmpNotReachablePowerSaving = 232,
    RelocationFailureNasMsgRedir = 233,
}

impl TryFrom<u8> for Cause {
    type Error = GtpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Cause::RequestImsi),
            1 => Ok(Cause::RequestImei),
            2 => Ok(Cause::RequestImsiImei),
            3 => Ok(Cause::NoIdNeeded),
            4 => Ok(Cause::MsRefuses),
            5 => Ok(Cause::MsNotGprsResponding),
            6 => Ok(Cause::ReactivationRequested),
            7 => Ok(Cause::PdpAddressInactivityTimerExp),
            8 => Ok(Cause::NetworkFailure),
            9 => Ok(Cause::QosParameterMismatch),
            128 => Ok(Cause::RequestAccepted),
            129 => Ok(Cause::NewPdpTypeDueToNetworkPreference),
            130 => Ok(Cause::NewPdpTypeDueToSingleAddressBearerOnly),
            192 => Ok(Cause::NonExistent),
            193 => Ok(Cause::InvalidMessageFormat),
            194 => Ok(Cause::ImsiImeiNotKnown),
            195 => Ok(Cause::MsGprsDetached),
            196 => Ok(Cause::RejMsNotGprsResponding),
            197 => Ok(Cause::RejMsRefuses),
            198 => Ok(Cause::VersionNotSupported),
            199 => Ok(Cause::NoResourcesAvailable),
            200 => Ok(Cause::ServiceNotSupported),
            201 => Ok(Cause::MandatoryIeIncorrect),
            202 => Ok(Cause::MandatoryIeMissing),
            203 => Ok(Cause::OptionalIeIncorrect),
            204 => Ok(Cause::SystemFailure),
            205 => Ok(Cause::RoamingRestriction),
            206 => Ok(Cause::PTmsiSignatureMismatch),
            207 => Ok(Cause::GprsConnSuspended),
            208 => Ok(Cause::AuthenticationFailure),
            209 => Ok(Cause::UserAuthenticationFailed),
            210 => Ok(Cause::ContextNotFound),
            211 => Ok(Cause::AllDynamicPdpAddrsOccupied),
            212 => Ok(Cause::NoMemoryAvailable),
            213 => Ok(Cause::RelocationFailure),
            214 => Ok(Cause::UnknownMandatoryExtensionHeader),
            215 => Ok(Cause::SemanticErrTftOperation),
            216 => Ok(Cause::SyntacticErrTftOperation),
            217 => Ok(Cause::SemanticErrPktFilter),
            218 => Ok(Cause::SyntacticErrPktFilter),
            219 => Ok(Cause::MissingOrUnknownApn),
            220 => Ok(Cause::UnknownPdpAddrOrType),
            221 => Ok(Cause::PdpContextWithoutTftActivated),
            222 => Ok(Cause::ApnAccessDenied),
            223 => Ok(Cause::ApnIncompatibleWithActivePdpContexts),
            224 => Ok(Cause::MsMbmsCapInsufficient),
            225 => Ok(Cause::InvalidCorrelationId),
            226 => Ok(Cause::MbmsBearerContextSuperseded),
            227 => Ok(Cause::BearerControlModeViolation),
            228 => Ok(Cause::CollisionWithNetInitiatedReq),
            229 => Ok(Cause::ApnCongestion),
            230 => Ok(Cause::BearerHandlingNotSupported),
            231 => Ok(Cause::TgtAccRestrictedSubscriber),
            232 => Ok(Cause::UeTmpNotReachablePowerSaving),
            233 => Ok(Cause::RelocationFailureNasMsgRedir),
            _ => Err(GtpError::InvalidCause(value)),
        }
    }
}

impl Cause {
    /// Check if cause indicates acceptance (0x80 bit set, 0xC0 not set)
    pub fn is_accept(&self) -> bool {
        let value = *self as u8;
        (value & 0x80) != 0 && (value & 0xC0) != 0xC0
    }

    /// Check if cause indicates rejection (0xC0 bits set)
    pub fn is_reject(&self) -> bool {
        let value = *self as u8;
        (value & 0xC0) == 0xC0
    }
}

/// GTPv1 Cause IE structure
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CauseIe {
    /// Cause value
    pub value: u8,
    /// PCE (PDN Connection Error) flag
    pub pce: bool,
    /// BCE (Bearer Context Error) flag
    pub bce: bool,
    /// CS (Cause Source) flag
    pub cs: bool,
}

impl CauseIe {
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

/// RAT Type values (TS 29.060 Table 7.7.50.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RatType {
    Reserved = 0,
    Utran = 1,
    Geran = 2,
    Wlan = 3,
    Gan = 4,
    HspaEvolution = 5,
    Eutran = 6,
}

impl TryFrom<u8> for RatType {
    type Error = GtpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(RatType::Reserved),
            1 => Ok(RatType::Utran),
            2 => Ok(RatType::Geran),
            3 => Ok(RatType::Wlan),
            4 => Ok(RatType::Gan),
            5 => Ok(RatType::HspaEvolution),
            6 => Ok(RatType::Eutran),
            _ => Err(GtpError::InvalidFormat(format!("Unknown RAT type: {value}"))),
        }
    }
}

/// Geographic Location Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GeoLocType {
    Cgi = 0,
    Sai = 1,
    Rai = 2,
}

/// PLMN ID (3 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PlmnId {
    pub bytes: [u8; 3],
}

impl PlmnId {
    /// Create from MCC and MNC
    pub fn new(mcc: u16, mnc: u16) -> Self {
        let mut bytes = [0u8; 3];
        // MCC digit 2 | MCC digit 1
        bytes[0] = ((mcc / 10 % 10) << 4) as u8 | (mcc % 10) as u8;
        // MNC digit 3 | MCC digit 3
        let mnc3 = if mnc > 99 { mnc / 100 } else { 0x0F };
        bytes[1] = ((mnc3 as u8) << 4) | ((mcc / 100) as u8);
        // MNC digit 2 | MNC digit 1
        bytes[2] = ((mnc / 10 % 10) << 4) as u8 | (mnc % 10) as u8;
        Self { bytes }
    }

    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(&self.bytes);
    }

    /// Decode from bytes
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

/// User Location Information - CGI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UliCgi {
    pub plmn_id: PlmnId,
    pub lac: u16,
    pub ci: u16,
}

/// User Location Information - SAI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UliSai {
    pub plmn_id: PlmnId,
    pub lac: u16,
    pub sac: u16,
}

/// User Location Information - RAI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UliRai {
    pub plmn_id: PlmnId,
    pub lac: u16,
    pub rac: u16,
}

/// User Location Information
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Uli {
    Cgi(UliCgi),
    Sai(UliSai),
    Rai(UliRai),
}

impl Uli {
    /// Encode ULI to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            Uli::Cgi(cgi) => {
                buf.put_u8(GeoLocType::Cgi as u8);
                cgi.plmn_id.encode(buf);
                buf.put_u16(cgi.lac);
                buf.put_u16(cgi.ci);
            }
            Uli::Sai(sai) => {
                buf.put_u8(GeoLocType::Sai as u8);
                sai.plmn_id.encode(buf);
                buf.put_u16(sai.lac);
                buf.put_u16(sai.sac);
            }
            Uli::Rai(rai) => {
                buf.put_u8(GeoLocType::Rai as u8);
                rai.plmn_id.encode(buf);
                buf.put_u16(rai.lac);
                buf.put_u16(rai.rac);
            }
        }
    }

    /// Decode ULI from bytes
    pub fn decode(buf: &mut Bytes) -> GtpResult<Self> {
        if buf.remaining() < 8 {
            return Err(GtpError::BufferTooShort {
                needed: 8,
                available: buf.remaining(),
            });
        }

        let geo_loc_type = buf.get_u8();
        let plmn_id = PlmnId::decode(buf)?;
        let lac = buf.get_u16();
        let value = buf.get_u16();

        match geo_loc_type {
            0 => Ok(Uli::Cgi(UliCgi { plmn_id, lac, ci: value })),
            1 => Ok(Uli::Sai(UliSai { plmn_id, lac, sac: value })),
            2 => Ok(Uli::Rai(UliRai { plmn_id, lac, rac: value })),
            _ => Err(GtpError::InvalidFormat(format!("Unknown geo location type: {geo_loc_type}"))),
        }
    }
}

/// GSN Address (IPv4 or IPv6)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GsnAddress {
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
}

impl GsnAddress {
    /// Encode GSN address to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            GsnAddress::Ipv4(addr) => buf.put_slice(addr),
            GsnAddress::Ipv6(addr) => buf.put_slice(addr),
        }
    }

    /// Decode GSN address from bytes (length determines type)
    pub fn decode(buf: &mut Bytes, len: usize) -> GtpResult<Self> {
        match len {
            4 => {
                if buf.remaining() < 4 {
                    return Err(GtpError::BufferTooShort {
                        needed: 4,
                        available: buf.remaining(),
                    });
                }
                let mut addr = [0u8; 4];
                buf.copy_to_slice(&mut addr);
                Ok(GsnAddress::Ipv4(addr))
            }
            16 => {
                if buf.remaining() < 16 {
                    return Err(GtpError::BufferTooShort {
                        needed: 16,
                        available: buf.remaining(),
                    });
                }
                let mut addr = [0u8; 16];
                buf.copy_to_slice(&mut addr);
                Ok(GsnAddress::Ipv6(addr))
            }
            _ => Err(GtpError::InvalidFormat(format!("Invalid GSN address length: {len}"))),
        }
    }
}

/// APN Restriction values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ApnRestriction {
    NoRestriction = 0,
    Public1 = 1,
    Public2 = 2,
    Private1 = 3,
    Private2 = 4,
}

/// Delivery Order values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeliveryOrder {
    Subscribed = 0,
    Yes = 1,
    No = 2,
}

/// Delivery of Erroneous SDUs values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeliveryErrSdu {
    Subscribed = 0,
    NoDetect = 1,
    Yes = 2,
    No = 3,
}

/// QoS Traffic Class values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum QosTrafficClass {
    Subscribed = 0,
    Conversational = 1,
    Streaming = 2,
    Interactive = 3,
    Background = 4,
}

/// QoS Source Statistics Descriptor values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum QosSrcStatsDesc {
    Unknown = 0,
    Speech = 1,
}

/// Common Flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CommonFlags {
    pub dual_address_bearer_flag: bool,
    pub upgrade_qos_supported: bool,
    pub nrsn: bool,
    pub no_qos_negotiation: bool,
    pub mbms_counting_information: bool,
    pub ran_procedures_ready: bool,
    pub mbms_service_type: bool,
    pub prohibit_payload_compression: bool,
}

impl CommonFlags {
    /// Encode to byte
    pub fn encode(&self) -> u8 {
        ((self.dual_address_bearer_flag as u8) << 7)
            | ((self.upgrade_qos_supported as u8) << 6)
            | ((self.nrsn as u8) << 5)
            | ((self.no_qos_negotiation as u8) << 4)
            | ((self.mbms_counting_information as u8) << 3)
            | ((self.ran_procedures_ready as u8) << 2)
            | ((self.mbms_service_type as u8) << 1)
            | (self.prohibit_payload_compression as u8)
    }

    /// Decode from byte
    pub fn decode(byte: u8) -> Self {
        Self {
            dual_address_bearer_flag: (byte >> 7) & 0x01 != 0,
            upgrade_qos_supported: (byte >> 6) & 0x01 != 0,
            nrsn: (byte >> 5) & 0x01 != 0,
            no_qos_negotiation: (byte >> 4) & 0x01 != 0,
            mbms_counting_information: (byte >> 3) & 0x01 != 0,
            ran_procedures_ready: (byte >> 2) & 0x01 != 0,
            mbms_service_type: (byte >> 1) & 0x01 != 0,
            prohibit_payload_compression: byte & 0x01 != 0,
        }
    }
}

/// APN-AMBR (Aggregate Maximum Bit Rate)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ApnAmbr {
    pub uplink: u32,
    pub downlink: u32,
}

impl ApnAmbr {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.uplink);
        buf.put_u32(self.downlink);
    }

    /// Decode from bytes
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

/// Tunnel Endpoint Identifier Data II
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TeidII {
    pub nsapi: u8,
    pub teid: u32,
}

impl TeidII {
    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.nsapi & 0x0F);
        buf.put_u32(self.teid);
    }

    /// Decode from bytes
    pub fn decode(buf: &mut Bytes) -> GtpResult<Self> {
        if buf.remaining() < 5 {
            return Err(GtpError::BufferTooShort {
                needed: 5,
                available: buf.remaining(),
            });
        }
        Ok(Self {
            nsapi: buf.get_u8() & 0x0F,
            teid: buf.get_u32(),
        })
    }
}
