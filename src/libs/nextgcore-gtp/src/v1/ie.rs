//! GTPv1 Information Elements
//!
//! Information Element types and encoding/decoding for GTPv1 protocol.

use crate::error::{GtpError, GtpResult};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// GTPv1 IE Types (TV format - Type-Value, fixed length)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Gtp1IeTypeTv {
    Cause = 1,
    Imsi = 2,
    Rai = 3,
    Tlli = 4,
    PTmsi = 5,
    ReorderingRequired = 8,
    AuthenticationTriplet = 9,
    MapCause = 11,
    PTmsiSignature = 12,
    MsValidated = 13,
    Recovery = 14,
    SelectionMode = 15,
    TunnelEndpointIdentifierDataI = 16,
    TunnelEndpointIdentifierControlPlane = 17,
    TunnelEndpointIdentifierDataII = 18,
    TeardownInd = 19,
    Nsapi = 20,
    RanapCause = 21,
    RabContext = 22,
    RadioPrioritySms = 23,
    RadioPriority = 24,
    PacketFlowId = 25,
    ChargingCharacteristics = 26,
    TraceReference = 27,
    TraceType = 28,
    MsNotReachableReason = 29,
    ChargingId = 127,
}

/// GTPv1 IE Types (TLV format - Type-Length-Value, variable length)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Gtp1IeTypeTlv {
    EndUserAddress = 128,
    MmContext = 129,
    PdpContext = 130,
    AccessPointName = 131,
    ProtocolConfigurationOptions = 132,
    GsnAddress = 133,
    Msisdn = 134,
    QualityOfServiceProfile = 135,
    AuthenticationQuintuplet = 136,
    TrafficFlowTemplate = 137,
    TargetIdentification = 138,
    UtranTransparentContainer = 139,
    RabSetupInformation = 140,
    ExtensionHeaderTypeList = 141,
    TriggerId = 142,
    OmcIdentity = 143,
    RanTransparentContainer = 144,
    PdpContextPrioritization = 145,
    AdditionalRabSetupInformation = 146,
    SgsnNumber = 147,
    CommonFlags = 148,
    ApnRestriction = 149,
    RadioPriorityLcs = 150,
    RatType = 151,
    UserLocationInformation = 152,
    MsTimeZone = 153,
    Sv = 154,
    CamelChargingInformationContainer = 155,
    MbmsUeContext = 156,
    Tmgi = 157,
    RimRoutingAddress = 158,
    MbmsProtocolConfigurationOptions = 159,
    MbmsServiceArea = 160,
    SourceRncPdcpContextInfo = 161,
    AdditionalTraceInfo = 162,
    HopCounter = 163,
    SelectedPlmnId = 164,
    MbmsSessionIdentifier = 165,
    Mbms2g3gIndicator = 166,
    EnhancedNsapi = 167,
    MbmsSessionDuration = 168,
    AdditionalMbmsTraceInfo = 169,
    MbmsSessionRepetitionNumber = 170,
    MbmsTimeToDataTransfer = 171,
    BssContainer = 173,
    CellIdentification = 174,
    PduNumbers = 175,
    BssgpCause = 176,
    RequiredMbmsBearerCapabilities = 177,
    RimRoutingAddressDiscriminator = 178,
    ListOfSetUpPfcs = 179,
    PsHandoverXidParameters = 180,
    MsInfoChangeReportingAction = 181,
    DirectTunnelFlags = 182,
    CorrelationId = 183,
    BearerControlMode = 184,
    MbmsFlowIdentifier = 185,
    MbmsIpMulticastDistribution = 186,
    MbmsDistributionAcknowledgement = 187,
    ReliableInterRatHandoverInfo = 188,
    RfspIndex = 189,
    Fqdn = 190,
    EvolvedAllocationRetentionPriorityI = 191,
    EvolvedAllocationRetentionPriorityII = 192,
    ExtendedCommonFlags = 193,
    Uci = 194,
    CsgInformationReportingAction = 195,
    CsgId = 196,
    Cmi = 197,
    Ambr = 198,
    UeNetworkCapability = 199,
    UeAmbr = 200,
    ApnAmbrWithNsapi = 201,
    GgsnBackOffTime = 202,
    SignallingPriorityIndication = 203,
    SignallingPriorityIndicationWithNsapi = 204,
    HigherBitratesThan16MbpsFlag = 205,
    AdditionalMmContextForSrvcc = 207,
    AdditionalFlagsForSrvcc = 208,
    StnSr = 209,
    CMsisdn = 210,
    ExtendedRanapCause = 211,
    EnodebId = 212,
    SelectionModeWithNsapi = 213,
    UliTimestamp = 214,
    LhnIdWithNsapi = 215,
    CnOperatorSelectionEntity = 216,
    UeUsageType = 217,
    ExtendedCommonFlagsII = 218,
    NodeIdentifier = 219,
    CiotOptimizationsSupportIndication = 220,
    ScefPdnConnection = 221,
    IovUpdatesCounter = 222,
    MappedUeUsageType = 223,
    UpFunctionSelectionIndicationFlags = 224,
    GtpuTunnelStatusInformation = 230,
    RecoveryTimeStamp = 231,
    SpecialIeTypeForIeTypeExtension = 238,
    ChargingGatewayAddress = 251,
}

/// Check if IE type is TV format (fixed length)
pub fn is_tv_ie(ie_type: u8) -> bool {
    ie_type < 128
}

/// Get TV IE length based on type
pub fn get_tv_ie_length(ie_type: u8) -> Option<usize> {
    match ie_type {
        1 => Some(1),   // Cause
        2 => Some(8),   // IMSI
        3 => Some(6),   // RAI
        4 => Some(4),   // TLLI
        5 => Some(4),   // P-TMSI
        8 => Some(1),   // Reordering Required
        9 => Some(28),  // Authentication Triplet
        11 => Some(1),  // MAP Cause
        12 => Some(3),  // P-TMSI Signature
        13 => Some(1),  // MS Validated
        14 => Some(1),  // Recovery
        15 => Some(1),  // Selection Mode
        16 => Some(4),  // TEID Data I
        17 => Some(4),  // TEID Control Plane
        18 => Some(5),  // TEID Data II
        19 => Some(1),  // Teardown Ind
        20 => Some(1),  // NSAPI
        21 => Some(1),  // RANAP Cause
        22 => Some(9),  // RAB Context
        23 => Some(1),  // Radio Priority SMS
        24 => Some(1),  // Radio Priority
        25 => Some(2),  // Packet Flow ID
        26 => Some(2),  // Charging Characteristics
        27 => Some(2),  // Trace Reference
        28 => Some(2),  // Trace Type
        29 => Some(1),  // MS Not Reachable Reason
        127 => Some(4), // Charging ID
        _ => None,
    }
}

/// Generic GTPv1 Information Element
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtp1Ie {
    /// IE Type
    pub ie_type: u8,
    /// IE Value (raw bytes)
    pub value: Bytes,
}

impl Gtp1Ie {
    /// Create a new IE
    pub fn new(ie_type: u8, value: Bytes) -> Self {
        Self { ie_type, value }
    }

    /// Create a TV IE (fixed length)
    pub fn new_tv(ie_type: u8, value: &[u8]) -> Self {
        Self {
            ie_type,
            value: Bytes::copy_from_slice(value),
        }
    }

    /// Create a TLV IE (variable length)
    pub fn new_tlv(ie_type: u8, value: &[u8]) -> Self {
        Self {
            ie_type,
            value: Bytes::copy_from_slice(value),
        }
    }

    /// Encode IE to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.ie_type);

        if is_tv_ie(self.ie_type) {
            // TV format: Type + Value (fixed length)
            buf.put_slice(&self.value);
        } else {
            // TLV format: Type + Length (2 bytes) + Value
            buf.put_u16(self.value.len() as u16);
            buf.put_slice(&self.value);
        }
    }

    /// Decode IE from bytes
    pub fn decode(buf: &mut Bytes) -> GtpResult<Self> {
        if buf.remaining() < 1 {
            return Err(GtpError::BufferTooShort {
                needed: 1,
                available: buf.remaining(),
            });
        }

        let ie_type = buf.get_u8();

        if is_tv_ie(ie_type) {
            // TV format
            let length = get_tv_ie_length(ie_type).ok_or(GtpError::InvalidIeType(ie_type))?;

            if buf.remaining() < length {
                return Err(GtpError::BufferTooShort {
                    needed: length,
                    available: buf.remaining(),
                });
            }

            let value = buf.copy_to_bytes(length);
            Ok(Self { ie_type, value })
        } else {
            // TLV format
            if buf.remaining() < 2 {
                return Err(GtpError::BufferTooShort {
                    needed: 2,
                    available: buf.remaining(),
                });
            }

            let length = buf.get_u16() as usize;

            if buf.remaining() < length {
                return Err(GtpError::BufferTooShort {
                    needed: length,
                    available: buf.remaining(),
                });
            }

            let value = buf.copy_to_bytes(length);
            Ok(Self { ie_type, value })
        }
    }

    /// Get encoded length
    pub fn encoded_len(&self) -> usize {
        if is_tv_ie(self.ie_type) {
            1 + self.value.len() // Type + Value
        } else {
            1 + 2 + self.value.len() // Type + Length + Value
        }
    }
}

/// Recovery IE
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryIe {
    pub restart_counter: u8,
}

impl RecoveryIe {
    pub fn new(restart_counter: u8) -> Self {
        Self { restart_counter }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(Gtp1IeTypeTv::Recovery as u8);
        buf.put_u8(self.restart_counter);
    }

    pub fn decode(buf: &mut Bytes) -> GtpResult<Self> {
        if buf.remaining() < 1 {
            return Err(GtpError::BufferTooShort {
                needed: 1,
                available: buf.remaining(),
            });
        }
        Ok(Self {
            restart_counter: buf.get_u8(),
        })
    }
}

/// TEID Data I IE
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TeidDataIIe {
    pub teid: u32,
}

impl TeidDataIIe {
    pub fn new(teid: u32) -> Self {
        Self { teid }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(Gtp1IeTypeTv::TunnelEndpointIdentifierDataI as u8);
        buf.put_u32(self.teid);
    }

    pub fn decode(buf: &mut Bytes) -> GtpResult<Self> {
        if buf.remaining() < 4 {
            return Err(GtpError::BufferTooShort {
                needed: 4,
                available: buf.remaining(),
            });
        }
        Ok(Self {
            teid: buf.get_u32(),
        })
    }
}

/// TEID Control Plane IE
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TeidControlPlaneIe {
    pub teid: u32,
}

impl TeidControlPlaneIe {
    pub fn new(teid: u32) -> Self {
        Self { teid }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(Gtp1IeTypeTv::TunnelEndpointIdentifierControlPlane as u8);
        buf.put_u32(self.teid);
    }

    pub fn decode(buf: &mut Bytes) -> GtpResult<Self> {
        if buf.remaining() < 4 {
            return Err(GtpError::BufferTooShort {
                needed: 4,
                available: buf.remaining(),
            });
        }
        Ok(Self {
            teid: buf.get_u32(),
        })
    }
}

/// NSAPI IE
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NsapiIe {
    pub nsapi: u8,
}

impl NsapiIe {
    pub fn new(nsapi: u8) -> Self {
        Self {
            nsapi: nsapi & 0x0F,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(Gtp1IeTypeTv::Nsapi as u8);
        buf.put_u8(self.nsapi & 0x0F);
    }

    pub fn decode(buf: &mut Bytes) -> GtpResult<Self> {
        if buf.remaining() < 1 {
            return Err(GtpError::BufferTooShort {
                needed: 1,
                available: buf.remaining(),
            });
        }
        Ok(Self {
            nsapi: buf.get_u8() & 0x0F,
        })
    }
}

/// GSN Address IE (TLV)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GsnAddressIe {
    pub address: Vec<u8>,
}

impl GsnAddressIe {
    pub fn new_ipv4(addr: [u8; 4]) -> Self {
        Self {
            address: addr.to_vec(),
        }
    }

    pub fn new_ipv6(addr: [u8; 16]) -> Self {
        Self {
            address: addr.to_vec(),
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(Gtp1IeTypeTlv::GsnAddress as u8);
        buf.put_u16(self.address.len() as u16);
        buf.put_slice(&self.address);
    }

    pub fn decode(buf: &mut Bytes, length: u16) -> GtpResult<Self> {
        let len = length as usize;
        if buf.remaining() < len {
            return Err(GtpError::BufferTooShort {
                needed: len,
                available: buf.remaining(),
            });
        }
        let mut address = vec![0u8; len];
        buf.copy_to_slice(&mut address);
        Ok(Self { address })
    }

    pub fn is_ipv4(&self) -> bool {
        self.address.len() == 4
    }

    pub fn is_ipv6(&self) -> bool {
        self.address.len() == 16
    }
}

/// Extension Header Type List IE (TLV, type 141; TS 29.281 Section 8.5).
///
/// Carries the list of `n` Extension Header Type octets supported by the
/// sending GTP entity; the Length field is `n`. Mandatory IE in a Supported
/// Extension Headers Notification (Section 7.2.3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExtHeaderTypeListIe {
    /// The list of extension header type octets.
    pub types: Vec<u8>,
}

impl ExtHeaderTypeListIe {
    pub fn new(types: Vec<u8>) -> Self {
        Self { types }
    }

    /// Encode the full TLV (type 141, 2-octet length = n, then the n octets).
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(Gtp1IeTypeTlv::ExtensionHeaderTypeList as u8);
        buf.put_u16(self.types.len() as u16);
        buf.put_slice(&self.types);
    }

    /// Decode the value field (`length` octets) into the type list.
    pub fn decode(buf: &mut Bytes, length: u16) -> GtpResult<Self> {
        let len = length as usize;
        if buf.remaining() < len {
            return Err(GtpError::BufferTooShort {
                needed: len,
                available: buf.remaining(),
            });
        }
        let mut types = vec![0u8; len];
        buf.copy_to_slice(&mut types);
        Ok(Self { types })
    }
}

/// GTP-U Tunnel Status Information IE (TLV, type 230; TS 29.281 Section 8.7).
///
/// Octet 4 carries the SPOC (Start Pause Of Charging) flag in bit 1; bits 2-8
/// are spare and set to 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TunnelStatusInfoIe {
    /// Start Pause Of Charging (octet 4, bit 1).
    pub spoc: bool,
}

impl TunnelStatusInfoIe {
    pub fn new(spoc: bool) -> Self {
        Self { spoc }
    }

    /// Encode the full TLV (type 230, length 1, octet 4 = SPOC in bit 1).
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(Gtp1IeTypeTlv::GtpuTunnelStatusInformation as u8);
        buf.put_u16(1);
        buf.put_u8(self.spoc as u8);
    }

    /// Decode the value field (`length` octets, octet 4 first) into the flags.
    pub fn decode(buf: &mut Bytes, length: u16) -> GtpResult<Self> {
        let len = length as usize;
        if len < 1 || buf.remaining() < len {
            return Err(GtpError::BufferTooShort {
                needed: len.max(1),
                available: buf.remaining(),
            });
        }
        let octet4 = buf.get_u8();
        // Skip any further explicitly-specified octets (spare/future use).
        for _ in 1..len {
            buf.get_u8();
        }
        Ok(Self {
            spoc: octet4 & 0x01 != 0,
        })
    }
}

/// Recovery Time Stamp IE (TLV, type 231; TS 29.281 Section 8.8).
///
/// Octets 4-7 hold the recovery time stamp, encoded as the first four octets of
/// the 64-bit NTP timestamp (seconds since 1900-01-01, per IETF RFC 5905).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecoveryTimeStampIe {
    /// Recovery time stamp value (NTP seconds since 1900-01-01).
    pub timestamp: u32,
}

impl RecoveryTimeStampIe {
    pub fn new(timestamp: u32) -> Self {
        Self { timestamp }
    }

    /// Encode the full TLV (type 231, length 4, then the 32-bit time stamp).
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(Gtp1IeTypeTlv::RecoveryTimeStamp as u8);
        buf.put_u16(4);
        buf.put_u32(self.timestamp);
    }

    /// Decode the value field (`length` octets, time stamp in octets 4-7).
    pub fn decode(buf: &mut Bytes, length: u16) -> GtpResult<Self> {
        let len = length as usize;
        if len < 4 || buf.remaining() < len {
            return Err(GtpError::BufferTooShort {
                needed: len.max(4),
                available: buf.remaining(),
            });
        }
        let timestamp = buf.get_u32();
        // Skip any further explicitly-specified octets.
        for _ in 4..len {
            buf.get_u8();
        }
        Ok(Self { timestamp })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_ie() {
        let ie = RecoveryIe::new(42);
        let mut buf = BytesMut::new();
        ie.encode(&mut buf);

        assert_eq!(buf[0], Gtp1IeTypeTv::Recovery as u8);
        assert_eq!(buf[1], 42);
    }

    #[test]
    fn test_teid_data_i_ie() {
        let ie = TeidDataIIe::new(0x12345678);
        let mut buf = BytesMut::new();
        ie.encode(&mut buf);

        assert_eq!(buf[0], Gtp1IeTypeTv::TunnelEndpointIdentifierDataI as u8);
        assert_eq!(&buf[1..5], &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_gsn_address_ie_ipv4() {
        let ie = GsnAddressIe::new_ipv4([192, 168, 1, 1]);
        let mut buf = BytesMut::new();
        ie.encode(&mut buf);

        assert_eq!(buf[0], Gtp1IeTypeTlv::GsnAddress as u8);
        assert_eq!(&buf[1..3], &[0x00, 0x04]); // Length = 4
        assert_eq!(&buf[3..7], &[192, 168, 1, 1]);
        assert!(ie.is_ipv4());
    }

    #[test]
    fn test_generic_ie_tv() {
        let ie = Gtp1Ie::new_tv(Gtp1IeTypeTv::Recovery as u8, &[42]);
        let mut buf = BytesMut::new();
        ie.encode(&mut buf);

        let mut bytes = buf.freeze();
        // Skip the type byte for decoding
        let ie_type = bytes.get_u8();
        assert_eq!(ie_type, Gtp1IeTypeTv::Recovery as u8);
    }

    // gtp-03: Extension Header Type List IE (141), exact wire bytes
    #[test]
    fn test_ext_header_type_list_ie_byte_vector() {
        let ie = ExtHeaderTypeListIe::new(vec![0x85, 0x84]);
        let mut buf = BytesMut::new();
        ie.encode(&mut buf);
        // type 141 (0x8D), length 0x0002, then the two type octets
        assert_eq!(&buf[..], &[0x8D, 0x00, 0x02, 0x85, 0x84]);

        // Round-trip from the value field
        let mut value = Bytes::from_static(&[0x85, 0x84]);
        let decoded = ExtHeaderTypeListIe::decode(&mut value, 2).unwrap();
        assert_eq!(decoded, ie);
    }

    // gtp-07: GTP-U Tunnel Status Information IE (230), exact wire bytes
    #[test]
    fn test_tunnel_status_info_ie_byte_vector() {
        let ie = TunnelStatusInfoIe::new(true);
        let mut buf = BytesMut::new();
        ie.encode(&mut buf);
        // type 230 (0xE6), length 0x0001, octet4 = 0x01 (SPOC set)
        assert_eq!(&buf[..], &[0xE6, 0x00, 0x01, 0x01]);

        let mut value = Bytes::from_static(&[0x01]);
        let decoded = TunnelStatusInfoIe::decode(&mut value, 1).unwrap();
        assert!(decoded.spoc);

        // SPOC clear
        let mut buf = BytesMut::new();
        TunnelStatusInfoIe::new(false).encode(&mut buf);
        assert_eq!(&buf[..], &[0xE6, 0x00, 0x01, 0x00]);
    }

    // gtp-06: Recovery Time Stamp IE (231), exact wire bytes
    #[test]
    fn test_recovery_timestamp_ie_byte_vector() {
        let ie = RecoveryTimeStampIe::new(0xE000_0000);
        let mut buf = BytesMut::new();
        ie.encode(&mut buf);
        // type 231 (0xE7), length 0x0004, then the 32-bit time stamp
        assert_eq!(&buf[..], &[0xE7, 0x00, 0x04, 0xE0, 0x00, 0x00, 0x00]);

        let mut value = Bytes::from_static(&[0xE0, 0x00, 0x00, 0x00]);
        let decoded = RecoveryTimeStampIe::decode(&mut value, 4).unwrap();
        assert_eq!(decoded.timestamp, 0xE000_0000);
    }
}
