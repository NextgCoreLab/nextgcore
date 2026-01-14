//! GTPv1 Header
//!
//! GTPv1 header structure as specified in 3GPP TS 29.060.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::error::{GtpError, GtpResult};

/// GTPv1-U header length (without optional fields)
pub const GTPV1U_HEADER_LEN: usize = 8;

/// GTPv1-C header length (with sequence number)
pub const GTPV1C_HEADER_LEN: usize = 12;

/// GTP TEID length
pub const GTP1_TEID_LEN: usize = 4;

/// GTPv1 Version
pub const GTP1_VERSION_0: u8 = 0;
pub const GTP1_VERSION_1: u8 = 1;

/// GTPv1-U Flags
pub const GTP1U_FLAGS_V: u8 = 0x20;
pub const GTP1U_FLAGS_PT: u8 = 0x10;
pub const GTP1U_FLAGS_E: u8 = 0x04;
pub const GTP1U_FLAGS_S: u8 = 0x02;
pub const GTP1U_FLAGS_PN: u8 = 0x01;

/// GTPv1-U Message Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Gtp1uMessageType {
    EchoRequest = 1,
    EchoResponse = 2,
    ErrorIndication = 26,
    SupportedExtensionHeadersNotification = 31,
    EndMarker = 254,
    GPdu = 255,
}

impl TryFrom<u8> for Gtp1uMessageType {
    type Error = GtpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Gtp1uMessageType::EchoRequest),
            2 => Ok(Gtp1uMessageType::EchoResponse),
            26 => Ok(Gtp1uMessageType::ErrorIndication),
            31 => Ok(Gtp1uMessageType::SupportedExtensionHeadersNotification),
            254 => Ok(Gtp1uMessageType::EndMarker),
            255 => Ok(Gtp1uMessageType::GPdu),
            _ => Err(GtpError::InvalidMessageType(value)),
        }
    }
}

/// GTPv1-C Message Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Gtp1cMessageType {
    EchoRequest = 1,
    EchoResponse = 2,
    VersionNotSupported = 3,
    NodeAliveRequest = 4,
    NodeAliveResponse = 5,
    RedirectionRequest = 6,
    RedirectionResponse = 7,
    CreatePdpContextRequest = 16,
    CreatePdpContextResponse = 17,
    UpdatePdpContextRequest = 18,
    UpdatePdpContextResponse = 19,
    DeletePdpContextRequest = 20,
    DeletePdpContextResponse = 21,
    InitiatePdpContextActivationRequest = 22,
    InitiatePdpContextActivationResponse = 23,
    ErrorIndication = 26,
    PduNotificationRequest = 27,
    PduNotificationResponse = 28,
    PduNotificationRejectRequest = 29,
    PduNotificationRejectResponse = 30,
    SupportedExtensionHeadersNotification = 31,
    SendRouteingInformationForGprsRequest = 32,
    SendRouteingInformationForGprsResponse = 33,
    FailureReportRequest = 34,
    FailureReportResponse = 35,
    NoteMsGprsPresentRequest = 36,
    NoteMsGprsPresentResponse = 37,
    IdentificationRequest = 48,
    IdentificationResponse = 49,
    SgsnContextRequest = 50,
    SgsnContextResponse = 51,
    SgsnContextAcknowledge = 52,
    ForwardRelocationRequest = 53,
    ForwardRelocationResponse = 54,
    ForwardRelocationComplete = 55,
    RelocationCancelRequest = 56,
    RelocationCancelResponse = 57,
    ForwardSrnsContext = 58,
    ForwardRelocationCompleteAcknowledge = 59,
    ForwardSrnsContextAcknowledge = 60,
    UeRegistrationQueryRequest = 61,
    UeRegistrationQueryResponse = 62,
    RanInformationRelay = 70,
    MbmsNotificationRequest = 96,
    MbmsNotificationResponse = 97,
    MbmsNotificationRejectRequest = 98,
    MbmsNotificationRejectResponse = 99,
    CreateMbmsContextRequest = 100,
    CreateMbmsContextResponse = 101,
    UpdateMbmsContextRequest = 102,
    UpdateMbmsContextResponse = 103,
    DeleteMbmsContextRequest = 104,
    DeleteMbmsContextResponse = 105,
    MbmsRegistrationRequest = 112,
    MbmsRegistrationResponse = 113,
    MbmsDeRegistrationRequest = 114,
    MbmsDeRegistrationResponse = 115,
    MbmsSessionStartRequest = 116,
    MbmsSessionStartResponse = 117,
    MbmsSessionStopRequest = 118,
    MbmsSessionStopResponse = 119,
    MbmsSessionUpdateRequest = 120,
    MbmsSessionUpdateResponse = 121,
}

impl TryFrom<u8> for Gtp1cMessageType {
    type Error = GtpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Gtp1cMessageType::EchoRequest),
            2 => Ok(Gtp1cMessageType::EchoResponse),
            3 => Ok(Gtp1cMessageType::VersionNotSupported),
            4 => Ok(Gtp1cMessageType::NodeAliveRequest),
            5 => Ok(Gtp1cMessageType::NodeAliveResponse),
            6 => Ok(Gtp1cMessageType::RedirectionRequest),
            7 => Ok(Gtp1cMessageType::RedirectionResponse),
            16 => Ok(Gtp1cMessageType::CreatePdpContextRequest),
            17 => Ok(Gtp1cMessageType::CreatePdpContextResponse),
            18 => Ok(Gtp1cMessageType::UpdatePdpContextRequest),
            19 => Ok(Gtp1cMessageType::UpdatePdpContextResponse),
            20 => Ok(Gtp1cMessageType::DeletePdpContextRequest),
            21 => Ok(Gtp1cMessageType::DeletePdpContextResponse),
            22 => Ok(Gtp1cMessageType::InitiatePdpContextActivationRequest),
            23 => Ok(Gtp1cMessageType::InitiatePdpContextActivationResponse),
            26 => Ok(Gtp1cMessageType::ErrorIndication),
            27 => Ok(Gtp1cMessageType::PduNotificationRequest),
            28 => Ok(Gtp1cMessageType::PduNotificationResponse),
            29 => Ok(Gtp1cMessageType::PduNotificationRejectRequest),
            30 => Ok(Gtp1cMessageType::PduNotificationRejectResponse),
            31 => Ok(Gtp1cMessageType::SupportedExtensionHeadersNotification),
            32 => Ok(Gtp1cMessageType::SendRouteingInformationForGprsRequest),
            33 => Ok(Gtp1cMessageType::SendRouteingInformationForGprsResponse),
            34 => Ok(Gtp1cMessageType::FailureReportRequest),
            35 => Ok(Gtp1cMessageType::FailureReportResponse),
            36 => Ok(Gtp1cMessageType::NoteMsGprsPresentRequest),
            37 => Ok(Gtp1cMessageType::NoteMsGprsPresentResponse),
            48 => Ok(Gtp1cMessageType::IdentificationRequest),
            49 => Ok(Gtp1cMessageType::IdentificationResponse),
            50 => Ok(Gtp1cMessageType::SgsnContextRequest),
            51 => Ok(Gtp1cMessageType::SgsnContextResponse),
            52 => Ok(Gtp1cMessageType::SgsnContextAcknowledge),
            53 => Ok(Gtp1cMessageType::ForwardRelocationRequest),
            54 => Ok(Gtp1cMessageType::ForwardRelocationResponse),
            55 => Ok(Gtp1cMessageType::ForwardRelocationComplete),
            56 => Ok(Gtp1cMessageType::RelocationCancelRequest),
            57 => Ok(Gtp1cMessageType::RelocationCancelResponse),
            58 => Ok(Gtp1cMessageType::ForwardSrnsContext),
            59 => Ok(Gtp1cMessageType::ForwardRelocationCompleteAcknowledge),
            60 => Ok(Gtp1cMessageType::ForwardSrnsContextAcknowledge),
            61 => Ok(Gtp1cMessageType::UeRegistrationQueryRequest),
            62 => Ok(Gtp1cMessageType::UeRegistrationQueryResponse),
            70 => Ok(Gtp1cMessageType::RanInformationRelay),
            96 => Ok(Gtp1cMessageType::MbmsNotificationRequest),
            97 => Ok(Gtp1cMessageType::MbmsNotificationResponse),
            98 => Ok(Gtp1cMessageType::MbmsNotificationRejectRequest),
            99 => Ok(Gtp1cMessageType::MbmsNotificationRejectResponse),
            100 => Ok(Gtp1cMessageType::CreateMbmsContextRequest),
            101 => Ok(Gtp1cMessageType::CreateMbmsContextResponse),
            102 => Ok(Gtp1cMessageType::UpdateMbmsContextRequest),
            103 => Ok(Gtp1cMessageType::UpdateMbmsContextResponse),
            104 => Ok(Gtp1cMessageType::DeleteMbmsContextRequest),
            105 => Ok(Gtp1cMessageType::DeleteMbmsContextResponse),
            112 => Ok(Gtp1cMessageType::MbmsRegistrationRequest),
            113 => Ok(Gtp1cMessageType::MbmsRegistrationResponse),
            114 => Ok(Gtp1cMessageType::MbmsDeRegistrationRequest),
            115 => Ok(Gtp1cMessageType::MbmsDeRegistrationResponse),
            116 => Ok(Gtp1cMessageType::MbmsSessionStartRequest),
            117 => Ok(Gtp1cMessageType::MbmsSessionStartResponse),
            118 => Ok(Gtp1cMessageType::MbmsSessionStopRequest),
            119 => Ok(Gtp1cMessageType::MbmsSessionStopResponse),
            120 => Ok(Gtp1cMessageType::MbmsSessionUpdateRequest),
            121 => Ok(Gtp1cMessageType::MbmsSessionUpdateResponse),
            _ => Err(GtpError::InvalidMessageType(value)),
        }
    }
}

/// GTPv1 Header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtp1Header {
    /// Version (3 bits) - should be 1 for GTPv1
    pub version: u8,
    /// Protocol Type (1 bit) - 1 for GTP, 0 for GTP'
    pub pt: bool,
    /// Extension Header flag (1 bit)
    pub e: bool,
    /// Sequence Number flag (1 bit)
    pub s: bool,
    /// N-PDU Number flag (1 bit)
    pub pn: bool,
    /// Message Type
    pub message_type: u8,
    /// Message Length (excluding header)
    pub length: u16,
    /// Tunnel Endpoint Identifier
    pub teid: u32,
    /// Sequence Number (optional, present if s=1)
    pub sequence_number: Option<u16>,
    /// N-PDU Number (optional, present if pn=1)
    pub npdu_number: Option<u8>,
    /// Next Extension Header Type (optional, present if e=1)
    pub next_extension_header_type: Option<u8>,
}

impl Default for Gtp1Header {
    fn default() -> Self {
        Self {
            version: GTP1_VERSION_1,
            pt: true,
            e: false,
            s: false,
            pn: false,
            message_type: 0,
            length: 0,
            teid: 0,
            sequence_number: None,
            npdu_number: None,
            next_extension_header_type: None,
        }
    }
}

impl Gtp1Header {
    /// Create a new GTPv1 header
    pub fn new(message_type: u8, teid: u32) -> Self {
        Self {
            version: GTP1_VERSION_1,
            pt: true,
            e: false,
            s: false,
            pn: false,
            message_type,
            length: 0,
            teid,
            sequence_number: None,
            npdu_number: None,
            next_extension_header_type: None,
        }
    }

    /// Create a GTPv1-U header for G-PDU
    pub fn new_gpdu(teid: u32) -> Self {
        Self::new(Gtp1uMessageType::GPdu as u8, teid)
    }

    /// Get the flags byte
    pub fn flags(&self) -> u8 {
        let mut flags = (self.version & 0x07) << 5;
        if self.pt {
            flags |= GTP1U_FLAGS_PT;
        }
        if self.e {
            flags |= GTP1U_FLAGS_E;
        }
        if self.s {
            flags |= GTP1U_FLAGS_S;
        }
        if self.pn {
            flags |= GTP1U_FLAGS_PN;
        }
        flags
    }

    /// Set flags from byte
    pub fn set_flags(&mut self, flags: u8) {
        self.version = (flags >> 5) & 0x07;
        self.pt = (flags & GTP1U_FLAGS_PT) != 0;
        self.e = (flags & GTP1U_FLAGS_E) != 0;
        self.s = (flags & GTP1U_FLAGS_S) != 0;
        self.pn = (flags & GTP1U_FLAGS_PN) != 0;
    }

    /// Check if optional fields are present
    pub fn has_optional_fields(&self) -> bool {
        self.e || self.s || self.pn
    }

    /// Get header length
    pub fn header_len(&self) -> usize {
        if self.has_optional_fields() {
            GTPV1C_HEADER_LEN
        } else {
            GTPV1U_HEADER_LEN
        }
    }

    /// Convert transaction ID to sequence number
    pub fn xid_to_sqn(xid: u32) -> u16 {
        (xid & 0xFFFF) as u16
    }

    /// Convert sequence number to transaction ID
    pub fn sqn_to_xid(sqn: u16) -> u32 {
        sqn as u32
    }

    /// Encode header to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags());
        buf.put_u8(self.message_type);
        buf.put_u16(self.length);
        buf.put_u32(self.teid);

        if self.has_optional_fields() {
            buf.put_u16(self.sequence_number.unwrap_or(0));
            buf.put_u8(self.npdu_number.unwrap_or(0));
            buf.put_u8(self.next_extension_header_type.unwrap_or(0));
        }
    }

    /// Decode header from bytes
    pub fn decode(buf: &mut Bytes) -> GtpResult<Self> {
        if buf.remaining() < GTPV1U_HEADER_LEN {
            return Err(GtpError::BufferTooShort {
                needed: GTPV1U_HEADER_LEN,
                available: buf.remaining(),
            });
        }

        let flags = buf.get_u8();
        let message_type = buf.get_u8();
        let length = buf.get_u16();
        let teid = buf.get_u32();

        let mut header = Self {
            version: (flags >> 5) & 0x07,
            pt: (flags & GTP1U_FLAGS_PT) != 0,
            e: (flags & GTP1U_FLAGS_E) != 0,
            s: (flags & GTP1U_FLAGS_S) != 0,
            pn: (flags & GTP1U_FLAGS_PN) != 0,
            message_type,
            length,
            teid,
            sequence_number: None,
            npdu_number: None,
            next_extension_header_type: None,
        };

        // Check version
        if header.version != GTP1_VERSION_1 {
            return Err(GtpError::InvalidVersion(header.version));
        }

        // Read optional fields if present
        if header.has_optional_fields() {
            if buf.remaining() < 4 {
                return Err(GtpError::BufferTooShort {
                    needed: 4,
                    available: buf.remaining(),
                });
            }
            header.sequence_number = Some(buf.get_u16());
            header.npdu_number = Some(buf.get_u8());
            header.next_extension_header_type = Some(buf.get_u8());
        }

        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_encode_decode() {
        let header = Gtp1Header {
            version: GTP1_VERSION_1,
            pt: true,
            e: false,
            s: true,
            pn: false,
            message_type: Gtp1uMessageType::GPdu as u8,
            length: 100,
            teid: 0x12345678,
            sequence_number: Some(0x1234),
            npdu_number: Some(0),
            next_extension_header_type: Some(0),
        };

        let mut buf = BytesMut::new();
        header.encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = Gtp1Header::decode(&mut bytes).unwrap();

        assert_eq!(header.version, decoded.version);
        assert_eq!(header.pt, decoded.pt);
        assert_eq!(header.e, decoded.e);
        assert_eq!(header.s, decoded.s);
        assert_eq!(header.pn, decoded.pn);
        assert_eq!(header.message_type, decoded.message_type);
        assert_eq!(header.length, decoded.length);
        assert_eq!(header.teid, decoded.teid);
        assert_eq!(header.sequence_number, decoded.sequence_number);
    }

    #[test]
    fn test_header_flags() {
        let mut header = Gtp1Header::default();
        header.e = true;
        header.s = true;
        
        let flags = header.flags();
        assert_eq!(flags & GTP1U_FLAGS_V, GTP1U_FLAGS_V); // Version 1
        assert_eq!(flags & GTP1U_FLAGS_PT, GTP1U_FLAGS_PT); // PT = 1
        assert_eq!(flags & GTP1U_FLAGS_E, GTP1U_FLAGS_E); // E = 1
        assert_eq!(flags & GTP1U_FLAGS_S, GTP1U_FLAGS_S); // S = 1
        assert_eq!(flags & GTP1U_FLAGS_PN, 0); // PN = 0
    }

    #[test]
    fn test_gpdu_header() {
        let header = Gtp1Header::new_gpdu(0xABCDEF01);
        assert_eq!(header.message_type, Gtp1uMessageType::GPdu as u8);
        assert_eq!(header.teid, 0xABCDEF01);
        assert_eq!(header.version, GTP1_VERSION_1);
        assert!(header.pt);
    }
}
