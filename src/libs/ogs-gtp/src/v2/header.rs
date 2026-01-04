//! GTPv2 Header
//!
//! GTPv2-C header structure as specified in 3GPP TS 29.274.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::error::{GtpError, GtpResult};

/// GTPv2-C header length (with TEID)
pub const GTPV2C_HEADER_LEN: usize = 12;

/// GTPv2-C header length (without TEID)
pub const GTPV2C_HEADER_LEN_NO_TEID: usize = 8;

/// GTP TEID length
pub const GTP2_TEID_LEN: usize = 4;

/// GTPv2 Version
pub const GTP2_VERSION_0: u8 = 0;
pub const GTP2_VERSION_1: u8 = 1;

/// GTPv2-C Message Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Gtp2MessageType {
    EchoRequest = 1,
    EchoResponse = 2,
    VersionNotSupportedIndication = 3,
    CreateSessionRequest = 32,
    CreateSessionResponse = 33,
    ModifyBearerRequest = 34,
    ModifyBearerResponse = 35,
    DeleteSessionRequest = 36,
    DeleteSessionResponse = 37,
    ChangeNotificationRequest = 38,
    ChangeNotificationResponse = 39,
    RemoteUeReportNotification = 40,
    RemoteUeReportAcknowledge = 41,
    ModifyBearerCommand = 64,
    ModifyBearerFailureIndication = 65,
    DeleteBearerCommand = 66,
    DeleteBearerFailureIndication = 67,
    BearerResourceCommand = 68,
    BearerResourceFailureIndication = 69,
    DownlinkDataNotificationFailureIndication = 70,
    TraceSessionActivation = 71,
    TraceSessionDeactivation = 72,
    StopPagingIndication = 73,
    CreateBearerRequest = 95,
    CreateBearerResponse = 96,
    UpdateBearerRequest = 97,
    UpdateBearerResponse = 98,
    DeleteBearerRequest = 99,
    DeleteBearerResponse = 100,
    DeletePdnConnectionSetRequest = 101,
    DeletePdnConnectionSetResponse = 102,
    PgwDownlinkTriggeringNotification = 103,
    PgwDownlinkTriggeringAcknowledge = 104,
    CreateForwardingTunnelRequest = 160,
    CreateForwardingTunnelResponse = 161,
    SuspendNotification = 162,
    SuspendAcknowledge = 163,
    ResumeNotification = 164,
    ResumeAcknowledge = 165,
    CreateIndirectDataForwardingTunnelRequest = 166,
    CreateIndirectDataForwardingTunnelResponse = 167,
    DeleteIndirectDataForwardingTunnelRequest = 168,
    DeleteIndirectDataForwardingTunnelResponse = 169,
    ReleaseAccessBearersRequest = 170,
    ReleaseAccessBearersResponse = 171,
    DownlinkDataNotification = 176,
    DownlinkDataNotificationAcknowledge = 177,
    PgwRestartNotification = 179,
    PgwRestartNotificationAcknowledge = 180,
    UpdatePdnConnectionSetRequest = 200,
    UpdatePdnConnectionSetResponse = 201,
    ModifyAccessBearersRequest = 211,
    ModifyAccessBearersResponse = 212,
}

impl TryFrom<u8> for Gtp2MessageType {
    type Error = GtpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::EchoRequest),
            2 => Ok(Self::EchoResponse),
            3 => Ok(Self::VersionNotSupportedIndication),
            32 => Ok(Self::CreateSessionRequest),
            33 => Ok(Self::CreateSessionResponse),
            34 => Ok(Self::ModifyBearerRequest),
            35 => Ok(Self::ModifyBearerResponse),
            36 => Ok(Self::DeleteSessionRequest),
            37 => Ok(Self::DeleteSessionResponse),
            38 => Ok(Self::ChangeNotificationRequest),
            39 => Ok(Self::ChangeNotificationResponse),
            40 => Ok(Self::RemoteUeReportNotification),
            41 => Ok(Self::RemoteUeReportAcknowledge),
            64 => Ok(Self::ModifyBearerCommand),
            65 => Ok(Self::ModifyBearerFailureIndication),
            66 => Ok(Self::DeleteBearerCommand),
            67 => Ok(Self::DeleteBearerFailureIndication),
            68 => Ok(Self::BearerResourceCommand),
            69 => Ok(Self::BearerResourceFailureIndication),
            70 => Ok(Self::DownlinkDataNotificationFailureIndication),
            71 => Ok(Self::TraceSessionActivation),
            72 => Ok(Self::TraceSessionDeactivation),
            73 => Ok(Self::StopPagingIndication),
            95 => Ok(Self::CreateBearerRequest),
            96 => Ok(Self::CreateBearerResponse),
            97 => Ok(Self::UpdateBearerRequest),
            98 => Ok(Self::UpdateBearerResponse),
            99 => Ok(Self::DeleteBearerRequest),
            100 => Ok(Self::DeleteBearerResponse),
            101 => Ok(Self::DeletePdnConnectionSetRequest),
            102 => Ok(Self::DeletePdnConnectionSetResponse),
            103 => Ok(Self::PgwDownlinkTriggeringNotification),
            104 => Ok(Self::PgwDownlinkTriggeringAcknowledge),
            160 => Ok(Self::CreateForwardingTunnelRequest),
            161 => Ok(Self::CreateForwardingTunnelResponse),
            162 => Ok(Self::SuspendNotification),
            163 => Ok(Self::SuspendAcknowledge),
            164 => Ok(Self::ResumeNotification),
            165 => Ok(Self::ResumeAcknowledge),
            166 => Ok(Self::CreateIndirectDataForwardingTunnelRequest),
            167 => Ok(Self::CreateIndirectDataForwardingTunnelResponse),
            168 => Ok(Self::DeleteIndirectDataForwardingTunnelRequest),
            169 => Ok(Self::DeleteIndirectDataForwardingTunnelResponse),
            170 => Ok(Self::ReleaseAccessBearersRequest),
            171 => Ok(Self::ReleaseAccessBearersResponse),
            176 => Ok(Self::DownlinkDataNotification),
            177 => Ok(Self::DownlinkDataNotificationAcknowledge),
            179 => Ok(Self::PgwRestartNotification),
            180 => Ok(Self::PgwRestartNotificationAcknowledge),
            200 => Ok(Self::UpdatePdnConnectionSetRequest),
            201 => Ok(Self::UpdatePdnConnectionSetResponse),
            211 => Ok(Self::ModifyAccessBearersRequest),
            212 => Ok(Self::ModifyAccessBearersResponse),
            _ => Err(GtpError::InvalidMessageType(value)),
        }
    }
}

/// GTPv2-C Header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtp2Header {
    /// Version (3 bits) - should be 2 for GTPv2
    pub version: u8,
    /// Piggybacked flag (1 bit)
    pub piggybacked: bool,
    /// TEID presence flag (1 bit)
    pub teid_presence: bool,
    /// Message Type
    pub message_type: u8,
    /// Message Length (excluding first 4 bytes of header)
    pub length: u16,
    /// Tunnel Endpoint Identifier (optional, present if teid_presence=1)
    pub teid: Option<u32>,
    /// Sequence Number (24 bits)
    pub sequence_number: u32,
}

impl Default for Gtp2Header {
    fn default() -> Self {
        Self {
            version: 2,
            piggybacked: false,
            teid_presence: true,
            message_type: 0,
            length: 0,
            teid: Some(0),
            sequence_number: 0,
        }
    }
}

impl Gtp2Header {
    /// Create a new GTPv2-C header with TEID
    pub fn new(message_type: u8, teid: u32, sequence_number: u32) -> Self {
        Self {
            version: 2,
            piggybacked: false,
            teid_presence: true,
            message_type,
            length: 0,
            teid: Some(teid),
            sequence_number,
        }
    }

    /// Create a new GTPv2-C header without TEID
    pub fn new_no_teid(message_type: u8, sequence_number: u32) -> Self {
        Self {
            version: 2,
            piggybacked: false,
            teid_presence: false,
            message_type,
            length: 0,
            teid: None,
            sequence_number,
        }
    }

    /// Get the flags byte
    pub fn flags(&self) -> u8 {
        let mut flags = (self.version & 0x07) << 5;
        if self.piggybacked {
            flags |= 0x10;
        }
        if self.teid_presence {
            flags |= 0x08;
        }
        flags
    }

    /// Get header length
    pub fn header_len(&self) -> usize {
        if self.teid_presence {
            GTPV2C_HEADER_LEN
        } else {
            GTPV2C_HEADER_LEN_NO_TEID
        }
    }

    /// Convert transaction ID to sequence number
    pub fn xid_to_sqn(xid: u32) -> u32 {
        xid << 8
    }

    /// Convert sequence number to transaction ID
    pub fn sqn_to_xid(sqn: u32) -> u32 {
        sqn >> 8
    }

    /// Encode header to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags());
        buf.put_u8(self.message_type);
        buf.put_u16(self.length);

        if self.teid_presence {
            buf.put_u32(self.teid.unwrap_or(0));
        }

        // Sequence number (24 bits) + spare (8 bits)
        buf.put_u32(self.sequence_number << 8);
    }

    /// Decode header from bytes
    pub fn decode(buf: &mut Bytes) -> GtpResult<Self> {
        if buf.remaining() < 4 {
            return Err(GtpError::BufferTooShort {
                needed: 4,
                available: buf.remaining(),
            });
        }

        let flags = buf.get_u8();
        let version = (flags >> 5) & 0x07;
        let piggybacked = (flags & 0x10) != 0;
        let teid_presence = (flags & 0x08) != 0;

        let message_type = buf.get_u8();
        let length = buf.get_u16();

        // Check version
        if version != 2 {
            return Err(GtpError::InvalidVersion(version));
        }

        let min_remaining = if teid_presence { 8 } else { 4 };
        if buf.remaining() < min_remaining {
            return Err(GtpError::BufferTooShort {
                needed: min_remaining,
                available: buf.remaining(),
            });
        }

        let teid = if teid_presence {
            Some(buf.get_u32())
        } else {
            None
        };

        // Sequence number (24 bits from upper 24 bits of u32)
        let sqn_raw = buf.get_u32();
        let sequence_number = sqn_raw >> 8;

        Ok(Self {
            version,
            piggybacked,
            teid_presence,
            message_type,
            length,
            teid,
            sequence_number,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_encode_decode_with_teid() {
        let header = Gtp2Header::new(
            Gtp2MessageType::CreateSessionRequest as u8,
            0x12345678,
            0x123456,
        );

        let mut buf = BytesMut::new();
        let mut h = header.clone();
        h.length = 100;
        h.encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = Gtp2Header::decode(&mut bytes).unwrap();

        assert_eq!(decoded.version, 2);
        assert!(decoded.teid_presence);
        assert_eq!(decoded.message_type, Gtp2MessageType::CreateSessionRequest as u8);
        assert_eq!(decoded.teid, Some(0x12345678));
        assert_eq!(decoded.sequence_number, 0x123456);
    }

    #[test]
    fn test_header_encode_decode_without_teid() {
        let header = Gtp2Header::new_no_teid(
            Gtp2MessageType::EchoRequest as u8,
            0x123456,
        );

        let mut buf = BytesMut::new();
        let mut h = header.clone();
        h.length = 0;
        h.encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = Gtp2Header::decode(&mut bytes).unwrap();

        assert_eq!(decoded.version, 2);
        assert!(!decoded.teid_presence);
        assert_eq!(decoded.teid, None);
        assert_eq!(decoded.sequence_number, 0x123456);
    }

    #[test]
    fn test_xid_sqn_conversion() {
        let xid = 0x123456;
        let sqn = Gtp2Header::xid_to_sqn(xid);
        let recovered = Gtp2Header::sqn_to_xid(sqn);
        assert_eq!(xid, recovered);
    }
}
