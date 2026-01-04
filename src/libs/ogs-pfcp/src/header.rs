//! PFCP Header
//!
//! PFCP message header as specified in 3GPP TS 29.244.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::error::{PfcpError, PfcpResult};
use crate::types::PFCP_VERSION;

/// PFCP Header length without SEID (8 bytes)
pub const PFCP_HEADER_LEN: usize = 8;

/// PFCP Header length with SEID (16 bytes)
pub const PFCP_HEADER_LEN_WITH_SEID: usize = 16;

/// PFCP Message Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PfcpMessageType {
    // Node related messages (no SEID)
    HeartbeatRequest = 1,
    HeartbeatResponse = 2,
    PfdManagementRequest = 3,
    PfdManagementResponse = 4,
    AssociationSetupRequest = 5,
    AssociationSetupResponse = 6,
    AssociationUpdateRequest = 7,
    AssociationUpdateResponse = 8,
    AssociationReleaseRequest = 9,
    AssociationReleaseResponse = 10,
    VersionNotSupportedResponse = 11,
    NodeReportRequest = 12,
    NodeReportResponse = 13,
    SessionSetDeletionRequest = 14,
    SessionSetDeletionResponse = 15,
    SessionSetModificationRequest = 16,
    SessionSetModificationResponse = 17,
    
    // Session related messages (with SEID)
    SessionEstablishmentRequest = 50,
    SessionEstablishmentResponse = 51,
    SessionModificationRequest = 52,
    SessionModificationResponse = 53,
    SessionDeletionRequest = 54,
    SessionDeletionResponse = 55,
    SessionReportRequest = 56,
    SessionReportResponse = 57,
}

impl TryFrom<u8> for PfcpMessageType {
    type Error = PfcpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::HeartbeatRequest),
            2 => Ok(Self::HeartbeatResponse),
            3 => Ok(Self::PfdManagementRequest),
            4 => Ok(Self::PfdManagementResponse),
            5 => Ok(Self::AssociationSetupRequest),
            6 => Ok(Self::AssociationSetupResponse),
            7 => Ok(Self::AssociationUpdateRequest),
            8 => Ok(Self::AssociationUpdateResponse),
            9 => Ok(Self::AssociationReleaseRequest),
            10 => Ok(Self::AssociationReleaseResponse),
            11 => Ok(Self::VersionNotSupportedResponse),
            12 => Ok(Self::NodeReportRequest),
            13 => Ok(Self::NodeReportResponse),
            14 => Ok(Self::SessionSetDeletionRequest),
            15 => Ok(Self::SessionSetDeletionResponse),
            16 => Ok(Self::SessionSetModificationRequest),
            17 => Ok(Self::SessionSetModificationResponse),
            50 => Ok(Self::SessionEstablishmentRequest),
            51 => Ok(Self::SessionEstablishmentResponse),
            52 => Ok(Self::SessionModificationRequest),
            53 => Ok(Self::SessionModificationResponse),
            54 => Ok(Self::SessionDeletionRequest),
            55 => Ok(Self::SessionDeletionResponse),
            56 => Ok(Self::SessionReportRequest),
            57 => Ok(Self::SessionReportResponse),
            _ => Err(PfcpError::InvalidMessageType(value)),
        }
    }
}

impl PfcpMessageType {
    /// Check if this message type requires SEID
    pub fn has_seid(&self) -> bool {
        matches!(
            self,
            Self::SessionEstablishmentRequest
                | Self::SessionEstablishmentResponse
                | Self::SessionModificationRequest
                | Self::SessionModificationResponse
                | Self::SessionDeletionRequest
                | Self::SessionDeletionResponse
                | Self::SessionReportRequest
                | Self::SessionReportResponse
        )
    }

    /// Get the name of the message type
    pub fn name(&self) -> &'static str {
        match self {
            Self::HeartbeatRequest => "Heartbeat Request",
            Self::HeartbeatResponse => "Heartbeat Response",
            Self::PfdManagementRequest => "PFD Management Request",
            Self::PfdManagementResponse => "PFD Management Response",
            Self::AssociationSetupRequest => "Association Setup Request",
            Self::AssociationSetupResponse => "Association Setup Response",
            Self::AssociationUpdateRequest => "Association Update Request",
            Self::AssociationUpdateResponse => "Association Update Response",
            Self::AssociationReleaseRequest => "Association Release Request",
            Self::AssociationReleaseResponse => "Association Release Response",
            Self::VersionNotSupportedResponse => "Version Not Supported Response",
            Self::NodeReportRequest => "Node Report Request",
            Self::NodeReportResponse => "Node Report Response",
            Self::SessionSetDeletionRequest => "Session Set Deletion Request",
            Self::SessionSetDeletionResponse => "Session Set Deletion Response",
            Self::SessionSetModificationRequest => "Session Set Modification Request",
            Self::SessionSetModificationResponse => "Session Set Modification Response",
            Self::SessionEstablishmentRequest => "Session Establishment Request",
            Self::SessionEstablishmentResponse => "Session Establishment Response",
            Self::SessionModificationRequest => "Session Modification Request",
            Self::SessionModificationResponse => "Session Modification Response",
            Self::SessionDeletionRequest => "Session Deletion Request",
            Self::SessionDeletionResponse => "Session Deletion Response",
            Self::SessionReportRequest => "Session Report Request",
            Self::SessionReportResponse => "Session Report Response",
        }
    }
}


/// PFCP Header structure
/// 
/// Format (without SEID - 8 bytes):
/// ```text
/// +-------+-------+-------+-------+-------+-------+-------+-------+
/// |  Ver  | Spare | S | MP|       Message Type                    |
/// +-------+-------+-------+-------+-------+-------+-------+-------+
/// |                    Message Length                             |
/// +-------+-------+-------+-------+-------+-------+-------+-------+
/// |                    Sequence Number                            |
/// +-------+-------+-------+-------+-------+-------+-------+-------+
/// |  Spare                                                        |
/// +-------+-------+-------+-------+-------+-------+-------+-------+
/// ```
/// 
/// Format (with SEID - 16 bytes):
/// ```text
/// +-------+-------+-------+-------+-------+-------+-------+-------+
/// |  Ver  | Spare | S | MP|       Message Type                    |
/// +-------+-------+-------+-------+-------+-------+-------+-------+
/// |                    Message Length                             |
/// +-------+-------+-------+-------+-------+-------+-------+-------+
/// |                    SEID (8 bytes)                             |
/// +-------+-------+-------+-------+-------+-------+-------+-------+
/// |                    Sequence Number                            |
/// +-------+-------+-------+-------+-------+-------+-------+-------+
/// |  Spare                                                        |
/// +-------+-------+-------+-------+-------+-------+-------+-------+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PfcpHeader {
    /// PFCP version (should be 1)
    pub version: u8,
    /// SEID flag (S bit)
    pub seid_presence: bool,
    /// Message Priority flag (MP bit)
    pub message_priority: bool,
    /// Message type
    pub message_type: PfcpMessageType,
    /// Message length (excluding first 4 bytes)
    pub length: u16,
    /// Session Endpoint Identifier (optional)
    pub seid: Option<u64>,
    /// Sequence number
    pub sequence_number: u32,
    /// Message priority value (if MP bit is set)
    pub priority: Option<u8>,
}

impl PfcpHeader {
    /// Create a new PFCP header without SEID
    pub fn new(message_type: PfcpMessageType, sequence_number: u32) -> Self {
        Self {
            version: PFCP_VERSION,
            seid_presence: false,
            message_priority: false,
            message_type,
            length: 0,
            seid: None,
            sequence_number,
            priority: None,
        }
    }

    /// Create a new PFCP header with SEID
    pub fn new_with_seid(message_type: PfcpMessageType, seid: u64, sequence_number: u32) -> Self {
        Self {
            version: PFCP_VERSION,
            seid_presence: true,
            message_priority: false,
            message_type,
            length: 0,
            seid: Some(seid),
            sequence_number,
            priority: None,
        }
    }

    /// Get the header length
    pub fn header_len(&self) -> usize {
        if self.seid_presence {
            PFCP_HEADER_LEN_WITH_SEID
        } else {
            PFCP_HEADER_LEN
        }
    }

    /// Encode the header to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        // First byte: version (3 bits) | spare (2 bits) | S (1 bit) | MP (1 bit) | spare (1 bit)
        let first_byte = ((self.version & 0x07) << 5)
            | ((self.seid_presence as u8) << 2)
            | ((self.message_priority as u8) << 1);
        buf.put_u8(first_byte);
        
        // Message type
        buf.put_u8(self.message_type as u8);
        
        // Message length
        buf.put_u16(self.length);
        
        // SEID (if present)
        if let Some(seid) = self.seid {
            buf.put_u64(seid);
        }
        
        // Sequence number (3 bytes) + spare/priority (1 byte)
        let seq_bytes = self.sequence_number.to_be_bytes();
        buf.put_slice(&seq_bytes[1..4]); // Only 3 bytes
        
        // Priority or spare
        let last_byte = self.priority.unwrap_or(0) << 4;
        buf.put_u8(last_byte);
    }

    /// Decode header from bytes
    pub fn decode(buf: &mut Bytes) -> PfcpResult<Self> {
        if buf.remaining() < 4 {
            return Err(PfcpError::BufferTooShort {
                needed: 4,
                available: buf.remaining(),
            });
        }

        let first_byte = buf.get_u8();
        let version = (first_byte >> 5) & 0x07;
        let seid_presence = (first_byte >> 2) & 0x01 != 0;
        let message_priority = (first_byte >> 1) & 0x01 != 0;

        if version != PFCP_VERSION {
            return Err(PfcpError::VersionNotSupported(version));
        }

        let message_type = PfcpMessageType::try_from(buf.get_u8())?;
        let length = buf.get_u16();

        let min_remaining = if seid_presence { 12 } else { 4 };
        if buf.remaining() < min_remaining {
            return Err(PfcpError::BufferTooShort {
                needed: min_remaining,
                available: buf.remaining(),
            });
        }

        let seid = if seid_presence {
            Some(buf.get_u64())
        } else {
            None
        };

        // Sequence number (3 bytes)
        let mut seq_bytes = [0u8; 4];
        buf.copy_to_slice(&mut seq_bytes[1..4]);
        let sequence_number = u32::from_be_bytes(seq_bytes);

        // Priority/spare byte
        let last_byte = buf.get_u8();
        let priority = if message_priority {
            Some((last_byte >> 4) & 0x0F)
        } else {
            None
        };

        Ok(Self {
            version,
            seid_presence,
            message_priority,
            message_type,
            length,
            seid,
            sequence_number,
            priority,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_encode_decode_no_seid() {
        let header = PfcpHeader::new(PfcpMessageType::HeartbeatRequest, 12345);
        let mut buf = BytesMut::new();
        header.encode(&mut buf);
        
        let mut bytes = buf.freeze();
        let decoded = PfcpHeader::decode(&mut bytes).unwrap();
        
        assert_eq!(decoded.version, PFCP_VERSION);
        assert_eq!(decoded.message_type, PfcpMessageType::HeartbeatRequest);
        assert_eq!(decoded.sequence_number, 12345);
        assert!(!decoded.seid_presence);
        assert!(decoded.seid.is_none());
    }

    #[test]
    fn test_header_encode_decode_with_seid() {
        let header = PfcpHeader::new_with_seid(
            PfcpMessageType::SessionEstablishmentRequest,
            0x123456789ABCDEF0,
            54321,
        );
        let mut buf = BytesMut::new();
        header.encode(&mut buf);
        
        let mut bytes = buf.freeze();
        let decoded = PfcpHeader::decode(&mut bytes).unwrap();
        
        assert_eq!(decoded.version, PFCP_VERSION);
        assert_eq!(decoded.message_type, PfcpMessageType::SessionEstablishmentRequest);
        assert_eq!(decoded.sequence_number, 54321);
        assert!(decoded.seid_presence);
        assert_eq!(decoded.seid, Some(0x123456789ABCDEF0));
    }

    #[test]
    fn test_message_type_has_seid() {
        assert!(!PfcpMessageType::HeartbeatRequest.has_seid());
        assert!(!PfcpMessageType::AssociationSetupRequest.has_seid());
        assert!(PfcpMessageType::SessionEstablishmentRequest.has_seid());
        assert!(PfcpMessageType::SessionModificationRequest.has_seid());
    }
}
