//! GTPv2 Messages
//!
//! Message structures and encoding/decoding for GTPv2-C protocol.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::error::{GtpError, GtpResult};
use super::header::{Gtp2Header, Gtp2MessageType};
use super::ie::{Gtp2Ie, Gtp2IeType};

/// GTPv2-C Message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtp2Message {
    /// Message header
    pub header: Gtp2Header,
    /// Information Elements
    pub ies: Vec<Gtp2Ie>,
}

impl Gtp2Message {
    /// Create a new GTPv2-C message
    pub fn new(header: Gtp2Header) -> Self {
        Self {
            header,
            ies: Vec::new(),
        }
    }

    /// Create an Echo Request message
    pub fn echo_request(sequence_number: u32) -> Self {
        let header = Gtp2Header::new_no_teid(
            Gtp2MessageType::EchoRequest as u8,
            sequence_number,
        );
        Self::new(header)
    }

    /// Create an Echo Response message
    pub fn echo_response(sequence_number: u32, recovery: u8) -> Self {
        let header = Gtp2Header::new_no_teid(
            Gtp2MessageType::EchoResponse as u8,
            sequence_number,
        );
        let mut msg = Self::new(header);

        // Add Recovery IE
        let mut ie_buf = BytesMut::new();
        ie_buf.put_u8(recovery);
        msg.ies.push(Gtp2Ie::from_slice(Gtp2IeType::Recovery as u8, 0, &ie_buf));

        msg
    }

    /// Add an IE to the message
    pub fn add_ie(&mut self, ie: Gtp2Ie) {
        self.ies.push(ie);
    }

    /// Get an IE by type and instance
    pub fn get_ie(&self, ie_type: u8, instance: u8) -> Option<&Gtp2Ie> {
        self.ies.iter().find(|ie| ie.ie_type == ie_type && ie.instance == instance)
    }

    /// Get first IE by type (any instance)
    pub fn get_ie_by_type(&self, ie_type: u8) -> Option<&Gtp2Ie> {
        self.ies.iter().find(|ie| ie.ie_type == ie_type)
    }

    /// Get all IEs of a specific type
    pub fn get_ies(&self, ie_type: u8) -> Vec<&Gtp2Ie> {
        self.ies.iter().filter(|ie| ie.ie_type == ie_type).collect()
    }

    /// Calculate message length (excluding first 4 bytes of header)
    fn calculate_length(&self) -> u16 {
        let mut length = 0u16;

        // Add TEID + sequence number if TEID present, else just sequence number
        if self.header.teid_presence {
            length += 8; // TEID(4) + SQN(3) + spare(1)
        } else {
            length += 4; // SQN(3) + spare(1)
        }

        // Add IE lengths
        for ie in &self.ies {
            length += ie.encoded_len() as u16;
        }

        length
    }

    /// Encode message to bytes
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();

        // Calculate and set length
        let mut header = self.header.clone();
        header.length = self.calculate_length();

        // Encode header
        header.encode(&mut buf);

        // Encode IEs
        for ie in &self.ies {
            ie.encode(&mut buf);
        }

        buf
    }

    /// Decode message from bytes
    pub fn decode(buf: &mut Bytes) -> GtpResult<Self> {
        // Decode header
        let header = Gtp2Header::decode(buf)?;

        let mut msg = Self::new(header.clone());

        // Calculate remaining payload length
        let header_extra = if header.teid_presence { 8 } else { 4 };
        let payload_len = header.length as usize - header_extra;

        if buf.remaining() < payload_len {
            return Err(GtpError::BufferTooShort {
                needed: payload_len,
                available: buf.remaining(),
            });
        }

        // Decode IEs
        let mut remaining = payload_len;
        while remaining > 0 && buf.remaining() > 0 {
            let start_pos = buf.remaining();
            let ie = Gtp2Ie::decode(buf)?;
            let consumed = start_pos - buf.remaining();
            remaining = remaining.saturating_sub(consumed);
            msg.ies.push(ie);
        }

        Ok(msg)
    }
}

/// Create Session Request message builder
#[derive(Debug, Clone)]
pub struct CreateSessionRequest {
    pub teid: u32,
    pub sequence_number: u32,
    pub ies: Vec<Gtp2Ie>,
}

impl CreateSessionRequest {
    pub fn new(teid: u32, sequence_number: u32) -> Self {
        Self {
            teid,
            sequence_number,
            ies: Vec::new(),
        }
    }

    pub fn add_ie(&mut self, ie: Gtp2Ie) {
        self.ies.push(ie);
    }

    pub fn encode(&self) -> BytesMut {
        let header = Gtp2Header::new(
            Gtp2MessageType::CreateSessionRequest as u8,
            self.teid,
            self.sequence_number,
        );
        let mut msg = Gtp2Message::new(header);
        msg.ies = self.ies.clone();
        msg.encode()
    }

    pub fn decode(msg: &Gtp2Message) -> GtpResult<Self> {
        if msg.header.message_type != Gtp2MessageType::CreateSessionRequest as u8 {
            return Err(GtpError::InvalidMessageType(msg.header.message_type));
        }
        Ok(Self {
            teid: msg.header.teid.unwrap_or(0),
            sequence_number: msg.header.sequence_number,
            ies: msg.ies.clone(),
        })
    }
}

/// Create Session Response message builder
#[derive(Debug, Clone)]
pub struct CreateSessionResponse {
    pub teid: u32,
    pub sequence_number: u32,
    pub ies: Vec<Gtp2Ie>,
}

impl CreateSessionResponse {
    pub fn new(teid: u32, sequence_number: u32) -> Self {
        Self {
            teid,
            sequence_number,
            ies: Vec::new(),
        }
    }

    pub fn add_ie(&mut self, ie: Gtp2Ie) {
        self.ies.push(ie);
    }

    pub fn encode(&self) -> BytesMut {
        let header = Gtp2Header::new(
            Gtp2MessageType::CreateSessionResponse as u8,
            self.teid,
            self.sequence_number,
        );
        let mut msg = Gtp2Message::new(header);
        msg.ies = self.ies.clone();
        msg.encode()
    }

    pub fn decode(msg: &Gtp2Message) -> GtpResult<Self> {
        if msg.header.message_type != Gtp2MessageType::CreateSessionResponse as u8 {
            return Err(GtpError::InvalidMessageType(msg.header.message_type));
        }
        Ok(Self {
            teid: msg.header.teid.unwrap_or(0),
            sequence_number: msg.header.sequence_number,
            ies: msg.ies.clone(),
        })
    }
}

/// Modify Bearer Request message builder
#[derive(Debug, Clone)]
pub struct ModifyBearerRequest {
    pub teid: u32,
    pub sequence_number: u32,
    pub ies: Vec<Gtp2Ie>,
}

impl ModifyBearerRequest {
    pub fn new(teid: u32, sequence_number: u32) -> Self {
        Self {
            teid,
            sequence_number,
            ies: Vec::new(),
        }
    }

    pub fn add_ie(&mut self, ie: Gtp2Ie) {
        self.ies.push(ie);
    }

    pub fn encode(&self) -> BytesMut {
        let header = Gtp2Header::new(
            Gtp2MessageType::ModifyBearerRequest as u8,
            self.teid,
            self.sequence_number,
        );
        let mut msg = Gtp2Message::new(header);
        msg.ies = self.ies.clone();
        msg.encode()
    }

    pub fn decode(msg: &Gtp2Message) -> GtpResult<Self> {
        if msg.header.message_type != Gtp2MessageType::ModifyBearerRequest as u8 {
            return Err(GtpError::InvalidMessageType(msg.header.message_type));
        }
        Ok(Self {
            teid: msg.header.teid.unwrap_or(0),
            sequence_number: msg.header.sequence_number,
            ies: msg.ies.clone(),
        })
    }
}

/// Modify Bearer Response message builder
#[derive(Debug, Clone)]
pub struct ModifyBearerResponse {
    pub teid: u32,
    pub sequence_number: u32,
    pub ies: Vec<Gtp2Ie>,
}

impl ModifyBearerResponse {
    pub fn new(teid: u32, sequence_number: u32) -> Self {
        Self {
            teid,
            sequence_number,
            ies: Vec::new(),
        }
    }

    pub fn add_ie(&mut self, ie: Gtp2Ie) {
        self.ies.push(ie);
    }

    pub fn encode(&self) -> BytesMut {
        let header = Gtp2Header::new(
            Gtp2MessageType::ModifyBearerResponse as u8,
            self.teid,
            self.sequence_number,
        );
        let mut msg = Gtp2Message::new(header);
        msg.ies = self.ies.clone();
        msg.encode()
    }

    pub fn decode(msg: &Gtp2Message) -> GtpResult<Self> {
        if msg.header.message_type != Gtp2MessageType::ModifyBearerResponse as u8 {
            return Err(GtpError::InvalidMessageType(msg.header.message_type));
        }
        Ok(Self {
            teid: msg.header.teid.unwrap_or(0),
            sequence_number: msg.header.sequence_number,
            ies: msg.ies.clone(),
        })
    }
}

/// Delete Session Request message builder
#[derive(Debug, Clone)]
pub struct DeleteSessionRequest {
    pub teid: u32,
    pub sequence_number: u32,
    pub ies: Vec<Gtp2Ie>,
}

impl DeleteSessionRequest {
    pub fn new(teid: u32, sequence_number: u32) -> Self {
        Self {
            teid,
            sequence_number,
            ies: Vec::new(),
        }
    }

    pub fn add_ie(&mut self, ie: Gtp2Ie) {
        self.ies.push(ie);
    }

    pub fn encode(&self) -> BytesMut {
        let header = Gtp2Header::new(
            Gtp2MessageType::DeleteSessionRequest as u8,
            self.teid,
            self.sequence_number,
        );
        let mut msg = Gtp2Message::new(header);
        msg.ies = self.ies.clone();
        msg.encode()
    }

    pub fn decode(msg: &Gtp2Message) -> GtpResult<Self> {
        if msg.header.message_type != Gtp2MessageType::DeleteSessionRequest as u8 {
            return Err(GtpError::InvalidMessageType(msg.header.message_type));
        }
        Ok(Self {
            teid: msg.header.teid.unwrap_or(0),
            sequence_number: msg.header.sequence_number,
            ies: msg.ies.clone(),
        })
    }
}

/// Delete Session Response message builder
#[derive(Debug, Clone)]
pub struct DeleteSessionResponse {
    pub teid: u32,
    pub sequence_number: u32,
    pub ies: Vec<Gtp2Ie>,
}

impl DeleteSessionResponse {
    pub fn new(teid: u32, sequence_number: u32) -> Self {
        Self {
            teid,
            sequence_number,
            ies: Vec::new(),
        }
    }

    pub fn add_ie(&mut self, ie: Gtp2Ie) {
        self.ies.push(ie);
    }

    pub fn encode(&self) -> BytesMut {
        let header = Gtp2Header::new(
            Gtp2MessageType::DeleteSessionResponse as u8,
            self.teid,
            self.sequence_number,
        );
        let mut msg = Gtp2Message::new(header);
        msg.ies = self.ies.clone();
        msg.encode()
    }

    pub fn decode(msg: &Gtp2Message) -> GtpResult<Self> {
        if msg.header.message_type != Gtp2MessageType::DeleteSessionResponse as u8 {
            return Err(GtpError::InvalidMessageType(msg.header.message_type));
        }
        Ok(Self {
            teid: msg.header.teid.unwrap_or(0),
            sequence_number: msg.header.sequence_number,
            ies: msg.ies.clone(),
        })
    }
}

/// Create Bearer Request message builder
#[derive(Debug, Clone)]
pub struct CreateBearerRequest {
    pub teid: u32,
    pub sequence_number: u32,
    pub ies: Vec<Gtp2Ie>,
}

impl CreateBearerRequest {
    pub fn new(teid: u32, sequence_number: u32) -> Self {
        Self {
            teid,
            sequence_number,
            ies: Vec::new(),
        }
    }

    pub fn add_ie(&mut self, ie: Gtp2Ie) {
        self.ies.push(ie);
    }

    pub fn encode(&self) -> BytesMut {
        let header = Gtp2Header::new(
            Gtp2MessageType::CreateBearerRequest as u8,
            self.teid,
            self.sequence_number,
        );
        let mut msg = Gtp2Message::new(header);
        msg.ies = self.ies.clone();
        msg.encode()
    }

    pub fn decode(msg: &Gtp2Message) -> GtpResult<Self> {
        if msg.header.message_type != Gtp2MessageType::CreateBearerRequest as u8 {
            return Err(GtpError::InvalidMessageType(msg.header.message_type));
        }
        Ok(Self {
            teid: msg.header.teid.unwrap_or(0),
            sequence_number: msg.header.sequence_number,
            ies: msg.ies.clone(),
        })
    }
}

/// Create Bearer Response message builder
#[derive(Debug, Clone)]
pub struct CreateBearerResponse {
    pub teid: u32,
    pub sequence_number: u32,
    pub ies: Vec<Gtp2Ie>,
}

impl CreateBearerResponse {
    pub fn new(teid: u32, sequence_number: u32) -> Self {
        Self {
            teid,
            sequence_number,
            ies: Vec::new(),
        }
    }

    pub fn add_ie(&mut self, ie: Gtp2Ie) {
        self.ies.push(ie);
    }

    pub fn encode(&self) -> BytesMut {
        let header = Gtp2Header::new(
            Gtp2MessageType::CreateBearerResponse as u8,
            self.teid,
            self.sequence_number,
        );
        let mut msg = Gtp2Message::new(header);
        msg.ies = self.ies.clone();
        msg.encode()
    }

    pub fn decode(msg: &Gtp2Message) -> GtpResult<Self> {
        if msg.header.message_type != Gtp2MessageType::CreateBearerResponse as u8 {
            return Err(GtpError::InvalidMessageType(msg.header.message_type));
        }
        Ok(Self {
            teid: msg.header.teid.unwrap_or(0),
            sequence_number: msg.header.sequence_number,
            ies: msg.ies.clone(),
        })
    }
}

/// Delete Bearer Request message builder
#[derive(Debug, Clone)]
pub struct DeleteBearerRequest {
    pub teid: u32,
    pub sequence_number: u32,
    pub ies: Vec<Gtp2Ie>,
}

impl DeleteBearerRequest {
    pub fn new(teid: u32, sequence_number: u32) -> Self {
        Self {
            teid,
            sequence_number,
            ies: Vec::new(),
        }
    }

    pub fn add_ie(&mut self, ie: Gtp2Ie) {
        self.ies.push(ie);
    }

    pub fn encode(&self) -> BytesMut {
        let header = Gtp2Header::new(
            Gtp2MessageType::DeleteBearerRequest as u8,
            self.teid,
            self.sequence_number,
        );
        let mut msg = Gtp2Message::new(header);
        msg.ies = self.ies.clone();
        msg.encode()
    }

    pub fn decode(msg: &Gtp2Message) -> GtpResult<Self> {
        if msg.header.message_type != Gtp2MessageType::DeleteBearerRequest as u8 {
            return Err(GtpError::InvalidMessageType(msg.header.message_type));
        }
        Ok(Self {
            teid: msg.header.teid.unwrap_or(0),
            sequence_number: msg.header.sequence_number,
            ies: msg.ies.clone(),
        })
    }
}

/// Delete Bearer Response message builder
#[derive(Debug, Clone)]
pub struct DeleteBearerResponse {
    pub teid: u32,
    pub sequence_number: u32,
    pub ies: Vec<Gtp2Ie>,
}

impl DeleteBearerResponse {
    pub fn new(teid: u32, sequence_number: u32) -> Self {
        Self {
            teid,
            sequence_number,
            ies: Vec::new(),
        }
    }

    pub fn add_ie(&mut self, ie: Gtp2Ie) {
        self.ies.push(ie);
    }

    pub fn encode(&self) -> BytesMut {
        let header = Gtp2Header::new(
            Gtp2MessageType::DeleteBearerResponse as u8,
            self.teid,
            self.sequence_number,
        );
        let mut msg = Gtp2Message::new(header);
        msg.ies = self.ies.clone();
        msg.encode()
    }

    pub fn decode(msg: &Gtp2Message) -> GtpResult<Self> {
        if msg.header.message_type != Gtp2MessageType::DeleteBearerResponse as u8 {
            return Err(GtpError::InvalidMessageType(msg.header.message_type));
        }
        Ok(Self {
            teid: msg.header.teid.unwrap_or(0),
            sequence_number: msg.header.sequence_number,
            ies: msg.ies.clone(),
        })
    }
}

/// Release Access Bearers Request message builder
#[derive(Debug, Clone)]
pub struct ReleaseAccessBearersRequest {
    pub teid: u32,
    pub sequence_number: u32,
    pub ies: Vec<Gtp2Ie>,
}

impl ReleaseAccessBearersRequest {
    pub fn new(teid: u32, sequence_number: u32) -> Self {
        Self {
            teid,
            sequence_number,
            ies: Vec::new(),
        }
    }

    pub fn add_ie(&mut self, ie: Gtp2Ie) {
        self.ies.push(ie);
    }

    pub fn encode(&self) -> BytesMut {
        let header = Gtp2Header::new(
            Gtp2MessageType::ReleaseAccessBearersRequest as u8,
            self.teid,
            self.sequence_number,
        );
        let mut msg = Gtp2Message::new(header);
        msg.ies = self.ies.clone();
        msg.encode()
    }

    pub fn decode(msg: &Gtp2Message) -> GtpResult<Self> {
        if msg.header.message_type != Gtp2MessageType::ReleaseAccessBearersRequest as u8 {
            return Err(GtpError::InvalidMessageType(msg.header.message_type));
        }
        Ok(Self {
            teid: msg.header.teid.unwrap_or(0),
            sequence_number: msg.header.sequence_number,
            ies: msg.ies.clone(),
        })
    }
}

/// Release Access Bearers Response message builder
#[derive(Debug, Clone)]
pub struct ReleaseAccessBearersResponse {
    pub teid: u32,
    pub sequence_number: u32,
    pub ies: Vec<Gtp2Ie>,
}

impl ReleaseAccessBearersResponse {
    pub fn new(teid: u32, sequence_number: u32) -> Self {
        Self {
            teid,
            sequence_number,
            ies: Vec::new(),
        }
    }

    pub fn add_ie(&mut self, ie: Gtp2Ie) {
        self.ies.push(ie);
    }

    pub fn encode(&self) -> BytesMut {
        let header = Gtp2Header::new(
            Gtp2MessageType::ReleaseAccessBearersResponse as u8,
            self.teid,
            self.sequence_number,
        );
        let mut msg = Gtp2Message::new(header);
        msg.ies = self.ies.clone();
        msg.encode()
    }

    pub fn decode(msg: &Gtp2Message) -> GtpResult<Self> {
        if msg.header.message_type != Gtp2MessageType::ReleaseAccessBearersResponse as u8 {
            return Err(GtpError::InvalidMessageType(msg.header.message_type));
        }
        Ok(Self {
            teid: msg.header.teid.unwrap_or(0),
            sequence_number: msg.header.sequence_number,
            ies: msg.ies.clone(),
        })
    }
}

/// Downlink Data Notification message builder
#[derive(Debug, Clone)]
pub struct DownlinkDataNotification {
    pub teid: u32,
    pub sequence_number: u32,
    pub ies: Vec<Gtp2Ie>,
}

impl DownlinkDataNotification {
    pub fn new(teid: u32, sequence_number: u32) -> Self {
        Self {
            teid,
            sequence_number,
            ies: Vec::new(),
        }
    }

    pub fn add_ie(&mut self, ie: Gtp2Ie) {
        self.ies.push(ie);
    }

    pub fn encode(&self) -> BytesMut {
        let header = Gtp2Header::new(
            Gtp2MessageType::DownlinkDataNotification as u8,
            self.teid,
            self.sequence_number,
        );
        let mut msg = Gtp2Message::new(header);
        msg.ies = self.ies.clone();
        msg.encode()
    }

    pub fn decode(msg: &Gtp2Message) -> GtpResult<Self> {
        if msg.header.message_type != Gtp2MessageType::DownlinkDataNotification as u8 {
            return Err(GtpError::InvalidMessageType(msg.header.message_type));
        }
        Ok(Self {
            teid: msg.header.teid.unwrap_or(0),
            sequence_number: msg.header.sequence_number,
            ies: msg.ies.clone(),
        })
    }
}

/// Downlink Data Notification Acknowledge message builder
#[derive(Debug, Clone)]
pub struct DownlinkDataNotificationAcknowledge {
    pub teid: u32,
    pub sequence_number: u32,
    pub ies: Vec<Gtp2Ie>,
}

impl DownlinkDataNotificationAcknowledge {
    pub fn new(teid: u32, sequence_number: u32) -> Self {
        Self {
            teid,
            sequence_number,
            ies: Vec::new(),
        }
    }

    pub fn add_ie(&mut self, ie: Gtp2Ie) {
        self.ies.push(ie);
    }

    pub fn encode(&self) -> BytesMut {
        let header = Gtp2Header::new(
            Gtp2MessageType::DownlinkDataNotificationAcknowledge as u8,
            self.teid,
            self.sequence_number,
        );
        let mut msg = Gtp2Message::new(header);
        msg.ies = self.ies.clone();
        msg.encode()
    }

    pub fn decode(msg: &Gtp2Message) -> GtpResult<Self> {
        if msg.header.message_type != Gtp2MessageType::DownlinkDataNotificationAcknowledge as u8 {
            return Err(GtpError::InvalidMessageType(msg.header.message_type));
        }
        Ok(Self {
            teid: msg.header.teid.unwrap_or(0),
            sequence_number: msg.header.sequence_number,
            ies: msg.ies.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_echo_request_encode_decode() {
        let msg = Gtp2Message::echo_request(0x123456);
        let encoded = msg.encode();

        let mut bytes = encoded.freeze();
        let decoded = Gtp2Message::decode(&mut bytes).unwrap();

        assert_eq!(decoded.header.message_type, Gtp2MessageType::EchoRequest as u8);
        assert!(!decoded.header.teid_presence);
        assert_eq!(decoded.header.sequence_number, 0x123456);
    }

    #[test]
    fn test_echo_response_encode_decode() {
        let msg = Gtp2Message::echo_response(0x123456, 42);
        let encoded = msg.encode();

        let mut bytes = encoded.freeze();
        let decoded = Gtp2Message::decode(&mut bytes).unwrap();

        assert_eq!(decoded.header.message_type, Gtp2MessageType::EchoResponse as u8);
        assert!(!decoded.header.teid_presence);

        let recovery_ie = decoded.get_ie_by_type(Gtp2IeType::Recovery as u8).unwrap();
        assert_eq!(recovery_ie.value[0], 42);
    }

    #[test]
    fn test_create_session_request() {
        let mut req = CreateSessionRequest::new(0x12345678, 0x123456);
        req.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Recovery as u8, 0, &[42]));

        let encoded = req.encode();
        let mut bytes = encoded.freeze();
        let decoded = Gtp2Message::decode(&mut bytes).unwrap();

        assert_eq!(decoded.header.message_type, Gtp2MessageType::CreateSessionRequest as u8);
        assert_eq!(decoded.header.teid, Some(0x12345678));
        assert_eq!(decoded.header.sequence_number, 0x123456);
        assert_eq!(decoded.ies.len(), 1);
    }

    #[test]
    fn test_message_with_multiple_ies() {
        let mut req = CreateSessionRequest::new(0x12345678, 0x123456);
        req.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Recovery as u8, 0, &[42]));
        req.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Ebi as u8, 0, &[5]));
        req.add_ie(Gtp2Ie::from_slice(Gtp2IeType::RatType as u8, 0, &[6]));

        let encoded = req.encode();
        let mut bytes = encoded.freeze();
        let decoded = Gtp2Message::decode(&mut bytes).unwrap();

        assert_eq!(decoded.ies.len(), 3);
    }
}
