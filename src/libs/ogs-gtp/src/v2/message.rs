//! GTPv2 Messages
//!
//! Message structures and encoding/decoding for GTPv2-C protocol.

use super::header::{Gtp2Header, Gtp2MessageType};
use super::ie::{Gtp2BearerContextIe, Gtp2Ie, Gtp2IeType};
use crate::error::{GtpError, GtpResult};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// GTPv2-C Message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtp2Message {
    /// Message header
    pub header: Gtp2Header,
    /// Information Elements
    pub ies: Vec<Gtp2Ie>,
    /// Piggybacked message following this one (P flag, TS 29.274 Section 5.5.1)
    pub piggybacked: Option<Box<Gtp2Message>>,
}

impl Gtp2Message {
    /// Create a new GTPv2-C message
    pub fn new(header: Gtp2Header) -> Self {
        Self {
            header,
            ies: Vec::new(),
            piggybacked: None,
        }
    }

    /// Create an Echo Request message
    pub fn echo_request(sequence_number: u32) -> Self {
        let header = Gtp2Header::new_no_teid(Gtp2MessageType::EchoRequest as u8, sequence_number);
        Self::new(header)
    }

    /// Create an Echo Response message
    pub fn echo_response(sequence_number: u32, recovery: u8) -> Self {
        let header = Gtp2Header::new_no_teid(Gtp2MessageType::EchoResponse as u8, sequence_number);
        let mut msg = Self::new(header);

        // Add Recovery IE
        let mut ie_buf = BytesMut::new();
        ie_buf.put_u8(recovery);
        msg.ies
            .push(Gtp2Ie::from_slice(Gtp2IeType::Recovery as u8, 0, &ie_buf));

        msg
    }

    /// Add an IE to the message
    pub fn add_ie(&mut self, ie: Gtp2Ie) {
        self.ies.push(ie);
    }

    /// Attach a piggybacked message (sets the P flag on encode).
    /// Per TS 29.274 the piggybacked message is a triggered initial message
    /// carried in the same UDP datagram (e.g. Create Bearer Request after a
    /// Create Session Response).
    pub fn set_piggybacked(&mut self, msg: Gtp2Message) {
        self.piggybacked = Some(Box::new(msg));
    }

    /// Get an IE by type and instance
    pub fn get_ie(&self, ie_type: u8, instance: u8) -> Option<&Gtp2Ie> {
        self.ies
            .iter()
            .find(|ie| ie.ie_type == ie_type && ie.instance == instance)
    }

    /// Get first IE by type (any instance)
    pub fn get_ie_by_type(&self, ie_type: u8) -> Option<&Gtp2Ie> {
        self.ies.iter().find(|ie| ie.ie_type == ie_type)
    }

    /// Get all IEs of a specific type
    pub fn get_ies(&self, ie_type: u8) -> Vec<&Gtp2Ie> {
        self.ies.iter().filter(|ie| ie.ie_type == ie_type).collect()
    }

    /// Add a Bearer Context grouped IE with the given instance
    pub fn add_bearer_context(&mut self, instance: u8, bearer: &Gtp2BearerContextIe) {
        self.ies.push(bearer.to_ie(instance));
    }

    /// Get a Bearer Context grouped IE by instance, if present
    pub fn bearer_context(&self, instance: u8) -> GtpResult<Option<Gtp2BearerContextIe>> {
        match self.get_ie(Gtp2IeType::BearerContext as u8, instance) {
            Some(ie) => Ok(Some(Gtp2BearerContextIe::decode(&ie.value)?)),
            None => Ok(None),
        }
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

        // Calculate and set length; the P flag reflects an attached message
        let mut header = self.header.clone();
        header.piggybacked = self.piggybacked.is_some();
        header.length = self.calculate_length();

        // Encode header
        header.encode(&mut buf);

        // Encode IEs
        for ie in &self.ies {
            ie.encode(&mut buf);
        }

        // Encode piggybacked message (its own header carries its own length)
        if let Some(ref piggybacked) = self.piggybacked {
            buf.put_slice(&piggybacked.encode());
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
        let payload_len =
            (header.length as usize)
                .checked_sub(header_extra)
                .ok_or(GtpError::InvalidHeader(
                    "Length shorter than TEID/sequence fields".to_string(),
                ))?;

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

        // P flag set: a piggybacked message follows in the same datagram
        if header.piggybacked {
            if buf.remaining() == 0 {
                return Err(GtpError::InvalidFormat(
                    "P flag set but no piggybacked message follows".to_string(),
                ));
            }
            msg.piggybacked = Some(Box::new(Self::decode(buf)?));
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

        assert_eq!(
            decoded.header.message_type,
            Gtp2MessageType::EchoRequest as u8
        );
        assert!(!decoded.header.teid_presence);
        assert_eq!(decoded.header.sequence_number, 0x123456);
    }

    #[test]
    fn test_echo_response_encode_decode() {
        let msg = Gtp2Message::echo_response(0x123456, 42);
        let encoded = msg.encode();

        let mut bytes = encoded.freeze();
        let decoded = Gtp2Message::decode(&mut bytes).unwrap();

        assert_eq!(
            decoded.header.message_type,
            Gtp2MessageType::EchoResponse as u8
        );
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

        assert_eq!(
            decoded.header.message_type,
            Gtp2MessageType::CreateSessionRequest as u8
        );
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

    #[test]
    fn test_create_session_request_with_bearer_context_round_trip() {
        use crate::v2::ie::{
            Gtp2BearerContextIe, Gtp2BearerQosIe, Gtp2FTeidIe, Gtp2IndicationIe, Gtp2PaaIe,
        };

        let header = Gtp2Header::new(
            Gtp2MessageType::CreateSessionRequest as u8,
            0x12345678,
            0x123456,
        );
        let mut msg = Gtp2Message::new(header);

        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::Imsi as u8,
            0,
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
        ));
        msg.add_ie(Gtp2FTeidIe::new_ipv4(10, 0x11111111, [10, 0, 0, 10]).to_ie(0));
        msg.add_ie(Gtp2PaaIe::ipv4([10, 45, 0, 2]).to_ie(0));
        msg.add_ie(
            Gtp2IndicationIe {
                daf: true,
                p: true,
                ..Default::default()
            }
            .to_ie(0),
        );

        let mut bearer = Gtp2BearerContextIe::new();
        bearer.set_ebi(5);
        bearer.set_fteid(0, &Gtp2FTeidIe::new_ipv4(0, 0x22222222, [10, 0, 0, 20]));
        bearer.set_bearer_qos(&Gtp2BearerQosIe::new(9, 100000, 200000, 0, 0));
        msg.add_bearer_context(0, &bearer);

        let encoded = msg.encode();
        let mut bytes = encoded.freeze();
        let decoded = Gtp2Message::decode(&mut bytes).unwrap();

        assert_eq!(
            decoded.header.message_type,
            Gtp2MessageType::CreateSessionRequest as u8
        );
        assert_eq!(decoded.header.teid, Some(0x12345678));
        assert_eq!(decoded.ies, msg.ies);

        let decoded_bearer = decoded.bearer_context(0).unwrap().unwrap();
        assert_eq!(decoded_bearer, bearer);
        assert_eq!(decoded_bearer.ebi().unwrap(), 5);
        assert_eq!(
            decoded_bearer.fteid(0).unwrap().unwrap().teid,
            0x22222222
        );
        assert_eq!(decoded_bearer.bearer_qos().unwrap().unwrap().qci, 9);

        let indication = crate::v2::ie::Gtp2IndicationIe::decode(
            &decoded
                .get_ie(Gtp2IeType::Indication as u8, 0)
                .unwrap()
                .value,
        )
        .unwrap();
        assert!(indication.daf);
        assert!(indication.p);
        assert!(!indication.oi);
    }

    #[test]
    fn test_piggybacked_message_round_trip() {
        // Create Session Response carrying a piggybacked Create Bearer Request
        let mut response = Gtp2Message::new(Gtp2Header::new(
            Gtp2MessageType::CreateSessionResponse as u8,
            0x11112222,
            0x000100,
        ));
        response.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Cause as u8, 0, &[16, 0]));

        let mut piggybacked = Gtp2Message::new(Gtp2Header::new(
            Gtp2MessageType::CreateBearerRequest as u8,
            0x11112222,
            0x000101,
        ));
        piggybacked.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Ebi as u8, 0, &[5]));
        response.set_piggybacked(piggybacked.clone());

        let encoded = response.encode();
        // P flag must be set in the first header
        assert_eq!(encoded[0] & 0x10, 0x10);

        let mut bytes = encoded.freeze();
        let decoded = Gtp2Message::decode(&mut bytes).unwrap();

        assert!(decoded.header.piggybacked);
        assert_eq!(
            decoded.header.message_type,
            Gtp2MessageType::CreateSessionResponse as u8
        );

        let decoded_piggybacked = decoded.piggybacked.as_deref().unwrap();
        assert_eq!(
            decoded_piggybacked.header.message_type,
            Gtp2MessageType::CreateBearerRequest as u8
        );
        assert!(!decoded_piggybacked.header.piggybacked);
        assert_eq!(decoded_piggybacked.ies, piggybacked.ies);
        assert_eq!(bytes.remaining(), 0);
    }

    #[test]
    fn test_piggyback_flag_without_message_rejected() {
        let msg = Gtp2Message::echo_response(0x123456, 42);
        let mut encoded = msg.encode();
        // Force the P flag without appending a second message
        encoded[0] |= 0x10;

        let mut bytes = encoded.freeze();
        assert!(Gtp2Message::decode(&mut bytes).is_err());
    }

    #[test]
    fn test_header_length_underflow_rejected() {
        // T flag set but length (4) cannot cover TEID + sequence (8 octets)
        let bytes: &[u8] = &[
            0x48, 0x20, 0x00, 0x04, // v2, T=1, CSR, length=4
            0x00, 0x00, 0x00, 0x01, // TEID
            0x00, 0x00, 0x01, 0x00, // sequence + spare
        ];
        let mut buf = Bytes::copy_from_slice(bytes);
        assert!(Gtp2Message::decode(&mut buf).is_err());
    }
}
