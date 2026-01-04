//! Diameter message header and base message types
//!
//! Message format (RFC 6733):
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |    Version    |                 Message Length                |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | command flags |                  Command-Code                 |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Application-ID                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      Hop-by-Hop Identifier                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      End-to-End Identifier                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  AVPs ...
//! +-+-+-+-+-+-+-+-+-+-+-+-+-
//! ```

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::avp::Avp;
use crate::error::{DiameterError, DiameterResult};
use crate::DIAMETER_VERSION;

/// Diameter message header size
pub const DIAMETER_HEADER_SIZE: usize = 20;

/// Command flags
pub mod cmd_flags {
    /// Request bit
    pub const REQUEST: u8 = 0x80;
    /// Proxiable bit
    pub const PROXIABLE: u8 = 0x40;
    /// Error bit
    pub const ERROR: u8 = 0x20;
    /// Potentially re-transmitted bit
    pub const RETRANSMIT: u8 = 0x10;
}

/// Diameter message header
#[derive(Debug, Clone)]
pub struct DiameterHeader {
    /// Protocol version (always 1)
    pub version: u8,
    /// Message length (including header)
    pub length: u32,
    /// Command flags
    pub flags: u8,
    /// Command code
    pub command_code: u32,
    /// Application ID
    pub application_id: u32,
    /// Hop-by-Hop identifier
    pub hop_by_hop_id: u32,
    /// End-to-End identifier
    pub end_to_end_id: u32,
}

impl DiameterHeader {
    /// Create a new request header
    pub fn new_request(command_code: u32, application_id: u32) -> Self {
        Self {
            version: DIAMETER_VERSION,
            length: DIAMETER_HEADER_SIZE as u32,
            flags: cmd_flags::REQUEST | cmd_flags::PROXIABLE,
            command_code,
            application_id,
            hop_by_hop_id: 0,
            end_to_end_id: 0,
        }
    }

    /// Create a new answer header from a request
    pub fn new_answer(request: &DiameterHeader) -> Self {
        Self {
            version: DIAMETER_VERSION,
            length: DIAMETER_HEADER_SIZE as u32,
            flags: cmd_flags::PROXIABLE, // Clear request bit
            command_code: request.command_code,
            application_id: request.application_id,
            hop_by_hop_id: request.hop_by_hop_id,
            end_to_end_id: request.end_to_end_id,
        }
    }

    /// Check if this is a request
    pub fn is_request(&self) -> bool {
        self.flags & cmd_flags::REQUEST != 0
    }

    /// Check if this is an answer
    pub fn is_answer(&self) -> bool {
        !self.is_request()
    }

    /// Check if this is proxiable
    pub fn is_proxiable(&self) -> bool {
        self.flags & cmd_flags::PROXIABLE != 0
    }

    /// Check if this is an error
    pub fn is_error(&self) -> bool {
        self.flags & cmd_flags::ERROR != 0
    }

    /// Set error flag
    pub fn set_error(&mut self) {
        self.flags |= cmd_flags::ERROR;
    }

    /// Encode header to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.version);
        // Length is 3 bytes
        buf.put_u8(((self.length >> 16) & 0xFF) as u8);
        buf.put_u16((self.length & 0xFFFF) as u16);
        buf.put_u8(self.flags);
        // Command code is 3 bytes
        buf.put_u8(((self.command_code >> 16) & 0xFF) as u8);
        buf.put_u16((self.command_code & 0xFFFF) as u16);
        buf.put_u32(self.application_id);
        buf.put_u32(self.hop_by_hop_id);
        buf.put_u32(self.end_to_end_id);
    }

    /// Decode header from bytes
    pub fn decode(buf: &mut Bytes) -> DiameterResult<Self> {
        if buf.remaining() < DIAMETER_HEADER_SIZE {
            return Err(DiameterError::BufferTooSmall {
                needed: DIAMETER_HEADER_SIZE,
                available: buf.remaining(),
            });
        }

        let version = buf.get_u8();
        if version != DIAMETER_VERSION {
            return Err(DiameterError::Protocol(format!(
                "Unsupported Diameter version: {}",
                version
            )));
        }

        let len_high = buf.get_u8() as u32;
        let len_low = buf.get_u16() as u32;
        let length = (len_high << 16) | len_low;

        let flags = buf.get_u8();
        let cmd_high = buf.get_u8() as u32;
        let cmd_low = buf.get_u16() as u32;
        let command_code = (cmd_high << 16) | cmd_low;

        let application_id = buf.get_u32();
        let hop_by_hop_id = buf.get_u32();
        let end_to_end_id = buf.get_u32();

        Ok(Self {
            version,
            length,
            flags,
            command_code,
            application_id,
            hop_by_hop_id,
            end_to_end_id,
        })
    }
}

/// Diameter message (header + AVPs)
#[derive(Debug, Clone)]
pub struct DiameterMessage {
    /// Message header
    pub header: DiameterHeader,
    /// AVPs
    pub avps: Vec<Avp>,
}

impl DiameterMessage {
    /// Create a new message
    pub fn new(header: DiameterHeader, avps: Vec<Avp>) -> Self {
        Self { header, avps }
    }

    /// Create a new request message
    pub fn new_request(command_code: u32, application_id: u32) -> Self {
        Self {
            header: DiameterHeader::new_request(command_code, application_id),
            avps: Vec::new(),
        }
    }

    /// Create a new answer message from a request
    pub fn new_answer(request: &DiameterMessage) -> Self {
        Self {
            header: DiameterHeader::new_answer(&request.header),
            avps: Vec::new(),
        }
    }

    /// Add an AVP to the message
    pub fn add_avp(&mut self, avp: Avp) {
        self.avps.push(avp);
    }

    /// Find an AVP by code
    pub fn find_avp(&self, code: u32) -> Option<&Avp> {
        crate::avp::find_avp(&self.avps, code)
    }

    /// Find an AVP by code and vendor ID
    pub fn find_vendor_avp(&self, code: u32, vendor_id: u32) -> Option<&Avp> {
        crate::avp::find_vendor_avp(&self.avps, code, vendor_id)
    }

    /// Calculate the total message length
    pub fn calculate_length(&self) -> u32 {
        let avp_len: usize = self.avps.iter().map(|a| a.encoded_len()).sum();
        (DIAMETER_HEADER_SIZE + avp_len) as u32
    }

    /// Encode message to bytes
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(self.calculate_length() as usize);

        // Update length in header
        let mut header = self.header.clone();
        header.length = self.calculate_length();
        header.encode(&mut buf);

        // Encode AVPs
        for avp in &self.avps {
            avp.encode(&mut buf);
        }

        buf
    }

    /// Decode message from bytes
    pub fn decode(buf: &mut Bytes) -> DiameterResult<Self> {
        let header = DiameterHeader::decode(buf)?;

        let avp_len = header.length as usize - DIAMETER_HEADER_SIZE;
        if buf.remaining() < avp_len {
            return Err(DiameterError::BufferTooSmall {
                needed: avp_len,
                available: buf.remaining(),
            });
        }

        let mut avp_buf = buf.copy_to_bytes(avp_len);
        let mut avps = Vec::new();

        while avp_buf.has_remaining() {
            let avp = Avp::decode(&mut avp_buf)?;
            avps.push(avp);
        }

        Ok(Self { header, avps })
    }

    /// Get Session-Id AVP value
    pub fn session_id(&self) -> Option<&str> {
        self.find_avp(crate::common::avp_code::SESSION_ID)?
            .as_utf8_string()
    }

    /// Get Origin-Host AVP value
    pub fn origin_host(&self) -> Option<&str> {
        self.find_avp(crate::common::avp_code::ORIGIN_HOST)?
            .as_utf8_string()
    }

    /// Get Origin-Realm AVP value
    pub fn origin_realm(&self) -> Option<&str> {
        self.find_avp(crate::common::avp_code::ORIGIN_REALM)?
            .as_utf8_string()
    }

    /// Get Destination-Host AVP value
    pub fn destination_host(&self) -> Option<&str> {
        self.find_avp(crate::common::avp_code::DESTINATION_HOST)?
            .as_utf8_string()
    }

    /// Get Destination-Realm AVP value
    pub fn destination_realm(&self) -> Option<&str> {
        self.find_avp(crate::common::avp_code::DESTINATION_REALM)?
            .as_utf8_string()
    }

    /// Get Result-Code AVP value
    pub fn result_code(&self) -> Option<u32> {
        self.find_avp(crate::common::avp_code::RESULT_CODE)?
            .as_u32()
    }

    /// Get User-Name AVP value
    pub fn user_name(&self) -> Option<&str> {
        self.find_avp(crate::common::avp_code::USER_NAME)?
            .as_utf8_string()
    }
}

/// Base Diameter command codes (RFC 6733)
pub mod base_cmd {
    /// Capabilities-Exchange-Request/Answer
    pub const CAPABILITIES_EXCHANGE: u32 = 257;
    /// Re-Auth-Request/Answer
    pub const RE_AUTH: u32 = 258;
    /// Accounting-Request/Answer
    pub const ACCOUNTING: u32 = 271;
    /// Abort-Session-Request/Answer
    pub const ABORT_SESSION: u32 = 274;
    /// Session-Termination-Request/Answer
    pub const SESSION_TERMINATION: u32 = 275;
    /// Device-Watchdog-Request/Answer
    pub const DEVICE_WATCHDOG: u32 = 280;
    /// Disconnect-Peer-Request/Answer
    pub const DISCONNECT_PEER: u32 = 282;
}

/// Base Diameter application ID
pub const BASE_APPLICATION_ID: u32 = 0;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::avp::AvpData;

    #[test]
    fn test_header_encode_decode() {
        let header = DiameterHeader::new_request(318, 16777251);
        let mut buf = BytesMut::new();
        header.encode(&mut buf);

        let mut bytes = buf.freeze();
        let decoded = DiameterHeader::decode(&mut bytes).unwrap();

        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.command_code, 318);
        assert_eq!(decoded.application_id, 16777251);
        assert!(decoded.is_request());
    }

    #[test]
    fn test_message_encode_decode() {
        let mut msg = DiameterMessage::new_request(318, 16777251);
        msg.add_avp(Avp::mandatory(263, AvpData::Utf8String("test-session".to_string())));
        msg.add_avp(Avp::mandatory(264, AvpData::DiameterIdentity("mme.epc.mnc001.mcc001.3gppnetwork.org".to_string())));

        let encoded = msg.encode();
        let mut bytes = encoded.freeze();
        let decoded = DiameterMessage::decode(&mut bytes).unwrap();

        assert_eq!(decoded.header.command_code, 318);
        assert_eq!(decoded.avps.len(), 2);
        assert_eq!(decoded.session_id(), Some("test-session"));
    }

    #[test]
    fn test_answer_from_request() {
        let request = DiameterMessage::new_request(318, 16777251);
        let answer = DiameterMessage::new_answer(&request);

        assert!(request.header.is_request());
        assert!(answer.header.is_answer());
        assert_eq!(answer.header.command_code, request.header.command_code);
        assert_eq!(answer.header.application_id, request.header.application_id);
    }
}
