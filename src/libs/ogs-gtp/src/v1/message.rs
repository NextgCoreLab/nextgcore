//! GTPv1 Messages
//!
//! Message structures and encoding/decoding for GTPv1 protocol.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::error::{GtpError, GtpResult};
use super::header::{Gtp1Header, Gtp1cMessageType, Gtp1uMessageType};
use super::ie::Gtp1Ie;

/// GTPv1 Message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtp1Message {
    /// Message header
    pub header: Gtp1Header,
    /// Information Elements
    pub ies: Vec<Gtp1Ie>,
    /// Payload (for G-PDU)
    pub payload: Option<Bytes>,
}

impl Gtp1Message {
    /// Create a new GTPv1 message
    pub fn new(header: Gtp1Header) -> Self {
        Self {
            header,
            ies: Vec::new(),
            payload: None,
        }
    }

    /// Create an Echo Request message
    pub fn echo_request(teid: u32, sequence_number: u16) -> Self {
        let mut header = Gtp1Header::new(Gtp1cMessageType::EchoRequest as u8, teid);
        header.s = true;
        header.sequence_number = Some(sequence_number);
        Self::new(header)
    }

    /// Create an Echo Response message
    pub fn echo_response(teid: u32, sequence_number: u16, recovery: u8) -> Self {
        let mut header = Gtp1Header::new(Gtp1cMessageType::EchoResponse as u8, teid);
        header.s = true;
        header.sequence_number = Some(sequence_number);
        
        let mut msg = Self::new(header);
        
        // Add Recovery IE
        let mut ie_buf = BytesMut::new();
        ie_buf.put_u8(recovery);
        msg.ies.push(Gtp1Ie::new_tv(14, &ie_buf)); // Recovery IE type = 14
        
        msg
    }

    /// Create a G-PDU message (user plane data)
    pub fn gpdu(teid: u32, payload: Bytes) -> Self {
        let header = Gtp1Header::new_gpdu(teid);
        Self {
            header,
            ies: Vec::new(),
            payload: Some(payload),
        }
    }

    /// Create an Error Indication message
    pub fn error_indication(teid: u32, peer_teid: u32, peer_addr: &[u8]) -> Self {
        let header = Gtp1Header::new(Gtp1uMessageType::ErrorIndication as u8, teid);
        let mut msg = Self::new(header);
        
        // Add TEID Data I IE
        let mut teid_buf = BytesMut::new();
        teid_buf.put_u32(peer_teid);
        msg.ies.push(Gtp1Ie::new_tv(16, &teid_buf)); // TEID Data I type = 16
        
        // Add GSN Address IE
        msg.ies.push(Gtp1Ie::new_tlv(133, peer_addr)); // GSN Address type = 133
        
        msg
    }

    /// Create an End Marker message
    pub fn end_marker(teid: u32) -> Self {
        let header = Gtp1Header::new(Gtp1uMessageType::EndMarker as u8, teid);
        Self::new(header)
    }

    /// Add an IE to the message
    pub fn add_ie(&mut self, ie: Gtp1Ie) {
        self.ies.push(ie);
    }

    /// Get an IE by type
    pub fn get_ie(&self, ie_type: u8) -> Option<&Gtp1Ie> {
        self.ies.iter().find(|ie| ie.ie_type == ie_type)
    }

    /// Get all IEs of a specific type
    pub fn get_ies(&self, ie_type: u8) -> Vec<&Gtp1Ie> {
        self.ies.iter().filter(|ie| ie.ie_type == ie_type).collect()
    }

    /// Calculate message length (excluding header)
    fn calculate_length(&self) -> u16 {
        let mut length = 0u16;
        
        // Add IE lengths
        for ie in &self.ies {
            length += ie.encoded_len() as u16;
        }
        
        // Add payload length
        if let Some(ref payload) = self.payload {
            length += payload.len() as u16;
        }
        
        length
    }

    /// Encode message to bytes
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        
        // Calculate and set length
        let mut header = self.header.clone();
        header.length = self.calculate_length();
        
        // If we have optional fields, add 4 bytes to length
        if header.has_optional_fields() {
            header.length += 4;
        }
        
        // Encode header
        header.encode(&mut buf);
        
        // Encode IEs
        for ie in &self.ies {
            ie.encode(&mut buf);
        }
        
        // Encode payload
        if let Some(ref payload) = self.payload {
            buf.put_slice(payload);
        }
        
        buf
    }

    /// Decode message from bytes
    pub fn decode(buf: &mut Bytes) -> GtpResult<Self> {
        // Decode header
        let header = Gtp1Header::decode(buf)?;
        
        let mut msg = Self::new(header.clone());
        
        // Calculate remaining payload length
        let header_extra = if header.has_optional_fields() { 4 } else { 0 };
        let payload_len = header.length as usize - header_extra;
        
        if buf.remaining() < payload_len {
            return Err(GtpError::BufferTooShort {
                needed: payload_len,
                available: buf.remaining(),
            });
        }
        
        // For G-PDU, the rest is payload
        if header.message_type == Gtp1uMessageType::GPdu as u8 {
            msg.payload = Some(buf.copy_to_bytes(payload_len));
            return Ok(msg);
        }
        
        // For other messages, decode IEs
        let mut remaining = payload_len;
        while remaining > 0 && buf.remaining() > 0 {
            let start_pos = buf.remaining();
            let ie = Gtp1Ie::decode(buf)?;
            let consumed = start_pos - buf.remaining();
            remaining = remaining.saturating_sub(consumed);
            msg.ies.push(ie);
        }
        
        Ok(msg)
    }
}

/// GTPv1-U Echo Request
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoRequest {
    pub sequence_number: u16,
}

impl EchoRequest {
    pub fn new(sequence_number: u16) -> Self {
        Self { sequence_number }
    }

    pub fn encode(&self, teid: u32) -> BytesMut {
        Gtp1Message::echo_request(teid, self.sequence_number).encode()
    }

    pub fn decode(msg: &Gtp1Message) -> GtpResult<Self> {
        Ok(Self {
            sequence_number: msg.header.sequence_number.unwrap_or(0),
        })
    }
}

/// GTPv1-U Echo Response
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoResponse {
    pub sequence_number: u16,
    pub recovery: u8,
}

impl EchoResponse {
    pub fn new(sequence_number: u16, recovery: u8) -> Self {
        Self {
            sequence_number,
            recovery,
        }
    }

    pub fn encode(&self, teid: u32) -> BytesMut {
        Gtp1Message::echo_response(teid, self.sequence_number, self.recovery).encode()
    }

    pub fn decode(msg: &Gtp1Message) -> GtpResult<Self> {
        let recovery = msg.get_ie(14) // Recovery IE type
            .map(|ie| ie.value.first().copied().unwrap_or(0))
            .unwrap_or(0);
        
        Ok(Self {
            sequence_number: msg.header.sequence_number.unwrap_or(0),
            recovery,
        })
    }
}

/// GTPv1-U Error Indication
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorIndication {
    pub teid: u32,
    pub gsn_address: Vec<u8>,
}

impl ErrorIndication {
    pub fn new(teid: u32, gsn_address: Vec<u8>) -> Self {
        Self { teid, gsn_address }
    }

    pub fn encode(&self, header_teid: u32) -> BytesMut {
        Gtp1Message::error_indication(header_teid, self.teid, &self.gsn_address).encode()
    }

    pub fn decode(msg: &Gtp1Message) -> GtpResult<Self> {
        let teid = msg.get_ie(16) // TEID Data I
            .map(|ie| {
                if ie.value.len() >= 4 {
                    u32::from_be_bytes([ie.value[0], ie.value[1], ie.value[2], ie.value[3]])
                } else {
                    0
                }
            })
            .unwrap_or(0);
        
        let gsn_address = msg.get_ie(133) // GSN Address
            .map(|ie| ie.value.to_vec())
            .unwrap_or_default();
        
        Ok(Self { teid, gsn_address })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_echo_request_encode_decode() {
        let msg = Gtp1Message::echo_request(0x12345678, 0x1234);
        let encoded = msg.encode();
        
        let mut bytes = encoded.freeze();
        let decoded = Gtp1Message::decode(&mut bytes).unwrap();
        
        assert_eq!(decoded.header.message_type, Gtp1cMessageType::EchoRequest as u8);
        assert_eq!(decoded.header.teid, 0x12345678);
        assert_eq!(decoded.header.sequence_number, Some(0x1234));
    }

    #[test]
    fn test_echo_response_encode_decode() {
        let msg = Gtp1Message::echo_response(0x12345678, 0x1234, 42);
        let encoded = msg.encode();
        
        let mut bytes = encoded.freeze();
        let decoded = Gtp1Message::decode(&mut bytes).unwrap();
        
        assert_eq!(decoded.header.message_type, Gtp1cMessageType::EchoResponse as u8);
        assert_eq!(decoded.header.teid, 0x12345678);
        
        let recovery_ie = decoded.get_ie(14).unwrap();
        assert_eq!(recovery_ie.value[0], 42);
    }

    #[test]
    fn test_gpdu_encode_decode() {
        let payload = Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let msg = Gtp1Message::gpdu(0xABCDEF01, payload.clone());
        let encoded = msg.encode();
        
        let mut bytes = encoded.freeze();
        let decoded = Gtp1Message::decode(&mut bytes).unwrap();
        
        assert_eq!(decoded.header.message_type, Gtp1uMessageType::GPdu as u8);
        assert_eq!(decoded.header.teid, 0xABCDEF01);
        assert_eq!(decoded.payload, Some(payload));
    }

    #[test]
    fn test_error_indication() {
        let msg = Gtp1Message::error_indication(0, 0x12345678, &[192, 168, 1, 1]);
        let encoded = msg.encode();
        
        let mut bytes = encoded.freeze();
        let decoded = Gtp1Message::decode(&mut bytes).unwrap();
        
        assert_eq!(decoded.header.message_type, Gtp1uMessageType::ErrorIndication as u8);
        
        let err_ind = ErrorIndication::decode(&decoded).unwrap();
        assert_eq!(err_ind.teid, 0x12345678);
        assert_eq!(err_ind.gsn_address, vec![192, 168, 1, 1]);
    }

    #[test]
    fn test_end_marker() {
        let msg = Gtp1Message::end_marker(0x12345678);
        let encoded = msg.encode();
        
        let mut bytes = encoded.freeze();
        let decoded = Gtp1Message::decode(&mut bytes).unwrap();
        
        assert_eq!(decoded.header.message_type, Gtp1uMessageType::EndMarker as u8);
        assert_eq!(decoded.header.teid, 0x12345678);
    }
}
