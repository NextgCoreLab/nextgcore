//! GTPv1 Messages
//!
//! Message structures and encoding/decoding for GTPv1 protocol.

use super::header::{Gtp1Header, Gtp1cMessageType, Gtp1uMessageType};
use super::ie::Gtp1Ie;
use super::types::{ExtensionHeaderType, Gtp1ExtHeader, PduSessionContainer};
use crate::error::{GtpError, GtpResult};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// GTPv1 Message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtp1Message {
    /// Message header
    pub header: Gtp1Header,
    /// Extension headers (TS 29.281 Section 5.2), chained after the header
    pub extension_headers: Vec<Gtp1ExtHeader>,
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
            extension_headers: Vec::new(),
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
            extension_headers: Vec::new(),
            ies: Vec::new(),
            payload: Some(payload),
        }
    }

    /// Create a G-PDU with a PDU Session Container extension header
    /// (TS 38.415 frame in the 0x85 extension header)
    pub fn gpdu_with_pdu_session(
        teid: u32,
        container: &PduSessionContainer,
        payload: Bytes,
    ) -> Self {
        let mut msg = Self::gpdu(teid, payload);
        msg.extension_headers
            .push(Gtp1ExtHeader::pdu_session_container(container));
        msg
    }

    /// Create a DL G-PDU carrying DL PDU SESSION INFORMATION with the given QFI
    pub fn gpdu_dl(teid: u32, qfi: u8, payload: Bytes) -> Self {
        Self::gpdu_with_pdu_session(teid, &PduSessionContainer::dl(qfi), payload)
    }

    /// Create an UL G-PDU carrying UL PDU SESSION INFORMATION with the given QFI
    pub fn gpdu_ul(teid: u32, qfi: u8, payload: Bytes) -> Self {
        Self::gpdu_with_pdu_session(teid, &PduSessionContainer::ul(qfi), payload)
    }

    /// Create an Error Indication message.
    ///
    /// Per TS 29.281 Section 5.1 the S flag shall be set to 1 for Error
    /// Indication; per Section 7.3.1 the header TEID shall be 0 and the
    /// offending TEID travels in the Tunnel Endpoint Identifier Data I IE.
    pub fn error_indication(teid: u32, peer_teid: u32, peer_addr: &[u8]) -> Self {
        let mut header = Gtp1Header::new(Gtp1uMessageType::ErrorIndication as u8, teid);
        header.s = true;
        header.sequence_number = Some(0);
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

    /// Add an extension header to the chain
    pub fn add_extension_header(&mut self, ext: Gtp1ExtHeader) {
        self.extension_headers.push(ext);
    }

    /// Get an extension header by type
    pub fn get_extension_header(&self, ext_type: u8) -> Option<&Gtp1ExtHeader> {
        self.extension_headers
            .iter()
            .find(|ext| ext.ext_type == ext_type)
    }

    /// Get the PDU Session Container frame, if present (TS 38.415)
    pub fn pdu_session_container(&self) -> GtpResult<Option<PduSessionContainer>> {
        match self.get_extension_header(ExtensionHeaderType::PduSessionContainer as u8) {
            Some(ext) => Ok(Some(ext.as_pdu_session_container()?)),
            None => Ok(None),
        }
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

    /// Total encoded size of the extension header chain
    fn extension_headers_len(&self) -> usize {
        self.extension_headers
            .iter()
            .map(|ext| ext.encoded_len())
            .sum()
    }

    /// Encode message to bytes
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();

        // Calculate and set length
        let mut header = self.header.clone();
        if !self.extension_headers.is_empty() {
            header.e = true;
            header.next_extension_header_type = Some(self.extension_headers[0].ext_type);
        }
        header.length = self.calculate_length();

        // If we have optional fields, add 4 bytes plus the extension chain
        if header.has_optional_fields() {
            header.length += 4 + self.extension_headers_len() as u16;
        }

        // Encode header
        header.encode(&mut buf);

        // Encode extension header chain (each carries the next header's type)
        for (i, ext) in self.extension_headers.iter().enumerate() {
            let next_type = self
                .extension_headers
                .get(i + 1)
                .map(|next| next.ext_type)
                .unwrap_or(ExtensionHeaderType::NoMoreExtensionHeaders as u8);
            ext.encode(&mut buf, next_type);
        }

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
        let mut payload_len =
            (header.length as usize)
                .checked_sub(header_extra)
                .ok_or(GtpError::InvalidHeader(
                    "Length shorter than optional header fields".to_string(),
                ))?;

        // Decode extension header chain if the E flag is set
        if header.e {
            let mut next_type = header.next_extension_header_type.unwrap_or(0);
            while next_type != ExtensionHeaderType::NoMoreExtensionHeaders as u8 {
                let start_pos = buf.remaining();
                let (ext, next) = Gtp1ExtHeader::decode(next_type, buf)?;
                let consumed = start_pos - buf.remaining();
                payload_len = payload_len
                    .checked_sub(consumed)
                    .ok_or(GtpError::InvalidHeader(
                        "Extension headers exceed message length".to_string(),
                    ))?;
                msg.extension_headers.push(ext);
                next_type = next;
            }
        }

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
        let recovery = msg
            .get_ie(14) // Recovery IE type
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
        // Both IEs are mandatory in an Error Indication
        // (TS 29.281 Section 7.3.1)
        let teid_ie = msg.get_ie(16).ok_or_else(|| {
            GtpError::MissingMandatoryIe("Tunnel Endpoint Identifier Data I".to_string())
        })?;
        if teid_ie.value.len() < 4 {
            return Err(GtpError::InvalidIeLength {
                expected: 4,
                actual: teid_ie.value.len(),
            });
        }
        let teid = u32::from_be_bytes([
            teid_ie.value[0],
            teid_ie.value[1],
            teid_ie.value[2],
            teid_ie.value[3],
        ]);

        let gsn_address = msg
            .get_ie(133) // GSN Address
            .map(|ie| ie.value.to_vec())
            .ok_or_else(|| GtpError::MissingMandatoryIe("GTP-U Peer Address".to_string()))?;

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

        assert_eq!(
            decoded.header.message_type,
            Gtp1cMessageType::EchoRequest as u8
        );
        assert_eq!(decoded.header.teid, 0x12345678);
        assert_eq!(decoded.header.sequence_number, Some(0x1234));
    }

    #[test]
    fn test_echo_response_encode_decode() {
        let msg = Gtp1Message::echo_response(0x12345678, 0x1234, 42);
        let encoded = msg.encode();

        let mut bytes = encoded.freeze();
        let decoded = Gtp1Message::decode(&mut bytes).unwrap();

        assert_eq!(
            decoded.header.message_type,
            Gtp1cMessageType::EchoResponse as u8
        );
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

        assert_eq!(
            decoded.header.message_type,
            Gtp1uMessageType::ErrorIndication as u8
        );

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

        assert_eq!(
            decoded.header.message_type,
            Gtp1uMessageType::EndMarker as u8
        );
        assert_eq!(decoded.header.teid, 0x12345678);
    }

    #[test]
    fn test_gpdu_dl_qfi_round_trip() {
        let payload = Bytes::from_static(&[0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4]);
        let msg = Gtp1Message::gpdu_dl(0x12345678, 9, payload.clone());
        let encoded = msg.encode();

        let mut bytes = encoded.freeze();
        let decoded = Gtp1Message::decode(&mut bytes).unwrap();

        assert_eq!(decoded.header.message_type, Gtp1uMessageType::GPdu as u8);
        assert_eq!(decoded.header.teid, 0x12345678);
        assert!(decoded.header.e);
        assert_eq!(decoded.extension_headers.len(), 1);
        assert_eq!(decoded.payload, Some(payload));

        let container = decoded.pdu_session_container().unwrap().unwrap();
        assert_eq!(container, PduSessionContainer::dl(9));
        assert_eq!(container.qfi(), 9);
    }

    #[test]
    fn test_gpdu_ul_qfi_round_trip() {
        let payload = Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let msg = Gtp1Message::gpdu_ul(0xABCDEF01, 5, payload.clone());
        let encoded = msg.encode();

        let mut bytes = encoded.freeze();
        let decoded = Gtp1Message::decode(&mut bytes).unwrap();

        assert_eq!(decoded.payload, Some(payload));
        let container = decoded.pdu_session_container().unwrap().unwrap();
        assert_eq!(container, PduSessionContainer::ul(5));
    }

    #[test]
    fn test_gpdu_dl_qfi_known_vector() {
        // Spec-derived wire image (TS 29.281 Section 5.2.1 + TS 38.415
        // Section 5.5.2.1); no public capture is bundled with the repo, so
        // the bytes are hand-derived from the spec figures and match what
        // Wireshark dissects for Open5GS/UERANSIM DL G-PDUs.
        let payload = Bytes::from_static(&[0xCA, 0xFE]);
        let msg = Gtp1Message::gpdu_dl(0x00000001, 9, payload);
        let encoded = msg.encode();

        let expected: &[u8] = &[
            0x34, // version 1, PT=1, E=1
            0xFF, // G-PDU
            0x00, 0x0A, // length = 4 (opt fields) + 4 (ext header) + 2 (payload)
            0x00, 0x00, 0x00, 0x01, // TEID
            0x00, 0x00, // sequence number (present, not meaningful)
            0x00, // N-PDU number (present, not meaningful)
            0x85, // next extension header: PDU Session Container
            0x01, // extension header length (1 * 4 octets)
            0x00, // PDU Type 0 (DL), no QMP/SNP
            0x09, // PPP=0, RQI=0, QFI=9
            0x00, // next extension header: none
            0xCA, 0xFE, // payload
        ];
        assert_eq!(&encoded[..], expected);
    }

    #[test]
    fn test_gpdu_extension_header_chain_round_trip() {
        // UDP Port (0x40) chained before the PDU Session Container (0x85)
        let payload = Bytes::from_static(&[1, 2, 3, 4]);
        let mut msg = Gtp1Message::gpdu(0x11223344, payload.clone());
        msg.add_extension_header(Gtp1ExtHeader::new(
            ExtensionHeaderType::UdpPort as u8,
            &2152u16.to_be_bytes(),
        ));
        msg.add_extension_header(Gtp1ExtHeader::pdu_session_container(
            &PduSessionContainer::dl(1),
        ));

        let encoded = msg.encode();
        let mut bytes = encoded.freeze();
        let decoded = Gtp1Message::decode(&mut bytes).unwrap();

        assert_eq!(decoded.extension_headers.len(), 2);
        assert_eq!(
            decoded.extension_headers[0].ext_type,
            ExtensionHeaderType::UdpPort as u8
        );
        assert_eq!(
            decoded.extension_headers[1].ext_type,
            ExtensionHeaderType::PduSessionContainer as u8
        );
        assert_eq!(decoded.payload, Some(payload));
        assert_eq!(
            decoded.pdu_session_container().unwrap(),
            Some(PduSessionContainer::dl(1))
        );
    }

    #[test]
    fn test_gpdu_truncated_extension_header_rejected() {
        let msg = Gtp1Message::gpdu_dl(0x12345678, 9, Bytes::from_static(&[1, 2]));
        let encoded = msg.encode();

        // Cut the message inside the extension header
        let mut bytes = encoded.freeze().slice(0..13);
        assert!(Gtp1Message::decode(&mut bytes).is_err());
    }

    #[test]
    fn test_gpdu_header_length_underflow_rejected() {
        // E flag set but header length (0) cannot cover the optional fields
        let bytes: &[u8] = &[
            0x34, 0xFF, 0x00, 0x00, // length = 0 with optional fields present
            0x00, 0x00, 0x00, 0x01, // TEID
            0x00, 0x00, 0x00, 0x85, // seq/N-PDU/next ext
        ];
        let mut buf = Bytes::copy_from_slice(bytes);
        assert!(Gtp1Message::decode(&mut buf).is_err());
    }
}
