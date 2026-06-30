//! GTPv1 Messages
//!
//! Message structures and encoding/decoding for GTPv1 protocol.

use super::header::{Gtp1Header, Gtp1cMessageType, Gtp1uMessageType};
use super::ie::{Gtp1Ie, Gtp1IeTypeTlv};
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

    /// Create an Echo Request message.
    ///
    /// Per TS 29.281 Section 5.1 the header Tunnel Endpoint Identifier of an
    /// Echo Request shall be set to all zeroes, so the `_teid` argument is
    /// retained for source compatibility but ignored — the header TEID is
    /// always 0.
    pub fn echo_request(_teid: u32, sequence_number: u16) -> Self {
        // TS 29.281 Section 5.1: Echo Request header TEID shall be all zeroes.
        let mut header = Gtp1Header::new(Gtp1cMessageType::EchoRequest as u8, 0);
        header.s = true;
        header.sequence_number = Some(sequence_number);
        Self::new(header)
    }

    /// Create an Echo Response message.
    ///
    /// Per TS 29.281 Section 5.1 the header Tunnel Endpoint Identifier of an
    /// Echo Response shall be set to all zeroes; per Section 7.2.2 / 8.2 the
    /// Recovery information element Restart Counter is not used in GTP-U and
    /// shall be set to 0 by the sender (it exists only for backwards
    /// compatibility). Both the `_teid` and `_recovery` arguments are retained
    /// for source compatibility but ignored — the header TEID and the Recovery
    /// value are always 0.
    pub fn echo_response(_teid: u32, sequence_number: u16, _recovery: u8) -> Self {
        // TS 29.281 Section 5.1: Echo Response header TEID shall be all zeroes.
        let mut header = Gtp1Header::new(Gtp1cMessageType::EchoResponse as u8, 0);
        header.s = true;
        header.sequence_number = Some(sequence_number);

        let mut msg = Self::new(header);

        // Add Recovery IE. TS 29.281 Section 7.2.2 / 8.2: the GTP-U Restart
        // Counter is unused and shall be set to 0 by the sender.
        let mut ie_buf = BytesMut::new();
        ie_buf.put_u8(0);
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
    /// Indication and the header Tunnel Endpoint Identifier shall be set to all
    /// zeros; the offending TEID travels in the Tunnel Endpoint Identifier
    /// Data I IE (Section 7.3.1). The `_teid` argument is retained for source
    /// compatibility but ignored — the header TEID is always 0.
    pub fn error_indication(_teid: u32, peer_teid: u32, peer_addr: &[u8]) -> Self {
        // TS 29.281 Section 5.1: Error Indication header TEID shall be all zeros.
        let mut header = Gtp1Header::new(Gtp1uMessageType::ErrorIndication as u8, 0);
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

    /// Create an Error Indication carrying the optional UDP Port (0x40)
    /// extension header (TS 29.281 Section 7.3.1).
    ///
    /// The UDP Port extension header conveys the UDP source port of the G-PDU
    /// that triggered the Error Indication so the peer can correlate it and
    /// mitigate Denial-of-Service risks. The header TEID stays 0 and the
    /// offending TEID/peer address travel in the mandatory IEs as usual.
    pub fn error_indication_with_udp_port(
        peer_teid: u32,
        peer_addr: &[u8],
        udp_src_port: u16,
    ) -> Self {
        let mut msg = Self::error_indication(0, peer_teid, peer_addr);
        msg.add_extension_header(Gtp1ExtHeader::new(
            ExtensionHeaderType::UdpPort as u8,
            &udp_src_port.to_be_bytes(),
        ));
        msg
    }

    /// Create an End Marker message
    pub fn end_marker(teid: u32) -> Self {
        let header = Gtp1Header::new(Gtp1uMessageType::EndMarker as u8, teid);
        Self::new(header)
    }

    /// Create a 5GS End Marker carrying a DL PDU Session Container (0x85)
    /// extension header with the given QFI (TS 29.281 Section 7.3.2.3).
    ///
    /// End markers sent over 5GS data forwarding tunnels shall include the PDU
    /// Session Container with the QoS Flow Identifier of one of the mapped QoS
    /// flows. The no-QFI variant (for flows transferred to/from a Secondary RAN
    /// Node) remains [`Gtp1Message::end_marker`].
    pub fn end_marker_with_qfi(teid: u32, qfi: u8) -> Self {
        let mut msg = Self::end_marker(teid);
        msg.add_extension_header(Gtp1ExtHeader::pdu_session_container(
            &PduSessionContainer::dl(qfi),
        ));
        msg
    }

    /// Create a Supported Extension Headers Notification (message type 31,
    /// TS 29.281 Section 7.2.3).
    ///
    /// The header TEID shall be 0 (Section 5.1) and the S flag is set. The
    /// message carries one mandatory Extension Header Type List IE (type 141)
    /// listing the extension header types the sender supports.
    pub fn supported_ext_headers_notification(sequence_number: u16, ext_types: &[u8]) -> Self {
        let mut header = Gtp1Header::new(
            Gtp1uMessageType::SupportedExtensionHeadersNotification as u8,
            0,
        );
        header.s = true;
        header.sequence_number = Some(sequence_number);
        let mut msg = Self::new(header);
        msg.ies.push(Gtp1Ie::new_tlv(
            Gtp1IeTypeTlv::ExtensionHeaderTypeList as u8,
            ext_types,
        ));
        msg
    }

    /// Create a Tunnel Status message (message type 253, TS 29.281
    /// Section 7.3.3).
    ///
    /// The S flag is set and the header TEID identifies the tunnel/PFCP session
    /// (Section 8.7). The message carries one mandatory GTP-U Tunnel Status
    /// Information IE (type 230) conveying the SPOC flag.
    pub fn tunnel_status(teid: u32, spoc: bool) -> Self {
        let mut header = Gtp1Header::new(Gtp1uMessageType::TunnelStatus as u8, teid);
        header.s = true;
        header.sequence_number = Some(0);
        let mut msg = Self::new(header);
        let mut ie_buf = BytesMut::new();
        ie_buf.put_u8(spoc as u8);
        msg.ies.push(Gtp1Ie::new_tlv(
            Gtp1IeTypeTlv::GtpuTunnelStatusInformation as u8,
            &ie_buf,
        ));
        msg
    }

    /// List the extension header types present on this message that are unknown
    /// and require comprehension by the local role (TS 29.281 Section 5.2.1).
    ///
    /// Per Section 5.2.1, a receiver of a request or G-PDU carrying an unknown
    /// comprehension-required extension header must discard the message and
    /// reply with a Supported Extension Headers Notification. Callers should
    /// invoke this after [`Gtp1Message::decode`] and, when the result is
    /// non-empty, trigger that procedure. NOTE 1 is honored: a G-PDU carrying
    /// the PDCP PDU Number (0xC0) header is treated as comprehension-not-required.
    ///
    /// `is_endpoint` is true when the local node is the Endpoint Receiver.
    pub fn unknown_comprehension_required(&self, is_endpoint: bool) -> Vec<u8> {
        let is_gpdu = self.header.message_type == Gtp1uMessageType::GPdu as u8;
        self.extension_headers
            .iter()
            .filter(|ext| {
                // NOTE 1: G-PDU + PDCP PDU Number (0xC0) => not required
                if is_gpdu && ext.ext_type == ExtensionHeaderType::PdcpPduNumber as u8 {
                    return false;
                }
                ext.requires_comprehension(is_endpoint)
            })
            .map(|ext| ext.ext_type)
            .collect()
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

/// GTPv1-U Supported Extension Headers Notification (message type 31).
///
/// Wraps the mandatory Extension Header Type List IE (type 141) listing the
/// extension header types the sender supports (TS 29.281 Section 7.2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportedExtHeadersNotification {
    pub ext_types: Vec<u8>,
}

impl SupportedExtHeadersNotification {
    pub fn new(ext_types: Vec<u8>) -> Self {
        Self { ext_types }
    }

    pub fn encode(&self, sequence_number: u16) -> BytesMut {
        Gtp1Message::supported_ext_headers_notification(sequence_number, &self.ext_types).encode()
    }

    pub fn decode(msg: &Gtp1Message) -> GtpResult<Self> {
        let ie = msg
            .get_ie(Gtp1IeTypeTlv::ExtensionHeaderTypeList as u8)
            .ok_or_else(|| GtpError::MissingMandatoryIe("Extension Header Type List".to_string()))?;
        Ok(Self {
            ext_types: ie.value.to_vec(),
        })
    }
}

/// GTPv1-U Tunnel Status (message type 253).
///
/// Wraps the mandatory GTP-U Tunnel Status Information IE (type 230) conveying
/// the SPOC (Start Pause Of Charging) flag (TS 29.281 Section 7.3.3 / 8.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelStatus {
    pub spoc: bool,
}

impl TunnelStatus {
    pub fn new(spoc: bool) -> Self {
        Self { spoc }
    }

    pub fn encode(&self, teid: u32) -> BytesMut {
        Gtp1Message::tunnel_status(teid, self.spoc).encode()
    }

    pub fn decode(msg: &Gtp1Message) -> GtpResult<Self> {
        let ie = msg
            .get_ie(Gtp1IeTypeTlv::GtpuTunnelStatusInformation as u8)
            .ok_or_else(|| {
                GtpError::MissingMandatoryIe("GTP-U Tunnel Status Information".to_string())
            })?;
        let octet4 = ie.value.first().copied().ok_or(GtpError::InvalidIeLength {
            expected: 1,
            actual: 0,
        })?;
        Ok(Self {
            spoc: octet4 & 0x01 != 0,
        })
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
        // gtp-01 re-baseline: TS 29.281 Section 5.1 forces the Echo Request
        // header TEID to all zeroes regardless of the value passed in.
        assert_eq!(decoded.header.teid, 0);
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
        // gtp-01 re-baseline: TS 29.281 Section 5.1 forces the Echo Response
        // header TEID to all zeroes regardless of the value passed in.
        assert_eq!(decoded.header.teid, 0);

        // gtp-05 re-baseline: TS 29.281 Section 7.2.2 / 8.2 force the GTP-U
        // Recovery Restart Counter to 0 regardless of the value passed in.
        let recovery_ie = decoded.get_ie(14).unwrap();
        assert_eq!(recovery_ie.value[0], 0);
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

    // gtp-04: 5GS End Marker carrying the PDU Session Container / QFI
    #[test]
    fn test_end_marker_with_qfi_round_trip() {
        let msg = Gtp1Message::end_marker_with_qfi(0x12345678, 5);
        let encoded = msg.encode();

        let mut bytes = encoded.freeze();
        let decoded = Gtp1Message::decode(&mut bytes).unwrap();

        assert_eq!(
            decoded.header.message_type,
            Gtp1uMessageType::EndMarker as u8
        );
        assert!(decoded.header.e);
        assert_eq!(decoded.extension_headers.len(), 1);
        let container = decoded.pdu_session_container().unwrap().unwrap();
        assert_eq!(container, PduSessionContainer::dl(5));
        assert_eq!(container.qfi(), 5);
    }

    #[test]
    fn test_end_marker_with_qfi_byte_vector() {
        let encoded = Gtp1Message::end_marker_with_qfi(0x00000001, 5).encode();
        let expected: &[u8] = &[
            0x34, // version 1, PT=1, E=1
            0xFE, // End Marker
            0x00, 0x08, // length = 4 (opt fields) + 4 (ext header)
            0x00, 0x00, 0x00, 0x01, // TEID
            0x00, 0x00, // sequence number (present, not meaningful)
            0x00, // N-PDU number (present, not meaningful)
            0x85, // next extension header: PDU Session Container
            0x01, // extension header length (1 * 4 octets)
            0x00, // PDU Type 0 (DL), no QMP/SNP
            0x05, // PPP=0, RQI=0, QFI=5
            0x00, // next extension header: none
        ];
        assert_eq!(&encoded[..], expected);
    }

    // gtp-03: Supported Extension Headers Notification (type 31) + IE 141
    #[test]
    fn test_supported_ext_headers_notification_round_trip() {
        let msg = Gtp1Message::supported_ext_headers_notification(0, &[0x85, 0x84]);
        let encoded = msg.encode();

        let mut bytes = encoded.freeze();
        let decoded = Gtp1Message::decode(&mut bytes).unwrap();

        assert_eq!(
            decoded.header.message_type,
            Gtp1uMessageType::SupportedExtensionHeadersNotification as u8
        );
        assert_eq!(decoded.header.teid, 0); // header TEID shall be 0
        assert!(decoded.header.s);

        let sehn = SupportedExtHeadersNotification::decode(&decoded).unwrap();
        assert_eq!(sehn.ext_types, vec![0x85, 0x84]);
    }

    #[test]
    fn test_supported_ext_headers_notification_byte_vector() {
        let encoded = Gtp1Message::supported_ext_headers_notification(0, &[0x85, 0x84]).encode();
        let expected: &[u8] = &[
            0x32, // version 1, PT=1, S=1
            0x1F, // Supported Extension Headers Notification (31)
            0x00, 0x09, // length = 4 (opt fields) + 5 (IE 141)
            0x00, 0x00, 0x00, 0x00, // header TEID = 0
            0x00, 0x00, // sequence number
            0x00, // N-PDU number
            0x00, // next extension header: none
            0x8D, // IE type 141 (Extension Header Type List)
            0x00, 0x02, // IE length = 2
            0x85, 0x84, // the two extension header types
        ];
        assert_eq!(&encoded[..], expected);
    }

    // gtp-07: Tunnel Status message (type 253) + IE 230
    #[test]
    fn test_tunnel_status_round_trip() {
        let msg = Gtp1Message::tunnel_status(0x12345678, true);
        let encoded = msg.encode();

        let mut bytes = encoded.freeze();
        let decoded = Gtp1Message::decode(&mut bytes).unwrap();

        assert_eq!(
            decoded.header.message_type,
            Gtp1uMessageType::TunnelStatus as u8
        );
        assert_eq!(decoded.header.teid, 0x12345678);
        assert!(decoded.header.s);
        assert!(TunnelStatus::decode(&decoded).unwrap().spoc);
    }

    #[test]
    fn test_tunnel_status_byte_vector() {
        let encoded = Gtp1Message::tunnel_status(0x00000001, true).encode();
        let expected: &[u8] = &[
            0x32, // version 1, PT=1, S=1
            0xFD, // Tunnel Status (253)
            0x00, 0x08, // length = 4 (opt fields) + 4 (IE 230)
            0x00, 0x00, 0x00, 0x01, // TEID
            0x00, 0x00, // sequence number
            0x00, // N-PDU number
            0x00, // next extension header: none
            0xE6, // IE type 230 (GTP-U Tunnel Status Information)
            0x00, 0x01, // IE length = 1
            0x01, // octet 4: SPOC = 1
        ];
        assert_eq!(&encoded[..], expected);
    }

    // gtp-10: Error Indication carrying the optional UDP Port (0x40) ext header
    #[test]
    fn test_error_indication_with_udp_port_round_trip() {
        let msg = Gtp1Message::error_indication_with_udp_port(0x12345678, &[192, 168, 1, 1], 2152);
        let encoded = msg.encode();

        let mut bytes = encoded.freeze();
        let decoded = Gtp1Message::decode(&mut bytes).unwrap();

        assert_eq!(
            decoded.header.message_type,
            Gtp1uMessageType::ErrorIndication as u8
        );
        assert_eq!(decoded.header.teid, 0); // header TEID shall be 0
        assert!(decoded.header.e);
        // Mandatory IEs still present
        let err_ind = ErrorIndication::decode(&decoded).unwrap();
        assert_eq!(err_ind.teid, 0x12345678);
        assert_eq!(err_ind.gsn_address, vec![192, 168, 1, 1]);
        // UDP Port extension header carries the source port
        let udp = decoded
            .get_extension_header(ExtensionHeaderType::UdpPort as u8)
            .unwrap();
        assert_eq!(
            u16::from_be_bytes([udp.content[0], udp.content[1]]),
            2152
        );
    }

    #[test]
    fn test_error_indication_with_udp_port_byte_vector() {
        let encoded =
            Gtp1Message::error_indication_with_udp_port(0x12345678, &[192, 168, 1, 1], 2152)
                .encode();
        let expected: &[u8] = &[
            0x36, // version 1, PT=1, E=1, S=1
            0x1A, // Error Indication (26)
            0x00, 0x14, // length = 4 (opt) + 4 (ext) + 5 (TEID IE) + 7 (GSN IE)
            0x00, 0x00, 0x00, 0x00, // header TEID = 0
            0x00, 0x00, // sequence number = 0
            0x00, // N-PDU number
            0x40, // next extension header: UDP Port
            0x01, // ext header length (1 * 4 octets)
            0x08, 0x68, // UDP source port 2152
            0x00, // next extension header: none
            0x10, // IE type 16 (TEID Data I)
            0x12, 0x34, 0x56, 0x78, // offending TEID
            0x85, // IE type 133 (GSN Address / GTP-U Peer Address)
            0x00, 0x04, // IE length = 4
            0xC0, 0xA8, 0x01, 0x01, // 192.168.1.1
        ];
        assert_eq!(&encoded[..], expected);
    }

    // gtp-02: unknown comprehension-required ext headers are surfaced on decode
    #[test]
    fn test_unknown_comprehension_required_on_gpdu() {
        // Unknown 0xC4 (bits 11) is required for the endpoint
        let mut msg = Gtp1Message::gpdu(0x11223344, Bytes::from_static(&[1, 2, 3, 4]));
        msg.add_extension_header(Gtp1ExtHeader::new(0xC4, &[0x00, 0x00]));
        let encoded = msg.encode();
        let mut bytes = encoded.freeze();
        let decoded = Gtp1Message::decode(&mut bytes).unwrap();
        assert_eq!(decoded.unknown_comprehension_required(true), vec![0xC4]);

        // Unknown 0x44 (bits 01) is comprehension-not-required -> empty
        let mut msg = Gtp1Message::gpdu(0x11223344, Bytes::from_static(&[1, 2, 3, 4]));
        msg.add_extension_header(Gtp1ExtHeader::new(0x44, &[0x00, 0x00]));
        let encoded = msg.encode();
        let mut bytes = encoded.freeze();
        let decoded = Gtp1Message::decode(&mut bytes).unwrap();
        assert!(decoded.unknown_comprehension_required(true).is_empty());
    }

    // gtp-02 NOTE 1 + gtp-08: known and NOTE-1 types are not flagged
    #[test]
    fn test_known_and_note1_ext_headers_not_flagged() {
        // gtp-08: NR RAN Container (0x84) is a known type -> not flagged
        let mut msg = Gtp1Message::gpdu(0x1, Bytes::from_static(&[1, 2, 3, 4]));
        msg.add_extension_header(Gtp1ExtHeader::new(0x84, &[0x00, 0x00]));
        let encoded = msg.encode();
        let mut bytes = encoded.freeze();
        let decoded = Gtp1Message::decode(&mut bytes).unwrap();
        assert!(decoded.unknown_comprehension_required(true).is_empty());

        // NOTE 1: PDCP PDU Number (0xC0) on a G-PDU is comprehension-not-required
        let mut msg = Gtp1Message::gpdu(0x1, Bytes::from_static(&[1, 2, 3, 4]));
        msg.add_extension_header(Gtp1ExtHeader::new(0xC0, &[0x00, 0x00]));
        let encoded = msg.encode();
        let mut bytes = encoded.freeze();
        let decoded = Gtp1Message::decode(&mut bytes).unwrap();
        assert!(decoded.unknown_comprehension_required(true).is_empty());
    }

    // gtp-01: the header TEID of Echo Request/Response and Error Indication is
    // forced to all zeroes even when the builder is handed a non-zero argument
    // (TS 29.281 Section 5.1).
    #[test]
    fn test_echo_and_error_indication_header_teid_zero() {
        // Echo Request: header TEID octets 4..8 are zero despite the argument.
        let encoded = Gtp1Message::echo_request(0xDEADBEEF, 0x1234).encode();
        assert_eq!(&encoded[4..8], &[0, 0, 0, 0]);

        // Echo Response: header TEID is zero despite the argument.
        let encoded = Gtp1Message::echo_response(0xDEADBEEF, 0x1234, 42).encode();
        assert_eq!(&encoded[4..8], &[0, 0, 0, 0]);

        // Error Indication: header TEID is zero, but the offending TEID still
        // travels in the Tunnel Endpoint Identifier Data I IE (type 16).
        let msg = Gtp1Message::error_indication(0xDEADBEEF, 0x12345678, &[192, 168, 1, 1]);
        let encoded = msg.encode();
        assert_eq!(&encoded[4..8], &[0, 0, 0, 0]);
        let mut bytes = encoded.freeze();
        let decoded = Gtp1Message::decode(&mut bytes).unwrap();
        assert_eq!(decoded.header.teid, 0);
        let err_ind = ErrorIndication::decode(&decoded).unwrap();
        assert_eq!(err_ind.teid, 0x12345678);
    }

    // gtp-01: exact wire image of an Echo Request — header TEID = 0.
    #[test]
    fn test_echo_request_header_teid_zero_byte_vector() {
        // Non-zero TEID argument must be ignored on the wire (Section 5.1).
        let encoded = Gtp1Message::echo_request(0x12345678, 0x1234).encode();
        let expected: &[u8] = &[
            0x32, // version 1, PT=1, S=1
            0x01, // Echo Request
            0x00, 0x04, // length = 4 (opt fields), no IEs
            0x00, 0x00, 0x00, 0x00, // header TEID = 0 (forced per Section 5.1)
            0x12, 0x34, // sequence number
            0x00, // N-PDU number
            0x00, // next extension header: none
        ];
        assert_eq!(&encoded[..], expected);
    }

    // gtp-01 + gtp-05: exact wire image of an Echo Response — header TEID = 0
    // and Recovery Restart Counter = 0.
    #[test]
    fn test_echo_response_header_teid_recovery_zero_byte_vector() {
        // Non-zero TEID and Recovery arguments must be ignored on the wire
        // (Section 5.1 + Section 7.2.2 / 8.2).
        let encoded = Gtp1Message::echo_response(0x12345678, 0x1234, 42).encode();
        let expected: &[u8] = &[
            0x32, // version 1, PT=1, S=1
            0x02, // Echo Response
            0x00, 0x06, // length = 4 (opt fields) + 2 (Recovery IE)
            0x00, 0x00, 0x00, 0x00, // header TEID = 0 (forced per Section 5.1)
            0x12, 0x34, // sequence number
            0x00, // N-PDU number
            0x00, // next extension header: none
            0x0E, // IE type 14 (Recovery)
            0x00, // Restart Counter = 0 (forced per Section 7.2.2 / 8.2)
        ];
        assert_eq!(&encoded[..], expected);
    }

    // gtp-01: exact wire image of an Error Indication — header TEID = 0 while
    // the offending TEID stays in the TEID Data I IE.
    #[test]
    fn test_error_indication_header_teid_zero_byte_vector() {
        // Non-zero header TEID argument must be ignored on the wire (Section 5.1).
        let encoded =
            Gtp1Message::error_indication(0x99999999, 0x12345678, &[192, 168, 1, 1]).encode();
        let expected: &[u8] = &[
            0x32, // version 1, PT=1, S=1
            0x1A, // Error Indication (26)
            0x00, 0x10, // length = 4 (opt) + 5 (TEID IE) + 7 (GSN IE)
            0x00, 0x00, 0x00, 0x00, // header TEID = 0 (forced per Section 5.1)
            0x00, 0x00, // sequence number = 0
            0x00, // N-PDU number
            0x00, // next extension header: none
            0x10, // IE type 16 (TEID Data I)
            0x12, 0x34, 0x56, 0x78, // offending TEID (unchanged)
            0x85, // IE type 133 (GSN Address / GTP-U Peer Address)
            0x00, 0x04, // IE length = 4
            0xC0, 0xA8, 0x01, 0x01, // 192.168.1.1
        ];
        assert_eq!(&encoded[..], expected);
    }
}
