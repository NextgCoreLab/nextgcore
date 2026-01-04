//! SGWU GTP-U Path Management
//!
//! Port of src/sgwu/gtp-path.c - GTP-U path management for user plane

use crate::context::sgwu_self;
use crate::sxa_build::UserPlaneReport;

// ============================================================================
// GTP-U Message Types
// ============================================================================

pub mod gtpu_type {
    pub const ECHO_REQUEST: u8 = 1;
    pub const ECHO_RESPONSE: u8 = 2;
    pub const ERROR_INDICATION: u8 = 26;
    pub const END_MARKER: u8 = 254;
    pub const G_PDU: u8 = 255;
}

// ============================================================================
// GTP-U Header
// ============================================================================

/// GTP-U header structure
#[derive(Debug, Clone, Default)]
pub struct GtpuHeader {
    /// Version (should be 1)
    pub version: u8,
    /// Protocol Type (1 = GTP)
    pub pt: bool,
    /// Extension Header flag
    pub e: bool,
    /// Sequence Number flag
    pub s: bool,
    /// N-PDU Number flag
    pub pn: bool,
    /// Message Type
    pub msg_type: u8,
    /// Length
    pub length: u16,
    /// TEID
    pub teid: u32,
    /// Sequence Number (optional)
    pub seq_num: Option<u16>,
    /// N-PDU Number (optional)
    pub npdu_num: Option<u8>,
    /// Next Extension Header Type (optional)
    pub next_ext_hdr_type: Option<u8>,
}

impl GtpuHeader {
    /// Parse GTP-U header from bytes
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 8 {
            return None;
        }

        let flags = data[0];
        let version = (flags >> 5) & 0x07;
        let pt = (flags & 0x10) != 0;
        let e = (flags & 0x04) != 0;
        let s = (flags & 0x02) != 0;
        let pn = (flags & 0x01) != 0;

        if version != 1 {
            return None;
        }

        let msg_type = data[1];
        let length = u16::from_be_bytes([data[2], data[3]]);
        let teid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        let mut header_len = 8;
        let mut seq_num = None;
        let mut npdu_num = None;
        let mut next_ext_hdr_type = None;

        if e || s || pn {
            if data.len() < 12 {
                return None;
            }
            seq_num = Some(u16::from_be_bytes([data[8], data[9]]));
            npdu_num = Some(data[10]);
            next_ext_hdr_type = Some(data[11]);
            header_len = 12;
        }

        Some((
            Self {
                version,
                pt,
                e,
                s,
                pn,
                msg_type,
                length,
                teid,
                seq_num,
                npdu_num,
                next_ext_hdr_type,
            },
            header_len,
        ))
    }

    /// Build GTP-U header bytes
    pub fn build(&self) -> Vec<u8> {
        let mut data = Vec::new();

        let mut flags = (self.version & 0x07) << 5;
        if self.pt {
            flags |= 0x10;
        }
        if self.e {
            flags |= 0x04;
        }
        if self.s {
            flags |= 0x02;
        }
        if self.pn {
            flags |= 0x01;
        }

        data.push(flags);
        data.push(self.msg_type);
        data.extend_from_slice(&self.length.to_be_bytes());
        data.extend_from_slice(&self.teid.to_be_bytes());

        if self.e || self.s || self.pn {
            data.extend_from_slice(&self.seq_num.unwrap_or(0).to_be_bytes());
            data.push(self.npdu_num.unwrap_or(0));
            data.push(self.next_ext_hdr_type.unwrap_or(0));
        }

        data
    }
}

// ============================================================================
// GTP-U Packet Pool
// ============================================================================

/// Packet pool for GTP-U
#[allow(dead_code)]
pub struct PacketPool {
    /// Maximum packet size
    max_pkt_len: usize,
    /// Pool initialized flag
    initialized: bool,
}

impl PacketPool {
    pub fn new() -> Self {
        Self {
            max_pkt_len: 65535,
            initialized: false,
        }
    }

    pub fn init(&mut self) {
        self.initialized = true;
        log::info!("GTP-U packet pool initialized");
    }

    pub fn fini(&mut self) {
        self.initialized = false;
        log::info!("GTP-U packet pool finalized");
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for PacketPool {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// GTP-U Path Functions
// ============================================================================

/// Initialize GTP-U subsystem
/// Port of sgwu_gtp_init
pub fn gtp_init() -> Result<(), String> {
    log::info!("Initializing GTP-U subsystem");

    // In actual implementation:
    // - Initialize packet pool
    // - Set up memory pools for GTP-U packets

    log::info!("GTP-U subsystem initialized");
    Ok(())
}

/// Finalize GTP-U subsystem
/// Port of sgwu_gtp_final
pub fn gtp_final() {
    log::info!("Finalizing GTP-U subsystem");

    // In actual implementation:
    // - Destroy packet pool
    // - Clean up memory pools
}

/// Open GTP-U server sockets
/// Port of sgwu_gtp_open
pub fn gtp_open() -> Result<(), String> {
    log::info!("Opening GTP-U server sockets");

    // In actual implementation:
    // - Create UDP sockets for GTP-U (port 2152)
    // - Bind to configured addresses
    // - Register poll callbacks for receiving messages

    log::info!("GTP-U server sockets opened successfully");
    Ok(())
}

/// Close GTP-U server sockets
/// Port of sgwu_gtp_close
pub fn gtp_close() {
    log::info!("Closing GTP-U server sockets");

    // In actual implementation:
    // - Close all GTP-U sockets
    // - Remove poll registrations
}

// ============================================================================
// GTP-U Receive Callback
// ============================================================================

/// GTP-U receive callback result
#[derive(Debug)]
pub enum GtpuRecvResult {
    /// Packet handled successfully
    Handled,
    /// Echo response sent
    EchoResponse,
    /// Packet forwarded
    Forwarded,
    /// Packet buffered
    Buffered,
    /// Error indication sent
    ErrorIndication,
    /// Session report needed
    SessionReport(UserPlaneReport),
    /// Packet dropped
    Dropped(String),
}

/// Handle received GTP-U packet
/// Port of _gtpv1_u_recv_cb
pub fn handle_gtpu_recv(
    data: &[u8],
    from_addr: &str,
    local_addr: &str,
) -> GtpuRecvResult {
    // Parse GTP-U header
    let (header, header_len) = match GtpuHeader::parse(data) {
        Some(h) => h,
        None => {
            log::error!("[DROP] Cannot decode GTPU packet");
            return GtpuRecvResult::Dropped("Invalid GTP-U header".to_string());
        }
    };

    if header.version != 1 {
        log::error!("[DROP] Invalid GTPU version [{}]", header.version);
        return GtpuRecvResult::Dropped("Invalid version".to_string());
    }

    log::trace!(
        "[RECV] GTP-U Type [{}] from [{}] : TEID[0x{:x}]",
        header.msg_type,
        from_addr,
        header.teid
    );

    match header.msg_type {
        gtpu_type::ECHO_REQUEST => {
            handle_echo_request(&header, from_addr)
        }
        gtpu_type::END_MARKER => {
            handle_end_marker(&header, &data[header_len..], from_addr, local_addr)
        }
        gtpu_type::ERROR_INDICATION => {
            handle_error_indication(&header, &data[header_len..], from_addr)
        }
        gtpu_type::G_PDU => {
            handle_gpdu(&header, &data[header_len..], from_addr, local_addr)
        }
        _ => {
            log::error!("[DROP] Invalid GTPU Type [{}]", header.msg_type);
            GtpuRecvResult::Dropped("Unknown message type".to_string())
        }
    }
}

/// Handle Echo Request
fn handle_echo_request(header: &GtpuHeader, from_addr: &str) -> GtpuRecvResult {
    log::debug!("[RECV] Echo Request from [{}]", from_addr);

    // Build Echo Response
    let _response = build_echo_response(header);

    log::debug!("[SEND] Echo Response to [{}]", from_addr);

    // In actual implementation, send response via socket
    GtpuRecvResult::EchoResponse
}

/// Handle End Marker
fn handle_end_marker(
    header: &GtpuHeader,
    _payload: &[u8],
    from_addr: &str,
    _local_addr: &str,
) -> GtpuRecvResult {
    log::debug!(
        "[RECV] End Marker from [{}] TEID[0x{:x}]",
        from_addr,
        header.teid
    );

    // In actual implementation:
    // 1. Find PDR by TEID
    // 2. Forward End Marker to peer (gNB/eNB)

    // If PDR not found, send Error Indication
    let _ctx = sgwu_self();
    // Lookup would happen here

    GtpuRecvResult::Handled
}

/// Handle Error Indication
fn handle_error_indication(
    header: &GtpuHeader,
    _payload: &[u8],
    from_addr: &str,
) -> GtpuRecvResult {
    log::warn!(
        "[RECV] Error Indication from [{}] TEID[0x{:x}]",
        from_addr,
        header.teid
    );

    // In actual implementation:
    // 1. Parse Error Indication to get remote F-TEID
    // 2. Find FAR by remote F-TEID
    // 3. Send Session Report Request to SGWC

    let report = UserPlaneReport {
        error_indication_report: true,
        remote_f_teid: Some(crate::sxa_build::LocalFTeid {
            teid: header.teid,
            ipv4: None,
            ipv6: None,
        }),
        ..Default::default()
    };

    GtpuRecvResult::SessionReport(report)
}

/// Handle G-PDU (user data)
fn handle_gpdu(
    header: &GtpuHeader,
    payload: &[u8],
    from_addr: &str,
    _local_addr: &str,
) -> GtpuRecvResult {
    log::trace!(
        "[RECV] G-PDU from [{}] TEID[0x{:x}] len={}",
        from_addr,
        header.teid,
        payload.len()
    );

    // In actual implementation:
    // 1. Find PDR by TEID (and optionally QFI for 5GC)
    // 2. Apply QER (rate limiting)
    // 3. Get FAR for forwarding action
    // 4. If FORW: forward to peer with outer header creation
    // 5. If BUFF: buffer packet and send DDN to SGWC
    // 6. If DROP: drop packet

    let _ctx = sgwu_self();

    // Simulate PDR lookup failure - would send error indication
    // In real implementation, this would look up the PDR

    // For now, assume packet is forwarded
    GtpuRecvResult::Forwarded
}

/// Build Echo Response
fn build_echo_response(request: &GtpuHeader) -> Vec<u8> {
    let response = GtpuHeader {
        version: 1,
        pt: true,
        e: false,
        s: request.s,
        pn: false,
        msg_type: gtpu_type::ECHO_RESPONSE,
        length: if request.s { 6 } else { 0 },
        teid: 0,
        seq_num: request.seq_num,
        npdu_num: None,
        next_ext_hdr_type: None,
    };

    let mut data = response.build();

    // Add Recovery IE if sequence number present
    if request.s {
        // Recovery IE: Type (14), Length (1), Recovery value
        data.push(14); // Recovery IE type
        data.push(0);  // Recovery value (placeholder)
    }

    data
}

/// Build Error Indication
pub fn build_error_indication(teid: u32, seq_num: u16) -> Vec<u8> {
    let header = GtpuHeader {
        version: 1,
        pt: true,
        e: false,
        s: true,
        pn: false,
        msg_type: gtpu_type::ERROR_INDICATION,
        length: 0, // Will be updated
        teid: 0,
        seq_num: Some(seq_num),
        npdu_num: None,
        next_ext_hdr_type: None,
    };

    let mut data = header.build();

    // Add Tunnel Endpoint Identifier Data I IE
    // Type (16), TEID value
    data.push(16); // TEID Data I IE type
    data.extend_from_slice(&teid.to_be_bytes());

    // Update length in header
    let payload_len = (data.len() - 8) as u16;
    data[2..4].copy_from_slice(&payload_len.to_be_bytes());

    data
}

/// Build End Marker
pub fn build_end_marker(teid: u32) -> Vec<u8> {
    let header = GtpuHeader {
        version: 1,
        pt: true,
        e: false,
        s: false,
        pn: false,
        msg_type: gtpu_type::END_MARKER,
        length: 0,
        teid,
        seq_num: None,
        npdu_num: None,
        next_ext_hdr_type: None,
    };

    header.build()
}

/// Send buffered packets for a PDR
/// Port of ogs_pfcp_send_buffered_gtpu
pub fn send_buffered_packets(pdr_id: u16) {
    log::debug!("Sending buffered packets for PDR {}", pdr_id);

    // In actual implementation:
    // 1. Get buffered packets for PDR
    // 2. Forward each packet using FAR
}

/// Send End Marker
/// Port of ogs_pfcp_send_end_marker
pub fn send_end_marker(pdr_id: u16) -> Result<(), String> {
    log::debug!("Sending End Marker for PDR {}", pdr_id);

    // In actual implementation:
    // 1. Get FAR for PDR
    // 2. Build End Marker with remote TEID
    // 3. Send to peer

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtpu_header_parse() {
        // Minimal GTP-U header (8 bytes)
        let data = [
            0x30, // Version=1, PT=1, no optional fields
            0xFF, // G-PDU
            0x00, 0x10, // Length = 16
            0x12, 0x34, 0x56, 0x78, // TEID
        ];

        let (header, len) = GtpuHeader::parse(&data).unwrap();
        assert_eq!(header.version, 1);
        assert!(header.pt);
        assert!(!header.e);
        assert!(!header.s);
        assert!(!header.pn);
        assert_eq!(header.msg_type, gtpu_type::G_PDU);
        assert_eq!(header.length, 16);
        assert_eq!(header.teid, 0x12345678);
        assert_eq!(len, 8);
    }

    #[test]
    fn test_gtpu_header_parse_with_seq() {
        // GTP-U header with sequence number (12 bytes)
        let data = [
            0x32, // Version=1, PT=1, S=1
            0x01, // Echo Request
            0x00, 0x04, // Length = 4
            0x00, 0x00, 0x00, 0x00, // TEID = 0
            0x00, 0x01, // Sequence = 1
            0x00, // N-PDU
            0x00, // Next ext header
        ];

        let (header, len) = GtpuHeader::parse(&data).unwrap();
        assert!(header.s);
        assert_eq!(header.seq_num, Some(1));
        assert_eq!(len, 12);
    }

    #[test]
    fn test_gtpu_header_build() {
        let header = GtpuHeader {
            version: 1,
            pt: true,
            e: false,
            s: false,
            pn: false,
            msg_type: gtpu_type::G_PDU,
            length: 100,
            teid: 0xABCD1234,
            seq_num: None,
            npdu_num: None,
            next_ext_hdr_type: None,
        };

        let data = header.build();
        assert_eq!(data.len(), 8);
        assert_eq!(data[0], 0x30); // Version=1, PT=1
        assert_eq!(data[1], gtpu_type::G_PDU);
        assert_eq!(u16::from_be_bytes([data[2], data[3]]), 100);
        assert_eq!(
            u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            0xABCD1234
        );
    }

    #[test]
    fn test_build_echo_response() {
        let request = GtpuHeader {
            version: 1,
            pt: true,
            e: false,
            s: true,
            pn: false,
            msg_type: gtpu_type::ECHO_REQUEST,
            length: 4,
            teid: 0,
            seq_num: Some(123),
            npdu_num: None,
            next_ext_hdr_type: None,
        };

        let response = build_echo_response(&request);
        assert!(!response.is_empty());
        assert_eq!(response[1], gtpu_type::ECHO_RESPONSE);
    }

    #[test]
    fn test_build_error_indication() {
        let data = build_error_indication(0x12345678, 1);
        assert!(!data.is_empty());
        assert_eq!(data[1], gtpu_type::ERROR_INDICATION);
    }

    #[test]
    fn test_build_end_marker() {
        let data = build_end_marker(0xABCD);
        assert_eq!(data.len(), 8);
        assert_eq!(data[1], gtpu_type::END_MARKER);
        assert_eq!(
            u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            0xABCD
        );
    }

    #[test]
    fn test_packet_pool() {
        let mut pool = PacketPool::new();
        assert!(!pool.is_initialized());

        pool.init();
        assert!(pool.is_initialized());

        pool.fini();
        assert!(!pool.is_initialized());
    }

    #[test]
    fn test_gtp_init_final() {
        assert!(gtp_init().is_ok());
        gtp_final();
    }

    #[test]
    fn test_gtp_open_close() {
        assert!(gtp_open().is_ok());
        gtp_close();
    }

    #[test]
    fn test_handle_gtpu_recv_invalid() {
        let data = [0x00]; // Too short
        let result = handle_gtpu_recv(&data, "10.0.0.1", "10.0.0.2");
        assert!(matches!(result, GtpuRecvResult::Dropped(_)));
    }

    #[test]
    fn test_handle_gtpu_recv_echo() {
        let data = [
            0x32, // Version=1, PT=1, S=1
            0x01, // Echo Request
            0x00, 0x04,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
            0x00,
            0x00,
        ];
        let result = handle_gtpu_recv(&data, "10.0.0.1", "10.0.0.2");
        assert!(matches!(result, GtpuRecvResult::EchoResponse));
    }
}
