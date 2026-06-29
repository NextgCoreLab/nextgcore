//! GTP-U Path — Control-Plane Stubs and Shared Types
//!
//! ## Division of responsibility
//!
//! | Concern | Module |
//! |---------|--------|
//! | **Live GTP-U forwarding** (encap/decap, session lookup, PDR/FAR/QER) | `data_plane.rs` |
//! | **GTP-U path management** (Echo, Recovery, path-failure) | `data_plane::GtpuPathTable` |
//! | **Lifecycle stubs** (init/open/close/final called from `main.rs`) | **this file** |
//! | **Shared constants + types** used by arp_nd.rs and data_plane.rs | **this file** |
//!
//! The forwarding stubs that used to live here (`gtpv1_tun_recv_cb`,
//! `gtpv1_u_recv_cb`, `handle_gpdu`, etc.) were non-functional duplicates of
//! the live `data_plane.rs` path.  They have been removed (upfd-06) to
//! eliminate dead code and prevent accidental use of a divergent implementation.

// ============================================================================
// Constants — shared with arp_nd.rs and data_plane.rs
// ============================================================================

/// Proxy MAC address for ARP/ND responses
pub const PROXY_MAC_ADDR: [u8; 6] = [0x0e, 0x00, 0x00, 0x00, 0x00, 0x01];

/// Ethernet header length
pub const ETHER_HDR_LEN: usize = 14;

/// Ethernet address length
pub const ETHER_ADDR_LEN: usize = 6;

/// Ethertype for IPv4
pub const ETHERTYPE_IP: u16 = 0x0800;

/// Ethertype for IPv6
pub const ETHERTYPE_IPV6: u16 = 0x86DD;

/// Ethertype for ARP
pub const ETHERTYPE_ARP: u16 = 0x0806;

/// Maximum packet length
pub const MAX_PKT_LEN: usize = 65535;

/// TUN maximum headroom for encapsulation
pub const TUN_MAX_HEADROOM: usize = 64;

/// GTP-U handled result sentinel (kept for source-level compatibility)
pub const GTP_HANDLED: i32 = 1;

// ============================================================================
// Ethernet Header — used by arp_nd.rs
// ============================================================================

/// Ethernet header structure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct EtherHeader {
    /// Destination MAC address
    pub dst_addr: [u8; ETHER_ADDR_LEN],
    /// Source MAC address
    pub src_addr: [u8; ETHER_ADDR_LEN],
    /// Ethertype (network byte order)
    pub ether_type: u16,
}

impl EtherHeader {
    /// Get ethertype in host byte order
    #[inline]
    pub fn get_ether_type(&self) -> u16 {
        u16::from_be(self.ether_type)
    }
}

// ============================================================================
// GTP-U Message Types — shared with data_plane.rs
// ============================================================================

/// GTP-U message type constants (TS 29.281 §8.1)
pub mod gtpu_msg_type {
    pub const ECHO_REQUEST: u8 = 1;
    pub const ECHO_RESPONSE: u8 = 2;
    pub const ERROR_INDICATION: u8 = 26;
    pub const END_MARKER: u8 = 254;
    pub const GPDU: u8 = 255;
}

// ============================================================================
// GTP-U Header Descriptor + Parser — used by data_plane.rs
// ============================================================================

/// Parsed GTP-U header fields
#[derive(Debug, Clone, Default)]
pub struct GtpuHeaderDesc {
    /// Message type
    pub msg_type: u8,
    /// TEID
    pub teid: u32,
    /// Sequence number (present when S=1)
    pub seq_num: Option<u16>,
    /// QoS Flow Identifier extracted from PDU Session Container extension header
    pub qfi: Option<u8>,
    /// Total header length in bytes (including optional fields and extensions)
    pub header_len: usize,
}

/// Parse GTP-U header from packet data.
///
/// Handles the 8-byte mandatory header, the optional 4-byte
/// seq/N-PDU/next-ext fields (when any of E/S/PN flags are set), and the
/// PDU Session Container extension header (type 0x85) for QFI extraction.
pub fn parse_gtpu_header(data: &[u8]) -> Result<GtpuHeaderDesc, GtpPathError> {
    if data.len() < 8 {
        return Err(GtpPathError::PacketTooShort);
    }

    let flags = data[0];
    let version = (flags >> 5) & 0x07;
    if version != 1 {
        return Err(GtpPathError::InvalidVersion(version));
    }

    let msg_type = data[1];
    let _length = u16::from_be_bytes([data[2], data[3]]);
    let teid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    let has_optional = (flags & 0x07) != 0; // E, S, or PN flags
    let mut header_len = 8;
    let mut seq_num = None;
    let mut qfi = None;

    if has_optional {
        if data.len() < 12 {
            return Err(GtpPathError::PacketTooShort);
        }
        seq_num = Some(u16::from_be_bytes([data[8], data[9]]));
        // data[10] = N-PDU number; data[11] = next extension header type
        header_len = 12;

        // Walk extension headers if E flag is set
        if (flags & 0x04) != 0 {
            let mut ext_offset = 12;
            let mut next_ext = data[11];

            while next_ext != 0 && ext_offset < data.len() {
                let ext_len = (data[ext_offset] as usize) * 4;
                if ext_len == 0 || ext_offset + ext_len > data.len() {
                    break;
                }
                // PDU Session Container (type 0x85) carries QFI in byte 1 of content
                if next_ext == 0x85 && ext_len >= 4 {
                    qfi = Some(data[ext_offset + 1] & 0x3F);
                }
                next_ext = data[ext_offset + ext_len - 1];
                ext_offset += ext_len;
                header_len = ext_offset;
            }
        }
    }

    Ok(GtpuHeaderDesc {
        msg_type,
        teid,
        seq_num,
        qfi,
        header_len,
    })
}

// ============================================================================
// Control-Plane Lifecycle Stubs — called from main.rs
// ============================================================================
//
// These stubs keep the main.rs call-chain intact while the live GTP-U I/O is
// owned by `data_plane::DataPlane`. They will be wired to real socket
// management if/when a control-plane GTP-U path separate from the data plane
// is needed.

use std::sync::OnceLock;
use std::sync::RwLock;

/// Minimal GTP path state (lifecycle only; no socket FDs at present)
pub struct GtpPath {
    initialized: bool,
    /// Optional raw socket FDs reserved for a future control-plane GTP-U path.
    gtpu_sock4: Option<i32>,
    gtpu_sock6: Option<i32>,
}

impl Default for GtpPath {
    fn default() -> Self {
        Self::new()
    }
}

impl GtpPath {
    pub fn new() -> Self {
        Self {
            initialized: false,
            gtpu_sock4: None,
            gtpu_sock6: None,
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

static GTP_PATH: OnceLock<RwLock<GtpPath>> = OnceLock::new();

/// Get the global GTP path singleton
pub fn gtp_path() -> &'static RwLock<GtpPath> {
    GTP_PATH.get_or_init(|| RwLock::new(GtpPath::new()))
}

/// Initialise the GTP-U path (called once at startup from main.rs).
pub fn upf_gtp_init() -> Result<(), GtpPathError> {
    let mut path = gtp_path().write().map_err(|_| GtpPathError::LockError)?;
    if path.initialized {
        log::warn!("GTP path already initialized");
        return Ok(());
    }
    path.initialized = true;
    log::info!("GTP-U path initialized");
    Ok(())
}

/// Finalise the GTP-U path (called at shutdown from main.rs).
pub fn upf_gtp_final() -> Result<(), GtpPathError> {
    let mut path = gtp_path().write().map_err(|_| GtpPathError::LockError)?;
    if !path.initialized {
        log::warn!("GTP path not initialized");
        return Ok(());
    }
    path.initialized = false;
    log::info!("GTP-U path finalized");
    Ok(())
}

/// Open GTP-U sockets (control-plane stub; real I/O is in DataPlane::init).
pub fn upf_gtp_open() -> Result<(), GtpPathError> {
    let path = gtp_path().read().map_err(|_| GtpPathError::LockError)?;
    if !path.initialized {
        return Err(GtpPathError::NotInitialized);
    }
    // Live socket creation is handled by DataPlane::init() (data_plane.rs).
    log::info!("GTP-U path opened (live socket owned by DataPlane)");
    Ok(())
}

/// Close GTP-U sockets (control-plane stub).
pub fn upf_gtp_close() -> Result<(), GtpPathError> {
    let mut path = gtp_path().write().map_err(|_| GtpPathError::LockError)?;
    if let Some(fd) = path.gtpu_sock4.take() {
        if fd >= 0 {
            unsafe { libc::close(fd); }
        }
    }
    if let Some(fd) = path.gtpu_sock6.take() {
        if fd >= 0 {
            unsafe { libc::close(fd); }
        }
    }
    log::info!("GTP-U path closed");
    Ok(())
}

// ============================================================================
// Error Types
// ============================================================================

/// GTP path errors
#[derive(Debug, Clone)]
pub enum GtpPathError {
    NotInitialized,
    LockError,
    PacketTooShort,
    EmptyPacket,
    InvalidVersion(u8),
    InvalidMessageType(u8),
    InvalidIfname,
    SyscallError(String),
    NotSupported,
    IoError(String),
}

impl std::fmt::Display for GtpPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GtpPathError::NotInitialized => write!(f, "GTP path not initialized"),
            GtpPathError::LockError => write!(f, "Failed to acquire lock"),
            GtpPathError::PacketTooShort => write!(f, "Packet too short"),
            GtpPathError::EmptyPacket => write!(f, "Empty packet"),
            GtpPathError::InvalidVersion(v) => write!(f, "Invalid GTP version: {v}"),
            GtpPathError::InvalidMessageType(t) => write!(f, "Invalid message type: {t}"),
            GtpPathError::InvalidIfname => write!(f, "Invalid interface name"),
            GtpPathError::SyscallError(msg) => write!(f, "System call error: {msg}"),
            GtpPathError::NotSupported => write!(f, "Not supported on this platform"),
            GtpPathError::IoError(msg) => write!(f, "I/O error: {msg}"),
        }
    }
}

impl std::error::Error for GtpPathError {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_gtpu_header_basic() {
        let data = [
            0x30, // Version=1, PT=1, no optional flags
            0xFF, // Message type = G-PDU
            0x00, 0x10, // Length = 16
            0x12, 0x34, 0x56, 0x78, // TEID
        ];
        let result = parse_gtpu_header(&data).unwrap();
        assert_eq!(result.msg_type, gtpu_msg_type::GPDU);
        assert_eq!(result.teid, 0x12345678);
        assert_eq!(result.header_len, 8);
        assert!(result.seq_num.is_none());
    }

    #[test]
    fn test_parse_gtpu_header_with_seq() {
        let data = [
            0x32, // Version=1, PT=1, S=1
            0xFF, // G-PDU
            0x00, 0x14, // Length = 20
            0x12, 0x34, 0x56, 0x78, // TEID
            0xAB, 0xCD, // Sequence number
            0x00, // N-PDU
            0x00, // Next ext = none
        ];
        let result = parse_gtpu_header(&data).unwrap();
        assert_eq!(result.msg_type, gtpu_msg_type::GPDU);
        assert_eq!(result.teid, 0x12345678);
        assert_eq!(result.seq_num, Some(0xABCD));
        assert_eq!(result.header_len, 12);
    }

    #[test]
    fn test_parse_gtpu_header_invalid_version() {
        let data = [0x00, 0xFF, 0x00, 0x10, 0x12, 0x34, 0x56, 0x78];
        let result = parse_gtpu_header(&data);
        assert!(matches!(result, Err(GtpPathError::InvalidVersion(0))));
    }

    #[test]
    fn test_parse_gtpu_header_too_short() {
        let data = [0x30, 0xFF, 0x00, 0x10]; // only 4 bytes
        let result = parse_gtpu_header(&data);
        assert!(matches!(result, Err(GtpPathError::PacketTooShort)));
    }

    #[test]
    fn test_gtp_path_init_final() {
        // Use a fresh static via the singleton — idempotent in test runs.
        let _ = upf_gtp_init();
        {
            let path = gtp_path().read().unwrap();
            assert!(path.is_initialized());
        }
        let _ = upf_gtp_final();
        {
            let path = gtp_path().read().unwrap();
            assert!(!path.is_initialized());
        }
    }

    #[test]
    fn test_ether_header_size() {
        assert_eq!(std::mem::size_of::<EtherHeader>(), ETHER_HDR_LEN);
    }

    #[test]
    fn test_constants() {
        assert_eq!(ETHER_HDR_LEN, 14);
        assert_eq!(ETHER_ADDR_LEN, 6);
        assert_eq!(ETHERTYPE_IP, 0x0800);
        assert_eq!(ETHERTYPE_IPV6, 0x86DD);
        assert_eq!(ETHERTYPE_ARP, 0x0806);
    }
}
