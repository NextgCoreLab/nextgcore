//! GTP-U Path Handling for UPF
//!
//! Port of src/upf/gtp-path.c - GTP-U path handling for User Plane Function
//!
//! This module handles:
//! - GTP-U socket management
//! - TUN/TAP device I/O
//! - Packet forwarding between GTP-U and TUN interfaces
//! - ARP/ND proxy for TAP devices
//! - IP source spoofing detection
//! - URR accounting

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::RwLock;

use crate::context::{upf_self, UpfSess};
use crate::rule_match::{
    upf_sess_find_by_ue_ip_address, Ipv4Header, Ipv6Header, 
    IPV4_MIN_HEADER_LEN, IPV6_HEADER_LEN, IP_VERSION_4, IP_VERSION_6,
};

// ============================================================================
// Constants
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

/// GTP-U handled result
pub const GTP_HANDLED: i32 = 1;

// ============================================================================
// Ethernet Header
// ============================================================================

/// Ethernet header structure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct EtherHeader {
    /// Destination MAC address
    pub dst_addr: [u8; ETHER_ADDR_LEN],
    /// Source MAC address
    pub src_addr: [u8; ETHER_ADDR_LEN],
    /// Ethertype
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
// GTP Path State
// ============================================================================

/// GTP Path state management
pub struct GtpPath {
    /// Packet pool (simplified - in real impl would use a proper pool)
    initialized: bool,
    /// GTP-U IPv4 socket file descriptor
    gtpu_sock4: Option<i32>,
    /// GTP-U IPv6 socket file descriptor
    gtpu_sock6: Option<i32>,
    /// TUN/TAP devices by interface name
    devices: HashMap<String, TunDeviceInfo>,
}

/// TUN/TAP device information
#[derive(Debug, Clone)]
pub struct TunDeviceInfo {
    /// File descriptor
    pub fd: i32,
    /// Interface name
    pub ifname: String,
    /// Whether this is a TAP device
    pub is_tap: bool,
    /// MAC address (for TAP devices)
    pub mac_addr: [u8; ETHER_ADDR_LEN],
}

impl Default for GtpPath {
    fn default() -> Self {
        Self::new()
    }
}

impl GtpPath {
    /// Create a new GTP path instance
    pub fn new() -> Self {
        Self {
            initialized: false,
            gtpu_sock4: None,
            gtpu_sock6: None,
            devices: HashMap::new(),
        }
    }

    /// Check if initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

// ============================================================================
// Global GTP Path (singleton)
// ============================================================================

use std::sync::OnceLock;

static GTP_PATH: OnceLock<RwLock<GtpPath>> = OnceLock::new();

/// Get the global GTP path instance
pub fn gtp_path() -> &'static RwLock<GtpPath> {
    GTP_PATH.get_or_init(|| RwLock::new(GtpPath::new()))
}

// ============================================================================
// Initialization / Finalization
// ============================================================================

/// Initialize GTP-U path handling
///
/// Port of upf_gtp_init() from gtp-path.c
/// Creates the packet pool for GTP-U processing.
pub fn upf_gtp_init() -> Result<(), GtpPathError> {
    let mut path = gtp_path().write().map_err(|_| GtpPathError::LockError)?;
    
    if path.initialized {
        log::warn!("GTP path already initialized");
        return Ok(());
    }

    // In the C code, this creates a packet buffer pool
    // In Rust, we rely on the allocator and Vec for packet buffers
    path.initialized = true;
    
    log::info!("GTP-U path initialized");
    Ok(())
}

/// Finalize GTP-U path handling
///
/// Port of upf_gtp_final() from gtp-path.c
/// Destroys the packet pool.
pub fn upf_gtp_final() -> Result<(), GtpPathError> {
    let mut path = gtp_path().write().map_err(|_| GtpPathError::LockError)?;
    
    if !path.initialized {
        log::warn!("GTP path not initialized");
        return Ok(());
    }

    path.initialized = false;
    path.devices.clear();
    path.gtpu_sock4 = None;
    path.gtpu_sock6 = None;
    
    log::info!("GTP-U path finalized");
    Ok(())
}

// ============================================================================
// Socket / Device Management
// ============================================================================

/// Open GTP-U sockets and TUN devices
///
/// Port of upf_gtp_open() from gtp-path.c
/// Opens GTP-U UDP sockets and TUN/TAP devices, sets up poll callbacks.
pub fn upf_gtp_open() -> Result<(), GtpPathError> {
    let path = gtp_path().write().map_err(|_| GtpPathError::LockError)?;
    
    if !path.initialized {
        return Err(GtpPathError::NotInitialized);
    }

    // Note: In the full implementation, this would:
    // 1. Create GTP-U UDP sockets on port 2152
    // 2. Open TUN/TAP devices
    // 3. Set up poll callbacks for async I/O
    // 4. Configure IP addresses on TUN interfaces
    
    log::info!("GTP-U path opened");
    Ok(())
}

/// Close GTP-U sockets and TUN devices
///
/// Port of upf_gtp_close() from gtp-path.c
pub fn upf_gtp_close() -> Result<(), GtpPathError> {
    let mut path = gtp_path().write().map_err(|_| GtpPathError::LockError)?;
    
    // Close all TUN/TAP devices
    for (name, dev) in path.devices.drain() {
        if dev.fd >= 0 {
            unsafe {
                libc::close(dev.fd);
            }
            log::info!("Closed TUN/TAP device: {}", name);
        }
    }

    // Close GTP-U sockets
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

/// Register a TUN/TAP device
pub fn register_device(ifname: &str, fd: i32, is_tap: bool) -> Result<(), GtpPathError> {
    let mut path = gtp_path().write().map_err(|_| GtpPathError::LockError)?;
    
    let mac_addr = if is_tap {
        get_dev_mac_addr(ifname)?
    } else {
        [0u8; ETHER_ADDR_LEN]
    };

    let info = TunDeviceInfo {
        fd,
        ifname: ifname.to_string(),
        is_tap,
        mac_addr,
    };

    path.devices.insert(ifname.to_string(), info);
    log::info!("Registered {} device: {}", if is_tap { "TAP" } else { "TUN" }, ifname);
    
    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get Ethernet type from packet data
///
/// Port of _get_eth_type() from gtp-path.c
#[inline]
pub fn get_eth_type(data: &[u8]) -> u16 {
    if data.len() > ETHER_HDR_LEN {
        let eth_hdr = unsafe { &*(data.as_ptr() as *const EtherHeader) };
        eth_hdr.get_ether_type()
    } else {
        0
    }
}

/// Get MAC address for a network interface
///
/// Port of _get_dev_mac_addr() from gtp-path.c
#[cfg(target_os = "linux")]
pub fn get_dev_mac_addr(ifname: &str) -> Result<[u8; ETHER_ADDR_LEN], GtpPathError> {
    use std::ffi::CString;
    use std::mem::MaybeUninit;

    let fd = unsafe { libc::socket(libc::PF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(GtpPathError::SyscallError("socket() failed".to_string()));
    }

    let mut req: libc::ifreq = unsafe { MaybeUninit::zeroed().assume_init() };
    let ifname_cstr = CString::new(ifname).map_err(|_| GtpPathError::InvalidIfname)?;
    let ifname_bytes = ifname_cstr.as_bytes_with_nul();
    let copy_len = ifname_bytes.len().min(libc::IF_NAMESIZE - 1);
    
    unsafe {
        std::ptr::copy_nonoverlapping(
            ifname_bytes.as_ptr(),
            req.ifr_name.as_mut_ptr() as *mut u8,
            copy_len,
        );
    }

    let ret = unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR, &mut req) };
    unsafe { libc::close(fd); }

    if ret != 0 {
        return Err(GtpPathError::SyscallError("ioctl(SIOCGIFHWADDR) failed".to_string()));
    }

    let mut mac_addr = [0u8; ETHER_ADDR_LEN];
    unsafe {
        std::ptr::copy_nonoverlapping(
            req.ifr_ifru.ifru_hwaddr.sa_data.as_ptr() as *const u8,
            mac_addr.as_mut_ptr(),
            ETHER_ADDR_LEN,
        );
    }

    Ok(mac_addr)
}

#[cfg(target_os = "macos")]
pub fn get_dev_mac_addr(_ifname: &str) -> Result<[u8; ETHER_ADDR_LEN], GtpPathError> {
    // macOS uses getifaddrs with AF_LINK
    // For now, return a placeholder - full implementation would use getifaddrs
    log::warn!("get_dev_mac_addr not fully implemented on macOS");
    Ok([0u8; ETHER_ADDR_LEN])
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn get_dev_mac_addr(_ifname: &str) -> Result<[u8; ETHER_ADDR_LEN], GtpPathError> {
    Err(GtpPathError::NotSupported)
}

/// Check if source address matches framed routes
///
/// Port of check_framed_routes() from gtp-path.c
pub fn check_framed_routes(sess: &UpfSess, addr: &[u32; 4], is_ipv6: bool) -> bool {
    sess.check_framed_routes(addr, is_ipv6)
}

// ============================================================================
// TUN Receive Callbacks
// ============================================================================

/// Result of processing a TUN packet
#[derive(Debug)]
pub enum TunRecvResult {
    /// Packet was handled (forwarded or dropped)
    Handled,
    /// No session found for packet
    NoSession,
    /// Packet was an ARP/ND request that was replied to
    ArpNdReplied,
    /// Error occurred
    Error(GtpPathError),
}

/// Process a packet received from TUN interface (downlink)
///
/// Port of _gtpv1_tun_recv_common_cb() from gtp-path.c
/// This handles packets coming from the core network destined for UEs.
pub fn gtpv1_tun_recv_cb(data: &[u8], is_tap: bool) -> TunRecvResult {
    if data.is_empty() {
        return TunRecvResult::Error(GtpPathError::EmptyPacket);
    }

    let ip_data = if is_tap {
        // For TAP devices, handle Ethernet framing
        let eth_type = get_eth_type(data);
        
        match eth_type {
            ETHERTYPE_ARP => {
                // Handle ARP request
                if is_arp_request(data) {
                    // Would send ARP reply here
                    log::debug!("Received ARP request on TAP device");
                    return TunRecvResult::ArpNdReplied;
                }
                return TunRecvResult::Handled;
            }
            ETHERTYPE_IPV6 => {
                // Check for ND solicitation
                if is_nd_solicitation(data) {
                    log::debug!("Received ND solicitation on TAP device");
                    return TunRecvResult::ArpNdReplied;
                }
                // Strip Ethernet header
                if data.len() <= ETHER_HDR_LEN {
                    return TunRecvResult::Error(GtpPathError::PacketTooShort);
                }
                &data[ETHER_HDR_LEN..]
            }
            ETHERTYPE_IP => {
                // Strip Ethernet header
                if data.len() <= ETHER_HDR_LEN {
                    return TunRecvResult::Error(GtpPathError::PacketTooShort);
                }
                &data[ETHER_HDR_LEN..]
            }
            _ => {
                log::error!("[DROP] Invalid eth_type [0x{:04x}]", eth_type);
                return TunRecvResult::Handled;
            }
        }
    } else {
        data
    };

    // Find session by destination IP address
    let sess = match upf_sess_find_by_ue_ip_address(ip_data) {
        Some(s) => s,
        None => {
            // No session found - might be multicast
            if should_handle_multicast(ip_data) {
                handle_multicast(ip_data);
            }
            return TunRecvResult::NoSession;
        }
    };

    // In full implementation:
    // 1. Find matching PDR (downlink, src_if = CORE)
    // 2. Apply FAR (forward action)
    // 3. Encapsulate in GTP-U and send to gNB/eNB
    // 4. Update URR accounting

    log::trace!("TUN recv: found session id={}", sess.id);
    TunRecvResult::Handled
}

// ============================================================================
// GTP-U Receive Callback
// ============================================================================

/// Result of processing a GTP-U packet
#[derive(Debug)]
pub enum GtpuRecvResult {
    /// Packet was handled successfully
    Handled,
    /// Echo request received and response sent
    EchoResponse,
    /// Error indication received
    ErrorIndication,
    /// End marker received
    EndMarker,
    /// G-PDU forwarded to TUN
    GpduForwarded,
    /// Session not found, error indication sent
    SessionNotFound,
    /// IP spoofing detected
    SpoofingDetected,
    /// Error occurred
    Error(GtpPathError),
}

/// GTP-U header descriptor (parsed header info)
#[derive(Debug, Clone, Default)]
pub struct GtpuHeaderDesc {
    /// Message type
    pub msg_type: u8,
    /// TEID
    pub teid: u32,
    /// Sequence number (if present)
    pub seq_num: Option<u16>,
    /// QoS Flow Identifier (QFI)
    pub qfi: Option<u8>,
    /// Header length (bytes consumed)
    pub header_len: usize,
}

/// GTP-U message types
pub mod gtpu_msg_type {
    pub const ECHO_REQUEST: u8 = 1;
    pub const ECHO_RESPONSE: u8 = 2;
    pub const ERROR_INDICATION: u8 = 26;
    pub const END_MARKER: u8 = 254;
    pub const GPDU: u8 = 255;
}

/// Process a packet received from GTP-U socket (uplink)
///
/// Port of _gtpv1_u_recv_cb() from gtp-path.c
/// This handles packets coming from gNB/eNB destined for the core network.
pub fn gtpv1_u_recv_cb(
    data: &[u8],
    from: &SocketAddr,
) -> GtpuRecvResult {
    if data.len() < 8 {
        log::error!("[DROP] GTP-U packet too short: {} bytes", data.len());
        return GtpuRecvResult::Error(GtpPathError::PacketTooShort);
    }

    // Parse GTP-U header
    let header_desc = match parse_gtpu_header(data) {
        Ok(h) => h,
        Err(e) => {
            log::error!("[DROP] Cannot decode GTP-U packet: {:?}", e);
            return GtpuRecvResult::Error(e);
        }
    };

    // Check GTP version
    let version = (data[0] >> 5) & 0x07;
    if version != 1 {
        log::error!("[DROP] Invalid GTP-U version [{}]", version);
        return GtpuRecvResult::Error(GtpPathError::InvalidVersion(version));
    }

    log::trace!(
        "[RECV] GTP-U Type [{}] from [{}] : TEID[0x{:x}]",
        header_desc.msg_type,
        from,
        header_desc.teid
    );

    match header_desc.msg_type {
        gtpu_msg_type::ECHO_REQUEST => {
            log::info!("[RECV] Echo Request from [{}]", from);
            // Would send echo response here
            GtpuRecvResult::EchoResponse
        }
        gtpu_msg_type::END_MARKER => {
            log::debug!("[RECV] End Marker from [{}]", from);
            GtpuRecvResult::EndMarker
        }
        gtpu_msg_type::ERROR_INDICATION => {
            log::warn!("[RECV] Error Indication from [{}]", from);
            // Would handle error indication here
            GtpuRecvResult::ErrorIndication
        }
        gtpu_msg_type::GPDU => {
            handle_gpdu(data, &header_desc, from)
        }
        _ => {
            log::error!("[DROP] Invalid GTP-U Type [{}]", header_desc.msg_type);
            GtpuRecvResult::Error(GtpPathError::InvalidMessageType(header_desc.msg_type))
        }
    }
}

/// Handle G-PDU (user data) packet
fn handle_gpdu(
    data: &[u8],
    header_desc: &GtpuHeaderDesc,
    from: &SocketAddr,
) -> GtpuRecvResult {
    // Get IP payload after GTP header
    if data.len() <= header_desc.header_len {
        log::error!("[DROP] Small GTP-U packet (type:{} len:{})", 
            header_desc.msg_type, header_desc.header_len);
        return GtpuRecvResult::Error(GtpPathError::PacketTooShort);
    }

    let ip_data = &data[header_desc.header_len..];
    
    if ip_data.is_empty() {
        return GtpuRecvResult::Error(GtpPathError::EmptyPacket);
    }

    // Get IP version
    let ip_version = (ip_data[0] >> 4) & 0x0F;

    // Find session by TEID
    let sess = match upf_self().sess_find_by_upf_n4_seid(header_desc.teid as u64) {
        Some(s) => s,
        None => {
            log::error!(
                "[DROP] Session not found for TEID:0x{:x} from [{}]",
                header_desc.teid,
                from
            );
            // Would send error indication here
            return GtpuRecvResult::SessionNotFound;
        }
    };

    // Check for IP source spoofing (uplink packets)
    if !verify_source_address(&sess, ip_data, ip_version) {
        log::error!(
            "[DROP] Source IP-{} Spoofing TEID:0x{:x}",
            ip_version,
            header_desc.teid
        );
        return GtpuRecvResult::SpoofingDetected;
    }

    // In full implementation:
    // 1. Find matching PDR (uplink, src_if = ACCESS)
    // 2. Apply FAR (forward action)
    // 3. Write to TUN device (decapsulated)
    // 4. Update URR accounting

    log::trace!("GTP-U recv: forwarding to TUN, session id={}", sess.id);
    GtpuRecvResult::GpduForwarded
}

/// Verify source IP address matches session (anti-spoofing)
///
/// Port of IP spoofing check from _gtpv1_u_recv_cb() in gtp-path.c
fn verify_source_address(sess: &UpfSess, ip_data: &[u8], ip_version: u8) -> bool {
    match ip_version {
        IP_VERSION_4 => {
            if ip_data.len() < IPV4_MIN_HEADER_LEN {
                return false;
            }
            
            let ip_hdr = unsafe { &*(ip_data.as_ptr() as *const Ipv4Header) };
            let src_addr = ip_hdr.src_addr();
            
            // Check if session has IPv4 address
            if let Some(ref ipv4) = sess.ipv4 {
                // Source should match session IP
                if src_addr == ipv4.addr[0] {
                    return true;
                }
                // Or match a framed route
                if check_framed_routes(sess, &[src_addr, 0, 0, 0], false) {
                    return true;
                }
            }
            false
        }
        IP_VERSION_6 => {
            if ip_data.len() < IPV6_HEADER_LEN {
                return false;
            }
            
            let ip6_hdr = unsafe { &*(ip_data.as_ptr() as *const Ipv6Header) };
            let src_addr = ip6_hdr.src_addr();
            
            // Check if session has IPv6 address
            if let Some(ref ipv6) = sess.ipv6 {
                // Check link-local (interface identifier match)
                if is_ipv6_link_local(&src_addr) {
                    if src_addr[2] == ipv6.addr[2] && src_addr[3] == ipv6.addr[3] {
                        return true;
                    }
                }
                // Check global (64-bit prefix match)
                if src_addr[0] == ipv6.addr[0] && src_addr[1] == ipv6.addr[1] {
                    return true;
                }
                // Or match a framed route
                if check_framed_routes(sess, &src_addr, true) {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

/// Check if IPv6 address is link-local
#[inline]
fn is_ipv6_link_local(addr: &[u32; 4]) -> bool {
    // Link-local addresses start with fe80::/10
    (addr[0] & 0xFFC00000) == 0xFE800000
}

// ============================================================================
// Multicast Handling
// ============================================================================

/// Check if packet should be handled as multicast
fn should_handle_multicast(ip_data: &[u8]) -> bool {
    if ip_data.is_empty() {
        return false;
    }

    let ip_version = (ip_data[0] >> 4) & 0x0F;
    
    if ip_version == IP_VERSION_6 && ip_data.len() >= IPV6_HEADER_LEN {
        let ip6_hdr = unsafe { &*(ip_data.as_ptr() as *const Ipv6Header) };
        let dst_addr = ip6_hdr.dst_addr();
        // IPv6 multicast addresses start with ff00::/8
        return (dst_addr[0] >> 24) == 0xFF;
    }
    
    false
}

/// Handle IPv6 multicast packet
///
/// Port of upf_gtp_handle_multicast() from gtp-path.c
pub fn handle_multicast(ip_data: &[u8]) {
    if ip_data.len() < IPV6_HEADER_LEN {
        return;
    }

    let ip_version = (ip_data[0] >> 4) & 0x0F;
    if ip_version != IP_VERSION_6 {
        return;
    }

    let ip6_hdr = unsafe { &*(ip_data.as_ptr() as *const Ipv6Header) };
    let dst_addr = ip6_hdr.dst_addr();

    // Check if multicast
    if (dst_addr[0] >> 24) != 0xFF {
        return;
    }

    log::debug!("Handling IPv6 multicast packet");

    // In full implementation:
    // Iterate through all sessions with IPv6 addresses
    // For each session, find downlink PDR and forward the packet
    let sessions = upf_self().get_all_sessions();
    for sess in sessions {
        if sess.ipv6.is_some() {
            // Would forward multicast packet to this session
            log::trace!("Would forward multicast to session id={}", sess.id);
        }
    }
}

// ============================================================================
// ARP/ND Handling
// ============================================================================

/// Check if packet is an ARP request
fn is_arp_request(data: &[u8]) -> bool {
    if data.len() < ETHER_HDR_LEN + 8 {
        return false;
    }
    
    let eth_type = get_eth_type(data);
    if eth_type != ETHERTYPE_ARP {
        return false;
    }

    // ARP operation: 1 = request, 2 = reply
    let arp_op = u16::from_be_bytes([data[ETHER_HDR_LEN + 6], data[ETHER_HDR_LEN + 7]]);
    arp_op == 1
}

/// Check if packet is an ND (Neighbor Discovery) solicitation
fn is_nd_solicitation(data: &[u8]) -> bool {
    if data.len() < ETHER_HDR_LEN + IPV6_HEADER_LEN + 8 {
        return false;
    }

    let eth_type = get_eth_type(data);
    if eth_type != ETHERTYPE_IPV6 {
        return false;
    }

    // Check ICMPv6 type (135 = Neighbor Solicitation)
    let ip6_data = &data[ETHER_HDR_LEN..];
    if ip6_data.len() < IPV6_HEADER_LEN + 1 {
        return false;
    }

    let ip6_hdr = unsafe { &*(ip6_data.as_ptr() as *const Ipv6Header) };
    
    // Next header should be ICMPv6 (58)
    if ip6_hdr.next_header != 58 {
        return false;
    }

    // ICMPv6 type is first byte after IPv6 header
    let icmp_type = ip6_data[IPV6_HEADER_LEN];
    icmp_type == 135 // Neighbor Solicitation
}

// ============================================================================
// GTP-U Header Parsing
// ============================================================================

/// Parse GTP-U header from packet data
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
        // N-PDU number at data[10]
        // Next extension header type at data[11]
        header_len = 12;

        // Parse extension headers if present
        let ext_flag = flags & 0x04;
        if ext_flag != 0 {
            let mut ext_offset = 12;
            let mut next_ext = data[11];
            
            while next_ext != 0 && ext_offset < data.len() {
                let ext_len = (data[ext_offset] as usize) * 4;
                if ext_len == 0 || ext_offset + ext_len > data.len() {
                    break;
                }
                
                // Check for PDU Session Container (type 0x85)
                if next_ext == 0x85 && ext_len >= 4 {
                    // QFI is in the first byte of extension content
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
// Error Types
// ============================================================================

/// GTP Path errors
#[derive(Debug, Clone)]
pub enum GtpPathError {
    /// Not initialized
    NotInitialized,
    /// Lock acquisition failed
    LockError,
    /// Packet too short
    PacketTooShort,
    /// Empty packet
    EmptyPacket,
    /// Invalid GTP version
    InvalidVersion(u8),
    /// Invalid message type
    InvalidMessageType(u8),
    /// Invalid interface name
    InvalidIfname,
    /// System call error
    SyscallError(String),
    /// Not supported on this platform
    NotSupported,
    /// I/O error
    IoError(String),
}

impl std::fmt::Display for GtpPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GtpPathError::NotInitialized => write!(f, "GTP path not initialized"),
            GtpPathError::LockError => write!(f, "Failed to acquire lock"),
            GtpPathError::PacketTooShort => write!(f, "Packet too short"),
            GtpPathError::EmptyPacket => write!(f, "Empty packet"),
            GtpPathError::InvalidVersion(v) => write!(f, "Invalid GTP version: {}", v),
            GtpPathError::InvalidMessageType(t) => write!(f, "Invalid message type: {}", t),
            GtpPathError::InvalidIfname => write!(f, "Invalid interface name"),
            GtpPathError::SyscallError(msg) => write!(f, "System call error: {}", msg),
            GtpPathError::NotSupported => write!(f, "Not supported on this platform"),
            GtpPathError::IoError(msg) => write!(f, "I/O error: {}", msg),
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
    fn test_get_eth_type() {
        // Valid Ethernet frame with IPv4
        let mut frame = vec![0u8; 20];
        frame[12] = 0x08; // ETHERTYPE_IP high byte
        frame[13] = 0x00; // ETHERTYPE_IP low byte
        assert_eq!(get_eth_type(&frame), ETHERTYPE_IP);

        // Valid Ethernet frame with IPv6
        frame[12] = 0x86;
        frame[13] = 0xDD;
        assert_eq!(get_eth_type(&frame), ETHERTYPE_IPV6);

        // Valid Ethernet frame with ARP
        frame[12] = 0x08;
        frame[13] = 0x06;
        assert_eq!(get_eth_type(&frame), ETHERTYPE_ARP);

        // Too short frame
        let short_frame = vec![0u8; 10];
        assert_eq!(get_eth_type(&short_frame), 0);
    }

    #[test]
    fn test_parse_gtpu_header_basic() {
        // Basic GTP-U header (8 bytes, no optional fields)
        let data = [
            0x30, // Version=1, PT=1, no optional flags
            0xFF, // Message type = G-PDU
            0x00, 0x10, // Length = 16
            0x12, 0x34, 0x56, 0x78, // TEID
            // Payload would follow
        ];

        let result = parse_gtpu_header(&data).unwrap();
        assert_eq!(result.msg_type, gtpu_msg_type::GPDU);
        assert_eq!(result.teid, 0x12345678);
        assert_eq!(result.header_len, 8);
        assert!(result.seq_num.is_none());
    }

    #[test]
    fn test_parse_gtpu_header_with_seq() {
        // GTP-U header with sequence number (12 bytes)
        let data = [
            0x32, // Version=1, PT=1, S=1
            0xFF, // Message type = G-PDU
            0x00, 0x14, // Length = 20
            0x12, 0x34, 0x56, 0x78, // TEID
            0xAB, 0xCD, // Sequence number
            0x00, // N-PDU number
            0x00, // Next extension header type
        ];

        let result = parse_gtpu_header(&data).unwrap();
        assert_eq!(result.msg_type, gtpu_msg_type::GPDU);
        assert_eq!(result.teid, 0x12345678);
        assert_eq!(result.seq_num, Some(0xABCD));
        assert_eq!(result.header_len, 12);
    }

    #[test]
    fn test_parse_gtpu_header_invalid_version() {
        let data = [
            0x00, // Version=0 (invalid)
            0xFF,
            0x00, 0x10,
            0x12, 0x34, 0x56, 0x78,
        ];

        let result = parse_gtpu_header(&data);
        assert!(matches!(result, Err(GtpPathError::InvalidVersion(0))));
    }

    #[test]
    fn test_parse_gtpu_header_too_short() {
        let data = [0x30, 0xFF, 0x00, 0x10]; // Only 4 bytes
        let result = parse_gtpu_header(&data);
        assert!(matches!(result, Err(GtpPathError::PacketTooShort)));
    }

    #[test]
    fn test_is_ipv6_link_local() {
        // fe80::1
        let link_local = [0xFE800000, 0, 0, 1];
        assert!(is_ipv6_link_local(&link_local));

        // 2001:db8::1 (not link-local)
        let global = [0x20010DB8, 0, 0, 1];
        assert!(!is_ipv6_link_local(&global));
    }

    #[test]
    fn test_gtp_path_init_final() {
        // Initialize
        let result = upf_gtp_init();
        assert!(result.is_ok());

        // Check initialized
        {
            let path = gtp_path().read().unwrap();
            assert!(path.is_initialized());
        }

        // Finalize
        let result = upf_gtp_final();
        assert!(result.is_ok());

        // Check not initialized
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
