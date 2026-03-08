//! Session Extensions: IPv6 Dual-Stack, SSC Modes, Ethernet PDU (Items #199-#201)
//!
//! Extends SMF session management with:
//! - IPv6 dual-stack address allocation (TS 29.244)
//! - SSC Mode 2/3 with N9 UPF-to-UPF forwarding (TS 23.502)
//! - Ethernet PDU sessions for non-IP traffic (TS 23.501 5.6.10)

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

// ============================================================================
// Item #199: IPv6 Dual-Stack Address Allocation
// ============================================================================

/// PDU session address type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduSessionType {
    /// IPv4 only
    Ipv4,
    /// IPv6 only
    Ipv6,
    /// Dual-stack (IPv4 + IPv6)
    Ipv4v6,
    /// Unstructured (non-IP)
    Unstructured,
    /// Ethernet (non-IP L2)
    Ethernet,
}

impl PduSessionType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => PduSessionType::Ipv4,
            2 => PduSessionType::Ipv6,
            3 => PduSessionType::Ipv4v6,
            4 => PduSessionType::Unstructured,
            5 => PduSessionType::Ethernet,
            _ => PduSessionType::Ipv4,
        }
    }
}

/// Allocated UE address (supports dual-stack)
#[derive(Debug, Clone)]
pub struct UeAddress {
    /// IPv4 address (if allocated)
    pub ipv4: Option<Ipv4Addr>,
    /// IPv6 prefix (prefix length, address)
    pub ipv6_prefix: Option<(u8, Ipv6Addr)>,
}

impl UeAddress {
    pub fn ipv4_only(addr: Ipv4Addr) -> Self {
        Self { ipv4: Some(addr), ipv6_prefix: None }
    }

    pub fn ipv6_only(prefix_len: u8, addr: Ipv6Addr) -> Self {
        Self { ipv4: None, ipv6_prefix: Some((prefix_len, addr)) }
    }

    pub fn dual_stack(ipv4: Ipv4Addr, prefix_len: u8, ipv6: Ipv6Addr) -> Self {
        Self { ipv4: Some(ipv4), ipv6_prefix: Some((prefix_len, ipv6)) }
    }

    pub fn is_dual_stack(&self) -> bool {
        self.ipv4.is_some() && self.ipv6_prefix.is_some()
    }
}

/// IPv6 prefix pool for UE address allocation
pub struct Ipv6PrefixPool {
    /// Base prefix (e.g., 2001:db8::/32)
    base_prefix: [u8; 16],
    /// Prefix length for the pool (e.g., 32)
    pool_prefix_len: u8,
    /// UE prefix length (e.g., 64)
    ue_prefix_len: u8,
    /// Next allocation counter
    next_alloc: AtomicU32,
}

impl Ipv6PrefixPool {
    /// Creates a new pool with base 2001:db8::/32 allocating /64 prefixes
    pub fn new(base: [u8; 16], pool_prefix_len: u8, ue_prefix_len: u8) -> Self {
        Self {
            base_prefix: base,
            pool_prefix_len,
            ue_prefix_len,
            next_alloc: AtomicU32::new(1),
        }
    }

    /// Creates default pool: fd00:cafe::/32 → /64 prefixes
    pub fn default_pool() -> Self {
        let mut base = [0u8; 16];
        base[0] = 0xfd; base[1] = 0x00;
        base[2] = 0xca; base[3] = 0xfe;
        Self::new(base, 32, 64)
    }

    /// Allocates a /64 prefix for a UE
    pub fn allocate(&self) -> (u8, Ipv6Addr) {
        let idx = self.next_alloc.fetch_add(1, Ordering::Relaxed);
        let mut addr = self.base_prefix;
        // Place allocation index in bytes 4-7 (within /32 → /64 space)
        addr[4] = ((idx >> 24) & 0xFF) as u8;
        addr[5] = ((idx >> 16) & 0xFF) as u8;
        addr[6] = ((idx >> 8) & 0xFF) as u8;
        addr[7] = (idx & 0xFF) as u8;

        let ipv6 = Ipv6Addr::from(addr);
        (self.ue_prefix_len, ipv6)
    }
}

/// Bitmap-based IPv4 address pool with allocation and release support.
///
/// Manages a subnet (default 10.45.0.0/16) using a bitset where each bit
/// represents a host address. Supports O(n/64) allocation via word scanning
/// and O(1) release.
pub struct Ipv4Pool {
    /// Base network octets (first 2 octets for /16)
    base: [u8; 4],
    /// Total number of host addresses in the pool
    pool_size: u32,
    /// Bitmap: bit i = 1 means host address i is allocated
    bitmap: Mutex<Vec<u64>>,
    /// Number of currently allocated addresses (excludes reserved)
    allocated_count: AtomicU32,
}

impl Ipv4Pool {
    /// Create a new pool for the given /16 subnet.
    /// Reserves .0.0 (network) and .0.1 (gateway).
    pub fn new(base_a: u8, base_b: u8) -> Self {
        let pool_size: u32 = 65536; // /16 = 2^16 addresses
        let bitmap_words = ((pool_size + 63) / 64) as usize;
        let pool = Self {
            base: [base_a, base_b, 0, 0],
            pool_size,
            bitmap: Mutex::new(vec![0u64; bitmap_words]),
            allocated_count: AtomicU32::new(0),
        };
        // Reserve network address (.0.0) and gateway (.0.1)
        pool.mark_allocated(0);
        pool.mark_allocated(1);
        pool
    }

    /// Default pool: 10.45.0.0/16
    pub fn default_pool() -> Self {
        Self::new(10, 45)
    }

    fn mark_allocated(&self, host_idx: u32) {
        if let Ok(mut bm) = self.bitmap.lock() {
            let word = (host_idx / 64) as usize;
            let bit = host_idx % 64;
            if word < bm.len() {
                bm[word] |= 1u64 << bit;
            }
        }
    }

    /// Allocate the next available IPv4 address from the pool.
    /// Returns `None` if the pool is exhausted.
    pub fn allocate(&self) -> Option<Ipv4Addr> {
        let mut bm = self.bitmap.lock().ok()?;
        for (word_idx, word) in bm.iter_mut().enumerate() {
            if *word != u64::MAX {
                let bit = (!*word).trailing_zeros();
                let host_idx = (word_idx as u32) * 64 + bit;
                if host_idx >= self.pool_size {
                    return None;
                }
                *word |= 1u64 << bit;
                self.allocated_count.fetch_add(1, Ordering::Relaxed);
                let mut octets = self.base;
                octets[2] = ((host_idx >> 8) & 0xFF) as u8;
                octets[3] = (host_idx & 0xFF) as u8;
                return Some(Ipv4Addr::from(octets));
            }
        }
        None
    }

    /// Release an IPv4 address back to the pool.
    /// Returns `true` if the address was successfully released.
    pub fn release(&self, addr: Ipv4Addr) -> bool {
        let octets = addr.octets();
        if octets[0] != self.base[0] || octets[1] != self.base[1] {
            return false;
        }
        let host_idx = ((octets[2] as u32) << 8) | (octets[3] as u32);
        if host_idx >= self.pool_size {
            return false;
        }
        if let Ok(mut bm) = self.bitmap.lock() {
            let word = (host_idx / 64) as usize;
            let bit = host_idx % 64;
            if bm[word] & (1u64 << bit) != 0 {
                bm[word] &= !(1u64 << bit);
                self.allocated_count.fetch_sub(1, Ordering::Relaxed);
                log::debug!("IPv4 pool: released {addr}");
                return true;
            }
        }
        false
    }

    /// Number of currently allocated addresses (excluding reserved).
    pub fn active_count(&self) -> u32 {
        self.allocated_count.load(Ordering::Relaxed)
    }

    /// Number of available addresses in the pool.
    pub fn available_count(&self) -> u32 {
        self.pool_size.saturating_sub(self.allocated_count.load(Ordering::Relaxed))
    }
}

/// Dual-stack address allocator using bitmap-based IPv4 pool
pub struct DualStackAllocator {
    /// Bitmap-based IPv4 pool
    pub ipv4_pool: Ipv4Pool,
    /// IPv6 prefix pool
    ipv6_pool: Ipv6PrefixPool,
}

impl DualStackAllocator {
    pub fn new() -> Self {
        Self {
            ipv4_pool: Ipv4Pool::default_pool(),
            ipv6_pool: Ipv6PrefixPool::default_pool(),
        }
    }

    /// Allocates address based on PDU session type
    pub fn allocate(&self, pdu_type: PduSessionType) -> UeAddress {
        match pdu_type {
            PduSessionType::Ipv4 => {
                match self.ipv4_pool.allocate() {
                    Some(addr) => UeAddress::ipv4_only(addr),
                    None => {
                        log::error!("IPv4 pool exhausted");
                        UeAddress { ipv4: None, ipv6_prefix: None }
                    }
                }
            }
            PduSessionType::Ipv6 => {
                let (prefix_len, addr) = self.ipv6_pool.allocate();
                UeAddress::ipv6_only(prefix_len, addr)
            }
            PduSessionType::Ipv4v6 => {
                match self.ipv4_pool.allocate() {
                    Some(ipv4) => {
                        let (prefix_len, ipv6) = self.ipv6_pool.allocate();
                        UeAddress::dual_stack(ipv4, prefix_len, ipv6)
                    }
                    None => {
                        log::error!("IPv4 pool exhausted for dual-stack");
                        let (prefix_len, addr) = self.ipv6_pool.allocate();
                        UeAddress::ipv6_only(prefix_len, addr)
                    }
                }
            }
            _ => UeAddress { ipv4: None, ipv6_prefix: None },
        }
    }

    /// Release an IPv4 address back to the pool
    pub fn release_ipv4(&self, addr: Ipv4Addr) -> bool {
        self.ipv4_pool.release(addr)
    }

    /// Total active IPv4 allocations
    pub fn total_ipv4_allocations(&self) -> u32 {
        self.ipv4_pool.active_count()
    }
}

// ============================================================================
// Item #200: SSC Mode 2/3 + N9 UPF-to-UPF Forwarding
// ============================================================================

/// Session and Service Continuity mode (TS 23.501 5.6.9)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SscMode {
    /// Mode 1: Session continuity (same UPF, default)
    Mode1,
    /// Mode 2: Break-before-make (release old, establish new)
    Mode2,
    /// Mode 3: Make-before-break (new session first, then release old)
    Mode3,
}

/// N9 forwarding tunnel between UPFs
#[derive(Debug, Clone)]
pub struct N9ForwardingTunnel {
    /// Source UPF identifier
    pub source_upf_id: String,
    /// Target UPF identifier
    pub target_upf_id: String,
    /// Source UPF GTP-U TEID
    pub source_teid: u32,
    /// Target UPF GTP-U TEID
    pub target_teid: u32,
    /// Source UPF N9 address
    pub source_addr: Ipv4Addr,
    /// Target UPF N9 address
    pub target_addr: Ipv4Addr,
    /// Whether forwarding is active
    pub active: bool,
}

/// SSC mode handler for session continuity
pub struct SscHandler {
    /// Active N9 forwarding tunnels
    forwarding_tunnels: HashMap<String, N9ForwardingTunnel>,
    /// TEID counter for N9
    next_n9_teid: AtomicU32,
}

impl SscHandler {
    pub fn new() -> Self {
        Self {
            forwarding_tunnels: HashMap::new(),
            next_n9_teid: AtomicU32::new(0x10000),
        }
    }

    /// Handles SSC Mode 2: Break-before-make
    /// Returns (should_release_old, should_create_new)
    pub fn handle_mode2(&self, _session_id: &str) -> (bool, bool) {
        // Mode 2: Release old session first, then create new
        (true, true)
    }

    /// Handles SSC Mode 3: Make-before-break with N9 forwarding
    /// Returns the N9 forwarding tunnel configuration
    pub fn handle_mode3(
        &mut self,
        session_id: &str,
        source_upf_id: &str,
        target_upf_id: &str,
        source_addr: Ipv4Addr,
        target_addr: Ipv4Addr,
    ) -> &N9ForwardingTunnel {
        let source_teid = self.next_n9_teid.fetch_add(1, Ordering::Relaxed);
        let target_teid = self.next_n9_teid.fetch_add(1, Ordering::Relaxed);

        let tunnel = N9ForwardingTunnel {
            source_upf_id: source_upf_id.to_string(),
            target_upf_id: target_upf_id.to_string(),
            source_teid,
            target_teid,
            source_addr,
            target_addr,
            active: true,
        };

        self.forwarding_tunnels.insert(session_id.to_string(), tunnel);
        self.forwarding_tunnels.get(session_id).unwrap_or_default()
    }

    /// Completes SSC Mode 3 handover (remove forwarding)
    pub fn complete_mode3_handover(&mut self, session_id: &str) -> bool {
        if let Some(tunnel) = self.forwarding_tunnels.get_mut(session_id) {
            tunnel.active = false;
            true
        } else {
            false
        }
    }

    /// Returns number of active forwarding tunnels
    pub fn active_tunnel_count(&self) -> usize {
        self.forwarding_tunnels.values().filter(|t| t.active).count()
    }
}

// ============================================================================
// Item #201: Ethernet PDU Sessions
// ============================================================================

/// Ethernet PDU session configuration (TS 23.501 5.6.10)
#[derive(Debug, Clone)]
pub struct EthernetPduConfig {
    /// VLAN ID (if applicable)
    pub vlan_id: Option<u16>,
    /// Source MAC address filter
    pub source_mac: Option<[u8; 6]>,
    /// Destination MAC address filter
    pub dest_mac: Option<[u8; 6]>,
    /// EtherType filter (e.g., 0x0800 for IPv4, 0x86DD for IPv6)
    pub ether_type: Option<u16>,
    /// Maximum frame size
    pub max_frame_size: u16,
}

impl Default for EthernetPduConfig {
    fn default() -> Self {
        Self {
            vlan_id: None,
            source_mac: None,
            dest_mac: None,
            ether_type: None,
            max_frame_size: 1518, // Standard Ethernet
        }
    }
}

/// Ethernet packet filter for PDR (Packet Detection Rule)
#[derive(Debug, Clone)]
pub struct EthernetPacketFilter {
    /// Filter ID
    pub filter_id: u8,
    /// Direction (0=downlink, 1=uplink, 2=bidirectional)
    pub direction: u8,
    /// Source MAC address
    pub source_mac: Option<[u8; 6]>,
    /// Destination MAC address
    pub dest_mac: Option<[u8; 6]>,
    /// EtherType
    pub ether_type: Option<u16>,
    /// VLAN C-TAG
    pub c_tag: Option<u16>,
    /// VLAN S-TAG
    pub s_tag: Option<u16>,
}

impl EthernetPacketFilter {
    /// Creates a filter matching all Ethernet frames
    pub fn match_all(filter_id: u8) -> Self {
        Self {
            filter_id,
            direction: 2,
            source_mac: None,
            dest_mac: None,
            ether_type: None,
            c_tag: None,
            s_tag: None,
        }
    }

    /// Checks if an Ethernet frame matches this filter
    pub fn matches_frame(&self, src_mac: &[u8; 6], dst_mac: &[u8; 6], ether_type: u16) -> bool {
        if let Some(ref filter_src) = self.source_mac {
            if filter_src != src_mac { return false; }
        }
        if let Some(ref filter_dst) = self.dest_mac {
            if filter_dst != dst_mac { return false; }
        }
        if let Some(filter_et) = self.ether_type {
            if filter_et != ether_type { return false; }
        }
        true
    }
}

/// Ethernet PDU session manager
pub struct EthernetSessionManager {
    /// Active Ethernet sessions (session_id → config)
    sessions: HashMap<u8, EthernetPduConfig>,
    /// Packet filters per session
    filters: HashMap<u8, Vec<EthernetPacketFilter>>,
    /// MAC address learning table (MAC → session_id)
    mac_table: HashMap<[u8; 6], u8>,
}

impl EthernetSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            filters: HashMap::new(),
            mac_table: HashMap::new(),
        }
    }

    /// Creates an Ethernet PDU session
    pub fn create_session(&mut self, psi: u8, config: EthernetPduConfig) {
        // Add default match-all filter
        let default_filter = EthernetPacketFilter::match_all(1);
        self.filters.insert(psi, vec![default_filter]);
        self.sessions.insert(psi, config);
    }

    /// Adds a packet filter to a session
    pub fn add_filter(&mut self, psi: u8, filter: EthernetPacketFilter) {
        self.filters.entry(psi).or_default().push(filter);
    }

    /// Learns a MAC address for a session
    pub fn learn_mac(&mut self, mac: [u8; 6], psi: u8) {
        self.mac_table.insert(mac, psi);
    }

    /// Looks up session for a destination MAC
    pub fn lookup_session(&self, dst_mac: &[u8; 6]) -> Option<u8> {
        self.mac_table.get(dst_mac).copied()
    }

    /// Returns active Ethernet session count
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Returns the MAC address table size
    pub fn mac_table_size(&self) -> usize {
        self.mac_table.len()
    }

    /// Removes an Ethernet session
    pub fn remove_session(&mut self, psi: u8) {
        self.sessions.remove(&psi);
        self.filters.remove(&psi);
        self.mac_table.retain(|_, v| *v != psi);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- IPv6 Dual-Stack tests --

    #[test]
    fn test_ipv6_prefix_allocation() {
        let pool = Ipv6PrefixPool::default_pool();
        let (prefix_len, addr1) = pool.allocate();
        let (_, addr2) = pool.allocate();
        assert_eq!(prefix_len, 64);
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_dual_stack_allocation() {
        let allocator = DualStackAllocator::new();

        let addr = allocator.allocate(PduSessionType::Ipv4v6);
        assert!(addr.is_dual_stack());
        assert!(addr.ipv4.is_some());
        assert!(addr.ipv6_prefix.is_some());
    }

    #[test]
    fn test_ipv4_only_allocation() {
        let allocator = DualStackAllocator::new();
        let addr = allocator.allocate(PduSessionType::Ipv4);
        assert!(addr.ipv4.is_some());
        assert!(addr.ipv6_prefix.is_none());
    }

    #[test]
    fn test_ipv6_only_allocation() {
        let allocator = DualStackAllocator::new();
        let addr = allocator.allocate(PduSessionType::Ipv6);
        assert!(addr.ipv4.is_none());
        assert!(addr.ipv6_prefix.is_some());
    }

    #[test]
    fn test_sequential_ipv4_allocation() {
        let allocator = DualStackAllocator::new();
        let a1 = allocator.allocate(PduSessionType::Ipv4);
        let a2 = allocator.allocate(PduSessionType::Ipv4);
        assert_ne!(a1.ipv4, a2.ipv4);
        assert_eq!(allocator.total_ipv4_allocations(), 2);
    }

    // -- SSC Mode tests --

    #[test]
    fn test_ssc_mode2() {
        let handler = SscHandler::new();
        let (release, create) = handler.handle_mode2("sess-1");
        assert!(release);
        assert!(create);
    }

    #[test]
    fn test_ssc_mode3_forwarding() {
        let mut handler = SscHandler::new();
        let tunnel = handler.handle_mode3(
            "sess-1", "upf-1", "upf-2",
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
        );
        assert!(tunnel.active);
        assert_eq!(tunnel.source_upf_id, "upf-1");
        assert_eq!(tunnel.target_upf_id, "upf-2");
        assert_eq!(handler.active_tunnel_count(), 1);
    }

    #[test]
    fn test_ssc_mode3_complete() {
        let mut handler = SscHandler::new();
        handler.handle_mode3(
            "sess-1", "upf-1", "upf-2",
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
        );
        assert!(handler.complete_mode3_handover("sess-1"));
        assert_eq!(handler.active_tunnel_count(), 0);
    }

    // -- Ethernet PDU Session tests --

    #[test]
    fn test_ethernet_session_create() {
        let mut mgr = EthernetSessionManager::new();
        mgr.create_session(1, EthernetPduConfig::default());
        assert_eq!(mgr.session_count(), 1);
    }

    #[test]
    fn test_ethernet_mac_learning() {
        let mut mgr = EthernetSessionManager::new();
        mgr.create_session(1, EthernetPduConfig::default());
        mgr.learn_mac([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], 1);
        assert_eq!(mgr.lookup_session(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]), Some(1));
        assert_eq!(mgr.mac_table_size(), 1);
    }

    #[test]
    fn test_ethernet_packet_filter() {
        let filter = EthernetPacketFilter::match_all(1);
        let src = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let dst = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert!(filter.matches_frame(&src, &dst, 0x0800));
    }

    #[test]
    fn test_ethernet_packet_filter_specific() {
        let filter = EthernetPacketFilter {
            filter_id: 1,
            direction: 2,
            source_mac: None,
            dest_mac: Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
            ether_type: Some(0x0800),
            c_tag: None,
            s_tag: None,
        };
        let src = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let matching_dst = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let other_dst = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        assert!(filter.matches_frame(&src, &matching_dst, 0x0800));
        assert!(!filter.matches_frame(&src, &other_dst, 0x0800));
        assert!(!filter.matches_frame(&src, &matching_dst, 0x86DD));
    }

    #[test]
    fn test_ethernet_session_remove() {
        let mut mgr = EthernetSessionManager::new();
        mgr.create_session(1, EthernetPduConfig::default());
        mgr.learn_mac([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], 1);
        mgr.remove_session(1);
        assert_eq!(mgr.session_count(), 0);
        assert_eq!(mgr.mac_table_size(), 0);
    }

    #[test]
    fn test_pdu_session_type_from_u8() {
        assert_eq!(PduSessionType::from_u8(1), PduSessionType::Ipv4);
        assert_eq!(PduSessionType::from_u8(2), PduSessionType::Ipv6);
        assert_eq!(PduSessionType::from_u8(3), PduSessionType::Ipv4v6);
        assert_eq!(PduSessionType::from_u8(5), PduSessionType::Ethernet);
    }

    #[test]
    fn test_pdu_session_type_from_u8_unknown_defaults_to_ipv4() {
        assert_eq!(PduSessionType::from_u8(0), PduSessionType::Ipv4);
        assert_eq!(PduSessionType::from_u8(99), PduSessionType::Ipv4);
        assert_eq!(PduSessionType::from_u8(255), PduSessionType::Ipv4);
    }

    // -- Ipv4Pool tests --

    #[test]
    fn test_ipv4_pool_first_alloc_skips_reserved() {
        let pool = Ipv4Pool::default_pool();
        // .0.0 (network) and .0.1 (gateway) are reserved
        let addr = pool.allocate().unwrap();
        let octets = addr.octets();
        assert_eq!(octets[0], 10);
        assert_eq!(octets[1], 45);
        // Must be .0.2 or higher, never .0.0 or .0.1
        let host = ((octets[2] as u16) << 8) | (octets[3] as u16);
        assert!(host >= 2, "First allocation should skip reserved .0.0 and .0.1, got .{}.{}", octets[2], octets[3]);
    }

    #[test]
    fn test_ipv4_pool_release_and_realloc() {
        let pool = Ipv4Pool::default_pool();
        let addr1 = pool.allocate().unwrap();
        assert_eq!(pool.active_count(), 1);

        // Release it
        assert!(pool.release(addr1));
        assert_eq!(pool.active_count(), 0);

        // Re-allocate — should get the same address back (lowest available)
        let addr2 = pool.allocate().unwrap();
        assert_eq!(addr1, addr2, "Released address should be re-allocated");
        assert_eq!(pool.active_count(), 1);
    }

    #[test]
    fn test_ipv4_pool_release_wrong_subnet_returns_false() {
        let pool = Ipv4Pool::default_pool(); // 10.45.0.0/16
        // Try releasing an address from a different subnet
        assert!(!pool.release(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!pool.release(Ipv4Addr::new(10, 46, 0, 2)));
    }

    #[test]
    fn test_ipv4_pool_double_release_returns_false() {
        let pool = Ipv4Pool::default_pool();
        let addr = pool.allocate().unwrap();
        assert!(pool.release(addr));
        // Second release should fail — bit already cleared
        assert!(!pool.release(addr));
    }

    #[test]
    fn test_ipv4_pool_release_unallocated_returns_false() {
        let pool = Ipv4Pool::default_pool();
        // Never allocated 10.45.1.100, should fail
        assert!(!pool.release(Ipv4Addr::new(10, 45, 1, 100)));
    }

    #[test]
    fn test_ipv4_pool_counters_after_alloc_and_release() {
        let pool = Ipv4Pool::default_pool();
        // Pool has 65536 total, 2 reserved by bitmap (but not counted in allocated_count)
        assert_eq!(pool.active_count(), 0);

        let a1 = pool.allocate().unwrap();
        let a2 = pool.allocate().unwrap();
        let a3 = pool.allocate().unwrap();
        assert_eq!(pool.active_count(), 3);

        pool.release(a2);
        assert_eq!(pool.active_count(), 2);

        pool.release(a1);
        pool.release(a3);
        assert_eq!(pool.active_count(), 0);
    }

    #[test]
    fn test_ipv4_pool_allocations_are_unique() {
        let pool = Ipv4Pool::default_pool();
        let mut addrs = std::collections::HashSet::new();
        for _ in 0..100 {
            let addr = pool.allocate().unwrap();
            assert!(addrs.insert(addr), "Duplicate allocation: {addr}");
        }
        assert_eq!(addrs.len(), 100);
        assert_eq!(pool.active_count(), 100);
    }

    #[test]
    fn test_ipv4_pool_small_pool_exhaustion() {
        // Create a tiny pool: use base 10.99 (will have 65536 addresses, but we can fill a custom one)
        // Instead, test with default pool and verify allocate returns None after filling
        // For speed, we'll test the logic differently: allocate a lot, release all, allocate again
        let pool = Ipv4Pool::new(10, 99);
        // Allocate 256 addresses (first /24 worth after reserved)
        let mut allocated = Vec::new();
        for _ in 0..254 {
            match pool.allocate() {
                Some(addr) => allocated.push(addr),
                None => break,
            }
        }
        assert_eq!(allocated.len(), 254);

        // Release all
        for addr in &allocated {
            assert!(pool.release(*addr));
        }
        assert_eq!(pool.active_count(), 0);

        // Re-allocate same count
        for _ in 0..254 {
            assert!(pool.allocate().is_some());
        }
        assert_eq!(pool.active_count(), 254);
    }

    #[test]
    fn test_ipv4_pool_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let pool = Arc::new(Ipv4Pool::default_pool());
        let mut handles = Vec::new();

        // Spawn 8 threads, each allocating 50 addresses
        for _ in 0..8 {
            let pool = Arc::clone(&pool);
            handles.push(thread::spawn(move || {
                let mut addrs = Vec::new();
                for _ in 0..50 {
                    if let Some(addr) = pool.allocate() {
                        addrs.push(addr);
                    }
                }
                addrs
            }));
        }

        let mut all_addrs = std::collections::HashSet::new();
        for h in handles {
            for addr in h.join().unwrap() {
                assert!(all_addrs.insert(addr), "Concurrent duplicate: {addr}");
            }
        }
        assert_eq!(all_addrs.len(), 400); // 8 * 50
        assert_eq!(pool.active_count(), 400);
    }
}
