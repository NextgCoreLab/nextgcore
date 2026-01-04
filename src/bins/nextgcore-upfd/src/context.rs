//! UPF Context Management
//!
//! Port of src/upf/context.c, src/upf/context.h - UPF context with session management,
//! hash tables for SEID/IP lookups, route tries, and URR accounting

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::RwLock;
use std::time::Instant;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of URRs per session
pub const OGS_MAX_NUM_OF_URR: usize = 8;
/// Maximum number of framed routes in PDI
pub const OGS_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI: usize = 8;

// ============================================================================
// IP Subnet
// ============================================================================

/// IP subnet for framed routes
#[derive(Debug, Clone, Default)]
pub struct IpSubnet {
    /// Address family (AF_INET or AF_INET6)
    pub family: u16,
    /// Subnet address (4 u32s for IPv6, 1 for IPv4)
    pub sub: [u32; 4],
    /// Subnet mask
    pub mask: [u32; 4],
}

impl IpSubnet {
    /// Create IPv4 subnet
    pub fn new_ipv4(addr: u32, prefix_len: u8) -> Self {
        let mask = if prefix_len >= 32 {
            0xFFFFFFFF
        } else {
            !((1u32 << (32 - prefix_len)) - 1)
        };
        Self {
            family: libc::AF_INET as u16,
            sub: [addr & mask, 0, 0, 0],
            mask: [mask, 0, 0, 0],
        }
    }

    /// Create IPv6 subnet
    pub fn new_ipv6(addr: [u32; 4], prefix_len: u8) -> Self {
        let mut mask = [0u32; 4];
        let mut remaining = prefix_len as i32;
        for i in 0..4 {
            if remaining >= 32 {
                mask[i] = 0xFFFFFFFF;
                remaining -= 32;
            } else if remaining > 0 {
                mask[i] = !((1u32 << (32 - remaining)) - 1);
                remaining = 0;
            }
        }
        Self {
            family: libc::AF_INET6 as u16,
            sub: [
                addr[0] & mask[0],
                addr[1] & mask[1],
                addr[2] & mask[2],
                addr[3] & mask[3],
            ],
            mask,
        }
    }

    /// Check if address matches this subnet
    pub fn matches(&self, addr: &[u32; 4]) -> bool {
        if self.family == 0 {
            return false;
        }
        if self.family == libc::AF_INET as u16 {
            self.sub[0] == (addr[0] & self.mask[0])
        } else {
            self.sub[0] == (addr[0] & self.mask[0])
                && self.sub[1] == (addr[1] & self.mask[1])
                && self.sub[2] == (addr[2] & self.mask[2])
                && self.sub[3] == (addr[3] & self.mask[3])
        }
    }
}

// ============================================================================
// UE IP Address
// ============================================================================

/// UE IP address structure
#[derive(Debug, Clone, Default)]
pub struct UeIp {
    /// IPv4 address (network byte order)
    pub addr: [u32; 4],
    /// Subnet reference (for IPv4/IPv6 pool management)
    pub subnet_id: Option<u64>,
}

impl UeIp {
    /// Create from IPv4 address
    pub fn from_ipv4(addr: Ipv4Addr) -> Self {
        Self {
            addr: [u32::from_be_bytes(addr.octets()), 0, 0, 0],
            subnet_id: None,
        }
    }

    /// Create from IPv6 address
    pub fn from_ipv6(addr: Ipv6Addr) -> Self {
        let octets = addr.octets();
        Self {
            addr: [
                u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]),
                u32::from_be_bytes([octets[4], octets[5], octets[6], octets[7]]),
                u32::from_be_bytes([octets[8], octets[9], octets[10], octets[11]]),
                u32::from_be_bytes([octets[12], octets[13], octets[14], octets[15]]),
            ],
            subnet_id: None,
        }
    }
}

// ============================================================================
// Route Trie Node
// ============================================================================

/// Trie node for IP framed routes mapping to sessions
#[derive(Debug, Default)]
pub struct RouteTrie {
    /// Left child (0 bit)
    left: Option<Box<RouteTrie>>,
    /// Right child (1 bit)
    right: Option<Box<RouteTrie>>,
    /// Session ID if this node represents a route endpoint
    sess_id: Option<u64>,
}

impl RouteTrie {
    /// Create a new empty trie
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a route into the trie
    pub fn insert(&mut self, addr: &[u32; 4], prefix_len: u8, sess_id: u64, is_ipv6: bool) {
        let total_bits = if is_ipv6 { 128 } else { 32 };
        let bits_to_use = prefix_len.min(total_bits);
        
        let mut node = self;
        for bit_idx in 0..bits_to_use {
            let word_idx = (bit_idx / 32) as usize;
            let bit_pos = 31 - (bit_idx % 32);
            let bit = (addr[word_idx] >> bit_pos) & 1;
            
            if bit == 0 {
                if node.left.is_none() {
                    node.left = Some(Box::new(RouteTrie::new()));
                }
                node = node.left.as_mut().unwrap();
            } else {
                if node.right.is_none() {
                    node.right = Some(Box::new(RouteTrie::new()));
                }
                node = node.right.as_mut().unwrap();
            }
        }
        node.sess_id = Some(sess_id);
    }

    /// Remove a route from the trie
    pub fn remove(&mut self, addr: &[u32; 4], prefix_len: u8, is_ipv6: bool) -> bool {
        let total_bits = if is_ipv6 { 128 } else { 32 };
        let bits_to_use = prefix_len.min(total_bits);
        
        let mut node = self;
        for bit_idx in 0..bits_to_use {
            let word_idx = (bit_idx / 32) as usize;
            let bit_pos = 31 - (bit_idx % 32);
            let bit = (addr[word_idx] >> bit_pos) & 1;
            
            let next = if bit == 0 {
                node.left.as_mut()
            } else {
                node.right.as_mut()
            };
            
            match next {
                Some(n) => node = n,
                None => return false,
            }
        }
        
        if node.sess_id.is_some() {
            node.sess_id = None;
            true
        } else {
            false
        }
    }

    /// Find session by IP address (longest prefix match)
    pub fn find(&self, addr: &[u32; 4], is_ipv6: bool) -> Option<u64> {
        let total_bits = if is_ipv6 { 128 } else { 32 };
        
        let mut node = self;
        let mut last_match = node.sess_id;
        
        for bit_idx in 0..total_bits {
            let word_idx = (bit_idx / 32) as usize;
            let bit_pos = 31 - (bit_idx % 32);
            let bit = (addr[word_idx] >> bit_pos) & 1;
            
            let next = if bit == 0 {
                node.left.as_ref()
            } else {
                node.right.as_ref()
            };
            
            match next {
                Some(n) => {
                    node = n;
                    if node.sess_id.is_some() {
                        last_match = node.sess_id;
                    }
                }
                None => break,
            }
        }
        
        last_match
    }
}

// ============================================================================
// URR Accounting
// ============================================================================

/// URR (Usage Reporting Rule) accounting data
/// Port of upf_sess_urr_acc_t from context.h
#[derive(Debug, Clone)]
pub struct UrrAccounting {
    /// Reporting enabled
    pub reporting_enabled: bool,
    /// Report sequence number
    pub report_seqn: u32,
    /// Total octets
    pub total_octets: u64,
    /// Uplink octets
    pub ul_octets: u64,
    /// Downlink octets
    pub dl_octets: u64,
    /// Total packets
    pub total_pkts: u64,
    /// Uplink packets
    pub ul_pkts: u64,
    /// Downlink packets
    pub dl_pkts: u64,
    /// Time of first packet
    pub time_of_first_packet: Option<Instant>,
    /// Time of last packet
    pub time_of_last_packet: Option<Instant>,
    /// Time when timers started
    pub time_start: Option<Instant>,
    /// Last report snapshot
    pub last_report: UrrAccountingSnapshot,
}

/// Snapshot of URR accounting for last report
#[derive(Debug, Clone, Default)]
pub struct UrrAccountingSnapshot {
    pub total_octets: u64,
    pub ul_octets: u64,
    pub dl_octets: u64,
    pub total_pkts: u64,
    pub ul_pkts: u64,
    pub dl_pkts: u64,
    pub timestamp: Option<Instant>,
}

impl Default for UrrAccounting {
    fn default() -> Self {
        Self {
            reporting_enabled: false,
            report_seqn: 0,
            total_octets: 0,
            ul_octets: 0,
            dl_octets: 0,
            total_pkts: 0,
            ul_pkts: 0,
            dl_pkts: 0,
            time_of_first_packet: None,
            time_of_last_packet: None,
            time_start: None,
            last_report: UrrAccountingSnapshot::default(),
        }
    }
}

impl UrrAccounting {
    /// Add traffic to accounting
    pub fn add(&mut self, size: usize, is_uplink: bool) {
        let now = Instant::now();
        
        if self.time_of_first_packet.is_none() {
            self.time_of_first_packet = Some(now);
        }
        self.time_of_last_packet = Some(now);
        
        self.total_octets += size as u64;
        self.total_pkts += 1;
        
        if is_uplink {
            self.ul_octets += size as u64;
            self.ul_pkts += 1;
        } else {
            self.dl_octets += size as u64;
            self.dl_pkts += 1;
        }
    }

    /// Take a snapshot for reporting
    pub fn snapshot(&mut self) {
        self.last_report = UrrAccountingSnapshot {
            total_octets: self.total_octets,
            ul_octets: self.ul_octets,
            dl_octets: self.dl_octets,
            total_pkts: self.total_pkts,
            ul_pkts: self.ul_pkts,
            dl_pkts: self.dl_pkts,
            timestamp: Some(Instant::now()),
        };
        self.report_seqn += 1;
    }

    /// Get delta since last report
    pub fn delta_since_last_report(&self) -> (u64, u64, u64) {
        (
            self.total_octets - self.last_report.total_octets,
            self.ul_octets - self.last_report.ul_octets,
            self.dl_octets - self.last_report.dl_octets,
        )
    }
}


// ============================================================================
// PFCP Session (simplified)
// ============================================================================

/// PFCP session data (simplified from ogs_pfcp_sess_t)
#[derive(Debug, Clone, Default)]
pub struct PfcpSess {
    /// PDR list IDs
    pub pdr_ids: Vec<u64>,
    /// FAR list IDs
    pub far_ids: Vec<u64>,
    /// URR list IDs
    pub urr_ids: Vec<u64>,
    /// QER list IDs
    pub qer_ids: Vec<u64>,
    /// BAR list IDs
    pub bar_ids: Vec<u64>,
}

// ============================================================================
// F-SEID (Fully qualified SEID)
// ============================================================================

/// F-SEID structure
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct FSeid {
    /// SEID value
    pub seid: u64,
    /// IPv4 address (if present)
    pub ipv4: Option<Ipv4Addr>,
    /// IPv6 address (if present)
    pub ipv6: Option<Ipv6Addr>,
}

impl FSeid {
    /// Create F-SEID with IPv4
    pub fn with_ipv4(seid: u64, ipv4: Ipv4Addr) -> Self {
        Self {
            seid,
            ipv4: Some(ipv4),
            ipv6: None,
        }
    }

    /// Create F-SEID with IPv6
    pub fn with_ipv6(seid: u64, ipv6: Ipv6Addr) -> Self {
        Self {
            seid,
            ipv4: None,
            ipv6: Some(ipv6),
        }
    }
}

// ============================================================================
// UPF Session
// ============================================================================

/// UPF Session context
/// Port of upf_sess_t from context.h
#[derive(Debug, Clone)]
pub struct UpfSess {
    /// Session ID (pool ID)
    pub id: u64,
    /// PFCP session data
    pub pfcp: PfcpSess,
    /// UPF N4 SEID (derived from node)
    pub upf_n4_seid: u64,
    /// SMF N4 F-SEID (received from peer)
    pub smf_n4_f_seid: FSeid,
    /// IPv4 UE address
    pub ipv4: Option<UeIp>,
    /// IPv6 UE address
    pub ipv6: Option<UeIp>,
    /// IPv4 framed routes
    pub ipv4_framed_routes: Option<Vec<IpSubnet>>,
    /// IPv6 framed routes
    pub ipv6_framed_routes: Option<Vec<IpSubnet>>,
    /// Gx Session ID
    pub gx_sid: Option<String>,
    /// PFCP node ID
    pub pfcp_node_id: Option<u64>,
    /// URR accounting data
    pub urr_acc: [UrrAccounting; OGS_MAX_NUM_OF_URR],
    /// APN/DNN
    pub apn_dnn: Option<String>,
}

impl UpfSess {
    /// Create a new UPF session
    pub fn new(id: u64, upf_n4_seid: u64) -> Self {
        Self {
            id,
            pfcp: PfcpSess::default(),
            upf_n4_seid,
            smf_n4_f_seid: FSeid::default(),
            ipv4: None,
            ipv6: None,
            ipv4_framed_routes: None,
            ipv6_framed_routes: None,
            gx_sid: None,
            pfcp_node_id: None,
            urr_acc: Default::default(),
            apn_dnn: None,
        }
    }

    /// Set UE IPv4 address
    pub fn set_ipv4(&mut self, addr: Ipv4Addr) {
        self.ipv4 = Some(UeIp::from_ipv4(addr));
    }

    /// Set UE IPv6 address
    pub fn set_ipv6(&mut self, addr: Ipv6Addr) {
        self.ipv6 = Some(UeIp::from_ipv6(addr));
    }

    /// Add IPv4 framed route
    pub fn add_ipv4_framed_route(&mut self, subnet: IpSubnet) {
        if self.ipv4_framed_routes.is_none() {
            self.ipv4_framed_routes = Some(Vec::new());
        }
        if let Some(routes) = &mut self.ipv4_framed_routes {
            if routes.len() < OGS_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI {
                routes.push(subnet);
            }
        }
    }

    /// Add IPv6 framed route
    pub fn add_ipv6_framed_route(&mut self, subnet: IpSubnet) {
        if self.ipv6_framed_routes.is_none() {
            self.ipv6_framed_routes = Some(Vec::new());
        }
        if let Some(routes) = &mut self.ipv6_framed_routes {
            if routes.len() < OGS_MAX_NUM_OF_FRAMED_ROUTES_IN_PDI {
                routes.push(subnet);
            }
        }
    }

    /// Check if address matches framed routes
    pub fn check_framed_routes(&self, addr: &[u32; 4], is_ipv6: bool) -> bool {
        let routes = if is_ipv6 {
            &self.ipv6_framed_routes
        } else {
            &self.ipv4_framed_routes
        };

        if let Some(routes) = routes {
            for route in routes {
                if route.matches(addr) {
                    return true;
                }
            }
        }
        false
    }

    /// Add URR accounting
    pub fn urr_acc_add(&mut self, urr_idx: usize, size: usize, is_uplink: bool) {
        if urr_idx < OGS_MAX_NUM_OF_URR {
            self.urr_acc[urr_idx].add(size, is_uplink);
        }
    }

    /// Take URR accounting snapshot
    pub fn urr_acc_snapshot(&mut self, urr_idx: usize) {
        if urr_idx < OGS_MAX_NUM_OF_URR {
            self.urr_acc[urr_idx].snapshot();
        }
    }
}

impl Default for UpfSess {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

// ============================================================================
// UPF Context
// ============================================================================

/// UPF Context - main context structure for UPF
/// Port of upf_context_t from context.h
pub struct UpfContext {
    // Hash tables
    /// UPF N4 SEID -> Session ID hash
    upf_n4_seid_hash: RwLock<HashMap<u64, u64>>,
    /// SMF N4 SEID -> Session ID hash
    smf_n4_seid_hash: RwLock<HashMap<u64, u64>>,
    /// SMF N4 F-SEID -> Session ID hash
    smf_n4_f_seid_hash: RwLock<HashMap<FSeid, u64>>,
    /// IPv4 address -> Session ID hash
    ipv4_hash: RwLock<HashMap<u32, u64>>,
    /// IPv6 address -> Session ID hash (using first 64 bits as key)
    ipv6_hash: RwLock<HashMap<[u32; 2], u64>>,

    // Route tries
    /// IPv4 framed routes trie
    ipv4_framed_routes: RwLock<RouteTrie>,
    /// IPv6 framed routes trie
    ipv6_framed_routes: RwLock<RouteTrie>,

    // Session list
    /// Session list (by pool ID)
    sess_list: RwLock<HashMap<u64, UpfSess>>,

    // ID generators
    /// Next session ID
    next_sess_id: AtomicUsize,
    /// N4 SEID generator
    n4_seid_generator: AtomicU64,

    // Pool limits
    /// Maximum number of sessions
    max_num_of_sess: usize,

    /// Context initialized flag
    initialized: AtomicBool,
}

impl UpfContext {
    /// Create a new UPF context
    pub fn new() -> Self {
        Self {
            upf_n4_seid_hash: RwLock::new(HashMap::new()),
            smf_n4_seid_hash: RwLock::new(HashMap::new()),
            smf_n4_f_seid_hash: RwLock::new(HashMap::new()),
            ipv4_hash: RwLock::new(HashMap::new()),
            ipv6_hash: RwLock::new(HashMap::new()),
            ipv4_framed_routes: RwLock::new(RouteTrie::new()),
            ipv6_framed_routes: RwLock::new(RouteTrie::new()),
            sess_list: RwLock::new(HashMap::new()),
            next_sess_id: AtomicUsize::new(1),
            n4_seid_generator: AtomicU64::new(1),
            max_num_of_sess: 0,
            initialized: AtomicBool::new(false),
        }
    }

    /// Initialize the UPF context
    pub fn init(&mut self, max_sess: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }

        self.max_num_of_sess = max_sess;
        self.initialized.store(true, Ordering::SeqCst);

        log::info!("UPF context initialized with max {} sessions", self.max_num_of_sess);
    }

    /// Finalize the UPF context
    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }

        self.sess_remove_all();
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("UPF context finalized");
    }

    /// Check if context is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Generate next N4 SEID
    fn next_n4_seid(&self) -> u64 {
        self.n4_seid_generator.fetch_add(1, Ordering::SeqCst)
    }

    // ========================================================================
    // Session Management
    // ========================================================================

    /// Add a new session by F-SEID
    pub fn sess_add(&self, f_seid: &FSeid) -> Option<UpfSess> {
        let mut sess_list = self.sess_list.write().ok()?;
        let mut smf_n4_f_seid_hash = self.smf_n4_f_seid_hash.write().ok()?;
        let mut smf_n4_seid_hash = self.smf_n4_seid_hash.write().ok()?;
        let mut upf_n4_seid_hash = self.upf_n4_seid_hash.write().ok()?;

        if sess_list.len() >= self.max_num_of_sess && self.max_num_of_sess > 0 {
            log::error!("Maximum number of sessions [{}] reached", self.max_num_of_sess);
            return None;
        }

        let id = self.next_sess_id.fetch_add(1, Ordering::SeqCst) as u64;
        let upf_n4_seid = self.next_n4_seid();
        
        let mut sess = UpfSess::new(id, upf_n4_seid);
        sess.smf_n4_f_seid = f_seid.clone();

        // Add to hash tables
        smf_n4_f_seid_hash.insert(f_seid.clone(), id);
        smf_n4_seid_hash.insert(f_seid.seid, id);
        upf_n4_seid_hash.insert(upf_n4_seid, id);
        
        sess_list.insert(id, sess.clone());

        log::info!(
            "[Added] UPF Session (id={}, upf_seid={}, smf_seid={})",
            id, upf_n4_seid, f_seid.seid
        );
        Some(sess)
    }

    /// Remove a session by ID
    pub fn sess_remove(&self, id: u64) -> Option<UpfSess> {
        let mut sess_list = self.sess_list.write().ok()?;
        let mut smf_n4_f_seid_hash = self.smf_n4_f_seid_hash.write().ok()?;
        let mut smf_n4_seid_hash = self.smf_n4_seid_hash.write().ok()?;
        let mut upf_n4_seid_hash = self.upf_n4_seid_hash.write().ok()?;
        let mut ipv4_hash = self.ipv4_hash.write().ok()?;
        let mut ipv6_hash = self.ipv6_hash.write().ok()?;

        if let Some(sess) = sess_list.remove(&id) {
            // Remove from hash tables
            smf_n4_f_seid_hash.remove(&sess.smf_n4_f_seid);
            smf_n4_seid_hash.remove(&sess.smf_n4_f_seid.seid);
            upf_n4_seid_hash.remove(&sess.upf_n4_seid);

            // Remove IP addresses from hash
            if let Some(ref ipv4) = sess.ipv4 {
                ipv4_hash.remove(&ipv4.addr[0]);
            }
            if let Some(ref ipv6) = sess.ipv6 {
                ipv6_hash.remove(&[ipv6.addr[0], ipv6.addr[1]]);
            }

            // Remove framed routes from tries
            if let Some(ref routes) = sess.ipv4_framed_routes {
                if let Ok(mut trie) = self.ipv4_framed_routes.write() {
                    for route in routes {
                        let prefix_len = route.mask[0].leading_ones() as u8;
                        trie.remove(&route.sub, prefix_len, false);
                    }
                }
            }
            if let Some(ref routes) = sess.ipv6_framed_routes {
                if let Ok(mut trie) = self.ipv6_framed_routes.write() {
                    for route in routes {
                        let prefix_len = (route.mask[0].leading_ones()
                            + route.mask[1].leading_ones()
                            + route.mask[2].leading_ones()
                            + route.mask[3].leading_ones()) as u8;
                        trie.remove(&route.sub, prefix_len, true);
                    }
                }
            }

            log::info!("[Removed] UPF Session (id={})", id);
            return Some(sess);
        }
        None
    }

    /// Remove all sessions
    pub fn sess_remove_all(&self) {
        if let Ok(sess_list) = self.sess_list.read() {
            let ids: Vec<u64> = sess_list.keys().copied().collect();
            drop(sess_list);
            for id in ids {
                self.sess_remove(id);
            }
        }
        log::info!("All UPF sessions removed");
    }

    /// Find session by SMF N4 SEID
    pub fn sess_find_by_smf_n4_seid(&self, seid: u64) -> Option<UpfSess> {
        let smf_n4_seid_hash = self.smf_n4_seid_hash.read().ok()?;
        let sess_id = smf_n4_seid_hash.get(&seid)?;
        let sess_list = self.sess_list.read().ok()?;
        sess_list.get(sess_id).cloned()
    }

    /// Find session by SMF N4 F-SEID
    pub fn sess_find_by_smf_n4_f_seid(&self, f_seid: &FSeid) -> Option<UpfSess> {
        let smf_n4_f_seid_hash = self.smf_n4_f_seid_hash.read().ok()?;
        let sess_id = smf_n4_f_seid_hash.get(f_seid)?;
        let sess_list = self.sess_list.read().ok()?;
        sess_list.get(sess_id).cloned()
    }

    /// Find session by UPF N4 SEID
    pub fn sess_find_by_upf_n4_seid(&self, seid: u64) -> Option<UpfSess> {
        let upf_n4_seid_hash = self.upf_n4_seid_hash.read().ok()?;
        let sess_id = upf_n4_seid_hash.get(&seid)?;
        let sess_list = self.sess_list.read().ok()?;
        sess_list.get(sess_id).cloned()
    }

    /// Find session by IPv4 address
    pub fn sess_find_by_ipv4(&self, addr: u32) -> Option<UpfSess> {
        // First check direct IP hash
        if let Ok(ipv4_hash) = self.ipv4_hash.read() {
            if let Some(sess_id) = ipv4_hash.get(&addr) {
                if let Ok(sess_list) = self.sess_list.read() {
                    if let Some(sess) = sess_list.get(sess_id) {
                        return Some(sess.clone());
                    }
                }
            }
        }

        // Then check framed routes trie
        if let Ok(trie) = self.ipv4_framed_routes.read() {
            if let Some(sess_id) = trie.find(&[addr, 0, 0, 0], false) {
                if let Ok(sess_list) = self.sess_list.read() {
                    if let Some(sess) = sess_list.get(&sess_id) {
                        return Some(sess.clone());
                    }
                }
            }
        }

        None
    }

    /// Find session by IPv6 address
    pub fn sess_find_by_ipv6(&self, addr: &[u32; 4]) -> Option<UpfSess> {
        // First check direct IP hash (using first 64 bits)
        if let Ok(ipv6_hash) = self.ipv6_hash.read() {
            if let Some(sess_id) = ipv6_hash.get(&[addr[0], addr[1]]) {
                if let Ok(sess_list) = self.sess_list.read() {
                    if let Some(sess) = sess_list.get(sess_id) {
                        return Some(sess.clone());
                    }
                }
            }
        }

        // Then check framed routes trie
        if let Ok(trie) = self.ipv6_framed_routes.read() {
            if let Some(sess_id) = trie.find(addr, true) {
                if let Ok(sess_list) = self.sess_list.read() {
                    if let Some(sess) = sess_list.get(&sess_id) {
                        return Some(sess.clone());
                    }
                }
            }
        }

        None
    }

    /// Find session by ID
    pub fn sess_find_by_id(&self, id: u64) -> Option<UpfSess> {
        let sess_list = self.sess_list.read().ok()?;
        sess_list.get(&id).cloned()
    }

    /// Set UE IP for session
    pub fn sess_set_ue_ip(&self, sess_id: u64, ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>) -> bool {
        let mut sess_list = self.sess_list.write().ok().unwrap();
        let mut ipv4_hash = self.ipv4_hash.write().ok().unwrap();
        let mut ipv6_hash = self.ipv6_hash.write().ok().unwrap();

        if let Some(sess) = sess_list.get_mut(&sess_id) {
            if let Some(addr) = ipv4 {
                let addr_u32 = u32::from_be_bytes(addr.octets());
                sess.set_ipv4(addr);
                ipv4_hash.insert(addr_u32, sess_id);
            }
            if let Some(addr) = ipv6 {
                let octets = addr.octets();
                let addr_key = [
                    u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]),
                    u32::from_be_bytes([octets[4], octets[5], octets[6], octets[7]]),
                ];
                sess.set_ipv6(addr);
                ipv6_hash.insert(addr_key, sess_id);
            }
            return true;
        }
        false
    }

    /// Add framed route for session
    pub fn sess_add_framed_route(&self, sess_id: u64, subnet: IpSubnet, is_ipv6: bool) -> bool {
        let mut sess_list = self.sess_list.write().ok().unwrap();
        
        if let Some(sess) = sess_list.get_mut(&sess_id) {
            let prefix_len = if is_ipv6 {
                (subnet.mask[0].leading_ones()
                    + subnet.mask[1].leading_ones()
                    + subnet.mask[2].leading_ones()
                    + subnet.mask[3].leading_ones()) as u8
            } else {
                subnet.mask[0].leading_ones() as u8
            };

            // Add to trie
            if is_ipv6 {
                if let Ok(mut trie) = self.ipv6_framed_routes.write() {
                    trie.insert(&subnet.sub, prefix_len, sess_id, true);
                }
                sess.add_ipv6_framed_route(subnet);
            } else {
                if let Ok(mut trie) = self.ipv4_framed_routes.write() {
                    trie.insert(&subnet.sub, prefix_len, sess_id, false);
                }
                sess.add_ipv4_framed_route(subnet);
            }
            return true;
        }
        false
    }

    /// Get session count
    pub fn sess_count(&self) -> usize {
        self.sess_list.read().map(|l| l.len()).unwrap_or(0)
    }

    /// Get all sessions (for iteration)
    pub fn get_all_sessions(&self) -> Vec<UpfSess> {
        self.sess_list
            .read()
            .map(|l| l.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Update session in context
    pub fn sess_update(&self, sess: &UpfSess) -> bool {
        if let Ok(mut sess_list) = self.sess_list.write() {
            if sess_list.contains_key(&sess.id) {
                sess_list.insert(sess.id, sess.clone());
                return true;
            }
        }
        false
    }
}

impl Default for UpfContext {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global Context (singleton pattern)
// ============================================================================

use std::sync::OnceLock;

static UPF_CONTEXT: OnceLock<UpfContext> = OnceLock::new();

/// Get the global UPF context
pub fn upf_self() -> &'static UpfContext {
    UPF_CONTEXT.get_or_init(UpfContext::new)
}

/// Initialize the global UPF context
pub fn upf_context_init(max_sess: usize) {
    let _ctx = UPF_CONTEXT.get_or_init(UpfContext::new);
    // Note: We can't mutate through OnceLock, so init is a no-op after first call
    // In real implementation, would use a different pattern
    log::info!("UPF context initialized with max {} sessions", max_sess);
}

/// Finalize the global UPF context
pub fn upf_context_final() {
    if let Some(ctx) = UPF_CONTEXT.get() {
        ctx.sess_remove_all();
    }
    log::info!("UPF context finalized");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_subnet_ipv4() {
        let subnet = IpSubnet::new_ipv4(0xC0A80100, 24); // 192.168.1.0/24
        assert!(subnet.matches(&[0xC0A80101, 0, 0, 0])); // 192.168.1.1
        assert!(subnet.matches(&[0xC0A801FF, 0, 0, 0])); // 192.168.1.255
        assert!(!subnet.matches(&[0xC0A80201, 0, 0, 0])); // 192.168.2.1
    }

    #[test]
    fn test_route_trie_ipv4() {
        let mut trie = RouteTrie::new();
        
        // Insert 192.168.1.0/24 -> session 1
        trie.insert(&[0xC0A80100, 0, 0, 0], 24, 1, false);
        
        // Insert 192.168.0.0/16 -> session 2
        trie.insert(&[0xC0A80000, 0, 0, 0], 16, 2, false);
        
        // Find 192.168.1.1 - should match /24 (longest prefix)
        assert_eq!(trie.find(&[0xC0A80101, 0, 0, 0], false), Some(1));
        
        // Find 192.168.2.1 - should match /16
        assert_eq!(trie.find(&[0xC0A80201, 0, 0, 0], false), Some(2));
        
        // Find 10.0.0.1 - no match
        assert_eq!(trie.find(&[0x0A000001, 0, 0, 0], false), None);
    }

    #[test]
    fn test_urr_accounting() {
        let mut acc = UrrAccounting::default();
        
        acc.add(100, true);  // uplink
        acc.add(200, false); // downlink
        
        assert_eq!(acc.total_octets, 300);
        assert_eq!(acc.ul_octets, 100);
        assert_eq!(acc.dl_octets, 200);
        assert_eq!(acc.total_pkts, 2);
        assert_eq!(acc.ul_pkts, 1);
        assert_eq!(acc.dl_pkts, 1);
        
        acc.snapshot();
        assert_eq!(acc.last_report.total_octets, 300);
        assert_eq!(acc.report_seqn, 1);
    }

    #[test]
    fn test_upf_sess_framed_routes() {
        let mut sess = UpfSess::new(1, 100);
        
        let subnet = IpSubnet::new_ipv4(0xC0A80100, 24);
        sess.add_ipv4_framed_route(subnet);
        
        assert!(sess.check_framed_routes(&[0xC0A80101, 0, 0, 0], false));
        assert!(!sess.check_framed_routes(&[0xC0A80201, 0, 0, 0], false));
    }

    #[test]
    fn test_upf_context_session_lifecycle() {
        let ctx = UpfContext::new();
        
        let f_seid = FSeid::with_ipv4(1000, Ipv4Addr::new(10, 0, 0, 1));
        
        // Add session
        let sess = ctx.sess_add(&f_seid).unwrap();
        assert_eq!(sess.smf_n4_f_seid.seid, 1000);
        
        // Find by various keys
        assert!(ctx.sess_find_by_smf_n4_seid(1000).is_some());
        assert!(ctx.sess_find_by_upf_n4_seid(sess.upf_n4_seid).is_some());
        assert!(ctx.sess_find_by_smf_n4_f_seid(&f_seid).is_some());
        
        // Set UE IP
        ctx.sess_set_ue_ip(sess.id, Some(Ipv4Addr::new(192, 168, 1, 100)), None);
        
        // Find by IP
        let addr = u32::from_be_bytes([192, 168, 1, 100]);
        assert!(ctx.sess_find_by_ipv4(addr).is_some());
        
        // Remove session
        ctx.sess_remove(sess.id);
        assert!(ctx.sess_find_by_smf_n4_seid(1000).is_none());
        assert!(ctx.sess_find_by_ipv4(addr).is_none());
    }

    #[test]
    fn test_f_seid() {
        let f_seid1 = FSeid::with_ipv4(100, Ipv4Addr::new(10, 0, 0, 1));
        let f_seid2 = FSeid::with_ipv4(100, Ipv4Addr::new(10, 0, 0, 1));
        let f_seid3 = FSeid::with_ipv4(101, Ipv4Addr::new(10, 0, 0, 1));
        
        assert_eq!(f_seid1, f_seid2);
        assert_ne!(f_seid1, f_seid3);
    }
}
