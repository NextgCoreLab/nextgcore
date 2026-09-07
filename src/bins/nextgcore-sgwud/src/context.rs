//! SGWU Context Management
//!
//! Port of src/sgwu/context.c, src/sgwu/context.h - SGWU context with session management,
//! hash tables for SEID lookups

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::RwLock;

// ============================================================================
// Constants
// ============================================================================

/// Invalid pool ID
pub const NEXTGCORE_INVALID_POOL_ID: u64 = 0;

// ============================================================================
// IP Address
// ============================================================================

/// IP Address (IPv4 or IPv6)
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct IpAddr {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

impl IpAddr {
    /// Create from IPv4 address
    pub fn from_ipv4(addr: Ipv4Addr) -> Self {
        Self {
            ipv4: Some(addr),
            ipv6: None,
        }
    }

    /// Create from IPv6 address
    pub fn from_ipv6(addr: Ipv6Addr) -> Self {
        Self {
            ipv4: None,
            ipv6: Some(addr),
        }
    }

    /// Check if address is set
    pub fn is_set(&self) -> bool {
        self.ipv4.is_some() || self.ipv6.is_some()
    }
}

// ============================================================================
// F-SEID (Fully qualified SEID)
// ============================================================================

/// F-SEID structure for SGWC
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct FSeid {
    /// SEID value
    pub seid: u64,
    /// IP address
    pub ip: IpAddr,
}

impl FSeid {
    /// Create F-SEID with IPv4
    pub fn with_ipv4(seid: u64, ipv4: Ipv4Addr) -> Self {
        Self {
            seid,
            ip: IpAddr::from_ipv4(ipv4),
        }
    }

    /// Create F-SEID with IPv6
    pub fn with_ipv6(seid: u64, ipv6: Ipv6Addr) -> Self {
        Self {
            seid,
            ip: IpAddr::from_ipv6(ipv6),
        }
    }

    /// Create from PFCP F-SEID data
    pub fn from_pfcp_f_seid(seid: u64, ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>) -> Self {
        Self {
            seid,
            ip: IpAddr { ipv4, ipv6 },
        }
    }
}

// ============================================================================
// PFCP Session (simplified)
// ============================================================================

/// PFCP session data (simplified from nextgcore_pfcp_sess_t)
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

impl PfcpSess {
    /// Clear all PFCP session data
    pub fn clear(&mut self) {
        self.pdr_ids.clear();
        self.far_ids.clear();
        self.urr_ids.clear();
        self.qer_ids.clear();
        self.bar_ids.clear();
    }
}

// ============================================================================
// SGWU Session
// ============================================================================

/// SGWU Session context
/// Port of sgwu_sess_t from context.h
#[derive(Debug, Clone)]
pub struct SgwuSess {
    /// Session ID (pool ID)
    pub id: u64,
    /// PFCP session data
    pub pfcp: PfcpSess,
    /// SGWU-SXA-SEID (derived from pool)
    pub sgwu_sxa_seid: u64,
    /// SGWC-SXA-F-SEID (received from peer)
    pub sgwc_sxa_f_seid: FSeid,
    /// PFCP node ID
    pub pfcp_node_id: Option<u64>,
}

impl SgwuSess {
    /// Create a new SGWU session
    pub fn new(id: u64, sgwu_sxa_seid: u64) -> Self {
        Self {
            id,
            pfcp: PfcpSess::default(),
            sgwu_sxa_seid,
            sgwc_sxa_f_seid: FSeid::default(),
            pfcp_node_id: None,
        }
    }

    /// Set SGWC F-SEID
    pub fn set_sgwc_f_seid(&mut self, seid: u64, ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>) {
        self.sgwc_sxa_f_seid = FSeid::from_pfcp_f_seid(seid, ipv4, ipv6);
    }

    /// Get SGWC SEID
    pub fn sgwc_sxa_seid(&self) -> u64 {
        self.sgwc_sxa_f_seid.seid
    }
}

impl Default for SgwuSess {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

// ============================================================================
// User-Plane Rules (PDR / FAR / QER / BAR)
// ============================================================================

/// FAR Apply Action flags (TS 29.244 Section 8.2.26)
pub mod apply_action {
    pub const DROP: u8 = 0x01;
    pub const FORW: u8 = 0x02;
    pub const BUFF: u8 = 0x04;
    pub const NOCP: u8 = 0x08;
    pub const DUPL: u8 = 0x10;
}

/// Maximum packets buffered per FAR while the action is BUFF
pub const MAX_BUFFERED_PACKETS: usize = 64;

/// Buffer cap for a FAR, honouring a BAR's DL Buffering Suggested Packet Count
/// when the CP function provided one (TS 29.244 §8.2.48) and otherwise the
/// local default, which `SGWU_MAX_BUFFERED_PACKETS` can override.
///
/// The hardcoded 64 was the only limit before; a CP function asking for deeper
/// extended buffering had no way to get it.
pub fn buffer_capacity(suggested: Option<u16>) -> usize {
    if let Some(count) = suggested {
        if count > 0 {
            return count as usize;
        }
    }
    std::env::var("SGWU_MAX_BUFFERED_PACKETS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(MAX_BUFFERED_PACKETS)
}

/// Packet Detection Rule installed by the SGW-C (TS 29.244 Section 7.5.2.2)
#[derive(Debug, Clone, Default)]
pub struct SgwuPdr {
    pub sess_id: u64,
    pub pdr_id: u16,
    pub precedence: u32,
    /// PDI Source Interface (0 = ACCESS, 1 = CORE, ...)
    pub source_interface: u8,
    /// Local F-TEID this PDR matches on
    pub local_teid: u32,
    pub local_addr: Option<Ipv4Addr>,
    /// Outer Header Removal description, if requested
    pub outer_header_removal: Option<u8>,
    pub far_id: Option<u32>,
    pub qer_id: Option<u32>,
}

/// Forwarding Action Rule installed by the SGW-C (TS 29.244 Section 7.5.2.3)
#[derive(Debug, Clone, Default)]
pub struct SgwuFar {
    pub sess_id: u64,
    pub far_id: u32,
    /// Apply Action flags (DROP/FORW/BUFF/NOCP/DUPL)
    pub apply_action: u8,
    /// Destination Interface
    pub destination_interface: u8,
    /// Outer Header Creation: (TEID, peer IPv4, peer IPv6)
    pub outer_header_creation: Option<(u32, Option<Ipv4Addr>, Option<Ipv6Addr>)>,
    /// Packets buffered while the action is BUFF
    pub buffered: Vec<Vec<u8>>,
}

/// QoS Enforcement Rule (TS 29.244 §5.2.5.1, §8.2.7).
///
/// `gate_status` packs both directions: bits 1-2 are the UL gate and bits 3-4
/// the DL gate, each `0` = OPEN and `1` = CLOSED.
#[derive(Debug, Clone, Default)]
pub struct SgwuQer {
    pub sess_id: u64,
    pub qer_id: u32,
    pub gate_status: Option<u8>,
    pub mbr_ul: u64,
    pub mbr_dl: u64,
}

/// Gate status values (TS 29.244 §8.2.7).
pub mod gate_status {
    pub const OPEN: u8 = 0;
    pub const CLOSED: u8 = 1;
}

impl SgwuQer {
    /// Whether the gate for a direction is CLOSED, so traffic must be dropped.
    ///
    /// An absent Gate Status IE means OPEN: TS 29.244 §8.2.7 makes the closed
    /// state something the CP must ASK for, so defaulting to closed on an absent
    /// IE would black-hole every session whose QER omits it.
    pub fn gate_is_closed(&self, uplink: bool) -> bool {
        let Some(status) = self.gate_status else {
            return false;
        };
        let gate = if uplink {
            status & 0x03
        } else {
            (status >> 2) & 0x03
        };
        gate == gate_status::CLOSED
    }

    /// MBR for a direction, in bits per second. `0` means "not provisioned",
    /// which TS 29.244 treats as unlimited rather than as a zero-rate cap.
    pub fn mbr_bps(&self, uplink: bool) -> u64 {
        if uplink {
            self.mbr_ul
        } else {
            self.mbr_dl
        }
    }
}

/// Buffering Action Rule (TS 29.244 §5.9, Table 7.5.9.2-1).
#[derive(Debug, Clone, Default)]
pub struct SgwuBar {
    pub sess_id: u64,
    pub bar_id: u8,
    /// Downlink Data Notification Delay in **50 ms units** (TS 29.244 §8.2.28).
    pub downlink_data_notification_delay: Option<u8>,
    /// DL Buffering Duration from an Update BAR (TS 29.244 §8.2.47), in the
    /// encoded form: bits 1-5 the value, bits 6-8 the unit.
    pub dl_buffering_duration: Option<u8>,
    /// DL Buffering Suggested Packet Count from an Update BAR
    /// (TS 29.244 §8.2.48): the cap the CP function suggests for this session,
    /// overriding the local default.
    pub dl_buffering_suggested_packet_count: Option<u16>,
}

impl SgwuBar {
    /// The Downlink Data Notification delay as a duration
    /// (TS 29.244 §8.2.28: 50 ms units). `None` when no delay was provisioned or
    /// the provisioned delay is zero.
    pub fn ddn_delay(&self) -> Option<std::time::Duration> {
        match self.downlink_data_notification_delay {
            Some(0) | None => None,
            Some(units) => Some(std::time::Duration::from_millis(units as u64 * 50)),
        }
    }
}

// ============================================================================
// SGWU Context
// ============================================================================

/// SGWU Context - main context structure for SGWU
/// Port of sgwu_context_t from context.h
pub struct SgwuContext {
    // Hash tables
    /// SGWU-SXA-SEID -> Session ID hash
    sgwu_sxa_seid_hash: RwLock<HashMap<u64, u64>>,
    /// SGWC-SXA-SEID -> Session ID hash
    sgwc_sxa_seid_hash: RwLock<HashMap<u64, u64>>,
    /// SGWC-SXA-F-SEID -> Session ID hash
    sgwc_sxa_f_seid_hash: RwLock<HashMap<FSeid, u64>>,

    // Session list
    /// Session list (by pool ID)
    sess_list: RwLock<HashMap<u64, SgwuSess>>,

    // User-plane rules
    /// PDRs keyed by (session id, PDR ID)
    pdr_list: RwLock<HashMap<(u64, u16), SgwuPdr>>,
    /// FARs keyed by (session id, FAR ID)
    far_list: RwLock<HashMap<(u64, u32), SgwuFar>>,
    /// QERs keyed by (session id, QER ID)
    qer_list: RwLock<HashMap<(u64, u32), SgwuQer>>,
    /// BARs keyed by (session id, BAR ID)
    bar_list: RwLock<HashMap<(u64, u8), SgwuBar>>,
    /// Local GTP-U TEID -> (session id, PDR ID) for G-PDU matching
    teid_hash: RwLock<HashMap<u32, (u64, u16)>>,
    /// Local GTP-U address advertised in allocated F-TEIDs
    gtpu_addr: RwLock<Option<Ipv4Addr>>,

    // ID generators
    /// Next session ID
    next_sess_id: AtomicUsize,
    /// SXA SEID generator
    sxa_seid_generator: AtomicU64,
    /// GTP-U TEID allocator (CH flag handling)
    teid_generator: AtomicU64,

    // Pool limits
    /// Maximum number of sessions
    max_num_of_sess: usize,

    /// Context initialized flag
    initialized: AtomicBool,
}

impl SgwuContext {
    /// Create a new SGWU context
    pub fn new() -> Self {
        Self {
            sgwu_sxa_seid_hash: RwLock::new(HashMap::new()),
            sgwc_sxa_seid_hash: RwLock::new(HashMap::new()),
            sgwc_sxa_f_seid_hash: RwLock::new(HashMap::new()),
            sess_list: RwLock::new(HashMap::new()),
            pdr_list: RwLock::new(HashMap::new()),
            far_list: RwLock::new(HashMap::new()),
            qer_list: RwLock::new(HashMap::new()),
            bar_list: RwLock::new(HashMap::new()),
            teid_hash: RwLock::new(HashMap::new()),
            gtpu_addr: RwLock::new(None),
            next_sess_id: AtomicUsize::new(1),
            sxa_seid_generator: AtomicU64::new(1),
            teid_generator: AtomicU64::new(1),
            max_num_of_sess: 0,
            initialized: AtomicBool::new(false),
        }
    }

    /// Initialize the SGWU context
    pub fn init(&mut self, max_sess: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }

        self.max_num_of_sess = max_sess;
        self.initialized.store(true, Ordering::SeqCst);

        log::info!(
            "SGWU context initialized with max {} sessions",
            self.max_num_of_sess
        );
    }

    /// Finalize the SGWU context
    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }

        self.sess_remove_all();
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("SGWU context finalized");
    }

    /// Check if context is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Generate next SXA SEID
    fn next_sxa_seid(&self) -> u64 {
        self.sxa_seid_generator.fetch_add(1, Ordering::SeqCst)
    }

    // ========================================================================
    // Session Management
    // ========================================================================

    /// Add a new session by F-SEID
    /// Port of sgwu_sess_add from context.c
    pub fn sess_add(&self, cp_f_seid: &FSeid) -> Option<SgwuSess> {
        let mut sess_list = self.sess_list.write().ok()?;
        let mut sgwu_sxa_seid_hash = self.sgwu_sxa_seid_hash.write().ok()?;
        let mut sgwc_sxa_seid_hash = self.sgwc_sxa_seid_hash.write().ok()?;
        let mut sgwc_sxa_f_seid_hash = self.sgwc_sxa_f_seid_hash.write().ok()?;

        if self.max_num_of_sess > 0 && sess_list.len() >= self.max_num_of_sess {
            log::error!(
                "Maximum number of sessions [{}] reached",
                self.max_num_of_sess
            );
            return None;
        }

        let id = self.next_sess_id.fetch_add(1, Ordering::SeqCst) as u64;
        let sgwu_sxa_seid = self.next_sxa_seid();

        let mut sess = SgwuSess::new(id, sgwu_sxa_seid);
        sess.sgwc_sxa_f_seid = cp_f_seid.clone();

        // Add to hash tables
        sgwu_sxa_seid_hash.insert(sgwu_sxa_seid, id);
        sgwc_sxa_seid_hash.insert(cp_f_seid.seid, id);
        sgwc_sxa_f_seid_hash.insert(cp_f_seid.clone(), id);

        sess_list.insert(id, sess.clone());

        log::info!(
            "UE F-SEID[UP:0x{:x} CP:0x{:x}]",
            sgwu_sxa_seid,
            cp_f_seid.seid
        );
        log::info!("[Added] Number of SGWU-Sessions is now {}", sess_list.len());

        Some(sess)
    }

    /// Remove a session by ID
    /// Port of sgwu_sess_remove from context.c
    pub fn sess_remove(&self, id: u64) -> Option<SgwuSess> {
        let mut sess_list = self.sess_list.write().ok()?;
        let mut sgwu_sxa_seid_hash = self.sgwu_sxa_seid_hash.write().ok()?;
        let mut sgwc_sxa_seid_hash = self.sgwc_sxa_seid_hash.write().ok()?;
        let mut sgwc_sxa_f_seid_hash = self.sgwc_sxa_f_seid_hash.write().ok()?;

        if let Some(mut sess) = sess_list.remove(&id) {
            // Remove from hash tables
            sgwu_sxa_seid_hash.remove(&sess.sgwu_sxa_seid);
            sgwc_sxa_seid_hash.remove(&sess.sgwc_sxa_f_seid.seid);
            sgwc_sxa_f_seid_hash.remove(&sess.sgwc_sxa_f_seid);

            // Drop all user-plane rules belonging to the session
            if let Ok(mut pdrs) = self.pdr_list.write() {
                if let Ok(mut teids) = self.teid_hash.write() {
                    teids.retain(|_, (sess_id, _)| *sess_id != id);
                }
                pdrs.retain(|(sess_id, _), _| *sess_id != id);
            }
            if let Ok(mut fars) = self.far_list.write() {
                fars.retain(|(sess_id, _), _| *sess_id != id);
            }
            if let Ok(mut qers) = self.qer_list.write() {
                qers.retain(|(sess_id, _), _| *sess_id != id);
            }
            if let Ok(mut bars) = self.bar_list.write() {
                bars.retain(|(sess_id, _), _| *sess_id != id);
            }

            // Clear PFCP session
            sess.pfcp.clear();

            log::info!(
                "[Removed] Number of SGWU-sessions is now {}",
                sess_list.len()
            );
            return Some(sess);
        }
        None
    }

    /// Remove all sessions
    /// Port of sgwu_sess_remove_all from context.c
    pub fn sess_remove_all(&self) {
        let ids: Vec<u64> = {
            if let Ok(list) = self.sess_list.read() {
                list.keys().copied().collect()
            } else {
                return;
            }
        };
        for id in ids {
            self.sess_remove(id);
        }
    }

    /// Find session by SGWC SXA SEID
    /// Port of sgwu_sess_find_by_sgwc_sxa_seid from context.c
    pub fn sess_find_by_sgwc_sxa_seid(&self, seid: u64) -> Option<SgwuSess> {
        // Drop the hash guard before locking sess_list: holding it inverts
        // sess_add's lock order and can deadlock.
        let sess_id = *self.sgwc_sxa_seid_hash.read().ok()?.get(&seid)?;
        self.sess_find_by_id(sess_id)
    }

    /// Find session by SGWC SXA F-SEID
    /// Port of sgwu_sess_find_by_sgwc_sxa_f_seid from context.c
    pub fn sess_find_by_sgwc_sxa_f_seid(&self, f_seid: &FSeid) -> Option<SgwuSess> {
        let sess_id = *self.sgwc_sxa_f_seid_hash.read().ok()?.get(f_seid)?;
        self.sess_find_by_id(sess_id)
    }

    /// Find session by SGWU SXA SEID
    /// Port of sgwu_sess_find_by_sgwu_sxa_seid from context.c
    pub fn sess_find_by_sgwu_sxa_seid(&self, seid: u64) -> Option<SgwuSess> {
        let sess_id = *self.sgwu_sxa_seid_hash.read().ok()?.get(&seid)?;
        self.sess_find_by_id(sess_id)
    }

    /// Find session by ID
    /// Port of sgwu_sess_find_by_id from context.c
    pub fn sess_find_by_id(&self, id: u64) -> Option<SgwuSess> {
        let sess_list = self.sess_list.read().ok()?;
        sess_list.get(&id).cloned()
    }

    /// Get session count
    pub fn sess_count(&self) -> usize {
        self.sess_list.read().map(|l| l.len()).unwrap_or(0)
    }

    /// Get all sessions (for iteration)
    pub fn get_all_sessions(&self) -> Vec<SgwuSess> {
        self.sess_list
            .read()
            .map(|l| l.values().cloned().collect())
            .expect("value expected")
    }

    /// Update session in context
    pub fn sess_update(&self, sess: &SgwuSess) -> bool {
        if let Ok(mut sess_list) = self.sess_list.write() {
            if let std::collections::hash_map::Entry::Occupied(mut e) = sess_list.entry(sess.id) {
                e.insert(sess.clone());
                return true;
            }
        }
        false
    }

    /// Set PFCP node for session
    pub fn sess_set_pfcp_node(&self, sess_id: u64, pfcp_node_id: u64) -> bool {
        if let Ok(mut sess_list) = self.sess_list.write() {
            if let Some(sess) = sess_list.get_mut(&sess_id) {
                sess.pfcp_node_id = Some(pfcp_node_id);
                return true;
            }
        }
        false
    }

    // ========================================================================
    // GTP-U configuration and TEID allocation
    // ========================================================================

    /// Set the local GTP-U address advertised in allocated F-TEIDs
    pub fn set_gtpu_address(&self, addr: Option<Ipv4Addr>) {
        if let Ok(mut a) = self.gtpu_addr.write() {
            *a = addr;
        }
    }

    /// Local GTP-U address advertised in allocated F-TEIDs
    pub fn gtpu_address(&self) -> Option<Ipv4Addr> {
        self.gtpu_addr.read().ok().and_then(|a| *a)
    }

    /// Allocate a local GTP-U TEID (F-TEID CH flag handling)
    pub fn alloc_teid(&self) -> u32 {
        self.teid_generator.fetch_add(1, Ordering::SeqCst) as u32
    }

    // ========================================================================
    // PDR Management
    // ========================================================================

    /// Install or replace a PDR; indexes its local TEID for G-PDU matching
    pub fn pdr_install(&self, pdr: SgwuPdr) -> bool {
        let key = (pdr.sess_id, pdr.pdr_id);
        let (Ok(mut pdrs), Ok(mut teids)) = (self.pdr_list.write(), self.teid_hash.write()) else {
            return false;
        };
        // Remove the previous TEID index when updating
        if let Some(old) = pdrs.get(&key) {
            if old.local_teid != 0 {
                teids.remove(&old.local_teid);
            }
        }
        if pdr.local_teid != 0 {
            teids.insert(pdr.local_teid, key);
        }
        pdrs.insert(key, pdr);
        true
    }

    /// Remove a PDR
    pub fn pdr_remove(&self, sess_id: u64, pdr_id: u16) -> Option<SgwuPdr> {
        let (Ok(mut pdrs), Ok(mut teids)) = (self.pdr_list.write(), self.teid_hash.write()) else {
            return None;
        };
        let pdr = pdrs.remove(&(sess_id, pdr_id))?;
        if pdr.local_teid != 0 {
            teids.remove(&pdr.local_teid);
        }
        Some(pdr)
    }

    /// Find a PDR by its session and PDR ID
    pub fn pdr_find(&self, sess_id: u64, pdr_id: u16) -> Option<SgwuPdr> {
        self.pdr_list.read().ok()?.get(&(sess_id, pdr_id)).cloned()
    }

    /// Find the PDR matching an incoming G-PDU by its local TEID
    pub fn pdr_find_by_teid(&self, teid: u32) -> Option<SgwuPdr> {
        let key = *self.teid_hash.read().ok()?.get(&teid)?;
        self.pdr_list.read().ok()?.get(&key).cloned()
    }

    // ========================================================================
    // FAR Management
    // ========================================================================

    /// Install or replace a FAR
    pub fn far_install(&self, far: SgwuFar) -> bool {
        if let Ok(mut fars) = self.far_list.write() {
            fars.insert((far.sess_id, far.far_id), far);
            return true;
        }
        false
    }

    /// Remove a FAR
    pub fn far_remove(&self, sess_id: u64, far_id: u32) -> Option<SgwuFar> {
        self.far_list.write().ok()?.remove(&(sess_id, far_id))
    }

    /// Find a FAR
    pub fn far_find(&self, sess_id: u64, far_id: u32) -> Option<SgwuFar> {
        self.far_list.read().ok()?.get(&(sess_id, far_id)).cloned()
    }

    /// Find the FAR whose Outer Header Creation TEID matches (used to map a
    /// received Error Indication back to a session).
    ///
    /// **Prefer [`SgwuContext::far_find_by_ohc_teid_peer`].** TS 29.281 §7.3.1:
    /// "The TEID and GTP-U peer Address together uniquely identify the related
    /// ... EPS bearer in the receiving node." A TEID alone does not, so this
    /// returns the first of possibly several matches and can name the wrong
    /// session. Kept for callers that genuinely have no peer address.
    pub fn far_find_by_ohc_teid(&self, teid: u32) -> Option<SgwuFar> {
        self.far_list
            .read()
            .ok()?
            .values()
            .find(|far| matches!(far.outer_header_creation, Some((t, _, _)) if t == teid))
            .cloned()
    }

    /// Find the FAR whose Outer Header Creation TEID **and** peer address both
    /// match (TS 29.281 §7.3.1).
    ///
    /// Returns `None` when the TEID matches but the peer does not: that is a
    /// TEID collision with another peer, and reporting it would attribute an
    /// Error Indication to an unrelated bearer — potentially tearing it down.
    /// Dropping is the safe direction, because a genuinely lost bearer will be
    /// re-reported by the peer.
    ///
    /// Both address families are compared against the corresponding slot of
    /// [`SgwuFar::outer_header_creation`], so a v4 Error Indication cannot match
    /// a FAR that only holds a v6 peer or vice versa.
    pub fn far_find_by_ohc_teid_peer(
        &self,
        teid: u32,
        peer_ip: std::net::IpAddr,
    ) -> Option<SgwuFar> {
        self.far_list
            .read()
            .ok()?
            .values()
            .find(|far| match far.outer_header_creation {
                Some((t, v4, v6)) if t == teid => match peer_ip {
                    std::net::IpAddr::V4(want) => v4 == Some(want),
                    std::net::IpAddr::V6(want) => v6 == Some(want),
                },
                _ => false,
            })
            .cloned()
    }

    /// Update a FAR in place via a closure; returns false when not found
    pub fn far_update_with<F: FnOnce(&mut SgwuFar)>(
        &self,
        sess_id: u64,
        far_id: u32,
        f: F,
    ) -> bool {
        if let Ok(mut fars) = self.far_list.write() {
            if let Some(far) = fars.get_mut(&(sess_id, far_id)) {
                f(far);
                return true;
            }
        }
        false
    }

    /// Buffer a packet on a FAR whose action is BUFF.
    /// Returns Some(buffered_count) on success; the count lets the caller
    /// send a Downlink Data Report only for the first buffered packet.
    /// Buffer a packet against a FAR, bounded by `capacity` (see
    /// [`buffer_capacity`], which folds in a BAR's suggested packet count).
    pub fn far_buffer_packet(
        &self,
        sess_id: u64,
        far_id: u32,
        packet: Vec<u8>,
        capacity: usize,
    ) -> Option<usize> {
        let mut fars = self.far_list.write().ok()?;
        let far = fars.get_mut(&(sess_id, far_id))?;
        if far.buffered.len() >= capacity {
            log::warn!("FAR {far_id}: buffer full at {capacity} packets, dropping packet");
            return Some(far.buffered.len());
        }
        far.buffered.push(packet);
        Some(far.buffered.len())
    }

    /// Take all buffered packets from a FAR (when transitioning BUFF -> FORW)
    pub fn far_take_buffered(&self, sess_id: u64, far_id: u32) -> Vec<Vec<u8>> {
        if let Ok(mut fars) = self.far_list.write() {
            if let Some(far) = fars.get_mut(&(sess_id, far_id)) {
                return std::mem::take(&mut far.buffered);
            }
        }
        Vec::new()
    }

    // ========================================================================
    // QER / BAR Management
    // ========================================================================

    /// Install or replace a QER
    pub fn qer_install(&self, qer: SgwuQer) -> bool {
        if let Ok(mut qers) = self.qer_list.write() {
            qers.insert((qer.sess_id, qer.qer_id), qer);
            return true;
        }
        false
    }

    /// Remove a QER
    pub fn qer_remove(&self, sess_id: u64, qer_id: u32) -> Option<SgwuQer> {
        self.qer_list.write().ok()?.remove(&(sess_id, qer_id))
    }

    /// Find a QER
    pub fn qer_find(&self, sess_id: u64, qer_id: u32) -> Option<SgwuQer> {
        self.qer_list.read().ok()?.get(&(sess_id, qer_id)).cloned()
    }

    /// Install or replace a BAR
    pub fn bar_install(&self, bar: SgwuBar) -> bool {
        if let Ok(mut bars) = self.bar_list.write() {
            bars.insert((bar.sess_id, bar.bar_id), bar);
            return true;
        }
        false
    }

    /// Remove a BAR
    /// Find a BAR by session and id.
    pub fn bar_find(&self, sess_id: u64, bar_id: u8) -> Option<SgwuBar> {
        self.bar_list.read().ok()?.get(&(sess_id, bar_id)).cloned()
    }

    /// The BAR installed for a session, if any. Sessions carry at most one BAR
    /// (TS 29.244 Section 7.5.2.6), so the buffering path can find it without
    /// knowing its id.
    pub fn bar_find_for_sess(&self, sess_id: u64) -> Option<SgwuBar> {
        self.bar_list
            .read()
            .ok()?
            .values()
            .find(|bar| bar.sess_id == sess_id)
            .cloned()
    }

    /// Apply an Update BAR: overwrite only the members the CP function supplied,
    /// leaving the rest of the rule intact (TS 29.244 Table 7.5.9.2-1 is a
    /// partial update, not a replacement). Returns false when no BAR is
    /// installed for that session and id.
    pub fn bar_update(
        &self,
        sess_id: u64,
        bar_id: u8,
        ddn_delay: Option<u8>,
        dl_buffering_duration: Option<u8>,
        dl_buffering_suggested_packet_count: Option<u16>,
    ) -> bool {
        let Ok(mut bars) = self.bar_list.write() else {
            return false;
        };
        let Some(bar) = bars.get_mut(&(sess_id, bar_id)) else {
            return false;
        };
        if ddn_delay.is_some() {
            bar.downlink_data_notification_delay = ddn_delay;
        }
        if dl_buffering_duration.is_some() {
            bar.dl_buffering_duration = dl_buffering_duration;
        }
        if dl_buffering_suggested_packet_count.is_some() {
            bar.dl_buffering_suggested_packet_count = dl_buffering_suggested_packet_count;
        }
        true
    }

    pub fn bar_remove(&self, sess_id: u64, bar_id: u8) -> Option<SgwuBar> {
        self.bar_list.write().ok()?.remove(&(sess_id, bar_id))
    }

    /// Remove all sessions for a PFCP node (for restoration)
    pub fn sess_remove_all_for_pfcp_node(&self, pfcp_node_id: u64) {
        let sess_ids: Vec<u64> = {
            if let Ok(list) = self.sess_list.read() {
                list.values()
                    .filter(|s| s.pfcp_node_id == Some(pfcp_node_id))
                    .map(|s| s.id)
                    .collect()
            } else {
                return;
            }
        };
        for id in sess_ids {
            if let Some(sess) = self.sess_find_by_id(id) {
                log::info!(
                    "DELETION: F-SEID[UP:0x{:x} CP:0x{:x}]",
                    sess.sgwu_sxa_seid,
                    sess.sgwc_sxa_f_seid.seid
                );
            }
            self.sess_remove(id);
        }
    }
}

impl Default for SgwuContext {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global Context (singleton pattern)
// ============================================================================

use std::sync::OnceLock;

static SGWU_CONTEXT: OnceLock<SgwuContext> = OnceLock::new();

/// Get the global SGWU context
pub fn sgwu_self() -> &'static SgwuContext {
    SGWU_CONTEXT.get_or_init(SgwuContext::new)
}

/// Initialize the global SGWU context
pub fn sgwu_context_init(max_sess: usize) {
    let _ctx = SGWU_CONTEXT.get_or_init(SgwuContext::new);
    log::info!("SGWU context initialized with max {max_sess} sessions");
}

/// Finalize the global SGWU context
pub fn sgwu_context_final() {
    if let Some(ctx) = SGWU_CONTEXT.get() {
        ctx.sess_remove_all();
    }
    log::info!("SGWU context finalized");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_f_seid_creation() {
        let f_seid = FSeid::with_ipv4(0x1234, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(f_seid.seid, 0x1234);
        assert_eq!(f_seid.ip.ipv4, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(f_seid.ip.ipv6.is_none());

        let f_seid6 = FSeid::with_ipv6(0x5678, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(f_seid6.seid, 0x5678);
        assert!(f_seid6.ip.ipv4.is_none());
        assert!(f_seid6.ip.ipv6.is_some());
    }

    #[test]
    fn test_sess_add_remove() {
        let ctx = SgwuContext::new();
        let f_seid = FSeid::with_ipv4(0x1000, Ipv4Addr::new(10, 0, 0, 1));

        let sess = ctx.sess_add(&f_seid).unwrap();
        assert_eq!(sess.sgwc_sxa_f_seid.seid, 0x1000);
        assert_eq!(ctx.sess_count(), 1);

        // Find by various methods
        let found = ctx.sess_find_by_sgwc_sxa_seid(0x1000).unwrap();
        assert_eq!(found.id, sess.id);

        let found = ctx.sess_find_by_sgwc_sxa_f_seid(&f_seid).unwrap();
        assert_eq!(found.id, sess.id);

        let found = ctx.sess_find_by_sgwu_sxa_seid(sess.sgwu_sxa_seid).unwrap();
        assert_eq!(found.id, sess.id);

        let found = ctx.sess_find_by_id(sess.id).unwrap();
        assert_eq!(found.id, sess.id);

        // Remove
        ctx.sess_remove(sess.id);
        assert_eq!(ctx.sess_count(), 0);
        assert!(ctx.sess_find_by_sgwc_sxa_seid(0x1000).is_none());
    }

    #[test]
    fn test_sess_remove_all() {
        let ctx = SgwuContext::new();

        for i in 0..5 {
            let f_seid = FSeid::with_ipv4(0x1000 + i, Ipv4Addr::new(10, 0, 0, i as u8));
            ctx.sess_add(&f_seid);
        }
        assert_eq!(ctx.sess_count(), 5);

        ctx.sess_remove_all();
        assert_eq!(ctx.sess_count(), 0);
    }

    #[test]
    fn test_sess_update() {
        let ctx = SgwuContext::new();
        let f_seid = FSeid::with_ipv4(0x2000, Ipv4Addr::new(10, 0, 0, 2));

        let mut sess = ctx.sess_add(&f_seid).unwrap();
        sess.pfcp_node_id = Some(999);

        assert!(ctx.sess_update(&sess));

        let found = ctx.sess_find_by_id(sess.id).unwrap();
        assert_eq!(found.pfcp_node_id, Some(999));
    }

    #[test]
    fn test_sess_set_pfcp_node() {
        let ctx = SgwuContext::new();
        let f_seid = FSeid::with_ipv4(0x3000, Ipv4Addr::new(10, 0, 0, 3));

        let sess = ctx.sess_add(&f_seid).unwrap();
        assert!(ctx.sess_set_pfcp_node(sess.id, 123));

        let found = ctx.sess_find_by_id(sess.id).unwrap();
        assert_eq!(found.pfcp_node_id, Some(123));
    }

    #[test]
    fn test_sess_remove_all_for_pfcp_node() {
        let ctx = SgwuContext::new();

        // Add sessions with different PFCP nodes
        for i in 0..3 {
            let f_seid = FSeid::with_ipv4(0x4000 + i, Ipv4Addr::new(10, 0, 0, i as u8));
            let sess = ctx.sess_add(&f_seid).unwrap();
            ctx.sess_set_pfcp_node(sess.id, 100);
        }
        for i in 0..2 {
            let f_seid = FSeid::with_ipv4(0x5000 + i, Ipv4Addr::new(10, 0, 1, i as u8));
            let sess = ctx.sess_add(&f_seid).unwrap();
            ctx.sess_set_pfcp_node(sess.id, 200);
        }
        assert_eq!(ctx.sess_count(), 5);

        // Remove sessions for PFCP node 100
        ctx.sess_remove_all_for_pfcp_node(100);
        assert_eq!(ctx.sess_count(), 2);

        // Remaining sessions should be for PFCP node 200
        let sessions = ctx.get_all_sessions();
        for sess in sessions {
            assert_eq!(sess.pfcp_node_id, Some(200));
        }
    }

    #[test]
    fn test_max_sessions() {
        let mut ctx = SgwuContext::new();
        ctx.init(3);

        for i in 0..3 {
            let f_seid = FSeid::with_ipv4(0x6000 + i, Ipv4Addr::new(10, 0, 0, i as u8));
            assert!(ctx.sess_add(&f_seid).is_some());
        }
        assert_eq!(ctx.sess_count(), 3);

        // Should fail to add more
        let f_seid = FSeid::with_ipv4(0x6003, Ipv4Addr::new(10, 0, 0, 3));
        assert!(ctx.sess_add(&f_seid).is_none());
    }

    #[test]
    fn test_pfcp_sess_clear() {
        let mut pfcp = PfcpSess::default();
        pfcp.pdr_ids.push(1);
        pfcp.far_ids.push(2);
        pfcp.urr_ids.push(3);
        pfcp.qer_ids.push(4);
        pfcp.bar_ids.push(5);

        pfcp.clear();

        assert!(pfcp.pdr_ids.is_empty());
        assert!(pfcp.far_ids.is_empty());
        assert!(pfcp.urr_ids.is_empty());
        assert!(pfcp.qer_ids.is_empty());
        assert!(pfcp.bar_ids.is_empty());
    }

    // ================================================================
    // nextgcore #60: peer-matched Error Indication, QER gate, BAR
    // ================================================================

    /// TS 29.281 Section 7.3.1: the TEID and the GTP-U peer address TOGETHER
    /// identify the bearer. Two sessions holding the SAME outbound TEID toward
    /// DIFFERENT peers is exactly the collision that made the TEID-only lookup
    /// name the wrong session.
    #[test]
    fn far_lookup_requires_both_teid_and_peer() {
        let ctx = SgwuContext::new();
        let peer_a = Ipv4Addr::new(10, 60, 0, 1);
        let peer_b = Ipv4Addr::new(10, 60, 0, 2);

        ctx.far_install(SgwuFar {
            sess_id: 1,
            far_id: 1,
            outer_header_creation: Some((0xABCD, Some(peer_a), None)),
            ..Default::default()
        });
        ctx.far_install(SgwuFar {
            sess_id: 2,
            far_id: 1,
            outer_header_creation: Some((0xABCD, Some(peer_b), None)),
            ..Default::default()
        });

        // Each peer resolves to ITS OWN session.
        let from_a = ctx
            .far_find_by_ohc_teid_peer(0xABCD, std::net::IpAddr::V4(peer_a))
            .expect("peer A matches");
        let from_b = ctx
            .far_find_by_ohc_teid_peer(0xABCD, std::net::IpAddr::V4(peer_b))
            .expect("peer B matches");
        assert_ne!(
            from_a.sess_id, from_b.sess_id,
            "the collision must resolve to two different sessions"
        );
        assert_eq!(from_a.sess_id, 1);
        assert_eq!(from_b.sess_id, 2);

        // A third peer holding the same TEID matches NOTHING rather than being
        // attributed to whichever session was stored first.
        assert!(ctx
            .far_find_by_ohc_teid_peer(0xABCD, std::net::IpAddr::V4(Ipv4Addr::new(10, 60, 0, 9)))
            .is_none());
        // Address families do not cross-match.
        assert!(ctx
            .far_find_by_ohc_teid_peer(
                0xABCD,
                std::net::IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
            )
            .is_none());
    }

    /// TS 29.244 Section 8.2.7: bits 1-2 are the UL gate, bits 3-4 the DL gate,
    /// 0 OPEN and 1 CLOSED. An absent IE must read as OPEN, or every session
    /// whose QER omits it would be black-holed.
    #[test]
    fn qer_gate_status_decodes_per_direction() {
        let open = SgwuQer::default();
        assert!(!open.gate_is_closed(true));
        assert!(!open.gate_is_closed(false));

        let ul_closed = SgwuQer {
            gate_status: Some(0x01),
            ..Default::default()
        };
        assert!(ul_closed.gate_is_closed(true), "UL gate closed");
        assert!(!ul_closed.gate_is_closed(false), "DL gate still open");

        let dl_closed = SgwuQer {
            gate_status: Some(0x04),
            ..Default::default()
        };
        assert!(!dl_closed.gate_is_closed(true), "UL gate still open");
        assert!(dl_closed.gate_is_closed(false), "DL gate closed");

        let both = SgwuQer {
            gate_status: Some(0x05),
            ..Default::default()
        };
        assert!(both.gate_is_closed(true) && both.gate_is_closed(false));

        // An explicitly-OPEN IE is open, not merely "not closed by accident".
        let explicit_open = SgwuQer {
            gate_status: Some(0x00),
            ..Default::default()
        };
        assert!(!explicit_open.gate_is_closed(true));
    }

    #[test]
    fn qer_mbr_zero_means_unlimited_not_zero_rate() {
        let q = SgwuQer {
            mbr_ul: 0,
            mbr_dl: 1_000_000,
            ..Default::default()
        };
        assert_eq!(
            q.mbr_bps(true),
            0,
            "0 signals not-provisioned to the caller"
        );
        assert_eq!(q.mbr_bps(false), 1_000_000);
    }

    /// TS 29.244 Section 8.2.28: the DDN delay is in 50 ms units, and 0 or
    /// absent means no delay.
    #[test]
    fn bar_ddn_delay_is_fifty_millisecond_units() {
        let mut bar = SgwuBar::default();
        assert_eq!(bar.ddn_delay(), None, "absent means no delay");

        bar.downlink_data_notification_delay = Some(0);
        assert_eq!(
            bar.ddn_delay(),
            None,
            "zero means no delay, not zero-length"
        );

        bar.downlink_data_notification_delay = Some(1);
        assert_eq!(bar.ddn_delay(), Some(std::time::Duration::from_millis(50)));

        bar.downlink_data_notification_delay = Some(20);
        assert_eq!(
            bar.ddn_delay(),
            Some(std::time::Duration::from_millis(1000)),
            "20 units is one second, not 20 ms"
        );
    }

    /// TS 29.244 Section 8.2.48: a suggested packet count from the CP function
    /// overrides the local default. The hardcoded 64 ignored it entirely.
    #[test]
    fn buffer_capacity_honours_the_suggested_packet_count() {
        assert_eq!(buffer_capacity(Some(200)), 200);
        // Zero is not a request for a zero-length buffer.
        assert_eq!(buffer_capacity(Some(0)), MAX_BUFFERED_PACKETS);
        assert_eq!(buffer_capacity(None), MAX_BUFFERED_PACKETS);
    }

    /// An Update BAR is a PARTIAL update (TS 29.244 Table 7.5.9.2-1): members
    /// the CP function omitted must survive it.
    #[test]
    fn bar_update_only_overwrites_supplied_members() {
        let ctx = SgwuContext::new();
        assert!(ctx.bar_install(SgwuBar {
            sess_id: 7,
            bar_id: 1,
            downlink_data_notification_delay: Some(4),
            dl_buffering_duration: Some(9),
            dl_buffering_suggested_packet_count: Some(50),
        }));

        // Supply only the suggested count.
        assert!(ctx.bar_update(7, 1, None, None, Some(120)));
        let bar = ctx.bar_find(7, 1).expect("bar present");
        assert_eq!(bar.dl_buffering_suggested_packet_count, Some(120));
        assert_eq!(bar.downlink_data_notification_delay, Some(4), "preserved");
        assert_eq!(bar.dl_buffering_duration, Some(9), "preserved");

        // An update for a BAR that is not installed is reported, not silently
        // dropped.
        assert!(!ctx.bar_update(7, 9, Some(1), None, None));
    }

    #[test]
    fn bar_find_for_sess_locates_the_sessions_bar() {
        let ctx = SgwuContext::new();
        assert!(ctx.bar_install(SgwuBar {
            sess_id: 11,
            bar_id: 3,
            downlink_data_notification_delay: Some(2),
            ..Default::default()
        }));
        let found = ctx.bar_find_for_sess(11).expect("found by session alone");
        assert_eq!(found.bar_id, 3);
        assert!(ctx.bar_find_for_sess(12).is_none());
    }

    /// The buffer cap must actually bound the buffer.
    #[test]
    fn far_buffer_packet_respects_the_supplied_capacity() {
        let ctx = SgwuContext::new();
        ctx.far_install(SgwuFar {
            sess_id: 21,
            far_id: 1,
            ..Default::default()
        });
        for _ in 0..5 {
            ctx.far_buffer_packet(21, 1, vec![0u8; 4], 3);
        }
        let far = ctx.far_find(21, 1).expect("far present");
        assert_eq!(
            far.buffered.len(),
            3,
            "buffer bounded by the capacity given"
        );
    }
}
