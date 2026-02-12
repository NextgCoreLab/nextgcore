//! SGWC Context Management
//!
//! Port of src/sgwc/context.c, src/sgwc/context.h - SGWC context with UE list,
//! session list, bearer list, tunnel list, and hash tables

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

// ============================================================================
// Constants
// ============================================================================

/// Maximum IMSI length
pub const OGS_MAX_IMSI_LEN: usize = 15;
/// Maximum IMSI BCD length
pub const OGS_MAX_IMSI_BCD_LEN: usize = 15;
/// Invalid pool ID
pub const OGS_INVALID_POOL_ID: u64 = 0;

// ============================================================================
// Basic Types
// ============================================================================

/// PLMN ID
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct PlmnId {
    pub mcc1: u8,
    pub mcc2: u8,
    pub mcc3: u8,
    pub mnc1: u8,
    pub mnc2: u8,
    pub mnc3: u8,
}

/// EPS TAI (Tracking Area Identity)
#[derive(Debug, Clone, Default)]
pub struct EpsTai {
    pub plmn_id: PlmnId,
    pub tac: u16,
}

/// E-CGI (E-UTRAN Cell Global Identity)
#[derive(Debug, Clone, Default)]
pub struct ECgi {
    pub plmn_id: PlmnId,
    pub cell_id: u32,
}

/// IP Address (IPv4 or IPv6)
#[derive(Debug, Clone, Default)]
pub struct IpAddr {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

/// Session configuration (APN/DNN)
#[derive(Debug, Clone, Default)]
pub struct SessionConfig {
    pub name: Option<String>,
}

/// PDN Address Allocation
#[derive(Debug, Clone, Default)]
pub struct Paa {
    pub pdn_type: u8,
    pub ipv4_addr: Option<Ipv4Addr>,
    pub ipv6_addr: Option<Ipv6Addr>,
}

// ============================================================================
// GTP Interface Types (from OGS_GTP2_F_TEID_*)
// ============================================================================

/// GTP F-TEID interface types
pub mod gtp_interface {
    /// S5/S8 SGW GTP-U (downlink)
    pub const S5_S8_SGW_GTP_U: u8 = 4;
    /// S1-U SGW GTP-U (uplink)
    pub const S1_U_SGW_GTP_U: u8 = 1;
    /// SGW GTP-U for DL data forwarding (indirect)
    pub const SGW_GTP_U_DL_DATA_FORWARDING: u8 = 22;
    /// SGW GTP-U for UL data forwarding (indirect)
    pub const SGW_GTP_U_UL_DATA_FORWARDING: u8 = 23;
}

// ============================================================================
// SGWC UE Context
// ============================================================================

/// SGWC UE context
/// Port of sgwc_ue_t from context.h
#[derive(Debug, Clone)]
pub struct SgwcUe {
    pub id: u64,
    /// SGW-S11-TEID (derived from pool)
    pub sgw_s11_teid: u32,
    /// MME-S11-TEID (received from MME)
    pub mme_s11_teid: u32,
    /// IMSI (binary)
    pub imsi: Vec<u8>,
    /// IMSI (BCD string)
    pub imsi_bcd: String,
    /// User-Location-Info presence
    pub uli_presence: bool,
    /// EPS TAI
    pub e_tai: EpsTai,
    /// E-CGI
    pub e_cgi: ECgi,
    /// Session IDs belonging to this UE
    pub sess_ids: Vec<u64>,
    /// GTP node ID (for MME connection)
    pub gnode_id: Option<u64>,
}

impl SgwcUe {
    pub fn new(id: u64, sgw_s11_teid: u32) -> Self {
        Self {
            id,
            sgw_s11_teid,
            mme_s11_teid: 0,
            imsi: Vec::new(),
            imsi_bcd: String::new(),
            uli_presence: false,
            e_tai: EpsTai::default(),
            e_cgi: ECgi::default(),
            sess_ids: Vec::new(),
            gnode_id: None,
        }
    }

    /// Set IMSI from binary buffer
    pub fn set_imsi(&mut self, imsi: &[u8]) {
        self.imsi = imsi.to_vec();
        self.imsi_bcd = Self::buffer_to_bcd(imsi);
    }

    /// Convert binary buffer to BCD string
    fn buffer_to_bcd(buf: &[u8]) -> String {
        let mut result = String::new();
        for byte in buf {
            let low = byte & 0x0f;
            let high = (byte >> 4) & 0x0f;
            if low < 10 {
                result.push((b'0' + low) as char);
            }
            if high < 10 {
                result.push((b'0' + high) as char);
            }
        }
        result
    }
}

impl Default for SgwcUe {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

// ============================================================================
// SGWC Session Context
// ============================================================================

/// SGWC Session context
/// Port of sgwc_sess_t from context.h
#[derive(Debug, Clone)]
pub struct SgwcSess {
    pub id: u64,
    /// SGW-S5C-TEID (derived from pool)
    pub sgw_s5c_teid: u32,
    /// PGW-S5C-TEID (received from PGW)
    pub pgw_s5c_teid: u32,
    /// SGWC-SXA-SEID (derived from pool)
    pub sgwc_sxa_seid: u64,
    /// SGWU-SXA-SEID (received from peer)
    pub sgwu_sxa_seid: u64,
    /// APN Configuration
    pub session: SessionConfig,
    /// PDN Address Allocation
    pub paa: Paa,
    /// Bearer IDs belonging to this session
    pub bearer_ids: Vec<u64>,
    /// GTP node ID (for PGW connection)
    pub gnode_id: Option<u64>,
    /// PFCP node ID
    pub pfcp_node_id: Option<u64>,
    /// Parent UE ID
    pub sgwc_ue_id: u64,
}

impl SgwcSess {
    pub fn new(id: u64, sgwc_ue_id: u64) -> Self {
        Self {
            id,
            sgw_s5c_teid: 0,
            pgw_s5c_teid: 0,
            sgwc_sxa_seid: 0,
            sgwu_sxa_seid: 0,
            session: SessionConfig::default(),
            paa: Paa::default(),
            bearer_ids: Vec::new(),
            gnode_id: None,
            pfcp_node_id: None,
            sgwc_ue_id,
        }
    }

    /// Set APN name
    pub fn set_apn(&mut self, apn: &str) {
        self.session.name = Some(apn.to_string());
    }

    /// Get APN name
    pub fn apn(&self) -> Option<&str> {
        self.session.name.as_deref()
    }
}

impl Default for SgwcSess {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

// ============================================================================
// SGWC Bearer Context
// ============================================================================

/// SGWC Bearer context
/// Port of sgwc_bearer_t from context.h
#[derive(Debug, Clone)]
pub struct SgwcBearer {
    pub id: u64,
    /// EPS Bearer ID
    pub ebi: u8,
    /// Tunnel IDs belonging to this bearer
    pub tunnel_ids: Vec<u64>,
    /// Parent session ID
    pub sess_id: u64,
    /// Parent UE ID
    pub sgwc_ue_id: u64,
}

impl SgwcBearer {
    pub fn new(id: u64, sess_id: u64, sgwc_ue_id: u64) -> Self {
        Self {
            id,
            ebi: 0,
            tunnel_ids: Vec::new(),
            sess_id,
            sgwc_ue_id,
        }
    }
}

impl Default for SgwcBearer {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

// ============================================================================
// SGWC Tunnel Context
// ============================================================================

/// SGWC Tunnel context
/// Port of sgwc_tunnel_t from context.h
#[derive(Debug, Clone)]
pub struct SgwcTunnel {
    pub id: u64,
    /// Interface type (S5/S8, S1-U, etc.)
    pub interface_type: u8,
    /// PDR ID
    pub pdr_id: Option<u16>,
    /// FAR ID
    pub far_id: Option<u32>,
    /// Local TEID
    pub local_teid: u32,
    /// Local IPv4 address
    pub local_addr: Option<Ipv4Addr>,
    /// Local IPv6 address
    pub local_addr6: Option<Ipv6Addr>,
    /// Remote TEID
    pub remote_teid: u32,
    /// Remote IP
    pub remote_ip: IpAddr,
    /// Parent bearer ID
    pub bearer_id: u64,
    /// GTP node ID
    pub gnode_id: Option<u64>,
}

impl SgwcTunnel {
    pub fn new(id: u64, bearer_id: u64, interface_type: u8) -> Self {
        Self {
            id,
            interface_type,
            pdr_id: None,
            far_id: None,
            local_teid: 0,
            local_addr: None,
            local_addr6: None,
            remote_teid: 0,
            remote_ip: IpAddr::default(),
            bearer_id,
            gnode_id: None,
        }
    }

    /// Check if this is a downlink tunnel
    pub fn is_downlink(&self) -> bool {
        self.interface_type == gtp_interface::S5_S8_SGW_GTP_U
    }

    /// Check if this is an uplink tunnel
    pub fn is_uplink(&self) -> bool {
        self.interface_type == gtp_interface::S1_U_SGW_GTP_U
    }
}

impl Default for SgwcTunnel {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

// ============================================================================
// SGWC Context (Main)
// ============================================================================

/// SGWC Context - main context structure for SGWC
/// Port of sgwc_context_t from context.h
pub struct SgwcContext {
    // Lists
    /// SGWC UE list (by pool ID)
    sgwc_ue_list: RwLock<HashMap<u64, SgwcUe>>,
    /// Session list (by pool ID)
    sess_list: RwLock<HashMap<u64, SgwcSess>>,
    /// Bearer list (by pool ID)
    bearer_list: RwLock<HashMap<u64, SgwcBearer>>,
    /// Tunnel list (by pool ID)
    tunnel_list: RwLock<HashMap<u64, SgwcTunnel>>,

    // Hash tables
    /// IMSI -> UE ID hash
    imsi_hash: RwLock<HashMap<Vec<u8>, u64>>,
    /// SGW-S11-TEID -> UE ID hash
    sgw_s11_teid_hash: RwLock<HashMap<u32, u64>>,
    /// SGWC-SXA-SEID -> Session ID hash
    sgwc_sxa_seid_hash: RwLock<HashMap<u64, u64>>,

    // ID generators
    /// Next UE ID
    next_ue_id: AtomicUsize,
    /// Next session ID
    next_sess_id: AtomicUsize,
    /// Next bearer ID
    next_bearer_id: AtomicUsize,
    /// Next tunnel ID
    next_tunnel_id: AtomicUsize,
    /// S11 TEID generator
    s11_teid_generator: AtomicU64,
    /// SXA SEID generator
    sxa_seid_generator: AtomicU64,

    // Pool limits
    /// Maximum number of UEs
    max_num_of_ue: usize,
    /// Maximum number of sessions
    max_num_of_sess: usize,
    /// Maximum number of bearers
    max_num_of_bearer: usize,
    /// Maximum number of tunnels
    max_num_of_tunnel: usize,

    /// Context initialized flag
    initialized: AtomicBool,
}

impl SgwcContext {
    /// Create a new SGWC context
    pub fn new() -> Self {
        Self {
            sgwc_ue_list: RwLock::new(HashMap::new()),
            sess_list: RwLock::new(HashMap::new()),
            bearer_list: RwLock::new(HashMap::new()),
            tunnel_list: RwLock::new(HashMap::new()),
            imsi_hash: RwLock::new(HashMap::new()),
            sgw_s11_teid_hash: RwLock::new(HashMap::new()),
            sgwc_sxa_seid_hash: RwLock::new(HashMap::new()),
            next_ue_id: AtomicUsize::new(1),
            next_sess_id: AtomicUsize::new(1),
            next_bearer_id: AtomicUsize::new(1),
            next_tunnel_id: AtomicUsize::new(1),
            s11_teid_generator: AtomicU64::new(1),
            sxa_seid_generator: AtomicU64::new(1),
            max_num_of_ue: 0,
            max_num_of_sess: 0,
            max_num_of_bearer: 0,
            max_num_of_tunnel: 0,
            initialized: AtomicBool::new(false),
        }
    }

    /// Initialize the SGWC context
    pub fn init(&mut self, max_ue: usize, max_sess: usize, max_bearer: usize, max_tunnel: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }

        self.max_num_of_ue = max_ue;
        self.max_num_of_sess = max_sess;
        self.max_num_of_bearer = max_bearer;
        self.max_num_of_tunnel = max_tunnel;
        self.initialized.store(true, Ordering::SeqCst);

        log::info!(
            "SGWC context initialized with max {} UEs, {} sessions, {} bearers, {} tunnels",
            self.max_num_of_ue, self.max_num_of_sess, self.max_num_of_bearer, self.max_num_of_tunnel
        );
    }

    /// Finalize the SGWC context
    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }

        self.ue_remove_all();
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("SGWC context finalized");
    }

    /// Check if context is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Generate next S11 TEID
    fn next_s11_teid(&self) -> u32 {
        self.s11_teid_generator.fetch_add(1, Ordering::SeqCst) as u32
    }

    /// Generate next SXA SEID
    fn next_sxa_seid(&self) -> u64 {
        self.sxa_seid_generator.fetch_add(1, Ordering::SeqCst)
    }

    // ========================================================================
    // UE Management
    // ========================================================================

    /// Add a new UE by IMSI
    pub fn ue_add(&self, imsi: &[u8]) -> Option<SgwcUe> {
        let mut sgwc_ue_list = self.sgwc_ue_list.write().ok()?;
        let mut imsi_hash = self.imsi_hash.write().ok()?;
        let mut sgw_s11_teid_hash = self.sgw_s11_teid_hash.write().ok()?;

        if self.max_num_of_ue > 0 && sgwc_ue_list.len() >= self.max_num_of_ue {
            log::error!("Maximum number of UEs [{}] reached", self.max_num_of_ue);
            return None;
        }

        let id = self.next_ue_id.fetch_add(1, Ordering::SeqCst) as u64;
        let sgw_s11_teid = self.next_s11_teid();
        let mut ue = SgwcUe::new(id, sgw_s11_teid);
        ue.set_imsi(imsi);

        imsi_hash.insert(imsi.to_vec(), id);
        sgw_s11_teid_hash.insert(sgw_s11_teid, id);
        sgwc_ue_list.insert(id, ue.clone());

        log::info!("[Added] SGWC UE IMSI[{}] (id={}, teid={})", ue.imsi_bcd, id, sgw_s11_teid);
        Some(ue)
    }

    /// Remove a UE by ID
    pub fn ue_remove(&self, id: u64) -> Option<SgwcUe> {
        // First, remove all sessions for this UE
        self.sess_remove_all_for_ue(id);

        let mut sgwc_ue_list = self.sgwc_ue_list.write().ok()?;
        let mut imsi_hash = self.imsi_hash.write().ok()?;
        let mut sgw_s11_teid_hash = self.sgw_s11_teid_hash.write().ok()?;

        if let Some(ue) = sgwc_ue_list.remove(&id) {
            if !ue.imsi.is_empty() {
                imsi_hash.remove(&ue.imsi);
            }
            sgw_s11_teid_hash.remove(&ue.sgw_s11_teid);

            log::info!("[Removed] SGWC UE (id={id})");
            return Some(ue);
        }
        None
    }

    /// Remove all UEs
    pub fn ue_remove_all(&self) {
        let ids: Vec<u64> = {
            if let Ok(list) = self.sgwc_ue_list.read() {
                list.keys().copied().collect()
            } else {
                return;
            }
        };
        for id in ids {
            self.ue_remove(id);
        }
    }

    /// Find UE by ID
    pub fn ue_find_by_id(&self, id: u64) -> Option<SgwcUe> {
        self.sgwc_ue_list.read().ok()?.get(&id).cloned()
    }

    /// Find UE by IMSI
    pub fn ue_find_by_imsi(&self, imsi: &[u8]) -> Option<SgwcUe> {
        let imsi_hash = self.imsi_hash.read().ok()?;
        let id = imsi_hash.get(imsi)?;
        self.ue_find_by_id(*id)
    }

    /// Find UE by S11 TEID
    pub fn ue_find_by_teid(&self, teid: u32) -> Option<SgwcUe> {
        let sgw_s11_teid_hash = self.sgw_s11_teid_hash.read().ok()?;
        let id = sgw_s11_teid_hash.get(&teid)?;
        self.ue_find_by_id(*id)
    }

    /// Update UE in context
    pub fn ue_update(&self, ue: &SgwcUe) -> bool {
        if let Ok(mut list) = self.sgwc_ue_list.write() {
            list.insert(ue.id, ue.clone());
            return true;
        }
        false
    }

    /// Get UE count
    pub fn ue_count(&self) -> usize {
        self.sgwc_ue_list.read().map(|l| l.len()).unwrap_or(0)
    }

    // ========================================================================
    // Session Management
    // ========================================================================

    /// Add a new session
    pub fn sess_add(&self, sgwc_ue_id: u64, apn: &str) -> Option<SgwcSess> {
        let mut sess_list = self.sess_list.write().ok()?;
        let mut sgwc_sxa_seid_hash = self.sgwc_sxa_seid_hash.write().ok()?;

        if self.max_num_of_sess > 0 && sess_list.len() >= self.max_num_of_sess {
            log::error!("Maximum number of sessions [{}] reached", self.max_num_of_sess);
            return None;
        }

        let id = self.next_sess_id.fetch_add(1, Ordering::SeqCst) as u64;
        let seid = self.next_sxa_seid();
        let mut sess = SgwcSess::new(id, sgwc_ue_id);
        sess.sgw_s5c_teid = seid as u32;
        sess.sgwc_sxa_seid = seid;
        sess.set_apn(apn);

        sgwc_sxa_seid_hash.insert(seid, id);
        sess_list.insert(id, sess.clone());

        // Add session to UE's session list
        if let Ok(mut ue_list) = self.sgwc_ue_list.write() {
            if let Some(ue) = ue_list.get_mut(&sgwc_ue_id) {
                ue.sess_ids.push(id);
            }
        }

        log::info!("[Added] SGWC Session APN[{apn}] (id={id}, seid={seid})");
        Some(sess)
    }

    /// Remove a session by ID
    pub fn sess_remove(&self, id: u64) -> Option<SgwcSess> {
        // First, remove all bearers for this session
        self.bearer_remove_all_for_sess(id);

        let mut sess_list = self.sess_list.write().ok()?;
        let mut sgwc_sxa_seid_hash = self.sgwc_sxa_seid_hash.write().ok()?;

        if let Some(sess) = sess_list.remove(&id) {
            sgwc_sxa_seid_hash.remove(&sess.sgwc_sxa_seid);

            // Remove session from UE's session list
            if let Ok(mut ue_list) = self.sgwc_ue_list.write() {
                if let Some(ue) = ue_list.get_mut(&sess.sgwc_ue_id) {
                    ue.sess_ids.retain(|&sid| sid != id);
                }
            }

            log::info!("[Removed] SGWC Session (id={id})");
            return Some(sess);
        }
        None
    }

    /// Remove all sessions for a UE
    fn sess_remove_all_for_ue(&self, sgwc_ue_id: u64) {
        let sess_ids: Vec<u64> = {
            if let Ok(list) = self.sess_list.read() {
                list.values()
                    .filter(|s| s.sgwc_ue_id == sgwc_ue_id)
                    .map(|s| s.id)
                    .collect()
            } else {
                return;
            }
        };
        for id in sess_ids {
            self.sess_remove(id);
        }
    }

    /// Find session by ID
    pub fn sess_find_by_id(&self, id: u64) -> Option<SgwcSess> {
        self.sess_list.read().ok()?.get(&id).cloned()
    }

    /// Find session by SEID
    pub fn sess_find_by_seid(&self, seid: u64) -> Option<SgwcSess> {
        let sgwc_sxa_seid_hash = self.sgwc_sxa_seid_hash.read().ok()?;
        let id = sgwc_sxa_seid_hash.get(&seid)?;
        self.sess_find_by_id(*id)
    }

    /// Find session by TEID (same as SEID for SGWC)
    pub fn sess_find_by_teid(&self, teid: u32) -> Option<SgwcSess> {
        self.sess_find_by_seid(teid as u64)
    }

    /// Find session by APN for a UE
    pub fn sess_find_by_apn(&self, sgwc_ue_id: u64, apn: &str) -> Option<SgwcSess> {
        let sess_list = self.sess_list.read().ok()?;
        sess_list.values()
            .find(|s| s.sgwc_ue_id == sgwc_ue_id && s.apn() == Some(apn))
            .cloned()
    }

    /// Update session in context
    pub fn sess_update(&self, sess: &SgwcSess) -> bool {
        if let Ok(mut list) = self.sess_list.write() {
            list.insert(sess.id, sess.clone());
            return true;
        }
        false
    }

    /// Get session count
    pub fn sess_count(&self) -> usize {
        self.sess_list.read().map(|l| l.len()).unwrap_or(0)
    }

    // ========================================================================
    // Bearer Management
    // ========================================================================

    /// Add a new bearer
    pub fn bearer_add(&self, sess_id: u64) -> Option<SgwcBearer> {
        // Get session info first (releases lock immediately)
        let sgwc_ue_id = {
            let sess_list = self.sess_list.read().ok()?;
            sess_list.get(&sess_id)?.sgwc_ue_id
        };

        let id = self.next_bearer_id.fetch_add(1, Ordering::SeqCst) as u64;
        let bearer = SgwcBearer::new(id, sess_id, sgwc_ue_id);

        // Insert bearer
        {
            let mut bearer_list = self.bearer_list.write().ok()?;
            if self.max_num_of_bearer > 0 && bearer_list.len() >= self.max_num_of_bearer {
                log::error!("Maximum number of bearers [{}] reached", self.max_num_of_bearer);
                return None;
            }
            bearer_list.insert(id, bearer.clone());
        }

        // Add bearer to session's bearer list
        {
            if let Ok(mut sess_list) = self.sess_list.write() {
                if let Some(s) = sess_list.get_mut(&sess_id) {
                    s.bearer_ids.push(id);
                }
            }
        }

        // Add downlink and uplink tunnels
        self.tunnel_add(id, gtp_interface::S5_S8_SGW_GTP_U);
        self.tunnel_add(id, gtp_interface::S1_U_SGW_GTP_U);

        log::debug!("[Added] SGWC Bearer (id={id})");
        Some(bearer)
    }

    /// Remove a bearer by ID
    pub fn bearer_remove(&self, id: u64) -> Option<SgwcBearer> {
        // First, remove all tunnels for this bearer
        self.tunnel_remove_all_for_bearer(id);

        let mut bearer_list = self.bearer_list.write().ok()?;

        if let Some(bearer) = bearer_list.remove(&id) {
            // Remove bearer from session's bearer list
            if let Ok(mut sess_list) = self.sess_list.write() {
                if let Some(sess) = sess_list.get_mut(&bearer.sess_id) {
                    sess.bearer_ids.retain(|&bid| bid != id);
                }
            }

            log::debug!("[Removed] SGWC Bearer (id={id})");
            return Some(bearer);
        }
        None
    }

    /// Remove all bearers for a session
    fn bearer_remove_all_for_sess(&self, sess_id: u64) {
        let bearer_ids: Vec<u64> = {
            if let Ok(list) = self.bearer_list.read() {
                list.values()
                    .filter(|b| b.sess_id == sess_id)
                    .map(|b| b.id)
                    .collect()
            } else {
                return;
            }
        };
        for id in bearer_ids {
            self.bearer_remove(id);
        }
    }

    /// Find bearer by ID
    pub fn bearer_find_by_id(&self, id: u64) -> Option<SgwcBearer> {
        self.bearer_list.read().ok()?.get(&id).cloned()
    }

    /// Find bearer by session and EBI
    pub fn bearer_find_by_sess_ebi(&self, sess_id: u64, ebi: u8) -> Option<SgwcBearer> {
        let bearer_list = self.bearer_list.read().ok()?;
        bearer_list.values()
            .find(|b| b.sess_id == sess_id && b.ebi == ebi)
            .cloned()
    }

    /// Find bearer by UE and EBI
    pub fn bearer_find_by_ue_ebi(&self, sgwc_ue_id: u64, ebi: u8) -> Option<SgwcBearer> {
        let bearer_list = self.bearer_list.read().ok()?;
        bearer_list.values()
            .find(|b| b.sgwc_ue_id == sgwc_ue_id && b.ebi == ebi)
            .cloned()
    }

    /// Get default bearer in session
    pub fn default_bearer_in_sess(&self, sess_id: u64) -> Option<SgwcBearer> {
        let sess = self.sess_find_by_id(sess_id)?;
        sess.bearer_ids.first().and_then(|&id| self.bearer_find_by_id(id))
    }

    /// Update bearer in context
    pub fn bearer_update(&self, bearer: &SgwcBearer) -> bool {
        if let Ok(mut list) = self.bearer_list.write() {
            list.insert(bearer.id, bearer.clone());
            return true;
        }
        false
    }

    // ========================================================================
    // Tunnel Management
    // ========================================================================

    /// Add a new tunnel
    pub fn tunnel_add(&self, bearer_id: u64, interface_type: u8) -> Option<SgwcTunnel> {
        let id = self.next_tunnel_id.fetch_add(1, Ordering::SeqCst) as u64;
        let tunnel = SgwcTunnel::new(id, bearer_id, interface_type);

        // Insert tunnel
        {
            let mut tunnel_list = self.tunnel_list.write().ok()?;
            if self.max_num_of_tunnel > 0 && tunnel_list.len() >= self.max_num_of_tunnel {
                log::error!("Maximum number of tunnels [{}] reached", self.max_num_of_tunnel);
                return None;
            }
            tunnel_list.insert(id, tunnel.clone());
        }

        // Add tunnel to bearer's tunnel list
        {
            if let Ok(mut bearer_list) = self.bearer_list.write() {
                if let Some(bearer) = bearer_list.get_mut(&bearer_id) {
                    bearer.tunnel_ids.push(id);
                }
            }
        }

        log::debug!("[Added] SGWC Tunnel (id={id}, type={interface_type})");
        Some(tunnel)
    }

    /// Remove a tunnel by ID
    pub fn tunnel_remove(&self, id: u64) -> Option<SgwcTunnel> {
        let mut tunnel_list = self.tunnel_list.write().ok()?;

        if let Some(tunnel) = tunnel_list.remove(&id) {
            // Remove tunnel from bearer's tunnel list
            if let Ok(mut bearer_list) = self.bearer_list.write() {
                if let Some(bearer) = bearer_list.get_mut(&tunnel.bearer_id) {
                    bearer.tunnel_ids.retain(|&tid| tid != id);
                }
            }

            log::debug!("[Removed] SGWC Tunnel (id={id})");
            return Some(tunnel);
        }
        None
    }

    /// Remove all tunnels for a bearer
    fn tunnel_remove_all_for_bearer(&self, bearer_id: u64) {
        let tunnel_ids: Vec<u64> = {
            if let Ok(list) = self.tunnel_list.read() {
                list.values()
                    .filter(|t| t.bearer_id == bearer_id)
                    .map(|t| t.id)
                    .collect()
            } else {
                return;
            }
        };
        for id in tunnel_ids {
            self.tunnel_remove(id);
        }
    }

    /// Find tunnel by ID
    pub fn tunnel_find_by_id(&self, id: u64) -> Option<SgwcTunnel> {
        self.tunnel_list.read().ok()?.get(&id).cloned()
    }

    /// Find tunnel by bearer and interface type
    pub fn tunnel_find_by_interface_type(&self, bearer_id: u64, interface_type: u8) -> Option<SgwcTunnel> {
        let tunnel_list = self.tunnel_list.read().ok()?;
        tunnel_list.values()
            .find(|t| t.bearer_id == bearer_id && t.interface_type == interface_type)
            .cloned()
    }

    /// Get downlink tunnel in bearer
    pub fn dl_tunnel_in_bearer(&self, bearer_id: u64) -> Option<SgwcTunnel> {
        self.tunnel_find_by_interface_type(bearer_id, gtp_interface::S5_S8_SGW_GTP_U)
    }

    /// Get uplink tunnel in bearer
    pub fn ul_tunnel_in_bearer(&self, bearer_id: u64) -> Option<SgwcTunnel> {
        self.tunnel_find_by_interface_type(bearer_id, gtp_interface::S1_U_SGW_GTP_U)
    }

    /// Update tunnel in context
    pub fn tunnel_update(&self, tunnel: &SgwcTunnel) -> bool {
        if let Ok(mut list) = self.tunnel_list.write() {
            list.insert(tunnel.id, tunnel.clone());
            return true;
        }
        false
    }
}

impl Default for SgwcContext {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global Context Instance
// ============================================================================

use std::sync::OnceLock;

static SGWC_CONTEXT: OnceLock<Arc<SgwcContext>> = OnceLock::new();

/// Get the global SGWC context
pub fn sgwc_self() -> Arc<SgwcContext> {
    SGWC_CONTEXT.get_or_init(|| Arc::new(SgwcContext::new())).clone()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ue_add_remove() {
        let ctx = SgwcContext::new();
        let imsi = vec![0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x01];
        
        let ue = ctx.ue_add(&imsi).unwrap();
        assert!(!ue.imsi_bcd.is_empty());
        assert_eq!(ctx.ue_count(), 1);
        
        let found = ctx.ue_find_by_imsi(&imsi).unwrap();
        assert_eq!(found.id, ue.id);
        
        let found = ctx.ue_find_by_teid(ue.sgw_s11_teid).unwrap();
        assert_eq!(found.id, ue.id);
        
        ctx.ue_remove(ue.id);
        assert_eq!(ctx.ue_count(), 0);
    }

    #[test]
    fn test_sess_add_remove() {
        let ctx = SgwcContext::new();
        let imsi = vec![0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x02];
        
        let ue = ctx.ue_add(&imsi).unwrap();
        let sess = ctx.sess_add(ue.id, "internet").unwrap();
        assert_eq!(sess.apn(), Some("internet"));
        assert_eq!(ctx.sess_count(), 1);
        
        let found = ctx.sess_find_by_seid(sess.sgwc_sxa_seid).unwrap();
        assert_eq!(found.id, sess.id);
        
        let found = ctx.sess_find_by_apn(ue.id, "internet").unwrap();
        assert_eq!(found.id, sess.id);
        
        ctx.sess_remove(sess.id);
        assert_eq!(ctx.sess_count(), 0);
    }

    #[test]
    fn test_bearer_add_remove() {
        let ctx = SgwcContext::new();
        let imsi = vec![0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x03];
        
        let ue = ctx.ue_add(&imsi).unwrap();
        let sess = ctx.sess_add(ue.id, "internet").unwrap();
        let bearer = ctx.bearer_add(sess.id).unwrap();
        
        // Bearer should have DL and UL tunnels
        let dl = ctx.dl_tunnel_in_bearer(bearer.id);
        let ul = ctx.ul_tunnel_in_bearer(bearer.id);
        assert!(dl.is_some());
        assert!(ul.is_some());
        
        ctx.bearer_remove(bearer.id);
        assert!(ctx.dl_tunnel_in_bearer(bearer.id).is_none());
    }

    #[test]
    fn test_cascade_remove() {
        let ctx = SgwcContext::new();
        let imsi = vec![0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x04];
        
        let ue = ctx.ue_add(&imsi).unwrap();
        let sess = ctx.sess_add(ue.id, "internet").unwrap();
        let _bearer = ctx.bearer_add(sess.id).unwrap();
        
        // Removing UE should cascade to sessions, bearers, tunnels
        ctx.ue_remove(ue.id);
        assert_eq!(ctx.ue_count(), 0);
        assert_eq!(ctx.sess_count(), 0);
    }
}
