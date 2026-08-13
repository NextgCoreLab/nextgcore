//! PCRF Context Management
//!
//! Port of src/pcrf/pcrf-context.c - PCRF context with IP hash tables for
//! Gx session lookup, DB operations, and session management

use serde::Deserialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

/// Maximum number of PCC rules per session
pub const NEXTGCORE_MAX_NUM_OF_PCC_RULE: usize = 8;

/// IPv6 address length in bytes
pub const NEXTGCORE_IPV6_LEN: usize = 16;

/// PCRF Rx Session State - represents an Rx session linked to a Gx session
#[derive(Debug, Clone)]
pub struct PcrfRxSession {
    /// Rx Session-Id
    pub sid: String,
    /// Associated Gx Session index
    pub gx_session_idx: usize,
    /// Peer host (AF / P-CSCF Origin-Host) for PCRF-initiated ASR
    pub peer_host: Option<String>,
    /// PCC rules installed on behalf of this Rx session
    pub pcc_rules: Vec<PccRule>,
}

impl PcrfRxSession {
    /// Create a new Rx session
    pub fn new(sid: &str, gx_session_idx: usize) -> Self {
        Self {
            sid: sid.to_string(),
            gx_session_idx,
            peer_host: None,
            pcc_rules: Vec::new(),
        }
    }
}

/// PCC Rule structure
#[derive(Debug, Clone)]
pub struct PccRule {
    /// Rule name
    pub name: String,
    /// QoS index
    pub qos_index: u8,
    /// Flow status
    pub flow_status: i32,
    /// Precedence
    pub precedence: u32,
    /// Number of flows
    pub num_of_flow: usize,
}

/// PCRF Gx Session State - represents a Gx session with P-GW
#[derive(Debug, Clone)]
pub struct PcrfGxSession {
    /// Gx Session-Id
    pub sid: String,
    /// Peer host (P-GW)
    pub peer_host: Option<String>,
    /// IMSI BCD string
    pub imsi_bcd: Option<String>,
    /// APN
    pub apn: Option<String>,
    /// Has IPv4 address
    pub has_ipv4: bool,
    /// Framed IPv4 address
    pub ipv4_addr: Option<Ipv4Addr>,
    /// Has IPv6 address
    pub has_ipv6: bool,
    /// Framed IPv6 prefix
    pub ipv6_addr: Option<[u8; NEXTGCORE_IPV6_LEN]>,
    /// RAT type
    pub rat_type: u32,
    /// List of Rx session indices
    pub rx_sessions: Vec<usize>,
}

impl PcrfGxSession {
    /// Create a new Gx session
    pub fn new(sid: &str) -> Self {
        Self {
            sid: sid.to_string(),
            peer_host: None,
            imsi_bcd: None,
            apn: None,
            has_ipv4: false,
            ipv4_addr: None,
            has_ipv6: false,
            ipv6_addr: None,
            rat_type: 0,
            rx_sessions: Vec::new(),
        }
    }

    /// Set peer host
    pub fn set_peer_host(&mut self, host: &str) {
        self.peer_host = Some(host.to_string());
    }

    /// Set IMSI
    pub fn set_imsi(&mut self, imsi: &str) {
        self.imsi_bcd = Some(imsi.to_string());
    }

    /// Set APN
    pub fn set_apn(&mut self, apn: &str) {
        self.apn = Some(apn.to_string());
    }

    /// Set IPv4 address
    pub fn set_ipv4(&mut self, addr: Ipv4Addr) {
        self.ipv4_addr = Some(addr);
        self.has_ipv4 = true;
    }

    /// Set IPv6 prefix
    pub fn set_ipv6(&mut self, addr: [u8; NEXTGCORE_IPV6_LEN]) {
        self.ipv6_addr = Some(addr);
        self.has_ipv6 = true;
    }

    /// Add Rx session
    pub fn add_rx_session(&mut self, rx_idx: usize) {
        if !self.rx_sessions.contains(&rx_idx) {
            self.rx_sessions.push(rx_idx);
        }
    }

    /// Remove Rx session
    pub fn remove_rx_session(&mut self, rx_idx: usize) {
        self.rx_sessions.retain(|&idx| idx != rx_idx);
    }
}

/// Diameter configuration
#[derive(Debug, Clone, Default)]
pub struct DiamConfig {
    /// Diameter identity
    pub cnf_diamid: Option<String>,
    /// Diameter realm
    pub cnf_diamrlm: Option<String>,
    /// Listen address
    pub cnf_addr: Option<String>,
    /// Port
    pub cnf_port: u16,
    /// TLS port
    pub cnf_port_tls: u16,
}

/// PCRF Context - main context structure for PCRF
pub struct PcrfContext {
    /// Diameter configuration file path
    pub diam_conf_path: Option<String>,
    /// Diameter configuration
    pub diam_config: DiamConfig,

    /// Database lock for thread-safe DB operations
    db_lock: Mutex<()>,

    /// Gx session list
    gx_sessions: RwLock<Vec<PcrfGxSession>>,
    /// Gx session hash by Session-Id
    gx_sid_hash: RwLock<HashMap<String, usize>>,
    /// IPv4 to Gx Session-Id mapping
    ipv4_hash: RwLock<HashMap<u32, String>>,
    /// IPv6 to Gx Session-Id mapping
    ipv6_hash: RwLock<HashMap<[u8; NEXTGCORE_IPV6_LEN], String>>,

    /// Rx session list
    rx_sessions: RwLock<Vec<PcrfRxSession>>,
    /// Rx session hash by Session-Id
    rx_sid_hash: RwLock<HashMap<String, usize>>,

    /// Context initialized flag
    initialized: AtomicBool,
    /// Maximum sessions
    max_sess: AtomicUsize,
}

impl PcrfContext {
    /// Create a new PCRF context
    pub fn new() -> Self {
        Self {
            diam_conf_path: None,
            diam_config: DiamConfig {
                cnf_port: 3868,
                cnf_port_tls: 5868,
                ..Default::default()
            },
            db_lock: Mutex::new(()),
            gx_sessions: RwLock::new(Vec::new()),
            gx_sid_hash: RwLock::new(HashMap::new()),
            ipv4_hash: RwLock::new(HashMap::new()),
            ipv6_hash: RwLock::new(HashMap::new()),
            rx_sessions: RwLock::new(Vec::new()),
            rx_sid_hash: RwLock::new(HashMap::new()),
            initialized: AtomicBool::new(false),
            max_sess: AtomicUsize::new(1024),
        }
    }

    /// Initialize the PCRF context
    pub fn init(&mut self, max_sess: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }

        self.max_sess.store(max_sess, Ordering::SeqCst);
        self.initialized.store(true, Ordering::SeqCst);

        log::info!("PCRF context initialized (max_sess={max_sess})");
    }

    /// Finalize the PCRF context
    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }

        // Clear all sessions
        self.gx_session_remove_all();
        self.rx_session_remove_all();

        self.initialized.store(false, Ordering::SeqCst);
        log::info!("PCRF context finalized");
    }

    /// Check if context is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    // ========== Gx Session Management ==========

    /// Add a new Gx session
    pub fn gx_session_add(&self, sid: &str) -> Option<usize> {
        let mut sessions = self.gx_sessions.write().ok()?;
        let mut hash = self.gx_sid_hash.write().ok()?;

        if hash.contains_key(sid) {
            return hash.get(sid).copied();
        }

        let session = PcrfGxSession::new(sid);
        let idx = sessions.len();
        sessions.push(session);
        hash.insert(sid.to_string(), idx);

        log::debug!("Gx session added: {sid}");
        Some(idx)
    }

    /// Find Gx session by Session-Id
    pub fn gx_session_find_by_sid(&self, sid: &str) -> Option<PcrfGxSession> {
        let sessions = self.gx_sessions.read().ok()?;
        let hash = self.gx_sid_hash.read().ok()?;

        hash.get(sid).and_then(|&idx| sessions.get(idx).cloned())
    }

    /// Get Gx session index by Session-Id
    pub fn gx_session_get_idx(&self, sid: &str) -> Option<usize> {
        let hash = self.gx_sid_hash.read().ok()?;
        hash.get(sid).copied()
    }

    /// Update Gx session
    pub fn gx_session_update<F>(&self, sid: &str, f: F) -> bool
    where
        F: FnOnce(&mut PcrfGxSession),
    {
        if let (Ok(mut sessions), Ok(hash)) = (self.gx_sessions.write(), self.gx_sid_hash.read()) {
            if let Some(&idx) = hash.get(sid) {
                if let Some(session) = sessions.get_mut(idx) {
                    f(session);
                    return true;
                }
            }
        }
        false
    }

    /// Remove Gx session
    pub fn gx_session_remove(&self, sid: &str) -> bool {
        // AB-BA: primary list (gx_sessions) before index/IP hashes — canonical order
        let sessions = self.gx_sessions.read();
        let mut hash = self.gx_sid_hash.write().unwrap();
        let mut ipv4_hash = self.ipv4_hash.write().unwrap();
        let mut ipv6_hash = self.ipv6_hash.write().unwrap();

        if let Some(&idx) = hash.get(sid) {
            // Remove IP mappings
            if let Ok(ref sessions) = sessions {
                if let Some(session) = sessions.get(idx) {
                    if let Some(addr) = session.ipv4_addr {
                        ipv4_hash.remove(&u32::from(addr));
                    }
                    if let Some(addr) = session.ipv6_addr {
                        ipv6_hash.remove(&addr);
                    }
                }
            }
            hash.remove(sid);
            log::debug!("Gx session removed: {sid}");
            return true;
        }
        false
    }

    /// Remove all Gx sessions
    pub fn gx_session_remove_all(&self) {
        if let (Ok(mut sessions), Ok(mut hash), Ok(mut ipv4), Ok(mut ipv6)) = (
            self.gx_sessions.write(),
            self.gx_sid_hash.write(),
            self.ipv4_hash.write(),
            self.ipv6_hash.write(),
        ) {
            sessions.clear();
            hash.clear();
            ipv4.clear();
            ipv6.clear();
        }
    }

    /// Get Gx session count
    pub fn gx_session_count(&self) -> usize {
        self.gx_sid_hash.read().map(|h| h.len()).unwrap_or(0)
    }

    // ========== IP Address Mapping ==========

    /// Set IPv4 to Session-Id mapping
    pub fn set_ipv4_mapping(&self, addr: &[u8; 4], sid: Option<&str>) {
        let mut hash = self.ipv4_hash.write().unwrap();
        let key = u32::from_be_bytes(*addr);

        if let Some(sid) = sid {
            hash.insert(key, sid.to_string());
            log::debug!("IPv4 mapping set: {addr:?} -> {sid}");
        } else {
            hash.remove(&key);
            log::debug!("IPv4 mapping removed: {addr:?}");
        }
    }

    /// Set IPv6 to Session-Id mapping
    pub fn set_ipv6_mapping(&self, addr: &[u8; NEXTGCORE_IPV6_LEN], sid: Option<&str>) {
        let mut hash = self.ipv6_hash.write().unwrap();

        if let Some(sid) = sid {
            hash.insert(*addr, sid.to_string());
            log::debug!("IPv6 mapping set: {addr:?} -> {sid}");
        } else {
            hash.remove(addr);
            log::debug!("IPv6 mapping removed: {addr:?}");
        }
    }

    /// Find Session-Id by IPv4 address
    pub fn find_sid_by_ipv4(&self, addr: &[u8; 4]) -> Option<String> {
        let hash = self.ipv4_hash.read().ok()?;
        let key = u32::from_be_bytes(*addr);
        hash.get(&key).cloned()
    }

    /// Find Session-Id by IPv6 address
    pub fn find_sid_by_ipv6(&self, addr: &[u8; NEXTGCORE_IPV6_LEN]) -> Option<String> {
        let hash = self.ipv6_hash.read().ok()?;
        hash.get(addr).cloned()
    }

    // ========== Rx Session Management ==========

    /// Add a new Rx session
    pub fn rx_session_add(&self, sid: &str, gx_session_idx: usize) -> Option<usize> {
        let mut sessions = self.rx_sessions.write().ok()?;
        let mut hash = self.rx_sid_hash.write().ok()?;

        if hash.contains_key(sid) {
            return hash.get(sid).copied();
        }

        let session = PcrfRxSession::new(sid, gx_session_idx);
        let idx = sessions.len();
        sessions.push(session);
        hash.insert(sid.to_string(), idx);

        // Add to Gx session's rx_sessions list
        if let Ok(mut gx_sessions) = self.gx_sessions.write() {
            if let Some(gx_session) = gx_sessions.get_mut(gx_session_idx) {
                gx_session.add_rx_session(idx);
            }
        }

        log::debug!("Rx session added: {sid} (gx_idx={gx_session_idx})");
        Some(idx)
    }

    /// Find Rx session by Session-Id
    pub fn rx_session_find_by_sid(&self, sid: &str) -> Option<PcrfRxSession> {
        let sessions = self.rx_sessions.read().ok()?;
        let hash = self.rx_sid_hash.read().ok()?;

        hash.get(sid).and_then(|&idx| sessions.get(idx).cloned())
    }

    /// Find Rx session by index (as referenced from a Gx session binding)
    pub fn rx_session_find_by_idx(&self, idx: usize) -> Option<PcrfRxSession> {
        let sessions = self.rx_sessions.read().ok()?;
        let hash = self.rx_sid_hash.read().ok()?;
        let session = sessions.get(idx)?;
        // Only return the session if it is still registered (not removed)
        if hash.get(&session.sid) == Some(&idx) {
            Some(session.clone())
        } else {
            None
        }
    }

    /// Update Rx session
    pub fn rx_session_update<F>(&self, sid: &str, f: F) -> bool
    where
        F: FnOnce(&mut PcrfRxSession),
    {
        if let (Ok(mut sessions), Ok(hash)) = (self.rx_sessions.write(), self.rx_sid_hash.read()) {
            if let Some(&idx) = hash.get(sid) {
                if let Some(session) = sessions.get_mut(idx) {
                    f(session);
                    return true;
                }
            }
        }
        false
    }

    /// Find Gx session by index (as referenced from an Rx session binding)
    pub fn gx_session_find_by_idx(&self, idx: usize) -> Option<PcrfGxSession> {
        let sessions = self.gx_sessions.read().ok()?;
        let hash = self.gx_sid_hash.read().ok()?;
        let session = sessions.get(idx)?;
        // Only return the session if it is still registered (not removed)
        if hash.get(&session.sid) == Some(&idx) {
            Some(session.clone())
        } else {
            None
        }
    }

    /// Remove Rx session
    pub fn rx_session_remove(&self, sid: &str) -> bool {
        // AB-BA: primary list (rx_sessions) before index (rx_sid_hash) — canonical order
        let rx_sessions = self.rx_sessions.read();
        let mut hash = self.rx_sid_hash.write().unwrap();

        if let Some(&idx) = hash.get(sid) {
            // Remove from Gx session's rx_sessions list
            if let Ok(ref rx_sessions) = rx_sessions {
                if let Some(rx_session) = rx_sessions.get(idx) {
                    let gx_idx = rx_session.gx_session_idx;
                    if let Ok(mut gx_sessions) = self.gx_sessions.write() {
                        if let Some(gx_session) = gx_sessions.get_mut(gx_idx) {
                            gx_session.remove_rx_session(idx);
                        }
                    }
                }
            }
            hash.remove(sid);
            log::debug!("Rx session removed: {sid}");
            return true;
        }
        false
    }

    /// Remove all Rx sessions
    pub fn rx_session_remove_all(&self) {
        if let (Ok(mut sessions), Ok(mut hash)) =
            (self.rx_sessions.write(), self.rx_sid_hash.write())
        {
            sessions.clear();
            hash.clear();
        }
    }

    /// Get Rx session count
    pub fn rx_session_count(&self) -> usize {
        self.rx_sid_hash.read().map(|h| h.len()).unwrap_or(0)
    }

    // ========== Database Operations ==========

    /// Lock database for thread-safe operations
    pub fn db_lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.db_lock.lock().unwrap()
    }
}

impl Default for PcrfContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global PCRF context (thread-safe singleton)
static GLOBAL_PCRF_CONTEXT: std::sync::OnceLock<Arc<RwLock<PcrfContext>>> =
    std::sync::OnceLock::new();

/// Get the global PCRF context
pub fn pcrf_self() -> Arc<RwLock<PcrfContext>> {
    GLOBAL_PCRF_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(PcrfContext::new())))
        .clone()
}

/// Initialize the global PCRF context
pub fn pcrf_context_init(max_sess: usize) {
    let ctx = pcrf_self();
    let result = ctx.write();
    if let Ok(mut context) = result {
        context.init(max_sess);
    }
}

/// Finalize the global PCRF context
pub fn pcrf_context_final() {
    let ctx = pcrf_self();
    let result = ctx.write();
    if let Ok(mut context) = result {
        context.fini();
    }
}

// ---------------------------------------------------------------------------
// YAML configuration (`pcrf:` section)
// ---------------------------------------------------------------------------

/// The `pcrf.diameter` block: this node's Diameter identity and listener.
///
/// Only the keys `PcrfContext`'s [`DiamConfig`] can hold are declared. It is a
/// smaller struct than the HSS's -- no Tc timer, no forwarding flag, no peer
/// connections -- so those keys are deliberately absent here rather than parsed
/// and dropped, which would be the same silently-ignored-config defect this
/// change removes.
#[derive(Debug, Default, Deserialize)]
pub struct DiameterYaml {
    /// Origin-Host (RFC 6733 §6.3) — this node's Diameter identity.
    pub identity: Option<String>,
    /// Origin-Realm (RFC 6733 §6.4).
    pub realm: Option<String>,
    /// Listen address for the shared Gx + Rx listener.
    pub addr: Option<String>,
    pub port: Option<u16>,
    pub port_tls: Option<u16>,
}

/// The `pcrf:` section. Unknown keys are ignored: the shipped configs carry
/// `freeDiameter:` and `metrics:` keys owned by other subsystems.
#[derive(Debug, Default, Deserialize)]
pub struct PcrfSectionYaml {
    pub diameter: Option<DiameterYaml>,
    /// Path to a freeDiameter-style config, recorded for diagnosis only; this
    /// daemon does not parse that format.
    #[serde(rename = "freeDiameter")]
    pub free_diameter: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct PcrfYaml {
    pub pcrf: Option<PcrfSectionYaml>,
}

/// Parse PCRF configuration from YAML and apply it to the global context.
///
/// # Why this exists
///
/// This function used to `return Ok(())` without reading the file, while
/// `main()` logged "Loading configuration from <file>". The only source of the
/// Diameter identity was therefore the CLI, whose defaults are
/// `pcrf.localdomain` / `localdomain` -- well-formed but matching no real
/// deployment, so Gx/Rx peers fail realm-based routing (RFC 6733 §6.1) until
/// flags are supplied, and the config file could not fix it.
///
/// Unlike the HSS, pcrfd does expose `--diameter-id`/`--diameter-realm`/
/// `--diameter-addr`, so those flags remain a valid workaround. `main()` applies
/// YAML first and lets an EXPLICITLY-passed flag win; see its
/// `resolve_diameter_identity`.
///
/// # Errors
///
/// Returns `Err` when the file cannot be read or is not valid YAML — a fatal
/// condition for `main()`, deliberately not a warn-and-continue, because
/// silently falling back to `localdomain` is much harder to diagnose than a
/// refusal to start. A file with no `pcrf.diameter` block is not an error: the
/// shipped `docker/rust/configs/epc/pcrf.yaml` is exactly that.
pub fn pcrf_context_parse_config(config_path: &str) -> Result<(), String> {
    let content = std::fs::read_to_string(config_path)
        .map_err(|e| format!("cannot read {config_path}: {e}"))?;

    let parsed: PcrfYaml = serde_yaml::from_str(&content)
        .map_err(|e| format!("invalid YAML in {config_path}: {e}"))?;

    let Some(section) = parsed.pcrf else {
        log::debug!("{config_path}: no 'pcrf' section; keeping defaults");
        return Ok(());
    };

    let ctx = pcrf_self();
    let mut ctx = ctx
        .write()
        .map_err(|_| "PCRF context lock poisoned".to_string())?;

    if let Some(path) = section.free_diameter {
        ctx.diam_conf_path = Some(path);
    }

    let Some(diam) = section.diameter else {
        log::debug!("{config_path}: no 'pcrf.diameter' block; keeping defaults");
        return Ok(());
    };

    apply_diameter_yaml(&mut ctx.diam_config, diam);
    Ok(())
}

/// Copy the parsed `diameter` block onto a [`DiamConfig`].
///
/// Absent keys leave the existing value untouched, so a partial config cannot
/// zero `cnf_port`. Shared with the unit tests so the mapping is verified
/// directly rather than only through `main()`.
pub fn apply_diameter_yaml(cfg: &mut DiamConfig, diam: DiameterYaml) {
    if let Some(v) = diam.identity {
        cfg.cnf_diamid = Some(v);
    }
    if let Some(v) = diam.realm {
        cfg.cnf_diamrlm = Some(v);
    }
    if let Some(v) = diam.addr {
        cfg.cnf_addr = Some(v);
    }
    if let Some(v) = diam.port {
        cfg.cnf_port = v;
    }
    if let Some(v) = diam.port_tls {
        cfg.cnf_port_tls = v;
    }
}

/// Set IPv4 to Session-Id mapping (global function)
pub fn pcrf_sess_set_ipv4(addr: &[u8; 4], sid: Option<&str>) {
    let ctx = pcrf_self();
    let result = ctx.read();
    if let Ok(context) = result {
        context.set_ipv4_mapping(addr, sid);
    }
}

/// Set IPv6 to Session-Id mapping (global function)
pub fn pcrf_sess_set_ipv6(addr: &[u8; NEXTGCORE_IPV6_LEN], sid: Option<&str>) {
    let ctx = pcrf_self();
    let result = ctx.read();
    if let Ok(context) = result {
        context.set_ipv6_mapping(addr, sid);
    }
}

/// Find Session-Id by IPv4 address (global function)
pub fn pcrf_sess_find_by_ipv4(addr: &[u8; 4]) -> Option<String> {
    let ctx = pcrf_self();
    let result = ctx.read();
    if let Ok(context) = result {
        return context.find_sid_by_ipv4(addr);
    }
    None
}

/// Find Session-Id by IPv6 address (global function)
pub fn pcrf_sess_find_by_ipv6(addr: &[u8; NEXTGCORE_IPV6_LEN]) -> Option<String> {
    let ctx = pcrf_self();
    let result = ctx.read();
    if let Ok(context) = result {
        return context.find_sid_by_ipv6(addr);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcrf_context_new() {
        let ctx = PcrfContext::new();
        assert!(!ctx.is_initialized());
        assert_eq!(ctx.gx_session_count(), 0);
        assert_eq!(ctx.rx_session_count(), 0);
    }

    #[test]
    fn test_pcrf_context_init_fini() {
        let mut ctx = PcrfContext::new();
        ctx.init(1024);
        assert!(ctx.is_initialized());

        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_gx_session_add_remove() {
        let mut ctx = PcrfContext::new();
        ctx.init(1024);

        let _idx = ctx.gx_session_add("gx-session-1").unwrap();
        assert_eq!(ctx.gx_session_count(), 1);

        let session = ctx.gx_session_find_by_sid("gx-session-1");
        assert!(session.is_some());
        assert_eq!(session.unwrap().sid, "gx-session-1");

        ctx.gx_session_remove("gx-session-1");
        assert_eq!(ctx.gx_session_count(), 0);
    }

    #[test]
    fn test_gx_session_update() {
        let mut ctx = PcrfContext::new();
        ctx.init(1024);

        ctx.gx_session_add("gx-session-1");

        ctx.gx_session_update("gx-session-1", |session| {
            session.set_imsi("123456789012345");
            session.set_apn("internet");
        });

        let session = ctx.gx_session_find_by_sid("gx-session-1").unwrap();
        assert_eq!(session.imsi_bcd, Some("123456789012345".to_string()));
        assert_eq!(session.apn, Some("internet".to_string()));
    }

    #[test]
    fn test_ipv4_mapping() {
        let mut ctx = PcrfContext::new();
        ctx.init(1024);

        ctx.gx_session_add("gx-session-1");

        let addr: [u8; 4] = [192, 168, 1, 1];
        ctx.set_ipv4_mapping(&addr, Some("gx-session-1"));

        let sid = ctx.find_sid_by_ipv4(&addr);
        assert_eq!(sid, Some("gx-session-1".to_string()));

        ctx.set_ipv4_mapping(&addr, None);
        let sid = ctx.find_sid_by_ipv4(&addr);
        assert!(sid.is_none());
    }

    #[test]
    fn test_ipv6_mapping() {
        let mut ctx = PcrfContext::new();
        ctx.init(1024);

        ctx.gx_session_add("gx-session-1");

        let addr: [u8; NEXTGCORE_IPV6_LEN] = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        ctx.set_ipv6_mapping(&addr, Some("gx-session-1"));

        let sid = ctx.find_sid_by_ipv6(&addr);
        assert_eq!(sid, Some("gx-session-1".to_string()));
    }

    #[test]
    fn test_rx_session_add_remove() {
        let mut ctx = PcrfContext::new();
        ctx.init(1024);

        let gx_idx = ctx.gx_session_add("gx-session-1").unwrap();
        let rx_idx = ctx.rx_session_add("rx-session-1", gx_idx).unwrap();

        assert_eq!(ctx.rx_session_count(), 1);

        let rx_session = ctx.rx_session_find_by_sid("rx-session-1");
        assert!(rx_session.is_some());
        assert_eq!(rx_session.unwrap().gx_session_idx, gx_idx);

        // Check Gx session has Rx session reference
        let gx_session = ctx.gx_session_find_by_sid("gx-session-1").unwrap();
        assert!(gx_session.rx_sessions.contains(&rx_idx));

        ctx.rx_session_remove("rx-session-1");
        assert_eq!(ctx.rx_session_count(), 0);
    }

    #[test]
    fn test_pcrf_gx_session() {
        let mut session = PcrfGxSession::new("test-session");
        assert_eq!(session.sid, "test-session");
        assert!(session.peer_host.is_none());

        session.set_peer_host("pgw.example.com");
        assert_eq!(session.peer_host, Some("pgw.example.com".to_string()));

        session.set_imsi("123456789012345");
        assert_eq!(session.imsi_bcd, Some("123456789012345".to_string()));

        session.set_apn("internet");
        assert_eq!(session.apn, Some("internet".to_string()));

        session.set_ipv4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(session.has_ipv4);
        assert_eq!(session.ipv4_addr, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_pcrf_rx_session() {
        let session = PcrfRxSession::new("rx-session-1", 0);
        assert_eq!(session.sid, "rx-session-1");
        assert_eq!(session.gx_session_idx, 0);
        assert!(session.pcc_rules.is_empty());
    }
}
