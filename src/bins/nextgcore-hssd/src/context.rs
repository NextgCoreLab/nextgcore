//! HSS Context Management
//!
//! Port of src/hss/hss-context.c - HSS context with IMSI/IMPI/IMPU hash tables,
//! DB operations, and CX identity management

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

/// Maximum IMSI BCD length
pub const NEXTGCORE_MAX_IMSI_BCD_LEN: usize = 15;

/// SUPI type prefix for IMSI
pub const NEXTGCORE_ID_SUPI_TYPE_IMSI: &str = "imsi";

/// HSS IMSI structure - represents an IMSI identity for S6a interface
#[derive(Debug, Clone)]
pub struct HssImsi {
    /// IMSI BCD string
    pub id: String,
    /// Visited network identifier
    pub visited_network_identifier: Option<String>,
}

impl HssImsi {
    /// Create a new IMSI
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            visited_network_identifier: None,
        }
    }

    /// Set visited network identifier
    pub fn set_visited_network_identifier(&mut self, vni: &str) {
        self.visited_network_identifier = Some(vni.to_string());
    }
}

/// HSS IMPI structure - represents an IMS Private Identity for Cx interface
#[derive(Debug, Clone)]
pub struct HssImpi {
    /// IMPI string (user_name)
    pub id: String,
    /// Associated IMSI
    pub imsi: Option<String>,
    /// List of associated IMPUs
    pub impu_list: Vec<String>,
}

impl HssImpi {
    /// Create a new IMPI
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            imsi: None,
            impu_list: Vec::new(),
        }
    }

    /// Add an IMPU to this IMPI
    pub fn add_impu(&mut self, impu_id: &str) {
        if !self.impu_list.contains(&impu_id.to_string()) {
            self.impu_list.push(impu_id.to_string());
        }
    }

    /// Remove an IMPU from this IMPI
    pub fn remove_impu(&mut self, impu_id: &str) {
        self.impu_list.retain(|id| id != impu_id);
    }

    /// Set associated IMSI
    pub fn set_imsi(&mut self, imsi_bcd: &str) {
        self.imsi = Some(imsi_bcd.to_string());
    }
}

/// HSS IMPU structure - represents an IMS Public Identity for Cx interface
#[derive(Debug, Clone)]
pub struct HssImpu {
    /// IMPU string (public_identity)
    pub id: String,
    /// Associated server name (S-CSCF)
    pub server_name: Option<String>,
    /// Associated IMPI ID
    pub impi_id: String,
}

impl HssImpu {
    /// Create a new IMPU
    pub fn new(id: &str, impi_id: &str) -> Self {
        Self {
            id: id.to_string(),
            server_name: None,
            impi_id: impi_id.to_string(),
        }
    }

    /// Set server name
    pub fn set_server_name(&mut self, server_name: &str) {
        self.server_name = Some(server_name.to_string());
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
    /// No forwarding flag
    pub cnf_flags_no_fwd: bool,
    /// Tc timer
    pub cnf_timer_tc: i32,
    /// Extensions
    pub extensions: Vec<DiamExtension>,
    /// Connections
    pub connections: Vec<DiamConnection>,
    /// Stats interval
    pub stats_interval_sec: i32,
}

/// Diameter extension configuration
#[derive(Debug, Clone)]
pub struct DiamExtension {
    pub module: String,
    pub conf: Option<String>,
}

/// Diameter connection configuration
#[derive(Debug, Clone)]
pub struct DiamConnection {
    pub identity: String,
    pub addr: String,
    pub port: u16,
    pub tc_timer: i32,
}

/// HSS Context - main context structure for HSS
pub struct HssContext {
    /// Diameter configuration file path
    pub diam_conf_path: Option<String>,
    /// Diameter configuration
    pub diam_config: DiamConfig,
    /// SMS over IMS server name
    pub sms_over_ims: Option<String>,
    /// Use MongoDB change stream
    pub use_mongodb_change_stream: bool,

    /// Database lock
    db_lock: Mutex<()>,
    /// Cx interface lock
    cx_lock: Mutex<()>,

    /// IMSI list (S6a interface)
    imsi_list: RwLock<Vec<HssImsi>>,
    /// IMSI hash table
    imsi_hash: RwLock<HashMap<String, usize>>,

    /// IMPI list (Cx interface)
    impi_list: RwLock<Vec<HssImpi>>,
    /// IMPI hash table
    impi_hash: RwLock<HashMap<String, usize>>,
    /// IMPU hash table (maps IMPU ID to IMPI index)
    impu_hash: RwLock<HashMap<String, (usize, usize)>>, // (impi_idx, impu_idx in impi's list)

    /// Context initialized flag
    initialized: AtomicBool,
    /// Pool sizes
    max_impi: AtomicUsize,
    max_impu: AtomicUsize,
}

impl HssContext {
    /// Create a new HSS context
    pub fn new() -> Self {
        Self {
            diam_conf_path: None,
            diam_config: DiamConfig {
                cnf_port: 3868,     // DIAMETER_PORT
                cnf_port_tls: 5868, // DIAMETER_SECURE_PORT
                ..Default::default()
            },
            sms_over_ims: None,
            use_mongodb_change_stream: false,
            db_lock: Mutex::new(()),
            cx_lock: Mutex::new(()),
            imsi_list: RwLock::new(Vec::new()),
            imsi_hash: RwLock::new(HashMap::new()),
            impi_list: RwLock::new(Vec::new()),
            impi_hash: RwLock::new(HashMap::new()),
            impu_hash: RwLock::new(HashMap::new()),
            initialized: AtomicBool::new(false),
            max_impi: AtomicUsize::new(1024),
            max_impu: AtomicUsize::new(4096),
        }
    }

    /// Initialize the HSS context
    pub fn init(&mut self, max_impi: usize, max_impu: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }

        self.max_impi.store(max_impi, Ordering::SeqCst);
        self.max_impu.store(max_impu, Ordering::SeqCst);
        self.initialized.store(true, Ordering::SeqCst);

        log::info!("HSS context initialized (max_impi={max_impi}, max_impu={max_impu})");
    }

    /// Finalize the HSS context
    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }

        // Remove all identities
        self.imsi_remove_all();
        self.impi_remove_all();

        self.initialized.store(false, Ordering::SeqCst);
        log::info!("HSS context finalized");
    }

    /// Check if context is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    // ========== IMSI Management (S6a) ==========

    /// Add a new IMSI
    pub fn imsi_add(&self, id: &str) -> Option<usize> {
        let mut list = self.imsi_list.write().ok()?;
        let mut hash = self.imsi_hash.write().ok()?;

        if hash.contains_key(id) {
            return hash.get(id).copied();
        }

        let imsi = HssImsi::new(id);
        let idx = list.len();
        list.push(imsi);
        hash.insert(id.to_string(), idx);

        log::debug!("IMSI added: {id}");
        Some(idx)
    }

    /// Remove an IMSI by ID
    pub fn imsi_remove(&self, id: &str) -> bool {
        let list = self.imsi_list.read().unwrap();
        let mut hash = self.imsi_hash.write().unwrap();

        if let Some(&idx) = hash.get(id) {
            // Mark as removed (we don't actually remove to preserve indices)
            if idx < list.len() {
                hash.remove(id);
                log::debug!("IMSI removed: {id}");
                return true;
            }
        }
        false
    }

    /// Remove all IMSIs
    pub fn imsi_remove_all(&self) {
        if let (Ok(mut list), Ok(mut hash)) = (self.imsi_list.write(), self.imsi_hash.write()) {
            list.clear();
            hash.clear();
        }
    }

    /// Find IMSI by ID
    pub fn imsi_find_by_id(&self, id: &str) -> Option<HssImsi> {
        let list = self.imsi_list.read().ok()?;
        let hash = self.imsi_hash.read().ok()?;

        hash.get(id).and_then(|&idx| list.get(idx).cloned())
    }

    /// Get IMSI count
    pub fn imsi_count(&self) -> usize {
        self.imsi_hash.read().map(|h| h.len()).unwrap_or(0)
    }

    // ========== IMPI Management (Cx) ==========

    /// Add a new IMPI
    pub fn impi_add(&self, id: &str) -> Option<usize> {
        let mut list = self.impi_list.write().ok()?;
        let mut hash = self.impi_hash.write().ok()?;

        if hash.contains_key(id) {
            return hash.get(id).copied();
        }

        let impi = HssImpi::new(id);
        let idx = list.len();
        list.push(impi);
        hash.insert(id.to_string(), idx);

        log::debug!("IMPI added: {id}");
        Some(idx)
    }

    /// Remove an IMPI by ID
    pub fn impi_remove(&self, id: &str) -> bool {
        let list = self.impi_list.read().unwrap();
        let mut hash = self.impi_hash.write().unwrap();
        let mut impu_hash = self.impu_hash.write().unwrap();

        if let Some(&idx) = hash.get(id) {
            if idx < list.len() {
                // Remove all IMPUs associated with this IMPI
                let impu_ids: Vec<String> = list[idx].impu_list.clone();
                for impu_id in impu_ids {
                    impu_hash.remove(&impu_id);
                }
                hash.remove(id);
                log::debug!("IMPI removed: {id}");
                return true;
            }
        }
        false
    }

    /// Remove all IMPIs
    pub fn impi_remove_all(&self) {
        if let (Ok(mut list), Ok(mut hash), Ok(mut impu_hash)) = (
            self.impi_list.write(),
            self.impi_hash.write(),
            self.impu_hash.write(),
        ) {
            list.clear();
            hash.clear();
            impu_hash.clear();
        }
    }

    /// Find IMPI by ID
    pub fn impi_find_by_id(&self, id: &str) -> Option<HssImpi> {
        let list = self.impi_list.read().ok()?;
        let hash = self.impi_hash.read().ok()?;

        hash.get(id).and_then(|&idx| list.get(idx).cloned())
    }

    /// Get IMPI count
    pub fn impi_count(&self) -> usize {
        self.impi_hash.read().map(|h| h.len()).unwrap_or(0)
    }

    // ========== IMPU Management (Cx) ==========

    /// Add a new IMPU to an IMPI
    pub fn impu_add(&self, impi_id: &str, impu_id: &str) -> bool {
        let mut list = self.impi_list.write().unwrap();
        let hash = self.impi_hash.read().unwrap();
        let mut impu_hash = self.impu_hash.write().unwrap();

        if let Some(&impi_idx) = hash.get(impi_id) {
            if impi_idx < list.len() {
                let impu_idx = list[impi_idx].impu_list.len();
                list[impi_idx].add_impu(impu_id);
                impu_hash.insert(impu_id.to_string(), (impi_idx, impu_idx));
                log::debug!("IMPU added: {impu_id} -> {impi_id}");
                return true;
            }
        }
        false
    }

    /// Find IMPU by ID
    pub fn impu_find_by_id(&self, id: &str) -> Option<HssImpu> {
        let list = self.impi_list.read().ok()?;
        let impu_hash = self.impu_hash.read().ok()?;

        if let Some(&(impi_idx, _)) = impu_hash.get(id) {
            if impi_idx < list.len() {
                let impi = &list[impi_idx];
                if impi.impu_list.contains(&id.to_string()) {
                    return Some(HssImpu::new(id, &impi.id));
                }
            }
        }
        None
    }

    /// Get IMPU count
    pub fn impu_count(&self) -> usize {
        self.impu_hash.read().map(|h| h.len()).unwrap_or(0)
    }

    // ========== Cx Identity Management ==========

    /// Associate an IMPI (user_name) with an IMPU (public_identity)
    pub fn cx_associate_identity(&self, user_name: &str, public_identity: &str) {
        let _lock = self.cx_lock.lock().unwrap();

        // Find or create IMPI
        let impi_exists = self.impi_find_by_id(user_name).is_some();
        if !impi_exists {
            self.impi_add(user_name);
        }

        // Find or create IMPU
        let impu_exists = self.impu_find_by_id(public_identity).is_some();
        if !impu_exists {
            self.impu_add(user_name, public_identity);
        }
    }

    /// Check if an IMPI and IMPU are associated
    pub fn cx_identity_is_associated(&self, user_name: &str, public_identity: &str) -> bool {
        let _lock = self.cx_lock.lock().unwrap();

        if let Some(impi) = self.impi_find_by_id(user_name) {
            return impi.impu_list.contains(&public_identity.to_string());
        }
        false
    }

    /// Set IMSI BCD for an IMPI
    pub fn cx_set_imsi_bcd(
        &self,
        user_name: &str,
        imsi_bcd: &str,
        visited_network_identifier: &str,
    ) {
        let _lock = self.cx_lock.lock().unwrap();

        // Find or create IMSI
        let imsi_exists = self.imsi_find_by_id(imsi_bcd).is_some();
        if !imsi_exists {
            self.imsi_add(imsi_bcd);
        }

        // Update IMSI with visited network identifier
        if let Ok(mut list) = self.imsi_list.write() {
            if let Ok(hash) = self.imsi_hash.read() {
                if let Some(&idx) = hash.get(imsi_bcd) {
                    if idx < list.len() {
                        list[idx].set_visited_network_identifier(visited_network_identifier);
                    }
                }
            }
        }

        // Associate IMPI with IMSI
        if let Ok(mut list) = self.impi_list.write() {
            if let Ok(hash) = self.impi_hash.read() {
                if let Some(&idx) = hash.get(user_name) {
                    if idx < list.len() {
                        list[idx].set_imsi(imsi_bcd);
                    }
                }
            }
        }
    }

    /// Internal helper to get IMSI BCD without acquiring cx_lock (caller must hold lock)
    fn cx_get_imsi_bcd_internal(&self, public_identity: &str) -> Option<String> {
        // AB-BA: primary list (impi_list) before index (impu_hash) — canonical order
        let impi_list = self.impi_list.read().ok()?;
        let impu_hash = self.impu_hash.read().ok()?;

        if let Some(&(impi_idx, _)) = impu_hash.get(public_identity) {
            if impi_idx < impi_list.len() {
                return impi_list[impi_idx].imsi.clone();
            }
        }
        None
    }

    /// Get IMSI BCD from public identity
    pub fn cx_get_imsi_bcd(&self, public_identity: &str) -> Option<String> {
        let _lock = self.cx_lock.lock().unwrap();
        self.cx_get_imsi_bcd_internal(public_identity)
    }

    /// Get visited network identifier from public identity
    pub fn cx_get_visited_network_identifier(&self, public_identity: &str) -> Option<String> {
        let _lock = self.cx_lock.lock().unwrap();

        let imsi_bcd = self.cx_get_imsi_bcd_internal(public_identity)?;
        let imsi = self.imsi_find_by_id(&imsi_bcd)?;
        imsi.visited_network_identifier
    }

    /// Get user name (IMPI) from public identity
    pub fn cx_get_user_name(&self, public_identity: &str) -> Option<String> {
        let _lock = self.cx_lock.lock().unwrap();

        // AB-BA: primary list (impi_list) before index (impu_hash) — canonical order
        let impi_list = self.impi_list.read().ok()?;
        let impu_hash = self.impu_hash.read().ok()?;

        if let Some(&(impi_idx, _)) = impu_hash.get(public_identity) {
            if impi_idx < impi_list.len() {
                return Some(impi_list[impi_idx].id.clone());
            }
        }
        None
    }

    /// Get server name from public identity
    pub fn cx_get_server_name(&self, public_identity: &str) -> Option<String> {
        let _lock = self.cx_lock.lock().unwrap();

        // First check IMPU's server name
        // AB-BA: primary list (impi_list) before index (impu_hash) — canonical order
        let impi_list = self.impi_list.read().ok()?;
        let impu_hash = self.impu_hash.read().ok()?;

        if let Some(&(impi_idx, _)) = impu_hash.get(public_identity) {
            if impi_idx < impi_list.len() {
                let _impi = &impi_list[impi_idx];
                // Check all IMPUs in this IMPI for a server name
                // In a full implementation, we'd store server_name per IMPU
                // For now, return None as we need the full IMPU structure
            }
        }
        None
    }

    /// Set server name for a public identity
    pub fn cx_set_server_name(&self, public_identity: &str, server_name: &str, overwrite: bool) {
        let _lock = self.cx_lock.lock().unwrap();

        // In a full implementation, we'd update the IMPU's server_name
        // This requires storing HssImpu objects with server_name field
        log::debug!(
            "cx_set_server_name: {public_identity} -> {server_name} (overwrite={overwrite})"
        );
    }

    // ========== Database Operations ==========

    /// Lock database for thread-safe operations
    pub fn db_lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.db_lock.lock().unwrap()
    }
}

impl Default for HssContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global HSS context (thread-safe singleton)
static GLOBAL_HSS_CONTEXT: std::sync::OnceLock<Arc<RwLock<HssContext>>> =
    std::sync::OnceLock::new();

/// Get the global HSS context
pub fn hss_self() -> Arc<RwLock<HssContext>> {
    GLOBAL_HSS_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(HssContext::new())))
        .clone()
}

/// Initialize the global HSS context
pub fn hss_context_init(max_impi: usize, max_impu: usize) {
    let ctx = hss_self();
    let result = ctx.write();
    if let Ok(mut context) = result {
        context.init(max_impi, max_impu);
    }
}

/// Finalize the global HSS context
pub fn hss_context_final() {
    let ctx = hss_self();
    let result = ctx.write();
    if let Ok(mut context) = result {
        context.fini();
    }
}

// ---------------------------------------------------------------------------
// YAML configuration (`hss:` section)
// ---------------------------------------------------------------------------

/// One `hss.diameter.connections[]` peer entry.
#[derive(Debug, Default, Deserialize)]
pub struct DiamConnectionYaml {
    pub identity: Option<String>,
    pub addr: Option<String>,
    pub port: Option<u16>,
    /// Per-peer Tc override, seconds. Absent means "use the node-level Tc",
    /// which `DiamConnection` represents as 0.
    pub timer_tc: Option<i32>,
}

/// The `hss.diameter` block: this node's Diameter identity and listener.
///
/// Field names mirror the freeDiameter vocabulary the deployment already uses
/// (`Identity`, `Realm`, `ListenOn`, `Port`) in snake_case, so an operator
/// translating an existing `hss.conf` does not have to learn new names.
#[derive(Debug, Default, Deserialize)]
pub struct DiameterYaml {
    /// Origin-Host (RFC 6733 §6.3) — this node's Diameter identity.
    pub identity: Option<String>,
    /// Origin-Realm (RFC 6733 §6.4). TS 23.003 §19.2 formats the EPC home
    /// realm as `epc.mncNNN.mccMMM.3gppnetwork.org`.
    pub realm: Option<String>,
    /// Listen address for the S6a server.
    pub addr: Option<String>,
    pub port: Option<u16>,
    pub port_tls: Option<u16>,
    /// Tc timer, seconds (RFC 6733 §12).
    pub timer_tc: Option<i32>,
    pub no_fwd: Option<bool>,
    pub connections: Option<Vec<DiamConnectionYaml>>,
}

/// The `hss:` section. Only the keys this daemon acts on are declared; unknown
/// keys are ignored rather than rejected, because the shipped configs carry
/// `freeDiameter:` and `metrics:` keys owned by other subsystems.
#[derive(Debug, Default, Deserialize)]
pub struct HssSectionYaml {
    pub diameter: Option<DiameterYaml>,
    /// Path to a freeDiameter-style config. Recorded in `diam_conf_path` so a
    /// deployment can be diagnosed; this daemon does not parse that format.
    #[serde(rename = "freeDiameter")]
    pub free_diameter: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct HssYaml {
    pub hss: Option<HssSectionYaml>,
}

/// Parse HSS configuration from YAML and apply it to the global context.
///
/// # Why this exists
///
/// This function used to `return Ok(())` without reading the file, while
/// `main()` logged "Loading configuration from <file>". Because hssd exposes no
/// `--diameter-id`/`--diameter-realm` CLI flag either, the daemon was
/// hard-locked to the `unwrap_or_else` fallbacks in `main.rs`
/// (`hss.epc.mnc001.mcc001.3gppnetwork.org` / `epc.mnc001.mcc001...`). RFC 6733
/// §6.1 routes and authorizes requests on Destination-Realm matched against the
/// receiver's Origin-Realm, so an HSS on any real PLMN could not be reached:
/// there was no runtime workaround at all.
///
/// # Errors
///
/// Returns `Err` when the file cannot be read or is not valid YAML. This
/// deliberately FAILS rather than warning and continuing, unlike the lenient
/// `if let Ok(..)` pattern the 5GC NFs use for their optional SBI knobs: here a
/// silently-ignored config does not degrade one feature, it silently reverts the
/// node's identity to a different PLMN, which is far worse to diagnose than a
/// refusal to start. `main()` is responsible for exiting non-zero.
///
/// A file that parses but carries no `hss.diameter` block is NOT an error: the
/// shipped `docker/rust/configs/epc/hss.yaml` is exactly that, and it must keep
/// working. Absent keys leave the existing defaults untouched.
pub fn hss_context_parse_config(config_path: &str) -> Result<(), String> {
    let content = std::fs::read_to_string(config_path)
        .map_err(|e| format!("cannot read {config_path}: {e}"))?;

    let parsed: HssYaml = serde_yaml::from_str(&content)
        .map_err(|e| format!("invalid YAML in {config_path}: {e}"))?;

    let Some(section) = parsed.hss else {
        log::debug!("{config_path}: no 'hss' section; keeping defaults");
        return Ok(());
    };

    let ctx = hss_self();
    let mut ctx = ctx
        .write()
        .map_err(|_| "HSS context lock poisoned".to_string())?;

    if let Some(path) = section.free_diameter {
        ctx.diam_conf_path = Some(path);
    }

    let Some(diam) = section.diameter else {
        log::debug!("{config_path}: no 'hss.diameter' block; keeping defaults");
        return Ok(());
    };

    apply_diameter_yaml(&mut ctx.diam_config, diam);
    log::info!(
        "HSS Diameter identity: {} realm: {} listen: {}:{}",
        ctx.diam_config.cnf_diamid.as_deref().unwrap_or("<default>"),
        ctx.diam_config
            .cnf_diamrlm
            .as_deref()
            .unwrap_or("<default>"),
        ctx.diam_config.cnf_addr.as_deref().unwrap_or("<default>"),
        ctx.diam_config.cnf_port,
    );
    Ok(())
}

/// Copy the parsed `diameter` block onto a [`DiamConfig`].
///
/// Absent keys are left at their existing value rather than being zeroed, so a
/// partial config cannot clear `cnf_port` (which `main.rs` reads as "unset" and
/// replaces with 3868) or reduce `cnf_timer_tc` below its `.max(1)` floor.
/// Shared with the unit tests so the mapping is verified directly.
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
    if let Some(v) = diam.timer_tc {
        cfg.cnf_timer_tc = v;
    }
    if let Some(v) = diam.no_fwd {
        cfg.cnf_flags_no_fwd = v;
    }
    if let Some(conns) = diam.connections {
        cfg.connections = conns
            .into_iter()
            .filter_map(|c| {
                // An entry with no identity cannot be routed to, so it is
                // dropped with a warning rather than stored as an empty peer.
                let identity = match c.identity {
                    Some(id) => id,
                    None => {
                        log::warn!("hss.diameter.connections[]: entry without identity; ignored");
                        return None;
                    }
                };
                Some(DiamConnection {
                    identity,
                    // `addr` is a plain String here, so an omitted address
                    // becomes empty rather than absent. Callers treat empty as
                    // "resolve the identity by DNS", matching freeDiameter's
                    // ConnectPeer without an explicit ConnectTo.
                    addr: c.addr.unwrap_or_default(),
                    port: c.port.unwrap_or(0),
                    tc_timer: c.timer_tc.unwrap_or(0),
                })
            })
            .collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // YAML Diameter configuration (issue #58)
    //
    // Asserted against `apply_diameter_yaml` / a local `DiamConfig` rather than
    // through `hss_context_parse_config`, because that writes the PROCESS-GLOBAL
    // context: two of these tests running in parallel would race, and the
    // surviving value would depend on scheduling. The parse function is a thin
    // read-file + deserialize + apply wrapper over this mapping.
    // -----------------------------------------------------------------------

    /// A realistic operator config must reach every DiamConfig field, so an HSS
    /// on a real PLMN advertises its own Origin-Realm instead of the hardcoded
    /// mnc001/mcc001 fallback in main.rs (RFC 6733 §6.1, TS 23.003 §19.2).
    #[test]
    fn diameter_yaml_populates_every_diam_config_field() {
        let yaml = r#"
hss:
  diameter:
    identity: hss.epc.mnc070.mcc310.3gppnetwork.org
    realm: epc.mnc070.mcc310.3gppnetwork.org
    addr: 10.0.0.5
    port: 3869
    port_tls: 5869
    timer_tc: 30
    no_fwd: true
    connections:
      - identity: mme.epc.mnc070.mcc310.3gppnetwork.org
        addr: 10.0.0.6
        port: 3868
        timer_tc: 15
"#;
        let parsed: HssYaml = serde_yaml::from_str(yaml).expect("fixture must deserialize");
        let diam = parsed
            .hss
            .expect("hss section")
            .diameter
            .expect("diameter block");

        let mut cfg = DiamConfig {
            cnf_port: 3868,
            cnf_port_tls: 5868,
            ..Default::default()
        };
        apply_diameter_yaml(&mut cfg, diam);

        assert_eq!(
            cfg.cnf_diamid.as_deref(),
            Some("hss.epc.mnc070.mcc310.3gppnetwork.org")
        );
        assert_eq!(
            cfg.cnf_diamrlm.as_deref(),
            Some("epc.mnc070.mcc310.3gppnetwork.org")
        );
        assert_eq!(cfg.cnf_addr.as_deref(), Some("10.0.0.5"));
        assert_eq!(cfg.cnf_port, 3869);
        assert_eq!(cfg.cnf_port_tls, 5869);
        assert_eq!(cfg.cnf_timer_tc, 30);
        assert!(cfg.cnf_flags_no_fwd);
        assert_eq!(cfg.connections.len(), 1);
        assert_eq!(
            cfg.connections[0].identity,
            "mme.epc.mnc070.mcc310.3gppnetwork.org"
        );
        assert_eq!(cfg.connections[0].addr, "10.0.0.6");
        assert_eq!(cfg.connections[0].port, 3868);
        assert_eq!(cfg.connections[0].tc_timer, 15);
    }

    /// A partial config must not zero the fields it omits. `main.rs` reads
    /// `cnf_port == 0` as "unset" and substitutes 3868, so clearing the port
    /// here would silently move the listener.
    #[test]
    fn absent_diameter_keys_leave_existing_values_untouched() {
        let parsed: HssYaml =
            serde_yaml::from_str("hss:\n  diameter:\n    realm: epc.example.org\n")
                .expect("fixture must deserialize");
        let mut cfg = DiamConfig {
            cnf_diamid: Some("keep.me".to_string()),
            cnf_port: 3868,
            cnf_port_tls: 5868,
            cnf_timer_tc: 7,
            ..Default::default()
        };
        apply_diameter_yaml(&mut cfg, parsed.hss.unwrap().diameter.unwrap());

        assert_eq!(cfg.cnf_diamrlm.as_deref(), Some("epc.example.org"));
        assert_eq!(cfg.cnf_diamid.as_deref(), Some("keep.me"), "not cleared");
        assert_eq!(cfg.cnf_port, 3868, "not zeroed");
        assert_eq!(cfg.cnf_port_tls, 5868, "not zeroed");
        assert_eq!(cfg.cnf_timer_tc, 7, "not zeroed");
    }

    /// A peer with no identity cannot be routed to, so it is dropped rather than
    /// stored as an empty-identity connection that would fail obscurely later.
    #[test]
    fn connection_without_identity_is_dropped() {
        let parsed: HssYaml = serde_yaml::from_str(
            "hss:\n  diameter:\n    connections:\n      - addr: 10.0.0.6\n      - identity: real.peer\n",
        )
        .expect("fixture must deserialize");
        let mut cfg = DiamConfig::default();
        apply_diameter_yaml(&mut cfg, parsed.hss.unwrap().diameter.unwrap());

        assert_eq!(cfg.connections.len(), 1);
        assert_eq!(cfg.connections[0].identity, "real.peer");
        assert_eq!(
            cfg.connections[0].addr, "",
            "omitted addr means DNS-resolve"
        );
    }

    /// The SHIPPED config (docker/rust/configs/epc/hss.yaml) has an `hss:`
    /// section with no `diameter:` block, plus keys owned by other subsystems.
    /// It must keep parsing, or this change breaks every existing deployment.
    #[test]
    fn shipped_config_shape_parses_and_keeps_defaults() {
        let yaml = r#"
db_uri: mongodb://mongodb:27017/nextgcore
logger:
  file:
    path: /var/log/nextgcore/hss.log
  level: info
global:
  max:
    ue: 1024
hss:
  freeDiameter: /etc/freeDiameter/hss.conf
  metrics:
    server:
      - address: 172.24.0.8
        port: 9090
"#;
        let parsed: HssYaml = serde_yaml::from_str(yaml).expect("shipped shape must deserialize");
        let section = parsed.hss.expect("hss section");
        assert_eq!(
            section.free_diameter.as_deref(),
            Some("/etc/freeDiameter/hss.conf")
        );
        assert!(
            section.diameter.is_none(),
            "no diameter block: defaults must survive"
        );
    }

    /// Malformed YAML must be an Err so main() can exit non-zero, rather than
    /// warn-and-continue on a different PLMN's identity.
    #[test]
    fn malformed_yaml_is_an_error() {
        let path = std::env::temp_dir().join(format!(
            "nextgcore-hssd-bad-{}-{:?}.yaml",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, "hss:\n  diameter:\n    port: \"not a number\"\n").unwrap();
        let result = hss_context_parse_config(path.to_str().unwrap());
        std::fs::remove_file(&path).ok();
        assert!(result.is_err(), "a malformed config must not be accepted");
    }

    /// An unreadable/missing path is an Err too. main() only calls this when the
    /// file exists, so reaching here means a genuine I/O problem.
    #[test]
    fn unreadable_config_is_an_error() {
        let missing = std::env::temp_dir().join("nextgcore-hssd-does-not-exist-58.yaml");
        assert!(hss_context_parse_config(missing.to_str().unwrap()).is_err());
    }

    #[test]
    fn test_hss_context_new() {
        let ctx = HssContext::new();
        assert!(!ctx.is_initialized());
        assert_eq!(ctx.imsi_count(), 0);
        assert_eq!(ctx.impi_count(), 0);
        assert_eq!(ctx.impu_count(), 0);
    }

    #[test]
    fn test_hss_context_init_fini() {
        let mut ctx = HssContext::new();
        ctx.init(1024, 4096);
        assert!(ctx.is_initialized());

        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_imsi_add_remove() {
        let mut ctx = HssContext::new();
        ctx.init(1024, 4096);

        let idx = ctx.imsi_add("123456789012345").unwrap();
        assert_eq!(ctx.imsi_count(), 1);

        let imsi = ctx.imsi_find_by_id("123456789012345");
        assert!(imsi.is_some());
        assert_eq!(imsi.unwrap().id, "123456789012345");

        ctx.imsi_remove("123456789012345");
        assert_eq!(ctx.imsi_count(), 0);
    }

    #[test]
    fn test_impi_add_remove() {
        let mut ctx = HssContext::new();
        ctx.init(1024, 4096);

        ctx.impi_add("user@example.com");
        assert_eq!(ctx.impi_count(), 1);

        let impi = ctx.impi_find_by_id("user@example.com");
        assert!(impi.is_some());
        assert_eq!(impi.unwrap().id, "user@example.com");

        ctx.impi_remove("user@example.com");
        assert_eq!(ctx.impi_count(), 0);
    }

    #[test]
    fn test_impu_add() {
        let mut ctx = HssContext::new();
        ctx.init(1024, 4096);

        ctx.impi_add("user@example.com");
        ctx.impu_add("user@example.com", "sip:user@example.com");
        assert_eq!(ctx.impu_count(), 1);

        let impu = ctx.impu_find_by_id("sip:user@example.com");
        assert!(impu.is_some());
    }

    #[test]
    fn test_cx_associate_identity() {
        let mut ctx = HssContext::new();
        ctx.init(1024, 4096);

        ctx.cx_associate_identity("user@example.com", "sip:user@example.com");
        assert!(ctx.cx_identity_is_associated("user@example.com", "sip:user@example.com"));
        assert!(!ctx.cx_identity_is_associated("user@example.com", "sip:other@example.com"));
    }

    #[test]
    fn test_cx_set_imsi_bcd() {
        let mut ctx = HssContext::new();
        ctx.init(1024, 4096);

        ctx.cx_associate_identity("user@example.com", "sip:user@example.com");
        ctx.cx_set_imsi_bcd("user@example.com", "123456789012345", "example.com");

        let imsi_bcd = ctx.cx_get_imsi_bcd("sip:user@example.com");
        assert_eq!(imsi_bcd, Some("123456789012345".to_string()));

        let vni = ctx.cx_get_visited_network_identifier("sip:user@example.com");
        assert_eq!(vni, Some("example.com".to_string()));
    }

    #[test]
    fn test_cx_get_user_name() {
        let mut ctx = HssContext::new();
        ctx.init(1024, 4096);

        ctx.cx_associate_identity("user@example.com", "sip:user@example.com");

        let user_name = ctx.cx_get_user_name("sip:user@example.com");
        assert_eq!(user_name, Some("user@example.com".to_string()));
    }

    #[test]
    fn test_hss_imsi() {
        let mut imsi = HssImsi::new("123456789012345");
        assert_eq!(imsi.id, "123456789012345");
        assert!(imsi.visited_network_identifier.is_none());

        imsi.set_visited_network_identifier("example.com");
        assert_eq!(
            imsi.visited_network_identifier,
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_hss_impi() {
        let mut impi = HssImpi::new("user@example.com");
        assert_eq!(impi.id, "user@example.com");
        assert!(impi.impu_list.is_empty());

        impi.add_impu("sip:user@example.com");
        assert_eq!(impi.impu_list.len(), 1);

        impi.add_impu("tel:+1234567890");
        assert_eq!(impi.impu_list.len(), 2);

        impi.remove_impu("sip:user@example.com");
        assert_eq!(impi.impu_list.len(), 1);
    }

    #[test]
    fn test_hss_impu() {
        let mut impu = HssImpu::new("sip:user@example.com", "user@example.com");
        assert_eq!(impu.id, "sip:user@example.com");
        assert_eq!(impu.impi_id, "user@example.com");
        assert!(impu.server_name.is_none());

        impu.set_server_name("sip:scscf.example.com");
        assert_eq!(impu.server_name, Some("sip:scscf.example.com".to_string()));
    }
}

#[cfg(test)]
mod shipped_config_smoke {
    //! Parses the REAL shipped config from the repo, not a fixture copy, so a
    //! future edit to that file cannot silently break the daemon's startup path.
    use super::*;

    #[test]
    fn repo_shipped_hss_yaml_parses() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../docker/rust/configs/epc/hss.yaml"
        );
        let content = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read shipped config {path}: {e}"));
        let parsed: HssYaml = serde_yaml::from_str(&content).expect("shipped hss.yaml must parse");
        let section = parsed.hss.expect("hss section");
        assert!(section.free_diameter.is_some());
        // The diameter block ships commented out, so defaults must survive.
        assert!(section.diameter.is_none());
    }

    /// Uncommenting the documented block must actually take effect -- otherwise
    /// the comment in the shipped file is advice that does not work.
    #[test]
    fn documented_diameter_block_takes_effect_when_uncommented() {
        let yaml = r#"
hss:
  freeDiameter: /etc/freeDiameter/hss.conf
  diameter:
    identity: hss.epc.mnc001.mcc001.3gppnetwork.org
    realm: epc.mnc001.mcc001.3gppnetwork.org
    addr: 172.24.0.8
    port: 3868
"#;
        let parsed: HssYaml = serde_yaml::from_str(yaml).expect("must parse");
        let diam = parsed.hss.unwrap().diameter.expect("diameter block");
        let mut cfg = DiamConfig::default();
        apply_diameter_yaml(&mut cfg, diam);
        assert_eq!(
            cfg.cnf_diamid.as_deref(),
            Some("hss.epc.mnc001.mcc001.3gppnetwork.org")
        );
        assert_eq!(cfg.cnf_addr.as_deref(), Some("172.24.0.8"));
        assert_eq!(cfg.cnf_port, 3868);
    }
}
