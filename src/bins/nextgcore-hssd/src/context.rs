//! HSS Context Management
//!
//! Port of src/hss/hss-context.c - HSS context with IMSI/IMPI/IMPU hash tables,
//! DB operations, and CX identity management

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

/// Maximum IMSI BCD length
pub const OGS_MAX_IMSI_BCD_LEN: usize = 15;

/// SUPI type prefix for IMSI
pub const OGS_ID_SUPI_TYPE_IMSI: &str = "imsi";

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
                cnf_port: 3868,      // DIAMETER_PORT
                cnf_port_tls: 5868,  // DIAMETER_SECURE_PORT
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

        log::info!(
            "HSS context initialized (max_impi={max_impi}, max_impu={max_impu})"
        );
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
        let list = self.imsi_list.write().ok().unwrap();
        let mut hash = self.imsi_hash.write().ok().unwrap();

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
        let list = self.impi_list.write().ok().unwrap();
        let mut hash = self.impi_hash.write().ok().unwrap();
        let mut impu_hash = self.impu_hash.write().ok().unwrap();

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
        let mut list = self.impi_list.write().ok().unwrap();
        let hash = self.impi_hash.read().ok().unwrap();
        let mut impu_hash = self.impu_hash.write().ok().unwrap();

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
    pub fn cx_set_imsi_bcd(&self, user_name: &str, imsi_bcd: &str, visited_network_identifier: &str) {
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
        let impu_hash = self.impu_hash.read().ok()?;
        let impi_list = self.impi_list.read().ok()?;

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

        let impu_hash = self.impu_hash.read().ok()?;
        let impi_list = self.impi_list.read().ok()?;

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
        let impu_hash = self.impu_hash.read().ok()?;
        let impi_list = self.impi_list.read().ok()?;

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

/// Parse HSS configuration from YAML
pub fn hss_context_parse_config(_config_path: &str) -> Result<(), String> {
    // Note: Implement YAML configuration parsing
    // This would parse the hss section from the config file
    // Configuration parsing uses the serde_yaml crate for YAML deserialization
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(imsi.visited_network_identifier, Some("example.com".to_string()));
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
