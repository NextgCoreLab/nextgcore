//! AUSF Context Management
//!
//! Port of src/ausf/context.c - AUSF context with UE list and hash tables

use ogs_crypt::kdf::{ogs_kdf_hxres_star, ogs_kdf_kseaf};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

/// Authentication type (from OpenAPI)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthType {
    /// 5G AKA authentication
    FiveGAka,
    /// EAP-AKA' authentication
    EapAkaPrime,
    /// EAP-TLS authentication
    EapTls,
}

impl Default for AuthType {
    fn default() -> Self {
        AuthType::FiveGAka
    }
}

/// Authentication result (from OpenAPI)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthResult {
    /// Authentication success
    AuthenticationSuccess,
    /// Authentication failure
    AuthenticationFailure,
    /// Authentication ongoing
    AuthenticationOngoing,
}

impl Default for AuthResult {
    fn default() -> Self {
        AuthResult::AuthenticationOngoing
    }
}

/// Authentication event data
#[derive(Debug, Clone, Default)]
pub struct AuthEvent {
    /// Resource URI for auth event
    pub resource_uri: Option<String>,
    /// Client for auth event
    pub client_id: Option<u64>,
}

impl AuthEvent {
    /// Create a new auth event
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear the auth event
    pub fn clear(&mut self) {
        self.resource_uri = None;
    }

    /// Store a resource URI
    pub fn store(&mut self, resource_uri: &str) {
        self.resource_uri = Some(resource_uri.to_string());
    }
}

/// AUSF UE context
#[derive(Debug, Clone)]
pub struct AusfUe {
    /// Unique pool ID
    pub id: u64,
    /// Context ID (string representation of pool index)
    pub ctx_id: String,
    /// SUCI (Subscription Concealed Identifier)
    pub suci: String,
    /// SUPI (Subscription Permanent Identifier)
    pub supi: Option<String>,
    /// Serving network name
    pub serving_network_name: Option<String>,
    /// Authentication type
    pub auth_type: AuthType,
    /// Authentication event
    pub auth_event: AuthEvent,
    /// Authentication result
    pub auth_result: AuthResult,
    /// RAND value (16 bytes)
    pub rand: [u8; 16],
    /// XRES* value (16 bytes)
    pub xres_star: [u8; 16],
    /// HXRES* value (16 bytes)
    pub hxres_star: [u8; 16],
    /// KAUSF value (32 bytes)
    pub kausf: [u8; 32],
    /// KSEAF value (32 bytes)
    pub kseaf: [u8; 32],
    /// Associated stream ID
    pub stream_id: Option<u64>,
}

impl AusfUe {
    /// Create a new AUSF UE
    pub fn new(id: u64, suci: &str) -> Self {
        Self {
            id,
            ctx_id: id.to_string(),
            suci: suci.to_string(),
            supi: None,
            serving_network_name: None,
            auth_type: AuthType::default(),
            auth_event: AuthEvent::new(),
            auth_result: AuthResult::default(),
            rand: [0u8; 16],
            xres_star: [0u8; 16],
            hxres_star: [0u8; 16],
            kausf: [0u8; 32],
            kseaf: [0u8; 32],
            stream_id: None,
        }
    }

    /// Clear auth event
    pub fn auth_event_clear(&mut self) {
        self.auth_event.clear();
    }

    /// Store auth event resource URI
    pub fn auth_event_store(&mut self, resource_uri: &str) {
        self.auth_event.store(resource_uri);
    }

    /// Calculate HXRES* from RAND and XRES*
    pub fn calculate_hxres_star(&mut self) {
        self.hxres_star = ogs_kdf_hxres_star(&self.rand, &self.xres_star);
    }

    /// Calculate KSEAF from serving network name and KAUSF
    pub fn calculate_kseaf(&mut self) {
        if let Some(ref serving_network_name) = self.serving_network_name {
            self.kseaf = ogs_kdf_kseaf(serving_network_name, &self.kausf);
        }
    }
}

/// AUSF Context - main context structure for AUSF
pub struct AusfContext {
    /// UE list (by pool ID)
    ue_list: RwLock<HashMap<u64, AusfUe>>,
    /// SUCI hash (SUCI -> pool ID)
    suci_hash: RwLock<HashMap<String, u64>>,
    /// SUPI hash (SUPI -> pool ID)
    supi_hash: RwLock<HashMap<String, u64>>,
    /// Next UE ID
    next_ue_id: AtomicUsize,
    /// Maximum number of UEs
    max_num_of_ue: usize,
    /// Context initialized flag
    initialized: AtomicBool,
}

impl AusfContext {
    /// Create a new AUSF context
    pub fn new() -> Self {
        Self {
            ue_list: RwLock::new(HashMap::new()),
            suci_hash: RwLock::new(HashMap::new()),
            supi_hash: RwLock::new(HashMap::new()),
            next_ue_id: AtomicUsize::new(1),
            max_num_of_ue: 0,
            initialized: AtomicBool::new(false),
        }
    }

    /// Initialize the AUSF context
    pub fn init(&mut self, max_ue: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }

        self.max_num_of_ue = max_ue;
        self.initialized.store(true, Ordering::SeqCst);

        log::info!("AUSF context initialized with max {} UEs", self.max_num_of_ue);
    }

    /// Finalize the AUSF context
    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }

        // Remove all UEs
        self.ue_remove_all();

        self.initialized.store(false, Ordering::SeqCst);
        log::info!("AUSF context finalized");
    }

    /// Check if context is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Add a new UE by SUCI
    pub fn ue_add(&self, suci: &str) -> Option<AusfUe> {
        let mut ue_list = self.ue_list.write().ok()?;
        let mut suci_hash = self.suci_hash.write().ok()?;

        if ue_list.len() >= self.max_num_of_ue {
            log::error!("Maximum number of UEs [{}] reached", self.max_num_of_ue);
            return None;
        }

        let id = self.next_ue_id.fetch_add(1, Ordering::SeqCst) as u64;
        let ue = AusfUe::new(id, suci);

        suci_hash.insert(suci.to_string(), id);
        ue_list.insert(id, ue.clone());

        log::debug!("[{}] AUSF UE added (id={})", suci, id);
        Some(ue)
    }

    /// Remove a UE by ID
    pub fn ue_remove(&self, id: u64) -> Option<AusfUe> {
        let mut ue_list = self.ue_list.write().ok()?;
        let mut suci_hash = self.suci_hash.write().ok()?;
        let mut supi_hash = self.supi_hash.write().ok()?;

        if let Some(ue) = ue_list.remove(&id) {
            suci_hash.remove(&ue.suci);
            if let Some(ref supi) = ue.supi {
                supi_hash.remove(supi);
            }
            log::debug!("[{}] AUSF UE removed (id={})", ue.suci, id);
            return Some(ue);
        }
        None
    }

    /// Remove all UEs
    pub fn ue_remove_all(&self) {
        if let (Ok(mut ue_list), Ok(mut suci_hash), Ok(mut supi_hash)) = (
            self.ue_list.write(),
            self.suci_hash.write(),
            self.supi_hash.write(),
        ) {
            ue_list.clear();
            suci_hash.clear();
            supi_hash.clear();
        }
    }

    /// Find UE by SUCI
    pub fn ue_find_by_suci(&self, suci: &str) -> Option<AusfUe> {
        let suci_hash = self.suci_hash.read().ok()?;
        let ue_list = self.ue_list.read().ok()?;

        if let Some(&id) = suci_hash.get(suci) {
            return ue_list.get(&id).cloned();
        }
        None
    }

    /// Find UE by SUPI
    pub fn ue_find_by_supi(&self, supi: &str) -> Option<AusfUe> {
        let supi_hash = self.supi_hash.read().ok()?;
        let ue_list = self.ue_list.read().ok()?;

        if let Some(&id) = supi_hash.get(supi) {
            return ue_list.get(&id).cloned();
        }
        None
    }

    /// Find UE by SUCI or SUPI
    pub fn ue_find_by_suci_or_supi(&self, suci_or_supi: &str) -> Option<AusfUe> {
        if suci_or_supi.starts_with("suci-") {
            self.ue_find_by_suci(suci_or_supi)
        } else {
            self.ue_find_by_supi(suci_or_supi)
        }
    }

    /// Find UE by context ID
    pub fn ue_find_by_ctx_id(&self, ctx_id: &str) -> Option<AusfUe> {
        let id: u64 = ctx_id.parse().ok()?;
        self.ue_find_by_id(id)
    }

    /// Find UE by pool ID
    pub fn ue_find_by_id(&self, id: u64) -> Option<AusfUe> {
        let ue_list = self.ue_list.read().ok()?;
        ue_list.get(&id).cloned()
    }

    /// Update UE in the context
    pub fn ue_update(&self, ue: &AusfUe) -> bool {
        let mut ue_list = self.ue_list.write().ok().unwrap();
        let mut supi_hash = self.supi_hash.write().ok().unwrap();

        if let Some(existing) = ue_list.get_mut(&ue.id) {
            // Update SUPI hash if SUPI changed
            if existing.supi != ue.supi {
                if let Some(ref old_supi) = existing.supi {
                    supi_hash.remove(old_supi);
                }
                if let Some(ref new_supi) = ue.supi {
                    supi_hash.insert(new_supi.clone(), ue.id);
                }
            }
            *existing = ue.clone();
            return true;
        }
        false
    }

    /// Set SUPI for a UE
    pub fn ue_set_supi(&self, id: u64, supi: &str) -> bool {
        let mut ue_list = self.ue_list.write().ok().unwrap();
        let mut supi_hash = self.supi_hash.write().ok().unwrap();

        if let Some(ue) = ue_list.get_mut(&id) {
            // Remove old SUPI from hash
            if let Some(ref old_supi) = ue.supi {
                supi_hash.remove(old_supi);
            }
            // Set new SUPI
            ue.supi = Some(supi.to_string());
            supi_hash.insert(supi.to_string(), id);
            return true;
        }
        false
    }

    /// Get UE load percentage
    pub fn get_ue_load(&self) -> i32 {
        let ue_list = self.ue_list.read().ok().unwrap();
        let used = ue_list.len();
        let total = self.max_num_of_ue;
        if total == 0 {
            return 0;
        }
        ((used * 100) / total) as i32
    }

    /// Get number of UEs
    pub fn ue_count(&self) -> usize {
        self.ue_list.read().map(|l| l.len()).unwrap_or(0)
    }
}

impl Default for AusfContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global AUSF context (thread-safe singleton)
static GLOBAL_AUSF_CONTEXT: std::sync::OnceLock<Arc<RwLock<AusfContext>>> =
    std::sync::OnceLock::new();

/// Get the global AUSF context
pub fn ausf_self() -> Arc<RwLock<AusfContext>> {
    GLOBAL_AUSF_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(AusfContext::new())))
        .clone()
}

/// Initialize the global AUSF context
pub fn ausf_context_init(max_ue: usize) {
    let ctx = ausf_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_ue);
    };
}

/// Finalize the global AUSF context
pub fn ausf_context_final() {
    let ctx = ausf_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ausf_context_new() {
        let ctx = AusfContext::new();
        assert!(!ctx.is_initialized());
        assert_eq!(ctx.ue_count(), 0);
    }

    #[test]
    fn test_ausf_context_init_fini() {
        let mut ctx = AusfContext::new();
        ctx.init(100);
        assert!(ctx.is_initialized());
        assert_eq!(ctx.max_num_of_ue, 100);

        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_ue_add_remove() {
        let mut ctx = AusfContext::new();
        ctx.init(100);

        let ue = ctx.ue_add("suci-0-001-01-0000-0-0-0000000001").unwrap();
        assert_eq!(ue.suci, "suci-0-001-01-0000-0-0-0000000001");
        assert_eq!(ctx.ue_count(), 1);

        let found = ctx.ue_find_by_suci("suci-0-001-01-0000-0-0-0000000001");
        assert!(found.is_some());

        ctx.ue_remove(ue.id);
        assert_eq!(ctx.ue_count(), 0);
    }

    #[test]
    fn test_ue_find_by_suci_or_supi() {
        let mut ctx = AusfContext::new();
        ctx.init(100);

        let ue = ctx.ue_add("suci-0-001-01-0000-0-0-0000000001").unwrap();
        ctx.ue_set_supi(ue.id, "imsi-001010000000001");

        // Find by SUCI
        let found = ctx.ue_find_by_suci_or_supi("suci-0-001-01-0000-0-0-0000000001");
        assert!(found.is_some());

        // Find by SUPI
        let found = ctx.ue_find_by_suci_or_supi("imsi-001010000000001");
        assert!(found.is_some());
    }

    #[test]
    fn test_ue_find_by_ctx_id() {
        let mut ctx = AusfContext::new();
        ctx.init(100);

        let ue = ctx.ue_add("suci-0-001-01-0000-0-0-0000000001").unwrap();
        let found = ctx.ue_find_by_ctx_id(&ue.ctx_id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().suci, ue.suci);
    }

    #[test]
    fn test_get_ue_load() {
        let mut ctx = AusfContext::new();
        ctx.init(100);

        assert_eq!(ctx.get_ue_load(), 0);

        ctx.ue_add("suci-0-001-01-0000-0-0-0000000001");
        assert_eq!(ctx.get_ue_load(), 1);

        for i in 2..=50 {
            ctx.ue_add(&format!("suci-0-001-01-0000-0-0-{:010}", i));
        }
        assert_eq!(ctx.get_ue_load(), 50);
    }

    #[test]
    fn test_auth_event() {
        let mut ue = AusfUe::new(1, "suci-test");
        assert!(ue.auth_event.resource_uri.is_none());

        ue.auth_event_store("http://example.com/auth-events/1");
        assert_eq!(
            ue.auth_event.resource_uri,
            Some("http://example.com/auth-events/1".to_string())
        );

        ue.auth_event_clear();
        assert!(ue.auth_event.resource_uri.is_none());
    }
}
