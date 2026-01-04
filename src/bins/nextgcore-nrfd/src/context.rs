//! NRF Context Management
//!
//! Port of src/nrf/context.c - NRF context with association list and pool management

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

/// Maximum number of NRF associations per UE (multiplier)
const MAX_NUM_OF_NRF_ASSOC: usize = 8;

/// NRF Association - represents a pending request association
#[derive(Debug, Clone)]
pub struct NrfAssoc {
    /// Unique association ID
    pub id: u64,
    /// Associated stream ID for response
    pub stream_id: u64,
}

impl NrfAssoc {
    /// Create a new NRF association
    pub fn new(id: u64, stream_id: u64) -> Self {
        Self { id, stream_id }
    }
}

/// NRF Context - main context structure for NRF
pub struct NrfContext {
    /// Association list (pending requests)
    assoc_list: RwLock<HashMap<u64, NrfAssoc>>,
    /// Next association ID
    next_assoc_id: AtomicUsize,
    /// Maximum number of associations
    max_num_of_assoc: usize,
    /// Context initialized flag
    initialized: AtomicBool,
    /// Heartbeat interval (seconds)
    pub heartbeat_interval: RwLock<u32>,
}

impl NrfContext {
    /// Create a new NRF context
    pub fn new() -> Self {
        Self {
            assoc_list: RwLock::new(HashMap::new()),
            next_assoc_id: AtomicUsize::new(1),
            max_num_of_assoc: 0,
            initialized: AtomicBool::new(false),
            heartbeat_interval: RwLock::new(10), // Default 10 seconds
        }
    }

    /// Initialize the NRF context
    pub fn init(&mut self, max_ue: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }

        self.max_num_of_assoc = max_ue * MAX_NUM_OF_NRF_ASSOC;
        self.initialized.store(true, Ordering::SeqCst);

        log::info!(
            "NRF context initialized with max {} associations",
            self.max_num_of_assoc
        );
    }

    /// Finalize the NRF context
    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }

        // Remove all associations
        self.assoc_remove_all();

        self.initialized.store(false, Ordering::SeqCst);
        log::info!("NRF context finalized");
    }

    /// Check if context is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Add a new association
    pub fn assoc_add(&self, stream_id: u64) -> Option<NrfAssoc> {
        let mut assoc_list = self.assoc_list.write().ok()?;

        if assoc_list.len() >= self.max_num_of_assoc {
            log::error!(
                "Maximum number of associations [{}] reached",
                self.max_num_of_assoc
            );
            return None;
        }

        let id = self.next_assoc_id.fetch_add(1, Ordering::SeqCst) as u64;
        let assoc = NrfAssoc::new(id, stream_id);
        assoc_list.insert(id, assoc.clone());

        Some(assoc)
    }

    /// Remove an association by ID
    pub fn assoc_remove(&self, id: u64) -> Option<NrfAssoc> {
        let mut assoc_list = self.assoc_list.write().ok()?;
        assoc_list.remove(&id)
    }

    /// Remove all associations
    pub fn assoc_remove_all(&self) {
        if let Ok(mut assoc_list) = self.assoc_list.write() {
            assoc_list.clear();
        }
    }

    /// Find an association by ID
    pub fn assoc_find(&self, id: u64) -> Option<NrfAssoc> {
        let assoc_list = self.assoc_list.read().ok()?;
        assoc_list.get(&id).cloned()
    }

    /// Get the number of associations
    pub fn assoc_count(&self) -> usize {
        self.assoc_list.read().map(|l| l.len()).unwrap_or(0)
    }

    /// Set heartbeat interval
    pub fn set_heartbeat_interval(&self, interval: u32) {
        if let Ok(mut hb) = self.heartbeat_interval.write() {
            *hb = interval;
        }
    }

    /// Get heartbeat interval
    pub fn get_heartbeat_interval(&self) -> u32 {
        self.heartbeat_interval.read().map(|hb| *hb).unwrap_or(10)
    }
}

impl Default for NrfContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global NRF context (thread-safe singleton)
static GLOBAL_NRF_CONTEXT: std::sync::OnceLock<Arc<RwLock<NrfContext>>> =
    std::sync::OnceLock::new();

/// Get the global NRF context
pub fn nrf_self() -> Arc<RwLock<NrfContext>> {
    GLOBAL_NRF_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(NrfContext::new())))
        .clone()
}

/// Initialize the global NRF context
pub fn nrf_context_init(max_ue: usize) {
    let ctx = nrf_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_ue);
    };
}

/// Finalize the global NRF context
pub fn nrf_context_final() {
    let ctx = nrf_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nrf_context_new() {
        let ctx = NrfContext::new();
        assert!(!ctx.is_initialized());
        assert_eq!(ctx.assoc_count(), 0);
    }

    #[test]
    fn test_nrf_context_init_fini() {
        let mut ctx = NrfContext::new();
        ctx.init(100);
        assert!(ctx.is_initialized());
        assert_eq!(ctx.max_num_of_assoc, 100 * MAX_NUM_OF_NRF_ASSOC);

        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_assoc_add_remove() {
        let mut ctx = NrfContext::new();
        ctx.init(100);

        let assoc = ctx.assoc_add(123).unwrap();
        assert_eq!(assoc.stream_id, 123);
        assert_eq!(ctx.assoc_count(), 1);

        let found = ctx.assoc_find(assoc.id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().stream_id, 123);

        ctx.assoc_remove(assoc.id);
        assert_eq!(ctx.assoc_count(), 0);
    }

    #[test]
    fn test_assoc_remove_all() {
        let mut ctx = NrfContext::new();
        ctx.init(100);

        ctx.assoc_add(1);
        ctx.assoc_add(2);
        ctx.assoc_add(3);
        assert_eq!(ctx.assoc_count(), 3);

        ctx.assoc_remove_all();
        assert_eq!(ctx.assoc_count(), 0);
    }

    #[test]
    fn test_heartbeat_interval() {
        let ctx = NrfContext::new();
        assert_eq!(ctx.get_heartbeat_interval(), 10);

        ctx.set_heartbeat_interval(30);
        assert_eq!(ctx.get_heartbeat_interval(), 30);
    }
}
