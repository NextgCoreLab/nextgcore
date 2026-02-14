//! UDR Context Management
//!
//! Port of src/udr/context.c - UDR context with per-UE and per-session tracking.
//!
//! While UDR is primarily a stateless data repository, per-UE/per-session
//! tracking enables subscription data change notifications and request correlation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use crate::ue_sm::UdrUeSmContext;
use crate::sess_sm::UdrSessSmContext;

/// UDR UE tracking data
pub struct UdrUe {
    /// SUPI (Subscriber Permanent Identifier)
    pub supi: String,
    /// Per-UE state machine
    pub sm: UdrUeSmContext,
    /// Sessions for this UE, keyed by PSI
    pub sessions: HashMap<u8, UdrSess>,
}

/// UDR Session tracking data
pub struct UdrSess {
    /// Parent SUPI
    pub supi: String,
    /// PDU Session Identifier
    pub psi: u8,
    /// DNN (Data Network Name)
    pub dnn: Option<String>,
    /// Per-session state machine
    pub sm: UdrSessSmContext,
}

/// UDR Context - main context structure for UDR
pub struct UdrContext {
    /// Context initialized flag
    initialized: AtomicBool,
    /// Per-UE tracking, keyed by SUPI
    ues: HashMap<String, UdrUe>,
}

impl UdrContext {
    /// Create a new UDR context
    pub fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            ues: HashMap::new(),
        }
    }

    /// Initialize the UDR context
    pub fn init(&mut self) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }

        self.ues.clear();
        self.initialized.store(true, Ordering::SeqCst);

        log::info!("UDR context initialized");
    }

    /// Finalize the UDR context
    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }

        // Finalize all UE and session state machines
        for ue in self.ues.values_mut() {
            for sess in ue.sessions.values_mut() {
                sess.sm.fini();
            }
            ue.sm.fini();
        }
        self.ues.clear();

        self.initialized.store(false, Ordering::SeqCst);
        log::info!("UDR context finalized");
    }

    /// Check if context is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Parse configuration
    pub fn parse_config(&self) -> Result<(), String> {
        log::debug!("UDR configuration parsed");
        Ok(())
    }

    /// Find or create a UE context by SUPI
    pub fn ue_find_or_add(&mut self, supi: &str) -> &mut UdrUe {
        if !self.ues.contains_key(supi) {
            log::debug!("[{supi}] Creating UDR UE context");
            let ue = UdrUe {
                supi: supi.to_string(),
                sm: UdrUeSmContext::new(supi),
                sessions: HashMap::new(),
            };
            self.ues.insert(supi.to_string(), ue);
        }
        self.ues.get_mut(supi).unwrap()
    }

    /// Find a UE context by SUPI
    pub fn ue_find(&self, supi: &str) -> Option<&UdrUe> {
        self.ues.get(supi)
    }

    /// Find a mutable UE context by SUPI
    pub fn ue_find_mut(&mut self, supi: &str) -> Option<&mut UdrUe> {
        self.ues.get_mut(supi)
    }

    /// Remove a UE context by SUPI
    pub fn ue_remove(&mut self, supi: &str) -> Option<UdrUe> {
        if let Some(mut ue) = self.ues.remove(supi) {
            for sess in ue.sessions.values_mut() {
                sess.sm.fini();
            }
            ue.sm.fini();
            log::debug!("[{supi}] Removed UDR UE context");
            Some(ue)
        } else {
            None
        }
    }

    /// Get the number of tracked UEs
    pub fn ue_count(&self) -> usize {
        self.ues.len()
    }

    /// Find or create a session context for a UE
    pub fn sess_find_or_add(&mut self, supi: &str, psi: u8, dnn: Option<&str>) -> Option<&mut UdrSess> {
        let ue = self.ue_find_or_add(supi);
        ue.sessions.entry(psi).or_insert_with(|| {
            log::debug!("[{supi}:{psi}] Creating UDR session context");
            
            UdrSess {
                supi: supi.to_string(),
                psi,
                dnn: dnn.map(|s| s.to_string()),
                sm: UdrSessSmContext::new(supi, psi, dnn),
            }
        });
        ue.sessions.get_mut(&psi)
    }

    /// Find a session context
    pub fn sess_find(&self, supi: &str, psi: u8) -> Option<&UdrSess> {
        self.ues.get(supi).and_then(|ue| ue.sessions.get(&psi))
    }

    /// Remove a session context
    pub fn sess_remove(&mut self, supi: &str, psi: u8) -> Option<UdrSess> {
        if let Some(ue) = self.ues.get_mut(supi) {
            if let Some(mut sess) = ue.sessions.remove(&psi) {
                sess.sm.fini();
                log::debug!("[{supi}:{psi}] Removed UDR session context");
                return Some(sess);
            }
        }
        None
    }
}

impl Default for UdrContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global UDR context (thread-safe singleton)
static GLOBAL_UDR_CONTEXT: std::sync::OnceLock<Arc<RwLock<UdrContext>>> = std::sync::OnceLock::new();

/// Get the global UDR context
///
/// Port of udr_self()
pub fn udr_self() -> Arc<RwLock<UdrContext>> {
    GLOBAL_UDR_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(UdrContext::new())))
        .clone()
}

/// Initialize the global UDR context
///
/// Port of udr_context_init()
pub fn udr_context_init() {
    let ctx = udr_self();
    if let Ok(mut context) = ctx.write() {
        context.init();
    };
}

/// Finalize the global UDR context
///
/// Port of udr_context_final()
pub fn udr_context_final() {
    let ctx = udr_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udr_context_new() {
        let ctx = UdrContext::new();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_udr_context_init_fini() {
        let mut ctx = UdrContext::new();
        ctx.init();
        assert!(ctx.is_initialized());

        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_udr_context_double_init() {
        let mut ctx = UdrContext::new();
        ctx.init();
        assert!(ctx.is_initialized());

        // Double init should be safe
        ctx.init();
        assert!(ctx.is_initialized());
    }

    #[test]
    fn test_udr_context_parse_config() {
        let mut ctx = UdrContext::new();
        ctx.init();

        let result = ctx.parse_config();
        assert!(result.is_ok());
    }

    #[test]
    fn test_udr_context_ue_lifecycle() {
        let mut ctx = UdrContext::new();
        ctx.init();

        // Add UE
        let ue = ctx.ue_find_or_add("imsi-001010000000001");
        assert_eq!(ue.supi, "imsi-001010000000001");
        assert_eq!(ctx.ue_count(), 1);

        // Find UE
        assert!(ctx.ue_find("imsi-001010000000001").is_some());
        assert!(ctx.ue_find("imsi-999999999999999").is_none());

        // Remove UE
        assert!(ctx.ue_remove("imsi-001010000000001").is_some());
        assert_eq!(ctx.ue_count(), 0);
        assert!(ctx.ue_find("imsi-001010000000001").is_none());
    }

    #[test]
    fn test_udr_context_sess_lifecycle() {
        let mut ctx = UdrContext::new();
        ctx.init();

        // Add session (auto-creates UE)
        let sess = ctx.sess_find_or_add("imsi-001010000000001", 5, Some("internet"));
        assert!(sess.is_some());
        let sess = sess.unwrap();
        assert_eq!(sess.psi, 5);
        assert_eq!(sess.dnn.as_deref(), Some("internet"));

        // Find session
        assert!(ctx.sess_find("imsi-001010000000001", 5).is_some());
        assert!(ctx.sess_find("imsi-001010000000001", 6).is_none());

        // Remove session
        assert!(ctx.sess_remove("imsi-001010000000001", 5).is_some());
        assert!(ctx.sess_find("imsi-001010000000001", 5).is_none());

        // UE still exists
        assert!(ctx.ue_find("imsi-001010000000001").is_some());
    }

    #[test]
    fn test_udr_context_fini_cleans_ues() {
        let mut ctx = UdrContext::new();
        ctx.init();

        ctx.ue_find_or_add("imsi-001010000000001");
        ctx.sess_find_or_add("imsi-001010000000001", 5, Some("internet"));
        assert_eq!(ctx.ue_count(), 1);

        ctx.fini();
        assert_eq!(ctx.ue_count(), 0);
    }
}
