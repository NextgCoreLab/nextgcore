//! UDR Context Management
//!
//! Port of src/udr/context.c - UDR context (empty struct in C)
//!
//! UDR is a stateless data repository - it has no UE/session management.
//! The context is essentially empty, just providing initialization/finalization.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

/// UDR Context - main context structure for UDR
///
/// Note: In the C implementation, udr_context_t is an empty struct.
/// UDR is a stateless data repository that queries the database directly.
pub struct UdrContext {
    /// Context initialized flag
    initialized: AtomicBool,
}

impl UdrContext {
    /// Create a new UDR context
    pub fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
        }
    }

    /// Initialize the UDR context
    ///
    /// Port of udr_context_init()
    pub fn init(&mut self) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }

        // In C: memset(&self, 0, sizeof(udr_context_t));
        // ogs_log_install_domain(&__ogs_dbi_domain, "dbi", ogs_core()->log.level);
        // ogs_log_install_domain(&__udr_log_domain, "udr", ogs_core()->log.level);

        self.initialized.store(true, Ordering::SeqCst);

        log::info!("UDR context initialized");
    }

    /// Finalize the UDR context
    ///
    /// Port of udr_context_final()
    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }

        self.initialized.store(false, Ordering::SeqCst);
        log::info!("UDR context finalized");
    }

    /// Check if context is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Parse configuration
    ///
    /// Port of udr_context_parse_config()
    pub fn parse_config(&self) -> Result<(), String> {
        // In C: This parses YAML config for udr section
        // Keys handled: default, sbi, nrf, scp, service_name, discovery
        // All are handled in sbi library

        // udr_context_prepare() - returns OGS_OK
        // udr_context_validation() - returns OGS_OK

        log::debug!("UDR configuration parsed");
        Ok(())
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
}
