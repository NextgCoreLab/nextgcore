//! TSCTSF Context Management
//!
//! Time Sensitive Communication and Time Synchronization Function context
//! (TS 23.501 §5.27–§5.28): the in-memory store of time-synchronization
//! exposure configurations managed via the minimal `Ntsctsf` surface of
//! issue #23. All state is in-memory (`RwLock<HashMap<..>>`), matching the
//! other small NFs (pind, nefd, easdfd).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// A stored time-synchronization configuration (TS 29.565 subset: the raw
/// AF/NEF-provided configuration is kept verbatim; translating it into 5GS
/// QoS / DS-TT/NW-TT port management is an explicit follow-up of issue #23).
#[derive(Debug, Clone)]
pub struct TimeSyncConfig {
    /// TSCTSF-assigned configuration ID (the northbound resource ID).
    pub id: String,
    /// Raw configuration JSON as received.
    pub raw: String,
}

impl TimeSyncConfig {
    pub fn new(raw: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            raw: raw.into(),
        }
    }
}

/// TSCTSF context errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsctsfContextError {
    MaxConfigsReached,
    LockPoisoned,
}

impl TsctsfContextError {
    pub fn detail(&self) -> &'static str {
        match self {
            Self::MaxConfigsReached => "Maximum number of time-sync configurations reached",
            Self::LockPoisoned => "TSCTSF context lock poisoned",
        }
    }

    pub fn cause(&self) -> &'static str {
        match self {
            Self::MaxConfigsReached => "MAX_CONFIGS_REACHED",
            Self::LockPoisoned => "INTERNAL",
        }
    }
}

/// TSCTSF Context
pub struct TsctsfContext {
    /// Time-sync configurations (by TSCTSF-assigned configuration ID).
    configs: RwLock<HashMap<String, TimeSyncConfig>>,
    /// Maximum stored configurations.
    max_configs: usize,
    /// Context initialized flag
    initialized: AtomicBool,
}

impl TsctsfContext {
    pub fn new() -> Self {
        Self {
            configs: RwLock::new(HashMap::new()),
            max_configs: 0,
            initialized: AtomicBool::new(false),
        }
    }

    pub fn init(&mut self, max_configs: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.max_configs = max_configs;
        self.initialized.store(true, Ordering::SeqCst);
        log::info!("TSCTSF context initialized (max {max_configs} time-sync configurations)");
    }

    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }
        if let Ok(mut configs) = self.configs.write() {
            configs.clear();
        }
        self.initialized.store(false, Ordering::SeqCst);
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Insert a configuration, enforcing the capacity cap.
    pub fn config_insert(&self, config: TimeSyncConfig) -> Result<(), TsctsfContextError> {
        let mut configs = self
            .configs
            .write()
            .map_err(|_| TsctsfContextError::LockPoisoned)?;
        if configs.len() >= self.max_configs {
            return Err(TsctsfContextError::MaxConfigsReached);
        }
        let id = config.id.clone();
        configs.insert(id.clone(), config);
        log::debug!("TSCTSF time-sync configuration inserted (id={id})");
        Ok(())
    }

    /// Find a configuration by ID.
    pub fn config_find(&self, id: &str) -> Option<TimeSyncConfig> {
        let configs = self.configs.read().ok()?;
        configs.get(id).cloned()
    }

    /// Remove a configuration by ID.
    pub fn config_remove(&self, id: &str) -> Option<TimeSyncConfig> {
        let mut configs = self.configs.write().ok()?;
        configs.remove(id)
    }

    /// Number of stored configurations (NRF `/load` gauge source).
    pub fn config_count(&self) -> usize {
        self.configs.read().map(|c| c.len()).unwrap_or(0)
    }
}

impl Default for TsctsfContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global TSCTSF context
static GLOBAL_TSCTSF_CONTEXT: std::sync::OnceLock<Arc<RwLock<TsctsfContext>>> =
    std::sync::OnceLock::new();

pub fn tsctsf_self() -> Arc<RwLock<TsctsfContext>> {
    GLOBAL_TSCTSF_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(TsctsfContext::new())))
        .clone()
}

pub fn tsctsf_context_init(max_configs: usize) {
    let ctx = tsctsf_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_configs);
    };
}

pub fn tsctsf_context_final() {
    let ctx = tsctsf_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Local instances — race-free without a global test lock.

    fn ctx(max: usize) -> TsctsfContext {
        let mut context = TsctsfContext::new();
        context.init(max);
        context
    }

    #[test]
    fn config_insert_find_remove_roundtrip() {
        let context = ctx(8);
        let config = TimeSyncConfig::new(r#"{"timeDomain": 1}"#);
        let id = config.id.clone();

        context.config_insert(config).expect("insert");
        assert_eq!(context.config_count(), 1);
        assert_eq!(context.config_find(&id).expect("find").id, id);

        assert_eq!(context.config_remove(&id).expect("remove").id, id);
        assert_eq!(context.config_count(), 0);
        assert!(context.config_find(&id).is_none());
    }

    #[test]
    fn config_cap_is_enforced() {
        let context = ctx(1);
        context
            .config_insert(TimeSyncConfig::new("{}"))
            .expect("fits");
        let err = context
            .config_insert(TimeSyncConfig::new("{}"))
            .expect_err("cap");
        assert_eq!(err, TsctsfContextError::MaxConfigsReached);
        assert_eq!(err.cause(), "MAX_CONFIGS_REACHED");
    }

    #[test]
    fn init_guards_reinit_and_fini_clears() {
        let mut context = TsctsfContext::new();
        assert!(!context.is_initialized());
        context.init(4);
        context.init(1); // guarded no-op
        context.config_insert(TimeSyncConfig::new("{}")).expect("a");
        context
            .config_insert(TimeSyncConfig::new("{}"))
            .expect("caps kept from first init");
        context.fini();
        assert!(!context.is_initialized());
        assert_eq!(context.config_count(), 0);
    }

    #[test]
    fn uninitialized_context_rejects_inserts() {
        let context = TsctsfContext::new();
        assert_eq!(
            context.config_insert(TimeSyncConfig::new("{}")),
            Err(TsctsfContextError::MaxConfigsReached)
        );
    }

    #[test]
    fn generated_ids_are_unique() {
        assert_ne!(TimeSyncConfig::new("{}").id, TimeSyncConfig::new("{}").id);
    }
}
