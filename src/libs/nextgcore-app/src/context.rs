//! Application Context Management
//!
//! This module provides application context management functionality,
//! ported from lib/app/nextgcore-context.c and lib/app/nextgcore-context.h.

use crate::config::{NextgcoreGlobalConf, NextgcoreLocalConf, NEXTGCORE_MAX_NUM_OF_GTPU_BUFFER};
use serde::{Deserialize, Serialize};
use std::sync::RwLock;

/// Log timestamp mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum NextgcoreLogTs {
    #[default]
    Default,
    Enabled,
    Disabled,
}

/// Logger default configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoggerDefaultConf {
    pub timestamp: NextgcoreLogTs,
}

/// Logger configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoggerConf {
    pub file: Option<String>,
    pub level: Option<String>,
    pub domain: Option<String>,
    pub timestamp: NextgcoreLogTs,
}

/// USRSCTP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsrsctpConf {
    pub udp_port: i32,
}

impl Default for UsrsctpConf {
    fn default() -> Self {
        UsrsctpConf {
            udp_port: 9899, // USRSCTP_LOCAL_UDP_PORT
        }
    }
}

/// Pool sizes configuration
/// Mirrors the pool struct in nextgcore_app_context_t
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PoolConf {
    pub gtpu: u64,
    pub sess: u64,
    pub bearer: u64,
    pub tunnel: u64,
    pub nf_service: u64,
    pub timer: u64,
    pub message: u64,
    pub event: u64,
    pub socket: u64,
    pub subscription: u64,
    pub xact: u64,
    pub stream: u64,
    pub nf: u64,
    pub gtp_node: u64,
    pub csmap: u64,
    pub emerg: u64,
    pub impi: u64,
    pub impu: u64,
}

/// Metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConf {
    pub max_specs: u64,
}

impl Default for MetricsConf {
    fn default() -> Self {
        MetricsConf { max_specs: 512 }
    }
}

/// Application context
/// Mirrors nextgcore_app_context_t
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NextgcoreAppContext {
    pub version: Option<String>,
    pub file: Option<String>,
    pub db_uri: Option<String>,
    pub logger_default: LoggerDefaultConf,
    pub logger: LoggerConf,
    pub usrsctp: UsrsctpConf,
    pub pool: PoolConf,
    pub metrics: MetricsConf,
    pub config_section_id: i32,
}

impl NextgcoreAppContext {
    /// Create a new application context
    pub fn new() -> Self {
        NextgcoreAppContext {
            usrsctp: UsrsctpConf::default(),
            metrics: MetricsConf::default(),
            ..Default::default()
        }
    }

    /// Recalculate pool sizes based on global configuration
    /// Mirrors recalculate_pool_size()
    pub fn recalculate_pool_size(&mut self, global_conf: &NextgcoreGlobalConf) {
        const MAX_NUM_OF_SESS: u64 = 4;
        const MAX_NUM_OF_BEARER: u64 = 4;
        const MAX_NUM_OF_TUNNEL: u64 = 3;
        const POOL_NUM_PER_UE: u64 = 16;
        const NF_SERVICE_PER_NF_INSTANCE: u64 = 16;
        const MAX_NUM_OF_IMPU: u64 = 8;
        const MAX_NUM_EMERG: u64 = 8;

        self.pool.gtpu = global_conf.max.ue * NEXTGCORE_MAX_NUM_OF_GTPU_BUFFER;

        self.pool.sess = global_conf.max.ue * MAX_NUM_OF_SESS;
        self.pool.bearer = self.pool.sess * MAX_NUM_OF_BEARER;
        self.pool.tunnel = self.pool.bearer * MAX_NUM_OF_TUNNEL;

        self.pool.timer = global_conf.max.ue * POOL_NUM_PER_UE;
        self.pool.message = global_conf.max.ue * POOL_NUM_PER_UE;
        self.pool.event = global_conf.max.ue * POOL_NUM_PER_UE;
        self.pool.socket = global_conf.max.ue * POOL_NUM_PER_UE;
        self.pool.xact = global_conf.max.ue * POOL_NUM_PER_UE;
        self.pool.stream = global_conf.max.ue * POOL_NUM_PER_UE;

        self.pool.nf = global_conf.max.peer;
        self.pool.nf_service = self.pool.nf * NF_SERVICE_PER_NF_INSTANCE;
        self.pool.subscription = self.pool.nf * NF_SERVICE_PER_NF_INSTANCE;

        self.pool.gtp_node = if global_conf.max.gtp_peer > 0 {
            global_conf.max.gtp_peer
        } else {
            self.pool.nf
        };

        self.pool.csmap = self.pool.nf;

        self.pool.impi = global_conf.max.ue;
        self.pool.impu = self.pool.impi * MAX_NUM_OF_IMPU;

        self.pool.emerg = MAX_NUM_EMERG;
    }
}

/// Global application state
/// Thread-safe singleton for application context
pub struct NextgcoreApp {
    context: RwLock<NextgcoreAppContext>,
    global_conf: RwLock<NextgcoreGlobalConf>,
    local_conf: RwLock<NextgcoreLocalConf>,
    initialized: RwLock<bool>,
}

impl NextgcoreApp {
    /// Create a new application state
    pub fn new() -> Self {
        NextgcoreApp {
            context: RwLock::new(NextgcoreAppContext::new()),
            global_conf: RwLock::new(NextgcoreGlobalConf::new()),
            local_conf: RwLock::new(NextgcoreLocalConf::new()),
            initialized: RwLock::new(false),
        }
    }

    /// Initialize the application
    pub fn init(&self) -> Result<(), &'static str> {
        let mut initialized = self.initialized.write().unwrap();
        if *initialized {
            return Err("Already initialized");
        }

        // Reset context
        *self.context.write().unwrap() = NextgcoreAppContext::new();

        // Prepare global configuration
        let mut global = self.global_conf.write().unwrap();
        global.prepare();

        // Prepare local configuration
        let mut local = self.local_conf.write().unwrap();
        local.prepare();

        // Recalculate pool sizes
        let mut ctx = self.context.write().unwrap();
        ctx.recalculate_pool_size(&global);

        *initialized = true;
        Ok(())
    }

    /// Finalize the application
    pub fn final_(&self) -> Result<(), &'static str> {
        let mut initialized = self.initialized.write().unwrap();
        if !*initialized {
            return Err("Not initialized");
        }

        *initialized = false;
        Ok(())
    }

    /// Check if initialized
    pub fn is_initialized(&self) -> bool {
        *self.initialized.read().unwrap()
    }

    /// Get application context (read-only)
    pub fn context(&self) -> std::sync::RwLockReadGuard<'_, NextgcoreAppContext> {
        self.context.read().unwrap()
    }

    /// Get application context (mutable)
    pub fn context_mut(&self) -> std::sync::RwLockWriteGuard<'_, NextgcoreAppContext> {
        self.context.write().unwrap()
    }

    /// Get global configuration (read-only)
    pub fn global_conf(&self) -> std::sync::RwLockReadGuard<'_, NextgcoreGlobalConf> {
        self.global_conf.read().unwrap()
    }

    /// Get global configuration (mutable)
    pub fn global_conf_mut(&self) -> std::sync::RwLockWriteGuard<'_, NextgcoreGlobalConf> {
        self.global_conf.write().unwrap()
    }

    /// Get local configuration (read-only)
    pub fn local_conf(&self) -> std::sync::RwLockReadGuard<'_, NextgcoreLocalConf> {
        self.local_conf.read().unwrap()
    }

    /// Get local configuration (mutable)
    pub fn local_conf_mut(&self) -> std::sync::RwLockWriteGuard<'_, NextgcoreLocalConf> {
        self.local_conf.write().unwrap()
    }

    /// Set version
    pub fn set_version(&self, version: &str) {
        self.context.write().unwrap().version = Some(version.to_string());
    }

    /// Set config file path
    pub fn set_file(&self, file: &str) {
        self.context.write().unwrap().file = Some(file.to_string());
    }

    /// Set database URI
    pub fn set_db_uri(&self, uri: &str) {
        self.context.write().unwrap().db_uri = Some(uri.to_string());
    }

    /// Set config section ID
    pub fn set_config_section_id(&self, id: i32) {
        self.context.write().unwrap().config_section_id = id;
    }

    /// Recalculate pool sizes
    pub fn recalculate_pool_size(&self) {
        let global = self.global_conf.read().unwrap();
        let mut ctx = self.context.write().unwrap();
        ctx.recalculate_pool_size(&global);
    }
}

impl Default for NextgcoreApp {
    fn default() -> Self {
        Self::new()
    }
}

// Thread-local storage for the global app instance
// This mimics the C static variable pattern
use std::sync::OnceLock;

static NEXTGCORE_APP: OnceLock<NextgcoreApp> = OnceLock::new();

/// Get the global application instance
/// Mirrors nextgcore_app()
pub fn nextgcore_app() -> &'static NextgcoreApp {
    NEXTGCORE_APP.get_or_init(NextgcoreApp::new)
}

/// Initialize the application context
/// Mirrors nextgcore_app_context_init()
pub fn nextgcore_app_context_init() -> Result<(), &'static str> {
    nextgcore_app().init()
}

/// Finalize the application context
/// Mirrors nextgcore_app_context_final()
pub fn nextgcore_app_context_final() -> Result<(), &'static str> {
    nextgcore_app().final_()
}

/// Get global configuration
/// Mirrors nextgcore_global_conf()
pub fn nextgcore_global_conf() -> std::sync::RwLockReadGuard<'static, NextgcoreGlobalConf> {
    nextgcore_app().global_conf()
}

/// Get local configuration
/// Mirrors nextgcore_local_conf()
pub fn nextgcore_local_conf() -> std::sync::RwLockReadGuard<'static, NextgcoreLocalConf> {
    nextgcore_app().local_conf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_new() {
        let ctx = NextgcoreAppContext::new();
        assert_eq!(ctx.usrsctp.udp_port, 9899);
        assert_eq!(ctx.metrics.max_specs, 512);
    }

    #[test]
    fn test_pool_calculation() {
        let mut ctx = NextgcoreAppContext::new();
        let global = NextgcoreGlobalConf::new();

        ctx.recalculate_pool_size(&global);

        // With default 1024 UEs
        assert_eq!(ctx.pool.gtpu, 1024 * NEXTGCORE_MAX_NUM_OF_GTPU_BUFFER);
        assert_eq!(ctx.pool.sess, 1024 * 4);
        assert_eq!(ctx.pool.timer, 1024 * 16);
        assert_eq!(ctx.pool.nf, 64); // MAX_NUM_OF_PEER
    }

    #[test]
    fn test_nextgcore_app_singleton() {
        let app1 = nextgcore_app();
        let app2 = nextgcore_app();

        // Should be the same instance
        assert!(std::ptr::eq(app1, app2));
    }

    #[test]
    fn test_logger_conf() {
        let logger = LoggerConf::default();
        assert!(logger.file.is_none());
        assert!(logger.level.is_none());
        assert_eq!(logger.timestamp, NextgcoreLogTs::Default);
    }
}
