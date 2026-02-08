//! Metrics context management
//!
//! This module provides the main context for metrics collection,
//! mirroring lib/metrics/context.c from the C implementation.

use std::sync::{Arc, RwLock, OnceLock};
use crate::{
    DEFAULT_PROMETHEUS_HTTP_PORT,
    types::{CustomEndpoint, ServerConfig},
    spec::MetricsSpec,
    server::MetricsServer,
};

/// Global metrics context singleton
static METRICS_CONTEXT: OnceLock<Arc<RwLock<MetricsContext>>> = OnceLock::new();

/// Metrics context - holds all metrics configuration and state
pub struct MetricsContext {
    /// List of metrics servers
    servers: Vec<MetricsServer>,
    /// List of metric specifications
    specs: Vec<Arc<MetricsSpec>>,
    /// Metrics HTTP port
    metrics_port: u16,
    /// Custom endpoints
    custom_endpoints: Vec<CustomEndpoint>,
    /// Whether the context is initialized
    initialized: bool,
}

impl MetricsContext {
    /// Create a new metrics context
    pub fn new() -> Self {
        MetricsContext {
            servers: Vec::new(),
            specs: Vec::new(),
            metrics_port: DEFAULT_PROMETHEUS_HTTP_PORT,
            custom_endpoints: Vec::new(),
            initialized: false,
        }
    }

    /// Initialize the global metrics context
    pub fn init() {
        let ctx = METRICS_CONTEXT.get_or_init(|| {
            Arc::new(RwLock::new(MetricsContext::new()))
        });
        
        if let Ok(mut context) = ctx.write() {
            context.initialized = true;
        }
    }

    /// Get the global metrics context
    pub fn get() -> Option<Arc<RwLock<MetricsContext>>> {
        METRICS_CONTEXT.get().cloned()
    }

    /// Open the metrics context (start servers)
    pub fn open(&mut self) {
        for server in &mut self.servers {
            if let Err(e) = server.start() {
                log::error!("Failed to start metrics server: {e}");
            }
        }
    }

    /// Close the metrics context (stop servers)
    pub fn close(&mut self) {
        for server in &mut self.servers {
            server.stop();
        }
        self.custom_endpoints.clear();
    }

    /// Finalize the metrics context
    pub fn finalize(&mut self) {
        self.specs.clear();
        self.servers.clear();
        self.initialized = false;
    }

    /// Get the metrics port
    pub fn metrics_port(&self) -> u16 {
        self.metrics_port
    }

    /// Set the metrics port
    pub fn set_metrics_port(&mut self, port: u16) {
        self.metrics_port = port;
    }

    /// Add a server configuration
    pub fn add_server(&mut self, config: ServerConfig) -> &MetricsServer {
        let server = MetricsServer::new(config);
        self.servers.push(server);
        self.servers.last().unwrap()
    }

    /// Remove a server by index
    pub fn remove_server(&mut self, index: usize) -> Option<MetricsServer> {
        if index < self.servers.len() {
            Some(self.servers.remove(index))
        } else {
            None
        }
    }

    /// Remove all servers
    pub fn remove_all_servers(&mut self) {
        self.servers.clear();
    }

    /// Get the list of servers
    pub fn servers(&self) -> &[MetricsServer] {
        &self.servers
    }

    /// Get mutable list of servers
    pub fn servers_mut(&mut self) -> &mut Vec<MetricsServer> {
        &mut self.servers
    }

    /// Add a metric specification
    pub fn add_spec(&mut self, spec: MetricsSpec) -> Arc<MetricsSpec> {
        let spec = Arc::new(spec);
        self.specs.push(spec.clone());
        spec
    }

    /// Remove a metric specification
    pub fn remove_spec(&mut self, name: &str) -> Option<Arc<MetricsSpec>> {
        if let Some(pos) = self.specs.iter().position(|s| s.name() == name) {
            Some(self.specs.remove(pos))
        } else {
            None
        }
    }

    /// Get the list of specs
    pub fn specs(&self) -> &[Arc<MetricsSpec>] {
        &self.specs
    }

    /// Register a custom endpoint
    pub fn register_custom_endpoint(&mut self, endpoint: CustomEndpoint) {
        self.custom_endpoints.push(endpoint);
    }

    /// Get custom endpoints
    pub fn custom_endpoints(&self) -> &[CustomEndpoint] {
        &self.custom_endpoints
    }

    /// Check if context is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Parse configuration from YAML
    /// 
    /// This parses the metrics section from the configuration file.
    /// Expected format:
    /// ```yaml
    /// metrics:
    ///   server:
    ///     - address: 127.0.0.1
    ///       port: 9090
    /// ```
    pub fn parse_config(&mut self, config: &serde_yaml::Value, local: Option<&str>) -> Result<(), String> {
        // Set default port
        self.metrics_port = DEFAULT_PROMETHEUS_HTTP_PORT;

        // Look for the local section if specified
        let root = if let Some(local_key) = local {
            config.get(local_key).unwrap_or(config)
        } else {
            config
        };

        // Look for metrics section
        if let Some(metrics) = root.get("metrics") {
            // Parse server configuration
            if let Some(server_config) = metrics.get("server") {
                self.parse_server_config(server_config)?;
            }
        }

        Ok(())
    }

    /// Parse server configuration from YAML
    fn parse_server_config(&mut self, config: &serde_yaml::Value) -> Result<(), String> {
        let servers = if config.is_sequence() {
            config.as_sequence().unwrap().iter().collect::<Vec<_>>()
        } else if config.is_mapping() {
            vec![config]
        } else {
            return Ok(());
        };

        for server in servers {
            let mut port = self.metrics_port;
            let mut addresses: Vec<String> = Vec::new();

            if let Some(addr) = server.get("address") {
                if let Some(addr_str) = addr.as_str() {
                    addresses.push(addr_str.to_string());
                } else if let Some(addr_seq) = addr.as_sequence() {
                    for a in addr_seq {
                        if let Some(s) = a.as_str() {
                            addresses.push(s.to_string());
                        }
                    }
                }
            }

            if let Some(p) = server.get("port") {
                if let Some(p_val) = p.as_u64() {
                    port = p_val as u16;
                }
            }

            // Create server configs for each address
            for addr in addresses {
                if let Ok(socket_addr) = format!("{addr}:{port}").parse() {
                    self.add_server(ServerConfig::new(socket_addr));
                }
            }
        }

        Ok(())
    }
}

impl Default for MetricsContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Initialize the global metrics context
pub fn ogs_metrics_context_init() {
    MetricsContext::init();
}

/// Open the metrics context
pub fn ogs_metrics_context_open() {
    if let Some(ctx) = MetricsContext::get() {
        if let Ok(mut context) = ctx.write() {
            context.open();
        }
    }
}

/// Close the metrics context
pub fn ogs_metrics_context_close() {
    if let Some(ctx) = MetricsContext::get() {
        if let Ok(mut context) = ctx.write() {
            context.close();
        }
    }
}

/// Finalize the metrics context
pub fn ogs_metrics_context_final() {
    if let Some(ctx) = MetricsContext::get() {
        if let Ok(mut context) = ctx.write() {
            context.finalize();
        }
    }
}

/// Get the global metrics context
pub fn ogs_metrics_self() -> Option<Arc<RwLock<MetricsContext>>> {
    MetricsContext::get()
}
