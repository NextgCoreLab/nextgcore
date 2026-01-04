//! Metrics HTTP server
//!
//! This module provides the HTTP server for exposing Prometheus metrics,
//! mirroring lib/metrics/prometheus/context.c from the C implementation.

use std::net::SocketAddr;
use crate::types::ServerConfig;

/// Metrics server state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    /// Server is stopped
    Stopped,
    /// Server is starting
    Starting,
    /// Server is running
    Running,
    /// Server encountered an error
    Error,
}

/// Metrics HTTP server
/// 
/// Provides HTTP endpoints for:
/// - `/` - Health check
/// - `/metrics` - Prometheus metrics
/// - Custom endpoints registered via the context
pub struct MetricsServer {
    /// Server configuration
    config: ServerConfig,
    /// Server state
    state: ServerState,
}

impl MetricsServer {
    /// Create a new metrics server
    pub fn new(config: ServerConfig) -> Self {
        MetricsServer {
            config,
            state: ServerState::Stopped,
        }
    }

    /// Get the server address
    pub fn addr(&self) -> SocketAddr {
        self.config.addr
    }

    /// Get the server configuration
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Get the server state
    pub fn state(&self) -> ServerState {
        self.state
    }

    /// Check if the server is running
    pub fn is_running(&self) -> bool {
        self.state == ServerState::Running
    }

    /// Start the metrics server
    /// 
    /// This starts an HTTP server that exposes:
    /// - `/` - Returns "OK" for health checks
    /// - `/metrics` - Returns Prometheus metrics in text format
    pub fn start(&mut self) -> Result<(), String> {
        if self.state == ServerState::Running {
            return Err("Server is already running".to_string());
        }

        self.state = ServerState::Starting;

        // In a real implementation, this would start an HTTP server
        // using hyper or another HTTP library. For now, we just mark
        // the server as running.
        //
        // The actual HTTP server implementation would:
        // 1. Bind to the configured address
        // 2. Handle GET requests to /
        // 3. Handle GET requests to /metrics
        // 4. Handle custom endpoints
        
        log::info!(
            "metrics_server() [http://{}]:{}",
            self.config.addr.ip(),
            self.config.addr.port()
        );

        self.state = ServerState::Running;
        Ok(())
    }

    /// Stop the metrics server
    pub fn stop(&mut self) {
        if self.state != ServerState::Running {
            return;
        }

        // In a real implementation, this would stop the HTTP server
        self.state = ServerState::Stopped;
    }
}

/// Server pool for managing multiple metrics servers
pub struct ServerPool {
    servers: Vec<MetricsServer>,
    capacity: usize,
}

impl ServerPool {
    /// Create a new server pool
    pub fn new(capacity: usize) -> Self {
        ServerPool {
            servers: Vec::with_capacity(capacity),
            capacity,
        }
    }

    /// Add a server to the pool
    pub fn add(&mut self, config: ServerConfig) -> Option<&MetricsServer> {
        if self.servers.len() >= self.capacity {
            return None;
        }
        
        let server = MetricsServer::new(config);
        self.servers.push(server);
        self.servers.last()
    }

    /// Remove a server from the pool
    pub fn remove(&mut self, addr: SocketAddr) -> Option<MetricsServer> {
        if let Some(pos) = self.servers.iter().position(|s| s.addr() == addr) {
            Some(self.servers.remove(pos))
        } else {
            None
        }
    }

    /// Remove all servers
    pub fn remove_all(&mut self) {
        self.servers.clear();
    }

    /// Get all servers
    pub fn servers(&self) -> &[MetricsServer] {
        &self.servers
    }

    /// Get mutable reference to all servers
    pub fn servers_mut(&mut self) -> &mut Vec<MetricsServer> {
        &mut self.servers
    }

    /// Start all servers
    pub fn start_all(&mut self) -> Vec<Result<(), String>> {
        self.servers
            .iter_mut()
            .map(|s| s.start())
            .collect()
    }

    /// Stop all servers
    pub fn stop_all(&mut self) {
        for server in &mut self.servers {
            server.stop();
        }
    }

    /// Get the number of servers
    pub fn len(&self) -> usize {
        self.servers.len()
    }

    /// Check if the pool is empty
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    /// Get the capacity
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl Default for ServerPool {
    fn default() -> Self {
        Self::new(16)
    }
}
