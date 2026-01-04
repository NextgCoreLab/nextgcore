//! Metrics types and enums
//!
//! This module defines the core types used throughout the metrics library.

use std::net::SocketAddr;

/// Metric type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricType {
    /// Counter metric - monotonically increasing value
    Counter,
    /// Gauge metric - value that can go up and down
    Gauge,
    /// Histogram metric - samples observations and counts them in buckets
    Histogram,
}

/// Histogram bucket type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistogramBucketType {
    /// Variable bucket boundaries
    Variable,
    /// Linear bucket boundaries
    Linear,
    /// Exponential bucket boundaries
    Exponential,
}

/// Histogram bucket parameters
#[derive(Debug, Clone)]
pub enum HistogramBucketParams {
    /// Variable bucket boundaries - explicit list of bucket boundaries
    Variable {
        buckets: Vec<f64>,
    },
    /// Linear bucket boundaries
    Linear {
        start: f64,
        width: f64,
        count: usize,
    },
    /// Exponential bucket boundaries
    Exponential {
        start: f64,
        factor: f64,
        count: usize,
    },
}

impl HistogramBucketParams {
    /// Create variable histogram buckets
    pub fn variable(buckets: Vec<f64>) -> Self {
        HistogramBucketParams::Variable { buckets }
    }

    /// Create linear histogram buckets
    pub fn linear(start: f64, width: f64, count: usize) -> Self {
        HistogramBucketParams::Linear { start, width, count }
    }

    /// Create exponential histogram buckets
    pub fn exponential(start: f64, factor: f64, count: usize) -> Self {
        HistogramBucketParams::Exponential { start, factor, count }
    }

    /// Get the bucket type
    pub fn bucket_type(&self) -> HistogramBucketType {
        match self {
            HistogramBucketParams::Variable { .. } => HistogramBucketType::Variable,
            HistogramBucketParams::Linear { .. } => HistogramBucketType::Linear,
            HistogramBucketParams::Exponential { .. } => HistogramBucketType::Exponential,
        }
    }

    /// Generate the actual bucket boundaries
    pub fn generate_buckets(&self) -> Vec<f64> {
        match self {
            HistogramBucketParams::Variable { buckets } => buckets.clone(),
            HistogramBucketParams::Linear { start, width, count } => {
                (0..*count)
                    .map(|i| start + (i as f64) * width)
                    .collect()
            }
            HistogramBucketParams::Exponential { start, factor, count } => {
                (0..*count)
                    .map(|i| start * factor.powi(i as i32))
                    .collect()
            }
        }
    }
}

/// Custom endpoint handler type
pub type CustomEndpointHandler = Box<dyn Fn(&mut [u8], usize, usize) -> usize + Send + Sync>;

/// Custom endpoint configuration
pub struct CustomEndpoint {
    /// Endpoint path (e.g., "/pdu-info")
    pub endpoint: String,
    /// Handler function
    pub handler: CustomEndpointHandler,
}

impl CustomEndpoint {
    /// Create a new custom endpoint
    pub fn new<F>(endpoint: &str, handler: F) -> Self
    where
        F: Fn(&mut [u8], usize, usize) -> usize + Send + Sync + 'static,
    {
        CustomEndpoint {
            endpoint: endpoint.to_string(),
            handler: Box::new(handler),
        }
    }
}

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Socket address to bind to
    pub addr: SocketAddr,
    /// Socket options
    pub options: Option<SocketOptions>,
}

impl ServerConfig {
    /// Create a new server configuration
    pub fn new(addr: SocketAddr) -> Self {
        ServerConfig {
            addr,
            options: None,
        }
    }

    /// Create a new server configuration with options
    pub fn with_options(addr: SocketAddr, options: SocketOptions) -> Self {
        ServerConfig {
            addr,
            options: Some(options),
        }
    }
}

/// Socket options for the metrics server
#[derive(Debug, Clone, Default)]
pub struct SocketOptions {
    /// TCP nodelay option
    pub tcp_nodelay: bool,
    /// SO_REUSEADDR option
    pub reuse_addr: bool,
    /// SO_REUSEPORT option
    pub reuse_port: bool,
}

impl SocketOptions {
    /// Create new socket options with defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Set TCP nodelay
    pub fn tcp_nodelay(mut self, value: bool) -> Self {
        self.tcp_nodelay = value;
        self
    }

    /// Set SO_REUSEADDR
    pub fn reuse_addr(mut self, value: bool) -> Self {
        self.reuse_addr = value;
        self
    }

    /// Set SO_REUSEPORT
    pub fn reuse_port(mut self, value: bool) -> Self {
        self.reuse_port = value;
        self
    }
}
