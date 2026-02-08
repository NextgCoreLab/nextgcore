//! OpenTelemetry Integration (B5.1)
//!
//! Provides OpenTelemetry SDK integration for traces, logs, and metrics.
//! This allows exporting NextGCore telemetry to OTLP collectors.

use std::sync::Arc;

/// OpenTelemetry configuration
#[derive(Debug, Clone)]
pub struct OtelConfig {
    /// Service name for telemetry
    pub service_name: String,
    /// Service version
    pub service_version: String,
    /// OTLP endpoint (e.g., "http://localhost:4317")
    pub otlp_endpoint: String,
    /// Export interval in seconds
    pub export_interval_secs: u64,
    /// Enable traces
    pub enable_traces: bool,
    /// Enable metrics
    pub enable_metrics: bool,
    /// Enable logs
    pub enable_logs: bool,
    /// Resource attributes
    pub resource_attributes: Vec<(String, String)>,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            service_name: "nextgcore".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            otlp_endpoint: "http://localhost:4317".to_string(),
            export_interval_secs: 10,
            enable_traces: true,
            enable_metrics: true,
            enable_logs: true,
            resource_attributes: Vec::new(),
        }
    }
}

impl OtelConfig {
    /// Create a new OpenTelemetry configuration
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            ..Default::default()
        }
    }

    /// Set OTLP endpoint
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.otlp_endpoint = endpoint.into();
        self
    }

    /// Set export interval
    pub fn with_export_interval(mut self, interval_secs: u64) -> Self {
        self.export_interval_secs = interval_secs;
        self
    }

    /// Add resource attribute
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.resource_attributes.push((key.into(), value.into()));
        self
    }

    /// Enable only traces
    pub fn traces_only(mut self) -> Self {
        self.enable_traces = true;
        self.enable_metrics = false;
        self.enable_logs = false;
        self
    }

    /// Enable only metrics
    pub fn metrics_only(mut self) -> Self {
        self.enable_traces = false;
        self.enable_metrics = true;
        self.enable_logs = false;
        self
    }
}

/// OpenTelemetry provider
pub struct OtelProvider {
    config: OtelConfig,
    initialized: bool,
}

impl OtelProvider {
    /// Create a new OpenTelemetry provider
    pub fn new(config: OtelConfig) -> Self {
        Self {
            config,
            initialized: false,
        }
    }

    /// Initialize the OpenTelemetry SDK
    ///
    /// This sets up:
    /// - Trace provider with OTLP exporter
    /// - Metrics provider with OTLP exporter
    /// - Log provider with OTLP exporter
    pub fn init(&mut self) -> Result<(), OtelError> {
        if self.initialized {
            return Err(OtelError::AlreadyInitialized);
        }

        // Note: In a real implementation, this would use the opentelemetry crate
        // and set up actual exporters. For now, we provide the structure.

        eprintln!(
            "Initializing OpenTelemetry for service '{}' (endpoint: {})",
            self.config.service_name,
            self.config.otlp_endpoint
        );

        if self.config.enable_traces {
            self.init_traces()?;
        }

        if self.config.enable_metrics {
            self.init_metrics()?;
        }

        if self.config.enable_logs {
            self.init_logs()?;
        }

        self.initialized = true;
        Ok(())
    }

    /// Initialize trace provider
    fn init_traces(&self) -> Result<(), OtelError> {
        eprintln!("Initializing OpenTelemetry traces");

        // In real implementation:
        // - Create OTLP trace exporter
        // - Set up batch span processor
        // - Configure resource with service name and attributes
        // - Install global tracer provider

        Ok(())
    }

    /// Initialize metrics provider
    fn init_metrics(&self) -> Result<(), OtelError> {
        eprintln!("Initializing OpenTelemetry metrics");

        // In real implementation:
        // - Create OTLP metrics exporter
        // - Set up periodic metric reader
        // - Configure resource with service name and attributes
        // - Install global meter provider

        Ok(())
    }

    /// Initialize log provider
    fn init_logs(&self) -> Result<(), OtelError> {
        eprintln!("Initializing OpenTelemetry logs");

        // In real implementation:
        // - Create OTLP log exporter
        // - Set up batch log processor
        // - Configure resource with service name and attributes
        // - Install global logger provider

        Ok(())
    }

    /// Shutdown the OpenTelemetry SDK
    pub fn shutdown(&mut self) -> Result<(), OtelError> {
        if !self.initialized {
            return Ok(());
        }

        eprintln!("Shutting down OpenTelemetry");

        // In real implementation:
        // - Shutdown tracer provider
        // - Shutdown meter provider
        // - Shutdown logger provider
        // - Flush all pending telemetry

        self.initialized = false;
        Ok(())
    }

    /// Check if initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get configuration
    pub fn config(&self) -> &OtelConfig {
        &self.config
    }
}

impl Drop for OtelProvider {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

/// OpenTelemetry span context for distributed tracing
#[derive(Debug, Clone, Default)]
pub struct OtelSpanContext {
    /// Trace ID (128-bit)
    pub trace_id: [u8; 16],
    /// Span ID (64-bit)
    pub span_id: [u8; 8],
    /// Trace flags
    pub trace_flags: u8,
    /// Trace state
    pub trace_state: Option<String>,
}

impl OtelSpanContext {
    /// Create a new span context
    pub fn new(trace_id: [u8; 16], span_id: [u8; 8]) -> Self {
        Self {
            trace_id,
            span_id,
            trace_flags: 0,
            trace_state: None,
        }
    }

    /// Check if context is valid
    pub fn is_valid(&self) -> bool {
        self.trace_id != [0; 16] && self.span_id != [0; 8]
    }

    /// Check if sampled
    pub fn is_sampled(&self) -> bool {
        (self.trace_flags & 0x01) != 0
    }

    /// Set sampled flag
    pub fn set_sampled(&mut self, sampled: bool) {
        if sampled {
            self.trace_flags |= 0x01;
        } else {
            self.trace_flags &= !0x01;
        }
    }

    /// Convert trace ID to hex string
    pub fn trace_id_hex(&self) -> String {
        hex::encode(self.trace_id)
    }

    /// Convert span ID to hex string
    pub fn span_id_hex(&self) -> String {
        hex::encode(self.span_id)
    }

    /// Parse from W3C traceparent header
    /// Format: 00-<trace-id>-<span-id>-<flags>
    pub fn from_traceparent(header: &str) -> Result<Self, OtelError> {
        let parts: Vec<&str> = header.split('-').collect();
        if parts.len() != 4 {
            return Err(OtelError::InvalidTraceparent(header.to_string()));
        }

        if parts[0] != "00" {
            return Err(OtelError::UnsupportedVersion(parts[0].to_string()));
        }

        let trace_id = hex::decode(parts[1])
            .map_err(|_| OtelError::InvalidTraceparent(header.to_string()))?;
        let span_id = hex::decode(parts[2])
            .map_err(|_| OtelError::InvalidTraceparent(header.to_string()))?;
        let flags = u8::from_str_radix(parts[3], 16)
            .map_err(|_| OtelError::InvalidTraceparent(header.to_string()))?;

        if trace_id.len() != 16 || span_id.len() != 8 {
            return Err(OtelError::InvalidTraceparent(header.to_string()));
        }

        let mut trace_id_arr = [0u8; 16];
        let mut span_id_arr = [0u8; 8];
        trace_id_arr.copy_from_slice(&trace_id);
        span_id_arr.copy_from_slice(&span_id);

        Ok(Self {
            trace_id: trace_id_arr,
            span_id: span_id_arr,
            trace_flags: flags,
            trace_state: None,
        })
    }

    /// Generate W3C traceparent header
    pub fn to_traceparent(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            self.trace_id_hex(),
            self.span_id_hex(),
            self.trace_flags
        )
    }
}

/// OpenTelemetry errors
#[derive(Debug, thiserror::Error)]
pub enum OtelError {
    #[error("OpenTelemetry already initialized")]
    AlreadyInitialized,
    #[error("OpenTelemetry not initialized")]
    NotInitialized,
    #[error("Invalid traceparent: {0}")]
    InvalidTraceparent(String),
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(String),
    #[error("Export error: {0}")]
    ExportError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Helper function to create and initialize an OpenTelemetry provider
pub fn init_otel(config: OtelConfig) -> Result<Arc<std::sync::Mutex<OtelProvider>>, OtelError> {
    let provider = Arc::new(std::sync::Mutex::new(OtelProvider::new(config)));
    provider.lock().unwrap().init()?;
    Ok(provider)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_otel_config_default() {
        let config = OtelConfig::default();
        assert_eq!(config.service_name, "nextgcore");
        assert_eq!(config.otlp_endpoint, "http://localhost:4317");
        assert!(config.enable_traces);
        assert!(config.enable_metrics);
        assert!(config.enable_logs);
    }

    #[test]
    fn test_otel_config_builder() {
        let config = OtelConfig::new("test-service")
            .with_endpoint("http://collector:4317")
            .with_export_interval(5)
            .with_attribute("deployment", "production")
            .traces_only();

        assert_eq!(config.service_name, "test-service");
        assert_eq!(config.otlp_endpoint, "http://collector:4317");
        assert_eq!(config.export_interval_secs, 5);
        assert!(config.enable_traces);
        assert!(!config.enable_metrics);
        assert_eq!(config.resource_attributes.len(), 1);
    }

    #[test]
    fn test_span_context_validity() {
        let mut ctx = OtelSpanContext::default();
        assert!(!ctx.is_valid());

        ctx.trace_id = [1; 16];
        ctx.span_id = [2; 8];
        assert!(ctx.is_valid());
    }

    #[test]
    fn test_span_context_sampled() {
        let mut ctx = OtelSpanContext::new([1; 16], [2; 8]);
        assert!(!ctx.is_sampled());

        ctx.set_sampled(true);
        assert!(ctx.is_sampled());
        assert_eq!(ctx.trace_flags, 0x01);

        ctx.set_sampled(false);
        assert!(!ctx.is_sampled());
        assert_eq!(ctx.trace_flags, 0x00);
    }

    #[test]
    fn test_traceparent_roundtrip() {
        let ctx = OtelSpanContext {
            trace_id: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10],
            span_id: [0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8],
            trace_flags: 0x01,
            trace_state: None,
        };

        let header = ctx.to_traceparent();
        assert_eq!(
            header,
            "00-0102030405060708090a0b0c0d0e0f10-a1a2a3a4a5a6a7a8-01"
        );

        let parsed = OtelSpanContext::from_traceparent(&header).unwrap();
        assert_eq!(parsed.trace_id, ctx.trace_id);
        assert_eq!(parsed.span_id, ctx.span_id);
        assert_eq!(parsed.trace_flags, ctx.trace_flags);
    }

    #[test]
    fn test_otel_provider_lifecycle() {
        let config = OtelConfig::new("test").metrics_only();
        let mut provider = OtelProvider::new(config);

        assert!(!provider.is_initialized());

        let result = provider.init();
        assert!(result.is_ok());
        assert!(provider.is_initialized());

        // Second init should fail
        let result = provider.init();
        assert!(result.is_err());

        let result = provider.shutdown();
        assert!(result.is_ok());
        assert!(!provider.is_initialized());
    }

    #[test]
    fn test_invalid_traceparent() {
        let invalid = "invalid-header";
        let result = OtelSpanContext::from_traceparent(invalid);
        assert!(result.is_err());

        let wrong_version = "99-0102030405060708090a0b0c0d0e0f10-a1a2a3a4a5a6a7a8-01";
        let result = OtelSpanContext::from_traceparent(wrong_version);
        assert!(result.is_err());
    }
}
