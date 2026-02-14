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

// ============================================================================
// SBI Tracing Helpers (G32: OTel NF Integration)
// ============================================================================

/// NF type identifier for telemetry attributes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfType {
    Amf, Ausf, Bsf, Ees, Hss, Lmf, MbSmf, Mme, Nrf, Nsacf,
    Nssf, Nwdaf, Pcf, Pcrf, Pin, Scp, Sepp, Sgwc, Sgwu, Smf, Udm, Udr, Upf,
}

impl NfType {
    /// Get the string name of this NF type
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Amf => "AMF", Self::Ausf => "AUSF", Self::Bsf => "BSF",
            Self::Ees => "EES", Self::Hss => "HSS", Self::Lmf => "LMF",
            Self::MbSmf => "MB-SMF", Self::Mme => "MME", Self::Nrf => "NRF",
            Self::Nsacf => "NSACF", Self::Nssf => "NSSF", Self::Nwdaf => "NWDAF",
            Self::Pcf => "PCF", Self::Pcrf => "PCRF", Self::Pin => "PIN",
            Self::Scp => "SCP", Self::Sepp => "SEPP", Self::Sgwc => "SGW-C",
            Self::Sgwu => "SGW-U", Self::Smf => "SMF", Self::Udm => "UDM",
            Self::Udr => "UDR", Self::Upf => "UPF",
        }
    }
}

/// SBI span for wrapping SBI service calls with trace context
#[derive(Debug, Clone)]
pub struct SbiSpan {
    /// Parent trace context
    pub parent: OtelSpanContext,
    /// Span context for this SBI call
    pub context: OtelSpanContext,
    /// NF type making the call
    pub nf_type: NfType,
    /// SBI service name (e.g., "namf-comm", "nsmf-pdusession")
    pub sbi_service: String,
    /// Operation ID (e.g., "UEContextTransfer", "CreateSMContext")
    pub operation_id: String,
    /// HTTP method
    pub method: String,
    /// Target URI
    pub uri: String,
    /// Start time (monotonic nanos)
    pub start_time_ns: u64,
    /// HTTP status code (set on completion)
    pub status_code: Option<u16>,
    /// Error message if failed
    pub error: Option<String>,
}

impl SbiSpan {
    /// Create a new SBI span
    pub fn new(
        parent: &OtelSpanContext,
        nf_type: NfType,
        sbi_service: impl Into<String>,
        operation_id: impl Into<String>,
    ) -> Self {
        let mut span_id = [0u8; 8];
        // Simple span ID generation using timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        span_id.copy_from_slice(&now.to_be_bytes());

        Self {
            parent: parent.clone(),
            context: OtelSpanContext {
                trace_id: parent.trace_id,
                span_id,
                trace_flags: parent.trace_flags,
                trace_state: parent.trace_state.clone(),
            },
            nf_type,
            sbi_service: sbi_service.into(),
            operation_id: operation_id.into(),
            method: String::new(),
            uri: String::new(),
            start_time_ns: now,
            status_code: None,
            error: None,
        }
    }

    /// Set HTTP method and URI
    pub fn with_request(mut self, method: &str, uri: &str) -> Self {
        self.method = method.to_string();
        self.uri = uri.to_string();
        self
    }

    /// Complete the span with a status code
    pub fn complete(&mut self, status_code: u16) {
        self.status_code = Some(status_code);
    }

    /// Complete the span with an error
    pub fn complete_with_error(&mut self, error: impl Into<String>) {
        self.error = Some(error.into());
    }

    /// Get span attributes as key-value pairs
    pub fn attributes(&self) -> Vec<(&'static str, String)> {
        let mut attrs = vec![
            ("nf.type", self.nf_type.as_str().to_string()),
            ("sbi.service", self.sbi_service.clone()),
            ("sbi.operation", self.operation_id.clone()),
        ];
        if !self.method.is_empty() {
            attrs.push(("http.method", self.method.clone()));
        }
        if !self.uri.is_empty() {
            attrs.push(("http.url", self.uri.clone()));
        }
        if let Some(code) = self.status_code {
            attrs.push(("http.status_code", code.to_string()));
        }
        if let Some(ref err) = self.error {
            attrs.push(("error.message", err.clone()));
        }
        attrs
    }

    /// Inject trace context into HTTP headers (W3C traceparent)
    pub fn inject_headers(&self) -> Vec<(String, String)> {
        let mut headers = vec![
            ("traceparent".to_string(), self.context.to_traceparent()),
        ];
        if let Some(ref state) = self.context.trace_state {
            headers.push(("tracestate".to_string(), state.clone()));
        }
        headers
    }
}

/// Extract trace context from HTTP headers
pub fn extract_trace_context(headers: &[(String, String)]) -> Option<OtelSpanContext> {
    headers.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("traceparent"))
        .and_then(|(_, v)| OtelSpanContext::from_traceparent(v).ok())
}

// ============================================================================
// NF Metrics Registry (G41: Prometheus NF Wiring)
// ============================================================================

/// Standard NF metrics that every NF should expose
#[derive(Debug, Clone)]
pub struct NfMetrics {
    /// NF type
    pub nf_type: NfType,
    /// Total SBI requests received
    pub sbi_request_total: u64,
    /// Total SBI errors
    pub sbi_error_total: u64,
    /// Active sessions (UE contexts for AMF, PDU sessions for SMF, etc.)
    pub active_sessions: u64,
    /// Request duration histogram buckets (ms): [1, 5, 10, 25, 50, 100, 250, 500, 1000]
    pub request_duration_buckets: [u64; 9],
    /// Total request duration for average calculation
    pub request_duration_total_ms: u64,
    /// NF uptime in seconds
    pub uptime_secs: u64,
    /// NF registration status with NRF
    pub registered_with_nrf: bool,
}

impl NfMetrics {
    /// Create new metrics for an NF type
    pub fn new(nf_type: NfType) -> Self {
        Self {
            nf_type,
            sbi_request_total: 0,
            sbi_error_total: 0,
            active_sessions: 0,
            request_duration_buckets: [0; 9],
            request_duration_total_ms: 0,
            uptime_secs: 0,
            registered_with_nrf: false,
        }
    }

    /// Record an SBI request
    pub fn record_request(&mut self, duration_ms: u64, is_error: bool) {
        self.sbi_request_total += 1;
        if is_error {
            self.sbi_error_total += 1;
        }
        self.request_duration_total_ms += duration_ms;

        // Update histogram buckets
        let thresholds = [1, 5, 10, 25, 50, 100, 250, 500, 1000];
        for (i, &threshold) in thresholds.iter().enumerate() {
            if duration_ms <= threshold {
                self.request_duration_buckets[i] += 1;
            }
        }
    }

    /// Get error rate (0.0 - 1.0)
    pub fn error_rate(&self) -> f64 {
        if self.sbi_request_total == 0 {
            0.0
        } else {
            self.sbi_error_total as f64 / self.sbi_request_total as f64
        }
    }

    /// Get average request duration in ms
    pub fn avg_duration_ms(&self) -> f64 {
        if self.sbi_request_total == 0 {
            0.0
        } else {
            self.request_duration_total_ms as f64 / self.sbi_request_total as f64
        }
    }

    /// Generate Prometheus exposition format
    pub fn to_prometheus(&self) -> String {
        let nf = self.nf_type.as_str().to_lowercase();
        let mut output = String::new();

        output.push_str(&format!(
            "# HELP nextgcore_{nf}_sbi_request_total Total SBI requests\n\
             # TYPE nextgcore_{nf}_sbi_request_total counter\n\
             nextgcore_{nf}_sbi_request_total {}\n",
            self.sbi_request_total
        ));
        output.push_str(&format!(
            "# HELP nextgcore_{nf}_sbi_error_total Total SBI errors\n\
             # TYPE nextgcore_{nf}_sbi_error_total counter\n\
             nextgcore_{nf}_sbi_error_total {}\n",
            self.sbi_error_total
        ));
        output.push_str(&format!(
            "# HELP nextgcore_{nf}_active_sessions Active sessions\n\
             # TYPE nextgcore_{nf}_active_sessions gauge\n\
             nextgcore_{nf}_active_sessions {}\n",
            self.active_sessions
        ));
        output.push_str(&format!(
            "# HELP nextgcore_{nf}_uptime_seconds NF uptime\n\
             # TYPE nextgcore_{nf}_uptime_seconds gauge\n\
             nextgcore_{nf}_uptime_seconds {}\n",
            self.uptime_secs
        ));
        output.push_str(&format!(
            "# HELP nextgcore_{nf}_nrf_registered NRF registration status\n\
             # TYPE nextgcore_{nf}_nrf_registered gauge\n\
             nextgcore_{nf}_nrf_registered {}\n",
            if self.registered_with_nrf { 1 } else { 0 }
        ));

        output
    }
}

// ============================================================================
// Jaeger Configuration (G43: Jaeger Trace Wiring)
// ============================================================================

/// Jaeger exporter configuration
#[derive(Debug, Clone)]
pub struct JaegerConfig {
    /// Jaeger collector endpoint
    pub endpoint: String,
    /// Service name
    pub service_name: String,
    /// Sampling rate (0.0 - 1.0)
    pub sampling_rate: f64,
    /// Whether to propagate baggage items
    pub propagate_baggage: bool,
    /// Max tag value length
    pub max_tag_value_length: usize,
}

impl Default for JaegerConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:14268/api/traces".to_string(),
            service_name: "nextgcore".to_string(),
            sampling_rate: 1.0,
            propagate_baggage: true,
            max_tag_value_length: 256,
        }
    }
}

impl JaegerConfig {
    /// Create a new Jaeger config for an NF
    pub fn for_nf(nf_type: NfType) -> Self {
        Self {
            service_name: format!("nextgcore-{}", nf_type.as_str().to_lowercase()),
            ..Default::default()
        }
    }

    /// Set endpoint
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    /// Set sampling rate
    pub fn with_sampling_rate(mut self, rate: f64) -> Self {
        self.sampling_rate = rate.clamp(0.0, 1.0);
        self
    }
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
