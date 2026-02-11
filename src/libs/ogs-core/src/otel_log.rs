//! OpenTelemetry Structured Logging Adapter (B2.1)
//!
//! Provides structured logging with OpenTelemetry context propagation for
//! distributed tracing across 6G core network functions.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Structured Log Entry
// ============================================================================

/// Severity level (aligned with OpenTelemetry Logs specification).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OtelSeverity {
    Trace = 1,
    Debug = 5,
    Info = 9,
    Warn = 13,
    Error = 17,
    Fatal = 21,
}

impl OtelSeverity {
    /// Returns the OTel severity number.
    pub fn number(&self) -> u8 {
        *self as u8
    }

    /// Returns the OTel severity text.
    pub fn text(&self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
            Self::Fatal => "FATAL",
        }
    }
}

impl fmt::Display for OtelSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text())
    }
}

/// Structured log entry with OTel context.
#[derive(Debug, Clone)]
pub struct StructuredLogEntry {
    /// Timestamp (nanoseconds since epoch).
    pub timestamp_ns: u64,
    /// Observed timestamp (when the log was collected).
    pub observed_timestamp_ns: u64,
    /// Severity level.
    pub severity: OtelSeverity,
    /// Log body (message).
    pub body: String,
    /// Resource attributes (service.name, service.version, etc.).
    pub resource: HashMap<String, String>,
    /// Log attributes (structured key-value pairs).
    pub attributes: HashMap<String, LogValue>,
    /// Trace context (if correlated with a trace).
    pub trace_id: Option<[u8; 16]>,
    /// Span ID (if correlated with a span).
    pub span_id: Option<[u8; 8]>,
    /// Trace flags.
    pub trace_flags: u8,
}

/// Structured log value types.
#[derive(Debug, Clone, PartialEq)]
pub enum LogValue {
    String(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Bytes(Vec<u8>),
}

impl fmt::Display for LogValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogValue::String(s) => write!(f, "{}", s),
            LogValue::Int(i) => write!(f, "{}", i),
            LogValue::Float(v) => write!(f, "{}", v),
            LogValue::Bool(b) => write!(f, "{}", b),
            LogValue::Bytes(b) => write!(f, "{:02x?}", b),
        }
    }
}

impl StructuredLogEntry {
    /// Creates a new structured log entry.
    pub fn new(severity: OtelSeverity, body: impl Into<String>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        Self {
            timestamp_ns: now,
            observed_timestamp_ns: now,
            severity,
            body: body.into(),
            resource: HashMap::new(),
            attributes: HashMap::new(),
            trace_id: None,
            span_id: None,
            trace_flags: 0,
        }
    }

    /// Set resource attribute.
    pub fn with_resource(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.resource.insert(key.into(), value.into());
        self
    }

    /// Set log attribute.
    pub fn with_attr(mut self, key: impl Into<String>, value: LogValue) -> Self {
        self.attributes.insert(key.into(), value);
        self
    }

    /// Set string attribute.
    pub fn with_str(self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.with_attr(key, LogValue::String(value.into()))
    }

    /// Set integer attribute.
    pub fn with_int(self, key: impl Into<String>, value: i64) -> Self {
        self.with_attr(key, LogValue::Int(value))
    }

    /// Attach trace context.
    pub fn with_trace(mut self, trace_id: [u8; 16], span_id: [u8; 8]) -> Self {
        self.trace_id = Some(trace_id);
        self.span_id = Some(span_id);
        self
    }

    /// Render as JSON (OTLP-compatible format).
    pub fn to_json(&self) -> String {
        let mut parts = Vec::new();
        parts.push(format!("\"timeUnixNano\":\"{}\"", self.timestamp_ns));
        parts.push(format!("\"severityNumber\":{}", self.severity.number()));
        parts.push(format!("\"severityText\":\"{}\"", self.severity.text()));
        parts.push(format!("\"body\":{{\"stringValue\":\"{}\"}}", escape_json(&self.body)));

        if let Some(tid) = &self.trace_id {
            parts.push(format!("\"traceId\":\"{}\"", hex_encode(tid)));
        }
        if let Some(sid) = &self.span_id {
            parts.push(format!("\"spanId\":\"{}\"", hex_encode(sid)));
        }

        if !self.attributes.is_empty() {
            let attrs: Vec<String> = self.attributes.iter().map(|(k, v)| {
                let val = match v {
                    LogValue::String(s) => format!("{{\"stringValue\":\"{}\"}}", escape_json(s)),
                    LogValue::Int(i) => format!("{{\"intValue\":\"{}\"}}", i),
                    LogValue::Float(f) => format!("{{\"doubleValue\":{}}}", f),
                    LogValue::Bool(b) => format!("{{\"boolValue\":{}}}", b),
                    LogValue::Bytes(b) => format!("{{\"bytesValue\":\"{}\"}}", hex_encode(b)),
                };
                format!("{{\"key\":\"{}\",\"value\":{}}}", escape_json(k), val)
            }).collect();
            parts.push(format!("\"attributes\":[{}]", attrs.join(",")));
        }

        format!("{{{}}}", parts.join(","))
    }
}

// ============================================================================
// Structured Logger
// ============================================================================

/// Thread-safe structured logger with NF context.
pub struct StructuredLogger {
    service_name: String,
    service_version: String,
    nf_type: String,
    instance_id: String,
    log_count: AtomicU64,
}

impl StructuredLogger {
    /// Creates a new structured logger for a network function.
    pub fn new(
        service_name: impl Into<String>,
        nf_type: impl Into<String>,
        instance_id: impl Into<String>,
    ) -> Self {
        Self {
            service_name: service_name.into(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            nf_type: nf_type.into(),
            instance_id: instance_id.into(),
            log_count: AtomicU64::new(0),
        }
    }

    /// Emit a structured log entry.
    pub fn emit(&self, entry: StructuredLogEntry) -> StructuredLogEntry {
        self.log_count.fetch_add(1, Ordering::Relaxed);
        entry
            .with_resource("service.name", &self.service_name)
            .with_resource("service.version", &self.service_version)
            .with_str("nf.type", &self.nf_type)
            .with_str("nf.instance_id", &self.instance_id)
    }

    /// Total log entries emitted.
    pub fn log_count(&self) -> u64 {
        self.log_count.load(Ordering::Relaxed)
    }

    /// Create an info-level log entry.
    pub fn info(&self, body: impl Into<String>) -> StructuredLogEntry {
        self.emit(StructuredLogEntry::new(OtelSeverity::Info, body))
    }

    /// Create a warn-level log entry.
    pub fn warn(&self, body: impl Into<String>) -> StructuredLogEntry {
        self.emit(StructuredLogEntry::new(OtelSeverity::Warn, body))
    }

    /// Create an error-level log entry.
    pub fn error(&self, body: impl Into<String>) -> StructuredLogEntry {
        self.emit(StructuredLogEntry::new(OtelSeverity::Error, body))
    }

    /// Create a debug-level log entry.
    pub fn debug(&self, body: impl Into<String>) -> StructuredLogEntry {
        self.emit(StructuredLogEntry::new(OtelSeverity::Debug, body))
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(OtelSeverity::Trace < OtelSeverity::Debug);
        assert!(OtelSeverity::Debug < OtelSeverity::Info);
        assert!(OtelSeverity::Info < OtelSeverity::Warn);
        assert!(OtelSeverity::Warn < OtelSeverity::Error);
        assert!(OtelSeverity::Error < OtelSeverity::Fatal);
    }

    #[test]
    fn test_structured_log_entry() {
        let entry = StructuredLogEntry::new(OtelSeverity::Info, "Test message")
            .with_str("nf.type", "AMF")
            .with_int("ue.count", 42);

        assert_eq!(entry.severity, OtelSeverity::Info);
        assert_eq!(entry.body, "Test message");
        assert_eq!(entry.attributes.len(), 2);
    }

    #[test]
    fn test_structured_log_json() {
        let entry = StructuredLogEntry::new(OtelSeverity::Warn, "High load")
            .with_str("nf.type", "SMF")
            .with_int("session.count", 1000);

        let json = entry.to_json();
        assert!(json.contains("\"severityText\":\"WARN\""));
        assert!(json.contains("\"severityNumber\":13"));
        assert!(json.contains("High load"));
    }

    #[test]
    fn test_structured_log_trace_context() {
        let tid = [1u8; 16];
        let sid = [2u8; 8];
        let entry = StructuredLogEntry::new(OtelSeverity::Info, "Traced")
            .with_trace(tid, sid);

        let json = entry.to_json();
        assert!(json.contains("\"traceId\""));
        assert!(json.contains("\"spanId\""));
    }

    #[test]
    fn test_structured_logger() {
        let logger = StructuredLogger::new("amfd", "AMF", "amf-001");
        let entry = logger.info("NF started");

        assert!(entry.resource.contains_key("service.name"));
        assert_eq!(logger.log_count(), 1);
    }

    #[test]
    fn test_log_value_display() {
        assert_eq!(LogValue::String("hello".into()).to_string(), "hello");
        assert_eq!(LogValue::Int(42).to_string(), "42");
        assert_eq!(LogValue::Bool(true).to_string(), "true");
    }
}
