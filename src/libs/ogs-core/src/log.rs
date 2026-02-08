//! Logging utilities
//!
//! Exact port of lib/core/ogs-log.h and ogs-log.c

pub use log::{debug, error, info, trace, warn};

/// Log levels matching C implementation
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[derive(Default)]
pub enum OgsLogLevel {
    None = 0,
    Fatal = 1,
    Error = 2,
    Warn = 3,
    #[default]
    Info = 4,
    Debug = 5,
    Trace = 6,
}


/// Initialize logging
pub fn ogs_log_init() {
    env_logger::init();
}

/// Logging macros matching C implementation
#[macro_export]
macro_rules! ogs_fatal {
    ($($arg:tt)*) => {
        log::error!("[FATAL] {}", format!($($arg)*));
        std::process::abort();
    };
}

#[macro_export]
macro_rules! ogs_error {
    ($($arg:tt)*) => {
        log::error!($($arg)*);
    };
}

#[macro_export]
macro_rules! ogs_warn {
    ($($arg:tt)*) => {
        log::warn!($($arg)*);
    };
}

#[macro_export]
macro_rules! ogs_info {
    ($($arg:tt)*) => {
        log::info!($($arg)*);
    };
}

#[macro_export]
macro_rules! ogs_debug {
    ($($arg:tt)*) => {
        log::debug!($($arg)*);
    };
}

#[macro_export]
macro_rules! ogs_trace {
    ($($arg:tt)*) => {
        log::trace!($($arg)*);
    };
}

/// Assertion macro matching C implementation
#[macro_export]
macro_rules! ogs_assert {
    ($cond:expr) => {
        if !$cond {
            log::error!("Assertion failed: {}", stringify!($cond));
            std::process::abort();
        }
    };
}

/// Expectation macro (non-fatal assertion)
#[macro_export]
macro_rules! ogs_expect {
    ($cond:expr) => {
        if !$cond {
            log::error!("Expectation failed: {}", stringify!($cond));
        }
    };
}

//
// B2.3: OpenTelemetry-Compatible Structured Logging (6G Feature)
//

use std::collections::HashMap;
use std::fmt;

/// Log severity level matching OpenTelemetry specification
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OtelSeverity {
    Trace = 1,
    Trace2 = 2,
    Trace3 = 3,
    Trace4 = 4,
    Debug = 5,
    Debug2 = 6,
    Debug3 = 7,
    Debug4 = 8,
    Info = 9,
    Info2 = 10,
    Info3 = 11,
    Info4 = 12,
    Warn = 13,
    Warn2 = 14,
    Warn3 = 15,
    Warn4 = 16,
    Error = 17,
    Error2 = 18,
    Error3 = 19,
    Error4 = 20,
    Fatal = 21,
    Fatal2 = 22,
    Fatal3 = 23,
    Fatal4 = 24,
}

impl OtelSeverity {
    /// Get severity text
    pub fn to_text(&self) -> &'static str {
        match self {
            OtelSeverity::Trace | OtelSeverity::Trace2 | OtelSeverity::Trace3 | OtelSeverity::Trace4 => "TRACE",
            OtelSeverity::Debug | OtelSeverity::Debug2 | OtelSeverity::Debug3 | OtelSeverity::Debug4 => "DEBUG",
            OtelSeverity::Info | OtelSeverity::Info2 | OtelSeverity::Info3 | OtelSeverity::Info4 => "INFO",
            OtelSeverity::Warn | OtelSeverity::Warn2 | OtelSeverity::Warn3 | OtelSeverity::Warn4 => "WARN",
            OtelSeverity::Error | OtelSeverity::Error2 | OtelSeverity::Error3 | OtelSeverity::Error4 => "ERROR",
            OtelSeverity::Fatal | OtelSeverity::Fatal2 | OtelSeverity::Fatal3 | OtelSeverity::Fatal4 => "FATAL",
        }
    }
}

/// Attribute value types for structured logging
#[derive(Debug, Clone)]
pub enum AttributeValue {
    String(String),
    Int(i64),
    Double(f64),
    Bool(bool),
    Bytes(Vec<u8>),
}

impl fmt::Display for AttributeValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttributeValue::String(s) => write!(f, "{s}"),
            AttributeValue::Int(i) => write!(f, "{i}"),
            AttributeValue::Double(d) => write!(f, "{d}"),
            AttributeValue::Bool(b) => write!(f, "{b}"),
            AttributeValue::Bytes(b) => write!(f, "{b:?}"),
        }
    }
}

/// OpenTelemetry-compatible structured log record
#[derive(Debug, Clone)]
pub struct OtelLogRecord {
    /// Timestamp (nanoseconds since epoch)
    pub timestamp: u128,
    /// Observed timestamp (nanoseconds since epoch)
    pub observed_timestamp: u128,
    /// Severity number
    pub severity_number: OtelSeverity,
    /// Severity text
    pub severity_text: String,
    /// Log body/message
    pub body: String,
    /// Resource attributes (e.g., service.name, service.instance.id)
    pub resource_attributes: HashMap<String, AttributeValue>,
    /// Log attributes (custom fields)
    pub attributes: HashMap<String, AttributeValue>,
    /// Trace context (trace_id, span_id)
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub trace_flags: u8,
}

impl OtelLogRecord {
    /// Create a new log record
    pub fn new(severity: OtelSeverity, message: impl Into<String>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        OtelLogRecord {
            timestamp: now,
            observed_timestamp: now,
            severity_number: severity,
            severity_text: severity.to_text().to_string(),
            body: message.into(),
            resource_attributes: HashMap::new(),
            attributes: HashMap::new(),
            trace_id: None,
            span_id: None,
            trace_flags: 0,
        }
    }

    /// Add a resource attribute
    pub fn with_resource_attr(mut self, key: impl Into<String>, value: AttributeValue) -> Self {
        self.resource_attributes.insert(key.into(), value);
        self
    }

    /// Add a log attribute
    pub fn with_attr(mut self, key: impl Into<String>, value: AttributeValue) -> Self {
        self.attributes.insert(key.into(), value);
        self
    }

    /// Set trace context
    pub fn with_trace_context(mut self, trace_id: String, span_id: String, flags: u8) -> Self {
        self.trace_id = Some(trace_id);
        self.span_id = Some(span_id);
        self.trace_flags = flags;
        self
    }

    /// Format as JSON (compatible with OTLP)
    pub fn to_json(&self) -> String {
        // Simple JSON formatting (in production, use serde_json)
        let mut json = format!(
            r#"{{"timestamp":{},"observedTimestamp":{},"severityNumber":{},"severityText":"{}","body":"{}""#,
            self.timestamp,
            self.observed_timestamp,
            self.severity_number as i32,
            self.severity_text,
            self.body.replace("\"", "\\\"")
        );

        if !self.resource_attributes.is_empty() {
            json.push_str(r#","resourceAttributes":{"#);
            let attrs: Vec<String> = self.resource_attributes
                .iter()
                .map(|(k, v)| format!(r#""{k}":"{v}""#))
                .collect();
            json.push_str(&attrs.join(","));
            json.push('}');
        }

        if !self.attributes.is_empty() {
            json.push_str(r#","attributes":{"#);
            let attrs: Vec<String> = self.attributes
                .iter()
                .map(|(k, v)| format!(r#""{k}":"{v}""#))
                .collect();
            json.push_str(&attrs.join(","));
            json.push('}');
        }

        if let (Some(trace_id), Some(span_id)) = (&self.trace_id, &self.span_id) {
            json.push_str(&format!(
                r#","traceId":"{}","spanId":"{}","traceFlags":{}"#,
                trace_id, span_id, self.trace_flags
            ));
        }

        json.push('}');
        json
    }

    /// Emit the log record
    pub fn emit(&self) {
        // For now, emit as structured log line
        let level_str = self.severity_text.as_str();
        let msg = format!(
            "[{}] {} (trace_id={}, span_id={}) {}",
            level_str,
            self.body,
            self.trace_id.as_deref().unwrap_or("none"),
            self.span_id.as_deref().unwrap_or("none"),
            self.attributes.iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(" ")
        );

        match self.severity_number {
            OtelSeverity::Trace | OtelSeverity::Trace2 | OtelSeverity::Trace3 | OtelSeverity::Trace4 => {
                log::trace!("{msg}");
            }
            OtelSeverity::Debug | OtelSeverity::Debug2 | OtelSeverity::Debug3 | OtelSeverity::Debug4 => {
                log::debug!("{msg}");
            }
            OtelSeverity::Info | OtelSeverity::Info2 | OtelSeverity::Info3 | OtelSeverity::Info4 => {
                log::info!("{msg}");
            }
            OtelSeverity::Warn | OtelSeverity::Warn2 | OtelSeverity::Warn3 | OtelSeverity::Warn4 => {
                log::warn!("{msg}");
            }
            OtelSeverity::Error | OtelSeverity::Error2 | OtelSeverity::Error3 | OtelSeverity::Error4 => {
                log::error!("{msg}");
            }
            OtelSeverity::Fatal | OtelSeverity::Fatal2 | OtelSeverity::Fatal3 | OtelSeverity::Fatal4 => {
                log::error!("[FATAL] {msg}");
            }
        }
    }
}

/// Structured logging macros with OpenTelemetry compatibility
#[macro_export]
macro_rules! otel_log {
    ($severity:expr, $msg:expr, $($key:expr => $value:expr),*) => {{
        let mut record = $crate::log::OtelLogRecord::new($severity, $msg);
        $(
            record = record.with_attr($key, $value);
        )*
        record.emit();
    }};
}

#[macro_export]
macro_rules! otel_info {
    ($msg:expr $(, $key:expr => $value:expr)*) => {
        otel_log!($crate::log::OtelSeverity::Info, $msg $(, $key => $value)*)
    };
}

#[macro_export]
macro_rules! otel_warn {
    ($msg:expr $(, $key:expr => $value:expr)*) => {
        otel_log!($crate::log::OtelSeverity::Warn, $msg $(, $key => $value)*)
    };
}

#[macro_export]
macro_rules! otel_error {
    ($msg:expr $(, $key:expr => $value:expr)*) => {
        otel_log!($crate::log::OtelSeverity::Error, $msg $(, $key => $value)*)
    };
}

#[cfg(test)]
mod otel_tests {
    use super::*;

    #[test]
    fn test_otel_severity_text() {
        assert_eq!(OtelSeverity::Trace.to_text(), "TRACE");
        assert_eq!(OtelSeverity::Debug.to_text(), "DEBUG");
        assert_eq!(OtelSeverity::Info.to_text(), "INFO");
        assert_eq!(OtelSeverity::Warn.to_text(), "WARN");
        assert_eq!(OtelSeverity::Error.to_text(), "ERROR");
        assert_eq!(OtelSeverity::Fatal.to_text(), "FATAL");
    }

    #[test]
    fn test_otel_log_record_creation() {
        let record = OtelLogRecord::new(OtelSeverity::Info, "Test message");
        assert_eq!(record.body, "Test message");
        assert_eq!(record.severity_text, "INFO");
        assert_eq!(record.severity_number, OtelSeverity::Info);
    }

    #[test]
    fn test_otel_log_record_with_attributes() {
        let record = OtelLogRecord::new(OtelSeverity::Info, "Test")
            .with_attr("user_id", AttributeValue::String("user123".to_string()))
            .with_attr("session_id", AttributeValue::Int(42))
            .with_attr("active", AttributeValue::Bool(true));

        assert_eq!(record.attributes.len(), 3);
        assert!(record.attributes.contains_key("user_id"));
        assert!(record.attributes.contains_key("session_id"));
        assert!(record.attributes.contains_key("active"));
    }

    #[test]
    fn test_otel_log_record_with_trace_context() {
        let record = OtelLogRecord::new(OtelSeverity::Debug, "Traced log")
            .with_trace_context(
                "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
                "00f067aa0ba902b7".to_string(),
                1,
            );

        assert_eq!(record.trace_id, Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()));
        assert_eq!(record.span_id, Some("00f067aa0ba902b7".to_string()));
        assert_eq!(record.trace_flags, 1);
    }

    #[test]
    fn test_otel_log_record_json() {
        let record = OtelLogRecord::new(OtelSeverity::Info, "Test JSON")
            .with_attr("key", AttributeValue::String("value".to_string()));

        let json = record.to_json();
        assert!(json.contains("\"body\":\"Test JSON\""));
        assert!(json.contains("\"severityText\":\"INFO\""));
        assert!(json.contains("\"key\":\"value\""));
    }
}
