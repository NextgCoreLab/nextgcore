//! gRPC / SBI 2.0 Support (B6.1)
//!
//! Provides gRPC service definitions and client/server types for SBI 2.0,
//! enabling high-performance RPC communication between 6G network functions.
//!
//! In 3GPP Rel-18+, SBI evolves to support gRPC alongside HTTP/2+JSON,
//! offering binary protobuf encoding for lower latency and higher throughput.

use std::collections::HashMap;
use std::time::Duration;

// ============================================================================
// gRPC Service Definitions
// ============================================================================

/// gRPC service type for 6G NF services.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GrpcServiceType {
    /// NWDAF analytics service.
    NnwdafAnalytics,
    /// NWDAF ML model provision.
    NnwdafMlModelProvision,
    /// NKEF key exposure service.
    NnkefExposure,
    /// AMF communication service.
    NamfComm,
    /// SMF PDU session service.
    NsmfPduSession,
    /// UDM subscriber data service.
    NudmSdm,
    /// PCF policy authorization service.
    NpcfPolicyAuthorization,
    /// AUSF authentication service.
    NausfAuth,
    /// SCP routing service.
    NscpRouting,
}

impl GrpcServiceType {
    /// Returns the gRPC service name (package.ServiceName).
    pub fn service_name(&self) -> &'static str {
        match self {
            Self::NnwdafAnalytics => "fiveg.nwdaf.AnalyticsService",
            Self::NnwdafMlModelProvision => "fiveg.nwdaf.MlModelProvisionService",
            Self::NnkefExposure => "fiveg.nkef.ExposureService",
            Self::NamfComm => "fiveg.amf.CommunicationService",
            Self::NsmfPduSession => "fiveg.smf.PduSessionService",
            Self::NudmSdm => "fiveg.udm.SubscriberDataService",
            Self::NpcfPolicyAuthorization => "fiveg.pcf.PolicyAuthorizationService",
            Self::NausfAuth => "fiveg.ausf.AuthenticationService",
            Self::NscpRouting => "fiveg.scp.RoutingService",
        }
    }
}

/// gRPC method descriptor.
#[derive(Debug, Clone)]
pub struct GrpcMethod {
    /// Method name.
    pub name: String,
    /// Service type.
    pub service: GrpcServiceType,
    /// Whether request is streaming.
    pub client_streaming: bool,
    /// Whether response is streaming.
    pub server_streaming: bool,
    /// Timeout.
    pub timeout: Duration,
}

impl GrpcMethod {
    /// Creates a unary method (request-response).
    pub fn unary(name: impl Into<String>, service: GrpcServiceType) -> Self {
        Self {
            name: name.into(),
            service,
            client_streaming: false,
            server_streaming: false,
            timeout: Duration::from_secs(5),
        }
    }

    /// Creates a server-streaming method.
    pub fn server_stream(name: impl Into<String>, service: GrpcServiceType) -> Self {
        Self {
            name: name.into(),
            service,
            client_streaming: false,
            server_streaming: true,
            timeout: Duration::from_secs(30),
        }
    }

    /// Creates a bidirectional streaming method.
    pub fn bidi_stream(name: impl Into<String>, service: GrpcServiceType) -> Self {
        Self {
            name: name.into(),
            service,
            client_streaming: true,
            server_streaming: true,
            timeout: Duration::from_secs(60),
        }
    }

    /// Full method path (/package.Service/Method).
    pub fn full_path(&self) -> String {
        format!("/{}/{}", self.service.service_name(), self.name)
    }

    /// Set timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

// ============================================================================
// gRPC Configuration
// ============================================================================

/// gRPC endpoint configuration.
#[derive(Debug, Clone)]
pub struct GrpcConfig {
    /// Host address.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Enable TLS.
    pub tls_enabled: bool,
    /// Maximum message size (bytes).
    pub max_message_size: usize,
    /// Maximum concurrent streams.
    pub max_concurrent_streams: u32,
    /// Keepalive interval.
    pub keepalive_interval: Duration,
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Enable gzip compression.
    pub enable_compression: bool,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 50051,
            tls_enabled: true,
            max_message_size: 4 * 1024 * 1024, // 4MB
            max_concurrent_streams: 100,
            keepalive_interval: Duration::from_secs(20),
            connect_timeout: Duration::from_secs(5),
            enable_compression: false,
        }
    }
}

impl GrpcConfig {
    /// Creates a new gRPC config for a given host and port.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            ..Default::default()
        }
    }

    /// Returns the authority string (host:port).
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

// ============================================================================
// gRPC Metadata
// ============================================================================

/// gRPC request/response metadata.
#[derive(Debug, Clone, Default)]
pub struct GrpcMetadata {
    entries: HashMap<String, String>,
}

impl GrpcMetadata {
    /// Creates empty metadata.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a metadata entry.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.entries.insert(key.into(), value.into());
    }

    /// Get a metadata value.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(|s| s.as_str())
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether metadata is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ============================================================================
// gRPC Status
// ============================================================================

/// gRPC status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcStatus {
    Ok = 0,
    Cancelled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
}

impl GrpcStatus {
    /// Returns the status code number.
    pub fn code(&self) -> u32 {
        *self as u32
    }

    /// Returns the status name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Cancelled => "CANCELLED",
            Self::Unknown => "UNKNOWN",
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::DeadlineExceeded => "DEADLINE_EXCEEDED",
            Self::NotFound => "NOT_FOUND",
            Self::AlreadyExists => "ALREADY_EXISTS",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::FailedPrecondition => "FAILED_PRECONDITION",
            Self::Aborted => "ABORTED",
            Self::OutOfRange => "OUT_OF_RANGE",
            Self::Unimplemented => "UNIMPLEMENTED",
            Self::Internal => "INTERNAL",
            Self::Unavailable => "UNAVAILABLE",
            Self::DataLoss => "DATA_LOSS",
            Self::Unauthenticated => "UNAUTHENTICATED",
        }
    }

    /// Whether this is a success status.
    pub fn is_ok(&self) -> bool {
        *self == Self::Ok
    }
}

// ============================================================================
// gRPC Service Registry (B6.2)
// ============================================================================

/// Registry of gRPC service methods with health status tracking.
pub struct GrpcServiceRegistry {
    /// Registered methods indexed by (service, method_name).
    methods: HashMap<(GrpcServiceType, String), GrpcMethod>,
    /// Service health status (true = serving).
    serving: HashMap<GrpcServiceType, bool>,
}

impl GrpcServiceRegistry {
    /// Creates an empty service registry.
    pub fn new() -> Self {
        Self {
            methods: HashMap::new(),
            serving: HashMap::new(),
        }
    }

    /// Register a gRPC method.
    pub fn register(&mut self, method: GrpcMethod) {
        let key = (method.service, method.name.clone());
        self.methods.insert(key, method);
    }

    /// Look up a method by service and name.
    pub fn lookup(&self, service: GrpcServiceType, name: &str) -> Option<&GrpcMethod> {
        self.methods.get(&(service, name.to_string()))
    }

    /// List all methods for a service.
    pub fn list_methods(&self, service: GrpcServiceType) -> Vec<&GrpcMethod> {
        self.methods
            .iter()
            .filter(|((s, _), _)| *s == service)
            .map(|(_, m)| m)
            .collect()
    }

    /// Total registered methods.
    pub fn method_count(&self) -> usize {
        self.methods.len()
    }

    /// Set serving status for a service.
    pub fn set_serving(&mut self, service: GrpcServiceType, serving: bool) {
        self.serving.insert(service, serving);
    }

    /// Check if a service is currently serving.
    pub fn is_serving(&self, service: GrpcServiceType) -> bool {
        self.serving.get(&service).copied().unwrap_or(false)
    }
}

impl Default for GrpcServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grpc_service_name() {
        assert_eq!(
            GrpcServiceType::NnwdafAnalytics.service_name(),
            "fiveg.nwdaf.AnalyticsService"
        );
        assert_eq!(
            GrpcServiceType::NamfComm.service_name(),
            "fiveg.amf.CommunicationService"
        );
    }

    #[test]
    fn test_grpc_method_path() {
        let method = GrpcMethod::unary("GetAnalytics", GrpcServiceType::NnwdafAnalytics);
        assert_eq!(method.full_path(), "/fiveg.nwdaf.AnalyticsService/GetAnalytics");
        assert!(!method.client_streaming);
        assert!(!method.server_streaming);
    }

    #[test]
    fn test_grpc_server_stream() {
        let method = GrpcMethod::server_stream("Subscribe", GrpcServiceType::NnwdafAnalytics);
        assert!(!method.client_streaming);
        assert!(method.server_streaming);
    }

    #[test]
    fn test_grpc_config_default() {
        let config = GrpcConfig::default();
        assert_eq!(config.port, 50051);
        assert!(config.tls_enabled);
        assert_eq!(config.authority(), "127.0.0.1:50051");
    }

    #[test]
    fn test_grpc_metadata() {
        let mut meta = GrpcMetadata::new();
        meta.insert("x-request-id", "abc-123");
        assert_eq!(meta.get("x-request-id"), Some("abc-123"));
        assert_eq!(meta.len(), 1);
    }

    #[test]
    fn test_grpc_status() {
        assert!(GrpcStatus::Ok.is_ok());
        assert!(!GrpcStatus::Internal.is_ok());
        assert_eq!(GrpcStatus::Ok.code(), 0);
        assert_eq!(GrpcStatus::Internal.name(), "INTERNAL");
    }

    #[test]
    fn test_service_registry() {
        let mut reg = GrpcServiceRegistry::new();
        let method = GrpcMethod::unary("GetAnalytics", GrpcServiceType::NnwdafAnalytics);
        reg.register(method);
        assert_eq!(reg.method_count(), 1);

        let found = reg.lookup(GrpcServiceType::NnwdafAnalytics, "GetAnalytics");
        assert!(found.is_some());
        assert!(reg.lookup(GrpcServiceType::NnwdafAnalytics, "Missing").is_none());
    }

    #[test]
    fn test_service_registry_list() {
        let mut reg = GrpcServiceRegistry::new();
        reg.register(GrpcMethod::unary("M1", GrpcServiceType::NamfComm));
        reg.register(GrpcMethod::server_stream("M2", GrpcServiceType::NamfComm));
        reg.register(GrpcMethod::unary("M3", GrpcServiceType::NsmfPduSession));

        let amf_methods = reg.list_methods(GrpcServiceType::NamfComm);
        assert_eq!(amf_methods.len(), 2);
    }

    #[test]
    fn test_service_registry_health() {
        let mut reg = GrpcServiceRegistry::new();
        reg.set_serving(GrpcServiceType::NamfComm, true);
        assert!(reg.is_serving(GrpcServiceType::NamfComm));
        assert!(!reg.is_serving(GrpcServiceType::NsmfPduSession));

        reg.set_serving(GrpcServiceType::NamfComm, false);
        assert!(!reg.is_serving(GrpcServiceType::NamfComm));
    }
}
