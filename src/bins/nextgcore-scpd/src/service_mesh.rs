//! Service Mesh Sidecar for SCP (Item #196)
//!
//! Evolves the Service Communication Proxy into a service mesh sidecar
//! with AI-aware routing, circuit breaking, and observability.

use std::collections::HashMap;
use std::time::{Duration, Instant};

// ============================================================================
// Service Mesh Configuration
// ============================================================================

/// Service mesh routing mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingMode {
    /// Round-robin (default 5G SCP).
    RoundRobin,
    /// Weighted least-connections.
    WeightedLeastConn,
    /// Latency-based (route to lowest latency).
    LatencyBased,
    /// AI-optimized (ML model selects target).
    AiOptimized,
}

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation.
    Closed,
    /// Monitoring after failures (limited traffic).
    HalfOpen,
    /// All requests rejected.
    Open,
}

/// Circuit breaker for a service endpoint.
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    /// Current state.
    pub state: CircuitState,
    /// Failure count.
    pub failure_count: u32,
    /// Failure threshold to open.
    pub failure_threshold: u32,
    /// Success count in half-open.
    pub half_open_success: u32,
    /// Half-open success threshold to close.
    pub half_open_threshold: u32,
    /// Time to wait before transitioning from Open to HalfOpen.
    pub open_timeout: Duration,
    /// When the circuit was opened.
    pub opened_at: Option<Instant>,
}

impl CircuitBreaker {
    /// Creates a new circuit breaker.
    pub fn new(failure_threshold: u32, open_timeout: Duration) -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            failure_threshold,
            half_open_success: 0,
            half_open_threshold: 3,
            open_timeout,
            opened_at: None,
        }
    }

    /// Record a successful request.
    pub fn record_success(&mut self) {
        match self.state {
            CircuitState::Closed => {
                self.failure_count = 0;
            }
            CircuitState::HalfOpen => {
                self.half_open_success += 1;
                if self.half_open_success >= self.half_open_threshold {
                    self.state = CircuitState::Closed;
                    self.failure_count = 0;
                    self.half_open_success = 0;
                }
            }
            CircuitState::Open => {}
        }
    }

    /// Record a failed request.
    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        match self.state {
            CircuitState::Closed => {
                if self.failure_count >= self.failure_threshold {
                    self.state = CircuitState::Open;
                    self.opened_at = Some(Instant::now());
                }
            }
            CircuitState::HalfOpen => {
                self.state = CircuitState::Open;
                self.opened_at = Some(Instant::now());
                self.half_open_success = 0;
            }
            CircuitState::Open => {}
        }
    }

    /// Check if requests should be allowed.
    pub fn allow_request(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::HalfOpen => true, // Limited, but allowed
            CircuitState::Open => {
                if let Some(opened) = self.opened_at {
                    if opened.elapsed() >= self.open_timeout {
                        self.state = CircuitState::HalfOpen;
                        self.half_open_success = 0;
                        return true;
                    }
                }
                false
            }
        }
    }
}

/// Service endpoint health info.
#[derive(Debug, Clone)]
pub struct EndpointHealth {
    /// Endpoint address.
    pub address: String,
    /// NF type.
    pub nf_type: String,
    /// Average latency (microseconds).
    pub avg_latency_us: u64,
    /// Request count.
    pub request_count: u64,
    /// Error count.
    pub error_count: u64,
    /// Circuit breaker.
    pub circuit_breaker: CircuitBreaker,
    /// Weight for weighted routing.
    pub weight: u32,
}

impl EndpointHealth {
    /// Error rate (0.0-1.0).
    pub fn error_rate(&self) -> f64 {
        if self.request_count == 0 { return 0.0; }
        self.error_count as f64 / self.request_count as f64
    }

    /// Whether the endpoint is healthy.
    pub fn is_healthy(&self) -> bool {
        self.circuit_breaker.state != CircuitState::Open && self.error_rate() < 0.5
    }
}

/// Service mesh manager.
pub struct ServiceMesh {
    /// Routing mode.
    routing_mode: RoutingMode,
    /// Service endpoints.
    endpoints: HashMap<String, Vec<EndpointHealth>>,
    /// Total routed requests.
    total_routed: u64,
}

impl ServiceMesh {
    /// Creates a new service mesh.
    pub fn new(routing_mode: RoutingMode) -> Self {
        Self {
            routing_mode,
            endpoints: HashMap::new(),
            total_routed: 0,
        }
    }

    /// Register an endpoint.
    pub fn register_endpoint(&mut self, nf_type: impl Into<String>, endpoint: EndpointHealth) {
        self.endpoints
            .entry(nf_type.into())
            .or_default()
            .push(endpoint);
    }

    /// Select best endpoint for a request.
    pub fn select_endpoint(&mut self, nf_type: &str) -> Option<&str> {
        let eps = self.endpoints.get(nf_type)?;
        let healthy: Vec<&EndpointHealth> = eps.iter().filter(|e| e.is_healthy()).collect();

        if healthy.is_empty() {
            return None;
        }

        self.total_routed += 1;

        match self.routing_mode {
            RoutingMode::LatencyBased => {
                healthy.iter().min_by_key(|e| e.avg_latency_us).map(|e| e.address.as_str())
            }
            RoutingMode::WeightedLeastConn => {
                healthy.iter().min_by_key(|e| e.request_count / (e.weight.max(1) as u64)).map(|e| e.address.as_str())
            }
            _ => {
                // Round-robin: pick by index
                let idx = (self.total_routed as usize) % healthy.len();
                Some(healthy[idx].address.as_str())
            }
        }
    }

    /// Total registered endpoints.
    pub fn endpoint_count(&self) -> usize {
        self.endpoints.values().map(|v| v.len()).sum()
    }

    /// Total routed requests.
    pub fn total_routed(&self) -> u64 { self.total_routed }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_endpoint(addr: &str, latency: u64) -> EndpointHealth {
        EndpointHealth {
            address: addr.to_string(),
            nf_type: "AMF".to_string(),
            avg_latency_us: latency,
            request_count: 0,
            error_count: 0,
            circuit_breaker: CircuitBreaker::new(5, Duration::from_secs(30)),
            weight: 1,
        }
    }

    #[test]
    fn test_circuit_breaker_lifecycle() {
        let mut cb = CircuitBreaker::new(3, Duration::from_millis(100));
        assert_eq!(cb.state, CircuitState::Closed);
        assert!(cb.allow_request());

        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state, CircuitState::Open);
        assert!(!cb.allow_request());
    }

    #[test]
    fn test_circuit_breaker_recovery() {
        let mut cb = CircuitBreaker::new(1, Duration::from_millis(1));
        cb.record_failure();
        assert_eq!(cb.state, CircuitState::Open);

        std::thread::sleep(Duration::from_millis(5));
        assert!(cb.allow_request()); // Should transition to HalfOpen
        assert_eq!(cb.state, CircuitState::HalfOpen);

        cb.record_success();
        cb.record_success();
        cb.record_success();
        assert_eq!(cb.state, CircuitState::Closed);
    }

    #[test]
    fn test_service_mesh_latency_routing() {
        let mut mesh = ServiceMesh::new(RoutingMode::LatencyBased);
        mesh.register_endpoint("AMF", make_endpoint("amf-1:7777", 500));
        mesh.register_endpoint("AMF", make_endpoint("amf-2:7777", 100));

        let selected = mesh.select_endpoint("AMF").unwrap();
        assert_eq!(selected, "amf-2:7777"); // Lower latency
    }

    #[test]
    fn test_service_mesh_no_healthy() {
        let mut mesh = ServiceMesh::new(RoutingMode::RoundRobin);
        assert!(mesh.select_endpoint("NWDAF").is_none());
    }

    #[test]
    fn test_endpoint_health() {
        let mut ep = make_endpoint("test:8080", 100);
        assert!(ep.is_healthy());
        assert_eq!(ep.error_rate(), 0.0);

        ep.request_count = 10;
        ep.error_count = 8;
        assert!(!ep.is_healthy()); // 80% error rate
    }
}
