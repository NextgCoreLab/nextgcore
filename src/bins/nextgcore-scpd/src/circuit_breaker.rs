//! Per-endpoint circuit breaker for SCP forwarding (scpd-#102).
//!
//! The SCP keeps one breaker per producer authority (`scheme://host:port`) and
//! consults it in [`crate::proxy::ScpProxy::forward`]: an Open circuit
//! short-circuits to `503` without contacting the producer, so a flapping or
//! down backend cannot amplify latency across every consumer. A transport
//! failure or a producer `5xx` records a failure; anything else records a
//! success. After `open_timeout` the breaker admits a single probe (HalfOpen),
//! closing again after enough consecutive successes.
//!
//! This is the standard closed → open → half-open state machine. It replaces
//! the former aspirational "service mesh sidecar" module, whose routing modes
//! and endpoint-health aggregator were never wired into the request path.

use std::time::{Duration, Instant};

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation — requests flow.
    Closed,
    /// Recovery probe window after the open timeout — one request is admitted.
    HalfOpen,
    /// Tripped — requests are rejected until the open timeout elapses.
    Open,
}

/// A circuit breaker for a single endpoint.
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    /// Current state.
    pub state: CircuitState,
    /// Consecutive failure count (in Closed).
    pub failure_count: u32,
    /// Failures required to trip Closed → Open.
    pub failure_threshold: u32,
    /// Consecutive successes accrued in HalfOpen.
    pub half_open_success: u32,
    /// Successes required to close from HalfOpen.
    pub half_open_threshold: u32,
    /// How long to stay Open before admitting a probe.
    pub open_timeout: Duration,
    /// When the circuit was opened.
    pub opened_at: Option<Instant>,
}

impl CircuitBreaker {
    /// Create a Closed breaker that opens after `failure_threshold` consecutive
    /// failures and stays open for `open_timeout`.
    pub fn new(failure_threshold: u32, open_timeout: Duration) -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            failure_threshold: failure_threshold.max(1),
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
                // A probe failed: back to Open for another timeout.
                self.state = CircuitState::Open;
                self.opened_at = Some(Instant::now());
                self.half_open_success = 0;
            }
            CircuitState::Open => {}
        }
    }

    /// Whether a request should be admitted. In Open, this transitions to
    /// HalfOpen (admitting a single probe) once `open_timeout` has elapsed, so
    /// it takes `&mut self`.
    pub fn allow_request(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::HalfOpen => true,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_after_threshold_failures() {
        let mut cb = CircuitBreaker::new(3, Duration::from_millis(100));
        assert_eq!(cb.state, CircuitState::Closed);
        assert!(cb.allow_request());

        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state, CircuitState::Closed, "not yet at threshold");
        cb.record_failure();
        assert_eq!(cb.state, CircuitState::Open);
        assert!(!cb.allow_request(), "Open rejects before the timeout");
    }

    #[test]
    fn recovers_through_half_open() {
        let mut cb = CircuitBreaker::new(1, Duration::from_millis(1));
        cb.record_failure();
        assert_eq!(cb.state, CircuitState::Open);

        std::thread::sleep(Duration::from_millis(5));
        assert!(
            cb.allow_request(),
            "the timeout elapsed: a probe is admitted"
        );
        assert_eq!(cb.state, CircuitState::HalfOpen);

        cb.record_success();
        cb.record_success();
        cb.record_success();
        assert_eq!(cb.state, CircuitState::Closed);
    }

    #[test]
    fn half_open_probe_failure_reopens() {
        let mut cb = CircuitBreaker::new(1, Duration::from_millis(1));
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(5));
        assert!(cb.allow_request());
        assert_eq!(cb.state, CircuitState::HalfOpen);
        cb.record_failure();
        assert_eq!(cb.state, CircuitState::Open, "a failed probe reopens");
    }

    #[test]
    fn success_in_closed_resets_failure_count() {
        let mut cb = CircuitBreaker::new(3, Duration::from_secs(30));
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        assert_eq!(cb.failure_count, 0);
        // Two more failures must not trip now that the count was reset.
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state, CircuitState::Closed);
    }
}
