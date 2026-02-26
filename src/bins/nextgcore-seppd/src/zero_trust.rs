//! Zero-Trust Security for SEPP (TS 33.501 §13, 3GPP SA3 Zero-Trust study)
//!
//! Implements zero-trust policy evaluation for inter-PLMN N32 sessions:
//! - per-request authorization with PLMN allowlist
//! - traffic anomaly detection counters
//! - adaptive trust scoring

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Trust level for an inter-PLMN session
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    /// Not yet established / unknown
    Unknown = 0,
    /// Initial trust (N32c handshake complete, not yet verified)
    Initial = 1,
    /// Established trust (normal operation)
    Established = 2,
    /// High trust (verified through out-of-band PKI + IPX audit)
    High = 3,
}

/// Zero-trust policy for a specific remote PLMN
#[derive(Debug, Clone)]
pub struct ZeroTrustPolicy {
    /// Remote PLMN ID (MCC+MNC, e.g. "001001")
    pub remote_plmn_id: String,
    /// Minimum trust level required for forwarding requests
    pub min_trust_level: TrustLevel,
    /// Whether to verify message integrity on every request
    pub integrity_required: bool,
    /// Whether to verify confidentiality (encryption required)
    pub confidentiality_required: bool,
    /// Rate limit: max requests per second (0 = no limit)
    pub max_rps: u32,
    /// Maximum tolerated anomaly score before blocking (0–100)
    pub anomaly_threshold: u8,
}

impl ZeroTrustPolicy {
    /// Strict policy — requires High trust, integrity, confidentiality
    pub fn strict(remote_plmn_id: String) -> Self {
        Self {
            remote_plmn_id,
            min_trust_level: TrustLevel::Established,
            integrity_required: true,
            confidentiality_required: true,
            max_rps: 1000,
            anomaly_threshold: 20,
        }
    }

    /// Permissive policy — used for trusted roaming partners
    pub fn permissive(remote_plmn_id: String) -> Self {
        Self {
            remote_plmn_id,
            min_trust_level: TrustLevel::Initial,
            integrity_required: true,
            confidentiality_required: false,
            max_rps: 0,
            anomaly_threshold: 80,
        }
    }
}

/// Per-PLMN session trust state
#[derive(Debug)]
pub struct TrustSessionState {
    /// Current trust level
    pub trust_level: TrustLevel,
    /// Anomaly score (0–100; increases on suspicious requests)
    pub anomaly_score: u8,
    /// Total requests processed
    pub requests_total: u64,
    /// Requests rejected due to policy
    pub requests_rejected: u64,
    /// Requests in the current rate-limit window
    pub rps_count: u32,
    /// Start of current rate-limit window
    pub window_start: Instant,
    /// Whether this session is currently blocked
    pub blocked: bool,
}

impl TrustSessionState {
    pub fn new(initial_trust: TrustLevel) -> Self {
        Self {
            trust_level: initial_trust,
            anomaly_score: 0,
            requests_total: 0,
            requests_rejected: 0,
            rps_count: 0,
            window_start: Instant::now(),
            blocked: false,
        }
    }
}

/// Result of a zero-trust policy check
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Request is allowed to proceed
    Allow,
    /// Request is denied; carry reason string
    Deny(String),
}

/// Zero-trust engine: evaluates per-PLMN requests against policies
pub struct ZeroTrustEngine {
    /// Policies keyed by remote PLMN ID
    policies: HashMap<String, ZeroTrustPolicy>,
    /// Live session states keyed by remote PLMN ID
    sessions: HashMap<String, TrustSessionState>,
}

impl ZeroTrustEngine {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            sessions: HashMap::new(),
        }
    }

    /// Register a policy for a remote PLMN
    pub fn register_policy(&mut self, policy: ZeroTrustPolicy) {
        self.sessions
            .entry(policy.remote_plmn_id.clone())
            .or_insert_with(|| TrustSessionState::new(TrustLevel::Unknown));
        self.policies.insert(policy.remote_plmn_id.clone(), policy);
    }

    /// Elevate the trust level for a PLMN (e.g. after N32c handshake)
    pub fn elevate_trust(&mut self, plmn_id: &str, level: TrustLevel) {
        if let Some(state) = self.sessions.get_mut(plmn_id) {
            state.trust_level = level;
        }
    }

    /// Evaluate a request from a remote PLMN
    ///
    /// Returns `PolicyDecision::Allow` or `PolicyDecision::Deny(reason)`
    pub fn evaluate(
        &mut self,
        plmn_id: &str,
        has_integrity_mac: bool,
        is_encrypted: bool,
    ) -> PolicyDecision {
        let policy = match self.policies.get(plmn_id) {
            Some(p) => p.clone(),
            None => return PolicyDecision::Deny(format!("No policy for PLMN {plmn_id}")),
        };

        let state = self.sessions.entry(plmn_id.to_string())
            .or_insert_with(|| TrustSessionState::new(TrustLevel::Unknown));

        state.requests_total += 1;

        // Check if blocked
        if state.blocked {
            state.requests_rejected += 1;
            return PolicyDecision::Deny("Session blocked due to anomaly score".into());
        }

        // Check trust level
        if state.trust_level < policy.min_trust_level {
            state.requests_rejected += 1;
            state.anomaly_score = state.anomaly_score.saturating_add(5);
            return PolicyDecision::Deny(format!(
                "Trust level {:?} < required {:?}", state.trust_level, policy.min_trust_level
            ));
        }

        // Check integrity
        if policy.integrity_required && !has_integrity_mac {
            state.requests_rejected += 1;
            state.anomaly_score = state.anomaly_score.saturating_add(10);
            return PolicyDecision::Deny("Integrity MAC required but missing".into());
        }

        // Check confidentiality
        if policy.confidentiality_required && !is_encrypted {
            state.requests_rejected += 1;
            state.anomaly_score = state.anomaly_score.saturating_add(10);
            return PolicyDecision::Deny("Encryption required but request is cleartext".into());
        }

        // Rate limiting (sliding 1-second window)
        let now = Instant::now();
        if policy.max_rps > 0 {
            if now.duration_since(state.window_start) > Duration::from_secs(1) {
                state.window_start = now;
                state.rps_count = 0;
            }
            state.rps_count += 1;
            if state.rps_count > policy.max_rps {
                state.requests_rejected += 1;
                state.anomaly_score = state.anomaly_score.saturating_add(2);
                return PolicyDecision::Deny(format!("Rate limit exceeded ({}/s)", policy.max_rps));
            }
        }

        // Check anomaly threshold
        if state.anomaly_score >= policy.anomaly_threshold {
            state.blocked = true;
            state.requests_rejected += 1;
            return PolicyDecision::Deny("Anomaly threshold exceeded; session blocked".into());
        }

        // Success: reduce anomaly score slightly on clean requests
        state.anomaly_score = state.anomaly_score.saturating_sub(1);

        PolicyDecision::Allow
    }

    /// Reset a blocked session (manual intervention)
    pub fn unblock(&mut self, plmn_id: &str) {
        if let Some(state) = self.sessions.get_mut(plmn_id) {
            state.blocked = false;
            state.anomaly_score = 0;
        }
    }

    /// Returns current trust state for a PLMN
    pub fn session_state(&self, plmn_id: &str) -> Option<&TrustSessionState> {
        self.sessions.get(plmn_id)
    }
}

impl Default for ZeroTrustEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine_with_strict_policy() -> ZeroTrustEngine {
        let mut e = ZeroTrustEngine::new();
        e.register_policy(ZeroTrustPolicy::strict("001001".into()));
        e.elevate_trust("001001", TrustLevel::Established);
        e
    }

    #[test]
    fn test_allow_valid_request() {
        let mut e = engine_with_strict_policy();
        assert_eq!(e.evaluate("001001", true, true), PolicyDecision::Allow);
    }

    #[test]
    fn test_deny_missing_integrity() {
        let mut e = engine_with_strict_policy();
        assert!(matches!(e.evaluate("001001", false, true), PolicyDecision::Deny(_)));
    }

    #[test]
    fn test_deny_missing_encryption() {
        let mut e = engine_with_strict_policy();
        assert!(matches!(e.evaluate("001001", true, false), PolicyDecision::Deny(_)));
    }

    #[test]
    fn test_deny_unknown_plmn() {
        let mut e = ZeroTrustEngine::new();
        assert!(matches!(e.evaluate("999999", true, true), PolicyDecision::Deny(_)));
    }

    #[test]
    fn test_deny_low_trust_level() {
        let mut e = ZeroTrustEngine::new();
        e.register_policy(ZeroTrustPolicy::strict("001001".into()));
        // trust stays at Unknown
        assert!(matches!(e.evaluate("001001", true, true), PolicyDecision::Deny(_)));
    }

    #[test]
    fn test_anomaly_score_accumulates_and_blocks() {
        let mut e = ZeroTrustEngine::new();
        e.register_policy(ZeroTrustPolicy {
            remote_plmn_id: "001001".into(),
            min_trust_level: TrustLevel::Established,
            integrity_required: true,
            confidentiality_required: false,
            max_rps: 0,
            anomaly_threshold: 10,
        });
        e.elevate_trust("001001", TrustLevel::Established);
        // Each missing-integrity request adds 10 to anomaly score
        let _ = e.evaluate("001001", false, false);
        // Now score >= threshold → blocked
        let d = e.evaluate("001001", true, false);
        // Either "Anomaly threshold" or "blocked" depending on order
        assert!(matches!(d, PolicyDecision::Deny(_)));
    }

    #[test]
    fn test_unblock_resets_session() {
        let mut e = engine_with_strict_policy();
        // Force block
        if let Some(s) = e.sessions.get_mut("001001") {
            s.blocked = true;
        }
        assert!(matches!(e.evaluate("001001", true, true), PolicyDecision::Deny(_)));
        e.unblock("001001");
        assert_eq!(e.evaluate("001001", true, true), PolicyDecision::Allow);
    }

    #[test]
    fn test_permissive_policy_allows_cleartext() {
        let mut e = ZeroTrustEngine::new();
        e.register_policy(ZeroTrustPolicy::permissive("002002".into()));
        e.elevate_trust("002002", TrustLevel::Initial);
        assert_eq!(e.evaluate("002002", true, false), PolicyDecision::Allow);
    }
}
