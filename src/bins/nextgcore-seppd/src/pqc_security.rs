//! Post-Quantum Cryptography Security for SEPP (Item #192)
//!
//! Implements zero-trust security model with PQC negotiation and
//! AI-based threat detection for inter-PLMN roaming security.
//!
//! References: 3GPP TR 33.831, TR 33.875, NIST FIPS 203/204

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ============================================================================
// Zero-Trust Security Model
// ============================================================================

/// Zero-trust verification level for inter-PLMN requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeroTrustLevel {
    /// No verification (legacy fallback).
    None,
    /// Basic verification (mTLS + token).
    Basic,
    /// Enhanced verification (mTLS + token + attestation).
    Enhanced,
    /// Full zero-trust (PQC mTLS + token + attestation + continuous).
    Full,
}

/// Zero-trust verification result.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Trust level achieved.
    pub level: ZeroTrustLevel,
    /// Whether the request is authorized.
    pub authorized: bool,
    /// Trust score (0.0 - 1.0).
    pub trust_score: f64,
    /// Reason for the decision.
    pub reason: String,
    /// Timestamp.
    pub timestamp_ms: u64,
}

/// NF instance trust information for service mesh authentication
#[derive(Debug, Clone)]
pub struct NfInstanceTrust {
    /// NF instance ID
    pub nf_instance_id: String,
    /// NF type (AMF, SMF, UPF, etc.)
    pub nf_type: String,
    /// Current trust score (0.0 - 1.0)
    pub trust_score: f64,
    /// mTLS certificate fingerprint (SHA-256)
    pub cert_fingerprint: Option<String>,
    /// Last successful authentication timestamp
    pub last_auth_ms: u64,
    /// Total authentication attempts
    pub auth_attempts: u64,
    /// Failed authentication attempts
    pub failed_attempts: u64,
    /// Trust revoked flag
    pub revoked: bool,
}

/// Zero-trust policy decision
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Allow the request
    Allow,
    /// Deny the request
    Deny,
    /// Require additional verification
    Challenge,
}

/// Zero-trust policy rule
#[derive(Debug, Clone)]
pub struct PolicyRule {
    /// Rule ID
    pub rule_id: String,
    /// Source NF type pattern (e.g., "AMF", "*")
    pub source_nf_type: String,
    /// Target NF type pattern
    pub target_nf_type: String,
    /// Minimum trust score required
    pub min_trust_score: f64,
    /// Require mTLS
    pub require_mtls: bool,
    /// Policy decision if rule matches
    pub decision: PolicyDecision,
}

impl Default for PolicyRule {
    fn default() -> Self {
        Self {
            rule_id: "default-deny".to_string(),
            source_nf_type: "*".to_string(),
            target_nf_type: "*".to_string(),
            min_trust_score: 0.8,
            require_mtls: true,
            decision: PolicyDecision::Deny,
        }
    }
}

/// Zero-trust policy engine with service mesh authentication.
pub struct ZeroTrustEngine {
    /// Minimum required trust level.
    min_level: ZeroTrustLevel,
    /// Trusted PLMN peers (PLMN ID → trust level).
    trusted_peers: HashMap<String, ZeroTrustLevel>,
    /// NF instance trust tracking for service mesh
    nf_trust: HashMap<String, NfInstanceTrust>,
    /// Zero-trust policy rules (deny by default, explicit allow)
    policy_rules: Vec<PolicyRule>,
    /// Verification count.
    verification_count: u64,
    /// Denied count.
    denied_count: u64,
}

impl ZeroTrustEngine {
    /// Creates a new zero-trust engine with deny-by-default policy.
    pub fn new(min_level: ZeroTrustLevel) -> Self {
        let mut engine = Self {
            min_level,
            trusted_peers: HashMap::new(),
            nf_trust: HashMap::new(),
            policy_rules: Vec::new(),
            verification_count: 0,
            denied_count: 0,
        };
        // Default deny rule
        engine.add_policy_rule(PolicyRule::default());
        engine
    }

    /// Register a trusted peer PLMN.
    pub fn add_trusted_peer(&mut self, plmn_id: impl Into<String>, level: ZeroTrustLevel) {
        self.trusted_peers.insert(plmn_id.into(), level);
    }

    /// Add a zero-trust policy rule.
    pub fn add_policy_rule(&mut self, rule: PolicyRule) {
        log::info!(
            "Zero-trust policy rule added: {} -> {} (score >= {}, mtls={})",
            rule.source_nf_type,
            rule.target_nf_type,
            rule.min_trust_score,
            rule.require_mtls
        );
        self.policy_rules.push(rule);
    }

    /// Register or update NF instance trust for service mesh authentication.
    pub fn register_nf_instance(&mut self, nf_instance_id: String, nf_type: String, cert_fingerprint: Option<String>) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        let trust = NfInstanceTrust {
            nf_instance_id: nf_instance_id.clone(),
            nf_type,
            trust_score: 1.0, // Start with full trust
            cert_fingerprint,
            last_auth_ms: now,
            auth_attempts: 1,
            failed_attempts: 0,
            revoked: false,
        };
        self.nf_trust.insert(nf_instance_id.clone(), trust);
        log::info!("NF instance registered in zero-trust mesh: {nf_instance_id}");
    }

    /// Authenticate NF instance with mTLS and update trust score dynamically.
    pub fn authenticate_nf(&mut self, nf_instance_id: &str, has_mtls: bool, cert_fingerprint: Option<String>) -> bool {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;

        if let Some(trust) = self.nf_trust.get_mut(nf_instance_id) {
            trust.auth_attempts += 1;

            // Check if trust is revoked
            if trust.revoked {
                log::warn!("Authentication denied: NF {nf_instance_id} trust revoked");
                self.denied_count += 1;
                return false;
            }

            // Verify mTLS certificate fingerprint
            if has_mtls {
                if let (Some(expected), Some(actual)) = (&trust.cert_fingerprint, &cert_fingerprint) {
                    if expected != actual {
                        log::error!("mTLS certificate mismatch for NF {nf_instance_id}: expected {expected}, got {actual}");
                        trust.failed_attempts += 1;
                        trust.trust_score = (trust.trust_score - 0.2).max(0.0);
                        self.denied_count += 1;
                        return false;
                    }
                }
                trust.last_auth_ms = now;
                trust.trust_score = (trust.trust_score + 0.05).min(1.0); // Slowly increase trust
                return true;
            } else {
                log::warn!("No mTLS for NF {nf_instance_id}, trust score degraded");
                trust.failed_attempts += 1;
                trust.trust_score = (trust.trust_score - 0.1).max(0.0);
                self.denied_count += 1;
                return false;
            }
        }

        // Unknown NF instance - deny by default
        log::warn!("Unknown NF instance attempted authentication: {nf_instance_id}");
        self.denied_count += 1;
        false
    }

    /// Evaluate zero-trust policy for inter-NF communication.
    pub fn evaluate_policy(&self, source_nf_type: &str, target_nf_type: &str, source_instance_id: &str) -> PolicyDecision {
        // Check NF instance trust
        if let Some(trust) = self.nf_trust.get(source_instance_id) {
            if trust.revoked {
                log::warn!("Policy denied: source NF {source_instance_id} trust revoked");
                return PolicyDecision::Deny;
            }

            // Find matching policy rule (first match wins)
            for rule in &self.policy_rules {
                let source_match = rule.source_nf_type == "*" || rule.source_nf_type == source_nf_type;
                let target_match = rule.target_nf_type == "*" || rule.target_nf_type == target_nf_type;

                if source_match && target_match {
                    if trust.trust_score >= rule.min_trust_score {
                        log::debug!("Policy matched: {} -> {} (score {:.2}, rule: {})",
                                   source_nf_type, target_nf_type, trust.trust_score, rule.rule_id);
                        return rule.decision;
                    } else {
                        log::warn!("Trust score too low: {:.2} < {:.2}", trust.trust_score, rule.min_trust_score);
                        return PolicyDecision::Deny;
                    }
                }
            }
        }

        // Default deny (no matching rule or unknown NF)
        log::warn!("Policy denied (default): {source_nf_type} -> {target_nf_type}");
        PolicyDecision::Deny
    }

    /// Revoke trust for an NF instance based on anomaly detection.
    pub fn revoke_nf_trust(&mut self, nf_instance_id: &str, reason: &str) {
        if let Some(trust) = self.nf_trust.get_mut(nf_instance_id) {
            trust.revoked = true;
            trust.trust_score = 0.0;
            log::error!("Trust revoked for NF {nf_instance_id}: {reason}");
        }
    }

    /// Get current trust score for an NF instance.
    pub fn get_nf_trust_score(&self, nf_instance_id: &str) -> Option<f64> {
        self.nf_trust.get(nf_instance_id).map(|t| t.trust_score)
    }

    /// Verify an inter-PLMN request.
    pub fn verify(&mut self, plmn_id: &str, has_mtls: bool, has_token: bool, has_attestation: bool) -> VerificationResult {
        self.verification_count += 1;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;

        let achieved_level = match (has_mtls, has_token, has_attestation) {
            (true, true, true) => ZeroTrustLevel::Full,
            (true, true, false) => ZeroTrustLevel::Enhanced,
            (true, false, _) => ZeroTrustLevel::Basic,
            _ => ZeroTrustLevel::None,
        };

        let _peer_level = self.trusted_peers.get(plmn_id).copied().unwrap_or(ZeroTrustLevel::None);
        let trust_score = match achieved_level {
            ZeroTrustLevel::Full => 1.0,
            ZeroTrustLevel::Enhanced => 0.8,
            ZeroTrustLevel::Basic => 0.5,
            ZeroTrustLevel::None => 0.0,
        };

        let authorized = (achieved_level as u8) >= (self.min_level as u8);
        if !authorized {
            self.denied_count += 1;
        }

        VerificationResult {
            level: achieved_level,
            authorized,
            trust_score,
            reason: if authorized {
                format!("Trust level {} meets minimum", achieved_level as u8)
            } else {
                format!("Trust level {} below minimum {}", achieved_level as u8, self.min_level as u8)
            },
            timestamp_ms: now,
        }
    }

    pub fn verification_count(&self) -> u64 { self.verification_count }
    pub fn denied_count(&self) -> u64 { self.denied_count }
    pub fn nf_instance_count(&self) -> usize { self.nf_trust.len() }
}

// ============================================================================
// PQC Negotiation
// ============================================================================

/// PQC capability for N32 handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqcCapability {
    /// Supported KEM algorithms.
    pub kem_algorithms: Vec<PqcKemAlgorithm>,
    /// Supported signature algorithms.
    pub sig_algorithms: Vec<PqcSigAlgorithm>,
    /// Preferred hybrid mode.
    pub hybrid_mode: bool,
}

/// PQC KEM algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PqcKemAlgorithm {
    MlKem512,
    MlKem768,
    MlKem1024,
}

/// PQC signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PqcSigAlgorithm {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

/// Negotiate PQC parameters between two SEPPs.
pub fn negotiate_pqc(local: &PqcCapability, remote: &PqcCapability) -> Option<(PqcKemAlgorithm, PqcSigAlgorithm)> {
    // Prefer highest mutual KEM
    let kem = [PqcKemAlgorithm::MlKem1024, PqcKemAlgorithm::MlKem768, PqcKemAlgorithm::MlKem512]
        .iter()
        .find(|k| local.kem_algorithms.contains(k) && remote.kem_algorithms.contains(k))
        .copied()?;

    // Prefer highest mutual signature
    let sig = [PqcSigAlgorithm::MlDsa87, PqcSigAlgorithm::MlDsa65, PqcSigAlgorithm::MlDsa44]
        .iter()
        .find(|s| local.sig_algorithms.contains(s) && remote.sig_algorithms.contains(s))
        .copied()?;

    Some((kem, sig))
}

// ============================================================================
// AI Threat Detection
// ============================================================================

/// Threat detection result.
#[derive(Debug, Clone)]
pub struct ThreatAssessment {
    /// Threat score (0.0 = safe, 1.0 = definite threat).
    pub score: f64,
    /// Threat category.
    pub category: ThreatCategory,
    /// Whether to block the request.
    pub block: bool,
    /// Details.
    pub details: String,
}

/// Threat categories for inter-PLMN traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatCategory {
    /// No threat detected.
    Clean,
    /// Suspicious traffic pattern.
    SuspiciousPattern,
    /// Replay attack detected.
    ReplayAttack,
    /// Rate limit exceeded.
    RateLimitExceeded,
    /// Invalid or expired credentials.
    CredentialAnomaly,
    /// Known malicious source.
    KnownMalicious,
}

/// Simple AI threat detector based on traffic statistics.
pub struct ThreatDetector {
    /// Request count per source PLMN (sliding window).
    request_counts: HashMap<String, Vec<u64>>,
    /// Rate limit (requests per window).
    rate_limit: u32,
    /// Window duration.
    window: Duration,
    /// Total assessments.
    assessment_count: u64,
    /// Total blocks.
    block_count: u64,
}

impl ThreatDetector {
    /// Creates a new threat detector.
    pub fn new(rate_limit: u32, window: Duration) -> Self {
        Self {
            request_counts: HashMap::new(),
            rate_limit,
            window,
            assessment_count: 0,
            block_count: 0,
        }
    }

    /// Assess a request for threats.
    pub fn assess(&mut self, plmn_id: &str) -> ThreatAssessment {
        self.assessment_count += 1;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        let window_start = now.saturating_sub(self.window.as_millis() as u64);

        let timestamps = self.request_counts.entry(plmn_id.to_string()).or_default();
        timestamps.retain(|&t| t > window_start);
        timestamps.push(now);

        let count = timestamps.len() as u32;

        if count > self.rate_limit {
            self.block_count += 1;
            ThreatAssessment {
                score: 0.9,
                category: ThreatCategory::RateLimitExceeded,
                block: true,
                details: format!("{} requests in window (limit: {})", count, self.rate_limit),
            }
        } else {
            let score = (count as f64) / (self.rate_limit as f64) * 0.3;
            ThreatAssessment {
                score,
                category: ThreatCategory::Clean,
                block: false,
                details: format!("{count} requests in window"),
            }
        }
    }

    pub fn assessment_count(&self) -> u64 { self.assessment_count }
    pub fn block_count(&self) -> u64 { self.block_count }
}

// ============================================================================
// Anomaly Tracking for AI Threat Detection (B6.3)
// ============================================================================

/// Tracks statistical baselines to detect anomalous inter-PLMN behavior.
pub struct AnomalyTracker {
    /// Ring buffer of historical observations.
    observations: Vec<f64>,
    /// Maximum observations to retain for baseline.
    max_observations: usize,
    /// Cached mean.
    mean: f64,
    /// Cached standard deviation.
    std_dev: f64,
    /// Whether baseline statistics are valid.
    baseline_valid: bool,
}

impl AnomalyTracker {
    /// Create a new anomaly tracker.
    pub fn new(max_observations: usize) -> Self {
        Self {
            observations: Vec::with_capacity(max_observations),
            max_observations,
            mean: 0.0,
            std_dev: 0.0,
            baseline_valid: false,
        }
    }

    /// Record an observation and update baseline statistics.
    pub fn record_observation(&mut self, value: f64) {
        if self.observations.len() >= self.max_observations {
            self.observations.remove(0);
        }
        self.observations.push(value);
        self.recompute_baseline();
    }

    /// Check if the baseline has enough data.
    pub fn has_baseline(&self) -> bool {
        self.baseline_valid
    }

    /// Check if a value is anomalous.
    /// Returns (anomaly_score, is_anomaly).
    /// Score is 0.0 (normal) to 1.0 (extreme outlier).
    pub fn check_anomaly(&self, value: f64) -> (f64, bool) {
        if !self.baseline_valid || self.std_dev == 0.0 {
            return (0.0, false);
        }
        let z_score = ((value - self.mean) / self.std_dev).abs();
        let score = (z_score / 5.0).min(1.0); // Normalize to 0-1 range
        let anomaly = z_score > 3.0; // 3-sigma rule
        (score, anomaly)
    }

    fn recompute_baseline(&mut self) {
        let n = self.observations.len() as f64;
        if n < 3.0 {
            self.baseline_valid = false;
            return;
        }
        self.mean = self.observations.iter().sum::<f64>() / n;
        let variance: f64 = self.observations.iter()
            .map(|v| (v - self.mean).powi(2))
            .sum::<f64>() / n;
        self.std_dev = variance.sqrt();
        self.baseline_valid = true;
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_trust_verify() {
        let mut engine = ZeroTrustEngine::new(ZeroTrustLevel::Enhanced);
        engine.add_trusted_peer("310260", ZeroTrustLevel::Full);

        let result = engine.verify("310260", true, true, true);
        assert!(result.authorized);
        assert_eq!(result.level, ZeroTrustLevel::Full);

        let result = engine.verify("310260", true, false, false);
        assert!(!result.authorized); // Basic < Enhanced
    }

    #[test]
    fn test_pqc_negotiation() {
        let local = PqcCapability {
            kem_algorithms: vec![PqcKemAlgorithm::MlKem768, PqcKemAlgorithm::MlKem1024],
            sig_algorithms: vec![PqcSigAlgorithm::MlDsa65, PqcSigAlgorithm::MlDsa87],
            hybrid_mode: true,
        };
        let remote = PqcCapability {
            kem_algorithms: vec![PqcKemAlgorithm::MlKem768],
            sig_algorithms: vec![PqcSigAlgorithm::MlDsa65],
            hybrid_mode: false,
        };

        let (kem, sig) = negotiate_pqc(&local, &remote).unwrap();
        assert_eq!(kem, PqcKemAlgorithm::MlKem768);
        assert_eq!(sig, PqcSigAlgorithm::MlDsa65);
    }

    #[test]
    fn test_threat_detector() {
        let mut detector = ThreatDetector::new(5, Duration::from_secs(60));
        for _ in 0..4 {
            let result = detector.assess("99901");
            assert!(!result.block);
        }
        // Exceed rate limit
        for _ in 0..3 {
            detector.assess("99901");
        }
        let result = detector.assess("99901");
        assert!(result.block);
        assert_eq!(result.category, ThreatCategory::RateLimitExceeded);
    }

    #[test]
    fn test_anomaly_tracker_baseline() {
        let mut tracker = AnomalyTracker::new(10);
        // Build baseline with normal request counts
        for _ in 0..10 {
            tracker.record_observation(100.0);
        }
        assert!(tracker.has_baseline());

        // Normal observation within 2 std deviations
        let (score, anomaly) = tracker.check_anomaly(100.0);
        assert!(score < 0.5);
        assert!(!anomaly);
    }

    #[test]
    fn test_anomaly_tracker_detect() {
        let mut tracker = AnomalyTracker::new(10);
        // Use slightly varying values so std_dev > 0
        for i in 0..10 {
            tracker.record_observation(100.0 + i as f64 * 0.1);
        }

        // Extreme outlier should be anomalous
        let (score, anomaly) = tracker.check_anomaly(10000.0);
        assert!(score > 0.5);
        assert!(anomaly);
    }

    #[test]
    fn test_anomaly_tracker_no_baseline() {
        let mut tracker = AnomalyTracker::new(10);
        tracker.record_observation(100.0);
        // Not enough observations for baseline
        assert!(!tracker.has_baseline());
        let (_, anomaly) = tracker.check_anomaly(100.0);
        assert!(!anomaly); // Cannot detect anomaly without baseline
    }

    #[test]
    fn test_zero_trust_service_mesh() {
        let mut engine = ZeroTrustEngine::new(ZeroTrustLevel::Enhanced);

        // Register NF instance with mTLS cert
        engine.register_nf_instance(
            "amf-instance-1".to_string(),
            "AMF".to_string(),
            Some("sha256:abcd1234".to_string()),
        );

        // Authenticate with correct cert
        assert!(engine.authenticate_nf("amf-instance-1", true, Some("sha256:abcd1234".to_string())));

        // Authenticate with wrong cert should fail
        assert!(!engine.authenticate_nf("amf-instance-1", true, Some("sha256:wrong".to_string())));

        // Trust score should have degraded
        let score = engine.get_nf_trust_score("amf-instance-1").unwrap();
        assert!(score < 1.0);
    }

    #[test]
    fn test_zero_trust_policy_evaluation() {
        let mut engine = ZeroTrustEngine::new(ZeroTrustLevel::Enhanced);

        // Register NF with high trust
        engine.register_nf_instance("amf-1".to_string(), "AMF".to_string(), None);

        // Add allow rule for AMF -> SMF
        engine.add_policy_rule(PolicyRule {
            rule_id: "allow-amf-smf".to_string(),
            source_nf_type: "AMF".to_string(),
            target_nf_type: "SMF".to_string(),
            min_trust_score: 0.8,
            require_mtls: true,
            decision: PolicyDecision::Allow,
        });

        // Should allow AMF -> SMF
        let decision = engine.evaluate_policy("AMF", "SMF", "amf-1");
        assert_eq!(decision, PolicyDecision::Allow);

        // Should deny AMF -> UDM (no explicit rule, default deny)
        let decision = engine.evaluate_policy("AMF", "UDM", "amf-1");
        assert_eq!(decision, PolicyDecision::Deny);
    }

    #[test]
    fn test_zero_trust_anomaly_revocation() {
        let mut engine = ZeroTrustEngine::new(ZeroTrustLevel::Enhanced);

        engine.register_nf_instance("smf-1".to_string(), "SMF".to_string(), None);
        assert_eq!(engine.get_nf_trust_score("smf-1"), Some(1.0));

        // Revoke trust due to anomaly
        engine.revoke_nf_trust("smf-1", "Abnormal traffic pattern detected");

        // Trust score should be 0
        assert_eq!(engine.get_nf_trust_score("smf-1"), Some(0.0));

        // Authentication should fail
        assert!(!engine.authenticate_nf("smf-1", true, None));
    }
}
