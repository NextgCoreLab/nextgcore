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

/// Zero-trust policy engine.
pub struct ZeroTrustEngine {
    /// Minimum required trust level.
    min_level: ZeroTrustLevel,
    /// Trusted PLMN peers (PLMN ID → trust level).
    trusted_peers: HashMap<String, ZeroTrustLevel>,
    /// Verification count.
    verification_count: u64,
    /// Denied count.
    denied_count: u64,
}

impl ZeroTrustEngine {
    /// Creates a new zero-trust engine.
    pub fn new(min_level: ZeroTrustLevel) -> Self {
        Self {
            min_level,
            trusted_peers: HashMap::new(),
            verification_count: 0,
            denied_count: 0,
        }
    }

    /// Register a trusted peer PLMN.
    pub fn add_trusted_peer(&mut self, plmn_id: impl Into<String>, level: ZeroTrustLevel) {
        self.trusted_peers.insert(plmn_id.into(), level);
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
