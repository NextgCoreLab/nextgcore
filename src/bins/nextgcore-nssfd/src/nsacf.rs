//! NSACF Interaction for 6G Slice Admission Control (Item #195)
//!
//! Implements Network Slice Admission Control Function (NSACF) interaction
//! for dynamic 6G slice admission, quota management, and overload control.
//!
//! Reference: 3GPP TS 29.536 (NSACF services)

use std::collections::HashMap;

// ============================================================================
// Slice Admission Types
// ============================================================================

/// Network Slice Admission result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionResult {
    /// Admission granted.
    Admitted,
    /// Admission denied (quota exceeded).
    DeniedQuotaExceeded,
    /// Admission denied (slice not available in area).
    DeniedNotAvailable,
    /// Admission denied (overload).
    DeniedOverload,
    /// Admission pending (waiting for NSACF response).
    Pending,
}

/// Slice quota information from NSACF.
#[derive(Debug, Clone)]
pub struct SliceQuota {
    /// S-NSSAI SST.
    pub sst: u8,
    /// S-NSSAI SD.
    pub sd: Option<u32>,
    /// Maximum number of UEs admitted.
    pub max_ues: u32,
    /// Current number of UEs.
    pub current_ues: u32,
    /// Maximum number of PDU sessions.
    pub max_pdu_sessions: u32,
    /// Current number of PDU sessions.
    pub current_pdu_sessions: u32,
}

impl SliceQuota {
    /// Whether the slice has capacity for a new UE.
    pub fn has_ue_capacity(&self) -> bool {
        self.current_ues < self.max_ues
    }

    /// Whether the slice has capacity for a new PDU session.
    pub fn has_session_capacity(&self) -> bool {
        self.current_pdu_sessions < self.max_pdu_sessions
    }

    /// UE utilization ratio (0.0-1.0).
    pub fn ue_utilization(&self) -> f64 {
        if self.max_ues == 0 { return 1.0; }
        self.current_ues as f64 / self.max_ues as f64
    }
}

/// NSACF client for slice admission queries.
pub struct NsacfClient {
    /// Cached slice quotas.
    quotas: HashMap<(u8, Option<u32>), SliceQuota>,
    /// Total admission requests.
    total_requests: u64,
    /// Total admissions granted.
    total_admitted: u64,
    /// Total admissions denied.
    total_denied: u64,
}

impl NsacfClient {
    /// Creates a new NSACF client.
    pub fn new() -> Self {
        Self {
            quotas: HashMap::new(),
            total_requests: 0,
            total_admitted: 0,
            total_denied: 0,
        }
    }

    /// Update cached slice quota (from NSACF response).
    pub fn update_quota(&mut self, quota: SliceQuota) {
        let key = (quota.sst, quota.sd);
        self.quotas.insert(key, quota);
    }

    /// Check admission for a UE into a slice.
    pub fn check_admission(&mut self, sst: u8, sd: Option<u32>) -> AdmissionResult {
        self.total_requests += 1;

        let key = (sst, sd);
        match self.quotas.get(&key) {
            Some(quota) => {
                if quota.has_ue_capacity() {
                    self.total_admitted += 1;
                    AdmissionResult::Admitted
                } else {
                    self.total_denied += 1;
                    AdmissionResult::DeniedQuotaExceeded
                }
            }
            None => {
                // No quota info; assume admitted (will be overridden by actual NSACF call).
                self.total_admitted += 1;
                AdmissionResult::Admitted
            }
        }
    }

    /// Record a UE admission (increment counter).
    pub fn record_admission(&mut self, sst: u8, sd: Option<u32>) {
        let key = (sst, sd);
        if let Some(quota) = self.quotas.get_mut(&key) {
            quota.current_ues = quota.current_ues.saturating_add(1);
        }
    }

    /// Record a UE release (decrement counter).
    pub fn record_release(&mut self, sst: u8, sd: Option<u32>) {
        let key = (sst, sd);
        if let Some(quota) = self.quotas.get_mut(&key) {
            quota.current_ues = quota.current_ues.saturating_sub(1);
        }
    }

    /// Get quota for a slice.
    pub fn get_quota(&self, sst: u8, sd: Option<u32>) -> Option<&SliceQuota> {
        self.quotas.get(&(sst, sd))
    }

    /// Total admission requests.
    pub fn total_requests(&self) -> u64 { self.total_requests }
    /// Total admissions.
    pub fn total_admitted(&self) -> u64 { self.total_admitted }
    /// Total denials.
    pub fn total_denied(&self) -> u64 { self.total_denied }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slice_quota_capacity() {
        let quota = SliceQuota {
            sst: 1, sd: None,
            max_ues: 100, current_ues: 50,
            max_pdu_sessions: 200, current_pdu_sessions: 100,
        };
        assert!(quota.has_ue_capacity());
        assert!(quota.has_session_capacity());
        assert!((quota.ue_utilization() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_slice_quota_full() {
        let quota = SliceQuota {
            sst: 2, sd: Some(0x010203),
            max_ues: 10, current_ues: 10,
            max_pdu_sessions: 20, current_pdu_sessions: 15,
        };
        assert!(!quota.has_ue_capacity());
        assert!(quota.has_session_capacity());
    }

    #[test]
    fn test_nsacf_admission() {
        let mut client = NsacfClient::new();

        client.update_quota(SliceQuota {
            sst: 1, sd: None,
            max_ues: 2, current_ues: 1,
            max_pdu_sessions: 4, current_pdu_sessions: 0,
        });

        assert_eq!(client.check_admission(1, None), AdmissionResult::Admitted);
        client.record_admission(1, None);
        assert_eq!(client.check_admission(1, None), AdmissionResult::DeniedQuotaExceeded);
    }

    #[test]
    fn test_nsacf_release() {
        let mut client = NsacfClient::new();
        client.update_quota(SliceQuota {
            sst: 1, sd: None,
            max_ues: 1, current_ues: 1,
            max_pdu_sessions: 1, current_pdu_sessions: 0,
        });

        assert_eq!(client.check_admission(1, None), AdmissionResult::DeniedQuotaExceeded);
        client.record_release(1, None);
        assert_eq!(client.check_admission(1, None), AdmissionResult::Admitted);
    }

    #[test]
    fn test_nsacf_counters() {
        let mut client = NsacfClient::new();
        client.check_admission(1, None);
        client.check_admission(2, None);
        assert_eq!(client.total_requests(), 2);
    }
}
