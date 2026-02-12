//! NSACF Context Management
//!
//! Network Slice Admission Control Function context (TS 23.502 4.2.9)

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

/// S-NSSAI (Single Network Slice Selection Assistance Information)
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct SNssai {
    pub sst: u8,
    pub sd: Option<u32>,
}

impl SNssai {
    pub fn new(sst: u8, sd: Option<u32>) -> Self {
        Self { sst, sd }
    }
}

/// PLMN ID
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct PlmnId {
    pub mcc: String,
    pub mnc: String,
}

/// Slice admission result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionResult {
    /// Admitted
    Admitted,
    /// Rejected - quota exceeded
    RejectedQuotaExceeded,
    /// Rejected - slice not available
    RejectedSliceNotAvailable,
}

/// Slice quota configuration
#[derive(Debug)]
pub struct SliceQuota {
    /// Unique ID
    pub id: u64,
    /// S-NSSAI this quota applies to
    pub s_nssai: SNssai,
    /// Maximum number of UEs allowed in this slice
    pub max_ues: u64,
    /// Maximum number of PDU sessions allowed in this slice
    pub max_pdu_sessions: u64,
    /// Current number of registered UEs
    pub current_ues: AtomicU64,
    /// Current number of PDU sessions
    pub current_pdu_sessions: AtomicU64,
}

impl SliceQuota {
    pub fn new(id: u64, s_nssai: SNssai, max_ues: u64, max_pdu_sessions: u64) -> Self {
        Self {
            id,
            s_nssai,
            max_ues,
            max_pdu_sessions,
            current_ues: AtomicU64::new(0),
            current_pdu_sessions: AtomicU64::new(0),
        }
    }

    /// Check if a new UE can be admitted
    pub fn can_admit_ue(&self) -> bool {
        self.current_ues.load(Ordering::SeqCst) < self.max_ues
    }

    /// Check if a new PDU session can be admitted
    pub fn can_admit_pdu_session(&self) -> bool {
        self.current_pdu_sessions.load(Ordering::SeqCst) < self.max_pdu_sessions
    }

    /// Register a UE (increment counter)
    pub fn register_ue(&self) -> bool {
        let current = self.current_ues.load(Ordering::SeqCst);
        if current >= self.max_ues {
            return false;
        }
        self.current_ues.fetch_add(1, Ordering::SeqCst);
        true
    }

    /// Deregister a UE (decrement counter)
    pub fn deregister_ue(&self) {
        let current = self.current_ues.load(Ordering::SeqCst);
        if current > 0 {
            self.current_ues.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Register a PDU session (increment counter)
    pub fn register_pdu_session(&self) -> bool {
        let current = self.current_pdu_sessions.load(Ordering::SeqCst);
        if current >= self.max_pdu_sessions {
            return false;
        }
        self.current_pdu_sessions.fetch_add(1, Ordering::SeqCst);
        true
    }

    /// Deregister a PDU session (decrement counter)
    pub fn deregister_pdu_session(&self) {
        let current = self.current_pdu_sessions.load(Ordering::SeqCst);
        if current > 0 {
            self.current_pdu_sessions.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Get UE utilization percentage
    pub fn ue_utilization(&self) -> f64 {
        if self.max_ues == 0 {
            return 0.0;
        }
        (self.current_ues.load(Ordering::SeqCst) as f64 / self.max_ues as f64) * 100.0
    }
}

// Clone requires manual impl due to AtomicU64
impl Clone for SliceQuota {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            s_nssai: self.s_nssai.clone(),
            max_ues: self.max_ues,
            max_pdu_sessions: self.max_pdu_sessions,
            current_ues: AtomicU64::new(self.current_ues.load(Ordering::SeqCst)),
            current_pdu_sessions: AtomicU64::new(self.current_pdu_sessions.load(Ordering::SeqCst)),
        }
    }
}

/// NSACF Context - main context structure
pub struct NsacfContext {
    /// Slice quota configurations
    quota_list: RwLock<HashMap<u64, SliceQuota>>,
    /// S-NSSAI -> quota ID hash
    snssai_hash: RwLock<HashMap<(u8, Option<u32>), u64>>,
    /// Next quota ID generator
    next_quota_id: AtomicUsize,
    /// Maximum number of slice quotas
    max_quotas: usize,
    /// Context initialized flag
    initialized: AtomicBool,
}

impl NsacfContext {
    pub fn new() -> Self {
        Self {
            quota_list: RwLock::new(HashMap::new()),
            snssai_hash: RwLock::new(HashMap::new()),
            next_quota_id: AtomicUsize::new(1),
            max_quotas: 0,
            initialized: AtomicBool::new(false),
        }
    }

    pub fn init(&mut self, max_quotas: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.max_quotas = max_quotas;
        self.initialized.store(true, Ordering::SeqCst);
        log::info!("NSACF context initialized with max {max_quotas} slice quotas");
    }

    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }
        if let (Ok(mut quota_list), Ok(mut snssai_hash)) = (
            self.quota_list.write(),
            self.snssai_hash.write(),
        ) {
            quota_list.clear();
            snssai_hash.clear();
        }
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("NSACF context finalized");
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    // Quota management

    pub fn quota_add(&self, s_nssai: SNssai, max_ues: u64, max_pdu_sessions: u64) -> Option<SliceQuota> {
        let mut quota_list = self.quota_list.write().ok()?;
        let mut snssai_hash = self.snssai_hash.write().ok()?;

        if quota_list.len() >= self.max_quotas {
            log::error!("Maximum number of slice quotas [{}] reached", self.max_quotas);
            return None;
        }

        let id = self.next_quota_id.fetch_add(1, Ordering::SeqCst) as u64;
        let quota = SliceQuota::new(id, s_nssai.clone(), max_ues, max_pdu_sessions);

        snssai_hash.insert((s_nssai.sst, s_nssai.sd), id);
        quota_list.insert(id, quota.clone());

        log::info!(
            "Slice quota added: S-NSSAI[SST:{} SD:{:?}] max_ues={} max_pdu={}",
            s_nssai.sst, s_nssai.sd, max_ues, max_pdu_sessions
        );
        Some(quota)
    }

    pub fn quota_find_by_snssai(&self, s_nssai: &SNssai) -> Option<SliceQuota> {
        let snssai_hash = self.snssai_hash.read().ok()?;
        let quota_list = self.quota_list.read().ok()?;
        snssai_hash
            .get(&(s_nssai.sst, s_nssai.sd))
            .and_then(|&id| quota_list.get(&id).cloned())
    }

    pub fn quota_find_by_id(&self, id: u64) -> Option<SliceQuota> {
        let quota_list = self.quota_list.read().ok()?;
        quota_list.get(&id).cloned()
    }

    /// Attempt to admit a UE to a slice (TS 23.502 4.2.9.2)
    pub fn admit_ue(&self, s_nssai: &SNssai) -> AdmissionResult {
        let snssai_hash = self.snssai_hash.read().ok()
            .unwrap_or_else(|| panic!("NSACF context lock poisoned"));
        let quota_list = self.quota_list.read().ok()
            .unwrap_or_else(|| panic!("NSACF context lock poisoned"));

        let quota_id = match snssai_hash.get(&(s_nssai.sst, s_nssai.sd)) {
            Some(&id) => id,
            None => {
                log::warn!(
                    "No quota configured for S-NSSAI[SST:{} SD:{:?}]",
                    s_nssai.sst, s_nssai.sd
                );
                return AdmissionResult::RejectedSliceNotAvailable;
            }
        };

        let quota = match quota_list.get(&quota_id) {
            Some(q) => q,
            None => return AdmissionResult::RejectedSliceNotAvailable,
        };

        if quota.register_ue() {
            log::debug!(
                "UE admitted to S-NSSAI[SST:{} SD:{:?}] ({}/{})",
                s_nssai.sst, s_nssai.sd,
                quota.current_ues.load(Ordering::SeqCst),
                quota.max_ues
            );
            AdmissionResult::Admitted
        } else {
            log::warn!(
                "UE rejected from S-NSSAI[SST:{} SD:{:?}] - quota exceeded ({}/{})",
                s_nssai.sst, s_nssai.sd,
                quota.current_ues.load(Ordering::SeqCst),
                quota.max_ues
            );
            AdmissionResult::RejectedQuotaExceeded
        }
    }

    /// Release a UE from a slice
    pub fn release_ue(&self, s_nssai: &SNssai) {
        let snssai_hash = self.snssai_hash.read().ok().unwrap();
        let quota_list = self.quota_list.read().ok().unwrap();

        if let Some(&quota_id) = snssai_hash.get(&(s_nssai.sst, s_nssai.sd)) {
            if let Some(quota) = quota_list.get(&quota_id) {
                quota.deregister_ue();
            }
        }
    }

    pub fn quota_count(&self) -> usize {
        self.quota_list.read().map(|l| l.len()).unwrap_or(0)
    }

    /// Get all quota utilizations
    pub fn get_utilization(&self) -> Vec<(SNssai, f64)> {
        self.quota_list
            .read()
            .map(|l| {
                l.values()
                    .map(|q| (q.s_nssai.clone(), q.ue_utilization()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Default for NsacfContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global NSACF context (thread-safe singleton)
static GLOBAL_NSACF_CONTEXT: std::sync::OnceLock<Arc<RwLock<NsacfContext>>> = std::sync::OnceLock::new();

/// Get the global NSACF context
pub fn nsacf_self() -> Arc<RwLock<NsacfContext>> {
    GLOBAL_NSACF_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(NsacfContext::new())))
        .clone()
}

/// Initialize the global NSACF context
pub fn nsacf_context_init(max_quotas: usize) {
    let ctx = nsacf_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_quotas);
    };
}

/// Finalize the global NSACF context
pub fn nsacf_context_final() {
    let ctx = nsacf_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nsacf_context_new() {
        let ctx = NsacfContext::new();
        assert!(!ctx.is_initialized());
        assert_eq!(ctx.quota_count(), 0);
    }

    #[test]
    fn test_nsacf_context_init_fini() {
        let mut ctx = NsacfContext::new();
        ctx.init(64);
        assert!(ctx.is_initialized());

        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_quota_add_and_find() {
        let mut ctx = NsacfContext::new();
        ctx.init(64);

        let s_nssai = SNssai::new(1, Some(0x010203));
        let quota = ctx.quota_add(s_nssai.clone(), 1000, 5000).unwrap();
        assert_eq!(quota.max_ues, 1000);
        assert_eq!(ctx.quota_count(), 1);

        let found = ctx.quota_find_by_snssai(&s_nssai);
        assert!(found.is_some());
    }

    #[test]
    fn test_admit_ue_success() {
        let mut ctx = NsacfContext::new();
        ctx.init(64);

        let s_nssai = SNssai::new(1, None);
        ctx.quota_add(s_nssai.clone(), 100, 500);

        let result = ctx.admit_ue(&s_nssai);
        assert_eq!(result, AdmissionResult::Admitted);
    }

    #[test]
    fn test_admit_ue_quota_exceeded() {
        let mut ctx = NsacfContext::new();
        ctx.init(64);

        let s_nssai = SNssai::new(2, None);
        ctx.quota_add(s_nssai.clone(), 2, 10);

        assert_eq!(ctx.admit_ue(&s_nssai), AdmissionResult::Admitted);
        assert_eq!(ctx.admit_ue(&s_nssai), AdmissionResult::Admitted);
        assert_eq!(ctx.admit_ue(&s_nssai), AdmissionResult::RejectedQuotaExceeded);
    }

    #[test]
    fn test_admit_ue_not_available() {
        let mut ctx = NsacfContext::new();
        ctx.init(64);

        let s_nssai = SNssai::new(99, None);
        let result = ctx.admit_ue(&s_nssai);
        assert_eq!(result, AdmissionResult::RejectedSliceNotAvailable);
    }

    #[test]
    fn test_release_ue() {
        let mut ctx = NsacfContext::new();
        ctx.init(64);

        let s_nssai = SNssai::new(1, None);
        ctx.quota_add(s_nssai.clone(), 2, 10);

        ctx.admit_ue(&s_nssai);
        ctx.admit_ue(&s_nssai);
        assert_eq!(ctx.admit_ue(&s_nssai), AdmissionResult::RejectedQuotaExceeded);

        ctx.release_ue(&s_nssai);
        assert_eq!(ctx.admit_ue(&s_nssai), AdmissionResult::Admitted);
    }

    #[test]
    fn test_ue_utilization() {
        let quota = SliceQuota::new(1, SNssai::new(1, None), 100, 500);
        assert_eq!(quota.ue_utilization(), 0.0);

        quota.register_ue();
        quota.register_ue();
        assert!((quota.ue_utilization() - 2.0).abs() < 0.01);
    }
}
