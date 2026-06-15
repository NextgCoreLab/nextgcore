//! NSACF Context Management
//!
//! Network Slice Admission Control Function context (TS 23.502 4.2.9,
//! TS 29.536). Counts are membership-based (per SUPI / per PDU-session key)
//! so INCREASE/DECREASE updates are idempotent and a UE is never counted
//! twice for the same slice. Counters survive restarts when a state file is
//! configured (`--state-file`).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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

    /// Serialize as TS 29.571 Snssai JSON
    pub fn to_json(&self) -> serde_json::Value {
        let mut v = serde_json::json!({ "sst": self.sst });
        if let Some(sd) = self.sd {
            v["sd"] = serde_json::json!(format!("{sd:06x}"));
        }
        v
    }

    /// Parse from TS 29.571 Snssai JSON
    pub fn from_json(v: &serde_json::Value) -> Option<Self> {
        let sst = v.get("sst")?.as_u64()?;
        if sst > 255 {
            return None;
        }
        let sd = match v.get("sd") {
            Some(serde_json::Value::String(s)) => Some(u32::from_str_radix(s, 16).ok()?),
            Some(serde_json::Value::Null) | None => None,
            _ => return None,
        };
        Some(Self::new(sst as u8, sd))
    }

    /// Parse from a URI path segment: `{sst}` or `{sst}-{sd-hex}`
    pub fn from_path_segment(seg: &str) -> Option<Self> {
        match seg.split_once('-') {
            Some((sst, sd)) => Some(Self::new(
                sst.parse().ok()?,
                Some(u32::from_str_radix(sd, 16).ok()?),
            )),
            None => Some(Self::new(seg.parse().ok()?, None)),
        }
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

/// Early Admission Control mode transition (TS 23.502 §4.2.9.5)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EacTransition {
    pub s_nssai: SNssai,
    /// true -> EAC mode activated, false -> deactivated
    pub activated: bool,
}

/// Slice quota configuration with membership-based counters
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
    /// Registered UE identities (SUPIs)
    pub(crate) ues: HashSet<String>,
    /// Established PDU session keys (`{supi}:{pduSessionId}`)
    pub(crate) pdu_sessions: HashSet<String>,
    /// Whether EAC mode is currently active for this slice
    pub(crate) eac_active: bool,
}

impl SliceQuota {
    pub fn new(id: u64, s_nssai: SNssai, max_ues: u64, max_pdu_sessions: u64) -> Self {
        Self {
            id,
            s_nssai,
            max_ues,
            max_pdu_sessions,
            ues: HashSet::new(),
            pdu_sessions: HashSet::new(),
            eac_active: false,
        }
    }

    pub fn current_ues(&self) -> u64 {
        self.ues.len() as u64
    }

    pub fn current_pdu_sessions(&self) -> u64 {
        self.pdu_sessions.len() as u64
    }

    /// Get UE utilization percentage
    pub fn ue_utilization(&self) -> f64 {
        if self.max_ues == 0 {
            return 0.0;
        }
        (self.current_ues() as f64 / self.max_ues as f64) * 100.0
    }

    /// Get PDU-session utilization percentage
    pub fn pdu_utilization(&self) -> f64 {
        if self.max_pdu_sessions == 0 {
            return 0.0;
        }
        (self.current_pdu_sessions() as f64 / self.max_pdu_sessions as f64) * 100.0
    }

    pub fn eac_active(&self) -> bool {
        self.eac_active
    }
}

impl Clone for SliceQuota {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            s_nssai: self.s_nssai.clone(),
            max_ues: self.max_ues,
            max_pdu_sessions: self.max_pdu_sessions,
            ues: self.ues.clone(),
            pdu_sessions: self.pdu_sessions.clone(),
            eac_active: self.eac_active,
        }
    }
}

/// SliceEventExposure subscription (TS 29.536 Nnsacf_SliceEventExposure)
#[derive(Debug, Clone)]
pub struct SacSubscription {
    pub subscription_id: String,
    /// Notification callback URI (mandatory)
    pub notification_uri: String,
    /// Subscribed events (mandatory), e.g. NUM_OF_REGISTERED_UES,
    /// NUM_OF_ESTABLISHED_PDU_SESSIONS
    pub events: Vec<String>,
    /// S-NSSAIs of interest (empty = all slices)
    pub snssais: Vec<SNssai>,
    pub expiry: Option<String>,
}

impl SacSubscription {
    pub fn matches_snssai(&self, s_nssai: &SNssai) -> bool {
        self.snssais.is_empty() || self.snssais.contains(s_nssai)
    }
}

/// NSACF Context - main context structure
pub struct NsacfContext {
    /// Slice quota configurations
    quota_list: RwLock<HashMap<u64, SliceQuota>>,
    /// S-NSSAI -> quota ID hash
    snssai_hash: RwLock<HashMap<(u8, Option<u32>), u64>>,
    /// SliceEventExposure subscriptions by subscriptionId
    subscriptions: RwLock<HashMap<String, SacSubscription>>,
    /// Next quota ID generator
    next_quota_id: AtomicUsize,
    /// Maximum number of slice quotas
    max_quotas: usize,
    /// EAC activation threshold in percent of max UEs (TS 23.502 §4.2.9.5)
    eac_threshold_percent: RwLock<u8>,
    /// Optional persistence path; counters survive restarts when set
    state_file: RwLock<Option<PathBuf>>,
    /// Context initialized flag
    initialized: AtomicBool,
}

impl NsacfContext {
    pub fn new() -> Self {
        Self {
            quota_list: RwLock::new(HashMap::new()),
            snssai_hash: RwLock::new(HashMap::new()),
            subscriptions: RwLock::new(HashMap::new()),
            next_quota_id: AtomicUsize::new(1),
            max_quotas: 0,
            eac_threshold_percent: RwLock::new(80),
            state_file: RwLock::new(None),
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
        if let Ok(mut quota_list) = self.quota_list.write() {
            quota_list.clear();
        }
        if let Ok(mut snssai_hash) = self.snssai_hash.write() {
            snssai_hash.clear();
        }
        if let Ok(mut subs) = self.subscriptions.write() {
            subs.clear();
        }
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("NSACF context finalized");
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    pub fn set_eac_threshold(&self, percent: u8) {
        if let Ok(mut t) = self.eac_threshold_percent.write() {
            *t = percent.min(100);
        }
    }

    pub fn eac_threshold(&self) -> u8 {
        self.eac_threshold_percent.read().map(|t| *t).unwrap_or(80)
    }

    // ------------------------------------------------------------------
    // Quota management
    // ------------------------------------------------------------------

    pub fn quota_add(
        &self,
        s_nssai: SNssai,
        max_ues: u64,
        max_pdu_sessions: u64,
    ) -> Option<SliceQuota> {
        let quota = {
            let mut quota_list = self.quota_list.write().ok()?;

            if quota_list.len() >= self.max_quotas {
                log::error!(
                    "Maximum number of slice quotas [{}] reached",
                    self.max_quotas
                );
                return None;
            }

            let id = self.next_quota_id.fetch_add(1, Ordering::SeqCst) as u64;
            let quota = SliceQuota::new(id, s_nssai.clone(), max_ues, max_pdu_sessions);
            quota_list.insert(id, quota.clone());
            quota
        }; // quota_list guard dropped before taking snssai_hash (no two-map hold)

        if let Ok(mut snssai_hash) = self.snssai_hash.write() {
            snssai_hash.insert((s_nssai.sst, s_nssai.sd), quota.id);
        }

        log::info!(
            "Slice quota added: S-NSSAI[SST:{} SD:{:?}] max_ues={} max_pdu={}",
            s_nssai.sst,
            s_nssai.sd,
            max_ues,
            max_pdu_sessions
        );
        self.save_state();
        Some(quota)
    }

    fn quota_id_for(&self, s_nssai: &SNssai) -> Option<u64> {
        // Copy the id and drop the hash guard before any other lock is taken
        let id = self
            .snssai_hash
            .read()
            .ok()?
            .get(&(s_nssai.sst, s_nssai.sd))
            .copied();
        id
    }

    pub fn quota_find_by_snssai(&self, s_nssai: &SNssai) -> Option<SliceQuota> {
        let id = self.quota_id_for(s_nssai)?;
        self.quota_find_by_id(id)
    }

    pub fn quota_find_by_id(&self, id: u64) -> Option<SliceQuota> {
        let quota = self.quota_list.read().ok()?.get(&id).cloned();
        quota
    }

    /// Remove a quota by ID, returning true if it existed.
    pub fn quota_remove(&self, id: u64) -> bool {
        let removed = {
            let mut quota_list = match self.quota_list.write() {
                Ok(l) => l,
                Err(_) => return false,
            };
            quota_list.remove(&id)
        };
        let Some(quota) = removed else {
            return false;
        };
        if let Ok(mut snssai_hash) = self.snssai_hash.write() {
            snssai_hash.remove(&(quota.s_nssai.sst, quota.s_nssai.sd));
        }
        log::info!(
            "Slice quota removed: id={} S-NSSAI[SST:{} SD:{:?}]",
            id,
            quota.s_nssai.sst,
            quota.s_nssai.sd
        );
        self.save_state();
        true
    }

    // ------------------------------------------------------------------
    // UE admission control (TS 29.536 NumOfUEsUpdate, updateFlag INCREASE)
    // ------------------------------------------------------------------

    /// Admit a UE (idempotent per SUPI). Returns the admission result and an
    /// EAC transition when the registered-UE count crosses the threshold.
    pub fn admit_ue(
        &self,
        s_nssai: &SNssai,
        supi: &str,
    ) -> (AdmissionResult, Option<EacTransition>) {
        let Some(id) = self.quota_id_for(s_nssai) else {
            log::warn!(
                "No quota configured for S-NSSAI[SST:{} SD:{:?}]",
                s_nssai.sst,
                s_nssai.sd
            );
            return (AdmissionResult::RejectedSliceNotAvailable, None);
        };
        let threshold = self.eac_threshold();
        let result = {
            let mut quota_list = match self.quota_list.write() {
                Ok(l) => l,
                Err(_) => return (AdmissionResult::RejectedSliceNotAvailable, None),
            };
            let Some(quota) = quota_list.get_mut(&id) else {
                return (AdmissionResult::RejectedSliceNotAvailable, None);
            };
            if quota.ues.contains(supi) {
                // Already counted; INCREASE is idempotent per TS 29.536
                (AdmissionResult::Admitted, None)
            } else if quota.current_ues() >= quota.max_ues {
                (AdmissionResult::RejectedQuotaExceeded, None)
            } else {
                quota.ues.insert(supi.to_string());
                let eac = update_eac(quota, threshold);
                (AdmissionResult::Admitted, eac)
            }
        };
        if result.0 == AdmissionResult::Admitted {
            self.save_state();
        }
        result
    }

    /// Release a UE (updateFlag DECREASE; idempotent). Returns an EAC
    /// transition when the count falls back below the threshold.
    pub fn release_ue(&self, s_nssai: &SNssai, supi: &str) -> Option<EacTransition> {
        let id = self.quota_id_for(s_nssai)?;
        let threshold = self.eac_threshold();
        let eac = {
            let mut quota_list = self.quota_list.write().ok()?;
            let quota = quota_list.get_mut(&id)?;
            if !quota.ues.remove(supi) {
                return None;
            }
            update_eac(quota, threshold)
        };
        self.save_state();
        eac
    }

    // ------------------------------------------------------------------
    // PDU session admission control (TS 29.536 NumOfPDUsUpdate)
    // ------------------------------------------------------------------

    pub fn admit_pdu_session(&self, s_nssai: &SNssai, session_key: &str) -> AdmissionResult {
        let Some(id) = self.quota_id_for(s_nssai) else {
            return AdmissionResult::RejectedSliceNotAvailable;
        };
        let result = {
            let mut quota_list = match self.quota_list.write() {
                Ok(l) => l,
                Err(_) => return AdmissionResult::RejectedSliceNotAvailable,
            };
            let Some(quota) = quota_list.get_mut(&id) else {
                return AdmissionResult::RejectedSliceNotAvailable;
            };
            if quota.pdu_sessions.contains(session_key) {
                AdmissionResult::Admitted
            } else if quota.current_pdu_sessions() >= quota.max_pdu_sessions {
                AdmissionResult::RejectedQuotaExceeded
            } else {
                quota.pdu_sessions.insert(session_key.to_string());
                AdmissionResult::Admitted
            }
        };
        if result == AdmissionResult::Admitted {
            self.save_state();
        }
        result
    }

    pub fn release_pdu_session(&self, s_nssai: &SNssai, session_key: &str) -> bool {
        let Some(id) = self.quota_id_for(s_nssai) else {
            return false;
        };
        let removed = {
            let mut quota_list = match self.quota_list.write() {
                Ok(l) => l,
                Err(_) => return false,
            };
            match quota_list.get_mut(&id) {
                Some(quota) => quota.pdu_sessions.remove(session_key),
                None => false,
            }
        };
        if removed {
            self.save_state();
        }
        removed
    }

    pub fn quota_count(&self) -> usize {
        self.quota_list.read().map(|l| l.len()).unwrap_or(0)
    }

    /// Get all quota utilizations: (S-NSSAI, ue%, pdu%)
    pub fn get_utilization(&self) -> Vec<(SNssai, f64, f64)> {
        self.quota_list
            .read()
            .map(|l| {
                l.values()
                    .map(|q| (q.s_nssai.clone(), q.ue_utilization(), q.pdu_utilization()))
                    .collect()
            })
            .unwrap_or_default()
    }

    // ------------------------------------------------------------------
    // SliceEventExposure subscriptions (TS 29.536)
    // ------------------------------------------------------------------

    pub fn subscription_add(&self, sub: SacSubscription) {
        if let Ok(mut subs) = self.subscriptions.write() {
            subs.insert(sub.subscription_id.clone(), sub);
        }
    }

    pub fn subscription_remove(&self, id: &str) -> bool {
        self.subscriptions
            .write()
            .map(|mut subs| subs.remove(id).is_some())
            .unwrap_or(false)
    }

    pub fn subscription_get(&self, id: &str) -> Option<SacSubscription> {
        let sub = self.subscriptions.read().ok()?.get(id).cloned();
        sub
    }

    pub fn subscription_count(&self) -> usize {
        self.subscriptions.read().map(|s| s.len()).unwrap_or(0)
    }

    /// Subscriptions interested in `s_nssai`
    pub fn subscriptions_matching(&self, s_nssai: &SNssai) -> Vec<SacSubscription> {
        self.subscriptions
            .read()
            .map(|subs| {
                subs.values()
                    .filter(|s| s.matches_snssai(s_nssai))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    // ------------------------------------------------------------------
    // Persistence (counters survive restart when a state file is set)
    // ------------------------------------------------------------------

    pub fn set_state_file(&self, path: Option<PathBuf>) {
        if let Ok(mut f) = self.state_file.write() {
            *f = path;
        }
    }

    /// Serialize quotas + memberships to the state file (atomic tmp+rename).
    /// Best-effort: failures are logged, never fatal.
    pub fn save_state(&self) {
        // Monotonic sequence so concurrent saves use distinct tmp files (the
        // rename is atomic, so last-writer-wins yields a consistent snapshot).
        static SAVE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = match self.state_file.read() {
            Ok(p) => match p.clone() {
                Some(p) => p,
                None => return,
            },
            Err(_) => return,
        };
        let quotas: Vec<serde_json::Value> = match self.quota_list.read() {
            Ok(list) => list
                .values()
                .map(|q| {
                    serde_json::json!({
                        "id": q.id,
                        "sst": q.s_nssai.sst,
                        "sd": q.s_nssai.sd,
                        "maxUes": q.max_ues,
                        "maxPduSessions": q.max_pdu_sessions,
                        "ues": q.ues.iter().collect::<Vec<_>>(),
                        "pduSessions": q.pdu_sessions.iter().collect::<Vec<_>>(),
                        "eacActive": q.eac_active,
                    })
                })
                .collect(),
            Err(_) => return,
        };
        let state = serde_json::json!({
            "nextQuotaId": self.next_quota_id.load(Ordering::SeqCst),
            "quotas": quotas,
        });
        // Serialization above touches only in-memory RwLocks (fast). Offload the
        // BLOCKING filesystem write+rename off the async executor so a request
        // handler never stalls a tokio worker on disk I/O: when a runtime is
        // active (the request-reachable path) spawn it on the blocking pool;
        // otherwise (sync tests / non-async startup) write inline.
        let body = state.to_string();
        let seq = SAVE_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = path.with_extension(format!("tmp{seq}"));
        let write = move || {
            let result = std::fs::write(&tmp, &body).and_then(|_| std::fs::rename(&tmp, &path));
            if let Err(e) = result {
                log::warn!("Failed to persist NSACF state to {}: {e}", path.display());
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn_blocking(write);
            }
            Err(_) => write(),
        }
    }

    /// Load quotas + memberships from the state file (if present).
    pub fn load_state(&self) -> bool {
        let path = match self.state_file.read() {
            Ok(p) => match p.clone() {
                Some(p) => p,
                None => return false,
            },
            Err(_) => return false,
        };
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return false, // no state yet
        };
        let state: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("Corrupt NSACF state file {}: {e}", path.display());
                return false;
            }
        };

        let mut restored = 0usize;
        if let Some(quotas) = state.get("quotas").and_then(|v| v.as_array()) {
            for q in quotas {
                let (Some(id), Some(sst), Some(max_ues), Some(max_pdu)) = (
                    q.get("id").and_then(|v| v.as_u64()),
                    q.get("sst").and_then(|v| v.as_u64()),
                    q.get("maxUes").and_then(|v| v.as_u64()),
                    q.get("maxPduSessions").and_then(|v| v.as_u64()),
                ) else {
                    continue;
                };
                let sd = q.get("sd").and_then(|v| v.as_u64()).map(|v| v as u32);
                let s_nssai = SNssai::new(sst as u8, sd);
                let mut quota = SliceQuota::new(id, s_nssai.clone(), max_ues, max_pdu);
                if let Some(ues) = q.get("ues").and_then(|v| v.as_array()) {
                    quota.ues = ues
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                }
                if let Some(pdus) = q.get("pduSessions").and_then(|v| v.as_array()) {
                    quota.pdu_sessions = pdus
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                }
                quota.eac_active = q
                    .get("eacActive")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                if let Ok(mut list) = self.quota_list.write() {
                    list.insert(id, quota);
                }
                if let Ok(mut hash) = self.snssai_hash.write() {
                    hash.insert((s_nssai.sst, s_nssai.sd), id);
                }
                restored += 1;
            }
        }
        if let Some(next) = state.get("nextQuotaId").and_then(|v| v.as_u64()) {
            self.next_quota_id.store(next as usize, Ordering::SeqCst);
        }
        if restored > 0 {
            log::info!("Restored {restored} slice quota(s) from {}", path.display());
        }
        restored > 0
    }
}

/// Update the quota's EAC flag against the threshold; returns the transition
/// (if any). Must be called with the quota mutably borrowed.
fn update_eac(quota: &mut SliceQuota, threshold_percent: u8) -> Option<EacTransition> {
    if quota.max_ues == 0 {
        return None;
    }
    let should_be_active = quota.current_ues() * 100 >= quota.max_ues * threshold_percent as u64;
    if should_be_active != quota.eac_active {
        quota.eac_active = should_be_active;
        Some(EacTransition {
            s_nssai: quota.s_nssai.clone(),
            activated: should_be_active,
        })
    } else {
        None
    }
}

impl Default for NsacfContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global NSACF context (thread-safe singleton)
static GLOBAL_NSACF_CONTEXT: std::sync::OnceLock<Arc<RwLock<NsacfContext>>> =
    std::sync::OnceLock::new();

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
    fn test_admit_ue_success_and_idempotent() {
        let mut ctx = NsacfContext::new();
        ctx.init(64);

        let s_nssai = SNssai::new(1, None);
        ctx.quota_add(s_nssai.clone(), 100, 500);

        let (result, _) = ctx.admit_ue(&s_nssai, "imsi-1");
        assert_eq!(result, AdmissionResult::Admitted);
        // Same SUPI again: idempotent, still counted once
        let (result, _) = ctx.admit_ue(&s_nssai, "imsi-1");
        assert_eq!(result, AdmissionResult::Admitted);
        assert_eq!(ctx.quota_find_by_snssai(&s_nssai).unwrap().current_ues(), 1);
    }

    #[test]
    fn test_admit_ue_quota_exceeded() {
        let mut ctx = NsacfContext::new();
        ctx.init(64);

        let s_nssai = SNssai::new(2, None);
        ctx.quota_add(s_nssai.clone(), 2, 10);

        assert_eq!(
            ctx.admit_ue(&s_nssai, "imsi-1").0,
            AdmissionResult::Admitted
        );
        assert_eq!(
            ctx.admit_ue(&s_nssai, "imsi-2").0,
            AdmissionResult::Admitted
        );
        assert_eq!(
            ctx.admit_ue(&s_nssai, "imsi-3").0,
            AdmissionResult::RejectedQuotaExceeded
        );
        // imsi-1 was already admitted: not rejected
        assert_eq!(
            ctx.admit_ue(&s_nssai, "imsi-1").0,
            AdmissionResult::Admitted
        );
    }

    #[test]
    fn test_admit_ue_not_available() {
        let mut ctx = NsacfContext::new();
        ctx.init(64);

        let s_nssai = SNssai::new(99, None);
        let (result, _) = ctx.admit_ue(&s_nssai, "imsi-1");
        assert_eq!(result, AdmissionResult::RejectedSliceNotAvailable);
    }

    #[test]
    fn test_release_ue() {
        let mut ctx = NsacfContext::new();
        ctx.init(64);

        let s_nssai = SNssai::new(3, None);
        ctx.quota_add(s_nssai.clone(), 2, 10);

        ctx.admit_ue(&s_nssai, "imsi-1");
        ctx.admit_ue(&s_nssai, "imsi-2");
        assert_eq!(
            ctx.admit_ue(&s_nssai, "imsi-3").0,
            AdmissionResult::RejectedQuotaExceeded
        );

        ctx.release_ue(&s_nssai, "imsi-2");
        assert_eq!(
            ctx.admit_ue(&s_nssai, "imsi-3").0,
            AdmissionResult::Admitted
        );
    }

    #[test]
    fn test_pdu_session_admission() {
        let mut ctx = NsacfContext::new();
        ctx.init(64);

        let s_nssai = SNssai::new(4, None);
        ctx.quota_add(s_nssai.clone(), 10, 2);

        assert_eq!(
            ctx.admit_pdu_session(&s_nssai, "imsi-1:1"),
            AdmissionResult::Admitted
        );
        // idempotent
        assert_eq!(
            ctx.admit_pdu_session(&s_nssai, "imsi-1:1"),
            AdmissionResult::Admitted
        );
        assert_eq!(
            ctx.admit_pdu_session(&s_nssai, "imsi-1:2"),
            AdmissionResult::Admitted
        );
        assert_eq!(
            ctx.admit_pdu_session(&s_nssai, "imsi-2:1"),
            AdmissionResult::RejectedQuotaExceeded
        );
        assert!(ctx.release_pdu_session(&s_nssai, "imsi-1:2"));
        assert_eq!(
            ctx.admit_pdu_session(&s_nssai, "imsi-2:1"),
            AdmissionResult::Admitted
        );
    }

    #[test]
    fn test_eac_threshold_crossing() {
        let mut ctx = NsacfContext::new();
        ctx.init(64);
        ctx.set_eac_threshold(80);

        let s_nssai = SNssai::new(5, None);
        ctx.quota_add(s_nssai.clone(), 10, 100);

        // 1..=7 admissions: below 80% threshold, no transition
        for i in 1..=7 {
            let (_, eac) = ctx.admit_ue(&s_nssai, &format!("imsi-{i}"));
            assert!(eac.is_none(), "no EAC transition expected at {i}/10");
        }
        // 8th admission: 80% reached -> EAC activated
        let (_, eac) = ctx.admit_ue(&s_nssai, "imsi-8");
        assert_eq!(
            eac,
            Some(EacTransition {
                s_nssai: s_nssai.clone(),
                activated: true
            })
        );
        // 9th: still active, no new transition
        let (_, eac) = ctx.admit_ue(&s_nssai, "imsi-9");
        assert!(eac.is_none());
        // release back below threshold -> deactivated
        let eac = ctx.release_ue(&s_nssai, "imsi-9");
        assert!(eac.is_none(), "8/10 still at threshold");
        let eac = ctx.release_ue(&s_nssai, "imsi-8");
        assert_eq!(
            eac,
            Some(EacTransition {
                s_nssai: s_nssai.clone(),
                activated: false
            })
        );
    }

    #[test]
    fn test_state_persistence_roundtrip() {
        let path =
            std::env::temp_dir().join(format!("nsacf-state-test-{}.json", uuid::Uuid::new_v4()));

        let mut ctx = NsacfContext::new();
        ctx.init(64);
        ctx.set_state_file(Some(path.clone()));

        let s_nssai = SNssai::new(6, Some(0x0A0B0C));
        ctx.quota_add(s_nssai.clone(), 5, 10);
        ctx.admit_ue(&s_nssai, "imsi-100");
        ctx.admit_ue(&s_nssai, "imsi-101");
        ctx.admit_pdu_session(&s_nssai, "imsi-100:1");

        // Simulate restart: fresh context restores from the state file
        let mut ctx2 = NsacfContext::new();
        ctx2.init(64);
        ctx2.set_state_file(Some(path.clone()));
        assert!(ctx2.load_state());

        let quota = ctx2.quota_find_by_snssai(&s_nssai).expect("quota restored");
        assert_eq!(quota.max_ues, 5);
        assert_eq!(quota.current_ues(), 2);
        assert_eq!(quota.current_pdu_sessions(), 1);
        // Membership survives: re-admitting an existing SUPI is idempotent
        assert_eq!(
            ctx2.admit_ue(&s_nssai, "imsi-100").0,
            AdmissionResult::Admitted
        );
        assert_eq!(
            ctx2.quota_find_by_snssai(&s_nssai).unwrap().current_ues(),
            2
        );

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_save_state_offloads_under_runtime() {
        // Under a tokio runtime, save_state() offloads the file write to the
        // blocking pool (fire-and-forget) instead of blocking the worker.
        // Confirm the state still lands and reloads correctly.
        let path = std::env::temp_dir()
            .join(format!("nsacf-state-async-{}.json", uuid::Uuid::new_v4()));
        let mut ctx = NsacfContext::new();
        ctx.init(64);
        ctx.set_state_file(Some(path.clone()));

        let s_nssai = SNssai::new(6, Some(0x0A0B0C));
        ctx.quota_add(s_nssai.clone(), 5, 10); // triggers an offloaded save_state

        // The blocking write runs on the pool; poll briefly for it to land.
        let mut persisted = false;
        for _ in 0..100 {
            if path.exists() {
                persisted = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(persisted, "save_state must persist under a tokio runtime");

        let mut ctx2 = NsacfContext::new();
        ctx2.init(64);
        ctx2.set_state_file(Some(path.clone()));
        assert!(ctx2.load_state());
        assert_eq!(
            ctx2.quota_find_by_snssai(&s_nssai).expect("restored").max_ues,
            5
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_subscription_store_and_matching() {
        let mut ctx = NsacfContext::new();
        ctx.init(64);

        ctx.subscription_add(SacSubscription {
            subscription_id: "s1".to_string(),
            notification_uri: "http://127.0.0.1:1/cb".to_string(),
            events: vec!["NUM_OF_REGISTERED_UES".to_string()],
            snssais: vec![SNssai::new(1, None)],
            expiry: None,
        });
        ctx.subscription_add(SacSubscription {
            subscription_id: "s2".to_string(),
            notification_uri: "http://127.0.0.1:1/cb".to_string(),
            events: vec![],
            snssais: vec![], // all slices
            expiry: None,
        });

        assert_eq!(ctx.subscriptions_matching(&SNssai::new(1, None)).len(), 2);
        assert_eq!(ctx.subscriptions_matching(&SNssai::new(2, None)).len(), 1);
        assert!(ctx.subscription_remove("s1"));
        assert!(!ctx.subscription_remove("s1"));
    }

    #[test]
    fn test_snssai_path_segment() {
        assert_eq!(SNssai::from_path_segment("1"), Some(SNssai::new(1, None)));
        assert_eq!(
            SNssai::from_path_segment("2-0a0b0c"),
            Some(SNssai::new(2, Some(0x0A0B0C)))
        );
        assert_eq!(SNssai::from_path_segment("bogus"), None);
        assert_eq!(SNssai::from_path_segment("1-zz"), None);
    }

    #[test]
    fn test_ue_utilization() {
        let mut quota = SliceQuota::new(1, SNssai::new(1, None), 100, 500);
        assert_eq!(quota.ue_utilization(), 0.0);

        quota.ues.insert("imsi-1".to_string());
        quota.ues.insert("imsi-2".to_string());
        assert!((quota.ue_utilization() - 2.0).abs() < 0.01);
    }
}
