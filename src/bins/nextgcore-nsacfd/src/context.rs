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

    /// Canonical string key for this S-NSSAI: `{sst}` or `{sst}-{sd-hex}`.
    /// Used as the `eacModeList` map key (TS 29.536 §6.1.6.2.4) and as the
    /// per-access membership-map key. Round-trips with [`from_path_segment`].
    pub fn to_key(&self) -> String {
        match self.sd {
            Some(sd) => format!("{}-{sd:06x}", self.sst),
            None => format!("{}", self.sst),
        }
    }
}

/// Access type (TS 29.571 AccessType) used for per-access-type slice admission
/// counting (TS 29.536 §6.1.6.2.9/.10). Only the two NSAC-relevant values are
/// modelled; an absent/unknown `anType` defaults to 3GPP access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessType {
    /// 3GPP_ACCESS
    ThreeGpp,
    /// NON_3GPP_ACCESS
    NonThreeGpp,
}

impl AccessType {
    /// Map an optional `anType` string to an [`AccessType`], defaulting to
    /// 3GPP access when absent or unrecognised (nsacf-05 accept-and-default).
    pub fn from_an_type(s: Option<&str>) -> AccessType {
        match s {
            Some("NON_3GPP_ACCESS") => AccessType::NonThreeGpp,
            _ => AccessType::ThreeGpp,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            AccessType::ThreeGpp => "3GPP_ACCESS",
            AccessType::NonThreeGpp => "NON_3GPP_ACCESS",
        }
    }

    pub fn is_3gpp(self) -> bool {
        matches!(self, AccessType::ThreeGpp)
    }
}

/// Optional per-access-type ceilings for a slice quota (TS 29.536 §6.1.6.2.9
/// procedural text). All `None` => aggregate-only counting (legacy path
/// unchanged); a `Some` ceiling enables per-access enforcement for that access.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AccessLimits {
    pub max_ues_3gpp: Option<u64>,
    pub max_ues_n3gpp: Option<u64>,
    pub max_pdu_3gpp: Option<u64>,
    pub max_pdu_n3gpp: Option<u64>,
}

/// Outcome of a DECREASE (release) operation (nsacf-10). Distinguishes a clean
/// release from an idempotent no-op (member already absent) and from an
/// S-NSSAI that is not NSAC-subject (no quota configured).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseOutcome {
    /// Member was present and removed; carries any EAC mode transition.
    Released(Option<EacTransition>),
    /// S-NSSAI is NSAC-subject but the member/session was not present.
    MemberAbsent,
    /// S-NSSAI is not NSAC-subject (no quota configured for it).
    SliceNotFound,
}

/// Outcome of an UPDATE (access-type move) operation (nsacf-06).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// Entry located; its access type is now `new_access` (idempotent).
    Updated,
    /// S-NSSAI not NSAC-subject, or the member/session is not present.
    NotFound,
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
    /// Rejected - aggregate slice quota exceeded
    RejectedQuotaExceeded,
    /// Rejected - the per-access-type ceiling for this access is exceeded
    /// (aggregate may still have room). Selects the `_3GPP`/`_N3GPP` reason.
    RejectedQuotaExceededPerAccess(AccessType),
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
    /// Maximum number of UEs allowed in this slice (aggregate over accesses)
    pub max_ues: u64,
    /// Maximum number of PDU sessions allowed in this slice (aggregate)
    pub max_pdu_sessions: u64,
    /// Optional per-access-type UE ceiling for 3GPP access (nsacf-05)
    pub max_ues_3gpp: Option<u64>,
    /// Optional per-access-type UE ceiling for non-3GPP access (nsacf-05)
    pub max_ues_n3gpp: Option<u64>,
    /// Optional per-access-type PDU-session ceiling for 3GPP access
    pub max_pdu_3gpp: Option<u64>,
    /// Optional per-access-type PDU-session ceiling for non-3GPP access
    pub max_pdu_n3gpp: Option<u64>,
    /// Registered UE identities (SUPIs)
    pub(crate) ues: HashSet<String>,
    /// Established PDU session keys (`{supi}:{pduSessionId}`)
    pub(crate) pdu_sessions: HashSet<String>,
    /// Per-member access type for registered UEs (nsacf-05/06). Always kept in
    /// sync with `ues`; lets per-access counts be derived and UPDATE move a UE
    /// between 3GPP/N3GPP buckets without changing the aggregate count.
    pub(crate) ue_access: HashMap<String, AccessType>,
    /// Per-session access type for established PDU sessions (nsacf-05/06).
    pub(crate) pdu_access: HashMap<String, AccessType>,
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
            max_ues_3gpp: None,
            max_ues_n3gpp: None,
            max_pdu_3gpp: None,
            max_pdu_n3gpp: None,
            ues: HashSet::new(),
            pdu_sessions: HashSet::new(),
            ue_access: HashMap::new(),
            pdu_access: HashMap::new(),
            eac_active: false,
        }
    }

    /// Apply optional per-access-type ceilings (nsacf-05).
    pub fn with_access_limits(mut self, limits: AccessLimits) -> Self {
        self.max_ues_3gpp = limits.max_ues_3gpp;
        self.max_ues_n3gpp = limits.max_ues_n3gpp;
        self.max_pdu_3gpp = limits.max_pdu_3gpp;
        self.max_pdu_n3gpp = limits.max_pdu_n3gpp;
        self
    }

    pub fn current_ues(&self) -> u64 {
        self.ues.len() as u64
    }

    pub fn current_pdu_sessions(&self) -> u64 {
        self.pdu_sessions.len() as u64
    }

    /// Registered UE count for a single access type (nsacf-05).
    pub fn current_ues_access(&self, access: AccessType) -> u64 {
        self.ue_access.values().filter(|a| **a == access).count() as u64
    }

    /// Established PDU-session count for a single access type (nsacf-05).
    pub fn current_pdu_access(&self, access: AccessType) -> u64 {
        self.pdu_access.values().filter(|a| **a == access).count() as u64
    }

    /// The configured per-access UE ceiling for `access`, if any.
    pub fn max_ues_for(&self, access: AccessType) -> Option<u64> {
        match access {
            AccessType::ThreeGpp => self.max_ues_3gpp,
            AccessType::NonThreeGpp => self.max_ues_n3gpp,
        }
    }

    /// The configured per-access PDU-session ceiling for `access`, if any.
    pub fn max_pdu_for(&self, access: AccessType) -> Option<u64> {
        match access {
            AccessType::ThreeGpp => self.max_pdu_3gpp,
            AccessType::NonThreeGpp => self.max_pdu_n3gpp,
        }
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
            max_ues_3gpp: self.max_ues_3gpp,
            max_ues_n3gpp: self.max_ues_n3gpp,
            max_pdu_3gpp: self.max_pdu_3gpp,
            max_pdu_n3gpp: self.max_pdu_n3gpp,
            ues: self.ues.clone(),
            pdu_sessions: self.pdu_sessions.clone(),
            ue_access: self.ue_access.clone(),
            pdu_access: self.pdu_access.clone(),
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
    /// EAC implicit subscriptions: AMF nfId -> eacNotificationUri (TS 29.536 §5.2.2.3.2)
    eac_subscriptions: RwLock<HashMap<String, String>>,
    /// Next quota ID generator
    next_quota_id: AtomicUsize,
    /// Maximum number of slice quotas
    max_quotas: usize,
    /// EAC activation threshold in percent of max UEs (TS 23.502 §4.2.9.5)
    eac_threshold_percent: RwLock<u8>,
    /// Optional persistence path; counters survive restarts when set
    state_file: RwLock<Option<PathBuf>>,
    /// Issue #66: set when `load_state` could not read the snapshot. While set,
    /// `save_state` REFUSES to write, so an unreadable file is never replaced by
    /// the empty quota set that failing to read it produced.
    state_unreadable: std::sync::atomic::AtomicBool,
    /// Context initialized flag
    initialized: AtomicBool,
}

impl NsacfContext {
    pub fn new() -> Self {
        Self {
            quota_list: RwLock::new(HashMap::new()),
            snssai_hash: RwLock::new(HashMap::new()),
            subscriptions: RwLock::new(HashMap::new()),
            eac_subscriptions: RwLock::new(HashMap::new()),
            next_quota_id: AtomicUsize::new(1),
            max_quotas: 0,
            eac_threshold_percent: RwLock::new(80),
            state_file: RwLock::new(None),
            state_unreadable: std::sync::atomic::AtomicBool::new(false),
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
        if let Ok(mut eac) = self.eac_subscriptions.write() {
            eac.clear();
        }
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("NSACF context finalized");
    }

    /// Register (or replace) an EAC notification callback for an AMF nfId.
    pub fn eac_subscription_set(&self, nf_id: &str, uri: &str) {
        if let Ok(mut m) = self.eac_subscriptions.write() {
            m.insert(nf_id.to_string(), uri.to_string());
        }
    }

    /// Remove the EAC notification callback for an AMF nfId (null unsubscribe).
    pub fn eac_subscription_remove(&self, nf_id: &str) -> bool {
        self.eac_subscriptions
            .write()
            .map(|mut m| m.remove(nf_id).is_some())
            .unwrap_or(false)
    }

    /// All registered EAC notification callback URIs.
    pub fn eac_notification_uris(&self) -> Vec<String> {
        self.eac_subscriptions
            .read()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
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
        self.quota_add_with_limits(s_nssai, max_ues, max_pdu_sessions, AccessLimits::default())
    }

    /// Add a slice quota carrying optional per-access-type ceilings (nsacf-05).
    /// `AccessLimits::default()` (all `None`) yields the legacy aggregate-only
    /// quota, so [`quota_add`] is just the no-per-access spelling of this.
    pub fn quota_add_with_limits(
        &self,
        s_nssai: SNssai,
        max_ues: u64,
        max_pdu_sessions: u64,
        limits: AccessLimits,
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
            let quota = SliceQuota::new(id, s_nssai.clone(), max_ues, max_pdu_sessions)
                .with_access_limits(limits);
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

    /// Update an existing quota's ceilings in place (preserving memberships),
    /// or create it if absent (nsacf-08 LocalConfigurations update).
    pub fn quota_update_or_add(
        &self,
        s_nssai: SNssai,
        max_ues: u64,
        max_pdu_sessions: u64,
        limits: AccessLimits,
    ) -> Option<SliceQuota> {
        if let Some(id) = self.quota_id_for(&s_nssai) {
            let updated = {
                let mut quota_list = self.quota_list.write().ok()?;
                let quota = quota_list.get_mut(&id)?;
                quota.max_ues = max_ues;
                quota.max_pdu_sessions = max_pdu_sessions;
                quota.max_ues_3gpp = limits.max_ues_3gpp;
                quota.max_ues_n3gpp = limits.max_ues_n3gpp;
                quota.max_pdu_3gpp = limits.max_pdu_3gpp;
                quota.max_pdu_n3gpp = limits.max_pdu_n3gpp;
                quota.clone()
            };
            self.save_state();
            Some(updated)
        } else {
            self.quota_add_with_limits(s_nssai, max_ues, max_pdu_sessions, limits)
        }
    }

    fn quota_id_for(&self, s_nssai: &SNssai) -> Option<u64> {
        // Copy the id and drop the hash guard before any other lock is taken
        let hash = self.snssai_hash.read().ok()?;
        // An SD-specific quota takes precedence.
        if let Some(id) = hash.get(&(s_nssai.sst, s_nssai.sd)).copied() {
            return Some(id);
        }
        // Fall back to an SST-wide quota (provisioned with no SD): a per-SST
        // quota caps all SDs of that SST when no SD-specific quota exists. This
        // also absorbs the "no SD" vs SD=0x000000 S-NSSAI representation some
        // NAS encoders emit (TS 23.003 §28.4 — SD is optional). A genuinely
        // unconfigured SST still returns None and is rejected as before.
        if s_nssai.sd.is_some() {
            return hash.get(&(s_nssai.sst, None)).copied();
        }
        None
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
    /// `an_type` selects the per-access bucket and, on a per-access ceiling
    /// breach, drives the `_3GPP`/`_N3GPP` failure reason (nsacf-05).
    pub fn admit_ue(
        &self,
        s_nssai: &SNssai,
        supi: &str,
        an_type: AccessType,
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
            // Per-access ceiling breached (only when a ceiling is configured for
            // this access). Aggregate is checked first so it keeps the plain
            // reason; per-access selects the _3GPP/_N3GPP reason.
            let over_per_access = quota
                .max_ues_for(an_type)
                .is_some_and(|max| quota.current_ues_access(an_type) >= max);
            if quota.ues.contains(supi) {
                // Already counted; INCREASE is idempotent per TS 29.536
                (AdmissionResult::Admitted, None)
            } else if quota.current_ues() >= quota.max_ues {
                (AdmissionResult::RejectedQuotaExceeded, None)
            } else if over_per_access {
                (
                    AdmissionResult::RejectedQuotaExceededPerAccess(an_type),
                    None,
                )
            } else {
                quota.ues.insert(supi.to_string());
                quota.ue_access.insert(supi.to_string(), an_type);
                let eac = update_eac(quota, threshold);
                (AdmissionResult::Admitted, eac)
            }
        };
        if result.0 == AdmissionResult::Admitted {
            self.save_state();
        }
        result
    }

    /// Release a UE (updateFlag DECREASE). Distinguishes a clean release from
    /// an idempotent no-op and from an S-NSSAI that is not NSAC-subject
    /// (nsacf-10). Carries the EAC transition when the count falls back below
    /// the threshold.
    pub fn release_ue(&self, s_nssai: &SNssai, supi: &str) -> ReleaseOutcome {
        let Some(id) = self.quota_id_for(s_nssai) else {
            return ReleaseOutcome::SliceNotFound;
        };
        let threshold = self.eac_threshold();
        let outcome = {
            let mut quota_list = match self.quota_list.write() {
                Ok(l) => l,
                Err(_) => return ReleaseOutcome::SliceNotFound,
            };
            let Some(quota) = quota_list.get_mut(&id) else {
                return ReleaseOutcome::SliceNotFound;
            };
            if !quota.ues.remove(supi) {
                ReleaseOutcome::MemberAbsent
            } else {
                quota.ue_access.remove(supi);
                ReleaseOutcome::Released(update_eac(quota, threshold))
            }
        };
        if matches!(outcome, ReleaseOutcome::Released(_)) {
            self.save_state();
        }
        outcome
    }

    /// Move a UE between access-type buckets (updateFlag UPDATE, nsacf-06). The
    /// aggregate count is unchanged (no double-count); only the per-access
    /// bucket moves. `NotFound` when the S-NSSAI is not NSAC-subject or the UE
    /// is not a member.
    pub fn update_ue_access(
        &self,
        s_nssai: &SNssai,
        supi: &str,
        new_access: AccessType,
    ) -> UpdateOutcome {
        let Some(id) = self.quota_id_for(s_nssai) else {
            return UpdateOutcome::NotFound;
        };
        let changed = {
            let mut quota_list = match self.quota_list.write() {
                Ok(l) => l,
                Err(_) => return UpdateOutcome::NotFound,
            };
            let Some(quota) = quota_list.get_mut(&id) else {
                return UpdateOutcome::NotFound;
            };
            if !quota.ues.contains(supi) {
                return UpdateOutcome::NotFound;
            }
            quota.ue_access.insert(supi.to_string(), new_access) != Some(new_access)
        };
        if changed {
            self.save_state();
        }
        UpdateOutcome::Updated
    }

    // ------------------------------------------------------------------
    // PDU session admission control (TS 29.536 NumOfPDUsUpdate)
    // ------------------------------------------------------------------

    pub fn admit_pdu_session(
        &self,
        s_nssai: &SNssai,
        session_key: &str,
        an_type: AccessType,
    ) -> AdmissionResult {
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
            let over_per_access = quota
                .max_pdu_for(an_type)
                .is_some_and(|max| quota.current_pdu_access(an_type) >= max);
            if quota.pdu_sessions.contains(session_key) {
                AdmissionResult::Admitted
            } else if quota.current_pdu_sessions() >= quota.max_pdu_sessions {
                AdmissionResult::RejectedQuotaExceeded
            } else if over_per_access {
                AdmissionResult::RejectedQuotaExceededPerAccess(an_type)
            } else {
                quota.pdu_sessions.insert(session_key.to_string());
                quota.pdu_access.insert(session_key.to_string(), an_type);
                AdmissionResult::Admitted
            }
        };
        if result == AdmissionResult::Admitted {
            self.save_state();
        }
        result
    }

    /// Release a PDU session (DECREASE). Mirrors [`release_ue`] (nsacf-10):
    /// clean release vs idempotent member-absent vs slice-not-NSAC-subject.
    pub fn release_pdu_session(&self, s_nssai: &SNssai, session_key: &str) -> ReleaseOutcome {
        let Some(id) = self.quota_id_for(s_nssai) else {
            return ReleaseOutcome::SliceNotFound;
        };
        let outcome = {
            let mut quota_list = match self.quota_list.write() {
                Ok(l) => l,
                Err(_) => return ReleaseOutcome::SliceNotFound,
            };
            let Some(quota) = quota_list.get_mut(&id) else {
                return ReleaseOutcome::SliceNotFound;
            };
            if quota.pdu_sessions.remove(session_key) {
                quota.pdu_access.remove(session_key);
                ReleaseOutcome::Released(None)
            } else {
                ReleaseOutcome::MemberAbsent
            }
        };
        if matches!(outcome, ReleaseOutcome::Released(_)) {
            self.save_state();
        }
        outcome
    }

    /// Move a PDU session between access-type buckets (UPDATE, nsacf-06).
    pub fn update_pdu_access(
        &self,
        s_nssai: &SNssai,
        session_key: &str,
        new_access: AccessType,
    ) -> UpdateOutcome {
        let Some(id) = self.quota_id_for(s_nssai) else {
            return UpdateOutcome::NotFound;
        };
        let changed = {
            let mut quota_list = match self.quota_list.write() {
                Ok(l) => l,
                Err(_) => return UpdateOutcome::NotFound,
            };
            let Some(quota) = quota_list.get_mut(&id) else {
                return UpdateOutcome::NotFound;
            };
            if !quota.pdu_sessions.contains(session_key) {
                return UpdateOutcome::NotFound;
            }
            quota.pdu_access.insert(session_key.to_string(), new_access) != Some(new_access)
        };
        if changed {
            self.save_state();
        }
        UpdateOutcome::Updated
    }

    pub fn quota_count(&self) -> usize {
        self.quota_list.read().map(|l| l.len()).unwrap_or(0)
    }

    /// Snapshot of every configured slice quota (nsacf-08 roaming-quotas query).
    pub fn quotas_snapshot(&self) -> Vec<SliceQuota> {
        self.quota_list
            .read()
            .map(|l| l.values().cloned().collect())
            .unwrap_or_default()
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
        // Issue #66: a failed load left the quota set EMPTY, so writing now would
        // replace the unreadable file with nothing and make the loss permanent.
        if self
            .state_unreadable
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            log::error!(
                "NSACF refusing to persist to {}: its previous contents could not be read, \
                 and overwriting them with the current (empty) state would make the loss \
                 permanent. Move the file aside to start fresh.",
                path.display()
            );
            return;
        }
        let quotas: Vec<serde_json::Value> = match self.quota_list.read() {
            Ok(list) => list
                .values()
                .map(|q| {
                    // Per-access membership maps (nsacf-05); absent in legacy
                    // state files, so load_state defaults them to 3GPP access.
                    let ues_access: serde_json::Map<String, serde_json::Value> = q
                        .ue_access
                        .iter()
                        .map(|(k, v)| {
                            (k.clone(), serde_json::Value::String(v.as_str().to_string()))
                        })
                        .collect();
                    let pdu_access: serde_json::Map<String, serde_json::Value> = q
                        .pdu_access
                        .iter()
                        .map(|(k, v)| {
                            (k.clone(), serde_json::Value::String(v.as_str().to_string()))
                        })
                        .collect();
                    serde_json::json!({
                        "id": q.id,
                        "sst": q.s_nssai.sst,
                        "sd": q.s_nssai.sd,
                        "maxUes": q.max_ues,
                        "maxPduSessions": q.max_pdu_sessions,
                        "maxUes3gpp": q.max_ues_3gpp,
                        "maxUesN3gpp": q.max_ues_n3gpp,
                        "maxPdu3gpp": q.max_pdu_3gpp,
                        "maxPduN3gpp": q.max_pdu_n3gpp,
                        "ues": q.ues.iter().collect::<Vec<_>>(),
                        "pduSessions": q.pdu_sessions.iter().collect::<Vec<_>>(),
                        "uesAccess": serde_json::Value::Object(ues_access),
                        "pduSessionsAccess": serde_json::Value::Object(pdu_access),
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
        // The shared writer (issue #66) does the serialise + temp + fsync +
        // rename, so the per-save sequence that used to name the temp file is no
        // longer needed -- it derives a non-colliding name itself.
        let _ = SAVE_SEQ.fetch_add(1, Ordering::Relaxed);
        let write = move || {
            if let Err(e) = nextgcore_core::state_store::write_snapshot(&path, &state) {
                log::warn!("Failed to persist NSACF state: {e}");
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
        let state: serde_json::Value = match nextgcore_core::state_store::read_snapshot(&path) {
            Ok(Some(v)) => v,
            // No file yet: a first boot, not a problem.
            Ok(None) => return false,
            // Issue #66: unreadable or malformed. This used to return false and
            // let the next save_state rewrite the file from the empty quota set,
            // making the loss permanent. Mark it so save_state refuses instead.
            Err(e) => {
                log::error!(
                    "NSACF state load failed, starting EMPTY and refusing to overwrite the \
                     file: {e}"
                );
                self.state_unreadable
                    .store(true, std::sync::atomic::Ordering::Relaxed);
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
                // Optional per-access ceilings (nsacf-05); absent in legacy files.
                quota.max_ues_3gpp = q.get("maxUes3gpp").and_then(|v| v.as_u64());
                quota.max_ues_n3gpp = q.get("maxUesN3gpp").and_then(|v| v.as_u64());
                quota.max_pdu_3gpp = q.get("maxPdu3gpp").and_then(|v| v.as_u64());
                quota.max_pdu_n3gpp = q.get("maxPduN3gpp").and_then(|v| v.as_u64());
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
                // Reconcile per-access membership maps with the aggregate sets.
                // Legacy state files have no `uesAccess`/`pduSessionsAccess`, so
                // every member defaults to 3GPP access (backward-compatible).
                let ues_access = q.get("uesAccess").and_then(|v| v.as_object());
                for supi in quota.ues.iter().cloned().collect::<Vec<_>>() {
                    let at = ues_access
                        .and_then(|m| m.get(&supi))
                        .and_then(|v| v.as_str())
                        .map(|s| AccessType::from_an_type(Some(s)))
                        .unwrap_or(AccessType::ThreeGpp);
                    quota.ue_access.insert(supi, at);
                }
                let pdu_access = q.get("pduSessionsAccess").and_then(|v| v.as_object());
                for key in quota.pdu_sessions.iter().cloned().collect::<Vec<_>>() {
                    let at = pdu_access
                        .and_then(|m| m.get(&key))
                        .and_then(|v| v.as_str())
                        .map(|s| AccessType::from_an_type(Some(s)))
                        .unwrap_or(AccessType::ThreeGpp);
                    quota.pdu_access.insert(key, at);
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

        let (result, _) = ctx.admit_ue(&s_nssai, "imsi-1", AccessType::ThreeGpp);
        assert_eq!(result, AdmissionResult::Admitted);
        // Same SUPI again: idempotent, still counted once
        let (result, _) = ctx.admit_ue(&s_nssai, "imsi-1", AccessType::ThreeGpp);
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
            ctx.admit_ue(&s_nssai, "imsi-1", AccessType::ThreeGpp).0,
            AdmissionResult::Admitted
        );
        assert_eq!(
            ctx.admit_ue(&s_nssai, "imsi-2", AccessType::ThreeGpp).0,
            AdmissionResult::Admitted
        );
        assert_eq!(
            ctx.admit_ue(&s_nssai, "imsi-3", AccessType::ThreeGpp).0,
            AdmissionResult::RejectedQuotaExceeded
        );
        // imsi-1 was already admitted: not rejected
        assert_eq!(
            ctx.admit_ue(&s_nssai, "imsi-1", AccessType::ThreeGpp).0,
            AdmissionResult::Admitted
        );
    }

    #[test]
    fn test_admit_pdu_sst_wide_quota_matches_sd_specific_request() {
        // A quota provisioned SST-only (no SD) must cover a PDU-session request
        // for that SST carrying SD=0x000000 (the "no SD" value some NAS encoders
        // emit). Regression for the E2E data-plane break where an SST:1 quota
        // failed to match an SST:1/SD:000000 admission and wrongly returned 403.
        let mut ctx = NsacfContext::new();
        ctx.init(64);
        ctx.quota_add(SNssai::new(1, None), 100, 500);

        // Request carries SD=0 → falls back to the SST-wide quota → admitted.
        let with_sd = SNssai::new(1, Some(0));
        assert_eq!(
            ctx.admit_pdu_session(&with_sd, "imsi-1:1", AccessType::ThreeGpp),
            AdmissionResult::Admitted
        );
        // A genuinely unconfigured SST is still rejected (not-subject semantic).
        assert_eq!(
            ctx.admit_pdu_session(&SNssai::new(99, Some(0)), "imsi-1:2", AccessType::ThreeGpp),
            AdmissionResult::RejectedSliceNotAvailable
        );
    }

    #[test]
    fn test_admit_ue_not_available() {
        let mut ctx = NsacfContext::new();
        ctx.init(64);

        let s_nssai = SNssai::new(99, None);
        let (result, _) = ctx.admit_ue(&s_nssai, "imsi-1", AccessType::ThreeGpp);
        assert_eq!(result, AdmissionResult::RejectedSliceNotAvailable);
    }

    #[test]
    fn test_release_ue() {
        let mut ctx = NsacfContext::new();
        ctx.init(64);

        let s_nssai = SNssai::new(3, None);
        ctx.quota_add(s_nssai.clone(), 2, 10);

        ctx.admit_ue(&s_nssai, "imsi-1", AccessType::ThreeGpp);
        ctx.admit_ue(&s_nssai, "imsi-2", AccessType::ThreeGpp);
        assert_eq!(
            ctx.admit_ue(&s_nssai, "imsi-3", AccessType::ThreeGpp).0,
            AdmissionResult::RejectedQuotaExceeded
        );

        // Releasing imsi-2 frees a slot (the EAC transition, if any, is
        // incidental to this test).
        assert!(matches!(
            ctx.release_ue(&s_nssai, "imsi-2"),
            ReleaseOutcome::Released(_)
        ));
        assert_eq!(
            ctx.admit_ue(&s_nssai, "imsi-3", AccessType::ThreeGpp).0,
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
            ctx.admit_pdu_session(&s_nssai, "imsi-1:1", AccessType::ThreeGpp),
            AdmissionResult::Admitted
        );
        // idempotent
        assert_eq!(
            ctx.admit_pdu_session(&s_nssai, "imsi-1:1", AccessType::ThreeGpp),
            AdmissionResult::Admitted
        );
        assert_eq!(
            ctx.admit_pdu_session(&s_nssai, "imsi-1:2", AccessType::ThreeGpp),
            AdmissionResult::Admitted
        );
        assert_eq!(
            ctx.admit_pdu_session(&s_nssai, "imsi-2:1", AccessType::ThreeGpp),
            AdmissionResult::RejectedQuotaExceeded
        );
        assert_eq!(
            ctx.release_pdu_session(&s_nssai, "imsi-1:2"),
            ReleaseOutcome::Released(None)
        );
        assert_eq!(
            ctx.admit_pdu_session(&s_nssai, "imsi-2:1", AccessType::ThreeGpp),
            AdmissionResult::Admitted
        );
    }

    #[test]
    fn test_eac_subscription_set_and_null_unsubscribe() {
        // TS 29.536 §5.2.2.3.2: a value registers the EAC callback keyed by nfId;
        // an explicit null (modeled as eac_subscription_remove) unsubscribes.
        let ctx = NsacfContext::new();
        ctx.eac_subscription_set("amf-1", "http://amf-1/cb");
        assert_eq!(
            ctx.eac_notification_uris(),
            vec!["http://amf-1/cb".to_string()]
        );
        assert!(ctx.eac_subscription_remove("amf-1"));
        assert!(ctx.eac_notification_uris().is_empty());
        assert!(!ctx.eac_subscription_remove("amf-1"));
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
            let (_, eac) = ctx.admit_ue(&s_nssai, &format!("imsi-{i}"), AccessType::ThreeGpp);
            assert!(eac.is_none(), "no EAC transition expected at {i}/10");
        }
        // 8th admission: 80% reached -> EAC activated
        let (_, eac) = ctx.admit_ue(&s_nssai, "imsi-8", AccessType::ThreeGpp);
        assert_eq!(
            eac,
            Some(EacTransition {
                s_nssai: s_nssai.clone(),
                activated: true
            })
        );
        // 9th: still active, no new transition
        let (_, eac) = ctx.admit_ue(&s_nssai, "imsi-9", AccessType::ThreeGpp);
        assert!(eac.is_none());
        // release back below threshold -> deactivated. A clean release that does
        // NOT cross the threshold is Released(None); the crossing carries the
        // EacTransition.
        let out = ctx.release_ue(&s_nssai, "imsi-9");
        assert_eq!(
            out,
            ReleaseOutcome::Released(None),
            "8/10 still at threshold"
        );
        let out = ctx.release_ue(&s_nssai, "imsi-8");
        assert_eq!(
            out,
            ReleaseOutcome::Released(Some(EacTransition {
                s_nssai: s_nssai.clone(),
                activated: false
            }))
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
        ctx.admit_ue(&s_nssai, "imsi-100", AccessType::ThreeGpp);
        ctx.admit_ue(&s_nssai, "imsi-101", AccessType::NonThreeGpp);
        ctx.admit_pdu_session(&s_nssai, "imsi-100:1", AccessType::ThreeGpp);

        // Simulate restart: fresh context restores from the state file
        let mut ctx2 = NsacfContext::new();
        ctx2.init(64);
        ctx2.set_state_file(Some(path.clone()));
        assert!(ctx2.load_state());

        let quota = ctx2.quota_find_by_snssai(&s_nssai).expect("quota restored");
        assert_eq!(quota.max_ues, 5);
        assert_eq!(quota.current_ues(), 2);
        assert_eq!(quota.current_pdu_sessions(), 1);
        // Per-access membership survives the round-trip (nsacf-05): imsi-100 on
        // 3GPP, imsi-101 on non-3GPP.
        assert_eq!(quota.current_ues_access(AccessType::ThreeGpp), 1);
        assert_eq!(quota.current_ues_access(AccessType::NonThreeGpp), 1);
        // Membership survives: re-admitting an existing SUPI is idempotent
        assert_eq!(
            ctx2.admit_ue(&s_nssai, "imsi-100", AccessType::ThreeGpp).0,
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
        let path =
            std::env::temp_dir().join(format!("nsacf-state-async-{}.json", uuid::Uuid::new_v4()));
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
            ctx2.quota_find_by_snssai(&s_nssai)
                .expect("restored")
                .max_ues,
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

    // -----------------------------------------------------------------
    // nsacf-05: per-access-type (anType) counting + per-access reason
    // -----------------------------------------------------------------

    #[test]
    fn test_per_access_ue_counting() {
        let mut ctx = NsacfContext::new();
        ctx.init(64);

        // Per-access quota: aggregate room for 10, but only 1 UE per access.
        let s_nssai = SNssai::new(11, None);
        ctx.quota_add_with_limits(
            s_nssai.clone(),
            10,
            50,
            AccessLimits {
                max_ues_3gpp: Some(1),
                max_ues_n3gpp: Some(1),
                ..Default::default()
            },
        );

        // First 3GPP UE admits; the 3GPP bucket is now full.
        assert_eq!(
            ctx.admit_ue(&s_nssai, "imsi-a", AccessType::ThreeGpp).0,
            AdmissionResult::Admitted
        );
        // Second 3GPP UE: aggregate has room (1/10) but the 3GPP ceiling is hit
        // -> per-access rejection drives the _3GPP reason (nsacf-05).
        assert_eq!(
            ctx.admit_ue(&s_nssai, "imsi-b", AccessType::ThreeGpp).0,
            AdmissionResult::RejectedQuotaExceededPerAccess(AccessType::ThreeGpp)
        );
        // An N3GPP UE for the same slice still admits (separate bucket).
        assert_eq!(
            ctx.admit_ue(&s_nssai, "imsi-c", AccessType::NonThreeGpp).0,
            AdmissionResult::Admitted
        );

        let quota = ctx.quota_find_by_snssai(&s_nssai).unwrap();
        assert_eq!(quota.current_ues(), 2, "aggregate counts both accesses");
        assert_eq!(quota.current_ues_access(AccessType::ThreeGpp), 1);
        assert_eq!(quota.current_ues_access(AccessType::NonThreeGpp), 1);
    }

    #[test]
    fn test_aggregate_only_quota_keeps_plain_reason() {
        let mut ctx = NsacfContext::new();
        ctx.init(64);

        // No per-access ceilings configured -> aggregate path, plain reason.
        let s_nssai = SNssai::new(12, None);
        ctx.quota_add(s_nssai.clone(), 1, 50);
        assert_eq!(
            ctx.admit_ue(&s_nssai, "imsi-a", AccessType::ThreeGpp).0,
            AdmissionResult::Admitted
        );
        assert_eq!(
            ctx.admit_ue(&s_nssai, "imsi-b", AccessType::NonThreeGpp).0,
            AdmissionResult::RejectedQuotaExceeded,
            "aggregate-only quota yields the plain reason regardless of anType"
        );
    }

    #[test]
    fn test_per_access_pdu_counting() {
        let mut ctx = NsacfContext::new();
        ctx.init(64);

        let s_nssai = SNssai::new(13, None);
        ctx.quota_add_with_limits(
            s_nssai.clone(),
            50,
            10,
            AccessLimits {
                max_pdu_3gpp: Some(1),
                ..Default::default()
            },
        );
        assert_eq!(
            ctx.admit_pdu_session(&s_nssai, "imsi-a:1", AccessType::ThreeGpp),
            AdmissionResult::Admitted
        );
        assert_eq!(
            ctx.admit_pdu_session(&s_nssai, "imsi-b:1", AccessType::ThreeGpp),
            AdmissionResult::RejectedQuotaExceededPerAccess(AccessType::ThreeGpp)
        );
        // N3GPP unconstrained -> admits.
        assert_eq!(
            ctx.admit_pdu_session(&s_nssai, "imsi-c:1", AccessType::NonThreeGpp),
            AdmissionResult::Admitted
        );
    }

    // -----------------------------------------------------------------
    // nsacf-06: AcuFlag UPDATE moves access buckets without double-counting
    // -----------------------------------------------------------------

    #[test]
    fn test_update_ue_access_moves_bucket() {
        let mut ctx = NsacfContext::new();
        ctx.init(64);

        let s_nssai = SNssai::new(14, None);
        ctx.quota_add(s_nssai.clone(), 10, 50);

        ctx.admit_ue(&s_nssai, "imsi-1", AccessType::ThreeGpp);
        let q = ctx.quota_find_by_snssai(&s_nssai).unwrap();
        assert_eq!(q.current_ues_access(AccessType::ThreeGpp), 1);
        assert_eq!(q.current_ues_access(AccessType::NonThreeGpp), 0);
        assert_eq!(q.current_ues(), 1);

        // UPDATE to non-3GPP: bucket moves, aggregate unchanged (no double-count).
        assert_eq!(
            ctx.update_ue_access(&s_nssai, "imsi-1", AccessType::NonThreeGpp),
            UpdateOutcome::Updated
        );
        let q = ctx.quota_find_by_snssai(&s_nssai).unwrap();
        assert_eq!(q.current_ues_access(AccessType::ThreeGpp), 0);
        assert_eq!(q.current_ues_access(AccessType::NonThreeGpp), 1);
        assert_eq!(q.current_ues(), 1, "aggregate not double-counted on UPDATE");

        // UPDATE again to the same access is idempotent.
        assert_eq!(
            ctx.update_ue_access(&s_nssai, "imsi-1", AccessType::NonThreeGpp),
            UpdateOutcome::Updated
        );

        // UPDATE for an unknown SUPI -> NotFound (becomes SLICE_NOT_FOUND).
        assert_eq!(
            ctx.update_ue_access(&s_nssai, "imsi-unknown", AccessType::ThreeGpp),
            UpdateOutcome::NotFound
        );
        // UPDATE on an unconfigured slice -> NotFound.
        assert_eq!(
            ctx.update_ue_access(&SNssai::new(97, None), "imsi-1", AccessType::ThreeGpp),
            UpdateOutcome::NotFound
        );
    }

    #[test]
    fn test_update_pdu_access_moves_bucket() {
        let mut ctx = NsacfContext::new();
        ctx.init(64);

        let s_nssai = SNssai::new(15, None);
        ctx.quota_add(s_nssai.clone(), 50, 10);
        ctx.admit_pdu_session(&s_nssai, "imsi-1:1", AccessType::ThreeGpp);

        assert_eq!(
            ctx.update_pdu_access(&s_nssai, "imsi-1:1", AccessType::NonThreeGpp),
            UpdateOutcome::Updated
        );
        let q = ctx.quota_find_by_snssai(&s_nssai).unwrap();
        assert_eq!(q.current_pdu_access(AccessType::ThreeGpp), 0);
        assert_eq!(q.current_pdu_access(AccessType::NonThreeGpp), 1);
        assert_eq!(q.current_pdu_sessions(), 1);

        assert_eq!(
            ctx.update_pdu_access(&s_nssai, "imsi-unknown:1", AccessType::ThreeGpp),
            UpdateOutcome::NotFound
        );
    }

    // -----------------------------------------------------------------
    // nsacf-10: DECREASE membership/cause correctness
    // -----------------------------------------------------------------

    #[test]
    fn test_release_outcomes() {
        let mut ctx = NsacfContext::new();
        ctx.init(64);

        let s_nssai = SNssai::new(16, None);
        ctx.quota_add(s_nssai.clone(), 10, 50);
        ctx.admit_ue(&s_nssai, "imsi-1", AccessType::ThreeGpp);

        // Clean release of a present member.
        assert_eq!(
            ctx.release_ue(&s_nssai, "imsi-1"),
            ReleaseOutcome::Released(None)
        );
        // Releasing again: slice known, member absent -> idempotent.
        assert_eq!(
            ctx.release_ue(&s_nssai, "imsi-1"),
            ReleaseOutcome::MemberAbsent
        );
        // Release on a slice that is not NSAC-subject -> SliceNotFound.
        assert_eq!(
            ctx.release_ue(&SNssai::new(96, None), "imsi-1"),
            ReleaseOutcome::SliceNotFound
        );

        // PDU mirror.
        ctx.admit_pdu_session(&s_nssai, "imsi-1:1", AccessType::ThreeGpp);
        assert_eq!(
            ctx.release_pdu_session(&s_nssai, "imsi-1:1"),
            ReleaseOutcome::Released(None)
        );
        assert_eq!(
            ctx.release_pdu_session(&s_nssai, "imsi-1:1"),
            ReleaseOutcome::MemberAbsent
        );
        assert_eq!(
            ctx.release_pdu_session(&SNssai::new(96, None), "imsi-1:1"),
            ReleaseOutcome::SliceNotFound
        );
    }

    #[test]
    fn test_access_type_from_an_type_defaults_3gpp() {
        assert_eq!(
            AccessType::from_an_type(Some("3GPP_ACCESS")),
            AccessType::ThreeGpp
        );
        assert_eq!(
            AccessType::from_an_type(Some("NON_3GPP_ACCESS")),
            AccessType::NonThreeGpp
        );
        // Absent or unrecognised -> default 3GPP (accept-and-default).
        assert_eq!(AccessType::from_an_type(None), AccessType::ThreeGpp);
        assert_eq!(AccessType::from_an_type(Some("WLAN")), AccessType::ThreeGpp);
    }

    #[test]
    fn test_snssai_to_key_roundtrip() {
        assert_eq!(SNssai::new(1, None).to_key(), "1");
        assert_eq!(SNssai::new(2, Some(0x0A0B0C)).to_key(), "2-0a0b0c");
        assert_eq!(
            SNssai::from_path_segment(&SNssai::new(2, Some(0x0A0B0C)).to_key()),
            Some(SNssai::new(2, Some(0x0A0B0C)))
        );
    }
}
