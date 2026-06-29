//! NWDAF Context Management
//!
//! Network Data Analytics Function context (TS 23.288)
//! Manages analytics subscriptions, ML models, and data collection

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

/// Analytics event types defined in TS 29.520 `NwdafEvent` (Rel-16/17/18).
///
/// The wire tokens returned by [`as_str`](Self::as_str) / accepted by
/// [`from_str`](Self::from_str) are the exact 3GPP enumeration values. The Rust
/// identifiers are spelled out for clarity (`UeCommunication`, `SliceLoadLevel`)
/// rather than the abbreviated forms used previously. Variants beyond the
/// original nine are accepted-and-carried so a conformant consumer's `event` is
/// not blanket-rejected, even where no analytics computation exists for them
/// yet (the dispatcher emits an empty per-event `*Infos` array in that case).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnalyticsId {
    /// NF load analytics (`NF_LOAD`)
    NfLoad,
    /// Network performance analytics (`NETWORK_PERFORMANCE`)
    NetworkPerformance,
    /// UE mobility analytics (`UE_MOBILITY`)
    UeMobility,
    /// UE communication patterns (`UE_COMMUNICATION`)
    UeCommunication,
    /// Abnormal behaviour detection (`ABNORMAL_BEHAVIOUR`)
    AbnormalBehaviour,
    /// Service experience analytics (`SERVICE_EXPERIENCE`)
    ServiceExperience,
    /// QoS sustainability analytics (`QOS_SUSTAINABILITY`)
    QosSustainability,
    /// Slice load-level analytics (`SLICE_LOAD_LEVEL`)
    SliceLoadLevel,
    /// User data congestion analytics (`USER_DATA_CONGESTION`)
    UserDataCongestion,
    /// Network-slice-instance load level (`NSI_LOAD_LEVEL`, Rel-17)
    NsiLoadLevel,
    /// Session-management congestion (`SM_CONGESTION`, Rel-17)
    SmCongestion,
    /// Dispersion analytics (`DISPERSION`, Rel-17)
    Dispersion,
    /// Redundant-transmission experience (`RED_TRANS_EXP`, Rel-17)
    RedTransExp,
    /// WLAN performance analytics (`WLAN_PERFORMANCE`, Rel-17)
    WlanPerformance,
    /// Data-network performance (`DN_PERFORMANCE`, Rel-17)
    DnPerformance,
    /// PDU session traffic analytics (`PDU_SESSION_TRAFFIC`, Rel-18)
    PduSessionTraffic,
}

impl AnalyticsId {
    /// Every TS 29.520 `NwdafEvent` token this binary recognises, in
    /// declaration order. Used by the round-trip conformance test and as the
    /// authoritative iteration source.
    pub const ALL: &'static [AnalyticsId] = &[
        Self::NfLoad,
        Self::NetworkPerformance,
        Self::UeMobility,
        Self::UeCommunication,
        Self::AbnormalBehaviour,
        Self::ServiceExperience,
        Self::QosSustainability,
        Self::SliceLoadLevel,
        Self::UserDataCongestion,
        Self::NsiLoadLevel,
        Self::SmCongestion,
        Self::Dispersion,
        Self::RedTransExp,
        Self::WlanPerformance,
        Self::DnPerformance,
        Self::PduSessionTraffic,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NfLoad => "NF_LOAD",
            Self::NetworkPerformance => "NETWORK_PERFORMANCE",
            Self::UeMobility => "UE_MOBILITY",
            Self::UeCommunication => "UE_COMMUNICATION",
            Self::AbnormalBehaviour => "ABNORMAL_BEHAVIOUR",
            Self::ServiceExperience => "SERVICE_EXPERIENCE",
            Self::QosSustainability => "QOS_SUSTAINABILITY",
            Self::SliceLoadLevel => "SLICE_LOAD_LEVEL",
            Self::UserDataCongestion => "USER_DATA_CONGESTION",
            Self::NsiLoadLevel => "NSI_LOAD_LEVEL",
            Self::SmCongestion => "SM_CONGESTION",
            Self::Dispersion => "DISPERSION",
            Self::RedTransExp => "RED_TRANS_EXP",
            Self::WlanPerformance => "WLAN_PERFORMANCE",
            Self::DnPerformance => "DN_PERFORMANCE",
            Self::PduSessionTraffic => "PDU_SESSION_TRAFFIC",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "NF_LOAD" => Some(Self::NfLoad),
            "NETWORK_PERFORMANCE" => Some(Self::NetworkPerformance),
            "UE_MOBILITY" => Some(Self::UeMobility),
            "UE_COMMUNICATION" => Some(Self::UeCommunication),
            "ABNORMAL_BEHAVIOUR" => Some(Self::AbnormalBehaviour),
            "SERVICE_EXPERIENCE" => Some(Self::ServiceExperience),
            "QOS_SUSTAINABILITY" => Some(Self::QosSustainability),
            "SLICE_LOAD_LEVEL" => Some(Self::SliceLoadLevel),
            "USER_DATA_CONGESTION" => Some(Self::UserDataCongestion),
            "NSI_LOAD_LEVEL" => Some(Self::NsiLoadLevel),
            "SM_CONGESTION" => Some(Self::SmCongestion),
            "DISPERSION" => Some(Self::Dispersion),
            "RED_TRANS_EXP" => Some(Self::RedTransExp),
            "WLAN_PERFORMANCE" => Some(Self::WlanPerformance),
            "DN_PERFORMANCE" => Some(Self::DnPerformance),
            "PDU_SESSION_TRAFFIC" => Some(Self::PduSessionTraffic),
            _ => None,
        }
    }

    /// The per-event `*Infos` array key used in `AnalyticsData`
    /// (Nnwdaf_AnalyticsInfo) and `EventNotification`
    /// (Nnwdaf_EventsSubscription_Notify) bodies, per TS 29.520.
    pub fn infos_key(&self) -> &'static str {
        match self {
            Self::NfLoad => "nfLoadLevelInfos",
            Self::SliceLoadLevel | Self::NsiLoadLevel => "sliceLoadLevelInfos",
            Self::NetworkPerformance => "nwPerfs",
            Self::UeMobility => "ueMobs",
            Self::UeCommunication => "ueComms",
            Self::QosSustainability => "qosSustainInfos",
            Self::AbnormalBehaviour => "abnorBehavrs",
            Self::ServiceExperience => "svcExps",
            Self::UserDataCongestion => "userDataCongInfos",
            Self::Dispersion => "disperInfos",
            Self::RedTransExp => "redTransInfos",
            Self::WlanPerformance => "wlanPerfInfos",
            Self::DnPerformance => "dnPerfInfos",
            Self::SmCongestion => "smcInfos",
            Self::PduSessionTraffic => "pduSesTrafInfos",
        }
    }
}

/// TS 29.520 `NotificationMethod` — how the consumer is notified for an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationMethod {
    /// `PERIODIC` — notify once per reporting period.
    Periodic,
    /// `THRESHOLD` — notify when a threshold is crossed.
    ///
    /// Threshold evaluation itself is deferred (remediation item nwafd-07); the
    /// dispatcher currently fires periodically regardless of method. The value
    /// is parsed and carried so the evaluation pass can be added without a
    /// wire-surface change.
    Threshold,
}

impl NotificationMethod {
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "PERIODIC" => Some(Self::Periodic),
            "THRESHOLD" => Some(Self::Threshold),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Periodic => "PERIODIC",
            Self::Threshold => "THRESHOLD",
        }
    }
}

/// One entry of TS 29.520 `NnwdafEventsSubscription.eventSubscriptions[]`
/// (`EventSubscription`).
#[derive(Debug, Clone)]
pub struct EventSubscription {
    /// The analytics event (`event`, NwdafEvent).
    pub event: AnalyticsId,
    /// `notificationMethod` (PERIODIC / THRESHOLD); `None` = unspecified.
    pub notification_method: Option<NotificationMethod>,
    /// Reporting period in seconds, from `extraReportReq.repPeriod`
    /// (`EventReportingRequirement`).
    pub rep_period_secs: Option<u64>,
    /// Load-level threshold (`loadLevelThreshold` / `nfLoadLvlThds`), carried
    /// for the deferred THRESHOLD evaluation (nwafd-07); not yet evaluated.
    pub load_level_threshold: Option<u64>,
    /// `matchingDir` (ASCENDING / DESCENDING / CROSSED), carried for nwafd-07.
    pub matching_dir: Option<String>,
    /// Per-event slice filters (`snssais`).
    pub snssais: Vec<SNssai>,
}

impl EventSubscription {
    /// A bare periodic subscription to a single event, used by the convenience
    /// [`AnalyticsSubscription::new`] constructor and by tests.
    pub fn periodic(event: AnalyticsId) -> Self {
        Self {
            event,
            notification_method: Some(NotificationMethod::Periodic),
            rep_period_secs: None,
            load_level_threshold: None,
            matching_dir: None,
            snssais: Vec::new(),
        }
    }
}

/// S-NSSAI (Single Network Slice Selection Assistance Information)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SNssai {
    /// Slice/Service Type (SST)
    pub sst: u8,
    /// Slice Differentiator (SD) - optional 24-bit value
    pub sd: Option<u32>,
}

impl Default for SNssai {
    fn default() -> Self {
        Self { sst: 1, sd: None }
    }
}

/// Analytics subscription (TS 29.520 `NnwdafEventsSubscription`).
///
/// A single subscription record may carry multiple events via
/// [`events`](Self::events), matching the spec `eventSubscriptions[]` array.
#[derive(Debug, Clone)]
pub struct AnalyticsSubscription {
    /// Unique subscription ID
    pub subscription_id: String,
    /// Per-event subscriptions (`eventSubscriptions[]`, minItems 1).
    pub events: Vec<EventSubscription>,
    /// Target SUPI (for UE-specific analytics)
    pub target_supi: Option<String>,
    /// Target S-NSSAI (for slice-specific analytics)
    pub target_snssai: Option<SNssai>,
    /// Notification URI for analytics reports (`notificationURI`)
    pub notification_uri: String,
    /// Subscription expiry time (Unix timestamp)
    pub expiry: u64,
    /// Subscription active flag
    pub active: bool,
    /// Notification correlation ID (`notifCorrId`, echoed in every Notify body)
    pub notification_correlation_id: String,
    /// Repetition period in seconds (None = one-shot / no periodic repeat).
    /// Enforced by the dispatcher: a notification is suppressed if the elapsed
    /// time since `last_notification_time` is less than this value.
    pub repetition_period_secs: Option<u64>,
    /// Unix timestamp of the last successfully dispatched notification.
    pub last_notification_time: Option<u64>,
}

impl AnalyticsSubscription {
    /// Convenience constructor for a single-event, periodic subscription.
    pub fn new(
        subscription_id: String,
        analytics_id: AnalyticsId,
        notification_uri: String,
        expiry: u64,
    ) -> Self {
        Self::new_with_events(
            subscription_id,
            vec![EventSubscription::periodic(analytics_id)],
            notification_uri,
            expiry,
        )
    }

    /// Full constructor carrying the parsed `eventSubscriptions[]`.
    pub fn new_with_events(
        subscription_id: String,
        events: Vec<EventSubscription>,
        notification_uri: String,
        expiry: u64,
    ) -> Self {
        let notification_correlation_id = format!("corr-{}", uuid::Uuid::new_v4());
        Self {
            subscription_id,
            events,
            target_supi: None,
            target_snssai: None,
            notification_uri,
            expiry,
            active: true,
            notification_correlation_id,
            repetition_period_secs: Some(60),
            last_notification_time: None,
        }
    }

    /// Returns true if any event in this subscription matches `analytics_id`.
    pub fn covers(&self, analytics_id: AnalyticsId) -> bool {
        self.events.iter().any(|e| e.event == analytics_id)
    }

    pub fn with_target_supi(mut self, supi: String) -> Self {
        self.target_supi = Some(supi);
        self
    }

    pub fn with_target_snssai(mut self, snssai: SNssai) -> Self {
        self.target_snssai = Some(snssai);
        self
    }

    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("value expected")
            .as_secs();
        now > self.expiry
    }

    /// Returns true if this subscription is due for a periodic notification.
    ///
    /// A subscription is due when:
    /// - It is active and not expired.
    /// - Either no notification has been sent yet, OR the elapsed time since
    ///   the last notification meets or exceeds `repetition_period_secs`.
    ///   If `repetition_period_secs` is `None` the subscription is treated as
    ///   a one-shot: due only on the very first dispatch.
    pub fn is_due_for_notification(&self) -> bool {
        if !self.active || self.is_expired() {
            return false;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs();
        match (self.last_notification_time, self.repetition_period_secs) {
            (None, _) => true, // never notified → always due
            (Some(_), None) => false, // one-shot already fired
            (Some(last), Some(period)) => now.saturating_sub(last) >= period,
        }
    }
}

/// ML model status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlModelStatus {
    /// Model is being trained
    Training,
    /// Model is trained and ready for inference
    Deployed,
    /// Model is being evaluated
    Evaluating,
    /// Model is inactive
    Inactive,
}

/// ML model information for analytics
#[derive(Debug, Clone)]
pub struct MlModelInfo {
    /// Unique model ID
    pub model_id: String,
    /// Analytics type this model supports
    pub analytics_id: AnalyticsId,
    /// Model version
    pub version: String,
    /// Model accuracy (0.0 - 1.0)
    pub accuracy: f64,
    /// Model status
    pub status: MlModelStatus,
    /// Training data count
    pub training_samples: usize,
    /// Last update timestamp
    pub updated_at: u64,
}

impl MlModelInfo {
    pub fn new(model_id: String, analytics_id: AnalyticsId, version: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("value expected")
            .as_secs();
        Self {
            model_id,
            analytics_id,
            version,
            accuracy: 0.0,
            status: MlModelStatus::Training,
            training_samples: 0,
            updated_at: now,
        }
    }

    pub fn is_deployed(&self) -> bool {
        self.status == MlModelStatus::Deployed
    }
}

/// Data source configuration for analytics collection
#[derive(Debug, Clone)]
pub struct DataSource {
    /// Source NF type (e.g., "AMF", "SMF", "UPF")
    pub nf_type: String,
    /// Source NF instance ID
    pub nf_instance_id: String,
    /// Data collection URI
    pub collection_uri: String,
    /// Collection enabled flag
    pub enabled: bool,
}

/// NWDAF Context - main context structure
pub struct NwdafContext {
    /// NF instance ID
    pub nf_instance_id: String,
    /// Analytics subscriptions (subscription_id -> subscription)
    analytics_subscriptions: RwLock<HashMap<String, AnalyticsSubscription>>,
    /// ML models (model_id -> model_info)
    ml_models: RwLock<HashMap<String, MlModelInfo>>,
    /// Data sources (nf_instance_id -> source)
    data_sources: RwLock<HashMap<String, DataSource>>,
    /// Next internal ID generator
    next_id: AtomicUsize,
    /// Maximum subscriptions
    max_subscriptions: usize,
    /// Context initialized flag
    initialized: AtomicBool,
}

impl NwdafContext {
    pub fn new(nf_instance_id: String) -> Self {
        Self {
            nf_instance_id,
            analytics_subscriptions: RwLock::new(HashMap::new()),
            ml_models: RwLock::new(HashMap::new()),
            data_sources: RwLock::new(HashMap::new()),
            next_id: AtomicUsize::new(1),
            max_subscriptions: 0,
            initialized: AtomicBool::new(false),
        }
    }

    pub fn init(&mut self, max_subscriptions: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.max_subscriptions = max_subscriptions;
        self.initialized.store(true, Ordering::SeqCst);
        log::info!(
            "NWDAF context initialized: instance={}, max_subscriptions={}",
            self.nf_instance_id,
            max_subscriptions
        );
    }

    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }
        if let Ok(mut subs) = self.analytics_subscriptions.write() {
            subs.clear();
        }
        if let Ok(mut models) = self.ml_models.write() {
            models.clear();
        }
        if let Ok(mut sources) = self.data_sources.write() {
            sources.clear();
        }
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("NWDAF context finalized");
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    /// Add an analytics subscription
    pub fn add_subscription(&self, subscription: AnalyticsSubscription) -> Option<String> {
        let mut subs = self.analytics_subscriptions.write().ok()?;

        if subs.len() >= self.max_subscriptions {
            log::error!(
                "Maximum analytics subscriptions [{}] reached",
                self.max_subscriptions
            );
            return None;
        }

        let sub_id = subscription.subscription_id.clone();
        subs.insert(sub_id.clone(), subscription);

        log::info!("Analytics subscription added: {sub_id}");
        Some(sub_id)
    }

    /// Remove an analytics subscription
    pub fn remove_subscription(&self, subscription_id: &str) -> Option<AnalyticsSubscription> {
        let mut subs = self.analytics_subscriptions.write().ok()?;
        let removed = subs.remove(subscription_id);
        if removed.is_some() {
            log::info!("Analytics subscription removed: {subscription_id}");
        }
        removed
    }

    /// Get analytics subscription by ID
    pub fn get_subscription(&self, subscription_id: &str) -> Option<AnalyticsSubscription> {
        self.analytics_subscriptions
            .read()
            .ok()?
            .get(subscription_id)
            .cloned()
    }

    /// Get all active subscriptions for a specific analytics type
    pub fn get_analytics(&self, analytics_id: AnalyticsId) -> Vec<AnalyticsSubscription> {
        self.analytics_subscriptions
            .read()
            .map(|subs| {
                subs.values()
                    .filter(|s| s.covers(analytics_id) && s.active && !s.is_expired())
                    .cloned()
                    .collect()
            })
            .expect("value expected")
    }

    /// Register an ML model
    pub fn register_model(&self, model: MlModelInfo) -> Option<String> {
        let mut models = self.ml_models.write().ok()?;
        let model_id = model.model_id.clone();
        models.insert(model_id.clone(), model);
        log::info!("ML model registered: {model_id}");
        Some(model_id)
    }

    /// Get ML model by ID
    pub fn get_model(&self, model_id: &str) -> Option<MlModelInfo> {
        self.ml_models.read().ok()?.get(model_id).cloned()
    }

    /// Get all deployed models for a specific analytics type
    pub fn get_deployed_models(&self, analytics_id: AnalyticsId) -> Vec<MlModelInfo> {
        self.ml_models
            .read()
            .map(|models| {
                models
                    .values()
                    .filter(|m| m.analytics_id == analytics_id && m.is_deployed())
                    .cloned()
                    .collect()
            })
            .expect("value expected")
    }

    /// Update ML model status
    pub fn update_model_status(&self, model_id: &str, status: MlModelStatus) -> bool {
        if let Ok(mut models) = self.ml_models.write() {
            if let Some(model) = models.get_mut(model_id) {
                model.status = status;
                model.updated_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("value expected")
                    .as_secs();
                log::info!("ML model {model_id} status updated to {status:?}");
                return true;
            }
        }
        false
    }

    /// Add a data source
    pub fn add_data_source(&self, source: DataSource) -> bool {
        if let Ok(mut sources) = self.data_sources.write() {
            sources.insert(source.nf_instance_id.clone(), source);
            return true;
        }
        false
    }

    /// Get all enabled data sources
    pub fn get_data_sources(&self) -> Vec<DataSource> {
        self.data_sources
            .read()
            .map(|sources| sources.values().filter(|s| s.enabled).cloned().collect())
            .expect("value expected")
    }

    /// Get all active, non-expired subscriptions (for the notification dispatcher)
    pub fn get_all_active_subscriptions(&self) -> Vec<AnalyticsSubscription> {
        self.analytics_subscriptions
            .read()
            .map(|subs| {
                subs.values()
                    .filter(|s| s.active && !s.is_expired())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Record that a notification was just dispatched for a subscription.
    /// Updates `last_notification_time` to the current Unix timestamp.
    pub fn update_subscription_last_notification(&self, subscription_id: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs();
        if let Ok(mut subs) = self.analytics_subscriptions.write() {
            if let Some(sub) = subs.get_mut(subscription_id) {
                sub.last_notification_time = Some(now);
            }
        }
    }

    pub fn subscription_count(&self) -> usize {
        self.analytics_subscriptions
            .read()
            .map(|s| s.len())
            .unwrap_or(0)
    }

    pub fn model_count(&self) -> usize {
        self.ml_models.read().map(|m| m.len()).unwrap_or(0)
    }

    pub fn data_source_count(&self) -> usize {
        self.data_sources.read().map(|d| d.len()).unwrap_or(0)
    }
}

impl Default for NwdafContext {
    fn default() -> Self {
        Self::new("nwdaf-instance-1".to_string())
    }
}

/// Global NWDAF context (thread-safe singleton)
static GLOBAL_NWDAF_CONTEXT: std::sync::OnceLock<Arc<RwLock<NwdafContext>>> =
    std::sync::OnceLock::new();

/// Get the global NWDAF context
pub fn nwdaf_self() -> Arc<RwLock<NwdafContext>> {
    GLOBAL_NWDAF_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(NwdafContext::default())))
        .clone()
}

/// Initialize the global NWDAF context
pub fn nwdaf_context_init(nf_instance_id: String, max_subscriptions: usize) {
    let ctx = nwdaf_self();
    if let Ok(mut context) = ctx.write() {
        context.nf_instance_id = nf_instance_id;
        context.init(max_subscriptions);
    };
}

/// Finalize the global NWDAF context
pub fn nwdaf_context_final() {
    let ctx = nwdaf_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analytics_id_conversion() {
        assert_eq!(AnalyticsId::NfLoad.as_str(), "NF_LOAD");
        assert_eq!(AnalyticsId::from_str("NF_LOAD"), Some(AnalyticsId::NfLoad));
        assert_eq!(AnalyticsId::from_str("INVALID"), None);
    }

    /// nwafd-01: every TS 29.520 `NwdafEvent` token round-trips both ways, and
    /// the two previously-wrong tokens are now correct while the old abbreviated
    /// spellings are rejected.
    #[test]
    fn test_analytics_id_token_round_trip() {
        // Full spec token list this binary recognises.
        let tokens = [
            "NF_LOAD",
            "NETWORK_PERFORMANCE",
            "UE_MOBILITY",
            "UE_COMMUNICATION",
            "ABNORMAL_BEHAVIOUR",
            "SERVICE_EXPERIENCE",
            "QOS_SUSTAINABILITY",
            "SLICE_LOAD_LEVEL",
            "USER_DATA_CONGESTION",
            "NSI_LOAD_LEVEL",
            "SM_CONGESTION",
            "DISPERSION",
            "RED_TRANS_EXP",
            "WLAN_PERFORMANCE",
            "DN_PERFORMANCE",
            "PDU_SESSION_TRAFFIC",
        ];

        // from_str(t).as_str() == t for every spec token.
        for t in tokens {
            let id = AnalyticsId::from_str(t)
                .unwrap_or_else(|| panic!("spec token {t} must be accepted by from_str"));
            assert_eq!(id.as_str(), t, "token {t} must round-trip back to itself");
        }

        // ALL covers exactly the token list, as_str() in declaration order.
        let from_all: Vec<&str> = AnalyticsId::ALL.iter().map(|e| e.as_str()).collect();
        assert_eq!(from_all, tokens, "ALL must enumerate every token in order");

        // The two corrected tokens are accepted.
        assert_eq!(
            AnalyticsId::from_str("UE_COMMUNICATION"),
            Some(AnalyticsId::UeCommunication)
        );
        assert_eq!(
            AnalyticsId::from_str("SLICE_LOAD_LEVEL"),
            Some(AnalyticsId::SliceLoadLevel)
        );

        // The old abbreviated tokens are rejected.
        assert_eq!(AnalyticsId::from_str("UE_COMM"), None);
        assert_eq!(AnalyticsId::from_str("SLICE_LOAD"), None);
    }

    #[test]
    fn test_nwdaf_context_new() {
        let ctx = NwdafContext::new("nwdaf-test".to_string());
        assert!(!ctx.is_initialized());
        assert_eq!(ctx.subscription_count(), 0);
    }

    #[test]
    fn test_nwdaf_context_init_fini() {
        let mut ctx = NwdafContext::new("nwdaf-test".to_string());
        ctx.init(100);
        assert!(ctx.is_initialized());
        ctx.fini();
        assert!(!ctx.is_initialized());
    }

    #[test]
    fn test_add_remove_subscription() {
        let mut ctx = NwdafContext::new("nwdaf-test".to_string());
        ctx.init(100);

        let sub = AnalyticsSubscription::new(
            "sub-1".to_string(),
            AnalyticsId::NfLoad,
            "http://localhost:8080/notify".to_string(),
            u64::MAX,
        );

        let sub_id = ctx.add_subscription(sub).unwrap();
        assert_eq!(sub_id, "sub-1");
        assert_eq!(ctx.subscription_count(), 1);

        let removed = ctx.remove_subscription("sub-1");
        assert!(removed.is_some());
        assert_eq!(ctx.subscription_count(), 0);
    }

    #[test]
    fn test_register_model() {
        let mut ctx = NwdafContext::new("nwdaf-test".to_string());
        ctx.init(100);

        let model = MlModelInfo::new(
            "model-1".to_string(),
            AnalyticsId::UeMobility,
            "v1.0".to_string(),
        );

        let model_id = ctx.register_model(model).unwrap();
        assert_eq!(model_id, "model-1");
        assert_eq!(ctx.model_count(), 1);
    }

    #[test]
    fn test_update_model_status() {
        let mut ctx = NwdafContext::new("nwdaf-test".to_string());
        ctx.init(100);

        let model = MlModelInfo::new(
            "model-1".to_string(),
            AnalyticsId::UeMobility,
            "v1.0".to_string(),
        );
        ctx.register_model(model);

        assert!(ctx.update_model_status("model-1", MlModelStatus::Deployed));
        let updated = ctx.get_model("model-1").unwrap();
        assert_eq!(updated.status, MlModelStatus::Deployed);
    }

    #[test]
    fn test_get_analytics_by_type() {
        let mut ctx = NwdafContext::new("nwdaf-test".to_string());
        ctx.init(100);

        ctx.add_subscription(AnalyticsSubscription::new(
            "sub-1".to_string(),
            AnalyticsId::NfLoad,
            "http://localhost:8080".to_string(),
            u64::MAX,
        ));

        ctx.add_subscription(AnalyticsSubscription::new(
            "sub-2".to_string(),
            AnalyticsId::UeMobility,
            "http://localhost:8080".to_string(),
            u64::MAX,
        ));

        let nf_load_subs = ctx.get_analytics(AnalyticsId::NfLoad);
        assert_eq!(nf_load_subs.len(), 1);

        let mobility_subs = ctx.get_analytics(AnalyticsId::UeMobility);
        assert_eq!(mobility_subs.len(), 1);
    }
}
