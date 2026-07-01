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

/// TS 29.520 `MatchingDirection` — the direction in which a measured analytic
/// must cross a threshold for a `THRESHOLD` event to fire (nwafd-07).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchingDirection {
    /// `ASCENDING` — fire when the value rises to/above the threshold.
    Ascending,
    /// `DESCENDING` — fire when the value falls to/below the threshold.
    Descending,
    /// `CROSSED` — fire when the value crosses the threshold in either
    /// direction relative to the previously observed value.
    Crossed,
}

impl MatchingDirection {
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "ASCENDING" => Some(Self::Ascending),
            "DESCENDING" => Some(Self::Descending),
            "CROSSED" => Some(Self::Crossed),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ascending => "ASCENDING",
            Self::Descending => "DESCENDING",
            Self::Crossed => "CROSSED",
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

    /// The parsed `matchingDir` (nwafd-07); defaults to `ASCENDING` when the
    /// consumer omitted it or sent an unrecognised token, mirroring the common
    /// 3GPP default for threshold reporting.
    pub fn matching_direction(&self) -> MatchingDirection {
        self.matching_dir
            .as_deref()
            .and_then(MatchingDirection::from_wire)
            .unwrap_or(MatchingDirection::Ascending)
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
            (None, _) => true,        // never notified → always due
            (Some(_), None) => false, // one-shot already fired
            (Some(last), Some(period)) => now.saturating_sub(last) >= period,
        }
    }
}

/// Stored Nnwdaf_MLModelProvision subscription (TS 29.520 `NwdafMLModelProvSubsc`).
///
/// nwafd-05: the bespoke REST `/models` registry was removed in favour of the
/// spec Subscribe/Notify resource. A consumer (e.g. an AnLF) subscribes for ML
/// model availability for one or more `NwdafEvent`s; the NWDAF delivers an
/// `NwdafMLModelProvNotif` callback carrying the model file address(es).
#[derive(Debug, Clone)]
pub struct MlProvSubscription {
    /// Unique subscription ID (`{subscriptionId}` in the resource URI).
    pub subscription_id: String,
    /// Consumer callback URI (`notifUri`, mandatory).
    pub notif_uri: String,
    /// Notification correlation ID (`notifCorreId`, optional — spec casing).
    pub notif_corr_id: Option<String>,
    /// Subscribed ML events (`mLEventSubscs[].mLEvent`, minItems 1).
    pub ml_events: Vec<AnalyticsId>,
    /// Whether the (one-shot, "model available") callback has been dispatched.
    pub notified: bool,
}

impl MlProvSubscription {
    pub fn new(
        subscription_id: String,
        notif_uri: String,
        notif_corr_id: Option<String>,
        ml_events: Vec<AnalyticsId>,
    ) -> Self {
        Self {
            subscription_id,
            notif_uri,
            notif_corr_id,
            ml_events,
            notified: false,
        }
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
    /// Nnwdaf_MLModelProvision subscriptions (subscription_id -> subscription)
    ml_prov_subscriptions: RwLock<HashMap<String, MlProvSubscription>>,
    /// Last observed analytic level per `(subscription_id, event)`, keyed
    /// `"{sub_id}\u{1f}{EVENT_TOKEN}"`. Drives THRESHOLD edge detection
    /// (nwafd-07) so `CROSSED`/`ASCENDING`/`DESCENDING` can compare against the
    /// previous value rather than re-firing on every cycle.
    event_levels: RwLock<HashMap<String, f64>>,
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
            ml_prov_subscriptions: RwLock::new(HashMap::new()),
            event_levels: RwLock::new(HashMap::new()),
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
        if let Ok(mut subs) = self.ml_prov_subscriptions.write() {
            subs.clear();
        }
        if let Ok(mut levels) = self.event_levels.write() {
            levels.clear();
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

    /// Replace an existing analytics subscription (PUT). Returns false if the
    /// subscription does not exist (so the handler can answer 404).
    pub fn update_subscription(&self, subscription: AnalyticsSubscription) -> bool {
        if let Ok(mut subs) = self.analytics_subscriptions.write() {
            if let std::collections::hash_map::Entry::Occupied(mut e) =
                subs.entry(subscription.subscription_id.clone())
            {
                e.insert(subscription);
                return true;
            }
        }
        false
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

    /// Add an Nnwdaf_MLModelProvision subscription (nwafd-05).
    pub fn add_ml_prov_subscription(&self, sub: MlProvSubscription) -> Option<String> {
        let mut subs = self.ml_prov_subscriptions.write().ok()?;
        if subs.len() >= self.max_subscriptions {
            log::error!(
                "Maximum ML-provision subscriptions [{}] reached",
                self.max_subscriptions
            );
            return None;
        }
        let id = sub.subscription_id.clone();
        subs.insert(id.clone(), sub);
        log::info!("ML-provision subscription added: {id}");
        Some(id)
    }

    /// Get an Nnwdaf_MLModelProvision subscription by ID.
    pub fn get_ml_prov_subscription(&self, subscription_id: &str) -> Option<MlProvSubscription> {
        self.ml_prov_subscriptions
            .read()
            .ok()?
            .get(subscription_id)
            .cloned()
    }

    /// Replace an existing ML-provision subscription (PUT). Returns false if the
    /// subscription does not exist (so the handler can answer 404).
    pub fn update_ml_prov_subscription(&self, sub: MlProvSubscription) -> bool {
        if let Ok(mut subs) = self.ml_prov_subscriptions.write() {
            if let std::collections::hash_map::Entry::Occupied(mut e) =
                subs.entry(sub.subscription_id.clone())
            {
                e.insert(sub);
                return true;
            }
        }
        false
    }

    /// Remove an ML-provision subscription (DELETE).
    pub fn remove_ml_prov_subscription(&self, subscription_id: &str) -> Option<MlProvSubscription> {
        let mut subs = self.ml_prov_subscriptions.write().ok()?;
        subs.remove(subscription_id)
    }

    /// All ML-provision subscriptions that have not yet had their (one-shot)
    /// "model available" callback dispatched. Used by the dispatcher.
    pub fn get_pending_ml_prov_subscriptions(&self) -> Vec<MlProvSubscription> {
        self.ml_prov_subscriptions
            .read()
            .map(|subs| subs.values().filter(|s| !s.notified).cloned().collect())
            .unwrap_or_default()
    }

    /// Mark an ML-provision subscription's callback as delivered.
    pub fn mark_ml_prov_notified(&self, subscription_id: &str) {
        if let Ok(mut subs) = self.ml_prov_subscriptions.write() {
            if let Some(sub) = subs.get_mut(subscription_id) {
                sub.notified = true;
            }
        }
    }

    pub fn ml_prov_subscription_count(&self) -> usize {
        self.ml_prov_subscriptions
            .read()
            .map(|s| s.len())
            .unwrap_or(0)
    }

    /// Last observed analytic level for a `(subscription, event)` pair, or
    /// `None` if this is the first observation (nwafd-07 edge detection).
    pub fn get_event_level(&self, subscription_id: &str, event: AnalyticsId) -> Option<f64> {
        let key = format!("{subscription_id}\u{1f}{}", event.as_str());
        self.event_levels.read().ok()?.get(&key).copied()
    }

    /// Record the latest observed analytic level for a `(subscription, event)`.
    pub fn set_event_level(&self, subscription_id: &str, event: AnalyticsId, level: f64) {
        let key = format!("{subscription_id}\u{1f}{}", event.as_str());
        if let Ok(mut levels) = self.event_levels.write() {
            levels.insert(key, level);
        }
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

    /// nwafd-05: ML-provision subscriptions are stored, updated and removed
    /// through the dedicated Subscribe/Notify store (no bespoke `/models`
    /// registry remains).
    #[test]
    fn test_ml_prov_subscription_crud() {
        let mut ctx = NwdafContext::new("nwdaf-test".to_string());
        ctx.init(100);

        let sub = MlProvSubscription::new(
            "mlsub-1".to_string(),
            "http://anlf.local/ml-notify".to_string(),
            Some("corr-1".to_string()),
            vec![AnalyticsId::NfLoad, AnalyticsId::UeMobility],
        );
        let id = ctx.add_ml_prov_subscription(sub).unwrap();
        assert_eq!(id, "mlsub-1");
        assert_eq!(ctx.ml_prov_subscription_count(), 1);

        // Update (PUT) replaces the events; updating a missing id returns false.
        let updated = MlProvSubscription::new(
            "mlsub-1".to_string(),
            "http://anlf.local/ml-notify".to_string(),
            Some("corr-1".to_string()),
            vec![AnalyticsId::NfLoad],
        );
        assert!(ctx.update_ml_prov_subscription(updated));
        assert_eq!(
            ctx.get_ml_prov_subscription("mlsub-1")
                .unwrap()
                .ml_events
                .len(),
            1
        );
        let absent = MlProvSubscription::new(
            "nope".to_string(),
            "http://x/y".to_string(),
            None,
            vec![AnalyticsId::NfLoad],
        );
        assert!(!ctx.update_ml_prov_subscription(absent));

        assert!(ctx.remove_ml_prov_subscription("mlsub-1").is_some());
        assert_eq!(ctx.ml_prov_subscription_count(), 0);
    }

    /// nwafd-07: per-(subscription, event) level state round-trips and is keyed
    /// so different events on the same subscription do not collide.
    #[test]
    fn test_event_level_state() {
        let ctx = NwdafContext::new("nwdaf-test".to_string());
        assert_eq!(ctx.get_event_level("s1", AnalyticsId::NfLoad), None);
        ctx.set_event_level("s1", AnalyticsId::NfLoad, 42.0);
        ctx.set_event_level("s1", AnalyticsId::UeMobility, 7.0);
        assert_eq!(ctx.get_event_level("s1", AnalyticsId::NfLoad), Some(42.0));
        assert_eq!(
            ctx.get_event_level("s1", AnalyticsId::UeMobility),
            Some(7.0)
        );
        assert_eq!(ctx.get_event_level("s2", AnalyticsId::NfLoad), None);
    }

    /// nwafd-07: `matchingDir` parses to the typed enum and defaults to
    /// ASCENDING when omitted or unrecognised.
    #[test]
    fn test_matching_direction_default() {
        let mut e = EventSubscription::periodic(AnalyticsId::NfLoad);
        assert_eq!(e.matching_direction(), MatchingDirection::Ascending);
        e.matching_dir = Some("DESCENDING".to_string());
        assert_eq!(e.matching_direction(), MatchingDirection::Descending);
        e.matching_dir = Some("CROSSED".to_string());
        assert_eq!(e.matching_direction(), MatchingDirection::Crossed);
        e.matching_dir = Some("bogus".to_string());
        assert_eq!(e.matching_direction(), MatchingDirection::Ascending);
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
