//! NWDAF Context Management
//!
//! Network Data Analytics Function context (TS 23.288)
//! Manages analytics subscriptions, ML models, and data collection

use crate::analytics::AnalyticsEngine;
use std::collections::HashMap;
#[cfg(feature = "sensing")]
use std::collections::VecDeque;
#[cfg(feature = "sensing")]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

/// G2-3 (supported-events honesty): the analytics events this NWDAF actually
/// supports — i.e., has a live data collector and computation path for. This is
/// the SINGLE SOURCE OF TRUTH; the three wire surfaces all derive from it:
///
/// 1. NRF `NFProfile.nwdafInfo.eventIds` advertisement
///    (TS 29.510 `NwdafInfo`, `main.rs::build_nf_profile`) so consumers
///    discover only supported analytics;
/// 2. `Nnwdaf_AnalyticsInfo` GET: an unsupported event returns **204 No
///    Content** (TS 29.520 §4.3.2.2.2 "requested Analytics data does not
///    exist"), never a fabricated 200 (`sbi_handler.rs`);
/// 3. `Nnwdaf_EventsSubscription`: unsupported events are declared failed in
///    the 201/200 body via `failEventReports[]` with
///    `NwdafFailureCode` = `UNAVAILABLE_DATA` (`sbi_handler.rs`), and the
///    notification dispatcher skips them entirely
///    (`notification_dispatcher.rs::build_event_notifications`).
///
/// Adding a new collector later only requires adding its variant here (plus
/// the actual computation arm in `compute_event_infos`).
///
/// Initially only NF_LOAD has a live data path (G2-1: NRF-sourced samples).
pub const SUPPORTED_EVENTS: &[AnalyticsId] = &[AnalyticsId::NfLoad];

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
    // The nine tokens below complete the TS 29.520 `NwdafEvent` enumeration
    // (issue #108). None has a collector in this build, so each is
    // `is_supported() == false` and is reported per-event via
    // `failEventReports` — but being *recognised* is what lets a subscription
    // mixing them with NF_LOAD succeed for the part we can serve, instead of
    // being rejected wholesale.
    /// PFD determination analytics (`PFD_DETERMINATION`, Rel-17)
    PfdDetermination,
    /// End-to-end data-volume transfer time (`E2E_DATA_VOL_TRANS_TIME`, Rel-17)
    E2eDataVolTransTime,
    /// UE movement behaviour (`MOVEMENT_BEHAVIOUR`, Rel-18)
    MovementBehaviour,
    /// Location accuracy analytics (`LOC_ACCURACY`, Rel-18)
    LocAccuracy,
    /// Relative UE proximity (`RELATIVE_PROXIMITY`, Rel-18)
    RelativeProximity,
    /// Signalling storm analytics (`SIGNALLING_STORM`, Rel-18)
    SignallingStorm,
    /// QoS policy assistance (`QOS_POLICY_ASSIST`, Rel-18)
    QosPolicyAssist,
    /// Abnormal uplink/downlink traffic (`ABNORMAL_UP_TRAFFIC`, Rel-18)
    AbnormalUpTraffic,
    /// Traffic pattern analytics (`TRAFFIC_PATTERN`, Rel-18)
    TrafficPattern,
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
        Self::PfdDetermination,
        Self::E2eDataVolTransTime,
        Self::MovementBehaviour,
        Self::LocAccuracy,
        Self::RelativeProximity,
        Self::SignallingStorm,
        Self::QosPolicyAssist,
        Self::AbnormalUpTraffic,
        Self::TrafficPattern,
    ];

    /// The TS 29.520 **`NwdafEvent`** token for this event.
    ///
    /// This is the spelling used by Nnwdaf_EventsSubscription
    /// (`eventSubscriptions[].event`), Nnwdaf_MLModelProvision
    /// (`mLEventSubscs[].mLEvent`) and `NwdafInfo.nwdafEvents`.
    ///
    /// NOT the spelling for Nnwdaf_AnalyticsInfo (issue #175): that API types its
    /// `event-id` as `EventId`, a different 24-value enumeration. Use
    /// [`as_event_id`](Self::as_event_id) there.
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
            Self::PfdDetermination => "PFD_DETERMINATION",
            Self::E2eDataVolTransTime => "E2E_DATA_VOL_TRANS_TIME",
            Self::MovementBehaviour => "MOVEMENT_BEHAVIOUR",
            Self::LocAccuracy => "LOC_ACCURACY",
            Self::RelativeProximity => "RELATIVE_PROXIMITY",
            Self::SignallingStorm => "SIGNALLING_STORM",
            Self::QosPolicyAssist => "QOS_POLICY_ASSIST",
            Self::AbnormalUpTraffic => "ABNORMAL_UP_TRAFFIC",
            Self::TrafficPattern => "TRAFFIC_PATTERN",
        }
    }

    /// Parse a TS 29.520 **`NwdafEvent`** token (the counterpart of
    /// [`as_str`](Self::as_str)).
    ///
    /// Accepts all 25 `NwdafEvent` values. NOT for the Nnwdaf_AnalyticsInfo
    /// `event-id` query parameter, which is an `EventId` — use
    /// [`from_event_id`](Self::from_event_id) there (issue #175).
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
            "PFD_DETERMINATION" => Some(Self::PfdDetermination),
            "E2E_DATA_VOL_TRANS_TIME" => Some(Self::E2eDataVolTransTime),
            "MOVEMENT_BEHAVIOUR" => Some(Self::MovementBehaviour),
            "LOC_ACCURACY" => Some(Self::LocAccuracy),
            "RELATIVE_PROXIMITY" => Some(Self::RelativeProximity),
            "SIGNALLING_STORM" => Some(Self::SignallingStorm),
            "QOS_POLICY_ASSIST" => Some(Self::QosPolicyAssist),
            "ABNORMAL_UP_TRAFFIC" => Some(Self::AbnormalUpTraffic),
            "TRAFFIC_PATTERN" => Some(Self::TrafficPattern),
            _ => None,
        }
    }

    /// The TS 29.520 **`EventId`** token for this event, or `None` when `EventId`
    /// has no value for it (issue #175).
    ///
    /// `EventId` (`TS29520_Nnwdaf_AnalyticsInfo.yaml:939-1004`) is a DIFFERENT
    /// enumeration from `NwdafEvent`, and the difference is not cosmetic:
    ///
    /// | | `NwdafEvent` (25) | `EventId` (24) |
    /// |---|---|---|
    /// | slice load level | `SLICE_LOAD_LEVEL` | `LOAD_LEVEL_INFORMATION` |
    /// | PFD determination | `PFD_DETERMINATION` | *(absent)* |
    ///
    /// `EventId` is the type of the Nnwdaf_AnalyticsInfo `event-id` query
    /// parameter (`yaml:35-40`) and of `NwdafInfo.eventIds` in the NRF profile
    /// (`TS29510_Nnrf_NFManagement.yaml` `NwdafInfo`). `NwdafInfo` also carries a
    /// separate `nwdafEvents` member typed `NwdafEvent`, which is how an event
    /// with no `EventId` value can still be advertised — see
    /// `main.rs::build_nf_profile`.
    pub fn as_event_id(&self) -> Option<&'static str> {
        Some(match self {
            // The one token whose EventId spelling differs from its NwdafEvent
            // spelling. Getting this wrong is what made a conformant
            // `event-id=LOAD_LEVEL_INFORMATION` a 400 before #175.
            Self::SliceLoadLevel => "LOAD_LEVEL_INFORMATION",
            // Not an EventId value: PFD determination analytics are
            // subscribe/notify-only, and `AnalyticsData` has no member for them
            // either (see `analytics_data_key`).
            Self::PfdDetermination => return None,
            // Every other token is spelled identically in both enumerations.
            other => other.as_str(),
        })
    }

    /// Parse a TS 29.520 **`EventId`** token — the enumeration the
    /// Nnwdaf_AnalyticsInfo `event-id` query parameter is typed as (issue #175).
    ///
    /// Accepts exactly `EventId`'s 24 values, so `LOAD_LEVEL_INFORMATION` is
    /// recognised (it was rejected `400 INVALID_ANALYTICS_TYPE` before #175,
    /// which is the spec's own token for that API) and the two `NwdafEvent`-only
    /// spellings `SLICE_LOAD_LEVEL` / `PFD_DETERMINATION` are NOT — accepting a
    /// token the called API does not define is the mirror-image of the same
    /// confusion.
    ///
    /// The exact-inverse property (`from_event_id(as_event_id(e)) == Some(e)` for
    /// every token with an `EventId` value, and no `EventId` value maps to two
    /// tokens) is asserted by `test_event_id_and_nwdaf_event_are_distinct_enums`.
    pub fn from_event_id(s: &str) -> Option<Self> {
        match s {
            "LOAD_LEVEL_INFORMATION" => Some(Self::SliceLoadLevel),
            // Reject the NwdafEvent-only spellings on this surface.
            "SLICE_LOAD_LEVEL" | "PFD_DETERMINATION" => None,
            other => Self::from_str(other),
        }
    }

    /// G2-3: whether this event has a live collector/computation in this
    /// build (membership in [`SUPPORTED_EVENTS`], the single source of truth).
    pub fn is_supported(&self) -> bool {
        SUPPORTED_EVENTS.contains(self)
    }

    /// The per-event payload member name in a TS 29.520 `EventNotification`
    /// body, i.e. what `Nnwdaf_EventsSubscription_Notify` emits.
    ///
    /// Read off `components.schemas.EventNotification` in
    /// `TS29520_Nnwdaf_EventsSubscription.yaml` (yaml:802-966), never inferred
    /// from the token name — several are abbreviated differently from what the
    /// token suggests (`dataVlTrnsTmInfos`, `movBehavInfos`, `abnorBehavrs`).
    ///
    /// THIS IS NOT INTERCHANGEABLE WITH [`analytics_data_key`](Self::analytics_data_key)
    /// (issue #172). The two service APIs name the same analytics differently, so
    /// one shared accessor cannot be right for both — which is exactly how the
    /// pre-#172 `infos_key()` was wrong on one surface or the other for seven
    /// tokens. See `analytics_data_key` for the divergence table.
    ///
    /// Every one of the 25 `NwdafEvent` tokens maps to a distinct member here,
    /// and those 25 are exactly the payload members of `EventNotification`
    /// (its other 11 members are envelope fields: `event`, `start`, `expiry`,
    /// `timeStampGen`, `failNotifyCode`, `rvWaitTime`, `anaMetaInfo`,
    /// `accuInfo`, `cancelAccuInd`, `pauseInd`, `resumeInd`). The bijection is
    /// asserted by `test_infos_keys_match_the_spec_for_every_token`.
    pub fn notification_infos_key(&self) -> &'static str {
        match self {
            Self::NfLoad => "nfLoadLevelInfos",
            // Issue #172: NSI_LOAD_LEVEL has its OWN member; it used to share
            // SLICE_LOAD_LEVEL's, so a consumer would have looked for
            // `nsiLoadLevelInfos` and found nothing.
            Self::NsiLoadLevel => "nsiLoadLevelInfos",
            // Issue #172: singular, and an OBJECT not an array — see
            // `notification_payload_is_single_object`.
            Self::SliceLoadLevel => "sliceLoadLevelInfo",
            Self::NetworkPerformance => "nwPerfs",
            Self::UeMobility => "ueMobs",
            Self::UeCommunication => "ueComms",
            Self::QosSustainability => "qosSustainInfos",
            Self::AbnormalBehaviour => "abnorBehavrs",
            Self::ServiceExperience => "svcExps",
            Self::UserDataCongestion => "userDataCongInfos",
            Self::Dispersion => "disperInfos",
            Self::RedTransExp => "redTransInfos",
            // Issue #172: was `wlanPerfInfos`, which the yaml does not define.
            Self::WlanPerformance => "wlanInfos",
            Self::DnPerformance => "dnPerfInfos",
            // Issue #172: was `smcInfos`, which the yaml does not define.
            Self::SmCongestion => "smccExps",
            Self::PduSessionTraffic => "pduSesTrafInfos",
            Self::PfdDetermination => "pfdDetermInfos",
            Self::E2eDataVolTransTime => "dataVlTrnsTmInfos",
            Self::MovementBehaviour => "movBehavInfos",
            Self::LocAccuracy => "locAccInfos",
            Self::RelativeProximity => "relProxInfos",
            Self::SignallingStorm => "signalStormInfos",
            Self::QosPolicyAssist => "qosPolAssistInfos",
            Self::AbnormalUpTraffic => "abnormalTrafficInfos",
            Self::TrafficPattern => "trafficPatternInfos",
        }
    }

    /// The per-event payload member name in a TS 29.520 `AnalyticsData` body,
    /// i.e. what an `Nnwdaf_AnalyticsInfo` GET returns — or `None` when
    /// `AnalyticsData` defines no member for this event.
    ///
    /// Read off `components.schemas.AnalyticsData` in
    /// `TS29520_Nnwdaf_AnalyticsInfo.yaml` (yaml:212-361).
    ///
    /// WHY THIS IS A SEPARATE ACCESSOR (issue #172). The two service APIs do not
    /// agree, so the single shared `infos_key()` this replaced was necessarily
    /// wrong on one surface or the other:
    ///
    /// | token | `EventNotification` | `AnalyticsData` |
    /// |---|---|---|
    /// | `SLICE_LOAD_LEVEL` | `sliceLoadLevelInfo` (object) | `sliceLoadLevelInfos` (array) |
    /// | `QOS_POLICY_ASSIST` | `qosPolAssistInfos` | `qosPlyAsstInfos` |
    /// | `ABNORMAL_UP_TRAFFIC` | `abnormalTrafficInfos` | `abnormalTraffic` |
    /// | `PFD_DETERMINATION` | `pfdDetermInfos` | *(no member)* |
    ///
    /// `PFD_DETERMINATION` is `None` because it is not even an `EventId` value:
    /// the AnalyticsInfo API's enum has 24 tokens where `NwdafEvent` has 25, so
    /// PFD determination analytics are subscribe/notify-only. A GET for it must
    /// fail closed rather than invent a member name (see `sbi_handler`).
    ///
    /// The 24 `Some` values are exactly the payload members of `AnalyticsData`
    /// (its other 7 are envelope fields: `start`, `expiry`, `timeStampGen`,
    /// `anaMetaInfo`, `accuInfo`, `cancelAccuInd`, `suppFeat`).
    pub fn analytics_data_key(&self) -> Option<&'static str> {
        Some(match self {
            Self::NfLoad => "nfLoadLevelInfos",
            Self::NsiLoadLevel => "nsiLoadLevelInfos",
            // An ARRAY here, unlike the notify surface's singular object.
            Self::SliceLoadLevel => "sliceLoadLevelInfos",
            Self::NetworkPerformance => "nwPerfs",
            Self::UeMobility => "ueMobs",
            Self::UeCommunication => "ueComms",
            Self::QosSustainability => "qosSustainInfos",
            Self::AbnormalBehaviour => "abnorBehavrs",
            Self::ServiceExperience => "svcExps",
            Self::UserDataCongestion => "userDataCongInfos",
            Self::Dispersion => "disperInfos",
            Self::RedTransExp => "redTransInfos",
            Self::WlanPerformance => "wlanInfos",
            Self::DnPerformance => "dnPerfInfos",
            Self::SmCongestion => "smccExps",
            Self::PduSessionTraffic => "pduSesTrafInfos",
            Self::E2eDataVolTransTime => "dataVlTrnsTmInfos",
            Self::MovementBehaviour => "movBehavInfos",
            Self::LocAccuracy => "locAccInfos",
            Self::RelativeProximity => "relProxInfos",
            Self::SignallingStorm => "signalStormInfos",
            // Differs from the notify surface's `qosPolAssistInfos`.
            Self::QosPolicyAssist => "qosPlyAsstInfos",
            // Differs from the notify surface's `abnormalTrafficInfos`.
            Self::AbnormalUpTraffic => "abnormalTraffic",
            Self::TrafficPattern => "trafficPatternInfos",
            // Not an `EventId` value: no AnalyticsData member exists.
            Self::PfdDetermination => return None,
        })
    }

    /// Whether this event's `EventNotification` payload is a SINGLE object
    /// rather than an array (issue #172).
    ///
    /// True only for `SLICE_LOAD_LEVEL`, whose notify member
    /// `sliceLoadLevelInfo` is a bare `SliceLoadLevelInformation`
    /// (`TS29520_Nnwdaf_EventsSubscription.yaml:835-836`) while every other
    /// payload member — including its own `AnalyticsData` counterpart
    /// `sliceLoadLevelInfos` — is a `minItems: 1` array. This is a *shape*
    /// difference, not just a name, so it cannot be handled by the key alone.
    pub fn notification_payload_is_single_object(&self) -> bool {
        matches!(self, Self::SliceLoadLevel)
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
    /// Additional `nfLoadLvlThds[]` entries beyond the first (issue #108).
    ///
    /// TS 29.520 `EventSubscription.nfLoadLvlThds` is a LIST of `ThresholdLevel`
    /// and a THRESHOLD notification fires when any of them is crossed. Only
    /// `[0]` used to be read. Kept as an overflow list beside the existing
    /// scalar rather than replacing it, so the many call sites and tests that
    /// read `load_level_threshold` for the primary threshold keep working;
    /// [`Self::load_level_thresholds`] is the accessor evaluation should use.
    pub extra_load_level_thresholds: Vec<u64>,
    /// `matchingDir` (ASCENDING / DESCENDING / CROSSED), carried for nwafd-07.
    pub matching_dir: Option<String>,
    /// Per-event slice filters (`snssais`).
    pub snssais: Vec<SNssai>,
    /// Per-event NF-instance filter (`nfInstanceIds`, TS 29.520
    /// `EventSubscription`); empty = no filter (G2-1).
    pub nf_instance_ids: Vec<String>,
    /// Per-event NF-type filter (`nfTypes`, TS 29.520 `EventSubscription`);
    /// empty = no filter (G2-1).
    pub nf_types: Vec<String>,
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
            extra_load_level_thresholds: Vec::new(),
            matching_dir: None,
            snssais: Vec::new(),
            nf_instance_ids: Vec::new(),
            nf_types: Vec::new(),
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

    /// Every configured load-level threshold, primary first (issue #108).
    ///
    /// THRESHOLD evaluation must consider all of `nfLoadLvlThds[]`, not just the
    /// first entry, so this is the accessor the dispatcher uses.
    pub fn load_level_thresholds(&self) -> Vec<u64> {
        self.load_level_threshold
            .into_iter()
            .chain(self.extra_load_level_thresholds.iter().copied())
            .collect()
    }
}

/// Key for the THRESHOLD edge-detection state: one previous level per
/// `(subscription, event, NF instance)`.
///
/// The instance is part of the key (issue #108) because thresholds are evaluated
/// per reported instance. Without it, two instances of the same NF type sharing a
/// subscription would overwrite each other's previous level and
/// `ASCENDING`/`DESCENDING` would fire or suppress on the wrong history.
fn event_level_key(subscription_id: &str, event: AnalyticsId, nf_instance_id: &str) -> String {
    format!(
        "{subscription_id}\u{1f}{}\u{1f}{nf_instance_id}",
        event.as_str()
    )
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
    /// Event tokens the consumer asked for that are outside the TS 29.520
    /// `NwdafEvent` enumeration entirely (issue #108).
    ///
    /// Carried rather than rejected: the enumeration's yaml `anyOf` includes a
    /// free-form string alternative expressly for forward compatibility, so a
    /// consumer requesting a newer analytics type must still get the events it
    /// *is* entitled to. These surface per-event in `failEventReports`.
    pub unknown_events: Vec<String>,
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
    /// `evtReq.maxReportNbr` (TS 29.523 `ReportingInformation`): stop after this
    /// many notifications. `None` = unlimited (issue #108).
    pub max_report_nbr: Option<u64>,
    /// Notifications successfully dispatched so far, counted against
    /// [`Self::max_report_nbr`].
    pub reports_sent: u64,
    /// Set once a termination notification carrying `termCause` has been sent,
    /// so it is emitted exactly once (issue #108).
    pub termination_notified: bool,
}

/// TS 29.520 `TerminationCause` — why the NWDAF stopped reporting.
///
/// Before issue #108 a subscription simply vanished from
/// `get_all_active_subscriptions` when its bespoke `expiryTime` passed, with no
/// notification at all: a consumer could not tell a deliberate termination from
/// a lost subscription, so it could not re-subscribe deterministically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationCause {
    /// The monitoring duration (`evtReq.monDur`) elapsed.
    MonitoringDurationExpiry,
    /// The requested number of reports (`evtReq.maxReportNbr`) was reached.
    MaxNumberOfReportsReached,
}

impl TerminationCause {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MonitoringDurationExpiry => "MONITORING_DURATION_EXPIRY",
            Self::MaxNumberOfReportsReached => "MAX_NUMBER_OF_REPORTS_REACHED",
        }
    }
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
            unknown_events: Vec::new(),
            notification_uri,
            expiry,
            active: true,
            notification_correlation_id,
            repetition_period_secs: Some(60),
            last_notification_time: None,
            max_report_nbr: None,
            reports_sent: 0,
            termination_notified: false,
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

    /// Why this subscription should stop reporting, or `None` while it is live
    /// (issue #108).
    ///
    /// Both causes are checked here rather than at the two former call sites so
    /// `is_due_for_notification` and the dispatcher's termination pass cannot
    /// disagree about whether a subscription is finished.
    pub fn termination_cause(&self) -> Option<TerminationCause> {
        if self
            .max_report_nbr
            .is_some_and(|max| self.reports_sent >= max)
        {
            return Some(TerminationCause::MaxNumberOfReportsReached);
        }
        if self.is_expired() {
            return Some(TerminationCause::MonitoringDurationExpiry);
        }
        None
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
        // Issue #108: `maxReportNbr` is a stop condition as much as expiry is.
        if !self.active || self.termination_cause().is_some() {
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

/// State of the NWDAF's own Nnrf_NFManagement NFStatusSubscribe subscription
/// at the NRF (TS 29.510 §5.2.2.5) — the G2-1 NF_LOAD data-collection channel.
#[derive(Debug, Clone)]
pub struct NrfStatusSubscription {
    /// NRF-assigned `subscriptionId`.
    pub subscription_id: String,
    /// Absolute expiry (Unix seconds) parsed from the NRF's `validityTime`,
    /// when the NRF returned one. `None` = no expiry communicated.
    pub validity_unix: Option<u64>,
}

/// Where the G2-1 NRF collector subscribes and where the NRF must deliver
/// NFStatusNotify callbacks. Set once at startup by `main()`; read by the
/// dispatcher tick for (re-)subscription.
#[derive(Debug, Clone)]
pub struct NrfCollectorConfig {
    /// NRF base URI (e.g., `http://127.0.0.1:7777`).
    pub nrf_uri: String,
    /// Our absolute `nfStatusNotificationUri` callback.
    pub callback_uri: String,
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
    /// The analytics engine (G2-1): sample store + computation, shared by the
    /// Nnwdaf_AnalyticsInfo handler, the notification dispatcher and the NRF
    /// NFStatusNotify ingestion path so samples actually accumulate.
    ///
    /// LOCK ORDER (nf-context-lock-deadlocks): always take the outer context
    /// `RwLock` (read) FIRST, then this `Mutex` — never the reverse.
    engine: Mutex<AnalyticsEngine>,
    /// Our own NFStatusSubscribe subscription at the NRF (G2-1), if active.
    nrf_status_subscription: RwLock<Option<NrfStatusSubscription>>,
    /// NRF collector configuration (G2-1), set by `main()` at startup.
    nrf_collector_config: RwLock<Option<NrfCollectorConfig>>,
    /// This NF's own SBI base URI (e.g. `http://10.0.0.5:7777`), set by `main()`
    /// at startup from the bound address.
    ///
    /// Needed because `Nnwdaf_MLModelProvision` notifies consumers of a model
    /// URL that must resolve back to *this* NF (issue #109); the placeholder it
    /// replaced was a hardcoded `http://nwdaf/...` that nothing served.
    sbi_base_uri: RwLock<Option<String>>,
    /// Next internal ID generator
    next_id: AtomicUsize,
    /// Maximum subscriptions
    max_subscriptions: usize,
    /// Context initialized flag
    initialized: AtomicBool,
    /// Bounded ISAC sensing-result store (issue #16, non-normative 6G).
    /// LOCK ORDER (nf-context-lock-deadlocks): outer context RwLock (read)
    /// FIRST, then only this lock — never while holding another interior lock.
    #[cfg(feature = "sensing")]
    sensing_results: RwLock<VecDeque<nextgcore_proto::SensingResult>>,
    /// NF-owned event broker for `SbiEventCategory::Isac` publications
    /// (issue #16). Same lock-order rule as `sensing_results`.
    #[cfg(feature = "sensing")]
    event_broker: Mutex<nextgcore_sbi::pubsub::EventBroker>,
    /// Running total of ingested sensing results — the value behind the
    /// `nextgcore_metrics::ai_native::ISAC_SENSING_RESULTS` counter.
    #[cfg(feature = "sensing")]
    sensing_ingested_total: AtomicU64,
}

impl NwdafContext {
    pub fn new(nf_instance_id: String) -> Self {
        Self {
            nf_instance_id,
            analytics_subscriptions: RwLock::new(HashMap::new()),
            ml_prov_subscriptions: RwLock::new(HashMap::new()),
            event_levels: RwLock::new(HashMap::new()),
            data_sources: RwLock::new(HashMap::new()),
            engine: Mutex::new(AnalyticsEngine::new()),
            nrf_status_subscription: RwLock::new(None),
            nrf_collector_config: RwLock::new(None),
            sbi_base_uri: RwLock::new(None),
            next_id: AtomicUsize::new(1),
            max_subscriptions: 0,
            initialized: AtomicBool::new(false),
            #[cfg(feature = "sensing")]
            sensing_results: RwLock::new(VecDeque::new()),
            #[cfg(feature = "sensing")]
            event_broker: Mutex::new(nextgcore_sbi::pubsub::EventBroker::new()),
            #[cfg(feature = "sensing")]
            sensing_ingested_total: AtomicU64::new(0),
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

    /// Bounded ISAC store capacity (issue #16); matches the ~100-sample house
    /// style of `AnalyticsEngine::MAX_SAMPLES`.
    #[cfg(feature = "sensing")]
    const MAX_SENSING_RESULTS: usize = 100;

    /// Ingest one sensing result into the bounded ring buffer and return the
    /// running ingest total (the `ISAC_SENSING_RESULTS` metric value).
    #[cfg(feature = "sensing")]
    pub fn push_sensing_result(&self, result: nextgcore_proto::SensingResult) -> u64 {
        let mut buf = self
            .sensing_results
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while buf.len() >= Self::MAX_SENSING_RESULTS {
            buf.pop_front();
        }
        buf.push_back(result);
        // Counter bumped while the buffer lock is held so sensing_snapshot()
        // can never observe a pushed result alongside a stale total.
        self.sensing_ingested_total.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Snapshot of the sensing store: (total ingested, buffered count,
    /// latest result if any).
    #[cfg(feature = "sensing")]
    pub fn sensing_snapshot(&self) -> (u64, usize, Option<nextgcore_proto::SensingResult>) {
        let buf = self
            .sensing_results
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Counter read while the buffer lock is held — pairs with the locked
        // increment in push_sensing_result for a consistent view.
        let total = self.sensing_ingested_total.load(Ordering::SeqCst);
        (total, buf.len(), buf.back().cloned())
    }

    /// Publish an `SbiEventCategory::Isac` event on the NF-owned broker and
    /// return the number of matched subscribers.
    #[cfg(feature = "sensing")]
    pub fn publish_isac_event(&self, event_type: &str, payload: String) -> usize {
        let mut broker = self
            .event_broker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let event = nextgcore_sbi::SbiEvent::new(
            broker.alloc_event_id(),
            nextgcore_sbi::SbiEventCategory::Isac,
            event_type,
            self.nf_instance_id.clone(),
            payload,
        );
        broker.publish(&event).len()
    }

    /// Access the NF-owned event broker (tests/introspection).
    #[cfg(feature = "sensing")]
    pub fn lock_event_broker(&self) -> MutexGuard<'_, nextgcore_sbi::pubsub::EventBroker> {
        self.event_broker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }
        #[cfg(feature = "sensing")]
        {
            let mut buf = self
                .sensing_results
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            buf.clear();
            drop(buf);
            self.sensing_ingested_total.store(0, Ordering::SeqCst);
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
        if let Ok(engine) = self.engine.get_mut() {
            *engine = AnalyticsEngine::new();
        }
        if let Ok(mut sub) = self.nrf_status_subscription.write() {
            *sub = None;
        }
        self.initialized.store(false, Ordering::SeqCst);
        log::info!("NWDAF context finalized");
    }

    /// Lock the shared analytics engine (G2-1).
    ///
    /// LOCK ORDER: callers must already hold (or not need) the outer context
    /// `RwLock`; never acquire the outer lock while holding this guard.
    /// A poisoned mutex is recovered (`into_inner`) rather than panicking on a
    /// runtime-reachable path.
    pub fn lock_engine(&self) -> MutexGuard<'_, AnalyticsEngine> {
        self.engine
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The active NFStatusSubscribe subscription at the NRF, if any (G2-1).
    pub fn nrf_status_subscription(&self) -> Option<NrfStatusSubscription> {
        self.nrf_status_subscription
            .read()
            .ok()
            .and_then(|s| s.clone())
    }

    /// Record (or clear) the NFStatusSubscribe subscription state (G2-1).
    pub fn set_nrf_status_subscription(&self, sub: Option<NrfStatusSubscription>) {
        if let Ok(mut slot) = self.nrf_status_subscription.write() {
            *slot = sub;
        }
    }

    /// The NRF collector configuration, if `main()` armed it (G2-1).
    pub fn nrf_collector_config(&self) -> Option<NrfCollectorConfig> {
        self.nrf_collector_config
            .read()
            .ok()
            .and_then(|c| c.clone())
    }

    /// Arm the NRF collector (G2-1): stores where to subscribe and the
    /// callback URI the NRF must POST NFStatusNotify to.
    /// Record this NF's own SBI base URI (issue #109).
    pub fn set_sbi_base_uri(&self, base: impl Into<String>) {
        if let Ok(mut guard) = self.sbi_base_uri.write() {
            *guard = Some(base.into());
        }
    }

    /// This NF's own SBI base URI.
    ///
    /// Falls back to a loopback default when `main()` has not set one (unit
    /// tests). That is a *local* address rather than a plausible-looking remote
    /// one on purpose: a URL that only resolves on this host is obviously wrong
    /// in a deployment, whereas the old `http://nwdaf/...` placeholder looked
    /// routable and silently 404'd.
    pub fn sbi_base_uri(&self) -> String {
        self.sbi_base_uri
            .read()
            .ok()
            .and_then(|guard| guard.clone())
            .unwrap_or_else(|| "http://127.0.0.1:7777".to_string())
    }

    /// The ONNX artefact for the active prediction model, or `None` when that
    /// model has no fixed-window linear form and so cannot be provisioned
    /// (issue #109).
    ///
    /// `None` is the signal that `nnwdaf-mlmodelprovision` must not be
    /// advertised and no `mLModelUrl` emitted.
    pub fn active_model_onnx(&self) -> Option<Vec<u8>> {
        let engine = self.lock_engine();
        crate::ml_service::active_model_onnx(engine.predictor())
    }

    /// Whether this NWDAF can currently provision a model artefact.
    pub fn can_provision_model(&self) -> bool {
        let engine = self.lock_engine();
        engine.predictor().linear_form().is_some()
    }

    pub fn set_nrf_collector_config(&self, config: NrfCollectorConfig) {
        if let Ok(mut slot) = self.nrf_collector_config.write() {
            *slot = Some(config);
        }
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

    /// Last observed analytic level for a `(subscription, event, instance)`, or
    /// `None` if this is the first observation (nwafd-07 edge detection).
    pub fn get_event_level(
        &self,
        subscription_id: &str,
        event: AnalyticsId,
        nf_instance_id: &str,
    ) -> Option<f64> {
        let key = event_level_key(subscription_id, event, nf_instance_id);
        self.event_levels.read().ok()?.get(&key).copied()
    }

    /// Record the latest observed analytic level for a
    /// `(subscription, event, instance)`.
    pub fn set_event_level(
        &self,
        subscription_id: &str,
        event: AnalyticsId,
        nf_instance_id: &str,
        level: f64,
    ) {
        let key = event_level_key(subscription_id, event, nf_instance_id);
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
                    // Issue #108: a subscription that has just hit a stop
                    // condition stays visible until its termCause notification
                    // has gone out, otherwise it disappears silently — which is
                    // the defect. `is_due_for_notification` still gates the
                    // ordinary reports, so a terminating subscription emits its
                    // termination and nothing else.
                    .filter(|s| {
                        s.active && (s.termination_cause().is_none() || !s.termination_notified)
                    })
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
                // Issue #108: counted here rather than at the send site so a
                // failed delivery does not consume one of `maxReportNbr`.
                sub.reports_sent = sub.reports_sent.saturating_add(1);
            }
        }
    }

    /// Mark a subscription's termination notification as delivered, so the
    /// `termCause` report is emitted exactly once (issue #108).
    pub fn mark_subscription_terminated(&self, subscription_id: &str) {
        if let Ok(mut subs) = self.analytics_subscriptions.write() {
            if let Some(sub) = subs.get_mut(subscription_id) {
                sub.termination_notified = true;
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
            // Issue #108: the remaining nine `NwdafEvent` tokens, completing the
            // enumeration at 25. Read off
            // TS29520_Nnwdaf_EventsSubscription.yaml, not inferred.
            "PFD_DETERMINATION",
            "E2E_DATA_VOL_TRANS_TIME",
            "MOVEMENT_BEHAVIOUR",
            "LOC_ACCURACY",
            "RELATIVE_PROXIMITY",
            "SIGNALLING_STORM",
            "QOS_POLICY_ASSIST",
            "ABNORMAL_UP_TRAFFIC",
            "TRAFFIC_PATTERN",
        ];
        assert_eq!(
            tokens.len(),
            25,
            "TS 29.520 NwdafEvent defines exactly 25 tokens"
        );

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

    /// **The issue #175 table test.** `EventId` and `NwdafEvent` are DIFFERENT
    /// enumerations, and each parse/emit pair is pinned against its own yaml so
    /// the two cannot drift back together.
    ///
    /// Sources: `TS29520_Nnwdaf_AnalyticsInfo.yaml:939-1004` (`EventId`, 24
    /// values, the type of the `event-id` query parameter at `yaml:35-40`) and
    /// `TS29520_Nnwdaf_EventsSubscription.yaml` (`NwdafEvent`, 25 values).
    #[test]
    fn test_event_id_and_nwdaf_event_are_distinct_enums() {
        // The EventId enumeration, transcribed from the yaml in its own order.
        let event_id_tokens = [
            "LOAD_LEVEL_INFORMATION",
            "NETWORK_PERFORMANCE",
            "NF_LOAD",
            "SERVICE_EXPERIENCE",
            "UE_MOBILITY",
            "UE_COMMUNICATION",
            "QOS_SUSTAINABILITY",
            "ABNORMAL_BEHAVIOUR",
            "USER_DATA_CONGESTION",
            "NSI_LOAD_LEVEL",
            "SM_CONGESTION",
            "DISPERSION",
            "RED_TRANS_EXP",
            "WLAN_PERFORMANCE",
            "DN_PERFORMANCE",
            "PDU_SESSION_TRAFFIC",
            "E2E_DATA_VOL_TRANS_TIME",
            "MOVEMENT_BEHAVIOUR",
            "LOC_ACCURACY",
            "RELATIVE_PROXIMITY",
            "SIGNALLING_STORM",
            "QOS_POLICY_ASSIST",
            "TRAFFIC_PATTERN",
            "ABNORMAL_UP_TRAFFIC",
        ];
        assert_eq!(event_id_tokens.len(), 24, "EventId defines 24 values");
        assert_eq!(AnalyticsId::ALL.len(), 25, "NwdafEvent defines 25");

        // Every EventId value is accepted on the AnalyticsInfo surface.
        for t in event_id_tokens {
            assert!(
                AnalyticsId::from_event_id(t).is_some(),
                "EventId value {t} must be accepted as an event-id"
            );
        }

        // The two NwdafEvent-only spellings are REJECTED there: accepting a token
        // the called API does not define is the mirror image of the #175 defect.
        assert_eq!(AnalyticsId::from_event_id("SLICE_LOAD_LEVEL"), None);
        assert_eq!(AnalyticsId::from_event_id("PFD_DETERMINATION"), None);
        // ...while both remain valid NwdafEvent values on the notify surface.
        assert_eq!(
            AnalyticsId::from_str("SLICE_LOAD_LEVEL"),
            Some(AnalyticsId::SliceLoadLevel)
        );
        assert_eq!(
            AnalyticsId::from_str("PFD_DETERMINATION"),
            Some(AnalyticsId::PfdDetermination)
        );
        // And LOAD_LEVEL_INFORMATION is NOT a NwdafEvent value.
        assert_eq!(AnalyticsId::from_str("LOAD_LEVEL_INFORMATION"), None);

        // The one token whose spelling differs between the enums.
        assert_eq!(
            AnalyticsId::from_event_id("LOAD_LEVEL_INFORMATION"),
            Some(AnalyticsId::SliceLoadLevel),
            "LOAD_LEVEL_INFORMATION is EventId's name for slice load level"
        );
        assert_eq!(
            AnalyticsId::SliceLoadLevel.as_event_id(),
            Some("LOAD_LEVEL_INFORMATION")
        );
        assert_eq!(AnalyticsId::SliceLoadLevel.as_str(), "SLICE_LOAD_LEVEL");

        // PFD_DETERMINATION has no EventId spelling at all.
        assert_eq!(AnalyticsId::PfdDetermination.as_event_id(), None);

        // Exact inverse: as_event_id round-trips for every token that has one,
        // and the 24 emitted spellings are exactly the EventId enumeration with
        // no token sharing another's spelling.
        let mut emitted: Vec<&str> = Vec::new();
        for event in AnalyticsId::ALL {
            match event.as_event_id() {
                Some(token) => {
                    assert_eq!(
                        AnalyticsId::from_event_id(token),
                        Some(*event),
                        "as_event_id/from_event_id must be inverses for {}",
                        event.as_str()
                    );
                    emitted.push(token);
                }
                None => assert_eq!(
                    *event,
                    AnalyticsId::PfdDetermination,
                    "only PFD_DETERMINATION lacks an EventId spelling, not {}",
                    event.as_str()
                ),
            }
        }
        emitted.sort_unstable();
        let mut expected = event_id_tokens;
        expected.sort_unstable();
        assert_eq!(
            emitted, expected,
            "the emitted EventId spellings must be exactly the EventId enumeration"
        );

        // Every token still round-trips on the NwdafEvent surface (#108's
        // contract is untouched by the new pair).
        for event in AnalyticsId::ALL {
            assert_eq!(AnalyticsId::from_str(event.as_str()), Some(*event));
        }
    }

    /// **The issue #172 table test.** Every token's payload member name is
    /// pinned against BOTH TS 29.520 schemas, transcribed from the yaml rather
    /// than inferred, so the next added collector cannot inherit a wrong key.
    ///
    /// The table below is the whole point: the two service APIs name the same
    /// analytics differently for four tokens, which is why one shared
    /// `infos_key()` was necessarily wrong on one surface or the other. Sources:
    /// `TS29520_Nnwdaf_EventsSubscription.yaml:802-966` (`EventNotification`) and
    /// `TS29520_Nnwdaf_AnalyticsInfo.yaml:212-361` (`AnalyticsData`).
    #[test]
    fn test_infos_keys_match_the_spec_for_every_token() {
        // (token, EventNotification member, AnalyticsData member or None)
        let spec: &[(AnalyticsId, &str, Option<&str>)] = &[
            (
                AnalyticsId::NfLoad,
                "nfLoadLevelInfos",
                Some("nfLoadLevelInfos"),
            ),
            (AnalyticsId::NetworkPerformance, "nwPerfs", Some("nwPerfs")),
            (AnalyticsId::UeMobility, "ueMobs", Some("ueMobs")),
            (AnalyticsId::UeCommunication, "ueComms", Some("ueComms")),
            (
                AnalyticsId::AbnormalBehaviour,
                "abnorBehavrs",
                Some("abnorBehavrs"),
            ),
            (AnalyticsId::ServiceExperience, "svcExps", Some("svcExps")),
            (
                AnalyticsId::QosSustainability,
                "qosSustainInfos",
                Some("qosSustainInfos"),
            ),
            // ── the four #172 divergences ─────────────────────────────────────
            // Shape differs too: singular OBJECT on notify, array in AnalyticsData.
            (
                AnalyticsId::SliceLoadLevel,
                "sliceLoadLevelInfo",
                Some("sliceLoadLevelInfos"),
            ),
            // Was sharing SLICE_LOAD_LEVEL's member; it has its own on both.
            (
                AnalyticsId::NsiLoadLevel,
                "nsiLoadLevelInfos",
                Some("nsiLoadLevelInfos"),
            ),
            // Was `wlanPerfInfos`, which neither schema defines.
            (AnalyticsId::WlanPerformance, "wlanInfos", Some("wlanInfos")),
            // Was `smcInfos`, which neither schema defines.
            (AnalyticsId::SmCongestion, "smccExps", Some("smccExps")),
            // ── divergences #172 did not list, found by diffing both schemas ──
            (
                AnalyticsId::QosPolicyAssist,
                "qosPolAssistInfos",
                Some("qosPlyAsstInfos"),
            ),
            (
                AnalyticsId::AbnormalUpTraffic,
                "abnormalTrafficInfos",
                Some("abnormalTraffic"),
            ),
            // Not an `EventId` value at all → no AnalyticsData member exists.
            (AnalyticsId::PfdDetermination, "pfdDetermInfos", None),
            // ── the rest, identical on both surfaces ──────────────────────────
            (
                AnalyticsId::UserDataCongestion,
                "userDataCongInfos",
                Some("userDataCongInfos"),
            ),
            (AnalyticsId::Dispersion, "disperInfos", Some("disperInfos")),
            (
                AnalyticsId::RedTransExp,
                "redTransInfos",
                Some("redTransInfos"),
            ),
            (
                AnalyticsId::DnPerformance,
                "dnPerfInfos",
                Some("dnPerfInfos"),
            ),
            (
                AnalyticsId::PduSessionTraffic,
                "pduSesTrafInfos",
                Some("pduSesTrafInfos"),
            ),
            (
                AnalyticsId::E2eDataVolTransTime,
                "dataVlTrnsTmInfos",
                Some("dataVlTrnsTmInfos"),
            ),
            (
                AnalyticsId::MovementBehaviour,
                "movBehavInfos",
                Some("movBehavInfos"),
            ),
            (AnalyticsId::LocAccuracy, "locAccInfos", Some("locAccInfos")),
            (
                AnalyticsId::RelativeProximity,
                "relProxInfos",
                Some("relProxInfos"),
            ),
            (
                AnalyticsId::SignallingStorm,
                "signalStormInfos",
                Some("signalStormInfos"),
            ),
            (
                AnalyticsId::TrafficPattern,
                "trafficPatternInfos",
                Some("trafficPatternInfos"),
            ),
        ];

        assert_eq!(
            spec.len(),
            AnalyticsId::ALL.len(),
            "the spec table must cover every recognised NwdafEvent token"
        );

        for (event, notify_key, data_key) in spec {
            assert_eq!(
                event.notification_infos_key(),
                *notify_key,
                "{} EventNotification member",
                event.as_str()
            );
            assert_eq!(
                event.analytics_data_key(),
                *data_key,
                "{} AnalyticsData member",
                event.as_str()
            );
        }

        // Bijection: 25 distinct EventNotification members (its other 11
        // properties are envelope fields), and 24 distinct AnalyticsData ones —
        // no token may silently share another's member, which is the defect that
        // hid NSI_LOAD_LEVEL behind SLICE_LOAD_LEVEL.
        let notify: std::collections::BTreeSet<&str> = AnalyticsId::ALL
            .iter()
            .map(|e| e.notification_infos_key())
            .collect();
        assert_eq!(notify.len(), 25, "every token needs its OWN notify member");
        let data: std::collections::BTreeSet<&str> = AnalyticsId::ALL
            .iter()
            .filter_map(|e| e.analytics_data_key())
            .collect();
        assert_eq!(
            data.len(),
            24,
            "24 AnalyticsData members: every token but PFD_DETERMINATION, none shared"
        );

        // Only SLICE_LOAD_LEVEL's notify payload is a single object.
        for event in AnalyticsId::ALL {
            assert_eq!(
                event.notification_payload_is_single_object(),
                *event == AnalyticsId::SliceLoadLevel,
                "{} payload shape",
                event.as_str()
            );
        }

        // The pre-#172 spellings are gone from both surfaces.
        for wrong in ["wlanPerfInfos", "smcInfos"] {
            assert!(
                !notify.contains(wrong) && !data.contains(wrong),
                "{wrong} is not defined by either schema"
            );
        }
    }

    /// G2-3 honesty: `SUPPORTED_EVENTS` is non-empty, a strict subset of the
    /// recognised `NwdafEvent` tokens, and `is_supported()` reads it — the
    /// single source of truth the three wire surfaces derive from.
    #[test]
    fn test_honesty_supported_events_single_source_of_truth() {
        assert!(
            !SUPPORTED_EVENTS.is_empty(),
            "at least one supported event (NF_LOAD has a live G2-1 collector)"
        );
        for e in SUPPORTED_EVENTS {
            assert!(
                AnalyticsId::ALL.contains(e),
                "every supported event must be a recognised NwdafEvent"
            );
            assert!(e.is_supported(), "is_supported must read SUPPORTED_EVENTS");
        }
        // Initially exactly NF_LOAD (G2-3): update this alongside a new
        // collector, never independently.
        assert_eq!(SUPPORTED_EVENTS, &[AnalyticsId::NfLoad]);
        // A collector-less event must NOT claim support.
        assert!(!AnalyticsId::UeMobility.is_supported());
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

    /// Issue #108: a subscription terminates for a NAMED reason, and the two
    /// reasons are distinguishable — `maxReportNbr` reached vs monitoring
    /// duration elapsed. Before this it just vanished with no `termCause`, so a
    /// consumer could not tell a deliberate termination from a lost subscription.
    #[test]
    fn test_termination_cause_is_named_and_distinguishes_its_two_reasons() {
        let live = |max: Option<u64>, sent: u64| {
            let mut sub = AnalyticsSubscription::new(
                "s1".into(),
                AnalyticsId::NfLoad,
                "http://x/y".into(),
                u64::MAX, // not expired
            );
            sub.max_report_nbr = max;
            sub.reports_sent = sent;
            sub
        };

        // Live: no cause, and reporting is due.
        let sub = live(Some(3), 1);
        assert_eq!(sub.termination_cause(), None);
        assert!(sub.is_due_for_notification());

        // maxReportNbr reached → that cause, and no longer due.
        let sub = live(Some(3), 3);
        assert_eq!(
            sub.termination_cause(),
            Some(TerminationCause::MaxNumberOfReportsReached)
        );
        assert!(
            !sub.is_due_for_notification(),
            "maxReportNbr is a stop condition, not just a counter"
        );

        // Monitoring duration elapsed → the other cause.
        let mut expired = live(None, 0);
        expired.expiry = 1; // 1970
        assert_eq!(
            expired.termination_cause(),
            Some(TerminationCause::MonitoringDurationExpiry)
        );

        // The two are distinct on the wire.
        assert_eq!(
            TerminationCause::MaxNumberOfReportsReached.as_str(),
            "MAX_NUMBER_OF_REPORTS_REACHED"
        );
        assert_eq!(
            TerminationCause::MonitoringDurationExpiry.as_str(),
            "MONITORING_DURATION_EXPIRY"
        );

        // Unlimited reporting never terminates on count.
        let unlimited = live(None, 10_000);
        assert_eq!(unlimited.termination_cause(), None);
    }

    /// Issue #108: a terminating subscription must stay visible until its
    /// termCause notification has gone out — disappearing silently is the defect.
    #[test]
    fn test_terminating_subscription_stays_visible_until_notified() {
        let mut ctx = NwdafContext::new("nwdaf-test".to_string());
        ctx.init(100);
        let mut sub = AnalyticsSubscription::new(
            "s-term".into(),
            AnalyticsId::NfLoad,
            "http://x/y".into(),
            1, // already expired
        );
        sub.notification_correlation_id = "corr-term".into();
        ctx.add_subscription(sub);

        assert_eq!(
            ctx.get_all_active_subscriptions().len(),
            1,
            "an expired subscription is still listed so its termCause can be sent"
        );

        ctx.mark_subscription_terminated("s-term");
        assert!(
            ctx.get_all_active_subscriptions().is_empty(),
            "once notified it drops out"
        );
    }

    /// A dispatched notification counts against `maxReportNbr` (issue #108).
    #[test]
    fn test_dispatched_notifications_count_against_max_report_nbr() {
        let mut ctx = NwdafContext::new("nwdaf-test".to_string());
        ctx.init(100);
        let mut sub = AnalyticsSubscription::new(
            "s-count".into(),
            AnalyticsId::NfLoad,
            "http://x/y".into(),
            u64::MAX,
        );
        sub.max_report_nbr = Some(2);
        sub.repetition_period_secs = None;
        ctx.add_subscription(sub);

        ctx.update_subscription_last_notification("s-count");
        assert_eq!(ctx.get_subscription("s-count").unwrap().reports_sent, 1);
        assert_eq!(
            ctx.get_subscription("s-count").unwrap().termination_cause(),
            None
        );

        ctx.update_subscription_last_notification("s-count");
        assert_eq!(ctx.get_subscription("s-count").unwrap().reports_sent, 2);
        assert_eq!(
            ctx.get_subscription("s-count").unwrap().termination_cause(),
            Some(TerminationCause::MaxNumberOfReportsReached),
            "the second report reaches the limit"
        );
    }

    /// nwafd-07: per-(subscription, event, instance) level state round-trips and
    /// is keyed so nothing on the same subscription collides.
    #[test]
    fn test_event_level_state() {
        let ctx = NwdafContext::new("nwdaf-test".to_string());
        assert_eq!(
            ctx.get_event_level("s1", AnalyticsId::NfLoad, "amf-1"),
            None
        );
        ctx.set_event_level("s1", AnalyticsId::NfLoad, "amf-1", 42.0);
        ctx.set_event_level("s1", AnalyticsId::UeMobility, "amf-1", 7.0);
        assert_eq!(
            ctx.get_event_level("s1", AnalyticsId::NfLoad, "amf-1"),
            Some(42.0)
        );
        assert_eq!(
            ctx.get_event_level("s1", AnalyticsId::UeMobility, "amf-1"),
            Some(7.0)
        );
        assert_eq!(
            ctx.get_event_level("s2", AnalyticsId::NfLoad, "amf-1"),
            None
        );

        // Issue #108: two instances under ONE subscription+event must not share
        // edge state, or ASCENDING/DESCENDING fires on the wrong history.
        ctx.set_event_level("s1", AnalyticsId::NfLoad, "amf-2", 99.0);
        assert_eq!(
            ctx.get_event_level("s1", AnalyticsId::NfLoad, "amf-1"),
            Some(42.0),
            "the second instance must not overwrite the first"
        );
        assert_eq!(
            ctx.get_event_level("s1", AnalyticsId::NfLoad, "amf-2"),
            Some(99.0)
        );
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
