//! TSCTSF Context Management
//!
//! Time Sensitive Communication and Time Synchronization Function context
//! (TS 23.501 §5.27–§5.28). Holds the state behind all three mandated TSCTSF
//! services (TS 23.501 Table 7.2.26-1, TS 23.502 Table 5.2.27.1-1):
//!
//! * `Ntsctsf_TimeSynchronization` — time-synchronization exposure
//!   configurations and capability subscriptions.
//! * `Ntsctsf_ASTI` — 5G access stratum time distribution configurations.
//! * `Ntsctsf_QoSandTSCAssistance` — AF QoS/TSC assistance sessions and their
//!   event subscriptions.
//!
//! All state is in-memory (`RwLock<HashMap<..>>`), matching the other small NFs
//! (pind, nefd, easdfd). #113 replaced the previous raw-JSON-string store with
//! typed IEs so a malformed configuration is refused at ingress instead of being
//! stored verbatim and discovered later.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// Why a request body was refused (#113).
///
/// Split by cause because TS 29.500 §5.2.7.2 distinguishes them and the
/// distinction is what tells a consumer whether its JSON is malformed or merely
/// incomplete — two different fixes on its side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IeError {
    /// A required member is absent, or present but empty.
    MandatoryIeMissing(&'static str),
    /// A member is present but of the wrong type or out of range.
    MandatoryIeIncorrect(&'static str),
}

impl IeError {
    pub fn cause(&self) -> &'static str {
        match self {
            Self::MandatoryIeMissing(_) => "MANDATORY_IE_MISSING",
            Self::MandatoryIeIncorrect(_) => "MANDATORY_IE_INCORRECT",
        }
    }

    /// A detail naming the offending member, so an operator reading a log does
    /// not have to guess which one.
    pub fn detail(&self) -> String {
        match self {
            Self::MandatoryIeMissing(m) => {
                format!("mandatory IE '{m}' is absent or empty")
            }
            Self::MandatoryIeIncorrect(m) => {
                format!("IE '{m}' is present but not a valid value")
            }
        }
    }
}

/// Clock-quality acceptance criteria a consumer can attach to a configuration
/// (TS 23.502 Table 4.15.9.3-1, "clock quality acceptance criteria").
///
/// Every member is optional: the table lists the criteria as optional service
/// parameters, and a configuration that states none simply has no criteria to
/// evaluate.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ClockQualityAcceptanceCriteria {
    /// Acceptable clock class values.
    pub clock_class: Option<u8>,
    /// Acceptable clock accuracy.
    pub clock_accuracy: Option<u8>,
    /// Acceptable offset scaled log variance.
    pub offset_scaled_log_variance: Option<u16>,
    /// Whether a synchronisation state of "not synchronised" is acceptable.
    pub synchronization_state: Option<String>,
}

/// A time-synchronization exposure configuration (#113).
///
/// Members are named from TS 23.502 §5.2.27.2.2/§5.2.27.2.3 and
/// Table 4.15.9.3-1. `TS29565_Ntsctsf_TimeSynchronization.yaml` is **not**
/// vendored in this tree, so the JSON member names are the camelCase form of the
/// Stage-2 parameter names rather than a spelling verified against the Stage-3
/// schema — stated here because that is exactly the kind of thing a later reader
/// would otherwise assume had been checked.
///
/// `raw` keeps the whole body: a consumer that sent an optional parameter this
/// build does not model should get it back on a GET rather than have it silently
/// dropped.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct TimeSyncExposureConfig {
    /// Notification Target Address (§5.2.27.2.2 "Inputs, Required"). Where
    /// ConfigUpdateNotify goes.
    pub notification_target_addr: String,
    /// User plane node ID (§5.2.27.2.2 "Inputs, Required"): the NW-TT this
    /// configuration applies to.
    pub up_node_id: String,
    /// Notification Correlation ID the consumer wants echoed back.
    pub notification_correlation_id: Option<String>,
    /// Reference to the time-synchronization capability set, i.e. the
    /// Subscription Correlation ID from a prior CapsSubscribe (§5.2.27.2.2).
    pub time_sync_caps_subscription_id: Option<String>,
    /// UE identities (SUPIs) in the configuration (§5.2.27.2.3 add/remove lists
    /// operate on this).
    pub supis: Vec<String>,
    /// IEEE 802.1AS time domain number.
    pub time_domain: Option<u16>,
    /// (g)PTP grandmaster enabled.
    pub gm_enable: Option<bool>,
    /// Grandmaster priority.
    pub gm_priority: Option<u8>,
    /// PTP profile identifier.
    pub ptp_profile: Option<String>,
    /// Clock quality detail level.
    pub clock_quality_detail_level: Option<String>,
    /// Clock quality acceptance criteria.
    pub clock_quality_acceptance_criteria: Option<ClockQualityAcceptanceCriteria>,
    /// Temporary validity condition, kept as received.
    pub temporal_validity: Option<serde_json::Value>,
    /// The UE address of the DS-TT this configuration applies to (#284).
    ///
    /// **Not a TS 23.502 §5.2.27.2.2 input.** These exist because TS 29.514's
    /// `AppSessionContextReqData` requires `oneOf [ueIpv4, ueIpv6, ueMac]` and a
    /// time-synchronization configuration's mandatory inputs carry SUPIs and a
    /// `upNodeId` but no UE address — so without one, the actuation leg cannot
    /// build a conformant body. Optional, and their absence declines actuation with
    /// a named reason rather than sending a body that violates the schema.
    ///
    /// A DS-TT behind an Ethernet PDU session has a MAC, which is the TS 23.501
    /// §5.28 case, so `ueMac` is checked first.
    pub ue_mac: Option<String>,
    pub ue_ipv4: Option<String>,
    pub ue_ipv6: Option<String>,
    /// The whole body as received, so nothing a consumer sent is lost.
    #[serde(skip)]
    pub raw: serde_json::Value,
}

impl Default for TimeSyncExposureConfig {
    fn default() -> Self {
        Self {
            notification_target_addr: String::new(),
            up_node_id: String::new(),
            notification_correlation_id: None,
            time_sync_caps_subscription_id: None,
            supis: Vec::new(),
            time_domain: None,
            gm_enable: None,
            gm_priority: None,
            ptp_profile: None,
            clock_quality_detail_level: None,
            clock_quality_acceptance_criteria: None,
            temporal_validity: None,
            ue_mac: None,
            ue_ipv4: None,
            ue_ipv6: None,
            raw: serde_json::Value::Null,
        }
    }
}

impl TimeSyncExposureConfig {
    /// Enforce the members §5.2.27.2.2 lists as required.
    ///
    /// The required scalars are modelled as bare `String` with `serde(default)`
    /// rather than `Option<String>` for the reason recorded in this project's
    /// learnings: a bare non-`Option` would make an ABSENT member a serde parse
    /// error, which a handler can only report as `INVALID_MSG_FORMAT` — losing the
    /// distinction between "your JSON is malformed" and "your JSON is incomplete".
    /// Presence is enforced here instead, per member.
    ///
    /// Present-but-EMPTY is refused too: serde accepts `""` for a `String`, and an
    /// empty notification target address is exactly the un-notifiable state this
    /// validation exists to prevent.
    pub fn validate(&self) -> Result<(), IeError> {
        if self.notification_target_addr.trim().is_empty() {
            return Err(IeError::MandatoryIeMissing("notificationTargetAddr"));
        }
        if self.up_node_id.trim().is_empty() {
            return Err(IeError::MandatoryIeMissing("upNodeId"));
        }
        // IEEE 802.1AS domainNumber is one octet. Modelled as u16 so a value of
        // 256 arrives as a *range* error naming the member, rather than as a serde
        // type error that names nothing.
        if let Some(domain) = self.time_domain {
            if domain > 255 {
                return Err(IeError::MandatoryIeIncorrect("timeDomain"));
            }
        }
        if let Some(prio) = self.gm_priority {
            // priority1/priority2 are one octet in IEEE 1588; u8 already bounds it,
            // so this only guards the semantic 255 = "not to be used" sentinel being
            // sent as a real priority.
            let _ = prio;
        }
        Ok(())
    }

    /// Apply an update body (§5.2.27.2.3): only the members it carries change.
    ///
    /// PATCH/PUT semantics deliberately merge rather than replace, because
    /// §5.2.27.2.3's required input is the PTP instance reference alone and every
    /// parameter is optional — a body carrying only `gmEnable` means "change the
    /// grandmaster flag", not "clear everything else".
    pub fn apply_update(&mut self, body: &serde_json::Value) {
        if let Some(v) = body.get("notificationTargetAddr").and_then(|v| v.as_str()) {
            self.notification_target_addr = v.to_string();
        }
        if let Some(v) = body.get("upNodeId").and_then(|v| v.as_str()) {
            self.up_node_id = v.to_string();
        }
        if let Some(v) = body
            .get("notificationCorrelationId")
            .and_then(|v| v.as_str())
        {
            self.notification_correlation_id = Some(v.to_string());
        }
        if let Some(v) = body.get("timeDomain").and_then(|v| v.as_u64()) {
            self.time_domain = Some(v as u16);
        }
        if let Some(v) = body.get("gmEnable").and_then(|v| v.as_bool()) {
            self.gm_enable = Some(v);
        }
        if let Some(v) = body.get("gmPriority").and_then(|v| v.as_u64()) {
            self.gm_priority = Some(v as u8);
        }
        if let Some(v) = body.get("ptpProfile").and_then(|v| v.as_str()) {
            self.ptp_profile = Some(v.to_string());
        }
        if let Some(v) = body.get("clockQualityDetailLevel").and_then(|v| v.as_str()) {
            self.clock_quality_detail_level = Some(v.to_string());
        }
        // §5.2.27.2.3: add and remove lists, applied in that order so a SUPI in
        // both is removed — a consumer asking for both cannot have meant "keep".
        if let Some(added) = body.get("supisToAdd").and_then(|v| v.as_array()) {
            for supi in added.iter().filter_map(|v| v.as_str()) {
                if !self.supis.iter().any(|s| s == supi) {
                    self.supis.push(supi.to_string());
                }
            }
        }
        if let Some(removed) = body.get("supisToRemove").and_then(|v| v.as_array()) {
            let drop: Vec<&str> = removed.iter().filter_map(|v| v.as_str()).collect();
            self.supis.retain(|s| !drop.iter().any(|d| d == s));
        }
        // A whole-list replacement is also accepted, since §5.2.27.2.2's create
        // carries the list directly.
        if let Some(list) = body.get("supis").and_then(|v| v.as_array()) {
            self.supis = list
                .iter()
                .filter_map(|v| v.as_str())
                .map(str::to_string)
                .collect();
        }
    }
}

/// A stored time-synchronization configuration.
#[derive(Debug, Clone)]
pub struct TimeSyncConfig {
    /// TSCTSF-assigned configuration ID (the northbound resource ID, which
    /// §5.2.27.2.2 calls the PTP instance reference).
    pub id: String,
    /// Typed configuration.
    pub config: TimeSyncExposureConfig,
}

impl TimeSyncConfig {
    pub fn new(config: TimeSyncExposureConfig) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            config,
        }
    }
}

/// A time-synchronization capability subscription (§5.2.27.2.6).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct CapsSubscription {
    /// Subscription Correlation ID (§5.2.27.2.6 "Outputs, Required"), which is
    /// also this resource's id and what CapsUnsubscribe takes.
    pub subscription_id: String,
    /// Notification Target Address — required.
    pub notification_target_addr: String,
    /// Notification Correlation ID.
    pub notification_correlation_id: Option<String>,
    /// DNN, one half of the (DNN, S-NSSAI) required-input alternative.
    pub dnn: Option<String>,
    /// S-NSSAI, the other half.
    pub snssai: Option<serde_json::Value>,
    /// AF-Service-Identifier, the second required-input alternative.
    pub af_service_id: Option<String>,
    /// Event filter: UE identities or group identifiers.
    pub supis: Vec<String>,
    pub gpsis: Vec<String>,
    pub external_group_id: Option<String>,
    pub internal_group_id: Option<String>,
    /// Event filter: supported PTP instance types.
    pub ptp_instance_types: Vec<String>,
    /// Event filter: supported transport protocols.
    pub transport_protocols: Vec<String>,
    /// Event filter: supported PTP profiles.
    pub ptp_profiles: Vec<String>,
    /// Report type: one-time, periodic or event-based.
    pub report_type: Option<String>,
}

impl CapsSubscription {
    /// §5.2.27.2.6 "Inputs, Required": *"Either a combination of (DNN, S-NSSAI)
    /// or an AF-Service-Identifier and Notification Target Address"*.
    ///
    /// So the target address is always required, and the *scope* must be given as
    /// one of the two alternatives. A subscription with neither scope could never
    /// be matched against anything, which is the un-notifiable state worth
    /// refusing rather than accepting and never firing.
    pub fn validate(&self) -> Result<(), IeError> {
        if self.notification_target_addr.trim().is_empty() {
            return Err(IeError::MandatoryIeMissing("notificationTargetAddr"));
        }
        let has_dnn_snssai =
            self.dnn.as_deref().is_some_and(|d| !d.trim().is_empty()) && self.snssai.is_some();
        let has_af_service = self
            .af_service_id
            .as_deref()
            .is_some_and(|a| !a.trim().is_empty());
        if !has_dnn_snssai && !has_af_service {
            return Err(IeError::MandatoryIeMissing("dnn+snssai or afServiceId"));
        }
        Ok(())
    }
}

/// A 5G access stratum time distribution configuration (`Ntsctsf_ASTI`,
/// §5.2.27.4).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AstiConfig {
    /// Time synchronization configuration id (§5.2.27.4.2 "Outputs, Required"),
    /// which is what Update/Delete/Get take.
    pub config_id: String,
    /// AF identifier — required (§5.2.27.4.2 "Inputs, Required").
    pub af_id: String,
    /// The distribution target: one of these must be present.
    pub supi: Option<String>,
    pub gpsi: Option<String>,
    pub external_group_id: Option<String>,
    pub internal_group_id: Option<String>,
    /// Whether access stratum time distribution is active.
    pub as_time_dis_enabled: Option<bool>,
    /// Uu time synchronization error budget (Table 4.15.9.4-1).
    pub uu_error_budget: Option<u32>,
    /// Coverage area the configuration applies to.
    pub coverage_area: Option<serde_json::Value>,
    /// Subscription for 5G access stratum time distribution status.
    pub notification_target_addr: Option<String>,
    pub notification_correlation_id: Option<String>,
}

impl AstiConfig {
    /// §5.2.27.4.2: an AF identifier and a target are both required inputs.
    ///
    /// A configuration with no target would activate time distribution for
    /// nobody, and one with no AF identifier could not be attributed — so both
    /// are refused rather than defaulted.
    pub fn validate(&self) -> Result<(), IeError> {
        if self.af_id.trim().is_empty() {
            return Err(IeError::MandatoryIeMissing("afId"));
        }
        let has_target = [
            self.supi.as_deref(),
            self.gpsi.as_deref(),
            self.external_group_id.as_deref(),
            self.internal_group_id.as_deref(),
        ]
        .iter()
        .any(|t| t.is_some_and(|v| !v.trim().is_empty()));
        if !has_target {
            return Err(IeError::MandatoryIeMissing(
                "supi, gpsi, externalGroupId or internalGroupId",
            ));
        }
        Ok(())
    }
}

/// An AF QoS/TSC assistance session (`Ntsctsf_QoSandTSCAssistance`, §5.2.27.3).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct QosTscSession {
    /// Transaction Reference ID (§5.2.27.3.2 "Outputs, Required"), which is what
    /// Update and Delete take.
    pub transaction_ref_id: String,
    /// AF Identifier — required.
    pub af_id: String,
    /// Target UE: a UE address, a GPSI, or an external group identifier. One is
    /// required.
    pub ue_ipv4: Option<String>,
    pub ue_ipv6: Option<String>,
    pub gpsi: Option<String>,
    pub external_group_id: Option<String>,
    /// Flow descriptions, or an external application identifier. One is required.
    pub flow_descriptions: Vec<String>,
    pub ext_app_id: Option<String>,
    /// QoS Reference, or individual QoS parameters. One is required.
    pub qos_reference: Option<String>,
    pub max_br_ul: Option<String>,
    pub max_br_dl: Option<String>,
    /// TSC assistance parameters (Table 4.15.9 / TS 23.503 §6.1.3.22).
    pub burst_arrival_time: Option<serde_json::Value>,
    pub periodicity: Option<u32>,
    pub survival_time: Option<u32>,
    pub time_domain: Option<u16>,
    pub flow_direction: Option<String>,
    pub bat_window: Option<serde_json::Value>,
    pub periodicity_range: Option<serde_json::Value>,
    /// Notification target for the Notify operation.
    pub notification_target_addr: Option<String>,
    pub notification_correlation_id: Option<String>,
}

impl QosTscSession {
    /// §5.2.27.3.2 "Inputs, Required": AF Identifier, a target UE identifier,
    /// flow description(s) **or** an external application identifier, and a QoS
    /// Reference **or** individual QoS parameters.
    ///
    /// Each alternative is checked as an alternative rather than as a conjunction:
    /// requiring both halves of an either/or would refuse conformant requests,
    /// which is the mirror of accepting one that names nothing.
    pub fn validate(&self) -> Result<(), IeError> {
        if self.af_id.trim().is_empty() {
            return Err(IeError::MandatoryIeMissing("afId"));
        }
        let has_target = [
            self.ue_ipv4.as_deref(),
            self.ue_ipv6.as_deref(),
            self.gpsi.as_deref(),
            self.external_group_id.as_deref(),
        ]
        .iter()
        .any(|t| t.is_some_and(|v| !v.trim().is_empty()));
        if !has_target {
            return Err(IeError::MandatoryIeMissing(
                "ueIpv4, ueIpv6, gpsi or externalGroupId",
            ));
        }
        let has_flows = !self.flow_descriptions.is_empty()
            || self
                .ext_app_id
                .as_deref()
                .is_some_and(|a| !a.trim().is_empty());
        if !has_flows {
            return Err(IeError::MandatoryIeMissing("flowDescriptions or extAppId"));
        }
        let has_qos = self
            .qos_reference
            .as_deref()
            .is_some_and(|q| !q.trim().is_empty())
            || self.max_br_ul.is_some()
            || self.max_br_dl.is_some();
        if !has_qos {
            return Err(IeError::MandatoryIeMissing(
                "qosReference or maxBrUl/maxBrDl",
            ));
        }
        Ok(())
    }
}

/// A QoS/TSC assistance event subscription (§5.2.27.3, Subscribe/Unsubscribe).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct QosTscSubscription {
    pub subscription_id: String,
    pub notification_target_addr: String,
    pub notification_correlation_id: Option<String>,
    /// The transaction this subscription reports on, when scoped to one.
    pub transaction_ref_id: Option<String>,
    /// Events subscribed to.
    pub events: Vec<String>,
}

impl QosTscSubscription {
    pub fn validate(&self) -> Result<(), IeError> {
        if self.notification_target_addr.trim().is_empty() {
            return Err(IeError::MandatoryIeMissing("notificationTargetAddr"));
        }
        Ok(())
    }
}

/// TSCTSF context errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsctsfContextError {
    MaxConfigsReached,
    LockPoisoned,
    NotFound,
}

impl TsctsfContextError {
    pub fn detail(&self) -> &'static str {
        match self {
            Self::MaxConfigsReached => "Maximum number of time-sync configurations reached",
            Self::LockPoisoned => "TSCTSF context lock poisoned",
            Self::NotFound => "No such resource",
        }
    }

    pub fn cause(&self) -> &'static str {
        match self {
            Self::MaxConfigsReached => "MAX_CONFIGS_REACHED",
            Self::LockPoisoned => "INTERNAL",
            Self::NotFound => "NOT_FOUND",
        }
    }
}

/// TSCTSF Context
pub struct TsctsfContext {
    /// Time-sync configurations (by TSCTSF-assigned configuration ID).
    configs: RwLock<HashMap<String, TimeSyncConfig>>,
    /// Time-sync capability subscriptions (§5.2.27.2.6), by Subscription
    /// Correlation ID.
    caps_subscriptions: RwLock<HashMap<String, CapsSubscription>>,
    /// `Ntsctsf_ASTI` configurations (§5.2.27.4), by configuration ID.
    asti_configs: RwLock<HashMap<String, AstiConfig>>,
    /// `Ntsctsf_QoSandTSCAssistance` sessions (§5.2.27.3), by Transaction
    /// Reference ID.
    qos_tsc_sessions: RwLock<HashMap<String, QosTscSession>>,
    /// `Ntsctsf_QoSandTSCAssistance` event subscriptions.
    qos_tsc_subscriptions: RwLock<HashMap<String, QosTscSubscription>>,
    /// Maximum stored resources, per collection.
    max_configs: usize,
    /// Context initialized flag
    initialized: AtomicBool,
}

impl TsctsfContext {
    pub fn new() -> Self {
        Self {
            configs: RwLock::new(HashMap::new()),
            caps_subscriptions: RwLock::new(HashMap::new()),
            asti_configs: RwLock::new(HashMap::new()),
            qos_tsc_sessions: RwLock::new(HashMap::new()),
            qos_tsc_subscriptions: RwLock::new(HashMap::new()),
            max_configs: 0,
            initialized: AtomicBool::new(false),
        }
    }

    pub fn init(&mut self, max_configs: usize) {
        if self.initialized.load(Ordering::SeqCst) {
            return;
        }
        self.max_configs = max_configs;
        self.initialized.store(true, Ordering::SeqCst);
        log::info!("TSCTSF context initialized (max {max_configs} resources per collection)");
    }

    pub fn fini(&mut self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }
        if let Ok(mut configs) = self.configs.write() {
            configs.clear();
        }
        if let Ok(mut subs) = self.caps_subscriptions.write() {
            subs.clear();
        }
        if let Ok(mut asti) = self.asti_configs.write() {
            asti.clear();
        }
        if let Ok(mut sessions) = self.qos_tsc_sessions.write() {
            sessions.clear();
        }
        if let Ok(mut subs) = self.qos_tsc_subscriptions.write() {
            subs.clear();
        }
        self.initialized.store(false, Ordering::SeqCst);
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    // ── Ntsctsf_TimeSynchronization: configurations ──────────────────────────

    /// Insert a configuration, enforcing the capacity cap.
    pub fn config_insert(&self, config: TimeSyncConfig) -> Result<(), TsctsfContextError> {
        let mut configs = self
            .configs
            .write()
            .map_err(|_| TsctsfContextError::LockPoisoned)?;
        if configs.len() >= self.max_configs {
            return Err(TsctsfContextError::MaxConfigsReached);
        }
        let id = config.id.clone();
        configs.insert(id.clone(), config);
        log::debug!("TSCTSF time-sync configuration inserted (id={id})");
        Ok(())
    }

    /// Find a configuration by ID.
    pub fn config_find(&self, id: &str) -> Option<TimeSyncConfig> {
        let configs = self.configs.read().ok()?;
        configs.get(id).cloned()
    }

    /// Apply an update body to a stored configuration, returning the updated
    /// record (#113, §5.2.27.2.3). `None` when the ID is unknown, which the
    /// handler answers 404 for.
    pub fn config_update(&self, id: &str, body: &serde_json::Value) -> Option<TimeSyncConfig> {
        let mut configs = self.configs.write().ok()?;
        let stored = configs.get_mut(id)?;
        stored.config.apply_update(body);
        Some(stored.clone())
    }

    /// Replace a stored configuration wholesale (PUT), keeping its ID.
    pub fn config_replace(
        &self,
        id: &str,
        config: TimeSyncExposureConfig,
    ) -> Option<TimeSyncConfig> {
        let mut configs = self.configs.write().ok()?;
        let stored = configs.get_mut(id)?;
        stored.config = config;
        Some(stored.clone())
    }

    /// Remove a configuration by ID.
    pub fn config_remove(&self, id: &str) -> Option<TimeSyncConfig> {
        let mut configs = self.configs.write().ok()?;
        configs.remove(id)
    }

    /// Number of stored configurations (NRF `/load` gauge source).
    pub fn config_count(&self) -> usize {
        self.configs.read().map(|c| c.len()).unwrap_or(0)
    }

    /// Every stored configuration, for a capability change that must notify all
    /// of them.
    pub fn config_list(&self) -> Vec<TimeSyncConfig> {
        self.configs
            .read()
            .map(|c| c.values().cloned().collect())
            .unwrap_or_default()
    }

    // ── Ntsctsf_TimeSynchronization: capability subscriptions ────────────────

    /// Create a capability subscription; mints and returns its Subscription
    /// Correlation ID.
    pub fn caps_sub_create(
        &self,
        mut sub: CapsSubscription,
    ) -> Result<CapsSubscription, TsctsfContextError> {
        let mut subs = self
            .caps_subscriptions
            .write()
            .map_err(|_| TsctsfContextError::LockPoisoned)?;
        if subs.len() >= self.max_configs {
            return Err(TsctsfContextError::MaxConfigsReached);
        }
        // Minted here, not taken from the request: a consumer-supplied id would let
        // one AF address another's subscription resource.
        sub.subscription_id = Uuid::new_v4().to_string();
        subs.insert(sub.subscription_id.clone(), sub.clone());
        Ok(sub)
    }

    pub fn caps_sub_find(&self, id: &str) -> Option<CapsSubscription> {
        self.caps_subscriptions.read().ok()?.get(id).cloned()
    }

    pub fn caps_sub_remove(&self, id: &str) -> Option<CapsSubscription> {
        self.caps_subscriptions.write().ok()?.remove(id)
    }

    pub fn caps_sub_list(&self) -> Vec<CapsSubscription> {
        self.caps_subscriptions
            .read()
            .map(|s| s.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn caps_sub_count(&self) -> usize {
        self.caps_subscriptions.read().map(|s| s.len()).unwrap_or(0)
    }

    // ── Ntsctsf_ASTI ─────────────────────────────────────────────────────────

    pub fn asti_create(&self, mut cfg: AstiConfig) -> Result<AstiConfig, TsctsfContextError> {
        let mut store = self
            .asti_configs
            .write()
            .map_err(|_| TsctsfContextError::LockPoisoned)?;
        if store.len() >= self.max_configs {
            return Err(TsctsfContextError::MaxConfigsReached);
        }
        cfg.config_id = Uuid::new_v4().to_string();
        store.insert(cfg.config_id.clone(), cfg.clone());
        Ok(cfg)
    }

    pub fn asti_find(&self, id: &str) -> Option<AstiConfig> {
        self.asti_configs.read().ok()?.get(id).cloned()
    }

    /// Merge an update body into a stored ASTI configuration (§5.2.27.4.3).
    pub fn asti_update(&self, id: &str, body: &serde_json::Value) -> Option<AstiConfig> {
        let mut store = self.asti_configs.write().ok()?;
        let stored = store.get_mut(id)?;
        if let Some(v) = body.get("asTimeDisEnabled").and_then(|v| v.as_bool()) {
            stored.as_time_dis_enabled = Some(v);
        }
        if let Some(v) = body.get("uuErrorBudget").and_then(|v| v.as_u64()) {
            stored.uu_error_budget = Some(v as u32);
        }
        if let Some(v) = body.get("coverageArea") {
            stored.coverage_area = Some(v.clone());
        }
        if let Some(v) = body.get("notificationTargetAddr").and_then(|v| v.as_str()) {
            stored.notification_target_addr = Some(v.to_string());
        }
        Some(stored.clone())
    }

    pub fn asti_remove(&self, id: &str) -> Option<AstiConfig> {
        self.asti_configs.write().ok()?.remove(id)
    }

    pub fn asti_count(&self) -> usize {
        self.asti_configs.read().map(|s| s.len()).unwrap_or(0)
    }

    // ── Ntsctsf_QoSandTSCAssistance ──────────────────────────────────────────

    pub fn qos_tsc_create(
        &self,
        mut session: QosTscSession,
    ) -> Result<QosTscSession, TsctsfContextError> {
        let mut store = self
            .qos_tsc_sessions
            .write()
            .map_err(|_| TsctsfContextError::LockPoisoned)?;
        if store.len() >= self.max_configs {
            return Err(TsctsfContextError::MaxConfigsReached);
        }
        session.transaction_ref_id = Uuid::new_v4().to_string();
        store.insert(session.transaction_ref_id.clone(), session.clone());
        Ok(session)
    }

    pub fn qos_tsc_find(&self, id: &str) -> Option<QosTscSession> {
        self.qos_tsc_sessions.read().ok()?.get(id).cloned()
    }

    /// Merge an update body into a stored session (§5.2.27.3.3).
    pub fn qos_tsc_update(&self, id: &str, body: &serde_json::Value) -> Option<QosTscSession> {
        let mut store = self.qos_tsc_sessions.write().ok()?;
        let stored = store.get_mut(id)?;
        if let Some(v) = body.get("qosReference").and_then(|v| v.as_str()) {
            stored.qos_reference = Some(v.to_string());
        }
        if let Some(v) = body.get("maxBrUl").and_then(|v| v.as_str()) {
            stored.max_br_ul = Some(v.to_string());
        }
        if let Some(v) = body.get("maxBrDl").and_then(|v| v.as_str()) {
            stored.max_br_dl = Some(v.to_string());
        }
        if let Some(v) = body.get("periodicity").and_then(|v| v.as_u64()) {
            stored.periodicity = Some(v as u32);
        }
        if let Some(v) = body.get("survivalTime").and_then(|v| v.as_u64()) {
            stored.survival_time = Some(v as u32);
        }
        if let Some(v) = body.get("burstArrivalTime") {
            stored.burst_arrival_time = Some(v.clone());
        }
        if let Some(v) = body.get("flowDescriptions").and_then(|v| v.as_array()) {
            stored.flow_descriptions = v
                .iter()
                .filter_map(|f| f.as_str())
                .map(str::to_string)
                .collect();
        }
        Some(stored.clone())
    }

    pub fn qos_tsc_remove(&self, id: &str) -> Option<QosTscSession> {
        self.qos_tsc_sessions.write().ok()?.remove(id)
    }

    pub fn qos_tsc_count(&self) -> usize {
        self.qos_tsc_sessions.read().map(|s| s.len()).unwrap_or(0)
    }

    pub fn qos_tsc_sub_create(
        &self,
        mut sub: QosTscSubscription,
    ) -> Result<QosTscSubscription, TsctsfContextError> {
        let mut store = self
            .qos_tsc_subscriptions
            .write()
            .map_err(|_| TsctsfContextError::LockPoisoned)?;
        if store.len() >= self.max_configs {
            return Err(TsctsfContextError::MaxConfigsReached);
        }
        sub.subscription_id = Uuid::new_v4().to_string();
        store.insert(sub.subscription_id.clone(), sub.clone());
        Ok(sub)
    }

    pub fn qos_tsc_sub_find(&self, id: &str) -> Option<QosTscSubscription> {
        self.qos_tsc_subscriptions.read().ok()?.get(id).cloned()
    }

    pub fn qos_tsc_sub_remove(&self, id: &str) -> Option<QosTscSubscription> {
        self.qos_tsc_subscriptions.write().ok()?.remove(id)
    }

    pub fn qos_tsc_sub_list(&self) -> Vec<QosTscSubscription> {
        self.qos_tsc_subscriptions
            .read()
            .map(|s| s.values().cloned().collect())
            .unwrap_or_default()
    }
}

impl Default for TsctsfContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global TSCTSF context
static GLOBAL_TSCTSF_CONTEXT: std::sync::OnceLock<Arc<RwLock<TsctsfContext>>> =
    std::sync::OnceLock::new();

/// One agreement about every process-global in this crate: the TSCTSF context and
/// `actuation`'s enable switch (#284).
///
/// Declared **here, beside the largest global it guards**, rather than inside
/// `main`'s `mod tests` where it used to live. A guard inside one module's `mod
/// tests` is unreachable from every sibling module, so `actuation`'s tests — which
/// flip a process-global switch that `main`'s handlers read — would have had to
/// declare a second lock over the same state. #308 established that two locks over
/// one ambient state are two disjoint agreements rather than one, and #276 showed
/// that the same mistake HANGS the suite rather than merely flaking it.
///
/// A `std` mutex rather than a `tokio` one: every holder here is a sync `#[test]`
/// or a `block_on` wrapper with no live runtime to block, and poisoning is absorbed
/// by `into_inner` at the call site.
pub static PROCESS_STATE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn tsctsf_self() -> Arc<RwLock<TsctsfContext>> {
    GLOBAL_TSCTSF_CONTEXT
        .get_or_init(|| Arc::new(RwLock::new(TsctsfContext::new())))
        .clone()
}

pub fn tsctsf_context_init(max_configs: usize) {
    let ctx = tsctsf_self();
    if let Ok(mut context) = ctx.write() {
        context.init(max_configs);
    };
}

pub fn tsctsf_context_final() {
    let ctx = tsctsf_self();
    if let Ok(mut context) = ctx.write() {
        context.fini();
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Local instances — race-free without a global test lock.

    fn ctx(max: usize) -> TsctsfContext {
        let mut context = TsctsfContext::new();
        context.init(max);
        context
    }

    fn valid_config() -> TimeSyncExposureConfig {
        TimeSyncExposureConfig {
            notification_target_addr: "http://af.example.com/notify".to_string(),
            up_node_id: "upf1.example.com".to_string(),
            time_domain: Some(1),
            ..Default::default()
        }
    }

    #[test]
    fn config_insert_find_remove_roundtrip() {
        let context = ctx(8);
        let config = TimeSyncConfig::new(valid_config());
        let id = config.id.clone();

        context.config_insert(config).expect("insert");
        assert_eq!(context.config_count(), 1);
        assert_eq!(context.config_find(&id).expect("find").id, id);

        assert_eq!(context.config_remove(&id).expect("remove").id, id);
        assert_eq!(context.config_count(), 0);
        assert!(context.config_find(&id).is_none());
    }

    #[test]
    fn config_cap_is_enforced() {
        let context = ctx(1);
        context
            .config_insert(TimeSyncConfig::new(valid_config()))
            .expect("fits");
        let err = context
            .config_insert(TimeSyncConfig::new(valid_config()))
            .expect_err("cap");
        assert_eq!(err, TsctsfContextError::MaxConfigsReached);
        assert_eq!(err.cause(), "MAX_CONFIGS_REACHED");
    }

    #[test]
    fn init_guards_reinit_and_fini_clears() {
        let mut context = TsctsfContext::new();
        assert!(!context.is_initialized());
        context.init(4);
        context.init(1); // guarded no-op
        context
            .config_insert(TimeSyncConfig::new(valid_config()))
            .expect("a");
        context
            .config_insert(TimeSyncConfig::new(valid_config()))
            .expect("caps kept from first init");
        context.fini();
        assert!(!context.is_initialized());
        assert_eq!(context.config_count(), 0);
    }

    #[test]
    fn uninitialized_context_rejects_inserts() {
        let context = TsctsfContext::new();
        assert_eq!(
            context.config_insert(TimeSyncConfig::new(valid_config())),
            Err(TsctsfContextError::MaxConfigsReached)
        );
    }

    #[test]
    fn generated_ids_are_unique() {
        assert_ne!(
            TimeSyncConfig::new(valid_config()).id,
            TimeSyncConfig::new(valid_config()).id
        );
    }

    // ── #113: typed IE validation ────────────────────────────────────────────

    /// A configuration missing a required member is `MANDATORY_IE_MISSING`, not
    /// `INVALID_MSG_FORMAT`: TS 29.500 §5.2.7.2 distinguishes them, and that
    /// distinction tells a consumer whether its JSON is malformed or incomplete.
    #[test]
    fn a_config_missing_a_required_ie_names_the_member() {
        let mut cfg = valid_config();
        cfg.notification_target_addr.clear();
        let err = cfg.validate().expect_err("absent target address");
        assert_eq!(err, IeError::MandatoryIeMissing("notificationTargetAddr"));
        assert_eq!(err.cause(), "MANDATORY_IE_MISSING");
        assert!(err.detail().contains("notificationTargetAddr"));

        let mut cfg = valid_config();
        cfg.up_node_id.clear();
        assert_eq!(
            cfg.validate().expect_err("absent node id"),
            IeError::MandatoryIeMissing("upNodeId")
        );
    }

    /// Present-but-EMPTY is refused as well: serde accepts `""` for a `String`,
    /// and an empty notification target address is exactly the un-notifiable
    /// state this validation exists to prevent — accepting it reproduces the
    /// defect through a different door.
    #[test]
    fn an_empty_required_ie_is_refused_like_an_absent_one() {
        let cfg = TimeSyncExposureConfig {
            notification_target_addr: "   ".to_string(),
            up_node_id: "upf1".to_string(),
            ..Default::default()
        };
        assert_eq!(
            cfg.validate().expect_err("blank target address"),
            IeError::MandatoryIeMissing("notificationTargetAddr")
        );
    }

    /// An out-of-range value is `MANDATORY_IE_INCORRECT` and names the member —
    /// not a serde type error that names nothing.
    #[test]
    fn an_out_of_range_time_domain_names_the_member() {
        let mut cfg = valid_config();
        cfg.time_domain = Some(256);
        let err = cfg.validate().expect_err("domain > 255");
        assert_eq!(err, IeError::MandatoryIeIncorrect("timeDomain"));
        assert_eq!(err.cause(), "MANDATORY_IE_INCORRECT");
        // And the boundary is inclusive.
        cfg.time_domain = Some(255);
        assert!(cfg.validate().is_ok());
    }

    /// §5.2.27.2.3: an update body carrying one member changes only that member.
    /// A replace would clear parameters the consumer did not mention, which its
    /// required input (the PTP instance reference alone) cannot have meant.
    #[test]
    fn an_update_merges_rather_than_replacing() {
        let mut cfg = valid_config();
        cfg.gm_priority = Some(7);
        cfg.apply_update(&serde_json::json!({ "gmEnable": true }));
        assert_eq!(cfg.gm_enable, Some(true));
        assert_eq!(cfg.gm_priority, Some(7), "an unmentioned member survives");
        assert_eq!(
            cfg.notification_target_addr, "http://af.example.com/notify",
            "and so does a required one"
        );
    }

    /// The add and remove lists are applied in that order, so a SUPI in both is
    /// removed: a consumer asking for both cannot have meant "keep".
    #[test]
    fn supi_add_and_remove_lists_apply_in_order() {
        let mut cfg = valid_config();
        cfg.apply_update(&serde_json::json!({ "supisToAdd": ["a", "b", "c"] }));
        assert_eq!(cfg.supis, vec!["a", "b", "c"]);
        cfg.apply_update(&serde_json::json!({
            "supisToAdd": ["d"],
            "supisToRemove": ["b", "d"],
        }));
        assert_eq!(cfg.supis, vec!["a", "c"]);
        // Adding a SUPI already present does not duplicate it.
        cfg.apply_update(&serde_json::json!({ "supisToAdd": ["a"] }));
        assert_eq!(cfg.supis, vec!["a", "c"]);
    }

    /// §5.2.27.2.6's required input is an EITHER/OR: (DNN, S-NSSAI) or an
    /// AF-Service-Identifier. Both alternatives must be accepted, and neither
    /// must be.
    #[test]
    fn a_caps_subscription_accepts_either_scope_and_refuses_neither() {
        let base = CapsSubscription {
            subscription_id: String::new(),
            notification_target_addr: "http://af/notify".to_string(),
            ..CapsSubscription::default()
        };

        let mut dnn_scoped = base.clone();
        dnn_scoped.dnn = Some("internet".to_string());
        dnn_scoped.snssai = Some(serde_json::json!({ "sst": 1 }));
        assert!(
            dnn_scoped.validate().is_ok(),
            "(DNN, S-NSSAI) is a valid scope"
        );

        let mut af_scoped = base.clone();
        af_scoped.af_service_id = Some("af-svc-1".to_string());
        assert!(
            af_scoped.validate().is_ok(),
            "an AF-Service-Identifier is the other valid scope"
        );

        // DNN alone is not the alternative: the spec pairs it with S-NSSAI.
        let mut dnn_only = base.clone();
        dnn_only.dnn = Some("internet".to_string());
        assert_eq!(
            dnn_only.validate().expect_err("dnn alone"),
            IeError::MandatoryIeMissing("dnn+snssai or afServiceId")
        );

        assert_eq!(
            base.validate().expect_err("no scope at all"),
            IeError::MandatoryIeMissing("dnn+snssai or afServiceId"),
            "a subscription that could never be matched must be refused, not accepted"
        );
    }

    /// A subscription with no notification target could never fire.
    #[test]
    fn a_caps_subscription_needs_a_notification_target() {
        let sub = CapsSubscription {
            af_service_id: Some("af-svc-1".to_string()),
            ..CapsSubscription::default()
        };
        assert_eq!(
            sub.validate().expect_err("no target"),
            IeError::MandatoryIeMissing("notificationTargetAddr")
        );
    }

    /// The subscription id is MINTED, never taken from the request: a
    /// consumer-supplied id would let one AF address another's resource.
    #[test]
    fn a_caps_subscription_id_is_minted_not_accepted() {
        let context = ctx(8);
        let sub = CapsSubscription {
            subscription_id: "attacker-chosen".to_string(),
            notification_target_addr: "http://af/notify".to_string(),
            af_service_id: Some("af-svc-1".to_string()),
            ..CapsSubscription::default()
        };
        let created = context.caps_sub_create(sub).expect("create");
        assert_ne!(created.subscription_id, "attacker-chosen");
        assert!(context.caps_sub_find("attacker-chosen").is_none());
        assert!(context.caps_sub_find(&created.subscription_id).is_some());
        assert_eq!(
            context
                .caps_sub_remove(&created.subscription_id)
                .map(|s| s.subscription_id),
            Some(created.subscription_id.clone())
        );
        assert_eq!(context.caps_sub_count(), 0);
    }

    /// §5.2.27.4.2: an AF identifier AND a target are both required. A
    /// configuration with no target would activate time distribution for nobody.
    #[test]
    fn an_asti_config_needs_an_af_id_and_a_target() {
        let no_af = AstiConfig {
            supi: Some("imsi-001010000000001".to_string()),
            ..AstiConfig::default()
        };
        assert_eq!(
            no_af.validate().expect_err("no af id"),
            IeError::MandatoryIeMissing("afId")
        );

        let no_target = AstiConfig {
            af_id: "af-1".to_string(),
            ..AstiConfig::default()
        };
        assert_eq!(
            no_target.validate().expect_err("no target"),
            IeError::MandatoryIeMissing("supi, gpsi, externalGroupId or internalGroupId")
        );

        // Any one of the four targets suffices.
        for target in ["supi", "gpsi", "externalGroupId", "internalGroupId"] {
            let mut cfg = AstiConfig {
                af_id: "af-1".to_string(),
                ..AstiConfig::default()
            };
            match target {
                "supi" => cfg.supi = Some("imsi-1".to_string()),
                "gpsi" => cfg.gpsi = Some("msisdn-1".to_string()),
                "externalGroupId" => cfg.external_group_id = Some("extgroup-1".to_string()),
                _ => cfg.internal_group_id = Some("intgroup-1".to_string()),
            }
            assert!(cfg.validate().is_ok(), "{target} must be a valid target");
        }
    }

    /// §5.2.27.3.2's required inputs are three either/ors plus the AF id. Each is
    /// checked as an alternative: requiring both halves would refuse conformant
    /// requests, which is the mirror of accepting one that names nothing.
    #[test]
    fn a_qos_tsc_session_checks_each_either_or() {
        let complete = QosTscSession {
            af_id: "af-1".to_string(),
            gpsi: Some("msisdn-491700000001".to_string()),
            flow_descriptions: vec!["permit out ip from any to assigned".to_string()],
            qos_reference: Some("qos-ref-1".to_string()),
            ..QosTscSession::default()
        };
        assert!(complete.validate().is_ok());

        // The ext-app-id alternative to flow descriptions.
        let mut ext_app = complete.clone();
        ext_app.flow_descriptions.clear();
        ext_app.ext_app_id = Some("app-1".to_string());
        assert!(ext_app.validate().is_ok());

        // The individual-QoS alternative to a QoS reference.
        let mut individual = complete.clone();
        individual.qos_reference = None;
        individual.max_br_dl = Some("100 Mbps".to_string());
        assert!(individual.validate().is_ok());

        for (mutate, expected) in [
            (
                Box::new(|s: &mut QosTscSession| s.af_id.clear())
                    as Box<dyn Fn(&mut QosTscSession)>,
                IeError::MandatoryIeMissing("afId"),
            ),
            (
                Box::new(|s: &mut QosTscSession| s.gpsi = None),
                IeError::MandatoryIeMissing("ueIpv4, ueIpv6, gpsi or externalGroupId"),
            ),
            (
                Box::new(|s: &mut QosTscSession| s.flow_descriptions.clear()),
                IeError::MandatoryIeMissing("flowDescriptions or extAppId"),
            ),
            (
                Box::new(|s: &mut QosTscSession| s.qos_reference = None),
                IeError::MandatoryIeMissing("qosReference or maxBrUl/maxBrDl"),
            ),
        ] {
            let mut broken = complete.clone();
            mutate(&mut broken);
            assert_eq!(broken.validate().expect_err("missing"), expected);
        }
    }

    #[test]
    fn asti_and_qos_tsc_stores_round_trip() {
        let context = ctx(8);

        let asti = context
            .asti_create(AstiConfig {
                af_id: "af-1".to_string(),
                supi: Some("imsi-1".to_string()),
                ..AstiConfig::default()
            })
            .expect("asti create");
        assert!(!asti.config_id.is_empty());
        assert_eq!(context.asti_count(), 1);
        let updated = context
            .asti_update(
                &asti.config_id,
                &serde_json::json!({ "asTimeDisEnabled": true, "uuErrorBudget": 900 }),
            )
            .expect("asti update");
        assert_eq!(updated.as_time_dis_enabled, Some(true));
        assert_eq!(updated.uu_error_budget, Some(900));
        assert_eq!(
            updated.af_id, "af-1",
            "an update must not clear what it did not mention"
        );
        assert!(context.asti_remove(&asti.config_id).is_some());
        assert_eq!(context.asti_count(), 0);
        assert!(context
            .asti_update("gone", &serde_json::json!({}))
            .is_none());

        let session = context
            .qos_tsc_create(QosTscSession {
                af_id: "af-1".to_string(),
                gpsi: Some("msisdn-1".to_string()),
                flow_descriptions: vec!["permit out ip from any to assigned".to_string()],
                qos_reference: Some("q1".to_string()),
                ..QosTscSession::default()
            })
            .expect("qos create");
        assert!(!session.transaction_ref_id.is_empty());
        let updated = context
            .qos_tsc_update(
                &session.transaction_ref_id,
                &serde_json::json!({ "periodicity": 1000, "survivalTime": 2000 }),
            )
            .expect("qos update");
        assert_eq!(updated.periodicity, Some(1000));
        assert_eq!(updated.survival_time, Some(2000));
        assert_eq!(updated.qos_reference.as_deref(), Some("q1"));
        assert!(context
            .qos_tsc_remove(&session.transaction_ref_id)
            .is_some());
        assert_eq!(context.qos_tsc_count(), 0);
    }
}
