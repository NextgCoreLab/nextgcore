//! AMF Metrics
//!
//! Port of src/amf/metrics.c - AMF metrics collection and reporting

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

// ============================================================================
// Global Metrics
// ============================================================================

/// Global metric types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GlobalMetric {
    // Gauges
    /// Number of RAN UEs
    RanUe,
    /// Number of AMF sessions
    AmfSession,
    /// Number of gNodeBs
    Gnb,

    // Counters
    /// Initial registration requests
    RmRegInitReq,
    /// Successful initial registrations
    RmRegInitSucc,
    /// Mobility registration update requests
    RmRegMobReq,
    /// Successful mobility registration updates
    RmRegMobSucc,
    /// Periodic registration update requests
    RmRegPeriodReq,
    /// Successful periodic registration updates
    RmRegPeriodSucc,
    /// Emergency registration requests
    RmRegEmergReq,
    /// Successful emergency registrations
    RmRegEmergSucc,
    /// 5G paging requests
    MmPaging5gReq,
    /// Successful 5G paging
    MmPaging5gSucc,
    /// Authentication requests
    AmfAuthReq,
    /// Authentication rejections
    AmfAuthReject,
    /// Configuration update commands
    MmConfUpdate,
    /// Successful configuration updates
    MmConfUpdateSucc,
    /// UEs an NG Reset moved to CM-IDLE (#754)
    NgResetUeIdled,
    /// UE-associated NGAP messages refused for a UE the sender does not serve (#739)
    UeAssociatedRefused,
}

impl GlobalMetric {
    /// Get metric name
    pub fn name(&self) -> &'static str {
        match self {
            Self::RanUe => "ran_ue",
            Self::AmfSession => "amf_session",
            Self::Gnb => "gnb",
            Self::RmRegInitReq => "fivegs_amffunction_rm_reginitreq",
            Self::RmRegInitSucc => "fivegs_amffunction_rm_reginitsucc",
            Self::RmRegMobReq => "fivegs_amffunction_rm_regmobreq",
            Self::RmRegMobSucc => "fivegs_amffunction_rm_regmobsucc",
            Self::RmRegPeriodReq => "fivegs_amffunction_rm_regperiodreq",
            Self::RmRegPeriodSucc => "fivegs_amffunction_rm_regperiodsucc",
            Self::RmRegEmergReq => "fivegs_amffunction_rm_regemergreq",
            Self::RmRegEmergSucc => "fivegs_amffunction_rm_regemergsucc",
            Self::MmPaging5gReq => "fivegs_amffunction_mm_paging5greq",
            Self::MmPaging5gSucc => "fivegs_amffunction_mm_paging5gsucc",
            Self::AmfAuthReq => "fivegs_amffunction_amf_authreq",
            Self::AmfAuthReject => "fivegs_amffunction_amf_authreject",
            Self::MmConfUpdate => "fivegs_amffunction_mm_confupdate",
            Self::MmConfUpdateSucc => "fivegs_amffunction_mm_confupdatesucc",
            Self::NgResetUeIdled => "amf_ng_reset_ue_idled",
            Self::UeAssociatedRefused => "amf_ngap_ue_associated_refused",
        }
    }

    /// Get metric description
    pub fn description(&self) -> &'static str {
        match self {
            Self::RanUe => "RAN UEs",
            Self::AmfSession => "AMF Sessions",
            Self::Gnb => "gNodeBs",
            Self::RmRegInitReq => "Number of initial registration requests received by the AMF",
            Self::RmRegInitSucc => "Number of successful initial registrations at the AMF",
            Self::RmRegMobReq => {
                "Number of mobility registration update requests received by the AMF"
            }
            Self::RmRegMobSucc => "Number of successful mobility registration updates at the AMF",
            Self::RmRegPeriodReq => {
                "Number of periodic registration update requests received by the AMF"
            }
            Self::RmRegPeriodSucc => {
                "Number of successful periodic registration update requests at the AMF"
            }
            Self::RmRegEmergReq => "Number of emergency registration requests received by the AMF",
            Self::RmRegEmergSucc => "Number of successful emergency registrations at the AMF",
            Self::MmPaging5gReq => "Number of 5G paging procedures initiated at the AMF",
            Self::MmPaging5gSucc => {
                "Number of successful 5G paging procedures initiated at the AMF"
            }
            Self::AmfAuthReq => "Number of authentication requests sent by the AMF",
            Self::AmfAuthReject => "Number of authentication rejections sent by the AMF",
            Self::MmConfUpdate => "Number of UE Configuration Update commands requested by the AMF",
            Self::MmConfUpdateSucc => {
                "Number of UE Configuration Update complete messages received by the AMF"
            }
            Self::NgResetUeIdled => {
                "Number of registered UEs an NG Reset moved to CM-IDLE (TS 38.413 §8.7.4.2.2)"
            }
            Self::UeAssociatedRefused => {
                "Number of UE-associated NGAP messages dropped with an Error Indication because \
                 the sending association does not serve the UE they name (TS 38.413 §10.6)"
            }
        }
    }

    /// Check if this is a gauge metric
    pub fn is_gauge(&self) -> bool {
        matches!(self, Self::RanUe | Self::AmfSession | Self::Gnb)
    }
}

// ============================================================================
// Slice Metrics
// ============================================================================

/// Slice metric types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SliceMetric {
    /// Number of registered subscribers per slice
    RegisteredSubNbr,
}

impl SliceMetric {
    /// Get metric name
    pub fn name(&self) -> &'static str {
        match self {
            Self::RegisteredSubNbr => "fivegs_amffunction_rm_registeredsubnbr",
        }
    }

    /// Get metric description
    pub fn description(&self) -> &'static str {
        match self {
            Self::RegisteredSubNbr => "Number of registered state subscribers per AMF",
        }
    }
}

/// Slice key for metrics
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SliceKey {
    /// PLMN ID
    pub plmn_id: String,
    /// S-NSSAI (SST and optional SD)
    pub snssai: String,
}

// ============================================================================
// Cause Metrics
// ============================================================================

/// Cause metric types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CauseMetric {
    /// Failed initial registrations
    RmRegInitFail,
    /// Failed mobility registration updates
    RmRegMobFail,
    /// Failed periodic registration updates
    RmRegPeriodFail,
    /// Failed emergency registrations
    RmRegEmergFail,
    /// Authentication failures
    AmfAuthFail,
}

impl CauseMetric {
    /// Get metric name
    pub fn name(&self) -> &'static str {
        match self {
            Self::RmRegInitFail => "fivegs_amffunction_rm_reginitfail",
            Self::RmRegMobFail => "fivegs_amffunction_rm_regmobfail",
            Self::RmRegPeriodFail => "fivegs_amffunction_rm_regperiodfail",
            Self::RmRegEmergFail => "fivegs_amffunction_rm_regemergfail",
            Self::AmfAuthFail => "fivegs_amffunction_amf_authfail",
        }
    }

    /// Get metric description
    pub fn description(&self) -> &'static str {
        match self {
            Self::RmRegInitFail => "Number of failed initial registrations at the AMF",
            Self::RmRegMobFail => "Number of failed mobility registration updates at the AMF",
            Self::RmRegPeriodFail => {
                "Number of failed periodic registration update requests at the AMF"
            }
            Self::RmRegEmergFail => "Number of failed emergency registrations at the AMF",
            Self::AmfAuthFail => "Number of authentication failure messages received by the AMF",
        }
    }
}

// ============================================================================
// Metrics Manager
// ============================================================================

/// AMF metrics manager
pub struct AmfMetrics {
    /// Global counters
    global_counters: HashMap<GlobalMetric, AtomicU64>,
    /// Slice metrics
    slice_metrics: RwLock<HashMap<(SliceKey, SliceMetric), u64>>,
    /// Cause metrics
    cause_metrics: RwLock<HashMap<(u8, CauseMetric), u64>>,
}

impl Default for AmfMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// The process's metrics registry: what the AMF counts, and what
/// [`AmfMetrics::export_prometheus`] renders.
pub fn global() -> &'static AmfMetrics {
    static GLOBAL: std::sync::OnceLock<AmfMetrics> = std::sync::OnceLock::new();
    GLOBAL.get_or_init(AmfMetrics::new)
}

impl AmfMetrics {
    /// Create a new metrics manager
    pub fn new() -> Self {
        let mut global_counters = HashMap::new();

        // Initialize all global metrics
        for metric in [
            GlobalMetric::RanUe,
            GlobalMetric::AmfSession,
            GlobalMetric::Gnb,
            GlobalMetric::RmRegInitReq,
            GlobalMetric::RmRegInitSucc,
            GlobalMetric::RmRegMobReq,
            GlobalMetric::RmRegMobSucc,
            GlobalMetric::RmRegPeriodReq,
            GlobalMetric::RmRegPeriodSucc,
            GlobalMetric::RmRegEmergReq,
            GlobalMetric::RmRegEmergSucc,
            GlobalMetric::MmPaging5gReq,
            GlobalMetric::MmPaging5gSucc,
            GlobalMetric::AmfAuthReq,
            GlobalMetric::AmfAuthReject,
            GlobalMetric::MmConfUpdate,
            GlobalMetric::MmConfUpdateSucc,
            GlobalMetric::NgResetUeIdled,
            GlobalMetric::UeAssociatedRefused,
        ] {
            global_counters.insert(metric, AtomicU64::new(0));
        }

        Self {
            global_counters,
            slice_metrics: RwLock::new(HashMap::new()),
            cause_metrics: RwLock::new(HashMap::new()),
        }
    }

    /// Increment a global counter
    pub fn inc(&self, metric: GlobalMetric) {
        if let Some(counter) = self.global_counters.get(&metric) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Add to a global counter
    pub fn add(&self, metric: GlobalMetric, value: u64) {
        if let Some(counter) = self.global_counters.get(&metric) {
            counter.fetch_add(value, Ordering::Relaxed);
        }
    }

    /// Set a global gauge
    pub fn set(&self, metric: GlobalMetric, value: u64) {
        if let Some(counter) = self.global_counters.get(&metric) {
            counter.store(value, Ordering::Relaxed);
        }
    }

    /// Get a global metric value
    pub fn get(&self, metric: GlobalMetric) -> u64 {
        self.global_counters
            .get(&metric)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Add to a slice metric
    pub fn add_slice_metric(&self, key: SliceKey, metric: SliceMetric, value: i64) {
        if let Ok(mut metrics) = self.slice_metrics.write() {
            let entry = metrics.entry((key, metric)).or_insert(0);
            if value >= 0 {
                *entry = entry.saturating_add(value as u64);
            } else {
                *entry = entry.saturating_sub((-value) as u64);
            }
        }
    }

    /// Get a slice metric value
    pub fn get_slice_metric(&self, key: &SliceKey, metric: SliceMetric) -> u64 {
        self.slice_metrics
            .read()
            .ok()
            .and_then(|m| m.get(&(key.clone(), metric)).copied())
            .unwrap_or(0)
    }

    /// Add to a cause metric
    pub fn add_cause_metric(&self, cause: u8, metric: CauseMetric, value: u64) {
        if let Ok(mut metrics) = self.cause_metrics.write() {
            let entry = metrics.entry((cause, metric)).or_insert(0);
            *entry = entry.saturating_add(value);
        }
    }

    /// Get a cause metric value
    pub fn get_cause_metric(&self, cause: u8, metric: CauseMetric) -> u64 {
        self.cause_metrics
            .read()
            .ok()
            .and_then(|m| m.get(&(cause, metric)).copied())
            .unwrap_or(0)
    }

    /// Reset all metrics
    pub fn reset(&self) {
        for counter in self.global_counters.values() {
            counter.store(0, Ordering::Relaxed);
        }
        if let Ok(mut metrics) = self.slice_metrics.write() {
            metrics.clear();
        }
        if let Ok(mut metrics) = self.cause_metrics.write() {
            metrics.clear();
        }
    }

    /// Export metrics in Prometheus format
    pub fn export_prometheus(&self) -> String {
        let mut output = String::new();

        // Export global counters
        for (metric, counter) in &self.global_counters {
            let value = counter.load(Ordering::Relaxed);
            let metric_type = if metric.is_gauge() {
                "gauge"
            } else {
                "counter"
            };

            output.push_str(&format!(
                "# HELP {} {}\n",
                metric.name(),
                metric.description()
            ));
            output.push_str(&format!("# TYPE {} {}\n", metric.name(), metric_type));
            output.push_str(&format!("{} {}\n", metric.name(), value));
        }

        // Export slice metrics
        if let Ok(slice_metrics) = self.slice_metrics.read() {
            for ((key, metric), value) in slice_metrics.iter() {
                output.push_str(&format!(
                    "# HELP {} {}\n",
                    metric.name(),
                    metric.description()
                ));
                output.push_str(&format!("# TYPE {} gauge\n", metric.name()));
                output.push_str(&format!(
                    "{}{{plmn_id=\"{}\",snssai=\"{}\"}} {}\n",
                    metric.name(),
                    key.plmn_id,
                    key.snssai,
                    value
                ));
            }
        }

        // Export cause metrics
        if let Ok(cause_metrics) = self.cause_metrics.read() {
            for ((cause, metric), value) in cause_metrics.iter() {
                output.push_str(&format!(
                    "# HELP {} {}\n",
                    metric.name(),
                    metric.description()
                ));
                output.push_str(&format!("# TYPE {} counter\n", metric.name()));
                output.push_str(&format!(
                    "{}{{cause=\"{}\"}} {}\n",
                    metric.name(),
                    cause,
                    value
                ));
            }
        }

        output
    }

    /// Get summary statistics
    pub fn get_summary(&self) -> MetricsSummary {
        MetricsSummary {
            total_ran_ues: self.get(GlobalMetric::RanUe),
            total_sessions: self.get(GlobalMetric::AmfSession),
            total_gnbs: self.get(GlobalMetric::Gnb),
            reg_init_success_rate: self
                .calculate_success_rate(GlobalMetric::RmRegInitReq, GlobalMetric::RmRegInitSucc),
            reg_mob_success_rate: self
                .calculate_success_rate(GlobalMetric::RmRegMobReq, GlobalMetric::RmRegMobSucc),
            auth_success_rate: self.calculate_auth_success_rate(),
        }
    }

    /// Calculate success rate as percentage
    fn calculate_success_rate(&self, req_metric: GlobalMetric, succ_metric: GlobalMetric) -> f64 {
        let req = self.get(req_metric);
        let succ = self.get(succ_metric);
        if req == 0 {
            0.0
        } else {
            (succ as f64 / req as f64) * 100.0
        }
    }

    /// Calculate authentication success rate
    fn calculate_auth_success_rate(&self) -> f64 {
        let req = self.get(GlobalMetric::AmfAuthReq);
        let reject = self.get(GlobalMetric::AmfAuthReject);
        if req == 0 {
            0.0
        } else {
            let succ = req.saturating_sub(reject);
            (succ as f64 / req as f64) * 100.0
        }
    }
}

/// Metrics summary statistics
#[derive(Debug, Clone)]
pub struct MetricsSummary {
    /// Total RAN UEs
    pub total_ran_ues: u64,
    /// Total AMF sessions
    pub total_sessions: u64,
    /// Total gNodeBs
    pub total_gnbs: u64,
    /// Initial registration success rate (%)
    pub reg_init_success_rate: f64,
    /// Mobility registration success rate (%)
    pub reg_mob_success_rate: f64,
    /// Authentication success rate (%)
    pub auth_success_rate: f64,
}

// ============================================================================
// Live Prometheus exposition (#1334)
// ============================================================================
//
// What `/metrics` serves: the families every NF shares (`nextgcore_metrics::nf`),
// then the AMF's own. Counters are fed from the AMF's choke points, not from each
// procedure's code:
//
// - every NGAP PDU received (`NgapServer::process_ngap_message`) and sent
//   (`NgapServer::send_to_association`) is counted by direction, procedure (TS 38.413
//   §9.4.7 procedure code) and outcome (the NGAP-PDU CHOICE);
// - the 5GMM messages TS 28.552 §5.2.2 counts "on transmission" are counted where
//   the AMF hands a plain message to NAS security for protection, or puts an
//   unprotected one in a DOWNLINK NAS TRANSPORT (each message reaches exactly one of
//   those; a T3550/T3560 retransmission re-sends a stored PDU and is not counted);
// - Registration Requests at `handle_registration_request_nas`, which every one
//   reaches, and 5G-AKA results where the AUSF confirmation is evaluated.
//
// The UE and session census is read from the live stores at scrape time; the gNB
// census is published by the NGAP loop, which owns the associations.

use std::sync::atomic::AtomicUsize;

/// Direction of an NGAP PDU, as seen by the AMF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NgapDirection {
    /// Received from a gNB.
    Rx,
    /// Sent to a gNB.
    Tx,
}

/// NGAP-PDU CHOICE alternatives (TS 38.413 §9.4.2).
const NGAP_OUTCOMES: [&str; 3] = ["initiating", "successful", "unsuccessful"];

/// NGAP elementary procedure names by procedure code (TS 38.413 §9.4.7,
/// `ngap-17.9.asn` `id-*`). The index is the code.
const NGAP_PROCEDURES: [&str; 76] = [
    "AMFConfigurationUpdate",
    "AMFStatusIndication",
    "CellTrafficTrace",
    "DeactivateTrace",
    "DownlinkNASTransport",
    "DownlinkNonUEAssociatedNRPPaTransport",
    "DownlinkRANConfigurationTransfer",
    "DownlinkRANStatusTransfer",
    "DownlinkUEAssociatedNRPPaTransport",
    "ErrorIndication",
    "HandoverCancel",
    "HandoverNotification",
    "HandoverPreparation",
    "HandoverResourceAllocation",
    "InitialContextSetup",
    "InitialUEMessage",
    "LocationReportingControl",
    "LocationReportingFailureIndication",
    "LocationReport",
    "NASNonDeliveryIndication",
    "NGReset",
    "NGSetup",
    "OverloadStart",
    "OverloadStop",
    "Paging",
    "PathSwitchRequest",
    "PDUSessionResourceModify",
    "PDUSessionResourceModifyIndication",
    "PDUSessionResourceRelease",
    "PDUSessionResourceSetup",
    "PDUSessionResourceNotify",
    "PrivateMessage",
    "PWSCancel",
    "PWSFailureIndication",
    "PWSRestartIndication",
    "RANConfigurationUpdate",
    "RerouteNASRequest",
    "RRCInactiveTransitionReport",
    "TraceFailureIndication",
    "TraceStart",
    "UEContextModification",
    "UEContextRelease",
    "UEContextReleaseRequest",
    "UERadioCapabilityCheck",
    "UERadioCapabilityInfoIndication",
    "UETNLABindingRelease",
    "UplinkNASTransport",
    "UplinkNonUEAssociatedNRPPaTransport",
    "UplinkRANConfigurationTransfer",
    "UplinkRANStatusTransfer",
    "UplinkUEAssociatedNRPPaTransport",
    "WriteReplaceWarning",
    "SecondaryRATDataUsageReport",
    "UplinkRIMInformationTransfer",
    "DownlinkRIMInformationTransfer",
    "RetrieveUEInformation",
    "UEInformationTransfer",
    "RANCPRelocationIndication",
    "UEContextResume",
    "UEContextSuspend",
    "UERadioCapabilityIDMapping",
    "HandoverSuccess",
    "UplinkRANEarlyStatusTransfer",
    "DownlinkRANEarlyStatusTransfer",
    "AMFCPRelocationIndication",
    "ConnectionEstablishmentIndication",
    "BroadcastSessionModification",
    "BroadcastSessionRelease",
    "BroadcastSessionSetup",
    "DistributionSetup",
    "DistributionRelease",
    "MulticastSessionActivation",
    "MulticastSessionDeactivation",
    "MulticastSessionUpdate",
    "MulticastGroupPaging",
    "BroadcastSessionReleaseRequired",
];

/// The name of NGAP procedure `code`, `unknown` past the table.
pub fn ngap_procedure_name(code: u8) -> &'static str {
    NGAP_PROCEDURES
        .get(code as usize)
        .copied()
        .unwrap_or("unknown")
}

/// Slots: direction (2) x procedure code (256) x outcome (3).
fn ngap_counters() -> &'static [AtomicU64] {
    static COUNTERS: std::sync::OnceLock<Vec<AtomicU64>> = std::sync::OnceLock::new();
    COUNTERS.get_or_init(|| (0..2 * 256 * 3).map(|_| AtomicU64::new(0)).collect())
}

fn ngap_slot(direction: NgapDirection, code: u8, outcome: usize) -> usize {
    let d = match direction {
        NgapDirection::Rx => 0,
        NgapDirection::Tx => 1,
    };
    (d * 256 + code as usize) * 3 + outcome
}

/// The outcome index (into [`NGAP_OUTCOMES`]) and procedure code of an APER NGAP
/// PDU: octet 0 holds the extension bit and the 2-bit CHOICE index, octet 1 the
/// procedure code.
fn ngap_header(pdu: &[u8]) -> Option<(usize, u8)> {
    let (b0, code) = (*pdu.first()?, *pdu.get(1)?);
    if b0 & 0x80 != 0 {
        return None; // a CHOICE extension: no alternative this AMF knows
    }
    let outcome = usize::from((b0 >> 5) & 0x03);
    (outcome < NGAP_OUTCOMES.len()).then_some((outcome, code))
}

/// Count one NGAP PDU received or sent.
pub fn observe_ngap(direction: NgapDirection, pdu: &[u8]) {
    if let Some((outcome, code)) = ngap_header(pdu) {
        ngap_counters()[ngap_slot(direction, code, outcome)].fetch_add(1, Ordering::Relaxed);
    }
}

/// The count of NGAP PDUs of `procedure_code` / `outcome` (0 initiating, 1
/// successful, 2 unsuccessful) in `direction`.
pub fn ngap_count(direction: NgapDirection, procedure_code: u8, outcome: usize) -> u64 {
    ngap_counters()[ngap_slot(direction, procedure_code, outcome)].load(Ordering::Relaxed)
}

/// 5GMM message types counted on transmission (TS 24.501 §9.7).
mod nas_type {
    pub const REGISTRATION_REQUEST: u8 = 0x41;
    pub const REGISTRATION_ACCEPT: u8 = 0x42;
    pub const REGISTRATION_REJECT: u8 = 0x44;
    pub const AUTHENTICATION_REQUEST: u8 = 0x56;
    pub const AUTHENTICATION_REJECT: u8 = 0x58;
}

/// Counters behind the AMF's NAS families.
#[derive(Debug)]
struct NasCounters {
    /// Registration Requests by 5GS registration type value (TS 24.501 §9.11.3.7: 1
    /// initial, 2 mobility, 3 periodic, 4 emergency, 5 SNPN onboarding; 0, 6, 7
    /// reserved).
    registration_requests: [AtomicU64; 8],
    registration_accepts: AtomicU64,
    registration_rejects: AtomicU64,
    /// Registration Rejects by 5GMM cause value.
    reject_causes: [AtomicU64; 256],
    auth_requests: AtomicU64,
    auth_successes: AtomicU64,
    auth_rejects: AtomicU64,
    auth_failures_from_ue: AtomicU64,
}

fn nas_counters() -> &'static NasCounters {
    static COUNTERS: std::sync::OnceLock<NasCounters> = std::sync::OnceLock::new();
    COUNTERS.get_or_init(|| NasCounters {
        registration_requests: Default::default(),
        registration_accepts: AtomicU64::new(0),
        registration_rejects: AtomicU64::new(0),
        reject_causes: std::array::from_fn(|_| AtomicU64::new(0)),
        auth_requests: AtomicU64::new(0),
        auth_successes: AtomicU64::new(0),
        auth_rejects: AtomicU64::new(0),
        auth_failures_from_ue: AtomicU64::new(0),
    })
}

/// Count a plain downlink 5GMM message the AMF is about to send.
pub fn observe_downlink_nas(plain: &[u8]) {
    if plain.len() < 3 || plain[0] != 0x7E || plain[1] & 0x0F != 0 {
        return;
    }
    let c = nas_counters();
    match plain[2] {
        nas_type::REGISTRATION_ACCEPT => {
            c.registration_accepts.fetch_add(1, Ordering::Relaxed);
        }
        nas_type::REGISTRATION_REJECT => {
            c.registration_rejects.fetch_add(1, Ordering::Relaxed);
            if let Some(cause) = plain.get(3) {
                c.reject_causes[*cause as usize].fetch_add(1, Ordering::Relaxed);
            }
        }
        nas_type::AUTHENTICATION_REQUEST => {
            c.auth_requests.fetch_add(1, Ordering::Relaxed);
        }
        nas_type::AUTHENTICATION_REJECT => {
            c.auth_rejects.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
}

/// Count a Registration Request (plain), by its 5GS registration type.
pub fn observe_registration_request(plain: &[u8]) {
    if plain.get(2) != Some(&nas_type::REGISTRATION_REQUEST) {
        return;
    }
    if let Some(octet) = plain.get(3) {
        nas_counters().registration_requests[usize::from(octet & 0x07)]
            .fetch_add(1, Ordering::Relaxed);
    }
}

/// Count an AUTHENTICATION FAILURE received from a UE (TS 24.501 §5.4.1.3.7).
pub fn observe_ue_authentication_failure() {
    nas_counters()
        .auth_failures_from_ue
        .fetch_add(1, Ordering::Relaxed);
}

/// Count a 5G-AKA the AUSF confirmed (TS 33.501 §6.1.3.2).
pub fn observe_authentication_success() {
    nas_counters()
        .auth_successes
        .fetch_add(1, Ordering::Relaxed);
}

/// The 5GS registration type label of value `v` (TS 24.501 Table 9.11.3.7.1).
fn registration_type_label(v: usize) -> &'static str {
    match v {
        1 => "initial",
        2 => "mobility",
        3 => "periodic",
        4 => "emergency",
        5 => "snpn_onboarding",
        _ => "reserved",
    }
}

static GNB_ASSOCIATIONS: AtomicUsize = AtomicUsize::new(0);
static GNB_SETUP: AtomicUsize = AtomicUsize::new(0);

/// Publish the gNB census: NG associations, and those whose NG Setup succeeded.
pub fn set_gnb_census(associations: usize, ng_setup: usize) {
    GNB_ASSOCIATIONS.store(associations, Ordering::Relaxed);
    GNB_SETUP.store(ng_setup, Ordering::Relaxed);
}

/// The AMF's live state at scrape time.
#[derive(Debug, Clone, Copy, Default)]
pub struct AmfCensus {
    /// UEs that completed registration (RM-REGISTERED).
    pub registered_ues: usize,
    /// UEs with an N1 signalling connection (CM-CONNECTED), registered or not.
    pub connected_ues: usize,
    /// PDU sessions the AMF holds.
    pub pdu_sessions: usize,
}

fn census() -> AmfCensus {
    let ctx = crate::context::amf_self();
    let Ok(ctx) = ctx.read() else {
        return AmfCensus::default();
    };
    let (registered_ues, connected_ues) = crate::ngap_path::ue_census(&ctx.ue_store());
    AmfCensus {
        registered_ues,
        connected_ues,
        pdu_sessions: ctx.sess_count(),
    }
}

/// Render the AMF-specific families for `census` into `out`.
pub fn render_amf_families(out: &mut String, census: &AmfCensus) {
    use nextgcore_metrics::nf::{write_header, write_metric};
    use std::fmt::Write as _;
    let c = nas_counters();
    let get = |a: &AtomicU64| a.load(Ordering::Relaxed);

    write_metric(
        out,
        "amf_registered_ue_count",
        "gauge",
        "UEs in RM-REGISTERED (Registration Complete received)",
        census.registered_ues,
    );
    write_metric(
        out,
        "amf_connected_ue_count",
        "gauge",
        "UEs with an N1 NAS signalling connection (CM-CONNECTED)",
        census.connected_ues,
    );
    write_metric(
        out,
        "nextgcore_amf_active_sessions",
        "gauge",
        "PDU sessions the AMF holds",
        census.pdu_sessions,
    );
    write_metric(
        out,
        "amf_gnb_count",
        "gauge",
        "NG-RAN nodes whose NG Setup succeeded (TS 38.413 §8.7.1)",
        GNB_SETUP.load(Ordering::Relaxed),
    );
    write_metric(
        out,
        "amf_gnb_associations",
        "gauge",
        "SCTP associations from NG-RAN nodes, NG Setup or not",
        GNB_ASSOCIATIONS.load(Ordering::Relaxed),
    );

    write_header(
        out,
        "amf_registration_requests_total",
        "counter",
        "Registration Requests received, by 5GS registration type (TS 28.552 §5.2.2.1 RM.Reg*Req)",
    );
    for (v, counter) in c.registration_requests.iter().enumerate() {
        let n = get(counter);
        if n > 0 || (1..=4).contains(&v) {
            let _ = writeln!(
                out,
                "amf_registration_requests_total{{type=\"{}\"}} {n}",
                registration_type_label(v)
            );
        }
    }
    write_metric(
        out,
        "amf_registration_success_total",
        "counter",
        "Registration Accepts sent (TS 28.552 §5.2.2 RM.Reg*Succ, all types)",
        get(&c.registration_accepts),
    );
    write_metric(
        out,
        "amf_registration_failure_total",
        "counter",
        "Registration Rejects sent (TS 28.552 §5.2.2 RM.Reg*Fail, all types)",
        get(&c.registration_rejects),
    );
    write_header(
        out,
        "amf_registration_reject_cause_total",
        "counter",
        "Registration Rejects sent, by 5GMM cause value (TS 24.501 §9.11.3.2)",
    );
    for (cause, counter) in c.reject_causes.iter().enumerate() {
        let n = get(counter);
        if n > 0 {
            let _ = writeln!(
                out,
                "amf_registration_reject_cause_total{{cause=\"{cause}\"}} {n}"
            );
        }
    }
    write_metric(
        out,
        "amf_auth_request_total",
        "counter",
        "Authentication Requests sent (TS 28.552 §5.2.11 AMF.AuthReq)",
        get(&c.auth_requests),
    );
    write_metric(
        out,
        "amf_auth_success_total",
        "counter",
        "5G-AKA authentications the AUSF confirmed",
        get(&c.auth_successes),
    );
    write_header(
        out,
        "amf_auth_failure_total",
        "counter",
        "Failed authentications: Authentication Rejects sent (source=network) and \
         Authentication Failures received (source=ue)",
    );
    let _ = writeln!(
        out,
        "amf_auth_failure_total{{source=\"network\"}} {}",
        get(&c.auth_rejects)
    );
    let _ = writeln!(
        out,
        "amf_auth_failure_total{{source=\"ue\"}} {}",
        get(&c.auth_failures_from_ue)
    );

    write_header(
        out,
        "amf_ngap_messages_total",
        "counter",
        "NGAP PDUs by direction, elementary procedure (TS 38.413 §9.4.7) and outcome",
    );
    let mut failures = Vec::new();
    for (d, dir) in [(NgapDirection::Rx, "rx"), (NgapDirection::Tx, "tx")] {
        for code in 0..=255u8 {
            for (o, outcome) in NGAP_OUTCOMES.iter().enumerate() {
                let n = ngap_count(d, code, o);
                if n == 0 {
                    continue;
                }
                let name = ngap_procedure_name(code);
                let _ = writeln!(out,
                    "amf_ngap_messages_total{{direction=\"{dir}\",procedure=\"{name}\",outcome=\"{outcome}\"}} {n}");
                if o == 2 {
                    failures.push((dir, name, n));
                }
            }
        }
    }
    write_header(
        out,
        "amf_ngap_failures_total",
        "counter",
        "NGAP unsuccessful outcomes (procedure failures) by direction and procedure",
    );
    for (dir, name, n) in failures {
        let _ = writeln!(
            out,
            "amf_ngap_failures_total{{direction=\"{dir}\",procedure=\"{name}\"}} {n}"
        );
    }

    let g = global();
    for metric in [
        GlobalMetric::NgResetUeIdled,
        GlobalMetric::UeAssociatedRefused,
    ] {
        write_metric(
            out,
            metric.name(),
            "counter",
            metric.description(),
            g.get(metric),
        );
    }
}

/// The whole AMF `/metrics` body.
pub fn render_prometheus() -> String {
    let mut out = nextgcore_metrics::nf::render_common(&nextgcore_metrics::nf::NfIdentity {
        nf: "amf",
        version: env!("CARGO_PKG_VERSION"),
        nrf_client: true,
    });
    render_amf_families(&mut out, &census());
    out
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Every AMF series the shipped Prometheus rules (`docker/rust/configs/
    /// observability/alert-rules.yml`) and Grafana dashboards (`.../dashboards/
    /// overview.json`, `docker/rust/monitoring/grafana/dashboards/nextg-overview.json`)
    /// query, plus the families every NF shares that they query.
    const SERIES_THE_RULES_AND_DASHBOARDS_USE: [&str; 14] = [
        "amf_registration_success_total",
        "amf_registration_failure_total",
        "amf_connected_ue_count",
        "amf_registered_ue_count",
        "amf_auth_success_total",
        "amf_auth_failure_total",
        "nextgcore_amf_active_sessions",
        "nextgcore_sbi_request_total",
        "nextgcore_sbi_error_total",
        "nextgcore_sbi_request_duration_seconds_bucket",
        "nextgcore_nrf_registered",
        "nextgcore_uptime_seconds",
        "process_resident_memory_bytes",
        "process_cpu_seconds_total",
    ];

    /// #1334: the AMF's `/metrics`, scraped over HTTP like Prometheus does, serves every
    /// series the rules and dashboards use, after one real Namf request through the
    /// production SBI server and handler.
    ///
    /// REVERT-VERIFIED: with `render_amf_families` left out of `render_prometheus` the
    /// `amf_*` series are missing, and without the SBI server's `record_sbi_request`
    /// the `nextgcore_sbi_*` ones are; either fails the loop.
    #[tokio::test]
    async fn the_scraped_endpoint_serves_every_series_the_rules_and_dashboards_use_1334() {
        crate::context::amf_context_init(64, 1024, 4096);
        let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let server = nextgcore_sbi::server::SbiServer::on_listener(
            nextgcore_sbi::server::SbiServerConfig::new(addr),
            listener,
        );
        server
            .start(crate::namf_server::namf_request_handler)
            .await
            .expect("Namf server starts");
        let client = nextgcore_sbi::client::SbiClient::with_host_port("127.0.0.1", addr.port());
        let answer = client
            .send_request(nextgcore_sbi::message::SbiRequest::get(
                "/namf-comm/v1/ue-contexts/imsi-001019999913340",
            ))
            .await
            .expect("Namf answers");
        assert!(answer.status >= 400, "no such UE: {}", answer.status);

        // #1334 review: an operation label is admitted on a 2xx, so a made-up resource
        // of every service this NF serves must be answered with an error, or a client
        // could mint label values.
        for (service, version) in [
            ("namf-comm", "v1"),
            ("namf-evts", "v1"),
            ("namf-mt", "v1"),
            ("namf-loc", "v1"),
            ("namf-callback", "v1"),
            ("namf-mbs-comm", "v1"),
            ("namf-mbs-bc", "v1"),
        ] {
            for path in [
                format!("/{service}/{version}/madeup-resource-1334"),
                format!("/{service}/{version}/imsi-001010000000001/madeup-resource-1334"),
            ] {
                for request in [
                    nextgcore_sbi::message::SbiRequest::get(&path),
                    nextgcore_sbi::message::SbiRequest::post(&path)
                        .with_body("{}", "application/json"),
                ] {
                    let resp = client.send_request(request).await.expect("answered");
                    assert!(resp.status >= 400, "{path} answered {}", resp.status);
                }
            }
        }
        let (bound, handle) = nextgcore_metrics::nes_energy::serve_metrics(
            "127.0.0.1:0".parse().unwrap(),
            std::sync::Arc::new(render_prometheus),
        )
        .await
        .expect("metrics endpoint");
        let body = nextgcore_metrics::nf::scrape_for_test(bound).await;
        for name in SERIES_THE_RULES_AND_DASHBOARDS_USE {
            assert!(
                nextgcore_metrics::nf::has_series(&body, name),
                "{name} missing from the AMF exposition:\n{body}"
            );
        }
        assert!(
            nextgcore_metrics::nf::has_series(&body, "nextgcore_sbi_error_total"),
            "{body}"
        );
        assert!(
            body.contains(r#"service="namf-comm",operation="unmatched""#)
                || body.contains(r#"service="namf-comm",operation="GET ue-contexts/{id}""#),
            "the Namf request is counted; a template not yet answered with success \
             is `unmatched`, never request text: {body}"
        );
        assert!(
            !body.contains("9999913340"),
            "no SUPI in the exposition: {body}"
        );
        assert!(
            !body.contains("madeup"),
            "no made-up resource in a label: {body}"
        );
        assert!(body.contains("nextgcore_build_info{nf=\"amf\""), "{body}");
        handle.abort();
        server.stop().await.expect("stops");
    }

    /// The census gauges render what the stores hold.
    #[test]
    fn the_census_gauges_render_the_values_given() {
        let mut out = String::new();
        render_amf_families(
            &mut out,
            &AmfCensus {
                registered_ues: 3,
                connected_ues: 2,
                pdu_sessions: 5,
            },
        );
        let v = |s| nextgcore_metrics::nf::sample_value(&out, s);
        assert_eq!(v("amf_registered_ue_count"), Some(3.0));
        assert_eq!(v("amf_connected_ue_count"), Some(2.0));
        assert_eq!(v("nextgcore_amf_active_sessions"), Some(5.0));
    }

    /// The NGAP header read: CHOICE index from octet 0, procedure code from octet 1.
    #[test]
    fn ngap_pdus_are_classified_by_choice_and_procedure_code() {
        assert_eq!(ngap_header(&[0x00, 0x15, 0x00]), Some((0, 21)));
        assert_eq!(ngap_header(&[0x20, 0x15, 0x00]), Some((1, 21)));
        assert_eq!(ngap_header(&[0x40, 0x0e, 0x00]), Some((2, 14)));
        assert_eq!(ngap_header(&[0x80, 0x15, 0x00]), None, "a CHOICE extension");
        assert_eq!(ngap_header(&[0x00]), None);
        assert_eq!(ngap_procedure_name(21), "NGSetup");
        assert_eq!(ngap_procedure_name(46), "UplinkNASTransport");
        assert_eq!(ngap_procedure_name(75), "BroadcastSessionReleaseRequired");
        assert_eq!(ngap_procedure_name(200), "unknown");
    }

    #[test]
    fn test_global_metric_names() {
        assert_eq!(GlobalMetric::RanUe.name(), "ran_ue");
        assert_eq!(
            GlobalMetric::RmRegInitReq.name(),
            "fivegs_amffunction_rm_reginitreq"
        );
    }

    #[test]
    fn test_global_metric_is_gauge() {
        assert!(GlobalMetric::RanUe.is_gauge());
        assert!(GlobalMetric::Gnb.is_gauge());
        assert!(!GlobalMetric::RmRegInitReq.is_gauge());
    }

    #[test]
    fn test_slice_metric_names() {
        assert_eq!(
            SliceMetric::RegisteredSubNbr.name(),
            "fivegs_amffunction_rm_registeredsubnbr"
        );
    }

    #[test]
    fn test_cause_metric_names() {
        assert_eq!(
            CauseMetric::RmRegInitFail.name(),
            "fivegs_amffunction_rm_reginitfail"
        );
    }

    #[test]
    fn test_metrics_inc() {
        let metrics = AmfMetrics::new();
        assert_eq!(metrics.get(GlobalMetric::RmRegInitReq), 0);
        metrics.inc(GlobalMetric::RmRegInitReq);
        assert_eq!(metrics.get(GlobalMetric::RmRegInitReq), 1);
        metrics.inc(GlobalMetric::RmRegInitReq);
        assert_eq!(metrics.get(GlobalMetric::RmRegInitReq), 2);
    }

    #[test]
    fn test_metrics_add() {
        let metrics = AmfMetrics::new();
        metrics.add(GlobalMetric::RmRegInitSucc, 5);
        assert_eq!(metrics.get(GlobalMetric::RmRegInitSucc), 5);
        metrics.add(GlobalMetric::RmRegInitSucc, 3);
        assert_eq!(metrics.get(GlobalMetric::RmRegInitSucc), 8);
    }

    #[test]
    fn test_metrics_set() {
        let metrics = AmfMetrics::new();
        metrics.set(GlobalMetric::RanUe, 100);
        assert_eq!(metrics.get(GlobalMetric::RanUe), 100);
        metrics.set(GlobalMetric::RanUe, 50);
        assert_eq!(metrics.get(GlobalMetric::RanUe), 50);
    }

    #[test]
    fn test_slice_metrics() {
        let metrics = AmfMetrics::new();
        let key = SliceKey {
            plmn_id: "310260".to_string(),
            snssai: "1-010203".to_string(),
        };

        metrics.add_slice_metric(key.clone(), SliceMetric::RegisteredSubNbr, 10);
        assert_eq!(
            metrics.get_slice_metric(&key, SliceMetric::RegisteredSubNbr),
            10
        );

        metrics.add_slice_metric(key.clone(), SliceMetric::RegisteredSubNbr, -3);
        assert_eq!(
            metrics.get_slice_metric(&key, SliceMetric::RegisteredSubNbr),
            7
        );
    }

    #[test]
    fn test_cause_metrics() {
        let metrics = AmfMetrics::new();
        metrics.add_cause_metric(5, CauseMetric::RmRegInitFail, 1);
        assert_eq!(metrics.get_cause_metric(5, CauseMetric::RmRegInitFail), 1);
        metrics.add_cause_metric(5, CauseMetric::RmRegInitFail, 2);
        assert_eq!(metrics.get_cause_metric(5, CauseMetric::RmRegInitFail), 3);
    }

    #[test]
    fn test_metrics_reset() {
        let metrics = AmfMetrics::new();
        metrics.inc(GlobalMetric::RmRegInitReq);
        metrics.set(GlobalMetric::RanUe, 100);

        let key = SliceKey {
            plmn_id: "310260".to_string(),
            snssai: "1".to_string(),
        };
        metrics.add_slice_metric(key.clone(), SliceMetric::RegisteredSubNbr, 10);

        metrics.reset();

        assert_eq!(metrics.get(GlobalMetric::RmRegInitReq), 0);
        assert_eq!(metrics.get(GlobalMetric::RanUe), 0);
        assert_eq!(
            metrics.get_slice_metric(&key, SliceMetric::RegisteredSubNbr),
            0
        );
    }

    #[test]
    fn test_export_prometheus() {
        let metrics = AmfMetrics::new();
        metrics.inc(GlobalMetric::RmRegInitReq);
        metrics.inc(GlobalMetric::RmRegInitSucc);
        metrics.set(GlobalMetric::RanUe, 5);

        let output = metrics.export_prometheus();
        assert!(output.contains("fivegs_amffunction_rm_reginitreq"));
        assert!(output.contains("ran_ue"));
        assert!(!output.is_empty());
    }

    #[test]
    fn test_get_summary() {
        let metrics = AmfMetrics::new();
        metrics.add(GlobalMetric::RmRegInitReq, 100);
        metrics.add(GlobalMetric::RmRegInitSucc, 95);
        metrics.set(GlobalMetric::RanUe, 50);
        metrics.set(GlobalMetric::Gnb, 3);

        let summary = metrics.get_summary();
        assert_eq!(summary.total_ran_ues, 50);
        assert_eq!(summary.total_gnbs, 3);
        assert_eq!(summary.reg_init_success_rate, 95.0);
    }

    #[test]
    fn test_calculate_success_rate() {
        let metrics = AmfMetrics::new();
        metrics.add(GlobalMetric::RmRegMobReq, 200);
        metrics.add(GlobalMetric::RmRegMobSucc, 180);

        let rate =
            metrics.calculate_success_rate(GlobalMetric::RmRegMobReq, GlobalMetric::RmRegMobSucc);
        assert_eq!(rate, 90.0);
    }

    #[test]
    fn test_calculate_success_rate_zero_requests() {
        let metrics = AmfMetrics::new();
        let rate =
            metrics.calculate_success_rate(GlobalMetric::RmRegMobReq, GlobalMetric::RmRegMobSucc);
        assert_eq!(rate, 0.0);
    }

    #[test]
    fn test_auth_success_rate() {
        let metrics = AmfMetrics::new();
        metrics.add(GlobalMetric::AmfAuthReq, 100);
        metrics.add(GlobalMetric::AmfAuthReject, 10);

        let summary = metrics.get_summary();
        assert_eq!(summary.auth_success_rate, 90.0);
    }
}
