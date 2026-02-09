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
            Self::RmRegMobReq => "Number of mobility registration update requests received by the AMF",
            Self::RmRegMobSucc => "Number of successful mobility registration updates at the AMF",
            Self::RmRegPeriodReq => "Number of periodic registration update requests received by the AMF",
            Self::RmRegPeriodSucc => "Number of successful periodic registration update requests at the AMF",
            Self::RmRegEmergReq => "Number of emergency registration requests received by the AMF",
            Self::RmRegEmergSucc => "Number of successful emergency registrations at the AMF",
            Self::MmPaging5gReq => "Number of 5G paging procedures initiated at the AMF",
            Self::MmPaging5gSucc => "Number of successful 5G paging procedures initiated at the AMF",
            Self::AmfAuthReq => "Number of authentication requests sent by the AMF",
            Self::AmfAuthReject => "Number of authentication rejections sent by the AMF",
            Self::MmConfUpdate => "Number of UE Configuration Update commands requested by the AMF",
            Self::MmConfUpdateSucc => "Number of UE Configuration Update complete messages received by the AMF",
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
            Self::RmRegPeriodFail => "Number of failed periodic registration update requests at the AMF",
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
            let metric_type = if metric.is_gauge() { "gauge" } else { "counter" };

            output.push_str(&format!(
                "# HELP {} {}\n",
                metric.name(),
                metric.description()
            ));
            output.push_str(&format!(
                "# TYPE {} {}\n",
                metric.name(),
                metric_type
            ));
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
            reg_init_success_rate: self.calculate_success_rate(
                GlobalMetric::RmRegInitReq,
                GlobalMetric::RmRegInitSucc,
            ),
            reg_mob_success_rate: self.calculate_success_rate(
                GlobalMetric::RmRegMobReq,
                GlobalMetric::RmRegMobSucc,
            ),
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
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_metric_names() {
        assert_eq!(GlobalMetric::RanUe.name(), "ran_ue");
        assert_eq!(GlobalMetric::RmRegInitReq.name(), "fivegs_amffunction_rm_reginitreq");
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
        assert_eq!(CauseMetric::RmRegInitFail.name(), "fivegs_amffunction_rm_reginitfail");
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
        assert_eq!(metrics.get_slice_metric(&key, SliceMetric::RegisteredSubNbr), 10);

        metrics.add_slice_metric(key.clone(), SliceMetric::RegisteredSubNbr, -3);
        assert_eq!(metrics.get_slice_metric(&key, SliceMetric::RegisteredSubNbr), 7);
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
        assert_eq!(metrics.get_slice_metric(&key, SliceMetric::RegisteredSubNbr), 0);
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

        let rate = metrics.calculate_success_rate(
            GlobalMetric::RmRegMobReq,
            GlobalMetric::RmRegMobSucc
        );
        assert_eq!(rate, 90.0);
    }

    #[test]
    fn test_calculate_success_rate_zero_requests() {
        let metrics = AmfMetrics::new();
        let rate = metrics.calculate_success_rate(
            GlobalMetric::RmRegMobReq,
            GlobalMetric::RmRegMobSucc
        );
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
