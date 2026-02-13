//! AI-Native Observability and SLA Monitoring (B5.1)
//!
//! Provides specialized metrics for AI/ML-driven network analytics (NWDAF),
//! SLA monitoring, and intent-based observability for 6G networks.

use std::collections::HashMap;

// ============================================================================
// AI-Native Metric Categories
// ============================================================================

/// Category of AI-native metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AiMetricCategory {
    /// NWDAF analytics metrics (model performance, data collection).
    NwdafAnalytics,
    /// Federated learning metrics (round progress, convergence).
    FederatedLearning,
    /// Inference metrics (latency, throughput, accuracy).
    Inference,
    /// Network slice SLA compliance.
    SliceSla,
    /// Energy efficiency metrics.
    Energy,
    /// ISAC sensing quality metrics.
    IsacSensing,
    /// Semantic communication quality metrics.
    SemanticComm,
}

/// Predefined AI-native metric definition.
#[derive(Debug, Clone)]
pub struct AiMetricDef {
    /// Metric name.
    pub name: &'static str,
    /// Help text.
    pub help: &'static str,
    /// Category.
    pub category: AiMetricCategory,
    /// Label names.
    pub labels: &'static [&'static str],
}

// ============================================================================
// Predefined NWDAF Metrics
// ============================================================================

/// NWDAF model inference latency (histogram).
pub const NWDAF_INFERENCE_LATENCY: AiMetricDef = AiMetricDef {
    name: "nwdaf_inference_latency_seconds",
    help: "Latency of ML model inference in NWDAF",
    category: AiMetricCategory::NwdafAnalytics,
    labels: &["model_id", "model_version", "nf_type"],
};

/// NWDAF analytics event count (counter).
pub const NWDAF_ANALYTICS_EVENTS: AiMetricDef = AiMetricDef {
    name: "nwdaf_analytics_events_total",
    help: "Total analytics events processed by NWDAF",
    category: AiMetricCategory::NwdafAnalytics,
    labels: &["event_type", "analytics_id"],
};

/// NWDAF data collection throughput (gauge).
pub const NWDAF_DATA_COLLECTION_RATE: AiMetricDef = AiMetricDef {
    name: "nwdaf_data_collection_rate_bytes",
    help: "Data collection rate in bytes per second",
    category: AiMetricCategory::NwdafAnalytics,
    labels: &["source_nf", "data_type"],
};

/// Federated learning round progress (gauge).
pub const FL_ROUND_PROGRESS: AiMetricDef = AiMetricDef {
    name: "fl_training_round_current",
    help: "Current federated learning training round",
    category: AiMetricCategory::FederatedLearning,
    labels: &["model_id", "aggregation_method"],
};

/// Federated learning convergence metric (gauge).
pub const FL_CONVERGENCE: AiMetricDef = AiMetricDef {
    name: "fl_convergence_loss",
    help: "Current loss value for federated learning convergence",
    category: AiMetricCategory::FederatedLearning,
    labels: &["model_id"],
};

/// Inference throughput (counter).
pub const INFERENCE_THROUGHPUT: AiMetricDef = AiMetricDef {
    name: "inference_requests_total",
    help: "Total inference requests processed",
    category: AiMetricCategory::Inference,
    labels: &["model_id", "result"],
};

// ============================================================================
// Predefined Energy Efficiency Metrics (Rel-18, TS 28.310)
// ============================================================================

/// Energy efficiency KPI: bits per joule (gauge).
pub const ENERGY_BITS_PER_JOULE: AiMetricDef = AiMetricDef {
    name: "energy_efficiency_bits_per_joule",
    help: "Energy efficiency in bits per joule per TS 28.310",
    category: AiMetricCategory::Energy,
    labels: &["nf_type", "nf_id", "slice_sst"],
};

/// Energy consumption in watts (gauge).
pub const ENERGY_CONSUMPTION_WATTS: AiMetricDef = AiMetricDef {
    name: "energy_consumption_watts",
    help: "Current energy consumption in watts",
    category: AiMetricCategory::Energy,
    labels: &["nf_type", "nf_id", "component"],
};

/// Total energy consumed in joules (counter).
pub const ENERGY_TOTAL_JOULES: AiMetricDef = AiMetricDef {
    name: "energy_consumed_joules_total",
    help: "Total energy consumed in joules",
    category: AiMetricCategory::Energy,
    labels: &["nf_type", "nf_id"],
};

/// Data volume in bits (counter).
pub const ENERGY_DATA_VOLUME_BITS: AiMetricDef = AiMetricDef {
    name: "energy_data_volume_bits_total",
    help: "Total data volume in bits for energy efficiency calculation",
    category: AiMetricCategory::Energy,
    labels: &["nf_type", "nf_id", "direction"],
};

/// Cell sleep ratio (gauge, 0.0-1.0).
pub const ENERGY_SLEEP_RATIO: AiMetricDef = AiMetricDef {
    name: "energy_sleep_ratio",
    help: "Ratio of time in sleep/dormant mode (0.0-1.0)",
    category: AiMetricCategory::Energy,
    labels: &["nf_type", "nf_id", "cell_id"],
};

// ============================================================================
// Energy Efficiency Monitor (Rel-18, TS 28.310)
// ============================================================================

/// Energy efficiency KPI per TS 28.310.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnergyKpi {
    /// EE_DV: Data volume-based energy efficiency (bits/J).
    DataVolumeEe,
    /// EE_SC: Service capacity-based energy efficiency.
    ServiceCapacityEe,
    /// EE_CO: Coverage-based energy efficiency.
    CoverageEe,
    /// Power consumption (watts).
    PowerConsumption,
    /// Sleep ratio (fraction of time in sleep mode).
    SleepRatio,
}

impl EnergyKpi {
    /// Returns the unit string for this KPI.
    pub fn unit(&self) -> &'static str {
        match self {
            Self::DataVolumeEe => "bits/J",
            Self::ServiceCapacityEe => "connections/J",
            Self::CoverageEe => "km2/J",
            Self::PowerConsumption => "W",
            Self::SleepRatio => "ratio",
        }
    }
}

/// NF energy metrics entry.
#[derive(Debug, Clone)]
pub struct NfEnergyMetrics {
    /// NF type (e.g., "gNB", "UPF", "AMF").
    pub nf_type: String,
    /// NF identifier.
    pub nf_id: String,
    /// Current power consumption in watts.
    pub power_consumption_w: f64,
    /// Total energy consumed in joules.
    pub total_energy_j: f64,
    /// Total data volume in bits (uplink + downlink).
    pub total_data_bits: u64,
    /// Time active (seconds).
    pub time_active_s: f64,
    /// Time in sleep mode (seconds).
    pub time_sleep_s: f64,
}

impl NfEnergyMetrics {
    /// Creates a new NF energy metrics entry.
    pub fn new(nf_type: &str, nf_id: &str) -> Self {
        Self {
            nf_type: nf_type.to_string(),
            nf_id: nf_id.to_string(),
            power_consumption_w: 0.0,
            total_energy_j: 0.0,
            total_data_bits: 0,
            time_active_s: 0.0,
            time_sleep_s: 0.0,
        }
    }

    /// Data volume energy efficiency (bits/J).
    pub fn bits_per_joule(&self) -> f64 {
        if self.total_energy_j > 0.0 {
            self.total_data_bits as f64 / self.total_energy_j
        } else {
            0.0
        }
    }

    /// Sleep ratio (0.0 - 1.0).
    pub fn sleep_ratio(&self) -> f64 {
        let total = self.time_active_s + self.time_sleep_s;
        if total > 0.0 {
            self.time_sleep_s / total
        } else {
            0.0
        }
    }
}

/// Energy efficiency monitoring engine per TS 28.310.
pub struct EnergyMonitor {
    /// NF energy metrics by NF ID.
    nf_metrics: HashMap<String, NfEnergyMetrics>,
    /// Total reporting periods.
    reporting_count: u64,
}

impl Default for EnergyMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl EnergyMonitor {
    /// Creates a new energy monitor.
    pub fn new() -> Self {
        Self {
            nf_metrics: HashMap::new(),
            reporting_count: 0,
        }
    }

    /// Register an NF for energy monitoring.
    pub fn register_nf(&mut self, nf_type: &str, nf_id: &str) {
        self.nf_metrics
            .insert(nf_id.to_string(), NfEnergyMetrics::new(nf_type, nf_id));
    }

    /// Update power consumption for an NF.
    pub fn update_power(&mut self, nf_id: &str, power_w: f64) {
        if let Some(metrics) = self.nf_metrics.get_mut(nf_id) {
            metrics.power_consumption_w = power_w;
        }
    }

    /// Record energy consumed by an NF during a time period.
    pub fn record_energy(&mut self, nf_id: &str, energy_j: f64, data_bits: u64) {
        if let Some(metrics) = self.nf_metrics.get_mut(nf_id) {
            metrics.total_energy_j += energy_j;
            metrics.total_data_bits += data_bits;
        }
    }

    /// Record time spent in active/sleep states.
    pub fn record_time(&mut self, nf_id: &str, active_s: f64, sleep_s: f64) {
        if let Some(metrics) = self.nf_metrics.get_mut(nf_id) {
            metrics.time_active_s += active_s;
            metrics.time_sleep_s += sleep_s;
        }
    }

    /// Get energy efficiency for an NF.
    pub fn get_efficiency(&self, nf_id: &str) -> Option<f64> {
        self.nf_metrics.get(nf_id).map(|m| m.bits_per_joule())
    }

    /// Get metrics for an NF.
    pub fn get_nf_metrics(&self, nf_id: &str) -> Option<&NfEnergyMetrics> {
        self.nf_metrics.get(nf_id)
    }

    /// Report all NF efficiencies.
    pub fn report_all(&mut self) -> Vec<(String, f64)> {
        self.reporting_count += 1;
        self.nf_metrics
            .iter()
            .map(|(id, m)| (id.clone(), m.bits_per_joule()))
            .collect()
    }

    /// Number of monitored NFs.
    pub fn nf_count(&self) -> usize {
        self.nf_metrics.len()
    }

    /// Total reporting periods.
    pub fn reporting_count(&self) -> u64 {
        self.reporting_count
    }
}

// ============================================================================
// SLA Monitoring
// ============================================================================

/// SLA target specification.
#[derive(Debug, Clone)]
pub struct SlaTarget {
    /// SLA identifier.
    pub sla_id: String,
    /// Slice SST.
    pub sst: u8,
    /// Optional slice SD.
    pub sd: Option<u32>,
    /// KPI targets.
    pub kpi_targets: Vec<SlaKpiTarget>,
    /// Whether SLA is currently met.
    pub compliant: bool,
    /// Compliance percentage (0.0-100.0).
    pub compliance_pct: f64,
}

/// Individual KPI target within an SLA.
#[derive(Debug, Clone)]
pub struct SlaKpiTarget {
    /// KPI name.
    pub kpi: SlaKpi,
    /// Target value.
    pub target: f64,
    /// Current measured value.
    pub current: f64,
    /// Comparison: true if current should be <= target.
    pub less_is_better: bool,
}

impl SlaKpiTarget {
    /// Returns true if this KPI target is being met.
    pub fn is_met(&self) -> bool {
        if self.less_is_better {
            self.current <= self.target
        } else {
            self.current >= self.target
        }
    }
}

/// Standard SLA KPI types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlaKpi {
    /// End-to-end latency (ms).
    E2eLatency,
    /// Packet loss ratio (%).
    PacketLoss,
    /// Throughput (Mbps).
    Throughput,
    /// Availability (%).
    Availability,
    /// Reliability (%).
    Reliability,
    /// Jitter (ms).
    Jitter,
    /// Energy efficiency (bits/joule).
    EnergyEfficiency,
}

impl SlaKpi {
    /// Returns the unit string for this KPI.
    pub fn unit(&self) -> &'static str {
        match self {
            Self::E2eLatency => "ms",
            Self::PacketLoss => "%",
            Self::Throughput => "Mbps",
            Self::Availability => "%",
            Self::Reliability => "%",
            Self::Jitter => "ms",
            Self::EnergyEfficiency => "bits/J",
        }
    }

    /// Whether lower values are better for this KPI.
    pub fn less_is_better(&self) -> bool {
        matches!(self, Self::E2eLatency | Self::PacketLoss | Self::Jitter)
    }
}

// ============================================================================
// SLA Monitor
// ============================================================================

/// SLA monitoring engine.
pub struct SlaMonitor {
    /// Active SLA targets.
    targets: HashMap<String, SlaTarget>,
    /// Total evaluations.
    evaluation_count: u64,
    /// Total violations.
    violation_count: u64,
}

impl Default for SlaMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl SlaMonitor {
    /// Creates a new SLA monitor.
    pub fn new() -> Self {
        Self {
            targets: HashMap::new(),
            evaluation_count: 0,
            violation_count: 0,
        }
    }

    /// Register an SLA target.
    pub fn register_sla(&mut self, target: SlaTarget) {
        self.targets.insert(target.sla_id.clone(), target);
    }

    /// Update a KPI measurement for an SLA.
    pub fn update_kpi(&mut self, sla_id: &str, kpi: SlaKpi, value: f64) {
        if let Some(target) = self.targets.get_mut(sla_id) {
            for kt in &mut target.kpi_targets {
                if kt.kpi == kpi {
                    kt.current = value;
                }
            }
        }
    }

    /// Evaluate all SLAs and update compliance status.
    pub fn evaluate(&mut self) -> Vec<SlaViolation> {
        self.evaluation_count += 1;
        let mut violations = Vec::new();

        for target in self.targets.values_mut() {
            let total = target.kpi_targets.len() as f64;
            let met = target.kpi_targets.iter().filter(|kt| kt.is_met()).count() as f64;

            target.compliance_pct = if total > 0.0 { (met / total) * 100.0 } else { 100.0 };
            target.compliant = (target.compliance_pct - 100.0).abs() < f64::EPSILON;

            if !target.compliant {
                for kt in &target.kpi_targets {
                    if !kt.is_met() {
                        violations.push(SlaViolation {
                            sla_id: target.sla_id.clone(),
                            kpi: kt.kpi,
                            target: kt.target,
                            actual: kt.current,
                        });
                    }
                }
            }
        }

        self.violation_count += violations.len() as u64;
        violations
    }

    /// Get SLA by ID.
    pub fn get_sla(&self, sla_id: &str) -> Option<&SlaTarget> {
        self.targets.get(sla_id)
    }

    /// Total registered SLAs.
    pub fn sla_count(&self) -> usize {
        self.targets.len()
    }

    /// Total evaluations performed.
    pub fn evaluation_count(&self) -> u64 {
        self.evaluation_count
    }

    /// Total violations detected.
    pub fn violation_count(&self) -> u64 {
        self.violation_count
    }
}

/// SLA violation report.
#[derive(Debug, Clone)]
pub struct SlaViolation {
    /// SLA that was violated.
    pub sla_id: String,
    /// KPI that failed.
    pub kpi: SlaKpi,
    /// Target value.
    pub target: f64,
    /// Actual value.
    pub actual: f64,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ai_metric_def() {
        assert_eq!(NWDAF_INFERENCE_LATENCY.category, AiMetricCategory::NwdafAnalytics);
        assert_eq!(FL_ROUND_PROGRESS.category, AiMetricCategory::FederatedLearning);
    }

    #[test]
    fn test_sla_kpi_unit() {
        assert_eq!(SlaKpi::E2eLatency.unit(), "ms");
        assert_eq!(SlaKpi::Throughput.unit(), "Mbps");
        assert!(SlaKpi::PacketLoss.less_is_better());
        assert!(!SlaKpi::Throughput.less_is_better());
    }

    #[test]
    fn test_sla_kpi_target_met() {
        let target = SlaKpiTarget {
            kpi: SlaKpi::E2eLatency,
            target: 10.0,
            current: 8.0,
            less_is_better: true,
        };
        assert!(target.is_met());

        let target_violated = SlaKpiTarget {
            kpi: SlaKpi::E2eLatency,
            target: 10.0,
            current: 15.0,
            less_is_better: true,
        };
        assert!(!target_violated.is_met());
    }

    #[test]
    fn test_sla_monitor() {
        let mut monitor = SlaMonitor::new();

        let sla = SlaTarget {
            sla_id: "urllc-slice-1".to_string(),
            sst: 2,
            sd: None,
            kpi_targets: vec![
                SlaKpiTarget {
                    kpi: SlaKpi::E2eLatency,
                    target: 1.0,
                    current: 0.5,
                    less_is_better: true,
                },
                SlaKpiTarget {
                    kpi: SlaKpi::Reliability,
                    target: 99.999,
                    current: 99.995,
                    less_is_better: false,
                },
            ],
            compliant: true,
            compliance_pct: 100.0,
        };

        monitor.register_sla(sla);
        assert_eq!(monitor.sla_count(), 1);

        let violations = monitor.evaluate();
        assert_eq!(violations.len(), 1); // Reliability is 99.995 < 99.999
        assert_eq!(monitor.evaluation_count(), 1);
    }

    #[test]
    fn test_energy_kpi_unit() {
        assert_eq!(EnergyKpi::DataVolumeEe.unit(), "bits/J");
        assert_eq!(EnergyKpi::PowerConsumption.unit(), "W");
        assert_eq!(EnergyKpi::SleepRatio.unit(), "ratio");
    }

    #[test]
    fn test_energy_metric_defs() {
        assert_eq!(ENERGY_BITS_PER_JOULE.category, AiMetricCategory::Energy);
        assert_eq!(ENERGY_CONSUMPTION_WATTS.category, AiMetricCategory::Energy);
        assert_eq!(ENERGY_TOTAL_JOULES.category, AiMetricCategory::Energy);
        assert_eq!(ENERGY_DATA_VOLUME_BITS.category, AiMetricCategory::Energy);
        assert_eq!(ENERGY_SLEEP_RATIO.category, AiMetricCategory::Energy);
    }

    #[test]
    fn test_nf_energy_metrics() {
        let mut m = NfEnergyMetrics::new("gNB", "gnb-001");
        assert_eq!(m.bits_per_joule(), 0.0);
        assert_eq!(m.sleep_ratio(), 0.0);

        m.total_energy_j = 100.0;
        m.total_data_bits = 1_000_000;
        assert_eq!(m.bits_per_joule(), 10_000.0);

        m.time_active_s = 80.0;
        m.time_sleep_s = 20.0;
        assert!((m.sleep_ratio() - 0.2).abs() < f64::EPSILON);
    }

    #[test]
    fn test_energy_monitor() {
        let mut monitor = EnergyMonitor::new();

        monitor.register_nf("gNB", "gnb-001");
        monitor.register_nf("UPF", "upf-001");
        assert_eq!(monitor.nf_count(), 2);

        monitor.update_power("gnb-001", 100.0);
        monitor.record_energy("gnb-001", 500.0, 5_000_000);
        monitor.record_time("gnb-001", 4.0, 1.0);

        let eff = monitor.get_efficiency("gnb-001").unwrap();
        assert_eq!(eff, 10_000.0); // 5M bits / 500 J

        let m = monitor.get_nf_metrics("gnb-001").unwrap();
        assert_eq!(m.power_consumption_w, 100.0);
        assert!((m.sleep_ratio() - 0.2).abs() < f64::EPSILON);

        let report = monitor.report_all();
        assert_eq!(report.len(), 2);
        assert_eq!(monitor.reporting_count(), 1);
    }

    #[test]
    fn test_sla_monitor_update_kpi() {
        let mut monitor = SlaMonitor::new();

        let sla = SlaTarget {
            sla_id: "embb-slice".to_string(),
            sst: 1,
            sd: None,
            kpi_targets: vec![SlaKpiTarget {
                kpi: SlaKpi::Throughput,
                target: 100.0,
                current: 0.0,
                less_is_better: false,
            }],
            compliant: false,
            compliance_pct: 0.0,
        };

        monitor.register_sla(sla);
        monitor.update_kpi("embb-slice", SlaKpi::Throughput, 150.0);

        let violations = monitor.evaluate();
        assert!(violations.is_empty()); // 150 >= 100
    }
}

// ============================================================================
// Distributed Trace Correlation for AI Pipelines (B5.2)
// ============================================================================

/// Trace segment representing one hop in a distributed AI pipeline.
#[derive(Debug, Clone)]
pub struct AiTraceSegment {
    /// Segment identifier.
    pub segment_id: String,
    /// Parent segment (None for root).
    pub parent_id: Option<String>,
    /// NF that executed this segment.
    pub nf_id: String,
    /// Operation name (e.g., "model_inference", "data_collection").
    pub operation: String,
    /// Start timestamp (epoch ms).
    pub start_ms: u64,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Status (true = success).
    pub success: bool,
    /// Attributes.
    pub attributes: HashMap<String, String>,
}

/// Distributed trace spanning multiple NFs in an AI/ML pipeline.
#[derive(Debug, Clone)]
pub struct AiPipelineTrace {
    /// Trace identifier (unique across the pipeline).
    pub trace_id: String,
    /// Pipeline name (e.g., "nwdaf_anomaly_detection").
    pub pipeline_name: String,
    /// Ordered segments.
    pub segments: Vec<AiTraceSegment>,
    /// Overall status.
    pub completed: bool,
}

impl AiPipelineTrace {
    /// Create a new pipeline trace.
    pub fn new(trace_id: impl Into<String>, pipeline_name: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            pipeline_name: pipeline_name.into(),
            segments: Vec::new(),
            completed: false,
        }
    }

    /// Add a trace segment.
    pub fn add_segment(&mut self, segment: AiTraceSegment) {
        self.segments.push(segment);
    }

    /// Total end-to-end latency (first segment start to last segment end).
    pub fn e2e_latency_ms(&self) -> u64 {
        if self.segments.is_empty() {
            return 0;
        }
        let earliest = self.segments.iter().map(|s| s.start_ms).min().unwrap_or(0);
        let latest = self.segments.iter().map(|s| s.start_ms + s.duration_ms).max().unwrap_or(0);
        latest.saturating_sub(earliest)
    }

    /// Count of failed segments.
    pub fn failure_count(&self) -> usize {
        self.segments.iter().filter(|s| !s.success).count()
    }

    /// Mark the trace as completed.
    pub fn complete(&mut self) {
        self.completed = true;
    }
}

/// AI pipeline trace collector.
pub struct AiTraceCollector {
    /// Active traces by trace ID.
    traces: HashMap<String, AiPipelineTrace>,
    /// Completed traces (for analysis).
    completed: Vec<AiPipelineTrace>,
    /// Max completed traces to retain.
    max_completed: usize,
}

impl AiTraceCollector {
    /// Create a new trace collector.
    pub fn new(max_completed: usize) -> Self {
        Self {
            traces: HashMap::new(),
            completed: Vec::new(),
            max_completed,
        }
    }

    /// Start a new pipeline trace.
    pub fn start_trace(&mut self, trace_id: impl Into<String>, pipeline_name: impl Into<String>) -> String {
        let id: String = trace_id.into();
        let trace = AiPipelineTrace::new(id.clone(), pipeline_name);
        self.traces.insert(id.clone(), trace);
        id
    }

    /// Add a segment to an active trace.
    pub fn add_segment(&mut self, trace_id: &str, segment: AiTraceSegment) -> bool {
        if let Some(trace) = self.traces.get_mut(trace_id) {
            trace.add_segment(segment);
            true
        } else {
            false
        }
    }

    /// Complete a trace and move it to the completed list.
    pub fn complete_trace(&mut self, trace_id: &str) -> bool {
        if let Some(mut trace) = self.traces.remove(trace_id) {
            trace.complete();
            self.completed.push(trace);
            if self.completed.len() > self.max_completed {
                self.completed.remove(0);
            }
            true
        } else {
            false
        }
    }

    /// Get an active trace.
    pub fn get_trace(&self, trace_id: &str) -> Option<&AiPipelineTrace> {
        self.traces.get(trace_id)
    }

    /// Number of active traces.
    pub fn active_count(&self) -> usize {
        self.traces.len()
    }

    /// Number of completed traces.
    pub fn completed_count(&self) -> usize {
        self.completed.len()
    }

    /// Average E2E latency of completed traces (ms).
    pub fn avg_e2e_latency_ms(&self) -> f64 {
        if self.completed.is_empty() {
            return 0.0;
        }
        let total: u64 = self.completed.iter().map(|t| t.e2e_latency_ms()).sum();
        total as f64 / self.completed.len() as f64
    }
}

impl Default for AiTraceCollector {
    fn default() -> Self {
        Self::new(1000)
    }
}

#[cfg(test)]
mod trace_tests {
    use super::*;

    #[test]
    fn test_pipeline_trace_e2e() {
        let mut trace = AiPipelineTrace::new("t1", "anomaly_detection");
        trace.add_segment(AiTraceSegment {
            segment_id: "s1".into(),
            parent_id: None,
            nf_id: "nwdaf-1".into(),
            operation: "data_collection".into(),
            start_ms: 1000,
            duration_ms: 50,
            success: true,
            attributes: HashMap::new(),
        });
        trace.add_segment(AiTraceSegment {
            segment_id: "s2".into(),
            parent_id: Some("s1".into()),
            nf_id: "nwdaf-1".into(),
            operation: "model_inference".into(),
            start_ms: 1050,
            duration_ms: 30,
            success: true,
            attributes: HashMap::new(),
        });

        assert_eq!(trace.e2e_latency_ms(), 80); // 1080 - 1000
        assert_eq!(trace.failure_count(), 0);
    }

    #[test]
    fn test_trace_collector() {
        let mut collector = AiTraceCollector::new(10);
        let trace_id = collector.start_trace("t1", "pipeline");
        assert_eq!(collector.active_count(), 1);

        collector.add_segment(&trace_id, AiTraceSegment {
            segment_id: "s1".into(),
            parent_id: None,
            nf_id: "amf-1".into(),
            operation: "classify".into(),
            start_ms: 100,
            duration_ms: 20,
            success: true,
            attributes: HashMap::new(),
        });

        collector.complete_trace(&trace_id);
        assert_eq!(collector.active_count(), 0);
        assert_eq!(collector.completed_count(), 1);
        assert!((collector.avg_e2e_latency_ms() - 20.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_trace_collector_max_completed() {
        let mut collector = AiTraceCollector::new(2);
        for i in 0..5 {
            let id = format!("t{i}");
            collector.start_trace(id.clone(), "p");
            collector.complete_trace(&id);
        }
        assert_eq!(collector.completed_count(), 2);
    }
}
