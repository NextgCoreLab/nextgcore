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
