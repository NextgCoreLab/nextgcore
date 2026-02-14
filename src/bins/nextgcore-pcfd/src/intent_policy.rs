//! Intent-Based Policy Control (Item #194)
//!
//! Translates high-level network intents into concrete PCF policies.
//! Supports energy-aware policy generation and AI-driven optimization.

use std::collections::HashMap;

// ============================================================================
// Intent-Based Policy
// ============================================================================

/// High-level policy intent.
#[derive(Debug, Clone)]
pub struct PolicyIntent {
    /// Intent identifier.
    pub id: u64,
    /// Intent type.
    pub intent_type: PolicyIntentType,
    /// Target slice SST.
    pub target_sst: Option<u8>,
    /// Priority (0-255).
    pub priority: u8,
    /// Constraints.
    pub constraints: Vec<PolicyConstraint>,
}

/// Types of policy intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyIntentType {
    /// Maximize throughput for a slice.
    MaxThroughput,
    /// Minimize latency for a slice.
    MinLatency,
    /// Ensure reliability target.
    EnsureReliability,
    /// Minimize energy consumption.
    MinEnergy,
    /// Balance load across slices.
    LoadBalance,
    /// Optimize for XR traffic.
    XrOptimize,
}

/// Policy constraint.
#[derive(Debug, Clone)]
pub enum PolicyConstraint {
    /// Maximum latency in milliseconds.
    MaxLatencyMs(f64),
    /// Minimum throughput in Mbps.
    MinThroughputMbps(f64),
    /// Maximum packet loss ratio.
    MaxPacketLoss(f64),
    /// Maximum power budget in watts.
    MaxPowerWatts(f64),
    /// Minimum reliability percentage.
    MinReliability(f64),
}

/// Generated QoS policy from intent.
#[derive(Debug, Clone)]
pub struct GeneratedPolicy {
    /// Source intent ID.
    pub intent_id: u64,
    /// 5QI value.
    pub five_qi: u16,
    /// ARP priority level.
    pub arp_priority: u8,
    /// Maximum bit rate DL (kbps).
    pub mbr_dl_kbps: u64,
    /// Maximum bit rate UL (kbps).
    pub mbr_ul_kbps: u64,
    /// Guaranteed bit rate DL (kbps).
    pub gbr_dl_kbps: u64,
    /// Guaranteed bit rate UL (kbps).
    pub gbr_ul_kbps: u64,
    /// DRX cycle (ms).
    pub drx_cycle_ms: u32,
    /// Energy mode.
    pub energy_mode: EnergyPolicyMode,
}

/// Energy policy mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnergyPolicyMode {
    /// No energy optimization.
    Normal,
    /// Extended DRX for battery saving.
    ExtendedDrx,
    /// Reduced measurement frequency.
    ReducedMeasurement,
    /// Full energy optimization.
    FullOptimization,
}

/// Intent-to-policy translator.
pub struct IntentPolicyTranslator {
    /// Generated policies.
    policies: HashMap<u64, GeneratedPolicy>,
    /// Translation count.
    translation_count: u64,
}

impl IntentPolicyTranslator {
    /// Creates a new translator.
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            translation_count: 0,
        }
    }

    /// Translate an intent into a concrete policy.
    pub fn translate(&mut self, intent: &PolicyIntent) -> GeneratedPolicy {
        self.translation_count += 1;

        let (five_qi, arp, drx) = match intent.intent_type {
            PolicyIntentType::MaxThroughput => (9, 10, 320),      // Non-GBR, default
            PolicyIntentType::MinLatency => (1, 2, 10),            // GBR, short DRX
            PolicyIntentType::EnsureReliability => (82, 1, 40),    // Delay-critical GBR
            PolicyIntentType::MinEnergy => (9, 15, 2560),          // Non-GBR, long DRX
            PolicyIntentType::LoadBalance => (9, 8, 320),          // Non-GBR, default
            PolicyIntentType::XrOptimize => (2, 3, 20),            // GBR, short DRX
        };

        let energy_mode = match intent.intent_type {
            PolicyIntentType::MinEnergy => EnergyPolicyMode::FullOptimization,
            PolicyIntentType::MinLatency | PolicyIntentType::XrOptimize => EnergyPolicyMode::Normal,
            _ => {
                let has_power_constraint = intent.constraints.iter().any(|c| matches!(c, PolicyConstraint::MaxPowerWatts(_)));
                if has_power_constraint { EnergyPolicyMode::ExtendedDrx } else { EnergyPolicyMode::Normal }
            }
        };

        // Apply constraints to tune values
        let mut mbr_dl = 1_000_000; // 1 Gbps default
        let mut mbr_ul = 500_000;   // 500 Mbps default
        let mut final_drx = drx;

        for constraint in &intent.constraints {
            match constraint {
                PolicyConstraint::MinThroughputMbps(mbps) => {
                    mbr_dl = mbr_dl.max((*mbps * 1000.0) as u64);
                    mbr_ul = mbr_ul.max((*mbps * 500.0) as u64);
                }
                PolicyConstraint::MaxLatencyMs(ms) if *ms < 10.0 => {
                    final_drx = final_drx.min(10);
                }
                _ => {}
            }
        }

        let policy = GeneratedPolicy {
            intent_id: intent.id,
            five_qi,
            arp_priority: arp,
            mbr_dl_kbps: mbr_dl,
            mbr_ul_kbps: mbr_ul,
            gbr_dl_kbps: 0,
            gbr_ul_kbps: 0,
            drx_cycle_ms: final_drx,
            energy_mode,
        };

        self.policies.insert(intent.id, policy.clone());
        policy
    }

    /// Get a generated policy by intent ID.
    pub fn get_policy(&self, intent_id: u64) -> Option<&GeneratedPolicy> {
        self.policies.get(&intent_id)
    }

    /// Total translations performed.
    pub fn translation_count(&self) -> u64 { self.translation_count }

    /// Active policies.
    pub fn policy_count(&self) -> usize { self.policies.len() }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translate_min_latency() {
        let mut translator = IntentPolicyTranslator::new();
        let intent = PolicyIntent {
            id: 1,
            intent_type: PolicyIntentType::MinLatency,
            target_sst: Some(2),
            priority: 1,
            constraints: vec![PolicyConstraint::MaxLatencyMs(1.0)],
        };
        let policy = translator.translate(&intent);
        assert_eq!(policy.five_qi, 1);
        assert!(policy.drx_cycle_ms <= 10);
        assert_eq!(policy.energy_mode, EnergyPolicyMode::Normal);
    }

    #[test]
    fn test_translate_min_energy() {
        let mut translator = IntentPolicyTranslator::new();
        let intent = PolicyIntent {
            id: 2,
            intent_type: PolicyIntentType::MinEnergy,
            target_sst: Some(1),
            priority: 10,
            constraints: vec![PolicyConstraint::MaxPowerWatts(1.0)],
        };
        let policy = translator.translate(&intent);
        assert_eq!(policy.energy_mode, EnergyPolicyMode::FullOptimization);
        assert!(policy.drx_cycle_ms >= 2560);
    }

    #[test]
    fn test_translate_xr() {
        let mut translator = IntentPolicyTranslator::new();
        let intent = PolicyIntent {
            id: 3,
            intent_type: PolicyIntentType::XrOptimize,
            target_sst: None,
            priority: 3,
            constraints: vec![
                PolicyConstraint::MaxLatencyMs(5.0),
                PolicyConstraint::MinThroughputMbps(100.0),
            ],
        };
        let policy = translator.translate(&intent);
        assert_eq!(policy.five_qi, 2); // GBR
        assert!(policy.mbr_dl_kbps >= 100_000);
    }

    #[test]
    fn test_translator_counts() {
        let mut translator = IntentPolicyTranslator::new();
        let intent = PolicyIntent {
            id: 1,
            intent_type: PolicyIntentType::LoadBalance,
            target_sst: None,
            priority: 5,
            constraints: vec![],
        };
        translator.translate(&intent);
        assert_eq!(translator.translation_count(), 1);
        assert_eq!(translator.policy_count(), 1);
    }

    #[test]
    fn test_sla_policy_adapter_no_violation() {
        let adapter = SlaPolicyAdapter::new(0.2);
        let policy = GeneratedPolicy {
            intent_id: 1,
            five_qi: 9,
            arp_priority: 10,
            mbr_dl_kbps: 100_000,
            mbr_ul_kbps: 50_000,
            gbr_dl_kbps: 0,
            gbr_ul_kbps: 0,
            drx_cycle_ms: 320,
            energy_mode: EnergyPolicyMode::Normal,
        };
        let feedback = SlaFeedback {
            latency_ms: 5.0,
            target_latency_ms: 10.0,
            throughput_mbps: 200.0,
            target_throughput_mbps: 100.0,
            packet_loss_pct: 0.01,
            target_packet_loss_pct: 1.0,
        };

        let adapted = adapter.adapt(&policy, &feedback);
        // No violations, policy should be unchanged
        assert_eq!(adapted.drx_cycle_ms, policy.drx_cycle_ms);
    }

    #[test]
    fn test_sla_policy_adapter_latency_violation() {
        let adapter = SlaPolicyAdapter::new(0.5);
        let policy = GeneratedPolicy {
            intent_id: 2,
            five_qi: 9,
            arp_priority: 10,
            mbr_dl_kbps: 100_000,
            mbr_ul_kbps: 50_000,
            gbr_dl_kbps: 0,
            gbr_ul_kbps: 0,
            drx_cycle_ms: 320,
            energy_mode: EnergyPolicyMode::Normal,
        };
        let feedback = SlaFeedback {
            latency_ms: 15.0,
            target_latency_ms: 10.0,
            throughput_mbps: 200.0,
            target_throughput_mbps: 100.0,
            packet_loss_pct: 0.01,
            target_packet_loss_pct: 1.0,
        };

        let adapted = adapter.adapt(&policy, &feedback);
        // Latency violation: DRX should decrease
        assert!(adapted.drx_cycle_ms < policy.drx_cycle_ms);
    }

    #[test]
    fn test_sla_policy_adapter_throughput_violation() {
        let adapter = SlaPolicyAdapter::new(0.5);
        let policy = GeneratedPolicy {
            intent_id: 3,
            five_qi: 9,
            arp_priority: 10,
            mbr_dl_kbps: 100_000,
            mbr_ul_kbps: 50_000,
            gbr_dl_kbps: 0,
            gbr_ul_kbps: 0,
            drx_cycle_ms: 320,
            energy_mode: EnergyPolicyMode::Normal,
        };
        let feedback = SlaFeedback {
            latency_ms: 5.0,
            target_latency_ms: 10.0,
            throughput_mbps: 50.0,
            target_throughput_mbps: 100.0,
            packet_loss_pct: 0.01,
            target_packet_loss_pct: 1.0,
        };

        let adapted = adapter.adapt(&policy, &feedback);
        // Throughput violation: MBR should increase
        assert!(adapted.mbr_dl_kbps > policy.mbr_dl_kbps);
    }
}

// ============================================================================
// SLA-Aware Policy Adaptation (B6.4)
// ============================================================================

/// Real-time SLA feedback for policy adaptation.
#[derive(Debug, Clone)]
pub struct SlaFeedback {
    /// Current measured latency (ms).
    pub latency_ms: f64,
    /// Target latency (ms).
    pub target_latency_ms: f64,
    /// Current measured throughput (Mbps).
    pub throughput_mbps: f64,
    /// Target throughput (Mbps).
    pub target_throughput_mbps: f64,
    /// Current packet loss percentage.
    pub packet_loss_pct: f64,
    /// Target packet loss percentage.
    pub target_packet_loss_pct: f64,
}

impl SlaFeedback {
    /// Whether latency SLA is violated.
    pub fn latency_violated(&self) -> bool {
        self.latency_ms > self.target_latency_ms
    }

    /// Whether throughput SLA is violated.
    pub fn throughput_violated(&self) -> bool {
        self.throughput_mbps < self.target_throughput_mbps
    }

    /// Whether packet loss SLA is violated.
    pub fn packet_loss_violated(&self) -> bool {
        self.packet_loss_pct > self.target_packet_loss_pct
    }
}

/// SLA-aware policy adapter that tunes generated policies in response to
/// real-time SLA measurements.
pub struct SlaPolicyAdapter {
    /// Adaptation aggressiveness (0.0 to 1.0).
    aggressiveness: f64,
}

impl SlaPolicyAdapter {
    /// Create a new SLA policy adapter.
    pub fn new(aggressiveness: f64) -> Self {
        Self {
            aggressiveness: aggressiveness.clamp(0.0, 1.0),
        }
    }

    /// Adapt a policy based on SLA feedback.
    pub fn adapt(&self, policy: &GeneratedPolicy, feedback: &SlaFeedback) -> GeneratedPolicy {
        let mut adapted = policy.clone();

        // Latency violation: reduce DRX cycle (more frequent scheduling)
        if feedback.latency_violated() {
            let ratio = feedback.latency_ms / feedback.target_latency_ms;
            let reduction = (ratio - 1.0) * self.aggressiveness;
            let new_drx = (adapted.drx_cycle_ms as f64 * (1.0 - reduction).max(0.1)) as u32;
            adapted.drx_cycle_ms = new_drx.max(5); // minimum 5ms
        }

        // Throughput violation: increase MBR
        if feedback.throughput_violated() {
            let ratio = feedback.target_throughput_mbps / feedback.throughput_mbps.max(0.001);
            let increase = (ratio - 1.0) * self.aggressiveness;
            adapted.mbr_dl_kbps = (adapted.mbr_dl_kbps as f64 * (1.0 + increase)) as u64;
            adapted.mbr_ul_kbps = (adapted.mbr_ul_kbps as f64 * (1.0 + increase)) as u64;
        }

        // Packet loss violation: increase ARP priority (lower number = higher priority)
        if feedback.packet_loss_violated() && adapted.arp_priority > 1 {
            adapted.arp_priority = adapted.arp_priority.saturating_sub(1);
        }

        adapted
    }
}
