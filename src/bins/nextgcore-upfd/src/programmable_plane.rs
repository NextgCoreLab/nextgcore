//! Programmable Data Plane & Energy-Aware Forwarding (Item #193)
//!
//! Provides P4/eBPF-inspired programmable data plane abstractions
//! and AI-driven energy-aware packet forwarding for 6G UPF.


// ============================================================================
// Programmable Data Plane
// ============================================================================

/// Match-action table entry (P4-style).
#[derive(Debug, Clone)]
pub struct MatchActionEntry {
    /// Entry ID.
    pub id: u32,
    /// Match fields.
    pub matches: Vec<MatchField>,
    /// Action to perform.
    pub action: ForwardingAction,
    /// Priority (higher = more specific).
    pub priority: u16,
    /// Hit counter.
    pub hit_count: u64,
}

/// Match field types.
#[derive(Debug, Clone, PartialEq)]
pub enum MatchField {
    /// Match on source IP (exact).
    SrcIpExact([u8; 4]),
    /// Match on destination IP (exact).
    DstIpExact([u8; 4]),
    /// Match on GTP TEID (exact).
    GtpTeid(u32),
    /// Match on QFI (exact).
    Qfi(u8),
    /// Match on DSCP value.
    Dscp(u8),
    /// Match on protocol (TCP=6, UDP=17).
    Protocol(u8),
    /// Match on destination port range.
    DstPortRange(u16, u16),
}

/// Forwarding action.
#[derive(Debug, Clone)]
pub enum ForwardingAction {
    /// Forward to a GTP tunnel.
    GtpEncap { teid: u32, dst_addr: [u8; 4], dst_port: u16 },
    /// Decapsulate GTP and forward.
    GtpDecap,
    /// Forward to local network.
    LocalForward { interface: String },
    /// Drop the packet.
    Drop,
    /// Mirror to sensing pipeline (ISAC).
    MirrorToSensing,
    /// Apply QoS marking.
    QosMarking { dscp: u8, qfi: u8 },
    /// Chain to next table.
    NextTable(u32),
}

/// Programmable pipeline stage.
#[derive(Debug, Clone)]
pub struct PipelineStage {
    /// Stage name.
    pub name: String,
    /// Table ID.
    pub table_id: u32,
    /// Match-action entries.
    pub entries: Vec<MatchActionEntry>,
}

/// Programmable data plane manager.
pub struct ProgrammablePlane {
    /// Pipeline stages.
    stages: Vec<PipelineStage>,
    /// Next entry ID.
    next_entry_id: u32,
    /// Total packet count.
    total_packets: u64,
}

impl Default for ProgrammablePlane {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgrammablePlane {
    /// Creates a new programmable data plane.
    pub fn new() -> Self {
        Self {
            stages: vec![
                PipelineStage { name: "ingress_classifier".into(), table_id: 0, entries: Vec::new() },
                PipelineStage { name: "qos_enforcer".into(), table_id: 1, entries: Vec::new() },
                PipelineStage { name: "forwarding".into(), table_id: 2, entries: Vec::new() },
            ],
            next_entry_id: 1,
            total_packets: 0,
        }
    }

    /// Add a match-action entry to a stage.
    pub fn add_entry(&mut self, table_id: u32, matches: Vec<MatchField>, action: ForwardingAction, priority: u16) -> u32 {
        let id = self.next_entry_id;
        self.next_entry_id += 1;

        let entry = MatchActionEntry {
            id,
            matches,
            action,
            priority,
            hit_count: 0,
        };

        if let Some(stage) = self.stages.iter_mut().find(|s| s.table_id == table_id) {
            stage.entries.push(entry);
            stage.entries.sort_by(|a, b| b.priority.cmp(&a.priority));
        }
        id
    }

    /// Remove an entry.
    pub fn remove_entry(&mut self, table_id: u32, entry_id: u32) -> bool {
        if let Some(stage) = self.stages.iter_mut().find(|s| s.table_id == table_id) {
            let before = stage.entries.len();
            stage.entries.retain(|e| e.id != entry_id);
            return stage.entries.len() < before;
        }
        false
    }

    /// Total entries across all stages.
    pub fn total_entries(&self) -> usize {
        self.stages.iter().map(|s| s.entries.len()).sum()
    }

    /// Number of pipeline stages.
    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }
}

// ============================================================================
// Energy-Aware Forwarding
// ============================================================================

/// Energy state of a forwarding path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnergyState {
    /// Full performance mode.
    FullPower,
    /// Reduced throughput, lower power.
    EcoMode,
    /// Minimal forwarding, deep sleep between packets.
    DeepEco,
    /// Path suspended (traffic rerouted).
    Suspended,
}

/// Energy-aware forwarding profile.
#[derive(Debug, Clone)]
pub struct EnergyForwardingProfile {
    /// Current energy state.
    pub state: EnergyState,
    /// Power consumption (watts).
    pub power_watts: f64,
    /// Bits per joule metric.
    pub bits_per_joule: f64,
    /// Traffic load (0.0-1.0).
    pub load_ratio: f64,
    /// Threshold to enter eco mode.
    pub eco_threshold: f64,
    /// Threshold to enter deep eco mode.
    pub deep_eco_threshold: f64,
    /// Active forwarding paths.
    pub active_paths: u32,
    /// Renewable energy percentage.
    pub renewable_pct: f64,
}

impl Default for EnergyForwardingProfile {
    fn default() -> Self {
        Self::new()
    }
}

impl EnergyForwardingProfile {
    /// Creates a new energy profile.
    pub fn new() -> Self {
        Self {
            state: EnergyState::FullPower,
            power_watts: 100.0,
            bits_per_joule: 0.0,
            load_ratio: 0.0,
            eco_threshold: 0.3,
            deep_eco_threshold: 0.1,
            active_paths: 0,
            renewable_pct: 0.0,
        }
    }

    /// Update energy state based on current load.
    pub fn update_state(&mut self, load_ratio: f64) {
        self.load_ratio = load_ratio;
        self.state = if load_ratio < self.deep_eco_threshold {
            EnergyState::DeepEco
        } else if load_ratio < self.eco_threshold {
            EnergyState::EcoMode
        } else {
            EnergyState::FullPower
        };

        // Approximate power model
        self.power_watts = match self.state {
            EnergyState::FullPower => 100.0 * (0.5 + 0.5 * load_ratio),
            EnergyState::EcoMode => 40.0 * (0.3 + 0.7 * load_ratio),
            EnergyState::DeepEco => 10.0,
            EnergyState::Suspended => 1.0,
        };
    }

    /// Compute energy efficiency.
    pub fn compute_efficiency(&mut self, bits_forwarded: u64, interval_secs: f64) {
        let joules = self.power_watts * interval_secs;
        self.bits_per_joule = if joules > 0.0 { bits_forwarded as f64 / joules } else { 0.0 };
    }

    /// Whether the UPF should shed load to save energy.
    pub fn should_shed_load(&self) -> bool {
        self.state == EnergyState::DeepEco && self.load_ratio < 0.05
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_programmable_plane_add_entry() {
        let mut plane = ProgrammablePlane::new();
        let id = plane.add_entry(
            0,
            vec![MatchField::GtpTeid(0x12345678)],
            ForwardingAction::GtpDecap,
            100,
        );
        assert_eq!(id, 1);
        assert_eq!(plane.total_entries(), 1);
    }

    #[test]
    fn test_programmable_plane_remove_entry() {
        let mut plane = ProgrammablePlane::new();
        let id = plane.add_entry(0, vec![], ForwardingAction::Drop, 10);
        assert!(plane.remove_entry(0, id));
        assert_eq!(plane.total_entries(), 0);
    }

    #[test]
    fn test_energy_state_transitions() {
        let mut profile = EnergyForwardingProfile::new();
        assert_eq!(profile.state, EnergyState::FullPower);

        profile.update_state(0.05);
        assert_eq!(profile.state, EnergyState::DeepEco);

        profile.update_state(0.2);
        assert_eq!(profile.state, EnergyState::EcoMode);

        profile.update_state(0.8);
        assert_eq!(profile.state, EnergyState::FullPower);
    }

    #[test]
    fn test_energy_efficiency() {
        let mut profile = EnergyForwardingProfile::new();
        profile.power_watts = 50.0;
        profile.compute_efficiency(1_000_000_000, 1.0); // 1 Gbps for 1 sec
        assert!(profile.bits_per_joule > 0.0);
    }

    #[test]
    fn test_load_shedding() {
        let mut profile = EnergyForwardingProfile::new();
        profile.update_state(0.01);
        assert!(profile.should_shed_load());

        profile.update_state(0.5);
        assert!(!profile.should_shed_load());
    }
}
