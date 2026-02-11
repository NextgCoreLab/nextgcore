//! Cross-NF 6G Hooks (Item #197)
//!
//! Provides AI/ML lifecycle hooks, digital twin export, energy management,
//! and intent-based operation API shared across all NFs.
//!
//! Reference: 3GPP TS 23.288 (NWDAF), TS 28.104 (Energy Efficiency)

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ============================================================================
// AI/ML Lifecycle Hooks
// ============================================================================

/// AI/ML hook point in NF processing pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AiMlHookPoint {
    /// Before NF processes an incoming request.
    PreRequest,
    /// After NF processes a request (before response).
    PostRequest,
    /// On NF registration/deregistration.
    NfLifecycle,
    /// On session establishment/release.
    SessionEvent,
    /// On policy decision.
    PolicyDecision,
    /// On handover event.
    MobilityEvent,
    /// On slice admission event.
    SliceEvent,
    /// Periodic analytics collection.
    PeriodicAnalytics,
}

/// AI/ML hook action.
#[derive(Debug, Clone)]
pub enum AiMlHookAction {
    /// Emit analytics event to NWDAF.
    EmitAnalytics { event_type: String, payload: Vec<u8> },
    /// Request ML inference.
    RequestInference { model_id: String, input: Vec<f64> },
    /// Override NF decision with ML result.
    OverrideDecision { confidence: f64, decision: Vec<u8> },
    /// No action.
    Passthrough,
}

/// Registered AI/ML hook.
#[derive(Debug, Clone)]
pub struct AiMlHook {
    /// Hook identifier.
    pub id: u32,
    /// Hook point.
    pub hook_point: AiMlHookPoint,
    /// NF type this hook applies to.
    pub nf_type: String,
    /// Priority (lower = earlier execution).
    pub priority: u8,
    /// Whether this hook is enabled.
    pub enabled: bool,
}

/// AI/ML hook registry for an NF.
pub struct AiMlHookRegistry {
    /// Registered hooks.
    hooks: Vec<AiMlHook>,
    /// Next hook ID.
    next_id: u32,
    /// Execution count.
    execution_count: u64,
}

impl AiMlHookRegistry {
    /// Creates a new hook registry.
    pub fn new() -> Self {
        Self {
            hooks: Vec::new(),
            next_id: 1,
            execution_count: 0,
        }
    }

    /// Register a hook.
    pub fn register(&mut self, hook_point: AiMlHookPoint, nf_type: impl Into<String>, priority: u8) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        self.hooks.push(AiMlHook {
            id,
            hook_point,
            nf_type: nf_type.into(),
            priority,
            enabled: true,
        });
        self.hooks.sort_by_key(|h| h.priority);
        id
    }

    /// Unregister a hook.
    pub fn unregister(&mut self, hook_id: u32) -> bool {
        let before = self.hooks.len();
        self.hooks.retain(|h| h.id != hook_id);
        self.hooks.len() < before
    }

    /// Get hooks for a given point.
    pub fn get_hooks(&mut self, point: AiMlHookPoint) -> Vec<&AiMlHook> {
        self.execution_count += 1;
        self.hooks.iter().filter(|h| h.hook_point == point && h.enabled).collect()
    }

    /// Total registered hooks.
    pub fn hook_count(&self) -> usize { self.hooks.len() }
    /// Total executions.
    pub fn execution_count(&self) -> u64 { self.execution_count }
}

// ============================================================================
// Digital Twin Export
// ============================================================================

/// NF state snapshot for digital twin synchronization.
#[derive(Debug, Clone)]
pub struct NfStateSnapshot {
    /// NF instance ID.
    pub nf_instance_id: String,
    /// NF type (AMF, SMF, UPF, etc.).
    pub nf_type: String,
    /// Timestamp (ms since epoch).
    pub timestamp_ms: u64,
    /// NF status.
    pub status: NfStatus,
    /// Load metric (0.0-1.0).
    pub load: f64,
    /// Active connections/sessions.
    pub active_sessions: u64,
    /// Resource utilization.
    pub cpu_utilization: f64,
    /// Memory utilization.
    pub memory_utilization: f64,
    /// Custom KPIs.
    pub kpis: HashMap<String, f64>,
}

/// NF operational status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfStatus {
    /// NF is registered and operational.
    Registered,
    /// NF is in standby/suspended.
    Suspended,
    /// NF is overloaded.
    Overloaded,
    /// NF is shutting down.
    Draining,
    /// NF is unreachable.
    Unreachable,
}

/// Digital twin export manager.
pub struct DigitalTwinExporter {
    /// NF instance info.
    nf_instance_id: String,
    nf_type: String,
    /// Latest snapshot.
    latest_snapshot: Option<NfStateSnapshot>,
    /// Export count.
    export_count: u64,
    /// Sync interval.
    sync_interval: Duration,
}

impl DigitalTwinExporter {
    /// Creates a new digital twin exporter.
    pub fn new(nf_instance_id: impl Into<String>, nf_type: impl Into<String>, sync_interval: Duration) -> Self {
        Self {
            nf_instance_id: nf_instance_id.into(),
            nf_type: nf_type.into(),
            latest_snapshot: None,
            export_count: 0,
            sync_interval,
        }
    }

    /// Capture current NF state as a snapshot.
    pub fn capture(&mut self, load: f64, active_sessions: u64, cpu: f64, memory: f64, kpis: HashMap<String, f64>) -> &NfStateSnapshot {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        let snapshot = NfStateSnapshot {
            nf_instance_id: self.nf_instance_id.clone(),
            nf_type: self.nf_type.clone(),
            timestamp_ms: now,
            status: if load > 0.9 { NfStatus::Overloaded } else { NfStatus::Registered },
            load,
            active_sessions,
            cpu_utilization: cpu,
            memory_utilization: memory,
            kpis,
        };
        self.latest_snapshot = Some(snapshot);
        self.export_count += 1;
        self.latest_snapshot.as_ref().unwrap()
    }

    /// Get latest snapshot.
    pub fn latest(&self) -> Option<&NfStateSnapshot> { self.latest_snapshot.as_ref() }
    /// Export count.
    pub fn export_count(&self) -> u64 { self.export_count }
    /// Sync interval.
    pub fn sync_interval(&self) -> Duration { self.sync_interval }
}

// ============================================================================
// Cross-NF Energy Management
// ============================================================================

/// Energy saving state for an NF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfEnergyState {
    /// Normal operation.
    Normal,
    /// Energy saving level 1 (reduced measurement, extended timers).
    EnergySaving1,
    /// Energy saving level 2 (suspend non-critical functions).
    EnergySaving2,
    /// Deep sleep (minimal operation, redirect traffic).
    DeepSleep,
}

/// Energy management recommendation.
#[derive(Debug, Clone)]
pub struct EnergyRecommendation {
    /// Target NF instance.
    pub nf_instance_id: String,
    /// Recommended state.
    pub recommended_state: NfEnergyState,
    /// Estimated power saving (watts).
    pub estimated_saving_watts: f64,
    /// Confidence (0.0-1.0).
    pub confidence: f64,
    /// Reason.
    pub reason: String,
}

/// Cross-NF energy coordinator.
pub struct EnergyCoordinator {
    /// Current NF energy states.
    nf_states: HashMap<String, NfEnergyState>,
    /// Total energy budget (watts).
    energy_budget_watts: f64,
    /// Current total consumption (watts).
    current_consumption_watts: f64,
    /// Renewable energy percentage.
    renewable_pct: f64,
    /// Recommendations generated.
    recommendation_count: u64,
}

impl EnergyCoordinator {
    /// Creates a new energy coordinator.
    pub fn new(energy_budget_watts: f64) -> Self {
        Self {
            nf_states: HashMap::new(),
            energy_budget_watts,
            current_consumption_watts: 0.0,
            renewable_pct: 0.0,
            recommendation_count: 0,
        }
    }

    /// Register an NF with its initial energy state.
    pub fn register_nf(&mut self, nf_id: impl Into<String>, state: NfEnergyState) {
        self.nf_states.insert(nf_id.into(), state);
    }

    /// Update energy consumption reading.
    pub fn update_consumption(&mut self, total_watts: f64, renewable_pct: f64) {
        self.current_consumption_watts = total_watts;
        self.renewable_pct = renewable_pct;
    }

    /// Generate energy recommendation for an NF based on budget.
    pub fn recommend(&mut self, nf_id: &str, nf_load: f64) -> EnergyRecommendation {
        self.recommendation_count += 1;
        let over_budget = self.current_consumption_watts > self.energy_budget_watts;
        let low_load = nf_load < 0.2;

        let (state, saving, reason) = if over_budget && low_load {
            (NfEnergyState::DeepSleep, 50.0, "Over budget, low load → deep sleep".into())
        } else if over_budget {
            (NfEnergyState::EnergySaving2, 25.0, "Over budget → ES level 2".into())
        } else if low_load && self.renewable_pct < 0.3 {
            (NfEnergyState::EnergySaving1, 15.0, "Low load, low renewable → ES level 1".into())
        } else {
            (NfEnergyState::Normal, 0.0, "Normal operation".into())
        };

        EnergyRecommendation {
            nf_instance_id: nf_id.to_string(),
            recommended_state: state,
            estimated_saving_watts: saving,
            confidence: if over_budget { 0.9 } else { 0.7 },
            reason,
        }
    }

    /// Apply a recommendation (update NF state).
    pub fn apply(&mut self, nf_id: &str, state: NfEnergyState) {
        self.nf_states.insert(nf_id.to_string(), state);
    }

    /// NFs in energy saving states.
    pub fn saving_count(&self) -> usize {
        self.nf_states.values().filter(|s| **s != NfEnergyState::Normal).count()
    }

    /// Total registered NFs.
    pub fn nf_count(&self) -> usize { self.nf_states.len() }
    /// Recommendation count.
    pub fn recommendation_count(&self) -> u64 { self.recommendation_count }
}

// ============================================================================
// Cross-NF Intent API
// ============================================================================

/// Cross-NF intent for coordinated operations.
#[derive(Debug, Clone)]
pub struct CrossNfIntent {
    /// Intent identifier.
    pub id: u64,
    /// Intent category.
    pub category: CrossNfIntentCategory,
    /// Target NF types.
    pub target_nf_types: Vec<String>,
    /// Parameters.
    pub params: HashMap<String, String>,
    /// Priority.
    pub priority: u8,
    /// Status.
    pub status: IntentStatus,
}

/// Cross-NF intent categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossNfIntentCategory {
    /// Scale a slice across NFs.
    SliceScaling,
    /// Coordinate handover across AMF/SMF/UPF.
    MobilityCoordination,
    /// Apply energy policy across NFs.
    EnergyOptimization,
    /// Coordinate security posture.
    SecurityPosture,
    /// Deploy ML model across NFs.
    AiMlDeployment,
    /// Traffic engineering across the core.
    TrafficEngineering,
}

/// Intent execution status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentStatus {
    /// Intent submitted.
    Pending,
    /// Being translated to NF-specific actions.
    Translating,
    /// Actions dispatched to NFs.
    Executing,
    /// All NFs confirmed.
    Completed,
    /// Intent failed.
    Failed,
}

/// Cross-NF intent coordinator.
pub struct CrossNfIntentCoordinator {
    /// Active intents.
    intents: HashMap<u64, CrossNfIntent>,
    /// Next intent ID.
    next_id: u64,
    /// Completed intents count.
    completed_count: u64,
}

impl CrossNfIntentCoordinator {
    /// Creates a new intent coordinator.
    pub fn new() -> Self {
        Self {
            intents: HashMap::new(),
            next_id: 1,
            completed_count: 0,
        }
    }

    /// Submit a new cross-NF intent.
    pub fn submit(&mut self, category: CrossNfIntentCategory, target_nf_types: Vec<String>, params: HashMap<String, String>, priority: u8) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.intents.insert(id, CrossNfIntent {
            id,
            category,
            target_nf_types,
            params,
            priority,
            status: IntentStatus::Pending,
        });
        id
    }

    /// Update intent status.
    pub fn update_status(&mut self, intent_id: u64, status: IntentStatus) -> bool {
        if let Some(intent) = self.intents.get_mut(&intent_id) {
            if status == IntentStatus::Completed {
                self.completed_count += 1;
            }
            intent.status = status;
            true
        } else {
            false
        }
    }

    /// Get intent by ID.
    pub fn get_intent(&self, intent_id: u64) -> Option<&CrossNfIntent> {
        self.intents.get(&intent_id)
    }

    /// Active (non-completed) intents.
    pub fn active_count(&self) -> usize {
        self.intents.values().filter(|i| i.status != IntentStatus::Completed && i.status != IntentStatus::Failed).count()
    }

    /// Total intents.
    pub fn total_count(&self) -> usize { self.intents.len() }
    /// Completed intents.
    pub fn completed_count(&self) -> u64 { self.completed_count }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aiml_hook_registry() {
        let mut registry = AiMlHookRegistry::new();
        let id1 = registry.register(AiMlHookPoint::PreRequest, "AMF", 1);
        let id2 = registry.register(AiMlHookPoint::PreRequest, "SMF", 2);
        assert_eq!(registry.hook_count(), 2);

        let hooks = registry.get_hooks(AiMlHookPoint::PreRequest);
        assert_eq!(hooks.len(), 2);
        assert_eq!(hooks[0].priority, 1);

        assert!(registry.unregister(id1));
        assert_eq!(registry.hook_count(), 1);
    }

    #[test]
    fn test_digital_twin_capture() {
        let mut exporter = DigitalTwinExporter::new("amf-1", "AMF", Duration::from_secs(5));
        assert!(exporter.latest().is_none());

        let kpis = HashMap::from([("ue_count".into(), 42.0)]);
        let snap = exporter.capture(0.6, 100, 0.4, 0.5, kpis);
        assert_eq!(snap.nf_type, "AMF");
        assert_eq!(snap.status, NfStatus::Registered);
        assert_eq!(snap.active_sessions, 100);

        let kpis2 = HashMap::new();
        let snap2 = exporter.capture(0.95, 500, 0.9, 0.8, kpis2);
        assert_eq!(snap2.status, NfStatus::Overloaded);
        assert_eq!(exporter.export_count(), 2);
    }

    #[test]
    fn test_energy_coordinator() {
        let mut coord = EnergyCoordinator::new(500.0);
        coord.register_nf("amf-1", NfEnergyState::Normal);
        coord.register_nf("smf-1", NfEnergyState::Normal);
        assert_eq!(coord.nf_count(), 2);

        // Under budget
        coord.update_consumption(400.0, 0.5);
        let rec = coord.recommend("amf-1", 0.7);
        assert_eq!(rec.recommended_state, NfEnergyState::Normal);

        // Over budget, low load
        coord.update_consumption(600.0, 0.1);
        let rec = coord.recommend("smf-1", 0.1);
        assert_eq!(rec.recommended_state, NfEnergyState::DeepSleep);

        coord.apply("smf-1", NfEnergyState::DeepSleep);
        assert_eq!(coord.saving_count(), 1);
    }

    #[test]
    fn test_cross_nf_intent() {
        let mut coord = CrossNfIntentCoordinator::new();
        let id = coord.submit(
            CrossNfIntentCategory::SliceScaling,
            vec!["AMF".into(), "SMF".into(), "UPF".into()],
            HashMap::from([("target_ues".into(), "1000".into())]),
            1,
        );
        assert_eq!(coord.active_count(), 1);

        coord.update_status(id, IntentStatus::Executing);
        assert_eq!(coord.get_intent(id).unwrap().status, IntentStatus::Executing);

        coord.update_status(id, IntentStatus::Completed);
        assert_eq!(coord.completed_count(), 1);
        assert_eq!(coord.active_count(), 0);
    }

    #[test]
    fn test_energy_low_load_low_renewable() {
        let mut coord = EnergyCoordinator::new(500.0);
        coord.register_nf("upf-1", NfEnergyState::Normal);
        coord.update_consumption(300.0, 0.1); // Under budget, low renewable
        let rec = coord.recommend("upf-1", 0.1);
        assert_eq!(rec.recommended_state, NfEnergyState::EnergySaving1);
    }
}
