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

impl Default for AiMlHookRegistry {
    fn default() -> Self {
        Self::new()
    }
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

impl Default for CrossNfIntentCoordinator {
    fn default() -> Self {
        Self::new()
    }
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
// Item #214: Digital Twin Full State Synchronization
// ============================================================================

/// Delta between two NF state snapshots for efficient sync.
#[derive(Debug, Clone)]
pub struct NfStateDelta {
    /// NF instance ID.
    pub nf_instance_id: String,
    /// Timestamp (ms since epoch).
    pub timestamp_ms: u64,
    /// Changed KPIs only (key → new value).
    pub changed_kpis: HashMap<String, f64>,
    /// Changed load (if different).
    pub load_delta: Option<f64>,
    /// Changed session count (if different).
    pub session_delta: Option<i64>,
    /// Status change (if different).
    pub status_change: Option<NfStatus>,
}

/// Snapshot history entry with sequence number for ordering.
#[derive(Debug, Clone)]
pub struct SnapshotHistoryEntry {
    /// Monotonic sequence number.
    pub sequence: u64,
    /// The snapshot.
    pub snapshot: NfStateSnapshot,
}

/// Full digital twin state synchronization manager.
/// Extends DigitalTwinExporter with delta sync, history, and cross-NF propagation.
pub struct DigitalTwinSyncManager {
    /// Inner exporter.
    exporter: DigitalTwinExporter,
    /// Snapshot history (ring buffer).
    history: Vec<SnapshotHistoryEntry>,
    /// Max history entries.
    max_history: usize,
    /// Next sequence number.
    next_sequence: u64,
    /// Peer NF snapshots received via cross-NF sync.
    peer_snapshots: HashMap<String, NfStateSnapshot>,
    /// Delta sync count.
    delta_sync_count: u64,
}

impl DigitalTwinSyncManager {
    /// Creates a new sync manager wrapping an exporter.
    pub fn new(nf_instance_id: impl Into<String>, nf_type: impl Into<String>, sync_interval: Duration, max_history: usize) -> Self {
        Self {
            exporter: DigitalTwinExporter::new(nf_instance_id, nf_type, sync_interval),
            history: Vec::with_capacity(max_history),
            max_history,
            next_sequence: 1,
            peer_snapshots: HashMap::new(),
            delta_sync_count: 0,
        }
    }

    /// Captures a snapshot and stores in history.
    pub fn capture_with_history(&mut self, load: f64, active_sessions: u64, cpu: f64, memory: f64, kpis: HashMap<String, f64>) -> &NfStateSnapshot {
        let snap = self.exporter.capture(load, active_sessions, cpu, memory, kpis);
        let entry = SnapshotHistoryEntry {
            sequence: self.next_sequence,
            snapshot: snap.clone(),
        };
        self.next_sequence += 1;
        if self.history.len() >= self.max_history {
            self.history.remove(0);
        }
        self.history.push(entry);
        self.exporter.latest().unwrap()
    }

    /// Computes a delta between the current snapshot and a previous one.
    pub fn compute_delta(&mut self, previous_sequence: u64) -> Option<NfStateDelta> {
        let current = self.exporter.latest()?;
        let previous = self.history.iter().find(|e| e.sequence == previous_sequence)?;
        self.delta_sync_count += 1;

        let mut changed_kpis = HashMap::new();
        for (k, v) in &current.kpis {
            match previous.snapshot.kpis.get(k) {
                Some(prev_v) if (prev_v - v).abs() > f64::EPSILON => {
                    changed_kpis.insert(k.clone(), *v);
                }
                None => {
                    changed_kpis.insert(k.clone(), *v);
                }
                _ => {}
            }
        }

        let load_delta = if (current.load - previous.snapshot.load).abs() > 0.001 {
            Some(current.load)
        } else { None };

        let session_delta = if current.active_sessions != previous.snapshot.active_sessions {
            Some(current.active_sessions as i64 - previous.snapshot.active_sessions as i64)
        } else { None };

        let status_change = if current.status != previous.snapshot.status {
            Some(current.status)
        } else { None };

        Some(NfStateDelta {
            nf_instance_id: current.nf_instance_id.clone(),
            timestamp_ms: current.timestamp_ms,
            changed_kpis,
            load_delta,
            session_delta,
            status_change,
        })
    }

    /// Receives a peer NF snapshot for cross-NF digital twin view.
    pub fn receive_peer_snapshot(&mut self, snapshot: NfStateSnapshot) {
        self.peer_snapshots.insert(snapshot.nf_instance_id.clone(), snapshot);
    }

    /// Gets the full digital twin view (self + all peers).
    pub fn full_twin_view(&self) -> Vec<&NfStateSnapshot> {
        let mut view: Vec<&NfStateSnapshot> = Vec::new();
        if let Some(snap) = self.exporter.latest() {
            view.push(snap);
        }
        for snap in self.peer_snapshots.values() {
            view.push(snap);
        }
        view
    }

    /// Latest snapshot sequence number.
    pub fn latest_sequence(&self) -> u64 { self.next_sequence.saturating_sub(1) }
    /// History length.
    pub fn history_len(&self) -> usize { self.history.len() }
    /// Peer count.
    pub fn peer_count(&self) -> usize { self.peer_snapshots.len() }
    /// Delta sync count.
    pub fn delta_sync_count(&self) -> u64 { self.delta_sync_count }
    /// Access inner exporter.
    pub fn exporter(&self) -> &DigitalTwinExporter { &self.exporter }
}

// ============================================================================
// Item #215: NF Power Profiling & Optimization
// ============================================================================

/// Power component within an NF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PowerComponent {
    /// CPU/processing.
    Cpu,
    /// Memory subsystem.
    Memory,
    /// Network I/O.
    NetworkIo,
    /// Storage I/O.
    StorageIo,
    /// Crypto/security acceleration.
    CryptoAccel,
    /// Base/idle overhead.
    BaseIdle,
}

/// Per-component power measurement.
#[derive(Debug, Clone)]
pub struct ComponentPowerProfile {
    /// Component type.
    pub component: PowerComponent,
    /// Current power draw (watts).
    pub current_watts: f64,
    /// Peak power draw (watts).
    pub peak_watts: f64,
    /// Idle power draw (watts).
    pub idle_watts: f64,
    /// Utilization (0.0-1.0).
    pub utilization: f64,
}

impl ComponentPowerProfile {
    pub fn new(component: PowerComponent, idle_watts: f64, peak_watts: f64) -> Self {
        Self {
            component,
            current_watts: idle_watts,
            peak_watts,
            idle_watts,
            utilization: 0.0,
        }
    }

    /// Updates power based on utilization using linear model.
    pub fn update_utilization(&mut self, utilization: f64) {
        self.utilization = utilization.clamp(0.0, 1.0);
        self.current_watts = self.idle_watts + (self.peak_watts - self.idle_watts) * self.utilization;
    }

    /// Energy efficiency ratio (throughput-equivalent per watt).
    pub fn efficiency(&self) -> f64 {
        if self.current_watts > 0.0 { self.utilization / self.current_watts } else { 0.0 }
    }
}

/// Power optimization recommendation.
#[derive(Debug, Clone)]
pub struct PowerOptimization {
    /// Target component.
    pub component: PowerComponent,
    /// Recommended action.
    pub action: PowerAction,
    /// Estimated saving (watts).
    pub estimated_saving_watts: f64,
    /// Impact on latency (estimated ms increase).
    pub latency_impact_ms: f64,
}

/// Power optimization action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerAction {
    /// Reduce clock frequency.
    ReduceFrequency,
    /// Disable idle cores.
    DisableIdleCores,
    /// Batch I/O operations.
    BatchIo,
    /// Enable hardware offload.
    EnableHwOffload,
    /// Consolidate workloads.
    ConsolidateWorkloads,
    /// No change needed.
    NoChange,
}

/// NF power profiler and optimizer.
pub struct NfPowerProfiler {
    /// NF instance ID.
    nf_instance_id: String,
    /// Per-component profiles.
    components: HashMap<PowerComponent, ComponentPowerProfile>,
    /// Power measurement history (timestamp_ms → total_watts).
    power_history: Vec<(u64, f64)>,
    /// Max history entries.
    max_history: usize,
    /// Optimization recommendations generated.
    optimization_count: u64,
    /// Carbon intensity (gCO2/kWh, for carbon-aware scheduling).
    carbon_intensity: f64,
}

impl NfPowerProfiler {
    /// Creates a new profiler with default component profiles.
    pub fn new(nf_instance_id: impl Into<String>) -> Self {
        let mut components = HashMap::new();
        components.insert(PowerComponent::Cpu, ComponentPowerProfile::new(PowerComponent::Cpu, 5.0, 65.0));
        components.insert(PowerComponent::Memory, ComponentPowerProfile::new(PowerComponent::Memory, 2.0, 10.0));
        components.insert(PowerComponent::NetworkIo, ComponentPowerProfile::new(PowerComponent::NetworkIo, 1.0, 15.0));
        components.insert(PowerComponent::StorageIo, ComponentPowerProfile::new(PowerComponent::StorageIo, 0.5, 5.0));
        components.insert(PowerComponent::CryptoAccel, ComponentPowerProfile::new(PowerComponent::CryptoAccel, 0.0, 20.0));
        components.insert(PowerComponent::BaseIdle, ComponentPowerProfile::new(PowerComponent::BaseIdle, 3.0, 3.0));

        Self {
            nf_instance_id: nf_instance_id.into(),
            components,
            power_history: Vec::new(),
            max_history: 1000,
            optimization_count: 0,
            carbon_intensity: 400.0, // Global average gCO2/kWh
        }
    }

    /// Updates utilization for a component.
    pub fn update_component(&mut self, component: PowerComponent, utilization: f64) {
        if let Some(profile) = self.components.get_mut(&component) {
            profile.update_utilization(utilization);
        }
    }

    /// Records a power measurement.
    pub fn record_measurement(&mut self) {
        let total = self.total_power_watts();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        if self.power_history.len() >= self.max_history {
            self.power_history.remove(0);
        }
        self.power_history.push((now, total));
    }

    /// Total current power draw across all components (watts).
    pub fn total_power_watts(&self) -> f64 {
        self.components.values().map(|c| c.current_watts).sum()
    }

    /// Average power over the history window (watts).
    pub fn average_power_watts(&self) -> f64 {
        if self.power_history.is_empty() { return 0.0; }
        let sum: f64 = self.power_history.iter().map(|(_, w)| w).sum();
        sum / self.power_history.len() as f64
    }

    /// Carbon footprint estimate (gCO2 per hour at current draw).
    pub fn carbon_footprint_g_per_hour(&self) -> f64 {
        self.total_power_watts() / 1000.0 * self.carbon_intensity
    }

    /// Sets carbon intensity for the deployment region.
    pub fn set_carbon_intensity(&mut self, g_co2_per_kwh: f64) {
        self.carbon_intensity = g_co2_per_kwh;
    }

    /// Generates power optimization recommendations.
    pub fn recommend_optimizations(&mut self) -> Vec<PowerOptimization> {
        self.optimization_count += 1;
        let mut recommendations = Vec::new();

        for profile in self.components.values() {
            let opt = match profile.component {
                PowerComponent::Cpu if profile.utilization < 0.2 => {
                    Some(PowerOptimization {
                        component: PowerComponent::Cpu,
                        action: PowerAction::DisableIdleCores,
                        estimated_saving_watts: (profile.current_watts - profile.idle_watts) * 0.5,
                        latency_impact_ms: 0.5,
                    })
                }
                PowerComponent::Cpu if profile.utilization < 0.5 => {
                    Some(PowerOptimization {
                        component: PowerComponent::Cpu,
                        action: PowerAction::ReduceFrequency,
                        estimated_saving_watts: (profile.current_watts - profile.idle_watts) * 0.3,
                        latency_impact_ms: 1.0,
                    })
                }
                PowerComponent::NetworkIo if profile.utilization < 0.3 => {
                    Some(PowerOptimization {
                        component: PowerComponent::NetworkIo,
                        action: PowerAction::BatchIo,
                        estimated_saving_watts: profile.current_watts * 0.2,
                        latency_impact_ms: 2.0,
                    })
                }
                PowerComponent::CryptoAccel if profile.utilization > 0.5 => {
                    Some(PowerOptimization {
                        component: PowerComponent::CryptoAccel,
                        action: PowerAction::EnableHwOffload,
                        estimated_saving_watts: profile.current_watts * 0.4,
                        latency_impact_ms: -0.5, // Actually faster
                    })
                }
                _ => None,
            };
            if let Some(o) = opt {
                recommendations.push(o);
            }
        }

        recommendations
    }

    /// Gets profile for a specific component.
    pub fn get_component(&self, component: PowerComponent) -> Option<&ComponentPowerProfile> {
        self.components.get(&component)
    }

    /// NF instance ID.
    pub fn nf_instance_id(&self) -> &str { &self.nf_instance_id }
    /// Total optimization recommendations generated.
    pub fn optimization_count(&self) -> u64 { self.optimization_count }
    /// Power history length.
    pub fn history_len(&self) -> usize { self.power_history.len() }
}

// ============================================================================
// B6.5: AI/ML Model Version Registry
// ============================================================================

/// Deployment status of an ML model on an NF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelDeploymentStatus {
    /// Model is being downloaded/prepared.
    Staging,
    /// Model is active and serving inference.
    Active,
    /// Model is being rolled back.
    RollingBack,
    /// Model deployment failed.
    Failed,
    /// Model was retired.
    Retired,
}

/// A deployed ML model instance on an NF.
#[derive(Debug, Clone)]
pub struct DeployedModel {
    /// Model identifier (e.g., "anomaly-detector-v3").
    pub model_id: String,
    /// Semantic version (e.g., "3.2.1").
    pub version: String,
    /// NF instance where deployed.
    pub nf_instance_id: String,
    /// Current status.
    pub status: ModelDeploymentStatus,
    /// Accuracy metric (0.0-1.0), updated after validation.
    pub accuracy: f64,
    /// Deployment timestamp (ms since epoch).
    pub deployed_at_ms: u64,
}

/// Cross-NF ML model version registry for coordinated rollout/rollback.
pub struct ModelVersionRegistry {
    /// All deployments: key = (model_id, nf_instance_id).
    deployments: HashMap<(String, String), DeployedModel>,
    /// Rollout count.
    rollout_count: u64,
    /// Rollback count.
    rollback_count: u64,
}

impl Default for ModelVersionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ModelVersionRegistry {
    /// Creates a new model version registry.
    pub fn new() -> Self {
        Self {
            deployments: HashMap::new(),
            rollout_count: 0,
            rollback_count: 0,
        }
    }

    /// Deploy a model version to an NF.
    pub fn deploy(&mut self, model_id: impl Into<String>, version: impl Into<String>, nf_instance_id: impl Into<String>) {
        let model_id = model_id.into();
        let nf_instance_id = nf_instance_id.into();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        self.rollout_count += 1;
        self.deployments.insert(
            (model_id.clone(), nf_instance_id.clone()),
            DeployedModel {
                model_id,
                version: version.into(),
                nf_instance_id,
                status: ModelDeploymentStatus::Staging,
                accuracy: 0.0,
                deployed_at_ms: now,
            },
        );
    }

    /// Activate a staged deployment.
    pub fn activate(&mut self, model_id: &str, nf_instance_id: &str) -> bool {
        if let Some(dep) = self.deployments.get_mut(&(model_id.to_string(), nf_instance_id.to_string())) {
            if dep.status == ModelDeploymentStatus::Staging {
                dep.status = ModelDeploymentStatus::Active;
                return true;
            }
        }
        false
    }

    /// Roll back a deployment (marks as RollingBack, then Retired).
    pub fn rollback(&mut self, model_id: &str, nf_instance_id: &str) -> bool {
        if let Some(dep) = self.deployments.get_mut(&(model_id.to_string(), nf_instance_id.to_string())) {
            if dep.status == ModelDeploymentStatus::Active || dep.status == ModelDeploymentStatus::Staging {
                dep.status = ModelDeploymentStatus::Retired;
                self.rollback_count += 1;
                return true;
            }
        }
        false
    }

    /// Update accuracy metric after validation.
    pub fn update_accuracy(&mut self, model_id: &str, nf_instance_id: &str, accuracy: f64) -> bool {
        if let Some(dep) = self.deployments.get_mut(&(model_id.to_string(), nf_instance_id.to_string())) {
            dep.accuracy = accuracy;
            return true;
        }
        false
    }

    /// Get all NFs running a specific model.
    pub fn nfs_with_model(&self, model_id: &str) -> Vec<&DeployedModel> {
        self.deployments.values()
            .filter(|d| d.model_id == model_id && d.status == ModelDeploymentStatus::Active)
            .collect()
    }

    /// Get all models deployed on a specific NF.
    pub fn models_on_nf(&self, nf_instance_id: &str) -> Vec<&DeployedModel> {
        self.deployments.values()
            .filter(|d| d.nf_instance_id == nf_instance_id)
            .collect()
    }

    /// Total deployments.
    pub fn deployment_count(&self) -> usize { self.deployments.len() }
    /// Active deployments.
    pub fn active_count(&self) -> usize {
        self.deployments.values().filter(|d| d.status == ModelDeploymentStatus::Active).count()
    }
    /// Total rollouts.
    pub fn rollout_count(&self) -> u64 { self.rollout_count }
    /// Total rollbacks.
    pub fn rollback_count(&self) -> u64 { self.rollback_count }
}

// ============================================================================
// B6.6: Digital Twin Scenario Simulator
// ============================================================================

/// A what-if scenario to evaluate against digital twin state.
#[derive(Debug, Clone)]
pub struct WhatIfScenario {
    /// Scenario name.
    pub name: String,
    /// Load multiplier per NF (nf_instance_id → multiplier).
    pub load_multipliers: HashMap<String, f64>,
    /// NF failures to simulate (nf_instance_id set).
    pub simulated_failures: Vec<String>,
    /// Additional sessions to inject per NF.
    pub extra_sessions: HashMap<String, u64>,
}

/// Result of running a what-if scenario.
#[derive(Debug, Clone)]
pub struct ScenarioResult {
    /// Scenario name.
    pub scenario_name: String,
    /// Projected NF statuses after scenario.
    pub projected_statuses: HashMap<String, NfStatus>,
    /// NFs projected to be overloaded.
    pub overloaded_nfs: Vec<String>,
    /// NFs projected as unreachable (failed).
    pub unreachable_nfs: Vec<String>,
    /// Total projected load across all NFs.
    pub total_projected_load: f64,
    /// Whether the scenario causes SLA risk.
    pub sla_risk: bool,
}

/// Runs what-if simulations against the current digital twin state.
pub struct ScenarioSimulator {
    /// Simulation run count.
    simulation_count: u64,
    /// Overload threshold.
    overload_threshold: f64,
}

impl Default for ScenarioSimulator {
    fn default() -> Self {
        Self::new(0.9)
    }
}

impl ScenarioSimulator {
    /// Creates a new scenario simulator.
    pub fn new(overload_threshold: f64) -> Self {
        Self {
            simulation_count: 0,
            overload_threshold,
        }
    }

    /// Simulate a what-if scenario against current twin state.
    pub fn simulate(&mut self, snapshots: &[&NfStateSnapshot], scenario: &WhatIfScenario) -> ScenarioResult {
        self.simulation_count += 1;
        let mut projected_statuses = HashMap::new();
        let mut overloaded_nfs = Vec::new();
        let mut unreachable_nfs = Vec::new();
        let mut total_load = 0.0;

        for snap in snapshots {
            let nf_id = &snap.nf_instance_id;

            // Check if this NF is simulated as failed
            if scenario.simulated_failures.contains(nf_id) {
                projected_statuses.insert(nf_id.clone(), NfStatus::Unreachable);
                unreachable_nfs.push(nf_id.clone());
                continue;
            }

            // Apply load multiplier
            let multiplier = scenario.load_multipliers.get(nf_id).copied().unwrap_or(1.0);
            let projected_load = (snap.load * multiplier).min(1.0);
            total_load += projected_load;

            let status = if projected_load > self.overload_threshold {
                overloaded_nfs.push(nf_id.clone());
                NfStatus::Overloaded
            } else {
                NfStatus::Registered
            };
            projected_statuses.insert(nf_id.clone(), status);
        }

        let sla_risk = !overloaded_nfs.is_empty() || !unreachable_nfs.is_empty();

        ScenarioResult {
            scenario_name: scenario.name.clone(),
            projected_statuses,
            overloaded_nfs,
            unreachable_nfs,
            total_projected_load: total_load,
            sla_risk,
        }
    }

    /// Total simulations run.
    pub fn simulation_count(&self) -> u64 { self.simulation_count }
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

    // ---- Item #214: Digital Twin State Sync tests ----

    #[test]
    fn test_digital_twin_sync_capture_history() {
        let mut mgr = DigitalTwinSyncManager::new("amf-1", "AMF", Duration::from_secs(5), 100);
        let kpis = HashMap::from([("ue_count".into(), 10.0)]);
        mgr.capture_with_history(0.3, 50, 0.2, 0.3, kpis);
        assert_eq!(mgr.history_len(), 1);
        assert_eq!(mgr.latest_sequence(), 1);

        let kpis2 = HashMap::from([("ue_count".into(), 20.0)]);
        mgr.capture_with_history(0.6, 100, 0.5, 0.4, kpis2);
        assert_eq!(mgr.history_len(), 2);
        assert_eq!(mgr.latest_sequence(), 2);
    }

    #[test]
    fn test_digital_twin_sync_delta() {
        let mut mgr = DigitalTwinSyncManager::new("smf-1", "SMF", Duration::from_secs(5), 100);
        let kpis1 = HashMap::from([("sessions".into(), 100.0)]);
        mgr.capture_with_history(0.3, 50, 0.2, 0.3, kpis1);
        let seq1 = mgr.latest_sequence();

        let kpis2 = HashMap::from([("sessions".into(), 150.0), ("throughput".into(), 500.0)]);
        mgr.capture_with_history(0.6, 80, 0.5, 0.4, kpis2);

        let delta = mgr.compute_delta(seq1).unwrap();
        assert_eq!(delta.nf_instance_id, "smf-1");
        assert!(delta.load_delta.is_some());
        assert!(delta.session_delta.is_some());
        assert_eq!(delta.session_delta.unwrap(), 30); // 80 - 50
        assert!(delta.changed_kpis.contains_key("sessions"));
        assert!(delta.changed_kpis.contains_key("throughput"));
        assert_eq!(mgr.delta_sync_count(), 1);
    }

    #[test]
    fn test_digital_twin_sync_peer_view() {
        let mut mgr = DigitalTwinSyncManager::new("amf-1", "AMF", Duration::from_secs(5), 100);
        mgr.capture_with_history(0.5, 100, 0.3, 0.4, HashMap::new());

        let peer_snap = NfStateSnapshot {
            nf_instance_id: "smf-1".into(),
            nf_type: "SMF".into(),
            timestamp_ms: 1000,
            status: NfStatus::Registered,
            load: 0.4,
            active_sessions: 200,
            cpu_utilization: 0.3,
            memory_utilization: 0.5,
            kpis: HashMap::new(),
        };
        mgr.receive_peer_snapshot(peer_snap);
        assert_eq!(mgr.peer_count(), 1);

        let view = mgr.full_twin_view();
        assert_eq!(view.len(), 2); // self + 1 peer
    }

    #[test]
    fn test_digital_twin_sync_history_ring_buffer() {
        let mut mgr = DigitalTwinSyncManager::new("upf-1", "UPF", Duration::from_secs(1), 3);
        for i in 0..5 {
            mgr.capture_with_history(0.1 * i as f64, i as u64, 0.0, 0.0, HashMap::new());
        }
        assert_eq!(mgr.history_len(), 3); // Capped at max
        assert_eq!(mgr.latest_sequence(), 5);
    }

    // ---- Item #215: NF Power Profiling tests ----

    #[test]
    fn test_power_profiler_defaults() {
        let profiler = NfPowerProfiler::new("amf-1");
        // At idle: CPU(5) + Mem(2) + Net(1) + Storage(0.5) + Crypto(0) + Base(3) = 11.5W
        let total = profiler.total_power_watts();
        assert!((total - 11.5).abs() < 0.01);
    }

    #[test]
    fn test_power_profiler_utilization() {
        let mut profiler = NfPowerProfiler::new("amf-1");
        profiler.update_component(PowerComponent::Cpu, 1.0); // Full load
        let cpu = profiler.get_component(PowerComponent::Cpu).unwrap();
        assert!((cpu.current_watts - 65.0).abs() < 0.01); // Peak
        assert!((cpu.utilization - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_power_profiler_efficiency() {
        let mut profile = ComponentPowerProfile::new(PowerComponent::Cpu, 5.0, 65.0);
        profile.update_utilization(0.5);
        let eff = profile.efficiency();
        assert!(eff > 0.0);
        // At 50% util: power = 5 + 60*0.5 = 35W, efficiency = 0.5/35 ≈ 0.0143
        assert!((eff - 0.5 / 35.0).abs() < 0.001);
    }

    #[test]
    fn test_power_profiler_recommendations() {
        let mut profiler = NfPowerProfiler::new("smf-1");
        profiler.update_component(PowerComponent::Cpu, 0.1); // Low CPU
        profiler.update_component(PowerComponent::NetworkIo, 0.1); // Low network

        let recs = profiler.recommend_optimizations();
        assert!(!recs.is_empty());
        // Should recommend DisableIdleCores for CPU
        assert!(recs.iter().any(|r| r.component == PowerComponent::Cpu && r.action == PowerAction::DisableIdleCores));
        // Should recommend BatchIo for NetworkIo
        assert!(recs.iter().any(|r| r.component == PowerComponent::NetworkIo && r.action == PowerAction::BatchIo));
        assert_eq!(profiler.optimization_count(), 1);
    }

    #[test]
    fn test_power_profiler_carbon_footprint() {
        let profiler = NfPowerProfiler::new("upf-1");
        let carbon = profiler.carbon_footprint_g_per_hour();
        // 11.5W / 1000 * 400 gCO2/kWh = 4.6 gCO2/h
        assert!((carbon - 4.6).abs() < 0.01);
    }

    #[test]
    fn test_power_profiler_measurement_history() {
        let mut profiler = NfPowerProfiler::new("amf-1");
        profiler.record_measurement();
        profiler.record_measurement();
        assert_eq!(profiler.history_len(), 2);
        assert!(profiler.average_power_watts() > 0.0);
    }

    #[test]
    fn test_power_profiler_crypto_offload() {
        let mut profiler = NfPowerProfiler::new("ausf-1");
        profiler.update_component(PowerComponent::CryptoAccel, 0.8); // High crypto
        profiler.update_component(PowerComponent::Cpu, 0.7); // High CPU (no recommendation)

        let recs = profiler.recommend_optimizations();
        assert!(recs.iter().any(|r| r.component == PowerComponent::CryptoAccel && r.action == PowerAction::EnableHwOffload));
    }

    // ---- B6.5: Model Version Registry tests ----

    #[test]
    fn test_model_registry_deploy_activate() {
        let mut registry = ModelVersionRegistry::new();
        registry.deploy("anomaly-det", "1.0.0", "amf-1");
        assert_eq!(registry.deployment_count(), 1);
        assert_eq!(registry.active_count(), 0);

        assert!(registry.activate("anomaly-det", "amf-1"));
        assert_eq!(registry.active_count(), 1);
        assert_eq!(registry.rollout_count(), 1);
    }

    #[test]
    fn test_model_registry_rollback() {
        let mut registry = ModelVersionRegistry::new();
        registry.deploy("anomaly-det", "1.0.0", "amf-1");
        registry.activate("anomaly-det", "amf-1");

        assert!(registry.rollback("anomaly-det", "amf-1"));
        assert_eq!(registry.active_count(), 0);
        assert_eq!(registry.rollback_count(), 1);
    }

    #[test]
    fn test_model_registry_cross_nf_query() {
        let mut registry = ModelVersionRegistry::new();
        registry.deploy("anomaly-det", "2.0.0", "amf-1");
        registry.deploy("anomaly-det", "2.0.0", "smf-1");
        registry.deploy("qos-predict", "1.0.0", "pcf-1");
        registry.activate("anomaly-det", "amf-1");
        registry.activate("anomaly-det", "smf-1");
        registry.activate("qos-predict", "pcf-1");

        let nfs = registry.nfs_with_model("anomaly-det");
        assert_eq!(nfs.len(), 2);

        let models = registry.models_on_nf("amf-1");
        assert_eq!(models.len(), 1);
    }

    #[test]
    fn test_model_registry_accuracy_update() {
        let mut registry = ModelVersionRegistry::new();
        registry.deploy("anomaly-det", "1.0.0", "amf-1");
        assert!(registry.update_accuracy("anomaly-det", "amf-1", 0.95));

        let models = registry.models_on_nf("amf-1");
        assert!((models[0].accuracy - 0.95).abs() < f64::EPSILON);
    }

    // ---- B6.6: Scenario Simulator tests ----

    #[test]
    fn test_scenario_simulator_no_overload() {
        let mut sim = ScenarioSimulator::new(0.9);
        let snap1 = NfStateSnapshot {
            nf_instance_id: "amf-1".into(),
            nf_type: "AMF".into(),
            timestamp_ms: 1000,
            status: NfStatus::Registered,
            load: 0.4,
            active_sessions: 100,
            cpu_utilization: 0.3,
            memory_utilization: 0.4,
            kpis: HashMap::new(),
        };

        let scenario = WhatIfScenario {
            name: "normal".into(),
            load_multipliers: HashMap::new(),
            simulated_failures: vec![],
            extra_sessions: HashMap::new(),
        };

        let result = sim.simulate(&[&snap1], &scenario);
        assert!(!result.sla_risk);
        assert!(result.overloaded_nfs.is_empty());
    }

    #[test]
    fn test_scenario_simulator_load_spike() {
        let mut sim = ScenarioSimulator::new(0.9);
        let snap1 = NfStateSnapshot {
            nf_instance_id: "amf-1".into(),
            nf_type: "AMF".into(),
            timestamp_ms: 1000,
            status: NfStatus::Registered,
            load: 0.5,
            active_sessions: 100,
            cpu_utilization: 0.4,
            memory_utilization: 0.4,
            kpis: HashMap::new(),
        };

        let scenario = WhatIfScenario {
            name: "load_spike".into(),
            load_multipliers: HashMap::from([("amf-1".into(), 2.0)]),
            simulated_failures: vec![],
            extra_sessions: HashMap::new(),
        };

        let result = sim.simulate(&[&snap1], &scenario);
        assert!(result.sla_risk);
        assert_eq!(result.overloaded_nfs.len(), 1);
        assert_eq!(result.overloaded_nfs[0], "amf-1");
    }

    #[test]
    fn test_scenario_simulator_nf_failure() {
        let mut sim = ScenarioSimulator::new(0.9);
        let snap1 = NfStateSnapshot {
            nf_instance_id: "smf-1".into(),
            nf_type: "SMF".into(),
            timestamp_ms: 1000,
            status: NfStatus::Registered,
            load: 0.3,
            active_sessions: 50,
            cpu_utilization: 0.2,
            memory_utilization: 0.3,
            kpis: HashMap::new(),
        };

        let scenario = WhatIfScenario {
            name: "smf_failure".into(),
            load_multipliers: HashMap::new(),
            simulated_failures: vec!["smf-1".into()],
            extra_sessions: HashMap::new(),
        };

        let result = sim.simulate(&[&snap1], &scenario);
        assert!(result.sla_risk);
        assert_eq!(result.unreachable_nfs.len(), 1);
        assert_eq!(sim.simulation_count(), 1);
    }
}
