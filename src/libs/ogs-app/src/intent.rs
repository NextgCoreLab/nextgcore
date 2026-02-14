//! Intent-Based Configuration Translation (6G Feature - B3.2)
//!
//! This module provides intent-based configuration that translates high-level
//! user intentions into concrete network function configurations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Intent translation errors
#[derive(Error, Debug)]
pub enum IntentError {
    #[error("Invalid intent specification: {0}")]
    InvalidIntent(String),
    #[error("Conflicting intents: {0}")]
    ConflictingIntents(String),
    #[error("Intent translation failed: {0}")]
    TranslationFailed(String),
    #[error("Unsupported intent type: {0}")]
    UnsupportedIntent(String),
}

/// Result type for intent operations
pub type IntentResult<T> = Result<T, IntentError>;

/// Intent priority level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IntentPriority {
    /// Low priority
    Low = 1,
    /// Medium priority
    Medium = 5,
    /// High priority
    High = 10,
    /// Critical priority
    Critical = 20,
}

/// Network slice intent types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SliceIntent {
    /// Enhanced mobile broadband
    EMbb,
    /// Ultra-reliable low-latency communications
    URLlc,
    /// Massive machine-type communications
    MMtc,
    /// Custom slice with specific parameters
    Custom(String),
}

/// Quality of Service intent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosIntent {
    /// Target latency (milliseconds)
    pub target_latency_ms: Option<u32>,
    /// Target throughput (Mbps)
    pub target_throughput_mbps: Option<u32>,
    /// Target reliability (percentage 0-100)
    pub target_reliability_pct: Option<u8>,
    /// Jitter tolerance (milliseconds)
    pub jitter_tolerance_ms: Option<u32>,
    /// Packet loss tolerance (percentage 0-100)
    pub packet_loss_tolerance_pct: Option<f32>,
}

/// Security intent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIntent {
    /// Require end-to-end encryption
    pub require_e2e_encryption: bool,
    /// Require post-quantum cryptography
    pub require_pqc: bool,
    /// Require zero-trust architecture
    pub require_zero_trust: bool,
    /// Authentication strength (1-5)
    pub auth_strength: u8,
    /// Enable security monitoring
    pub enable_monitoring: bool,
}

/// Energy efficiency intent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnergyIntent {
    /// Target energy efficiency (operations per watt)
    pub target_efficiency: Option<f64>,
    /// Power saving mode enabled
    pub power_saving_enabled: bool,
    /// Green routing preference (0-100)
    pub green_routing_preference: u8,
    /// Allow dynamic scaling
    pub allow_dynamic_scaling: bool,
}

/// AI/ML service intent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiMlIntent {
    /// Enable AI-assisted optimization
    pub enable_ai_optimization: bool,
    /// Enable predictive analytics
    pub enable_predictive_analytics: bool,
    /// ML model deployment preferences
    pub model_deployment: Vec<String>,
    /// Training data locality requirements
    pub data_locality: Option<String>,
}

/// High-level network intent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIntent {
    /// Intent identifier
    pub id: String,
    /// Intent name/description
    pub name: String,
    /// Priority
    pub priority: IntentPriority,
    /// Slice intent
    pub slice: Option<SliceIntent>,
    /// QoS intent
    pub qos: Option<QosIntent>,
    /// Security intent
    pub security: Option<SecurityIntent>,
    /// Energy intent
    pub energy: Option<EnergyIntent>,
    /// AI/ML intent
    pub ai_ml: Option<AiMlIntent>,
    /// Custom parameters
    pub custom_params: HashMap<String, String>,
}

impl NetworkIntent {
    /// Create a new network intent
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        NetworkIntent {
            id: id.into(),
            name: name.into(),
            priority: IntentPriority::Medium,
            slice: None,
            qos: None,
            security: None,
            energy: None,
            ai_ml: None,
            custom_params: HashMap::new(),
        }
    }

    /// Set priority
    pub fn with_priority(mut self, priority: IntentPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Set slice intent
    pub fn with_slice(mut self, slice: SliceIntent) -> Self {
        self.slice = Some(slice);
        self
    }

    /// Set QoS intent
    pub fn with_qos(mut self, qos: QosIntent) -> Self {
        self.qos = Some(qos);
        self
    }

    /// Set security intent
    pub fn with_security(mut self, security: SecurityIntent) -> Self {
        self.security = Some(security);
        self
    }

    /// Set energy intent
    pub fn with_energy(mut self, energy: EnergyIntent) -> Self {
        self.energy = Some(energy);
        self
    }

    /// Set AI/ML intent
    pub fn with_ai_ml(mut self, ai_ml: AiMlIntent) -> Self {
        self.ai_ml = Some(ai_ml);
        self
    }

    /// Add custom parameter
    pub fn with_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom_params.insert(key.into(), value.into());
        self
    }

    /// Validate the intent
    pub fn validate(&self) -> IntentResult<()> {
        // Check for conflicting intents
        if let (Some(energy), Some(qos)) = (&self.energy, &self.qos) {
            if energy.power_saving_enabled && qos.target_latency_ms.is_some_and(|lat| lat < 10) {
                return Err(IntentError::ConflictingIntents(
                    "Power saving conflicts with ultra-low latency requirement".to_string(),
                ));
            }
        }

        // Validate QoS parameters
        if let Some(qos) = &self.qos {
            if let Some(reliability) = qos.target_reliability_pct {
                if reliability > 100 {
                    return Err(IntentError::InvalidIntent(
                        "Reliability percentage must be 0-100".to_string(),
                    ));
                }
            }
            if let Some(loss) = qos.packet_loss_tolerance_pct {
                if !(0.0..=100.0).contains(&loss) {
                    return Err(IntentError::InvalidIntent(
                        "Packet loss tolerance must be 0-100".to_string(),
                    ));
                }
            }
        }

        // Validate security parameters
        if let Some(security) = &self.security {
            if security.auth_strength < 1 || security.auth_strength > 5 {
                return Err(IntentError::InvalidIntent(
                    "Authentication strength must be 1-5".to_string(),
                ));
            }
        }

        // Validate energy parameters
        if let Some(energy) = &self.energy {
            if energy.green_routing_preference > 100 {
                return Err(IntentError::InvalidIntent(
                    "Green routing preference must be 0-100".to_string(),
                ));
            }
        }

        Ok(())
    }
}

/// Concrete configuration derived from intent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivedConfig {
    /// Source intent ID
    pub intent_id: String,
    /// NF-specific configuration parameters
    pub nf_params: HashMap<String, String>,
    /// Slice configuration
    pub slice_config: HashMap<String, String>,
    /// QoS parameters
    pub qos_params: HashMap<String, String>,
    /// Security parameters
    pub security_params: HashMap<String, String>,
    /// Energy parameters
    pub energy_params: HashMap<String, String>,
}

/// Intent translator that converts high-level intents to concrete configs
pub struct IntentTranslator {
    /// Translation rules
    rules: HashMap<String, String>,
}

impl IntentTranslator {
    /// Create a new intent translator
    pub fn new() -> Self {
        IntentTranslator {
            rules: HashMap::new(),
        }
    }

    /// Add translation rule
    pub fn add_rule(&mut self, intent_key: impl Into<String>, config_value: impl Into<String>) {
        self.rules.insert(intent_key.into(), config_value.into());
    }

    /// Translate intent to concrete configuration
    pub fn translate(&self, intent: &NetworkIntent) -> IntentResult<DerivedConfig> {
        // Validate intent first
        intent.validate()?;

        let mut config = DerivedConfig {
            intent_id: intent.id.clone(),
            nf_params: HashMap::new(),
            slice_config: HashMap::new(),
            qos_params: HashMap::new(),
            security_params: HashMap::new(),
            energy_params: HashMap::new(),
        };

        // Translate slice intent
        if let Some(slice) = &intent.slice {
            match slice {
                SliceIntent::EMbb => {
                    config.slice_config.insert("sst".to_string(), "1".to_string());
                    config.qos_params.insert("5qi".to_string(), "9".to_string());
                    config.qos_params.insert("target_throughput".to_string(), "1000".to_string());
                }
                SliceIntent::URLlc => {
                    config.slice_config.insert("sst".to_string(), "2".to_string());
                    config.qos_params.insert("5qi".to_string(), "82".to_string());
                    config.qos_params.insert("target_latency".to_string(), "1".to_string());
                    config.qos_params.insert("reliability".to_string(), "99.999".to_string());
                }
                SliceIntent::MMtc => {
                    config.slice_config.insert("sst".to_string(), "3".to_string());
                    config.qos_params.insert("5qi".to_string(), "70".to_string());
                    config.qos_params.insert("max_devices".to_string(), "1000000".to_string());
                }
                SliceIntent::Custom(name) => {
                    config.slice_config.insert("type".to_string(), name.clone());
                }
            }
        }

        // Translate QoS intent
        if let Some(qos) = &intent.qos {
            if let Some(latency) = qos.target_latency_ms {
                config.qos_params.insert("max_latency_ms".to_string(), latency.to_string());
            }
            if let Some(throughput) = qos.target_throughput_mbps {
                config.qos_params.insert("min_throughput_mbps".to_string(), throughput.to_string());
            }
            if let Some(reliability) = qos.target_reliability_pct {
                config.qos_params.insert("reliability_pct".to_string(), reliability.to_string());
            }
            if let Some(jitter) = qos.jitter_tolerance_ms {
                config.qos_params.insert("max_jitter_ms".to_string(), jitter.to_string());
            }
            if let Some(loss) = qos.packet_loss_tolerance_pct {
                config.qos_params.insert("max_packet_loss_pct".to_string(), loss.to_string());
            }
        }

        // Translate security intent
        if let Some(security) = &intent.security {
            config.security_params.insert("e2e_encryption".to_string(), security.require_e2e_encryption.to_string());
            config.security_params.insert("pqc_enabled".to_string(), security.require_pqc.to_string());
            config.security_params.insert("zero_trust".to_string(), security.require_zero_trust.to_string());
            config.security_params.insert("auth_strength".to_string(), security.auth_strength.to_string());
            config.security_params.insert("monitoring".to_string(), security.enable_monitoring.to_string());
        }

        // Translate energy intent
        if let Some(energy) = &intent.energy {
            if let Some(efficiency) = energy.target_efficiency {
                config.energy_params.insert("target_ops_per_watt".to_string(), efficiency.to_string());
            }
            config.energy_params.insert("power_saving".to_string(), energy.power_saving_enabled.to_string());
            config.energy_params.insert("green_routing_pref".to_string(), energy.green_routing_preference.to_string());
            config.energy_params.insert("dynamic_scaling".to_string(), energy.allow_dynamic_scaling.to_string());
        }

        // Translate AI/ML intent
        if let Some(ai_ml) = &intent.ai_ml {
            config.nf_params.insert("ai_optimization".to_string(), ai_ml.enable_ai_optimization.to_string());
            config.nf_params.insert("predictive_analytics".to_string(), ai_ml.enable_predictive_analytics.to_string());
            if let Some(locality) = &ai_ml.data_locality {
                config.nf_params.insert("data_locality".to_string(), locality.clone());
            }
        }

        // Add custom parameters
        for (key, value) in &intent.custom_params {
            config.nf_params.insert(key.clone(), value.clone());
        }

        Ok(config)
    }

    /// Translate multiple intents and merge configurations
    pub fn translate_multi(&self, intents: &[NetworkIntent]) -> IntentResult<DerivedConfig> {
        if intents.is_empty() {
            return Err(IntentError::InvalidIntent("No intents provided".to_string()));
        }

        // Sort by priority
        let mut sorted_intents = intents.to_vec();
        sorted_intents.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Translate highest priority first
        let mut merged_config = self.translate(&sorted_intents[0])?;

        // Merge lower priority intents (higher priority wins)
        for intent in &sorted_intents[1..] {
            let config = self.translate(intent)?;

            // Merge non-conflicting parameters
            for (key, value) in config.nf_params {
                merged_config.nf_params.entry(key).or_insert(value);
            }
            for (key, value) in config.qos_params {
                merged_config.qos_params.entry(key).or_insert(value);
            }
            for (key, value) in config.security_params {
                merged_config.security_params.entry(key).or_insert(value);
            }
            for (key, value) in config.energy_params {
                merged_config.energy_params.entry(key).or_insert(value);
            }
        }

        Ok(merged_config)
    }
}

impl Default for IntentTranslator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_intent_creation() {
        let intent = NetworkIntent::new("intent-1", "Test Intent");
        assert_eq!(intent.id, "intent-1");
        assert_eq!(intent.name, "Test Intent");
        assert_eq!(intent.priority, IntentPriority::Medium);
    }

    #[test]
    fn test_intent_with_qos() {
        let qos = QosIntent {
            target_latency_ms: Some(10),
            target_throughput_mbps: Some(100),
            target_reliability_pct: Some(99),
            jitter_tolerance_ms: Some(5),
            packet_loss_tolerance_pct: Some(0.1),
        };

        let intent = NetworkIntent::new("intent-1", "QoS Test")
            .with_qos(qos.clone());

        assert!(intent.qos.is_some());
        assert_eq!(intent.qos.unwrap().target_latency_ms, qos.target_latency_ms);
    }

    #[test]
    fn test_intent_validation_success() {
        let intent = NetworkIntent::new("intent-1", "Valid Intent")
            .with_qos(QosIntent {
                target_latency_ms: Some(10),
                target_throughput_mbps: Some(100),
                target_reliability_pct: Some(99),
                jitter_tolerance_ms: None,
                packet_loss_tolerance_pct: Some(1.0),
            });

        assert!(intent.validate().is_ok());
    }

    #[test]
    fn test_intent_validation_invalid_reliability() {
        let intent = NetworkIntent::new("intent-1", "Invalid Intent")
            .with_qos(QosIntent {
                target_latency_ms: None,
                target_throughput_mbps: None,
                target_reliability_pct: Some(150), // Invalid
                jitter_tolerance_ms: None,
                packet_loss_tolerance_pct: None,
            });

        assert!(intent.validate().is_err());
    }

    #[test]
    fn test_intent_validation_conflicting() {
        let intent = NetworkIntent::new("intent-1", "Conflicting Intent")
            .with_qos(QosIntent {
                target_latency_ms: Some(5), // Ultra-low latency
                target_throughput_mbps: None,
                target_reliability_pct: None,
                jitter_tolerance_ms: None,
                packet_loss_tolerance_pct: None,
            })
            .with_energy(EnergyIntent {
                target_efficiency: None,
                power_saving_enabled: true, // Conflicts with low latency
                green_routing_preference: 50,
                allow_dynamic_scaling: true,
            });

        assert!(intent.validate().is_err());
    }

    #[test]
    fn test_intent_translation_embb() {
        let translator = IntentTranslator::new();
        let intent = NetworkIntent::new("intent-1", "eMBB Slice")
            .with_slice(SliceIntent::EMbb);

        let config = translator.translate(&intent).unwrap();
        assert_eq!(config.slice_config.get("sst"), Some(&"1".to_string()));
        assert_eq!(config.qos_params.get("5qi"), Some(&"9".to_string()));
    }

    #[test]
    fn test_intent_translation_urllc() {
        let translator = IntentTranslator::new();
        let intent = NetworkIntent::new("intent-2", "URLLC Slice")
            .with_slice(SliceIntent::URLlc);

        let config = translator.translate(&intent).unwrap();
        assert_eq!(config.slice_config.get("sst"), Some(&"2".to_string()));
        assert_eq!(config.qos_params.get("target_latency"), Some(&"1".to_string()));
        assert_eq!(config.qos_params.get("reliability"), Some(&"99.999".to_string()));
    }

    #[test]
    fn test_intent_translation_with_security() {
        let translator = IntentTranslator::new();
        let intent = NetworkIntent::new("intent-3", "Secure Service")
            .with_security(SecurityIntent {
                require_e2e_encryption: true,
                require_pqc: true,
                require_zero_trust: false,
                auth_strength: 5,
                enable_monitoring: true,
            });

        let config = translator.translate(&intent).unwrap();
        assert_eq!(config.security_params.get("e2e_encryption"), Some(&"true".to_string()));
        assert_eq!(config.security_params.get("pqc_enabled"), Some(&"true".to_string()));
        assert_eq!(config.security_params.get("auth_strength"), Some(&"5".to_string()));
    }

    #[test]
    fn test_multi_intent_translation() {
        let translator = IntentTranslator::new();

        let intent1 = NetworkIntent::new("intent-1", "High Priority")
            .with_priority(IntentPriority::High)
            .with_slice(SliceIntent::EMbb);

        let intent2 = NetworkIntent::new("intent-2", "Medium Priority")
            .with_priority(IntentPriority::Medium)
            .with_slice(SliceIntent::URLlc); // Should be overridden

        let config = translator.translate_multi(&[intent1, intent2]).unwrap();

        // High priority (eMBB) should win
        assert_eq!(config.slice_config.get("sst"), Some(&"1".to_string()));
    }
}

//
// B3.5: Intent Lifecycle Management (6G Feature)
//

/// Intent lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntentState {
    /// Intent submitted, awaiting validation.
    Pending,
    /// Intent validated and translated to config.
    Active,
    /// Intent temporarily suspended.
    Suspended,
    /// Intent fulfilled and completed.
    Fulfilled,
    /// Intent failed or rejected.
    Failed,
    /// Intent expired.
    Expired,
}

/// Tracked intent with lifecycle state and derived configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedIntent {
    /// The original network intent.
    pub intent: NetworkIntent,
    /// Current lifecycle state.
    pub state: IntentState,
    /// Derived configuration (populated when Active).
    pub derived_config: Option<DerivedConfig>,
    /// Creation timestamp (epoch seconds).
    pub created_at: u64,
    /// Last state change timestamp.
    pub updated_at: u64,
    /// Failure reason (if Failed).
    pub failure_reason: Option<String>,
}

/// Intent lifecycle manager - tracks, activates, and expires intents.
pub struct IntentLifecycleManager {
    /// All managed intents by ID.
    intents: HashMap<String, ManagedIntent>,
    /// Intent translator for deriving configs.
    translator: IntentTranslator,
    /// Default TTL for intents (seconds, 0 = no expiry).
    default_ttl_secs: u64,
    /// Total intents ever submitted.
    total_submitted: u64,
    /// Total intents that reached Active state.
    total_activated: u64,
}

impl IntentLifecycleManager {
    /// Create a new lifecycle manager.
    pub fn new(default_ttl_secs: u64) -> Self {
        Self {
            intents: HashMap::new(),
            translator: IntentTranslator::new(),
            default_ttl_secs,
            total_submitted: 0,
            total_activated: 0,
        }
    }

    /// Submit a new intent. Returns the intent ID.
    pub fn submit(&mut self, intent: NetworkIntent) -> IntentResult<String> {
        intent.validate()?;
        self.total_submitted += 1;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let id = intent.id.clone();
        let managed = ManagedIntent {
            intent,
            state: IntentState::Pending,
            derived_config: None,
            created_at: now,
            updated_at: now,
            failure_reason: None,
        };

        self.intents.insert(id.clone(), managed);
        Ok(id)
    }

    /// Activate a pending intent (translate to config).
    pub fn activate(&mut self, id: &str) -> IntentResult<&DerivedConfig> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let managed = self.intents.get_mut(id)
            .ok_or_else(|| IntentError::InvalidIntent(format!("Intent {id} not found")))?;

        if managed.state != IntentState::Pending && managed.state != IntentState::Suspended {
            return Err(IntentError::InvalidIntent(
                format!("Intent {id} is in state {:?}, cannot activate", managed.state),
            ));
        }

        let config = self.translator.translate(&managed.intent)?;
        managed.derived_config = Some(config);
        managed.state = IntentState::Active;
        managed.updated_at = now;
        self.total_activated += 1;

        // Safe: we just set derived_config above
        Ok(self.intents[id].derived_config.as_ref()
            .expect("derived_config was just set"))
    }

    /// Suspend an active intent.
    pub fn suspend(&mut self, id: &str) -> IntentResult<()> {
        let managed = self.intents.get_mut(id)
            .ok_or_else(|| IntentError::InvalidIntent(format!("Intent {id} not found")))?;

        if managed.state != IntentState::Active {
            return Err(IntentError::InvalidIntent(
                format!("Intent {id} is not Active, cannot suspend"),
            ));
        }

        managed.state = IntentState::Suspended;
        managed.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Ok(())
    }

    /// Mark an intent as fulfilled.
    pub fn fulfill(&mut self, id: &str) -> IntentResult<()> {
        let managed = self.intents.get_mut(id)
            .ok_or_else(|| IntentError::InvalidIntent(format!("Intent {id} not found")))?;

        managed.state = IntentState::Fulfilled;
        managed.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Ok(())
    }

    /// Fail an intent with a reason.
    pub fn fail(&mut self, id: &str, reason: impl Into<String>) -> IntentResult<()> {
        let managed = self.intents.get_mut(id)
            .ok_or_else(|| IntentError::InvalidIntent(format!("Intent {id} not found")))?;

        managed.state = IntentState::Failed;
        managed.failure_reason = Some(reason.into());
        managed.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Ok(())
    }

    /// Expire intents that have exceeded their TTL.
    pub fn expire_stale(&mut self) -> usize {
        if self.default_ttl_secs == 0 {
            return 0;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut expired = 0;
        for managed in self.intents.values_mut() {
            if (managed.state == IntentState::Active || managed.state == IntentState::Pending)
                && now - managed.created_at > self.default_ttl_secs {
                managed.state = IntentState::Expired;
                managed.updated_at = now;
                expired += 1;
            }
        }
        expired
    }

    /// Get a managed intent by ID.
    pub fn get(&self, id: &str) -> Option<&ManagedIntent> {
        self.intents.get(id)
    }

    /// List all intents in a given state.
    pub fn list_by_state(&self, state: IntentState) -> Vec<&ManagedIntent> {
        self.intents.values().filter(|m| m.state == state).collect()
    }

    /// Total managed intents.
    pub fn count(&self) -> usize {
        self.intents.len()
    }

    /// Total intents submitted.
    pub fn total_submitted(&self) -> u64 {
        self.total_submitted
    }

    /// Total intents activated.
    pub fn total_activated(&self) -> u64 {
        self.total_activated
    }
}

impl Default for IntentLifecycleManager {
    fn default() -> Self {
        Self::new(3600) // 1 hour default TTL
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    fn make_intent(id: &str) -> NetworkIntent {
        NetworkIntent::new(id, format!("Test intent {id}"))
            .with_slice(SliceIntent::EMbb)
    }

    #[test]
    fn test_submit_and_activate() {
        let mut mgr = IntentLifecycleManager::new(0);
        let id = mgr.submit(make_intent("i1")).unwrap();

        assert_eq!(mgr.get(&id).unwrap().state, IntentState::Pending);

        let config = mgr.activate(&id).unwrap();
        assert_eq!(config.slice_config.get("sst"), Some(&"1".to_string()));
        assert_eq!(mgr.get(&id).unwrap().state, IntentState::Active);
    }

    #[test]
    fn test_suspend_and_reactivate() {
        let mut mgr = IntentLifecycleManager::new(0);
        let id = mgr.submit(make_intent("i2")).unwrap();
        mgr.activate(&id).unwrap();
        mgr.suspend(&id).unwrap();

        assert_eq!(mgr.get(&id).unwrap().state, IntentState::Suspended);

        // Can re-activate from Suspended
        mgr.activate(&id).unwrap();
        assert_eq!(mgr.get(&id).unwrap().state, IntentState::Active);
    }

    #[test]
    fn test_fulfill() {
        let mut mgr = IntentLifecycleManager::new(0);
        let id = mgr.submit(make_intent("i3")).unwrap();
        mgr.activate(&id).unwrap();
        mgr.fulfill(&id).unwrap();

        assert_eq!(mgr.get(&id).unwrap().state, IntentState::Fulfilled);
    }

    #[test]
    fn test_fail_with_reason() {
        let mut mgr = IntentLifecycleManager::new(0);
        let id = mgr.submit(make_intent("i4")).unwrap();
        mgr.fail(&id, "Resource unavailable").unwrap();

        let managed = mgr.get(&id).unwrap();
        assert_eq!(managed.state, IntentState::Failed);
        assert_eq!(managed.failure_reason.as_deref(), Some("Resource unavailable"));
    }

    #[test]
    fn test_list_by_state() {
        let mut mgr = IntentLifecycleManager::new(0);
        mgr.submit(make_intent("a")).unwrap();
        mgr.submit(make_intent("b")).unwrap();
        mgr.submit(make_intent("c")).unwrap();
        mgr.activate("a").unwrap();
        mgr.activate("b").unwrap();

        assert_eq!(mgr.list_by_state(IntentState::Active).len(), 2);
        assert_eq!(mgr.list_by_state(IntentState::Pending).len(), 1);
    }

    #[test]
    fn test_counters() {
        let mut mgr = IntentLifecycleManager::new(0);
        mgr.submit(make_intent("x")).unwrap();
        mgr.submit(make_intent("y")).unwrap();
        mgr.activate("x").unwrap();

        assert_eq!(mgr.total_submitted(), 2);
        assert_eq!(mgr.total_activated(), 1);
        assert_eq!(mgr.count(), 2);
    }

    #[test]
    fn test_invalid_submit() {
        let mut mgr = IntentLifecycleManager::new(0);
        let bad_intent = NetworkIntent::new("bad", "Bad")
            .with_qos(QosIntent {
                target_latency_ms: None,
                target_throughput_mbps: None,
                target_reliability_pct: Some(200), // Invalid
                jitter_tolerance_ms: None,
                packet_loss_tolerance_pct: None,
            });
        assert!(mgr.submit(bad_intent).is_err());
    }
}
