//! NWDAF ML Model Provisioning Service (TS 23.288 §6.12, Rel-17)
//!
//! Implements Nnwdaf_MLModelProvision service:
//! - ML model registry (registration, discovery, deployment)
//! - Model lifecycle: Training → Validation → Deployed → Deprecated
//! - Model performance tracking

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::context::AnalyticsId;

/// ML model lifecycle state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelStatus {
    /// Model is being trained
    Training,
    /// Model is under validation
    Validation,
    /// Model is deployed and serving inference requests
    Deployed,
    /// Model is deprecated (newer version available)
    Deprecated,
    /// Model training or validation failed
    Failed,
}

impl std::fmt::Display for ModelStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Training => write!(f, "TRAINING"),
            Self::Validation => write!(f, "VALIDATION"),
            Self::Deployed => write!(f, "DEPLOYED"),
            Self::Deprecated => write!(f, "DEPRECATED"),
            Self::Failed => write!(f, "FAILED"),
        }
    }
}

/// ML model descriptor
#[derive(Debug, Clone)]
pub struct MlModel {
    /// Unique model ID
    pub model_id: String,
    /// Model version (semantic versioning)
    pub version: String,
    /// Analytics type this model serves
    pub analytics_id: AnalyticsId,
    /// Model status
    pub status: ModelStatus,
    /// Validation accuracy (0.0–1.0)
    pub accuracy: f64,
    /// Inference latency in milliseconds (p99)
    pub inference_latency_p99_ms: f64,
    /// Model size in bytes
    pub model_size_bytes: u64,
    /// URI for model download (if distributable)
    pub model_uri: Option<String>,
    /// Registration timestamp (UNIX seconds)
    pub registered_at: u64,
    /// Deployment timestamp
    pub deployed_at: Option<u64>,
    /// Number of inference requests served
    pub inference_count: u64,
    /// Inference errors
    pub inference_errors: u64,
}

impl MlModel {
    pub fn new(model_id: String, version: String, analytics_id: AnalyticsId) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        Self {
            model_id,
            version,
            analytics_id,
            status: ModelStatus::Training,
            accuracy: 0.0,
            inference_latency_p99_ms: 0.0,
            model_size_bytes: 0,
            model_uri: None,
            registered_at: now,
            deployed_at: None,
            inference_count: 0,
            inference_errors: 0,
        }
    }

    /// Transitions to Validation with measured accuracy
    pub fn validate(&mut self, accuracy: f64) {
        self.accuracy = accuracy.clamp(0.0, 1.0);
        self.status = if accuracy >= 0.7 {
            ModelStatus::Validation
        } else {
            ModelStatus::Failed
        };
    }

    /// Deploys a validated model
    pub fn deploy(&mut self) -> Result<(), String> {
        if self.status != ModelStatus::Validation {
            return Err(format!("Cannot deploy model in state: {}", self.status));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        self.status = ModelStatus::Deployed;
        self.deployed_at = Some(now);
        Ok(())
    }

    /// Records an inference request outcome
    pub fn record_inference(&mut self, success: bool) {
        self.inference_count += 1;
        if !success {
            self.inference_errors += 1;
        }
    }

    /// Returns error rate (0.0–1.0)
    pub fn error_rate(&self) -> f64 {
        if self.inference_count == 0 {
            0.0
        } else {
            self.inference_errors as f64 / self.inference_count as f64
        }
    }
}

/// ML model registry
#[derive(Debug, Default)]
pub struct MlModelRegistry {
    /// Models keyed by model_id
    models: HashMap<String, MlModel>,
}

impl MlModelRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a new model
    pub fn register(&mut self, model: MlModel) -> String {
        let id = model.model_id.clone();
        self.models.insert(id.clone(), model);
        id
    }

    /// Returns a model by ID
    pub fn get(&self, model_id: &str) -> Option<&MlModel> {
        self.models.get(model_id)
    }

    /// Returns a model mutably
    pub fn get_mut(&mut self, model_id: &str) -> Option<&mut MlModel> {
        self.models.get_mut(model_id)
    }

    /// Returns all deployed models for a given analytics ID
    pub fn deployed_for(&self, analytics_id: AnalyticsId) -> Vec<&MlModel> {
        self.models.values()
            .filter(|m| m.analytics_id == analytics_id && m.status == ModelStatus::Deployed)
            .collect()
    }

    /// Returns the best deployed model for an analytics ID (highest accuracy)
    pub fn best_deployed(&self, analytics_id: AnalyticsId) -> Option<&MlModel> {
        self.deployed_for(analytics_id)
            .into_iter()
            .max_by(|a, b| a.accuracy.partial_cmp(&b.accuracy).unwrap())
    }

    /// Deprecates all models for an analytics ID except the given one
    pub fn deprecate_others(&mut self, analytics_id: AnalyticsId, keep_id: &str) {
        for model in self.models.values_mut() {
            if model.analytics_id == analytics_id
                && model.model_id != keep_id
                && model.status == ModelStatus::Deployed
            {
                model.status = ModelStatus::Deprecated;
            }
        }
    }

    pub fn model_count(&self) -> usize {
        self.models.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_lifecycle() {
        let mut m = MlModel::new("m1".into(), "1.0.0".into(), AnalyticsId::NfLoad);
        assert_eq!(m.status, ModelStatus::Training);
        m.validate(0.85);
        assert_eq!(m.status, ModelStatus::Validation);
        assert!(m.deploy().is_ok());
        assert_eq!(m.status, ModelStatus::Deployed);
    }

    #[test]
    fn test_model_failed_validation() {
        let mut m = MlModel::new("m1".into(), "1.0.0".into(), AnalyticsId::NfLoad);
        m.validate(0.5); // below 70% threshold
        assert_eq!(m.status, ModelStatus::Failed);
        assert!(m.deploy().is_err());
    }

    #[test]
    fn test_error_rate() {
        let mut m = MlModel::new("m1".into(), "1.0.0".into(), AnalyticsId::NfLoad);
        m.record_inference(true);
        m.record_inference(false);
        m.record_inference(true);
        assert!((m.error_rate() - 0.333).abs() < 0.001);
    }

    #[test]
    fn test_registry_deployed_for() {
        let mut reg = MlModelRegistry::new();
        let mut m = MlModel::new("m1".into(), "1.0".into(), AnalyticsId::NfLoad);
        m.validate(0.9);
        m.deploy().unwrap();
        reg.register(m);

        let deployed = reg.deployed_for(AnalyticsId::NfLoad);
        assert_eq!(deployed.len(), 1);
        assert!(reg.deployed_for(AnalyticsId::UeMobility).is_empty());
    }

    #[test]
    fn test_best_deployed() {
        let mut reg = MlModelRegistry::new();
        for (id, acc) in [("m1", 0.75), ("m2", 0.92), ("m3", 0.80)] {
            let mut m = MlModel::new(id.into(), "1.0".into(), AnalyticsId::UeMobility);
            m.validate(acc);
            m.deploy().unwrap();
            reg.register(m);
        }
        let best = reg.best_deployed(AnalyticsId::UeMobility).unwrap();
        assert_eq!(best.model_id, "m2");
    }

    #[test]
    fn test_deprecate_others() {
        let mut reg = MlModelRegistry::new();
        for id in ["m1", "m2", "m3"] {
            let mut m = MlModel::new(id.into(), "1.0".into(), AnalyticsId::NfLoad);
            m.validate(0.8);
            m.deploy().unwrap();
            reg.register(m);
        }
        reg.deprecate_others(AnalyticsId::NfLoad, "m2");
        assert_eq!(reg.get("m1").unwrap().status, ModelStatus::Deprecated);
        assert_eq!(reg.get("m2").unwrap().status, ModelStatus::Deployed);
        assert_eq!(reg.get("m3").unwrap().status, ModelStatus::Deprecated);
    }
}
