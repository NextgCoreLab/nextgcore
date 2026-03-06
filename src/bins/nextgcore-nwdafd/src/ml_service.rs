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
            .max_by(|a, b| a.accuracy.partial_cmp(&b.accuracy).unwrap_or_default())
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

// ============================================================================
// G14: Accuracy Feedback Loop (TS 23.288 §6.12.3, Rel-17)
// ============================================================================

/// A single feedback sample: predicted value vs observed ground truth
#[derive(Debug, Clone)]
pub struct FeedbackSample {
    /// Absolute prediction error (0.0 = perfect, 1.0 = worst)
    pub error: f64,
    /// UNIX timestamp when the feedback was collected
    pub timestamp: u64,
}

/// Closed-loop accuracy feedback collector.
///
/// Accumulates prediction errors from consumers and triggers a retraining
/// signal when the rolling-window accuracy drops below the retraining threshold.
#[derive(Debug)]
pub struct FeedbackCollector {
    /// Model this collector is attached to
    pub model_id: String,
    /// Sliding window of recent feedback samples
    samples: std::collections::VecDeque<FeedbackSample>,
    /// Maximum window size (number of samples kept)
    window_size: usize,
    /// Accuracy (1 - mean_error) must stay above this to avoid retraining
    accuracy_threshold: f64,
    /// Whether a retraining signal has been raised
    retrain_requested: bool,
}

impl FeedbackCollector {
    /// Creates a new feedback collector with given window size and threshold.
    pub fn new(model_id: String, window_size: usize, accuracy_threshold: f64) -> Self {
        Self {
            model_id,
            samples: std::collections::VecDeque::with_capacity(window_size),
            window_size,
            accuracy_threshold: accuracy_threshold.clamp(0.0, 1.0),
            retrain_requested: false,
        }
    }

    /// Records a ground-truth feedback sample.
    ///
    /// `predicted` and `actual` are normalised values in [0.0, 1.0].
    /// The absolute error is stored; a rolling-window accuracy is recomputed
    /// and if it falls below the threshold the retrain flag is set.
    pub fn record(&mut self, predicted: f64, actual: f64) {
        let error = (predicted - actual).abs().clamp(0.0, 1.0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs();

        if self.samples.len() >= self.window_size {
            self.samples.pop_front();
        }
        self.samples.push_back(FeedbackSample { error, timestamp: now });

        // Trigger retraining if rolling accuracy drops
        if self.rolling_accuracy() < self.accuracy_threshold {
            if !self.retrain_requested {
                log::warn!(
                    "[NWDAF FeedbackLoop] model={} rolling_accuracy={:.3} < threshold={:.3} → retrain requested",
                    self.model_id,
                    self.rolling_accuracy(),
                    self.accuracy_threshold,
                );
                self.retrain_requested = true;
            }
        }
    }

    /// Returns the rolling accuracy (1 - mean_error) over the window.
    pub fn rolling_accuracy(&self) -> f64 {
        if self.samples.is_empty() {
            return 1.0; // no data → assume perfect
        }
        let mean_error = self.samples.iter().map(|s| s.error).sum::<f64>()
            / self.samples.len() as f64;
        1.0 - mean_error
    }

    /// Returns true if a retraining signal has been raised.
    pub fn retrain_requested(&self) -> bool {
        self.retrain_requested
    }

    /// Clears the retraining signal (called when retraining has started).
    pub fn acknowledge_retrain(&mut self) {
        self.retrain_requested = false;
        self.samples.clear();
        log::info!("[NWDAF FeedbackLoop] model={} retrain acknowledged, window reset", self.model_id);
    }

    /// Returns the number of samples in the window.
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }
}

/// Registry of feedback collectors keyed by model_id.
/// Wired into the ML model registry so each deployed model has one.
#[derive(Debug, Default)]
pub struct FeedbackRegistry {
    collectors: HashMap<String, FeedbackCollector>,
}

impl FeedbackRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a collector for a model (called when a model is deployed).
    pub fn register_model(&mut self, model_id: String) {
        self.collectors.entry(model_id.clone()).or_insert_with(|| {
            FeedbackCollector::new(model_id, 100, 0.70)
        });
    }

    /// Records feedback for a model.
    pub fn record(&mut self, model_id: &str, predicted: f64, actual: f64) {
        if let Some(c) = self.collectors.get_mut(model_id) {
            c.record(predicted, actual);
        }
    }

    /// Returns models that need retraining.
    pub fn models_needing_retrain(&self) -> Vec<&str> {
        self.collectors.values()
            .filter(|c| c.retrain_requested())
            .map(|c| c.model_id.as_str())
            .collect()
    }

    /// Acknowledges retrain signal for a model.
    pub fn acknowledge_retrain(&mut self, model_id: &str) {
        if let Some(c) = self.collectors.get_mut(model_id) {
            c.acknowledge_retrain();
        }
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

    // ---- G14 feedback loop tests ----

    #[test]
    fn test_feedback_perfect_predictions() {
        let mut fc = FeedbackCollector::new("m1".into(), 10, 0.70);
        for _ in 0..5 {
            fc.record(0.5, 0.5); // zero error
        }
        assert!((fc.rolling_accuracy() - 1.0).abs() < 1e-9);
        assert!(!fc.retrain_requested());
    }

    #[test]
    fn test_feedback_triggers_retrain_on_degradation() {
        let mut fc = FeedbackCollector::new("m1".into(), 10, 0.70);
        // Inject large errors to push accuracy below 70%
        for _ in 0..10 {
            fc.record(0.0, 1.0); // 100% error each sample
        }
        assert!(fc.rolling_accuracy() < 0.70);
        assert!(fc.retrain_requested());
    }

    #[test]
    fn test_feedback_acknowledge_clears_flag() {
        let mut fc = FeedbackCollector::new("m1".into(), 10, 0.70);
        for _ in 0..10 {
            fc.record(0.0, 1.0);
        }
        assert!(fc.retrain_requested());
        fc.acknowledge_retrain();
        assert!(!fc.retrain_requested());
        assert_eq!(fc.sample_count(), 0);
    }

    #[test]
    fn test_feedback_sliding_window() {
        let mut fc = FeedbackCollector::new("m1".into(), 3, 0.70);
        // Fill with bad samples
        fc.record(0.0, 1.0);
        fc.record(0.0, 1.0);
        fc.record(0.0, 1.0);
        assert!(fc.retrain_requested());
        fc.acknowledge_retrain();

        // Good samples that evict the bad ones
        fc.record(0.8, 0.8);
        fc.record(0.8, 0.8);
        fc.record(0.8, 0.8);
        assert!(fc.rolling_accuracy() >= 0.70);
        assert!(!fc.retrain_requested());
    }

    #[test]
    fn test_feedback_registry_retrain_detection() {
        let mut reg = FeedbackRegistry::new();
        reg.register_model("m1".into());
        reg.register_model("m2".into());

        // Drive m1 into degradation
        for _ in 0..100 {
            reg.record("m1", 0.0, 1.0);
        }
        // m2 remains healthy
        for _ in 0..100 {
            reg.record("m2", 0.5, 0.5);
        }

        let need_retrain = reg.models_needing_retrain();
        assert!(need_retrain.contains(&"m1"));
        assert!(!need_retrain.contains(&"m2"));

        reg.acknowledge_retrain("m1");
        assert!(reg.models_needing_retrain().is_empty());
    }
}
