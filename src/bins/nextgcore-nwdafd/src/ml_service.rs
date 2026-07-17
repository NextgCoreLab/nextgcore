//! NWDAF ML Model Provisioning Service (TS 23.288 §6.12, Rel-17)
//!
//! Implements the Nnwdaf_MLModelProvision service as a TS 29.520 **Subscribe /
//! Notify** resource (nwafd-05):
//! - `POST /subscriptions` accepts an `NwdafMLModelProvSubsc`
//!   (`mLEventSubscs[]` + `notifUri`) and returns 201 + `Location`.
//! - `PUT` / `DELETE` on `/subscriptions/{id}` update / remove it.
//! - The NWDAF later POSTs an `NwdafMLModelProvNotif` callback (an array of
//!   them) to `notifUri`, each carrying `MLEventNotif`s with the model file
//!   address (`mLFileAddr.mLModelUrl`).
//!
//! The in-process `MlModelRegistry` / `MlModel` lifecycle and the G14 accuracy
//! feedback loop below remain as internal MTLF bookkeeping; they are no longer
//! exposed as a bespoke REST `/models` resource.
//!
//! # Out of scope (nwafd-11)
//!
//! Management-plane ML provisioning is intentionally **not** implemented here:
//! - **TS 28.104** — Management Data Analytics (MDA): an OAM/management-plane
//!   analytics service, not an SBI Nnwdaf service.
//! - **TS 28.105** — AI/ML management (training-job/model lifecycle management
//!   over the management plane).
//!
//! This binary implements only the TS 29.520 control-plane `Nnwdaf_*` SBI
//! services. The `accuracy` figures it reports are linear-regression residual
//! quality (see `analytics.rs` / nwafd-10), not 28.104/28.105 MDA/AI-ML
//! management KPIs, and no MDA/AI-ML management interface is advertised.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use crate::context::{AnalyticsId, MlProvSubscription};

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
        self.models
            .values()
            .filter(|m| m.analytics_id == analytics_id && m.status == ModelStatus::Deployed)
            .collect()
    }

    /// Returns the best deployed model for an analytics ID (highest accuracy)
    pub fn best_deployed(&self, analytics_id: AnalyticsId) -> Option<&MlModel> {
        self.deployed_for(analytics_id)
            .into_iter()
            .max_by(|a, b| a.accuracy.partial_cmp(&b.accuracy).expect("value expected"))
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
        self.samples.push_back(FeedbackSample {
            error,
            timestamp: now,
        });

        // Trigger retraining if rolling accuracy drops
        if self.rolling_accuracy() < self.accuracy_threshold && !self.retrain_requested {
            log::warn!(
                    "[NWDAF FeedbackLoop] model={} rolling_accuracy={:.3} < threshold={:.3} → retrain requested",
                    self.model_id,
                    self.rolling_accuracy(),
                    self.accuracy_threshold,
                );
            self.retrain_requested = true;
        }
    }

    /// Returns the rolling accuracy (1 - mean_error) over the window.
    pub fn rolling_accuracy(&self) -> f64 {
        if self.samples.is_empty() {
            return 1.0; // no data → assume perfect
        }
        let mean_error =
            self.samples.iter().map(|s| s.error).sum::<f64>() / self.samples.len() as f64;
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
        log::info!(
            "[NWDAF FeedbackLoop] model={} retrain acknowledged, window reset",
            self.model_id
        );
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
        self.collectors
            .entry(model_id.clone())
            .or_insert_with(|| FeedbackCollector::new(model_id, 100, 0.70));
    }

    /// Records feedback for a model.
    pub fn record(&mut self, model_id: &str, predicted: f64, actual: f64) {
        if let Some(c) = self.collectors.get_mut(model_id) {
            c.record(predicted, actual);
        }
    }

    /// Returns models that need retraining.
    pub fn models_needing_retrain(&self) -> Vec<&str> {
        self.collectors
            .values()
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

// ============================================================================
// nwafd-05: Nnwdaf_MLModelProvision Subscribe/Notify wire codec (TS 29.520)
// ============================================================================

/// Parsed result of an `NwdafMLModelProvSubsc` request body.
#[derive(Debug, Clone)]
pub struct ParsedMlProvSubsc {
    /// `notifUri` (mandatory).
    pub notif_uri: String,
    /// `notifCorreId` (optional — note the spec's `…CorreId` spelling).
    pub notif_corr_id: Option<String>,
    /// Distinct `mLEventSubscs[].mLEvent` values.
    pub ml_events: Vec<AnalyticsId>,
}

/// Parse a TS 29.520 `NwdafMLModelProvSubsc` JSON body.
///
/// Enforces the two `required` IEs (`notifUri`, `mLEventSubscs` minItems 1) and
/// maps each `mLEvent` token onto an [`AnalyticsId`]. Returns a human-readable
/// error string (used as the 400 `ProblemDetails` detail) on any violation.
pub fn parse_ml_model_prov_subsc(body: &Value) -> Result<ParsedMlProvSubsc, String> {
    let notif_uri = match body.get("notifUri").and_then(|v| v.as_str()) {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => return Err("notifUri is a mandatory IE".to_string()),
    };

    let event_subs = match body.get("mLEventSubscs").and_then(|v| v.as_array()) {
        Some(arr) if !arr.is_empty() => arr,
        _ => return Err("mLEventSubscs is a mandatory IE and must be non-empty".to_string()),
    };

    let mut ml_events: Vec<AnalyticsId> = Vec::with_capacity(event_subs.len());
    for es in event_subs {
        let token = es.get("mLEvent").and_then(|v| v.as_str()).unwrap_or("");
        match AnalyticsId::from_str(token) {
            Some(ev) => {
                if !ml_events.contains(&ev) {
                    ml_events.push(ev);
                }
            }
            None => return Err(format!("Invalid or missing mLEvent: {token}")),
        }
    }

    let notif_corr_id = body
        .get("notifCorreId")
        .and_then(|v| v.as_str())
        .map(String::from);

    Ok(ParsedMlProvSubsc {
        notif_uri,
        notif_corr_id,
        ml_events,
    })
}

/// Echo a stored [`MlProvSubscription`] back as a TS 29.520
/// `NwdafMLModelProvSubsc` JSON object (the 201/200 response representation).
pub fn ml_prov_subsc_json(sub: &MlProvSubscription) -> Value {
    let mut obj = Map::new();
    obj.insert("notifUri".to_string(), json!(sub.notif_uri));
    if let Some(corr) = &sub.notif_corr_id {
        obj.insert("notifCorreId".to_string(), json!(corr));
    }
    obj.insert(
        "mLEventSubscs".to_string(),
        json!(sub
            .ml_events
            .iter()
            .map(|e| json!({ "mLEvent": e.as_str() }))
            .collect::<Vec<_>>()),
    );
    // Convenience echo of the resource id (also conveyed in the Location header).
    obj.insert("subscriptionId".to_string(), json!(sub.subscription_id));
    Value::Object(obj)
}

/// Synthesize the model-file address advertised in a notification.
///
/// HONESTY NOTE: this NWDAF is a linear-regression analytics prototype, not an
/// MTLF that trains and exports real ML model files. The URL is a stable,
/// well-formed placeholder so a conformant consumer can parse `mLFileAddr`; no
/// downloadable model artefact exists behind it.
fn synthetic_model_url(sub_id: &str, event: AnalyticsId) -> String {
    format!(
        "http://nwdaf/nnwdaf-mlmodelprovision/v1/models/{}/{}",
        event.as_str(),
        sub_id
    )
}

/// Build the `Nnwdaf_MLModelProvision` notification callback body for a
/// subscription.
///
/// Per TS 29.520 the callback payload is an **array** of `NwdafMLModelProvNotif`
/// (minItems 1); each carries the required `subscriptionId` and `eventNotifs[]`
/// of `MLEventNotif`, where every `MLEventNotif` satisfies the `oneOf` by
/// supplying `mLFileAddr.mLModelUrl`.
pub fn build_ml_model_prov_notif_body(sub: &MlProvSubscription) -> Value {
    let event_notifs: Vec<Value> = sub
        .ml_events
        .iter()
        .map(|ev| {
            let mut notif = Map::new();
            notif.insert("event".to_string(), json!(ev.as_str()));
            if let Some(corr) = &sub.notif_corr_id {
                notif.insert("notifCorreId".to_string(), json!(corr));
            }
            notif.insert(
                "mLFileAddr".to_string(),
                json!({ "mLModelUrl": synthetic_model_url(&sub.subscription_id, *ev) }),
            );
            Value::Object(notif)
        })
        .collect();

    json!([
        {
            "subscriptionId": sub.subscription_id,
            "eventNotifs": event_notifs,
        }
    ])
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

    // ---- nwafd-05: MLModelProvision Subscribe/Notify codec ----

    /// A conformant `NwdafMLModelProvSubsc` parses into the notifUri, the
    /// optional `notifCorreId`, and the distinct `mLEvent`s.
    #[test]
    fn test_parse_ml_prov_subsc_ok() {
        let body = json!({
            "notifUri": "http://anlf.local/ml-cb",
            "notifCorreId": "corr-7",
            "mLEventSubscs": [
                { "mLEvent": "NF_LOAD" },
                { "mLEvent": "UE_MOBILITY" },
                { "mLEvent": "NF_LOAD" }
            ]
        });
        let parsed = parse_ml_model_prov_subsc(&body).expect("must parse");
        assert_eq!(parsed.notif_uri, "http://anlf.local/ml-cb");
        assert_eq!(parsed.notif_corr_id.as_deref(), Some("corr-7"));
        // Duplicate NF_LOAD collapses to one distinct event.
        assert_eq!(
            parsed.ml_events,
            vec![AnalyticsId::NfLoad, AnalyticsId::UeMobility]
        );
    }

    /// Missing `notifUri` or empty `mLEventSubscs` are rejected (the two spec
    /// `required` IEs).
    #[test]
    fn test_parse_ml_prov_subsc_rejects_missing_required() {
        let no_uri = json!({ "mLEventSubscs": [ { "mLEvent": "NF_LOAD" } ] });
        assert!(parse_ml_model_prov_subsc(&no_uri).is_err());

        let empty_events = json!({ "notifUri": "http://x/y", "mLEventSubscs": [] });
        assert!(parse_ml_model_prov_subsc(&empty_events).is_err());

        let bad_event = json!({
            "notifUri": "http://x/y",
            "mLEventSubscs": [ { "mLEvent": "NOT_AN_EVENT" } ]
        });
        assert!(parse_ml_model_prov_subsc(&bad_event).is_err());
    }

    /// The notify callback body deserializes as the TS 29.520 array-of-
    /// `NwdafMLModelProvNotif` shape: `subscriptionId` + `eventNotifs[]`, each
    /// `MLEventNotif` carrying `event` and `mLFileAddr.mLModelUrl`.
    #[test]
    fn test_build_ml_prov_notif_body_shape() {
        let sub = MlProvSubscription::new(
            "mlsub-9".to_string(),
            "http://anlf.local/ml-cb".to_string(),
            Some("corr-9".to_string()),
            vec![AnalyticsId::NfLoad],
        );
        let body = build_ml_model_prov_notif_body(&sub);

        let arr = body.as_array().expect("callback body is an array");
        assert_eq!(arr.len(), 1, "minItems 1 array of NwdafMLModelProvNotif");

        let notif = &arr[0];
        assert_eq!(notif["subscriptionId"].as_str(), Some("mlsub-9"));
        let evns = notif["eventNotifs"]
            .as_array()
            .expect("eventNotifs is a required array");
        assert_eq!(evns.len(), 1);
        assert_eq!(evns[0]["event"].as_str(), Some("NF_LOAD"));
        assert_eq!(evns[0]["notifCorreId"].as_str(), Some("corr-9"));
        assert!(
            evns[0]["mLFileAddr"]["mLModelUrl"].as_str().is_some(),
            "MLEventNotif must satisfy the oneOf via mLFileAddr.mLModelUrl"
        );
        // No bespoke registry keys leak into the notification.
        assert!(notif.get("modelCount").is_none());
        assert!(notif.get("accuracy").is_none());
    }
}

// ============================================================================
// Issue #26: inference abstraction (load-by-id + predict)
// ============================================================================

/// A loaded prediction model: one-step-ahead forecasting over a numeric
/// series (issue #26). `Send + Sync` because the analytics engine that owns
/// the active model lives behind a shared `Mutex` in the NWDAF context.
///
/// Non-normative: TS 23.288 does not specify model internals; the baselines
/// here need no model file so the default build and E2E path are unchanged.
pub trait InferenceModel: Send + Sync {
    /// Stable identifier (also what `load_model` resolves).
    fn model_id(&self) -> &str;
    /// Predict the next value of `series` (values in 0.0..=1.0).
    /// Returns `(prediction clamped to 0..=1, confidence 0..=1)`, or `None`
    /// when the series is empty or shorter than the model's input window.
    fn predict_series(&self, series: &[f64]) -> Option<(f64, f64)>;
}

/// Default baseline: ordinary-least-squares linear fit over the last ≤5
/// samples — byte-for-byte the math `AnalyticsEngine::compute_nf_load`
/// used inline before issue #26 (confidence = R² of the fit; single sample
/// → (value, 0.0)).
#[derive(Debug, Clone, Default)]
pub struct OlsLinearModel;

impl InferenceModel for OlsLinearModel {
    fn model_id(&self) -> &str {
        "ols-linear"
    }

    fn predict_series(&self, series: &[f64]) -> Option<(f64, f64)> {
        if series.is_empty() {
            return None;
        }
        let n = series.len().min(5);
        if n < 2 {
            // A single sample yields no residual basis; report no confidence.
            return Some((series[series.len() - 1].clamp(0.0, 1.0), 0.0));
        }
        let last = &series[series.len() - n..];
        let nf = n as f64;
        let sum_x: f64 = (0..n).map(|i| i as f64).sum();
        let sum_y: f64 = last.iter().sum();
        let sum_xx: f64 = (0..n).map(|i| (i as f64).powi(2)).sum();
        let sum_xy: f64 = last.iter().enumerate().map(|(i, y)| i as f64 * y).sum();
        // denom = N·Σx² − (Σx)² is strictly positive for N ≥ 2 distinct x.
        let denom = nf * sum_xx - sum_x * sum_x;
        let b = (nf * sum_xy - sum_x * sum_y) / denom;
        let a = (sum_y - b * sum_x) / nf;
        let predicted = (a + b * nf).clamp(0.0, 1.0);
        // R² = 1 − SS_res / SS_tot.
        let mean_y = sum_y / nf;
        let ss_tot: f64 = last.iter().map(|y| (y - mean_y).powi(2)).sum();
        let ss_res: f64 = last
            .iter()
            .enumerate()
            .map(|(i, y)| (y - (a + b * i as f64)).powi(2))
            .sum();
        let r_squared = if ss_tot <= f64::EPSILON {
            // Flat series: the predictor reproduces it exactly → R² = 1.
            1.0
        } else {
            (1.0 - ss_res / ss_tot).clamp(0.0, 1.0)
        };
        Some((predicted, r_squared))
    }
}

/// EWMA baseline: exponentially weighted moving average as the next-step
/// prediction; confidence is `1 − mean(|one-step EWMA error|)` over the
/// series (a documented heuristic, NOT a goodness-of-fit statistic).
#[derive(Debug, Clone)]
pub struct EwmaModel {
    alpha: f64,
}

impl EwmaModel {
    pub fn new(alpha: f64) -> Self {
        Self {
            alpha: if alpha.is_finite() {
                alpha.clamp(0.01, 1.0)
            } else {
                0.3
            },
        }
    }

    pub fn alpha(&self) -> f64 {
        self.alpha
    }
}

impl Default for EwmaModel {
    fn default() -> Self {
        Self::new(0.3)
    }
}

impl InferenceModel for EwmaModel {
    fn model_id(&self) -> &str {
        "ewma"
    }

    fn predict_series(&self, series: &[f64]) -> Option<(f64, f64)> {
        let (first, rest) = series.split_first()?;
        if rest.is_empty() {
            return Some((first.clamp(0.0, 1.0), 0.0));
        }
        let mut ewma = *first;
        let mut abs_err_sum = 0.0;
        for y in rest {
            // The pre-update EWMA is the one-step prediction for `y`.
            abs_err_sum += (y - ewma).abs();
            ewma = self.alpha * y + (1.0 - self.alpha) * ewma;
        }
        let confidence = (1.0 - abs_err_sum / rest.len() as f64).clamp(0.0, 1.0);
        Some((ewma.clamp(0.0, 1.0), confidence))
    }
}

/// Wrapper giving the boxed active model `Debug` + `Default` (the analytics
/// engine derives both; the default is the OLS baseline, keeping default
/// builds behavior-identical).
pub struct Predictor(pub Box<dyn InferenceModel>);

impl std::fmt::Debug for Predictor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Predictor")
            .field(&self.0.model_id())
            .finish()
    }
}

impl Default for Predictor {
    fn default() -> Self {
        Self(Box::new(OlsLinearModel))
    }
}

/// Load a prediction model by id (issue #26 "load-by-id" surface):
/// - `"ols-linear"` — the default OLS baseline (no model file)
/// - `"ewma"` or `"ewma:<alpha>"` — EWMA baseline (no model file)
/// - `"onnx:<path>"` — ONNX-backed linear model, only with the off-by-default
///   `onnx-model` cargo feature (zero-dependency minimal subset reader)
pub fn load_model(model_id: &str) -> Result<Box<dyn InferenceModel>, String> {
    if model_id == "ols-linear" {
        return Ok(Box::new(OlsLinearModel));
    }
    if model_id == "ewma" {
        return Ok(Box::new(EwmaModel::default()));
    }
    if let Some(alpha) = model_id.strip_prefix("ewma:") {
        let alpha: f64 = alpha
            .parse()
            .map_err(|e| format!("invalid ewma alpha {alpha:?}: {e}"))?;
        return Ok(Box::new(EwmaModel::new(alpha)));
    }
    if let Some(path) = model_id.strip_prefix("onnx:") {
        #[cfg(feature = "onnx-model")]
        {
            return crate::onnx_model::OnnxLinearRegressor::load(std::path::Path::new(path))
                .map(|m| Box::new(m) as Box<dyn InferenceModel>);
        }
        #[cfg(not(feature = "onnx-model"))]
        {
            return Err(format!(
                "model {path:?} requires the off-by-default `onnx-model` cargo feature"
            ));
        }
    }
    Err(format!(
        "unknown model id {model_id:?} (expected ols-linear, ewma[:<alpha>], or onnx:<path>)"
    ))
}

#[cfg(test)]
mod inference_tests {
    use super::*;

    #[test]
    fn ols_matches_legacy_inline_math() {
        // Clean rising trend → high R² (mirrors test_confidence_reflects_fit_quality).
        let clean: Vec<f64> = (0..10).map(|i| 0.1 + 0.05 * i as f64).collect();
        let (pred, conf) = OlsLinearModel.predict_series(&clean).unwrap();
        assert!(conf > 0.9, "clean trend must have high confidence ({conf})");
        assert!(
            pred > *clean.last().unwrap(),
            "rising trend projects upward"
        );

        // Zig-zag → poor fit.
        let zigzag = [0.3, 0.7, 0.3, 0.7, 0.3, 0.7, 0.3, 0.7];
        let (_, zconf) = OlsLinearModel.predict_series(&zigzag).unwrap();
        assert!(zconf < 0.5, "zig-zag must have low confidence ({zconf})");
        assert!(zconf < conf);

        // Single sample → (value, 0.0); empty → None.
        assert_eq!(OlsLinearModel.predict_series(&[0.4]), Some((0.4, 0.0)));
        assert!(OlsLinearModel.predict_series(&[]).is_none());

        // Flat series → R² = 1.
        let (fp, fc) = OlsLinearModel.predict_series(&[0.5; 6]).unwrap();
        assert!((fp - 0.5).abs() < 1e-9);
        assert!((fc - 1.0).abs() < 1e-9);
    }

    #[test]
    fn ewma_predicts_and_scores() {
        let m = EwmaModel::default();
        assert_eq!(m.model_id(), "ewma");
        let (pred, conf) = m.predict_series(&[0.5; 8]).unwrap();
        assert!((pred - 0.5).abs() < 1e-9, "flat series predicts itself");
        assert!((conf - 1.0).abs() < 1e-9, "no error → full confidence");
        let (_, noisy_conf) = m.predict_series(&[0.1, 0.9, 0.1, 0.9]).unwrap();
        assert!(noisy_conf < 0.5);
        assert!(m.predict_series(&[]).is_none());
        // Alpha clamping.
        assert!((EwmaModel::new(f64::NAN).alpha() - 0.3).abs() < 1e-9);
        assert!((EwmaModel::new(7.0).alpha() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn load_model_resolves_ids() {
        assert_eq!(load_model("ols-linear").unwrap().model_id(), "ols-linear");
        assert_eq!(load_model("ewma").unwrap().model_id(), "ewma");
        assert_eq!(load_model("ewma:0.5").unwrap().model_id(), "ewma");
        assert!(load_model("ewma:x").is_err());
        assert!(load_model("bogus").is_err());
        #[cfg(not(feature = "onnx-model"))]
        assert!(load_model("onnx:/tmp/m.onnx")
            .err()
            .expect("onnx must fail without the feature")
            .contains("onnx-model"));
    }

    #[test]
    fn predictor_wrapper_debug_and_default() {
        let p = Predictor::default();
        assert_eq!(p.0.model_id(), "ols-linear");
        assert!(format!("{p:?}").contains("ols-linear"));
    }
}
