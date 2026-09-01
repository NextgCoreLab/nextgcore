//! NWDAF Analytics Engine (TS 23.288 §6)
//!
//! Implements analytics computation for:
//! - NF Load (§6.2.4): CPU/memory/session utilization per NF
//! - UE Mobility (§6.7): predicted mobility patterns
//! - QoS Sustainability (§6.9): predicted QoS degradation
//! - Slice Load (§6.10): per-slice resource utilization
//! - Abnormal Behaviour (§6.5): anomaly detection
//!
//! # OPERATIONAL ALGORITHM
//!
//! **NF_LOAD prediction is routed through the pluggable
//! `ml_service::InferenceModel` (issue #26); the default model is ordinary
//! least-squares linear regression on the last N samples, and the other
//! analytics in this module use the same OLS approach inline.** The `confidence` field is the regression R² (the
//! fraction of variance the linear fit explains, nwafd-10) — it reflects how
//! well the predictor fits the observed data, NOT trained-model accuracy. No ML
//! model is used. When `Nnwdaf_MLModelProvision` models are integrated, the
//! prediction path should switch to model-accuracy metrics (TS 23.288 §6.14).

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// NF load sample collected from OAM/metrics
#[derive(Debug, Clone)]
pub struct NfLoadSample {
    /// NF type (e.g., "AMF", "SMF")
    pub nf_type: String,
    /// NF instance ID
    pub nf_instance_id: String,
    /// CPU utilization 0.0–1.0
    pub cpu_usage: f64,
    /// Memory utilization 0.0–1.0
    pub mem_usage: f64,
    /// Active PDU sessions / registrations
    pub active_sessions: u32,
    /// Timestamp (UNIX seconds)
    pub timestamp: u64,
}

impl NfLoadSample {
    pub fn now(nf_type: &str, nf_instance_id: &str, cpu: f64, mem: f64, sessions: u32) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        Self {
            nf_type: nf_type.into(),
            nf_instance_id: nf_instance_id.into(),
            cpu_usage: cpu.clamp(0.0, 1.0),
            mem_usage: mem.clamp(0.0, 1.0),
            active_sessions: sessions,
            timestamp: ts,
        }
    }
}

/// A closed observation window in Unix seconds, inclusive at both ends.
///
/// Issue #171: TS 29.520 NOTE 7 on `AnalyticsData` — when the requested
/// analytics target period (`ana-req.startTs`/`endTs`) refers to the PAST, the
/// reported analytics are *statistics over that period*, so the samples they are
/// computed from must come from that period and no other. Without this, a
/// request for statistics over last Tuesday is answered with today's numbers
/// carrying last Tuesday's `start`/`expiry` — a fabricated label on real data.
///
/// A *future* target period is deliberately NOT expressed as a window: a
/// prediction is computed *from* past samples, so restricting the input to the
/// prediction interval would leave nothing to predict from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservationWindow {
    /// Earliest sample timestamp to consider (inclusive).
    pub start: u64,
    /// Latest sample timestamp to consider (inclusive).
    pub end: u64,
}

impl ObservationWindow {
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    /// Whether a sample timestamp falls inside this window.
    pub fn contains(&self, timestamp: u64) -> bool {
        timestamp >= self.start && timestamp <= self.end
    }
}

/// Cached per-NF-instance profile metadata sourced from NRF
/// NFStatusSubscribe/Notify (TS 29.510 §5.2.2.5/§5.2.2.6). This is the
/// authoritative record of what the NRF last told us about an instance —
/// `nf_status` feeds the emitted `NfLoadLevelInformation.nfStatus` and
/// `last_load` is the base value `profileChanges` `/load` deltas apply to.
#[derive(Debug, Clone)]
pub struct NfProfileMeta {
    /// NF type from the NRF profile (e.g., "AMF")
    pub nf_type: String,
    /// NF status token from the NRF profile ("REGISTERED" / "SUSPENDED" / ...)
    pub nf_status: String,
    /// Last known NFProfile.load (0..=100), when the profile carried one
    pub last_load: Option<u8>,
}

/// NF load analytics report
#[derive(Debug, Clone)]
pub struct NfLoadAnalytics {
    pub nf_type: String,
    pub nf_instance_id: String,
    /// Mean CPU load over the observation window
    pub mean_cpu: f64,
    /// Peak CPU over the window
    pub peak_cpu: f64,
    /// Predicted load at next interval (simple linear projection)
    pub predicted_load: f64,
    /// Confidence (0.0–1.0)
    pub confidence: f64,
}

/// UE mobility prediction entry
#[derive(Debug, Clone)]
pub struct UeMobilityPrediction {
    pub supi: String,
    /// Current serving cell ID
    pub current_cell: u64,
    /// Predicted next cell and probability
    pub predicted_next_cell: Option<u64>,
    pub prediction_probability: f64,
    /// Predicted time-of-move (seconds from now)
    pub predicted_move_in_secs: u64,
}

/// QoS sustainability prediction
#[derive(Debug, Clone)]
pub struct QosSustainabilityPrediction {
    pub supi: String,
    pub pdu_session_id: u8,
    /// Predicted QFI that may degrade
    pub affected_qfi: u8,
    /// Predicted degradation window start (UNIX seconds)
    pub start_time: u64,
    /// Duration of predicted degradation
    pub duration_secs: u32,
    /// Confidence
    pub confidence: f64,
}

/// Abnormal behaviour record
#[derive(Debug, Clone)]
pub struct AbnormalBehaviourRecord {
    pub supi: String,
    /// Anomaly type description
    pub anomaly_type: String,
    /// Anomaly score (0–100)
    pub score: u8,
    pub detected_at: u64,
}

/// NWDAF analytics engine: stores samples and computes analytics
#[derive(Debug, Default)]
pub struct AnalyticsEngine {
    /// NF load samples, keyed by NF instance ID, bounded circular buffer (last 100)
    nf_samples: HashMap<String, Vec<NfLoadSample>>,
    /// Cached NRF profile metadata per NF instance (G2-1: fed by the
    /// Nnrf_NFManagement NFStatusNotify ingestion path)
    nf_meta: HashMap<String, NfProfileMeta>,
    /// UE mobility history: last observed cell per SUPI
    ue_cells: HashMap<String, Vec<(u64, u64)>>, // (cell_id, timestamp)
    /// Anomaly scores per SUPI
    anomaly_scores: HashMap<String, Vec<AbnormalBehaviourRecord>>,
    /// Active prediction model for NF_LOAD (issue #26): defaults to the OLS
    /// baseline, swappable via `set_predictor` / NWDAF_PREDICTION_MODEL.
    predictor: crate::ml_service::Predictor,
}

pub(crate) const MAX_SAMPLES: usize = 100;

impl AnalyticsEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest a new NF load sample
    pub fn ingest_nf_load(&mut self, sample: NfLoadSample) {
        let key = sample.nf_instance_id.clone();
        let buf = self.nf_samples.entry(key).or_default();
        if buf.len() >= MAX_SAMPLES {
            buf.remove(0);
        }
        buf.push(sample);
    }

    /// Swap the active NF_LOAD prediction model (issue #26).
    pub fn set_predictor(&mut self, model: Box<dyn crate::ml_service::InferenceModel>) {
        self.predictor = crate::ml_service::Predictor(model);
    }

    /// Identifier of the active prediction model.
    pub fn predictor_id(&self) -> &str {
        self.predictor.0.model_id()
    }

    /// The active prediction model, so callers can ask what it *is* rather than
    /// only what it predicts — `Nnwdaf_MLModelProvision` needs its linear form
    /// to export a model artefact (issue #109).
    pub fn predictor(&self) -> &dyn crate::ml_service::InferenceModel {
        self.predictor.0.as_ref()
    }

    /// Upsert the cached NRF profile metadata for an NF instance (G2-1).
    pub fn upsert_nf_meta(&mut self, nf_instance_id: &str, meta: NfProfileMeta) {
        self.nf_meta.insert(nf_instance_id.to_string(), meta);
    }

    /// Cached NRF profile metadata for an NF instance, if any.
    pub fn nf_meta(&self, nf_instance_id: &str) -> Option<&NfProfileMeta> {
        self.nf_meta.get(nf_instance_id)
    }

    /// Drop everything known about an NF instance (samples + cached profile
    /// metadata). Called on NF_DEREGISTERED so analytics never report data
    /// for an instance the NRF says is gone (G2-1 fail-closed).
    pub fn remove_nf_instance(&mut self, nf_instance_id: &str) {
        self.nf_samples.remove(nf_instance_id);
        self.nf_meta.remove(nf_instance_id);
    }

    /// All NF instance IDs that currently have at least one load sample,
    /// sorted for deterministic emission order.
    pub fn nf_instance_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .nf_samples
            .iter()
            .filter(|(_, samples)| !samples.is_empty())
            .map(|(id, _)| id.clone())
            .collect();
        ids.sort();
        ids
    }

    /// Compute NF load analytics for a given instance.
    ///
    /// OPERATIONAL ALGORITHM: ordinary least-squares linear regression over the
    /// last N samples (up to 5). `predicted_load` is the fitted value projected
    /// one step ahead, clamped to [0, 1].
    ///
    /// `predicted_load` and `confidence` are produced by the active
    /// `ml_service::InferenceModel` (issue #26). The default model is the OLS
    /// baseline whose confidence (nwafd-10) is the regression **R²** — the
    /// fraction of the window's CPU variance explained by the linear fit,
    /// clamped to [0, 1] — byte-identical to the math this method previously
    /// inlined. HONESTY NOTE: the baselines are statistical predictors, NOT
    /// trained ML models; the feature-gated `onnx-model` backend loads real
    /// (linear) model files, and each model documents its own confidence
    /// semantics (TS 23.288 §6.14).
    pub fn compute_nf_load(&self, nf_instance_id: &str) -> Option<NfLoadAnalytics> {
        self.compute_nf_load_in_window(nf_instance_id, None)
    }

    /// Compute NF load analytics from the samples inside `window` only
    /// (issue #171).
    ///
    /// `None` considers every stored sample and is exactly
    /// [`compute_nf_load`](Self::compute_nf_load). A `Some(window)` restricts the
    /// input to samples observed inside it, so a request for statistics over a
    /// past analytics target period is answered from *that* period's data — and
    /// returns `None` when the window holds no sample, which is what lets the
    /// AnalyticsInfo handler distinguish "no data for the requested period"
    /// (`500 UNAVAILABLE_DATA`, TS 29.520 §4.3.2.2.2) from "no data at all".
    pub fn compute_nf_load_in_window(
        &self,
        nf_instance_id: &str,
        window: Option<ObservationWindow>,
    ) -> Option<NfLoadAnalytics> {
        let samples = self.nf_samples.get(nf_instance_id)?;
        let windowed: Vec<&NfLoadSample> = match window {
            Some(w) => samples.iter().filter(|s| w.contains(s.timestamp)).collect(),
            None => samples.iter().collect(),
        };
        if windowed.is_empty() {
            return None;
        }
        let mean_cpu = windowed.iter().map(|s| s.cpu_usage).sum::<f64>() / windowed.len() as f64;
        let peak_cpu = windowed.iter().map(|s| s.cpu_usage).fold(0.0f64, f64::max);

        // Issue #26: route the prediction through the active inference model
        // (default: the OLS baseline, byte-identical to the formerly inline
        // least-squares fit). A model that declines (window too short) falls
        // back to (mean, no-confidence), preserving the pre-#26 contract.
        let values: Vec<f64> = windowed.iter().map(|s| s.cpu_usage).collect();
        let (predicted_load, confidence) = self
            .predictor
            .0
            .predict_series(&values)
            .unwrap_or((mean_cpu, 0.0));

        Some(NfLoadAnalytics {
            nf_type: windowed[0].nf_type.clone(),
            nf_instance_id: nf_instance_id.into(),
            mean_cpu,
            peak_cpu,
            predicted_load,
            confidence,
        })
    }

    /// Records a UE cell update for mobility analytics
    pub fn ingest_ue_cell(&mut self, supi: &str, cell_id: u64, timestamp: u64) {
        let buf = self.ue_cells.entry(supi.into()).or_default();
        if buf.len() >= MAX_SAMPLES {
            buf.remove(0);
        }
        buf.push((cell_id, timestamp));
    }

    /// Returns a mobility prediction for a UE (simplified: next cell = most-visited)
    pub fn predict_mobility(&self, supi: &str) -> Option<UeMobilityPrediction> {
        let history = self.ue_cells.get(supi)?;
        if history.is_empty() {
            return None;
        }
        let current_cell = history.last().expect("value expected").0;

        // Count transitions to find most likely next cell
        let mut next_counts: HashMap<u64, u32> = HashMap::new();
        for i in 0..history.len().saturating_sub(1) {
            if history[i].0 == current_cell {
                *next_counts.entry(history[i + 1].0).or_default() += 1;
            }
        }

        let (next_cell, count) = next_counts
            .iter()
            .max_by_key(|(_, c)| *c)
            .map(|(c, n)| (Some(*c), *n))
            .unwrap_or((None, 0));

        let total = next_counts.values().sum::<u32>().max(1);
        let probability = count as f64 / total as f64;

        Some(UeMobilityPrediction {
            supi: supi.into(),
            current_cell,
            predicted_next_cell: next_cell,
            prediction_probability: probability,
            predicted_move_in_secs: 30,
        })
    }

    /// Records an anomaly for a UE
    pub fn record_anomaly(&mut self, record: AbnormalBehaviourRecord) {
        let buf = self.anomaly_scores.entry(record.supi.clone()).or_default();
        if buf.len() >= 20 {
            buf.remove(0);
        }
        buf.push(record);
    }

    /// Returns recent anomaly records for a UE
    pub fn get_anomalies(&self, supi: &str) -> &[AbnormalBehaviourRecord] {
        self.anomaly_scores
            .get(supi)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nf_load_analytics() {
        let mut engine = AnalyticsEngine::new();
        for i in 0..10 {
            let sample =
                NfLoadSample::now("AMF", "amf-01", 0.3 + i as f64 * 0.05, 0.4, 100 + i * 10);
            engine.ingest_nf_load(sample);
        }
        let analytics = engine.compute_nf_load("amf-01").unwrap();
        assert!(analytics.mean_cpu > 0.3);
        assert!(analytics.peak_cpu <= 1.0);
        assert!(analytics.confidence > 0.0);
    }

    /// nwafd-10: confidence is the regression R² — high for a clean linear
    /// trend, much lower for noisy zig-zag input, and never the old constant.
    #[test]
    fn test_confidence_reflects_fit_quality() {
        let mut clean = AnalyticsEngine::new();
        for i in 0..5 {
            clean.ingest_nf_load(NfLoadSample::now(
                "AMF",
                "amf-clean",
                0.3 + i as f64 * 0.05,
                0.4,
                0,
            ));
        }
        let clean_r = clean.compute_nf_load("amf-clean").expect("analytics");

        let mut noisy = AnalyticsEngine::new();
        for v in [0.3, 0.7, 0.3, 0.7, 0.3] {
            noisy.ingest_nf_load(NfLoadSample::now("AMF", "amf-noisy", v, 0.4, 0));
        }
        let noisy_r = noisy.compute_nf_load("amf-noisy").expect("analytics");

        assert!(
            clean_r.confidence > 0.9,
            "a clean linear trend must yield near-1.0 R² confidence, got {}",
            clean_r.confidence
        );
        assert!(
            noisy_r.confidence < clean_r.confidence,
            "noisy input must yield lower confidence than a clean trend"
        );
        assert!(
            noisy_r.confidence < 0.5,
            "a trendless zig-zag must yield low R², got {}",
            noisy_r.confidence
        );
        // The previous synthetic constant (sample-count ratio) is gone: with 5
        // of 100 samples it would have been 0.05, not ~1.0 for the clean trend.
        assert!((clean_r.confidence - 0.05).abs() > 0.1);
    }

    /// Issue #171: a past analytics target period must be answered from the
    /// samples observed inside it, and a window holding no sample must return
    /// `None` rather than silently widening to every sample.
    #[test]
    fn test_windowed_nf_load_uses_only_samples_in_the_window() {
        let mut engine = AnalyticsEngine::new();
        // Three samples at t = 1000, 2000, 3000 with distinct CPU values.
        for (ts, cpu) in [(1000u64, 0.20), (2000, 0.60), (3000, 1.00)] {
            engine.ingest_nf_load(NfLoadSample {
                nf_type: "AMF".into(),
                nf_instance_id: "amf-window".into(),
                cpu_usage: cpu,
                mem_usage: 0.0,
                active_sessions: 0,
                timestamp: ts,
            });
        }

        // No window → every sample: mean of 0.2/0.6/1.0 = 0.6.
        let all = engine.compute_nf_load("amf-window").expect("analytics");
        assert!((all.mean_cpu - 0.6).abs() < 1e-9, "{}", all.mean_cpu);
        assert!((all.peak_cpu - 1.0).abs() < 1e-9);

        // A window covering only the first two samples → mean 0.4, peak 0.6.
        // A whole-series computation could not produce either number.
        let early = engine
            .compute_nf_load_in_window("amf-window", Some(ObservationWindow::new(900, 2500)))
            .expect("analytics inside the window");
        assert!((early.mean_cpu - 0.4).abs() < 1e-9, "{}", early.mean_cpu);
        assert!((early.peak_cpu - 0.6).abs() < 1e-9, "{}", early.peak_cpu);

        // Inclusive at both ends.
        let exact = engine
            .compute_nf_load_in_window("amf-window", Some(ObservationWindow::new(1000, 1000)))
            .expect("boundary sample is inside the window");
        assert!((exact.mean_cpu - 0.2).abs() < 1e-9);

        // A window with no sample in it → None, which is what makes
        // `500 UNAVAILABLE_DATA` an evidence-based answer rather than a guess.
        assert!(engine
            .compute_nf_load_in_window("amf-window", Some(ObservationWindow::new(1, 999)))
            .is_none());
        assert!(engine
            .compute_nf_load_in_window("amf-window", Some(ObservationWindow::new(3001, 4000)))
            .is_none());

        // An unknown instance is still None regardless of window.
        assert!(engine
            .compute_nf_load_in_window("nope", Some(ObservationWindow::new(0, u64::MAX)))
            .is_none());
    }

    #[test]
    fn test_mobility_prediction() {
        let mut engine = AnalyticsEngine::new();
        let supi = "imsi-001011234567890";
        // UE visits: cell 1 → 2 → 1 → 2 → 1 → 2
        for i in 0..6u64 {
            engine.ingest_ue_cell(supi, if i % 2 == 0 { 1 } else { 2 }, i * 30);
        }
        let pred = engine.predict_mobility(supi).unwrap();
        assert_eq!(pred.current_cell, 2); // last cell is 2
                                          // From cell 2, most transitions go to cell 1
        assert_eq!(pred.predicted_next_cell, Some(1));
    }

    #[test]
    fn test_anomaly_recording() {
        let mut engine = AnalyticsEngine::new();
        let supi = "imsi-001011234567890";
        engine.record_anomaly(AbnormalBehaviourRecord {
            supi: supi.into(),
            anomaly_type: "UNEXPECTED_LOCATION".into(),
            score: 75,
            detected_at: 1000,
        });
        let records = engine.get_anomalies(supi);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].score, 75);
    }

    #[test]
    fn test_samples_bounded() {
        let mut engine = AnalyticsEngine::new();
        for _ in 0..150 {
            engine.ingest_nf_load(NfLoadSample::now("SMF", "smf-01", 0.5, 0.5, 0));
        }
        assert!(engine.nf_samples["smf-01"].len() <= MAX_SAMPLES);
    }
}

#[cfg(test)]
mod inference_wiring_tests {
    use super::*;

    /// Issue #26 acceptance: the NF_LOAD analytics values are produced by the
    /// active `ml_service::InferenceModel` — a swapped model changes the
    /// computed prediction/confidence.
    struct FixedModel;
    impl crate::ml_service::InferenceModel for FixedModel {
        fn model_id(&self) -> &str {
            "fixed-test"
        }
        fn predict_series(&self, _series: &[f64]) -> Option<(f64, f64)> {
            Some((0.87, 0.42))
        }
    }

    #[test]
    fn compute_nf_load_uses_active_model() {
        let mut engine = AnalyticsEngine::new();
        for i in 0..6 {
            engine.ingest_nf_load(NfLoadSample::now(
                "AMF",
                "amf-01",
                0.1 + 0.05 * f64::from(i),
                0.0,
                0,
            ));
        }
        assert_eq!(engine.predictor_id(), "ols-linear");
        let default_result = engine.compute_nf_load("amf-01").unwrap();

        engine.set_predictor(Box::new(FixedModel));
        assert_eq!(engine.predictor_id(), "fixed-test");
        let r = engine.compute_nf_load("amf-01").unwrap();
        assert!((r.predicted_load - 0.87).abs() < 1e-9);
        assert!((r.confidence - 0.42).abs() < 1e-9);
        // mean/peak are engine statistics, unaffected by the model swap.
        assert!((r.mean_cpu - default_result.mean_cpu).abs() < 1e-9);
        assert!((r.peak_cpu - default_result.peak_cpu).abs() < 1e-9);
    }
}
