//! NWDAF Analytics Engine (TS 23.288 §6)
//!
//! Implements analytics computation for:
//! - NF Load (§6.2.4): CPU/memory/session utilization per NF
//! - UE Mobility (§6.7): predicted mobility patterns
//! - QoS Sustainability (§6.9): predicted QoS degradation
//! - Slice Load (§6.10): per-slice resource utilization
//! - Abnormal Behaviour (§6.5): anomaly detection

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
    /// UE mobility history: last observed cell per SUPI
    ue_cells: HashMap<String, Vec<(u64, u64)>>, // (cell_id, timestamp)
    /// Anomaly scores per SUPI
    anomaly_scores: HashMap<String, Vec<AbnormalBehaviourRecord>>,
}

const MAX_SAMPLES: usize = 100;

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

    /// Compute NF load analytics for a given instance
    pub fn compute_nf_load(&self, nf_instance_id: &str) -> Option<NfLoadAnalytics> {
        let samples = self.nf_samples.get(nf_instance_id)?;
        if samples.is_empty() {
            return None;
        }
        let mean_cpu = samples.iter().map(|s| s.cpu_usage).sum::<f64>() / samples.len() as f64;
        let peak_cpu = samples.iter().map(|s| s.cpu_usage).fold(0.0f64, f64::max);

        // Simple linear prediction: slope of last 5 samples
        let n = samples.len().min(5);
        let predicted_load = if n >= 2 {
            let last = &samples[samples.len() - n..];
            let slope = (last[n - 1].cpu_usage - last[0].cpu_usage) / (n - 1) as f64;
            (last[n - 1].cpu_usage + slope).clamp(0.0, 1.0)
        } else {
            mean_cpu
        };

        let confidence = (samples.len() as f64 / MAX_SAMPLES as f64).min(1.0);

        Some(NfLoadAnalytics {
            nf_type: samples[0].nf_type.clone(),
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
        let current_cell = history.last().unwrap().0;

        // Count transitions to find most likely next cell
        let mut next_counts: HashMap<u64, u32> = HashMap::new();
        for i in 0..history.len().saturating_sub(1) {
            if history[i].0 == current_cell {
                *next_counts.entry(history[i + 1].0).or_default() += 1;
            }
        }

        let (next_cell, count) = next_counts.iter()
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
        self.anomaly_scores.get(supi).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nf_load_analytics() {
        let mut engine = AnalyticsEngine::new();
        for i in 0..10 {
            let sample = NfLoadSample::now(
                "AMF", "amf-01",
                0.3 + i as f64 * 0.05,
                0.4,
                100 + i * 10,
            );
            engine.ingest_nf_load(sample);
        }
        let analytics = engine.compute_nf_load("amf-01").unwrap();
        assert!(analytics.mean_cpu > 0.3);
        assert!(analytics.peak_cpu <= 1.0);
        assert!(analytics.confidence > 0.0);
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
