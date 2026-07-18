//! Observe-only slice-SLA assurance loop (issue #27, feature `sla-observe`).
//!
//! Non-normative prototype: slice management & assurance align with
//! TS 28.530 / TS 28.541, but the loop here is observe-ONLY — it evaluates a
//! configured per-slice SLA (admission-utilization thresholds) against the
//! live counters the NSACF already maintains (TS 29.536 admission state) and
//! emits an observable signal (structured log transitions + Prometheus-text
//! gauges). No remediation, and no listener unless `metrics_port` opts in.
//!
//! Why not `nextgcore_metrics::ai_native::SlaMonitor`: its `SlaKpi` set is
//! latency/loss/throughput-class KPIs that nothing in nsacfd can measure
//! today; mapping admission utilization onto one of them would mislabel the
//! signal. When NWDAF-fed per-slice KPIs exist, this observer is the place
//! to adopt it. See `docs/slice-sla-observe.md`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::Deserialize;

use crate::context::{nsacf_self, SliceQuota};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Typed shape of the `nsacf.sla` YAML block. Converted leniently from the
/// raw `serde_yaml::Value` the config parser captures (a malformed block
/// warns and disables the observer; it can never break quota provisioning).
#[derive(Debug, Default, Deserialize, Clone)]
pub(crate) struct SlaYaml {
    enabled: Option<bool>,
    poll_interval_secs: Option<u64>,
    /// 0 or absent = no listener (the default); >0 binds `/metrics` there.
    metrics_port: Option<u16>,
    slices: Option<Vec<SlaSliceYaml>>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub(crate) struct SlaSliceYaml {
    sst: Option<u8>,
    /// Hex string, like `slice_quotas.sd` (e.g. "000001").
    sd: Option<String>,
    max_ue_utilization_pct: Option<f64>,
    max_pdu_utilization_pct: Option<f64>,
}

/// One configured slice SLA: utilization thresholds for a target S-NSSAI.
#[derive(Debug, Clone)]
pub struct SliceSla {
    pub sst: u8,
    pub sd: Option<u32>,
    pub max_ue_utilization_pct: Option<f64>,
    pub max_pdu_utilization_pct: Option<f64>,
}

impl SliceSla {
    /// Matches [`crate::context::SNssai::to_key`] exactly.
    fn key(&self) -> String {
        match self.sd {
            Some(sd) => format!("{}-{:06x}", self.sst, sd),
            None => format!("{}", self.sst),
        }
    }
}

/// Resolved observer settings.
#[derive(Debug, Clone)]
pub struct SlaSettings {
    pub enabled: bool,
    pub poll_interval_secs: u64,
    pub metrics_port: u16,
    pub slices: Vec<SliceSla>,
}

impl Default for SlaSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            poll_interval_secs: 30,
            metrics_port: 0,
            slices: Vec::new(),
        }
    }
}

impl SlaSettings {
    pub(crate) fn from_yaml(yaml: &SlaYaml) -> Self {
        let d = Self::default();
        fn valid_threshold(v: Option<f64>, sst: u8, kpi: &str) -> Option<f64> {
            match v {
                Some(t) if t.is_finite() && t > 0.0 => Some(t),
                Some(t) => {
                    log::warn!(
                        "sla-observe: slice SLA sst={sst} {kpi} threshold {t} is invalid \
                         (must be finite and > 0); that KPI is unmonitored"
                    );
                    None
                }
                None => None,
            }
        }
        let slices = yaml
            .slices
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|s| {
                let Some(sst) = s.sst else {
                    log::warn!("sla-observe: slice SLA without sst ignored");
                    return None;
                };
                let sd = match &s.sd {
                    None => None,
                    Some(hex) => match u32::from_str_radix(hex, 16) {
                        Ok(v) => Some(v),
                        Err(e) => {
                            log::warn!(
                                "sla-observe: slice SLA sst={sst} has invalid sd {hex:?} \
                                 ({e}); entry ignored"
                            );
                            return None;
                        }
                    },
                };
                let sla = SliceSla {
                    sst,
                    sd,
                    max_ue_utilization_pct: valid_threshold(
                        s.max_ue_utilization_pct,
                        sst,
                        "max_ue_utilization_pct",
                    ),
                    max_pdu_utilization_pct: valid_threshold(
                        s.max_pdu_utilization_pct,
                        sst,
                        "max_pdu_utilization_pct",
                    ),
                };
                if sla.max_ue_utilization_pct.is_none() && sla.max_pdu_utilization_pct.is_none() {
                    log::warn!("sla-observe: slice SLA sst={sst} has no valid threshold; ignored");
                    return None;
                }
                Some(sla)
            })
            .collect::<Vec<_>>();
        // Duplicate S-NSSAI keys would share breach state and oscillate the
        // transition log every tick — first entry wins, rest are dropped.
        let mut seen = std::collections::HashSet::new();
        let slices: Vec<SliceSla> = slices
            .into_iter()
            .filter(|sla| {
                if seen.insert(sla.key()) {
                    true
                } else {
                    log::warn!(
                        "sla-observe: duplicate slice SLA for {} ignored (first entry wins)",
                        sla.key()
                    );
                    false
                }
            })
            .collect();
        Self {
            enabled: yaml.enabled.unwrap_or(d.enabled),
            poll_interval_secs: yaml
                .poll_interval_secs
                .unwrap_or(d.poll_interval_secs)
                .max(1),
            metrics_port: yaml.metrics_port.unwrap_or(d.metrics_port),
            slices,
        }
    }
}

/// Lenient conversion of the raw captured `nsacf.sla` value.
pub(crate) fn settings_from_value(raw: &serde_yaml::Value) -> Option<SlaSettings> {
    match serde_yaml::from_value::<SlaYaml>(raw.clone()) {
        Ok(yaml) => Some(SlaSettings::from_yaml(&yaml)),
        Err(e) => {
            log::warn!("sla-observe: invalid nsacf.sla block ignored: {e}");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/// Breach-state transition of one evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlaTransition {
    Breached,
    Cleared,
}

/// Outcome of evaluating one configured slice SLA against the live quota.
#[derive(Debug, Clone)]
pub struct SlaEvaluation {
    pub key: String,
    pub sst: u8,
    pub sd: Option<u32>,
    pub ue_utilization_pct: f64,
    pub pdu_utilization_pct: f64,
    /// Which KPIs are over target ("ue-utilization" / "pdu-utilization").
    pub breached_kpis: Vec<&'static str>,
    pub breached: bool,
    /// Set only when the breach state changed since the previous evaluation.
    pub transition: Option<SlaTransition>,
}

/// The observe-only evaluator: configured SLAs + per-slice breach state for
/// transition detection, feeding the gauges. Pure given a quota snapshot, so
/// tests inject state directly.
pub struct SlaObserver {
    settings: SlaSettings,
    breach_state: HashMap<String, bool>,
    gauges: Arc<SlaGauges>,
}

impl SlaObserver {
    pub fn new(settings: SlaSettings) -> Self {
        Self {
            settings,
            breach_state: HashMap::new(),
            gauges: SlaGauges::new(),
        }
    }

    pub fn gauges(&self) -> Arc<SlaGauges> {
        Arc::clone(&self.gauges)
    }

    /// Evaluate every configured slice SLA against the snapshot. Slices with
    /// no matching quota are skipped (logged at debug); quotas without a
    /// configured SLA are not evaluated (observe-only, opt-in per slice).
    pub fn evaluate(&mut self, quotas: &[SliceQuota]) -> Vec<SlaEvaluation> {
        let mut out = Vec::new();
        for sla in &self.settings.slices {
            let key = sla.key();
            let Some(quota) = quotas.iter().find(|q| q.s_nssai.to_key() == key) else {
                // Quotas can be deleted at runtime (SBI DELETE → quota_remove):
                // drop the per-slice state and gauge series so /metrics never
                // exports a stale breach, and count the implicit clear.
                let was_breached = self.breach_state.remove(&key).unwrap_or(false);
                self.gauges.remove(&key, was_breached);
                if was_breached {
                    log::info!(
                        "sla-observe: slice {key} quota removed while breached; state reset"
                    );
                } else {
                    log::debug!("sla-observe: no quota provisioned for slice {key}; skipping");
                }
                continue;
            };
            let ue_utilization_pct = quota.ue_utilization();
            let pdu_utilization_pct = quota.pdu_utilization();
            let mut breached_kpis = Vec::new();
            if sla
                .max_ue_utilization_pct
                .is_some_and(|t| ue_utilization_pct > t)
            {
                breached_kpis.push("ue-utilization");
            }
            if sla
                .max_pdu_utilization_pct
                .is_some_and(|t| pdu_utilization_pct > t)
            {
                breached_kpis.push("pdu-utilization");
            }
            let breached = !breached_kpis.is_empty();
            let prev = self
                .breach_state
                .insert(key.clone(), breached)
                .unwrap_or(false);
            let transition = match (prev, breached) {
                (false, true) => Some(SlaTransition::Breached),
                (true, false) => Some(SlaTransition::Cleared),
                _ => None,
            };
            let eval = SlaEvaluation {
                key,
                sst: sla.sst,
                sd: sla.sd,
                ue_utilization_pct,
                pdu_utilization_pct,
                breached_kpis,
                breached,
                transition,
            };
            self.gauges.record(&eval);
            out.push(eval);
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Observable signal: Prometheus-text gauges (+ the log transitions the loop
// emits). Rendering mirrors nes_energy::EnergyGauges; serving reuses the
// generic nextgcore_metrics::nes_energy::serve_metrics helper.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct SlaSample {
    sst: u8,
    sd: Option<u32>,
    ue_pct: f64,
    pdu_pct: f64,
    breached: bool,
}

#[derive(Debug, Default)]
pub struct SlaGauges {
    samples: Mutex<HashMap<String, SlaSample>>,
    breach_transitions_total: AtomicU64,
}

impl SlaGauges {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn record(&self, eval: &SlaEvaluation) {
        let mut samples = self.samples.lock().unwrap_or_else(|e| e.into_inner());
        samples.insert(
            eval.key.clone(),
            SlaSample {
                sst: eval.sst,
                sd: eval.sd,
                ue_pct: eval.ue_utilization_pct,
                pdu_pct: eval.pdu_utilization_pct,
                breached: eval.breached,
            },
        );
        if eval.transition.is_some() {
            self.breach_transitions_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Drop a slice's series (its quota disappeared); counts the implicit
    /// breach-clear transition when the slice was breached.
    fn remove(&self, key: &str, count_transition: bool) {
        self.samples
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
        if count_transition {
            self.breach_transitions_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn breach_transitions_total(&self) -> u64 {
        self.breach_transitions_total.load(Ordering::Relaxed)
    }

    /// Prometheus text exposition (0.0.4), deterministic slice order.
    pub fn render_prometheus(&self) -> String {
        let samples = {
            let guard = self.samples.lock().unwrap_or_else(|e| e.into_inner());
            let mut v: Vec<(String, SlaSample)> =
                guard.iter().map(|(k, s)| (k.clone(), s.clone())).collect();
            v.sort_by(|a, b| a.0.cmp(&b.0));
            v
        };
        let labels = |s: &SlaSample| match s.sd {
            Some(sd) => format!("sst=\"{}\",sd=\"{:06x}\"", s.sst, sd),
            None => format!("sst=\"{}\"", s.sst),
        };
        let mut out = String::new();
        out.push_str(
            "# HELP nextgcore_slice_sla_ue_utilization_pct Admitted-UE utilization percent per slice (TS 29.536 admission state).\n\
             # TYPE nextgcore_slice_sla_ue_utilization_pct gauge\n",
        );
        for (_, s) in &samples {
            out.push_str(&format!(
                "nextgcore_slice_sla_ue_utilization_pct{{{}}} {}\n",
                labels(s),
                s.ue_pct
            ));
        }
        out.push_str(
            "# HELP nextgcore_slice_sla_pdu_utilization_pct PDU-session utilization percent per slice.\n\
             # TYPE nextgcore_slice_sla_pdu_utilization_pct gauge\n",
        );
        for (_, s) in &samples {
            out.push_str(&format!(
                "nextgcore_slice_sla_pdu_utilization_pct{{{}}} {}\n",
                labels(s),
                s.pdu_pct
            ));
        }
        out.push_str(
            "# HELP nextgcore_slice_sla_breached 1 while the slice SLA is in breach, else 0 (observe-only).\n\
             # TYPE nextgcore_slice_sla_breached gauge\n",
        );
        for (_, s) in &samples {
            out.push_str(&format!(
                "nextgcore_slice_sla_breached{{{}}} {}\n",
                labels(s),
                u8::from(s.breached)
            ));
        }
        out.push_str(
            "# HELP nextgcore_slice_sla_breach_transitions_total Breach-state transitions (enter or clear) observed since start.\n\
             # TYPE nextgcore_slice_sla_breach_transitions_total counter\n",
        );
        out.push_str(&format!(
            "nextgcore_slice_sla_breach_transitions_total {}\n",
            self.breach_transitions_total()
        ));
        out
    }
}

// ---------------------------------------------------------------------------
// Task wiring
// ---------------------------------------------------------------------------

/// Spawn the observer when an `nsacf.sla` block is present, valid, and
/// enabled; logged no-op otherwise (default behavior unchanged, no listener).
pub(crate) fn spawn_if_enabled(raw: Option<serde_yaml::Value>) {
    let Some(raw) = raw else {
        log::debug!("sla-observe: no nsacf.sla block configured; observer not started");
        return;
    };
    let Some(settings) = settings_from_value(&raw) else {
        return; // already warned
    };
    if !settings.enabled {
        log::debug!("sla-observe: nsacf.sla.enabled=false; observer not started");
        return;
    }
    if settings.slices.is_empty() {
        log::warn!("sla-observe: enabled but no valid slice SLA entries; observer not started");
        return;
    }
    log::info!(
        "sla-observe: starting ({} slice SLA(s), poll={}s, metrics={})",
        settings.slices.len(),
        settings.poll_interval_secs,
        if settings.metrics_port > 0 {
            format!("0.0.0.0:{}", settings.metrics_port)
        } else {
            "disabled".to_string()
        }
    );
    tokio::spawn(run_sla_observe_loop(settings));
}

async fn run_sla_observe_loop(settings: SlaSettings) {
    let mut observer = SlaObserver::new(settings.clone());
    if settings.metrics_port > 0 {
        let addr: std::net::SocketAddr = ([0, 0, 0, 0], settings.metrics_port).into();
        let gauges = observer.gauges();
        match nextgcore_metrics::nes_energy::serve_metrics(
            addr,
            Arc::new(move || gauges.render_prometheus()),
        )
        .await
        {
            Ok((bound, _handle)) => log::info!("sla-observe: serving /metrics on {bound}"),
            Err(e) => log::warn!(
                "sla-observe: metrics bind on {addr} failed ({e}); continuing without listener"
            ),
        }
    }
    let mut ticker =
        tokio::time::interval(std::time::Duration::from_secs(settings.poll_interval_secs));
    // First tick fires immediately (tokio default) — deliberate, so the first
    // observation lands at startup.
    loop {
        ticker.tick().await;
        // Copy the quota state out under short locks; never hold either the
        // outer context guard or an interior lock across an await.
        let quotas = {
            let ctx = nsacf_self();
            let guard = ctx.read().unwrap_or_else(|e| e.into_inner());
            guard.quotas_snapshot()
        };
        for eval in observer.evaluate(&quotas) {
            match eval.transition {
                Some(SlaTransition::Breached) => log::warn!(
                    "sla-observe: SLA BREACH slice={} ue={:.1}% pdu={:.1}% kpis={:?}",
                    eval.key,
                    eval.ue_utilization_pct,
                    eval.pdu_utilization_pct,
                    eval.breached_kpis
                ),
                Some(SlaTransition::Cleared) => log::info!(
                    "sla-observe: SLA cleared slice={} ue={:.1}% pdu={:.1}%",
                    eval.key,
                    eval.ue_utilization_pct,
                    eval.pdu_utilization_pct
                ),
                None => log::debug!(
                    "sla-observe: slice={} ue={:.1}% pdu={:.1}% breached={}",
                    eval.key,
                    eval.ue_utilization_pct,
                    eval.pdu_utilization_pct,
                    eval.breached
                ),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::SNssai;
    use std::collections::HashSet;

    fn quota(sst: u8, sd: Option<u32>, max_ues: u64, admitted: usize) -> SliceQuota {
        let ues: HashSet<String> = (0..admitted)
            .map(|i| format!("imsi-00101000000{i:04}"))
            .collect();
        SliceQuota {
            id: 1,
            s_nssai: SNssai { sst, sd },
            max_ues,
            max_pdu_sessions: 100,
            max_ues_3gpp: None,
            max_ues_n3gpp: None,
            max_pdu_3gpp: None,
            max_pdu_n3gpp: None,
            ues,
            pdu_sessions: HashSet::new(),
            ue_access: HashMap::new(),
            pdu_access: HashMap::new(),
            eac_active: false,
        }
    }

    fn settings_one_slice(threshold: f64) -> SlaSettings {
        SlaSettings {
            enabled: true,
            slices: vec![SliceSla {
                sst: 1,
                sd: None,
                max_ue_utilization_pct: Some(threshold),
                max_pdu_utilization_pct: None,
            }],
            ..SlaSettings::default()
        }
    }

    #[test]
    fn settings_from_value_is_lenient_and_defaults_off() {
        // Empty block → disabled defaults.
        let s = settings_from_value(&serde_yaml::from_str("{}").unwrap()).unwrap();
        assert!(!s.enabled, "sla-observe must default to disabled");
        assert_eq!(s.poll_interval_secs, 30);
        assert_eq!(s.metrics_port, 0, "no listener by default");

        // Malformed block → None (warned), never a parse failure upstream.
        assert!(settings_from_value(&serde_yaml::Value::String("garbage".into())).is_none());

        // Invalid entries are skipped, valid ones kept; sd is hex like
        // slice_quotas.sd; poll clamps up to 1.
        let raw: serde_yaml::Value = serde_yaml::from_str(
            r#"
enabled: true
poll_interval_secs: 0
slices:
  - sst: 1
    sd: "000001"
    max_ue_utilization_pct: 80.0
  - sd: "000002"           # no sst → skipped
    max_ue_utilization_pct: 50.0
  - sst: 3
    sd: "zz"               # bad hex → skipped
    max_ue_utilization_pct: 50.0
  - sst: 4                 # no valid threshold → skipped
    max_ue_utilization_pct: -5.0
"#,
        )
        .unwrap();
        let s = settings_from_value(&raw).unwrap();
        assert!(s.enabled);
        assert_eq!(s.poll_interval_secs, 1);
        assert_eq!(s.slices.len(), 1);
        assert_eq!((s.slices[0].sst, s.slices[0].sd), (1, Some(1)));

        // Duplicate S-NSSAI entries: first wins, duplicate dropped (would
        // otherwise oscillate the shared breach state every tick).
        let raw: serde_yaml::Value = serde_yaml::from_str(
            r#"
enabled: true
slices:
  - sst: 1
    max_ue_utilization_pct: 50.0
  - sst: 1
    max_ue_utilization_pct: 90.0
"#,
        )
        .unwrap();
        let s = settings_from_value(&raw).unwrap();
        assert_eq!(s.slices.len(), 1);
        assert_eq!(s.slices[0].max_ue_utilization_pct, Some(50.0));

        // One invalid threshold + one valid → entry kept, invalid KPI None.
        let raw: serde_yaml::Value = serde_yaml::from_str(
            r#"
slices:
  - sst: 2
    max_ue_utilization_pct: 0.0
    max_pdu_utilization_pct: 80.0
"#,
        )
        .unwrap();
        let s = settings_from_value(&raw).unwrap();
        assert_eq!(s.slices.len(), 1);
        assert_eq!(s.slices[0].max_ue_utilization_pct, None);
        assert_eq!(s.slices[0].max_pdu_utilization_pct, Some(80.0));
    }

    /// Review regression: a breached slice whose quota is deleted mid-run
    /// must not export a stale breach, and a re-provisioned over-threshold
    /// quota must fire a fresh Breached transition.
    #[test]
    fn quota_removed_while_breached_resets_state() {
        let mut observer = SlaObserver::new(settings_one_slice(80.0));
        let evals = observer.evaluate(&[quota(1, None, 10, 9)]);
        assert_eq!(evals[0].transition, Some(SlaTransition::Breached));

        // Quota deleted: series dropped from /metrics, implicit clear counted.
        assert!(observer.evaluate(&[]).is_empty());
        let gauges = observer.gauges();
        assert_eq!(gauges.breach_transitions_total(), 2);
        assert!(!gauges.render_prometheus().contains("sst=\"1\""));

        // Re-provisioned already over threshold → fresh Breached transition.
        let evals = observer.evaluate(&[quota(1, None, 10, 9)]);
        assert_eq!(evals[0].transition, Some(SlaTransition::Breached));
        assert_eq!(gauges.breach_transitions_total(), 3);
    }

    /// Issue #27 acceptance: a configured SLA evaluated against the live
    /// per-slice KPI; a breach produces the observable signal (transition +
    /// gauges), and clearing is observed too.
    #[test]
    fn breach_and_clear_transitions_reach_gauges() {
        let mut observer = SlaObserver::new(settings_one_slice(80.0));

        // 9/10 admitted UEs = 90% > 80% → breach transition.
        let evals = observer.evaluate(&[quota(1, None, 10, 9)]);
        assert_eq!(evals.len(), 1);
        assert!(evals[0].breached);
        assert_eq!(evals[0].breached_kpis, vec!["ue-utilization"]);
        assert_eq!(evals[0].transition, Some(SlaTransition::Breached));
        assert!((evals[0].ue_utilization_pct - 90.0).abs() < 1e-9);

        // Still breached → no new transition.
        let evals = observer.evaluate(&[quota(1, None, 10, 9)]);
        assert!(evals[0].breached);
        assert_eq!(evals[0].transition, None);

        // Back to 5/10 = 50% → cleared transition.
        let evals = observer.evaluate(&[quota(1, None, 10, 5)]);
        assert!(!evals[0].breached);
        assert_eq!(evals[0].transition, Some(SlaTransition::Cleared));

        // Gauges reflect the latest state + both transitions.
        let gauges = observer.gauges();
        assert_eq!(gauges.breach_transitions_total(), 2);
        let text = gauges.render_prometheus();
        assert!(text.contains("nextgcore_slice_sla_ue_utilization_pct{sst=\"1\"} 50"));
        assert!(text.contains("nextgcore_slice_sla_breached{sst=\"1\"} 0"));
        assert!(text.contains("nextgcore_slice_sla_breach_transitions_total 2"));
    }

    #[test]
    fn unmatched_slices_and_sd_labels() {
        // Configured SLA with no provisioned quota → no evaluation.
        let mut observer = SlaObserver::new(settings_one_slice(80.0));
        assert!(observer.evaluate(&[quota(9, None, 10, 9)]).is_empty());

        // sd-qualified slice matches SNssai::to_key and labels carry sd.
        let mut observer = SlaObserver::new(SlaSettings {
            enabled: true,
            slices: vec![SliceSla {
                sst: 1,
                sd: Some(1),
                max_ue_utilization_pct: Some(50.0),
                max_pdu_utilization_pct: None,
            }],
            ..SlaSettings::default()
        });
        let evals = observer.evaluate(&[quota(1, Some(1), 10, 9)]);
        assert_eq!(evals.len(), 1);
        assert!(evals[0].breached);
        let text = observer.gauges().render_prometheus();
        assert!(text.contains("nextgcore_slice_sla_breached{sst=\"1\",sd=\"000001\"} 1"));
    }
}
