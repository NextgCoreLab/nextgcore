//! Intent-driven closed-loop policy controller (issue #24, feature `intent-loop`).
//!
//! Non-normative 6G / autonomous-networks research prototype: no frozen
//! Rel-20 Stage-3 exists for intent-driven management; the closest normative
//! anchor is the Rel-17/18 intent work (TS 28.312). This module connects the
//! pre-existing scaffolding into ONE running loop for ONE declared outcome —
//! "keep slice X latency below N ms":
//!
//! - intent → policy: [`crate::intent_policy::IntentPolicyTranslator`]
//! - monitor: live `Nnwdaf_AnalyticsInfo` GET (TS 29.520) via NRF discovery
//! - decide: [`crate::intent_policy::SlaPolicyAdapter`], plus
//!   [`crate::context::AnalyticsPolicyEngine`] for observability
//! - act: re-issue an updated SM policy decision through
//!   [`crate::sm_policy_build::build_sm_policy_decision`]
//!
//! Latency-observation caveat: today's nwdafd serves real data only for
//! `NF_LOAD` (`QOS_SUSTAINABILITY` is a recognised token but always answers
//! 204 no-data), so the loop derives its observed latency from NF load
//! through a documented synthetic proxy (`nf_load_latency_ms_per_pct`).
//! See `docs/intent-driven-policy-loop.md`.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::app::IntentYaml;
use crate::context::{AnalyticsPolicyEngine, AnalyticsState, PolicyAdjustment};
use crate::intent_policy::{
    GeneratedPolicy, IntentPolicyTranslator, PolicyConstraint, PolicyIntent, PolicyIntentType,
    SlaFeedback, SlaPolicyAdapter,
};
use crate::nudr_handler::SessionData;
use crate::sm_policy_build::{build_sm_policy_decision, SmPolicyDecisionParts};

/// Resolved intent-loop configuration (YAML overlaid onto defaults).
#[derive(Debug, Clone)]
pub struct IntentSettings {
    pub enabled: bool,
    /// Target slice S-NSSAI SST.
    pub sst: u8,
    /// Target slice S-NSSAI SD (hex string; informational in the spike).
    pub sd: Option<String>,
    /// The declared outcome: keep slice latency below this many milliseconds.
    pub max_latency_ms: f64,
    pub poll_interval_secs: u64,
    /// [`SlaPolicyAdapter`] aggressiveness (clamped to 0.0..=1.0).
    pub aggressiveness: f64,
    /// Synthetic NF_LOAD→latency proxy slope: observed latency is modelled
    /// as `load_pct * nf_load_latency_ms_per_pct` ms (see the design doc).
    pub nf_load_latency_ms_per_pct: f64,
}

impl Default for IntentSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            sst: 1,
            sd: None,
            max_latency_ms: 20.0,
            poll_interval_secs: 30,
            aggressiveness: 0.5,
            nf_load_latency_ms_per_pct: 0.5,
        }
    }
}

impl IntentSettings {
    /// Overlay a parsed `pcf.intent` YAML block onto the defaults, clamping
    /// nonsensical values instead of failing startup.
    pub(crate) fn from_yaml(yaml: &IntentYaml) -> Self {
        let d = Self::default();
        Self {
            enabled: yaml.enabled.unwrap_or(d.enabled),
            sst: yaml.sst.unwrap_or(d.sst),
            sd: yaml.sd.clone(),
            max_latency_ms: yaml
                .max_latency_ms
                .filter(|v| *v > 0.0)
                .unwrap_or(d.max_latency_ms),
            poll_interval_secs: yaml
                .poll_interval_secs
                .unwrap_or(d.poll_interval_secs)
                .max(1),
            aggressiveness: yaml
                .aggressiveness
                .filter(|v| v.is_finite())
                .unwrap_or(d.aggressiveness)
                .clamp(0.0, 1.0),
            nf_load_latency_ms_per_pct: yaml
                .nf_load_latency_ms_per_pct
                .filter(|v| *v > 0.0)
                .unwrap_or(d.nf_load_latency_ms_per_pct),
        }
    }

    /// Express the declared outcome as the existing [`PolicyIntent`] shape
    /// (issue #24: reuse `PolicyIntentType::MinLatency` +
    /// `PolicyConstraint::MaxLatencyMs`; no new intent type).
    pub fn to_policy_intent(&self) -> PolicyIntent {
        PolicyIntent {
            id: 1,
            intent_type: PolicyIntentType::MinLatency,
            target_sst: Some(self.sst),
            priority: 1,
            constraints: vec![PolicyConstraint::MaxLatencyMs(self.max_latency_ms)],
        }
    }
}

/// One monitor reading, derived from live NWDAF analytics.
#[derive(Debug, Clone)]
pub struct Observation {
    /// Observed (proxy) latency for the slice, in milliseconds.
    pub latency_ms: f64,
    /// NF load percent (0-100) the proxy latency was derived from.
    pub load_pct: f64,
}

/// Derive an [`Observation`] from an `NF_LOAD` `AnalyticsData` body
/// (TS 29.520 `nfLoadLevelInfos`). Uses the worst (max) per-instance
/// `nfLoadLevelAverage`, then applies the synthetic latency proxy slope.
pub fn observation_from_nf_load(body: &serde_json::Value, ms_per_pct: f64) -> Option<Observation> {
    let infos = body.get("nfLoadLevelInfos")?.as_array()?;
    let worst = infos
        .iter()
        .filter_map(|i| i.get("nfLoadLevelAverage").and_then(|v| v.as_f64()))
        .fold(f64::NAN, f64::max);
    if !worst.is_finite() {
        return None;
    }
    Some(Observation {
        latency_ms: worst * ms_per_pct,
        load_pct: worst,
    })
}

/// What one loop iteration decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IterationAction {
    /// No analytics available this round (no NRF/NWDAF, or no data yet).
    NoData,
    /// Observed latency within target; policy untouched, nothing re-issued.
    WithinTarget,
    /// Latency violated: [`SlaPolicyAdapter`] tightened the policy and an
    /// updated SM policy decision was rebuilt (produced + logged; delivery
    /// to an SMF is out of the spike's scope).
    Adapted {
        drx_before_ms: u32,
        drx_after_ms: u32,
    },
    /// Latency still violated but the adapter has no headroom left (DRX at
    /// its 5 ms floor, or aggressiveness 0): policy unchanged, nothing
    /// rebuilt.
    NoHeadroom { drx_ms: u32 },
}

/// Outcome of one monitor→decide→act iteration. (No `Debug` derive:
/// `SmPolicyDecisionParts` deliberately doesn't implement it.)
pub struct IterationOutcome {
    pub observed_ms: Option<f64>,
    pub target_ms: f64,
    pub action: IterationAction,
    /// The rebuilt decision (only on [`IterationAction::Adapted`]).
    pub decision: Option<SmPolicyDecisionParts>,
    /// What the broader analytics engine would do with this reading
    /// (observability only in the spike; not applied to the decision).
    pub analytics_adjustment: Option<PolicyAdjustment>,
}

/// The closed-loop controller state: declared intent, translated baseline
/// policy, the currently active (possibly adapted) policy, and the two
/// pre-existing decision engines.
pub struct IntentController {
    settings: IntentSettings,
    intent: PolicyIntent,
    baseline: GeneratedPolicy,
    current: GeneratedPolicy,
    adapter: SlaPolicyAdapter,
    engine: AnalyticsPolicyEngine,
    analytics: AnalyticsState,
    iterations: u64,
}

impl IntentController {
    pub fn new(settings: IntentSettings) -> Self {
        let intent = settings.to_policy_intent();
        let mut translator = IntentPolicyTranslator::new();
        let baseline = translator.translate(&intent);
        let current = baseline.clone();
        let adapter = SlaPolicyAdapter::new(settings.aggressiveness);
        Self {
            settings,
            intent,
            baseline,
            current,
            adapter,
            engine: AnalyticsPolicyEngine::new(),
            analytics: AnalyticsState::default(),
            iterations: 0,
        }
    }

    /// The intent-derived baseline policy (before any SLA adaptation).
    pub fn baseline(&self) -> &GeneratedPolicy {
        &self.baseline
    }

    /// The currently active policy (baseline, possibly tightened by `adapt`).
    pub fn current(&self) -> &GeneratedPolicy {
        &self.current
    }

    /// The [`AnalyticsState`] populated from the most recent NWDAF reading.
    pub fn analytics(&self) -> &AnalyticsState {
        &self.analytics
    }

    pub fn iterations(&self) -> u64 {
        self.iterations
    }

    /// One monitor→decide→act iteration, pure given the observation so tests
    /// can inject readings (the async NWDAF poll lives in [`observe_nwdaf`]).
    pub fn drive_iteration(&mut self, observation: Option<Observation>) -> IterationOutcome {
        self.iterations += 1;
        let target_ms = self.settings.max_latency_ms;
        let Some(obs) = observation else {
            return IterationOutcome {
                observed_ms: None,
                target_ms,
                action: IterationAction::NoData,
                decision: None,
                analytics_adjustment: None,
            };
        };

        // Populate the (previously never-populated) AnalyticsState from the
        // live reading: congestion = load fraction, sustainability = its
        // complement — proxy semantics documented in the design note.
        let load_fraction = (obs.load_pct / 100.0).clamp(0.0, 1.0) as f32;
        self.analytics.predicted_congestion = load_fraction;
        self.analytics.qos_sustainability = 1.0 - load_fraction;
        self.analytics.last_query_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Observability: what the broader analytics engine would do. Its
        // congestion reaction (throttle) can oppose a min-latency intent, so
        // the spike logs it without applying it.
        let current_5qi = u8::try_from(self.current.five_qi).unwrap_or(9);
        let analytics_adjustment =
            self.engine
                .evaluate(&self.analytics, current_5qi, self.current.arp_priority);

        // Feed ONLY the declared outcome (latency) into the SLA adapter; the
        // throughput/loss targets are set trivially-satisfied.
        let feedback = SlaFeedback {
            latency_ms: obs.latency_ms,
            target_latency_ms: target_ms,
            throughput_mbps: 0.0,
            target_throughput_mbps: 0.0,
            packet_loss_pct: 0.0,
            target_packet_loss_pct: 100.0,
        };
        if !feedback.latency_violated() {
            return IterationOutcome {
                observed_ms: Some(obs.latency_ms),
                target_ms,
                action: IterationAction::WithinTarget,
                decision: None,
                analytics_adjustment,
            };
        }

        let drx_before_ms = self.current.drx_cycle_ms;
        self.current = self.adapter.adapt(&self.current, &feedback);
        // No-op detection: with only the latency target able to fire, DRX is
        // the sole field `adapt` can change; when it didn't move (5 ms floor,
        // or aggressiveness 0) don't claim an adaptation or rebuild an
        // identical decision.
        if self.current.drx_cycle_ms == drx_before_ms {
            return IterationOutcome {
                observed_ms: Some(obs.latency_ms),
                target_ms,
                action: IterationAction::NoHeadroom {
                    drx_ms: drx_before_ms,
                },
                decision: None,
                analytics_adjustment,
            };
        }
        let decision = decision_from_policy(&self.current, &format!("intent-{}", self.intent.id));
        IterationOutcome {
            observed_ms: Some(obs.latency_ms),
            target_ms,
            action: IterationAction::Adapted {
                drx_before_ms,
                drx_after_ms: self.current.drx_cycle_ms,
            },
            decision: Some(decision),
            analytics_adjustment,
        }
    }
}

/// Map a [`GeneratedPolicy`] onto the existing SM policy decision builder
/// (5QI/ARP direct, MBR kbps → session AMBR bps; DRX and energy mode have no
/// TS 29.512 SmPolicyDecision representation and stay loop-internal).
pub fn decision_from_policy(policy: &GeneratedPolicy, sm_policy_id: &str) -> SmPolicyDecisionParts {
    let session_data = SessionData {
        qos_index: u8::try_from(policy.five_qi).unwrap_or(9),
        arp_priority_level: policy.arp_priority,
        arp_preempt_cap: false,
        arp_preempt_vuln: true,
        ambr_uplink: policy.mbr_ul_kbps.saturating_mul(1000),
        ambr_downlink: policy.mbr_dl_kbps.saturating_mul(1000),
        pcc_rules: vec![],
    };
    build_sm_policy_decision(sm_policy_id, &session_data)
}

/// Spawn the controller task when a `pcf.intent` block is present and
/// enabled; logged no-op otherwise (default build/behavior unchanged).
pub(crate) fn spawn_if_enabled(settings: Option<IntentSettings>) {
    let Some(settings) = settings else {
        log::debug!("intent-loop: no pcf.intent block configured; controller not started");
        return;
    };
    if !settings.enabled {
        log::debug!("intent-loop: pcf.intent.enabled=false; controller not started");
        return;
    }
    log::info!(
        "intent-loop: starting (slice sst={} sd={} outcome: latency<{:.1}ms poll={}s aggressiveness={:.2})",
        settings.sst,
        settings.sd.as_deref().unwrap_or("-"),
        settings.max_latency_ms,
        settings.poll_interval_secs,
        settings.aggressiveness
    );
    tokio::spawn(run_intent_loop(settings));
}

async fn run_intent_loop(settings: IntentSettings) {
    let mut controller = IntentController::new(settings.clone());
    log::info!(
        "intent-loop: intent translated → baseline policy 5qi={} arp={} drx={}ms",
        controller.current().five_qi,
        controller.current().arp_priority,
        controller.current().drx_cycle_ms
    );
    let mut ticker =
        tokio::time::interval(std::time::Duration::from_secs(settings.poll_interval_secs));
    // The first tick fires immediately (tokio interval default) — deliberate,
    // so the loop emits its first monitor line at startup.
    loop {
        ticker.tick().await;
        let observation = observe_nwdaf(&settings).await;
        let outcome = controller.drive_iteration(observation);
        log_outcome(&settings, &outcome);
    }
}

/// Poll live NWDAF analytics: discover an NWDAF via the NRF, ask for the
/// slice's QoS-sustainability analytic first (the analytic the intent
/// semantically wants, TS 23.288 §6.9), then fall back to the one analytic
/// today's nwdafd actually serves (`NF_LOAD`) and derive the latency proxy.
async fn observe_nwdaf(settings: &IntentSettings) -> Option<Observation> {
    let ep = match crate::sbi_path::pcf_discover_endpoint("NWDAF", "nnwdaf-analyticsinfo").await {
        Ok(Some(ep)) => ep,
        Ok(None) => {
            log::debug!("intent-loop: no NWDAF discovered (no NRF configured or no instance)");
            return None;
        }
        Err(e) => {
            log::debug!("intent-loop: NWDAF discovery failed: {e}");
            return None;
        }
    };
    let client = crate::sbi_path::client_for(&ep, nextgcore_sbi::types::NfType::Nwdaf);

    match query_analytics(&client, "QOS_SUSTAINABILITY").await {
        Some((200, Some(body))) => {
            // Neither this build nor TS 29.520 QosSustainabilityInfo carries a
            // direct latency member; log and fall through to the NF_LOAD proxy.
            log::debug!("intent-loop: QOS_SUSTAINABILITY returned data: {body}");
        }
        Some((status, _)) => {
            log::debug!("intent-loop: QOS_SUSTAINABILITY status={status} (no data)");
        }
        None => return None, // transport error; NF_LOAD would fail identically
    }

    match query_analytics(&client, "NF_LOAD").await {
        Some((200, Some(body))) => {
            observation_from_nf_load(&body, settings.nf_load_latency_ms_per_pct)
        }
        Some((status, _)) => {
            log::debug!("intent-loop: NF_LOAD status={status} (no data)");
            None
        }
        None => None,
    }
}

/// GET `/nnwdaf-analyticsinfo/v1/analytics?event-id=…`; returns the HTTP
/// status and parsed JSON body (204 no-data arrives as `(204, None)`).
async fn query_analytics(
    client: &nextgcore_sbi::client::SbiClient,
    event_id: &str,
) -> Option<(u16, Option<serde_json::Value>)> {
    let request = nextgcore_sbi::message::SbiRequest::get("/nnwdaf-analyticsinfo/v1/analytics")
        .with_param("event-id", event_id);
    match client.send_request(request).await {
        Ok(resp) => {
            let body = resp
                .http
                .content
                .as_deref()
                .and_then(|c| serde_json::from_str(c).ok());
            Some((resp.status, body))
        }
        Err(e) => {
            log::debug!("intent-loop: analytics GET event-id={event_id} failed: {e}");
            None
        }
    }
}

fn log_outcome(settings: &IntentSettings, outcome: &IterationOutcome) {
    let observed = match outcome.observed_ms {
        Some(ms) => format!("{ms:.1}ms(nf-load-proxy)"),
        None => "unavailable".to_string(),
    };
    let action = match &outcome.action {
        IterationAction::NoData => "none(no-analytics)".to_string(),
        IterationAction::WithinTarget => "none(within-target)".to_string(),
        IterationAction::Adapted {
            drx_before_ms,
            drx_after_ms,
        } => format!(
            "adapt(drx {drx_before_ms}ms→{drx_after_ms}ms; rebuilt SmPolicyDecision intent-1)"
        ),
        IterationAction::NoHeadroom { drx_ms } => {
            format!("none(no-headroom; drx at {drx_ms}ms floor, latency still violated)")
        }
    };
    let engine = match &outcome.analytics_adjustment {
        Some(adj) => format!(" engine={:?}/{:?}", adj.reason, adj.action),
        None => String::new(),
    };
    log::info!(
        "intent-loop: monitor → observed={observed} target={:.1}ms action={action} (slice sst={}{engine})",
        outcome.target_ms,
        settings.sst
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::AdjustmentReason;

    fn enabled_settings(max_latency_ms: f64) -> IntentSettings {
        IntentSettings {
            enabled: true,
            max_latency_ms,
            ..IntentSettings::default()
        }
    }

    #[test]
    fn settings_defaults_and_yaml_overlay() {
        let empty = IntentYaml::default();
        let s = IntentSettings::from_yaml(&empty);
        assert!(!s.enabled, "intent loop must default to disabled");
        assert_eq!(s.sst, 1);
        assert!((s.max_latency_ms - 20.0).abs() < f64::EPSILON);

        let yaml = IntentYaml {
            enabled: Some(true),
            sst: Some(2),
            sd: Some("000001".to_string()),
            max_latency_ms: Some(10.0),
            poll_interval_secs: Some(0),            // clamped up to 1
            aggressiveness: Some(7.0),              // clamped to 1.0
            nf_load_latency_ms_per_pct: Some(-3.0), // invalid → default
        };
        let s = IntentSettings::from_yaml(&yaml);
        assert!(s.enabled);
        assert_eq!(s.sst, 2);
        assert_eq!(s.sd.as_deref(), Some("000001"));
        assert!((s.max_latency_ms - 10.0).abs() < f64::EPSILON);
        assert_eq!(s.poll_interval_secs, 1);
        assert!((s.aggressiveness - 1.0).abs() < f64::EPSILON);
        assert!((s.nf_load_latency_ms_per_pct - 0.5).abs() < f64::EPSILON);

        // NaN must not escape the clamp (it would propagate through
        // SlaPolicyAdapter and behave as maximum aggressiveness).
        let yaml = IntentYaml {
            aggressiveness: Some(f64::NAN),
            ..IntentYaml::default()
        };
        let s = IntentSettings::from_yaml(&yaml);
        assert!((s.aggressiveness - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn to_policy_intent_maps_min_latency() {
        let s = enabled_settings(12.5);
        let intent = s.to_policy_intent();
        assert_eq!(intent.intent_type, PolicyIntentType::MinLatency);
        assert_eq!(intent.target_sst, Some(1));
        assert!(matches!(
            intent.constraints.as_slice(),
            [PolicyConstraint::MaxLatencyMs(ms)] if (*ms - 12.5).abs() < f64::EPSILON
        ));
    }

    #[test]
    fn observation_from_nf_load_uses_worst_instance_and_slope() {
        let body = serde_json::json!({
            "nfLoadLevelInfos": [
                { "nfType": "AMF", "nfInstanceId": "amf-01", "nfLoadLevelAverage": 35, "confidence": 90 },
                { "nfType": "SMF", "nfInstanceId": "smf-01", "nfLoadLevelAverage": 60, "confidence": 80 }
            ],
            "timeStampGen": "2026-07-17T00:00:00Z"
        });
        let obs = observation_from_nf_load(&body, 0.5).expect("observation");
        assert!((obs.load_pct - 60.0).abs() < f64::EPSILON);
        assert!((obs.latency_ms - 30.0).abs() < f64::EPSILON);
    }

    #[test]
    fn observation_from_nf_load_empty_or_missing_is_none() {
        assert!(
            observation_from_nf_load(&serde_json::json!({ "nfLoadLevelInfos": [] }), 0.5).is_none()
        );
        assert!(observation_from_nf_load(&serde_json::json!({}), 0.5).is_none());
    }

    /// Issue #24 acceptance test: one loop iteration end-to-end. A declarative
    /// intent (`max_latency_ms = 10`) plus an injected analytics reading above
    /// target produces an adjusted SmPolicyDecision (reduced DRX, intent 5QI/
    /// ARP in the re-issued decision); a reading within target produces no
    /// adjustment and no re-issue.
    #[test]
    fn closed_loop_iteration_end_to_end() {
        let mut controller = IntentController::new(enabled_settings(10.0));
        // MinLatency translate: 5QI=1, ARP=2, DRX=10ms baseline.
        assert_eq!(controller.baseline().five_qi, 1);
        assert_eq!(controller.baseline().arp_priority, 2);
        let baseline_drx = controller.baseline().drx_cycle_ms;

        // Reading above target (25ms > 10ms) → adapted + re-issued decision.
        let outcome = controller.drive_iteration(Some(Observation {
            latency_ms: 25.0,
            load_pct: 50.0,
        }));
        let IterationAction::Adapted {
            drx_before_ms,
            drx_after_ms,
        } = outcome.action
        else {
            panic!("expected Adapted, got {:?}", outcome.action);
        };
        assert_eq!(drx_before_ms, baseline_drx);
        assert!(
            drx_after_ms < baseline_drx,
            "latency violation must reduce DRX ({drx_after_ms} !< {baseline_drx})"
        );
        assert_eq!(controller.current().drx_cycle_ms, drx_after_ms);
        let decision = outcome.decision.expect("adjusted decision re-issued");
        let auth_def_qos = &decision.sess_rules["SessRule-intent-1"]["authDefQos"];
        assert_eq!(auth_def_qos["5qi"], 1, "decision carries the intent 5QI");
        assert_eq!(auth_def_qos["arp"]["priorityLevel"], 2);

        // Second consecutive violation: DRX already at the adapter's 5ms
        // floor → steady-state no-headroom, no false "Adapted", no identical
        // decision rebuild.
        let outcome = controller.drive_iteration(Some(Observation {
            latency_ms: 25.0,
            load_pct: 50.0,
        }));
        assert_eq!(outcome.action, IterationAction::NoHeadroom { drx_ms: 5 });
        assert!(outcome.decision.is_none());

        // Reading within target (5ms < 10ms) → no adjustment, no re-issue.
        let tightened_drx = controller.current().drx_cycle_ms;
        let outcome = controller.drive_iteration(Some(Observation {
            latency_ms: 5.0,
            load_pct: 10.0,
        }));
        assert_eq!(outcome.action, IterationAction::WithinTarget);
        assert!(outcome.decision.is_none());
        assert_eq!(controller.current().drx_cycle_ms, tightened_drx);

        // No analytics at all → explicit no-data action, no re-issue.
        let outcome = controller.drive_iteration(None);
        assert_eq!(outcome.action, IterationAction::NoData);
        assert!(outcome.decision.is_none());
        assert_eq!(controller.iterations(), 4);
    }

    #[test]
    fn analytics_state_populated_and_engine_observability() {
        let mut controller = IntentController::new(enabled_settings(10.0));
        // 80% load → congestion 0.8 (≥ engine threshold 0.75) → the analytics
        // engine reports a CongestionAvoidance adjustment (observability only).
        let outcome = controller.drive_iteration(Some(Observation {
            latency_ms: 40.0,
            load_pct: 80.0,
        }));
        assert!((controller.analytics().predicted_congestion - 0.8).abs() < 1e-6);
        assert!((controller.analytics().qos_sustainability - 0.2).abs() < 1e-6);
        assert!(controller.analytics().last_query_epoch > 0);
        let adj = outcome.analytics_adjustment.expect("engine adjustment");
        assert_eq!(adj.reason, AdjustmentReason::CongestionAvoidance);
        // The engine's throttle reaction is NOT applied to the decision: the
        // re-issued decision still carries the intent policy 5QI/ARP.
        let decision = outcome.decision.expect("latency violation re-issues");
        assert_eq!(
            decision.sess_rules["SessRule-intent-1"]["authDefQos"]["5qi"],
            1
        );
    }
}
