//! NWDAF Event-Notification Dispatcher (TS 29.520 Nnwdaf_EventsSubscription)
//!
//! When an analytics event triggers (periodic interval or threshold breach),
//! the NWDAF SHALL POST an `Nnwdaf_EventsSubscription_Notify` carrying an
//! `NnwdafEventsSubscriptionNotification` to the consumer's `notificationURI`.
//! The schema lives in `components.schemas.NnwdafEventsSubscriptionNotification`
//! of `TS29520_Nnwdaf_EventsSubscription.yaml`.
//!
//! # Notify body shape
//!
//! ```json
//! {
//!   "subscriptionId": "<sub id>",
//!   "notifCorrId":    "<from subscription, optional>",
//!   "eventNotifications": [
//!     {
//!       "event":  "NF_LOAD",
//!       "start":  "<RFC-3339>",
//!       "expiry": "<RFC-3339>",
//!       "nfLoadLevelInfos": [ { ... } ]   // per-event *Infos array
//!     }
//!   ]
//! }
//! ```
//!
//! # Periodicity guard
//!
//! The dispatcher checks `subscription.is_due_for_notification()` before
//! POSTing.  After a successful delivery it calls
//! `NwdafContext::update_subscription_last_notification()` so that
//! `repetition_period_secs` is honoured on the next cycle.
//!
//! # Threshold conditions (nwafd-07)
//!
//! When an event's `notificationMethod` is `THRESHOLD`, the dispatcher evaluates
//! the computed analytic against the subscription's `load_level_threshold` and
//! `matchingDir` ([`threshold_crossed`]) and only includes that event in the
//! notification when the threshold is crossed. The previous level is held in the
//! context per `(subscription, event)` so `ASCENDING`/`DESCENDING`/`CROSSED` are
//! edge-triggered rather than re-firing every cycle. `PERIODIC` events are
//! unaffected and always reported on their period.

use crate::analytics::AnalyticsEngine;
use crate::context::{
    AnalyticsId, AnalyticsSubscription, EventSubscription, MatchingDirection, NotificationMethod,
    NwdafContext,
};
use nextgcore_sbi::client::{SbiClient, SbiClientConfig};
use serde_json::{json, Map, Value};
use std::sync::{Arc, RwLock};
use std::time::Duration;

// ── connection timeouts (mirror the AMF pattern: namf_server.rs:693-698) ──
const NOTIFY_CONNECT_TIMEOUT_SECS: u64 = 5;
const NOTIFY_REQUEST_TIMEOUT_SECS: u64 = 10;

// ── background task default tick period ──
/// How often (seconds) the background dispatcher tick runs.
/// Each tick: run analytics + check subscriptions + POST any due notifications.
pub const DEFAULT_DISPATCH_INTERVAL_SECS: u64 = 30;

// ─────────────────────────────────────────────────────────────────────────────
// URI parsing (mirrors namf_server.rs:701-730)
// ─────────────────────────────────────────────────────────────────────────────

/// Parse an absolute `http[s]://host[:port][/path]` URI into `(host, port, path)`.
/// Returns `None` for unsupported schemes or malformed host fields.
pub(crate) fn parse_notify_uri(uri: &str) -> Option<(String, u16, String)> {
    let (default_port, rest) = if let Some(r) = uri.strip_prefix("https://") {
        (443u16, r)
    } else if let Some(r) = uri.strip_prefix("http://") {
        (80u16, r)
    } else {
        return None;
    };

    let (host_port, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{p}")),
        None => (rest, "/".to_string()),
    };

    if host_port.is_empty() {
        return None;
    }

    match host_port.rsplit_once(':') {
        Some((host, port_str)) => {
            if host.is_empty() {
                return None;
            }
            let port: u16 = port_str.parse().ok()?;
            Some((host.to_string(), port, path))
        }
        None => Some((host_port.to_string(), default_port, path)),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Client factory (mirrors namf_server.rs:693-698)
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn notify_client(host: &str, port: u16) -> SbiClient {
    let config = SbiClientConfig::new(host, port)
        .with_connect_timeout(Duration::from_secs(NOTIFY_CONNECT_TIMEOUT_SECS))
        .with_request_timeout(Duration::from_secs(NOTIFY_REQUEST_TIMEOUT_SECS));
    SbiClient::new(config)
}

// ─────────────────────────────────────────────────────────────────────────────
// nwafd-07: THRESHOLD evaluation
// ─────────────────────────────────────────────────────────────────────────────

/// TS 29.520 THRESHOLD predicate. Returns `true` when `current` satisfies the
/// crossing condition for `threshold` under `dir`, given the previously observed
/// level `previous` (`None` on the first observation).
///
/// - `ASCENDING`: fires on the rising edge to/above the threshold.
/// - `DESCENDING`: fires on the falling edge to/below the threshold.
/// - `CROSSED`: fires whenever the value moves across the threshold in either
///   direction relative to `previous`.
pub fn threshold_crossed(
    previous: Option<f64>,
    current: f64,
    threshold: f64,
    dir: MatchingDirection,
) -> bool {
    match dir {
        MatchingDirection::Ascending => {
            current >= threshold && previous.is_none_or(|p| p < threshold)
        }
        MatchingDirection::Descending => {
            current <= threshold && previous.is_none_or(|p| p > threshold)
        }
        MatchingDirection::Crossed => match previous {
            Some(p) => (p < threshold) != (current < threshold),
            None => current >= threshold,
        },
    }
}

/// Extract the scalar level (0–100) used for THRESHOLD evaluation from a
/// previously-computed per-event `*Infos` array. Only `NF_LOAD` exposes such a
/// scalar today (`nfLoadLevelAverage`); other events return `None`, so a
/// THRESHOLD subscription on them cannot be evaluated and is suppressed.
fn extract_level(event: AnalyticsId, infos: &Value) -> Option<f64> {
    match event {
        AnalyticsId::NfLoad => infos
            .as_array()?
            .first()?
            .get("nfLoadLevelAverage")?
            .as_f64(),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Analytics runner
// ─────────────────────────────────────────────────────────────────────────────

/// Per-event analytics filter (TS 29.520 `EventFilter` /
/// `EventSubscription.nfInstanceIds`/`nfTypes`). Empty vectors = no filter.
#[derive(Debug, Clone, Default)]
pub struct EventInfoFilter {
    /// Restrict to these NF instance IDs (`nfInstanceIds`), when non-empty.
    pub nf_instance_ids: Vec<String>,
    /// Restrict to these NF types (`nfTypes`), when non-empty.
    pub nf_types: Vec<String>,
}

impl EventInfoFilter {
    /// No filtering: report every instance with data.
    pub fn none() -> Self {
        Self::default()
    }

    /// Build the filter from a subscription's per-event
    /// `nfInstanceIds`/`nfTypes` (TS 29.520 `EventSubscription`).
    pub fn from_event_subscription(e: &EventSubscription) -> Self {
        Self {
            nf_instance_ids: e.nf_instance_ids.clone(),
            nf_types: e.nf_types.clone(),
        }
    }

    fn matches(&self, nf_instance_id: &str, nf_type: &str) -> bool {
        (self.nf_instance_ids.is_empty()
            || self.nf_instance_ids.iter().any(|i| i == nf_instance_id))
            && (self.nf_types.is_empty() || self.nf_types.iter().any(|t| t == nf_type))
    }
}

/// Serialize the cached NRF `nfStatus` token into the TS 29.520 `NfStatus`
/// object (percentage of time per state, `SamplingRatio` 1..=100). We track
/// only the latest NRF-reported state, so it is reported as 100 %.
fn nf_status_json(status: &str) -> Value {
    match status {
        "REGISTERED" => json!({ "statusRegistered": 100 }),
        _ => json!({ "statusUnregistered": 100 }),
    }
}

/// Compute the per-event `*Infos` **array** (the value stored under
/// `event.infos_key()`) for a single analytics event.
///
/// Shared by `Nnwdaf_AnalyticsInfo` (GET → `AnalyticsData`) and the
/// `Nnwdaf_EventsSubscription_Notify` dispatcher so both stay wire-aligned on
/// TS 29.520. Only NF_LOAD has a live analytics path today (linear
/// regression); which events are live is declared by
/// `context::SUPPORTED_EVENTS` (G2-3) and both callers gate on it before
/// emitting anything for an event.
///
/// G2-1: NF_LOAD is computed from **NRF-sourced samples only** (TS 23.288
/// §6.5 Table 6.5.2-1: the NF load data source is the NRF). One
/// `NfLoadLevelInformation` is emitted per NF instance with samples, honoring
/// `filter`. No samples → empty array — never fabricated data. The former
/// hard-coded synthetic self-sample placeholder is gone.
///
/// Emission shape per TS 29.520 `NfLoadLevelInformation`
/// (`TS29520_Nnwdaf_EventsSubscription.yaml` `NfLoadLevelInformation`):
/// `nfType`+`nfInstanceId` mandatory; `nfStatus` is the **object** form
/// (`statusRegistered`/`statusUnregistered` SamplingRatio), emitted only when
/// the NRF profile status is cached; `confidence` is a `Uinteger` 0..=100
/// (`round(R² × 100)`). The former non-spec vendor keys `predictedLoad` and
/// float `confidence` are dropped (documented per the G2-1 spec item).
///
/// T5.4/issue #26 HONESTY NOTE: `compute_nf_load` routes prediction and
/// `confidence` through the active `ml_service::InferenceModel`. The default
/// is the OLS baseline (confidence = regression R², byte-identical to the
/// formerly inline math); the feature-gated `onnx-model` backend loads real
/// linear model files, and each model documents its own confidence
/// semantics (TS 23.288 §6.14).
pub fn compute_event_infos(
    engine: &AnalyticsEngine,
    event: AnalyticsId,
    filter: &EventInfoFilter,
) -> Value {
    match event {
        AnalyticsId::NfLoad => {
            let mut infos: Vec<Value> = Vec::new();
            for instance_id in engine.nf_instance_ids() {
                let Some(r) = engine.compute_nf_load(&instance_id) else {
                    continue;
                };
                if !filter.matches(&instance_id, &r.nf_type) {
                    continue;
                }
                let mut obj = Map::new();
                obj.insert("nfType".to_string(), json!(r.nf_type));
                obj.insert("nfInstanceId".to_string(), json!(r.nf_instance_id));
                if let Some(meta) = engine.nf_meta(&instance_id) {
                    obj.insert("nfStatus".to_string(), nf_status_json(&meta.nf_status));
                }
                obj.insert(
                    "nfCpuUsage".to_string(),
                    json!((r.mean_cpu * 100.0).round() as u64),
                );
                obj.insert(
                    "nfLoadLevelAverage".to_string(),
                    json!((r.mean_cpu * 100.0).round() as u64),
                );
                obj.insert(
                    "nfLoadLevelpeak".to_string(),
                    json!((r.peak_cpu * 100.0).round() as u64),
                );
                obj.insert(
                    "confidence".to_string(),
                    json!((r.confidence * 100.0).round().clamp(0.0, 100.0) as u64),
                );
                infos.push(Value::Object(obj));
            }
            Value::Array(infos)
        }
        // G2-3: events without a live collector never reach an emitted
        // surface — the AnalyticsInfo GET answers 204 before computing and the
        // dispatcher skips them (declared failed via failEventReports at
        // subscription time). This defensive arm only makes the honest
        // "no data exists" outcome explicit for any future caller.
        _ => Value::Array(Vec::new()),
    }
}

/// Build the TS 29.520 `eventNotifications[]` array for a subscription: one
/// `EventNotification` per subscribed event, each carrying `event`,
/// `start`/`expiry` and the event-specific `*Infos` array.
///
/// nwafd-07: events whose `notificationMethod` is `THRESHOLD` are only emitted
/// when their computed analytic crosses the configured threshold in the
/// configured `matchingDir`; the previous level is read from / written back to
/// `ctx` so the crossing is edge-triggered. `PERIODIC` (and unspecified) events
/// are always emitted **when they have data**: G2-1 suppresses an event whose
/// computed `*Infos` array is empty — nothing observed means nothing is
/// reported, never an empty/fabricated entry.
///
/// G2-3: events not in `context::SUPPORTED_EVENTS` are skipped outright —
/// they were declared failed (`failEventReports[]`/`UNAVAILABLE_DATA`) in the
/// subscription response and must never appear in `eventNotifications[]`.
fn build_event_notifications(
    ctx: &NwdafContext,
    engine: &AnalyticsEngine,
    sub: &AnalyticsSubscription,
) -> Vec<Value> {
    let now = chrono::Utc::now();
    let start = now.to_rfc3339();
    let expiry = (now + chrono::Duration::seconds(3600)).to_rfc3339();

    sub.events
        .iter()
        .filter_map(|e| {
            // G2-3 (supported-events honesty): an event without a live
            // collector was declared failed at subscription time
            // (failEventReports[] / UNAVAILABLE_DATA in the 201/200 body) —
            // it is never notified, not even as an empty-array entry.
            // Derived from context::SUPPORTED_EVENTS.
            if !e.event.is_supported() {
                return None;
            }

            let filter = EventInfoFilter::from_event_subscription(e);
            let infos = compute_event_infos(engine, e.event, &filter);

            // G2-1: no data for this event → do not report it at all.
            if infos.as_array().is_none_or(|a| a.is_empty()) {
                return None;
            }

            // THRESHOLD gate (nwafd-07).
            if e.notification_method == Some(NotificationMethod::Threshold) {
                let measured = extract_level(e.event, &infos);
                let threshold = e.load_level_threshold.map(|t| t as f64);
                match (measured, threshold) {
                    (Some(m), Some(th)) => {
                        let prev = ctx.get_event_level(&sub.subscription_id, e.event);
                        ctx.set_event_level(&sub.subscription_id, e.event, m);
                        if !threshold_crossed(prev, m, th, e.matching_direction()) {
                            return None;
                        }
                    }
                    // No computable metric or no configured threshold → the
                    // THRESHOLD condition cannot be evaluated; suppress.
                    _ => return None,
                }
            }

            let mut obj = Map::new();
            obj.insert("event".to_string(), json!(e.event.as_str()));
            obj.insert("start".to_string(), json!(start));
            obj.insert("expiry".to_string(), json!(expiry));
            obj.insert(e.event.infos_key().to_string(), infos);
            Some(Value::Object(obj))
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Notify body builder (pure, testable without network)
// ─────────────────────────────────────────────────────────────────────────────

/// Build the `NnwdafEventsSubscriptionNotification` JSON body for one
/// subscription (TS 29.520 `components.schemas`):
/// ```json
/// {
///   "subscriptionId": "...",
///   "notifCorrId":    "...",
///   "eventNotifications": [ { "event": "...", "start": "...", "<event>Infos": [...] } ]
/// }
/// ```
pub fn build_notify_body(sub: &AnalyticsSubscription, event_notifications: Vec<Value>) -> Value {
    json!({
        "subscriptionId":     sub.subscription_id,
        "notifCorrId":        sub.notification_correlation_id,
        "eventNotifications": event_notifications,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Dispatcher entry point (called by the background task)
// ─────────────────────────────────────────────────────────────────────────────

/// Run one dispatcher cycle:
/// 1. Collect all active, non-expired subscriptions.
/// 2. For each subscription that `is_due_for_notification()`:
///    a. Compute analytics.
///    b. POST the Notify body to `notificationUri`.
///    c. On success, update `last_notification_time`.
///
/// Network errors are logged as warnings and do **not** abort the cycle for
/// other subscriptions.  No `unwrap()` on any runtime-reachable path.
pub async fn dispatch_notifications(ctx: Arc<RwLock<NwdafContext>>) {
    // G2-1: keep the NRF NFStatusSubscribe channel alive (initial retry +
    // validityTime renewal) on the existing dispatcher tick — no extra loop.
    crate::nrf_collector::maybe_renew_nrf_subscription(&ctx).await;

    let subscriptions: Vec<AnalyticsSubscription> = {
        match ctx.read() {
            Ok(guard) => guard.get_all_active_subscriptions(),
            Err(e) => {
                log::error!("dispatch_notifications: failed to read context: {e}");
                return;
            }
        }
    };

    for sub in &subscriptions {
        if !sub.is_due_for_notification() {
            continue;
        }

        // Lock order (nf-context-lock-deadlocks): context read → engine mutex.
        let event_notifications = match ctx.read() {
            Ok(guard) => {
                let engine = guard.lock_engine();
                build_event_notifications(&guard, &engine, sub)
            }
            Err(e) => {
                log::error!("dispatch_notifications: failed to read context: {e}");
                continue;
            }
        };
        if event_notifications.is_empty() {
            log::debug!(
                "dispatch: no events to report for subscription {}",
                sub.subscription_id
            );
            continue;
        }

        let body = build_notify_body(sub, event_notifications);

        // Parse the notification URI
        let (host, port, path) = match parse_notify_uri(&sub.notification_uri) {
            Some(t) => t,
            None => {
                log::warn!(
                    "dispatch: invalid notificationUri '{}' for sub={}",
                    sub.notification_uri,
                    sub.subscription_id
                );
                continue;
            }
        };

        let client = notify_client(&host, port);
        match client.post_json(&path, &body).await {
            Ok(resp) if resp.is_success() => {
                log::debug!(
                    "dispatch: notification delivered sub={} uri={} status={}",
                    sub.subscription_id,
                    sub.notification_uri,
                    resp.status
                );
                // Update last_notification_time so periodicity is enforced
                if let Ok(guard) = ctx.read() {
                    guard.update_subscription_last_notification(&sub.subscription_id);
                }
            }
            Ok(resp) => {
                log::warn!(
                    "dispatch: notify POST returned non-success status={} sub={}",
                    resp.status,
                    sub.subscription_id
                );
            }
            Err(e) => {
                log::warn!(
                    "dispatch: notify POST failed sub={} uri={}: {e}",
                    sub.subscription_id,
                    sub.notification_uri
                );
            }
        }
    }

    // nwafd-05: deliver pending Nnwdaf_MLModelProvision callbacks.
    dispatch_ml_prov_notifications(ctx).await;
}

/// Deliver the one-shot "model available" `Nnwdaf_MLModelProvision` callbacks.
///
/// For each subscription that has not yet been notified, POST an array of
/// `NwdafMLModelProvNotif` (built by [`crate::ml_service::build_ml_model_prov_notif_body`])
/// to its `notifUri` and, on success, mark it delivered so it is not re-sent.
/// This reuses the same URI parsing + client plumbing as the analytics path.
async fn dispatch_ml_prov_notifications(ctx: Arc<RwLock<NwdafContext>>) {
    let pending = match ctx.read() {
        Ok(guard) => guard.get_pending_ml_prov_subscriptions(),
        Err(e) => {
            log::error!("dispatch_ml_prov_notifications: failed to read context: {e}");
            return;
        }
    };

    for sub in &pending {
        let body = crate::ml_service::build_ml_model_prov_notif_body(sub);

        let (host, port, path) = match parse_notify_uri(&sub.notif_uri) {
            Some(t) => t,
            None => {
                log::warn!(
                    "dispatch: invalid ML-prov notifUri '{}' for sub={}",
                    sub.notif_uri,
                    sub.subscription_id
                );
                continue;
            }
        };

        let client = notify_client(&host, port);
        match client.post_json(&path, &body).await {
            Ok(resp) if resp.is_success() => {
                if let Ok(guard) = ctx.read() {
                    guard.mark_ml_prov_notified(&sub.subscription_id);
                }
            }
            Ok(resp) => log::warn!(
                "dispatch: ML-prov notify non-success status={} sub={}",
                resp.status,
                sub.subscription_id
            ),
            Err(e) => log::warn!(
                "dispatch: ML-prov notify POST failed sub={} uri={}: {e}",
                sub.subscription_id,
                sub.notif_uri
            ),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Background task spawner
// ─────────────────────────────────────────────────────────────────────────────

/// Spawn the background tokio task that periodically runs analytics and
/// dispatches notifications to all due subscriptions.
///
/// `interval_secs` controls the tick period; pass `DEFAULT_DISPATCH_INTERVAL_SECS`
/// for the standard 30-second default.
pub fn spawn_dispatcher(ctx: Arc<RwLock<NwdafContext>>, interval_secs: u64) {
    let tick = Duration::from_secs(interval_secs.max(1));
    tokio::spawn(async move {
        log::info!(
            "NWDAF notification dispatcher started (interval={}s)",
            interval_secs
        );
        loop {
            tokio::time::sleep(tick).await;
            dispatch_notifications(ctx.clone()).await;
        }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{AnalyticsId, AnalyticsSubscription, NwdafContext};
    use std::sync::{Arc, RwLock};

    // ── helper ──────────────────────────────────────────────────────────────

    fn make_ctx_with_sub(
        notification_uri: &str,
        repetition_period_secs: Option<u64>,
    ) -> (Arc<RwLock<NwdafContext>>, String) {
        let mut ctx = NwdafContext::new("nwdaf-test".to_string());
        ctx.init(100);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs();

        let mut sub = AnalyticsSubscription::new(
            "sub-test-001".to_string(),
            AnalyticsId::NfLoad,
            notification_uri.to_string(),
            now + 3600,
        );
        sub.notification_correlation_id = "corr-abc123".to_string();
        sub.repetition_period_secs = repetition_period_secs;

        let sub_id = sub.subscription_id.clone();
        ctx.add_subscription(sub);

        (Arc::new(RwLock::new(ctx)), sub_id)
    }

    // ── T5.3: notify body shape ──────────────────────────────────────────────

    /// Ingest `n` NRF-style load samples (0..=100) for an instance into the
    /// context's shared engine (G2-1: samples only ever come from NRF data).
    fn ingest_loads(ctx: &NwdafContext, nf_type: &str, instance: &str, loads: &[u8]) {
        let mut engine = ctx.lock_engine();
        for &load in loads {
            engine.ingest_nf_load(crate::analytics::NfLoadSample::now(
                nf_type,
                instance,
                f64::from(load) / 100.0,
                0.0,
                0,
            ));
        }
    }

    /// nwafd-04: the Notify body is an `NnwdafEventsSubscriptionNotification`:
    /// it MUST carry `subscriptionId`, `notifCorrId`, and `eventNotifications[]`
    /// where each entry has `event` and the event-specific `*Infos` **array**
    /// (`nfLoadLevelInfos` for NF_LOAD). The legacy `reportList` /
    /// `notificationCorrelationId` keys MUST be gone.
    ///
    /// G2-1: the reported data comes from ingested NRF-sourced samples — the
    /// old synthetic self-sample is gone, so the test seeds real samples.
    #[test]
    fn test_notify_body_shape() {
        let (ctx_arc, sub_id) = make_ctx_with_sub("http://amf.local:8080/notify", Some(60));
        let ctx = ctx_arc.read().unwrap();
        ingest_loads(&ctx, "AMF", "amf-notify-shape", &[30, 32]);
        let sub = ctx.get_subscription(&sub_id).unwrap();

        let engine = ctx.lock_engine();
        let event_notifications = build_event_notifications(&ctx, &engine, &sub);
        drop(engine);
        let body = build_notify_body(&sub, event_notifications);

        assert_eq!(
            body["notifCorrId"].as_str(),
            Some("corr-abc123"),
            "notifCorrId must be echoed from the subscription"
        );
        assert_eq!(
            body["subscriptionId"].as_str(),
            Some("sub-test-001"),
            "subscriptionId must identify the subscription"
        );
        assert!(
            body.get("reportList").is_none(),
            "legacy reportList key must be gone"
        );
        assert!(
            body.get("notificationCorrelationId").is_none(),
            "legacy notificationCorrelationId key must be gone"
        );

        let notifs = body["eventNotifications"]
            .as_array()
            .expect("eventNotifications must be an array");
        assert_eq!(notifs.len(), 1, "one event → one EventNotification");

        let entry = &notifs[0];
        assert_eq!(entry["event"].as_str(), Some("NF_LOAD"));
        assert!(
            entry["start"].as_str().is_some(),
            "EventNotification must carry a start timestamp"
        );
        let infos = entry["nfLoadLevelInfos"]
            .as_array()
            .expect("NF_LOAD notification must carry an nfLoadLevelInfos array");
        assert!(
            !infos.is_empty(),
            "NF_LOAD nfLoadLevelInfos must have at least one element"
        );
    }

    // ── T5.3: subscription matching ─────────────────────────────────────────

    /// Only subscriptions whose `is_due_for_notification()` returns true should
    /// be selected by the dispatcher.  A freshly-created subscription (no last
    /// notification yet) is always due.
    #[test]
    fn test_subscription_matching_fresh_is_due() {
        let (ctx_arc, sub_id) = make_ctx_with_sub("http://amf.local/notify", Some(60));
        let ctx = ctx_arc.read().unwrap();
        let sub = ctx.get_subscription(&sub_id).unwrap();
        assert!(
            sub.is_due_for_notification(),
            "a fresh subscription must be due immediately"
        );
    }

    // ── T5.3: periodicity guard ─────────────────────────────────────────────

    /// After recording a notification, a subscription with a 60-second period
    /// must NOT be due again immediately.
    #[test]
    fn test_periodicity_guard_suppresses_too_soon() {
        let (ctx_arc, sub_id) = make_ctx_with_sub("http://amf.local/notify", Some(60));

        // Record that a notification was just sent
        {
            let ctx = ctx_arc.read().unwrap();
            ctx.update_subscription_last_notification(&sub_id);
        }

        // Immediately check: must NOT be due (0 seconds < 60 second period)
        let ctx = ctx_arc.read().unwrap();
        let sub = ctx.get_subscription(&sub_id).unwrap();
        assert!(
            !sub.is_due_for_notification(),
            "subscription must NOT be due immediately after a notification"
        );
    }

    /// A one-shot subscription (None period) must be due exactly once.
    #[test]
    fn test_one_shot_due_exactly_once() {
        let (ctx_arc, sub_id) = make_ctx_with_sub("http://amf.local/notify", None);

        {
            let ctx = ctx_arc.read().unwrap();
            let sub = ctx.get_subscription(&sub_id).unwrap();
            assert!(
                sub.is_due_for_notification(),
                "one-shot must be due before first notification"
            );
        }

        // Simulate notification sent
        {
            let ctx = ctx_arc.read().unwrap();
            ctx.update_subscription_last_notification(&sub_id);
        }

        {
            let ctx = ctx_arc.read().unwrap();
            let sub = ctx.get_subscription(&sub_id).unwrap();
            assert!(
                !sub.is_due_for_notification(),
                "one-shot must NOT be due after the first notification"
            );
        }
    }

    // ── T5.4: analytics field shapes unchanged ───────────────────────────────

    /// The analytics engine must still return the same field set after the
    /// T5.4 docstring-only honesty edits.
    #[test]
    fn test_analytics_field_shapes_unchanged() {
        use crate::analytics::{AnalyticsEngine, NfLoadSample};

        let mut engine = AnalyticsEngine::new();
        for i in 0..5 {
            engine.ingest_nf_load(NfLoadSample::now(
                "AMF",
                "amf-01",
                0.3 + i as f64 * 0.05,
                0.4,
                100,
            ));
        }
        let result = engine
            .compute_nf_load("amf-01")
            .expect("should produce analytics");

        // All expected fields present and in valid ranges
        assert!(!result.nf_type.is_empty(), "nf_type must be non-empty");
        assert!(
            !result.nf_instance_id.is_empty(),
            "nf_instance_id must be non-empty"
        );
        assert!(
            (0.0..=1.0).contains(&result.mean_cpu),
            "mean_cpu must be in [0,1]"
        );
        assert!(
            (0.0..=1.0).contains(&result.peak_cpu),
            "peak_cpu must be in [0,1]"
        );
        assert!(
            (0.0..=1.0).contains(&result.predicted_load),
            "predicted_load must be in [0,1]"
        );
        assert!(
            (0.0..=1.0).contains(&result.confidence),
            "confidence must be in [0,1]"
        );
    }

    // ── URI parser ──────────────────────────────────────────────────────────

    #[test]
    fn test_parse_notify_uri() {
        assert_eq!(
            parse_notify_uri("http://1.2.3.4:8080/notify"),
            Some(("1.2.3.4".to_string(), 8080, "/notify".to_string()))
        );
        assert_eq!(
            parse_notify_uri("http://amf.local/cb"),
            Some(("amf.local".to_string(), 80, "/cb".to_string()))
        );
        assert_eq!(
            parse_notify_uri("https://secure.host"),
            Some(("secure.host".to_string(), 443, "/".to_string()))
        );
        assert_eq!(parse_notify_uri("ftp://host/x"), None);
        assert_eq!(parse_notify_uri("http://:80/x"), None);
        assert_eq!(parse_notify_uri(""), None);
    }

    // ── dispatch_notifications: skips invalid URI ───────────────────────────

    /// When a subscription has an invalid notificationUri, the dispatcher
    /// must log + skip it rather than panic.  We test this by running the
    /// dispatcher against a context whose subscription has a bad URI.
    #[tokio::test]
    async fn test_dispatch_skips_invalid_uri() {
        let (ctx_arc, _sub_id) = make_ctx_with_sub("not-a-valid-uri", Some(60));
        // Should complete without panicking
        dispatch_notifications(ctx_arc).await;
    }

    // ── nwafd-07: THRESHOLD evaluation ───────────────────────────────────────

    /// The pure predicate honours every `matchingDir` and is edge-triggered.
    #[test]
    fn test_threshold_predicate_directions() {
        // ASCENDING: fires only on the rising edge to/above the threshold.
        assert!(!threshold_crossed(
            None,
            30.0,
            80.0,
            MatchingDirection::Ascending
        ));
        assert!(threshold_crossed(
            None,
            90.0,
            80.0,
            MatchingDirection::Ascending
        ));
        // Already above → no re-fire.
        assert!(!threshold_crossed(
            Some(90.0),
            95.0,
            80.0,
            MatchingDirection::Ascending
        ));

        // DESCENDING: fires on the falling edge to/below the threshold.
        assert!(threshold_crossed(
            None,
            30.0,
            80.0,
            MatchingDirection::Descending
        ));
        assert!(!threshold_crossed(
            None,
            90.0,
            80.0,
            MatchingDirection::Descending
        ));

        // CROSSED: fires on a crossing in either direction, not otherwise.
        assert!(threshold_crossed(
            Some(30.0),
            90.0,
            80.0,
            MatchingDirection::Crossed
        ));
        assert!(threshold_crossed(
            Some(90.0),
            30.0,
            80.0,
            MatchingDirection::Crossed
        ));
        assert!(!threshold_crossed(
            Some(85.0),
            95.0,
            80.0,
            MatchingDirection::Crossed
        ));
    }

    /// A THRESHOLD event is suppressed below its threshold and emitted at/above
    /// it; a PERIODIC event is unaffected. G2-1: the load level under test is
    /// **ingested** (NRF-sourced samples at load 30), not the former synthetic
    /// self-sample constant.
    #[test]
    fn test_threshold_event_gating_vs_periodic() {
        let ctx = NwdafContext::new("nwdaf-test".to_string());
        ingest_loads(&ctx, "AMF", "amf-thr-01", &[30, 30]);

        let thr_event = |threshold: u64| {
            let mut e = EventSubscription::periodic(AnalyticsId::NfLoad);
            e.notification_method = Some(NotificationMethod::Threshold);
            e.load_level_threshold = Some(threshold);
            e.matching_dir = Some("ASCENDING".to_string());
            e
        };

        // Threshold 80 > ingested load 30 → suppressed (no event reported).
        let mut sub_high = AnalyticsSubscription::new(
            "sub-high".into(),
            AnalyticsId::NfLoad,
            "http://x/y".into(),
            u64::MAX,
        );
        sub_high.events = vec![thr_event(80)];
        let engine = ctx.lock_engine();
        assert!(
            build_event_notifications(&ctx, &engine, &sub_high).is_empty(),
            "THRESHOLD must not fire when ingested load (30) is below threshold 80"
        );

        // Threshold 20 ≤ ingested load 30 → fires (one EventNotification).
        let mut sub_low = AnalyticsSubscription::new(
            "sub-low".into(),
            AnalyticsId::NfLoad,
            "http://x/y".into(),
            u64::MAX,
        );
        sub_low.events = vec![thr_event(20)];
        assert_eq!(
            build_event_notifications(&ctx, &engine, &sub_low).len(),
            1,
            "THRESHOLD must fire when ingested load (30) is at/above threshold 20"
        );

        // PERIODIC (the default from `new`) is unaffected by thresholds.
        let sub_periodic = AnalyticsSubscription::new(
            "sub-per".into(),
            AnalyticsId::NfLoad,
            "http://x/y".into(),
            u64::MAX,
        );
        assert_eq!(
            build_event_notifications(&ctx, &engine, &sub_periodic).len(),
            1,
            "PERIODIC subscription must always report when data exists"
        );
    }

    // ── G2-3: supported-events honesty in the dispatcher ────────────────────

    /// G2-3: a subscription covering {NF_LOAD, UE_MOBILITY} (UE_MOBILITY was
    /// declared failed via failEventReports at create time) notifies ONLY
    /// NF_LOAD: no UE_MOBILITY entry, no empty-array `*Infos` entry, ever —
    /// even though NF_LOAD data exists in the same engine.
    #[test]
    fn test_honesty_dispatcher_skips_unsupported_events() {
        let ctx = NwdafContext::new("nwdaf-test".to_string());
        ingest_loads(&ctx, "AMF", "amf-honesty-disp", &[25, 35]);

        let mut sub = AnalyticsSubscription::new(
            "sub-honesty".into(),
            AnalyticsId::NfLoad,
            "http://x/y".into(),
            u64::MAX,
        );
        sub.events = vec![
            EventSubscription::periodic(AnalyticsId::NfLoad),
            EventSubscription::periodic(AnalyticsId::UeMobility),
        ];

        let engine = ctx.lock_engine();
        let notifications = build_event_notifications(&ctx, &engine, &sub);

        assert_eq!(
            notifications.len(),
            1,
            "only the supported event may be notified"
        );
        assert_eq!(
            notifications[0]["event"].as_str(),
            Some("NF_LOAD"),
            "the single EventNotification must be NF_LOAD"
        );
        assert!(
            notifications
                .iter()
                .all(|n| n["event"].as_str() != Some("UE_MOBILITY")),
            "the failed-at-subscribe UE_MOBILITY event must never be notified"
        );
        // No entry may carry an empty *Infos array (the old empty-array leak).
        for n in &notifications {
            let obj = n.as_object().expect("EventNotification object");
            for (key, value) in obj {
                if let Some(arr) = value.as_array() {
                    assert!(
                        !arr.is_empty(),
                        "no EventNotification may carry an empty {key} array"
                    );
                }
            }
        }
    }

    // ── G2-1: NRF-sourced NF_LOAD computation ────────────────────────────────

    /// The hard-coded self-sample is gone: with an empty engine, NF_LOAD
    /// computes NO infos, and a PERIODIC subscription reports NOTHING (no
    /// fabricated data, no empty-array entry).
    #[test]
    fn test_no_ingested_data_reports_nothing() {
        let ctx = NwdafContext::new("nwdaf-test".to_string());
        let engine = ctx.lock_engine();

        let infos = compute_event_infos(&engine, AnalyticsId::NfLoad, &EventInfoFilter::none());
        assert_eq!(
            infos.as_array().map(Vec::len),
            Some(0),
            "no samples → empty infos, never a fabricated self-sample"
        );

        let sub = AnalyticsSubscription::new(
            "sub-empty".into(),
            AnalyticsId::NfLoad,
            "http://x/y".into(),
            u64::MAX,
        );
        assert!(
            build_event_notifications(&ctx, &engine, &sub).is_empty(),
            "an event with no data must be suppressed entirely"
        );
    }

    /// One NfLoadLevelInformation per NF instance with samples; the
    /// per-event `nfTypes`/`nfInstanceIds` filters are honored.
    #[test]
    fn test_per_instance_infos_and_filters() {
        let ctx = NwdafContext::new("nwdaf-test".to_string());
        ingest_loads(&ctx, "AMF", "amf-multi-01", &[10, 20]);
        ingest_loads(&ctx, "SMF", "smf-multi-01", &[40, 50]);
        ingest_loads(&ctx, "UPF", "upf-multi-01", &[70, 80]);
        let engine = ctx.lock_engine();

        // Unfiltered: 3 instances → 3 infos (sorted by instance id).
        let infos = compute_event_infos(&engine, AnalyticsId::NfLoad, &EventInfoFilter::none());
        let arr = infos.as_array().expect("array");
        assert_eq!(arr.len(), 3, "one info per instance with samples");
        assert_eq!(arr[0]["nfInstanceId"].as_str(), Some("amf-multi-01"));
        assert_eq!(arr[0]["nfLoadLevelAverage"].as_u64(), Some(15));
        assert_eq!(arr[0]["nfLoadLevelpeak"].as_u64(), Some(20));

        // nfTypes filter.
        let by_type = compute_event_infos(
            &engine,
            AnalyticsId::NfLoad,
            &EventInfoFilter {
                nf_instance_ids: Vec::new(),
                nf_types: vec!["SMF".to_string()],
            },
        );
        let arr = by_type.as_array().expect("array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["nfType"].as_str(), Some("SMF"));

        // nfInstanceIds filter.
        let by_id = compute_event_infos(
            &engine,
            AnalyticsId::NfLoad,
            &EventInfoFilter {
                nf_instance_ids: vec!["upf-multi-01".to_string()],
                nf_types: Vec::new(),
            },
        );
        let arr = by_id.as_array().expect("array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["nfInstanceId"].as_str(), Some("upf-multi-01"));

        // Non-matching filter → empty.
        let none = compute_event_infos(
            &engine,
            AnalyticsId::NfLoad,
            &EventInfoFilter {
                nf_instance_ids: vec!["nope".to_string()],
                nf_types: Vec::new(),
            },
        );
        assert_eq!(none.as_array().map(Vec::len), Some(0));
    }

    /// G2-1 spec-shaping regression: `confidence` is a TS 29.571 `Uinteger`
    /// 0..=100 (never the old float R²), the non-spec `predictedLoad` vendor
    /// key is gone, and `nfStatus` is the TS 29.520 object form sourced from
    /// the cached NRF profile (never a bare string literal).
    /// Issue #26 acceptance: a swapped inference model's output reaches the
    /// wire — the emitted `confidence` Uinteger is the model's confidence.
    #[test]
    fn swapped_model_output_reaches_wire_confidence() {
        struct FixedModel;
        impl crate::ml_service::InferenceModel for FixedModel {
            fn model_id(&self) -> &str {
                "fixed-test"
            }
            fn predict_series(&self, _series: &[f64]) -> Option<(f64, f64)> {
                Some((0.87, 0.42))
            }
        }
        let mut engine = AnalyticsEngine::new();
        for v in [0.1_f64, 0.2, 0.3] {
            engine.ingest_nf_load(crate::analytics::NfLoadSample::now(
                "AMF",
                "amf-fixed-01",
                v,
                0.0,
                0,
            ));
        }
        engine.set_predictor(Box::new(FixedModel));
        let infos = compute_event_infos(&engine, AnalyticsId::NfLoad, &EventInfoFilter::none());
        assert_eq!(infos[0]["nfInstanceId"], "amf-fixed-01");
        assert_eq!(
            infos[0]["confidence"], 42,
            "wire confidence = model output x100"
        );
    }

    #[test]
    fn test_nf_load_info_spec_shape() {
        use crate::analytics::NfProfileMeta;

        let ctx = NwdafContext::new("nwdaf-test".to_string());
        ingest_loads(&ctx, "AMF", "amf-shape-01", &[10, 20, 30]);
        {
            let mut engine = ctx.lock_engine();
            engine.upsert_nf_meta(
                "amf-shape-01",
                NfProfileMeta {
                    nf_type: "AMF".to_string(),
                    nf_status: "REGISTERED".to_string(),
                    last_load: Some(30),
                },
            );
        }
        let engine = ctx.lock_engine();
        let infos = compute_event_infos(&engine, AnalyticsId::NfLoad, &EventInfoFilter::none());
        let info = &infos.as_array().expect("array")[0];

        // confidence: integer 0..=100 (rejects the old float emission).
        let confidence = &info["confidence"];
        assert!(
            confidence.is_u64(),
            "confidence must be an integer Uinteger, got {confidence:?}"
        );
        assert!(confidence.as_u64().expect("u64") <= 100);

        // predictedLoad (non-spec vendor key) must be gone.
        assert!(
            info.get("predictedLoad").is_none(),
            "non-spec predictedLoad must not be emitted"
        );

        // nfStatus: TS 29.520 object form from the cached NRF profile.
        assert_eq!(
            info["nfStatus"]["statusRegistered"].as_u64(),
            Some(100),
            "nfStatus must be the object form sourced from the NRF profile"
        );
        assert!(
            !info["nfStatus"].is_string(),
            "nfStatus must never be a bare string literal"
        );

        // Mandatory IEs per the yaml allOf.
        assert!(info["nfType"].is_string());
        assert!(info["nfInstanceId"].is_string());
    }

    /// An instance whose cached NRF status is SUSPENDED reports
    /// `statusUnregistered`, and NF_DEREGISTERED removal drops its data.
    #[test]
    fn test_nf_status_object_and_removal() {
        use crate::analytics::NfProfileMeta;

        let ctx = NwdafContext::new("nwdaf-test".to_string());
        ingest_loads(&ctx, "SMF", "smf-status-01", &[42]);
        {
            let mut engine = ctx.lock_engine();
            engine.upsert_nf_meta(
                "smf-status-01",
                NfProfileMeta {
                    nf_type: "SMF".to_string(),
                    nf_status: "SUSPENDED".to_string(),
                    last_load: Some(42),
                },
            );
        }
        {
            let engine = ctx.lock_engine();
            let infos = compute_event_infos(&engine, AnalyticsId::NfLoad, &EventInfoFilter::none());
            let info = &infos.as_array().expect("array")[0];
            assert_eq!(info["nfStatus"]["statusUnregistered"].as_u64(), Some(100));
        }

        // NF_DEREGISTERED → all data for the instance is dropped.
        ctx.lock_engine().remove_nf_instance("smf-status-01");
        let engine = ctx.lock_engine();
        let infos = compute_event_infos(&engine, AnalyticsId::NfLoad, &EventInfoFilter::none());
        assert_eq!(
            infos.as_array().map(Vec::len),
            Some(0),
            "a deregistered instance must not be reported"
        );
    }
}
