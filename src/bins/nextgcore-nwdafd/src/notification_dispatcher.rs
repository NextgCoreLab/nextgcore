//! NWDAF Event-Notification Dispatcher (TS 29.520 §5.2)
//!
//! When an analytics event triggers (periodic interval or threshold breach),
//! the NWDAF SHALL POST an `Nnwdaf_EventsSubscription_Notify` to the
//! consumer's `notificationUri` (TS 29.520 §5.2.2.3).
//!
//! # Notify body shape
//!
//! ```json
//! {
//!   "notificationCorrelationId": "<from subscription>",
//!   "subscriptionId":            "<sub id>",
//!   "reportList": [
//!     {
//!       "analyticsId":  "NF_LOAD",
//!       "timestamp":    "<RFC-3339>",
//!       "nfLoadLevelInfo": { ... }   // analyticsId-specific payload
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
//! # Threshold conditions
//!
//! Threshold-based triggering (e.g. fire only when CPU > 0.8) is **not yet
//! wired** — the dispatcher fires on periodicity only.  The `ReportingCondition`
//! struct in `subscription.rs` already carries a `threshold` field; a future
//! pass should evaluate that against the analytics output here and skip the
//! POST when the threshold is not breached.

use crate::analytics::{AnalyticsEngine, NfLoadSample};
use crate::context::{AnalyticsId, AnalyticsSubscription, NwdafContext};
use ogs_sbi::client::{SbiClient, SbiClientConfig};
use serde_json::{json, Value};
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

fn notify_client(host: &str, port: u16) -> SbiClient {
    let config = SbiClientConfig::new(host, port)
        .with_connect_timeout(Duration::from_secs(NOTIFY_CONNECT_TIMEOUT_SECS))
        .with_request_timeout(Duration::from_secs(NOTIFY_REQUEST_TIMEOUT_SECS));
    SbiClient::new(config)
}

// ─────────────────────────────────────────────────────────────────────────────
// Analytics runner
// ─────────────────────────────────────────────────────────────────────────────

/// Synthesise a synthetic NF load sample and compute analytics.
///
/// In production this would query OAM/metrics endpoints for each registered
/// data source. For now it ingests a placeholder sample so the engine always
/// has something to report. The important part is that `compute_nf_load`
/// exercises the linear-regression path and returns a real report struct.
fn compute_analytics_for_subscription(
    engine: &mut AnalyticsEngine,
    sub: &AnalyticsSubscription,
) -> Option<Value> {
    match sub.analytics_id {
        AnalyticsId::NfLoad => {
            // Ingest a placeholder sample representing the NWDAF's own NF load.
            // A real implementation would collect these from data sources.
            let sample = NfLoadSample::now("NWDAF", "nwdaf-self", 0.3, 0.4, 0);
            engine.ingest_nf_load(sample);

            engine.compute_nf_load("nwdaf-self").map(|r| {
                json!({
                    "analyticsId": AnalyticsId::NfLoad.as_str(),
                    "timestamp":   chrono::Utc::now().to_rfc3339(),
                    "nfLoadLevelInfo": {
                        "nfType":        r.nf_type,
                        "nfInstanceId":  r.nf_instance_id,
                        "meanCpu":       r.mean_cpu,
                        "peakCpu":       r.peak_cpu,
                        "predictedLoad": r.predicted_load,
                        "confidence":    r.confidence,
                    }
                })
            })
        }

        AnalyticsId::UeMobility => {
            // No live UE cell data collected yet; emit a placeholder report
            // so subscriptions receive *something*.
            Some(json!({
                "analyticsId": AnalyticsId::UeMobility.as_str(),
                "timestamp":   chrono::Utc::now().to_rfc3339(),
                "ueMobilityInfo": {
                    "note": "no UE mobility data collected yet",
                }
            }))
        }

        other => {
            // Generic fallback for other analytics types
            Some(json!({
                "analyticsId": other.as_str(),
                "timestamp":   chrono::Utc::now().to_rfc3339(),
            }))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Notify body builder (pure, testable without network)
// ─────────────────────────────────────────────────────────────────────────────

/// Build the `Nnwdaf_EventsSubscription_Notify` JSON body for one subscription.
///
/// Shape (TS 29.520 §5.2.2.3):
/// ```json
/// {
///   "notificationCorrelationId": "...",
///   "subscriptionId":            "...",
///   "reportList": [ { "analyticsId": "...", "timestamp": "...", ... } ]
/// }
/// ```
pub fn build_notify_body(sub: &AnalyticsSubscription, report: Value) -> Value {
    json!({
        "notificationCorrelationId": sub.notification_correlation_id,
        "subscriptionId":            sub.subscription_id,
        "reportList": [ report ],
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
    let subscriptions: Vec<AnalyticsSubscription> = {
        match ctx.read() {
            Ok(guard) => guard.get_all_active_subscriptions(),
            Err(e) => {
                log::error!("dispatch_notifications: failed to read context: {e}");
                return;
            }
        }
    };

    let mut engine = AnalyticsEngine::new();

    for sub in &subscriptions {
        if !sub.is_due_for_notification() {
            continue;
        }

        let report = match compute_analytics_for_subscription(&mut engine, sub) {
            Some(r) => r,
            None => {
                log::debug!(
                    "dispatch: no analytics data for subscription {} ({})",
                    sub.subscription_id,
                    sub.analytics_id.as_str()
                );
                continue;
            }
        };

        let body = build_notify_body(sub, report);

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

    /// The Notify body MUST carry `notificationCorrelationId`, `subscriptionId`,
    /// and `reportList` with at least one entry that has `analyticsId` and
    /// `timestamp`.
    #[test]
    fn test_notify_body_shape() {
        let (ctx_arc, sub_id) = make_ctx_with_sub("http://amf.local:8080/notify", Some(60));
        let ctx = ctx_arc.read().unwrap();
        let sub = ctx.get_subscription(&sub_id).unwrap();

        let report = json!({
            "analyticsId": "NF_LOAD",
            "timestamp":   "2026-06-14T00:00:00Z",
            "nfLoadLevelInfo": { "meanCpu": 0.3 }
        });

        let body = build_notify_body(&sub, report);

        assert_eq!(
            body["notificationCorrelationId"].as_str(),
            Some("corr-abc123"),
            "notificationCorrelationId must be echoed from the subscription"
        );
        assert_eq!(
            body["subscriptionId"].as_str(),
            Some("sub-test-001"),
            "subscriptionId must identify the subscription"
        );

        let report_list = body["reportList"].as_array().expect("reportList must be an array");
        assert_eq!(report_list.len(), 1, "reportList must have exactly one entry");

        let entry = &report_list[0];
        assert_eq!(entry["analyticsId"].as_str(), Some("NF_LOAD"));
        assert!(
            entry["timestamp"].as_str().is_some(),
            "report entry must carry a timestamp"
        );
        assert!(
            entry["nfLoadLevelInfo"].is_object(),
            "NF_LOAD report must include nfLoadLevelInfo"
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
            assert!(sub.is_due_for_notification(), "one-shot must be due before first notification");
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
        let result = engine.compute_nf_load("amf-01").expect("should produce analytics");

        // All expected fields present and in valid ranges
        assert!(!result.nf_type.is_empty(), "nf_type must be non-empty");
        assert!(!result.nf_instance_id.is_empty(), "nf_instance_id must be non-empty");
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
}
