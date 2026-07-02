//! G2-1: NRF-sourced NF_LOAD data collection (TS 23.288 §6.5 Table 6.5.2-1:
//! the data source for NF load analytics is the NRF).
//!
//! Two halves:
//!
//! 1. **Subscribe / renew** — the NWDAF POSTs an Nnrf_NFManagement
//!    NFStatusSubscribe (TS 29.510 §5.2.2.5) `SubscriptionData` to
//!    `{nrfUri}/nnrf-nfm/v1/subscriptions` with our
//!    `nfStatusNotificationUri`; `subscrCond` is omitted so every NF matches.
//!    Failures degrade to no-data (log + retry on the dispatcher tick) —
//!    the NF never panics and analytics simply report nothing.
//!
//! 2. **Ingest** — the NRF POSTs TS 29.510 §5.2.2.6 `NotificationData`
//!    (`event`, `nfInstanceUri`, optional `nfProfile` / `profileChanges`)
//!    to our callback. `NFProfile.load` (0..=100) becomes an
//!    [`NfLoadSample`] (`cpu = load / 100`); `profileChanges` `/load`
//!    add/replace items update the cached load and yield a sample;
//!    NF_DEREGISTERED drops the instance. Malformed bodies are rejected
//!    with 400 (fail-closed); unknown *fields* are ignored per TS 29.500
//!    SBI extensibility.

use crate::analytics::{NfLoadSample, NfProfileMeta};
use crate::context::{NrfStatusSubscription, NwdafContext};
use crate::notification_dispatcher::{notify_client, parse_notify_uri};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::send_bad_request;
use serde_json::Value;
use std::sync::{Arc, RwLock};

/// Renew the NRF subscription when it expires within this margin (seconds).
/// Two default dispatcher ticks (2 × 30 s) plus slack.
const RENEW_MARGIN_SECS: u64 = 120;

/// The notification events we subscribe for (`reqNotifEvents`, TS 29.510).
const REQ_NOTIF_EVENTS: [&str; 3] = ["NF_REGISTERED", "NF_DEREGISTERED", "NF_PROFILE_CHANGED"];

// ─────────────────────────────────────────────────────────────────────────────
// Subscribe / renew
// ─────────────────────────────────────────────────────────────────────────────

/// Build the TS 29.510 `SubscriptionData` request body for NFStatusSubscribe.
/// `subscrCond` is deliberately omitted: the NWDAF wants load data for ALL
/// NF instances (TS 23.288 §6.5).
pub fn build_nf_status_subscription_body(callback_uri: &str) -> Value {
    serde_json::json!({
        "nfStatusNotificationUri": callback_uri,
        "reqNfType": "NWDAF",
        "reqNotifEvents": REQ_NOTIF_EVENTS,
    })
}

/// Parse the NRF's 201 response into an [`NrfStatusSubscription`].
///
/// `subscriptionId` is read from the response body (TS 29.510
/// `SubscriptionData`), falling back to the last segment of the `Location`
/// header. `validityTime` (RFC 3339) becomes an absolute Unix expiry.
pub fn parse_subscription_create_response(
    body: Option<&str>,
    location: Option<&str>,
) -> Option<NrfStatusSubscription> {
    let parsed: Option<Value> = body.and_then(|b| serde_json::from_str(b).ok());

    let from_body = parsed
        .as_ref()
        .and_then(|v| v.get("subscriptionId"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let from_location = location
        .and_then(|l| l.rsplit('/').next())
        .filter(|s| !s.is_empty())
        .map(String::from);
    let subscription_id = from_body.or(from_location)?;

    let validity_unix = parsed
        .as_ref()
        .and_then(|v| v.get("validityTime"))
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.timestamp().max(0) as u64);

    Some(NrfStatusSubscription {
        subscription_id,
        validity_unix,
    })
}

/// POST the NFStatusSubscribe to the NRF and store the resulting subscription
/// state in the context. Non-fatal on every failure path (logs a warning);
/// the dispatcher tick retries via [`maybe_renew_nrf_subscription`].
pub async fn subscribe_nf_status(ctx: &Arc<RwLock<NwdafContext>>) {
    let config = match ctx.read().ok().and_then(|g| g.nrf_collector_config()) {
        Some(c) => c,
        None => return, // collector not armed (e.g., unit tests)
    };

    let (host, port, base_path) = match parse_notify_uri(&config.nrf_uri) {
        Some(t) => t,
        None => {
            log::warn!(
                "NRF NFStatusSubscribe: invalid NRF URI '{}'",
                config.nrf_uri
            );
            return;
        }
    };
    let path = format!(
        "{}/nnrf-nfm/v1/subscriptions",
        base_path.trim_end_matches('/')
    );

    let body = build_nf_status_subscription_body(&config.callback_uri);
    let client = notify_client(&host, port);
    match client.post_json(&path, &body).await {
        Ok(resp) if resp.status == 201 || resp.status == 200 => {
            let location = resp.http.get_header("Location").map(String::from);
            match parse_subscription_create_response(
                resp.http.content.as_deref(),
                location.as_deref(),
            ) {
                Some(sub) => {
                    log::info!(
                        "NRF NFStatusSubscribe active: id={} validity_unix={:?}",
                        sub.subscription_id,
                        sub.validity_unix
                    );
                    if let Ok(guard) = ctx.read() {
                        guard.set_nrf_status_subscription(Some(sub));
                    }
                }
                None => log::warn!(
                    "NRF NFStatusSubscribe: 201 without a parseable subscriptionId — will retry"
                ),
            }
        }
        Ok(resp) => log::warn!(
            "NRF NFStatusSubscribe rejected (status {}) — will retry",
            resp.status
        ),
        Err(e) => log::warn!("NRF NFStatusSubscribe failed: {e} — will retry"),
    }
}

/// Dispatcher-tick hook: (re-)subscribe when the collector is armed and there
/// is no active subscription, or the active one expires within
/// [`RENEW_MARGIN_SECS`]. No-op when the collector is not armed.
pub async fn maybe_renew_nrf_subscription(ctx: &Arc<RwLock<NwdafContext>>) {
    let (armed, current) = match ctx.read() {
        Ok(guard) => (
            guard.nrf_collector_config().is_some(),
            guard.nrf_status_subscription(),
        ),
        Err(_) => return,
    };
    if !armed {
        return;
    }

    let needs_subscribe = match current {
        None => true,
        Some(sub) => match sub.validity_unix {
            None => false, // no expiry communicated → nothing to renew
            Some(expiry) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or(std::time::Duration::ZERO)
                    .as_secs();
                expiry.saturating_sub(now) <= RENEW_MARGIN_SECS
            }
        },
    };

    if needs_subscribe {
        subscribe_nf_status(ctx).await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NFStatusNotify ingestion
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed TS 29.510 §5.2.2.6 `NotificationData`, reduced to what NF_LOAD
/// ingestion needs.
#[derive(Debug)]
struct ParsedNfStatusNotification {
    event: NfStatusEvent,
    nf_instance_id: String,
    /// From `nfProfile` when present: (nfType, nfStatus, load).
    profile: Option<(String, String, Option<u8>)>,
    /// The effective new `/load` from `profileChanges` (add/replace), and
    /// whether a `/load` remove was seen.
    load_change: Option<LoadChange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NfStatusEvent {
    Registered,
    Deregistered,
    ProfileChanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoadChange {
    /// `/load` add/replace with the new value.
    Set(u8),
    /// `/load` remove.
    Removed,
}

/// Extract a 0..=100 load from a JSON number, rejecting out-of-range values.
fn parse_load(v: &Value) -> Option<u8> {
    v.as_u64().filter(|&n| n <= 100).map(|n| n as u8)
}

/// Parse and validate a `NotificationData` body. Mandatory-IE violations and
/// malformed values return `(detail, cause)` for a 400 ProblemDetails
/// (fail-closed); unknown additional fields are ignored (SBI extensibility).
fn parse_notification_data(
    data: &Value,
) -> Result<ParsedNfStatusNotification, (String, &'static str)> {
    let event_token = match data.get("event").and_then(|v| v.as_str()) {
        Some(t) if !t.is_empty() => t,
        _ => {
            return Err((
                "event is a mandatory IE".to_string(),
                "MANDATORY_IE_MISSING",
            ))
        }
    };
    let event = match event_token {
        "NF_REGISTERED" => NfStatusEvent::Registered,
        "NF_DEREGISTERED" => NfStatusEvent::Deregistered,
        "NF_PROFILE_CHANGED" => NfStatusEvent::ProfileChanged,
        other => {
            return Err((
                format!("Unsupported NotificationEventType: {other}"),
                "MANDATORY_IE_INCORRECT",
            ))
        }
    };

    let nf_instance_uri = match data.get("nfInstanceUri").and_then(|v| v.as_str()) {
        Some(u) if !u.is_empty() => u,
        _ => {
            return Err((
                "nfInstanceUri is a mandatory IE".to_string(),
                "MANDATORY_IE_MISSING",
            ))
        }
    };
    let nf_instance_id = match nf_instance_uri
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
    {
        Some(id) => id.to_string(),
        None => {
            return Err((
                format!("nfInstanceUri has no instance id: {nf_instance_uri}"),
                "MANDATORY_IE_INCORRECT",
            ))
        }
    };

    let profile = match data.get("nfProfile") {
        Some(Value::Object(p)) => {
            let nf_type = p
                .get("nfType")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let nf_status = p
                .get("nfStatus")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if nf_type.is_empty() || nf_status.is_empty() {
                return Err((
                    "nfProfile must carry nfType and nfStatus".to_string(),
                    "MANDATORY_IE_MISSING",
                ));
            }
            let load = p.get("load").and_then(parse_load);
            Some((nf_type, nf_status, load))
        }
        Some(_) => {
            return Err((
                "nfProfile must be an object".to_string(),
                "MANDATORY_IE_INCORRECT",
            ))
        }
        None => None,
    };

    // TS 29.510: for NF_PROFILE_CHANGED one of nfProfile / profileChanges /
    // completeNfProfile must be present; for NF_REGISTERED, nfProfile (or
    // completeNfProfile, which we treat identically) must be present.
    let profile_changes = data.get("profileChanges").and_then(|v| v.as_array());
    match event {
        NfStatusEvent::Registered if profile.is_none() => {
            return Err((
                "NF_REGISTERED requires nfProfile".to_string(),
                "MANDATORY_IE_MISSING",
            ))
        }
        NfStatusEvent::ProfileChanged if profile.is_none() && profile_changes.is_none() => {
            return Err((
                "NF_PROFILE_CHANGED requires nfProfile or profileChanges".to_string(),
                "MANDATORY_IE_MISSING",
            ))
        }
        _ => {}
    }

    // Walk profileChanges for `/load` items (TS 29.510 ChangeItem: op, path,
    // newValue). Later items win. A malformed newValue on /load fails closed.
    let mut load_change = None;
    if let Some(changes) = profile_changes {
        for item in changes {
            let path = item.get("path").and_then(|v| v.as_str()).unwrap_or("");
            if path != "/load" {
                continue;
            }
            let op = item.get("op").and_then(|v| v.as_str()).unwrap_or("");
            match op {
                "add" | "replace" => match item.get("newValue").and_then(parse_load) {
                    Some(load) => load_change = Some(LoadChange::Set(load)),
                    None => {
                        return Err((
                            "profileChanges /load newValue must be an integer 0..=100".to_string(),
                            "MANDATORY_IE_INCORRECT",
                        ))
                    }
                },
                "remove" => load_change = Some(LoadChange::Removed),
                _ => {}
            }
        }
    }

    Ok(ParsedNfStatusNotification {
        event,
        nf_instance_id,
        profile,
        load_change,
    })
}

/// Apply a parsed notification to the shared analytics engine.
///
/// Lock order (nf-context-lock-deadlocks): the caller holds the outer context
/// read guard; this takes the interior engine mutex.
fn ingest_notification(ctx: &NwdafContext, parsed: &ParsedNfStatusNotification) {
    let mut engine = ctx.lock_engine();
    let id = parsed.nf_instance_id.as_str();

    match parsed.event {
        NfStatusEvent::Deregistered => {
            log::debug!("NFStatusNotify: NF_DEREGISTERED {id} — dropping samples");
            engine.remove_nf_instance(id);
            return;
        }
        NfStatusEvent::Registered | NfStatusEvent::ProfileChanged => {}
    }

    // Update the cached profile metadata from nfProfile when present.
    if let Some((nf_type, nf_status, load)) = &parsed.profile {
        engine.upsert_nf_meta(
            id,
            NfProfileMeta {
                nf_type: nf_type.clone(),
                nf_status: nf_status.clone(),
                last_load: *load,
            },
        );
    }

    // Determine the effective new load: profileChanges `/load` wins over the
    // (already-patched) nfProfile.load nrfd also includes.
    let effective_load = match parsed.load_change {
        Some(LoadChange::Set(load)) => Some(load),
        Some(LoadChange::Removed) => {
            if let Some(meta) = engine.nf_meta(id) {
                let mut cleared = meta.clone();
                cleared.last_load = None;
                engine.upsert_nf_meta(id, cleared);
            }
            None
        }
        None => parsed.profile.as_ref().and_then(|(_, _, load)| *load),
    };

    if let Some(load) = effective_load {
        let nf_type = engine
            .nf_meta(id)
            .map(|m| m.nf_type.clone())
            .unwrap_or_else(|| "UNKNOWN".to_string());
        if let Some(meta) = engine.nf_meta(id) {
            let mut updated = meta.clone();
            updated.last_load = Some(load);
            engine.upsert_nf_meta(id, updated);
        }
        log::debug!("NFStatusNotify: ingesting load={load} for {id} ({nf_type})");
        engine.ingest_nf_load(NfLoadSample::now(
            &nf_type,
            id,
            f64::from(load) / 100.0,
            0.0,
            0,
        ));
    }
}

/// Handle `POST /nnwdaf-nfstatus-notify/v1/notify` against an explicit
/// context (isolated-context variant for tests; mirrors the DI pilot in
/// `main.rs`).
pub async fn handle_nf_status_notify_with_ctx(
    ctx: &Arc<RwLock<NwdafContext>>,
    request: &SbiRequest,
) -> SbiResponse {
    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let data: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let parsed = match parse_notification_data(&data) {
        Ok(p) => p,
        Err((detail, cause)) => return send_bad_request(&detail, Some(cause)),
    };

    match ctx.read() {
        Ok(guard) => ingest_notification(&guard, &parsed),
        Err(e) => {
            log::error!("handle_nf_status_notify: failed to read context: {e}");
            return nextgcore_sbi::server::send_internal_error("context unavailable");
        }
    }

    // TS 29.510 §5.2.2.6: NFStatusNotify success response is 204 No Content.
    SbiResponse::with_status(204)
}

/// Handle `POST /nnwdaf-nfstatus-notify/v1/notify` (TS 29.510 NFStatusNotify
/// callback) against the global context.
pub async fn handle_nf_status_notify(request: &SbiRequest) -> SbiResponse {
    let ctx = crate::context::nwdaf_self();
    handle_nf_status_notify_with_ctx(&ctx, request).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::AnalyticsId;
    use crate::notification_dispatcher::{compute_event_infos, EventInfoFilter};
    use serde_json::json;

    fn isolated_ctx() -> Arc<RwLock<NwdafContext>> {
        let mut ctx = NwdafContext::new("nwdaf-collector-test".to_string());
        ctx.init(64);
        Arc::new(RwLock::new(ctx))
    }

    fn notify_req(body: &Value) -> SbiRequest {
        SbiRequest::post("/nnwdaf-nfstatus-notify/v1/notify")
            .with_json_body(body)
            .expect("valid JSON body")
    }

    fn nf_load_infos(ctx: &Arc<RwLock<NwdafContext>>, instance: &str) -> Vec<Value> {
        let guard = ctx.read().unwrap();
        let engine = guard.lock_engine();
        let infos = compute_event_infos(
            &engine,
            AnalyticsId::NfLoad,
            &EventInfoFilter {
                nf_instance_ids: vec![instance.to_string()],
                nf_types: Vec::new(),
            },
        );
        infos.as_array().cloned().unwrap_or_default()
    }

    // ── golden TS 29.510 NotificationData bodies (typed from the yaml /
    //    nrfd's serializer, NOT produced by any encoder in this crate) ────────

    /// NF_REGISTERED with a full `nfProfile` carrying `load` ingests one
    /// sample with `cpu = load/100` and caches the profile metadata.
    #[tokio::test]
    async fn test_notify_nf_registered_full_profile_ingests_load() {
        let ctx = isolated_ctx();
        // Golden body: TS 29.510 §5.2.2.6 NotificationData with nfProfile
        // (shape matches nrfd's build_notification_json).
        let body = json!({
            "event": "NF_REGISTERED",
            "nfInstanceUri": "http://nrf.example:7777/nnrf-nfm/v1/nf-instances/amf-g21-reg",
            "nfProfile": {
                "nfInstanceId": "amf-g21-reg",
                "nfType": "AMF",
                "nfStatus": "REGISTERED",
                "load": 40
            }
        });
        let resp = handle_nf_status_notify_with_ctx(&ctx, &notify_req(&body)).await;
        assert_eq!(resp.status, 204, "NFStatusNotify success must be 204");

        let infos = nf_load_infos(&ctx, "amf-g21-reg");
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0]["nfType"].as_str(), Some("AMF"));
        assert_eq!(infos[0]["nfLoadLevelAverage"].as_u64(), Some(40));
        assert_eq!(infos[0]["nfStatus"]["statusRegistered"].as_u64(), Some(100));
    }

    /// NF_PROFILE_CHANGED with `profileChanges` `/load` replace (nrfd's
    /// `newValue` key) ingests the new load; a subsequent add also ingests.
    #[tokio::test]
    async fn test_notify_profile_changed_load_replace_and_add() {
        let ctx = isolated_ctx();
        let register = json!({
            "event": "NF_REGISTERED",
            "nfInstanceUri": "http://nrf.example:7777/nnrf-nfm/v1/nf-instances/smf-g21-chg",
            "nfProfile": {
                "nfInstanceId": "smf-g21-chg",
                "nfType": "SMF",
                "nfStatus": "REGISTERED",
                "load": 40
            }
        });
        assert_eq!(
            handle_nf_status_notify_with_ctx(&ctx, &notify_req(&register))
                .await
                .status,
            204
        );

        // Golden replace body (matches nrfd's profileChanges serialization:
        // op/path/newValue/origValue).
        let replace = json!({
            "event": "NF_PROFILE_CHANGED",
            "nfInstanceUri": "http://nrf.example:7777/nnrf-nfm/v1/nf-instances/smf-g21-chg",
            "profileChanges": [
                { "op": "replace", "path": "/load", "newValue": 80, "origValue": 40 }
            ]
        });
        assert_eq!(
            handle_nf_status_notify_with_ctx(&ctx, &notify_req(&replace))
                .await
                .status,
            204
        );
        let infos = nf_load_infos(&ctx, "smf-g21-chg");
        // Samples [40, 80] → average 60.
        assert_eq!(infos[0]["nfLoadLevelAverage"].as_u64(), Some(60));
        assert_eq!(infos[0]["nfLoadLevelpeak"].as_u64(), Some(80));

        // add op is also accepted (TS 29.510 ChangeItem).
        let add = json!({
            "event": "NF_PROFILE_CHANGED",
            "nfInstanceUri": "http://nrf.example:7777/nnrf-nfm/v1/nf-instances/smf-g21-chg",
            "profileChanges": [
                { "op": "add", "path": "/load", "newValue": 90 }
            ]
        });
        assert_eq!(
            handle_nf_status_notify_with_ctx(&ctx, &notify_req(&add))
                .await
                .status,
            204
        );
        let infos = nf_load_infos(&ctx, "smf-g21-chg");
        // Samples [40, 80, 90] → average 70.
        assert_eq!(infos[0]["nfLoadLevelAverage"].as_u64(), Some(70));
    }

    /// `/load` remove clears the cached load without fabricating a sample;
    /// changes not touching `/load` ingest nothing new.
    #[tokio::test]
    async fn test_notify_profile_changed_load_remove_and_unrelated() {
        let ctx = isolated_ctx();
        let register = json!({
            "event": "NF_REGISTERED",
            "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/upf-g21-rm",
            "nfProfile": {
                "nfInstanceId": "upf-g21-rm",
                "nfType": "UPF",
                "nfStatus": "REGISTERED",
                "load": 50
            }
        });
        handle_nf_status_notify_with_ctx(&ctx, &notify_req(&register)).await;

        // Unrelated change (no /load) → still one sample.
        let unrelated = json!({
            "event": "NF_PROFILE_CHANGED",
            "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/upf-g21-rm",
            "profileChanges": [
                { "op": "replace", "path": "/priority", "newValue": 3 }
            ]
        });
        assert_eq!(
            handle_nf_status_notify_with_ctx(&ctx, &notify_req(&unrelated))
                .await
                .status,
            204
        );
        let infos = nf_load_infos(&ctx, "upf-g21-rm");
        assert_eq!(
            infos[0]["nfLoadLevelAverage"].as_u64(),
            Some(50),
            "an unrelated change must not add a load sample"
        );

        // /load remove → 204, no new sample (average unchanged).
        let remove = json!({
            "event": "NF_PROFILE_CHANGED",
            "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/upf-g21-rm",
            "profileChanges": [
                { "op": "remove", "path": "/load", "origValue": 50 }
            ]
        });
        assert_eq!(
            handle_nf_status_notify_with_ctx(&ctx, &notify_req(&remove))
                .await
                .status,
            204
        );
        let infos = nf_load_infos(&ctx, "upf-g21-rm");
        assert_eq!(infos[0]["nfLoadLevelAverage"].as_u64(), Some(50));
    }

    /// NF_DEREGISTERED drops the instance's samples: analytics stop reporting
    /// it (fail-closed — no data survives the NRF saying the NF is gone).
    #[tokio::test]
    async fn test_notify_nf_deregistered_drops_instance() {
        let ctx = isolated_ctx();
        let register = json!({
            "event": "NF_REGISTERED",
            "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/pcf-g21-dereg",
            "nfProfile": {
                "nfInstanceId": "pcf-g21-dereg",
                "nfType": "PCF",
                "nfStatus": "REGISTERED",
                "load": 25
            }
        });
        handle_nf_status_notify_with_ctx(&ctx, &notify_req(&register)).await;
        assert_eq!(nf_load_infos(&ctx, "pcf-g21-dereg").len(), 1);

        // Golden dereg body: no nfProfile (nrfd omits it for deregistration).
        let dereg = json!({
            "event": "NF_DEREGISTERED",
            "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/pcf-g21-dereg"
        });
        assert_eq!(
            handle_nf_status_notify_with_ctx(&ctx, &notify_req(&dereg))
                .await
                .status,
            204
        );
        assert!(
            nf_load_infos(&ctx, "pcf-g21-dereg").is_empty(),
            "a deregistered NF must vanish from NF_LOAD analytics"
        );
    }

    // ── fail-closed mandatory-IE validation ─────────────────────────────────

    #[tokio::test]
    async fn test_notify_missing_event_400() {
        let ctx = isolated_ctx();
        let body = json!({
            "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/x"
        });
        let resp = handle_nf_status_notify_with_ctx(&ctx, &notify_req(&body)).await;
        assert_eq!(resp.status, 400, "missing event must be 400");
    }

    #[tokio::test]
    async fn test_notify_missing_nf_instance_uri_400() {
        let ctx = isolated_ctx();
        let body = json!({ "event": "NF_REGISTERED" });
        let resp = handle_nf_status_notify_with_ctx(&ctx, &notify_req(&body)).await;
        assert_eq!(resp.status, 400, "missing nfInstanceUri must be 400");
    }

    #[tokio::test]
    async fn test_notify_unknown_event_400() {
        let ctx = isolated_ctx();
        let body = json!({
            "event": "NF_EXPLODED",
            "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/x"
        });
        let resp = handle_nf_status_notify_with_ctx(&ctx, &notify_req(&body)).await;
        assert_eq!(resp.status, 400, "unknown event enum must be 400");
    }

    #[tokio::test]
    async fn test_notify_registered_without_profile_400() {
        let ctx = isolated_ctx();
        let body = json!({
            "event": "NF_REGISTERED",
            "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/x"
        });
        let resp = handle_nf_status_notify_with_ctx(&ctx, &notify_req(&body)).await;
        assert_eq!(resp.status, 400, "NF_REGISTERED without nfProfile is 400");
    }

    #[tokio::test]
    async fn test_notify_profile_changed_without_payload_400() {
        let ctx = isolated_ctx();
        let body = json!({
            "event": "NF_PROFILE_CHANGED",
            "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/x"
        });
        let resp = handle_nf_status_notify_with_ctx(&ctx, &notify_req(&body)).await;
        assert_eq!(
            resp.status, 400,
            "NF_PROFILE_CHANGED without nfProfile/profileChanges is 400"
        );
    }

    #[tokio::test]
    async fn test_notify_out_of_range_load_400() {
        let ctx = isolated_ctx();
        let body = json!({
            "event": "NF_PROFILE_CHANGED",
            "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/x",
            "profileChanges": [
                { "op": "replace", "path": "/load", "newValue": 250 }
            ]
        });
        let resp = handle_nf_status_notify_with_ctx(&ctx, &notify_req(&body)).await;
        assert_eq!(
            resp.status, 400,
            "NFProfile.load is 0..=100; out-of-range must fail closed"
        );
    }

    #[tokio::test]
    async fn test_notify_malformed_json_400() {
        let ctx = isolated_ctx();
        let req = SbiRequest::post("/nnwdaf-nfstatus-notify/v1/notify")
            .with_body("{not json", "application/json");
        let resp = handle_nf_status_notify_with_ctx(&ctx, &req).await;
        assert_eq!(resp.status, 400, "malformed JSON must be 400");
    }

    /// Unknown additional fields are IGNORED (TS 29.500 SBI extensibility) —
    /// only malformed/missing mandatory IEs fail.
    #[tokio::test]
    async fn test_notify_unknown_fields_ignored() {
        let ctx = isolated_ctx();
        let body = json!({
            "event": "NF_REGISTERED",
            "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/amf-g21-ext",
            "nfProfile": {
                "nfInstanceId": "amf-g21-ext",
                "nfType": "AMF",
                "nfStatus": "REGISTERED",
                "load": 10,
                "futureRel19Field": { "x": 1 }
            },
            "someNewTopLevelField": true
        });
        let resp = handle_nf_status_notify_with_ctx(&ctx, &notify_req(&body)).await;
        assert_eq!(resp.status, 204, "unknown fields must be ignored");
        assert_eq!(nf_load_infos(&ctx, "amf-g21-ext").len(), 1);
    }

    // ── subscription body / response parsing ─────────────────────────────────

    /// The SubscriptionData we POST carries exactly the TS 29.510 fields nrfd
    /// parses: nfStatusNotificationUri (mandatory), reqNfType, reqNotifEvents;
    /// subscrCond is omitted so ALL NF instances match.
    #[test]
    fn test_subscription_body_shape() {
        let body = build_nf_status_subscription_body(
            "http://10.0.0.5:7815/nnwdaf-nfstatus-notify/v1/notify",
        );
        assert_eq!(
            body["nfStatusNotificationUri"].as_str(),
            Some("http://10.0.0.5:7815/nnwdaf-nfstatus-notify/v1/notify")
        );
        assert_eq!(body["reqNfType"].as_str(), Some("NWDAF"));
        let events: Vec<&str> = body["reqNotifEvents"]
            .as_array()
            .expect("array")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(
            events,
            vec!["NF_REGISTERED", "NF_DEREGISTERED", "NF_PROFILE_CHANGED"]
        );
        assert!(
            body.get("subscrCond").is_none(),
            "subscrCond must be omitted (subscribe to all NFs)"
        );
    }

    /// The 201 parser reads subscriptionId from the body (nrfd's
    /// subscription_response_json shape) and converts the RFC 3339
    /// validityTime to Unix seconds; it falls back to the Location header.
    #[test]
    fn test_parse_subscription_create_response() {
        // Golden body: nrfd 201 response shape.
        let body = r#"{
            "subscriptionId": "sub-123",
            "nfStatusNotificationUri": "http://cb/notify",
            "validityTime": "2026-07-01T12:00:00+00:00"
        }"#;
        let sub = parse_subscription_create_response(Some(body), None).expect("parsed");
        assert_eq!(sub.subscription_id, "sub-123");
        // 2026-07-01T12:00:00Z == 1782907200 Unix (hand-derived:
        // days(1970-01-01..2026-07-01) = 20635; 20635*86400 + 12*3600
        // = 1782864000 + 43200 = 1782907200).
        assert_eq!(sub.validity_unix, Some(1_782_907_200));

        // Location-header fallback.
        let sub =
            parse_subscription_create_response(None, Some("/nnrf-nfm/v1/subscriptions/sub-456"))
                .expect("parsed");
        assert_eq!(sub.subscription_id, "sub-456");
        assert_eq!(sub.validity_unix, None);

        // Neither → None (caller retries).
        assert!(parse_subscription_create_response(Some("{}"), None).is_none());
    }

    /// Renewal predicate: no subscription → subscribe; expiring within the
    /// margin → subscribe; healthy → leave alone. Exercised through
    /// `maybe_renew_nrf_subscription` with an unroutable NRF so the POST
    /// fails fast and the state stays observable.
    #[tokio::test]
    async fn test_maybe_renew_paths() {
        let ctx = isolated_ctx();

        // Not armed → no-op (no panic, no network).
        maybe_renew_nrf_subscription(&ctx).await;
        assert!(ctx.read().unwrap().nrf_status_subscription().is_none());

        // Armed with a healthy subscription (far-future expiry) → untouched.
        {
            let guard = ctx.read().unwrap();
            guard.set_nrf_collector_config(crate::context::NrfCollectorConfig {
                nrf_uri: "http://127.0.0.1:1".to_string(), // unroutable port
                callback_uri: "http://127.0.0.1:2/nnwdaf-nfstatus-notify/v1/notify".to_string(),
            });
            guard.set_nrf_status_subscription(Some(NrfStatusSubscription {
                subscription_id: "sub-healthy".to_string(),
                validity_unix: Some(u64::MAX),
            }));
        }
        maybe_renew_nrf_subscription(&ctx).await;
        assert_eq!(
            ctx.read()
                .unwrap()
                .nrf_status_subscription()
                .expect("kept")
                .subscription_id,
            "sub-healthy",
            "a healthy subscription must not be replaced"
        );

        // Expiring subscription → renewal attempted (POST fails against the
        // unroutable NRF, state keeps the old id — retry semantics, no panic).
        {
            let guard = ctx.read().unwrap();
            guard.set_nrf_status_subscription(Some(NrfStatusSubscription {
                subscription_id: "sub-expiring".to_string(),
                validity_unix: Some(0),
            }));
        }
        maybe_renew_nrf_subscription(&ctx).await;
        assert_eq!(
            ctx.read()
                .unwrap()
                .nrf_status_subscription()
                .expect("kept on failure")
                .subscription_id,
            "sub-expiring",
            "a failed renewal must not clear the stored subscription"
        );
    }
}
