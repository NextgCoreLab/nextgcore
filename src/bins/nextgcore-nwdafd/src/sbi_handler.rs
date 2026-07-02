//! NWDAF SBI Handler
//!
//! Implements Nnwdaf SBI services (TS 23.288):
//! - Nnwdaf_AnalyticsInfo: Analytics query and retrieval
//! - Nnwdaf_EventsSubscription: Analytics subscription management
//! - Nnwdaf_MLModelProvision: ML model provision Subscribe/Notify (nwafd-05)

use crate::context::*;
use crate::notification_dispatcher::{compute_event_infos, EventInfoFilter};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::{send_bad_request, send_not_found};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// ── query-string + S-NSSAI parsing helpers ───────────────────────────────────

/// Minimal application/x-www-form-urlencoded percent-decoder for query values.
/// Decodes `%XX` escapes and `+` → space; leaves anything else untouched.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse the query string out of a full request URI (`/path?k=v&...`) into a
/// key→value map. Keys and values are percent-decoded. Done in-handler rather
/// than relying on the server glue so unit tests can drive it directly from
/// `SbiRequest::get(uri_with_query)`.
fn parse_query(uri: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let query = match uri.split_once('?') {
        Some((_, q)) => q,
        None => return map,
    };
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        map.insert(percent_decode(k), percent_decode(v));
    }
    map
}

/// Collect the request's query parameters from BOTH sources: the query string
/// embedded in `header.uri` (unit tests build requests that way) and
/// `http.params` (the live SBI server strips the query from the path and
/// stores raw pairs there — see `server.rs` request conversion). Values from
/// `http.params` are percent-decoded and take precedence.
fn request_query_params(request: &SbiRequest) -> HashMap<String, String> {
    let mut map = parse_query(&request.header.uri);
    for (k, v) in &request.http.params {
        map.insert(percent_decode(k), percent_decode(v));
    }
    map
}

/// Parse an S-NSSAI JSON object (`{ "sst": <int>, "sd": <hex-string|int> }`).
fn parse_snssai(v: &serde_json::Value) -> Option<SNssai> {
    let sst = v.get("sst").and_then(|x| x.as_u64())? as u8;
    let sd = v.get("sd").and_then(|x| {
        x.as_u64().or_else(|| {
            x.as_str()
                .and_then(|s| u32::from_str_radix(s, 16).ok())
                .map(u64::from)
        })
    });
    Some(SNssai {
        sst,
        sd: sd.map(|n| n as u32),
    })
}

/// Echo a stored `EventSubscription` back as a TS 29.520 `EventSubscription`
/// JSON object (used in the 201/200 subscription bodies).
fn event_subscription_json(e: &EventSubscription) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("event".to_string(), serde_json::json!(e.event.as_str()));
    if let Some(nm) = e.notification_method {
        obj.insert(
            "notificationMethod".to_string(),
            serde_json::json!(nm.as_str()),
        );
    }
    if let Some(rp) = e.rep_period_secs {
        obj.insert(
            "extraReportReq".to_string(),
            serde_json::json!({ "repPeriod": rp }),
        );
    }
    if !e.snssais.is_empty() {
        obj.insert(
            "snssais".to_string(),
            serde_json::json!(e
                .snssais
                .iter()
                .map(|s| serde_json::json!({ "sst": s.sst, "sd": s.sd }))
                .collect::<Vec<_>>()),
        );
    }
    serde_json::Value::Object(obj)
}

/// Parse the `event-filter` query parameter (TS 29.520 `EventFilter`, JSON in
/// the query per the AnalyticsInfo yaml) into an [`EventInfoFilter`]. Only the
/// `nfInstanceIds`/`nfTypes` members are honored (G2-1); other members are
/// ignored. `None` param → no filter; present-but-invalid JSON → `Err` (400).
fn parse_event_filter(raw: Option<&String>) -> Result<EventInfoFilter, String> {
    let raw = match raw {
        Some(r) if !r.is_empty() => r,
        _ => return Ok(EventInfoFilter::none()),
    };
    let v: serde_json::Value = serde_json::from_str(raw)
        .map_err(|e| format!("event-filter is not valid EventFilter JSON: {e}"))?;
    let string_array = |key: &str| -> Vec<String> {
        v.get(key)
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|s| s.as_str())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default()
    };
    Ok(EventInfoFilter {
        nf_instance_ids: string_array("nfInstanceIds"),
        nf_types: string_array("nfTypes"),
    })
}

/// Handle Nnwdaf_AnalyticsInfo query against an explicit context
/// (isolated-context variant used by tests; mirrors the DI pilot in `main.rs`).
///
/// TS 29.520 §4.3.2.2.2: `GET /analytics` with an `event-id` query parameter
/// (plus optional `event-filter`, `tgt-ue`, `ana-req`, `supported-features`)
/// and **no** request body; the 200 response is an `AnalyticsData` object
/// whose per-event `*Infos` array matches the requested event.
///
/// G2-1: analytics come from the **shared** NRF-fed engine in the context —
/// never a fresh per-request engine, never a synthetic sample. When the
/// requested analytics data does not exist (empty infos) the response is
/// **204 No Content** per TS 29.520 §4.3.2.2.2 ("If the requested NWDAF
/// Analytics data does not exist, the NWDAF shall respond with 204") — this
/// is the shared G2-1/G2-3 boundary piece, landed here because G2-1 merges
/// first.
///
/// T5.4 HONESTY NOTE: the analytics engine uses linear regression (slope on
/// the last N samples), NOT a trained ML model. `confidence` is the regression
/// R² scaled to a Uinteger, not model accuracy (TS 23.288 §6.14).
pub async fn handle_analytics_info_query_with_ctx(
    ctx: &Arc<RwLock<NwdafContext>>,
    request: &SbiRequest,
) -> SbiResponse {
    log::info!("Analytics Info Query: {}", request.header.uri);

    let params = request_query_params(request);

    let event_token = match params.get("event-id") {
        Some(t) if !t.is_empty() => t.as_str(),
        _ => {
            return send_bad_request(
                "event-id query parameter is mandatory",
                Some("MANDATORY_QUERY_PARAM_INCORRECT"),
            )
        }
    };

    let analytics_id = match AnalyticsId::from_str(event_token) {
        Some(id) => id,
        None => {
            return send_bad_request(
                &format!("Invalid event-id: {event_token}"),
                Some("INVALID_ANALYTICS_TYPE"),
            )
        }
    };

    // event-filter (G2-1): nfInstanceIds/nfTypes are honored; malformed JSON
    // fails closed with 400.
    let filter = match parse_event_filter(params.get("event-filter")) {
        Ok(f) => f,
        Err(detail) => return send_bad_request(&detail, Some("INVALID_QUERY_PARAM")),
    };

    // tgt-ue / ana-req / supported-features are parsed and acknowledged; only
    // tgt-ue is echoed back. Full filtering by these is out of scope here.
    let tgt_ue = params.get("tgt-ue").cloned();
    let _ana_req = params.get("ana-req");
    let _supported_features = params.get("supported-features");

    // Lock order (nf-context-lock-deadlocks): context read → engine mutex.
    let infos = match ctx.read() {
        Ok(guard) => {
            let engine = guard.lock_engine();
            compute_event_infos(&engine, analytics_id, &filter)
        }
        Err(e) => {
            log::error!("handle_analytics_info_query: failed to read context: {e}");
            return nextgcore_sbi::server::send_internal_error("context unavailable");
        }
    };

    // TS 29.520 §4.3.2.2.2: requested analytics data does not exist → 204.
    if infos.as_array().is_none_or(|a| a.is_empty()) {
        return SbiResponse::with_status(204);
    }

    let now = chrono::Utc::now();
    let start = now.to_rfc3339();
    let expiry = (now + chrono::Duration::seconds(3600)).to_rfc3339();

    // Build the AnalyticsData object with the event-specific *Infos key.
    let mut analytics_data = serde_json::Map::new();
    analytics_data.insert(analytics_id.infos_key().to_string(), infos);
    analytics_data.insert("start".to_string(), serde_json::json!(start));
    analytics_data.insert("expiry".to_string(), serde_json::json!(expiry));
    analytics_data.insert(
        "timeStampGen".to_string(),
        serde_json::json!(now.to_rfc3339()),
    );
    if let Some(t) = tgt_ue {
        analytics_data.insert("tgtUe".to_string(), serde_json::json!(t));
    }

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::Value::Object(analytics_data))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Handle Nnwdaf_AnalyticsInfo query against the global context.
pub async fn handle_analytics_info_query(request: &SbiRequest) -> SbiResponse {
    let ctx = nwdaf_self();
    handle_analytics_info_query_with_ctx(&ctx, request).await
}

/// Shared parser for the `NnwdafEventsSubscription` request body used by both
/// POST (create) and PUT (update, TS 29.520 §5.1.3.3.3.2). Builds the
/// `AnalyticsSubscription` keyed by `subscription_id`. On a validation failure
/// returns a tiny `(detail, cause)` pair the caller turns into a 400 (keeps the
/// Err variant small — clippy::result_large_err).
fn parse_events_subscription(
    request: &SbiRequest,
    subscription_id: String,
) -> Result<AnalyticsSubscription, (String, &'static str)> {
    let body = match &request.http.content {
        Some(content) => content,
        None => return Err(("Missing request body".to_string(), "MISSING_BODY")),
    };
    let data: serde_json::Value =
        serde_json::from_str(body).map_err(|e| (format!("Invalid JSON: {e}"), "INVALID_JSON"))?;

    // nwafd-09: notificationURI (exact casing), mandatory — no localhost default.
    let notification_uri = match data.get("notificationURI").and_then(|v| v.as_str()) {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => {
            return Err((
                "notificationURI is a mandatory IE".to_string(),
                "MANDATORY_IE_MISSING",
            ))
        }
    };

    let event_array = match data.get("eventSubscriptions").and_then(|v| v.as_array()) {
        Some(arr) if !arr.is_empty() => arr,
        _ => {
            return Err((
                "eventSubscriptions is a mandatory IE and must be non-empty".to_string(),
                "MANDATORY_IE_MISSING",
            ))
        }
    };

    let mut events: Vec<EventSubscription> = Vec::with_capacity(event_array.len());
    for es in event_array {
        let event_token = es.get("event").and_then(|v| v.as_str()).unwrap_or("");
        let event = match AnalyticsId::from_str(event_token) {
            Some(e) => e,
            None => {
                return Err((
                    format!("Invalid or missing event: {event_token}"),
                    "INVALID_ANALYTICS_TYPE",
                ))
            }
        };

        let notification_method = es
            .get("notificationMethod")
            .and_then(|v| v.as_str())
            .and_then(NotificationMethod::from_wire);

        let rep_period_secs = es
            .get("extraReportReq")
            .and_then(|v| v.get("repPeriod"))
            .and_then(|v| v.as_u64());

        // TS 29.520 EventSubscription threshold source depends on the event:
        //  - SLICE_LOAD_LEVEL / NSI_LOAD_LEVEL use the scalar `loadLevelThreshold`.
        //  - NF_LOAD (and other NF-load events) use `nfLoadLvlThds[].nfLoadLevel`
        //    (ThresholdLevel, §5.1.6.2.30), falling back to `nfCpuUsage`.
        let load_level_threshold = match event {
            AnalyticsId::SliceLoadLevel | AnalyticsId::NsiLoadLevel => {
                es.get("loadLevelThreshold").and_then(|v| v.as_u64())
            }
            _ => es
                .get("nfLoadLvlThds")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|t| {
                    t.get("nfLoadLevel")
                        .or_else(|| t.get("nfCpuUsage"))
                        .and_then(|v| v.as_u64())
                }),
        };

        let matching_dir = es
            .get("matchingDir")
            .and_then(|v| v.as_str())
            .map(String::from);

        let snssais = es
            .get("snssais")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(parse_snssai).collect())
            .unwrap_or_default();

        // G2-1: per-event NF filters (TS 29.520 EventSubscription
        // `nfInstanceIds` / `nfTypes`), honored by NF_LOAD computation.
        let string_array = |key: &str| -> Vec<String> {
            es.get(key)
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|s| s.as_str())
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default()
        };
        let nf_instance_ids = string_array("nfInstanceIds");
        let nf_types = string_array("nfTypes");

        events.push(EventSubscription {
            event,
            notification_method,
            rep_period_secs,
            load_level_threshold,
            matching_dir,
            snssais,
            nf_instance_ids,
            nf_types,
        });
    }

    let notif_corr_id = data
        .get("notifCorrId")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| format!("corr-{}", uuid::Uuid::new_v4()));

    let expiry_seconds = data
        .get("expiryTime")
        .and_then(|v| v.as_u64())
        .unwrap_or(3600);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("value expected")
        .as_secs();

    let rep_period = events.first().and_then(|e| e.rep_period_secs).or(Some(60));
    let first_snssai = events.first().and_then(|e| e.snssais.first()).cloned();
    let tgt_supi = data
        .get("eventSubscriptions")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|e| e.get("tgtUe"))
        .and_then(|t| t.get("supi"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let mut subscription = AnalyticsSubscription::new_with_events(
        subscription_id,
        events,
        notification_uri,
        now + expiry_seconds,
    );
    subscription.notification_correlation_id = notif_corr_id;
    subscription.repetition_period_secs = rep_period;
    if let Some(supi) = tgt_supi {
        subscription = subscription.with_target_supi(supi);
    }
    if let Some(s) = first_snssai {
        subscription = subscription.with_target_snssai(s);
    }
    Ok(subscription)
}

/// Build the 200/201 body echoing the stored subscription representation.
fn events_subscription_echo(sub: &AnalyticsSubscription) -> serde_json::Value {
    serde_json::json!({
        "subscriptionId": sub.subscription_id,
        "notificationURI": sub.notification_uri,
        "notifCorrId": sub.notification_correlation_id,
        "eventSubscriptions": sub
            .events
            .iter()
            .map(event_subscription_json)
            .collect::<Vec<_>>(),
    })
}

/// Handle analytics subscription creation (POST /subscriptions).
pub async fn handle_subscription_create(request: &SbiRequest) -> SbiResponse {
    log::info!("Analytics Subscription Create");

    let subscription_id = format!("sub-{}", uuid::Uuid::new_v4());
    let subscription = match parse_events_subscription(request, subscription_id) {
        Ok(s) => s,
        Err((detail, cause)) => return send_bad_request(&detail, Some(cause)),
    };
    let echo = events_subscription_echo(&subscription);

    let ctx = nwdaf_self();
    let result = if let Ok(context) = ctx.read() {
        context.add_subscription(subscription)
    } else {
        None
    };

    match result {
        Some(sub_id) => SbiResponse::with_status(201)
            .with_header(
                "Location",
                format!("/nnwdaf-eventssubscription/v1/subscriptions/{sub_id}"),
            )
            .with_json_body(&echo)
            .unwrap_or_else(|_| SbiResponse::with_status(201)),
        None => send_bad_request("Failed to create subscription", Some("SUBSCRIPTION_FAILED")),
    }
}

/// Handle `PUT /nnwdaf-eventssubscription/v1/subscriptions/{id}` — replace an
/// existing Individual NWDAF Events Subscription (TS 29.520 §5.1.3.3.3.2,
/// UpdateNWDAFEventsSubscription). 200 + representation on success, 404 if the
/// subscription is unknown.
pub async fn handle_subscription_update(
    subscription_id: &str,
    request: &SbiRequest,
) -> SbiResponse {
    log::info!("Analytics Subscription Update: {subscription_id}");

    let subscription = match parse_events_subscription(request, subscription_id.to_string()) {
        Ok(s) => s,
        Err((detail, cause)) => return send_bad_request(&detail, Some(cause)),
    };
    let echo = events_subscription_echo(&subscription);

    let ctx = nwdaf_self();
    let updated = if let Ok(context) = ctx.read() {
        context.update_subscription(subscription)
    } else {
        false
    };

    if updated {
        SbiResponse::with_status(200)
            .with_json_body(&echo)
            .unwrap_or_else(|_| SbiResponse::with_status(200))
    } else {
        send_not_found(
            &format!("Subscription {subscription_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        )
    }
}

/// Handle subscription retrieval
pub async fn handle_subscription_get(subscription_id: &str) -> SbiResponse {
    log::debug!("Get subscription: {subscription_id}");

    let ctx = nwdaf_self();
    let subscription = if let Ok(context) = ctx.read() {
        context.get_subscription(subscription_id)
    } else {
        None
    };

    match subscription {
        Some(sub) => SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({
                "subscriptionId": sub.subscription_id,
                "notificationURI": sub.notification_uri,
                "notifCorrId": sub.notification_correlation_id,
                "eventSubscriptions": sub
                    .events
                    .iter()
                    .map(event_subscription_json)
                    .collect::<Vec<_>>(),
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("Subscription {subscription_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        ),
    }
}

/// Handle subscription deletion
pub async fn handle_subscription_delete(subscription_id: &str) -> SbiResponse {
    log::info!("Delete subscription: {subscription_id}");

    let ctx = nwdaf_self();
    let removed = if let Ok(context) = ctx.read() {
        context.remove_subscription(subscription_id)
    } else {
        None
    };

    match removed {
        Some(_) => SbiResponse::with_status(204),
        None => send_not_found(
            &format!("Subscription {subscription_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        ),
    }
}

// ── Nnwdaf_MLModelProvision: Subscribe/Notify (nwafd-05, TS 29.520) ──────────

/// Parse the request body of an ML-provision subscription POST/PUT into JSON.
/// On failure returns a small `(detail, cause)` pair the caller turns into a
/// 400 `ProblemDetails` (keeps the `Err` variant tiny — `clippy::result_large_err`).
fn ml_prov_request_json(
    request: &SbiRequest,
) -> Result<serde_json::Value, (&'static str, &'static str)> {
    let body = match &request.http.content {
        Some(content) => content,
        None => return Err(("Missing request body", "MISSING_BODY")),
    };
    serde_json::from_str(body).map_err(|_| ("Invalid request body JSON", "INVALID_JSON"))
}

/// Handle `POST /nnwdaf-mlmodelprovision/v1/subscriptions`.
///
/// TS 29.520 `NwdafMLModelProvSubsc`: requires `notifUri` and a non-empty
/// `mLEventSubscs[]`. On success returns 201 with a `Location` header pointing
/// at `/nnwdaf-mlmodelprovision/v1/subscriptions/{subscriptionId}` and echoes
/// the subscription representation. There is no `/models` resource.
pub async fn handle_ml_prov_subscription_create(request: &SbiRequest) -> SbiResponse {
    log::info!("ML Model Provision subscribe");

    let data = match ml_prov_request_json(request) {
        Ok(d) => d,
        Err((detail, cause)) => return send_bad_request(detail, Some(cause)),
    };

    let parsed = match crate::ml_service::parse_ml_model_prov_subsc(&data) {
        Ok(p) => p,
        Err(detail) => return send_bad_request(&detail, Some("MANDATORY_IE_MISSING")),
    };

    let subscription_id = format!("mlsub-{}", uuid::Uuid::new_v4());
    let sub = MlProvSubscription::new(
        subscription_id.clone(),
        parsed.notif_uri,
        parsed.notif_corr_id,
        parsed.ml_events,
    );

    let ctx = nwdaf_self();
    let result = if let Ok(context) = ctx.read() {
        context.add_ml_prov_subscription(sub.clone())
    } else {
        None
    };

    match result {
        Some(sub_id) => SbiResponse::with_status(201)
            .with_header(
                "Location",
                format!("/nnwdaf-mlmodelprovision/v1/subscriptions/{sub_id}"),
            )
            .with_json_body(&crate::ml_service::ml_prov_subsc_json(&sub))
            .unwrap_or_else(|_| SbiResponse::with_status(201)),
        None => send_bad_request(
            "Failed to create ML-provision subscription",
            Some("SUBSCRIPTION_FAILED"),
        ),
    }
}

/// Handle `PUT /nnwdaf-mlmodelprovision/v1/subscriptions/{id}` — replace an
/// existing ML-provision subscription. 200 + representation on success, 404 if
/// the subscription is unknown.
pub async fn handle_ml_prov_subscription_update(
    subscription_id: &str,
    request: &SbiRequest,
) -> SbiResponse {
    log::info!("ML Model Provision update: {subscription_id}");

    let data = match ml_prov_request_json(request) {
        Ok(d) => d,
        Err((detail, cause)) => return send_bad_request(detail, Some(cause)),
    };

    let parsed = match crate::ml_service::parse_ml_model_prov_subsc(&data) {
        Ok(p) => p,
        Err(detail) => return send_bad_request(&detail, Some("MANDATORY_IE_MISSING")),
    };

    let sub = MlProvSubscription::new(
        subscription_id.to_string(),
        parsed.notif_uri,
        parsed.notif_corr_id,
        parsed.ml_events,
    );

    let ctx = nwdaf_self();
    let updated = if let Ok(context) = ctx.read() {
        context.update_ml_prov_subscription(sub.clone())
    } else {
        false
    };

    if updated {
        SbiResponse::with_status(200)
            .with_json_body(&crate::ml_service::ml_prov_subsc_json(&sub))
            .unwrap_or_else(|_| SbiResponse::with_status(200))
    } else {
        send_not_found(
            &format!("ML-provision subscription {subscription_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        )
    }
}

/// Handle `DELETE /nnwdaf-mlmodelprovision/v1/subscriptions/{id}`.
pub async fn handle_ml_prov_subscription_delete(subscription_id: &str) -> SbiResponse {
    log::info!("ML Model Provision delete: {subscription_id}");

    let ctx = nwdaf_self();
    let removed = if let Ok(context) = ctx.read() {
        context.remove_ml_prov_subscription(subscription_id)
    } else {
        None
    };

    match removed {
        Some(_) => SbiResponse::with_status(204),
        None => send_not_found(
            &format!("ML-provision subscription {subscription_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn body_json(resp: &SbiResponse) -> Value {
        resp.json_body::<Value>()
            .expect("response body must be valid JSON")
    }

    // ── query / S-NSSAI parsing helpers ──────────────────────────────────────

    #[test]
    fn test_parse_query_decodes_pairs() {
        let q = parse_query("/analytics?event-id=NF_LOAD&tgt-ue=imsi-1%2C2&empty=");
        assert_eq!(q.get("event-id").map(String::as_str), Some("NF_LOAD"));
        assert_eq!(q.get("tgt-ue").map(String::as_str), Some("imsi-1,2"));
        assert_eq!(q.get("empty").map(String::as_str), Some(""));
        // No query string at all → empty map.
        assert!(parse_query("/analytics").is_empty());
    }

    // ── nwafd-02 / G2-1: Nnwdaf_AnalyticsInfo GET → AnalyticsData ────────────

    /// Isolated context with NRF-style load samples ingested for one instance
    /// (G2-1: analytics data only ever comes from ingested NRF samples).
    fn ctx_with_loads(nf_type: &str, instance: &str, loads: &[u8]) -> Arc<RwLock<NwdafContext>> {
        let mut ctx = NwdafContext::new("nwdaf-handler-test".to_string());
        ctx.init(64);
        {
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
        Arc::new(RwLock::new(ctx))
    }

    /// A GET with `event-id=NF_LOAD` (with ingested data) returns 200 and an
    /// `AnalyticsData` object carrying the per-event `nfLoadLevelInfos` array
    /// plus `start`/`expiry`/`timeStampGen`, and NONE of the legacy
    /// `modelCount`/`analyticsReport` keys.
    #[tokio::test]
    async fn test_analytics_info_get_returns_analytics_data() {
        let ctx = ctx_with_loads("AMF", "amf-get-01", &[30, 40]);
        let req =
            SbiRequest::get("/nnwdaf-analyticsinfo/v1/analytics?event-id=NF_LOAD&tgt-ue=imsi-001");
        let resp = handle_analytics_info_query_with_ctx(&ctx, &req).await;
        assert_eq!(
            resp.status, 200,
            "GET with a valid event-id and existing data must be 200"
        );

        let body = body_json(&resp);
        let infos = body
            .get("nfLoadLevelInfos")
            .and_then(|v| v.as_array())
            .expect("AnalyticsData must carry an nfLoadLevelInfos array for NF_LOAD");
        assert!(
            !infos.is_empty(),
            "NF_LOAD AnalyticsData should carry at least one NfLoadLevelInformation"
        );
        assert_eq!(
            infos[0]["nfLoadLevelAverage"].as_u64(),
            Some(35),
            "the reported average must derive from the ingested loads (30, 40)"
        );
        assert!(body.get("start").and_then(|v| v.as_str()).is_some());
        assert!(body.get("expiry").and_then(|v| v.as_str()).is_some());
        assert!(body.get("timeStampGen").and_then(|v| v.as_str()).is_some());
        assert_eq!(body.get("tgtUe").and_then(|v| v.as_str()), Some("imsi-001"));

        // Legacy bespoke keys must be gone.
        assert!(body.get("modelCount").is_none(), "no modelCount key");
        assert!(
            body.get("analyticsReport").is_none(),
            "no analyticsReport key"
        );
        assert!(body.get("models").is_none(), "no models key");
    }

    /// G2-1 fail-closed acceptance: with NO ingested data the response is
    /// **204 No Content** (TS 29.520 §4.3.2.2.2), never a fabricated 200.
    #[tokio::test]
    async fn test_analytics_info_no_data_204() {
        let mut inner = NwdafContext::new("nwdaf-empty-test".to_string());
        inner.init(64);
        let ctx = Arc::new(RwLock::new(inner));

        let req = SbiRequest::get("/nnwdaf-analyticsinfo/v1/analytics?event-id=NF_LOAD");
        let resp = handle_analytics_info_query_with_ctx(&ctx, &req).await;
        assert_eq!(
            resp.status, 204,
            "no analytics data must be 204, not a fabricated 200"
        );
        assert!(
            resp.http.content.as_deref().is_none_or(str::is_empty),
            "204 must carry no body"
        );
    }

    /// G2-1: the `event-filter` query parameter (TS 29.520 EventFilter JSON)
    /// restricts the reported instances; a filter matching nothing → 204.
    #[tokio::test]
    async fn test_analytics_info_event_filter_honored() {
        let ctx = ctx_with_loads("AMF", "amf-filter-01", &[50]);
        {
            let guard = ctx.read().unwrap();
            let mut engine = guard.lock_engine();
            engine.ingest_nf_load(crate::analytics::NfLoadSample::now(
                "SMF",
                "smf-filter-01",
                0.7,
                0.0,
                0,
            ));
        }

        // Filter to the SMF instance only (percent-encoded EventFilter JSON).
        let uri = "/nnwdaf-analyticsinfo/v1/analytics?event-id=NF_LOAD&event-filter=%7B%22nfInstanceIds%22%3A%5B%22smf-filter-01%22%5D%7D";
        let resp = handle_analytics_info_query_with_ctx(&ctx, &SbiRequest::get(uri)).await;
        assert_eq!(resp.status, 200);
        let infos = body_json(&resp)["nfLoadLevelInfos"]
            .as_array()
            .cloned()
            .expect("array");
        assert_eq!(infos.len(), 1, "filter must restrict to one instance");
        assert_eq!(infos[0]["nfInstanceId"].as_str(), Some("smf-filter-01"));

        // nfTypes filter.
        let uri = "/nnwdaf-analyticsinfo/v1/analytics?event-id=NF_LOAD&event-filter=%7B%22nfTypes%22%3A%5B%22AMF%22%5D%7D";
        let resp = handle_analytics_info_query_with_ctx(&ctx, &SbiRequest::get(uri)).await;
        assert_eq!(resp.status, 200);
        let infos = body_json(&resp)["nfLoadLevelInfos"]
            .as_array()
            .cloned()
            .expect("array");
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0]["nfType"].as_str(), Some("AMF"));

        // Filter matching nothing → 204 (data "does not exist" for the query).
        let uri = "/nnwdaf-analyticsinfo/v1/analytics?event-id=NF_LOAD&event-filter=%7B%22nfInstanceIds%22%3A%5B%22absent%22%5D%7D";
        let resp = handle_analytics_info_query_with_ctx(&ctx, &SbiRequest::get(uri)).await;
        assert_eq!(resp.status, 204);
    }

    /// A malformed `event-filter` (not JSON) fails closed with 400.
    #[tokio::test]
    async fn test_analytics_info_bad_event_filter_400() {
        let ctx = ctx_with_loads("AMF", "amf-badfilter-01", &[50]);
        let uri = "/nnwdaf-analyticsinfo/v1/analytics?event-id=NF_LOAD&event-filter=not-json";
        let resp = handle_analytics_info_query_with_ctx(&ctx, &SbiRequest::get(uri)).await;
        assert_eq!(resp.status, 400, "malformed event-filter must be 400");
    }

    /// A GET with no `event-id` query parameter is rejected with 400.
    #[tokio::test]
    async fn test_analytics_info_missing_event_id_400() {
        let req = SbiRequest::get("/nnwdaf-analyticsinfo/v1/analytics");
        let resp = handle_analytics_info_query(&req).await;
        assert_eq!(resp.status, 400, "missing event-id must be a 400");
    }

    /// A GET with an unrecognised `event-id` token is rejected with 400.
    #[tokio::test]
    async fn test_analytics_info_invalid_event_id_400() {
        let req = SbiRequest::get("/nnwdaf-analyticsinfo/v1/analytics?event-id=NOT_AN_EVENT");
        let resp = handle_analytics_info_query(&req).await;
        assert_eq!(resp.status, 400, "invalid event-id must be a 400");
    }

    /// G2-1: the subscription parser stores per-event `nfInstanceIds` and
    /// `nfTypes` (TS 29.520 EventSubscription) for dispatcher-side filtering.
    #[tokio::test]
    async fn test_subscription_parses_nf_filters() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        let create = SbiRequest::post("/nnwdaf-eventssubscription/v1/subscriptions")
            .with_json_body(&json!({
                "notificationURI": "http://amf.example.org/notify",
                "eventSubscriptions": [{
                    "event": "NF_LOAD",
                    "nfInstanceIds": ["amf-1", "amf-2"],
                    "nfTypes": ["AMF"]
                }]
            }))
            .expect("valid JSON body");
        let resp = handle_subscription_create(&create).await;
        assert_eq!(resp.status, 201);
        let sub_id = body_json(&resp)["subscriptionId"]
            .as_str()
            .expect("subscriptionId")
            .to_string();

        let ctx = nwdaf_self();
        let stored = ctx
            .read()
            .unwrap()
            .get_subscription(&sub_id)
            .expect("subscription");
        assert_eq!(stored.events[0].nf_instance_ids, vec!["amf-1", "amf-2"]);
        assert_eq!(stored.events[0].nf_types, vec!["AMF"]);
    }

    // ── nwafd-03 / nwafd-09: Nnwdaf_EventsSubscription create ─────────────────

    /// A conformant `NnwdafEventsSubscription` body (`notificationURI` +
    /// `eventSubscriptions[]`) yields 201, a Location header pointing at the new
    /// subscription, and a body echoing the standard field names.
    #[tokio::test]
    async fn test_subscription_create_conformant_201() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);

        let req = SbiRequest::post("/nnwdaf-eventssubscription/v1/subscriptions")
            .with_json_body(&json!({
                "notificationURI": "http://amf.example.org:8080/nnwdaf-notify",
                "notifCorrId": "corr-xyz",
                "eventSubscriptions": [
                    {
                        "event": "NF_LOAD",
                        "notificationMethod": "PERIODIC",
                        "extraReportReq": { "repPeriod": 120 }
                    }
                ]
            }))
            .expect("valid JSON body");

        let resp = handle_subscription_create(&req).await;
        assert_eq!(resp.status, 201, "conformant subscription must be 201");

        let location = resp
            .http
            .get_header("Location")
            .expect("201 must carry a Location header");
        assert!(
            location.starts_with("/nnwdaf-eventssubscription/v1/subscriptions/"),
            "Location must point at the subscriptions collection, got {location}"
        );

        let body = body_json(&resp);
        assert!(body
            .get("subscriptionId")
            .and_then(|v| v.as_str())
            .is_some());
        assert_eq!(
            body.get("notificationURI").and_then(|v| v.as_str()),
            Some("http://amf.example.org:8080/nnwdaf-notify"),
            "notificationURI must be echoed with exact casing"
        );
        assert_eq!(
            body.get("notifCorrId").and_then(|v| v.as_str()),
            Some("corr-xyz"),
            "consumer-supplied notifCorrId must be echoed, not regenerated"
        );
        let events = body
            .get("eventSubscriptions")
            .and_then(|v| v.as_array())
            .expect("eventSubscriptions must be echoed as an array");
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].get("event").and_then(|v| v.as_str()),
            Some("NF_LOAD")
        );
    }

    /// `eventSubscriptions` absent → 400 (mandatory IE, minItems 1).
    #[tokio::test]
    async fn test_subscription_create_missing_event_subscriptions_400() {
        let req = SbiRequest::post("/nnwdaf-eventssubscription/v1/subscriptions")
            .with_json_body(&json!({
                "notificationURI": "http://amf.example.org/notify"
            }))
            .expect("valid JSON body");
        let resp = handle_subscription_create(&req).await;
        assert_eq!(resp.status, 400, "absent eventSubscriptions must be a 400");
    }

    /// An empty `eventSubscriptions` array → 400 (minItems 1).
    #[tokio::test]
    async fn test_subscription_create_empty_event_subscriptions_400() {
        let req = SbiRequest::post("/nnwdaf-eventssubscription/v1/subscriptions")
            .with_json_body(&json!({
                "notificationURI": "http://amf.example.org/notify",
                "eventSubscriptions": []
            }))
            .expect("valid JSON body");
        let resp = handle_subscription_create(&req).await;
        assert_eq!(resp.status, 400, "empty eventSubscriptions must be a 400");
    }

    /// nwafd-09: the lowercase legacy `notificationUri` is NOT accepted — a body
    /// that only carries the legacy casing is treated as missing → 400, and no
    /// localhost default is substituted.
    #[tokio::test]
    async fn test_subscription_create_legacy_lowercase_uri_400() {
        let req = SbiRequest::post("/nnwdaf-eventssubscription/v1/subscriptions")
            .with_json_body(&json!({
                "analyticsId": "NF_LOAD",
                "notificationUri": "http://amf.example.org/notify"
            }))
            .expect("valid JSON body");
        let resp = handle_subscription_create(&req).await;
        assert_eq!(
            resp.status, 400,
            "legacy lowercase notificationUri must not satisfy the mandatory notificationURI IE"
        );
    }

    /// nwafd-09: `notificationURI` absent (but events present) → 400.
    #[tokio::test]
    async fn test_subscription_create_missing_notification_uri_400() {
        let req = SbiRequest::post("/nnwdaf-eventssubscription/v1/subscriptions")
            .with_json_body(&json!({
                "eventSubscriptions": [ { "event": "NF_LOAD" } ]
            }))
            .expect("valid JSON body");
        let resp = handle_subscription_create(&req).await;
        assert_eq!(resp.status, 400, "missing notificationURI must be a 400");
    }

    /// nwafd-09: the subscription GET response emits `notificationURI` (capital
    /// I), never the legacy lowercase spelling.
    #[tokio::test]
    async fn test_subscription_get_emits_notification_uri_casing() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);

        let create = SbiRequest::post("/nnwdaf-eventssubscription/v1/subscriptions")
            .with_json_body(&json!({
                "notificationURI": "http://smf.example.org/notify",
                "eventSubscriptions": [ { "event": "SLICE_LOAD_LEVEL" } ]
            }))
            .expect("valid JSON body");
        let create_resp = handle_subscription_create(&create).await;
        assert_eq!(create_resp.status, 201);
        let sub_id = body_json(&create_resp)["subscriptionId"]
            .as_str()
            .expect("subscriptionId")
            .to_string();

        let get_resp = handle_subscription_get(&sub_id).await;
        assert_eq!(get_resp.status, 200);
        let body = body_json(&get_resp);
        assert_eq!(
            body.get("notificationURI").and_then(|v| v.as_str()),
            Some("http://smf.example.org/notify")
        );
        assert!(
            body.get("notificationUri").is_none(),
            "GET body must not carry the legacy lowercase notificationUri key"
        );
    }

    // ── nwafd-05: Nnwdaf_MLModelProvision Subscribe/Notify ────────────────────

    /// POST a conformant `NwdafMLModelProvSubsc` → 201, a Location pointing at
    /// the `/subscriptions/{id}` resource (never `/models`), and a body echoing
    /// the `NwdafMLModelProvSubsc` representation.
    #[tokio::test]
    async fn test_ml_prov_subscribe_201() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);

        let req = SbiRequest::post("/nnwdaf-mlmodelprovision/v1/subscriptions")
            .with_json_body(&json!({
                "notifUri": "http://anlf.example.org/ml-cb",
                "notifCorreId": "corr-ml-1",
                "mLEventSubscs": [
                    { "mLEvent": "NF_LOAD", "mLEventFilter": {} }
                ]
            }))
            .expect("valid JSON body");

        let resp = handle_ml_prov_subscription_create(&req).await;
        assert_eq!(resp.status, 201, "conformant ML-prov subscribe must be 201");

        let location = resp
            .http
            .get_header("Location")
            .expect("201 must carry a Location header");
        assert!(
            location.starts_with("/nnwdaf-mlmodelprovision/v1/subscriptions/"),
            "Location must point at the subscriptions collection, got {location}"
        );
        assert!(
            !location.contains("/models"),
            "the bespoke /models resource must be gone"
        );

        let body = body_json(&resp);
        assert_eq!(
            body.get("notifUri").and_then(|v| v.as_str()),
            Some("http://anlf.example.org/ml-cb")
        );
        assert_eq!(
            body.get("notifCorreId").and_then(|v| v.as_str()),
            Some("corr-ml-1")
        );
        let events = body
            .get("mLEventSubscs")
            .and_then(|v| v.as_array())
            .expect("mLEventSubscs echoed as an array");
        assert_eq!(
            events[0].get("mLEvent").and_then(|v| v.as_str()),
            Some("NF_LOAD")
        );
    }

    /// Missing `notifUri` (a required IE) → 400.
    #[tokio::test]
    async fn test_ml_prov_subscribe_missing_notif_uri_400() {
        let req = SbiRequest::post("/nnwdaf-mlmodelprovision/v1/subscriptions")
            .with_json_body(&json!({
                "mLEventSubscs": [ { "mLEvent": "NF_LOAD" } ]
            }))
            .expect("valid JSON body");
        let resp = handle_ml_prov_subscription_create(&req).await;
        assert_eq!(resp.status, 400, "missing notifUri must be a 400");
    }

    /// PUT updates an existing subscription (200) and 404s an unknown id;
    /// DELETE removes it (204) then 404s.
    #[tokio::test]
    async fn test_ml_prov_update_and_delete() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);

        let create = SbiRequest::post("/nnwdaf-mlmodelprovision/v1/subscriptions")
            .with_json_body(&json!({
                "notifUri": "http://anlf.example.org/ml-cb",
                "mLEventSubscs": [ { "mLEvent": "NF_LOAD" } ]
            }))
            .expect("valid JSON body");
        let create_resp = handle_ml_prov_subscription_create(&create).await;
        assert_eq!(create_resp.status, 201);
        let sub_id = body_json(&create_resp)["subscriptionId"]
            .as_str()
            .expect("subscriptionId")
            .to_string();

        // PUT a known id → 200 + updated representation.
        let put = SbiRequest::put(format!(
            "/nnwdaf-mlmodelprovision/v1/subscriptions/{sub_id}"
        ))
        .with_json_body(&json!({
            "notifUri": "http://anlf.example.org/ml-cb2",
            "mLEventSubscs": [ { "mLEvent": "UE_MOBILITY" } ]
        }))
        .expect("valid JSON body");
        let put_resp = handle_ml_prov_subscription_update(&sub_id, &put).await;
        assert_eq!(put_resp.status, 200);
        let put_body = body_json(&put_resp);
        assert_eq!(
            put_body["notifUri"].as_str(),
            Some("http://anlf.example.org/ml-cb2")
        );

        // PUT an unknown id → 404.
        let put_missing = SbiRequest::put("/nnwdaf-mlmodelprovision/v1/subscriptions/nope")
            .with_json_body(&json!({
                "notifUri": "http://x/y",
                "mLEventSubscs": [ { "mLEvent": "NF_LOAD" } ]
            }))
            .expect("valid JSON body");
        let put_missing_resp = handle_ml_prov_subscription_update("nope", &put_missing).await;
        assert_eq!(put_missing_resp.status, 404);

        // DELETE the known id → 204, then 404 on the second attempt.
        assert_eq!(
            handle_ml_prov_subscription_delete(&sub_id).await.status,
            204
        );
        assert_eq!(
            handle_ml_prov_subscription_delete(&sub_id).await.status,
            404
        );
    }

    #[tokio::test]
    async fn test_subscription_put_updates_and_404s() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        let create = SbiRequest::post("/nnwdaf-eventssubscription/v1/subscriptions")
            .with_json_body(&json!({
                "notificationURI": "http://amf.example.org/notify",
                "eventSubscriptions": [ { "event": "NF_LOAD" } ]
            }))
            .expect("valid JSON body");
        let create_resp = handle_subscription_create(&create).await;
        assert_eq!(create_resp.status, 201);
        let sub_id = body_json(&create_resp)["subscriptionId"]
            .as_str()
            .expect("subscriptionId")
            .to_string();

        let put = SbiRequest::put(format!(
            "/nnwdaf-eventssubscription/v1/subscriptions/{sub_id}"
        ))
        .with_json_body(&json!({
            "notificationURI": "http://amf.example.org/notify2",
            "eventSubscriptions": [ { "event": "UE_MOBILITY" } ]
        }))
        .expect("valid JSON body");
        let put_resp = handle_subscription_update(&sub_id, &put).await;
        assert_eq!(
            put_resp.status, 200,
            "PUT on an existing subscription must be 200"
        );
        let put_body = body_json(&put_resp);
        assert_eq!(
            put_body["notificationURI"].as_str(),
            Some("http://amf.example.org/notify2")
        );
        assert_eq!(put_body["subscriptionId"].as_str(), Some(sub_id.as_str()));
        assert_eq!(
            put_body["eventSubscriptions"][0]["event"].as_str(),
            Some("UE_MOBILITY")
        );

        // GET must now reflect the replaced representation.
        let get_resp = handle_subscription_get(&sub_id).await;
        assert_eq!(get_resp.status, 200);
        assert_eq!(
            body_json(&get_resp)["eventSubscriptions"][0]["event"].as_str(),
            Some("UE_MOBILITY")
        );

        // PUT an unknown id -> 404.
        let put_missing = SbiRequest::put("/nnwdaf-eventssubscription/v1/subscriptions/nope")
            .with_json_body(&json!({
                "notificationURI": "http://x/y",
                "eventSubscriptions": [ { "event": "NF_LOAD" } ]
            }))
            .expect("valid JSON body");
        assert_eq!(
            handle_subscription_update("nope", &put_missing)
                .await
                .status,
            404
        );
    }

    #[tokio::test]
    async fn test_nf_load_threshold_parsed_from_nf_load_level() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        let create = SbiRequest::post("/nnwdaf-eventssubscription/v1/subscriptions")
            .with_json_body(&json!({
                "notificationURI": "http://amf.example.org/notify",
                "eventSubscriptions": [{
                    "event": "NF_LOAD",
                    "notificationMethod": "THRESHOLD",
                    "matchingDir": "ASCENDING",
                    "nfLoadLvlThds": [ { "nfLoadLevel": 55 } ]
                }]
            }))
            .expect("valid JSON body");
        let resp = handle_subscription_create(&create).await;
        assert_eq!(resp.status, 201);
        let sub_id = body_json(&resp)["subscriptionId"]
            .as_str()
            .expect("subscriptionId")
            .to_string();

        let ctx = nwdaf_self();
        let stored = ctx
            .read()
            .unwrap()
            .get_subscription(&sub_id)
            .expect("subscription");
        assert_eq!(
            stored.events[0].load_level_threshold,
            Some(55),
            "NF_LOAD threshold must be read from nfLoadLvlThds[].nfLoadLevel, not the absent `loadLevel` field"
        );
    }
}
