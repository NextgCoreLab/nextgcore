//! NWDAF SBI Handler
//!
//! Implements Nnwdaf SBI services (TS 23.288):
//! - Nnwdaf_AnalyticsInfo: Analytics query and retrieval
//! - Nnwdaf_EventsSubscription: Analytics subscription management
//! - Nnwdaf_MLModelProvision: ML model provision Subscribe/Notify (nwafd-05)

use crate::analytics::AnalyticsEngine;
use crate::context::*;
use crate::notification_dispatcher::compute_event_infos;
use ogs_sbi::message::{SbiRequest, SbiResponse};
use ogs_sbi::server::{send_bad_request, send_not_found};
use std::collections::HashMap;

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

/// Parse an S-NSSAI JSON object (`{ "sst": <int>, "sd": <hex-string|int> }`).
fn parse_snssai(v: &serde_json::Value) -> Option<SNssai> {
    let sst = v.get("sst").and_then(|x| x.as_u64())? as u8;
    let sd = v.get("sd").and_then(|x| {
        x.as_u64()
            .or_else(|| x.as_str().and_then(|s| u32::from_str_radix(s, 16).ok()).map(u64::from))
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

/// Handle Nnwdaf_AnalyticsInfo query.
///
/// TS 29.520 §4.3.2.2.2: `GET /analytics` with an `event-id` query parameter
/// (plus optional `tgt-ue`, `ana-req`, `supported-features`) and **no** request
/// body; the 200 response is an `AnalyticsData` object whose per-event `*Infos`
/// array matches the requested event.
///
/// T5.4 HONESTY NOTE: the analytics engine uses linear regression (slope on the
/// last N samples), NOT a trained ML model. The reported figures and any
/// `confidence` are sample-count derived, not model accuracy; if
/// Nnwdaf_MLModelProvision models are integrated this should switch to
/// model-accuracy metrics (TS 23.288 §6.14).
pub async fn handle_analytics_info_query(request: &SbiRequest) -> SbiResponse {
    log::info!("Analytics Info Query: {}", request.header.uri);

    let params = parse_query(&request.header.uri);

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

    // tgt-ue / ana-req / supported-features are parsed and acknowledged; only
    // tgt-ue is echoed back. Full filtering by these is out of scope here.
    let tgt_ue = params.get("tgt-ue").cloned();
    let _ana_req = params.get("ana-req");
    let _supported_features = params.get("supported-features");

    let mut engine = AnalyticsEngine::new();
    let infos = compute_event_infos(&mut engine, analytics_id);

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

/// Handle analytics subscription creation.
///
/// TS 29.520 `NnwdafEventsSubscription`: parses `notificationURI` (mandatory),
/// `notifCorrId` (optional), and `eventSubscriptions[]` (mandatory, minItems 1).
/// Each `EventSubscription` carries `event`, optional `notificationMethod`,
/// `extraReportReq.repPeriod`, threshold fields and per-event `snssais` filters.
pub async fn handle_subscription_create(request: &SbiRequest) -> SbiResponse {
    log::info!("Analytics Subscription Create");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    // nwafd-09: notificationURI (exact casing), mandatory — no localhost default.
    let notification_uri = match data.get("notificationURI").and_then(|v| v.as_str()) {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => {
            return send_bad_request(
                "notificationURI is a mandatory IE",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };

    // eventSubscriptions[] is mandatory with minItems 1.
    let event_array = match data.get("eventSubscriptions").and_then(|v| v.as_array()) {
        Some(arr) if !arr.is_empty() => arr,
        _ => {
            return send_bad_request(
                "eventSubscriptions is a mandatory IE and must be non-empty",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };

    let mut events: Vec<EventSubscription> = Vec::with_capacity(event_array.len());
    for es in event_array {
        let event_token = es.get("event").and_then(|v| v.as_str()).unwrap_or("");
        let event = match AnalyticsId::from_str(event_token) {
            Some(e) => e,
            None => {
                return send_bad_request(
                    &format!("Invalid or missing event: {event_token}"),
                    Some("INVALID_ANALYTICS_TYPE"),
                )
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

        // loadLevelThreshold, or the loadLevel of the first nfLoadLvlThds entry.
        let load_level_threshold = es
            .get("loadLevelThreshold")
            .and_then(|v| v.as_u64())
            .or_else(|| {
                es.get("nfLoadLvlThds")
                    .and_then(|v| v.as_array())
                    .and_then(|a| a.first())
                    .and_then(|t| t.get("loadLevel"))
                    .and_then(|v| v.as_u64())
            });

        let matching_dir = es
            .get("matchingDir")
            .and_then(|v| v.as_str())
            .map(String::from);

        let snssais = es
            .get("snssais")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(parse_snssai).collect())
            .unwrap_or_default();

        events.push(EventSubscription {
            event,
            notification_method,
            rep_period_secs,
            load_level_threshold,
            matching_dir,
            snssais,
        });
    }

    // notifCorrId from the consumer; generate only if truly absent.
    let notif_corr_id = data
        .get("notifCorrId")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| format!("corr-{}", uuid::Uuid::new_v4()));

    // Optional legacy expiry hint (seconds-from-now); defaults to one hour.
    let expiry_seconds = data
        .get("expiryTime")
        .and_then(|v| v.as_u64())
        .unwrap_or(3600);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("value expected")
        .as_secs();

    // Derive periodicity + target from the events before they are moved.
    let rep_period = events
        .first()
        .and_then(|e| e.rep_period_secs)
        .or(Some(60));
    let first_snssai = events.first().and_then(|e| e.snssais.first()).cloned();
    let tgt_supi = data
        .get("eventSubscriptions")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|e| e.get("tgtUe"))
        .and_then(|t| t.get("supi"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let echo_events: Vec<serde_json::Value> = events.iter().map(event_subscription_json).collect();

    let subscription_id = format!("sub-{}", uuid::Uuid::new_v4());
    let mut subscription = AnalyticsSubscription::new_with_events(
        subscription_id.clone(),
        events,
        notification_uri.clone(),
        now + expiry_seconds,
    );
    subscription.notification_correlation_id = notif_corr_id.clone();
    subscription.repetition_period_secs = rep_period;
    if let Some(supi) = tgt_supi {
        subscription = subscription.with_target_supi(supi);
    }
    if let Some(s) = first_snssai {
        subscription = subscription.with_target_snssai(s);
    }

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
            .with_json_body(&serde_json::json!({
                "subscriptionId": sub_id,
                "notificationURI": notification_uri,
                "notifCorrId": notif_corr_id,
                "eventSubscriptions": echo_events,
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(201)),
        None => send_bad_request("Failed to create subscription", Some("SUBSCRIPTION_FAILED")),
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

    // ── nwafd-02: Nnwdaf_AnalyticsInfo GET → AnalyticsData ────────────────────

    /// A GET with `event-id=NF_LOAD` returns 200 and an `AnalyticsData` object
    /// carrying the per-event `nfLoadLevelInfos` array plus `start`/`expiry`/
    /// `timeStampGen`, and NONE of the legacy `modelCount`/`analyticsReport`
    /// keys.
    #[tokio::test]
    async fn test_analytics_info_get_returns_analytics_data() {
        let req = SbiRequest::get("/nnwdaf-analyticsinfo/v1/analytics?event-id=NF_LOAD&tgt-ue=imsi-001");
        let resp = handle_analytics_info_query(&req).await;
        assert_eq!(resp.status, 200, "GET with a valid event-id must be 200");

        let body = body_json(&resp);
        let infos = body
            .get("nfLoadLevelInfos")
            .and_then(|v| v.as_array())
            .expect("AnalyticsData must carry an nfLoadLevelInfos array for NF_LOAD");
        assert!(
            !infos.is_empty(),
            "NF_LOAD AnalyticsData should carry at least one NfLoadLevelInformation"
        );
        assert!(body.get("start").and_then(|v| v.as_str()).is_some());
        assert!(body.get("expiry").and_then(|v| v.as_str()).is_some());
        assert!(body.get("timeStampGen").and_then(|v| v.as_str()).is_some());
        assert_eq!(body.get("tgtUe").and_then(|v| v.as_str()), Some("imsi-001"));

        // Legacy bespoke keys must be gone.
        assert!(body.get("modelCount").is_none(), "no modelCount key");
        assert!(body.get("analyticsReport").is_none(), "no analyticsReport key");
        assert!(body.get("models").is_none(), "no models key");
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
        assert!(body.get("subscriptionId").and_then(|v| v.as_str()).is_some());
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
        assert_eq!(events[0].get("event").and_then(|v| v.as_str()), Some("NF_LOAD"));
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
        assert_eq!(events[0].get("mLEvent").and_then(|v| v.as_str()), Some("NF_LOAD"));
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
        assert_eq!(handle_ml_prov_subscription_delete(&sub_id).await.status, 204);
        assert_eq!(handle_ml_prov_subscription_delete(&sub_id).await.status, 404);
    }
}
