//! Namf HTTP/2 SBI server resources (TS 29.518)
//!
//! Server-side implementation of the AMF's own SBI services:
//! - Namf_Communication (§6.1): N1N2MessageTransfer, UEContextTransfer,
//!   RegistrationStatusUpdate
//! - Namf_EventExposure (§6.2): Subscribe / Unsubscribe / Modify with real
//!   HTTP POST notification delivery to the subscribed notify URI
//! - Namf_MT (§6.3): EnableUeReachability, ProvideDomainSelectionInfo
//! - Namf_Location (§6.4): ProvidePositioningInfo
//!
//! All error outcomes carry ProblemDetails bodies per TS 29.500 §5.2.7.
//! Malformed input returns 400 — handlers never panic on bad bodies.

use nextgcore_sbi::client::SbiClient;
use nextgcore_sbi::message::{ProblemDetails, SbiRequest, SbiResponse};
use nextgcore_sbi::server::{send_error, send_method_not_allowed, send_not_found};
use serde_json::{json, Value};

use crate::context::{
    amf_self, AmfSess, AmfUe, EventSubscription, NrCgi, PendingPositioningDl, PlmnId,
    PositioningDlKind, RanUe, Tai5gs, UeContextTransferState, NEXTGCORE_INVALID_POOL_ID,
};
use crate::namf_handler::{
    self, N1N2MessageTransferCause, N1N2MessageTransferReqData, N2InfoContainer, NgapIeType,
};

/// Notification client connect timeout (bounded so notification tasks can
/// never hang)
const NOTIFY_CONNECT_TIMEOUT_SECS: u64 = 2;
/// Notification client request timeout
const NOTIFY_REQUEST_TIMEOUT_SECS: u64 = 3;

// ============================================================================
// Request router
// ============================================================================

/// Top-level Namf SBI request handler. Routes all Namf services served by
/// the AMF (TS 29.518): namf-comm, namf-evts, namf-mt, namf-loc.
pub async fn namf_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.clone();
    let uri = request.header.uri.clone();
    log::debug!("AMF SBI request: {method} {uri}");

    let path = uri.split('?').next().unwrap_or(&uri);
    let parts: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    if parts.len() < 3 {
        return send_not_found(
            "Invalid resource path",
            Some("RESOURCE_URI_STRUCTURE_NOT_FOUND"),
        );
    }

    let service = parts[0];
    let method = method.as_str();

    match service {
        // --------------------------------------------------------------
        // Namf_EventExposure (TS 29.518 §6.2)
        //   POST   /namf-evts/v1/subscriptions
        //   PATCH  /namf-evts/v1/subscriptions/{subscriptionId}
        //   DELETE /namf-evts/v1/subscriptions/{subscriptionId}
        // --------------------------------------------------------------
        "namf-evts" if parts[2] == "subscriptions" => match (method, parts.len()) {
            ("POST", 3) => handle_event_subscription_create(&request),
            ("PATCH", 4) => handle_event_subscription_modify(parts[3], &request),
            ("DELETE", 4) => handle_event_subscription_delete(parts[3]),
            _ => send_method_not_allowed(method, path),
        },

        // --------------------------------------------------------------
        // Namf_Communication (TS 29.518 §6.1)
        //   POST /namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages
        //   POST /namf-comm/v1/ue-contexts/{ueContextId}/transfer
        //   POST /namf-comm/v1/ue-contexts/{ueContextId}/transfer-update
        // --------------------------------------------------------------
        "namf-comm" if parts[2] == "ue-contexts" && parts.len() >= 5 => {
            let ue_context_id = parts[3];
            match (method, parts[4]) {
                ("POST", "n1-n2-messages") => {
                    handle_n1_n2_message_transfer_request(ue_context_id, &request)
                }
                ("POST", "transfer") => handle_ue_context_transfer(ue_context_id, &request),
                ("POST", "transfer-update") => {
                    handle_registration_status_update(ue_context_id, &request)
                }
                _ => send_method_not_allowed(method, path),
            }
        }

        // --------------------------------------------------------------
        // Namf_MT (TS 29.518 §6.3)
        //   POST /namf-mt/v1/ue-contexts/{ueContextId}/ue-reachind
        //   GET  /namf-mt/v1/ue-contexts/{ueContextId}?info-class=...
        // --------------------------------------------------------------
        "namf-mt" if parts[2] == "ue-contexts" => match (method, parts.len()) {
            ("POST", 5) if parts[4] == "ue-reachind" => {
                handle_enable_ue_reachability(parts[3], &request)
            }
            ("GET", 4) => handle_mt_ue_context_info(parts[3], &request),
            _ => send_method_not_allowed(method, path),
        },

        // --------------------------------------------------------------
        // Namf_Location (TS 29.518 §6.4)
        //   POST /namf-loc/v1/{ueContextId}/provide-pos-info
        // --------------------------------------------------------------
        "namf-loc" if parts.len() == 4 && parts[3] == "provide-pos-info" && method == "POST" => {
            handle_provide_positioning_info(parts[2], &request)
        }

        _ => {
            log::warn!("Unknown AMF SBI request: {method} {uri}");
            send_not_found(
                &format!("No resource for {method} {path}"),
                Some("RESOURCE_URI_STRUCTURE_NOT_FOUND"),
            )
        }
    }
}

// ============================================================================
// Shared helpers
// ============================================================================

/// Parse the request body as JSON, or None when missing/malformed
fn parse_json_body(request: &SbiRequest) -> Option<Value> {
    request
        .http
        .content
        .as_deref()
        .and_then(|body| serde_json::from_str(body).ok())
}

/// 400 with ProblemDetails cause MANDATORY_IE_MISSING (TS 29.500 Table 5.2.7.2-1)
fn mandatory_ie_missing(attr: &str) -> SbiResponse {
    send_error(
        400,
        "Bad Request",
        &format!("Mandatory attribute '{attr}' is missing"),
        Some("MANDATORY_IE_MISSING"),
    )
}

/// 400 with ProblemDetails cause MANDATORY_IE_INCORRECT
fn mandatory_ie_incorrect(attr: &str, detail: &str) -> SbiResponse {
    send_error(
        400,
        "Bad Request",
        &format!("Attribute '{attr}' is incorrect: {detail}"),
        Some("MANDATORY_IE_INCORRECT"),
    )
}

/// 400 for an unparseable body
fn malformed_body() -> SbiResponse {
    send_error(
        400,
        "Bad Request",
        "Request body is missing or not valid JSON",
        Some("INVALID_MSG_FORMAT"),
    )
}

/// 404 with ProblemDetails cause CONTEXT_NOT_FOUND (TS 29.518 §6.1.7.3)
fn context_not_found(ue_context_id: &str) -> SbiResponse {
    send_error(
        404,
        "Not Found",
        &format!("UE context '{ue_context_id}' not found"),
        Some("CONTEXT_NOT_FOUND"),
    )
}

/// Look up a UE by its ueContextId path component. Supports the SUPI forms
/// (imsi-..., nai-...) per TS 29.518 §6.1.3.2.2.
fn find_ue_by_context_id(ue_context_id: &str) -> Option<AmfUe> {
    let ctx = amf_self();
    let guard = ctx.read().ok()?;
    if ue_context_id.starts_with("imsi-") || ue_context_id.starts_with("nai-") {
        guard.amf_ue_find_by_supi(ue_context_id)
    } else {
        None
    }
}

/// CM state check: the UE is CM-CONNECTED when it has a live RAN UE context
fn ue_ran_context(ue: &AmfUe) -> Option<RanUe> {
    if ue.ran_ue_id == NEXTGCORE_INVALID_POOL_ID {
        return None;
    }
    let ctx = amf_self();
    let guard = ctx.read().ok()?;
    guard.ran_ue_find_by_id(ue.ran_ue_id)
}

/// Encode a PlmnId as TS 29.571 JSON ({"mcc": "...", "mnc": "..."})
fn plmn_id_json(plmn: &PlmnId) -> Value {
    let mcc = format!("{}{}{}", plmn.mcc1, plmn.mcc2, plmn.mcc3);
    let mnc = if plmn.mnc3 == 0xf {
        format!("{}{}", plmn.mnc1, plmn.mnc2)
    } else {
        format!("{}{}{}", plmn.mnc1, plmn.mnc2, plmn.mnc3)
    };
    json!({ "mcc": mcc, "mnc": mnc })
}

/// Encode an NCGI as TS 29.571 JSON (nrCellId: 9 hex digits / 36 bits)
fn ncgi_json(ncgi: &NrCgi) -> Value {
    json!({
        "plmnId": plmn_id_json(&ncgi.plmn_id),
        "nrCellId": format!("{:09X}", ncgi.cell_id & 0xF_FFFF_FFFF),
    })
}

/// Encode a TAI as TS 29.571 JSON (tac: 4 or 6 hex digits)
fn tai_json(tai: &Tai5gs) -> Value {
    let tac = if tai.tac > 0xFFFF {
        format!("{:06X}", tai.tac & 0xFF_FFFF)
    } else {
        format!("{:04X}", tai.tac)
    };
    json!({ "plmnId": plmn_id_json(&tai.plmn_id), "tac": tac })
}

/// NrLocation user-location JSON for a UE (TS 29.571 UserLocation)
fn nr_location_json(ue: &AmfUe) -> Value {
    json!({
        "nrLocation": {
            "tai": tai_json(&ue.nr_tai),
            "ncgi": ncgi_json(&ue.nr_cgi),
        }
    })
}

// ============================================================================
// RFC 3339 DateTime helpers (3GPP DateTime, TS 29.571)
// ============================================================================

/// Convert days-since-epoch to (year, month, day) — Howard Hinnant's
/// civil_from_days algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Inverse of `civil_from_days`: (year, month, day) to days-since-epoch
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

/// Format a SystemTime as an RFC 3339 UTC timestamp
fn system_time_to_rfc3339(t: std::time::SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

/// Current time as an RFC 3339 UTC timestamp
fn rfc3339_now() -> String {
    system_time_to_rfc3339(std::time::SystemTime::now())
}

/// Parse an RFC 3339 timestamp ("YYYY-MM-DDTHH:MM:SS[.frac](Z|±hh:mm)") into
/// a SystemTime. Returns None on malformed input (never panics).
fn rfc3339_to_system_time(s: &str) -> Option<std::time::SystemTime> {
    let bytes = s.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    let num = |range: std::ops::Range<usize>| -> Option<i64> { s.get(range)?.parse::<i64>().ok() };
    if bytes[4] != b'-' || bytes[7] != b'-' || (bytes[10] != b'T' && bytes[10] != b't') {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)? as u32, num(8..10)? as u32);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(0..24).contains(&h) || !(0..60).contains(&mi) || !(0..61).contains(&sec) {
        return None;
    }
    // Skip fractional seconds, then parse the offset
    let mut idx = 19;
    if bytes.get(idx) == Some(&b'.') {
        idx += 1;
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
    }
    let offset_secs: i64 = match bytes.get(idx) {
        Some(b'Z') | Some(b'z') => 0,
        Some(sign @ (b'+' | b'-')) => {
            let oh = num(idx + 1..idx + 3)?;
            let om = num(idx + 4..idx + 6)?;
            let v = oh * 3600 + om * 60;
            if *sign == b'+' {
                v
            } else {
                -v
            }
        }
        _ => return None,
    };
    let days = days_from_civil(y, mo, d);
    let epoch_secs = days * 86_400 + h * 3600 + mi * 60 + sec - offset_secs;
    if epoch_secs < 0 {
        return Some(std::time::UNIX_EPOCH);
    }
    Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(epoch_secs as u64))
}

// ============================================================================
// Namf_EventExposure — subscription resource handlers (TS 29.518 §6.2)
// ============================================================================

/// Known AMF event types (TS 29.518 AmfEventType)
const AMF_EVENT_TYPES: &[&str] = &[
    "LOCATION_REPORT",
    "PRESENCE_IN_AOI_REPORT",
    "TIMEZONE_REPORT",
    "ACCESS_TYPE_REPORT",
    "REGISTRATION_STATE_REPORT",
    "CONNECTIVITY_STATE_REPORT",
    "REACHABILITY_REPORT",
    "COMMUNICATION_FAILURE_REPORT",
    "UES_IN_AREA_REPORT",
    "SUBSCRIPTION_ID_CHANGE",
    "SUBSCRIPTION_ID_ADDITION",
    "LOSS_OF_CONNECTIVITY",
];

/// Rebuild the AmfEventSubscription JSON echo from the stored subscription
fn subscription_echo_json(sub: &EventSubscription) -> Value {
    let mut subscription = json!({
        "eventList": sub.event_types.iter()
            .map(|t| json!({"type": t}))
            .collect::<Vec<_>>(),
        "eventNotifyUri": sub.notify_uri,
        "notifyCorrelationId": sub.notify_correlation_id,
        "nfId": sub.nf_id,
    });
    if let Some(supi) = &sub.supi {
        subscription["supi"] = json!(supi);
    }
    if sub.any_ue {
        subscription["anyUE"] = json!(true);
    }
    if let Some(expiry) = sub.expiry {
        subscription["options"] = json!({
            "trigger": "CONTINUOUS",
            "expiry": system_time_to_rfc3339(expiry),
        });
    }
    subscription
}

/// POST /namf-evts/v1/subscriptions — Namf_EventExposure_Subscribe
/// (TS 29.518 §5.3.2.2.2). Persists the subscription in the AMF context and
/// returns 201 with Location + AmfCreatedEventSubscription.
fn handle_event_subscription_create(request: &SbiRequest) -> SbiResponse {
    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };
    let Some(subscription) = body.get("subscription") else {
        return mandatory_ie_missing("subscription");
    };

    // Mandatory attributes per TS 29.518 Table 6.2.6.2.3-1
    let Some(notify_uri) = subscription.get("eventNotifyUri").and_then(Value::as_str) else {
        return mandatory_ie_missing("subscription.eventNotifyUri");
    };
    let Some(correlation_id) = subscription
        .get("notifyCorrelationId")
        .and_then(Value::as_str)
    else {
        return mandatory_ie_missing("subscription.notifyCorrelationId");
    };
    let Some(nf_id) = subscription.get("nfId").and_then(Value::as_str) else {
        return mandatory_ie_missing("subscription.nfId");
    };
    let Some(event_list) = subscription.get("eventList").and_then(Value::as_array) else {
        return mandatory_ie_missing("subscription.eventList");
    };
    if event_list.is_empty() {
        return mandatory_ie_incorrect("subscription.eventList", "must contain at least one event");
    }
    if parse_http_uri(notify_uri).is_none() {
        return mandatory_ie_incorrect("subscription.eventNotifyUri", "not a valid HTTP URI");
    }

    let mut event_types = Vec::new();
    let mut immediate_types = Vec::new();
    for event in event_list {
        let Some(event_type) = event.get("type").and_then(Value::as_str) else {
            return mandatory_ie_missing("subscription.eventList[].type");
        };
        if !AMF_EVENT_TYPES.contains(&event_type) {
            return mandatory_ie_incorrect(
                "subscription.eventList[].type",
                &format!("unknown event type '{event_type}'"),
            );
        }
        if event
            .get("immediateFlag")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            immediate_types.push(event_type.to_string());
        }
        event_types.push(event_type.to_string());
    }

    let supi = subscription
        .get("supi")
        .and_then(Value::as_str)
        .map(String::from);
    let any_ue = subscription
        .get("anyUE")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if supi.is_none() && !any_ue {
        // TS 29.518: the subscription must target a UE (supi/gpsi/pei/groupId)
        // or set anyUE.
        return mandatory_ie_missing("subscription.supi or subscription.anyUE");
    }

    // Optional expiry: AmfEventMode.expiry (options) or top-level expiry
    let expiry_str = subscription
        .pointer("/options/expiry")
        .or_else(|| subscription.get("expiry"))
        .and_then(Value::as_str);
    let expiry = match expiry_str {
        Some(s) => match rfc3339_to_system_time(s) {
            Some(t) => Some(t),
            None => {
                return mandatory_ie_incorrect("subscription.options.expiry", "invalid DateTime");
            }
        },
        None => None,
    };

    let subscription_id = format!("sub-{}", uuid::Uuid::new_v4());
    let sub = EventSubscription {
        subscription_id: subscription_id.clone(),
        notify_uri: notify_uri.to_string(),
        notify_correlation_id: correlation_id.to_string(),
        nf_id: nf_id.to_string(),
        event_types,
        supi: supi.clone(),
        any_ue,
        expiry,
    };

    // Immediate reports for events with immediateFlag (current state)
    let report_list = build_immediate_reports(&immediate_types, supi.as_deref());

    let ctx = amf_self();
    {
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        // Opportunistic cleanup of expired subscriptions
        guard.event_subscriptions_remove_expired();
        if !guard.event_subscription_add(sub.clone()) {
            return send_error(
                500,
                "Internal Server Error",
                "subscription ID collision",
                None,
            );
        }
    }

    log::info!(
        "Event subscription created: id={subscription_id}, events={:?}, notifyUri={notify_uri}",
        sub.event_types
    );

    let mut response_body = json!({
        "subscription": subscription_echo_json(&sub),
        "subscriptionId": subscription_id,
    });
    if !report_list.is_empty() {
        response_body["reportList"] = json!(report_list);
    }

    let location = format!("/namf-evts/v1/subscriptions/{subscription_id}");
    match SbiResponse::with_status(201).with_json_body(&response_body) {
        Ok(resp) => resp.with_header("location", location),
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

/// Build immediate event reports for the subscribed UE's current state
fn build_immediate_reports(immediate_types: &[String], supi: Option<&str>) -> Vec<Value> {
    let Some(supi) = supi else {
        return Vec::new();
    };
    let Some(ue) = find_ue_by_context_id(supi) else {
        return Vec::new();
    };
    immediate_types
        .iter()
        .filter_map(|event_type| {
            let extra = match event_type.as_str() {
                "LOCATION_REPORT" => json!({ "location": nr_location_json(&ue) }),
                "REGISTRATION_STATE_REPORT" => json!({
                    "rmInfoList": [{ "rmState": "REGISTERED", "accessType": "3GPP_ACCESS" }]
                }),
                "REACHABILITY_REPORT" => {
                    let reachable = ue_ran_context(&ue).is_some();
                    json!({ "reachability": if reachable { "REACHABLE" } else { "UNREACHABLE" } })
                }
                "CONNECTIVITY_STATE_REPORT" => {
                    let connected = ue_ran_context(&ue).is_some();
                    json!({
                        "cmInfoList": [{
                            "cmState": if connected { "CONNECTED" } else { "IDLE" },
                            "accessType": "3GPP_ACCESS"
                        }]
                    })
                }
                _ => return None,
            };
            Some(build_event_report(event_type, Some(supi), extra))
        })
        .collect()
}

/// PATCH /namf-evts/v1/subscriptions/{subscriptionId} —
/// Namf_EventExposure_Subscribe (modify). Accepts the
/// AmfUpdateEventSubscriptionItem array form (op/path/value); only
/// `replace` of eventNotifyUri, eventList and options/expiry is supported.
fn handle_event_subscription_modify(subscription_id: &str, request: &SbiRequest) -> SbiResponse {
    let ctx = amf_self();
    let existing = {
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        guard.event_subscription_find(subscription_id)
    };
    let Some(mut sub) = existing else {
        return send_error(
            404,
            "Not Found",
            &format!("Subscription '{subscription_id}' not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        );
    };

    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };
    let Some(items) = body.as_array() else {
        return malformed_body();
    };

    for item in items {
        let op = item.get("op").and_then(Value::as_str).unwrap_or("");
        let path = item.get("path").and_then(Value::as_str).unwrap_or("");
        let value = item.get("value");
        match (op, path) {
            ("replace", "/subscription/eventNotifyUri") => {
                let Some(uri) = value.and_then(Value::as_str) else {
                    return mandatory_ie_incorrect("value", "eventNotifyUri must be a string");
                };
                if parse_http_uri(uri).is_none() {
                    return mandatory_ie_incorrect("value", "not a valid HTTP URI");
                }
                sub.notify_uri = uri.to_string();
            }
            ("replace", "/subscription/eventList") => {
                let Some(list) = value.and_then(Value::as_array) else {
                    return mandatory_ie_incorrect("value", "eventList must be an array");
                };
                let mut event_types = Vec::new();
                for event in list {
                    let Some(t) = event.get("type").and_then(Value::as_str) else {
                        return mandatory_ie_missing("value[].type");
                    };
                    if !AMF_EVENT_TYPES.contains(&t) {
                        return mandatory_ie_incorrect("value[].type", "unknown event type");
                    }
                    event_types.push(t.to_string());
                }
                if event_types.is_empty() {
                    return mandatory_ie_incorrect("value", "eventList must not be empty");
                }
                sub.event_types = event_types;
            }
            ("replace", "/subscription/options/expiry") => {
                let Some(expiry) = value
                    .and_then(Value::as_str)
                    .and_then(rfc3339_to_system_time)
                else {
                    return mandatory_ie_incorrect("value", "invalid DateTime");
                };
                sub.expiry = Some(expiry);
            }
            _ => {
                return mandatory_ie_incorrect(
                    "op/path",
                    &format!("unsupported patch item op='{op}' path='{path}'"),
                );
            }
        }
    }

    let updated = {
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        guard.event_subscription_update(sub.clone())
    };
    if !updated {
        return send_error(
            404,
            "Not Found",
            &format!("Subscription '{subscription_id}' not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        );
    }

    let response_body = json!({ "subscription": subscription_echo_json(&sub) });
    match SbiResponse::ok().with_json_body(&response_body) {
        Ok(resp) => resp,
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

/// DELETE /namf-evts/v1/subscriptions/{subscriptionId} —
/// Namf_EventExposure_Unsubscribe (TS 29.518 §5.3.2.3). 204 on success,
/// 404 when the subscription does not exist.
fn handle_event_subscription_delete(subscription_id: &str) -> SbiResponse {
    let ctx = amf_self();
    let removed = {
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        guard.event_subscription_remove(subscription_id)
    };
    match removed {
        Some(_) => {
            log::info!("Event subscription removed: {subscription_id}");
            SbiResponse::no_content()
        }
        None => send_error(
            404,
            "Not Found",
            &format!("Subscription '{subscription_id}' not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        ),
    }
}

// ============================================================================
// Namf_EventExposure — notification delivery (TS 29.518 §6.2.5.2)
// ============================================================================

/// Build a notification SBI client with bounded connect/request timeouts
fn notify_client(host: &str, port: u16) -> SbiClient {
    let config = nextgcore_sbi::client::SbiClientConfig::new(host, port)
        .with_connect_timeout(std::time::Duration::from_secs(NOTIFY_CONNECT_TIMEOUT_SECS))
        .with_request_timeout(std::time::Duration::from_secs(NOTIFY_REQUEST_TIMEOUT_SECS));
    SbiClient::new(config)
}

/// Parse an absolute http/https URI into (host, port, path)
pub(crate) fn parse_http_uri(uri: &str) -> Option<(String, u16, String)> {
    let (default_port, rest) = if let Some(rest) = uri.strip_prefix("https://") {
        (443u16, rest)
    } else if let Some(rest) = uri.strip_prefix("http://") {
        (80u16, rest)
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
            let port: u16 = port_str.parse().ok()?;
            if host.is_empty() {
                return None;
            }
            Some((host.to_string(), port, path))
        }
        None => Some((host_port.to_string(), default_port, path)),
    }
}

/// Build a single AmfEventReport (TS 29.518 §6.2.6.2.5). `extra` carries the
/// event-specific attributes (location, rmInfoList, reachability, ...).
fn build_event_report(event_type: &str, supi: Option<&str>, extra: Value) -> Value {
    let mut report = json!({
        "type": event_type,
        "state": { "active": true },
        "timeStamp": rfc3339_now(),
    });
    if let Some(supi) = supi {
        report["supi"] = json!(supi);
    }
    if let Value::Object(extra_map) = extra {
        if let Value::Object(report_map) = &mut report {
            for (k, v) in extra_map {
                report_map.insert(k, v);
            }
        }
    }
    report
}

/// POST one AmfEventNotification to a subscriber's notify URI with bounded
/// timeouts. Returns Err on any delivery failure.
async fn deliver_event_notification(sub: EventSubscription, report: Value) -> Result<(), String> {
    let (host, port, path) =
        parse_http_uri(&sub.notify_uri).ok_or_else(|| format!("bad URI {}", sub.notify_uri))?;

    let body = json!({
        "notifyCorrelationId": sub.notify_correlation_id,
        "subsChangeNotifyCorrelationId": Value::Null,
        "reportList": [report],
    });
    // Strip the null field (serde_json keeps explicit nulls)
    let mut body = body;
    if let Value::Object(map) = &mut body {
        map.remove("subsChangeNotifyCorrelationId");
    }

    let client = notify_client(&host, port);

    let response = client
        .post_json(&path, &body)
        .await
        .map_err(|e| format!("notify POST to {} failed: {e}", sub.notify_uri))?;

    if response.is_success() {
        log::debug!(
            "Event notification delivered: sub={}, status={}",
            sub.subscription_id,
            response.status
        );
        Ok(())
    } else {
        Err(format!(
            "notify POST to {} returned {}",
            sub.notify_uri, response.status
        ))
    }
}

/// Fire an AMF event: collect matching subscriptions (expired ones are
/// skipped and swept) and deliver one notification POST per subscriber on
/// background tasks. Safe to call from sync code; outside a tokio runtime
/// the event is dropped with a debug log.
pub fn fire_amf_event(event_type: &str, supi: Option<&str>, extra: Value) {
    let ctx = amf_self();
    let subs = {
        let Ok(guard) = ctx.read() else {
            return;
        };
        guard.event_subscriptions_remove_expired();
        guard.event_subscriptions_matching(event_type, supi)
    };
    if subs.is_empty() {
        return;
    }
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        log::debug!("fire_amf_event({event_type}): no tokio runtime, skipping delivery");
        return;
    };
    let report = build_event_report(event_type, supi, extra);
    for sub in subs {
        let report = report.clone();
        let sub_id = sub.subscription_id.clone();
        handle.spawn(async move {
            if let Err(e) = deliver_event_notification(sub, report).await {
                log::warn!("Event notification delivery failed (sub={sub_id}): {e}");
            }
        });
    }
}

/// Fire a LOCATION_REPORT for the UE's current TAI/NCGI
pub fn fire_location_report(ue: &AmfUe) {
    fire_amf_event(
        "LOCATION_REPORT",
        ue.supi.as_deref(),
        json!({ "location": nr_location_json(ue) }),
    );
}

/// Fire a REGISTRATION_STATE_REPORT (REGISTERED / DEREGISTERED)
pub fn fire_registration_state_report(ue: &AmfUe, registered: bool) {
    fire_amf_event(
        "REGISTRATION_STATE_REPORT",
        ue.supi.as_deref(),
        json!({
            "rmInfoList": [{
                "rmState": if registered { "REGISTERED" } else { "DEREGISTERED" },
                "accessType": "3GPP_ACCESS",
            }]
        }),
    );
}

/// Fire a REACHABILITY_REPORT (REACHABLE / UNREACHABLE)
pub fn fire_reachability_report(ue: &AmfUe, reachable: bool) {
    fire_amf_event(
        "REACHABILITY_REPORT",
        ue.supi.as_deref(),
        json!({ "reachability": if reachable { "REACHABLE" } else { "UNREACHABLE" } }),
    );
}

// ============================================================================
// Namf_Communication — N1N2MessageTransfer (TS 29.518 §5.2.2.3)
// ============================================================================

/// Map a TS 29.518 NgapIeType string onto the internal enum
fn parse_ngap_ie_type(s: &str) -> Option<NgapIeType> {
    match s {
        "PDU_RES_SETUP_REQ" => Some(NgapIeType::PduResSetupReq),
        "PDU_RES_MOD_REQ" => Some(NgapIeType::PduResModReq),
        "PDU_RES_REL_CMD" => Some(NgapIeType::PduResRelCmd),
        "PDU_RES_NTY" => Some(NgapIeType::PduResNotify),
        "PDU_RES_MOD_IND" => Some(NgapIeType::PduResModInd),
        // LCS positioning (TS 29.518 / TS 23.273): the LMF tags an NRPPa PDU
        // carried under n2InfoContainer.nrppaInfo with this ngapIeType.
        "NRPPA_PDU" => Some(NgapIeType::Nrppa),
        _ => None,
    }
}

/// Resolve a RefToBinaryData contentId against the multipart binary parts
fn find_binary_part(request: &SbiRequest, content_id: &str) -> Option<Vec<u8>> {
    request
        .http
        .parts
        .iter()
        .find(|p| p.content_id.as_deref() == Some(content_id))
        .map(|p| p.data.to_vec())
}

/// 504 N1N2MessageTransferError with cause UE_NOT_REACHABLE
/// (TS 29.518 Table 6.1.7.3-1) + asynchronous failure notification when
/// the consumer supplied n1n2FailureTxfNotifURI.
fn ue_not_reachable_error(ue_context_id: &str, failure_uri: Option<&str>) -> SbiResponse {
    if let Some(uri) = failure_uri {
        send_n1n2_failure_notification(
            uri.to_string(),
            "UE_NOT_REACHABLE",
            format!("/namf-comm/v1/ue-contexts/{ue_context_id}/n1-n2-messages"),
        );
    }
    let problem = ProblemDetails::with_status(504)
        .with_title("Gateway Timeout")
        .with_detail("UE is not reachable")
        .with_cause("UE_NOT_REACHABLE");
    let body = json!({ "error": problem });
    match SbiResponse::with_status(504).with_json_body(&body) {
        Ok(resp) => resp.with_header("content-type", "application/problem+json"),
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

/// Send the N1N2MsgTxfrFailureNotification callback POST
/// (TS 29.518 §6.1.6.2.8: cause and n1n2MsgDataUri are both mandatory).
/// Fire-and-forget on a background task with bounded timeouts.
pub fn send_n1n2_failure_notification(notify_uri: String, cause: &str, n1n2_msg_data_uri: String) {
    let cause = cause.to_string();
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        log::debug!("N1N2 failure notification skipped (no tokio runtime)");
        return;
    };
    handle.spawn(async move {
        let Some((host, port, path)) = parse_http_uri(&notify_uri) else {
            log::warn!("Invalid n1n2FailureTxfNotifURI: {notify_uri}");
            return;
        };
        let body = json!({
            "cause": cause,
            "n1n2MsgDataUri": n1n2_msg_data_uri,
        });
        let client = notify_client(&host, port);
        match client.post_json(&path, &body).await {
            Ok(resp) if resp.is_success() => {
                log::info!("N1N2 failure notification delivered to {notify_uri}");
            }
            Ok(resp) => {
                log::warn!(
                    "N1N2 failure notification to {notify_uri} returned {}",
                    resp.status
                );
            }
            Err(e) => log::warn!("N1N2 failure notification to {notify_uri} failed: {e}"),
        }
    });
}

/// LCS positioning relay (TS 23.273 §7): build the downlink wire messages for
/// an LMF-originated `Namf_Communication_N1N2MessageTransfer` carrying NRPPa
/// (→ serving gNB over N2) and/or LPP (→ UE over N1). Returns `Some(response)`
/// when `body` is a positioning transfer (so the caller skips SM handling), or
/// `None` when it is an ordinary SM transfer.
///
/// A positioning transfer is identified structurally: it carries
/// `n1MessageClass == "LPP"` and/or an `n2InfoContainer.nrppaInfo`, and never an
/// `smInfo` / `pduSessionId`. This guard runs before the SM-centric logic so
/// that path is completely untouched (strictly additive).
///
/// Egress is performed by the NGAP server task (it owns the SCTP associations +
/// the per-UE NAS security context): this handler validates the request, models
/// the downlink, and enqueues it on `positioning_dl_queue`; the NGAP pump
/// (`process_positioning_downlinks`) resolves the serving association and
/// delivers. The opaque NRPPa/LPP payloads are carried verbatim — the AMF is a
/// transparent relay. The `Nlmf` uplink callback (UE/gNB→LMF) is `lmfd-07`.
fn try_positioning_relay(
    ue_context_id: &str,
    ue: &AmfUe,
    request: &SbiRequest,
    body: &Value,
) -> Option<SbiResponse> {
    let is_lpp = body
        .pointer("/n1MessageContainer/n1MessageClass")
        .and_then(Value::as_str)
        == Some("LPP");
    let nrppa_info = body.pointer("/n2InfoContainer/nrppaInfo");
    if !is_lpp && nrppa_info.is_none() {
        return None; // not a positioning transfer — fall through to SM handling
    }

    // Both LPP→UE and UE-associated NRPPa→gNB require the UE to be CM-CONNECTED.
    if ue_ran_context(ue).is_none() {
        return Some(ue_not_reachable_error(ue_context_id, None));
    }

    let mut downlinks: Vec<PendingPositioningDl> = Vec::new();

    // LPP → UE (N1, DL NAS Transport, payload container type LPP).
    if is_lpp {
        let Some(lpp_pdu) = body
            .pointer("/n1MessageContainer/n1MessageContent/contentId")
            .and_then(Value::as_str)
            .and_then(|cid| find_binary_part(request, cid))
        else {
            return Some(mandatory_ie_incorrect(
                "n1MessageContainer.n1MessageContent.contentId",
                "no binary part for the LPP payload",
            ));
        };
        downlinks.push(PendingPositioningDl {
            amf_ue_ngap_id: ue.id,
            kind: PositioningDlKind::LppToUe { lpp_pdu },
        });
    }

    // NRPPa → serving gNB (N2, UE-associated NRPPa transport, NGAP procedure 8).
    if let Some(nrppa) = nrppa_info {
        let ie_ok = nrppa
            .pointer("/nrppaPdu/ngapIeType")
            .and_then(Value::as_str)
            .and_then(parse_ngap_ie_type)
            == Some(NgapIeType::Nrppa);
        if !ie_ok {
            return Some(mandatory_ie_incorrect(
                "n2InfoContainer.nrppaInfo.nrppaPdu.ngapIeType",
                "expected NRPPA_PDU",
            ));
        }
        let Some(nrppa_pdu) = nrppa
            .pointer("/nrppaPdu/ngapData/contentId")
            .and_then(Value::as_str)
            .and_then(|cid| find_binary_part(request, cid))
        else {
            return Some(mandatory_ie_incorrect(
                "n2InfoContainer.nrppaInfo.nrppaPdu.ngapData.contentId",
                "no binary part for the NRPPa PDU",
            ));
        };
        // The originating LMF id seeds the NGAP RoutingID so the gNB's uplink
        // reply routes back to the right LMF (opaque echo for our relay).
        let routing_id = nrppa
            .get("nfId")
            .and_then(Value::as_str)
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        downlinks.push(PendingPositioningDl {
            amf_ue_ngap_id: ue.id,
            kind: PositioningDlKind::NrppaToGnb {
                routing_id,
                nrppa_pdu,
            },
        });
    }

    // Enqueue for NGAP-task egress (TS 23.273). The pump resolves the serving
    // SCTP association from its per-UE state and delivers over N2/N1.
    if let Ok(context) = amf_self().read() {
        let n = downlinks.len();
        for dl in downlinks {
            context.positioning_dl_add(dl);
        }
        log::info!("[{ue_context_id}] LCS: enqueued {n} positioning downlink(s) for egress");
    }

    let rsp = json!({ "cause": "N1_N2_TRANSFER_INITIATED" });
    Some(match SbiResponse::ok().with_json_body(&rsp) {
        Ok(resp) => resp,
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    })
}

/// POST /namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages —
/// Namf_Communication_N1N2MessageTransfer (TS 29.518 §5.2.2.3.1).
fn handle_n1_n2_message_transfer_request(ue_context_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(ue) = find_ue_by_context_id(ue_context_id) else {
        return context_not_found(ue_context_id);
    };
    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };

    let n1_container = body.get("n1MessageContainer");
    let n2_container = body.get("n2InfoContainer");
    if n1_container.is_none() && n2_container.is_none() {
        // At least one of N1/N2 content must be present
        return mandatory_ie_missing("n1MessageContainer or n2InfoContainer");
    }

    // LCS positioning relay (TS 23.273): an LMF push of NRPPa (→gNB, N2) and/or
    // LPP (→UE, N1) carries no PDU session and no smInfo. Detect and handle it
    // up front so the SM-centric path below is completely untouched.
    if let Some(resp) = try_positioning_relay(ue_context_id, &ue, request, &body) {
        return resp;
    }

    // N1 message: RefToBinaryData into the multipart binary parts
    let n1_message = match n1_container {
        Some(c) => {
            let Some(content_id) = c
                .pointer("/n1MessageContent/contentId")
                .and_then(Value::as_str)
            else {
                return mandatory_ie_missing("n1MessageContainer.n1MessageContent.contentId");
            };
            match find_binary_part(request, content_id) {
                Some(data) => Some(data),
                None => {
                    return mandatory_ie_incorrect(
                        "n1MessageContainer.n1MessageContent.contentId",
                        &format!("no binary part with contentId '{content_id}'"),
                    );
                }
            }
        }
        None => None,
    };

    // N2 info: ngapIeType + RefToBinaryData
    let mut sm_psi: Option<u8> = None;
    let n2_info = match n2_container {
        Some(c) => {
            let sm_info = c.get("smInfo");
            let Some(sm_info) = sm_info else {
                return mandatory_ie_missing("n2InfoContainer.smInfo");
            };
            sm_psi = sm_info
                .get("pduSessionId")
                .and_then(Value::as_u64)
                .and_then(|v| u8::try_from(v).ok());
            if sm_psi.is_none() {
                return mandatory_ie_missing("n2InfoContainer.smInfo.pduSessionId");
            }
            let Some(ie_type_str) = sm_info
                .pointer("/n2InfoContent/ngapIeType")
                .and_then(Value::as_str)
            else {
                return mandatory_ie_missing("n2InfoContainer.smInfo.n2InfoContent.ngapIeType");
            };
            let Some(ngap_ie_type) = parse_ngap_ie_type(ie_type_str) else {
                return mandatory_ie_incorrect(
                    "n2InfoContainer.smInfo.n2InfoContent.ngapIeType",
                    &format!("unknown value '{ie_type_str}'"),
                );
            };
            let ngap_data = sm_info
                .pointer("/n2InfoContent/ngapData/contentId")
                .and_then(Value::as_str)
                .and_then(|cid| find_binary_part(request, cid));
            Some(N2InfoContainer {
                ngap_ie_type,
                ngap_data,
            })
        }
        None => None,
    };

    let pdu_session_id = body
        .get("pduSessionId")
        .and_then(Value::as_u64)
        .and_then(|v| u8::try_from(v).ok())
        .or(sm_psi);
    let skip_ind = body
        .get("skipInd")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let failure_uri = body
        .get("n1n2FailureTxfNotifURI")
        .and_then(Value::as_str)
        .map(String::from);

    let ran_ue = ue_ran_context(&ue);

    // Pure N1 transfer without an SM context (e.g. SMS/LPP payloads): the
    // internal handler requires a PDU session, so handle reachability here.
    let Some(psi) = pdu_session_id else {
        return if ran_ue.is_some() {
            let rsp = json!({ "cause": "N1_N2_TRANSFER_INITIATED" });
            match SbiResponse::ok().with_json_body(&rsp) {
                Ok(resp) => resp,
                Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
            }
        } else {
            ue_not_reachable_error(ue_context_id, failure_uri.as_deref())
        };
    };

    // Look up the session for this PSI
    let ctx = amf_self();
    let sess = {
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        guard.sess_find_by_psi(ue.id, psi)
    };
    let Some(mut sess) = sess else {
        return send_error(
            404,
            "Not Found",
            &format!("PDU session {psi} not found for UE '{ue_context_id}'"),
            Some("CONTEXT_NOT_FOUND"),
        );
    };

    let req_data = N1N2MessageTransferReqData {
        pdu_session_id: Some(psi),
        n1_message,
        n2_info,
        n1n2_failure_txf_notif_uri: failure_uri.clone(),
        skip_ind,
    };

    let result =
        namf_handler::handle_n1_n2_message_transfer(&ue, &mut sess, ran_ue.as_ref(), &req_data);

    // Persist any session mutations (paging state, release flags)
    {
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        guard.sess_update(&sess);
    }

    match result {
        Ok(rsp) => match rsp.cause {
            N1N2MessageTransferCause::N1N2TransferInitiated => {
                let body = json!({ "cause": rsp.cause.as_str() });
                match SbiResponse::ok().with_json_body(&body) {
                    Ok(resp) => resp,
                    Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
                }
            }
            N1N2MessageTransferCause::AttemptingToReachUe => {
                // 202 Accepted with a Location pointing at the transfer
                // resource (TS 29.518 §5.2.2.3.1)
                let body = json!({ "cause": rsp.cause.as_str() });
                let location =
                    format!("/namf-comm/v1/ue-contexts/{ue_context_id}/n1-n2-messages/{psi}");
                match SbiResponse::with_status(202).with_json_body(&body) {
                    Ok(resp) => resp.with_header("location", location),
                    Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
                }
            }
            N1N2MessageTransferCause::N1MsgNotTransferred
            | N1N2MessageTransferCause::N2MsgNotTransferred
            | N1N2MessageTransferCause::UeNotResponding
            | N1N2MessageTransferCause::UeNotReachable => {
                ue_not_reachable_error(ue_context_id, failure_uri.as_deref())
            }
            N1N2MessageTransferCause::TemporaryRejectRegistrationOngoing
            | N1N2MessageTransferCause::TemporaryRejectHandoverOngoing => {
                // 409 Conflict per TS 29.518 §5.2.2.3.1
                let problem = ProblemDetails::with_status(409)
                    .with_title("Conflict")
                    .with_detail("Temporary rejection, procedure ongoing")
                    .with_cause(rsp.cause.as_str());
                let body = json!({ "error": problem });
                match SbiResponse::with_status(409).with_json_body(&body) {
                    Ok(resp) => resp.with_header("content-type", "application/problem+json"),
                    Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
                }
            }
        },
        Err(namf_handler::NamfHandlerError::MissingField(f)) => mandatory_ie_missing(&f),
        Err(e) => send_error(
            500,
            "Internal Server Error",
            &format!("N1N2 transfer failed: {e:?}"),
            None,
        ),
    }
}

// ============================================================================
// Namf_Communication — UEContextTransfer (TS 29.518 §5.2.2.2.1)
// ============================================================================

/// Selected NAS integrity algorithm name (TS 29.571 IntegrityAlgorithm)
fn nia_name(alg: u8) -> &'static str {
    match alg {
        1 => "NIA1",
        2 => "NIA2",
        3 => "NIA3",
        _ => "NIA0",
    }
}

/// Selected NAS ciphering algorithm name (TS 29.571 CipheringAlgorithm)
fn nea_name(alg: u8) -> &'static str {
    match alg {
        1 => "NEA1",
        2 => "NEA2",
        3 => "NEA3",
        _ => "NEA0",
    }
}

/// Build the UeContext JSON for UEContextTransfer responses
/// (TS 29.518 Table 6.1.6.2.50-1)
fn build_ue_context_json(ue: &AmfUe, sessions: &[AmfSess]) -> Value {
    let mut ue_context = json!({
        "mmContextList": [{
            "accessType": "3GPP_ACCESS",
            "nasSecurityMode": {
                "integrityAlgorithm": nia_name(ue.selected_int_algorithm),
                "cipheringAlgorithm": nea_name(ue.selected_enc_algorithm),
            },
            "nasDownlinkCount": ue.dl_count,
            "nasUplinkCount": ue.ul_count,
            "ueSecurityCapability": format!(
                "{:02X}{:02X}{:02X}{:02X}",
                ue.ue_security_capability.ea,
                ue.ue_security_capability.ia,
                ue.ue_security_capability.eea,
                ue.ue_security_capability.eia,
            ),
        }],
    });
    if let Some(supi) = &ue.supi {
        ue_context["supi"] = json!(supi);
    }
    if let Some(pei) = &ue.pei {
        ue_context["pei"] = json!(pei);
    }
    if ue.ue_ambr.uplink > 0 || ue.ue_ambr.downlink > 0 {
        ue_context["ueAmbr"] = json!({
            "uplink": format!("{} bps", ue.ue_ambr.uplink),
            "downlink": format!("{} bps", ue.ue_ambr.downlink),
        });
    }

    // PduSessionContext mandatory attrs: pduSessionId, smContextRef, sNssai,
    // dnn, accessType. Sessions missing any of them are skipped (we never
    // invent values).
    let session_contexts: Vec<Value> = sessions
        .iter()
        .filter_map(|sess| {
            let sm_context_ref = sess.sm_context_ref.as_ref()?;
            let dnn = sess.dnn.as_ref()?;
            let mut snssai = json!({ "sst": sess.s_nssai.sst });
            if let Some(sd) = sess.s_nssai.sd {
                snssai["sd"] = json!(format!("{sd:06X}"));
            }
            Some(json!({
                "pduSessionId": sess.psi,
                "smContextRef": sm_context_ref,
                "sNssai": snssai,
                "dnn": dnn,
                "accessType": "3GPP_ACCESS",
            }))
        })
        .collect();
    if !session_contexts.is_empty() {
        ue_context["sessionContextList"] = json!(session_contexts);
    }

    ue_context
}

/// POST /namf-comm/v1/ue-contexts/{ueContextId}/transfer —
/// Namf_Communication_UEContextTransfer (TS 29.518 §5.2.2.2.1).
fn handle_ue_context_transfer(ue_context_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(mut ue) = find_ue_by_context_id(ue_context_id) else {
        return context_not_found(ue_context_id);
    };
    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };

    // Mandatory attributes per TS 29.518 Table 6.1.6.2.7-1
    let Some(reason) = body.get("reason").and_then(Value::as_str) else {
        return mandatory_ie_missing("reason");
    };
    let Some(access_type) = body.get("accessType").and_then(Value::as_str) else {
        return mandatory_ie_missing("accessType");
    };
    if access_type != "3GPP_ACCESS" && access_type != "NON_3GPP_ACCESS" {
        return mandatory_ie_incorrect("accessType", &format!("unknown value '{access_type}'"));
    }
    match reason {
        "INIT_REG" | "MOBI_REG" | "MOBI_REG_UE_VALIDATED" => {}
        _ => {
            return mandatory_ie_incorrect("reason", &format!("unknown value '{reason}'"));
        }
    }

    if reason == "MOBI_REG" {
        // The integrity-protected Registration Request must be supplied so
        // the old AMF can verify it (TS 29.518 §5.2.2.2.1.1)
        let Some(reg_content_id) = body
            .pointer("/regRequest/n1MessageContent/contentId")
            .and_then(Value::as_str)
        else {
            return mandatory_ie_missing("regRequest (required for MOBI_REG)");
        };
        if find_binary_part(request, reg_content_id).is_none() {
            return mandatory_ie_incorrect(
                "regRequest.n1MessageContent.contentId",
                &format!("no binary part with contentId '{reg_content_id}'"),
            );
        }
        // Integrity check of the Registration Request against the stored
        // security context. Without a valid security context the transfer
        // is rejected with 403 INTEGRITY_CHECK_FAIL.
        if !ue.security_context_available || ue.mac_failed {
            return send_error(
                403,
                "Forbidden",
                "Registration Request integrity check failed",
                Some("INTEGRITY_CHECK_FAIL"),
            );
        }
    }

    // Collect this UE's sessions and mark the transfer state (old-AMF side)
    let ctx = amf_self();
    let sessions = {
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        guard.sess_list_for_ue(ue.id)
    };

    ue.amf_ue_context_transfer_state = UeContextTransferState::TransferOldAmf;
    {
        let Ok(guard) = ctx.read() else {
            return send_error(500, "Internal Server Error", "context lock poisoned", None);
        };
        guard.amf_ue_update(&ue);
    }

    let response_body = json!({
        "ueContext": build_ue_context_json(&ue, &sessions),
    });
    log::info!(
        "[{}] UEContextTransfer: reason={reason}, accessType={access_type}, {} sessions",
        ue_context_id,
        sessions.len()
    );
    match SbiResponse::ok().with_json_body(&response_body) {
        Ok(resp) => resp,
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

/// POST /namf-comm/v1/ue-contexts/{ueContextId}/transfer-update —
/// Namf_Communication_RegistrationStatusUpdate (TS 29.518 §5.2.2.2.2).
fn handle_registration_status_update(ue_context_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(mut ue) = find_ue_by_context_id(ue_context_id) else {
        return context_not_found(ue_context_id);
    };
    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };

    // Mandatory attribute per TS 29.518 Table 6.1.6.2.9-1
    let Some(transfer_status) = body.get("transferStatus").and_then(Value::as_str) else {
        return mandatory_ie_missing("transferStatus");
    };
    match transfer_status {
        "TRANSFERRED" | "NOT_TRANSFERRED" => {}
        _ => {
            return mandatory_ie_incorrect(
                "transferStatus",
                &format!("unknown value '{transfer_status}'"),
            );
        }
    }

    let ctx = amf_self();
    if transfer_status == "TRANSFERRED" {
        ue.amf_ue_context_transfer_state = UeContextTransferState::RegistrationStatusUpdateOldAmf;
        {
            let Ok(guard) = ctx.read() else {
                return send_error(500, "Internal Server Error", "context lock poisoned", None);
            };
            guard.amf_ue_update(&ue);
        }

        // toReleaseSessionList: PDU sessions the new AMF could not accept
        if let Some(to_release) = body.get("toReleaseSessionList").and_then(Value::as_array) {
            for psi_val in to_release {
                let Some(psi) = psi_val.as_u64().and_then(|v| u8::try_from(v).ok()) else {
                    continue;
                };
                // Copy out, mutate, write back — never hold a lock across
                // a second context call (the documented lock-order rule)
                let sess = {
                    let Ok(guard) = ctx.read() else {
                        break;
                    };
                    guard.sess_find_by_psi(ue.id, psi)
                };
                if let Some(mut sess) = sess {
                    sess.n1_released = true;
                    sess.n2_released = true;
                    if let Ok(guard) = ctx.read() {
                        guard.sess_update(&sess);
                    }
                }
            }
        }
    } else {
        // NOT_TRANSFERRED: registration at the new AMF failed; keep the
        // context and clear any transfer state.
        ue.amf_ue_context_transfer_state = UeContextTransferState::Initial;
        if let Ok(guard) = ctx.read() {
            guard.amf_ue_update(&ue);
        }
    }

    log::info!("[{ue_context_id}] RegistrationStatusUpdate: {transfer_status}");
    let response_body = json!({ "regStatusTransferComplete": true });
    match SbiResponse::ok().with_json_body(&response_body) {
        Ok(resp) => resp,
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

// ============================================================================
// Namf_MT (TS 29.518 §6.3)
// ============================================================================

/// POST /namf-mt/v1/ue-contexts/{ueContextId}/ue-reachind —
/// Namf_MT_EnableUEReachability (TS 29.518 §5.4.2.2). Returns 200 with the
/// reachability when the UE is CM-CONNECTED and 504 UE_NOT_REACHABLE
/// otherwise (per §6.3.7.3).
fn handle_enable_ue_reachability(ue_context_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(ue) = find_ue_by_context_id(ue_context_id) else {
        return context_not_found(ue_context_id);
    };
    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };

    // Mandatory attribute per TS 29.518 Table 6.3.6.2.2-1
    let Some(reachability) = body.get("reachability").and_then(Value::as_str) else {
        return mandatory_ie_missing("reachability");
    };
    match reachability {
        "UNREACHABLE" | "REACHABLE" | "REGULATORY_ONLY" => {}
        _ => {
            return mandatory_ie_incorrect(
                "reachability",
                &format!("unknown value '{reachability}'"),
            );
        }
    }

    if ue_ran_context(&ue).is_some() {
        let response_body = json!({ "reachability": "REACHABLE" });
        match SbiResponse::ok().with_json_body(&response_body) {
            Ok(resp) => resp,
            Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
        }
    } else {
        // CM-IDLE and not pageable within the synchronous request: 504
        send_error(
            504,
            "Gateway Timeout",
            &format!("UE '{ue_context_id}' is not reachable"),
            Some("UE_NOT_REACHABLE"),
        )
    }
}

/// GET /namf-mt/v1/ue-contexts/{ueContextId} —
/// Namf_MT_ProvideDomainSelectionInfo (TS 29.518 §5.4.2.3). Returns the
/// UeContextInfo derived from the AMF's view of the UE.
fn handle_mt_ue_context_info(ue_context_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(ue) = find_ue_by_context_id(ue_context_id) else {
        return context_not_found(ue_context_id);
    };
    // info-class query parameter is mandatory for domain selection info
    if request.http.get_param("info-class").is_none() {
        return mandatory_ie_missing("info-class");
    }

    let connected = ue_ran_context(&ue).is_some();
    let mut response_body = json!({
        "accessType": "3GPP_ACCESS",
        "ratType": "NR",
    });
    if connected && ue.ue_location_timestamp > 0 {
        response_body["lastActTime"] = json!(system_time_to_rfc3339(
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(ue.ue_location_timestamp)
        ));
    }
    match SbiResponse::ok().with_json_body(&response_body) {
        Ok(resp) => resp,
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

// ============================================================================
// Namf_Location (TS 29.518 §6.4)
// ============================================================================

/// POST /namf-loc/v1/{ueContextId}/provide-pos-info —
/// Namf_Location_ProvidePositioningInfo (TS 29.518 §5.5.2.2). No LMF client
/// path exists in this AMF, so the response carries the location the AMF
/// knows from NGAP (NCGI + age of the location estimate) per the
/// ProvidePosInfo shape.
fn handle_provide_positioning_info(ue_context_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(ue) = find_ue_by_context_id(ue_context_id) else {
        return context_not_found(ue_context_id);
    };
    let Some(body) = parse_json_body(request) else {
        return malformed_body();
    };

    // Mandatory attributes per TS 29.518 Table 6.4.6.2.2-1 (RequestPosInfo)
    if body.get("lcsClientType").and_then(Value::as_str).is_none() {
        return mandatory_ie_missing("lcsClientType");
    }
    if body.get("lcsLocation").and_then(Value::as_str).is_none() {
        return mandatory_ie_missing("lcsLocation");
    }

    let mut response_body = json!({
        "ncgi": ncgi_json(&ue.nr_cgi),
    });
    if ue.ue_location_timestamp > 0 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        response_body["ageOfLocationEstimate"] =
            json!(now.saturating_sub(ue.ue_location_timestamp).min(32_767));
    }

    log::info!(
        "[{ue_context_id}] ProvidePositioningInfo: NCGI cell=0x{:09X}",
        ue.nr_cgi.cell_id
    );
    match SbiResponse::ok().with_json_body(&response_body) {
        Ok(resp) => resp,
        Err(e) => send_error(500, "Internal Server Error", &e.to_string(), None),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::amf_context_init;
    use nextgcore_sbi::message::SbiPart;
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    /// Unique RAN-UE-NGAP-ID source so tests never collide on the shared
    /// global context
    static NEXT_NGAP_ID: AtomicU64 = AtomicU64::new(50_000);

    /// Create a UE in the global context with the given SUPI.
    /// `connected` controls whether a live RAN UE context is associated
    /// (CM-CONNECTED); `security` sets security_context_available.
    fn setup_ue(supi: &str, connected: bool, security: bool) -> AmfUe {
        amf_context_init(64, 1024, 4096);
        let ctx = amf_self();
        let guard = ctx.read().expect("ctx lock");
        let ngap_id = NEXT_NGAP_ID.fetch_add(1, Ordering::SeqCst);
        let ran_ue = guard
            .ran_ue_add(900_100, ngap_id)
            .expect("ran_ue_add failed");
        let mut ue = guard.amf_ue_add(ran_ue.id).expect("amf_ue_add failed");
        guard.amf_ue_set_supi(ue.id, supi);
        ue.supi = Some(supi.to_string());
        ue.security_context_available = security;
        ue.nr_tai.tac = 100;
        ue.nr_cgi.cell_id = 0x12345;
        if connected {
            guard.amf_ue_associate_ran_ue(ue.id, ran_ue.id);
            ue.ran_ue_id = ran_ue.id;
        } else {
            ue.ran_ue_id = NEXTGCORE_INVALID_POOL_ID;
        }
        guard.amf_ue_update(&ue);
        ue
    }

    /// Add a session with an SM context ref + DNN for the UE
    fn setup_sess(ue: &AmfUe, psi: u8) -> AmfSess {
        let ctx = amf_self();
        let guard = ctx.read().expect("ctx lock");
        let mut sess = guard.sess_add(ue.id, psi).expect("sess_add failed");
        sess.sm_context_ref = Some(format!("smctx-{psi}"));
        sess.dnn = Some("internet".to_string());
        sess.s_nssai.sst = 1;
        guard.sess_update(&sess);
        sess
    }

    fn body_json(resp: &SbiResponse) -> Value {
        serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}"))
            .expect("response body is not JSON")
    }

    fn problem_cause(resp: &SbiResponse) -> String {
        body_json(resp)["cause"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    fn free_port() -> u16 {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let port = probe.local_addr().expect("local_addr").port();
        drop(probe);
        port
    }

    /// Start a capture server on an ephemeral port; returns (server, port, rx)
    async fn start_capture_server() -> (
        SbiServer,
        u16,
        tokio::sync::mpsc::Receiver<(String, String)>,
    ) {
        let port = free_port();
        let (tx, rx) = tokio::sync::mpsc::channel::<(String, String)>(16);
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
        let server = SbiServer::new(SbiServerConfig::new(addr));
        server
            .start(move |req: SbiRequest| {
                let tx = tx.clone();
                async move {
                    let _ = tx
                        .send((
                            req.header.uri.clone(),
                            req.http.content.clone().unwrap_or_default(),
                        ))
                        .await;
                    SbiResponse::no_content()
                }
            })
            .await
            .expect("capture server start");
        (server, port, rx)
    }

    fn subscription_body(supi: &str, notify_uri: &str, event_type: &str) -> Value {
        json!({
            "subscription": {
                "eventList": [{ "type": event_type }],
                "eventNotifyUri": notify_uri,
                "notifyCorrelationId": format!("corr-{supi}"),
                "nfId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "supi": supi,
            }
        })
    }

    // ------------------------------------------------------------------
    // RFC 3339 + URI helpers
    // ------------------------------------------------------------------

    #[test]
    fn test_rfc3339_roundtrip() {
        let t = std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let s = system_time_to_rfc3339(t);
        assert_eq!(s, "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339_to_system_time(&s), Some(t));

        // Offsets and fractional seconds
        let with_offset = rfc3339_to_system_time("2023-11-14T23:13:20+01:00");
        assert_eq!(with_offset, Some(t));
        let with_frac = rfc3339_to_system_time("2023-11-14T22:13:20.500Z");
        assert_eq!(with_frac, Some(t));

        // Malformed inputs never panic
        assert_eq!(rfc3339_to_system_time("not-a-date"), None);
        assert_eq!(rfc3339_to_system_time("2023-13-99T99:99:99Z"), None);
        assert_eq!(rfc3339_to_system_time(""), None);
    }

    #[test]
    fn test_parse_http_uri() {
        assert_eq!(
            parse_http_uri("http://1.2.3.4:8080/a/b"),
            Some(("1.2.3.4".to_string(), 8080, "/a/b".to_string()))
        );
        assert_eq!(
            parse_http_uri("http://host/cb"),
            Some(("host".to_string(), 80, "/cb".to_string()))
        );
        assert_eq!(
            parse_http_uri("https://host"),
            Some(("host".to_string(), 443, "/".to_string()))
        );
        assert_eq!(parse_http_uri("ftp://host/x"), None);
        assert_eq!(parse_http_uri("http://:80/x"), None);
        assert_eq!(parse_http_uri(""), None);
    }

    // ------------------------------------------------------------------
    // Namf_EventExposure — handler round-trips + strict mandatory attrs
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_event_subscription_create_delete_roundtrip() {
        amf_context_init(64, 1024, 4096);
        let body = subscription_body(
            "imsi-001010000060001",
            "http://127.0.0.1:9/notify",
            "REGISTRATION_STATE_REPORT",
        );
        let req = SbiRequest::post("/namf-evts/v1/subscriptions")
            .with_json_body(&body)
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 201);
        let rsp_body = body_json(&resp);
        let sub_id = rsp_body["subscriptionId"].as_str().expect("subscriptionId");
        assert!(sub_id.starts_with("sub-"));
        assert!(resp
            .http
            .get_header("location")
            .expect("location header")
            .ends_with(sub_id));
        // Echoed subscription carries the mandatory attributes
        assert_eq!(
            rsp_body["subscription"]["eventNotifyUri"].as_str(),
            Some("http://127.0.0.1:9/notify")
        );

        // Persisted in the context store
        let ctx = amf_self();
        assert!(ctx
            .read()
            .unwrap()
            .event_subscription_find(sub_id)
            .is_some());

        // DELETE removes it; second DELETE is 404 SUBSCRIPTION_NOT_FOUND
        let del = SbiRequest::delete(format!("/namf-evts/v1/subscriptions/{sub_id}"));
        let resp = namf_request_handler(del).await;
        assert_eq!(resp.status, 204);
        let del = SbiRequest::delete(format!("/namf-evts/v1/subscriptions/{sub_id}"));
        let resp = namf_request_handler(del).await;
        assert_eq!(resp.status, 404);
        assert_eq!(problem_cause(&resp), "SUBSCRIPTION_NOT_FOUND");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_event_subscription_missing_mandatory_attrs() {
        amf_context_init(64, 1024, 4096);
        // Strict peer: each missing mandatory attribute is rejected with 400
        let cases = vec![
            json!({}),
            json!({ "subscription": {} }),
            json!({ "subscription": {
                "eventList": [{ "type": "LOCATION_REPORT" }],
                "notifyCorrelationId": "c", "nfId": "n", "anyUE": true } }),
            json!({ "subscription": {
                "eventList": [{ "type": "LOCATION_REPORT" }],
                "eventNotifyUri": "http://127.0.0.1:9/cb", "nfId": "n", "anyUE": true } }),
            json!({ "subscription": {
                "eventList": [{ "type": "LOCATION_REPORT" }],
                "eventNotifyUri": "http://127.0.0.1:9/cb", "notifyCorrelationId": "c",
                "anyUE": true } }),
            json!({ "subscription": {
                "eventNotifyUri": "http://127.0.0.1:9/cb", "notifyCorrelationId": "c",
                "nfId": "n", "anyUE": true } }),
            // eventList entry without mandatory `type`
            json!({ "subscription": {
                "eventList": [{}],
                "eventNotifyUri": "http://127.0.0.1:9/cb", "notifyCorrelationId": "c",
                "nfId": "n", "anyUE": true } }),
            // no UE target at all (neither supi nor anyUE)
            json!({ "subscription": {
                "eventList": [{ "type": "LOCATION_REPORT" }],
                "eventNotifyUri": "http://127.0.0.1:9/cb", "notifyCorrelationId": "c",
                "nfId": "n" } }),
        ];
        for body in cases {
            let req = SbiRequest::post("/namf-evts/v1/subscriptions")
                .with_json_body(&body)
                .expect("json");
            let resp = namf_request_handler(req).await;
            assert_eq!(resp.status, 400, "body should be rejected: {body}");
            assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");
        }

        // Malformed (non-JSON) body: 400, no panic
        let mut req = SbiRequest::post("/namf-evts/v1/subscriptions");
        req.http.set_content("this is not json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_event_subscription_modify() {
        amf_context_init(64, 1024, 4096);
        let body = subscription_body(
            "imsi-001010000060002",
            "http://127.0.0.1:9/notify-old",
            "LOCATION_REPORT",
        );
        let req = SbiRequest::post("/namf-evts/v1/subscriptions")
            .with_json_body(&body)
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 201);
        let sub_id = body_json(&resp)["subscriptionId"]
            .as_str()
            .expect("subscriptionId")
            .to_string();

        // PATCH replace of the notify URI
        let patch = json!([{
            "op": "replace",
            "path": "/subscription/eventNotifyUri",
            "value": "http://127.0.0.1:9/notify-new",
        }]);
        let req = SbiRequest::patch(format!("/namf-evts/v1/subscriptions/{sub_id}"))
            .with_json_body(&patch)
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 200);
        let ctx = amf_self();
        let stored = ctx
            .read()
            .unwrap()
            .event_subscription_find(&sub_id)
            .unwrap();
        assert_eq!(stored.notify_uri, "http://127.0.0.1:9/notify-new");

        // Unsupported patch op rejected with 400
        let patch = json!([{ "op": "remove", "path": "/subscription/nfId" }]);
        let req = SbiRequest::patch(format!("/namf-evts/v1/subscriptions/{sub_id}"))
            .with_json_body(&patch)
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);

        // PATCH on unknown subscription is 404
        let patch = json!([{
            "op": "replace", "path": "/subscription/eventNotifyUri",
            "value": "http://127.0.0.1:9/x" }]);
        let req = SbiRequest::patch("/namf-evts/v1/subscriptions/sub-unknown")
            .with_json_body(&patch)
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 404);

        let _ = namf_request_handler(SbiRequest::delete(format!(
            "/namf-evts/v1/subscriptions/{sub_id}"
        )))
        .await;
    }

    #[test]
    fn test_expired_subscription_is_skipped_and_swept() {
        amf_context_init(64, 1024, 4096);
        let ctx = amf_self();
        let guard = ctx.read().unwrap();
        let supi = "imsi-001010000060003";
        let sub = EventSubscription {
            subscription_id: "sub-expired-test".to_string(),
            notify_uri: "http://127.0.0.1:9/cb".to_string(),
            notify_correlation_id: "c".to_string(),
            nf_id: "n".to_string(),
            event_types: vec!["LOCATION_REPORT".to_string()],
            supi: Some(supi.to_string()),
            any_ue: false,
            expiry: Some(std::time::UNIX_EPOCH), // long expired
        };
        assert!(guard.event_subscription_add(sub));
        // Expired subscriptions never match (other tests may add unrelated
        // subscriptions to the shared global context, so scope by ID)
        assert!(!guard
            .event_subscriptions_matching("LOCATION_REPORT", Some(supi))
            .iter()
            .any(|s| s.subscription_id == "sub-expired-test"));
        // ... and the sweep removes them
        guard.event_subscriptions_remove_expired();
        assert!(guard.event_subscription_find("sub-expired-test").is_none());
    }

    // ------------------------------------------------------------------
    // Namf_EventExposure — HTTP-level notification POST delivery
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_event_notification_post_delivery() {
        amf_context_init(64, 1024, 4096);
        let supi = "imsi-001010000060010";
        let (server, port, mut rx) = start_capture_server().await;

        // Subscribe with the capture server as the notify endpoint
        let notify_uri = format!("http://127.0.0.1:{port}/amf-event-notify");
        let body = subscription_body(supi, &notify_uri, "REACHABILITY_REPORT");
        let req = SbiRequest::post("/namf-evts/v1/subscriptions")
            .with_json_body(&body)
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 201);
        let sub_id = body_json(&resp)["subscriptionId"]
            .as_str()
            .expect("subscriptionId")
            .to_string();

        // Fire the event the AMF tracks; delivery happens on a spawned task
        fire_amf_event(
            "REACHABILITY_REPORT",
            Some(supi),
            json!({ "reachability": "REACHABLE" }),
        );

        let (uri, posted) = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("notification not delivered within 3s")
            .expect("capture channel closed");
        assert_eq!(uri, "/amf-event-notify");
        let posted: Value = serde_json::from_str(&posted).expect("notification body JSON");
        assert_eq!(
            posted["notifyCorrelationId"].as_str(),
            Some(format!("corr-{supi}").as_str())
        );
        let report = &posted["reportList"][0];
        assert_eq!(report["type"].as_str(), Some("REACHABILITY_REPORT"));
        assert_eq!(report["supi"].as_str(), Some(supi));
        assert_eq!(report["reachability"].as_str(), Some("REACHABLE"));
        assert!(report["timeStamp"].as_str().is_some());
        assert_eq!(report["state"]["active"].as_bool(), Some(true));

        let _ = namf_request_handler(SbiRequest::delete(format!(
            "/namf-evts/v1/subscriptions/{sub_id}"
        )))
        .await;
        server.stop().await.expect("server stop");
    }

    // ------------------------------------------------------------------
    // Namf_Communication — N1N2MessageTransfer
    // ------------------------------------------------------------------

    fn n1n2_body(psi: u8, with_n1: bool, skip_ind: bool, failure_uri: Option<&str>) -> Value {
        let mut body = json!({
            "pduSessionId": psi,
            "n2InfoContainer": {
                "n2InformationClass": "SM",
                "smInfo": {
                    "pduSessionId": psi,
                    "n2InfoContent": {
                        "ngapIeType": "PDU_RES_SETUP_REQ",
                        "ngapData": { "contentId": "ngap-sm" },
                    },
                },
            },
        });
        if with_n1 {
            body["n1MessageContainer"] = json!({
                "n1MessageClass": "SM",
                "n1MessageContent": { "contentId": "5gnas-sm" },
            });
        }
        if skip_ind {
            body["skipInd"] = json!(true);
        }
        if let Some(uri) = failure_uri {
            body["n1n2FailureTxfNotifURI"] = json!(uri);
        }
        body
    }

    fn n1n2_request(ue_context_id: &str, body: &Value, with_n1: bool) -> SbiRequest {
        let mut req = SbiRequest::post(format!(
            "/namf-comm/v1/ue-contexts/{ue_context_id}/n1-n2-messages"
        ))
        .with_json_body(body)
        .expect("json")
        .with_part(SbiPart::with_content(
            "ngap-sm",
            "application/vnd.3gpp.ngap",
            bytes::Bytes::from_static(&[0x00, 0x1d, 0x00, 0x03]),
        ));
        if with_n1 {
            req = req.with_part(SbiPart::with_content(
                "5gnas-sm",
                "application/vnd.3gpp.5gnas",
                bytes::Bytes::from_static(&[0x2e, 0x01, 0x01, 0xc1]),
            ));
        }
        req
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_n1n2_transfer_connected_ue() {
        let supi = "imsi-001010000060020";
        let ue = setup_ue(supi, true, true);
        setup_sess(&ue, 5);

        let body = n1n2_body(5, true, false, None);
        let resp = namf_request_handler(n1n2_request(supi, &body, true)).await;
        assert_eq!(resp.status, 200);
        assert_eq!(
            body_json(&resp)["cause"].as_str(),
            Some("N1_N2_TRANSFER_INITIATED")
        );
    }

    /// LCS: an LMF push of LPP (n1MessageClass "LPP", no PDU session) to a
    /// connected UE is recognised by the positioning relay, the DL NAS Transport
    /// is built, and the transfer is accepted (200) — the SM path is skipped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_n1n2_lpp_to_connected_ue_relays() {
        let supi = "imsi-001010000060030";
        setup_ue(supi, true, true);

        let body = json!({
            "n1MessageContainer": {
                "n1MessageClass": "LPP",
                "n1MessageContent": { "contentId": "lpp-pdu" }
            }
        });
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"))
            .with_json_body(&body)
            .expect("json")
            .with_part(SbiPart::with_content(
                "lpp-pdu",
                "application/vnd.3gpp.lpp",
                bytes::Bytes::from_static(&[0x90, 0x01, 0x20, 0x09, 0x30]),
            ));
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 200);
        assert_eq!(
            body_json(&resp)["cause"].as_str(),
            Some("N1_N2_TRANSFER_INITIATED")
        );
    }

    /// LCS: an LMF push of NRPPa (n2InfoContainer.nrppaInfo, ngapIeType
    /// NRPPA_PDU, no PDU session) to a connected UE is recognised, the
    /// UE-associated NRPPa DL transport is built, and the transfer is accepted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_n1n2_nrppa_to_connected_ue_relays() {
        let supi = "imsi-001010000060031";
        setup_ue(supi, true, true);

        let body = json!({
            "n2InfoContainer": {
                "n2InformationClass": "NRPPa",
                "nrppaInfo": {
                    "nfId": "lmf-0001",
                    "nrppaPdu": {
                        "ngapIeType": "NRPPA_PDU",
                        "ngapData": { "contentId": "nrppa-pdu" }
                    }
                }
            }
        });
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"))
            .with_json_body(&body)
            .expect("json")
            .with_part(SbiPart::with_content(
                "nrppa-pdu",
                "application/vnd.3gpp.ngap",
                bytes::Bytes::from_static(&[0x00, 0x00, 0x01, 0x00, 0x1d, 0x00]),
            ));
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 200);
        assert_eq!(
            body_json(&resp)["cause"].as_str(),
            Some("N1_N2_TRANSFER_INITIATED")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_n1n2_transfer_idle_ue_paging_202() {
        let supi = "imsi-001010000060021";
        let ue = setup_ue(supi, false, false);
        setup_sess(&ue, 6);

        // No N1 message, idle UE -> network-triggered service request: 202
        let body = n1n2_body(6, false, false, None);
        let resp = namf_request_handler(n1n2_request(supi, &body, false)).await;
        assert_eq!(resp.status, 202);
        assert_eq!(
            body_json(&resp)["cause"].as_str(),
            Some("ATTEMPTING_TO_REACH_UE")
        );
        assert!(resp.http.get_header("location").is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_n1n2_transfer_missing_mandatory_attrs() {
        let supi = "imsi-001010000060022";
        let ue = setup_ue(supi, true, true);
        setup_sess(&ue, 7);

        // Neither n1MessageContainer nor n2InfoContainer
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"))
            .with_json_body(&json!({ "pduSessionId": 7 }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");

        // n2InfoContainer without smInfo.pduSessionId
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"))
            .with_json_body(&json!({
                "n2InfoContainer": { "n2InformationClass": "SM", "smInfo": {
                    "n2InfoContent": { "ngapIeType": "PDU_RES_SETUP_REQ" } } }
            }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");

        // Referenced binary part missing
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"))
            .with_json_body(&json!({
                "pduSessionId": 7,
                "n1MessageContainer": {
                    "n1MessageClass": "SM",
                    "n1MessageContent": { "contentId": "no-such-part" },
                },
            }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_INCORRECT");

        // Malformed body never panics
        let mut req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"));
        req.http.set_content("{{{{");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_n1n2_transfer_unknown_ue_404() {
        amf_context_init(64, 1024, 4096);
        let body = n1n2_body(1, false, false, None);
        let resp = namf_request_handler(n1n2_request("imsi-001019999999999", &body, false)).await;
        assert_eq!(resp.status, 404);
        assert_eq!(problem_cause(&resp), "CONTEXT_NOT_FOUND");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_n1n2_failure_callback_http_delivery() {
        // Idle UE + PDU_RES_REL_CMD + skipInd: N1 message is not transferred,
        // the response is 504 UE_NOT_REACHABLE and the failure notification
        // is POSTed to n1n2FailureTxfNotifURI.
        let supi = "imsi-001010000060023";
        let ue = setup_ue(supi, false, false);
        setup_sess(&ue, 8);

        let (server, port, mut rx) = start_capture_server().await;
        let failure_uri = format!("http://127.0.0.1:{port}/smf-n1n2-failure");

        let body = json!({
            "pduSessionId": 8,
            "skipInd": true,
            "n1n2FailureTxfNotifURI": failure_uri,
            "n2InfoContainer": {
                "n2InformationClass": "SM",
                "smInfo": {
                    "pduSessionId": 8,
                    "n2InfoContent": {
                        "ngapIeType": "PDU_RES_REL_CMD",
                        "ngapData": { "contentId": "ngap-sm" },
                    },
                },
            },
        });
        let resp = namf_request_handler(n1n2_request(supi, &body, false)).await;
        assert_eq!(resp.status, 504);
        let err = body_json(&resp);
        assert_eq!(err["error"]["cause"].as_str(), Some("UE_NOT_REACHABLE"));

        let (uri, posted) = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("failure notification not delivered within 3s")
            .expect("capture channel closed");
        assert_eq!(uri, "/smf-n1n2-failure");
        let posted: Value = serde_json::from_str(&posted).expect("failure body JSON");
        // Both mandatory attributes of N1N2MsgTxfrFailureNotification
        assert_eq!(posted["cause"].as_str(), Some("UE_NOT_REACHABLE"));
        assert!(posted["n1n2MsgDataUri"]
            .as_str()
            .expect("n1n2MsgDataUri")
            .contains(supi));

        server.stop().await.expect("server stop");
    }

    // ------------------------------------------------------------------
    // Namf_Communication — UEContextTransfer + RegistrationStatusUpdate
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_ue_context_transfer_roundtrip() {
        let supi = "imsi-001010000060030";
        let ue = setup_ue(supi, true, true);
        setup_sess(&ue, 9);

        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/transfer"))
            .with_json_body(&json!({ "reason": "INIT_REG", "accessType": "3GPP_ACCESS" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 200);
        let body = body_json(&resp);
        let ue_context = &body["ueContext"];
        assert_eq!(ue_context["supi"].as_str(), Some(supi));
        // mmContextList mandatory attrs are encoded
        let mm = &ue_context["mmContextList"][0];
        assert_eq!(mm["accessType"].as_str(), Some("3GPP_ACCESS"));
        assert!(mm["nasSecurityMode"]["integrityAlgorithm"]
            .as_str()
            .is_some());
        // session context carries its mandatory attrs
        let sess_ctx = &ue_context["sessionContextList"][0];
        assert_eq!(sess_ctx["pduSessionId"].as_u64(), Some(9));
        assert_eq!(sess_ctx["smContextRef"].as_str(), Some("smctx-9"));
        assert_eq!(sess_ctx["dnn"].as_str(), Some("internet"));
        assert!(sess_ctx["sNssai"]["sst"].as_u64().is_some());

        // Transfer state moved to old-AMF side
        let ctx = amf_self();
        let stored = ctx.read().unwrap().amf_ue_find_by_supi(supi).unwrap();
        assert_eq!(
            stored.amf_ue_context_transfer_state,
            UeContextTransferState::TransferOldAmf
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_ue_context_transfer_error_paths() {
        // Unique SUPI: the process-global AMF context (supi_hash) is shared by
        // every test in this binary and amf_context_init is a one-shot OnceLock
        // that never clears it. `imsi-001010000060031` is also registered by
        // test_n1n2_nrppa_to_connected_ue_relays with security_context_available
        // = true; reusing it raced that UE into supi_hash, so this MOBI_REG
        // integrity check found a UE *with* a security context and passed (200)
        // instead of failing (403). A SUPI no other test registers keeps this
        // error path deterministic.
        let supi = "imsi-001010000060033";
        setup_ue(supi, true, false); // no security context

        // 404 for unknown UE (CONTEXT_NOT_FOUND per TS 29.518 §6.1.7.3)
        let req = SbiRequest::post("/namf-comm/v1/ue-contexts/imsi-00101888/transfer")
            .with_json_body(&json!({ "reason": "INIT_REG", "accessType": "3GPP_ACCESS" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 404);
        assert_eq!(problem_cause(&resp), "CONTEXT_NOT_FOUND");

        // Missing mandatory `reason`
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/transfer"))
            .with_json_body(&json!({ "accessType": "3GPP_ACCESS" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");

        // Missing mandatory `accessType`
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/transfer"))
            .with_json_body(&json!({ "reason": "INIT_REG" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");

        // MOBI_REG without regRequest is rejected
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/transfer"))
            .with_json_body(&json!({ "reason": "MOBI_REG", "accessType": "3GPP_ACCESS" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);

        // MOBI_REG with regRequest but no valid security context: 403
        // INTEGRITY_CHECK_FAIL (TS 29.518 §5.2.2.2.1.1)
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/transfer"))
            .with_json_body(&json!({
                "reason": "MOBI_REG",
                "accessType": "3GPP_ACCESS",
                "regRequest": { "n1MessageContent": { "contentId": "reg-req" } },
            }))
            .expect("json")
            .with_part(SbiPart::with_content(
                "reg-req",
                "application/vnd.3gpp.5gnas",
                bytes::Bytes::from_static(&[0x7e, 0x00, 0x41]),
            ));
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 403);
        assert_eq!(problem_cause(&resp), "INTEGRITY_CHECK_FAIL");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_registration_status_update() {
        let supi = "imsi-001010000060032";
        let ue = setup_ue(supi, true, true);
        let _sess = setup_sess(&ue, 10);

        // TRANSFERRED with a session to release
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/transfer-update"))
            .with_json_body(&json!({
                "transferStatus": "TRANSFERRED",
                "toReleaseSessionList": [10],
            }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 200);
        assert_eq!(
            body_json(&resp)["regStatusTransferComplete"].as_bool(),
            Some(true)
        );
        let ctx = amf_self();
        {
            let guard = ctx.read().unwrap();
            let stored = guard.amf_ue_find_by_supi(supi).unwrap();
            assert_eq!(
                stored.amf_ue_context_transfer_state,
                UeContextTransferState::RegistrationStatusUpdateOldAmf
            );
            let sess = guard.sess_find_by_psi(ue.id, 10).unwrap();
            assert!(sess.n1_released && sess.n2_released);
        }

        // Missing mandatory transferStatus
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/transfer-update"))
            .with_json_body(&json!({}))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");

        // Invalid enum value
        let req = SbiRequest::post(format!("/namf-comm/v1/ue-contexts/{supi}/transfer-update"))
            .with_json_body(&json!({ "transferStatus": "MAYBE" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_INCORRECT");

        // Unknown UE
        let req = SbiRequest::post("/namf-comm/v1/ue-contexts/imsi-00101777/transfer-update")
            .with_json_body(&json!({ "transferStatus": "TRANSFERRED" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 404);
    }

    // ------------------------------------------------------------------
    // Namf_MT — EnableUeReachability
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_mt_enable_ue_reachability() {
        let connected_supi = "imsi-001010000060040";
        setup_ue(connected_supi, true, true);
        let idle_supi = "imsi-001010000060041";
        setup_ue(idle_supi, false, true);

        // CM-CONNECTED UE: 200 with mandatory reachability attribute
        let req = SbiRequest::post(format!(
            "/namf-mt/v1/ue-contexts/{connected_supi}/ue-reachind"
        ))
        .with_json_body(&json!({ "reachability": "REACHABLE" }))
        .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 200);
        assert_eq!(body_json(&resp)["reachability"].as_str(), Some("REACHABLE"));

        // CM-IDLE UE: 504 UE_NOT_REACHABLE per TS 29.518 §6.3.7.3
        let req = SbiRequest::post(format!("/namf-mt/v1/ue-contexts/{idle_supi}/ue-reachind"))
            .with_json_body(&json!({ "reachability": "REACHABLE" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 504);
        assert_eq!(problem_cause(&resp), "UE_NOT_REACHABLE");

        // Missing mandatory reachability
        let req = SbiRequest::post(format!(
            "/namf-mt/v1/ue-contexts/{connected_supi}/ue-reachind"
        ))
        .with_json_body(&json!({}))
        .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");

        // Unknown UE
        let req = SbiRequest::post("/namf-mt/v1/ue-contexts/imsi-00101666/ue-reachind")
            .with_json_body(&json!({ "reachability": "REACHABLE" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 404);
        assert_eq!(problem_cause(&resp), "CONTEXT_NOT_FOUND");
    }

    // ------------------------------------------------------------------
    // Namf_Location — ProvidePositioningInfo
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_loc_provide_pos_info() {
        let supi = "imsi-001010000060050";
        setup_ue(supi, true, true);

        let req = SbiRequest::post(format!("/namf-loc/v1/{supi}/provide-pos-info"))
            .with_json_body(&json!({
                "lcsClientType": "EXTERNAL",
                "lcsLocation": "CURRENT_LOCATION",
            }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 200);
        let body = body_json(&resp);
        // The AMF returns what it knows: the serving cell (NCGI from NGAP)
        assert_eq!(body["ncgi"]["nrCellId"].as_str(), Some("000012345"));
        assert!(body["ncgi"]["plmnId"]["mcc"].as_str().is_some());

        // Missing mandatory lcsClientType
        let req = SbiRequest::post(format!("/namf-loc/v1/{supi}/provide-pos-info"))
            .with_json_body(&json!({ "lcsLocation": "CURRENT_LOCATION" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(problem_cause(&resp), "MANDATORY_IE_MISSING");

        // Missing mandatory lcsLocation
        let req = SbiRequest::post(format!("/namf-loc/v1/{supi}/provide-pos-info"))
            .with_json_body(&json!({ "lcsClientType": "EXTERNAL" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 400);

        // Unknown UE
        let req = SbiRequest::post("/namf-loc/v1/imsi-00101555/provide-pos-info")
            .with_json_body(&json!({
                "lcsClientType": "EXTERNAL", "lcsLocation": "CURRENT_LOCATION" }))
            .expect("json");
        let resp = namf_request_handler(req).await;
        assert_eq!(resp.status, 404);
        assert_eq!(problem_cause(&resp), "CONTEXT_NOT_FOUND");
    }

    // ------------------------------------------------------------------
    // Full HTTP/2 round-trip through the real server
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_namf_server_http_roundtrip() {
        amf_context_init(64, 1024, 4096);
        let port = free_port();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
        let server = SbiServer::new(SbiServerConfig::new(addr));
        server
            .start(namf_request_handler)
            .await
            .expect("namf server start");

        let client = SbiClient::with_host_port("127.0.0.1", port);

        // Strict peer over real HTTP/2: missing mandatory attr -> 400
        let bad = SbiRequest::post("/namf-evts/v1/subscriptions")
            .with_json_body(&json!({ "subscription": { "anyUE": true } }))
            .expect("json");
        let resp = tokio::time::timeout(Duration::from_secs(3), client.send_request(bad))
            .await
            .expect("request timed out")
            .expect("request failed");
        assert_eq!(resp.status, 400);
        assert_eq!(
            resp.http.get_header("content-type").map(String::as_str),
            Some("application/problem+json")
        );

        // Valid subscription -> 201 over the wire
        let good = SbiRequest::post("/namf-evts/v1/subscriptions")
            .with_json_body(&subscription_body(
                "imsi-001010000060060",
                "http://127.0.0.1:9/cb",
                "LOCATION_REPORT",
            ))
            .expect("json");
        let resp = tokio::time::timeout(Duration::from_secs(3), client.send_request(good))
            .await
            .expect("request timed out")
            .expect("request failed");
        assert_eq!(resp.status, 201);
        let sub_id = body_json(&resp)["subscriptionId"]
            .as_str()
            .expect("subscriptionId")
            .to_string();

        // DELETE over the wire -> 204
        let del = SbiRequest::delete(format!("/namf-evts/v1/subscriptions/{sub_id}"));
        let resp = tokio::time::timeout(Duration::from_secs(3), client.send_request(del))
            .await
            .expect("request timed out")
            .expect("request failed");
        assert_eq!(resp.status, 204);

        server.stop().await.expect("server stop");
    }
}
