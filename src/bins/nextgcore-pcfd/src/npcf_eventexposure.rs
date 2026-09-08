//! Npcf_EventExposure service (TS 29.523, `TS29523_Npcf_EventExposure.yaml`).
//!
//! Two resources: a `/subscriptions` collection that accepts POST, and an
//! individual `/subscriptions/{subscriptionId}` that accepts GET, PUT and
//! DELETE. When a policy-control event fires, every matching subscription is
//! POSTed a `PcEventExposureNotif` at its `notifUri`.
//!
//! # What this PCF can actually report
//!
//! `PcEvent` enumerates thirteen tokens. Only four have a real producer in this
//! tree — see [`crate::context::PC_EVENTS_WITH_PRODUCERS`] for the list and for
//! why the other nine are not faked. A subscription is accepted when at least
//! one requested event is serviceable and refused when none is, because a
//! subscription that can never fire is a feed the consumer waits on forever.
//!
//! Note what is deliberately NOT done: an individual unrecognised token is not
//! rejected. `PcEvent` is an `anyOf` over the enum plus a free-form string, so
//! an unknown token is forward-compatibility with a later release, and
//! rejecting it would make this PCF fail against a conformant future consumer.

use crate::context::{pcf_self, PcEventSubscription};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::{send_bad_request, send_method_not_allowed_with_allow, send_not_found};

/// URI prefix of the individual subscription resource, per the OpenAPI
/// `servers` entry plus the resource path.
const SUBSCRIPTIONS_BASE: &str = "/npcf-eventexposure/v1/subscriptions";

/// Format `secs` since the Unix epoch as an RFC 3339 UTC timestamp
/// (TS 29.571 `DateTime`).
///
/// Hand-rolled rather than pulling in a date/time crate, matching what udmd and
/// nrfd already do for the same reason.
pub fn epoch_to_rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The parsed, validated members of a `PcEventExposureSubsc`.
struct ParsedSubsc {
    notif_uri: String,
    notif_id: String,
    event_subs: Vec<String>,
    filter_dnns: Vec<String>,
    group_id: Option<String>,
    max_report_nbr: Option<u32>,
    raw: serde_json::Value,
}

/// Validate a `PcEventExposureSubsc` body.
///
/// Enforces exactly the schema's three required members plus the `minItems: 1`
/// on `eventSubs`, then the serviceability rule. Everything else is optional and
/// is carried through verbatim.
fn parse_subsc(body: &str) -> Result<ParsedSubsc, Box<SbiResponse>> {
    let doc: serde_json::Value = serde_json::from_str(body).map_err(|e| {
        Box::new(send_bad_request(
            &format!("Invalid JSON: {e}"),
            Some("INVALID_JSON"),
        ))
    })?;

    let notif_uri = doc
        .get("notifUri")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            Box::new(send_bad_request(
                "PcEventExposureSubsc.notifUri is mandatory (TS 29.523)",
                Some("MANDATORY_IE_MISSING"),
            ))
        })?
        .to_string();

    // A notifUri that is not an absolute http(s) URI can never be POSTed to, so
    // accepting it would create a subscription guaranteed to fail silently at
    // every notification. Refused at ingress instead, where the consumer can see
    // it, rather than logged per-event forever after.
    if !(notif_uri.starts_with("http://") || notif_uri.starts_with("https://")) {
        return Err(Box::new(send_bad_request(
            &format!("notifUri must be an absolute http(s) URI, got {notif_uri}"),
            Some("MANDATORY_IE_INCORRECT"),
        )));
    }

    let notif_id = doc
        .get("notifId")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            Box::new(send_bad_request(
                "PcEventExposureSubsc.notifId is mandatory (TS 29.523)",
                Some("MANDATORY_IE_MISSING"),
            ))
        })?
        .to_string();

    let Some(events) = doc.get("eventSubs").and_then(|v| v.as_array()) else {
        return Err(Box::new(send_bad_request(
            "PcEventExposureSubsc.eventSubs is mandatory (TS 29.523)",
            Some("MANDATORY_IE_MISSING"),
        )));
    };
    // `PcEvent` is `anyOf [enum, string]`, so every member must be A STRING, but
    // the particular token is not constrained. A non-string member is malformed;
    // an unrecognised string is not.
    let mut event_subs: Vec<String> = Vec::with_capacity(events.len());
    for e in events {
        match e.as_str() {
            Some(s) if !s.is_empty() => event_subs.push(s.to_string()),
            _ => {
                return Err(Box::new(send_bad_request(
                    "eventSubs members must be non-empty PcEvent strings",
                    Some("MANDATORY_IE_INCORRECT"),
                )))
            }
        }
    }
    // Schema: minItems 1.
    if event_subs.is_empty() {
        return Err(Box::new(send_bad_request(
            "eventSubs must contain at least one PcEvent (minItems: 1)",
            Some("MANDATORY_IE_INCORRECT"),
        )));
    }

    // Refuse only when NOTHING requested can ever be reported. 400 with a cause
    // naming the events follows the precedent this repo already set for a
    // spec-valid input the NF cannot evaluate (the SubscrCond gate in #68),
    // rather than inventing a new answer: TS 29.523 defines no per-item failure
    // report on this resource, so there is nowhere conformant to say "kept, but
    // cannot serve token X".
    if PcEventSubscription::serviceable_events(&event_subs).is_empty() {
        return Err(Box::new(send_bad_request(
            &format!(
                "none of the requested events can be reported by this PCF: {}. Reportable \
                 events are: {}",
                event_subs.join(", "),
                crate::context::PC_EVENTS_WITH_PRODUCERS.join(", ")
            ),
            Some("EVENT_NOT_SUPPORTED"),
        )));
    }

    let filter_dnns = doc
        .get("filterDnns")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|d| d.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let group_id = doc
        .get("groupId")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    // maxReportNbr is a TS 29.571 Uinteger; a value that does not fit u32 is
    // treated as unlimited rather than rejected, since the intent ("do not stop")
    // is unambiguous and refusing a large integer would be pedantic.
    let max_report_nbr = doc
        .pointer("/eventsRepInfo/maxReportNbr")
        .and_then(|v| v.as_u64())
        .and_then(|n| u32::try_from(n).ok());

    Ok(ParsedSubsc {
        notif_uri,
        notif_id,
        event_subs,
        filter_dnns,
        group_id,
        max_report_nbr,
        raw: doc,
    })
}

/// `POST /npcf-eventexposure/v1/subscriptions` — create an Individual Policy
/// Control Events Subscription. 201 with a `Location` header (TS 29.523 §4.2).
pub async fn handle_create(request: &SbiRequest) -> SbiResponse {
    let Some(body) = &request.http.content else {
        return send_bad_request("Missing request body", Some("MISSING_BODY"));
    };
    let parsed = match parse_subsc(body) {
        Ok(p) => p,
        Err(resp) => return *resp,
    };

    let ctx = pcf_self();
    let Ok(context) = ctx.read() else {
        return SbiResponse::with_status(500);
    };
    let Some(sub) = context.event_sub_add(
        &parsed.notif_uri,
        &parsed.notif_id,
        parsed.event_subs,
        parsed.filter_dnns,
        parsed.group_id,
        parsed.max_report_nbr,
        parsed.raw.clone(),
    ) else {
        return SbiResponse::with_status(500);
    };

    log::info!(
        "Npcf_EventExposure subscription created (id={}, notifId={}, events={:?})",
        sub.subscription_id,
        sub.notif_id,
        sub.event_subs
    );

    // The created representation is what was received. `eventNotifs` is NOT
    // added: it would be an immediate report, and all four reportable events are
    // change/outcome events with no current-state form to report at create time,
    // so emitting one would mean inventing an event that did not happen.
    let location = format!("{SUBSCRIPTIONS_BASE}/{}", sub.subscription_id);
    SbiResponse::with_status(201)
        .with_json_body(&sub.raw)
        .unwrap_or_else(|_| SbiResponse::with_status(201))
        .with_header("Location", &location)
}

/// `GET /npcf-eventexposure/v1/subscriptions/{subscriptionId}`.
pub async fn handle_get(sub_id: &str) -> SbiResponse {
    let ctx = pcf_self();
    let sub = ctx
        .read()
        .ok()
        .and_then(|c| c.event_sub_find_by_subscription_id(sub_id));
    match sub {
        // Echoed verbatim: the resource is what the consumer sent, including
        // members this build does not interpret.
        Some(sub) => SbiResponse::with_status(200)
            .with_json_body(&sub.raw)
            .unwrap_or_else(|_| SbiResponse::with_status(500)),
        None => send_not_found(
            &format!("Policy control events subscription {sub_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        ),
    }
}

/// `PUT /npcf-eventexposure/v1/subscriptions/{subscriptionId}` — full
/// replacement of the subscription, answering 200 with the updated resource.
///
/// The pool id and `subscriptionId` are preserved so the resource URI stays
/// valid; `reportCount` is preserved too, because a PUT modifies the
/// subscription rather than starting a new one, so a consumer cannot reset its
/// own `maxReportNbr` budget by re-PUTting the same document.
pub async fn handle_update(sub_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(body) = &request.http.content else {
        return send_bad_request("Missing request body", Some("MISSING_BODY"));
    };

    let ctx = pcf_self();
    let existing = ctx
        .read()
        .ok()
        .and_then(|c| c.event_sub_find_by_subscription_id(sub_id));
    let Some(existing) = existing else {
        return send_not_found(
            &format!("Policy control events subscription {sub_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        );
    };

    let parsed = match parse_subsc(body) {
        Ok(p) => p,
        Err(resp) => return *resp,
    };

    let updated = PcEventSubscription {
        id: existing.id,
        subscription_id: existing.subscription_id.clone(),
        notif_uri: parsed.notif_uri,
        notif_id: parsed.notif_id,
        event_subs: parsed.event_subs,
        filter_dnns: parsed.filter_dnns,
        group_id: parsed.group_id,
        max_report_nbr: parsed.max_report_nbr,
        report_count: existing.report_count,
        raw: parsed.raw.clone(),
    };

    let Ok(context) = ctx.read() else {
        return SbiResponse::with_status(500);
    };
    if !context.event_sub_update(&updated) {
        return SbiResponse::with_status(500);
    }

    log::info!(
        "Npcf_EventExposure subscription {} updated (events={:?})",
        updated.subscription_id,
        updated.event_subs
    );
    SbiResponse::with_status(200)
        .with_json_body(&updated.raw)
        .unwrap_or_else(|_| SbiResponse::with_status(500))
}

/// `DELETE /npcf-eventexposure/v1/subscriptions/{subscriptionId}` — 204.
pub async fn handle_delete(sub_id: &str) -> SbiResponse {
    let ctx = pcf_self();
    let removed = ctx.read().ok().and_then(|c| c.event_sub_remove(sub_id));
    match removed {
        Some(sub) => {
            log::info!(
                "Npcf_EventExposure subscription {} deleted",
                sub.subscription_id
            );
            SbiResponse::with_status(204)
        }
        None => send_not_found(
            &format!("Policy control events subscription {sub_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        ),
    }
}

/// Route an `npcf-eventexposure` request.
///
/// `parts` is the path with the leading '/' trimmed and split on '/', matching
/// what `pcf_sbi_request_handler` builds: `parts[0]` is the service name,
/// `parts[1]` the version, `parts[2]` the resource and `parts[3]` the
/// `{subscriptionId}`. So the collection is length 3 and the individual
/// resource length 4.
pub async fn route(parts: &[&str], method: &str, uri: &str, request: &SbiRequest) -> SbiResponse {
    match (parts.get(2), parts.len(), method) {
        (Some(&"subscriptions"), 3, "POST") => handle_create(request).await,
        (Some(&"subscriptions"), 4, "GET") => handle_get(parts[3]).await,
        (Some(&"subscriptions"), 4, "PUT") => handle_update(parts[3], request).await,
        (Some(&"subscriptions"), 4, "DELETE") => handle_delete(parts[3]).await,
        // A known resource reached with the wrong method answers 405 WITH an
        // Allow header, which is what #229 established for the Nudm surface;
        // anything else is a resource this service does not have.
        (Some(&"subscriptions"), 3, _) => {
            send_method_not_allowed_with_allow(method, uri, &["POST"])
        }
        (Some(&"subscriptions"), 4, _) => {
            send_method_not_allowed_with_allow(method, uri, &["GET", "PUT", "DELETE"])
        }
        _ => nextgcore_sbi::server::send_resource_uri_not_found(uri),
    }
}

/// Build a `PcEventExposureNotif` for one event (TS 29.523 §5.6.2.2).
///
/// `extra` carries the event-specific members of `PcEventNotification` — for
/// example `accType`/`ratType` for `AC_TY_CH`, or `plmnId` for `PLMN_CH`. Only
/// `event` and `timeStamp` are mandatory, and nothing is invented: a member the
/// caller does not hold is simply absent.
pub fn build_notification(
    notif_id: &str,
    event: &str,
    extra: serde_json::Value,
) -> serde_json::Value {
    let mut notif = serde_json::json!({
        "event": event,
        "timeStamp": epoch_to_rfc3339(now_secs()),
    });
    if let (Some(obj), Some(add)) = (notif.as_object_mut(), extra.as_object()) {
        for (k, v) in add {
            obj.insert(k.clone(), v.clone());
        }
    }
    serde_json::json!({
        "notifId": notif_id,
        "eventNotifs": [notif],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_to_rfc3339_matches_known_instants() {
        assert_eq!(epoch_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(epoch_to_rfc3339(946_684_800), "2000-01-01T00:00:00Z");
        // A leap day, which the civil_from_days conversion has to get right.
        assert_eq!(epoch_to_rfc3339(1_583_020_800), "2020-03-01T00:00:00Z");
    }

    #[test]
    fn build_notification_carries_only_what_it_is_given() {
        let n = build_notification("nid-1", "PLMN_CH", serde_json::json!({}));
        assert_eq!(n["notifId"], "nid-1");
        assert_eq!(n["eventNotifs"][0]["event"], "PLMN_CH");
        assert!(n["eventNotifs"][0]["timeStamp"].is_string());
        // Nothing fabricated: only the two mandatory members are present.
        let obj = n["eventNotifs"][0].as_object().expect("object");
        assert_eq!(
            obj.len(),
            2,
            "an absent member must be omitted, never placeheld: {obj:?}"
        );

        let n = build_notification(
            "nid-2",
            "AC_TY_CH",
            serde_json::json!({"accType": "NON_3GPP_ACCESS"}),
        );
        assert_eq!(n["eventNotifs"][0]["accType"], "NON_3GPP_ACCESS");
    }

    #[test]
    fn serviceable_events_keeps_only_tokens_with_producers() {
        let requested: Vec<String> = ["PLMN_CH", "SAC_CH", "AC_TY_CH", "SOME_FUTURE_EVENT"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let ok = PcEventSubscription::serviceable_events(&requested);
        assert_eq!(ok, vec!["PLMN_CH".to_string(), "AC_TY_CH".to_string()]);
    }
}
