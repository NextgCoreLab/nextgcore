//! NWDAF SBI Handler
//!
//! Implements Nnwdaf SBI services (TS 23.288):
//! - Nnwdaf_AnalyticsInfo: Analytics query and retrieval
//! - Nnwdaf_EventsSubscription: Analytics subscription management
//! - Nnwdaf_MLModelProvision: ML model provision Subscribe/Notify (nwafd-05)

use crate::analytics::ObservationWindow;
use crate::context::*;
use crate::notification_dispatcher::{compute_event_infos, EventInfoFilter};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::{send_bad_request, send_error, send_not_found};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Monitoring duration used when `evtReq.monDur` is absent (issue #108).
///
/// Keeps the pre-#108 window so a consumer that sends no `evtReq` sees unchanged
/// behaviour — except that its subscription now terminates with a `termCause`
/// instead of vanishing.
const DEFAULT_MONITORING_DURATION_SECS: u64 = 3600;

/// Validity of an `AnalyticsData` report when the consumer requested no
/// analytics target period, and the span of a target period the consumer bounded
/// on only one side (issue #171).
///
/// TS 29.520 NOTE 7 on `AnalyticsData` leaves the validity period to "NWDAF
/// internal logic" as long as it is a subset of the requested target period, so
/// this keeps the pre-#171 one hour: a consumer that sends no `ana-req` sees
/// byte-unchanged `start`/`expiry`.
const DEFAULT_ANALYTICS_VALIDITY_SECS: i64 = 3600;

/// Seconds since the Unix epoch.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_secs()
}

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

/// The string members of a JSON array property, or empty when the property is
/// absent, null or not an array of strings.
fn json_string_array(v: &serde_json::Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.as_str())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
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
    // `nfSetIds` is an alternative to `nfInstanceIds` in TS 29.520 §4.3.2.2.2
    // that this NWDAF does not resolve (it has no NF-Set membership view), so a
    // query naming only NF Sets is not narrowed by it. Said out loud rather than
    // dropped silently — a caller cannot otherwise tell a honoured filter from an
    // ignored one.
    if !json_string_array(&v, "nfSetIds").is_empty() {
        log::warn!(
            "event-filter.nfSetIds is not honoured by this NWDAF: NF-Set membership is not \
             tracked, so the query is not narrowed to those sets (TS 29.520 §4.3.2.2.2)"
        );
    }
    Ok(EventInfoFilter {
        nf_instance_ids: json_string_array(&v, "nfInstanceIds"),
        nf_types: json_string_array(&v, "nfTypes"),
        window: None,
    })
}

/// The `tgt-ue` query parameter of `GET /analytics`: TS 29.520
/// `TargetUeInformation` (`TS29520_Nnwdaf_AnalyticsInfo.yaml:62-69`).
///
/// Only the members that decide *scope* are modelled — whether the request
/// applies to every UE or to an identified set. `ueIpAddrs` counts as an
/// identified set without its shape being modelled: it still names specific UEs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TargetUeInfo {
    /// `anyUe` — the request applies to every UE (default false when omitted).
    any_ue: bool,
    /// `supis`
    supis: Vec<String>,
    /// `gpsis`
    gpsis: Vec<String>,
    /// `intGroupIds`
    int_group_ids: Vec<String>,
    /// Whether `ueIpAddrs` was present.
    ue_ip_addrs: bool,
}

impl TargetUeInfo {
    /// Whether this restricts the request to an identified set of UEs, as
    /// opposed to `anyUe`.
    fn names_specific_ues(&self) -> bool {
        !self.supis.is_empty()
            || !self.gpsis.is_empty()
            || !self.int_group_ids.is_empty()
            || self.ue_ip_addrs
    }

    /// Whether this `TargetUeInformation` identifies any target at all. A body
    /// that sets neither `anyUe` nor any identifier scopes nothing, which is a
    /// malformed query parameter rather than an empty filter.
    fn identifies_a_target(&self) -> bool {
        self.any_ue || self.names_specific_ues()
    }
}

/// Parse the `tgt-ue` query parameter into [`TargetUeInfo`] (issue #171).
///
/// `Ok(None)` = the parameter was absent. Present-but-not-JSON, or a
/// `TargetUeInformation` identifying no target, is `Err` → 400: the yaml declares
/// this parameter as `content: application/json`, so a bare identifier string is
/// not a conformant value, and quietly ignoring it is precisely the defect.
fn parse_target_ue(raw: Option<&String>) -> Result<Option<TargetUeInfo>, String> {
    let raw = match raw {
        Some(r) if !r.is_empty() => r,
        _ => return Ok(None),
    };
    let v: serde_json::Value = serde_json::from_str(raw)
        .map_err(|e| format!("tgt-ue is not valid TargetUeInformation JSON: {e}"))?;
    let info = TargetUeInfo {
        any_ue: v.get("anyUe").and_then(|x| x.as_bool()).unwrap_or(false),
        supis: json_string_array(&v, "supis"),
        gpsis: json_string_array(&v, "gpsis"),
        int_group_ids: json_string_array(&v, "intGroupIds"),
        ue_ip_addrs: v.get("ueIpAddrs").is_some_and(|x| !x.is_null()),
    };
    if !info.identifies_a_target() {
        return Err(
            "tgt-ue identifies no target UE: one of anyUe/supis/gpsis/intGroupIds/ueIpAddrs \
             is required"
                .to_string(),
        );
    }
    Ok(Some(info))
}

/// The analytics target period a consumer asked for, derived from the `ana-req`
/// query parameter (TS 29.520 `EventReportingRequirement`, issue #171).
///
/// Never straddles the present — see [`parse_analytics_target_period`] — so
/// [`is_statistics`](Self::is_statistics) is a total classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AnalyticsTargetPeriod {
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
}

impl AnalyticsTargetPeriod {
    /// Whether this period refers to the past, i.e. the consumer asked for
    /// STATISTICS rather than a prediction (TS 29.520 NOTE 7 on `AnalyticsData`).
    fn is_statistics(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        self.end <= now
    }

    /// The sample-selection window a statistics request must be computed over.
    fn observation_window(&self) -> ObservationWindow {
        ObservationWindow::new(
            self.start.timestamp().max(0) as u64,
            self.end.timestamp().max(0) as u64,
        )
    }
}

/// `t + d`, or a 400-shaped error when the result leaves the representable
/// `DateTime` range (reachable from a consumer-supplied instant at the edge of
/// the calendar).
fn shifted(
    t: chrono::DateTime<chrono::Utc>,
    d: chrono::Duration,
) -> Result<chrono::DateTime<chrono::Utc>, (String, &'static str)> {
    t.checked_add_signed(d).ok_or_else(|| {
        (
            "the analytics target period falls outside the representable DateTime range"
                .to_string(),
            "INVALID_QUERY_PARAM",
        )
    })
}

/// Parse the `ana-req` query parameter into the requested analytics target
/// period (issue #171).
///
/// `ana-req` is TS 29.520 `EventReportingRequirement`
/// (`TS29520_Nnwdaf_AnalyticsInfo.yaml:41-48`); the target period is
/// `startTs`/`endTs`, with `offsetPeriod` as the relative alternative (negative =
/// statistics over the past offset period, positive = prediction over the future
/// one). `Ok(None)` means the consumer requested no period, which keeps the
/// pre-#171 internal default window.
///
/// Two deliberate shapes:
///
/// - **`400 BOTH_STAT_PRED_NOT_ALLOWED`** when `startTs` is in the past and
///   `endTs` in the future (TS 29.520 §4.3.2.2.2, table 5.2.7.3-1): that asks for
///   statistics and prediction in one request.
/// - A period the consumer bounded on **one** side has the other bound derived
///   and **clamped to `now`**, so a derived period never straddles the present.
///   That keeps `BOTH_STAT_PRED_NOT_ALLOWED` tied to a period the consumer
///   actually asked to straddle, which is how the spec words it.
///
/// Every malformed value fails closed with `400 INVALID_QUERY_PARAM` rather than
/// silently falling back to the default window.
fn parse_analytics_target_period(
    raw: Option<&String>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<AnalyticsTargetPeriod>, (String, &'static str)> {
    let raw = match raw {
        Some(r) if !r.is_empty() => r,
        _ => return Ok(None),
    };
    let v: serde_json::Value = serde_json::from_str(raw).map_err(|e| {
        (
            format!("ana-req is not valid EventReportingRequirement JSON: {e}"),
            "INVALID_QUERY_PARAM",
        )
    })?;

    let instant =
        |key: &str| -> Result<Option<chrono::DateTime<chrono::Utc>>, (String, &'static str)> {
            match v.get(key) {
                None | Some(serde_json::Value::Null) => Ok(None),
                Some(x) => {
                    let s = x.as_str().ok_or_else(|| {
                        (
                            format!("ana-req.{key} must be an RFC-3339 DateTime string"),
                            "INVALID_QUERY_PARAM",
                        )
                    })?;
                    let dt = chrono::DateTime::parse_from_rfc3339(s).map_err(|e| {
                        (
                            format!("ana-req.{key} is not a valid RFC-3339 DateTime: {e}"),
                            "INVALID_QUERY_PARAM",
                        )
                    })?;
                    Ok(Some(dt.with_timezone(&chrono::Utc)))
                }
            }
        };

    let start_ts = instant("startTs")?;
    let end_ts = instant("endTs")?;
    let default = chrono::Duration::seconds(DEFAULT_ANALYTICS_VALIDITY_SECS);

    let (start, end) = match (start_ts, end_ts) {
        (Some(s), Some(e)) => {
            if e < s {
                return Err((
                    "ana-req.endTs is earlier than ana-req.startTs".to_string(),
                    "INVALID_QUERY_PARAM",
                ));
            }
            if s < now && e > now {
                return Err((
                    "the analytics target period starts in the past and ends in the future, \
                     which requests both statistics and prediction"
                        .to_string(),
                    "BOTH_STAT_PRED_NOT_ALLOWED",
                ));
            }
            (s, e)
        }
        (Some(s), None) if s < now => (s, now),
        (Some(s), None) => (s, shifted(s, default)?),
        (None, Some(e)) if e > now => (now, e),
        (None, Some(e)) => (shifted(e, -default)?, e),
        (None, None) => match v.get("offsetPeriod") {
            None | Some(serde_json::Value::Null) => return Ok(None),
            Some(x) => {
                let offset = x.as_i64().ok_or_else(|| {
                    (
                        "ana-req.offsetPeriod must be an integer number of seconds".to_string(),
                        "INVALID_QUERY_PARAM",
                    )
                })?;
                if offset == 0 {
                    return Ok(None);
                }
                let d = chrono::Duration::try_seconds(offset).ok_or_else(|| {
                    (
                        "ana-req.offsetPeriod is out of range".to_string(),
                        "INVALID_QUERY_PARAM",
                    )
                })?;
                if offset < 0 {
                    (shifted(now, d)?, now)
                } else {
                    (now, shifted(now, d)?)
                }
            }
        },
    };

    Ok(Some(AnalyticsTargetPeriod { start, end }))
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
/// G2-3 (supported-events honesty): a recognised event with **no live
/// collector** (not in [`SUPPORTED_EVENTS`]) is also 204 — its analytics data
/// cannot exist. Only tokens outside the `NwdafEvent` enum are 400
/// `INVALID_ANALYTICS_TYPE`. The former non-spec `tgtUe` echo is removed.
///
/// T5.4/issue #26 HONESTY NOTE: the analytics engine routes prediction and
/// `confidence` through the active `ml_service::InferenceModel` (default: the
/// OLS linear-regression baseline, whose confidence is the regression R²
/// scaled to a Uinteger; the feature-gated `onnx-model` backend loads real
/// linear model files — TS 23.288 §6.14).
///
/// Issue #171: `tgt-ue` and `ana-req` are now typed, validated and acted on
/// instead of being bound to unused locals.
///
/// - The reported `start`/`expiry` are a subset of the requested analytics target
///   period (`ana-req.startTs`/`endTs`/`offsetPeriod`), per NOTE 7 on
///   `AnalyticsData`, and default to `now`/`now + 3600 s` when none is requested.
/// - A target period in the **past** is a request for statistics, so the samples
///   are restricted to that period; if none falls inside it the answer is
///   `500 UNAVAILABLE_DATA` rather than statistics from another period.
/// - A period starting in the past and ending in the future is
///   `400 BOTH_STAT_PRED_NOT_ALLOWED`.
/// - `tgt-ue` scoping follows §4.3.2.2.2 for NF_LOAD (see the inline gate).
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

    // Issue #16 (non-normative 6G ISAC): sensing-summary surface. Not a TS
    // 29.520 NwdafEvent token, so intercept before AnalyticsId parsing.
    #[cfg(feature = "sensing")]
    if event_token == "ISAC_SENSING" {
        // Fail closed on a malformed optional event-filter, matching the
        // TS 29.520 path below (INVALID_QUERY_PARAM).
        if let Err(detail) = parse_event_filter(params.get("event-filter")) {
            return send_bad_request(&detail, Some("INVALID_QUERY_PARAM"));
        }
        return isac_sensing_summary_with_ctx(ctx);
    }

    // Issue #175: `event-id` is typed `EventId`
    // (`TS29520_Nnwdaf_AnalyticsInfo.yaml:35-40`), NOT the `NwdafEvent` the
    // EventsSubscription API uses. The two enumerations differ, so parsing this
    // with `from_str` rejected `LOAD_LEVEL_INFORMATION` — the spec's own token for
    // slice load level on THIS API — while accepting `SLICE_LOAD_LEVEL` and
    // `PFD_DETERMINATION`, which `EventId` does not define.
    let analytics_id = match AnalyticsId::from_event_id(event_token) {
        Some(id) => id,
        None => {
            return send_bad_request(
                &format!("Invalid event-id: {event_token} is not a TS 29.520 EventId value"),
                Some("INVALID_ANALYTICS_TYPE"),
            )
        }
    };

    // ── request validation (issue #171) ──────────────────────────────────────
    // `ana-req` and `tgt-ue` are parsed BEFORE the supported-events gate below:
    // a malformed request is malformed whether or not the event could be served,
    // which is the order the existing `event-id` validation already establishes.
    // Both fail closed, like `event-filter`: answering over a window or a
    // population the consumer did not ask for is the defect being fixed.
    let now = chrono::Utc::now();
    let target_period = match parse_analytics_target_period(params.get("ana-req"), now) {
        Ok(p) => p,
        Err((detail, cause)) => return send_bad_request(&detail, Some(cause)),
    };
    let target_ue = match parse_target_ue(params.get("tgt-ue")) {
        Ok(t) => t,
        Err(detail) => return send_bad_request(&detail, Some("INVALID_QUERY_PARAM")),
    };
    // `supported-features` is read and acknowledged. No optional feature of this
    // API is implemented, so nothing is negotiated away — logged rather than
    // silently dropped (SBI feature negotiation is issue #65).
    if let Some(features) = params.get("supported-features") {
        log::debug!(
            "AnalyticsInfo supported-features={features}: this NWDAF negotiates no optional \
             feature of TS 29.520, so the response carries no suppFeat"
        );
    }

    // G2-3 (supported-events honesty): a recognised NwdafEvent token with no
    // live collector means the requested analytics data cannot exist → 204 No
    // Content (TS 29.520 §4.3.2.2.2), NOT 400/501 and never an empty-200.
    // Unrecognised tokens were already rejected above with 400
    // INVALID_ANALYTICS_TYPE. Derived from context::SUPPORTED_EVENTS.
    if !analytics_id.is_supported() {
        return SbiResponse::with_status(204);
    }

    // event-filter (G2-1): nfInstanceIds/nfTypes are honored; malformed JSON
    // fails closed with 400.
    let filter = match parse_event_filter(params.get("event-filter")) {
        Ok(f) => f,
        Err(detail) => return send_bad_request(&detail, Some("INVALID_QUERY_PARAM")),
    };

    // tgt-ue scoping (issue #171). TS 29.520 §4.3.2.2.2 for NF_LOAD — the only
    // event with a live collector, so the only one whose tgt-ue semantics are
    // reachable; a future collector for a UE-scoped event needs its own arm here:
    //
    //  * NOTE 4 — "Only NF instances of type AMF and SMF which are serving the UE
    //    can be determined using a SUPI in supis". Resolving a SUPI to the NF
    //    instances *serving* it needs a UE→serving-NF view this NWDAF does not
    //    collect, so the requested analytics data does not exist → 204. Reporting
    //    every AMF/SMF instead would relabel a whole-network figure as that UE's.
    //  * NOTE 5 — "If a list of the NF Instance IDs ... is provided ... the target
    //    UE(s) of the Analytics Reporting need be ignored". So a UE-scoped tgt-ue
    //    accompanied by event-filter.nfInstanceIds IS served. `nfSetIds` does not
    //    trigger this exception: it is not resolved to instances (see
    //    `parse_event_filter`), and serving every instance for an unresolved set
    //    would be broader than the consumer asked for.
    //
    // `anyUe`, and an absent tgt-ue, impose no restriction. §4.3.2.2.2 says a
    // NF_LOAD consumer *shall* provide tgt-ue, but that mandate is conditional on
    // the `NfLoad` feature being negotiated and `supported-features` is not acted
    // on yet (issue #65), so absence is treated as "no UE restriction" rather
    // than rejected.
    if target_ue
        .as_ref()
        .is_some_and(TargetUeInfo::names_specific_ues)
        && filter.nf_instance_ids.is_empty()
    {
        log::info!(
            "AnalyticsInfo {}: tgt-ue names specific UEs but this NWDAF holds no \
             UE-to-serving-NF mapping and the query names no nfInstanceIds, so no analytics \
             exist for that scope → 204 (TS 29.520 §4.3.2.2.2 NOTE 4/NOTE 5)",
            analytics_id.as_str()
        );
        return SbiResponse::with_status(204);
    }

    // A PAST target period is a request for statistics, which must be computed
    // from that period's samples (NOTE 7 on `AnalyticsData`). A FUTURE one is a
    // prediction, computed *from* past samples, so it is deliberately not
    // windowed — restricting the input to the prediction interval would leave
    // nothing to predict from.
    let statistics_window = target_period
        .filter(|p| p.is_statistics(now))
        .map(|p| p.observation_window());
    let filter = match statistics_window {
        Some(window) => filter.with_window(window),
        None => filter,
    };

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

    if infos.as_array().is_none_or(|a| a.is_empty()) {
        // TS 29.520 §4.3.2.2.2: "If the statistics in the past are requested but
        // the necessary data to perform the service is unavailable, the NWDAF
        // shall reject the request with an HTTP 500 ... cause UNAVAILABLE_DATA."
        // Only a PAST target period escalates: absent data with no period, or a
        // future one, stays 204 ("the requested analytics data does not exist").
        if let Some(window) = statistics_window {
            log::info!(
                "AnalyticsInfo {}: no sample inside the requested statistics window \
                 [{}, {}] → 500 UNAVAILABLE_DATA",
                analytics_id.as_str(),
                window.start,
                window.end
            );
            return send_error(
                500,
                "Internal Server Error",
                "no data was collected inside the requested analytics target period, so the \
                 requested statistics cannot be computed",
                Some("UNAVAILABLE_DATA"),
            );
        }
        return SbiResponse::with_status(204);
    }

    // The reported validity period is a subset of the requested analytics target
    // period (NOTE 7 on `AnalyticsData`), or the internal default hour when the
    // consumer requested none.
    let (period_start, period_end) = match target_period {
        Some(p) => (p.start, p.end),
        None => (
            now,
            now + chrono::Duration::seconds(DEFAULT_ANALYTICS_VALIDITY_SECS),
        ),
    };
    let start = period_start.to_rfc3339();
    let expiry = period_end.to_rfc3339();

    // Build the AnalyticsData object with the event-specific payload member.
    //
    // Issue #172: the member name comes from `AnalyticsData`, NOT from the
    // EventsSubscription `EventNotification` schema — they disagree for four
    // tokens. `None` means `AnalyticsData` defines no member for this event
    // (PFD_DETERMINATION, which is not even an `EventId` value), so there is no
    // conformant body to return and the honest answer is 204 rather than a
    // fabricated member name. Unreachable while that event has no collector, but
    // it is the guard a future collector needs.
    let Some(infos_key) = analytics_id.analytics_data_key() else {
        log::info!(
            "AnalyticsInfo {}: TS 29.520 AnalyticsData defines no member for this event (it is \
             not an EventId value — subscribe/notify only), so no conformant response body \
             exists → 204",
            analytics_id.as_str()
        );
        return SbiResponse::with_status(204);
    };
    let mut analytics_data = serde_json::Map::new();
    analytics_data.insert(infos_key.to_string(), infos);
    analytics_data.insert("start".to_string(), serde_json::json!(start));
    analytics_data.insert("expiry".to_string(), serde_json::json!(expiry));
    analytics_data.insert(
        "timeStampGen".to_string(),
        serde_json::json!(now.to_rfc3339()),
    );

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::Value::Object(analytics_data))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Handle Nnwdaf_AnalyticsInfo query against the global context.
pub async fn handle_analytics_info_query(request: &SbiRequest) -> SbiResponse {
    let ctx = nwdaf_self();
    handle_analytics_info_query_with_ctx(&ctx, request).await
}

// ── Nnwdaf_AnalyticsInfo_ContextTransfer (TS 29.520 §4.3.2.3, issue #171) ─────

/// One entry of the `context-ids` query parameter: TS 29.520
/// `AnalyticsContextIdentifier`, which requires `subscriptionId` plus at least
/// one of `nfAnaCtxts`/`ueAnaCtxts`.
#[derive(Debug, Clone)]
struct RequestedAnalyticsContext {
    /// `subscriptionId` — the analytics subscription this context belongs to.
    subscription_id: String,
    /// `nfAnaCtxts` — the NF-related analytics types whose context is wanted.
    /// Empty means the consumer asked only for UE-related contexts.
    nf_ana_ctxts: Vec<String>,
    /// Whether `ueAnaCtxts` was present. Carried so the handler can say plainly
    /// that no UE-related analytics context exists here, rather than answering
    /// with NF contexts the consumer did not ask for.
    wants_ue_contexts: bool,
}

/// Parse the mandatory `context-ids` query parameter (TS 29.520 `ContextIdList`).
fn parse_context_id_list(
    raw: Option<&String>,
) -> Result<Vec<RequestedAnalyticsContext>, (String, &'static str)> {
    let raw = match raw {
        Some(r) if !r.is_empty() => r,
        _ => {
            return Err((
                "context-ids query parameter is mandatory".to_string(),
                "MANDATORY_QUERY_PARAM_INCORRECT",
            ))
        }
    };
    let v: serde_json::Value = serde_json::from_str(raw).map_err(|e| {
        (
            format!("context-ids is not valid ContextIdList JSON: {e}"),
            "INVALID_QUERY_PARAM",
        )
    })?;
    let ids = v
        .get("contextIds")
        .and_then(|x| x.as_array())
        .filter(|a| !a.is_empty())
        .ok_or_else(|| {
            (
                "context-ids.contextIds is a required member with minItems 1".to_string(),
                "INVALID_QUERY_PARAM",
            )
        })?;

    let mut out = Vec::with_capacity(ids.len());
    for item in ids {
        let subscription_id = item
            .get("subscriptionId")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                (
                    "every AnalyticsContextIdentifier requires a subscriptionId".to_string(),
                    "INVALID_QUERY_PARAM",
                )
            })?;
        let nf_ana_ctxts = json_string_array(item, "nfAnaCtxts");
        let wants_ue_contexts = item
            .get("ueAnaCtxts")
            .and_then(|x| x.as_array())
            .is_some_and(|a| !a.is_empty());
        if nf_ana_ctxts.is_empty() && !wants_ue_contexts {
            return Err((
                "every AnalyticsContextIdentifier requires nfAnaCtxts or ueAnaCtxts".to_string(),
                "INVALID_QUERY_PARAM",
            ));
        }
        out.push(RequestedAnalyticsContext {
            subscription_id: subscription_id.to_string(),
            nf_ana_ctxts,
            wants_ue_contexts,
        });
    }
    Ok(out)
}

/// Parse the optional `req-context` query parameter (TS 29.520
/// `RequestedContext`), returning the requested `ContextType` tokens.
///
/// `Ok(None)` = absent, which §4.3.2.3.2 leaves as "whatever is available".
/// `contexts` is a required member with minItems 1, so present-but-empty is a
/// 400. Unrecognised tokens are CARRIED rather than rejected: `ContextType` has a
/// free-form `anyOf` alternative for forward compatibility, exactly like
/// `NwdafEvent` (issue #108).
fn parse_requested_context(
    raw: Option<&String>,
) -> Result<Option<Vec<String>>, (String, &'static str)> {
    let raw = match raw {
        Some(r) if !r.is_empty() => r,
        _ => return Ok(None),
    };
    let v: serde_json::Value = serde_json::from_str(raw).map_err(|e| {
        (
            format!("req-context is not valid RequestedContext JSON: {e}"),
            "INVALID_QUERY_PARAM",
        )
    })?;
    let contexts = json_string_array(&v, "contexts");
    if contexts.is_empty() {
        return Err((
            "req-context.contexts is a required member with minItems 1".to_string(),
            "INVALID_QUERY_PARAM",
        ));
    }
    Ok(Some(contexts))
}

/// Format a Unix-seconds timestamp as the RFC-3339 string a TS 29.571 `DateTime`
/// requires, or `None` when the value is not a representable instant.
fn rfc3339_from_unix(secs: u64) -> Option<String> {
    chrono::DateTime::from_timestamp(i64::try_from(secs).ok()?, 0).map(|dt| dt.to_rfc3339())
}

/// Handle `GET /nnwdaf-analyticsinfo/v1/context` against an explicit context.
///
/// The Nnwdaf_AnalyticsInfo_ContextTransfer service operation (`GetNwdafContext`,
/// TS 29.520 §4.3.2.3, `TS29520_Nnwdaf_AnalyticsInfo.yaml:118`). Issue #171: this
/// route did not exist, so an operation on an otherwise-advertised API surface
/// 404'd.
///
/// For each requested `AnalyticsContextIdentifier` naming a **known**
/// subscription, the `ContextData` response carries a `ContextElement` with:
///
/// - `contextId` — `{subscriptionId, nfAnaCtxts}`, where `nfAnaCtxts` is the
///   intersection of the requested analytics types with the subscription's events
///   **that have a live collector**. An event with no collector has no analytics
///   context to transfer, so the `SUPPORTED_EVENTS` gate every other wire surface
///   uses applies here too. An empty intersection contributes no element (and
///   `nfAnaCtxts` has `minItems: 1`, so an empty array would be schema-invalid).
/// - `lastOutputTime` — the subscription's last dispatched notification, when one
///   has gone out and the consumer asked for `PENDING_ANALYTICS` and/or
///   `HISTORICAL_ANALYTICS` (or sent no `req-context` at all).
///
/// Nothing matching → **204**, per "if the requested context information does not
/// exist, the NWDAF shall respond with 204 No Content".
///
/// WHAT IS OMITTED, AND WHY THAT IS CONFORMANT RATHER THAN A FACADE: every other
/// `ContextElement` member is conditional on the information being *available*.
/// This NWDAF stores no analytics history and no aggregation state, so
/// `pendAnalytics`, `histAnalytics`, `histData`, `aggrSubs`, `aggrNwdafIds`,
/// `adrfId`/`adrfDataTypes`, `anaAccuInfos` and `modelAccuInfos` are absent, and
/// the requested-but-unavailable types are named in a log line. `modelInfo` is
/// absent for a different reason worth recording: it describes ML models the
/// *consumer* NWDAF subscribes to for the analytics, whereas this NWDAF is the
/// MTLF serving its own artefact (issue #109) — emitting our own model there
/// would be the wrong direction, not merely incomplete.
///
/// `pendAnalytics` was considered and rejected rather than overlooked: the only
/// code that builds `EventNotification[]` is
/// `notification_dispatcher::build_event_notifications`, which MUTATES THRESHOLD
/// edge-detection state via `set_event_level`. Calling it from a GET would let a
/// read suppress a later THRESHOLD notification. Serving analytics history needs
/// its own storage and belongs in its own issue.
pub async fn handle_nwdaf_context_query_with_ctx(
    ctx: &Arc<RwLock<NwdafContext>>,
    request: &SbiRequest,
) -> SbiResponse {
    log::info!("NWDAF Context Transfer: {}", request.header.uri);

    let params = request_query_params(request);
    let requested_ids = match parse_context_id_list(params.get("context-ids")) {
        Ok(ids) => ids,
        Err((detail, cause)) => return send_bad_request(&detail, Some(cause)),
    };
    let requested_contexts = match parse_requested_context(params.get("req-context")) {
        Ok(c) => c,
        Err((detail, cause)) => return send_bad_request(&detail, Some(cause)),
    };

    // §4.3.2.3.2 reports `lastOutputTime` when the consumer indicated the pending
    // and/or historical output-analytics context types; an absent `req-context`
    // asks for whatever is available.
    let wants_output_time = requested_contexts.as_ref().is_none_or(|types| {
        types
            .iter()
            .any(|t| t == "PENDING_ANALYTICS" || t == "HISTORICAL_ANALYTICS")
    });
    if let Some(types) = &requested_contexts {
        log::info!(
            "NWDAF context transfer requested context types {types:?}: this NWDAF stores no \
             analytics history, aggregation state or ADRF data, so only contextId and \
             lastOutputTime are returned (TS 29.520 §4.3.2.3.2 makes every other \
             ContextElement member conditional on availability)"
        );
    }

    let guard = match ctx.read() {
        Ok(guard) => guard,
        Err(e) => {
            log::error!("handle_nwdaf_context_query: failed to read context: {e}");
            return nextgcore_sbi::server::send_internal_error("context unavailable");
        }
    };

    let mut elements: Vec<serde_json::Value> = Vec::new();
    for requested in &requested_ids {
        if requested.wants_ue_contexts {
            log::info!(
                "NWDAF context transfer: no UE-related analytics context exists for \
                 subscription {} — this NWDAF has no UE-scoped analytics collector, so \
                 ueAnaCtxts is not answered",
                requested.subscription_id
            );
        }
        let Some(sub) = guard.get_subscription(&requested.subscription_id) else {
            log::info!(
                "NWDAF context transfer: subscription {} is unknown — omitted from ContextData",
                requested.subscription_id
            );
            continue;
        };

        // The analytics contexts that actually exist for this subscription.
        let mut available: Vec<&'static str> = Vec::new();
        for event in &sub.events {
            let token = event.event.as_str();
            if !event.event.is_supported() || available.contains(&token) {
                continue;
            }
            if !requested.nf_ana_ctxts.iter().any(|r| r == token) {
                continue;
            }
            available.push(token);
        }
        if available.is_empty() {
            log::info!(
                "NWDAF context transfer: subscription {} has no analytics context matching \
                 the requested types {:?} that also has a live collector — omitted",
                requested.subscription_id,
                requested.nf_ana_ctxts
            );
            continue;
        }

        let mut context_id = serde_json::Map::new();
        context_id.insert(
            "subscriptionId".to_string(),
            serde_json::json!(sub.subscription_id),
        );
        context_id.insert("nfAnaCtxts".to_string(), serde_json::json!(available));

        let mut element = serde_json::Map::new();
        element.insert(
            "contextId".to_string(),
            serde_json::Value::Object(context_id),
        );
        if wants_output_time {
            if let Some(last) = sub.last_notification_time.and_then(rfc3339_from_unix) {
                element.insert("lastOutputTime".to_string(), serde_json::json!(last));
            }
        }
        elements.push(serde_json::Value::Object(element));
    }
    drop(guard);

    if elements.is_empty() {
        return SbiResponse::with_status(204);
    }

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({ "contextElems": elements }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Handle `GET /nnwdaf-analyticsinfo/v1/context` against the global context.
pub async fn handle_nwdaf_context_query(request: &SbiRequest) -> SbiResponse {
    let ctx = nwdaf_self();
    handle_nwdaf_context_query_with_ctx(&ctx, request).await
}

/// Issue #16 (non-normative 6G ISAC): ingest one `SensingResult` posted to
/// `POST /nnwdaf-sensingdata/v1/results`, against the global context.
#[cfg(feature = "sensing")]
pub async fn handle_sensing_result_post(request: &SbiRequest) -> SbiResponse {
    let ctx = nwdaf_self();
    handle_sensing_result_post_with_ctx(&ctx, request).await
}

/// Ingest one sensing result: store in the bounded ring buffer, publish an
/// `SbiEventCategory::Isac` event, bump the `ISAC_SENSING_RESULTS` counter.
#[cfg(feature = "sensing")]
pub async fn handle_sensing_result_post_with_ctx(
    ctx: &Arc<RwLock<NwdafContext>>,
    request: &SbiRequest,
) -> SbiResponse {
    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let result: nextgcore_proto::SensingResult = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            return send_bad_request(
                &format!("Invalid SensingResult JSON: {e}"),
                Some("INVALID_JSON"),
            )
        }
    };

    // Lock order (nf-context-lock-deadlocks): context read → one interior
    // lock at a time (ring buffer inside push, then broker inside publish).
    let (total, subscribers) = match ctx.read() {
        Ok(guard) => {
            let total = guard.push_sensing_result(result);
            let subscribers = guard.publish_isac_event("SENSING_RESULT", body.clone());
            (total, subscribers)
        }
        Err(e) => {
            log::error!("handle_sensing_result_post: failed to read context: {e}");
            return nextgcore_sbi::server::send_internal_error("context unavailable");
        }
    };
    log::info!(
        "ISAC sensing result ingested: {}={total}, subscribers_notified={subscribers}",
        nextgcore_metrics::ai_native::ISAC_SENSING_RESULTS.name
    );

    SbiResponse::with_status(201)
        .with_json_body(&serde_json::json!({ "ingestedTotal": total }))
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// Issue #16: sensing summary for `GET ...analytics?event-id=ISAC_SENSING` —
/// count + latest result; 204 when nothing has been ingested (house style for
/// "requested analytics data does not exist").
#[cfg(feature = "sensing")]
fn isac_sensing_summary_with_ctx(ctx: &Arc<RwLock<NwdafContext>>) -> SbiResponse {
    let (total, buffered, latest) = match ctx.read() {
        Ok(guard) => guard.sensing_snapshot(),
        Err(e) => {
            log::error!("isac_sensing_summary: failed to read context: {e}");
            return nextgcore_sbi::server::send_internal_error("context unavailable");
        }
    };
    if total == 0 {
        return SbiResponse::with_status(204);
    }
    let summary = serde_json::json!({
        "isacSensingSummary": {
            "ingestedTotal": total,
            "buffered": buffered,
            "latest": latest,
        }
    });
    SbiResponse::with_status(200)
        .with_json_body(&summary)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
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
    let mut unknown_events: Vec<String> = Vec::new();
    for es in event_array {
        let event_token = es.get("event").and_then(|v| v.as_str()).unwrap_or("");
        let event = match AnalyticsId::from_str(event_token) {
            Some(e) => e,
            None => {
                // Issue #108: an event outside the enumeration fails on its own,
                // not for the whole subscription. TS 29.520 §4.2.2.4.2 reports
                // events the NWDAF cannot serve via `failEventReports`, and the
                // `NwdafEvent` yaml has a free-form `anyOf` alternative
                // expressly for forward compatibility — so a consumer asking for
                // a newer analytics type must still receive the events it *is*
                // entitled to. Rejecting the lot with 400
                // INVALID_ANALYTICS_TYPE made that brittle.
                //
                // An `event` member that is absent entirely is a different
                // thing: it is a missing mandatory IE, not an unknown value.
                if event_token.is_empty() {
                    return Err((
                        "eventSubscriptions[] entry is missing the mandatory 'event' member"
                            .to_string(),
                        "MANDATORY_IE_MISSING",
                    ));
                }
                log::info!(
                    "subscription requests unrecognised event {event_token:?}; reporting it in \
                     failEventReports rather than rejecting the subscription"
                );
                unknown_events.push(event_token.to_string());
                continue;
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
        // Issue #108: `nfLoadLvlThds` is a LIST of ThresholdLevel and a
        // THRESHOLD notification fires when ANY entry is crossed; only `[0]`
        // used to be read, so every additional threshold was inert.
        let mut all_thresholds: Vec<u64> = match event {
            AnalyticsId::SliceLoadLevel | AnalyticsId::NsiLoadLevel => es
                .get("loadLevelThreshold")
                .and_then(|v| v.as_u64())
                .into_iter()
                .collect(),
            _ => es
                .get("nfLoadLvlThds")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|t| {
                            t.get("nfLoadLevel")
                                .or_else(|| t.get("nfCpuUsage"))
                                .and_then(|v| v.as_u64())
                        })
                        .collect()
                })
                .unwrap_or_default(),
        };
        let load_level_threshold = (!all_thresholds.is_empty()).then(|| all_thresholds.remove(0));
        let extra_load_level_thresholds = all_thresholds;

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
            extra_load_level_thresholds,
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

    // Issue #108: duration comes from `evtReq` → TS 29.523 `ReportingInformation`,
    // NOT a bespoke top-level `expiryTime`. The TS 29.520 subscription resource
    // has no `expiryTime` member at all (yaml:414-433), so the old key was
    // non-spec: a conformant consumer could not set it, and every subscription
    // silently died after the 3600 s default with no termCause.
    let evt_req = data.get("evtReq");
    // `monDur` is an absolute DateTime in TS 29.523; `monDurOrDuration` styles
    // vary by release, so accept either an RFC-3339 instant or a duration in
    // seconds and fall back to the previous 3600 s window when neither is given.
    let mon_dur_secs = evt_req
        .and_then(|r| r.get("monDur"))
        .and_then(|v| {
            v.as_u64().or_else(|| {
                v.as_str().and_then(|ts| {
                    chrono::DateTime::parse_from_rfc3339(ts)
                        .ok()
                        .map(|dt| dt.timestamp().max(0) as u64)
                        .map(|abs| abs.saturating_sub(now_secs()))
                })
            })
        })
        .unwrap_or(DEFAULT_MONITORING_DURATION_SECS);
    let max_report_nbr = evt_req
        .and_then(|r| r.get("maxReportNbr"))
        .and_then(|v| v.as_u64());
    let expiry_seconds = mon_dur_secs;

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
    subscription.unknown_events = unknown_events;
    subscription.max_report_nbr = max_report_nbr;
    if let Some(supi) = tgt_supi {
        subscription = subscription.with_target_supi(supi);
    }
    if let Some(s) = first_snssai {
        subscription = subscription.with_target_snssai(s);
    }
    Ok(subscription)
}

/// G2-3: build the TS 29.520 `failEventReports[]` array — one
/// `FailureEventInfo { event, failureCode }` (both mandatory per the yaml)
/// per event this NWDAF cannot serve. Empty when every event is serviceable.
///
/// Two distinct reasons land here, both `UNAVAILABLE_DATA`:
///
/// - a **recognised** event with no collector in this build (not in
///   [`SUPPORTED_EVENTS`]);
/// - an **unrecognised** token, i.e. outside the `NwdafEvent` enumeration
///   (issue #108). These used to fail the whole subscription with
///   `400 INVALID_ANALYTICS_TYPE`; they are now reported per-event, so a
///   consumer requesting a newer analytics type keeps the events it is entitled
///   to. The token is echoed back verbatim, since that is what the consumer
///   asked for and `FailureEventInfo.event` is a free-form-capable `NwdafEvent`.
fn fail_event_reports(sub: &AnalyticsSubscription) -> Vec<serde_json::Value> {
    sub.events
        .iter()
        .filter(|e| !e.event.is_supported())
        .map(|e| {
            serde_json::json!({
                "event": e.event.as_str(),
                "failureCode": "UNAVAILABLE_DATA",
            })
        })
        .chain(sub.unknown_events.iter().map(|token| {
            serde_json::json!({
                "event": token,
                "failureCode": "UNAVAILABLE_DATA",
            })
        }))
        .collect()
}

/// Build the 200/201 body echoing the stored subscription representation.
///
/// G2-3 (partial grant, TS 29.520): the subscription is ACCEPTED as a whole —
/// even when ALL events are unsupported the create still answers 201 (the yaml
/// allows every subscribed event to appear in `failEventReports`) — but each
/// unsupported event is declared failed via `failEventReports[]` with
/// `UNAVAILABLE_DATA`, and the dispatcher never notifies it.
fn events_subscription_echo(sub: &AnalyticsSubscription) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert(
        "subscriptionId".to_string(),
        serde_json::json!(sub.subscription_id),
    );
    obj.insert(
        "notificationURI".to_string(),
        serde_json::json!(sub.notification_uri),
    );
    obj.insert(
        "notifCorrId".to_string(),
        serde_json::json!(sub.notification_correlation_id),
    );
    obj.insert(
        "eventSubscriptions".to_string(),
        serde_json::json!(sub
            .events
            .iter()
            .map(event_subscription_json)
            .collect::<Vec<_>>()),
    );
    // failEventReports has minItems 1 in the yaml: omit entirely when empty.
    let failed = fail_event_reports(sub);
    if !failed.is_empty() {
        obj.insert("failEventReports".to_string(), serde_json::json!(failed));
    }
    serde_json::Value::Object(obj)
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
        // G2-3: the GET representation is the same echo as 201/200, including
        // failEventReports for events without a collector.
        Some(sub) => SbiResponse::with_status(200)
            .with_json_body(&events_subscription_echo(&sub))
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

/// Serve the ML model artefact a `Nnwdaf_MLModelProvision` notification pointed
/// at (issue #109, TS 29.520 §4.2.2.5).
///
/// Returns the active predictor serialized as an ONNX `ai.onnx.ml
/// LinearRegressor` — bytes that reproduce this NWDAF's own prediction, not a
/// stand-in. Before #109 the notified URL was a fabricated `http://nwdaf/...`
/// that no route served, so a consumer following it got a 404.
///
/// A 404 here means this NWDAF's active predictor has no exportable
/// fixed-window linear form (e.g. EWMA), which is also the state in which the
/// service is not advertised and no URL is emitted — so a conformant consumer
/// should never reach this branch.
pub async fn handle_ml_model_download() -> SbiResponse {
    let ctx = nwdaf_self();
    let bytes = match ctx.read() {
        Ok(context) => context.active_model_onnx(),
        Err(e) => {
            log::error!("ML model download: failed to read context: {e}");
            None
        }
    };

    match bytes {
        Some(bytes) => {
            log::debug!("Serving ONNX model artefact ({} bytes)", bytes.len());
            let mut response = SbiResponse::with_status(200);
            response
                .http
                .set_header("Content-Type", crate::onnx_export::ONNX_CONTENT_TYPE);
            response.http.binary_content = Some(bytes.into());
            response
        }
        None => send_not_found(
            "this NWDAF's active prediction model has no exportable form, so no \
             model artefact can be provisioned",
            Some("MODEL_NOT_AVAILABLE"),
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
        // `tgt-ue` is percent-encoded `{"anyUe":true}` — a conformant
        // TargetUeInformation (issue #171 made the bare `tgt-ue=imsi-001` this
        // test used to send a 400, since the yaml declares the parameter as
        // `content: application/json`).
        let req = SbiRequest::get(
            "/nnwdaf-analyticsinfo/v1/analytics?event-id=NF_LOAD&tgt-ue=%7B%22anyUe%22%3Atrue%7D",
        );
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
        // G2-3: the non-spec tgtUe echo is removed — TS 29.520 AnalyticsData
        // has no such member, even when the tgt-ue query parameter is present.
        assert!(
            body.get("tgtUe").is_none(),
            "non-spec tgtUe must not be injected into AnalyticsData"
        );

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

    // ── issue #175: event-id is an EventId, not a NwdafEvent ─────────────────

    /// **The #175 acceptance test.** `event-id` is typed `EventId`
    /// (`TS29520_Nnwdaf_AnalyticsInfo.yaml:35-40`), so
    /// `LOAD_LEVEL_INFORMATION` — the spec's own token for slice load level on
    /// THIS API — must be accepted. Before #175 it was rejected
    /// `400 INVALID_ANALYTICS_TYPE`, which is a live defect a conformant consumer
    /// hits immediately, unlike #172's latent member names.
    ///
    /// It resolves to the same analytics as `SLICE_LOAD_LEVEL` does on the
    /// subscribe surface, so with no collector for it the honest answer is 204 —
    /// the supported-events gate, NOT a parse rejection. The distinction is the
    /// whole point: 400 says "no such analytics type", 204 says "that analytics
    /// type exists but has no data".
    #[tokio::test]
    async fn test_analytics_info_accepts_the_event_id_spelling() {
        // NF_LOAD data exists, so a 204 can only come from the supported-events
        // gate rather than from a globally empty engine.
        let ctx = ctx_with_loads("AMF", "amf-eventid-01", &[50]);

        let resp = handle_analytics_info_query_with_ctx(
            &ctx,
            &SbiRequest::get("/nnwdaf-analyticsinfo/v1/analytics?event-id=LOAD_LEVEL_INFORMATION"),
        )
        .await;
        assert_eq!(
            resp.status, 204,
            "LOAD_LEVEL_INFORMATION is an EventId value: it must reach the \
             supported-events gate (204), not be rejected as an unknown type (400)"
        );

        // The two NwdafEvent-only spellings are NOT EventId values, so on this
        // surface they are a genuine 400 INVALID_ANALYTICS_TYPE.
        for token in ["SLICE_LOAD_LEVEL", "PFD_DETERMINATION"] {
            let uri = format!("/nnwdaf-analyticsinfo/v1/analytics?event-id={token}");
            let resp = handle_analytics_info_query_with_ctx(&ctx, &SbiRequest::get(&uri)).await;
            assert_eq!(
                resp.status, 400,
                "{token} is not an EventId value, so event-id={token} must be 400"
            );
            assert_eq!(
                body_json(&resp)["cause"].as_str(),
                Some("INVALID_ANALYTICS_TYPE")
            );
        }

        // Every other EventId value keeps reaching the gate, and a token outside
        // both enumerations is still a 400.
        let resp = handle_analytics_info_query_with_ctx(
            &ctx,
            &SbiRequest::get("/nnwdaf-analyticsinfo/v1/analytics?event-id=NF_LOAD"),
        )
        .await;
        assert_eq!(
            resp.status, 200,
            "NF_LOAD is spelled the same in both enums"
        );
        let resp = handle_analytics_info_query_with_ctx(
            &ctx,
            &SbiRequest::get("/nnwdaf-analyticsinfo/v1/analytics?event-id=NOT_AN_EVENT"),
        )
        .await;
        assert_eq!(resp.status, 400);
    }

    /// The subscribe surface is unchanged: `eventSubscriptions[].event` really is
    /// a `NwdafEvent`, so `SLICE_LOAD_LEVEL` belongs there and
    /// `LOAD_LEVEL_INFORMATION` does not — the exact opposite of the GET surface.
    #[tokio::test]
    async fn test_subscription_event_stays_a_nwdaf_event() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);

        let create = |token: &str| {
            SbiRequest::post("/nnwdaf-eventssubscription/v1/subscriptions")
                .with_json_body(&json!({
                    "notificationURI": "http://amf.example.org/notify",
                    "eventSubscriptions": [{ "event": token }]
                }))
                .expect("valid JSON body")
        };

        // SLICE_LOAD_LEVEL is a NwdafEvent → carried as a recognised event.
        let resp = handle_subscription_create(&create("SLICE_LOAD_LEVEL")).await;
        assert_eq!(resp.status, 201);
        assert_eq!(
            body_json(&resp)["eventSubscriptions"][0]["event"].as_str(),
            Some("SLICE_LOAD_LEVEL"),
            "the notify surface keeps the NwdafEvent spelling"
        );

        // LOAD_LEVEL_INFORMATION is NOT a NwdafEvent. Per #108 an unrecognised
        // token is reported per-event in failEventReports rather than rejecting
        // the subscription, so it lands there — echoed verbatim.
        let resp = handle_subscription_create(&create("LOAD_LEVEL_INFORMATION")).await;
        assert_eq!(resp.status, 201);
        let body = body_json(&resp);
        assert!(
            body["eventSubscriptions"]
                .as_array()
                .is_none_or(Vec::is_empty),
            "LOAD_LEVEL_INFORMATION is not a NwdafEvent, so it is not carried as one: {body}"
        );
        assert_eq!(
            body["failEventReports"][0]["event"].as_str(),
            Some("LOAD_LEVEL_INFORMATION"),
            "it is reported unserviceable, echoed verbatim (#108)"
        );
    }

    // ── issue #171: tgt-ue, the analytics target period, and its errors ───────

    /// Percent-encode a JSON value for use as a query-parameter value, so tests
    /// drive exactly the wire shape the yaml declares (`content:
    /// application/json`). Necessary rather than cosmetic: an RFC-3339 instant
    /// ends in `+00:00`, and a raw `+` decodes to a space.
    fn qp(v: &Value) -> String {
        let mut out = String::new();
        for b in v.to_string().bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(char::from(b))
                }
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }

    /// Isolated context whose one NF instance has samples at EXPLICIT timestamps,
    /// so a requested analytics target period can be aimed at or away from them.
    fn ctx_with_timed_loads(instance: &str, samples: &[(u64, u8)]) -> Arc<RwLock<NwdafContext>> {
        let mut ctx = NwdafContext::new("nwdaf-window-test".to_string());
        ctx.init(64);
        {
            let mut engine = ctx.lock_engine();
            for &(timestamp, load) in samples {
                engine.ingest_nf_load(crate::analytics::NfLoadSample {
                    nf_type: "AMF".to_string(),
                    nf_instance_id: instance.to_string(),
                    cpu_usage: f64::from(load) / 100.0,
                    mem_usage: 0.0,
                    active_sessions: 0,
                    timestamp,
                });
            }
        }
        Arc::new(RwLock::new(ctx))
    }

    fn analytics_uri(query: &str) -> String {
        format!("/nnwdaf-analyticsinfo/v1/analytics?event-id=NF_LOAD&{query}")
    }

    /// **Acceptance criterion 1 of #171.** A requested analytics target period
    /// changes the reported window AND the samples the statistics are computed
    /// from — the hardcoded `now`/`now + 3600 s` is gone.
    ///
    /// Two samples 10 and 5 minutes old carry loads 20 and 80. A period covering
    /// only the older one must report `nfLoadLevelAverage` 20, and a period
    /// covering both must report 50. Neither number is producible by the
    /// whole-series computation the handler used to do, and `start`/`expiry` must
    /// equal what was asked for rather than `now`.
    #[tokio::test]
    async fn test_analytics_info_target_period_drives_window_and_statistics() {
        let now = chrono::Utc::now();
        let at = |mins: i64| (now - chrono::Duration::minutes(mins)).timestamp() as u64;
        let ctx = ctx_with_timed_loads("amf-period-01", &[(at(10), 20), (at(5), 80)]);

        // ── only the older sample is inside [now-12min, now-8min] ─────────────
        let start = now - chrono::Duration::minutes(12);
        let end = now - chrono::Duration::minutes(8);
        let uri = analytics_uri(&format!(
            "ana-req={}",
            qp(&json!({ "startTs": start.to_rfc3339(), "endTs": end.to_rfc3339() }))
        ));
        let resp = handle_analytics_info_query_with_ctx(&ctx, &SbiRequest::get(&uri)).await;
        assert_eq!(
            resp.status, 200,
            "a past period with data in it must be 200"
        );
        let body = body_json(&resp);
        assert_eq!(
            body["nfLoadLevelInfos"][0]["nfLoadLevelAverage"].as_u64(),
            Some(20),
            "statistics must come from the requested period's samples only"
        );
        let reported = |key: &str| -> chrono::DateTime<chrono::FixedOffset> {
            chrono::DateTime::parse_from_rfc3339(
                body[key]
                    .as_str()
                    .unwrap_or_else(|| panic!("{key} present")),
            )
            .expect("RFC-3339")
        };
        assert_eq!(
            reported("start").timestamp(),
            start.timestamp(),
            "start must be the requested startTs, not now"
        );
        assert_eq!(
            reported("expiry").timestamp(),
            end.timestamp(),
            "expiry must be the requested endTs, not now + 3600"
        );

        // ── a wider past period covers both samples → average 50 ─────────────
        let wide_start = now - chrono::Duration::minutes(20);
        let wide_end = now - chrono::Duration::minutes(1);
        let uri = analytics_uri(&format!(
            "ana-req={}",
            qp(&json!({ "startTs": wide_start.to_rfc3339(), "endTs": wide_end.to_rfc3339() }))
        ));
        let resp = handle_analytics_info_query_with_ctx(&ctx, &SbiRequest::get(&uri)).await;
        assert_eq!(resp.status, 200);
        assert_eq!(
            body_json(&resp)["nfLoadLevelInfos"][0]["nfLoadLevelAverage"].as_u64(),
            Some(50),
            "a wider period must report the average of both samples"
        );

        // ── no ana-req → the pre-#171 default window, both samples ────────────
        let resp =
            handle_analytics_info_query_with_ctx(&ctx, &SbiRequest::get(analytics_uri(""))).await;
        assert_eq!(resp.status, 200);
        let body = body_json(&resp);
        assert_eq!(
            body["nfLoadLevelInfos"][0]["nfLoadLevelAverage"].as_u64(),
            Some(50)
        );
        let default_expiry = chrono::DateTime::parse_from_rfc3339(body["expiry"].as_str().unwrap())
            .expect("RFC-3339")
            .timestamp();
        assert!(
            (default_expiry - (now.timestamp() + 3600)).abs() <= 5,
            "with no requested period the validity stays now + 3600 s (got {default_expiry})"
        );
    }

    /// **Acceptance criterion 2 of #171, the `500` half.** Statistics over a past
    /// period with no sample in it is `500 UNAVAILABLE_DATA` (TS 29.520
    /// §4.3.2.2.2), while absent data with no period — or a FUTURE period — stays
    /// `204`. The same context serves all three, so the difference provably comes
    /// from the requested period and not from an empty engine.
    #[tokio::test]
    async fn test_analytics_info_past_period_without_data_is_500_unavailable_data() {
        let now = chrono::Utc::now();
        let ctx = ctx_with_timed_loads(
            "amf-unavail-01",
            &[((now - chrono::Duration::minutes(5)).timestamp() as u64, 40)],
        );

        // A past period that predates every sample → 500 UNAVAILABLE_DATA.
        let start = now - chrono::Duration::days(30);
        let end = now - chrono::Duration::days(29);
        let uri = analytics_uri(&format!(
            "ana-req={}",
            qp(&json!({ "startTs": start.to_rfc3339(), "endTs": end.to_rfc3339() }))
        ));
        let resp = handle_analytics_info_query_with_ctx(&ctx, &SbiRequest::get(&uri)).await;
        assert_eq!(
            resp.status, 500,
            "statistics in the past with no data must be 500, not 204 and never a 200 \
             computed over another period"
        );
        assert_eq!(
            body_json(&resp)["cause"].as_str(),
            Some("UNAVAILABLE_DATA"),
            "the 500 must carry the TS 29.520 table 5.2.7.3-1 cause"
        );

        // The very same engine answers 200 without a period — so the 500 above is
        // about the requested window, not about having no data at all.
        let resp =
            handle_analytics_info_query_with_ctx(&ctx, &SbiRequest::get(analytics_uri(""))).await;
        assert_eq!(resp.status, 200, "the engine does hold data");

        // A FUTURE period is a prediction, computed from the past samples → 200.
        let uri = analytics_uri(&format!(
            "ana-req={}",
            qp(&json!({
                "startTs": (now + chrono::Duration::minutes(5)).to_rfc3339(),
                "endTs": (now + chrono::Duration::minutes(30)).to_rfc3339(),
            }))
        ));
        let resp = handle_analytics_info_query_with_ctx(&ctx, &SbiRequest::get(&uri)).await;
        assert_eq!(
            resp.status, 200,
            "a future period must predict from past samples, not window them away"
        );

        // A future period with NO data anywhere stays 204, not 500: the spec ties
        // UNAVAILABLE_DATA to statistics in the past.
        let mut empty = NwdafContext::new("nwdaf-empty-window".to_string());
        empty.init(8);
        let empty = Arc::new(RwLock::new(empty));
        let resp = handle_analytics_info_query_with_ctx(&empty, &SbiRequest::get(&uri)).await;
        assert_eq!(resp.status, 204, "a future period with no data is 204");
    }

    /// **Acceptance criterion 2 of #171, the `400` half.** A target period whose
    /// start is in the past and end in the future asks for statistics AND
    /// prediction → `400 BOTH_STAT_PRED_NOT_ALLOWED` (TS 29.520 §4.3.2.2.2).
    #[tokio::test]
    async fn test_analytics_info_straddling_period_is_400_both_stat_pred() {
        let now = chrono::Utc::now();
        let ctx = ctx_with_timed_loads("amf-straddle-01", &[(now.timestamp() as u64, 40)]);
        let uri = analytics_uri(&format!(
            "ana-req={}",
            qp(&json!({
                "startTs": (now - chrono::Duration::hours(1)).to_rfc3339(),
                "endTs": (now + chrono::Duration::hours(1)).to_rfc3339(),
            }))
        ));
        let resp = handle_analytics_info_query_with_ctx(&ctx, &SbiRequest::get(&uri)).await;
        assert_eq!(resp.status, 400);
        assert_eq!(
            body_json(&resp)["cause"].as_str(),
            Some("BOTH_STAT_PRED_NOT_ALLOWED")
        );
    }

    /// A malformed `ana-req` fails closed rather than falling back to the default
    /// window — silently computing over an unrequested window is the defect.
    #[tokio::test]
    async fn test_analytics_info_malformed_ana_req_400() {
        let ctx = ctx_with_loads("AMF", "amf-badana-01", &[50]);
        let now = chrono::Utc::now();
        let cases = [
            ("not-json".to_string(), "not JSON at all"),
            (
                qp(&json!({ "startTs": "yesterday" })),
                "a non-RFC-3339 startTs",
            ),
            (qp(&json!({ "endTs": 12345 })), "a numeric endTs"),
            (
                qp(&json!({
                    "startTs": now.to_rfc3339(),
                    "endTs": (now - chrono::Duration::hours(2)).to_rfc3339(),
                })),
                "endTs before startTs",
            ),
            (
                qp(&json!({ "offsetPeriod": "-600" })),
                "a non-integer offsetPeriod",
            ),
        ];
        for (value, what) in cases {
            let uri = analytics_uri(&format!("ana-req={value}"));
            let resp = handle_analytics_info_query_with_ctx(&ctx, &SbiRequest::get(&uri)).await;
            assert_eq!(resp.status, 400, "{what} must be rejected with 400");
        }
    }

    /// `offsetPeriod` is the relative form of the target period: negative selects
    /// statistics over the past offset window, positive a prediction over the
    /// future one (TS 29.520 `EventReportingRequirement`).
    #[tokio::test]
    async fn test_analytics_info_offset_period_selects_statistics_or_prediction() {
        let now = chrono::Utc::now();
        let ctx = ctx_with_timed_loads(
            "amf-offset-01",
            &[((now - chrono::Duration::minutes(2)).timestamp() as u64, 60)],
        );

        // −600 s: statistics over [now-600, now]; the sample is inside it.
        let uri = analytics_uri(&format!("ana-req={}", qp(&json!({ "offsetPeriod": -600 }))));
        let resp = handle_analytics_info_query_with_ctx(&ctx, &SbiRequest::get(&uri)).await;
        assert_eq!(resp.status, 200);
        let body = body_json(&resp);
        assert_eq!(
            body["nfLoadLevelInfos"][0]["nfLoadLevelAverage"].as_u64(),
            Some(60)
        );
        let expiry = chrono::DateTime::parse_from_rfc3339(body["expiry"].as_str().unwrap())
            .expect("RFC-3339")
            .timestamp();
        assert!(
            (expiry - now.timestamp()).abs() <= 5,
            "a negative offset ends the window at now (got {expiry})"
        );

        // −60 s: the sample is 2 minutes old, so this past window is empty.
        let uri = analytics_uri(&format!("ana-req={}", qp(&json!({ "offsetPeriod": -60 }))));
        let resp = handle_analytics_info_query_with_ctx(&ctx, &SbiRequest::get(&uri)).await;
        assert_eq!(
            resp.status, 500,
            "a negative offset naming a window with no sample is UNAVAILABLE_DATA"
        );

        // +1800 s: prediction from the past sample, validity ending now+1800.
        let uri = analytics_uri(&format!("ana-req={}", qp(&json!({ "offsetPeriod": 1800 }))));
        let resp = handle_analytics_info_query_with_ctx(&ctx, &SbiRequest::get(&uri)).await;
        assert_eq!(resp.status, 200);
        let expiry =
            chrono::DateTime::parse_from_rfc3339(body_json(&resp)["expiry"].as_str().unwrap())
                .expect("RFC-3339")
                .timestamp();
        assert!(
            (expiry - (now.timestamp() + 1800)).abs() <= 5,
            "a positive offset predicts forward to now + offset (got {expiry})"
        );
    }

    /// A one-sided target period has its missing bound derived and clamped to
    /// `now`, so a period the consumer did not ask to straddle never does —
    /// which is what keeps `BOTH_STAT_PRED_NOT_ALLOWED` tied to an explicit
    /// two-bound request.
    #[test]
    fn test_parse_analytics_target_period_never_straddles_now() {
        let now = chrono::Utc::now();
        let period = |v: Value| {
            parse_analytics_target_period(Some(&v.to_string()), now)
                .expect("valid ana-req")
                .expect("a period")
        };

        // startTs in the past, no endTs → [startTs, now]: pure statistics, even
        // though startTs + 3600 s would have landed in the future.
        let p = period(json!({ "startTs": (now - chrono::Duration::minutes(1)).to_rfc3339() }));
        assert_eq!(p.end.timestamp(), now.timestamp());
        assert!(p.is_statistics(now), "a past start alone means statistics");

        // startTs in the future, no endTs → [startTs, startTs + 3600]: prediction.
        let future = now + chrono::Duration::hours(2);
        let p = period(json!({ "startTs": future.to_rfc3339() }));
        assert_eq!(p.start.timestamp(), future.timestamp());
        assert_eq!(p.end.timestamp(), future.timestamp() + 3600);
        assert!(!p.is_statistics(now));

        // endTs in the future, no startTs → [now, endTs]: prediction.
        let p = period(json!({ "endTs": (now + chrono::Duration::minutes(1)).to_rfc3339() }));
        assert_eq!(p.start.timestamp(), now.timestamp());
        assert!(!p.is_statistics(now));

        // endTs in the past, no startTs → [endTs - 3600, endTs]: statistics.
        let past = now - chrono::Duration::hours(2);
        let p = period(json!({ "endTs": past.to_rfc3339() }));
        assert_eq!(p.start.timestamp(), past.timestamp() - 3600);
        assert!(p.is_statistics(now));

        // An `ana-req` carrying no target period at all is not an error.
        assert!(parse_analytics_target_period(
            Some(&json!({ "accuracy": "HIGH" }).to_string()),
            now
        )
        .expect("valid")
        .is_none());
        assert!(parse_analytics_target_period(None, now)
            .expect("valid")
            .is_none());
    }

    /// `tgt-ue` is a JSON `TargetUeInformation` per the yaml, so a bare
    /// identifier string, or an object that identifies no target, fails closed.
    #[tokio::test]
    async fn test_analytics_info_tgt_ue_must_identify_a_target() {
        let ctx = ctx_with_loads("AMF", "amf-tgtue-01", &[50]);

        for (value, what) in [
            ("imsi-001".to_string(), "a bare identifier string"),
            (qp(&json!({})), "an empty TargetUeInformation"),
            (qp(&json!({ "anyUe": false })), "anyUe explicitly false"),
        ] {
            let uri = analytics_uri(&format!("tgt-ue={value}"));
            let resp = handle_analytics_info_query_with_ctx(&ctx, &SbiRequest::get(&uri)).await;
            assert_eq!(resp.status, 400, "{what} must be rejected with 400");
        }

        // `anyUe: true` identifies every UE and imposes no restriction.
        let uri = analytics_uri(&format!("tgt-ue={}", qp(&json!({ "anyUe": true }))));
        let resp = handle_analytics_info_query_with_ctx(&ctx, &SbiRequest::get(&uri)).await;
        assert_eq!(resp.status, 200, "anyUe must not narrow anything away");
    }

    /// **The `tgt-ue` behaviour of #171, including the NOTE 5 exception.**
    ///
    /// A `tgt-ue` naming specific UEs cannot be resolved to the AMF/SMF instances
    /// serving them (TS 29.520 §4.3.2.2.2 NOTE 4) — this NWDAF holds no
    /// UE-to-serving-NF view — so those analytics do not exist → 204. But NOTE 5
    /// says the target UEs are IGNORED when the query names NF instance IDs, so
    /// the same request plus `event-filter.nfInstanceIds` must be SERVED. A naive
    /// "UE-scoped ⇒ 204" gate gets that second case wrong.
    #[tokio::test]
    async fn test_analytics_info_ue_scoped_tgt_ue_honours_note_4_and_note_5() {
        let ctx = ctx_with_loads("AMF", "amf-scope-01", &[70]);
        let scoped = qp(&json!({ "supis": ["imsi-001010000000001"] }));

        // NOTE 4: no way to know which NF serves that SUPI → 204.
        let uri = analytics_uri(&format!("tgt-ue={scoped}"));
        let resp = handle_analytics_info_query_with_ctx(&ctx, &SbiRequest::get(&uri)).await;
        assert_eq!(
            resp.status, 204,
            "a UE-scoped NF_LOAD query must not be answered with the whole network's load"
        );

        // Every other UE identifier behaves the same way.
        for value in [
            qp(&json!({ "gpsis": ["msisdn-15551234"] })),
            qp(&json!({ "intGroupIds": ["group-1"] })),
            qp(&json!({ "ueIpAddrs": { "ipv4Addrs": ["10.0.0.1"] } })),
        ] {
            let uri = analytics_uri(&format!("tgt-ue={value}"));
            let resp = handle_analytics_info_query_with_ctx(&ctx, &SbiRequest::get(&uri)).await;
            assert_eq!(resp.status, 204, "UE-scoped query {value} must be 204");
        }

        // NOTE 5: with nfInstanceIds present the target UEs are ignored → served.
        let uri = analytics_uri(&format!(
            "tgt-ue={scoped}&event-filter={}",
            qp(&json!({ "nfInstanceIds": ["amf-scope-01"] }))
        ));
        let resp = handle_analytics_info_query_with_ctx(&ctx, &SbiRequest::get(&uri)).await;
        assert_eq!(
            resp.status, 200,
            "NOTE 5: nfInstanceIds means the target UEs are ignored, not that the query fails"
        );
        assert_eq!(
            body_json(&resp)["nfLoadLevelInfos"][0]["nfInstanceId"].as_str(),
            Some("amf-scope-01")
        );
    }

    // ── issue #171: Nnwdaf_AnalyticsInfo_ContextTransfer (GET /context) ───────

    /// Isolated context holding one analytics subscription over `events`.
    fn ctx_with_subscription(events: &[AnalyticsId]) -> (Arc<RwLock<NwdafContext>>, String) {
        let mut inner = NwdafContext::new("nwdaf-ctxtransfer-test".to_string());
        inner.init(64);
        let sub_id = "sub-ctxtransfer-1".to_string();
        let sub = AnalyticsSubscription::new_with_events(
            sub_id.clone(),
            events
                .iter()
                .copied()
                .map(EventSubscription::periodic)
                .collect(),
            "http://amf.example.org/notify".to_string(),
            u64::MAX,
        );
        inner.add_subscription(sub).expect("subscription stored");
        (Arc::new(RwLock::new(inner)), sub_id)
    }

    fn context_uri(context_ids: &Value, req_context: Option<&Value>) -> String {
        let mut uri = format!(
            "/nnwdaf-analyticsinfo/v1/context?context-ids={}",
            qp(context_ids)
        );
        if let Some(rc) = req_context {
            uri.push_str(&format!("&req-context={}", qp(rc)));
        }
        uri
    }

    /// **Acceptance criterion 3 of #171.** `GET /context` is routed and answers a
    /// known subscription with a `ContextData` naming the analytics contexts that
    /// actually exist for it.
    #[tokio::test]
    async fn test_context_transfer_returns_context_data_for_a_known_subscription() {
        let (ctx, sub_id) = ctx_with_subscription(&[AnalyticsId::NfLoad, AnalyticsId::UeMobility]);
        let uri = context_uri(
            &json!({ "contextIds": [{ "subscriptionId": sub_id, "nfAnaCtxts": ["NF_LOAD", "UE_MOBILITY"] }] }),
            None,
        );
        let resp = handle_nwdaf_context_query_with_ctx(&ctx, &SbiRequest::get(&uri)).await;
        assert_eq!(resp.status, 200, "a known subscription must be 200");

        let body = body_json(&resp);
        let elems = body["contextElems"]
            .as_array()
            .expect("ContextData.contextElems is required");
        assert_eq!(elems.len(), 1);
        assert_eq!(
            elems[0]["contextId"]["subscriptionId"].as_str(),
            Some(sub_id.as_str())
        );
        // UE_MOBILITY was requested and IS on the subscription, but it has no
        // collector, so no analytics context exists to transfer for it.
        assert_eq!(
            elems[0]["contextId"]["nfAnaCtxts"],
            json!(["NF_LOAD"]),
            "only events with a live collector have a transferable context"
        );
        // Nothing this NWDAF does not store may appear.
        for absent in [
            "pendAnalytics",
            "histAnalytics",
            "histData",
            "aggrSubs",
            "aggrNwdafIds",
            "adrfId",
            "modelInfo",
        ] {
            assert!(
                elems[0].get(absent).is_none(),
                "{absent} must be omitted, not fabricated"
            );
        }
    }

    /// `lastOutputTime` is real state: it appears only after a notification has
    /// actually been dispatched, and only when the consumer asked for the pending
    /// or historical output-analytics context types (TS 29.520 §4.3.2.3.2).
    #[tokio::test]
    async fn test_context_transfer_last_output_time_tracks_dispatched_notifications() {
        let (ctx, sub_id) = ctx_with_subscription(&[AnalyticsId::NfLoad]);
        let ids =
            json!({ "contextIds": [{ "subscriptionId": sub_id, "nfAnaCtxts": ["NF_LOAD"] }] });
        let pending = json!({ "contexts": ["PENDING_ANALYTICS"] });

        // Nothing dispatched yet → no lastOutputTime to report.
        let resp = handle_nwdaf_context_query_with_ctx(
            &ctx,
            &SbiRequest::get(context_uri(&ids, Some(&pending))),
        )
        .await;
        assert_eq!(resp.status, 200);
        assert!(
            body_json(&resp)["contextElems"][0]
                .get("lastOutputTime")
                .is_none(),
            "no notification has gone out, so there is no last output time"
        );

        // Record a dispatch, then it is reported as an RFC-3339 instant.
        ctx.read()
            .unwrap()
            .update_subscription_last_notification(&sub_id);
        let resp = handle_nwdaf_context_query_with_ctx(
            &ctx,
            &SbiRequest::get(context_uri(&ids, Some(&pending))),
        )
        .await;
        let reported = body_json(&resp)["contextElems"][0]["lastOutputTime"]
            .as_str()
            .expect("lastOutputTime after a dispatch")
            .to_string();
        let parsed = chrono::DateTime::parse_from_rfc3339(&reported).expect("RFC-3339 DateTime");
        assert!(
            (parsed.timestamp() - chrono::Utc::now().timestamp()).abs() <= 5,
            "lastOutputTime must be the moment of dispatch, got {reported}"
        );

        // A consumer that asked for neither output-analytics type does not get it.
        let resp = handle_nwdaf_context_query_with_ctx(
            &ctx,
            &SbiRequest::get(context_uri(
                &ids,
                Some(&json!({ "contexts": ["AGGR_SUBS"] })),
            )),
        )
        .await;
        assert!(
            body_json(&resp)["contextElems"][0]
                .get("lastOutputTime")
                .is_none(),
            "lastOutputTime is conditional on PENDING_ANALYTICS/HISTORICAL_ANALYTICS"
        );
    }

    /// 204 whenever no requested context information exists (TS 29.520
    /// §4.3.2.3.2) — an unknown subscription, a type the subscription does not
    /// carry, a subscription whose only event has no collector, or a request for
    /// UE-related contexts, which this NWDAF has none of.
    #[tokio::test]
    async fn test_context_transfer_204_when_nothing_matches() {
        let (ctx, sub_id) = ctx_with_subscription(&[AnalyticsId::NfLoad]);

        let cases = [
            (
                json!({ "contextIds": [{ "subscriptionId": "sub-does-not-exist", "nfAnaCtxts": ["NF_LOAD"] }] }),
                "an unknown subscription",
            ),
            (
                json!({ "contextIds": [{ "subscriptionId": sub_id, "nfAnaCtxts": ["UE_MOBILITY"] }] }),
                "a type the subscription does not carry",
            ),
            (
                json!({ "contextIds": [{ "subscriptionId": sub_id, "ueAnaCtxts": [{ "supi": "imsi-1", "ueAnaTypes": ["UE_MOBILITY"] }] }] }),
                "a request for UE-related analytics contexts",
            ),
        ];
        for (ids, what) in cases {
            let resp = handle_nwdaf_context_query_with_ctx(
                &ctx,
                &SbiRequest::get(context_uri(&ids, None)),
            )
            .await;
            assert_eq!(resp.status, 204, "{what} must be 204");
            assert!(
                resp.http.content.as_deref().is_none_or(str::is_empty),
                "204 carries no body"
            );
        }

        // A subscription whose only event has no collector has no context either.
        let (collectorless, id) = ctx_with_subscription(&[AnalyticsId::UeMobility]);
        let resp = handle_nwdaf_context_query_with_ctx(
            &collectorless,
            &SbiRequest::get(context_uri(
                &json!({ "contextIds": [{ "subscriptionId": id, "nfAnaCtxts": ["UE_MOBILITY"] }] }),
                None,
            )),
        )
        .await;
        assert_eq!(resp.status, 204);
    }

    /// `context-ids` is mandatory and must be a conformant `ContextIdList`; a
    /// malformed `req-context` is rejected too rather than silently ignored.
    #[tokio::test]
    async fn test_context_transfer_rejects_missing_or_malformed_query_params() {
        let (ctx, sub_id) = ctx_with_subscription(&[AnalyticsId::NfLoad]);

        // Absent context-ids → 400 with the mandatory-parameter cause.
        let resp = handle_nwdaf_context_query_with_ctx(
            &ctx,
            &SbiRequest::get("/nnwdaf-analyticsinfo/v1/context"),
        )
        .await;
        assert_eq!(resp.status, 400);
        assert_eq!(
            body_json(&resp)["cause"].as_str(),
            Some("MANDATORY_QUERY_PARAM_INCORRECT")
        );

        let bad = [
            ("context-ids=not-json".to_string(), "context-ids not JSON"),
            (
                format!("context-ids={}", qp(&json!({ "contextIds": [] }))),
                "an empty contextIds array",
            ),
            (
                format!(
                    "context-ids={}",
                    qp(&json!({ "contextIds": [{ "nfAnaCtxts": ["NF_LOAD"] }] }))
                ),
                "an identifier with no subscriptionId",
            ),
            (
                format!(
                    "context-ids={}",
                    qp(&json!({ "contextIds": [{ "subscriptionId": "s" }] }))
                ),
                "an identifier with neither nfAnaCtxts nor ueAnaCtxts",
            ),
            (
                format!(
                    "context-ids={}&req-context={}",
                    qp(
                        &json!({ "contextIds": [{ "subscriptionId": sub_id, "nfAnaCtxts": ["NF_LOAD"] }] })
                    ),
                    qp(&json!({ "contexts": [] }))
                ),
                "an empty req-context.contexts",
            ),
        ];
        for (query, what) in bad {
            let uri = format!("/nnwdaf-analyticsinfo/v1/context?{query}");
            let resp = handle_nwdaf_context_query_with_ctx(&ctx, &SbiRequest::get(&uri)).await;
            assert_eq!(resp.status, 400, "{what} must be 400");
        }
    }

    // ── G2-3: supported-events honesty ────────────────────────────────────────

    /// G2-3 honesty: a GET for a recognised but collector-less event
    /// (UE_MOBILITY) returns **204 No Content** (TS 29.520 §4.3.2.2.2 — the
    /// requested analytics data does not exist), never an empty-200 — even
    /// when OTHER events (NF_LOAD) do have data in the same engine.
    #[tokio::test]
    async fn test_honesty_unsupported_event_get_204() {
        // NF_LOAD data exists, so a 204 here can only come from the
        // supported-events gate, not from the empty-infos path.
        let ctx = ctx_with_loads("AMF", "amf-honesty-01", &[30, 40]);
        let req = SbiRequest::get("/nnwdaf-analyticsinfo/v1/analytics?event-id=UE_MOBILITY");
        let resp = handle_analytics_info_query_with_ctx(&ctx, &req).await;
        assert_eq!(
            resp.status, 204,
            "unsupported event must be 204 No Content, got {}",
            resp.status
        );
        assert!(
            resp.http.content.as_deref().is_none_or(str::is_empty),
            "204 must carry no body"
        );

        // Every recognised-but-unsupported event behaves identically.
        //
        // Issue #175: iterated by the event's `EventId` spelling, because that is
        // what this API's `event-id` parameter is typed as. A token with no
        // EventId value (PFD_DETERMINATION) is not "unsupported analytics" on this
        // surface at all — it is an unknown analytics type, so 400 rather than
        // 204, which `test_analytics_info_accepts_the_event_id_spelling` pins.
        for event in AnalyticsId::ALL {
            if event.is_supported() {
                continue;
            }
            let Some(token) = event.as_event_id() else {
                continue;
            };
            let uri = format!("/nnwdaf-analyticsinfo/v1/analytics?event-id={token}");
            let resp = handle_analytics_info_query_with_ctx(&ctx, &SbiRequest::get(&uri)).await;
            assert_eq!(
                resp.status, 204,
                "GET event-id={token} must be 204 (a 200 here is empty-200 dishonesty)"
            );
        }
    }

    /// Issue #108: the non-spec top-level `expiryTime` is no longer honoured —
    /// TS 29.520's subscription resource has no such member (yaml:414-433), so a
    /// conformant consumer could never set it. Duration comes from `evtReq`.
    #[tokio::test]
    async fn test_duration_comes_from_evt_req_not_expiry_time() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);

        // A bespoke expiryTime of 1 second must NOT shorten the subscription.
        let req = SbiRequest::post("/nnwdaf-eventssubscription/v1/subscriptions")
            .with_json_body(&json!({
                "notificationURI": "http://amf.example.org/notify",
                "expiryTime": 1,
                "eventSubscriptions": [{ "event": "NF_LOAD" }]
            }))
            .expect("valid JSON body");
        assert_eq!(handle_subscription_create(&req).await.status, 201);
        let ctx = nwdaf_self();
        let stored = ctx
            .read()
            .unwrap()
            .get_all_active_subscriptions()
            .into_iter()
            .next()
            .expect("subscription stored");
        assert!(
            stored.expiry > now_secs() + 1000,
            "the non-spec expiryTime must be ignored, not applied (expiry={}, now={})",
            stored.expiry,
            now_secs()
        );
        assert_eq!(stored.max_report_nbr, None, "no evtReq → unlimited reports");

        // evtReq.maxReportNbr and a monDur duration ARE honoured.
        nwdaf_context_init("nwdaf-test2".to_string(), 1024);
        let req = SbiRequest::post("/nnwdaf-eventssubscription/v1/subscriptions")
            .with_json_body(&json!({
                "notificationURI": "http://amf.example.org/notify",
                "evtReq": { "maxReportNbr": 5, "monDur": 120 },
                "eventSubscriptions": [{ "event": "NF_LOAD" }]
            }))
            .expect("valid JSON body");
        assert_eq!(handle_subscription_create(&req).await.status, 201);
        let stored = nwdaf_self()
            .read()
            .unwrap()
            .get_all_active_subscriptions()
            .into_iter()
            .find(|s| s.max_report_nbr == Some(5))
            .expect("the evtReq subscription");
        assert!(
            stored.expiry <= now_secs() + 121 && stored.expiry > now_secs(),
            "monDur must set the window (expiry={})",
            stored.expiry
        );
    }

    /// Issue #108: a subscription mixing a serviceable event with an
    /// unrecognised token must SUCCEED, listing the unknown one in
    /// `failEventReports` — not die with 400 INVALID_ANALYTICS_TYPE and take the
    /// serviceable event with it. The `NwdafEvent` yaml has a free-form `anyOf`
    /// alternative expressly so consumers can request newer analytics types.
    #[tokio::test]
    async fn test_unrecognised_event_fails_alone_not_the_subscription() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        let req = SbiRequest::post("/nnwdaf-eventssubscription/v1/subscriptions")
            .with_json_body(&json!({
                "notificationURI": "http://amf.example.org/notify",
                "eventSubscriptions": [
                    { "event": "NF_LOAD" },
                    { "event": "SOME_REL20_ANALYTIC" }
                ]
            }))
            .expect("valid JSON body");
        let resp = handle_subscription_create(&req).await;
        assert_eq!(
            resp.status, 201,
            "one unknown token must not reject the whole subscription"
        );

        let body = body_json(&resp);
        // The serviceable event survived.
        let events: Vec<&str> = body["eventSubscriptions"]
            .as_array()
            .expect("eventSubscriptions")
            .iter()
            .filter_map(|e| e["event"].as_str())
            .collect();
        assert_eq!(events, vec!["NF_LOAD"], "the entitled event is kept");

        // The unknown one is reported per-event, echoed verbatim.
        let failed = body["failEventReports"]
            .as_array()
            .expect("failEventReports must list the unknown event");
        assert!(
            failed.iter().any(|f| {
                f["event"].as_str() == Some("SOME_REL20_ANALYTIC")
                    && f["failureCode"].as_str() == Some("UNAVAILABLE_DATA")
            }),
            "got {failed:?}"
        );
    }

    /// A previously-missing but spec-valid token is now recognised, so it is
    /// carried as an event (and reported unsupported because it has no
    /// collector) rather than rejected as an invalid analytics type.
    #[tokio::test]
    async fn test_previously_missing_spec_token_is_accepted() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        let req = SbiRequest::post("/nnwdaf-eventssubscription/v1/subscriptions")
            .with_json_body(&json!({
                "notificationURI": "http://amf.example.org/notify",
                // One of the nine tokens #108 added; before it, this returned 400.
                "eventSubscriptions": [{ "event": "MOVEMENT_BEHAVIOUR" }]
            }))
            .expect("valid JSON body");
        let resp = handle_subscription_create(&req).await;
        assert_eq!(resp.status, 201);

        let body = body_json(&resp);
        assert_eq!(
            body["eventSubscriptions"][0]["event"].as_str(),
            Some("MOVEMENT_BEHAVIOUR"),
            "a spec token must be recognised and carried"
        );
        assert_eq!(
            body["failEventReports"][0]["event"].as_str(),
            Some("MOVEMENT_BEHAVIOUR"),
            "recognised but with no collector → reported unsupported"
        );
    }

    /// An `event` member absent entirely is a missing mandatory IE, which is a
    /// different failure from an unknown value and must stay a 400.
    #[tokio::test]
    async fn test_missing_event_member_is_still_a_bad_request() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        let req = SbiRequest::post("/nnwdaf-eventssubscription/v1/subscriptions")
            .with_json_body(&json!({
                "notificationURI": "http://amf.example.org/notify",
                "eventSubscriptions": [{ "notificationMethod": "PERIODIC" }]
            }))
            .expect("valid JSON body");
        let resp = handle_subscription_create(&req).await;
        assert_eq!(
            resp.status, 400,
            "a missing mandatory IE is not an unknown value"
        );
    }

    /// G2-3 honesty: POST subscription {NF_LOAD, UE_MOBILITY} → 201 whose body
    /// carries `failEventReports` of exactly
    /// `[{event: UE_MOBILITY, failureCode: UNAVAILABLE_DATA}]` (TS 29.520
    /// `FailureEventInfo`; partial grant, the subscription itself is accepted).
    #[tokio::test]
    async fn test_honesty_subscription_fail_event_reports() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        let req = SbiRequest::post("/nnwdaf-eventssubscription/v1/subscriptions")
            .with_json_body(&json!({
                "notificationURI": "http://amf.example.org/notify",
                "eventSubscriptions": [
                    { "event": "NF_LOAD" },
                    { "event": "UE_MOBILITY" }
                ]
            }))
            .expect("valid JSON body");
        let resp = handle_subscription_create(&req).await;
        assert_eq!(resp.status, 201, "partial grant: subscription accepted");

        let body = body_json(&resp);
        let failed = body
            .get("failEventReports")
            .and_then(|v| v.as_array())
            .expect("201 body must carry failEventReports for unsupported events");
        assert_eq!(
            failed,
            &vec![json!({ "event": "UE_MOBILITY", "failureCode": "UNAVAILABLE_DATA" })],
            "exactly one FailureEventInfo: UE_MOBILITY/UNAVAILABLE_DATA"
        );

        // The GET representation reflects the same declared failure.
        let sub_id = body["subscriptionId"].as_str().expect("id").to_string();
        let get_resp = handle_subscription_get(&sub_id).await;
        assert_eq!(get_resp.status, 200);
        assert_eq!(
            body_json(&get_resp)["failEventReports"],
            json!([{ "event": "UE_MOBILITY", "failureCode": "UNAVAILABLE_DATA" }])
        );
    }

    /// G2-3: a fully-supported subscription carries NO failEventReports key
    /// (minItems 1 in the yaml — an empty array would be schema-invalid).
    #[tokio::test]
    async fn test_honesty_supported_only_subscription_has_no_fail_reports() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        let req = SbiRequest::post("/nnwdaf-eventssubscription/v1/subscriptions")
            .with_json_body(&json!({
                "notificationURI": "http://amf.example.org/notify",
                "eventSubscriptions": [ { "event": "NF_LOAD" } ]
            }))
            .expect("valid JSON body");
        let resp = handle_subscription_create(&req).await;
        assert_eq!(resp.status, 201);
        assert!(
            body_json(&resp).get("failEventReports").is_none(),
            "no failEventReports when every event is supported"
        );
    }

    /// G2-3 (documented decision): a subscription whose events are ALL
    /// unsupported is still accepted with 201 — the yaml allows every event to
    /// appear in failEventReports — with every event declared failed.
    #[tokio::test]
    async fn test_honesty_all_unsupported_still_201_all_failed() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        let req = SbiRequest::post("/nnwdaf-eventssubscription/v1/subscriptions")
            .with_json_body(&json!({
                "notificationURI": "http://amf.example.org/notify",
                "eventSubscriptions": [
                    { "event": "UE_MOBILITY" },
                    { "event": "ABNORMAL_BEHAVIOUR" }
                ]
            }))
            .expect("valid JSON body");
        let resp = handle_subscription_create(&req).await;
        assert_eq!(resp.status, 201, "all-unsupported is still a 201");
        let body = body_json(&resp);
        assert_eq!(
            body["failEventReports"],
            json!([
                { "event": "UE_MOBILITY", "failureCode": "UNAVAILABLE_DATA" },
                { "event": "ABNORMAL_BEHAVIOUR", "failureCode": "UNAVAILABLE_DATA" }
            ]),
            "every unsupported event must be declared failed"
        );
    }

    /// G2-3: the PUT (update) response also declares unsupported events failed.
    #[tokio::test]
    async fn test_honesty_subscription_update_fail_event_reports() {
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
            "notificationURI": "http://amf.example.org/notify",
            "eventSubscriptions": [
                { "event": "NF_LOAD" },
                { "event": "DN_PERFORMANCE" }
            ]
        }))
        .expect("valid JSON body");
        let put_resp = handle_subscription_update(&sub_id, &put).await;
        assert_eq!(put_resp.status, 200);
        assert_eq!(
            body_json(&put_resp)["failEventReports"],
            json!([{ "event": "DN_PERFORMANCE", "failureCode": "UNAVAILABLE_DATA" }]),
            "the 200 update body must declare the unsupported event failed"
        );
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

#[cfg(all(test, feature = "sensing"))]
mod sensing_tests {
    use super::*;
    use nextgcore_proto::{SensingMode, SensingResult, SensingType};
    use nextgcore_sbi::pubsub::{EventFilter, Subscription};
    use nextgcore_sbi::SbiEventCategory;

    fn fresh_ctx() -> Arc<RwLock<NwdafContext>> {
        Arc::new(RwLock::new(NwdafContext::new("nwdaf-test".to_string())))
    }

    fn sensing_result_json() -> String {
        serde_json::to_string(&SensingResult {
            sensing_type: SensingType::TargetDetection,
            mode: SensingMode::GnbMonostatic,
            timestamp_us: 1_000_000,
            targets: vec![],
            snr_db: 12.5,
        })
        .expect("serialize SensingResult")
    }

    fn summary_request() -> SbiRequest {
        let mut request = SbiRequest::get("/nnwdaf-analyticsinfo/v1/analytics");
        request
            .http
            .params
            .insert("event-id".to_string(), "ISAC_SENSING".to_string());
        request
    }

    /// Acceptance (issue #16): POST a SensingResult -> 2xx, then the analytics
    /// GET returns the summary with count >= 1.
    #[tokio::test]
    async fn sensing_ingest_then_query_roundtrip() {
        let ctx = fresh_ctx();

        // Nothing ingested yet -> 204 (requested data does not exist).
        let empty = handle_analytics_info_query_with_ctx(&ctx, &summary_request()).await;
        assert_eq!(empty.status, 204);

        let post = SbiRequest::post("/nnwdaf-sensingdata/v1/results")
            .with_body(sensing_result_json(), "application/json");
        let response = handle_sensing_result_post_with_ctx(&ctx, &post).await;
        assert_eq!(response.status, 201);

        let summary = handle_analytics_info_query_with_ctx(&ctx, &summary_request()).await;
        assert_eq!(summary.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(summary.http.content.as_deref().expect("summary body"))
                .expect("summary JSON");
        assert_eq!(body["isacSensingSummary"]["ingestedTotal"], 1);
        assert_eq!(body["isacSensingSummary"]["buffered"], 1);
        assert_eq!(
            body["isacSensingSummary"]["latest"]["snr_db"],
            serde_json::json!(12.5)
        );
    }

    /// Acceptance (issue #16): ingest publishes an SbiEventCategory::Isac
    /// event on the pub-sub bus (subscriber matched, publish counter bumped).
    #[tokio::test]
    async fn sensing_ingest_publishes_isac_event() {
        let ctx = fresh_ctx();

        // Subscribe to Isac events before ingesting.
        {
            let guard = ctx.read().expect("ctx read");
            let mut broker = guard.lock_event_broker();
            let sub_id = broker.alloc_subscription_id();
            broker.subscribe(Subscription::new(
                sub_id,
                "consumer-1",
                "http://consumer:8080/callback",
                EventFilter::category(SbiEventCategory::Isac),
            ));
        }

        let post = SbiRequest::post("/nnwdaf-sensingdata/v1/results")
            .with_body(sensing_result_json(), "application/json");
        let response = handle_sensing_result_post_with_ctx(&ctx, &post).await;
        assert_eq!(response.status, 201);

        let guard = ctx.read().expect("ctx read");
        let broker = guard.lock_event_broker();
        assert_eq!(broker.total_published(), 1);
        assert_eq!(broker.total_delivered(), 1);
    }

    /// Malformed body fails closed with 400, ingesting nothing.
    #[tokio::test]
    async fn sensing_ingest_rejects_bad_json() {
        let ctx = fresh_ctx();
        let post = SbiRequest::post("/nnwdaf-sensingdata/v1/results")
            .with_body("{not json", "application/json");
        let response = handle_sensing_result_post_with_ctx(&ctx, &post).await;
        assert_eq!(response.status, 400);
        let (total, buffered, _) = ctx.read().expect("ctx read").sensing_snapshot();
        assert_eq!((total, buffered), (0, 0));
    }
}
