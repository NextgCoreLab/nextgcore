//! UE Mobility analytics from AMF location events (nextgsim#466, demo
//! `d441c-amf-mobility`). Cargo feature `amf-mobility`, off by default.
//!
//! TS 23.288 §6.7.2.2 Table 6.7.2.2-1 (`23288-k10.txt:14940-14967`) sources UE
//! Mobility's input, "TA or cells that the UE enters" with a timestamp, from the
//! AMF. This module is that input path and the answer built from it:
//!
//! 1. **Subscribe.** At start-up the NWDAF discovers an AMF at the NRF and sends it
//!    `Namf_EventExposure_Subscribe` for `LOCATION_REPORT`, `anyUE`
//!    (`TS29518_Namf_EventExposure.yaml`), retrying until the AMF answers 201.
//! 2. **Notify.** The AMF POSTs `AmfEventNotification`s to
//!    `/nnwdaf-callback/v1/amf-location-notify/{token}` on the NWDAF's existing SBI
//!    listener. TS 33.501 §13.4.1 says *"The OAuth 2.0 framework does not apply to
//!    the notification operation"* (`33501-k20.txt:14458`), so the AMF sends no
//!    access token; what makes a notify genuine is the per-process random token in
//!    the `eventNotifyUri` this NWDAF gave the AMF, the pattern amfd's own
//!    NF-status and deregistration callbacks use (#940, #753). An unknown token is
//!    404 and ingests nothing. The token is redacted from SBI log lines
//!    (`nextgcore_sbi::log_redact`).
//! 3. **Ingest.** Each `LOCATION_REPORT` with an `nrLocation` goes into
//!    [`AnalyticsEngine::ingest_ue_location`](crate::analytics::AnalyticsEngine::ingest_ue_location).
//! 4. **Answer.** `Nnwdaf_AnalyticsInfo` `UE_MOBILITY` builds TS 29.520
//!    `UeMobility` (`TS29520_Nnwdaf_EventsSubscription.yaml:1180-1208`) from the
//!    history ([`ue_mobility_infos`]).
//!
//! # Modes
//!
//! | config                                         | subscribes | UE_MOBILITY       |
//! |------------------------------------------------|------------|-------------------|
//! | demo `d441c-amf-mobility` mode `on`            | yes        | served, advertised |
//! | demo `d441c-amf-mobility` mode `baseline`      | no         | 204, not advertised |
//! | no active demo, `nwdaf.amf_mobility.enabled: true` | yes    | served, advertised |
//! | no active demo, knob absent or false (default) | no         | 204, not advertised |
//!
//! An active demo block supersedes the knob. The decision is made once at start-up
//! ([`resolve`]) and switched by config plus restart only.
//!
//! # Honesty
//!
//! The cell history is whatever the simulator's gNBs report. The prediction is a
//! first-order transition count (`AnalyticsEngine::predict_mobility`), not a
//! learned model, and its `confidence` is the share of observed transitions out of
//! the current cell that went to the predicted one.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use serde_json::{json, Value};

use crate::analytics::{AnalyticsEngine, ObservationWindow};
use crate::context::NwdafContext;

/// The demo key (nextgsim#458 convention).
pub const DEMO_KEY: &str = "d441c-amf-mobility";
/// Mode: subscribe to the AMF, ingest, serve UE_MOBILITY.
pub const MODE_ON: &str = "on";
/// Mode: no AMF subscription; UE_MOBILITY is 204 and not advertised.
pub const MODE_BASELINE: &str = "baseline";

/// What this binary registers in its demo registry under the `amf-mobility`
/// feature.
pub const DEMO_SPEC: nextgcore_demo::DemoSpec = nextgcore_demo::DemoSpec {
    key: DEMO_KEY,
    modes: &[MODE_ON, MODE_BASELINE],
    requires: &[],
};

/// The callback path segment; the next segment is the token. Listed in
/// `nextgcore_sbi::log_redact::CALLBACK_TOKEN_SEGMENTS` so the token is never
/// logged.
pub const CALLBACK_SEGMENT: &str = "amf-location-notify";

/// `notifyCorrelationId` of the subscription (TS 29.518 `AmfEventSubscription`).
pub const NOTIFY_CORRELATION_ID: &str = "nwdaf-ue-mobility";

/// Whether UE_MOBILITY is served by this process. Set once at start-up by
/// [`install`]; never written by a test (tests use [`ServingOnThisThread`]).
static SERVING: AtomicBool = AtomicBool::new(false);

/// The callback token of this process's subscription.
static CALLBACK_TOKEN: OnceLock<String> = OnceLock::new();

/// LOCATION_REPORTs ingested, and notifies refused, for `/metrics`.
static INGESTED: AtomicU64 = AtomicU64::new(0);
static REFUSED: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
thread_local! {
    static SERVING_ON_THIS_THREAD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test-only: serve UE_MOBILITY on the current thread for the guard's lifetime,
/// without touching the process-wide [`SERVING`], so a test that needs it served
/// cannot race one that asserts the 204 (`#[tokio::test]` runs its handlers on
/// the test's own thread).
#[cfg(test)]
pub(crate) struct ServingOnThisThread;

#[cfg(test)]
impl ServingOnThisThread {
    pub(crate) fn new() -> Self {
        SERVING_ON_THIS_THREAD.with(|s| s.set(true));
        Self
    }
}

#[cfg(test)]
impl Drop for ServingOnThisThread {
    fn drop(&mut self) {
        SERVING_ON_THIS_THREAD.with(|s| s.set(false));
    }
}

/// Whether UE_MOBILITY is served: mode `on`, or the knob with no demo active.
pub fn serving() -> bool {
    #[cfg(test)]
    if SERVING_ON_THIS_THREAD.with(|s| s.get()) {
        return true;
    }
    SERVING.load(Ordering::Relaxed)
}

/// The start-up decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    /// Neither the demo nor the knob: the default build's behaviour.
    Off,
    /// Subscribe and serve. `demo` = the demo block asked for it (log lines carry
    /// the `[demo:d441c-amf-mobility]` prefix).
    On { demo: bool },
    /// Demo mode `baseline`: the control arm.
    Baseline,
}

impl Plan {
    /// Whether this plan subscribes to the AMF and serves UE_MOBILITY.
    pub fn serves(self) -> bool {
        matches!(self, Plan::On { .. })
    }
}

/// Decide the plan from the active demo mode (`nextgcore_demo::active_mode`) and
/// the `nwdaf.amf_mobility.enabled` knob. An active demo supersedes the knob.
pub fn resolve(demo_mode: Option<&str>, knob: bool) -> Plan {
    match demo_mode {
        Some(MODE_ON) => Plan::On { demo: true },
        Some(_) => Plan::Baseline,
        None if knob => Plan::On { demo: false },
        None => Plan::Off,
    }
}

/// `nwdaf.amf_mobility.enabled` from the config root. Absent means false; a
/// present value that is not a boolean fails start-up.
pub fn knob_from_root(root: &serde_yaml::Value) -> Result<bool, String> {
    match root.get("nwdaf").and_then(|n| n.get("amf_mobility")) {
        None | Some(serde_yaml::Value::Null) => Ok(false),
        Some(section) => match section.get("enabled") {
            None | Some(serde_yaml::Value::Null) => Ok(false),
            Some(serde_yaml::Value::Bool(b)) => Ok(*b),
            Some(other) => Err(format!(
                "nwdaf.amf_mobility.enabled must be a boolean, got {other:?}"
            )),
        },
    }
}

/// Record the plan for this process. Call once, before the NRF registration, so
/// the profile advertises UE_MOBILITY exactly when it is served.
pub fn install(plan: Plan) {
    SERVING.store(plan.serves(), Ordering::Relaxed);
    match plan {
        Plan::On { demo } => line(
            demo,
            "ue-mobility: on (subscribing to AMF LOCATION_REPORT; UE_MOBILITY served)",
        ),
        Plan::Baseline => nextgcore_demo::demo_log!(
            info,
            DEMO_KEY,
            "ue-mobility: baseline (no AMF subscription; UE_MOBILITY answers 204)"
        ),
        Plan::Off => {}
    }
}

/// An INFO line, `[demo:<key>]`-prefixed when the demo asked for this.
fn line(demo: bool, msg: &str) {
    if demo {
        nextgcore_demo::demo_log!(info, DEMO_KEY, "{msg}");
    } else {
        log::info!("{msg}");
    }
}

fn demo_active() -> bool {
    nextgcore_demo::active_mode(DEMO_KEY).is_some()
}

/// This process's callback token: 128 random bits, hex.
pub fn callback_token() -> &'static str {
    CALLBACK_TOKEN.get_or_init(|| uuid::Uuid::new_v4().simple().to_string())
}

/// The `eventNotifyUri` this NWDAF subscribes with.
pub fn notify_uri(sbi_base: &str) -> String {
    format!(
        "{}/nnwdaf-callback/v1/{CALLBACK_SEGMENT}/{}",
        sbi_base.trim_end_matches('/'),
        callback_token()
    )
}

/// The TS 29.518 `AmfCreateEventSubscription` body: LOCATION_REPORT for any UE,
/// on TA and cell changes.
pub fn subscription_body(notify_uri: &str, nf_id: &str) -> Value {
    json!({
        "subscription": {
            // TS 29.518 Table 6.2.6.2.3-1: without a filter the AMF reports TA
            // changes only; UE Mobility needs "cells that the UE enters" too
            // (TS 23.288 Table 6.7.2.2-1), and an intra-TA handover changes only
            // the cell.
            "eventList": [{
                "type": "LOCATION_REPORT",
                "locationFilterList": ["TAI", "CELL_ID"],
            }],
            "eventNotifyUri": notify_uri,
            "notifyCorrelationId": NOTIFY_CORRELATION_ID,
            "nfId": nf_id,
            "anyUE": true,
        }
    })
}

/// The `namf-evts` endpoint of the first AMF in a TS 29.510 `SearchResult`: the
/// service's first `ipEndPoints` entry, else the instance's first IPv4 address or
/// FQDN on port 80 (the http default the profile's `scheme` implies).
pub fn amf_endpoint_from_search_result(result: &Value) -> Option<(String, u16)> {
    let instances = result.get("nfInstances")?.as_array()?;
    for inst in instances {
        if inst.get("nfType").and_then(Value::as_str) != Some("AMF") {
            continue;
        }
        let service = inst
            .get("nfServices")
            .and_then(Value::as_array)
            .and_then(|s| {
                s.iter()
                    .find(|s| s.get("serviceName").and_then(Value::as_str) == Some("namf-evts"))
            });
        if let Some(ep) = service
            .and_then(|s| s.get("ipEndPoints"))
            .and_then(Value::as_array)
            .and_then(|eps| eps.first())
        {
            let host = ep
                .get("ipv4Address")
                .and_then(Value::as_str)
                .or_else(|| service.and_then(|s| s.get("fqdn")).and_then(Value::as_str))
                .or_else(|| inst.get("fqdn").and_then(Value::as_str));
            let port = ep.get("port").and_then(Value::as_u64).unwrap_or(80);
            if let (Some(host), Ok(port)) = (host, u16::try_from(port)) {
                return Some((host.to_string(), port));
            }
        }
        let host = inst
            .get("ipv4Addresses")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_str)
            .or_else(|| inst.get("fqdn").and_then(Value::as_str));
        if let Some(host) = host {
            return Some((host.to_string(), 80));
        }
    }
    None
}

/// One subscribe attempt: discover the AMF at `nrf_uri`, then POST the
/// subscription. The AMF's `subscriptionId` on success.
pub async fn subscribe_once(nrf_uri: &str, sbi_base: &str, nf_id: &str) -> Result<String, String> {
    let (nrf_host, nrf_port, nrf_base) = crate::notification_dispatcher::parse_notify_uri(nrf_uri)
        .ok_or_else(|| format!("invalid NRF URI {nrf_uri:?}"))?;
    let nrf = crate::notification_dispatcher::notify_client(&nrf_host, nrf_port);
    let disc = format!(
        "{}/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=NWDAF\
         &service-names=namf-evts",
        nrf_base.trim_end_matches('/')
    );
    let resp = nrf
        .get(&disc)
        .await
        .map_err(|e| format!("AMF discovery at the NRF failed: {e}"))?;
    if resp.status != 200 {
        return Err(format!("AMF discovery answered {}", resp.status));
    }
    let result: Value = serde_json::from_str(resp.http.content.as_deref().unwrap_or(""))
        .map_err(|e| format!("AMF discovery answer is not JSON: {e}"))?;
    let (host, port) = amf_endpoint_from_search_result(&result)
        .ok_or("the NRF knows no AMF offering namf-evts")?;

    let mut amf = crate::notification_dispatcher::notify_client(&host, port);
    if let Some(oauth2) = crate::oauth2_client() {
        amf = amf.with_oauth2(oauth2, nextgcore_sbi::types::NfType::Amf);
    }
    let body = subscription_body(&notify_uri(sbi_base), nf_id);
    let resp = amf
        .post_json("/namf-evts/v1/subscriptions", &body)
        .await
        .map_err(|e| format!("Namf_EventExposure_Subscribe to {host}:{port} failed: {e}"))?;
    if resp.status != 201 {
        return Err(format!(
            "Namf_EventExposure_Subscribe to {host}:{port} answered {}",
            resp.status
        ));
    }
    let created: Value = serde_json::from_str(resp.http.content.as_deref().unwrap_or(""))
        .map_err(|e| format!("subscription answer is not JSON: {e}"))?;
    created
        .get("subscriptionId")
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| "the 201 carries no subscriptionId".to_string())
}

/// Subscribe in the background, retrying (2 s doubling to 30 s) until the AMF
/// accepts. Logs `subscribed to AMF LOCATION_REPORT id=<id>` once.
pub fn spawn_subscriber(nrf_uri: String, sbi_base: String, nf_id: String) {
    tokio::spawn(async move {
        let mut backoff = Duration::from_secs(2);
        loop {
            match subscribe_once(&nrf_uri, &sbi_base, &nf_id).await {
                Ok(id) => {
                    line(
                        demo_active(),
                        &format!("subscribed to AMF LOCATION_REPORT id={id}"),
                    );
                    return;
                }
                Err(e) => {
                    log::warn!("ue-mobility: AMF LOCATION_REPORT subscription: {e}; retrying");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
    });
}

/// One `LOCATION_REPORT` as ingested: `(supi, cell id, UserLocation, unix s)`.
type LocationSample = (String, u64, Value, u64);

/// The `LOCATION_REPORT`s of an `AmfEventNotification` that carry a SUPI and an
/// NR cell. Other report types and reports without an `nrLocation` are skipped:
/// the history is keyed by NR cell.
pub fn location_samples(notification: &Value, now: u64) -> Vec<LocationSample> {
    let Some(reports) = notification.get("reportList").and_then(Value::as_array) else {
        return Vec::new();
    };
    reports
        .iter()
        .filter(|r| r.get("type").and_then(Value::as_str) == Some("LOCATION_REPORT"))
        .filter_map(|r| {
            let supi = r.get("supi").and_then(Value::as_str)?;
            let loc = r.get("location")?;
            let nr = loc.get("nrLocation")?;
            let cell_hex = nr.pointer("/ncgi/nrCellId").and_then(Value::as_str)?;
            let cell = u64::from_str_radix(cell_hex, 16).ok()?;
            let ts = r
                .get("timeStamp")
                .and_then(Value::as_str)
                .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                .and_then(|t| u64::try_from(t.timestamp()).ok())
                .unwrap_or(now);
            Some((supi.to_string(), cell, loc.clone(), ts))
        })
        .collect()
}

/// `PLMN-nrCellId tac=<tac>` of a `UserLocation`, for the ingest log line.
fn describe(loc: &Value) -> String {
    let nr = &loc["nrLocation"];
    let plmn = &nr["ncgi"]["plmnId"];
    format!(
        "{}{}-{} tac={}",
        plmn["mcc"].as_str().unwrap_or("?"),
        plmn["mnc"].as_str().unwrap_or("?"),
        nr["ncgi"]["nrCellId"].as_str().unwrap_or("?"),
        nr["tai"]["tac"].as_str().unwrap_or("?"),
    )
}

/// `POST /nnwdaf-callback/v1/amf-location-notify/{token}`: Namf_EventExposure
/// Notify from the AMF this NWDAF subscribed to.
///
/// - not serving UE_MOBILITY, or a token this process did not hand out: 404,
///   nothing ingested;
/// - a body that is not JSON or has no `reportList`: 400;
/// - otherwise 204, every `LOCATION_REPORT` with an NR cell ingested.
pub fn handle_location_notify(
    ctx: &Arc<RwLock<NwdafContext>>,
    token: &str,
    request: &SbiRequest,
) -> SbiResponse {
    if !serving() || CALLBACK_TOKEN.get().map(String::as_str) != Some(token) {
        REFUSED.fetch_add(1, Ordering::Relaxed);
        log::warn!(
            "ue-mobility: location notify on a subscription this NWDAF does not hold; refused"
        );
        return nextgcore_sbi::server::send_not_found(
            "no such AMF event subscription callback",
            Some("RESOURCE_URI_STRUCTURE_NOT_FOUND"),
        );
    }
    let body: Value = match request
        .http
        .content
        .as_deref()
        .map(serde_json::from_str::<Value>)
    {
        Some(Ok(v)) if v.get("reportList").is_some_and(Value::is_array) => v,
        _ => {
            return nextgcore_sbi::server::send_bad_request(
                "an AmfEventNotification with a reportList is required",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };
    let now = unix_now();
    let samples = location_samples(&body, now);
    let demo = demo_active();
    if let Ok(guard) = ctx.read() {
        let mut engine = guard.lock_engine();
        for (supi, cell, loc, ts) in samples {
            line(
                demo,
                &format!("ue-mobility ingest supi={supi} cell={}", describe(&loc)),
            );
            engine.ingest_ue_location(&supi, cell, loc, ts);
            INGESTED.fetch_add(1, Ordering::Relaxed);
        }
    }
    SbiResponse::with_status(204)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn rfc3339(secs: u64) -> String {
    i64::try_from(secs)
        .ok()
        .and_then(|s| chrono::DateTime::from_timestamp(s, 0))
        .unwrap_or_default()
        .to_rfc3339()
}

/// What the consumer asked for, from `ana-req` (TS 29.520 NOTE 7 on
/// `AnalyticsData`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ask {
    /// Statistics: the observed history, optionally restricted to a past window.
    Statistics(Option<ObservationWindow>),
    /// A prediction over a future period `[start, end]` (unix seconds).
    Prediction { start: u64, end: u64 },
}

/// The `LocationInfo.loc` for `cell`: the `UserLocation` the AMF reported, else a
/// bare NCGI (never reached: every ingested cell has a location).
fn loc_of(engine: &AnalyticsEngine, cell: u64) -> Value {
    engine.cell_location(cell).cloned().unwrap_or_else(
        || json!({ "nrLocation": { "ncgi": { "nrCellId": format!("{cell:09X}") } } }),
    )
}

/// The `ueMobs` array for `supis` (TS 29.520 `UeMobility`, one entry per SUPI
/// with data, in request order). Empty when none has data, which the caller
/// answers 204 (or 500 UNAVAILABLE_DATA for a past window).
///
/// - **Statistics.** One aggregated `UeMobility` per UE (`ueLocOrderInd` absent,
///   Table 5.1.6.2.71-1 NOTE 2): `ts` the first observation, `duration` the
///   observed span, `locInfos` every cell in first-visit order. No `ratio` (it
///   *"Shall be present if the analytics result applies for a group of UEs"*,
///   Table 5.1.6.2.11-1) and no `confidence` (for predictions only).
/// - **Prediction.** `ts` the period start, `duration` its length, and one
///   `locInfos` entry, the predicted next cell, with `confidence` = the transition
///   share in percent. No entry when no transition out of the current cell has
///   been observed.
pub fn ue_mobility_infos(engine: &AnalyticsEngine, supis: &[String], ask: Ask) -> Vec<Value> {
    let mut out = Vec::new();
    for supi in supis {
        let Some(history) = engine.ue_cell_history(supi) else {
            continue;
        };
        match ask {
            Ask::Statistics(window) => {
                let samples: Vec<(u64, u64)> = history
                    .iter()
                    .copied()
                    .filter(|(_, ts)| window.is_none_or(|w| w.contains(*ts)))
                    .collect();
                let (Some(first), Some(last)) = (samples.first(), samples.last()) else {
                    continue;
                };
                let mut cells: Vec<u64> = Vec::new();
                for (cell, _) in &samples {
                    if !cells.contains(cell) {
                        cells.push(*cell);
                    }
                }
                let loc_infos: Vec<Value> = cells
                    .iter()
                    .map(|c| json!({ "loc": loc_of(engine, *c) }))
                    .collect();
                out.push(json!({
                    "ts": rfc3339(first.1),
                    "duration": last.1.saturating_sub(first.1),
                    "locInfos": loc_infos,
                }));
            }
            Ask::Prediction { start, end } => {
                let Some(p) = engine.predict_mobility(supi) else {
                    continue;
                };
                let Some(next) = p.predicted_next_cell else {
                    continue;
                };
                let confidence = (p.prediction_probability * 100.0).round().clamp(0.0, 100.0);
                out.push(json!({
                    "ts": rfc3339(start),
                    "duration": end.saturating_sub(start),
                    "locInfos": [{ "loc": loc_of(engine, next), "confidence": confidence as u64 }],
                }));
            }
        }
    }
    out
}

/// This module's `/metrics` families.
pub fn render_metrics(out: &mut String) {
    use std::fmt::Write as _;
    nextgcore_metrics::nf::write_metric(
        out,
        "nwdaf_ue_mobility_serving",
        "gauge",
        "1 when UE_MOBILITY analytics are served from AMF LOCATION_REPORTs (nextgsim#466)",
        u8::from(serving()),
    );
    nextgcore_metrics::nf::write_header(
        out,
        "nwdaf_ue_mobility_location_reports_total",
        "counter",
        "AMF LOCATION_REPORT notifies by outcome: reports ingested, notifies refused",
    );
    let _ = writeln!(
        out,
        "nwdaf_ue_mobility_location_reports_total{{result=\"ingested\"}} {}",
        INGESTED.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        out,
        "nwdaf_ue_mobility_location_reports_total{{result=\"refused\"}} {}",
        REFUSED.load(Ordering::Relaxed)
    );
}

#[cfg(test)]
mod tests;
