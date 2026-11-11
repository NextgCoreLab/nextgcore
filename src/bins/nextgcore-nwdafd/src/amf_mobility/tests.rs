//! nextgsim#466 tests. Every test that needs UE_MOBILITY served holds a
//! [`ServingOnThisThread`] and runs on a current-thread runtime, so the
//! process-wide `SERVING` stays false and the default-build 204 tests in the same
//! binary cannot see it flip.

use super::*;
use crate::context::NwdafContext;
use crate::sbi_handler::handle_analytics_info_query_with_ctx;

const SUPI: &str = "imsi-001010000466100";

fn fresh_ctx(tag: &str) -> Arc<RwLock<NwdafContext>> {
    let mut ctx = NwdafContext::new(format!("nwdaf-466-{tag}"));
    ctx.init(64);
    Arc::new(RwLock::new(ctx))
}

/// An `AmfEventNotification` exactly as amfd's `deliver_event_notification`
/// builds it for `fire_location_report` (`namf_server.rs`): `reportList[]` of
/// `AmfEventReport` with `location.nrLocation.{tai,ncgi}`.
fn amf_notification(supi: &str, cell_hex: &str, tac: &str, ts: &str) -> Value {
    json!({
        "notifyCorrelationId": NOTIFY_CORRELATION_ID,
        "reportList": [{
            "type": "LOCATION_REPORT",
            "state": { "active": true },
            "timeStamp": ts,
            "supi": supi,
            "location": { "nrLocation": {
                "tai": { "plmnId": { "mcc": "001", "mnc": "01" }, "tac": tac },
                "ncgi": { "plmnId": { "mcc": "001", "mnc": "01" }, "nrCellId": cell_hex },
            }},
        }],
    })
}

fn notify(ctx: &Arc<RwLock<NwdafContext>>, token: &str, body: &Value) -> SbiResponse {
    let req = SbiRequest::post(format!("/nnwdaf-callback/v1/{CALLBACK_SEGMENT}/{token}"))
        .with_json_body(body)
        .expect("json");
    handle_location_notify(ctx, token, &req)
}

fn ue_mobility_get(supis: &[&str], extra: &str) -> SbiRequest {
    let tgt = json!({ "supis": supis }).to_string();
    SbiRequest::get(format!(
        "/nnwdaf-analyticsinfo/v1/analytics?event-id=UE_MOBILITY&tgt-ue={}{extra}",
        nextgcore_sbi::uri_encode::encode_query_value(&tgt)
    ))
}

/// TS 29.520 `UeMobility` (`TS29520_Nnwdaf_EventsSubscription.yaml:1180-1208`):
/// `duration` and `locInfos` (minItems 1) required, and exactly one of `ts` /
/// `recurringTime`; each `LocationInfo` requires `loc` (`:1209-1229`).
fn assert_valid_ue_mobility(m: &Value) {
    assert!(m["duration"].is_u64(), "duration is a DurationSec: {m}");
    let locs = m["locInfos"].as_array().expect("locInfos");
    assert!(!locs.is_empty(), "locInfos minItems 1: {m}");
    assert!(
        m.get("ts").is_some() ^ m.get("recurringTime").is_some(),
        "exactly one of ts / recurringTime: {m}"
    );
    if let Some(ts) = m["ts"].as_str() {
        chrono::DateTime::parse_from_rfc3339(ts).expect("ts is a DateTime");
    }
    for l in locs {
        assert!(l.get("loc").is_some(), "LocationInfo requires loc: {l}");
        if let Some(c) = l.get("confidence") {
            assert!(c.as_u64().is_some_and(|c| c <= 100), "confidence 0..100");
        }
    }
}

fn cell_ids(m: &Value) -> Vec<String> {
    m["locInfos"]
        .as_array()
        .expect("locInfos")
        .iter()
        .map(|l| {
            l["loc"]["nrLocation"]["ncgi"]["nrCellId"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        })
        .collect()
}

#[test]
fn the_demo_block_supersedes_the_knob() {
    assert_eq!(resolve(Some("on"), false), Plan::On { demo: true });
    assert_eq!(resolve(Some("baseline"), true), Plan::Baseline);
    assert_eq!(resolve(None, true), Plan::On { demo: false });
    assert_eq!(resolve(None, false), Plan::Off);
    assert!(!Plan::Baseline.serves() && !Plan::Off.serves());
}

#[test]
fn the_knob_is_a_boolean_and_off_when_absent() {
    let root = |y: &str| serde_yaml::from_str::<serde_yaml::Value>(y).expect("yaml");
    assert_eq!(knob_from_root(&serde_yaml::Value::Null), Ok(false));
    assert_eq!(knob_from_root(&root("nwdaf: {sbi: {}}")), Ok(false));
    assert_eq!(
        knob_from_root(&root("nwdaf: {amf_mobility: {enabled: true}}")),
        Ok(true)
    );
    assert!(knob_from_root(&root("nwdaf: {amf_mobility: {enabled: yes-please}}")).is_err());
}

/// The demo-toggle criteria at the registry level: `mode: bogus` fails with
/// `UnknownMode` for this key, no fallback; and `demo.enabled: false` with the
/// key enabled activates nothing.
#[test]
fn an_unknown_mode_fails_and_the_kill_switch_wins() {
    let registry = nextgcore_demo::DemoRegistry::new(&[DEMO_SPEC]);
    let cfg = |y: &str| {
        nextgcore_demo::DemoConfig::from_root(&serde_yaml::from_str(y).expect("yaml"))
            .expect("parse")
    };
    let err = cfg("demo: {enabled: true, d441c-amf-mobility: {enabled: true, mode: bogus}}")
        .validate(&registry)
        .expect_err("bogus must fail");
    assert!(
        matches!(&err, nextgcore_demo::DemoConfigError::UnknownMode { demo, mode, .. }
            if demo == DEMO_KEY && mode == "bogus"),
        "{err:?}"
    );
    let off = cfg("demo: {enabled: false, d441c-amf-mobility: {enabled: true, mode: on}}")
        .validate(&registry)
        .expect("valid");
    assert!(off.is_empty(), "the kill switch leaves nothing active");
    let on = cfg("demo: {enabled: true, d441c-amf-mobility: {enabled: true, mode: on}}")
        .validate(&registry)
        .expect("valid");
    assert_eq!(on.mode(DEMO_KEY), Some("on"));
    // And a build without the feature has an empty registry: the key is unknown.
    let err = cfg("demo: {enabled: true, d441c-amf-mobility: {enabled: true, mode: on}}")
        .validate(&nextgcore_demo::DemoRegistry::default())
        .expect_err("no feature, no key");
    assert!(
        matches!(err, nextgcore_demo::DemoConfigError::UnknownKey { .. }),
        "{err:?}"
    );
}

#[test]
fn the_subscription_is_location_report_for_any_ue_on_the_callback() {
    let uri = notify_uri("http://nwdaf.svc:7815/");
    assert_eq!(
        uri,
        format!(
            "http://nwdaf.svc:7815/nnwdaf-callback/v1/amf-location-notify/{}",
            callback_token()
        )
    );
    assert_eq!(callback_token().len(), 32, "128 random bits, hex");
    let body = subscription_body(&uri, "nwdaf-1", 1_794_391_200);
    let s = &body["subscription"];
    assert_eq!(
        s["eventList"],
        json!([{ "type": "LOCATION_REPORT", "locationFilterList": ["TAI", "CELL_ID"] }])
    );
    assert_eq!(s["anyUE"], json!(true));
    assert_eq!(s["eventNotifyUri"].as_str(), Some(uri.as_str()));
    assert_eq!(s["nfId"].as_str(), Some("nwdaf-1"));
    assert!(s["notifyCorrelationId"].is_string());
    assert_eq!(
        s["options"],
        json!({ "trigger": "CONTINUOUS", "expiry": "2026-11-11T10:00:00+00:00" }),
        "a bounded subscription, so an orphan expires at the AMF"
    );
}

/// Discovery reads amfd's REAL registered profile (`amf_nf_profile_json`), so the
/// endpoint this NWDAF dials is the one amfd advertises for `namf-evts`.
#[test]
fn the_amf_endpoint_comes_from_its_namf_evts_service() {
    let profile = nextgcore_amfd::sbi_path::amf_nf_profile_json("amf-466", "10.1.2.3", 7777);
    let result = json!({ "nfInstances": [profile] });
    assert_eq!(
        amf_endpoint_from_search_result(&result),
        Some(("10.1.2.3".to_string(), 7777))
    );
    assert_eq!(
        amf_endpoint_from_search_result(&json!({ "nfInstances": [] })),
        None
    );
    assert_eq!(
        amf_endpoint_from_search_result(&json!({ "nfInstances": [{ "nfType": "SMF",
            "ipv4Addresses": ["10.9.9.9"] }] })),
        None,
        "only an AMF"
    );
}

#[test]
fn only_location_reports_with_an_nr_cell_are_samples() {
    let mut n = amf_notification(SUPI, "000000010", "000001", "2026-11-11T10:00:00Z");
    n["reportList"]
        .as_array_mut()
        .expect("list")
        .push(json!({ "type": "REACHABILITY_REPORT", "supi": SUPI }));
    n["reportList"].as_array_mut().expect("list").push(
        json!({ "type": "LOCATION_REPORT", "supi": SUPI, "location": { "eutraLocation": {} } }),
    );
    let samples = location_samples(&n, 7);
    assert_eq!(samples.len(), 1, "{samples:?}");
    let (supi, cell, loc, ts) = &samples[0];
    assert_eq!((supi.as_str(), *cell), (SUPI, 0x10));
    assert_eq!(*ts, 1_794_391_200, "the report's own timeStamp");
    assert_eq!(loc["nrLocation"]["tai"]["tac"], json!("000001"));
}

/// The forged-notify criterion: a notify on a token this NWDAF did not hand out
/// is refused and ingests nothing, even while serving.
///
/// REVERT-VERIFIED: dropping the token comparison in `handle_location_notify`
/// answers 204 and the GET then returns 200.
#[tokio::test]
async fn a_notify_on_an_unknown_token_is_refused_and_ingests_nothing() {
    let _serving = ServingOnThisThread::new();
    let ctx = fresh_ctx("forged");
    let _ = callback_token();
    let resp = notify(
        &ctx,
        "00000000000000000000000000000000",
        &amf_notification(SUPI, "000000010", "000001", "2026-11-11T10:00:00Z"),
    );
    assert_eq!(resp.status, 404);
    assert!(ctx
        .read()
        .expect("ctx")
        .lock_engine()
        .ue_cell_history(SUPI)
        .is_none());
    let resp = handle_analytics_info_query_with_ctx(&ctx, &ue_mobility_get(&[SUPI], "")).await;
    assert_eq!(resp.status, 204, "nothing was ingested, so nothing exists");
}

/// Mode `baseline` / mode-off: even the right token is refused, because no
/// subscription exists to notify.
#[test]
fn a_notify_is_refused_when_not_serving() {
    let ctx = fresh_ctx("not-serving");
    let resp = notify(
        &ctx,
        callback_token(),
        &amf_notification(SUPI, "000000010", "000001", "2026-11-11T10:00:00Z"),
    );
    assert_eq!(resp.status, 404);
    assert!(ctx
        .read()
        .expect("ctx")
        .lock_engine()
        .ue_cell_history(SUPI)
        .is_none());
}

#[test]
fn a_notify_without_a_report_list_is_400() {
    let _serving = ServingOnThisThread::new();
    let ctx = fresh_ctx("malformed");
    let resp = notify(
        &ctx,
        callback_token(),
        &json!({ "notifyCorrelationId": "x" }),
    );
    assert_eq!(resp.status, 400);
}

/// **The success signal.** Cell A at registration, A again at a service request,
/// then B after the N2 handover: the GET is 200 with one schema-valid
/// `UeMobility` whose `locInfos` are A then B, each carrying the AMF's own
/// `UserLocation`.
///
/// REVERT-VERIFIED: patching out the `ingest_ue_location` call in
/// `handle_location_notify` (the issue's revert arm) makes the GET 204.
#[tokio::test]
async fn location_reports_become_a_ue_mobility_answer() {
    let _serving = ServingOnThisThread::new();
    let ctx = fresh_ctx("chain");
    for (cell, ts) in [
        ("000000010", "2026-11-11T10:00:00Z"),
        ("000000010", "2026-11-11T10:00:20Z"),
        ("000000020", "2026-11-11T10:00:50Z"),
    ] {
        let resp = notify(
            &ctx,
            callback_token(),
            &amf_notification(SUPI, cell, "000001", ts),
        );
        assert_eq!(resp.status, 204);
    }
    let resp = handle_analytics_info_query_with_ctx(&ctx, &ue_mobility_get(&[SUPI], "")).await;
    assert_eq!(resp.status, 200);
    let body: Value =
        serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("json");
    let mobs = body["ueMobs"].as_array().expect("ueMobs");
    assert_eq!(mobs.len(), 1, "{body}");
    assert_valid_ue_mobility(&mobs[0]);
    assert_eq!(cell_ids(&mobs[0]), ["000000010", "000000020"]);
    assert_eq!(mobs[0]["duration"], json!(50), "10:00:00 to 10:00:50");
    assert_eq!(
        chrono::DateTime::parse_from_rfc3339(mobs[0]["ts"].as_str().expect("ts"))
            .expect("ts")
            .timestamp(),
        1_794_391_200,
        "ts = when the UE arrived at the first location"
    );
    assert!(
        mobs[0]["locInfos"][0].get("ratio").is_none(),
        "ratio is for a group of UEs (Table 5.1.6.2.11-1); this is one UE"
    );
    assert_eq!(
        mobs[0]["locInfos"][1]["loc"]["nrLocation"]["tai"]["tac"],
        json!("000001")
    );
    for key in ["start", "expiry", "timeStampGen"] {
        assert!(body[key].is_string(), "AnalyticsData.{key}: {body}");
    }

    // Another SUPI has no history: 204, never an empty 200.
    let resp =
        handle_analytics_info_query_with_ctx(&ctx, &ue_mobility_get(&["imsi-001010000466999"], ""))
            .await;
    assert_eq!(resp.status, 204);
}

/// A future `ana-req` period is a prediction: the next cell from the transition
/// counts, with `confidence` the transition share. A→B twice and A→C once, UE now
/// at A: B with 67.
#[tokio::test]
async fn a_future_period_is_a_transition_count_prediction() {
    let _serving = ServingOnThisThread::new();
    let ctx = fresh_ctx("predict");
    let base = 1_794_391_200u64;
    for (i, cell) in ["010", "020", "010", "020", "010", "030", "010"]
        .iter()
        .enumerate()
    {
        let ts = rfc3339(base + 10 * i as u64);
        let r = notify(
            &ctx,
            callback_token(),
            &amf_notification(SUPI, &format!("000000{cell}"), "000001", &ts),
        );
        assert_eq!(r.status, 204);
    }
    let start = chrono::Utc::now() + chrono::Duration::seconds(60);
    let end = start + chrono::Duration::seconds(600);
    let ana = json!({ "startTs": start.to_rfc3339(), "endTs": end.to_rfc3339() }).to_string();
    let extra = format!(
        "&ana-req={}",
        nextgcore_sbi::uri_encode::encode_query_value(&ana)
    );
    let resp = handle_analytics_info_query_with_ctx(&ctx, &ue_mobility_get(&[SUPI], &extra)).await;
    assert_eq!(resp.status, 200, "{:?}", resp.http.content);
    let body: Value =
        serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("json");
    let m = &body["ueMobs"][0];
    assert_valid_ue_mobility(m);
    assert_eq!(cell_ids(m), ["000000020"]);
    assert_eq!(m["locInfos"][0]["confidence"], json!(67));
    assert_eq!(m["duration"], json!(600));
}

/// TS 29.520 §4.3.2.2.2: UE_MOBILITY needs `tgt-ue` with `supis` or
/// `intGroupIds`. Without: 400. Groups only: 204 (no membership is resolved).
#[tokio::test]
async fn ue_mobility_needs_a_target_ue() {
    let _serving = ServingOnThisThread::new();
    let ctx = fresh_ctx("tgt");
    let resp = handle_analytics_info_query_with_ctx(
        &ctx,
        &SbiRequest::get("/nnwdaf-analyticsinfo/v1/analytics?event-id=UE_MOBILITY"),
    )
    .await;
    assert_eq!(resp.status, 400);
    let any = nextgcore_sbi::uri_encode::encode_query_value(r#"{"anyUe":true}"#);
    let resp = handle_analytics_info_query_with_ctx(
        &ctx,
        &SbiRequest::get(format!(
            "/nnwdaf-analyticsinfo/v1/analytics?event-id=UE_MOBILITY&tgt-ue={any}"
        )),
    )
    .await;
    assert_eq!(resp.status, 400, "anyUe is not one of supis/intGroupIds");
    let grp = nextgcore_sbi::uri_encode::encode_query_value(r#"{"intGroupIds":["g1"]}"#);
    let resp = handle_analytics_info_query_with_ctx(
        &ctx,
        &SbiRequest::get(format!(
            "/nnwdaf-analyticsinfo/v1/analytics?event-id=UE_MOBILITY&tgt-ue={grp}"
        )),
    )
    .await;
    assert_eq!(resp.status, 204);
}

/// Mode `baseline` and mode-off (not serving): 204 before any computation, even
/// with history in the engine — not an empty 200.
#[tokio::test]
async fn not_serving_is_204_even_with_history() {
    let ctx = fresh_ctx("baseline");
    ctx.read().expect("ctx").lock_engine().ingest_ue_location(
        SUPI,
        0x10,
        json!({ "nrLocation": {} }),
        1,
    );
    let resp = handle_analytics_info_query_with_ctx(&ctx, &ue_mobility_get(&[SUPI], "")).await;
    assert_eq!(resp.status, 204);
}

/// The NRF profile lists UE_MOBILITY (as an AnalyticsInfo `eventIds` value) only
/// while it is served; `nwdafEvents` never, since EventsSubscription does not
/// serve it.
#[test]
fn the_profile_advertises_ue_mobility_only_while_served() {
    let ids = |p: &Value| p["nwdafInfo"]["eventIds"].clone();
    let off = crate::build_nf_profile("nwdaf-466", "127.0.0.1", 7815, &[]);
    assert_eq!(ids(&off), json!(["NF_LOAD"]));
    let _serving = ServingOnThisThread::new();
    let on = crate::build_nf_profile("nwdaf-466", "127.0.0.1", 7815, &[]);
    assert_eq!(ids(&on), json!(["NF_LOAD", "UE_MOBILITY"]));
    assert_eq!(on["nwdafInfo"]["nwdafEvents"], json!(["NF_LOAD"]));
}

#[test]
fn metrics_report_serving_and_counts() {
    let mut out = String::new();
    render_metrics(&mut out);
    assert!(out.contains("nwdaf_ue_mobility_serving 0"), "{out}");
    assert!(out.contains("nwdaf_ue_mobility_location_reports_total{result=\"ingested\"}"));
    let _serving = ServingOnThisThread::new();
    let mut out = String::new();
    render_metrics(&mut out);
    assert!(out.contains("nwdaf_ue_mobility_serving 1"), "{out}");
}

/// **End to end with the real AMF code.** A stand-in NRF answers discovery with
/// amfd's real profile; amfd's real `namf_request_handler` takes the subscription
/// [`subscribe_once`] sends; amfd's real `fire_location_report` then POSTs the
/// notify over HTTP/2 to this NWDAF's real SBI router, and the GET is 200 with
/// the cell amfd reported.
#[tokio::test]
async fn amfd_location_reports_reach_ue_mobility_over_http() {
    let _serving = ServingOnThisThread::new();
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    nextgcore_amfd::context::amf_context_init(64, 1024, 4096);
    crate::nwdaf_context_init("nwdaf-466-e2e".to_string(), 1024);
    let supi = "imsi-001010000466200";

    let (amf, amf_port, nrf, nrf_port) = amf_and_nrf("amf-466-e2e").await;
    let (nwdaf, nwdaf_port) = serve(crate::nwdaf_sbi_request_handler).await;

    let sub = subscribe_once(
        &format!("http://127.0.0.1:{nrf_port}"),
        &format!("http://127.0.0.1:{nwdaf_port}"),
        "nwdaf-466-e2e",
        unix_now() + 600,
    )
    .await
    .expect("amfd accepts the subscription");
    assert!(
        sub.id.starts_with("sub-"),
        "amfd's subscriptionId: {}",
        sub.id
    );
    assert_eq!(sub.port, amf_port);

    let mut ue = nextgcore_amfd::context::AmfUe::new(466_200, 0);
    ue.supi = Some(supi.to_string());
    ue.nr_tai.plmn_id = nextgcore_amfd::context::PlmnId::new("001", "01");
    ue.nr_tai.tac = 0x000466;
    ue.nr_cgi.plmn_id = nextgcore_amfd::context::PlmnId::new("001", "01");
    ue.nr_cgi.cell_id = 0x0000_0042;
    nextgcore_amfd::namf_server::fire_location_report(&ue);

    let ctx = crate::nwdaf_self();
    let mut answer = None;
    for _ in 0..100 {
        let resp = handle_analytics_info_query_with_ctx(&ctx, &ue_mobility_get(&[supi], "")).await;
        if resp.status == 200 {
            answer = resp.http.content;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let body: Value =
        serde_json::from_str(&answer.expect("amfd's notify must be ingested")).expect("json");
    assert_valid_ue_mobility(&body["ueMobs"][0]);
    assert_eq!(cell_ids(&body["ueMobs"][0]), ["000000042"]);
    assert_eq!(
        body["ueMobs"][0]["locInfos"][0]["loc"]["nrLocation"]["tai"]["tac"],
        json!("0466")
    );

    for s in [nwdaf, nrf, amf] {
        s.stop().await.expect("stop");
    }
}

async fn serve<F, Fut>(handler: F) -> (nextgcore_sbi::SbiServer, u16)
where
    F: Fn(SbiRequest) -> Fut + Send + Sync + Clone + 'static,
    Fut: std::future::Future<Output = SbiResponse> + Send + 'static,
{
    let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
    let server =
        nextgcore_sbi::SbiServer::on_listener(nextgcore_sbi::SbiServerConfig::new(addr), listener);
    server.start(handler).await.expect("start");
    (server, addr.port())
}

/// amfd's real Namf handler, and a stand-in NRF that answers this NWDAF's AMF
/// discovery with amfd's real profile.
async fn amf_and_nrf(
    amf_id: &'static str,
) -> (nextgcore_sbi::SbiServer, u16, nextgcore_sbi::SbiServer, u16) {
    let (amf, amf_port) = serve(nextgcore_amfd::namf_server::namf_request_handler).await;
    let profile = nextgcore_amfd::sbi_path::amf_nf_profile_json(amf_id, "127.0.0.1", amf_port);
    let (nrf, nrf_port) = serve(move |req: SbiRequest| {
        let profile = profile.clone();
        async move {
            let uri = &req.header.uri;
            let p = &req.http.params;
            let asks_for_amf_evts = p.get("target-nf-type").map(String::as_str) == Some("AMF")
                && p.get("requester-nf-type").map(String::as_str) == Some("NWDAF")
                && p.get("service-names").map(String::as_str) == Some("namf-evts");
            if uri.starts_with("/nnrf-disc/v1/nf-instances") && asks_for_amf_evts {
                SbiResponse::with_status(200)
                    .with_json_body(&json!({ "nfInstances": [profile] }))
                    .expect("json")
            } else {
                SbiResponse::with_status(404)
            }
        }
    })
    .await;
    (amf, amf_port, nrf, nrf_port)
}

/// The expiry amfd holds for subscription `id`.
fn amfd_expiry(id: &str) -> Option<std::time::SystemTime> {
    let ctx = nextgcore_amfd::context::amf_self();
    let guard = ctx.read().expect("amf ctx");
    guard.event_subscription_find(id).and_then(|s| s.expiry)
}

/// **Review MAJOR (#1425): the subscription is maintained.** It is created with
/// an `options.expiry` amfd stores, the expiry is renewed by PATCH, and when amfd
/// no longer holds it (an AMF restart keeps subscriptions in memory only; here a
/// DELETE through amfd's real handler) the renewal's 404 makes this NWDAF
/// subscribe again, under a new id.
///
/// REVERT-VERIFIED: treating `RenewError::Gone` like `Other` (no re-subscribe)
/// times the last wait out.
#[tokio::test]
async fn a_lost_amf_subscription_is_renewed_and_then_replaced() {
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    nextgcore_amfd::context::amf_context_init(64, 1024, 4096);
    let (amf, amf_port, nrf, nrf_port) = amf_and_nrf("amf-466-renew").await;
    let lifetime = Lifetime {
        ttl: Duration::from_secs(60),
        renew_every: Duration::from_millis(300),
    };
    let task = tokio::spawn(maintain_subscription(
        format!("http://127.0.0.1:{nrf_port}"),
        "http://127.0.0.1:1".to_string(),
        "nwdaf-466-renew".to_string(),
        lifetime,
    ));
    async fn until<T>(mut f: impl FnMut() -> Option<T>) -> T {
        for _ in 0..200 {
            if let Some(v) = f() {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("condition not reached within 5 s");
    }
    let first = until(current_subscription).await;
    assert_eq!(first.port, amf_port, "held at the discovered AMF");
    let created = amfd_expiry(&first.id).expect("amfd stores the subscription's expiry");
    // A renewal moves the expiry forward (RFC 3339 has 1 s resolution).
    until(|| amfd_expiry(&first.id).filter(|e| *e > created)).await;

    let del = nextgcore_amfd::namf_server::namf_request_handler(SbiRequest::delete(format!(
        "/namf-evts/v1/subscriptions/{}",
        first.id
    )))
    .await;
    assert!(del.status / 100 == 2, "amfd drops it: {}", del.status);
    let second = until(|| current_subscription().filter(|s| s.id != first.id)).await;
    assert!(
        amfd_expiry(&second.id).is_some(),
        "the replacement is a real subscription at amfd"
    );
    task.abort();
    amf.stop().await.expect("stop");
    nrf.stop().await.expect("stop");
}
