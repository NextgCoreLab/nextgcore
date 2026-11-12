//! nextgsim#465 tests. A test that needs the feature served holds a
//! [`ServingOnThisThread`] on a current-thread runtime, so the process-wide flag
//! stays false for the default-build 204 tests in the same binary. Tests that
//! go through the process store use their own cell id and TAC.

use super::*;
use crate::sbi_handler::handle_analytics_info_query_with_ctx;
use std::sync::{Arc, RwLock};

const KID: &str = "nrf-465";

fn signing_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[0x46u8; 32]).expect("key")
}

fn token(aud: &str, scope: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::ecdsa::{signature::Signer, Signature};
    let exp = unix_now() + 3600;
    let header = format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{KID}"}}"#);
    let claims = json!({
        "iss": "NRF", "sub": "gnb-exporter-465", "aud": aud,
        "scope": scope, "exp": exp, "iat": 0
    })
    .to_string();
    let h = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let p = URL_SAFE_NO_PAD.encode(claims.as_bytes());
    let sig: Signature = signing_key().sign(format!("{h}.{p}").as_bytes());
    format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

/// A JWKS cache seeded with the test NRF's key; its URI is never fetched.
async fn seeded_jwks() -> nextgcore_sbi::oauth::JwksCache {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let point = signing_key().verifying_key().to_encoded_point(false);
    let cache = nextgcore_sbi::oauth::JwksCache::new("http://127.0.0.1:1/nnrf-oauth2/v1/jwks");
    cache
        .seed(json!({"keys":[{
            "kty":"EC","crv":"P-256","use":"sig","alg":"ES256","kid":KID,
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        }]}))
        .await;
    cache
}

/// The cell report the nextgsim gNB exporter sends (the wire contract).
fn report_body(cell: &str, tac: &str, occupancy: f64, ts_ms: u64, prediction: bool) -> Value {
    let mut body = json!({
        "ncgi": {"plmnId": {"mcc": "999", "mnc": "70"}, "nrCellId": cell},
        "tai": {"plmnId": {"mcc": "999", "mnc": "70"}, "tac": tac},
        "timeStamp": rfc3339_ms(ts_ms),
        "windowMs": 1000,
        "capacityKbps": 5000,
        "dlServedKbps": (occupancy * 50.0) as u64,
        "occupancyPct": occupancy,
        "connectedUes": 2,
    });
    if prediction {
        body["prediction"] = json!({"occupancyPct": 99.0, "horizonMs": 5000, "confidence": 87});
    }
    body
}

fn post(body: &Value, bearer: Option<&str>) -> SbiRequest {
    let mut req = SbiRequest::post("/nnwdaf-randata/v1/cell-reports")
        .with_json_body(body)
        .expect("json");
    if let Some(t) = bearer {
        req = req.with_header("Authorization", format!("Bearer {t}"));
    }
    req
}

fn udc_get(cell: &str, extra: &str) -> SbiRequest {
    let tgt = json!({"anyUe": true}).to_string();
    let filter = json!({"networkArea": {"ncgis": [
        {"plmnId": {"mcc": "999", "mnc": "70"}, "nrCellId": cell}
    ]}})
    .to_string();
    SbiRequest::get(format!(
        "/nnwdaf-analyticsinfo/v1/analytics?event-id=USER_DATA_CONGESTION&tgt-ue={}&event-filter={}{extra}",
        nextgcore_sbi::uri_encode::encode_query_value(&tgt),
        nextgcore_sbi::uri_encode::encode_query_value(&filter),
    ))
}

fn fresh_ctx() -> Arc<RwLock<crate::context::NwdafContext>> {
    let mut ctx = crate::context::NwdafContext::new("nwdaf-465".into());
    ctx.init(64);
    Arc::new(RwLock::new(ctx))
}

#[test]
fn the_registry_knows_three_modes_and_refuses_bogus() {
    let registry = nextgcore_demo::DemoRegistry::new(&[DEMO_SPEC]);
    let cfg = |y: &str| {
        nextgcore_demo::DemoConfig::from_root(&serde_yaml::from_str(y).expect("yaml"))
            .expect("parse")
    };
    for mode in MODES {
        let on = cfg(&format!(
            "demo: {{enabled: true, d441a-congestion-loop: {{enabled: true, mode: {mode}}}}}"
        ))
        .validate(&registry)
        .expect("valid");
        assert_eq!(on.mode(DEMO_KEY), Some(*mode));
    }
    let err = cfg("demo: {enabled: true, d441a-congestion-loop: {enabled: true, mode: bogus}}")
        .validate(&registry)
        .expect_err("bogus");
    assert_eq!(
        err,
        nextgcore_demo::DemoConfigError::UnknownMode {
            demo: DEMO_KEY.into(),
            mode: "bogus".into(),
            known: MODES.to_vec(),
        }
    );
    for off in [
        "nwdaf: {}",
        "demo: {enabled: false}",
        "demo: {enabled: false, d441a-congestion-loop: {enabled: true, mode: statistics}}",
    ] {
        assert!(
            cfg(off).validate(&registry).expect("valid").is_empty(),
            "{off}"
        );
    }
}

#[test]
fn the_contract_body_parses_and_bad_fields_are_named() {
    let r = parse_report(&report_body(
        "00000001a",
        "000001",
        96.0,
        1_700_000_000_000,
        true,
    ))
    .expect("contract body");
    assert_eq!(r.cell.nr_cell_id, "00000001A", "uppercased");
    assert_eq!(r.tai.tac, "000001");
    assert_eq!(r.occupancy_pct, 96.0);
    assert_eq!(r.connected_ues, 2);
    assert_eq!(
        r.prediction,
        Some(Prediction {
            occupancy_pct: 99.0,
            horizon_ms: 5000,
            confidence: 87
        })
    );
    for (field, bad) in [
        ("occupancyPct", json!(101.0)),
        ("windowMs", json!(0)),
        ("timeStamp", json!("yesterday")),
    ] {
        let mut b = report_body("000000010", "000001", 50.0, 1_700_000_000_000, false);
        b[field] = bad;
        let e = parse_report(&b).expect_err(field);
        assert!(e.contains(field), "{field}: {e}");
    }
    let mut b = report_body("000000010", "000001", 50.0, 1_700_000_000_000, false);
    b["ncgi"]["nrCellId"] = json!("10");
    assert!(parse_report(&b).unwrap_err().contains("nrCellId"));
}

/// Criterion: "An unauthenticated POST to /nnwdaf-randata/v1/cell-reports returns
/// 401 and creates no throttle". No token, a wrong-audience token and a bad
/// signature are 401; a token without the scope is 403; no keys is 503. None of
/// them ingests anything, and a valid token is 204 and ingested.
///
/// REVERT-VERIFIED: skipping `verify_token` in `ingest_report` turns the first
/// assertion into 204 and fills the store.
#[tokio::test]
async fn only_a_scoped_nrf_token_gets_a_report_in() {
    let _serving = ServingOnThisThread::new();
    let store = CellStore::default();
    let jwks = seeded_jwks().await;
    let now = unix_now_ms();
    let body = report_body("000000465", "000465", 96.0, now, false);

    for (bearer, status) in [
        (None, 401),
        (Some(token("AMF", SERVICE_NAME)), 401),
        (Some(format!("{}x", token("NWDAF", SERVICE_NAME))), 401),
        (Some(token("NWDAF", "nnwdaf-analyticsinfo")), 403),
    ] {
        let out = ingest_report(&store, Some(&jwks), &post(&body, bearer.as_deref())).await;
        assert_eq!(out.response.status, status, "bearer {bearer:?}");
        assert!(store.latest().is_empty(), "nothing ingested on {status}");
        assert!(out.new_tai.is_none());
    }
    let out = ingest_report(
        &store,
        None,
        &post(&body, Some(&token("NWDAF", SERVICE_NAME))),
    )
    .await;
    assert_eq!(out.response.status, 503, "no NRF, no keys: fail closed");
    assert!(store.latest().is_empty());

    let good = token("NWDAF", SERVICE_NAME);
    let out = ingest_report(&store, Some(&jwks), &post(&body, Some(&good))).await;
    assert_eq!(out.response.status, 204);
    assert_eq!(store.latest().len(), 1);
    assert_eq!(
        out.new_tai.map(|t| t.to_string()).as_deref(),
        Some("99970-000465"),
        "first sight of a TAI starts the AMF subscription"
    );
    let again = ingest_report(&store, Some(&jwks), &post(&body, Some(&good))).await;
    assert_eq!(again.response.status, 204);
    assert!(again.new_tai.is_none(), "once per TAI");
}

/// A process that is not serving answers 404, whatever the token.
#[tokio::test]
async fn not_serving_is_404() {
    let store = CellStore::default();
    let jwks = seeded_jwks().await;
    let body = report_body("000000466", "000466", 10.0, unix_now_ms(), false);
    let out = ingest_report(
        &store,
        Some(&jwks),
        &post(&body, Some(&token("NWDAF", SERVICE_NAME))),
    )
    .await;
    assert_eq!(out.response.status, 404);
    assert!(store.latest().is_empty());
}

/// Ordered-chain step 2: `GET ...USER_DATA_CONGESTION` is 200 with `congLevel`,
/// through the real Nnwdaf_AnalyticsInfo handler, for the cell in the requested
/// `networkArea`; a cell outside it gets nothing.
///
/// REVERT-VERIFIED: dropping the USER_DATA_CONGESTION arm in
/// `is_served_by_analytics_info` makes the first GET 204.
#[tokio::test]
async fn a_fresh_report_is_a_statistics_answer_with_cong_level() {
    let _serving = ServingOnThisThread::new();
    let now = unix_now_ms();
    store().ingest(parse_report(&report_body("000004651", "004651", 96.4, now, false)).unwrap());
    let ctx = fresh_ctx();

    let resp = handle_analytics_info_query_with_ctx(&ctx, &udc_get("000004651", "")).await;
    assert_eq!(resp.status, 200);
    let body: Value = serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
    let infos = body["userDataCongInfos"]
        .as_array()
        .expect("userDataCongInfos");
    assert_eq!(infos.len(), 1, "{body}");
    let info = &infos[0];
    // TS 29.520 Table 5.1.6.2.17-1 / 5.1.6.2.18-1: networkArea, congestionInfo
    // {congType, timeIntev, nsi} mandatory; no confidence for statistics.
    assert_eq!(info["networkArea"]["ncgis"][0]["nrCellId"], "000004651");
    assert_eq!(info["congestionInfo"]["congType"], "USER_PLANE");
    assert_eq!(info["congestionInfo"]["nsi"]["congLevel"], 96);
    assert!(info["congestionInfo"]["timeIntev"]["startTime"].is_string());
    assert!(info["congestionInfo"]["timeIntev"]["stopTime"].is_string());
    assert!(info["congestionInfo"].get("confidence").is_none());

    let other = handle_analytics_info_query_with_ctx(&ctx, &udc_get("000004659", "")).await;
    assert_eq!(other.status, 204, "a cell with no report has no analytics");
}

/// A future `ana-req` is a prediction: the gNB's predicted occupancy, with the
/// `confidence` Table 5.1.6.2.18-1 requires for predictions. A report without a
/// prediction (mode statistics) has none to give: 204.
#[tokio::test]
async fn a_future_period_is_the_gnb_prediction_with_confidence() {
    let _serving = ServingOnThisThread::new();
    let now = unix_now_ms();
    store().ingest(parse_report(&report_body("000004652", "004652", 70.0, now, true)).unwrap());
    store().ingest(parse_report(&report_body("000004653", "004653", 70.0, now, false)).unwrap());
    let ctx = fresh_ctx();
    let ana = format!(
        "&ana-req={}",
        nextgcore_sbi::uri_encode::encode_query_value(&json!({"offsetPeriod": 5}).to_string())
    );

    let resp = handle_analytics_info_query_with_ctx(&ctx, &udc_get("000004652", &ana)).await;
    assert_eq!(resp.status, 200);
    let body: Value = serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
    let ci = &body["userDataCongInfos"][0]["congestionInfo"];
    assert_eq!(
        ci["nsi"]["congLevel"], 99,
        "the predicted level, not the measured 70"
    );
    assert_eq!(ci["confidence"], 87);

    let none = handle_analytics_info_query_with_ctx(&ctx, &udc_get("000004653", &ana)).await;
    assert_eq!(none.status, 204);
}

/// Staleness: a report older than three windows (and 3 s) is no analytics: 204,
/// which is what pcfd reads as `hold(no-ran-data)`.
#[tokio::test]
async fn a_stale_report_is_204() {
    let _serving = ServingOnThisThread::new();
    let old = unix_now_ms() - 10_000;
    store().ingest(parse_report(&report_body("000004654", "004654", 99.0, old, false)).unwrap());
    let resp = handle_analytics_info_query_with_ctx(&fresh_ctx(), &udc_get("000004654", "")).await;
    assert_eq!(resp.status, 204);
}

/// TS 29.520 §4.3.2.2.2: an any-UE USER_DATA_CONGESTION request must name the
/// area (400 otherwise); a tgt-ue absent is 400; supis alone is 204 (no UE to
/// cell resolution here).
#[tokio::test]
async fn the_request_must_name_its_target_and_area() {
    let _serving = ServingOnThisThread::new();
    let ctx = fresh_ctx();
    let q = |extra: &str| {
        SbiRequest::get(format!(
            "/nnwdaf-analyticsinfo/v1/analytics?event-id=USER_DATA_CONGESTION{extra}"
        ))
    };
    let enc = |v: Value| nextgcore_sbi::uri_encode::encode_query_value(&v.to_string());
    let no_tgt = handle_analytics_info_query_with_ctx(&ctx, &q("")).await;
    assert_eq!(no_tgt.status, 400);
    let no_area = handle_analytics_info_query_with_ctx(
        &ctx,
        &q(&format!("&tgt-ue={}", enc(json!({"anyUe": true})))),
    )
    .await;
    assert_eq!(no_area.status, 400);
    let supis = handle_analytics_info_query_with_ctx(
        &ctx,
        &q(&format!(
            "&tgt-ue={}",
            enc(json!({"supis": ["imsi-999700000000001"]}))
        )),
    )
    .await;
    assert_eq!(supis.status, 204);
}

/// With the demo off the analytics stays the default build's 204.
#[tokio::test]
async fn not_serving_the_get_is_204_even_with_a_report() {
    store().ingest(
        parse_report(&report_body(
            "000004655",
            "004655",
            99.0,
            unix_now_ms(),
            false,
        ))
        .unwrap(),
    );
    let resp = handle_analytics_info_query_with_ctx(&fresh_ctx(), &udc_get("000004655", "")).await;
    assert_eq!(resp.status, 204);
}

#[test]
fn a_ues_in_area_notify_on_a_foreign_token_is_404() {
    let _serving = ServingOnThisThread::new();
    let store = CellStore::default();
    let _ = callback_token();
    let req = SbiRequest::post(format!("/nnwdaf-callback/v1/{CALLBACK_SEGMENT}/nope"))
        .with_json_body(&json!({"reportList": []}))
        .unwrap();
    assert_eq!(handle_ues_in_area_notify(&store, "nope", &req).status, 404);
}

/// Criterion: "nwdafd's numberOfUes for the AoI equals the gNB's connected-UE
/// count" needs the AMF's count in hand. amfd's REAL Namf_EventExposure handler,
/// reached over HTTP/2 after a discovery at a stand-in NRF, takes the
/// UES_IN_AREA_REPORT subscription this NWDAF sends; its immediate report
/// (TS 29.518 NOTE 8, carried in the 201's `reportList`) puts amfd's count of
/// the UEs in the TAI into the store. amfd spells TAC 0x4656 with four digits
/// and the gNB with six; they are the same TAI.
///
/// REVERT-VERIFIED: dropping `immediateFlag` from `ues_in_area_body` leaves the
/// count `None`.
#[tokio::test]
async fn amfd_counts_the_ues_in_the_reported_tai() {
    let _serving = ServingOnThisThread::new();
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    nextgcore_amfd::context::amf_context_init(64, 1024, 4096);
    crate::nwdaf_context_init("nwdaf-465-e2e".to_string(), 1024);
    {
        let ctx = nextgcore_amfd::context::amf_self();
        let guard = ctx.read().expect("amf ctx");
        for (i, ran_ue) in [465_101u64, 465_102].into_iter().enumerate() {
            let mut ue = guard.amf_ue_add(ran_ue).expect("ue");
            ue.supi = Some(format!("imsi-99970000046510{i}"));
            ue.nr_tai.plmn_id = nextgcore_amfd::context::PlmnId::new("999", "70");
            ue.nr_tai.tac = 0x004656;
            guard.amf_ue_update(&ue);
            guard.amf_ue_publish(&ue, ran_ue as u32, 1);
        }
    }
    let (amf, _amf_port, nrf, nrf_port) = amf_and_nrf("amf-465-e2e").await;
    let (nwdaf, nwdaf_port) = serve(crate::nwdaf_sbi_request_handler).await;
    let tai = TaiKey {
        mcc: "999".into(),
        mnc: "70".into(),
        tac: "004656".into(),
    };
    let ctx = AmfSubContext {
        nrf_uri: format!("http://127.0.0.1:{nrf_port}"),
        sbi_base: format!("http://127.0.0.1:{nwdaf_port}"),
        nf_id: "nwdaf-465-e2e".into(),
    };
    let sub = subscribe_ues_in_area(store(), &ctx, &tai, unix_now() + 600)
        .await
        .expect("amfd accepts UES_IN_AREA_REPORT");
    assert!(sub.id.starts_with("sub-"), "{}", sub.id);

    let mut count = None;
    for _ in 0..200 {
        count = store().ues_in_area(&tai);
        if count.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(count, Some(2), "amfd's numberOfUes for the TAI");
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

async fn amf_and_nrf(
    amf_id: &'static str,
) -> (nextgcore_sbi::SbiServer, u16, nextgcore_sbi::SbiServer, u16) {
    let (amf, amf_port) = serve(nextgcore_amfd::namf_server::namf_request_handler).await;
    let profile = nextgcore_amfd::sbi_path::amf_nf_profile_json(amf_id, "127.0.0.1", amf_port);
    let (nrf, nrf_port) = serve(move |req: SbiRequest| {
        let profile = profile.clone();
        async move {
            if req.header.uri.starts_with("/nnrf-disc/v1/nf-instances")
                && req.http.params.get("target-nf-type").map(String::as_str) == Some("AMF")
            {
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

/// While serving, the NRF profile offers `nnwdaf-randata` to the AF only (so the
/// NRF can grant the exporter its token and nobody else one) and advertises
/// USER_DATA_CONGESTION in `eventIds`; not serving, neither.
///
/// REVERT-VERIFIED: removing the `services.push` in `build_nf_profile` fails the
/// first assertion.
#[test]
fn the_profile_offers_the_ingest_service_only_while_serving() {
    let allowed = vec!["PCF".to_string(), "AF".to_string()];
    let find = |p: &Value| {
        p["nfServices"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["serviceName"] == SERVICE_NAME)
            .cloned()
    };
    let udc = |p: &Value| {
        p["nwdafInfo"]["eventIds"]
            .as_array()
            .is_some_and(|ids| ids.iter().any(|e| e == "USER_DATA_CONGESTION"))
    };
    let off = crate::build_nf_profile("nwdaf-465-p", "10.0.0.5", 7777, &allowed);
    assert!(find(&off).is_none() && !udc(&off), "{off}");
    let _serving = ServingOnThisThread::new();
    let on = crate::build_nf_profile("nwdaf-465-p", "10.0.0.5", 7777, &allowed);
    let svc = find(&on).expect("nnwdaf-randata advertised while serving");
    assert_eq!(svc["allowedNfTypes"], json!(["AF"]));
    assert_eq!(svc["ipEndPoints"][0]["port"], 7777);
    assert!(udc(&on), "{on}");
    assert!(
        !on["nwdafInfo"]["nwdafEvents"]
            .as_array()
            .is_some_and(|e| e.iter().any(|x| x == "USER_DATA_CONGESTION")),
        "not on the EventsSubscription surface, which does not serve it"
    );
}
