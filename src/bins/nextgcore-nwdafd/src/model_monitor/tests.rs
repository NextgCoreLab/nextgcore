//! nextgsim#468 PR 3: Nnwdaf_MLModelMonitor between an MTLF and an AnLF, both
//! nwdafd's own handlers, over real HTTP with a stand-in NRF.

use super::*;
use crate::context::{AnalyticsId, MlProvSubscription, NwdafContext};
use std::sync::Arc;
use std::time::Instant;

type Ctx = Arc<RwLock<NwdafContext>>;

fn context(id: &str) -> Ctx {
    let mut ctx = NwdafContext::new(id.to_string());
    ctx.init(16);
    Arc::new(RwLock::new(ctx))
}

fn leak(m: Monitor) -> &'static Monitor {
    Box::leak(Box::new(m))
}

fn post(path: &str, body: Value) -> SbiRequest {
    SbiRequest::post(path).with_json_body(&body).unwrap()
}

#[test]
fn registrations_need_a_model_id_and_one_consumer_identifier() {
    assert_eq!(
        parse_registration(&json!({ "modelId": 7, "consumerId": "a" })),
        Ok((Some("a".into()), 7))
    );
    assert_eq!(
        parse_registration(&json!({ "modelId": 7, "consumerSetId": "set" })),
        Ok((None, 7))
    );
    for bad in [
        json!({ "consumerId": "a" }),
        json!({ "modelId": "7", "consumerId": "a" }),
        json!({ "modelId": 7 }),
        json!({ "modelId": 7, "consumerId": "a", "consumerSetId": "s" }),
    ] {
        assert!(parse_registration(&bad).is_err(), "{bad}");
    }
}

#[test]
fn subscriptions_need_model_ids_a_uri_and_a_correlation_id() {
    let ok = json!({
        "modelIds": [1, 2], "notificationUri": "http://m:1/cb", "notifCorrId": "c",
        "accuThreshold": 70, "eventReportReq": { "notifMethod": "PERIODIC", "repPeriod": 5 }
    });
    let s = parse_subscription(&ok).unwrap();
    assert_eq!(
        (s.model_ids.clone(), s.accu_threshold, s.period_secs),
        (vec![1, 2], Some(70), 5)
    );
    let mut d = ok.clone();
    d.as_object_mut().unwrap().remove("eventReportReq");
    assert_eq!(
        parse_subscription(&d).unwrap().period_secs,
        DEFAULT_REPORT_PERIOD_SECS
    );
    for (k, v) in [
        ("modelIds", json!([])),
        ("modelIds", json!(["1"])),
        ("notificationUri", json!("nope")),
        ("notifCorrId", json!(3)),
        ("accuThreshold", json!(101)),
    ] {
        let mut b = ok.clone();
        b[k] = v;
        assert!(parse_subscription(&b).is_err(), "{k}");
    }
}

/// Demo off: every resource is 404. Each role serves only its half.
#[tokio::test]
async fn routes_are_gated_by_the_demo_and_the_role() {
    let ctx = context("gate");
    let req = post("/x", json!({}));
    let s = |r: SbiResponse| r.status;
    for rest in [&["registrations"][..], &["subscriptions"][..]] {
        assert_eq!(s(route(None, &ctx, "POST", rest, &req)), 404, "{rest:?}");
    }
    let mtlf = leak(Monitor::new(
        "retrain",
        Role::Mtlf,
        "http://m",
        "m",
        "http://n",
    ));
    let anlf = leak(Monitor::new(
        "retrain",
        Role::Anlf,
        "http://a",
        "a",
        "http://n",
    ));
    assert_eq!(
        s(route(Some(mtlf), &ctx, "POST", &["subscriptions"], &req)),
        404
    );
    assert_eq!(
        s(route(Some(anlf), &ctx, "POST", &["registrations"], &req)),
        404
    );
    // Live on the right role: a malformed body is a 400, not a 404.
    assert_eq!(
        s(route(Some(mtlf), &ctx, "POST", &["registrations"], &req)),
        400
    );
    assert_eq!(
        s(route(Some(anlf), &ctx, "POST", &["subscriptions"], &req)),
        400
    );
    assert_eq!(
        s(route(Some(mtlf), &ctx, "GET", &["registrations"], &req)),
        405
    );
    // The MTLF callback is not served by an AnLF, nor with a wrong token.
    assert_eq!(s(handle_notify(Some(anlf), &anlf.token, &req)), 404);
    assert_eq!(s(handle_notify(Some(mtlf), "nope", &req)), 404);
    assert_eq!(s(handle_notify(None, "nope", &req)), 404);
}

/// A registration names a model this MTLF provisioned; the threshold comes from
/// the AnLF's ML-provision subscription.
#[tokio::test]
async fn a_registration_for_an_unknown_model_is_refused() {
    let ctx = context("reg");
    let m = leak(Monitor::new(
        "retrain",
        Role::Mtlf,
        "http://m",
        "m",
        "http://127.0.0.1:1",
    ));
    let guard = ctx.read().unwrap();
    let r = handle_register(
        m,
        &guard,
        &post("/", json!({ "modelId": 1, "consumerId": "a" })),
    );
    assert_eq!(r.status, 400);
    let v1 = guard.current_model_version().unwrap();
    let mut sub = MlProvSubscription::new(
        "s".into(),
        "http://a/cb".into(),
        None,
        vec![AnalyticsId::NfLoad],
    );
    sub.accuracy_thresholds = vec![crate::ml_service::EventAccuracyThreshold {
        event: AnalyticsId::NfLoad,
        threshold: 65,
    }];
    guard.add_ml_prov_subscription(sub);
    let r = handle_register(
        m,
        &guard,
        &post("/", json!({ "modelId": v1.unique_id(), "consumerId": "a" })),
    );
    assert_eq!(r.status, 201);
    let loc = r.http.get_header("Location").unwrap().clone();
    assert!(
        loc.starts_with("/nnwdaf-mlmodelmonitor/v1/registrations/reg-"),
        "{loc}"
    );
    let c = lock(&m.feedback);
    let col = c.collector(&v1.unique_id().to_string()).unwrap();
    assert!((col.threshold() - 0.65).abs() < 1e-9);
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

fn parts(req: &SbiRequest) -> Vec<String> {
    req.header
        .uri
        .split('?')
        .next()
        .unwrap_or("")
        .trim_start_matches('/')
        .split('/')
        .map(String::from)
        .collect()
}

/// An NWDAF's SBI: the MLModelMonitor routes and the MTLF callback.
async fn nwdaf_on(
    listener: nextgcore_sbi::test_support::BoundListener,
    m: &'static Monitor,
    ctx: Ctx,
) -> nextgcore_sbi::SbiServer {
    let (listener, addr) = listener.into_parts();
    let server =
        nextgcore_sbi::SbiServer::on_listener(nextgcore_sbi::SbiServerConfig::new(addr), listener);
    server
        .start(move |req: SbiRequest| {
            let ctx = ctx.clone();
            async move {
                let p = parts(&req);
                let p: Vec<&str> = p.iter().map(String::as_str).collect();
                let method = req.header.method.clone();
                match p.as_slice() {
                    ["nnwdaf-mlmodelmonitor", "v1", rest @ ..] => {
                        route(Some(m), &ctx, &method, rest, &req)
                    }
                    ["nnwdaf-callback", "v1", CALLBACK_SEGMENT, token] => {
                        handle_notify(Some(m), token, &req)
                    }
                    _ => SbiResponse::with_status(404),
                }
            }
        })
        .await
        .expect("start");
    server
}

/// A stand-in NRF that answers discovery of `anlf_id` with its profile.
async fn nrf(anlf_id: &'static str, anlf_port: u16) -> (nextgcore_sbi::SbiServer, u16) {
    serve(move |req: SbiRequest| async move {
        if req
            .http
            .params
            .get("target-nf-instance-id")
            .map(String::as_str)
            != Some(anlf_id)
            || req.http.params.get("service-names").map(String::as_str) != Some(SERVICE_NAME)
        {
            return SbiResponse::with_status(200)
                .with_json_body(&json!({ "nfInstances": [] }))
                .unwrap();
        }
        let profile = json!({ "nfInstances": [{
            "nfInstanceId": anlf_id, "nfType": "NWDAF",
            "nfServices": [nf_service(anlf_id, "127.0.0.1", anlf_port)]
        }]});
        SbiResponse::with_status(200)
            .with_json_body(&profile)
            .unwrap()
    })
    .await
}

async fn until(what: &str, cond: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Feed `values` as one NF's CPU-load series into `ctx`.
fn ingest(ctx: &Ctx, nf: &str, values: &[f64]) {
    let guard = ctx.read().unwrap();
    let mut engine = guard.lock_engine();
    for (i, v) in values.iter().enumerate() {
        let mut s = crate::analytics::NfLoadSample::now("AMF", nf, *v, 0.0, 0);
        s.timestamp = 1_000 + i as u64;
        engine.ingest_nf_load(s);
    }
}

struct Pair {
    mtlf: &'static Monitor,
    anlf: &'static Monitor,
    mtlf_ctx: Ctx,
    anlf_ctx: Ctx,
    mtlf_port: u16,
    servers: Vec<nextgcore_sbi::SbiServer>,
}

async fn pair(mode: &str, anlf_id: &'static str) -> Pair {
    let (mtlf_ctx, anlf_ctx) = (context("mtlf-468m"), context(anlf_id));
    let anlf = leak(Monitor::new(
        mode,
        Role::Anlf,
        "http://unused",
        anlf_id,
        "http://unused",
    ));
    let anlf_listener = nextgcore_sbi::test_support::bound_listener();
    let anlf_port = anlf_listener.port();
    let anlf_srv = nwdaf_on(anlf_listener, anlf, anlf_ctx.clone()).await;
    let (nrf_srv, nrf_port) = nrf(anlf_id, anlf_port).await;
    let mtlf_listener = nextgcore_sbi::test_support::bound_listener();
    let mtlf_port = mtlf_listener.port();
    let mtlf = leak(Monitor::new(
        mode,
        Role::Mtlf,
        &format!("http://127.0.0.1:{mtlf_port}"),
        "mtlf-468m",
        &format!("http://127.0.0.1:{nrf_port}"),
    ));
    let mtlf_srv = nwdaf_on(mtlf_listener, mtlf, mtlf_ctx.clone()).await;
    Pair {
        mtlf,
        anlf,
        mtlf_ctx,
        anlf_ctx,
        mtlf_port,
        servers: vec![anlf_srv, nrf_srv, mtlf_srv],
    }
}

/// A ramp the OLS predictor extrapolates exactly, then a scripted regime change
/// (an alternating series OLS cannot follow).
const RAMP: [f64; 12] = [
    0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65,
];
const CHOPPY: [f64; 12] = [0.9, 0.1, 0.9, 0.1, 0.9, 0.1, 0.9, 0.1, 0.9, 0.1, 0.9, 0.1];

/// Register → Subscribe at the AnLF → accuracy Notify → FeedbackRegistry → a
/// drop below 0.70 requests a retrain (mode `retrain`). Then a new model:
/// deregister, unsubscribe, register again.
#[tokio::test]
async fn register_subscribe_report_and_request_a_retrain() {
    let p = pair("retrain", "anlf-468m").await;
    let v1 = p.mtlf_ctx.read().unwrap().current_model_version().unwrap();
    let model_id = v1.unique_id();

    // Register (AnLF → MTLF); the MTLF then subscribes at the AnLF.
    let held = register_at_mtlf(p.anlf, ("127.0.0.1".into(), p.mtlf_port), model_id)
        .await
        .expect("registered");
    let reg = p.mtlf.registration(&held.id).expect("the MTLF holds it");
    assert_eq!(reg.consumer_id.as_deref(), Some("anlf-468m"));
    until("the MTLF's subscription at the AnLF", || {
        lock(&p.anlf.subscriptions).len() == 1
    })
    .await;
    let sub = lock(&p.anlf.subscriptions).values().next().unwrap().clone();
    assert_eq!(sub.model_ids, vec![model_id]);
    assert_eq!(sub.notif_corr_id, held.id);
    assert_eq!(sub.accu_threshold, Some(70));

    // Good data: accuracy ~1.00 and no retrain.
    ingest(&p.anlf_ctx, "amf-1", &RAMP);
    let (pct, n) = measure(&p.anlf_ctx).expect("points to judge on");
    assert!(pct >= 99 && n > 0, "{pct} {n}");
    assert_eq!(
        report_tick(p.anlf, &p.anlf_ctx, Some(model_id), 10_000).await,
        1
    );
    assert_eq!(
        report_tick(p.anlf, &p.anlf_ctx, Some(model_id), 10_001).await,
        0,
        "not due before repPeriod"
    );
    assert_eq!(
        report_tick(p.anlf, &p.anlf_ctx, Some(model_id + 1), 20_000).await,
        0,
        "only for the subscribed model"
    );
    until("the report at the MTLF", || p.mtlf.counts().1 == 1).await;
    assert!(p.mtlf.rolling(model_id).unwrap().0 > 0.98);
    assert!(!p.mtlf.retrain_requested(model_id));

    // The regime change: accuracy collapses; after enough reports the rolling
    // accuracy is below 0.70 and a retrain is requested.
    ingest(&p.anlf_ctx, "amf-1", &CHOPPY);
    let (low, _) = measure(&p.anlf_ctx).unwrap();
    assert!(low < 70, "{low}");
    for k in 1..=FEEDBACK_WINDOW as u64 {
        report_tick(p.anlf, &p.anlf_ctx, Some(model_id), 10_000 + k * 100).await;
    }
    until("the reports at the MTLF", || {
        p.mtlf.counts().1 == 1 + FEEDBACK_WINDOW as u64
    })
    .await;
    assert!(p.mtlf.rolling(model_id).unwrap().0 < 0.70);
    assert!(p.mtlf.retrain_requested(model_id));

    // A new model: the AnLF deregisters v1 and registers v2; the MTLF
    // unsubscribes v1's subscription at the AnLF and subscribes for v2.
    let refit = crate::onnx_export::encode_linear_regressor(&[0.1, 0.2, 0.3, 0.4], 0.02);
    p.mtlf_ctx
        .read()
        .unwrap()
        .lock_engine()
        .set_predictor(Box::new(
            crate::onnx_model::OnnxLinearRegressor::from_bytes(&refit, "refit").unwrap(),
        ));
    let v2 = p.mtlf_ctx.read().unwrap().current_model_version().unwrap();
    let held2 = register_at_mtlf(p.anlf, ("127.0.0.1".into(), p.mtlf_port), v2.unique_id())
        .await
        .unwrap();
    assert!(p.mtlf.registration(&held.id).is_none(), "v1 deregistered");
    assert!(p.mtlf.registration(&held2.id).is_some());
    until("v1's subscription gone and v2's in place", || {
        let subs = lock(&p.anlf.subscriptions);
        subs.len() == 1 && subs.values().all(|s| s.model_ids == vec![v2.unique_id()])
    })
    .await;
    for s in p.servers {
        s.stop().await.unwrap();
    }
}

/// Mode `no-retrain`: the same drop is detected, and no retrain is requested.
#[tokio::test]
async fn no_retrain_detects_the_drop_but_requests_nothing() {
    let p = pair("no-retrain", "anlf-468n").await;
    let model_id = p
        .mtlf_ctx
        .read()
        .unwrap()
        .current_model_version()
        .unwrap()
        .unique_id();
    register_at_mtlf(p.anlf, ("127.0.0.1".into(), p.mtlf_port), model_id)
        .await
        .unwrap();
    until("subscribed", || lock(&p.anlf.subscriptions).len() == 1).await;
    ingest(&p.anlf_ctx, "amf-1", &CHOPPY);
    for k in 0..FEEDBACK_WINDOW as u64 {
        report_tick(p.anlf, &p.anlf_ctx, Some(model_id), 50_000 + k * 100).await;
    }
    until("the reports", || {
        p.mtlf.counts().1 == FEEDBACK_WINDOW as u64
    })
    .await;
    assert!(p.mtlf.below_threshold(model_id));
    assert!(!p.mtlf.retrain_requested(model_id));
    for s in p.servers {
        s.stop().await.unwrap();
    }
}

/// The Notify body: TS 29.520 `MLModelMonitorNotify`, and the callback refuses
/// what is not one.
#[test]
fn notify_bodies() {
    let sub = parse_subscription(&json!({
        "modelIds": [9], "notificationUri": "http://m:1/cb", "notifCorrId": "reg-1", "accuThreshold": 70
    }))
    .unwrap();
    let b = notify_body(&sub, 9, 64, 12, 100, 130);
    assert_eq!(b["notifCorrId"], "reg-1");
    assert_eq!(b["modelAccuInfos"][0]["mlModelAcc"], 64);
    assert_eq!(b["modelAccuInfos"][0]["inferenceNum"], 12);
    assert!(b["modelAccuInfos"][0]["monitorInterval"]["startTime"].is_string());
    assert_eq!(b["accuMeetInd"], false);

    let m = leak(Monitor::new(
        "retrain",
        Role::Mtlf,
        "http://m",
        "m",
        "http://n",
    ));
    let t = m.token.clone();
    lock(&m.feedback).register_model_with("9".into(), 3, 0.7);
    for bad in [
        json!({ "modelAccuInfos": [] }),
        json!({ "notifCorrId": "x" }),
        json!({ "notifCorrId": "x", "modelAccuInfos": [{ "modelId": 9, "mlModelAcc": 101 }] }),
    ] {
        assert_eq!(
            handle_notify(Some(m), &t, &post("/", bad.clone())).status,
            400,
            "{bad}"
        );
    }
    let ok = json!({ "notifCorrId": "x", "modelAccuInfos": [{ "modelId": 9, "mlModelAcc": 90 }] });
    assert_eq!(handle_notify(Some(m), &t, &post("/", ok)).status, 204);
    assert_eq!(m.rolling(9).unwrap().1, 1);
}
