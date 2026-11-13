//! nextgsim#468 PR 3: Nnwdaf_MLModelMonitor between an MTLF and an AnLF, both
//! nwdafd's own handlers, over real HTTP with a stand-in NRF.

use super::*;
use crate::context::{AnalyticsId, MlProvSubscription, NwdafContext};
use std::sync::{Arc, Mutex};
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
/// the registering AnLF's own ML-provision subscription, not another AnLF's
/// lower one (#1473 review, MINOR 4).
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
    sub.consumer_id = Some("a".into());
    guard.add_ml_prov_subscription(sub);
    let mut other = MlProvSubscription::new(
        "s-b".into(),
        "http://b/cb".into(),
        None,
        vec![AnalyticsId::NfLoad],
    );
    other.accuracy_thresholds = vec![crate::ml_service::EventAccuracyThreshold {
        event: AnalyticsId::NfLoad,
        threshold: 50,
    }];
    other.consumer_id = Some("b".into());
    guard.add_ml_prov_subscription(other);
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
    let reg_id = loc.rsplit('/').next().unwrap();
    assert_eq!(
        m.registration(reg_id).unwrap().threshold,
        65,
        "a's, not b's 50"
    );
    let c = lock(&m.feedback);
    let col = c.collector(reg_id).unwrap();
    assert!((col.threshold() - 0.65).abs() < 1e-9);
    drop(c);
    // An AnLF with no ML-provision subscription of its own gets the default.
    let r = handle_register(
        m,
        &guard,
        &post("/", json!({ "modelId": v1.unique_id(), "consumerId": "c" })),
    );
    let loc = r.http.get_header("Location").unwrap().clone();
    assert_eq!(
        m.registration(loc.rsplit('/').next().unwrap())
            .unwrap()
            .threshold,
        crate::model_retrain::DEFAULT_ACCURACY_THRESHOLD
    );
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

/// The monitor an NWDAF's SBI serves; swapping it simulates a restart (a new
/// token, no registrations or subscriptions) on the same address.
type Slot = Arc<Mutex<&'static Monitor>>;

/// An NWDAF's SBI: the MLModelMonitor routes and the MTLF callback.
async fn nwdaf_on(
    listener: nextgcore_sbi::test_support::BoundListener,
    slot: Slot,
    ctx: Ctx,
) -> nextgcore_sbi::SbiServer {
    let (listener, addr) = listener.into_parts();
    let server =
        nextgcore_sbi::SbiServer::on_listener(nextgcore_sbi::SbiServerConfig::new(addr), listener);
    server
        .start(move |req: SbiRequest| {
            let ctx = ctx.clone();
            let m: &'static Monitor = *slot.lock().unwrap();
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
    nrf_port: u16,
    mtlf_slot: Slot,
    anlf_slot: Slot,
    servers: Vec<nextgcore_sbi::SbiServer>,
}

impl Pair {
    /// Restart the MTLF: a new monitor (new token, no registrations) on the
    /// same address.
    fn restart_mtlf(&mut self, mode: &str) -> &'static Monitor {
        let m = leak(Monitor::new(
            mode,
            Role::Mtlf,
            &format!("http://127.0.0.1:{}", self.mtlf_port),
            "mtlf-468m",
            &format!("http://127.0.0.1:{}", self.nrf_port),
        ));
        *self.mtlf_slot.lock().unwrap() = m;
        self.mtlf = m;
        m
    }

    /// Restart the AnLF: a new monitor (no subscriptions, nothing held).
    fn restart_anlf(&mut self, mode: &str, anlf_id: &str) -> &'static Monitor {
        let m = leak(Monitor::new(
            mode,
            Role::Anlf,
            "http://unused",
            anlf_id,
            "http://unused",
        ));
        *self.anlf_slot.lock().unwrap() = m;
        self.anlf = m;
        m
    }

    fn mtlf_addr(&self) -> (String, u16) {
        ("127.0.0.1".into(), self.mtlf_port)
    }

    async fn stop(self) {
        for s in self.servers {
            s.stop().await.unwrap();
        }
    }
}

async fn pair(mode: &str, anlf_id: &'static str) -> Pair {
    pair_with(mode, anlf_id, NOTIFY_BUDGET).await
}

async fn pair_with(mode: &str, anlf_id: &'static str, budget: Duration) -> Pair {
    let (mtlf_ctx, anlf_ctx) = (context("mtlf-468m"), context(anlf_id));
    let anlf = leak(
        Monitor::new(mode, Role::Anlf, "http://unused", anlf_id, "http://unused")
            .with_limits(MAX_SUBSCRIPTIONS, budget),
    );
    let anlf_slot: Slot = Arc::new(Mutex::new(anlf));
    let anlf_listener = nextgcore_sbi::test_support::bound_listener();
    let anlf_port = anlf_listener.port();
    let anlf_srv = nwdaf_on(anlf_listener, anlf_slot.clone(), anlf_ctx.clone()).await;
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
    let mtlf_slot: Slot = Arc::new(Mutex::new(mtlf));
    let mtlf_srv = nwdaf_on(mtlf_listener, mtlf_slot.clone(), mtlf_ctx.clone()).await;
    Pair {
        mtlf,
        anlf,
        mtlf_ctx,
        anlf_ctx,
        mtlf_port,
        nrf_port,
        mtlf_slot,
        anlf_slot,
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
    let (pct, n) = measure(&p.anlf_ctx, None).expect("points to judge on");
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
    let (low, _) = measure(&p.anlf_ctx, None).unwrap();
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
    p.stop().await;
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
    p.stop().await;
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
    registered(m, "x", 9);
    for bad in [
        json!({ "modelAccuInfos": [] }),
        json!({ "notifCorrId": "x" }),
        json!({ "notifCorrId": "x", "modelAccuInfos": [{ "modelId": 9, "mlModelAcc": 101 }] }),
        json!({ "notifCorrId": "x", "modelAccuInfos": [{ "mlModelAcc": 90 }] }),
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

/// A live registration `id` of `model_id` at MTLF `m`, with its collector.
fn registered(m: &Monitor, id: &str, model_id: u64) {
    lock(&m.registrations).insert(
        id.into(),
        Registration {
            consumer_id: Some("a".into()),
            model_id,
            threshold: 70,
            anlf_subscription: None,
            last_seen: unix_now(),
            auditing: false,
        },
    );
    lock(&m.feedback).register_model_with(id.into(), FEEDBACK_WINDOW, 0.70);
}

fn cause(r: &SbiResponse) -> Option<String> {
    let body: Value = serde_json::from_str(r.http.content.as_deref()?).ok()?;
    body.get("cause").and_then(Value::as_str).map(String::from)
}

// ── #1473 review, MAJOR 1: bounds ───────────────────────────────────────────

/// The reviewer's AnLF probe: 20,000 `POST /subscriptions` with `repPeriod: 1`
/// and arbitrary hosts. At a cap of 8 the map holds 8 and the rest are 500
/// `INSUFFICIENT_RESOURCES`; the period applied is the floor; a freed slot can
/// be reused.
#[test]
fn the_anlf_subscription_map_is_capped() {
    let m = leak(
        Monitor::new("retrain", Role::Anlf, "http://a", "a", "http://n")
            .with_limits(8, NOTIFY_BUDGET),
    );
    let (mut ok, mut refused) = (Vec::new(), 0);
    for i in 0..20_000 {
        let r = handle_subscribe(
            m,
            None,
            &post(
                "/",
                json!({
                    "modelIds": [1], "notificationUri": format!("http://h{i}.example:80/cb"),
                    "notifCorrId": "c", "eventReportReq": { "notifMethod": "PERIODIC", "repPeriod": 1 }
                }),
            ),
        );
        match r.status {
            201 => ok.push(
                r.http
                    .get_header("Location")
                    .unwrap()
                    .rsplit('/')
                    .next()
                    .unwrap()
                    .to_string(),
            ),
            500 => {
                assert_eq!(cause(&r).as_deref(), Some(INSUFFICIENT_RESOURCES));
                refused += 1;
            }
            s => panic!("unexpected {s}"),
        }
    }
    assert_eq!((ok.len(), refused), (8, 20_000 - 8));
    assert_eq!(m.subscription_count(), 8);
    assert!(lock(&m.subscriptions)
        .values()
        .all(|s| s.period_secs == MIN_REPORT_PERIOD_SECS));
    assert_eq!(handle_unsubscribe(m, &ok[0]).status, 204);
    let r = handle_subscribe(
        m,
        None,
        &post(
            "/",
            json!({ "modelIds": [1], "notificationUri": "http://m:1/cb", "notifCorrId": "c" }),
        ),
    );
    assert_eq!(r.status, 201, "a freed slot is reusable");
}

/// The reviewer's MTLF probe: 5,000 registrations for one valid `modelId`. At
/// a cap of 8 distinct consumers fill it and the rest are 500
/// `INSUFFICIENT_RESOURCES` (so at most 8 Subscribe tasks are spawned); one
/// consumer registering the same model again replaces its registration.
#[tokio::test]
async fn the_mtlf_registration_map_is_capped() {
    let ctx = context("cap-468");
    let down = nextgcore_sbi::test_support::down_port();
    let m = leak(
        Monitor::new(
            "retrain",
            Role::Mtlf,
            "http://m",
            "m",
            &format!("http://127.0.0.1:{}", down.addr().port()),
        )
        .with_limits(8, NOTIFY_BUDGET),
    );
    let guard = ctx.read().unwrap();
    let model = guard.current_model_version().unwrap().unique_id();
    let mut refused = 0;
    for i in 0..5_000 {
        let r = handle_register(
            m,
            &guard,
            &post(
                "/",
                json!({ "modelId": model, "consumerId": format!("anlf-{i}") }),
            ),
        );
        match r.status {
            201 => {}
            500 => {
                assert_eq!(cause(&r).as_deref(), Some(INSUFFICIENT_RESOURCES));
                refused += 1;
            }
            s => panic!("unexpected {s}"),
        }
    }
    assert_eq!((m.registration_count(), refused), (8, 5_000 - 8));
    assert_eq!(lock(&m.feedback).collector_count(), 8, "one collector each");

    // The same consumer and model again: replaced, not added, even at the cap.
    for _ in 0..5_000 {
        let r = handle_register(
            m,
            &guard,
            &post("/", json!({ "modelId": model, "consumerId": "anlf-0" })),
        );
        assert_eq!(r.status, 201);
    }
    assert_eq!(m.registration_count(), 8);
    assert_eq!(lock(&m.feedback).collector_count(), 8);
}

/// A connection that never answers.
async fn blackhole() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = l.accept().await {
            held.push(s);
        }
    });
    port
}

/// Dead `notificationUri`s cost a tick one Notify budget, not one each, and do
/// not delay the MTLF's real report.
#[tokio::test]
async fn slow_peers_do_not_stall_the_reporter() {
    let budget = Duration::from_millis(400);
    let p = pair_with("retrain", "anlf-468s", budget).await;
    let model_id = p
        .mtlf_ctx
        .read()
        .unwrap()
        .current_model_version()
        .unwrap()
        .unique_id();
    register_at_mtlf(p.anlf, p.mtlf_addr(), model_id)
        .await
        .unwrap();
    until("subscribed", || p.anlf.subscription_count() == 1).await;
    let hole = blackhole().await;
    for _ in 0..10 {
        let r = handle_subscribe(
            p.anlf,
            None,
            &post(
                "/",
                json!({
                    "modelIds": [model_id], "notificationUri": format!("http://127.0.0.1:{hole}/cb"),
                    "notifCorrId": "junk"
                }),
            ),
        );
        assert_eq!(r.status, 201);
    }
    ingest(&p.anlf_ctx, "amf-1", &RAMP);
    let t0 = Instant::now();
    let sent = report_tick(p.anlf, &p.anlf_ctx, Some(model_id), 10_000).await;
    let took = t0.elapsed();
    assert_eq!(sent, 1, "the real report");
    assert_eq!(
        p.mtlf.counts().1,
        1,
        "the MTLF has it when the tick returns"
    );
    assert!(
        took < budget * 3,
        "10 dead peers took {took:?}; one budget is {budget:?}"
    );
    p.stop().await;
}

// ── #1473 review, MAJOR 2: peer restarts ────────────────────────────────────

/// The MTLF restarts (a new token, no registrations): the AnLF's next Notify
/// is answered 404, the AnLF drops the subscription, registers again, and
/// reports resume at the new MTLF.
#[tokio::test]
async fn an_mtlf_restart_is_recovered() {
    let mut p = pair("retrain", "anlf-468r").await;
    let model_id = p
        .mtlf_ctx
        .read()
        .unwrap()
        .current_model_version()
        .unwrap()
        .unique_id();
    let held = register_at_mtlf(p.anlf, p.mtlf_addr(), model_id)
        .await
        .unwrap();
    until("subscribed", || p.anlf.subscription_count() == 1).await;
    ingest(&p.anlf_ctx, "amf-1", &RAMP);
    assert_eq!(
        report_tick(p.anlf, &p.anlf_ctx, Some(model_id), 10_000).await,
        1
    );

    let mtlf2 = p.restart_mtlf("retrain");
    assert_eq!(
        report_tick(p.anlf, &p.anlf_ctx, Some(model_id), 10_100).await,
        0,
        "the old token is 404"
    );
    assert_eq!(
        p.anlf.subscription_count(),
        0,
        "the dead subscription is dropped"
    );
    assert!(p.anlf.held().is_none(), "and the registration forgotten");

    // The next tick registers again (no same-model short-circuit); the new
    // MTLF subscribes, and the reports reach it.
    report_tick(p.anlf, &p.anlf_ctx, Some(model_id), 10_101).await;
    until("registered at the new MTLF", || {
        p.anlf.held().is_some_and(|h| h.id != held.id)
            && mtlf2.registration_count() == 1
            && p.anlf.subscription_count() == 1
    })
    .await;
    let held2 = p.anlf.held().unwrap();
    assert!(mtlf2.registration(&held2.id).is_some());
    assert_eq!(
        report_tick(p.anlf, &p.anlf_ctx, Some(model_id), 10_200).await,
        1
    );
    until("the report at the new MTLF", || mtlf2.counts().1 == 1).await;
    assert_eq!(mtlf2.rolling_of(&held2.id).unwrap().1, 1);
    p.stop().await;
}

/// The AnLF holds a registration the MTLF never subscribed to (or dropped):
/// after the grace it deregisters it and registers again.
#[tokio::test]
async fn an_unserved_registration_is_renewed() {
    let p = pair("retrain", "anlf-468o").await;
    let model_id = p
        .mtlf_ctx
        .read()
        .unwrap()
        .current_model_version()
        .unwrap()
        .unique_id();
    let held = register_at_mtlf(p.anlf, p.mtlf_addr(), model_id)
        .await
        .unwrap();
    until("subscribed", || p.anlf.subscription_count() == 1).await;
    // The subscription vanishes at the AnLF (as if the MTLF unsubscribed).
    lock(&p.anlf.subscriptions).clear();
    report_tick(p.anlf, &p.anlf_ctx, Some(model_id), 20_000).await;
    report_tick(
        p.anlf,
        &p.anlf_ctx,
        Some(model_id),
        20_000 + ORPHAN_GRACE_SECS - 1,
    )
    .await;
    assert_eq!(p.anlf.held().unwrap().id, held.id, "within the grace");
    report_tick(
        p.anlf,
        &p.anlf_ctx,
        Some(model_id),
        20_000 + ORPHAN_GRACE_SECS,
    )
    .await;
    until("registered again", || {
        p.anlf.held().is_some_and(|h| h.id != held.id) && p.anlf.subscription_count() == 1
    })
    .await;
    until("the old registration deregistered", || {
        p.mtlf.registration(&held.id).is_none()
    })
    .await;
    assert_eq!(p.mtlf.registration_count(), 1);
    p.stop().await;
}

/// The AnLF restarts (no subscriptions). If it registers again under the same
/// instance id, the MTLF replaces the old registration. If it does not, the
/// MTLF's audit finds the subscription gone (404) and drops the registration.
#[tokio::test]
async fn an_anlf_restart_is_recovered() {
    let mut p = pair("retrain", "anlf-468q").await;
    let model_id = p
        .mtlf_ctx
        .read()
        .unwrap()
        .current_model_version()
        .unwrap()
        .unique_id();
    let held = register_at_mtlf(p.anlf, p.mtlf_addr(), model_id)
        .await
        .unwrap();
    until("subscribed", || {
        p.mtlf
            .registration(&held.id)
            .is_some_and(|r| r.anlf_subscription.is_some())
    })
    .await;

    // An idle registration whose AnLF is alive survives the audit.
    let base = unix_now();
    assert_eq!(audit_tick(p.mtlf, base + AUDIT_AFTER_SECS + 5).await, 0);
    assert!(p.mtlf.registration(&held.id).is_some());
    assert!(!p.mtlf.registration(&held.id).unwrap().auditing);

    // Restart without registering again: the next audit drops it.
    let anlf2 = p.restart_anlf("retrain", "anlf-468q");
    assert_eq!(
        audit_tick(p.mtlf, base + 2 * (AUDIT_AFTER_SECS + 5)).await,
        1
    );
    assert_eq!(p.mtlf.registration_count(), 0);
    assert!(p.mtlf.rolling_of(&held.id).is_none(), "its collector too");

    // Restart and register again: one registration, the new one.
    let a = register_at_mtlf(anlf2, p.mtlf_addr(), model_id)
        .await
        .unwrap();
    until("subscribed", || anlf2.subscription_count() == 1).await;
    let anlf3 = p.restart_anlf("retrain", "anlf-468q");
    let b = register_at_mtlf(anlf3, p.mtlf_addr(), model_id)
        .await
        .unwrap();
    assert_ne!(a.id, b.id);
    assert!(p.mtlf.registration(&a.id).is_none(), "replaced");
    assert!(p.mtlf.registration(&b.id).is_some());
    assert_eq!(p.mtlf.registration_count(), 1);
    p.stop().await;
}

/// A registration whose AnLF is gone (audits unanswered) expires.
#[tokio::test]
async fn a_dead_anlf_registration_expires() {
    let m = leak(Monitor::new(
        "retrain",
        Role::Mtlf,
        "http://m",
        "m",
        "http://n",
    ));
    let down = nextgcore_sbi::test_support::down_port();
    registered(m, "reg-dead", 9);
    lock(&m.registrations)
        .get_mut("reg-dead")
        .unwrap()
        .anlf_subscription = Some(("127.0.0.1".into(), down.addr().port(), "mmsub-1".into()));
    let base = unix_now();
    assert_eq!(audit_tick(m, base + AUDIT_AFTER_SECS + 1).await, 0);
    assert!(
        m.registration("reg-dead").is_some(),
        "unanswered is not 404"
    );
    assert_eq!(audit_tick(m, base + REGISTRATION_EXPIRY_SECS + 1).await, 1);
    assert!(m.registration("reg-dead").is_none());
    assert_eq!(lock(&m.feedback).collector_count(), 0);
}

// ── #1473 review, MINORs 3-6 ────────────────────────────────────────────────

/// MINOR 3: a Deregister while the MTLF's Subscribe is in flight leaves no
/// subscription at the AnLF.
#[tokio::test]
async fn a_deregister_during_the_subscribe_leaves_nothing() {
    let anlf_id = "anlf-468d";
    let ctx = context("mtlf-468d");
    let anlf = leak(Monitor::new(
        "retrain",
        Role::Anlf,
        "http://unused",
        anlf_id,
        "http://unused",
    ));
    let anlf_listener = nextgcore_sbi::test_support::bound_listener();
    let anlf_port = anlf_listener.port();
    let anlf_srv = nwdaf_on(anlf_listener, Arc::new(Mutex::new(anlf)), context(anlf_id)).await;
    // An NRF that answers discovery only when released.
    let asked = Arc::new(AtomicBool::new(false));
    let release = Arc::new(tokio::sync::Notify::new());
    let (a2, r2) = (asked.clone(), release.clone());
    let (nrf_srv, nrf_port) = serve(move |_req: SbiRequest| {
        let (asked, release) = (a2.clone(), r2.clone());
        async move {
            asked.store(true, Ordering::SeqCst);
            release.notified().await;
            let profile = json!({ "nfInstances": [{
                "nfInstanceId": anlf_id, "nfType": "NWDAF",
                "nfServices": [nf_service(anlf_id, "127.0.0.1", anlf_port)]
            }]});
            SbiResponse::with_status(200)
                .with_json_body(&profile)
                .unwrap()
        }
    })
    .await;
    let mtlf = leak(Monitor::new(
        "retrain",
        Role::Mtlf,
        "http://127.0.0.1:1",
        "mtlf-468d",
        &format!("http://127.0.0.1:{nrf_port}"),
    ));
    let model = ctx
        .read()
        .unwrap()
        .current_model_version()
        .unwrap()
        .unique_id();
    let r = handle_register(
        mtlf,
        &ctx.read().unwrap(),
        &post("/", json!({ "modelId": model, "consumerId": anlf_id })),
    );
    let reg = r
        .http
        .get_header("Location")
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();
    until("the Subscribe in flight", || asked.load(Ordering::SeqCst)).await;
    assert_eq!(handle_deregister(mtlf, &reg).status, 204);
    release.notify_one();
    until("the AnLF created the subscription", || {
        anlf.next_id.load(Ordering::SeqCst) >= 1
    })
    .await;
    until("and it was deleted again", || {
        anlf.subscription_count() == 0
    })
    .await;
    anlf_srv.stop().await.unwrap();
    nrf_srv.stop().await.unwrap();
}

/// MINOR 5: a report with one bad entry is refused whole; nothing is recorded.
#[test]
fn a_bad_entry_refuses_the_whole_report() {
    let m = leak(Monitor::new(
        "retrain",
        Role::Mtlf,
        "http://m",
        "m",
        "http://n",
    ));
    registered(m, "reg-5", 9);
    let t = m.token.clone();
    for bad in [
        json!({ "notifCorrId": "reg-5", "modelAccuInfos": [
            { "modelId": 9, "mlModelAcc": 90 }, { "modelId": 9, "mlModelAcc": 101 } ] }),
        json!({ "notifCorrId": "reg-5", "modelAccuInfos": [
            { "modelId": 9, "mlModelAcc": 90 }, { "mlModelAcc": 80 } ] }),
        json!({ "notifCorrId": "reg-5", "modelAccuInfos": [
            { "modelId": 9, "mlModelAcc": 90 }, { "modelId": 9, "mlModelAcc": "80" } ] }),
    ] {
        assert_eq!(
            handle_notify(Some(m), &t, &post("/", bad.clone())).status,
            400,
            "{bad}"
        );
    }
    assert_eq!(m.rolling_of("reg-5").unwrap().1, 0, "nothing half-applied");
    assert_eq!(m.counts().1, 0);
}

/// MINOR 6: a report must name a live registration (else 404, so the AnLF
/// registers again), only the registration's model counts, and a new
/// registration of the same model starts with a fresh latch.
#[test]
fn reports_are_bound_to_a_live_registration() {
    let m = leak(Monitor::new(
        "retrain",
        Role::Mtlf,
        "http://m",
        "m",
        "http://n",
    ));
    let t = m.token.clone();
    let low = |corr: &str| json!({ "notifCorrId": corr, "modelAccuInfos": [{ "modelId": 9, "mlModelAcc": 10 }] });
    assert_eq!(
        handle_notify(Some(m), &t, &post("/", low("reg-gone"))).status,
        404
    );
    registered(m, "reg-1", 9);
    let other =
        json!({ "notifCorrId": "reg-1", "modelAccuInfos": [{ "modelId": 8, "mlModelAcc": 10 }] });
    assert_eq!(handle_notify(Some(m), &t, &post("/", other)).status, 204);
    assert_eq!(
        m.rolling_of("reg-1").unwrap().1,
        0,
        "another model's entry is ignored"
    );
    for _ in 0..FEEDBACK_WINDOW {
        assert_eq!(
            handle_notify(Some(m), &t, &post("/", low("reg-1"))).status,
            204
        );
    }
    assert!(m.retrain_requested(9));

    // The AnLF re-registers (say, after a restart): the old registration is
    // gone, its reports are 404, and the new one has its own, unlatched,
    // collector.
    lock(&m.registrations).remove("reg-1");
    lock(&m.feedback).unregister_model("reg-1");
    assert_eq!(
        handle_notify(Some(m), &t, &post("/", low("reg-1"))).status,
        404
    );
    registered(m, "reg-2", 9);
    assert!(!m.retrain_requested(9), "a fresh latch");
    let mut crossed = 0;
    for _ in 0..FEEDBACK_WINDOW {
        handle_notify(Some(m), &t, &post("/", low("reg-2")));
        crossed += usize::from(m.retrain_requested(9));
    }
    assert!(crossed > 0, "the drop is requested again");
}

/// The MTLF learns whose ML-provision subscription it holds from the
/// `User-Agent` (TS 29.500 Table 5.2.2.2-1).
#[test]
fn the_consumer_is_read_from_the_user_agent() {
    let with = |ua: &str| {
        let mut r = SbiRequest::post("/");
        r.http.set_header("User-Agent", ua);
        crate::sbi_handler::nwdaf_consumer_of(&r)
    };
    assert_eq!(with("NWDAF-anlf-1").as_deref(), Some("anlf-1"));
    assert_eq!(with("nwdaf-x").as_deref(), Some("x"));
    assert_eq!(with("AMF-x"), None);
    assert_eq!(with("NWDAF-"), None);
    assert_eq!(
        crate::sbi_handler::nwdaf_consumer_of(&SbiRequest::post("/")),
        None
    );
}

/// MINOR 6, through the handlers: Deregister then Register of the same model
/// (an AnLF restart) starts with a fresh latch, so the next drop is requested
/// again.
#[tokio::test]
async fn a_new_registration_has_a_fresh_latch() {
    let ctx = context("latch-468");
    let down = nextgcore_sbi::test_support::down_port();
    let m = leak(Monitor::new(
        "retrain",
        Role::Mtlf,
        "http://m",
        "m",
        &format!("http://127.0.0.1:{}", down.addr().port()),
    ));
    let guard = ctx.read().unwrap();
    let model = guard.current_model_version().unwrap().unique_id();
    let register = || {
        let r = handle_register(
            m,
            &guard,
            &post("/", json!({ "modelId": model, "consumerId": "anlf-l" })),
        );
        assert_eq!(r.status, 201);
        r.http
            .get_header("Location")
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_string()
    };
    let t = m.token.clone();
    let drop_reports = |corr: &str| {
        for _ in 0..FEEDBACK_WINDOW {
            let low = json!({ "notifCorrId": corr,
                "modelAccuInfos": [{ "modelId": model, "mlModelAcc": 10 }] });
            assert_eq!(handle_notify(Some(m), &t, &post("/", low)).status, 204);
        }
    };
    let r1 = register();
    drop_reports(&r1);
    assert!(m.retrain_requested(model));
    assert_eq!(handle_deregister(m, &r1).status, 204);
    let r2 = register();
    assert!(!m.retrain_requested(model), "a fresh latch");
    drop_reports(&r2);
    assert!(m.retrain_requested(model), "requested again");
}
