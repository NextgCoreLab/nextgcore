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
        false,
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
        false,
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
        false,
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
            "nfServices": [nf_service(anlf_id, "127.0.0.1", anlf_port, nextgcore_sbi::types::UriScheme::Http)]
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
    // A plaintext stand-in NRF: the dev profile, or #1617's NRF client dials https.
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
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
            owner: None,
            create_key: None,
            subscribe_key: "k".into(),
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
            false,
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
    assert_eq!(
        handle_unsubscribe(m, &ok[0], &SbiRequest::delete("/"), false).status,
        204
    );
    let r = handle_subscribe(
        m,
        None,
        &post(
            "/",
            json!({ "modelIds": [1], "notificationUri": "http://m:1/cb", "notifCorrId": "c" }),
        ),
        false,
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
            false,
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
            false,
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
            false,
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
    // A plaintext stand-in NRF: the dev profile, or #1617's NRF client dials https.
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
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
                "nfServices": [nf_service(anlf_id, "127.0.0.1", anlf_port, nextgcore_sbi::types::UriScheme::Http)]
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
        false,
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
    assert_eq!(
        handle_deregister(mtlf, &reg, &SbiRequest::delete("/"), false).status,
        204
    );
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
            false,
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
    assert_eq!(
        handle_deregister(m, &r1, &SbiRequest::delete("/"), false).status,
        204
    );
    let r2 = register();
    assert!(!m.retrain_requested(model), "a fresh latch");
    drop_reports(&r2);
    assert!(m.retrain_requested(model), "requested again");
}

/// #1421: the server's OAuth2 callback exemption and the handler share
/// `holds_callback_token`; it admits an MTLF's own notificationUri token only.
#[test]
fn only_an_mtlfs_own_token_is_held() {
    let mtlf = Monitor::new("retrain", Role::Mtlf, "http://m", "m", "http://n");
    let anlf = Monitor::new("retrain", Role::Anlf, "http://a", "a", "http://n");
    assert!(holds_callback_token(Some(&mtlf), &mtlf.token));
    assert!(!holds_callback_token(Some(&mtlf), "nope"));
    assert!(!holds_callback_token(Some(&mtlf), &anlf.token));
    assert!(
        !holds_callback_token(Some(&anlf), &anlf.token),
        "an AnLF serves no notify"
    );
    assert!(!holds_callback_token(None, &mtlf.token));
}

// ── #1937: registrations and subscriptions are managed only by their owner ───

const OWNER_1937: &str = "aaaaaaaa-1937-4000-8000-00000000000a";
const OTHER_1937: &str = "bbbbbbbb-1937-4000-8000-00000000000b";
const SCP_1937: &str = "5c5c5c5c-1937-4000-8000-0000000005c9";

/// `request` from NF instance `id` over a direct mTLS connection.
fn direct_1937(mut request: SbiRequest, id: &str) -> SbiRequest {
    request.peer_cert_present = true;
    request.peer_cert_nf_instance_id = Some(id.to_string());
    request.peer_cert_nf_types = vec!["NWDAF".to_string()];
    request
}

/// `request` from NF instance `id` through an SCP: the SCP's certificate (a
/// relay), the consumer's verified access token.
fn via_scp_1937(mut request: SbiRequest, id: &str) -> SbiRequest {
    request.peer_cert_present = true;
    request.peer_cert_nf_instance_id = Some(SCP_1937.to_string());
    request.peer_cert_nf_types = vec!["SCP".to_string()];
    request.oauth2_subject = Some(id.to_string());
    request
}

/// The two ways [`OWNER_1937`] reaches this NWDAF, labelled.
fn owner_paths_1937() -> [(&'static str, fn(SbiRequest, &str) -> SbiRequest); 2] {
    [("direct", direct_1937), ("via SCP", via_scp_1937)]
}

/// Every caller that is not [`OWNER_1937`], each labelled.
fn strangers_1937(request: impl Fn() -> SbiRequest) -> Vec<(&'static str, SbiRequest)> {
    let mut mismatch = direct_1937(request(), OWNER_1937);
    mismatch.oauth2_subject = Some(OTHER_1937.to_string());
    let mut scp_alone = via_scp_1937(request(), OWNER_1937);
    scp_alone.oauth2_subject = None;
    vec![
        ("a foreign certificate", direct_1937(request(), OTHER_1937)),
        (
            "a foreign token via an SCP",
            via_scp_1937(request(), OTHER_1937),
        ),
        ("the owner's certificate with a foreign token", mismatch),
        ("an SCP certificate and no token", scp_alone),
        ("an anonymous caller", request()),
    ]
}

/// A peer that counts the connections made to it (an outbound call made).
async fn counting_peer() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let h = hits.clone();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = l.accept().await {
            h.fetch_add(1, Ordering::SeqCst);
            held.push(s);
        }
    });
    (port, hits)
}

fn location_id(r: &SbiResponse) -> String {
    r.http
        .get_header("Location")
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string()
}

/// An MTLF whose AnLF discovery never succeeds (its NRF is down), so the only
/// outbound call a test can see is the Unsubscribe of a Deregister.
fn mtlf_1937() -> (&'static Monitor, Ctx, u64) {
    let ctx = context("mtlf-1937");
    let down = nextgcore_sbi::test_support::down_port();
    let m = leak(Monitor::new(
        "retrain",
        Role::Mtlf,
        "http://m",
        "mtlf-1937",
        &format!("http://127.0.0.1:{}", down.addr().port()),
    ));
    std::mem::forget(down);
    let model = ctx
        .read()
        .unwrap()
        .current_model_version()
        .unwrap()
        .unique_id();
    (m, ctx, model)
}

/// #1937, the MTLF as producer: a registration is bound at Register to the
/// AnLF that made it (direct: its certificate; through an SCP: its token), and
/// only that AnLF deregisters it. Every stranger gets 403 and changes nothing:
/// the registration, its collector and the counters are as they were and no
/// Unsubscribe reaches the AnLF. A stranger cannot register in the owner's name,
/// nor displace the owner's registration.
///
/// REVERT-VERIFIED: the Deregister owner check skipped ("must not deregister");
/// the owner not recorded at Register ("bound to the registering AnLF"); the
/// consumerId check skipped ("may not register as"); the replacement not scoped
/// to the owner ("is not displaced").
#[tokio::test]
async fn mtlf_registrations_are_deregistered_only_by_their_owner_1937() {
    // The owner's Unsubscribe is plaintext to a loopback peer (the positive
    // control); the owner rule itself is the explicit `required` below.
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let (m, ctx, model) = mtlf_1937();
    let (anlf_port, unsubscribes) = counting_peer().await;
    let body = || json!({ "modelId": model, "consumerId": OWNER_1937 });
    let route_now = |method: &str, rest: &[&str], req: &SbiRequest| {
        route_with(Some(m), &ctx, method, rest, req, true)
    };
    for (path, as_owner) in owner_paths_1937() {
        let r = route_now(
            "POST",
            &["registrations"],
            &as_owner(post("/", body()), OWNER_1937),
        );
        assert_eq!(r.status, 201, "{path}");
        let id = location_id(&r);
        assert_eq!(
            m.registration(&id).unwrap().owner.as_deref(),
            Some(OWNER_1937),
            "{path}: bound to the registering AnLF"
        );
        lock(&m.registrations)
            .get_mut(&id)
            .unwrap()
            .anlf_subscription = Some(("127.0.0.1".into(), anlf_port, format!("sub-{path}")));
        let before = m.registration(&id).unwrap();
        let collectors = lock(&m.feedback).collector_count();

        // Nobody else registers in the owner's name or displaces it.
        for (who, req) in strangers_1937(|| post("/", body())) {
            let r = route_now("POST", &["registrations"], &req);
            assert_eq!(
                r.status, 403,
                "{path}: {who} may not register as {OWNER_1937}"
            );
        }
        assert_eq!(m.registration_count(), 1, "{path}: nothing stored");

        for (who, req) in strangers_1937(|| SbiRequest::delete("/")) {
            let r = route_now("DELETE", &["registrations", &id], &req);
            assert_eq!(r.status, 403, "{path}: {who} must not deregister");
            assert_eq!(m.registration(&id).as_ref(), Some(&before), "{path}: {who}");
        }
        assert_eq!(lock(&m.feedback).collector_count(), collectors, "{path}");
        assert_eq!(m.counts(), (0, 0), "{path}");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            unsubscribes.load(Ordering::SeqCst),
            0,
            "{path}: a refused Deregister sent no Unsubscribe to the AnLF"
        );

        // The owner deregisters, by either path; the Unsubscribe goes out once.
        let (_, other_path) = owner_paths_1937()
            .into_iter()
            .find(|(p, _)| *p != path)
            .unwrap();
        let r = route_now(
            "DELETE",
            &["registrations", &id],
            &other_path(SbiRequest::delete("/"), &OWNER_1937.to_uppercase()),
        );
        assert_eq!(r.status, 204, "{path}: the owner deregisters");
        assert!(m.registration(&id).is_none());
        until("the Unsubscribe at the AnLF", || {
            unsubscribes.load(Ordering::SeqCst) == 1
        })
        .await;
        // A retried Deregister: 404, no second Unsubscribe.
        let r = route_now(
            "DELETE",
            &["registrations", &id],
            &as_owner(SbiRequest::delete("/"), OWNER_1937),
        );
        assert_eq!(r.status, 404, "{path}: a retry finds it gone");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(unsubscribes.swap(0, Ordering::SeqCst), 1, "{path}");
    }

    // A Register from the same consumerId and modelId replaces only a
    // registration of the same owner (dev: an anonymous one may not displace a
    // bound one).
    let r = route_now(
        "POST",
        &["registrations"],
        &direct_1937(post("/", body()), OWNER_1937),
    );
    let bound = location_id(&r);
    let r = route_with(
        Some(m),
        &ctx,
        "POST",
        &["registrations"],
        &post("/", body()),
        false,
    );
    assert_eq!(r.status, 201);
    assert!(
        m.registration(&bound).is_some(),
        "the owner's registration is not displaced by another's Register"
    );
    // The owner registering again does replace its own (idempotent retry).
    let r = route_now(
        "POST",
        &["registrations"],
        &via_scp_1937(post("/", body()), OWNER_1937),
    );
    assert_eq!(r.status, 201);
    assert!(m.registration(&bound).is_none(), "replaced by its owner");
    assert_eq!(
        m.registration_count(),
        2,
        "the owner's one, and the anonymous one"
    );
}

/// #1937, the AnLF as producer: a subscription is bound at Subscribe to the MTLF
/// that made it, and only that MTLF updates (`PUT`) or deletes it, directly or
/// through an SCP. A stranger's `PUT` is refused before its body is read.
/// Retries by the owner are idempotent.
///
/// REVERT-VERIFIED: the `PUT` owner check skipped ("must not update"); the
/// Unsubscribe owner check skipped ("must not unsubscribe"); the owner not
/// recorded at Subscribe ("bound to the subscribing MTLF").
#[test]
fn anlf_subscriptions_are_managed_only_by_their_mtlf_1937() {
    let ctx = context("anlf-1937");
    let m = leak(Monitor::new(
        "retrain",
        Role::Anlf,
        "http://a",
        "anlf-1937",
        "http://n",
    ));
    let body = |uri: &str| {
        json!({
            "modelIds": [7], "notificationUri": uri, "notifCorrId": "reg-1937",
            "eventReportReq": { "notifMethod": "PERIODIC", "repPeriod": 30 }
        })
    };
    let route_now = |method: &str, rest: &[&str], req: &SbiRequest| {
        route_with(Some(m), &ctx, method, rest, req, true)
    };
    for (path, as_owner) in owner_paths_1937() {
        let r = route_now(
            "POST",
            &["subscriptions"],
            &as_owner(post("/", body("http://mtlf.example/cb")), OWNER_1937),
        );
        assert_eq!(r.status, 201, "{path}");
        let id = location_id(&r);
        assert_eq!(
            m.subscription(&id).unwrap().owner.as_deref(),
            Some(OWNER_1937),
            "{path}: bound to the subscribing MTLF"
        );
        let before = m.subscription(&id).unwrap();

        let put = || post("/", body("http://attacker.example/cb"));
        for (who, mut req) in strangers_1937(put) {
            req.header.method = "PUT".into();
            let r = route_now("PUT", &["subscriptions", &id], &req);
            assert_eq!(r.status, 403, "{path}: {who} must not update");
            assert_eq!(m.subscription(&id).as_ref(), Some(&before), "{path}: {who}");
        }
        // Refused before the body is read: a malformed body is still a 403.
        let r = route_now(
            "PUT",
            &["subscriptions", &id],
            &direct_1937(SbiRequest::put("/"), OTHER_1937),
        );
        assert_eq!(r.status, 403, "{path}");
        for (who, req) in strangers_1937(|| SbiRequest::delete("/")) {
            let r = route_now("DELETE", &["subscriptions", &id], &req);
            assert_eq!(r.status, 403, "{path}: {who} must not unsubscribe");
            assert_eq!(m.subscription(&id).as_ref(), Some(&before), "{path}: {who}");
        }
        assert_eq!(m.subscription_count(), 1, "{path}");

        // The owner updates, twice (a retry): one record, same state, owner kept.
        let mut states = Vec::new();
        for _ in 0..2 {
            let r = route_now(
                "PUT",
                &["subscriptions", &id],
                &as_owner(post("/", body("http://mtlf.example/cb2")), OWNER_1937),
            );
            assert_eq!(r.status, 200, "{path}: the owner updates");
            states.push(m.subscription(&id).unwrap());
        }
        assert_eq!(
            states[0], states[1],
            "{path}: a retried update is idempotent"
        );
        assert_eq!(states[0].notification_uri, "http://mtlf.example/cb2");
        assert_eq!(states[0].owner.as_deref(), Some(OWNER_1937), "{path}");
        assert_eq!(m.subscription_count(), 1, "{path}");

        let del = || as_owner(SbiRequest::delete("/"), OWNER_1937);
        assert_eq!(
            route_now("DELETE", &["subscriptions", &id], &del()).status,
            204
        );
        assert_eq!(
            route_now("DELETE", &["subscriptions", &id], &del()).status,
            404
        );
        assert_eq!(m.subscription_count(), 0, "{path}");
    }
}

/// #1937: an ownerless registration or subscription (created with no verified
/// identity, which only the `dev` profile allows) is open under `dev` and
/// frozen under `production`, for every caller; and `production` refuses the
/// anonymous create outright, storing nothing.
///
/// REVERT-VERIFIED: `route_with` passing `false` whatever `required` is
/// ("frozen under production", "refused under production").
#[tokio::test]
async fn ownerless_records_are_frozen_under_production_1937() {
    let (mtlf, ctx, model) = mtlf_1937();
    let anlf = leak(Monitor::new(
        "retrain",
        Role::Anlf,
        "http://a",
        "anlf-1937f",
        "http://n",
    ));
    let reg_body = || post("/", json!({ "modelId": model, "consumerId": OWNER_1937 }));
    let sub_body = || {
        post(
            "/",
            json!({ "modelIds": [7], "notificationUri": "http://m.example/cb", "notifCorrId": "c" }),
        )
    };
    // Production: an anonymous create is refused and nothing is stored.
    for (m, rest, req) in [
        (mtlf, "registrations", reg_body()),
        (anlf, "subscriptions", sub_body()),
    ] {
        let r = route_with(Some(m), &ctx, "POST", &[rest], &req, true);
        assert_eq!(
            r.status, 403,
            "{rest}: an anonymous create is refused under production"
        );
    }
    assert_eq!(
        (mtlf.registration_count(), anlf.subscription_count()),
        (0, 0)
    );

    // Dev: created ownerless.
    let reg = location_id(&route_with(
        Some(mtlf),
        &ctx,
        "POST",
        &["registrations"],
        &reg_body(),
        false,
    ));
    let sub = location_id(&route_with(
        Some(anlf),
        &ctx,
        "POST",
        &["subscriptions"],
        &sub_body(),
        false,
    ));
    assert_eq!(mtlf.registration(&reg).unwrap().owner, None);
    assert_eq!(anlf.subscription(&sub).unwrap().owner, None);
    let (reg_before, sub_before) = (mtlf.registration(&reg), anlf.subscription(&sub));

    // Production: frozen for everyone, the would-be owner included.
    let mut everyone = strangers_1937(SbiRequest::new);
    for (path, as_owner) in owner_paths_1937() {
        everyone.push((path, as_owner(SbiRequest::new(), OWNER_1937)));
    }
    for (who, mut req) in everyone {
        req.http.content = Some(sub_body().http.content.unwrap());
        let r = route_with(
            Some(mtlf),
            &ctx,
            "DELETE",
            &["registrations", &reg],
            &req,
            true,
        );
        assert_eq!(
            r.status, 403,
            "{who}: an ownerless registration is frozen under production"
        );
        for method in ["PUT", "DELETE"] {
            let r = route_with(
                Some(anlf),
                &ctx,
                method,
                &["subscriptions", &sub],
                &req,
                true,
            );
            assert_eq!(
                r.status, 403,
                "{who} {method}: an ownerless subscription is frozen under production"
            );
        }
    }
    assert_eq!(mtlf.registration(&reg), reg_before);
    assert_eq!(anlf.subscription(&sub), sub_before);

    // Dev: open to anyone, as before the binding.
    let del = SbiRequest::delete("/");
    assert_eq!(
        route_with(
            Some(mtlf),
            &ctx,
            "DELETE",
            &["registrations", &reg],
            &del,
            false
        )
        .status,
        204
    );
    assert_eq!(
        route_with(
            Some(anlf),
            &ctx,
            "DELETE",
            &["subscriptions", &sub],
            &del,
            false
        )
        .status,
        204
    );
}

// ── #2048: duplicate detection of creates (TS 29.500 §5.2.8) ────────────────

/// `request` carrying `3gpp-Sbi-Request-Info: idempotency-key=<key>`.
fn keyed_2048(request: SbiRequest, key: &str) -> SbiRequest {
    request.with_header(
        nextgcore_sbi::constants::custom_header::REQUEST_INFO,
        request_info(key, false),
    )
}

fn json_of(r: &SbiResponse) -> Value {
    serde_json::from_str(r.http.content.as_deref().unwrap_or("null")).unwrap()
}

/// #2048, the AnLF as producer: a keyed `POST /subscriptions` retransmitted
/// (its 201 lost) answers the subscription it created, 201 with the same
/// Location and the resource as it is now, and creates nothing. The replay is
/// scoped to the same owner (on either path), key and body, inside
/// [`IDEMPOTENCY_WINDOW_SECS`]; a deleted subscription is not resurrected; a
/// rejected create records nothing; a replay at the cap is answered, not
/// refused, and the cap still holds for new keys.
///
/// REVERT-VERIFIED: the replay lookup skipped ("a retransmission answers the
/// same Location"); the owner not compared ("another owner's retry creates
/// its own"); the body not compared ("a different body creates its own"); the
/// window not applied ("an expired key creates a new one"); the replay after
/// the cap check ("a retry at the cap is answered"); a malformed key accepted
/// ("a malformed key is 400"); the record not kept on update ("a retry after an
/// update answers the updated resource").
#[test]
fn anlf_subscribe_replays_a_retransmitted_create_2048() {
    let ctx = context("anlf-2048");
    let m = leak(
        Monitor::new("retrain", Role::Anlf, "http://a", "anlf-2048", "http://n")
            .with_limits(8, NOTIFY_BUDGET),
    );
    let body = |uri: &str| {
        json!({
            "modelIds": [7], "notificationUri": uri, "notifCorrId": "reg-2048",
            "eventReportReq": { "notifMethod": "PERIODIC", "repPeriod": 30 }
        })
    };
    let subscribe =
        |req: SbiRequest| route_with(Some(m), &ctx, "POST", &["subscriptions"], &req, true);
    let as_owner = |b: Value, key: &str| direct_1937(keyed_2048(post("/", b), key), OWNER_1937);

    let first = subscribe(as_owner(body("http://mtlf.example/cb"), "k-1"));
    assert_eq!(first.status, 201);
    let id = location_id(&first);
    let minted = m.next_id.load(Ordering::SeqCst);
    for (path, owner) in owner_paths_1937() {
        let retry = subscribe(owner(
            keyed_2048(post("/", body("http://mtlf.example/cb")), "k-1"),
            OWNER_1937,
        ));
        assert_eq!(retry.status, 201, "{path}");
        assert_eq!(
            retry.http.get_header("Location"),
            first.http.get_header("Location"),
            "{path}: a retransmission answers the same Location"
        );
        assert_eq!(
            json_of(&retry),
            json_of(&first),
            "{path}: and the same body"
        );
    }
    // The same JSON with its members in another order is the same body.
    let reordered = SbiRequest::post("/").with_body(
        r#"{"eventReportReq":{"repPeriod":30,"notifMethod":"PERIODIC"},"notifCorrId":"reg-2048","notificationUri":"http://mtlf.example/cb","modelIds":[7]}"#,
        "application/json",
    );
    assert_eq!(
        location_id(&subscribe(direct_1937(
            keyed_2048(reordered, "k-1"),
            OWNER_1937
        ))),
        id
    );
    assert_eq!(m.subscription_count(), 1, "one subscription");
    assert_eq!(m.next_id.load(Ordering::SeqCst), minted, "no id minted");

    // Another owner, the same key and body: its own subscription.
    let other = subscribe(direct_1937(
        keyed_2048(post("/", body("http://mtlf.example/cb")), "k-1"),
        OTHER_1937,
    ));
    assert_eq!(other.status, 201);
    assert_ne!(
        location_id(&other),
        id,
        "another owner's retry creates its own"
    );
    // The same owner and key, another body: its own subscription.
    let changed = subscribe(as_owner(body("http://mtlf.example/other"), "k-1"));
    assert_eq!(changed.status, 201);
    assert_ne!(
        location_id(&changed),
        id,
        "a different body creates its own"
    );
    // No key: the duplicate detection is optional (§5.2.8), nothing is merged.
    let plain = || direct_1937(post("/", body("http://mtlf.example/cb")), OWNER_1937);
    assert_ne!(
        location_id(&subscribe(plain())),
        location_id(&subscribe(plain()))
    );
    assert_eq!(m.subscription_count(), 5);

    // A rejected create records nothing: a bad body, a malformed key, an
    // anonymous caller under production (403). The key is still unused after.
    let bad = subscribe(direct_1937(
        keyed_2048(post("/", json!({ "modelIds": [] })), "k-2"),
        OWNER_1937,
    ));
    assert_eq!(bad.status, 400);
    let long = format!(
        "idempotency-key={}",
        "x".repeat(MAX_IDEMPOTENCY_KEY_LEN + 1)
    );
    for malformed in ["idempotency-key=", long.as_str()] {
        let r = subscribe(direct_1937(
            post("/", body("http://mtlf.example/k2")).with_header(
                nextgcore_sbi::constants::custom_header::REQUEST_INFO,
                malformed,
            ),
            OWNER_1937,
        ));
        assert_eq!(r.status, 400, "a malformed key is 400");
    }
    let anonymous = subscribe(keyed_2048(post("/", body("http://mtlf.example/k2")), "k-2"));
    assert_eq!(anonymous.status, 403);
    assert_eq!(
        m.subscription_count(),
        5,
        "a rejected create applies nothing"
    );
    let k2 = subscribe(as_owner(body("http://mtlf.example/k2"), "k-2"));
    assert_eq!(k2.status, 201);
    let k2_id = location_id(&k2);
    assert!(![id.as_str(), &location_id(&other), &location_id(&changed)].contains(&k2_id.as_str()));

    // An update keeps the record: a late retry answers the resource as it is.
    let mut put = direct_1937(post("/", body("http://mtlf.example/moved")), OWNER_1937);
    put.header.method = "PUT".into();
    assert_eq!(
        route_with(Some(m), &ctx, "PUT", &["subscriptions", &id], &put, true).status,
        200
    );
    let late = subscribe(as_owner(body("http://mtlf.example/cb"), "k-1"));
    assert_eq!(
        location_id(&late),
        id,
        "a retry after an update answers the updated resource"
    );
    assert_eq!(
        json_of(&late)["notificationUri"],
        "http://mtlf.example/moved"
    );

    // At the cap: a replay is answered; a new key is refused and stores nothing.
    for i in 0..2 {
        assert_eq!(
            subscribe(as_owner(
                body(&format!("http://fill{i}.example/cb")),
                &format!("f-{i}")
            ))
            .status,
            201
        );
    }
    assert_eq!(m.subscription_count(), 8);
    let at_cap = subscribe(as_owner(body("http://mtlf.example/k2"), "k-2"));
    assert_eq!(at_cap.status, 201, "a retry at the cap is answered");
    assert_eq!(location_id(&at_cap), k2_id);
    let full = subscribe(as_owner(body("http://mtlf.example/new"), "k-3"));
    assert_eq!(full.status, 500);
    assert_eq!(cause(&full).as_deref(), Some(INSUFFICIENT_RESOURCES));
    assert_eq!(m.subscription_count(), 8);

    // A deleted subscription is not resurrected by a retry of its create.
    let del = direct_1937(SbiRequest::delete("/"), OWNER_1937);
    assert_eq!(handle_unsubscribe(m, &k2_id, &del, true).status, 204);
    let after = subscribe(as_owner(body("http://mtlf.example/k2"), "k-2"));
    assert_eq!(after.status, 201);
    assert_ne!(
        location_id(&after),
        k2_id,
        "a deleted subscription stays deleted"
    );
    assert!(m.subscription(&k2_id).is_none());

    // Past the window a key is expired: the retry creates a new subscription.
    m.age_create_keys_for_test(IDEMPOTENCY_WINDOW_SECS - 1);
    assert_eq!(
        location_id(&subscribe(as_owner(body("http://mtlf.example/k2"), "k-2"))),
        location_id(&after),
        "inside the window it still replays"
    );
    // (Make room: the expired retry must be a create, not a 500.)
    let theirs = direct_1937(SbiRequest::delete("/"), OTHER_1937);
    assert_eq!(
        handle_unsubscribe(m, &location_id(&other), &theirs, true).status,
        204
    );
    m.age_create_keys_for_test(1);
    let expired = subscribe(as_owner(body("http://mtlf.example/k2"), "k-2"));
    assert_eq!(expired.status, 201);
    assert_ne!(
        location_id(&expired),
        location_id(&after),
        "an expired key creates a new one"
    );
}

/// #2048: concurrent retransmissions of one keyed create make one subscription,
/// and every one of them is answered its Location. The handler checks and
/// inserts under one lock with no await in between, so there is no in-flight
/// window at the AnLF.
///
/// REVERT-VERIFIED: the replay lookup skipped ("one subscription").
#[test]
fn concurrent_retransmissions_make_one_subscription_2048() {
    let m = leak(Monitor::new(
        "retrain",
        Role::Anlf,
        "http://a",
        "a",
        "http://n",
    ));
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let req = keyed_2048(
                    post(
                        "/",
                        json!({ "modelIds": [7], "notificationUri": "http://m.example/cb", "notifCorrId": "c" }),
                    ),
                    "k-concurrent",
                );
                barrier.wait();
                let r = handle_subscribe(m, None, &req, false);
                assert_eq!(r.status, 201);
                location_id(&r)
            })
        })
        .collect();
    let ids: std::collections::HashSet<String> =
        threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(m.subscription_count(), 1, "one subscription");
    assert_eq!(ids.len(), 1, "one Location for all");
}

/// #2048, the MTLF as producer: a keyed Register retransmitted answers the
/// registration it created (same Location and body) and replaces nothing,
/// spawns nothing, adds no collector. Scoped to the owner, key and body inside
/// the window; a deregistered registration is not resurrected; a rejected
/// Register records nothing.
///
/// REVERT-VERIFIED: the replay lookup skipped ("the same registration").
#[tokio::test]
async fn mtlf_register_replays_a_retransmitted_create_2048() {
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let (m, ctx, model) = mtlf_1937();
    let guard = ctx.read().unwrap();
    let reg = |req: SbiRequest| handle_register(m, &guard, &req, true);
    let own = json!({ "modelId": model, "consumerId": OWNER_1937 });
    let set = json!({ "modelId": model, "consumerSetId": "set-2048" });
    let as_owner =
        |b: &Value, key: &str| direct_1937(keyed_2048(post("/", b.clone()), key), OWNER_1937);

    let first = reg(as_owner(&own, "r-1"));
    assert_eq!(first.status, 201);
    let id = location_id(&first);
    let minted = m.next_id.load(Ordering::SeqCst);
    for (path, owner) in owner_paths_1937() {
        let retry = reg(owner(keyed_2048(post("/", own.clone()), "r-1"), OWNER_1937));
        assert_eq!(location_id(&retry), id, "{path}: the same registration");
        assert_eq!(json_of(&retry), json_of(&first), "{path}");
    }
    assert_eq!(m.registration_count(), 1);
    assert_eq!(lock(&m.feedback).collector_count(), 1, "no collector added");
    assert_eq!(
        m.next_id.load(Ordering::SeqCst),
        minted,
        "nothing new created"
    );
    assert_eq!(m.counts(), (0, 0));

    // Another owner (a consumerSetId body, so it may), or another body: new.
    let theirs = reg(direct_1937(
        keyed_2048(post("/", set.clone()), "r-1"),
        OTHER_1937,
    ));
    let mine = reg(as_owner(&set, "r-1"));
    assert_eq!((theirs.status, mine.status), (201, 201));
    assert_ne!(location_id(&theirs), location_id(&mine));
    assert!(![location_id(&theirs), location_id(&mine)].contains(&id));
    assert_eq!(m.registration_count(), 3);

    // Rejected: an impersonating consumerId (403), a malformed key (400).
    let other_id = json!({ "modelId": model, "consumerId": OTHER_1937 });
    assert_eq!(reg(as_owner(&other_id, "r-2")).status, 403);
    let bad_key = direct_1937(
        post("/", set.clone()).with_header(
            nextgcore_sbi::constants::custom_header::REQUEST_INFO,
            "idempotency-key=",
        ),
        OWNER_1937,
    );
    assert_eq!(reg(bad_key).status, 400);
    assert_eq!(
        m.registration_count(),
        3,
        "a rejected Register applies nothing"
    );

    // A deregistered registration is not resurrected.
    let del = direct_1937(SbiRequest::delete("/"), OWNER_1937);
    assert_eq!(
        handle_deregister(m, &location_id(&mine), &del, true).status,
        204
    );
    let again = reg(as_owner(&set, "r-1"));
    assert_eq!(again.status, 201);
    assert_ne!(
        location_id(&again),
        location_id(&mine),
        "stays deregistered"
    );
    assert!(m.registration(&location_id(&mine)).is_none());

    // Past the window: a new registration (which replaces the same consumer's).
    m.age_create_keys_for_test(IDEMPOTENCY_WINDOW_SECS);
    let expired = reg(as_owner(&own, "r-1"));
    assert_eq!(expired.status, 201);
    assert_ne!(location_id(&expired), id, "an expired key registers anew");
    assert!(m.registration(&id).is_none(), "and replaces the old one");
}

/// #2048: a stand-in peer in front of a real NWDAF's MLModelMonitor routes.
/// It records the `3gpp-Sbi-Request-Info` of every `POST /<collection>`; with
/// `hold` it holds the first one until `release`, and with `lose_first` it
/// processes the first one and then answers 500, as if its 201 were lost.
struct Creates {
    infos: Arc<Mutex<Vec<String>>>,
    arrived: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

impl Creates {
    fn infos(&self) -> Vec<String> {
        self.infos.lock().unwrap().clone()
    }
}

async fn creates_peer(
    m: &'static Monitor,
    ctx: Ctx,
    collection: &'static str,
    hold: bool,
    lose_first: bool,
) -> (nextgcore_sbi::SbiServer, u16, Creates) {
    let creates = Creates {
        infos: Arc::default(),
        arrived: Arc::default(),
        release: Arc::default(),
    };
    let (infos, arrived, release) = (
        creates.infos.clone(),
        creates.arrived.clone(),
        creates.release.clone(),
    );
    let (srv, port) = serve(move |req: SbiRequest| {
        let (ctx, infos, arrived, release) =
            (ctx.clone(), infos.clone(), arrived.clone(), release.clone());
        async move {
            let p = parts(&req);
            let p: Vec<&str> = p.iter().map(String::as_str).collect();
            let method = req.header.method.clone();
            let ["nnwdaf-mlmodelmonitor", "v1", rest @ ..] = p.as_slice() else {
                return SbiResponse::with_status(404);
            };
            if method != "POST" || rest != [collection] {
                return route(Some(m), &ctx, &method, rest, &req);
            }
            let n = {
                let mut infos = infos.lock().unwrap();
                infos.push(
                    req.http
                        .get_header(nextgcore_sbi::constants::custom_header::REQUEST_INFO)
                        .cloned()
                        .unwrap_or_default(),
                );
                infos.len()
            };
            arrived.notify_one();
            if hold && n == 1 {
                release.notified().await;
            }
            let r = route(Some(m), &ctx, &method, rest, &req);
            if lose_first && n == 1 {
                return SbiResponse::with_status(500);
            }
            r
        }
    })
    .await;
    (srv, port, creates)
}

/// #2048, cancellation and both peers: an AnLF retries its Register while the
/// MTLF's Subscribe for it is still in flight at the AnLF (held by the seam).
/// The retry is answered the same registration and the counting AnLF sees one
/// Subscribe, before and after the first one completes, carrying the
/// registration's key; the MTLF records that one subscription.
///
/// REVERT-VERIFIED: the MTLF replay lookup skipped ("one Subscribe at the
/// AnLF", the retry's replacement and second Subscribe); the Subscribe's key
/// header not sent ("carries the registration's key").
#[tokio::test]
async fn a_register_retried_during_its_subscribe_makes_one_subscribe_2048() {
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let anlf = leak(Monitor::new(
        "retrain",
        Role::Anlf,
        "http://unused",
        OWNER_1937,
        "http://unused",
    ));
    let (anlf_srv, anlf_port, subscribes) =
        creates_peer(anlf, context(OWNER_1937), "subscriptions", true, false).await;
    let (nrf_srv, nrf_port) = nrf(OWNER_1937, anlf_port).await;
    let ctx = context("mtlf-2048");
    let mtlf = leak(Monitor::new(
        "retrain",
        Role::Mtlf,
        "http://127.0.0.1:1",
        "mtlf-2048",
        &format!("http://127.0.0.1:{nrf_port}"),
    ));
    let model = ctx
        .read()
        .unwrap()
        .current_model_version()
        .unwrap()
        .unique_id();
    let register = || {
        let req = direct_1937(
            keyed_2048(
                post("/", json!({ "modelId": model, "consumerId": OWNER_1937 })),
                "r-flight",
            ),
            OWNER_1937,
        );
        handle_register(mtlf, &ctx.read().unwrap(), &req, true)
    };
    let first = register();
    assert_eq!(first.status, 201);
    let id = location_id(&first);
    tokio::time::timeout(Duration::from_secs(10), subscribes.arrived.notified())
        .await
        .expect("the Subscribe reached the AnLF");

    // The Subscribe is in flight: the retry finds the registration.
    let retry = register();
    assert_eq!(
        location_id(&retry),
        id,
        "the retry finds the in-flight registration"
    );
    assert_eq!(json_of(&retry), json_of(&first));
    assert_eq!(mtlf.registration_count(), 1);
    assert!(mtlf.registration(&id).unwrap().anlf_subscription.is_none());

    subscribes.release.notify_one();
    until("the MTLF recorded the subscription", || {
        mtlf.registration(&id)
            .is_some_and(|r| r.anlf_subscription.is_some())
    })
    .await;
    assert_eq!(subscribes.infos().len(), 1, "one Subscribe at the AnLF");
    assert_eq!(anlf.subscription_count(), 1);
    let reg = mtlf.registration(&id).unwrap();
    assert_eq!(
        subscribes.infos()[0],
        request_info(&reg.subscribe_key, false),
        "carries the registration's key"
    );
    let (_, _, sub) = reg.anlf_subscription.unwrap();
    assert_eq!(anlf.subscription(&sub).unwrap().notif_corr_id, id);
    anlf_srv.stop().await.unwrap();
    nrf_srv.stop().await.unwrap();
}

/// #2048, the MTLF as client: its Subscribe is processed by the AnLF but the
/// 201 is lost (the seam answers 500). The retry carries the same key with
/// `retrans=true`, the AnLF answers the subscription it created, and the AnLF
/// holds one subscription, the one the MTLF records.
///
/// REVERT-VERIFIED: the AnLF replay lookup skipped, or a new key per attempt
/// ("one subscription at the AnLF").
#[tokio::test]
async fn a_subscribe_retried_after_a_lost_201_is_one_subscription_2048() {
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    const ANLF: &str = "cccccccc-2048-4000-8000-00000000000c";
    let anlf = leak(Monitor::new(
        "retrain",
        Role::Anlf,
        "http://unused",
        ANLF,
        "http://unused",
    ));
    let (anlf_srv, anlf_port, subscribes) =
        creates_peer(anlf, context(ANLF), "subscriptions", false, true).await;
    let (nrf_srv, nrf_port) = nrf(ANLF, anlf_port).await;
    let ctx = context("mtlf-2048l");
    let mtlf = leak(Monitor::new(
        "retrain",
        Role::Mtlf,
        "http://127.0.0.1:1",
        "mtlf-2048l",
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
        &post("/", json!({ "modelId": model, "consumerId": ANLF })),
        false,
    );
    let id = location_id(&r);
    until("the MTLF recorded the subscription", || {
        mtlf.registration(&id)
            .is_some_and(|r| r.anlf_subscription.is_some())
    })
    .await;
    let key = mtlf.registration(&id).unwrap().subscribe_key;
    assert_eq!(
        subscribes.infos(),
        vec![request_info(&key, false), request_info(&key, true)],
        "the retry carries the same key, marked retransmitted"
    );
    assert_eq!(anlf.subscription_count(), 1, "one subscription at the AnLF");
    let (_, _, sub) = mtlf.registration(&id).unwrap().anlf_subscription.unwrap();
    assert!(
        anlf.subscription(&sub).is_some(),
        "the one the MTLF records"
    );
    anlf_srv.stop().await.unwrap();
    nrf_srv.stop().await.unwrap();
}

/// #2048, the AnLF as client: its Register is processed by the MTLF but the
/// 201 is lost. The next Register carries the same key with `retrans=true`
/// and gets the registration already created, so the MTLF holds one and the
/// AnLF holds that one. Once answered, a later Register uses a fresh key.
///
/// REVERT-VERIFIED: the key not reused ("the same registration"); the pending
/// key not cleared on a 201 ("a later Register uses a fresh key").
#[tokio::test]
async fn a_register_retried_after_a_lost_201_is_one_registration_2048() {
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let (mtlf, ctx, model) = mtlf_1937();
    let (mtlf_srv, mtlf_port, registers) =
        creates_peer(mtlf, ctx, "registrations", false, true).await;
    let anlf = leak(Monitor::new(
        "retrain",
        Role::Anlf,
        "http://unused",
        "anlf-2048r",
        "http://unused",
    ));
    let at = ("127.0.0.1".to_string(), mtlf_port);
    assert!(register_at_mtlf(anlf, at.clone(), model).await.is_err());
    assert_eq!(mtlf.registration_count(), 1, "the lost 201's registration");
    let created = lock(&mtlf.registrations).keys().next().unwrap().clone();
    let held = register_at_mtlf(anlf, at.clone(), model).await.unwrap();
    assert_eq!(held.id, created, "the same registration");
    assert_eq!(mtlf.registration_count(), 1);
    let infos = registers.infos();
    let key = infos[0].trim_start_matches("idempotency-key=").to_string();
    assert_eq!(
        infos,
        vec![request_info(&key, false), request_info(&key, true)]
    );

    // The registration is lost later: registering again is a new request.
    *lock(&anlf.held) = None;
    register_at_mtlf(anlf, at, model).await.unwrap();
    let third = registers.infos()[2].clone();
    assert!(
        !third.contains(&key) && !third.contains("retrans"),
        "a later Register uses a fresh key: {third}"
    );
    mtlf_srv.stop().await.unwrap();
}
