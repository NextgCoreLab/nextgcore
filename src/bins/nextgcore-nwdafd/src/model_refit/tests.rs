//! nextgsim#468 PR 4: the seeded series, the AR refit, and the whole
//! provision → monitor → retrain → re-provision chain between an MTLF and an
//! AnLF, both nwdafd's own handlers, over real HTTP with a stand-in NRF.

use super::*;
use crate::model_monitor::{self as mm, Monitor};
use crate::model_retrain::{Anlf, MtlfTarget};
use crate::role::Role;
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use serde_json::{json, Value};
use std::time::Instant;

type Ctx = Arc<RwLock<NwdafContext>>;

fn context(id: &str) -> Ctx {
    let mut ctx = NwdafContext::new(id.to_string());
    ctx.init(16);
    Arc::new(RwLock::new(ctx))
}

fn root(yaml: &str) -> serde_yaml::Value {
    serde_yaml::from_str(yaml).unwrap()
}

fn feed(ctx: &Ctx, cfg: &SeriesConfig, from: u64, to: u64) {
    ingest_steps(&ctx.read().unwrap(), cfg, from, to);
}

fn measure(ctx: &Ctx) -> u8 {
    mm::measure(ctx, Some(SERIES_NF_INSTANCE))
        .expect("points")
        .0
}

/// Load `bytes` as `ctx`'s NF_LOAD predictor, the way the AnLF loads a
/// verified model.
fn load(ctx: &Ctx, bytes: &[u8]) {
    let m = OnnxLinearRegressor::from_bytes(bytes, "loaded").unwrap();
    ctx.read().unwrap().lock_engine().set_predictor(Box::new(m));
}

#[test]
fn series_config_defaults_and_rejects_malformed_blocks() {
    assert_eq!(
        series_config_from_root(&root("nwdaf: {}")),
        Ok(Some(SeriesConfig::default()))
    );
    assert_eq!(
        series_config_from_root(&root(
            "nwdaf: { retrain_series: { seed: 7, step_secs: 2, cycle_steps: 10, change_at_step: 4 } }"
        )),
        Ok(Some(SeriesConfig {
            seed: 7,
            step_secs: 2,
            cycle_steps: 10,
            change_at_step: 4
        }))
    );
    assert_eq!(
        series_config_from_root(&root("nwdaf: { retrain_series: { enabled: false } }")),
        Ok(None)
    );
    for bad in [
        "nwdaf: { retrain_series: 3 }",
        "nwdaf: { retrain_series: { bogus: 1 } }",
        "nwdaf: { retrain_series: { seed: -1 } }",
        "nwdaf: { retrain_series: { enabled: 1 } }",
        "nwdaf: { retrain_series: { step_secs: 0 } }",
        "nwdaf: { retrain_series: { change_at_step: 0 } }",
        "nwdaf: { retrain_series: { cycle_steps: 100, change_at_step: 100 } }",
    ] {
        assert!(series_config_from_root(&root(bad)).is_err(), "{bad}");
    }
}

/// Two NWDAFs with the same config see the same series, whatever their start;
/// the regime changes where the config says.
#[test]
fn the_series_is_a_function_of_seed_and_step() {
    let cfg = SeriesConfig::default();
    let same = SeriesConfig::default();
    let other = SeriesConfig {
        seed: 469,
        ..SeriesConfig::default()
    };
    assert!((0..1200).all(|k| cfg.value(k) == same.value(k)));
    assert!(
        (0..1200).any(|k| cfg.value(k) != other.value(k)),
        "the seed matters"
    );
    for k in [0, 119, 600, 719] {
        assert_eq!(cfg.regime(k), Regime::Calm, "{k}");
    }
    for k in [120, 599, 720, 1199] {
        assert_eq!(cfg.regime(k), Regime::Alternating, "{k}");
    }
    assert_eq!(cfg.next_change(5), 120);
    assert_eq!(cfg.next_change(120), 600);
    assert_eq!(cfg.next_change(700), 720);
    // Calm: near the sine. Alternating: near 0.8 / 0.2.
    for k in 0..120 {
        let s = 0.5 + 0.1 * (2.0 * std::f64::consts::PI * (k % 60) as f64 / 60.0).sin();
        assert!((cfg.value(k) - s).abs() <= 0.02, "{k}");
    }
    for k in 120..600u64 {
        let e = if k.is_multiple_of(2) { 0.8 } else { 0.2 };
        assert!((cfg.value(k) - e).abs() <= 0.02, "{k}");
    }
    // Two contexts fed from different starts agree on the overlap.
    let (a, b) = (context("a"), context("b"));
    feed(&a, &cfg, 0, 150);
    feed(&b, &cfg, 100, 150);
    let sa = a
        .read()
        .unwrap()
        .lock_engine()
        .nf_load_series(None)
        .unwrap()
        .1;
    let sb = b
        .read()
        .unwrap()
        .lock_engine()
        .nf_load_series(None)
        .unwrap()
        .1;
    assert_eq!(sa[sa.len() - sb.len()..], sb[..]);
}

/// Least squares recovers a known AR process (oldest lag first), whatever
/// the noise realisation: the noise comes from fixed local seeds, not the
/// series default, and the tolerance (0.06, about 3 sigma of the estimate at
/// N = 4000) holds at every one of them (#1491 review, MINOR 1: 0.03 held at
/// seed 468 only).
#[test]
fn fit_ar_recovers_a_known_process() {
    for seed in [1, 5, 7, 42, 468, 100_000] {
        let noise = SeriesConfig {
            seed,
            ..SeriesConfig::default()
        };
        let mut y = vec![0.3, 0.4, 0.5, 0.4, 0.3];
        for k in 5..4000u64 {
            let t = y.len();
            y.push(0.1 + 0.6 * y[t - 1] - 0.2 * y[t - 3] + 0.1 * noise.noise(k));
        }
        let (w, c) = fit_ar(&y, 5).unwrap();
        let want = [0.0, 0.0, -0.2, 0.0, 0.6];
        for (got, want) in w.iter().zip(want) {
            assert!((got - want).abs() < 0.06, "seed {seed}: {w:?}");
        }
        assert!((c - 0.1).abs() < 0.06, "seed {seed}: {c}");
    }
    let y = [0.3, 0.4, 0.5, 0.4, 0.3];
    assert!(fit_ar(&y, 5).is_err());
}

/// The one-step predictions of an AR fit `(w, c)` over `series`.
fn ar_predictions(series: &[f64], w: &[f64], c: f64) -> Vec<f64> {
    (w.len()..series.len())
        .map(|t| {
            c + w
                .iter()
                .zip(&series[t - w.len()..t])
                .map(|(w, x)| w * x)
                .sum::<f64>()
        })
        .collect()
}

/// The ridge term's degenerate cases (#1491 review, MINOR 2). A constant
/// series (a flat real NF with `retrain_series.enabled: false`) has a zero
/// lag covariance: without the ridge it never fits and the retrain defers
/// for ever; with it, it fits the mean.
#[test]
fn fit_ar_fits_a_constant_series_to_its_mean() {
    let y = vec![0.42; REFIT_WINDOW];
    let (w, c) = fit_ar(&y, AR_ORDER).expect("a constant series fits");
    assert!(w.iter().all(|w| w.abs() < 1e-9), "{w:?}");
    assert!((c - 0.42).abs() < 1e-9, "{c}");
    for p in ar_predictions(&y, &w, c) {
        assert!((p - 0.42).abs() < 1e-9, "{p}");
    }
}

/// A noise-free period-2 series makes the odd lags identical and the even
/// lags identical: the normal equations are singular without the ridge.
/// With it the fit exists and predicts every next point.
#[test]
fn fit_ar_fits_a_noise_free_period_2_series() {
    let y: Vec<f64> = (0..REFIT_WINDOW)
        .map(|k| if k % 2 == 0 { 0.2 } else { 0.8 })
        .collect();
    let (w, c) = fit_ar(&y, AR_ORDER).expect("a period-2 series fits");
    for (t, p) in (AR_ORDER..y.len()).zip(ar_predictions(&y, &w, c)) {
        assert!(
            (p - y[t]).abs() < 1e-3,
            "step {t}: {p} vs {} ({w:?}, {c})",
            y[t]
        );
    }
}

/// The demo's arithmetic in one place: v1 follows the calm part, scores 0.6x
/// after the scripted change, the refit restores it (and keeps it when the
/// calm part comes back); the held-out MAE is reported against the model it
/// replaces and persistence.
#[test]
fn the_regime_change_degrades_v1_and_the_refit_restores_it() {
    let cfg = SeriesConfig::default();
    let (mtlf, anlf) = (context("mtlf-r"), context("anlf-r"));
    let v1 = mtlf.read().unwrap().current_model_version().unwrap();
    load(&anlf, &v1.bytes);
    feed(&mtlf, &cfg, 0, 119);
    feed(&anlf, &cfg, 0, 119);
    assert!(measure(&anlf) >= 90, "calm: {}", measure(&anlf));

    feed(&mtlf, &cfg, 120, 199);
    feed(&anlf, &cfg, 120, 199);
    let low = measure(&anlf);
    assert!((60..70).contains(&low), "alternating: 0.6x, got {low}");

    let (instance, series) = mtlf
        .read()
        .unwrap()
        .lock_engine()
        .nf_load_series(Some(SERIES_NF_INSTANCE))
        .unwrap();
    let window = &series[series.len() - REFIT_WINDOW..];
    let current = crate::ml_service::OlsLinearModel;
    let r = refit(window, &instance, &current).unwrap();
    assert_eq!((r.train_rows, r.holdout_rows), (33, 10));
    assert!(r.mae_refit < 0.05, "{r:?}");
    assert!(r.mae_current > 0.3, "{r:?}");
    assert!(r.mae_persistence > 0.5, "{r:?}");

    let (w, c) = r.model.linear_form().unwrap();
    load(&anlf, &crate::onnx_export::encode_linear_regressor(&w, c));
    assert!(measure(&anlf) >= 90, "v2: {}", measure(&anlf));
    // The next cycle's calm part: v2 still above the threshold.
    feed(&anlf, &cfg, 600, 719);
    assert!(measure(&anlf) >= 70, "v2 on calm: {}", measure(&anlf));
}

/// The judging is on the series only: a flat real NF next to it does not
/// dilute the drop.
#[test]
fn the_anlf_judges_on_the_series_only() {
    let cfg = SeriesConfig::default();
    let anlf = context("anlf-only");
    feed(&anlf, &cfg, 120, 199);
    {
        let g = anlf.read().unwrap();
        let mut e = g.lock_engine();
        for i in 0..80 {
            let mut s = crate::analytics::NfLoadSample::now("SMF", "smf-flat", 0.4, 0.0, 0);
            s.timestamp = i;
            e.ingest_nf_load(s);
        }
    }
    assert!(measure(&anlf) < 70);
    assert!(
        mm::measure(&anlf, None).unwrap().0 >= 70,
        "diluted without the filter"
    );
    let (id, _) = anlf
        .read()
        .unwrap()
        .lock_engine()
        .nf_load_series(Some(SERIES_NF_INSTANCE))
        .unwrap();
    assert_eq!(id, SERIES_NF_INSTANCE);
}

// ── over HTTP ────────────────────────────────────────────────────────────────

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

async fn start<F, Fut>(handler: F) -> (nextgcore_sbi::SbiServer, u16)
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

/// The MTLF's SBI: ML-provision create and artefacts, MLModelMonitor
/// registrations and its accuracy callback.
async fn mtlf_server(
    m: &'static Monitor,
    ctx: Ctx,
    listener: nextgcore_sbi::test_support::BoundListener,
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
                    ["nnwdaf-mlmodelprovision", "v1", "subscriptions"] => {
                        let g = ctx.read().unwrap();
                        crate::sbi_handler::handle_ml_prov_subscription_create_with_ctx(&g, &req)
                    }
                    ["nnwdaf-mlmodelprovision", "v1", "models", ev, art] => {
                        let g = ctx.read().unwrap();
                        crate::sbi_handler::handle_ml_model_download_with_ctx(&g, ev, art)
                    }
                    ["nnwdaf-mlmodelmonitor", "v1", rest @ ..] => {
                        mm::route(Some(m), &ctx, &method, rest, &req)
                    }
                    ["nnwdaf-callback", "v1", mm::CALLBACK_SEGMENT, token] => {
                        mm::handle_notify(Some(m), token, &req)
                    }
                    _ => SbiResponse::with_status(404),
                }
            }
        })
        .await
        .expect("mtlf starts");
    server
}

/// The AnLF's SBI: the model-notify callback and MLModelMonitor subscriptions.
async fn anlf_server(
    anlf: &'static Anlf,
    m: &'static Monitor,
    ctx: Ctx,
    listener: nextgcore_sbi::test_support::BoundListener,
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
                    ["nnwdaf-callback", "v1", crate::model_retrain::CALLBACK_SEGMENT, token] => {
                        crate::model_retrain::handle_model_notify(Some(anlf), ctx, token, &req)
                    }
                    ["nnwdaf-mlmodelmonitor", "v1", rest @ ..] => {
                        mm::route(Some(m), &ctx, &method, rest, &req)
                    }
                    _ => SbiResponse::with_status(404),
                }
            }
        })
        .await
        .expect("anlf starts");
    server
}

/// A stand-in NRF: discovery of `anlf_id`'s MLModelMonitor service.
async fn nrf(anlf_id: &'static str, anlf_port: u16) -> (nextgcore_sbi::SbiServer, u16) {
    start(move |req: SbiRequest| async move {
        let hit = req
            .http
            .params
            .get("target-nf-instance-id")
            .map(String::as_str)
            == Some(anlf_id);
        let body = if hit {
            json!({ "nfInstances": [{
                "nfInstanceId": anlf_id, "nfType": "NWDAF",
                "nfServices": [mm::nf_service(anlf_id, "127.0.0.1", anlf_port)]
            }]})
        } else {
            json!({ "nfInstances": [] })
        };
        SbiResponse::with_status(200).with_json_body(&body).unwrap()
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

/// A flat NF series, a full buffer, sorting before the seeded one.
fn flat(ctx: &Ctx) {
    let g = ctx.read().unwrap();
    let mut e = g.lock_engine();
    for i in 0..crate::analytics::MAX_SAMPLES as u64 {
        let mut s = crate::analytics::NfLoadSample::now("SMF", "0-flat-smf", 0.4, 0.0, 0);
        s.timestamp = i;
        e.ingest_nf_load(s);
    }
}

fn leak<T>(t: T) -> &'static T {
    Box::leak(Box::new(t))
}

/// What one run of the chain saw.
#[derive(Debug)]
struct Chain {
    /// The AnLF's accuracy (percent) on calm data with v1, after the change
    /// with v1, and at the end with whatever it runs.
    calm: u8,
    dropped: u8,
    end: u8,
    /// The versions the AnLF loaded, in order.
    loaded: Vec<String>,
    /// The MTLF's last refit, if any.
    refit: Option<(u32, u32, Value)>,
    retrain_requested: bool,
}

/// One seeded run of the demo's chain in mode `mode`: subscribe, v1
/// provisioned and verified, Register, the MTLF subscribes at the AnLF,
/// accuracy reports on calm data, the scripted change, reports, the MTLF's
/// upkeep (refit), Notify of v2, v2 verified, Register v2, a report on v2.
async fn chain(mode: &'static str, anlf_id: &'static str) -> Chain {
    let cfg = SeriesConfig::default();
    let (mtlf_ctx, anlf_ctx) = (context("mtlf-468r"), context(anlf_id));
    // The AnLF starts on a distinct local model, so loading v1 is observable.
    anlf_ctx
        .read()
        .unwrap()
        .lock_engine()
        .set_predictor(Box::new(crate::ml_service::EwmaModel::default()));

    let anlf_listener = nextgcore_sbi::test_support::bound_listener();
    let anlf_port = anlf_listener.port();
    let mtlf_listener = nextgcore_sbi::test_support::bound_listener();
    let mtlf_port = mtlf_listener.port();
    let (nrf_srv, nrf_port) = nrf(anlf_id, anlf_port).await;
    let series = Some(SERIES_NF_INSTANCE);
    let mtlf_m = leak(
        Monitor::new(
            mode,
            Role::Mtlf,
            &format!("http://127.0.0.1:{mtlf_port}"),
            "mtlf-468r",
            &format!("http://127.0.0.1:{nrf_port}"),
        )
        .with_series(series),
    );
    let anlf_m = leak(
        Monitor::new(mode, Role::Anlf, "http://unused", anlf_id, "http://unused")
            .with_series(series),
    );
    let anlf = leak(Anlf::new());
    mtlf_ctx
        .read()
        .unwrap()
        .set_sbi_base_uri(format!("http://127.0.0.1:{mtlf_port}"));
    let mtlf_srv = mtlf_server(mtlf_m, mtlf_ctx.clone(), mtlf_listener).await;
    let anlf_srv = anlf_server(anlf, anlf_m, anlf_ctx.clone(), anlf_listener).await;

    // The seeded series, calm part, on both. Next to it a flat real NF with as
    // many samples and a lower id: judged or retrained on, it would hide the
    // drop and teach the refit nothing.
    feed(&mtlf_ctx, &cfg, 0, 119);
    feed(&anlf_ctx, &cfg, 0, 119);
    flat(&mtlf_ctx);
    flat(&anlf_ctx);

    // ML-provision Subscribe; v1 is notified, verified and loaded.
    let target = MtlfTarget {
        host: "127.0.0.1".into(),
        port: mtlf_port,
        id: "mtlf-468r".into(),
    };
    crate::model_retrain::subscribe_once(
        anlf,
        &target,
        &format!("http://127.0.0.1:{anlf_port}"),
        anlf_id,
        70,
    )
    .await
    .expect("subscribed");
    let mut loaded = Vec::new();
    crate::notification_dispatcher::dispatch_ml_prov_notifications(mtlf_ctx.clone()).await;
    until("v1 loaded", || anlf.loaded().is_some()).await;
    loaded.push(anlf.loaded().unwrap().version);
    let mtlf_addr = ("127.0.0.1".to_string(), mtlf_port);

    // Register the use of v1; the MTLF subscribes at the AnLF.
    let model_id = |a: &Anlf| crate::model_store::unique_id_of(&a.loaded().unwrap().sha256);
    mm::register_at_mtlf(anlf_m, mtlf_addr.clone(), model_id(anlf))
        .await
        .expect("registered");
    until("subscribed at the AnLF", || {
        anlf_m.subscription_count() == 1
    })
    .await;

    let mut now = 100_000;
    let mut report = |n: u64| {
        now += 1_000;
        let t = now;
        let id = model_id(anlf);
        let actx = anlf_ctx.clone();
        async move {
            mm::report_tick(anlf_m, &actx, Some(id), t).await;
            until("the report at the MTLF", || mtlf_m.counts().1 == n).await;
        }
    };
    report(1).await;
    let calm = measure(&anlf_ctx);
    assert!(
        matches!(refit_tick(mtlf_m, &mtlf_ctx), Outcome::Idle),
        "no drop yet"
    );

    // The scripted regime change.
    feed(&mtlf_ctx, &cfg, 120, 199);
    feed(&anlf_ctx, &cfg, 120, 199);
    let dropped = measure(&anlf_ctx);
    for n in 2..=(1 + mm::FEEDBACK_WINDOW as u64) {
        report(n).await;
    }
    let v1_id = model_id(anlf);
    let retrain_requested = mtlf_m.retrain_requested(v1_id);
    assert!(
        mtlf_m.below_threshold(v1_id),
        "the drop is seen in both modes"
    );

    // The MTLF's upkeep.
    let refit = match refit_tick(mtlf_m, &mtlf_ctx) {
        Outcome::Refitted { from, to, refit } => {
            assert!(refit.mae_refit < refit.mae_current, "{refit:?}");
            assert!(
                matches!(refit_tick(mtlf_m, &mtlf_ctx), Outcome::Idle),
                "a model is retrained once"
            );
            Some((from.version, to.version, to.manifest.clone()))
        }
        Outcome::Idle => None,
        Outcome::Deferred(e) => panic!("deferred: {e}"),
    };

    // The dispatcher notifies whatever is new; the AnLF verifies and loads.
    crate::notification_dispatcher::dispatch_ml_prov_notifications(mtlf_ctx.clone()).await;
    if refit.is_some() {
        until("v2 loaded", || {
            anlf.loaded().is_some_and(|l| l.version == "2")
        })
        .await;
        loaded.push("2".into());
        assert_eq!(
            anlf.loaded().unwrap().sha256,
            mtlf_ctx
                .read()
                .unwrap()
                .current_model_version()
                .unwrap()
                .sha256
        );
        mm::register_at_mtlf(anlf_m, mtlf_addr, model_id(anlf))
            .await
            .expect("v2 registered");
        until("v2's subscription", || {
            anlf_m.subscription_count() == 1
                && anlf_m.held().is_some_and(|h| h.model_id == model_id(anlf))
        })
        .await;
    }
    let reports = mtlf_m.counts().1;
    report(reports + 1).await;
    let end = measure(&anlf_ctx);
    let after = model_id(anlf);
    if refit.is_some() {
        assert!(
            mtlf_m.rolling(after).unwrap().0 >= 0.70,
            "the MTLF sees v2 above the threshold"
        );
    }
    assert!(matches!(refit_tick(mtlf_m, &mtlf_ctx), Outcome::Idle));
    mtlf_srv.stop().await.unwrap();
    anlf_srv.stop().await.unwrap();
    nrf_srv.stop().await.unwrap();
    Chain {
        calm,
        dropped,
        end,
        loaded,
        refit,
        retrain_requested,
    }
}

/// Mode `retrain`: the ticket's chain to `model v2 verified`, with the AnLF's
/// accuracy back at or above 0.70.
#[tokio::test]
async fn retrain_provisions_v2_and_restores_the_accuracy() {
    let c = chain("retrain", "anlf-468r").await;
    assert!(c.calm >= 90 && c.dropped < 70, "{c:?}");
    assert!(c.retrain_requested);
    let (from, to, manifest) = c.refit.clone().expect("a refit");
    assert_eq!((from, to), (1, 2));
    assert_eq!(manifest["training_type"], "RE_TRAINING");
    assert_eq!(c.loaded, vec!["1", "2"]);
    assert!(c.end >= 70, "{c:?}");
}

/// Mode `no-retrain`, the same seeded run: the drop is seen, nothing is
/// refitted, and the AnLF stays on v1 below the threshold.
#[tokio::test]
async fn no_retrain_keeps_v1_below_the_threshold() {
    let c = chain("no-retrain", "anlf-468n").await;
    assert!(c.calm >= 90 && c.dropped < 70, "{c:?}");
    assert!(!c.retrain_requested);
    assert!(c.refit.is_none(), "{c:?}");
    assert_eq!(c.loaded, vec!["1"]);
    assert!(c.end < 70, "{c:?}");
}

/// A window too short to fit defers the retrain, and the next upkeep with
/// enough data does it.
#[test]
fn a_short_window_defers_the_retrain() {
    let cfg = SeriesConfig::default();
    let ctx = context("mtlf-short");
    let m = Monitor::new(
        "retrain",
        Role::Mtlf,
        "http://x",
        "mtlf-short",
        "http://nrf",
    )
    .with_series(Some(SERIES_NF_INSTANCE));
    let v1 = ctx.read().unwrap().current_model_version().unwrap();
    force_below(&m, v1.unique_id());
    feed(&ctx, &cfg, 120, 130);
    assert!(matches!(refit_tick(&m, &ctx), Outcome::Deferred(_)));
    assert_eq!(
        ctx.read().unwrap().current_model_version().unwrap().version,
        1
    );
    feed(&ctx, &cfg, 131, 199);
    assert!(matches!(refit_tick(&m, &ctx), Outcome::Refitted { .. }));
    assert_eq!(
        ctx.read().unwrap().current_model_version().unwrap().version,
        2
    );
}

/// A live registration of `model_id` below its threshold, without HTTP.
fn force_below(m: &Monitor, model_id: u64) {
    m.insert_registration_for_test("reg-short", model_id);
    m.record_for_test("reg-short", 0.5);
    assert!(m.below_threshold(model_id));
}

#[test]
fn metrics_render_the_refit() {
    let mut out = String::new();
    render_metrics(&mut out, None);
    assert!(out.contains("nwdaf_model_refits_total 0"), "{out}");
    assert!(!out.contains("nwdaf_model_refit_holdout_mae{"));
    let m = Monitor::new("retrain", Role::Mtlf, "http://x", "m", "http://nrf");
    lock(&m.refit).refits = 1;
    lock(&m.refit).last = Some((0.01, 0.36, 0.6));
    let mut out = String::new();
    render_metrics(&mut out, Some(&m));
    assert!(out.contains("nwdaf_model_refits_total 1"), "{out}");
    assert!(
        out.contains("nwdaf_model_refit_holdout_mae{model=\"persistence\"} 0.6"),
        "{out}"
    );
}

/// The upkeep (the wiring the MTLF runs) retrains a model below the threshold.
#[tokio::test]
async fn the_upkeep_retrains() {
    let cfg = SeriesConfig::default();
    let ctx = context("mtlf-upkeep");
    let m = leak(
        Monitor::new(
            "retrain",
            Role::Mtlf,
            "http://x",
            "mtlf-upkeep",
            "http://nrf",
        )
        .with_series(Some(SERIES_NF_INSTANCE)),
    );
    let v1 = ctx.read().unwrap().current_model_version().unwrap();
    force_below(m, v1.unique_id());
    feed(&ctx, &cfg, 120, 199);
    mm::spawn_upkeep(m, ctx.clone());
    until("v2 published by the upkeep", || {
        ctx.read().unwrap().current_model_version().unwrap().version == 2
    })
    .await;
}

/// A refit that is the served model already is no new version, and is not
/// counted as a retrain.
#[test]
fn an_identical_refit_is_not_a_new_version() {
    let cfg = SeriesConfig::default();
    let ctx = context("mtlf-same");
    let m = Monitor::new("retrain", Role::Mtlf, "http://x", "mtlf-same", "http://nrf")
        .with_series(Some(SERIES_NF_INSTANCE));
    let v1 = ctx.read().unwrap().current_model_version().unwrap();
    force_below(&m, v1.unique_id());
    feed(&ctx, &cfg, 120, 199);
    assert!(matches!(refit_tick(&m, &ctx), Outcome::Refitted { .. }));
    let v2 = ctx.read().unwrap().current_model_version().unwrap();
    // v2 drops below too, on the very same window: the refit is v2 again.
    m.insert_registration_for_test("reg-v2", v2.unique_id());
    m.record_for_test("reg-v2", 0.5);
    match refit_tick(&m, &ctx) {
        Outcome::Deferred(e) => assert!(e.contains("v2 itself"), "{e}"),
        o => panic!("{o:?}"),
    }
    assert_eq!(
        ctx.read().unwrap().current_model_version().unwrap().version,
        2
    );
    assert_eq!(lock(&m.refit).refits, 1);
}

/// A refit the store cannot publish (here: coefficients beyond float32) leaves
/// the model that was served, and still provisionable.
#[test]
fn an_unpublishable_refit_keeps_the_served_model() {
    let ctx = context("mtlf-unpub");
    let m = Monitor::new(
        "retrain",
        Role::Mtlf,
        "http://x",
        "mtlf-unpub",
        "http://nrf",
    );
    let v1 = ctx.read().unwrap().current_model_version().unwrap();
    let bytes = crate::onnx_export::encode_linear_regressor(&[1e39; AR_ORDER], 0.0);
    let model = OnnxLinearRegressor::from_bytes(&bytes, "huge").unwrap();
    let r = Refit {
        instance: "x".into(),
        model,
        points: 0,
        train_rows: 0,
        holdout_rows: 0,
        mae_refit: 0.0,
        mae_current: 0.0,
        mae_persistence: 0.0,
    };
    let g = ctx.read().unwrap();
    match apply(&m, &g, v1.clone(), r) {
        Outcome::Deferred(e) => assert!(e.contains("cannot be published"), "{e}"),
        o => panic!("{o:?}"),
    }
    assert_eq!(g.current_model_version().map(|v| v.sha256), Some(v1.sha256));
}
