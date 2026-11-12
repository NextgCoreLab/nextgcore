//! nextgsim#468 PR 2: the AnLF client against nwdafd's own MTLF handlers, over
//! real HTTP.

use super::*;
use crate::context::{MlProvSubscription, NwdafContext};
use std::time::Instant;

fn root(yaml: &str) -> serde_yaml::Value {
    serde_yaml::from_str(yaml).unwrap()
}

#[test]
fn anlf_config_defaults_and_rejects_malformed_blocks() {
    assert_eq!(
        anlf_config_from_root(&serde_yaml::Value::Null),
        Ok(AnlfConfig::default())
    );
    assert_eq!(
        anlf_config_from_root(&root(
            "nwdaf:\n  anlf:\n    mtlf_uri: http://mtlf:7777/\n    accuracy_threshold: 65\n"
        )),
        Ok(AnlfConfig {
            mtlf_uri: Some("http://mtlf:7777".into()),
            accuracy_threshold: 65
        })
    );
    for bad in [
        "anlf: 3",
        "anlf:\n    accuracy_threshold: 101",
        "anlf:\n    accuracy_threshold: -1",
        "anlf:\n    mtlf_uri: mtlf:7777",
        "anlf:\n    mtlf: http://x",
    ] {
        assert!(
            anlf_config_from_root(&root(&format!("nwdaf:\n  {bad}\n"))).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn only_an_anlf_role_with_the_demo_on_runs_the_client() {
    let r = serde_yaml::Value::Null;
    assert_eq!(resolve(None, Role::Anlf, &r), Ok(Plan::Off));
    assert!(matches!(
        resolve(Some("retrain"), Role::Both, &r),
        Ok(Plan::On {
            role: Role::Both,
            ..
        })
    ));
    assert!(matches!(
        resolve(Some("retrain"), Role::Mtlf, &r),
        Ok(Plan::On {
            role: Role::Mtlf,
            ..
        })
    ));
    assert!(matches!(
        resolve(Some("no-retrain"), Role::Anlf, &r),
        Ok(Plan::Client { .. })
    ));
    // The anlf block is read only for a client, and a bad one fails it.
    assert!(resolve(
        Some("retrain"),
        Role::Anlf,
        &root("nwdaf:\n  anlf:\n    accuracy_threshold: 300\n")
    )
    .is_err());
}

/// The AnLF's Subscribe is what the MTLF's own parser accepts, and negotiates
/// ModelProvisionExt with it: the threshold is kept and echoed with `suppFeats`.
#[test]
fn the_subscription_body_negotiates_model_provision_ext_at_the_mtlf() {
    let body = subscription_body("http://anlf:7777/cb", 70);
    let parsed = crate::ml_service::parse_ml_model_prov_subsc(&body).expect("parses");
    assert_eq!(parsed.ml_events, vec![AnalyticsId::NfLoad]);
    assert_eq!(parsed.supp_feats.as_deref(), Some("8"));
    assert_eq!(
        parsed.accuracy_thresholds,
        vec![crate::ml_service::EventAccuracyThreshold {
            event: AnalyticsId::NfLoad,
            threshold: 70
        }]
    );
    let sub = MlProvSubscription::from_parsed("s".into(), parsed);
    let echo = crate::ml_service::ml_prov_subsc_json(&sub);
    assert_eq!(echo["suppFeats"], "8");
    assert_eq!(
        echo["mLEventSubscs"][0]["mlEvRepCon"]["mlAccuracyThreshold"],
        70
    );
}

#[test]
fn discovery_picks_another_nwdaf_offering_the_service() {
    let result = json!({ "nfInstances": [
        { "nfInstanceId": "me", "nfType": "NWDAF", "nfServices": [
            { "serviceName": "nnwdaf-mlmodelprovision",
              "ipEndPoints": [{ "ipv4Address": "10.0.0.1", "port": 1 }] } ] },
        { "nfInstanceId": "amf", "nfType": "AMF", "nfServices": [
            { "serviceName": "nnwdaf-mlmodelprovision",
              "ipEndPoints": [{ "ipv4Address": "10.0.0.2", "port": 2 }] } ] },
        { "nfInstanceId": "nwdaf-x", "nfType": "NWDAF", "nfServices": [
            { "serviceName": "nnwdaf-analyticsinfo",
              "ipEndPoints": [{ "ipv4Address": "10.0.0.3", "port": 3 }] } ] },
        { "nfInstanceId": "mtlf-1", "nfType": "NWDAF", "nfServices": [
            { "serviceName": "nnwdaf-mlmodelprovision",
              "ipEndPoints": [{ "ipv4Address": "10.0.0.4", "port": 7777 }] } ] }
    ]});
    assert_eq!(
        mtlf_from_search_result(&result, "me"),
        Some(MtlfTarget {
            host: "10.0.0.4".into(),
            port: 7777,
            id: "mtlf-1".into()
        })
    );
    assert_eq!(
        mtlf_from_search_result(&json!({"nfInstances": []}), "me"),
        None
    );
}

#[test]
fn notify_bodies_yield_the_nf_load_model_url() {
    let body = json!([{ "subscriptionId": "s", "eventNotifs": [
        { "event": "UE_MOBILITY", "mLFileAddr": { "mLModelUrl": "http://x/ue" } },
        { "event": "NF_LOAD", "mLFileAddr": { "mLModelUrl": "http://x/nf" } },
        { "event": "NF_LOAD", "mLFileAddr": { "mLModelUrl": "http://x/nf" } }
    ]}]);
    assert_eq!(model_urls(&body), Ok(vec!["http://x/nf".to_string()]));
    assert!(model_urls(&json!({})).is_err());
    assert!(model_urls(&json!([])).is_err());
    assert!(model_urls(&json!([{ "eventNotifs": [] }])).is_err());
}

fn published(coef: &[f64], icpt: f64) -> crate::model_store::ModelVersion {
    crate::model_store::ModelStore::new()
        .publish(coef, icpt, "mtlf")
        .unwrap()
        .0
}

fn manifest_of(v: &crate::model_store::ModelVersion) -> Manifest {
    Manifest::from_json(&v.manifest.to_string()).expect("the MTLF's manifest parses")
}

/// nextgsim#463's checks, each with its own refusal, on nwdafd's real exports.
#[test]
fn verification_passes_real_exports_and_refuses_each_defect() {
    // OLS, a negative output and an output above 1 all verify.
    for (c, i) in [
        (vec![-0.4, -0.1, 0.2, 0.5, 0.8], 0.0),
        (vec![0.1; 4], -0.6),
        (vec![0.5; 4], 0.5),
    ] {
        let v = published(&c, i);
        verify(&v.bytes, &manifest_of(&v)).expect("a real export verifies");
    }

    let v = published(&[0.1, 0.2, 0.3, 0.4], 0.05);
    let m = manifest_of(&v);
    let mut flipped = v.bytes.to_vec();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    assert!(matches!(
        verify(&flipped, &m),
        Err(Refusal::Sha256Mismatch { .. })
    ));

    // Bytes and sha changed together (a re-hashed tamper) fail the golden.
    let other = published(&[0.1, 0.2, 0.3, 0.5], 0.05);
    let mut m2 = m.clone();
    m2.sha256 = other.sha256.clone();
    assert!(matches!(
        verify(&other.bytes, &m2),
        Err(Refusal::GoldenMismatch { .. })
    ));

    let mut m3 = m.clone();
    m3.opset = 12;
    assert!(matches!(
        verify(&v.bytes, &m3),
        Err(Refusal::OpsetMismatch {
            expected: 12,
            actual: Some(13)
        })
    ));

    let mut m4 = m.clone();
    m4.inputs[0].shape = vec![-1, 5];
    assert!(matches!(
        verify(&v.bytes, &m4),
        Err(Refusal::SignatureMismatch(_))
    ));

    let mut bad = v.manifest.clone();
    bad["extra"] = json!(1);
    assert!(matches!(
        Manifest::from_json(&bad.to_string()),
        Err(Refusal::ManifestInvalid(_))
    ));
}

// ── over HTTP: nwdafd's MTLF handlers and its dispatcher, an AnLF server ────

type Ctx = Arc<RwLock<NwdafContext>>;

fn context(id: &str) -> Ctx {
    let mut ctx = NwdafContext::new(id.to_string());
    ctx.init(16);
    Arc::new(RwLock::new(ctx))
}

/// The MTLF: the real create handler and artefact routes on `ctx`. With
/// `flip`, the model body has its last byte flipped (the revert arm).
async fn mtlf_server(ctx: Ctx, flip: bool) -> (nextgcore_sbi::SbiServer, u16) {
    let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
    let server =
        nextgcore_sbi::SbiServer::on_listener(nextgcore_sbi::SbiServerConfig::new(addr), listener);
    server
        .start(move |req: SbiRequest| {
            let ctx = ctx.clone();
            async move {
                let path = req.header.uri.split('?').next().unwrap_or("").to_string();
                let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
                let guard = ctx.read().unwrap();
                match parts.as_slice() {
                    ["nnwdaf-mlmodelprovision", "v1", "subscriptions"] => {
                        crate::sbi_handler::handle_ml_prov_subscription_create_with_ctx(
                            &guard, &req,
                        )
                    }
                    ["nnwdaf-mlmodelprovision", "v1", "models", ev, art] => {
                        let mut resp =
                            crate::sbi_handler::handle_ml_model_download_with_ctx(&guard, ev, art);
                        if flip && !art.ends_with(crate::model_store::MANIFEST_SUFFIX) {
                            if let Some(b) = resp.http.binary_content.take() {
                                let mut b = b.to_vec();
                                let last = b.len() - 1;
                                b[last] ^= 0x01;
                                resp.http.binary_content = Some(b.into());
                            }
                        }
                        resp
                    }
                    _ => SbiResponse::with_status(404),
                }
            }
        })
        .await
        .expect("mtlf starts");
    (server, addr.port())
}

/// The AnLF: the real notify handler on `ctx`.
async fn anlf_server(anlf: &'static Anlf, ctx: Ctx) -> (nextgcore_sbi::SbiServer, u16) {
    let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
    let server =
        nextgcore_sbi::SbiServer::on_listener(nextgcore_sbi::SbiServerConfig::new(addr), listener);
    server
        .start(move |req: SbiRequest| {
            let ctx = ctx.clone();
            async move {
                let token = req.header.uri.rsplit('/').next().unwrap_or("").to_string();
                handle_model_notify(Some(anlf), ctx, &token, &req)
            }
        })
        .await
        .expect("anlf starts");
    (server, addr.port())
}

/// Wait (bounded) until `cond` holds.
async fn until(what: &str, cond: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn linear(ctx: &Ctx) -> Option<(Vec<f64>, f64)> {
    ctx.read().unwrap().lock_engine().predictor().linear_form()
}

/// The sha256 of what `ctx`'s predictor exports: equal to the MTLF's version
/// exactly when the AnLF runs the same (float32) model.
fn exported_sha(ctx: &Ctx) -> String {
    ctx.read().unwrap().current_model_version().unwrap().sha256
}

fn ewma_anlf(id: &str) -> Ctx {
    let ctx = context(id);
    // A distinct local model, so loading the MTLF's is observable.
    ctx.read()
        .unwrap()
        .lock_engine()
        .set_predictor(Box::new(crate::ml_service::EwmaModel::default()));
    ctx
}

/// Subscribe → Notify v1 → verify and load v1 → the MTLF's model changes →
/// Notify v2 → load v2: the ticket's success chain, minus the retrain trigger
/// (PRs 3-4).
#[tokio::test]
async fn the_anlf_subscribes_verifies_and_loads_v1_then_v2() {
    let mtlf_ctx = context("mtlf-468");
    let (mtlf, mtlf_port) = mtlf_server(mtlf_ctx.clone(), false).await;
    mtlf_ctx
        .read()
        .unwrap()
        .set_sbi_base_uri(format!("http://127.0.0.1:{mtlf_port}"));

    let anlf: &'static Anlf = Box::leak(Box::new(Anlf::new()));
    let anlf_ctx = ewma_anlf("anlf-468");
    let (anlf_srv, anlf_port) = anlf_server(anlf, anlf_ctx.clone()).await;

    let target = MtlfTarget {
        host: "127.0.0.1".into(),
        port: mtlf_port,
        id: "mtlf-468".into(),
    };
    let created = subscribe_once(anlf, &target, &format!("http://127.0.0.1:{anlf_port}"), 70)
        .await
        .expect("the MTLF accepts the AnLF's subscription");
    assert_eq!(created["suppFeats"], "8");
    let sub_id = created["subscriptionId"].as_str().unwrap().to_string();
    let stored = mtlf_ctx
        .read()
        .unwrap()
        .get_ml_prov_subscription(&sub_id)
        .unwrap();
    assert!(stored.model_provision_ext());
    assert_eq!(stored.accuracy_thresholds[0].threshold, 70);

    // The MTLF's dispatcher notifies v1; the AnLF verifies and loads it.
    crate::notification_dispatcher::dispatch_ml_prov_notifications(mtlf_ctx.clone()).await;
    until("v1 loaded", || anlf.loaded().is_some()).await;
    let v1 = mtlf_ctx.read().unwrap().current_model_version().unwrap();
    let loaded = anlf.loaded().unwrap();
    assert_eq!(loaded.version, "1");
    assert_eq!(loaded.sha256, v1.sha256);
    assert_eq!(
        exported_sha(&anlf_ctx),
        v1.sha256,
        "the AnLF runs exactly the MTLF's v1 bytes"
    );

    // The MTLF's model changes (PR 4's refit); v2 reaches the AnLF.
    let refit = crate::onnx_export::encode_linear_regressor(&[0.1, 0.2, 0.3, 0.4], 0.02);
    mtlf_ctx
        .read()
        .unwrap()
        .lock_engine()
        .set_predictor(Box::new(
            crate::onnx_model::OnnxLinearRegressor::from_bytes(&refit, "refit").unwrap(),
        ));
    crate::notification_dispatcher::dispatch_ml_prov_notifications(mtlf_ctx.clone()).await;
    until("v2 loaded", || {
        anlf.loaded().is_some_and(|l| l.version == "2")
    })
    .await;
    let v2 = mtlf_ctx.read().unwrap().current_model_version().unwrap();
    assert_eq!(anlf.loaded().unwrap().sha256, v2.sha256);
    assert_eq!(exported_sha(&anlf_ctx), v2.sha256);
    assert_eq!(anlf.counts(), (2, 0));

    // A forged token is refused.
    let forged = crate::notification_dispatcher::notify_client("127.0.0.1", anlf_port)
        .post_json(
            &format!("/nnwdaf-callback/v1/{CALLBACK_SEGMENT}/not-the-token"),
            &json!([{ "subscriptionId": "x", "eventNotifs": [] }]),
        )
        .await
        .unwrap();
    assert_eq!(forged.status, 404);

    mtlf.stop().await.unwrap();
    anlf_srv.stop().await.unwrap();
}

/// The revert arm: a one-byte-flipped artefact is refused (sha256 mismatch)
/// and the AnLF keeps the model it had.
#[tokio::test]
async fn a_flipped_byte_is_refused_and_the_model_kept() {
    let mtlf_ctx = context("mtlf-468-flip");
    let (mtlf, mtlf_port) = mtlf_server(mtlf_ctx.clone(), true).await;
    let base = format!("http://127.0.0.1:{mtlf_port}");
    let anlf: &'static Anlf = Box::leak(Box::new(Anlf::new()));
    let anlf_ctx = ewma_anlf("anlf-468-flip");
    let url = mtlf_ctx
        .read()
        .unwrap()
        .current_model_version()
        .unwrap()
        .url(&base, AnalyticsId::NfLoad);

    let refusal = fetch_verify_load(anlf, &anlf_ctx, &url).await.unwrap_err();
    assert_eq!(refusal.kind(), "sha256 mismatch");
    assert!(anlf.loaded().is_none());
    assert_eq!(anlf.counts(), (0, 1));
    assert!(
        linear(&anlf_ctx).is_none(),
        "the AnLF still runs its own (EWMA) model"
    );
    mtlf.stop().await.unwrap();
}

#[test]
fn metrics_render_with_no_client() {
    let mut out = String::new();
    render_metrics(&mut out);
    assert!(out.contains("nwdaf_anlf_client_active 0"), "{out}");
    assert!(
        out.contains("nwdaf_anlf_models_total{outcome=\"refused\"} 0"),
        "{out}"
    );
}
