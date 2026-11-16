//! nextgsim#471 through `ees_sbi_request_handler` itself: EAS registrations,
//! QOS_MON notifications at the demo route, EEC registrations, with the real
//! OAuth2 gate on every eees-* operation.

use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};

fn signing_key() -> SigningKey {
    SigningKey::from_slice(&[47u8; 32]).unwrap()
}

fn jwks_for(sk: &SigningKey) -> serde_json::Value {
    let point = sk.verifying_key().to_encoded_point(false);
    serde_json::json!({"keys":[{
        "kty":"EC","crv":"P-256","use":"sig","alg":"ES256","kid":"k471",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    }]})
}

fn bearer(sk: &SigningKey, scope: &str) -> String {
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let header = r#"{"alg":"ES256","typ":"JWT","kid":"k471"}"#;
    let claims = serde_json::json!({
        "iss":"NRF","sub":"eec-471","aud":"EES","scope":scope,"exp":exp,"iat":0
    })
    .to_string();
    let h = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let p = URL_SAFE_NO_PAD.encode(claims.as_bytes());
    let sig: Signature = sk.sign(format!("{h}.{p}").as_bytes());
    format!("Bearer {h}.{p}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(fut)
}

const EASES: [(&str, &str, u32, u32); 3] = [
    ("eas-local-471", "10.60.0.11", 10, 50),
    ("eas-regional-471", "10.60.0.12", 14, 50),
    ("eas-cloud-471", "10.60.0.13", 40, 200),
];

fn eas_body(id: &str, ip: &str, max_resp: u32, avl: u32) -> String {
    format!(
        r#"{{"easProf":{{"easId":"{id}","endPt":{{"ipv4Addrs":["{ip}"],"port":9471}},"svcKpi":{{"maxRespTime":{max_resp},"avlComp":{avl}}}}}}}"#
    )
}

/// Register the three sidecars; their registrationIds.
fn register_eases(sk: &SigningKey) -> Vec<String> {
    EASES
        .iter()
        .map(|(id, ip, rt, avl)| {
            let r = block_on(ees_sbi_request_handler(
                SbiRequest::post("/eees-easregistration/v1/registrations")
                    .with_header("Authorization", bearer(sk, "eees-easregistration"))
                    .with_body(eas_body(id, ip, *rt, *avl), "application/json"),
            ));
            assert_eq!(r.status, 201, "{:?}", r.http.content);
            r.http
                .get_header("location")
                .unwrap()
                .rsplit('/')
                .next()
                .unwrap()
                .to_string()
        })
        .collect()
}

fn eas_get(sk: &SigningKey, reg_id: &str) -> String {
    let r = block_on(ees_sbi_request_handler(
        SbiRequest::get(format!("{EASREG_REGISTRATIONS_PATH}/{reg_id}"))
            .with_header("Authorization", bearer(sk, "eees-easregistration")),
    ));
    assert_eq!(r.status, 200);
    r.http.content.unwrap()
}

/// An EEC registration asking for selection, one AC profile naming the three.
/// `(status, discoveredEas easIds, achievableLatency values)`.
fn eec_register(sk: &SigningKey) -> (u16, Vec<String>, Vec<serde_json::Value>) {
    let eass: Vec<serde_json::Value> = EASES
        .iter()
        .map(|(id, ..)| serde_json::json!({ "easId": id, "minimumReqSvcKPIs": { "reqComp": "100" } }))
        .collect();
    let body = serde_json::json!({
        "eecId": "eec-471", "easSelReqInd": true,
        "acProfs": [{ "acId": "ac-471", "eass": eass }],
    });
    let r = block_on(ees_sbi_request_handler(
        SbiRequest::post("/eees-eecregistration/v1/registrations")
            .with_header("Authorization", bearer(sk, "eees-eecregistration"))
            .with_json_body(&body)
            .unwrap(),
    ));
    let v: serde_json::Value = r
        .http
        .content
        .as_deref()
        .and_then(|c| serde_json::from_str(c).ok())
        .unwrap_or_default();
    if let Some(loc) = r.http.get_header("location") {
        let id = loc.rsplit('/').next().unwrap().to_string();
        if let Ok(c) = ees_self().read() {
            c.eec_deregister(&id);
        }
    }
    let list = v["discoveredEas"].as_array().cloned().unwrap_or_default();
    (
        r.status,
        list.iter()
            .map(|d| d["eas"]["easId"].as_str().unwrap().to_string())
            .collect(),
        list.iter()
            .map(|d| d["vendorSpecific-032473"].clone())
            .collect(),
    )
}

fn deregister(sk: &SigningKey, ids: &[String]) {
    for id in ids {
        block_on(ees_sbi_request_handler(
            SbiRequest::delete(format!("{EASREG_REGISTRATIONS_PATH}/{id}"))
                .with_header("Authorization", bearer(sk, "eees-easregistration")),
        ));
    }
}

/// With the demo off (or not built): the eass order, no vendor member, and the
/// demo route is the router's plain 404.
fn assert_base_behaviour(sk: &SigningKey) {
    let (status, ids, vendor) = eec_register(sk);
    assert_eq!(status, 201);
    assert_eq!(ids, ["eas-local-471", "eas-regional-471", "eas-cloud-471"]);
    assert!(vendor.iter().all(serde_json::Value::is_null), "{vendor:?}");
    let r = block_on(ees_sbi_request_handler(
        SbiRequest::post("/d443a-edge-budget/qos-mon/0123456789abcdef0123456789abcdef")
            .with_body("{}", "application/json"),
    ));
    assert_eq!(r.status, 404);
}

#[cfg(not(feature = "demo-d443a-edge-budget"))]
#[test]
fn a_default_build_selects_in_eass_order_and_has_no_demo_route_471() {
    let _g = auth::GLOBAL_STATE_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    ees_context_init(512);
    let sk = signing_key();
    auth::set_auth_jwks(jwks_for(&sk));
    let regs = register_eases(&sk);
    assert_base_behaviour(&sk);
    deregister(&sk, &regs);
    auth::clear_auth_jwks();
}

#[cfg(feature = "demo-d443a-edge-budget")]
#[test]
fn the_selection_follows_the_qos_mon_budget_through_the_router_471() {
    let _g = auth::GLOBAL_STATE_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let _d = edge_budget::lock_for_test();
    ees_context_init(512);
    let sk = signing_key();
    auth::set_auth_jwks(jwks_for(&sk));
    edge_budget::install(None);
    edge_budget::clear_for_test();
    let regs = register_eases(&sk);
    let local_before = eas_get(&sk, &regs[0]);

    // Off, with the feature built: the base behaviour.
    assert_base_behaviour(&sk);

    let token = "fedcba9876543210fedcba9876543210";
    let plan = |mode| edge_budget::Plan {
        mode,
        config: edge_budget::Config::default(),
        token: token.into(),
    };
    // The route goes through the OAuth2 gate, which admits a token-less notify
    // only through its registered callback exemption (#1525); here with a
    // bearer of the route's scope, then the path token.
    let notify_as = |auth: Option<String>, tok: &str, rt: u32, n6_local: u32| {
        let mut req = SbiRequest::post(format!("/d443a-edge-budget/qos-mon/{tok}")).with_body(
            edge_budget::tests::qos_mon_body(rt, n6_local),
            "application/json",
        );
        if let Some(a) = auth {
            req = req.with_header("Authorization", a);
        }
        block_on(ees_sbi_request_handler(req)).status
    };
    let notify = |tok: &str, rt: u32, n6_local: u32| {
        notify_as(Some(bearer(&sk, edge_budget::SCOPE)), tok, rt, n6_local)
    };
    edge_budget::install(Some(plan(edge_budget::Mode::MeasuredBudget)));
    auth::set_callback_exemptions(oauth2_callback_exemptions());

    // No report yet: measured-budget ranks on the advertisement, labelled.
    let (status, ids, vendor) = eec_register(&sk);
    assert_eq!(status, 201);
    assert_eq!(ids, ["eas-local-471", "eas-regional-471"]);
    assert_eq!(vendor[0]["budgetSrc"], "static-fallback");

    // Act 1: rt 6, N6 local 2 / regional 3 / cloud none.
    assert_eq!(notify(token, 6, 2), 204);
    let (status, ids, vendor) = eec_register(&sk);
    assert_eq!(status, 201);
    assert_eq!(ids, ["eas-local-471", "eas-regional-471"]);
    assert_eq!(
        vendor[0],
        serde_json::json!({ "achievableLatency": 12, "budgetSrc": "upf-n3+upf-n6" })
    );
    assert_eq!(vendor[1]["achievableLatency"], 14);

    // Act 2: N6 local 18 → regional first, local out of the deadline.
    assert_eq!(notify(token, 6, 18), 204);
    let (status, ids, _) = eec_register(&sk);
    assert_eq!(status, 201);
    assert_eq!(ids, ["eas-regional-471"]);
    // The EAS's registration is what it was: only the measurement moved.
    assert_eq!(eas_get(&sk, &regs[0]), local_before);

    // No bearer (what a TS 33.501 §13.4.1 notify carries) on the current path
    // token: admitted by the route's callback exemption (#1525).
    assert_eq!(notify_as(None, token, 6, 18), 204);
    // With no bearer, a wrong path token is not exempt: 401, the same answer as
    // any unauthenticated request, so the route is no token-validity oracle
    // (#1523 review m1), and the budget does not move back.
    assert_eq!(
        notify_as(None, "fedcba9876543210fedcba9876543211", 6, 2),
        401
    );
    assert_eq!(eec_register(&sk).1, ["eas-regional-471"]);

    // A wrong token: 404, and the budget does not move back.
    assert_eq!(notify("fedcba9876543210fedcba9876543211", 6, 2), 404);
    assert_eq!(eec_register(&sk).1, ["eas-regional-471"]);

    // Act 3: rt 26 → nothing within 15 ms → 404.
    assert_eq!(notify(token, 26, 2), 204);
    let (status, ids, _) = eec_register(&sk);
    assert_eq!(status, 404);
    assert!(ids.is_empty());

    // static (restart into the baseline): the advertisement, whatever was measured.
    edge_budget::install(Some(plan(edge_budget::Mode::Static)));
    assert_eq!(notify(token, 6, 18), 204);
    let (status, ids, vendor) = eec_register(&sk);
    assert_eq!(status, 201);
    assert_eq!(ids, ["eas-local-471", "eas-regional-471"]);
    assert_eq!(
        vendor[0],
        serde_json::json!({ "achievableLatency": 10, "budgetSrc": "static" })
    );

    // Off again: the base behaviour, the route gone, nothing exempt.
    edge_budget::install(None);
    assert!(oauth2_callback_exemptions().is_empty());
    auth::set_callback_exemptions(oauth2_callback_exemptions());
    assert_base_behaviour(&sk);

    edge_budget::clear_for_test();
    deregister(&sk, &regs);
    auth::clear_auth_jwks();
}

/// nextgsim#458: a `demo:` block naming d443a-edge-budget fails start-up in a
/// build without the feature, and `mode: bogus` fails it in one with it.
#[test]
fn the_demo_block_is_checked_against_this_build_471() {
    let root: serde_yaml::Value = serde_yaml::from_str(
        "demo:\n  enabled: true\n  d443a-edge-budget:\n    enabled: true\n    mode: bogus\n",
    )
    .unwrap();
    let err = nextgcore_demo::DemoConfig::from_root(&root)
        .unwrap()
        .validate(&demo_registry())
        .unwrap_err();
    #[cfg(feature = "demo-d443a-edge-budget")]
    assert!(
        matches!(&err, nextgcore_demo::DemoConfigError::UnknownMode { demo, mode, .. }
            if demo == "d443a-edge-budget" && mode == "bogus"),
        "{err:?}"
    );
    #[cfg(not(feature = "demo-d443a-edge-budget"))]
    assert!(
        matches!(&err, nextgcore_demo::DemoConfigError::UnknownKey { key, .. } if key == "d443a-edge-budget"),
        "{err:?}"
    );
    // No block, or the kill switch off: nothing active.
    for off in [
        "{}",
        "demo:\n  enabled: false\n  d443a-edge-budget:\n    enabled: true\n    mode: static\n",
    ] {
        let root: serde_yaml::Value = serde_yaml::from_str(off).unwrap();
        let parsed = nextgcore_demo::DemoConfig::from_root(&root).unwrap();
        #[cfg(feature = "demo-d443a-edge-budget")]
        assert!(parsed.validate(&demo_registry()).unwrap().is_empty());
        #[cfg(not(feature = "demo-d443a-edge-budget"))]
        let _ = parsed;
    }
}

/// #1523 review m2: the debug request log never shows the callback token; other
/// URIs are logged as they were.
#[test]
fn the_request_log_redacts_the_callback_token_471() {
    let tok = "fedcba9876543210fedcba9876543210";
    let uri = format!("/d443a-edge-budget/qos-mon/{tok}");
    let line = request_log_uri(&uri);
    assert!(!line.contains(tok), "{line}");
    assert_eq!(line, "/d443a-edge-budget/qos-mon/<redacted>");
    assert_eq!(
        request_log_uri("/eees-easregistration/v1/registrations/abc"),
        "/eees-easregistration/v1/registrations/abc"
    );
}

/// TS 24.558 §5.2.2.2: with two AC profiles of which only one has an EAS within
/// the deadline, the registration succeeds (step 3 ii), `24558-k00.txt:1263-1270`)
/// with the other listed in `unfulfillAcProfs` as REQ_UNFULFILLED; with neither,
/// it is refused 404 (step 1, `:1239-1243`).
#[cfg(feature = "demo-d443a-edge-budget")]
#[test]
fn an_ac_profile_with_no_eas_within_the_deadline_is_unfulfilled_471() {
    let _g = auth::GLOBAL_STATE_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let _d = edge_budget::lock_for_test();
    ees_context_init(512);
    let sk = signing_key();
    auth::set_auth_jwks(jwks_for(&sk));
    edge_budget::clear_for_test();
    let regs = register_eases(&sk);
    edge_budget::install(Some(edge_budget::Plan {
        mode: edge_budget::Mode::Static,
        config: edge_budget::Config::default(),
        token: "fedcba9876543210fedcba9876543210".into(),
    }));
    let register = |profs: serde_json::Value| {
        let body =
            serde_json::json!({ "eecId": "eec-471-multi", "easSelReqInd": true, "acProfs": profs });
        let r = block_on(ees_sbi_request_handler(
            SbiRequest::post("/eees-eecregistration/v1/registrations")
                .with_header("Authorization", bearer(&sk, "eees-eecregistration"))
                .with_json_body(&body)
                .unwrap(),
        ));
        if let Some(loc) = r.http.get_header("location") {
            let id = loc.rsplit('/').next().unwrap().to_string();
            if let Ok(c) = ees_self().read() {
                c.eec_deregister(&id);
            }
        }
        let v: serde_json::Value = r
            .http
            .content
            .as_deref()
            .and_then(|c| serde_json::from_str(c).ok())
            .unwrap_or_default();
        (r.status, v)
    };
    // ac-fast names eas-local (10 ms advertised), ac-slow eas-cloud (40 ms).
    let (status, v) = register(serde_json::json!([
        { "acId": "ac-fast", "eass": [{ "easId": "eas-local-471" }] },
        { "acId": "ac-slow", "eass": [{ "easId": "eas-cloud-471" }] },
    ]));
    assert_eq!(status, 201, "{v}");
    let ids: Vec<&str> = v["discoveredEas"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["eas"]["easId"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["eas-local-471"]);
    let unful = v
        .get("unfulfillAcProfs")
        .or_else(|| v.get("unfulfilledAcProfs"))
        .cloned();
    let unful = serde_json::to_string(&unful).unwrap();
    assert!(
        unful.contains("ac-slow") && unful.contains("REQ_UNFULFILLED"),
        "{v}"
    );
    assert!(!unful.contains("ac-fast"), "{v}");
    // An AC profile the base matcher already marked unfulfilled (its EAS is not
    // registered: EAS_NOT_AVAILABLE) keeps that one reason: listed once, in the
    // singular form, and not again as REQ_UNFULFILLED (#1523 review r2).
    let (status, v) = register(serde_json::json!([
        { "acId": "ac-fast", "eass": [{ "easId": "eas-local-471" }] },
        { "acId": "ac-missing", "eass": [{ "easId": "eas-not-registered-471" }] },
    ]));
    assert_eq!(status, 201, "{v}");
    let all =
        serde_json::to_string(&(v.get("unfulfillAcProfs"), v.get("unfulfilledAcProfs"))).unwrap();
    assert_eq!(all.matches("ac-missing").count(), 1, "{v}");
    assert!(
        all.contains("EAS_NOT_AVAILABLE") && !all.contains("REQ_UNFULFILLED"),
        "{v}"
    );
    assert!(
        v.get("unfulfillAcProfs").is_none(),
        "one entry: the singular form ({v})"
    );
    assert_eq!(v["unfulfilledAcProfs"]["acId"], "ac-missing", "{v}");
    let (status, _) = register(serde_json::json!([
        { "acId": "ac-slow", "eass": [{ "easId": "eas-cloud-471" }] },
    ]));
    assert_eq!(status, 404);
    edge_budget::install(None);
    deregister(&sk, &regs);
    auth::clear_auth_jwks();
}

/// #1525 through the router, with OAuth2 enforced (a JWKS configured): the
/// D443A notify route's callback exemption admits a token-less notify on the
/// current path token, and nothing else.
#[cfg(feature = "demo-d443a-edge-budget")]
#[test]
fn the_qos_mon_notify_is_admitted_without_a_bearer_only_on_its_current_token_1525() {
    let _g = auth::GLOBAL_STATE_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let _d = edge_budget::lock_for_test();
    ees_context_init(512);
    let sk = signing_key();
    auth::set_auth_jwks(jwks_for(&sk));
    edge_budget::clear_for_test();
    let token = "0a1b2c3d4e5f60718293a4b5c6d7e8f9";
    edge_budget::install(Some(edge_budget::Plan {
        mode: edge_budget::Mode::MeasuredBudget,
        config: edge_budget::Config::default(),
        token: token.into(),
    }));
    // What the composition root registers, on the server config and in the
    // per-route gate: exactly the one route.
    auth::set_callback_exemptions(Vec::new());
    let cfg = install_callback_exemptions(NextgcoreSbiServerConfig::new(
        "127.0.0.1:0".parse().unwrap(),
    ));
    assert_eq!(
        cfg.oauth2_callback_exemptions
            .iter()
            .map(OAuth2CallbackExemption::route)
            .collect::<Vec<_>>(),
        ["POST /d443a-edge-budget/qos-mon/{token}"]
    );
    assert_eq!(
        auth::callback_exemption_routes(),
        ["POST /d443a-edge-budget/qos-mon/{token}"]
    );
    let body = edge_budget::tests::qos_mon_body(6, 2);
    let send = |method: &str, uri: &str| {
        let req = match method {
            "POST" => SbiRequest::post(uri.to_string()),
            "PUT" => SbiRequest::put(uri.to_string()),
            "GET" => SbiRequest::get(uri.to_string()),
            _ => SbiRequest::delete(uri.to_string()),
        }
        .with_body(body.clone(), "application/json");
        block_on(ees_sbi_request_handler(req))
    };
    let route = format!("/d443a-edge-budget/qos-mon/{token}");

    // Admitted: no bearer, the current token; the report is used.
    assert!(edge_budget::latest_for_test().is_none());
    assert_eq!(send("POST", &route).status, 204);
    assert_eq!(edge_budget::latest_for_test().map(|s| s.rt_ms), Some(6));
    edge_budget::clear_for_test();
    // As at #1519's server gate, an exempt request's bearer is not consulted:
    // one without the route's scope is admitted on the current token too.
    let mut with_bearer =
        SbiRequest::post(route.clone()).with_body(body.clone(), "application/json");
    with_bearer = with_bearer.with_header("Authorization", bearer(&sk, "eees-easdiscovery"));
    assert_eq!(block_on(ees_sbi_request_handler(with_bearer)).status, 204);
    edge_budget::clear_for_test();

    // A forged or stale token, no bearer: 401, nothing used.
    let forged = "/d443a-edge-budget/qos-mon/0a1b2c3d4e5f60718293a4b5c6d7e8f8";
    assert_eq!(send("POST", forged).status, 401);
    // Another method on the exact route: not exempt.
    for m in ["PUT", "GET", "DELETE"] {
        assert_eq!(send(m, &route).status, 401, "{m}");
    }
    // A token-less service request is still refused.
    assert_eq!(
        send("POST", "/eees-eecregistration/v1/registrations").status,
        401
    );
    assert_eq!(
        send("GET", "/eees-easregistration/v1/registrations").status,
        401
    );
    // A leading `//` routes to the arm (the router trims leading slashes) but
    // is not the exempt shape: 401.
    assert_eq!(send("POST", &format!("/{route}")).status, 401);
    // Spellings the router does not route here: never 204, and at the gate
    // itself every one of them needs a bearer.
    let variants = [
        format!("{route}/"),
        format!("{route}/extra"),
        route.replace("d443a-edge-budget", "d443a%2Dedge-budget"),
        route.replace("qos-mon", "qos%2Dmon"),
        format!("{route}?x=1"),
        format!("/d443a-edge-budget/qos-mon/{token}%00"),
        "/D443A-EDGE-BUDGET/qos-mon/".to_string() + token,
    ];
    for v in &variants {
        assert_ne!(send("POST", v).status, 204, "{v}");
        let gate = auth::require_oauth2(&SbiRequest::post(v.clone()), edge_budget::SCOPE);
        assert_eq!(gate.map(|r| r.status), Some(401), "{v}");
    }
    assert!(
        edge_budget::latest_for_test().is_none(),
        "no refused request was used"
    );

    // Demo off: the route does not exist and nothing is exempt.
    edge_budget::install(None);
    assert!(oauth2_callback_exemptions().is_empty());
    auth::set_callback_exemptions(oauth2_callback_exemptions());
    assert_eq!(send("POST", &route).status, 404);
    let gate = auth::require_oauth2(&SbiRequest::post(route.clone()), edge_budget::SCOPE);
    assert_eq!(gate.map(|r| r.status), Some(401));
    // Even a stale list left installed admits nothing with the demo off: the
    // check is the live token.
    edge_budget::install(Some(edge_budget::Plan {
        mode: edge_budget::Mode::MeasuredBudget,
        config: edge_budget::Config::default(),
        token: token.into(),
    }));
    auth::set_callback_exemptions(oauth2_callback_exemptions());
    edge_budget::install(None);
    let gate = auth::require_oauth2(&SbiRequest::post(route.clone()), edge_budget::SCOPE);
    assert_eq!(gate.map(|r| r.status), Some(401));

    auth::set_callback_exemptions(Vec::new());
    edge_budget::clear_for_test();
    auth::clear_auth_jwks();
}

/// #1525, default build: no demo route, so nothing is exempt.
#[cfg(not(feature = "demo-d443a-edge-budget"))]
#[test]
fn a_default_build_registers_no_callback_exemption_1525() {
    let _g = auth::GLOBAL_STATE_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    assert!(oauth2_callback_exemptions().is_empty());
    let cfg = install_callback_exemptions(NextgcoreSbiServerConfig::new(
        "127.0.0.1:0".parse().unwrap(),
    ));
    assert!(cfg.oauth2_callback_exemptions.is_empty());
    assert!(auth::callback_exemption_routes().is_empty());
}
