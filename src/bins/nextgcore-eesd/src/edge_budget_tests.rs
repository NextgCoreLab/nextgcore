//! nextgsim#471: the demo's config, ranking, notification route and
//! subscription. Values: the plan's Act 1 / Act 2 (netem +16 ms on eas-local's
//! N6 path) shapes; the QOS_MON body is the one smfd builds (its own test pins
//! it), with the n6Delays member smfd's demo adds.

use super::*;
use crate::types::{EasServiceKpi, EndPoint};

fn yaml(s: &str) -> serde_yaml::Value {
    serde_yaml::from_str(s).unwrap()
}

fn eas(id: &str, ip: &str, max_resp_ms: Option<u32>, avl_comp: Option<u32>) -> EasProfile {
    EasProfile {
        eas_id: id.into(),
        end_pt: EndPoint {
            ipv4_addrs: Some(vec![ip.into()]),
            ..Default::default()
        },
        prov_id: None,
        eas_type: None,
        flex_eas_type: None,
        ac_ids: None,
        svc_area: None,
        svc_kpi: Some(EasServiceKpi {
            max_resp_time_ms: max_resp_ms,
            avl_comp,
            ..Default::default()
        }),
    }
}

/// The three sidecars: local (advertises 10 ms), regional (14 ms), cloud (40 ms).
fn three() -> Vec<Candidate> {
    [
        eas("eas-local", "10.60.0.11", Some(10), Some(50)),
        eas("eas-regional", "10.60.0.12", Some(14), Some(50)),
        eas("eas-cloud", "10.60.0.13", Some(40), Some(200)),
    ]
    .into_iter()
    .map(|eas| Candidate {
        eas,
        req_comp: Some("100".into()),
    })
    .collect()
}

fn sample(rt: u32, n6: &[(&str, u32)]) -> Sample {
    Sample {
        rt_ms: rt,
        supi: Some("imsi-001010000000471".into()),
        n6_ms: n6
            .iter()
            .map(|(ip, ms)| (ip.parse().unwrap(), *ms))
            .collect(),
        at: Instant::now(),
    }
}

fn ids(d: &Decision, c: &[Candidate]) -> Vec<String> {
    d.selected
        .iter()
        .map(|i| c[*i].eas.eas_id.clone())
        .collect()
}

#[test]
fn the_member_name_is_the_one_smfd_writes_471() {
    assert_eq!(VENDOR_MEMBER, "vendorSpecific-032473");
    assert_eq!(DEMO_KEY, "d443a-edge-budget");
    assert_eq!(MODES, ["measured-budget", "static"]);
}

#[test]
fn the_block_parses_with_defaults_and_refuses_what_is_malformed_471() {
    assert_eq!(
        config_from_root(&yaml("ees: {}")).unwrap(),
        Config::default()
    );
    assert_eq!(Config::default().deadline_ms, 15);
    let c = config_from_root(&yaml(
        "ees:\n  edge_budget:\n    smf_uri: http://smf.nextg:7777/\n    deadline_ms: 20\n    rep_period_s: 1\n    eas_n6_endpoints: {eas-local: 10.60.0.11, eas-v6: '::ffff:10.60.0.14'}\n",
    ))
    .unwrap();
    assert_eq!(c.smf_uri.as_deref(), Some("http://smf.nextg:7777"));
    assert_eq!((c.deadline_ms, c.rep_period_s), (20, 1));
    assert_eq!(
        c.eas_n6_endpoints["eas-local"],
        "10.60.0.11".parse::<IpAddr>().unwrap()
    );
    // An IPv4-mapped address is the IPv4 one, as smfd's store keys it.
    assert_eq!(
        c.eas_n6_endpoints["eas-v6"],
        "10.60.0.14".parse::<IpAddr>().unwrap()
    );
    for bad in [
        "ees:\n  edge_budget:\n    smf: http://x:1\n",
        "ees:\n  edge_budget:\n    smf_uri: smf:7777\n",
        "ees:\n  edge_budget:\n    smf_uri: http://smf:7777/nsmf\n",
        "ees:\n  edge_budget:\n    deadline_ms: 0\n",
        "ees:\n  edge_budget:\n    deadline_ms: fifteen\n",
        "ees:\n  edge_budget:\n    rep_period_s: -1\n",
        "ees:\n  edge_budget:\n    eas_n6_endpoints: {eas-local: not-an-ip}\n",
        "ees:\n  edge_budget:\n    eas_n6_endpoints: [10.60.0.11]\n",
        "ees:\n  edge_budget: 3\n",
    ] {
        assert!(config_from_root(&yaml(bad)).is_err(), "accepted: {bad}");
    }
}

/// Act 1 and Act 2 under `measured-budget`: rt 6 + 2·N6 + ceil(100/50).
/// Act 1 (N6 2/3/20): local 12, regional 14, cloud 47 → [local, regional].
/// Act 2 (+16 ms on local: N6 18): local 44 → [regional]. Nothing in any EAS's
/// advertisement changed between the two.
#[test]
fn measured_budget_follows_the_n6_delay_with_the_advertisement_unchanged_471() {
    let cfg = Config::default();
    let c = three();
    let act1 = rank(
        Mode::MeasuredBudget,
        &cfg,
        &c,
        Some(&sample(
            6,
            &[("10.60.0.11", 2), ("10.60.0.12", 3), ("10.60.0.13", 20)],
        )),
    );
    assert_eq!(act1.src, Src::Measured);
    assert_eq!(
        act1.budgets,
        vec![
            ("eas-local".into(), Ok(12)),
            ("eas-regional".into(), Ok(14)),
            ("eas-cloud".into(), Ok(47)),
        ]
    );
    assert_eq!(ids(&act1, &c), ["eas-local", "eas-regional"]);
    let act2 = rank(
        Mode::MeasuredBudget,
        &cfg,
        &c,
        Some(&sample(
            6,
            &[("10.60.0.11", 18), ("10.60.0.12", 3), ("10.60.0.13", 20)],
        )),
    );
    assert_eq!(act2.budgets[0], ("eas-local".into(), Ok(44)));
    assert_eq!(ids(&act2, &c), ["eas-regional"]);
    // With a looser local policy all three fit, ranked by budget, not eass order.
    let loose = Config {
        deadline_ms: 50,
        ..Config::default()
    };
    let ranked = rank(
        Mode::MeasuredBudget,
        &loose,
        &c,
        Some(&sample(
            6,
            &[("10.60.0.11", 18), ("10.60.0.12", 3), ("10.60.0.13", 20)],
        )),
    );
    assert_eq!(ids(&ranked, &c), ["eas-regional", "eas-local", "eas-cloud"]);
    // Act 3 (+20 ms on the gNB's N3: rt 26): nothing within 15 ms.
    let act3 = rank(
        Mode::MeasuredBudget,
        &cfg,
        &c,
        Some(&sample(
            26,
            &[("10.60.0.11", 2), ("10.60.0.12", 3), ("10.60.0.13", 20)],
        )),
    );
    assert!(act3.selected.is_empty());
}

/// `static` ranks on `maxRespTime` whatever was measured: Act 2's netem keeps
/// eas-local (the baseline arm).
#[test]
fn static_ranks_on_the_advertisement_whatever_was_measured_471() {
    let cfg = Config::default();
    let c = three();
    let d = rank(
        Mode::Static,
        &cfg,
        &c,
        Some(&sample(6, &[("10.60.0.11", 18)])),
    );
    assert_eq!(d.src, Src::Static);
    assert_eq!(ids(&d, &c), ["eas-local", "eas-regional"]);
    // measured-budget with no current report: the same ranking, labelled.
    let f = rank(Mode::MeasuredBudget, &cfg, &c, None);
    assert_eq!(f.src, Src::StaticFallback);
    assert_eq!(f.selected, d.selected);
    assert_eq!(Src::Measured.as_str(), "upf-n3+upf-n6");
    assert_eq!(Src::StaticFallback.as_str(), "static-fallback");
}

/// A budget that cannot be formed is not within the deadline, and says why;
/// equal budgets keep the candidates' order; the configured endpoint wins over
/// the registered address.
#[test]
fn an_unformable_budget_is_never_within_the_deadline_471() {
    let mut cfg = Config::default();
    let mut c = three();
    c[0].req_comp = Some("lots".into());
    c[1].eas.svc_kpi.as_mut().unwrap().avl_comp = None;
    let s = sample(6, &[("10.60.0.11", 1), ("10.60.0.12", 1)]);
    let d = rank(Mode::MeasuredBudget, &cfg, &c, Some(&s));
    assert_eq!(
        d.budgets,
        vec![
            ("eas-local".into(), Err("reqcomp-not-integer")),
            ("eas-regional".into(), Err("no-avlcomp")),
            ("eas-cloud".into(), Err("no-n6")),
        ]
    );
    assert!(d.selected.is_empty());

    let mut c = three();
    for x in &mut c {
        x.req_comp = None;
    }
    c[2].eas.end_pt.ipv4_addrs = None;
    c[2].eas.end_pt.fqdn = Some("eas-cloud.example".into());
    cfg.eas_n6_endpoints
        .insert("eas-regional".into(), "10.60.0.11".parse().unwrap());
    let d = rank(Mode::MeasuredBudget, &cfg, &c, Some(&s));
    assert_eq!(d.budgets[0].1, Ok(8));
    assert_eq!(
        d.budgets[1].1,
        Ok(8),
        "regional measured at the configured .11"
    );
    assert_eq!(d.budgets[2].1, Err("no-n6-endpoint"));
    assert_eq!(
        ids(&d, &c),
        ["eas-local", "eas-regional"],
        "ties keep eass order"
    );
    // A missing advertisement under static: not within the deadline.
    c[0].eas.svc_kpi = None;
    let d = rank(Mode::Static, &cfg, &c, None);
    assert_eq!(d.budgets[0].1, Err("no-maxresptime"));
    assert_eq!(ids(&d, &c), ["eas-regional"]);
}

/// ceil, and no overflow on a huge reqComp.
#[test]
fn the_compute_term_is_the_ceiling_471() {
    let e = eas("e", "10.0.0.1", None, Some(3));
    assert_eq!(compute_ms(Some("10"), &e), Ok(4));
    assert_eq!(compute_ms(Some(" 9 "), &e), Ok(3));
    assert_eq!(compute_ms(None, &e), Ok(0));
    assert_eq!(compute_ms(Some("18446744073709551615"), &e), Ok(u32::MAX));
    let zero = eas("e", "10.0.0.1", None, Some(0));
    assert_eq!(compute_ms(Some("1"), &zero), Err("no-avlcomp"));
}

fn plan_on(mode: Mode) -> Plan {
    Plan {
        mode,
        config: Config::default(),
        token: "0123456789abcdef0123456789abcdef".into(),
    }
}

/// The QOS_MON body smfd sends with the demo on (smfd's
/// `the_notification_carries_the_psa_upf_s_n6_delays_only_when_on_471`).
pub(crate) fn qos_mon_body(rt: u32, n6_local: u32) -> String {
    serde_json::json!({
        "notifId": NOTIF_ID,
        "eventNotifs": [{
            "event": "QOS_MON",
            "timeStamp": "2026-11-15T10:00:00Z",
            "supi": "imsi-001010000000471",
            "pduSeId": 1,
            "ulDelays": [rt / 2], "dlDelays": [rt / 2], "rtDelays": [rt],
            VENDOR_MEMBER: { "n6Delays": [
                { "endpoint": "10.60.0.11", "avgMs": n6_local },
                { "endpoint": "10.60.0.12", "avgMs": 3, "minMs": 2, "maxMs": 4 },
            ]},
        }],
    })
    .to_string()
}

fn notify(token: &str, body: &str) -> Option<SbiResponse> {
    let req = SbiRequest::post(format!("/{ROUTE_ROOT}/{ROUTE_QOS_MON}/{token}"))
        .with_body(body, "application/json");
    on_notify(token, &req)
}

/// The right token stores the report (rt and the N6 member); a wrong one is a
/// 404 that changes nothing and is counted; another notifId is acknowledged and
/// ignored; a body that is not JSON is a 400; off, the route does not exist.
#[test]
fn only_the_path_token_s_notifications_are_used_471() {
    let _l = lock_for_test();
    install(None);
    clear_for_test();
    assert!(notify("x", "{}").is_none(), "demo off: no route");

    install(Some(plan_on(Mode::MeasuredBudget)));
    let wrong_before = NOTIFICATIONS.get(&["wrong-token"]);
    let r = notify("0123456789abcdef0123456789abcdee", &qos_mon_body(6, 18)).unwrap();
    assert_eq!(r.status, 404);
    assert_eq!(NOTIFICATIONS.get(&["wrong-token"]), wrong_before + 1);
    assert!(latest_for_test().is_none(), "a wrong token changes nothing");
    assert_eq!(notify("", &qos_mon_body(6, 18)).unwrap().status, 404);
    assert!(latest_for_test().is_none());

    let ok_before = NOTIFICATIONS.get(&["accepted"]);
    let r = notify("0123456789abcdef0123456789abcdef", &qos_mon_body(6, 18)).unwrap();
    assert_eq!(r.status, 204);
    assert_eq!(NOTIFICATIONS.get(&["accepted"]), ok_before + 1);
    let s = latest_for_test().unwrap();
    assert_eq!(s.rt_ms, 6);
    assert_eq!(s.supi.as_deref(), Some("imsi-001010000000471"));
    assert_eq!(
        s.n6_ms,
        [("10.60.0.11", 18), ("10.60.0.12", 3)]
            .iter()
            .map(|(ip, ms)| (ip.parse::<IpAddr>().unwrap(), *ms))
            .collect::<BTreeMap<_, _>>()
    );

    let other = qos_mon_body(30, 30).replace(NOTIF_ID, "someone-else");
    let r = notify("0123456789abcdef0123456789abcdef", &other).unwrap();
    assert_eq!(r.status, 204);
    assert_eq!(latest_for_test().unwrap().rt_ms, 6, "not ours: ignored");
    let r = notify("0123456789abcdef0123456789abcdef", "not json").unwrap();
    assert_eq!(r.status, 400);

    // Only POST, and only QOS_MON entries (#1523 review o1).
    clear_for_test();
    let get = SbiRequest::get(format!(
        "/{ROUTE_ROOT}/{ROUTE_QOS_MON}/0123456789abcdef0123456789abcdef"
    ))
    .with_body(qos_mon_body(6, 2), "application/json");
    assert_eq!(
        on_notify("0123456789abcdef0123456789abcdef", &get)
            .unwrap()
            .status,
        405
    );
    assert!(latest_for_test().is_none(), "a GET is not a notification");
    let other_event = qos_mon_body(6, 2).replace("\"QOS_MON\"", "\"PDU_SES_EST\"");
    let r = notify("0123456789abcdef0123456789abcdef", &other_event).unwrap();
    assert_eq!(r.status, 204);
    assert!(
        latest_for_test().is_none(),
        "a PDU_SES_EST entry carries no budget"
    );

    install(None);
    clear_for_test();
}

#[test]
fn the_subscription_asks_for_qos_mon_any_ue_periodic_with_qos_monitoring_471() {
    let b = subscription_body("http://10.0.0.31:7814/d443a-edge-budget/qos-mon/t", 2);
    assert_eq!(b["notifId"], NOTIF_ID);
    assert_eq!(b["eventSubs"], serde_json::json!([{ "event": "QOS_MON" }]));
    assert_eq!(b["anyUeInd"], true);
    assert_eq!(b["notifMethod"], "PERIODIC");
    assert_eq!(b["repPeriod"], 2);
    assert_eq!(b["supportedFeatures"], "10");
    assert!(b.get("supi").is_none());
    assert_eq!(
        notif_uri(false, "fd00::31", 7814, "t"),
        "http://[fd00::31]:7814/d443a-edge-budget/qos-mon/t"
    );
    assert_eq!(
        notif_uri(true, "ees.nextg", 7814, "t"),
        "https://ees.nextg:7814/d443a-edge-budget/qos-mon/t"
    );
    let t = mint_token().unwrap();
    assert_eq!(t.len(), 32);
    assert!(t.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_ne!(t, mint_token().unwrap());
    assert_eq!(path_of("http://smf:7777/a/b"), "/a/b");
    assert_eq!(path_of("/a/b"), "/a/b");
}

/// A stand-in SMF: POST answers 201 + Location; the first GET answers 404 (the SMF
/// restarted), later GETs 200. The subscriber must subscribe, find it gone, and
/// subscribe again.
#[test]
fn a_subscription_gone_at_the_smf_is_re_created_471() {
    let _l = lock_for_test();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let log = Arc::new(Mutex::new(Vec::<(String, String, Option<Value>)>::new()));
        let sink = log.clone();
        let (server, addr) =
            nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
                let sink = sink.clone();
                async move {
                    let body = req
                        .http
                        .content
                        .as_deref()
                        .and_then(|c| serde_json::from_str(c).ok());
                    let mut l = sink.lock().unwrap();
                    l.push((req.header.method.clone(), req.header.uri.clone(), body));
                    let gets = l.iter().filter(|(m, _, _)| m == "GET").count();
                    match req.header.method.as_str() {
                        "POST" => SbiResponse::with_status(201).with_header(
                            "Location",
                            format!("/nsmf-event-exposure/v1/subscriptions/s{}", l.len()),
                        ),
                        "GET" if gets == 1 => SbiResponse::with_status(404),
                        _ => SbiResponse::with_status(200),
                    }
                }
            })
            .await;
        let task = tokio::spawn(run_subscriber(
            format!("http://127.0.0.1:{}", addr.port()),
            "http://127.0.0.1:1/d443a-edge-budget/qos-mon/t".into(),
            2,
            Duration::from_millis(50),
        ));
        let deadline = Instant::now() + Duration::from_secs(5);
        while log.lock().unwrap().len() < 4 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        task.abort();
        server.stop().await.ok();
        let l = log.lock().unwrap().clone();
        let methods: Vec<&str> = l.iter().take(4).map(|(m, _, _)| m.as_str()).collect();
        assert_eq!(methods, ["POST", "GET", "POST", "GET"], "{l:?}");
        assert_eq!(l[0].1, "/nsmf-event-exposure/v1/subscriptions");
        assert_eq!(l[1].1, "/nsmf-event-exposure/v1/subscriptions/s1");
        assert_eq!(l[3].1, "/nsmf-event-exposure/v1/subscriptions/s3");
        assert_eq!(l[0].2.as_ref().unwrap()["anyUeInd"], true);
    });
    clear_for_test();
}

#[test]
fn the_metrics_name_the_selection_source_471() {
    let _l = lock_for_test();
    clear_for_test();
    SELECTIONS.inc(&["upf-n3+upf-n6", "201"]);
    let m = render_metrics();
    assert!(
        m.contains("eees_selection_total{src=\"upf-n3+upf-n6\",result=\"201\"}"),
        "{m}"
    );
    assert!(m.contains("# TYPE eees_d443a_qos_mon_notifications_total counter"));
    assert!(m.contains("eees_d443a_qos_mon_subscribed 0"));
}

/// A report older than three report periods is not current: measured-budget
/// then ranks on the advertisement (static-fallback), and says so.
#[test]
fn a_stale_report_is_not_used_471() {
    let _l = lock_for_test();
    let cfg = Config {
        rep_period_s: 1,
        ..Config::default()
    };
    let mut s = sample(6, &[("10.60.0.11", 2)]);
    set_latest_for_test(Some(s.clone()));
    assert_eq!(current_sample(&cfg).map(|c| c.rt_ms), Some(6));
    s.at = Instant::now() - Duration::from_secs(4);
    set_latest_for_test(Some(s));
    assert!(current_sample(&cfg).is_none(), "4 s > 3 x 1 s");
    clear_for_test();
}

/// A stand-in SMF answering POST with 201 + Location (or with `post_status`),
/// recording every request. `(server, port, log)`.
async fn stand_in_smf(
    post_status: u16,
) -> (
    nextgcore_sbi::server::SbiServer,
    u16,
    Arc<Mutex<Vec<(String, String)>>>,
) {
    stand_in_smf_with(post_status, Duration::ZERO, 200).await
}

/// [`stand_in_smf`] whose first POST answers after `post_delay`, and whose GET
/// answers `get_status`; POSTs after the first answer 503.
async fn stand_in_smf_with(
    post_status: u16,
    post_delay: Duration,
    get_status: u16,
) -> (
    nextgcore_sbi::server::SbiServer,
    u16,
    Arc<Mutex<Vec<(String, String)>>>,
) {
    let log = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let sink = log.clone();
    let (server, addr) =
        nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
            let sink = sink.clone();
            async move {
                let posts = {
                    let mut l = sink.lock().unwrap();
                    l.push((req.header.method.clone(), req.header.uri.clone()));
                    l.iter().filter(|(m, _)| m == "POST").count()
                };
                match req.header.method.as_str() {
                    "POST" if posts > 1 && (!post_delay.is_zero() || get_status == 404) => {
                        SbiResponse::with_status(503)
                    }
                    "POST" if post_status == 201 => {
                        tokio::time::sleep(post_delay).await;
                        SbiResponse::with_status(201)
                            .with_header("Location", "/nsmf-event-exposure/v1/subscriptions/s471")
                    }
                    "POST" => SbiResponse::with_status(post_status),
                    "DELETE" => SbiResponse::with_status(204),
                    _ => SbiResponse::with_status(get_status),
                }
            }
        })
        .await;
    (server, addr.port(), log)
}

/// #1523 review M1: on shutdown the held subscription is DELETEd at the SMF, and
/// the subscriber creates no other one afterwards.
#[test]
fn shutdown_deletes_the_held_subscription_471() {
    let _l = lock_for_test();
    clear_for_test();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (server, port, log) = stand_in_smf(201).await;
        let task = tokio::spawn(run_subscriber(
            format!("http://127.0.0.1:{port}"),
            "http://127.0.0.1:1/d443a-edge-budget/qos-mon/t".into(),
            2,
            Duration::from_millis(50),
        ));
        let deadline = Instant::now() + Duration::from_secs(5);
        while !log.lock().unwrap().iter().any(|(m, _)| m == "POST") && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            release_subscription(Duration::from_secs(2)).await,
            Some(204)
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while !task.is_finished() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(task.is_finished(), "the subscriber stops after shutdown");
        server.stop().await.ok();
        let l = log.lock().unwrap().clone();
        assert!(
            l.contains(&(
                "DELETE".to_string(),
                "/nsmf-event-exposure/v1/subscriptions/s471".to_string()
            )),
            "{l:?}"
        );
        assert_eq!(l.iter().filter(|(m, _)| m == "POST").count(), 1, "{l:?}");
        // Nothing held any more: a second release sends nothing.
        assert_eq!(release_subscription(Duration::from_secs(1)).await, None);
    });
    clear_for_test();
}

/// #1523 review o2: an SMF that refuses the Subscribe (401: no access token,
/// nextgcore#1529) is counted as `refused`, not left to look like "no data".
#[test]
fn a_refused_subscribe_is_counted_471() {
    let _l = lock_for_test();
    clear_for_test();
    let before = SUBSCRIBE_FAILURES.get(&["refused"]);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (server, port, _log) = stand_in_smf(401).await;
        let task = tokio::spawn(run_subscriber(
            format!("http://127.0.0.1:{port}"),
            "http://127.0.0.1:1/d443a-edge-budget/qos-mon/t".into(),
            2,
            Duration::from_millis(50),
        ));
        let deadline = Instant::now() + Duration::from_secs(5);
        while SUBSCRIBE_FAILURES.get(&["refused"]) == before && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        task.abort();
        server.stop().await.ok();
    });
    assert!(SUBSCRIBE_FAILURES.get(&["refused"]) > before);
    assert!(render_metrics()
        .contains("eees_d443a_qos_mon_subscribe_failures_total{reason=\"refused\"}"));
    clear_for_test();
}

/// #1523 review r2: shutdown while the Subscribe is in flight. `release` finds
/// nothing held; the 201 that lands afterwards is deleted at once and the
/// subscriber stops.
#[test]
fn a_subscribe_answered_after_shutdown_is_deleted_at_once_471() {
    let _l = lock_for_test();
    clear_for_test();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (server, port, log) = stand_in_smf_with(201, Duration::from_millis(400), 200).await;
        let task = tokio::spawn(run_subscriber(
            format!("http://127.0.0.1:{port}"),
            "http://127.0.0.1:1/d443a-edge-budget/qos-mon/t".into(),
            2,
            Duration::from_millis(50),
        ));
        let deadline = Instant::now() + Duration::from_secs(5);
        while !log.lock().unwrap().iter().any(|(m, _)| m == "POST") && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            release_subscription(Duration::from_secs(1)).await,
            None,
            "nothing held yet"
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while !task.is_finished() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(task.is_finished(), "the subscriber stops");
        server.stop().await.ok();
        let l = log.lock().unwrap().clone();
        assert!(
            l.contains(&(
                "DELETE".to_string(),
                "/nsmf-event-exposure/v1/subscriptions/s471".to_string()
            )),
            "{l:?}"
        );
        assert!(held_for_test().is_none());
    });
    clear_for_test();
}

/// #1523 review r2: a subscription the SMF reports gone is no longer held, so
/// shutdown does not DELETE it.
#[test]
fn a_subscription_gone_at_the_smf_is_no_longer_held_471() {
    let _l = lock_for_test();
    clear_for_test();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (server, port, log) = stand_in_smf_with(201, Duration::ZERO, 404).await;
        let task = tokio::spawn(run_subscriber(
            format!("http://127.0.0.1:{port}"),
            "http://127.0.0.1:1/d443a-edge-budget/qos-mon/t".into(),
            2,
            Duration::from_millis(50),
        ));
        let deadline = Instant::now() + Duration::from_secs(5);
        while log
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, _)| m == "POST")
            .count()
            < 2
            && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // GET 404 seen, the re-create refused (503): nothing is held.
        assert!(log.lock().unwrap().iter().any(|(m, _)| m == "GET"));
        assert!(held_for_test().is_none(), "a gone subscription is not held");
        assert_eq!(release_subscription(Duration::from_secs(1)).await, None);
        task.abort();
        server.stop().await.ok();
        assert!(!log.lock().unwrap().iter().any(|(m, _)| m == "DELETE"));
    });
    clear_for_test();
}

/// #1523 re-review r3, the shutdown path main takes: SIGTERM while the Subscribe
/// to a slow SMF is in flight. `release_subscription` waits (within its bound)
/// for the subscriber started by `start_subscriber`, so by the time it returns
/// the late 201 has been DELETEd: nothing is left for a dropped runtime to cancel.
/// (main itself is not driven: it needs a process and a signal; it calls exactly
/// this before stopping the SBI server.)
#[test]
fn shutdown_waits_for_an_in_flight_subscribe_471() {
    let _l = lock_for_test();
    clear_for_test();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (server, port, log) = stand_in_smf_with(201, Duration::from_millis(400), 200).await;
        start_subscriber(
            format!("http://127.0.0.1:{port}"),
            "http://127.0.0.1:1/d443a-edge-budget/qos-mon/t".into(),
            2,
            Duration::from_secs(30),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while !log.lock().unwrap().iter().any(|(m, _)| m == "POST") && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let started = Instant::now();
        release_subscription(Duration::from_secs(2)).await;
        // Checked as soon as release returns: no polling after it.
        let l = log.lock().unwrap().clone();
        assert!(
            l.contains(&(
                "DELETE".to_string(),
                "/nsmf-event-exposure/v1/subscriptions/s471".to_string()
            )),
            "the late 201 is deleted before shutdown proceeds: {l:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "within the bound"
        );
        assert!(SUBSCRIBER.lock().unwrap().is_none());
        server.stop().await.ok();
    });
    clear_for_test();
}

/// Idle (between checks, a 30 s interval) the subscriber is woken at shutdown,
/// so release returns at once rather than after the bound.
#[test]
fn shutdown_wakes_an_idle_subscriber_471() {
    let _l = lock_for_test();
    clear_for_test();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (server, port, log) = stand_in_smf(201).await;
        start_subscriber(
            format!("http://127.0.0.1:{port}"),
            "http://127.0.0.1:1/d443a-edge-budget/qos-mon/t".into(),
            2,
            Duration::from_secs(30),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while held_for_test().is_none() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let started = Instant::now();
        assert_eq!(
            release_subscription(Duration::from_secs(2)).await,
            Some(204)
        );
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "{:?}",
            started.elapsed()
        );
        server.stop().await.ok();
        assert_eq!(
            log.lock()
                .unwrap()
                .iter()
                .filter(|(m, _)| m == "POST")
                .count(),
            1
        );
    });
    clear_for_test();
}
