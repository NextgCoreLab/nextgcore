//! #2221: the AF's QoS monitoring subscription through pcfd's real router, to
//! the SmPolicyDecision the SMF is sent and back to the AF.

use super::*;
use std::sync::{Arc, Mutex};

type Seen = Arc<Mutex<Vec<(String, serde_json::Value)>>>;

/// `req` (a POST, or the one DELETE) with `body` as its JSON.
fn with_body(req: SbiRequest, body: serde_json::Value) -> SbiRequest {
    req.with_json_body(&body).expect("encode test body")
}

/// POST `body` to `uri` through pcfd's router: the status and the JSON answered.
async fn route(uri: &str, body: serde_json::Value) -> (u16, serde_json::Value) {
    let resp = pcf_sbi_request_handler(with_body(SbiRequest::post(uri), body)).await;
    let json = resp
        .http
        .content
        .as_deref()
        .and_then(|c| serde_json::from_str(c).ok())
        .unwrap_or(serde_json::Value::Null);
    (resp.status, json)
}

/// The SMF and the AF in one: every POST it is sent, by path.
async fn recorder() -> (Seen, u16, nextgcore_sbi::server::SbiServer) {
    let seen: Seen = Arc::default();
    let sink = seen.clone();
    let (server, addr) =
        nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
            let sink = sink.clone();
            async move {
                let body = req
                    .http
                    .content
                    .as_deref()
                    .and_then(|c| serde_json::from_str(c).ok())
                    .unwrap_or(serde_json::Value::Null);
                sink.lock().unwrap().push((req.header.uri.clone(), body));
                SbiResponse::with_status(204)
            }
        })
        .await;
    (seen, addr.port(), server)
}

/// The next body POSTed to a path ending in `suffix` that satisfies `pred`.
async fn next_post(
    seen: &Seen,
    suffix: &str,
    pred: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    for _ in 0..300 {
        let hit = seen
            .lock()
            .unwrap()
            .iter()
            .find(|(u, b)| u.ends_with(suffix) && pred(b))
            .map(|(_, b)| b.clone());
        if let Some(b) = hit {
            seen.lock().unwrap().clear();
            return b;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("nothing POSTed to *{suffix}: {:?}", seen.lock().unwrap());
}

/// An SM policy for `ipv4` from an SMF offering `supp_feat`, notified at the
/// recorder. Returns the smPolicyId and the answered suppFeat.
async fn sm_policy(port: u16, supi: &str, ipv4: &str, supp_feat: &str) -> (String, String) {
    let (status, body) = route(
        "/npcf-smpolicycontrol/v1/sm-policies",
        serde_json::json!({
            "supi": supi,
            "pduSessionId": 5,
            "pduSessionType": "IPV4",
            "dnn": "internet",
            "notificationUri": format!("http://127.0.0.1:{port}/smf/{supi}"),
            "ipv4Address": ipv4,
            "sliceInfo": { "sst": 1 },
            "servingNetwork": { "mcc": "001", "mnc": "01" },
            "suppFeat": supp_feat,
        }),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    (
        body["smPolicyId"].as_str().unwrap().to_string(),
        body["suppFeat"].as_str().unwrap().to_string(),
    )
}

/// An AF app session on `ipv4` with one media component and `ev_subsc`.
fn af_body(
    port: u16,
    ipv4: &str,
    supp_feat: &str,
    ev_subsc: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "notifUri": format!("http://127.0.0.1:{port}/af"),
        "suppFeat": supp_feat,
        "ueIpv4": ipv4,
        "medComponents": { "1": {
            "medCompN": 1,
            "medType": "AUDIO",
            "marBwDl": "256 Kbps",
            "marBwUl": "128 Kbps",
            "medSubComps": { "1": { "fNum": 1, "fDescs": ["permit out ip from any to assigned"] } },
        }},
        "evSubsc": ev_subsc,
    })
}

fn qos_mon_subsc() -> serde_json::Value {
    serde_json::json!({
        "events": [
            { "event": "QOS_MONITORING", "notifMethod": "PERIODIC", "repPeriod": 5 },
            { "event": "QOS_MONITORING", "notifMethod": "EVENT_DETECTION", "waitTime": 2 },
        ],
        "reqQosMonParams": ["DOWNLINK", "ROUND_TRIP"],
        "qosMon": { "repThreshDl": 20 },
    })
}

/// SM features 24 (QosMonitoring) and 73 (PacketDelayFailureReport).
fn sm_24_73() -> String {
    format!("1{}800000", "0".repeat(12))
}

/// PA features 16 (QoSMonitoring) and 44 (PacketDelayFailureReport).
const PA_16_44: &str = "80000008000";

/// #2221, TS 23.503 §6.1.3.21 / TS 29.512 §4.2.3.25.1 / TS 29.514 §4.2.2.23.1:
/// - an AF app session subscribing to QOS_MONITORING has the SMF sent a
///   `QosMonitoringData` (`qosMonDecs`) referenced from its PCC rule
///   (`refQosMon`), with QOS_MONITORING added to the create's triggers;
/// - the SMF's `qosMonReports` (§4.2.4.24) are answered with an empty decision
///   and reach the AF as `flows` (TS 29.514 §4.2.5.14);
/// - unsubscribing withdraws it: `refQosMon: null`, the triggers without it.
/// Features 24 and 73 (SM) and 16 and 44 (PA) are negotiated.
///
/// REVERT-VERIFIED: see the PR.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)] // std guard held across .await to serialize the process-global PCF context
async fn an_af_qos_monitoring_subscription_is_the_smf_s_policy_and_its_reports_reach_the_af_2221() {
    let _guard = crate::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    crate::test_support::init_context();
    let (seen, port, server) = recorder().await;
    let (pol, sm_feat) = sm_policy(port, "imsi-001010000022210", "10.45.22.10", &sm_24_73()).await;
    assert_eq!(sm_feat, sm_24_73(), "24 and 73 negotiated");

    let (status, asc) = route(
        "/npcf-policyauthorization/v1/app-sessions",
        af_body(port, "10.45.22.10", PA_16_44, qos_mon_subsc()),
    )
    .await;
    assert_eq!(status, 201, "{asc}");
    assert_eq!(asc["suppFeat"], PA_16_44, "16 and 44 negotiated");
    let app_session_id = asc["appSessionId"].as_str().unwrap().to_string();
    let qm = format!("QosMon-{app_session_id}");

    let n = next_post(&seen, "/update", |b| {
        b["smPolicyDecision"].get("qosMonDecs").is_some()
    })
    .await;
    let d = &n["smPolicyDecision"];
    assert_eq!(
        d["qosMonDecs"][&qm],
        serde_json::json!({
            "qmId": qm,
            "reqQosMonParams": ["DOWNLINK", "ROUND_TRIP"],
            "repFreqs": ["PERIODIC", "EVENT_TRIGGERED"],
            "repPeriod": 5,
            "waitTime": 2,
            "repThreshDl": 20,
        })
    );
    let rules = d["pccRules"].as_object().unwrap();
    assert_eq!(rules.len(), 1);
    let (rule_id, rule) = rules.iter().next().unwrap();
    assert_eq!(rule["refQosMon"], serde_json::json!([qm]));
    let triggers = d["policyCtrlReqTriggers"].as_array().unwrap();
    assert!(
        triggers.contains(&serde_json::json!("QOS_MONITORING")),
        "{triggers:?}"
    );
    assert!(
        triggers.contains(&serde_json::json!("SE_AMBR_CH")),
        "the create's, restated: {triggers:?}"
    );

    // The SMF reports (TS 29.512 §4.2.4.24).
    let (status, answer) = route(
        &format!("/npcf-smpolicycontrol/v1/sm-policies/{pol}/update"),
        serde_json::json!({
            "repPolicyCtrlReqTriggers": ["QOS_MONITORING"],
            "qosMonReports": [
                { "refPccRuleIds": [rule_id], "dlDelays": [13], "rtDelays": [27] },
                { "refPccRuleIds": [rule_id], "pdmf": true },
            ],
        }),
    )
    .await;
    assert_eq!(
        (status, answer),
        (200, serde_json::json!({})),
        "an empty decision"
    );
    let af = next_post(&seen, "/af/notify", |_| true).await;
    assert_eq!(
        af["evNotifs"],
        serde_json::json!([{ "event": "QOS_MONITORING" }])
    );
    assert_eq!(
        af["qosMonReports"],
        serde_json::json!([
            { "flows": [{ "medCompN": 1 }], "dlDelays": [13], "rtDelays": [27] },
            { "flows": [{ "medCompN": 1 }], "pdmf": true },
        ])
    );

    // Unsubscribed: withdrawn at the SMF.
    let resp = pcf_sbi_request_handler(SbiRequest::delete(format!(
        "/npcf-policyauthorization/v1/app-sessions/{app_session_id}/events-subscription"
    )))
    .await;
    assert_eq!(resp.status, 204);
    let n = next_post(&seen, "/update", |_| true).await;
    let d = &n["smPolicyDecision"];
    assert!(d["pccRules"][rule_id]["refQosMon"].is_null(), "{d}");
    assert!(d.get("qosMonDecs").is_none(), "{d}");
    let triggers = d["policyCtrlReqTriggers"].as_array().unwrap();
    assert!(
        !triggers.contains(&serde_json::json!("QOS_MONITORING")),
        "{triggers:?}"
    );
    assert!(
        triggers.contains(&serde_json::json!("SE_AMBR_CH")),
        "{triggers:?}"
    );
    server.stop().await.ok();
}

/// #2221: without QosMonitoring negotiated with the SMF, or QoSMonitoring with
/// the AF, no policy is generated, and the AF's decision is sent as before: no
/// `qosMonDecs`, no `refQosMon`, no `policyCtrlReqTriggers`. Without
/// PacketDelayFailureReport, an EVENT_DETECTION `repPeriod` is not passed on.
///
/// REVERT-VERIFIED: see the PR.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)] // std guard held across .await to serialize the process-global PCF context
async fn qos_monitoring_needs_the_features_negotiated_on_both_legs_2221() {
    let _guard = crate::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    crate::test_support::init_context();
    let (seen, port, server) = recorder().await;
    for (n, sm, pa) in [(11, "100", "8000"), (12, "800000", "0")] {
        let ip = format!("10.45.22.{n}");
        let (_, sm_feat) = sm_policy(port, &format!("imsi-0010100000222{n}"), &ip, sm).await;
        assert_eq!(sm_feat, if sm == "100" { "100" } else { "800000" });
        let (status, _) = route(
            "/npcf-policyauthorization/v1/app-sessions",
            af_body(port, &ip, pa, qos_mon_subsc()),
        )
        .await;
        assert_eq!(status, 201);
        let n = next_post(&seen, "/update", |_| true).await;
        let d = &n["smPolicyDecision"];
        assert!(d.get("qosMonDecs").is_none(), "SM {sm}, PA {pa}: {d}");
        assert!(
            d.get("policyCtrlReqTriggers").is_none(),
            "SM {sm}, PA {pa}: {d}"
        );
        let rule = d["pccRules"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .clone();
        assert!(rule.get("refQosMon").is_none(), "SM {sm}, PA {pa}: {rule}");
    }

    // 24 and 16 without 73 / 44: the event-triggered repPeriod is dropped.
    let ip = "10.45.22.13";
    let _ = sm_policy(port, "imsi-001010000022213", ip, "800000").await;
    let subsc = serde_json::json!({
        "events": [{ "event": "QOS_MONITORING", "notifMethod": "EVENT_DETECTION", "waitTime": 2, "repPeriod": 30 }],
        "reqQosMonParams": ["UPLINK"],
        "qosMon": { "repThreshUl": 10 },
    });
    let (status, _) = route(
        "/npcf-policyauthorization/v1/app-sessions",
        af_body(port, ip, PA_16_44, subsc),
    )
    .await;
    assert_eq!(status, 201);
    let n = next_post(&seen, "/update", |b| {
        b["smPolicyDecision"].get("qosMonDecs").is_some()
    })
    .await;
    let dec = n["smPolicyDecision"]["qosMonDecs"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .clone();
    assert_eq!(dec["repFreqs"], serde_json::json!(["EVENT_TRIGGERED"]));
    assert!(dec.get("repPeriod").is_none(), "{dec}");
    server.stop().await.ok();
}

/// [`af_body`] for the AF at `/<af>`.
fn af_body_at(
    port: u16,
    af: &str,
    ipv4: &str,
    supp_feat: &str,
    ev_subsc: serde_json::Value,
) -> serde_json::Value {
    let mut body = af_body(port, ipv4, supp_feat, ev_subsc);
    body["notifUri"] = serde_json::json!(format!("http://127.0.0.1:{port}/{af}"));
    body
}

/// The PCC rules app session `app_session_id` installed.
fn rules_of(app_session_id: &str) -> Vec<String> {
    pcf_self()
        .read()
        .unwrap()
        .app_find_by_app_session_id(app_session_id)
        .expect("the app session")
        .pcc_rule_ids
}

async fn af_session(port: u16, af: &str, ipv4: &str) -> String {
    let (status, asc) = route(
        "/npcf-policyauthorization/v1/app-sessions",
        af_body_at(port, af, ipv4, PA_16_44, qos_mon_subsc()),
    )
    .await;
    assert_eq!(status, 201, "{asc}");
    asc["appSessionId"].as_str().unwrap().to_string()
}

/// #2221 (R47 M1): two AFs on one PDU session, each numbering its media from 1,
/// get a PCC rule each, each referencing only its own QoS monitoring instance,
/// and a report on one AF's rule reaches only that AF (TS 29.514 §4.2.5.14).
/// Keyed by (PDU session, medCompN) the second AF overwrote the first's rule,
/// and the report went to both.
///
/// REVERT-VERIFIED: see the PR.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)] // std guard held across .await to serialize the process-global PCF context
async fn each_af_on_a_pdu_session_gets_only_its_own_qos_monitoring_reports_2221() {
    let _guard = crate::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    crate::test_support::init_context();
    let (seen, port, server) = recorder().await;
    let ip = "10.45.22.20";
    let (pol, _) = sm_policy(port, "imsi-001010000022220", ip, &sm_24_73()).await;
    let a = af_session(port, "afA", ip).await;
    let _ = next_post(&seen, "/update", |_| true).await;
    let b = af_session(port, "afB", ip).await;
    let n = next_post(&seen, "/update", |d| {
        d["smPolicyDecision"]["pccRules"]
            .as_object()
            .is_some_and(|r| r.len() == 2)
    })
    .await;
    let (rule_a, rule_b) = (rules_of(&a), rules_of(&b));
    assert_eq!((rule_a.len(), rule_b.len()), (1, 1));
    assert_ne!(rule_a, rule_b, "a rule per app session");
    let rules = &n["smPolicyDecision"]["pccRules"];
    assert_eq!(
        rules[&rule_a[0]]["refQosMon"],
        serde_json::json!([format!("QosMon-{a}")])
    );
    assert_eq!(
        rules[&rule_b[0]]["refQosMon"],
        serde_json::json!([format!("QosMon-{b}")])
    );

    let (status, _) = route(
        &format!("/npcf-smpolicycontrol/v1/sm-policies/{pol}/update"),
        serde_json::json!({
            "repPolicyCtrlReqTriggers": ["QOS_MONITORING"],
            "qosMonReports": [{ "refPccRuleIds": [rule_b[0]], "dlDelays": [9] }],
        }),
    )
    .await;
    assert_eq!(status, 200);
    let to_b = next_post(&seen, "/afB/notify", |_| true).await;
    assert_eq!(to_b["qosMonReports"][0]["dlDelays"], serde_json::json!([9]));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let posted = seen.lock().unwrap().clone();
    assert!(
        posted.iter().all(|(u, _)| !u.starts_with("/afA")),
        "AF A is not sent B's report: {posted:?}"
    );
    server.stop().await.ok();
}

/// #2221 (R47): an app session delete removes its PCC rules from the session
/// and, in one decision, from the SMF (TS 29.514 §4.2.4.2; TS 29.512 §4.2.6.1: a
/// `null` entry removes): its rule and QosData, its QoS monitoring instance, and
/// the trigger list restated without QOS_MONITORING. The other app session's
/// rule stays. Before, a null went for `PccRule-app-<id>`, which nothing installs.
///
/// REVERT-VERIFIED: see the PR.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)] // std guard held across .await to serialize the process-global PCF context
async fn an_app_session_delete_removes_its_rules_at_the_smf_2221() {
    let _guard = crate::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    crate::test_support::init_context();
    let (seen, port, server) = recorder().await;
    let ip = "10.45.22.21";
    let _ = sm_policy(port, "imsi-001010000022221", ip, &sm_24_73()).await;
    let a = af_session(port, "afA", ip).await;
    let _ = next_post(&seen, "/update", |_| true).await;
    let (status, asc) = route(
        "/npcf-policyauthorization/v1/app-sessions",
        af_body_at(
            port,
            "afB",
            ip,
            "0",
            serde_json::json!({ "events": [{ "event": "USAGE_REPORT" }] }),
        ),
    )
    .await;
    assert_eq!(status, 201, "{asc}");
    let _ = next_post(&seen, "/update", |_| true).await;
    let rule_a = rules_of(&a)[0].clone();
    let qos_a = pcf_self()
        .read()
        .unwrap()
        .sess_find_by_ipv4addr(ip)
        .unwrap()
        .af_pcc_rules
        .iter()
        .find(|r| r.pcc_rule_id == rule_a)
        .unwrap()
        .qos_data
        .qos_id
        .clone();

    let (status, _) = route(
        &format!("/npcf-policyauthorization/v1/app-sessions/{a}/delete"),
        serde_json::json!({}),
    )
    .await;
    assert!((200..300).contains(&status), "{status}");
    let n = next_post(&seen, "/update", |_| true).await;
    let d = &n["smPolicyDecision"];
    assert_eq!(
        d["pccRules"],
        serde_json::json!({ rule_a.clone(): null }),
        "{d}"
    );
    assert_eq!(d["qosDecs"], serde_json::json!({ qos_a: null }), "{d}");
    assert_eq!(
        d["qosMonDecs"],
        serde_json::json!({ format!("QosMon-{a}"): null }),
        "{d}"
    );
    let triggers = d["policyCtrlReqTriggers"].as_array().unwrap();
    assert!(
        !triggers.contains(&serde_json::json!("QOS_MONITORING")),
        "{triggers:?}"
    );
    assert!(
        triggers.contains(&serde_json::json!("SE_AMBR_CH")),
        "{triggers:?}"
    );
    let left: Vec<String> = pcf_self()
        .read()
        .unwrap()
        .sess_find_by_ipv4addr(ip)
        .unwrap()
        .af_pcc_rules
        .iter()
        .map(|r| r.pcc_rule_id.clone())
        .collect();
    assert_eq!(left.len(), 1, "B's rule stays: {left:?}");
    assert_ne!(left[0], rule_a);
    server.stop().await.ok();
}

/// #2269: a session restored from a snapshot written before #2263 holds its AF
/// rule under the old key (`PccRule-af-<psi>-<medCompN>`), and its app session
/// records no rule ids. A modify re-deriving that media component replaces it:
/// the SMF is sent `null` for the old rule and its QosData in the same decision
/// as the new rule, and the session keeps only the new one.
///
/// REVERT-VERIFIED: without the legacy removal in the modify, this fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)] // std guard held across .await to serialize the process-global PCF context
async fn a_modify_replaces_the_pre_upgrade_rule_at_the_smf_2269() {
    let _guard = crate::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    crate::test_support::init_context();
    let (seen, port, server) = recorder().await;
    let ip = "10.45.22.69";
    let _ = sm_policy(port, "imsi-001010000022269", ip, "0").await;
    let app = af_session(port, "af69", ip).await;
    let _ = next_post(&seen, "/update", |_| true).await;

    // As restored from a pre-#2263 snapshot: the rule under the old key, and an
    // app session that recorded no rule ids.
    let (legacy, legacy_qos) = {
        let ctx = pcf_self();
        let c = ctx.read().unwrap();
        let mut sess = c.sess_find_by_ipv4addr(ip).unwrap();
        let rule = &mut sess.af_pcc_rules[0];
        rule.pcc_rule_id = npcf_handler::legacy_af_pcc_rule_id(sess.psi, 1);
        rule.qos_data.qos_id = format!("QosData-af-{}-1", sess.psi);
        let ids = (rule.pcc_rule_id.clone(), rule.qos_data.qos_id.clone());
        c.sess_update(&sess);
        let mut a = c.app_find_by_app_session_id(&app).unwrap();
        a.pcc_rule_ids.clear();
        c.app_update(&a);
        ids
    };

    let patch = af_body(
        port,
        ip,
        "0",
        serde_json::json!({ "events": [{ "event": "USAGE_REPORT" }] }),
    );
    let resp = pcf_sbi_request_handler(
        SbiRequest::patch(format!("/npcf-policyauthorization/v1/app-sessions/{app}"))
            .with_json_body(&patch)
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status, 200, "{:?}", resp.http.content);
    let n = next_post(&seen, "/update", |_| true).await;
    let d = &n["smPolicyDecision"];
    let new_rule = rules_of(&app)[0].clone();
    assert_ne!(new_rule, legacy);
    assert!(
        d["pccRules"][&legacy].is_null() && d["pccRules"].get(&legacy).is_some(),
        "{d}"
    );
    assert!(
        d["qosDecs"].get(&legacy_qos).is_some_and(|v| v.is_null()),
        "{d}"
    );
    assert!(d["pccRules"][&new_rule].is_object(), "{d}");
    let held: Vec<String> = pcf_self()
        .read()
        .unwrap()
        .sess_find_by_ipv4addr(ip)
        .unwrap()
        .af_pcc_rules
        .iter()
        .map(|r| r.pcc_rule_id.clone())
        .collect();
    assert_eq!(held, vec![new_rule], "the old rule is gone");
    server.stop().await.ok();
}

/// #2269 (decision on #2278): deleting the LAST app session on a PDU session
/// removes any pre-#2263 AF rule left on it, which names no app session: the SMF
/// is sent `null` for it and its QosData in the delete's decision. Deleting an
/// app session while another remains leaves it (it cannot be told whose it is).
///
/// REVERT-VERIFIED: without the last-app-session legacy removal, this fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)] // std guard held across .await to serialize the process-global PCF context
async fn deleting_the_last_app_session_removes_the_pre_upgrade_rule_2269() {
    let _guard = crate::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    crate::test_support::init_context();
    let (seen, port, server) = recorder().await;
    let ip = "10.45.22.70";
    let _ = sm_policy(port, "imsi-001010000022270", ip, "0").await;
    let a = af_session(port, "afA", ip).await;
    let _ = next_post(&seen, "/update", |_| true).await;
    let b = af_session(port, "afB", ip).await;
    let _ = next_post(&seen, "/update", |_| true).await;

    // As restored from a pre-#2263 snapshot: A's rule under the old key, and A
    // recorded no rule ids. B's rule is in the current form.
    let (legacy, legacy_qos) = {
        let ctx = pcf_self();
        let c = ctx.read().unwrap();
        let mut sess = c.sess_find_by_ipv4addr(ip).unwrap();
        let own = rules_of(&a)[0].clone();
        let rule = sess
            .af_pcc_rules
            .iter_mut()
            .find(|r| r.pcc_rule_id == own)
            .unwrap();
        rule.pcc_rule_id = npcf_handler::legacy_af_pcc_rule_id(sess.psi, 1);
        rule.qos_data.qos_id = format!("QosData-af-{}-1", sess.psi);
        let ids = (rule.pcc_rule_id.clone(), rule.qos_data.qos_id.clone());
        c.sess_update(&sess);
        let mut app = c.app_find_by_app_session_id(&a).unwrap();
        app.pcc_rule_ids.clear();
        c.app_update(&app);
        ids
    };
    let held = || -> Vec<String> {
        pcf_self()
            .read()
            .unwrap()
            .sess_find_by_ipv4addr(ip)
            .unwrap()
            .af_pcc_rules
            .iter()
            .map(|r| r.pcc_rule_id.clone())
            .collect()
    };

    // A goes first, B remains: the old rule cannot be told to be A's, so it stays.
    let (status, _) = route(
        &format!("/npcf-policyauthorization/v1/app-sessions/{a}/delete"),
        serde_json::json!({}),
    )
    .await;
    assert!((200..300).contains(&status), "{status}");
    assert!(
        held().contains(&legacy),
        "kept while B remains: {:?}",
        held()
    );

    // B, the last, goes: its rule and the old one, in one decision.
    let rule_b = rules_of(&b)[0].clone();
    seen.lock().unwrap().clear();
    let (status, _) = route(
        &format!("/npcf-policyauthorization/v1/app-sessions/{b}/delete"),
        serde_json::json!({}),
    )
    .await;
    assert!((200..300).contains(&status), "{status}");
    let n = next_post(&seen, "/update", |_| true).await;
    let d = &n["smPolicyDecision"];
    assert!(
        d["pccRules"].get(&legacy).is_some_and(|v| v.is_null()),
        "{d}"
    );
    assert!(
        d["pccRules"].get(&rule_b).is_some_and(|v| v.is_null()),
        "{d}"
    );
    assert!(
        d["qosDecs"].get(&legacy_qos).is_some_and(|v| v.is_null()),
        "{d}"
    );
    assert!(held().is_empty(), "{:?}", held());
    server.stop().await.ok();
}
