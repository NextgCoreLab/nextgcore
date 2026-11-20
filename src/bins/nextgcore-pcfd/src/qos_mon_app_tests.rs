//! #2221: the AF's QoS monitoring subscription through pcfd's real router, to
//! the SmPolicyDecision the SMF is sent and back to the AF.

use super::*;
use std::sync::{Arc, Mutex};

type Seen = Arc<Mutex<Vec<(String, serde_json::Value)>>>;

fn request(method: &str, uri: &str, body: Option<serde_json::Value>) -> SbiRequest {
    let req = match method {
        "DELETE" => SbiRequest::delete(uri),
        "PUT" => SbiRequest::put(uri),
        "PATCH" => SbiRequest::patch(uri),
        _ => SbiRequest::post(uri),
    };
    match body {
        Some(b) => req.with_json_body(&b).expect("encode test body"),
        None => req,
    }
}

async fn route(method: &str, uri: &str, body: serde_json::Value) -> (u16, serde_json::Value) {
    let resp = pcf_sbi_request_handler(request(method, uri, Some(body))).await;
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
        "POST",
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
        "POST",
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
        "POST",
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
    let resp = pcf_sbi_request_handler(request(
        "DELETE",
        &format!("/npcf-policyauthorization/v1/app-sessions/{app_session_id}/events-subscription"),
        None,
    ))
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
            "POST",
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
        "POST",
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
