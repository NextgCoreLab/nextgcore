//! Wave-6 E6 strict-peer test: the UE-policy delivery-RESULT loop, exercising
//! amfd's REAL `N1MessageNotify` producer against pcfd's REAL notify-callback
//! consumer + delivery-state correlation — no lenient mock, both real code
//! driven in-process (Wave-6 H1 lib-targetization).
//!
//! The un-driveable middle (the NGAP UL NAS path needs live SCTP) is elided:
//! we build the exact `N1MessageNotify` amfd's `forward_ul_updp_to_pcf` emits
//! (amfd's real `build_n1_message_notify_request`, class "UPDP") and feed it to
//! pcfd's REAL SBI router (`pcf_sbi_request_handler`) — the same producer→
//! consumer cross-decode the wire would carry.
//!
//! Specs: TS 29.518 §5.2.2.4 (N1MessageNotify), TS 24.501 D.2.1.3 (COMPLETE
//! stops the procedure), D.2.1.4/D.6.3 (REJECT carries per-instruction result),
//! D.2.1.6 (drop a stale/duplicate command's answer), TS 29.525 §4.2.2.2.
//!
//! Falsifiable acceptance (E6): the association reaches `Delivered` ONLY via a
//! decoded MANAGE UE POLICY COMPLETE with the matching PTI; a REJECT yields
//! `Failed` with the D.6.3 cause; a wrong-PTI answer leaves it `Pending`.

use nextgcore_amfd::namf_server::build_n1_message_notify_request;
use nextgcore_nas::fiveg::ue_policy as nas_updp;
use nextgcore_pcfd::pcf_sbi_request_handler;
use nextgcore_pcfd::ue_policy::{
    ue_policy_add, ue_policy_find, ue_policy_set_delivery, DeliveryState,
};

/// Seed a Pending pcfd UE-policy association carrying `pti`, return its id.
fn seed_pending_association(pti: u8) -> String {
    let assoc = ue_policy_add(
        "imsi-001010000006e60",
        "http://127.0.0.1:9/ue-policy-notify",
        "",
    );
    ue_policy_set_delivery(
        &assoc.pol_asso_id,
        pti,
        1, // UPSC 1
        Some(("001".into(), "01".into())),
        nextgcore_pcfd::ue_policy::default_wire_rules(),
    );
    assoc.pol_asso_id
}

/// The N1MessageNotify amfd would POST to the PCF's registered callback for a
/// UE-policy uplink message: amfd's REAL multipart builder (class "UPDP"),
/// targeting pcfd's callback path for `pol_asso_id`.
fn amfd_notify_request(pol_asso_id: &str, n1_payload: &[u8]) -> nextgcore_sbi::message::SbiRequest {
    let path = format!("/npcf-ue-policy-control/v1/notify/{pol_asso_id}/n1-message-notify");
    build_n1_message_notify_request(
        &path,
        Some("n1n2sub-test"),
        "UPDP",
        None,
        Some("imsi-001010000006e60"),
        n1_payload,
    )
    .expect("amfd builds the N1MessageNotify")
}

/// COMPLETE with the matching PTI → real amfd notify → real pcfd callback flips
/// the association Pending→Delivered (records the UPSC as installed UPSI).
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn complete_via_real_amfd_notify_delivers() {
    // The PCF context is process-global and the UE-policy delivery events fire from
    // this very handler, so a sibling test's firing would land on this test's stub
    // consumer. `CONTEXT_GUARD` serialises every test in this file; poison-tolerant
    // so one failure does not turn its siblings into misleading second failures.
    let _guard = nextgcore_pcfd::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // Drives production peer-call code against a loopback PLAINTEXT peer, i.e. a
    // dev-profile deployment (issue #63). Declared rather than inherited from env.
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let id = seed_pending_association(0x91);
    let complete = nas_updp::ManageUePolicyComplete { pti: 0x91 }
        .encode()
        .expect("COMPLETE encodes");

    let resp = pcf_sbi_request_handler(amfd_notify_request(&id, &complete)).await;
    assert_eq!(resp.status, 204, "notify callback acks 204");

    let a = ue_policy_find(&id).expect("association still present");
    assert_eq!(
        a.delivery_state,
        DeliveryState::Delivered,
        "Delivered ONLY via a matching-PTI COMPLETE"
    );
    assert_eq!(a.installed_upsc, Some(1), "UPSC recorded as installed UPSI");
}

/// REJECT with the matching PTI → association Failed, carrying the decoded
/// D.6.3 per-instruction cause.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn reject_via_real_amfd_notify_fails_with_cause() {
    // The PCF context is process-global and the UE-policy delivery events fire from
    // this very handler, so a sibling test's firing would land on this test's stub
    // consumer. `CONTEXT_GUARD` serialises every test in this file; poison-tolerant
    // so one failure does not turn its siblings into misleading second failures.
    let _guard = nextgcore_pcfd::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // Drives production peer-call code against a loopback PLAINTEXT peer, i.e. a
    // dev-profile deployment (issue #63). Declared rather than inherited from env.
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let id = seed_pending_association(0x92);
    let reject = nas_updp::ManageUePolicyCommandReject {
        pti: 0x92,
        result: nas_updp::UePolicySectionManagementResult {
            subresults: vec![nas_updp::UePolicySectionManagementSubresult {
                plmn_id: nextgcore_nas::common::types::PlmnId::new([0, 0, 1], [0, 1, 0xf], 2),
                results: vec![nas_updp::UePolicyResult {
                    upsc: 0x0001,
                    failed_instruction_order: 1,
                    cause: nas_updp::UE_POLICY_CAUSE_PROTOCOL_ERROR_UNSPECIFIED,
                }],
            }],
        },
    }
    .encode()
    .expect("REJECT encodes");

    let resp = pcf_sbi_request_handler(amfd_notify_request(&id, &reject)).await;
    assert_eq!(resp.status, 204);

    match ue_policy_find(&id).expect("association").delivery_state {
        DeliveryState::Failed(cause) => {
            assert!(cause.contains("REJECT"), "cause names the REJECT: {cause}");
            assert!(
                cause.contains("UPSC"),
                "cause names the failed UPSC: {cause}"
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

/// A COMPLETE with a NON-matching PTI (stale/duplicate command, D.2.1.6) is
/// dropped: the callback still acks 204 (no crash) but the association stays
/// Pending — Delivered is reached ONLY via a matching PTI.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn wrong_pti_complete_is_dropped() {
    // The PCF context is process-global and the UE-policy delivery events fire from
    // this very handler, so a sibling test's firing would land on this test's stub
    // consumer. `CONTEXT_GUARD` serialises every test in this file; poison-tolerant
    // so one failure does not turn its siblings into misleading second failures.
    let _guard = nextgcore_pcfd::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // Drives production peer-call code against a loopback PLAINTEXT peer, i.e. a
    // dev-profile deployment (issue #63). Declared rather than inherited from env.
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let id = seed_pending_association(0x93);
    let stale = nas_updp::ManageUePolicyComplete { pti: 0x9F }
        .encode()
        .expect("COMPLETE encodes");

    let resp = pcf_sbi_request_handler(amfd_notify_request(&id, &stale)).await;
    assert_eq!(
        resp.status, 204,
        "stale answer is still consumed (no crash)"
    );
    assert_eq!(
        ue_policy_find(&id).expect("association").delivery_state,
        DeliveryState::Pending,
        "a wrong-PTI COMPLETE must NOT deliver"
    );
}

// ─── Closing the #90 verification ceiling ────────────────────────────────────
//
// The three tests above prove the delivery-state correlation. What they do NOT
// prove is the thing #90 actually added on top of it: that reaching a terminal
// outcome puts a `SUCCESS_UE_POL_DEL_SP` / `UNSUCCESS_UE_POL_DEL_SP` report on the
// Npcf_EventExposure feed. That producer was wired and type-checked, and nothing
// observed its output arriving — the recorded "the helper is tested and the wiring
// is not" pattern.
//
// These tests drive the SAME real handler and additionally read a STUB CONSUMER, so
// the assertion is that the POST landed with the right event token and SUPI. The
// subscription is created through pcfd's REAL SBI router rather than by seeding the
// context, so the create path is part of what is proved.

use std::sync::{Arc, Mutex};

/// A stub Npcf_EventExposure consumer: records every notification body it is POSTed.
/// Returns `(addr, recorded)`; the server is left running for the test's lifetime.
async fn start_stub_consumer() -> (
    std::net::SocketAddr,
    Arc<Mutex<Vec<serde_json::Value>>>,
    nextgcore_sbi::server::SbiServer,
) {
    let seen: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let addr = nextgcore_sbi::test_support::ephemeral_addr();
    let server =
        nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(addr));
    server
        .start(move |req: nextgcore_sbi::message::SbiRequest| {
            let sink = Arc::clone(&sink);
            async move {
                if let Some(body) = req.http.content.as_deref() {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
                        sink.lock().expect("sink lock").push(v);
                    }
                }
                nextgcore_sbi::message::SbiResponse::with_status(204)
            }
        })
        .await
        .expect("stub Npcf_EventExposure consumer starts");
    (addr, seen, server)
}

/// Subscribe to both UE-policy delivery events through pcfd's REAL router, and
/// return the created resource's URI so the test can remove it again.
async fn subscribe_to_delivery_events(addr: std::net::SocketAddr, notif_id: &str) -> String {
    let body = serde_json::json!({
        "notifUri": format!("http://127.0.0.1:{}/pc-events", addr.port()),
        "notifId": notif_id,
        "eventSubs": ["SUCCESS_UE_POL_DEL_SP", "UNSUCCESS_UE_POL_DEL_SP"],
    });
    let req = nextgcore_sbi::message::SbiRequest::post("/npcf-eventexposure/v1/subscriptions")
        .with_json_body(&body)
        .expect("subscription body serialises");
    let resp = pcf_sbi_request_handler(req).await;
    assert_eq!(
        resp.status, 201,
        "the subscription must be created through the real router"
    );
    resp.http
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("location"))
        .map(|(_, v)| v.clone())
        .expect("create answers with a Location header")
}

/// Remove the subscription again, so a later test's firing cannot be POSTed at a
/// stub consumer this test has already stopped.
async fn delete_subscription(location: &str) {
    let resp = pcf_sbi_request_handler(nextgcore_sbi::message::SbiRequest::delete(location)).await;
    assert_eq!(resp.status, 204, "the subscription must be removable");
}

/// A matching-PTI COMPLETE must put a `SUCCESS_UE_POL_DEL_SP` report on the feed,
/// carrying the association's SUPI so a consumer can correlate it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn a_delivered_ue_policy_reports_success_to_a_real_subscriber() {
    // The PCF context is process-global and the UE-policy delivery events fire from
    // this very handler, so a sibling test's firing would land on this test's stub
    // consumer. `CONTEXT_GUARD` serialises every test in this file; poison-tolerant
    // so one failure does not turn its siblings into misleading second failures.
    let _guard = nextgcore_pcfd::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let (addr, seen, server) = start_stub_consumer().await;
    let location = subscribe_to_delivery_events(addr, "notif-e2e-success").await;

    let id = seed_pending_association(0xA1);
    let complete = nas_updp::ManageUePolicyComplete { pti: 0xA1 }
        .encode()
        .expect("COMPLETE encodes");
    let resp = pcf_sbi_request_handler(amfd_notify_request(&id, &complete)).await;
    assert_eq!(resp.status, 204);

    let recorded = seen.lock().expect("sink lock").clone();
    let ours: Vec<&serde_json::Value> = recorded
        .iter()
        .filter(|v| v["notifId"] == "notif-e2e-success")
        .collect();
    assert_eq!(
        ours.len(),
        1,
        "exactly one report must have landed, got {recorded:?}"
    );
    let notif = &ours[0]["eventNotifs"][0];
    assert_eq!(
        notif["event"], "SUCCESS_UE_POL_DEL_SP",
        "a Delivered outcome reports SUCCESS_UE_POL_DEL_SP"
    );
    assert_eq!(
        notif["supi"], "imsi-001010000006e60",
        "the report carries the SUPI a consumer correlates on"
    );
    assert!(
        notif["timeStamp"]
            .as_str()
            .is_some_and(|t| t.ends_with('Z')),
        "the report carries an RFC 3339 UTC timeStamp: {notif:?}"
    );

    delete_subscription(&location).await;
    server.stop().await.expect("stub consumer stops");
}

/// A matching-PTI REJECT reports `UNSUCCESS_UE_POL_DEL_SP`, and deliberately does
/// NOT carry `delivFailure`: TS 29.522 `Failure` enumerates NORTHBOUND delivery
/// failures, and a D.6.3 UE-side rejection is not one of them, so mapping it to a
/// token would misreport the reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn a_rejected_ue_policy_reports_unsuccess_to_a_real_subscriber() {
    // The PCF context is process-global and the UE-policy delivery events fire from
    // this very handler, so a sibling test's firing would land on this test's stub
    // consumer. `CONTEXT_GUARD` serialises every test in this file; poison-tolerant
    // so one failure does not turn its siblings into misleading second failures.
    let _guard = nextgcore_pcfd::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let (addr, seen, server) = start_stub_consumer().await;
    let location = subscribe_to_delivery_events(addr, "notif-e2e-unsuccess").await;

    let id = seed_pending_association(0xA2);
    let reject = nas_updp::ManageUePolicyCommandReject {
        pti: 0xA2,
        result: nas_updp::UePolicySectionManagementResult {
            subresults: vec![nas_updp::UePolicySectionManagementSubresult {
                plmn_id: nextgcore_nas::common::types::PlmnId::new([0, 0, 1], [0, 1, 0xf], 2),
                results: vec![nas_updp::UePolicyResult {
                    upsc: 0x0001,
                    failed_instruction_order: 1,
                    cause: nas_updp::UE_POLICY_CAUSE_PROTOCOL_ERROR_UNSPECIFIED,
                }],
            }],
        },
    }
    .encode()
    .expect("REJECT encodes");
    let resp = pcf_sbi_request_handler(amfd_notify_request(&id, &reject)).await;
    assert_eq!(resp.status, 204);

    let recorded = seen.lock().expect("sink lock").clone();
    let ours: Vec<&serde_json::Value> = recorded
        .iter()
        .filter(|v| v["notifId"] == "notif-e2e-unsuccess")
        .collect();
    assert_eq!(ours.len(), 1, "exactly one report, got {recorded:?}");
    let notif = &ours[0]["eventNotifs"][0];
    assert_eq!(notif["event"], "UNSUCCESS_UE_POL_DEL_SP");
    assert_eq!(notif["supi"], "imsi-001010000006e60");
    assert!(
        notif.get("delivFailure").is_none(),
        "a UE-side D.6.3 rejection must not be reported as a TS 29.522 Failure: {notif:?}"
    );

    delete_subscription(&location).await;
    server.stop().await.expect("stub consumer stops");
}

/// The NEGATIVE half, and the one that makes the two above mean something: a
/// non-terminal outcome must put NOTHING on the feed. A wrong-PTI COMPLETE is a
/// stale or duplicate command (TS 24.501 D.2.1.6) and the delivery is still in
/// flight, so reporting it would tell a consumer the delivery concluded when it has
/// not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn a_non_terminal_outcome_reports_nothing() {
    // The PCF context is process-global and the UE-policy delivery events fire from
    // this very handler, so a sibling test's firing would land on this test's stub
    // consumer. `CONTEXT_GUARD` serialises every test in this file; poison-tolerant
    // so one failure does not turn its siblings into misleading second failures.
    let _guard = nextgcore_pcfd::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let (addr, seen, server) = start_stub_consumer().await;
    let location = subscribe_to_delivery_events(addr, "notif-e2e-none").await;

    let id = seed_pending_association(0xA3);
    let stale = nas_updp::ManageUePolicyComplete { pti: 0xAF }
        .encode()
        .expect("COMPLETE encodes");
    let resp = pcf_sbi_request_handler(amfd_notify_request(&id, &stale)).await;
    assert_eq!(resp.status, 204);

    let recorded = seen.lock().expect("sink lock").clone();
    let ours: Vec<&serde_json::Value> = recorded
        .iter()
        .filter(|v| v["notifId"] == "notif-e2e-none")
        .collect();
    assert!(
        ours.is_empty(),
        "a stale answer must not be reported as a delivery result: {ours:?}"
    );

    delete_subscription(&location).await;
    server.stop().await.expect("stub consumer stops");
}
