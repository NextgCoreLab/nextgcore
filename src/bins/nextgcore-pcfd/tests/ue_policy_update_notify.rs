//! #92 criterion 8: an update on an existing UE-policy association POSTs a
//! `PolicyUpdate` notification to the association's recorded `notificationUri`, and
//! the AMF's `ue-policy-notify` route answers 204 when driven through amfd's REAL
//! router.
//!
//! Two halves, both driven against real code:
//!
//! 1. **pcfd's producer.** `handle_ue_policy_update` — the REAL handler — is driven
//!    over an association whose `notificationUri` points at a stub consumer on an
//!    ephemeral port. The stub records method, path and body, so the assertion is on
//!    the WIRE artifact rather than on a log line. Before #92 this handler applied the
//!    update, answered 200 and notified nobody, so the stub would record nothing.
//! 2. **amfd's consumer.** The same `{notificationUri}/update` and
//!    `{notificationUri}/terminate` requests are fed to `namf_request_handler` —
//!    amfd's REAL SBI router — which must answer 204. Before #92 the
//!    `ue-policy-notify` path was unrouted and fell to the router's 404 arm, so this
//!    is a real routing assertion and not a tautology.
//!
//! Specs: TS 29.525 §4.2.4 (UE Policy Association Update/Termination initiated by the
//! PCF: POST `{notificationUri}/update` with a `PolicyUpdate`, terminate modelled as a
//! Delete of the association), §5.6.2.4 (`PolicyAssociationUpdateRequest` members);
//! TS 29.500 §6.1 (callback URIs are absolute), §6.10 (reliable notification
//! delivery).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nextgcore_pcfd::ue_policy::{ue_policy_add, ue_policy_find};
use nextgcore_pcfd::{handle_ue_policy_delete, handle_ue_policy_update};
use nextgcore_sbi::message::{SbiRequest as Req, SbiResponse as Resp};

/// One notification the stub consumer received, as it arrived on the wire.
#[derive(Clone, Debug)]
struct Received {
    method: String,
    path: String,
    body: serde_json::Value,
}

/// Start a stub `Npcf_UEPolicyControl` notification consumer (what an AMF is, for this
/// leg) on an ephemeral port, recording every request. Returns the server, its port,
/// and the shared log.
///
/// Answers 204 to everything, as TS 29.525 §4.2.4 specifies for the callbacks: a stub
/// that 400'd would make a missing notification indistinguishable from a rejected one.
async fn start_stub_consumer() -> (
    nextgcore_sbi::server::SbiServer,
    u16,
    Arc<Mutex<Vec<Received>>>,
    Arc<AtomicUsize>,
) {
    let log: Arc<Mutex<Vec<Received>>> = Arc::new(Mutex::new(Vec::new()));
    let hits = Arc::new(AtomicUsize::new(0));
    let sink_log = Arc::clone(&log);
    let sink_hits = Arc::clone(&hits);
    let (server, addr) = nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: Req| {
        let log = Arc::clone(&sink_log);
        let hits = Arc::clone(&sink_hits);
        async move {
            let path = req.header.uri.split('?').next().unwrap_or("").to_string();
            let body = req
                .http
                .content
                .as_deref()
                .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
                .unwrap_or(serde_json::Value::Null);
            if let Ok(mut l) = log.lock() {
                l.push(Received {
                    method: req.header.method.clone(),
                    path,
                    body,
                });
            }
            hits.fetch_add(1, Ordering::SeqCst);
            Resp::with_status(204)
        }
    })
    .await;
    (server, addr.port(), log, hits)
}

/// An `Npcf_UEPolicyControl_Update` request as a consumer would send it
/// (TS 29.525 §5.6.2.4). `triggers: ["UE_POLICY"]` is the member the notification's
/// `triggers` is expected to echo.
fn update_request(pol_asso_id: &str) -> Req {
    Req::post(format!(
        "/npcf-ue-policy-control/v1/policies/{pol_asso_id}/update"
    ))
    .with_json_body(&serde_json::json!({ "triggers": ["UE_POLICY"] }))
    .expect("update body serializes")
}

/// #92 criterion 8 (producer half): a real update POSTs a `PolicyUpdate` to the
/// association's recorded `notificationUri` — asserted on method, path AND body.
///
/// Why these three and not just "a request arrived": the method distinguishes the
/// §4.2.4 POST from anything else the delivery machinery might emit; the path proves
/// the `/update` suffix was appended to the STORED URI (so an update that changed the
/// URI is honoured, rather than the create-time one being reused); and the body proves
/// it is a `PolicyUpdate` naming THIS association, which is what lets a consumer
/// holding several correlate it. A bare arrival count would also be satisfied by the
/// re-delivery leg's own traffic.
///
/// Delivery is fire-and-forget (`spawn_notification`), so the test polls for the
/// arrival with a bounded budget rather than sleeping a fixed interval.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // std guard held across .await to serialize the process-global PCF context (current-thread test)
async fn update_posts_a_policy_update_to_the_recorded_notification_uri() {
    // `notificationUri` lives in the process-global UE-policy store and the delivery
    // task fires from the same handler, so a sibling test's notification could land on
    // this test's stub. Serialize on the crate-wide guard.
    let _guard = nextgcore_pcfd::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // Drives production notification code against a loopback PLAINTEXT consumer, i.e.
    // a dev-profile deployment (issue #63). Declared rather than inherited from env.
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    // The re-delivery an update triggers would try to reach an AMF; with delivery off
    // the only traffic the stub can see is the notification, so an arrival there is
    // unambiguous.
    std::env::set_var("PCF_UE_POLICY_DELIVERY", "off");

    let (consumer, port, log, hits) = start_stub_consumer().await;
    let notification_uri =
        format!("http://127.0.0.1:{port}/namf-callback/v1/supi/ue-policy-notify");
    let assoc = ue_policy_add("imsi-001010000009210", &notification_uri, "");

    let resp =
        handle_ue_policy_update(&assoc.pol_asso_id, &update_request(&assoc.pol_asso_id)).await;
    assert_eq!(resp.status, 200, "the update itself still answers 200");

    // The WIRE first, before the handler's own report about itself. Order matters: a
    // self-reported `notified: true` is the producer's claim, and asserting it first
    // means a regression that stops sending but keeps claiming success is caught by the
    // claim rather than by the missing request — which would make the weaker assertion
    // the one doing the work. The recorded POST is the evidence; the flag is checked
    // afterwards, against it.
    let arrived = nextgcore_sbi::test_support::poll_until(
        Duration::from_secs(8),
        Duration::from_millis(50),
        || {
            let log = Arc::clone(&log);
            let hits = Arc::clone(&hits);
            async move {
                if hits.load(Ordering::SeqCst) == 0 {
                    return None;
                }
                log.lock().ok().and_then(|l| l.first().cloned())
            }
        },
    )
    .await
    .expect("the PolicyUpdate notification must reach the recorded notificationUri");

    assert_eq!(
        arrived.method, "POST",
        "TS 29.525 §4.2.4 notifies by POST; got {arrived:?}"
    );
    assert_eq!(
        arrived.path, "/namf-callback/v1/supi/ue-policy-notify/update",
        "the notification must go to {{notificationUri}}/update; got {arrived:?}"
    );
    assert_eq!(
        arrived.body.get("resourceUri").and_then(|v| v.as_str()),
        Some(format!("/npcf-ue-policy-control/v1/policies/{}", assoc.pol_asso_id).as_str()),
        "the PolicyUpdate must name THIS association, so a consumer holding several can \
         correlate it; got {}",
        arrived.body
    );
    assert_eq!(
        arrived.body.get("triggers"),
        Some(&serde_json::json!(["UE_POLICY"])),
        "the PolicyUpdate must carry the triggers the update recorded; got {}",
        arrived.body
    );

    // And only now the handler's self-report, which the recorded POST above has just
    // made checkable: the 200 body must AGREE with what actually went out, so a consumer
    // driving the update can trust `notified` instead of having to observe the callback.
    let reported: serde_json::Value =
        serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap_or_default();
    assert_eq!(
        reported.pointer("/nextgcoreUpdateApplied/notified"),
        Some(&serde_json::json!(true)),
        "the 200 body must report the notification that demonstrably went out, got {reported}"
    );

    std::env::remove_var("PCF_UE_POLICY_DELIVERY");
    consumer.stop().await.ok();
}

/// #92 criterion 2 (terminate leg): deleting the association POSTs to
/// `{notificationUri}/terminate`, so a consumer learns the association is gone instead
/// of discovering it by 404 on its next update.
///
/// Held to the same three-way assertion as the update, and for the same reason. The
/// association is also asserted GONE from pcfd's store afterwards — a terminate
/// notification that left the PCF's own state behind would be the mirror of the defect
/// being fixed.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // std guard held across .await to serialize the process-global PCF context (current-thread test)
async fn delete_posts_a_terminate_notification() {
    let _guard = nextgcore_pcfd::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    std::env::set_var("PCF_UE_POLICY_DELIVERY", "off");

    let (consumer, port, log, hits) = start_stub_consumer().await;
    let notification_uri =
        format!("http://127.0.0.1:{port}/namf-callback/v1/supi/ue-policy-notify");
    let assoc = ue_policy_add("imsi-001010000009211", &notification_uri, "");

    let resp = handle_ue_policy_delete(&assoc.pol_asso_id).await;
    assert_eq!(resp.status, 204, "the delete itself answers 204");
    assert!(
        ue_policy_find(&assoc.pol_asso_id).is_none(),
        "the association must be removed from pcfd's store"
    );

    let arrived = nextgcore_sbi::test_support::poll_until(
        Duration::from_secs(8),
        Duration::from_millis(50),
        || {
            let log = Arc::clone(&log);
            let hits = Arc::clone(&hits);
            async move {
                if hits.load(Ordering::SeqCst) == 0 {
                    return None;
                }
                log.lock().ok().and_then(|l| l.first().cloned())
            }
        },
    )
    .await
    .expect("the terminate notification must reach the recorded notificationUri");

    assert_eq!(arrived.method, "POST");
    assert_eq!(
        arrived.path, "/namf-callback/v1/supi/ue-policy-notify/terminate",
        "TS 29.525 §4.2.4 models termination as a POST to {{notificationUri}}/terminate; got \
         {arrived:?}"
    );
    assert_eq!(
        arrived.body.get("resourceUri").and_then(|v| v.as_str()),
        Some(format!("/npcf-ue-policy-control/v1/policies/{}", assoc.pol_asso_id).as_str()),
        "the terminate body must name the association being released; got {}",
        arrived.body
    );

    std::env::remove_var("PCF_UE_POLICY_DELIVERY");
    consumer.stop().await.ok();
}

/// #92 criterion 3 (consumer half): amfd's REAL router answers 204 on
/// `POST /namf-callback/v1/{supi}/ue-policy-notify/{update,terminate}`.
///
/// Driven through `namf_request_handler` — the same entry point the live HTTP/2 server
/// dispatches into — rather than by calling the handler directly, because the thing
/// under test IS the route: before #92 this path matched no arm and fell to the 404
/// arm. Calling the handler directly would assert only that a function returns 204 and
/// would have passed on unmodified `main`.
///
/// The 404 control at the end is what makes the 204s meaningful: it proves this router
/// really does reject paths it has no arm for, so the 204s above are the new arm
/// answering and not a catch-all.
#[tokio::test]
async fn amfd_router_answers_204_on_the_ue_policy_notify_route() {
    let supi = "imsi-001010000009212";
    let body = serde_json::json!({
        "resourceUri": "/npcf-ue-policy-control/v1/policies/pol-1",
        "triggers": ["UE_POLICY"],
    });

    for op in ["update", "terminate"] {
        let req = Req::post(format!("/namf-callback/v1/{supi}/ue-policy-notify/{op}"))
            .with_json_body(&body)
            .expect("PolicyUpdate serializes");
        let resp = nextgcore_amfd::namf_request_handler(req).await;
        assert_eq!(
            resp.status, 204,
            "amfd must route POST .../ue-policy-notify/{op} to a 204 handler, got {} ({:?})",
            resp.status, resp.http.content
        );
    }

    // A POST to the bare notification URI is also accepted: TS 29.525 does not forbid
    // a consumer POSTing there, and 404-ing the exact URI the AMF itself registered
    // would be the #92 defect in miniature.
    let bare = Req::post(format!("/namf-callback/v1/{supi}/ue-policy-notify"))
        .with_json_body(&body)
        .expect("PolicyUpdate serializes");
    assert_eq!(
        nextgcore_amfd::namf_request_handler(bare).await.status,
        204,
        "the bare registered notificationUri must be routed too"
    );

    // Control: the router is genuinely selective, so the 204s above are this route
    // answering rather than a permissive default.
    let unknown = Req::post(format!("/namf-callback/v1/{supi}/no-such-callback"));
    assert_eq!(
        nextgcore_amfd::namf_request_handler(unknown).await.status,
        404,
        "an unrouted namf-callback path must still 404 — otherwise the 204s prove nothing"
    );
}
