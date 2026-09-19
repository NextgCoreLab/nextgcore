//! #92 criterion 9: a UE-policy delivery to a CM-IDLE UE carries
//! `n1n2FailureTxfNotifURI`, and a subsequent CM-CONNECTED transition RETRIES the
//! delivery rather than leaving the association terminally `Failed`.
//!
//! Three things are asserted, each against real code:
//!
//! 1. The `n1n2FailureTxfNotifURI` member is present in the N1N2 body pcfd puts on the
//!    wire — recorded by a stub AMF, so it is the serialised request being asserted and
//!    not the builder's return value, and asserted to be ABSOLUTE and to name this
//!    association.
//!
//!    NOT asserted here: that an AMF then POSTs the failure notification to it. That is
//!    amfd's half and it already existed before #92, with its own tests
//!    (`namf_server.rs`'s `ue_not_reachable_error` / `send_n1n2_failure_notification`,
//!    covered at `namf_server.rs:3247` and `:3862`). #92's pcfd-side gap was that nobody
//!    SUPPLIED the URI, so the existing AMF machinery could never fire — which is what
//!    makes asserting the member's presence the whole of this criterion's pcfd half.
//! 2. A CM-IDLE delivery parks the command instead of failing the association: the
//!    delivery state stays `Pending`, which is the honest state for a delivery that has
//!    not concluded.
//! 3. The `CONNECTIVITY_STATE_REPORT` callback — driven through pcfd's REAL SBI router
//!    — retries the parked command, and the stub AMF records the SECOND transfer.
//!
//! Specs: TS 29.518 §5.2.2.3.1 (`N1N2MessageTransfer`, `n1n2FailureTxfNotifURI`),
//! §6.1.6.2.8 (`N1N2MsgTxfrFailureNotification`), §5.3.2.2.2
//! (`Namf_EventExposure_Subscribe`), §6.2.6.2.4/5 (`AmfEventNotification`,
//! `CONNECTIVITY_STATE_REPORT` / `cmInfoList`); TS 23.502 §4.2.4.3 (react to the UE
//! returning to CM-CONNECTED); TS 29.525 §4.2.2.2.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nextgcore_pcfd::pcf_sbi_request_handler;
use nextgcore_pcfd::ue_policy::{
    ue_policy_add, ue_policy_find, ue_policy_has_parked_delivery, ue_policy_set_delivery,
    ue_policy_set_serving_amf, AmfGuami, DeliveryState,
};
use nextgcore_sbi::message::{SbiRequest as Req, SbiResponse as Resp};

/// The GUAMI the fixture's single stub AMF advertises and the association stores.
const AMF_ID: &str = "cafe09";

/// What the stub AMF recorded about each `N1N2MessageTransfer`: the root JSON body, so
/// the presence and value of `n1n2FailureTxfNotifURI` is asserted on the WIRE.
#[derive(Default)]
struct N1n2Recorder {
    bodies: Mutex<Vec<serde_json::Value>>,
    /// Whether the next transfer should be answered 504 UE_NOT_REACHABLE. Flipped by
    /// the test so the SAME stub serves both the idle failure and the successful retry
    /// — which is what makes the retry's success attributable to the retry and not to a
    /// different peer.
    reject: AtomicBool,
    subscribes: AtomicUsize,
}

impl N1n2Recorder {
    fn bodies(&self) -> Vec<serde_json::Value> {
        self.bodies.lock().map(|b| b.clone()).unwrap_or_default()
    }
    fn transfers(&self) -> usize {
        self.bodies().len()
    }
}

/// Start a stub AMF serving `namf-comm` (N1N2 transfer) and `namf-evts`
/// (`Namf_EventExposure_Subscribe`) on one ephemeral port.
///
/// The transfer arm answers 504 with cause `UE_NOT_REACHABLE` while `reject` is set —
/// the exact status and cause amfd's real `ue_not_reachable_error` produces for a
/// CM-IDLE UE (`namf_server.rs`) — and 200 once it is cleared.
async fn start_stub_amf(rec: Arc<N1n2Recorder>) -> (nextgcore_sbi::server::SbiServer, u16) {
    let (server, addr) = nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: Req| {
        let rec = Arc::clone(&rec);
        async move {
            let path = req.header.uri.split('?').next().unwrap_or("").to_string();
            if req.header.method == "POST" && path == "/namf-evts/v1/subscriptions" {
                rec.subscribes.fetch_add(1, Ordering::SeqCst);
                return Resp::with_status(201)
                    .with_json_body(&serde_json::json!({"subscriptionId": "cm-sub-1"}))
                    .unwrap_or_else(|_| Resp::with_status(500))
                    .with_header("location", "/namf-evts/v1/subscriptions/cm-sub-1");
            }
            if req.header.method == "POST" && path.ends_with("/n1-n2-messages") {
                if let Some(c) = req.http.content.as_deref() {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(c) {
                        if let Ok(mut b) = rec.bodies.lock() {
                            b.push(v);
                        }
                    }
                }
                if rec.reject.load(Ordering::SeqCst) {
                    // Byte-shaped like amfd's real 504 (TS 29.518 Table 6.1.7.3-1), so
                    // pcfd's unreachability classifier is exercised on the real text.
                    return Resp::with_status(504)
                        .with_json_body(&serde_json::json!({
                            "error": { "status": 504, "cause": "UE_NOT_REACHABLE" }
                        }))
                        .unwrap_or_else(|_| Resp::with_status(500));
                }
                return Resp::with_status(200)
                    .with_json_body(&serde_json::json!({"cause": "N1_N2_TRANSFER_INITIATED"}))
                    .unwrap_or_else(|_| Resp::with_status(500));
            }
            Resp::with_status(404)
        }
    })
    .await;
    (server, addr.port())
}

/// Start a stub NRF that advertises the one stub AMF with a matching
/// `amfInfo.guamiList`, so the association's GUAMI resolves to it.
async fn start_stub_nrf(amf_port: u16) -> (nextgcore_sbi::server::SbiServer, u16) {
    let (server, addr) =
        nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: Req| async move {
            if !req.header.uri.starts_with("/nnrf-disc/v1/nf-instances") {
                return Resp::with_status(404);
            }
            Resp::with_status(200)
                .with_json_body(&serde_json::json!({
                    "nfInstances": [{
                        "nfInstanceId": "amf-idle-fixture",
                        "nfType": "AMF",
                        "ipv4Addresses": ["127.0.0.1"],
                        "amfInfo": {
                            "guamiList": [
                                {"plmnId": {"mcc": "001", "mnc": "01"}, "amfId": AMF_ID}
                            ]
                        },
                        "nfServices": [{
                            "serviceName": "namf-comm",
                            "scheme": "http",
                            "ipEndPoints": [{"ipv4Address": "127.0.0.1", "port": amf_port}]
                        }]
                    }]
                }))
                .unwrap_or_else(|_| Resp::with_status(500))
        })
        .await;
    (server, addr.port())
}

/// Seed an association targeting the fixture's AMF, with a PTI/UPSC recorded so the
/// delivery state machine has something to be `Pending` about.
fn seed_association(supi: &str) -> String {
    let assoc = ue_policy_add(supi, "http://127.0.0.1:9/ue-policy-notify", "");
    ue_policy_set_serving_amf(
        &assoc.pol_asso_id,
        Some(AmfGuami {
            mcc: "001".into(),
            mnc: "01".into(),
            amf_id: AMF_ID.into(),
        }),
        None,
    );
    ue_policy_set_delivery(
        &assoc.pol_asso_id,
        0x92,
        1,
        Some(("001".into(), "01".into())),
        nextgcore_pcfd::ue_policy::default_wire_rules(),
    );
    assoc.pol_asso_id
}

/// An `AmfEventNotification` carrying a `CONNECTIVITY_STATE_REPORT` with `cmState`,
/// shaped as amfd's `build_event_report` emits it (TS 29.518 §6.2.6.2.5).
fn cm_state_notification(pol_asso_id: &str, cm_state: &str) -> Req {
    Req::post(format!(
        "/npcf-ue-policy-control/v1/notify/{pol_asso_id}/connectivity-state-notify"
    ))
    .with_json_body(&serde_json::json!({
        "notifyCorrelationId": pol_asso_id,
        "reportList": [{
            "type": "CONNECTIVITY_STATE_REPORT",
            "state": { "active": true },
            "cmInfoList": [{ "cmState": cm_state, "accessType": "3GPP_ACCESS" }],
        }]
    }))
    .expect("AmfEventNotification serializes")
}

/// #92 criterion 9, end to end: a CM-IDLE delivery puts `n1n2FailureTxfNotifURI` on
/// the wire and stays `Pending`; a CM-CONNECTED transition retries it.
///
/// Why this shape rather than three separate tests: the retry assertion is only
/// meaningful against the SAME association and the SAME stub AMF that just refused the
/// first transfer, because "a transfer arrived" has to be attributable to the retry
/// rather than to a fresh delivery. Keeping one linear run over one fixture is what
/// makes the second transfer's arrival proof of a retry.
///
/// The load-bearing assertions, in order:
/// - `n1n2FailureTxfNotifURI` present and absolute in the FIRST recorded body. Absolute
///   because a relative callback URI is one the AMF cannot POST to (TS 29.500 §6.1),
///   which is the same defect #92 fixes on the amfd side.
/// - state still `Pending` after the 504, NOT `Failed`. Paired with the terminal-failure
///   control test below, which proves `Failed` is still reachable — so `Pending` here
///   means "parked", not "the state machine stopped working".
/// - a SECOND transfer recorded after the CM-CONNECTED callback. This is the positive
///   form of "a retry happened": the count goes 1 -> 2 at a peer that recorded both.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // std guard held across .await to serialize the process-global NRF URI / PCF context
async fn cm_idle_delivery_carries_the_failure_uri_and_retries_on_cm_connected() {
    // The NRF URI, the PCF self identity and the UE-policy store are all
    // process-global; serialize on the crate-wide guard rather than adding a second
    // lock over the same shared state.
    let _guard = nextgcore_pcfd::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // Drives production peer-call code against loopback PLAINTEXT peers (issue #63).
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);

    let rec = Arc::new(N1n2Recorder::default());
    rec.reject.store(true, Ordering::SeqCst);
    let (amf, amf_port) = start_stub_amf(Arc::clone(&rec)).await;
    let (nrf, nrf_port) = start_stub_nrf(amf_port).await;
    nextgcore_sbi::context::global_context()
        .set_nrf_uri(format!("http://127.0.0.1:{nrf_port}"))
        .await;

    // A published self identity is what makes `n1n2FailureTxfNotifURI` constructible;
    // without it the member is (correctly) OMITTED, so it must be set for this test to
    // be about the member at all.
    //
    // `pcf_self_info_set` is set-once process-wide, so whether THIS call wins depends
    // on whether a sibling integration test in the same binary published first. That is
    // why the assertions below are on the URI's SHAPE — absolute, and ending in this
    // association's `/{polAssoId}/n1n2-failure-notify` — rather than on a literal
    // host:port. Those two properties are what the criterion is about (TS 29.500 §6.1
    // absoluteness, and correlatability back to the association), and both hold for
    // whichever identity won.
    nextgcore_pcfd::pcf_self_info_set(nextgcore_pcfd::PcfSelfInfo {
        sbi_addr: "127.0.0.1".to_string(),
        sbi_port: 7777,
        fqdn: None,
        nf_instance_id: "pcf-idle-fixture".to_string(),
    });

    let supi = "imsi-001010000009220";
    let id = seed_association(supi);
    let pdu: Vec<u8> = vec![0x92, 0x01, 0x00, 0x02];

    // --- 1. the CM-IDLE delivery ---------------------------------------------
    let first = tokio::time::timeout(
        Duration::from_secs(10),
        nextgcore_pcfd::sbi_path::pcf_deliver_ue_policy(&id, supi, &pdu),
    )
    .await
    .expect("delivery is bounded");
    assert!(
        first.is_err(),
        "a 504 UE_NOT_REACHABLE must surface as an Err so the caller can classify it; got \
         {first:?}"
    );

    let bodies = rec.bodies();
    assert_eq!(
        bodies.len(),
        1,
        "exactly one transfer so far; recorded {bodies:?}"
    );
    let failure_uri = bodies[0]
        .get("n1n2FailureTxfNotifURI")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| {
            panic!("n1n2FailureTxfNotifURI must be present in the N1N2 body; got {bodies:?}")
        });
    assert!(
        failure_uri.starts_with("http://") || failure_uri.starts_with("https://"),
        "n1n2FailureTxfNotifURI must be ABSOLUTE so the AMF can POST to it (TS 29.500 §6.1); \
         got {failure_uri}"
    );
    assert!(
        failure_uri.ends_with(&format!("/{id}/n1n2-failure-notify")),
        "the failure URI must name this association so the callback can correlate; got \
         {failure_uri}"
    );
    // The transfer still carries the UPDP container it always did — the new member is
    // additive, not a replacement.
    assert_eq!(
        bodies[0].pointer("/n1MessageContainer/n1MessageClass"),
        Some(&serde_json::json!("UPDP")),
        "the UPDP container must be unchanged by #92; got {bodies:?}"
    );

    // --- 2. parked, not Failed -----------------------------------------------
    // The REAL classification the production delivery task runs on a failed transfer
    // (`handle_ue_policy_delivery_failure`), fed the error the stub AMF just produced.
    // Driven directly rather than through `spawn_ue_policy_delivery` because that
    // function owns its own tokio task and its own UDR lookup; what is under test here
    // is what the failure arm DOES, and this is that arm.
    let err = first.expect_err("the 504 is an Err");
    tokio::time::timeout(
        Duration::from_secs(10),
        nextgcore_pcfd::handle_ue_policy_delivery_failure(&id, supi, pdu.clone(), err),
    )
    .await
    .expect("the failure arm is bounded");

    assert!(
        ue_policy_has_parked_delivery(&id),
        "the CM-IDLE delivery must be PARKED for retry, not discarded"
    );
    // And the connectivity subscription was armed at the serving AMF — the wake-up
    // source without which nothing would ever retry the parked command.
    assert_eq!(
        rec.subscribes.load(Ordering::SeqCst),
        1,
        "arming the retry must create a CONNECTIVITY_STATE_REPORT subscription at the \
         serving AMF (TS 29.518 §5.3.2.2.2)"
    );
    assert_eq!(
        ue_policy_find(&id)
            .expect("association present")
            .connectivity_subscription_id
            .as_deref(),
        Some("cm-sub-1"),
        "the AMF-minted subscription id must be recorded so the delete leg can unsubscribe"
    );
    let state = ue_policy_find(&id)
        .expect("association present")
        .delivery_state;
    assert_eq!(
        state,
        DeliveryState::Pending,
        "a delivery awaiting reachability has NOT concluded, so it must stay Pending — \
         Failed is the #92 defect; got {state:?}"
    );

    // --- 3. the UE comes back; the callback retries ---------------------------
    rec.reject.store(false, Ordering::SeqCst);
    let resp = pcf_sbi_request_handler(cm_state_notification(&id, "CONNECTED")).await;
    assert_eq!(
        resp.status, 204,
        "the CONNECTIVITY_STATE_REPORT callback acknowledges 204"
    );

    let retried = nextgcore_sbi::test_support::poll_until(
        Duration::from_secs(8),
        Duration::from_millis(50),
        || {
            let rec = Arc::clone(&rec);
            async move { (rec.transfers() >= 2).then_some(rec.transfers()) }
        },
    )
    .await
    .expect("the CM-CONNECTED transition must retry the parked delivery");
    assert_eq!(
        retried, 2,
        "exactly ONE retry — a second transfer with the same PTI is a duplicate command \
         (TS 24.501 D.2.1.6), so the parked delivery is taken, not copied"
    );

    // The retried transfer is the SAME command, not a re-encode: the UE will answer the
    // PTI it was given, and a re-encode could have picked up a changed rule set.
    let bodies = rec.bodies();
    assert_eq!(
        bodies[1].pointer("/n1MessageContainer/n1MessageClass"),
        Some(&serde_json::json!("UPDP")),
        "the retry is the same UPDP transfer; got {bodies:?}"
    );
    let state = ue_policy_find(&id)
        .expect("association present")
        .delivery_state;
    assert_eq!(
        state,
        DeliveryState::Pending,
        "an accepted retry still awaits the UE's MANAGE UE POLICY COMPLETE, so Pending is \
         correct (never a fake Delivered); got {state:?}"
    );

    nrf.stop().await.ok();
    amf.stop().await.ok();
}

/// Control for the `Pending` assertion above: a NON-reachability failure is still
/// terminal.
///
/// Without this, "the state is `Pending`" could mean the failure path stopped writing
/// state at all. Driving a 403 through the same delivery function and seeing `Failed`
/// proves the terminal transition is reachable, so the `Pending` above is specifically
/// the reachability retry and not a broken state machine.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // std guard held across .await to serialize the process-global NRF URI / PCF context
async fn a_non_reachability_failure_is_still_terminal() {
    let _guard = nextgcore_pcfd::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);

    // A stub AMF that refuses with 403 FORBIDDEN — not a reachability problem, so
    // retrying it could never help.
    let (amf, amf_addr) =
        nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: Req| async move {
            let path = req.header.uri.split('?').next().unwrap_or("").to_string();
            if path.ends_with("/n1-n2-messages") {
                return Resp::with_status(403);
            }
            Resp::with_status(404)
        })
        .await;
    let (nrf, nrf_port) = start_stub_nrf(amf_addr.port()).await;
    nextgcore_sbi::context::global_context()
        .set_nrf_uri(format!("http://127.0.0.1:{nrf_port}"))
        .await;

    let supi = "imsi-001010000009221";
    let id = seed_association(supi);
    let err = tokio::time::timeout(
        Duration::from_secs(10),
        nextgcore_pcfd::sbi_path::pcf_deliver_ue_policy(&id, supi, &[0x92, 0x01]),
    )
    .await
    .expect("delivery is bounded")
    .expect_err("a 403 must be an Err");

    assert!(
        !nextgcore_pcfd::ue_policy::is_ue_unreachable_failure(&err),
        "a 403 must NOT be classified as a reachability failure, or every refusal would be \
         retried forever; got {err}"
    );
    // And the classifier's positive case, on the same code path, so the discriminator
    // is shown to actually discriminate.
    assert!(
        nextgcore_pcfd::ue_policy::is_ue_unreachable_failure(
            "namf-comm N1N2MessageTransfer returned status 504"
        ),
        "the 504 form amfd produces MUST classify as unreachable"
    );

    nrf.stop().await.ok();
    amf.stop().await.ok();
}
