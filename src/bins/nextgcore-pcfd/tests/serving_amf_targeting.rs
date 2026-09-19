//! #92 criterion 7: UE-policy delivery and its delivery-result subscription go to
//! the AMF that SERVES the UE, not to whichever AMF the NRF happens to list first.
//!
//! Two stub AMFs run on different ephemeral ports and are both registered with a stub
//! NRF, differing ONLY in their `amfInfo.guamiList`. The stub NRF answers every
//! discovery with BOTH of them, and deliberately lists the wrong one FIRST — so the
//! pre-#92 `parse_first_endpoint` behaviour would send to the wrong AMF, and the test
//! fails if pcfd regresses to it. (It also ignores the `guami` query parameter, which
//! is what this tree's own `nrfd` does — see spec Decision 1. That is the point: the
//! selection under test is pcfd's CLIENT-SIDE verification, which is the half that
//! works against a real deployment.)
//!
//! Specs: TS 29.525 §4.2.2.2 (the PCF delivers UE policy to the SERVING AMF,
//! addressed via the `PolicyAssociationRequest` `guami`/`servingNfId`);
//! TS 29.510 §6.1.6.2.4 (`AmfInfo.guamiList`), §6.2.3.2.3.1 (the `guami` discovery
//! query parameter); TS 29.518 §5.2.2.3.1 (N1N2MessageTransfer), §5.2.2.6
//! (N1N2MessageSubscribe).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nextgcore_pcfd::ue_policy::{ue_policy_add, ue_policy_set_serving_amf, AmfGuami};
use nextgcore_sbi::message::{SbiRequest as Req, SbiResponse as Resp};

/// What one stub AMF recorded: how many N1N2 transfers and how many
/// N1N2MessageSubscribes arrived, and the request paths, so an assertion can name
/// WHICH AMF was addressed rather than inferring it from a log.
#[derive(Default)]
struct AmfRecorder {
    transfers: AtomicUsize,
    subscribes: AtomicUsize,
    paths: Mutex<Vec<String>>,
}

impl AmfRecorder {
    fn record(&self, method: &str, path: &str) {
        if method == "POST" && path.ends_with("/n1-n2-messages") {
            self.transfers.fetch_add(1, Ordering::SeqCst);
        }
        if method == "POST" && path.ends_with("/n1-n2-messages/subscriptions") {
            self.subscribes.fetch_add(1, Ordering::SeqCst);
        }
        if let Ok(mut p) = self.paths.lock() {
            p.push(format!("{method} {path}"));
        }
    }
    fn transfers(&self) -> usize {
        self.transfers.load(Ordering::SeqCst)
    }
    fn subscribes(&self) -> usize {
        self.subscribes.load(Ordering::SeqCst)
    }
    fn paths(&self) -> Vec<String> {
        self.paths.lock().map(|p| p.clone()).unwrap_or_default()
    }
}

/// Start a stub `namf-comm` AMF on an ephemeral port, recording into `rec`.
///
/// Answers 200 to the N1N2 transfer and 201 (with a `n1n2NotifySubscriptionId`) to
/// the subscribe, i.e. it accepts everything — so the test cannot pass merely because
/// the wrong AMF refused. The ONLY difference between the two stubs is which GUAMI the
/// NRF advertises for it; behaviour is identical, which is what makes "which stub
/// recorded it" the load-bearing signal.
async fn start_stub_amf(rec: Arc<AmfRecorder>) -> (nextgcore_sbi::server::SbiServer, u16) {
    let (server, addr) = nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: Req| {
        let rec = Arc::clone(&rec);
        async move {
            let path = req.header.uri.split('?').next().unwrap_or("").to_string();
            rec.record(&req.header.method, &path);
            if req.header.method == "POST" && path.ends_with("/n1-n2-messages/subscriptions") {
                return Resp::with_status(201)
                    .with_json_body(&serde_json::json!({
                        "n1n2NotifySubscriptionId": "stub-sub-1"
                    }))
                    .unwrap_or_else(|_| Resp::with_status(500));
            }
            if req.header.method == "POST" && path.ends_with("/n1-n2-messages") {
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

/// One AMF NFProfile with a specific `amfInfo.guamiList`, as the stub NRF returns it.
fn amf_profile(instance_id: &str, port: u16, amf_id: &str) -> serde_json::Value {
    serde_json::json!({
        "nfInstanceId": instance_id,
        "nfType": "AMF",
        "ipv4Addresses": ["127.0.0.1"],
        // The member the client-side GUAMI check reads (TS 29.510 §6.1.6.2.4). Both
        // stubs serve PLMN 001-01 and differ only in `amfId`, so the test cannot pass
        // by accidentally discriminating on the PLMN.
        "amfInfo": {
            "guamiList": [{ "plmnId": {"mcc": "001", "mnc": "01"}, "amfId": amf_id }]
        },
        "nfServices": [{
            "serviceName": "namf-comm",
            "scheme": "http",
            "ipEndPoints": [{ "ipv4Address": "127.0.0.1", "port": port }]
        }]
    })
}

/// One discovery the stub NRF received: the query parameters the SBI server decoded
/// out of the request line.
///
/// `http.params`, not a hand-split of `header.uri`: the server sets `header.uri` to the
/// PATH only (`server.rs`'s `convert_request` — `req.uri().path()`) and decodes the
/// query into `http.params` percent-DECODED (TS 29.500 §5.2.10.2). Splitting
/// `header.uri` on `?` therefore always yields an empty query, which is how the first
/// version of this test recorded `[""]` and asserted nothing — and how its sibling
/// "no `guami` parameter" assertion passed vacuously. Reading `params` is also what the
/// rest of this tree does (see `app.rs`'s `req.http.params.get("snssai")`), and it hands
/// back the DECODED value, which is what an assertion about the GUAMI's content wants.
type Discovery = std::collections::HashMap<String, String>;

/// Start a stub NRF that answers AMF discovery with BOTH stub AMFs, `wrong` FIRST.
///
/// Returns the NRF's port. The ordering is the falsifier: with the wrong AMF first,
/// `parse_first_endpoint` — the pre-#92 selection — sends to it, so a regression to
/// type-only discovery fails this test rather than passing it by luck.
///
/// The stub also records each discovery's decoded query parameters, so the test can
/// assert the TS 29.510 §6.2.3.2.3.1 `guami` parameter was actually SENT (spec
/// Decision 1's first half) even though this NRF, like nextgcore's own `nrfd`, ignores
/// it.
async fn start_stub_nrf(
    wrong_port: u16,
    right_port: u16,
    queries: Arc<Mutex<Vec<Discovery>>>,
) -> (nextgcore_sbi::server::SbiServer, u16) {
    let (server, addr) = nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: Req| {
        let queries = Arc::clone(&queries);
        async move {
            if req.header.uri != "/nnrf-disc/v1/nf-instances" {
                return Resp::with_status(404);
            }
            if let Ok(mut q) = queries.lock() {
                q.push(req.http.params.clone());
            }
            // Deliberately unfiltered and wrong-first: the NRF answers with every AMF
            // it knows, exactly as an NRF that does not implement the `guami`
            // parameter would.
            Resp::with_status(200)
                .with_json_body(&serde_json::json!({
                    "nfInstances": [
                        amf_profile("amf-wrong", wrong_port, WRONG_AMF_ID),
                        amf_profile("amf-serving", right_port, SERVING_AMF_ID),
                    ]
                }))
                .unwrap_or_else(|_| Resp::with_status(500))
        }
    })
    .await;
    (server, addr.port())
}

/// The GUAMI of the AMF that actually serves the UE in this fixture.
const SERVING_AMF_ID: &str = "cafe01";
/// The GUAMI of the other registered AMF — listed FIRST by the stub NRF.
const WRONG_AMF_ID: &str = "beef02";

/// #92 criterion 7 (delivery leg): the N1N2MessageTransfer arrives at the AMF whose
/// `amfInfo.guamiList` matches the association's stored GUAMI, and NOT at the AMF the
/// NRF listed first.
///
/// Why this assertion is load-bearing: both stubs accept everything identically, and
/// the NRF returns both with the wrong one first. So "the serving stub recorded a
/// transfer" can only be true if pcfd read the association's GUAMI and matched it
/// against the candidates' profiles. The paired assertion on the wrong stub is the
/// one that catches a fan-out bug (delivering to both, which would also satisfy the
/// first assertion alone), and it is safe as an absence because the serving stub's
/// non-zero count on the SAME fixture proves the recording mechanism works — that is
/// the control.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // std guard held across .await to serialize the process-global NRF URI (current-thread test)
async fn delivery_targets_the_amf_matching_the_stored_guami() {
    // The NRF URI and the PCF self identity are PROCESS-GLOBAL, so a test that sets
    // them races any other test that does. Serialize on the crate-wide guard rather
    // than adding a private lock the other side would not know about.
    let _guard = nextgcore_pcfd::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // Drives production peer-call code against loopback PLAINTEXT peers, i.e. a
    // dev-profile deployment (issue #63). Declared rather than inherited from env.
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);

    let wrong = Arc::new(AmfRecorder::default());
    let serving = Arc::new(AmfRecorder::default());
    let (wrong_srv, wrong_port) = start_stub_amf(Arc::clone(&wrong)).await;
    let (serving_srv, serving_port) = start_stub_amf(Arc::clone(&serving)).await;
    let queries: Arc<Mutex<Vec<Discovery>>> = Arc::new(Mutex::new(Vec::new()));
    let (nrf_srv, nrf_port) = start_stub_nrf(wrong_port, serving_port, Arc::clone(&queries)).await;

    nextgcore_sbi::context::global_context()
        .set_nrf_uri(format!("http://127.0.0.1:{nrf_port}"))
        .await;

    let supi = "imsi-001010000009201";
    let assoc = ue_policy_add(supi, "http://127.0.0.1:9/ue-policy-notify", "");
    ue_policy_set_serving_amf(
        &assoc.pol_asso_id,
        Some(AmfGuami {
            mcc: "001".into(),
            mnc: "01".into(),
            amf_id: SERVING_AMF_ID.into(),
        }),
        None,
    );

    let result = tokio::time::timeout(
        Duration::from_secs(10),
        nextgcore_pcfd::sbi_path::pcf_deliver_ue_policy(&assoc.pol_asso_id, supi, &[0x80, 0x01]),
    )
    .await
    .expect("delivery is bounded");
    assert!(
        result.is_ok(),
        "the serving stub AMF 200-accepts the transfer, so delivery must succeed: {result:?}"
    );

    // POSITIVE: the serving AMF recorded the transfer, at the expected resource path.
    assert_eq!(
        serving.transfers(),
        1,
        "the serving AMF (guami amfId={SERVING_AMF_ID}) must receive the N1N2 transfer; it \
         recorded {:?}",
        serving.paths()
    );
    assert!(
        serving
            .paths()
            .iter()
            .any(|p| p == &format!("POST /namf-comm/v1/ue-contexts/{supi}/n1-n2-messages")),
        "the transfer must address this UE's n1-n2-messages resource (TS 29.518 §5.2.2.3.1); \
         got {:?}",
        serving.paths()
    );
    // Control-backed absence: the serving stub's count above proves an arrival at
    // either stub IS observable, so a zero here means "not addressed", not "not wired".
    assert_eq!(
        wrong.transfers(),
        0,
        "the FIRST-listed, non-serving AMF must receive nothing — it recorded {:?}",
        wrong.paths()
    );

    // Spec Decision 1's other half: the `guami` query parameter is SENT for a
    // conformant NRF, even though this one (like nextgcore's own nrfd) ignores it.
    //
    // Asserted on the DECODED parameter value, which is what makes this a statement
    // about the GUAMI's content rather than about percent-encoding: the value must
    // parse as the TS 29.571 `Guami` JSON naming the serving AMF. Asserting a substring
    // of the raw query would also pass for a `guami` that was sent malformed.
    let sent = queries.lock().map(|q| q.clone()).unwrap_or_default();
    assert!(
        !sent.is_empty(),
        "the delivery must have performed an NRF discovery"
    );
    for q in &sent {
        assert_eq!(
            q.get("target-nf-type").map(String::as_str),
            Some("AMF"),
            "the discovery must be scoped to AMFs; got {q:?}"
        );
        let guami = q.get("guami").unwrap_or_else(|| {
            panic!(
                "every AMF discovery must carry the TS 29.510 §6.2.3.2.3.1 `guami` parameter; \
                 got {q:?}"
            )
        });
        let parsed: serde_json::Value = serde_json::from_str(guami).unwrap_or_else(|e| {
            panic!("`guami` must be a JSON-serialized Guami ({e}); got {guami}")
        });
        assert_eq!(
            parsed.get("amfId").and_then(|v| v.as_str()),
            Some(SERVING_AMF_ID),
            "the `guami` parameter must name the SERVING AMF's amfId; got {parsed}"
        );
        assert_eq!(
            parsed.pointer("/plmnId/mcc").and_then(|v| v.as_str()),
            Some("001"),
            "and its PLMN, without which the amfId is ambiguous; got {parsed}"
        );
    }

    nrf_srv.stop().await.ok();
    serving_srv.stop().await.ok();
    wrong_srv.stop().await.ok();
}

/// #92 criterion 7 (subscribe leg): the N1N2MessageSubscribe goes to the SAME serving
/// AMF, selected the same way.
///
/// Asserted separately from the delivery because the two legs resolve the AMF through
/// independent calls, and the failure this guards against is specifically them
/// DISAGREEING: a subscription on AMF A and a transfer on AMF B is a delivery whose
/// MANAGE UE POLICY COMPLETE has nowhere to arrive, so the association dies on T3501
/// with no signal that the two legs picked different nodes. Both counts are therefore
/// checked on the serving stub in one run.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // std guard held across .await to serialize the process-global NRF URI (current-thread test)
async fn subscribe_targets_the_same_serving_amf_as_delivery() {
    let _guard = nextgcore_pcfd::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);

    let wrong = Arc::new(AmfRecorder::default());
    let serving = Arc::new(AmfRecorder::default());
    let (wrong_srv, wrong_port) = start_stub_amf(Arc::clone(&wrong)).await;
    let (serving_srv, serving_port) = start_stub_amf(Arc::clone(&serving)).await;
    let queries: Arc<Mutex<Vec<Discovery>>> = Arc::new(Mutex::new(Vec::new()));
    let (nrf_srv, nrf_port) = start_stub_nrf(wrong_port, serving_port, Arc::clone(&queries)).await;

    nextgcore_sbi::context::global_context()
        .set_nrf_uri(format!("http://127.0.0.1:{nrf_port}"))
        .await;

    let supi = "imsi-001010000009202";
    let assoc = ue_policy_add(supi, "http://127.0.0.1:9/ue-policy-notify", "");
    ue_policy_set_serving_amf(
        &assoc.pol_asso_id,
        Some(AmfGuami {
            mcc: "001".into(),
            mnc: "01".into(),
            amf_id: SERVING_AMF_ID.into(),
        }),
        None,
    );

    let run = async {
        let sub = nextgcore_pcfd::sbi_path::pcf_subscribe_ue_policy_notify(
            &assoc.pol_asso_id,
            supi,
            "http://127.0.0.1:9/npcf-ue-policy-control/v1/notify/x/n1-message-notify",
        )
        .await
        .expect("subscribe reaches an AMF");
        // POSITIVE: the id came back from the SERVING stub's 201 body, so the
        // subscription genuinely completed at that node rather than merely being sent.
        assert_eq!(
            sub.as_deref(),
            Some("stub-sub-1"),
            "the serving AMF's minted n1n2NotifySubscriptionId must be returned"
        );
        nextgcore_pcfd::sbi_path::pcf_deliver_ue_policy(&assoc.pol_asso_id, supi, &[0x80, 0x01])
            .await
            .expect("delivery to the serving AMF succeeds");
    };
    tokio::time::timeout(Duration::from_secs(12), run)
        .await
        .expect("subscribe + deliver are bounded");

    assert_eq!(
        serving.subscribes(),
        1,
        "the subscribe must land on the serving AMF; it recorded {:?}",
        serving.paths()
    );
    assert_eq!(
        serving.transfers(),
        1,
        "and so must the transfer — the same AMF, resolved twice; serving recorded {:?}",
        serving.paths()
    );
    // Control-backed absence, as above: the serving stub's two non-zero counts prove
    // both request kinds are observable at a stub.
    assert_eq!(
        wrong.subscribes() + wrong.transfers(),
        0,
        "the non-serving AMF must see neither leg — it recorded {:?}",
        wrong.paths()
    );

    nrf_srv.stop().await.ok();
    serving_srv.stop().await.ok();
    wrong_srv.stop().await.ok();
}

/// #92's documented fallback: with NO GUAMI stored, the first discovered endpoint is
/// used — the pre-#92 single-AMF behaviour the issue asks be preserved.
///
/// This is the test that stops the fix from being a regression for every association
/// created before it, and it asserts POSITIVELY: the wrong-listed-first AMF (which is
/// simply "the first one" when there is nothing to match against) records the
/// transfer. Pairing it with the two tests above is what makes the GUAMI selection
/// falsifiable — the same fixture produces a DIFFERENT target purely because the
/// association carries a GUAMI.
#[tokio::test]
#[allow(clippy::await_holding_lock)] // std guard held across .await to serialize the process-global NRF URI (current-thread test)
async fn no_stored_guami_falls_back_to_the_first_endpoint() {
    let _guard = nextgcore_pcfd::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);

    let first = Arc::new(AmfRecorder::default());
    let second = Arc::new(AmfRecorder::default());
    let (first_srv, first_port) = start_stub_amf(Arc::clone(&first)).await;
    let (second_srv, second_port) = start_stub_amf(Arc::clone(&second)).await;
    let queries: Arc<Mutex<Vec<Discovery>>> = Arc::new(Mutex::new(Vec::new()));
    let (nrf_srv, nrf_port) = start_stub_nrf(first_port, second_port, Arc::clone(&queries)).await;

    nextgcore_sbi::context::global_context()
        .set_nrf_uri(format!("http://127.0.0.1:{nrf_port}"))
        .await;

    // No `ue_policy_set_serving_amf` call: an association as it would exist before
    // #92, or one created by an AMF that sent no `guami`.
    let supi = "imsi-001010000009203";
    let assoc = ue_policy_add(supi, "http://127.0.0.1:9/ue-policy-notify", "");

    tokio::time::timeout(
        Duration::from_secs(10),
        nextgcore_pcfd::sbi_path::pcf_deliver_ue_policy(&assoc.pol_asso_id, supi, &[0x80, 0x01]),
    )
    .await
    .expect("delivery is bounded")
    .expect("the first endpoint accepts the transfer");

    assert_eq!(
        first.transfers(),
        1,
        "with no stored GUAMI the FIRST discovered endpoint is used (pre-#92 behaviour, \
         preserved); first recorded {:?}, second {:?}",
        first.paths(),
        second.paths()
    );
    // And the `guami` parameter is absent, because there is no GUAMI to filter on —
    // sending an empty one would ask a conformant NRF for AMFs serving nothing.
    //
    // The absence is safe to assert here because the SAME recording mechanism, on the
    // same stub, is proven to observe a present `guami` in
    // `delivery_targets_the_amf_matching_the_stored_guami` above. Without that control
    // this would be the assertion that passes because nothing was ever recorded — which
    // is exactly what it did before the harness read `http.params` instead of splitting
    // the (query-less) `header.uri`.
    let sent = queries.lock().map(|q| q.clone()).unwrap_or_default();
    assert_eq!(
        sent.len(),
        1,
        "exactly one discovery was performed, and it WAS recorded; got {sent:?}"
    );
    assert_eq!(
        sent[0].get("target-nf-type").map(String::as_str),
        Some("AMF"),
        "the recording captured the real query parameters; got {sent:?}"
    );
    assert_eq!(
        sent[0].get("guami"),
        None,
        "no stored GUAMI => no `guami` query parameter; got {sent:?}"
    );

    nrf_srv.stop().await.ok();
    first_srv.stop().await.ok();
    second_srv.stop().await.ok();
}
