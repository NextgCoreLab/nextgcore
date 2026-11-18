//! #1642, the PCF half: an AMF that moves a UE policy association made before
//! #1518 to a tokened `notificationUri` sends it in Npcf_UEPolicyControl_Update
//! (TS 29.525 §4.2.3.1, the body amfd's `call_pcf_ue_policy_update_serving_amf`
//! builds: `notificationUri`, `guami`, `servingNfId`). The PCF must answer 2xx, the
//! answer the AMF adopts the token on, and send its next notification to the tokened
//! URI, not the token-less one it held before. The AMF half is amfd's
//! `ue_context_store_tests::*_1642`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use nextgcore_pcfd::handle_ue_policy_update;
use nextgcore_pcfd::ue_policy::ue_policy_add;
use nextgcore_sbi::message::{SbiRequest as Req, SbiResponse as Resp};

#[tokio::test]
#[allow(clippy::await_holding_lock)] // std guard held across .await to serialize the process-global PCF context (current-thread test)
async fn the_pcf_takes_a_re_issued_tokened_notification_uri_and_notifies_it_1642() {
    let _guard = nextgcore_pcfd::test_support::CONTEXT_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let _delivery = nextgcore_pcfd::test_support::ue_policy_delivery(false);

    let paths: Arc<Mutex<Vec<String>>> = Arc::default();
    let sink = Arc::clone(&paths);
    let (consumer, addr) = nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: Req| {
        let sink = Arc::clone(&sink);
        async move {
            if req.header.method == "POST" {
                sink.lock()
                    .unwrap()
                    .push(req.header.uri.split('?').next().unwrap_or("").to_string());
            }
            Resp::with_status(204)
        }
    })
    .await;
    let supi = "imsi-001010000016421";
    let base = format!("http://127.0.0.1:{}/namf-callback/v1/{supi}", addr.port());
    let token_less = format!("{base}/ue-policy-notify");
    let tokened = format!("{base}/ue-policy-notify/0123456789abcdef0123456789ab1642");
    let assoc = ue_policy_add(supi, &token_less, "");
    let path = format!(
        "/npcf-ue-policy-control/v1/policies/{}/update",
        assoc.pol_asso_id
    );

    // The AMF's re-issue, sent twice (a retry): each is answered 2xx.
    let re_issue = Req::post(path.clone())
        .with_json_body(&serde_json::json!({
            "notificationUri": tokened,
            "guami": {"plmnId": {"mcc": "001", "mnc": "01"}, "amfId": "020040"},
            "servingNfId": "00000000-0000-4000-8000-000000001642",
        }))
        .expect("json");
    for _ in 0..2 {
        let resp = handle_ue_policy_update(&assoc.pol_asso_id, &re_issue).await;
        assert!(
            (200..300).contains(&resp.status),
            "the AMF adopts the token only on a 2xx: {}",
            resp.status
        );
    }

    // The PCF's next notification goes to the tokened URI.
    let before = paths.lock().unwrap().len();
    let trigger = Req::post(path)
        .with_json_body(&serde_json::json!({"triggers": ["UE_POLICY"]}))
        .expect("json");
    let resp = handle_ue_policy_update(&assoc.pol_asso_id, &trigger).await;
    assert_eq!(resp.status, 200);
    let arrived = nextgcore_sbi::test_support::poll_until(
        Duration::from_secs(8),
        Duration::from_millis(50),
        || {
            let paths = Arc::clone(&paths);
            async move { paths.lock().ok()?.get(before).cloned() }
        },
    )
    .await
    .expect("a notification after the re-issue");
    let tokened_path = format!(
        "{}/update",
        &tokened[tokened.find("/namf-callback").unwrap()..]
    );
    assert_eq!(
        arrived, tokened_path,
        "to the tokened URI, not the token-less one"
    );
    assert!(
        paths
            .lock()
            .unwrap()
            .iter()
            .all(|p| !p.ends_with("/ue-policy-notify/update")),
        "nothing went to the token-less URI: {:?}",
        paths.lock().unwrap()
    );
    consumer.stop().await.ok();
}
