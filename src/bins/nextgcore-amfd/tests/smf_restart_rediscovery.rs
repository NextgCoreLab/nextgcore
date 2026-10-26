//! #664 / #673: an SM Context Create to a restarted SMF reaches its new address.
//!
//! This is an integration test, so it runs in its own process. It seeds the
//! process-wide SBI discovery cache, points the global context at a stand-in
//! NRF, and depends on the endpoint hold-down map. Every amfd path that
//! resolves the SMF (PDU session establishment, `release_all_pdu_sessions`,
//! ...) reads those same globals. As a unit test it shared them with roughly
//! 850 concurrent tests. When one of those resolved the SMF during this test's
//! window, it got the dead cached SMF, failed against it, and evicted the stale
//! profile (or consumed the resend). This test's own call then had nothing to
//! fail over from and ended in "Connection refused", about 1 CI run in 4
//! (#673). Locking only the tests known to touch the globals (#674) could not
//! cover the paths that touch them as a side effect.

use base64::Engine as _;
use nextgcore_amfd::sbi_path::{self, SmContextIdentity};
use nextgcore_sbi::context::{global_context, NfInstance, NfService};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};

/// A UE PDU Session Establishment Request N1 container (PSI=5, PTI=2).
const UE_N1_REQUEST: [u8; 14] = [
    0x2E, 0x05, 0x02, 0xC1, 0xFF, 0xFF, 0x93, 0xA2, 0x28, 0x01, 0x00, 0x55, 0x00, 0x10,
];

fn test_identity() -> SmContextIdentity {
    SmContextIdentity {
        supi: Some("imsi-262011234567890".to_string()),
        pei: Some("imeisv-1234567890123456".to_string()),
        guami: Some(serde_json::json!({
            "plmnId": { "mcc": "262", "mnc": "01" },
            "amfId": "01000a",
        })),
        serving_plmn: Some(("262".to_string(), "01".to_string())),
        serving_nf_id: Some("amf-instance-1".to_string()),
        ue_location: Some(serde_json::json!({
            "nrLocation": {
                "tai": { "plmnId": { "mcc": "262", "mnc": "01" }, "tac": "000001" }
            }
        })),
        gpsi: Some("msisdn-491234567890".to_string()),
        origination_timestamp: None,
        request_type: None,
        message_priority: None,
    }
}

/// #664, end to end through the AMF's own code: the SMF restarted at a new
/// address. The AMF's cache holds the old profile; the NRF (a stand-in)
/// still lists it next to the new one, as it does until the old heartbeat
/// expires. `call_smf_create_sm_context` to the cached (dead) SMF must reach
/// the NEW SMF -- the same SM Context Create, not a rejected PDU session --
/// through `register_rediscovery_hook` -> `amf_nrf_discover` (replace) ->
/// the SBI client's one-shot resend.
#[tokio::test]
async fn sm_context_create_reaches_an_smf_restarted_at_a_new_address() {
    use nextgcore_sbi::types::NfType;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let ctx = global_context();
    // Plaintext loopback stand-ins: a dev-profile deployment, said explicitly.
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);

    let old_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let hits = Arc::new(AtomicUsize::new(0));
    let served = hits.clone();
    let (smf, new_smf) =
        nextgcore_sbi::test_support::sbi_server_on_free_port(move |_req: SbiRequest| {
            let served = served.clone();
            async move {
                served.fetch_add(1, Ordering::SeqCst);
                let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
                let mut resp = SbiResponse::with_status(201);
                resp.http.content = Some(
                    serde_json::json!({
                        "smContextRef": "664",
                        "n1SmMsg": b64(&[0x2E, 0x05, 0x02, 0xC2]),
                        "n2SmInfo": b64(&[0x00, 0x01]),
                    })
                    .to_string(),
                );
                resp
            }
        })
        .await;

    let profile = |id: &str, port: u16| {
        serde_json::json!({
            "nfInstanceId": id, "nfType": "SMF", "nfStatus": "REGISTERED",
            "ipv4Addresses": ["127.0.0.1"],
            "nfServices": [{
                "serviceInstanceId": "1", "serviceName": "nsmf-pdusession",
                "ipEndPoints": [{ "ipv4Address": "127.0.0.1", "port": port }]
            }]
        })
    };
    let answer = serde_json::json!({
        "validityPeriod": 3600,
        "nfInstances": [profile("smf-664-old", old_port), profile("smf-664-new", new_smf.port())],
    })
    .to_string();
    let (nrf, nrf_addr) =
        nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
            let answer = answer.clone();
            async move {
                if req.header.uri.contains("target-nf-type=SMF")
                    || req.http.params.get("target-nf-type").map(String::as_str) == Some("SMF")
                {
                    let mut resp = SbiResponse::with_status(200);
                    resp.http.content = Some(answer);
                    resp
                } else {
                    SbiResponse::with_status(404)
                }
            }
        })
        .await;
    ctx.set_nrf_uri(format!("http://{nrf_addr}")).await;
    sbi_path::register_rediscovery_hook();

    // The AMF discovered the SMF before it restarted: only the old profile.
    let mut stale = NfInstance::new("smf-664-old", NfType::Smf);
    let mut svc = NfService::new(
        "nsmf-pdusession",
        nextgcore_sbi::types::SbiServiceType::NsmfPdusession,
    );
    svc.ip_addresses = vec!["127.0.0.1".into()];
    svc.port = old_port;
    stale.add_service(svc);
    ctx.replace_nf_instances(
        NfType::Smf,
        vec![stale],
        std::time::Duration::from_secs(3600),
    )
    .await;
    let (host, port) =
        sbi_path::resolve_nf_endpoint_async(sbi_path::SbiServiceType::NsmfPdusession)
            .await
            .unwrap();
    assert_eq!(
        (host.as_str(), port),
        ("127.0.0.1", old_port),
        "premise: cached old SMF"
    );

    let created = sbi_path::call_smf_create_sm_context(
        &host,
        port,
        5,
        1,
        None,
        Some("internet"),
        &UE_N1_REQUEST,
        false,
        &test_identity(),
    )
    .await
    .expect("SM Context Create must reach the restarted SMF");
    assert_eq!(created.sm_context_ref, "664");
    assert_eq!(
        created.smf_authority,
        Some(format!("127.0.0.1:{}", new_smf.port())),
        "#669: the context lives in the SMF that answered, not the dead one asked"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    // And the next PDU session resolves straight to the new SMF.
    assert_eq!(
        sbi_path::resolve_nf_endpoint_async(sbi_path::SbiServiceType::NsmfPdusession)
            .await
            .unwrap(),
        ("127.0.0.1".to_string(), new_smf.port())
    );

    ctx.replace_nf_instances(NfType::Smf, vec![], std::time::Duration::from_secs(1))
        .await;
    ctx.clear_endpoint_failure("127.0.0.1", old_port);
    ctx.set_rediscovery_hook(Arc::new(|_, _| Box::pin(async {})));
    ctx.clear_nrf_uri().await;
    nrf.stop().await.ok();
    smf.stop().await.ok();
}
