//! #2179 / #2187 (R41, SECURITY): the runtime backstop to the source guard
//! `libs/nextgcore-sbi/tests/nf_status_notify_receivers.rs`.
//!
//! That guard scans source text, so a route whose path never appears whole (a
//! path joined at runtime from two consts, or split across `concat!` pieces in a
//! `macro_rules!` route) escapes it. This test does not read source: it
//! subscribes at a stand-in NRF the way the maintainer does (on
//! `nrf_subscription::notification_uri()`), takes every
//! `nfStatusNotificationUri` the NRF was given, and POSTs a forged
//! NF_DEREGISTERED to each one through amfd's real router
//! (`namf_server::namf_request_handler`) under the production SBI profile. Each
//! must be 403 from a sender that is neither the NRF nor a relaying SCP, and
//! the NRF's own certificate on the same path must get past the check (204).
//!
//! What it does not prove: the TLS layer is not exercised (the request carries
//! the verified-certificate fields the server would fill in), and only paths
//! amfd advertises to the NRF are tried; a receiver on a path amfd never
//! advertises is the source guard's to find. An integration test so that it
//! runs in its own process: it sets the production profile, which amfd's unit
//! tests (sharing the Dev override) must not see.

use std::sync::{Arc, Mutex};

use nextgcore_amfd::nrf_subscription::{self, NrfSubscriptions};
use nextgcore_amfd::sbi_path::CACHED_PEER_NF_TYPES;
use nextgcore_sbi::context::{global_context, NfInstance, NfService};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::security::{set_sbi_profile_override, SbiProfile};
use serde_json::{json, Value};

/// A stand-in NRF that grants every NFStatusSubscribe and records its body.
async fn stand_in_nrf() -> (
    nextgcore_sbi::server::SbiServer,
    std::net::SocketAddr,
    Arc<Mutex<Vec<Value>>>,
) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = seen.clone();
    let (server, addr) =
        nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
            let seen = s.clone();
            async move {
                let body: Value = req
                    .http
                    .content
                    .as_deref()
                    .and_then(|b| serde_json::from_str(b).ok())
                    .unwrap_or(Value::Null);
                if req.header.method != "POST"
                    || req.header.uri.split('?').next() != Some("/nnrf-nfm/v1/subscriptions")
                {
                    return SbiResponse::with_status(404);
                }
                let n = {
                    let mut seen = seen.lock().unwrap();
                    seen.push(body.clone());
                    seen.len()
                };
                let mut doc = body;
                doc["subscriptionId"] = json!(format!("sub-2179-{n}"));
                let mut r = SbiResponse::with_status(201);
                r.http.content = Some(doc.to_string());
                r.http.set_header("Content-Type", "application/json");
                r
            }
        })
        .await;
    (server, addr, seen)
}

fn cached_smf(id: &str, port: u16) -> NfInstance {
    use nextgcore_sbi::types::{NfType, SbiServiceType};
    let mut i = NfInstance::new(id, NfType::Smf);
    let mut svc = NfService::new("nsmf-pdusession", SbiServiceType::NsmfPdusession);
    svc.ip_addresses = vec!["127.0.0.1".into()];
    svc.port = port;
    i.add_service(svc);
    i
}

/// The path part of an absolute `nfStatusNotificationUri`.
fn path_of(uri: &str) -> &str {
    let rest = uri.split_once("://").map_or(uri, |(_, r)| r);
    &rest[rest.find('/').expect("an absolute URI with a path")..]
}

#[tokio::test]
async fn every_advertised_nf_status_notify_path_refuses_a_forged_sender_2179() {
    // Subscribing goes out over loopback plaintext: dev for this half only.
    set_sbi_profile_override(SbiProfile::Dev);
    let (_nrf, nrf_addr, seen) = stand_in_nrf().await;
    let nrf_uri = format!("http://{nrf_addr}");
    let mut subs = NrfSubscriptions::default();
    nrf_subscription::maintain_all(
        &mut subs,
        &nrf_uri,
        "amf-2179-backstop",
        &nrf_subscription::notification_uri(),
    )
    .await;
    let advertised: Vec<(String, String)> = seen
        .lock()
        .unwrap()
        .iter()
        .map(|b| {
            (
                b["subscrCond"]["nfType"]
                    .as_str()
                    .unwrap_or("?")
                    .to_string(),
                b["nfStatusNotificationUri"]
                    .as_str()
                    .expect("every subscription advertises a notification URI")
                    .to_string(),
            )
        })
        .collect();
    assert_eq!(
        advertised.len(),
        CACHED_PEER_NF_TYPES.len(),
        "one subscription per cached NF type: {advertised:?}"
    );

    // Everything below is the receiving side, under production.
    set_sbi_profile_override(SbiProfile::Production);
    let ctx = global_context();
    ctx.add_nf_instance(cached_smf("smf-2179-backstop", 42190))
        .await;
    let body = json!({
        "event": "NF_DEREGISTERED",
        "nfInstanceUri": format!("{nrf_uri}/nnrf-nfm/v1/nf-instances/smf-2179-backstop"),
    });
    let from = |path: &str, types: &[&str]| {
        let mut r =
            SbiRequest::post(path.to_string()).with_body(body.to_string(), "application/json");
        r.peer_cert_present = !types.is_empty();
        r.peer_cert_nf_instance_id =
            (!types.is_empty()).then(|| "ffffffff-2179-4000-8000-0000000000f1".to_string());
        r.peer_cert_nf_types = types.iter().map(|t| t.to_string()).collect();
        r
    };
    for (nf_type, uri) in &advertised {
        let path = path_of(uri);
        for forged in [
            &["AMF"][..],
            &["SMF"],
            &["NRF", "AMF"],
            &["SCP", "AMF"],
            &[],
        ] {
            let resp = nextgcore_amfd::namf_server::namf_request_handler(from(path, forged)).await;
            assert_eq!(
                resp.status, 403,
                "{nf_type} subscription, {path}, sender {forged:?}: {:?}",
                resp.http.content
            );
        }
        assert!(
            ctx.get_nf_instance("smf-2179-backstop").await.is_some(),
            "{nf_type}: a forged sender evicted the SMF"
        );
    }

    // Control: the same paths from the NRF's certificate get past the check, so
    // the 403s above are the sender check and not some earlier refusal. On a
    // subscription other than the SMF's, nothing is evicted.
    for (nf_type, uri) in advertised.iter().filter(|(t, _)| t != "SMF") {
        let resp =
            nextgcore_amfd::namf_server::namf_request_handler(from(path_of(uri), &["NRF"])).await;
        assert_eq!(
            resp.status, 204,
            "{nf_type}: the NRF's own notification is admitted: {:?}",
            resp.http.content
        );
    }
    assert!(ctx.get_nf_instance("smf-2179-backstop").await.is_some());
    ctx.remove_nf_instance("smf-2179-backstop").await;
}
