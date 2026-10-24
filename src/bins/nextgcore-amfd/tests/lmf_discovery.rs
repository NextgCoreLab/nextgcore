//! #938: an LMF the NRF lists is discoverable, so AMF→LMF positioning does not
//! depend on `LMF_SBI_ADDR`.
//!
//! An integration test, so it runs in its own process: it points the global SBI
//! context at a stand-in NRF and writes the process-wide discovery cache, which
//! amfd's unit tests share.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use nextgcore_sbi::context::global_context;
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use serde_json::json;

/// A SearchResult as the NRF answers `GET /nnrf-disc/v1/nf-instances
/// ?target-nf-type=LMF&requester-nf-type=AMF&service-names=nlmf-loc`
/// (TS 29.510 §6.2.3.2.3.1), carrying one LMF NFProfile with `lmfInfo`
/// (§6.1.6.2.2 / `LmfInfo`).
fn lmf_search_result(port: u16) -> serde_json::Value {
    json!({
        "validityPeriod": 3600,
        "nfInstances": [{
            "nfInstanceId": "93800000-0000-4000-8000-000000000938",
            "nfType": "LMF",
            "nfStatus": "REGISTERED",
            "ipv4Addresses": ["127.0.0.1"],
            "lmfInfo": {
                "lmfId": "938",
                "servingAccessTypes": ["3GPP_ACCESS"],
                "servingAnNodeTypes": ["GNB"],
                "servingRatTypes": ["NR"],
                "taiList": [{ "plmnId": { "mcc": "001", "mnc": "01" }, "tac": "000001" }],
                "supportedGADShapes": ["POINT", "ELLIPSOID_ARC"]
            },
            "nfServices": [{
                "serviceInstanceId": "1",
                "serviceName": "nlmf-loc",
                "versions": [{ "apiVersionInUri": "v1", "apiFullVersion": "1.0.0" }],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{ "ipv4Address": "127.0.0.1", "port": port }]
            }]
        }]
    })
}

/// The point of #938: with an NRF that lists an LMF and **no `LMF_SBI_ADDR`**,
/// the AMF resolves the LMF's `nlmf-loc` endpoint from discovery. Before, every
/// LMF profile was dropped by `amf_nrf_discover`'s `nfType` match, so this
/// returned `None` and positioning could not work at all.
#[tokio::test]
async fn an_lmf_the_nrf_lists_is_discoverable_without_the_configured_fallback() {
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    std::env::remove_var("LMF_SBI_ADDR");
    std::env::remove_var("LMF_SBI_PORT");

    // The port the discovered profile advertises; never dialled by this test.
    let lmf_port = nextgcore_sbi::test_support::free_port();
    let queries = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&queries);
    let answer = lmf_search_result(lmf_port).to_string();
    let (_nrf, nrf_addr) =
        nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
            let (counted, answer) = (Arc::clone(&counted), answer.clone());
            async move {
                let uri = req.header.uri.clone();
                let target = req
                    .http
                    .params
                    .get("target-nf-type")
                    .cloned()
                    .unwrap_or_default();
                let services = req
                    .http
                    .params
                    .get("service-names")
                    .cloned()
                    .unwrap_or_default();
                let wants_lmf = target == "LMF" || uri.contains("target-nf-type=LMF");
                let wants_nlmf_loc =
                    services == "nlmf-loc" || uri.contains("service-names=nlmf-loc");
                if !(wants_lmf && wants_nlmf_loc) {
                    return SbiResponse::with_status(404);
                }
                counted.fetch_add(1, Ordering::SeqCst);
                let mut resp = SbiResponse::with_status(200);
                resp.http.content = Some(answer);
                resp
            }
        })
        .await;

    let ctx = global_context();
    ctx.set_nrf_uri(format!("http://{nrf_addr}")).await;
    ctx.clear_nf_instances().await;

    let endpoint = nextgcore_amfd::sbi_path::resolve_lmf_endpoint().await;

    assert_eq!(
        endpoint,
        Some(("127.0.0.1".to_string(), lmf_port)),
        "the LMF must be resolved from the NRF's SearchResult"
    );
    assert_eq!(
        queries.load(Ordering::SeqCst),
        1,
        "exactly one LMF discovery query (target-nf-type=LMF, service-names=nlmf-loc)"
    );

    // The profile is CACHED under the LMF type, so the next resolution needs no
    // query at all, and the subscription machinery (#668) covers it.
    let endpoint = nextgcore_amfd::sbi_path::resolve_lmf_endpoint().await;
    assert_eq!(endpoint, Some(("127.0.0.1".to_string(), lmf_port)));
    assert_eq!(
        queries.load(Ordering::SeqCst),
        1,
        "the second resolution is served from the discovery cache"
    );
    let cached = ctx
        .find_nf_instances_by_type(nextgcore_sbi::types::NfType::Lmf)
        .await;
    assert_eq!(
        cached.len(),
        1,
        "the LMF profile is cached under NfType::Lmf"
    );
    assert_eq!(cached[0].id, "93800000-0000-4000-8000-000000000938");

    // #668: the AMF's NRF status subscriptions cover every cached type, so the
    // LMF now gets one too.
    assert!(nextgcore_amfd::sbi_path::CACHED_PEER_NF_TYPES.contains(&"LMF"));
}
