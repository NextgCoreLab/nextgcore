//! #997 review m1: an NRF answer to a `tai`-qualified LMF discovery is MERGED into
//! the discovery cache. It lists only the LMFs serving that TAI, so replacing the
//! cached LMFs with it (#664's rule for an unqualified answer) would drop the LMFs
//! of every other area.
//!
//! An integration test, so it runs in its own process: it points the global SBI
//! context at a stand-in NRF and writes the process-wide discovery cache, which
//! amfd's unit tests share.

use std::sync::{Arc, Mutex};

use nextgcore_sbi::context::global_context;
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use serde_json::json;

/// An LMF NFProfile (TS 29.510 §6.1.6.2.2) whose `lmfInfo.taiList` is one TAI of
/// PLMN 001-01 (§6.1.6.2.46).
fn lmf_profile(id: &str, port: u16, tac: &str) -> serde_json::Value {
    json!({
        "nfInstanceId": id,
        "nfType": "LMF",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": ["127.0.0.1"],
        "priority": 1,
        "capacity": 100,
        "lmfInfo": {
            "servingAccessTypes": ["3GPP_ACCESS"],
            "servingAnNodeTypes": ["GNB"],
            "servingRatTypes": ["NR"],
            "taiList": [{ "plmnId": { "mcc": "001", "mnc": "01" }, "tac": tac }]
        },
        "nfServices": [{
            "serviceInstanceId": "1",
            "serviceName": "nlmf-loc",
            "versions": [{ "apiVersionInUri": "v1", "apiFullVersion": "1.0.0" }],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{ "ipv4Address": "127.0.0.1", "port": port }]
        }]
    })
}

/// A stand-in LMF answering DetermineLocation with a position, counting the calls.
async fn stand_in_lmf() -> (nextgcore_sbi::server::SbiServer, u16, Arc<Mutex<usize>>) {
    let calls = Arc::new(Mutex::new(0usize));
    let counted = Arc::clone(&calls);
    let (server, addr) =
        nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
            let counted = Arc::clone(&counted);
            async move {
                if req.header.uri.contains("/nlmf-loc/v1/determine-location") {
                    *counted.lock().expect("calls") += 1;
                }
                SbiResponse::with_status(200).with_body(
                    json!({ "locationEstimate": {
                        "shape": "POINT",
                        "point": { "lat": 1.0, "lon": 2.0 }
                    }})
                    .to_string(),
                    "application/json",
                )
            }
        })
        .await;
    (server, addr.port(), calls)
}

fn ue_in_tac(tac: u32) -> nextgcore_amfd::context::AmfUe {
    let mut ue = nextgcore_amfd::context::AmfUe::new(9_970_001, 1);
    ue.supi = Some("imsi-001010000997001".to_string());
    ue.nr_tai.plmn_id = nextgcore_amfd::context::PlmnId::new("001", "01");
    ue.nr_tai.tac = tac;
    ue
}

/// Each `tai` query is answered with only that TAI's LMF. A UE in TAC 2, then one in
/// TAC 1, each discover their own; both LMFs stay cached, and the next UEs in either
/// TAC are served from the cache with no further discovery.
///
/// REVERT-VERIFIED: with a qualified answer replacing the cached LMFs, the TAC-1
/// discovery drops the TAC-2 LMF and the third request discovers again.
#[tokio::test]
async fn a_tai_qualified_discovery_keeps_the_other_areas_lmfs() {
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    std::env::remove_var("LMF_SBI_ADDR");
    std::env::remove_var("LMF_SBI_PORT");

    let (_lmf1, port1, calls1) = stand_in_lmf().await;
    let (_lmf2, port2, calls2) = stand_in_lmf().await;
    let queries: Arc<Mutex<Vec<String>>> = Arc::default();
    let seen = Arc::clone(&queries);
    let (_nrf, nrf_addr) =
        nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
            let seen = Arc::clone(&seen);
            async move {
                let tai = req.http.params.get("tai").cloned().unwrap_or_default();
                seen.lock().expect("queries").push(tai.clone());
                let tac = serde_json::from_str::<serde_json::Value>(&tai)
                    .ok()
                    .and_then(|t| t.get("tac").and_then(|v| v.as_str()).map(str::to_string));
                let profiles = match tac.as_deref() {
                    Some("000001") => vec![lmf_profile(
                        "99700000-0000-4000-8000-000000000011",
                        port1,
                        "000001",
                    )],
                    Some("000002") => vec![lmf_profile(
                        "99700000-0000-4000-8000-000000000012",
                        port2,
                        "000002",
                    )],
                    _ => Vec::new(),
                };
                let mut resp = SbiResponse::with_status(200);
                resp.http.content =
                    Some(json!({ "validityPeriod": 3600, "nfInstances": profiles }).to_string());
                resp
            }
        })
        .await;
    let ctx = global_context();
    ctx.set_nrf_uri(format!("http://{nrf_addr}")).await;
    ctx.clear_nf_instances().await;

    for (n, tac) in [2u32, 1, 2, 1].into_iter().enumerate() {
        let before = (*calls1.lock().unwrap(), *calls2.lock().unwrap());
        nextgcore_amfd::sbi_path::call_lmf_determine_location(&ue_in_tac(tac), &json!({}))
            .await
            .expect("positioned");
        let after = (*calls1.lock().unwrap(), *calls2.lock().unwrap());
        let want = if tac == 1 {
            (before.0 + 1, before.1)
        } else {
            (before.0, before.1 + 1)
        };
        assert_eq!(after, want, "request {n}, TAC {tac}: (LMF1, LMF2) calls");
    }
    let queries = queries.lock().unwrap().clone();
    assert_eq!(
        queries.len(),
        2,
        "one discovery per TAI, then the cache: {queries:?}"
    );
    let cached = ctx
        .find_nf_instances_by_type(nextgcore_sbi::types::NfType::Lmf)
        .await;
    assert_eq!(cached.len(), 2, "both areas' LMFs stay cached");
}
