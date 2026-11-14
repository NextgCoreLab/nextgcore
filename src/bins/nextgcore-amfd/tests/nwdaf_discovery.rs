//! #1504: under `paging.strategy: nwdaf-mobility` the AMF finds the NWDAF
//! through the NRF and asks it for a UE_MOBILITY prediction over a period the
//! NWDAF accepts.
//!
//! An integration test, so it runs in its own process: it points the global SBI
//! context at a stand-in NRF and writes the process-wide discovery cache, which
//! amfd's unit tests share. It never sets `NWDAF_ENDPOINT_OVERRIDE`, which is
//! how the paging unit tests missed both defects.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use nextgcore_sbi::context::global_context;
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use serde_json::{json, Value};

const NWDAF_ID: &str = "15040000-0000-4000-8000-000000001504";

/// A SearchResult as the NRF answers `GET /nnrf-disc/v1/nf-instances
/// ?target-nf-type=NWDAF&requester-nf-type=AMF&service-names=nnwdaf-analyticsinfo`
/// (TS 29.510 §6.2.3.2.3.1), carrying one NWDAF NFProfile with `nwdafInfo`
/// (§6.1.6.2.2, `NwdafInfo`), the shape nwdafd registers.
fn nwdaf_search_result(port: u16) -> Value {
    json!({
        "validityPeriod": 3600,
        "nfInstances": [{
            "nfInstanceId": NWDAF_ID,
            "nfType": "NWDAF",
            "nfStatus": "REGISTERED",
            "ipv4Addresses": ["127.0.0.1"],
            "nwdafInfo": { "eventIds": ["NF_LOAD", "UE_MOBILITY"] },
            "nfServices": [{
                "serviceInstanceId": "nnwdaf-analyticsinfo-1",
                "serviceName": "nnwdaf-analyticsinfo",
                "versions": [{ "apiVersionInUri": "v1", "apiFullVersion": "1.4.0" }],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{ "ipv4Address": "127.0.0.1", "port": port }]
            }]
        }]
    })
}

/// nwdafd's prediction body (`amf_mobility::ue_mobility_infos`) naming NCI
/// `000000020`.
fn prediction() -> Value {
    json!({
        "ueMobs": [{
            "ts": "2026-11-14T19:44:21Z",
            "duration": 30,
            "locInfos": [{
                "loc": { "nrLocation": {
                    "tai": { "plmnId": { "mcc": "999", "mnc": "70" }, "tac": "000001" },
                    "ncgi": { "plmnId": { "mcc": "999", "mnc": "70" }, "nrCellId": "000000020" }
                }},
                "confidence": 67
            }]
        }]
    })
}

/// TS 29.520 §4.3.2.2.2 (`29520-k00.txt:5889-5893`), as nwdafd's
/// `parse_analytics_target_period` applies it: a period starting in the past and
/// ending in the future is `400 BOTH_STAT_PRED_NOT_ALLOWED`. An absent `startTs`
/// is the present time.
fn both_stat_and_pred(ana_req: &str) -> bool {
    let v: Value = serde_json::from_str(ana_req).expect("ana-req is JSON");
    let at = |k: &str| {
        v.get(k).and_then(Value::as_str).map(|s| {
            chrono::DateTime::parse_from_rfc3339(s)
                .expect("an RFC 3339 DateTime")
                .with_timezone(&chrono::Utc)
        })
    };
    let now = chrono::Utc::now();
    matches!((at("startTs"), at("endTs")), (Some(s), Some(e)) if s < now && e > now)
}

/// The point of #1504: with an NRF that lists an NWDAF, no `NWDAF_SBI_ADDR` and
/// no test override, the AMF discovers the NWDAF, keeps its profile, and its
/// UE_MOBILITY query is one the NWDAF answers. Before, the profile was dropped
/// by `cached_peer_nf_type` ("no NWDAF (NRF discovery found none, ...)"), and
/// once past that, the `startTs = now` window drew a 400.
#[tokio::test]
async fn the_nwdaf_the_nrf_lists_is_found_and_answers_the_prediction_query() {
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    std::env::remove_var("NWDAF_SBI_ADDR");
    std::env::remove_var("NWDAF_SBI_PORT");
    let supi = "imsi-999700000001504";

    // The NWDAF: refuses a straddling window as nwdafd does, else predicts.
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let sink = Arc::clone(&seen);
    let (_nwdaf, nwdaf_addr) =
        nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
            let sink = Arc::clone(&sink);
            async move {
                let p = |k: &str| req.http.params.get(k).cloned().unwrap_or_default();
                let ana_req = p("ana-req");
                sink.lock()
                    .unwrap()
                    .push(format!("{} {} {ana_req}", p("event-id"), p("tgt-ue")));
                if !req
                    .header
                    .uri
                    .starts_with("/nnwdaf-analyticsinfo/v1/analytics")
                {
                    return SbiResponse::with_status(404);
                }
                if both_stat_and_pred(&ana_req) {
                    return SbiResponse::with_status(400)
                        .with_json_body(&json!({ "cause": "BOTH_STAT_PRED_NOT_ALLOWED" }))
                        .expect("json");
                }
                SbiResponse::with_status(200)
                    .with_json_body(&prediction())
                    .expect("json")
            }
        })
        .await;

    let queries = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&queries);
    let answer = nwdaf_search_result(nwdaf_addr.port()).to_string();
    let (_nrf, nrf_addr) =
        nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
            let (counted, answer) = (Arc::clone(&counted), answer.clone());
            async move {
                let p = |k: &str| req.http.params.get(k).map(String::as_str);
                let asks_for_nwdaf = req.header.uri.starts_with("/nnrf-disc/v1/nf-instances")
                    && p("target-nf-type") == Some("NWDAF")
                    && p("requester-nf-type") == Some("AMF")
                    && p("service-names") == Some("nnwdaf-analyticsinfo");
                if !asks_for_nwdaf {
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

    // Discovery: the NRF's NWDAF is the endpoint, and its profile is cached.
    assert_eq!(
        nextgcore_amfd::nwdaf_mobility::resolve_nwdaf_endpoint().await,
        Some(("127.0.0.1".to_string(), nwdaf_addr.port())),
        "the NWDAF must be resolved from the NRF's SearchResult"
    );
    assert_eq!(
        queries.load(Ordering::SeqCst),
        1,
        "one NWDAF discovery query"
    );
    let cached = ctx
        .find_nf_instances_by_type(nextgcore_sbi::types::NfType::Nwdaf)
        .await;
    assert_eq!(
        cached.len(),
        1,
        "the NWDAF profile is cached under NfType::Nwdaf"
    );
    assert_eq!(cached[0].id, NWDAF_ID);
    // #668: the AMF's NRF status subscriptions cover every cached type.
    assert!(nextgcore_amfd::sbi_path::CACHED_PEER_NF_TYPES.contains(&"NWDAF"));

    // The query, through the production path: the NWDAF answers it.
    let predicted = nextgcore_amfd::nwdaf_mobility::query_prediction(supi)
        .await
        .expect("the NWDAF answers 200, not 400 BOTH_STAT_PRED_NOT_ALLOWED")
        .expect("a predicted cell");
    assert_eq!(predicted.nci, 0x0_0000_0020);
    assert_eq!(predicted.confidence, Some(67));
    assert_eq!(
        queries.load(Ordering::SeqCst),
        1,
        "the query's resolution is served from the discovery cache"
    );

    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(
        seen[0].starts_with(&format!(r#"UE_MOBILITY {{"supis":["{supi}"]}} {{"endTs":"#)),
        "UE_MOBILITY for the SUPI, over a period from the present time: {seen:?}"
    );
}
