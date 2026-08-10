//! Wave-6 WSB-1 + H2 strict-peer tests: pcfd's REAL PcfBinding body builder
//! against bsfd's REAL SBI request handler (no lenient mocks).
//!
//! Specs: TS 29.521 §5.3.2 (PcfBinding must carry pcfFqdn and/or
//! pcfIpEndPoints; `specs/TS29521_Nbsf_Management.yaml`), TS 29.510
//! IpEndPoint, TS 23.503 §6.1.1.2 (BSF binding purpose).
//!
//! The acceptance for WSB-1/H2 is falsifiable here: bsfd's real handler must
//! return 2xx for pcfd's production builder output at ALL THREE of its
//! PCF-address validation sites (PDU-session `pcfBindings`, UE
//! `pcf-ue-bindings`, MBS `pcf-mbs-bindings`), and must keep 400-rejecting
//! the pre-fix legacy body (the permanent regression guard against the
//! lenient-mock trap that hid this defect).

use nextgcore_pcfd::sbi_path::{
    build_pcf_binding_body, build_pcf_binding_body_with, pcf_deregister_bsf_binding,
    pcf_register_bsf_binding, pcf_self_info_set, PcfSelfInfo,
};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use std::sync::Once;

static INIT: Once = Once::new();

/// Bring up the process-global BSF context once and publish the PCF self
/// identity once (OnceLock semantics; all tests share the same values).
fn init_peers() {
    INIT.call_once(|| {
        nextgcore_bsfd::test_support::init_context(64);
        pcf_self_info_set(PcfSelfInfo {
            sbi_addr: "10.45.0.10".to_string(),
            sbi_port: 7777,
            fqdn: None,
            nf_instance_id: uuid::Uuid::new_v4().to_string(),
        });
    });
}

/// pcfd's production PcfBinding body (real builder, real self identity).
fn production_body(supi: &str, ipv4: &str) -> serde_json::Value {
    build_pcf_binding_body(supi, "internet", 1, Some(0x010203), Some(ipv4))
}

/// The pre-WSB-1 legacy body shape (no pcfFqdn/pcfIpEndPoints/pcfId),
/// produced by the same production builder with no self identity.
fn legacy_body(supi: &str, ipv4: &str) -> serde_json::Value {
    build_pcf_binding_body_with(None, supi, "internet", 1, Some(0x010203), Some(ipv4))
}

/// A conformant TS 29.571 `MbsSessionId` OBJECT (anyOf tmgi / ssm).
///
/// These tests previously set `mbsSessionId` to a bare string
/// ("mbs-session-703"), which is not a valid MbsSessionId in any form -- it only
/// passed because bsfd read the field with `.as_str()`, the #97 defect 3 being
/// fixed. `mbsServiceId` is `^[A-Fa-f0-9]{6}$`.
fn mbs_session_id(svc_hex: &str) -> serde_json::Value {
    serde_json::json!({
        "tmgi": {"mbsServiceId": svc_hex, "plmnId": {"mcc": "001", "mnc": "01"}}
    })
}

fn problem(resp: &SbiResponse) -> serde_json::Value {
    serde_json::from_str(resp.http.content.as_deref().expect("problem body")).expect("json body")
}

async fn post(uri: &str, body: &serde_json::Value) -> SbiResponse {
    let req = SbiRequest::post(uri)
        .with_json_body(body)
        .expect("serialize body");
    nextgcore_bsfd::bsf_sbi_request_handler(req).await
}

async fn delete(uri: &str) -> SbiResponse {
    nextgcore_bsfd::bsf_sbi_request_handler(SbiRequest::delete(uri)).await
}

/// Extract the bindingId from a 201 Location header.
fn binding_id_from_location(resp: &SbiResponse, prefix: &str) -> String {
    let loc = resp
        .http
        .get_header("location")
        .expect("201 must carry a Location header")
        .clone();
    assert!(
        loc.starts_with(prefix),
        "Location {loc} does not start with {prefix}"
    );
    let id = loc.rsplit('/').next().unwrap_or_default().to_string();
    assert!(!id.is_empty(), "empty bindingId in Location {loc}");
    id
}

/// WSB-1 acceptance site 1 (bsfd main validation, PDU-session bindings):
/// pcfd's production body -> REAL bsfd handler -> 201 + Location, then
/// DELETE -> 204. A 400 here fails the test (the pre-fix behavior).
#[tokio::test]
async fn pcfd_production_binding_accepted_at_session_site() {
    init_peers();
    let body = production_body("imsi-001010000000701", "10.45.0.71");

    let resp = post("/nbsf-management/v1/pcfBindings", &body).await;
    assert_eq!(
        resp.status, 201,
        "real bsfd must 201-accept pcfd's production PcfBinding, got {} ({:?})",
        resp.status, resp.http.content
    );
    let id = binding_id_from_location(&resp, "/nbsf-management/v1/pcfBindings/");

    // Echoed representation carries the PCF address info we sent.
    let echoed = problem(&resp);
    assert_eq!(echoed["pcfIpEndPoints"][0]["ipv4Address"], "10.45.0.10");
    assert_eq!(echoed["pcfIpEndPoints"][0]["port"], 7777);
    assert_eq!(echoed["supi"], "imsi-001010000000701");

    let del = delete(&format!("/nbsf-management/v1/pcfBindings/{id}")).await;
    assert_eq!(del.status, 204, "delete via real handler");
}

/// WSB-1 acceptance site 2 (UE-policy bindings, bsfd pcf-ue-bindings):
/// the production body's PCF address, RE-KEYED to this resource's schema.
///
/// PcfForUeBinding (TS 29.521) names the address members `pcfForUeFqdn` /
/// `pcfForUeIpEndPoints`; the unprefixed `pcfFqdn` / `pcfIpEndPoints` this test
/// used to send belong to `PcfBinding`, the PDU-session binding. Reusing one
/// body across all three sites only passed because bsfd read the unprefixed
/// names on every resource -- which is exactly the #97 defect. The PCF-address
/// requirement under test is unchanged; only the member names are now the ones
/// this resource actually defines.
///
/// pcfd has no production UE-binding registration path (it POSTs only to
/// /pcfBindings), so there is no builder to re-key -- the mapping lives here.
#[tokio::test]
async fn pcfd_production_binding_accepted_at_ue_site() {
    init_peers();
    let src = production_body("imsi-001010000000702", "10.45.0.72");
    let mut body = serde_json::json!({ "supi": src["supi"].clone() });
    body["pcfForUeIpEndPoints"] = src["pcfIpEndPoints"].clone();
    if let Some(fqdn) = src.get("pcfFqdn") {
        body["pcfForUeFqdn"] = fqdn.clone();
    }
    if let Some(id) = src.get("pcfId") {
        body["pcfId"] = id.clone();
    }

    let resp = post("/nbsf-management/v1/pcf-ue-bindings", &body).await;
    assert_eq!(
        resp.status, 201,
        "real bsfd must 201-accept the UE binding, got {} ({:?})",
        resp.status, resp.http.content
    );
    let id = binding_id_from_location(&resp, "/nbsf-management/v1/pcf-ue-bindings/");

    let del = delete(&format!("/nbsf-management/v1/pcf-ue-bindings/{id}")).await;
    assert_eq!(del.status, 204, "delete via real handler");
}

/// WSB-1 acceptance site 3 (MBS bindings, bsfd pcf-mbs-bindings): the
/// production body plus the endpoint-specific mandatory `mbsSessionId`
/// (pcfd's PDU-session builder legitimately has no MBS correlation id; the
/// PCF-address members under test come from the real builder) -> 201.
#[tokio::test]
async fn pcfd_production_binding_accepted_at_mbs_site() {
    init_peers();
    let mut body = production_body("imsi-001010000000703", "10.45.0.73");
    body["mbsSessionId"] = mbs_session_id("000703");

    let resp = post("/nbsf-management/v1/pcf-mbs-bindings", &body).await;
    assert_eq!(
        resp.status, 201,
        "real bsfd must 201-accept the MBS binding, got {} ({:?})",
        resp.status, resp.http.content
    );
    let id = binding_id_from_location(&resp, "/nbsf-management/v1/pcf-mbs-bindings/");

    let del = delete(&format!("/nbsf-management/v1/pcf-mbs-bindings/{id}")).await;
    assert_eq!(del.status, 204, "delete via real handler");
}

/// Negative twin (regression guard for the lenient-mock trap): the pre-fix
/// legacy field set (supi/dnn/snssai/ipv4Addr only) must STILL be
/// 400-rejected with MANDATORY_IE_MISSING at all three validation sites.
/// If bsfd is ever loosened instead of pcfd being fixed, this fails.
#[tokio::test]
async fn legacy_binding_still_rejected_400_at_all_three_sites() {
    init_peers();
    let body = legacy_body("imsi-001010000000704", "10.45.0.74");

    // Site 1: PDU-session bindings.
    let resp = post("/nbsf-management/v1/pcfBindings", &body).await;
    assert_eq!(resp.status, 400, "legacy body must stay rejected");
    let p = problem(&resp);
    assert_eq!(p["cause"], "MANDATORY_IE_MISSING");
    assert!(
        p["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("pcfFqdn|pcfIpEndPoints"),
        "detail must name the missing PCF address IEs: {p}"
    );

    // Site 2: UE bindings (supi present, PCF address absent).
    let resp = post("/nbsf-management/v1/pcf-ue-bindings", &body).await;
    assert_eq!(resp.status, 400);
    assert_eq!(problem(&resp)["cause"], "MANDATORY_IE_MISSING");

    // Site 3: MBS bindings (mbsSessionId present and VALID, PCF address absent).
    // The id must be a conformant object, or the mbsSessionId validation fires
    // first and this stops testing the PCF-address requirement it exists for.
    let mut mbs = body.clone();
    mbs["mbsSessionId"] = mbs_session_id("000704");
    let resp = post("/nbsf-management/v1/pcf-mbs-bindings", &mbs).await;
    assert_eq!(resp.status, 400);
    assert_eq!(problem(&resp)["cause"], "MANDATORY_IE_MISSING");
}

/// H2 conversion of the old `discover_and_send_udr_and_bsf_mock` BSF leg:
/// full wire round trip through pcfd's REAL register/deregister client
/// functions (NRF discovery -> POST -> Location parse -> DELETE) against a
/// REAL bsfd HTTP/2 server running bsfd's real handler. Only the
/// NRF-discovery bootstrap is mocked (H1 policy: mocks are allowed solely
/// for third-party endpoints the test does not target).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pcfd_client_registers_binding_with_real_bsfd_over_http() {
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    use std::time::Duration;

    init_peers();

    fn ephemeral_addr() -> std::net::SocketAddr {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe binds");
        let addr = probe.local_addr().expect("probe addr");
        drop(probe);
        addr
    }

    // Real bsfd SBI server.
    let bsf_addr = ephemeral_addr();
    let bsf_server = SbiServer::new(SbiServerConfig::new(bsf_addr));
    bsf_server
        .start(nextgcore_bsfd::bsf_sbi_request_handler)
        .await
        .expect("start real bsfd");

    // Mock NRF advertising ONLY the real BSF endpoint (discovery bootstrap).
    let bsf_port = bsf_addr.port();
    let nrf_addr = ephemeral_addr();
    let nrf_server = SbiServer::new(SbiServerConfig::new(nrf_addr));
    let nrf_handler = move |req: SbiRequest| async move {
        let path = req.header.uri.split('?').next().unwrap_or("");
        if path == "/nnrf-disc/v1/nf-instances" {
            let body = serde_json::json!({
                "nfInstances": [{
                    "nfInstanceId": "bsf-real",
                    "nfType": "BSF",
                    "ipv4Addresses": ["127.0.0.1"],
                    "nfServices": [{
                        "serviceName": "nbsf-management",
                        "scheme": "http",
                        "ipEndPoints": [{ "ipv4Address": "127.0.0.1", "port": bsf_port }]
                    }]
                }]
            });
            return SbiResponse::with_status(200)
                .with_json_body(&body)
                .unwrap_or_else(|_| SbiResponse::with_status(500));
        }
        SbiResponse::with_status(404)
    };
    nrf_server.start(nrf_handler).await.expect("start mock NRF");
    nextgcore_sbi::context::global_context()
        .set_nrf_uri(format!("http://127.0.0.1:{}", nrf_addr.port()))
        .await;

    let run = async {
        let body = production_body("imsi-001010000000777", "10.45.0.77");
        // Register through pcfd's real client fn -> real bsfd validation.
        let binding_id = pcf_register_bsf_binding(&body)
            .await
            .expect("bsf register ok")
            .expect("real bsfd must 201-accept the production binding");
        assert!(!binding_id.is_empty());

        // Deregister (DELETE /pcfBindings/{id}) -> 204 from the real handler.
        assert!(pcf_deregister_bsf_binding(&binding_id)
            .await
            .expect("bsf delete ok"));
    };
    tokio::time::timeout(Duration::from_secs(15), run)
        .await
        .expect("strict-peer wire round trip timed out");

    bsf_server.stop().await.ok();
    nrf_server.stop().await.ok();
}
