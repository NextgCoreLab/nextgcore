//! Wave-6 H1 proving test: the bsfd lib target exposes the REAL SBI request
//! handler to external crates, and the harness surfaces bsfd's real
//! validation (a deficient PcfBinding gets the spec 400, not a mock 2xx).
//!
//! Spec: TS 29.521 §5.3.2 — a PcfBinding must carry PCF address information
//! (pcfFqdn and/or pcfIpEndPoints); `specs/TS29521_Nbsf_Management.yaml`.

use nextgcore_sbi::message::SbiRequest;

/// KNOWN-BAD PcfBinding (no pcfFqdn/pcfIpEndPoints) through the lib-exposed
/// real handler -> 400 MANDATORY_IE_MISSING. This is the H1 falsifiable
/// check that the strict-peer harness exercises real validation in-process.
#[tokio::test]
async fn known_bad_pcf_binding_gets_real_400() {
    nextgcore_bsfd::test_support::init_context(16);

    let bad = serde_json::json!({
        "supi": "imsi-001010000000001",
        "dnn": "internet",
        "snssai": { "sst": 1 },
        "ipv4Addr": "10.45.0.1",
    });
    let req = SbiRequest::post("/nbsf-management/v1/pcfBindings")
        .with_json_body(&bad)
        .expect("serialize");
    let resp = nextgcore_bsfd::bsf_sbi_request_handler(req).await;

    assert_eq!(
        resp.status, 400,
        "real validation must reject, not mock-2xx"
    );
    let problem: serde_json::Value =
        serde_json::from_str(resp.http.content.as_deref().expect("problem body")).expect("json");
    assert_eq!(problem["cause"], "MANDATORY_IE_MISSING");
    assert!(problem["detail"]
        .as_str()
        .unwrap_or_default()
        .contains("pcfFqdn|pcfIpEndPoints"));
}
