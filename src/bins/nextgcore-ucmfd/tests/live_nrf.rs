//! #585 item 5: the real `nextgcore-ucmfd` binary against the real `nextgcore-nrfd`
//! binary over HTTP/2 on loopback.
//!
//! 1. ucmfd registers with nrfd (TS 29.510 NFRegister). This is checked from the
//!    NRF's side: NFDiscover for `target-nf-type=UCMF` returns its profile.
//! 2. The UCMF is then driven at the address the NRF advertised: Assign a TS 38.331
//!    capability, then Resolve it in EPS format. This proves the transcoding (#585
//!    item 1) over the wire.
//!
//! The nrfd binary is a sibling of this crate's binary in the target directory.
//! `cargo test --workspace` (CI) always builds it. A `cargo test -p
//! nextgcore-ucmfd` that never built nrfd skips with a message saying so, rather
//! than failing on something unrelated to the UCMF.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use nextgcore_sbi::client::{SbiClient, SbiClientConfig};
use nextgcore_sbi::message::SbiRequest;
use nextgcore_sbi::test_support::NfSpawn;
use serde_json::Value;

/// The env every child gets.
///
/// Plain-HTTP SBI on loopback: the `dev` profile (issue #63). The default
/// `production` profile dials peers over mTLS with this NF's client certificate,
/// which a test host does not have.
fn child_env(cmd: &mut std::process::Command) {
    cmd.env("NEXTGCORE_SBI_PROFILE", "dev")
        .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1");
}

fn nrfd_bin() -> Option<PathBuf> {
    let ucmfd = PathBuf::from(env!("CARGO_BIN_EXE_nextgcore-ucmfd"));
    let nrfd = ucmfd.with_file_name("nextgcore-nrfd");
    nrfd.exists().then_some(nrfd)
}

/// The UCMF profiles the NRF returns for an AMF's discovery, once there is one.
async fn discover_ucmf(nrf: &SbiClient, deadline: Instant) -> Vec<Value> {
    loop {
        let uri = "/nnrf-disc/v1/nf-instances?target-nf-type=UCMF&requester-nf-type=AMF";
        if let Ok(r) = nrf.send_request(SbiRequest::get(uri)).await {
            if r.status == 200 {
                let body: Value = r
                    .http
                    .content
                    .as_deref()
                    .and_then(|c| serde_json::from_str(c).ok())
                    .unwrap_or(Value::Null);
                let found = body["nfInstances"].as_array().cloned().unwrap_or_default();
                if !found.is_empty() {
                    return found;
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "the UCMF never appeared in the NRF's discovery"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
async fn ucmfd_registers_with_a_live_nrfd_and_serves_a_transcoded_resolve() {
    let Some(nrfd) = nrfd_bin() else {
        eprintln!(
            "SKIPPED: nextgcore-nrfd is not built next to nextgcore-ucmfd \
             (`cargo test --workspace` builds it; CI always does)"
        );
        return;
    };
    let ucmfd = PathBuf::from(env!("CARGO_BIN_EXE_nextgcore-ucmfd"));
    // #1521: both children through the shared `NfSpawn`, which waits for each
    // SBI listener and respawns on a fresh port if a child loses its probed one
    // to another process (the #1497 race). nrfd is up before the UCMF starts, so
    // the UCMF's first registration attempt has an NRF to reach.
    let nrfd = NfSpawn::new(&nrfd, "ucmf-live-nrfd")
        .ready_when_logged("server listening on")
        .spawn_async(|cmd, port, _| {
            child_env(cmd);
            cmd.args(["-c", "/nonexistent/nrf.yaml", "--sbi-addr", "127.0.0.1"])
                .args(["--sbi-port", &port.to_string()]);
        })
        .await;
    let nrf_uri = format!("http://127.0.0.1:{}", nrfd.port());
    let nrf = SbiClient::new(SbiClientConfig::new("127.0.0.1", nrfd.port()));

    let ucmf_proc = NfSpawn::new(&ucmfd, "ucmf-live-ucmfd")
        .ready_when_logged("SBI server listening on")
        .spawn_async(|cmd, port, _| {
            child_env(cmd);
            cmd.args(["-c", "/nonexistent/ucmf.yaml", "--sbi-addr", "127.0.0.1"])
                .args(["--sbi-port", &port.to_string()])
                .args(["--nrf-uri", &nrf_uri, "--mode", "B"]);
        })
        .await;
    let ucmf_port = ucmf_proc.port();

    let profiles = discover_ucmf(&nrf, Instant::now() + Duration::from_secs(20)).await;
    let profile = &profiles[0];
    assert_eq!(profile["nfType"], "UCMF");
    let services = profile["nfServices"].to_string();
    assert!(
        // TS 29.510 ServiceName values (the URI api name is `nucmf-uecm`).
        services.contains("\"nucmf-uecapabilitymanagement\"")
            && services.contains("\"nucmf-provisioning\""),
        "both UCMF services are registered: {services}"
    );
    // Drive the UCMF where the NRF says it is.
    let port = profile["nfServices"]
        .as_array()
        .and_then(|s| s.first())
        .and_then(|s| s["ipEndPoints"][0]["port"].as_u64())
        .unwrap_or(u64::from(ucmf_port)) as u16;
    assert_eq!(port, ucmf_port, "the NRF advertises the UCMF's real port");
    let ucmf = SbiClient::new(SbiClientConfig::new("127.0.0.1", port));

    // Assign: TS 29.673 multipart, one JSON part and the NGAP capability part.
    let cap = include_bytes!("data/cap_5gs.bin");
    let mut assign = SbiRequest::post("/nucmf-uecm/v1/dic-entries")
        .with_json_body(&serde_json::json!({
            "typeAllocationCode": "35123456",
            "ueRadioCapability5GS": {"contentId": "nr"}
        }))
        .unwrap();
    assign
        .http
        .parts
        .push(nextgcore_sbi::message::SbiPart::with_content(
            "nr",
            "application/vnd.3gpp.ngap",
            bytes::Bytes::from_static(cap),
        ));
    let r = ucmf.send_request(assign).await.expect("Assign over HTTP/2");
    assert_eq!(r.status, 201);
    let body: Value = serde_json::from_str(r.http.content.as_deref().unwrap()).unwrap();
    let id = body["plmnAssiUeRadioCapId"].as_str().unwrap().to_string();

    // Resolve in the format the AMF never sent.
    let mut resolve = SbiRequest::get("/nucmf-uecm/v1/dic-entries");
    resolve.http.params.insert(
        "ue-radio-capa-id".into(),
        serde_json::json!({"plmnAssiUeRadioCapId": id}).to_string(),
    );
    resolve
        .http
        .params
        .insert("rac-format".into(), "EPS".into());
    let r = ucmf
        .send_request(resolve)
        .await
        .expect("Resolve over HTTP/2");
    assert_eq!(r.status, 200, "{:?}", r.http.content);
    assert!(
        r.http.parts.iter().any(
            |p| p.content_type.as_deref() == Some("application/vnd.3gpp.s1ap")
                && !p.data.is_empty()
        ),
        "the EPS-format capability comes back as an S1AP binary part"
    );
}
