//! HTTP-level two-SEPP N32 tests (TS 29.573).
//!
//! The test process acts as SEPP-A (home) using the library paths and an
//! in-process N32 listener (to receive n32f-error reports). Peer SEPPs
//! (B1: PRINS-capable, B2: TLS-only) run as real `nextgcore-seppd` child
//! processes on ephemeral ports, so the full handshake + forward round
//! trips cross real HTTP/2 connections between separate processes.
//!
//! Scenarios:
//! 1. N32-c handshake with PRINS selection + exchange-params key agreement
//! 2. N32-f PRINS-protected forward, reconstructed by the peer
//! 3. Tampered N32-f message: peer rejects (400) AND delivers an
//!    n32f-error report back to SEPP-A (produced and consumed)
//! 4. TLS preferred over PRINS/NONE when both sides support it + TLS-mode
//!    forward round trip
//! 5. Capability mismatch -> negotiation failure (HTTP 400,
//!    NEGOTIATION_NOT_ALLOWED)

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use nextgcore_seppd::context::{sepp_self, SecurityCapability};
use nextgcore_seppd::jose::{b64url_decode, b64url_encode};
use nextgcore_seppd::n32_server::{
    forward_via_n32f, initiate_n32c_handshake, start_n32_listener, take_received_n32f_errors,
};
use nextgcore_seppd::prins::{protect_message, N32fErrorType};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);
const PHASE_TIMEOUT: Duration = Duration::from_secs(30);

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

/// A peer SEPP running as a real child process; killed on drop.
struct ChildSepp {
    child: Child,
    n32_port: u16,
}

impl ChildSepp {
    fn spawn(sender: &str, prins: bool) -> Self {
        Self::spawn_inner(sender, prins, None)
    }

    /// Spawn a peer SEPP that itself initiates the N32-c handshake
    /// towards `peer` ("fqdn=apiroot") at startup.
    fn spawn_with_peer(sender: &str, prins: bool, peer: &str) -> Self {
        Self::spawn_inner(sender, prins, Some(peer))
    }

    fn spawn_inner(sender: &str, prins: bool, peer: Option<&str>) -> Self {
        let n32_port = free_port();
        let sbi_port = free_port();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_nextgcore-seppd"));
        cmd.args([
            "-c",
            "/nonexistent/sepp.yaml",
            "-e",
            "warn",
            "--sbi-addr",
            "127.0.0.1",
            "--sbi-port",
            &sbi_port.to_string(),
            "--n32-addr",
            "127.0.0.1",
            "--n32-port",
            &n32_port.to_string(),
            "--sender",
            sender,
            "--serving-plmn",
            "999:70",
        ]);
        if prins {
            cmd.arg("--prins");
        }
        // sepp-10: these peer SEPPs run over plaintext HTTP (no N32-c TLS), so
        // permit the deterministic no-TLS N32-f key-derivation fallback. In
        // production this is off and exchange-params requires the TLS exporter.
        cmd.arg("--allow-insecure-no-tls");
        if let Some(peer) = peer {
            cmd.args(["--peer-sepp", peer]);
        }
        let child = cmd
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn nextgcore-seppd");
        Self { child, n32_port }
    }

    fn api_root(&self) -> String {
        format!("http://127.0.0.1:{}", self.n32_port)
    }

    async fn wait_ready(&self) {
        let deadline = tokio::time::Instant::now() + STARTUP_TIMEOUT;
        loop {
            if tokio::net::TcpStream::connect(("127.0.0.1", self.n32_port))
                .await
                .is_ok()
            {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "peer SEPP did not open its N32 port in time"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

impl Drop for ChildSepp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Configure the in-process SEPP-A identity and capabilities
fn configure_local_sepp(tls: bool, prins: bool) {
    // sepp-10: the in-process SEPP-A also runs over plaintext HTTP here, so
    // permit the no-TLS N32-f key-derivation fallback (off by default).
    nextgcore_seppd::n32c_handler::set_allow_insecure_no_tls(true);
    let ctx = sepp_self();
    let mut context = ctx.write().expect("context lock");
    if !context.is_initialized() {
        context.init(16, 100);
    }
    context.set_sender("sepp-a.example.com");
    context.security_capability.tls = tls;
    context.security_capability.prins = prins;
}

/// Raw POST helper (for crafting tampered messages)
async fn raw_post(api_root: &str, path: &str, body: String) -> (u16, String) {
    let rest = api_root.strip_prefix("http://").expect("http api root");
    let (host, port) = rest.split_once(':').expect("host:port");
    let config = ogs_sbi::client::SbiClientConfig::new(host, port.parse().unwrap())
        .with_connect_timeout(Duration::from_secs(3))
        .with_request_timeout(Duration::from_secs(5));
    let client = ogs_sbi::client::SbiClient::new(config);
    let mut request = ogs_sbi::message::SbiRequest::post(path);
    request.http.set_content(body);
    request.http.set_header("Content-Type", "application/json");
    let response = client.send_request(request).await.expect("raw POST");
    (response.status, response.http.content.unwrap_or_default())
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReconstructedJson {
    method: String,
    url: String,
    body: Option<String>,
    message_id: Option<String>,
}

#[tokio::test(flavor = "multi_thread")]
async fn two_sepp_n32_handshake_and_forwarding() {
    let _ = env_logger::builder().is_test(true).try_init();

    tokio::time::timeout(PHASE_TIMEOUT * 3, async {
        // ------------------------------------------------------------------
        // SEPP-A: in-process listener (receives n32f-error reports)
        // ------------------------------------------------------------------
        configure_local_sepp(false, true); // PRINS-only for phase 1
        let a_port = free_port();
        let a_server = start_n32_listener("127.0.0.1", a_port, None)
            .await
            .expect("start SEPP-A N32 listener");
        let a_root = format!("http://127.0.0.1:{a_port}");

        // ------------------------------------------------------------------
        // Phase 1: PRINS handshake against B1 (capability + exchange-params)
        // ------------------------------------------------------------------
        let b1 = ChildSepp::spawn("sepp-b1.example.com", true);
        b1.wait_ready().await;

        let outcome =
            initiate_n32c_handshake("sepp-b1.example.com", &b1.api_root(), Some(&a_root), None)
                .await
                .expect("PRINS handshake should succeed");
        assert_eq!(outcome.security, SecurityCapability::Prins);

        // Session key + context IDs must be installed
        let node = {
            let ctx = sepp_self();
            let context = ctx.read().unwrap();
            context.node_find(outcome.node_id).unwrap()
        };
        let security = node.n32f_security.clone().expect("N32-f keys established");
        assert!(!security.local_context_id.is_empty());
        assert!(!security.peer_context_id.is_empty());
        assert_eq!(security.jwe_cipher_suite, "A256GCM");
        // modificationsBlock is signed with the asymmetric ES256 key
        // (TS 33.501 §13.2.4.6), not the symmetric session key.
        assert_eq!(security.jws_cipher_suite, "ES256");
        // Peer learned our serving PLMN list (sent in the handshake)
        // and we learned the peer's (configured as 999:70 on the child)
        assert!(node.has_plmn_id(999, 70), "peer serving PLMNs not learned");

        // ------------------------------------------------------------------
        // Phase 2: PRINS-protected N32-f forward round trip
        // ------------------------------------------------------------------
        let body = serde_json::json!({
            "supi": "imsi-999700000000001",
            "nssai": {"sst": 1}
        });
        let headers = vec![("content-type".to_string(), "application/json".to_string())];
        // Include a query string so the spec RequestLine (sepp-03,
        // scheme/authority/path/queryFragment) round-trips over real HTTP.
        let forward_url = "/nudm-sdm/v1/supi?supported-features=1";
        let (status, rsp_body) = forward_via_n32f(
            outcome.node_id,
            "POST",
            forward_url,
            &headers,
            Some(serde_json::to_vec(&body).unwrap().as_slice()),
            None,
        )
        .await
        .expect("N32-f forward");
        assert_eq!(status, 200, "peer rejected protected message: {rsp_body}");

        let rec: ReconstructedJson = serde_json::from_str(&rsp_body).unwrap();
        assert_eq!(rec.method, "POST");
        // The path and query must be reconstructed identically by the peer.
        assert_eq!(rec.url, forward_url);
        assert!(rec.message_id.is_some());
        let rec_body = b64url_decode(&rec.body.expect("body")).unwrap();
        let rec_json: serde_json::Value = serde_json::from_slice(&rec_body).unwrap();
        assert_eq!(rec_json["supi"], "imsi-999700000000001");
        assert_eq!(rec_json["nssai"]["sst"], 1);

        // ------------------------------------------------------------------
        // Phase 3: tampered message -> 400 + n32f-error report back to A
        // ------------------------------------------------------------------
        let _ = take_received_n32f_errors(); // drain
        let prins_ctx = nextgcore_seppd::sbi_path::build_prins_context(outcome.node_id).unwrap();
        let mut msg = protect_message(
            &prins_ctx,
            "POST",
            "/nudm-sdm/v1/supi",
            &headers,
            Some(serde_json::to_vec(&body).unwrap().as_slice()),
        )
        .unwrap();
        let mut ct = b64url_decode(&msg.reformatted_data.ciphertext).unwrap();
        ct[0] ^= 0xff;
        msg.reformatted_data.ciphertext = b64url_encode(&ct);

        let (status, err_body) = raw_post(
            &b1.api_root(),
            "/n32f-forward/v1/n32f-process",
            serde_json::to_string(&msg).unwrap(),
        )
        .await;
        assert_eq!(status, 400, "tampered message must be rejected");
        assert!(
            err_body.contains("INTEGRITY_CHECK_FAILED"),
            "expected integrity cause, got: {err_body}"
        );

        // B1 must deliver an n32f-error report to SEPP-A (produced there,
        // consumed here by our listener)
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let received = loop {
            let errors = take_received_n32f_errors();
            if !errors.is_empty() {
                break errors;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "n32f-error report never arrived"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert_eq!(
            received[0].n32f_error_type,
            N32fErrorType::IntegrityCheckFailed
        );
        assert!(!received[0].n32f_message_id.is_empty());

        // ------------------------------------------------------------------
        // Phase 4: TLS preferred when both sides support it + TLS forward
        // ------------------------------------------------------------------
        configure_local_sepp(true, true); // we offer TLS + PRINS
        let b2 = ChildSepp::spawn("sepp-b2.example.com", false); // TLS only
        b2.wait_ready().await;

        let outcome2 =
            initiate_n32c_handshake("sepp-b2.example.com", &b2.api_root(), Some(&a_root), None)
                .await
                .expect("TLS handshake should succeed");
        assert_eq!(
            outcome2.security,
            SecurityCapability::Tls,
            "TLS must be preferred"
        );

        let (status, rsp_body) = forward_via_n32f(
            outcome2.node_id,
            "GET",
            "/nnrf-disc/v1/nf-instances",
            &headers,
            None,
            None,
        )
        .await
        .expect("TLS-mode N32-f forward");
        assert_eq!(status, 200);
        let rec: ReconstructedJson = serde_json::from_str(&rsp_body).unwrap();
        assert_eq!(rec.method, "GET");
        assert_eq!(rec.url, "/nnrf-disc/v1/nf-instances");

        // ------------------------------------------------------------------
        // Phase 5: capability mismatch -> negotiation failure
        // ------------------------------------------------------------------
        configure_local_sepp(false, true); // we offer PRINS only; B2 has no PRINS
        let err = initiate_n32c_handshake(
            "sepp-b2-fail.example.com",
            &b2.api_root(),
            Some(&a_root),
            None,
        )
        .await
        .expect_err("mismatched capabilities must fail the handshake");
        assert!(
            err.contains("400"),
            "expected HTTP 400 negotiation failure, got: {err}"
        );

        // ------------------------------------------------------------------
        // Phase 6: reverse direction - peer SEPP initiates the handshake
        // toward us (exercises our responder path over real HTTP)
        // ------------------------------------------------------------------
        // Local caps are PRINS-only (from phase 5); B3 offers TLS+PRINS,
        // so our responder must select PRINS and complete exchange-params.
        let b3 = ChildSepp::spawn_with_peer(
            "sepp-b3.example.com",
            true,
            &format!("sepp-a.example.com={a_root}"),
        );
        b3.wait_ready().await;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        let node_b3 = loop {
            let node = {
                let ctx = sepp_self();
                let context = ctx.read().unwrap();
                context.node_find_by_receiver("sepp-b3.example.com")
            };
            if let Some(node) = node {
                if node.n32f_security.is_some() {
                    break node;
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "peer-initiated handshake never established"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert_eq!(
            node_b3.negotiated_security_scheme,
            SecurityCapability::Prins
        );
        let sec_b3 = node_b3.n32f_security.unwrap();
        assert_eq!(sec_b3.jwe_cipher_suite, "A256GCM");
        assert_eq!(sec_b3.jws_cipher_suite, "ES256");

        let _ = a_server.stop().await;
        drop(b1);
        drop(b2);
        drop(b3);
    })
    .await
    .expect("two-SEPP N32 test timed out");
}
