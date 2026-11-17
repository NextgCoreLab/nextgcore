//! #1617 step a: every transport an NF uses toward its NRF dials TLS and
//! presents this NF's client certificate, so the NRF can bind NFRegister /
//! NFUpdate / NFDeregister to the certificate's `urn:uuid:` URI SAN
//! (TS 33.310 §6.1.3c.3, TS 33.501 §13.1.0).
//!
//! The NRF here is a real `SbiServer` serving the dev PKI's `nrf.crt` with
//! client-certificate verification; the certificates come from the real
//! `docker/rust/certs/generate-dev-certs.sh`. Each request records the URN of
//! the certificate the NRF verified, so every assertion is positive: the path
//! reached the NRF **as the AMF**.
//!
//! The process runs the `dev` SBI profile, which dials every other peer h2c: an
//! `https://` NRF URI alone is what makes these paths TLS.
//!
//! An integration test (own process) because it sets process-wide state: the
//! global SBI context's NRF URI, the SBI profile and the NRF client TLS.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nextgcore_sbi::client::SbiClient;
use nextgcore_sbi::context::{global_context, NfStatus, SbiContext};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::nrf_tls::{set_nrf_client_tls_override, NrfClientTls, NRF_CLIENT_TLS_TEST_LOCK};
use nextgcore_sbi::oauth::{JwksCache, OAuth2Client};
use nextgcore_sbi::security::{set_sbi_profile_override, SbiProfile};
use nextgcore_sbi::server::SbiServerConfig;
use nextgcore_sbi::test_support::sbi_server_on_free_port_with;
use nextgcore_sbi::types::{NfType, UriScheme};

const NRF_ID: &str = "6b1d7e3c-0000-4000-8000-0000000000f0";
const AMF_ID: &str = "6b1d7e3c-0000-4000-8000-000000000af0";

/// The dev PKI for an NRF and an AMF, issued by the shipped generator into a
/// directory removed on drop.
struct DevPki(PathBuf);

impl DevPki {
    fn generate() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let dir = tempfile::Builder::new()
            .prefix("nrf-client-tls-1617-")
            .tempdir()
            .expect("tempdir")
            .keep();
        let ids = dir.join("ids.txt");
        std::fs::write(
            &ids,
            format!("nrf NRF {NRF_ID} 172.23.0.10\namf AMF {AMF_ID} 172.23.0.5\n"),
        )
        .unwrap();
        let out = std::process::Command::new("bash")
            .arg(root.join("docker/rust/certs/generate-dev-certs.sh"))
            .arg("--out")
            .arg(&dir)
            .arg("--ids")
            .arg(&ids)
            .output()
            .expect("run generate-dev-certs.sh (needs bash and openssl)");
        assert!(
            out.status.success(),
            "generate-dev-certs.sh failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Self(dir)
    }

    fn file(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
    }

    /// The AMF's NRF client TLS, verifying the NRF as `server_name`.
    fn amf_tls(&self, server_name: Option<&str>) -> NrfClientTls {
        NrfClientTls {
            ca_cert: self.file("ca.crt"),
            client_cert: Some(self.file("amf.crt")),
            client_key: Some(self.file("amf.key")),
            server_name: server_name.map(str::to_string),
            error: None,
        }
    }
}

impl Drop for DevPki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `(method, path, verified client certificate URN)` of each request.
type Seen = Arc<Mutex<Vec<(String, String, Option<String>)>>>;

/// A stand-in NRF over mutual TLS with the dev PKI's `nrf.crt`.
async fn mtls_nrf(pki: &DevPki) -> (nextgcore_sbi::server::SbiServer, u16, Seen) {
    let seen: Seen = Arc::default();
    let log = seen.clone();
    let (key, cert, ca) = (pki.file("nrf.key"), pki.file("nrf.crt"), pki.file("ca.crt"));
    let (server, addr) = sbi_server_on_free_port_with(
        move |addr| {
            let mut cfg = SbiServerConfig::new(addr).with_tls(key, cert);
            cfg.verify_client = true;
            cfg.verify_client_cacert = Some(ca);
            cfg
        },
        move |req: SbiRequest| {
            let log = log.clone();
            async move {
                let method = req.header.method.to_string();
                let path = req.header.uri.clone();
                log.lock().unwrap().push((
                    method.clone(),
                    path.clone(),
                    req.peer_cert_nf_instance_id.clone(),
                ));
                if path.contains("access-token") || path.ends_with("/oauth2/token") {
                    SbiResponse::with_status(200).with_body(
                        r#"{"access_token":"t","token_type":"Bearer","expires_in":60}"#,
                        "application/json",
                    )
                } else if path.contains("jwks") || path.contains("retrieve-key") {
                    SbiResponse::with_status(200).with_body(r#"{"keys":[]}"#, "application/json")
                } else {
                    match method.as_str() {
                        "PUT" => SbiResponse::with_status(201)
                            .with_body(r#"{"nfInstanceId":"x"}"#, "application/json"),
                        "PATCH" | "DELETE" => SbiResponse::with_status(204),
                        _ => SbiResponse::with_status(200).with_body("{}", "application/json"),
                    }
                }
            }
        },
    )
    .await;
    (server, addr.port(), seen)
}

/// The URN the NRF verified on the last request to a path containing `needle`.
fn verified_as(seen: &Seen, method: &str, needle: &str) -> Option<String> {
    seen.lock()
        .unwrap()
        .iter()
        .rev()
        .find(|(m, p, _)| m == method && p.contains(needle))
        .and_then(|(_, _, id)| id.clone())
}

fn setup(pki: &DevPki) {
    set_sbi_profile_override(SbiProfile::Dev);
    set_nrf_client_tls_override(Some(pki.amf_tls(Some("nrf"))));
}

#[tokio::test]
async fn get_client_dials_only_the_nrf_with_this_nfs_certificate_1617() {
    let _g = NRF_CLIENT_TLS_TEST_LOCK.lock().await;
    let pki = DevPki::generate();
    setup(&pki);
    let (_nrf, port, seen) = mtls_nrf(&pki).await;

    let ctx = SbiContext::new_isolated();
    // A client cached before the NRF was configured is not reused for it.
    let early = ctx.get_client("127.0.0.1", port).await;
    assert_eq!(early.config().scheme, UriScheme::Http);
    ctx.set_nrf_uri(format!("https://127.0.0.1:{port}")).await;

    let client = ctx.get_client("127.0.0.1", port).await;
    assert_eq!(client.config().scheme, UriScheme::Https);
    let resp = client
        .get("/nnrf-disc/v1/nf-instances?target-nf-type=SMF")
        .await
        .expect("discovery over mTLS");
    assert_eq!(resp.status, 200);
    assert_eq!(
        verified_as(&seen, "GET", "nnrf-disc").as_deref(),
        Some(AMF_ID)
    );

    // Any other authority still follows the (dev) profile.
    let peer = ctx.get_client("127.0.0.1", port.wrapping_add(1)).await;
    assert_eq!(peer.config().scheme, UriScheme::Http);
    assert_eq!(peer.config().client_cert, None);
}

#[tokio::test]
async fn every_heartbeat_path_reaches_the_nrf_as_this_nf_1617() {
    let _g = NRF_CLIENT_TLS_TEST_LOCK.lock().await;
    let pki = DevPki::generate();
    setup(&pki);
    let (_nrf, port, seen) = mtls_nrf(&pki).await;
    global_context()
        .set_nrf_uri(format!("https://127.0.0.1:{port}"))
        .await;
    let path = format!("/nnrf-nfm/v1/nf-instances/{AMF_ID}");

    // NFRegister of the recorded profile (reregister_self).
    nextgcore_sbi::heartbeat::set_registered_profile(&serde_json::json!({
        "nfInstanceId": AMF_ID, "nfType": "AMF", "nfStatus": "REGISTERED"
    }));
    assert_eq!(
        nextgcore_sbi::heartbeat::reregister_self(AMF_ID).await,
        Ok(201)
    );
    assert_eq!(verified_as(&seen, "PUT", &path).as_deref(), Some(AMF_ID));

    // NFUpdate of nfStatus (patch_nf_status).
    nextgcore_sbi::heartbeat::patch_nf_status(AMF_ID, NfStatus::Registered, 10)
        .await
        .expect("nfStatus PATCH over mTLS");
    assert_eq!(verified_as(&seen, "PATCH", &path).as_deref(), Some(AMF_ID));

    // The heartbeat worker's PATCH.
    seen.lock().unwrap().clear();
    nextgcore_sbi::heartbeat::spawn_heartbeat_worker(AMF_ID.to_string(), 1);
    let beat = nextgcore_sbi::test_support::poll_until(
        Duration::from_secs(20),
        Duration::from_millis(20),
        || {
            let seen = seen.clone();
            let path = path.clone();
            async move { verified_as(&seen, "PATCH", &path) }
        },
    )
    .await;
    assert_eq!(beat.as_deref(), Some(AMF_ID));

    // NFDeregister (deregister_nf).
    nextgcore_sbi::heartbeat::deregister_nf(AMF_ID)
        .await
        .expect("NFDeregister over mTLS");
    assert_eq!(verified_as(&seen, "DELETE", &path).as_deref(), Some(AMF_ID));
    global_context().clear_nrf_uri().await;
}

#[tokio::test]
async fn for_nrf_uri_carries_the_nrf_tls_and_http_stays_cleartext_1617() {
    let _g = NRF_CLIENT_TLS_TEST_LOCK.lock().await;
    let pki = DevPki::generate();
    setup(&pki);
    let (_nrf, port, seen) = mtls_nrf(&pki).await;

    let client = SbiClient::for_nrf_uri(&format!("https://127.0.0.1:{port}")).unwrap();
    let resp = client
        .put_json(
            &format!("/nnrf-nfm/v1/nf-instances/{AMF_ID}"),
            &serde_json::json!({}),
        )
        .await
        .expect("NFRegister over mTLS");
    assert_eq!(resp.status, 201);
    assert_eq!(verified_as(&seen, "PUT", AMF_ID).as_deref(), Some(AMF_ID));

    let plain = SbiClient::for_nrf_uri("http://nrf:7777").unwrap();
    assert_eq!(plain.config().scheme, UriScheme::Http);
    assert_eq!(plain.config().client_cert, None);
    assert_eq!(
        SbiClient::for_nrf_uri("nrf:7777").unwrap().config().scheme,
        UriScheme::Http
    );
    assert!(SbiClient::for_nrf_uri("ftp://nrf:7777").is_none());
}

#[tokio::test]
async fn the_token_and_key_transports_present_this_nfs_certificate_1617() {
    let _g = NRF_CLIENT_TLS_TEST_LOCK.lock().await;
    let pki = DevPki::generate();
    setup(&pki);
    let (_nrf, port, seen) = mtls_nrf(&pki).await;
    let nrf = format!("https://127.0.0.1:{port}");

    let oauth = OAuth2Client::new(&nrf, AMF_ID, NfType::Amf);
    let token = oauth
        .get_token(NfType::Smf, "nsmf-pdusession")
        .await
        .expect("access token over mTLS");
    assert_eq!(token, "t");
    assert_eq!(verified_as(&seen, "POST", "").as_deref(), Some(AMF_ID));

    JwksCache::for_nrf(&nrf)
        .refresh()
        .await
        .expect("JWKS for_nrf over mTLS");
    // The listener-side cache is built from the configured JWKS URI.
    let uri = JwksCache::for_nrf(&nrf).jwks_uri().to_string();
    JwksCache::new(uri.clone())
        .refresh()
        .await
        .expect("JWKS from its URI over mTLS");
    let path = uri.split_once(&format!("{port}")).unwrap().1.to_string();
    let keyed: Vec<_> = seen
        .lock()
        .unwrap()
        .iter()
        .filter(|(m, p, _)| m == "GET" && p.contains(&path))
        .map(|(_, _, id)| id.clone())
        .collect();
    assert_eq!(keyed, vec![Some(AMF_ID.to_string()); 2]);
}

#[tokio::test]
async fn the_nrf_is_verified_by_name_and_loopback_names_no_certificate_1617() {
    let _g = NRF_CLIENT_TLS_TEST_LOCK.lock().await;
    let pki = DevPki::generate();
    set_sbi_profile_override(SbiProfile::Dev);
    let (_nrf, port, seen) = mtls_nrf(&pki).await;
    let nrf = format!("https://127.0.0.1:{port}");
    let path = format!("/nnrf-nfm/v1/nf-instances/{AMF_ID}");

    // Without the server name, 127.0.0.1 is not a name nrf.crt carries.
    set_nrf_client_tls_override(Some(pki.amf_tls(None)));
    let err = SbiClient::for_nrf_uri(&nrf)
        .unwrap()
        .put_json(&path, &serde_json::json!({}))
        .await
        .expect_err("nrf.crt does not name 127.0.0.1");
    assert!(err.to_string().contains("TLS"), "{err}");
    let err = JwksCache::for_nrf(&nrf)
        .refresh()
        .await
        .expect_err("same for JWKS");
    assert!(err.to_string().contains("TLS"), "{err}");

    // Verified as another NF's name, the NRF's certificate does not pass.
    set_nrf_client_tls_override(Some(pki.amf_tls(Some("amf"))));
    assert!(SbiClient::for_nrf_uri(&nrf)
        .unwrap()
        .put_json(&path, &serde_json::json!({}))
        .await
        .is_err());

    // Half a client pair fails every NRF connection rather than dialling
    // without the certificate.
    let mut half = pki.amf_tls(Some("nrf"));
    half.client_key = None;
    half.error = Some("half a pair".into());
    set_nrf_client_tls_override(Some(half));
    let err = SbiClient::for_nrf_uri(&nrf)
        .unwrap()
        .put_json(&path, &serde_json::json!({}))
        .await
        .expect_err("half a pair");
    assert!(err.to_string().contains("half a pair"), "{err}");
    assert!(
        seen.lock().unwrap().is_empty(),
        "no request reached the NRF"
    );
}
