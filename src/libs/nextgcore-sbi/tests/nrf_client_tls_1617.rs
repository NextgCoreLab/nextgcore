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
        Self::generate_with(&[])
    }

    /// As [`DevPki::generate`], passing `extra` to the generator (`--loopback`).
    fn generate_with(extra: &[&str]) -> Self {
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
            .args(extra)
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
    // The listener-side cache is built from the configured JWKS URI; it is the
    // NRF's because it names the NRF URI this NF configured (#1690 review m2).
    let uri = JwksCache::for_nrf(&nrf).jwks_uri().to_string();
    global_context().set_nrf_uri(nrf.clone()).await;
    let fetched = JwksCache::new(uri.clone()).refresh().await;
    global_context().clear_nrf_uri().await;
    fetched.expect("JWKS from its URI over mTLS");
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

/// A server over TLS with `cert` (`<name>.crt` / `.key`) that answers every
/// request with `respond`, recording the verified client URN.
async fn tls_server(
    pki: &DevPki,
    name: &str,
    respond: impl Fn(&SbiRequest) -> SbiResponse + Send + Sync + 'static,
) -> (nextgcore_sbi::server::SbiServer, u16, Seen) {
    let seen: Seen = Arc::default();
    let log = seen.clone();
    let respond = Arc::new(respond);
    let (key, cert) = (
        pki.file(&format!("{name}.key")),
        pki.file(&format!("{name}.crt")),
    );
    let (server, addr) = sbi_server_on_free_port_with(
        move |addr| SbiServerConfig::new(addr).with_tls(key, cert),
        move |req: SbiRequest| {
            let log = log.clone();
            let respond = respond.clone();
            async move {
                log.lock().unwrap().push((
                    req.header.method.to_string(),
                    req.header.uri.clone(),
                    req.peer_cert_nf_instance_id.clone(),
                ));
                respond(&req)
            }
        },
    )
    .await;
    (server, addr.port(), seen)
}

/// #1690 review m1: the NRF server name stands in for the configured host only.
/// A redirect from the NRF (`127.0.0.1`, verified as `nrf`) to another host is
/// verified as that host: here `localhost`, served with `amf.crt`, which names
/// `localhost` (the generator's `--loopback`) but not `nrf`. Applying the NRF
/// name to the redirect target fails its handshake.
#[tokio::test]
async fn a_redirect_away_from_the_nrf_is_verified_as_its_own_host_1617() {
    let _g = NRF_CLIENT_TLS_TEST_LOCK.lock().await;
    let pki = DevPki::generate_with(&["--loopback"]);
    setup(&pki);
    let (_other, other_port, other_seen) = tls_server(&pki, "amf", |_| {
        SbiResponse::with_status(200).with_body("{}", "application/json")
    })
    .await;
    let location = format!("https://localhost:{other_port}/nnrf-disc/v1/nf-instances");
    let (_nrf, port, nrf_seen) = tls_server(&pki, "nrf", move |_| {
        SbiResponse::with_status(307).with_header("location", location.clone())
    })
    .await;

    let client = SbiClient::for_nrf_uri(&format!("https://127.0.0.1:{port}")).unwrap();
    assert_eq!(client.config().tls_server_name.as_deref(), Some("nrf"));
    let resp = client
        .get("/nnrf-disc/v1/nf-instances")
        .await
        .expect("the redirect target verifies as localhost");
    assert_eq!(resp.status, 200);
    assert_eq!(nrf_seen.lock().unwrap().len(), 1, "the NRF answered 307");
    assert_eq!(
        other_seen.lock().unwrap().len(),
        1,
        "the redirect reached the other host"
    );
}

/// #1690 review m2: the token / JWKS transport applies the NRF server name only
/// to the NRF's own authority. A JWKS URI at another host (`localhost`, served
/// with `amf.crt`) is verified as itself; one at the NRF authority is verified
/// as `nrf`.
#[tokio::test]
async fn a_jwks_uri_off_the_nrf_is_verified_as_its_own_host_1617() {
    let _g = NRF_CLIENT_TLS_TEST_LOCK.lock().await;
    let pki = DevPki::generate_with(&["--loopback"]);
    setup(&pki);
    let keys = |_: &SbiRequest| {
        SbiResponse::with_status(200).with_body(r#"{"keys":[]}"#, "application/json")
    };
    let (_other, other_port, other_seen) = tls_server(&pki, "amf", keys).await;
    let (_nrf, nrf_port, nrf_seen) = tls_server(&pki, "nrf", keys).await;
    global_context()
        .set_nrf_uri(format!("https://127.0.0.1:{nrf_port}"))
        .await;

    let off_nrf = format!("https://localhost:{other_port}/nnrf-oauth2/v1/jwks");
    let explicit = JwksCache::new(off_nrf.clone()).refresh().await;
    let free = nextgcore_sbi::oauth::fetch_jwks(&off_nrf).await;
    // The NRF's own key endpoint, by an explicit URI: matched to the context's
    // NRF URI, so verified as `nrf`.
    let at_nrf = JwksCache::new(format!("https://127.0.0.1:{nrf_port}/nnrf-oauth2/v1/jwks"))
        .refresh()
        .await;
    global_context().clear_nrf_uri().await;

    explicit.expect("an explicit JWKS URI off the NRF verifies as its host");
    free.expect("fetch_jwks off the NRF verifies as its host");
    at_nrf.expect("the NRF's JWKS URI verifies as nrf");
    assert_eq!(other_seen.lock().unwrap().len(), 2);
    assert_eq!(nrf_seen.lock().unwrap().len(), 1);
}

/// #1690 review m5: an unusable NRF client TLS configuration fails before any
/// TCP connection. Dialled at a port that refuses connections, the error is the
/// configuration's (a TLS error), not a connection error.
#[tokio::test]
async fn an_unusable_nrf_tls_configuration_fails_before_dialling_1617() {
    let _g = NRF_CLIENT_TLS_TEST_LOCK.lock().await;
    let pki = DevPki::generate();
    set_sbi_profile_override(SbiProfile::Dev);
    let mut half = pki.amf_tls(Some("nrf"));
    half.client_key = None;
    half.error = Some("half a pair 1617".into());
    set_nrf_client_tls_override(Some(half));
    let down = nextgcore_sbi::test_support::down_port();
    let nrf = format!("https://127.0.0.1:{}", down.port());

    let err = SbiClient::for_nrf_uri(&nrf)
        .unwrap()
        .get("/nnrf-disc/v1/nf-instances")
        .await
        .expect_err("half a pair");
    assert!(
        matches!(&err, nextgcore_sbi::error::SbiError::TlsError(m) if m.contains("half a pair 1617")),
        "the client reports the configuration, not the refused connect: {err:?}"
    );
    let err = OAuth2Client::new(&nrf, AMF_ID, NfType::Amf)
        .get_token(NfType::Smf, "nsmf-pdusession")
        .await
        .expect_err("half a pair");
    assert!(
        matches!(&err, nextgcore_sbi::error::SbiError::TlsError(m) if m.contains("half a pair 1617")),
        "the token transport reports the configuration: {err:?}"
    );
    let err = JwksCache::for_nrf(&nrf)
        .refresh()
        .await
        .expect_err("half a pair");
    assert!(
        matches!(&err, nextgcore_sbi::error::SbiError::TlsError(m) if m.contains("half a pair 1617")),
        "the JWKS transport reports the configuration: {err:?}"
    );
}

/// #1617 step b: a listener with OPTIONAL client authentication (the NRF's)
/// admits a client that presents no certificate, binds the identity of one that
/// presents a valid certificate, and refuses the handshake of one whose
/// certificate does not chain to its CA. With client authentication required,
/// a client without a certificate is refused.
#[tokio::test]
async fn optional_client_auth_admits_no_certificate_but_verifies_a_presented_one_1617() {
    let _g = NRF_CLIENT_TLS_TEST_LOCK.lock().await;
    let pki = DevPki::generate();
    let foreign = DevPki::generate();
    set_sbi_profile_override(SbiProfile::Dev);

    let start = |optional: bool| {
        let seen: Seen = Arc::default();
        let log = seen.clone();
        let (key, cert, ca) = (pki.file("nrf.key"), pki.file("nrf.crt"), pki.file("ca.crt"));
        async move {
            let (server, addr) = sbi_server_on_free_port_with(
                move |addr| {
                    let mut cfg = SbiServerConfig::new(addr).with_tls(key, cert);
                    cfg.verify_client = true;
                    cfg.verify_client_cacert = Some(ca);
                    cfg.verify_client_optional = optional;
                    cfg
                },
                move |req: SbiRequest| {
                    let log = log.clone();
                    async move {
                        log.lock().unwrap().push((
                            req.header.method.to_string(),
                            req.header.uri.clone(),
                            req.peer_cert_nf_instance_id.clone(),
                        ));
                        SbiResponse::with_status(200).with_body("{}", "application/json")
                    }
                },
            )
            .await;
            (server, addr.port(), seen)
        }
    };
    let get = |tls: NrfClientTls, port: u16| async move {
        set_nrf_client_tls_override(Some(tls));
        SbiClient::for_nrf_uri(&format!("https://127.0.0.1:{port}"))
            .unwrap()
            .get("/nnrf-disc/v1/nf-instances")
            .await
    };
    let anonymous = |pki: &DevPki| {
        let mut t = pki.amf_tls(Some("nrf"));
        t.client_cert = None;
        t.client_key = None;
        t
    };

    let (_optional, port, seen) = start(true).await;
    let resp = get(anonymous(&pki), port)
        .await
        .expect("no certificate: the handshake completes");
    assert_eq!(resp.status, 200);
    assert_eq!(seen.lock().unwrap().last().unwrap().2, None, "no identity");
    let resp = get(pki.amf_tls(Some("nrf")), port)
        .await
        .expect("a valid certificate");
    assert_eq!(resp.status, 200);
    assert_eq!(
        seen.lock().unwrap().last().unwrap().2.as_deref(),
        Some(AMF_ID)
    );
    // The foreign AMF certificate, presented with a CA that trusts our NRF:
    // the NRF must refuse it, not treat it as "no certificate".
    let mut forged = pki.amf_tls(Some("nrf"));
    forged.client_cert = Some(foreign.file("amf.crt"));
    forged.client_key = Some(foreign.file("amf.key"));
    let err = get(forged, port)
        .await
        .expect_err("a certificate from another CA is refused");
    assert!(
        err.to_string().contains("TLS") || err.to_string().contains("onnection"),
        "{err}"
    );
    assert_eq!(
        seen.lock().unwrap().len(),
        2,
        "the forged client never reached the handler"
    );

    let (_required, port, seen) = start(false).await;
    assert!(
        get(anonymous(&pki), port).await.is_err(),
        "client authentication required: no certificate, no handshake"
    );
    assert!(seen.lock().unwrap().is_empty());
}

/// #1690 review m4: the generator writes every private key 0600 and every
/// certificate (the CA's included) 0644, so a container user other than the
/// owner can read the public material through a bind mount but no key.
#[cfg(unix)]
#[test]
fn the_generator_writes_keys_0600_and_certificates_0644_1617() {
    use std::os::unix::fs::PermissionsExt;
    let pki = DevPki::generate();
    let mut seen = (0, 0);
    for entry in std::fs::read_dir(&pki.0).unwrap() {
        let path = entry.unwrap().path();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        match path.extension().and_then(|e| e.to_str()) {
            Some("key") => {
                assert_eq!(mode, 0o600, "{}", path.display());
                seen.0 += 1;
            }
            Some("crt") => {
                assert_eq!(mode, 0o644, "{}", path.display());
                seen.1 += 1;
            }
            _ => {}
        }
    }
    // ca, nrf, amf.
    assert_eq!(seen, (3, 3));
}
