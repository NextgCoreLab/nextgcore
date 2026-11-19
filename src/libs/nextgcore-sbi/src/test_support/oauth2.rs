//! OAuth2 stand-ins for tests of an NF's outbound service requests (#1658).
//!
//! A consumer presents an NRF-issued access token on each service request
//! (TS 33.501 §13.4.1.1.2, in `Authorization: Bearer`, TS 29.500 §6.7.3). To
//! prove a site does, a test needs two things: an NRF that issues tokens, and a
//! producer that refuses a request without a valid one, the way an OAuth2-required
//! NF listener does. Both are here, so every NF's test uses the same producer gate
//! (nextgcore-sbi's own `require_oauth2`, JWKS and audience check), not a copy.
//!
//! Test-only: compiled under `cfg(test)` or the `test-support` feature, which
//! only dev-dependencies enable, so no production build ships a token minter.
//!
//! Both stand-ins listen on loopback in cleartext. A test that drives production
//! code at them sets the `dev` SBI profile override and never resets it (see
//! [`crate::security::set_sbi_profile_override`]).

use std::sync::{Arc, Mutex};

use crate::message::{SbiRequest, SbiResponse};
use crate::oauth::OAuth2Client;
use crate::server::{SbiServer, SbiServerConfig};
use crate::types::NfType;

/// The `kid` the stand-in NRF signs its tokens under.
pub const TEST_NRF_KID: &str = "nrf-test";

/// One request a stand-in producer served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenRequest {
    /// HTTP method.
    pub method: String,
    /// Request path, without the query.
    pub path: String,
    /// The `Authorization` header, if any.
    pub authorization: Option<String>,
}

/// What a stand-in producer served, in order.
pub type SeenRequests = Arc<Mutex<Vec<SeenRequest>>>;

/// A compact ES256 access token signed by `sk` under `kid`, for audience `aud`
/// and scope `scope`, expiring in an hour.
pub fn es256_access_token(
    sk: &p256::ecdsa::SigningKey,
    kid: &str,
    aud: &str,
    scope: &str,
) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::ecdsa::{signature::Signer, Signature};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": kid }).to_string();
    let claims = serde_json::json!({
        "iss": "NRF", "sub": "consumer", "aud": aud,
        "scope": scope, "exp": now + 3600, "iat": now,
    })
    .to_string();
    let h = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let p = URL_SAFE_NO_PAD.encode(claims.as_bytes());
    let sig: Signature = sk.sign(format!("{h}.{p}").as_bytes());
    format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

/// The public JWKS for `sk` under `kid`.
pub fn jwks_for(sk: &p256::ecdsa::SigningKey, kid: &str) -> serde_json::Value {
    serde_json::json!({ "keys": [crate::oauth::es256_public_jwk(sk.verifying_key(), kid)] })
}

/// A stand-in NRF token endpoint. It mints an ES256 token signed by `sk` whose
/// `aud` is the request's `targetNfType` and whose `scope` is the request's
/// `scope` (TS 29.510 §6.3.5.2.2 AccessTokenReq), so a producer that checks both
/// accepts it. It answers the bespoke and the TS 29.510 standard token path, and
/// 404 to anything else. Returns the server (keep it alive) and its port.
pub async fn token_nrf(sk: p256::ecdsa::SigningKey) -> (SbiServer, u16) {
    let (listener, addr) = super::bound_listener().into_parts();
    let server = SbiServer::on_listener(SbiServerConfig::new(addr), listener);
    server
        .start(move |req: SbiRequest| {
            let sk = sk.clone();
            async move {
                let path = req.header.uri.split('?').next().unwrap_or_default();
                if path != OAuth2Client::TOKEN_PATH_BESPOKE
                    && path != OAuth2Client::TOKEN_PATH_STANDARD
                {
                    return SbiResponse::with_status(404);
                }
                let form = req.http.content.clone().unwrap_or_default();
                let field = |name: &str| {
                    form.split('&')
                        .find_map(|kv| kv.strip_prefix(&format!("{name}=")))
                        .map(crate::uri_encode::decode_form_value)
                        .unwrap_or_default()
                };
                let token =
                    es256_access_token(&sk, TEST_NRF_KID, &field("targetNfType"), &field("scope"));
                SbiResponse::with_status(200)
                    .with_json_body(&serde_json::json!({
                        "access_token": token,
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    }))
                    .unwrap_or_else(|_| SbiResponse::with_status(500))
            }
        })
        .await
        .expect("stand-in token NRF starts");
    (server, addr.port())
}

/// An OAuth2 client of NF type `consumer`, asking the stand-in NRF on `nrf_port`.
///
/// It touches no process-wide CCA state: no signing key, no `x5c` chain, and
/// nothing published to the CCA public-JWK directory
/// ([`OAuth2Client::isolated_for_test`]). `OAuth2Client::new` would resolve both
/// from the process-wide override or environment, which a sibling test may have
/// set, and could publish a key file. The stand-in NRF needs no assertion.
pub fn oauth2_client_for(nrf_port: u16, consumer: NfType) -> Arc<OAuth2Client> {
    Arc::new(OAuth2Client::isolated_for_test(
        format!("http://127.0.0.1:{nrf_port}"),
        format!("{}-test", consumer.to_str().to_ascii_lowercase()),
        consumer,
    ))
}

/// A producer of NF type `nf_type` that REQUIRES OAuth2 the way an OAuth2-required
/// NF listens: nextgcore-sbi verifies the bearer against `sk`'s JWKS and checks
/// that its `aud` names `nf_type`, answering 401 before the handler runs
/// otherwise. `respond` answers each request that passed.
///
/// Every request the handler serves is recorded, so a recorded request is one
/// that PASSED the gate: a test asserts that the request it expects is there,
/// which a token-less or wrong-audience send cannot satisfy.
pub async fn oauth2_producer(
    sk: &p256::ecdsa::SigningKey,
    nf_type: NfType,
    respond: impl Fn(&SbiRequest) -> SbiResponse + Clone + Send + Sync + 'static,
) -> (SbiServer, u16, SeenRequests) {
    let seen: SeenRequests = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let (listener, addr) = super::bound_listener().into_parts();
    let mut cfg = SbiServerConfig::new(addr).with_expected_audience_nf_type(nf_type);
    cfg.require_oauth2 = true;
    cfg.oauth2_jwks = Some(jwks_for(sk, TEST_NRF_KID));
    let server = SbiServer::on_listener(cfg, listener);
    server
        .start(move |req: SbiRequest| {
            let sink = Arc::clone(&sink);
            let respond = respond.clone();
            async move {
                sink.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(SeenRequest {
                        method: req.header.method.clone(),
                        path: req
                            .header
                            .uri
                            .split('?')
                            .next()
                            .unwrap_or_default()
                            .to_string(),
                        authorization: req.http.get_header("authorization").cloned(),
                    });
                respond(&req)
            }
        })
        .await
        .expect("stand-in OAuth2 producer starts");
    (server, addr.port(), seen)
}

/// How many requests in `seen` were `method` on a path containing `fragment` and
/// carried a bearer.
pub fn bearer_requests(seen: &SeenRequests, method: &str, fragment: &str) -> usize {
    seen.lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|r| {
            r.method == method
                && r.path.contains(fragment)
                && r.authorization
                    .as_deref()
                    .is_some_and(|a| a.starts_with("Bearer "))
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::SbiClient;

    /// The fixture's client carries no CCA key or chain, whatever the
    /// process-wide CCA state is: it never reads it (R8 review).
    #[test]
    fn the_fixture_client_carries_no_process_wide_cca_state() {
        let client = oauth2_client_for(1, NfType::Udm);
        assert!(!client.has_cca_signing_key());
        assert!(!client.has_cca_cert_chain());
    }

    /// The two stand-ins agree with each other and with the shared client: a client
    /// with the OAuth2 client attached gets through the gate, and one without is
    /// refused 401 and never reaches the handler.
    #[tokio::test]
    async fn the_gate_admits_a_tokened_request_and_refuses_a_bare_one() {
        crate::security::set_sbi_profile_override(crate::security::SbiProfile::Dev);
        let sk = crate::oauth::generate_es256_key();
        let (_nrf, nrf_port) = token_nrf(sk.clone()).await;
        let (_pcf, pcf_port, seen) =
            oauth2_producer(&sk, NfType::Pcf, |_| SbiResponse::with_status(204)).await;

        let bare = SbiClient::with_host_port("127.0.0.1", pcf_port);
        let resp = bare
            .post_json(
                "/npcf-policyauthorization/v1/app-sessions",
                &serde_json::json!({}),
            )
            .await
            .expect("bare send");
        assert_eq!(resp.status, 401);
        assert!(
            seen.lock().unwrap().is_empty(),
            "a 401 never reaches the handler"
        );

        let tokened = SbiClient::with_host_port("127.0.0.1", pcf_port)
            .with_oauth2(oauth2_client_for(nrf_port, NfType::Tsctsf), NfType::Pcf);
        let resp = tokened
            .post_json(
                "/npcf-policyauthorization/v1/app-sessions",
                &serde_json::json!({}),
            )
            .await
            .expect("tokened send");
        assert_eq!(resp.status, 204);
        assert_eq!(
            bearer_requests(&seen, "POST", "/npcf-policyauthorization/v1/app-sessions"),
            1
        );
    }
}
