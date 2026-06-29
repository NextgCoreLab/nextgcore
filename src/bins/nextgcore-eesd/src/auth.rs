//! Per-operation OAuth2 authorization for the EES service APIs (eesd-08).
//!
//! TS 29.558 §6 requires the EES to verify that a service consumer is
//! authorized on every operation; the access token is a CAPIF/NRF-issued
//! OAuth2 bearer (RFC 6749). This module provides a LOCAL `require_oauth2`
//! gate built entirely on the existing public `ogs-sbi` primitives
//! (`authorize_bearer` for bearer extraction + ES256/JWKS verification, and
//! the `send_unauthorized`/`send_forbidden` ProblemDetails helpers). It is NOT
//! added to `ogs-sbi` — it lives in the EES crate per the bounded scope.
//!
//! Token verification needs the issuer's public keys (a JWKS). Since no live
//! CAPIF/NRF peer exists in this stack, the JWKS is provisioned out-of-band via
//! [`set_auth_jwks`] (from `--oauth2-jwks-file` at startup, or seeded in tests).
//! When no JWKS is configured the gate FAILS CLOSED: every protected operation
//! is rejected with 401 (authorization is mandatory, TS 29.558 §6). Full CAPIF
//! onboarding (AEF credential exchange) is DEFERRED.

use std::sync::OnceLock;
use std::sync::RwLock;

use ogs_sbi::message::{SbiRequest, SbiResponse};
use ogs_sbi::oauth::authorize_bearer;
use ogs_sbi::server::{send_forbidden, send_unauthorized};

/// OAuth2 scope required for the `eees-easregistration` service operations.
pub const SCOPE_EASREGISTRATION: &str = "eees-easregistration";
/// OAuth2 scope required for the `eees-easdiscovery` service operations.
pub const SCOPE_EASDISCOVERY: &str = "eees-easdiscovery";
/// OAuth2 scope required for the `eees-eecregistration` service operations.
pub const SCOPE_EECREGISTRATION: &str = "eees-eecregistration";
/// OAuth2 scope required for the `eees-appctxtreloc` service operations (eesd-07).
pub const SCOPE_APPCTXTRELOC: &str = "eees-appctxtreloc";
/// OAuth2 scope required for the `eees-eel-acr` service operations (eesd-07).
pub const SCOPE_EEL_ACR: &str = "eees-eel-acr";
/// OAuth2 scope required for the `eees-acrstatus-update` service operations (eesd-07).
pub const SCOPE_ACRSTATUS_UPDATE: &str = "eees-acrstatus-update";
/// OAuth2 scope required for the `eees-cea` service operations (eesd-13).
pub const SCOPE_CEA: &str = "eees-cea";
/// OAuth2 scope required for the `eees-appclientinformation` service operations (eesd-13).
pub const SCOPE_APPCLIENTINFORMATION: &str = "eees-appclientinformation";
/// OAuth2 scope required for the `eees-acrmgntevent` service operations (eesd-13).
pub const SCOPE_ACRMGNTEVENT: &str = "eees-acrmgntevent";
/// OAuth2 scope required for the `eees-eeccontextreloc` service operations (eesd-13).
pub const SCOPE_EECCONTEXTRELOC: &str = "eees-eeccontextreloc";
/// OAuth2 scope required for the `eees-acr-param` service operations (eesd-13).
pub const SCOPE_ACR_PARAM: &str = "eees-acr-param";

/// Process-wide JWKS used to verify access tokens. `None` ⇒ unconfigured
/// (fail-closed). Seeded from `--oauth2-jwks-file` or by tests.
static AUTH_JWKS: OnceLock<RwLock<Option<serde_json::Value>>> = OnceLock::new();

fn auth_jwks() -> &'static RwLock<Option<serde_json::Value>> {
    AUTH_JWKS.get_or_init(|| RwLock::new(None))
}

/// Provision the JWKS used to verify OAuth2 access tokens.
pub fn set_auth_jwks(jwks: serde_json::Value) {
    if let Ok(mut g) = auth_jwks().write() {
        *g = Some(jwks);
    }
}

/// Whether an OAuth2 verification key set has been configured.
pub fn is_auth_configured() -> bool {
    auth_jwks().read().map(|g| g.is_some()).unwrap_or(false)
}

#[cfg(test)]
pub fn clear_auth_jwks() {
    if let Ok(mut g) = auth_jwks().write() {
        *g = None;
    }
}

/// Serializes tests that mutate the process-global JWKS / EES context across
/// modules (`auth` + `main` router tests) so they don't race under the default
/// parallel test runner.
#[cfg(test)]
pub(crate) static GLOBAL_STATE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Per-operation OAuth2 gate.
///
/// Returns `None` when the request is authorized (handler should run), or
/// `Some(response)` carrying the RFC 7807 error to return:
/// * 401 — missing/malformed/invalid/expired bearer token, or no JWKS configured.
/// * 403 — valid token whose `scope` does not include `expected_scope`.
pub fn require_oauth2(req: &SbiRequest, expected_scope: &str) -> Option<SbiResponse> {
    // Clone the configured JWKS out of the lock so verification happens without
    // holding the guard.
    let jwks = auth_jwks().read().ok().and_then(|g| g.clone());
    let auth_header = req.http.get_header("authorization").map(String::as_str);
    require_oauth2_with(auth_header, expected_scope, jwks.as_ref())
}

/// Pure core of [`require_oauth2`] — takes the bearer header value and the JWKS
/// explicitly so it is deterministically unit-testable without process globals.
pub(crate) fn require_oauth2_with(
    auth_header: Option<&str>,
    expected_scope: &str,
    jwks: Option<&serde_json::Value>,
) -> Option<SbiResponse> {
    let Some(jwks) = jwks else {
        return Some(send_unauthorized(
            "OAuth2 authorization not configured (CAPIF/NRF JWKS missing)",
            Some("UNAUTHORIZED"),
        ));
    };

    let claims = match authorize_bearer(auth_header, jwks) {
        Ok(c) => c,
        Err(_) => {
            return Some(send_unauthorized(
                "Missing or invalid OAuth2 access token",
                Some("UNAUTHORIZED"),
            ));
        }
    };

    if !claims.scope.split_whitespace().any(|s| s == expected_scope) {
        return Some(send_forbidden(
            &format!("Access token scope does not permit '{expected_scope}'"),
            Some("INSUFFICIENT_SCOPE"),
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    fn signing_key() -> SigningKey {
        SigningKey::from_slice(&[7u8; 32]).unwrap()
    }

    fn jwks_for(sk: &SigningKey, kid: &str) -> serde_json::Value {
        let point = sk.verifying_key().to_encoded_point(false);
        serde_json::json!({"keys":[{
            "kty":"EC","crv":"P-256","use":"sig","alg":"ES256","kid":kid,
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        }]})
    }

    fn mint_token(sk: &SigningKey, kid: &str, scope: &str) -> String {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let header = format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{kid}"}}"#);
        let claims = serde_json::json!({
            "iss":"CAPIF","sub":"eec-1","aud":"EES","scope":scope,"exp":exp,"iat":0
        })
        .to_string();
        let h = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let p = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let sig: Signature = sk.sign(format!("{h}.{p}").as_bytes());
        let s = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{h}.{p}.{s}")
    }

    #[test]
    fn test_require_oauth2_unconfigured_401() {
        // No JWKS provisioned: fail closed with 401.
        let resp = require_oauth2_with(Some("Bearer x.y.z"), SCOPE_EASREGISTRATION, None);
        assert_eq!(resp.unwrap().status, 401);
    }

    #[test]
    fn test_require_oauth2_missing_token_401() {
        let sk = signing_key();
        let jwks = jwks_for(&sk, "k1");
        let resp = require_oauth2_with(None, SCOPE_EASREGISTRATION, Some(&jwks));
        assert_eq!(resp.unwrap().status, 401);
    }

    #[test]
    fn test_require_oauth2_invalid_token_401() {
        let sk = signing_key();
        let jwks = jwks_for(&sk, "k1");
        let resp = require_oauth2_with(Some("Bearer not.a.jwt"), SCOPE_EASREGISTRATION, Some(&jwks));
        assert_eq!(resp.unwrap().status, 401);
    }

    #[test]
    fn test_require_oauth2_wrong_scope_403() {
        let sk = signing_key();
        let jwks = jwks_for(&sk, "k1");
        let token = mint_token(&sk, "k1", "eees-easdiscovery");
        let header = format!("Bearer {token}");
        let resp = require_oauth2_with(Some(&header), SCOPE_EASREGISTRATION, Some(&jwks));
        assert_eq!(resp.unwrap().status, 403);
    }

    #[test]
    fn test_require_oauth2_valid_scope_passes() {
        let sk = signing_key();
        let jwks = jwks_for(&sk, "k1");
        let token = mint_token(&sk, "k1", "eees-easregistration");
        let header = format!("Bearer {token}");
        let resp = require_oauth2_with(Some(&header), SCOPE_EASREGISTRATION, Some(&jwks));
        assert!(resp.is_none(), "valid token with correct scope is authorized");
    }

    #[test]
    fn test_require_oauth2_multi_scope_token() {
        let sk = signing_key();
        let jwks = jwks_for(&sk, "k1");
        let token = mint_token(&sk, "k1", "eees-easdiscovery eees-easregistration");
        let header = format!("Bearer {token}");
        assert!(
            require_oauth2_with(Some(&header), SCOPE_EASREGISTRATION, Some(&jwks)).is_none(),
            "space-delimited scope set is matched per-entry"
        );
    }

    #[test]
    fn test_global_jwks_store_roundtrip() {
        let _g = GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let sk = signing_key();
        clear_auth_jwks();
        assert!(!is_auth_configured());
        set_auth_jwks(jwks_for(&sk, "k1"));
        assert!(is_auth_configured());
        clear_auth_jwks();
    }
}
