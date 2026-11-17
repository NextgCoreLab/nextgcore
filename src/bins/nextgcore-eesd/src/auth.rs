//! Per-operation OAuth2 authorization for the EES service APIs (eesd-08).
//!
//! TS 29.558 §6 requires the EES to verify that a service consumer is
//! authorized on every operation; the access token is a CAPIF/NRF-issued
//! OAuth2 bearer (RFC 6749). This module provides a LOCAL `require_oauth2`
//! gate built entirely on the existing public `nextgcore-sbi` primitives
//! (`authorize_bearer` for bearer extraction + ES256/JWKS verification, and
//! the `send_unauthorized`/`send_forbidden` ProblemDetails helpers). It is NOT
//! added to `nextgcore-sbi` — it lives in the EES crate per the bounded scope.
//!
//! Token verification needs the issuer's public keys (a JWKS). Since no live
//! CAPIF/NRF peer exists in this stack, the JWKS is provisioned out-of-band via
//! [`set_auth_jwks`] (from `--oauth2-jwks-file` at startup, or seeded in tests).
//! When no JWKS is configured the gate FAILS CLOSED: every protected operation
//! is rejected with 401 (authorization is mandatory, TS 29.558 §6). Full CAPIF
//! onboarding (AEF credential exchange) is DEFERRED.

use std::sync::OnceLock;
use std::sync::RwLock;

use nextgcore_sbi::callback_auth::{admits_without_bearer, OAuth2CallbackExemption};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::oauth::authorize_bearer;
use nextgcore_sbi::server::{send_forbidden, send_unauthorized};

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
/// OAuth2 scope required for the `eees-acrevents` service operations (D5).
pub const SCOPE_ACREVENTS: &str = "eees-acrevents";
/// OAuth2 scope required for the `eees-easinfoprov` service operations (#106).
pub const SCOPE_EASINFOPROV: &str = "eees-easinfoprov";
/// OAuth2 scope required for the `eees-ueidentifier` service operations (#106).
pub const SCOPE_UEIDENTIFIER: &str = "eees-ueidentifier";
/// OAuth2 scope required for the `eees-uelocation` service operations (#106).
pub const SCOPE_UELOCATION: &str = "eees-uelocation";
/// OAuth2 scope required for the `eees-session-with-qos` service operations (#106).
pub const SCOPE_SESSION_WITH_QOS: &str = "eees-session-with-qos";
/// OAuth2 scope required for the `eees-tie` service operations (#106).
pub const SCOPE_TIE: &str = "eees-tie";

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

/// The callback routes this EES serves that are admitted without a bearer
/// (#1525): a notification carries no access token (TS 33.501 §13.4.1, TS
/// 29.500 §6.10.7 NOTE) and is authenticated by the callback token in its path.
/// The same list is registered on the SBI server (#1519's
/// `with_oauth2_callback_exemptions`); because eesd gates the bearer per route
/// (eesd-08), [`require_oauth2`] consults it too. Empty unless a route that
/// needs one is served (today only demo d443a-edge-budget's QOS_MON notify), so
/// by default every route requires a bearer, as before.
static CALLBACK_EXEMPTIONS: RwLock<Vec<OAuth2CallbackExemption>> = RwLock::new(Vec::new());

/// Install the callback exemptions [`require_oauth2`] consults (start-up, and
/// tests).
pub fn set_callback_exemptions(exemptions: Vec<OAuth2CallbackExemption>) {
    *CALLBACK_EXEMPTIONS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = exemptions;
}

/// The installed callback exemptions, as `METHOD /pattern` (tests, logs).
pub fn callback_exemption_routes() -> Vec<String> {
    CALLBACK_EXEMPTIONS
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .map(OAuth2CallbackExemption::route)
        .collect()
}

/// Whether `req` is a registered callback route carrying a callback token the
/// EES holds: then no bearer is required. The shared matcher
/// (`callback_auth::admits_without_bearer`) is strict: exact method, the raw
/// path segment for segment (no trailing `/`, no extra segment, no
/// percent-encoded variant), and the route's own token check.
fn callback_admitted(req: &SbiRequest) -> bool {
    let exemptions = CALLBACK_EXEMPTIONS
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let admitted = admits_without_bearer(&exemptions, &req.header.method, &req.header.uri);
    if admitted {
        log::debug!(
            "{} {}: callback admitted on its callback token, no bearer required (#1525)",
            req.header.method,
            // An exempt route's token is its last segment, by construction.
            nextgcore_sbi::log_redact::redact_last_segment(&req.header.uri)
        );
    }
    admitted
}

/// Serializes tests that mutate any process-global in this crate.
///
/// An ALIAS for `context::PROCESS_STATE_TEST_LOCK` as of #107, not a second static.
/// It used to be declared here, which made a test for a new global in another module
/// reach for its own lock -- two disjoint agreements over one ambient state, which is
/// #308's defect and #276's hang. Kept under this name so the 55 existing call sites
/// do not churn.
#[cfg(test)]
pub(crate) use crate::context::PROCESS_STATE_TEST_LOCK as GLOBAL_STATE_TEST_LOCK;

/// Per-operation OAuth2 gate.
///
/// Returns `None` when the request is authorized (handler should run), or
/// `Some(response)` carrying the RFC 7807 error to return:
/// * 401 — missing/malformed/invalid/expired bearer token, or no JWKS configured.
/// * 403 — valid token whose `scope` does not include `expected_scope`.
///
/// A registered callback route with a callback token the EES holds is admitted
/// without a bearer (#1525, [`set_callback_exemptions`]); every other request,
/// including that route with a wrong, stale or missing token, needs a bearer.
pub fn require_oauth2(req: &SbiRequest, expected_scope: &str) -> Option<SbiResponse> {
    require_oauth2_aud(req, expected_scope, &[])
}

/// [`require_oauth2`] that also requires the token's `aud` to name one of
/// `audiences` (TS 33.501 §13.4.1.1.2: the producer checks "that the audience
/// claim in the access token matches its own identity or the NF type of NF
/// Service Producer"). An empty `audiences` checks no audience.
pub fn require_oauth2_aud(
    req: &SbiRequest,
    expected_scope: &str,
    audiences: &[&str],
) -> Option<SbiResponse> {
    if callback_admitted(req) {
        return None;
    }
    // Clone the configured JWKS out of the lock so verification happens without
    // holding the guard.
    let jwks = auth_jwks().read().ok().and_then(|g| g.clone());
    let auth_header = req.http.get_header("authorization").map(String::as_str);
    require_oauth2_with_aud(auth_header, expected_scope, audiences, jwks.as_ref())
}

/// The audiences the `eees-eeccontextreloc` route accepts (#1664 review M1):
/// `AF`, the NF type every EES registers at the NRF as and the target type of
/// the relocation pull's token, and this EES's own AF `nfInstanceId`. An
/// NRF-signed token for any other audience is refused, even with the right
/// scope.
///
/// `EES` is deliberately not accepted. nrfd sets `aud` to the requested
/// `targetNfType` verbatim, so a profile registered with that type could obtain
/// an NRF-signed `aud=EES` token. A CAPIF-issued token would carry `EES` (TS
/// 29.558 §10.2), but this EES has one trust source, `--oauth2-jwks-file`, and
/// cannot tell a CAPIF signature from an NRF one. CAPIF tokens on this route are
/// out of scope until a separate CAPIF trust source exists.
pub fn eec_context_reloc_audiences() -> [String; 2] {
    let shared = nextgcore_sbi::nf_instance_id::nf_instance_id(nextgcore_sbi::types::NfType::Af);
    [
        nextgcore_sbi::types::NfType::Af.to_str().to_string(),
        crate::nrf_af::af_instance_id(shared),
    ]
}

/// Pure core of [`require_oauth2`] — takes the bearer header value and the JWKS
/// explicitly so it is deterministically unit-testable without process globals.
pub(crate) fn require_oauth2_with(
    auth_header: Option<&str>,
    expected_scope: &str,
    jwks: Option<&serde_json::Value>,
) -> Option<SbiResponse> {
    require_oauth2_with_aud(auth_header, expected_scope, &[], jwks)
}

/// [`require_oauth2_with`] that also requires the token's `aud` to name one of
/// `audiences` (none checked when empty). A wrong audience is a 401: the token
/// was not issued for this producer (RFC 6750 `invalid_token`).
pub(crate) fn require_oauth2_with_aud(
    auth_header: Option<&str>,
    expected_scope: &str,
    audiences: &[&str],
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

    if !audiences.is_empty()
        && !audiences
            .iter()
            .any(|aud| nextgcore_sbi::oauth::check_audience(&claims.aud, aud).is_ok())
    {
        return Some(send_unauthorized(
            "Access token audience is not this EES",
            Some("UNAUTHORIZED"),
        ));
    }

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

    /// #1664 review M1: with audiences required, a token with the right scope
    /// but another NF's audience (an NRF-signed token for an SMF) is refused
    /// 401; one for AF, or for an audience in an `aud` array, passes.
    #[test]
    fn a_reloc_token_for_another_audience_is_refused() {
        use nextgcore_sbi::test_support::oauth2::{es256_access_token, jwks_for};
        let sk = signing_key();
        let jwks = jwks_for(&sk, "k1");
        let header = |aud: &str| {
            format!(
                "Bearer {}",
                es256_access_token(&sk, "k1", aud, SCOPE_EECCONTEXTRELOC)
            )
        };
        let audiences = ["AF", "6b1d7e3c-1664-4000-8000-000000000001"];
        let check = |h: &str| {
            require_oauth2_with_aud(Some(h), SCOPE_EECCONTEXTRELOC, &audiences, Some(&jwks))
                .map(|r| r.status)
        };
        assert_eq!(check(&header("SMF")), Some(401), "another NF's audience");
        assert_eq!(check(&header("AF")), None);
        assert_eq!(check(&header("6b1d7e3c-1664-4000-8000-000000000001")), None);
        assert_eq!(
            check(&header("EES")),
            Some(401),
            "EES: not distinguishable from an NRF token"
        );
        // Without required audiences the scope alone decides, as before.
        assert_eq!(
            require_oauth2_with(Some(&header("SMF")), SCOPE_EECCONTEXTRELOC, Some(&jwks))
                .map(|r| r.status),
            None
        );
    }
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
        let resp =
            require_oauth2_with(Some("Bearer not.a.jwt"), SCOPE_EASREGISTRATION, Some(&jwks));
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
        assert!(
            resp.is_none(),
            "valid token with correct scope is authorized"
        );
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
