//! OAuth2 Token Exchange for 5G SBA
//!
//! Implements the OAuth2 client credentials grant flow (RFC 6749 Section 4.4)
//! as used in 3GPP TS 29.510 for NRF-based access token management.
//!
//! In 5G SBA, the NRF acts as the Authorization Server. NF service consumers
//! request access tokens using the client credentials grant before calling
//! NF service producers.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio_rustls::TlsConnector;

use crate::error::{SbiError, SbiResult};
use crate::types::NfType;

// ============================================================================
// I4 — flag-gated default OAuth2 resource paths (TS 29.510 §5.4 Nnrf_AccessToken)
// ============================================================================
//
// H8-AB / sbi-06 made the standard TS 29.510 paths (`/oauth2/token`,
// `/oauth2/retrieve-key`) selectable *per instance* while keeping the bespoke
// Open5GS-style paths as the compiled-in default. I4 adds a single process-wide
// flip so a deployment can make the *default* path set the standard one without
// touching every construction site — shipped OFF (bespoke) so the matched-sim
// E2E, whose NRF still serves the bespoke endpoints, stays green until the
// consumers move. Explicit per-instance overrides ([`OAuth2Client::with_token_path`],
// [`JwksCache::for_nrf_with_path`]) always win over this selector.

/// Environment variable selecting, process-wide, whether newly-constructed
/// OAuth2 clients and JWKS caches default to the **standard** TS 29.510
/// resource paths (`/oauth2/token`, `/oauth2/retrieve-key`) instead of the
/// bespoke Open5GS-style paths (`/nnrf-oauth2/v1/access-token`,
/// `/nnrf-oauth2/v1/jwks`).
///
/// Truthy values (`1`, `true`, `yes`, `on`, case-insensitive) enable the
/// standard paths; anything else — including the variable being unset — keeps
/// the bespoke default. A programmatic override via
/// [`set_oauth2_standard_paths_default`] takes precedence over the env var.
pub const OAUTH2_STANDARD_PATHS_ENV: &str = "NEXTGCORE_SBI_OAUTH2_STANDARD_PATHS";

/// Tri-state programmatic override of the default-path selector:
/// `0` = unset (consult [`OAUTH2_STANDARD_PATHS_ENV`]), `1` = force bespoke,
/// `2` = force standard.
static OAUTH2_PATH_MODE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Force (or clear) the process-wide default OAuth2 resource-path selection,
/// overriding [`OAUTH2_STANDARD_PATHS_ENV`].
///
/// `true` makes every subsequently-constructed [`OAuth2Client::new`] /
/// [`JwksCache::for_nrf`] default to the TS 29.510 standard paths; `false`
/// forces the bespoke default. Instances built with an explicit path
/// ([`OAuth2Client::with_token_path`] / [`JwksCache::for_nrf_with_path`]) are
/// unaffected. The shipped default is **bespoke** (env unset, no override) so
/// the matched-sim E2E stays green until the NRF serves the standard paths.
pub fn set_oauth2_standard_paths_default(enabled: bool) {
    OAUTH2_PATH_MODE.store(
        if enabled { 2 } else { 1 },
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// Clear a programmatic override set by [`set_oauth2_standard_paths_default`],
/// restoring env-var-driven resolution.
pub fn reset_oauth2_standard_paths_default() {
    OAUTH2_PATH_MODE.store(0, std::sync::atomic::Ordering::Relaxed);
}

/// Whether newly-constructed OAuth2 clients / JWKS caches default to the
/// standard TS 29.510 paths. Resolves the programmatic override first, then
/// [`OAUTH2_STANDARD_PATHS_ENV`], defaulting to `false` (bespoke).
pub fn oauth2_standard_paths_default() -> bool {
    match OAUTH2_PATH_MODE.load(std::sync::atomic::Ordering::Relaxed) {
        1 => false,
        2 => true,
        _ => env_flag_truthy(std::env::var(OAUTH2_STANDARD_PATHS_ENV).ok().as_deref()),
    }
}

/// Pure truthiness test for the standard-paths env value (unit-testable without
/// touching the process environment).
fn env_flag_truthy(value: Option<&str>) -> bool {
    match value {
        Some(v) => {
            let v = v.trim();
            v.eq_ignore_ascii_case("1")
                || v.eq_ignore_ascii_case("true")
                || v.eq_ignore_ascii_case("yes")
                || v.eq_ignore_ascii_case("on")
        }
        None => false,
    }
}

// ============================================================================
// ES256 key material (issue #64) — shared by the NRF's token-signing key and
// every NF's Client-Credentials-Assertion signing key
// ============================================================================

/// Load a hex-encoded ES256 (ECDSA P-256) private key from `path`, or generate
/// one and persist it there.
///
/// The format is the raw 32-byte scalar, hex-encoded. Deliberately not
/// PKCS#8/PEM: that needs a `p256` feature this build does not enable, and the
/// intended operator flow is to let the process generate the file on first
/// start and then mount it (as a Kubernetes Secret or equivalent) so restarts
/// and replicas share it — no externally-generated key has to be parsed.
///
/// **A malformed or wrong-length file is an error, never a silent
/// regeneration.** The distinction that matters is between *absent* and
/// *invalid*: absent legitimately means "create one", invalid means a human
/// needs to look at it. Quietly minting a replacement would invalidate every
/// credential other parties have already verified against the old key — for the
/// NRF's signing key that is exactly the defect issue #64 gap 4 fixed, and for
/// an NF's CCA key it would silently stop the NRF trusting that NF.
///
/// The file is created `0600` on Unix: it is a private key.
pub fn load_or_create_es256_key(path: &std::path::Path) -> SbiResult<p256::ecdsa::SigningKey> {
    if path.exists() {
        let text = std::fs::read_to_string(path).map_err(|e| {
            SbiError::ClientError(format!("failed to read ES256 key {}: {e}", path.display()))
        })?;
        let raw = hex::decode(text.trim()).map_err(|e| {
            SbiError::ClientError(format!(
                "ES256 key {} is not hex ({e}); refusing to regenerate, because a new key \
                 would invalidate every credential already issued under the old one",
                path.display()
            ))
        })?;
        let key = p256::ecdsa::SigningKey::from_slice(&raw).map_err(|e| {
            SbiError::ClientError(format!(
                "ES256 key {} does not hold a valid P-256 scalar ({} bytes): {e}",
                path.display(),
                raw.len()
            ))
        })?;
        return Ok(key);
    }

    let key = generate_es256_key();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                SbiError::ClientError(format!(
                    "failed to create the directory for {}: {e}",
                    path.display()
                ))
            })?;
        }
    }
    std::fs::write(path, hex::encode(key.to_bytes()))
        .map_err(|e| SbiError::ClientError(format!("failed to write {}: {e}", path.display())))?;
    // Owner-only: this is a private key.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
            SbiError::ClientError(format!(
                "failed to restrict permissions on {}: {e}",
                path.display()
            ))
        })?;
    }
    Ok(key)
}

/// Generate a fresh ES256 (ECDSA P-256) signing key.
pub fn generate_es256_key() -> p256::ecdsa::SigningKey {
    use rand::Rng;
    // Draw a random scalar; reject the (vanishingly rare) invalid ones.
    loop {
        let bytes = rand::rng().random::<[u8; 32]>();
        if let Ok(sk) = p256::ecdsa::SigningKey::from_slice(&bytes) {
            break sk;
        }
    }
}

// ============================================================================
// Client Credentials Assertion (CCA) — TS 33.501 §13.3.8
// ============================================================================

/// Default CCA lifetime. The assertion is presented once, immediately, on a
/// single token request, so it is deliberately short: TS 33.501 §13.3.8.3 has
/// the NRF validate the timestamp, and a long-lived assertion is a replayable
/// bearer credential.
pub const CCA_DEFAULT_LIFETIME_SECS: u64 = 60;

/// Build a signed Client Credentials Assertion (TS 33.501 §13.3.8.2).
///
/// The CCA is how an NF proves its identity to the NRF's access-token endpoint
/// when the NRF cannot see a mutually-authenticated client certificate — for
/// example when an SCP terminates TLS, or on a deployment where the NRF's
/// listener does not surface the peer certificate. Without it the endpoint has
/// nothing to authenticate and can only trust a self-asserted `nfInstanceId`,
/// which is issue #64 gaps 1 and 2.
///
/// Claims are exactly what the receiving NRF validates: `sub` and `iss` are the
/// asserting NF's own instance ID (the assertion is self-issued), `aud` is the
/// receiving NF's *type* (`"NRF"` for the token endpoint), plus `iat` and `exp`.
/// The signature is ES256 over `base64url(header) "." base64url(payload)`
/// (RFC 7515 §5.2), with the fixed 64-byte `r||s` form of RFC 7518 §3.4.
pub fn mint_cca(
    key: &p256::ecdsa::SigningKey,
    nf_instance_id: &str,
    audience: &str,
    now: u64,
    lifetime_secs: u64,
) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::ecdsa::{signature::Signer, Signature};

    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"JWT"}"#);
    let claims = serde_json::json!({
        "sub": nf_instance_id,
        "iss": nf_instance_id,
        "aud": audience,
        "iat": now,
        "exp": now.saturating_add(lifetime_secs),
    });
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    let signing_input = format!("{header}.{payload}");
    let signature: Signature = key.sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

/// Environment variable naming the file that holds this NF's ES256 CCA signing
/// key. Generated on first use if absent (see [`load_or_create_es256_key`]).
///
/// Resolved process-wide so a deployment gains client authentication without
/// touching any of the 16 `OAuth2Client::new` construction sites — the same
/// reasoning as the shared `--kill` helper: a knob duplicated per daemon stays
/// wrong in every one of them at once. Register the corresponding PUBLIC key
/// with the NRF under `nrf.sbi.oauth2.cca_trusted_keys`, keyed by this NF's
/// `nfInstanceId`, or the NRF cannot verify the assertion.
pub const CCA_SIGNING_KEY_FILE_ENV: &str = "NEXTGCORE_SBI_CCA_SIGNING_KEY_FILE";

/// Process-wide CCA signing key state: whether a programmatic override is in
/// force, and if so what it is.
enum CcaKeyOverride {
    /// No override — resolve [`CCA_SIGNING_KEY_FILE_ENV`].
    Unset,
    /// Explicitly no key: send token requests without a CCA even if the env var
    /// is set. Used by tests that assert the unauthenticated path.
    Disabled,
    /// Use this key.
    Key(Arc<p256::ecdsa::SigningKey>),
}

static CCA_KEY_OVERRIDE: std::sync::RwLock<CcaKeyOverride> =
    std::sync::RwLock::new(CcaKeyOverride::Unset);

/// Env-resolved key, computed at most once per process.
static CCA_KEY_FROM_ENV: OnceLock<Option<Arc<p256::ecdsa::SigningKey>>> = OnceLock::new();

/// Set the process-wide CCA signing key, overriding
/// [`CCA_SIGNING_KEY_FILE_ENV`]. Every subsequently-constructed
/// [`OAuth2Client`] signs its access-token requests with it.
pub fn set_cca_signing_key(key: Arc<p256::ecdsa::SigningKey>) {
    if let Ok(mut guard) = CCA_KEY_OVERRIDE.write() {
        *guard = CcaKeyOverride::Key(key);
    }
}

/// Force the process-wide CCA signing key OFF, so token requests carry no
/// assertion even when [`CCA_SIGNING_KEY_FILE_ENV`] is set.
pub fn disable_cca_signing_key() {
    if let Ok(mut guard) = CCA_KEY_OVERRIDE.write() {
        *guard = CcaKeyOverride::Disabled;
    }
}

/// Clear a programmatic override, restoring env-var-driven resolution.
pub fn reset_cca_signing_key() {
    if let Ok(mut guard) = CCA_KEY_OVERRIDE.write() {
        *guard = CcaKeyOverride::Unset;
    }
}

/// Resolve this NF's CCA signing key: the programmatic override first, then
/// [`CCA_SIGNING_KEY_FILE_ENV`], else `None` (no assertion is sent).
///
/// An unusable key file logs an `error!` naming the consequence and resolves to
/// `None` rather than aborting a request path that cannot report it; the NRF
/// then rejects the token request with `invalid_client` under its default
/// policy, so the misconfiguration is loud in both logs. Call
/// [`init_cca_signing_key_from_env`] at startup to fail fast instead.
pub fn cca_signing_key_default() -> Option<Arc<p256::ecdsa::SigningKey>> {
    if let Ok(guard) = CCA_KEY_OVERRIDE.read() {
        match &*guard {
            CcaKeyOverride::Disabled => return None,
            CcaKeyOverride::Key(k) => return Some(k.clone()),
            CcaKeyOverride::Unset => {}
        }
    }
    CCA_KEY_FROM_ENV
        .get_or_init(|| {
            let path = std::env::var(CCA_SIGNING_KEY_FILE_ENV).ok()?;
            let path = path.trim();
            if path.is_empty() {
                return None;
            }
            match load_or_create_es256_key(std::path::Path::new(path)) {
                Ok(key) => {
                    log::info!("CCA signing key loaded from {path}");
                    Some(Arc::new(key))
                }
                Err(e) => {
                    log::error!(
                        "CCA signing key {path} is unusable: {e}. Access-token requests will \
                         be sent WITHOUT client authentication, and an NRF running its \
                         default policy will reject them with invalid_client."
                    );
                    None
                }
            }
        })
        .clone()
}

/// Resolve [`CCA_SIGNING_KEY_FILE_ENV`] eagerly so a misconfigured key file
/// fails at startup rather than at the first token request. Returns whether a
/// key is now configured.
pub fn init_cca_signing_key_from_env() -> SbiResult<bool> {
    let Ok(path) = std::env::var(CCA_SIGNING_KEY_FILE_ENV) else {
        return Ok(false);
    };
    let path = path.trim().to_string();
    if path.is_empty() {
        return Ok(false);
    }
    let key = load_or_create_es256_key(std::path::Path::new(&path))?;
    set_cca_signing_key(Arc::new(key));
    log::info!("CCA signing key loaded from {path}");
    Ok(true)
}

/// OAuth2 access token response per RFC 6749 Section 4.4.3 and 3GPP TS 29.510.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenResponse {
    /// The access token (JWT in 5G SBA)
    pub access_token: String,
    /// Token type, always "Bearer"
    pub token_type: String,
    /// Lifetime of the token in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    /// Scope granted (space-delimited NF service names)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// OAuth2 access token request per RFC 6749 Section 4.4.2 and 3GPP TS 29.510.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenRequest {
    /// Grant type: must be "client_credentials"
    pub grant_type: String,
    /// NF Instance ID of the NF service consumer
    #[serde(rename = "nfInstanceId")]
    pub nf_instance_id: String,
    /// NF type of the NF service consumer
    #[serde(rename = "nfType")]
    pub nf_type: NfType,
    /// NF type of the target NF service producer
    #[serde(rename = "targetNfType")]
    pub target_nf_type: NfType,
    /// Requested scope (space-delimited NF service names)
    pub scope: String,
    /// Target NF Instance ID (optional)
    #[serde(rename = "targetNfInstanceId", skip_serializing_if = "Option::is_none")]
    pub target_nf_instance_id: Option<String>,
    /// Client Credentials Assertion (TS 33.501 §13.3.8, TS 29.510 §6.7.5): a
    /// self-issued, ES256-signed JWT proving the requester really is
    /// `nf_instance_id`. Absent by default; populated by [`OAuth2Client`] when a
    /// CCA signing key is configured (see [`CCA_SIGNING_KEY_FILE_ENV`]).
    ///
    /// Without it the NRF has nothing to authenticate and can only trust a
    /// self-asserted `nfInstanceId` — issue #64 gaps 1 and 2 — so an NRF running
    /// its default policy rejects such a request with `invalid_client`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cca: Option<String>,
}

impl AccessTokenRequest {
    /// Create a new access token request for the given consumer/producer pair.
    pub fn new(
        nf_instance_id: impl Into<String>,
        nf_type: NfType,
        target_nf_type: NfType,
        scope: impl Into<String>,
    ) -> Self {
        Self {
            grant_type: "client_credentials".to_string(),
            nf_instance_id: nf_instance_id.into(),
            nf_type,
            target_nf_type,
            scope: scope.into(),
            target_nf_instance_id: None,
            cca: None,
        }
    }

    /// Set the target NF instance ID.
    pub fn with_target_nf_instance_id(mut self, id: impl Into<String>) -> Self {
        self.target_nf_instance_id = Some(id.into());
        self
    }

    /// Attach a Client Credentials Assertion (TS 33.501 §13.3.8). Build one with
    /// [`mint_cca`].
    pub fn with_cca(mut self, cca: impl Into<String>) -> Self {
        self.cca = Some(cca.into());
        self
    }

    /// Encode the request as `application/x-www-form-urlencoded` body.
    pub fn to_form_body(&self) -> String {
        let mut parts = vec![
            format!("grant_type={}", url_encode(&self.grant_type)),
            format!("nfInstanceId={}", url_encode(&self.nf_instance_id)),
            format!("nfType={}", url_encode(self.nf_type.to_str())),
            format!("targetNfType={}", url_encode(self.target_nf_type.to_str())),
            format!("scope={}", url_encode(&self.scope)),
        ];
        if let Some(ref id) = self.target_nf_instance_id {
            parts.push(format!("targetNfInstanceId={}", url_encode(id)));
        }
        // TS 29.510 §6.7.5: the CCA travels in the token request. It is a JWT —
        // base64url plus two `.` separators, all form-safe — but it is
        // percent-encoded like every other value so the encoding is uniform.
        if let Some(ref cca) = self.cca {
            parts.push(format!("cca={}", url_encode(cca)));
        }
        parts.join("&")
    }
}

/// OAuth2 error response per RFC 6749 Section 5.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenError {
    /// Error code
    pub error: String,
    /// Human-readable description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    /// URI for more information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,
}

/// A cached token with expiry tracking.
#[derive(Debug, Clone)]
struct CachedToken {
    response: AccessTokenResponse,
    obtained_at: Instant,
}

impl CachedToken {
    fn is_expired(&self) -> bool {
        let expires_in = self.response.expires_in.unwrap_or(3600);
        // Refresh 30 seconds before actual expiry to avoid race conditions
        let margin = Duration::from_secs(30);
        let lifetime = Duration::from_secs(expires_in).saturating_sub(margin);
        self.obtained_at.elapsed() >= lifetime
    }
}

/// Cache key for tokens: (target_nf_type_str, scope).
type CacheKey = (String, String);

/// OAuth2 token cache with automatic expiry.
///
/// Caches access tokens keyed by `(target_nf_type, scope)` so repeated
/// requests to the same service reuse the token until it expires.
pub struct TokenCache {
    tokens: RwLock<HashMap<CacheKey, CachedToken>>,
}

impl TokenCache {
    pub fn new() -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
        }
    }

    /// Retrieve a non-expired cached token for the given key.
    pub async fn get(&self, target_nf_type: NfType, scope: &str) -> Option<AccessTokenResponse> {
        let key = (target_nf_type.to_str().to_string(), scope.to_string());
        let tokens = self.tokens.read().await;
        tokens.get(&key).and_then(|cached| {
            if cached.is_expired() {
                None
            } else {
                Some(cached.response.clone())
            }
        })
    }

    /// Store a token in the cache.
    pub async fn put(&self, target_nf_type: NfType, scope: &str, response: AccessTokenResponse) {
        let key = (target_nf_type.to_str().to_string(), scope.to_string());
        let cached = CachedToken {
            response,
            obtained_at: Instant::now(),
        };
        let mut tokens = self.tokens.write().await;
        tokens.insert(key, cached);
    }

    /// Remove expired entries from the cache.
    pub async fn purge_expired(&self) {
        let mut tokens = self.tokens.write().await;
        tokens.retain(|_, v| !v.is_expired());
    }

    /// Clear all cached tokens.
    pub async fn clear(&self) {
        let mut tokens = self.tokens.write().await;
        tokens.clear();
    }
}

impl Default for TokenCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate that an access token response looks well-formed.
pub fn validate_token_response(response: &AccessTokenResponse) -> SbiResult<()> {
    if response.access_token.is_empty() {
        return Err(SbiError::AuthorizationFailed(
            "Empty access token in response".into(),
        ));
    }
    if !response.token_type.eq_ignore_ascii_case("bearer") {
        return Err(SbiError::AuthorizationFailed(format!(
            "Unsupported token type: {}",
            response.token_type
        )));
    }
    Ok(())
}

/// Decode the three-part structure of a JWT access token.
/// Returns (header, payload, signature) as raw bytes.
/// This only checks structure — call [`verify_access_token`] (or
/// [`verify_access_token_with_jwks`]) to cryptographically verify the signature.
pub fn decode_jwt_parts(token: &str) -> SbiResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(SbiError::AuthorizationFailed(
            "Access token is not a valid JWT (expected 3 dot-separated parts)".into(),
        ));
    }

    let header = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| SbiError::AuthorizationFailed(format!("Invalid JWT header: {e}")))?;
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| SbiError::AuthorizationFailed(format!("Invalid JWT payload: {e}")))?;
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| SbiError::AuthorizationFailed(format!("Invalid JWT signature: {e}")))?;

    Ok((header, payload, signature))
}

/// JWT claims expected in a 5G SBA access token (3GPP TS 29.510 Section 6.3.5.2.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Issuer (NRF NF Instance ID)
    pub iss: String,
    /// Subject (NF Instance ID of the NF service consumer)
    pub sub: String,
    /// Audience (NF type or NF Instance ID of the NF service producer)
    pub aud: serde_json::Value,
    /// Scope (space-delimited service names)
    pub scope: String,
    /// Expiration time (seconds since epoch)
    pub exp: u64,
}

/// Parses a single ES256 JWK (`kty=EC, crv=P-256`) into a P-256 verifying key.
pub fn parse_es256_jwk(jwk: &serde_json::Value) -> SbiResult<p256::ecdsa::VerifyingKey> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let err = |m: String| SbiError::AuthorizationFailed(format!("Invalid ES256 JWK: {m}"));
    if jwk.get("kty").and_then(|v| v.as_str()) != Some("EC")
        || jwk.get("crv").and_then(|v| v.as_str()) != Some("P-256")
    {
        return Err(err("expected kty=EC, crv=P-256".into()));
    }
    let x_b64 = jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err("missing x".into()))?;
    let y_b64 = jwk
        .get("y")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err("missing y".into()))?;
    let x = URL_SAFE_NO_PAD
        .decode(x_b64)
        .map_err(|e| err(format!("x: {e}")))?;
    let y = URL_SAFE_NO_PAD
        .decode(y_b64)
        .map_err(|e| err(format!("y: {e}")))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(err("x/y must each be 32 bytes".into()));
    }
    let point = p256::EncodedPoint::from_affine_coordinates(
        p256::FieldBytes::from_slice(&x),
        p256::FieldBytes::from_slice(&y),
        false,
    );
    p256::ecdsa::VerifyingKey::from_encoded_point(&point)
        .map_err(|e| err(format!("not a valid public key: {e}")))
}

/// Verifies an ES256 access token against a public key and returns its claims.
///
/// Checks: `alg=ES256`, the ECDSA signature over `header.payload`, and that the
/// token has not expired (`exp`). This is the verification that was previously
/// missing — [`decode_jwt_parts`] only checks structure.
pub fn verify_access_token(
    token: &str,
    key: &p256::ecdsa::VerifyingKey,
) -> SbiResult<AccessTokenClaims> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::ecdsa::signature::Verifier;

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(SbiError::AuthorizationFailed(
            "Access token is not a valid JWT".into(),
        ));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| SbiError::AuthorizationFailed(format!("Invalid JWT header: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| SbiError::AuthorizationFailed(format!("Invalid JWT header JSON: {e}")))?;
    if header.get("alg").and_then(|v| v.as_str()) != Some("ES256") {
        return Err(SbiError::AuthorizationFailed(
            "token alg is not ES256".into(),
        ));
    }

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| SbiError::AuthorizationFailed(format!("Invalid JWT signature: {e}")))?;
    let signature = p256::ecdsa::Signature::from_slice(&sig_bytes)
        .map_err(|e| SbiError::AuthorizationFailed(format!("Malformed ES256 signature: {e}")))?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    key.verify(signing_input.as_bytes(), &signature)
        .map_err(|_| SbiError::AuthorizationFailed("token signature verification failed".into()))?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| SbiError::AuthorizationFailed(format!("Invalid JWT payload: {e}")))?;
    let claims: AccessTokenClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| SbiError::AuthorizationFailed(format!("Invalid token claims: {e}")))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if claims.exp <= now {
        return Err(SbiError::AuthorizationFailed(
            "access token has expired".into(),
        ));
    }
    Ok(claims)
}

/// Error detail emitted when a token's `kid` has no match in the JWKS.
/// [`JwksCache::authorize`] keys its refresh-on-rotation retry off this text.
const KID_MISMATCH_MSG: &str = "no JWKS key matches token kid";

/// Verifies an access token against a JWKS document (as published by the NRF at
/// `/nnrf-oauth2/v1/jwks`), selecting the key by the token header's `kid` (or
/// the sole key when the header carries no `kid`).
pub fn verify_access_token_with_jwks(
    token: &str,
    jwks: &serde_json::Value,
) -> SbiResult<AccessTokenClaims> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(SbiError::AuthorizationFailed(
            "Access token is not a valid JWT".into(),
        ));
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| SbiError::AuthorizationFailed(format!("Invalid JWT header: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| SbiError::AuthorizationFailed(format!("Invalid JWT header JSON: {e}")))?;
    let want_kid = header.get("kid").and_then(|v| v.as_str());

    let keys = jwks
        .get("keys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| SbiError::AuthorizationFailed("JWKS has no 'keys' array".into()))?;
    let jwk = keys
        .iter()
        .find(|k| match want_kid {
            Some(kid) => k.get("kid").and_then(|v| v.as_str()) == Some(kid),
            None => true,
        })
        .ok_or_else(|| SbiError::AuthorizationFailed(KID_MISMATCH_MSG.into()))?;

    let key = parse_es256_jwk(jwk)?;
    verify_access_token(token, &key)
}

/// Extracts the bearer token from an `Authorization` header value and verifies
/// it against the JWKS. A missing or non-`Bearer` header is an authorization
/// failure. Used by the SBI server to enforce OAuth2 on incoming requests.
pub fn authorize_bearer(
    auth_header: Option<&str>,
    jwks: &serde_json::Value,
) -> SbiResult<AccessTokenClaims> {
    authorize_bearer_aud(auth_header, jwks, None)
}

/// Like [`authorize_bearer`], but additionally validates the token's `aud`
/// (audience) claim when `expected_audience` is `Some` (RFC 7519 §4.1.3,
/// TS 33.501 §13.4.1.2). `None` skips the audience check, preserving
/// [`authorize_bearer`]'s behaviour.
pub fn authorize_bearer_aud(
    auth_header: Option<&str>,
    jwks: &serde_json::Value,
    expected_audience: Option<&str>,
) -> SbiResult<AccessTokenClaims> {
    let token = auth_header
        .and_then(|h| {
            h.strip_prefix("Bearer ")
                .or_else(|| h.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| SbiError::AuthorizationFailed("missing or malformed Bearer token".into()))?;
    let claims = verify_access_token_with_jwks(token, jwks)?;
    if let Some(expected) = expected_audience {
        check_audience(&claims.aud, expected)?;
    }
    Ok(claims)
}

/// Validate that a token's `aud` claim includes `expected`.
///
/// Per RFC 7519 §4.1.3 the `aud` claim is either a single string or an array
/// of strings; in 5G SBA (TS 29.510 §6.3.5.2.4) the NRF sets it to the target
/// NF's type or NF Instance ID. The token is accepted when any audience entry
/// equals `expected`. Returns `AuthorizationFailed` otherwise so the SBI
/// server maps it to 401.
pub fn check_audience(aud: &serde_json::Value, expected: &str) -> SbiResult<()> {
    let matches = match aud {
        serde_json::Value::String(s) => s == expected,
        serde_json::Value::Array(items) => items
            .iter()
            .any(|v| v.as_str().map(|s| s == expected).unwrap_or(false)),
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(SbiError::AuthorizationFailed(format!(
            "token audience {aud} does not include expected audience '{expected}'"
        )))
    }
}

/// Verify that a token's space-delimited `scope` claim authorizes the invoked
/// SBI service.
///
/// TS 33.501 §13.4.1.2 / TS 29.510 §5.4.2.2.2: the NRF issues a token whose
/// `scope` lists the service name(s) the consumer is authorized to invoke on
/// the producer; the producer must reject a request whose service is not among
/// them. `required` is the invoked service name (apiName, e.g. `nudm-sdm`); the
/// token is accepted when its scope contains that exact entry. Returns
/// `AuthorizationFailed` (→ 401) otherwise.
pub fn check_token_scope(scope_claim: &str, required: &str) -> SbiResult<()> {
    if scope_claim.split_whitespace().any(|s| s == required) {
        Ok(())
    } else {
        Err(SbiError::AuthorizationFailed(format!(
            "token scope '{scope_claim}' does not authorize the requested service '{required}'"
        )))
    }
}

// ============================================================================
// OAuth2 Client (Token exchange with NRF)
// ============================================================================

/// OAuth2 client for requesting tokens from the NRF (Authorization Server).
///
/// Implements the NF service consumer side of the client credentials grant
/// flow per 3GPP TS 29.510. Handles token requests, caching with automatic
/// expiry, and token refresh.
pub struct OAuth2Client {
    /// NRF URI (e.g., "http://127.0.0.10:7777")
    nrf_uri: String,
    /// This NF's instance ID
    nf_instance_id: String,
    /// This NF's type
    nf_type: NfType,
    /// Token cache
    cache: TokenCache,
    /// TLS connector used for `https://` NRF URIs; `None` keeps the cleartext
    /// `http://` path unchanged (the connector is consulted only for `https`).
    tls: Option<TlsConnector>,
    /// Resource path (appended to `nrf_uri`) of the NRF access-token endpoint
    /// (sbi-06). [`OAuth2Client::new`] seeds this from
    /// [`OAuth2Client::default_token_path`], which honours the process-wide
    /// selector (I4): the standard [`OAuth2Client::TOKEN_PATH_STANDARD`] when
    /// [`oauth2_standard_paths_default`] is on, else the bespoke
    /// [`OAuth2Client::TOKEN_PATH_BESPOKE`]. Override per instance with
    /// [`OAuth2Client::with_token_path`].
    token_path: String,
    /// ES256 key this NF signs its Client Credentials Assertion with (issue #64
    /// gaps 1 and 2). Seeded from the process-wide
    /// [`cca_signing_key_default`]; override per instance with
    /// [`OAuth2Client::with_cca_signing_key`]. `None` sends token requests with
    /// no assertion, which an NRF running its default policy rejects.
    cca_signing_key: Option<Arc<p256::ecdsa::SigningKey>>,
}

impl OAuth2Client {
    /// Bespoke (Open5GS-style) access-token path — the **default**, kept until
    /// the nrfd consumer is migrated to the standard path (sbi-06).
    pub const TOKEN_PATH_BESPOKE: &'static str = "/nnrf-oauth2/v1/access-token";
    /// TS 29.510 §5.4 / clause 6.3 standard access-token path
    /// (`POST {nrfApiRoot}/oauth2/token`). Opt in with
    /// [`OAuth2Client::with_token_path`].
    pub const TOKEN_PATH_STANDARD: &'static str = "/oauth2/token";

    /// The access-token resource path a freshly-built client uses by default,
    /// per the process-wide selector (I4, [`oauth2_standard_paths_default`]):
    /// the TS 29.510 [`TOKEN_PATH_STANDARD`](Self::TOKEN_PATH_STANDARD) when the
    /// standard-paths flag is on, else the bespoke
    /// [`TOKEN_PATH_BESPOKE`](Self::TOKEN_PATH_BESPOKE).
    pub fn default_token_path() -> &'static str {
        if oauth2_standard_paths_default() {
            Self::TOKEN_PATH_STANDARD
        } else {
            Self::TOKEN_PATH_BESPOKE
        }
    }

    /// Create a new OAuth2 client. Its access-token path defaults to
    /// [`OAuth2Client::default_token_path`] (the process-wide selector, I4);
    /// override per instance with [`OAuth2Client::with_token_path`].
    pub fn new(
        nrf_uri: impl Into<String>,
        nf_instance_id: impl Into<String>,
        nf_type: NfType,
    ) -> Self {
        Self {
            nrf_uri: nrf_uri.into(),
            nf_instance_id: nf_instance_id.into(),
            nf_type,
            cache: TokenCache::new(),
            tls: None,
            token_path: Self::default_token_path().to_string(),
            cca_signing_key: cca_signing_key_default(),
        }
    }

    /// Sign this client's access-token requests with `key`, overriding the
    /// process-wide [`cca_signing_key_default`].
    ///
    /// The NRF verifies the assertion against the PUBLIC half, which it must
    /// hold under `nrf.sbi.oauth2.cca_trusted_keys` keyed by this NF's
    /// `nfInstanceId`; an issuer with no trusted key there is rejected
    /// fail-closed.
    pub fn with_cca_signing_key(mut self, key: Arc<p256::ecdsa::SigningKey>) -> Self {
        self.cca_signing_key = Some(key);
        self
    }

    /// Send access-token requests WITHOUT a Client Credentials Assertion, even
    /// when one is configured process-wide. An NRF running its default policy
    /// rejects such a request with `invalid_client`.
    pub fn without_cca(mut self) -> Self {
        self.cca_signing_key = None;
        self
    }

    /// Whether this client can authenticate itself to the NRF token endpoint.
    pub fn has_cca_signing_key(&self) -> bool {
        self.cca_signing_key.is_some()
    }

    /// Mint the Client Credentials Assertion for a token request, when a signing
    /// key is configured. `aud` is the receiving NF's type, `"NRF"` for the
    /// access-token endpoint (TS 33.501 §13.3.8.3: the NRF checks the audience
    /// against its own NF type).
    fn build_cca(&self) -> Option<String> {
        let key = self.cca_signing_key.as_ref()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Some(mint_cca(
            key,
            &self.nf_instance_id,
            NfType::Nrf.to_str(),
            now,
            CCA_DEFAULT_LIFETIME_SECS,
        ))
    }

    /// Override the access-token resource path (sbi-06). The default is the
    /// bespoke [`OAuth2Client::TOKEN_PATH_BESPOKE`]; pass
    /// [`OAuth2Client::TOKEN_PATH_STANDARD`] (or a custom path) to address an
    /// NRF that serves the TS 29.510 standard route. Leading slash expected.
    pub fn with_token_path(mut self, token_path: impl Into<String>) -> Self {
        self.token_path = token_path.into();
        self
    }

    /// The configured access-token resource path.
    pub fn token_path(&self) -> &str {
        &self.token_path
    }

    /// Enable TLS for `https://` NRF URIs. Default off (`None`) ⇒ the
    /// `http://` path is byte-for-byte unchanged; the connector is consulted
    /// only when the NRF URI scheme is `https`.
    pub fn with_tls(mut self, connector: TlsConnector) -> Self {
        self.tls = Some(connector);
        self
    }

    /// Convenience: enable TLS with a default server-auth (webpki-roots)
    /// connector. Use [`OAuth2Client::with_tls`] to supply a private-CA or
    /// mTLS connector instead.
    ///
    /// ```no_run
    /// # async fn f() -> nextgcore_sbi::SbiResult<()> {
    /// use nextgcore_sbi::oauth::OAuth2Client;
    /// use nextgcore_sbi::types::NfType;
    /// let c = OAuth2Client::new("https://nrf:7777", "amf-1", NfType::Amf).with_default_tls()?;
    /// # let _ = c; Ok(()) }
    /// ```
    pub fn with_default_tls(self) -> SbiResult<Self> {
        let cfg = crate::tls::build_client_config(None, false)?;
        Ok(self.with_tls(TlsConnector::from(Arc::new(cfg))))
    }

    /// Get the NRF URI.
    pub fn nrf_uri(&self) -> &str {
        &self.nrf_uri
    }

    /// Get a valid access token for the given target NF type and scope.
    ///
    /// Returns a cached token if available and not expired, otherwise
    /// requests a new one from the NRF.
    pub async fn get_token(&self, target_nf_type: NfType, scope: &str) -> SbiResult<String> {
        // Check cache first
        if let Some(cached) = self.cache.get(target_nf_type, scope).await {
            return Ok(cached.access_token);
        }

        // Request new token from NRF
        let response = self.request_token(target_nf_type, scope).await?;
        let token = response.access_token.clone();

        // Cache it
        self.cache.put(target_nf_type, scope, response).await;

        Ok(token)
    }

    /// Request a new access token from the NRF.
    pub async fn request_token(
        &self,
        target_nf_type: NfType,
        scope: &str,
    ) -> SbiResult<AccessTokenResponse> {
        let mut request =
            AccessTokenRequest::new(&self.nf_instance_id, self.nf_type, target_nf_type, scope);
        // Issue #64 gaps 1+2: authenticate this NF to the token endpoint. Absent
        // a CCA (and absent a client certificate the NRF can see) the NRF has
        // only the self-asserted nfInstanceId in the body to go on.
        request.cca = self.build_cca();

        let body = request.to_form_body();
        // sbi-06/I4: the resource path is configurable; the process-wide
        // selector defaults it (bespoke `/nnrf-oauth2/v1/access-token` unless
        // the standard-paths flag is on) so the wire request is unchanged until
        // the NRF is migrated to the TS 29.510 standard path.
        let uri = format!("{}{}", self.nrf_uri, self.token_path);

        // Cleartext for `http://`, TLS for `https://` (scheme-branched).
        let mut sender = http2_connect(
            &self.nrf_uri,
            self.tls.as_ref(),
            "OAuth2 HTTP/2 connection error",
        )
        .await?;

        let http_request = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(&uri)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(http_body_util::Full::new(bytes::Bytes::from(body)))
            .map_err(|e| SbiError::ClientError(e.to_string()))?;

        let response =
            tokio::time::timeout(Duration::from_secs(10), sender.send_request(http_request))
                .await
                .map_err(|_| SbiError::Timeout)?
                .map_err(|e| SbiError::HyperError(e.to_string()))?;

        let status = response.status().as_u16();
        let body_bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .map_err(|e| SbiError::InvalidResponse(e.to_string()))?
            .to_bytes();

        if status != 200 {
            let error_body = String::from_utf8_lossy(&body_bytes);
            return Err(SbiError::AuthorizationFailed(format!(
                "NRF token request failed (HTTP {status}): {error_body}"
            )));
        }

        let token_response: AccessTokenResponse = serde_json::from_slice(&body_bytes)
            .map_err(|e| SbiError::AuthorizationFailed(format!("Invalid token response: {e}")))?;

        validate_token_response(&token_response)?;
        Ok(token_response)
    }

    /// Invalidate all cached tokens.
    pub async fn clear_cache(&self) {
        self.cache.clear().await;
    }

    /// Purge expired tokens from the cache.
    pub async fn purge_expired(&self) {
        self.cache.purge_expired().await;
    }

    /// Build an Authorization header value for the given target.
    pub async fn authorization_header(
        &self,
        target_nf_type: NfType,
        scope: &str,
    ) -> SbiResult<String> {
        let token = self.get_token(target_nf_type, scope).await?;
        Ok(format!("Bearer {token}"))
    }
}

/// Parse a URI like "http://host:port" into "host:port" for TCP connection.
fn parse_uri_to_addr(uri: &str) -> SbiResult<String> {
    let without_scheme = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);
    if host_port.is_empty() {
        return Err(SbiError::InvalidUri("Empty NRF URI".into()));
    }
    Ok(host_port.to_string())
}

/// Scheme test that decides whether a connection uses TLS. The sole TLS
/// trigger, kept pure so it is unit-testable without sockets.
#[inline]
fn uri_is_https(uri: &str) -> bool {
    uri.starts_with("https://")
}

/// Open an HTTP/2 connection to the authority in `uri` and return its request
/// sender.
///
/// * `http://`  → cleartext h2c (prior knowledge), byte-for-byte identical to
///   the previous inline connect code: no TLS, no ALPN. The `tls` connector is
///   ignored for this scheme.
/// * `https://` → a rustls TLS 1.2/1.3 handshake (ALPN `h2`) then HTTP/2, using
///   the supplied `tls` connector or, when `None`, a default webpki-roots
///   server-auth connector (secure by default).
///
/// `conn_label` names the spawned connection-driver error log so each call
/// site preserves its original message text.
async fn http2_connect(
    uri: &str,
    tls: Option<&TlsConnector>,
    conn_label: &'static str,
) -> SbiResult<hyper::client::conn::http2::SendRequest<http_body_util::Full<bytes::Bytes>>> {
    let addr = parse_uri_to_addr(uri)?;
    let stream = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| SbiError::Timeout)?
    .map_err(|e| SbiError::ConnectionError(e.to_string()))?;

    if uri_is_https(uri) {
        let connector = match tls {
            Some(c) => c.clone(),
            None => TlsConnector::from(Arc::new(crate::tls::build_client_config(None, false)?)),
        };
        let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(&addr);
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| SbiError::TlsError(format!("Invalid server name: {e}")))?;
        let tls_stream = tokio::time::timeout(
            Duration::from_secs(5),
            connector.connect(server_name, stream),
        )
        .await
        .map_err(|_| SbiError::Timeout)?
        .map_err(|e| SbiError::TlsError(format!("TLS handshake failed: {e}")))?;
        let io = hyper_util::rt::TokioIo::new(tls_stream);
        let (sender, conn) =
            hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
                .await
                .map_err(|e| SbiError::ConnectionError(e.to_string()))?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                log::error!("{conn_label} (TLS): {e}");
            }
        });
        Ok(sender)
    } else {
        // Cleartext h2c — byte-for-byte the previous inline connect code.
        let io = hyper_util::rt::TokioIo::new(stream);
        let (sender, conn) =
            hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
                .await
                .map_err(|e| SbiError::ConnectionError(e.to_string()))?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                log::error!("{conn_label}: {e}");
            }
        });
        Ok(sender)
    }
}

/// Percent-encoding for `application/x-www-form-urlencoded` values.
///
/// Issue #101: was a local copy. It now delegates to the shared encoder, which
/// keeps the form encoding (space -> `+`) DISTINCT from the RFC 3986 query
/// encoding (space -> `%20`) rather than merging them -- the two are not
/// interchangeable, and this is the form-body surface. See
/// [`crate::uri_encode`].
fn url_encode(s: &str) -> String {
    crate::uri_encode::encode_form_value(s)
}

// ============================================================================
// JWKS client (auth stage 4b): fetch + cache the NRF's public keys
// ============================================================================

/// Fetches and caches the NRF's JWKS so an SBI server can verify access
/// tokens without a key provisioned at startup.
///
/// The document is fetched lazily on first use and reused until `ttl`
/// expires. When a token carries a `kid` that is not in the cached document
/// (NRF key rotation or restart), [`JwksCache::authorize`] re-fetches once
/// before rejecting. The fetch speaks cleartext HTTP/2 (h2c prior knowledge)
/// for `http://` JWKS URIs; enable TLS for `https://` URIs with
/// [`JwksCache::with_tls`] / [`JwksCache::with_default_tls`].
pub struct JwksCache {
    /// Full JWKS URI, e.g. `http://nrf:7777/nnrf-oauth2/v1/jwks`.
    jwks_uri: String,
    /// Cached document and the instant it was fetched.
    cached: RwLock<Option<(serde_json::Value, Instant)>>,
    /// How long a fetched document is reused before re-fetching.
    ttl: Duration,
    /// TLS connector for `https://` JWKS URIs; `None` keeps the cleartext
    /// `http://` path unchanged.
    tls: Option<TlsConnector>,
}

impl JwksCache {
    /// Default reuse window for a fetched JWKS document.
    pub const DEFAULT_TTL: Duration = Duration::from_secs(300);
    /// Bespoke (Open5GS-style) JWKS endpoint path — the **default** used by
    /// [`JwksCache::for_nrf`], kept until the nrfd consumer is migrated
    /// (sbi-06).
    pub const NRF_JWKS_PATH: &'static str = "/nnrf-oauth2/v1/jwks";
    /// TS 29.510 standard key-retrieval path
    /// (`POST {nrfApiRoot}/oauth2/retrieve-key`). Opt in via
    /// [`JwksCache::for_nrf_with_path`].
    pub const NRF_KEY_PATH_STANDARD: &'static str = "/oauth2/retrieve-key";

    /// The NRF key-retrieval resource path [`JwksCache::for_nrf`] uses by
    /// default, per the process-wide selector (I4,
    /// [`oauth2_standard_paths_default`]): the TS 29.510
    /// [`NRF_KEY_PATH_STANDARD`](Self::NRF_KEY_PATH_STANDARD) when the
    /// standard-paths flag is on, else the bespoke
    /// [`NRF_JWKS_PATH`](Self::NRF_JWKS_PATH).
    pub fn default_key_path() -> &'static str {
        if oauth2_standard_paths_default() {
            Self::NRF_KEY_PATH_STANDARD
        } else {
            Self::NRF_JWKS_PATH
        }
    }

    /// Create a cache for an explicit JWKS URI.
    pub fn new(jwks_uri: impl Into<String>) -> Self {
        Self {
            jwks_uri: jwks_uri.into(),
            cached: RwLock::new(None),
            ttl: Self::DEFAULT_TTL,
            tls: None,
        }
    }

    /// Create a cache pointing at the NRF's key endpoint, using
    /// [`JwksCache::default_key_path`] — the process-wide selector (I4): the
    /// standard TS 29.510 `/oauth2/retrieve-key` when
    /// [`oauth2_standard_paths_default`] is on, else the bespoke
    /// [`JwksCache::NRF_JWKS_PATH`]. Use [`JwksCache::for_nrf_with_path`] to
    /// pin an explicit path regardless of the selector.
    pub fn for_nrf(nrf_uri: &str) -> Self {
        Self::for_nrf_with_path(nrf_uri, Self::default_key_path())
    }

    /// Create a cache pointing at the NRF, with an explicit key resource path
    /// (sbi-06). Pass [`JwksCache::NRF_KEY_PATH_STANDARD`] for the TS 29.510
    /// route, or [`JwksCache::NRF_JWKS_PATH`] (the [`for_nrf`](Self::for_nrf)
    /// default) for the bespoke one.
    pub fn for_nrf_with_path(nrf_uri: &str, path: &str) -> Self {
        Self::new(format!("{}{}", nrf_uri.trim_end_matches('/'), path))
    }

    /// Override the cache TTL.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Enable TLS for an `https://` JWKS URI. Default off; the connector is
    /// consulted only when the JWKS URI scheme is `https`, so an `http://`
    /// cache is unaffected.
    pub fn with_tls(mut self, connector: TlsConnector) -> Self {
        self.tls = Some(connector);
        self
    }

    /// Convenience: enable TLS with a default server-auth (webpki-roots)
    /// connector.
    pub fn with_default_tls(self) -> SbiResult<Self> {
        let cfg = crate::tls::build_client_config(None, false)?;
        Ok(self.with_tls(TlsConnector::from(Arc::new(cfg))))
    }

    /// The JWKS URI this cache fetches from.
    pub fn jwks_uri(&self) -> &str {
        &self.jwks_uri
    }

    /// Return the cached document, fetching it if absent or expired.
    pub async fn get(&self) -> SbiResult<serde_json::Value> {
        if let Some((doc, fetched_at)) = self.cached.read().await.as_ref() {
            if fetched_at.elapsed() < self.ttl {
                return Ok(doc.clone());
            }
        }
        self.refresh().await
    }

    /// Force a re-fetch, replacing the cached document on success.
    pub async fn refresh(&self) -> SbiResult<serde_json::Value> {
        let doc = fetch_jwks_with(&self.jwks_uri, self.tls.as_ref()).await?;
        *self.cached.write().await = Some((doc.clone(), Instant::now()));
        Ok(doc)
    }

    /// Seed the cache without fetching (static provisioning / tests).
    pub async fn seed(&self, jwks: serde_json::Value) {
        *self.cached.write().await = Some((jwks, Instant::now()));
    }

    /// Verify an `Authorization` header against the cached JWKS.
    ///
    /// On a `kid` miss the document is re-fetched once and verification
    /// retried, so a rotated NRF key does not lock out fresh tokens for a
    /// full TTL. Fetch failures surface as non-`AuthorizationFailed` errors
    /// so callers can distinguish "bad token" (401) from "keys unavailable"
    /// (503).
    pub async fn authorize(&self, auth_header: Option<&str>) -> SbiResult<AccessTokenClaims> {
        self.authorize_aud(auth_header, None).await
    }

    /// Like [`JwksCache::authorize`], but additionally validates the token's
    /// `aud` claim against `expected_audience` when `Some` (T1.2). The
    /// kid-rotation refresh-and-retry behaviour is preserved.
    pub async fn authorize_aud(
        &self,
        auth_header: Option<&str>,
        expected_audience: Option<&str>,
    ) -> SbiResult<AccessTokenClaims> {
        let jwks = self.get().await?;
        match authorize_bearer_aud(auth_header, &jwks, expected_audience) {
            Err(SbiError::AuthorizationFailed(msg)) if msg == KID_MISMATCH_MSG => {
                let fresh = self.refresh().await?;
                authorize_bearer_aud(auth_header, &fresh, expected_audience)
            }
            other => other,
        }
    }
}

/// Fetch a JWKS document and validate its shape, using TLS for `https://`
/// URIs and cleartext HTTP/2 for `http://`. `tls = None` uses a default
/// webpki-roots connector for `https` (and is ignored for `http`).
pub async fn fetch_jwks_with(
    jwks_uri: &str,
    tls: Option<&TlsConnector>,
) -> SbiResult<serde_json::Value> {
    let mut sender = http2_connect(jwks_uri, tls, "JWKS HTTP/2 connection error").await?;

    let http_request = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(jwks_uri)
        .body(http_body_util::Full::new(bytes::Bytes::new()))
        .map_err(|e| SbiError::ClientError(e.to_string()))?;

    let response = tokio::time::timeout(Duration::from_secs(10), sender.send_request(http_request))
        .await
        .map_err(|_| SbiError::Timeout)?
        .map_err(|e| SbiError::HyperError(e.to_string()))?;

    let status = response.status().as_u16();
    let body_bytes = http_body_util::BodyExt::collect(response.into_body())
        .await
        .map_err(|e| SbiError::InvalidResponse(e.to_string()))?
        .to_bytes();

    if status != 200 {
        return Err(SbiError::HttpError {
            status,
            message: format!(
                "JWKS fetch failed: {}",
                String::from_utf8_lossy(&body_bytes)
            ),
        });
    }

    let doc: serde_json::Value = serde_json::from_slice(&body_bytes)
        .map_err(|e| SbiError::InvalidResponse(format!("Invalid JWKS JSON: {e}")))?;
    if doc.get("keys").and_then(|k| k.as_array()).is_none() {
        return Err(SbiError::InvalidResponse(
            "JWKS document has no 'keys' array".into(),
        ));
    }
    Ok(doc)
}

/// Fetch a JWKS document: cleartext HTTP/2 for `http://`, default TLS for
/// `https://`. Back-compat wrapper over [`fetch_jwks_with`].
pub async fn fetch_jwks(jwks_uri: &str) -> SbiResult<serde_json::Value> {
    fetch_jwks_with(jwks_uri, None).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes every test that reads or mutates the process-wide default
    /// OAuth2 path selector (I4) so a parallel flip cannot perturb a
    /// default-asserting test. Poison-tolerant so one panicking test does not
    /// cascade-fail the rest.
    static PATH_MODE_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_path_mode() -> std::sync::MutexGuard<'static, ()> {
        let g = PATH_MODE_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        // Clear any override leaked by a previously-panicked guarded test so we
        // start from the shipped (env-driven) baseline.
        reset_oauth2_standard_paths_default();
        g
    }

    /// Same treatment for the process-wide CCA signing key (issue #64): tests
    /// that flip it must not perturb one asserting the default.
    static CCA_KEY_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_cca_key() -> std::sync::MutexGuard<'static, ()> {
        let g = CCA_KEY_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        reset_cca_signing_key();
        g
    }

    /// Issue #64 gaps 1+2: `mint_cca` must produce exactly the assertion the NRF
    /// validates — ES256 header, `sub == iss == nfInstanceId`, `aud` = the
    /// receiving NF type, `iat`/`exp` present — and its signature must verify
    /// against the public half.
    ///
    /// If this drifts, every NF silently loses the ability to authenticate to the
    /// token endpoint and the NRF's default policy refuses them all.
    #[test]
    fn mint_cca_is_verifiable_and_carries_the_claims_the_nrf_checks() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use p256::ecdsa::signature::Verifier;

        let key = generate_es256_key();
        let now = 1_700_000_000u64;
        let cca = mint_cca(&key, "amf-1", "NRF", now, CCA_DEFAULT_LIFETIME_SECS);

        let parts: Vec<&str> = cca.split('.').collect();
        assert_eq!(parts.len(), 3, "a CCA is a three-part JWS");

        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).expect("header b64"))
                .expect("header JSON");
        assert_eq!(
            header["alg"], "ES256",
            "the NRF rejects any other alg, `none` included"
        );

        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).expect("payload b64"))
                .expect("claims JSON");
        assert_eq!(claims["sub"], "amf-1");
        assert_eq!(claims["iss"], "amf-1", "the assertion is self-issued");
        assert_eq!(claims["aud"], "NRF", "audience is the receiving NF's TYPE");
        assert_eq!(claims["iat"], now);
        assert_eq!(claims["exp"], now + CCA_DEFAULT_LIFETIME_SECS);

        // The signature covers `header.payload` and verifies with the public key.
        let sig = p256::ecdsa::Signature::from_slice(
            &URL_SAFE_NO_PAD.decode(parts[2]).expect("signature b64"),
        )
        .expect("64-byte r||s");
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        key.verifying_key()
            .verify(signing_input.as_bytes(), &sig)
            .expect("the CCA signature must verify against the public key");

        // A tampered payload must not verify — the whole point of signing it.
        let tampered = format!("{}.{}", parts[0], URL_SAFE_NO_PAD.encode(br#"{"sub":"x"}"#));
        assert!(key
            .verifying_key()
            .verify(tampered.as_bytes(), &sig)
            .is_err());
    }

    /// Issue #64 gaps 1+2: a configured signing key puts a `cca` on the wire, and
    /// no key leaves the request unauthenticated.
    #[test]
    fn token_request_carries_a_cca_only_when_a_key_is_configured() {
        let key = Arc::new(generate_es256_key());

        // Per-instance key (no process-global state touched).
        let with_key = OAuth2Client::new("http://nrf:7777", "amf-1", NfType::Amf)
            .with_cca_signing_key(key.clone());
        assert!(with_key.has_cca_signing_key());
        let cca = with_key.build_cca().expect("a key means an assertion");
        let mut req = AccessTokenRequest::new("amf-1", NfType::Amf, NfType::Udm, "nudm-sdm");
        req.cca = Some(cca);
        let body = req.to_form_body();
        assert!(body.contains("cca="), "the CCA must reach the wire: {body}");
        // Still a well-formed form body alongside the mandatory parameters.
        assert!(body.contains("grant_type=client_credentials"));
        assert!(body.contains("nfInstanceId=amf-1"));

        // No key -> no assertion, and no `cca` parameter at all (rather than an
        // empty one, which the NRF would read as "a CCA was presented").
        let without = OAuth2Client::new("http://nrf:7777", "amf-1", NfType::Amf).without_cca();
        assert!(!without.has_cca_signing_key());
        assert!(without.build_cca().is_none());
        let bare = AccessTokenRequest::new("amf-1", NfType::Amf, NfType::Udm, "nudm-sdm");
        assert!(!bare.to_form_body().contains("cca="));
    }

    /// Issue #64: the signing key is resolved PROCESS-WIDE so a deployment gains
    /// client authentication without editing any of the 16 `OAuth2Client::new`
    /// construction sites — a knob duplicated per daemon stays wrong in every one
    /// of them at once.
    #[test]
    fn cca_signing_key_is_resolved_process_wide() {
        let _g = lock_cca_key();

        // Baseline: no override, and (in the test environment) no env var.
        assert!(
            cca_signing_key_default().is_none() || std::env::var(CCA_SIGNING_KEY_FILE_ENV).is_ok(),
            "with no override and no env var, no assertion is sent"
        );

        let key = Arc::new(generate_es256_key());
        set_cca_signing_key(key.clone());
        assert_eq!(
            cca_signing_key_default().map(|k| k.to_bytes()),
            Some(key.to_bytes()),
            "the override is what every new client picks up"
        );
        // A freshly-constructed client inherits it with no per-NF wiring.
        assert!(OAuth2Client::new("http://nrf:7777", "amf-1", NfType::Amf).has_cca_signing_key());

        disable_cca_signing_key();
        assert!(
            cca_signing_key_default().is_none(),
            "an explicit disable beats the env var"
        );

        reset_cca_signing_key();
    }

    /// Issue #64: the shared ES256 key loader distinguishes ABSENT (create one)
    /// from INVALID (a human must look at it). Regenerating on a malformed file
    /// would invalidate every credential already issued under the old key — which
    /// for the NRF's signing key is precisely the gap-4 defect.
    #[test]
    fn load_or_create_es256_key_fails_on_invalid_and_creates_on_absent() {
        let dir = std::env::temp_dir().join(format!("sbi-cca-key-{}", std::process::id()));
        let path = dir.join("nested").join("cca.key");
        let _ = std::fs::remove_dir_all(&dir);

        // Absent -> created, including parent directories, and stable on reload.
        let first = load_or_create_es256_key(&path).expect("absent means create");
        assert!(path.exists());
        let second = load_or_create_es256_key(&path).expect("present means load");
        assert_eq!(
            first.to_bytes(),
            second.to_bytes(),
            "reloading must yield the identical key"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "a private key must not be world-readable"
            );
        }

        // Invalid -> error, never a silent replacement. Both shapes: unparseable,
        // and right-encoding-wrong-length (the likelier real corruption, e.g. a
        // truncated write or a partially-mounted secret).
        std::fs::write(&path, "not-hex").expect("write");
        assert!(load_or_create_es256_key(&path).is_err());
        std::fs::write(&path, "aabbcc").expect("write");
        assert!(load_or_create_es256_key(&path).is_err());
        // The file is left untouched, so an operator can still recover it.
        assert_eq!(
            std::fs::read_to_string(&path).expect("read").trim(),
            "aabbcc",
            "a failed load must not overwrite the file it could not parse"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_access_token_request_form_body() {
        let req = AccessTokenRequest::new(
            "nf-instance-123",
            NfType::Amf,
            NfType::Smf,
            "nsmf-pdusession",
        );
        let body = req.to_form_body();
        assert!(body.contains("grant_type=client_credentials"));
        assert!(body.contains("nfInstanceId=nf-instance-123"));
        assert!(body.contains("nfType=AMF"));
        assert!(body.contains("targetNfType=SMF"));
        assert!(body.contains("scope=nsmf-pdusession"));
    }

    #[test]
    fn test_access_token_response_serialization() {
        let response = AccessTokenResponse {
            access_token: "eyJhbGciOi.eyJpc3Mi.signature".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(3600),
            scope: Some("nsmf-pdusession".to_string()),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("Bearer"));
        assert!(json.contains("3600"));

        let parsed: AccessTokenResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.access_token, response.access_token);
    }

    #[test]
    fn test_validate_token_response_ok() {
        let response = AccessTokenResponse {
            access_token: "some-token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(3600),
            scope: None,
        };
        assert!(validate_token_response(&response).is_ok());
    }

    #[test]
    fn test_validate_token_response_empty_token() {
        let response = AccessTokenResponse {
            access_token: String::new(),
            token_type: "Bearer".to_string(),
            expires_in: None,
            scope: None,
        };
        assert!(validate_token_response(&response).is_err());
    }

    #[test]
    fn test_validate_token_response_bad_type() {
        let response = AccessTokenResponse {
            access_token: "some-token".to_string(),
            token_type: "MAC".to_string(),
            expires_in: None,
            scope: None,
        };
        assert!(validate_token_response(&response).is_err());
    }

    #[test]
    fn test_decode_jwt_parts() {
        // Build a simple JWT: header.payload.signature (base64url encoded)
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"RS256\"}");
        let payload = URL_SAFE_NO_PAD.encode(b"{\"sub\":\"test\"}");
        let sig = URL_SAFE_NO_PAD.encode(b"fakesig");

        let token = format!("{header}.{payload}.{sig}");
        let result = decode_jwt_parts(&token);
        assert!(result.is_ok());

        let (h, p, s) = result.unwrap();
        assert_eq!(h, b"{\"alg\":\"RS256\"}");
        assert_eq!(p, b"{\"sub\":\"test\"}");
        assert_eq!(s, b"fakesig");
    }

    #[test]
    fn test_decode_jwt_parts_invalid() {
        assert!(decode_jwt_parts("not-a-jwt").is_err());
        assert!(decode_jwt_parts("a.b").is_err());
    }

    #[tokio::test]
    async fn test_token_cache_basic() {
        let cache = TokenCache::new();

        // Nothing cached yet
        assert!(cache.get(NfType::Smf, "nsmf-pdusession").await.is_none());

        // Store a token
        let response = AccessTokenResponse {
            access_token: "cached-token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(3600),
            scope: Some("nsmf-pdusession".to_string()),
        };
        cache
            .put(NfType::Smf, "nsmf-pdusession", response.clone())
            .await;

        // Should be retrievable
        let cached = cache.get(NfType::Smf, "nsmf-pdusession").await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().access_token, "cached-token");

        // Different key should miss
        assert!(cache.get(NfType::Amf, "nsmf-pdusession").await.is_none());
        assert!(cache.get(NfType::Smf, "other-scope").await.is_none());
    }

    #[tokio::test]
    async fn test_token_cache_clear() {
        let cache = TokenCache::new();
        let response = AccessTokenResponse {
            access_token: "token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(3600),
            scope: None,
        };
        cache.put(NfType::Smf, "scope", response).await;
        assert!(cache.get(NfType::Smf, "scope").await.is_some());

        cache.clear().await;
        assert!(cache.get(NfType::Smf, "scope").await.is_none());
    }

    #[test]
    fn test_access_token_error_serialization() {
        let error = AccessTokenError {
            error: "invalid_scope".to_string(),
            error_description: Some("The requested scope is invalid".to_string()),
            error_uri: None,
        };

        let json = serde_json::to_string(&error).unwrap();
        let parsed: AccessTokenError = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.error, "invalid_scope");
    }

    #[test]
    fn test_access_token_claims_serialization() {
        let claims = AccessTokenClaims {
            iss: "nrf-instance-id".to_string(),
            sub: "amf-instance-id".to_string(),
            aud: serde_json::Value::String("SMF".to_string()),
            scope: "nsmf-pdusession".to_string(),
            exp: 1700000000,
        };

        let json = serde_json::to_string(&claims).unwrap();
        let parsed: AccessTokenClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.iss, "nrf-instance-id");
        assert_eq!(parsed.scope, "nsmf-pdusession");
    }

    #[test]
    fn test_url_encode() {
        assert_eq!(url_encode("hello"), "hello");
        assert_eq!(url_encode("hello world"), "hello+world");
        assert_eq!(url_encode("a=b&c=d"), "a%3Db%26c%3Dd");
    }

    #[test]
    fn test_parse_uri_to_addr() {
        assert_eq!(
            parse_uri_to_addr("http://127.0.0.10:7777").unwrap(),
            "127.0.0.10:7777"
        );
        assert_eq!(
            parse_uri_to_addr("https://nrf.local:443").unwrap(),
            "nrf.local:443"
        );
        assert_eq!(
            parse_uri_to_addr("http://nrf:7777/some/path").unwrap(),
            "nrf:7777"
        );
        assert!(parse_uri_to_addr("http://").is_err());
    }

    #[test]
    fn test_oauth2_client_creation() {
        let client = OAuth2Client::new("http://127.0.0.10:7777", "amf-instance-001", NfType::Amf);
        assert_eq!(client.nrf_uri(), "http://127.0.0.10:7777");
    }

    // --- ES256 access-token verification (NRF auth stage 3) ---

    fn build_es256_token(sk: &p256::ecdsa::SigningKey, kid: &str, exp: u64) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use p256::ecdsa::{signature::Signer, Signature};

        let header = format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{kid}"}}"#);
        let claims = serde_json::json!({
            "iss": "NRF", "sub": "amf-1", "aud": "UDM", "scope": "nudm-sdm", "exp": exp, "iat": 0
        })
        .to_string();
        let h = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let p = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let sig: Signature = sk.sign(format!("{h}.{p}").as_bytes());
        let s = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{h}.{p}.{s}")
    }

    fn jwks_for(sk: &p256::ecdsa::SigningKey, kid: &str) -> serde_json::Value {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let point = sk.verifying_key().to_encoded_point(false);
        serde_json::json!({"keys":[{
            "kty":"EC","crv":"P-256","use":"sig","alg":"ES256","kid":kid,
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        }]})
    }

    fn future_exp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600
    }

    #[test]
    fn test_verify_valid_token_against_jwks() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let token = build_es256_token(&sk, "nrf-es256", future_exp());
        let claims = verify_access_token_with_jwks(&token, &jwks_for(&sk, "nrf-es256"))
            .expect("valid token verifies");
        assert_eq!(claims.iss, "NRF");
        assert_eq!(claims.scope, "nudm-sdm");
    }

    #[test]
    fn test_verify_rejects_tampered_token() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let token = build_es256_token(&sk, "nrf-es256", future_exp());
        let jwks = jwks_for(&sk, "nrf-es256");
        let mut parts: Vec<&str> = token.split('.').collect();
        let tampered_payload = format!("{}x", parts[1]);
        parts[1] = tampered_payload.as_str();
        assert!(verify_access_token_with_jwks(&parts.join("."), &jwks).is_err());
    }

    #[test]
    fn test_verify_rejects_wrong_key() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let other = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let token = build_es256_token(&sk, "nrf-es256", future_exp());
        assert!(verify_access_token_with_jwks(&token, &jwks_for(&other, "nrf-es256")).is_err());
    }

    #[test]
    fn test_verify_rejects_expired_token() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let token = build_es256_token(&sk, "nrf-es256", 1); // exp in 1970
        let err = verify_access_token_with_jwks(&token, &jwks_for(&sk, "nrf-es256")).unwrap_err();
        assert!(format!("{err:?}").contains("expired"));
    }

    #[test]
    fn test_authorize_bearer_header() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let token = build_es256_token(&sk, "nrf-es256", future_exp());
        let jwks = jwks_for(&sk, "nrf-es256");

        // Valid "Bearer <token>" authorizes.
        let header = format!("Bearer {token}");
        assert!(authorize_bearer(Some(&header), &jwks).is_ok());

        // Missing header, non-bearer scheme, and a bad token are all rejected.
        assert!(authorize_bearer(None, &jwks).is_err());
        assert!(authorize_bearer(Some("Basic abc"), &jwks).is_err());
        assert!(authorize_bearer(Some("Bearer not.a.jwt"), &jwks).is_err());
    }

    // --- audience ('aud') validation (T1.2, RFC 7519 / TS 33.501 §13.4.1.2) ---

    #[test]
    fn test_check_audience_string_and_array() {
        // Single-string aud: exact match accepted, mismatch rejected.
        assert!(check_audience(&serde_json::json!("UDM"), "UDM").is_ok());
        assert!(check_audience(&serde_json::json!("UDM"), "AMF").is_err());

        // Array aud: accepted when any entry matches.
        let arr = serde_json::json!(["AMF", "UDM", "SMF"]);
        assert!(check_audience(&arr, "UDM").is_ok());
        assert!(check_audience(&arr, "PCF").is_err());

        // Non-string/array aud (malformed) is rejected.
        assert!(check_audience(&serde_json::json!(42), "UDM").is_err());
    }

    /// The fixed test token (see `build_es256_token`) has `aud == "UDM"`.
    #[test]
    fn test_authorize_bearer_aud_matching_accepted() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let token = build_es256_token(&sk, "nrf-es256", future_exp());
        let jwks = jwks_for(&sk, "nrf-es256");
        let header = format!("Bearer {token}");

        // Matching expected audience: accepted.
        let claims = authorize_bearer_aud(Some(&header), &jwks, Some("UDM"))
            .expect("matching aud authorizes");
        assert_eq!(claims.aud, serde_json::json!("UDM"));
    }

    #[test]
    fn test_authorize_bearer_aud_wrong_rejected() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let token = build_es256_token(&sk, "nrf-es256", future_exp());
        let jwks = jwks_for(&sk, "nrf-es256");
        let header = format!("Bearer {token}");

        // Wrong expected audience: rejected even though signature/exp are good.
        let err = authorize_bearer_aud(Some(&header), &jwks, Some("AMF")).unwrap_err();
        assert!(matches!(err, SbiError::AuthorizationFailed(_)));
    }

    #[test]
    fn test_authorize_bearer_aud_absent_expectation_skips() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let token = build_es256_token(&sk, "nrf-es256", future_exp());
        let jwks = jwks_for(&sk, "nrf-es256");
        let header = format!("Bearer {token}");

        // No expected audience: audience check skipped (prior behaviour).
        assert!(authorize_bearer_aud(Some(&header), &jwks, None).is_ok());
        // And plain authorize_bearer still works (delegates with None).
        assert!(authorize_bearer(Some(&header), &jwks).is_ok());
    }

    #[tokio::test]
    async fn test_jwks_cache_authorize_aud() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let cache = JwksCache::new("http://127.0.0.1:1/unused");
        cache.seed(jwks_for(&sk, "nrf-es256")).await;

        let token = build_es256_token(&sk, "nrf-es256", future_exp());
        let header = format!("Bearer {token}");

        // Matching aud through the cache path.
        assert!(cache
            .authorize_aud(Some(&header), Some("UDM"))
            .await
            .is_ok());
        // Wrong aud rejected.
        assert!(matches!(
            cache.authorize_aud(Some(&header), Some("AMF")).await,
            Err(SbiError::AuthorizationFailed(_))
        ));
        // No expectation skips.
        assert!(cache.authorize_aud(Some(&header), None).await.is_ok());
    }

    // --- JWKS fetch + cache (NRF auth stage 4b) ---

    /// Serve `jwks` on every request over cleartext HTTP/2 from an ephemeral
    /// local port.
    async fn serve_jwks(jwks: serde_json::Value) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let body = jwks.to_string();
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let svc = hyper::service::service_fn(move |_req| {
                        let body = body.clone();
                        async move {
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(
                                http_body_util::Full::new(bytes::Bytes::from(body)),
                            ))
                        }
                    });
                    let _ = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(io, svc)
                    .await;
                });
            }
        });
        addr
    }

    #[test]
    fn test_jwks_cache_uri_construction() {
        let _g = lock_path_mode(); // for_nrf honours the I4 selector; pin baseline
        assert_eq!(
            JwksCache::for_nrf("http://nrf:7777").jwks_uri(),
            "http://nrf:7777/nnrf-oauth2/v1/jwks"
        );
        assert_eq!(
            JwksCache::for_nrf("http://nrf:7777/").jwks_uri(),
            "http://nrf:7777/nnrf-oauth2/v1/jwks"
        );
    }

    #[tokio::test]
    async fn test_jwks_cache_seeded_authorize() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let cache = JwksCache::new("http://127.0.0.1:1/unused");
        cache.seed(jwks_for(&sk, "nrf-es256")).await;

        let token = build_es256_token(&sk, "nrf-es256", future_exp());
        let header = format!("Bearer {token}");
        assert!(cache.authorize(Some(&header)).await.is_ok());
        assert!(matches!(
            cache.authorize(Some("Bearer not.a.jwt")).await,
            Err(SbiError::AuthorizationFailed(_))
        ));
    }

    #[tokio::test]
    async fn test_fetch_jwks_live() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let addr = serve_jwks(jwks_for(&sk, "nrf-es256")).await;
        let doc = fetch_jwks(&format!("http://{addr}/nnrf-oauth2/v1/jwks"))
            .await
            .expect("live JWKS fetch succeeds");
        assert_eq!(doc["keys"][0]["kid"], "nrf-es256");
    }

    // --- sbi-01: TLS for OAuth2 token + JWKS over https:// ---

    #[test]
    fn test_uri_is_https_scheme_branch() {
        // The single TLS decision point.
        assert!(uri_is_https("https://nrf:7777/x"));
        assert!(!uri_is_https("http://nrf:7777/x"));
        assert!(!uri_is_https("nrf:7777"));
    }

    #[test]
    fn test_oauth2_client_tls_default_off() {
        let c = OAuth2Client::new("http://127.0.0.10:7777", "amf-1", NfType::Amf);
        assert!(c.tls.is_none());
    }

    #[test]
    fn test_jwks_cache_tls_default_off() {
        assert!(JwksCache::new("http://nrf:7777/jwks").tls.is_none());
        assert!(JwksCache::for_nrf("http://nrf:7777").tls.is_none());
    }

    #[tokio::test]
    async fn test_fetch_jwks_http_ignores_tls_connector() {
        // Load-bearing matched-sim guard: passing a real TLS connector to an
        // http:// URI must be a no-op — the cleartext path is taken and the
        // connector is never consulted, so the plaintext fetch still succeeds
        // (a TLS handshake against this plaintext h2c server would fail).
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let addr = serve_jwks(jwks_for(&sk, "nrf-es256")).await;
        let connector = TlsConnector::from(Arc::new(
            crate::tls::build_client_config(None, false).unwrap(),
        ));
        let doc = fetch_jwks_with(
            &format!("http://{addr}/nnrf-oauth2/v1/jwks"),
            Some(&connector),
        )
        .await
        .expect("http:// path ignores the TLS connector");
        assert_eq!(doc["keys"][0]["kid"], "nrf-es256");
    }

    /// Serve `jwks` over HTTP/2-in-TLS (self-signed "localhost" cert) from an
    /// ephemeral local port.
    async fn serve_jwks_tls(jwks: serde_json::Value) -> std::net::SocketAddr {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
        let server_config = crate::tls::build_server_config(vec![cert_der], key_der).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let body = jwks.to_string();
                tokio::spawn(async move {
                    let Ok(tls_stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let svc = hyper::service::service_fn(move |_req| {
                        let body = body.clone();
                        async move {
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(
                                http_body_util::Full::new(bytes::Bytes::from(body)),
                            ))
                        }
                    });
                    let _ = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(io, svc)
                    .await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_fetch_jwks_over_tls() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let addr = serve_jwks_tls(jwks_for(&sk, "nrf-es256")).await;
        // Self-signed server cert ⇒ an insecure client connector skips verify.
        let connector = TlsConnector::from(Arc::new(
            crate::tls::build_client_config(None, true).unwrap(),
        ));
        let doc = fetch_jwks_with(
            &format!("https://{addr}/nnrf-oauth2/v1/jwks"),
            Some(&connector),
        )
        .await
        .expect("https:// JWKS fetch over TLS succeeds");
        assert_eq!(doc["keys"][0]["kid"], "nrf-es256");
    }

    #[tokio::test]
    async fn test_jwks_cache_over_tls_with_connector() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let addr = serve_jwks_tls(jwks_for(&sk, "nrf-es256")).await;
        let connector = TlsConnector::from(Arc::new(
            crate::tls::build_client_config(None, true).unwrap(),
        ));
        let cache =
            JwksCache::new(format!("https://{addr}/nnrf-oauth2/v1/jwks")).with_tls(connector);
        let token = build_es256_token(&sk, "nrf-es256", future_exp());
        let claims = cache
            .authorize(Some(&format!("Bearer {token}")))
            .await
            .expect("TLS JWKS cache verifies a token");
        assert_eq!(claims.iss, "NRF");
    }

    #[tokio::test]
    async fn test_jwks_cache_lazy_fetch_and_authorize() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let addr = serve_jwks(jwks_for(&sk, "nrf-es256")).await;
        let cache = JwksCache::new(format!("http://{addr}/nnrf-oauth2/v1/jwks"));

        let token = build_es256_token(&sk, "nrf-es256", future_exp());
        let header = format!("Bearer {token}");
        let claims = cache
            .authorize(Some(&header))
            .await
            .expect("lazy fetch + verify succeeds");
        assert_eq!(claims.iss, "NRF");
    }

    #[tokio::test]
    async fn test_jwks_cache_refreshes_on_kid_rotation() {
        // The NRF rotated its key: the cache holds the old document, the
        // server publishes the new one, and a fresh token uses the new kid.
        let old_sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let new_sk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let addr = serve_jwks(jwks_for(&new_sk, "nrf-es256-v2")).await;

        let cache = JwksCache::new(format!("http://{addr}/nnrf-oauth2/v1/jwks"));
        cache.seed(jwks_for(&old_sk, "nrf-es256-v1")).await;

        let token = build_es256_token(&new_sk, "nrf-es256-v2", future_exp());
        let header = format!("Bearer {token}");
        let claims = cache
            .authorize(Some(&header))
            .await
            .expect("kid miss triggers refresh and the new key verifies");
        assert_eq!(claims.iss, "NRF");
    }

    #[tokio::test]
    async fn test_jwks_fetch_failure_is_not_authorization_failed() {
        // Nothing listens on the target: the error must be a transport
        // error, not AuthorizationFailed, so servers can answer 503 not 401.
        let cache = JwksCache::new("http://127.0.0.1:1/nnrf-oauth2/v1/jwks");
        let err = cache.authorize(Some("Bearer a.b.c")).await.unwrap_err();
        assert!(!matches!(err, SbiError::AuthorizationFailed(_)));
    }

    // --- sbi-06: configurable OAuth2 token + JWKS resource paths ---

    #[test]
    fn test_token_path_defaults_to_bespoke() {
        let _g = lock_path_mode(); // pin the I4 baseline (shipped: bespoke)
                                   // The default keeps the bespoke path so the wire request is unchanged
                                   // until the NRF is migrated to the TS 29.510 route.
        let c = OAuth2Client::new("http://nrf:7777", "amf-1", NfType::Amf);
        assert_eq!(c.token_path(), "/nnrf-oauth2/v1/access-token");
        assert_eq!(c.token_path(), OAuth2Client::TOKEN_PATH_BESPOKE);

        // Opt-in override to the standard TS 29.510 path.
        let c = c.with_token_path(OAuth2Client::TOKEN_PATH_STANDARD);
        assert_eq!(c.token_path(), "/oauth2/token");
    }

    #[test]
    fn test_jwks_path_default_and_standard() {
        let _g = lock_path_mode(); // pin the I4 baseline (shipped: bespoke)
                                   // Default `for_nrf` uses the bespoke path.
        assert_eq!(
            JwksCache::for_nrf("http://nrf:7777").jwks_uri(),
            "http://nrf:7777/nnrf-oauth2/v1/jwks"
        );
        // Opt-in to the TS 29.510 standard key-retrieval path.
        assert_eq!(
            JwksCache::for_nrf_with_path("http://nrf:7777", JwksCache::NRF_KEY_PATH_STANDARD)
                .jwks_uri(),
            "http://nrf:7777/oauth2/retrieve-key"
        );
    }

    /// Serve an access-token response only for `expected_path`; 404 otherwise.
    /// Lets a test assert which path the client actually requested on the wire.
    async fn serve_token_on_path(expected_path: &'static str) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let svc = hyper::service::service_fn(
                        move |req: hyper::Request<hyper::body::Incoming>| {
                            let path = req.uri().path().to_string();
                            async move {
                                let resp = if path == expected_path {
                                    hyper::Response::builder().status(200).body(
                                        http_body_util::Full::new(bytes::Bytes::from(
                                            r#"{"access_token":"tok","token_type":"Bearer","expires_in":3600}"#,
                                        )),
                                    )
                                } else {
                                    hyper::Response::builder()
                                        .status(404)
                                        .body(http_body_util::Full::new(bytes::Bytes::from("nope")))
                                };
                                Ok::<_, std::convert::Infallible>(resp.unwrap())
                            }
                        },
                    );
                    let _ = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(io, svc)
                    .await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_default_token_path_used_on_wire() {
        // A server that only answers the bespoke path → default client succeeds.
        let addr = serve_token_on_path("/nnrf-oauth2/v1/access-token").await;
        // The I4 selector is read at construction; hold the guard only over the
        // (synchronous) build to pin the bespoke baseline, then release before I/O.
        let client = {
            let _g = lock_path_mode();
            OAuth2Client::new(format!("http://{addr}"), "amf-1", NfType::Amf)
        };
        let resp = client
            .request_token(NfType::Udm, "nudm-sdm")
            .await
            .expect("default bespoke token path succeeds");
        assert_eq!(resp.access_token, "tok");
    }

    #[tokio::test]
    async fn test_standard_token_path_override_used_on_wire() {
        // A server that only answers the standard path → overridden client wins.
        let addr = serve_token_on_path("/oauth2/token").await;
        let client = OAuth2Client::new(format!("http://{addr}"), "amf-1", NfType::Amf)
            .with_token_path(OAuth2Client::TOKEN_PATH_STANDARD);
        let resp = client
            .request_token(NfType::Udm, "nudm-sdm")
            .await
            .expect("standard token path succeeds when configured");
        assert_eq!(resp.access_token, "tok");
    }

    // --- I4: flag-gated default OAuth2 resource paths (TS 29.510 §5.4) ---

    #[test]
    fn test_env_flag_truthy_pure() {
        // Truthy spellings (trimmed, case-insensitive) select the standard paths.
        for v in ["1", "true", "TRUE", "Yes", " on ", "On"] {
            assert!(env_flag_truthy(Some(v)), "{v:?} should be truthy");
        }
        // Everything else — including unset — keeps the bespoke default.
        for v in ["0", "false", "no", "off", "", "bespoke", "2", "enable"] {
            assert!(!env_flag_truthy(Some(v)), "{v:?} should be falsey");
        }
        assert!(!env_flag_truthy(None));
    }

    #[test]
    fn test_default_paths_bespoke_out_of_the_box() {
        let _g = lock_path_mode();
        // Shipped default (no programmatic override, env unset in the gate):
        // bespoke on both surfaces, so the matched-sim wire is unchanged.
        assert!(!oauth2_standard_paths_default());
        assert_eq!(
            OAuth2Client::default_token_path(),
            OAuth2Client::TOKEN_PATH_BESPOKE
        );
        assert_eq!(JwksCache::default_key_path(), JwksCache::NRF_JWKS_PATH);
        assert_eq!(
            OAuth2Client::new("http://nrf:7777", "amf-1", NfType::Amf).token_path(),
            "/nnrf-oauth2/v1/access-token"
        );
        assert_eq!(
            JwksCache::for_nrf("http://nrf:7777").jwks_uri(),
            "http://nrf:7777/nnrf-oauth2/v1/jwks"
        );
    }

    #[test]
    fn test_flag_flips_default_to_standard() {
        let _g = lock_path_mode();
        set_oauth2_standard_paths_default(true);
        assert!(oauth2_standard_paths_default());
        assert_eq!(
            OAuth2Client::default_token_path(),
            OAuth2Client::TOKEN_PATH_STANDARD
        );
        assert_eq!(
            JwksCache::default_key_path(),
            JwksCache::NRF_KEY_PATH_STANDARD
        );
        // Constructors now default to the TS 29.510 standard paths.
        assert_eq!(
            OAuth2Client::new("http://nrf:7777", "amf-1", NfType::Amf).token_path(),
            "/oauth2/token"
        );
        assert_eq!(
            JwksCache::for_nrf("http://nrf:7777").jwks_uri(),
            "http://nrf:7777/oauth2/retrieve-key"
        );
        reset_oauth2_standard_paths_default();
    }

    #[test]
    fn test_force_bespoke_overrides_env() {
        let _g = lock_path_mode();
        // A programmatic `false` forces bespoke even if the env asked for
        // standard (the override wins over the env var).
        set_oauth2_standard_paths_default(false);
        assert!(!oauth2_standard_paths_default());
        assert_eq!(
            OAuth2Client::default_token_path(),
            OAuth2Client::TOKEN_PATH_BESPOKE
        );
        assert_eq!(JwksCache::default_key_path(), JwksCache::NRF_JWKS_PATH);
        reset_oauth2_standard_paths_default();
    }

    #[test]
    fn test_per_instance_override_wins_over_flag() {
        let _g = lock_path_mode();
        // Even with the standard-paths flag ON, an explicit per-instance path
        // wins (H8-AB / sbi-06 override semantics preserved, not undone).
        set_oauth2_standard_paths_default(true);
        let c = OAuth2Client::new("http://nrf:7777", "amf-1", NfType::Amf)
            .with_token_path(OAuth2Client::TOKEN_PATH_BESPOKE);
        assert_eq!(c.token_path(), "/nnrf-oauth2/v1/access-token");
        let cache = JwksCache::for_nrf_with_path("http://nrf:7777", JwksCache::NRF_JWKS_PATH);
        assert_eq!(cache.jwks_uri(), "http://nrf:7777/nnrf-oauth2/v1/jwks");
        reset_oauth2_standard_paths_default();
    }

    #[tokio::test]
    async fn test_flag_default_hits_standard_path_on_wire() {
        // Server answers ONLY the TS 29.510 standard path; with the flag on, the
        // default-constructed client (no per-instance override) must request it.
        let addr = serve_token_on_path("/oauth2/token").await;
        // The selector is read at construction; flip → build → reset all under
        // the guard, then release before the network I/O (no lock across await).
        let client = {
            let _g = lock_path_mode();
            set_oauth2_standard_paths_default(true);
            let c = OAuth2Client::new(format!("http://{addr}"), "amf-1", NfType::Amf);
            reset_oauth2_standard_paths_default();
            c
        };
        assert_eq!(client.token_path(), "/oauth2/token");
        let resp = client
            .request_token(NfType::Udm, "nudm-sdm")
            .await
            .expect("standard path used by default when the flag is on");
        assert_eq!(resp.access_token, "tok");
    }
}
