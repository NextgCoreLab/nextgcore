//! OAuth2 Token Exchange for 5G SBA
//!
//! Implements the OAuth2 client credentials grant flow (RFC 6749 Section 4.4)
//! as used in 3GPP TS 29.510 for NRF-based access token management.
//!
//! In 5G SBA, the NRF acts as the Authorization Server. NF service consumers
//! request access tokens using the client credentials grant before calling
//! NF service producers.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio_rustls::TlsConnector;

use crate::error::{SbiError, SbiResult};
use crate::types::NfType;

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
        }
    }

    /// Set the target NF instance ID.
    pub fn with_target_nf_instance_id(mut self, id: impl Into<String>) -> Self {
        self.target_nf_instance_id = Some(id.into());
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
    /// (sbi-06). Defaults to the bespoke [`OAuth2Client::TOKEN_PATH_BESPOKE`];
    /// set [`OAuth2Client::TOKEN_PATH_STANDARD`] via
    /// [`OAuth2Client::with_token_path`] once the NRF serves the TS 29.510 path.
    token_path: String,
}

impl OAuth2Client {
    /// Bespoke (Open5GS-style) access-token path — the **default**, kept until
    /// the nrfd consumer is migrated to the standard path (sbi-06).
    pub const TOKEN_PATH_BESPOKE: &'static str = "/nnrf-oauth2/v1/access-token";
    /// TS 29.510 §5.4 / clause 6.3 standard access-token path
    /// (`POST {nrfApiRoot}/oauth2/token`). Opt in with
    /// [`OAuth2Client::with_token_path`].
    pub const TOKEN_PATH_STANDARD: &'static str = "/oauth2/token";

    /// Create a new OAuth2 client.
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
            token_path: Self::TOKEN_PATH_BESPOKE.to_string(),
        }
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
        let request =
            AccessTokenRequest::new(&self.nf_instance_id, self.nf_type, target_nf_type, scope);

        let body = request.to_form_body();
        // sbi-06: the resource path is configurable; the default keeps the
        // bespoke `/nnrf-oauth2/v1/access-token` so the wire request is
        // unchanged until the NRF is migrated to the TS 29.510 standard path.
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

/// Minimal percent-encoding for form values.
fn url_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => result.push(c),
            ' ' => result.push('+'),
            _ => {
                let mut buf = [0u8; 4];
                let encoded = c.encode_utf8(&mut buf);
                for &b in encoded.as_bytes() {
                    result.push('%');
                    result.push_str(&format!("{b:02X}"));
                }
            }
        }
    }
    result
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

    /// Create a cache for an explicit JWKS URI.
    pub fn new(jwks_uri: impl Into<String>) -> Self {
        Self {
            jwks_uri: jwks_uri.into(),
            cached: RwLock::new(None),
            ttl: Self::DEFAULT_TTL,
            tls: None,
        }
    }

    /// Create a cache pointing at the NRF's JWKS endpoint, using the bespoke
    /// default path ([`JwksCache::NRF_JWKS_PATH`]).
    pub fn for_nrf(nrf_uri: &str) -> Self {
        Self::for_nrf_with_path(nrf_uri, Self::NRF_JWKS_PATH)
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
        assert!(cache.authorize_aud(Some(&header), Some("UDM")).await.is_ok());
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
                                    hyper::Response::builder().status(404).body(
                                        http_body_util::Full::new(bytes::Bytes::from("nope")),
                                    )
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
        let client = OAuth2Client::new(format!("http://{addr}"), "amf-1", NfType::Amf);
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
}
