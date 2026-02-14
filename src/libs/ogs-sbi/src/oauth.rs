//! OAuth2 Token Exchange for 5G SBA
//!
//! Implements the OAuth2 client credentials grant flow (RFC 6749 Section 4.4)
//! as used in 3GPP TS 29.510 for NRF-based access token management.
//!
//! In 5G SBA, the NRF acts as the Authorization Server. NF service consumers
//! request access tokens using the client credentials grant before calling
//! NF service producers.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

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
    pub async fn put(
        &self,
        target_nf_type: NfType,
        scope: &str,
        response: AccessTokenResponse,
    ) {
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

/// Decode and validate the three-part structure of a JWT access token.
/// Returns (header, payload, signature) as raw bytes.
/// This does NOT verify the cryptographic signature; it only checks structure.
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

// ============================================================================
// OAuth2 Client (W1.23: Token exchange with NRF)
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
}

impl OAuth2Client {
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
        }
    }

    /// Get the NRF URI.
    pub fn nrf_uri(&self) -> &str {
        &self.nrf_uri
    }

    /// Get a valid access token for the given target NF type and scope.
    ///
    /// Returns a cached token if available and not expired, otherwise
    /// requests a new one from the NRF.
    pub async fn get_token(
        &self,
        target_nf_type: NfType,
        scope: &str,
    ) -> SbiResult<String> {
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
        let request = AccessTokenRequest::new(
            &self.nf_instance_id,
            self.nf_type,
            target_nf_type,
            scope,
        );

        let body = request.to_form_body();
        let uri = format!("{}/nnrf-oauth2/v1/access-token", self.nrf_uri);

        // Build HTTP request using hyper
        let addr = parse_uri_to_addr(&self.nrf_uri)?;

        let stream = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| SbiError::Timeout)?
        .map_err(|e| SbiError::ConnectionError(e.to_string()))?;

        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            io,
        )
        .await
        .map_err(|e| SbiError::ConnectionError(e.to_string()))?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                log::error!("OAuth2 HTTP/2 connection error: {e}");
            }
        });

        let http_request = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(&uri)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(http_body_util::Full::new(bytes::Bytes::from(body)))
            .map_err(|e| SbiError::ClientError(e.to_string()))?;

        let response = tokio::time::timeout(
            Duration::from_secs(10),
            sender.send_request(http_request),
        )
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
        cache.put(NfType::Smf, "nsmf-pdusession", response.clone()).await;

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
        let client = OAuth2Client::new(
            "http://127.0.0.10:7777",
            "amf-instance-001",
            NfType::Amf,
        );
        assert_eq!(client.nrf_uri(), "http://127.0.0.10:7777");
    }
}
