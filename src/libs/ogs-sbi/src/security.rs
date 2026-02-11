//! SBI Security Configuration (Items 115-119)
//!
//! Provides shared security configuration for all NFs:
//! - TLS/mTLS defaults (Item 115)
//! - OAuth2 Bearer token middleware (Item 116)
//! - NRF-specific TLS configuration (Item 117)
//! - PQC hybrid cipher suite configuration (Item 119)
//!
//! Per 3GPP TS 33.501 (Security architecture and procedures for 5G System),
//! all SBI communication between NFs SHALL use TLS with mutual authentication.

use crate::error::{SbiError, SbiResult};
use crate::oauth::{AccessTokenClaims, decode_jwt_parts};
use crate::tls;
use crate::types::NfType;

// ============================================================================
// SBI Security Policy (Item 115: TLS/mTLS by default)
// ============================================================================

/// SBI security policy for NF communication
#[derive(Debug, Clone)]
pub struct SbiSecurityPolicy {
    /// Require TLS for all SBI connections (TS 33.501 §13.1)
    pub tls_required: bool,
    /// Require mutual TLS (client certificate verification)
    pub mtls_required: bool,
    /// Require OAuth2 Bearer tokens on incoming requests
    pub oauth2_required: bool,
    /// Allow insecure connections (testing/development only)
    pub allow_insecure: bool,
    /// PQC configuration
    pub pqc: PqcTlsConfig,
    /// TLS certificate paths
    pub tls_paths: TlsPaths,
}

/// TLS certificate file paths
#[derive(Debug, Clone)]
pub struct TlsPaths {
    /// Server certificate path
    pub cert: String,
    /// Server private key path
    pub key: String,
    /// CA certificate for client verification (mTLS)
    pub ca_cert: String,
    /// Client certificate for outgoing mTLS connections
    pub client_cert: Option<String>,
    /// Client key for outgoing mTLS connections
    pub client_key: Option<String>,
}

impl Default for TlsPaths {
    fn default() -> Self {
        Self {
            cert: "/etc/nextgcore/tls/server.crt".to_string(),
            key: "/etc/nextgcore/tls/server.key".to_string(),
            ca_cert: "/etc/nextgcore/tls/ca.crt".to_string(),
            client_cert: Some("/etc/nextgcore/tls/client.crt".to_string()),
            client_key: Some("/etc/nextgcore/tls/client.key".to_string()),
        }
    }
}

impl Default for SbiSecurityPolicy {
    fn default() -> Self {
        Self::production()
    }
}

impl SbiSecurityPolicy {
    /// Production security policy: TLS + mTLS + OAuth2 required (TS 33.501)
    pub fn production() -> Self {
        Self {
            tls_required: true,
            mtls_required: true,
            oauth2_required: true,
            allow_insecure: false,
            pqc: PqcTlsConfig::default(),
            tls_paths: TlsPaths::default(),
        }
    }

    /// Development security policy: TLS optional, no mTLS/OAuth2
    pub fn development() -> Self {
        Self {
            tls_required: false,
            mtls_required: false,
            oauth2_required: false,
            allow_insecure: true,
            pqc: PqcTlsConfig::default(),
            tls_paths: TlsPaths::default(),
        }
    }

    /// Testing security policy: TLS with insecure verify, no OAuth2
    pub fn testing() -> Self {
        Self {
            tls_required: true,
            mtls_required: false,
            oauth2_required: false,
            allow_insecure: true,
            pqc: PqcTlsConfig::default(),
            tls_paths: TlsPaths::default(),
        }
    }

    /// Check if a given configuration meets the security policy
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut violations = Vec::new();

        if self.tls_required && self.allow_insecure {
            violations.push(
                "TLS is required but allow_insecure is set; this weakens security".to_string(),
            );
        }

        if self.mtls_required && !self.tls_required {
            violations.push("mTLS requires TLS to be enabled".to_string());
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

// ============================================================================
// NRF-specific TLS Configuration (Item 117)
// ============================================================================

/// NRF-specific security configuration
///
/// The NRF has additional security requirements per TS 33.501 §13.3:
/// - Must verify client certificates (all NFs register via mTLS)
/// - Must issue and validate OAuth2 access tokens
/// - Acts as the Authorization Server in 5G SBA
#[derive(Debug, Clone)]
pub struct NrfSecurityConfig {
    /// Base security policy
    pub policy: SbiSecurityPolicy,
    /// NRF Instance ID (used as OAuth2 issuer)
    pub nrf_instance_id: String,
    /// Token lifetime in seconds (default: 3600)
    pub token_lifetime_secs: u64,
    /// Maximum tokens per NF consumer (rate limiting)
    pub max_tokens_per_nf: u32,
    /// Allowed NF types for registration
    pub allowed_nf_types: Vec<NfType>,
}

impl Default for NrfSecurityConfig {
    fn default() -> Self {
        Self {
            policy: SbiSecurityPolicy::production(),
            nrf_instance_id: String::new(),
            token_lifetime_secs: 3600,
            max_tokens_per_nf: 100,
            allowed_nf_types: vec![
                NfType::Amf,
                NfType::Smf,
                NfType::Upf,
                NfType::Ausf,
                NfType::Udm,
                NfType::Udr,
                NfType::Pcf,
                NfType::Bsf,
                NfType::Nssf,
                NfType::Scp,
                NfType::Sepp,
            ],
        }
    }
}

impl NrfSecurityConfig {
    /// Create NRF security config with instance ID
    pub fn new(nrf_instance_id: impl Into<String>) -> Self {
        Self {
            nrf_instance_id: nrf_instance_id.into(),
            ..Default::default()
        }
    }

    /// Set token lifetime
    pub fn with_token_lifetime(mut self, secs: u64) -> Self {
        self.token_lifetime_secs = secs;
        self
    }
}

// ============================================================================
// OAuth2 Bearer Token Middleware (Item 116)
// ============================================================================

/// Extract Bearer token from Authorization header
pub fn extract_bearer_token(auth_header: &str) -> Option<&str> {
    let trimmed = auth_header.trim();
    if trimmed.len() > 7
        && trimmed[..7].eq_ignore_ascii_case("bearer ")
    {
        Some(trimmed[7..].trim())
    } else {
        None
    }
}

/// Validate a Bearer token for SBI request authorization
///
/// Checks:
/// 1. Token is well-formed JWT (3 parts)
/// 2. Claims contain required fields (iss, sub, aud, scope, exp)
/// 3. Token is not expired
/// 4. Scope matches the requested service
///
/// Note: Cryptographic signature verification requires the NRF's public key,
/// which should be done at the NRF or via a shared secret.
pub fn validate_bearer_token(
    token: &str,
    required_scope: &str,
    current_time_secs: u64,
) -> SbiResult<AccessTokenClaims> {
    // Decode JWT structure
    let (_header, payload, _signature) = decode_jwt_parts(token)?;

    // Parse claims
    let claims: AccessTokenClaims = serde_json::from_slice(&payload)
        .map_err(|e| SbiError::AuthorizationFailed(format!("Invalid JWT claims: {e}")))?;

    // Check expiration
    if claims.exp < current_time_secs {
        return Err(SbiError::AuthorizationFailed(
            "Access token has expired".to_string(),
        ));
    }

    // Check scope
    let scopes: Vec<&str> = claims.scope.split_whitespace().collect();
    if !scopes.iter().any(|s| *s == required_scope) {
        return Err(SbiError::AuthorizationFailed(format!(
            "Token scope '{}' does not include required scope '{}'",
            claims.scope, required_scope
        )));
    }

    Ok(claims)
}

/// OAuth2 middleware for SBI request handling
///
/// Returns Ok(claims) if the request is authorized, Err if not.
pub fn authorize_sbi_request(
    auth_header: Option<&str>,
    required_scope: &str,
    policy: &SbiSecurityPolicy,
) -> SbiResult<Option<AccessTokenClaims>> {
    if !policy.oauth2_required {
        return Ok(None);
    }

    let header = auth_header.ok_or_else(|| {
        SbiError::AuthorizationFailed("Missing Authorization header".to_string())
    })?;

    let token = extract_bearer_token(header).ok_or_else(|| {
        SbiError::AuthorizationFailed("Invalid Authorization header: expected Bearer token".to_string())
    })?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let claims = validate_bearer_token(token, required_scope, now)?;
    Ok(Some(claims))
}

// ============================================================================
// PQC Hybrid TLS Configuration (Item 119)
// ============================================================================

/// Post-Quantum Cryptography TLS configuration
///
/// Supports hybrid key exchange combining classical ECDH with
/// ML-KEM (FIPS 203) for quantum-resistant key establishment,
/// and ML-DSA-65 (FIPS 204) for quantum-resistant signatures.
///
/// Per 3GPP TR 33.875 (Study on post-quantum cryptography for 5G security).
#[derive(Debug, Clone)]
pub struct PqcTlsConfig {
    /// Enable PQC hybrid mode
    pub enabled: bool,
    /// Preferred key exchange: X25519_MLKEM768 (hybrid classical + PQC)
    pub hybrid_kex: PqcKeyExchange,
    /// Preferred signature: ML-DSA-65 (hybrid with ECDSA-P256 fallback)
    pub hybrid_sig: PqcSignature,
    /// Minimum TLS version (TLS 1.3 required for PQC)
    pub min_tls_version: TlsVersion,
}

impl Default for PqcTlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            hybrid_kex: PqcKeyExchange::X25519MlKem768,
            hybrid_sig: PqcSignature::MlDsa65,
            min_tls_version: TlsVersion::Tls13,
        }
    }
}

impl PqcTlsConfig {
    /// Enable PQC hybrid mode
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            ..Default::default()
        }
    }

    /// Get the cipher suite identifiers for TLS configuration
    pub fn cipher_suite_names(&self) -> Vec<&'static str> {
        let mut suites = vec![
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
        ];

        if self.enabled {
            // PQC hybrid cipher suites (IANA assignments pending, using draft IDs)
            suites.insert(0, "TLS_AES_256_GCM_SHA384_MLKEM768");
        }

        suites
    }

    /// Get the key exchange group names
    pub fn kex_group_names(&self) -> Vec<&'static str> {
        let mut groups = vec!["x25519", "secp256r1", "secp384r1"];

        if self.enabled {
            groups.insert(0, "x25519_mlkem768");
        }

        groups
    }

    /// Get the signature algorithm names
    pub fn sig_alg_names(&self) -> Vec<&'static str> {
        let mut algs = vec![
            "ecdsa_secp256r1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha256",
            "ed25519",
        ];

        if self.enabled {
            algs.insert(0, "mldsa65");
        }

        algs
    }
}

/// PQC key exchange algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqcKeyExchange {
    /// X25519 + ML-KEM-768 hybrid (FIPS 203)
    X25519MlKem768,
    /// X25519 + ML-KEM-1024 hybrid (higher security level)
    X25519MlKem1024,
}

/// PQC signature algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqcSignature {
    /// ML-DSA-65 (FIPS 204, ~128-bit post-quantum security)
    MlDsa65,
    /// ML-DSA-87 (FIPS 204, ~192-bit post-quantum security)
    MlDsa87,
}

/// TLS version
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    /// TLS 1.2 (minimum for 5G SBI)
    Tls12,
    /// TLS 1.3 (required for PQC)
    Tls13,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_production_policy() {
        let policy = SbiSecurityPolicy::production();
        assert!(policy.tls_required);
        assert!(policy.mtls_required);
        assert!(policy.oauth2_required);
        assert!(!policy.allow_insecure);
    }

    #[test]
    fn test_development_policy() {
        let policy = SbiSecurityPolicy::development();
        assert!(!policy.tls_required);
        assert!(!policy.mtls_required);
        assert!(!policy.oauth2_required);
        assert!(policy.allow_insecure);
    }

    #[test]
    fn test_testing_policy() {
        let policy = SbiSecurityPolicy::testing();
        assert!(policy.tls_required);
        assert!(!policy.mtls_required);
        assert!(!policy.oauth2_required);
        assert!(policy.allow_insecure);
    }

    #[test]
    fn test_policy_validation() {
        let policy = SbiSecurityPolicy::production();
        assert!(policy.validate().is_ok());

        // mTLS without TLS should warn
        let mut bad = SbiSecurityPolicy::development();
        bad.mtls_required = true;
        let result = bad.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_bearer_token() {
        assert_eq!(
            extract_bearer_token("Bearer eyJhbGciOi"),
            Some("eyJhbGciOi")
        );
        assert_eq!(
            extract_bearer_token("bearer  token123  "),
            Some("token123")
        );
        assert_eq!(extract_bearer_token("Basic dXNlcjpwYXNz"), None);
        assert_eq!(extract_bearer_token(""), None);
        assert_eq!(extract_bearer_token("Bearer"), None);
    }

    #[test]
    fn test_validate_bearer_token() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
        let claims = serde_json::json!({
            "iss": "nrf-instance-1",
            "sub": "amf-instance-1",
            "aud": "SMF",
            "scope": "nsmf-pdusession nsmf-event",
            "exp": 9999999999u64
        });
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(b"fakesig");
        let token = format!("{header}.{payload}.{sig}");

        // Valid token
        let result = validate_bearer_token(&token, "nsmf-pdusession", 1000000000);
        assert!(result.is_ok());
        let c = result.unwrap();
        assert_eq!(c.iss, "nrf-instance-1");
        assert_eq!(c.sub, "amf-instance-1");

        // Wrong scope
        let result = validate_bearer_token(&token, "nausf-auth", 1000000000);
        assert!(result.is_err());

        // Expired
        let result = validate_bearer_token(&token, "nsmf-pdusession", 99999999999);
        assert!(result.is_err());
    }

    #[test]
    fn test_authorize_sbi_request_not_required() {
        let policy = SbiSecurityPolicy::development();
        let result = authorize_sbi_request(None, "any-scope", &policy);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_authorize_sbi_request_missing_header() {
        let policy = SbiSecurityPolicy::production();
        let result = authorize_sbi_request(None, "nsmf-pdusession", &policy);
        assert!(result.is_err());
    }

    #[test]
    fn test_nrf_security_config() {
        let config = NrfSecurityConfig::new("nrf-001")
            .with_token_lifetime(7200);
        assert_eq!(config.nrf_instance_id, "nrf-001");
        assert_eq!(config.token_lifetime_secs, 7200);
        assert!(config.policy.tls_required);
    }

    #[test]
    fn test_pqc_tls_config_disabled() {
        let pqc = PqcTlsConfig::default();
        assert!(!pqc.enabled);
        let suites = pqc.cipher_suite_names();
        assert!(!suites.iter().any(|s| s.contains("MLKEM")));
        let groups = pqc.kex_group_names();
        assert!(!groups.iter().any(|s| s.contains("mlkem")));
    }

    #[test]
    fn test_pqc_tls_config_enabled() {
        let pqc = PqcTlsConfig::enabled();
        assert!(pqc.enabled);
        let suites = pqc.cipher_suite_names();
        assert!(suites[0].contains("MLKEM"));
        let groups = pqc.kex_group_names();
        assert!(groups[0].contains("mlkem"));
        let algs = pqc.sig_alg_names();
        assert!(algs[0].contains("mldsa"));
    }

    #[test]
    fn test_tls_paths_default() {
        let paths = TlsPaths::default();
        assert!(paths.cert.contains("server.crt"));
        assert!(paths.key.contains("server.key"));
        assert!(paths.ca_cert.contains("ca.crt"));
    }
}
