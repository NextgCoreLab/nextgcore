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
use crate::oauth::{authorize_bearer, AccessTokenClaims};
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
    if trimmed.len() > 7 && trimmed[..7].eq_ignore_ascii_case("bearer ") {
        Some(trimmed[7..].trim())
    } else {
        None
    }
}

/// OAuth2 middleware for SBI request handling.
///
/// Cryptographically verifies the Bearer token against the NRF's JWKS
/// (signature, `alg=ES256`, expiry — via [`crate::oauth::authorize_bearer`])
/// and then enforces the required scope. There is intentionally NO
/// signature-skipping variant: 3GPP TS 33.501 §13.4.1 requires NF service
/// producers to validate the token's signature before serving a request.
/// (The former `validate_bearer_token`, which decoded the JWT without
/// verifying the signature, was removed in the Wave 3 nrfd remediation.)
///
/// Returns Ok(Some(claims)) when authorized, Ok(None) when the policy does
/// not require OAuth2, Err otherwise.
pub fn authorize_sbi_request(
    auth_header: Option<&str>,
    required_scope: &str,
    policy: &SbiSecurityPolicy,
    jwks: &serde_json::Value,
) -> SbiResult<Option<AccessTokenClaims>> {
    if !policy.oauth2_required {
        return Ok(None);
    }

    // Signature + expiry verification against the NRF public key set.
    let claims = authorize_bearer(auth_header, jwks)?;

    // Scope enforcement (TS 29.510 §6.3.5.2.4: space-delimited service names).
    let scopes: Vec<&str> = claims.scope.split_whitespace().collect();
    if !scopes.contains(&required_scope) {
        return Err(SbiError::AuthorizationFailed(format!(
            "Token scope '{}' does not include required scope '{}'",
            claims.scope, required_scope
        )));
    }

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
        assert_eq!(extract_bearer_token("bearer  token123  "), Some("token123"));
        assert_eq!(extract_bearer_token("Basic dXNlcjpwYXNz"), None);
        assert_eq!(extract_bearer_token(""), None);
        assert_eq!(extract_bearer_token("Bearer"), None);
    }

    /// Builds an ES256-signed token + matching JWKS for middleware tests.
    fn signed_token_and_jwks(scope: &str, exp: u64) -> (String, serde_json::Value) {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};

        let key = SigningKey::from_slice(&[7u8; 32]).expect("valid P-256 scalar");
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","kid":"test-key"}"#);
        let claims = serde_json::json!({
            "iss": "nrf-instance-1",
            "sub": "amf-instance-1",
            "aud": "SMF",
            "scope": scope,
            "exp": exp,
        });
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let signing_input = format!("{header}.{payload}");
        let sig: Signature = key.sign(signing_input.as_bytes());
        let token = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));

        let point = key.verifying_key().to_encoded_point(false);
        let jwks = serde_json::json!({
            "keys": [{
                "kty": "EC", "crv": "P-256", "alg": "ES256", "kid": "test-key",
                "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
            }]
        });
        (token, jwks)
    }

    #[test]
    fn test_authorize_sbi_request_verifies_signature_and_scope() {
        let policy = SbiSecurityPolicy::production();
        let (token, jwks) = signed_token_and_jwks("nsmf-pdusession nsmf-event", 9999999999);
        let auth = format!("Bearer {token}");

        // Properly signed token with the right scope is accepted.
        let claims = authorize_sbi_request(Some(&auth), "nsmf-pdusession", &policy, &jwks)
            .expect("signed token authorizes")
            .expect("claims returned");
        assert_eq!(claims.iss, "nrf-instance-1");
        assert_eq!(claims.sub, "amf-instance-1");

        // Wrong scope is rejected even with a valid signature.
        assert!(authorize_sbi_request(Some(&auth), "nausf-auth", &policy, &jwks).is_err());

        // A token whose signature does not verify is rejected: there is no
        // signature-skipping path anymore.
        let mut tampered = token.clone();
        tampered.replace_range(0..1, "f");
        let tampered_auth = format!("Bearer {tampered}");
        assert!(
            authorize_sbi_request(Some(&tampered_auth), "nsmf-pdusession", &policy, &jwks).is_err()
        );

        // An unsigned/garbage-signature token is rejected too.
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let parts: Vec<&str> = token.split('.').collect();
        let forged = format!(
            "{}.{}.{}",
            parts[0],
            parts[1],
            URL_SAFE_NO_PAD.encode([0u8; 64])
        );
        let forged_auth = format!("Bearer {forged}");
        assert!(
            authorize_sbi_request(Some(&forged_auth), "nsmf-pdusession", &policy, &jwks).is_err()
        );

        // Expired token is rejected.
        let (expired, jwks2) = signed_token_and_jwks("nsmf-pdusession", 1);
        let expired_auth = format!("Bearer {expired}");
        assert!(
            authorize_sbi_request(Some(&expired_auth), "nsmf-pdusession", &policy, &jwks2).is_err()
        );
    }

    #[test]
    fn test_authorize_sbi_request_not_required() {
        let policy = SbiSecurityPolicy::development();
        let jwks = serde_json::json!({"keys": []});
        let result = authorize_sbi_request(None, "any-scope", &policy, &jwks);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_authorize_sbi_request_missing_header() {
        let policy = SbiSecurityPolicy::production();
        let jwks = serde_json::json!({"keys": []});
        let result = authorize_sbi_request(None, "nsmf-pdusession", &policy, &jwks);
        assert!(result.is_err());
    }

    #[test]
    fn test_nrf_security_config() {
        let config = NrfSecurityConfig::new("nrf-001").with_token_lifetime(7200);
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
