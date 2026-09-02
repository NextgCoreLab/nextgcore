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
use crate::oauth::AccessTokenClaims;
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

impl TlsPaths {
    /// Environment variables overriding each certificate path, so a deployment
    /// can mount its SBI certificates wherever it likes (issue #63).
    ///
    /// Kubernetes Secret mounts, Docker bind mounts and distro packaging all put
    /// these in different places, and the compiled-in `/etc/nextgcore/tls`
    /// default cannot be right for all of them. Without an override the
    /// production profile would be unusable anywhere it does not match — and
    /// "unusable" in practice means an operator selects the dev profile instead,
    /// which is the opposite of the intent.
    pub const CERT_ENV: &'static str = "NEXTGCORE_SBI_TLS_CERT";
    pub const KEY_ENV: &'static str = "NEXTGCORE_SBI_TLS_KEY";
    pub const CA_ENV: &'static str = "NEXTGCORE_SBI_TLS_CA";
    /// The certificate this NF presents when it DIALS a peer. Under mTLS an NF is
    /// both a server and a client, and a deployment may well mount the two roles'
    /// material separately.
    pub const CLIENT_CERT_ENV: &'static str = "NEXTGCORE_SBI_TLS_CLIENT_CERT";
    pub const CLIENT_KEY_ENV: &'static str = "NEXTGCORE_SBI_TLS_CLIENT_KEY";

    /// [`TlsPaths::default`] with each path overridden by its environment
    /// variable when that variable is set and non-empty.
    pub fn from_env() -> Self {
        let or_env = |var: &str, fallback: String| -> String {
            match std::env::var(var) {
                Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
                _ => fallback,
            }
        };
        let or_env_opt = |var: &str, fallback: Option<String>| -> Option<String> {
            match std::env::var(var) {
                Ok(v) if !v.trim().is_empty() => Some(v.trim().to_string()),
                _ => fallback,
            }
        };
        let d = Self::default();
        Self {
            cert: or_env(Self::CERT_ENV, d.cert),
            key: or_env(Self::KEY_ENV, d.key),
            ca_cert: or_env(Self::CA_ENV, d.ca_cert),
            client_cert: or_env_opt(Self::CLIENT_CERT_ENV, d.client_cert),
            client_key: or_env_opt(Self::CLIENT_KEY_ENV, d.client_key),
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

    /// The policy for a resolved [`SbiProfile`], with certificate paths taken
    /// from the environment ([`TlsPaths::from_env`]) so a deployment can mount
    /// them where it likes.
    ///
    /// This is the **runtime** entry point that gives
    /// [`SbiSecurityPolicy::production`] a non-test caller (issue #63 criterion
    /// 4); before this it was defined and reachable only from unit tests, so the
    /// intended production posture was dead code.
    pub fn for_profile(profile: SbiProfile) -> Self {
        let mut policy = match profile {
            SbiProfile::Production => Self::production(),
            SbiProfile::Dev => Self::development(),
        };
        policy.tls_paths = TlsPaths::from_env();
        policy
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
// SBI security profile (issue #63) — one resolved posture per process
// ============================================================================

/// Which security posture an NF starts in (issue #63, TS 33.501 §13.1.0).
///
/// **`Production` is the default**, so an NF that is simply started serves SBI
/// over mutually-authenticated TLS and requires an OAuth2 access token. The
/// previous behaviour — cleartext h2c with no token verification — is still
/// reachable, but only by asking for it by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbiProfile {
    /// TLS + mTLS + OAuth2 required (TS 33.501 §13.1.0, §13.4.1.1).
    Production,
    /// Cleartext h2c, no client-certificate verification, no token
    /// verification. For local development and the matched-simulator E2E only.
    Dev,
}

/// Environment variable selecting the profile, process-wide.
///
/// `dev`, `development`, `insecure`, `local` and `test` select
/// [`SbiProfile::Dev`]; `production` and `prod` select
/// [`SbiProfile::Production`]. **Anything else — including the variable being
/// unset — is `Production`**: an unrecognised value must not silently downgrade
/// security, which is the failure mode this issue is about.
pub const SBI_PROFILE_ENV: &str = "NEXTGCORE_SBI_PROFILE";

/// Tri-state programmatic override of the profile: `0` = consult
/// [`SBI_PROFILE_ENV`], `1` = force [`SbiProfile::Dev`], `2` = force
/// [`SbiProfile::Production`].
static SBI_PROFILE_MODE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Force the process-wide profile, overriding [`SBI_PROFILE_ENV`].
///
/// Exists for tests that exercise production code paths against a loopback
/// **plaintext** peer: such a test is describing a dev-profile deployment, and
/// saying so explicitly is better than depending on whatever the environment
/// happens to hold. Storing the same value from several threads is benign, so
/// parallel tests that all want `Dev` do not need to serialise.
pub fn set_sbi_profile_override(profile: SbiProfile) {
    SBI_PROFILE_MODE.store(
        match profile {
            SbiProfile::Dev => 1,
            SbiProfile::Production => 2,
        },
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// Clear an override set by [`set_sbi_profile_override`], restoring env-driven
/// resolution.
pub fn reset_sbi_profile_override() {
    SBI_PROFILE_MODE.store(0, std::sync::atomic::Ordering::Relaxed);
}

impl SbiProfile {
    /// Resolve the process-wide profile: the programmatic override
    /// ([`set_sbi_profile_override`]) first, then [`SBI_PROFILE_ENV`].
    pub fn resolve() -> Self {
        match SBI_PROFILE_MODE.load(std::sync::atomic::Ordering::Relaxed) {
            1 => Self::Dev,
            2 => Self::Production,
            _ => Self::from_env_value(std::env::var(SBI_PROFILE_ENV).ok().as_deref()),
        }
    }

    /// Pure resolution of an env value, unit-testable without touching the
    /// process environment.
    ///
    /// An unrecognised non-empty value resolves to `Production` **and warns**:
    /// a typo like `NEXTGCORE_SBI_PROFILE=devel` must not be read as "insecure
    /// is fine", but it also must not pass silently, because the operator
    /// clearly meant something.
    pub fn from_env_value(value: Option<&str>) -> Self {
        let Some(raw) = value else {
            return Self::Production;
        };
        let v = raw.trim();
        if v.is_empty() {
            return Self::Production;
        }
        match v.to_ascii_lowercase().as_str() {
            "dev" | "development" | "insecure" | "local" | "test" => Self::Dev,
            "production" | "prod" => Self::Production,
            other => {
                log::warn!(
                    "{SBI_PROFILE_ENV}={other:?} is not a recognised profile; using \
                     'production'. Accepted values: production, prod, dev, development, \
                     insecure, local, test."
                );
                Self::Production
            }
        }
    }

    /// Whether this profile serves SBI over TLS.
    pub fn is_production(&self) -> bool {
        matches!(self, Self::Production)
    }
}

/// Apply the resolved [`SbiProfile`] to an NF's SBI **server** configuration
/// (issue #63 criteria 1-4, 7).
///
/// Under [`SbiProfile::Production`] this is the single place that turns
/// [`SbiSecurityPolicy::production`] into concrete listener settings: TLS from
/// the policy's certificate paths, `verify_client` for mTLS, `require_oauth2`
/// with the NRF's JWKS as the verification source, and the NF's own type as the
/// expected token audience. Under [`SbiProfile::Dev`] the config is returned
/// **untouched**, so the cleartext h2c path is byte-for-byte what it was.
///
/// Centralised deliberately. The four core NFs each build their listener at a
/// different site, and a posture expressed as four copies of the same twenty
/// lines is a posture that will disagree with itself — the same failure shape as
/// the `--kill` flag that was duplicated across twelve daemons and wrong in all
/// twelve. Peripheral NFs that already hand-roll `with_tls` can migrate onto
/// this later.
///
/// # Errors
///
/// Fails when the production profile is selected but its certificate, key or CA
/// file is missing or unreadable. That is deliberate: it surfaces at startup,
/// naming the path, rather than as a TLS handshake failure on the first peer
/// connection — and it must never fall back to cleartext, because a security
/// posture that degrades when a file is absent is not a posture.
pub fn apply_sbi_security_profile(
    config: crate::server::SbiServerConfig,
    profile: SbiProfile,
    nf_type: NfType,
    nrf_uri: &str,
) -> SbiResult<crate::server::SbiServerConfig> {
    let policy = SbiSecurityPolicy::for_profile(profile);
    apply_sbi_security_policy(config, profile, &policy, nf_type, nrf_uri)
}

/// [`apply_sbi_security_profile`] against an explicit policy.
///
/// Split out so the production path is testable without writing to the policy's
/// real certificate directory: a test supplies a policy whose [`TlsPaths`] point
/// at generated certificates in a temporary directory. Production code should
/// call [`apply_sbi_security_profile`], which resolves the policy from the
/// profile and the environment.
pub fn apply_sbi_security_policy(
    config: crate::server::SbiServerConfig,
    profile: SbiProfile,
    policy: &SbiSecurityPolicy,
    nf_type: NfType,
    nrf_uri: &str,
) -> SbiResult<crate::server::SbiServerConfig> {
    if profile == SbiProfile::Dev {
        log::warn!(
            "SBI security profile is DEV ({SBI_PROFILE_ENV}): serving cleartext h2c with \
             no client-certificate verification and no access-token verification. \
             Subscriber identifiers, authentication vectors and session context are \
             readable and modifiable by anything on the path. Do not run this in \
             production."
        );
        return Ok(config);
    }

    // Self-check the policy before acting on it, so a contradictory policy is a
    // startup error rather than a surprising listener.
    if let Err(violations) = policy.validate() {
        return Err(SbiError::TlsError(format!(
            "the production SBI security policy is self-contradictory: {}",
            violations.join("; ")
        )));
    }

    // Every file the posture needs, checked at startup so a missing one names
    // itself here rather than surfacing later as a handshake error. Under mTLS an
    // NF is both server and client, so the client material it presents when
    // DIALLING a peer is just as required as the server material -- omitting it
    // from this check is how "the listener came up fine" turns into every
    // outbound call failing.
    let paths = &policy.tls_paths;
    let mut required: Vec<(&str, &str)> = vec![
        ("certificate", paths.cert.as_str()),
        ("private key", paths.key.as_str()),
        ("client CA certificate", paths.ca_cert.as_str()),
    ];
    if let Some(cc) = paths.client_cert.as_deref() {
        required.push(("client certificate (for outbound peer calls)", cc));
    }
    if let Some(ck) = paths.client_key.as_deref() {
        required.push(("client private key (for outbound peer calls)", ck));
    }
    for (label, path) in required {
        if !std::path::Path::new(path).is_file() {
            return Err(SbiError::TlsError(format!(
                "SBI production profile requires a TLS {label} at {path}, which does not \
                 exist. Provision it, or select the dev profile explicitly with \
                 {SBI_PROFILE_ENV}=dev (cleartext h2c, no token verification)."
            )));
        }
    }

    let mut config = config.with_tls(&paths.key, &paths.cert);
    if policy.mtls_required {
        config.verify_client = true;
        config.verify_client_cacert = Some(paths.ca_cert.clone());
    }

    if policy.oauth2_required {
        config.require_oauth2 = true;
        // The verification source is the NRF's JWKS. An ALREADY-configured source
        // wins: an NF that set a static `oauth2_jwks`, or derived a JWKS URI from
        // its own config, has said something more specific than "use the NRF".
        //
        // With neither configured this stays None, and the server then rejects
        // every request with 503 rather than serving unauthenticated (see
        // `OAuthVerifier::from_config`) -- so an absent NRF is safe to leave to
        // the server rather than special-casing here.
        if config.oauth2_jwks.is_none() && config.oauth2_jwks_uri.is_none() {
            let uri = nrf_uri.trim();
            if !uri.is_empty() {
                config.oauth2_jwks_uri =
                    Some(crate::oauth::JwksCache::for_nrf(uri).jwks_uri().to_string());
            }
        }
        // TS 33.501 §13.4.1.2: a token minted for another producer must not be
        // accepted here. Again, an explicit audience already set wins.
        if config.oauth2_expected_audience.is_none() {
            config = config.with_expected_audience_nf_type(nf_type);
        }
    }

    log::info!(
        "SBI security profile PRODUCTION for {}: TLS cert={} mTLS={} \
         require_oauth2={} JWKS={}",
        nf_type.to_str(),
        paths.cert,
        config.verify_client,
        config.require_oauth2,
        config.oauth2_jwks_uri.as_deref().unwrap_or("UNCONFIGURED"),
    );
    Ok(config)
}

/// The client configuration for DIALLING a peer NF under the resolved profile
/// (issue #63, the outbound half of criterion 1).
///
/// An NF is both a server and a client on the SBI. Configuring only the listener
/// leaves a "secure by default" posture that cannot talk to itself: the callee
/// requires mutually-authenticated TLS while the caller still dials cleartext
/// http with no certificate, so every inter-NF request fails at the TLS layer —
/// and it fails on the *callee* side, with nothing pointing at the caller's
/// scheme.
///
/// Under [`SbiProfile::Production`] this returns an `https` config presenting
/// this NF's client certificate and verifying the peer against the configured CA.
/// Under [`SbiProfile::Dev`] it is exactly `SbiClientConfig::new`, so the
/// cleartext path is byte-identical.
///
/// **Scheme comes from the profile, not from a discovered URI.** In a uniformly
/// production deployment every peer is `https`; in a uniformly dev one every peer
/// is `http`. A deployment that mixes the two per-NF is not supported here — it
/// was already broken before this, since the scheme was hardcoded `http`
/// regardless of what a peer advertised.
pub fn sbi_client_config_for_profile(
    host: &str,
    port: u16,
    profile: SbiProfile,
) -> crate::client::SbiClientConfig {
    let config = crate::client::SbiClientConfig::new(host, port);
    if profile == SbiProfile::Dev {
        return config;
    }
    let paths = TlsPaths::from_env();
    let mut config = config.with_https();
    config.ca_cert = Some(paths.ca_cert);
    config.client_cert = paths.client_cert;
    config.client_key = paths.client_key;
    config
}

/// [`sbi_client_config_for_profile`] with the profile resolved from the
/// environment.
pub fn sbi_peer_client_config(host: &str, port: u16) -> crate::client::SbiClientConfig {
    sbi_client_config_for_profile(host, port, SbiProfile::resolve())
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
/// verifying the signature, was removed in the nrfd remediation.)
///
/// Returns Ok(Some(claims)) when authorized, Ok(None) when the policy does
/// not require OAuth2, Err otherwise.
/// `expected_audience` is the producer's own identity (TS 29.510 `NfType` token,
/// e.g. `"UDR"`). Issue #64 gap 3: this used to call the audience-SKIPPING
/// `authorize_bearer`, so a token the NRF minted for producer A verified happily at
/// producer B — an authorisation bypass (TS 33.501 §13.4.1.2 requires the producer
/// to verify it is the intended audience). It is a required parameter rather than an
/// `Option` so a caller cannot omit it by accident; pass the NF's own type.
pub fn authorize_sbi_request(
    auth_header: Option<&str>,
    required_scope: &str,
    expected_audience: &str,
    policy: &SbiSecurityPolicy,
    jwks: &serde_json::Value,
) -> SbiResult<Option<AccessTokenClaims>> {
    if !policy.oauth2_required {
        return Ok(None);
    }

    // Signature + expiry verification against the NRF public key set, plus the
    // audience binding.
    let claims = crate::oauth::authorize_bearer_aud(auth_header, jwks, Some(expected_audience))?;

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
        let suites = vec![
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
        ];

        // The hybrid ML-KEM exchange lives in the key-exchange groups (see
        // kex_group_names), not in the cipher-suite list: TLS 1.3 keeps the
        // standard suites. No fabricated "…_MLKEM768" suite is advertised.
        suites
    }

    /// Get the key exchange group names
    pub fn kex_group_names(&self) -> Vec<&'static str> {
        let mut groups = vec!["x25519", "secp256r1", "secp384r1"];

        if self.enabled {
            // IETF/rustls group name for the default hybrid suite that
            // tls.rs::select_provider offers first under the `pqc-tls`
            // feature (issue #17). Pure-ML-KEM mode negotiates "MLKEM768"
            // instead; this advisory list covers the hybrid default.
            groups.insert(0, "X25519MLKEM768");
        }

        groups
    }

    /// Get the signature algorithm names
    pub fn sig_alg_names(&self) -> Vec<&'static str> {
        let algs = vec![
            "ecdsa_secp256r1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha256",
            "ed25519",
        ];

        // Signature algorithms stay classical even with PQC enabled: rustls
        // 0.23 ships no ML-DSA certificate support (see tls.rs). "mldsa65"
        // is deliberately NOT advertised until it can actually be negotiated.
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
mod profile_tests {
    use super::*;
    use crate::server::SbiServerConfig;
    use crate::types::UriScheme;
    use std::net::SocketAddr;

    fn cfg() -> SbiServerConfig {
        SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], 7777)))
    }

    /// **Issue #63.** An unrecognised or absent profile value resolves to
    /// PRODUCTION.
    ///
    /// This is the load-bearing assertion of the whole posture change. The
    /// defect being fixed is that the secure path was opt-in, so anything that
    /// makes it opt-in again — including a typo like `NEXTGCORE_SBI_PROFILE=devel`
    /// silently reading as "insecure is fine" — reintroduces it. Absent, empty
    /// and garbage must all mean production.
    #[test]
    fn unrecognised_or_absent_profile_resolves_to_production() {
        for value in [None, Some(""), Some("   ")] {
            assert_eq!(
                SbiProfile::from_env_value(value),
                SbiProfile::Production,
                "absent/blank must not downgrade: {value:?}"
            );
        }
        for typo in ["devel", "dv", "off", "0", "false", "no", "yes", "1", "prd"] {
            assert_eq!(
                SbiProfile::from_env_value(Some(typo)),
                SbiProfile::Production,
                "an unrecognised value must not downgrade security: {typo:?}"
            );
        }
        for dev in ["dev", "DEV", " Development ", "insecure", "local", "test"] {
            assert_eq!(
                SbiProfile::from_env_value(Some(dev)),
                SbiProfile::Dev,
                "explicit opt-out must be honoured: {dev:?}"
            );
        }
        for prod in ["production", "PROD", " Production "] {
            assert_eq!(
                SbiProfile::from_env_value(Some(prod)),
                SbiProfile::Production
            );
        }
    }

    /// **Issue #63 criterion 7.** The dev profile leaves the listener exactly as
    /// it was: cleartext h2c, no client-certificate verification, no token
    /// verification. Existing dev/E2E flows depend on this being byte-identical.
    #[test]
    fn dev_profile_leaves_the_listener_untouched() {
        let before = cfg();
        let after = apply_sbi_security_profile(before.clone(), SbiProfile::Dev, NfType::Amf, "")
            .expect("dev never fails");
        assert_eq!(after.scheme, UriScheme::Http, "dev stays cleartext h2c");
        assert!(after.cert.is_none() && after.private_key.is_none());
        assert!(!after.verify_client);
        assert!(!after.require_oauth2, "dev verifies no tokens");
        assert!(after.oauth2_expected_audience.is_none());
        // And nothing else drifted.
        assert_eq!(after.addr, before.addr);
        assert_eq!(after.max_request_body_size, before.max_request_body_size);
    }

    /// **Issue #63.** The production profile refuses to start when its
    /// certificates are missing — it never falls back to cleartext.
    ///
    /// A posture that degrades when a file is absent is not a posture. The error
    /// must name the missing path, because the alternative is a TLS handshake
    /// failure on the first peer connection that looks like a peer problem.
    #[test]
    fn production_profile_fails_closed_on_missing_certificates() {
        let missing = SbiSecurityPolicy {
            tls_paths: TlsPaths {
                cert: "/nonexistent/nextgcore-test/server.crt".to_string(),
                key: "/nonexistent/nextgcore-test/server.key".to_string(),
                ca_cert: "/nonexistent/nextgcore-test/ca.crt".to_string(),
                ..TlsPaths::default()
            },
            ..SbiSecurityPolicy::production()
        };
        let err = apply_sbi_security_policy(
            cfg(),
            SbiProfile::Production,
            &missing,
            NfType::Amf,
            "http://nrf:7777",
        )
        .expect_err("missing certificates must fail startup, not degrade");
        let msg = err.to_string();
        assert!(
            msg.contains("/nonexistent/nextgcore-test/server.crt"),
            "the error must name the missing path: {msg}"
        );
        assert!(
            msg.contains(SBI_PROFILE_ENV),
            "and say how to opt out deliberately: {msg}"
        );
    }

    /// **Issue #63 criteria 1-4.** With certificates present, the production
    /// profile produces a TLS + mTLS listener that requires an OAuth2 token
    /// bound to this NF's own audience.
    #[test]
    fn production_profile_configures_tls_mtls_and_oauth2() {
        let dir = std::env::temp_dir().join(format!("sbi-profile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let cert = dir.join("server.crt");
        let key = dir.join("server.key");
        let ca = dir.join("ca.crt");
        for p in [&cert, &key, &ca] {
            std::fs::write(p, b"placeholder").expect("write");
        }

        let policy = SbiSecurityPolicy {
            tls_paths: TlsPaths {
                cert: cert.display().to_string(),
                key: key.display().to_string(),
                ca_cert: ca.display().to_string(),
                // The production posture needs client material too (an NF dials
                // peers as well as serving them), so these must exist.
                client_cert: Some(cert.display().to_string()),
                client_key: Some(key.display().to_string()),
                ..TlsPaths::default()
            },
            ..SbiSecurityPolicy::production()
        };
        let out = apply_sbi_security_policy(
            cfg(),
            SbiProfile::Production,
            &policy,
            NfType::Udm,
            "http://nrf.example:7777",
        )
        .expect("present certificates");

        // Criterion 1/2: TLS, and mTLS client verification.
        assert_eq!(out.scheme, UriScheme::Https);
        assert_eq!(
            out.cert.as_deref(),
            Some(cert.display().to_string().as_str())
        );
        assert!(out.verify_client, "the production profile mandates mTLS");
        assert_eq!(
            out.verify_client_cacert.as_deref(),
            Some(ca.display().to_string().as_str())
        );
        // Criterion 3: tokens required, verified against the NRF's JWKS.
        assert!(out.require_oauth2);
        assert_eq!(
            out.oauth2_jwks_uri.as_deref(),
            Some("http://nrf.example:7777/nnrf-oauth2/v1/jwks")
        );
        // TS 33.501 §13.4.1.2: bound to THIS producer's audience.
        assert_eq!(out.oauth2_expected_audience.as_deref(), Some("UDM"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Issue #63 criterion 3: with `require_oauth2` on and no JWKS source, the
    /// server must fail closed (503) rather than serve unauthenticated. The
    /// profile deliberately leaves that to the server rather than refusing to
    /// start, so an NRF that is merely not yet reachable does not block boot.
    #[test]
    fn production_profile_with_no_nrf_leaves_the_server_to_fail_closed() {
        let dir = std::env::temp_dir().join(format!("sbi-profile-nonrf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let (cert, key, ca) = (
            dir.join("server.crt"),
            dir.join("server.key"),
            dir.join("ca.crt"),
        );
        for p in [&cert, &key, &ca] {
            std::fs::write(p, b"placeholder").expect("write");
        }
        let policy = SbiSecurityPolicy {
            tls_paths: TlsPaths {
                cert: cert.display().to_string(),
                key: key.display().to_string(),
                ca_cert: ca.display().to_string(),
                // The production posture needs client material too (an NF dials
                // peers as well as serving them), so these must exist.
                client_cert: Some(cert.display().to_string()),
                client_key: Some(key.display().to_string()),
                ..TlsPaths::default()
            },
            ..SbiSecurityPolicy::production()
        };
        let out =
            apply_sbi_security_policy(cfg(), SbiProfile::Production, &policy, NfType::Amf, "")
                .expect("an unreachable NRF must not block startup");
        assert!(out.require_oauth2, "tokens are still required");
        assert!(
            out.oauth2_jwks_uri.is_none() && out.oauth2_jwks.is_none(),
            "no key source, so the server rejects every request with 503 rather than \
             serving unauthenticated"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Issue #63: an explicitly-configured JWKS source or audience wins over the
    /// profile's NRF-derived default. An NF that said something more specific
    /// than "use the NRF" must not have it overwritten.
    #[test]
    fn an_explicit_jwks_source_and_audience_survive_the_profile() {
        let dir = std::env::temp_dir().join(format!("sbi-profile-explicit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let (cert, key, ca) = (
            dir.join("server.crt"),
            dir.join("server.key"),
            dir.join("ca.crt"),
        );
        for p in [&cert, &key, &ca] {
            std::fs::write(p, b"placeholder").expect("write");
        }
        let policy = SbiSecurityPolicy {
            tls_paths: TlsPaths {
                cert: cert.display().to_string(),
                key: key.display().to_string(),
                ca_cert: ca.display().to_string(),
                // The production posture needs client material too (an NF dials
                // peers as well as serving them), so these must exist.
                client_cert: Some(cert.display().to_string()),
                client_key: Some(key.display().to_string()),
                ..TlsPaths::default()
            },
            ..SbiSecurityPolicy::production()
        };

        let mut pre = cfg();
        pre.oauth2_jwks_uri = Some("https://elsewhere/jwks".to_string());
        pre.oauth2_expected_audience = Some("custom-aud".to_string());
        let out = apply_sbi_security_policy(
            pre,
            SbiProfile::Production,
            &policy,
            NfType::Udm,
            "http://nrf.example:7777",
        )
        .expect("present certificates");
        assert_eq!(
            out.oauth2_jwks_uri.as_deref(),
            Some("https://elsewhere/jwks")
        );
        assert_eq!(out.oauth2_expected_audience.as_deref(), Some("custom-aud"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Issue #63 criterion 4: `SbiSecurityPolicy::production()` now has a real
    /// runtime caller, reached through `for_profile`, and its certificate paths
    /// are environment-overridable so a deployment can mount them anywhere.
    #[test]
    fn for_profile_adopts_the_production_policy() {
        let p = SbiSecurityPolicy::for_profile(SbiProfile::Production);
        assert!(p.tls_required && p.mtls_required && p.oauth2_required);
        assert!(!p.allow_insecure);
        let d = SbiSecurityPolicy::for_profile(SbiProfile::Dev);
        assert!(!d.tls_required && !d.mtls_required && !d.oauth2_required);
    }
}

/// **Issue #63 criterion 6.** An SBI transaction between two NFs over mTLS with
/// OAuth2, end to end, plus the negative case where the token endpoint is down.
///
/// This is the criterion the issue itself called the expensive one, and it is the
/// only test here that exercises the production posture as a whole rather than
/// one setting at a time: a real TLS handshake with client-certificate
/// verification, a real token minted by a stub NRF and fetched over the wire, and
/// a real signature check against a JWKS.
///
/// **Scope limit, stated rather than implied:** this drives the same
/// `SbiServer`/`SbiClient` stack the four core NFs use, in one process, against
/// generated certificates. It is not two containers running `nextgcore-amfd` and
/// `nextgcore-udmd` — CI skips the Docker E2E jobs, so that variant would not run
/// anywhere. What this proves is that the library path the NFs were just wired
/// onto works; what it cannot prove is that each daemon's startup wiring reaches
/// it. The per-NF wiring is covered by the `every_core_nf_applies_the_sbi_profile`
/// source guard instead.
#[cfg(test)]
mod mtls_oauth2_e2e {
    use super::*;
    use crate::client::{SbiClient, SbiClientConfig};
    use crate::message::{SbiRequest, SbiResponse};
    use crate::oauth::OAuth2Client;
    use crate::server::{SbiServer, SbiServerConfig};
    use std::net::SocketAddr;
    use std::sync::Arc;

    /// A CA plus a server leaf and a client leaf signed by it, written as PEM.
    /// mTLS needs a real chain: the server verifies the client leaf against the
    /// CA and vice versa, so self-signed leaves would not do.
    struct Pki {
        dir: std::path::PathBuf,
        ca: String,
        server_cert: String,
        server_key: String,
        client_cert: String,
        client_key: String,
    }

    impl Drop for Pki {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn pki(tag: &str) -> Pki {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

        let dir = std::env::temp_dir().join(format!("sbi-e2e-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "nextgcore-test-ca");
        let ca_key = KeyPair::generate().expect("ca key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("self-signed ca");

        let leaf = |name: &str| -> (String, String) {
            let mut params =
                CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
            params.distinguished_name.push(DnType::CommonName, name);
            let key = KeyPair::generate().expect("leaf key");
            let cert = params
                .signed_by(&key, &ca_cert, &ca_key)
                .expect("ca-signed leaf");
            (cert.pem(), key.serialize_pem())
        };
        let (server_cert_pem, server_key_pem) = leaf("nextgcore-test-producer");
        let (client_cert_pem, client_key_pem) = leaf("nextgcore-test-consumer");

        let write = |name: &str, contents: &str| -> String {
            let p = dir.join(name);
            std::fs::write(&p, contents).expect("write pem");
            p.display().to_string()
        };
        Pki {
            ca: write("ca.crt", &ca_cert.pem()),
            server_cert: write("server.crt", &server_cert_pem),
            server_key: write("server.key", &server_key_pem),
            client_cert: write("client.crt", &client_cert_pem),
            client_key: write("client.key", &client_key_pem),
            dir,
        }
    }

    /// The RFC 7517 JWKS a producer verifies tokens against, for one ES256 key.
    fn jwks(key: &p256::ecdsa::VerifyingKey) -> serde_json::Value {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let point = key.to_encoded_point(false);
        serde_json::json!({"keys": [{
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig",
            "kid": "test-es256",
            "x": URL_SAFE_NO_PAD.encode(point.x().expect("x")),
            "y": URL_SAFE_NO_PAD.encode(point.y().expect("y")),
        }]})
    }

    /// Mint an NRF-style ES256 access token.
    fn mint_token(key: &p256::ecdsa::SigningKey, aud: &str, scope: &str) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use p256::ecdsa::{signature::Signer, Signature};
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"JWT","kid":"test-es256"}"#);
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "iss": "nrf-test", "sub": "consumer-1", "aud": [aud],
                "scope": scope, "iat": now, "exp": now + 300,
            })
            .to_string()
            .as_bytes(),
        );
        let signing_input = format!("{header}.{claims}");
        let sig: Signature = key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    /// A stub NRF that answers the access-token endpoint with `token`.
    async fn start_stub_nrf(token: String) -> (SbiServer, u16) {
        let port = crate::test_support::free_port();
        let server = SbiServer::new(SbiServerConfig::new(SocketAddr::from((
            [127, 0, 0, 1],
            port,
        ))));
        server
            .start(move |_req: SbiRequest| {
                let token = token.clone();
                async move {
                    SbiResponse::with_status(200)
                        .with_json_body(&serde_json::json!({
                            "access_token": token,
                            "token_type": "Bearer",
                            "expires_in": 300,
                            "scope": "nudm-sdm",
                        }))
                        .expect("token response")
                }
            })
            .await
            .expect("stub NRF starts");
        (server, port)
    }

    /// The producer: mTLS listener that requires an OAuth2 token whose audience
    /// is its own NF type, configured through the PRODUCTION profile.
    async fn start_producer(pki: &Pki, jwks: serde_json::Value) -> (SbiServer, u16) {
        let port = crate::test_support::free_port();
        let policy = SbiSecurityPolicy {
            tls_paths: TlsPaths {
                cert: pki.server_cert.clone(),
                key: pki.server_key.clone(),
                ca_cert: pki.ca.clone(),
                client_cert: Some(pki.client_cert.clone()),
                client_key: Some(pki.client_key.clone()),
                ..TlsPaths::default()
            },
            ..SbiSecurityPolicy::production()
        };
        let mut cfg = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
        // A static JWKS stands in for the NRF's live one, so the producer's
        // verification is exercised without a second network dependency.
        cfg.oauth2_jwks = Some(jwks);
        let cfg = apply_sbi_security_policy(
            cfg,
            SbiProfile::Production,
            &policy,
            NfType::Udm,
            "http://unused",
        )
        .expect("production profile applies");
        assert!(cfg.verify_client && cfg.require_oauth2);

        let server = SbiServer::new(cfg);
        server
            .start(|_req: SbiRequest| async move { SbiResponse::ok() })
            .await
            .expect("producer starts");
        (server, port)
    }

    fn consumer_config(pki: &Pki, port: u16) -> SbiClientConfig {
        let mut cfg = SbiClientConfig::new("localhost", port).with_https();
        cfg.ca_cert = Some(pki.ca.clone());
        cfg.client_cert = Some(pki.client_cert.clone());
        cfg.client_key = Some(pki.client_key.clone());
        cfg
    }

    /// The consumer config **as the NFs actually build it** — through
    /// `sbi_client_config_for_profile`, with the certificate paths supplied via
    /// the same env vars a deployment would use.
    ///
    /// [`consumer_config`] hand-builds the equivalent, which proves the transport
    /// works but not that the helper the NFs call produces it. This closes that
    /// gap: if the helper stopped setting `https`, or dropped the client
    /// certificate, this test would fail where the hand-built one would not.
    /// Serialised because it mutates process environment.
    fn consumer_config_via_profile_helper(pki: &Pki, port: u16) -> SbiClientConfig {
        static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(TlsPaths::CA_ENV, &pki.ca);
        std::env::set_var(TlsPaths::CLIENT_CERT_ENV, &pki.client_cert);
        std::env::set_var(TlsPaths::CLIENT_KEY_ENV, &pki.client_key);
        let cfg = sbi_client_config_for_profile("localhost", port, SbiProfile::Production);
        std::env::remove_var(TlsPaths::CA_ENV);
        std::env::remove_var(TlsPaths::CLIENT_CERT_ENV);
        std::env::remove_var(TlsPaths::CLIENT_KEY_ENV);
        cfg
    }

    /// **Issue #63, the outbound half of criterion 1.** The transaction succeeds
    /// with the consumer built by the profile helper the NFs call — not by hand.
    ///
    /// Before this, the four core NFs dialled peers with `SbiClient::with_host_port`
    /// (cleartext http, no client certificate) while their own listeners required
    /// mutually-authenticated TLS, so a call between two production-profile NFs
    /// failed at the TLS layer. That made the production default a configuration
    /// that could not work.
    #[tokio::test]
    async fn peer_client_built_by_the_profile_helper_completes_the_transaction() {
        let pki = pki("helper");
        let signing = crate::oauth::generate_es256_key();
        let token = mint_token(&signing, "UDM", "nudm-sdm");

        let (nrf, nrf_port) = start_stub_nrf(token).await;
        let (producer, producer_port) = start_producer(&pki, jwks(signing.verifying_key())).await;

        let cfg = consumer_config_via_profile_helper(&pki, producer_port);
        // The helper must have produced a TLS config carrying THIS NF's client
        // certificate; without the certificate the mTLS listener refuses it, and
        // without https it never gets that far.
        assert_eq!(cfg.scheme, crate::types::UriScheme::Https);
        assert!(cfg.client_cert.is_some() && cfg.client_key.is_some());

        let oauth2 = Arc::new(OAuth2Client::new(
            format!("http://127.0.0.1:{nrf_port}"),
            "consumer-1",
            NfType::Amf,
        ));
        let resp = SbiClient::new(cfg)
            .with_oauth2(oauth2, NfType::Udm)
            .send_request(SbiRequest::get("/nudm-sdm/v1/imsi-001010000000001/am-data"))
            .await
            .expect("the profile-built peer client must complete the transaction");
        assert_eq!(resp.status, 200);

        producer.stop().await.ok();
        nrf.stop().await.ok();
    }

    /// Issue #63: under the dev profile the peer client is byte-identical to
    /// today's cleartext one, so existing deployments and tests are untouched.
    #[test]
    fn dev_profile_peer_client_stays_cleartext() {
        let cfg = sbi_client_config_for_profile("peer", 7777, SbiProfile::Dev);
        assert_eq!(cfg.scheme, crate::types::UriScheme::Http);
        assert!(cfg.ca_cert.is_none());
        assert!(cfg.client_cert.is_none() && cfg.client_key.is_none());
        assert_eq!(cfg.base_uri(), "http://peer:7777");
    }

    #[tokio::test]
    async fn sbi_transaction_over_mtls_with_oauth2_end_to_end() {
        let pki = pki("ok");
        let signing = crate::oauth::generate_es256_key();
        let token = mint_token(&signing, "UDM", "nudm-sdm");

        let (nrf, nrf_port) = start_stub_nrf(token).await;
        let (producer, producer_port) = start_producer(&pki, jwks(signing.verifying_key())).await;

        // The consumer authenticates at the transport with its client certificate
        // and carries an NRF-issued token it fetched over the wire.
        let oauth2 = Arc::new(OAuth2Client::new(
            format!("http://127.0.0.1:{nrf_port}"),
            "consumer-1",
            NfType::Amf,
        ));
        let client =
            SbiClient::new(consumer_config(&pki, producer_port)).with_oauth2(oauth2, NfType::Udm);

        let resp = client
            .send_request(SbiRequest::get("/nudm-sdm/v1/imsi-001010000000001/am-data"))
            .await
            .expect("the mTLS + OAuth2 transaction must complete");
        assert_eq!(
            resp.status, 200,
            "authenticated request over mTLS must be served"
        );

        producer.stop().await.ok();
        nrf.stop().await.ok();
    }

    /// **The negative case criterion 6 names.** With the token endpoint down, the
    /// transaction must FAIL — not proceed unauthenticated.
    ///
    /// This guards PR 181's fix from the outside: before it, token-acquisition
    /// failure logged a warning and sent the request anyway, so an operator who
    /// had configured OAuth2 could silently lose SBI authentication. Here the
    /// producer would then reject it 401, which looks like a token problem rather
    /// than a client that gave up on authenticating.
    #[tokio::test]
    async fn transaction_fails_when_the_token_endpoint_is_unavailable() {
        let pki = pki("notoken");
        let signing = crate::oauth::generate_es256_key();
        let (producer, producer_port) = start_producer(&pki, jwks(signing.verifying_key())).await;

        // Port 1 on loopback: nothing listens, so token acquisition cannot succeed.
        let oauth2 = Arc::new(OAuth2Client::new(
            "http://127.0.0.1:1",
            "consumer-1",
            NfType::Amf,
        ));
        let client =
            SbiClient::new(consumer_config(&pki, producer_port)).with_oauth2(oauth2, NfType::Udm);

        let err = client
            .send_request(SbiRequest::get("/nudm-sdm/v1/imsi-001010000000001/am-data"))
            .await
            .expect_err("an unobtainable token must fail the call, not downgrade it");
        assert!(
            matches!(err, SbiError::AuthenticationFailed(_)),
            "the failure must name authentication, so it is distinguishable from a \
             transport error and from a producer rejection: {err:?}"
        );

        producer.stop().await.ok();
    }

    /// Issue #63 criterion 3: a request carrying NO token is rejected by a
    /// production-profile producer, even though its client certificate verified.
    /// Transport authentication is not service authorisation.
    #[tokio::test]
    async fn producer_rejects_a_request_with_no_access_token() {
        let pki = pki("notok");
        let signing = crate::oauth::generate_es256_key();
        let (producer, producer_port) = start_producer(&pki, jwks(signing.verifying_key())).await;

        // Same mTLS identity, but no OAuth2 client -> no Authorization header.
        let client = SbiClient::new(consumer_config(&pki, producer_port));
        let resp = client
            .send_request(SbiRequest::get("/nudm-sdm/v1/imsi-001010000000001/am-data"))
            .await
            .expect("the connection itself succeeds; the request is refused");
        assert_eq!(
            resp.status, 401,
            "a tokenless request must be refused by a producer that requires OAuth2"
        );

        producer.stop().await.ok();
    }

    /// Issue #63 criterion 1: the client CERTIFICATE is genuinely required, not
    /// merely accepted when offered.
    ///
    /// Without this case the rest of this module would pass just as happily
    /// against `verify_client = false` — a TLS-only listener serves a client that
    /// brings no certificate, so "mTLS" would be untested. A TLS client that
    /// trusts the CA but presents no certificate of its own must be refused at
    /// the handshake.
    #[tokio::test]
    async fn tls_client_without_a_certificate_is_refused() {
        let pki = pki("noclientcert");
        let signing = crate::oauth::generate_es256_key();
        let (producer, producer_port) = start_producer(&pki, jwks(signing.verifying_key())).await;

        // https and the right CA, but no client_cert/client_key.
        let mut cfg = SbiClientConfig::new("localhost", producer_port).with_https();
        cfg.ca_cert = Some(pki.ca.clone());
        let result = SbiClient::new(cfg)
            .send_request(SbiRequest::get("/nudm-sdm/v1/imsi-001010000000001/am-data"))
            .await;
        assert!(
            result.is_err(),
            "an mTLS listener must refuse a client that presents no certificate, but got \
             {:?}",
            result.map(|r| r.status)
        );

        producer.stop().await.ok();
    }

    /// Issue #63 criterion 2, second half: a cleartext h2c client cannot talk to
    /// a production-profile listener. This is what "a plaintext connection to a
    /// core NF producer is refused" means in practice.
    #[tokio::test]
    async fn cleartext_client_cannot_reach_a_tls_producer() {
        let pki = pki("plain");
        let signing = crate::oauth::generate_es256_key();
        let (producer, producer_port) = start_producer(&pki, jwks(signing.verifying_key())).await;

        // http:// against an https listener.
        let plain = SbiClient::with_host_port("127.0.0.1", producer_port);
        let result = plain
            .send_request(SbiRequest::get("/nudm-sdm/v1/imsi-001010000000001/am-data"))
            .await;
        assert!(
            result.is_err(),
            "cleartext h2c must not be served by a TLS listener, but got {:?}",
            result.map(|r| r.status)
        );

        producer.stop().await.ok();
    }
}

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
        let claims = authorize_sbi_request(Some(&auth), "nsmf-pdusession", "SMF", &policy, &jwks)
            .expect("signed token authorizes")
            .expect("claims returned");
        assert_eq!(claims.iss, "nrf-instance-1");
        assert_eq!(claims.sub, "amf-instance-1");

        // Wrong scope is rejected even with a valid signature.
        assert!(authorize_sbi_request(Some(&auth), "nausf-auth", "SMF", &policy, &jwks).is_err());

        // A token whose signature does not verify is rejected: there is no
        // signature-skipping path anymore.
        let mut tampered = token.clone();
        tampered.replace_range(0..1, "f");
        let tampered_auth = format!("Bearer {tampered}");
        assert!(authorize_sbi_request(
            Some(&tampered_auth),
            "nsmf-pdusession",
            "SMF",
            &policy,
            &jwks
        )
        .is_err());

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
        assert!(authorize_sbi_request(
            Some(&forged_auth),
            "nsmf-pdusession",
            "SMF",
            &policy,
            &jwks
        )
        .is_err());

        // Expired token is rejected.
        let (expired, jwks2) = signed_token_and_jwks("nsmf-pdusession", 1);
        let expired_auth = format!("Bearer {expired}");
        assert!(authorize_sbi_request(
            Some(&expired_auth),
            "nsmf-pdusession",
            "SMF",
            &policy,
            &jwks2
        )
        .is_err());
    }

    #[test]
    fn test_authorize_sbi_request_not_required() {
        let policy = SbiSecurityPolicy::development();
        let jwks = serde_json::json!({"keys": []});
        let result = authorize_sbi_request(None, "any-scope", "SMF", &policy, &jwks);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_authorize_sbi_request_missing_header() {
        let policy = SbiSecurityPolicy::production();
        let jwks = serde_json::json!({"keys": []});
        let result = authorize_sbi_request(None, "nsmf-pdusession", "SMF", &policy, &jwks);
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
        assert!(!groups.iter().any(|s| s.contains("MLKEM")));
    }

    #[test]
    fn test_pqc_tls_config_enabled() {
        let pqc = PqcTlsConfig::enabled();
        assert!(pqc.enabled);
        // TLS 1.3 keeps standard suites: the hybrid lives in the kx groups.
        let suites = pqc.cipher_suite_names();
        assert!(!suites.iter().any(|s| s.contains("MLKEM")));
        let groups = pqc.kex_group_names();
        assert_eq!(groups[0], "X25519MLKEM768");
        // Signatures stay classical until rustls ships ML-DSA support.
        let algs = pqc.sig_alg_names();
        assert!(!algs.iter().any(|s| s.contains("mldsa")));
    }

    #[test]
    fn test_tls_paths_default() {
        let paths = TlsPaths::default();
        assert!(paths.cert.contains("server.crt"));
        assert!(paths.key.contains("server.key"));
        assert!(paths.ca_cert.contains("ca.crt"));
    }
}

#[cfg(test)]
mod audience_binding_guards {
    /// Issue #64 gap 3: every NF that enforces OAuth2 must also assert the token's
    /// audience, or it accepts tokens the NRF minted for a different producer.
    ///
    /// This guard is the thing that would have caught the UDR: 15 daemons set
    /// `require_oauth2 = true` and only 13 set an expected audience, and nothing
    /// compared the two lists. Read from the daemon sources so a new NF cannot enable
    /// enforcement without making an explicit choice about `aud`.
    #[test]
    fn every_oauth2_enforcing_nf_asserts_an_audience() {
        // pind is deliberately exempt AND documents why in-source: it is not a
        // TS 29.510 NfType, so there is no NF-type `aud` for the NRF to mint or for
        // it to assert. Any other exemption must be argued the same way, here.
        const DOCUMENTED_EXEMPTIONS: &[&str] = &["nextgcore-pind"];

        let bins = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crate is at <root>/libs/nextgcore-sbi")
            .join("bins");
        assert!(bins.is_dir(), "expected {} to exist", bins.display());

        let mut enforcing = Vec::new();
        let mut asserting = Vec::new();

        for entry in std::fs::read_dir(&bins).expect("read bins/") {
            let path = entry.expect("dir entry").path();
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let src = path.join("src");
            if !src.is_dir() {
                continue;
            }
            let mut enforces = false;
            let mut asserts = false;
            for file in std::fs::read_dir(&src).expect("read src/") {
                let f = file.expect("file entry").path();
                if f.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&f).unwrap_or_default();
                if text.contains("require_oauth2 = true") {
                    enforces = true;
                }
                if text.contains("with_expected_audience") {
                    asserts = true;
                }
            }
            if enforces && !DOCUMENTED_EXEMPTIONS.contains(&name.as_str()) {
                enforcing.push(name.clone());
                if asserts {
                    asserting.push(name);
                }
            }
        }

        assert!(
            !enforcing.is_empty(),
            "expected to find NFs enforcing OAuth2; the guard found none, so it is no \
             longer checking anything"
        );
        enforcing.sort();
        asserting.sort();
        assert_eq!(
            enforcing, asserting,
            "these NFs verify OAuth2 tokens WITHOUT asserting the audience, so a token \
             minted for another producer is accepted (TS 33.501 13.4.1.2). Set \
             with_expected_audience_nf_type(<own NfType>), or add a documented \
             exemption to this guard explaining why the NF has no NF-type aud."
        );
    }

    /// **Issue #63 criterion 1.** Each of the four core NFs applies the SBI
    /// security profile at startup.
    ///
    /// The library-level E2E in `mtls_oauth2_e2e` proves the mTLS + OAuth2 path
    /// works; it cannot prove that amfd/smfd/ausfd/udmd actually reach it, because
    /// each builds its listener at its own site and CI skips the Docker E2E that
    /// would run the real daemons. This guard closes that gap by reading their
    /// sources — the same shape as the audience guard above, and the reason it is
    /// a guard rather than a comment is that a future refactor of any one of these
    /// four startup paths could silently drop the call and leave that NF back on
    /// cleartext h2c with no test failing.
    #[test]
    fn every_core_nf_applies_the_sbi_profile() {
        const CORE_NFS: &[&str] = &[
            "nextgcore-amfd",
            "nextgcore-smfd",
            "nextgcore-ausfd",
            "nextgcore-udmd",
        ];

        let bins = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crate is at <root>/libs/nextgcore-sbi")
            .join("bins");

        let mut missing = Vec::new();
        for nf in CORE_NFS {
            let src = bins.join(nf).join("src");
            assert!(src.is_dir(), "expected {} to exist", src.display());
            let mut applies = false;
            for file in std::fs::read_dir(&src).expect("read src/") {
                let f = file.expect("file entry").path();
                if f.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&f).unwrap_or_default();
                if text.contains("apply_sbi_security_profile") {
                    applies = true;
                }
            }
            if !applies {
                missing.push(*nf);
            }
        }

        assert!(
            missing.is_empty(),
            "these core NFs never apply the SBI security profile, so they serve cleartext \
             h2c with no access-token verification regardless of {}: {missing:?}. Call \
             nextgcore_sbi::security::apply_sbi_security_profile on the SbiServerConfig \
             before building the SbiServer.",
            crate::security::SBI_PROFILE_ENV
        );
    }

    /// **Issue #63, the outbound half of criterion 1.** The files that hold the
    /// core NFs' peer-call code must not build cleartext clients.
    ///
    /// `SbiClient::with_host_port` is plain http always, on purpose — tests that
    /// start a loopback plaintext server need it. That makes it exactly the thing
    /// a future edit could reach for in production code without noticing, putting
    /// that NF back to dialling cleartext while its own listener demands mTLS.
    /// These two files contain only peer-call code (their test modules use
    /// separate helpers), so a hit here is unambiguous.
    #[test]
    fn core_nf_peer_call_paths_do_not_build_cleartext_clients() {
        let bins = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crate is at <root>/libs/nextgcore-sbi")
            .join("bins");

        // (file, first line of its test module) — everything before it is
        // production peer-call code.
        let files = [
            ("nextgcore-amfd/src/sbi_path.rs", "mod tests {"),
            ("nextgcore-smfd/src/policy.rs", "mod tests {"),
        ];
        for (rel, test_marker) in files {
            let path = bins.join(rel);
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let production = match text.find(test_marker) {
                Some(i) => &text[..i],
                None => &text[..],
            };
            assert!(
                !production.contains("SbiClient::with_host_port"),
                "{rel} builds a peer client with SbiClient::with_host_port, which is \
                 cleartext http with no client certificate regardless of the SBI security \
                 profile. Use SbiClient::for_peer (or \
                 security::sbi_peer_client_config) so the call follows the profile."
            );
            assert!(
                production.contains("for_peer") || production.contains("sbi_peer_client_config"),
                "{rel} should reach peers through the profile-aware helper; if its peer \
                 calls moved elsewhere, move this guard with them rather than deleting it"
            );
        }
    }

    /// Issue #63 criterion 2: amfd must not hardcode the scheme it advertises.
    ///
    /// The AMF publishes its own endpoint in its NFProfile and in the callback
    /// URIs it registers with peers. If those keep saying `http` while the
    /// listener moves to TLS, peers discover an unusable URL and the failure
    /// surfaces on THEIR side as a connection error, with nothing pointing back at
    /// the AMF's registration. A literal `"scheme": "http"` is therefore a defect,
    /// not a default.
    #[test]
    fn amfd_does_not_hardcode_its_advertised_scheme() {
        let sbi_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crate is at <root>/libs/nextgcore-sbi")
            .join("bins/nextgcore-amfd/src/sbi_path.rs");
        let text = std::fs::read_to_string(&sbi_path).expect("read amfd sbi_path.rs");

        assert!(
            !text.contains(r#""scheme": "http""#),
            "amfd advertises a hardcoded http scheme in its NFProfile; it must follow the \
             listener via advertised_sbi_scheme()"
        );
        assert!(
            !text.contains(r#"format!("http://{addr}:{port}")"#),
            "amfd builds a hardcoded http:// base URL; it must follow the listener via \
             advertised_sbi_scheme()"
        );
        assert!(
            text.contains("fn advertised_sbi_scheme"),
            "the scheme helper must exist for the two sites above to use"
        );
    }

    /// Issue #64 gaps 1+2: every NF acquires its OAuth2 client through
    /// `OAuth2Client::new`, which is where the process-wide CCA signing key is
    /// seeded — so a deployment turns on client authentication in ONE place.
    ///
    /// A struct literal would bypass that seeding silently: the NF would still
    /// compile, still request tokens, and be rejected by an NRF running its
    /// default policy with nothing pointing at the cause. This is the same failure
    /// shape as the `--kill` flag that was duplicated across 12 daemons and
    /// therefore wrong in 12 places at once.
    #[test]
    fn every_nf_builds_its_oauth2_client_through_the_shared_constructor() {
        let bins = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crate is at <root>/libs/nextgcore-sbi")
            .join("bins");
        assert!(bins.is_dir(), "expected {} to exist", bins.display());

        let mut constructing = Vec::new();
        let mut bypassing = Vec::new();

        for entry in std::fs::read_dir(&bins).expect("read bins/") {
            let path = entry.expect("dir entry").path();
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let src = path.join("src");
            if !src.is_dir() {
                continue;
            }
            for file in std::fs::read_dir(&src).expect("read src/") {
                let f = file.expect("file entry").path();
                if f.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&f).unwrap_or_default();
                if text.contains("OAuth2Client::new") {
                    constructing.push(name.clone());
                }
                // A struct literal skips `new`, so it skips the key seeding.
                if text.contains("OAuth2Client {") {
                    bypassing.push(name.clone());
                }
            }
        }

        assert!(
            !constructing.is_empty(),
            "expected to find NFs constructing an OAuth2Client; the guard found none, so \
             it is no longer checking anything"
        );
        bypassing.sort();
        bypassing.dedup();
        assert!(
            bypassing.is_empty(),
            "these NFs build an OAuth2Client by struct literal, bypassing \
             OAuth2Client::new and therefore the process-wide CCA signing key: {bypassing:?}. \
             They would request tokens with no client authentication and be rejected by an \
             NRF running its default policy. Use OAuth2Client::new (plus \
             with_cca_signing_key when a per-instance key is wanted)."
        );
    }
}
