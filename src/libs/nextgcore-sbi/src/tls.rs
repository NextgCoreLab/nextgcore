//! TLS utilities for SBI client and server
//!
//! Provides certificate loading, key loading, and rustls configuration
//! builders for TLS and mTLS on the SBI interface.
//!
//! Research/future-direction additions (not in any frozen 3GPP release; no Rel-20 stage-3 spec exists):
//! - Post-Quantum Cryptography (PQC) TLS 1.3 support (NIST FIPS 203/204 algorithms)
//! - Hybrid key exchange (X25519 + ML-KEM-768)
//! - PQC signature algorithms (ML-DSA-65)
//! - Certificate chain validation with PQC

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig, SignatureScheme};

use crate::error::{SbiError, SbiResult};

// ============================================================================
// Post-Quantum Cryptography (PQC) Support
// Research/future-direction — not in any frozen 3GPP release (no Rel-20 stage-3 spec exists).
// Algorithms follow NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA).
// ============================================================================

/// PQC cipher suite support for TLS 1.3
/// These represent the NIST-standardized ML-KEM and ML-DSA algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqcCipherSuite {
    /// ML-KEM-768 (NIST FIPS 203) - Medium security quantum-resistant KEM
    MlKem768,
    /// Hybrid: X25519 + ML-KEM-768 (recommended for transition period)
    HybridX25519MlKem768,
}

/// PQC signature scheme support
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqcSignatureScheme {
    /// ML-DSA-65 (NIST FIPS 204) - Medium security quantum-resistant signature
    MlDsa65,
    /// Hybrid: ECDSA P-256 + ML-DSA-65 (recommended for transition period)
    HybridEcdsaP256MlDsa65,
}

/// PQC TLS configuration
#[derive(Debug, Clone)]
pub struct PqcTlsConfig {
    /// Enable PQC cipher suites
    pub enabled: bool,
    /// Preferred cipher suite
    pub cipher_suite: PqcCipherSuite,
    /// Preferred signature scheme
    pub signature_scheme: PqcSignatureScheme,
    /// Allow fallback to classical algorithms if peer doesn't support PQC
    pub allow_fallback: bool,
}

impl Default for PqcTlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cipher_suite: PqcCipherSuite::HybridX25519MlKem768,
            signature_scheme: PqcSignatureScheme::HybridEcdsaP256MlDsa65,
            allow_fallback: true,
        }
    }
}

impl PqcTlsConfig {
    /// Create PQC config with hybrid mode (recommended for production)
    pub fn hybrid() -> Self {
        Self {
            enabled: true,
            cipher_suite: PqcCipherSuite::HybridX25519MlKem768,
            signature_scheme: PqcSignatureScheme::HybridEcdsaP256MlDsa65,
            allow_fallback: true,
        }
    }

    /// Create PQC config with pure post-quantum mode (future-proof)
    pub fn pure_pqc() -> Self {
        Self {
            enabled: true,
            cipher_suite: PqcCipherSuite::MlKem768,
            signature_scheme: PqcSignatureScheme::MlDsa65,
            allow_fallback: false,
        }
    }
}

/// Get supported PQC signature schemes for rustls
fn get_pqc_signature_schemes(config: &PqcTlsConfig) -> Vec<SignatureScheme> {
    let mut schemes = Vec::new();

    if config.enabled {
        // Key exchange is the real PQC surface (see `select_provider`, which
        // negotiates X25519MLKEM768 under the `pqc-tls` feature). Signature
        // schemes remain classical: rustls 0.23 ships no ML-DSA certificate
        // support, so the hybrid choice maps to ECDSA P-256 for now.
        match config.signature_scheme {
            PqcSignatureScheme::MlDsa65 => {
                log::debug!("PQC: ML-DSA-65 signature requested (unsupported: rustls 0.23 ships no ML-DSA certificates; staying classical)");
            }
            PqcSignatureScheme::HybridEcdsaP256MlDsa65 => {
                // Use ECDSA P-256 for now, with planned ML-DSA-65 hybrid
                schemes.push(SignatureScheme::ECDSA_NISTP256_SHA256);
                log::debug!("PQC: Hybrid ECDSA P-256 + ML-DSA-65 (using ECDSA for now)");
            }
        }
    }

    // Classical algorithms (always include for compatibility)
    schemes.extend_from_slice(&[
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::ED25519,
    ]);

    schemes
}

/// Get the ring crypto provider.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Select the crypto provider for a PQC-aware builder (issue #17,
/// non-normative — no frozen 3GPP Stage-3 covers PQC TLS).
///
/// With the `pqc-tls` feature compiled in and `pqc_config.enabled`, returns
/// the rustls aws-lc-rs provider with the requested ML-KEM key-exchange group
/// first (`X25519MLKEM768` for the hybrid suite, pure `MLKEM768` otherwise);
/// `allow_fallback` keeps the classical groups after it. In every other case
/// this is exactly the default ring provider, byte-for-byte the pre-existing
/// behaviour.
#[cfg(feature = "pqc-tls")]
fn select_provider(pqc_config: &PqcTlsConfig) -> Arc<rustls::crypto::CryptoProvider> {
    use rustls::crypto::aws_lc_rs::kx_group;

    if !pqc_config.enabled {
        return provider();
    }
    let preferred: &'static dyn rustls::crypto::SupportedKxGroup = match pqc_config.cipher_suite {
        PqcCipherSuite::HybridX25519MlKem768 => kx_group::X25519MLKEM768,
        PqcCipherSuite::MlKem768 => kx_group::MLKEM768,
    };
    let mut pqc_provider = rustls::crypto::aws_lc_rs::default_provider();
    pqc_provider.kx_groups = if pqc_config.allow_fallback {
        vec![
            preferred,
            kx_group::X25519,
            kx_group::SECP256R1,
            kx_group::SECP384R1,
        ]
    } else {
        vec![preferred]
    };
    Arc::new(pqc_provider)
}

/// Without the `pqc-tls` feature the PQC-aware builders compile to exactly
/// the classical ring path.
#[cfg(not(feature = "pqc-tls"))]
fn select_provider(_pqc_config: &PqcTlsConfig) -> Arc<rustls::crypto::CryptoProvider> {
    provider()
}

/// Load PEM-encoded certificates from a file path.
pub fn load_certs(path: &str) -> SbiResult<Vec<CertificateDer<'static>>> {
    let file = File::open(path)
        .map_err(|e| SbiError::TlsError(format!("Failed to open cert file {path}: {e}")))?;
    let mut reader = BufReader::new(file);

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| SbiError::TlsError(format!("Failed to parse certs from {path}: {e}")))?;

    if certs.is_empty() {
        return Err(SbiError::TlsError(format!(
            "No certificates found in {path}"
        )));
    }

    Ok(certs)
}

/// Load a PEM-encoded private key from a file path.
pub fn load_private_key(path: &str) -> SbiResult<PrivateKeyDer<'static>> {
    let file = File::open(path)
        .map_err(|e| SbiError::TlsError(format!("Failed to open key file {path}: {e}")))?;
    let mut reader = BufReader::new(file);

    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| SbiError::TlsError(format!("Failed to parse key from {path}: {e}")))?
        .ok_or_else(|| SbiError::TlsError(format!("No private key found in {path}")))?;

    Ok(key)
}

/// Build a `RootCertStore` from a CA certificate file.
fn load_root_store(ca_path: &str) -> SbiResult<RootCertStore> {
    let ca_certs = load_certs(ca_path)?;
    let mut root_store = RootCertStore::empty();
    for cert in ca_certs {
        root_store
            .add(cert)
            .map_err(|e| SbiError::TlsError(format!("Failed to add CA cert: {e}")))?;
    }
    Ok(root_store)
}

/// Build a server-side TLS config (no client auth).
pub fn build_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> SbiResult<ServerConfig> {
    build_server_config_with_pqc(certs, key, &PqcTlsConfig::default())
}

/// Build a server-side TLS config with PQC support (no client auth).
pub fn build_server_config_with_pqc(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    pqc_config: &PqcTlsConfig,
) -> SbiResult<ServerConfig> {
    let config = ServerConfig::builder_with_provider(select_provider(pqc_config))
        .with_safe_default_protocol_versions()
        .map_err(|e| SbiError::TlsError(format!("Failed to set protocol versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| SbiError::TlsError(format!("Failed to build server TLS config: {e}")))?;

    if pqc_config.enabled {
        log::info!(
            "PQC TLS enabled: cipher={:?}, sig={:?}, fallback={}",
            pqc_config.cipher_suite,
            pqc_config.signature_scheme,
            pqc_config.allow_fallback
        );
        // Key-exchange group selection happened in `select_provider` above;
        // under `--features pqc-tls` this handshake offers X25519MLKEM768.
    }

    Ok(config)
}

/// Build a server-side TLS config with mutual TLS (client certificate verification).
pub fn build_server_config_mtls(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_ca_path: &str,
) -> SbiResult<ServerConfig> {
    build_server_config_mtls_with_pqc(certs, key, client_ca_path, &PqcTlsConfig::default())
}

/// Build a server-side TLS config with mTLS and PQC support.
pub fn build_server_config_mtls_with_pqc(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_ca_path: &str,
    pqc_config: &PqcTlsConfig,
) -> SbiResult<ServerConfig> {
    let root_store = load_root_store(client_ca_path)?;

    // builder() would resolve the ambient process-default CryptoProvider,
    // which is ambiguous in this workspace (tokio-rustls enables aws-lc-rs
    // beside our ring pin) and panics at runtime — pass the provider
    // explicitly, same as every config builder in this module.
    let client_verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(root_store),
        select_provider(pqc_config),
    )
    .build()
    .map_err(|e| SbiError::TlsError(format!("Failed to build client verifier: {e}")))?;

    let config = ServerConfig::builder_with_provider(select_provider(pqc_config))
        .with_safe_default_protocol_versions()
        .map_err(|e| SbiError::TlsError(format!("Failed to set protocol versions: {e}")))?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)
        .map_err(|e| SbiError::TlsError(format!("Failed to build mTLS server config: {e}")))?;

    if pqc_config.enabled {
        log::info!(
            "PQC mTLS enabled: cipher={:?}, sig={:?}",
            pqc_config.cipher_suite,
            pqc_config.signature_scheme
        );
        // Certificate chains remain classical (no ML-DSA certificate
        // support in rustls 0.23); only the key exchange is hybrid.
    }

    Ok(config)
}

/// Build a client-side TLS config (server auth only, no client cert).
pub fn build_client_config(
    ca_path: Option<&str>,
    insecure_skip_verify: bool,
) -> SbiResult<ClientConfig> {
    build_client_config_with_pqc(ca_path, insecure_skip_verify, &PqcTlsConfig::default())
}

/// Build a client-side TLS config with PQC support (server auth only, no client cert).
pub fn build_client_config_with_pqc(
    ca_path: Option<&str>,
    insecure_skip_verify: bool,
    pqc_config: &PqcTlsConfig,
) -> SbiResult<ClientConfig> {
    let mut root_store = RootCertStore::empty();

    if let Some(ca) = ca_path {
        let ca_certs = load_certs(ca)?;
        for cert in ca_certs {
            root_store
                .add(cert)
                .map_err(|e| SbiError::TlsError(format!("Failed to add CA cert: {e}")))?;
        }
    } else {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let mut config = ClientConfig::builder_with_provider(select_provider(pqc_config))
        .with_safe_default_protocol_versions()
        .map_err(|e| SbiError::TlsError(format!("Failed to set protocol versions: {e}")))?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config.alpn_protocols = vec![b"h2".to_vec()];

    if pqc_config.enabled {
        log::info!(
            "PQC TLS client: cipher={:?}, sig={:?}",
            pqc_config.cipher_suite,
            pqc_config.signature_scheme
        );
        // Key-exchange group selection happened in `select_provider` above.
    }

    if insecure_skip_verify {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoCertificateVerification));
    }

    Ok(config)
}

/// Build a client-side TLS config with client certificate (mTLS).
pub fn build_client_config_mtls(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    ca_path: Option<&str>,
    insecure_skip_verify: bool,
) -> SbiResult<ClientConfig> {
    build_client_config_mtls_with_pqc(
        certs,
        key,
        ca_path,
        insecure_skip_verify,
        &PqcTlsConfig::default(),
    )
}

/// Build a client-side TLS config with mTLS and PQC support.
pub fn build_client_config_mtls_with_pqc(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    ca_path: Option<&str>,
    insecure_skip_verify: bool,
    pqc_config: &PqcTlsConfig,
) -> SbiResult<ClientConfig> {
    let mut root_store = RootCertStore::empty();

    if let Some(ca) = ca_path {
        let ca_certs = load_certs(ca)?;
        for cert in ca_certs {
            root_store
                .add(cert)
                .map_err(|e| SbiError::TlsError(format!("Failed to add CA cert: {e}")))?;
        }
    } else {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let mut config = ClientConfig::builder_with_provider(select_provider(pqc_config))
        .with_safe_default_protocol_versions()
        .map_err(|e| SbiError::TlsError(format!("Failed to set protocol versions: {e}")))?
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .map_err(|e| SbiError::TlsError(format!("Failed to set client cert: {e}")))?;

    config.alpn_protocols = vec![b"h2".to_vec()];

    if pqc_config.enabled {
        log::info!(
            "PQC mTLS client: cipher={:?}, sig={:?}",
            pqc_config.cipher_suite,
            pqc_config.signature_scheme
        );
        // Key-exchange selection happened in `select_provider`; the client
        // certificate remains classical (no ML-DSA in rustls 0.23).
    }

    if insecure_skip_verify {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoCertificateVerification));
    }

    Ok(config)
}

// ============================================================================
// TLS exporter (RFC 5705) — N32-f session-key derivation dependency (B2/SEPP)
// ============================================================================

/// RFC 5705 / TS 33.501 §13.2.4.4 exporter label SEPP uses to derive the
/// N32-f PRINS session key from the N32-c TLS connection. B2 should pass this
/// as the `label` to [`export_keying_material`].
pub const N32F_EXPORTER_LABEL: &[u8] = b"EXPORTER-3GPP-N32f-Session-Key";

/// Default length, in bytes, of the keying material SEPP exports for the
/// N32-f session key (256-bit / AES-256-GCM-class secret).
pub const N32F_EXPORTER_KEY_LEN: usize = 32;

/// TS 33.501 §13.2.4.4.1 exporter label for the 64-octet N32 master key.
/// This is the RFC 5705 label whose exported material is the PRK ("master")
/// fed into the N32-KDF (HKDF-Expand) that produces the four N32-f session
/// keys and IV salts. The two SEPPs share this master because both ends of
/// the N32-c TLS connection export identical keying material.
pub const N32_MASTER_EXPORTER_LABEL: &[u8] = b"EXPORTER_3GPP_N32_MASTER";

/// Length, in bytes, of the N32 master key exported from the N32-c TLS
/// connection (512-bit, per TS 33.501 §13.2.4.4.1). A 64-octet PRK satisfies
/// HKDF's `from_prk` requirement (PRK length >= HashLen = 32 for SHA-256).
pub const N32_MASTER_KEY_LEN: usize = 64;

/// Export `len` bytes of keying material from an established rustls connection
/// per RFC 5705 ("Keying Material Exporters for TLS").
///
/// This is the additive accessor SEPP uses to derive the N32-f key hierarchy
/// from the N32-c TLS exporter (TS 33.501 §13.2.4.4.1); the glue uses
/// [`export_n32_master_key`] to obtain the 64-octet master fed into
/// `seppd::n32c_handler::derive_n32f_key_material`.
///
/// `conn` is the rustls connection obtained from the established TLS stream —
/// e.g. `tokio_rustls::server::TlsStream::get_ref().1` (a `&ServerConnection`)
/// or `client::TlsStream::get_ref().1` (a `&ClientConnection`). Both deref to
/// [`rustls::ConnectionCommon`], which carries `export_keying_material`.
///
/// `label` is the exporter label (use [`N32F_EXPORTER_LABEL`] for N32-f) and
/// `context` is the optional RFC 5705 context value. Fails if called before
/// the handshake completes or if `len` is zero.
///
/// # Example (what B2 should call)
/// ```ignore
/// // after `acceptor.accept(tcp).await?` yields a server TlsStream `tls`:
/// let (_io, conn) = tls.get_ref();
/// let key = nextgcore_sbi::tls::export_keying_material(
///     conn,
///     nextgcore_sbi::tls::N32F_EXPORTER_LABEL,
///     None,
///     nextgcore_sbi::tls::N32F_EXPORTER_KEY_LEN,
/// )?;
/// ```
pub fn export_keying_material<Data>(
    conn: &rustls::ConnectionCommon<Data>,
    label: &[u8],
    context: Option<&[u8]>,
    len: usize,
) -> SbiResult<Vec<u8>> {
    if len == 0 {
        return Err(SbiError::TlsError(
            "export_keying_material: requested length must be non-zero".into(),
        ));
    }
    let output = vec![0u8; len];
    conn.export_keying_material(output, label, context)
        .map_err(|e| SbiError::TlsError(format!("TLS keying-material export failed: {e}")))
}

/// Convenience wrapper deriving the N32-f session key from an N32-c TLS
/// connection using the N32-f exporter label and 32-byte length (B2/SEPP).
pub fn export_n32f_session_key<Data>(
    conn: &rustls::ConnectionCommon<Data>,
    context: Option<&[u8]>,
) -> SbiResult<Vec<u8>> {
    let output = vec![0u8; N32F_EXPORTER_KEY_LEN];
    conn.export_keying_material(output, N32F_EXPORTER_LABEL, context)
        .map_err(|e| SbiError::TlsError(format!("N32-f keying-material export failed: {e}")))
}

/// Export the 64-octet N32 master key from an established N32-c TLS
/// connection (TS 33.501 §13.2.4.4.1). This is the value SEPP deposits via
/// `set_n32c_tls_exporter_secret` and feeds, as the HKDF PRK, into the
/// N32-KDF that derives the four N32-f session keys + IV salts. Both N32-c
/// endpoints export an identical master, so both derive identical key
/// material. This is what the `client.rs`/`server.rs` exporter glue calls.
pub fn export_n32_master_key<Data>(
    conn: &rustls::ConnectionCommon<Data>,
    context: Option<&[u8]>,
) -> SbiResult<Vec<u8>> {
    let output = vec![0u8; N32_MASTER_KEY_LEN];
    conn.export_keying_material(output, N32_MASTER_EXPORTER_LABEL, context)
        .map_err(|e| SbiError::TlsError(format!("N32 master keying-material export failed: {e}")))
}

/// Dangerous: skip all server certificate verification (for testing only).
#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_certs_nonexistent_file() {
        let result = load_certs("/nonexistent/path.pem");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, SbiError::TlsError(_)));
    }

    #[test]
    fn test_load_key_nonexistent_file() {
        let result = load_private_key("/nonexistent/path.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_build_client_config_with_webpki_roots() {
        let config = build_client_config(None, false);
        assert!(config.is_ok());
        let cfg = config.unwrap();
        assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec()]);
    }

    #[test]
    fn test_build_client_config_insecure() {
        let config = build_client_config(None, true);
        assert!(config.is_ok());
    }

    // --- RFC 5705 TLS exporter (B2/SEPP N32-f dependency) ---

    #[test]
    fn test_export_keying_material_zero_len_rejected() {
        // The length guard rejects a zero-length request (RFC 5705 forbids it).
        let HandshakeOutput { server, .. } = test_handshake();
        let err = export_keying_material(&server, N32F_EXPORTER_LABEL, None, 0).unwrap_err();
        assert!(matches!(err, SbiError::TlsError(_)));
    }

    #[test]
    fn test_export_keying_material_agrees_across_peers() {
        let HandshakeOutput { client, server } = test_handshake();

        // Both peers derive the same N32-f session key from the shared TLS
        // secret (RFC 5705 / TS 33.501 §13.2.4.4).
        let client_key = export_n32f_session_key(&client, None).expect("client export");
        let server_key = export_n32f_session_key(&server, None).expect("server export");
        assert_eq!(client_key.len(), N32F_EXPORTER_KEY_LEN);
        assert_eq!(client_key, server_key);

        // A different label/context yields different material.
        let other = export_keying_material(&client, b"OTHER-LABEL", None, 32).expect("export");
        assert_ne!(other, client_key);

        // Context diversification: same label, different context => different key.
        let ctx_a = export_keying_material(&client, N32F_EXPORTER_LABEL, Some(b"a"), 32).unwrap();
        let ctx_b = export_keying_material(&client, N32F_EXPORTER_LABEL, Some(b"b"), 32).unwrap();
        assert_ne!(ctx_a, ctx_b);
    }

    // --- T1.5b: exporter extraction matches across server/client connections ---

    /// Verify that the label and length used by the server glue (sepp-00)
    /// produce the same 64-octet N32 master key as the client glue on the
    /// other end of the same handshake. This is the in-process analogue of
    /// the `get_ref()` path in `server.rs` and `client.rs`, which now call
    /// [`export_n32_master_key`] (TS 33.501 §13.2.4.4.1).
    #[test]
    fn test_server_and_client_exporter_match_via_get_ref_analogue() {
        let HandshakeOutput { client, server } = test_handshake();

        // Mimic what server.rs does after `acceptor.accept()`:
        //   let (_, server_conn) = tls_stream.get_ref();
        //   export_n32_master_key(server_conn, None)
        let server_secret = export_n32_master_key(&server, None)
            .expect("server-side N32 master exporter must succeed after handshake");

        // Mimic what client.rs does after `connector.connect()`:
        //   let (_, client_conn) = tls_stream.get_ref();
        //   export_n32_master_key(client_conn, None)
        let client_secret = export_n32_master_key(&client, None)
            .expect("client-side N32 master exporter must succeed after handshake");

        // Both ends use the exact same label (`N32_MASTER_EXPORTER_LABEL`) and
        // the same output length (`N32_MASTER_KEY_LEN = 64`), so RFC 5705
        // guarantees they produce identical material.
        assert_eq!(
            server_secret, client_secret,
            "server-side and client-side N32 master secrets must agree \
             (sepp-00 / TS 33.501 §13.2.4.4.1)"
        );
        assert_eq!(
            server_secret.len(),
            N32_MASTER_KEY_LEN,
            "exporter output must be exactly N32_MASTER_KEY_LEN (64) bytes"
        );

        // The label constant used by both glue paths must be
        // N32_MASTER_EXPORTER_LABEL. A different label produces different
        // material — confirming the label selection is significant.
        let wrong_label = export_keying_material(&server, b"WRONG-LABEL", None, N32_MASTER_KEY_LEN)
            .expect("export with wrong label");
        assert_ne!(
            server_secret, wrong_label,
            "different label must produce different material"
        );

        // The 64-octet master is also distinct from the legacy 32-octet
        // N32-f session-key export (different label and length).
        let legacy = export_n32f_session_key(&server, None).expect("legacy export");
        assert_eq!(legacy.len(), N32F_EXPORTER_KEY_LEN);
        assert_ne!(
            server_secret[..32],
            legacy[..],
            "master != legacy session key"
        );
    }

    /// Completed in-memory TLS 1.3 handshake, exposing both rustls connections
    /// for exporter testing.
    struct HandshakeOutput {
        client: rustls::ClientConnection,
        server: rustls::ServerConnection,
    }

    /// Perform a full in-memory rustls handshake with a self-signed cert and
    /// return both completed connections.
    fn test_handshake() -> HandshakeOutput {
        use rustls::pki_types::ServerName;

        // Self-signed leaf cert + key for "localhost".
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der()).expect("private key");

        let server_config = build_server_config(vec![cert_der.clone()], key_der).unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let client_config = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let server_name = ServerName::try_from("localhost").unwrap();
        let mut client =
            rustls::ClientConnection::new(Arc::new(client_config), server_name).unwrap();
        let mut server = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();

        // Pump handshake bytes between the two in-memory connections until
        // neither side wants to write more.
        for _ in 0..16 {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                server.read_tls(&mut buf.as_slice()).unwrap();
                server.process_new_packets().unwrap();
            }

            let mut buf2 = Vec::new();
            server.write_tls(&mut buf2).unwrap();
            if !buf2.is_empty() {
                client.read_tls(&mut buf2.as_slice()).unwrap();
                client.process_new_packets().unwrap();
            }

            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
        assert!(!client.is_handshaking(), "client handshake incomplete");
        assert!(!server.is_handshaking(), "server handshake incomplete");

        HandshakeOutput { client, server }
    }
}

#[cfg(all(test, feature = "pqc-tls"))]
mod pqc_tls_tests {
    use super::*;

    /// In-memory handshake through the real PQC-aware builders; returns the
    /// negotiated key-exchange group plus both peers' N32 exporter keys.
    fn pqc_handshake(pqc: &PqcTlsConfig) -> (rustls::NamedGroup, Vec<u8>, Vec<u8>) {
        use rustls::pki_types::ServerName;

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der()).expect("private key");

        let server_config =
            build_server_config_with_pqc(vec![cert_der], key_der, pqc).expect("server config");

        // Feed the self-signed cert through the real CA-path loading. The
        // dir must be unique per call: tests run in parallel in one process,
        // and a shared path races create/write against remove_dir_all.
        static DIR_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let seq = DIR_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("nextgcore-sbi-pqc-{}-{seq}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let ca_path = dir.join("ca.pem");
        std::fs::write(&ca_path, cert.cert.pem()).expect("write ca");
        let client_config =
            build_client_config_with_pqc(Some(ca_path.to_str().expect("ca path")), false, pqc)
                .expect("client config");
        let _ = std::fs::remove_dir_all(&dir);

        let server_name = ServerName::try_from("localhost").unwrap();
        let mut client =
            rustls::ClientConnection::new(Arc::new(client_config), server_name).unwrap();
        let mut server = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();

        for _ in 0..16 {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                server.read_tls(&mut buf.as_slice()).unwrap();
                server.process_new_packets().unwrap();
            }
            let mut buf2 = Vec::new();
            server.write_tls(&mut buf2).unwrap();
            if !buf2.is_empty() {
                client.read_tls(&mut buf2.as_slice()).unwrap();
                client.process_new_packets().unwrap();
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
        assert!(!client.is_handshaking(), "client handshake incomplete");
        assert!(!server.is_handshaking(), "server handshake incomplete");

        let group = client
            .negotiated_key_exchange_group()
            .expect("negotiated kx group")
            .name();
        let client_key = export_n32_master_key(&client, None).expect("client exporter");
        let server_key = export_n32_master_key(&server, None).expect("server exporter");
        (group, client_key, server_key)
    }

    /// Issue #17 acceptance: PQC enabled on both ends negotiates the hybrid
    /// X25519MLKEM768 group, and the N32-f exporter still agrees.
    #[test]
    fn pqc_enabled_negotiates_x25519mlkem768() {
        let (group, client_key, server_key) = pqc_handshake(&PqcTlsConfig::hybrid());
        assert_eq!(group, rustls::NamedGroup::X25519MLKEM768);
        assert_eq!(client_key, server_key, "N32 exporter keys must agree");
        assert_eq!(client_key.len(), N32_MASTER_KEY_LEN);
    }

    /// Issue #17 acceptance: with PQC disabled the same builders negotiate a
    /// classical group (ring provider, X25519 first).
    #[test]
    fn pqc_disabled_negotiates_classical_group() {
        let (group, client_key, server_key) = pqc_handshake(&PqcTlsConfig::default());
        assert_eq!(group, rustls::NamedGroup::X25519);
        assert_eq!(client_key, server_key);
    }

    /// Pure ML-KEM mode (no hybrid, no fallback) negotiates MLKEM768.
    #[test]
    fn pqc_pure_mode_negotiates_mlkem768() {
        let (group, client_key, server_key) = pqc_handshake(&PqcTlsConfig::pure_pqc());
        assert_eq!(group, rustls::crypto::aws_lc_rs::kx_group::MLKEM768.name());
        assert_eq!(client_key, server_key);
    }

    /// mTLS builders complete a hybrid handshake end-to-end — in particular
    /// the client-cert verifier must not resolve the ambient (ambiguous)
    /// process-default provider.
    #[test]
    fn pqc_mtls_handshake_negotiates_hybrid() {
        use rustls::pki_types::ServerName;

        let pqc = PqcTlsConfig::hybrid();
        let server_cert =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let client_cert = rcgen::generate_simple_self_signed(vec!["client".to_string()]).unwrap();

        static DIR_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let seq = DIR_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "nextgcore-sbi-pqc-mtls-{}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let server_ca = dir.join("server-ca.pem");
        let client_ca = dir.join("client-ca.pem");
        std::fs::write(&server_ca, server_cert.cert.pem()).expect("write server ca");
        std::fs::write(&client_ca, client_cert.cert.pem()).expect("write client ca");

        let server_config = build_server_config_mtls_with_pqc(
            vec![CertificateDer::from(server_cert.cert.der().to_vec())],
            PrivateKeyDer::try_from(server_cert.key_pair.serialize_der()).unwrap(),
            client_ca.to_str().expect("client ca path"),
            &pqc,
        )
        .expect("mtls server config");
        let client_config = build_client_config_mtls_with_pqc(
            vec![CertificateDer::from(client_cert.cert.der().to_vec())],
            PrivateKeyDer::try_from(client_cert.key_pair.serialize_der()).unwrap(),
            Some(server_ca.to_str().expect("server ca path")),
            false,
            &pqc,
        )
        .expect("mtls client config");
        let _ = std::fs::remove_dir_all(&dir);

        let server_name = ServerName::try_from("localhost").unwrap();
        let mut client =
            rustls::ClientConnection::new(Arc::new(client_config), server_name).unwrap();
        let mut server = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
        for _ in 0..16 {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                server.read_tls(&mut buf.as_slice()).unwrap();
                server.process_new_packets().unwrap();
            }
            let mut buf2 = Vec::new();
            server.write_tls(&mut buf2).unwrap();
            if !buf2.is_empty() {
                client.read_tls(&mut buf2.as_slice()).unwrap();
                client.process_new_packets().unwrap();
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
        assert!(!client.is_handshaking() && !server.is_handshaking());
        assert_eq!(
            client.negotiated_key_exchange_group().expect("kx").name(),
            rustls::NamedGroup::X25519MLKEM768
        );
    }
}
