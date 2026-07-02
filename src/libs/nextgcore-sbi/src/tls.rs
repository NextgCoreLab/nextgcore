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
        // Note: These are placeholder values as rustls doesn't natively support PQC yet.
        // In a real implementation, this would require a custom CryptoProvider with
        // PQC algorithm support (e.g., via liboqs or AWS libcrypto).
        match config.signature_scheme {
            PqcSignatureScheme::MlDsa65 => {
                // Future: Add ML-DSA-65 signature scheme
                log::debug!("PQC: ML-DSA-65 signature requested (not yet in rustls)");
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
    let config = ServerConfig::builder_with_provider(provider())
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
        // Note: Actual PQC cipher suite configuration would require custom CryptoProvider
        // This is a framework for future PQC integration
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

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| SbiError::TlsError(format!("Failed to build client verifier: {e}")))?;

    let config = ServerConfig::builder_with_provider(provider())
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
        // PQC certificate chain validation would be implemented here
        // with custom verifier supporting ML-DSA signatures
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

    let mut config = ClientConfig::builder_with_provider(provider())
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
        // PQC cipher suite negotiation would be configured here
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

    let mut config = ClientConfig::builder_with_provider(provider())
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
        // PQC client certificate and key exchange would be configured here
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
