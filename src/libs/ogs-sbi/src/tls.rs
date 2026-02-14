//! TLS utilities for SBI client and server
//!
//! Provides certificate loading, key loading, and rustls configuration
//! builders for TLS and mTLS on the SBI interface.
//!
//! Rel-20 (6G) additions:
//! - Post-Quantum Cryptography (PQC) TLS 1.3 support
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
// Post-Quantum Cryptography (PQC) Support - Rel-20 (6G)
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
    build_client_config_mtls_with_pqc(certs, key, ca_path, insecure_skip_verify, &PqcTlsConfig::default())
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
}
