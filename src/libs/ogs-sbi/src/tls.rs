//! TLS utilities for SBI client and server
//!
//! Provides certificate loading, key loading, and rustls configuration
//! builders for TLS and mTLS on the SBI interface.

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use crate::error::{SbiError, SbiResult};

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
    ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| SbiError::TlsError(format!("Failed to set protocol versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| SbiError::TlsError(format!("Failed to build server TLS config: {e}")))
}

/// Build a server-side TLS config with mutual TLS (client certificate verification).
pub fn build_server_config_mtls(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_ca_path: &str,
) -> SbiResult<ServerConfig> {
    let root_store = load_root_store(client_ca_path)?;

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| SbiError::TlsError(format!("Failed to build client verifier: {e}")))?;

    ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| SbiError::TlsError(format!("Failed to set protocol versions: {e}")))?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)
        .map_err(|e| SbiError::TlsError(format!("Failed to build mTLS server config: {e}")))
}

/// Build a client-side TLS config (server auth only, no client cert).
pub fn build_client_config(
    ca_path: Option<&str>,
    insecure_skip_verify: bool,
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
