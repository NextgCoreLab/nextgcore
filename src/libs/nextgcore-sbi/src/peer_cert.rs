//! NF identity from a verified TLS peer certificate (issue #186).
//!
//! TS 33.310 carries an NF's Instance ID in a certificate **URI
//! SubjectAltName**, conventionally as the URN `urn:uuid:<nfInstanceId>`.
//! TS 33.501 §13.4.1.1 then expects a token's subject to correspond to that
//! authenticated identity rather than to anything the requester asserts about
//! itself.
//!
//! Before this module the identity was only ever read from an
//! `x-forwarded-client-cert` header set by a TLS-terminating SCP or ingress. An
//! NF that terminated TLS itself — with `verify_client = true`, so rustls had
//! just verified the client's chain — **threw the certificate away**. The
//! strongest authentication available was configured and then discarded, which
//! is why `nrf.sbi.oauth2.require_client_cert_binding` could only ever *reject*
//! on a direct connection.
//!
//! This module does no verification. It extracts an identity from a certificate
//! the TLS layer has **already** verified, and it is deliberately the only thing
//! it does: chain validation, expiry and revocation are rustls's job, and a
//! parser that also decided trust would be the wrong shape.

use x509_cert::der::{oid::AssociatedOid, Decode};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::Certificate;

/// The `urn:uuid:` prefix a 3GPP NF certificate conventionally wraps its NF
/// Instance ID in (TS 33.310). Matched case-insensitively: RFC 8141 makes the
/// scheme and NID case-insensitive, and real certificates are inconsistent
/// about it.
const URN_UUID_PREFIX: &str = "urn:uuid:";

/// Extract the NF Instance ID from the URI SubjectAltName of a DER-encoded
/// certificate.
///
/// Returns `None` when the certificate cannot be parsed, carries no
/// `subjectAltName` extension, or carries one with no URI entry — every one of
/// which means "this peer asserted no NF identity", not "trust it anyway".
///
/// When several URI SANs are present the **first** is used, matching the
/// convention already applied to the forwarded-certificate header (the leaf
/// entry wins). A certificate with two URI SANs naming different NFs is
/// malformed for this purpose; picking the first is at least deterministic.
///
/// The `urn:uuid:` prefix is stripped so the result compares directly against a
/// `nfInstanceId`. Any other URI form is returned verbatim, because a deployment
/// may legitimately identify NFs by an `https://` service URI and truncating
/// that would silently weaken the comparison.
pub fn nf_instance_id_from_der(der: &[u8]) -> Option<String> {
    let cert = Certificate::from_der(der).ok()?;
    let extensions = cert.tbs_certificate.extensions.as_ref()?;

    let san_ext = extensions
        .iter()
        .find(|e| e.extn_id == SubjectAltName::OID)?;
    let san = SubjectAltName::from_der(san_ext.extn_value.as_bytes()).ok()?;

    san.0.iter().find_map(|name| match name {
        GeneralName::UniformResourceIdentifier(uri) => normalize_uri_san(uri.as_str()),
        _ => None,
    })
}

/// Strip a case-insensitive `urn:uuid:` prefix and trim, rejecting an empty
/// result. Split out so the normalisation is testable without building a
/// certificate.
fn normalize_uri_san(uri: &str) -> Option<String> {
    let uri = uri.trim();
    let id = match uri.get(..URN_UUID_PREFIX.len()) {
        Some(prefix) if prefix.eq_ignore_ascii_case(URN_UUID_PREFIX) => {
            &uri[URN_UUID_PREFIX.len()..]
        }
        _ => uri,
    };
    let id = id.trim();
    if id.is_empty() {
        None
    } else {
        Some(id.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a certificate carrying `uri` as a URI SubjectAltName, and return
    /// its DER. Uses a real encoder rather than a hand-written byte fixture, so
    /// the parser is proven against something interoperable rather than against
    /// my own idea of the encoding.
    fn cert_with_uri_san(uri: &str) -> Vec<u8> {
        use rcgen::{CertificateParams, KeyPair, SanType};
        let mut params = CertificateParams::new(Vec::new()).expect("params");
        params.subject_alt_names = vec![SanType::URI(uri.try_into().expect("ia5 uri"))];
        let key = KeyPair::generate().expect("key");
        params.self_signed(&key).expect("cert").der().to_vec()
    }

    /// **Issue #186.** The NF Instance ID is recovered from a real certificate's
    /// URI SAN, with the `urn:uuid:` prefix stripped.
    #[test]
    fn extracts_the_nf_instance_id_from_a_urn_uuid_san() {
        let der = cert_with_uri_san("urn:uuid:amf-0001-2222-3333");
        assert_eq!(
            nf_instance_id_from_der(&der).as_deref(),
            Some("amf-0001-2222-3333")
        );
    }

    /// RFC 8141 makes the URN scheme and NID case-insensitive, and certificates
    /// in the wild are inconsistent, so an uppercase prefix must still match.
    #[test]
    fn the_urn_prefix_is_case_insensitive() {
        let der = cert_with_uri_san("URN:UUID:smf-9");
        assert_eq!(nf_instance_id_from_der(&der).as_deref(), Some("smf-9"));
    }

    /// A non-URN URI SAN is returned verbatim. Truncating it would silently
    /// weaken the identity comparison for a deployment that identifies NFs by
    /// service URI.
    #[test]
    fn a_non_urn_uri_san_is_returned_unchanged() {
        let der = cert_with_uri_san("https://udm.example/nf/udm-1");
        assert_eq!(
            nf_instance_id_from_der(&der).as_deref(),
            Some("https://udm.example/nf/udm-1")
        );
    }

    /// A certificate with no URI SAN asserts no NF identity. It must yield
    /// `None` rather than anything a caller could mistake for one — the caller
    /// then treats the peer as unidentified, which is the safe reading.
    #[test]
    fn a_certificate_without_a_uri_san_yields_no_identity() {
        use rcgen::{CertificateParams, KeyPair};
        // DNS SAN only.
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        params.subject_alt_names = vec![rcgen::SanType::DnsName(
            "localhost".try_into().expect("ia5 dns"),
        )];
        let key = KeyPair::generate().expect("key");
        let der = params.self_signed(&key).expect("cert").der().to_vec();
        assert_eq!(nf_instance_id_from_der(&der), None);
    }

    /// Garbage in yields `None`, not a panic. This parses attacker-influenced
    /// bytes: a malformed certificate must be a refusal, never a crash.
    #[test]
    fn malformed_input_is_none_not_a_panic() {
        assert_eq!(nf_instance_id_from_der(&[]), None);
        assert_eq!(nf_instance_id_from_der(b"not a certificate"), None);
        assert_eq!(nf_instance_id_from_der(&[0x30, 0x82, 0xff, 0xff]), None);
        // A truncated but structurally plausible prefix.
        let valid = cert_with_uri_san("urn:uuid:amf-1");
        assert_eq!(nf_instance_id_from_der(&valid[..valid.len() / 2]), None);
    }

    /// The normalisation rules, without building certificates.
    #[test]
    fn uri_san_normalisation() {
        assert_eq!(normalize_uri_san("urn:uuid:x").as_deref(), Some("x"));
        assert_eq!(normalize_uri_san("  urn:uuid:x  ").as_deref(), Some("x"));
        assert_eq!(normalize_uri_san("urn:uuid:").as_deref(), None);
        assert_eq!(normalize_uri_san("").as_deref(), None);
        assert_eq!(normalize_uri_san("   ").as_deref(), None);
        // A shorter-than-prefix value must not panic on the slice.
        assert_eq!(normalize_uri_san("urn:").as_deref(), Some("urn:"));
    }
}
