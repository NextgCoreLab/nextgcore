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
/// When several URI SANs are present, the first `urn:uuid:` one is used (#1611):
/// TS 33.310 §6.1.3c.3 puts the NF Instance ID in a URI-ID "as an URN", and
/// also lets the same certificate carry HTTPS URI-IDs for the NF's apiRoot, in
/// any order. Without a `urn:uuid:` entry the **first** URI SAN is used, matching
/// the convention already applied to the forwarded-certificate header. A
/// certificate with two URNs naming different NFs is malformed for this
/// purpose; picking the first is at least deterministic.
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

    let uris: Vec<&str> = san
        .0
        .iter()
        .filter_map(|name| match name {
            GeneralName::UniformResourceIdentifier(uri) => Some(uri.as_str()),
            _ => None,
        })
        .collect();
    let is_urn_uuid = |uri: &str| {
        uri.trim()
            .get(..URN_UUID_PREFIX.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(URN_UUID_PREFIX))
    };
    uris.iter()
        .copied()
        .filter(|uri| is_urn_uuid(uri))
        .chain(uris.iter().copied())
        .find_map(normalize_uri_san)
}

/// The RFC 9310 NFTypes certificate extension, `id-pe-nftype`
/// (1.3.6.1.5.5.7.1.34). TS 33.310 §6.1.3c.3: "nfTypes shall contain NF type for
/// the Network Function instance formatted according to RFC 9310".
pub const NF_TYPES_OID: x509_cert::der::oid::ObjectIdentifier =
    x509_cert::der::oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.34");

/// The NF types a DER-encoded certificate's RFC 9310 NFTypes extension names
/// (#1522): `NFTypes ::= SEQUENCE SIZE (1..MAX) OF NFType`, `NFType ::= IA5String
/// (SIZE (1..32))`.
///
/// Empty when the certificate cannot be parsed, carries no NFTypes extension, or
/// carries one that does not decode as RFC 9310 defines it (an empty sequence, an
/// entry that is not a 1-32 character IA5String). Every one of those means "this
/// certificate asserts no NF type", never "any type". Like
/// [`nf_instance_id_from_der`] this does no verification: it reads a certificate
/// the TLS layer has already verified.
pub fn nf_types_from_der(der: &[u8]) -> Vec<String> {
    let Ok(cert) = Certificate::from_der(der) else {
        return Vec::new();
    };
    let Some(ext) = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .and_then(|exts| exts.iter().find(|e| e.extn_id == NF_TYPES_OID))
    else {
        return Vec::new();
    };
    let Ok(types) = Vec::<x509_cert::der::asn1::Ia5String>::from_der(ext.extn_value.as_bytes())
    else {
        return Vec::new();
    };
    let types: Vec<String> = types.iter().map(|t| t.as_str().to_string()).collect();
    if types.is_empty() || types.iter().any(|t| t.is_empty() || t.len() > 32) {
        return Vec::new();
    }
    types
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
pub(crate) mod tests {
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

    /// An RFC 9310 NFTypes extension's DER: SEQUENCE OF IA5String.
    pub(crate) fn nf_types_der(types: &[&str]) -> Vec<u8> {
        let mut body = Vec::new();
        for t in types {
            body.push(0x16);
            body.push(t.len() as u8);
            body.extend_from_slice(t.as_bytes());
        }
        let mut der = vec![0x30, body.len() as u8];
        der.extend(body);
        der
    }

    fn cert_with_nf_types(content: Option<Vec<u8>>) -> Vec<u8> {
        use rcgen::{CertificateParams, CustomExtension, KeyPair};
        let mut params = CertificateParams::new(Vec::new()).expect("params");
        if let Some(content) = content {
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 5, 5, 7, 1, 34],
                    content,
                ));
        }
        let key = KeyPair::generate().expect("key");
        params.self_signed(&key).expect("cert").der().to_vec()
    }

    /// #1522, RFC 9310 / TS 33.310 §6.1.3c.2: the NF types a certificate's NFTypes
    /// extension names; nothing for a certificate without one, or with one that
    /// does not decode as RFC 9310 defines it.
    #[test]
    fn reads_the_rfc_9310_nf_types_extension_1522() {
        assert_eq!(
            nf_types_from_der(&cert_with_nf_types(Some(nf_types_der(&["UDM"])))),
            ["UDM"]
        );
        assert_eq!(
            nf_types_from_der(&cert_with_nf_types(Some(nf_types_der(&["AMF", "SMF"])))),
            ["AMF", "SMF"]
        );
        assert!(nf_types_from_der(&cert_with_nf_types(None)).is_empty());
        assert!(
            nf_types_from_der(&cert_with_nf_types(Some(vec![0x30, 0x00]))).is_empty(),
            "an empty sequence (SIZE (1..MAX))"
        );
        assert!(
            nf_types_from_der(&cert_with_nf_types(Some(vec![
                0x04, 0x03, b'U', b'D', b'M'
            ])))
            .is_empty(),
            "an OCTET STRING, not a SEQUENCE OF IA5String"
        );
        assert!(nf_types_from_der(b"not a certificate").is_empty());
    }

    /// #1611, TS 33.310 §6.1.3c.3: a certificate that lists its apiRoot HTTPS
    /// URI-ID before the NF Instance ID URN still yields the NF Instance ID.
    #[test]
    fn prefers_the_urn_uuid_san_over_an_earlier_https_uri_1611() {
        use rcgen::{CertificateParams, KeyPair, SanType};
        let mut params = CertificateParams::new(Vec::new()).expect("params");
        params.subject_alt_names = vec![
            SanType::URI("https://amf.example.org:443".try_into().expect("ia5")),
            SanType::URI(
                "URN:UUID:4947a69a-f61b-4bc1-b9da-47c9c5d14b64"
                    .try_into()
                    .expect("ia5"),
            ),
        ];
        let key = KeyPair::generate().expect("key");
        let der = params.self_signed(&key).expect("cert").der().to_vec();
        assert_eq!(
            nf_instance_id_from_der(&der).as_deref(),
            Some("4947a69a-f61b-4bc1-b9da-47c9c5d14b64")
        );
        // Without a URN the first URI SAN is still the identity, as before.
        let der = cert_with_uri_san("https://amf.example.org:443");
        assert_eq!(
            nf_instance_id_from_der(&der).as_deref(),
            Some("https://amf.example.org:443")
        );
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
