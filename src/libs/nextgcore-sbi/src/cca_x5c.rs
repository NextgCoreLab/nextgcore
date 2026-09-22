//! The CCA's `x5c` certificate chain, and the certificate-to-NF-Instance-ID
//! binding TS 33.501 §13.3.8.3 requires of the receiving node (issue #393).
//!
//! # What was missing
//!
//! TS 33.501 §13.3.8.2 is unconditional (`6g_docs/specs/33501-k20.txt:14370`):
//!
//! > The NF Service Consumer shall digitally sign the generated CCA based on its
//! > private key as described in RFC 7515 [45]. The signed CCA **shall include
//! > one of the following fields**: the X.509 URL (x5u) to refer to a resource
//! > for the X.509 public key certificate or certificate chain used for signing
//! > the client authentication assertion, **or** the X.509 Certificate Chain
//! > (x5c) […]
//!
//! and §13.3.8.3's last validation bullet (`:14401`) depends on it:
//!
//! > It verifies that the NF instance ID of the NFc in the CCA matches the NF
//! > instance ID in the public key certificate used for signing the CCA.
//!
//! Before this module [`crate::oauth::mint_cca`] emitted a fixed two-field JOSE
//! header with neither field, so that fourth step was unimplementable — the NRF
//! substituted a trust store keyed by `nfInstanceId`
//! (`nrf.sbi.oauth2.cca_trusted_keys[_dir]`, issue #187). That is a sound
//! binding, and it remains the no-PKI path, but it is a documented deviation.
//!
//! Where the instance ID lives in the certificate is not in TS 33.501 but in
//! TS 33.310 (`6g_docs/specs/33310-j50.txt:734`): `subjectAltName` **shall**, in
//! "X.509 PKIX certificates used for signing validation of OAuth 2.0 JWT access
//! tokens and/or CCA tokens", contain a URI-ID holding the `nfInstanceId` as a
//! URN — `urn:uuid:<uuid-v4>` (`:735`). [`crate::peer_cert`] already extracts
//! exactly that, for issue #186, so this module does not re-parse X.509 names.
//!
//! # `x5c`, not `x5u` — and why
//!
//! §13.3.8.2 lets the *sender* choose. This implementation accepts only `x5c`,
//! and refuses `x5u` explicitly rather than ignoring it.
//!
//! `x5u` is a URL, chosen by the party being authenticated, that the verifier
//! must dereference to obtain the key it will then trust. The CCA arrives in the
//! body of an access-token request that is by definition not yet authenticated,
//! so an NRF that fetched `x5u` would let any party able to reach the token
//! endpoint drive an arbitrary outbound GET from inside the core network — a
//! pre-authentication SSRF primitive, from a host with reach to every NF. It
//! would also put a requester-controlled HTTP fetch on the authentication hot
//! path (a CCA lives 60s and is minted per token request), making the latency,
//! and therefore the availability, of the token endpoint the attacker's choice.
//! Constraining that needs an allowlist of fetchable origins, which is a per-peer
//! operator-provisioned trust list — the very thing `x5u` was meant to avoid, and
//! weaker than the existing key store because it names hosts rather than keys.
//!
//! `x5c` inlines the chain, so verification needs no network at all. The cost is
//! assertion size (~500 bytes of base64 per P-256 certificate), which is paid on
//! a single local SBI hop.
//!
//! # This module validates; it does not decide policy
//!
//! [`verify_x5c_binding`] takes the trust anchors and returns the leaf's verified
//! public key. Which requests are *required* to carry `x5c`, and what happens
//! when they do not, is the NRF's policy decision and lives there.
//!
//! The order of operations inside it is load-bearing and is asserted by tests:
//! the chain is validated to a trust anchor **first**, and only then is the URI
//! SAN read off the validated leaf. Reading the SAN from an unvalidated
//! certificate and comparing it to `sub` would authenticate anyone who could
//! write both fields, which is not a binding at all.

use crate::error::{SbiError, SbiResult};
use rustls::pki_types::{CertificateDer, TrustAnchor, UnixTime};

/// Signature algorithms accepted in a CCA certificate CHAIN's signatures.
///
/// Note this constrains how the CA signed the certificates, not the CCA's own
/// JWS — that is ES256 by TS 33.501 §13.3.8.2 and is checked separately. ECDSA
/// P-256/P-384 and RSA PKCS#1/PSS are all legitimate for an operator CA under
/// TS 33.310 §6.1.1, so restricting the CA's choice here would refuse conformant
/// PKIs for no security gain. Ed25519 is excluded: TS 33.310 does not list it.
const CHAIN_SIG_ALGS: &[&dyn rustls::pki_types::SignatureVerificationAlgorithm] = &[
    webpki::ring::ECDSA_P256_SHA256,
    webpki::ring::ECDSA_P256_SHA384,
    webpki::ring::ECDSA_P384_SHA256,
    webpki::ring::ECDSA_P384_SHA384,
    webpki::ring::RSA_PKCS1_2048_8192_SHA256,
    webpki::ring::RSA_PKCS1_2048_8192_SHA384,
    webpki::ring::RSA_PKCS1_2048_8192_SHA512,
    webpki::ring::RSA_PKCS1_3072_8192_SHA384,
    webpki::ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    webpki::ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    webpki::ring::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
];

/// RFC 7515 §4.1.6 `x5c` JOSE header parameter: the certificate chain that
/// certifies the JWS signing key, leaf first.
pub const X5C_HEADER: &str = "x5c";

/// RFC 7515 §4.1.5 `x5u` JOSE header parameter: a URL to fetch that chain from.
/// Recognised only so it can be refused by name — see the module docs.
pub const X5U_HEADER: &str = "x5u";

/// The certificate chain carried by a CCA's JOSE header, already decoded from
/// base64 to DER but **not yet validated**.
///
/// Deliberately a distinct type from a validated chain: the whole defect class
/// this module guards against is treating an unvalidated certificate's contents
/// as an identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcaCertChain {
    /// DER certificates, leaf (the CCA signing certificate) first.
    der: Vec<Vec<u8>>,
}

impl CcaCertChain {
    /// The leaf — the certificate over the CCA signing key.
    pub fn leaf(&self) -> &[u8] {
        // Non-empty by construction: `from_jose_header` rejects an empty array.
        &self.der[0]
    }

    /// The intermediates between the leaf and a trust anchor, in order.
    pub fn intermediates(&self) -> &[Vec<u8>] {
        &self.der[1..]
    }

    /// How many certificates the chain holds.
    pub fn len(&self) -> usize {
        self.der.len()
    }

    /// Always false — a `CcaCertChain` cannot be empty by construction. Present
    /// because clippy requires it alongside `len`, and honest about why.
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// What a CCA's JOSE header says about the certificate that signed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CcaCertReference {
    /// An `x5c` chain, decoded to DER and ready for path validation.
    Chain(CcaCertChain),
    /// An `x5u` URL. Carried through as a distinct case, not an error, so the
    /// caller can refuse it with a reason that NAMES the unsupported mechanism
    /// instead of reporting a generic malformed header. A conformant peer that
    /// chose the other §13.3.8.2 arm deserves to be told which arm is missing.
    Url(String),
    /// Neither field. A deviation from §13.3.8.2 that the caller may still
    /// accept via the trust-store path (issue #187).
    Absent,
}

/// Read the certificate reference out of a CCA's JOSE header.
///
/// `header` is the already-decoded JSON of the JWS protected header. Errors are
/// reserved for a header that *claims* a certificate reference and gets it wrong
/// — a present-but-malformed `x5c` is never silently downgraded to
/// [`CcaCertReference::Absent`], because that would make a broken certificate a
/// route to the weaker trust-store path.
pub fn cert_reference_from_jose_header(header: &serde_json::Value) -> SbiResult<CcaCertReference> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    if let Some(x5c) = header.get(X5C_HEADER) {
        let entries = x5c.as_array().ok_or_else(|| {
            SbiError::ClientError("CCA x5c is not a JSON array (RFC 7515 §4.1.6)".to_string())
        })?;
        if entries.is_empty() {
            return Err(SbiError::ClientError(
                "CCA x5c is an empty array; it must hold at least the signing certificate \
                 (RFC 7515 §4.1.6)"
                    .to_string(),
            ));
        }
        let mut der = Vec::with_capacity(entries.len());
        for (i, entry) in entries.iter().enumerate() {
            let b64 = entry.as_str().ok_or_else(|| {
                SbiError::ClientError(format!("CCA x5c entry {i} is not a string"))
            })?;
            // RFC 7515 §4.1.6: each entry is base64 per RFC 4648 §4 — STANDARD
            // base64 with padding, NOT the base64url used for the JWS parts
            // themselves. Decoding with the wrong alphabet is the classic x5c
            // interop bug, so the alphabet is named here rather than inherited.
            let bytes = STANDARD.decode(b64).map_err(|e| {
                SbiError::ClientError(format!(
                    "CCA x5c entry {i} is not valid base64 ({e}); RFC 7515 §4.1.6 requires \
                     standard base64, not base64url"
                ))
            })?;
            der.push(bytes);
        }
        return Ok(CcaCertReference::Chain(CcaCertChain { der }));
    }

    if let Some(x5u) = header.get(X5U_HEADER).and_then(|v| v.as_str()) {
        return Ok(CcaCertReference::Url(x5u.to_string()));
    }

    Ok(CcaCertReference::Absent)
}

/// The outcome of validating a CCA's `x5c` chain and binding it to an NF
/// Instance ID.
#[derive(Debug, Clone)]
pub struct VerifiedCcaCert {
    /// The NF Instance ID the **validated** leaf certificate attests, taken from
    /// its URI SubjectAltName (TS 33.310 `:734`).
    pub nf_instance_id: String,
    /// The leaf's DER, so the caller can verify the JWS against the key this
    /// certificate certifies rather than against anything else.
    leaf_der: Vec<u8>,
}

impl VerifiedCcaCert {
    /// The ES256 verifying key the validated leaf certificate certifies.
    ///
    /// This is the key the JWS signature MUST be checked against. Verifying
    /// against a trust-store key while *also* validating a chain would make the
    /// certificate decorative: it would constrain nothing about who signed the
    /// assertion, which is the "theatre" this issue exists to avoid.
    ///
    /// Errors when the certificate's subject public key is not a P-256 key — an
    /// RSA CCA certificate is well-formed X.509 but cannot have produced the
    /// ES256 signature this tree mints and verifies.
    pub fn es256_verifying_key(&self) -> SbiResult<p256::ecdsa::VerifyingKey> {
        use x509_cert::der::Decode;
        let cert = x509_cert::Certificate::from_der(&self.leaf_der).map_err(|e| {
            SbiError::ClientError(format!("CCA x5c leaf certificate does not parse: {e}"))
        })?;
        let spki = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| {
                SbiError::ClientError(
                    "CCA x5c leaf subject public key is not a whole number of bytes".to_string(),
                )
            })?;
        p256::ecdsa::VerifyingKey::from_sec1_bytes(spki).map_err(|e| {
            SbiError::ClientError(format!(
                "CCA x5c leaf does not certify a P-256 public key, so it cannot have produced \
                 the ES256 signature the CCA carries: {e}"
            ))
        })
    }
}

/// Validate a CCA's `x5c` chain to one of `trust_anchors` and extract the NF
/// Instance ID the validated leaf attests (TS 33.501 §13.3.8.3, TS 33.310).
///
/// `now` is the validation time — expiry is checked, so a chain that was once
/// good does not stay good. `trust_anchors` are DER CA certificates; an empty
/// set is an error rather than "trust anything", because the caller reaching here
/// with nothing configured means it cannot evaluate the assertion at all.
///
/// # Order
///
/// 1. Path-build and validate the chain to an anchor at `now`.
/// 2. **Then** read the URI SAN off the validated leaf.
///
/// Step 2 must not precede step 1. The SAN of an unvalidated certificate is
/// attacker-chosen data, and comparing it to an attacker-chosen `sub` would be a
/// tautology, not a binding.
///
/// The EKU is `id-kp-jwt`-or-absent rather than required: TS 33.310 `:731` gives
/// CCA signing certificates the `id-kp-jwt` EKU (RFC 9509), and `:1214` says the
/// EKU extension **may** be used to indicate the purpose — so a certificate with
/// no EKU at all is conformant and must not be refused, while one that declares
/// EKUs must include `id-kp-jwt` among them. That is exactly RFC 5280 §4.2.1.12's
/// "required if present" semantics.
pub fn verify_x5c_binding(
    chain: &CcaCertChain,
    trust_anchors: &[Vec<u8>],
    now: u64,
) -> SbiResult<VerifiedCcaCert> {
    if trust_anchors.is_empty() {
        return Err(SbiError::ClientError(
            "no CCA trust anchors are configured, so an x5c chain cannot be validated \
             (TS 33.501 §13.3.8.3)"
                .to_string(),
        ));
    }

    let anchor_ders: Vec<CertificateDer<'_>> = trust_anchors
        .iter()
        .map(|d| CertificateDer::from(d.as_slice()))
        .collect();
    let anchors: Vec<TrustAnchor<'_>> = anchor_ders
        .iter()
        .map(|d| {
            webpki::anchor_from_trusted_cert(d).map_err(|e| {
                SbiError::ClientError(format!("a configured CCA trust anchor is unusable: {e}"))
            })
        })
        .collect::<SbiResult<_>>()?;

    let leaf_der = CertificateDer::from(chain.leaf());
    let end_entity = webpki::EndEntityCert::try_from(&leaf_der).map_err(|e| {
        SbiError::ClientError(format!("CCA x5c leaf certificate does not parse: {e}"))
    })?;
    let intermediates: Vec<CertificateDer<'_>> = chain
        .intermediates()
        .iter()
        .map(|d| CertificateDer::from(d.as_slice()))
        .collect();

    end_entity
        .verify_for_usage(
            CHAIN_SIG_ALGS,
            &anchors,
            &intermediates,
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(now)),
            // TS 33.310 `:731` / RFC 9509 `id-kp-jwt`: required only if the
            // certificate declares any EKU at all (see the doc comment).
            webpki::KeyUsage::required_if_present(EKU_ID_KP_JWT_DER),
            // Revocation is not checked: no deployment in this tree can yet
            // configure a CRL or an OCSP responder, and passing an empty CRL set
            // to a checker that requires one would refuse every chain. Stated as
            // a ceiling in specs/fix-cca-x5c-certificate-binding.md rather than
            // left to be inferred from a `None`.
            None,
            None,
        )
        .map_err(|e| {
            SbiError::ClientError(format!(
                "CCA x5c chain does not validate to a configured trust anchor: {e}"
            ))
        })?;

    // Only now, on the VALIDATED leaf.
    let nf_instance_id =
        crate::peer_cert::nf_instance_id_from_der(chain.leaf()).ok_or_else(|| {
            SbiError::ClientError(
                "CCA x5c leaf certificate carries no URI SubjectAltName, so it attests no NF \
             Instance ID to bind the assertion to (TS 33.310: subjectAltName shall contain a \
             URI-ID with the NF Instance ID as a urn:uuid URN)"
                    .to_string(),
            )
        })?;

    Ok(VerifiedCcaCert {
        nf_instance_id,
        leaf_der: chain.leaf().to_vec(),
    })
}

/// DER encoding of the `id-kp-jwt` extended key usage OID, `1.3.6.1.5.5.7.3.37`
/// (RFC 9509 §2.2), as the raw OID contents webpki's [`webpki::KeyUsage`] expects
/// — the value octets of the OBJECT IDENTIFIER, without the tag or length.
///
/// TS 33.310 `33310-j50.txt:731` names it for CCA token certificates:
/// "id-kp-jwt for validating the JWS signature in JWT [63], for example for CCA
/// token", where [63] is RFC 9509 (`:321`).
///
/// Encoding, byte by byte, so this is checkable without an ASN.1 decoder:
/// `1.3` → `40*1+3` = `0x2b`; then `6`, `1`, `5`, `5`, `7`, `3` each below 128 so
/// each is its own byte; then `37` = `0x25`.
const EKU_ID_KP_JWT_DER: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x25];

#[cfg(test)]
mod tests {
    use super::*;

    /// A CA plus a leaf certifying `signing_key`, with `uri_san` as the leaf's URI
    /// SubjectAltName. Returns `(ca_der, leaf_der)`.
    ///
    /// A real encoder and a real CA signature, not a byte fixture: the point of
    /// this module is interoperating with a conformant peer's X.509, so a fixture
    /// of my own making would prove only self-consistency.
    fn ca_and_leaf(
        signing_key: &p256::ecdsa::SigningKey,
        uri_san: &str,
    ) -> (Vec<u8>, Vec<u8>, rcgen::Certificate, rcgen::KeyPair) {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

        let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "nextgcore test CCA CA");
        let ca_key = KeyPair::generate().expect("ca key");
        let ca = ca_params.self_signed(&ca_key).expect("ca cert");
        let ca_der = ca.der().to_vec();

        let leaf_der = leaf_signed_by(signing_key, uri_san, &ca, &ca_key);
        (ca_der, leaf_der, ca, ca_key)
    }

    /// Issue a leaf over `signing_key`'s PUBLIC half, carrying `uri_san`, signed
    /// by `(ca, ca_key)`.
    ///
    /// The leaf certifies the CCA **signing** key, which is the property that
    /// makes `x5c` mean anything: `VerifiedCcaCert::es256_verifying_key` pulls
    /// this key back out and the JWS is checked against it.
    fn leaf_signed_by(
        signing_key: &p256::ecdsa::SigningKey,
        uri_san: &str,
        ca: &rcgen::Certificate,
        ca_key: &rcgen::KeyPair,
    ) -> Vec<u8> {
        use rcgen::{CertificateParams, KeyPair, SanType};

        // rcgen signs with its own KeyPair type, so the CCA key is imported as
        // PKCS#8 to be certified. `p256`'s `SigningKey` -> PKCS#8 DER is the only
        // bridge between the two crates' key types.
        use p256::pkcs8::EncodePrivateKey;
        let pkcs8 = signing_key
            .to_pkcs8_der()
            .expect("cca key to pkcs8")
            .as_bytes()
            .to_vec();
        let subject_key =
            KeyPair::try_from(pkcs8.as_slice()).expect("import the cca key for certification");

        let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
        params.subject_alt_names = vec![SanType::URI(uri_san.try_into().expect("ia5 uri"))];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "nextgcore test NF");
        // An EXPLICIT validity window. rcgen's default is 1975..4096, which is
        // effectively never-expiring, and `an_expired_leaf_is_refused` found that
        // by failing: validating 50 years out still succeeded. A real NF
        // certificate has a bounded lifetime, so the fixture must too, or the
        // time argument to `verify_x5c_binding` would be untested.
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(30);
        params
            .signed_by(&subject_key, ca, ca_key)
            .expect("leaf cert")
            .der()
            .to_vec()
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs()
    }

    /// **Issue #393, the core positive case.** A chain that validates to the
    /// configured anchor yields the instance ID from the leaf's URI SAN, and the
    /// key the leaf certifies is the CCA signing key.
    #[test]
    fn a_validating_chain_yields_the_instance_id_and_the_certified_key() {
        let key = crate::oauth::generate_es256_key();
        let (ca, leaf, _, _) = ca_and_leaf(&key, "urn:uuid:6b1d7e3c-0000-4000-8000-000000000af0");
        let chain = CcaCertChain { der: vec![leaf] };

        let verified = verify_x5c_binding(&chain, &[ca], now()).expect("the chain must validate");
        assert_eq!(
            verified.nf_instance_id, "6b1d7e3c-0000-4000-8000-000000000af0",
            "the urn:uuid: prefix must be stripped so the id compares to a CCA sub"
        );
        assert_eq!(
            verified
                .es256_verifying_key()
                .expect("the leaf certifies a P-256 key")
                .to_encoded_point(false),
            key.verifying_key().to_encoded_point(false),
            "the key recovered from the certificate MUST be the CCA signing key, or verifying \
             the JWS against it proves nothing about who signed the assertion"
        );
    }

    /// A chain from a CA the verifier does not trust is refused. Without this the
    /// `x5c` path would accept a self-signed certificate asserting any identity,
    /// which is strictly weaker than the trust store it replaces.
    #[test]
    fn a_chain_from_an_untrusted_ca_is_refused() {
        let key = crate::oauth::generate_es256_key();
        let (_, leaf, _, _) = ca_and_leaf(&key, "urn:uuid:nf-1");
        let (other_ca, _, _, _) = ca_and_leaf(&crate::oauth::generate_es256_key(), "urn:uuid:nf-2");
        let chain = CcaCertChain { der: vec![leaf] };

        let err = verify_x5c_binding(&chain, &[other_ca], now())
            .expect_err("a chain from an unconfigured CA must not validate");
        assert!(
            err.to_string().contains("does not validate"),
            "the reason must name path validation as the failure: {err}"
        );
    }

    /// No anchors configured is an error, never "trust anything". This is the
    /// anti-downgrade property at the module level: a verifier that cannot
    /// evaluate a chain must say so rather than wave it through.
    #[test]
    fn no_trust_anchors_is_an_error_not_blanket_trust() {
        let key = crate::oauth::generate_es256_key();
        let (_, leaf, _, _) = ca_and_leaf(&key, "urn:uuid:nf-1");
        let chain = CcaCertChain { der: vec![leaf] };

        let err = verify_x5c_binding(&chain, &[], now())
            .expect_err("an empty anchor set must not accept a chain");
        assert!(
            err.to_string().contains("no CCA trust anchors"),
            "the reason must name the missing configuration: {err}"
        );
    }

    /// TS 33.310 `:734` makes the URI SAN mandatory in a CCA signing
    /// certificate. A validly-issued certificate WITHOUT one attests no NF
    /// Instance ID, so there is nothing to bind and it must be refused — even
    /// though its chain is perfectly good. NOTE 1a at `:736` states exactly this
    /// consequence.
    #[test]
    fn a_validating_chain_with_no_uri_san_is_refused() {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, SanType};
        let key = crate::oauth::generate_es256_key();

        let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        let ca_key = KeyPair::generate().expect("ca key");
        let ca = ca_params.self_signed(&ca_key).expect("ca cert");

        use p256::pkcs8::EncodePrivateKey;
        let pkcs8 = key.to_pkcs8_der().expect("pkcs8").as_bytes().to_vec();
        let subject_key = KeyPair::try_from(pkcs8.as_slice()).expect("import");
        let mut params = CertificateParams::new(Vec::new()).expect("leaf params");
        // A DNS SAN only: well-formed, and useless for NF identity.
        params.subject_alt_names = vec![SanType::DnsName("amf".try_into().expect("ia5 dns"))];
        let leaf = params
            .signed_by(&subject_key, &ca, &ca_key)
            .expect("leaf")
            .der()
            .to_vec();

        let chain = CcaCertChain { der: vec![leaf] };
        let err = verify_x5c_binding(&chain, &[ca.der().to_vec()], now())
            .expect_err("a certificate with no URI SAN binds nothing");
        assert!(
            err.to_string().contains("no URI SubjectAltName"),
            "the reason must name the missing SAN, not the chain: {err}"
        );
    }

    /// An intermediate CA is validated through, so a real two-tier PKI works.
    /// Chains in the wild are rarely one certificate deep, and `intermediates()`
    /// slicing off `der[0]` is exactly the kind of off-by-one that a leaf-only
    /// test would never catch.
    #[test]
    fn a_chain_through_an_intermediate_validates() {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

        let mut root_params = CertificateParams::new(Vec::new()).expect("root params");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        root_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "root");
        let root_key = KeyPair::generate().expect("root key");
        let root = root_params.self_signed(&root_key).expect("root");

        let mut mid_params = CertificateParams::new(Vec::new()).expect("mid params");
        mid_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        mid_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "intermediate");
        let mid_key = KeyPair::generate().expect("mid key");
        let mid = mid_params
            .signed_by(&mid_key, &root, &root_key)
            .expect("intermediate");

        let key = crate::oauth::generate_es256_key();
        let leaf = leaf_signed_by(&key, "urn:uuid:nf-mid", &mid, &mid_key);

        let chain = CcaCertChain {
            der: vec![leaf, mid.der().to_vec()],
        };
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.intermediates().len(), 1);
        let verified = verify_x5c_binding(&chain, &[root.der().to_vec()], now())
            .expect("a two-tier chain must validate to the root");
        assert_eq!(verified.nf_instance_id, "nf-mid");
    }

    /// An expired leaf is refused. Path validation is time-dependent, and a
    /// verifier that ignored `now` would keep trusting a rotated-out certificate
    /// forever — the revocation hole this design already concedes would become
    /// unbounded.
    #[test]
    fn an_expired_leaf_is_refused() {
        let key = crate::oauth::generate_es256_key();
        let (ca, leaf, _, _) = ca_and_leaf(&key, "urn:uuid:nf-1");
        let chain = CcaCertChain { der: vec![leaf] };

        // `leaf_signed_by` issues a 30-day leaf, so validate past its notAfter
        // rather than fabricating a backdated certificate.
        let after_expiry = now() + 60 * 60 * 24 * 60;
        let err = verify_x5c_binding(&chain, &[ca], after_expiry)
            .expect_err("an expired certificate must not validate");
        assert!(
            err.to_string().contains("does not validate"),
            "expiry must surface as a path-validation failure: {err}"
        );
    }

    /// The JOSE header parser: an `x5c` array round-trips from the encoding
    /// [`crate::oauth::mint_cca`] produces.
    #[test]
    fn an_x5c_header_decodes_to_the_der_that_was_encoded() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;

        let der_a = vec![0x30u8, 0x03, 0x02, 0x01, 0x05];
        let der_b = vec![0x30u8, 0x03, 0x02, 0x01, 0x06];
        let header = serde_json::json!({
            "alg": "ES256",
            "typ": "JWT",
            "x5c": [STANDARD.encode(&der_a), STANDARD.encode(&der_b)],
        });

        match cert_reference_from_jose_header(&header).expect("parse") {
            CcaCertReference::Chain(chain) => {
                assert_eq!(chain.leaf(), der_a.as_slice());
                assert_eq!(chain.intermediates(), &[der_b]);
            }
            other => panic!("expected a chain, got {other:?}"),
        }
    }

    /// A header with neither field is `Absent` — the no-PKI path, which the
    /// caller may still accept via the trust store (issue #187).
    #[test]
    fn a_header_with_no_certificate_reference_is_absent() {
        let header = serde_json::json!({"alg": "ES256", "typ": "JWT"});
        assert_eq!(
            cert_reference_from_jose_header(&header).expect("parse"),
            CcaCertReference::Absent
        );
    }

    /// `x5u` is reported as itself, so the caller can refuse it by name. A
    /// conformant peer that chose §13.3.8.2's other arm gets told which arm is
    /// missing instead of a generic parse error.
    #[test]
    fn an_x5u_header_is_reported_as_a_url_not_an_error() {
        let header = serde_json::json!({
            "alg": "ES256",
            "x5u": "https://pki.example/nf/amf-1.crt",
        });
        assert_eq!(
            cert_reference_from_jose_header(&header).expect("parse"),
            CcaCertReference::Url("https://pki.example/nf/amf-1.crt".to_string())
        );
    }

    /// A present-but-malformed `x5c` is an ERROR, never `Absent`. If it degraded
    /// to `Absent` a requester could reach the weaker trust-store path by
    /// attaching a deliberately broken certificate — a downgrade it chooses.
    #[test]
    fn a_malformed_x5c_is_an_error_not_a_downgrade_to_absent() {
        for header in [
            serde_json::json!({"x5c": "not-an-array"}),
            serde_json::json!({"x5c": []}),
            serde_json::json!({"x5c": [42]}),
            // base64url where standard base64 is required (RFC 7515 §4.1.6).
            serde_json::json!({"x5c": ["!!!not base64!!!"]}),
        ] {
            let result = cert_reference_from_jose_header(&header);
            assert!(
                result.is_err(),
                "a malformed x5c must be refused, not treated as absent: {header:?} -> \
                 {result:?}"
            );
        }
    }

    /// An `x5c` entry that decodes as base64 but is not a certificate fails at
    /// path validation, not at parse time — and must not panic. This parses
    /// attacker-supplied bytes.
    #[test]
    fn garbage_der_in_x5c_fails_validation_without_panicking() {
        let key = crate::oauth::generate_es256_key();
        let (ca, _, _, _) = ca_and_leaf(&key, "urn:uuid:nf-1");
        let chain = CcaCertChain {
            der: vec![b"not a certificate".to_vec()],
        };
        assert!(verify_x5c_binding(&chain, &[ca], now()).is_err());
    }
}
