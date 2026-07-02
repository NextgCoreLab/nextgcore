//! JOSE primitives for N32-f PRINS protection (TS 29.573 sec 6.3).
//!
//! Self-contained JWE (alg="dir", enc="A256GCM" per RFC 7516) and
//! JWS (alg="HS256" per RFC 7515) on RustCrypto crates already in the
//! workspace (`aes-gcm`, `hmac`, `sha2`, `base64`). TS 29.573 mandates the
//! flattened JSON serialization (FlatJweJson / FlatJwsJson) for the
//! N32fReformattedReqMsg, which is what this module produces: the
//! DataToIntegrityProtectBlock travels as the JWE external AAD and the
//! DataToIntegrityProtectAndCipherBlock as the JWE plaintext.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// JWE/JWS processing errors. Tamper conditions are distinguished so that
/// the caller can map them onto the proper `N32fErrorType`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoseError {
    /// Malformed serialization (bad base64, bad JSON header, missing field)
    Format(String),
    /// Header announces an algorithm this implementation does not support
    UnsupportedAlgorithm(String),
    /// AEAD tag or HMAC signature verification failed (tampered message)
    Tampered,
    /// Key has the wrong size or the cipher failed internally
    Crypto(String),
}

impl std::fmt::Display for JoseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JoseError::Format(s) => write!(f, "JOSE format error: {s}"),
            JoseError::UnsupportedAlgorithm(s) => write!(f, "unsupported JOSE algorithm: {s}"),
            JoseError::Tampered => write!(f, "JOSE integrity verification failed"),
            JoseError::Crypto(s) => write!(f, "JOSE crypto error: {s}"),
        }
    }
}

/// base64url without padding (RFC 7515 section 2 "Base64url Encoding")
pub fn b64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// base64url decode (no padding)
pub fn b64url_decode(input: &str) -> Result<Vec<u8>, JoseError> {
    URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|e| JoseError::Format(format!("base64url: {e}")))
}

// ============================================================================
// JWE - flattened JSON serialization, alg "dir", enc "A128GCM"/"A256GCM"
// ============================================================================

/// A256GCM key length (bytes). The N32-KDF derives a 32-octet session key;
/// A128GCM uses its first 16 octets (HKDF-Expand is prefix-stable, so this is
/// identical to a direct 16-octet derivation).
pub const JWE_KEY_LEN: usize = 32;
/// AES-GCM IV length (bytes) per RFC 7518 section 5.3
const JWE_IV_LEN: usize = 12;
/// AES-GCM tag length (bytes)
const JWE_TAG_LEN: usize = 16;

/// JWE content-encryption algorithm profile (TS 33.501 §13.2.4.9 / TS 33.210):
/// at least A128GCM and A256GCM. The N32-f session-key length follows the
/// selected enc (16 vs 32 octets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JweEnc {
    A128Gcm,
    A256Gcm,
}

impl JweEnc {
    /// Parse the IANA "enc" header value; `None` if unsupported.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "A128GCM" => Some(JweEnc::A128Gcm),
            "A256GCM" => Some(JweEnc::A256Gcm),
            _ => None,
        }
    }
    /// IANA "enc" header value.
    pub fn name(self) -> &'static str {
        match self {
            JweEnc::A128Gcm => "A128GCM",
            JweEnc::A256Gcm => "A256GCM",
        }
    }
    /// Content-encryption key length in octets (16 for A128GCM, 32 for A256GCM).
    pub fn key_len(self) -> usize {
        match self {
            JweEnc::A128Gcm => 16,
            JweEnc::A256Gcm => 32,
        }
    }
}

/// Flattened JWE JSON serialization (RFC 7516 section 7.2.2), the
/// `FlatJweJson` shape required by TS 29.573 for `reformattedData`.
/// With alg="dir" the `encrypted_key` member is absent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FlatJwe {
    /// base64url(UTF8(JWE Protected Header))
    pub protected: String,
    /// base64url(external AAD) - carries the DataToIntegrityProtectBlock
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,
    /// base64url(initialization vector)
    pub iv: String,
    /// base64url(ciphertext)
    pub ciphertext: String,
    /// base64url(authentication tag)
    pub tag: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct JweHeader {
    alg: String,
    enc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
}

/// Low-level AES-GCM encryption with caller-provided IV, dispatched by `enc`
/// (A128GCM / A256GCM). `key` must be exactly `enc.key_len()` octets.
/// Returns (ciphertext, tag).
fn gcm_encrypt(
    enc: JweEnc,
    key: &[u8],
    iv: &[u8; JWE_IV_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), JoseError> {
    let mut out = match enc {
        JweEnc::A128Gcm => {
            let cipher =
                Aes128Gcm::new_from_slice(key).map_err(|e| JoseError::Crypto(e.to_string()))?;
            cipher.encrypt(
                Nonce::from_slice(iv),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
        }
        JweEnc::A256Gcm => {
            let cipher =
                Aes256Gcm::new_from_slice(key).map_err(|e| JoseError::Crypto(e.to_string()))?;
            cipher.encrypt(
                Nonce::from_slice(iv),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
        }
    }
    .map_err(|e| JoseError::Crypto(e.to_string()))?;
    let tag = out.split_off(out.len() - JWE_TAG_LEN);
    Ok((out, tag))
}

/// Low-level AES-GCM decryption dispatched by `enc`. `key` must be exactly
/// `enc.key_len()` octets; `iv` must be 12 octets and `tag` 16 octets.
fn gcm_decrypt(
    enc: JweEnc,
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, JoseError> {
    if iv.len() != JWE_IV_LEN || tag.len() != JWE_TAG_LEN {
        return Err(JoseError::Format("bad IV/tag length".into()));
    }
    let mut ct_and_tag = Vec::with_capacity(ciphertext.len() + tag.len());
    ct_and_tag.extend_from_slice(ciphertext);
    ct_and_tag.extend_from_slice(tag);
    match enc {
        JweEnc::A128Gcm => {
            let cipher =
                Aes128Gcm::new_from_slice(key).map_err(|e| JoseError::Crypto(e.to_string()))?;
            cipher.decrypt(
                Nonce::from_slice(iv),
                Payload {
                    msg: &ct_and_tag,
                    aad,
                },
            )
        }
        JweEnc::A256Gcm => {
            let cipher =
                Aes256Gcm::new_from_slice(key).map_err(|e| JoseError::Crypto(e.to_string()))?;
            cipher.decrypt(
                Nonce::from_slice(iv),
                Payload {
                    msg: &ct_and_tag,
                    aad,
                },
            )
        }
    }
    .map_err(|_| JoseError::Tampered)
}

/// Low-level A256GCM encryption with caller-provided IV.
/// Returns (ciphertext, tag). Exposed for RFC 7516 known-answer tests.
pub fn a256gcm_encrypt(
    key: &[u8; JWE_KEY_LEN],
    iv: &[u8; JWE_IV_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), JoseError> {
    gcm_encrypt(JweEnc::A256Gcm, key, iv, aad, plaintext)
}

/// Low-level A256GCM decryption (RFC 7516 known-answer tests).
fn a256gcm_decrypt(
    key: &[u8; JWE_KEY_LEN],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, JoseError> {
    gcm_decrypt(JweEnc::A256Gcm, key, iv, aad, ciphertext, tag)
}

/// Build the AEAD AAD input per RFC 7516 section 5.1 step 14:
/// ASCII(Encoded Protected Header) when no external AAD, otherwise
/// ASCII(Encoded Protected Header || '.' || Encoded AAD).
fn jwe_aad_input(protected_b64: &str, aad_b64: Option<&str>) -> Vec<u8> {
    match aad_b64 {
        Some(aad) => format!("{protected_b64}.{aad}").into_bytes(),
        None => protected_b64.as_bytes().to_vec(),
    }
}

/// Encrypt `plaintext` as a flattened JWE with alg="dir" and the selected
/// `enc`, using the caller-supplied 96-bit IV. `key` must hold at least
/// `enc.key_len()` octets (the leading `enc.key_len()` are used). Shared core
/// of [`jwe_encrypt`] and [`jwe_encrypt_with_iv_salt`].
fn jwe_encrypt_with_iv(
    key: &[u8],
    enc: JweEnc,
    iv: &[u8; JWE_IV_LEN],
    plaintext: &[u8],
    external_aad: Option<&[u8]>,
    kid: Option<&str>,
) -> Result<FlatJwe, JoseError> {
    let klen = enc.key_len();
    if key.len() < klen {
        return Err(JoseError::Crypto(format!(
            "key too short for {}: need {klen}, got {}",
            enc.name(),
            key.len()
        )));
    }
    let key = &key[..klen];
    let header = JweHeader {
        alg: "dir".to_string(),
        enc: enc.name().to_string(),
        kid: kid.map(|s| s.to_string()),
    };
    let protected = b64url_encode(
        serde_json::to_string(&header)
            .map_err(|e| JoseError::Format(e.to_string()))?
            .as_bytes(),
    );
    let aad_b64 = external_aad.map(b64url_encode);

    let aad_input = jwe_aad_input(&protected, aad_b64.as_deref());
    let (ciphertext, tag) = gcm_encrypt(enc, key, iv, &aad_input, plaintext)?;

    Ok(FlatJwe {
        protected,
        aad: aad_b64,
        iv: b64url_encode(iv),
        ciphertext: b64url_encode(&ciphertext),
        tag: b64url_encode(&tag),
    })
}

/// Encrypt `plaintext` as a flattened JWE with alg="dir"/enc="A256GCM".
/// `external_aad` (raw bytes, will be base64url-encoded) carries the
/// integrity-protected-but-cleartext block per TS 29.573 sec 6.3. A fresh
/// 96-bit IV is generated at random.
pub fn jwe_encrypt(
    key: &[u8; JWE_KEY_LEN],
    plaintext: &[u8],
    external_aad: Option<&[u8]>,
    kid: Option<&str>,
) -> Result<FlatJwe, JoseError> {
    let mut iv = [0u8; JWE_IV_LEN];
    use rand::Rng as _;
    rand::rng().fill(&mut iv);
    jwe_encrypt_with_iv(key, JweEnc::A256Gcm, &iv, plaintext, external_aad, kid)
}

/// Encrypt `plaintext` as a flattened JWE with alg="dir" and the selected
/// `enc`, building the 96-bit AES-GCM nonce as the N32-f
/// `IV salt (8B) || SEQ (32-bit big-endian)` per TS 33.501 §13.2.4.4.1: the
/// per-(IV-salt/direction) SEQ counter guarantees nonce uniqueness without a
/// random component. The IV is transmitted in the JWE, so the receiver decrypts
/// via [`jwe_decrypt`] without reconstructing it (and reads SEQ back from it
/// for replay protection).
pub fn jwe_encrypt_with_iv_salt(
    key: &[u8],
    enc: JweEnc,
    iv_salt: &[u8; 8],
    seq: u32,
    plaintext: &[u8],
    external_aad: Option<&[u8]>,
    kid: Option<&str>,
) -> Result<FlatJwe, JoseError> {
    let mut iv = [0u8; JWE_IV_LEN];
    iv[..8].copy_from_slice(iv_salt);
    iv[8..].copy_from_slice(&seq.to_be_bytes());
    jwe_encrypt_with_iv(key, enc, &iv, plaintext, external_aad, kid)
}

/// Recover the `(IV salt, SEQ)` pair from a JWE's 12-octet nonce
/// (TS 33.501 §13.2.4.4.1: `Nonce = IV salt (8B) || SEQ (32-bit BE)`); used on
/// receive for the anti-replay window. `None` if the nonce is malformed.
pub fn jwe_iv_salt_and_seq(jwe: &FlatJwe) -> Option<([u8; 8], u32)> {
    let iv = b64url_decode(&jwe.iv).ok()?;
    if iv.len() != JWE_IV_LEN {
        return None;
    }
    let mut salt = [0u8; 8];
    salt.copy_from_slice(&iv[..8]);
    let seq = u32::from_be_bytes([iv[8], iv[9], iv[10], iv[11]]);
    Some((salt, seq))
}

/// Decrypt and verify a flattened JWE produced by [`jwe_encrypt`]. `key` must
/// hold at least the selected enc's key length (the leading octets are used);
/// callers pass the full 32-octet N32-f session key and the enc (A128/A256GCM)
/// is taken from the JWE header. The external AAD (if any) is authenticated as
/// part of decryption; the caller obtains it from `jwe.aad`.
pub fn jwe_decrypt(key: &[u8], jwe: &FlatJwe) -> Result<Vec<u8>, JoseError> {
    let header_bytes = b64url_decode(&jwe.protected)?;
    let header: JweHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| JoseError::Format(format!("JWE header: {e}")))?;
    if header.alg != "dir" {
        return Err(JoseError::UnsupportedAlgorithm(format!(
            "alg={} enc={}",
            header.alg, header.enc
        )));
    }
    let enc = JweEnc::from_name(&header.enc).ok_or_else(|| {
        JoseError::UnsupportedAlgorithm(format!("alg={} enc={}", header.alg, header.enc))
    })?;
    let klen = enc.key_len();
    if key.len() < klen {
        return Err(JoseError::Crypto(format!(
            "key too short for {}: need {klen}, got {}",
            enc.name(),
            key.len()
        )));
    }
    let key = &key[..klen];
    let iv = b64url_decode(&jwe.iv)?;
    let ciphertext = b64url_decode(&jwe.ciphertext)?;
    let tag = b64url_decode(&jwe.tag)?;
    // Validate the AAD member is well-formed base64url before use
    if let Some(ref aad) = jwe.aad {
        b64url_decode(aad)?;
    }
    let aad_input = jwe_aad_input(&jwe.protected, jwe.aad.as_deref());
    gcm_decrypt(enc, key, &iv, &aad_input, &ciphertext, &tag)
}

// ============================================================================
// JWS - flattened JSON serialization, alg "HS256"
// ============================================================================

/// Flattened JWS JSON serialization (RFC 7515 section 7.2.2), the
/// `FlatJwsJson` shape required by TS 29.573 for `modificationsBlock`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FlatJws {
    /// base64url(UTF8(JWS Protected Header))
    pub protected: String,
    /// base64url(JWS Payload)
    pub payload: String,
    /// base64url(JWS Signature)
    pub signature: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct JwsHeader {
    alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
}

/// HMAC-SHA-256 over a raw JWS signing input (`protected.payload`).
/// Exposed for RFC 7515 Appendix A.1 known-answer tests.
pub fn hs256_sign_input(key: &[u8], signing_input: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(signing_input);
    mac.finalize().into_bytes().to_vec()
}

/// Sign `payload` as a flattened HS256 JWS.
pub fn jws_sign(key: &[u8], payload: &[u8], kid: Option<&str>) -> Result<FlatJws, JoseError> {
    let header = JwsHeader {
        alg: "HS256".to_string(),
        kid: kid.map(|s| s.to_string()),
    };
    let protected = b64url_encode(
        serde_json::to_string(&header)
            .map_err(|e| JoseError::Format(e.to_string()))?
            .as_bytes(),
    );
    let payload_b64 = b64url_encode(payload);
    let signing_input = format!("{protected}.{payload_b64}");
    let signature = hs256_sign_input(key, signing_input.as_bytes());
    Ok(FlatJws {
        protected,
        payload: payload_b64,
        signature: b64url_encode(&signature),
    })
}

/// Verify a flattened HS256 JWS and return the raw payload bytes.
pub fn jws_verify(key: &[u8], jws: &FlatJws) -> Result<Vec<u8>, JoseError> {
    let header_bytes = b64url_decode(&jws.protected)?;
    let header: JwsHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| JoseError::Format(format!("JWS header: {e}")))?;
    if header.alg != "HS256" {
        return Err(JoseError::UnsupportedAlgorithm(header.alg));
    }
    let signature = b64url_decode(&jws.signature)?;
    let signing_input = format!("{}.{}", jws.protected, jws.payload);

    // Constant-time verification via the Mac trait
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|e| JoseError::Crypto(e.to_string()))?;
    mac.update(signing_input.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| JoseError::Tampered)?;

    b64url_decode(&jws.payload)
}

// ============================================================================
// JWS - flattened JSON serialization, alg "ES256" (asymmetric, ECDSA P-256)
//
// TS 33.501 §13.2.4.6 / TS 29.573 §6.3.4: each modificationsBlock entry must
// be signed with the *asymmetric* key of the SEPP/IPX that created it, and
// verified against that entity's registered public key. The shared symmetric
// N32-f session key is reserved for the JWE only; using it for the
// modificationsBlock JWS would make every entry forgeable by either peer.
// ============================================================================

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature as P256Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};

/// Sign `payload` as a flattened ES256 (ECDSA P-256 / SHA-256) JWS with the
/// signer's asymmetric private key.
pub fn jws_sign_es256(
    signing_key: &SigningKey,
    payload: &[u8],
    kid: Option<&str>,
) -> Result<FlatJws, JoseError> {
    let header = JwsHeader {
        alg: "ES256".to_string(),
        kid: kid.map(|s| s.to_string()),
    };
    let protected = b64url_encode(
        serde_json::to_string(&header)
            .map_err(|e| JoseError::Format(e.to_string()))?
            .as_bytes(),
    );
    let payload_b64 = b64url_encode(payload);
    let signing_input = format!("{protected}.{payload_b64}");
    // ES256 JWS signature is the raw R||S (64 bytes) per RFC 7518 §3.4.
    let sig: P256Signature = signing_key.sign(signing_input.as_bytes());
    let sig_bytes = sig.to_bytes();
    Ok(FlatJws {
        protected,
        payload: payload_b64,
        signature: b64url_encode(&sig_bytes),
    })
}

/// Verify a flattened ES256 JWS against the signer's public key and return
/// the raw payload bytes. Rejects any alg other than ES256.
pub fn jws_verify_es256(verifying_key: &VerifyingKey, jws: &FlatJws) -> Result<Vec<u8>, JoseError> {
    let header_bytes = b64url_decode(&jws.protected)?;
    let header: JwsHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| JoseError::Format(format!("JWS header: {e}")))?;
    if header.alg != "ES256" {
        return Err(JoseError::UnsupportedAlgorithm(header.alg));
    }
    let sig_bytes = b64url_decode(&jws.signature)?;
    let signature =
        P256Signature::try_from(sig_bytes.as_slice()).map_err(|_| JoseError::Tampered)?;
    let signing_input = format!("{}.{}", jws.protected, jws.payload);
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| JoseError::Tampered)?;
    b64url_decode(&jws.payload)
}

/// Parse a PEM-encoded PKCS#8 ECDSA P-256 private key.
pub fn parse_es256_private_key_pem(pem: &str) -> Result<SigningKey, JoseError> {
    SigningKey::from_pkcs8_pem(pem)
        .map_err(|e| JoseError::Crypto(format!("bad ES256 private key PEM: {e}")))
}

/// Parse a PEM-encoded SubjectPublicKeyInfo ECDSA P-256 public key.
pub fn parse_es256_public_key_pem(pem: &str) -> Result<VerifyingKey, JoseError> {
    VerifyingKey::from_public_key_pem(pem)
        .map_err(|e| JoseError::Crypto(format!("bad ES256 public key PEM: {e}")))
}

// ============================================================================
// X.509 certificate signing-key extraction (TS 29.573 §6.1.5.2.18
// IpxProviderSecInfo.certificateList; TS 33.501 §13.2.4.6 modificationsBlock).
//
// N32-c peers may advertise their ES256 modifications-signing key either as a
// raw SubjectPublicKeyInfo (the `rawPublicKeyList` PEM handled above) OR inside
// an X.509 certificate (`certificateList`). To verify a modificationsBlock a
// cert-profile peer signs, we must recover the SPKI from the certificate.
//
// x509-cert is not vendored offline, so the certificate is walked with a
// strict, fail-closed DER TLV reader that descends Certificate -> tbsCertificate
// and returns the raw `subjectPublicKeyInfo` element. That SPKI is then handed
// to p256/`spki` (`VerifyingKey::from_public_key_der`), which performs the
// security-critical validation: only a well-formed secp256r1 point on the
// ecPublicKey/prime256v1 algorithm is accepted. A location bug in the walker
// therefore still fails closed at the key decode; a non-ES256 (e.g. RSA or
// P-384) certificate is rejected, matching the raw-key path.
// ============================================================================

/// DER `SEQUENCE` (constructed) tag.
const DER_SEQUENCE: u8 = 0x30;
/// DER `[0]` EXPLICIT context-specific constructed tag (`tbsCertificate.version`).
const DER_CONTEXT_EXPLICIT_0: u8 = 0xA0;

/// One parsed DER TLV: its tag byte, the length of the tag+length header, and
/// the content length. The element occupies `header_len + content_len` bytes
/// starting at the read offset.
struct DerTlv {
    tag: u8,
    header_len: usize,
    content_len: usize,
}

/// Read a single DER TLV at `data[pos..]`. Strict / fail-closed: definite
/// lengths only (indefinite form is not valid DER), high-tag-number form is
/// rejected (never used on the Certificate spine we walk), and the element is
/// bounds-checked against the buffer.
fn der_read_tlv(data: &[u8], pos: usize) -> Result<DerTlv, JoseError> {
    let e = |m: &str| JoseError::Format(format!("X.509 DER: {m}"));
    let tag = *data.get(pos).ok_or_else(|| e("truncated at tag"))?;
    if tag & 0x1f == 0x1f {
        return Err(e("high-tag-number form unsupported"));
    }
    let len_byte = *data.get(pos + 1).ok_or_else(|| e("truncated at length"))?;
    let (content_len, len_size) = if len_byte & 0x80 == 0 {
        (len_byte as usize, 1usize)
    } else {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 {
            return Err(e("indefinite length is not valid DER"));
        }
        if n > 4 {
            return Err(e("length field too large"));
        }
        let mut len = 0usize;
        for k in 0..n {
            let b = *data
                .get(pos + 2 + k)
                .ok_or_else(|| e("truncated in long-form length"))?;
            len = (len << 8) | b as usize;
        }
        (len, 1 + n)
    };
    let header_len = 1 + len_size;
    let end = pos
        .checked_add(header_len)
        .and_then(|h| h.checked_add(content_len))
        .ok_or_else(|| e("length overflow"))?;
    if end > data.len() {
        return Err(e("element exceeds buffer"));
    }
    Ok(DerTlv {
        tag,
        header_len,
        content_len,
    })
}

/// Extract the raw `subjectPublicKeyInfo` DER element from an X.509 certificate
/// DER. Walks `Certificate ::= SEQUENCE { tbsCertificate, .. }` then the
/// `tbsCertificate` fields, skipping the optional `[0] version` and the fixed
/// prefix `serialNumber, signature, issuer, validity, subject` to reach the
/// SPKI (RFC 5280 §4.1). Returns the SPKI as its own DER SEQUENCE for
/// `VerifyingKey::from_public_key_der`.
fn spki_der_from_x509_der(cert: &[u8]) -> Result<Vec<u8>, JoseError> {
    let e = |m: &str| JoseError::Format(format!("X.509: {m}"));
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let outer = der_read_tlv(cert, 0)?;
    if outer.tag != DER_SEQUENCE {
        return Err(e("Certificate is not a SEQUENCE"));
    }
    if outer.header_len + outer.content_len != cert.len() {
        return Err(e("trailing bytes after Certificate"));
    }
    let tbs_container = &cert[outer.header_len..outer.header_len + outer.content_len];
    // tbsCertificate ::= SEQUENCE { .. } (first element of Certificate)
    let tbs_hdr = der_read_tlv(tbs_container, 0)?;
    if tbs_hdr.tag != DER_SEQUENCE {
        return Err(e("tbsCertificate is not a SEQUENCE"));
    }
    let tbs = &tbs_container[tbs_hdr.header_len..tbs_hdr.header_len + tbs_hdr.content_len];

    let mut pos = 0usize;
    // Optional [0] EXPLICIT version (DEFAULT v1 -> absent in v1 certs).
    let first = der_read_tlv(tbs, pos)?;
    if first.tag == DER_CONTEXT_EXPLICIT_0 {
        pos += first.header_len + first.content_len;
    }
    // Skip the five fixed fields before the SPKI: serialNumber, signature,
    // issuer, validity, subject.
    for _ in 0..5 {
        let f = der_read_tlv(tbs, pos)?;
        pos += f.header_len + f.content_len;
    }
    // subjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }
    let spki = der_read_tlv(tbs, pos)?;
    if spki.tag != DER_SEQUENCE {
        return Err(e("subjectPublicKeyInfo is not a SEQUENCE"));
    }
    let spki_end = pos + spki.header_len + spki.content_len;
    Ok(tbs[pos..spki_end].to_vec())
}

/// Decode an X.509 certificate supplied as RFC 7468 PEM (`-----BEGIN
/// CERTIFICATE-----`) or bare base64 DER into raw DER bytes. Fail-closed on any
/// base64 error or a missing PEM footer.
fn decode_certificate(input: &str) -> Result<Vec<u8>, JoseError> {
    use base64::engine::general_purpose::STANDARD;
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let trimmed = input.trim();
    let body: String = if let Some(begin) = trimmed.find(BEGIN) {
        let after = &trimmed[begin + BEGIN.len()..];
        let end = after
            .find(END)
            .ok_or_else(|| JoseError::Format("X.509 PEM: missing END CERTIFICATE".into()))?;
        after[..end].split_whitespace().collect()
    } else {
        trimmed.split_whitespace().collect()
    };
    STANDARD
        .decode(body.as_bytes())
        .map_err(|err| JoseError::Format(format!("X.509: bad base64 certificate: {err}")))
}

/// Extract and validate the ES256 (ECDSA P-256) signing key from an X.509
/// certificate supplied as RFC 7468 PEM or bare base64 DER, for the N32-c
/// `IpxProviderSecInfo.certificateList` profile (TS 29.573 §6.1.5.2.18,
/// TS 33.501 §13.2.4.6). Fail-closed: any structural DER error, or an SPKI that
/// is not a valid secp256r1 public key, is rejected. The final key validation
/// is delegated to p256/`spki`, so only genuine ES256 keys are accepted.
pub fn parse_es256_public_key_from_cert(cert: &str) -> Result<VerifyingKey, JoseError> {
    let der = decode_certificate(cert)?;
    let spki = spki_der_from_x509_der(&der)?;
    VerifyingKey::from_public_key_der(&spki).map_err(|err| {
        JoseError::Crypto(format!("certificate SPKI is not a valid ES256 key: {err}"))
    })
}

/// Read the `kid` and `alg` header of a flattened JWS without verifying it.
/// Used to locate the registered public key for the entity that signed it.
pub fn jws_peek_header(jws: &FlatJws) -> Result<(String, Option<String>), JoseError> {
    let header_bytes = b64url_decode(&jws.protected)?;
    let header: JwsHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| JoseError::Format(format!("JWS header: {e}")))?;
    Ok((header.alg, header.kid))
}

/// Test-only: build a minimal but structurally-valid X.509 v3 certificate DER
/// (RFC 5280 §4.1 spine) wrapping the given `subjectPublicKeyInfo` bytes, then
/// PEM-armor it. The signature is a placeholder — extraction never validates
/// it. Shared with the n32c_handler cert-registration tests.
#[cfg(test)]
pub(crate) fn build_test_x509_cert_pem_from_spki(spki: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else if len < 0x100 {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push((len & 0xff) as u8);
        }
        out.extend_from_slice(content);
        out
    }
    // AlgorithmIdentifier { ecdsa-with-SHA256 } (OID 1.2.840.10045.4.3.2).
    let sig_algid = tlv(
        0x30,
        &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02],
    );
    let version = tlv(DER_CONTEXT_EXPLICIT_0, &tlv(0x02, &[0x02])); // [0] INTEGER 2 (v3)
    let serial = tlv(0x02, &[0x01]); // serialNumber
    let issuer = tlv(0x30, &[]); // empty RDNSequence
    let mut validity_content = tlv(0x17, b"260101000000Z"); // UTCTime notBefore
    validity_content.extend_from_slice(&tlv(0x17, b"270101000000Z")); // UTCTime notAfter
    let validity = tlv(0x30, &validity_content);
    let subject = tlv(0x30, &[]); // empty RDNSequence

    let mut tbs_content = Vec::new();
    for part in [&version, &serial, &sig_algid, &issuer, &validity, &subject] {
        tbs_content.extend_from_slice(part);
    }
    tbs_content.extend_from_slice(spki);
    let tbs = tlv(0x30, &tbs_content);
    let sig_value = tlv(0x03, &[0x00, 0xde, 0xad, 0xbe, 0xef]); // placeholder BIT STRING

    let mut cert_content = Vec::new();
    cert_content.extend_from_slice(&tbs);
    cert_content.extend_from_slice(&sig_algid);
    cert_content.extend_from_slice(&sig_value);
    let cert = tlv(0x30, &cert_content);

    let b64 = STANDARD.encode(&cert);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// Test-only: build a certificate PEM carrying `vk`'s SubjectPublicKeyInfo.
#[cfg(test)]
pub(crate) fn build_test_x509_cert_pem(vk: &VerifyingKey) -> String {
    use p256::pkcs8::EncodePublicKey;
    let spki = vk.to_public_key_der().unwrap().as_bytes().to_vec();
    build_test_x509_cert_pem_from_spki(&spki)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];

    // ------------------------------------------------------------------
    // RFC 7515 Appendix A.1 - HS256 known-answer vector
    // ------------------------------------------------------------------
    #[test]
    fn rfc7515_a1_hs256_vector() {
        let key = b64url_decode(
            "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
        )
        .unwrap();
        let signing_input = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        let sig = hs256_sign_input(&key, signing_input.as_bytes());
        assert_eq!(
            b64url_encode(&sig),
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        );
    }

    // ------------------------------------------------------------------
    // RFC 7516 Appendix A.1 - A256GCM content-encryption known answer
    // (the RSA-OAEP key wrap is out of scope; we test the AEAD step with
    // the appendix CEK/IV/AAD, which is exactly what enc="A256GCM" does)
    // ------------------------------------------------------------------
    #[test]
    fn rfc7516_a1_a256gcm_vector() {
        let cek: [u8; 32] = [
            177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7,
            110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252,
        ];
        let iv: [u8; 12] = [227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219];
        let aad = b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ";
        let plaintext = b"The true sign of intelligence is not knowledge but imagination.";

        let (ct, tag) = a256gcm_encrypt(&cek, &iv, aad, plaintext).unwrap();
        assert_eq!(
            b64url_encode(&ct),
            "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A"
        );
        assert_eq!(b64url_encode(&tag), "XFBoMYUZodetZdvTiFvSkQ");

        // And the reverse direction
        let pt = a256gcm_decrypt(&cek, &iv, aad, &ct, &tag).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn jwe_roundtrip_with_external_aad() {
        let aad = br#"{"requestLine":"POST /nudm-sdm/v1"}"#;
        let jwe = jwe_encrypt(&KEY, b"secret-supi", Some(aad), Some("kid-1")).unwrap();
        assert!(jwe.aad.is_some());
        let pt = jwe_decrypt(&KEY, &jwe).unwrap();
        assert_eq!(pt, b"secret-supi");
    }

    #[test]
    fn jwe_roundtrip_without_aad() {
        let jwe = jwe_encrypt(&KEY, b"payload", None, None).unwrap();
        assert_eq!(jwe_decrypt(&KEY, &jwe).unwrap(), b"payload");
    }

    #[test]
    fn jwe_tampered_ciphertext_rejected() {
        let mut jwe = jwe_encrypt(&KEY, b"secret", Some(b"aad"), None).unwrap();
        let mut ct = b64url_decode(&jwe.ciphertext).unwrap();
        ct[0] ^= 0x01;
        jwe.ciphertext = b64url_encode(&ct);
        assert_eq!(jwe_decrypt(&KEY, &jwe), Err(JoseError::Tampered));
    }

    #[test]
    fn jwe_tampered_aad_rejected() {
        let mut jwe = jwe_encrypt(&KEY, b"secret", Some(b"integrity-block"), None).unwrap();
        jwe.aad = Some(b64url_encode(b"integrity-block-MODIFIED"));
        assert_eq!(jwe_decrypt(&KEY, &jwe), Err(JoseError::Tampered));
    }

    #[test]
    fn jwe_tampered_tag_rejected() {
        let mut jwe = jwe_encrypt(&KEY, b"secret", None, None).unwrap();
        let mut tag = b64url_decode(&jwe.tag).unwrap();
        tag[15] ^= 0x80;
        jwe.tag = b64url_encode(&tag);
        assert_eq!(jwe_decrypt(&KEY, &jwe), Err(JoseError::Tampered));
    }

    #[test]
    fn jwe_wrong_key_rejected() {
        let jwe = jwe_encrypt(&KEY, b"secret", None, None).unwrap();
        let wrong = [8u8; 32];
        assert_eq!(jwe_decrypt(&wrong, &jwe), Err(JoseError::Tampered));
    }

    #[test]
    fn jwe_unsupported_alg_rejected() {
        let mut jwe = jwe_encrypt(&KEY, b"secret", None, None).unwrap();
        jwe.protected = b64url_encode(br#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#);
        assert!(matches!(
            jwe_decrypt(&KEY, &jwe),
            Err(JoseError::UnsupportedAlgorithm(_))
        ));
    }

    // ------------------------------------------------------------------
    // sepp-02: nonce = IV salt(8) || SEQ(32-bit BE)
    // ------------------------------------------------------------------
    #[test]
    fn jwe_nonce_is_iv_salt_concat_seq() {
        let salt: [u8; 8] = [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7];
        let seq: u32 = 0x0001_02ff;
        let jwe =
            jwe_encrypt_with_iv_salt(&KEY, JweEnc::A256Gcm, &salt, seq, b"pt", None, None).unwrap();
        let iv = b64url_decode(&jwe.iv).unwrap();
        assert_eq!(&iv[..8], &salt, "leading 8 octets are the IV salt");
        assert_eq!(
            &iv[8..],
            &seq.to_be_bytes(),
            "trailing 4 octets are SEQ (BE)"
        );
        // And the recovered (salt, seq) round-trips.
        let (rsalt, rseq) = jwe_iv_salt_and_seq(&jwe).unwrap();
        assert_eq!(rsalt, salt);
        assert_eq!(rseq, seq);
        // Decrypt still works (full 32-octet key, enc from header).
        assert_eq!(jwe_decrypt(&KEY, &jwe).unwrap(), b"pt");
    }

    #[test]
    fn jwe_same_salt_distinct_seq_distinct_nonces() {
        let salt: [u8; 8] = [9u8; 8];
        let a =
            jwe_encrypt_with_iv_salt(&KEY, JweEnc::A256Gcm, &salt, 0, b"x", None, None).unwrap();
        let b =
            jwe_encrypt_with_iv_salt(&KEY, JweEnc::A256Gcm, &salt, 1, b"x", None, None).unwrap();
        assert_ne!(a.iv, b.iv, "SEQ 0 and 1 must yield different nonces");
    }

    // ------------------------------------------------------------------
    // sepp-12: JWE enc profile A128GCM and A256GCM round trip
    // ------------------------------------------------------------------
    #[test]
    fn jwe_enc_profile_roundtrip_a128_and_a256() {
        let salt = [3u8; 8];
        for enc in [JweEnc::A128Gcm, JweEnc::A256Gcm] {
            let jwe = jwe_encrypt_with_iv_salt(
                &KEY,
                enc,
                &salt,
                7,
                b"secret-supi",
                Some(b"aad"),
                Some("k"),
            )
            .unwrap();
            // Header advertises the selected enc.
            let hdr: JweHeader =
                serde_json::from_slice(&b64url_decode(&jwe.protected).unwrap()).unwrap();
            assert_eq!(hdr.enc, enc.name());
            // A128GCM uses the first 16 octets of the 32-octet key.
            assert_eq!(jwe_decrypt(&KEY, &jwe).unwrap(), b"secret-supi");
        }
    }

    #[test]
    fn jwe_a128gcm_uses_16_byte_key_prefix() {
        // The leading 16 octets of `KEY` must decrypt an A128GCM JWE made with
        // the full key (proves "session-key length follows the selected enc").
        let salt = [1u8; 8];
        let jwe =
            jwe_encrypt_with_iv_salt(&KEY, JweEnc::A128Gcm, &salt, 0, b"m", None, None).unwrap();
        let mut k16 = [0u8; 32];
        k16[..16].copy_from_slice(&KEY[..16]);
        assert_eq!(jwe_decrypt(&k16, &jwe).unwrap(), b"m");
    }

    #[test]
    fn jws_roundtrip() {
        let jws = jws_sign(&KEY, b"{\"op\":\"replace\"}", Some("kid-1")).unwrap();
        let payload = jws_verify(&KEY, &jws).unwrap();
        assert_eq!(payload, b"{\"op\":\"replace\"}");
    }

    #[test]
    fn jws_tampered_payload_rejected() {
        let mut jws = jws_sign(&KEY, b"original", None).unwrap();
        jws.payload = b64url_encode(b"modified");
        assert_eq!(jws_verify(&KEY, &jws), Err(JoseError::Tampered));
    }

    #[test]
    fn jws_tampered_signature_rejected() {
        let mut jws = jws_sign(&KEY, b"original", None).unwrap();
        let mut sig = b64url_decode(&jws.signature).unwrap();
        sig[0] ^= 0xff;
        jws.signature = b64url_encode(&sig);
        assert_eq!(jws_verify(&KEY, &jws), Err(JoseError::Tampered));
    }

    #[test]
    fn jws_wrong_key_rejected() {
        let jws = jws_sign(&KEY, b"original", None).unwrap();
        assert_eq!(jws_verify(&[9u8; 32], &jws), Err(JoseError::Tampered));
    }

    #[test]
    fn jws_unsupported_alg_rejected() {
        let mut jws = jws_sign(&KEY, b"x", None).unwrap();
        jws.protected = b64url_encode(br#"{"alg":"none"}"#);
        assert!(matches!(
            jws_verify(&KEY, &jws),
            Err(JoseError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn b64url_roundtrip() {
        for data in [&b""[..], b"f", b"fo", b"foo", b"foobar", &[0u8, 255, 128]] {
            assert_eq!(b64url_decode(&b64url_encode(data)).unwrap(), data);
        }
    }

    // ------------------------------------------------------------------
    // ES256 asymmetric JWS (TS 33.501 §13.2.4.6)
    // ------------------------------------------------------------------

    fn es256_keypair() -> (SigningKey, VerifyingKey) {
        // p256 expects rand_core 0.6's OsRng (re-exported via elliptic-curve),
        // distinct from the workspace `rand` 0.9 OsRng.
        use p256::elliptic_curve::rand_core::OsRng;
        let sk = SigningKey::random(&mut OsRng);
        let vk = *sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn es256_jws_roundtrip() {
        let (sk, vk) = es256_keypair();
        let jws = jws_sign_es256(&sk, b"{\"op\":\"replace\"}", Some("sepp-a")).unwrap();
        let (alg, kid) = jws_peek_header(&jws).unwrap();
        assert_eq!(alg, "ES256");
        assert_eq!(kid.as_deref(), Some("sepp-a"));
        let payload = jws_verify_es256(&vk, &jws).unwrap();
        assert_eq!(payload, b"{\"op\":\"replace\"}");
    }

    #[test]
    fn es256_jws_tampered_payload_rejected() {
        let (sk, vk) = es256_keypair();
        let mut jws = jws_sign_es256(&sk, b"original", None).unwrap();
        jws.payload = b64url_encode(b"modified");
        assert_eq!(jws_verify_es256(&vk, &jws), Err(JoseError::Tampered));
    }

    #[test]
    fn es256_jws_wrong_key_rejected() {
        let (sk, _vk) = es256_keypair();
        let (_sk2, vk2) = es256_keypair();
        let jws = jws_sign_es256(&sk, b"original", None).unwrap();
        // Signed by sk, but verified against an unrelated public key
        assert_eq!(jws_verify_es256(&vk2, &jws), Err(JoseError::Tampered));
    }

    #[test]
    fn es256_jws_rejects_hs256_alg() {
        // An HS256 (symmetric) JWS must NOT verify under the ES256 path:
        // this prevents algorithm-confusion / symmetric-key forgery.
        let (_sk, vk) = es256_keypair();
        let hs = jws_sign(&[7u8; 32], b"forged", None).unwrap();
        assert!(matches!(
            jws_verify_es256(&vk, &hs),
            Err(JoseError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn es256_pem_roundtrip() {
        use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
        let (sk, vk) = es256_keypair();
        let sk_pem = sk.to_pkcs8_pem(LineEnding::LF).unwrap();
        let vk_pem = vk.to_public_key_pem(LineEnding::LF).unwrap();

        let sk2 = parse_es256_private_key_pem(&sk_pem).unwrap();
        let vk2 = parse_es256_public_key_pem(&vk_pem).unwrap();

        let jws = jws_sign_es256(&sk2, b"payload", None).unwrap();
        assert_eq!(jws_verify_es256(&vk2, &jws).unwrap(), b"payload");
    }

    /// Golden byte-vector: the SPKI recovered from an X.509 certificate by the
    /// hand-rolled DER walk is byte-identical to the SPKI encoded independently
    /// by p256/`spki` (dual-derivation, per the wave's golden-vector method),
    /// AND matches the hand-derived RFC 5480 P-256 SPKI constant.
    #[test]
    fn es256_cert_spki_extraction_golden() {
        // Fixed private scalar -> deterministic public key -> deterministic SPKI.
        let sk = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let vk = *sk.verifying_key();
        let expected_spki = {
            use p256::pkcs8::EncodePublicKey;
            vk.to_public_key_der().unwrap().as_bytes().to_vec()
        };

        let cert_pem = build_test_x509_cert_pem(&vk);
        let der = decode_certificate(&cert_pem).unwrap();
        let spki = spki_der_from_x509_der(&der).unwrap();

        // Derivation 1 (hand DER walk) == derivation 2 (p256/spki encoder).
        assert_eq!(spki, expected_spki);
        // Hand-derived spec constant: a P-256 SubjectPublicKeyInfo is 91 bytes
        // and begins with SEQUENCE{ SEQUENCE{ ecPublicKey OID, prime256v1 OID },
        // BIT STRING 00 04 } (RFC 5480 §2.1.1).
        assert_eq!(spki.len(), 91);
        let p256_spki_prefix: [u8; 27] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        ];
        assert_eq!(&spki[..27], &p256_spki_prefix);

        // The recovered VerifyingKey is A's actual key, and verifies A's JWS.
        let recovered = parse_es256_public_key_from_cert(&cert_pem).unwrap();
        assert_eq!(recovered, vk);
        let jws = jws_sign_es256(&sk, b"modificationsBlock", None).unwrap();
        assert_eq!(
            jws_verify_es256(&recovered, &jws).unwrap(),
            b"modificationsBlock"
        );
    }

    /// The cert path is fail-closed: junk, truncated DER, and a structurally
    /// valid certificate whose SPKI is not a secp256r1 key are all rejected.
    #[test]
    fn es256_cert_extraction_fail_closed() {
        // Not PEM and not base64.
        assert!(parse_es256_public_key_from_cert("this is not a certificate!").is_err());

        // Empty / no key material.
        assert!(parse_es256_public_key_from_cert("").is_err());

        // Truncated DER (outer SEQUENCE header intact, body cut).
        let (_sk, vk) = es256_keypair();
        let cert_pem = build_test_x509_cert_pem(&vk);
        let mut der = decode_certificate(&cert_pem).unwrap();
        der.truncate(der.len() / 2);
        assert!(spki_der_from_x509_der(&der).is_err());

        // Structurally valid cert, but the SPKI is a bogus SEQUENCE (not a
        // P-256 key): the walker extracts it, p256's decode rejects it.
        let bogus_spki: Vec<u8> = vec![0x30, 0x03, 0x02, 0x01, 0x00]; // SEQUENCE { INTEGER 0 }
        let bogus_cert = build_test_x509_cert_pem_from_spki(&bogus_spki);
        let extracted = {
            let d = decode_certificate(&bogus_cert).unwrap();
            spki_der_from_x509_der(&d).unwrap()
        };
        assert_eq!(extracted, bogus_spki); // walker located it correctly
        assert!(parse_es256_public_key_from_cert(&bogus_cert).is_err()); // key decode fails closed

        // Missing PEM footer.
        assert!(parse_es256_public_key_from_cert("-----BEGIN CERTIFICATE-----\nQUJD").is_err());
    }

    /// A v1 certificate (no `[0] version` field) is also walked correctly:
    /// with the optional version absent, the SPKI is still located.
    #[test]
    fn es256_cert_spki_extraction_no_version_field() {
        use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
        let sk = SigningKey::from_slice(&[0x2au8; 32]).unwrap();
        let vk = *sk.verifying_key();
        let spki = vk.to_public_key_der().unwrap().as_bytes().to_vec();

        // Build a v1 TBSCertificate: serialNumber, signature, issuer, validity,
        // subject, subjectPublicKeyInfo (NO [0] version).
        fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            let len = content.len();
            if len < 0x80 {
                out.push(len as u8);
            } else {
                out.push(0x81);
                out.push(len as u8);
            }
            out.extend_from_slice(content);
            out
        }
        let sig_algid = tlv(
            0x30,
            &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02],
        );
        let mut validity_content = tlv(0x17, b"260101000000Z");
        validity_content.extend_from_slice(&tlv(0x17, b"270101000000Z"));
        let mut tbs_content = Vec::new();
        tbs_content.extend_from_slice(&tlv(0x02, &[0x01])); // serialNumber
        tbs_content.extend_from_slice(&sig_algid); // signature
        tbs_content.extend_from_slice(&tlv(0x30, &[])); // issuer
        tbs_content.extend_from_slice(&tlv(0x30, &validity_content)); // validity
        tbs_content.extend_from_slice(&tlv(0x30, &[])); // subject
        tbs_content.extend_from_slice(&spki); // subjectPublicKeyInfo
        let tbs = tlv(0x30, &tbs_content);
        let mut cert_content = tbs;
        cert_content.extend_from_slice(&sig_algid);
        cert_content.extend_from_slice(&tlv(0x03, &[0x00, 0x01]));
        let cert = tlv(0x30, &cert_content);

        let got = spki_der_from_x509_der(&cert).unwrap();
        assert_eq!(got, spki);
        assert_eq!(VerifyingKey::from_public_key_der(&got).unwrap(), vk);
    }
}
