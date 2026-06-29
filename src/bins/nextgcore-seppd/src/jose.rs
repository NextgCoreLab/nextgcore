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
            cipher.encrypt(Nonce::from_slice(iv), Payload { msg: plaintext, aad })
        }
        JweEnc::A256Gcm => {
            let cipher =
                Aes256Gcm::new_from_slice(key).map_err(|e| JoseError::Crypto(e.to_string()))?;
            cipher.encrypt(Nonce::from_slice(iv), Payload { msg: plaintext, aad })
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
            cipher.decrypt(Nonce::from_slice(iv), Payload { msg: &ct_and_tag, aad })
        }
        JweEnc::A256Gcm => {
            let cipher =
                Aes256Gcm::new_from_slice(key).map_err(|e| JoseError::Crypto(e.to_string()))?;
            cipher.decrypt(Nonce::from_slice(iv), Payload { msg: &ct_and_tag, aad })
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
pub fn jws_verify_es256(
    verifying_key: &VerifyingKey,
    jws: &FlatJws,
) -> Result<Vec<u8>, JoseError> {
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

/// Read the `kid` and `alg` header of a flattened JWS without verifying it.
/// Used to locate the registered public key for the entity that signed it.
pub fn jws_peek_header(jws: &FlatJws) -> Result<(String, Option<String>), JoseError> {
    let header_bytes = b64url_decode(&jws.protected)?;
    let header: JwsHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| JoseError::Format(format!("JWS header: {e}")))?;
    Ok((header.alg, header.kid))
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
        let jwe = jwe_encrypt_with_iv_salt(&KEY, JweEnc::A256Gcm, &salt, seq, b"pt", None, None)
            .unwrap();
        let iv = b64url_decode(&jwe.iv).unwrap();
        assert_eq!(&iv[..8], &salt, "leading 8 octets are the IV salt");
        assert_eq!(&iv[8..], &seq.to_be_bytes(), "trailing 4 octets are SEQ (BE)");
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
        let a = jwe_encrypt_with_iv_salt(&KEY, JweEnc::A256Gcm, &salt, 0, b"x", None, None).unwrap();
        let b = jwe_encrypt_with_iv_salt(&KEY, JweEnc::A256Gcm, &salt, 1, b"x", None, None).unwrap();
        assert_ne!(a.iv, b.iv, "SEQ 0 and 1 must yield different nonces");
    }

    // ------------------------------------------------------------------
    // sepp-12: JWE enc profile A128GCM and A256GCM round trip
    // ------------------------------------------------------------------
    #[test]
    fn jwe_enc_profile_roundtrip_a128_and_a256() {
        let salt = [3u8; 8];
        for enc in [JweEnc::A128Gcm, JweEnc::A256Gcm] {
            let jwe =
                jwe_encrypt_with_iv_salt(&KEY, enc, &salt, 7, b"secret-supi", Some(b"aad"), Some("k"))
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
        let jwe = jwe_encrypt_with_iv_salt(&KEY, JweEnc::A128Gcm, &salt, 0, b"m", None, None).unwrap();
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
}
