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
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
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
// JWE - flattened JSON serialization, alg "dir", enc "A256GCM"
// ============================================================================

/// A256GCM key length (bytes)
pub const JWE_KEY_LEN: usize = 32;
/// AES-GCM IV length (bytes) per RFC 7518 section 5.3
const JWE_IV_LEN: usize = 12;
/// AES-GCM tag length (bytes)
const JWE_TAG_LEN: usize = 16;

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

/// Low-level A256GCM encryption with caller-provided IV.
/// Returns (ciphertext, tag). Exposed for RFC 7516 known-answer tests.
pub fn a256gcm_encrypt(
    key: &[u8; JWE_KEY_LEN],
    iv: &[u8; JWE_IV_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), JoseError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| JoseError::Crypto(e.to_string()))?;
    let mut out = cipher
        .encrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| JoseError::Crypto(e.to_string()))?;
    let tag = out.split_off(out.len() - JWE_TAG_LEN);
    Ok((out, tag))
}

/// Low-level A256GCM decryption.
fn a256gcm_decrypt(
    key: &[u8; JWE_KEY_LEN],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, JoseError> {
    if iv.len() != JWE_IV_LEN || tag.len() != JWE_TAG_LEN {
        return Err(JoseError::Format("bad IV/tag length".into()));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| JoseError::Crypto(e.to_string()))?;
    let mut ct_and_tag = Vec::with_capacity(ciphertext.len() + tag.len());
    ct_and_tag.extend_from_slice(ciphertext);
    ct_and_tag.extend_from_slice(tag);
    cipher
        .decrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: &ct_and_tag,
                aad,
            },
        )
        .map_err(|_| JoseError::Tampered)
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

/// Encrypt `plaintext` as a flattened JWE with alg="dir"/enc="A256GCM".
/// `external_aad` (raw bytes, will be base64url-encoded) carries the
/// integrity-protected-but-cleartext block per TS 29.573 sec 6.3.
pub fn jwe_encrypt(
    key: &[u8; JWE_KEY_LEN],
    plaintext: &[u8],
    external_aad: Option<&[u8]>,
    kid: Option<&str>,
) -> Result<FlatJwe, JoseError> {
    let header = JweHeader {
        alg: "dir".to_string(),
        enc: "A256GCM".to_string(),
        kid: kid.map(|s| s.to_string()),
    };
    let protected = b64url_encode(
        serde_json::to_string(&header)
            .map_err(|e| JoseError::Format(e.to_string()))?
            .as_bytes(),
    );
    let aad_b64 = external_aad.map(b64url_encode);

    let mut iv = [0u8; JWE_IV_LEN];
    use rand::Rng as _;
    rand::rng().fill(&mut iv);

    let aad_input = jwe_aad_input(&protected, aad_b64.as_deref());
    let (ciphertext, tag) = a256gcm_encrypt(key, &iv, &aad_input, plaintext)?;

    Ok(FlatJwe {
        protected,
        aad: aad_b64,
        iv: b64url_encode(&iv),
        ciphertext: b64url_encode(&ciphertext),
        tag: b64url_encode(&tag),
    })
}

/// Decrypt and verify a flattened JWE produced by [`jwe_encrypt`].
/// Returns the plaintext. The external AAD (if any) is authenticated as
/// part of decryption; the caller obtains it from `jwe.aad`.
pub fn jwe_decrypt(key: &[u8; JWE_KEY_LEN], jwe: &FlatJwe) -> Result<Vec<u8>, JoseError> {
    let header_bytes = b64url_decode(&jwe.protected)?;
    let header: JweHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| JoseError::Format(format!("JWE header: {e}")))?;
    if header.alg != "dir" || header.enc != "A256GCM" {
        return Err(JoseError::UnsupportedAlgorithm(format!(
            "alg={} enc={}",
            header.alg, header.enc
        )));
    }
    let iv = b64url_decode(&jwe.iv)?;
    let ciphertext = b64url_decode(&jwe.ciphertext)?;
    let tag = b64url_decode(&jwe.tag)?;
    // Validate the AAD member is well-formed base64url before use
    if let Some(ref aad) = jwe.aad {
        b64url_decode(aad)?;
    }
    let aad_input = jwe_aad_input(&jwe.protected, jwe.aad.as_deref());
    a256gcm_decrypt(key, &iv, &aad_input, &ciphertext, &tag)
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
}
