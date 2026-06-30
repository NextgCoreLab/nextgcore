//! ECIES Profile A (3GPP TS 33.501 Annex C.3.4.1) and SUCI scheme-output helpers
//!
//! Profile A uses Curve25519 (X25519) for the ephemeral-static Diffie-Hellman,
//! the ANSI X9.63 KDF with SHA-256 (SharedInfo = ephemeral public key) for key
//! derivation, AES-128-CTR keyed with the derived initial counter block (ICB)
//! for confidentiality, and HMAC-SHA-256 truncated to 64 bits for integrity.
//!
//! Profile B (P-256) lives in [`crate::ecc`]; this module additionally provides
//! the scheme-output level deconcealment helpers used for SUCI (TS 23.003
//! §2.2B): `scheme_output = ephemeral_public_key || ciphertext || mac_tag(8)`.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::ecc::{
    ecies_profile_b_decrypt, EccError, ECC_BYTES, ECC_PUBLIC_KEY_SIZE, ECIES_MAC_TAG_SIZE,
};
use crate::kdf::nextgcore_kdf_ansi_x963;

/// X25519 key size in bytes (Profile A keys and shared secret)
pub const ECIES_X25519_KEY_SIZE: usize = 32;

/// ECIES errors (Profile A and SUCI scheme-output level)
#[derive(Error, Debug)]
pub enum EciesError {
    #[error("Invalid key length")]
    InvalidKey,
    #[error("Scheme output too short")]
    SchemeOutputTooShort,
    #[error("MAC verification failed")]
    MacVerificationFailed,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Profile B error: {0}")]
    ProfileB(#[from] EccError),
}

/// Result type for ECIES operations
pub type EciesResult<T> = Result<T, EciesError>;

/// AES-128-CTR with explicit initial counter block (shared with Profile B semantics).
fn aes128_ctr(key: &[u8; 16], icb: &[u8; 16], data: &[u8]) -> Vec<u8> {
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockEncrypt, KeyInit};
    use aes::Aes128;

    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut output = vec![0u8; data.len()];
    let mut counter = *icb;
    let mut pos = 0;

    while pos < data.len() {
        let mut keystream = GenericArray::clone_from_slice(&counter);
        cipher.encrypt_block(&mut keystream);

        let block_len = (data.len() - pos).min(16);
        for i in 0..block_len {
            output[pos + i] = data[pos + i] ^ keystream[i];
        }
        pos += block_len;

        // Increment counter (big-endian)
        let mut carry: u16 = 1;
        for j in (0..16).rev() {
            carry += counter[j] as u16;
            counter[j] = carry as u8;
            carry >>= 8;
            if carry == 0 {
                break;
            }
        }
    }

    output
}

/// HMAC-SHA-256 over `data`, truncated to the 8-byte ECIES MAC tag.
fn hmac_tag(mac_key: &[u8; 32], data: &[u8]) -> EciesResult<[u8; ECIES_MAC_TAG_SIZE]> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(mac_key).map_err(|_| EciesError::EncryptionFailed)?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut tag = [0u8; ECIES_MAC_TAG_SIZE];
    tag.copy_from_slice(&result[..ECIES_MAC_TAG_SIZE]);
    Ok(tag)
}

/// ECIES Profile A encryption (TS 33.501 Annex C.3.4.1).
///
/// Generates a fresh X25519 ephemeral key pair, computes the shared secret with
/// the home network public key, derives (enc key, ICB, MAC key) via the X9.63
/// KDF with SharedInfo = ephemeral public key, then encrypts with AES-128-CTR
/// and MACs the ciphertext with HMAC-SHA-256/64.
///
/// Returns `(ephemeral_public_key, ciphertext, mac_tag)`.
pub fn ecies_profile_a_encrypt(
    hn_pub_key: &[u8; ECIES_X25519_KEY_SIZE],
    plaintext: &[u8],
) -> EciesResult<(
    [u8; ECIES_X25519_KEY_SIZE],
    Vec<u8>,
    [u8; ECIES_MAC_TAG_SIZE],
)> {
    let mut eph_priv = [0u8; ECIES_X25519_KEY_SIZE];
    nextgcore_core::rand::nextgcore_random(&mut eph_priv);
    ecies_profile_a_encrypt_with_ephemeral(hn_pub_key, plaintext, &eph_priv)
}

/// ECIES Profile A encryption with a caller-supplied ephemeral private key.
///
/// Deterministic variant of [`ecies_profile_a_encrypt`] used for the TS 33.501
/// Annex C.4 test vectors.
pub fn ecies_profile_a_encrypt_with_ephemeral(
    hn_pub_key: &[u8; ECIES_X25519_KEY_SIZE],
    plaintext: &[u8],
    eph_priv: &[u8; ECIES_X25519_KEY_SIZE],
) -> EciesResult<(
    [u8; ECIES_X25519_KEY_SIZE],
    Vec<u8>,
    [u8; ECIES_MAC_TAG_SIZE],
)> {
    let secret = StaticSecret::from(*eph_priv);
    let eph_pub = X25519PublicKey::from(&secret);
    let shared = secret.diffie_hellman(&X25519PublicKey::from(*hn_pub_key));

    let (enc_key, icb, mac_key) = nextgcore_kdf_ansi_x963(shared.as_bytes(), eph_pub.as_bytes());

    let ciphertext = aes128_ctr(&enc_key, &icb, plaintext);
    let mac_tag = hmac_tag(&mac_key, &ciphertext)?;

    Ok((*eph_pub.as_bytes(), ciphertext, mac_tag))
}

/// ECIES Profile A decryption (TS 33.501 Annex C.3.4.1).
///
/// Computes the X25519 shared secret from the home network private key and the
/// UE ephemeral public key, derives keys via the X9.63 KDF (SharedInfo =
/// ephemeral public key), verifies the HMAC-SHA-256/64 tag, then decrypts.
pub fn ecies_profile_a_decrypt(
    hn_priv_key: &[u8; ECIES_X25519_KEY_SIZE],
    ephemeral_pub: &[u8; ECIES_X25519_KEY_SIZE],
    ciphertext: &[u8],
    mac_tag: &[u8; ECIES_MAC_TAG_SIZE],
) -> EciesResult<Vec<u8>> {
    let secret = StaticSecret::from(*hn_priv_key);
    let shared = secret.diffie_hellman(&X25519PublicKey::from(*ephemeral_pub));

    let (enc_key, icb, mac_key) = nextgcore_kdf_ansi_x963(shared.as_bytes(), ephemeral_pub);

    let expected = hmac_tag(&mac_key, ciphertext)?;
    if expected != *mac_tag {
        return Err(EciesError::MacVerificationFailed);
    }

    Ok(aes128_ctr(&enc_key, &icb, ciphertext))
}

/// Derive the X25519 public key from a Profile A home network private key.
pub fn x25519_public_key(priv_key: &[u8; ECIES_X25519_KEY_SIZE]) -> [u8; ECIES_X25519_KEY_SIZE] {
    let secret = StaticSecret::from(*priv_key);
    *X25519PublicKey::from(&secret).as_bytes()
}

/// Deconceal a SUCI Profile A scheme output (TS 23.003 §2.2B, scheme 1).
///
/// `scheme_output = eph_pub(32) || ciphertext || mac_tag(8)`.
/// Returns the decrypted plaintext block (MSIN in BCD).
pub fn suci_deconceal_profile_a(
    hn_priv_key: &[u8; ECIES_X25519_KEY_SIZE],
    scheme_output: &[u8],
) -> EciesResult<Vec<u8>> {
    if scheme_output.len() < ECIES_X25519_KEY_SIZE + 1 + ECIES_MAC_TAG_SIZE {
        return Err(EciesError::SchemeOutputTooShort);
    }
    let mut eph_pub = [0u8; ECIES_X25519_KEY_SIZE];
    eph_pub.copy_from_slice(&scheme_output[..ECIES_X25519_KEY_SIZE]);
    let ct_end = scheme_output.len() - ECIES_MAC_TAG_SIZE;
    let ciphertext = &scheme_output[ECIES_X25519_KEY_SIZE..ct_end];
    let mut mac_tag = [0u8; ECIES_MAC_TAG_SIZE];
    mac_tag.copy_from_slice(&scheme_output[ct_end..]);

    ecies_profile_a_decrypt(hn_priv_key, &eph_pub, ciphertext, &mac_tag)
}

/// Deconceal a SUCI Profile B scheme output (TS 23.003 §2.2B, scheme 2).
///
/// `scheme_output = eph_pub_compressed(33) || ciphertext || mac_tag(8)`.
/// Returns the decrypted plaintext block (MSIN in BCD).
pub fn suci_deconceal_profile_b(
    hn_priv_key: &[u8; ECC_BYTES],
    scheme_output: &[u8],
) -> EciesResult<Vec<u8>> {
    if scheme_output.len() < ECC_PUBLIC_KEY_SIZE + 1 + ECIES_MAC_TAG_SIZE {
        return Err(EciesError::SchemeOutputTooShort);
    }
    let mut eph_pub = [0u8; ECC_PUBLIC_KEY_SIZE];
    eph_pub.copy_from_slice(&scheme_output[..ECC_PUBLIC_KEY_SIZE]);
    let ct_end = scheme_output.len() - ECIES_MAC_TAG_SIZE;
    let ciphertext = &scheme_output[ECC_PUBLIC_KEY_SIZE..ct_end];
    let mut mac_tag = [0u8; ECIES_MAC_TAG_SIZE];
    mac_tag.copy_from_slice(&scheme_output[ct_end..]);

    Ok(ecies_profile_b_decrypt(
        hn_priv_key,
        &eph_pub,
        ciphertext,
        &mac_tag,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// TS 33.501 Annex C.4.3 ECIES Profile A test data.
    #[test]
    fn test_ecies_profile_a_ts33501_annex_c4_vector() {
        let hn_priv_v = unhex("c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d");
        let hn_pub_v = unhex("5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650");
        let eph_priv_v = unhex("c80949f13ebe61af4ebdbd293ea4f942696b9e815d7e8f0096bbf6ed7de62256");
        let eph_pub_v = unhex("b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457d");
        let plaintext = unhex("00012080f6");
        let expected_ciphertext = unhex("cb02352410");
        let expected_mac = unhex("cddd9e730ef3fa87");

        let mut hn_priv = [0u8; 32];
        hn_priv.copy_from_slice(&hn_priv_v);
        let mut eph_priv = [0u8; 32];
        eph_priv.copy_from_slice(&eph_priv_v);
        let mut hn_pub = [0u8; 32];
        hn_pub.copy_from_slice(&hn_pub_v);

        // Sanity: HN public key derives from HN private key
        assert_eq!(&x25519_public_key(&hn_priv)[..], &hn_pub_v[..]);

        // UE-side encryption with fixed ephemeral key
        let (eph_pub, ciphertext, mac_tag) =
            ecies_profile_a_encrypt_with_ephemeral(&hn_pub, &plaintext, &eph_priv).unwrap();

        assert_eq!(&eph_pub[..], &eph_pub_v[..], "ephemeral public key");
        assert_eq!(&ciphertext[..], &expected_ciphertext[..], "ciphertext");
        assert_eq!(&mac_tag[..], &expected_mac[..], "MAC tag");

        // Home-network-side decryption
        let decrypted = ecies_profile_a_decrypt(&hn_priv, &eph_pub, &ciphertext, &mac_tag).unwrap();
        assert_eq!(decrypted, plaintext);

        // Scheme-output level helper
        let mut scheme_output = Vec::new();
        scheme_output.extend_from_slice(&eph_pub);
        scheme_output.extend_from_slice(&ciphertext);
        scheme_output.extend_from_slice(&mac_tag);
        let deconcealed = suci_deconceal_profile_a(&hn_priv, &scheme_output).unwrap();
        assert_eq!(deconcealed, plaintext);
    }

    #[test]
    fn test_ecies_profile_a_roundtrip() {
        let hn_priv = [0x42u8; 32];
        let hn_pub = x25519_public_key(&hn_priv);
        let plaintext = b"profile A roundtrip";

        let (eph_pub, ct, tag) = ecies_profile_a_encrypt(&hn_pub, plaintext).unwrap();
        assert_ne!(&ct[..], &plaintext[..]);
        let pt = ecies_profile_a_decrypt(&hn_priv, &eph_pub, &ct, &tag).unwrap();
        assert_eq!(&pt[..], &plaintext[..]);
    }

    #[test]
    fn test_ecies_profile_a_tampered_mac() {
        let hn_priv = [0x42u8; 32];
        let hn_pub = x25519_public_key(&hn_priv);
        let (eph_pub, ct, mut tag) = ecies_profile_a_encrypt(&hn_pub, b"data").unwrap();
        tag[0] ^= 0xFF;
        assert!(matches!(
            ecies_profile_a_decrypt(&hn_priv, &eph_pub, &ct, &tag),
            Err(EciesError::MacVerificationFailed)
        ));
    }

    #[test]
    fn test_ecies_profile_a_wrong_key() {
        let hn_priv = [0x42u8; 32];
        let hn_pub = x25519_public_key(&hn_priv);
        let wrong_priv = [0x43u8; 32];
        let (eph_pub, ct, tag) = ecies_profile_a_encrypt(&hn_pub, b"data").unwrap();
        assert!(ecies_profile_a_decrypt(&wrong_priv, &eph_pub, &ct, &tag).is_err());
    }

    #[test]
    fn test_suci_deconceal_profile_b_roundtrip() {
        use crate::ecc::{ecc_make_key, ecies_profile_b_encrypt};

        let mut hn_pub = [0u8; ECC_PUBLIC_KEY_SIZE];
        let mut hn_priv = [0u8; ECC_BYTES];
        ecc_make_key(&mut hn_pub, &mut hn_priv).unwrap();

        let msin = [0x00u8, 0x00, 0x00, 0x00, 0x01];
        let (eph_pub, ct, tag) = ecies_profile_b_encrypt(&hn_pub, &msin).unwrap();

        let mut scheme_output = Vec::new();
        scheme_output.extend_from_slice(&eph_pub);
        scheme_output.extend_from_slice(&ct);
        scheme_output.extend_from_slice(&tag);

        let pt = suci_deconceal_profile_b(&hn_priv, &scheme_output).unwrap();
        assert_eq!(pt, msin);
    }

    #[test]
    fn test_suci_deconceal_too_short() {
        let hn_priv = [0x42u8; 32];
        assert!(matches!(
            suci_deconceal_profile_a(&hn_priv, &[0u8; 10]),
            Err(EciesError::SchemeOutputTooShort)
        ));
        assert!(matches!(
            suci_deconceal_profile_b(&hn_priv, &[0u8; 10]),
            Err(EciesError::SchemeOutputTooShort)
        ));
    }
}
