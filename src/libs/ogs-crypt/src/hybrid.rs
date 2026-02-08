//! Hybrid Key Exchange (P-256 + ML-KEM-768)
//!
//! Combines classical ECDH (P-256) with post-quantum ML-KEM-768 to provide
//! a hybrid key exchange mechanism resistant to both classical and quantum attacks.
//!
//! The combined shared secret is derived as:
//!   shared_secret = SHA-256(ecdh_shared_secret || ml_kem_shared_secret)
//!
//! This follows the "hybrid" approach recommended by:
//! - NIST SP 800-227: Recommendations for Key-Encapsulation Mechanisms
//! - 3GPP TR 33.831: Study on Post-Quantum Cryptography
//! - IETF draft-ietf-tls-hybrid-design

use sha2::{Sha256, Digest};
use thiserror::Error;

use crate::ecc::{self, ECC_BYTES, ECC_PUBLIC_KEY_SIZE};
use crate::ml_kem::{self, MlKemLevel};

/// Hybrid shared secret size (SHA-256 output = 32 bytes)
pub const HYBRID_SHARED_SECRET_SIZE: usize = 32;

/// Hybrid key exchange error types
#[derive(Error, Debug)]
pub enum HybridError {
    #[error("P-256 key generation failed: {0}")]
    EccKeyGenFailed(#[from] ecc::EccError),
    #[error("ML-KEM operation failed: {0}")]
    MlKemFailed(#[from] ml_kem::MlKemError),
    #[error("Invalid hybrid public key")]
    InvalidPublicKey,
    #[error("Invalid hybrid ciphertext")]
    InvalidCiphertext,
}

/// Result type for hybrid operations
pub type HybridResult<T> = Result<T, HybridError>;

/// Hybrid key pair containing both P-256 and ML-KEM-768 keys.
pub struct HybridKeyPair {
    /// P-256 public key (compressed, 33 bytes)
    pub ecc_public_key: [u8; ECC_PUBLIC_KEY_SIZE],
    /// P-256 private key (32 bytes)
    pub ecc_private_key: [u8; ECC_BYTES],
    /// ML-KEM-768 public key
    pub ml_kem_public_key: Vec<u8>,
    /// ML-KEM-768 secret key
    pub ml_kem_secret_key: Vec<u8>,
}

/// Hybrid public key for encapsulation.
pub struct HybridPublicKey {
    /// P-256 public key (compressed, 33 bytes)
    pub ecc_public_key: [u8; ECC_PUBLIC_KEY_SIZE],
    /// ML-KEM-768 public key
    pub ml_kem_public_key: Vec<u8>,
}

/// Hybrid ciphertext containing both P-256 ephemeral public key and ML-KEM ciphertext.
pub struct HybridCiphertext {
    /// P-256 ephemeral public key (compressed, 33 bytes)
    pub ecc_ephemeral_pub: [u8; ECC_PUBLIC_KEY_SIZE],
    /// ML-KEM-768 ciphertext
    pub ml_kem_ciphertext: Vec<u8>,
}

/// Generate a hybrid key pair (P-256 + ML-KEM-768).
///
/// # Returns
/// * `HybridKeyPair` containing both classical and post-quantum keys
pub fn hybrid_keygen() -> HybridResult<HybridKeyPair> {
    // Generate P-256 key pair
    let mut ecc_public_key = [0u8; ECC_PUBLIC_KEY_SIZE];
    let mut ecc_private_key = [0u8; ECC_BYTES];
    ecc::ecc_make_key(&mut ecc_public_key, &mut ecc_private_key)?;

    // Generate ML-KEM-768 key pair
    let (ml_kem_public_key, ml_kem_secret_key) = ml_kem::ml_kem_keygen(MlKemLevel::Kem768)?;

    Ok(HybridKeyPair {
        ecc_public_key,
        ecc_private_key,
        ml_kem_public_key,
        ml_kem_secret_key,
    })
}

/// Encapsulate a shared secret using a hybrid public key.
///
/// Performs both P-256 ECDH and ML-KEM-768 encapsulation, then combines
/// the two shared secrets using SHA-256.
///
/// # Arguments
/// * `hybrid_pk` - Hybrid public key (P-256 + ML-KEM-768)
///
/// # Returns
/// * `(HybridCiphertext, shared_secret)` on success
pub fn hybrid_encapsulate(
    hybrid_pk: &HybridPublicKey,
) -> HybridResult<(HybridCiphertext, [u8; HYBRID_SHARED_SECRET_SIZE])> {
    // 1. P-256 ECDH: generate ephemeral key pair and compute shared secret
    let mut eph_pub = [0u8; ECC_PUBLIC_KEY_SIZE];
    let mut eph_priv = [0u8; ECC_BYTES];
    ecc::ecc_make_key(&mut eph_pub, &mut eph_priv)?;

    let mut ecdh_ss = [0u8; ECC_BYTES];
    ecc::ecdh_shared_secret(&hybrid_pk.ecc_public_key, &eph_priv, &mut ecdh_ss)?;

    // 2. ML-KEM-768 encapsulation
    let (ml_kem_ct, ml_kem_ss) =
        ml_kem::ml_kem_encapsulate(MlKemLevel::Kem768, &hybrid_pk.ml_kem_public_key)?;

    // 3. Combine shared secrets: SHA-256(ecdh_ss || ml_kem_ss)
    let mut hasher = Sha256::new();
    hasher.update(ecdh_ss);
    hasher.update(ml_kem_ss);
    let combined = hasher.finalize();

    let mut shared_secret = [0u8; HYBRID_SHARED_SECRET_SIZE];
    shared_secret.copy_from_slice(&combined);

    let ct = HybridCiphertext {
        ecc_ephemeral_pub: eph_pub,
        ml_kem_ciphertext: ml_kem_ct,
    };

    Ok((ct, shared_secret))
}

/// Decapsulate a shared secret using a hybrid secret key and ciphertext.
///
/// Performs both P-256 ECDH and ML-KEM-768 decapsulation, then combines
/// the two shared secrets using SHA-256.
///
/// # Arguments
/// * `hybrid_kp` - Hybrid key pair (containing secret keys)
/// * `ct` - Hybrid ciphertext from encapsulation
///
/// # Returns
/// * Shared secret (32 bytes) on success
pub fn hybrid_decapsulate(
    hybrid_kp: &HybridKeyPair,
    ct: &HybridCiphertext,
) -> HybridResult<[u8; HYBRID_SHARED_SECRET_SIZE]> {
    // 1. P-256 ECDH: compute shared secret using own private key + ephemeral public key
    let mut ecdh_ss = [0u8; ECC_BYTES];
    ecc::ecdh_shared_secret(&ct.ecc_ephemeral_pub, &hybrid_kp.ecc_private_key, &mut ecdh_ss)?;

    // 2. ML-KEM-768 decapsulation
    let ml_kem_ss = ml_kem::ml_kem_decapsulate(
        MlKemLevel::Kem768,
        &hybrid_kp.ml_kem_secret_key,
        &ct.ml_kem_ciphertext,
    )?;

    // 3. Combine shared secrets: SHA-256(ecdh_ss || ml_kem_ss)
    let mut hasher = Sha256::new();
    hasher.update(ecdh_ss);
    hasher.update(ml_kem_ss);
    let combined = hasher.finalize();

    let mut shared_secret = [0u8; HYBRID_SHARED_SECRET_SIZE];
    shared_secret.copy_from_slice(&combined);

    Ok(shared_secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_keygen() {
        let kp = hybrid_keygen().unwrap();

        // P-256 public key should be in compressed format
        assert!(kp.ecc_public_key[0] == 0x02 || kp.ecc_public_key[0] == 0x03);

        // P-256 private key should be non-zero
        assert!(kp.ecc_private_key.iter().any(|&b| b != 0));

        // ML-KEM keys should be non-empty
        assert!(!kp.ml_kem_public_key.is_empty());
        assert!(!kp.ml_kem_secret_key.is_empty());

        // ML-KEM-768 public key should be 1184 bytes
        assert_eq!(kp.ml_kem_public_key.len(), 1184);
    }

    #[test]
    fn test_hybrid_roundtrip() {
        // Generate key pair
        let kp = hybrid_keygen().unwrap();

        // Create public key for encapsulation
        let pk = HybridPublicKey {
            ecc_public_key: kp.ecc_public_key,
            ml_kem_public_key: kp.ml_kem_public_key.clone(),
        };

        // Encapsulate
        let (ct, ss_enc) = hybrid_encapsulate(&pk).unwrap();

        // Shared secret should be non-zero
        assert!(ss_enc.iter().any(|&b| b != 0));

        // Decapsulate
        let ss_dec = hybrid_decapsulate(&kp, &ct).unwrap();

        // Both parties should derive the same shared secret
        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn test_hybrid_different_keys_different_secrets() {
        let kp1 = hybrid_keygen().unwrap();
        let kp2 = hybrid_keygen().unwrap();

        let pk1 = HybridPublicKey {
            ecc_public_key: kp1.ecc_public_key,
            ml_kem_public_key: kp1.ml_kem_public_key.clone(),
        };

        let pk2 = HybridPublicKey {
            ecc_public_key: kp2.ecc_public_key,
            ml_kem_public_key: kp2.ml_kem_public_key.clone(),
        };

        let (_ct1, ss1) = hybrid_encapsulate(&pk1).unwrap();
        let (_ct2, ss2) = hybrid_encapsulate(&pk2).unwrap();

        // Different keys should produce different shared secrets
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn test_hybrid_multiple_encapsulations() {
        let kp = hybrid_keygen().unwrap();

        let pk = HybridPublicKey {
            ecc_public_key: kp.ecc_public_key,
            ml_kem_public_key: kp.ml_kem_public_key.clone(),
        };

        // Multiple encapsulations should produce different ciphertexts and secrets
        let (ct1, ss1) = hybrid_encapsulate(&pk).unwrap();
        let (ct2, ss2) = hybrid_encapsulate(&pk).unwrap();

        // Each encapsulation uses fresh randomness
        assert_ne!(ss1, ss2);
        assert_ne!(ct1.ecc_ephemeral_pub, ct2.ecc_ephemeral_pub);

        // But both should decapsulate correctly
        let ss1_dec = hybrid_decapsulate(&kp, &ct1).unwrap();
        let ss2_dec = hybrid_decapsulate(&kp, &ct2).unwrap();

        assert_eq!(ss1, ss1_dec);
        assert_eq!(ss2, ss2_dec);
    }

    #[test]
    fn test_hybrid_shared_secret_size() {
        let kp = hybrid_keygen().unwrap();

        let pk = HybridPublicKey {
            ecc_public_key: kp.ecc_public_key,
            ml_kem_public_key: kp.ml_kem_public_key.clone(),
        };

        let (_ct, ss) = hybrid_encapsulate(&pk).unwrap();

        // Shared secret should be exactly 32 bytes (SHA-256 output)
        assert_eq!(ss.len(), HYBRID_SHARED_SECRET_SIZE);
    }
}
