//! ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
//!
//! Post-quantum digital signature algorithm based on CRYSTALS-Dilithium,
//! standardized as FIPS 204 (ML-DSA).
//!
//! Supports three security levels:
//! - ML-DSA-44: NIST Level 2
//! - ML-DSA-65: NIST Level 3 (equivalent to AES-192)
//! - ML-DSA-87: NIST Level 5 (equivalent to AES-256)
//!
//! References:
//! - FIPS 204: Module-Lattice-Based Digital Signature Standard
//! - 3GPP TR 33.831: Study on Post-Quantum Cryptography

use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};
use ml_dsa::{SigningKey, VerifyingKey, Signature, EncodedVerifyingKey, EncodedSignature};
use ml_dsa::signature::{Signer, Verifier};
use thiserror::Error;

/// ML-DSA error types
#[derive(Error, Debug)]
pub enum MlDsaError {
    #[error("Key generation failed")]
    KeyGenFailed,
    #[error("Signing failed")]
    SigningFailed,
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid secret key")]
    InvalidSecretKey,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Unsupported security level")]
    UnsupportedLevel,
}

/// Result type for ML-DSA operations
pub type MlDsaResult<T> = Result<T, MlDsaError>;

/// ML-DSA security levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaLevel {
    /// ML-DSA-44: NIST Level 2
    Dsa44,
    /// ML-DSA-65: NIST Level 3
    Dsa65,
    /// ML-DSA-87: NIST Level 5
    Dsa87,
}

/// Generate an ML-DSA key pair.
///
/// # Arguments
/// * `level` - Security level (Dsa44, Dsa65, or Dsa87)
///
/// # Returns
/// * `(public_key_bytes, secret_key_bytes)` on success
pub fn ml_dsa_keygen(level: MlDsaLevel) -> MlDsaResult<(Vec<u8>, Vec<u8>)> {
    let mut seed_bytes = [0u8; 32];
    // Use p256's OsRng (rand_core 0.6) to fill random bytes
    {
        use p256::elliptic_curve::rand_core::RngCore;
        p256::elliptic_curve::rand_core::OsRng.fill_bytes(&mut seed_bytes);
    }
    let seed = ml_dsa::Seed::from(seed_bytes);

    match level {
        MlDsaLevel::Dsa44 => {
            let sk = SigningKey::<MlDsa44>::from_seed(&seed);
            let vk = sk.verifying_key();
            let vk_bytes: Vec<u8> = vk.encode()[..].to_vec();
            // Store the seed as the "secret key" for later reconstruction
            let sk_bytes: Vec<u8> = seed[..].to_vec();
            Ok((vk_bytes, sk_bytes))
        }
        MlDsaLevel::Dsa65 => {
            let sk = SigningKey::<MlDsa65>::from_seed(&seed);
            let vk = sk.verifying_key();
            let vk_bytes: Vec<u8> = vk.encode()[..].to_vec();
            let sk_bytes: Vec<u8> = seed[..].to_vec();
            Ok((vk_bytes, sk_bytes))
        }
        MlDsaLevel::Dsa87 => {
            let sk = SigningKey::<MlDsa87>::from_seed(&seed);
            let vk = sk.verifying_key();
            let vk_bytes: Vec<u8> = vk.encode()[..].to_vec();
            let sk_bytes: Vec<u8> = seed[..].to_vec();
            Ok((vk_bytes, sk_bytes))
        }
    }
}

/// Sign a message using ML-DSA.
///
/// # Arguments
/// * `level` - Security level (must match key generation level)
/// * `secret_key` - Secret key bytes
/// * `message` - Message to sign
///
/// # Returns
/// * Signature bytes on success
pub fn ml_dsa_sign(
    level: MlDsaLevel,
    secret_key: &[u8],
    message: &[u8],
) -> MlDsaResult<Vec<u8>> {
    // Secret key is stored as the 32-byte seed
    if secret_key.len() != 32 {
        return Err(MlDsaError::InvalidSecretKey);
    }
    let seed_bytes: [u8; 32] = secret_key.try_into()
        .map_err(|_| MlDsaError::InvalidSecretKey)?;
    let seed = ml_dsa::Seed::from(seed_bytes);

    match level {
        MlDsaLevel::Dsa44 => {
            let sk = SigningKey::<MlDsa44>::from_seed(&seed);
            let sig = sk.sign(message);
            Ok(sig.encode()[..].to_vec())
        }
        MlDsaLevel::Dsa65 => {
            let sk = SigningKey::<MlDsa65>::from_seed(&seed);
            let sig = sk.sign(message);
            Ok(sig.encode()[..].to_vec())
        }
        MlDsaLevel::Dsa87 => {
            let sk = SigningKey::<MlDsa87>::from_seed(&seed);
            let sig = sk.sign(message);
            Ok(sig.encode()[..].to_vec())
        }
    }
}

/// Verify a signature using ML-DSA.
///
/// # Arguments
/// * `level` - Security level (must match key generation level)
/// * `public_key` - Public key bytes
/// * `message` - Message that was signed
/// * `signature` - Signature bytes to verify
///
/// # Returns
/// * `true` if signature is valid, `false` otherwise
pub fn ml_dsa_verify(
    level: MlDsaLevel,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> MlDsaResult<bool> {
    match level {
        MlDsaLevel::Dsa44 => {
            let vk_enc = EncodedVerifyingKey::<MlDsa44>::try_from(public_key)
                .map_err(|_| MlDsaError::InvalidPublicKey)?;
            let vk = VerifyingKey::<MlDsa44>::decode(&vk_enc);
            let sig_enc = EncodedSignature::<MlDsa44>::try_from(signature)
                .map_err(|_| MlDsaError::InvalidSignature)?;
            let sig = Signature::<MlDsa44>::decode(&sig_enc)
                .ok_or(MlDsaError::InvalidSignature)?;
            match vk.verify(message, &sig) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        }
        MlDsaLevel::Dsa65 => {
            let vk_enc = EncodedVerifyingKey::<MlDsa65>::try_from(public_key)
                .map_err(|_| MlDsaError::InvalidPublicKey)?;
            let vk = VerifyingKey::<MlDsa65>::decode(&vk_enc);
            let sig_enc = EncodedSignature::<MlDsa65>::try_from(signature)
                .map_err(|_| MlDsaError::InvalidSignature)?;
            let sig = Signature::<MlDsa65>::decode(&sig_enc)
                .ok_or(MlDsaError::InvalidSignature)?;
            match vk.verify(message, &sig) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        }
        MlDsaLevel::Dsa87 => {
            let vk_enc = EncodedVerifyingKey::<MlDsa87>::try_from(public_key)
                .map_err(|_| MlDsaError::InvalidPublicKey)?;
            let vk = VerifyingKey::<MlDsa87>::decode(&vk_enc);
            let sig_enc = EncodedSignature::<MlDsa87>::try_from(signature)
                .map_err(|_| MlDsaError::InvalidSignature)?;
            let sig = Signature::<MlDsa87>::decode(&sig_enc)
                .ok_or(MlDsaError::InvalidSignature)?;
            match vk.verify(message, &sig) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        }
    }
}

/// C-compatible ML-DSA key generation.
///
/// Returns 1 on success, 0 on failure.
pub fn ml_dsa_keygen_c(
    level: u32,
    pk_out: &mut [u8],
    pk_len: &mut usize,
    sk_out: &mut [u8],
    sk_len: &mut usize,
) -> i32 {
    let lvl = match level {
        44 => MlDsaLevel::Dsa44,
        65 => MlDsaLevel::Dsa65,
        87 => MlDsaLevel::Dsa87,
        _ => return 0,
    };

    match ml_dsa_keygen(lvl) {
        Ok((pk, sk)) => {
            if pk_out.len() < pk.len() || sk_out.len() < sk.len() {
                return 0;
            }
            pk_out[..pk.len()].copy_from_slice(&pk);
            sk_out[..sk.len()].copy_from_slice(&sk);
            *pk_len = pk.len();
            *sk_len = sk.len();
            1
        }
        Err(_) => 0,
    }
}

/// C-compatible ML-DSA signing.
///
/// Returns 1 on success, 0 on failure.
pub fn ml_dsa_sign_c(
    level: u32,
    secret_key: &[u8],
    sk_len: usize,
    message: &[u8],
    msg_len: usize,
    sig_out: &mut [u8],
    sig_len: &mut usize,
) -> i32 {
    let lvl = match level {
        44 => MlDsaLevel::Dsa44,
        65 => MlDsaLevel::Dsa65,
        87 => MlDsaLevel::Dsa87,
        _ => return 0,
    };

    match ml_dsa_sign(lvl, &secret_key[..sk_len], &message[..msg_len]) {
        Ok(sig) => {
            if sig_out.len() < sig.len() {
                return 0;
            }
            sig_out[..sig.len()].copy_from_slice(&sig);
            *sig_len = sig.len();
            1
        }
        Err(_) => 0,
    }
}

/// C-compatible ML-DSA verification.
///
/// Returns 1 if valid, 0 if invalid or error.
pub fn ml_dsa_verify_c(
    level: u32,
    public_key: &[u8],
    pk_len: usize,
    message: &[u8],
    msg_len: usize,
    signature: &[u8],
    sig_len: usize,
) -> i32 {
    let lvl = match level {
        44 => MlDsaLevel::Dsa44,
        65 => MlDsaLevel::Dsa65,
        87 => MlDsaLevel::Dsa87,
        _ => return 0,
    };

    match ml_dsa_verify(
        lvl,
        &public_key[..pk_len],
        &message[..msg_len],
        &signature[..sig_len],
    ) {
        Ok(true) => 1,
        Ok(false) | Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sign_verify_for_level(level: MlDsaLevel) {
        let (pk, sk) = ml_dsa_keygen(level).unwrap();
        assert!(!pk.is_empty());
        assert!(!sk.is_empty());

        let message = b"Hello, post-quantum world!";
        let signature = ml_dsa_sign(level, &sk, message).unwrap();
        assert!(!signature.is_empty());

        let valid = ml_dsa_verify(level, &pk, message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_ml_dsa_44_roundtrip() {
        test_sign_verify_for_level(MlDsaLevel::Dsa44);
    }

    #[test]
    fn test_ml_dsa_65_roundtrip() {
        test_sign_verify_for_level(MlDsaLevel::Dsa65);
    }

    #[test]
    fn test_ml_dsa_87_roundtrip() {
        test_sign_verify_for_level(MlDsaLevel::Dsa87);
    }

    #[test]
    fn test_ml_dsa_wrong_message() {
        let (pk, sk) = ml_dsa_keygen(MlDsaLevel::Dsa65).unwrap();

        let message = b"Original message";
        let wrong_message = b"Tampered message";

        let signature = ml_dsa_sign(MlDsaLevel::Dsa65, &sk, message).unwrap();

        let valid = ml_dsa_verify(MlDsaLevel::Dsa65, &pk, wrong_message, &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_ml_dsa_wrong_key() {
        let (_pk1, sk1) = ml_dsa_keygen(MlDsaLevel::Dsa65).unwrap();
        let (pk2, _sk2) = ml_dsa_keygen(MlDsaLevel::Dsa65).unwrap();

        let message = b"Key mismatch test";
        let signature = ml_dsa_sign(MlDsaLevel::Dsa65, &sk1, message).unwrap();

        let valid = ml_dsa_verify(MlDsaLevel::Dsa65, &pk2, message, &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_ml_dsa_invalid_secret_key() {
        let invalid_sk = vec![0u8; 10];
        let result = ml_dsa_sign(MlDsaLevel::Dsa65, &invalid_sk, b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_ml_dsa_invalid_public_key() {
        let invalid_pk = vec![0u8; 10];
        let sig = vec![0u8; 100];
        let result = ml_dsa_verify(MlDsaLevel::Dsa65, &invalid_pk, b"test", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_ml_dsa_empty_message() {
        let (pk, sk) = ml_dsa_keygen(MlDsaLevel::Dsa44).unwrap();
        let message = b"";

        let signature = ml_dsa_sign(MlDsaLevel::Dsa44, &sk, message).unwrap();
        let valid = ml_dsa_verify(MlDsaLevel::Dsa44, &pk, message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_ml_dsa_c_interface() {
        let mut pk = vec![0u8; 2600];
        let mut sk = vec![0u8; 4900];
        let mut pk_len = 0;
        let mut sk_len = 0;

        let ret = ml_dsa_keygen_c(65, &mut pk, &mut pk_len, &mut sk, &mut sk_len);
        assert_eq!(ret, 1);

        let message = b"C interface test";
        let mut sig = vec![0u8; 4000];
        let mut sig_len = 0;

        let ret = ml_dsa_sign_c(65, &sk, sk_len, message, message.len(), &mut sig, &mut sig_len);
        assert_eq!(ret, 1);

        let ret = ml_dsa_verify_c(65, &pk, pk_len, message, message.len(), &sig, sig_len);
        assert_eq!(ret, 1);
    }
}
