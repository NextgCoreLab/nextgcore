//! ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
//!
//! Post-quantum key encapsulation mechanism based on CRYSTALS-Kyber,
//! standardized as FIPS 203 (ML-KEM).
//!
//! Supports three security levels:
//! - ML-KEM-512: NIST Level 1 (equivalent to AES-128)
//! - ML-KEM-768: NIST Level 3 (equivalent to AES-192)
//! - ML-KEM-1024: NIST Level 5 (equivalent to AES-256)
//!
//! References:
//! - FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
//! - 3GPP TR 33.831: Study on Post-Quantum Cryptography

use ml_kem::{KemCore, MlKem512, MlKem768, MlKem1024, Encoded, EncodedSizeUser};
use ml_kem::kem::{Decapsulate, Encapsulate};
use p256::elliptic_curve::rand_core::OsRng;
use thiserror::Error;

/// ML-KEM error types
#[derive(Error, Debug)]
pub enum MlKemError {
    #[error("Key generation failed")]
    KeyGenFailed,
    #[error("Encapsulation failed")]
    EncapsulationFailed,
    #[error("Decapsulation failed")]
    DecapsulationFailed,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid secret key")]
    InvalidSecretKey,
    #[error("Invalid ciphertext")]
    InvalidCiphertext,
    #[error("Unsupported security level")]
    UnsupportedLevel,
    #[error("Invalid key size for level")]
    InvalidKeySize,
}

/// Result type for ML-KEM operations
pub type MlKemResult<T> = Result<T, MlKemError>;

/// ML-KEM security levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemLevel {
    /// ML-KEM-512: NIST Level 1
    Kem512,
    /// ML-KEM-768: NIST Level 3
    Kem768,
    /// ML-KEM-1024: NIST Level 5
    Kem1024,
}

/// Shared secret size (32 bytes for all levels)
pub const ML_KEM_SHARED_SECRET_SIZE: usize = 32;

/// Generate an ML-KEM key pair.
///
/// # Arguments
/// * `level` - Security level (Kem512, Kem768, or Kem1024)
///
/// # Returns
/// * `(public_key_bytes, secret_key_bytes)` on success
pub fn ml_kem_keygen(level: MlKemLevel) -> MlKemResult<(Vec<u8>, Vec<u8>)> {
    let mut rng = OsRng;
    match level {
        MlKemLevel::Kem512 => {
            let (dk, ek) = MlKem512::generate(&mut rng);
            Ok((ek.as_bytes()[..].to_vec(), dk.as_bytes()[..].to_vec()))
        }
        MlKemLevel::Kem768 => {
            let (dk, ek) = MlKem768::generate(&mut rng);
            Ok((ek.as_bytes()[..].to_vec(), dk.as_bytes()[..].to_vec()))
        }
        MlKemLevel::Kem1024 => {
            let (dk, ek) = MlKem1024::generate(&mut rng);
            Ok((ek.as_bytes()[..].to_vec(), dk.as_bytes()[..].to_vec()))
        }
    }
}

/// Encapsulate a shared secret using a public key.
///
/// # Arguments
/// * `level` - Security level (must match key generation level)
/// * `public_key` - Public key bytes
///
/// # Returns
/// * `(ciphertext_bytes, shared_secret)` on success
pub fn ml_kem_encapsulate(
    level: MlKemLevel,
    public_key: &[u8],
) -> MlKemResult<(Vec<u8>, [u8; ML_KEM_SHARED_SECRET_SIZE])> {
    let mut rng = OsRng;
    match level {
        MlKemLevel::Kem512 => {
            type Ek = <MlKem512 as KemCore>::EncapsulationKey;
            let ek_enc = Encoded::<Ek>::try_from(public_key)
                .map_err(|_| MlKemError::InvalidPublicKey)?;
            let ek = Ek::from_bytes(&ek_enc);
            let (ct, ss) = ek.encapsulate(&mut rng)
                .map_err(|_| MlKemError::EncapsulationFailed)?;
            let mut shared_secret = [0u8; ML_KEM_SHARED_SECRET_SIZE];
            shared_secret.copy_from_slice(ss.as_slice());
            Ok((ct[..].to_vec(), shared_secret))
        }
        MlKemLevel::Kem768 => {
            type Ek = <MlKem768 as KemCore>::EncapsulationKey;
            let ek_enc = Encoded::<Ek>::try_from(public_key)
                .map_err(|_| MlKemError::InvalidPublicKey)?;
            let ek = Ek::from_bytes(&ek_enc);
            let (ct, ss) = ek.encapsulate(&mut rng)
                .map_err(|_| MlKemError::EncapsulationFailed)?;
            let mut shared_secret = [0u8; ML_KEM_SHARED_SECRET_SIZE];
            shared_secret.copy_from_slice(ss.as_slice());
            Ok((ct[..].to_vec(), shared_secret))
        }
        MlKemLevel::Kem1024 => {
            type Ek = <MlKem1024 as KemCore>::EncapsulationKey;
            let ek_enc = Encoded::<Ek>::try_from(public_key)
                .map_err(|_| MlKemError::InvalidPublicKey)?;
            let ek = Ek::from_bytes(&ek_enc);
            let (ct, ss) = ek.encapsulate(&mut rng)
                .map_err(|_| MlKemError::EncapsulationFailed)?;
            let mut shared_secret = [0u8; ML_KEM_SHARED_SECRET_SIZE];
            shared_secret.copy_from_slice(ss.as_slice());
            Ok((ct[..].to_vec(), shared_secret))
        }
    }
}

/// Decapsulate a shared secret using a secret key and ciphertext.
///
/// # Arguments
/// * `level` - Security level (must match key generation level)
/// * `secret_key` - Secret key bytes
/// * `ciphertext` - Ciphertext bytes from encapsulation
///
/// # Returns
/// * Shared secret (32 bytes) on success
pub fn ml_kem_decapsulate(
    level: MlKemLevel,
    secret_key: &[u8],
    ciphertext: &[u8],
) -> MlKemResult<[u8; ML_KEM_SHARED_SECRET_SIZE]> {
    match level {
        MlKemLevel::Kem512 => {
            type Dk = <MlKem512 as KemCore>::DecapsulationKey;
            let dk_enc = Encoded::<Dk>::try_from(secret_key)
                .map_err(|_| MlKemError::InvalidSecretKey)?;
            let dk = Dk::from_bytes(&dk_enc);
            type Ct = ml_kem::Ciphertext<MlKem512>;
            let ct_enc = Ct::try_from(ciphertext)
                .map_err(|_| MlKemError::InvalidCiphertext)?;
            let ss = dk.decapsulate(&ct_enc)
                .map_err(|_| MlKemError::DecapsulationFailed)?;
            let mut shared_secret = [0u8; ML_KEM_SHARED_SECRET_SIZE];
            shared_secret.copy_from_slice(ss.as_slice());
            Ok(shared_secret)
        }
        MlKemLevel::Kem768 => {
            type Dk = <MlKem768 as KemCore>::DecapsulationKey;
            let dk_enc = Encoded::<Dk>::try_from(secret_key)
                .map_err(|_| MlKemError::InvalidSecretKey)?;
            let dk = Dk::from_bytes(&dk_enc);
            type Ct = ml_kem::Ciphertext<MlKem768>;
            let ct_enc = Ct::try_from(ciphertext)
                .map_err(|_| MlKemError::InvalidCiphertext)?;
            let ss = dk.decapsulate(&ct_enc)
                .map_err(|_| MlKemError::DecapsulationFailed)?;
            let mut shared_secret = [0u8; ML_KEM_SHARED_SECRET_SIZE];
            shared_secret.copy_from_slice(ss.as_slice());
            Ok(shared_secret)
        }
        MlKemLevel::Kem1024 => {
            type Dk = <MlKem1024 as KemCore>::DecapsulationKey;
            let dk_enc = Encoded::<Dk>::try_from(secret_key)
                .map_err(|_| MlKemError::InvalidSecretKey)?;
            let dk = Dk::from_bytes(&dk_enc);
            type Ct = ml_kem::Ciphertext<MlKem1024>;
            let ct_enc = Ct::try_from(ciphertext)
                .map_err(|_| MlKemError::InvalidCiphertext)?;
            let ss = dk.decapsulate(&ct_enc)
                .map_err(|_| MlKemError::DecapsulationFailed)?;
            let mut shared_secret = [0u8; ML_KEM_SHARED_SECRET_SIZE];
            shared_secret.copy_from_slice(ss.as_slice());
            Ok(shared_secret)
        }
    }
}

/// C-compatible ML-KEM key generation.
///
/// Returns 1 on success, 0 on failure.
pub fn ml_kem_keygen_c(
    level: u32,
    pk_out: &mut [u8],
    pk_len: &mut usize,
    sk_out: &mut [u8],
    sk_len: &mut usize,
) -> i32 {
    let lvl = match level {
        512 => MlKemLevel::Kem512,
        768 => MlKemLevel::Kem768,
        1024 => MlKemLevel::Kem1024,
        _ => return 0,
    };

    match ml_kem_keygen(lvl) {
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

/// C-compatible ML-KEM encapsulation.
///
/// Returns 1 on success, 0 on failure.
pub fn ml_kem_encapsulate_c(
    level: u32,
    public_key: &[u8],
    pk_len: usize,
    ct_out: &mut [u8],
    ct_len: &mut usize,
    ss_out: &mut [u8; ML_KEM_SHARED_SECRET_SIZE],
) -> i32 {
    let lvl = match level {
        512 => MlKemLevel::Kem512,
        768 => MlKemLevel::Kem768,
        1024 => MlKemLevel::Kem1024,
        _ => return 0,
    };

    match ml_kem_encapsulate(lvl, &public_key[..pk_len]) {
        Ok((ct, ss)) => {
            if ct_out.len() < ct.len() {
                return 0;
            }
            ct_out[..ct.len()].copy_from_slice(&ct);
            *ct_len = ct.len();
            ss_out.copy_from_slice(&ss);
            1
        }
        Err(_) => 0,
    }
}

/// C-compatible ML-KEM decapsulation.
///
/// Returns 1 on success, 0 on failure.
pub fn ml_kem_decapsulate_c(
    level: u32,
    secret_key: &[u8],
    sk_len: usize,
    ciphertext: &[u8],
    ct_len: usize,
    ss_out: &mut [u8; ML_KEM_SHARED_SECRET_SIZE],
) -> i32 {
    let lvl = match level {
        512 => MlKemLevel::Kem512,
        768 => MlKemLevel::Kem768,
        1024 => MlKemLevel::Kem1024,
        _ => return 0,
    };

    match ml_kem_decapsulate(lvl, &secret_key[..sk_len], &ciphertext[..ct_len]) {
        Ok(ss) => {
            ss_out.copy_from_slice(&ss);
            1
        }
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_roundtrip_for_level(level: MlKemLevel) {
        let (pk, sk) = ml_kem_keygen(level).unwrap();
        assert!(!pk.is_empty());
        assert!(!sk.is_empty());

        let (ct, ss_enc) = ml_kem_encapsulate(level, &pk).unwrap();
        assert!(!ct.is_empty());
        assert!(ss_enc.iter().any(|&b| b != 0));

        let ss_dec = ml_kem_decapsulate(level, &sk, &ct).unwrap();
        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn test_ml_kem_512_roundtrip() {
        test_roundtrip_for_level(MlKemLevel::Kem512);
    }

    #[test]
    fn test_ml_kem_768_roundtrip() {
        test_roundtrip_for_level(MlKemLevel::Kem768);
    }

    #[test]
    fn test_ml_kem_1024_roundtrip() {
        test_roundtrip_for_level(MlKemLevel::Kem1024);
    }

    #[test]
    fn test_ml_kem_different_keys_different_secrets() {
        let (pk1, _sk1) = ml_kem_keygen(MlKemLevel::Kem768).unwrap();
        let (pk2, _sk2) = ml_kem_keygen(MlKemLevel::Kem768).unwrap();

        let (_ct1, ss1) = ml_kem_encapsulate(MlKemLevel::Kem768, &pk1).unwrap();
        let (_ct2, ss2) = ml_kem_encapsulate(MlKemLevel::Kem768, &pk2).unwrap();

        assert_ne!(ss1, ss2);
    }

    #[test]
    fn test_ml_kem_invalid_public_key() {
        let invalid_pk = vec![0u8; 10];
        let result = ml_kem_encapsulate(MlKemLevel::Kem768, &invalid_pk);
        assert!(result.is_err());
    }

    #[test]
    fn test_ml_kem_invalid_secret_key() {
        let (pk, _sk) = ml_kem_keygen(MlKemLevel::Kem768).unwrap();
        let (ct, _ss) = ml_kem_encapsulate(MlKemLevel::Kem768, &pk).unwrap();

        let invalid_sk = vec![0u8; 10];
        let result = ml_kem_decapsulate(MlKemLevel::Kem768, &invalid_sk, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_ml_kem_c_interface() {
        let mut pk = vec![0u8; 1200];
        let mut sk = vec![0u8; 2500];
        let mut pk_len = 0;
        let mut sk_len = 0;

        let ret = ml_kem_keygen_c(768, &mut pk, &mut pk_len, &mut sk, &mut sk_len);
        assert_eq!(ret, 1);

        let mut ct = vec![0u8; 1200];
        let mut ct_len = 0;
        let mut ss_enc = [0u8; ML_KEM_SHARED_SECRET_SIZE];

        let ret = ml_kem_encapsulate_c(768, &pk, pk_len, &mut ct, &mut ct_len, &mut ss_enc);
        assert_eq!(ret, 1);

        let mut ss_dec = [0u8; ML_KEM_SHARED_SECRET_SIZE];
        let ret = ml_kem_decapsulate_c(768, &sk, sk_len, &ct, ct_len, &mut ss_dec);
        assert_eq!(ret, 1);

        assert_eq!(ss_enc, ss_dec);
    }
}
