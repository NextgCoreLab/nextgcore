//! Elliptic Curve Cryptography
//!
//! Wrapper around `p256` and `elliptic-curve` crates to match lib/crypt/ecc.c interface.
//! Uses NIST P-256 (secp256r1) curve - the default curve in the C implementation.
//!
//! This module provides:
//! - Key pair generation (ecc_make_key)
//! - ECDH shared secret computation (ecdh_shared_secret)
//! - ECDSA signing (ecdsa_sign)
//! - ECDSA verification (ecdsa_verify)

use p256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::{
        rand_core::OsRng,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
    EncodedPoint, PublicKey, SecretKey,
};
use thiserror::Error;

/// ECC key size in bytes for P-256 curve
pub const ECC_BYTES: usize = 32;

/// Public key size (compressed format: 1 byte prefix + 32 bytes x-coordinate)
pub const ECC_PUBLIC_KEY_SIZE: usize = ECC_BYTES + 1;

/// Signature size (r + s, each 32 bytes)
pub const ECC_SIGNATURE_SIZE: usize = ECC_BYTES * 2;

/// ECC error types
#[derive(Error, Debug)]
pub enum EccError {
    #[error("Failed to generate random number")]
    RandomGenerationFailed,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid private key")]
    InvalidPrivateKey,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("ECDH computation failed")]
    EcdhFailed,
    #[error("Signing failed")]
    SigningFailed,
    #[error("Verification failed")]
    VerificationFailed,
}

/// Result type for ECC operations
pub type EccResult<T> = Result<T, EccError>;

/// Create a public/private key pair.
///
/// Outputs:
/// - `public_key`: Will be filled with the public key (compressed format, 33 bytes)
/// - `private_key`: Will be filled with the private key (32 bytes)
///
/// Returns Ok(()) if the key pair was generated successfully.
///
/// # Example
/// ```
/// use ogs_crypt::ecc::{ecc_make_key, ECC_BYTES, ECC_PUBLIC_KEY_SIZE};
///
/// let mut public_key = [0u8; ECC_PUBLIC_KEY_SIZE];
/// let mut private_key = [0u8; ECC_BYTES];
/// ecc_make_key(&mut public_key, &mut private_key).unwrap();
/// ```
pub fn ecc_make_key(
    public_key: &mut [u8; ECC_PUBLIC_KEY_SIZE],
    private_key: &mut [u8; ECC_BYTES],
) -> EccResult<()> {
    // Generate a random private key using the OsRng from elliptic-curve crate
    let secret_key = SecretKey::random(&mut OsRng);
    
    // Get the public key
    let public = secret_key.public_key();
    
    // Encode private key as big-endian bytes
    let secret_bytes = secret_key.to_bytes();
    private_key.copy_from_slice(&secret_bytes);
    
    // Encode public key in compressed format (matching C implementation)
    let encoded = public.to_encoded_point(true);
    let compressed = encoded.as_bytes();
    
    // The compressed format is 33 bytes: 0x02 or 0x03 prefix + 32 bytes x-coordinate
    if compressed.len() != ECC_PUBLIC_KEY_SIZE {
        return Err(EccError::RandomGenerationFailed);
    }
    public_key.copy_from_slice(compressed);
    
    Ok(())
}

/// Compute a shared secret given your secret key and someone else's public key.
///
/// Note: It is recommended that you hash the result of ecdh_shared_secret before
/// using it for symmetric encryption or HMAC.
///
/// Inputs:
/// - `public_key`: The public key of the remote party (compressed format, 33 bytes)
/// - `private_key`: Your private key (32 bytes)
///
/// Outputs:
/// - `secret`: Will be filled with the shared secret value (32 bytes)
///
/// Returns Ok(()) if the shared secret was generated successfully.
///
/// # Example
/// ```
/// use ogs_crypt::ecc::{ecc_make_key, ecdh_shared_secret, ECC_BYTES, ECC_PUBLIC_KEY_SIZE};
///
/// // Generate two key pairs
/// let mut pub1 = [0u8; ECC_PUBLIC_KEY_SIZE];
/// let mut priv1 = [0u8; ECC_BYTES];
/// ecc_make_key(&mut pub1, &mut priv1).unwrap();
///
/// let mut pub2 = [0u8; ECC_PUBLIC_KEY_SIZE];
/// let mut priv2 = [0u8; ECC_BYTES];
/// ecc_make_key(&mut pub2, &mut priv2).unwrap();
///
/// // Compute shared secrets (should be equal)
/// let mut secret1 = [0u8; ECC_BYTES];
/// let mut secret2 = [0u8; ECC_BYTES];
/// ecdh_shared_secret(&pub2, &priv1, &mut secret1).unwrap();
/// ecdh_shared_secret(&pub1, &priv2, &mut secret2).unwrap();
/// assert_eq!(secret1, secret2);
/// ```
pub fn ecdh_shared_secret(
    public_key: &[u8; ECC_PUBLIC_KEY_SIZE],
    private_key: &[u8; ECC_BYTES],
    secret: &mut [u8; ECC_BYTES],
) -> EccResult<()> {
    // Parse the public key from compressed format
    let encoded_point = EncodedPoint::from_bytes(public_key)
        .map_err(|_| EccError::InvalidPublicKey)?;
    
    let public: PublicKey = Option::from(PublicKey::from_encoded_point(&encoded_point))
        .ok_or(EccError::InvalidPublicKey)?;
    
    // Parse the private key
    let secret_key = SecretKey::from_bytes(private_key.into())
        .map_err(|_| EccError::InvalidPrivateKey)?;
    
    // Compute the shared secret using ECDH
    // The p256 crate's diffie_hellman returns the x-coordinate of the shared point
    let shared_secret = p256::ecdh::diffie_hellman(
        secret_key.to_nonzero_scalar(),
        public.as_affine(),
    );
    
    // Copy the raw shared secret bytes
    secret.copy_from_slice(shared_secret.raw_secret_bytes());
    
    Ok(())
}

/// Generate an ECDSA signature for a given hash value.
///
/// Usage: Compute a hash of the data you wish to sign (SHA-256 is recommended) and pass it in to
/// this function along with your private key.
///
/// Inputs:
/// - `private_key`: Your private key (32 bytes)
/// - `hash`: The message hash to sign (32 bytes)
///
/// Outputs:
/// - `signature`: Will be filled with the signature value (64 bytes: r || s)
///
/// Returns Ok(()) if the signature was generated successfully.
///
/// # Example
/// ```
/// use ogs_crypt::ecc::{ecc_make_key, ecdsa_sign, ECC_BYTES, ECC_PUBLIC_KEY_SIZE, ECC_SIGNATURE_SIZE};
///
/// let mut public_key = [0u8; ECC_PUBLIC_KEY_SIZE];
/// let mut private_key = [0u8; ECC_BYTES];
/// ecc_make_key(&mut public_key, &mut private_key).unwrap();
///
/// let hash = [0x42u8; ECC_BYTES]; // Example hash
/// let mut signature = [0u8; ECC_SIGNATURE_SIZE];
/// ecdsa_sign(&private_key, &hash, &mut signature).unwrap();
/// ```
pub fn ecdsa_sign(
    private_key: &[u8; ECC_BYTES],
    hash: &[u8; ECC_BYTES],
    signature: &mut [u8; ECC_SIGNATURE_SIZE],
) -> EccResult<()> {
    // Parse the private key
    let signing_key = SigningKey::from_bytes(private_key.into())
        .map_err(|_| EccError::InvalidPrivateKey)?;
    
    // Sign the hash
    let sig: Signature = signing_key.sign(hash);
    
    // Convert signature to bytes (r || s format)
    let sig_bytes = sig.to_bytes();
    signature.copy_from_slice(&sig_bytes);
    
    Ok(())
}

/// Verify an ECDSA signature.
///
/// Usage: Compute the hash of the signed data using the same hash as the signer and
/// pass it to this function along with the signer's public key and the signature values.
///
/// Inputs:
/// - `public_key`: The signer's public key (compressed format, 33 bytes)
/// - `hash`: The hash of the signed data (32 bytes)
/// - `signature`: The signature value (64 bytes: r || s)
///
/// Returns Ok(true) if the signature is valid, Ok(false) if it is invalid.
///
/// # Example
/// ```
/// use ogs_crypt::ecc::{ecc_make_key, ecdsa_sign, ecdsa_verify, ECC_BYTES, ECC_PUBLIC_KEY_SIZE, ECC_SIGNATURE_SIZE};
///
/// let mut public_key = [0u8; ECC_PUBLIC_KEY_SIZE];
/// let mut private_key = [0u8; ECC_BYTES];
/// ecc_make_key(&mut public_key, &mut private_key).unwrap();
///
/// let hash = [0x42u8; ECC_BYTES];
/// let mut signature = [0u8; ECC_SIGNATURE_SIZE];
/// ecdsa_sign(&private_key, &hash, &mut signature).unwrap();
///
/// assert!(ecdsa_verify(&public_key, &hash, &signature).unwrap());
/// ```
pub fn ecdsa_verify(
    public_key: &[u8; ECC_PUBLIC_KEY_SIZE],
    hash: &[u8; ECC_BYTES],
    signature: &[u8; ECC_SIGNATURE_SIZE],
) -> EccResult<bool> {
    // Parse the public key from compressed format
    let encoded_point = EncodedPoint::from_bytes(public_key)
        .map_err(|_| EccError::InvalidPublicKey)?;
    
    let verifying_key = VerifyingKey::from_encoded_point(&encoded_point)
        .map_err(|_| EccError::InvalidPublicKey)?;
    
    // Parse the signature
    let sig = Signature::from_bytes(signature.into())
        .map_err(|_| EccError::InvalidSignature)?;
    
    // Verify the signature
    match verifying_key.verify(hash, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ============================================================================
// C-compatible interface functions (returning 1 for success, 0 for failure)
// These match the exact interface of lib/crypt/ecc.h
// ============================================================================

/// C-compatible key generation function.
/// Returns 1 if the key pair was generated successfully, 0 if an error occurred.
pub fn ecc_make_key_c(
    public_key: &mut [u8; ECC_PUBLIC_KEY_SIZE],
    private_key: &mut [u8; ECC_BYTES],
) -> i32 {
    match ecc_make_key(public_key, private_key) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

/// C-compatible ECDH shared secret function.
/// Returns 1 if the shared secret was generated successfully, 0 if an error occurred.
pub fn ecdh_shared_secret_c(
    public_key: &[u8; ECC_PUBLIC_KEY_SIZE],
    private_key: &[u8; ECC_BYTES],
    secret: &mut [u8; ECC_BYTES],
) -> i32 {
    match ecdh_shared_secret(public_key, private_key, secret) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

/// C-compatible ECDSA sign function.
/// Returns 1 if the signature was generated successfully, 0 if an error occurred.
pub fn ecdsa_sign_c(
    private_key: &[u8; ECC_BYTES],
    hash: &[u8; ECC_BYTES],
    signature: &mut [u8; ECC_SIGNATURE_SIZE],
) -> i32 {
    match ecdsa_sign(private_key, hash, signature) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

/// C-compatible ECDSA verify function.
/// Returns 1 if the signature is valid, 0 if it is invalid.
pub fn ecdsa_verify_c(
    public_key: &[u8; ECC_PUBLIC_KEY_SIZE],
    hash: &[u8; ECC_BYTES],
    signature: &[u8; ECC_SIGNATURE_SIZE],
) -> i32 {
    match ecdsa_verify(public_key, hash, signature) {
        Ok(true) => 1,
        Ok(false) | Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let mut public_key = [0u8; ECC_PUBLIC_KEY_SIZE];
        let mut private_key = [0u8; ECC_BYTES];
        
        assert!(ecc_make_key(&mut public_key, &mut private_key).is_ok());
        
        // Public key should start with 0x02 or 0x03 (compressed format)
        assert!(public_key[0] == 0x02 || public_key[0] == 0x03);
        
        // Private key should not be all zeros
        assert!(private_key.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_ecdh_shared_secret() {
        // Generate two key pairs
        let mut pub1 = [0u8; ECC_PUBLIC_KEY_SIZE];
        let mut priv1 = [0u8; ECC_BYTES];
        ecc_make_key(&mut pub1, &mut priv1).unwrap();

        let mut pub2 = [0u8; ECC_PUBLIC_KEY_SIZE];
        let mut priv2 = [0u8; ECC_BYTES];
        ecc_make_key(&mut pub2, &mut priv2).unwrap();

        // Compute shared secrets
        let mut secret1 = [0u8; ECC_BYTES];
        let mut secret2 = [0u8; ECC_BYTES];
        
        ecdh_shared_secret(&pub2, &priv1, &mut secret1).unwrap();
        ecdh_shared_secret(&pub1, &priv2, &mut secret2).unwrap();

        // Both parties should derive the same shared secret
        assert_eq!(secret1, secret2);
        
        // Shared secret should not be all zeros
        assert!(secret1.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_ecdsa_sign_verify() {
        let mut public_key = [0u8; ECC_PUBLIC_KEY_SIZE];
        let mut private_key = [0u8; ECC_BYTES];
        ecc_make_key(&mut public_key, &mut private_key).unwrap();

        // Create a test hash (simulating SHA-256 output)
        let hash = [0x42u8; ECC_BYTES];
        
        // Sign the hash
        let mut signature = [0u8; ECC_SIGNATURE_SIZE];
        ecdsa_sign(&private_key, &hash, &mut signature).unwrap();

        // Verify the signature
        assert!(ecdsa_verify(&public_key, &hash, &signature).unwrap());
    }

    #[test]
    fn test_ecdsa_verify_wrong_hash() {
        let mut public_key = [0u8; ECC_PUBLIC_KEY_SIZE];
        let mut private_key = [0u8; ECC_BYTES];
        ecc_make_key(&mut public_key, &mut private_key).unwrap();

        let hash = [0x42u8; ECC_BYTES];
        let wrong_hash = [0x43u8; ECC_BYTES];
        
        let mut signature = [0u8; ECC_SIGNATURE_SIZE];
        ecdsa_sign(&private_key, &hash, &mut signature).unwrap();

        // Verification with wrong hash should fail
        assert!(!ecdsa_verify(&public_key, &wrong_hash, &signature).unwrap());
    }

    #[test]
    fn test_ecdsa_verify_wrong_key() {
        let mut public_key1 = [0u8; ECC_PUBLIC_KEY_SIZE];
        let mut private_key1 = [0u8; ECC_BYTES];
        ecc_make_key(&mut public_key1, &mut private_key1).unwrap();

        let mut public_key2 = [0u8; ECC_PUBLIC_KEY_SIZE];
        let mut private_key2 = [0u8; ECC_BYTES];
        ecc_make_key(&mut public_key2, &mut private_key2).unwrap();

        let hash = [0x42u8; ECC_BYTES];
        
        let mut signature = [0u8; ECC_SIGNATURE_SIZE];
        ecdsa_sign(&private_key1, &hash, &mut signature).unwrap();

        // Verification with wrong public key should fail
        assert!(!ecdsa_verify(&public_key2, &hash, &signature).unwrap());
    }

    #[test]
    fn test_c_compatible_interface() {
        let mut public_key = [0u8; ECC_PUBLIC_KEY_SIZE];
        let mut private_key = [0u8; ECC_BYTES];
        
        // Test key generation
        assert_eq!(ecc_make_key_c(&mut public_key, &mut private_key), 1);
        
        // Test ECDH
        let mut pub2 = [0u8; ECC_PUBLIC_KEY_SIZE];
        let mut priv2 = [0u8; ECC_BYTES];
        assert_eq!(ecc_make_key_c(&mut pub2, &mut priv2), 1);
        
        let mut secret = [0u8; ECC_BYTES];
        assert_eq!(ecdh_shared_secret_c(&pub2, &private_key, &mut secret), 1);
        
        // Test ECDSA
        let hash = [0x42u8; ECC_BYTES];
        let mut signature = [0u8; ECC_SIGNATURE_SIZE];
        assert_eq!(ecdsa_sign_c(&private_key, &hash, &mut signature), 1);
        assert_eq!(ecdsa_verify_c(&public_key, &hash, &signature), 1);
    }

    #[test]
    fn test_invalid_public_key() {
        let invalid_public_key = [0u8; ECC_PUBLIC_KEY_SIZE]; // All zeros is invalid
        let private_key = [0x42u8; ECC_BYTES];
        let mut secret = [0u8; ECC_BYTES];
        
        assert!(ecdh_shared_secret(&invalid_public_key, &private_key, &mut secret).is_err());
    }

    #[test]
    fn test_multiple_signatures_same_key() {
        let mut public_key = [0u8; ECC_PUBLIC_KEY_SIZE];
        let mut private_key = [0u8; ECC_BYTES];
        ecc_make_key(&mut public_key, &mut private_key).unwrap();

        // Sign multiple different hashes
        for i in 0..5 {
            let hash = [i as u8; ECC_BYTES];
            let mut signature = [0u8; ECC_SIGNATURE_SIZE];
            ecdsa_sign(&private_key, &hash, &mut signature).unwrap();
            assert!(ecdsa_verify(&public_key, &hash, &signature).unwrap());
        }
    }
}
