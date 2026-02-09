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

use aes::cipher::{KeyInit, generic_array::GenericArray};
use aes::Aes128;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};

/// ECC key size in bytes for P-256 curve
pub const ECC_BYTES: usize = 32;

/// Public key size (compressed format: 1 byte prefix + 32 bytes x-coordinate)
pub const ECC_PUBLIC_KEY_SIZE: usize = ECC_BYTES + 1;

/// Signature size (r + s, each 32 bytes)
pub const ECC_SIGNATURE_SIZE: usize = ECC_BYTES * 2;

/// ECIES Profile B MAC tag size (HMAC-SHA256 truncated to 8 bytes)
pub const ECIES_MAC_TAG_SIZE: usize = 8;

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
    #[error("ECIES encryption failed")]
    EciesEncryptionFailed,
    #[error("ECIES decryption failed")]
    EciesDecryptionFailed,
    #[error("ECIES MAC verification failed")]
    EciesMacVerificationFailed,
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
// ECIES Profile B (3GPP TS 33.501 Annex C.3.4.2)
//
// Uses P-256 ECDH, X9.63 KDF with SHA-256, AES-128-CTR, HMAC-SHA256 (8 bytes)
// ============================================================================

/// X9.63 KDF for ECIES Profile B.
///
/// Derives enc_key (16 bytes) and mac_key (32 bytes) from the shared secret
/// using ANSI X9.63 KDF with SHA-256.
///
/// KDF output = SHA-256(Z || counter || SharedInfo)
/// - First 16 bytes -> encryption key (AES-128)
/// - Next 32 bytes -> MAC key (HMAC-SHA256)
fn x963_kdf_profile_b(shared_secret: &[u8; ECC_BYTES]) -> ([u8; 16], [u8; 32]) {
    // We need 48 bytes total: 16 (enc_key) + 32 (mac_key)
    // SHA-256 produces 32 bytes per iteration, so we need 2 iterations.

    // Iteration 1: counter = 0x00000001
    let mut hasher1 = Sha256::new();
    hasher1.update(shared_secret);
    hasher1.update(1u32.to_be_bytes());
    let output1 = hasher1.finalize();

    // Iteration 2: counter = 0x00000002
    let mut hasher2 = Sha256::new();
    hasher2.update(shared_secret);
    hasher2.update(2u32.to_be_bytes());
    let output2 = hasher2.finalize();

    let mut enc_key = [0u8; 16];
    let mut mac_key = [0u8; 32];

    // First 16 bytes of output1 -> enc_key
    enc_key.copy_from_slice(&output1[..16]);
    // Last 16 bytes of output1 + first 16 bytes of output2 -> mac_key
    mac_key[..16].copy_from_slice(&output1[16..32]);
    mac_key[16..].copy_from_slice(&output2[..16]);

    (enc_key, mac_key)
}

/// AES-128-CTR encryption/decryption (symmetric operation).
///
/// Uses a zero IV (all zeros) as the initial counter block per Profile B.
fn aes128_ctr(key: &[u8; 16], data: &[u8]) -> Vec<u8> {
    use aes::cipher::BlockEncrypt;

    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut output = vec![0u8; data.len()];
    let mut counter = [0u8; 16]; // zero IV for Profile B
    let mut pos = 0;

    while pos < data.len() {
        // Encrypt counter to get keystream block
        let mut keystream = GenericArray::clone_from_slice(&counter);
        cipher.encrypt_block(&mut keystream);

        // XOR data with keystream
        let remaining = data.len() - pos;
        let block_len = remaining.min(16);
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

/// ECIES Profile B encryption.
///
/// Encrypts plaintext using ECIES Profile B as defined in 3GPP TS 33.501:
/// 1. Generate ephemeral P-256 key pair
/// 2. Compute ECDH shared secret with recipient's public key
/// 3. Derive enc_key + mac_key via X9.63 KDF
/// 4. Encrypt with AES-128-CTR
/// 5. Compute HMAC-SHA256 over ciphertext, truncated to 8 bytes
///
/// # Arguments
/// * `pub_key` - Recipient's P-256 public key (compressed, 33 bytes)
/// * `plaintext` - Data to encrypt
///
/// # Returns
/// * `(ephemeral_pub, ciphertext, mac_tag)` on success
pub fn ecies_profile_b_encrypt(
    pub_key: &[u8; ECC_PUBLIC_KEY_SIZE],
    plaintext: &[u8],
) -> EccResult<([u8; ECC_PUBLIC_KEY_SIZE], Vec<u8>, [u8; ECIES_MAC_TAG_SIZE])> {
    // 1. Generate ephemeral key pair
    let mut eph_pub = [0u8; ECC_PUBLIC_KEY_SIZE];
    let mut eph_priv = [0u8; ECC_BYTES];
    ecc_make_key(&mut eph_pub, &mut eph_priv)?;

    // 2. Compute ECDH shared secret
    let mut shared_secret = [0u8; ECC_BYTES];
    ecdh_shared_secret(pub_key, &eph_priv, &mut shared_secret)?;

    // 3. Derive enc_key and mac_key via X9.63 KDF
    let (enc_key, mac_key) = x963_kdf_profile_b(&shared_secret);

    // 4. Encrypt with AES-128-CTR
    let ciphertext = aes128_ctr(&enc_key, plaintext);

    // 5. Compute HMAC-SHA256 over ciphertext, truncated to 8 bytes
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&mac_key)
        .map_err(|_| EccError::EciesEncryptionFailed)?;
    mac.update(&ciphertext);
    let mac_result = mac.finalize().into_bytes();

    let mut mac_tag = [0u8; ECIES_MAC_TAG_SIZE];
    mac_tag.copy_from_slice(&mac_result[..ECIES_MAC_TAG_SIZE]);

    Ok((eph_pub, ciphertext, mac_tag))
}

/// ECIES Profile B decryption.
///
/// Decrypts ciphertext using ECIES Profile B as defined in 3GPP TS 33.501:
/// 1. Compute ECDH shared secret using own private key + ephemeral public key
/// 2. Derive enc_key + mac_key via X9.63 KDF
/// 3. Verify HMAC-SHA256 MAC tag
/// 4. Decrypt with AES-128-CTR
///
/// # Arguments
/// * `priv_key` - Recipient's P-256 private key (32 bytes)
/// * `ephemeral_pub` - Sender's ephemeral public key (compressed, 33 bytes)
/// * `ciphertext` - Encrypted data
/// * `mac_tag` - 8-byte MAC tag
///
/// # Returns
/// * Decrypted plaintext on success
pub fn ecies_profile_b_decrypt(
    priv_key: &[u8; ECC_BYTES],
    ephemeral_pub: &[u8; ECC_PUBLIC_KEY_SIZE],
    ciphertext: &[u8],
    mac_tag: &[u8; ECIES_MAC_TAG_SIZE],
) -> EccResult<Vec<u8>> {
    // 1. Compute ECDH shared secret
    let mut shared_secret = [0u8; ECC_BYTES];
    ecdh_shared_secret(ephemeral_pub, priv_key, &mut shared_secret)?;

    // 2. Derive enc_key and mac_key via X9.63 KDF
    let (enc_key, mac_key) = x963_kdf_profile_b(&shared_secret);

    // 3. Verify MAC tag
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&mac_key)
        .map_err(|_| EccError::EciesDecryptionFailed)?;
    mac.update(ciphertext);
    let mac_result = mac.finalize().into_bytes();

    let mut expected_tag = [0u8; ECIES_MAC_TAG_SIZE];
    expected_tag.copy_from_slice(&mac_result[..ECIES_MAC_TAG_SIZE]);

    // Constant-time comparison
    if expected_tag != *mac_tag {
        return Err(EccError::EciesMacVerificationFailed);
    }

    // 4. Decrypt with AES-128-CTR (symmetric operation)
    let plaintext = aes128_ctr(&enc_key, ciphertext);

    Ok(plaintext)
}

/// C-compatible ECIES Profile B encrypt function.
///
/// Encrypts plaintext and writes ephemeral public key, ciphertext, and MAC tag
/// to the provided output buffers.
///
/// Returns 1 on success, 0 on failure.
pub fn ecies_profile_b_encrypt_c(
    pub_key: &[u8; ECC_PUBLIC_KEY_SIZE],
    plaintext: &[u8],
    plaintext_len: usize,
    ephemeral_pub_out: &mut [u8; ECC_PUBLIC_KEY_SIZE],
    ciphertext_out: &mut [u8],
    mac_tag_out: &mut [u8; ECIES_MAC_TAG_SIZE],
) -> i32 {
    if ciphertext_out.len() < plaintext_len {
        return 0;
    }
    match ecies_profile_b_encrypt(pub_key, &plaintext[..plaintext_len]) {
        Ok((eph_pub, ct, mac_tag)) => {
            ephemeral_pub_out.copy_from_slice(&eph_pub);
            ciphertext_out[..ct.len()].copy_from_slice(&ct);
            mac_tag_out.copy_from_slice(&mac_tag);
            1
        }
        Err(_) => 0,
    }
}

/// C-compatible ECIES Profile B decrypt function.
///
/// Decrypts ciphertext and writes plaintext to the provided output buffer.
///
/// Returns 1 on success, 0 on failure.
pub fn ecies_profile_b_decrypt_c(
    priv_key: &[u8; ECC_BYTES],
    ephemeral_pub: &[u8; ECC_PUBLIC_KEY_SIZE],
    ciphertext: &[u8],
    ciphertext_len: usize,
    mac_tag: &[u8; ECIES_MAC_TAG_SIZE],
    plaintext_out: &mut [u8],
) -> i32 {
    if plaintext_out.len() < ciphertext_len {
        return 0;
    }
    match ecies_profile_b_decrypt(priv_key, ephemeral_pub, &ciphertext[..ciphertext_len], mac_tag) {
        Ok(pt) => {
            plaintext_out[..pt.len()].copy_from_slice(&pt);
            1
        }
        Err(_) => 0,
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

    // ========================================================================
    // ECIES Profile B tests
    // ========================================================================

    #[test]
    fn test_ecies_profile_b_roundtrip() {
        // Generate recipient key pair
        let mut pub_key = [0u8; ECC_PUBLIC_KEY_SIZE];
        let mut priv_key = [0u8; ECC_BYTES];
        ecc_make_key(&mut pub_key, &mut priv_key).unwrap();

        let plaintext = b"Hello, ECIES Profile B!";

        // Encrypt
        let (eph_pub, ciphertext, mac_tag) =
            ecies_profile_b_encrypt(&pub_key, plaintext).unwrap();

        // Ciphertext should differ from plaintext
        assert_ne!(&ciphertext[..], &plaintext[..]);

        // Decrypt
        let decrypted =
            ecies_profile_b_decrypt(&priv_key, &eph_pub, &ciphertext, &mac_tag).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ecies_profile_b_empty_plaintext() {
        let mut pub_key = [0u8; ECC_PUBLIC_KEY_SIZE];
        let mut priv_key = [0u8; ECC_BYTES];
        ecc_make_key(&mut pub_key, &mut priv_key).unwrap();

        let plaintext = b"";

        let (eph_pub, ciphertext, mac_tag) =
            ecies_profile_b_encrypt(&pub_key, plaintext).unwrap();

        assert!(ciphertext.is_empty());

        let decrypted =
            ecies_profile_b_decrypt(&priv_key, &eph_pub, &ciphertext, &mac_tag).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ecies_profile_b_large_plaintext() {
        let mut pub_key = [0u8; ECC_PUBLIC_KEY_SIZE];
        let mut priv_key = [0u8; ECC_BYTES];
        ecc_make_key(&mut pub_key, &mut priv_key).unwrap();

        // Test with data larger than one AES block
        let plaintext = vec![0xABu8; 256];

        let (eph_pub, ciphertext, mac_tag) =
            ecies_profile_b_encrypt(&pub_key, &plaintext).unwrap();

        let decrypted =
            ecies_profile_b_decrypt(&priv_key, &eph_pub, &ciphertext, &mac_tag).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ecies_profile_b_wrong_key() {
        let mut pub_key = [0u8; ECC_PUBLIC_KEY_SIZE];
        let mut priv_key = [0u8; ECC_BYTES];
        ecc_make_key(&mut pub_key, &mut priv_key).unwrap();

        // Generate a different key pair
        let mut wrong_pub = [0u8; ECC_PUBLIC_KEY_SIZE];
        let mut wrong_priv = [0u8; ECC_BYTES];
        ecc_make_key(&mut wrong_pub, &mut wrong_priv).unwrap();

        let plaintext = b"Secret message";

        let (eph_pub, ciphertext, mac_tag) =
            ecies_profile_b_encrypt(&pub_key, plaintext).unwrap();

        // Decrypting with wrong private key should fail MAC verification
        let result =
            ecies_profile_b_decrypt(&wrong_priv, &eph_pub, &ciphertext, &mac_tag);

        assert!(result.is_err());
    }

    #[test]
    fn test_ecies_profile_b_tampered_ciphertext() {
        let mut pub_key = [0u8; ECC_PUBLIC_KEY_SIZE];
        let mut priv_key = [0u8; ECC_BYTES];
        ecc_make_key(&mut pub_key, &mut priv_key).unwrap();

        let plaintext = b"Integrity test";

        let (eph_pub, mut ciphertext, mac_tag) =
            ecies_profile_b_encrypt(&pub_key, plaintext).unwrap();

        // Tamper with ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        // MAC verification should fail
        let result =
            ecies_profile_b_decrypt(&priv_key, &eph_pub, &ciphertext, &mac_tag);

        assert!(result.is_err());
    }

    #[test]
    fn test_ecies_profile_b_tampered_mac() {
        let mut pub_key = [0u8; ECC_PUBLIC_KEY_SIZE];
        let mut priv_key = [0u8; ECC_BYTES];
        ecc_make_key(&mut pub_key, &mut priv_key).unwrap();

        let plaintext = b"MAC tamper test";

        let (eph_pub, ciphertext, mut mac_tag) =
            ecies_profile_b_encrypt(&pub_key, plaintext).unwrap();

        // Tamper with MAC tag
        mac_tag[0] ^= 0xFF;

        let result =
            ecies_profile_b_decrypt(&priv_key, &eph_pub, &ciphertext, &mac_tag);

        assert!(result.is_err());
    }

    #[test]
    fn test_ecies_profile_b_c_interface() {
        let mut pub_key = [0u8; ECC_PUBLIC_KEY_SIZE];
        let mut priv_key = [0u8; ECC_BYTES];
        ecc_make_key(&mut pub_key, &mut priv_key).unwrap();

        let plaintext = b"C interface test";
        let mut eph_pub = [0u8; ECC_PUBLIC_KEY_SIZE];
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut mac_tag = [0u8; ECIES_MAC_TAG_SIZE];

        let ret = ecies_profile_b_encrypt_c(
            &pub_key,
            plaintext,
            plaintext.len(),
            &mut eph_pub,
            &mut ciphertext,
            &mut mac_tag,
        );
        assert_eq!(ret, 1);

        let mut decrypted = vec![0u8; plaintext.len()];
        let ret = ecies_profile_b_decrypt_c(
            &priv_key,
            &eph_pub,
            &ciphertext,
            ciphertext.len(),
            &mac_tag,
            &mut decrypted,
        );
        assert_eq!(ret, 1);
        assert_eq!(&decrypted[..], &plaintext[..]);
    }
}
