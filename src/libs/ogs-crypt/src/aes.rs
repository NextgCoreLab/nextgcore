//! AES Operations
//!
//! Wrapper around the `aes` crate to match the interface of lib/crypt/ogs-aes.c
//!
//! Supports AES-128, AES-192, and AES-256 in ECB, CBC, and CTR modes.

use aes::cipher::{
    BlockDecrypt, BlockEncrypt, KeyInit,
    generic_array::GenericArray,
};
use aes::{Aes128, Aes192, Aes256};

/// AES block size in bytes
pub const AES_BLOCK_SIZE: usize = 16;

/// Maximum key bits supported
pub const AES_MAX_KEY_BITS: u32 = 256;

/// Error type for AES operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesError {
    /// Invalid key size (must be 128, 192, or 256 bits)
    InvalidKeySize,
    /// Output buffer too small
    OutputBufferTooSmall,
    /// Invalid input length (must be multiple of block size for CBC decrypt)
    InvalidInputLength,
}

/// AES cipher context that can hold any key size
pub enum AesCipher {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
}

/// AES encryption context
pub struct AesEncContext {
    cipher: AesCipher,
}

/// AES decryption context
pub struct AesDecContext {
    cipher: AesCipher,
}

impl AesEncContext {
    /// Set up AES encryption context with the given key
    ///
    /// # Arguments
    /// * `key` - The encryption key (16, 24, or 32 bytes for 128, 192, or 256 bits)
    /// * `keybits` - Key size in bits (128, 192, or 256)
    ///
    /// # Returns
    /// * `Ok(AesEncContext)` - The encryption context
    /// * `Err(AesError::InvalidKeySize)` - If keybits is not 128, 192, or 256
    pub fn new(key: &[u8], keybits: u32) -> Result<Self, AesError> {
        let cipher = match keybits {
            128 => {
                if key.len() < 16 {
                    return Err(AesError::InvalidKeySize);
                }
                AesCipher::Aes128(Aes128::new(GenericArray::from_slice(&key[..16])))
            }
            192 => {
                if key.len() < 24 {
                    return Err(AesError::InvalidKeySize);
                }
                AesCipher::Aes192(Aes192::new(GenericArray::from_slice(&key[..24])))
            }
            256 => {
                if key.len() < 32 {
                    return Err(AesError::InvalidKeySize);
                }
                AesCipher::Aes256(Aes256::new(GenericArray::from_slice(&key[..32])))
            }
            _ => return Err(AesError::InvalidKeySize),
        };
        Ok(Self { cipher })
    }

    /// Encrypt a single 16-byte block
    ///
    /// # Arguments
    /// * `plaintext` - 16-byte input block
    /// * `ciphertext` - 16-byte output buffer
    pub fn encrypt_block(&self, plaintext: &[u8; 16], ciphertext: &mut [u8; 16]) {
        let mut block = GenericArray::clone_from_slice(plaintext);
        match &self.cipher {
            AesCipher::Aes128(c) => c.encrypt_block(&mut block),
            AesCipher::Aes192(c) => c.encrypt_block(&mut block),
            AesCipher::Aes256(c) => c.encrypt_block(&mut block),
        }
        ciphertext.copy_from_slice(&block);
    }
}

impl AesDecContext {
    /// Set up AES decryption context with the given key
    ///
    /// # Arguments
    /// * `key` - The decryption key (16, 24, or 32 bytes for 128, 192, or 256 bits)
    /// * `keybits` - Key size in bits (128, 192, or 256)
    ///
    /// # Returns
    /// * `Ok(AesDecContext)` - The decryption context
    /// * `Err(AesError::InvalidKeySize)` - If keybits is not 128, 192, or 256
    pub fn new(key: &[u8], keybits: u32) -> Result<Self, AesError> {
        let cipher = match keybits {
            128 => {
                if key.len() < 16 {
                    return Err(AesError::InvalidKeySize);
                }
                AesCipher::Aes128(Aes128::new(GenericArray::from_slice(&key[..16])))
            }
            192 => {
                if key.len() < 24 {
                    return Err(AesError::InvalidKeySize);
                }
                AesCipher::Aes192(Aes192::new(GenericArray::from_slice(&key[..24])))
            }
            256 => {
                if key.len() < 32 {
                    return Err(AesError::InvalidKeySize);
                }
                AesCipher::Aes256(Aes256::new(GenericArray::from_slice(&key[..32])))
            }
            _ => return Err(AesError::InvalidKeySize),
        };
        Ok(Self { cipher })
    }

    /// Decrypt a single 16-byte block
    ///
    /// # Arguments
    /// * `ciphertext` - 16-byte input block
    /// * `plaintext` - 16-byte output buffer
    pub fn decrypt_block(&self, ciphertext: &[u8; 16], plaintext: &mut [u8; 16]) {
        let mut block = GenericArray::clone_from_slice(ciphertext);
        match &self.cipher {
            AesCipher::Aes128(c) => c.decrypt_block(&mut block),
            AesCipher::Aes192(c) => c.decrypt_block(&mut block),
            AesCipher::Aes256(c) => c.decrypt_block(&mut block),
        }
        plaintext.copy_from_slice(&block);
    }
}


/// AES-CBC encryption
///
/// Encrypts data using AES in CBC mode with PKCS#7-like padding behavior
/// matching the C implementation.
///
/// # Arguments
/// * `key` - The encryption key
/// * `keybits` - Key size in bits (128, 192, or 256)
/// * `ivec` - 16-byte initialization vector (will be updated to last ciphertext block)
/// * `input` - Input plaintext
/// * `output` - Output buffer (must be at least ceil(input.len() / 16) * 16 bytes)
///
/// # Returns
/// * `Ok(usize)` - Number of bytes written to output
/// * `Err(AesError)` - On error
pub fn aes_cbc_encrypt(
    key: &[u8],
    keybits: u32,
    ivec: &mut [u8; 16],
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, AesError> {
    if input.is_empty() {
        return Ok(0);
    }

    let ctx = AesEncContext::new(key, keybits)?;
    
    // Calculate output length (round up to block size)
    let outlen = ((input.len() - 1) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
    
    if output.len() < outlen {
        return Err(AesError::OutputBufferTooSmall);
    }

    let mut iv = *ivec;
    let mut in_pos = 0;
    let mut out_pos = 0;

    // Process full blocks
    while input.len() - in_pos >= AES_BLOCK_SIZE {
        // XOR plaintext with IV
        let mut block = [0u8; 16];
        for i in 0..AES_BLOCK_SIZE {
            block[i] = input[in_pos + i] ^ iv[i];
        }
        
        // Encrypt
        let mut out_block = [0u8; 16];
        ctx.encrypt_block(&block, &mut out_block);
        
        // Copy to output and update IV
        output[out_pos..out_pos + AES_BLOCK_SIZE].copy_from_slice(&out_block);
        iv = out_block;
        
        in_pos += AES_BLOCK_SIZE;
        out_pos += AES_BLOCK_SIZE;
    }

    // Handle remaining bytes (partial block)
    let remaining = input.len() - in_pos;
    if remaining > 0 {
        let mut block = [0u8; 16];
        // XOR remaining plaintext bytes with IV
        for i in 0..remaining {
            block[i] = input[in_pos + i] ^ iv[i];
        }
        // Pad with IV bytes (matching C implementation behavior)
        for i in remaining..AES_BLOCK_SIZE {
            block[i] = iv[i];
        }
        
        // Encrypt
        let mut out_block = [0u8; 16];
        ctx.encrypt_block(&block, &mut out_block);
        
        output[out_pos..out_pos + AES_BLOCK_SIZE].copy_from_slice(&out_block);
        iv = out_block;
    }

    // Update ivec with last ciphertext block
    ivec.copy_from_slice(&iv);

    Ok(outlen)
}

/// AES-CBC decryption
///
/// Decrypts data using AES in CBC mode.
///
/// # Arguments
/// * `key` - The decryption key
/// * `keybits` - Key size in bits (128, 192, or 256)
/// * `ivec` - 16-byte initialization vector (will be updated to last ciphertext block)
/// * `input` - Input ciphertext (must be multiple of 16 bytes)
/// * `output` - Output buffer (must be at least input.len() bytes)
///
/// # Returns
/// * `Ok(usize)` - Number of bytes written to output
/// * `Err(AesError)` - On error
pub fn aes_cbc_decrypt(
    key: &[u8],
    keybits: u32,
    ivec: &mut [u8; 16],
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, AesError> {
    if input.is_empty() {
        return Ok(0);
    }

    if input.len() % AES_BLOCK_SIZE != 0 {
        return Err(AesError::InvalidInputLength);
    }

    if output.len() < input.len() {
        return Err(AesError::OutputBufferTooSmall);
    }

    let ctx = AesDecContext::new(key, keybits)?;
    let outlen = input.len();

    let mut iv = *ivec;
    let mut in_pos = 0;
    let mut out_pos = 0;

    // Check if input and output overlap (in-place decryption)
    let in_place = std::ptr::eq(input.as_ptr(), output.as_ptr());

    if !in_place {
        // Non-overlapping buffers
        while in_pos < input.len() {
            let in_block: [u8; 16] = input[in_pos..in_pos + AES_BLOCK_SIZE]
                .try_into()
                .unwrap();
            
            // Decrypt
            let mut out_block = [0u8; 16];
            ctx.decrypt_block(&in_block, &mut out_block);
            
            // XOR with IV
            for i in 0..AES_BLOCK_SIZE {
                out_block[i] ^= iv[i];
            }
            
            // Copy to output and update IV
            output[out_pos..out_pos + AES_BLOCK_SIZE].copy_from_slice(&out_block);
            iv = in_block;
            
            in_pos += AES_BLOCK_SIZE;
            out_pos += AES_BLOCK_SIZE;
        }
    } else {
        // In-place decryption - need to save ciphertext before decrypting
        while in_pos < input.len() {
            let mut tmp = [0u8; 16];
            tmp.copy_from_slice(&input[in_pos..in_pos + AES_BLOCK_SIZE]);
            
            // Decrypt
            let mut out_block = [0u8; 16];
            ctx.decrypt_block(&tmp, &mut out_block);
            
            // XOR with IV
            for i in 0..AES_BLOCK_SIZE {
                out_block[i] ^= iv[i];
            }
            
            // Copy to output and update IV
            output[out_pos..out_pos + AES_BLOCK_SIZE].copy_from_slice(&out_block);
            iv = tmp;
            
            in_pos += AES_BLOCK_SIZE;
            out_pos += AES_BLOCK_SIZE;
        }
    }

    // Update ivec with last ciphertext block
    ivec.copy_from_slice(&iv);

    Ok(outlen)
}


/// Increment a 128-bit counter (big-endian)
#[inline]
fn ctr128_inc(counter: &mut [u8; 16]) {
    let mut c: u16 = 1;
    for i in (0..16).rev() {
        c += counter[i] as u16;
        counter[i] = c as u8;
        c >>= 8;
        if c == 0 {
            break;
        }
    }
}

/// AES-CTR128 encryption/decryption
///
/// Encrypts or decrypts data using AES in CTR mode with 128-bit counter.
/// CTR mode is symmetric - encryption and decryption are the same operation.
///
/// # Arguments
/// * `key` - The 128-bit encryption key (16 bytes)
/// * `ivec` - 16-byte counter/nonce (will be updated)
/// * `input` - Input data
/// * `output` - Output buffer (must be at least input.len() bytes)
///
/// # Returns
/// * `Ok(())` - On success
/// * `Err(AesError)` - On error
pub fn aes_ctr128_encrypt(
    key: &[u8],
    ivec: &mut [u8; 16],
    input: &[u8],
    output: &mut [u8],
) -> Result<(), AesError> {
    if input.is_empty() {
        return Ok(());
    }

    if output.len() < input.len() {
        return Err(AesError::OutputBufferTooSmall);
    }

    // CTR mode always uses 128-bit key in the C implementation
    let ctx = AesEncContext::new(key, 128)?;
    
    let mut ecount_buf = [0u8; 16];
    let mut pos = 0;

    // Process full blocks
    while input.len() - pos >= AES_BLOCK_SIZE {
        // Encrypt counter to get keystream
        ctx.encrypt_block(ivec, &mut ecount_buf);
        ctr128_inc(ivec);
        
        // XOR with input
        for i in 0..AES_BLOCK_SIZE {
            output[pos + i] = input[pos + i] ^ ecount_buf[i];
        }
        
        pos += AES_BLOCK_SIZE;
    }

    // Handle remaining bytes
    let remaining = input.len() - pos;
    if remaining > 0 {
        ctx.encrypt_block(ivec, &mut ecount_buf);
        ctr128_inc(ivec);
        
        for i in 0..remaining {
            output[pos + i] = input[pos + i] ^ ecount_buf[i];
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128_encrypt_decrypt_block() {
        // NIST test vector
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let plaintext = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let expected_ciphertext = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
            0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
        ];

        let enc_ctx = AesEncContext::new(&key, 128).unwrap();
        let mut ciphertext = [0u8; 16];
        enc_ctx.encrypt_block(&plaintext, &mut ciphertext);
        assert_eq!(ciphertext, expected_ciphertext);

        let dec_ctx = AesDecContext::new(&key, 128).unwrap();
        let mut decrypted = [0u8; 16];
        dec_ctx.decrypt_block(&ciphertext, &mut decrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes256_encrypt_decrypt_block() {
        // NIST test vector for AES-256
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let plaintext = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let expected_ciphertext = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
            0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
        ];

        let enc_ctx = AesEncContext::new(&key, 256).unwrap();
        let mut ciphertext = [0u8; 16];
        enc_ctx.encrypt_block(&plaintext, &mut ciphertext);
        assert_eq!(ciphertext, expected_ciphertext);

        let dec_ctx = AesDecContext::new(&key, 256).unwrap();
        let mut decrypted = [0u8; 16];
        dec_ctx.decrypt_block(&ciphertext, &mut decrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_cbc_encrypt_decrypt() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let plaintext = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        ];

        let mut enc_iv = iv;
        let mut ciphertext = [0u8; 32];
        let enc_len = aes_cbc_encrypt(&key, 128, &mut enc_iv, &plaintext, &mut ciphertext).unwrap();
        assert_eq!(enc_len, 32);

        let mut dec_iv = iv;
        let mut decrypted = [0u8; 32];
        let dec_len = aes_cbc_decrypt(&key, 128, &mut dec_iv, &ciphertext, &mut decrypted).unwrap();
        assert_eq!(dec_len, 32);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_ctr128_encrypt_decrypt() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let nonce = [
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
            0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
        ];
        let plaintext = b"Hello, World! This is a test of AES-CTR mode.";

        let mut enc_nonce = nonce;
        let mut ciphertext = vec![0u8; plaintext.len()];
        aes_ctr128_encrypt(&key, &mut enc_nonce, plaintext, &mut ciphertext).unwrap();

        // CTR mode is symmetric - decrypt by encrypting again with same nonce
        let mut dec_nonce = nonce;
        let mut decrypted = vec![0u8; ciphertext.len()];
        aes_ctr128_encrypt(&key, &mut dec_nonce, &ciphertext, &mut decrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ctr128_inc() {
        let mut counter = [0u8; 16];
        counter[15] = 0xff;
        ctr128_inc(&mut counter);
        assert_eq!(counter[15], 0x00);
        assert_eq!(counter[14], 0x01);

        // Test overflow across multiple bytes
        let mut counter2 = [0u8; 16];
        counter2[14] = 0xff;
        counter2[15] = 0xff;
        ctr128_inc(&mut counter2);
        assert_eq!(counter2[15], 0x00);
        assert_eq!(counter2[14], 0x00);
        assert_eq!(counter2[13], 0x01);
    }

    #[test]
    fn test_invalid_key_size() {
        let key = [0u8; 16];
        assert!(AesEncContext::new(&key, 64).is_err());
        assert!(AesEncContext::new(&key, 512).is_err());
        assert!(AesDecContext::new(&key, 64).is_err());
    }

    #[test]
    fn test_cbc_invalid_input_length() {
        let key = [0u8; 16];
        let mut iv = [0u8; 16];
        let input = [0u8; 17]; // Not a multiple of 16
        let mut output = [0u8; 32];
        
        // Decrypt should fail with non-block-aligned input
        assert!(aes_cbc_decrypt(&key, 128, &mut iv, &input, &mut output).is_err());
    }
}
