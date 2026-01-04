//! SHA-1 and SHA-2 Hash Functions
//!
//! Wrapper around the `sha1` and `sha2` crates to match the interface of
//! lib/crypt/ogs-sha1.c and lib/crypt/ogs-sha2.c

use sha1::{Sha1, Digest};
use sha2::{Sha224, Sha256, Sha384, Sha512};

// Digest sizes
pub const SHA1_DIGEST_SIZE: usize = 20;    // 160 / 8
pub const SHA224_DIGEST_SIZE: usize = 28;  // 224 / 8
pub const SHA256_DIGEST_SIZE: usize = 32;  // 256 / 8
pub const SHA384_DIGEST_SIZE: usize = 48;  // 384 / 8
pub const SHA512_DIGEST_SIZE: usize = 64;  // 512 / 8

// Block sizes
pub const SHA1_BLOCK_SIZE: usize = 64;     // 512 / 8
pub const SHA256_BLOCK_SIZE: usize = 64;   // 512 / 8
pub const SHA224_BLOCK_SIZE: usize = SHA256_BLOCK_SIZE;
pub const SHA512_BLOCK_SIZE: usize = 128;  // 1024 / 8
pub const SHA384_BLOCK_SIZE: usize = SHA512_BLOCK_SIZE;

/// SHA-1 context for incremental hashing
pub struct Sha1Context {
    hasher: Sha1,
}

impl Sha1Context {
    /// Initialize a new SHA-1 context
    pub fn new() -> Self {
        Self {
            hasher: Sha1::new(),
        }
    }

    /// Update the hash with additional data
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalize the hash and write the digest
    pub fn finalize(self, digest: &mut [u8; SHA1_DIGEST_SIZE]) {
        let result = self.hasher.finalize();
        digest.copy_from_slice(&result);
    }
}

impl Default for Sha1Context {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute SHA-1 hash of a message in one shot
pub fn sha1(message: &[u8]) -> [u8; SHA1_DIGEST_SIZE] {
    let mut hasher = Sha1::new();
    hasher.update(message);
    let result = hasher.finalize();
    let mut digest = [0u8; SHA1_DIGEST_SIZE];
    digest.copy_from_slice(&result);
    digest
}

/// SHA-224 context for incremental hashing
pub struct Sha224Context {
    hasher: Sha224,
}

impl Sha224Context {
    /// Initialize a new SHA-224 context
    pub fn new() -> Self {
        Self {
            hasher: Sha224::new(),
        }
    }

    /// Update the hash with additional data
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalize the hash and write the digest
    pub fn finalize(self, digest: &mut [u8; SHA224_DIGEST_SIZE]) {
        let result = self.hasher.finalize();
        digest.copy_from_slice(&result);
    }
}

impl Default for Sha224Context {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute SHA-224 hash of a message in one shot
pub fn sha224(message: &[u8]) -> [u8; SHA224_DIGEST_SIZE] {
    let mut hasher = Sha224::new();
    hasher.update(message);
    let result = hasher.finalize();
    let mut digest = [0u8; SHA224_DIGEST_SIZE];
    digest.copy_from_slice(&result);
    digest
}

/// SHA-256 context for incremental hashing
pub struct Sha256Context {
    hasher: Sha256,
}

impl Sha256Context {
    /// Initialize a new SHA-256 context
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    /// Update the hash with additional data
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalize the hash and write the digest
    pub fn finalize(self, digest: &mut [u8; SHA256_DIGEST_SIZE]) {
        let result = self.hasher.finalize();
        digest.copy_from_slice(&result);
    }
}

impl Default for Sha256Context {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute SHA-256 hash of a message in one shot
pub fn sha256(message: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let result = hasher.finalize();
    let mut digest = [0u8; SHA256_DIGEST_SIZE];
    digest.copy_from_slice(&result);
    digest
}

/// SHA-384 context for incremental hashing
pub struct Sha384Context {
    hasher: Sha384,
}

impl Sha384Context {
    /// Initialize a new SHA-384 context
    pub fn new() -> Self {
        Self {
            hasher: Sha384::new(),
        }
    }

    /// Update the hash with additional data
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalize the hash and write the digest
    pub fn finalize(self, digest: &mut [u8; SHA384_DIGEST_SIZE]) {
        let result = self.hasher.finalize();
        digest.copy_from_slice(&result);
    }
}

impl Default for Sha384Context {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute SHA-384 hash of a message in one shot
pub fn sha384(message: &[u8]) -> [u8; SHA384_DIGEST_SIZE] {
    let mut hasher = Sha384::new();
    hasher.update(message);
    let result = hasher.finalize();
    let mut digest = [0u8; SHA384_DIGEST_SIZE];
    digest.copy_from_slice(&result);
    digest
}

/// SHA-512 context for incremental hashing
pub struct Sha512Context {
    hasher: Sha512,
}

impl Sha512Context {
    /// Initialize a new SHA-512 context
    pub fn new() -> Self {
        Self {
            hasher: Sha512::new(),
        }
    }

    /// Update the hash with additional data
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalize the hash and write the digest
    pub fn finalize(self, digest: &mut [u8; SHA512_DIGEST_SIZE]) {
        let result = self.hasher.finalize();
        digest.copy_from_slice(&result);
    }
}

impl Default for Sha512Context {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute SHA-512 hash of a message in one shot
pub fn sha512(message: &[u8]) -> [u8; SHA512_DIGEST_SIZE] {
    let mut hasher = Sha512::new();
    hasher.update(message);
    let result = hasher.finalize();
    let mut digest = [0u8; SHA512_DIGEST_SIZE];
    digest.copy_from_slice(&result);
    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from NIST FIPS 180-4

    #[test]
    fn test_sha1_empty() {
        let expected = [
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
            0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
            0xaf, 0xd8, 0x07, 0x09,
        ];
        assert_eq!(sha1(b""), expected);
    }

    #[test]
    fn test_sha1_abc() {
        // SHA1("abc") = a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d
        let expected = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
            0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
            0x9c, 0xd0, 0xd8, 0x9d,
        ];
        assert_eq!(sha1(b"abc"), expected);
    }

    #[test]
    fn test_sha1_incremental() {
        let mut ctx = Sha1Context::new();
        ctx.update(b"a");
        ctx.update(b"bc");
        let mut digest = [0u8; SHA1_DIGEST_SIZE];
        ctx.finalize(&mut digest);
        
        let expected = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
            0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
            0x9c, 0xd0, 0xd8, 0x9d,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha224_abc() {
        // SHA224("abc") = 23097d22 3405d822 8642a477 bda255b3 2aadbce4 bda0b3f7 e36c9da7
        let expected = [
            0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22,
            0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2, 0x55, 0xb3,
            0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7,
            0xe3, 0x6c, 0x9d, 0xa7,
        ];
        assert_eq!(sha224(b"abc"), expected);
    }

    #[test]
    fn test_sha256_empty() {
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(sha256(b""), expected);
    }

    #[test]
    fn test_sha256_abc() {
        // SHA256("abc") = ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(sha256(b"abc"), expected);
    }

    #[test]
    fn test_sha256_incremental() {
        let mut ctx = Sha256Context::new();
        ctx.update(b"a");
        ctx.update(b"bc");
        let mut digest = [0u8; SHA256_DIGEST_SIZE];
        ctx.finalize(&mut digest);
        
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha384_abc() {
        // SHA384("abc")
        let expected = [
            0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,
            0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
            0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
            0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
            0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,
            0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
        ];
        assert_eq!(sha384(b"abc"), expected);
    }

    #[test]
    fn test_sha512_abc() {
        // SHA512("abc")
        let expected = [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
            0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
            0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
            0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
            0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
            0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
            0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
        ];
        assert_eq!(sha512(b"abc"), expected);
    }

    #[test]
    fn test_sha512_incremental() {
        let mut ctx = Sha512Context::new();
        ctx.update(b"a");
        ctx.update(b"bc");
        let mut digest = [0u8; SHA512_DIGEST_SIZE];
        ctx.finalize(&mut digest);
        
        let expected = [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
            0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
            0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
            0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
            0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
            0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
            0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
        ];
        assert_eq!(digest, expected);
    }
}
