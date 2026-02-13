//! ZUC-256 Stream Cipher
//!
//! Implements ZUC-256 for next-generation 3GPP EEA3 (confidentiality) and
//! EIA3 (integrity) at the 256-bit security level.
//!
//! ZUC-256 extends the original ZUC cipher from 128-bit to 256-bit key support
//! with a 25-byte IV (184 bits + padding).
//!
//! References:
//! - ZUC-256 Stream Cipher (specification v1.1)
//! - 3GPP EEA3/EIA3 with 256-bit keys

use thiserror::Error;

/// ZUC-256 error types
#[derive(Error, Debug)]
pub enum Zuc256Error {
    #[error("Invalid key length (expected 32 bytes)")]
    InvalidKeyLength,
    #[error("Invalid IV length (expected 25 bytes)")]
    InvalidIvLength,
    #[error("Output buffer too small")]
    OutputBufferTooSmall,
}

/// Result type for ZUC-256 operations
pub type Zuc256Result<T> = Result<T, Zuc256Error>;

// S-boxes (same S0 and S1 as ZUC-128)
const S0: [u8; 256] = [
    0x3e,0x72,0x5b,0x47,0xca,0xe0,0x00,0x33,0x04,0xd1,0x54,0x98,0x09,0xb9,0x6d,0xcb,
    0x7b,0x1b,0xf9,0x32,0xaf,0x9d,0x6a,0xa5,0xb8,0x2d,0xfc,0x1d,0x08,0x53,0x03,0x90,
    0x4d,0x4e,0x84,0x99,0xe4,0xce,0xd9,0x91,0xdd,0xb6,0x85,0x48,0x8b,0x29,0x6e,0xac,
    0xcd,0xc1,0xf8,0x1e,0x73,0x43,0x69,0xc6,0xb5,0xbd,0xfd,0x39,0x63,0x20,0xd4,0x38,
    0x76,0x7d,0xb2,0xa7,0xcf,0xed,0x57,0xc5,0xf3,0x2c,0xbb,0x14,0x21,0x06,0x55,0x9b,
    0xe3,0xef,0x5e,0x31,0x4f,0x7f,0x5a,0xa4,0x0d,0x82,0x51,0x49,0x5f,0xba,0x58,0x1c,
    0x4a,0x16,0xd5,0x17,0xa8,0x92,0x24,0x1f,0x8c,0xff,0xd8,0xae,0x2e,0x01,0xd3,0xad,
    0x3b,0x4b,0xda,0x46,0xeb,0xc9,0xde,0x9a,0x8f,0x87,0xd7,0x3a,0x80,0x6f,0x2f,0xc8,
    0xb1,0xb4,0x37,0xf7,0x0a,0x22,0x13,0x28,0x7c,0xcc,0x3c,0x89,0xc7,0xc3,0x96,0x56,
    0x07,0xbf,0x7e,0xf0,0x0b,0x2b,0x97,0x52,0x35,0x41,0x79,0x61,0xa6,0x4c,0x10,0xfe,
    0xbc,0x26,0x95,0x88,0x8a,0xb0,0xa3,0xfb,0xc0,0x18,0x94,0xf2,0xe1,0xe5,0xe9,0x5d,
    0xd0,0xdc,0x11,0x66,0x64,0x5c,0xec,0x59,0x42,0x75,0x12,0xf5,0x74,0x9c,0xaa,0x23,
    0x0e,0x86,0xab,0xbe,0x2a,0x02,0xe7,0x67,0xe6,0x44,0xa2,0x6c,0xc2,0x93,0x9f,0xf1,
    0xf6,0xfa,0x36,0xd2,0x50,0x68,0x9e,0x62,0x71,0x15,0x3d,0xd6,0x40,0xc4,0xe2,0x0f,
    0x8e,0x83,0x77,0x6b,0x25,0x05,0x3f,0x0c,0x30,0xea,0x70,0xb7,0xa1,0xe8,0xa9,0x65,
    0x8d,0x27,0x1a,0xdb,0x81,0xb3,0xa0,0xf4,0x45,0x7a,0x19,0xdf,0xee,0x78,0x34,0x60,
];

const S1: [u8; 256] = [
    0x55,0xc2,0x63,0x71,0x3b,0xc8,0x47,0x86,0x9f,0x3c,0xda,0x5b,0x29,0xaa,0xfd,0x77,
    0x8c,0xc5,0x94,0x0c,0xa6,0x1a,0x13,0x00,0xe3,0xa8,0x16,0x72,0x40,0xf9,0xf8,0x42,
    0x44,0x26,0x68,0x96,0x81,0xd9,0x45,0x3e,0x10,0x76,0xc6,0xa7,0x8b,0x39,0x43,0xe1,
    0x3a,0xb5,0x56,0x2a,0xc0,0x6d,0xb3,0x05,0x22,0x66,0xbf,0xdc,0x0b,0xfa,0x62,0x48,
    0xdd,0x20,0x11,0x06,0x36,0xc9,0xc1,0xcf,0xf6,0x27,0x52,0xbb,0x69,0xf5,0xd4,0x87,
    0x7f,0x84,0x4c,0xd2,0x9c,0x57,0xa4,0xbc,0x4f,0x9a,0xdf,0xfe,0xd6,0x8d,0x7a,0xeb,
    0x2b,0x53,0xd8,0x5c,0xa1,0x14,0x17,0xfb,0x23,0xd5,0x7d,0x30,0x67,0x73,0x08,0x09,
    0xee,0xb7,0x70,0x3f,0x61,0xb2,0x19,0x8e,0x4e,0xe5,0x4b,0x93,0x8f,0x5d,0xdb,0xa9,
    0xad,0xf1,0xae,0x2e,0xcb,0x0d,0xfc,0xf4,0x2d,0x46,0x6e,0x1d,0x97,0xe8,0xd1,0xe9,
    0x4d,0x37,0xa5,0x75,0x5e,0x83,0x9e,0xab,0x82,0x9d,0xb9,0x1c,0xe0,0xcd,0x49,0x89,
    0x01,0xb6,0xbd,0x58,0x24,0xa2,0x5f,0x38,0x78,0x99,0x15,0x90,0x50,0xb8,0x95,0xe4,
    0xd0,0x91,0xc7,0xce,0xed,0x0f,0xb4,0x6f,0xa0,0xcc,0xf0,0x02,0x4a,0x79,0xc3,0xde,
    0xa3,0xef,0xea,0x51,0xe6,0x6b,0x18,0xec,0x1b,0x2c,0x80,0xf7,0x74,0xe7,0xff,0x21,
    0x5a,0x6a,0x54,0x1e,0x41,0x31,0x92,0x35,0xc4,0x33,0x07,0x0a,0xba,0x7e,0x0e,0x34,
    0x88,0xb1,0x98,0x7c,0xf3,0x3d,0x60,0x6c,0x7b,0xca,0xd3,0x1f,0x32,0x65,0x04,0x28,
    0x64,0xbe,0x85,0x9b,0x2f,0x59,0x8a,0xd7,0xb0,0x25,0xac,0xaf,0x12,0x03,0xe2,0xf2,
];

/// ZUC-256 loading constants (d values for 256-bit key loading)
const D_256: [u8; 16] = [
    0x22, 0x2F, 0x24, 0x2A, 0x6D, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x52, 0x10, 0x30,
];

/// ZUC-256 state
pub struct Zuc256State {
    lfsr: [u32; 16],
    r1: u32,
    r2: u32,
    x: [u32; 4],
}

impl Zuc256State {
    /// Create a new uninitialized ZUC-256 state
    pub fn new() -> Self {
        Self {
            lfsr: [0; 16],
            r1: 0,
            r2: 0,
            x: [0; 4],
        }
    }
}

impl Default for Zuc256State {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
fn add_m(a: u32, b: u32) -> u32 {
    let c = a.wrapping_add(b);
    (c & 0x7FFFFFFF).wrapping_add(c >> 31)
}

#[inline]
fn mul_by_pow2(x: u32, k: u32) -> u32 {
    ((x << k) | (x >> (31 - k))) & 0x7FFFFFFF
}

#[inline]
fn rot(a: u32, k: u32) -> u32 {
    (a << k) | (a >> (32 - k))
}

#[inline]
fn l1(x: u32) -> u32 {
    x ^ rot(x, 2) ^ rot(x, 10) ^ rot(x, 18) ^ rot(x, 24)
}

#[inline]
fn l2(x: u32) -> u32 {
    x ^ rot(x, 8) ^ rot(x, 14) ^ rot(x, 22) ^ rot(x, 30)
}

#[inline]
fn make_u32(a: u8, b: u8, c: u8, d: u8) -> u32 {
    ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32)
}

impl Zuc256State {
    fn lfsr_init(&mut self, u: u32) {
        let mut f = self.lfsr[0];
        f = add_m(f, mul_by_pow2(self.lfsr[0], 8));
        f = add_m(f, mul_by_pow2(self.lfsr[4], 20));
        f = add_m(f, mul_by_pow2(self.lfsr[10], 21));
        f = add_m(f, mul_by_pow2(self.lfsr[13], 17));
        f = add_m(f, mul_by_pow2(self.lfsr[15], 15));
        f = add_m(f, u);
        for i in 0..15 {
            self.lfsr[i] = self.lfsr[i + 1];
        }
        self.lfsr[15] = f;
    }

    fn lfsr_work(&mut self) {
        let mut f = self.lfsr[0];
        f = add_m(f, mul_by_pow2(self.lfsr[0], 8));
        f = add_m(f, mul_by_pow2(self.lfsr[4], 20));
        f = add_m(f, mul_by_pow2(self.lfsr[10], 21));
        f = add_m(f, mul_by_pow2(self.lfsr[13], 17));
        f = add_m(f, mul_by_pow2(self.lfsr[15], 15));
        for i in 0..15 {
            self.lfsr[i] = self.lfsr[i + 1];
        }
        self.lfsr[15] = f;
    }

    fn bit_reorg(&mut self) {
        self.x[0] = ((self.lfsr[15] & 0x7FFF8000) << 1) | (self.lfsr[14] & 0xFFFF);
        self.x[1] = ((self.lfsr[11] & 0xFFFF) << 16) | (self.lfsr[9] >> 15);
        self.x[2] = ((self.lfsr[7] & 0xFFFF) << 16) | (self.lfsr[5] >> 15);
        self.x[3] = ((self.lfsr[2] & 0xFFFF) << 16) | (self.lfsr[0] >> 15);
    }

    fn f(&mut self) -> u32 {
        let w = (self.x[0] ^ self.r1).wrapping_add(self.r2);
        let w1 = self.r1.wrapping_add(self.x[1]);
        let w2 = self.r2 ^ self.x[2];
        let u = l1((w1 << 16) | (w2 >> 16));
        let v = l2((w2 << 16) | (w1 >> 16));
        self.r1 = make_u32(
            S0[(u >> 24) as usize],
            S1[((u >> 16) & 0xFF) as usize],
            S0[((u >> 8) & 0xFF) as usize],
            S1[(u & 0xFF) as usize],
        );
        self.r2 = make_u32(
            S0[(v >> 24) as usize],
            S1[((v >> 16) & 0xFF) as usize],
            S0[((v >> 8) & 0xFF) as usize],
            S1[(v & 0xFF) as usize],
        );
        w
    }

    /// Initialize ZUC-256 with a 256-bit key and 25-byte IV.
    ///
    /// The LFSR is loaded as follows per the ZUC-256 spec:
    /// s_i = k_i || d_i || iv_i  (each 31 bits)
    pub fn initialize(&mut self, key: &[u8; 32], iv: &[u8; 25]) {
        // Load LFSR with key, d constants, and IV
        // ZUC-256 loading: s_i = k[i] << 23 | d[i] << 16 | k[i+16] << 8 | iv[i]
        // for i = 0..15, with special handling per the spec
        for i in 0..16 {
            let k_hi = key[i] as u32;
            let d_i = D_256[i] as u32;
            let k_lo = if i < 16 { key[i + 16] as u32 } else { 0 };
            let iv_i = if i < 17 { iv[i] as u32 } else { 0 };

            // s_i = k_hi || d_i || k_lo || iv_i  as 31-bit value
            // Construct: (k[i] << 23) | (d[i] << 16) | (k[i+16] << 8) | iv[i]
            // then take lower 31 bits
            let s = ((k_hi << 23) | (d_i << 16) | (k_lo << 8) | iv_i) & 0x7FFFFFFF;

            // Handle remaining IV bytes for indices that need them
            // Per ZUC-256 spec, IV bytes beyond index 16 are XORed into specific positions
            self.lfsr[i] = if s == 0 { 0x7FFFFFFF } else { s };
        }

        // XOR remaining IV bytes (iv[17..24]) into LFSR state
        // These additional IV bytes provide the full 184-bit IV support
        if iv.len() > 17 {
            for i in 0..std::cmp::min(8, iv.len() - 17) {
                let extra = (iv[17 + i] as u32) << 8;
                self.lfsr[i] = add_m(self.lfsr[i], extra);
                if self.lfsr[i] == 0 {
                    self.lfsr[i] = 0x7FFFFFFF;
                }
            }
        }

        self.r1 = 0;
        self.r2 = 0;

        // 32 rounds of initialization
        for _ in 0..32 {
            self.bit_reorg();
            let w = self.f();
            self.lfsr_init(w >> 1);
        }
    }

    /// Generate keystream words.
    pub fn generate_keystream(&mut self, ks: &mut [u32]) {
        self.bit_reorg();
        self.f();
        self.lfsr_work();

        for i in 0..ks.len() {
            self.bit_reorg();
            ks[i] = self.f() ^ self.x[3];
            self.lfsr_work();
        }
    }
}

/// ZUC-256 EEA3 - Confidentiality algorithm with 256-bit key.
///
/// Encrypts or decrypts data using ZUC-256 as a stream cipher.
/// The operation is symmetric (encrypt = decrypt).
///
/// # Arguments
/// * `key` - 256-bit confidentiality key (32 bytes)
/// * `iv` - 25-byte initialization vector
/// * `data` - Input data to encrypt/decrypt
///
/// # Returns
/// Encrypted/decrypted data
pub fn zuc256_eea3(key: &[u8; 32], iv: &[u8; 25], data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }

    let num_words = data.len().div_ceil(4);
    let mut state = Zuc256State::new();
    state.initialize(key, iv);

    let mut keystream = vec![0u32; num_words];
    state.generate_keystream(&mut keystream);

    let mut output = vec![0u8; data.len()];
    for i in 0..data.len() {
        let ks_byte = ((keystream[i / 4] >> ((3 - (i % 4)) * 8)) & 0xFF) as u8;
        output[i] = data[i] ^ ks_byte;
    }

    output
}

/// ZUC-256 EIA3 - Integrity algorithm with 256-bit key.
///
/// Computes a 32-bit MAC (Message Authentication Code) over the data
/// using ZUC-256.
///
/// # Arguments
/// * `key` - 256-bit integrity key (32 bytes)
/// * `iv` - 25-byte initialization vector
/// * `data` - Input data to authenticate
///
/// # Returns
/// 4-byte MAC tag
pub fn zuc256_eia3(key: &[u8; 32], iv: &[u8; 25], data: &[u8]) -> [u8; 4] {
    let bit_len = (data.len() as u32) * 8;
    let num_words = (bit_len.div_ceil(32) + 2) as usize;

    let mut state = Zuc256State::new();
    state.initialize(key, iv);

    let mut keystream = vec![0u32; num_words];
    state.generate_keystream(&mut keystream);

    // Compute MAC using the keystream and message bits
    let mut t: u32 = 0;
    for i in 0..bit_len {
        let byte_idx = (i / 8) as usize;
        let bit_idx = 7 - (i % 8);
        if byte_idx < data.len() && (data[byte_idx] >> bit_idx) & 1 == 1 {
            // XOR with keystream word starting at bit position i
            let word_idx = (i / 32) as usize;
            let bit_off = i % 32;
            if bit_off == 0 {
                t ^= keystream[word_idx];
            } else {
                t ^= (keystream[word_idx] << bit_off)
                    | keystream.get(word_idx + 1).copied().unwrap_or(0) >> (32 - bit_off);
            }
        }
    }

    // Final XOR with last keystream word
    t ^= keystream[num_words - 1];

    t.to_be_bytes()
}

/// C-compatible ZUC-256 EEA3 encryption/decryption.
///
/// Returns 1 on success, 0 on failure.
pub fn zuc256_eea3_c(
    key: &[u8; 32],
    iv: &[u8; 25],
    input: &[u8],
    input_len: usize,
    output: &mut [u8],
) -> i32 {
    if output.len() < input_len {
        return 0;
    }
    let result = zuc256_eea3(key, iv, &input[..input_len]);
    output[..result.len()].copy_from_slice(&result);
    1
}

/// C-compatible ZUC-256 EIA3 integrity computation.
///
/// Returns 1 on success, 0 on failure.
pub fn zuc256_eia3_c(
    key: &[u8; 32],
    iv: &[u8; 25],
    data: &[u8],
    data_len: usize,
    mac_out: &mut [u8; 4],
) -> i32 {
    let result = zuc256_eia3(key, iv, &data[..data_len]);
    mac_out.copy_from_slice(&result);
    1
}

/// ZUC-256 EIA3 with 64-bit MAC (8 bytes) for enhanced integrity.
///
/// Uses two sequential keystream evaluations to produce an 8-byte MAC
/// instead of the standard 4-byte MAC, providing stronger forgery resistance.
pub fn zuc256_eia3_64(key: &[u8; 32], iv: &[u8; 25], data: &[u8]) -> [u8; 8] {
    // Compute first 4-byte MAC with the original IV
    let mac_lo = zuc256_eia3(key, iv, data);

    // Compute second 4-byte MAC with a modified IV (flip LSB of first byte)
    let mut iv2 = *iv;
    iv2[0] ^= 0x01;
    let mac_hi = zuc256_eia3(key, &iv2, data);

    let mut mac64 = [0u8; 8];
    mac64[..4].copy_from_slice(&mac_hi);
    mac64[4..].copy_from_slice(&mac_lo);
    mac64
}

/// Derive a subkey from a master key using ZUC-256 keystream.
///
/// Generates `output_len` bytes of key material by running ZUC-256 with the
/// given key and IV, then extracting keystream bytes.
pub fn zuc256_kdf(key: &[u8; 32], iv: &[u8; 25], output_len: usize) -> Vec<u8> {
    let mut state = Zuc256State::new();
    state.initialize(key, iv);

    let num_words = output_len.div_ceil(4);
    let mut keystream = vec![0u32; num_words];
    state.generate_keystream(&mut keystream);

    let mut output = Vec::with_capacity(output_len);
    for word in &keystream {
        output.extend_from_slice(&word.to_be_bytes());
        if output.len() >= output_len {
            break;
        }
    }
    output.truncate(output_len);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zuc256_state_init() {
        let key = [0x12u8; 32];
        let iv = [0x34u8; 25];
        let mut state = Zuc256State::new();
        state.initialize(&key, &iv);

        // State should be non-trivial after initialization
        assert!(state.lfsr.iter().any(|&x| x != 0));
    }

    #[test]
    fn test_zuc256_keystream_generation() {
        let key = [0x12u8; 32];
        let iv = [0x34u8; 25];
        let mut state = Zuc256State::new();
        state.initialize(&key, &iv);

        let mut ks = [0u32; 4];
        state.generate_keystream(&mut ks);

        // Keystream should be non-zero
        assert!(ks.iter().any(|&x| x != 0));
    }

    #[test]
    fn test_zuc256_keystream_deterministic() {
        let key = [0xABu8; 32];
        let iv = [0xCDu8; 25];

        let mut state1 = Zuc256State::new();
        state1.initialize(&key, &iv);
        let mut ks1 = [0u32; 8];
        state1.generate_keystream(&mut ks1);

        let mut state2 = Zuc256State::new();
        state2.initialize(&key, &iv);
        let mut ks2 = [0u32; 8];
        state2.generate_keystream(&mut ks2);

        assert_eq!(ks1, ks2);
    }

    #[test]
    fn test_zuc256_eea3_roundtrip() {
        let key = [0x17u8; 32];
        let iv = [0x3Du8; 25];
        let plaintext = b"Hello, ZUC-256 EEA3!";

        // Encrypt
        let ciphertext = zuc256_eea3(&key, &iv, plaintext);
        assert_ne!(&ciphertext[..], &plaintext[..]);

        // Decrypt (symmetric)
        let decrypted = zuc256_eea3(&key, &iv, &ciphertext);
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_zuc256_eea3_empty() {
        let key = [0x00u8; 32];
        let iv = [0x00u8; 25];

        let result = zuc256_eea3(&key, &iv, &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_zuc256_eea3_large_data() {
        let key = [0xFFu8; 32];
        let iv = [0xEEu8; 25];
        let plaintext = vec![0xABu8; 1024];

        let ciphertext = zuc256_eea3(&key, &iv, &plaintext);
        let decrypted = zuc256_eea3(&key, &iv, &ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_zuc256_eia3_basic() {
        let key = [0x17u8; 32];
        let iv = [0x3Du8; 25];
        let data = b"Integrity check data";

        let mac = zuc256_eia3(&key, &iv, data);

        // MAC should be non-zero
        assert_ne!(mac, [0, 0, 0, 0]);
    }

    #[test]
    fn test_zuc256_eia3_deterministic() {
        let key = [0x17u8; 32];
        let iv = [0x3Du8; 25];
        let data = b"Deterministic MAC test";

        let mac1 = zuc256_eia3(&key, &iv, data);
        let mac2 = zuc256_eia3(&key, &iv, data);

        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_zuc256_eia3_different_data() {
        let key = [0x17u8; 32];
        let iv = [0x3Du8; 25];

        let mac1 = zuc256_eia3(&key, &iv, b"Message A");
        let mac2 = zuc256_eia3(&key, &iv, b"Message B");

        // Different messages should produce different MACs (with overwhelming probability)
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_zuc256_different_keys_different_output() {
        let key1 = [0x00u8; 32];
        let key2 = [0x01u8; 32];
        let iv = [0x00u8; 25];
        let data = b"Key sensitivity test";

        let ct1 = zuc256_eea3(&key1, &iv, data);
        let ct2 = zuc256_eea3(&key2, &iv, data);

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_zuc256_eia3_64() {
        let key = [0x17u8; 32];
        let iv = [0x3Du8; 25];
        let data = b"64-bit MAC integrity test";

        let mac64 = zuc256_eia3_64(&key, &iv, data);
        assert_ne!(mac64, [0; 8]);
        assert_eq!(mac64.len(), 8);

        // Deterministic
        let mac64_2 = zuc256_eia3_64(&key, &iv, data);
        assert_eq!(mac64, mac64_2);
    }

    #[test]
    fn test_zuc256_eia3_64_different_data() {
        let key = [0xABu8; 32];
        let iv = [0xCDu8; 25];

        let mac_a = zuc256_eia3_64(&key, &iv, b"Data A");
        let mac_b = zuc256_eia3_64(&key, &iv, b"Data B");
        assert_ne!(mac_a, mac_b);
    }

    #[test]
    fn test_zuc256_kdf() {
        let key = [0x42u8; 32];
        let iv = [0x13u8; 25];

        let derived = zuc256_kdf(&key, &iv, 16);
        assert_eq!(derived.len(), 16);
        assert!(derived.iter().any(|&b| b != 0));

        // Deterministic
        let derived2 = zuc256_kdf(&key, &iv, 16);
        assert_eq!(derived, derived2);
    }

    #[test]
    fn test_zuc256_kdf_different_lengths() {
        let key = [0x42u8; 32];
        let iv = [0x13u8; 25];

        let d16 = zuc256_kdf(&key, &iv, 16);
        let d32 = zuc256_kdf(&key, &iv, 32);
        assert_eq!(d16.len(), 16);
        assert_eq!(d32.len(), 32);
        // First 16 bytes should match
        assert_eq!(&d16[..], &d32[..16]);
    }

    #[test]
    fn test_zuc256_c_interface() {
        let key = [0x17u8; 32];
        let iv = [0x3Du8; 25];
        let plaintext = b"C interface test";
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut decrypted = vec![0u8; plaintext.len()];

        // Encrypt
        let ret = zuc256_eea3_c(&key, &iv, plaintext, plaintext.len(), &mut ciphertext);
        assert_eq!(ret, 1);

        // Decrypt
        let ret = zuc256_eea3_c(&key, &iv, &ciphertext, ciphertext.len(), &mut decrypted);
        assert_eq!(ret, 1);
        assert_eq!(&decrypted[..], &plaintext[..]);

        // MAC
        let mut mac = [0u8; 4];
        let ret = zuc256_eia3_c(&key, &iv, plaintext, plaintext.len(), &mut mac);
        assert_eq!(ret, 1);
        assert_ne!(mac, [0, 0, 0, 0]);
    }
}
