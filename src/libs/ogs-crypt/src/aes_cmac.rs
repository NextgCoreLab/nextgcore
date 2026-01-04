//! AES-CMAC
//!
//! Wrapper around the `cmac` crate to match the interface of lib/crypt/ogs-aes-cmac.c
//!
//! Implements RFC 4493 AES-CMAC algorithm for message authentication.

use aes::Aes128;
use cmac::{Cmac, Mac};

/// CMAC output size in bytes
pub const CMAC_SIZE: usize = 16;

/// Error type for CMAC operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmacError {
    /// Invalid CMAC verification failed
    InvalidCmac,
}

/// Calculate AES-CMAC for a message
///
/// # Arguments
/// * `key` - 128-bit key (16 bytes)
/// * `msg` - Message to authenticate
///
/// # Returns
/// * 16-byte CMAC value
pub fn aes_cmac_calculate(key: &[u8; 16], msg: &[u8]) -> [u8; 16] {
    let mut mac = Cmac::<Aes128>::new_from_slice(key).expect("CMAC key should be valid");
    mac.update(msg);
    let result = mac.finalize();
    let mut cmac = [0u8; 16];
    cmac.copy_from_slice(&result.into_bytes());
    cmac
}

/// Verify AES-CMAC for a message
///
/// # Arguments
/// * `cmac` - Expected 16-byte CMAC value
/// * `key` - 128-bit key (16 bytes)
/// * `msg` - Message to verify
///
/// # Returns
/// * `Ok(())` - If CMAC is valid
/// * `Err(CmacError::InvalidCmac)` - If CMAC verification fails
pub fn aes_cmac_verify(cmac: &[u8; 16], key: &[u8; 16], msg: &[u8]) -> Result<(), CmacError> {
    let calculated = aes_cmac_calculate(key, msg);
    
    // Constant-time comparison to prevent timing attacks
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= calculated[i] ^ cmac[i];
    }
    
    if diff == 0 {
        Ok(())
    } else {
        Err(CmacError::InvalidCmac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4493 Test Vectors
    // K = 2b7e1516 28aed2a6 abf71588 09cf4f3c
    const TEST_KEY: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    ];

    #[test]
    fn test_cmac_empty_message() {
        // Example 1: len = 0
        // M = <empty>
        // AES-CMAC = bb1d6929 e9593728 7fa37d12 9b756746
        let msg: [u8; 0] = [];
        let expected = [
            0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
            0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46,
        ];
        
        let cmac = aes_cmac_calculate(&TEST_KEY, &msg);
        assert_eq!(cmac, expected);
    }

    #[test]
    fn test_cmac_16_bytes() {
        // Example 2: len = 16
        // M = 6bc1bee2 2e409f96 e93d7e11 7393172a
        // AES-CMAC = 070a16b4 6b4d4144 f79bdd9d d04a287c
        let msg = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        ];
        let expected = [
            0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
            0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c,
        ];
        
        let cmac = aes_cmac_calculate(&TEST_KEY, &msg);
        assert_eq!(cmac, expected);
    }

    #[test]
    fn test_cmac_40_bytes() {
        // Example 3: len = 40
        // M = 6bc1bee2 2e409f96 e93d7e11 7393172a
        //     ae2d8a57 1e03ac9c 9eb76fac 45af8e51
        //     30c81c46 a35ce411
        // AES-CMAC = dfa66747 de9ae630 30ca3261 1497c827
        let msg = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        ];
        let expected = [
            0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
            0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27,
        ];
        
        let cmac = aes_cmac_calculate(&TEST_KEY, &msg);
        assert_eq!(cmac, expected);
    }

    #[test]
    fn test_cmac_64_bytes() {
        // Example 4: len = 64
        // M = 6bc1bee2 2e409f96 e93d7e11 7393172a
        //     ae2d8a57 1e03ac9c 9eb76fac 45af8e51
        //     30c81c46 a35ce411 e5fbc119 1a0a52ef
        //     f69f2445 df4f9b17 ad2b417b e66c3710
        // AES-CMAC = 51f0bebf 7e3b9d92 fc497417 79363cfe
        let msg = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
            0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];
        let expected = [
            0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
            0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe,
        ];
        
        let cmac = aes_cmac_calculate(&TEST_KEY, &msg);
        assert_eq!(cmac, expected);
    }

    #[test]
    fn test_cmac_verify_valid() {
        let msg = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        ];
        let expected = [
            0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
            0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c,
        ];
        
        assert!(aes_cmac_verify(&expected, &TEST_KEY, &msg).is_ok());
    }

    #[test]
    fn test_cmac_verify_invalid() {
        let msg = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        ];
        let wrong_cmac = [
            0x00, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
            0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c,
        ];
        
        assert_eq!(aes_cmac_verify(&wrong_cmac, &TEST_KEY, &msg), Err(CmacError::InvalidCmac));
    }
}
