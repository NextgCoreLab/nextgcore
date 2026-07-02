//! Random number generation
//!
//! Exact port of lib/core/nextgcore-rand.h and nextgcore-rand.c

use rand::RngCore;

/// Fill buffer with random bytes (identical to nextgcore_random)
pub fn nextgcore_random(buf: &mut [u8]) {
    rand::rng().fill_bytes(buf);
}

/// Generate random 32-bit value (identical to nextgcore_random32)
pub fn nextgcore_random32() -> u32 {
    rand::random()
}

/// Generate random 64-bit value
pub fn nextgcore_random64() -> u64 {
    rand::random()
}

/// Generate random bytes as Vec
pub fn nextgcore_random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    nextgcore_random(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nextgcore_random() {
        let mut buf1 = [0u8; 16];
        let mut buf2 = [0u8; 16];

        nextgcore_random(&mut buf1);
        nextgcore_random(&mut buf2);

        // Very unlikely to be equal
        assert_ne!(buf1, buf2);
        // Very unlikely to be all zeros
        assert!(buf1.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_nextgcore_random32() {
        let r1 = nextgcore_random32();
        let r2 = nextgcore_random32();

        // Very unlikely to be equal
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_nextgcore_random_bytes() {
        let bytes = nextgcore_random_bytes(32);
        assert_eq!(bytes.len(), 32);
        // Very unlikely to be all zeros
        assert!(bytes.iter().any(|&b| b != 0));
    }
}
