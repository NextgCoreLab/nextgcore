//! NextGCore Cryptographic Library
//!
//! This crate provides cryptographic algorithms used in 3GPP networks.
//! It is a direct port of lib/crypt/ from the C implementation.

pub mod milenage;   // 3GPP Milenage algorithm
pub mod kasumi;     // KASUMI block cipher (f8/f9)
pub mod snow3g;     // SNOW 3G stream cipher
pub mod zuc;        // ZUC stream cipher
pub mod zuc256;     // ZUC-256 stream cipher (256-bit security)
pub mod aes;        // AES operations
pub mod aes_cmac;   // AES-CMAC
pub mod sha;        // SHA-1 and SHA-2
pub mod kdf;        // Key Derivation Functions
pub mod ecc;        // Elliptic Curve Cryptography (P-256 + ECIES Profile B)
pub mod base64;     // Base64 encoding/decoding
pub mod ml_kem;     // ML-KEM (CRYSTALS-Kyber) post-quantum KEM
pub mod ml_dsa;     // ML-DSA (CRYSTALS-Dilithium) post-quantum signatures
pub mod hybrid;     // Hybrid key exchange (P-256 + ML-KEM-768)
pub mod snow5g;     // SNOW5G stream cipher (placeholder)

#[cfg(test)]
mod property_tests; // Property-based tests for crypto algorithms
