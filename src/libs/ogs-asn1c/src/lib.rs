//! NextGCore ASN.1 Codec Library
//!
//! This crate provides ASN.1 PER encoding/decoding for NGAP and S1AP protocols.
//! 
//! # Modules
//! 
//! - `per` - Packed Encoding Rules (APER) encoder/decoder
//! - `ngap` - NGAP protocol types and codec (3GPP TS 38.413)
//! - `s1ap` - S1AP protocol types and codec (3GPP TS 36.413)

pub mod per;    // Packed Encoding Rules
pub mod ngap;   // NGAP codec (directory module)
pub mod s1ap;   // S1AP codec
pub mod xnap;   // XnAP codec - inter-gNB (TS 38.423)
pub mod f1ap;   // F1AP codec - CU-DU (TS 38.473)
pub mod e1ap;   // E1AP codec - CU-CP/CU-UP (TS 38.463)

#[cfg(test)]
mod property_tests;

// Re-export commonly used types
pub use per::{AperEncoder, AperDecoder, AperEncode, AperDecode, PerError, PerResult};
