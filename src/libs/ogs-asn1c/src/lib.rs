//! NextGCore ASN.1 Codec Library
//!
//! This crate provides ASN.1 PER encoding/decoding for NGAP and S1AP protocols.
//!
//! # Modules
//!
//! - `per` - Packed Encoding Rules (APER) encoder/decoder
//! - `ngap` - NGAP protocol types and codec (3GPP TS 38.413)
//! - `s1ap` - S1AP protocol types and codec (3GPP TS 36.413)

pub mod e1ap;
pub mod f1ap; // F1AP codec - CU-DU (TS 38.473)
pub mod lpp; // LPP codec - LTE/NR Positioning Protocol (TS 37.355), UPER, LMF<->UE
pub mod ngap; // NGAP codec (directory module)
pub mod nrppa; // NRPPa codec - NR Positioning Protocol A (TS 38.455), APER, NGAP-carried
pub mod per; // Packed Encoding Rules (APER)
pub mod s1ap; // S1AP codec
pub mod uper; // Unaligned PER (UPER) - LPP (TS 37.355) / RRC
pub mod xnap; // XnAP codec - inter-gNB (TS 38.423) // E1AP codec - CU-CP/CU-UP (TS 38.463)

#[cfg(test)]
mod property_tests;

// Re-export commonly used types
pub use per::{AperDecode, AperDecoder, AperEncode, AperEncoder, PerError, PerResult};
