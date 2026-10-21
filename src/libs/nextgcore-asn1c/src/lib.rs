//! NextGCore ASN.1 Codec Library
//!
//! This crate provides ASN.1 PER encoding/decoding for NGAP and S1AP protocols.
//!
//! # Modules
//!
//! - `per` - Packed Encoding Rules (APER) encoder/decoder
//! - `ngap` - NGAP protocol types and codec (3GPP TS 38.413)
//! - `lpp` - LPP (3GPP TS 37.355, UPER)
//!
//! NRPPa (TS 38.455) is generated from the 3GPP ASN.1 by `nextgcore-nrppa-gen`;
//! the hand-written module here was removed (#515).
//!
//! There is no E1AP, F1AP or XnAP codec. Earlier hand-written modules for
//! them were not ASN.1 PDUs (no PDU CHOICE, open type or ProtocolIE-Container)
//! and had no consumers, so they were removed (#457). A future one should be
//! generated from the 3GPP ASN.1 (TS 38.463 / 38.473 / 38.423) with the forked
//! compiler, as `nextgcore-ngap-gen` does for NGAP (#417).

pub mod lpp; // LPP codec - LTE/NR Positioning Protocol (TS 37.355), UPER, LMF<->UE
pub mod ngap; // NGAP codec (directory module)
pub mod per; // Packed Encoding Rules (APER)
pub mod uper; // Unaligned PER (UPER) - LPP (TS 37.355) / RRC

#[cfg(test)]
mod property_tests;

// Re-export commonly used types
pub use per::{AperDecode, AperDecoder, AperEncode, AperEncoder, PerError, PerResult};
