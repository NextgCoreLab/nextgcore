//! NRPPa codec — NR Positioning Protocol A (3GPP TS 38.455), gNB <-> LMF,
//! carried transparently inside NGAP (DL/UL (non-)UE-associated NRPPa transport).
//!
//! Uses Aligned PER (APER), so it reuses `crate::per` unchanged and mirrors the
//! `crate::ngap` module layout (types / ies / pdu / cause). The one structural
//! divergence from NGAP: every NRPPa message carries an extra root field
//! `nrppatransactionID INTEGER(0..32767)` between `criticality` and `value`.
//!
//! Wave-3 lmfd-LIB-01 — v1 covers the E-CID Measurement procedures (Initiation
//! Request/Response/Failure + Measurement Report) with typed E-CID IEs; every
//! other procedure rides through as an opaque `ProtocolIE-Container`.

pub mod cause;
pub mod ies;
pub mod pdu;
pub mod trp;
pub mod types;

// Re-export commonly used types.
pub use cause::*;
pub use ies::*;
pub use pdu::*;
pub use trp::*;
pub use types::*;
