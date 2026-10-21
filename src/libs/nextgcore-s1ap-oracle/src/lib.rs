//! TEST-ONLY oracle: the hand-written S1AP codec mmed used before #514.
//!
//! Production mmed encodes and decodes every S1AP PDU with the codec generated
//! from the TS 36.413 ASN.1 (`nextgcore-s1ap-gen`). This crate keeps the old
//! hand-written builders, parser and APER structures only so mmed's
//! equivalence tests can still compare against them while they are converted
//! to hand-derived golden bytes (#514 stage 13b deletes this crate). It is a
//! dev-dependency only and must never be a normal dependency of a binary.

pub mod asn1;
pub mod builder;
pub mod error;
pub mod ie;
pub mod parser;

/// The domain types the old codec encoded from and decoded into.
pub mod types {
    pub use nextgcore_s1ap::types::*;
}

pub use builder::*;
pub use error::{S1apError, S1apResult};
pub use nextgcore_s1ap::S1apMessage;
pub use parser::{decode_s1ap_pdu, decode_s1ap_pdu_raw};
