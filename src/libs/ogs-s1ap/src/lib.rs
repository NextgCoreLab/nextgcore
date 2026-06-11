//! NextGCore S1AP Protocol Library
//!
//! This crate provides S1AP message building and parsing.
//! S1AP is the control plane protocol between eNodeB and MME/EPC per 3GPP TS 36.413.
//!
//! Messages are APER-encoded/decoded via the `ogs-asn1c` s1ap module:
//! builders in [`builder`] produce wire bytes from the strongly-typed
//! structures in [`types`], and [`parser::decode_s1ap_pdu`] dispatches the
//! S1AP-PDU CHOICE (initiatingMessage / successfulOutcome /
//! unsuccessfulOutcome) by procedure code.

pub mod builder;
pub mod error;
pub mod ie;
pub mod parser;
pub mod types;

pub use builder::*;
pub use error::{S1apError, S1apResult};
pub use parser::{decode_s1ap_pdu, decode_s1ap_pdu_raw, S1apMessage};
pub use types::*;
