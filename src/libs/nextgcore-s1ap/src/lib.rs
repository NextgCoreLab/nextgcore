//! NextGCore S1AP domain types
//!
//! S1AP is the control plane protocol between eNodeB and MME/EPC per 3GPP TS 36.413.
//!
//! This crate holds the strongly-typed S1AP message structures mmed's handlers
//! work with ([`types`]), the Cause / Criticality values ([`cause`]) and the
//! [`S1apMessage`] dispatch union ([`message`]). It carries no codec: every S1AP
//! PDU is encoded and decoded by the codec generated from the TS 36.413 ASN.1
//! (`nextgcore-s1ap-gen`), which replaced the hand-written one here (#514).

pub mod cause;
pub mod error;
pub mod message;
pub mod types;

pub use error::{S1apError, S1apResult};
pub use message::S1apMessage;
pub use types::*;
