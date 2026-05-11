//! NextGCore S1AP Protocol Library
//!
//! This crate provides S1AP message building and handling.
//! S1AP is the control plane protocol between eNodeB and MME/EPC per 3GPP TS 36.413.

pub mod builder;
pub mod error;
pub mod types;

pub use builder::*;
pub use error::{S1apError, S1apResult};
pub use types::*;
