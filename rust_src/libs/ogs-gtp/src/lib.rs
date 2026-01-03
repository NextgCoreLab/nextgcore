//! NextGCore GTP Protocol Library
//!
//! This crate provides GTPv1-U and GTPv2-C message building and parsing.
//! It implements the GPRS Tunneling Protocol as specified in 3GPP TS 29.060 (GTPv1)
//! and 3GPP TS 29.274 (GTPv2).

pub mod error;
pub mod v1;
pub mod v2;

#[cfg(test)]
mod property_tests;

pub use error::{GtpError, GtpResult};

/// GTPv1-U UDP port (2152)
pub const GTPV1_U_UDP_PORT: u16 = 2152;

/// GTPv2-C UDP port (2123)
pub const GTPV2_C_UDP_PORT: u16 = 2123;

/// Maximum indirect tunnel count
pub const MAX_INDIRECT_TUNNEL: usize = 8;

/// 5GC GTP Header length (16 bytes)
pub const GTPV1U_5GC_HEADER_LEN: usize = 16;

/// GTPv1-U extension header length
pub const GTPV1U_EXTENSION_HEADER_LEN: usize = 4;
