//! NextGCore Diameter Protocol Library
//!
//! This crate provides Diameter message handling for 3GPP interfaces:
//! - S6a: MME <-> HSS (Authentication and Location Update)
//! - S6b: PGW/SMF <-> 3GPP AAA Server (Non-3GPP Access Authorization)
//! - Gx: PCEF <-> PCRF (Policy and Charging Control)
//! - Gy: CTF <-> OCS (Online Charging)
//! - Rx: AF <-> PCRF (Application Function)
//! - Cx: I-CSCF/S-CSCF <-> HSS (IMS Registration)
//! - SWx: 3GPP AAA Server <-> HSS (Non-3GPP Access)
//!
//! The implementation follows RFC 6733 (Diameter Base Protocol) and
//! 3GPP specifications for each interface.

pub mod common;
pub mod avp;
pub mod message;
pub mod s6a;
pub mod s6b;
pub mod gx;
pub mod gy;
pub mod rx;
pub mod cx;
pub mod swx;
pub mod error;
pub mod config;
pub mod transport;
pub mod peer;

pub use common::*;
pub use avp::*;
pub use message::*;
pub use error::*;
pub use config::*;
pub use transport::*;
pub use peer::*;

/// 3GPP Vendor ID
pub const OGS_3GPP_VENDOR_ID: u32 = 10415;

/// Diameter protocol version
pub const DIAMETER_VERSION: u8 = 1;

/// Default Diameter port
pub const DIAMETER_PORT: u16 = 3868;

/// Default Diameter TLS port
pub const DIAMETER_TLS_PORT: u16 = 5658;
