//! NextGCore Rust Integration Tests
//!
//! This module contains integration tests for the NextGCore Rust implementation.
//! Tests verify end-to-end functionality of 5G Core and EPC network functions.
//!
//! ## Test Categories
//!
//! - `registration`: 5G UE registration and 4G UE attach flows
//! - `session`: PDU session and EPS bearer establishment
//! - `inter_nf`: Inter-NF communication (SBI, Diameter, GTP)
//! - `property`: Property-based tests for protocol flows
//! - `volte`: Voice over LTE call flows and IMS procedures
//! - `handover`: Mobility procedures (X2, S1, Xn, N2, inter-RAT)
//! - `slicing`: 5G network slicing (S-NSSAI, NSSF, slice QoS)

pub mod common;
pub mod registration;
pub mod session;
pub mod inter_nf;
pub mod property;
pub mod volte;
pub mod handover;
pub mod slicing;

// Re-export common test utilities
pub use common::*;
