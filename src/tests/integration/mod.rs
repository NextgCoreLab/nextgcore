//! NextGCore Rust Integration Tests
//!
//! This module contains integration tests for the NextGCore Rust implementation.
//! Tests verify end-to-end functionality of the 5G Core network functions.
//!
//! ## Test Categories
//!
//! - `registration`: 5G UE registration flows
//! - `session`: PDU session establishment
//! - `inter_nf`: Inter-NF communication (SBI, GTP)
//! - `property`: Property-based tests for protocol flows
//! - `handover`: Mobility procedures (X2, S1, Xn, N2, inter-RAT)
//! - `slicing`: 5G network slicing (S-NSSAI, NSSF, slice QoS)
//! - `pfcp`: PFCP N4 interface tests (SMF-UPF communication)

pub mod common;
pub mod handover;
pub mod inter_nf;
pub mod pfcp;
pub mod property;
pub mod registration;
pub mod session;
pub mod slicing;

// Re-export common test utilities
pub use common::*;
