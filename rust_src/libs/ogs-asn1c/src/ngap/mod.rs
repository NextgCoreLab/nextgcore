//! NGAP (NG Application Protocol) codec
//!
//! Implementation of NGAP protocol as defined in 3GPP TS 38.413 (R17.3.0)
//! for 5G Core Network communication between gNB and AMF.

pub mod types;
pub mod cause;
pub mod pdu;
pub mod ies;

// Re-export commonly used types
pub use types::*;
pub use cause::*;
pub use pdu::*;
pub use ies::*;
