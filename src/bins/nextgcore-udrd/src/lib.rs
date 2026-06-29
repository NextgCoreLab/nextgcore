//! NextGCore UDR (Unified Data Repository) Library
//!
//! This crate implements the UDR network function for 5G core network.
//! UDR provides data repository services for subscriber data, policy data,
//! and application data to other network functions like UDM and PCF.

pub mod context;
pub mod data_store;
pub mod event;
/// Non-serving legacy handler/state-machine path (udrd-09).
///
/// `nudr_handler` (and the sibling `udr_sm`/`ue_sm`/`sess_sm` state machines)
/// are a ported C implementation that was never wired to the live HTTP/2 SBI
/// server and produces no wire responses.  The module is kept as a non-public
/// (crate-internal) module because `udr_sm` still references it; it is NOT
/// re-exported as part of the public crate API.  No handler in this module
/// is reachable from `udr_sbi_request_handler`.
mod nudr_handler;
pub mod sbi_path;
pub mod sess_sm;
pub mod udr_sm;
pub mod ue_sm;

// Re-export commonly used types
pub use context::{udr_context_final, udr_context_init, udr_self, UdrContext, UdrSess, UdrUe};
pub use event::{UdrEvent, UdrEventId, UdrTimerId};
pub use udr_sm::{UdrSmContext, UdrState};

// Re-export SBI path functions
pub use sbi_path::{udr_sbi_close, udr_sbi_is_running, udr_sbi_open, SbiServer, SbiServerConfig};
