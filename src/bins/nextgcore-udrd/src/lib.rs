//! NextGCore UDR (Unified Data Repository) Library
//!
//! This crate implements the UDR network function for 5G core network.
//! UDR provides data repository services for subscriber data, policy data,
//! and application data to other network functions like UDM and PCF.

pub mod context;
pub mod event;
pub mod nudr_handler;
pub mod sbi_path;
pub mod sess_sm;
pub mod udr_sm;
pub mod ue_sm;

// Re-export commonly used types
pub use context::{udr_context_final, udr_context_init, udr_self, UdrContext, UdrUe, UdrSess};
pub use event::{UdrEvent, UdrEventId, UdrTimerId};
pub use udr_sm::{UdrSmContext, UdrState};
pub use ue_sm::{UdrUeSmContext, UdrUeState};
pub use sess_sm::{UdrSessSmContext, UdrSessState};

// Re-export SBI path functions
pub use sbi_path::{
    udr_sbi_close, udr_sbi_is_running, udr_sbi_open,
    SbiServer, SbiServerConfig,
};
