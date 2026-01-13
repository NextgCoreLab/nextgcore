//! NextGCore UDM (Unified Data Management) Library
//!
//! This crate implements the UDM network function for 5G core network.
//! UDM provides subscriber data management, authentication credential processing,
//! and subscription management services.

pub mod context;
pub mod event;
pub mod nudm_handler;
pub mod nudr_handler;
pub mod sbi_path;
pub mod sbi_response;
pub mod sess_sm;
pub mod timer;
pub mod udm_sm;
pub mod ue_sm;

// Re-export commonly used types
pub use context::{udm_context_final, udm_context_init, udm_self, UdmContext, UdmSdmSubscription, UdmSess, UdmUe};
pub use event::{UdmEvent, UdmEventId, UdmTimerId};
pub use udm_sm::{UdmSmContext, UdmState};
pub use ue_sm::{UdmUeSmContext, UdmUeState};
pub use sess_sm::{UdmSessSmContext, UdmSessState};
pub use timer::{udm_timer_get_name, timer_manager, UdmTimerManager};

// Re-export SBI path functions
pub use sbi_path::{
    udm_sbi_close, udm_sbi_is_running, udm_sbi_open,
    SbiServer, SbiServerConfig, SbiXact,
};
