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
pub mod uecm;

// Re-export commonly used types
pub use context::{
    udm_context_final, udm_context_init, udm_self, AuthEvent, UdmContext, UdmEeSubscription,
    UdmSdmSubscription, UdmSess, UdmUe,
};
pub use event::{UdmEvent, UdmEventId, UdmTimerId};
pub use sess_sm::{UdmSessSmContext, UdmSessState};
pub use timer::{timer_manager, timer_type_to_timer_id, udm_timer_get_name, UdmTimerManager};
pub use udm_sm::{UdmSmContext, UdmState};
pub use ue_sm::{UdmUeSmContext, UdmUeState};

// Re-export SBI path functions
pub use sbi_path::{
    udm_nrf_deregister, udm_nrf_discover, udm_nrf_heartbeat, udm_nrf_register,
    udm_nudr_dr_send_amf_context_get, udm_nudr_dr_send_amf_context_patch,
    udm_nudr_dr_send_amf_context_put, udm_nudr_dr_send_auth_status_put,
    udm_nudr_dr_send_auth_subscription_get, udm_nudr_dr_send_auth_subscription_patch,
    udm_nudr_dr_send_context_delete, udm_nudr_dr_send_provisioned_data_get,
    udm_nudr_dr_send_provisioned_data_get_with_params, udm_nudr_dr_send_smf_context_get,
    udm_nudr_dr_send_smf_context_put, udm_sbi_close, udm_sbi_discover_and_send_nudr_dr,
    udm_sbi_is_running, udm_sbi_open, udm_sbi_send_dereg_notification, udm_sbi_send_request,
    SbiServer, SbiServerConfig, SbiXact,
};
