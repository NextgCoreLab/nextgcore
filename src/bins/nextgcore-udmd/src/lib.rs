//! NextGCore UDM (Unified Data Management) Library
//!
//! This crate implements the UDM network function for 5G core network.
//! UDM provides subscriber data management, authentication credential processing,
//! and subscription management services.

/// Daemon entrypoint + SBI request handlers, moved verbatim from the former
/// `main.rs` for Wave-6 H1 lib-targetization; the binary is now a thin wrapper
/// around [`app::run`]. Peer NF crates drive `udm_sbi_request_handler` (and the
/// sub-handlers below) in-process for strict-peer tests.
pub mod app;
pub mod context;
pub mod event;
#[cfg(feature = "nes")]
pub mod nes_driver; // issue #22 Network Energy Saving runtime (off by default)
pub mod nudm_handler;
pub mod nudr_handler;
pub mod sbi_path;
pub mod sbi_response;
pub mod sess_sm;
/// Wave-6 F-04: Steering-of-Roaming injection into Nudm_SDM am-data via the
/// real Nausf_SoRProtection producer (TS 33.501 §6.14.2.1, TS 29.503/29.509).
pub mod sor;
pub mod timer;
pub mod udm_sm;
pub mod ue_sm;
pub mod uecm;
/// Wave-6 F-05: UE-Parameters-Update injection into Nudm_SDM am-data via the
/// real Nausf_UPUProtection producer (TS 33.501 §6.15.2.1, TS 29.503/29.509).
/// Notification-driven UPU (Nudm_SDM_Notification) is deferred — see the module
/// doc-comment.
pub mod upu;

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

// Wave-6 H1: expose the real SBI request handler + the sub-handlers peer NF
// crates drive for strict-peer tests (am-data GET + SoR/UPU ack), plus `run`.
pub use app::{handle_get_am_data, handle_sor_ack, handle_upu_ack, run, udm_sbi_request_handler};

/// Helpers for in-process strict-peer tests in *other* crates. Not gated behind
/// `#[cfg(test)]` because cfg(test) items are invisible across crate
/// boundaries; a dev-dependency test in a peer crate must seed the
/// process-global UDM context.
pub mod test_support {
    use std::sync::Mutex;

    /// Process-wide lock so strict-peer tests that touch the global UDM context
    /// run serially (the UDM context is process-global; parallel tests race).
    pub static CONTEXT_GUARD: Mutex<()> = Mutex::new(());

    /// Initialize the process-global UDM context for in-process strict-peer
    /// tests (wraps [`crate::context::udm_context_init`] with test capacities).
    pub fn init_context() {
        crate::context::udm_context_init(64, 64);
    }
}

// Re-export SBI path functions
pub use sbi_path::{
    udm_ausf_send_sor_protect, udm_ausf_send_upu_protect, udm_nrf_deregister, udm_nrf_discover,
    udm_nrf_heartbeat, udm_nrf_register, udm_nudr_dr_send_amf_context_get,
    udm_nudr_dr_send_amf_context_patch, udm_nudr_dr_send_amf_context_put,
    udm_nudr_dr_send_auth_status_put, udm_nudr_dr_send_auth_subscription_get,
    udm_nudr_dr_send_auth_subscription_patch, udm_nudr_dr_send_context_delete,
    udm_nudr_dr_send_provisioned_data_get, udm_nudr_dr_send_provisioned_data_get_with_params,
    udm_nudr_dr_send_smf_context_get, udm_nudr_dr_send_smf_context_put, udm_sbi_close,
    udm_sbi_discover_and_send_nudr_dr, udm_sbi_is_running, udm_sbi_open,
    udm_sbi_send_dereg_notification, udm_sbi_send_request, SbiServer, SbiServerConfig, SbiXact,
};

// Wave-6 F-04: expose the am-data SoR injection entry point for strict-peer
// tests (F-07) driving the real handler in-process.
pub use sor::maybe_inject_sor_info;

// Wave-6 F-05: expose the am-data UPU injection entry point for strict-peer
// tests (F-07) driving the real handler in-process.
pub use upu::maybe_inject_upu_info;
