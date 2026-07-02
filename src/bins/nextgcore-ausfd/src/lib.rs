//! NextGCore AUSF (Authentication Server Function) Library
//!
//! This crate implements the AUSF (Authentication Server Function) for 5G core networks.
//! The AUSF is responsible for:
//! - UE authentication
//! - Authentication vector generation
//! - Key derivation (KAUSF, KSEAF)
//! - Authentication result confirmation

/// Daemon entrypoint + SBI request handlers, moved verbatim from the former
/// `main.rs` for Wave-6 H1 lib-targetization; the binary is now a thin wrapper
/// around [`app::run`]. Peer NF crates drive `ausf_sbi_request_handler` (and
/// the auth sub-handlers below) in-process for strict-peer tests.
pub mod app;
pub mod ausf_sm;
pub mod context;
pub mod eap_aka_prime;
pub mod event;
pub mod nausf_handler;
pub mod nudm_build;
pub mod nudm_handler;
pub mod sbi_path;
pub mod sbi_response;
pub mod sor_protection;
pub mod timer;
pub mod ue_sm;
pub mod upu_protection;

// Re-export commonly used types
pub use ausf_sm::{ausf_sm_debug, AusfSmContext, AusfState};
pub use context::{
    ausf_context_final, ausf_context_init, ausf_self, AnchorCounterError, AusfContext, AusfUe,
    AuthEvent, AuthResult, AuthType, SorUpuAnchor,
};
pub use event::{AusfEvent, AusfEventId, AusfTimerId};
pub use timer::{ausf_timer_get_name, timer_manager, AusfTimerManager};
pub use ue_sm::{AusfUeSmContext, AusfUeState};

// Re-export EAP-AKA' types
pub use eap_aka_prime::{EapAkaSession, EapCode, EapPacket, EapType};

// Re-export handler types
pub use nausf_handler::{
    ausf_nausf_auth_handle_authenticate, ausf_nausf_auth_handle_authenticate_confirmation,
    ausf_nausf_auth_handle_authenticate_delete,
};

// Re-export SoR/UPU protection producers (Wave-6 F-03, TS 29.509)
pub use sor_protection::handle_sor_protect;
pub use upu_protection::handle_upu_protect;

// Wave-6 H1: expose the real SBI request handler + Nausf_UEAuthentication
// sub-handlers peer NF crates drive for strict-peer tests, plus `run`.
pub use app::{
    ausf_sbi_request_handler, handle_5g_aka_confirmation, handle_auth_context_delete,
    handle_eap_session, handle_ue_authentication, run,
};

/// Helpers for in-process strict-peer tests in *other* crates. Not gated behind
/// `#[cfg(test)]` because cfg(test) items are invisible across crate
/// boundaries; a dev-dependency test in a peer crate must seed the
/// process-global AUSF context.
pub mod test_support {
    use std::sync::Mutex;

    /// Process-wide lock so strict-peer tests that touch the global AUSF
    /// context run serially (the context is process-global; parallel tests
    /// race).
    pub static CONTEXT_GUARD: Mutex<()> = Mutex::new(());

    /// Initialize the process-global AUSF context for in-process strict-peer
    /// tests (wraps [`crate::context::ausf_context_init`] with test capacity).
    pub fn init_context() {
        crate::context::ausf_context_init(128);
    }
}

// Re-export NUDM handler types
pub use nudm_handler::{
    ausf_nudm_ueau_handle_auth_removal_ind, ausf_nudm_ueau_handle_get,
    ausf_nudm_ueau_handle_result_confirmation_inform,
};

// Re-export build types
pub use nudm_build::{
    ausf_nudm_ueau_build_auth_removal_ind, ausf_nudm_ueau_build_get,
    ausf_nudm_ueau_build_result_confirmation_inform, AuthEvent as AuthEventBuild,
    AuthenticationInfoRequest, ResynchronizationInfo, SbiRequest,
};

// Re-export SBI path functions
pub use sbi_path::{
    ausf_sbi_close, ausf_sbi_discover_and_send_nudm_ueau_auth_removal,
    ausf_sbi_discover_and_send_nudm_ueau_get,
    ausf_sbi_discover_and_send_nudm_ueau_result_confirmation, ausf_sbi_is_running, ausf_sbi_open,
    SbiServer, SbiServerConfig, SbiXact,
};
