//! NextGCore AUSF (Authentication Server Function) Library
//!
//! This crate implements the AUSF (Authentication Server Function) for 5G core networks.
//! The AUSF is responsible for:
//! - UE authentication
//! - Authentication vector generation
//! - Key derivation (KAUSF, KSEAF)
//! - Authentication result confirmation

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
