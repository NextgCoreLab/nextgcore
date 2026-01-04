//! NextGCore NRF (Network Repository Function) Library
//!
//! This crate implements the NRF (Network Repository Function) for 5G core networks.
//! The NRF is responsible for:
//! - NF registration and deregistration
//! - NF discovery
//! - NF status notifications
//! - Subscription management

pub mod context;
pub mod event;
pub mod nf_sm;
pub mod nnrf_build;
pub mod nnrf_handler;
pub mod nrf_sm;
pub mod sbi_path;
pub mod timer;

// Re-export commonly used types
pub use context::{nrf_context_final, nrf_context_init, nrf_self, NrfAssoc, NrfContext};
pub use event::{NrfEvent, NrfEventId, NrfTimerId};
pub use nf_sm::{nrf_nf_fsm_fini, nrf_nf_fsm_init, NfSmContext, NfState};
pub use nrf_sm::{nrf_sm_debug, NrfSmContext, NrfState};
pub use timer::{nrf_timer_get_name, timer_manager, NrfTimerManager};

// Re-export handler types
pub use nnrf_handler::{
    nf_manager, nrf_nnrf_handle_nf_discover, nrf_nnrf_handle_nf_register,
    nrf_nnrf_handle_nf_status_subscribe, nrf_nnrf_handle_nf_status_unsubscribe,
    DiscoveryOptions, HandlerResult, NfInstanceManager, NfProfile, SubscriptionData,
};

// Re-export build types
pub use nnrf_build::{
    nrf_nnrf_nfm_build_nf_status_notify, NotificationData, NotificationEventType, SbiNotifyRequest,
};

// Re-export SBI path functions
pub use sbi_path::{
    nrf_nnrf_nfm_send_nf_status_notify, nrf_nnrf_nfm_send_nf_status_notify_all, nrf_sbi_close,
    nrf_sbi_is_running, nrf_sbi_open, SbiServer, SbiServerConfig,
};
