//! NextGCore SEPP (Security Edge Protection Proxy) Library
//!
//! The SEPP is a 5G core network function responsible for:
//! - Securing inter-PLMN communication (roaming)
//! - N32c handshake for security capability negotiation
//! - N32f forwarding of SBI messages between PLMNs
//! - TLS/PRINS security scheme negotiation

pub mod context;
pub mod event;
pub mod timer;
pub mod sepp_sm;
pub mod handshake_sm;
pub mod n32c_handler;
pub mod n32c_build;
pub mod prins;
pub mod pqc_security;
pub mod sbi_path;
pub mod sbi_response;

// Re-export specific items to avoid ambiguous glob re-exports
pub use context::{
    sepp_self, sepp_context_init, sepp_context_final, SeppContext, SeppNode, SeppAssoc,
    PlmnId, SecurityCapability, NfType, SbiServiceType, SecurityCapabilityConfig,
};
pub use event::{SeppEventId, SeppTimerId, SeppEvent};
pub use handshake_sm::{HandshakeState, HandshakeSmContext};
pub use n32c_build::{build_security_capability_request, build_security_capability_response, build_security_capability_sbi_request};
pub use n32c_handler::{handle_security_capability_request, handle_security_capability_response};
pub use sbi_path::{
    sepp_sbi_open, sepp_sbi_close, sepp_sbi_is_running, handle_request, handle_response,
    SbiServerConfig, SbiRequest, SbiResponse, RequestHandlerResult,
};
pub use sepp_sm::SeppSmContext;
pub use timer::{TimerConfig, TimerManager, sepp_timer_get_name, timer_manager};
