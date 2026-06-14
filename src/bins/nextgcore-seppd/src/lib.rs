//! NextGCore SEPP (Security Edge Protection Proxy) Library
//!
//! The SEPP is a 5G core network function responsible for:
//! - Securing inter-PLMN communication (roaming)
//! - N32c handshake for security capability negotiation
//! - N32f forwarding of SBI messages between PLMNs
//! - TLS/PRINS security scheme negotiation

pub mod context;
pub mod event;
pub mod handshake_sm;
pub mod jose;
pub mod n32_server;
pub mod n32c_build;
pub mod n32c_handler;
pub mod pqc_security;
pub mod prins;
pub mod sbi_path;
pub mod sbi_response;
pub mod sepp_sm;
pub mod timer;

// Re-export specific items to avoid ambiguous glob re-exports
pub use context::{
    sepp_context_final, sepp_context_init, sepp_self, NfType, PlmnId, SbiServiceType,
    SecurityCapability, SecurityCapabilityConfig, SeppAssoc, SeppContext, SeppNode,
};
pub use event::{SeppEvent, SeppEventId, SeppTimerId};
pub use handshake_sm::{HandshakeSmContext, HandshakeState};
pub use n32_server::{
    forward_via_n32f, initiate_n32c_handshake, send_n32f_error, start_n32_listener,
    take_received_n32f_errors, HandshakeOutcome, N32TlsConfig,
};
pub use n32c_build::{
    build_security_capability_request, build_security_capability_response,
    build_security_capability_sbi_request,
};
pub use n32c_handler::{
    handle_exchange_params_request, handle_exchange_params_response,
    handle_security_capability_request, handle_security_capability_response, SecParamExchReqData,
    SecParamExchRspData,
};
pub use sbi_path::{
    handle_request, handle_response, sepp_sbi_close, sepp_sbi_is_running, sepp_sbi_open,
    RequestHandlerResult, SbiRequest, SbiResponse, SbiServerConfig,
};
pub use sepp_sm::SeppSmContext;
pub use timer::{sepp_timer_get_name, timer_manager, TimerConfig, TimerManager};
