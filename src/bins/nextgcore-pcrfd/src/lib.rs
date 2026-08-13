//! NextGCore PCRF (Policy and Charging Rules Function) Library
//!
//! This crate implements the PCRF for LTE/EPC networks.
//! The PCRF is responsible for:
//! - Policy and charging control (Gx interface with P-GW/SMF)
//! - Application function interaction (Rx interface with AF/P-CSCF)
//! - QoS policy decisions based on subscriber data

pub mod context;
pub mod event;
pub mod fd_path;
pub mod gx_path;
pub mod rx_path;
pub mod sm;

// Re-export commonly used types
pub use context::{
    apply_diameter_yaml, pcrf_context_final, pcrf_context_init, pcrf_context_parse_config,
    pcrf_self, pcrf_sess_find_by_ipv4, pcrf_sess_find_by_ipv6, pcrf_sess_set_ipv4,
    pcrf_sess_set_ipv6, DiamConfig, DiameterYaml, PcrfContext, PcrfGxSession, PcrfRxSession,
    PcrfSectionYaml, PcrfYaml,
};
pub use event::{PcrfEvent, PcrfEventId};
pub use fd_path::{
    pcrf_fd_final, pcrf_fd_init, pcrf_fd_listen, pcrf_fd_peer_connected, pcrf_fd_send_request,
    pcrf_fd_set_local_identity, pcrf_local_identity, LocalIdentity, PcrfDiamStats, PcrfDiamStatsGx,
    PcrfDiamStatsRx,
};
pub use gx_path::{pcrf_gx_final, pcrf_gx_init, pcrf_gx_send_rar, RarAction};
pub use rx_path::{pcrf_rx_final, pcrf_rx_init, pcrf_rx_send_asr_for_target};
pub use sm::{pcrf_sm_debug, PcrfSmContext, PcrfState};
