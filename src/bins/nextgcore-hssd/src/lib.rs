//! NextGCore HSS (Home Subscriber Server) Library
//!
//! This crate implements the HSS (Home Subscriber Server) for LTE/EPC networks.
//! The HSS is responsible for:
//! - Subscriber authentication (S6a interface with MME)
//! - IMS authentication (Cx interface with I-CSCF/S-CSCF)
//! - Non-3GPP authentication (SWx interface with 3GPP AAA)
//! - Subscriber data management

pub mod context;
pub mod event;
pub mod fd_path;
pub mod s6a_path;
pub mod cx_path;
pub mod swx_path;
pub mod sm;
pub mod timer;

// Re-export commonly used types
pub use context::{
    hss_context_final, hss_context_init, hss_context_parse_config, hss_self,
    HssContext, HssImpi, HssImpu, HssImsi,
};
pub use event::{HssEvent, HssEventId, HssTimerId};
pub use fd_path::{hss_fd_final, hss_fd_init, HssDiamStats, HssDiamStatsCx, HssDiamStatsS6a, HssDiamStatsSwx};
pub use s6a_path::{hss_s6a_final, hss_s6a_init, hss_s6a_send_clr, hss_s6a_send_idr};
pub use cx_path::{hss_cx_final, hss_cx_init};
pub use swx_path::{hss_swx_final, hss_swx_init};
pub use sm::{hss_sm_debug, HssSmContext, HssState};
pub use timer::{hss_timer_get_name, timer_manager, HssTimerManager};
