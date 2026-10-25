//! NextGCore SGWC (Serving Gateway Control Plane), as a library.
//!
//! The SGW-C's modules live here so a peer NF crate can drive its real S5/S8 codecs
//! and handlers in-process -- smfd's tests parse the PGW-C's Create Session Response
//! with this crate's own code, so the two ends of S5/S8 cannot drift on an IE
//! instance again (#1113). `src/main.rs` is the daemon around it.

pub mod config;
pub mod context;
pub mod event;
pub mod gtp_path;
pub mod pfcp_path;
pub mod pfcp_sm;
pub mod s11_build;
pub mod s11_handler;
pub mod s11_parse;
pub mod s5c_handler;
pub mod sm;
pub mod sxa_build;
pub mod sxa_handler;
pub mod sxa_response;
pub mod timer;
pub mod up_path;

use context::sgwc_self;

/// The SGW-C's runtime state in Prometheus text format: liveness, the Sxa
/// association, the UE census, and the user plane path reports (#994).
pub fn render_metrics() -> String {
    let associated = pfcp_path::sxa_node()
        .map(|n| n.associated_peer_count())
        .unwrap_or(0);
    let mut out = format!(
        "# HELP sgwc_up 1 while the SGW-C runtime is serving\n\
         # TYPE sgwc_up gauge\n\
         sgwc_up 1\n\
         # HELP sgwc_pfcp_associations Sxa PFCP associations with an SGW-U\n\
         # TYPE sgwc_pfcp_associations gauge\n\
         sgwc_pfcp_associations {associated}\n\
         # TYPE sgwc_ues gauge\n\
         sgwc_ues {}\n",
        sgwc_self().ue_count()
    );
    up_path::render_metrics(&mut out);
    gtp_path::render_s5_delete_metrics(&mut out);
    out
}

/// [`render_metrics`] for the tests of other modules.
#[cfg(test)]
pub(crate) fn main_render_metrics_for_test() -> String {
    render_metrics()
}
