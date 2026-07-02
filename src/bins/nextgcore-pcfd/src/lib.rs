//! NextGCore PCF (Policy Control Function) Library
//!
//! The PCF module tree lives in this library crate (Wave-6 H1
//! lib-targetization, mirroring nextgcore-udrd/udmd) so that:
//! - the `nextgcore-pcfd` binary consumes it like any other crate, and
//! - peer NF crates and this package's own integration tests can call the
//!   real builders (e.g. [`sbi_path::build_pcf_binding_body`]) in-process
//!   for strict-peer tests instead of hand-rolled lenient mocks.

/// Daemon entrypoint + SBI request handlers, moved verbatim from the former
/// `main.rs` for Wave-6 H1 lib-targetization; the binary is now a thin wrapper
/// around [`app::run`]. Peer NF crates drive `pcf_sbi_request_handler` (and the
/// AM/SM/UE-policy sub-handlers below) in-process for strict-peer tests.
pub mod app;
pub mod am_sm;
pub mod context;
pub mod event;
/// Future-use intent-policy translation (Rel-20 research scaffolding): not
/// wired to any live handler, kept crate-internal (mirrors udrd's non-public
/// `nudr_handler` precedent) and NOT part of the public crate API.
#[allow(dead_code)]
mod intent_policy;
pub mod npcf_handler;
pub mod nudr_handler;
pub mod pcf_sm;
pub mod sbi_path;
pub mod sbi_response;
pub mod sm_policy_build;
pub mod sm_sm;
pub mod timer;
pub mod ue_policy; // Rel-16: URSP rule provisioning (TS 23.503)

// Re-export the WSB-1/H2 strict-peer surface (PcfBinding body builder and
// the PCF self identity it reads) and the shared SM policy decision builder.
pub use sbi_path::{
    build_pcf_binding_body, build_pcf_binding_body_with, pcf_deregister_bsf_binding,
    pcf_register_bsf_binding, pcf_self_info, pcf_self_info_set, PcfSelfInfo,
};
pub use sm_policy_build::{build_sm_policy_decision, SmPolicyDecisionParts};

// Wave-6 H1: expose the real SBI request handler + the sub-handlers peer NF
// crates drive for strict-peer tests (UE-policy create, SM-policy create/
// update-notify, AM-policy create), plus `run`.
pub use app::{
    handle_am_policy_create, handle_sm_policy_create, handle_sm_policy_update_notify,
    handle_ue_policy_create, pcf_sbi_request_handler, run,
};

/// Helpers for in-process strict-peer tests in *other* crates. Not gated behind
/// `#[cfg(test)]` because cfg(test) items are invisible across crate
/// boundaries; a dev-dependency test in a peer crate must seed the
/// process-global PCF context.
pub mod test_support {
    use std::sync::Mutex;

    /// Process-wide lock so strict-peer tests that touch the global PCF context
    /// run serially (the PCF context is process-global; parallel tests race).
    pub static CONTEXT_GUARD: Mutex<()> = Mutex::new(());

    /// Initialize the process-global PCF context for in-process strict-peer
    /// tests (wraps [`crate::context::pcf_context_init`] with test capacities).
    pub fn init_context() {
        crate::context::pcf_context_init(64, 64);
    }
}
