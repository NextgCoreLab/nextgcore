//! NextGCore PCF (Policy Control Function) Library
//!
//! The PCF module tree lives in this library crate (Wave-6 H1
//! lib-targetization, mirroring nextgcore-udrd/udmd) so that:
//! - the `nextgcore-pcfd` binary consumes it like any other crate, and
//! - peer NF crates and this package's own integration tests can call the
//!   real builders (e.g. [`sbi_path::build_pcf_binding_body`]) in-process
//!   for strict-peer tests instead of hand-rolled lenient mocks.

pub mod am_sm;
/// Daemon entrypoint + SBI request handlers, moved verbatim from the former
/// `main.rs` for Wave-6 H1 lib-targetization; the binary is now a thin wrapper
/// around [`app::run`]. Peer NF crates drive `pcf_sbi_request_handler` (and the
/// AM/SM/UE-policy sub-handlers below) in-process for strict-peer tests.
pub mod app;
pub mod context;
pub mod event;
/// Issue #24: intent-driven closed-loop policy controller (non-normative 6G
/// research spike, off by default). Crate-internal like `intent_policy`; the
/// `pcf.intent` YAML block + `--features intent-loop` activate it.
#[cfg(feature = "intent-loop")]
pub(crate) mod intent_loop;
/// Intent-policy translation (TS 28.312-inspired research scaffolding),
/// consumed by the feature-gated `intent_loop` controller (issue #24). Kept
/// crate-internal (mirrors udrd's non-public `nudr_handler` precedent) and
/// NOT part of the public crate API. Without the `intent-loop` feature
/// nothing references it; the conditional allowance documents that intent —
/// the workspace-wide `dead_code = "allow"` (src/Cargo.toml) already
/// suppresses the lint in both configurations.
#[cfg_attr(not(feature = "intent-loop"), allow(dead_code))]
mod intent_policy;
pub mod npcf_eventexposure; // TS 29.523: policy-control event exposure
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
    pcf_register_bsf_binding, pcf_self_info, pcf_self_info_set, pcf_sess_update_bsf_binding,
    pcf_update_bsf_binding, PcfSelfInfo,
};
pub use sm_policy_build::{build_sm_policy_decision, SmPolicyDecisionParts};

// Wave-6 H1: expose the real SBI request handler + the sub-handlers peer NF
// crates drive for strict-peer tests (UE-policy create, SM-policy create/
// update-notify, AM-policy create), plus `run`.
pub use app::{
    handle_am_policy_create, handle_sm_policy_create, handle_sm_policy_update_notify,
    handle_ue_policy_create, pcf_sbi_request_handler, run,
};

// #92: the UE-policy handlers whose behaviour the serving-AMF / callback tests drive
// end to end — the update must NOTIFY the consumer, the delete must terminate-notify,
// and the CM-state callback must retry a parked delivery rather than let it die.
// Exported for the same reason the create handler above is: the tests assert what the
// REAL handler does, not what a reimplementation of it would do.
pub use app::{
    handle_ue_policy_connectivity_notify, handle_ue_policy_delete,
    handle_ue_policy_delivery_failure, handle_ue_policy_update,
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

    /// Point the process-global NRF URI at a test's mock, dropping every cached SBI
    /// client first (#529).
    ///
    /// The client cache (`nextgcore_sbi::context::global_context`) is process-global and
    /// keyed by host:port, but each cached client's HTTP/2 connection is driven by a task
    /// on the tokio runtime that FIRST used it -- and every `#[tokio::test]` has its own
    /// runtime. A client another test created toward this mock dies with that test's
    /// runtime, and the next request through it fails with "dispatch task is gone":
    /// `a_change_for_one_slice_does_not_reauthorise_another_slices_session` saw exactly
    /// that on its NRF discovery, so nothing was re-authorised. Clearing here means the
    /// clients a test uses are created on its own runtime. Call it with
    /// [`CONTEXT_GUARD`] held, as every test that touches the NRF URI must.
    pub async fn point_nrf_at(uri: impl Into<String>) {
        let ctx = nextgcore_sbi::context::global_context();
        ctx.clear_clients().await;
        ctx.set_nrf_uri(uri).await;
    }

    /// `PCF_UE_POLICY_DELIVERY` pinned to `enabled` for as long as the returned guard
    /// lives (#541). Holds [`crate::ue_policy::DELIVERY_ENV_LOCK`], so no other test can
    /// change the variable underneath the holder, and restores the previous value on
    /// drop. Every test that sets the variable, or whose assertions depend on delivery
    /// being on or off, takes one of these instead of calling `std::env::set_var`.
    pub fn ue_policy_delivery(enabled: bool) -> UePolicyDeliveryEnv {
        let guard = crate::ue_policy::DELIVERY_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let previous = std::env::var_os(crate::ue_policy::DELIVERY_ENV);
        std::env::set_var(
            crate::ue_policy::DELIVERY_ENV,
            if enabled { "on" } else { "off" },
        );
        UePolicyDeliveryEnv {
            previous,
            _guard: guard,
        }
    }

    /// Guard returned by [`ue_policy_delivery`].
    pub struct UePolicyDeliveryEnv {
        previous: Option<std::ffi::OsString>,
        // Declared last so it drops after `Drop::drop` has restored the variable.
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for UePolicyDeliveryEnv {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(v) => std::env::set_var(crate::ue_policy::DELIVERY_ENV, v),
                None => std::env::remove_var(crate::ue_policy::DELIVERY_ENV),
            }
        }
    }
}
