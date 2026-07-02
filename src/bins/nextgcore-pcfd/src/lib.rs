//! NextGCore PCF (Policy Control Function) Library
//!
//! The PCF module tree lives in this library crate (Wave-6 H1
//! lib-targetization, mirroring nextgcore-udrd/udmd) so that:
//! - the `nextgcore-pcfd` binary consumes it like any other crate, and
//! - peer NF crates and this package's own integration tests can call the
//!   real builders (e.g. [`sbi_path::build_pcf_binding_body`]) in-process
//!   for strict-peer tests instead of hand-rolled lenient mocks.

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
