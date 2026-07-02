//! NextGCore AUSF (Authentication Server Function) binary entrypoint.
//!
//! All AUSF logic lives in the `nextgcore_ausfd` library crate (Wave-6 H1
//! lib-targetization) so peer NF crates can drive the real
//! `ausf_sbi_request_handler` in-process from strict-peer integration tests;
//! this binary is a thin wrapper around [`nextgcore_ausfd::run`].

fn main() -> anyhow::Result<()> {
    nextgcore_ausfd::run()
}
