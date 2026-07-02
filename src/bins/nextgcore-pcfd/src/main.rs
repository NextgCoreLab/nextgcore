//! NextGCore PCF (Policy Control Function) binary entrypoint.
//!
//! All PCF logic lives in the `nextgcore_pcfd` library crate (Wave-6 H1
//! lib-targetization) so peer NF crates can drive the real
//! `pcf_sbi_request_handler` in-process from strict-peer integration tests;
//! this binary is a thin wrapper around [`nextgcore_pcfd::run`].

fn main() -> anyhow::Result<()> {
    nextgcore_pcfd::run()
}
