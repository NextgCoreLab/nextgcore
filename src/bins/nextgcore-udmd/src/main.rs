//! NextGCore UDM (Unified Data Management) binary entrypoint.
//!
//! All UDM logic lives in the `nextgcore_udmd` library crate (Wave-6 H1
//! lib-targetization) so peer NF crates can drive the real
//! `udm_sbi_request_handler` in-process from strict-peer integration tests;
//! this binary is a thin wrapper around [`nextgcore_udmd::run`].

fn main() -> anyhow::Result<()> {
    nextgcore_udmd::run()
}
