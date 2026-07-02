//! NextGCore AMF (Access and Mobility Management Function) binary entrypoint.
//!
//! All AMF logic lives in the `nextgcore_amfd` library crate (Wave-6 H1
//! lib-targetization) so peer NF crates can drive the real Namf SBI request
//! handler in-process from strict-peer integration tests; this binary is a
//! thin wrapper around [`nextgcore_amfd::run`].

fn main() -> anyhow::Result<()> {
    nextgcore_amfd::run()
}
