//! NextGCore BSF (Binding Support Function) binary entrypoint.
//!
//! All BSF logic lives in the `nextgcore_bsfd` library crate (Wave-6 H1
//! lib-targetization) so strict-peer integration tests can drive the real
//! SBI request handler in-process; this binary is a thin wrapper.

fn main() -> anyhow::Result<()> {
    nextgcore_bsfd::run()
}
