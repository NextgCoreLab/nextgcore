//! NextGCore UPF (User Plane Function), as a library (#2208): the data plane,
//! the PFCP server and the apply of its session events, so another crate's tests
//! can run a UPF in-process. The `nextgcore-upfd` binary is this library plus its
//! command line, metrics and NRF registration (`main.rs`).
//!
//! Port of src/upf/ - User Plane Function for 5G/LTE core network
//!
//! The UPF is responsible for:
//! - User plane packet routing and forwarding
//! - QoS handling
//! - Traffic usage reporting
//! - Uplink/downlink traffic detection

// `dead_code` is `allow` workspace-wide (`Cargo.toml`, "Future-use code for
// Rel-17/18/20 features"), and #335 asked whether that is what hid two parallel
// models in `context.rs`. Measured: it is not. At `warn` the workspace emits 277
// warnings and upfd emits NONE of them, because the lint does not fire on a `pub`
// item — a `pub fn` added to `context.rs` warns not at all, while the same
// function written `pub(crate)` warns immediately. So the blind spot is
// visibility, not the lint level, and `pub mod` is what created it: it gives
// every item inside an effective visibility of `pub`, in a crate that has no
// external consumers to be `pub` FOR.
//
// `mod context` (crate-private) drops those items to an effective `pub(crate)`,
// which the lint does cover, and the local level re-enables it over the workspace
// `allow`. Together they are what would have caught #325 and #335. Verified by
// probe: a `pub(crate)` method with no caller now fails the build here; before
// this change it was silent.
//
// `deny` and not `warn`, because CI runs `cargo clippy --workspace` with no
// `-D warnings` ("Gate on errors only", `.github/workflows/ci.yml`) -- a `warn`
// here would print into a log nobody reads and gate nothing, which is the same
// mistake as the retry that hid a 20% flake (#308). At `deny` this crate is at
// zero today, so the gate costs nothing to adopt, and future-use code has to say
// what it is waiting for in an `#[allow(dead_code)]` reason rather than resting on
// a workspace-wide blanket -- which is #335's option 2, enforced instead of asked
// for. Scoped to upfd: the workspace has 277 such items, 121 of them in smfd's
// tracked #223, so a workspace sweep is a different change.
#![deny(dead_code)]

pub mod arp_nd;
mod context;
pub mod data_plane;
pub mod event;
pub mod gtp_path;
pub mod mcast;
pub mod n4_build;
pub mod n4_handler;
pub mod n6_delay;
pub mod nat_exclude;
pub mod path_qos;
pub mod pfcp_dup;
pub mod pfcp_path;
pub mod pfcp_sm;
pub mod programmable_plane;
pub mod qos_flow_mon;
pub mod rule_match;
pub mod session_metrics;
pub mod timer;
pub mod transport_delay;
pub mod tsn_bridge;
pub mod upf_sm;

#[cfg(test)]
mod property_tests;
pub mod runtime;
pub mod session_apply;

pub use context::{upf_context_final, upf_context_init, upf_self};
pub use session_apply::handle_pfcp_session_event;
