//! NAS-level congestion control posture (TS 24.501 §5.3.5)
//!
//! The AMF's only NAS-level overload defence is to reject a request with 5GMM cause #22
//! ("congestion") and a T3346 back-off, so the UE waits instead of retrying immediately.
//! Without it a congested core cannot shed load gracefully: every refused UE comes
//! straight back.
//!
//! # What counts as congested
//!
//! Two independent sources, either sufficient:
//!
//! - **Occupancy.** The registered-UE count against `AMF_NAS_CONGESTION_THRESHOLD`.
//!   `0`, the default, means never — so the shipped behaviour is unchanged.
//! - **An operator declaration.** `AMF_NAS_CONGESTION=1` forces the posture on, for a
//!   drill or while a real overload is being investigated by hand.
//!
//! Both are runtime values, not cargo features: a feature-gated congestion path would
//! sit outside `cargo test --workspace`, which is this repo's CI gate, and so would ship
//! uncompiled.
//!
//! # What is deliberately NOT here
//!
//! The back-off is a fixed configured value, identical for every UE. TS 24.008
//! §10.5.7.4a's guidance is to spread retries so a fleet does not return in lockstep,
//! which wants per-UE jitter. That is a design choice about fairness rather than a
//! conformance requirement, it makes the value untestable without injecting a clock or a
//! seed, and #72's criterion asks only that the back-off be carried. Left out
//! deliberately rather than half-done.

use std::sync::atomic::{AtomicBool, Ordering};

/// Operator-forced congestion, independent of occupancy.
static FORCED: AtomicBool = AtomicBool::new(false);

/// The ONE lock over this module's process-global posture and the environment variables
/// it reads.
///
/// Declared here, beside the state it guards, so tests in OTHER modules take the same one
/// — `ngap_path`'s congestion test forces the posture too, and a lock private to this
/// file's `mod tests` could not order against it. #346 is the same defect in nssfd: three
/// guards over one global, none of which ordered against the others.
#[cfg(test)]
pub(crate) static CONGESTION_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serialise on [`CONGESTION_TEST_LOCK`] and hand the caller a known-clean posture.
#[cfg(test)]
pub(crate) fn congestion_test_guard() -> std::sync::MutexGuard<'static, ()> {
    let guard = CONGESTION_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    set_forced(false);
    std::env::remove_var("AMF_NAS_CONGESTION");
    std::env::remove_var("AMF_NAS_CONGESTION_THRESHOLD");
    std::env::remove_var("AMF_T3346_SECS");
    guard
}

/// Default T3346 when congestion is active and `AMF_T3346_SECS` is unset.
///
/// 60 s: long enough to matter as load shedding, short enough that a UE refused during a
/// transient is not stranded. TS 24.501 fixes no value.
const DEFAULT_T3346_SECS: u64 = 60;

/// Force the congestion posture on or off (operator declaration / tests).
///
/// Returns the previous value, so a test can restore it and not leak the posture into
/// its siblings — this is process-global state.
pub fn set_forced(active: bool) -> bool {
    FORCED.swap(active, Ordering::SeqCst)
}

/// Whether an operator has forced the posture on.
pub fn is_forced() -> bool {
    FORCED.load(Ordering::SeqCst) || env_flag("AMF_NAS_CONGESTION")
}

/// The registered-UE count above which the AMF declares NAS congestion.
///
/// `None` when unset or 0 — congestion by occupancy is off, which is the shipped default.
pub fn occupancy_threshold() -> Option<usize> {
    match std::env::var("AMF_NAS_CONGESTION_THRESHOLD") {
        Ok(raw) => match raw.trim().parse::<usize>() {
            Ok(0) => None,
            Ok(v) => Some(v),
            Err(e) => {
                log::warn!(
                    "AMF_NAS_CONGESTION_THRESHOLD={raw:?} is not a UE count ({e}); \
                     congestion by occupancy stays off"
                );
                None
            }
        },
        Err(_) => None,
    }
}

/// Whether the AMF is currently under NAS-level congestion, given `registered_ues`.
///
/// The count is passed in rather than read here so this stays a pure decision: the
/// caller already holds the context lock, and taking it again inside would invert a lock
/// order for no reason.
pub fn is_active(registered_ues: usize) -> bool {
    if is_forced() {
        return true;
    }
    occupancy_threshold().is_some_and(|threshold| registered_ues >= threshold)
}

/// The T3346 back-off in seconds to impose while congested.
pub fn backoff_secs() -> u64 {
    match std::env::var("AMF_T3346_SECS") {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(v) => v,
            Err(e) => {
                log::warn!(
                    "AMF_T3346_SECS={raw:?} is not a number of seconds ({e}); using \
                     {DEFAULT_T3346_SECS}s"
                );
                DEFAULT_T3346_SECS
            }
        },
        Err(_) => DEFAULT_T3346_SECS,
    }
}

/// The traffic reduction to ask gNBs for in an NGAP Overload Start while congested.
pub fn ngap_reduce_percent() -> u8 {
    std::env::var("AMF_OVERLOAD_REDUCE_PERCENT")
        .ok()
        .and_then(|raw| raw.trim().parse::<u8>().ok())
        .map(|v| v.min(100))
        .unwrap_or(50)
}

fn env_flag(var: &str) -> bool {
    std::env::var(var)
        .map(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes" | "on"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::congestion_test_guard as guard;

    #[test]
    fn the_shipped_default_is_never_congested() {
        let _g = guard();
        assert!(!is_active(0));
        assert!(
            !is_active(1_000_000),
            "with no threshold configured, no occupancy is congestion"
        );
    }

    #[test]
    fn occupancy_crosses_at_the_threshold_not_past_it() {
        let _g = guard();
        std::env::set_var("AMF_NAS_CONGESTION_THRESHOLD", "10");
        assert!(!is_active(9));
        assert!(is_active(10), "the threshold itself is congested");
        assert!(is_active(11));
        std::env::remove_var("AMF_NAS_CONGESTION_THRESHOLD");
    }

    #[test]
    fn a_forced_posture_ignores_occupancy() {
        let _g = guard();
        let previous = set_forced(true);
        assert!(is_active(0), "a declaration does not need a UE count");
        set_forced(previous);
        assert!(!is_active(0));
    }

    #[test]
    fn an_unparseable_threshold_leaves_congestion_off() {
        let _g = guard();
        std::env::set_var("AMF_NAS_CONGESTION_THRESHOLD", "lots");
        assert!(
            !is_active(1_000_000),
            "a typo must not silently enable load shedding"
        );
        std::env::remove_var("AMF_NAS_CONGESTION_THRESHOLD");
    }

    #[test]
    fn the_backoff_is_configurable_and_defaults() {
        let _g = guard();
        assert_eq!(backoff_secs(), DEFAULT_T3346_SECS);
        std::env::set_var("AMF_T3346_SECS", "600");
        assert_eq!(backoff_secs(), 600);
        std::env::set_var("AMF_T3346_SECS", "not-a-number");
        assert_eq!(
            backoff_secs(),
            DEFAULT_T3346_SECS,
            "an unparseable value falls back rather than becoming 0, which would mean \
             'deactivated' on the wire"
        );
        std::env::remove_var("AMF_T3346_SECS");
    }
}
