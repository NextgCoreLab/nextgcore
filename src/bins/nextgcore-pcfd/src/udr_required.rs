//! The operator setting `pcf.policy.udr_required` (#1639, operator decision of
//! 2026-11-17): what a policy create does when an NRF is configured, the NRF does
//! not answer the UDR discovery, and the PCF has no UDR to fall back on.
//!
//! After #1621 a create reads the UDR the NRF lists, or the one remembered from an
//! earlier discovery (TS 29.510 Table 6.2.6.2.2-1 `validityPeriod`) when the NRF
//! fails. One case is left with no basis either way: nothing is remembered (the
//! PCF never discovered a UDR since start-up, or what it learned has expired) and
//! the NRF gives no answer. TS 29.512 §4.2.2.2 and TS 29.507 are silent on it; it
//! is availability against policy enforcement, so it is the operator's:
//!
//! - `true`: the create is refused, 500 SYSTEM_FAILURE (TS 29.500 Table
//!   5.2.7.2-1), as for a UDR outage (#1597, #1613). The production Helm chart and
//!   the Kubernetes manifests the EKS profiles build on state it.
//! - `false` (the default when absent, the behaviour before #1639): the local
//!   default policy applies. The compose, dev and demo configs state it.
//!
//! An NRF whose last answer was that no UDR is deployed (it listed none, or the
//! remembered UDR's NFProfile is gone, #1653) is a basis: the local default
//! applies under both values. So is having no NRF configured at all. Emergency DNs
//! never read the UDR (TS 29.512 §4.2.2.2, `pcf.policy.emergency_dnns`), so this
//! setting cannot refuse an emergency session.
//!
//! Anything but a YAML boolean is an error, and start-up fails on it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// The value when `pcf.policy.udr_required` is absent: today's local default.
pub const DEFAULT: bool = false;

/// The setting in force. Written once at start-up ([`set`]), read on every
/// create-path UDR read.
static UDR_REQUIRED: AtomicBool = AtomicBool::new(DEFAULT);

/// Serialises tests that change [`UDR_REQUIRED`] or whose assertions depend on
/// it. Taken through [`crate::test_support::udr_required`].
pub static UDR_REQUIRED_LOCK: Mutex<()> = Mutex::new(());

/// The setting in force.
pub fn get() -> bool {
    UDR_REQUIRED.load(Ordering::Relaxed)
}

/// Put `required` in force.
pub fn set(required: bool) {
    UDR_REQUIRED.store(required, Ordering::Relaxed);
}

/// The setting a config root states: `pcf.policy.udr_required`, [`DEFAULT`] when
/// absent or null. A value that is not a YAML boolean (`"true"`, `yes`, `1`) is an
/// error: a misspelt setting silently left at `false` would leave a production
/// operator believing creates fail closed when they do not.
pub fn from_config_root(root: &serde_yaml::Value) -> Result<bool, String> {
    let Some(v) = root
        .get("pcf")
        .and_then(|p| p.get("policy"))
        .and_then(|p| p.get("udr_required"))
    else {
        return Ok(DEFAULT);
    };
    if v.is_null() {
        return Ok(DEFAULT);
    }
    v.as_bool()
        .ok_or_else(|| format!("pcf.policy.udr_required: {v:?} is not true or false"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(yaml: &str) -> serde_yaml::Value {
        serde_yaml::from_str(yaml).unwrap()
    }

    /// #1639: a YAML boolean, `false` when absent; anything else fails start-up.
    #[test]
    fn the_setting_is_a_yaml_boolean_1639() {
        assert_eq!(from_config_root(&serde_yaml::Value::Null), Ok(false));
        assert_eq!(from_config_root(&root("pcf: {}")), Ok(false));
        assert_eq!(
            from_config_root(&root("pcf: { policy: { session_ambr_cap: none } }")),
            Ok(false)
        );
        assert_eq!(
            from_config_root(&root("pcf: { policy: { udr_required: ~ } }")),
            Ok(false)
        );
        assert_eq!(
            from_config_root(&root("pcf: { policy: { udr_required: true } }")),
            Ok(true)
        );
        assert_eq!(
            from_config_root(&root("pcf: { policy: { udr_required: false } }")),
            Ok(false)
        );
        for bad in [
            "\"true\"", "yes", "on", "1", "0", "[true]", "{}", "required",
        ] {
            let err = from_config_root(&root(&format!(
                "pcf: {{ policy: {{ udr_required: {bad} }} }}"
            )))
            .expect_err(bad);
            assert!(err.contains("pcf.policy.udr_required"), "{bad}: {err}");
        }
    }
}
