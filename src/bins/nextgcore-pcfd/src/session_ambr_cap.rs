//! The operator setting `pcf.policy.session_ambr_cap` (#1402): whether the
//! subscribed Session-AMBR the SMF reports (`subsSessAmbr`) caps the Session-AMBR
//! this PCF authorises.
//!
//! TS 29.512 §4.2.2.5 has the PCF authorise the Session-AMBR "based on the
//! operator's policy", and §4.2.3.5 lets it modify that value at any time; neither
//! makes the subscribed value a ceiling outside home-routed roaming. So the cap is
//! operator policy, and this setting is where the operator states it:
//!
//! - `subscribed` (the default): per direction, `min(policy, subsSessAmbr)`;
//! - `none`: the policy value, unbounded by the subscription.
//!
//! One setting, applied by [`apply`] on every path that authorises a
//! Session-AMBR: the SM policy create, the UpdateNotify (and the GET that answers
//! the decision in force), and the `SE_AMBR_CH` update. Before #1402 only the
//! `SE_AMBR_CH` arm applied the cap, so the three paths disagreed.
//!
//! The home-routed-roaming bound (TS 29.512 §4.2.2.5, §4.2.3.5, §4.2.4.4; TS 23.503
//! §6.1.3.6: the H-PCF ensures the authorised value does not exceed the VPLMN's) is
//! not this setting: it would apply whatever the setting says. pcfd does not
//! implement it today; it negotiates no VPLMN-QoS-Control (TS 29.512 Table 5.8-1
//! feature 49), so no SMF sends it a `vplmnQos` to bound by.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;

use crate::context::Ambr;
use crate::nudr_handler::SessionData;
use crate::sm_policy_build::parse_bitrate;

/// The values `pcf.policy.session_ambr_cap` takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionAmbrCap {
    /// Per direction, `min(policy, subsSessAmbr)`.
    #[default]
    Subscribed,
    /// The policy value, unbounded by the subscription.
    None,
}

impl SessionAmbrCap {
    /// The config spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            SessionAmbrCap::Subscribed => "subscribed",
            SessionAmbrCap::None => "none",
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            SessionAmbrCap::Subscribed => 0,
            SessionAmbrCap::None => 1,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            1 => SessionAmbrCap::None,
            _ => SessionAmbrCap::Subscribed,
        }
    }
}

/// The setting in force. Written once at start-up ([`set`]), read on every
/// authorisation.
static SESSION_AMBR_CAP: AtomicU8 = AtomicU8::new(0);

/// Serialises tests that change [`SESSION_AMBR_CAP`] or whose assertions depend on
/// it. Taken through [`crate::test_support::session_ambr_cap`].
pub static SESSION_AMBR_CAP_LOCK: Mutex<()> = Mutex::new(());

/// The setting in force.
pub fn get() -> SessionAmbrCap {
    SessionAmbrCap::from_u8(SESSION_AMBR_CAP.load(Ordering::Relaxed))
}

/// Put `cap` in force.
pub fn set(cap: SessionAmbrCap) {
    SESSION_AMBR_CAP.store(cap.to_u8(), Ordering::Relaxed);
}

/// The setting a config root states: `pcf.policy.session_ambr_cap`, the default
/// when absent. A value other than `subscribed` or `none`, a `pcf.policy` that is
/// not a mapping, or an unknown key in it is an error, and start-up fails on it: a
/// misspelt setting silently left at the default would leave the operator believing
/// the cap was off (or on) when it is not.
pub fn from_config_root(root: &serde_yaml::Value) -> Result<SessionAmbrCap, String> {
    let Some(policy) = root.get("pcf").and_then(|p| p.get("policy")) else {
        return Ok(SessionAmbrCap::default());
    };
    if policy.is_null() {
        return Ok(SessionAmbrCap::default());
    }
    let Some(map) = policy.as_mapping() else {
        return Err("pcf.policy must be a mapping".to_string());
    };
    for key in map.keys() {
        match key.as_str() {
            Some("session_ambr_cap") => {}
            other => {
                return Err(format!(
                    "pcf.policy: unknown key {other:?} (known: session_ambr_cap)"
                ))
            }
        }
    }
    match map.get("session_ambr_cap") {
        None => Ok(SessionAmbrCap::default()),
        Some(v) => match v.as_str() {
            Some("subscribed") => Ok(SessionAmbrCap::Subscribed),
            Some("none") => Ok(SessionAmbrCap::None),
            _ => Err(format!(
                "pcf.policy.session_ambr_cap: {v:?} is not one of \"subscribed\", \"none\""
            )),
        },
    }
}

/// `sd` with its Session-AMBR capped by `subscribed` per the setting in force.
///
/// Under `subscribed`, each direction is `min(policy, subscribed)`, independently:
/// a subscription that lowers only the uplink leaves the downlink alone. A
/// direction whose subscribed value does not parse is left at the policy value
/// rather than read as zero, which would police the subscriber to a standstill
/// (`parse_subs_sess_ambr` already refuses such a value whole, so this is a
/// second line). No subscribed value, or the setting `none`: `sd` unchanged.
pub fn apply(sd: &SessionData, subscribed: Option<&Ambr>) -> SessionData {
    let mut out = sd.clone();
    if get() == SessionAmbrCap::None {
        return out;
    }
    if let Some(subs) = subscribed {
        if let Some(ul) = parse_bitrate(&subs.uplink) {
            out.ambr_uplink = out.ambr_uplink.min(ul);
        }
        if let Some(dl) = parse_bitrate(&subs.downlink) {
            out.ambr_downlink = out.ambr_downlink.min(dl);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(y: &str) -> serde_yaml::Value {
        serde_yaml::from_str(y).unwrap()
    }

    fn sd(ul: u64, dl: u64) -> SessionData {
        SessionData {
            qos_index: 9,
            arp_priority_level: 8,
            arp_preempt_cap: false,
            arp_preempt_vuln: true,
            ambr_uplink: ul,
            ambr_downlink: dl,
            pcc_rules: vec![],
        }
    }

    fn ambr(ul: &str, dl: &str) -> Ambr {
        Ambr {
            uplink: ul.to_string(),
            downlink: dl.to_string(),
        }
    }

    #[test]
    fn the_default_is_subscribed() {
        assert_eq!(SessionAmbrCap::default(), SessionAmbrCap::Subscribed);
        assert_eq!(
            from_config_root(&serde_yaml::Value::Null),
            Ok(SessionAmbrCap::Subscribed)
        );
        assert_eq!(
            from_config_root(&root("pcf:\n  sbi: {}\n")),
            Ok(SessionAmbrCap::Subscribed)
        );
        assert_eq!(
            from_config_root(&root("pcf:\n  policy:\n")),
            Ok(SessionAmbrCap::Subscribed)
        );
        assert_eq!(
            from_config_root(&root("pcf:\n  policy: {}\n")),
            Ok(SessionAmbrCap::Subscribed)
        );
    }

    #[test]
    fn both_values_parse() {
        assert_eq!(
            from_config_root(&root("pcf:\n  policy:\n    session_ambr_cap: subscribed\n")),
            Ok(SessionAmbrCap::Subscribed)
        );
        assert_eq!(
            from_config_root(&root("pcf:\n  policy:\n    session_ambr_cap: none\n")),
            Ok(SessionAmbrCap::None)
        );
    }

    #[test]
    fn an_unknown_value_or_key_is_an_error() {
        for bad in [
            "pcf:\n  policy:\n    session_ambr_cap: Subscribed\n",
            "pcf:\n  policy:\n    session_ambr_cap: off\n",
            "pcf:\n  policy:\n    session_ambr_cap: 1\n",
            "pcf:\n  policy:\n    session_ambr_cap: ~\n",
            "pcf:\n  policy:\n    session_ambr_cap: [none]\n",
            "pcf:\n  policy:\n    session_ambr_ceiling: none\n",
            "pcf:\n  policy: none\n",
        ] {
            let err = from_config_root(&root(bad)).expect_err(bad);
            assert!(err.starts_with("pcf.policy"), "{bad}: {err}");
        }
    }

    #[test]
    fn apply_caps_per_direction_under_subscribed_and_not_under_none() {
        let cap = crate::test_support::session_ambr_cap(SessionAmbrCap::Subscribed);
        let p = sd(11_000_000, 22_000_000);
        assert_eq!(apply(&p, None), p, "no subscribed value: unchanged");
        assert_eq!(
            apply(&p, Some(&ambr("50 Mbps", "50 Mbps"))),
            p,
            "above: policy"
        );
        assert_eq!(
            apply(&p, Some(&ambr("5 Mbps", "7 Mbps"))),
            sd(5_000_000, 7_000_000),
            "below: subscribed"
        );
        assert_eq!(apply(&p, Some(&ambr("11 Mbps", "22 Mbps"))), p, "equal");
        assert_eq!(
            apply(&p, Some(&ambr("5 Mbps", "50 Mbps"))),
            sd(5_000_000, 22_000_000),
            "one direction above: each direction on its own"
        );
        assert_eq!(
            apply(&p, Some(&ambr("fast", "7 Mbps"))),
            sd(11_000_000, 7_000_000),
            "an unparseable direction is no bound, not a zero"
        );
        drop(cap);

        let _cap = crate::test_support::session_ambr_cap(SessionAmbrCap::None);
        assert_eq!(apply(&p, Some(&ambr("5 Mbps", "7 Mbps"))), p);
    }
}
