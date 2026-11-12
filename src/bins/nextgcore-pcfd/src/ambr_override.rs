//! The per-session Session-AMBR override layer (nextgsim#465, owned here and
//! shared by the demos that cap a live session: #470, #477, #484).
//!
//! A demo controller does not rewrite the subscriber's policy data: it records a
//! cap for one SM policy association under its own writer key, and every
//! decision the PCF emits for that association is built from
//! `min(subscription-derived Session-AMBR, every active cap)`. That is what keeps
//! a throttle in force across a subscription-derived re-notify (a UDR
//! policy-data change, a P-CSCF restoration, an SMF `SE_AMBR_CH` report): since
//! #1383 each of those re-reads the UDR, which would otherwise silently undo it.
//!
//! TS 23.503 §6.1.3.2 bounds the authorised Session-AMBR by the subscribed one;
//! a cap can only lower it, never raise it, so the layer cannot violate that.
//!
//! Compiled only with `demo-d441a-congestion-loop`; without it the call sites in
//! `sbi_path` and `app` use the session data unchanged.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use crate::nudr_handler::SessionData;

/// The demos that write this layer. pcfd arbitrates between writers by taking
/// the minimum, which is only meaningful for writers built to share a session;
/// until one is, two active writers fail start-up ([`check_writers`]).
pub const WRITERS: &[&str] = &[crate::congestion_loop::DEMO_KEY];

/// One writer's cap, bits per second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cap {
    pub uplink_bps: u64,
    pub downlink_bps: u64,
}

/// `sm_policy_id` -> writer -> cap.
static CAPS: Mutex<BTreeMap<String, HashMap<&'static str, Cap>>> = Mutex::new(BTreeMap::new());

fn caps() -> std::sync::MutexGuard<'static, BTreeMap<String, HashMap<&'static str, Cap>>> {
    CAPS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Record `writer`'s cap on `sm_policy_id`, replacing its previous one.
pub fn set(sm_policy_id: &str, writer: &'static str, cap: Cap) {
    caps()
        .entry(sm_policy_id.to_string())
        .or_default()
        .insert(writer, cap);
}

/// Drop `writer`'s cap on `sm_policy_id`. True when there was one.
pub fn clear(sm_policy_id: &str, writer: &'static str) -> bool {
    let mut caps = caps();
    let Some(by_writer) = caps.get_mut(sm_policy_id) else {
        return false;
    };
    let had = by_writer.remove(writer).is_some();
    if by_writer.is_empty() {
        caps.remove(sm_policy_id);
    }
    had
}

/// The effective cap on `sm_policy_id`: the minimum over its writers, per
/// direction.
pub fn get(sm_policy_id: &str) -> Option<Cap> {
    caps().get(sm_policy_id).and_then(|by_writer| {
        by_writer.values().copied().reduce(|a, b| Cap {
            uplink_bps: a.uplink_bps.min(b.uplink_bps),
            downlink_bps: a.downlink_bps.min(b.downlink_bps),
        })
    })
}

/// The `sm_policy_id`s `writer` holds a cap on.
pub fn held_by(writer: &'static str) -> Vec<String> {
    caps()
        .iter()
        .filter(|(_, w)| w.contains_key(writer))
        .map(|(id, _)| id.clone())
        .collect()
}

/// `sd` with its Session-AMBR lowered to the active cap on `sm_policy_id`, if
/// any. Never raised: the result is `min(subscribed, cap)`.
pub fn apply(sm_policy_id: &str, sd: &SessionData) -> SessionData {
    let mut out = sd.clone();
    if let Some(cap) = get(sm_policy_id) {
        out.ambr_uplink = out.ambr_uplink.min(cap.uplink_bps);
        out.ambr_downlink = out.ambr_downlink.min(cap.downlink_bps);
    }
    out
}

/// Fail start-up when more than one demo that writes this layer is active.
pub fn check_writers(active: &[&str]) -> Result<(), String> {
    let on: Vec<&str> = WRITERS
        .iter()
        .copied()
        .filter(|w| active.contains(w))
        .collect();
    if on.len() > 1 {
        return Err(format!(
            "demos {on:?} all write pcfd's Session-AMBR override layer, which arbitrates \
             only one writer per process; enable one"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn a_cap_lowers_never_raises_and_clears() {
        let id = "ambr-override-unit-465";
        assert_eq!(
            apply(id, &sd(11_000_000, 22_000_000)),
            sd(11_000_000, 22_000_000)
        );
        set(
            id,
            WRITERS[0],
            Cap {
                uplink_bps: 1_000_000,
                downlink_bps: 50_000_000,
            },
        );
        assert_eq!(
            apply(id, &sd(11_000_000, 22_000_000)),
            sd(1_000_000, 22_000_000),
            "uplink lowered; downlink stays at the subscribed value it is below"
        );
        assert_eq!(held_by(WRITERS[0]), vec![id.to_string()]);
        assert!(clear(id, WRITERS[0]));
        assert!(!clear(id, WRITERS[0]));
        assert_eq!(get(id), None);
    }

    #[test]
    fn two_writers_fail_and_one_is_fine() {
        assert!(check_writers(&[WRITERS[0]]).is_ok());
        assert!(check_writers(&[]).is_ok());
    }
}
