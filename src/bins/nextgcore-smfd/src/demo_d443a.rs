//! nextgsim#471 (demo `d443a-edge-budget`), the SMF side: the N6 delays this SMF
//! holds for a session's PSA UPF, carried to the QOS_MON consumer.
//!
//! # What it adds
//! With the `demo-d443a-edge-budget` cargo feature built **and** the `demo:`
//! block on (any mode), every QOS_MON `NsmfEventExposureNotification` this SMF
//! sends also carries, in its `EventNotification`, the latest N6 delay results
//! of the session's PSA UPF (the #1502 store, `n6_delay`):
//!
//! ```json
//! "vendorSpecific-032473": { "n6Delays": [ { "endpoint": "10.60.0.11", "avgMs": 8, "minMs": 7, "maxMs": 9 } ] }
//! ```
//!
//! # Why a vendor-specific member
//! TS 29.508 has no N6 member in `EventNotification` (§4.2.3.2 item 12 carries
//! only the per QoS flow `ulDelays`/`dlDelays`/`rtDelays`), and TS 23.501
//! §5.8.2.23 gives N6 delay to the SMF for PSA UPF (re)selection and EAS
//! (re)discovery, not for exposure. Exposing it is therefore non-normative. TS
//! 29.500 §6.6.3 is the one sanctioned way to extend a 3GPP JSON object:
//! a member named `vendorSpecific-nnnnnn`, nnnnnn the IANA Private Enterprise
//! Number. NextgCoreLab has no PEN, so the member uses **32473**, the PEN that
//! RFC 5612 reserves for documentation and examples: it can collide with no real
//! vendor's member, and it says plainly that this is not a registered extension.
//! `EventNotification` sets no `additionalProperties: false`
//! (`TS29508_Nsmf_EventExposure.yaml`), so a conformant consumer ignores it.
//!
//! # Off
//! A default build has no such module; a build with the feature but the demo off
//! sends the notification it sent before, byte for byte (see the tests).

use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Value;

/// The demo key (nextgsim#458 convention).
pub const DEMO_KEY: &str = "d443a-edge-budget";
/// The modes, shared with eesd and the UE. The SMF behaves the same in both: the
/// mode selects the EES's ranking, not what the SMF exposes.
pub const MODES: &[&str] = &["measured-budget", "static"];

/// What this binary registers under the `demo-d443a-edge-budget` feature.
pub const DEMO_SPEC: nextgcore_demo::DemoSpec = nextgcore_demo::DemoSpec {
    key: DEMO_KEY,
    modes: MODES,
    requires: &[],
};

/// The TS 29.500 §6.6.3 vendor-specific member (PEN 32473, RFC 5612).
pub const VENDOR_MEMBER: &str = "vendorSpecific-032473";

/// Whether the demo is on in this process. Set once at startup from the installed
/// demo state; tests set it under [`TEST_LOCK`].
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Serialises the tests that set [`ACTIVE`]. Declared beside it (one lock per
/// process-global). Taken after `PROCESS_STATE_TEST_LOCK`, `qos_mon::TEST_LOCK`
/// and `n6_delay::N6_TEST_LOCK`.
#[cfg(test)]
pub(crate) static TEST_LOCK: crate::context::TestLock = crate::context::TestLock::new();

/// Install the startup decision: `mode` is the demo's active mode, if any.
pub fn install(mode: Option<&str>) {
    ACTIVE.store(mode.is_some(), Ordering::SeqCst);
    if let Some(mode) = mode {
        nextgcore_demo::demo_log!(
            warn,
            DEMO_KEY,
            "mode={mode}: QOS_MON notifications carry the PSA UPF's N6 delays in \
             {VENDOR_MEMBER}.n6Delays (non-normative: TS 29.508 has no N6 member)"
        );
    }
}

/// Test only: set the decision without the banner.
#[cfg(test)]
pub(crate) fn set_active_for_test(on: bool) {
    ACTIVE.store(on, Ordering::SeqCst);
}

/// Whether the demo is on.
pub fn active() -> bool {
    ACTIVE.load(Ordering::SeqCst)
}

/// The `n6Delays` array for the UPF `upf_key`: one entry per endpoint with a
/// current result, sorted by endpoint. Empty when the SMF holds none.
pub fn n6_delays(upf_key: &str) -> Vec<Value> {
    crate::n6_delay::latest_for(upf_key)
        .into_iter()
        .map(|(ip, m)| {
            let mut e = serde_json::json!({ "endpoint": ip.to_string(), "avgMs": m.average_ms });
            if let Some(v) = m.minimum_ms {
                e["minMs"] = v.into();
            }
            if let Some(v) = m.maximum_ms {
                e["maxMs"] = v.into();
            }
            e
        })
        .collect()
}

/// Add the N6 member to the QOS_MON notification `body` of a session whose PSA
/// UPF is `upf_key`, when the demo is on and the SMF holds a result for that UPF.
/// Returns how many endpoints it added (0: the body is unchanged).
pub fn extend(body: &mut Value, upf_key: Option<&str>, reference: &str) -> usize {
    if !active() {
        return 0;
    }
    let Some(upf_key) = upf_key else {
        nextgcore_demo::demo_log!(
            info,
            DEMO_KEY,
            "QOS_MON ref={reference}: no PSA UPF known for the session, no n6Delays"
        );
        return 0;
    };
    let delays = n6_delays(upf_key);
    if delays.is_empty() {
        nextgcore_demo::demo_log!(
            info,
            DEMO_KEY,
            "QOS_MON ref={reference}: no N6 delay result for UPF {upf_key}, no n6Delays"
        );
        return 0;
    }
    let n = delays.len();
    let summary: Vec<String> = delays
        .iter()
        .map(|d| format!("{}={}ms", d["endpoint"].as_str().unwrap_or("?"), d["avgMs"]))
        .collect();
    if let Some(e) = body
        .get_mut("eventNotifs")
        .and_then(|v| v.get_mut(0))
        .and_then(Value::as_object_mut)
    {
        e.insert(
            VENDOR_MEMBER.to_string(),
            serde_json::json!({ "n6Delays": delays }),
        );
        nextgcore_demo::demo_log!(
            info,
            DEMO_KEY,
            "QOS_MON ref={reference} +n6Delays upf={upf_key} [{}]",
            summary.join(",")
        );
        n
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::n6_delay::{self, Measured};
    use std::net::IpAddr;

    fn body() -> Value {
        serde_json::json!({
            "notifId": "n",
            "eventNotifs": [{ "event": "QOS_MON", "supi": "imsi-001010000000471", "rtDelays": [6] }],
        })
    }

    /// The member's name is the TS 29.500 §6.6.3 form with PEN 32473 (RFC 5612),
    /// and eesd reads the same name (its own test pins it too).
    #[test]
    fn the_member_is_a_ts29500_vendor_specific_name_471() {
        assert_eq!(VENDOR_MEMBER, "vendorSpecific-032473");
        let digits = VENDOR_MEMBER.strip_prefix("vendorSpecific-").unwrap();
        assert_eq!(digits.len(), 6);
        assert!(digits.bytes().all(|b| b.is_ascii_digit()));
    }

    /// On: the session's UPF's results only, sorted, min/max when reported. Off,
    /// or no result for that UPF: the body is unchanged.
    #[tokio::test]
    async fn the_notification_carries_the_psa_upf_s_n6_delays_only_when_on_471() {
        let _n6 = n6_delay::N6_TEST_LOCK.lock().await;
        let _t = TEST_LOCK.lock().await;
        n6_delay::reset_for_test();
        let a: IpAddr = "10.60.0.12".parse().unwrap();
        let b: IpAddr = "10.60.0.11".parse().unwrap();
        n6_delay::insert_for_test(
            "upf-471-a:8805",
            a,
            Measured {
                average_ms: 4,
                minimum_ms: None,
                maximum_ms: None,
            },
        );
        n6_delay::insert_for_test(
            "upf-471-a:8805",
            b,
            Measured {
                average_ms: 18,
                minimum_ms: Some(17),
                maximum_ms: Some(20),
            },
        );
        n6_delay::insert_for_test(
            "upf-471-b:8805",
            b,
            Measured {
                average_ms: 99,
                minimum_ms: None,
                maximum_ms: None,
            },
        );

        set_active_for_test(false);
        let mut off = body();
        assert_eq!(extend(&mut off, Some("upf-471-a:8805"), "r"), 0);
        assert_eq!(off, body(), "demo off: byte-identical");

        set_active_for_test(true);
        let mut on = body();
        assert_eq!(extend(&mut on, Some("upf-471-a:8805"), "r"), 2);
        assert_eq!(
            on["eventNotifs"][0][VENDOR_MEMBER],
            serde_json::json!({ "n6Delays": [
                { "endpoint": "10.60.0.11", "avgMs": 18, "minMs": 17, "maxMs": 20 },
                { "endpoint": "10.60.0.12", "avgMs": 4 },
            ]})
        );
        // Everything else is as it was.
        on["eventNotifs"][0]
            .as_object_mut()
            .unwrap()
            .remove(VENDOR_MEMBER);
        assert_eq!(on, body());

        let mut none = body();
        assert_eq!(extend(&mut none, Some("upf-471-c:8805"), "r"), 0);
        assert_eq!(none, body(), "no result for that UPF: unchanged");
        let mut unknown = body();
        assert_eq!(extend(&mut unknown, None, "r"), 0);
        assert_eq!(unknown, body());

        set_active_for_test(false);
        n6_delay::reset_for_test();
    }
}
