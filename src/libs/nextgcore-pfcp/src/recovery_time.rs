//! The PFCP Recovery Time Stamp (TS 29.244 §8.2.65, #995).
//!
//! The IE carries "the UTC time when the PFCP entity started", encoded "in the same
//! format as the first four octets of the 64-bit timestamp format as defined in
//! section 6 of IETF RFC 5905": seconds since 00:00:00 UTC on 1 January 1900 (NTP era
//! 0), rolling over into era 1 on 7 February 2036 06:28:16 UTC.
//!
//! Every nextgcore PFCP function used to send Unix seconds (since 1970), about
//! 2,208,988,800 s -- 70 years -- too small. [`now`] produces the right value.
//!
//! Peers running an older nextgcore still send Unix seconds, and smfd's durable state
//! holds stamps it received from them. The two readings of a value are 70 years apart,
//! more than half the 32-bit serial space, so a comparison across the change is
//! meaningless: an upgraded UPF's NTP stamp compares as OLDER than its stored Unix
//! one (RFC 1982), and a Unix stamp compares as different from its NTP rendering.
//! [`normalize`] maps a stamp to the NTP reading that is closer to the local clock:
//! a real start time is in the recent past, the other reading is 70 years away. A
//! function applies it to every stamp it receives or loads, so mixed-version peers
//! and pre-#995 durable state stay comparable, and an upgrade of one side reads as
//! what it is (a restart of the side that was restarted) and never as a false one.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds from the NTP epoch (1900-01-01) to the Unix epoch (1970-01-01).
pub const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

/// The NTP-era seconds (§8.2.65) for `unix` seconds since 1970, wrapping into era 1
/// in February 2036.
pub fn from_unix_secs(unix: u64) -> u32 {
    (unix.wrapping_add(NTP_UNIX_OFFSET) & 0xFFFF_FFFF) as u32
}

/// This PFCP entity's Recovery Time Stamp if it starts now. A clock before 1970
/// yields the NTP value of the Unix epoch rather than panicking.
pub fn now() -> u32 {
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    from_unix_secs(unix)
}

/// Whether stamp `a` is newer than `b` in serial-number arithmetic (RFC 1982): a stamp
/// just past the 2036 era wrap is newer than one just before it.
pub fn is_newer(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// The distance between two stamps on the 32-bit circle.
fn distance(a: u32, b: u32) -> u32 {
    let d = a.wrapping_sub(b);
    d.min(d.wrapping_neg())
}

/// A received or stored stamp in the NTP reading (#995): `stamp` itself, or, when it is
/// a pre-#995 Unix-seconds stamp, its NTP equivalent -- whichever is closer to
/// `now_ntp`. A real NTP stamp less than ~33 years old is never reinterpreted.
pub fn normalize(stamp: u32, now_ntp: u32) -> u32 {
    let as_unix = from_unix_secs(u64::from(stamp));
    if distance(as_unix, now_ntp) < distance(stamp, now_ntp) {
        as_unix
    } else {
        stamp
    }
}

/// [`normalize`] against the local clock.
///
/// Transitional (#995): the Unix reading exists only for pre-#995 nextgcore peers and
/// durable state. Tracked for removal in #1033 once mixed-version deployments are gone,
/// because it also re-reads a third-party NTP stamp when a clock is ~34 years off.
pub fn normalize_received(stamp: u32) -> u32 {
    normalize(stamp, now())
}

/// How far ahead of our clock a peer's start time may plausibly be (clock skew).
pub const FUTURE_SKEW_SECS: u32 = 86_400;

/// Whether `stamp`, a start time, lies more than [`FUTURE_SKEW_SECS`] in the future
/// of `now_ntp` (#1004 review). A start time cannot be in the future: such a stamp
/// came from a clock that was wrong (an RTC-less peer that booted at 1970, its stamp
/// then read in the Unix branch, ~2040), and an ordering judged against it is
/// meaningless.
pub fn is_in_the_future(stamp: u32, now_ntp: u32) -> bool {
    is_newer(stamp, now_ntp.wrapping_add(FUTURE_SKEW_SECS))
}

/// 2020-01-01T00:00:00Z: a local clock before this has not been set.
pub const PLAUSIBLE_CLOCK_UNIX: u64 = 1_577_836_800;

/// Refuse to run PFCP with an unset local clock (#1004 review): its Recovery Time
/// Stamp would read as ~1970, which peers misjudge (and [`normalize`] reads the other
/// way). The classic RTC-unset check.
pub fn check_local_clock() -> Result<(), String> {
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    check_clock(unix)
}

fn check_clock(unix: u64) -> Result<(), String> {
    if unix < PLAUSIBLE_CLOCK_UNIX {
        return Err(format!(
            "the local clock reads {unix} s after 1970, before 2020-01-01: it is not set. \
             A PFCP Recovery Time Stamp taken from it (TS 29.244 §8.2.65) would be wrong; \
             set the clock (NTP) before starting this NF"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-01-01T00:00:00Z is Unix 1_767_225_600 and NTP 3_976_214_400.
    #[test]
    fn a_known_date_has_its_ntp_value() {
        assert_eq!(from_unix_secs(1_767_225_600), 3_976_214_400);
        assert_eq!(from_unix_secs(0), 2_208_988_800, "the Unix epoch");
    }

    /// 2036-02-07T06:28:16Z (Unix 2_085_978_496) starts NTP era 1 at 0.
    #[test]
    fn the_2036_era_wrap() {
        assert_eq!(from_unix_secs(2_085_978_495), u32::MAX);
        assert_eq!(from_unix_secs(2_085_978_496), 0);
        assert_eq!(from_unix_secs(2_085_978_500), 4);
        assert!(is_newer(4, u32::MAX), "just past the wrap is newer");
        assert!(!is_newer(u32::MAX, 4));
    }

    #[test]
    fn now_is_ntp_seconds() {
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let n = now();
        assert!(distance(n, from_unix_secs(unix)) <= 1);
    }

    /// A pre-#995 Unix stamp is mapped to its NTP value; an NTP stamp is left alone,
    /// before and after the era wrap and for a peer started years ago.
    #[test]
    fn legacy_unix_stamps_are_normalized_and_ntp_ones_are_not() {
        let now_unix = 1_767_225_600u64; // 2026-01-01
        let now = from_unix_secs(now_unix);
        for age in [0u64, 60, 86_400 * 400, 86_400 * 365 * 10] {
            let started = now_unix - age;
            let ntp = from_unix_secs(started);
            assert_eq!(normalize(ntp, now), ntp, "NTP stamp {age} s old");
            assert_eq!(
                normalize(started as u32, now),
                ntp,
                "Unix stamp {age} s old"
            );
        }
        // Across the 2036 wrap: now in era 1, a peer started in era 0 or era 1.
        let now_unix = 2_085_978_496u64 + 86_400; // 2036-02-08
        let now = from_unix_secs(now_unix);
        for started in [now_unix - 86_400 * 2, now_unix - 60] {
            let ntp = from_unix_secs(started);
            assert_eq!(normalize(ntp, now), ntp);
            assert_eq!(normalize(started as u32, now), ntp);
        }
    }

    #[test]
    fn a_start_time_in_the_future_is_flagged() {
        let now = from_unix_secs(1_767_225_600);
        assert!(!is_in_the_future(now, now));
        assert!(!is_in_the_future(now.wrapping_add(3600), now), "skew");
        assert!(
            is_in_the_future(now.wrapping_add(86_400 * 365 * 14), now),
            "~2040"
        );
        assert!(!is_in_the_future(now.wrapping_sub(86_400 * 365), now));
    }

    #[test]
    fn an_unset_clock_is_refused() {
        assert!(check_clock(0).is_err(), "1970");
        assert!(check_clock(PLAUSIBLE_CLOCK_UNIX - 1).is_err());
        assert!(check_clock(PLAUSIBLE_CLOCK_UNIX).is_ok());
        assert!(check_local_clock().is_ok(), "this host's clock is set");
    }

    /// Why normalization is needed: across the change the two readings are more than
    /// half the serial space apart, so an upgraded peer's NTP stamp compares as OLDER
    /// than its stored Unix one.
    #[test]
    fn unnormalized_the_upgrade_compares_backwards() {
        let started_unix = 1_767_225_600u64;
        let stored_legacy = started_unix as u32;
        let restarted_ntp = from_unix_secs(started_unix + 3600);
        assert!(!is_newer(restarted_ntp, stored_legacy), "the bug");
        let now = from_unix_secs(started_unix + 7200);
        assert!(
            is_newer(restarted_ntp, normalize(stored_legacy, now)),
            "the fix"
        );
    }
}
