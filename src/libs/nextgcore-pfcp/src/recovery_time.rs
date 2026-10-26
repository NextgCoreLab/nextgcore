//! The PFCP Recovery Time Stamp (TS 29.244 §8.2.65, #995).
//!
//! The IE carries "the UTC time when the PFCP entity started", encoded "in the same
//! format as the first four octets of the 64-bit timestamp format as defined in
//! section 6 of IETF RFC 5905": seconds since 00:00:00 UTC on 1 January 1900 (NTP era
//! 0), rolling over into era 1 on 7 February 2036 06:28:16 UTC.
//!
//! [`now`] produces this entity's stamp. A received stamp is used as it is on the wire:
//! §8.2.65 defines no other reading. nextgcore 0.1.x sent Unix seconds (since 1970);
//! 0.2.0 carried a transition shim that also read a received stamp as Unix seconds when
//! that reading was closer to the local clock. It was retired in 0.2.0 (#1033), so a
//! 0.1.x peer's Unix-seconds stamp now reads as a time about 70 years off. See the
//! CHANGELOG upgrade notes for the upgrade order.

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

/// How far ahead of our clock a peer's start time may plausibly be (clock skew).
pub const FUTURE_SKEW_SECS: u32 = 86_400;

/// Whether `stamp`, a start time, lies more than [`FUTURE_SKEW_SECS`] in the future
/// of `now_ntp` (#1004 review). A start time cannot be in the future: such a stamp
/// came from a clock that was wrong, or from a peer that does not send NTP-era seconds
/// (a 0.1.x nextgcore's Unix-seconds stamp reads as ~2096, #1033), and an ordering
/// judged against it is meaningless.
pub fn is_in_the_future(stamp: u32, now_ntp: u32) -> bool {
    is_newer(stamp, now_ntp.wrapping_add(FUTURE_SKEW_SECS))
}

/// 2020-01-01T00:00:00Z: a local clock before this has not been set.
pub const PLAUSIBLE_CLOCK_UNIX: u64 = 1_577_836_800;

/// Refuse to run PFCP with an unset local clock (#1004 review): its Recovery Time
/// Stamp would read as ~1970, which peers misjudge. The classic RTC-unset check.
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
        let expected = from_unix_secs(unix);
        assert!(
            n.wrapping_sub(expected) <= 1,
            "now() {n} is the NTP reading {expected}"
        );
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

    /// #1033: a 0.1.x peer's Unix-seconds stamp is not an NTP-era start time. Taken as
    /// sent, it reads as ~2096: in the future of the local clock, so it is never a
    /// trusted ordering reference, and an upgraded peer's NTP stamp compares as older.
    #[test]
    fn a_unix_seconds_stamp_is_a_time_70_years_off() {
        let started_unix = 1_767_225_600u64; // 2026-01-01
        let legacy = started_unix as u32;
        let now = from_unix_secs(started_unix + 7200);
        assert!(is_in_the_future(legacy, now), "~2096");
        let restarted_ntp = from_unix_secs(started_unix + 3600);
        assert!(!is_newer(restarted_ntp, legacy));
    }

    /// #1033, TS 29.244 §8.2.65: a Heartbeat Request's Recovery Time Stamp IE (type 96,
    /// length 4) decodes to the NTP-era seconds on the wire, 2026-01-01 here.
    #[test]
    fn a_heartbeat_request_decodes_the_ntp_stamp_as_sent() {
        let body = [0x00, 0x60, 0x00, 0x04, 0xED, 0x00, 0x37, 0x80];
        assert_eq!(u32::from_be_bytes([0xED, 0x00, 0x37, 0x80]), 3_976_214_400);
        let req =
            crate::message::HeartbeatRequest::decode(&mut bytes::Bytes::copy_from_slice(&body))
                .unwrap();
        assert_eq!(req.recovery_time_stamp, from_unix_secs(1_767_225_600));
    }
}
