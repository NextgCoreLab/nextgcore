//! TS 29.571 `DateTime` conversion: RFC 3339 UTC text <-> seconds since the
//! Unix epoch.
//!
//! # Why this lives here
//!
//! Six copies of one or both of these functions already exist across the
//! daemons (`nrfd`, `udmd`, `eesd`, `bsfd`, `pcfd`, and — before this module —
//! the one nssfd was about to add as a seventh). `DateTime` is a WIRE type, so
//! the crate every NF already depends on for wire types is where the conversion
//! belongs, and a shared implementation is the only way a fix to the leap-year
//! or offset handling reaches every producer at once.
//!
//! The existing copies are deliberately NOT migrated here in the change that
//! introduced this module: rewriting six daemons' timestamp handling is its own
//! blast radius, and each copy differs slightly in signature (`u64` vs `i64`) and
//! in strictness. This module is the canonical target for that migration; new
//! call sites must use it rather than adding copy number seven.
//!
//! Hand-rolled rather than pulling in a date/time crate, matching what the
//! existing copies already do.

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 -> (year, month, day)
/// in the proleptic Gregorian calendar.
///
/// Extracted so the `u64` and `i64` entry points below share one calendar
/// conversion. The two differ only in how they split an epoch into days and
/// seconds-of-day, which is where the signedness actually matters.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Format `secs` since the Unix epoch as an RFC 3339 UTC timestamp
/// (TS 29.571 `DateTime`).
pub fn epoch_to_rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Format a **signed** epoch as an RFC 3339 UTC timestamp, for the call sites that
/// hold an `i64`.
///
/// Not a convenience wrapper over [`epoch_to_rfc3339`]: a negative epoch cast to
/// `u64` becomes an enormous positive number and formats as a year far in the
/// future, so the split into days and seconds-of-day must be Euclidean.
/// `(-1).div_euclid(86400) == -1` and `(-1).rem_euclid(86400) == 86399`, giving
/// `1969-12-31T23:59:59Z`; `-1 / 86400 == 0` with a remainder of `-1` would not.
///
/// This is `eesd`'s implementation, promoted here during the RFC 3339 migration —
/// it was the only one of the six copies that handled a pre-epoch instant, and
/// keeping the `u64` entry point as the common case rather than widening it means
/// no existing caller changes.
pub fn epoch_to_rfc3339_signed(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let rem = epoch.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Split a trailing RFC 3339 zone designator off a time string, returning the
/// time without it and the zone's offset from UTC in seconds.
///
/// Accepted: `Z` / `z`, and a numeric `±HH:MM` or `±HHMM`. Anything else — most
/// importantly *no zone at all* — is refused, because a naive local time has no
/// defined instant and guessing UTC for it is how a deadline moves by hours.
///
/// The no-colon `±HHMM` form is not strictly RFC 3339 (its `time-numoffset`
/// requires the colon), but the shared parser already accepted `+0000` and
/// `eesd`'s parser accepts `±HHMM` generally. Accepting both spellings uniformly
/// is easier to explain than accepting `+0000` while refusing `+0200`.
/// A field of exactly `n` ASCII digits (RFC 3339 §5.6 `2DIGIT` / `4DIGIT`).
/// No sign and no other width, so no field can be negative or large enough to
/// overflow the seconds arithmetic (#856 review).
fn digits(s: &str, n: usize) -> Option<i64> {
    if s.len() == n && s.bytes().all(|b| b.is_ascii_digit()) {
        s.parse().ok()
    } else {
        None
    }
}

/// Days in `month` of `year` (proleptic Gregorian), for RFC 3339 §5.7's
/// "date-mday ... based on month/year".
fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn split_zone(rest: &str) -> Option<(&str, i64)> {
    // RFC 3339 is ASCII. The byte-offset `split_at` and slices below would panic
    // if a cut landed inside a multi-byte character, and the text comes from a
    // peer's JSON.
    if !rest.is_ascii() {
        return None;
    }
    if let Some(time) = rest.strip_suffix('Z').or_else(|| rest.strip_suffix('z')) {
        return Some((time, 0));
    }
    // Find the sign that starts the offset. Scanning from the end keeps the date's
    // own '-' separators out of it, since only the last 5 or 6 bytes can be a zone.
    for width in [6usize, 5] {
        if rest.len() < width + 1 {
            continue;
        }
        let (time, zone) = rest.split_at(rest.len() - width);
        let bytes = zone.as_bytes();
        let sign = match bytes[0] {
            b'+' => 1i64,
            b'-' => -1i64,
            _ => continue,
        };
        let (hh, mm) = if width == 6 {
            if bytes[3] != b':' {
                continue;
            }
            (&zone[1..3], &zone[4..6])
        } else {
            (&zone[1..3], &zone[3..5])
        };
        let Some(hours) = digits(hh, 2) else {
            continue;
        };
        let Some(minutes) = digits(mm, 2) else {
            continue;
        };
        if hours > 23 || minutes > 59 {
            return None;
        }
        return Some((time, sign * (hours * 3600 + minutes * 60)));
    }
    None
}

/// Parse an RFC 3339 date-time into **signed** seconds since the epoch, the
/// inverse of [`epoch_to_rfc3339_signed`].
///
/// Accepts the `YYYY-MM-DDThh:mm:ss` form with an optional fractional part and a
/// `Z` or numeric `±HH:MM` / `±HHMM` zone.
///
/// # A non-UTC offset is APPLIED, not rejected
///
/// This module originally **refused** any offset other than UTC, on the reasoning
/// that "misreading an offset shifts a deadline by hours". The reasoning was
/// right about the hazard and wrong about the remedy: the hazard is *ignoring* the
/// offset, and honouring it avoids that hazard without refusing conformant input.
/// Refusing turned out to be actively worse, because every consumer of this
/// function treats `None` as "no deadline":
///
/// * `bsfd` accepted a `+02:00` binding `expiry` at ingress and stored it verbatim,
///   then its subscription matcher parsed it with this function, got `None`, skipped
///   the deadline check and reported the binding as **live past its expiry**.
/// * `nsacfd` stores a consumer's `expiry` verbatim too, with the same fail-open
///   result in its report-decision path.
/// * `nssfd` silently substituted its own default for a conformant consumer's
///   requested expiry.
///
/// So the strict version converted a valid request into a *missing deadline*, which
/// is a worse failure than the shifted one it was guarding against. TS 29.571's
/// `DateTime` is RFC 3339, which permits any offset, so honouring it is also what
/// the spec says.
///
/// Still refused, because these are genuinely undecidable rather than merely
/// inconvenient: a time with **no zone**, a malformed zone, and out-of-range
/// fields.
pub fn rfc3339_to_epoch_signed(text: &str) -> Option<i64> {
    let t = text.trim();
    // RFC 3339 §5.6 NOTE: "T" and "Z" may be lower case; a space separator is
    // also allowed there "for the sake of readability".
    let (date, rest) = t.split_once(['T', 't']).or_else(|| t.split_once(' '))?;
    // Every field is fixed-width ASCII digits (RFC 3339 §5.6): no sign, no
    // other width. That keeps every value small, so the day and second
    // arithmetic below cannot overflow: an 18-digit year or a
    // `-9223372036854775808` hour from a peer used to (a panic with overflow
    // checks, a wrapped instant without), and `+2024` or `T-1:00:00` were
    // accepted (#856 review).
    let mut parts = date.split('-');
    let year = digits(parts.next()?, 4)?;
    let month = digits(parts.next()?, 2)?;
    let day = digits(parts.next()?, 2)?;
    if parts.next().is_some() || !(1..=12).contains(&month) {
        return None;
    }
    // §5.7: the day must exist in that month, so 2024-02-31 is refused rather
    // than silently becoming 2 March.
    if !(1..=days_in_month(year, month)).contains(&day) {
        return None;
    }

    let (time, offset_secs) = split_zone(rest)?;
    // Fractional seconds: digits only, and dropped.
    let (time, frac) = time.split_once('.').unwrap_or((time, "0"));
    if frac.is_empty() || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }

    let mut tparts = time.split(':');
    let hour = digits(tparts.next()?, 2)?;
    let minute = digits(tparts.next()?, 2)?;
    // RFC 3339 `partial-time` requires seconds (`time-hour ":" time-minute ":"
    // time-second`), so `hh:mm` is refused.
    let second = digits(tparts.next()?, 2)?;
    if tparts.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    Some(
        days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second
            - offset_secs,
    )
}

/// Days since 1970-01-01 for a valid proleptic Gregorian date, the inverse of
/// [`civil_from_days`].
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Format milliseconds since the epoch as a `3gpp-Sbi-Origination-Timestamp`
/// header value (TS 29.502 §6.1.2.3.2), e.g. `Sun, 06 Nov 1994 08:49:37.123 GMT`;
/// the inverse of [`origination_timestamp_to_epoch_ms`].
pub fn epoch_ms_to_origination_timestamp(ms: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{}, {d:02} {} {y:04} {:02}:{:02}:{:02}.{millis:03} GMT",
        DAYS[days.rem_euclid(7) as usize],
        MONTHS[(m - 1) as usize],
        tod / 3600,
        tod % 3600 / 60,
        tod % 60
    )
}

/// The current time as a `3gpp-Sbi-Origination-Timestamp` header value.
pub fn now_origination_timestamp() -> String {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    epoch_ms_to_origination_timestamp(ms)
}

/// Parse a `3gpp-Sbi-Origination-Timestamp` header value into milliseconds
/// since the Unix epoch.
///
/// TS 29.502 §6.1.2.3.2 / `TS29502_CustomHeaders.abnf`:
/// `day-name "," SP date1 SP time-of-day "." milliseconds SP "GMT"`, e.g.
/// `Sun, 06 Nov 1994 08:49:37.123 GMT`. Every field is fixed-width and
/// case-sensitive, as in that ABNF; OWS around the value is allowed. Strict
/// like [`rfc3339_to_epoch_signed`]: a value from a peer never panics and
/// never wraps, and a date that does not exist (`31 Feb`) or a day-name
/// that does not match the date is refused.
pub fn origination_timestamp_to_epoch_ms(text: &str) -> Option<i64> {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"]; // 1970-01-01 was a Thursday
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let t = text.trim_matches([' ', '\t']);
    if !t.is_ascii() {
        return None;
    }
    // Fixed layout: "Sun, 06 Nov 1994 08:49:37.123 GMT" is 33 octets.
    let b = t.as_bytes();
    if b.len() != 33
        || &t[3..5] != ", "
        || b[7] != b' '
        || b[11] != b' '
        || b[16] != b' '
        || b[19] != b':'
        || b[22] != b':'
        || b[25] != b'.'
        || &t[29..] != " GMT"
    {
        return None;
    }
    let day_name = &t[0..3];
    let day = digits(&t[5..7], 2)?;
    let month = MONTHS.iter().position(|m| *m == &t[8..11])? as i64 + 1;
    let year = digits(&t[12..16], 4)?;
    let hour = digits(&t[17..19], 2)?;
    let minute = digits(&t[20..22], 2)?;
    let second = digits(&t[23..25], 2)?;
    let millis = digits(&t[26..29], 3)?;
    if !(1..=days_in_month(year, month)).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    if DAYS[days.rem_euclid(7) as usize] != day_name {
        return None;
    }
    Some((days * 86_400 + hour * 3600 + minute * 60 + second) * 1000 + millis)
}

/// Parse an RFC 3339 date-time into seconds since the epoch, the inverse of
/// [`epoch_to_rfc3339`].
///
/// Returns `None` for an instant **before** the epoch, which no `u64` can hold —
/// the same answer the pre-offset implementation gave via its `days < 0` guard.
/// Call [`rfc3339_to_epoch_signed`] where a pre-epoch instant must survive.
pub fn rfc3339_to_epoch(text: &str) -> Option<u64> {
    rfc3339_to_epoch_signed(text).and_then(|secs| u64::try_from(secs).ok())
}

/// Seconds since the Unix epoch, or 0 if the clock is before it.
pub fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {

    /// The formatter is the parser's inverse, across a leap day, the epoch and
    /// a millisecond boundary.
    #[test]
    fn origination_timestamp_round_trips() {
        assert_eq!(
            epoch_ms_to_origination_timestamp(784_111_777_123),
            "Sun, 06 Nov 1994 08:49:37.123 GMT"
        );
        for ms in [0, 1, 999, 1_000, 1_709_251_199_999, 1_792_771_200_000] {
            let text = epoch_ms_to_origination_timestamp(ms);
            assert_eq!(origination_timestamp_to_epoch_ms(&text), Some(ms), "{text}");
        }
        assert!(origination_timestamp_to_epoch_ms(&now_origination_timestamp()).is_some());
    }

    /// TS 29.502 §6.1.2.3.2: the ABNF's example shape, OWS, and every refusal.
    #[test]
    fn origination_timestamp_is_parsed_strictly() {
        assert_eq!(
            origination_timestamp_to_epoch_ms("Sun, 06 Nov 1994 08:49:37.123 GMT"),
            Some(784_111_777_123)
        );
        assert_eq!(
            origination_timestamp_to_epoch_ms(" \tThu, 01 Jan 1970 00:00:00.000 GMT "),
            Some(0)
        );
        assert_eq!(
            origination_timestamp_to_epoch_ms("Thu, 29 Feb 2024 23:59:59.999 GMT"),
            Some(1_709_251_199_999)
        );
        for bad in [
            "",
            "Sun, 06 Nov 1994 08:49:37 GMT",     // no milliseconds
            "Sun, 06 Nov 1994 08:49:37.12 GMT",  // two-digit milliseconds
            "Sun, 6 Nov 1994 08:49:37.123 GMT",  // one-digit day
            "Sun, 06 nov 1994 08:49:37.123 GMT", // case-sensitive month
            "Sun, 06 Nov 1994 08:49:37.123 UTC", // not GMT
            "Mon, 06 Nov 1994 08:49:37.123 GMT", // wrong day-name
            "Fri, 31 Feb 2023 08:49:37.123 GMT", // no such date
            "Sun, 06 Nov 1994 24:00:00.000 GMT", // hour
            "Sun, 06 Nov 1994 08:49:37.+12 GMT", // sign
            "Sun, 06 Nov 1994 08:49:37.123 GMT x",
            "Sun,\u{e9}06 Nov 1994 08:49:37.123 GMT", // non-ASCII: no panic
            "2026-01-01T00:00:00Z",
        ] {
            assert_eq!(origination_timestamp_to_epoch_ms(bad), None, "{bad:?}");
        }
    }

    use super::*;

    #[test]
    fn hostile_date_times_are_refused_without_panicking() {
        // A peer's TS 29.571 DateTime: a multi-byte character where the zone
        // split cuts used to panic `split_at`, and an oversized year overflowed
        // the seconds arithmetic.
        for bad in [
            "2024-01-01T0\u{e9}00000",
            "2024-01-01T00:00:0\u{e9}0",
            "2024-01-01T\u{e9}\u{e9}\u{e9}",
            "999999999999999-01-01T00:00:00Z",
            "-1-01-01T00:00:00Z",
            "10000-01-01T00:00:00Z",
            // #856 review: signed or over-wide H/M/S, a signed year, a doubly
            // signed zone, and dates that do not exist.
            "2024-01-01T-9223372036854775808:00:00Z",
            "2024-01-01T00:-9223372036854775808:00Z",
            "2024-01-01T00:00:-9223372036854775808Z",
            "2024-01-01T-1:00:00Z",
            "2024-01-01T00:00:00-+1:00",
            "+2024-01-01T00:00:00Z",
            "2024-1-01T00:00:00Z",
            "2024-01-01T0:00:00Z",
            "2024-02-31T00:00:00Z",
            "2023-02-29T00:00:00Z",
            "2024-04-31T00:00:00Z",
            "2024-01-01T00:00:00.Z",
            "2024-01-01T12:00Z",
            "2024-01-01T00:00:00.1aZ",
        ] {
            assert_eq!(rfc3339_to_epoch_signed(bad), None, "{bad:?}");
            assert_eq!(rfc3339_to_epoch(bad), None, "{bad:?}");
        }
        // The edges of the 4-digit range still parse.
        assert!(rfc3339_to_epoch_signed("0000-01-01T00:00:00Z").is_some());
        assert!(rfc3339_to_epoch_signed("9999-12-31T23:59:59+01:00").is_some());
        assert!(
            rfc3339_to_epoch_signed("2024-02-29T00:00:00Z").is_some(),
            "leap day"
        );
        assert_eq!(
            rfc3339_to_epoch_signed("2024-01-01t00:00:00z"),
            rfc3339_to_epoch_signed("2024-01-01T00:00:00Z"),
            "lower-case t and z (RFC 3339 §5.6 NOTE)"
        );
        assert!(
            rfc3339_to_epoch_signed("2000-02-29T00:00:00Z").is_some(),
            "400-year leap"
        );
        assert!(
            rfc3339_to_epoch_signed("1900-02-29T00:00:00Z").is_none(),
            "100-year non-leap"
        );
    }

    #[test]
    fn known_instants_round_trip() {
        for (secs, text) in [
            (0u64, "1970-01-01T00:00:00Z"),
            (946_684_800, "2000-01-01T00:00:00Z"),
            // A leap day, which the civil-days conversion must get right.
            (1_583_020_800, "2020-03-01T00:00:00Z"),
            (1_709_164_800, "2024-02-29T00:00:00Z"),
        ] {
            assert_eq!(epoch_to_rfc3339(secs), text, "format {secs}");
            assert_eq!(rfc3339_to_epoch(text), Some(secs), "parse {text}");
        }
    }

    /// The signed entry point agrees with the `u64` one wherever both are defined,
    /// and handles the pre-epoch instants the `u64` one cannot represent.
    ///
    /// The negative cases are the whole reason it exists: `-1` as a `u64` is
    /// 18446744073709551615, which formats as a year around 584 billion. Getting
    /// `1969-12-31T23:59:59Z` instead is what `div_euclid`/`rem_euclid` buy.
    #[test]
    fn signed_epochs_agree_with_unsigned_and_handle_pre_epoch_instants() {
        for secs in [0u64, 946_684_800, 1_583_020_800, 1_709_164_800] {
            assert_eq!(
                epoch_to_rfc3339_signed(secs as i64),
                epoch_to_rfc3339(secs),
                "signed and unsigned must agree at {secs}"
            );
        }
        assert_eq!(epoch_to_rfc3339_signed(-1), "1969-12-31T23:59:59Z");
        assert_eq!(epoch_to_rfc3339_signed(-86_400), "1969-12-31T00:00:00Z");
        assert_eq!(epoch_to_rfc3339_signed(-86_401), "1969-12-30T23:59:59Z");
        // A truncating (non-Euclidean) split would give 1970-01-01T00:00:00Z here,
        // i.e. it would silently round a pre-epoch instant up to the epoch.
        assert_ne!(epoch_to_rfc3339_signed(-1), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn accepts_the_utc_spellings_and_fractional_seconds() {
        let base = Some(946_684_800);
        assert_eq!(rfc3339_to_epoch("2000-01-01T00:00:00Z"), base);
        assert_eq!(rfc3339_to_epoch("2000-01-01T00:00:00z"), base);
        assert_eq!(rfc3339_to_epoch("2000-01-01T00:00:00+00:00"), base);
        assert_eq!(rfc3339_to_epoch("2000-01-01T00:00:00+0000"), base);
        assert_eq!(rfc3339_to_epoch("2000-01-01T00:00:00.123Z"), base);
        assert_eq!(rfc3339_to_epoch("  2000-01-01T00:00:00Z  "), base);
    }

    /// INVERTED from `rejects_a_non_utc_offset_rather_than_reading_it_as_utc`.
    ///
    /// That test asserted `+02:00` parsed to `None`. It pinned behaviour that
    /// turned out to be the defect rather than the guard: every consumer reads
    /// `None` as "no deadline", so refusing a conformant offset made `bsfd` and
    /// `nsacfd` treat an EXPIRED subscription as live, and made `nssfd` discard a
    /// consumer's requested expiry. The offset is now applied. The flip is
    /// recorded here rather than the old test being deleted, so the widening is
    /// visible to anyone reading the history.
    #[test]
    fn applies_a_non_utc_offset_rather_than_refusing_it() {
        // 02:00 in a +02:00 zone is 00:00 UTC. Subtracting the offset, not
        // ignoring it, is what makes these equal.
        let utc = rfc3339_to_epoch("2000-01-01T00:00:00Z").expect("UTC parses");
        assert_eq!(rfc3339_to_epoch("2000-01-01T02:00:00+02:00"), Some(utc));
        assert_eq!(rfc3339_to_epoch("1999-12-31T19:00:00-05:00"), Some(utc));
        // Both spellings of the zone, and the zero offset that was already accepted.
        assert_eq!(rfc3339_to_epoch("2000-01-01T02:00:00+0200"), Some(utc));
        assert_eq!(rfc3339_to_epoch("2000-01-01T00:00:00+00:00"), Some(utc));
        assert_eq!(rfc3339_to_epoch("2000-01-01T00:00:00+0000"), Some(utc));
        // The sign matters: reading -05:00 as +05:00 would be a ten-hour error.
        assert_ne!(
            rfc3339_to_epoch("2000-01-01T00:00:00-05:00"),
            rfc3339_to_epoch("2000-01-01T00:00:00+05:00")
        );
    }

    /// What is still refused, and why each is undecidable rather than merely
    /// inconvenient.
    #[test]
    fn refuses_input_with_no_defined_instant() {
        // No zone at all: a naive local time names no instant, and guessing UTC
        // for it is the hazard the old strictness was actually worried about.
        assert_eq!(rfc3339_to_epoch("2000-01-01T00:00:00"), None);
        // Malformed rather than guessed at.
        assert_eq!(rfc3339_to_epoch(""), None);
        assert_eq!(rfc3339_to_epoch("not a date"), None);
        assert_eq!(rfc3339_to_epoch("2000-13-01T00:00:00Z"), None);
        assert_eq!(rfc3339_to_epoch("2000-01-01T24:00:00Z"), None);
        assert_eq!(rfc3339_to_epoch("2000-01-01T00:60:00Z"), None);
        // A malformed zone is refused rather than read as UTC.
        assert_eq!(rfc3339_to_epoch("2000-01-01T00:00:00+2:00"), None);
        assert_eq!(rfc3339_to_epoch("2000-01-01T00:00:00+xx:00"), None);
        assert_eq!(rfc3339_to_epoch("2000-01-01T00:00:00+25:00"), None);
        assert_eq!(rfc3339_to_epoch("2000-01-01T00:00:00+02:60"), None);
    }

    /// The `u64` entry point cannot hold a pre-epoch instant and says so with
    /// `None`, which is the answer the pre-offset implementation gave via its
    /// `days < 0` guard. The signed one keeps the value.
    ///
    /// Reachable now that offsets are applied: a positive-offset timestamp just
    /// after the epoch resolves to before it.
    #[test]
    fn pre_epoch_instants_are_none_for_u64_and_kept_when_signed() {
        assert_eq!(rfc3339_to_epoch("1970-01-01T00:00:00+02:00"), None);
        assert_eq!(
            rfc3339_to_epoch_signed("1970-01-01T00:00:00+02:00"),
            Some(-7200)
        );
        assert_eq!(rfc3339_to_epoch_signed("1969-12-31T23:59:59Z"), Some(-1));
        // The signed parser agrees with the unsigned one wherever both are defined,
        // so the u64 entry point is a narrowing and not a second implementation.
        for text in ["1970-01-01T00:00:00Z", "2000-01-01T00:00:00Z"] {
            assert_eq!(
                rfc3339_to_epoch_signed(text).map(|s| s as u64),
                rfc3339_to_epoch(text),
                "signed and unsigned must agree for {text}"
            );
        }
    }
}
