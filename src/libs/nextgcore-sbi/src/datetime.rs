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
fn split_zone(rest: &str) -> Option<(&str, i64)> {
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
        let hours: i64 = match hh.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let minutes: i64 = match mm.parse() {
            Ok(v) => v,
            Err(_) => continue,
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
    let (date, rest) = t.split_once('T').or_else(|| t.split_once(' '))?;
    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    let (time, offset_secs) = split_zone(rest)?;
    // Drop any fractional seconds.
    let time = time.split('.').next()?;

    let mut tparts = time.split(':');
    let hour: i64 = tparts.next()?.parse().ok()?;
    let minute: i64 = tparts.next()?.parse().ok()?;
    let second: i64 = tparts.next().unwrap_or("0").parse().ok()?;
    if tparts.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    // days_from_civil, the inverse of civil_from_days above.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset_secs)
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
    use super::*;

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
