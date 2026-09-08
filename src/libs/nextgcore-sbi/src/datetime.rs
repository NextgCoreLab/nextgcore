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

/// Format `secs` since the Unix epoch as an RFC 3339 UTC timestamp
/// (TS 29.571 `DateTime`).
pub fn epoch_to_rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
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

/// Parse an RFC 3339 UTC date-time into seconds since the epoch, the inverse of
/// [`epoch_to_rfc3339`].
///
/// Deliberately strict: only the `YYYY-MM-DDThh:mm:ss` form, with an optional
/// fractional part and a `Z`/`+00:00` offset. **A non-UTC offset is REJECTED**
/// rather than silently read as UTC, because misreading an offset shifts a
/// deadline by hours — the same reasoning nrfd's copy records.
pub fn rfc3339_to_epoch(text: &str) -> Option<u64> {
    let t = text.trim();
    let (date, rest) = t.split_once('T').or_else(|| t.split_once(' '))?;
    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    // Strip the zone, accepting only UTC.
    let time = rest
        .strip_suffix('Z')
        .or_else(|| rest.strip_suffix('z'))
        .or_else(|| rest.strip_suffix("+00:00"))
        .or_else(|| rest.strip_suffix("+0000"))?;
    // Drop any fractional seconds.
    let time = time.split('.').next()?;

    let mut tparts = time.split(':');
    let hour: u64 = tparts.next()?.parse().ok()?;
    let minute: u64 = tparts.next()?.parse().ok()?;
    let second: u64 = tparts.next().unwrap_or("0").parse().ok()?;
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
    if days < 0 {
        return None;
    }
    Some(days as u64 * 86_400 + hour * 3600 + minute * 60 + second)
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

    #[test]
    fn rejects_a_non_utc_offset_rather_than_reading_it_as_utc() {
        // The whole point of the strictness: silently treating +02:00 as UTC
        // shifts a deadline by two hours.
        assert_eq!(rfc3339_to_epoch("2000-01-01T00:00:00+02:00"), None);
        assert_eq!(rfc3339_to_epoch("2000-01-01T00:00:00-05:00"), None);
        // Malformed input is refused, not guessed at.
        assert_eq!(rfc3339_to_epoch(""), None);
        assert_eq!(rfc3339_to_epoch("not a date"), None);
        assert_eq!(rfc3339_to_epoch("2000-13-01T00:00:00Z"), None);
        assert_eq!(rfc3339_to_epoch("2000-01-01T24:00:00Z"), None);
        assert_eq!(rfc3339_to_epoch("2000-01-01T00:60:00Z"), None);
        // No zone at all.
        assert_eq!(rfc3339_to_epoch("2000-01-01T00:00:00"), None);
    }
}
