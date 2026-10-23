//! NUDM UEAU request helpers
//!
//! Port of src/ausf/nudm-build.c. The live Nudm_UEAuthentication requests
//! are built and sent by `app` (`send_udm_generate_auth_data` /
//! `send_udm_auth_result`). The C port's synchronous request builders were
//! only reachable from the deleted per-UE FSM (#654); what is left here is
//! shared with the live path.

/// Resynchronization info for authentication (TS 29.503 ResynchronizationInfo)
#[derive(Debug, Clone)]
pub struct ResynchronizationInfo {
    pub rand: String,
    pub auts: String,
}

/// Get current timestamp in ISO 8601 format
pub fn get_current_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("value expected");

    // Format as ISO 8601
    let secs = duration.as_secs();

    chrono_lite_format(secs)
}

/// Simple ISO 8601 timestamp formatter (without chrono dependency)
fn chrono_lite_format(secs: u64) -> String {
    // Calculate date/time components from Unix timestamp
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    // Calculate year, month, day (simplified - doesn't handle leap years perfectly)
    let mut year = 1970;
    let mut remaining_days = days;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_months: [u64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    for days_in_month in days_in_months.iter() {
        if remaining_days < *days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        month += 1;
    }

    let day = remaining_days + 1;

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_current_timestamp() {
        let ts = get_current_timestamp();
        // Should be in ISO 8601 format
        assert!(ts.contains("T"));
        assert!(ts.ends_with("Z"));
    }

    #[test]
    fn test_chrono_lite_format() {
        // Test Unix epoch
        assert_eq!(chrono_lite_format(0), "1970-01-01T00:00:00Z");

        // Test a known timestamp (2024-01-01 00:00:00 UTC)
        let ts_2024 = 1704067200;
        assert_eq!(chrono_lite_format(ts_2024), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn test_is_leap_year() {
        assert!(!is_leap_year(1970));
        assert!(is_leap_year(2000));
        assert!(!is_leap_year(1900));
        assert!(is_leap_year(2024));
    }
}
