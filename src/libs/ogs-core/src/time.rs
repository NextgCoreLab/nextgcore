//! Time utilities
//!
//! Exact port of lib/core/ogs-time.h and ogs-time.c

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Time in microseconds (identical to ogs_time_t)
pub type OgsTime = i64;

/// Time constants
pub const OGS_USEC_PER_SEC: i64 = 1_000_000;
pub const OGS_MSEC_PER_SEC: i64 = 1_000;
pub const OGS_USEC_PER_MSEC: i64 = 1_000;

/// Get current time in microseconds (identical to ogs_time_now)
pub fn ogs_time_now() -> OgsTime {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

/// Get monotonic time in microseconds (identical to ogs_get_monotonic_time)
pub fn ogs_get_monotonic_time() -> OgsTime {
    use std::time::Instant;
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_micros() as i64
}

/// Convert seconds to microseconds
pub const fn ogs_time_from_sec(sec: i64) -> OgsTime {
    sec * OGS_USEC_PER_SEC
}

/// Convert milliseconds to microseconds
pub const fn ogs_time_from_msec(msec: i64) -> OgsTime {
    msec * OGS_USEC_PER_MSEC
}

/// Convert microseconds to seconds
pub const fn ogs_time_to_sec(usec: OgsTime) -> i64 {
    usec / OGS_USEC_PER_SEC
}

/// Convert microseconds to milliseconds
pub const fn ogs_time_to_msec(usec: OgsTime) -> i64 {
    usec / OGS_USEC_PER_MSEC
}

/// Convert OgsTime to Duration
pub fn ogs_time_to_duration(usec: OgsTime) -> Duration {
    Duration::from_micros(usec as u64)
}

/// Convert Duration to OgsTime
pub fn duration_to_ogs_time(d: Duration) -> OgsTime {
    d.as_micros() as i64
}

/// Sleep for specified microseconds (identical to ogs_usleep)
pub fn ogs_usleep(usec: OgsTime) {
    std::thread::sleep(Duration::from_micros(usec as u64));
}

/// Sleep for specified milliseconds (identical to ogs_msleep)
pub fn ogs_msleep(msec: i64) {
    std::thread::sleep(Duration::from_millis(msec as u64));
}

/// Sleep for specified seconds
pub fn ogs_sleep(sec: i64) {
    std::thread::sleep(Duration::from_secs(sec as u64));
}
