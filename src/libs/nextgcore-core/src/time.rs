//! Time utilities
//!
//! Exact port of lib/core/nextgcore-time.h and nextgcore-time.c

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Time in microseconds (identical to nextgcore_time_t)
pub type NextgcoreTime = i64;

/// Time constants
pub const NEXTGCORE_USEC_PER_SEC: i64 = 1_000_000;
pub const NEXTGCORE_MSEC_PER_SEC: i64 = 1_000;
pub const NEXTGCORE_USEC_PER_MSEC: i64 = 1_000;

/// Get current time in microseconds (identical to nextgcore_time_now)
pub fn nextgcore_time_now() -> NextgcoreTime {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

/// Get monotonic time in microseconds (identical to nextgcore_get_monotonic_time)
pub fn nextgcore_get_monotonic_time() -> NextgcoreTime {
    use std::time::Instant;
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_micros() as i64
}

/// Convert seconds to microseconds
pub const fn nextgcore_time_from_sec(sec: i64) -> NextgcoreTime {
    sec * NEXTGCORE_USEC_PER_SEC
}

/// Convert milliseconds to microseconds
pub const fn nextgcore_time_from_msec(msec: i64) -> NextgcoreTime {
    msec * NEXTGCORE_USEC_PER_MSEC
}

/// Convert microseconds to seconds
pub const fn nextgcore_time_to_sec(usec: NextgcoreTime) -> i64 {
    usec / NEXTGCORE_USEC_PER_SEC
}

/// Convert microseconds to milliseconds
pub const fn nextgcore_time_to_msec(usec: NextgcoreTime) -> i64 {
    usec / NEXTGCORE_USEC_PER_MSEC
}

/// Convert NextgcoreTime to Duration
pub fn nextgcore_time_to_duration(usec: NextgcoreTime) -> Duration {
    Duration::from_micros(usec as u64)
}

/// Convert Duration to NextgcoreTime
pub fn duration_to_ogs_time(d: Duration) -> NextgcoreTime {
    d.as_micros() as i64
}

/// Sleep for specified microseconds (identical to nextgcore_usleep)
pub fn nextgcore_usleep(usec: NextgcoreTime) {
    std::thread::sleep(Duration::from_micros(usec as u64));
}

/// Sleep for specified milliseconds (identical to nextgcore_msleep)
pub fn nextgcore_msleep(msec: i64) {
    std::thread::sleep(Duration::from_millis(msec as u64));
}

/// Sleep for specified seconds
pub fn nextgcore_sleep(sec: i64) {
    std::thread::sleep(Duration::from_secs(sec as u64));
}
