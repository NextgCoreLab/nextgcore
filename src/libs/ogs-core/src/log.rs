//! Logging utilities
//!
//! Exact port of lib/core/ogs-log.h and ogs-log.c

pub use log::{debug, error, info, trace, warn};

/// Log levels matching C implementation
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OgsLogLevel {
    None = 0,
    Fatal = 1,
    Error = 2,
    Warn = 3,
    Info = 4,
    Debug = 5,
    Trace = 6,
}

impl Default for OgsLogLevel {
    fn default() -> Self {
        OgsLogLevel::Info
    }
}

/// Initialize logging
pub fn ogs_log_init() {
    env_logger::init();
}

/// Logging macros matching C implementation
#[macro_export]
macro_rules! ogs_fatal {
    ($($arg:tt)*) => {
        log::error!("[FATAL] {}", format!($($arg)*));
        std::process::abort();
    };
}

#[macro_export]
macro_rules! ogs_error {
    ($($arg:tt)*) => {
        log::error!($($arg)*);
    };
}

#[macro_export]
macro_rules! ogs_warn {
    ($($arg:tt)*) => {
        log::warn!($($arg)*);
    };
}

#[macro_export]
macro_rules! ogs_info {
    ($($arg:tt)*) => {
        log::info!($($arg)*);
    };
}

#[macro_export]
macro_rules! ogs_debug {
    ($($arg:tt)*) => {
        log::debug!($($arg)*);
    };
}

#[macro_export]
macro_rules! ogs_trace {
    ($($arg:tt)*) => {
        log::trace!($($arg)*);
    };
}

/// Assertion macro matching C implementation
#[macro_export]
macro_rules! ogs_assert {
    ($cond:expr) => {
        if !$cond {
            log::error!("Assertion failed: {}", stringify!($cond));
            std::process::abort();
        }
    };
}

/// Expectation macro (non-fatal assertion)
#[macro_export]
macro_rules! ogs_expect {
    ($cond:expr) => {
        if !$cond {
            log::error!("Expectation failed: {}", stringify!($cond));
        }
    };
}
