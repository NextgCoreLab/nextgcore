//! SEPP Timer Functions
//!
//! Port of src/sepp/timer.h and timer.c - Timer definitions and handlers

use crate::event::SeppTimerId;

/// Get the name of a timer (for logging)
pub fn sepp_timer_get_name(timer_id: SeppTimerId) -> &'static str {
    timer_id.name()
}

/// Timer configuration
#[derive(Debug, Clone)]
pub struct TimerConfig {
    /// Reconnect interval in milliseconds
    pub reconnect_interval: u64,
    /// Reconnect interval in exception state (longer)
    pub reconnect_interval_in_exception: u64,
}

impl Default for TimerConfig {
    fn default() -> Self {
        Self {
            reconnect_interval: 3000,           // 3 seconds
            reconnect_interval_in_exception: 10000, // 10 seconds
        }
    }
}

/// Timer manager for SEPP
pub struct TimerManager {
    config: TimerConfig,
}

impl TimerManager {
    pub fn new(config: TimerConfig) -> Self {
        Self { config }
    }

    pub fn reconnect_interval(&self) -> u64 {
        self.config.reconnect_interval
    }

    pub fn reconnect_interval_in_exception(&self) -> u64 {
        self.config.reconnect_interval_in_exception
    }
}

impl Default for TimerManager {
    fn default() -> Self {
        Self::new(TimerConfig::default())
    }
}
