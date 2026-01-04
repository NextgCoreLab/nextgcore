//! HSS Timer Definitions
//!
//! Port of src/hss/hss-timer.h and hss-timer.c - Timer definitions and callbacks

use crate::event::{HssEvent, HssTimerId};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Default DB polling interval (100ms)
pub const DB_POLLING_TIME_MS: u64 = 100;

/// Timer entry
pub struct TimerEntry {
    /// Timer ID
    pub id: u64,
    /// Timer type
    pub timer_type: HssTimerId,
    /// Expiration time
    pub expires_at: Instant,
    /// Associated data
    pub data: Option<String>,
    /// Whether the timer is active
    pub active: bool,
}

impl TimerEntry {
    /// Create a new timer entry
    pub fn new(id: u64, timer_type: HssTimerId, duration: Duration, data: Option<String>) -> Self {
        Self {
            id,
            timer_type,
            expires_at: Instant::now() + duration,
            data,
            active: true,
        }
    }

    /// Check if the timer has expired
    pub fn is_expired(&self) -> bool {
        self.active && Instant::now() >= self.expires_at
    }

    /// Stop the timer
    pub fn stop(&mut self) {
        self.active = false;
    }

    /// Restart the timer with a new duration
    pub fn restart(&mut self, duration: Duration) {
        self.expires_at = Instant::now() + duration;
        self.active = true;
    }
}

/// Timer manager for HSS
pub struct HssTimerManager {
    /// Active timers
    timers: RwLock<HashMap<u64, TimerEntry>>,
    /// Next timer ID
    next_id: std::sync::atomic::AtomicU64,
}

impl HssTimerManager {
    /// Create a new timer manager
    pub fn new() -> Self {
        Self {
            timers: RwLock::new(HashMap::new()),
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Add a new timer
    pub fn add_timer(
        &self,
        timer_type: HssTimerId,
        duration: Duration,
        data: Option<String>,
    ) -> Option<u64> {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let entry = TimerEntry::new(id, timer_type, duration, data);

        if let Ok(mut timers) = self.timers.write() {
            timers.insert(id, entry);
            log::debug!(
                "Timer added: id={}, type={:?}, duration={:?}",
                id,
                timer_type,
                duration
            );
            Some(id)
        } else {
            None
        }
    }

    /// Start a timer (alias for add_timer for API compatibility)
    pub fn start_timer(
        &self,
        timer_type: HssTimerId,
        duration: Duration,
        data: Option<String>,
    ) -> Option<u64> {
        self.add_timer(timer_type, duration, data)
    }

    /// Stop a timer
    pub fn stop_timer(&self, id: u64) -> bool {
        if let Ok(mut timers) = self.timers.write() {
            if let Some(timer) = timers.get_mut(&id) {
                timer.stop();
                log::debug!("Timer stopped: id={}", id);
                return true;
            }
        }
        false
    }

    /// Delete a timer
    pub fn delete_timer(&self, id: u64) -> bool {
        if let Ok(mut timers) = self.timers.write() {
            if timers.remove(&id).is_some() {
                log::debug!("Timer deleted: id={}", id);
                return true;
            }
        }
        false
    }

    /// Restart a timer with a new duration
    pub fn restart_timer(&self, id: u64, duration: Duration) -> bool {
        if let Ok(mut timers) = self.timers.write() {
            if let Some(timer) = timers.get_mut(&id) {
                timer.restart(duration);
                log::debug!("Timer restarted: id={}, duration={:?}", id, duration);
                return true;
            }
        }
        false
    }

    /// Get expired timers and generate events
    pub fn get_expired_events(&self) -> Vec<HssEvent> {
        let mut events = Vec::new();

        if let Ok(mut timers) = self.timers.write() {
            let expired_ids: Vec<u64> = timers
                .iter()
                .filter(|(_, t)| t.is_expired())
                .map(|(id, _)| *id)
                .collect();

            for id in expired_ids {
                if let Some(timer) = timers.remove(&id) {
                    let event = match timer.timer_type {
                        HssTimerId::DbiPollChangeStream => {
                            HssEvent::dbi_poll_timer(HssTimerId::DbiPollChangeStream)
                        }
                    };
                    events.push(event);
                    log::debug!("Timer expired: id={}, type={:?}", id, timer.timer_type);
                }
            }
        }

        events
    }

    /// Get the number of active timers
    pub fn active_count(&self) -> usize {
        self.timers
            .read()
            .map(|t| t.values().filter(|e| e.active).count())
            .unwrap_or(0)
    }

    /// Clear all timers
    pub fn clear(&self) {
        if let Ok(mut timers) = self.timers.write() {
            timers.clear();
        }
    }
}

impl Default for HssTimerManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Get the name of a timer
pub fn hss_timer_get_name(timer_id: HssTimerId) -> &'static str {
    timer_id.name()
}

/// Global timer manager
static GLOBAL_TIMER_MANAGER: std::sync::OnceLock<Arc<HssTimerManager>> = std::sync::OnceLock::new();

/// Get the global timer manager
pub fn timer_manager() -> Arc<HssTimerManager> {
    GLOBAL_TIMER_MANAGER
        .get_or_init(|| Arc::new(HssTimerManager::new()))
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timer_entry_creation() {
        let entry = TimerEntry::new(
            1,
            HssTimerId::DbiPollChangeStream,
            Duration::from_secs(10),
            None,
        );
        assert_eq!(entry.id, 1);
        assert_eq!(entry.timer_type, HssTimerId::DbiPollChangeStream);
        assert!(entry.active);
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_timer_stop() {
        let mut entry = TimerEntry::new(
            1,
            HssTimerId::DbiPollChangeStream,
            Duration::from_secs(10),
            None,
        );
        assert!(entry.active);
        entry.stop();
        assert!(!entry.active);
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_timer_manager_add_delete() {
        let manager = HssTimerManager::new();

        let id = manager
            .add_timer(
                HssTimerId::DbiPollChangeStream,
                Duration::from_secs(10),
                None,
            )
            .unwrap();

        assert_eq!(manager.active_count(), 1);

        assert!(manager.delete_timer(id));
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn test_timer_manager_stop() {
        let manager = HssTimerManager::new();

        let id = manager
            .add_timer(
                HssTimerId::DbiPollChangeStream,
                Duration::from_secs(10),
                None,
            )
            .unwrap();

        assert!(manager.stop_timer(id));
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn test_timer_manager_clear() {
        let manager = HssTimerManager::new();

        manager.add_timer(
            HssTimerId::DbiPollChangeStream,
            Duration::from_secs(10),
            None,
        );
        manager.add_timer(
            HssTimerId::DbiPollChangeStream,
            Duration::from_secs(20),
            None,
        );

        assert_eq!(manager.active_count(), 2);

        manager.clear();
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn test_timer_get_name() {
        assert_eq!(
            hss_timer_get_name(HssTimerId::DbiPollChangeStream),
            "HSS_TIMER_DBI_POLL_CHANGE_STREAM"
        );
    }
}
