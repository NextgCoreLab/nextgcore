//! AUSF Timer Management
//!
//! Timer management for AUSF operations

use crate::event::AusfTimerId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Timer entry
#[derive(Debug, Clone)]
pub struct TimerEntry {
    /// Timer ID
    pub id: u64,
    /// Timer type
    pub timer_type: AusfTimerId,
    /// Expiration time
    pub expires_at: Instant,
    /// Associated data (e.g., NF instance ID, subscription ID)
    pub data: Option<String>,
    /// Whether the timer is active
    pub active: bool,
}

impl TimerEntry {
    /// Create a new timer entry
    pub fn new(id: u64, timer_type: AusfTimerId, duration: Duration, data: Option<String>) -> Self {
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

    /// Cancel the timer
    pub fn cancel(&mut self) {
        self.active = false;
    }

    /// Get remaining time until expiration
    pub fn remaining(&self) -> Duration {
        if self.is_expired() {
            Duration::ZERO
        } else {
            self.expires_at - Instant::now()
        }
    }
}

/// AUSF Timer Manager
pub struct AusfTimerManager {
    /// Timer entries
    timers: RwLock<HashMap<u64, TimerEntry>>,
    /// Next timer ID
    next_id: std::sync::atomic::AtomicU64,
}

impl AusfTimerManager {
    /// Create a new timer manager
    pub fn new() -> Self {
        Self {
            timers: RwLock::new(HashMap::new()),
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Start a new timer
    pub fn start(
        &self,
        timer_type: AusfTimerId,
        duration: Duration,
        data: Option<String>,
    ) -> u64 {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let entry = TimerEntry::new(id, timer_type, duration, data);

        if let Ok(mut timers) = self.timers.write() {
            timers.insert(id, entry);
        }

        log::debug!("Timer started: {id} ({timer_type:?})");
        id
    }

    /// Stop a timer
    pub fn stop(&self, id: u64) -> bool {
        if let Ok(mut timers) = self.timers.write() {
            if let Some(entry) = timers.get_mut(&id) {
                entry.cancel();
                log::debug!("Timer stopped: {id}");
                return true;
            }
        }
        false
    }

    /// Remove a timer
    pub fn remove(&self, id: u64) -> Option<TimerEntry> {
        if let Ok(mut timers) = self.timers.write() {
            return timers.remove(&id);
        }
        None
    }

    /// Get expired timers
    pub fn get_expired(&self) -> Vec<TimerEntry> {
        let mut expired = Vec::new();

        if let Ok(timers) = self.timers.read() {
            for entry in timers.values() {
                if entry.is_expired() {
                    expired.push(entry.clone());
                }
            }
        }

        expired
    }

    /// Process expired timers and remove them
    pub fn process_expired(&self) -> Vec<TimerEntry> {
        let expired = self.get_expired();

        if let Ok(mut timers) = self.timers.write() {
            for entry in &expired {
                timers.remove(&entry.id);
            }
        }

        expired
    }

    /// Get the next expiration time
    pub fn next_expiration(&self) -> Option<Duration> {
        if let Ok(timers) = self.timers.read() {
            let mut min_remaining = None;

            for entry in timers.values() {
                if entry.active {
                    let remaining = entry.remaining();
                    match min_remaining {
                        None => min_remaining = Some(remaining),
                        Some(current) if remaining < current => min_remaining = Some(remaining),
                        _ => {}
                    }
                }
            }

            return min_remaining;
        }
        None
    }

    /// Get timer count
    pub fn count(&self) -> usize {
        self.timers.read().map(|t| t.len()).unwrap_or(0)
    }

    /// Clear all timers
    pub fn clear(&self) {
        if let Ok(mut timers) = self.timers.write() {
            timers.clear();
        }
    }
}

impl Default for AusfTimerManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Global timer manager
static GLOBAL_TIMER_MANAGER: std::sync::OnceLock<Arc<AusfTimerManager>> =
    std::sync::OnceLock::new();

/// Get the global timer manager
pub fn timer_manager() -> Arc<AusfTimerManager> {
    GLOBAL_TIMER_MANAGER
        .get_or_init(|| Arc::new(AusfTimerManager::new()))
        .clone()
}

/// Get timer name
pub fn ausf_timer_get_name(timer_id: AusfTimerId) -> &'static str {
    timer_id.name()
}

/// Default timer durations
pub mod defaults {
    use super::*;

    /// NF instance registration interval (default: 3 seconds)
    pub const NF_INSTANCE_REGISTRATION_INTERVAL: Duration = Duration::from_secs(3);

    /// NF instance heartbeat interval (default: 10 seconds)
    pub const NF_INSTANCE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

    /// NF instance no heartbeat timeout (default: 30 seconds)
    pub const NF_INSTANCE_NO_HEARTBEAT: Duration = Duration::from_secs(30);

    /// Subscription validity (default: 86400 seconds = 24 hours)
    pub const SUBSCRIPTION_VALIDITY: Duration = Duration::from_secs(86400);

    /// SBI client wait timeout (default: 2 seconds)
    pub const SBI_CLIENT_WAIT: Duration = Duration::from_secs(2);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_timer_entry_new() {
        let entry = TimerEntry::new(
            1,
            AusfTimerId::NfInstanceHeartbeatInterval,
            Duration::from_secs(10),
            None,
        );
        assert_eq!(entry.id, 1);
        assert!(entry.active);
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_timer_entry_expiration() {
        let entry = TimerEntry::new(
            1,
            AusfTimerId::SbiClientWait,
            Duration::from_millis(10),
            None,
        );
        assert!(!entry.is_expired());

        thread::sleep(Duration::from_millis(20));
        assert!(entry.is_expired());
    }

    #[test]
    fn test_timer_entry_cancel() {
        let mut entry = TimerEntry::new(
            1,
            AusfTimerId::NfInstanceHeartbeatInterval,
            Duration::from_millis(10),
            None,
        );
        entry.cancel();
        assert!(!entry.active);

        thread::sleep(Duration::from_millis(20));
        assert!(!entry.is_expired()); // Cancelled timers don't expire
    }

    #[test]
    fn test_timer_manager_start_stop() {
        let manager = AusfTimerManager::new();

        let id = manager.start(
            AusfTimerId::NfInstanceHeartbeatInterval,
            Duration::from_secs(10),
            None,
        );
        assert_eq!(manager.count(), 1);

        assert!(manager.stop(id));
        assert_eq!(manager.count(), 1); // Still in map, just cancelled
    }

    #[test]
    fn test_timer_manager_remove() {
        let manager = AusfTimerManager::new();

        let id = manager.start(
            AusfTimerId::NfInstanceHeartbeatInterval,
            Duration::from_secs(10),
            None,
        );
        assert_eq!(manager.count(), 1);

        let entry = manager.remove(id);
        assert!(entry.is_some());
        assert_eq!(manager.count(), 0);
    }

    #[test]
    fn test_timer_manager_get_expired() {
        let manager = AusfTimerManager::new();

        manager.start(
            AusfTimerId::SbiClientWait,
            Duration::from_millis(10),
            Some("test".to_string()),
        );

        thread::sleep(Duration::from_millis(20));

        let expired = manager.get_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].data, Some("test".to_string()));
    }

    #[test]
    fn test_timer_manager_process_expired() {
        let manager = AusfTimerManager::new();

        manager.start(
            AusfTimerId::SbiClientWait,
            Duration::from_millis(10),
            None,
        );
        assert_eq!(manager.count(), 1);

        thread::sleep(Duration::from_millis(20));

        let expired = manager.process_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(manager.count(), 0);
    }

    #[test]
    fn test_timer_manager_next_expiration() {
        let manager = AusfTimerManager::new();

        manager.start(
            AusfTimerId::NfInstanceHeartbeatInterval,
            Duration::from_secs(10),
            None,
        );
        manager.start(
            AusfTimerId::SbiClientWait,
            Duration::from_secs(2),
            None,
        );

        let next = manager.next_expiration();
        assert!(next.is_some());
        assert!(next.unwrap() <= Duration::from_secs(2));
    }

    #[test]
    fn test_timer_manager_clear() {
        let manager = AusfTimerManager::new();

        manager.start(
            AusfTimerId::NfInstanceHeartbeatInterval,
            Duration::from_secs(10),
            None,
        );
        manager.start(
            AusfTimerId::SbiClientWait,
            Duration::from_secs(2),
            None,
        );
        assert_eq!(manager.count(), 2);

        manager.clear();
        assert_eq!(manager.count(), 0);
    }
}
