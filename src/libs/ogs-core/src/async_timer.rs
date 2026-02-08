//! Async Timer Manager for NF Event Loops
//!
//! Provides a generic, tokio-based async timer system that all network functions
//! can use. Supports:
//! - Named timers with unique IDs
//! - One-shot and periodic (repeating) timers
//! - Cancel and reset operations
//! - Firing timer events into the NF's event channel
//! - Thread-safe operation via interior mutability
//!
//! This module complements the synchronous `OgsTimerMgr` in `timer.rs` by
//! providing an async-aware timer system suitable for tokio-based event loops.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

// ============================================================================
// Timer Types
// ============================================================================

/// Timer mode: one-shot fires once, periodic repeats at interval
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerMode {
    /// Fire once and then stop
    OneShot,
    /// Fire repeatedly at the given interval
    Periodic,
}

/// A timer entry stored in the async timer manager
#[derive(Debug, Clone)]
pub struct AsyncTimerEntry<T: Clone + fmt::Debug> {
    /// Unique timer handle ID
    pub id: u64,
    /// NF-specific timer type (e.g., NfInstanceHeartbeat, SbiClientWait)
    pub timer_type: T,
    /// Absolute expiration time
    pub expires_at: Instant,
    /// Timer duration (used for periodic restart)
    pub duration: Duration,
    /// Timer mode
    pub mode: TimerMode,
    /// Associated context data (e.g., NF instance ID, subscription ID, UE ID)
    pub data: Option<String>,
    /// Whether the timer is active
    pub active: bool,
}

impl<T: Clone + fmt::Debug> AsyncTimerEntry<T> {
    /// Create a new timer entry
    pub fn new(id: u64, timer_type: T, duration: Duration, mode: TimerMode, data: Option<String>) -> Self {
        Self {
            id,
            timer_type,
            expires_at: Instant::now() + duration,
            duration,
            mode,
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

    /// Reset the timer with the same duration
    pub fn reset(&mut self) {
        self.expires_at = Instant::now() + self.duration;
        self.active = true;
    }

    /// Reset the timer with a new duration
    pub fn reset_with_duration(&mut self, duration: Duration) {
        self.duration = duration;
        self.expires_at = Instant::now() + duration;
        self.active = true;
    }

    /// Get remaining time until expiration
    pub fn remaining(&self) -> Duration {
        if !self.active {
            return Duration::MAX;
        }
        let now = Instant::now();
        if now >= self.expires_at {
            Duration::ZERO
        } else {
            self.expires_at - now
        }
    }
}

// ============================================================================
// Async Timer Manager
// ============================================================================

/// Generic async timer manager that works with any NF's timer type.
///
/// `T` is the NF-specific timer ID enum (e.g., `NssfTimerId`, `BsfTimerId`).
///
/// # Usage
///
/// ```ignore
/// use ogs_core::async_timer::{AsyncTimerMgr, TimerMode};
///
/// let mgr = AsyncTimerMgr::<MyTimerId>::new();
///
/// // Start a one-shot timer
/// let id = mgr.start(MyTimerId::Heartbeat, Duration::from_secs(10), TimerMode::OneShot, None);
///
/// // In the event loop, poll for expired timers
/// let expired = mgr.process_expired();
/// for entry in expired {
///     // Dispatch entry.timer_type to state machine
/// }
///
/// // Cancel a timer
/// mgr.cancel(id);
///
/// // Reset a timer
/// mgr.reset(id);
/// ```
pub struct AsyncTimerMgr<T: Clone + fmt::Debug + Send + Sync + 'static> {
    /// Active timers indexed by handle ID
    timers: RwLock<HashMap<u64, AsyncTimerEntry<T>>>,
    /// Monotonically increasing timer handle counter
    next_id: AtomicU64,
}

impl<T: Clone + fmt::Debug + Send + Sync + 'static> AsyncTimerMgr<T> {
    /// Create a new async timer manager
    pub fn new() -> Self {
        Self {
            timers: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// Start a new timer and return its handle ID.
    ///
    /// - `timer_type`: NF-specific timer identifier
    /// - `duration`: how long until the timer fires
    /// - `mode`: OneShot or Periodic
    /// - `data`: optional context string (NF instance ID, etc.)
    pub fn start(
        &self,
        timer_type: T,
        duration: Duration,
        mode: TimerMode,
        data: Option<String>,
    ) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let entry = AsyncTimerEntry::new(id, timer_type.clone(), duration, mode, data);

        if let Ok(mut timers) = self.timers.write() {
            timers.insert(id, entry);
        }

        log::debug!(
            "AsyncTimer started: id={id} type={timer_type:?} duration={duration:?} mode={mode:?}"
        );
        id
    }

    /// Start a one-shot timer (convenience method)
    pub fn start_oneshot(
        &self,
        timer_type: T,
        duration: Duration,
        data: Option<String>,
    ) -> u64 {
        self.start(timer_type, duration, TimerMode::OneShot, data)
    }

    /// Start a periodic timer (convenience method)
    pub fn start_periodic(
        &self,
        timer_type: T,
        interval: Duration,
        data: Option<String>,
    ) -> u64 {
        self.start(timer_type, interval, TimerMode::Periodic, data)
    }

    /// Cancel a timer by handle ID. Returns true if the timer was found and cancelled.
    pub fn cancel(&self, id: u64) -> bool {
        if let Ok(mut timers) = self.timers.write() {
            if let Some(entry) = timers.get_mut(&id) {
                entry.cancel();
                log::debug!("AsyncTimer cancelled: id={} type={:?}", id, entry.timer_type);
                return true;
            }
        }
        false
    }

    /// Remove a timer entirely from the manager. Returns the entry if found.
    pub fn remove(&self, id: u64) -> Option<AsyncTimerEntry<T>> {
        if let Ok(mut timers) = self.timers.write() {
            let removed = timers.remove(&id);
            if let Some(ref entry) = removed {
                log::debug!("AsyncTimer removed: id={} type={:?}", id, entry.timer_type);
            }
            return removed;
        }
        None
    }

    /// Reset a timer to fire again from now with its original duration.
    /// Returns true if the timer was found and reset.
    pub fn reset(&self, id: u64) -> bool {
        if let Ok(mut timers) = self.timers.write() {
            if let Some(entry) = timers.get_mut(&id) {
                entry.reset();
                log::debug!("AsyncTimer reset: id={} type={:?}", id, entry.timer_type);
                return true;
            }
        }
        false
    }

    /// Reset a timer with a new duration. Returns true if found and reset.
    pub fn reset_with_duration(&self, id: u64, duration: Duration) -> bool {
        if let Ok(mut timers) = self.timers.write() {
            if let Some(entry) = timers.get_mut(&id) {
                entry.reset_with_duration(duration);
                log::debug!(
                    "AsyncTimer reset with new duration: id={} type={:?} duration={:?}",
                    id, entry.timer_type, duration
                );
                return true;
            }
        }
        false
    }

    /// Process all expired timers and return them.
    ///
    /// - One-shot timers are removed from the manager.
    /// - Periodic timers are reset to fire again at the next interval.
    ///
    /// The returned entries should be dispatched to the NF's state machine.
    pub fn process_expired(&self) -> Vec<AsyncTimerEntry<T>> {
        let mut expired = Vec::new();
        let mut to_remove = Vec::new();

        if let Ok(mut timers) = self.timers.write() {
            for (id, entry) in timers.iter_mut() {
                if entry.is_expired() {
                    expired.push(entry.clone());
                    match entry.mode {
                        TimerMode::OneShot => {
                            to_remove.push(*id);
                        }
                        TimerMode::Periodic => {
                            // Reset for next interval
                            entry.expires_at = Instant::now() + entry.duration;
                        }
                    }
                }
            }

            // Remove one-shot timers that fired
            for id in to_remove {
                timers.remove(&id);
            }
        }

        expired
    }

    /// Get the duration until the next timer expires.
    /// Returns `None` if there are no active timers.
    /// Returns `Some(Duration::ZERO)` if a timer has already expired.
    pub fn next_expiration(&self) -> Option<Duration> {
        if let Ok(timers) = self.timers.read() {
            let mut min_remaining: Option<Duration> = None;

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

    /// Get the number of active timers (including expired but not yet processed)
    pub fn count(&self) -> usize {
        self.timers.read().map(|t| t.len()).unwrap_or(0)
    }

    /// Get the number of active (non-cancelled) timers
    pub fn active_count(&self) -> usize {
        self.timers
            .read()
            .map(|t| t.values().filter(|e| e.active).count())
            .unwrap_or(0)
    }

    /// Check if a timer exists by handle ID
    pub fn exists(&self, id: u64) -> bool {
        self.timers
            .read()
            .map(|t| t.contains_key(&id))
            .unwrap_or(false)
    }

    /// Check if a timer is active by handle ID
    pub fn is_active(&self, id: u64) -> bool {
        self.timers
            .read()
            .map(|t| t.get(&id).map(|e| e.active).unwrap_or(false))
            .unwrap_or(false)
    }

    /// Clear all timers
    pub fn clear(&self) {
        if let Ok(mut timers) = self.timers.write() {
            timers.clear();
        }
        log::debug!("AsyncTimer: all timers cleared");
    }

    /// Cancel all timers of a specific type
    pub fn cancel_all_of_type(&self, timer_type: &T) -> usize
    where
        T: PartialEq,
    {
        let mut cancelled = 0;
        if let Ok(mut timers) = self.timers.write() {
            for entry in timers.values_mut() {
                if entry.active && entry.timer_type == *timer_type {
                    entry.cancel();
                    cancelled += 1;
                }
            }
        }
        if cancelled > 0 {
            log::debug!(
                "AsyncTimer: cancelled {cancelled} timers of type {timer_type:?}"
            );
        }
        cancelled
    }

    /// Find all active timers matching a specific data string
    pub fn find_by_data(&self, data: &str) -> Vec<u64> {
        self.timers
            .read()
            .map(|t| {
                t.values()
                    .filter(|e| e.active && e.data.as_deref() == Some(data))
                    .map(|e| e.id)
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl<T: Clone + fmt::Debug + Send + Sync + 'static> Default for AsyncTimerMgr<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone + fmt::Debug + Send + Sync + 'static> fmt::Debug for AsyncTimerMgr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.count();
        let active = self.active_count();
        f.debug_struct("AsyncTimerMgr")
            .field("total", &count)
            .field("active", &active)
            .finish()
    }
}

// ============================================================================
// Default Timer Durations (common across NFs)
// ============================================================================

/// Default timer duration constants used by SBI-based NFs.
/// Mirrors the C implementation's timer.h defaults.
pub mod defaults {
    use std::time::Duration;

    /// NF instance registration interval (default: 3 seconds)
    pub const NF_INSTANCE_REGISTRATION_INTERVAL: Duration = Duration::from_secs(3);

    /// NF instance heartbeat interval (default: 10 seconds)
    pub const NF_INSTANCE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

    /// NF instance no heartbeat timeout (default: 30 seconds)
    pub const NF_INSTANCE_NO_HEARTBEAT: Duration = Duration::from_secs(30);

    /// NF instance validity (default: 3600 seconds = 1 hour)
    pub const NF_INSTANCE_VALIDITY: Duration = Duration::from_secs(3600);

    /// Subscription validity (default: 86400 seconds = 24 hours)
    pub const SUBSCRIPTION_VALIDITY: Duration = Duration::from_secs(86400);

    /// Subscription patch interval (default: 86400 seconds = 24 hours)
    pub const SUBSCRIPTION_PATCH: Duration = Duration::from_secs(86400);

    /// SBI client wait timeout (default: 2 seconds)
    pub const SBI_CLIENT_WAIT: Duration = Duration::from_secs(2);
}

// ============================================================================
// Helper: compute sleep duration for event loop tick
// ============================================================================

/// Compute the optimal sleep duration for the next event loop iteration.
///
/// Returns the minimum of:
/// - The time until the next timer expires
/// - The provided `max_interval` (upper bound to prevent indefinite sleeping)
///
/// If no timers are active, returns `max_interval`.
pub fn compute_poll_interval<T: Clone + fmt::Debug + Send + Sync + 'static>(
    mgr: &AsyncTimerMgr<T>,
    max_interval: Duration,
) -> Duration {
    match mgr.next_expiration() {
        Some(next) if next < max_interval => {
            // Add a small epsilon to avoid busy-looping on boundary
            if next.is_zero() {
                Duration::from_millis(1)
            } else {
                next
            }
        }
        _ => max_interval,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TestTimerId {
        Heartbeat,
        Registration,
        ClientWait,
    }

    #[test]
    fn test_timer_mgr_new() {
        let mgr = AsyncTimerMgr::<TestTimerId>::new();
        assert_eq!(mgr.count(), 0);
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn test_timer_start_and_count() {
        let mgr = AsyncTimerMgr::<TestTimerId>::new();

        let id1 = mgr.start_oneshot(TestTimerId::Heartbeat, Duration::from_secs(10), None);
        let id2 = mgr.start_periodic(
            TestTimerId::Registration,
            Duration::from_secs(3),
            Some("nf-001".to_string()),
        );

        assert_eq!(mgr.count(), 2);
        assert!(mgr.exists(id1));
        assert!(mgr.exists(id2));
        assert!(mgr.is_active(id1));
        assert!(mgr.is_active(id2));
    }

    #[test]
    fn test_timer_cancel() {
        let mgr = AsyncTimerMgr::<TestTimerId>::new();

        let id = mgr.start_oneshot(TestTimerId::Heartbeat, Duration::from_secs(10), None);
        assert!(mgr.is_active(id));

        assert!(mgr.cancel(id));
        assert!(!mgr.is_active(id));
        assert!(mgr.exists(id)); // Still in map, just cancelled
    }

    #[test]
    fn test_timer_remove() {
        let mgr = AsyncTimerMgr::<TestTimerId>::new();

        let id = mgr.start_oneshot(TestTimerId::Heartbeat, Duration::from_secs(10), None);
        assert_eq!(mgr.count(), 1);

        let entry = mgr.remove(id);
        assert!(entry.is_some());
        assert_eq!(mgr.count(), 0);
        assert!(!mgr.exists(id));
    }

    #[test]
    fn test_timer_reset() {
        let mgr = AsyncTimerMgr::<TestTimerId>::new();

        let id = mgr.start_oneshot(TestTimerId::ClientWait, Duration::from_millis(50), None);

        // Wait for it to be near expiry
        thread::sleep(Duration::from_millis(30));

        // Reset it
        assert!(mgr.reset(id));
        assert!(mgr.is_active(id));

        // It should not have expired yet
        let expired = mgr.process_expired();
        assert!(expired.is_empty());
    }

    #[test]
    fn test_timer_reset_with_duration() {
        let mgr = AsyncTimerMgr::<TestTimerId>::new();

        let id = mgr.start_oneshot(TestTimerId::ClientWait, Duration::from_millis(10), None);

        // Reset with longer duration
        assert!(mgr.reset_with_duration(id, Duration::from_secs(10)));

        thread::sleep(Duration::from_millis(20));

        // Should NOT have expired because we reset to 10s
        let expired = mgr.process_expired();
        assert!(expired.is_empty());
    }

    #[test]
    fn test_oneshot_timer_expires() {
        let mgr = AsyncTimerMgr::<TestTimerId>::new();

        mgr.start_oneshot(
            TestTimerId::ClientWait,
            Duration::from_millis(10),
            Some("test-data".to_string()),
        );

        thread::sleep(Duration::from_millis(20));

        let expired = mgr.process_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].timer_type, TestTimerId::ClientWait);
        assert_eq!(expired[0].data, Some("test-data".to_string()));
        assert_eq!(expired[0].mode, TimerMode::OneShot);

        // One-shot timer should be removed
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_periodic_timer_repeats() {
        let mgr = AsyncTimerMgr::<TestTimerId>::new();

        let id = mgr.start_periodic(TestTimerId::Heartbeat, Duration::from_millis(10), None);

        // Wait for first expiry
        thread::sleep(Duration::from_millis(20));

        let expired = mgr.process_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].mode, TimerMode::Periodic);

        // Periodic timer should still be in the manager
        assert!(mgr.exists(id));
        assert!(mgr.is_active(id));

        // Wait for second expiry
        thread::sleep(Duration::from_millis(20));

        let expired2 = mgr.process_expired();
        assert_eq!(expired2.len(), 1);
        assert!(mgr.exists(id));
    }

    #[test]
    fn test_cancelled_timer_does_not_expire() {
        let mgr = AsyncTimerMgr::<TestTimerId>::new();

        let id = mgr.start_oneshot(TestTimerId::ClientWait, Duration::from_millis(10), None);
        mgr.cancel(id);

        thread::sleep(Duration::from_millis(20));

        let expired = mgr.process_expired();
        assert!(expired.is_empty());
    }

    #[test]
    fn test_next_expiration() {
        let mgr = AsyncTimerMgr::<TestTimerId>::new();

        // No timers
        assert!(mgr.next_expiration().is_none());

        mgr.start_oneshot(TestTimerId::Heartbeat, Duration::from_secs(10), None);
        mgr.start_oneshot(TestTimerId::ClientWait, Duration::from_secs(2), None);

        let next = mgr.next_expiration();
        assert!(next.is_some());
        assert!(next.unwrap() <= Duration::from_secs(2));
    }

    #[test]
    fn test_cancel_all_of_type() {
        let mgr = AsyncTimerMgr::<TestTimerId>::new();

        mgr.start_oneshot(TestTimerId::Heartbeat, Duration::from_secs(10), None);
        mgr.start_oneshot(TestTimerId::Heartbeat, Duration::from_secs(20), None);
        mgr.start_oneshot(TestTimerId::ClientWait, Duration::from_secs(5), None);

        let cancelled = mgr.cancel_all_of_type(&TestTimerId::Heartbeat);
        assert_eq!(cancelled, 2);
        assert_eq!(mgr.active_count(), 1); // Only ClientWait remains active
    }

    #[test]
    fn test_find_by_data() {
        let mgr = AsyncTimerMgr::<TestTimerId>::new();

        mgr.start_oneshot(
            TestTimerId::Heartbeat,
            Duration::from_secs(10),
            Some("nf-001".to_string()),
        );
        mgr.start_oneshot(
            TestTimerId::Registration,
            Duration::from_secs(10),
            Some("nf-001".to_string()),
        );
        mgr.start_oneshot(
            TestTimerId::ClientWait,
            Duration::from_secs(10),
            Some("nf-002".to_string()),
        );

        let ids = mgr.find_by_data("nf-001");
        assert_eq!(ids.len(), 2);

        let ids2 = mgr.find_by_data("nf-002");
        assert_eq!(ids2.len(), 1);

        let ids3 = mgr.find_by_data("nf-999");
        assert!(ids3.is_empty());
    }

    #[test]
    fn test_clear() {
        let mgr = AsyncTimerMgr::<TestTimerId>::new();

        mgr.start_oneshot(TestTimerId::Heartbeat, Duration::from_secs(10), None);
        mgr.start_oneshot(TestTimerId::ClientWait, Duration::from_secs(5), None);
        assert_eq!(mgr.count(), 2);

        mgr.clear();
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_compute_poll_interval() {
        let mgr = AsyncTimerMgr::<TestTimerId>::new();
        let max = Duration::from_millis(100);

        // No timers: should return max
        assert_eq!(compute_poll_interval(&mgr, max), max);

        // Timer that expires in 50ms
        mgr.start_oneshot(TestTimerId::ClientWait, Duration::from_millis(50), None);
        let interval = compute_poll_interval(&mgr, max);
        assert!(interval <= Duration::from_millis(50));
        assert!(interval > Duration::ZERO);

        // Timer that expired: should return small value
        thread::sleep(Duration::from_millis(60));
        let interval2 = compute_poll_interval(&mgr, max);
        assert!(interval2 <= Duration::from_millis(1));
    }

    #[test]
    fn test_multiple_timers_mixed_expiry() {
        let mgr = AsyncTimerMgr::<TestTimerId>::new();

        let _id1 = mgr.start_oneshot(TestTimerId::ClientWait, Duration::from_millis(10), None);
        let id2 = mgr.start_oneshot(TestTimerId::Heartbeat, Duration::from_secs(100), None);
        let _id3 = mgr.start_oneshot(TestTimerId::Registration, Duration::from_millis(10), None);

        thread::sleep(Duration::from_millis(20));

        let expired = mgr.process_expired();
        assert_eq!(expired.len(), 2);

        // Long timer should still be running
        assert!(mgr.exists(id2));
        assert!(mgr.is_active(id2));
        assert_eq!(mgr.count(), 1);
    }
}
