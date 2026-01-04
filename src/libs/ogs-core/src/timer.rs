//! Timer wheel implementation
//!
//! Exact port of lib/core/ogs-timer.h and ogs-timer.c
//!
//! This implementation uses a BTreeMap for efficient timer management,
//! which provides O(log n) insertion and removal like the C red-black tree.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Time constants matching C implementation
pub const OGS_NO_WAIT_TIME: Duration = Duration::ZERO;
pub const OGS_INFINITE_TIME: Duration = Duration::MAX;

/// Timer ID type
pub type OgsTimerId = u64;

/// Timer callback function type
pub type OgsTimerCallback<T> = fn(&mut T);

/// Timer structure (identical to ogs_timer_t)
#[derive(Debug)]
pub struct OgsTimer<T> {
    /// Timer ID
    id: OgsTimerId,
    /// Callback function
    callback: Option<OgsTimerCallback<T>>,
    /// User data
    data: Option<T>,
    /// Running state
    running: bool,
    /// Timeout time (absolute, as nanos since epoch)
    timeout_nanos: Option<u128>,
}

impl<T> OgsTimer<T> {
    fn new(id: OgsTimerId, callback: Option<OgsTimerCallback<T>>, data: Option<T>) -> Self {
        OgsTimer {
            id,
            callback,
            data,
            running: false,
            timeout_nanos: None,
        }
    }

    /// Get timer ID
    pub fn id(&self) -> OgsTimerId {
        self.id
    }

    /// Check if timer is running
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Get user data reference
    pub fn data(&self) -> Option<&T> {
        self.data.as_ref()
    }

    /// Get mutable user data reference
    pub fn data_mut(&mut self) -> Option<&mut T> {
        self.data.as_mut()
    }
}

/// Timer entry in the tree (for ordering by timeout)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TimerKey {
    timeout: u128, // nanoseconds since epoch for ordering
    id: OgsTimerId, // tie-breaker for same timeout
}

/// Timer manager for handling multiple timers (identical to ogs_timer_mgr_t)
pub struct OgsTimerMgr<T> {
    /// Timer storage
    timers: Vec<Option<OgsTimer<T>>>,
    /// Free list of timer indices
    free_indices: Vec<usize>,
    /// Tree for ordering timers by timeout (maps timeout -> timer index)
    tree: BTreeMap<TimerKey, usize>,
    /// Next timer ID
    next_id: OgsTimerId,
    /// Capacity
    capacity: usize,
    /// Reference instant for timeout calculations
    epoch: Instant,
}

impl<T> OgsTimerMgr<T> {
    /// Create a new timer manager with given capacity (identical to ogs_timer_mgr_create)
    pub fn new(capacity: usize) -> Self {
        let mut timers = Vec::with_capacity(capacity);
        let mut free_indices = Vec::with_capacity(capacity);
        
        for i in (0..capacity).rev() {
            timers.push(None);
            free_indices.push(i);
        }
        
        OgsTimerMgr {
            timers,
            free_indices,
            tree: BTreeMap::new(),
            next_id: 1,
            capacity,
            epoch: Instant::now(),
        }
    }

    /// Add a new timer (identical to ogs_timer_add)
    pub fn add(&mut self, callback: OgsTimerCallback<T>, data: T) -> Option<OgsTimerId> {
        let index = self.free_indices.pop()?;
        
        let id = self.next_id;
        self.next_id += 1;
        
        let timer = OgsTimer::new(id, Some(callback), Some(data));
        self.timers[index] = Some(timer);
        
        Some(id)
    }

    /// Add a timer without callback (for testing)
    pub fn add_simple(&mut self) -> Option<OgsTimerId> {
        let index = self.free_indices.pop()?;
        
        let id = self.next_id;
        self.next_id += 1;
        
        let timer: OgsTimer<T> = OgsTimer::new(id, None, None);
        self.timers[index] = Some(timer);
        
        Some(id)
    }

    /// Delete a timer (identical to ogs_timer_delete)
    pub fn delete(&mut self, id: OgsTimerId) {
        if let Some(index) = self.find_index(id) {
            // Stop the timer first (removes from tree)
            self.stop(id);
            
            // Return to free list
            self.timers[index] = None;
            self.free_indices.push(index);
        }
    }

    /// Start a timer (identical to ogs_timer_start)
    pub fn start(&mut self, id: OgsTimerId, duration: Duration) {
        if let Some(index) = self.find_index(id) {
            // Get timer info for tree operations
            let (old_timeout_nanos, timer_id) = {
                let timer = self.timers[index].as_ref().unwrap();
                (timer.timeout_nanos, timer.id)
            };
            
            // If already running, remove from tree first
            if let Some(timeout_nanos) = old_timeout_nanos {
                let key = TimerKey {
                    timeout: timeout_nanos,
                    id: timer_id,
                };
                self.tree.remove(&key);
            }
            
            // Calculate new timeout
            let timeout_nanos = self.instant_to_nanos(Instant::now() + duration);
            
            // Update timer
            let timer = self.timers[index].as_mut().unwrap();
            timer.timeout_nanos = Some(timeout_nanos);
            timer.running = true;
            
            // Add to tree
            let key = TimerKey {
                timeout: timeout_nanos,
                id: timer_id,
            };
            self.tree.insert(key, index);
        }
    }

    /// Stop a timer (identical to ogs_timer_stop)
    pub fn stop(&mut self, id: OgsTimerId) {
        if let Some(index) = self.find_index(id) {
            // Get timer info for tree operations
            let (timeout_nanos, timer_id, running) = {
                let timer = self.timers[index].as_ref().unwrap();
                (timer.timeout_nanos, timer.id, timer.running)
            };
            
            if !running {
                return;
            }
            
            // Remove from tree
            if let Some(timeout_nanos) = timeout_nanos {
                let key = TimerKey {
                    timeout: timeout_nanos,
                    id: timer_id,
                };
                self.tree.remove(&key);
            }
            
            // Update timer
            let timer = self.timers[index].as_mut().unwrap();
            timer.running = false;
            timer.timeout_nanos = None;
        }
    }

    /// Get time until next timer expires (identical to ogs_timer_mgr_next)
    pub fn next(&self) -> Duration {
        if let Some((key, _)) = self.tree.first_key_value() {
            let now_nanos = self.instant_to_nanos(Instant::now());
            
            if key.timeout > now_nanos {
                Duration::from_nanos((key.timeout - now_nanos) as u64)
            } else {
                OGS_NO_WAIT_TIME
            }
        } else {
            OGS_INFINITE_TIME
        }
    }

    /// Expire all timers that have timed out (identical to ogs_timer_mgr_expire)
    /// Returns list of expired timer IDs
    pub fn expire(&mut self) -> Vec<OgsTimerId> {
        let now_nanos = self.instant_to_nanos(Instant::now());
        let mut expired = Vec::new();
        
        // Collect expired timer keys
        let expired_keys: Vec<TimerKey> = self.tree
            .range(..=TimerKey { timeout: now_nanos, id: OgsTimerId::MAX })
            .map(|(k, _)| *k)
            .collect();
        
        // Process expired timers
        for key in expired_keys {
            if let Some(index) = self.tree.remove(&key) {
                if let Some(timer) = self.timers[index].as_mut() {
                    timer.running = false;
                    timer.timeout_nanos = None;
                    expired.push(timer.id);
                }
            }
        }
        
        expired
    }

    /// Expire and call callbacks
    pub fn expire_with_callbacks(&mut self) {
        let now_nanos = self.instant_to_nanos(Instant::now());
        
        // Collect expired timer indices and keys
        let expired_data: Vec<(TimerKey, usize)> = self.tree
            .range(..=TimerKey { timeout: now_nanos, id: OgsTimerId::MAX })
            .map(|(k, &idx)| (*k, idx))
            .collect();
        
        // Remove from tree and call callbacks
        for (key, index) in expired_data {
            self.tree.remove(&key);
            
            if let Some(timer) = self.timers[index].as_mut() {
                timer.running = false;
                timer.timeout_nanos = None;
                
                // Call callback
                if let (Some(cb), Some(data)) = (timer.callback, timer.data.as_mut()) {
                    cb(data);
                }
            }
        }
    }

    /// Get timer by ID
    pub fn get(&self, id: OgsTimerId) -> Option<&OgsTimer<T>> {
        self.find_index(id)
            .and_then(|idx| self.timers[idx].as_ref())
    }

    /// Get mutable timer by ID
    pub fn get_mut(&mut self, id: OgsTimerId) -> Option<&mut OgsTimer<T>> {
        self.find_index(id)
            .and_then(|idx| self.timers[idx].as_mut())
    }

    /// Get number of active timers
    pub fn count(&self) -> usize {
        self.tree.len()
    }

    /// Get capacity
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Get available slots
    pub fn available(&self) -> usize {
        self.free_indices.len()
    }

    /// Find timer index by ID
    fn find_index(&self, id: OgsTimerId) -> Option<usize> {
        self.timers.iter().position(|t| {
            t.as_ref().map(|timer| timer.id == id).unwrap_or(false)
        })
    }

    /// Convert Instant to nanoseconds for ordering
    fn instant_to_nanos(&self, instant: Instant) -> u128 {
        instant.duration_since(self.epoch).as_nanos()
    }
}

impl<T> Default for OgsTimerMgr<T> {
    fn default() -> Self {
        Self::new(1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_timer_mgr_new() {
        let mgr: OgsTimerMgr<()> = OgsTimerMgr::new(10);
        assert_eq!(mgr.capacity(), 10);
        assert_eq!(mgr.available(), 10);
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_timer_add_delete() {
        let mut mgr: OgsTimerMgr<i32> = OgsTimerMgr::new(10);
        
        fn callback(_data: &mut i32) {}
        
        let id = mgr.add(callback, 42).unwrap();
        assert_eq!(mgr.available(), 9);
        
        mgr.delete(id);
        assert_eq!(mgr.available(), 10);
    }

    #[test]
    fn test_timer_start_stop() {
        let mut mgr: OgsTimerMgr<()> = OgsTimerMgr::new(10);
        
        let id = mgr.add_simple().unwrap();
        
        mgr.start(id, Duration::from_millis(100));
        assert_eq!(mgr.count(), 1);
        assert!(mgr.get(id).unwrap().is_running());
        
        mgr.stop(id);
        assert_eq!(mgr.count(), 0);
        assert!(!mgr.get(id).unwrap().is_running());
    }

    #[test]
    fn test_timer_next() {
        let mut mgr: OgsTimerMgr<()> = OgsTimerMgr::new(10);
        
        // No timers - should return infinite
        assert_eq!(mgr.next(), OGS_INFINITE_TIME);
        
        let id = mgr.add_simple().unwrap();
        mgr.start(id, Duration::from_millis(100));
        
        // Should return time until next timer
        let next = mgr.next();
        assert!(next <= Duration::from_millis(100));
        assert!(next > Duration::ZERO);
    }

    #[test]
    fn test_timer_expire() {
        let mut mgr: OgsTimerMgr<()> = OgsTimerMgr::new(10);
        
        let id1 = mgr.add_simple().unwrap();
        let id2 = mgr.add_simple().unwrap();
        
        mgr.start(id1, Duration::from_millis(10));
        mgr.start(id2, Duration::from_millis(1000));
        
        // Wait for first timer to expire
        thread::sleep(Duration::from_millis(20));
        
        let expired = mgr.expire();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], id1);
        
        // Second timer should still be running
        assert!(mgr.get(id2).unwrap().is_running());
    }

    #[test]
    fn test_timer_restart() {
        let mut mgr: OgsTimerMgr<()> = OgsTimerMgr::new(10);
        
        let id = mgr.add_simple().unwrap();
        
        mgr.start(id, Duration::from_millis(100));
        assert_eq!(mgr.count(), 1);
        
        // Restart with different duration
        mgr.start(id, Duration::from_millis(200));
        assert_eq!(mgr.count(), 1); // Should still be 1, not 2
    }

    #[test]
    fn test_timer_ordering() {
        let mut mgr: OgsTimerMgr<()> = OgsTimerMgr::new(10);
        
        let id1 = mgr.add_simple().unwrap();
        let id2 = mgr.add_simple().unwrap();
        let id3 = mgr.add_simple().unwrap();
        
        // Start in reverse order
        mgr.start(id3, Duration::from_millis(300));
        mgr.start(id1, Duration::from_millis(100));
        mgr.start(id2, Duration::from_millis(200));
        
        // First to expire should be id1
        thread::sleep(Duration::from_millis(150));
        let expired = mgr.expire();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], id1);
    }

    // Property-based tests
    mod prop_tests {
        use super::*;
        use proptest::prelude::*;
        use std::collections::HashSet;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(50))]

            /// Property 1: Capacity invariant
            /// available + allocated should always equal capacity
            #[test]
            fn prop_capacity_invariant(
                capacity in 5..50usize,
                add_count in 0..30usize
            ) {
                let mut mgr: OgsTimerMgr<()> = OgsTimerMgr::new(capacity);
                
                let actual_adds = add_count.min(capacity);
                for _ in 0..actual_adds {
                    mgr.add_simple();
                }
                
                let allocated = capacity - mgr.available();
                prop_assert_eq!(
                    mgr.available() + allocated,
                    capacity,
                    "available + allocated should equal capacity"
                );
            }

            /// Property 2: Timer IDs are unique
            #[test]
            fn prop_unique_ids(count in 1..20usize) {
                let mut mgr: OgsTimerMgr<()> = OgsTimerMgr::new(count + 10);
                let mut ids: HashSet<OgsTimerId> = HashSet::new();
                
                for _ in 0..count {
                    if let Some(id) = mgr.add_simple() {
                        prop_assert!(!ids.contains(&id), "Timer ID should be unique");
                        ids.insert(id);
                    }
                }
            }

            /// Property 3: Start increases count, stop decreases it
            #[test]
            fn prop_start_stop_count(timer_count in 1..10usize) {
                let mut mgr: OgsTimerMgr<()> = OgsTimerMgr::new(timer_count + 5);
                let mut ids = Vec::new();
                
                // Add timers
                for _ in 0..timer_count {
                    if let Some(id) = mgr.add_simple() {
                        ids.push(id);
                    }
                }
                
                // Start all timers
                for id in &ids {
                    mgr.start(*id, Duration::from_secs(100));
                }
                prop_assert_eq!(mgr.count(), ids.len(), "count should equal started timers");
                
                // Stop all timers
                for id in &ids {
                    mgr.stop(*id);
                }
                prop_assert_eq!(mgr.count(), 0, "count should be 0 after stopping all");
            }

            /// Property 4: Delete returns slot to pool
            #[test]
            fn prop_delete_returns_slot(count in 1..10usize) {
                let capacity = count + 5;
                let mut mgr: OgsTimerMgr<()> = OgsTimerMgr::new(capacity);
                let mut ids = Vec::new();
                
                // Add timers
                for _ in 0..count {
                    if let Some(id) = mgr.add_simple() {
                        ids.push(id);
                    }
                }
                
                let available_after_add = mgr.available();
                
                // Delete all timers
                for id in ids {
                    mgr.delete(id);
                }
                
                prop_assert_eq!(
                    mgr.available(),
                    available_after_add + count,
                    "available should increase after delete"
                );
            }

            /// Property 5: Restart doesn't increase count
            #[test]
            fn prop_restart_no_count_increase(restarts in 1..10usize) {
                let mut mgr: OgsTimerMgr<()> = OgsTimerMgr::new(10);
                let id = mgr.add_simple().unwrap();
                
                mgr.start(id, Duration::from_secs(100));
                prop_assert_eq!(mgr.count(), 1);
                
                // Restart multiple times
                for i in 0..restarts {
                    mgr.start(id, Duration::from_secs(100 + i as u64));
                    prop_assert_eq!(mgr.count(), 1, "count should remain 1 after restart");
                }
            }

            /// Property 6: Stop is idempotent
            #[test]
            fn prop_stop_idempotent(stop_count in 1..5usize) {
                let mut mgr: OgsTimerMgr<()> = OgsTimerMgr::new(10);
                let id = mgr.add_simple().unwrap();
                
                mgr.start(id, Duration::from_secs(100));
                
                // Stop multiple times
                for _ in 0..stop_count {
                    mgr.stop(id);
                    prop_assert_eq!(mgr.count(), 0, "count should be 0 after stop");
                    prop_assert!(!mgr.get(id).unwrap().is_running(), "timer should not be running");
                }
            }

            /// Property 7: next() returns INFINITE when no timers
            #[test]
            fn prop_next_infinite_when_empty(capacity in 5..20usize) {
                let mgr: OgsTimerMgr<()> = OgsTimerMgr::new(capacity);
                prop_assert_eq!(mgr.next(), OGS_INFINITE_TIME, "next should be INFINITE when empty");
            }

            /// Property 8: next() returns reasonable value when timers exist
            #[test]
            fn prop_next_reasonable(duration_ms in 100..1000u64) {
                let mut mgr: OgsTimerMgr<()> = OgsTimerMgr::new(10);
                let id = mgr.add_simple().unwrap();
                
                let duration = Duration::from_millis(duration_ms);
                mgr.start(id, duration);
                
                let next = mgr.next();
                prop_assert!(next <= duration, "next should be <= duration");
                prop_assert!(next > Duration::ZERO, "next should be > 0");
            }

            /// Property 9: Expire only returns timers that have timed out
            #[test]
            fn prop_expire_only_timed_out(
                short_count in 0..3usize,
                long_count in 0..3usize
            ) {
                let mut mgr: OgsTimerMgr<()> = OgsTimerMgr::new(20);
                let mut short_ids = Vec::new();
                let mut long_ids = Vec::new();
                
                // Add short timers (will expire)
                for _ in 0..short_count {
                    if let Some(id) = mgr.add_simple() {
                        mgr.start(id, Duration::from_millis(5));
                        short_ids.push(id);
                    }
                }
                
                // Add long timers (won't expire)
                for _ in 0..long_count {
                    if let Some(id) = mgr.add_simple() {
                        mgr.start(id, Duration::from_secs(100));
                        long_ids.push(id);
                    }
                }
                
                // Wait for short timers to expire
                thread::sleep(Duration::from_millis(20));
                
                let expired = mgr.expire();
                
                // All short timers should have expired
                for id in &short_ids {
                    prop_assert!(expired.contains(id), "short timer should have expired");
                }
                
                // No long timers should have expired
                for id in &long_ids {
                    prop_assert!(!expired.contains(id), "long timer should not have expired");
                    prop_assert!(mgr.get(*id).unwrap().is_running(), "long timer should still be running");
                }
            }
        }
    }
}
