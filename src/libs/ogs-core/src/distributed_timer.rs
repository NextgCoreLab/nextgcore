//! Distributed Timer System (B2.1 - 6G)
//!
//! Provides distributed timer coordination across NF instances for
//! synchronized operations in 6G networks (e.g., ISAC sensing windows,
//! FL training rounds, digital twin sync).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ============================================================================
// Distributed Timer Types
// ============================================================================

/// Distributed timer identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DistTimerId(pub u64);

impl DistTimerId {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }
}

/// Clock synchronization state for distributed timers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockSyncState {
    /// Not synchronized.
    Unsynchronized,
    /// Synchronizing (exchange in progress).
    Synchronizing,
    /// Synchronized within tolerance.
    Synchronized,
    /// Lost synchronization (drift exceeded threshold).
    Drifted,
}

/// Distributed timer synchronization info.
#[derive(Debug, Clone)]
pub struct ClockSyncInfo {
    /// Current sync state.
    pub state: ClockSyncState,
    /// Estimated offset from leader (microseconds, signed).
    pub offset_us: i64,
    /// Estimated round-trip time (microseconds).
    pub rtt_us: u64,
    /// Last sync timestamp (epoch ms).
    pub last_sync_ms: u64,
    /// Maximum acceptable drift (microseconds).
    pub max_drift_us: u64,
}

impl Default for ClockSyncInfo {
    fn default() -> Self {
        Self {
            state: ClockSyncState::Unsynchronized,
            offset_us: 0,
            rtt_us: 0,
            last_sync_ms: 0,
            max_drift_us: 1000, // 1ms default
        }
    }
}

/// Distributed timer entry.
#[derive(Debug, Clone)]
pub struct DistTimerEntry {
    /// Timer identifier.
    pub id: DistTimerId,
    /// Timer name for debugging.
    pub name: String,
    /// Interval between fires.
    pub interval: Duration,
    /// Whether to repeat.
    pub repeating: bool,
    /// Coordination scope.
    pub scope: TimerScope,
    /// Next fire time (monotonic instant).
    pub next_fire: Option<Instant>,
    /// Number of times fired.
    pub fire_count: u64,
    /// Whether this timer is active.
    pub active: bool,
}

/// Scope of timer coordination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimerScope {
    /// Local NF instance only.
    Local,
    /// Coordinated across NF instances of same type (e.g., all AMF instances).
    NfType,
    /// Coordinated across all NF instances in the network.
    Global,
    /// Coordinated across a specific slice.
    Slice(u8),
}

impl DistTimerEntry {
    /// Creates a new distributed timer entry.
    pub fn new(id: DistTimerId, name: impl Into<String>, interval: Duration) -> Self {
        Self {
            id,
            name: name.into(),
            interval,
            repeating: false,
            scope: TimerScope::Local,
            next_fire: None,
            fire_count: 0,
            active: false,
        }
    }

    /// Set repeating mode.
    pub fn repeating(mut self) -> Self {
        self.repeating = true;
        self
    }

    /// Set coordination scope.
    pub fn with_scope(mut self, scope: TimerScope) -> Self {
        self.scope = scope;
        self
    }

    /// Start the timer.
    pub fn start(&mut self) {
        self.next_fire = Some(Instant::now() + self.interval);
        self.active = true;
    }

    /// Check if timer has fired and advance if repeating.
    pub fn check_and_advance(&mut self) -> bool {
        if !self.active {
            return false;
        }
        if let Some(next) = self.next_fire {
            if Instant::now() >= next {
                self.fire_count += 1;
                if self.repeating {
                    self.next_fire = Some(next + self.interval);
                } else {
                    self.active = false;
                    self.next_fire = None;
                }
                return true;
            }
        }
        false
    }

    /// Cancel the timer.
    pub fn cancel(&mut self) {
        self.active = false;
        self.next_fire = None;
    }

    /// Time until next fire (None if not active).
    pub fn time_until_fire(&self) -> Option<Duration> {
        self.next_fire.map(|next| {
            let now = Instant::now();
            if next > now {
                next - now
            } else {
                Duration::ZERO
            }
        })
    }
}

// ============================================================================
// Distributed Timer Manager
// ============================================================================

/// Manager for distributed timers across NF instances.
pub struct DistTimerManager {
    /// NF instance identifier.
    instance_id: String,
    /// Registered timers.
    timers: HashMap<DistTimerId, DistTimerEntry>,
    /// Next timer ID.
    next_id: AtomicU64,
    /// Clock sync info.
    sync_info: ClockSyncInfo,
}

impl DistTimerManager {
    /// Creates a new distributed timer manager.
    pub fn new(instance_id: impl Into<String>) -> Self {
        Self {
            instance_id: instance_id.into(),
            timers: HashMap::new(),
            next_id: AtomicU64::new(1),
            sync_info: ClockSyncInfo::default(),
        }
    }

    /// Allocate a new timer ID.
    pub fn alloc_id(&self) -> DistTimerId {
        DistTimerId::new(self.next_id.fetch_add(1, Ordering::Relaxed))
    }

    /// Register a timer.
    pub fn register(&mut self, entry: DistTimerEntry) -> DistTimerId {
        let id = entry.id;
        self.timers.insert(id, entry);
        id
    }

    /// Create and register a one-shot timer.
    pub fn create_oneshot(
        &mut self,
        name: impl Into<String>,
        interval: Duration,
        scope: TimerScope,
    ) -> DistTimerId {
        let id = self.alloc_id();
        let entry = DistTimerEntry::new(id, name, interval).with_scope(scope);
        self.register(entry)
    }

    /// Create and register a repeating timer.
    pub fn create_periodic(
        &mut self,
        name: impl Into<String>,
        interval: Duration,
        scope: TimerScope,
    ) -> DistTimerId {
        let id = self.alloc_id();
        let entry = DistTimerEntry::new(id, name, interval)
            .repeating()
            .with_scope(scope);
        self.register(entry)
    }

    /// Start a registered timer.
    pub fn start(&mut self, id: DistTimerId) -> bool {
        if let Some(timer) = self.timers.get_mut(&id) {
            timer.start();
            true
        } else {
            false
        }
    }

    /// Cancel a timer.
    pub fn cancel(&mut self, id: DistTimerId) -> bool {
        if let Some(timer) = self.timers.get_mut(&id) {
            timer.cancel();
            true
        } else {
            false
        }
    }

    /// Poll all timers and return IDs of those that fired.
    pub fn poll(&mut self) -> Vec<DistTimerId> {
        let mut fired = Vec::new();
        for (id, timer) in &mut self.timers {
            if timer.check_and_advance() {
                fired.push(*id);
            }
        }
        fired
    }

    /// Get the minimum time until next fire across all active timers.
    pub fn next_deadline(&self) -> Option<Duration> {
        self.timers
            .values()
            .filter(|t| t.active)
            .filter_map(|t| t.time_until_fire())
            .min()
    }

    /// Get timer by ID.
    pub fn get(&self, id: DistTimerId) -> Option<&DistTimerEntry> {
        self.timers.get(&id)
    }

    /// Number of active timers.
    pub fn active_count(&self) -> usize {
        self.timers.values().filter(|t| t.active).count()
    }

    /// Total registered timers.
    pub fn total_count(&self) -> usize {
        self.timers.len()
    }

    /// Update clock sync info.
    pub fn update_sync(&mut self, offset_us: i64, rtt_us: u64) {
        self.sync_info.offset_us = offset_us;
        self.sync_info.rtt_us = rtt_us;
        self.sync_info.last_sync_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.sync_info.state = if offset_us.unsigned_abs() <= self.sync_info.max_drift_us {
            ClockSyncState::Synchronized
        } else {
            ClockSyncState::Drifted
        };
    }

    /// Get clock sync info.
    pub fn sync_info(&self) -> &ClockSyncInfo {
        &self.sync_info
    }

    /// Instance ID.
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dist_timer_id() {
        let id = DistTimerId::new(42);
        assert_eq!(id.0, 42);
    }

    #[test]
    fn test_dist_timer_entry_oneshot() {
        let id = DistTimerId::new(1);
        let mut entry = DistTimerEntry::new(id, "test", Duration::from_millis(10));
        assert!(!entry.active);
        entry.start();
        assert!(entry.active);
    }

    #[test]
    fn test_dist_timer_entry_cancel() {
        let id = DistTimerId::new(1);
        let mut entry = DistTimerEntry::new(id, "test", Duration::from_secs(60));
        entry.start();
        assert!(entry.active);
        entry.cancel();
        assert!(!entry.active);
    }

    #[test]
    fn test_dist_timer_manager_create() {
        let mut mgr = DistTimerManager::new("amf-001");
        let id = mgr.create_periodic("heartbeat", Duration::from_secs(1), TimerScope::Local);
        assert_eq!(mgr.total_count(), 1);
        assert_eq!(mgr.active_count(), 0);

        mgr.start(id);
        assert_eq!(mgr.active_count(), 1);
    }

    #[test]
    fn test_dist_timer_manager_cancel() {
        let mut mgr = DistTimerManager::new("smf-001");
        let id = mgr.create_oneshot("timeout", Duration::from_secs(5), TimerScope::NfType);
        mgr.start(id);
        assert_eq!(mgr.active_count(), 1);

        mgr.cancel(id);
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn test_clock_sync_info() {
        let mut mgr = DistTimerManager::new("nwdaf-001");
        assert_eq!(mgr.sync_info().state, ClockSyncState::Unsynchronized);

        mgr.update_sync(50, 200);
        assert_eq!(mgr.sync_info().state, ClockSyncState::Synchronized);

        mgr.update_sync(5000, 200); // Way over 1ms drift
        assert_eq!(mgr.sync_info().state, ClockSyncState::Drifted);
    }

    #[test]
    fn test_timer_scope() {
        assert_ne!(TimerScope::Local, TimerScope::Global);
        assert_eq!(TimerScope::Slice(1), TimerScope::Slice(1));
        assert_ne!(TimerScope::Slice(1), TimerScope::Slice(2));
    }
}
