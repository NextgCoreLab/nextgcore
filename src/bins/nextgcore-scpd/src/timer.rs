//! SCP Timer Management
//!
//! Timer management for SCP operations using the shared AsyncTimerMgr
//! from ogs-core.

use crate::event::ScpTimerId;
use ogs_core::async_timer::{AsyncTimerMgr, TimerMode};
use std::sync::Arc;
use std::time::Duration;

/// SCP Timer Manager wrapping the generic AsyncTimerMgr
pub struct ScpTimerManager {
    inner: AsyncTimerMgr<ScpTimerId>,
}

impl ScpTimerManager {
    /// Create a new SCP timer manager
    pub fn new() -> Self {
        Self {
            inner: AsyncTimerMgr::new(),
        }
    }

    /// Start a one-shot timer
    pub fn start(
        &self,
        timer_type: ScpTimerId,
        duration: Duration,
        data: Option<String>,
    ) -> u64 {
        self.inner.start(timer_type, duration, TimerMode::OneShot, data)
    }

    /// Start a periodic timer
    pub fn start_periodic(
        &self,
        timer_type: ScpTimerId,
        interval: Duration,
        data: Option<String>,
    ) -> u64 {
        self.inner.start(timer_type, interval, TimerMode::Periodic, data)
    }

    /// Stop/cancel a timer
    pub fn stop(&self, id: u64) -> bool {
        self.inner.cancel(id)
    }

    /// Remove a timer entirely
    pub fn remove(&self, id: u64) -> bool {
        self.inner.remove(id).is_some()
    }

    /// Reset a timer with its original duration
    pub fn reset(&self, id: u64) -> bool {
        self.inner.reset(id)
    }

    /// Process expired timers and return them for dispatch to the state machine
    pub fn process_expired(&self) -> Vec<ogs_core::async_timer::AsyncTimerEntry<ScpTimerId>> {
        self.inner.process_expired()
    }

    /// Get the number of active timers
    pub fn count(&self) -> usize {
        self.inner.count()
    }

    /// Clear all timers
    pub fn clear(&self) {
        self.inner.clear();
    }

    /// Get reference to inner manager (for compute_poll_interval)
    pub fn inner(&self) -> &AsyncTimerMgr<ScpTimerId> {
        &self.inner
    }
}

impl Default for ScpTimerManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Global timer manager
static TIMER_MANAGER: std::sync::OnceLock<Arc<ScpTimerManager>> = std::sync::OnceLock::new();

/// Get the global SCP timer manager
pub fn timer_manager() -> Arc<ScpTimerManager> {
    TIMER_MANAGER
        .get_or_init(|| Arc::new(ScpTimerManager::new()))
        .clone()
}

/// Get timer name for logging
#[allow(dead_code)]
pub fn scp_timer_get_name(timer_id: ScpTimerId) -> &'static str {
    timer_id.name()
}

/// Default timer durations for SCP
#[allow(dead_code)]
pub mod defaults {
    use std::time::Duration;

    pub const NF_INSTANCE_REGISTRATION_INTERVAL: Duration = Duration::from_secs(3);
    pub const NF_INSTANCE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
    pub const NF_INSTANCE_NO_HEARTBEAT: Duration = Duration::from_secs(30);
    pub const SUBSCRIPTION_VALIDITY: Duration = Duration::from_secs(86400);
    pub const SBI_CLIENT_WAIT: Duration = Duration::from_secs(2);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_timer_manager_start_stop() {
        let mgr = ScpTimerManager::new();

        let id = mgr.start(
            ScpTimerId::NfInstanceHeartbeatInterval,
            Duration::from_secs(10),
            None,
        );
        assert_eq!(mgr.count(), 1);

        assert!(mgr.stop(id));
    }

    #[test]
    fn test_timer_manager_process_expired() {
        let mgr = ScpTimerManager::new();

        mgr.start(
            ScpTimerId::SbiClientWait,
            Duration::from_millis(10),
            None,
        );

        thread::sleep(Duration::from_millis(20));

        let expired = mgr.process_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].timer_type, ScpTimerId::SbiClientWait);
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_timer_manager_periodic() {
        let mgr = ScpTimerManager::new();

        let id = mgr.start_periodic(
            ScpTimerId::NfInstanceHeartbeatInterval,
            Duration::from_millis(10),
            Some("nf-001".to_string()),
        );

        thread::sleep(Duration::from_millis(20));

        let expired = mgr.process_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(mgr.count(), 1);

        mgr.stop(id);
    }
}
