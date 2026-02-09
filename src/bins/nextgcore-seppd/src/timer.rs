//! SEPP Timer Management
//!
//! Timer management for SEPP operations using the shared AsyncTimerMgr
//! from ogs-core. Handles peer establishment retries, NRF heartbeats,
//! and subscription validity.

use crate::event::SeppTimerId;
use ogs_core::async_timer::{AsyncTimerMgr, TimerMode};
use std::sync::Arc;
use std::time::Duration;

/// Timer configuration for SEPP-specific parameters
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

/// SEPP Timer Manager wrapping the generic AsyncTimerMgr
pub struct TimerManager {
    inner: AsyncTimerMgr<SeppTimerId>,
    config: TimerConfig,
}

impl TimerManager {
    /// Create a new SEPP timer manager with default config
    pub fn new(config: TimerConfig) -> Self {
        Self {
            inner: AsyncTimerMgr::new(),
            config,
        }
    }

    /// Get reconnect interval
    pub fn reconnect_interval(&self) -> u64 {
        self.config.reconnect_interval
    }

    /// Get reconnect interval in exception state
    pub fn reconnect_interval_in_exception(&self) -> u64 {
        self.config.reconnect_interval_in_exception
    }

    /// Start a one-shot timer
    pub fn start(
        &self,
        timer_type: SeppTimerId,
        duration: Duration,
        data: Option<String>,
    ) -> u64 {
        self.inner.start(timer_type, duration, TimerMode::OneShot, data)
    }

    /// Start a periodic timer
    pub fn start_periodic(
        &self,
        timer_type: SeppTimerId,
        interval: Duration,
        data: Option<String>,
    ) -> u64 {
        self.inner.start(timer_type, interval, TimerMode::Periodic, data)
    }

    /// Start peer establishment timer using config interval
    pub fn start_peer_establish(&self, data: Option<String>) -> u64 {
        self.inner.start(
            SeppTimerId::PeerEstablish,
            Duration::from_millis(self.config.reconnect_interval),
            TimerMode::OneShot,
            data,
        )
    }

    /// Start peer establishment timer with exception interval
    pub fn start_peer_establish_exception(&self, data: Option<String>) -> u64 {
        self.inner.start(
            SeppTimerId::PeerEstablish,
            Duration::from_millis(self.config.reconnect_interval_in_exception),
            TimerMode::OneShot,
            data,
        )
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
    pub fn process_expired(&self) -> Vec<ogs_core::async_timer::AsyncTimerEntry<SeppTimerId>> {
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
    pub fn inner(&self) -> &AsyncTimerMgr<SeppTimerId> {
        &self.inner
    }
}

impl Default for TimerManager {
    fn default() -> Self {
        Self::new(TimerConfig::default())
    }
}

/// Global timer manager
static TIMER_MANAGER: std::sync::OnceLock<Arc<TimerManager>> = std::sync::OnceLock::new();

/// Get the global SEPP timer manager
pub fn timer_manager() -> Arc<TimerManager> {
    TIMER_MANAGER
        .get_or_init(|| Arc::new(TimerManager::default()))
        .clone()
}

/// Get the name of a timer (for logging)
pub fn sepp_timer_get_name(timer_id: SeppTimerId) -> &'static str {
    timer_id.name()
}

/// Default timer durations for SEPP
#[allow(dead_code)]
pub mod defaults {
    use std::time::Duration;

    pub const NF_INSTANCE_REGISTRATION_INTERVAL: Duration = Duration::from_secs(3);
    pub const NF_INSTANCE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
    pub const NF_INSTANCE_NO_HEARTBEAT: Duration = Duration::from_secs(30);
    pub const SUBSCRIPTION_VALIDITY: Duration = Duration::from_secs(86400);
    pub const SBI_CLIENT_WAIT: Duration = Duration::from_secs(2);
    pub const PEER_ESTABLISH: Duration = Duration::from_secs(3);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_timer_config_default() {
        let config = TimerConfig::default();
        assert_eq!(config.reconnect_interval, 3000);
        assert_eq!(config.reconnect_interval_in_exception, 10000);
    }

    #[test]
    fn test_timer_manager_start_stop() {
        let mgr = TimerManager::default();

        let id = mgr.start(
            SeppTimerId::NfInstanceHeartbeatInterval,
            Duration::from_secs(10),
            None,
        );
        assert_eq!(mgr.count(), 1);

        assert!(mgr.stop(id));
    }

    #[test]
    fn test_timer_manager_process_expired() {
        let mgr = TimerManager::default();

        mgr.start(
            SeppTimerId::SbiClientWait,
            Duration::from_millis(10),
            None,
        );

        thread::sleep(Duration::from_millis(20));

        let expired = mgr.process_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].timer_type, SeppTimerId::SbiClientWait);
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_timer_manager_peer_establish() {
        let config = TimerConfig {
            reconnect_interval: 10,
            reconnect_interval_in_exception: 20,
        };
        let mgr = TimerManager::new(config);

        let _id = mgr.start_peer_establish(Some("peer-sepp-1".to_string()));

        thread::sleep(Duration::from_millis(20));

        let expired = mgr.process_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].timer_type, SeppTimerId::PeerEstablish);
        assert_eq!(expired[0].data, Some("peer-sepp-1".to_string()));
    }

    #[test]
    fn test_reconnect_intervals() {
        let mgr = TimerManager::default();
        assert_eq!(mgr.reconnect_interval(), 3000);
        assert_eq!(mgr.reconnect_interval_in_exception(), 10000);
    }
}
