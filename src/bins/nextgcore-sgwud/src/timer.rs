//! SGWU Timer Management
//!
//! Port of src/sgwu/timer.c and timer.h - SGWU timer configuration and handling

use std::time::Duration;

// ============================================================================
// Timer IDs
// ============================================================================

/// SGWU timer identifiers
/// Port of sgwu_timer_e from timer.h
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SgwuTimerId {
    /// PFCP association timer
    Association,
    /// PFCP no heartbeat timer
    NoHeartbeat,
}

impl SgwuTimerId {
    /// Get timer name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Association => "SGWU_TIMER_ASSOCIATION",
            Self::NoHeartbeat => "SGWU_TIMER_NO_HEARTBEAT",
        }
    }
}

// ============================================================================
// Timer Configuration
// ============================================================================

/// Timer configuration
#[derive(Debug, Clone)]
pub struct TimerConfig {
    /// Timer is configured
    pub enabled: bool,
    /// Maximum retry count
    pub max_count: u32,
    /// Timer duration
    pub duration: Duration,
}

impl Default for TimerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_count: 0,
            duration: Duration::ZERO,
        }
    }
}

impl TimerConfig {
    /// Create a new timer configuration
    pub fn new(max_count: u32, duration_secs: u64) -> Self {
        Self {
            enabled: true,
            max_count,
            duration: Duration::from_secs(duration_secs),
        }
    }

    /// Create a timer configuration with milliseconds
    pub fn new_millis(max_count: u32, duration_millis: u64) -> Self {
        Self {
            enabled: true,
            max_count,
            duration: Duration::from_millis(duration_millis),
        }
    }
}

/// SGWU timer configurations
#[derive(Debug, Clone)]
pub struct SgwuTimerConfigs {
    /// PFCP association configuration
    pub association: TimerConfig,
    /// PFCP no heartbeat configuration
    pub no_heartbeat: TimerConfig,
}

impl Default for SgwuTimerConfigs {
    fn default() -> Self {
        Self {
            // PFCP association - retry every 3 seconds
            association: TimerConfig::new(0, 3),
            // PFCP no heartbeat - 10 seconds
            no_heartbeat: TimerConfig::new(0, 10),
        }
    }
}

impl SgwuTimerConfigs {
    /// Get timer configuration by ID
    pub fn get(&self, timer_id: SgwuTimerId) -> Option<&TimerConfig> {
        match timer_id {
            SgwuTimerId::Association => Some(&self.association),
            SgwuTimerId::NoHeartbeat => Some(&self.no_heartbeat),
        }
    }
}

// ============================================================================
// Timer Instance
// ============================================================================

/// Timer instance for tracking active timers
#[derive(Debug, Clone)]
pub struct TimerInstance {
    /// Timer ID
    pub timer_id: SgwuTimerId,
    /// Associated PFCP node ID
    pub pfcp_node_id: Option<u64>,
    /// Current retry count
    pub retry_count: u32,
    /// Timer is running
    pub running: bool,
}

impl TimerInstance {
    /// Create a new timer instance for PFCP node
    pub fn new_for_pfcp_node(timer_id: SgwuTimerId, pfcp_node_id: u64) -> Self {
        Self {
            timer_id,
            pfcp_node_id: Some(pfcp_node_id),
            retry_count: 0,
            running: false,
        }
    }

    /// Start the timer
    pub fn start(&mut self) {
        self.running = true;
        log::debug!("Timer {} started", self.timer_id.name());
    }

    /// Stop the timer
    pub fn stop(&mut self) {
        self.running = false;
        log::debug!("Timer {} stopped", self.timer_id.name());
    }

    /// Increment retry count
    pub fn increment_retry(&mut self) {
        self.retry_count += 1;
    }

    /// Check if max retries exceeded
    pub fn max_retries_exceeded(&self, config: &TimerConfig) -> bool {
        config.max_count > 0 && self.retry_count >= config.max_count
    }
}

// ============================================================================
// Timer Manager
// ============================================================================

/// Timer manager for SGWU
#[derive(Debug, Default)]
pub struct TimerManager {
    /// Timer configurations
    pub configs: SgwuTimerConfigs,
    /// Active timers
    active_timers: Vec<TimerInstance>,
}

impl TimerManager {
    /// Create a new timer manager
    pub fn new() -> Self {
        Self {
            configs: SgwuTimerConfigs::default(),
            active_timers: Vec::new(),
        }
    }

    /// Start a timer for PFCP node
    pub fn start_pfcp_node_timer(&mut self, timer_id: SgwuTimerId, pfcp_node_id: u64) -> bool {
        if let Some(config) = self.configs.get(timer_id) {
            if !config.enabled {
                log::warn!("Timer {} is not enabled", timer_id.name());
                return false;
            }

            let mut timer = TimerInstance::new_for_pfcp_node(timer_id, pfcp_node_id);
            timer.start();
            self.active_timers.push(timer);
            log::debug!(
                "Started timer {} for PFCP node {} (duration: {:?})",
                timer_id.name(),
                pfcp_node_id,
                config.duration
            );
            return true;
        }
        false
    }

    /// Stop a timer for PFCP node
    pub fn stop_pfcp_node_timer(&mut self, timer_id: SgwuTimerId, pfcp_node_id: u64) {
        self.active_timers.retain(|t| {
            !(t.timer_id == timer_id && t.pfcp_node_id == Some(pfcp_node_id))
        });
        log::debug!("Stopped timer {} for PFCP node {}", timer_id.name(), pfcp_node_id);
    }

    /// Stop all timers for PFCP node
    pub fn stop_all_pfcp_node_timers(&mut self, pfcp_node_id: u64) {
        self.active_timers.retain(|t| t.pfcp_node_id != Some(pfcp_node_id));
        log::debug!("Stopped all timers for PFCP node {}", pfcp_node_id);
    }

    /// Get active timer count
    pub fn active_timer_count(&self) -> usize {
        self.active_timers.len()
    }
}

// ============================================================================
// Timer Callback Functions (stubs for integration)
// ============================================================================

/// PFCP association timer callback
/// Port of sgwu_timer_association from timer.c
pub fn sgwu_timer_association(_data: u64) {
    log::debug!("PFCP association timer expired");
    // TODO: Send SGWU_EVT_SXA_TIMER event to queue
}

/// PFCP no heartbeat timer callback
/// Port of sgwu_timer_no_heartbeat from timer.c
pub fn sgwu_timer_no_heartbeat(_data: u64) {
    log::debug!("PFCP no heartbeat timer expired");
    // TODO: Send SGWU_EVT_SXA_NO_HEARTBEAT event to queue
}

/// Get timer name by ID
/// Port of sgwu_timer_get_name from timer.c
pub fn sgwu_timer_get_name(timer_id: SgwuTimerId) -> &'static str {
    timer_id.name()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timer_id_names() {
        assert_eq!(SgwuTimerId::Association.name(), "SGWU_TIMER_ASSOCIATION");
        assert_eq!(SgwuTimerId::NoHeartbeat.name(), "SGWU_TIMER_NO_HEARTBEAT");
    }

    #[test]
    fn test_timer_config_default() {
        let configs = SgwuTimerConfigs::default();
        assert!(configs.association.enabled);
        assert_eq!(configs.association.duration, Duration::from_secs(3));
        assert!(configs.no_heartbeat.enabled);
        assert_eq!(configs.no_heartbeat.duration, Duration::from_secs(10));
    }

    #[test]
    fn test_timer_config_get() {
        let configs = SgwuTimerConfigs::default();
        let assoc = configs.get(SgwuTimerId::Association).unwrap();
        assert_eq!(assoc.duration, Duration::from_secs(3));
        let no_hb = configs.get(SgwuTimerId::NoHeartbeat).unwrap();
        assert_eq!(no_hb.duration, Duration::from_secs(10));
    }

    #[test]
    fn test_timer_instance_for_pfcp_node() {
        let timer = TimerInstance::new_for_pfcp_node(SgwuTimerId::NoHeartbeat, 200);
        assert_eq!(timer.timer_id, SgwuTimerId::NoHeartbeat);
        assert_eq!(timer.pfcp_node_id, Some(200));
        assert!(!timer.running);
    }

    #[test]
    fn test_timer_instance_start_stop() {
        let mut timer = TimerInstance::new_for_pfcp_node(SgwuTimerId::Association, 100);
        assert!(!timer.running);
        timer.start();
        assert!(timer.running);
        timer.stop();
        assert!(!timer.running);
    }

    #[test]
    fn test_timer_instance_retry() {
        let mut timer = TimerInstance::new_for_pfcp_node(SgwuTimerId::Association, 100);
        let config = TimerConfig::new(4, 3);

        assert_eq!(timer.retry_count, 0);
        assert!(!timer.max_retries_exceeded(&config));

        for _ in 0..4 {
            timer.increment_retry();
        }
        assert_eq!(timer.retry_count, 4);
        assert!(timer.max_retries_exceeded(&config));
    }

    #[test]
    fn test_timer_manager_start_stop() {
        let mut manager = TimerManager::new();

        assert!(manager.start_pfcp_node_timer(SgwuTimerId::Association, 100));
        assert_eq!(manager.active_timer_count(), 1);

        manager.stop_pfcp_node_timer(SgwuTimerId::Association, 100);
        assert_eq!(manager.active_timer_count(), 0);
    }

    #[test]
    fn test_timer_manager_stop_all() {
        let mut manager = TimerManager::new();

        manager.start_pfcp_node_timer(SgwuTimerId::Association, 100);
        manager.start_pfcp_node_timer(SgwuTimerId::NoHeartbeat, 100);
        manager.start_pfcp_node_timer(SgwuTimerId::Association, 200);
        assert_eq!(manager.active_timer_count(), 3);

        manager.stop_all_pfcp_node_timers(100);
        assert_eq!(manager.active_timer_count(), 1);
    }
}
