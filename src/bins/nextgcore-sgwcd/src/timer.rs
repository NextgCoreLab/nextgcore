//! SGWC Timer Management
//!
//! Port of src/sgwc/timer.c and timer.h - SGWC timer configuration and handling

use std::collections::HashMap;
use std::time::{Duration, Instant};

// ============================================================================
// Timer IDs
// ============================================================================

/// SGWC timer identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SgwcTimerId {
    /// PFCP association timer
    PfcpAssociation,
    /// PFCP no heartbeat timer
    PfcpNoHeartbeat,
}

impl SgwcTimerId {
    /// Get timer name
    pub fn name(&self) -> &'static str {
        match self {
            Self::PfcpAssociation => "SGWC_TIMER_PFCP_ASSOCIATION",
            Self::PfcpNoHeartbeat => "SGWC_TIMER_PFCP_NO_HEARTBEAT",
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
}

/// SGWC timer configurations
#[derive(Debug, Clone)]
pub struct SgwcTimerConfigs {
    /// PFCP association configuration
    pub pfcp_association: TimerConfig,
    /// PFCP no heartbeat configuration
    pub pfcp_no_heartbeat: TimerConfig,
}

impl Default for SgwcTimerConfigs {
    fn default() -> Self {
        Self {
            // PFCP association - retry every 3 seconds
            pfcp_association: TimerConfig::new(0, 3),
            // PFCP no heartbeat - 10 seconds
            pfcp_no_heartbeat: TimerConfig::new(0, 10),
        }
    }
}

impl SgwcTimerConfigs {
    /// Get timer configuration by ID
    pub fn get(&self, timer_id: SgwcTimerId) -> Option<&TimerConfig> {
        match timer_id {
            SgwcTimerId::PfcpAssociation => Some(&self.pfcp_association),
            SgwcTimerId::PfcpNoHeartbeat => Some(&self.pfcp_no_heartbeat),
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
    pub timer_id: SgwcTimerId,
    /// Associated PFCP node ID
    pub pfcp_node_id: Option<u64>,
    /// Current retry count
    pub retry_count: u32,
    /// Timer is running
    pub running: bool,
}

impl TimerInstance {
    /// Create a new timer instance for PFCP node
    pub fn new_for_pfcp_node(timer_id: SgwcTimerId, pfcp_node_id: u64) -> Self {
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
}

// ============================================================================
// Timer Manager
// ============================================================================

/// Timer manager for SGWC
#[derive(Debug, Default)]
pub struct TimerManager {
    /// Timer configurations
    pub configs: SgwcTimerConfigs,
    /// Active timers
    active_timers: Vec<TimerInstance>,
    /// Timer expiration times (timer_id -> expiration instant)
    expiration_times: HashMap<SgwcTimerId, Instant>,
}

impl TimerManager {
    /// Create a new timer manager
    pub fn new() -> Self {
        Self {
            configs: SgwcTimerConfigs::default(),
            active_timers: Vec::new(),
            expiration_times: HashMap::new(),
        }
    }

    /// Start a timer with a specific duration
    pub fn start(&mut self, timer_id: SgwcTimerId, duration: Duration) {
        let expiration = Instant::now() + duration;
        self.expiration_times.insert(timer_id, expiration);
        log::debug!("Started timer {} with duration {:?}", timer_id.name(), duration);
    }

    /// Stop a timer
    pub fn stop(&mut self, timer_id: SgwcTimerId) {
        self.expiration_times.remove(&timer_id);
        log::debug!("Stopped timer {}", timer_id.name());
    }

    /// Check for expired timers and return their IDs
    pub fn check_expired(&mut self) -> Vec<SgwcTimerId> {
        let now = Instant::now();
        let mut expired = Vec::new();
        
        self.expiration_times.retain(|timer_id, expiration| {
            if now >= *expiration {
                expired.push(*timer_id);
                false // Remove from map
            } else {
                true // Keep in map
            }
        });
        
        expired
    }

    /// Start a timer for PFCP node
    pub fn start_pfcp_node_timer(&mut self, timer_id: SgwcTimerId, pfcp_node_id: u64) -> bool {
        // Get duration first to avoid borrow issues
        let duration = match self.configs.get(timer_id) {
            Some(config) if config.enabled => config.duration,
            Some(_) => {
                log::warn!("Timer {} is not enabled", timer_id.name());
                return false;
            }
            None => return false,
        };

        let mut timer = TimerInstance::new_for_pfcp_node(timer_id, pfcp_node_id);
        timer.start();
        self.active_timers.push(timer);
        
        // Also track expiration time
        self.start(timer_id, duration);
        
        log::debug!(
            "Started timer {} for PFCP node {} (duration: {:?})",
            timer_id.name(),
            pfcp_node_id,
            duration
        );
        true
    }

    /// Stop a timer for PFCP node
    pub fn stop_pfcp_node_timer(&mut self, timer_id: SgwcTimerId, pfcp_node_id: u64) {
        self.active_timers.retain(|t| {
            !(t.timer_id == timer_id && t.pfcp_node_id == Some(pfcp_node_id))
        });
        self.stop(timer_id);
        log::debug!("Stopped timer {} for PFCP node {}", timer_id.name(), pfcp_node_id);
    }

    /// Stop all timers for PFCP node
    pub fn stop_all_pfcp_node_timers(&mut self, pfcp_node_id: u64) {
        // Collect timer IDs to stop
        let timer_ids: Vec<SgwcTimerId> = self.active_timers
            .iter()
            .filter(|t| t.pfcp_node_id == Some(pfcp_node_id))
            .map(|t| t.timer_id)
            .collect();
        
        self.active_timers.retain(|t| t.pfcp_node_id != Some(pfcp_node_id));
        
        for timer_id in timer_ids {
            self.stop(timer_id);
        }
        
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
pub fn sgwc_timer_pfcp_association(_data: u64) {
    log::debug!("PFCP association timer expired");
}

/// PFCP no heartbeat timer callback
pub fn sgwc_timer_pfcp_no_heartbeat(_data: u64) {
    log::debug!("PFCP no heartbeat timer expired");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timer_id_names() {
        assert_eq!(SgwcTimerId::PfcpAssociation.name(), "SGWC_TIMER_PFCP_ASSOCIATION");
        assert_eq!(SgwcTimerId::PfcpNoHeartbeat.name(), "SGWC_TIMER_PFCP_NO_HEARTBEAT");
    }

    #[test]
    fn test_timer_config_default() {
        let configs = SgwcTimerConfigs::default();
        assert!(configs.pfcp_association.enabled);
        assert_eq!(configs.pfcp_association.duration, Duration::from_secs(3));
    }

    #[test]
    fn test_timer_manager_pfcp_node() {
        let mut manager = TimerManager::new();

        assert!(manager.start_pfcp_node_timer(SgwcTimerId::PfcpNoHeartbeat, 300));
        assert_eq!(manager.active_timer_count(), 1);

        manager.stop_pfcp_node_timer(SgwcTimerId::PfcpNoHeartbeat, 300);
        assert_eq!(manager.active_timer_count(), 0);
    }
}
