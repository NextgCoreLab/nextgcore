//! AMF Timer Management
//!
//! Port of src/amf/timer.c - AMF timer configuration and handling

use std::time::Duration;

// ============================================================================
// Timer IDs
// ============================================================================

/// AMF timer identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AmfTimerId {
    /// NG delayed send timer
    NgDelayedSend,
    /// T3513 - Paging procedure for EPS services initiated
    T3513,
    /// T3522 - Deregistration request sent
    T3522,
    /// T3550 - Registration accept sent
    T3550,
    /// T3555 - Configuration update command sent
    T3555,
    /// T3560 - Authentication request / Security mode command sent
    T3560,
    /// T3570 - Identity request sent
    T3570,
    /// NG holding timer
    NgHolding,
    /// Mobile reachable timer
    MobileReachable,
    /// Implicit deregistration timer
    ImplicitDeregistration,
}

impl AmfTimerId {
    /// Get timer name
    pub fn name(&self) -> &'static str {
        match self {
            Self::NgDelayedSend => "AMF_TIMER_NG_DELAYED_SEND",
            Self::T3513 => "AMF_TIMER_T3513",
            Self::T3522 => "AMF_TIMER_T3522",
            Self::T3550 => "AMF_TIMER_T3550",
            Self::T3555 => "AMF_TIMER_T3555",
            Self::T3560 => "AMF_TIMER_T3560",
            Self::T3570 => "AMF_TIMER_T3570",
            Self::NgHolding => "AMF_TIMER_NG_HOLDING",
            Self::MobileReachable => "AMF_TIMER_MOBILE_REACHABLE",
            Self::ImplicitDeregistration => "AMF_TIMER_IMPLICIT_DEREGISTRATION",
        }
    }

    /// Check if this is a GMM timer
    pub fn is_gmm_timer(&self) -> bool {
        matches!(
            self,
            Self::T3513
                | Self::T3522
                | Self::T3550
                | Self::T3555
                | Self::T3560
                | Self::T3570
                | Self::MobileReachable
                | Self::ImplicitDeregistration
        )
    }

    /// Check if this is an NGAP timer
    pub fn is_ngap_timer(&self) -> bool {
        matches!(self, Self::NgHolding | Self::NgDelayedSend)
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

/// AMF timer configurations
#[derive(Debug, Clone)]
pub struct AmfTimerConfigs {
    /// T3513 configuration
    pub t3513: TimerConfig,
    /// T3522 configuration
    pub t3522: TimerConfig,
    /// T3550 configuration
    pub t3550: TimerConfig,
    /// T3555 configuration
    pub t3555: TimerConfig,
    /// T3560 configuration
    pub t3560: TimerConfig,
    /// T3570 configuration
    pub t3570: TimerConfig,
    /// NG holding configuration
    pub ng_holding: TimerConfig,
}

impl Default for AmfTimerConfigs {
    fn default() -> Self {
        Self {
            // T3513 - Paging procedure for EPS services initiated
            t3513: TimerConfig::new(2, 2),
            // T3522 - Deregistration request sent
            t3522: TimerConfig::new(4, 3),
            // T3550 - Registration accept sent
            t3550: TimerConfig::new(4, 6),
            // T3555 - Configuration update command sent
            t3555: TimerConfig::new(4, 6),
            // T3560 - Authentication request / Security mode command sent
            t3560: TimerConfig::new(4, 6),
            // T3570 - Identity request sent
            t3570: TimerConfig::new(4, 3),
            // NG holding timer
            ng_holding: TimerConfig {
                enabled: true,
                max_count: 0,
                duration: Duration::from_secs(30),
            },
        }
    }
}

impl AmfTimerConfigs {
    /// Get timer configuration by ID
    pub fn get(&self, timer_id: AmfTimerId) -> Option<&TimerConfig> {
        match timer_id {
            AmfTimerId::T3513 => Some(&self.t3513),
            AmfTimerId::T3522 => Some(&self.t3522),
            AmfTimerId::T3550 => Some(&self.t3550),
            AmfTimerId::T3555 => Some(&self.t3555),
            AmfTimerId::T3560 => Some(&self.t3560),
            AmfTimerId::T3570 => Some(&self.t3570),
            AmfTimerId::NgHolding => Some(&self.ng_holding),
            _ => None,
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
    pub timer_id: AmfTimerId,
    /// Associated UE ID (for GMM timers)
    pub amf_ue_id: Option<u64>,
    /// Associated RAN UE ID (for NGAP timers)
    pub ran_ue_id: Option<u64>,
    /// Current retry count
    pub retry_count: u32,
    /// Timer is running
    pub running: bool,
}

impl TimerInstance {
    /// Create a new timer instance for UE
    pub fn new_for_ue(timer_id: AmfTimerId, amf_ue_id: u64) -> Self {
        Self {
            timer_id,
            amf_ue_id: Some(amf_ue_id),
            ran_ue_id: None,
            retry_count: 0,
            running: false,
        }
    }

    /// Create a new timer instance for RAN UE
    pub fn new_for_ran_ue(timer_id: AmfTimerId, ran_ue_id: u64) -> Self {
        Self {
            timer_id,
            amf_ue_id: None,
            ran_ue_id: Some(ran_ue_id),
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
        self.retry_count >= config.max_count
    }
}

// ============================================================================
// Timer Manager
// ============================================================================

/// Timer manager for AMF
#[derive(Debug, Default)]
pub struct TimerManager {
    /// Timer configurations
    pub configs: AmfTimerConfigs,
    /// Active timers (simplified - in real impl would use actual timer handles)
    active_timers: Vec<TimerInstance>,
}

impl TimerManager {
    /// Create a new timer manager
    pub fn new() -> Self {
        Self {
            configs: AmfTimerConfigs::default(),
            active_timers: Vec::new(),
        }
    }

    /// Start a timer for UE
    pub fn start_ue_timer(&mut self, timer_id: AmfTimerId, amf_ue_id: u64) -> bool {
        if let Some(config) = self.configs.get(timer_id) {
            if !config.enabled {
                log::warn!("Timer {} is not enabled", timer_id.name());
                return false;
            }

            let mut timer = TimerInstance::new_for_ue(timer_id, amf_ue_id);
            timer.start();
            self.active_timers.push(timer);
            log::debug!(
                "Started timer {} for UE {} (duration: {:?})",
                timer_id.name(),
                amf_ue_id,
                config.duration
            );
            return true;
        }
        false
    }

    /// Start a timer for RAN UE
    pub fn start_ran_ue_timer(&mut self, timer_id: AmfTimerId, ran_ue_id: u64) -> bool {
        if let Some(config) = self.configs.get(timer_id) {
            if !config.enabled {
                log::warn!("Timer {} is not enabled", timer_id.name());
                return false;
            }

            let mut timer = TimerInstance::new_for_ran_ue(timer_id, ran_ue_id);
            timer.start();
            self.active_timers.push(timer);
            log::debug!(
                "Started timer {} for RAN UE {} (duration: {:?})",
                timer_id.name(),
                ran_ue_id,
                config.duration
            );
            return true;
        }
        false
    }

    /// Stop a timer for UE
    pub fn stop_ue_timer(&mut self, timer_id: AmfTimerId, amf_ue_id: u64) {
        self.active_timers.retain(|t| {
            !(t.timer_id == timer_id && t.amf_ue_id == Some(amf_ue_id))
        });
        log::debug!("Stopped timer {} for UE {}", timer_id.name(), amf_ue_id);
    }

    /// Stop a timer for RAN UE
    pub fn stop_ran_ue_timer(&mut self, timer_id: AmfTimerId, ran_ue_id: u64) {
        self.active_timers.retain(|t| {
            !(t.timer_id == timer_id && t.ran_ue_id == Some(ran_ue_id))
        });
        log::debug!("Stopped timer {} for RAN UE {}", timer_id.name(), ran_ue_id);
    }

    /// Stop all timers for UE
    pub fn stop_all_ue_timers(&mut self, amf_ue_id: u64) {
        self.active_timers.retain(|t| t.amf_ue_id != Some(amf_ue_id));
        log::debug!("Stopped all timers for UE {amf_ue_id}");
    }

    /// Stop all timers for RAN UE
    pub fn stop_all_ran_ue_timers(&mut self, ran_ue_id: u64) {
        self.active_timers.retain(|t| t.ran_ue_id != Some(ran_ue_id));
        log::debug!("Stopped all timers for RAN UE {ran_ue_id}");
    }

    /// Get active timer count
    pub fn active_timer_count(&self) -> usize {
        self.active_timers.len()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timer_id_names() {
        assert_eq!(AmfTimerId::T3513.name(), "AMF_TIMER_T3513");
        assert_eq!(AmfTimerId::T3560.name(), "AMF_TIMER_T3560");
        assert_eq!(AmfTimerId::NgHolding.name(), "AMF_TIMER_NG_HOLDING");
    }

    #[test]
    fn test_timer_id_is_gmm() {
        assert!(AmfTimerId::T3513.is_gmm_timer());
        assert!(AmfTimerId::T3560.is_gmm_timer());
        assert!(!AmfTimerId::NgHolding.is_gmm_timer());
    }

    #[test]
    fn test_timer_id_is_ngap() {
        assert!(AmfTimerId::NgHolding.is_ngap_timer());
        assert!(AmfTimerId::NgDelayedSend.is_ngap_timer());
        assert!(!AmfTimerId::T3513.is_ngap_timer());
    }

    #[test]
    fn test_timer_config_default() {
        let configs = AmfTimerConfigs::default();
        assert!(configs.t3513.enabled);
        assert_eq!(configs.t3513.max_count, 2);
        assert_eq!(configs.t3513.duration, Duration::from_secs(2));
    }

    #[test]
    fn test_timer_config_get() {
        let configs = AmfTimerConfigs::default();
        let t3560 = configs.get(AmfTimerId::T3560).unwrap();
        assert_eq!(t3560.max_count, 4);
        assert_eq!(t3560.duration, Duration::from_secs(6));
    }

    #[test]
    fn test_timer_instance_for_ue() {
        let timer = TimerInstance::new_for_ue(AmfTimerId::T3560, 100);
        assert_eq!(timer.timer_id, AmfTimerId::T3560);
        assert_eq!(timer.amf_ue_id, Some(100));
        assert!(timer.ran_ue_id.is_none());
        assert!(!timer.running);
    }

    #[test]
    fn test_timer_instance_start_stop() {
        let mut timer = TimerInstance::new_for_ue(AmfTimerId::T3560, 100);
        assert!(!timer.running);
        timer.start();
        assert!(timer.running);
        timer.stop();
        assert!(!timer.running);
    }

    #[test]
    fn test_timer_instance_retry() {
        let mut timer = TimerInstance::new_for_ue(AmfTimerId::T3560, 100);
        let config = TimerConfig::new(4, 6);

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

        assert!(manager.start_ue_timer(AmfTimerId::T3560, 100));
        assert_eq!(manager.active_timer_count(), 1);

        manager.stop_ue_timer(AmfTimerId::T3560, 100);
        assert_eq!(manager.active_timer_count(), 0);
    }

    #[test]
    fn test_timer_manager_stop_all() {
        let mut manager = TimerManager::new();

        manager.start_ue_timer(AmfTimerId::T3560, 100);
        manager.start_ue_timer(AmfTimerId::T3570, 100);
        manager.start_ue_timer(AmfTimerId::T3560, 200);
        assert_eq!(manager.active_timer_count(), 3);

        manager.stop_all_ue_timers(100);
        assert_eq!(manager.active_timer_count(), 1);
    }
}
