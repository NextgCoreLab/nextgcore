//! UDM Timer Management
//!
//! Port of timer management for UDM network function

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// UDM Timer types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UdmTimerType {
    /// No timer
    None,
    /// NF instance heartbeat timer
    NfInstanceHeartbeat,
    /// NF instance no heartbeat timer
    NfInstanceNoHeartbeat,
    /// NF instance validity timer
    NfInstanceValidity,
    /// Subscription validity timer
    SubscriptionValidity,
    /// SBI client wait timer
    SbiClientWait,
}

impl Default for UdmTimerType {
    fn default() -> Self {
        UdmTimerType::None
    }
}

/// Get timer name for logging
pub fn udm_timer_get_name(timer_type: UdmTimerType) -> &'static str {
    match timer_type {
        UdmTimerType::None => "NONE",
        UdmTimerType::NfInstanceHeartbeat => "NF_INSTANCE_HEARTBEAT",
        UdmTimerType::NfInstanceNoHeartbeat => "NF_INSTANCE_NO_HEARTBEAT",
        UdmTimerType::NfInstanceValidity => "NF_INSTANCE_VALIDITY",
        UdmTimerType::SubscriptionValidity => "SUBSCRIPTION_VALIDITY",
        UdmTimerType::SbiClientWait => "SBI_CLIENT_WAIT",
    }
}

/// Timer entry
#[derive(Debug, Clone)]
pub struct UdmTimer {
    /// Timer ID
    pub id: u64,
    /// Timer type
    pub timer_type: UdmTimerType,
    /// Expiration time
    pub expires_at: Instant,
    /// Associated data (e.g., UE ID, session ID)
    pub data: Option<u64>,
}

impl UdmTimer {
    /// Create a new timer
    pub fn new(id: u64, timer_type: UdmTimerType, duration: Duration, data: Option<u64>) -> Self {
        Self {
            id,
            timer_type,
            expires_at: Instant::now() + duration,
            data,
        }
    }

    /// Check if timer has expired
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Get remaining time until expiration
    pub fn remaining(&self) -> Duration {
        let now = Instant::now();
        if now >= self.expires_at {
            Duration::ZERO
        } else {
            self.expires_at - now
        }
    }
}

/// UDM Timer Manager
pub struct UdmTimerManager {
    /// Active timers
    timers: RwLock<HashMap<u64, UdmTimer>>,
    /// Next timer ID
    next_id: Mutex<u64>,
}

impl UdmTimerManager {
    /// Create a new timer manager
    pub fn new() -> Self {
        Self {
            timers: RwLock::new(HashMap::new()),
            next_id: Mutex::new(1),
        }
    }

    /// Start a new timer
    pub fn start(&self, timer_type: UdmTimerType, duration: Duration, data: Option<u64>) -> u64 {
        let mut next_id = self.next_id.lock().unwrap();
        let id = *next_id;
        *next_id += 1;
        drop(next_id);

        let timer = UdmTimer::new(id, timer_type, duration, data);
        
        let mut timers = self.timers.write().unwrap();
        timers.insert(id, timer);

        log::debug!(
            "Timer started: {} ({:?}, {:?})",
            id,
            timer_type,
            duration
        );

        id
    }

    /// Stop a timer
    pub fn stop(&self, id: u64) -> Option<UdmTimer> {
        let mut timers = self.timers.write().unwrap();
        let timer = timers.remove(&id);
        
        if timer.is_some() {
            log::debug!("Timer stopped: {}", id);
        }

        timer
    }

    /// Process expired timers and return them
    pub fn process_expired(&self) -> Vec<UdmTimer> {
        let mut timers = self.timers.write().unwrap();
        let mut expired = Vec::new();

        timers.retain(|_, timer| {
            if timer.is_expired() {
                expired.push(timer.clone());
                false
            } else {
                true
            }
        });

        expired
    }

    /// Get number of active timers
    pub fn count(&self) -> usize {
        self.timers.read().unwrap().len()
    }

    /// Check if a timer exists
    pub fn exists(&self, id: u64) -> bool {
        self.timers.read().unwrap().contains_key(&id)
    }
}

impl Default for UdmTimerManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Global timer manager
static TIMER_MANAGER: std::sync::OnceLock<Arc<UdmTimerManager>> = std::sync::OnceLock::new();

/// Get the global timer manager
pub fn timer_manager() -> Arc<UdmTimerManager> {
    TIMER_MANAGER
        .get_or_init(|| Arc::new(UdmTimerManager::new()))
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timer_type_default() {
        assert_eq!(UdmTimerType::default(), UdmTimerType::None);
    }

    #[test]
    fn test_timer_get_name() {
        assert_eq!(udm_timer_get_name(UdmTimerType::None), "NONE");
        assert_eq!(udm_timer_get_name(UdmTimerType::NfInstanceHeartbeat), "NF_INSTANCE_HEARTBEAT");
        assert_eq!(udm_timer_get_name(UdmTimerType::SbiClientWait), "SBI_CLIENT_WAIT");
    }

    #[test]
    fn test_timer_creation() {
        let timer = UdmTimer::new(1, UdmTimerType::SbiClientWait, Duration::from_secs(5), Some(100));
        assert_eq!(timer.id, 1);
        assert_eq!(timer.timer_type, UdmTimerType::SbiClientWait);
        assert_eq!(timer.data, Some(100));
        assert!(!timer.is_expired());
    }

    #[test]
    fn test_timer_manager_start_stop() {
        let mgr = UdmTimerManager::new();
        
        let id = mgr.start(UdmTimerType::SbiClientWait, Duration::from_secs(10), None);
        assert!(mgr.exists(id));
        assert_eq!(mgr.count(), 1);

        let timer = mgr.stop(id);
        assert!(timer.is_some());
        assert!(!mgr.exists(id));
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_timer_manager_process_expired() {
        let mgr = UdmTimerManager::new();
        
        // Start a timer that expires immediately
        mgr.start(UdmTimerType::SbiClientWait, Duration::ZERO, None);
        
        // Process expired timers
        std::thread::sleep(Duration::from_millis(10));
        let expired = mgr.process_expired();
        
        assert_eq!(expired.len(), 1);
        assert_eq!(mgr.count(), 0);
    }
}
