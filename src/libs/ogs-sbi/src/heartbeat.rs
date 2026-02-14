//! NF Heartbeat and Keep-Alive Support (B8.4)
//!
//! Implements NF heartbeat mechanism for status monitoring per 3GPP TS 29.510.

#![allow(unexpected_cfgs)]

use crate::client::SbiClient;
use crate::error::SbiResult;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// NF heartbeat status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatStatus {
    /// NF is healthy
    Healthy,
    /// NF missed heartbeat but within grace period
    Degraded,
    /// NF is unreachable
    Unreachable,
    /// Heartbeat suspended
    Suspended,
}

/// NF heartbeat record
#[derive(Debug, Clone)]
pub struct HeartbeatRecord {
    /// NF instance ID
    pub nf_instance_id: String,
    /// NF FQDN
    pub nf_fqdn: String,
    /// Last successful heartbeat time
    pub last_heartbeat: Instant,
    /// Heartbeat interval (seconds)
    pub interval: u64,
    /// Number of consecutive failures
    pub failure_count: u32,
    /// Current status
    pub status: HeartbeatStatus,
    /// Grace period multiplier
    pub grace_multiplier: u32,
}

impl HeartbeatRecord {
    /// Create a new heartbeat record
    pub fn new(nf_instance_id: String, nf_fqdn: String, interval: u64) -> Self {
        Self {
            nf_instance_id,
            nf_fqdn,
            last_heartbeat: Instant::now(),
            interval,
            failure_count: 0,
            status: HeartbeatStatus::Healthy,
            grace_multiplier: 3, // Allow 3 missed heartbeats
        }
    }

    /// Check if heartbeat is overdue
    pub fn is_overdue(&self) -> bool {
        let grace_period = Duration::from_secs(self.interval * self.grace_multiplier as u64);
        self.last_heartbeat.elapsed() > grace_period
    }

    /// Check if within grace period
    pub fn is_in_grace_period(&self) -> bool {
        let normal_period = Duration::from_secs(self.interval);
        let grace_period = Duration::from_secs(self.interval * self.grace_multiplier as u64);
        let elapsed = self.last_heartbeat.elapsed();
        elapsed > normal_period && elapsed <= grace_period
    }

    /// Update status based on time
    pub fn update_status(&mut self) {
        if self.status == HeartbeatStatus::Suspended {
            return;
        }

        if self.is_overdue() {
            self.status = HeartbeatStatus::Unreachable;
        } else if self.is_in_grace_period() {
            self.status = HeartbeatStatus::Degraded;
        } else {
            self.status = HeartbeatStatus::Healthy;
        }
    }

    /// Mark heartbeat success
    pub fn mark_success(&mut self) {
        self.last_heartbeat = Instant::now();
        self.failure_count = 0;
        if self.status != HeartbeatStatus::Suspended {
            self.status = HeartbeatStatus::Healthy;
        }
    }

    /// Mark heartbeat failure
    pub fn mark_failure(&mut self) {
        self.failure_count += 1;
        self.update_status();
    }
}

/// Heartbeat configuration
#[derive(Debug, Clone)]
pub struct HeartbeatConfig {
    /// Default heartbeat interval (seconds)
    pub default_interval: u64,
    /// Worker thread poll interval (milliseconds)
    pub poll_interval_ms: u64,
    /// Maximum concurrent heartbeat requests
    pub max_concurrent: usize,
    /// Request timeout (seconds)
    pub request_timeout: u64,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            default_interval: 10,      // 10 seconds
            poll_interval_ms: 1000,     // 1 second
            max_concurrent: 100,
            request_timeout: 5,         // 5 seconds
        }
    }
}

/// Heartbeat manager
pub struct HeartbeatManager {
    /// Heartbeat records
    records: Arc<Mutex<HashMap<String, HeartbeatRecord>>>,
    /// Configuration
    config: HeartbeatConfig,
    /// Running flag
    running: Arc<Mutex<bool>>,
    /// SBI client for heartbeat requests
    client: Arc<SbiClient>,
}

impl HeartbeatManager {
    /// Create a new heartbeat manager
    pub fn new(config: HeartbeatConfig) -> Self {
        Self {
            records: Arc::new(Mutex::new(HashMap::new())),
            config,
            running: Arc::new(Mutex::new(false)),
            client: Arc::new(SbiClient::with_host_port("localhost", 7777)),
        }
    }

    /// Create with default configuration
    pub fn default() -> Self {
        Self::new(HeartbeatConfig::default())
    }

    /// Add NF instance for monitoring
    pub fn add_nf(&self, nf_instance_id: String, nf_fqdn: String, interval: Option<u64>) {
        let interval = interval.unwrap_or(self.config.default_interval);
        let record = HeartbeatRecord::new(nf_instance_id.clone(), nf_fqdn, interval);

        let mut records = self.records.lock().unwrap();
        records.insert(nf_instance_id, record);
    }

    /// Remove NF instance from monitoring
    pub fn remove_nf(&self, nf_instance_id: &str) {
        let mut records = self.records.lock().unwrap();
        records.remove(nf_instance_id);
    }

    /// Get heartbeat status for NF
    pub fn get_status(&self, nf_instance_id: &str) -> Option<HeartbeatStatus> {
        let records = self.records.lock().unwrap();
        records.get(nf_instance_id).map(|r| r.status)
    }

    /// Get all NF instances by status
    pub fn get_nfs_by_status(&self, status: HeartbeatStatus) -> Vec<String> {
        let records = self.records.lock().unwrap();
        records
            .iter()
            .filter(|(_, r)| r.status == status)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Suspend heartbeat for an NF
    pub fn suspend(&self, nf_instance_id: &str) {
        let mut records = self.records.lock().unwrap();
        if let Some(record) = records.get_mut(nf_instance_id) {
            record.status = HeartbeatStatus::Suspended;
        }
    }

    /// Resume heartbeat for an NF
    pub fn resume(&self, nf_instance_id: &str) {
        let mut records = self.records.lock().unwrap();
        if let Some(record) = records.get_mut(nf_instance_id) {
            if record.status == HeartbeatStatus::Suspended {
                record.status = HeartbeatStatus::Healthy;
                record.last_heartbeat = Instant::now();
            }
        }
    }

    /// Start heartbeat worker thread
    pub fn start(&self) {
        let mut running = self.running.lock().unwrap();
        if *running {
            eprintln!("Heartbeat manager already running");
            return;
        }
        *running = true;
        drop(running);

        let records = Arc::clone(&self.records);
        let running = Arc::clone(&self.running);
        let client = Arc::clone(&self.client);
        let poll_interval = Duration::from_millis(self.config.poll_interval_ms);
        let timeout = Duration::from_secs(self.config.request_timeout);

        std::thread::spawn(move || {
            #[cfg(feature = "log")]
            log::info!("Heartbeat manager started");

            while *running.lock().unwrap() {
                let nf_instances: Vec<(String, String, u64)> = {
                    let mut recs = records.lock().unwrap();
                    recs.iter_mut()
                        .filter(|(_, r)| r.status != HeartbeatStatus::Suspended)
                        .map(|(id, r)| {
                            r.update_status();
                            (id.clone(), r.nf_fqdn.clone(), r.interval)
                        })
                        .collect()
                };

                for (nf_id, nf_fqdn, interval) in nf_instances {
                    let should_send = {
                        let recs = records.lock().unwrap();
                        if let Some(record) = recs.get(&nf_id) {
                            record.last_heartbeat.elapsed() >= Duration::from_secs(interval)
                        } else {
                            false
                        }
                    };

                    if should_send {
                        Self::send_heartbeat(
                            Arc::clone(&records),
                            Arc::clone(&client),
                            nf_id,
                            nf_fqdn,
                            timeout,
                        );
                    }
                }

                std::thread::sleep(poll_interval);
            }

            #[cfg(feature = "log")]
            log::info!("Heartbeat manager stopped");
        });
    }

    /// Stop heartbeat worker thread
    pub fn stop(&self) {
        let mut running = self.running.lock().unwrap();
        *running = false;
    }

    /// Send heartbeat to an NF instance
    fn send_heartbeat(
        records: Arc<Mutex<HashMap<String, HeartbeatRecord>>>,
        client: Arc<SbiClient>,
        nf_instance_id: String,
        nf_fqdn: String,
        timeout: Duration,
    ) {
        std::thread::spawn(move || {
            // Build heartbeat URI
            let uri = format!("http://{nf_fqdn}/nnrf-nfm/v1/nf-instances/{nf_instance_id}");

            #[cfg(feature = "log")]
            log::debug!("Sending heartbeat to NF: {}", nf_instance_id);

            // Send heartbeat request (simplified - should be async in real implementation)
            // This would use the SBI client to send a PATCH request with heartbeat data
            let result = Self::perform_heartbeat_request(&client, &uri, timeout);

            let mut recs = records.lock().unwrap();
            if let Some(record) = recs.get_mut(&nf_instance_id) {
                match result {
                    Ok(_) => {
                        #[cfg(feature = "log")]
                        log::debug!("Heartbeat success for NF: {}", nf_instance_id);
                        record.mark_success();
                    }
                    Err(_e) => {
                        #[cfg(feature = "log")]
                        log::warn!("Heartbeat failed for NF {}: {}", nf_instance_id, _e);
                        record.mark_failure();
                    }
                }
            }
        });
    }

    /// Perform heartbeat request (placeholder)
    fn perform_heartbeat_request(
        _client: &SbiClient,
        _uri: &str,
        _timeout: Duration,
    ) -> SbiResult<()> {
        // In real implementation, this would:
        // 1. Build a PATCH request with heartbeat data
        // 2. Set timeout
        // 3. Send request and await response
        // 4. Validate response status

        // For now, simulate success
        Ok(())
    }

    /// Get statistics
    pub fn get_stats(&self) -> HeartbeatStats {
        let records = self.records.lock().unwrap();
        let total = records.len();
        let healthy = records.iter().filter(|(_, r)| r.status == HeartbeatStatus::Healthy).count();
        let degraded = records.iter().filter(|(_, r)| r.status == HeartbeatStatus::Degraded).count();
        let unreachable = records.iter().filter(|(_, r)| r.status == HeartbeatStatus::Unreachable).count();
        let suspended = records.iter().filter(|(_, r)| r.status == HeartbeatStatus::Suspended).count();

        HeartbeatStats {
            total,
            healthy,
            degraded,
            unreachable,
            suspended,
        }
    }
}

impl Drop for HeartbeatManager {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Heartbeat statistics
#[derive(Debug, Clone, Copy)]
pub struct HeartbeatStats {
    pub total: usize,
    pub healthy: usize,
    pub degraded: usize,
    pub unreachable: usize,
    pub suspended: usize,
}

/// Global heartbeat manager instance
static mut GLOBAL_HEARTBEAT_MANAGER: Option<HeartbeatManager> = None;
static MANAGER_INIT: std::sync::Once = std::sync::Once::new();

/// Get global heartbeat manager
pub fn global_heartbeat_manager() -> &'static HeartbeatManager {
    #[allow(static_mut_refs)]
    unsafe {
        MANAGER_INIT.call_once(|| {
            GLOBAL_HEARTBEAT_MANAGER = Some(HeartbeatManager::default());
        });
        GLOBAL_HEARTBEAT_MANAGER.as_ref()
            .expect("heartbeat manager initialized by call_once")
    }
}

/// Initialize heartbeat manager
pub fn init_heartbeat_manager() {
    let _ = global_heartbeat_manager();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heartbeat_record_creation() {
        let record = HeartbeatRecord::new(
            "nf-001".to_string(),
            "nf.example.com".to_string(),
            10,
        );

        assert_eq!(record.nf_instance_id, "nf-001");
        assert_eq!(record.interval, 10);
        assert_eq!(record.status, HeartbeatStatus::Healthy);
        assert_eq!(record.failure_count, 0);
    }

    #[test]
    fn test_heartbeat_status_transitions() {
        let mut record = HeartbeatRecord::new(
            "nf-001".to_string(),
            "nf.example.com".to_string(),
            1, // 1 second for fast testing
        );

        // Initially healthy
        assert_eq!(record.status, HeartbeatStatus::Healthy);

        // Mark failure
        record.mark_failure();
        assert_eq!(record.failure_count, 1);

        // Mark success
        record.mark_success();
        assert_eq!(record.failure_count, 0);
        assert_eq!(record.status, HeartbeatStatus::Healthy);
    }

    #[test]
    fn test_heartbeat_manager_add_remove() {
        let manager = HeartbeatManager::default();

        manager.add_nf(
            "nf-001".to_string(),
            "nf.example.com".to_string(),
            Some(10),
        );

        let status = manager.get_status("nf-001");
        assert_eq!(status, Some(HeartbeatStatus::Healthy));

        manager.remove_nf("nf-001");
        let status = manager.get_status("nf-001");
        assert_eq!(status, None);
    }

    #[test]
    fn test_heartbeat_suspend_resume() {
        let manager = HeartbeatManager::default();

        manager.add_nf(
            "nf-001".to_string(),
            "nf.example.com".to_string(),
            None,
        );

        manager.suspend("nf-001");
        assert_eq!(manager.get_status("nf-001"), Some(HeartbeatStatus::Suspended));

        manager.resume("nf-001");
        assert_eq!(manager.get_status("nf-001"), Some(HeartbeatStatus::Healthy));
    }

    #[test]
    fn test_get_nfs_by_status() {
        let manager = HeartbeatManager::default();

        manager.add_nf("nf-001".to_string(), "nf1.example.com".to_string(), None);
        manager.add_nf("nf-002".to_string(), "nf2.example.com".to_string(), None);
        manager.add_nf("nf-003".to_string(), "nf3.example.com".to_string(), None);

        manager.suspend("nf-003");

        let healthy_nfs = manager.get_nfs_by_status(HeartbeatStatus::Healthy);
        assert_eq!(healthy_nfs.len(), 2);

        let suspended_nfs = manager.get_nfs_by_status(HeartbeatStatus::Suspended);
        assert_eq!(suspended_nfs.len(), 1);
        assert!(suspended_nfs.contains(&"nf-003".to_string()));
    }

    #[test]
    fn test_heartbeat_stats() {
        let manager = HeartbeatManager::default();

        manager.add_nf("nf-001".to_string(), "nf1.example.com".to_string(), None);
        manager.add_nf("nf-002".to_string(), "nf2.example.com".to_string(), None);
        manager.suspend("nf-002");

        let stats = manager.get_stats();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.healthy, 1);
        assert_eq!(stats.suspended, 1);
    }

    #[test]
    fn test_heartbeat_config() {
        let config = HeartbeatConfig {
            default_interval: 30,
            poll_interval_ms: 500,
            max_concurrent: 50,
            request_timeout: 10,
        };

        assert_eq!(config.default_interval, 30);
        assert_eq!(config.poll_interval_ms, 500);
    }
}
