//! NF Heartbeat and Keep-Alive Support (B8.4)
//!
//! Implements NF heartbeat mechanism for status monitoring per 3GPP TS 29.510.

#![allow(unexpected_cfgs)]

use crate::client::SbiClient;
use crate::error::SbiResult;
use crate::message::SbiRequest;
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
            default_interval: 10,   // 10 seconds
            poll_interval_ms: 1000, // 1 second
            max_concurrent: 100,
            request_timeout: 5, // 5 seconds
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
        let healthy = records
            .iter()
            .filter(|(_, r)| r.status == HeartbeatStatus::Healthy)
            .count();
        let degraded = records
            .iter()
            .filter(|(_, r)| r.status == HeartbeatStatus::Degraded)
            .count();
        let unreachable = records
            .iter()
            .filter(|(_, r)| r.status == HeartbeatStatus::Unreachable)
            .count();
        let suspended = records
            .iter()
            .filter(|(_, r)| r.status == HeartbeatStatus::Suspended)
            .count();

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
static GLOBAL_HEARTBEAT_MANAGER: std::sync::OnceLock<HeartbeatManager> = std::sync::OnceLock::new();

/// Get global heartbeat manager
pub fn global_heartbeat_manager() -> &'static HeartbeatManager {
    GLOBAL_HEARTBEAT_MANAGER.get_or_init(HeartbeatManager::default)
}

/// Initialize heartbeat manager
pub fn init_heartbeat_manager() {
    let _ = global_heartbeat_manager();
}

// ---------------------------------------------------------------------------
// NF-side outbound heartbeat worker
// ---------------------------------------------------------------------------

/// Parse host and port from a URI string (e.g., "http://localhost:7777").
fn parse_nrf_host_port(uri: &str) -> Option<(String, u16)> {
    let without_scheme = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    let (host_port, _path) = without_scheme
        .split_once('/')
        .unwrap_or((without_scheme, ""));
    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        let port: u16 = port_str.parse().ok()?;
        Some((host.to_string(), port))
    } else {
        let default_port = if uri.starts_with("https://") { 443 } else { 80 };
        Some((host_port.to_string(), default_port))
    }
}

/// Build the RFC 6902 JSON Patch body for an NRF heartbeat that also reports a
/// real `NFProfile.load` gauge (TS 29.510 §5.2.2.3.2; `load` is `0..=100`).
///
/// - `nfStatus` is refreshed via `replace` (always present after registration).
/// - `/load` uses `add` so it is created-or-replaced regardless of whether the
///   initial registration carried a `load` value (RFC 6902 `replace` requires
///   the target to already exist; `add` does not — nrfd's `apply_json_patch`
///   enforces that distinction). `load` is saturated to 100.
///
/// nrfd auto-detects an array body as JSON Patch (`main.rs` dispatch on shape)
/// and applies both the merge-object and json-patch load PATCH forms.
pub fn build_load_patch(load: u8) -> serde_json::Value {
    build_status_patch(load, self_nf_status())
}

/// Like [`build_load_patch`] but with an explicit `nfStatus` (issue #22
/// NES: a self-suspended NF keeps heartbeating with `SUSPENDED` so the
/// NRF's liveness timer stays armed without reactivating the profile).
/// With the default [`self_nf_status`] of `Registered` the output is
/// byte-identical to the historical `build_load_patch`.
pub fn build_status_patch(load: u8, status: crate::context::NfStatus) -> serde_json::Value {
    let load = load.min(100);
    serde_json::json!([
        {"op": "replace", "path": "/nfStatus", "value": nf_status_wire(status)},
        {"op": "add",     "path": "/load",     "value": load}
    ])
}

/// TS 29.510 wire string for an [`crate::context::NfStatus`].
pub fn nf_status_wire(status: crate::context::NfStatus) -> &'static str {
    match status {
        crate::context::NfStatus::Registered => "REGISTERED",
        crate::context::NfStatus::Suspended => "SUSPENDED",
        crate::context::NfStatus::Undiscoverable => "UNDISCOVERABLE",
    }
}

// ─── NES self-status plumbing (issue #22) ────────────────────────────────────
// Defaults (Registered, unpaused) keep the heartbeat worker byte-for-byte on
// its pre-NES behavior; only an NF that opts into NES ever mutates these.

static SELF_NF_STATUS: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
static HEARTBEAT_PAUSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Set the status this NF advertises in its own NRF heartbeats.
pub fn set_self_nf_status(status: crate::context::NfStatus) {
    let value = match status {
        crate::context::NfStatus::Registered => 0,
        crate::context::NfStatus::Suspended => 1,
        crate::context::NfStatus::Undiscoverable => 2,
    };
    SELF_NF_STATUS.store(value, std::sync::atomic::Ordering::Relaxed);
}

/// The status this NF currently advertises in its own NRF heartbeats.
pub fn self_nf_status() -> crate::context::NfStatus {
    match SELF_NF_STATUS.load(std::sync::atomic::Ordering::Relaxed) {
        1 => crate::context::NfStatus::Suspended,
        2 => crate::context::NfStatus::Undiscoverable,
        _ => crate::context::NfStatus::Registered,
    }
}

/// Pause/resume the outbound heartbeat worker (issue #22 NES `deregister`
/// action: a deregistered NF must not keep PATCHing its deleted profile).
pub fn set_heartbeat_paused(paused: bool) {
    HEARTBEAT_PAUSED.store(paused, std::sync::atomic::Ordering::Relaxed);
}

/// Whether the outbound heartbeat worker is paused.
pub fn heartbeat_paused() -> bool {
    HEARTBEAT_PAUSED.load(std::sync::atomic::Ordering::Relaxed)
}

// ─── NF deregistration on shutdown (#235) ────────────────────────────────────
//
// Every NF in this workspace that registers an NFProfile also spawns a
// heartbeat worker — verified by grep: the 17 crates matching
// `spawn_heartbeat_worker` are exactly the 17 that PUT
// `/nnrf-nfm/v1/nf-instances/{id}`. `pind` deliberately does not register
// (PIND-01), and `scpd` / `seppd` only consume `nnrf-disc`. So recording the ID
// here catches every registering NF, and `deregister_self()` needs no argument
// — which matters, because an ID passed by hand at 17 shutdown sites is exactly
// where a copy-paste error would live.

static REGISTERED_NF_INSTANCE_ID: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Record the NF instance ID this process registered under, so
/// [`deregister_self`] can DELETE the right profile without being told.
///
/// Called automatically by [`spawn_heartbeat_worker_with_load`]; public so an NF
/// that registers without a heartbeat worker can opt in (none does today).
pub fn set_registered_nf_instance_id(nf_instance_id: impl Into<String>) {
    let id = nf_instance_id.into();
    match REGISTERED_NF_INSTANCE_ID.lock() {
        Ok(mut slot) => *slot = Some(id),
        // A poisoned lock here must not take the process down on a path whose
        // only job is bookkeeping; the cost is that deregistration is skipped,
        // which is the pre-#235 behaviour and is logged.
        Err(e) => log::warn!("could not record registered NF instance ID: {e}"),
    }
}

/// The NF instance ID this process registered under, if it registered.
pub fn registered_nf_instance_id() -> Option<String> {
    REGISTERED_NF_INSTANCE_ID
        .lock()
        .ok()
        .and_then(|slot| slot.clone())
}

/// Forget the recorded NF instance ID.
///
/// **Only for use in tests**, so a test that records an ID leaves the
/// process-global back as it found it.
///
/// NOT gated behind `cfg(test)`: `nextgcore-sbi` compiles as a *dependency* of
/// every NF crate, and `cfg(test)` is false in that build — the recorded trap
/// that `udmd`'s ungated `test_support` module exists for. A test in `nrfd` needs
/// this, so gating it would make the symbol invisible exactly where it is used.
pub fn clear_registered_nf_instance_id() {
    if let Ok(mut slot) = REGISTERED_NF_INSTANCE_ID.lock() {
        *slot = None;
    }
}

// ─── Re-registration after the NRF forgets us (#434) ────────────────────────
//
// A heartbeat that gets 404 means the NRF no longer holds this NF's profile —
// an NRF restart, or a registration that landed on an NRF pod a rollout then
// killed. TS 29.510 §5.2.2.3.2 step 2b defines only the 404 itself; it does not
// say what the NF does next (§5.2.2.1's "needs not re-register" concerns an NRF
// Set with SHARED context, which a single in-memory NRF is not). Re-registering
// is this implementation's choice, made because nothing else restores
// discoverability: before #434 the NF stayed Ready and undiscoverable until
// someone restarted it.
//
// Each of the 17 registering daemons builds its own profile in its own
// `register_with_nrf`, so the worker cannot rebuild one. Each daemon instead
// records the exact profile it PUT, here, and the worker re-PUTs that.

static REGISTERED_PROFILE: std::sync::Mutex<Option<serde_json::Value>> =
    std::sync::Mutex::new(None);

/// Serialises tests that mutate this process's NRF-registration state: the
/// pause flag, the registered instance ID and the registered profile.
///
/// **A test harness hook, not a product knob**; no NF takes it. `pub` and NOT
/// `cfg(test)`-gated because the tests that need it live in `nrfd`, where this
/// crate is a dependency and `cfg(test)` is false. Declared here, beside the
/// globals it guards, so there is exactly one lock for them; a second lock in a
/// test module would serialise nothing against the first.
static REGISTRATION_STATE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take [`REGISTRATION_STATE_TEST_LOCK`], recovering a poisoned guard so one
/// failing test does not cascade into every other holder.
pub fn lock_registration_state_for_test() -> std::sync::MutexGuard<'static, ()> {
    REGISTRATION_STATE_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Record the NFProfile this process just registered, so a heartbeat that finds
/// the NRF has forgotten it can register the same profile again (#434).
///
/// Call it in the registration PUT's success arm with the value that was sent.
/// Every daemon that spawns the heartbeat worker must call it; a source guard
/// in this module's tests enforces that, because a daemon that forgot would
/// silently keep the pre-#434 behaviour.
pub fn set_registered_profile(profile: &impl serde::Serialize) {
    let value = match serde_json::to_value(profile) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("could not record registered NF profile: {e}");
            return;
        }
    };
    // #1334: every registering daemon calls this in its NFRegister success arm, so
    // it is the one place the registration is counted for `/metrics`.
    nextgcore_metrics::nf::nrf_registration_succeeded();
    match REGISTERED_PROFILE.lock() {
        Ok(mut slot) => *slot = Some(value),
        // Same posture as the instance-ID slot: bookkeeping must not take the
        // process down; the cost is that re-registration is unavailable.
        Err(e) => log::warn!("could not record registered NF profile: {e}"),
    }
}

/// The NFProfile this process last registered, if it recorded one.
pub fn registered_profile() -> Option<serde_json::Value> {
    REGISTERED_PROFILE.lock().ok().and_then(|slot| slot.clone())
}

/// Forget the recorded profile.
///
/// **Only for use in tests.** NOT gated behind `cfg(test)`, for the reason
/// [`clear_registered_nf_instance_id`] gives: `nrfd`'s test needs it, and
/// `cfg(test)` is false in the dependency build.
pub fn clear_registered_profile() {
    if let Ok(mut slot) = REGISTERED_PROFILE.lock() {
        *slot = None;
    }
}

/// How many times [`reregister_self`] has succeeded in this process.
static REREGISTRATIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many times this process has re-registered after the NRF lost its
/// profile (#434). A change means the NRF lost its state, so whatever else this
/// NF holds at that NRF, its NF status subscriptions included, is gone too
/// (#940: the AMF re-subscribes when it sees this move).
pub fn reregistration_count() -> u64 {
    REREGISTRATIONS.load(std::sync::atomic::Ordering::Acquire)
}

/// Re-register this process's recorded profile under `nf_instance_id`
/// (`PUT /nnrf-nfm/v1/nf-instances/{id}`, NFRegister, TS 29.510 §5.2.2.2.1).
///
/// Refuses a recorded profile whose `nfInstanceId` names a different instance:
/// the NES resume path re-registers under a new ID, and PUTting a stale profile
/// would resurrect an instance this process no longer is. Returns the NRF's
/// status on 200/201.
pub async fn reregister_self(nf_instance_id: &str) -> Result<u16, String> {
    let profile =
        registered_profile().ok_or_else(|| "no registered profile recorded".to_string())?;
    if let Some(recorded) = profile.get("nfInstanceId").and_then(|v| v.as_str()) {
        if recorded != nf_instance_id {
            return Err(format!(
                "recorded profile is for {recorded}, not {nf_instance_id}; refusing to re-register it"
            ));
        }
    }
    let ctx = crate::context::global_context();
    let nrf_uri = ctx
        .get_nrf_uri()
        .await
        .ok_or_else(|| "no NRF URI configured".to_string())?;
    let (nrf_host, nrf_port) =
        parse_nrf_host_port(&nrf_uri).ok_or_else(|| format!("invalid NRF URI '{nrf_uri}'"))?;
    let client = SbiClient::with_host_port(&nrf_host, nrf_port);
    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    match client.put_json(&path, &profile).await {
        Ok(resp) if resp.status == 200 || resp.status == 201 => {
            REREGISTRATIONS.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            nextgcore_metrics::nf::nrf_registration_succeeded();
            Ok(resp.status)
        }
        Ok(resp) => Err(format!("NRF returned status {}", resp.status)),
        Err(e) => Err(format!("NFRegister failed: {e}")),
    }
}

// ─── Initial NFRegister retry (#1482) ───────────────────────────────────────
//
// TS 29.510 §5.2.2.2.1: NFRegister is what makes the NRF mark an NF "available
// to be discovered by other NFs". §5.2.2.2.2 step 2b lists the failures (400,
// 500, 3xx) and says nothing about what the NF does next, so the retry policy
// is this implementation's. Before #1482 every registering daemon made ONE
// attempt and, on a transport error or a non-2xx, logged "will operate without
// NRF" and ran undiscoverable for its whole life. An NRF restarting, or an NRF
// Service with no ready endpoint during a rollout, was enough to cause that.
// pcfd was worse: it read a failure as success and started a heartbeat with no
// recorded profile, so even the #434 404 path could not re-register it.
//
// Every daemon now registers through [`register_or_retry`]. The first attempt
// is awaited inline, so the happy-path startup order is unchanged. A failure
// moves the attempts to a background task with bounded exponential backoff,
// and the daemon's `on_registered` (heartbeat worker, and anything else that
// must follow a registration) runs exactly once, after the attempt that
// succeeded. So `set_registered_profile` always holds what the NRF holds, and
// the heartbeat never runs for a profile the NRF never accepted.

/// Backoff for the initial NFRegister retry (#1482).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterRetryPolicy {
    /// The wait before the second attempt. Each later wait doubles it.
    pub initial: Duration,
    /// The cap on any one wait. Attempts continue at this period until one
    /// succeeds or the NF deregisters for shutdown.
    pub max: Duration,
    /// Each wait is spread uniformly by up to this many percent either way, so
    /// replicas that failed together do not retry in lockstep (#1574 review).
    /// 0 for none.
    pub jitter_percent: u8,
}

impl Default for RegisterRetryPolicy {
    /// 1 s, 2 s, 4 s, ... capped at 30 s. An NRF that is back within a
    /// rollout's few seconds is reached within a second or two of its return.
    /// A long outage costs one attempt (and one warning) per 30 s.
    fn default() -> Self {
        RegisterRetryPolicy {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(30),
            jitter_percent: 20,
        }
    }
}

impl RegisterRetryPolicy {
    /// The wait after failed attempt `n` (1-based).
    pub fn delay_after(&self, attempt: u32) -> Duration {
        let factor = 1u32
            .checked_shl(attempt.saturating_sub(1))
            .unwrap_or(u32::MAX);
        self.initial.saturating_mul(factor).min(self.max)
    }

    /// `delay` spread by up to [`RegisterRetryPolicy::jitter_percent`] either way.
    pub fn jittered(&self, delay: Duration) -> Duration {
        if self.jitter_percent == 0 {
            return delay;
        }
        let span = f64::from(self.jitter_percent.min(100)) / 100.0;
        let factor = 1.0 + span * (2.0 * rand::random::<f64>() - 1.0);
        delay.mul_f64(factor.max(0.0))
    }
}

/// Whether an NFRegister error is the NRF REJECTING the profile (a 3xx or 4xx,
/// TS 29.510 §5.2.2.2.2 step 2b: 400 for an encoding or shared-data error, 3xx
/// for a redirect) rather than the NRF being down. Retrying the same PUT will
/// not fix that, so it is logged as an error and retried only at the cap.
/// 408 and 429 are load, not rejection. The register functions report a
/// status as "... status NNN ...".
fn is_rejection(error: &str) -> bool {
    error
        .match_indices("status ")
        .filter_map(|(i, m)| error.get(i + m.len()..i + m.len() + 3))
        .filter_map(|code| code.parse::<u16>().ok())
        .any(|code| (300..500).contains(&code) && code != 408 && code != 429)
}

/// What [`register_or_retry`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Registration {
    /// The first attempt succeeded under this NF instance ID. `on_registered`
    /// has already run.
    Registered(String),
    /// No NRF is configured. Nothing was sent, nothing is retried, and
    /// `on_registered` does not run.
    NotConfigured,
    /// The first attempt failed. A background task keeps trying and runs
    /// `on_registered` after the first attempt that succeeds.
    Retrying,
}

/// The background NFRegister retry's state, shared with [`deregister_self`].
///
/// One `Mutex` so each check and the step it guards are one step against
/// shutdown. With separate flags a retry could see "not abandoned", lose the CPU
/// to `deregister_self` (which finds no recorded ID and sends nothing), and
/// register a profile nothing will ever delete.
#[derive(Debug)]
struct RetryState {
    /// [`deregister_self`] has run: no new attempt starts.
    abandoned: bool,
    /// An attempt's PUT is at the NRF now.
    in_flight: bool,
    /// [`deregister_self`] is waiting for that attempt (bounded), and will
    /// DELETE what it lands with: the attempt hands the ID over in `landed`.
    waiter: bool,
    /// The ID an attempt registered under after shutdown began.
    landed: Option<String>,
}

static RETRY_STATE: std::sync::Mutex<RetryState> = std::sync::Mutex::new(RetryState {
    abandoned: false,
    in_flight: false,
    waiter: false,
    landed: None,
});

fn retry_state() -> std::sync::MutexGuard<'static, RetryState> {
    RETRY_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Signalled each time an attempt finishes, for a waiting [`deregister_self`].
fn attempt_done() -> &'static tokio::sync::Notify {
    static DONE: std::sync::OnceLock<tokio::sync::Notify> = std::sync::OnceLock::new();
    DONE.get_or_init(tokio::sync::Notify::new)
}

/// Whether [`deregister_self`] has stopped any pending NFRegister retry.
pub fn registration_abandoned() -> bool {
    retry_state().abandoned
}

/// Reset the retry state [`deregister_self`] sets.
///
/// **Only for use in tests**, under [`lock_registration_state_for_test`]. Not
/// `cfg(test)`-gated, for the reason [`clear_registered_nf_instance_id`] gives.
pub fn clear_registration_abandoned() {
    let mut st = retry_state();
    st.abandoned = false;
    st.in_flight = false;
    st.waiter = false;
    st.landed = None;
}

/// NFRegister (TS 29.510 §5.2.2.2.2) with a bounded-backoff retry (#1482).
///
/// `register` makes one attempt. It returns:
/// - `Ok(Some(id))` on a 200/201, with the profile already recorded by
///   [`set_registered_profile`];
/// - `Ok(None)` when no NRF is configured;
/// - `Err` on a transport error or any other status.
///
/// The first attempt is awaited here. On success `on_registered(id)` runs before
/// this returns. On failure the attempts continue on a spawned task, waiting
/// [`RegisterRetryPolicy::delay_after`] between them, and `on_registered` runs
/// on that task after the first success. It runs at most once. The task stops
/// when an attempt reports `Ok(None)` (the NRF URI was removed), or when
/// [`deregister_self`] has run. An attempt in flight when `deregister_self`
/// runs is waited for (bounded), and what it registered is DELETEd by
/// `deregister_self` itself, before the process can exit (#1574 review).
///
/// A rejection (3xx/4xx but 408/429, see [`is_rejection`]) is logged as an
/// error and retried only at the cap: the same PUT will not fix it.
///
/// `nf` names the daemon in the log lines (e.g. `"PCF"`).
pub async fn register_or_retry<R, Fut, S>(
    nf: &'static str,
    policy: RegisterRetryPolicy,
    mut register: R,
    on_registered: S,
) -> Registration
where
    R: FnMut() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<Option<String>, String>> + Send + 'static,
    S: FnOnce(String) + Send + 'static,
{
    let first = match register().await {
        Ok(Some(id)) => {
            on_registered(id.clone());
            return Registration::Registered(id);
        }
        Ok(None) => return Registration::NotConfigured,
        Err(e) => e,
    };
    let delay = if is_rejection(&first) {
        log::error!(
            "{nf}: the NRF rejected NFRegister (attempt 1): {first}. Retrying the same \
             profile will not fix this; check the NFProfile and the NRF. Retrying every {:?} \
             (the NF is not discoverable until it registers, TS 29.510 §5.2.2.2.1)",
            policy.max
        );
        policy.max
    } else {
        let delay = policy.delay_after(1);
        log::warn!(
            "{nf}: NFRegister failed (attempt 1): {first}; retrying in ~{delay:?} \
             (the NF is not discoverable until it registers, TS 29.510 §5.2.2.2.1)"
        );
        delay
    };
    tokio::spawn(async move {
        let mut attempt: u32 = 1;
        let mut delay = delay;
        let mut rejected = is_rejection(&first);
        loop {
            tokio::time::sleep(policy.jittered(delay)).await;
            {
                let mut st = retry_state();
                if st.abandoned {
                    log::info!("{nf}: shutting down; NFRegister retry stopped");
                    return;
                }
                st.in_flight = true;
            }
            attempt = attempt.saturating_add(1);
            let result = register().await;
            match result {
                Ok(Some(id)) => {
                    // None: registered; Some(true): handed to the waiting
                    // deregister_self; Some(false): nobody waits, DELETE here.
                    let late = {
                        let mut st = retry_state();
                        st.in_flight = false;
                        if !st.abandoned {
                            on_registered(id.clone());
                            None
                        } else if st.waiter {
                            st.landed = Some(id.clone());
                            Some(true)
                        } else {
                            Some(false)
                        }
                    };
                    attempt_done().notify_waiters();
                    match late {
                        None => {
                            log::info!(
                                "{nf}: registered with the NRF on attempt {attempt} (id={id})"
                            )
                        }
                        Some(true) => log::info!(
                            "{nf}: registered during shutdown; NFDeregister of {id} follows"
                        ),
                        Some(false) => {
                            log::info!("{nf}: registered during shutdown; deregistering {id}");
                            if let Err(e) = deregister_nf(&id).await {
                                log::warn!("{nf}: NFDeregister of {id} failed: {e}");
                            }
                        }
                    }
                    return;
                }
                Ok(None) => {
                    retry_state().in_flight = false;
                    attempt_done().notify_waiters();
                    log::info!("{nf}: no NRF configured any more; NFRegister retry stopped");
                    return;
                }
                Err(e) => {
                    retry_state().in_flight = false;
                    attempt_done().notify_waiters();
                    if is_rejection(&e) {
                        delay = policy.max;
                        if !rejected {
                            rejected = true;
                            log::error!(
                                "{nf}: the NRF rejected NFRegister (attempt {attempt}): {e}. \
                                 Retrying the same profile will not fix this; check the \
                                 NFProfile and the NRF. Retrying every {delay:?}"
                            );
                            continue;
                        }
                    } else {
                        delay = policy.delay_after(attempt);
                    }
                    log::warn!(
                        "{nf}: NFRegister failed (attempt {attempt}): {e}; retrying in ~{delay:?}"
                    );
                }
            }
        }
    });
    Registration::Retrying
}

/// `Some(id)` unless `id` is empty: the convention the `Result<String, String>`
/// registration functions use for "no NRF configured".
pub fn registered_id(id: String) -> Option<String> {
    (!id.is_empty()).then_some(id)
}

/// The most [`deregister_self`] waits for an in-flight NFRegister retry to land,
/// and then, separately, for the NRF's answer to the DELETE: at most 10 s in
/// all. Before this, the client's own 5 s connect plus 30 s request timeouts
/// applied, which is longer than Kubernetes' default 30 s termination grace.
pub const DEREGISTER_TIMEOUT: Duration = Duration::from_secs(5);

/// `DELETE /nnrf-nfm/v1/nf-instances/{nfInstanceId}` — NFDeregister,
/// TS 29.510 §5.2.2.2.3.
///
/// The single client for this operation. Before #235 there were two hand-rolled
/// copies (`udmd`'s `udm_nrf_deregister` and the inline DELETE in `udmd`'s NES
/// driver) and sixteen NFs with none at all.
pub async fn deregister_nf(nf_instance_id: &str) -> Result<(), String> {
    let ctx = crate::context::global_context();
    let nrf_uri = ctx
        .get_nrf_uri()
        .await
        .ok_or_else(|| "no NRF URI configured".to_string())?;
    let (nrf_host, nrf_port) =
        parse_nrf_host_port(&nrf_uri).ok_or_else(|| format!("invalid NRF URI '{nrf_uri}'"))?;
    let client = SbiClient::with_host_port(&nrf_host, nrf_port);
    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    // #1334: deleting this process's own profile ends its registration.
    let own = registered_nf_instance_id().as_deref() == Some(nf_instance_id);

    let result = match client.send_request(SbiRequest::delete(&path)).await {
        // TS 29.510 §5.2.2.2.3 specifies 204; 200 is accepted too rather than
        // reported as a failure, since either means the profile is gone.
        Ok(resp) if resp.status == 204 || resp.status == 200 => Ok(()),
        // A profile the NRF does not hold is the state we wanted: treat 404 as
        // success so a shutdown after the supervision timer already expired does
        // not log an alarming warning.
        Ok(resp) if resp.status == 404 => {
            log::debug!("NRF had already dropped NF instance {nf_instance_id}");
            Ok(())
        }
        Ok(resp) => Err(format!("NRF returned status {}", resp.status)),
        Err(e) => Err(format!("NFDeregister failed: {e}")),
    };
    if own && result.is_ok() {
        nextgcore_metrics::nf::nrf_registered(false);
    }
    result
}

/// Deregister this process's own NFProfile from the NRF, for the shutdown path.
///
/// Pauses the heartbeat worker **first**: a tick that lands after the DELETE
/// would PATCH a profile that no longer exists, which reads to an operator as
/// the NRF losing registrations rather than as an ordering bug here. The NES
/// deregister action established the same ordering.
///
/// Never returns an error the caller has to handle at shutdown — a failure is
/// logged and swallowed, because refusing to exit because the NRF is unreachable
/// would be worse than the stale profile this is trying to avoid. Returns
/// whether a DELETE was actually issued so a test can assert it.
pub async fn deregister_self() -> bool {
    // #1482: stop any pending NFRegister retry FIRST, and read the recorded ID
    // under the same guard, so a retry cannot register between the two.
    let (registered, in_flight) = {
        let mut st = retry_state();
        st.abandoned = true;
        if st.in_flight {
            st.waiter = true;
        }
        (registered_nf_instance_id(), st.in_flight)
    };
    // #1574 review: an attempt whose PUT is at the NRF now may still register.
    // Wait for it (bounded), and DELETE what it lands with HERE: a DELETE left
    // to the retry task would be cancelled when the process exits.
    let landed = if in_flight {
        wait_for_in_flight_attempt().await
    } else {
        None
    };
    let Some(nf_instance_id) = registered.or(landed) else {
        log::debug!("No registered NF instance ID: skipping NRF deregistration");
        return false;
    };

    set_heartbeat_paused(true);

    // #1482: bounded, so an unreachable NRF cannot hold the process past its
    // termination grace.
    let result =
        match tokio::time::timeout(DEREGISTER_TIMEOUT, deregister_nf(&nf_instance_id)).await {
            Ok(r) => r,
            Err(_) => Err(format!("no answer within {DEREGISTER_TIMEOUT:?}")),
        };
    match result {
        Ok(()) => {
            log::info!("Deregistered NF instance {nf_instance_id} from the NRF");
            true
        }
        Err(e) => {
            // Deliberately a warning, not an error return: the process is
            // exiting either way, and the NRF's supervision timer is the
            // backstop this is merely trying to pre-empt.
            log::warn!("NRF deregistration for {nf_instance_id} failed: {e}");
            true
        }
    }
}

/// Wait, bounded by [`DEREGISTER_TIMEOUT`], for the NFRegister attempt in flight
/// to finish, and take the ID it registered under during shutdown, if any.
async fn wait_for_in_flight_attempt() -> Option<String> {
    let deadline = tokio::time::Instant::now() + DEREGISTER_TIMEOUT;
    loop {
        // Register interest BEFORE looking, so a notify between the look and
        // the await is not lost.
        let notified = attempt_done().notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        {
            let mut st = retry_state();
            if !st.in_flight {
                st.waiter = false;
                return st.landed.take();
            }
        }
        if tokio::time::timeout_at(deadline, notified).await.is_err() {
            // Give up waiting. From here an attempt that lands DELETEs its own
            // registration (best effort: the process may exit first). One that
            // landed in between left its ID here.
            let mut st = retry_state();
            st.waiter = false;
            let landed = st.landed.take();
            if landed.is_none() {
                log::warn!(
                    "an NFRegister attempt was still in flight after {DEREGISTER_TIMEOUT:?}; \
                     if it lands, it deregisters itself"
                );
            }
            return landed;
        }
    }
}

/// One-off `nfStatus` PATCH toward the NRF (issue #22 NES transitions),
/// using the exact wire shape of the heartbeat worker (RFC 6902 array,
/// `application/json-patch+json`).
pub async fn patch_nf_status(
    nf_instance_id: &str,
    status: crate::context::NfStatus,
    load: u8,
) -> Result<(), String> {
    let ctx = crate::context::global_context();
    let nrf_uri = ctx
        .get_nrf_uri()
        .await
        .ok_or_else(|| "no NRF URI configured".to_string())?;
    let (nrf_host, nrf_port) =
        parse_nrf_host_port(&nrf_uri).ok_or_else(|| format!("invalid NRF URI '{nrf_uri}'"))?;
    let client = SbiClient::with_host_port(&nrf_host, nrf_port);
    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    let body = build_status_patch(load, status);
    let request = SbiRequest::patch(&path)
        .with_json_body(&body)
        .map_err(|e| format!("failed to serialize nfStatus patch: {e}"))?
        .with_header("Content-Type", "application/json-patch+json");
    match client.send_request(request).await {
        Ok(resp) if resp.status == 200 || resp.status == 204 => Ok(()),
        Ok(resp) => Err(format!("NRF returned status {}", resp.status)),
        Err(e) => Err(format!("nfStatus PATCH failed: {e}")),
    }
}

/// Spawn a background tokio task that periodically sends a heartbeat
/// `PATCH /nnrf-nfm/v1/nf-instances/{nf_instance_id}` to the NRF.
///
/// The NRF URI is read from the global SBI context at each tick so it
/// stays correct even if the context is updated after startup.
///
/// `interval_secs` is the fire interval (use `heartBeatTimer / 2`, e.g. 5).
/// The task runs until the process exits; it logs warnings on failure but
/// never panics, so a temporary NRF outage does not crash the NF.
///
/// NFs that do not (yet) expose a load gauge report a constant `0` load,
/// keeping the `/load` hook wired for later (see
/// [`spawn_heartbeat_worker_with_load`] for the real-gauge variant).
pub fn spawn_heartbeat_worker(nf_instance_id: String, interval_secs: u64) {
    spawn_heartbeat_worker_with_load(nf_instance_id, interval_secs, || 0);
}

/// Publish an `NFProfile.load` reading to this process's own
/// [`OverloadReporter`](crate::overload::OverloadReporter), so responses carry
/// `3gpp-Sbi-Oci` while the NF is above
/// [`LOAD_OVERLOAD_THRESHOLD`](crate::overload::LOAD_OVERLOAD_THRESHOLD) (#273).
///
/// Extracted from the tick body so it is unit-testable without a running worker,
/// and `pub` so an NF with a faster-moving signal than the 5s heartbeat (an AMF
/// reacting to an N2 burst, say) can publish between ticks. Logs only on a
/// *transition*, honouring §6.4.3.4.3's warning against churning on small
/// variations: a steady overload produces one line, not one per tick.
pub fn publish_overload_from_load(nf_instance_id: &str, load_percent: u8) {
    let reporter = crate::overload::self_overload_reporter();
    let before = reporter.reduction_metric();
    reporter.report_load(load_percent);
    let after = reporter.reduction_metric();
    if after != before {
        if after == 0 {
            log::info!(
                "NF {nf_instance_id} load {load_percent}% has fallen below the overload \
                 threshold; withdrawing 3gpp-Sbi-Oci (TS 29.500 §6.4.3.4.3 metric 0)"
            );
        } else {
            log::warn!(
                "NF {nf_instance_id} load {load_percent}% is at or above the overload \
                 threshold; asking peers for {after}% traffic reduction via 3gpp-Sbi-Oci \
                 (TS 29.500 §6.4.3.2)"
            );
        }
    }
}

/// Like [`spawn_heartbeat_worker`], but PATCHes a real `NFProfile.load` gauge
/// each tick, computed fresh by `load_fn` (TS 29.510 §5.2.2.3.2).
///
/// `load_fn` is polled on every tick so the reported load tracks live NF state
/// (e.g. registered-UE or session count as a percentage of configured
/// capacity). Values are saturated to 100 by [`build_load_patch`]. As with the
/// plain worker, a PATCH failure only logs a warning and never affects NF
/// operation, so a temporary NRF outage cannot crash the NF.
///
/// # #273: this is also the producer-side overload metric source
///
/// The same `load_fn` reading drives
/// [`self_overload_reporter`](crate::overload::self_overload_reporter) via
/// [`OverloadReporter::report_load`](crate::overload::OverloadReporter::report_load),
/// so an NF above [`LOAD_OVERLOAD_THRESHOLD`](crate::overload::LOAD_OVERLOAD_THRESHOLD)
/// starts stamping `3gpp-Sbi-Oci` on its own responses (TS 29.500 §6.4.3.2)
/// without any per-daemon wiring. This function is the right place because it is
/// the ONE place every registering NF in this tree already computes a real
/// capacity percentage — grep confirms 16 call sites across 16 daemons, each
/// passing its own gauge. Deriving the OCI here rather than in the SBI server is
/// the whole point of decision 2 in #273: the number is the NF's, not the
/// transport's.
///
/// Also updated on the ticks where the NRF PATCH is skipped (no NRF URI, or the
/// NES pause), because peers still need the truth even when the NRF cannot be
/// told it.
pub fn spawn_heartbeat_worker_with_load<F>(nf_instance_id: String, interval_secs: u64, load_fn: F)
where
    F: Fn() -> u8 + Send + 'static,
{
    // #235: remember the ID so the shutdown path can deregister without being
    // handed it again. Done here rather than at each NF's registration site
    // because every registering NF reaches this function.
    set_registered_nf_instance_id(nf_instance_id.clone());

    // #273: scope the OCI this NF emits to its own NF Instance ID. §6.4.3.4.1
    // makes a scope mandatory and Table 6.4.3.4.5.2-1 lists `NF-Instance` as the
    // "all services of this NF instance" scope, which is what a load-derived
    // metric actually describes — it is computed from whole-NF capacity, not per
    // service. Done here because this is where the registered ID is known.
    crate::overload::self_overload_reporter().set_scope("NF-Instance", nf_instance_id.clone());

    tokio::spawn(async move {
        log::info!(
            "Heartbeat worker started for NF instance {nf_instance_id} (interval={interval_secs}s)"
        );

        let interval = tokio::time::Duration::from_secs(interval_secs);
        let mut ticker = tokio::time::interval(interval);
        // #434: a daemon that never recorded its profile cannot re-register. Say
        // so once, rather than on every 404 tick.
        let mut warned_no_profile = false;
        // First tick fires immediately — we want to send the first heartbeat
        // right away to refresh NRF state before the suspension timer
        // (typically 10s) elapses. Subsequent ticks fire every interval.

        loop {
            ticker.tick().await;

            // #273: read the gauge ONCE per tick and publish it to this NF's own
            // overload reporter before any of the early `continue`s below. A peer
            // dialling this NF needs the truth about its load even on a tick that
            // cannot reach the NRF — an NF that is overloaded AND cut off from the
            // NRF is exactly when abatement matters most.
            let load = load_fn();
            publish_overload_from_load(&nf_instance_id, load);

            // Issue #22 NES: while paused (deregistered sleep) skip the
            // tick entirely — a deleted NF profile must not be PATCHed.
            if heartbeat_paused() {
                log::debug!("Heartbeat paused for {nf_instance_id}, skipping tick");
                continue;
            }

            let ctx = crate::context::global_context();
            let nrf_uri = ctx.get_nrf_uri().await;

            let nrf_uri = match nrf_uri {
                Some(u) => u,
                None => {
                    log::debug!("Heartbeat: no NRF URI configured, skipping");
                    continue;
                }
            };

            let (nrf_host, nrf_port) = match parse_nrf_host_port(&nrf_uri) {
                Some(hp) => hp,
                None => {
                    log::warn!("Heartbeat: could not parse NRF URI '{nrf_uri}'");
                    continue;
                }
            };

            let client = SbiClient::with_host_port(&nrf_host, nrf_port);
            let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
            let body = build_load_patch(load);

            // TS 29.510 §5.2.2.3 mandates application/json-patch+json for
            // NFUpdate; set it explicitly (nrfd also shape-detects the array).
            let request = match SbiRequest::patch(&path).with_json_body(&body) {
                Ok(req) => req.with_header("Content-Type", "application/json-patch+json"),
                Err(e) => {
                    log::warn!("Heartbeat: failed to serialize body for {nf_instance_id}: {e}");
                    continue;
                }
            };

            match client.send_request(request).await {
                Ok(resp) if resp.status == 200 || resp.status == 204 => {
                    nextgcore_metrics::nf::nrf_heartbeat(
                        nextgcore_metrics::nf::HeartbeatOutcome::Ok,
                    );
                    log::debug!(
                        "Heartbeat OK for {} (status={}, load={})",
                        nf_instance_id,
                        resp.status,
                        load
                    );
                }
                // #434: the NRF no longer holds this profile. Re-register it, or
                // this NF stays Ready and undiscoverable until restarted.
                Ok(resp) if resp.status == 404 => {
                    // Re-checked AFTER the response: an NES deregistration can
                    // pause the worker while this PATCH is in flight, and its 404
                    // is then the deregistration working, not a lost profile.
                    if heartbeat_paused() {
                        continue;
                    }
                    nextgcore_metrics::nf::nrf_heartbeat(
                        nextgcore_metrics::nf::HeartbeatOutcome::NotFound,
                    );
                    if registered_profile().is_none() {
                        if !warned_no_profile {
                            log::warn!(
                                "Heartbeat got 404 for {nf_instance_id}: the NRF no longer \
                                 holds this NF, and no registered profile was recorded, so it \
                                 cannot re-register and will stay undiscoverable"
                            );
                            warned_no_profile = true;
                        }
                        continue;
                    }
                    match reregister_self(&nf_instance_id).await {
                        Ok(status) => log::info!(
                            "Heartbeat got 404 for {nf_instance_id}: the NRF had lost this NF; \
                             re-registered (status={status})"
                        ),
                        Err(e) => log::warn!(
                            "Heartbeat got 404 for {nf_instance_id}; re-registration failed, \
                             retrying next tick: {e}"
                        ),
                    }
                }
                // Any other status (a 5xx is an NRF fault, not a lost
                // registration) keeps the pre-#434 behaviour.
                Ok(resp) => {
                    nextgcore_metrics::nf::nrf_heartbeat(
                        nextgcore_metrics::nf::HeartbeatOutcome::Rejected,
                    );
                    log::warn!(
                        "Heartbeat got unexpected status {} for {}",
                        resp.status,
                        nf_instance_id
                    );
                }
                Err(e) => {
                    nextgcore_metrics::nf::nrf_heartbeat(
                        nextgcore_metrics::nf::HeartbeatOutcome::TransportError,
                    );
                    log::warn!("Heartbeat failed for {nf_instance_id}: {e}");
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #235: the registered-NF-instance-ID plumbing that lets `deregister_self`
    /// DELETE the right profile without being handed the ID at 17 shutdown sites.
    ///
    /// One test, not several, and it restores the static — same reason the NES
    /// test below gives: the slot is process-global, so mutation and restoration
    /// belong together. Deliberately does NOT call `deregister_self()`: that
    /// pauses the heartbeat, which is another process-global the NES test
    /// asserts on. The end-to-end path is covered in `nrfd`, whose binary
    /// touches neither global.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // see SELF_REPORTER_TEST_LOCK's rationale
    async fn test_registered_nf_instance_id_plumbing() {
        // #273: `spawn_heartbeat_worker_with_load` now also writes the OCI scope
        // on the process-global reporter, so this test contends with
        // `an_nf_above_its_load_threshold_reports_overload_to_a_default_consumer`
        // over that global even though it asserts nothing about it. Takes the same
        // lock — declared beside the global in `overload.rs`, never a second one.
        let _guard = crate::overload::lock_self_reporter();

        // Nothing has registered in this test binary.
        clear_registered_nf_instance_id();
        assert_eq!(registered_nf_instance_id(), None);

        set_registered_nf_instance_id("5e9b1c0a-2222-4f6a-8888-0123456789ab");
        assert_eq!(
            registered_nf_instance_id().as_deref(),
            Some("5e9b1c0a-2222-4f6a-8888-0123456789ab")
        );

        // A re-registration (the NES resume path re-registers under a new ID)
        // must replace, not accumulate — deregistering the previous ID would
        // delete a profile that is no longer this process's.
        set_registered_nf_instance_id("5e9b1c0a-3333-4f6a-8888-0123456789ab");
        assert_eq!(
            registered_nf_instance_id().as_deref(),
            Some("5e9b1c0a-3333-4f6a-8888-0123456789ab")
        );

        // Spawning the heartbeat worker is what records the ID in production —
        // no NF calls the setter itself. Asserted here because otherwise the
        // recording is the untested half and every other test seeds the slot by
        // hand, which would pass with the recording deleted. No NRF URI is
        // configured, so the worker's first tick logs "no NRF URI" and skips;
        // the task dies with this test's runtime.
        clear_registered_nf_instance_id();
        spawn_heartbeat_worker_with_load(
            "5e9b1c0a-5555-4f6a-8888-0123456789ab".to_string(),
            3600,
            || 0,
        );
        assert_eq!(
            registered_nf_instance_id().as_deref(),
            Some("5e9b1c0a-5555-4f6a-8888-0123456789ab"),
            "spawning the heartbeat worker must record the ID the shutdown path deregisters"
        );

        clear_registered_nf_instance_id();
        assert_eq!(registered_nf_instance_id(), None);
    }

    /// #273 decision 2, end to end and on a LIVE path: an NF whose load gauge
    /// crosses the threshold stamps `3gpp-Sbi-Oci` on its own responses, and a
    /// DEFAULT consumer of this tree abates against it.
    ///
    /// This is the test that makes the producer half *driven* rather than
    /// reachable-but-undriven. It asserts the whole chain in the order production
    /// runs it:
    ///
    /// 1. `spawn_heartbeat_worker_with_load` — the real production entry point,
    ///    called at 17 sites — records the scope from the NF instance ID and
    ///    starts ticking.
    /// 2. The worker's **own tick** polls the gauge closure and publishes it. This
    ///    test never calls `publish_overload_from_load` itself: doing so would
    ///    leave the tick's call to it unpinned, which is precisely the
    ///    reachable-but-undriven defect being closed. The gauge below returns a
    ///    value this test controls, so a tick that stopped publishing shows up as
    ///    the OCI never appearing.
    /// 3. An `SbiServer` configured with `with_self_overload_reporting()` — the
    ///    one line each daemon adds, and which `amfd` and `smfd` now carry — picks
    ///    the metric up and stamps it on a response.
    /// 4. A DEFAULT `SbiClient` sheds its next request to that server.
    ///
    /// Step 4 is what the whole issue is about: the shedding consumer here is
    /// configured with nothing at all.
    ///
    /// Takes `lock_self_reporter()` and restores the reporter, because
    /// `self_overload_reporter()` is process-global and a leftover non-zero metric
    /// would make every other server test in this binary emit an OCI.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // see SELF_REPORTER_TEST_LOCK's rationale
    async fn an_nf_above_its_load_threshold_reports_overload_to_a_default_consumer() {
        use crate::overload::{self_overload_reporter, LOAD_OVERLOAD_THRESHOLD};
        use std::sync::atomic::{AtomicU8, Ordering as AtomicOrd};

        let _guard = crate::overload::lock_self_reporter();

        // Distinct literal instance IDs per test in this binary: the scope is
        // stored on the ONE process-global reporter, so two tests using the same
        // ID could not tell whose scope they were reading.
        let nf_instance_id = "c3f1e7d2-2730-4bcd-9a01-000000000273";

        let reporter = self_overload_reporter();
        reporter.set_operator_metric(0);
        reporter.report_load(0);

        // The NF's capacity gauge, standing in for `AmfContext::get_ue_load()`.
        // The worker polls it on every tick, so moving it is how this test
        // simulates the AMF filling up — through the production path, not past it.
        let gauge = Arc::new(AtomicU8::new(0));
        let gauge_for_worker = gauge.clone();
        // 1s interval so a change to the gauge reaches a tick promptly. No NRF URI
        // is configured, so each tick takes the "no NRF URI, skipping" branch —
        // which is exactly the branch #273 must still publish the metric on, and
        // would be the branch a real overloaded-and-isolated NF took.
        spawn_heartbeat_worker_with_load(nf_instance_id.to_string(), 1, move || {
            gauge_for_worker.load(AtomicOrd::Relaxed)
        });

        // The exact server configuration `amfd` and `smfd` now use in production:
        // one builder call, no reporter of their own.
        let (server, addr) = crate::test_support::sbi_server_on_free_port_with(
            |addr| crate::server::SbiServerConfig::new(addr).with_self_overload_reporting(),
            |_req: SbiRequest| async { crate::message::SbiResponse::with_status(204) },
        )
        .await;
        let port = addr.port();

        let probe = SbiClient::with_host_port("127.0.0.1", port);
        let healthy = probe
            .send_request(SbiRequest::get("/x"))
            .await
            .expect("response");
        assert!(
            healthy
                .http
                .get_header(crate::constants::custom_header::OCI)
                .is_none(),
            "an NF below its threshold must emit no OCI at all"
        );

        // The NF fills up. Only the gauge is touched; the worker's tick is what
        // must notice.
        gauge.store(100, AtomicOrd::Relaxed);
        // The ramp needs headroom to span, or `report_load` would divide by zero.
        const _: () = assert!(LOAD_OVERLOAD_THRESHOLD < 100);
        assert_eq!(
            crate::test_support::poll_until(
                Duration::from_secs(20),
                Duration::from_millis(25),
                || async { (reporter.reduction_metric() == 100).then_some(()) }
            )
            .await,
            Some(()),
            "the heartbeat tick must publish the gauge: load 100% asks for a 100% \
             reduction, the deterministic end of the ramp"
        );

        let loaded = probe
            .send_request(SbiRequest::get("/x"))
            .await
            .expect("response");
        let header = loaded
            .http
            .get_header(crate::constants::custom_header::OCI)
            .expect("an overloaded NF must stamp 3gpp-Sbi-Oci (TS 29.500 §6.4.3.2)")
            .clone();
        let oci = crate::overload::Oci::parse(&header).expect("parseable");
        assert_eq!(oci.reduction_metric, 100);
        assert_eq!(
            oci.extra,
            vec![("NF-Instance".to_string(), nf_instance_id.to_string())],
            "the scope must name the instance the heartbeat worker registered"
        );

        // The consumer half, with a fresh DEFAULT client: the recorded OCI is
        // conformant, so the next request is shed rather than sent. `probe` is
        // reused for nothing here because it already recorded an OCI above and a
        // fresh client proves the reaction needs no priming.
        let consumer = SbiClient::with_host_port("127.0.0.1", port);
        assert_eq!(
            consumer
                .send_request(SbiRequest::get("/x"))
                .await
                .expect("the first request is always sent")
                .status,
            204
        );
        let err = consumer
            .send_request(SbiRequest::get("/x"))
            .await
            .expect_err("a default consumer must abate against a real NF's OCI");
        assert!(
            matches!(err, crate::error::SbiError::OverloadShed(_)),
            "expected a local shed, got {err:?}"
        );

        // Recovery through the same path: drop the gauge and the tick withdraws the
        // OCI (§6.4.3.4.3 — the metric falling to 0 signals the overload ceased).
        // Asserted as a transition, and it also restores the process-global so
        // other tests in this binary do not inherit a loaded reporter. The worker
        // outlives this test's runtime, so the gauge is left at 0 too.
        gauge.store(0, AtomicOrd::Relaxed);
        assert_eq!(
            crate::test_support::poll_until(
                Duration::from_secs(20),
                Duration::from_millis(25),
                || async { (reporter.reduction_metric() == 0).then_some(()) }
            )
            .await,
            Some(()),
            "a recovered NF must stop asking for reduction"
        );
        server.stop().await.expect("stop");
    }

    /// Issue #22 NES: the default heartbeat body is byte-identical to the
    /// historical hardcoded-REGISTERED patch, the status builder emits the
    /// requested status, and the self-status/pause plumbing round-trips.
    /// One test (not several): the statics are process-global, so mutation
    /// and restoration happen under a single test to avoid races.
    #[test]
    fn test_nes_status_patch_plumbing() {
        // Defaults: Registered, unpaused, historical JSON shape (load
        // saturated at 100).
        assert_eq!(self_nf_status(), crate::context::NfStatus::Registered);
        assert!(!heartbeat_paused());
        assert_eq!(
            build_load_patch(150),
            serde_json::json!([
                {"op": "replace", "path": "/nfStatus", "value": "REGISTERED"},
                {"op": "add",     "path": "/load",     "value": 100}
            ])
        );

        // Explicit status builder.
        let suspended = build_status_patch(7, crate::context::NfStatus::Suspended);
        assert_eq!(suspended[0]["value"], "SUSPENDED");
        assert_eq!(suspended[1]["value"], 7);
        assert_eq!(
            nf_status_wire(crate::context::NfStatus::Undiscoverable),
            "UNDISCOVERABLE"
        );

        // NES plumbing round-trip; restore defaults for other tests.
        set_self_nf_status(crate::context::NfStatus::Suspended);
        assert_eq!(build_load_patch(1)[0]["value"], "SUSPENDED");
        set_heartbeat_paused(true);
        assert!(heartbeat_paused());
        set_self_nf_status(crate::context::NfStatus::Registered);
        set_heartbeat_paused(false);
        assert_eq!(build_load_patch(0)[0]["value"], "REGISTERED");
    }

    /// #434: every daemon that spawns the heartbeat worker also records the
    /// profile it registered, or a 404 heartbeat cannot re-register it.
    ///
    /// A source guard because the failure is otherwise silent: an unwired daemon
    /// compiles, passes its tests, and only shows its gap after an NRF restart in a
    /// deployment, logging one warning. Scans `bins/` like
    /// `each_daemon_registers_with_the_nrf_exactly_once` in `security.rs`, and
    /// walks subdirectories, since a daemon may register from a nested module.
    #[test]
    fn every_heartbeating_daemon_records_its_registered_profile() {
        fn rust_sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                let p = entry.path();
                if p.is_dir() {
                    rust_sources(&p, out);
                } else if p.extension().is_some_and(|e| e == "rs") {
                    out.push(p);
                }
            }
        }
        // A code line, not a comment mentioning the name.
        fn calls(text: &str, needle: &str) -> bool {
            text.lines()
                .any(|l| l.contains(needle) && !l.trim_start().starts_with("//"))
        }

        let bins = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crate is at <root>/libs/nextgcore-sbi")
            .join("bins");
        assert!(bins.is_dir(), "expected {} to exist", bins.display());

        let mut heartbeating = Vec::new();
        let mut unwired = Vec::new();
        for entry in std::fs::read_dir(&bins).expect("read bins/").flatten() {
            let crate_dir = entry.path();
            let name = crate_dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let mut files = Vec::new();
            rust_sources(&crate_dir.join("src"), &mut files);
            let text: String = files
                .iter()
                .map(|f| std::fs::read_to_string(f).unwrap_or_default())
                .collect::<Vec<_>>()
                .join("\n");
            if calls(&text, "spawn_heartbeat_worker") {
                heartbeating.push(name.clone());
                if !calls(&text, "set_registered_profile(") {
                    unwired.push(name);
                }
            }
        }
        heartbeating.sort();
        unwired.sort();

        // Positive premise: the scan really found the daemons. A path change that
        // made it find nothing would otherwise pass vacuously.
        assert!(
            heartbeating.len() >= 17,
            "expected the 17 heartbeating daemons, found {}: {heartbeating:?}",
            heartbeating.len()
        );
        assert!(
            unwired.is_empty(),
            "these daemons spawn the heartbeat worker but never call \
             set_registered_profile, so a 404 heartbeat cannot re-register them (#434): \
             {unwired:?}"
        );
    }

    #[test]
    fn test_heartbeat_record_creation() {
        let record = HeartbeatRecord::new("nf-001".to_string(), "nf.example.com".to_string(), 10);

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

        manager.add_nf("nf-001".to_string(), "nf.example.com".to_string(), Some(10));

        let status = manager.get_status("nf-001");
        assert_eq!(status, Some(HeartbeatStatus::Healthy));

        manager.remove_nf("nf-001");
        let status = manager.get_status("nf-001");
        assert_eq!(status, None);
    }

    #[test]
    fn test_heartbeat_suspend_resume() {
        let manager = HeartbeatManager::default();

        manager.add_nf("nf-001".to_string(), "nf.example.com".to_string(), None);

        manager.suspend("nf-001");
        assert_eq!(
            manager.get_status("nf-001"),
            Some(HeartbeatStatus::Suspended)
        );

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

    #[test]
    fn test_build_load_patch_shape() {
        use serde_json::json;
        // Review fix (issue #22): use the explicit-status builder so this
        // test cannot observe another test's mutation of the process-global
        // SELF_NF_STATUS (test_nes_status_patch_plumbing is the sole mutator).
        let patch = build_status_patch(42, crate::context::NfStatus::Registered);
        let items = patch.as_array().expect("json-patch array");
        assert_eq!(items.len(), 2, "nfStatus + load");

        // nfStatus refresh via replace (target always present).
        assert_eq!(items[0]["op"], "replace");
        assert_eq!(items[0]["path"], "/nfStatus");
        assert_eq!(items[0]["value"], "REGISTERED");

        // /load via add so it is created-or-replaced.
        assert_eq!(items[1]["op"], "add");
        assert_eq!(items[1]["path"], "/load");
        assert_eq!(items[1]["value"], json!(42));
    }

    #[test]
    fn test_build_load_patch_saturates_at_100() {
        use serde_json::json;
        // u8 max is 255; anything over 100 saturates to 100 (NFProfile.load 0..=100).
        let patch = build_status_patch(200, crate::context::NfStatus::Registered);
        assert_eq!(patch.as_array().unwrap()[1]["value"], json!(100));

        let patch = build_status_patch(0, crate::context::NfStatus::Registered);
        assert_eq!(patch.as_array().unwrap()[1]["value"], json!(0));
    }

    // ─── #1482: initial NFRegister retry ────────────────────────────────────

    use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};

    /// The default backoff with no jitter, so paused-time tests see exact waits.
    fn no_jitter() -> RegisterRetryPolicy {
        RegisterRetryPolicy {
            jitter_percent: 0,
            ..RegisterRetryPolicy::default()
        }
    }

    #[test]
    fn jitter_stays_within_its_percent() {
        let p = RegisterRetryPolicy::default();
        for _ in 0..1000 {
            let d = p.jittered(Duration::from_secs(10));
            assert!(
                d >= Duration::from_secs(8) && d <= Duration::from_secs(12),
                "{d:?}"
            );
        }
        assert_eq!(
            no_jitter().jittered(Duration::from_secs(10)),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn a_3xx_or_4xx_is_a_rejection_but_load_and_transport_are_not() {
        assert!(is_rejection("NRF registration returned status 400"));
        assert!(is_rejection(
            "NRF registration returned status 307: Some(..)"
        ));
        assert!(is_rejection("NRF returned status 403"));
        assert!(!is_rejection("NRF registration returned status 503"));
        assert!(!is_rejection("NRF registration returned status 429"));
        assert!(!is_rejection("NRF registration returned status 408"));
        assert!(!is_rejection("NRF registration failed: connection refused"));
    }

    /// #1574 review m4: the NRF rejecting the profile (a 400) is retried only at
    /// the 30 s cap, not on the 1, 2, 4 s ramp: the same PUT will not fix it.
    ///
    /// REVERT-VERIFIED: with the rejection branch removed (the normal ramp), 6
    /// attempts are made in the 61 s, not 3.
    #[tokio::test(start_paused = true)]
    #[allow(clippy::await_holding_lock)] // the registration-state test lock; one runtime thread
    async fn a_rejected_registration_is_retried_only_at_the_cap() {
        let _g = lock_registration_state_for_test();
        clear_registration_abandoned();
        let attempts = Arc::new(AtomicU32::new(0));
        let a = attempts.clone();
        let out = register_or_retry(
            "TEST",
            no_jitter(),
            move || {
                a.fetch_add(1, AtomicOrdering::SeqCst);
                std::future::ready(Err("NRF registration returned status 400".to_string()))
            },
            |_| {},
        )
        .await;
        assert_eq!(out, Registration::Retrying);
        tokio::time::sleep(Duration::from_secs(61)).await;
        assert_eq!(
            attempts.load(AtomicOrdering::SeqCst),
            3,
            "attempts at 0, 30 and 60 s"
        );
        // Stop the task before the lock is released.
        retry_state().abandoned = true;
        tokio::time::sleep(Duration::from_secs(31)).await;
        clear_registration_abandoned();
    }

    /// #1574 review m2: an attempt that finds the NRF URI gone (`Ok(None)`)
    /// stops the retry, without running `on_registered`.
    ///
    /// REVERT-VERIFIED: with `Ok(None)` treated like an error (retry), attempts
    /// keep climbing past 2.
    #[tokio::test(start_paused = true)]
    #[allow(clippy::await_holding_lock)] // the registration-state test lock; one runtime thread
    async fn a_retry_that_finds_no_nrf_configured_stops() {
        let _g = lock_registration_state_for_test();
        clear_registration_abandoned();
        let attempts = Arc::new(AtomicU32::new(0));
        let a = attempts.clone();
        let ran = Arc::new(Mutex::new(false));
        let r = ran.clone();
        let out = register_or_retry(
            "TEST",
            no_jitter(),
            move || {
                let n = a.fetch_add(1, AtomicOrdering::SeqCst) + 1;
                std::future::ready(if n == 1 {
                    Err("NRF unreachable".to_string())
                } else {
                    Ok(None)
                })
            },
            move |_| *r.lock().unwrap() = true,
        )
        .await;
        assert_eq!(out, Registration::Retrying);
        tokio::time::sleep(Duration::from_secs(300)).await;
        assert_eq!(attempts.load(AtomicOrdering::SeqCst), 2);
        assert!(!*ran.lock().unwrap());
    }

    /// A `register` closure that fails `failures` times, then returns `Ok(Some(id))`.
    /// Counts its calls in `attempts`.
    fn failing_then_ok(
        failures: u32,
        id: &'static str,
        attempts: Arc<AtomicU32>,
    ) -> impl FnMut() -> std::future::Ready<Result<Option<String>, String>> + Send + 'static {
        move || {
            let n = attempts.fetch_add(1, AtomicOrdering::SeqCst) + 1;
            std::future::ready(if n <= failures {
                Err(format!("NRF unreachable (attempt {n})"))
            } else {
                Ok(Some(id.to_string()))
            })
        }
    }

    #[test]
    fn register_retry_backoff_doubles_from_initial_and_caps_at_max() {
        let p = RegisterRetryPolicy::default();
        let secs: Vec<u64> = (1..=8).map(|n| p.delay_after(n).as_secs()).collect();
        assert_eq!(secs, vec![1, 2, 4, 8, 16, 30, 30, 30]);
        // No overflow however long the outage lasts.
        assert_eq!(p.delay_after(u32::MAX), Duration::from_secs(30));
        assert_eq!(p.delay_after(0), Duration::from_secs(1));
    }

    /// The happy path keeps today's ordering: one attempt, awaited, and the
    /// daemon's follow-up (the heartbeat) has run by the time this returns.
    #[tokio::test(start_paused = true)]
    async fn a_first_registration_that_succeeds_runs_on_registered_before_returning() {
        let attempts = Arc::new(AtomicU32::new(0));
        let ran = Arc::new(Mutex::new(None::<String>));
        let r = ran.clone();
        let out = register_or_retry(
            "TEST",
            no_jitter(),
            failing_then_ok(0, "id-1482-ok", attempts.clone()),
            move |id| *r.lock().unwrap() = Some(id),
        )
        .await;
        assert_eq!(out, Registration::Registered("id-1482-ok".into()));
        assert_eq!(ran.lock().unwrap().as_deref(), Some("id-1482-ok"));
        assert_eq!(attempts.load(AtomicOrdering::SeqCst), 1);
    }

    /// No NRF configured: nothing is retried and nothing follows.
    #[tokio::test(start_paused = true)]
    async fn no_nrf_configured_is_not_retried() {
        let attempts = Arc::new(AtomicU32::new(0));
        let a = attempts.clone();
        let ran = Arc::new(Mutex::new(false));
        let r = ran.clone();
        let out = register_or_retry(
            "TEST",
            no_jitter(),
            move || {
                a.fetch_add(1, AtomicOrdering::SeqCst);
                std::future::ready(Ok(None))
            },
            move |_| *r.lock().unwrap() = true,
        )
        .await;
        assert_eq!(out, Registration::NotConfigured);
        tokio::time::sleep(Duration::from_secs(120)).await;
        assert_eq!(attempts.load(AtomicOrdering::SeqCst), 1);
        assert!(!*ran.lock().unwrap());
    }

    /// The #1482 defect: a failed first NFRegister was never retried. Now the
    /// attempts continue at 1 s, 2 s, 4 s, and `on_registered` runs once, after
    /// the attempt that succeeded and not before.
    ///
    /// REVERT-VERIFIED: with `register_or_retry` returning after the failed
    /// first attempt (no spawned retry), this fails at "registered after the
    /// fourth attempt" with 1 attempt and nothing run.
    #[tokio::test(start_paused = true)]
    #[allow(clippy::await_holding_lock)] // the registration-state test lock; one runtime thread
    async fn a_failed_first_registration_is_retried_with_backoff_until_it_succeeds() {
        let _g = lock_registration_state_for_test();
        clear_registration_abandoned();
        let attempts = Arc::new(AtomicU32::new(0));
        let (tx, rx) = tokio::sync::oneshot::channel::<(String, u32)>();
        let a = attempts.clone();
        let start = tokio::time::Instant::now();
        let out = register_or_retry(
            "TEST",
            no_jitter(),
            failing_then_ok(3, "id-1482-retry", attempts.clone()),
            move |id| {
                let _ = tx.send((id, a.load(AtomicOrdering::SeqCst)));
            },
        )
        .await;
        assert_eq!(out, Registration::Retrying);
        assert_eq!(attempts.load(AtomicOrdering::SeqCst), 1);

        let (id, attempts_when_run) = tokio::time::timeout(Duration::from_secs(60), rx)
            .await
            .expect("registered after the fourth attempt")
            .expect("on_registered ran");
        assert_eq!(id, "id-1482-retry");
        assert_eq!(attempts_when_run, 4, "on_registered follows the success");
        // 1 s + 2 s + 4 s of backoff before attempts 2, 3 and 4.
        assert_eq!(start.elapsed(), Duration::from_secs(7));
        // And nothing more after the success.
        tokio::time::sleep(Duration::from_secs(120)).await;
        assert_eq!(attempts.load(AtomicOrdering::SeqCst), 4);
    }

    /// Shutdown (`deregister_self`) stops a retry that has not registered yet:
    /// a profile registered after the NF deregistered would stay at the NRF
    /// until its heartbeat expired.
    ///
    /// REVERT-VERIFIED: without the `registration_abandoned()` check before
    /// each attempt, this fails with attempts still climbing after shutdown.
    #[tokio::test(start_paused = true)]
    #[allow(clippy::await_holding_lock)] // see SELF_REPORTER_TEST_LOCK's rationale
    async fn deregister_self_stops_a_pending_registration_retry() {
        let _g = lock_registration_state_for_test();
        // The recorded instance ID is also written by the tests that spawn a
        // heartbeat worker, under this lock. Held so `deregister_self` below
        // finds no ID and neither pauses the heartbeat nor sends a DELETE.
        let _r = crate::overload::lock_self_reporter();
        clear_registration_abandoned();
        clear_registered_nf_instance_id();
        let attempts = Arc::new(AtomicU32::new(0));
        let ran = Arc::new(Mutex::new(false));
        let r = ran.clone();
        let out = register_or_retry(
            "TEST",
            no_jitter(),
            failing_then_ok(u32::MAX, "never", attempts.clone()),
            move |_| *r.lock().unwrap() = true,
        )
        .await;
        assert_eq!(out, Registration::Retrying);
        tokio::time::sleep(Duration::from_millis(3500)).await;
        let before = attempts.load(AtomicOrdering::SeqCst);
        assert_eq!(before, 3, "premise: attempts at 0, 1 s and 3 s");

        // Nothing recorded, so no DELETE is sent; the retry still stops.
        assert!(!deregister_self().await);
        tokio::time::sleep(Duration::from_secs(300)).await;
        assert_eq!(attempts.load(AtomicOrdering::SeqCst), before);
        assert!(!*ran.lock().unwrap());
        clear_registration_abandoned();
    }

    /// An attempt in flight when shutdown begins, that then succeeds, must not
    /// start the heartbeat (`deregister_self` has already looked for an ID).
    ///
    /// REVERT-VERIFIED: running `on_registered` without the abandoned check
    /// fails at "on_registered did not run".
    #[tokio::test(start_paused = true)]
    #[allow(clippy::await_holding_lock)] // the registration-state test lock; one runtime thread
    async fn a_registration_that_lands_during_shutdown_does_not_start_the_heartbeat() {
        let _g = lock_registration_state_for_test();
        clear_registration_abandoned();
        let attempts = Arc::new(AtomicU32::new(0));
        let a = attempts.clone();
        let ran = Arc::new(Mutex::new(false));
        let r = ran.clone();
        let out = register_or_retry(
            "TEST",
            no_jitter(),
            move || {
                let n = a.fetch_add(1, AtomicOrdering::SeqCst) + 1;
                async move {
                    if n == 1 {
                        return Err("NRF unreachable".to_string());
                    }
                    // Shutdown begins while this attempt is at the NRF.
                    retry_state().abandoned = true;
                    Ok(Some("id-1482-late".to_string()))
                }
            },
            move |_| *r.lock().unwrap() = true,
        )
        .await;
        assert_eq!(out, Registration::Retrying);
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(
            attempts.load(AtomicOrdering::SeqCst),
            2,
            "premise: it was retried"
        );
        assert!(!*ran.lock().unwrap(), "on_registered did not run");
        clear_registration_abandoned();
    }

    /// #1482 source guard: every daemon that starts the heartbeat worker
    /// registers through [`register_or_retry`], so none of them is back to one
    /// attempt and "will operate without NRF". nrfd is excluded: it IS the NRF,
    /// and its only heartbeat call is in a test.
    #[test]
    fn every_heartbeating_daemon_registers_through_register_or_retry() {
        fn rust_sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                let p = entry.path();
                if p.is_dir() {
                    rust_sources(&p, out);
                } else if p.extension().is_some_and(|e| e == "rs") {
                    out.push(p);
                }
            }
        }
        fn calls(text: &str, needle: &str) -> bool {
            text.lines()
                .any(|l| l.contains(needle) && !l.trim_start().starts_with("//"))
        }
        let bins = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crate is at <root>/libs/nextgcore-sbi")
            .join("bins");
        let mut heartbeating = Vec::new();
        let mut one_shot = Vec::new();
        for entry in std::fs::read_dir(&bins).expect("read bins/").flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "nextgcore-nrfd" {
                continue;
            }
            let mut files = Vec::new();
            rust_sources(&entry.path().join("src"), &mut files);
            let text: String = files
                .iter()
                .map(|f| std::fs::read_to_string(f).unwrap_or_default())
                .collect::<Vec<_>>()
                .join("\n");
            if calls(&text, "spawn_heartbeat_worker") {
                heartbeating.push(name.clone());
                if !calls(&text, "register_or_retry(") {
                    one_shot.push(name);
                }
            }
        }
        one_shot.sort();
        assert!(
            heartbeating.len() >= 18,
            "expected the 18 registering daemons, found {}: {heartbeating:?}",
            heartbeating.len()
        );
        assert!(
            one_shot.is_empty(),
            "these daemons start the heartbeat but do not register through \
             register_or_retry, so a failed first NFRegister is never retried (#1482): \
             {one_shot:?}"
        );
    }
}
