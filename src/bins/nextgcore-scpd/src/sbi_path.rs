//! SCP SBI Path Functions
//!
//! Port of src/scp/sbi-path.c - SBI server/client path functions
//!
//! The SCP acts as a proxy that:
//! - Receives requests from NF consumers
//! - Performs NF discovery delegation when needed
//! - Forwards requests to target NFs
//! - Routes responses back to original requesters
//!
//! The actual HTTP/2 forwarding data path (Model C / Model D per TS 29.500
//! §6.10, binding stickiness per §6.12, ProblemDetails error semantics) lives
//! in [`crate::proxy::ScpProxy`]; this module keeps the parsing and
//! producer-selection helpers it builds on.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

use nextgcore_sbi::types::UriScheme;

use crate::context::NfType;

/// SBI server configuration
#[derive(Debug, Clone)]
pub struct SbiServerConfig {
    pub addr: String,
    pub port: u16,
    pub tls_enabled: bool,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
}

impl Default for SbiServerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1".to_string(),
            port: 7777, // Default SCP port
            tls_enabled: false,
            tls_cert: None,
            tls_key: None,
        }
    }
}

/// SBI server state
static SBI_SERVER_RUNNING: AtomicBool = AtomicBool::new(false);

/// Custom HTTP headers used by SCP
pub mod headers {
    pub const TARGET_APIROOT: &str = "3gpp-sbi-target-apiroot";
    pub const CALLBACK: &str = "3gpp-sbi-callback";
    pub const NRF_URI: &str = "3gpp-sbi-nrf-uri";
    pub const DISCOVERY_TARGET_NF_TYPE: &str = "3gpp-sbi-discovery-target-nf-type";
    pub const DISCOVERY_REQUESTER_NF_TYPE: &str = "3gpp-sbi-discovery-requester-nf-type";
    pub const DISCOVERY_TARGET_NF_INSTANCE_ID: &str = "3gpp-sbi-discovery-target-nf-instance-id";
    pub const DISCOVERY_REQUESTER_NF_INSTANCE_ID: &str =
        "3gpp-sbi-discovery-requester-nf-instance-id";
    pub const DISCOVERY_SERVICE_NAMES: &str = "3gpp-sbi-discovery-service-names";
    pub const DISCOVERY_SNSSAIS: &str = "3gpp-sbi-discovery-snssais";
    pub const DISCOVERY_GUAMI: &str = "3gpp-sbi-discovery-guami";
    pub const DISCOVERY_DNN: &str = "3gpp-sbi-discovery-dnn";
    pub const DISCOVERY_TAI: &str = "3gpp-sbi-discovery-tai";
    pub const DISCOVERY_TARGET_PLMN_LIST: &str = "3gpp-sbi-discovery-target-plmn-list";
    pub const DISCOVERY_HNRF_URI: &str = "3gpp-sbi-discovery-hnrf-uri";
    pub const DISCOVERY_REQUESTER_PLMN_LIST: &str = "3gpp-sbi-discovery-requester-plmn-list";
    pub const DISCOVERY_REQUESTER_FEATURES: &str = "3gpp-sbi-discovery-requester-features";
    pub const PRODUCER_ID: &str = "3gpp-sbi-producer-id";
    pub const USER_AGENT: &str = "user-agent";
}

/// Open SBI server
/// Port of scp_sbi_open
pub fn scp_sbi_open(config: Option<SbiServerConfig>) -> Result<(), String> {
    if SBI_SERVER_RUNNING.load(Ordering::SeqCst) {
        return Err("SBI server already running".to_string());
    }

    let config = config.unwrap_or_default();

    log::info!("Opening SCP SBI server on {}:{}", config.addr, config.port);

    // The HTTP/2 listener itself is started in main.rs
    // (nextgcore_sbi::server::SbiServer fronting crate::proxy::ScpProxy); this
    // function tracks the lifecycle state used by the state machine.
    SBI_SERVER_RUNNING.store(true, Ordering::SeqCst);

    log::info!("SCP SBI server opened successfully");
    Ok(())
}

/// Close SBI server
/// Port of scp_sbi_close
pub fn scp_sbi_close() {
    if !SBI_SERVER_RUNNING.load(Ordering::SeqCst) {
        return;
    }

    log::info!("Closing SCP SBI server");

    // The HTTP/2 listener is stopped in main.rs (SbiServer::stop); this
    // function tracks the lifecycle state used by the state machine.
    SBI_SERVER_RUNNING.store(false, Ordering::SeqCst);

    log::info!("SCP SBI server closed");
}

/// Check if SBI server is running
pub fn scp_sbi_is_running() -> bool {
    SBI_SERVER_RUNNING.load(Ordering::SeqCst)
}

// ============================================================================
// NF Instance Selection & Request Routing
// ============================================================================

/// NF instance candidate for load-balanced routing
#[derive(Debug, Clone)]
pub struct NfInstanceCandidate {
    pub nf_instance_id: String,
    pub nf_type: NfType,
    pub host: String,
    pub port: u16,
    pub priority: u16,
    pub capacity: u16,
    pub load: u16,
    /// Whether the instance is considered healthy
    pub healthy: bool,
    /// URI scheme derived from `nfServices[].scheme` (TS 29.510 §6.1.6.2.x).
    /// Defaults to `Http` when no TLS indicator is present in the NF profile.
    pub scheme: UriScheme,
    /// Optional deployment-specific API prefix from `nfServices[].apiPrefix`
    /// (TS 29.501 §4.4.1 / TS 29.500 §6.10.2.5).
    pub prefix: String,
}

/// Select the best NF instance from a list of candidates using weighted round-robin.
///
/// Supports health-check awareness (skips unhealthy instances) and
/// weighted distribution based on NF load/priority.
///
/// Selection algorithm:
/// 1. Filter to healthy instances only
/// 2. Group by priority (lower = better)
/// 3. Among same-priority, pick by available capacity (capacity - load)
pub fn select_nf_instance(candidates: &[NfInstanceCandidate]) -> Option<&NfInstanceCandidate> {
    if candidates.is_empty() {
        return None;
    }

    // Filter to healthy instances only
    let healthy: Vec<&NfInstanceCandidate> = candidates.iter().filter(|c| c.healthy).collect();

    // Fall back to all candidates if none are marked healthy
    let pool = if healthy.is_empty() {
        candidates.iter().collect()
    } else {
        healthy
    };

    // Group by priority (lower is better)
    let min_priority = pool.iter().map(|c| c.priority).min().unwrap_or(0);
    let top_priority: Vec<&&NfInstanceCandidate> =
        pool.iter().filter(|c| c.priority == min_priority).collect();

    if top_priority.len() == 1 {
        return Some(top_priority[0]);
    }

    // Among same-priority candidates, pick by available capacity (capacity - load)
    top_priority
        .iter()
        .max_by_key(|c| c.capacity.saturating_sub(c.load) as u32)
        .map(|c| **c)
}

/// Round-robin index for distributing requests across equal-weight instances.
static ROUND_ROBIN_INDEX: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Select an NF instance using round-robin among healthy, same-priority candidates.
///
/// Implements round-robin load balancing among NF instances with
/// weighted distribution based on NF load/priority and health-check awareness.
pub fn select_nf_instance_round_robin(
    candidates: &[NfInstanceCandidate],
) -> Option<&NfInstanceCandidate> {
    if candidates.is_empty() {
        return None;
    }

    // Filter to healthy instances
    let healthy: Vec<&NfInstanceCandidate> = candidates.iter().filter(|c| c.healthy).collect();

    let pool: Vec<&NfInstanceCandidate> = if healthy.is_empty() {
        candidates.iter().collect()
    } else {
        healthy
    };

    // Group by best priority
    let min_priority = pool.iter().map(|c| c.priority).min().unwrap_or(0);
    let top_priority: Vec<&NfInstanceCandidate> = pool
        .into_iter()
        .filter(|c| c.priority == min_priority)
        .collect();

    if top_priority.is_empty() {
        return None;
    }

    // Round-robin within the top-priority group
    let idx = ROUND_ROBIN_INDEX.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let selected_idx = (idx as usize) % top_priority.len();
    Some(top_priority[selected_idx])
}

// ============================================================================
// NF Discovery Cache
// ============================================================================

/// Cached NF discovery result with TTL.
#[derive(Debug, Clone)]
pub struct DiscoveryCacheEntry {
    pub candidates: Vec<NfInstanceCandidate>,
    pub cached_at: std::time::Instant,
    pub ttl: std::time::Duration,
}

impl DiscoveryCacheEntry {
    pub fn is_expired(&self) -> bool {
        self.cached_at.elapsed() >= self.ttl
    }
}

/// NF discovery result cache.
///
/// Caches NF discovery results with TTL to avoid repeated NRF queries.
/// Cache key is (target_nf_type, service_name).
pub struct DiscoveryCache {
    entries: std::sync::RwLock<HashMap<(String, String), DiscoveryCacheEntry>>,
}

impl DiscoveryCache {
    pub fn new() -> Self {
        Self {
            entries: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Look up a cached discovery result.
    pub fn get(
        &self,
        target_nf_type: &str,
        service_name: &str,
    ) -> Option<Vec<NfInstanceCandidate>> {
        let entries = self.entries.read().ok()?;
        let key = (target_nf_type.to_string(), service_name.to_string());
        entries.get(&key).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.candidates.clone())
            }
        })
    }

    /// Store a discovery result in the cache.
    pub fn put(
        &self,
        target_nf_type: &str,
        service_name: &str,
        candidates: Vec<NfInstanceCandidate>,
        ttl: std::time::Duration,
    ) {
        if let Ok(mut entries) = self.entries.write() {
            let key = (target_nf_type.to_string(), service_name.to_string());
            entries.insert(
                key,
                DiscoveryCacheEntry {
                    candidates,
                    cached_at: std::time::Instant::now(),
                    ttl,
                },
            );
        }
    }

    /// Purge expired entries.
    pub fn purge_expired(&self) {
        if let Ok(mut entries) = self.entries.write() {
            entries.retain(|_, v| !v.is_expired());
        }
    }

    /// Clear the entire cache.
    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.write() {
            entries.clear();
        }
    }
}

impl Default for DiscoveryCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Global discovery cache
static DISCOVERY_CACHE: std::sync::OnceLock<DiscoveryCache> = std::sync::OnceLock::new();

/// Get the global discovery cache instance.
pub fn discovery_cache() -> &'static DiscoveryCache {
    DISCOVERY_CACHE.get_or_init(DiscoveryCache::new)
}

/// Parse NF discovery search result JSON into NfInstanceCandidate list.
///
/// Parses the SearchResult response from NRF discovery
/// (TS 29.510 §6.2.3.2.3.1).  For each nfInstance the following fields are
/// extracted per TS 29.510 §6.1.6.2.x and TS 29.500 §6.10.2.5:
///
/// - **scheme**: from `nfServices[0].scheme`; `https` → `UriScheme::Https`,
///   absent/other → `UriScheme::Http` (backward-compat default).
/// - **host**: `ipv4Addresses[0]` → `fqdn` → `ipv6Addresses[0]` (bracketed
///   as `[addr]` so it is valid in an authority component).
/// - **port**: from the first `ipEndPoints` entry whose `transport` is `TCP`
///   (case-insensitive), falling back to `ipEndPoints[0]` if none specifies
///   a transport.
/// - **prefix**: from `nfServices[0].apiPrefix` (empty string when absent).
pub fn parse_search_result(body: &[u8]) -> Vec<NfInstanceCandidate> {
    let value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            log::error!("Failed to parse NF discovery response: {e}");
            return Vec::new();
        }
    };

    let mut candidates = Vec::new();

    if let Some(instances) = value.get("nfInstances").and_then(|v| v.as_array()) {
        for inst in instances {
            let nf_instance_id = inst
                .get("nfInstanceId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let nf_type_str = inst
                .get("nfType")
                .and_then(|v| v.as_str())
                .unwrap_or("NULL");
            let nf_status = inst
                .get("nfStatus")
                .and_then(|v| v.as_str())
                .unwrap_or("REGISTERED");

            // Host resolution: ipv4Addresses[0] → fqdn → ipv6Addresses[0].
            // IPv6 literals are bracketed (e.g. `[2001:db8::1]`) so they are
            // valid inside an HTTP authority component (RFC 3986 §3.2.2).
            let host = inst
                .get("ipv4Addresses")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .or_else(|| {
                    inst.get("fqdn")
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                })
                .or_else(|| {
                    inst.get("ipv6Addresses")
                        .and_then(|v| v.as_array())
                        .and_then(|a| a.first())
                        .and_then(|v| v.as_str())
                        .map(|v6| format!("[{v6}]"))
                })
                .unwrap_or_else(|| "127.0.0.1".to_string());

            // Service-level fields: scheme, port, and apiPrefix come from
            // nfServices[0].  Port is taken from the first ipEndPoints entry
            // whose transport is TCP (case-insensitive); falls back to [0].
            let first_service = inst
                .get("nfServices")
                .and_then(|v| v.as_array())
                .and_then(|s| s.first());

            let scheme = first_service
                .and_then(|svc| svc.get("scheme"))
                .and_then(|v| v.as_str())
                .map(|s| {
                    if s.eq_ignore_ascii_case("https") {
                        UriScheme::Https
                    } else {
                        UriScheme::Http
                    }
                })
                .unwrap_or(UriScheme::Http);

            let prefix = first_service
                .and_then(|svc| svc.get("apiPrefix"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let port = first_service
                .and_then(|svc| svc.get("ipEndPoints"))
                .and_then(|v| v.as_array())
                .and_then(|eps| {
                    // Prefer an endpoint explicitly marked as TCP.
                    eps.iter()
                        .find(|ep| {
                            ep.get("transport")
                                .and_then(|t| t.as_str())
                                .map(|t| t.eq_ignore_ascii_case("TCP"))
                                .unwrap_or(false)
                        })
                        .or_else(|| eps.first())
                })
                .and_then(|ep| ep.get("port"))
                .and_then(|v| v.as_u64())
                .unwrap_or(7777) as u16;

            let priority = inst.get("priority").and_then(|v| v.as_u64()).unwrap_or(50) as u16;
            let capacity = inst.get("capacity").and_then(|v| v.as_u64()).unwrap_or(100) as u16;
            let load = inst.get("load").and_then(|v| v.as_u64()).unwrap_or(0) as u16;

            candidates.push(NfInstanceCandidate {
                nf_instance_id,
                nf_type: NfType::from_string(nf_type_str),
                host,
                port,
                priority,
                capacity,
                load,
                healthy: nf_status == "REGISTERED",
                scheme,
                prefix,
            });
        }
    }

    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbi_server_config_default() {
        let config = SbiServerConfig::default();
        assert_eq!(config.addr, "127.0.0.1");
        assert_eq!(config.port, 7777);
        assert!(!config.tls_enabled);
    }

    #[test]
    fn test_sbi_open_close() {
        // Reset state
        SBI_SERVER_RUNNING.store(false, Ordering::SeqCst);

        let result = scp_sbi_open(None);
        assert!(result.is_ok());
        assert!(scp_sbi_is_running());

        scp_sbi_close();
        assert!(!scp_sbi_is_running());
    }

    #[test]
    fn test_sbi_open_already_running() {
        // Reset state
        SBI_SERVER_RUNNING.store(false, Ordering::SeqCst);

        let _ = scp_sbi_open(None);
        let result = scp_sbi_open(None);
        assert!(result.is_err());

        scp_sbi_close();
    }

    #[test]
    fn test_select_nf_instance_empty() {
        let result = select_nf_instance(&[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_select_nf_instance_single() {
        let candidates = vec![NfInstanceCandidate {
            nf_instance_id: "nf-1".to_string(),
            nf_type: NfType::Amf,
            host: "amf.local".to_string(),
            port: 7777,
            priority: 10,
            capacity: 100,
            load: 50,
            healthy: true,
            scheme: UriScheme::Http,
            prefix: String::new(),
        }];
        let selected = select_nf_instance(&candidates);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().nf_instance_id, "nf-1");
    }

    #[test]
    fn test_select_nf_instance_by_priority() {
        let candidates = vec![
            NfInstanceCandidate {
                nf_instance_id: "nf-low".to_string(),
                nf_type: NfType::Smf,
                host: "smf1.local".to_string(),
                port: 7777,
                priority: 20,
                capacity: 100,
                load: 10,
                healthy: true,
                scheme: UriScheme::Http,
                prefix: String::new(),
            },
            NfInstanceCandidate {
                nf_instance_id: "nf-high".to_string(),
                nf_type: NfType::Smf,
                host: "smf2.local".to_string(),
                port: 7777,
                priority: 10,
                capacity: 100,
                load: 90,
                healthy: true,
                scheme: UriScheme::Http,
                prefix: String::new(),
            },
        ];
        let selected = select_nf_instance(&candidates);
        assert_eq!(selected.unwrap().nf_instance_id, "nf-high");
    }

    #[test]
    fn test_select_nf_instance_by_capacity() {
        let candidates = vec![
            NfInstanceCandidate {
                nf_instance_id: "nf-loaded".to_string(),
                nf_type: NfType::Udm,
                host: "udm1.local".to_string(),
                port: 7777,
                priority: 10,
                capacity: 100,
                load: 90,
                healthy: true,
                scheme: UriScheme::Http,
                prefix: String::new(),
            },
            NfInstanceCandidate {
                nf_instance_id: "nf-idle".to_string(),
                nf_type: NfType::Udm,
                host: "udm2.local".to_string(),
                port: 7777,
                priority: 10,
                capacity: 100,
                load: 10,
                healthy: true,
                scheme: UriScheme::Http,
                prefix: String::new(),
            },
        ];
        let selected = select_nf_instance(&candidates);
        assert_eq!(selected.unwrap().nf_instance_id, "nf-idle");
    }

    #[test]
    fn test_select_nf_instance_skips_unhealthy() {
        let candidates = vec![
            NfInstanceCandidate {
                nf_instance_id: "nf-unhealthy".to_string(),
                nf_type: NfType::Smf,
                host: "smf1.local".to_string(),
                port: 7777,
                priority: 1,
                capacity: 100,
                load: 0,
                healthy: false,
                scheme: UriScheme::Http,
                prefix: String::new(),
            },
            NfInstanceCandidate {
                nf_instance_id: "nf-healthy".to_string(),
                nf_type: NfType::Smf,
                host: "smf2.local".to_string(),
                port: 7777,
                priority: 10,
                capacity: 100,
                load: 50,
                healthy: true,
                scheme: UriScheme::Http,
                prefix: String::new(),
            },
        ];
        let selected = select_nf_instance(&candidates);
        assert_eq!(selected.unwrap().nf_instance_id, "nf-healthy");
    }

    #[test]
    fn test_round_robin_selection() {
        let candidates = vec![
            NfInstanceCandidate {
                nf_instance_id: "nf-a".to_string(),
                nf_type: NfType::Smf,
                host: "smf1.local".to_string(),
                port: 7777,
                priority: 10,
                capacity: 100,
                load: 50,
                healthy: true,
                scheme: UriScheme::Http,
                prefix: String::new(),
            },
            NfInstanceCandidate {
                nf_instance_id: "nf-b".to_string(),
                nf_type: NfType::Smf,
                host: "smf2.local".to_string(),
                port: 7777,
                priority: 10,
                capacity: 100,
                load: 50,
                healthy: true,
                scheme: UriScheme::Http,
                prefix: String::new(),
            },
        ];
        // Call twice to see round-robin switching
        let first = select_nf_instance_round_robin(&candidates)
            .unwrap()
            .nf_instance_id
            .clone();
        let second = select_nf_instance_round_robin(&candidates)
            .unwrap()
            .nf_instance_id
            .clone();
        // They should be different (round-robin)
        assert_ne!(first, second);
    }

    #[test]
    fn test_discovery_cache() {
        let cache = DiscoveryCache::new();

        assert!(cache.get("SMF", "nsmf-pdusession").is_none());

        let candidates = vec![NfInstanceCandidate {
            nf_instance_id: "smf-1".to_string(),
            nf_type: NfType::Smf,
            host: "smf.local".to_string(),
            port: 7777,
            priority: 10,
            capacity: 100,
            load: 0,
            healthy: true,
            scheme: UriScheme::Http,
            prefix: String::new(),
        }];

        cache.put(
            "SMF",
            "nsmf-pdusession",
            candidates.clone(),
            std::time::Duration::from_secs(3600),
        );

        let cached = cache.get("SMF", "nsmf-pdusession");
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().len(), 1);

        assert!(cache.get("AMF", "nsmf-pdusession").is_none());
        assert!(cache.get("SMF", "other").is_none());
    }

    #[test]
    fn test_parse_search_result() {
        let json = serde_json::json!({
            "validityPeriod": 3600,
            "nfInstances": [
                {
                    "nfInstanceId": "smf-001",
                    "nfType": "SMF",
                    "nfStatus": "REGISTERED",
                    "ipv4Addresses": ["10.0.0.1"],
                    "priority": 10,
                    "capacity": 100,
                    "load": 30,
                },
                {
                    "nfInstanceId": "smf-002",
                    "nfType": "SMF",
                    "nfStatus": "SUSPENDED",
                    "fqdn": "smf2.local",
                }
            ]
        });
        let body = serde_json::to_vec(&json).unwrap();
        let candidates = parse_search_result(&body);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].nf_instance_id, "smf-001");
        assert_eq!(candidates[0].host, "10.0.0.1");
        assert!(candidates[0].healthy);
        // No scheme in the profile → defaults to Http (backward-compat).
        assert_eq!(candidates[0].scheme, UriScheme::Http);
        assert_eq!(candidates[0].prefix, "");
        assert_eq!(candidates[1].nf_instance_id, "smf-002");
        assert!(!candidates[1].healthy);
    }

    /// scpd-01 acceptance: an `https` profile with an IPv6 address and
    /// apiPrefix yields `ApiRoot` `https://[v6]:port/prefix`.
    #[test]
    fn test_parse_search_result_https_ipv6_apiprefix() {
        let json = serde_json::json!({
            "validityPeriod": 3600,
            "nfInstances": [{
                "nfInstanceId": "udm-tls-1",
                "nfType": "UDM",
                "nfStatus": "REGISTERED",
                "ipv6Addresses": ["2001:db8::1"],
                "priority": 1,
                "capacity": 100,
                "load": 0,
                "nfServices": [{
                    "serviceInstanceId": "nudm-sdm-1",
                    "serviceName": "nudm-sdm",
                    "scheme": "https",
                    "apiPrefix": "/nudm",
                    "ipEndPoints": [{"transport": "TCP", "port": 8443}]
                }]
            }]
        });
        let body = serde_json::to_vec(&json).unwrap();
        let candidates = parse_search_result(&body);
        assert_eq!(candidates.len(), 1);
        let c = &candidates[0];
        // IPv6 literal must be bracketed for use in an authority component.
        assert_eq!(c.host, "[2001:db8::1]");
        assert_eq!(c.port, 8443);
        assert_eq!(c.scheme, UriScheme::Https);
        assert_eq!(c.prefix, "/nudm");
    }

    /// scpd-01 acceptance: a plain http/ipv4 profile yields the current
    /// default scheme and empty prefix (backward-compat).
    #[test]
    fn test_parse_search_result_http_ipv4_default() {
        let json = serde_json::json!({
            "validityPeriod": 3600,
            "nfInstances": [{
                "nfInstanceId": "udm-plain-1",
                "nfType": "UDM",
                "nfStatus": "REGISTERED",
                "ipv4Addresses": ["10.0.0.2"],
                "priority": 1,
                "capacity": 100,
                "load": 0,
                "nfServices": [{
                    "serviceInstanceId": "nudm-uecm-1",
                    "serviceName": "nudm-uecm",
                    "ipEndPoints": [{"port": 7777}]
                }]
            }]
        });
        let body = serde_json::to_vec(&json).unwrap();
        let candidates = parse_search_result(&body);
        assert_eq!(candidates.len(), 1);
        let c = &candidates[0];
        assert_eq!(c.host, "10.0.0.2");
        assert_eq!(c.port, 7777);
        assert_eq!(c.scheme, UriScheme::Http);
        assert_eq!(c.prefix, "");
    }

    /// scpd-01: when multiple ipEndPoints are present, the one with
    /// `transport: TCP` is preferred over the first entry.
    #[test]
    fn test_parse_search_result_prefers_tcp_endpoint() {
        let json = serde_json::json!({
            "validityPeriod": 3600,
            "nfInstances": [{
                "nfInstanceId": "smf-multi-ep",
                "nfType": "SMF",
                "nfStatus": "REGISTERED",
                "ipv4Addresses": ["10.0.0.3"],
                "nfServices": [{
                    "serviceName": "nsmf-pdusession",
                    "ipEndPoints": [
                        {"transport": "SCTP", "port": 9999},
                        {"transport": "TCP",  "port": 8888}
                    ]
                }]
            }]
        });
        let body = serde_json::to_vec(&json).unwrap();
        let candidates = parse_search_result(&body);
        assert_eq!(candidates.len(), 1);
        // TCP endpoint (port 8888) wins over the first (SCTP, port 9999).
        assert_eq!(candidates[0].port, 8888);
    }

    /// scpd-01: fqdn is chosen when ipv4Addresses is absent.
    #[test]
    fn test_parse_search_result_fqdn_fallback() {
        let json = serde_json::json!({
            "validityPeriod": 3600,
            "nfInstances": [{
                "nfInstanceId": "ausf-fqdn",
                "nfType": "AUSF",
                "nfStatus": "REGISTERED",
                "fqdn": "ausf.5gc.example.org",
                "nfServices": [{
                    "serviceName": "nausf-auth",
                    "ipEndPoints": [{"port": 8443}]
                }]
            }]
        });
        let body = serde_json::to_vec(&json).unwrap();
        let candidates = parse_search_result(&body);
        assert_eq!(candidates[0].host, "ausf.5gc.example.org");
    }
}
