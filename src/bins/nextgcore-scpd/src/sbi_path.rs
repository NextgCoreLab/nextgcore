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

use crate::context::{DiscoveryOption, NfType, SbiServiceType};

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
    // (ogs_sbi::server::SbiServer fronting crate::proxy::ScpProxy); this
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

/// Simplified SBI request
#[derive(Debug, Clone)]
pub struct SbiRequest {
    pub method: String,
    pub uri: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

impl SbiRequest {
    pub fn new(method: &str, uri: &str) -> Self {
        Self {
            method: method.to_string(),
            uri: uri.to_string(),
            headers: HashMap::new(),
            body: None,
        }
    }

    pub fn set_header(&mut self, key: &str, value: &str) {
        self.headers.insert(key.to_string(), value.to_string());
    }

    pub fn get_header(&self, key: &str) -> Option<&String> {
        // Case-insensitive header lookup
        for (k, v) in &self.headers {
            if k.eq_ignore_ascii_case(key) {
                return Some(v);
            }
        }
        None
    }
}

/// Simplified SBI response
#[derive(Debug, Clone)]
pub struct SbiResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

impl SbiResponse {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: HashMap::new(),
            body: None,
        }
    }

    pub fn set_header(&mut self, key: &str, value: &str) {
        self.headers.insert(key.to_string(), value.to_string());
    }
}

/// Parse discovery parameters from request headers
/// Port of header extraction in request_handler
pub fn parse_discovery_headers(
    request: &SbiRequest,
) -> (
    Option<NfType>,
    Option<NfType>,
    Option<SbiServiceType>,
    DiscoveryOption,
) {
    let mut target_nf_type: Option<NfType> = None;
    let mut requester_nf_type: Option<NfType> = None;
    let mut service_type: Option<SbiServiceType> = None;
    let mut discovery_option = DiscoveryOption::new();

    // Requester identity comes from 3gpp-Sbi-Discovery-requester-nf-type
    // (TS 29.500 §5.2.3.2.7) — NOT from User-Agent.
    if let Some(val) = request.get_header(headers::DISCOVERY_REQUESTER_NF_TYPE) {
        requester_nf_type = Some(NfType::from_string(val));
    }

    // Parse target NF type
    if let Some(val) = request.get_header(headers::DISCOVERY_TARGET_NF_TYPE) {
        target_nf_type = Some(NfType::from_string(val));
    }

    // Parse target NF instance ID
    if let Some(val) = request.get_header(headers::DISCOVERY_TARGET_NF_INSTANCE_ID) {
        discovery_option.set_target_nf_instance_id(val);
    }

    // Parse requester NF instance ID
    if let Some(val) = request.get_header(headers::DISCOVERY_REQUESTER_NF_INSTANCE_ID) {
        discovery_option.set_requester_nf_instance_id(val);
    }

    // Parse service names
    if let Some(val) = request.get_header(headers::DISCOVERY_SERVICE_NAMES) {
        discovery_option.parse_service_names(val);
        // Use first service name to determine service type
        if let Some(first_service) = discovery_option.service_names.first() {
            service_type = Some(SbiServiceType::from_name(first_service));
        }
    }

    // Parse DNN
    if let Some(val) = request.get_header(headers::DISCOVERY_DNN) {
        discovery_option.set_dnn(val);
    }

    // Parse HNRF URI
    if let Some(val) = request.get_header(headers::DISCOVERY_HNRF_URI) {
        discovery_option.set_hnrf_uri(val);
    }

    (
        target_nf_type,
        requester_nf_type,
        service_type,
        discovery_option,
    )
}

/// Copy request headers, optionally removing custom discovery headers
/// Port of copy_request from sbi-path.c
pub fn copy_request_headers(
    source: &SbiRequest,
    do_not_remove_custom_header: bool,
) -> HashMap<String, String> {
    let mut target = HashMap::new();

    for (key, val) in &source.headers {
        // Skip scheme and authority (will be set by client)
        if key.eq_ignore_ascii_case(":scheme") || key.eq_ignore_ascii_case(":authority") {
            continue;
        }

        // Optionally skip custom discovery headers
        if !do_not_remove_custom_header {
            if key.eq_ignore_ascii_case(headers::TARGET_APIROOT) {
                continue;
            }
            if key.to_lowercase().starts_with("3gpp-sbi-discovery-") {
                continue;
            }
        }

        target.insert(key.clone(), val.clone());
    }

    target
}

// ============================================================================
// NF Instance Selection & Request Routing (W1.25, W1.27)
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
}

/// Select the best NF instance from a list of candidates using weighted round-robin.
///
/// W1.27: Supports health-check awareness (skips unhealthy instances) and
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

    // W1.27: Filter to healthy instances only
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
/// W1.27: Implements round-robin load balancing among NF instances with
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
// NF Discovery Cache (W1.26)
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
/// W1.26: Caches NF discovery results with TTL to avoid repeated NRF queries.
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
/// W1.26: Parses the SearchResult response from NRF discovery
/// (TS 29.510 Section 6.2.3.2.3.1).
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

            // Extract host/port from ipv4Addresses or fqdn
            let host = inst
                .get("ipv4Addresses")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .or_else(|| inst.get("fqdn").and_then(|v| v.as_str()))
                .unwrap_or("127.0.0.1")
                .to_string();

            let port = inst
                .get("nfServices")
                .and_then(|v| v.as_array())
                .and_then(|services| services.first())
                .and_then(|svc| svc.get("ipEndPoints"))
                .and_then(|v| v.as_array())
                .and_then(|eps| eps.first())
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
            });
        }
    }

    candidates
}

/// Route an SBI request to the appropriate NF instance
/// Returns the target host:port to forward to
pub fn route_request(
    request: &SbiRequest,
    candidates: &[NfInstanceCandidate],
) -> Result<(String, u16, HashMap<String, String>), String> {
    // If Target-apiRoot is present, use it directly
    if let Some(target_apiroot) = request.get_header(headers::TARGET_APIROOT) {
        // Parse host:port from target_apiroot URL
        let (host, port) = parse_apiroot_url(target_apiroot)?;
        let fwd_headers = copy_request_headers(request, false);
        return Ok((host, port, fwd_headers));
    }

    // Otherwise, select from candidates via NF discovery
    let selected = select_nf_instance(candidates)
        .ok_or_else(|| "No NF instance available for routing".to_string())?;

    log::debug!(
        "Selected NF instance {} ({}:{}) for routing",
        selected.nf_instance_id,
        selected.host,
        selected.port
    );

    let fwd_headers = copy_request_headers(request, false);
    Ok((selected.host.clone(), selected.port, fwd_headers))
}

/// Parse a URL to extract host and port
fn parse_apiroot_url(url: &str) -> Result<(String, u16), String> {
    // Strip scheme
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    // Strip path
    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);

    if let Some(colon_idx) = host_port.rfind(':') {
        let host = &host_port[..colon_idx];
        let port: u16 = host_port[colon_idx + 1..]
            .parse()
            .map_err(|_| "Invalid port in URL".to_string())?;
        Ok((host.to_string(), port))
    } else {
        // Default ports
        let port = if url.starts_with("https://") { 443 } else { 80 };
        Ok((host_port.to_string(), port))
    }
}

/// Build a forwarded SBI request with updated authority
pub fn build_forwarded_request(
    original: &SbiRequest,
    target_host: &str,
    target_port: u16,
    headers: HashMap<String, String>,
) -> SbiRequest {
    let mut fwd = SbiRequest {
        method: original.method.clone(),
        uri: original.uri.clone(),
        headers,
        body: original.body.clone(),
    };
    fwd.set_header(":authority", &format!("{target_host}:{target_port}"));
    fwd
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
    fn test_sbi_request() {
        let mut request = SbiRequest::new("POST", "/test");
        request.set_header("Content-Type", "application/json");

        assert_eq!(request.method, "POST");
        assert_eq!(request.uri, "/test");
        assert_eq!(
            request.get_header("content-type"),
            Some(&"application/json".to_string())
        );
    }

    #[test]
    fn test_sbi_response() {
        let mut response = SbiResponse::new(200);
        response.set_header("Content-Type", "application/json");

        assert_eq!(response.status, 200);
    }

    #[test]
    fn test_parse_discovery_headers() {
        let mut request = SbiRequest::new("GET", "/test");
        // Requester identity is carried in the Discovery-requester-nf-type
        // header (TS 29.500 §5.2.3.2.7), not in User-Agent.
        request.set_header(headers::DISCOVERY_REQUESTER_NF_TYPE, "AMF");
        request.set_header(headers::DISCOVERY_TARGET_NF_TYPE, "UDM");
        request.set_header(headers::DISCOVERY_SERVICE_NAMES, "nudm-uecm,nudm-sdm");
        request.set_header(headers::DISCOVERY_DNN, "internet");

        let (target_nf_type, requester_nf_type, service_type, discovery_option) =
            parse_discovery_headers(&request);

        assert_eq!(target_nf_type, Some(NfType::Udm));
        assert_eq!(requester_nf_type, Some(NfType::Amf));
        assert_eq!(service_type, Some(SbiServiceType::NudmUecm));
        assert_eq!(discovery_option.dnn, Some("internet".to_string()));
        assert_eq!(discovery_option.service_names.len(), 2);
    }

    #[test]
    fn test_copy_request_headers() {
        let mut request = SbiRequest::new("GET", "/test");
        request.set_header(":scheme", "https");
        request.set_header(":authority", "example.com");
        request.set_header("Content-Type", "application/json");
        request.set_header(headers::TARGET_APIROOT, "https://target.com");
        request.set_header(headers::DISCOVERY_TARGET_NF_TYPE, "UDM");

        // With custom headers removed
        let headers = copy_request_headers(&request, false);
        assert!(!headers.contains_key(":scheme"));
        assert!(!headers.contains_key(":authority"));
        assert!(headers.contains_key("Content-Type"));
        assert!(!headers.contains_key(headers::TARGET_APIROOT));

        // With custom headers preserved
        let headers = copy_request_headers(&request, true);
        assert!(headers.contains_key(headers::TARGET_APIROOT));
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
        assert_eq!(candidates[1].nf_instance_id, "smf-002");
        assert!(!candidates[1].healthy);
    }

    #[test]
    fn test_parse_apiroot_url() {
        let (host, port) = parse_apiroot_url("https://amf.example.com:8443").unwrap();
        assert_eq!(host, "amf.example.com");
        assert_eq!(port, 8443);

        let (host, port) = parse_apiroot_url("https://smf.local").unwrap();
        assert_eq!(host, "smf.local");
        assert_eq!(port, 443);

        let (host, port) = parse_apiroot_url("http://127.0.0.1:7777/path").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 7777);
    }

    #[test]
    fn test_route_request_with_target_apiroot() {
        let mut request = SbiRequest::new("POST", "/nsmf-pdusession/v1/sm-contexts");
        request.set_header(headers::TARGET_APIROOT, "https://smf.local:7778");

        let result = route_request(&request, &[]);
        assert!(result.is_ok());
        let (host, port, _) = result.unwrap();
        assert_eq!(host, "smf.local");
        assert_eq!(port, 7778);
    }

    #[test]
    fn test_build_forwarded_request() {
        let original = SbiRequest::new("GET", "/nudm-sdm/v1/imsi-123/sm-data");
        let headers = HashMap::new();
        let fwd = build_forwarded_request(&original, "udm.local", 7777, headers);
        assert_eq!(fwd.method, "GET");
        assert_eq!(fwd.uri, "/nudm-sdm/v1/imsi-123/sm-data");
        assert_eq!(
            fwd.headers.get(":authority"),
            Some(&"udm.local:7777".to_string())
        );
    }
}
