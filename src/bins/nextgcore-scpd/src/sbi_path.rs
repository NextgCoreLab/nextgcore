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

/// One `nfServices` entry of an NF profile, reduced to what endpoint selection
/// needs (TS 29.510 §6.1.6.2.x).
///
/// An NF may register several services with **different** schemes, `apiPrefix`
/// values and ports — a UDM registering `nudm-sdm`, `nudm-uecm` and `nudm-ueau`
/// is the ordinary case. TS 29.510 §6.2.6.2 selects the endpoint from the
/// service matching the requested service name and the API version in the URI,
/// so those three fields must be kept *per service* rather than collapsed to
/// the profile's first entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfServiceEndpoint {
    /// `serviceName`, e.g. `nudm-sdm`.
    pub service_name: String,
    /// `versions[].apiVersionInUri` values, e.g. `["v1"]`. **Empty means the
    /// profile declared none**, which is treated as "serves any version" rather
    /// than "serves no version": a great many profiles omit `versions`, and
    /// refusing them would turn a missing optional field into an outage.
    pub versions: Vec<String>,
    /// `scheme` (`https` → TLS), defaulting to `Http` when absent.
    pub scheme: UriScheme,
    /// Port from this service's `ipEndPoints` (TCP entry preferred).
    pub port: u16,
    /// `apiPrefix` for this service (empty when absent).
    pub prefix: String,
}

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
    /// Every `nfServices` entry of the profile, so the endpoint can be taken
    /// from the *matching* service (TS 29.510 §6.2.6.2) instead of the first.
    /// The `scheme`/`port`/`prefix` fields above remain the profile-level
    /// fallback used when the profile declares no services at all.
    pub services: Vec<NfServiceEndpoint>,
}

/// Why no producer endpoint could be selected for a requested service and API
/// version (TS 29.510 §6.2.6.2). The variants are kept distinct because the
/// SCP owes the consumer three *different* answers: nothing to choose from,
/// nobody offers the service, and the service exists in another version only —
/// the last of which is `INVALID_API` rather than a discovery failure
/// (TS 29.500 Table 5.2.7.2-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointSelectionError {
    /// The candidate list is empty, or holds nothing selectable.
    NoCandidate,
    /// Candidates exist but none registers the requested `serviceName`.
    ServiceNotOffered,
    /// The requested `serviceName` is registered, but no candidate declares the
    /// requested API major version for it.
    UnsupportedApiVersion,
}

/// A producer endpoint resolved from the *matching* `NFService` of the selected
/// candidate. `scheme`/`port`/`prefix` are the matched service's, not the
/// profile's first service's.
#[derive(Debug, Clone)]
pub struct SelectedEndpoint<'a> {
    pub candidate: &'a NfInstanceCandidate,
    pub scheme: UriScheme,
    pub port: u16,
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
    select_best(candidates.iter().collect())
}

/// The health / priority / capacity ordering of [`select_nf_instance`], factored
/// out so it can be applied *within* a service-and-version-matched subset
/// (TS 29.510 §6.2.6.2) rather than only over a whole SearchResult. Behaviour is
/// unchanged for the whole-list caller.
fn select_best(pool: Vec<&NfInstanceCandidate>) -> Option<&NfInstanceCandidate> {
    if pool.is_empty() {
        return None;
    }

    // Filter to healthy instances only
    let healthy: Vec<&NfInstanceCandidate> = pool.iter().copied().filter(|c| c.healthy).collect();

    // Fall back to all candidates if none are marked healthy
    let pool = if healthy.is_empty() { pool } else { healthy };

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

/// True when `service` is the service the consumer asked for. A `None` request
/// service name matches everything (the caller could not determine one).
fn service_name_matches(service: &NfServiceEndpoint, requested: Option<&str>) -> bool {
    match requested {
        None => true,
        Some(name) => service.service_name.eq_ignore_ascii_case(name),
    }
}

/// True when `service` serves the requested API major version. A service that
/// declares **no** `versions` matches any version: the field is optional in
/// TS 29.510 and most profiles in this tree omit it, so treating "unstated" as
/// "unsupported" would reject conformant producers. A `None` requested version
/// likewise matches everything.
fn service_version_matches(service: &NfServiceEndpoint, requested: Option<&str>) -> bool {
    match requested {
        None => true,
        Some(version) => {
            service.versions.is_empty()
                || service
                    .versions
                    .iter()
                    .any(|v| v.eq_ignore_ascii_case(version))
        }
    }
}

/// Select a producer endpoint by matching the requested **service name** and
/// **API major version**, per TS 29.510 §6.2.6.2.
///
/// This is the selection TS 29.510 actually defines: an `NFService` is chosen by
/// service name and by the API version in the URI, and the endpoint (scheme,
/// `apiPrefix`, port) comes from *that* service. Taking the endpoint from
/// `nfServices[0]` instead mis-addresses every multi-service producer — a UDM
/// serving `nudm-uecm` on 8080 and `nudm-sdm` on 8443 resolves both to whichever
/// entry the NRF happened to list first, and the failure then surfaces as a
/// producer 404 that looks like a producer bug.
///
/// The existing priority / capacity / load ordering is applied **within** the
/// matching set, so a single-service producer selects exactly as before.
///
/// A candidate whose profile declares no `nfServices` at all keeps the
/// profile-level `scheme`/`port`/`prefix` and matches any request: there is no
/// service list to contradict the request, and the alternative is refusing to
/// route to a producer the NRF returned.
pub fn select_nf_service_endpoint<'a>(
    candidates: &'a [NfInstanceCandidate],
    service_name: Option<&str>,
    api_version: Option<&str>,
) -> Result<SelectedEndpoint<'a>, EndpointSelectionError> {
    rank_nf_service_endpoints(candidates, service_name, api_version)?
        .into_iter()
        .next()
        .ok_or(EndpointSelectionError::NoCandidate)
}

/// Every producer endpoint matching the requested service and API version, in
/// **selection order** — the head is exactly what [`select_nf_service_endpoint`]
/// returns, and each subsequent entry is what it *would* return with all the
/// preceding ones removed (scpd-#209).
///
/// The ranking is built by applying the same health / priority / capacity rule
/// repeatedly rather than by sorting on a comparable key. That is deliberate:
/// `select_best` breaks a capacity tie via `max_by_key`, which yields the **last**
/// maximum, whereas a descending sort yields the first. Re-running the real rule
/// makes head-equality true by construction instead of by reproducing a tie-break
/// exactly — which is the sort of detail that drifts and then silently changes
/// which producer every Model D request goes to.
///
/// The candidate lists here are a handful of entries, so the repeated pass is not
/// a cost worth trading correctness for.
pub fn rank_nf_service_endpoints<'a>(
    candidates: &'a [NfInstanceCandidate],
    service_name: Option<&str>,
    api_version: Option<&str>,
) -> Result<Vec<SelectedEndpoint<'a>>, EndpointSelectionError> {
    let matching = match_candidates(candidates, service_name, api_version)?;

    // The pool rule is applied ONCE, up front, rather than left to emerge from
    // `select_best`'s own fallback. It has to be: `select_best` falls back to "all
    // candidates" when none are healthy, so re-running it until the pool empties
    // would hand back every SUSPENDED instance as a last-resort alternate once the
    // healthy ones were exhausted. A SUSPENDED NF must not be selected
    // (TS 29.510 `nfStatus`), so that would trade a reachability problem for a
    // conformance one. The existing leniency — use everything when the NRF reports
    // nothing healthy at all — is preserved, because that is a different case.
    let healthy: Vec<&NfInstanceCandidate> =
        matching.iter().copied().filter(|c| c.healthy).collect();
    let mut remaining = if healthy.is_empty() {
        matching
    } else {
        healthy
    };
    let mut ranked = Vec::with_capacity(remaining.len());
    while !remaining.is_empty() {
        let Some(best) = select_best(remaining.clone()) else {
            break;
        };
        remaining.retain(|c| !std::ptr::eq(*c, best));
        ranked.push(resolve_endpoint(best, service_name, api_version));
    }
    if ranked.is_empty() {
        return Err(EndpointSelectionError::NoCandidate);
    }
    Ok(ranked)
}

/// The candidates that match the requested service name and API version, in
/// SearchResult order and before any priority ordering. Splitting this out is
/// what lets the error variants stay distinct while both the single-pick and the
/// ranked-list entry points share one definition of "matching".
fn match_candidates<'a>(
    candidates: &'a [NfInstanceCandidate],
    service_name: Option<&str>,
    api_version: Option<&str>,
) -> Result<Vec<&'a NfInstanceCandidate>, EndpointSelectionError> {
    if candidates.is_empty() {
        return Err(EndpointSelectionError::NoCandidate);
    }

    // Stage 1: candidates that offer the requested service at all. Kept separate
    // from the version stage so "offered in another version" is distinguishable
    // from "not offered", which are different answers to the consumer.
    let offers_service: Vec<&NfInstanceCandidate> = candidates
        .iter()
        .filter(|c| {
            c.services.is_empty()
                || c.services
                    .iter()
                    .any(|s| service_name_matches(s, service_name))
        })
        .collect();
    if offers_service.is_empty() {
        return Err(EndpointSelectionError::ServiceNotOffered);
    }

    // Stage 2: of those, the ones serving the requested API major version.
    let serves_version: Vec<&NfInstanceCandidate> = offers_service
        .iter()
        .copied()
        .filter(|c| {
            c.services.is_empty()
                || c.services.iter().any(|s| {
                    service_name_matches(s, service_name) && service_version_matches(s, api_version)
                })
        })
        .collect();
    if serves_version.is_empty() {
        return Err(EndpointSelectionError::UnsupportedApiVersion);
    }

    Ok(serves_version)
}

/// Resolve `candidate` to its endpoint, taking scheme / port / `apiPrefix` from
/// the **matching** service and falling back to the profile-level fields only
/// when the profile declares no service list.
fn resolve_endpoint<'a>(
    candidate: &'a NfInstanceCandidate,
    service_name: Option<&str>,
    api_version: Option<&str>,
) -> SelectedEndpoint<'a> {
    let matched = candidate
        .services
        .iter()
        .find(|s| service_name_matches(s, service_name) && service_version_matches(s, api_version));
    match matched {
        Some(service) => SelectedEndpoint {
            candidate,
            scheme: service.scheme,
            port: service.port,
            prefix: service.prefix.clone(),
        },
        None => SelectedEndpoint {
            candidate,
            scheme: candidate.scheme,
            port: candidate.port,
            prefix: candidate.prefix.clone(),
        },
    }
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
/// The cache key is (target_nf_type, service_name, discriminator), where
/// `discriminator` folds in every routing-relevant 3gpp-Sbi-Discovery-* factor
/// (S-NSSAI, DNN, GUAMI, TAI, target-PLMN-list, target-NF-instance-id) so that
/// two delegated requests for the same NF type + service but a different slice,
/// DNN, area, or pinned instance are not served each other's producer set
/// (TS 29.500 §6.10.3.2 / §6.10.3.4 NOTE 2).
pub struct DiscoveryCache {
    entries: std::sync::RwLock<HashMap<(String, String, String), DiscoveryCacheEntry>>,
    /// Hard ceiling on cached SearchResults (scpd-#102). The discriminator is
    /// header-influenced, so an unbounded map is a slow-memory-growth concern
    /// (TS 33.522 §4.2.3.3). Unlike the other proxy caches this keeps its own
    /// per-entry `validityPeriod` TTL, so only a size bound is added here.
    max_entries: usize,
}

/// Default ceiling for the discovery cache when constructed with [`new`].
const DEFAULT_DISCOVERY_MAX_ENTRIES: usize = 4096;

impl DiscoveryCache {
    pub fn new() -> Self {
        Self::with_max_entries(DEFAULT_DISCOVERY_MAX_ENTRIES)
    }

    /// Create a discovery cache bounded to `max_entries` (clamped to >= 1).
    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            entries: std::sync::RwLock::new(HashMap::new()),
            max_entries: max_entries.max(1),
        }
    }

    /// Look up a cached discovery result. `discriminator` must be built the same
    /// way for lookup and store (see `DiscoveryCache` docs).
    pub fn get(
        &self,
        target_nf_type: &str,
        service_name: &str,
        discriminator: &str,
    ) -> Option<Vec<NfInstanceCandidate>> {
        let entries = self.entries.read().ok()?;
        let key = (
            target_nf_type.to_string(),
            service_name.to_string(),
            discriminator.to_string(),
        );
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
        discriminator: &str,
        candidates: Vec<NfInstanceCandidate>,
        ttl: std::time::Duration,
    ) {
        if let Ok(mut entries) = self.entries.write() {
            let key = (
                target_nf_type.to_string(),
                service_name.to_string(),
                discriminator.to_string(),
            );
            // Enforce the size bound (scpd-#102): when the key is new and the
            // cache is full, drop expired entries first and, failing that, evict
            // the oldest by insertion time so the ceiling is a hard bound.
            if !entries.contains_key(&key) && entries.len() >= self.max_entries {
                entries.retain(|_, v| !v.is_expired());
                if entries.len() >= self.max_entries {
                    if let Some(oldest) = entries
                        .iter()
                        .min_by_key(|(_, v)| v.cached_at)
                        .map(|(k, _)| k.clone())
                    {
                        entries.remove(&oldest);
                    }
                }
            }
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

    /// Number of cached entries (including any not-yet-purged expired ones).
    /// For tests and observability.
    pub fn len(&self) -> usize {
        self.entries.read().map(|e| e.len()).unwrap_or(0)
    }

    /// Whether the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
///
/// In addition **every** `nfServices` entry is retained in
/// [`NfInstanceCandidate::services`] with its own scheme / port / `apiPrefix` and
/// `versions[].apiVersionInUri`, so [`select_nf_service_endpoint`] can address
/// the service the consumer actually asked for (TS 29.510 §6.2.6.2). The
/// `nfServices[0]`-derived fields above are kept as the profile-level fallback
/// for a profile that registers no services.
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
            let service_array = inst.get("nfServices").and_then(|v| v.as_array());
            let first_service = service_array.and_then(|s| s.first());

            let scheme = service_scheme(first_service);
            let prefix = service_prefix(first_service);
            let port = service_port(first_service);

            // Every registered service, with ITS OWN endpoint, so the SCP can
            // address the requested one (TS 29.510 §6.2.6.2).
            let services: Vec<NfServiceEndpoint> = service_array
                .map(|arr| {
                    arr.iter()
                        .map(|svc| NfServiceEndpoint {
                            service_name: svc
                                .get("serviceName")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                            versions: service_versions(svc),
                            scheme: service_scheme(Some(svc)),
                            port: service_port(Some(svc)),
                            prefix: service_prefix(Some(svc)),
                        })
                        .collect()
                })
                .unwrap_or_default();

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
                services,
            });
        }
    }

    candidates
}

/// `nfServices[].scheme` → [`UriScheme`]; `Http` when absent or unrecognised
/// (backward-compat default, TS 29.510 §6.1.6.2.x).
fn service_scheme(service: Option<&serde_json::Value>) -> UriScheme {
    service
        .and_then(|svc| svc.get("scheme"))
        .and_then(|v| v.as_str())
        .map(|s| {
            if s.eq_ignore_ascii_case("https") {
                UriScheme::Https
            } else {
                UriScheme::Http
            }
        })
        .unwrap_or(UriScheme::Http)
}

/// `nfServices[].apiPrefix`, empty string when absent (TS 29.501 §4.4.1).
fn service_prefix(service: Option<&serde_json::Value>) -> String {
    service
        .and_then(|svc| svc.get("apiPrefix"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Port from `nfServices[].ipEndPoints`, preferring an entry explicitly marked
/// `transport: TCP` and falling back to the first entry, then to 7777.
fn service_port(service: Option<&serde_json::Value>) -> u16 {
    service
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
        .unwrap_or(7777) as u16
}

/// `nfServices[].versions[].apiVersionInUri` values (TS 29.510 §6.1.6.2.12).
/// Entries without an `apiVersionInUri` are skipped rather than guessed at from
/// `apiFullVersion`; a profile whose whole `versions` array yields nothing is
/// therefore indistinguishable from one that declared none, which
/// [`service_version_matches`] treats as "serves any version".
fn service_versions(service: &serde_json::Value) -> Vec<String> {
    service
        .get("versions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.get("apiVersionInUri").and_then(|x| x.as_str()))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
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

    /// Serialises the tests that drive the process-global SBI_SERVER_RUNNING
    /// lifecycle flag.
    ///
    /// `store(false)` at the top of each test is not isolation: cargo runs the
    /// tests of one binary on parallel threads, so a second test's reset or its
    /// `scp_sbi_open` can land between this test's open and its assert. Observed
    /// as `test_sbi_open_close` failing on `assert!(result.is_ok())` because
    /// `test_sbi_open_already_running` had already set the flag, making open
    /// return Err("SBI server already running"). Rare (it needs the two threads
    /// to interleave inside a few instructions) but a real race, not an
    /// environment artefact.
    fn sbi_lifecycle_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn test_sbi_open_close() {
        let _serial = sbi_lifecycle_lock();
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
        let _serial = sbi_lifecycle_lock();
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
            services: Vec::new(),
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
                services: Vec::new(),
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
                services: Vec::new(),
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
                services: Vec::new(),
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
                services: Vec::new(),
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
                services: Vec::new(),
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
                services: Vec::new(),
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
                services: Vec::new(),
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
                services: Vec::new(),
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

        assert!(cache.get("SMF", "nsmf-pdusession", "").is_none());

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
            services: Vec::new(),
        }];

        cache.put(
            "SMF",
            "nsmf-pdusession",
            "",
            candidates.clone(),
            std::time::Duration::from_secs(3600),
        );

        let cached = cache.get("SMF", "nsmf-pdusession", "");
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().len(), 1);

        assert!(cache.get("AMF", "nsmf-pdusession", "").is_none());
        assert!(cache.get("SMF", "other", "").is_none());
        // A different discriminator (e.g. a different S-NSSAI) must miss even
        // for the same NF type + service (TS 29.500 §6.10.3.2).
        assert!(cache
            .get("SMF", "nsmf-pdusession", "sst=1,sd=000001")
            .is_none());
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

    /// Build a one-instance candidate list for cache tests.
    fn one_candidate(id: &str) -> Vec<NfInstanceCandidate> {
        vec![NfInstanceCandidate {
            nf_instance_id: id.to_string(),
            nf_type: NfType::Smf,
            host: "smf.local".to_string(),
            port: 7777,
            priority: 10,
            capacity: 100,
            load: 0,
            healthy: true,
            scheme: UriScheme::Http,
            prefix: String::new(),
            services: Vec::new(),
        }]
    }

    /// scpd-#102: the discovery cache enforces its max-entry bound, evicting the
    /// oldest entry when a new one is inserted at capacity.
    #[test]
    fn test_discovery_cache_bound_evicts_oldest() {
        let cache = DiscoveryCache::with_max_entries(2);
        let ttl = std::time::Duration::from_secs(3600);
        cache.put("SMF", "svc", "d1", one_candidate("a"), ttl);
        cache.put("SMF", "svc", "d2", one_candidate("b"), ttl);
        assert_eq!(cache.len(), 2);
        // Third insert at capacity evicts the oldest (d1).
        cache.put("SMF", "svc", "d3", one_candidate("c"), ttl);
        assert_eq!(cache.len(), 2, "the bound is a hard ceiling");
        assert!(cache.get("SMF", "svc", "d1").is_none(), "oldest evicted");
        assert!(cache.get("SMF", "svc", "d3").is_some(), "newest present");
    }

    /// scpd-#102: purge_expired removes entries past their per-entry TTL, so a
    /// sweep from the main loop shrinks the map.
    #[test]
    fn test_discovery_cache_purge_expired_shrinks() {
        let cache = DiscoveryCache::with_max_entries(8);
        // ttl of zero => immediately expired (elapsed >= 0), deterministic.
        cache.put(
            "SMF",
            "svc",
            "d1",
            one_candidate("a"),
            std::time::Duration::ZERO,
        );
        assert_eq!(cache.len(), 1, "entry occupies a slot until purged");
        assert!(
            cache.get("SMF", "svc", "d1").is_none(),
            "expired: get misses"
        );
        cache.purge_expired();
        assert!(cache.is_empty(), "purge_expired reclaims the expired entry");
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

    // ------------------------------------------------------------------
    // scpd-#207: endpoint selection matches serviceName AND API version
    // (TS 29.510 §6.2.6.2)
    // ------------------------------------------------------------------

    /// A UDM registering two services on different ports / prefixes / schemes —
    /// the ordinary shape TS 29.510 §6.2.6.2 exists for.
    ///
    /// Both services declare the SAME `v1`, deliberately: with different versions
    /// the version filter alone would resolve the endpoint and
    /// `test_select_endpoint_uses_the_requested_services_endpoint` would pass with
    /// service-name matching disabled. It was written that way first and the
    /// revert caught it. The name is now the only discriminator.
    fn multi_service_udm() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "validityPeriod": 3600,
            "nfInstances": [{
                "nfInstanceId": "udm-multi",
                "nfType": "UDM",
                "nfStatus": "REGISTERED",
                "ipv4Addresses": ["10.0.0.9"],
                "priority": 1,
                "capacity": 100,
                "load": 0,
                "nfServices": [
                    {
                        "serviceName": "nudm-uecm",
                        "apiPrefix": "/uecm",
                        "versions": [{"apiVersionInUri": "v1"}],
                        "ipEndPoints": [{"transport": "TCP", "port": 8080}]
                    },
                    {
                        "serviceName": "nudm-sdm",
                        "scheme": "https",
                        "apiPrefix": "/sdm",
                        "versions": [{"apiVersionInUri": "v1"}],
                        "ipEndPoints": [{"transport": "TCP", "port": 8443}]
                    }
                ]
            }]
        }))
        .unwrap()
    }

    /// scpd-#207: `parse_search_result` retains EVERY service with its own
    /// endpoint, not just `nfServices[0]`.
    #[test]
    fn test_parse_search_result_retains_every_service_endpoint() {
        let candidates = parse_search_result(&multi_service_udm());
        assert_eq!(candidates.len(), 1);
        let services = &candidates[0].services;
        assert_eq!(services.len(), 2, "both services retained");
        assert_eq!(services[0].service_name, "nudm-uecm");
        assert_eq!(services[0].port, 8080);
        assert_eq!(services[0].prefix, "/uecm");
        assert_eq!(services[0].scheme, UriScheme::Http);
        assert_eq!(services[0].versions, vec!["v1".to_string()]);
        assert_eq!(services[1].service_name, "nudm-sdm");
        assert_eq!(services[1].port, 8443);
        assert_eq!(services[1].prefix, "/sdm");
        assert_eq!(services[1].scheme, UriScheme::Https);
        assert_eq!(services[1].versions, vec!["v1".to_string()]);
        // The profile-level fallback fields still mirror nfServices[0].
        assert_eq!(candidates[0].port, 8080);
        assert_eq!(candidates[0].prefix, "/uecm");
    }

    /// scpd-#207 acceptance: with a two-service producer on differing ports and
    /// prefixes, the REQUESTED service's endpoint is used — for both services, so
    /// the test cannot pass by always returning the first (or the last) entry.
    #[test]
    fn test_select_endpoint_uses_the_requested_services_endpoint() {
        let candidates = parse_search_result(&multi_service_udm());

        let uecm = select_nf_service_endpoint(&candidates, Some("nudm-uecm"), Some("v1"))
            .expect("uecm selected");
        assert_eq!(uecm.candidate.nf_instance_id, "udm-multi");
        assert_eq!(uecm.port, 8080);
        assert_eq!(uecm.prefix, "/uecm");
        assert_eq!(uecm.scheme, UriScheme::Http);

        let sdm = select_nf_service_endpoint(&candidates, Some("nudm-sdm"), Some("v1"))
            .expect("sdm selected");
        assert_eq!(sdm.port, 8443, "the second service's port, not the first's");
        assert_eq!(sdm.prefix, "/sdm");
        assert_eq!(sdm.scheme, UriScheme::Https);
    }

    /// scpd-#207 acceptance: an API version the producer does not declare for the
    /// requested service is `UnsupportedApiVersion` — distinct from
    /// `ServiceNotOffered`, because the two owe the consumer different answers.
    #[test]
    fn test_select_endpoint_distinguishes_version_from_service_mismatch() {
        let candidates = parse_search_result(&multi_service_udm());

        // nudm-uecm exists, but only at v1.
        assert_eq!(
            select_nf_service_endpoint(&candidates, Some("nudm-uecm"), Some("v2")).unwrap_err(),
            EndpointSelectionError::UnsupportedApiVersion
        );
        // nudm-ueau is not registered at all.
        assert_eq!(
            select_nf_service_endpoint(&candidates, Some("nudm-ueau"), Some("v1")).unwrap_err(),
            EndpointSelectionError::ServiceNotOffered
        );
        // An empty SearchResult is neither.
        assert_eq!(
            select_nf_service_endpoint(&[], Some("nudm-uecm"), Some("v1")).unwrap_err(),
            EndpointSelectionError::NoCandidate
        );
    }

    /// scpd-#207: a profile that declares NO `versions` serves any version, and a
    /// profile with no `nfServices` at all keeps its profile-level endpoint. Both
    /// are the backward-compatibility cases: refusing them would turn a missing
    /// optional field into an outage.
    #[test]
    fn test_select_endpoint_is_lenient_where_the_profile_is_silent() {
        let versionless = serde_json::to_vec(&serde_json::json!({
            "nfInstances": [{
                "nfInstanceId": "udm-versionless",
                "nfType": "UDM",
                "nfStatus": "REGISTERED",
                "ipv4Addresses": ["10.0.0.10"],
                "nfServices": [{
                    "serviceName": "nudm-uecm",
                    "ipEndPoints": [{"port": 7777}]
                }]
            }]
        }))
        .unwrap();
        let candidates = parse_search_result(&versionless);
        for version in ["v1", "v2", "v9"] {
            let selected =
                select_nf_service_endpoint(&candidates, Some("nudm-uecm"), Some(version))
                    .unwrap_or_else(|e| panic!("versionless profile must serve {version}: {e:?}"));
            assert_eq!(selected.port, 7777);
        }

        let serviceless = serde_json::to_vec(&serde_json::json!({
            "nfInstances": [{
                "nfInstanceId": "udm-serviceless",
                "nfType": "UDM",
                "nfStatus": "REGISTERED",
                "ipv4Addresses": ["10.0.0.11"]
            }]
        }))
        .unwrap();
        let candidates = parse_search_result(&serviceless);
        let selected = select_nf_service_endpoint(&candidates, Some("nudm-uecm"), Some("v1"))
            .expect("a profile with no service list is still routable");
        assert_eq!(selected.port, 7777, "profile-level fallback port");
        assert_eq!(selected.scheme, UriScheme::Http);
    }

    /// scpd-#207: the priority / capacity ordering is applied WITHIN the matching
    /// set. The best-priority instance here does not offer the requested service,
    /// so the worse-priority one that does must win — a test that only ever had
    /// matching candidates could not tell the filter from the ordering.
    #[test]
    fn test_select_endpoint_orders_within_the_matching_set_only() {
        let mixed = serde_json::to_vec(&serde_json::json!({
            "nfInstances": [
                {
                    "nfInstanceId": "udm-sdm-only",
                    "nfType": "UDM",
                    "nfStatus": "REGISTERED",
                    "ipv4Addresses": ["10.0.0.12"],
                    "priority": 1,
                    "nfServices": [{
                        "serviceName": "nudm-sdm",
                        "ipEndPoints": [{"port": 1111}]
                    }]
                },
                {
                    "nfInstanceId": "udm-uecm-only",
                    "nfType": "UDM",
                    "nfStatus": "REGISTERED",
                    "ipv4Addresses": ["10.0.0.13"],
                    "priority": 90,
                    "nfServices": [{
                        "serviceName": "nudm-uecm",
                        "ipEndPoints": [{"port": 2222}]
                    }]
                }
            ]
        }))
        .unwrap();
        let candidates = parse_search_result(&mixed);
        // Whole-list selection still prefers priority 1 (unchanged behaviour).
        assert_eq!(
            select_nf_instance(&candidates)
                .expect("selected")
                .nf_instance_id,
            "udm-sdm-only"
        );
        // Service-matched selection must skip it: it does not serve nudm-uecm.
        let selected = select_nf_service_endpoint(&candidates, Some("nudm-uecm"), Some("v1"))
            .expect("the matching instance is selected despite worse priority");
        assert_eq!(selected.candidate.nf_instance_id, "udm-uecm-only");
        assert_eq!(selected.port, 2222);
    }

    // ------------------------------------------------------------------
    // scpd-#209: the ranked candidate list reselection walks
    // ------------------------------------------------------------------

    /// scpd-#209: the ranked list's **head is exactly** what the single-pick entry
    /// point returns, and each tail entry is the same rule with the preceding ones
    /// removed. That equality is the whole reason `rank_nf_service_endpoints`
    /// re-runs `select_best` instead of sorting on a key.
    ///
    /// The fixture contains a deliberate **capacity tie** between `udm-a` and
    /// `udm-b`: `select_best` resolves it with `max_by_key`, which yields the LAST
    /// maximum, so the head is `udm-b`. A descending sort would have produced
    /// `udm-a` and silently changed which producer every Model D request goes to.
    #[test]
    fn test_ranked_endpoints_head_matches_the_single_pick() {
        let tied = serde_json::to_vec(&serde_json::json!({
            "nfInstances": [
                {
                    "nfInstanceId": "udm-a",
                    "nfType": "UDM", "nfStatus": "REGISTERED",
                    "ipv4Addresses": ["10.0.0.20"],
                    "priority": 10, "capacity": 100, "load": 50,
                    "nfServices": [{"serviceName": "nudm-uecm",
                                    "ipEndPoints": [{"port": 1001}]}]
                },
                {
                    "nfInstanceId": "udm-b",
                    "nfType": "UDM", "nfStatus": "REGISTERED",
                    "ipv4Addresses": ["10.0.0.21"],
                    "priority": 10, "capacity": 100, "load": 50,
                    "nfServices": [{"serviceName": "nudm-uecm",
                                    "ipEndPoints": [{"port": 1002}]}]
                },
                {
                    "nfInstanceId": "udm-c",
                    "nfType": "UDM", "nfStatus": "REGISTERED",
                    "ipv4Addresses": ["10.0.0.22"],
                    "priority": 20, "capacity": 100, "load": 0,
                    "nfServices": [{"serviceName": "nudm-uecm",
                                    "ipEndPoints": [{"port": 1003}]}]
                }
            ]
        }))
        .unwrap();
        let candidates = parse_search_result(&tied);

        let single = select_nf_service_endpoint(&candidates, Some("nudm-uecm"), Some("v1"))
            .expect("single pick");
        let ranked =
            rank_nf_service_endpoints(&candidates, Some("nudm-uecm"), Some("v1")).expect("ranked");

        assert_eq!(
            ranked.len(),
            3,
            "every matching candidate is available as an alternate"
        );
        assert_eq!(
            ranked[0].candidate.nf_instance_id, single.candidate.nf_instance_id,
            "the ranked head must BE the single pick, or reselection would start \
             somewhere other than where selection did"
        );
        let order: Vec<&str> = ranked
            .iter()
            .map(|e| e.candidate.nf_instance_id.as_str())
            .collect();
        assert_eq!(order, vec!["udm-b", "udm-a", "udm-c"]);
        // Each entry still carries its own matched endpoint.
        assert_eq!(ranked[0].port, 1002);
        assert_eq!(ranked[1].port, 1001);
        assert_eq!(ranked[2].port, 1003);
    }

    /// scpd-#209: an unhealthy instance is **not** offered as an alternate while a
    /// healthy one exists, mirroring `select_best`'s pool rule. A `SUSPENDED` NF
    /// must not be selected (TS 29.510), so failing over onto one would trade a
    /// reachability problem for a conformance one — the ranked list therefore
    /// stops at the healthy set rather than appending the rest as a last resort.
    #[test]
    fn test_ranked_endpoints_exclude_unhealthy_while_a_healthy_one_exists() {
        let mixed = serde_json::to_vec(&serde_json::json!({
            "nfInstances": [
                {
                    "nfInstanceId": "udm-suspended",
                    "nfType": "UDM", "nfStatus": "SUSPENDED",
                    "ipv4Addresses": ["10.0.0.30"],
                    "priority": 1,
                    "nfServices": [{"serviceName": "nudm-uecm",
                                    "ipEndPoints": [{"port": 2001}]}]
                },
                {
                    "nfInstanceId": "udm-registered",
                    "nfType": "UDM", "nfStatus": "REGISTERED",
                    "ipv4Addresses": ["10.0.0.31"],
                    "priority": 50,
                    "nfServices": [{"serviceName": "nudm-uecm",
                                    "ipEndPoints": [{"port": 2002}]}]
                }
            ]
        }))
        .unwrap();
        let candidates = parse_search_result(&mixed);
        let ranked =
            rank_nf_service_endpoints(&candidates, Some("nudm-uecm"), Some("v1")).expect("ranked");
        assert_eq!(
            ranked.len(),
            1,
            "the SUSPENDED instance is not an alternate"
        );
        assert_eq!(ranked[0].candidate.nf_instance_id, "udm-registered");
    }

    /// scpd-#207: an unhealthy instance is still skipped inside the matching set,
    /// so the version/name filter does not defeat the health filter.
    #[test]
    fn test_select_endpoint_still_skips_unhealthy_within_the_match() {
        let mixed = serde_json::to_vec(&serde_json::json!({
            "nfInstances": [
                {
                    "nfInstanceId": "udm-down",
                    "nfType": "UDM",
                    "nfStatus": "SUSPENDED",
                    "ipv4Addresses": ["10.0.0.14"],
                    "priority": 1,
                    "nfServices": [{
                        "serviceName": "nudm-uecm",
                        "ipEndPoints": [{"port": 3333}]
                    }]
                },
                {
                    "nfInstanceId": "udm-up",
                    "nfType": "UDM",
                    "nfStatus": "REGISTERED",
                    "ipv4Addresses": ["10.0.0.15"],
                    "priority": 50,
                    "nfServices": [{
                        "serviceName": "nudm-uecm",
                        "ipEndPoints": [{"port": 4444}]
                    }]
                }
            ]
        }))
        .unwrap();
        let candidates = parse_search_result(&mixed);
        let selected = select_nf_service_endpoint(&candidates, Some("nudm-uecm"), Some("v1"))
            .expect("healthy");
        assert_eq!(selected.candidate.nf_instance_id, "udm-up");
        assert_eq!(selected.port, 4444);
    }
}
