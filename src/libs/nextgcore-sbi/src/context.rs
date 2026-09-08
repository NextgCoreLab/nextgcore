//! SBI Context Management
//!
//! Context management for SBI operations, including NF instance management
//! and service discovery context.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::client::SbiClient;
use crate::message::{PlmnId, SNssai};
use crate::types::{NfType, SbiServiceType, UriScheme};

/// NF Service information
#[derive(Debug, Clone)]
pub struct NfService {
    /// Service name
    pub name: String,
    /// Service type
    pub service_type: SbiServiceType,
    /// API versions supported
    pub versions: Vec<String>,
    /// Service URI scheme
    pub scheme: UriScheme,
    /// Service FQDN
    pub fqdn: Option<String>,
    /// Service IP addresses
    pub ip_addresses: Vec<String>,
    /// Service port
    pub port: u16,
}

impl NfService {
    pub fn new(name: impl Into<String>, service_type: SbiServiceType) -> Self {
        Self {
            name: name.into(),
            service_type,
            versions: vec!["v1".to_string()],
            scheme: UriScheme::Http,
            fqdn: None,
            ip_addresses: Vec::new(),
            port: 80,
        }
    }
}

/// NF Instance information - matches nextgcore_sbi_nf_instance_t
#[derive(Debug, Clone)]
pub struct NfInstance {
    /// NF Instance ID (UUID)
    pub id: String,
    /// NF Type
    pub nf_type: NfType,
    /// NF Status
    pub nf_status: NfStatus,
    /// FQDN
    pub fqdn: Option<String>,
    /// IPv4 addresses
    pub ipv4_addresses: Vec<String>,
    /// IPv6 addresses
    pub ipv6_addresses: Vec<String>,
    /// PLMN list
    pub plmn_list: Vec<PlmnId>,
    /// S-NSSAI list
    pub s_nssai_list: Vec<SNssai>,
    /// Services provided
    pub services: Vec<NfService>,
    /// Heartbeat timer interval (seconds)
    pub heartbeat_interval: u32,
    /// Load percentage (0-100)
    pub load: u8,
    /// Priority
    pub priority: u16,
    /// Capacity
    pub capacity: u16,
}

impl NfInstance {
    pub fn new(id: impl Into<String>, nf_type: NfType) -> Self {
        Self {
            id: id.into(),
            nf_type,
            nf_status: NfStatus::Registered,
            fqdn: None,
            ipv4_addresses: Vec::new(),
            ipv6_addresses: Vec::new(),
            plmn_list: Vec::new(),
            s_nssai_list: Vec::new(),
            services: Vec::new(),
            heartbeat_interval: 10,
            load: 0,
            priority: 0,
            capacity: 100,
        }
    }

    /// Add a service to this NF instance
    pub fn add_service(&mut self, service: NfService) {
        self.services.push(service);
    }

    /// Find a service by type
    pub fn find_service(&self, service_type: SbiServiceType) -> Option<&NfService> {
        self.services
            .iter()
            .find(|s| s.service_type == service_type)
    }
}

/// NF Status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfStatus {
    Registered,
    Suspended,
    Undiscoverable,
}

/// Subscription information for NF status notifications
#[derive(Debug, Clone)]
pub struct NfSubscription {
    /// Subscription ID
    pub id: String,
    /// Callback URI for notifications
    pub callback_uri: String,
    /// NF type to subscribe to
    pub nf_type: Option<NfType>,
    /// Service names to subscribe to
    pub service_names: Vec<String>,
    /// Validity time (seconds from now)
    pub validity_time: Option<u64>,
}

/// A discovered NF instance plus the deadline after which it must not be
/// selected again (#235).
///
/// The deadline is a monotonic [`Instant`], not a wall-clock time, so a clock
/// step cannot make a live entry look expired or vice versa.
#[derive(Debug, Clone)]
struct CachedNfInstance {
    instance: NfInstance,
    /// `None` means "never expires" — the state every entry was in before #235,
    /// and still what [`SbiContext::add_nf_instance`] produces.
    expires_at: Option<Instant>,
}

impl CachedNfInstance {
    /// Whether this entry is past its validity deadline.
    ///
    /// A zero validity expires immediately and deterministically, which is what
    /// lets the expiry tests run without sleeping.
    fn is_expired(&self) -> bool {
        self.expires_at
            .is_some_and(|deadline| Instant::now() >= deadline)
    }
}

/// Cache validity applied to a discovered NF profile when the NRF's
/// `SearchResult` omits `validityPeriod` (#235).
///
/// 3600s, matching `nrfd`'s own `NRF_DISC_VALIDITY_PERIOD` default. The point of
/// having a fallback at all is that a *foreign* NRF which omits the member must
/// not mean "cache this peer forever" — an hour is a bound, not a guess at what
/// that NRF intended.
pub const DEFAULT_NF_DISCOVERY_VALIDITY_SECS: u64 = 3600;

/// Read a discovery `SearchResult`'s `validityPeriod` (seconds, TS 29.510
/// §6.1.6.2.x) as a cache TTL, falling back to
/// [`DEFAULT_NF_DISCOVERY_VALIDITY_SECS`].
///
/// A `validityPeriod` of `0` is honoured as zero rather than coerced to the
/// default: an NRF saying "do not cache this" is a legitimate instruction, and
/// silently replacing it with an hour would be the lower-layer-can-never-win
/// mistake.
pub fn search_result_validity(search_result: &serde_json::Value) -> Duration {
    match search_result.get("validityPeriod").and_then(|v| v.as_u64()) {
        Some(secs) => Duration::from_secs(secs),
        None => Duration::from_secs(DEFAULT_NF_DISCOVERY_VALIDITY_SECS),
    }
}

/// SBI Context - manages NF instances and clients
pub struct SbiContext {
    /// Self NF instance
    self_instance: RwLock<Option<NfInstance>>,
    /// Discovered NF instances by ID, each with its validity deadline (#235)
    nf_instances: RwLock<HashMap<String, CachedNfInstance>>,
    /// Clients by endpoint
    clients: RwLock<HashMap<String, Arc<SbiClient>>>,
    /// Subscriptions
    subscriptions: RwLock<HashMap<String, NfSubscription>>,
    /// NRF URI
    nrf_uri: RwLock<Option<String>>,
}

impl SbiContext {
    /// Create a new SBI context
    pub fn new() -> Self {
        Self {
            self_instance: RwLock::new(None),
            nf_instances: RwLock::new(HashMap::new()),
            clients: RwLock::new(HashMap::new()),
            subscriptions: RwLock::new(HashMap::new()),
            nrf_uri: RwLock::new(None),
        }
    }

    /// Set the self NF instance
    pub async fn set_self_instance(&self, instance: NfInstance) {
        let mut self_instance = self.self_instance.write().await;
        *self_instance = Some(instance);
    }

    /// Get the self NF instance
    pub async fn get_self_instance(&self) -> Option<NfInstance> {
        let self_instance = self.self_instance.read().await;
        self_instance.clone()
    }

    /// Set the NRF URI
    pub async fn set_nrf_uri(&self, uri: impl Into<String>) {
        let mut nrf_uri = self.nrf_uri.write().await;
        *nrf_uri = Some(uri.into());
    }

    /// Get the NRF URI
    pub async fn get_nrf_uri(&self) -> Option<String> {
        let nrf_uri = self.nrf_uri.read().await;
        nrf_uri.clone()
    }

    /// Add an NF instance that **never expires**.
    ///
    /// This is the pre-#235 behaviour, kept for callers that seed the registry
    /// by hand (tests, and the strict-peer harnesses that stand in for a real
    /// NRF). A production discovery path should use
    /// [`Self::add_nf_instance_with_validity`] instead: an entry added here is
    /// selected for the whole process lifetime, which is exactly the permanent
    /// staleness #235 was filed about.
    pub async fn add_nf_instance(&self, instance: NfInstance) {
        let mut instances = self.nf_instances.write().await;
        instances.insert(
            instance.id.clone(),
            CachedNfInstance {
                instance,
                expires_at: None,
            },
        );
    }

    /// Add a discovered NF instance that stops being selectable after
    /// `validity` (#235, TS 29.510 §6.1.6.2.x `validityPeriod`).
    ///
    /// Once the deadline passes, the reads below behave as if the entry were
    /// absent, so the caller's "not in cache -> discover" branch runs again and
    /// picks up whatever the NRF says now. A `validity` of zero expires the
    /// entry immediately, which is the lever the tests use.
    pub async fn add_nf_instance_with_validity(&self, instance: NfInstance, validity: Duration) {
        let mut instances = self.nf_instances.write().await;
        instances.insert(
            instance.id.clone(),
            CachedNfInstance {
                instance,
                expires_at: Some(Instant::now() + validity),
            },
        );
    }

    /// Remove an NF instance
    pub async fn remove_nf_instance(&self, id: &str) -> Option<NfInstance> {
        let mut instances = self.nf_instances.write().await;
        instances.remove(id).map(|cached| cached.instance)
    }

    /// Evict a cached NF instance because sending to it failed (#235).
    ///
    /// Returns whether an entry was actually removed, so a caller can log the
    /// difference between "we dropped the stale peer" and "someone else already
    /// had". Separate from [`Self::remove_nf_instance`] so the *reason* is
    /// legible at the call site: a delivery failure is evidence the profile is
    /// wrong, and the next request should re-discover rather than retry an
    /// endpoint the NRF may already have replaced.
    pub async fn evict_nf_instance_on_failure(&self, id: &str) -> bool {
        let removed = {
            let mut instances = self.nf_instances.write().await;
            instances.remove(id).is_some()
        };
        if removed {
            log::info!(
                "Evicted NF instance {id} from the discovery cache after a delivery failure"
            );
        }
        removed
    }

    /// Drop every entry past its validity deadline, returning how many went.
    ///
    /// The reads below already ignore expired entries, so this is bookkeeping
    /// rather than correctness — it stops a long-lived consumer accumulating
    /// dead profiles it will never look at.
    pub async fn purge_expired_nf_instances(&self) -> usize {
        let mut instances = self.nf_instances.write().await;
        let before = instances.len();
        instances.retain(|_, cached| !cached.is_expired());
        before - instances.len()
    }

    /// Get an NF instance by ID, or `None` if it is absent **or expired**.
    pub async fn get_nf_instance(&self, id: &str) -> Option<NfInstance> {
        let instances = self.nf_instances.read().await;
        instances
            .get(id)
            .filter(|cached| !cached.is_expired())
            .map(|cached| cached.instance.clone())
    }

    /// Find non-expired NF instances by type
    pub async fn find_nf_instances_by_type(&self, nf_type: NfType) -> Vec<NfInstance> {
        let instances = self.nf_instances.read().await;
        instances
            .values()
            .filter(|cached| !cached.is_expired() && cached.instance.nf_type == nf_type)
            .map(|cached| cached.instance.clone())
            .collect()
    }

    /// Find non-expired NF instances by service type
    pub async fn find_nf_instances_by_service(
        &self,
        service_type: SbiServiceType,
    ) -> Vec<NfInstance> {
        let instances = self.nf_instances.read().await;
        instances
            .values()
            .filter(|cached| {
                !cached.is_expired()
                    && cached
                        .instance
                        .services
                        .iter()
                        .any(|s| s.service_type == service_type)
            })
            .map(|cached| cached.instance.clone())
            .collect()
    }

    /// Get or create a client for the given endpoint
    pub async fn get_client(&self, host: &str, port: u16) -> Arc<SbiClient> {
        let key = format!("{host}:{port}");

        // Check if client exists
        {
            let clients = self.clients.read().await;
            if let Some(client) = clients.get(&key) {
                return client.clone();
            }
        }

        // Create new client
        // Issue #63: this cache hands out clients for dialling PEER NFs, so it
        // must honour the SBI security profile. Left cleartext it would silently
        // undo the outbound half for every NF that resolves peers through it.
        let config = crate::security::sbi_peer_client_config(host, port);
        let client = Arc::new(SbiClient::new(config));

        let mut clients = self.clients.write().await;
        clients.insert(key, client.clone());

        client
    }

    /// Add a subscription
    pub async fn add_subscription(&self, subscription: NfSubscription) {
        let mut subscriptions = self.subscriptions.write().await;
        subscriptions.insert(subscription.id.clone(), subscription);
    }

    /// Remove a subscription
    pub async fn remove_subscription(&self, id: &str) -> Option<NfSubscription> {
        let mut subscriptions = self.subscriptions.write().await;
        subscriptions.remove(id)
    }

    /// Get a subscription by ID
    pub async fn get_subscription(&self, id: &str) -> Option<NfSubscription> {
        let subscriptions = self.subscriptions.read().await;
        subscriptions.get(id).cloned()
    }

    /// Clear all NF instances
    pub async fn clear_nf_instances(&self) {
        let mut instances = self.nf_instances.write().await;
        instances.clear();
    }

    /// Clear all clients
    pub async fn clear_clients(&self) {
        let mut clients = self.clients.write().await;
        clients.clear();
    }

    /// Get the number of **selectable** NF instances.
    ///
    /// Counts what the reads above would return, so it cannot report a peer that
    /// `find_nf_instances_by_type` has already stopped handing out.
    pub async fn nf_instance_count(&self) -> usize {
        let instances = self.nf_instances.read().await;
        instances
            .values()
            .filter(|cached| !cached.is_expired())
            .count()
    }
}

impl Default for SbiContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Global SBI context (thread-safe singleton pattern)
static GLOBAL_CONTEXT: std::sync::OnceLock<Arc<SbiContext>> = std::sync::OnceLock::new();

/// Get the global SBI context
pub fn global_context() -> Arc<SbiContext> {
    GLOBAL_CONTEXT
        .get_or_init(|| Arc::new(SbiContext::new()))
        .clone()
}

impl SbiContext {
    /// Create a fresh, independent `SbiContext` that is **not** the global
    /// singleton.
    ///
    /// Use this in tests to obtain a context whose NF-instance registry and
    /// discovery table are fully isolated from other tests and from the
    /// production singleton.
    ///
    /// # Example
    /// ```
    /// # use nextgcore_sbi::context::SbiContext;
    /// let ctx = SbiContext::new_isolated();
    /// // ctx is independent — changes here never affect global_context()
    /// ```
    pub fn new_isolated() -> Arc<SbiContext> {
        Arc::new(SbiContext::new())
    }
}

/// Reset the global SBI context to an empty state.
///
/// **Only for use in tests.** Because `OnceLock` cannot be replaced on stable
/// Rust, this clears the contents of the already-initialised singleton through
/// its internal `RwLock`s rather than re-creating the lock.  Call this in
/// `#[cfg(test)]` teardown so that NF instances and clients registered during
/// one test do not bleed into subsequent ones.
///
/// Note: if the global singleton has not been initialised yet this is a no-op.
#[cfg(any(test, feature = "test-helpers"))]
pub async fn global_context_reset() {
    if let Some(ctx) = GLOBAL_CONTEXT.get() {
        ctx.clear_nf_instances().await;
        ctx.clear_clients().await;
        {
            let mut subscriptions = ctx.subscriptions.write().await;
            subscriptions.clear();
        }
        {
            let mut self_instance = ctx.self_instance.write().await;
            *self_instance = None;
        }
        {
            let mut nrf_uri = ctx.nrf_uri.write().await;
            *nrf_uri = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nf_instance() {
        let mut instance = NfInstance::new("test-id", NfType::Amf);
        instance.add_service(NfService::new("namf-comm", SbiServiceType::NamfComm));

        assert_eq!(instance.id, "test-id");
        assert_eq!(instance.nf_type, NfType::Amf);
        assert!(instance.find_service(SbiServiceType::NamfComm).is_some());
    }

    #[tokio::test]
    async fn test_sbi_context() {
        let ctx = SbiContext::new();

        let instance = NfInstance::new("nf-1", NfType::Smf);
        ctx.add_nf_instance(instance).await;

        assert_eq!(ctx.nf_instance_count().await, 1);

        let found = ctx.get_nf_instance("nf-1").await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().nf_type, NfType::Smf);
    }

    #[tokio::test]
    async fn test_find_by_type() {
        let ctx = SbiContext::new();

        ctx.add_nf_instance(NfInstance::new("amf-1", NfType::Amf))
            .await;
        ctx.add_nf_instance(NfInstance::new("smf-1", NfType::Smf))
            .await;
        ctx.add_nf_instance(NfInstance::new("amf-2", NfType::Amf))
            .await;

        let amfs = ctx.find_nf_instances_by_type(NfType::Amf).await;
        assert_eq!(amfs.len(), 2);
    }

    // ─── #235: discovery-cache validity ──────────────────────────────────────

    /// An entry past its validity must read as ABSENT on every path, not merely
    /// be flagged — the caller's "not in cache -> discover" branch is what
    /// re-discovery hangs off, so anything that still returns the instance keeps
    /// the consumer pointed at a dead endpoint.
    ///
    /// `Duration::ZERO` expires immediately, so this is deterministic without
    /// sleeping.
    #[tokio::test]
    async fn expired_instance_reads_as_a_cache_miss_on_every_path() {
        let ctx = SbiContext::new();

        let mut instance = NfInstance::new("udr-stale", NfType::Udr);
        instance.add_service(NfService::new("nudr-dr", SbiServiceType::NudrDr));
        ctx.add_nf_instance_with_validity(instance, Duration::ZERO)
            .await;

        assert!(
            ctx.get_nf_instance("udr-stale").await.is_none(),
            "get_nf_instance must not return an expired profile"
        );
        assert!(
            ctx.find_nf_instances_by_type(NfType::Udr).await.is_empty(),
            "find_nf_instances_by_type must not return an expired profile"
        );
        assert!(
            ctx.find_nf_instances_by_service(SbiServiceType::NudrDr)
                .await
                .is_empty(),
            "find_nf_instances_by_service must not return an expired profile"
        );
        assert_eq!(
            ctx.nf_instance_count().await,
            0,
            "the count must agree with what the reads hand out"
        );
    }

    /// The complement: a validity that has not elapsed leaves the entry usable,
    /// so the expiry check cannot be passing the test above by rejecting
    /// everything.
    #[tokio::test]
    async fn instance_within_its_validity_stays_selectable() {
        let ctx = SbiContext::new();

        let mut instance = NfInstance::new("udr-live", NfType::Udr);
        instance.add_service(NfService::new("nudr-dr", SbiServiceType::NudrDr));
        ctx.add_nf_instance_with_validity(instance, Duration::from_secs(3600))
            .await;

        assert!(ctx.get_nf_instance("udr-live").await.is_some());
        assert_eq!(ctx.find_nf_instances_by_type(NfType::Udr).await.len(), 1);
        assert_eq!(
            ctx.find_nf_instances_by_service(SbiServiceType::NudrDr)
                .await
                .len(),
            1
        );
        assert_eq!(ctx.nf_instance_count().await, 1);
    }

    /// `add_nf_instance` deliberately opts out of expiry, so the strict-peer
    /// harnesses that seed the registry by hand keep working. Pinned as a test
    /// because it is a behaviour difference between two adjacent methods, and the
    /// kind of thing a later reader would "tidy" into consistency.
    #[tokio::test]
    async fn add_without_validity_never_expires() {
        let ctx = SbiContext::new();
        ctx.add_nf_instance(NfInstance::new("udr-forever", NfType::Udr))
            .await;

        assert!(ctx.get_nf_instance("udr-forever").await.is_some());
        assert_eq!(
            ctx.purge_expired_nf_instances().await,
            0,
            "an entry with no deadline is never purged"
        );
        assert!(ctx.get_nf_instance("udr-forever").await.is_some());
    }

    /// Purging drops expired entries and leaves live ones, and reports the count
    /// it dropped.
    #[tokio::test]
    async fn purge_expired_drops_only_the_expired() {
        let ctx = SbiContext::new();

        ctx.add_nf_instance_with_validity(NfInstance::new("gone-1", NfType::Udr), Duration::ZERO)
            .await;
        ctx.add_nf_instance_with_validity(NfInstance::new("gone-2", NfType::Ausf), Duration::ZERO)
            .await;
        ctx.add_nf_instance_with_validity(
            NfInstance::new("kept", NfType::Udm),
            Duration::from_secs(3600),
        )
        .await;

        assert_eq!(ctx.purge_expired_nf_instances().await, 2);
        assert!(ctx.get_nf_instance("kept").await.is_some());
        assert_eq!(ctx.purge_expired_nf_instances().await, 0);
    }

    /// A delivery failure evicts the entry, and the return value distinguishes
    /// "we dropped it" from "it was already gone" — which is what lets a caller
    /// log the difference instead of claiming an eviction it did not perform.
    #[tokio::test]
    async fn eviction_on_failure_removes_the_entry_and_reports_whether_it_did() {
        let ctx = SbiContext::new();
        ctx.add_nf_instance_with_validity(
            NfInstance::new("udr-dead", NfType::Udr),
            Duration::from_secs(3600),
        )
        .await;

        assert!(
            ctx.evict_nf_instance_on_failure("udr-dead").await,
            "the first eviction removed a live entry"
        );
        assert!(ctx.get_nf_instance("udr-dead").await.is_none());
        assert!(
            !ctx.evict_nf_instance_on_failure("udr-dead").await,
            "a second eviction must report that there was nothing to remove"
        );
        assert!(
            !ctx.evict_nf_instance_on_failure("never-cached").await,
            "evicting an unknown id must not claim a removal"
        );
    }

    /// `validityPeriod` drives the TTL; a MISSING member falls back to the
    /// bounded default; and an explicit `0` is honoured as zero rather than
    /// coerced to the default, because an NRF saying "do not cache this" is an
    /// instruction, not an omission.
    #[test]
    fn search_result_validity_reads_the_member_and_honours_zero() {
        assert_eq!(
            search_result_validity(&serde_json::json!({"validityPeriod": 120})),
            Duration::from_secs(120)
        );
        assert_eq!(
            search_result_validity(&serde_json::json!({"validityPeriod": 0})),
            Duration::ZERO
        );
        assert_eq!(
            search_result_validity(&serde_json::json!({"nfInstances": []})),
            Duration::from_secs(DEFAULT_NF_DISCOVERY_VALIDITY_SECS)
        );
        // A non-numeric value is not a validity; fall back rather than panic.
        assert_eq!(
            search_result_validity(&serde_json::json!({"validityPeriod": "3600"})),
            Duration::from_secs(DEFAULT_NF_DISCOVERY_VALIDITY_SECS)
        );
    }
}
