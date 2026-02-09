//! SBI Context Management
//!
//! Context management for SBI operations, including NF instance management
//! and service discovery context.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::client::{SbiClient, SbiClientConfig};
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

/// NF Instance information - matches ogs_sbi_nf_instance_t
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
        self.services.iter().find(|s| s.service_type == service_type)
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

/// SBI Context - manages NF instances and clients
pub struct SbiContext {
    /// Self NF instance
    self_instance: RwLock<Option<NfInstance>>,
    /// Discovered NF instances by ID
    nf_instances: RwLock<HashMap<String, NfInstance>>,
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

    /// Add an NF instance
    pub async fn add_nf_instance(&self, instance: NfInstance) {
        let mut instances = self.nf_instances.write().await;
        instances.insert(instance.id.clone(), instance);
    }

    /// Remove an NF instance
    pub async fn remove_nf_instance(&self, id: &str) -> Option<NfInstance> {
        let mut instances = self.nf_instances.write().await;
        instances.remove(id)
    }

    /// Get an NF instance by ID
    pub async fn get_nf_instance(&self, id: &str) -> Option<NfInstance> {
        let instances = self.nf_instances.read().await;
        instances.get(id).cloned()
    }

    /// Find NF instances by type
    pub async fn find_nf_instances_by_type(&self, nf_type: NfType) -> Vec<NfInstance> {
        let instances = self.nf_instances.read().await;
        instances
            .values()
            .filter(|i| i.nf_type == nf_type)
            .cloned()
            .collect()
    }

    /// Find NF instances by service type
    pub async fn find_nf_instances_by_service(
        &self,
        service_type: SbiServiceType,
    ) -> Vec<NfInstance> {
        let instances = self.nf_instances.read().await;
        instances
            .values()
            .filter(|i| i.services.iter().any(|s| s.service_type == service_type))
            .cloned()
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
        let config = SbiClientConfig::new(host, port);
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

    /// Get the number of NF instances
    pub async fn nf_instance_count(&self) -> usize {
        let instances = self.nf_instances.read().await;
        instances.len()
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
        
        ctx.add_nf_instance(NfInstance::new("amf-1", NfType::Amf)).await;
        ctx.add_nf_instance(NfInstance::new("smf-1", NfType::Smf)).await;
        ctx.add_nf_instance(NfInstance::new("amf-2", NfType::Amf)).await;
        
        let amfs = ctx.find_nf_instances_by_type(NfType::Amf).await;
        assert_eq!(amfs.len(), 2);
    }
}
