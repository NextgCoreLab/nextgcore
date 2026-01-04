//! NRF Handler Implementation
//!
//! Port of src/nrf/nnrf-handler.c - Handlers for NF management and discovery

use crate::nf_sm::{nrf_nf_fsm_fini, nrf_nf_fsm_init, NfSmContext, NfState};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// NF Profile data structure
#[derive(Debug, Clone)]
pub struct NfProfile {
    /// NF Instance ID
    pub nf_instance_id: String,
    /// NF Type
    pub nf_type: String,
    /// NF Status
    pub nf_status: String,
    /// Heartbeat timer (seconds)
    pub heartbeat_timer: Option<u32>,
    /// PLMN list
    pub plmn_list: Vec<PlmnId>,
    /// IPv4 addresses
    pub ipv4_addresses: Vec<String>,
    /// IPv6 addresses
    pub ipv6_addresses: Vec<String>,
    /// FQDN
    pub fqdn: Option<String>,
    /// NF services
    pub nf_services: Vec<NfService>,
}

/// PLMN ID
#[derive(Debug, Clone)]
pub struct PlmnId {
    pub mcc: String,
    pub mnc: String,
}

/// NF Service
#[derive(Debug, Clone)]
pub struct NfService {
    pub service_instance_id: String,
    pub service_name: String,
    pub versions: Vec<String>,
    pub scheme: String,
    pub fqdn: Option<String>,
    pub ip_endpoints: Vec<IpEndpoint>,
}

/// IP Endpoint
#[derive(Debug, Clone)]
pub struct IpEndpoint {
    pub ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
    pub port: u16,
}

/// Subscription data
#[derive(Debug, Clone)]
pub struct SubscriptionData {
    /// Subscription ID
    pub id: String,
    /// Requester NF type
    pub req_nf_type: Option<String>,
    /// Requester NF instance ID
    pub req_nf_instance_id: Option<String>,
    /// Notification URI
    pub notification_uri: String,
    /// Subscription condition
    pub subscr_cond: Option<SubscrCond>,
    /// Validity duration (seconds)
    pub validity_duration: u64,
}

/// Subscription condition
#[derive(Debug, Clone)]
pub struct SubscrCond {
    /// NF type condition
    pub nf_type: Option<String>,
    /// Service name condition
    pub service_name: Option<String>,
    /// NF instance ID condition
    pub nf_instance_id: Option<String>,
}

/// Search result for NF discovery
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// Validity period (seconds)
    pub validity_period: u32,
    /// NF instances found
    pub nf_instances: Vec<NfProfile>,
    /// Number of NF instances complete
    pub num_nf_inst_complete: Option<u32>,
}

/// Handler result
#[derive(Debug)]
pub enum HandlerResult {
    /// Success with HTTP status code
    Success(u16),
    /// Error with HTTP status code and message
    Error(u16, String),
}

/// NF Instance manager
pub struct NfInstanceManager {
    /// NF instances by ID
    instances: RwLock<HashMap<String, NfSmContext>>,
    /// Subscriptions by ID
    subscriptions: RwLock<HashMap<String, SubscriptionData>>,
}

impl NfInstanceManager {
    /// Create a new NF instance manager
    pub fn new() -> Self {
        Self {
            instances: RwLock::new(HashMap::new()),
            subscriptions: RwLock::new(HashMap::new()),
        }
    }

    /// Find an NF instance by ID
    pub fn find_instance(&self, id: &str) -> Option<NfState> {
        let instances = self.instances.read().ok()?;
        instances.get(id).map(|ctx| ctx.state())
    }

    /// Add a new NF instance
    pub fn add_instance(&self, id: String) -> bool {
        if let Ok(mut instances) = self.instances.write() {
            if instances.contains_key(&id) {
                return false;
            }
            let mut ctx = NfSmContext::new(id.clone());
            nrf_nf_fsm_init(&mut ctx);
            instances.insert(id, ctx);
            true
        } else {
            false
        }
    }

    /// Remove an NF instance
    pub fn remove_instance(&self, id: &str) -> bool {
        if let Ok(mut instances) = self.instances.write() {
            if let Some(mut ctx) = instances.remove(id) {
                nrf_nf_fsm_fini(&mut ctx);
                return true;
            }
        }
        false
    }

    /// Get instance count
    pub fn instance_count(&self) -> usize {
        self.instances.read().map(|i| i.len()).unwrap_or(0)
    }

    /// Add a subscription
    pub fn add_subscription(&self, subscription: SubscriptionData) -> bool {
        if let Ok(mut subscriptions) = self.subscriptions.write() {
            subscriptions.insert(subscription.id.clone(), subscription);
            true
        } else {
            false
        }
    }

    /// Find a subscription by ID
    pub fn find_subscription(&self, id: &str) -> Option<SubscriptionData> {
        let subscriptions = self.subscriptions.read().ok()?;
        subscriptions.get(id).cloned()
    }

    /// Remove a subscription
    pub fn remove_subscription(&self, id: &str) -> bool {
        if let Ok(mut subscriptions) = self.subscriptions.write() {
            subscriptions.remove(id).is_some()
        } else {
            false
        }
    }

    /// Get subscription count
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.read().map(|s| s.len()).unwrap_or(0)
    }
}

impl Default for NfInstanceManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Global NF instance manager
static GLOBAL_NF_MANAGER: std::sync::OnceLock<Arc<NfInstanceManager>> = std::sync::OnceLock::new();

/// Get the global NF instance manager
pub fn nf_manager() -> Arc<NfInstanceManager> {
    GLOBAL_NF_MANAGER
        .get_or_init(|| Arc::new(NfInstanceManager::new()))
        .clone()
}

/// Handle NF registration (PUT /nf-instances/{nfInstanceId})
pub fn nrf_nnrf_handle_nf_register(
    nf_instance_id: &str,
    profile: &NfProfile,
) -> HandlerResult {
    log::info!("[{}] NF registration request", nf_instance_id);

    // Validate profile
    if profile.nf_instance_id.is_empty() {
        return HandlerResult::Error(400, "No NFProfile.NFInstanceId".to_string());
    }

    if profile.nf_type.is_empty() {
        return HandlerResult::Error(400, "No NFProfile.NFType".to_string());
    }

    if profile.nf_status.is_empty() {
        return HandlerResult::Error(400, "No NFProfile.NFStatus".to_string());
    }

    // Add NF instance
    let manager = nf_manager();
    let is_new = manager.add_instance(nf_instance_id.to_string());

    if is_new {
        log::info!("[{}] NF registered (new)", nf_instance_id);
        HandlerResult::Success(201) // Created
    } else {
        log::info!("[{}] NF registered (updated)", nf_instance_id);
        HandlerResult::Success(200) // OK
    }
}

/// Handle NF update (PATCH /nf-instances/{nfInstanceId})
pub fn nrf_nnrf_handle_nf_update(
    nf_instance_id: &str,
    _patch_items: &[PatchItem],
) -> HandlerResult {
    log::debug!("[{}] NF update request", nf_instance_id);

    let manager = nf_manager();
    if manager.find_instance(nf_instance_id).is_none() {
        return HandlerResult::Error(404, "NF instance not found".to_string());
    }

    // TODO: Apply patch items

    HandlerResult::Success(204) // No Content
}

/// Patch item for NF update
#[derive(Debug, Clone)]
pub struct PatchItem {
    pub op: String,
    pub path: String,
    pub value: Option<String>,
}

/// Handle NF status subscribe (POST /subscriptions)
pub fn nrf_nnrf_handle_nf_status_subscribe(
    subscription: SubscriptionData,
) -> HandlerResult {
    log::info!("[{}] NF status subscribe request", subscription.id);

    // Validate subscription
    if subscription.notification_uri.is_empty() {
        return HandlerResult::Error(400, "No nfStatusNotificationUri".to_string());
    }

    if subscription.subscr_cond.is_none() {
        return HandlerResult::Error(400, "No SubscrCond".to_string());
    }

    let manager = nf_manager();
    manager.add_subscription(subscription);

    HandlerResult::Success(201) // Created
}

/// Handle NF status update (PATCH /subscriptions/{subscriptionId})
pub fn nrf_nnrf_handle_nf_status_update(
    subscription_id: &str,
    _validity_time: Option<&str>,
) -> HandlerResult {
    log::debug!("[{}] NF status update request", subscription_id);

    let manager = nf_manager();
    if manager.find_subscription(subscription_id).is_none() {
        return HandlerResult::Error(404, "Subscription not found".to_string());
    }

    // TODO: Update validity time

    HandlerResult::Success(204) // No Content
}

/// Handle NF status unsubscribe (DELETE /subscriptions/{subscriptionId})
pub fn nrf_nnrf_handle_nf_status_unsubscribe(subscription_id: &str) -> HandlerResult {
    log::info!("[{}] NF status unsubscribe request", subscription_id);

    let manager = nf_manager();
    if manager.remove_subscription(subscription_id) {
        HandlerResult::Success(204) // No Content
    } else {
        HandlerResult::Error(404, "Subscription not found".to_string())
    }
}

/// Handle NF list retrieval (GET /nf-instances)
pub fn nrf_nnrf_handle_nf_list_retrieval(
    nf_type: Option<&str>,
    limit: Option<u32>,
) -> HandlerResult {
    log::debug!("NF list retrieval request (type={:?}, limit={:?})", nf_type, limit);

    // TODO: Return list of NF instance URIs

    HandlerResult::Success(200)
}

/// Handle NF profile retrieval (GET /nf-instances/{nfInstanceId})
pub fn nrf_nnrf_handle_nf_profile_retrieval(nf_instance_id: &str) -> HandlerResult {
    log::debug!("[{}] NF profile retrieval request", nf_instance_id);

    let manager = nf_manager();
    if manager.find_instance(nf_instance_id).is_none() {
        return HandlerResult::Error(404, "NF instance not found".to_string());
    }

    // TODO: Return NF profile

    HandlerResult::Success(200)
}

/// Handle NF discover (GET /nf-instances for discovery)
pub fn nrf_nnrf_handle_nf_discover(
    target_nf_type: &str,
    requester_nf_type: &str,
    _discovery_options: Option<&DiscoveryOptions>,
) -> HandlerResult {
    log::debug!(
        "NF discover request (target={}, requester={})",
        target_nf_type,
        requester_nf_type
    );

    if target_nf_type.is_empty() {
        return HandlerResult::Error(400, "No target-nf-type".to_string());
    }

    if requester_nf_type.is_empty() {
        return HandlerResult::Error(400, "No requester-nf-type".to_string());
    }

    // TODO: Search for matching NF instances

    HandlerResult::Success(200)
}

/// Discovery options
#[derive(Debug, Clone, Default)]
pub struct DiscoveryOptions {
    pub target_nf_instance_id: Option<String>,
    pub requester_nf_instance_id: Option<String>,
    pub service_names: Vec<String>,
    pub snssais: Vec<Snssai>,
    pub dnn: Option<String>,
    pub limit: Option<u32>,
}

/// S-NSSAI (Single Network Slice Selection Assistance Information)
#[derive(Debug, Clone)]
pub struct Snssai {
    pub sst: u8,
    pub sd: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nf_instance_manager_new() {
        let manager = NfInstanceManager::new();
        assert_eq!(manager.instance_count(), 0);
        assert_eq!(manager.subscription_count(), 0);
    }

    #[test]
    fn test_nf_instance_add_remove() {
        let manager = NfInstanceManager::new();

        assert!(manager.add_instance("nf-1".to_string()));
        assert_eq!(manager.instance_count(), 1);

        // Adding same instance should fail
        assert!(!manager.add_instance("nf-1".to_string()));
        assert_eq!(manager.instance_count(), 1);

        assert!(manager.remove_instance("nf-1"));
        assert_eq!(manager.instance_count(), 0);
    }

    #[test]
    fn test_subscription_add_remove() {
        let manager = NfInstanceManager::new();

        let subscription = SubscriptionData {
            id: "sub-1".to_string(),
            req_nf_type: Some("AMF".to_string()),
            req_nf_instance_id: None,
            notification_uri: "http://example.com/notify".to_string(),
            subscr_cond: Some(SubscrCond {
                nf_type: Some("SMF".to_string()),
                service_name: None,
                nf_instance_id: None,
            }),
            validity_duration: 3600,
        };

        assert!(manager.add_subscription(subscription));
        assert_eq!(manager.subscription_count(), 1);

        let found = manager.find_subscription("sub-1");
        assert!(found.is_some());
        assert_eq!(found.unwrap().notification_uri, "http://example.com/notify");

        assert!(manager.remove_subscription("sub-1"));
        assert_eq!(manager.subscription_count(), 0);
    }

    #[test]
    fn test_nf_register_validation() {
        let profile = NfProfile {
            nf_instance_id: "".to_string(),
            nf_type: "AMF".to_string(),
            nf_status: "REGISTERED".to_string(),
            heartbeat_timer: None,
            plmn_list: vec![],
            ipv4_addresses: vec![],
            ipv6_addresses: vec![],
            fqdn: None,
            nf_services: vec![],
        };

        let result = nrf_nnrf_handle_nf_register("nf-1", &profile);
        match result {
            HandlerResult::Error(400, msg) => {
                assert!(msg.contains("NFInstanceId"));
            }
            _ => panic!("Expected error for empty nf_instance_id"),
        }
    }

    #[test]
    fn test_nf_register_success() {
        let profile = NfProfile {
            nf_instance_id: "nf-test".to_string(),
            nf_type: "AMF".to_string(),
            nf_status: "REGISTERED".to_string(),
            heartbeat_timer: Some(10),
            plmn_list: vec![],
            ipv4_addresses: vec!["192.168.1.1".to_string()],
            ipv6_addresses: vec![],
            fqdn: None,
            nf_services: vec![],
        };

        let result = nrf_nnrf_handle_nf_register("nf-test", &profile);
        match result {
            HandlerResult::Success(201) => {}
            _ => panic!("Expected success for valid registration"),
        }
    }

    #[test]
    fn test_nf_discover_validation() {
        let result = nrf_nnrf_handle_nf_discover("", "AMF", None);
        match result {
            HandlerResult::Error(400, msg) => {
                assert!(msg.contains("target-nf-type"));
            }
            _ => panic!("Expected error for empty target_nf_type"),
        }

        let result = nrf_nnrf_handle_nf_discover("SMF", "", None);
        match result {
            HandlerResult::Error(400, msg) => {
                assert!(msg.contains("requester-nf-type"));
            }
            _ => panic!("Expected error for empty requester_nf_type"),
        }
    }

    #[test]
    fn test_subscription_validation() {
        let subscription = SubscriptionData {
            id: "sub-test".to_string(),
            req_nf_type: None,
            req_nf_instance_id: None,
            notification_uri: "".to_string(),
            subscr_cond: None,
            validity_duration: 3600,
        };

        let result = nrf_nnrf_handle_nf_status_subscribe(subscription);
        match result {
            HandlerResult::Error(400, msg) => {
                assert!(msg.contains("nfStatusNotificationUri"));
            }
            _ => panic!("Expected error for empty notification_uri"),
        }
    }
}
