//! NRF Handler Implementation
//!
//! Port of src/nrf/nnrf-handler.c - Handlers for NF management and discovery

use crate::nf_sm::{nrf_nf_fsm_fini, nrf_nf_fsm_init, NfSmContext, NfState};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// NF Profile data structure
#[derive(Debug, Clone, Default)]
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
    /// Full NFProfile document exactly as received on register (TS 29.510
    /// Table 6.1.6.2.2-1). Preserves every attribute (services, sNssais,
    /// capacities, *Info containers, ...) so GET / discovery / notifications
    /// can return the complete profile, not just the parsed summary above.
    /// `Value::Null` for profiles created via the legacy struct path.
    pub attributes: serde_json::Value,
}

/// Mandatory NFProfile attributes per TS 29.510 Table 6.1.6.2.2-1
/// (nfInstanceId, nfType, nfStatus are the only `M` attributes).
pub const MANDATORY_PROFILE_ATTRS: [&str; 3] = ["nfInstanceId", "nfType", "nfStatus"];

impl NfProfile {
    /// Returns the mandatory attributes missing (or empty/not a string) in a
    /// candidate NFProfile document.
    pub fn missing_mandatory_attrs(doc: &serde_json::Value) -> Vec<&'static str> {
        MANDATORY_PROFILE_ATTRS
            .iter()
            .filter(|attr| {
                !matches!(doc.get(**attr),
                          Some(serde_json::Value::String(s)) if !s.is_empty())
            })
            .copied()
            .collect()
    }

    /// Builds an NfProfile from a full NFProfile JSON document, preserving the
    /// document verbatim in `attributes` and parsing the summary fields the
    /// NRF core logic needs (heartbeat, status, addresses, services).
    ///
    /// Errors with the list of missing mandatory attributes (TS 29.510:
    /// nfInstanceId, nfType, nfStatus) for a 400 ProblemDetails response.
    pub fn from_json(doc: &serde_json::Value) -> Result<Self, Vec<&'static str>> {
        let missing = Self::missing_mandatory_attrs(doc);
        if !missing.is_empty() {
            return Err(missing);
        }

        let str_at = |key: &str| doc.get(key).and_then(|v| v.as_str()).map(|s| s.to_string());
        let str_vec = |key: &str| -> Vec<String> {
            doc.get(key)
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| s.to_string())
                        .collect()
                })
                .unwrap_or_default()
        };

        let plmn_list = doc
            .get("plmnList")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|p| {
                        Some(PlmnId {
                            mcc: p.get("mcc")?.as_str()?.to_string(),
                            mnc: p.get("mnc")?.as_str()?.to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let nf_services = doc
            .get("nfServices")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| {
                        Some(NfService {
                            service_instance_id: s.get("serviceInstanceId")?.as_str()?.to_string(),
                            service_name: s.get("serviceName")?.as_str()?.to_string(),
                            versions: s
                                .get("versions")
                                .and_then(|v| v.as_array())
                                .map(|vs| {
                                    vs.iter()
                                        .filter_map(|v| {
                                            v.get("apiVersionInUri")
                                                .and_then(|u| u.as_str())
                                                .or_else(|| v.as_str())
                                                .map(|s| s.to_string())
                                        })
                                        .collect()
                                })
                                .unwrap_or_default(),
                            scheme: s
                                .get("scheme")
                                .and_then(|v| v.as_str())
                                .unwrap_or("http")
                                .to_string(),
                            fqdn: s.get("fqdn").and_then(|v| v.as_str()).map(String::from),
                            ip_endpoints: s
                                .get("ipEndPoints")
                                .and_then(|v| v.as_array())
                                .map(|eps| {
                                    eps.iter()
                                        .map(|ep| IpEndpoint {
                                            ipv4_address: ep
                                                .get("ipv4Address")
                                                .and_then(|v| v.as_str())
                                                .map(String::from),
                                            ipv6_address: ep
                                                .get("ipv6Address")
                                                .and_then(|v| v.as_str())
                                                .map(String::from),
                                            port: ep
                                                .get("port")
                                                .and_then(|v| v.as_u64())
                                                .unwrap_or(0)
                                                as u16,
                                        })
                                        .collect()
                                })
                                .unwrap_or_default(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(NfProfile {
            nf_instance_id: str_at("nfInstanceId").unwrap_or_default(),
            nf_type: str_at("nfType").unwrap_or_default(),
            nf_status: str_at("nfStatus").unwrap_or_default(),
            heartbeat_timer: doc
                .get("heartBeatTimer")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            plmn_list,
            ipv4_addresses: str_vec("ipv4Addresses"),
            ipv6_addresses: str_vec("ipv6Addresses"),
            fqdn: str_at("fqdn"),
            nf_services,
            attributes: doc.clone(),
        })
    }

    /// Returns the full NFProfile document. Prefers the verbatim registered
    /// document; falls back to a reconstruction from the summary fields for
    /// legacy profiles created without one.
    pub fn to_json(&self) -> serde_json::Value {
        if self.attributes.is_object() {
            let mut doc = self.attributes.clone();
            // nfStatus can change server-side (SUSPENDED/REGISTERED); keep
            // the returned document consistent with the live status.
            if let Some(obj) = doc.as_object_mut() {
                obj.insert(
                    "nfStatus".to_string(),
                    serde_json::Value::String(self.nf_status.clone()),
                );
            }
            return doc;
        }
        let mut doc = serde_json::json!({
            "nfInstanceId": self.nf_instance_id,
            "nfType": self.nf_type,
            "nfStatus": self.nf_status,
        });
        let obj = doc.as_object_mut().expect("doc is an object");
        if let Some(hb) = self.heartbeat_timer {
            obj.insert("heartBeatTimer".into(), hb.into());
        }
        if !self.plmn_list.is_empty() {
            obj.insert(
                "plmnList".into(),
                self.plmn_list
                    .iter()
                    .map(|p| serde_json::json!({"mcc": p.mcc, "mnc": p.mnc}))
                    .collect(),
            );
        }
        if !self.ipv4_addresses.is_empty() {
            obj.insert("ipv4Addresses".into(), self.ipv4_addresses.clone().into());
        }
        if !self.ipv6_addresses.is_empty() {
            obj.insert("ipv6Addresses".into(), self.ipv6_addresses.clone().into());
        }
        if let Some(ref fqdn) = self.fqdn {
            obj.insert("fqdn".into(), fqdn.clone().into());
        }
        doc
    }
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
    /// NF instances by ID (state machine context)
    instances: RwLock<HashMap<String, NfSmContext>>,
    /// NF profiles by ID
    profiles: RwLock<HashMap<String, NfProfile>>,
    /// Subscriptions by ID
    subscriptions: RwLock<HashMap<String, SubscriptionData>>,
}

impl NfInstanceManager {
    /// Create a new NF instance manager
    pub fn new() -> Self {
        Self {
            instances: RwLock::new(HashMap::new()),
            profiles: RwLock::new(HashMap::new()),
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
                // Also remove profile
                if let Ok(mut profiles) = self.profiles.write() {
                    profiles.remove(id);
                }
                return true;
            }
        }
        false
    }

    /// Get instance count
    pub fn instance_count(&self) -> usize {
        self.instances.read().map(|i| i.len()).unwrap_or(0)
    }

    /// Register an NF profile
    pub fn register(&self, profile: NfProfile) -> Result<(), String> {
        let id = profile.nf_instance_id.clone();

        // Add instance FSM if new
        self.add_instance(id.clone());

        // Store profile
        if let Ok(mut profiles) = self.profiles.write() {
            profiles.insert(id, profile);
            Ok(())
        } else {
            Err("Failed to acquire write lock".to_string())
        }
    }

    /// Deregister an NF
    pub fn deregister(&self, id: &str) -> Result<(), String> {
        if self.remove_instance(id) {
            Ok(())
        } else {
            Err(format!("NF instance {id} not found"))
        }
    }

    /// Suspend an NF (mark as SUSPENDED due to missed heartbeat, TS 29.510)
    ///
    /// The NF is not deregistered yet - it will be auto-deregistered if no
    /// heartbeat is received within the grace period.
    pub fn suspend(&self, id: &str) -> bool {
        if let Ok(mut profiles) = self.profiles.write() {
            if let Some(profile) = profiles.get_mut(id) {
                log::warn!(
                    "[{}] NF status: {} -> SUSPENDED (missed heartbeat)",
                    id,
                    profile.nf_status
                );
                profile.nf_status = "SUSPENDED".to_string();
                return true;
            }
        }
        false
    }

    /// Reactivate a SUSPENDED NF (heartbeat received within grace period, TS 29.510)
    ///
    /// Returns true only if the NF was SUSPENDED and is now REGISTERED again.
    pub fn reactivate(&self, id: &str) -> bool {
        if let Ok(mut profiles) = self.profiles.write() {
            if let Some(profile) = profiles.get_mut(id) {
                if profile.nf_status == "SUSPENDED" {
                    log::info!("[{id}] NF status: SUSPENDED -> REGISTERED (heartbeat received)");
                    profile.nf_status = "REGISTERED".to_string();
                    return true;
                }
            }
        }
        false
    }

    /// Check if an NF is suspended
    pub fn is_suspended(&self, id: &str) -> bool {
        if let Ok(profiles) = self.profiles.read() {
            if let Some(profile) = profiles.get(id) {
                return profile.nf_status == "SUSPENDED";
            }
        }
        false
    }

    /// Get an NF profile by ID
    pub fn get(&self, id: &str) -> Option<NfProfile> {
        let profiles = self.profiles.read().ok()?;
        profiles.get(id).cloned()
    }

    /// List all NF profiles
    pub fn list(&self) -> Vec<NfProfile> {
        self.profiles
            .read()
            .map(|p| p.values().cloned().collect())
            .expect("value expected")
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

    /// List all subscriptions
    pub fn list_subscriptions(&self) -> Vec<SubscriptionData> {
        self.subscriptions
            .read()
            .map(|s| s.values().cloned().collect())
            .expect("value expected")
    }

    /// Remove expired subscriptions (returns number removed)
    pub fn remove_expired_subscriptions(&self, expired_ids: &[String]) -> usize {
        let mut removed = 0;
        if let Ok(mut subscriptions) = self.subscriptions.write() {
            for id in expired_ids {
                if subscriptions.remove(id).is_some() {
                    log::info!("Removed expired subscription: {id}");
                    removed += 1;
                }
            }
        }
        removed
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
pub fn nrf_nnrf_handle_nf_register(nf_instance_id: &str, profile: &NfProfile) -> HandlerResult {
    log::info!(
        "[{}] NF registration request (type={})",
        nf_instance_id,
        profile.nf_type
    );

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

    // Add NF instance and store profile
    let manager = nf_manager();
    let is_new = manager.add_instance(nf_instance_id.to_string());

    // Store the full profile
    if let Err(e) = manager.register(profile.clone()) {
        log::error!("[{nf_instance_id}] Failed to store NF profile: {e}");
        return HandlerResult::Error(500, "Internal server error".to_string());
    }

    if is_new {
        log::info!(
            "[{}] NF registered (new) - type={}, services={}",
            nf_instance_id,
            profile.nf_type,
            profile.nf_services.len()
        );
        HandlerResult::Success(201) // Created
    } else {
        log::info!(
            "[{}] NF registered (updated) - type={}, services={}",
            nf_instance_id,
            profile.nf_type,
            profile.nf_services.len()
        );
        HandlerResult::Success(200) // OK
    }
}

/// Handle NF update (PATCH /nf-instances/{nfInstanceId})
pub fn nrf_nnrf_handle_nf_update(
    nf_instance_id: &str,
    _patch_items: &[PatchItem],
) -> HandlerResult {
    log::debug!("[{nf_instance_id}] NF update request");

    let manager = nf_manager();
    if manager.find_instance(nf_instance_id).is_none() {
        return HandlerResult::Error(404, "NF instance not found".to_string());
    }

    // Note: Apply patch items
    // Patch application would update the NF profile fields based on RFC 6902 JSON Patch operations

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
pub fn nrf_nnrf_handle_nf_status_subscribe(subscription: SubscriptionData) -> HandlerResult {
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
    log::debug!("[{subscription_id}] NF status update request");

    let manager = nf_manager();
    if manager.find_subscription(subscription_id).is_none() {
        return HandlerResult::Error(404, "Subscription not found".to_string());
    }

    // Note: Update validity time
    // Validity time update would extend the subscription expiration

    HandlerResult::Success(204) // No Content
}

/// Handle NF status unsubscribe (DELETE /subscriptions/{subscriptionId})
pub fn nrf_nnrf_handle_nf_status_unsubscribe(subscription_id: &str) -> HandlerResult {
    log::info!("[{subscription_id}] NF status unsubscribe request");

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
    log::debug!("NF list retrieval request (type={nf_type:?}, limit={limit:?})");

    // Note: Return list of NF instance URIs
    // The response body would contain a Links structure with hrefs to each NF instance

    HandlerResult::Success(200)
}

/// Handle NF profile retrieval (GET /nf-instances/{nfInstanceId})
pub fn nrf_nnrf_handle_nf_profile_retrieval(nf_instance_id: &str) -> HandlerResult {
    log::debug!("[{nf_instance_id}] NF profile retrieval request");

    let manager = nf_manager();
    if manager.find_instance(nf_instance_id).is_none() {
        return HandlerResult::Error(404, "NF instance not found".to_string());
    }

    // Note: Return NF profile
    // The response body would contain the complete NfProfile for this instance

    HandlerResult::Success(200)
}

/// Handle NF discover (GET /nf-instances for discovery)
pub fn nrf_nnrf_handle_nf_discover(
    target_nf_type: &str,
    requester_nf_type: &str,
    discovery_options: Option<&DiscoveryOptions>,
) -> HandlerResult {
    log::debug!("NF discover request (target={target_nf_type}, requester={requester_nf_type})");

    if target_nf_type.is_empty() {
        return HandlerResult::Error(400, "No target-nf-type".to_string());
    }

    if requester_nf_type.is_empty() {
        return HandlerResult::Error(400, "No requester-nf-type".to_string());
    }

    // Search for matching NF instances
    let manager = nf_manager();
    let all_profiles = manager.list();

    let matching: Vec<NfProfile> = all_profiles
        .into_iter()
        .filter(|profile| {
            // Filter by target NF type
            if profile.nf_type.to_uppercase() != target_nf_type.to_uppercase() {
                return false;
            }

            // Filter by NF status - must be REGISTERED
            if profile.nf_status.to_uppercase() != "REGISTERED" {
                return false;
            }

            // Apply discovery options if provided
            if let Some(opts) = discovery_options {
                // Filter by target NF instance ID
                if let Some(ref target_id) = opts.target_nf_instance_id {
                    if &profile.nf_instance_id != target_id {
                        return false;
                    }
                }

                // Filter by service names
                if !opts.service_names.is_empty() {
                    let has_service = profile.nf_services.iter().any(|svc| {
                        opts.service_names
                            .iter()
                            .any(|name| svc.service_name.to_lowercase() == name.to_lowercase())
                    });
                    if !has_service {
                        return false;
                    }
                }

                // Filter by S-NSSAI (if provided)
                // Note: Full S-NSSAI filtering would require profile to contain slice info
            }

            true
        })
        .collect();

    let limit = discovery_options.and_then(|o| o.limit).unwrap_or(10) as usize;
    let result_count = matching.len().min(limit);

    log::info!(
        "NF discover: found {} matching NF instances (returning {})",
        matching.len(),
        result_count
    );

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

// ============================================================================
// NFUpdate patch engines (TS 29.510 §5.2.2.3)
//
// TS 29.510 mandates `application/json-patch+json` (RFC 6902, array(PatchItem),
// minItems 1) as the NFUpdate PATCH body — see TS29510_Nnrf_NFManagement.yaml
// UpdateNFInstance requestBody. RFC 7396 merge-patch is additionally accepted
// for `application/merge-patch+json` bodies as a lenient-peer convenience.
// ============================================================================

/// Patch application failure, mapped to HTTP statuses by the caller:
/// `Malformed` -> 400 Bad Request, `TestFailed` -> 409 Conflict
/// (RFC 5789 §2.2 error-handling guidance for failed `test` ops).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchError {
    /// Structurally invalid patch document or inapplicable operation.
    Malformed(String),
    /// An RFC 6902 `test` operation did not match.
    TestFailed(String),
}

impl std::fmt::Display for PatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatchError::Malformed(m) => write!(f, "malformed patch: {m}"),
            PatchError::TestFailed(m) => write!(f, "test operation failed: {m}"),
        }
    }
}

/// Applies an RFC 7396 JSON merge patch to `target` in place.
pub fn json_merge_patch(target: &mut serde_json::Value, patch: &serde_json::Value) {
    use serde_json::Value;
    if let Value::Object(patch_obj) = patch {
        if !target.is_object() {
            *target = Value::Object(serde_json::Map::new());
        }
        let target_obj = target.as_object_mut().expect("target coerced to object");
        for (key, value) in patch_obj {
            if value.is_null() {
                target_obj.remove(key);
            } else {
                json_merge_patch(target_obj.entry(key.clone()).or_insert(Value::Null), value);
            }
        }
    } else {
        *target = patch.clone();
    }
}

/// Splits an RFC 6901 JSON Pointer into unescaped reference tokens.
fn pointer_tokens(path: &str) -> Result<Vec<String>, PatchError> {
    if path.is_empty() {
        return Ok(vec![]);
    }
    if !path.starts_with('/') {
        return Err(PatchError::Malformed(format!(
            "JSON Pointer must start with '/': {path:?}"
        )));
    }
    Ok(path[1..]
        .split('/')
        .map(|t| t.replace("~1", "/").replace("~0", "~"))
        .collect())
}

/// Resolves a JSON Pointer to a reference inside `doc`.
fn pointer_get<'a>(
    doc: &'a serde_json::Value,
    path: &str,
) -> Result<&'a serde_json::Value, PatchError> {
    let mut current = doc;
    for token in pointer_tokens(path)? {
        current = match current {
            serde_json::Value::Object(map) => map.get(&token).ok_or_else(|| {
                PatchError::Malformed(format!("path {path:?}: no member {token:?}"))
            })?,
            serde_json::Value::Array(arr) => {
                let idx: usize = token.parse().map_err(|_| {
                    PatchError::Malformed(format!("path {path:?}: bad array index {token:?}"))
                })?;
                arr.get(idx).ok_or_else(|| {
                    PatchError::Malformed(format!("path {path:?}: index {idx} out of bounds"))
                })?
            }
            _ => {
                return Err(PatchError::Malformed(format!(
                    "path {path:?}: {token:?} indexes a scalar"
                )))
            }
        };
    }
    Ok(current)
}

/// Navigates to the parent container of `path` and returns it with the final
/// reference token. The empty pointer ("") has no parent.
fn pointer_parent<'a>(
    doc: &'a mut serde_json::Value,
    path: &str,
) -> Result<(&'a mut serde_json::Value, String), PatchError> {
    let mut tokens = pointer_tokens(path)?;
    let last = tokens.pop().ok_or_else(|| {
        PatchError::Malformed("operation on whole-document pointer \"\" is not supported".into())
    })?;
    let mut current = doc;
    for token in tokens {
        current = match current {
            serde_json::Value::Object(map) => map.get_mut(&token).ok_or_else(|| {
                PatchError::Malformed(format!("path {path:?}: no member {token:?}"))
            })?,
            serde_json::Value::Array(arr) => {
                let idx: usize = token.parse().map_err(|_| {
                    PatchError::Malformed(format!("path {path:?}: bad array index {token:?}"))
                })?;
                arr.get_mut(idx).ok_or_else(|| {
                    PatchError::Malformed(format!("path {path:?}: index {idx} out of bounds"))
                })?
            }
            _ => {
                return Err(PatchError::Malformed(format!(
                    "path {path:?}: {token:?} indexes a scalar"
                )))
            }
        };
    }
    Ok((current, last))
}

/// RFC 6902 `add` semantics: insert into arrays (index or `-`), insert or
/// replace object members.
fn pointer_add(
    doc: &mut serde_json::Value,
    path: &str,
    value: serde_json::Value,
) -> Result<(), PatchError> {
    if path.is_empty() {
        *doc = value;
        return Ok(());
    }
    let (parent, token) = pointer_parent(doc, path)?;
    match parent {
        serde_json::Value::Object(map) => {
            map.insert(token, value);
            Ok(())
        }
        serde_json::Value::Array(arr) => {
            let idx = if token == "-" {
                arr.len()
            } else {
                token.parse().map_err(|_| {
                    PatchError::Malformed(format!("path {path:?}: bad array index {token:?}"))
                })?
            };
            if idx > arr.len() {
                return Err(PatchError::Malformed(format!(
                    "path {path:?}: index {idx} out of bounds for add"
                )));
            }
            arr.insert(idx, value);
            Ok(())
        }
        _ => Err(PatchError::Malformed(format!(
            "path {path:?}: parent is a scalar"
        ))),
    }
}

/// RFC 6902 `remove` semantics; returns the removed value (used by `move`).
fn pointer_remove(
    doc: &mut serde_json::Value,
    path: &str,
) -> Result<serde_json::Value, PatchError> {
    let (parent, token) = pointer_parent(doc, path)?;
    match parent {
        serde_json::Value::Object(map) => map.remove(&token).ok_or_else(|| {
            PatchError::Malformed(format!("path {path:?}: no member {token:?} to remove"))
        }),
        serde_json::Value::Array(arr) => {
            let idx: usize = token.parse().map_err(|_| {
                PatchError::Malformed(format!("path {path:?}: bad array index {token:?}"))
            })?;
            if idx >= arr.len() {
                return Err(PatchError::Malformed(format!(
                    "path {path:?}: index {idx} out of bounds for remove"
                )));
            }
            Ok(arr.remove(idx))
        }
        _ => Err(PatchError::Malformed(format!(
            "path {path:?}: parent is a scalar"
        ))),
    }
}

/// Applies an RFC 6902 JSON Patch (TS 29.510 PatchItem array, minItems 1) to
/// `doc` in place. Supports all six operations (add/remove/replace/move/copy/
/// test). On error the document is left in a partially patched state — callers
/// must apply to a copy and only commit on success.
pub fn apply_json_patch(
    doc: &mut serde_json::Value,
    patch: &serde_json::Value,
) -> Result<(), PatchError> {
    let items = patch.as_array().ok_or_else(|| {
        PatchError::Malformed("JSON Patch body must be an array of PatchItem".into())
    })?;
    if items.is_empty() {
        return Err(PatchError::Malformed(
            "PatchItem array must contain at least one item (TS 29.510)".into(),
        ));
    }
    for (i, item) in items.iter().enumerate() {
        let op = item
            .get("op")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PatchError::Malformed(format!("PatchItem[{i}]: missing op")))?;
        let path = item
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PatchError::Malformed(format!("PatchItem[{i}]: missing path")))?;
        let value = || {
            item.get("value")
                .cloned()
                .ok_or_else(|| PatchError::Malformed(format!("PatchItem[{i}]: missing value")))
        };
        let from = || {
            item.get("from")
                .and_then(|v| v.as_str())
                .ok_or_else(|| PatchError::Malformed(format!("PatchItem[{i}]: missing from")))
        };
        match op {
            "add" => pointer_add(doc, path, value()?)?,
            "remove" => {
                pointer_remove(doc, path)?;
            }
            "replace" => {
                // Target location must exist (RFC 6902 §4.3).
                pointer_get(doc, path)?;
                pointer_remove(doc, path)?;
                pointer_add(doc, path, value()?)?;
            }
            "move" => {
                let moved = pointer_remove(doc, from()?)?;
                pointer_add(doc, path, moved)?;
            }
            "copy" => {
                let copied = pointer_get(doc, from()?)?.clone();
                pointer_add(doc, path, copied)?;
            }
            "test" => {
                let actual = pointer_get(doc, path)?;
                let expected = value()?;
                if *actual != expected {
                    return Err(PatchError::TestFailed(format!(
                        "PatchItem[{i}]: value at {path:?} does not match"
                    )));
                }
            }
            other => {
                return Err(PatchError::Malformed(format!(
                    "PatchItem[{i}]: unknown op {other:?}"
                )))
            }
        }
    }
    Ok(())
}

// ============================================================================
// NF Discovery filtering (TS 29.510 §6.2.3.2.3.1 SearchNFInstances)
// ============================================================================

/// Parsed discovery query parameters (subset of TS 29.510 §6.2.3.2.3.1).
#[derive(Debug, Clone, Default)]
pub struct DiscoveryQuery {
    /// target-nf-type (mandatory)
    pub target_nf_type: String,
    /// requester-nf-type (mandatory)
    pub requester_nf_type: String,
    /// service-names (comma-separated ServiceName list)
    pub service_names: Vec<String>,
    /// snssais (JSON array of Snssai)
    pub snssais: Vec<serde_json::Value>,
    /// dnn (Dnn supported by the BSF, SMF or UPF)
    pub dnn: Option<String>,
    /// target-plmn-list (JSON array of PlmnId)
    pub target_plmn_list: Vec<serde_json::Value>,
    /// target-nf-instance-id
    pub target_nf_instance_id: Option<String>,
    /// target-nf-fqdn
    pub target_nf_fqdn: Option<String>,
    /// limit (minimum 1)
    pub limit: Option<usize>,
}

/// Two S-NSSAIs match when sst is equal and sd is equal (an absent sd only
/// matches an absent sd, per TS 29.571 Snssai).
fn snssai_matches(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    a.get("sst").and_then(|v| v.as_u64()) == b.get("sst").and_then(|v| v.as_u64())
        && a.get("sd").and_then(|v| v.as_str()) == b.get("sd").and_then(|v| v.as_str())
}

fn plmn_matches(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    a.get("mcc").and_then(|v| v.as_str()) == b.get("mcc").and_then(|v| v.as_str())
        && a.get("mnc").and_then(|v| v.as_str()) == b.get("mnc").and_then(|v| v.as_str())
}

/// Collects every DNN advertised in the NF-type-specific info containers
/// (smfInfo.sNssaiSmfInfoList[].dnnSmfInfoList[].dnn,
/// upfInfo.sNssaiUpfInfoList[].dnnUpfInfoList[].dnn, bsfInfo.dnnList[]).
fn advertised_dnns(doc: &serde_json::Value) -> Vec<String> {
    let mut dnns = Vec::new();
    let lists = [
        ("smfInfo", "sNssaiSmfInfoList", "dnnSmfInfoList"),
        ("upfInfo", "sNssaiUpfInfoList", "dnnUpfInfoList"),
    ];
    for (info, snssai_list, dnn_list) in lists {
        if let Some(entries) = doc
            .get(info)
            .and_then(|v| v.get(snssai_list))
            .and_then(|v| v.as_array())
        {
            for entry in entries {
                if let Some(dnn_infos) = entry.get(dnn_list).and_then(|v| v.as_array()) {
                    for dnn_info in dnn_infos {
                        if let Some(dnn) = dnn_info.get("dnn").and_then(|v| v.as_str()) {
                            dnns.push(dnn.to_string());
                        }
                    }
                }
            }
        }
    }
    if let Some(bsf_dnns) = doc
        .get("bsfInfo")
        .and_then(|v| v.get("dnnList"))
        .and_then(|v| v.as_array())
    {
        dnns.extend(bsf_dnns.iter().filter_map(|v| v.as_str().map(String::from)));
    }
    dnns
}

/// Evaluates one full NFProfile document against the discovery query.
/// Per TS 29.510, an NF profile that omits an attribute (sNssais, plmnList,
/// DNN info) is not disqualified by the corresponding filter — absence means
/// "serves any".
fn profile_matches(doc: &serde_json::Value, status: &str, query: &DiscoveryQuery) -> bool {
    // target-nf-type and REGISTERED status are always required.
    if doc
        .get("nfType")
        .and_then(|v| v.as_str())
        .map(str::to_uppercase)
        != Some(query.target_nf_type.to_uppercase())
    {
        return false;
    }
    if status.to_uppercase() != "REGISTERED" {
        return false;
    }

    if let Some(ref target_id) = query.target_nf_instance_id {
        if doc.get("nfInstanceId").and_then(|v| v.as_str()) != Some(target_id.as_str()) {
            return false;
        }
    }

    if let Some(ref target_fqdn) = query.target_nf_fqdn {
        if doc.get("fqdn").and_then(|v| v.as_str()) != Some(target_fqdn.as_str()) {
            return false;
        }
    }

    // allowedNfTypes: when the profile restricts consumers, the requester
    // type must be allowed (TS 29.510 §6.2: NRF shall not return NF profiles
    // the requester is not allowed to access).
    if let Some(allowed) = doc.get("allowedNfTypes").and_then(|v| v.as_array()) {
        if !allowed
            .iter()
            .filter_map(|v| v.as_str())
            .any(|t| t.eq_ignore_ascii_case(&query.requester_nf_type))
        {
            return false;
        }
    }

    // service-names: the profile must offer at least one requested service.
    if !query.service_names.is_empty() {
        let offers = doc
            .get("nfServices")
            .and_then(|v| v.as_array())
            .map(|services| {
                services
                    .iter()
                    .filter_map(|s| s.get("serviceName").and_then(|v| v.as_str()))
                    .any(|name| {
                        query
                            .service_names
                            .iter()
                            .any(|q| q.eq_ignore_ascii_case(name))
                    })
            })
            .unwrap_or(false);
        if !offers {
            return false;
        }
    }

    // snssais: when the profile advertises slices, at least one must match.
    if !query.snssais.is_empty() {
        if let Some(profile_snssais) = doc.get("sNssais").and_then(|v| v.as_array()) {
            if !profile_snssais.is_empty()
                && !profile_snssais
                    .iter()
                    .any(|p| query.snssais.iter().any(|q| snssai_matches(p, q)))
            {
                return false;
            }
        }
    }

    // target-plmn-list: when the profile advertises PLMNs, one must match.
    if !query.target_plmn_list.is_empty() {
        if let Some(profile_plmns) = doc.get("plmnList").and_then(|v| v.as_array()) {
            if !profile_plmns.is_empty()
                && !profile_plmns
                    .iter()
                    .any(|p| query.target_plmn_list.iter().any(|q| plmn_matches(p, q)))
            {
                return false;
            }
        }
    }

    // dnn: when the profile advertises DNNs (SMF/UPF/BSF info), the requested
    // DNN must be among them.
    if let Some(ref dnn) = query.dnn {
        let dnns = advertised_dnns(doc);
        if !dnns.is_empty() && !dnns.iter().any(|d| d == dnn) {
            return false;
        }
    }

    true
}

/// Runs discovery over all registered profiles and returns the matching full
/// NFProfile documents. When `service-names` is present, the returned
/// profiles' nfServices arrays are trimmed to the requested services
/// (TS 29.510 §5.3.2.2.2: the NRF may omit services the consumer did not ask
/// for). Empty result => 200 with empty SearchResult, NOT 404: the
/// SearchResult schema (TS 29.510 Table 6.2.6.2.2) requires `nfInstances` but
/// permits an empty array, and the reference NRF (Open5GS nnrf-handler.c)
/// returns 200 OK with an empty list when nothing matches.
pub fn discover_profiles(query: &DiscoveryQuery) -> Vec<serde_json::Value> {
    // Copy the profile list out of the manager (no lock is held while we
    // evaluate filters — Wave 2 lock-order rule).
    let profiles = nf_manager().list();

    let mut matches: Vec<serde_json::Value> = profiles
        .iter()
        .filter_map(|profile| {
            let doc = profile.to_json();
            if !profile_matches(&doc, &profile.nf_status, query) {
                return None;
            }
            let mut doc = doc;
            if !query.service_names.is_empty() {
                if let Some(services) = doc.get_mut("nfServices").and_then(|v| v.as_array_mut()) {
                    services.retain(|s| {
                        s.get("serviceName")
                            .and_then(|v| v.as_str())
                            .map(|name| {
                                query
                                    .service_names
                                    .iter()
                                    .any(|q| q.eq_ignore_ascii_case(name))
                            })
                            .unwrap_or(false)
                    });
                }
            }
            Some(doc)
        })
        .collect();

    if let Some(limit) = query.limit {
        matches.truncate(limit.max(1));
    }
    matches
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
            ..Default::default()
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
            ipv4_addresses: vec!["192.168.1.1".to_string()],
            ..Default::default()
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
    fn test_nf_suspend_and_deregister() {
        let manager = NfInstanceManager::new();

        let profile = NfProfile {
            nf_instance_id: "nf-suspend-test".to_string(),
            nf_type: "SMF".to_string(),
            nf_status: "REGISTERED".to_string(),
            heartbeat_timer: Some(10),
            ipv4_addresses: vec!["10.0.0.1".to_string()],
            ..Default::default()
        };
        manager.register(profile).unwrap();

        // Verify initially registered
        assert!(!manager.is_suspended("nf-suspend-test"));
        let p = manager.get("nf-suspend-test").unwrap();
        assert_eq!(p.nf_status, "REGISTERED");

        // Suspend on first missed heartbeat
        assert!(manager.suspend("nf-suspend-test"));
        assert!(manager.is_suspended("nf-suspend-test"));
        let p = manager.get("nf-suspend-test").unwrap();
        assert_eq!(p.nf_status, "SUSPENDED");

        // Discovery must not return SUSPENDED NFs
        let query = DiscoveryQuery {
            target_nf_type: "SMF".to_string(),
            requester_nf_type: "AMF".to_string(),
            ..Default::default()
        };
        assert!(!discover_profiles(&query)
            .iter()
            .any(|p| p.get("nfInstanceId").and_then(|v| v.as_str()) == Some("nf-suspend-test")));

        // Auto-deregister after grace period
        manager.deregister("nf-suspend-test").unwrap();
        assert!(manager.get("nf-suspend-test").is_none());
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

    // ------------------------------------------------------------------
    // Full-profile ingest fidelity (TS 29.510 Table 6.1.6.2.2-1)
    // ------------------------------------------------------------------

    fn full_profile_doc(id: &str, nf_type: &str) -> serde_json::Value {
        serde_json::json!({
            "nfInstanceId": id,
            "nfType": nf_type,
            "nfStatus": "REGISTERED",
            "heartBeatTimer": 10,
            "plmnList": [{"mcc": "001", "mnc": "01"}],
            "sNssais": [{"sst": 1, "sd": "010203"}, {"sst": 2}],
            "ipv4Addresses": ["10.0.0.1"],
            "ipv6Addresses": ["2001:db8::1"],
            "fqdn": "nf.example.com",
            "capacity": 100,
            "load": 12,
            "priority": 1,
            "allowedNfTypes": ["AMF", "SMF"],
            "nfServices": [{
                "serviceInstanceId": "svc-1",
                "serviceName": "nsmf-pdusession",
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": "10.0.0.1", "port": 7777}]
            }],
            "smfInfo": {
                "sNssaiSmfInfoList": [{
                    "sNssai": {"sst": 1, "sd": "010203"},
                    "dnnSmfInfoList": [{"dnn": "internet"}, {"dnn": "ims"}]
                }]
            }
        })
    }

    #[test]
    fn test_from_json_round_trip_preserves_every_attribute() {
        let doc = full_profile_doc("nf-full-1", "SMF");
        let profile = NfProfile::from_json(&doc).expect("valid profile");

        // Summary fields parsed.
        assert_eq!(profile.nf_instance_id, "nf-full-1");
        assert_eq!(profile.nf_type, "SMF");
        assert_eq!(profile.heartbeat_timer, Some(10));
        assert_eq!(profile.plmn_list.len(), 1);
        assert_eq!(profile.ipv4_addresses, vec!["10.0.0.1"]);
        assert_eq!(profile.ipv6_addresses, vec!["2001:db8::1"]);
        assert_eq!(profile.fqdn.as_deref(), Some("nf.example.com"));
        assert_eq!(profile.nf_services.len(), 1);
        assert_eq!(profile.nf_services[0].service_name, "nsmf-pdusession");
        assert_eq!(profile.nf_services[0].versions, vec!["v1"]);
        assert_eq!(profile.nf_services[0].ip_endpoints[0].port, 7777);

        // Round-trip: every attribute survives, byte-for-byte as JSON values.
        assert_eq!(profile.to_json(), doc);
    }

    #[test]
    fn test_from_json_rejects_missing_mandatory_attrs() {
        // Strict-peer rejections: each mandatory attr absent/empty -> error.
        let missing_type = serde_json::json!({"nfInstanceId": "x", "nfStatus": "REGISTERED"});
        assert_eq!(
            NfProfile::from_json(&missing_type).unwrap_err(),
            vec!["nfType"]
        );

        let missing_status = serde_json::json!({"nfInstanceId": "x", "nfType": "AMF"});
        assert_eq!(
            NfProfile::from_json(&missing_status).unwrap_err(),
            vec!["nfStatus"]
        );

        let empty_id =
            serde_json::json!({"nfInstanceId": "", "nfType": "AMF", "nfStatus": "REGISTERED"});
        assert_eq!(
            NfProfile::from_json(&empty_id).unwrap_err(),
            vec!["nfInstanceId"]
        );

        let all_missing = serde_json::json!({"capacity": 100});
        assert_eq!(
            NfProfile::from_json(&all_missing).unwrap_err(),
            vec!["nfInstanceId", "nfType", "nfStatus"]
        );

        // Non-string mandatory attr is also rejected.
        let wrong_type =
            serde_json::json!({"nfInstanceId": 42, "nfType": "AMF", "nfStatus": "REGISTERED"});
        assert_eq!(
            NfProfile::from_json(&wrong_type).unwrap_err(),
            vec!["nfInstanceId"]
        );
    }

    // ------------------------------------------------------------------
    // RFC 7396 JSON merge patch — examples from RFC 7396 Appendix A
    // ------------------------------------------------------------------

    #[test]
    fn test_json_merge_patch_rfc7396_appendix_examples() {
        use serde_json::json;
        // (original, patch, expected) rows from RFC 7396 Appendix A.
        let cases = vec![
            (json!({"a":"b"}), json!({"a":"c"}), json!({"a":"c"})),
            (json!({"a":"b"}), json!({"b":"c"}), json!({"a":"b","b":"c"})),
            (json!({"a":"b"}), json!({"a":null}), json!({})),
            (
                json!({"a":"b","b":"c"}),
                json!({"a":null}),
                json!({"b":"c"}),
            ),
            (json!({"a":["b"]}), json!({"a":"c"}), json!({"a":"c"})),
            (json!({"a":"c"}), json!({"a":["b"]}), json!({"a":["b"]})),
            (
                json!({"a":{"b":"c"}}),
                json!({"a":{"b":"d","c":null}}),
                json!({"a":{"b":"d"}}),
            ),
            (json!({"a":[{"b":"c"}]}), json!({"a":[1]}), json!({"a":[1]})),
            (json!(["a", "b"]), json!(["c", "d"]), json!(["c", "d"])),
            (json!({"a":"b"}), json!(["c"]), json!(["c"])),
            (json!({"a":"foo"}), json!(null), json!(null)),
            (json!({"a":"foo"}), json!("bar"), json!("bar")),
            (json!({"e":null}), json!({"a":1}), json!({"e":null,"a":1})),
            (json!([1, 2]), json!({"a":"b","c":null}), json!({"a":"b"})),
            (
                json!({}),
                json!({"a":{"bb":{"ccc":null}}}),
                json!({"a":{"bb":{}}}),
            ),
        ];
        for (i, (mut original, patch, expected)) in cases.into_iter().enumerate() {
            json_merge_patch(&mut original, &patch);
            assert_eq!(original, expected, "RFC 7396 Appendix A case {i}");
        }
    }

    // ------------------------------------------------------------------
    // RFC 6902 JSON patch (TS 29.510-mandated NFUpdate format)
    // ------------------------------------------------------------------

    #[test]
    fn test_apply_json_patch_all_six_ops() {
        use serde_json::json;
        let mut doc = json!({"nfStatus": "REGISTERED", "load": 10, "tags": ["a", "b"]});
        let patch = json!([
            {"op": "test", "path": "/nfStatus", "value": "REGISTERED"},
            {"op": "replace", "path": "/load", "value": 50},
            {"op": "add", "path": "/capacity", "value": 100},
            {"op": "add", "path": "/tags/1", "value": "x"},
            {"op": "add", "path": "/tags/-", "value": "z"},
            {"op": "remove", "path": "/tags/0"},
            {"op": "copy", "from": "/capacity", "path": "/capacityCopy"},
            {"op": "move", "from": "/capacityCopy", "path": "/capacityMoved"}
        ]);
        apply_json_patch(&mut doc, &patch).expect("patch applies");
        assert_eq!(
            doc,
            json!({
                "nfStatus": "REGISTERED", "load": 50, "capacity": 100,
                "tags": ["x", "b", "z"], "capacityMoved": 100
            })
        );
    }

    #[test]
    fn test_apply_json_patch_pointer_escapes() {
        use serde_json::json;
        let mut doc = json!({"a/b": 1, "m~n": 2});
        let patch = json!([
            {"op": "replace", "path": "/a~1b", "value": 10},
            {"op": "remove", "path": "/m~0n"}
        ]);
        apply_json_patch(&mut doc, &patch).expect("escaped pointers resolve");
        assert_eq!(doc, json!({"a/b": 10}));
    }

    #[test]
    fn test_apply_json_patch_errors() {
        use serde_json::json;
        let mut doc = json!({"a": 1});

        // Not an array.
        assert!(matches!(
            apply_json_patch(&mut doc, &json!({"op": "add"})),
            Err(PatchError::Malformed(_))
        ));
        // Empty array violates TS 29.510 minItems 1.
        assert!(matches!(
            apply_json_patch(&mut doc, &json!([])),
            Err(PatchError::Malformed(_))
        ));
        // replace on a non-existent member.
        assert!(matches!(
            apply_json_patch(
                &mut doc,
                &json!([{"op": "replace", "path": "/zzz", "value": 1}])
            ),
            Err(PatchError::Malformed(_))
        ));
        // Unknown op.
        assert!(matches!(
            apply_json_patch(
                &mut doc,
                &json!([{"op": "merge", "path": "/a", "value": 1}])
            ),
            Err(PatchError::Malformed(_))
        ));
        // Failed test -> distinct error class (mapped to 409 by the server).
        assert!(matches!(
            apply_json_patch(&mut doc, &json!([{"op": "test", "path": "/a", "value": 2}])),
            Err(PatchError::TestFailed(_))
        ));
    }

    // ------------------------------------------------------------------
    // Discovery filter matrix (TS 29.510 §6.2.3.2.3.1)
    // ------------------------------------------------------------------

    #[test]
    fn test_discovery_filter_matrix() {
        let manager = nf_manager();
        // Unique ids so this test is independent of other tests sharing the
        // global manager.
        let smf_id = "disc-smf-1";
        let upf_id = "disc-upf-1";
        let suspended_id = "disc-smf-suspended";

        let smf = NfProfile::from_json(&full_profile_doc(smf_id, "SMF")).unwrap();
        manager.register(smf).unwrap();

        let upf_doc = serde_json::json!({
            "nfInstanceId": upf_id,
            "nfType": "UPF",
            "nfStatus": "REGISTERED",
            "plmnList": [{"mcc": "999", "mnc": "99"}],
            "upfInfo": {
                "sNssaiUpfInfoList": [{
                    "sNssai": {"sst": 1},
                    "dnnUpfInfoList": [{"dnn": "edge"}]
                }]
            }
        });
        manager
            .register(NfProfile::from_json(&upf_doc).unwrap())
            .unwrap();

        let suspended = NfProfile::from_json(&full_profile_doc(suspended_id, "SMF")).unwrap();
        manager.register(suspended).unwrap();
        manager.suspend(suspended_id);

        let base = |target: &str| DiscoveryQuery {
            target_nf_type: target.to_string(),
            requester_nf_type: "AMF".to_string(),
            ..Default::default()
        };

        // target-nf-type only: REGISTERED SMF found, SUSPENDED one excluded.
        let found = discover_profiles(&base("SMF"));
        let ids: Vec<&str> = found
            .iter()
            .filter_map(|p| p.get("nfInstanceId").and_then(|v| v.as_str()))
            .collect();
        assert!(ids.contains(&smf_id));
        assert!(!ids.contains(&suspended_id));

        // Unregistered target type: empty result (200-empty per spec, not 404).
        assert!(discover_profiles(&base("AUSF")).is_empty());

        // service-names: match and trim.
        let mut q = base("SMF");
        q.service_names = vec!["nsmf-pdusession".to_string()];
        let found = discover_profiles(&q);
        assert!(found
            .iter()
            .any(|p| p.get("nfInstanceId").and_then(|v| v.as_str()) == Some(smf_id)));
        // No SMF offers this service.
        let mut q = base("SMF");
        q.service_names = vec!["namf-comm".to_string()];
        assert!(!discover_profiles(&q)
            .iter()
            .any(|p| p.get("nfInstanceId").and_then(|v| v.as_str()) == Some(smf_id)));

        // snssais: sst+sd match, sst-only match, and mismatch.
        let mut q = base("SMF");
        q.snssais = vec![serde_json::json!({"sst": 1, "sd": "010203"})];
        assert!(discover_profiles(&q)
            .iter()
            .any(|p| p.get("nfInstanceId").and_then(|v| v.as_str()) == Some(smf_id)));
        let mut q = base("SMF");
        q.snssais = vec![serde_json::json!({"sst": 2})];
        assert!(discover_profiles(&q)
            .iter()
            .any(|p| p.get("nfInstanceId").and_then(|v| v.as_str()) == Some(smf_id)));
        let mut q = base("SMF");
        q.snssais = vec![serde_json::json!({"sst": 7})];
        assert!(!discover_profiles(&q)
            .iter()
            .any(|p| p.get("nfInstanceId").and_then(|v| v.as_str()) == Some(smf_id)));

        // dnn: SMF advertises internet+ims; UPF advertises edge.
        let mut q = base("SMF");
        q.dnn = Some("internet".to_string());
        assert!(discover_profiles(&q)
            .iter()
            .any(|p| p.get("nfInstanceId").and_then(|v| v.as_str()) == Some(smf_id)));
        let mut q = base("SMF");
        q.dnn = Some("edge".to_string());
        assert!(!discover_profiles(&q)
            .iter()
            .any(|p| p.get("nfInstanceId").and_then(|v| v.as_str()) == Some(smf_id)));
        let mut q = base("UPF");
        q.dnn = Some("edge".to_string());
        assert!(discover_profiles(&q)
            .iter()
            .any(|p| p.get("nfInstanceId").and_then(|v| v.as_str()) == Some(upf_id)));

        // target-plmn-list: matching and non-matching PLMN.
        let mut q = base("UPF");
        q.target_plmn_list = vec![serde_json::json!({"mcc": "999", "mnc": "99"})];
        assert!(discover_profiles(&q)
            .iter()
            .any(|p| p.get("nfInstanceId").and_then(|v| v.as_str()) == Some(upf_id)));
        let mut q = base("UPF");
        q.target_plmn_list = vec![serde_json::json!({"mcc": "310", "mnc": "260"})];
        assert!(!discover_profiles(&q)
            .iter()
            .any(|p| p.get("nfInstanceId").and_then(|v| v.as_str()) == Some(upf_id)));

        // requester-nf-type vs allowedNfTypes: SMF profile allows AMF/SMF only.
        let mut q = base("SMF");
        q.requester_nf_type = "PCF".to_string();
        assert!(!discover_profiles(&q)
            .iter()
            .any(|p| p.get("nfInstanceId").and_then(|v| v.as_str()) == Some(smf_id)));

        // target-nf-instance-id pinpoint.
        let mut q = base("SMF");
        q.target_nf_instance_id = Some(smf_id.to_string());
        let found = discover_profiles(&q);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].get("nfInstanceId").and_then(|v| v.as_str()),
            Some(smf_id)
        );

        // limit truncation.
        let mut q = base("SMF");
        q.limit = Some(1);
        assert!(discover_profiles(&q).len() <= 1);

        manager.deregister(smf_id).ok();
        manager.deregister(upf_id).ok();
        manager.deregister(suspended_id).ok();
    }
}
