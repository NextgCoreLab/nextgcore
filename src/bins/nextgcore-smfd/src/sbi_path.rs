//! SMF SBI Path Implementation
//!
//! This module implements the SBI (Service Based Interface) path handling
//! for the SMF, including NF discovery, service registration, and message routing.
//!
//! Based on NextGCore src/smf/sbi-path.c

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

// ============================================================================
// Constants
// ============================================================================

/// SMF SBI service name for PDU session management
pub const SERVICE_NAME_NSMF_PDUSESSION: &str = "nsmf-pdusession";

/// AMF communication service name
pub const SERVICE_NAME_NAMF_COMM: &str = "namf-comm";

/// PCF SM policy control service name
pub const SERVICE_NAME_NPCF_SMPOLICYCONTROL: &str = "npcf-smpolicycontrol";

/// UDM subscriber data management service name
pub const SERVICE_NAME_NUDM_SDM: &str = "nudm-sdm";

/// UDM UE context management service name
pub const SERVICE_NAME_NUDM_UECM: &str = "nudm-uecm";

/// CHF charging service name
pub const SERVICE_NAME_NCHF_CONVERGEDCHARGING: &str = "nchf-convergedcharging";

// API versions
pub const API_V1: &str = "v1";
pub const API_V1_0_0: &str = "1.0.0";

// ============================================================================
// NF Types
// ============================================================================

/// Network Function types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NfType {
    Nrf,
    Amf,
    Smf,
    Upf,
    Pcf,
    Udm,
    Udr,
    Ausf,
    Nssf,
    Bsf,
    Chf,
    Scp,
    Sepp,
}


impl NfType {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            NfType::Nrf => "NRF",
            NfType::Amf => "AMF",
            NfType::Smf => "SMF",
            NfType::Upf => "UPF",
            NfType::Pcf => "PCF",
            NfType::Udm => "UDM",
            NfType::Udr => "UDR",
            NfType::Ausf => "AUSF",
            NfType::Nssf => "NSSF",
            NfType::Bsf => "BSF",
            NfType::Chf => "CHF",
            NfType::Scp => "SCP",
            NfType::Sepp => "SEPP",
        }
    }
}

// ============================================================================
// Service Types
// ============================================================================

/// SBI Service types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceType {
    /// AMF Communication
    NamfComm,
    /// PCF SM Policy Control
    NpcfSmpolicycontrol,
    /// UDM Subscriber Data Management
    NudmSdm,
    /// UDM UE Context Management
    NudmUecm,
    /// CHF Converged Charging
    NchfConvergedcharging,
    /// SMF PDU Session
    NsmfPdusession,
}

impl ServiceType {
    /// Get the service name string
    pub fn service_name(&self) -> &'static str {
        match self {
            ServiceType::NamfComm => SERVICE_NAME_NAMF_COMM,
            ServiceType::NpcfSmpolicycontrol => SERVICE_NAME_NPCF_SMPOLICYCONTROL,
            ServiceType::NudmSdm => SERVICE_NAME_NUDM_SDM,
            ServiceType::NudmUecm => SERVICE_NAME_NUDM_UECM,
            ServiceType::NchfConvergedcharging => SERVICE_NAME_NCHF_CONVERGEDCHARGING,
            ServiceType::NsmfPdusession => SERVICE_NAME_NSMF_PDUSESSION,
        }
    }

    /// Get the target NF type for this service
    pub fn target_nf_type(&self) -> NfType {
        match self {
            ServiceType::NamfComm => NfType::Amf,
            ServiceType::NpcfSmpolicycontrol => NfType::Pcf,
            ServiceType::NudmSdm => NfType::Udm,
            ServiceType::NudmUecm => NfType::Udm,
            ServiceType::NchfConvergedcharging => NfType::Chf,
            ServiceType::NsmfPdusession => NfType::Smf,
        }
    }
}


// ============================================================================
// Discovery Options
// ============================================================================

/// Discovery options for NF selection
#[derive(Debug, Clone, Default)]
pub struct DiscoveryOption {
    /// Target PLMN IDs
    pub target_plmn_list: Vec<PlmnId>,
    /// Requester PLMN IDs
    pub requester_plmn_list: Vec<PlmnId>,
    /// Target NF instance ID
    pub target_nf_instance_id: Option<String>,
    /// Required features
    pub required_features: Vec<String>,
    /// S-NSSAI list
    pub snssai_list: Vec<SNssai>,
    /// DNN
    pub dnn: Option<String>,
}

/// PLMN ID
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct PlmnId {
    pub mcc: String,
    pub mnc: String,
}

impl PlmnId {
    pub fn new(mcc: &str, mnc: &str) -> Self {
        Self {
            mcc: mcc.to_string(),
            mnc: mnc.to_string(),
        }
    }
}

/// S-NSSAI
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct SNssai {
    pub sst: u8,
    pub sd: Option<u32>,
}

impl SNssai {
    pub fn new(sst: u8, sd: Option<u32>) -> Self {
        Self { sst, sd }
    }
}

// ============================================================================
// SBI Transaction
// ============================================================================

/// SBI Transaction state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbiXactState {
    /// Initial state
    Initial,
    /// Request sent, waiting for response
    WaitingResponse,
    /// Response received
    ResponseReceived,
    /// Transaction completed
    Completed,
    /// Transaction timed out
    TimedOut,
    /// Transaction failed
    Failed,
}

impl Default for SbiXactState {
    fn default() -> Self {
        SbiXactState::Initial
    }
}


/// SBI Transaction
#[derive(Debug, Clone)]
pub struct SbiXact {
    /// Transaction ID
    pub id: u64,
    /// Service type
    pub service_type: ServiceType,
    /// Target NF type
    pub target_nf_type: NfType,
    /// Transaction state
    pub state: SbiXactState,
    /// Session ID (if associated with a session)
    pub sess_id: Option<u64>,
    /// Request data
    pub request_data: Option<Vec<u8>>,
    /// Response data
    pub response_data: Option<Vec<u8>>,
    /// HTTP status code
    pub status_code: Option<u16>,
    /// Retry count
    pub retry_count: u32,
    /// Maximum retries
    pub max_retries: u32,
}

impl SbiXact {
    /// Create a new SBI transaction
    pub fn new(id: u64, service_type: ServiceType) -> Self {
        Self {
            id,
            service_type,
            target_nf_type: service_type.target_nf_type(),
            state: SbiXactState::Initial,
            sess_id: None,
            request_data: None,
            response_data: None,
            status_code: None,
            retry_count: 0,
            max_retries: 3,
        }
    }

    /// Set session ID
    pub fn with_session(mut self, sess_id: u64) -> Self {
        self.sess_id = Some(sess_id);
        self
    }

    /// Set request data
    pub fn with_request(mut self, data: Vec<u8>) -> Self {
        self.request_data = Some(data);
        self
    }

    /// Mark as sent
    pub fn mark_sent(&mut self) {
        self.state = SbiXactState::WaitingResponse;
    }

    /// Handle response
    pub fn handle_response(&mut self, status_code: u16, data: Vec<u8>) {
        self.status_code = Some(status_code);
        self.response_data = Some(data);
        self.state = if status_code >= 200 && status_code < 300 {
            SbiXactState::ResponseReceived
        } else {
            SbiXactState::Failed
        };
    }

    /// Mark as completed
    pub fn complete(&mut self) {
        self.state = SbiXactState::Completed;
    }

    /// Mark as timed out
    pub fn timeout(&mut self) {
        self.state = SbiXactState::TimedOut;
    }

    /// Check if can retry
    pub fn can_retry(&self) -> bool {
        self.retry_count < self.max_retries
    }

    /// Increment retry count
    pub fn retry(&mut self) {
        self.retry_count += 1;
        self.state = SbiXactState::Initial;
    }
}


// ============================================================================
// NF Instance
// ============================================================================

/// NF Instance information
#[derive(Debug, Clone)]
pub struct NfInstance {
    /// Instance ID (UUID)
    pub id: String,
    /// NF type
    pub nf_type: NfType,
    /// NF status
    pub status: NfStatus,
    /// IPv4 addresses
    pub ipv4_addresses: Vec<String>,
    /// IPv6 addresses
    pub ipv6_addresses: Vec<String>,
    /// FQDN
    pub fqdn: Option<String>,
    /// Services provided
    pub services: Vec<NfService>,
    /// Allowed NF types
    pub allowed_nf_types: Vec<NfType>,
    /// PLMN list
    pub plmn_list: Vec<PlmnId>,
    /// S-NSSAI list
    pub snssai_list: Vec<SNssai>,
    /// Priority (0-65535, lower is higher priority)
    pub priority: u16,
    /// Capacity (0-65535)
    pub capacity: u16,
    /// Load (0-100)
    pub load: u8,
}

/// NF Status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfStatus {
    Registered,
    Suspended,
    Undiscoverable,
}

impl Default for NfStatus {
    fn default() -> Self {
        NfStatus::Registered
    }
}

/// NF Service information
#[derive(Debug, Clone)]
pub struct NfService {
    /// Service instance ID
    pub service_instance_id: String,
    /// Service name
    pub service_name: String,
    /// Versions
    pub versions: Vec<ServiceVersion>,
    /// Scheme (http/https)
    pub scheme: String,
    /// FQDN
    pub fqdn: Option<String>,
    /// IP endpoints
    pub ip_endpoints: Vec<IpEndpoint>,
    /// Allowed NF types
    pub allowed_nf_types: Vec<NfType>,
}

/// Service version
#[derive(Debug, Clone)]
pub struct ServiceVersion {
    pub api_version_in_uri: String,
    pub api_full_version: String,
}

/// IP Endpoint
#[derive(Debug, Clone)]
pub struct IpEndpoint {
    pub ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
    pub port: u16,
}


// ============================================================================
// SBI Path Manager
// ============================================================================

/// SBI Path Manager for handling NF discovery and message routing
#[derive(Debug)]
pub struct SbiPathManager {
    /// Self NF instance
    self_instance: Option<NfInstance>,
    /// NRF instance
    nrf_instance: Option<NfInstance>,
    /// Discovered NF instances by type
    nf_instances: RwLock<HashMap<NfType, Vec<NfInstance>>>,
    /// Active transactions
    transactions: RwLock<HashMap<u64, SbiXact>>,
    /// Transaction ID counter
    xact_id_counter: AtomicU64,
    /// Subscription specs
    subscription_specs: RwLock<Vec<SubscriptionSpec>>,
}

/// Subscription specification
#[derive(Debug, Clone)]
pub struct SubscriptionSpec {
    pub nf_type: Option<NfType>,
    pub service_name: Option<String>,
}

impl SbiPathManager {
    /// Create a new SBI path manager
    pub fn new() -> Self {
        Self {
            self_instance: None,
            nrf_instance: None,
            nf_instances: RwLock::new(HashMap::new()),
            transactions: RwLock::new(HashMap::new()),
            xact_id_counter: AtomicU64::new(1),
            subscription_specs: RwLock::new(Vec::new()),
        }
    }

    /// Initialize the SBI path
    pub fn open(&mut self, self_instance: NfInstance) -> Result<(), &'static str> {
        self.self_instance = Some(self_instance);
        Ok(())
    }

    /// Close the SBI path
    pub fn close(&mut self) {
        self.self_instance = None;
        self.nrf_instance = None;
        if let Ok(mut instances) = self.nf_instances.write() {
            instances.clear();
        }
        if let Ok(mut xacts) = self.transactions.write() {
            xacts.clear();
        }
    }

    /// Set NRF instance
    pub fn set_nrf_instance(&mut self, instance: NfInstance) {
        self.nrf_instance = Some(instance);
    }

    /// Add subscription spec
    pub fn add_subscription_spec(&self, nf_type: Option<NfType>, service_name: Option<&str>) {
        if let Ok(mut specs) = self.subscription_specs.write() {
            specs.push(SubscriptionSpec {
                nf_type,
                service_name: service_name.map(|s| s.to_string()),
            });
        }
    }

    /// Add discovered NF instance
    pub fn add_nf_instance(&self, instance: NfInstance) {
        if let Ok(mut instances) = self.nf_instances.write() {
            let nf_type = instance.nf_type;
            instances.entry(nf_type).or_insert_with(Vec::new).push(instance);
        }
    }


    /// Find NF instance by type
    pub fn find_nf_instance(&self, nf_type: NfType) -> Option<NfInstance> {
        if let Ok(instances) = self.nf_instances.read() {
            if let Some(list) = instances.get(&nf_type) {
                // Return the instance with lowest priority (highest priority value)
                return list.iter()
                    .filter(|i| i.status == NfStatus::Registered)
                    .min_by_key(|i| i.priority)
                    .cloned();
            }
        }
        None
    }

    /// Find NF instance by service type
    pub fn find_nf_by_service(&self, service_type: ServiceType) -> Option<NfInstance> {
        let target_nf_type = service_type.target_nf_type();
        self.find_nf_instance(target_nf_type)
    }

    /// Create a new transaction
    pub fn create_xact(&self, service_type: ServiceType) -> SbiXact {
        let id = self.xact_id_counter.fetch_add(1, Ordering::SeqCst);
        let xact = SbiXact::new(id, service_type);
        
        if let Ok(mut xacts) = self.transactions.write() {
            xacts.insert(id, xact.clone());
        }
        
        xact
    }

    /// Get transaction by ID
    pub fn get_xact(&self, id: u64) -> Option<SbiXact> {
        if let Ok(xacts) = self.transactions.read() {
            return xacts.get(&id).cloned();
        }
        None
    }

    /// Update transaction
    pub fn update_xact(&self, xact: &SbiXact) {
        if let Ok(mut xacts) = self.transactions.write() {
            xacts.insert(xact.id, xact.clone());
        }
    }

    /// Remove transaction
    pub fn remove_xact(&self, id: u64) -> Option<SbiXact> {
        if let Ok(mut xacts) = self.transactions.write() {
            return xacts.remove(&id);
        }
        None
    }

    /// Get self instance
    pub fn self_instance(&self) -> Option<&NfInstance> {
        self.self_instance.as_ref()
    }

    /// Get NRF instance
    pub fn nrf_instance(&self) -> Option<&NfInstance> {
        self.nrf_instance.as_ref()
    }
}

impl Default for SbiPathManager {
    fn default() -> Self {
        Self::new()
    }
}


// ============================================================================
// SBI Request/Response Building
// ============================================================================

/// HTTP Method
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
        }
    }
}

/// SBI Request
#[derive(Debug, Clone)]
pub struct SbiRequest {
    pub method: HttpMethod,
    pub uri: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

impl SbiRequest {
    pub fn new(method: HttpMethod, uri: &str) -> Self {
        Self {
            method,
            uri: uri.to_string(),
            headers: HashMap::new(),
            body: None,
        }
    }

    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_json_body(mut self, body: Vec<u8>) -> Self {
        self.headers.insert("Content-Type".to_string(), "application/json".to_string());
        self.body = Some(body);
        self
    }
}

/// SBI Response
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

    pub fn ok() -> Self {
        Self::new(200)
    }

    pub fn created() -> Self {
        Self::new(201)
    }

    pub fn no_content() -> Self {
        Self::new(204)
    }

    pub fn bad_request() -> Self {
        Self::new(400)
    }

    pub fn not_found() -> Self {
        Self::new(404)
    }

    pub fn internal_error() -> Self {
        Self::new(500)
    }

    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_json_body(mut self, body: Vec<u8>) -> Self {
        self.headers.insert("Content-Type".to_string(), "application/json".to_string());
        self.body = Some(body);
        self
    }

    pub fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
}


// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nf_type_as_str() {
        assert_eq!(NfType::Smf.as_str(), "SMF");
        assert_eq!(NfType::Amf.as_str(), "AMF");
        assert_eq!(NfType::Pcf.as_str(), "PCF");
    }

    #[test]
    fn test_service_type_service_name() {
        assert_eq!(ServiceType::NsmfPdusession.service_name(), SERVICE_NAME_NSMF_PDUSESSION);
        assert_eq!(ServiceType::NamfComm.service_name(), SERVICE_NAME_NAMF_COMM);
    }

    #[test]
    fn test_service_type_target_nf() {
        assert_eq!(ServiceType::NamfComm.target_nf_type(), NfType::Amf);
        assert_eq!(ServiceType::NpcfSmpolicycontrol.target_nf_type(), NfType::Pcf);
        assert_eq!(ServiceType::NudmSdm.target_nf_type(), NfType::Udm);
    }

    #[test]
    fn test_plmn_id() {
        let plmn = PlmnId::new("310", "260");
        assert_eq!(plmn.mcc, "310");
        assert_eq!(plmn.mnc, "260");
    }

    #[test]
    fn test_snssai() {
        let snssai = SNssai::new(1, Some(0x010203));
        assert_eq!(snssai.sst, 1);
        assert_eq!(snssai.sd, Some(0x010203));
    }

    #[test]
    fn test_sbi_xact_new() {
        let xact = SbiXact::new(1, ServiceType::NamfComm);
        assert_eq!(xact.id, 1);
        assert_eq!(xact.service_type, ServiceType::NamfComm);
        assert_eq!(xact.target_nf_type, NfType::Amf);
        assert_eq!(xact.state, SbiXactState::Initial);
    }

    #[test]
    fn test_sbi_xact_with_session() {
        let xact = SbiXact::new(1, ServiceType::NamfComm)
            .with_session(100);
        assert_eq!(xact.sess_id, Some(100));
    }

    #[test]
    fn test_sbi_xact_lifecycle() {
        let mut xact = SbiXact::new(1, ServiceType::NamfComm);
        
        xact.mark_sent();
        assert_eq!(xact.state, SbiXactState::WaitingResponse);
        
        xact.handle_response(200, vec![]);
        assert_eq!(xact.state, SbiXactState::ResponseReceived);
        
        xact.complete();
        assert_eq!(xact.state, SbiXactState::Completed);
    }


    #[test]
    fn test_sbi_xact_retry() {
        let mut xact = SbiXact::new(1, ServiceType::NamfComm);
        
        assert!(xact.can_retry());
        xact.retry();
        assert_eq!(xact.retry_count, 1);
        assert_eq!(xact.state, SbiXactState::Initial);
        
        xact.retry();
        xact.retry();
        assert!(!xact.can_retry());
    }

    #[test]
    fn test_sbi_xact_timeout() {
        let mut xact = SbiXact::new(1, ServiceType::NamfComm);
        xact.mark_sent();
        xact.timeout();
        assert_eq!(xact.state, SbiXactState::TimedOut);
    }

    #[test]
    fn test_sbi_xact_failed_response() {
        let mut xact = SbiXact::new(1, ServiceType::NamfComm);
        xact.mark_sent();
        xact.handle_response(404, vec![]);
        assert_eq!(xact.state, SbiXactState::Failed);
        assert_eq!(xact.status_code, Some(404));
    }

    #[test]
    fn test_sbi_path_manager_new() {
        let manager = SbiPathManager::new();
        assert!(manager.self_instance().is_none());
        assert!(manager.nrf_instance().is_none());
    }

    #[test]
    fn test_sbi_path_manager_create_xact() {
        let manager = SbiPathManager::new();
        
        let xact1 = manager.create_xact(ServiceType::NamfComm);
        let xact2 = manager.create_xact(ServiceType::NpcfSmpolicycontrol);
        
        assert_eq!(xact1.id, 1);
        assert_eq!(xact2.id, 2);
    }

    #[test]
    fn test_sbi_path_manager_xact_operations() {
        let manager = SbiPathManager::new();
        
        let mut xact = manager.create_xact(ServiceType::NamfComm);
        xact.mark_sent();
        manager.update_xact(&xact);
        
        let retrieved = manager.get_xact(xact.id).unwrap();
        assert_eq!(retrieved.state, SbiXactState::WaitingResponse);
        
        let removed = manager.remove_xact(xact.id);
        assert!(removed.is_some());
        assert!(manager.get_xact(xact.id).is_none());
    }

    #[test]
    fn test_sbi_path_manager_subscription_spec() {
        let manager = SbiPathManager::new();
        
        manager.add_subscription_spec(Some(NfType::Sepp), None);
        manager.add_subscription_spec(None, Some(SERVICE_NAME_NAMF_COMM));
        
        let specs = manager.subscription_specs.read().unwrap();
        assert_eq!(specs.len(), 2);
    }

    #[test]
    fn test_http_method() {
        assert_eq!(HttpMethod::Get.as_str(), "GET");
        assert_eq!(HttpMethod::Post.as_str(), "POST");
        assert_eq!(HttpMethod::Put.as_str(), "PUT");
        assert_eq!(HttpMethod::Patch.as_str(), "PATCH");
        assert_eq!(HttpMethod::Delete.as_str(), "DELETE");
    }

    #[test]
    fn test_sbi_request() {
        let req = SbiRequest::new(HttpMethod::Post, "/nsmf-pdusession/v1/sm-contexts")
            .with_header("Accept", "application/json")
            .with_json_body(vec![1, 2, 3]);
        
        assert_eq!(req.method, HttpMethod::Post);
        assert!(req.uri.contains("sm-contexts"));
        assert_eq!(req.headers.get("Content-Type"), Some(&"application/json".to_string()));
        assert!(req.body.is_some());
    }


    #[test]
    fn test_sbi_response() {
        let resp = SbiResponse::ok()
            .with_header("Location", "/sm-contexts/1")
            .with_json_body(vec![1, 2, 3]);
        
        assert_eq!(resp.status, 200);
        assert!(resp.is_success());
        assert!(resp.body.is_some());
    }

    #[test]
    fn test_sbi_response_status_codes() {
        assert!(SbiResponse::ok().is_success());
        assert!(SbiResponse::created().is_success());
        assert!(SbiResponse::no_content().is_success());
        assert!(!SbiResponse::bad_request().is_success());
        assert!(!SbiResponse::not_found().is_success());
        assert!(!SbiResponse::internal_error().is_success());
    }

    #[test]
    fn test_nf_status_default() {
        let status = NfStatus::default();
        assert_eq!(status, NfStatus::Registered);
    }

    #[test]
    fn test_discovery_option_default() {
        let opt = DiscoveryOption::default();
        assert!(opt.target_plmn_list.is_empty());
        assert!(opt.requester_plmn_list.is_empty());
        assert!(opt.target_nf_instance_id.is_none());
    }
}
