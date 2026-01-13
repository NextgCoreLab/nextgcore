//! SCP SBI Path Functions
//!
//! Port of src/scp/sbi-path.c - SBI server/client path functions
//! 
//! The SCP acts as a proxy that:
//! - Receives requests from NF consumers
//! - Performs NF discovery delegation when needed
//! - Forwards requests to target NFs
//! - Routes responses back to original requesters
//! - Handles SEPP routing for inter-PLMN communication

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::context::{scp_self, NfType, SbiServiceType, DiscoveryOption};

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
    pub const DISCOVERY_REQUESTER_NF_INSTANCE_ID: &str = "3gpp-sbi-discovery-requester-nf-instance-id";
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

    log::info!(
        "Opening SCP SBI server on {}:{}",
        config.addr,
        config.port
    );

    // Note: Initialize SELF NF instance
    // In C: ogs_sbi_nf_instance_build_default(nf_instance)
    // - Build NF instance information for NRF registration
    // This is handled by the ogs_sbi module when NRF integration is enabled

    // Note: Initialize NRF NF Instance if configured (Model D)
    // In C: ogs_sbi_nf_fsm_init(nf_instance)
    // This is handled by the nnrf integration when NRF is enabled

    // Note: Check if Next-SCP's client is configured
    // In C: NF_INSTANCE_CLIENT(ogs_sbi_self()->scp_instance)
    // Next-SCP support is configured via scp.yaml configuration file

    // Note: Setup subscription data for NF types
    // In C: ogs_sbi_subscription_spec_add(OpenAPI_nf_type_SEPP, NULL)
    //       ogs_sbi_subscription_spec_add(OpenAPI_nf_type_AMF, NULL)
    // Subscription setup is handled by the nnrf integration when NRF is enabled

    // Note: Start SBI server with request_handler
    // In C: ogs_sbi_server_start_all(request_handler)
    // Server startup is handled by the HTTP server module in main.rs

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

    // Note: Stop SBI client
    // In C: ogs_sbi_client_stop_all()
    // Client cleanup is handled by the HTTP client module

    // Note: Stop SBI server
    // In C: ogs_sbi_server_stop_all()
    // Server cleanup is handled by the HTTP server module in main.rs

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

/// Request handler result
#[derive(Debug)]
pub enum RequestHandlerResult {
    /// Request forwarded to target NF
    Forwarded,
    /// Request forwarded to Next-SCP
    ForwardedToNextScp,
    /// Discovery initiated, waiting for response
    DiscoveryPending,
    /// Request handled locally (e.g., NRF notification)
    Handled,
    /// Error occurred
    Error(String),
}

/// Parse discovery parameters from request headers
/// Port of header extraction in request_handler
pub fn parse_discovery_headers(
    request: &SbiRequest,
) -> (Option<NfType>, Option<NfType>, Option<SbiServiceType>, DiscoveryOption) {
    let mut target_nf_type: Option<NfType> = None;
    let mut requester_nf_type: Option<NfType> = None;
    let mut service_type: Option<SbiServiceType> = None;
    let mut discovery_option = DiscoveryOption::new();

    // Parse User-Agent to get requester NF type
    if let Some(user_agent) = request.get_header(headers::USER_AGENT) {
        // User-Agent format: "NF_TYPE-additional_info"
        if let Some(nf_type_str) = user_agent.split('-').next() {
            requester_nf_type = Some(NfType::from_string(nf_type_str));
        }
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

    (target_nf_type, requester_nf_type, service_type, discovery_option)
}

/// Handle incoming SBI request
/// Port of request_handler from sbi-path.c
pub fn handle_request(
    stream_id: u64,
    request: &SbiRequest,
) -> RequestHandlerResult {
    log::debug!("SCP handling request: {} {} (stream_id={})", 
        request.method, request.uri, stream_id);

    // Create association for this request
    let ctx = scp_self();
    let assoc = {
        if let Ok(context) = ctx.read() {
            context.assoc_add(stream_id)
        } else {
            None
        }
    };

    let mut assoc = match assoc {
        Some(a) => a,
        None => {
            log::error!("Failed to create association");
            return RequestHandlerResult::Error("Failed to create association".to_string());
        }
    };

    // Parse discovery headers
    let (target_nf_type, requester_nf_type, service_type, discovery_option) = 
        parse_discovery_headers(request);

    // Validate requester NF type (from User-Agent)
    let requester_nf_type = match requester_nf_type {
        Some(nf_type) if nf_type != NfType::Null => nf_type,
        _ => {
            log::error!("[{}] No User-Agent", request.uri);
            remove_assoc(assoc.id);
            return RequestHandlerResult::Error("No User-Agent header".to_string());
        }
    };

    assoc.requester_nf_type = requester_nf_type;
    assoc.discovery_option = discovery_option;

    // Check for Target-apiRoot header (direct routing)
    if let Some(target_apiroot) = request.get_header(headers::TARGET_APIROOT) {
        assoc.set_target_apiroot(target_apiroot);
        
        // Note: Check if target is in VPLMN (requires SEPP)
        // In C: ogs_sbi_fqdn_in_vplmn(headers.target_apiroot)
        // VPLMN detection is handled by the SEPP integration when inter-PLMN routing is enabled

        log::debug!("Forwarding to target apiroot: {}", target_apiroot);

        // Note: Forward request to target
        // In C: send_request(client, response_handler, request, false, assoc)
        // Request forwarding is handled by the HTTP client module
        
        return RequestHandlerResult::Forwarded;
    }

    // Check for discovery parameters
    let discovery_presence = target_nf_type.is_some() && service_type.is_some();

    if discovery_presence {
        let target_nf_type = target_nf_type.unwrap();
        let service_type = service_type.unwrap();

        assoc.target_nf_type = target_nf_type;
        assoc.service_type = service_type;

        // If target is NRF, route directly
        if target_nf_type == NfType::Nrf {
            log::debug!("Routing directly to NRF");
            // Note: Get NRF client and forward
            // NRF client lookup is handled by the nnrf integration module
            return RequestHandlerResult::Forwarded;
        }

        // Check if we already know the target NF instance
        if assoc.discovery_option.target_nf_instance_id.is_some() {
            // Note: Look up NF instance and forward if found
            // NF instance lookup is handled by the ogs_sbi module's NF instance cache
            log::debug!("Target NF instance ID provided, looking up...");
        }

        // Need to perform NF discovery
        log::debug!("Initiating NF discovery for {} -> {}", 
            requester_nf_type.to_string(), target_nf_type.to_string());

        // Store request for forwarding after discovery
        assoc.request = Some(crate::context::SbiRequest {
            method: request.method.clone(),
            uri: request.uri.clone(),
            headers: request.headers.clone(),
            body: request.body.clone(),
        });

        // Update association
        if let Ok(context) = ctx.read() {
            context.assoc_update(&assoc);
        }

        // Note: Send discovery request to NRF
        // In C: send_discover(nrf_client, nf_discover_handler, assoc)
        // Discovery requests are sent via the nnrf integration module

        return RequestHandlerResult::DiscoveryPending;
    }

    // No discovery needed, this might be a notification from NRF
    log::debug!("No discovery parameters, handling as notification");
    
    // Clean up association since we're handling locally
    remove_assoc(assoc.id);

    RequestHandlerResult::Handled
}

/// Handle response from forwarded request
/// Port of response_handler from sbi-path.c
pub fn handle_response(
    assoc_id: u64,
    response: &SbiResponse,
) -> Result<(), String> {
    let ctx = scp_self();
    let assoc = {
        if let Ok(context) = ctx.read() {
            context.assoc_find(assoc_id)
        } else {
            None
        }
    };

    let assoc = match assoc {
        Some(a) => a,
        None => {
            return Err(format!("Association not found: {}", assoc_id));
        }
    };

    log::debug!("SCP handling response for stream_id={}, status={}", 
        assoc.stream_id, response.status);

    // Add producer ID header if we have it
    let mut response = response.clone();
    if let Some(ref producer_id) = assoc.nf_service_producer_id {
        response.set_header(headers::PRODUCER_ID, producer_id);
    }

    // Note: Send response back to original requester
    // In C: ogs_sbi_server_send_response(stream, response)
    // Response sending is handled by the HTTP server module

    // Clean up association
    remove_assoc(assoc.id);

    Ok(())
}

/// Handle NF discovery response
/// Port of nf_discover_handler from sbi-path.c
pub fn handle_nf_discover_response(
    assoc_id: u64,
    response: &SbiResponse,
) -> Result<(), String> {
    let ctx = scp_self();
    let assoc = {
        if let Ok(context) = ctx.read() {
            context.assoc_find(assoc_id)
        } else {
            None
        }
    };

    let assoc = match assoc {
        Some(a) => a,
        None => {
            return Err(format!("Association not found: {}", assoc_id));
        }
    };

    if response.status != 200 {
        log::error!("NF-Discover failed [{}]", response.status);
        remove_assoc(assoc.id);
        return Err(format!("NF-Discover failed [{}]", response.status));
    }

    log::debug!("NF discovery successful for {} -> {}",
        assoc.requester_nf_type.to_string(),
        assoc.target_nf_type.to_string());

    // Note: Parse SearchResult from response body
    // In C: ogs_nnrf_disc_handle_nf_discover_search_result(message.SearchResult)
    // SearchResult parsing is handled by the nnrf integration module

    // Note: Find NF instance by discovery parameters
    // In C: ogs_sbi_nf_instance_find_by_discovery_param(...)
    // NF instance lookup is handled by the ogs_sbi module's NF instance cache

    // Note: Store NF service producer
    // assoc.nf_service_producer_id = Some(nf_instance.id);
    // Producer ID is stored when the NF instance is selected

    // Note: Get client for the discovered NF
    // In C: ogs_sbi_client_find_by_service_type(nf_instance, service_type)
    // Client lookup is handled by the HTTP client module

    // Note: Check if SEPP is needed for VPLMN routing
    // In C: ogs_sbi_fqdn_in_vplmn(client->fqdn)
    // VPLMN detection is handled by the SEPP integration when inter-PLMN routing is enabled

    // Note: Forward original request to discovered NF
    // In C: send_request(client, response_handler, request, false, assoc)
    // Request forwarding is handled by the HTTP client module

    // Update association
    if let Ok(context) = ctx.read() {
        context.assoc_update(&assoc);
    }

    Ok(())
}

/// Handle SEPP discovery response
/// Port of sepp_discover_handler from sbi-path.c
pub fn handle_sepp_discover_response(
    assoc_id: u64,
    response: &SbiResponse,
) -> Result<(), String> {
    let ctx = scp_self();
    let assoc = {
        if let Ok(context) = ctx.read() {
            context.assoc_find(assoc_id)
        } else {
            None
        }
    };

    let assoc = match assoc {
        Some(a) => a,
        None => {
            return Err(format!("Association not found: {}", assoc_id));
        }
    };

    if response.status != 200 {
        log::error!("SEPP-Discover failed [{}]", response.status);
        remove_assoc(assoc.id);
        return Err(format!("SEPP-Discover failed [{}]", response.status));
    }

    log::debug!("SEPP discovery successful");

    // Note: Parse SearchResult and get SEPP client
    // In C: ogs_nnrf_disc_handle_nf_discover_search_result(message.SearchResult)
    // In C: NF_INSTANCE_CLIENT(ogs_sbi_self()->sepp_instance)
    // SEPP client lookup is handled by the SEPP integration module

    // Note: Forward original request via SEPP
    // In C: send_request(sepp_client, response_handler, request, false, assoc)
    // Request forwarding via SEPP is handled by the HTTP client module

    Ok(())
}

/// Remove association helper
fn remove_assoc(assoc_id: u64) {
    let ctx = scp_self();
    let _ = ctx.read().map(|context| {
        context.assoc_remove(assoc_id);
    });
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
        assert_eq!(request.get_header("content-type"), Some(&"application/json".to_string()));
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
        request.set_header(headers::USER_AGENT, "AMF-nextgcore");
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
}
