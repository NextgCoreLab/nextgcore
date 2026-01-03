//! SEPP SBI Path Functions
//!
//! Port of src/sepp/sbi-path.c - SBI server/client path functions
//!
//! The SEPP acts as a security proxy that:
//! - Receives requests from NFs in the home PLMN
//! - Forwards requests to peer SEPPs in visited PLMNs
//! - Handles N32c handshake for security capability negotiation
//! - Routes responses back to original requesters

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::context::{sepp_self, SeppNode};
use crate::n32c_build::build_security_capability_sbi_request;

/// SBI server configuration
#[derive(Debug, Clone)]
pub struct SbiServerConfig {
    pub addr: String,
    pub port: u16,
    pub tls_enabled: bool,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    /// N32 interface address (for peer SEPP communication)
    pub n32_addr: Option<String>,
    pub n32_port: Option<u16>,
}

impl Default for SbiServerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1".to_string(),
            port: 7777, // Default SEPP port
            tls_enabled: false,
            tls_cert: None,
            tls_key: None,
            n32_addr: None,
            n32_port: None,
        }
    }
}

/// SBI server state
static SBI_SERVER_RUNNING: AtomicBool = AtomicBool::new(false);

/// Custom HTTP headers used by SEPP
pub mod headers {
    pub const TARGET_APIROOT: &str = "3gpp-sbi-target-apiroot";
    pub const CALLBACK: &str = "3gpp-sbi-callback";
    pub const NRF_URI: &str = "3gpp-sbi-nrf-uri";
    pub const SCHEME: &str = ":scheme";
    pub const AUTHORITY: &str = ":authority";
}

/// Interface names
pub mod interfaces {
    pub const SEPP: &str = "sepp";
    pub const N32F: &str = "n32f";
}

/// Open SBI server
/// Port of sepp_sbi_open
pub fn sepp_sbi_open(config: Option<SbiServerConfig>) -> Result<(), String> {
    if SBI_SERVER_RUNNING.load(Ordering::SeqCst) {
        return Err("SBI server already running".to_string());
    }

    let config = config.unwrap_or_default();

    log::info!(
        "Opening SEPP SBI server on {}:{}",
        config.addr,
        config.port
    );

    // TODO: Initialize SELF NF instance
    // In C: ogs_sbi_nf_instance_build_default(nf_instance)

    // TODO: Initialize NRF NF Instance if configured
    // In C: ogs_sbi_nf_fsm_init(nf_instance)

    // TODO: Start SBI server with request_handler
    // In C: ogs_sbi_server_start_all(request_handler)

    SBI_SERVER_RUNNING.store(true, Ordering::SeqCst);

    log::info!("SEPP SBI server opened successfully");
    Ok(())
}

/// Close SBI server
/// Port of sepp_sbi_close
pub fn sepp_sbi_close() {
    if !SBI_SERVER_RUNNING.load(Ordering::SeqCst) {
        return;
    }

    log::info!("Closing SEPP SBI server");

    // TODO: Stop SBI client
    // In C: ogs_sbi_client_stop_all()

    // TODO: Stop SBI server
    // In C: ogs_sbi_server_stop_all()

    SBI_SERVER_RUNNING.store(false, Ordering::SeqCst);

    log::info!("SEPP SBI server closed");
}

/// Check if SBI server is running
pub fn sepp_sbi_is_running() -> bool {
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
    /// Request forwarded to peer SEPP
    ForwardedToPeerSepp,
    /// Request forwarded to local NF via SCP
    ForwardedToLocalNf,
    /// Request handled locally (e.g., N32c handshake)
    Handled,
    /// Error occurred
    Error(String),
}

/// Send N32c handshake security capability request
/// Port of sepp_n32c_handshake_send_security_capability_request
pub fn send_security_capability_request(
    node: &mut SeppNode,
    none_mode: bool,
) -> Result<(), String> {
    let client_id = node.client_id.ok_or("No client configured")?;

    let request = build_security_capability_sbi_request(node, none_mode)
        .ok_or("Failed to build security capability request")?;

    log::info!(
        "[{}] Sending security capability request (none={})",
        node.receiver,
        none_mode
    );

    // TODO: Actually send the request via SBI client
    // In C: ogs_sbi_client_send_request(client, ogs_sbi_client_handler, request, sepp_node)

    log::debug!(
        "[{}] Request sent to client_id={}: {} {}",
        node.receiver,
        client_id,
        request.method,
        request.resource
    );

    Ok(())
}

/// Handle incoming SBI request
/// Port of request_handler from sbi-path.c
pub fn handle_request(
    stream_id: u64,
    request: &SbiRequest,
    server_interface: Option<&str>,
) -> RequestHandlerResult {
    log::debug!(
        "SEPP handling request: {} {} (stream_id={})",
        request.method,
        request.uri,
        stream_id
    );

    // Check for Target-apiRoot header
    let target_apiroot = request.get_header(headers::TARGET_APIROOT);

    if let Some(target_apiroot) = target_apiroot {
        return handle_forwarding_request(stream_id, request, target_apiroot, server_interface);
    }

    // No Target-apiRoot, this is a local request (e.g., NRF notification)
    handle_local_request(stream_id, request, server_interface)
}

/// Handle request that needs to be forwarded
fn handle_forwarding_request(
    stream_id: u64,
    request: &SbiRequest,
    target_apiroot: &str,
    server_interface: Option<&str>,
) -> RequestHandlerResult {
    let ctx = sepp_self();

    // Create association for this request
    let assoc = {
        if let Ok(context) = ctx.read() {
            context.assoc_add(stream_id)
        } else {
            None
        }
    };

    let assoc = match assoc {
        Some(a) => a,
        None => {
            log::error!("Failed to create association");
            return RequestHandlerResult::Error("Failed to create association".to_string());
        }
    };

    // Check if target is in VPLMN (different PLMN)
    let is_vplmn = is_fqdn_in_vplmn(target_apiroot);

    if is_vplmn {
        // Request from local NF to remote PLMN - forward via peer SEPP
        if server_interface.is_some() {
            log::error!(
                "[DROP] Peer SEPP is using the wrong interface [{:?}]",
                server_interface
            );
            remove_assoc(assoc.id);
            return RequestHandlerResult::Error("Wrong interface".to_string());
        }

        // Find peer SEPP by PLMN ID
        let (mcc, mnc) = extract_plmn_from_fqdn(target_apiroot);
        let sepp_node = {
            if let Ok(context) = ctx.read() {
                context.node_find_by_plmn_id(mcc, mnc)
            } else {
                None
            }
        };

        match sepp_node {
            Some(node) => {
                log::debug!(
                    "Forwarding to peer SEPP [{}] for PLMN {}:{}",
                    node.receiver,
                    mcc,
                    mnc
                );
                // TODO: Forward request to peer SEPP
                RequestHandlerResult::ForwardedToPeerSepp
            }
            None => {
                log::error!(
                    "Cannot find SEPP Peer Node for [{}:{}:{}]",
                    target_apiroot,
                    mcc,
                    mnc
                );
                remove_assoc(assoc.id);
                RequestHandlerResult::Error("Peer SEPP not found".to_string())
            }
        }
    } else {
        // Request from peer SEPP to local NF - forward via SCP or directly
        if server_interface.is_none() {
            // Check if we have separate SEPP/N32F interfaces
            // If so, this request should come on the SEPP interface
            log::debug!("Request from peer SEPP to local NF");
        }

        // TODO: Forward to local NF via SCP or directly
        log::debug!("Forwarding to local NF: {}", target_apiroot);
        RequestHandlerResult::ForwardedToLocalNf
    }
}

/// Handle local request (no forwarding needed)
fn handle_local_request(
    _stream_id: u64,
    _request: &SbiRequest,
    server_interface: Option<&str>,
) -> RequestHandlerResult {
    // Check interface
    if let Some(interface) = server_interface {
        if interface == interfaces::N32F {
            log::error!(
                "[DROP] Peer SEPP is using the wrong interface [{}]",
                interface
            );
            return RequestHandlerResult::Error("Wrong interface".to_string());
        }
    }

    // This is a local request (e.g., NRF notification)
    // Push to event queue for processing
    log::debug!("Handling local request");
    RequestHandlerResult::Handled
}

/// Handle response from forwarded request
/// Port of response_handler from sbi-path.c
pub fn handle_response(assoc_id: u64, response: &SbiResponse) -> Result<(), String> {
    let ctx = sepp_self();
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

    log::debug!(
        "SEPP handling response for stream_id={}, status={}",
        assoc.stream_id,
        response.status
    );

    // TODO: Send response back to original requester
    // In C: ogs_sbi_server_send_response(stream, response)

    // Clean up association
    remove_assoc(assoc.id);

    Ok(())
}

/// Copy request headers, removing scheme and authority
/// Port of copy_request from sbi-path.c
pub fn copy_request_headers(
    source: &SbiRequest,
    do_not_remove_custom_header: bool,
) -> HashMap<String, String> {
    let mut target = HashMap::new();

    for (key, val) in &source.headers {
        // Skip scheme and authority (will be set by client)
        if key.eq_ignore_ascii_case(headers::SCHEME)
            || key.eq_ignore_ascii_case(headers::AUTHORITY)
        {
            continue;
        }

        // Optionally skip custom headers
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

/// Remove association helper
fn remove_assoc(assoc_id: u64) {
    let ctx = sepp_self();
    let _ = ctx.read().map(|context| {
        context.assoc_remove(assoc_id);
    });
}

/// Check if FQDN is in VPLMN (visited PLMN)
/// Port of ogs_sbi_fqdn_in_vplmn
fn is_fqdn_in_vplmn(fqdn: &str) -> bool {
    // Check if the FQDN contains a different PLMN ID than our serving PLMNs
    // Format: xxx.5gc.mnc<MNC>.mcc<MCC>.3gppnetwork.org
    if !fqdn.contains(".3gppnetwork.org") {
        return false;
    }

    // TODO: Compare with local serving PLMN IDs
    // For now, assume any 3gppnetwork.org FQDN is in VPLMN
    true
}

/// Extract PLMN ID from FQDN
/// Port of ogs_plmn_id_mcc_from_fqdn / ogs_plmn_id_mnc_from_fqdn
fn extract_plmn_from_fqdn(fqdn: &str) -> (u16, u16) {
    // Format: xxx.5gc.mnc<MNC>.mcc<MCC>.3gppnetwork.org
    let mut mcc: u16 = 0;
    let mut mnc: u16 = 0;

    for part in fqdn.split('.') {
        if part.starts_with("mcc") {
            if let Ok(val) = part[3..].parse::<u16>() {
                mcc = val;
            }
        } else if part.starts_with("mnc") {
            if let Ok(val) = part[3..].parse::<u16>() {
                mnc = val;
            }
        }
    }

    (mcc, mnc)
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

        let result = sepp_sbi_open(None);
        assert!(result.is_ok());
        assert!(sepp_sbi_is_running());

        sepp_sbi_close();
        assert!(!sepp_sbi_is_running());
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
    fn test_extract_plmn_from_fqdn() {
        let fqdn = "sepp.5gc.mnc260.mcc310.3gppnetwork.org";
        let (mcc, mnc) = extract_plmn_from_fqdn(fqdn);
        assert_eq!(mcc, 310);
        assert_eq!(mnc, 260);
    }

    #[test]
    fn test_is_fqdn_in_vplmn() {
        assert!(is_fqdn_in_vplmn("sepp.5gc.mnc260.mcc310.3gppnetwork.org"));
        assert!(!is_fqdn_in_vplmn("sepp.local.example.com"));
    }

    #[test]
    fn test_copy_request_headers() {
        let mut request = SbiRequest::new("GET", "/test");
        request.set_header(":scheme", "https");
        request.set_header(":authority", "example.com");
        request.set_header("Content-Type", "application/json");
        request.set_header(headers::TARGET_APIROOT, "https://target.com");

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
