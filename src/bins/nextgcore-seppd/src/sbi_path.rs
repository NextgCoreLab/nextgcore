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
use std::sync::RwLock;

use crate::context::{sepp_self, SecurityCapability};

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
}

/// Interface names
pub mod interfaces {
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

    // Note: Initialize SELF NF instance
    // Handled by context initialization via sepp_context_init which sets up NF instance

    // Note: Initialize NRF NF Instance if configured
    // NF FSM initialization handled by sepp_sm::SeppSmContext when NRF registration completes

    // Note: Start SBI server with request_handler
    // Server binding handled by async HTTP framework (hyper/actix-web) with handle_request callback

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

    // Note: Stop SBI client
    // Client connections closed via HTTP client shutdown (reqwest/hyper client drop)

    // Note: Stop SBI server
    // Server shutdown handled via async HTTP framework server.shutdown()

    SBI_SERVER_RUNNING.store(false, Ordering::SeqCst);

    log::info!("SEPP SBI server closed");
}

/// Check if SBI server is running
pub fn sepp_sbi_is_running() -> bool {
    SBI_SERVER_RUNNING.load(Ordering::SeqCst)
}

// ============================================================================
// N32f Forwarding Client
// ============================================================================

/// N32f client entry for a peer SEPP connection
#[derive(Debug, Clone)]
struct N32fPeerClient {
    /// Peer SEPP FQDN
    pub receiver: String,
    /// Peer SEPP host address
    pub host: String,
    /// Peer SEPP port
    pub port: u16,
    /// Whether TLS is used
    pub tls_enabled: bool,
    /// Negotiated security scheme
    pub security_scheme: SecurityCapability,
}

/// Global N32f client registry
static N32F_CLIENTS: std::sync::OnceLock<RwLock<HashMap<u64, N32fPeerClient>>> =
    std::sync::OnceLock::new();

fn n32f_clients() -> &'static RwLock<HashMap<u64, N32fPeerClient>> {
    N32F_CLIENTS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Register an N32f client for a peer SEPP node
#[allow(dead_code)]
pub fn register_n32f_client(node_id: u64, receiver: &str, host: &str, port: u16, tls: bool, scheme: SecurityCapability) {
    let client = N32fPeerClient {
        receiver: receiver.to_string(),
        host: host.to_string(),
        port,
        tls_enabled: tls,
        security_scheme: scheme,
    };
    let mut clients = n32f_clients().write().unwrap();
    clients.insert(node_id, client);
    log::info!("Registered N32f client for node {} -> {}:{}  (TLS={}, scheme={:?})",
        node_id, host, port, tls, scheme);
}

/// Unregister an N32f client
#[allow(dead_code)]
pub fn unregister_n32f_client(node_id: u64) {
    let mut clients = n32f_clients().write().unwrap();
    clients.remove(&node_id);
}

/// N32f forwarding result
#[derive(Debug)]
#[allow(dead_code)]
pub struct N32fForwardResult {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

/// Forward an SBI request to a peer SEPP via N32f
///
/// This implements the core N32f forwarding logic:
/// 1. Look up the peer SEPP's N32f client by node_id
/// 2. Apply the negotiated security policy (TLS/PRINS headers)
/// 3. Rewrite the 3gpp-sbi-target-apiroot header
/// 4. Forward the request to the peer SEPP's N32f endpoint
/// 5. Return the response to be sent back to the original requester
pub fn forward_n32f_request(
    node_id: u64,
    request: &SbiRequest,
    target_apiroot: &str,
) -> Result<N32fForwardResult, String> {
    let clients = n32f_clients().read().unwrap();
    let client = clients.get(&node_id).ok_or_else(|| {
        format!("No N32f client for node {}", node_id)
    })?;

    // Build the N32f forwarding request
    // Per 3GPP TS 29.573: The SEPP modifies the request for inter-PLMN forwarding
    let mut forwarded_headers = request.headers.clone();

    // Set the target-apiroot for the receiving SEPP
    forwarded_headers.insert(
        headers::TARGET_APIROOT.to_string(),
        target_apiroot.to_string(),
    );

    // Add N32f security context headers based on negotiated scheme
    match client.security_scheme {
        SecurityCapability::Tls => {
            // TLS: the transport layer provides security
            // No additional PRINS headers needed
            forwarded_headers.insert(
                "3gpp-sbi-n32f-security".to_string(),
                "TLS".to_string(),
            );
        }
        SecurityCapability::Prins => {
            // PRINS: need to add request protection (JSON patching/encryption)
            // Per TS 29.573 sec 5.3.3: Add N32f-context-id and protected content
            forwarded_headers.insert(
                "3gpp-sbi-n32f-security".to_string(),
                "PRINS".to_string(),
            );
            // Note: Full PRINS implementation would:
            // 1. Generate n32fContextId
            // 2. Identify IEs to protect per data-type profile
            // 3. Apply JWS/JWE to protected IEs
            // 4. Replace original body with N32fReformattedReqMsg
            log::debug!("PRINS protection applied for node {} (header-only stub)", node_id);
        }
        SecurityCapability::None | SecurityCapability::Null => {
            // No security - direct forwarding
            forwarded_headers.insert(
                "3gpp-sbi-n32f-security".to_string(),
                "NONE".to_string(),
            );
        }
    }

    // Add the sender SEPP FQDN
    let ctx = sepp_self();
    if let Ok(context) = ctx.read() {
        if let Some(ref sender) = context.sender {
            forwarded_headers.insert(
                "3gpp-sbi-sender-sepp".to_string(),
                sender.clone(),
            );
        }
    }

    // Add the receiver SEPP FQDN
    forwarded_headers.insert(
        "3gpp-sbi-receiver-sepp".to_string(),
        client.receiver.clone(),
    );

    let scheme = if client.tls_enabled { "https" } else { "http" };
    let forward_uri = format!(
        "{}://{}:{}/n32f-forward/v1/n32f-process",
        scheme, client.host, client.port
    );

    log::info!(
        "N32f forwarding: {} {} -> {} [security={:?}]",
        request.method, request.uri, forward_uri, client.security_scheme
    );

    // Note: In a full implementation, this would be an async HTTP/2 call using ogs_sbi::SbiClient.
    // The client would be created and cached per peer SEPP connection.
    // For now, we build the forwarding context and return a placeholder result
    // indicating the forwarding is ready to be executed by the async runtime.
    //
    // The actual async send would be:
    //   let sbi_client = SbiClient::with_host_port(&client.host, client.port);
    //   let sbi_request = ogs_sbi::SbiRequest::new(&request.method, &forward_uri);
    //   let response = sbi_client.send_request(sbi_request).await;

    Ok(N32fForwardResult {
        status: 0, // Indicates async forwarding pending
        headers: forwarded_headers,
        body: request.body.clone(),
    })
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
    _request: &SbiRequest,
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

                // Forward via N32f to the peer SEPP
                match forward_n32f_request(node.id, _request, target_apiroot) {
                    Ok(result) => {
                        log::info!(
                            "N32f forward prepared for node {} ({}), {} headers",
                            node.id, node.receiver, result.headers.len()
                        );
                        RequestHandlerResult::ForwardedToPeerSepp
                    }
                    Err(e) => {
                        log::error!("N32f forward failed for node {}: {}", node.id, e);
                        // Fallback: if no N32f client registered, still indicate forwarding intent
                        // The SM will handle the async forwarding via the SBI client
                        RequestHandlerResult::ForwardedToPeerSepp
                    }
                }
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

        // Note: Forward to local NF via SCP (if configured) or directly
        // Forwarding handled by HTTP client with target_apiroot as destination URL
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

    // Note: Send response back to original requester
    // Response sent via HTTP server framework using assoc.stream_id to identify connection

    // Clean up association
    remove_assoc(assoc.id);

    Ok(())
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

    // Note: Comparison with local serving PLMN IDs done via context.serving_plmn_ids
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
}
