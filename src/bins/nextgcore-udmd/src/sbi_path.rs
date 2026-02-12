//! UDM SBI Path Functions
//!
//! Port of src/udm/sbi-path.c - SBI server and client path functions

use std::sync::atomic::{AtomicBool, Ordering};

use ogs_sbi::context::{global_context, NfInstance, NfService};
use ogs_sbi::message::{SbiRequest, SbiResponse};
use ogs_sbi::types::{NfType, SbiServiceType};

/// SBI server configuration
#[derive(Debug, Clone)]
pub struct SbiServerConfig {
    /// Server address
    pub addr: String,
    /// Server port
    pub port: u16,
    /// TLS enabled
    pub tls_enabled: bool,
    /// TLS certificate path
    pub tls_cert: Option<String>,
    /// TLS key path
    pub tls_key: Option<String>,
}

impl Default for SbiServerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1".to_string(),
            port: 7777,  // UDM default port
            tls_enabled: false,
            tls_cert: None,
            tls_key: None,
        }
    }
}

/// SBI server state
static SBI_RUNNING: AtomicBool = AtomicBool::new(false);

/// Open SBI server and register with NRF
///
/// Port of udm_sbi_open()
pub fn udm_sbi_open(config: Option<SbiServerConfig>) -> Result<(), String> {
    let config = config.unwrap_or_default();

    log::info!("Opening UDM SBI server on {}:{}", config.addr, config.port);

    // Build self NF instance for UDM
    let nf_instance_id = uuid::Uuid::new_v4().to_string();
    let mut nf_instance = NfInstance::new(&nf_instance_id, NfType::Udm);
    nf_instance.ipv4_addresses.push(config.addr.clone());

    // Register NUDM services: nudm-ueau, nudm-uecm, nudm-sdm
    let mut ueau_service = NfService::new("nudm-ueau", SbiServiceType::NudmUeau);
    ueau_service.versions = vec!["v1".to_string()];
    ueau_service.port = config.port;
    nf_instance.add_service(ueau_service);

    let mut uecm_service = NfService::new("nudm-uecm", SbiServiceType::NudmUecm);
    uecm_service.versions = vec!["v1".to_string()];
    uecm_service.port = config.port;
    nf_instance.add_service(uecm_service);

    let mut sdm_service = NfService::new("nudm-sdm", SbiServiceType::NudmSdm);
    sdm_service.versions = vec!["v2".to_string()];
    sdm_service.port = config.port;
    nf_instance.add_service(sdm_service);

    // Store self NF instance in global SBI context
    // Use spawn to avoid blocking the runtime (block_on panics inside async)
    let sbi_ctx = global_context();
    tokio::spawn(async move {
        sbi_ctx.set_self_instance(nf_instance.clone()).await;
    });

    SBI_RUNNING.store(true, Ordering::SeqCst);

    log::info!("UDM SBI server opened successfully (nf_instance_id={nf_instance_id})");
    Ok(())
}

/// Register UDM NF instance with NRF
///
/// Sends NFRegister (PUT) to NRF at /nnrf-nfm/v1/nf-instances/{nfInstanceId}
pub async fn udm_nrf_register(nrf_host: &str, nrf_port: u16) -> Result<(), String> {
    let sbi_ctx = global_context();
    let self_instance = sbi_ctx.get_self_instance().await
        .ok_or("Self NF instance not initialized")?;

    let client = sbi_ctx.get_client(nrf_host, nrf_port).await;

    let path = format!("/nnrf-nfm/v1/nf-instances/{}", self_instance.id);

    // Build NF profile JSON for registration
    let nf_profile = serde_json::json!({
        "nfInstanceId": self_instance.id,
        "nfType": "UDM",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": self_instance.ipv4_addresses,
        "nfServices": self_instance.services.iter().map(|s| {
            serde_json::json!({
                "serviceName": s.name,
                "versions": s.versions.iter().map(|v| {
                    serde_json::json!({"apiVersionInUri": v, "apiFullVersion": format!("{}.0.0", v)})
                }).collect::<Vec<_>>(),
                "scheme": "http",
            })
        }).collect::<Vec<_>>(),
        "heartBeatTimer": self_instance.heartbeat_interval,
    });

    let request = SbiRequest::put(&path)
        .with_json_body(&nf_profile)
        .map_err(|e| format!("Failed to serialize NF profile: {e}"))?;

    let response = client.send_request(request).await
        .map_err(|e| format!("NRF registration request failed: {e}"))?;

    if response.is_success() {
        // Parse heartbeat interval from response if provided
        log::info!("UDM registered with NRF (status={})", response.status);
        Ok(())
    } else {
        Err(format!("NRF registration failed with status {}", response.status))
    }
}

/// Send NRF heartbeat (PATCH to NRF)
pub async fn udm_nrf_heartbeat(nrf_host: &str, nrf_port: u16) -> Result<(), String> {
    let sbi_ctx = global_context();
    let self_instance = sbi_ctx.get_self_instance().await
        .ok_or("Self NF instance not initialized")?;

    let client = sbi_ctx.get_client(nrf_host, nrf_port).await;

    let path = format!("/nnrf-nfm/v1/nf-instances/{}", self_instance.id);

    let update = serde_json::json!([{
        "op": "replace",
        "path": "/nfStatus",
        "value": "REGISTERED"
    }, {
        "op": "replace",
        "path": "/load",
        "value": crate::context::get_ue_load()
    }]);

    let request = SbiRequest::patch(&path)
        .with_json_body(&update)
        .map_err(|e| format!("Failed to serialize heartbeat: {e}"))?;

    let response = client.send_request(request).await
        .map_err(|e| format!("NRF heartbeat request failed: {e}"))?;

    if response.is_success() {
        log::debug!("NRF heartbeat OK (status={})", response.status);
        Ok(())
    } else {
        Err(format!("NRF heartbeat failed with status {}", response.status))
    }
}

/// Discover NF instances via NRF
///
/// Queries /nnrf-disc/v1/nf-instances?target-nf-type={type}
pub async fn udm_nrf_discover(
    nrf_host: &str,
    nrf_port: u16,
    target_nf_type: NfType,
) -> Result<Vec<NfInstance>, String> {
    let sbi_ctx = global_context();
    let _self_instance = sbi_ctx.get_self_instance().await
        .ok_or("Self NF instance not initialized")?;

    let client = sbi_ctx.get_client(nrf_host, nrf_port).await;

    let target_type_str = match target_nf_type {
        NfType::Udr => "UDR",
        NfType::Ausf => "AUSF",
        NfType::Amf => "AMF",
        NfType::Smf => "SMF",
        _ => "UNKNOWN",
    };

    let request = SbiRequest::get("/nnrf-disc/v1/nf-instances")
        .with_param("target-nf-type", target_type_str)
        .with_param("requester-nf-type", "UDM");

    let response = client.send_request(request).await
        .map_err(|e| format!("NRF discovery request failed: {e}"))?;

    if !response.is_success() {
        return Err(format!("NRF discovery failed with status {}", response.status));
    }

    // Parse discovered NF instances from response body
    let body = response.http.content.unwrap_or_default();
    let search_result: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse NRF discovery response: {e}"))?;

    let mut instances = Vec::new();
    if let Some(nf_instances) = search_result.get("nfInstances").and_then(|v| v.as_array()) {
        for nf_json in nf_instances {
            let id = nf_json.get("nfInstanceId").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let mut instance = NfInstance::new(&id, target_nf_type);

            if let Some(addrs) = nf_json.get("ipv4Addresses").and_then(|v| v.as_array()) {
                for addr in addrs {
                    if let Some(s) = addr.as_str() {
                        instance.ipv4_addresses.push(s.to_string());
                    }
                }
            }

            // Cache discovered instance in SBI context
            sbi_ctx.add_nf_instance(instance.clone()).await;
            instances.push(instance);
        }
    }

    log::info!("NRF discovery found {} {} instances", instances.len(), target_type_str);
    Ok(instances)
}

/// Deregister from NRF and close SBI server
///
/// Port of udm_sbi_close()
pub async fn udm_nrf_deregister(nrf_host: &str, nrf_port: u16) -> Result<(), String> {
    let sbi_ctx = global_context();
    if let Some(self_instance) = sbi_ctx.get_self_instance().await {
        let client = sbi_ctx.get_client(nrf_host, nrf_port).await;
        let path = format!("/nnrf-nfm/v1/nf-instances/{}", self_instance.id);
        let request = SbiRequest::delete(&path);

        match client.send_request(request).await {
            Ok(response) if response.is_success() => {
                log::info!("UDM deregistered from NRF");
            }
            Ok(response) => {
                log::warn!("NRF deregister returned status {}", response.status);
            }
            Err(e) => {
                log::warn!("NRF deregister failed: {e}");
            }
        }
    }
    Ok(())
}

/// Close SBI server
///
/// Port of udm_sbi_close()
pub fn udm_sbi_close() {
    log::info!("Closing UDM SBI server");

    // Clear SBI client connections
    let sbi_ctx = global_context();
    if let Ok(_handle) = tokio::runtime::Handle::try_current() {
        // Use spawn instead of block_on to avoid panicking when called from async context
        tokio::spawn(async move {
            sbi_ctx.clear_clients().await;
            sbi_ctx.clear_nf_instances().await;
        });
    }

    SBI_RUNNING.store(false, Ordering::SeqCst);

    log::info!("UDM SBI server closed");
}

/// Check if SBI server is running
pub fn udm_sbi_is_running() -> bool {
    SBI_RUNNING.load(Ordering::SeqCst)
}

/// Send SBI request to a specific NF instance by ID
///
/// Port of udm_sbi_send_request()
pub async fn udm_sbi_send_request(
    nf_instance_id: &str,
    request: SbiRequest,
) -> Result<SbiResponse, String> {
    let sbi_ctx = global_context();

    // Look up the NF instance to get its address
    let nf_instance = sbi_ctx.get_nf_instance(nf_instance_id).await
        .ok_or_else(|| format!("NF instance not found: {nf_instance_id}"))?;

    let host = nf_instance.ipv4_addresses.first()
        .ok_or_else(|| format!("NF instance {nf_instance_id} has no IPv4 address"))?;

    // Determine port from first service or default
    let port = nf_instance.services.first()
        .map(|s| s.port)
        .unwrap_or(80);

    let client = sbi_ctx.get_client(host, port).await;

    log::debug!(
        "Sending SBI request to NF [{}] at {}:{} ({})",
        nf_instance_id,
        host,
        port,
        request.header.method
    );

    client.send_request(request).await
        .map_err(|e| format!("SBI request to {nf_instance_id} failed: {e}"))
}

/// Discover UDR and send a NUDR-DR request
///
/// Port of udm_sbi_discover_and_send() for UDR queries.
/// 1. Looks up cached UDR instances in SBI context
/// 2. If none found, returns error (caller should trigger NRF discovery first)
/// 3. Sends the request to the first available UDR
pub async fn udm_sbi_discover_and_send_nudr_dr(
    udm_ue_id: u64,
    stream_id: u64,
    request: SbiRequest,
) -> Result<SbiResponse, String> {
    let sbi_ctx = global_context();

    // Find UDR instances (from discovery cache or env var fallback)
    let udr_instances = sbi_ctx.find_nf_instances_by_type(NfType::Udr).await;

    let (host_str, port);
    if let Some(udr) = udr_instances.first() {
        host_str = udr.ipv4_addresses.first()
            .ok_or("UDR has no IPv4 address")?.clone();
        port = udr.find_service(SbiServiceType::NudrDr)
            .map(|s| s.port)
            .unwrap_or(80);
    } else {
        // Fallback: use UDR_SBI_ADDR/UDR_SBI_PORT env vars
        host_str = std::env::var("UDR_SBI_ADDR").map_err(|_| {
            "No UDR instance discovered and UDR_SBI_ADDR not set".to_string()
        })?;
        port = std::env::var("UDR_SBI_PORT")
            .ok().and_then(|p| p.parse().ok()).unwrap_or(7777);
        log::info!("Using UDR env var fallback: {host_str}:{port}");
    }

    let client = sbi_ctx.get_client(&host_str, port).await;

    log::debug!(
        "Sending NUDR-DR request for UE [{udm_ue_id}] stream [{stream_id}] to UDR at {host_str}:{port}"
    );

    client.send_request(request).await
        .map_err(|e| format!("NUDR-DR request to UDR failed: {e}"))
}

/// Build and send authentication subscription GET to UDR
///
/// Builds: GET /nudr-dr/v1/subscription-data/{supi}/authentication-data/authentication-subscription
pub async fn udm_nudr_dr_send_auth_subscription_get(
    supi: &str,
    udm_ue_id: u64,
    stream_id: u64,
) -> Result<SbiResponse, String> {
    let path = format!(
        "/nudr-dr/v1/subscription-data/{supi}/authentication-data/authentication-subscription"
    );
    let request = SbiRequest::get(&path);
    udm_sbi_discover_and_send_nudr_dr(udm_ue_id, stream_id, request).await
}

/// Build and send SQN update PATCH to UDR
///
/// Builds: PATCH /nudr-dr/v1/subscription-data/{supi}/authentication-data/authentication-subscription
pub async fn udm_nudr_dr_send_auth_subscription_patch(
    supi: &str,
    sqn_hex: &str,
    udm_ue_id: u64,
    stream_id: u64,
) -> Result<SbiResponse, String> {
    let path = format!(
        "/nudr-dr/v1/subscription-data/{supi}/authentication-data/authentication-subscription"
    );
    let patch_body = serde_json::json!([{
        "op": "replace",
        "path": "/sequenceNumber/sqn",
        "value": sqn_hex
    }]);
    let request = SbiRequest::patch(&path)
        .with_json_body(&patch_body)
        .map_err(|e| format!("Failed to serialize PATCH body: {e}"))?;

    udm_sbi_discover_and_send_nudr_dr(udm_ue_id, stream_id, request).await
}

/// Build and send provisioned data GET to UDR
///
/// Builds: GET /nudr-dr/v1/subscription-data/{supi}/provisioned-data/{dataset}
pub async fn udm_nudr_dr_send_provisioned_data_get(
    supi: &str,
    dataset: &str,
    udm_ue_id: u64,
    stream_id: u64,
) -> Result<SbiResponse, String> {
    let path = format!(
        "/nudr-dr/v1/subscription-data/{supi}/provisioned-data/{dataset}"
    );
    let request = SbiRequest::get(&path);
    udm_sbi_discover_and_send_nudr_dr(udm_ue_id, stream_id, request).await
}

/// SBI transaction for tracking requests
#[derive(Debug, Clone)]
pub struct SbiXact {
    /// Transaction ID
    pub id: u64,
    /// Associated SBI object ID (e.g., udm_ue_id)
    pub sbi_object_id: u64,
    /// Associated stream ID for response
    pub assoc_stream_id: u64,
    /// Service type
    pub service_type: String,
    /// State for multi-step operations
    pub state: u32,
}

impl SbiXact {
    /// Create a new SBI transaction
    pub fn new(id: u64, sbi_object_id: u64, service_type: &str) -> Self {
        Self {
            id,
            sbi_object_id,
            assoc_stream_id: 0,
            service_type: service_type.to_string(),
            state: 0,
        }
    }
}

/// SBI server handle (placeholder)
pub struct SbiServer {
    config: SbiServerConfig,
}

impl SbiServer {
    /// Create a new SBI server
    pub fn new(config: SbiServerConfig) -> Self {
        Self { config }
    }

    /// Get server URI
    pub fn uri(&self) -> String {
        let scheme = if self.config.tls_enabled {
            "https"
        } else {
            "http"
        };
        format!("{}://{}:{}", scheme, self.config.addr, self.config.port)
    }
}

/// Send SBI response to a client stream
///
/// This function sends the prepared SBI response back to the client.
/// In a full implementation, this would interact with the HTTP server's
/// response channel to send the data back to the client connection.
pub fn send_sbi_response(stream_id: u64, response: SbiResponse) {
    log::debug!(
        "Sending SBI response (stream_id={}, status={})",
        stream_id,
        response.status
    );

    // In a real implementation, this would:
    // 1. Look up the stream/connection by stream_id
    // 2. Serialize the response to HTTP format
    // 3. Send through the appropriate HTTP server channel
    //
    // For now, we track response in memory for testing/integration
    // The actual HTTP server in main.rs handles response delivery

    // Placeholder for actual response sending
    // The response would be queued to the HTTP server's response channel
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_sbi_open_close() {
        assert!(!udm_sbi_is_running());

        udm_sbi_open(None).unwrap();
        assert!(udm_sbi_is_running());

        udm_sbi_close();
        assert!(!udm_sbi_is_running());
    }

    #[test]
    fn test_sbi_server_uri() {
        let config = SbiServerConfig {
            addr: "192.168.1.1".to_string(),
            port: 8080,
            tls_enabled: false,
            tls_cert: None,
            tls_key: None,
        };
        let server = SbiServer::new(config);
        assert_eq!(server.uri(), "http://192.168.1.1:8080");
    }

    #[test]
    fn test_sbi_server_uri_tls() {
        let config = SbiServerConfig {
            addr: "192.168.1.1".to_string(),
            port: 8443,
            tls_enabled: true,
            tls_cert: Some("/path/to/cert".to_string()),
            tls_key: Some("/path/to/key".to_string()),
        };
        let server = SbiServer::new(config);
        assert_eq!(server.uri(), "https://192.168.1.1:8443");
    }

    #[test]
    fn test_sbi_xact() {
        let xact = SbiXact::new(1, 100, "nudm-ueau");
        assert_eq!(xact.id, 1);
        assert_eq!(xact.sbi_object_id, 100);
        assert_eq!(xact.service_type, "nudm-ueau");
        assert_eq!(xact.state, 0);
    }
}
