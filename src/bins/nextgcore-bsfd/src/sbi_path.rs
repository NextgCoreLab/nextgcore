//! BSF SBI Path Functions
//!
//! Port of src/bsf/sbi-path.c - SBI server/client path functions

use std::sync::atomic::{AtomicBool, Ordering};

use ogs_sbi::context::{global_context, NfInstance, NfService};
use ogs_sbi::types::{NfType, SbiServiceType, UriScheme};

/// SBI server configuration
#[derive(Debug, Clone)]
pub struct SbiServerConfig {
    pub addr: String,
    pub port: u16,
    pub tls_enabled: bool,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub nrf_uri: Option<String>,
}

impl Default for SbiServerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1".to_string(),
            port: 7777,
            tls_enabled: false,
            tls_cert: None,
            tls_key: None,
            nrf_uri: None,
        }
    }
}

/// SBI server state
static SBI_SERVER_RUNNING: AtomicBool = AtomicBool::new(false);

/// Parse host and port from a URI string (e.g., "http://127.0.0.1:7777")
fn parse_uri_host_port(uri_str: &str) -> Result<(String, u16), String> {
    let stripped = uri_str
        .strip_prefix("https://")
        .or_else(|| uri_str.strip_prefix("http://"))
        .unwrap_or(uri_str);
    let (host, port_str) = if let Some(idx) = stripped.rfind(':') {
        (&stripped[..idx], &stripped[idx + 1..])
    } else {
        (stripped, if uri_str.starts_with("https") { "443" } else { "80" })
    };
    let port: u16 = port_str
        .split('/')
        .next()
        .unwrap_or(port_str)
        .parse()
        .map_err(|e| format!("Invalid port in URI: {}", e))?;
    Ok((host.to_string(), port))
}

/// Build the BSF NF instance with service information
fn build_bsf_nf_instance(config: &SbiServerConfig) -> NfInstance {
    let nf_id = uuid::Uuid::new_v4().to_string();
    let mut nf_instance = NfInstance::new(&nf_id, NfType::Bsf);

    nf_instance.ipv4_addresses.push(config.addr.clone());
    nf_instance.heartbeat_interval = 10;

    let scheme = if config.tls_enabled {
        UriScheme::Https
    } else {
        UriScheme::Http
    };

    // nbsf-management service (allowed: PCF, AF)
    let mut bsf_svc = NfService::new(
        SbiServiceType::NbsfManagement.to_name(),
        SbiServiceType::NbsfManagement,
    );
    bsf_svc.scheme = scheme;
    bsf_svc.ip_addresses.push(config.addr.clone());
    bsf_svc.port = config.port;
    nf_instance.add_service(bsf_svc);

    nf_instance
}

/// Register BSF NF instance with NRF
async fn register_with_nrf(nrf_uri: &str, nf_instance: &NfInstance) -> Result<(), String> {
    let (host, port) = parse_uri_host_port(nrf_uri)?;

    let ctx = global_context();
    let client = ctx.get_client(&host, port).await;

    let register_path = format!(
        "/nnrf-nfm/v1/nf-instances/{}",
        nf_instance.id
    );

    let body = serde_json::json!({
        "nfInstanceId": nf_instance.id,
        "nfType": "BSF",
        "nfStatus": "REGISTERED",
        "heartBeatTimer": nf_instance.heartbeat_interval,
        "ipv4Addresses": nf_instance.ipv4_addresses,
        "nfServices": nf_instance.services.iter().map(|s| {
            serde_json::json!({
                "serviceName": s.name,
                "versions": s.versions.iter().map(|v| {
                    serde_json::json!({"apiVersionInUri": v, "apiFullVersion": format!("{}.0.0", v)})
                }).collect::<Vec<_>>(),
                "scheme": s.scheme.as_str(),
                "nfServiceStatus": "REGISTERED",
            })
        }).collect::<Vec<_>>(),
    });

    match client
        .put_json(&register_path, &body)
        .await
    {
        Ok(response) => {
            let status = response.status;
            if status == 200 || status == 201 {
                log::info!(
                    "BSF registered with NRF (id={}, status={})",
                    nf_instance.id,
                    status
                );
                Ok(())
            } else {
                log::warn!(
                    "NRF registration returned status {}: {:?}",
                    status,
                    response.http.content
                );
                Ok(())
            }
        }
        Err(e) => {
            log::warn!("NRF registration failed (BSF will operate standalone): {}", e);
            Ok(())
        }
    }
}

/// Open SBI server and register with NRF
/// Port of bsf_sbi_open
pub fn bsf_sbi_open(config: Option<SbiServerConfig>) -> Result<(), String> {
    if SBI_SERVER_RUNNING.load(Ordering::SeqCst) {
        return Err("SBI server already running".to_string());
    }

    let config = config.unwrap_or_default();

    log::info!(
        "Opening BSF SBI server on {}:{}",
        config.addr,
        config.port
    );

    // Build and register the BSF NF instance
    let nf_instance = build_bsf_nf_instance(&config);
    let nf_id = nf_instance.id.clone();
    let nrf_uri_clone = config.nrf_uri.clone();
    let nf_clone = nf_instance.clone();

    // Attempt async registration (only if tokio runtime is available)
    let sbi_ctx = global_context();
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            sbi_ctx.set_self_instance(nf_clone).await;
            if let Some(ref nrf_uri) = nrf_uri_clone {
                sbi_ctx.set_nrf_uri(nrf_uri).await;
                if let Err(e) = register_with_nrf(nrf_uri, &nf_instance).await {
                    log::error!("Failed to register BSF with NRF: {}", e);
                }
            } else {
                log::info!("No NRF URI configured, BSF running in standalone mode");
            }
        });
    } else {
        log::debug!("No tokio runtime available, skipping async NRF registration");
    }

    log::info!("BSF NF instance built (id={})", nf_id);

    SBI_SERVER_RUNNING.store(true, Ordering::SeqCst);

    log::info!("BSF SBI server opened successfully");
    Ok(())
}

/// Close SBI server and deregister from NRF
/// Port of bsf_sbi_close
pub fn bsf_sbi_close() {
    if !SBI_SERVER_RUNNING.load(Ordering::SeqCst) {
        return;
    }

    log::info!("Closing BSF SBI server");

    // Attempt async deregistration (only if tokio runtime is available)
    let sbi_ctx = global_context();
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            if let (Some(nrf_uri), Some(self_instance)) = (
                sbi_ctx.get_nrf_uri().await,
                sbi_ctx.get_self_instance().await,
            ) {
                if let Ok((host, port)) = parse_uri_host_port(&nrf_uri) {
                    let client = sbi_ctx.get_client(&host, port).await;
                    let path = format!("/nnrf-nfm/v1/nf-instances/{}", self_instance.id);
                    if let Err(e) = client.delete(&path).await {
                        log::warn!("Failed to deregister BSF from NRF: {}", e);
                    } else {
                        log::info!("BSF deregistered from NRF");
                    }
                }
            }
            sbi_ctx.clear_clients().await;
        });
    }

    SBI_SERVER_RUNNING.store(false, Ordering::SeqCst);

    log::info!("BSF SBI server closed");
}

/// Check if SBI server is running
pub fn bsf_sbi_is_running() -> bool {
    SBI_SERVER_RUNNING.load(Ordering::SeqCst)
}


/// SBI request builder function type
pub type PathSbiRequestBuilder = fn(sess_id: u64, data: &dyn std::any::Any) -> Option<PathSbiRequest>;

/// Simplified SBI request for path operations
#[derive(Debug, Clone)]
pub struct PathSbiRequest {
    pub method: String,
    pub uri: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// SBI transaction for tracking requests
#[derive(Debug)]
pub struct SbiXact {
    pub id: u64,
    pub sess_id: u64,
    pub stream_id: u64,
    pub service_type: String,
}

/// Send SBI request to NF instance
/// Port of bsf_sbi_send_request
pub fn bsf_sbi_send_request(nf_instance_id: &str, request: PathSbiRequest) -> Result<u64, String> {
    log::debug!(
        "Sending SBI request to NF instance [{}]: {} {}",
        nf_instance_id,
        request.method,
        request.uri
    );

    // Note: SBI request sending requires HTTP client integration
    // In C: ogs_sbi_send_request_to_nf_instance(nf_instance, xact)
    // The actual HTTP client would send the request and handle the response

    // Return transaction ID (placeholder)
    Ok(1)
}

/// Discover NF and send request
/// Port of bsf_sbi_discover_and_send
pub fn bsf_sbi_discover_and_send(
    service_type: &str,
    sess_id: u64,
    stream_id: u64,
    _request: PathSbiRequest,
) -> Result<u64, String> {
    log::debug!(
        "Discover and send: service_type={}, sess_id={}, stream_id={}",
        service_type,
        sess_id,
        stream_id
    );

    // Note: SBI transaction tracking and NF discovery require NRF integration
    // In C: ogs_sbi_xact_add(...) creates a transaction
    // In C: ogs_sbi_discover_and_send(xact) discovers and sends to target NF

    // Return transaction ID (placeholder)
    Ok(1)
}

/// Send SBI response
/// Port of bsf_sbi_send_response
pub fn bsf_sbi_send_response(stream_id: u64, status: u16) -> Result<(), String> {
    log::debug!("Sending SBI response: stream_id={}, status={}", stream_id, status);

    // Note: Build and send response through HTTP server
    // In C: ogs_sbi_build_response(&sendmsg, status)
    // In C: ogs_sbi_server_send_response(stream, response)
    // The actual response is sent by the HTTP handler in main.rs

    Ok(())
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

        let result = bsf_sbi_open(None);
        assert!(result.is_ok());
        assert!(bsf_sbi_is_running());

        // Try to open again while running - should fail
        let result = bsf_sbi_open(None);
        assert!(result.is_err());

        bsf_sbi_close();
        assert!(!bsf_sbi_is_running());
    }

    #[test]
    fn test_sbi_request() {
        let request = PathSbiRequest {
            method: "POST".to_string(),
            uri: "/nbsf-management/v1/pcf-bindings".to_string(),
            headers: vec![],
            body: None,
        };
        assert_eq!(request.method, "POST");
    }

    #[test]
    fn test_sbi_send_response() {
        let result = bsf_sbi_send_response(1, 200);
        assert!(result.is_ok());
    }
}
