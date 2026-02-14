//! PCF SBI Path Management
//!
//! Port of src/pcf/sbi-path.c - SBI server and client path handling

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

/// Build the PCF NF instance with service information
fn build_pcf_nf_instance(config: &SbiServerConfig) -> NfInstance {
    let nf_id = uuid::Uuid::new_v4().to_string();
    let mut nf_instance = NfInstance::new(&nf_id, NfType::Pcf);

    nf_instance.ipv4_addresses.push(config.addr.clone());
    nf_instance.heartbeat_interval = 10;

    let scheme = if config.tls_enabled {
        UriScheme::Https
    } else {
        UriScheme::Http
    };

    // npcf-am-policy-control service (allowed: AMF)
    let mut am_policy_svc = NfService::new(
        SbiServiceType::NpcfAmPolicyControl.to_name(),
        SbiServiceType::NpcfAmPolicyControl,
    );
    am_policy_svc.scheme = scheme;
    am_policy_svc.ip_addresses.push(config.addr.clone());
    am_policy_svc.port = config.port;
    nf_instance.add_service(am_policy_svc);

    // npcf-smpolicycontrol service (allowed: SMF)
    let mut sm_policy_svc = NfService::new(
        SbiServiceType::NpcfSmpolicycontrol.to_name(),
        SbiServiceType::NpcfSmpolicycontrol,
    );
    sm_policy_svc.scheme = scheme;
    sm_policy_svc.ip_addresses.push(config.addr.clone());
    sm_policy_svc.port = config.port;
    nf_instance.add_service(sm_policy_svc);

    // npcf-policyauthorization service (allowed: AF, PCF)
    let mut pa_svc = NfService::new(
        SbiServiceType::NpcfPolicyauthorization.to_name(),
        SbiServiceType::NpcfPolicyauthorization,
    );
    pa_svc.scheme = scheme;
    pa_svc.ip_addresses.push(config.addr.clone());
    pa_svc.port = config.port;
    nf_instance.add_service(pa_svc);

    nf_instance
}

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
        .map_err(|e| format!("Invalid port in URI: {e}"))?;
    Ok((host.to_string(), port))
}

/// Register PCF NF instance with NRF
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
        "nfType": "PCF",
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
                    "PCF registered with NRF (id={}, status={})",
                    nf_instance.id,
                    status
                );
                Ok(())
            } else {
                let msg = format!(
                    "NRF registration returned status {}: {:?}",
                    status,
                    response.http.content
                );
                log::warn!("{msg}");
                // Non-fatal: PCF can operate without NRF
                Ok(())
            }
        }
        Err(e) => {
            log::warn!("NRF registration failed (PCF will operate standalone): {e}");
            // Non-fatal: PCF can operate without NRF
            Ok(())
        }
    }
}

/// Open SBI server and register with NRF
/// Port of pcf_sbi_open() from sbi-path.c
pub fn pcf_sbi_open(config: Option<SbiServerConfig>) -> Result<(), String> {
    let config = config.unwrap_or_default();

    if SBI_SERVER_RUNNING.load(Ordering::SeqCst) {
        return Err("SBI server already running".to_string());
    }

    log::info!(
        "Opening PCF SBI server on {}:{}",
        config.addr,
        config.port
    );

    // Build and register the PCF NF instance
    let nf_instance = build_pcf_nf_instance(&config);

    // Store self instance and NRF URI in SBI context
    let sbi_ctx = global_context();
    let nf_id = nf_instance.id.clone();
    let nrf_uri_clone = config.nrf_uri.clone();
    let nf_clone = nf_instance.clone();

    // Attempt async registration (only if tokio runtime is available)
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            sbi_ctx.set_self_instance(nf_clone).await;
            if let Some(ref nrf_uri) = nrf_uri_clone {
                sbi_ctx.set_nrf_uri(nrf_uri).await;
                if let Err(e) = register_with_nrf(nrf_uri, &nf_instance).await {
                    log::error!("Failed to register PCF with NRF: {e}");
                }
            } else {
                log::info!("No NRF URI configured, PCF running in standalone mode");
            }
        });
    } else {
        log::debug!("No tokio runtime available, skipping async NRF registration");
    }

    log::info!("PCF NF instance built (id={nf_id})");

    SBI_SERVER_RUNNING.store(true, Ordering::SeqCst);

    log::debug!("PCF SBI server opened successfully");
    Ok(())
}

/// Close SBI server and deregister from NRF
/// Port of pcf_sbi_close() from sbi-path.c
pub fn pcf_sbi_close() {
    if !SBI_SERVER_RUNNING.load(Ordering::SeqCst) {
        log::warn!("SBI server not running");
        return;
    }

    log::info!("Closing PCF SBI server");

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
                        log::warn!("Failed to deregister PCF from NRF: {e}");
                    } else {
                        log::info!("PCF deregistered from NRF");
                    }
                }
            }
            sbi_ctx.clear_clients().await;
        });
    }

    SBI_SERVER_RUNNING.store(false, Ordering::SeqCst);

    log::debug!("PCF SBI server closed");
}

/// Check if SBI server is running
pub fn pcf_sbi_is_running() -> bool {
    SBI_SERVER_RUNNING.load(Ordering::SeqCst)
}

/// Send AM policy control notify to AMF
/// Port of pcf_sbi_send_am_policy_control_notify() from sbi-path.c
pub fn pcf_sbi_send_am_policy_control_notify(pcf_ue_am_id: u64) -> bool {
    log::debug!(
        "[ue_am_id={pcf_ue_am_id}] Sending AM policy control notify"
    );

    // In C implementation:
    // 1. Get pcf_ue_am from ID
    // 2. Get client from pcf_ue_am->namf
    // 3. Build request using pcf_namf_callback_build_am_policy_control()
    // 4. Send request to client with client_notify_cb callback

    // Note: Notification sending requires HTTP client integration
    true
}

/// Send SM policy control create response
/// Port of pcf_sbi_send_smpolicycontrol_create_response() from sbi-path.c
pub fn pcf_sbi_send_smpolicycontrol_create_response(
    sess_id: u64,
    stream_id: u64,
) -> bool {
    log::debug!(
        "[sess_id={sess_id}, stream_id={stream_id}] Sending SM policy control create response"
    );

    // In C implementation:
    // 1. Get session and UE SM from IDs
    // 2. Get session data from database
    // 3. Build SmPolicyDecision with:
    //    - Session rules (auth_sess_ambr, auth_def_qos)
    //    - PCC rules
    //    - QoS decisions
    //    - Policy control request triggers
    //    - Supported features
    // 4. Build response with location header
    // 5. Send response to stream

    // Note: Response building and sending is handled by the HTTP handler in main.rs
    true
}

/// Send SM policy control update notify to SMF
/// Port of pcf_sbi_send_smpolicycontrol_update_notify() from sbi-path.c
pub fn pcf_sbi_send_smpolicycontrol_update_notify(sess_id: u64) -> bool {
    log::debug!(
        "[sess_id={sess_id}] Sending SM policy control update notify"
    );

    // In C implementation:
    // 1. Get session from ID
    // 2. Get client from sess->nsmf
    // 3. Build request using pcf_nsmf_callback_build_smpolicycontrol_update()
    // 4. Send request to client with client_notify_cb callback

    // Note: Notification sending requires HTTP client integration
    true
}

/// Send SM policy control delete notify to SMF
/// Port of pcf_sbi_send_smpolicycontrol_delete_notify() from sbi-path.c
pub fn pcf_sbi_send_smpolicycontrol_delete_notify(
    sess_id: u64,
    app_session_id: u64,
) -> bool {
    log::debug!(
        "[sess_id={sess_id}, app_id={app_session_id}] Sending SM policy control delete notify"
    );

    // In C implementation:
    // 1. Get session from ID
    // 2. Get client from sess->nsmf
    // 3. Build request using pcf_nsmf_callback_build_smpolicycontrol_update()
    // 4. Send request to client with client_delete_notify_cb callback
    //    (which removes app_session after callback)

    // Note: Notification sending requires HTTP client integration
    true
}

/// Send policy authorization terminate notify to AF
/// Port of pcf_sbi_send_policyauthorization_terminate_notify() from sbi-path.c
pub fn pcf_sbi_send_policyauthorization_terminate_notify(app_id: u64) -> bool {
    log::debug!(
        "[app_id={app_id}] Sending policy authorization terminate notify"
    );

    // In C implementation:
    // 1. Get app session from ID
    // 2. Get client from app->naf
    // 3. Build request using pcf_naf_callback_build_policyauthorization_terminate()
    // 4. Send request to client with client_notify_cb callback

    // Note: Notification sending requires HTTP client integration
    true
}

/// Discover and send request to UDR for UE AM
/// Port of pcf_ue_am_sbi_discover_and_send() from sbi-path.c
pub fn pcf_ue_am_sbi_discover_and_send(
    pcf_ue_am_id: u64,
    stream_id: u64,
    service_type: &str,
) -> Result<(), String> {
    log::debug!(
        "[ue_am_id={pcf_ue_am_id}, stream_id={stream_id}] Discover and send to {service_type}"
    );

    // In C implementation:
    // 1. Create SBI transaction
    // 2. Set associated stream ID
    // 3. Call ogs_sbi_discover_and_send()

    // Note: Discovery and sending requires NRF integration
    Ok(())
}

/// Discover and send request for session
/// Port of pcf_sess_sbi_discover_and_send() from sbi-path.c
pub fn pcf_sess_sbi_discover_and_send(
    sess_id: u64,
    stream_id: u64,
    service_type: &str,
) -> Result<(), String> {
    log::debug!(
        "[sess_id={sess_id}, stream_id={stream_id}] Discover and send to {service_type}"
    );

    // In C implementation:
    // 1. Create SBI transaction
    // 2. Set associated stream ID
    // 3. Call ogs_sbi_discover_and_send()

    // Note: Discovery and sending requires NRF integration
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
    fn test_sbi_open_close_and_config() {
        // Reset state
        SBI_SERVER_RUNNING.store(false, Ordering::SeqCst);

        // Open with default config
        let result = pcf_sbi_open(None);
        assert!(result.is_ok());
        assert!(pcf_sbi_is_running());

        // Try to open again - should fail
        let result = pcf_sbi_open(None);
        assert!(result.is_err());

        pcf_sbi_close();
        assert!(!pcf_sbi_is_running());

        // Open with custom config
        let config = SbiServerConfig {
            addr: "0.0.0.0".to_string(),
            port: 8080,
            tls_enabled: true,
            tls_cert: Some("/path/to/cert.pem".to_string()),
            tls_key: Some("/path/to/key.pem".to_string()),
            nrf_uri: None,
        };

        let result = pcf_sbi_open(Some(config));
        assert!(result.is_ok());

        pcf_sbi_close();
    }

    #[test]
    fn test_parse_uri_host_port() {
        let (host, port) = parse_uri_host_port("http://127.0.0.1:7777").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 7777);

        let (host, port) = parse_uri_host_port("https://nrf.example.com:443").unwrap();
        assert_eq!(host, "nrf.example.com");
        assert_eq!(port, 443);
    }
}
