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
        (
            stripped,
            if uri_str.starts_with("https") {
                "443"
            } else {
                "80"
            },
        )
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

    let register_path = format!("/nnrf-nfm/v1/nf-instances/{}", nf_instance.id);

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

    match client.put_json(&register_path, &body).await {
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
                    status, response.http.content
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

    log::info!("Opening PCF SBI server on {}:{}", config.addr, config.port);

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

// ---------------------------------------------------------------------------
// Outbound notification delivery (real HTTP POST — TS 29.507/29.512/29.514)
// ---------------------------------------------------------------------------

/// Extract the path component of a URI ("/a/b" from "http://h:p/a/b").
fn uri_path(uri: &str) -> String {
    let stripped = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    match stripped.find('/') {
        Some(idx) => stripped[idx..].to_string(),
        None => String::new(),
    }
}

/// POST a notification body to `{notification_uri}{suffix}` with bounded
/// connect/request timeouts. Returns the HTTP status on success.
pub async fn send_notification_post(
    notification_uri: &str,
    suffix: &str,
    body: &serde_json::Value,
) -> Result<u16, String> {
    use ogs_sbi::client::{SbiClient, SbiClientConfig};
    use std::time::Duration;

    let (host, port) = parse_uri_host_port(notification_uri)?;
    let path = format!("{}{}", uri_path(notification_uri), suffix);
    let client = SbiClient::new(
        SbiClientConfig::new(host, port)
            .with_connect_timeout(Duration::from_secs(2))
            .with_request_timeout(Duration::from_secs(3)),
    );
    let resp = client
        .post_json(&path, body)
        .await
        .map_err(|e| format!("notification POST {path} failed: {e}"))?;
    Ok(resp.status)
}

/// Spawn an async notification POST (fire-and-forget for sync call sites).
fn spawn_notification(uri: String, suffix: &'static str, body: serde_json::Value, what: &'static str) -> bool {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn(async move {
                match send_notification_post(&uri, suffix, &body).await {
                    Ok(status) if (200..300).contains(&status) => {
                        log::info!("{what} notification delivered ({status}) to {uri}{suffix}");
                    }
                    Ok(status) => {
                        log::warn!("{what} notification rejected ({status}) by {uri}{suffix}");
                    }
                    Err(e) => log::warn!("{what} notification failed: {e}"),
                }
            });
            true
        }
        Err(_) => {
            log::warn!("{what} notification skipped: no async runtime");
            false
        }
    }
}

/// Send AM policy control update notify to the AMF over HTTP
/// (TS 29.507 §4.2.3: POST {notificationUri}/update with PolicyUpdate).
pub fn pcf_sbi_send_am_policy_control_notify(pcf_ue_am_id: u64) -> bool {
    // Copy out what we need, then drop the guards (lock-order rule).
    let info = crate::context::pcf_self().read().ok().and_then(|ctx| {
        ctx.ue_am_find_by_id(pcf_ue_am_id)
            .and_then(|ue| ue.notification_uri.clone().map(|uri| (uri, ue.association_id)))
    });
    let Some((uri, association_id)) = info else {
        log::warn!("[ue_am_id={pcf_ue_am_id}] AM policy notify: no notification URI stored");
        return false;
    };

    let body = serde_json::json!({
        "resourceUri": format!("/npcf-am-policy-control/v1/policies/{association_id}"),
        "triggers": [],
    });
    spawn_notification(uri, "/update", body, "AM policy update")
}

/// Send SM policy control create response
/// Port of pcf_sbi_send_smpolicycontrol_create_response() from sbi-path.c
pub fn pcf_sbi_send_smpolicycontrol_create_response(sess_id: u64, stream_id: u64) -> bool {
    log::debug!(
        "[sess_id={sess_id}, stream_id={stream_id}] Sending SM policy control create response"
    );
    // Response building and sending is handled by the HTTP handler in main.rs
    true
}

/// Build the SmPolicyNotification body for a session (TS 29.512 §5.6.2.7).
fn build_sm_policy_notification(sess: &crate::context::PcfSess) -> serde_json::Value {
    // Re-evaluate the policy decision for the session from subscription data
    let dnn = sess.dnn.clone().unwrap_or_else(|| "internet".to_string());
    let decision = crate::nudr_handler::pcf_get_session_data("", None, &sess.s_nssai, &dnn)
        .map(|sd| {
            let parts = crate::build_sm_policy_decision(&sess.sm_policy_id, &sd);
            serde_json::json!({
                "sessRules": parts.sess_rules,
                "pccRules": parts.pcc_rules,
                "qosDecs": parts.qos_decs,
                "chgDecs": parts.chg_decs,
                "traffContDecs": parts.traff_cont_decs,
            })
        })
        .unwrap_or_else(|| serde_json::json!({}));

    serde_json::json!({
        "resourceUri": format!("/npcf-smpolicycontrol/v1/sm-policies/{}", sess.sm_policy_id),
        "smPolicyDecision": decision,
    })
}

/// Send SM policy control update notify to the SMF over HTTP
/// (TS 29.512 §4.2.3.2: POST {notificationUri}/update with
/// SmPolicyNotification).
pub fn pcf_sbi_send_smpolicycontrol_update_notify(sess_id: u64) -> bool {
    // Copy out the session, then drop the guard (lock-order rule).
    let sess = crate::context::pcf_self()
        .read()
        .ok()
        .and_then(|ctx| ctx.sess_find_by_id(sess_id));
    let Some(sess) = sess else {
        log::warn!("[sess_id={sess_id}] SM policy update notify: session not found");
        return false;
    };
    let Some(uri) = sess.notification_uri.clone() else {
        log::warn!("[sess_id={sess_id}] SM policy update notify: no notification URI stored");
        return false;
    };
    let body = build_sm_policy_notification(&sess);
    spawn_notification(uri, "/update", body, "SM policy update")
}

/// Send SM policy control delete notify to the SMF over HTTP: an update
/// notification removing the PCC rules installed for the app session
/// (TS 29.512 — a null PCC-rule entry means removal).
pub fn pcf_sbi_send_smpolicycontrol_delete_notify(sess_id: u64, app_session_id: u64) -> bool {
    let sess = crate::context::pcf_self()
        .read()
        .ok()
        .and_then(|ctx| ctx.sess_find_by_id(sess_id));
    let Some(sess) = sess else {
        log::warn!("[sess_id={sess_id}] SM policy delete notify: session not found");
        return false;
    };
    let Some(uri) = sess.notification_uri.clone() else {
        log::warn!("[sess_id={sess_id}] SM policy delete notify: no notification URI stored");
        return false;
    };
    let rule_id = format!("PccRule-app-{app_session_id}");
    let body = serde_json::json!({
        "resourceUri": format!("/npcf-smpolicycontrol/v1/sm-policies/{}", sess.sm_policy_id),
        "smPolicyDecision": { "pccRules": { rule_id: null } },
    });
    spawn_notification(uri, "/update", body, "SM policy delete")
}

/// Send policy authorization terminate notify to the AF over HTTP
/// (TS 29.514 §4.2.5.2: POST {notifUri}/terminate with TerminationInfo).
pub fn pcf_sbi_send_policyauthorization_terminate_notify(app_id: u64) -> bool {
    let info = crate::context::pcf_self().read().ok().and_then(|ctx| {
        ctx.app_find_by_id(app_id)
            .and_then(|app| app.notif_uri.clone().map(|uri| (uri, app.app_session_id)))
    });
    let Some((uri, app_session_id)) = info else {
        log::warn!("[app_id={app_id}] AF terminate notify: no notification URI stored");
        return false;
    };
    let body = serde_json::json!({
        "resUri": format!("/npcf-policyauthorization/v1/app-sessions/{app_session_id}"),
        "termCause": "PDU_SESSION_TERMINATION",
    });
    spawn_notification(uri, "/terminate", body, "AF terminate")
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
    log::debug!("[sess_id={sess_id}, stream_id={stream_id}] Discover and send to {service_type}");

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

    #[test]
    fn test_uri_path_extraction() {
        assert_eq!(
            uri_path("http://1.2.3.4:7777/nsmf-callback/v1/sm-policy-notify/3"),
            "/nsmf-callback/v1/sm-policy-notify/3"
        );
        assert_eq!(uri_path("http://1.2.3.4:7777"), "");
    }

    /// The notify callbacks are real HTTP POSTs: a stub "SMF" server on an
    /// ephemeral port receives POST {notificationUri}/update with the
    /// SmPolicyNotification body (bounded timeouts both directions).
    #[tokio::test]
    async fn notification_post_round_trip() {
        use ogs_sbi::message::{SbiRequest as Req, SbiResponse as Resp};
        use ogs_sbi::server::{SbiServer, SbiServerConfig};
        use std::time::Duration;

        async fn stub_smf(req: Req) -> Resp {
            let path = req.header.uri.split('?').next().unwrap_or("").to_string();
            if req.header.method == "POST"
                && path == "/nsmf-callback/v1/sm-policy-notify/42/update"
            {
                // Body must be an SmPolicyNotification with resourceUri
                let ok = req
                    .http
                    .content
                    .as_deref()
                    .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
                    .map(|v| v.get("resourceUri").is_some())
                    .unwrap_or(false);
                return if ok {
                    Resp::with_status(204)
                } else {
                    Resp::with_status(400)
                };
            }
            if req.header.method == "POST" && path.ends_with("/terminate") {
                return Resp::with_status(204);
            }
            Resp::with_status(404)
        }

        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .map(|a| a.port())
            .expect("probe ephemeral port");
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let server = SbiServer::new(SbiServerConfig::new(addr));
        server.start(stub_smf).await.expect("start stub SMF");

        let uri = format!("http://127.0.0.1:{port}/nsmf-callback/v1/sm-policy-notify/42");
        let body = serde_json::json!({
            "resourceUri": "/npcf-smpolicycontrol/v1/sm-policies/42",
            "smPolicyDecision": {}
        });

        let status = tokio::time::timeout(
            Duration::from_secs(8),
            send_notification_post(&uri, "/update", &body),
        )
        .await
        .expect("bounded")
        .expect("notification delivered");
        assert_eq!(status, 204);

        // Terminate suffix path
        let status = tokio::time::timeout(
            Duration::from_secs(8),
            send_notification_post(&uri, "/terminate", &body),
        )
        .await
        .expect("bounded")
        .expect("terminate delivered");
        assert_eq!(status, 204);

        // Unreachable receiver → bounded error, not a hang
        let dead_port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .map(|a| a.port())
            .unwrap();
        let dead_uri = format!("http://127.0.0.1:{dead_port}/cb");
        let res = tokio::time::timeout(
            Duration::from_secs(8),
            send_notification_post(&dead_uri, "/update", &body),
        )
        .await
        .expect("bounded");
        assert!(res.is_err());

        server.stop().await.ok();
    }
}
