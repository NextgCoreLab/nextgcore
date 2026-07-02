//! PCF SBI Path Management
//!
//! Port of src/pcf/sbi-path.c - SBI server and client path handling

use std::sync::atomic::{AtomicBool, Ordering};

use nextgcore_sbi::context::{global_context, NfInstance, NfService};
use nextgcore_sbi::types::{NfType, SbiServiceType, UriScheme};

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

    // npcf-ue-policy-control service (allowed: AMF) — TS 29.525
    let mut ue_policy_svc = NfService::new(
        SbiServiceType::NpcfUePolicyControl.to_name(),
        SbiServiceType::NpcfUePolicyControl,
    );
    ue_policy_svc.scheme = scheme;
    ue_policy_svc.ip_addresses.push(config.addr.clone());
    ue_policy_svc.port = config.port;
    nf_instance.add_service(ue_policy_svc);

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
    use nextgcore_sbi::client::{SbiClient, SbiClientConfig};
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
fn spawn_notification(
    uri: String,
    suffix: &'static str,
    body: serde_json::Value,
    what: &'static str,
) -> bool {
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
        ctx.ue_am_find_by_id(pcf_ue_am_id).and_then(|ue| {
            ue.notification_uri
                .clone()
                .map(|uri| (uri, ue.association_id))
        })
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
            let parts = crate::sm_policy_build::build_sm_policy_decision(&sess.sm_policy_id, &sd);
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

/// Send an SM policy control update notify to the SMF carrying the AF-derived
/// PCC rules stored on the session (TS 29.514 PolicyAuthorization → TS 29.512
/// §4.2.3.2). Unlike `pcf_sbi_send_smpolicycontrol_update_notify` (which
/// re-derives the subscription decision), this pushes the
/// media-component-installed PccRule/QosData decisions.
pub fn pcf_sbi_send_af_smpolicycontrol_update_notify(sess_id: u64) -> bool {
    let sess = crate::context::pcf_self()
        .read()
        .ok()
        .and_then(|ctx| ctx.sess_find_by_id(sess_id));
    let Some(sess) = sess else {
        log::warn!("[sess_id={sess_id}] AF SM policy update notify: session not found");
        return false;
    };
    let Some(uri) = sess.notification_uri.clone() else {
        log::warn!("[sess_id={sess_id}] AF SM policy update notify: no notification URI stored");
        return false;
    };
    let body = crate::npcf_handler::build_af_sm_policy_notification(&sess);
    spawn_notification(uri, "/update", body, "AF SM policy update")
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
    // 3. Call nextgcore_sbi_discover_and_send()

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
    // 3. Call nextgcore_sbi_discover_and_send()

    // Note: Discovery and sending requires NRF integration
    Ok(())
}

// ---------------------------------------------------------------------------
// Real NRF NF-discovery + nudr-dr GET / nbsf-management binding wiring (pcfd-09)
//
// These helpers implement the real discover-and-send mechanism the PCF needs to
// retrieve UDR PolicyData (TS 29.519 nudr-dr) and register/deregister a BSF
// binding (TS 29.521 Nbsf_Management) over the shared nextgcore-sbi client.
//
// FLAGGED (deferred E2E): invoking these from the live SM-policy create/delete
// path against real udrd/bsfd is the deferred, E2E-gated pcfd-04 work. The
// mechanism here is unit-tested against mock NRF/UDR/BSF servers (see tests).
// The live SM/AM policy create path is intentionally unchanged so nothing that
// currently passes can newly fail.
// ---------------------------------------------------------------------------

/// A discovered NF service endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredEndpoint {
    pub host: String,
    pub port: u16,
    pub scheme: String,
}

/// Minimal RFC 3986 percent-encoding for a query-string value (no external dep).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Parse the first matching service endpoint from an NRF SearchResult body.
fn parse_first_endpoint(
    json: &serde_json::Value,
    service_name: &str,
) -> Option<DiscoveredEndpoint> {
    let instances = json.get("nfInstances")?.as_array()?;
    for nf in instances {
        let Some(services) = nf.get("nfServices").and_then(|v| v.as_array()) else {
            continue;
        };
        for svc in services {
            if svc.get("serviceName").and_then(|v| v.as_str()) != Some(service_name) {
                continue;
            }
            let scheme = svc
                .get("scheme")
                .and_then(|v| v.as_str())
                .unwrap_or("http")
                .to_string();
            // Prefer the service ipEndPoints; only when the matching service
            // carries no endpoint fall back to the instance-level ipv4Addresses.
            if let Some(ep) = svc
                .get("ipEndPoints")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
            {
                if let Some(host) = ep.get("ipv4Address").and_then(|v| v.as_str()) {
                    let port = ep.get("port").and_then(|v| v.as_u64()).unwrap_or(80) as u16;
                    return Some(DiscoveredEndpoint {
                        host: host.to_string(),
                        port,
                        scheme,
                    });
                }
            }
            if let Some(host) = nf
                .get("ipv4Addresses")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
            {
                return Some(DiscoveredEndpoint {
                    host: host.to_string(),
                    port: 80,
                    scheme,
                });
            }
        }
    }
    None
}

/// Discover the first NF instance of `target_nf_type` exposing `service_name`
/// via the NRF (`GET /nnrf-disc/v1/nf-instances`) and return its endpoint.
/// `Ok(None)` when no NRF is configured or no matching instance is found.
pub async fn pcf_discover_endpoint(
    target_nf_type: &str,
    service_name: &str,
) -> Result<Option<DiscoveredEndpoint>, String> {
    let ctx = global_context();
    let Some(nrf_uri) = ctx.get_nrf_uri().await else {
        log::debug!("No NRF URI configured; cannot discover {target_nf_type}");
        return Ok(None);
    };
    let (nrf_host, nrf_port) = parse_uri_host_port(&nrf_uri)?;
    let client = ctx.get_client(&nrf_host, nrf_port).await;
    let path = format!(
        "/nnrf-disc/v1/nf-instances?target-nf-type={target_nf_type}&requester-nf-type=PCF&service-names={service_name}"
    );
    let response = client
        .get(&path)
        .await
        .map_err(|e| format!("NRF discovery failed: {e}"))?;
    if response.status != 200 {
        return Err(format!("NRF discovery returned status {}", response.status));
    }
    let body = response
        .http
        .content
        .ok_or("Empty NRF discovery response")?;
    let json: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("Invalid NRF discovery response: {e}"))?;
    Ok(parse_first_endpoint(&json, service_name))
}

/// Build a bounded-timeout SBI client for a discovered endpoint.
fn client_for(ep: &DiscoveredEndpoint) -> nextgcore_sbi::client::SbiClient {
    use nextgcore_sbi::client::{SbiClient, SbiClientConfig};
    use std::time::Duration;
    SbiClient::new(
        SbiClientConfig::new(ep.host.clone(), ep.port)
            .with_connect_timeout(Duration::from_secs(2))
            .with_request_timeout(Duration::from_secs(3)),
    )
}

/// Discover a UDR and GET the SM PolicyData for `(supi, snssai, dnn)`
/// (TS 29.519 nudr-dr: `GET /nudr-dr/v2/policy-data/ues/{ueId}/sm-data`).
/// Returns the decoded body on 200, `Ok(None)` on 404 or when no UDR is
/// reachable (caller then falls back to config defaults, as today).
pub async fn pcf_udr_get_sm_policy_data(
    supi: &str,
    snssai_sst: u8,
    snssai_sd: Option<u32>,
    dnn: &str,
) -> Result<Option<serde_json::Value>, String> {
    let Some(ep) = pcf_discover_endpoint("UDR", "nudr-dr").await? else {
        return Ok(None);
    };
    let client = client_for(&ep);
    let snssai = match snssai_sd {
        Some(sd) => format!("{{\"sst\":{snssai_sst},\"sd\":\"{sd:06x}\"}}"),
        None => format!("{{\"sst\":{snssai_sst}}}"),
    };
    let path = format!(
        "/nudr-dr/v2/policy-data/ues/{}/sm-data?snssai={}&dnn={}",
        percent_encode(supi),
        percent_encode(&snssai),
        percent_encode(dnn),
    );
    let resp = client
        .get(&path)
        .await
        .map_err(|e| format!("nudr-dr GET failed: {e}"))?;
    match resp.status {
        200 => {
            let body = resp.http.content.ok_or("empty nudr-dr body")?;
            let json =
                serde_json::from_str(&body).map_err(|e| format!("invalid nudr-dr body: {e}"))?;
            Ok(Some(json))
        }
        404 => {
            log::warn!("nudr-dr returned 404 for SUPI {supi}; using config defaults");
            Ok(None)
        }
        other => Err(format!("nudr-dr GET returned status {other}")),
    }
}

/// Navigate a TS 29.519 SmPolicyData body to the SmPolicyDnnData object for
/// `dnn` (smPolicySnssaiData{*}.smPolicyDnnData{dnn}). Pure/sync for unit tests.
pub fn extract_sm_policy_dnn_data(
    data: &serde_json::Value,
    dnn: &str,
) -> Option<serde_json::Value> {
    let snssai_map = data.get("smPolicySnssaiData")?.as_object()?;
    for (_k, entry) in snssai_map {
        if let Some(dnn_map) = entry.get("smPolicyDnnData").and_then(|v| v.as_object()) {
            if let Some(d) = dnn_map.get(dnn) {
                return Some(d.clone());
            }
        }
    }
    None
}

/// Live-path bounded Nudr_DataRepository GET of the UE's SM PolicyData (TS 29.519),
/// returning the SmPolicyDnnData object for `dnn` when provisioned. `None` on
/// 404 / unreachable / timeout — caller then falls back to local defaults.
pub async fn pcf_udr_sm_policy_dnn_data(
    supi: &str,
    sst: u8,
    sd: Option<u32>,
    dnn: &str,
) -> Option<serde_json::Value> {
    let fut = pcf_udr_get_sm_policy_data(supi, sst, sd, dnn);
    match tokio::time::timeout(std::time::Duration::from_secs(3), fut).await {
        Ok(Ok(Some(v))) => extract_sm_policy_dnn_data(&v, dnn),
        _ => None,
    }
}

/// Discover a UDR and GET the UE PolicySet for `supi`
/// (TS 29.519 §5.4: `GET /nudr-dr/v1/policy-data/ues/{ueId}/ue-policy-set`;
/// the ue-policy-set resource is served at v1 by udrd, TS29519_Policy_Data.yaml
/// / udrd `handle_policy_data`). Returns the decoded UePolicySet body on 200,
/// `Ok(None)` on 404 or when no UDR is reachable — the caller (E3 rule source)
/// then falls back to the static default rule set, fail-closed.
pub async fn pcf_udr_get_ue_policy_set(
    supi: &str,
) -> Result<Option<serde_json::Value>, String> {
    let Some(ep) = pcf_discover_endpoint("UDR", "nudr-dr").await? else {
        return Ok(None);
    };
    let client = client_for(&ep);
    let path = format!(
        "/nudr-dr/v1/policy-data/ues/{}/ue-policy-set",
        percent_encode(supi),
    );
    let resp = client
        .get(&path)
        .await
        .map_err(|e| format!("nudr-dr ue-policy-set GET failed: {e}"))?;
    match resp.status {
        200 => {
            let body = resp.http.content.ok_or("empty ue-policy-set body")?;
            let json = serde_json::from_str(&body)
                .map_err(|e| format!("invalid ue-policy-set body: {e}"))?;
            Ok(Some(json))
        }
        404 => {
            log::warn!("nudr-dr returned 404 for ue-policy-set SUPI {supi}; using static defaults");
            Ok(None)
        }
        other => Err(format!("nudr-dr ue-policy-set GET returned status {other}")),
    }
}

/// Live-path bounded Nudr_DataRepository GET of the UE's provisioned UePolicySet
/// (TS 29.519 §5.4), returning the doc when provisioned. `None` on
/// 404 / unreachable / timeout — the E3 rule source then falls back to the
/// static default set (fail-closed against a stuck UDR blocking delivery).
pub async fn pcf_udr_ue_policy_set(supi: &str) -> Option<serde_json::Value> {
    let fut = pcf_udr_get_ue_policy_set(supi);
    match tokio::time::timeout(std::time::Duration::from_secs(3), fut).await {
        Ok(Ok(Some(v))) => Some(v),
        _ => None,
    }
}

/// Register a PCF binding with a discovered BSF
/// (TS 29.521 Nbsf_Management: `POST /nbsf-management/v1/pcfBindings`).
/// Returns the binding id (from the Location header, else the response
/// `bindingId`) on 201/200; `Ok(None)` when no BSF is reachable.
pub async fn pcf_register_bsf_binding(
    binding: &serde_json::Value,
) -> Result<Option<String>, String> {
    let Some(ep) = pcf_discover_endpoint("BSF", "nbsf-management").await? else {
        return Ok(None);
    };
    let client = client_for(&ep);
    let resp = client
        .post_json("/nbsf-management/v1/pcfBindings", binding)
        .await
        .map_err(|e| format!("nbsf-management register failed: {e}"))?;
    match resp.status {
        200 | 201 => {
            let id = resp
                .http
                .get_header("location")
                .and_then(|loc| loc.rsplit('/').next())
                .map(str::to_string)
                .or_else(|| {
                    resp.http
                        .content
                        .as_deref()
                        .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
                        .and_then(|v| {
                            v.get("bindingId")
                                .and_then(|b| b.as_str())
                                .map(str::to_string)
                        })
                });
            Ok(id)
        }
        other => Err(format!("nbsf-management register returned status {other}")),
    }
}

/// Deregister a PCF binding with a discovered BSF
/// (`DELETE /nbsf-management/v1/pcfBindings/{bindingId}`). `Ok(true)` on 204/200.
pub async fn pcf_deregister_bsf_binding(binding_id: &str) -> Result<bool, String> {
    let Some(ep) = pcf_discover_endpoint("BSF", "nbsf-management").await? else {
        return Ok(false);
    };
    let client = client_for(&ep);
    let path = format!("/nbsf-management/v1/pcfBindings/{binding_id}");
    let resp = client
        .delete(&path)
        .await
        .map_err(|e| format!("nbsf-management delete failed: {e}"))?;
    Ok(resp.status == 204 || resp.status == 200)
}

// --- Wave-6 E4: UE-policy (URSP) delivery via Namf_Communication N1N2 ---

/// contentId of the binary UPDP part inside the multipart/related N1N2
/// request. Referenced by `n1MessageContent.contentId` (TS 29.500 §6.1.2.3).
const UPDP_CONTENT_ID: &str = "updp-pdu";

/// Build pcfd's production `Namf_Communication_N1N2MessageTransfer` request
/// carrying a UE policy container (TS 29.518 §5.2.2.3.1; TS 29.525 §4.2.2.2:
/// the PCF delivers UE policies via N1N2MessageTransfer). Root JSON =
/// `n1MessageContainer{n1MessageClass:"UPDP", n1MessageContent{contentId}}`;
/// the MANAGE UE POLICY COMMAND (`updp_pdu`) is the binary part. Kept as a
/// standalone builder so both the delivery task and the strict-peer test
/// (against amfd's REAL handler) use identical bytes.
pub fn build_ue_policy_n1n2_request(
    supi: &str,
    updp_pdu: &[u8],
) -> nextgcore_sbi::message::SbiRequest {
    use nextgcore_sbi::message::{SbiPart, SbiRequest};
    let body = serde_json::json!({
        "n1MessageContainer": {
            "n1MessageClass": "UPDP",
            "n1MessageContent": { "contentId": UPDP_CONTENT_ID }
        }
    });
    SbiRequest::post(format!(
        "/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages"
    ))
    .with_json_body(&body)
    .expect("n1n2 UPDP root JSON serializes")
    .with_part(SbiPart::with_content(
        UPDP_CONTENT_ID,
        // 5GS NAS message media type (TS 29.500 Table 6.1.2.3-1).
        "application/vnd.3gpp.5gnas",
        bytes::Bytes::copy_from_slice(updp_pdu),
    ))
}

/// Discover an AMF and POST the UE policy container over
/// `Namf_Communication_N1N2MessageTransfer` (multipart/related, class UPDP).
/// `Ok(())` when the AMF accepts the transfer (200/202 — delivery still awaits
/// the UE's MANAGE UE POLICY COMPLETE, item E6); `Err` on no reachable AMF or
/// a non-2xx (e.g. 504 UE_NOT_REACHABLE), which the caller records as
/// `DeliveryState::Failed` (fail-closed — never a fake `Delivered`).
///
/// AMF discovery: single-AMF matched sim uses NRF discovery by NF type. E4
/// risk note — for multi-AMF, the PolicyAssociationRequest `guami`/`servingNfId`
/// must be honoured to target the serving AMF; that is flagged, not solved here.
pub async fn pcf_deliver_ue_policy(supi: &str, updp_pdu: &[u8]) -> Result<(), String> {
    let Some(ep) = pcf_discover_endpoint("AMF", "namf-comm").await? else {
        return Err("no AMF reachable (NRF discovery found no namf-comm endpoint)".into());
    };
    let client = client_for(&ep);
    let req = build_ue_policy_n1n2_request(supi, updp_pdu);
    let resp = client
        .send_request(req)
        .await
        .map_err(|e| format!("namf-comm N1N2MessageTransfer failed: {e}"))?;
    match resp.status {
        200 | 202 => Ok(()),
        other => Err(format!(
            "namf-comm N1N2MessageTransfer returned status {other}"
        )),
    }
}

// --- Wave-6 E6: N1N2MessageSubscribe for the UE-policy delivery-result loop --

/// Subscribe to the AMF's uplink UE-policy (`n1MessageClass == "UPDP"`)
/// notifications for `supi` (TS 29.518 §5.2.2.6 N1N2MessageSubscribe; TS 29.525
/// §4.2.2.2 subscribe-BEFORE-transfer order): the AMF will POST an
/// `N1MessageNotify` to `callback_uri` when the UE returns a MANAGE UE POLICY
/// COMPLETE/REJECT. Returns the AMF-minted `n1n2NotifySubscriptionId` (from the
/// response body or the Location header) on 201; `Ok(None)` when no AMF is
/// reachable; `Err` on a non-2xx. The subscription is per-UE and bound to the
/// UE context lifetime at the AMF.
pub async fn pcf_subscribe_ue_policy_notify(
    supi: &str,
    callback_uri: &str,
) -> Result<Option<String>, String> {
    let Some(ep) = pcf_discover_endpoint("AMF", "namf-comm").await? else {
        return Ok(None);
    };
    let client = client_for(&ep);
    // UeN1N2InfoSubscriptionCreateData (TS29518_Namf_Communication.yaml): the
    // (n1MessageClass, n1NotifyCallbackUri) pair — the AMF fail-closed-rejects a
    // half-pair (Wave-6 A3).
    let body = serde_json::json!({
        "n1MessageClass": "UPDP",
        "n1NotifyCallbackUri": callback_uri,
    });
    let path = format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages/subscriptions");
    let resp = client
        .post_json(&path, &body)
        .await
        .map_err(|e| format!("N1N2MessageSubscribe failed: {e}"))?;
    match resp.status {
        200 | 201 => {
            let id = resp
                .http
                .content
                .as_deref()
                .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
                .and_then(|v| {
                    v.get("n1n2NotifySubscriptionId")
                        .and_then(|b| b.as_str())
                        .map(str::to_string)
                })
                .or_else(|| {
                    resp.http
                        .get_header("location")
                        .and_then(|loc| loc.rsplit('/').next())
                        .map(str::to_string)
                });
            Ok(id)
        }
        other => Err(format!("N1N2MessageSubscribe returned status {other}")),
    }
}

/// Unsubscribe a previously created UE-policy N1N2 notification
/// (`DELETE .../n1-n2-messages/subscriptions/{subscriptionId}`, TS 29.518
/// §5.2.2.7), called on association delete. `Ok(true)` on 204/200.
pub async fn pcf_unsubscribe_ue_policy_notify(
    supi: &str,
    subscription_id: &str,
) -> Result<bool, String> {
    let Some(ep) = pcf_discover_endpoint("AMF", "namf-comm").await? else {
        return Ok(false);
    };
    let client = client_for(&ep);
    let path = format!(
        "/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages/subscriptions/{subscription_id}"
    );
    let resp = client
        .delete(&path)
        .await
        .map_err(|e| format!("N1N2MessageUnSubscribe failed: {e}"))?;
    Ok(resp.status == 204 || resp.status == 200)
}

/// This PCF's advertised identity for Nbsf_Management PcfBinding bodies
/// (WSB-1/H2): SBI address information (TS 29.521 `pcfIpEndPoints`, shaped as
/// TS 29.510 IpEndPoint), the optional configured FQDN (`pcfFqdn` — never
/// invented when absent), and the NRF NF instance id (`pcfId`).
#[derive(Debug, Clone)]
pub struct PcfSelfInfo {
    /// Advertised (routable) SBI IPv4 address, same value the NRF NFProfile
    /// advertises in `ipv4Addresses`.
    pub sbi_addr: String,
    /// Advertised SBI port.
    pub sbi_port: u16,
    /// Optional configured FQDN (`pcf.sbi.server[0].fqdn` in pcf.yaml).
    pub fqdn: Option<String>,
    /// NF instance id (UUID) registered with the NRF; emitted as `pcfId`.
    pub nf_instance_id: String,
}

/// Process-global PCF self identity, set once in `main` after config parse
/// (before any PDU session can register a binding).
static PCF_SELF_INFO: std::sync::OnceLock<PcfSelfInfo> = std::sync::OnceLock::new();

/// Publish the PCF's advertised identity (set-once; later calls are ignored
/// and return `false`).
pub fn pcf_self_info_set(info: PcfSelfInfo) -> bool {
    PCF_SELF_INFO.set(info).is_ok()
}

/// The published PCF identity, if `main` (or a test) has set it.
pub fn pcf_self_info() -> Option<&'static PcfSelfInfo> {
    PCF_SELF_INFO.get()
}

/// Build the TS 29.521 PcfBinding body for a PDU session. `dnn` and `snssai`
/// are the mandatory members; supi and ipv4Addr are included when known.
///
/// WSB-1/H2: also emits the PCF address information the spec requires the
/// binding to carry — `pcfIpEndPoints` (TS 29.510 IpEndPoint array) always,
/// `pcfFqdn` only when configured, and `pcfId` — from the process-global
/// [`PcfSelfInfo`]. Our own bsfd (the conformant strict peer) rejects a
/// binding without pcfFqdn|pcfIpEndPoints with 400 MANDATORY_IE_MISSING
/// (TS 29.521 §5.3.2 / PcfBinding NOTE).
pub fn build_pcf_binding_body(
    supi: &str,
    dnn: &str,
    sst: u8,
    sd: Option<u32>,
    ipv4: Option<&str>,
) -> serde_json::Value {
    build_pcf_binding_body_with(pcf_self_info(), supi, dnn, sst, sd, ipv4)
}

/// Pure variant of [`build_pcf_binding_body`] taking the self identity
/// explicitly (unit-testable without touching the process-global OnceLock).
pub fn build_pcf_binding_body_with(
    self_info: Option<&PcfSelfInfo>,
    supi: &str,
    dnn: &str,
    sst: u8,
    sd: Option<u32>,
    ipv4: Option<&str>,
) -> serde_json::Value {
    let mut b = serde_json::json!({
        "supi": supi,
        "dnn": dnn,
        "snssai": match sd {
            Some(sd) => serde_json::json!({"sst": sst, "sd": format!("{sd:06x}")}),
            None => serde_json::json!({"sst": sst}),
        },
    });
    if let Some(ip) = ipv4 {
        b["ipv4Addr"] = serde_json::json!(ip);
    }
    match self_info {
        Some(info) => {
            // TS 29.510 IpEndPoint: ipv4Address + transport + port.
            b["pcfIpEndPoints"] = serde_json::json!([{
                "ipv4Address": info.sbi_addr,
                "transport": "TCP",
                "port": info.sbi_port,
            }]);
            if let Some(fqdn) = &info.fqdn {
                b["pcfFqdn"] = serde_json::json!(fqdn);
            }
            b["pcfId"] = serde_json::json!(info.nf_instance_id);
        }
        None => {
            log::warn!(
                "PCF self info not set; PcfBinding omits pcfIpEndPoints/pcfId \
                 (a conformant BSF rejects it, TS 29.521)"
            );
        }
    }
    b
}

/// Register this PDU session's PCF binding with the BSF (TS 23.503 §6.1.1.2,
/// TS 29.521). Best-effort, spawned fire-and-forget; the returned bindingId is
/// stored on the session so delete can deregister it. No-op when no BSF is
/// reachable (Ok(None)).
pub fn pcf_sess_register_bsf_binding(sess_id: u64) {
    let snap = crate::context::pcf_self().read().ok().and_then(|ctx| {
        let sess = ctx.sess_find_by_id(sess_id)?;
        let supi = ctx
            .ue_sm_find_by_id(sess.pcf_ue_sm_id)
            .map(|u| u.supi)
            .unwrap_or_default();
        Some((
            sess.sm_policy_id.clone(),
            supi,
            sess.dnn.clone(),
            sess.s_nssai.sst,
            sess.s_nssai.sd,
            sess.ipv4addr_string.clone(),
        ))
    });
    let Some((sm_policy_id, supi, dnn, sst, sd, ipv4)) = snap else {
        log::warn!("[sess_id={sess_id}] BSF binding: session not found");
        return;
    };
    let dnn = dnn.unwrap_or_else(|| "internet".to_string());
    let binding = build_pcf_binding_body(&supi, &dnn, sst, sd, ipv4.as_deref());
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn(async move {
                match pcf_register_bsf_binding(&binding).await {
                    Ok(Some(id)) => {
                        log::info!("PCF binding registered with BSF (id={id}) for {sm_policy_id}");
                        if let Ok(ctx) = crate::context::pcf_self().read() {
                            if let Some(mut sess) = ctx.sess_find_by_sm_policy_id(&sm_policy_id) {
                                sess.binding
                                    .store(&format!("/nbsf-management/v1/pcfBindings/{id}"), &id);
                                ctx.sess_update(&sess);
                            }
                        }
                    }
                    Ok(None) => log::debug!("No BSF reachable; PCF binding not registered"),
                    Err(e) => log::warn!("BSF binding registration failed: {e}"),
                }
            });
        }
        Err(_) => log::warn!("BSF binding registration skipped: no async runtime"),
    }
}

/// Deregister a session's BSF binding (best-effort, spawned).
pub fn pcf_sess_deregister_bsf_binding(binding_id: String) {
    if binding_id.is_empty() {
        return;
    }
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            match pcf_deregister_bsf_binding(&binding_id).await {
                Ok(true) => log::info!("PCF binding {binding_id} deregistered from BSF"),
                Ok(false) => {
                    log::debug!("No BSF reachable; binding {binding_id} not deregistered")
                }
                Err(e) => log::warn!("BSF binding deregistration failed: {e}"),
            }
        });
    }
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
        use nextgcore_sbi::message::{SbiRequest as Req, SbiResponse as Resp};
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        use std::time::Duration;

        async fn stub_smf(req: Req) -> Resp {
            let path = req.header.uri.split('?').next().unwrap_or("").to_string();
            if req.header.method == "POST" && path == "/nsmf-callback/v1/sm-policy-notify/42/update"
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

    /// pcfd-09: real NRF NF-discovery + nudr-dr GET against a mock server
    /// that plays NRF and UDR (routed by path). Proves the discover-and-send
    /// wiring without a live peer; live-interop invocation from the SM-policy
    /// path remains E2E-gated.
    ///
    /// Wave-6 H2: the former BSF leg of this test (a lenient mock that
    /// 201-accepted a PcfBinding our real bsfd 400-rejects) was converted to
    /// a strict-peer test against bsfd's REAL `bsf_sbi_request_handler` —
    /// see `tests/strict_peer_bsfd.rs`. Only the NRF-discovery bootstrap may
    /// stay mocked (H1 policy).
    #[tokio::test]
    async fn discover_and_send_udr_mock() {
        use nextgcore_sbi::message::SbiRequest as Req;
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        use std::time::Duration;

        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .map(|a| a.port())
            .expect("probe ephemeral port");
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let server = SbiServer::new(SbiServerConfig::new(addr));

        // Mock NRF/UDR: the closure captures its own port so the NRF
        // SearchResult advertises a UDR endpoint that points back at itself.
        let handler = move |req: Req| {
            let resp = build_mock_response(&req, port);
            async move { resp }
        };
        server.start(handler).await.expect("start mock NRF/UDR");

        // Point the PCF's SBI context at the mock NRF.
        global_context()
            .set_nrf_uri(format!("http://127.0.0.1:{port}"))
            .await;

        let run = async {
            // Discovery returns the UDR's nudr-dr endpoint (pointing at the mock).
            let ep = pcf_discover_endpoint("UDR", "nudr-dr")
                .await
                .expect("discover ok")
                .expect("udr found");
            assert_eq!(ep.host, "127.0.0.1");
            assert_eq!(ep.port, port);

            // nudr-dr GET SmPolicyData → decoded body.
            let data =
                pcf_udr_get_sm_policy_data("imsi-001010000000777", 1, Some(0x010203), "internet")
                    .await
                    .expect("udr GET ok")
                    .expect("policy data present");
            assert!(data.get("smPolicySnssaiData").is_some());

            // E3: nudr-dr GET UePolicySet (v1) → decoded body carrying our
            // structured `urspRules` provisioning extension.
            let ue = pcf_udr_get_ue_policy_set("imsi-001010000000777")
                .await
                .expect("udr ue-policy-set GET ok")
                .expect("ue-policy-set present");
            assert!(ue.get("urspRules").is_some());
        };
        tokio::time::timeout(Duration::from_secs(15), run)
            .await
            .expect("discover-and-send timed out");

        server.stop().await.ok();
    }

    /// Mock NRF/UDR response router used by the pcfd-09 test.
    ///
    /// Wave-6 H2: this mock deliberately serves ONLY the NRF-discovery
    /// bootstrap and the UDR leg. It must NOT grow BSF (nbsf-management)
    /// arms again — the lenient 201-accepting BSF mock masked the missing
    /// pcfIpEndPoints defect for months; the BSF leg is strict-peer tested
    /// against the real bsfd handler in `tests/strict_peer_bsfd.rs`.
    fn build_mock_response(
        req: &nextgcore_sbi::message::SbiRequest,
        port: u16,
    ) -> nextgcore_sbi::message::SbiResponse {
        let path = req.header.uri.split('?').next().unwrap_or("").to_string();
        if path == "/nnrf-disc/v1/nf-instances" {
            let body = serde_json::json!({
                "nfInstances": [
                    {
                        "nfInstanceId": "udr-mock",
                        "nfType": "UDR",
                        "ipv4Addresses": ["127.0.0.1"],
                        "nfServices": [{
                            "serviceName": "nudr-dr",
                            "scheme": "http",
                            "ipEndPoints": [{ "ipv4Address": "127.0.0.1", "port": port }]
                        }]
                    }
                ]
            });
            return nextgcore_sbi::message::SbiResponse::with_status(200)
                .with_json_body(&body)
                .unwrap_or_else(|_| nextgcore_sbi::message::SbiResponse::with_status(500));
        }
        if path.starts_with("/nudr-dr/v2/policy-data/") && path.ends_with("/sm-data") {
            let body = serde_json::json!({
                "smPolicySnssaiData": {
                    "01010203": {
                        "snssai": { "sst": 1, "sd": "010203" },
                        "smPolicyDnnData": { "internet": { "dnn": "internet" } }
                    }
                }
            });
            return nextgcore_sbi::message::SbiResponse::with_status(200)
                .with_json_body(&body)
                .unwrap_or_else(|_| nextgcore_sbi::message::SbiResponse::with_status(500));
        }
        // E3: ue-policy-set is served at v1 by udrd. The body carries the
        // 3GPP subscPolicySections alongside our structured `urspRules`
        // provisioning extension (compiled to wire by the E2 codec).
        if path.starts_with("/nudr-dr/v1/policy-data/") && path.ends_with("/ue-policy-set") {
            let body = serde_json::json!({
                "subscPolicySections": {},
                "urspRules": [{
                    "precedence": 10,
                    "trafficDescriptor": { "dnn": "ims" },
                    "routeSelectionDescriptors": [{
                        "precedence": 10, "sscMode": 1, "snssai": {"sst": 1},
                        "dnn": "ims", "pduSessionType": "ipv4v6", "preferredAccess": "3gpp"
                    }]
                }]
            });
            return nextgcore_sbi::message::SbiResponse::with_status(200)
                .with_json_body(&body)
                .unwrap_or_else(|_| nextgcore_sbi::message::SbiResponse::with_status(500));
        }
        nextgcore_sbi::message::SbiResponse::with_status(404)
    }

    /// pcfd#1: TS 29.521 PcfBinding body builder emits the mandatory dnn + snssai
    /// members and optional supi/ipv4Addr when present.
    #[test]
    fn pcf_binding_body_has_mandatory_dnn_and_snssai() {
        let b = build_pcf_binding_body(
            "imsi-001010000000088",
            "internet",
            1,
            Some(0x010203),
            Some("10.45.0.88"),
        );
        assert_eq!(b["dnn"], "internet");
        assert_eq!(b["snssai"]["sst"], 1);
        assert_eq!(b["snssai"]["sd"], "010203");
        assert_eq!(b["supi"], "imsi-001010000000088");
        assert_eq!(b["ipv4Addr"], "10.45.0.88");

        // Without SD and without IPv4
        let b2 = build_pcf_binding_body("imsi-1", "ims", 2, None, None);
        assert!(b2["snssai"].get("sd").is_none());
        assert!(b2.get("ipv4Addr").is_none());
    }

    /// WSB-1: with the PCF self identity available, the PcfBinding carries
    /// the mandatory PCF address information — a non-empty pcfIpEndPoints
    /// array shaped per TS 29.510 IpEndPoint (ipv4Address/transport/port)
    /// — plus pcfId as a UUID; pcfFqdn is emitted ONLY when configured
    /// (TS 29.521 §5.3.2, TS29521_Nbsf_Management.yaml PcfBinding).
    #[test]
    fn pcf_binding_body_carries_pcf_address_info() {
        let info = PcfSelfInfo {
            sbi_addr: "10.45.0.10".to_string(),
            sbi_port: 7777,
            fqdn: None,
            nf_instance_id: "5f4dc3a2-1c8f-4e0b-9d5a-0e2b7f6a1c33".to_string(),
        };
        let b = build_pcf_binding_body_with(
            Some(&info),
            "imsi-001010000000088",
            "internet",
            1,
            Some(0x010203),
            Some("10.45.0.88"),
        );
        // Existing members unchanged
        assert_eq!(b["dnn"], "internet");
        assert_eq!(b["snssai"]["sst"], 1);
        assert_eq!(b["ipv4Addr"], "10.45.0.88");
        // pcfIpEndPoints: non-empty, TS 29.510 IpEndPoint field names
        let eps = b["pcfIpEndPoints"].as_array().expect("pcfIpEndPoints array");
        assert!(!eps.is_empty());
        assert_eq!(eps[0]["ipv4Address"], "10.45.0.10");
        assert_eq!(eps[0]["port"], 7777);
        assert_eq!(eps[0]["transport"], "TCP");
        // pcfId is a UUID
        let pcf_id = b["pcfId"].as_str().expect("pcfId string");
        assert!(uuid::Uuid::parse_str(pcf_id).is_ok(), "pcfId not a UUID");
        // No FQDN configured -> pcfFqdn must NOT be invented
        assert!(b.get("pcfFqdn").is_none());

        // With a configured FQDN it is emitted alongside the endpoints.
        let info_fqdn = PcfSelfInfo {
            fqdn: Some("pcf.5gc.mnc001.mcc001.3gppnetwork.org".to_string()),
            ..info
        };
        let bf = build_pcf_binding_body_with(
            Some(&info_fqdn),
            "imsi-001010000000088",
            "internet",
            1,
            None,
            None,
        );
        assert_eq!(bf["pcfFqdn"], "pcf.5gc.mnc001.mcc001.3gppnetwork.org");
        assert!(bf["pcfIpEndPoints"].as_array().is_some_and(|a| !a.is_empty()));

        // Without self info (pre-WSB-1 legacy shape): no PCF address members —
        // this is exactly the body our bsfd 400-rejects (negative-control
        // shape pinned strict-peer in tests/strict_peer_bsfd.rs).
        let legacy = build_pcf_binding_body_with(
            None,
            "imsi-001010000000088",
            "internet",
            1,
            None,
            None,
        );
        assert!(legacy.get("pcfIpEndPoints").is_none());
        assert!(legacy.get("pcfFqdn").is_none());
        assert!(legacy.get("pcfId").is_none());
    }

    /// pcfd#2: TS 29.519 SmPolicyData navigation extracts the DNN data object.
    #[test]
    fn extract_sm_policy_dnn_data_navigates_udr_body() {
        let body = serde_json::json!({
            "smPolicySnssaiData": { "01010203": {
                "snssai": { "sst": 1, "sd": "010203" },
                "smPolicyDnnData": { "internet": { "dnn": "internet", "online": true, "offline": false } }
            }}
        });
        let d = extract_sm_policy_dnn_data(&body, "internet").expect("dnn data");
        assert_eq!(d["online"], true);
        assert_eq!(d["offline"], false);
        assert_eq!(d["dnn"], "internet");
        assert!(extract_sm_policy_dnn_data(&body, "ims").is_none());
    }
}
