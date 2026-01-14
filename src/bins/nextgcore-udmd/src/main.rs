//! NextGCore UDM (Unified Data Management)
//!
//! The UDM is a 5G core network function responsible for:
//! - Subscriber data management
//! - Authentication credential processing
//! - Subscription management
//! - UE context management (AMF/SMF registration)

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_udmd::{
    udm_context_final, udm_context_init, udm_sbi_close, udm_sbi_open, udm_self,
    timer_manager, UdmSmContext, SbiServerConfig,
};
use ogs_sbi::message::{SbiRequest, SbiResponse};
use ogs_sbi::server::{
    send_bad_request, send_method_not_allowed, send_not_found,
    SbiServer, SbiServerConfig as OgsSbiServerConfig,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// NextGCore UDM - Unified Data Management
#[derive(Parser, Debug)]
#[command(name = "nextgcore-udmd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Unified Data Management", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/udm.yaml")]
    config: String,

    /// Log file path
    #[arg(short = 'l', long)]
    log_file: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short = 'e', long, default_value = "info")]
    log_level: String,

    /// Disable color output
    #[arg(short = 'm', long)]
    no_color: bool,

    /// Kill running instance
    #[arg(short = 'k', long)]
    kill: bool,

    /// SBI server address
    #[arg(long, default_value = "0.0.0.0")]
    sbi_addr: String,

    /// SBI server port
    #[arg(long, default_value = "7777")]
    sbi_port: u16,

    /// Enable TLS
    #[arg(long)]
    tls: bool,

    /// TLS certificate path
    #[arg(long)]
    tls_cert: Option<String>,

    /// TLS key path
    #[arg(long)]
    tls_key: Option<String>,

    /// Maximum number of UEs
    #[arg(long, default_value = "1024")]
    max_ue: usize,

    /// Maximum number of sessions
    #[arg(long, default_value = "4096")]
    max_sess: usize,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    init_logging(&args)?;

    log::info!("NextGCore UDM v{} starting...", env!("CARGO_PKG_VERSION"));

    // Handle kill flag
    if args.kill {
        log::info!("Kill flag set - would send SIGTERM to running instance");
        return Ok(());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize UDM context
    udm_context_init(args.max_ue, args.max_sess);
    log::info!("UDM context initialized (max_ue={}, max_sess={})", args.max_ue, args.max_sess);

    // Initialize UDM state machine
    let mut udm_sm = UdmSmContext::new();
    udm_sm.init();
    log::info!("UDM state machine initialized");

    // Parse configuration (if file exists)
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
        match std::fs::read_to_string(&args.config) {
            Ok(content) => {
                log::debug!("Configuration file loaded ({} bytes)", content.len());
            }
            Err(e) => {
                log::warn!("Failed to read configuration file: {}", e);
            }
        }
    } else {
        log::debug!("Configuration file not found: {}", args.config);
    }

    // Build SBI server configuration (legacy, for context)
    let sbi_config = SbiServerConfig {
        addr: args.sbi_addr.clone(),
        port: args.sbi_port,
        tls_enabled: args.tls,
        tls_cert: args.tls_cert.clone(),
        tls_key: args.tls_key.clone(),
    };

    // Open legacy SBI server (for context initialization)
    udm_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;

    // Start actual HTTP/2 SBI server using ogs-sbi
    let sbi_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let sbi_server = SbiServer::new(OgsSbiServerConfig::new(sbi_addr));

    sbi_server.start(udm_sbi_request_handler).await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {}", e))?;

    log::info!("SBI HTTP/2 server listening on {}", sbi_addr);
    log::info!("NextGCore UDM ready");

    // Main event loop (async)
    run_event_loop_async(&mut udm_sm, shutdown).await?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Stop SBI server
    sbi_server.stop().await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {}", e))?;
    log::info!("SBI HTTP/2 server stopped");

    // Close legacy SBI server
    udm_sbi_close();
    log::info!("SBI server closed");

    // Cleanup state machine
    udm_sm.fini();
    log::info!("UDM state machine finalized");

    // Cleanup context
    udm_context_final();
    log::info!("UDM context finalized");

    log::info!("NextGCore UDM stopped");
    Ok(())
}

/// SBI request handler for UDM
async fn udm_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("UDM SBI request: {} {}", method, uri);

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    // Route based on service and resource
    // Expected paths:
    // - /nudm-uecm/v1/{supi}/registrations/amf-3gpp-access
    // - /nudm-uecm/v1/{supi}/registrations/smf-registrations/{pduSessionId}
    // - /nudm-sdm/v1/{supi}/am-data
    // - /nudm-sdm/v1/{supi}/smf-select-data
    // - /nudm-sdm/v1/{supi}/sm-data
    // - /nudm-ueau/v1/{supi}/security-information/generate-auth-data

    if parts.len() < 3 {
        return send_not_found("Invalid path", None);
    }

    let service = parts[0];
    let _version = parts[1];

    match service {
        // UE Context Management Service (nudm-uecm)
        "nudm-uecm" if parts.len() >= 4 => {
            let supi = parts[2];
            let resource = parts.get(3).unwrap_or(&"");

            match (*resource, method) {
                ("registrations", "PUT") if parts.len() >= 5 && parts[4] == "amf-3gpp-access" => {
                    handle_amf_registration(supi, &request).await
                }
                ("registrations", "PATCH") if parts.len() >= 5 && parts[4] == "amf-3gpp-access" => {
                    handle_amf_registration_update(supi, &request).await
                }
                ("registrations", "DELETE") if parts.len() >= 5 && parts[4] == "amf-3gpp-access" => {
                    handle_amf_deregistration(supi).await
                }
                ("registrations", "PUT") if parts.len() >= 6 && parts[4] == "smf-registrations" => {
                    let pdu_session_id = parts[5];
                    handle_smf_registration(supi, pdu_session_id, &request).await
                }
                ("registrations", "DELETE") if parts.len() >= 6 && parts[4] == "smf-registrations" => {
                    let pdu_session_id = parts[5];
                    handle_smf_deregistration(supi, pdu_session_id).await
                }
                _ => send_method_not_allowed(method, uri)
            }
        }

        // Subscriber Data Management Service (nudm-sdm)
        "nudm-sdm" if parts.len() >= 4 => {
            let supi = parts[2];
            let resource = parts.get(3).unwrap_or(&"");

            match (*resource, method) {
                ("am-data", "GET") => {
                    handle_get_am_data(supi, &request).await
                }
                ("smf-select-data", "GET") => {
                    handle_get_smf_select_data(supi, &request).await
                }
                ("sm-data", "GET") => {
                    handle_get_sm_data(supi, &request).await
                }
                ("nssai", "GET") => {
                    handle_get_nssai(supi, &request).await
                }
                ("sdm-subscriptions", "POST") => {
                    handle_sdm_subscribe(supi, &request).await
                }
                ("sdm-subscriptions", "DELETE") if parts.len() >= 5 => {
                    let subscription_id = parts[4];
                    handle_sdm_unsubscribe(supi, subscription_id).await
                }
                _ => send_method_not_allowed(method, uri)
            }
        }

        // UE Authentication Service (nudm-ueau)
        "nudm-ueau" if parts.len() >= 5 => {
            let supi = parts[2];
            let resource = parts.get(3).unwrap_or(&"");
            let action = parts.get(4).unwrap_or(&"");

            match (*resource, *action, method) {
                ("security-information", "generate-auth-data", "POST") => {
                    handle_generate_auth_data(supi, &request).await
                }
                ("auth-events", _, "POST") => {
                    handle_auth_event(supi, &request).await
                }
                _ => send_method_not_allowed(method, uri)
            }
        }

        _ => {
            log::warn!("Unknown UDM request: {} {}", method, uri);
            send_method_not_allowed(method, uri)
        }
    }
}

// UE Context Management handlers

async fn handle_amf_registration(supi: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("AMF Registration: SUPI={}", supi);

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let reg_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    // Store AMF registration in context
    let ctx = udm_self();
    if let Ok(context) = ctx.read() {
        context.ue_add(supi);
    }

    SbiResponse::with_status(201)
        .with_header("Location", &format!("/nudm-uecm/v1/{}/registrations/amf-3gpp-access", supi))
        .with_json_body(&serde_json::json!({
            "amfInstanceId": reg_data.get("amfInstanceId"),
            "deregCallbackUri": reg_data.get("deregCallbackUri"),
            "guami": reg_data.get("guami"),
            "ratType": reg_data.get("ratType"),
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

async fn handle_amf_registration_update(supi: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("AMF Registration Update: SUPI={}", supi);

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let _update_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    SbiResponse::with_status(204)
}

async fn handle_amf_deregistration(supi: &str) -> SbiResponse {
    log::info!("AMF Deregistration: SUPI={}", supi);

    let ctx = udm_self();
    if let Ok(context) = ctx.read() {
        if let Some(ue) = context.ue_find_by_supi(supi) {
            context.ue_remove(ue.id);
        }
    }

    SbiResponse::with_status(204)
}

async fn handle_smf_registration(supi: &str, pdu_session_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("SMF Registration: SUPI={}, PDU Session={}", supi, pdu_session_id);

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let reg_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    SbiResponse::with_status(201)
        .with_header("Location", &format!("/nudm-uecm/v1/{}/registrations/smf-registrations/{}", supi, pdu_session_id))
        .with_json_body(&serde_json::json!({
            "smfInstanceId": reg_data.get("smfInstanceId"),
            "pduSessionId": pdu_session_id,
            "singleNssai": reg_data.get("singleNssai"),
            "dnn": reg_data.get("dnn"),
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

async fn handle_smf_deregistration(supi: &str, pdu_session_id: &str) -> SbiResponse {
    log::info!("SMF Deregistration: SUPI={}, PDU Session={}", supi, pdu_session_id);
    SbiResponse::with_status(204)
}

// Subscriber Data Management handlers

async fn handle_get_am_data(supi: &str, _request: &SbiRequest) -> SbiResponse {
    log::info!("Get AM Data: SUPI={}", supi);

    // Return subscriber access and mobility data
    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "gpsis": ["msisdn-1234567890"],
            "subscribedUeAmbr": {
                "uplink": "1000 Mbps",
                "downlink": "1000 Mbps"
            },
            "nssai": {
                "defaultSingleNssais": [
                    { "sst": 1, "sd": "000001" }
                ],
                "singleNssais": [
                    { "sst": 1, "sd": "000001" }
                ]
            }
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

async fn handle_get_smf_select_data(supi: &str, _request: &SbiRequest) -> SbiResponse {
    log::info!("Get SMF Select Data: SUPI={}", supi);

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "subscribedSnssaiInfos": {
                "01000001": {
                    "dnnInfos": [
                        { "dnn": "internet", "defaultDnnIndicator": true }
                    ]
                }
            }
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

async fn handle_get_sm_data(supi: &str, request: &SbiRequest) -> SbiResponse {
    let dnn = request.http.params.get("dnn")
        .map(|s| s.as_str())
        .unwrap_or("internet");

    log::info!("Get SM Data: SUPI={}, DNN={}", supi, dnn);

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!([{
            "singleNssai": { "sst": 1, "sd": "000001" },
            "dnnConfigurations": {
                "internet": {
                    "pduSessionTypes": {
                        "defaultSessionType": "IPV4",
                        "allowedSessionTypes": ["IPV4", "IPV6", "IPV4V6"]
                    },
                    "sscModes": {
                        "defaultSscMode": "SSC_MODE_1",
                        "allowedSscModes": ["SSC_MODE_1", "SSC_MODE_2", "SSC_MODE_3"]
                    },
                    "5gQosProfile": {
                        "5qi": 9,
                        "arp": {
                            "priorityLevel": 8,
                            "preemptCap": "NOT_PREEMPT",
                            "preemptVuln": "PREEMPTABLE"
                        }
                    },
                    "sessionAmbr": {
                        "uplink": "1000 Mbps",
                        "downlink": "1000 Mbps"
                    }
                }
            }
        }]))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

async fn handle_get_nssai(supi: &str, _request: &SbiRequest) -> SbiResponse {
    log::info!("Get NSSAI: SUPI={}", supi);

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "defaultSingleNssais": [
                { "sst": 1, "sd": "000001" }
            ],
            "singleNssais": [
                { "sst": 1, "sd": "000001" }
            ]
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

async fn handle_sdm_subscribe(supi: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("SDM Subscribe: SUPI={}", supi);

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let sub_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    let subscription_id = uuid::Uuid::new_v4().to_string();

    SbiResponse::with_status(201)
        .with_header("Location", &format!("/nudm-sdm/v1/{}/sdm-subscriptions/{}", supi, subscription_id))
        .with_json_body(&serde_json::json!({
            "subscriptionId": subscription_id,
            "nfInstanceId": sub_data.get("nfInstanceId"),
            "callbackReference": sub_data.get("callbackReference"),
            "monitoredResourceUris": sub_data.get("monitoredResourceUris"),
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

async fn handle_sdm_unsubscribe(supi: &str, subscription_id: &str) -> SbiResponse {
    log::info!("SDM Unsubscribe: SUPI={}, subscriptionId={}", supi, subscription_id);
    SbiResponse::with_status(204)
}

// UE Authentication handlers

async fn handle_generate_auth_data(supi: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("Generate Auth Data: SUPI={}", supi);

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let auth_info: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    let serving_network_name = auth_info.get("servingNetworkName")
        .and_then(|v| v.as_str())
        .unwrap_or("5G:mnc001.mcc001.3gppnetwork.org");

    log::info!("Generate Auth Data: SNN={}", serving_network_name);

    // Return mock authentication vector
    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "authType": "5G_AKA",
            "authenticationVector": {
                "avType": "5G_HE_AKA",
                "rand": "00000000000000000000000000000000",
                "autn": "00000000000000000000000000000000",
                "xresStar": "0000000000000000",
                "kausf": "0000000000000000000000000000000000000000000000000000000000000000"
            },
            "supi": supi
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

async fn handle_auth_event(supi: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("Auth Event: SUPI={}", supi);

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let auth_event: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    let success = auth_event.get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    log::info!("Auth Event: success={}", success);

    SbiResponse::with_status(201)
        .with_json_body(&serde_json::json!({
            "nfInstanceId": auth_event.get("nfInstanceId"),
            "success": success,
            "timeStamp": auth_event.get("timeStamp"),
            "authType": auth_event.get("authType"),
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// Initialize logging based on command line arguments
fn init_logging(args: &Args) -> Result<()> {
    let mut builder = env_logger::Builder::new();

    // Set log level
    let level = match args.log_level.to_lowercase().as_str() {
        "trace" => log::LevelFilter::Trace,
        "debug" => log::LevelFilter::Debug,
        "info" => log::LevelFilter::Info,
        "warn" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        _ => log::LevelFilter::Info,
    };
    builder.filter_level(level);

    // Configure format
    builder.format_timestamp_millis();

    if args.no_color {
        builder.write_style(env_logger::WriteStyle::Never);
    }

    builder.init();

    Ok(())
}

/// Set up signal handlers for graceful shutdown
fn setup_signal_handlers(shutdown: Arc<AtomicBool>) -> Result<()> {
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        shutdown_clone.store(true, Ordering::SeqCst);
        SHUTDOWN.store(true, Ordering::SeqCst);
    })
    .context("Failed to set Ctrl+C handler")?;

    Ok(())
}

/// Async main event loop with timer integration
async fn run_event_loop_async(_udm_sm: &mut UdmSmContext, shutdown: Arc<AtomicBool>) -> Result<()> {
    log::debug!("Entering async main event loop");

    let mut interval = tokio::time::interval(Duration::from_millis(100));

    while !shutdown.load(Ordering::SeqCst) && !SHUTDOWN.load(Ordering::SeqCst) {
        // Wait for next tick
        interval.tick().await;

        // Process timer expirations
        let timer_mgr = timer_manager();
        let expired = timer_mgr.process_expired();
        for timer in expired {
            log::debug!("Timer expired: {} ({:?})", timer.id, timer.timer_type);
        }

        // Check for shutdown
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
    }

    log::debug!("Exiting async main event loop");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-udmd"]);
        assert_eq!(args.config, "/etc/nextgcore/udm.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 7777);
        assert!(!args.tls);
        assert_eq!(args.max_ue, 1024);
        assert_eq!(args.max_sess, 4096);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-udmd",
            "-c",
            "/custom/udm.yaml",
            "-e",
            "debug",
            "--sbi-addr",
            "0.0.0.0",
            "--sbi-port",
            "8080",
            "--max-ue",
            "2048",
            "--max-sess",
            "8192",
        ]);
        assert_eq!(args.config, "/custom/udm.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 8080);
        assert_eq!(args.max_ue, 2048);
        assert_eq!(args.max_sess, 8192);
    }

    #[test]
    fn test_args_tls() {
        let args = Args::parse_from([
            "nextgcore-udmd",
            "--tls",
            "--tls-cert",
            "/path/to/cert.pem",
            "--tls-key",
            "/path/to/key.pem",
        ]);
        assert!(args.tls);
        assert_eq!(args.tls_cert, Some("/path/to/cert.pem".to_string()));
        assert_eq!(args.tls_key, Some("/path/to/key.pem".to_string()));
    }
}
