//! NextGCore NRF (Network Repository Function)
//!
//! The NRF is a 5G core network function responsible for:
//! - NF registration and deregistration
//! - NF discovery
//! - NF status notifications
//! - Subscription management

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_nrfd::{
    nf_manager, nrf_context_final, nrf_context_init, nrf_sbi_close, nrf_sbi_open,
    timer_manager, NrfSmContext, SbiServerConfig,
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

/// NextGCore NRF - Network Repository Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-nrfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Network Repository Function", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/nrf.yaml")]
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
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    init_logging(&args)?;

    log::info!("NextGCore NRF v{} starting...", env!("CARGO_PKG_VERSION"));

    // Handle kill flag
    if args.kill {
        log::info!("Kill flag set - would send SIGTERM to running instance");
        return Ok(());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize NRF context
    nrf_context_init(args.max_ue);
    log::info!("NRF context initialized (max_ue={})", args.max_ue);

    // Initialize NRF state machine
    let mut nrf_sm = NrfSmContext::new();
    nrf_sm.init();
    log::info!("NRF state machine initialized");

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
    let _server = nrf_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;

    // Start actual HTTP/2 SBI server using ogs-sbi
    let sbi_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let sbi_server = SbiServer::new(OgsSbiServerConfig::new(sbi_addr));

    sbi_server.start(nrf_sbi_request_handler).await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {}", e))?;

    log::info!("SBI HTTP/2 server listening on {}", sbi_addr);
    log::info!("NextGCore NRF ready");

    // Main event loop (async)
    run_event_loop_async(&mut nrf_sm, shutdown).await?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Stop SBI server
    sbi_server.stop().await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {}", e))?;
    log::info!("SBI HTTP/2 server stopped");

    // Close legacy SBI server
    nrf_sbi_close();
    log::info!("SBI server closed");

    // Cleanup state machine
    nrf_sm.fini();
    log::info!("NRF state machine finalized");

    // Cleanup context
    nrf_context_final();
    log::info!("NRF context finalized");

    log::info!("NextGCore NRF stopped");
    Ok(())
}

/// SBI request handler for NRF
async fn nrf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("NRF SBI request: {} {}", method, uri);

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    // Route based on service and resource
    // Expected paths:
    // - /nnrf-nfm/v1/nf-instances/{nfInstanceId}
    // - /nnrf-nfm/v1/subscriptions/{subscriptionId}
    // - /nnrf-disc/v1/nf-instances

    if parts.len() < 3 {
        return send_not_found("Invalid path", None);
    }

    let service = parts[0];
    let _version = parts[1];
    let resource = parts[2];

    match (service, resource, method) {
        // NF Management Service (nnrf-nfm)
        ("nnrf-nfm", "nf-instances", "PUT") if parts.len() >= 4 => {
            // NF Register/Update: PUT /nnrf-nfm/v1/nf-instances/{nfInstanceId}
            let nf_instance_id = parts[3];
            handle_nf_register(nf_instance_id, &request).await
        }
        ("nnrf-nfm", "nf-instances", "GET") if parts.len() >= 4 => {
            // NF Profile Retrieval: GET /nnrf-nfm/v1/nf-instances/{nfInstanceId}
            let nf_instance_id = parts[3];
            handle_nf_profile_retrieval(nf_instance_id).await
        }
        ("nnrf-nfm", "nf-instances", "DELETE") if parts.len() >= 4 => {
            // NF Deregister: DELETE /nnrf-nfm/v1/nf-instances/{nfInstanceId}
            let nf_instance_id = parts[3];
            handle_nf_deregister(nf_instance_id).await
        }
        ("nnrf-nfm", "nf-instances", "PATCH") if parts.len() >= 4 => {
            // NF Update: PATCH /nnrf-nfm/v1/nf-instances/{nfInstanceId}
            let nf_instance_id = parts[3];
            handle_nf_update(nf_instance_id, &request).await
        }
        ("nnrf-nfm", "nf-instances", "GET") => {
            // NF List Retrieval: GET /nnrf-nfm/v1/nf-instances
            handle_nf_list_retrieval(&request).await
        }

        // Subscriptions
        ("nnrf-nfm", "subscriptions", "POST") => {
            // Subscribe: POST /nnrf-nfm/v1/subscriptions
            handle_subscription_create(&request).await
        }
        ("nnrf-nfm", "subscriptions", "DELETE") if parts.len() >= 4 => {
            // Unsubscribe: DELETE /nnrf-nfm/v1/subscriptions/{subscriptionId}
            let subscription_id = parts[3];
            handle_subscription_delete(subscription_id).await
        }
        ("nnrf-nfm", "subscriptions", "PATCH") if parts.len() >= 4 => {
            // Update subscription: PATCH /nnrf-nfm/v1/subscriptions/{subscriptionId}
            let subscription_id = parts[3];
            handle_subscription_update(subscription_id, &request).await
        }

        // NF Discovery Service (nnrf-disc)
        ("nnrf-disc", "nf-instances", "GET") => {
            // NF Discovery: GET /nnrf-disc/v1/nf-instances?target-nf-type=...&requester-nf-type=...
            handle_nf_discover(&request).await
        }

        _ => {
            log::warn!("Unknown NRF request: {} {}", method, uri);
            send_method_not_allowed(method, uri)
        }
    }
}

/// Handle NF Register request
async fn handle_nf_register(nf_instance_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("NF Register: {}", nf_instance_id);

    // Parse the NF profile from request body
    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    // Parse as NfProfile
    let profile: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    // Register the NF instance
    let manager = nf_manager();

    // Create NfProfile from JSON
    let nf_type = profile.get("nfType")
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN")
        .to_string();
    let nf_status = profile.get("nfStatus")
        .and_then(|v| v.as_str())
        .unwrap_or("REGISTERED")
        .to_string();
    let heartbeat_timer = profile.get("heartBeatTimer")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);

    let nf_profile = nextgcore_nrfd::NfProfile {
        nf_instance_id: nf_instance_id.to_string(),
        nf_type: nf_type.clone(),
        nf_status,
        heartbeat_timer,
        plmn_list: vec![],
        ipv4_addresses: vec![],
        ipv6_addresses: vec![],
        fqdn: None,
        nf_services: vec![],
    };

    match manager.register(nf_profile.clone()) {
        Ok(_) => {
            log::info!("NF {} ({}) registered successfully", nf_instance_id, nf_type);

            // Return 201 Created with the NF profile
            SbiResponse::with_status(201)
                .with_header("Location", &format!("/nnrf-nfm/v1/nf-instances/{}", nf_instance_id))
                .with_json_body(&profile)
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        Err(e) => {
            log::error!("Failed to register NF {}: {}", nf_instance_id, e);
            send_bad_request(&e, Some("REGISTRATION_FAILED"))
        }
    }
}

/// Handle NF Profile Retrieval request
async fn handle_nf_profile_retrieval(nf_instance_id: &str) -> SbiResponse {
    log::debug!("NF Profile Retrieval: {}", nf_instance_id);

    let manager = nf_manager();

    match manager.get(nf_instance_id) {
        Some(profile) => {
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "nfInstanceId": profile.nf_instance_id,
                    "nfType": profile.nf_type,
                    "nfStatus": profile.nf_status,
                    "heartBeatTimer": profile.heartbeat_timer,
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => {
            send_not_found(&format!("NF instance {} not found", nf_instance_id), Some("NF_NOT_FOUND"))
        }
    }
}

/// Handle NF Deregister request
async fn handle_nf_deregister(nf_instance_id: &str) -> SbiResponse {
    log::info!("NF Deregister: {}", nf_instance_id);

    let manager = nf_manager();

    match manager.deregister(nf_instance_id) {
        Ok(_) => {
            log::info!("NF {} deregistered successfully", nf_instance_id);
            SbiResponse::with_status(204) // No Content
        }
        Err(e) => {
            log::error!("Failed to deregister NF {}: {}", nf_instance_id, e);
            send_not_found(&e, Some("NF_NOT_FOUND"))
        }
    }
}

/// Handle NF Update request (PATCH)
async fn handle_nf_update(nf_instance_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("NF Update: {}", nf_instance_id);

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    // Parse patch items
    let _patch: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    // For now, just verify the NF exists and return success
    let manager = nf_manager();

    match manager.get(nf_instance_id) {
        Some(profile) => {
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "nfInstanceId": profile.nf_instance_id,
                    "nfType": profile.nf_type,
                    "nfStatus": profile.nf_status,
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => {
            send_not_found(&format!("NF instance {} not found", nf_instance_id), Some("NF_NOT_FOUND"))
        }
    }
}

/// Handle NF List Retrieval request
async fn handle_nf_list_retrieval(_request: &SbiRequest) -> SbiResponse {
    log::debug!("NF List Retrieval");

    let manager = nf_manager();

    let instances: Vec<String> = manager.list().iter().map(|p| p.nf_instance_id.clone()).collect();

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "_links": {
                "self": "/nnrf-nfm/v1/nf-instances",
                "items": instances.iter().map(|id| format!("/nnrf-nfm/v1/nf-instances/{}", id)).collect::<Vec<_>>()
            }
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Handle Subscription Create request
async fn handle_subscription_create(request: &SbiRequest) -> SbiResponse {
    log::info!("Subscription Create");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let subscription: serde_json::Value = match serde_json::from_str(body) {
        Ok(s) => s,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    // Generate subscription ID
    let subscription_id = uuid::Uuid::new_v4().to_string();

    log::info!("Created subscription: {}", subscription_id);

    // Return 201 Created
    SbiResponse::with_status(201)
        .with_header("Location", &format!("/nnrf-nfm/v1/subscriptions/{}", subscription_id))
        .with_json_body(&serde_json::json!({
            "subscriptionId": subscription_id,
            "nfStatusNotificationUri": subscription.get("nfStatusNotificationUri"),
            "validityTime": subscription.get("validityTime"),
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// Handle Subscription Delete request
async fn handle_subscription_delete(subscription_id: &str) -> SbiResponse {
    log::info!("Subscription Delete: {}", subscription_id);
    SbiResponse::with_status(204) // No Content
}

/// Handle Subscription Update request
async fn handle_subscription_update(subscription_id: &str, _request: &SbiRequest) -> SbiResponse {
    log::info!("Subscription Update: {}", subscription_id);
    SbiResponse::with_status(200)
}

/// Handle NF Discovery request
async fn handle_nf_discover(request: &SbiRequest) -> SbiResponse {
    // Parse query parameters
    let target_nf_type = request.http.params.get("target-nf-type")
        .map(|s| s.as_str())
        .unwrap_or("");
    let requester_nf_type = request.http.params.get("requester-nf-type")
        .map(|s| s.as_str())
        .unwrap_or("");

    log::info!("NF Discovery: target={}, requester={}", target_nf_type, requester_nf_type);

    if target_nf_type.is_empty() {
        return send_bad_request("Missing target-nf-type parameter", Some("MISSING_PARAM"));
    }

    // Search for matching NF instances
    let manager = nf_manager();

    let matching: Vec<_> = manager.list()
        .iter()
        .filter(|p| p.nf_type == target_nf_type && p.nf_status == "REGISTERED")
        .cloned()
        .collect();

    log::info!("Found {} matching NF instances for type {}", matching.len(), target_nf_type);

    // Build SearchResult response
    let nf_instances: Vec<serde_json::Value> = matching.iter().map(|p| {
        serde_json::json!({
            "nfInstanceId": p.nf_instance_id,
            "nfType": p.nf_type,
            "nfStatus": p.nf_status,
            "heartBeatTimer": p.heartbeat_timer,
            "ipv4Addresses": p.ipv4_addresses,
            "fqdn": p.fqdn,
        })
    }).collect();

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "validityPeriod": 3600,
            "nfInstances": nf_instances,
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
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
async fn run_event_loop_async(_nrf_sm: &mut NrfSmContext, shutdown: Arc<AtomicBool>) -> Result<()> {
    log::debug!("Entering async main event loop");

    let mut interval = tokio::time::interval(Duration::from_millis(100));

    while !shutdown.load(Ordering::SeqCst) && !SHUTDOWN.load(Ordering::SeqCst) {
        // Wait for next tick
        interval.tick().await;

        // Process timer expirations
        let expired_events = timer_manager().get_expired_events();
        for event in expired_events {
            log::debug!("Processing timer event: {:?}", event);
            // Dispatch to state machine
            // nrf_sm.handle_event(event);
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
        let args = Args::parse_from(["nextgcore-nrfd"]);
        assert_eq!(args.config, "/etc/nextgcore/nrf.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 7777);
        assert!(!args.tls);
        assert_eq!(args.max_ue, 1024);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-nrfd",
            "-c",
            "/custom/nrf.yaml",
            "-e",
            "debug",
            "--sbi-addr",
            "0.0.0.0",
            "--sbi-port",
            "8080",
            "--max-ue",
            "2048",
        ]);
        assert_eq!(args.config, "/custom/nrf.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 8080);
        assert_eq!(args.max_ue, 2048);
    }

    #[test]
    fn test_args_tls() {
        let args = Args::parse_from([
            "nextgcore-nrfd",
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
