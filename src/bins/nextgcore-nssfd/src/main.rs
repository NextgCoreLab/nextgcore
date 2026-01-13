//! NextGCore NSSF (Network Slice Selection Function)
//!
//! The NSSF is a 5G core network function responsible for:
//! - Selecting the Network Slice instances to serve the UE
//! - Determining the allowed NSSAI and mapping to subscribed S-NSSAIs
//! - Determining the AMF Set to be used to serve the UE

use anyhow::{Context, Result};
use clap::Parser;
use ogs_sbi::message::{SbiRequest, SbiResponse};
use ogs_sbi::server::{
    send_bad_request, send_method_not_allowed, send_not_found,
    SbiServer, SbiServerConfig as OgsSbiServerConfig,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod context;
mod event;
mod nnrf_handler;
mod nnssf_build;
mod nnssf_handler;
mod nssf_sm;
mod sbi_path;
mod sbi_response;

pub use context::*;
pub use event::{NssfEvent, NssfEventId, NssfTimerId, SbiEventData, SbiMessage, EventSbiRequest, EventSbiResponse};
pub use nnrf_handler::*;
pub use nnssf_build::*;
pub use nnssf_handler::*;
pub use nssf_sm::{NssfSmContext, NssfState};
pub use sbi_path::*;

/// NextGCore NSSF - Network Slice Selection Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-nssfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Network Slice Selection Function", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/nssf.yaml")]
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

    /// Maximum number of NF instances
    #[arg(long, default_value = "512")]
    max_nf: usize,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    init_logging(&args)?;

    log::info!("NextGCore NSSF v{} starting...", env!("CARGO_PKG_VERSION"));

    // Handle kill flag
    if args.kill {
        log::info!("Kill flag set - would send SIGTERM to running instance");
        return Ok(());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize NSSF context
    nssf_context_init(args.max_nf);
    log::info!("NSSF context initialized (max_nf={})", args.max_nf);

    // Initialize NSSF state machine
    let mut nssf_sm = NssfSmContext::new();
    nssf_sm.init();
    log::info!("NSSF state machine initialized");

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
    nssf_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;

    // Start actual HTTP/2 SBI server using ogs-sbi
    let sbi_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let sbi_server = SbiServer::new(OgsSbiServerConfig::new(sbi_addr));

    sbi_server.start(nssf_sbi_request_handler).await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {}", e))?;

    log::info!("SBI HTTP/2 server listening on {}", sbi_addr);
    log::info!("NextGCore NSSF ready");

    // Main event loop (async)
    run_event_loop_async(&mut nssf_sm, shutdown).await?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Stop SBI server
    sbi_server.stop().await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {}", e))?;
    log::info!("SBI HTTP/2 server stopped");

    // Close legacy SBI server
    nssf_sbi_close();
    log::info!("SBI server closed");

    // Cleanup state machine
    nssf_sm.fini();
    log::info!("NSSF state machine finalized");

    // Cleanup context
    nssf_context_final();
    log::info!("NSSF context finalized");

    log::info!("NextGCore NSSF stopped");
    Ok(())
}

/// SBI request handler for NSSF
async fn nssf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("NSSF SBI request: {} {}", method, uri);

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    // Route based on service and resource
    // Expected paths:
    // - /nnssf-nsselection/v1/network-slice-information
    // - /nnssf-nssaiavailability/v1/nssai-availability/{nfId}

    if parts.len() < 3 {
        return send_not_found("Invalid path", None);
    }

    let service = parts[0];
    let _version = parts[1];
    let resource = parts[2];

    match (service, resource, method) {
        // NS Selection Service (nnssf-nsselection)
        ("nnssf-nsselection", "network-slice-information", "GET") => {
            // Network Slice Selection
            handle_ns_selection(&request).await
        }

        // NSSAI Availability Service (nnssf-nssaiavailability)
        ("nnssf-nssaiavailability", "nssai-availability", "PUT") if parts.len() >= 4 => {
            // Update NSSAI Availability
            let nf_id = parts[3];
            handle_nssai_availability_update(nf_id, &request).await
        }
        ("nnssf-nssaiavailability", "nssai-availability", "PATCH") if parts.len() >= 4 => {
            // Patch NSSAI Availability
            let nf_id = parts[3];
            handle_nssai_availability_patch(nf_id, &request).await
        }
        ("nnssf-nssaiavailability", "nssai-availability", "DELETE") if parts.len() >= 4 => {
            // Delete NSSAI Availability
            let nf_id = parts[3];
            handle_nssai_availability_delete(nf_id).await
        }
        ("nnssf-nssaiavailability", "nssai-availability", "OPTIONS") => {
            // Options for subscription
            handle_nssai_availability_options().await
        }

        // Subscriptions
        ("nnssf-nssaiavailability", "subscriptions", "POST") => {
            // Create subscription
            handle_subscription_create(&request).await
        }
        ("nnssf-nssaiavailability", "subscriptions", "DELETE") if parts.len() >= 4 => {
            // Delete subscription
            let subscription_id = parts[3];
            handle_subscription_delete(subscription_id).await
        }

        _ => {
            log::warn!("Unknown NSSF request: {} {}", method, uri);
            send_method_not_allowed(method, uri)
        }
    }
}

// NS Selection handlers

async fn handle_ns_selection(request: &SbiRequest) -> SbiResponse {
    // Parse query parameters
    let nf_type = request.http.params.get("nf-type")
        .map(|s| s.as_str())
        .unwrap_or("AMF");
    let nf_id = request.http.params.get("nf-id")
        .map(|s| s.as_str());
    let slice_info_for_pdu_session = request.http.params.get("slice-info-request-for-pdu-session")
        .map(|s| s.as_str());

    log::info!("NS Selection: nf-type={}, nf-id={:?}", nf_type, nf_id);

    // Build response with allowed NSSAI
    // In a real implementation, this would query the NSSF context
    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "allowedNssaiList": [
                {
                    "allowedSnssaiList": [
                        {
                            "allowedSnssai": {
                                "sst": 1,
                                "sd": "000001"
                            }
                        }
                    ],
                    "accessType": "3GPP_ACCESS"
                }
            ],
            "nsiInformationList": slice_info_for_pdu_session.map(|_| vec![
                serde_json::json!({
                    "nrfId": "nrf.5gc.mnc001.mcc001.3gppnetwork.org",
                    "nsiId": "1"
                })
            ]),
            "supportedFeatures": "1"
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

// NSSAI Availability handlers

async fn handle_nssai_availability_update(nf_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("NSSAI Availability Update: nf_id={}", nf_id);

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let availability_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    // Store the NSSAI availability info
    // In a real implementation, this would update the NSSF context

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "authorizedNssaiAvailabilityInfo": availability_data.get("nssaiAvailabilityInfos"),
            "supportedFeatures": "1"
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

async fn handle_nssai_availability_patch(nf_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("NSSAI Availability Patch: nf_id={}", nf_id);

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let _patch_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "supportedFeatures": "1"
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

async fn handle_nssai_availability_delete(nf_id: &str) -> SbiResponse {
    log::info!("NSSAI Availability Delete: nf_id={}", nf_id);
    SbiResponse::with_status(204)
}

async fn handle_nssai_availability_options() -> SbiResponse {
    log::debug!("NSSAI Availability Options");
    SbiResponse::with_status(200)
        .with_header("Allow", "GET, PUT, PATCH, DELETE, OPTIONS")
}

// Subscription handlers

async fn handle_subscription_create(request: &SbiRequest) -> SbiResponse {
    log::info!("NSSAI Availability Subscription Create");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let subscription_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    let subscription_id = uuid::Uuid::new_v4().to_string();

    log::info!("Created subscription: {}", subscription_id);

    SbiResponse::with_status(201)
        .with_header("Location", &format!("/nnssf-nssaiavailability/v1/subscriptions/{}", subscription_id))
        .with_json_body(&serde_json::json!({
            "subscriptionId": subscription_id,
            "nfNssaiAvailabilityUri": subscription_data.get("nfNssaiAvailabilityUri"),
            "expiry": subscription_data.get("expiry"),
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

async fn handle_subscription_delete(subscription_id: &str) -> SbiResponse {
    log::info!("NSSAI Availability Subscription Delete: {}", subscription_id);
    SbiResponse::with_status(204)
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
async fn run_event_loop_async(_nssf_sm: &mut NssfSmContext, shutdown: Arc<AtomicBool>) -> Result<()> {
    log::debug!("Entering async main event loop");

    let mut interval = tokio::time::interval(Duration::from_millis(100));

    while !shutdown.load(Ordering::SeqCst) && !SHUTDOWN.load(Ordering::SeqCst) {
        // Wait for next tick
        interval.tick().await;

        // Process timer expirations
        // Note: Timer manager integration for NRF heartbeats and subscription validity

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
        let args = Args::parse_from(["nextgcore-nssfd"]);
        assert_eq!(args.config, "/etc/nextgcore/nssf.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 7777);
        assert!(!args.tls);
        assert_eq!(args.max_nf, 512);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-nssfd",
            "-c",
            "/custom/nssf.yaml",
            "-e",
            "debug",
            "--sbi-addr",
            "0.0.0.0",
            "--sbi-port",
            "8080",
            "--max-nf",
            "1024",
        ]);
        assert_eq!(args.config, "/custom/nssf.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 8080);
        assert_eq!(args.max_nf, 1024);
    }

    #[test]
    fn test_args_tls() {
        let args = Args::parse_from([
            "nextgcore-nssfd",
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
