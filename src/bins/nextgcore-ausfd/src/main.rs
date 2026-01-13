//! NextGCore AUSF (Authentication Server Function)
//!
//! The AUSF is a 5G core network function responsible for:
//! - UE authentication
//! - Authentication vector generation
//! - Key derivation (KAUSF, KSEAF)
//! - Authentication result confirmation

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_ausfd::{
    ausf_context_final, ausf_context_init, ausf_sbi_close, ausf_sbi_open, ausf_self,
    timer_manager, AusfSmContext, SbiServerConfig,
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

/// NextGCore AUSF - Authentication Server Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-ausfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Authentication Server Function", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/ausf.yaml")]
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

    log::info!("NextGCore AUSF v{} starting...", env!("CARGO_PKG_VERSION"));

    // Handle kill flag
    if args.kill {
        log::info!("Kill flag set - would send SIGTERM to running instance");
        return Ok(());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize AUSF context
    ausf_context_init(args.max_ue);
    log::info!("AUSF context initialized (max_ue={})", args.max_ue);

    // Initialize AUSF state machine
    let mut ausf_sm = AusfSmContext::new();
    ausf_sm.init();
    log::info!("AUSF state machine initialized");

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
    ausf_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;

    // Start actual HTTP/2 SBI server using ogs-sbi
    let sbi_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let sbi_server = SbiServer::new(OgsSbiServerConfig::new(sbi_addr));

    sbi_server.start(ausf_sbi_request_handler).await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {}", e))?;

    log::info!("SBI HTTP/2 server listening on {}", sbi_addr);
    log::info!("NextGCore AUSF ready");

    // Main event loop (async)
    run_event_loop_async(&mut ausf_sm, shutdown).await?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Stop SBI server
    sbi_server.stop().await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {}", e))?;
    log::info!("SBI HTTP/2 server stopped");

    // Close legacy SBI server
    ausf_sbi_close();
    log::info!("SBI server closed");

    // Cleanup state machine
    ausf_sm.fini();
    log::info!("AUSF state machine finalized");

    // Cleanup context
    ausf_context_final();
    log::info!("AUSF context finalized");

    log::info!("NextGCore AUSF stopped");
    Ok(())
}

/// SBI request handler for AUSF
async fn ausf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("AUSF SBI request: {} {}", method, uri);

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    // Route based on service and resource
    // Expected paths:
    // - /nausf-auth/v1/ue-authentications
    // - /nausf-auth/v1/ue-authentications/{authCtxId}/5g-aka-confirmation
    // - /nausf-auth/v1/ue-authentications/{authCtxId}/eap-session

    if parts.len() < 3 {
        return send_not_found("Invalid path", None);
    }

    let service = parts[0];
    let _version = parts[1];
    let resource = parts[2];

    match (service, resource, method) {
        // UE Authentication Service (nausf-auth)
        // Note: Order matters - more specific patterns first
        ("nausf-auth", "ue-authentications", "POST") if parts.len() >= 5 && parts[4] == "eap-session" => {
            // EAP Session
            let auth_ctx_id = parts[3];
            handle_eap_session(auth_ctx_id, &request).await
        }
        ("nausf-auth", "ue-authentications", "POST") => {
            // UE Authentication (5G-AKA or EAP-AKA')
            handle_ue_authentication(&request).await
        }
        ("nausf-auth", "ue-authentications", "PUT") if parts.len() >= 5 && parts[4] == "5g-aka-confirmation" => {
            // 5G-AKA Confirmation
            let auth_ctx_id = parts[3];
            handle_5g_aka_confirmation(auth_ctx_id, &request).await
        }
        ("nausf-auth", "ue-authentications", "DELETE") if parts.len() >= 4 => {
            // Delete Authentication Context
            let auth_ctx_id = parts[3];
            handle_auth_context_delete(auth_ctx_id).await
        }

        _ => {
            log::warn!("Unknown AUSF request: {} {}", method, uri);
            send_method_not_allowed(method, uri)
        }
    }
}

// UE Authentication handlers

async fn handle_ue_authentication(request: &SbiRequest) -> SbiResponse {
    log::info!("UE Authentication Request");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let auth_info: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    let supi = auth_info.get("supiOrSuci")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let serving_network_name = auth_info.get("servingNetworkName")
        .and_then(|v| v.as_str())
        .unwrap_or("5G:mnc001.mcc001.3gppnetwork.org");

    log::info!("UE Authentication: SUPI/SUCI={}, SNN={}", supi, serving_network_name);

    // In a real implementation, this would:
    // 1. Get authentication vector from UDM
    // 2. Generate RAND, AUTN, XRES*, KAUSF
    // 3. Return 5G-AKA challenge or EAP-Request

    // Generate a mock auth context ID
    let auth_ctx_id = uuid::Uuid::new_v4().to_string();

    // Add UE to context
    let ctx = ausf_self();
    if let Ok(context) = ctx.read() {
        context.ue_add(supi);
    }

    // For 5G-AKA, return authentication challenge
    SbiResponse::with_status(201)
        .with_header("Location", &format!("/nausf-auth/v1/ue-authentications/{}", auth_ctx_id))
        .with_json_body(&serde_json::json!({
            "authType": "5G_AKA",
            "5gAuthData": {
                "rand": "00000000000000000000000000000000",
                "hxresStar": "0000000000000000",
                "autn": "00000000000000000000000000000000"
            },
            "_links": {
                "5g-aka": {
                    "href": format!("/nausf-auth/v1/ue-authentications/{}/5g-aka-confirmation", auth_ctx_id)
                }
            },
            "servingNetworkName": serving_network_name
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

async fn handle_5g_aka_confirmation(auth_ctx_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("5G-AKA Confirmation: auth_ctx_id={}", auth_ctx_id);

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let confirmation: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    let res_star = confirmation.get("resStar")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    log::info!("5G-AKA Confirmation: RES*={}", res_star);

    // In a real implementation, this would:
    // 1. Verify RES* against XRES*
    // 2. If successful, return KSEAF
    // 3. Notify UDM of authentication result

    // Return success with KSEAF
    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "authResult": "AUTHENTICATION_SUCCESS",
            "kseaf": "0000000000000000000000000000000000000000000000000000000000000000",
            "supi": "imsi-001010000000001"
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

async fn handle_eap_session(auth_ctx_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("EAP Session: auth_ctx_id={}", auth_ctx_id);

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let eap_session: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    let eap_payload = eap_session.get("eapPayload")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    log::info!("EAP Session: payload_len={}", eap_payload.len());

    // In a real implementation, this would process EAP-AKA' messages
    // For now, return success
    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "authResult": "AUTHENTICATION_SUCCESS",
            "kseaf": "0000000000000000000000000000000000000000000000000000000000000000",
            "supi": "imsi-001010000000001",
            "eapPayload": ""
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

async fn handle_auth_context_delete(auth_ctx_id: &str) -> SbiResponse {
    log::info!("Auth Context Delete: auth_ctx_id={}", auth_ctx_id);
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
async fn run_event_loop_async(_ausf_sm: &mut AusfSmContext, shutdown: Arc<AtomicBool>) -> Result<()> {
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
        let args = Args::parse_from(["nextgcore-ausfd"]);
        assert_eq!(args.config, "/etc/nextgcore/ausf.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 7777);
        assert!(!args.tls);
        assert_eq!(args.max_ue, 1024);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-ausfd",
            "-c",
            "/custom/ausf.yaml",
            "-e",
            "debug",
            "--sbi-addr",
            "0.0.0.0",
            "--sbi-port",
            "8080",
            "--max-ue",
            "2048",
        ]);
        assert_eq!(args.config, "/custom/ausf.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 8080);
        assert_eq!(args.max_ue, 2048);
    }

    #[test]
    fn test_args_tls() {
        let args = Args::parse_from([
            "nextgcore-ausfd",
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
