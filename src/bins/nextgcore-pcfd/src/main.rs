//! NextGCore PCF (Policy Control Function)
//!
//! The PCF is a 5G core network function responsible for:
//! - Policy control for AM (Access Management)
//! - Policy control for SM (Session Management)
//! - Policy authorization for application sessions

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

mod am_sm;
mod context;
mod event;
mod npcf_handler;
mod nudr_handler;
mod pcf_sm;
mod sbi_path;
mod sbi_response;
mod sm_sm;

pub use am_sm::{PcfAmSmContext, PcfAmState};
pub use context::*;
pub use event::*;
pub use npcf_handler::*;
pub use nudr_handler::*;
pub use pcf_sm::{PcfSmContext, PcfState};
pub use sbi_path::*;
pub use sm_sm::{PcfSmSmContext, PcfSmState};

/// NextGCore PCF - Policy Control Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-pcfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Policy Control Function", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/pcf.yaml")]
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

    log::info!("NextGCore PCF v{} starting...", env!("CARGO_PKG_VERSION"));

    // Handle kill flag
    if args.kill {
        log::info!("Kill flag set - would send SIGTERM to running instance");
        return Ok(());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize PCF context
    pcf_context_init(args.max_ue, args.max_sess);
    log::info!(
        "PCF context initialized (max_ue={}, max_sess={})",
        args.max_ue,
        args.max_sess
    );

    // Initialize PCF state machine
    let mut pcf_sm = PcfSmContext::new();
    pcf_sm.init();
    log::info!("PCF state machine initialized");

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
    pcf_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;

    // Start actual HTTP/2 SBI server using ogs-sbi
    let sbi_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let sbi_server = SbiServer::new(OgsSbiServerConfig::new(sbi_addr));

    sbi_server.start(pcf_sbi_request_handler).await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {}", e))?;

    log::info!("SBI HTTP/2 server listening on {}", sbi_addr);
    log::info!("NextGCore PCF ready");

    // Main event loop (async)
    run_event_loop_async(&mut pcf_sm, shutdown).await?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Stop SBI server
    sbi_server.stop().await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {}", e))?;
    log::info!("SBI HTTP/2 server stopped");

    // Close legacy SBI server
    pcf_sbi_close();
    log::info!("SBI server closed");

    // Cleanup state machine
    pcf_sm.fini();
    log::info!("PCF state machine finalized");

    // Cleanup context
    pcf_context_final();
    log::info!("PCF context finalized");

    log::info!("NextGCore PCF stopped");
    Ok(())
}

/// SBI request handler for PCF
async fn pcf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("PCF SBI request: {} {}", method, uri);

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    // Route based on service and resource
    // Expected paths:
    // - /npcf-am-policy-control/v1/policies/{polAssoId}
    // - /npcf-smpolicycontrol/v1/sm-policies/{smPolicyId}
    // - /npcf-policyauthorization/v1/app-sessions/{appSessionId}

    if parts.len() < 3 {
        return send_not_found("Invalid path", None);
    }

    let service = parts[0];
    let _version = parts[1];
    let resource = parts[2];

    match (service, resource, method) {
        // AM Policy Control Service (npcf-am-policy-control)
        ("npcf-am-policy-control", "policies", "POST") => {
            // Create AM Policy Association
            handle_am_policy_create(&request).await
        }
        ("npcf-am-policy-control", "policies", "GET") if parts.len() >= 4 => {
            // Get AM Policy Association
            let pol_asso_id = parts[3];
            handle_am_policy_get(pol_asso_id).await
        }
        ("npcf-am-policy-control", "policies", "DELETE") if parts.len() >= 4 => {
            // Delete AM Policy Association
            let pol_asso_id = parts[3];
            handle_am_policy_delete(pol_asso_id).await
        }
        ("npcf-am-policy-control", "policies", "PATCH") if parts.len() >= 4 => {
            // Update AM Policy Association
            let pol_asso_id = parts[3];
            handle_am_policy_update(pol_asso_id, &request).await
        }

        // SM Policy Control Service (npcf-smpolicycontrol)
        // Note: Order matters - more specific patterns first
        ("npcf-smpolicycontrol", "sm-policies", "POST") if parts.len() >= 5 && parts[4] == "update" => {
            // Update SM Policy (POST with update action)
            let sm_policy_id = parts[3];
            handle_sm_policy_update_notify(sm_policy_id, &request).await
        }
        ("npcf-smpolicycontrol", "sm-policies", "POST") => {
            // Create SM Policy
            handle_sm_policy_create(&request).await
        }
        ("npcf-smpolicycontrol", "sm-policies", "GET") if parts.len() >= 4 => {
            // Get SM Policy
            let sm_policy_id = parts[3];
            handle_sm_policy_get(sm_policy_id).await
        }
        ("npcf-smpolicycontrol", "sm-policies", "DELETE") if parts.len() >= 4 => {
            // Delete SM Policy
            let sm_policy_id = parts[3];
            handle_sm_policy_delete(sm_policy_id).await
        }

        // Policy Authorization Service (npcf-policyauthorization)
        ("npcf-policyauthorization", "app-sessions", "POST") => {
            // Create App Session
            handle_app_session_create(&request).await
        }
        ("npcf-policyauthorization", "app-sessions", "GET") if parts.len() >= 4 => {
            // Get App Session
            let app_session_id = parts[3];
            handle_app_session_get(app_session_id).await
        }
        ("npcf-policyauthorization", "app-sessions", "DELETE") if parts.len() >= 4 => {
            // Delete App Session
            let app_session_id = parts[3];
            handle_app_session_delete(app_session_id).await
        }
        ("npcf-policyauthorization", "app-sessions", "PATCH") if parts.len() >= 4 => {
            // Modify App Session
            let app_session_id = parts[3];
            handle_app_session_modify(app_session_id, &request).await
        }

        _ => {
            log::warn!("Unknown PCF request: {} {}", method, uri);
            send_method_not_allowed(method, uri)
        }
    }
}

// AM Policy Control handlers

async fn handle_am_policy_create(request: &SbiRequest) -> SbiResponse {
    log::info!("AM Policy Create");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let policy_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    // Extract SUPI from request
    let supi = policy_data.get("supi")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Add UE AM to context
    let ctx = pcf_self();
    let ue_am = if let Ok(context) = ctx.read() {
        context.ue_am_add(supi)
    } else {
        None
    };

    match ue_am {
        Some(ue_am) => {
            log::info!("AM Policy created for SUPI {} (id={})", supi, ue_am.association_id);

            SbiResponse::with_status(201)
                .with_header("Location", &format!("/npcf-am-policy-control/v1/policies/{}", ue_am.association_id))
                .with_json_body(&serde_json::json!({
                    "polAssoId": ue_am.association_id,
                    "supi": supi,
                    "triggers": [],
                    "servAreaRes": null,
                    "rfsp": null,
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        None => {
            send_bad_request("Failed to create AM policy", Some("CREATION_FAILED"))
        }
    }
}

async fn handle_am_policy_get(pol_asso_id: &str) -> SbiResponse {
    log::debug!("AM Policy Get: {}", pol_asso_id);

    let ctx = pcf_self();
    let ue_am = if let Ok(context) = ctx.read() {
        context.ue_am_find_by_association_id(pol_asso_id)
    } else {
        None
    };

    match ue_am {
        Some(ue_am) => {
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "polAssoId": ue_am.association_id,
                    "supi": ue_am.supi,
                    "triggers": [],
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => {
            send_not_found(&format!("AM Policy {} not found", pol_asso_id), Some("POLICY_NOT_FOUND"))
        }
    }
}

async fn handle_am_policy_delete(pol_asso_id: &str) -> SbiResponse {
    log::info!("AM Policy Delete: {}", pol_asso_id);

    let ctx = pcf_self();

    // Find the UE AM by association ID first
    let ue_am = if let Ok(context) = ctx.read() {
        context.ue_am_find_by_association_id(pol_asso_id)
    } else {
        None
    };

    match ue_am {
        Some(ue_am) => {
            // Remove the UE AM
            if let Ok(context) = ctx.read() {
                context.ue_am_remove(ue_am.id);
            }
            log::info!("AM Policy {} deleted", pol_asso_id);
            SbiResponse::with_status(204)
        }
        None => {
            send_not_found(&format!("AM Policy {} not found", pol_asso_id), Some("POLICY_NOT_FOUND"))
        }
    }
}

async fn handle_am_policy_update(pol_asso_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("AM Policy Update: {}", pol_asso_id);

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let _update_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    let ctx = pcf_self();
    let ue_am = if let Ok(context) = ctx.read() {
        context.ue_am_find_by_association_id(pol_asso_id)
    } else {
        None
    };

    match ue_am {
        Some(ue_am) => {
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "polAssoId": ue_am.association_id,
                    "supi": ue_am.supi,
                    "triggers": [],
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => {
            send_not_found(&format!("AM Policy {} not found", pol_asso_id), Some("POLICY_NOT_FOUND"))
        }
    }
}

// SM Policy Control handlers

async fn handle_sm_policy_create(request: &SbiRequest) -> SbiResponse {
    log::info!("SM Policy Create");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let policy_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    let supi = policy_data.get("supi")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let pdu_session_id = policy_data.get("pduSessionId")
        .and_then(|v| v.as_u64())
        .unwrap_or(1) as u8;

    let ctx = pcf_self();

    // Get or create UE SM
    let ue_sm_id = if let Ok(context) = ctx.read() {
        match context.ue_sm_find_by_supi(supi) {
            Some(ue_sm) => Some(ue_sm.id),
            None => context.ue_sm_add(supi).map(|ue| ue.id),
        }
    } else {
        None
    };

    let sess = ue_sm_id.and_then(|ue_sm_id| {
        if let Ok(context) = ctx.read() {
            context.sess_add(ue_sm_id, pdu_session_id)
        } else {
            None
        }
    });

    match sess {
        Some(sess) => {
            log::info!("SM Policy created for SUPI {} PDU Session {} (id={})", supi, pdu_session_id, sess.sm_policy_id);

            SbiResponse::with_status(201)
                .with_header("Location", &format!("/npcf-smpolicycontrol/v1/sm-policies/{}", sess.sm_policy_id))
                .with_json_body(&serde_json::json!({
                    "smPolicyId": sess.sm_policy_id,
                    "supi": supi,
                    "pduSessionId": pdu_session_id,
                    "sessRules": {},
                    "pccRules": {},
                    "qosDecs": {},
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        None => {
            send_bad_request("Failed to create SM policy", Some("CREATION_FAILED"))
        }
    }
}

async fn handle_sm_policy_get(sm_policy_id: &str) -> SbiResponse {
    log::debug!("SM Policy Get: {}", sm_policy_id);

    let ctx = pcf_self();
    let sess = if let Ok(context) = ctx.read() {
        context.sess_find_by_sm_policy_id(sm_policy_id)
    } else {
        None
    };

    match sess {
        Some(sess) => {
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "smPolicyId": sess.sm_policy_id,
                    "pduSessionId": sess.psi,
                    "sessRules": {},
                    "pccRules": {},
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => {
            send_not_found(&format!("SM Policy {} not found", sm_policy_id), Some("POLICY_NOT_FOUND"))
        }
    }
}

async fn handle_sm_policy_delete(sm_policy_id: &str) -> SbiResponse {
    log::info!("SM Policy Delete: {}", sm_policy_id);

    let ctx = pcf_self();

    let sess = if let Ok(context) = ctx.read() {
        context.sess_find_by_sm_policy_id(sm_policy_id)
    } else {
        None
    };

    match sess {
        Some(sess) => {
            if let Ok(context) = ctx.read() {
                context.sess_remove(sess.id);
            }
            log::info!("SM Policy {} deleted", sm_policy_id);
            SbiResponse::with_status(204)
        }
        None => {
            send_not_found(&format!("SM Policy {} not found", sm_policy_id), Some("POLICY_NOT_FOUND"))
        }
    }
}

async fn handle_sm_policy_update_notify(sm_policy_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("SM Policy Update Notify: {}", sm_policy_id);

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let _update_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    let ctx = pcf_self();
    let sess = if let Ok(context) = ctx.read() {
        context.sess_find_by_sm_policy_id(sm_policy_id)
    } else {
        None
    };

    match sess {
        Some(sess) => {
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "smPolicyId": sess.sm_policy_id,
                    "pduSessionId": sess.psi,
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => {
            send_not_found(&format!("SM Policy {} not found", sm_policy_id), Some("POLICY_NOT_FOUND"))
        }
    }
}

// Policy Authorization handlers

async fn handle_app_session_create(request: &SbiRequest) -> SbiResponse {
    log::info!("App Session Create");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let session_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    // For now, just create a dummy app session
    let app_session_id = uuid::Uuid::new_v4().to_string();

    log::info!("App Session created (id={})", app_session_id);

    SbiResponse::with_status(201)
        .with_header("Location", &format!("/npcf-policyauthorization/v1/app-sessions/{}", app_session_id))
        .with_json_body(&serde_json::json!({
            "appSessionId": app_session_id,
            "notifUri": session_data.get("notifUri"),
            "suppFeat": session_data.get("suppFeat"),
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

async fn handle_app_session_get(app_session_id: &str) -> SbiResponse {
    log::debug!("App Session Get: {}", app_session_id);

    let ctx = pcf_self();
    let app = if let Ok(context) = ctx.read() {
        context.app_find_by_app_session_id(app_session_id)
    } else {
        None
    };

    match app {
        Some(app) => {
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "appSessionId": app.app_session_id,
                    "notifUri": app.notif_uri,
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => {
            send_not_found(&format!("App Session {} not found", app_session_id), Some("SESSION_NOT_FOUND"))
        }
    }
}

async fn handle_app_session_delete(app_session_id: &str) -> SbiResponse {
    log::info!("App Session Delete: {}", app_session_id);

    let ctx = pcf_self();

    let app = if let Ok(context) = ctx.read() {
        context.app_find_by_app_session_id(app_session_id)
    } else {
        None
    };

    match app {
        Some(app) => {
            if let Ok(context) = ctx.read() {
                context.app_remove(app.id);
            }
            log::info!("App Session {} deleted", app_session_id);
            SbiResponse::with_status(204)
        }
        None => {
            send_not_found(&format!("App Session {} not found", app_session_id), Some("SESSION_NOT_FOUND"))
        }
    }
}

async fn handle_app_session_modify(app_session_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("App Session Modify: {}", app_session_id);

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let _modify_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    let ctx = pcf_self();
    let app = if let Ok(context) = ctx.read() {
        context.app_find_by_app_session_id(app_session_id)
    } else {
        None
    };

    match app {
        Some(app) => {
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "appSessionId": app.app_session_id,
                    "notifUri": app.notif_uri,
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => {
            send_not_found(&format!("App Session {} not found", app_session_id), Some("SESSION_NOT_FOUND"))
        }
    }
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
async fn run_event_loop_async(_pcf_sm: &mut PcfSmContext, shutdown: Arc<AtomicBool>) -> Result<()> {
    log::debug!("Entering async main event loop");

    let mut interval = tokio::time::interval(Duration::from_millis(100));

    while !shutdown.load(Ordering::SeqCst) && !SHUTDOWN.load(Ordering::SeqCst) {
        // Wait for next tick
        interval.tick().await;

        // Process timer expirations
        // Note: Timer manager integration for NRF heartbeats and subscription validity
        // let expired_events = timer_manager().get_expired_events();
        // for event in expired_events {
        //     log::debug!("Processing timer event: {:?}", event);
        // }

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
        let args = Args::parse_from(["nextgcore-pcfd"]);
        assert_eq!(args.config, "/etc/nextgcore/pcf.yaml");
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
            "nextgcore-pcfd",
            "-c",
            "/custom/pcf.yaml",
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
        assert_eq!(args.config, "/custom/pcf.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 8080);
        assert_eq!(args.max_ue, 2048);
        assert_eq!(args.max_sess, 8192);
    }

    #[test]
    fn test_args_tls() {
        let args = Args::parse_from([
            "nextgcore-pcfd",
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
