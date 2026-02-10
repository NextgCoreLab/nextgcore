//! NextGCore BSF (Binding Support Function)
//!
//! The BSF is a 5G core network function responsible for:
//! - Managing PCF (Policy Control Function) bindings
//! - Providing binding information to PCF and AF
//! - Supporting session binding based on IP addresses

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

mod bsf_sm;
mod context;
mod event;
mod nbsf_handler;
mod nnrf_handler;
mod sbi_path;
mod sbi_response;
mod timer;

pub use bsf_sm::{BsfSmContext, BsfState};
pub use context::*;
pub use event::{BsfEvent, BsfEventId, BsfTimerId, SbiEventData, SbiMessage, EventSbiRequest, EventSbiResponse};
pub use nbsf_handler::*;
pub use nnrf_handler::*;
pub use sbi_path::*;
pub use timer::{timer_manager, BsfTimerManager};

/// NextGCore BSF - Binding Support Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-bsfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Binding Support Function", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/bsf.yaml")]
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

    /// NRF URI (e.g., http://127.0.0.10:7777)
    #[arg(long)]
    nrf_uri: Option<String>,

    /// Maximum number of sessions
    #[arg(long, default_value = "1024")]
    max_sess: usize,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    init_logging(&args)?;

    log::info!("NextGCore BSF v{} starting...", env!("CARGO_PKG_VERSION"));

    // Handle kill flag
    if args.kill {
        log::info!("Kill flag set - would send SIGTERM to running instance");
        return Ok(());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize BSF context
    bsf_context_init(args.max_sess);
    log::info!("BSF context initialized (max_sess={})", args.max_sess);

    // Load persisted bindings from database (if available)
    {
        let ctx = bsf_self();
        let guard = ctx.read();
        if let Ok(context) = guard {
            context.load_persisted_bindings();
        }
    }

    // Initialize BSF state machine
    let mut bsf_sm = BsfSmContext::new();
    bsf_sm.init();
    log::info!("BSF state machine initialized");

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
        nrf_uri: args.nrf_uri.clone(),
    };

    // Open legacy SBI server (for context initialization)
    bsf_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;

    // Start actual HTTP/2 SBI server using ogs-sbi
    let sbi_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let sbi_server = SbiServer::new(OgsSbiServerConfig::new(sbi_addr));

    sbi_server.start(bsf_sbi_request_handler).await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {}", e))?;

    log::info!("SBI HTTP/2 server listening on {}", sbi_addr);
    log::info!("NextGCore BSF ready");

    // Main event loop (async)
    run_event_loop_async(&mut bsf_sm, shutdown).await?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Stop SBI server
    sbi_server.stop().await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {}", e))?;
    log::info!("SBI HTTP/2 server stopped");

    // Close legacy SBI server
    bsf_sbi_close();
    log::info!("SBI server closed");

    // Cleanup state machine
    bsf_sm.fini();
    log::info!("BSF state machine finalized");

    // Cleanup context
    bsf_context_final();
    log::info!("BSF context finalized");

    log::info!("NextGCore BSF stopped");
    Ok(())
}

/// SBI request handler for BSF
async fn bsf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("BSF SBI request: {} {}", method, uri);

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    // Route based on service and resource
    // Expected paths:
    // - /nbsf-management/v1/pcfBindings
    // - /nbsf-management/v1/pcfBindings/{bindingId}

    if parts.len() < 3 {
        return send_not_found("Invalid path", None);
    }

    let service = parts[0];
    let _version = parts[1];
    let resource = parts[2];

    match (service, resource, method) {
        // BSF Management Service (nbsf-management)
        ("nbsf-management", "pcfBindings", "POST") => {
            // Create PCF Binding
            handle_pcf_binding_create(&request).await
        }
        ("nbsf-management", "pcfBindings", "GET") if parts.len() >= 4 => {
            // Get PCF Binding
            let binding_id = parts[3];
            handle_pcf_binding_get(binding_id).await
        }
        ("nbsf-management", "pcfBindings", "GET") => {
            // Discovery PCF Binding (with query params)
            handle_pcf_binding_discovery(&request).await
        }
        ("nbsf-management", "pcfBindings", "DELETE") if parts.len() >= 4 => {
            // Delete PCF Binding
            let binding_id = parts[3];
            handle_pcf_binding_delete(binding_id).await
        }
        ("nbsf-management", "pcfBindings", "PATCH") if parts.len() >= 4 => {
            // Update PCF Binding
            let binding_id = parts[3];
            handle_pcf_binding_update(binding_id, &request).await
        }

        _ => {
            log::warn!("Unknown BSF request: {} {}", method, uri);
            send_method_not_allowed(method, uri)
        }
    }
}

// PCF Binding handlers

async fn handle_pcf_binding_create(request: &SbiRequest) -> SbiResponse {
    log::info!("PCF Binding Create");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let binding_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    // Extract IP addresses from request
    let ipv4addr = binding_data.get("ipv4Addr")
        .and_then(|v| v.as_str());
    let ipv6prefix = binding_data.get("ipv6Prefix")
        .and_then(|v| v.as_str());

    if ipv4addr.is_none() && ipv6prefix.is_none() {
        return send_bad_request("Either ipv4Addr or ipv6Prefix must be provided", Some("MISSING_IP"));
    }

    // Add session to context
    let ctx = bsf_self();
    let sess = if let Ok(context) = ctx.read() {
        context.sess_add_by_ip_address(ipv4addr, ipv6prefix)
    } else {
        None
    };

    match sess {
        Some(mut sess) => {
            // Apply additional fields from request
            if let Some(supi) = binding_data.get("supi").and_then(|v| v.as_str()) {
                sess.supi = Some(supi.to_string());
            }
            if let Some(gpsi) = binding_data.get("gpsi").and_then(|v| v.as_str()) {
                sess.gpsi = Some(gpsi.to_string());
            }
            if let Some(dnn) = binding_data.get("dnn").and_then(|v| v.as_str()) {
                sess.dnn = Some(dnn.to_string());
            }
            if let Some(pcf_fqdn) = binding_data.get("pcfFqdn").and_then(|v| v.as_str()) {
                sess.pcf_fqdn = Some(pcf_fqdn.to_string());
            }
            if let Some(snssai) = binding_data.get("snssai") {
                let sst = snssai.get("sst").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
                let sd = snssai.get("sd").and_then(|v| v.as_str())
                    .and_then(|s| u32::from_str_radix(s, 16).ok());
                sess.s_nssai = context::SNssai::new(sst, sd);
            }

            // Update session in context and persist to DB
            if let Ok(context) = ctx.read() {
                context.sess_update(&sess);
                context.sess_persist(&sess);
            }

            // Start binding expiry timer (TTL)
            // Use expiry from request if provided, otherwise default 1 hour
            let ttl_secs = binding_data.get("expiry")
                .and_then(|v| v.as_str())
                .and_then(|s| {
                    // Parse ISO 8601 duration or seconds
                    s.parse::<u64>().ok()
                })
                .unwrap_or(timer::defaults::BINDING_EXPIRY.as_secs());

            let timer_mgr = timer_manager();
            timer_mgr.start(
                BsfTimerId::BindingExpiry,
                Duration::from_secs(ttl_secs),
                Some(sess.binding_id.clone()),
            );
            log::debug!("Binding expiry timer started for {} (TTL={}s)", sess.binding_id, ttl_secs);

            log::info!("PCF Binding created (id={}, ipv4={:?}, ipv6={:?}, TTL={}s)",
                sess.binding_id, ipv4addr, ipv6prefix, ttl_secs);

            SbiResponse::with_status(201)
                .with_header("Location", &format!("/nbsf-management/v1/pcfBindings/{}", sess.binding_id))
                .with_json_body(&serde_json::json!({
                    "pcfBindingId": sess.binding_id,
                    "ipv4Addr": ipv4addr,
                    "ipv6Prefix": ipv6prefix,
                    "supi": sess.supi,
                    "gpsi": sess.gpsi,
                    "dnn": sess.dnn,
                    "snssai": binding_data.get("snssai"),
                    "pcfFqdn": sess.pcf_fqdn,
                    "pcfIpEndPoints": binding_data.get("pcfIpEndPoints"),
                    "suppFeat": "1",
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        None => {
            send_bad_request("Failed to create PCF binding", Some("CREATION_FAILED"))
        }
    }
}

async fn handle_pcf_binding_get(binding_id: &str) -> SbiResponse {
    log::debug!("PCF Binding Get: {}", binding_id);

    let ctx = bsf_self();
    let sess = if let Ok(context) = ctx.read() {
        context.sess_find_by_binding_id(binding_id)
    } else {
        None
    };

    match sess {
        Some(sess) => {
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "pcfBindingId": sess.binding_id,
                    "ipv4Addr": sess.ipv4addr_string,
                    "ipv6Prefix": sess.ipv6prefix_string,
                    "supi": sess.supi,
                    "gpsi": sess.gpsi,
                    "dnn": sess.dnn,
                    "pcfFqdn": sess.pcf_fqdn,
                    "suppFeat": "1",
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => {
            send_not_found(&format!("PCF Binding {} not found", binding_id), Some("BINDING_NOT_FOUND"))
        }
    }
}

async fn handle_pcf_binding_discovery(request: &SbiRequest) -> SbiResponse {
    // Parse query parameters
    let ipv4addr = request.http.params.get("ipv4Addr")
        .map(|s| s.as_str());
    let ipv6prefix = request.http.params.get("ipv6Prefix")
        .map(|s| s.as_str());

    log::info!("PCF Binding Discovery: ipv4={:?}, ipv6={:?}", ipv4addr, ipv6prefix);

    if ipv4addr.is_none() && ipv6prefix.is_none() {
        return send_bad_request("Either ipv4Addr or ipv6Prefix query parameter required", Some("MISSING_PARAM"));
    }

    let ctx = bsf_self();
    let sess = if let Ok(context) = ctx.read() {
        if let Some(ipv4) = ipv4addr {
            context.sess_find_by_ipv4addr(ipv4)
        } else if let Some(ipv6) = ipv6prefix {
            context.sess_find_by_ipv6prefix(ipv6)
        } else {
            None
        }
    } else {
        None
    };

    match sess {
        Some(sess) => {
            log::info!("PCF Binding found: {}", sess.binding_id);
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "pcfBindingId": sess.binding_id,
                    "ipv4Addr": sess.ipv4addr_string,
                    "ipv6Prefix": sess.ipv6prefix_string,
                    "supi": sess.supi,
                    "gpsi": sess.gpsi,
                    "dnn": sess.dnn,
                    "pcfFqdn": sess.pcf_fqdn,
                    "suppFeat": "1",
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => {
            send_not_found("No PCF binding found for the specified IP address", Some("BINDING_NOT_FOUND"))
        }
    }
}

async fn handle_pcf_binding_delete(binding_id: &str) -> SbiResponse {
    log::info!("PCF Binding Delete: {}", binding_id);

    let ctx = bsf_self();

    // Parse binding ID to session ID
    let sess_id: Option<u64> = binding_id.parse().ok();

    match sess_id {
        Some(id) => {
            if let Ok(context) = ctx.read() {
                if context.sess_remove(id).is_some() {
                    context.sess_unpersist(binding_id);
                    log::info!("PCF Binding {} deleted", binding_id);
                    return SbiResponse::with_status(204);
                }
            }
            send_not_found(&format!("PCF Binding {} not found", binding_id), Some("BINDING_NOT_FOUND"))
        }
        None => {
            send_bad_request("Invalid binding ID format", Some("INVALID_BINDING_ID"))
        }
    }
}

async fn handle_pcf_binding_update(binding_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("PCF Binding Update (PATCH): {}", binding_id);

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let update_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    let ctx = bsf_self();
    let sess = if let Ok(context) = ctx.read() {
        context.sess_find_by_binding_id(binding_id)
    } else {
        None
    };

    match sess {
        Some(mut sess) => {
            // Apply patch fields from the request body
            if let Some(pcf_fqdn) = update_data.get("pcfFqdn").and_then(|v| v.as_str()) {
                sess.pcf_fqdn = Some(pcf_fqdn.to_string());
            }
            if let Some(ipv4) = update_data.get("ipv4Addr").and_then(|v| v.as_str()) {
                sess.set_ipv4addr(ipv4);
            }
            if let Some(ipv6) = update_data.get("ipv6Prefix").and_then(|v| v.as_str()) {
                sess.set_ipv6prefix(ipv6);
            }
            if let Some(supi) = update_data.get("supi").and_then(|v| v.as_str()) {
                sess.supi = Some(supi.to_string());
            }
            if let Some(gpsi) = update_data.get("gpsi").and_then(|v| v.as_str()) {
                sess.gpsi = Some(gpsi.to_string());
            }
            if let Some(dnn) = update_data.get("dnn").and_then(|v| v.as_str()) {
                sess.dnn = Some(dnn.to_string());
            }
            if let Some(snssai) = update_data.get("snssai") {
                let sst = snssai.get("sst").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
                let sd = snssai.get("sd").and_then(|v| v.as_str())
                    .and_then(|s| u32::from_str_radix(s, 16).ok());
                sess.s_nssai = context::SNssai::new(sst, sd);
            }
            if let Some(routes) = update_data.get("ipv4FrameRouteList").and_then(|v| v.as_array()) {
                sess.ipv4_frame_route_list = routes.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
            }
            if let Some(routes) = update_data.get("ipv6FrameRouteList").and_then(|v| v.as_array()) {
                sess.ipv6_frame_route_list = routes.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
            }
            if let Some(endpoints) = update_data.get("pcfIpEndPoints").and_then(|v| v.as_array()) {
                sess.pcf_ip = endpoints.iter().map(|ep| {
                    context::PcfIpEndpoint {
                        addr: ep.get("ipv4Address").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        addr6: ep.get("ipv6Address").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        is_port: ep.get("port").is_some(),
                        port: ep.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16,
                    }
                }).collect();
            }

            // Update session in context and persist to DB
            if let Ok(context) = ctx.read() {
                context.sess_update(&sess);
                context.sess_persist(&sess);
            }

            log::info!("PCF Binding {} updated", binding_id);

            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "pcfBindingId": sess.binding_id,
                    "ipv4Addr": sess.ipv4addr_string,
                    "ipv6Prefix": sess.ipv6prefix_string,
                    "supi": sess.supi,
                    "gpsi": sess.gpsi,
                    "dnn": sess.dnn,
                    "pcfFqdn": sess.pcf_fqdn,
                    "snssai": {
                        "sst": sess.s_nssai.sst,
                        "sd": sess.s_nssai.sd_to_string(),
                    },
                    "suppFeat": "1",
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => {
            send_not_found(&format!("PCF Binding {} not found", binding_id), Some("BINDING_NOT_FOUND"))
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
async fn run_event_loop_async(bsf_sm: &mut BsfSmContext, shutdown: Arc<AtomicBool>) -> Result<()> {
    log::debug!("Entering async main event loop");

    let timer_mgr = timer_manager();

    while !shutdown.load(Ordering::SeqCst) && !SHUTDOWN.load(Ordering::SeqCst) {
        // Compute optimal sleep duration based on pending timers
        let poll_interval = ogs_core::async_timer::compute_poll_interval(
            timer_mgr.inner(),
            Duration::from_millis(100),
        );
        tokio::time::sleep(poll_interval).await;

        // Process timer expirations and dispatch to state machine
        let expired = timer_mgr.process_expired();
        for entry in &expired {
            log::debug!(
                "BSF timer expired: id={} type={:?} data={:?}",
                entry.id, entry.timer_type, entry.data
            );

            // Handle binding expiry timer directly (TTL cleanup)
            if entry.timer_type == BsfTimerId::BindingExpiry {
                if let Some(ref binding_id) = entry.data {
                    log::info!("PCF Binding {} expired (TTL), removing", binding_id);
                    let ctx = bsf_self();
                    if let Ok(sess_id) = binding_id.parse::<u64>() {
                        if let Ok(context) = ctx.read() {
                            if context.sess_remove(sess_id).is_some() {
                                context.sess_unpersist(binding_id);
                                log::info!("PCF Binding {} auto-removed on TTL expiry", binding_id);
                            }
                        }
                    }
                }
                continue;
            }

            // Create timer event and dispatch to state machine
            let mut event = BsfEvent::sbi_timer(entry.timer_type);
            if let Some(ref nf_id) = entry.data {
                event = event.with_nf_instance(nf_id.clone());
            }

            bsf_sm.dispatch(&mut event);
        }

        // Check for shutdown
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
    }

    // Cleanup: clear all timers on shutdown
    timer_mgr.clear();
    log::debug!("Exiting async main event loop");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-bsfd"]);
        assert_eq!(args.config, "/etc/nextgcore/bsf.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 7777);
        assert!(!args.tls);
        assert_eq!(args.max_sess, 1024);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-bsfd",
            "-c",
            "/custom/bsf.yaml",
            "-e",
            "debug",
            "--sbi-addr",
            "0.0.0.0",
            "--sbi-port",
            "8080",
            "--max-sess",
            "2048",
        ]);
        assert_eq!(args.config, "/custom/bsf.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 8080);
        assert_eq!(args.max_sess, 2048);
    }

    #[test]
    fn test_args_tls() {
        let args = Args::parse_from([
            "nextgcore-bsfd",
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
