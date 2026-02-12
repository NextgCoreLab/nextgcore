//! NextGCore SCP (Service Communication Proxy)
//!
//! The SCP is a 5G core network function responsible for:
//! - Acting as a proxy between NF consumers and producers
//! - Performing NF discovery delegation
//! - Routing requests to target NFs
//! - Handling inter-PLMN communication via SEPP

use anyhow::{Context, Result};
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod context;
mod event;
mod sbi_path;
mod service_mesh;
mod sbi_response;
mod scp_sm;
mod timer;

pub use context::{
    scp_self, scp_context_init, scp_context_final, ScpContext, ScpAssoc,
    NfType, SbiServiceType, DiscoveryOption, SNssai, Tai, Guami, PlmnId, AmfId,
};
pub use event::{ScpEvent, ScpEventId, ScpTimerId, SbiEventData, SbiMessage, SbiResponse};
pub use sbi_path::{
    scp_sbi_open, scp_sbi_close, scp_sbi_is_running, SbiServerConfig,
    SbiRequest, handle_request, handle_response, handle_nf_discover_response,
    handle_sepp_discover_response, parse_discovery_headers, copy_request_headers,
    RequestHandlerResult, headers, NfInstanceCandidate, select_nf_instance,
    select_nf_instance_round_robin, route_request, build_forwarded_request,
    discovery_cache, DiscoveryCache, parse_search_result,
};
pub use scp_sm::{ScpSmContext, ScpState};
pub use timer::{timer_manager, ScpTimerManager};

/// NextGCore SCP - Service Communication Proxy
#[derive(Parser, Debug)]
#[command(name = "nextgcore-scpd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Service Communication Proxy", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/scp.yaml")]
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
    #[arg(long, default_value = "127.0.0.1")]
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

    /// Maximum number of associations
    #[arg(long, default_value = "8192")]
    max_assoc: usize,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    init_logging(&args)?;

    log::info!("NextGCore SCP v{} starting...", env!("CARGO_PKG_VERSION"));

    // Handle kill flag
    if args.kill {
        log::info!("Kill flag set - would send SIGTERM to running instance");
        return Ok(());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize SCP context
    scp_context_init(args.max_assoc);
    log::info!("SCP context initialized (max_assoc={})", args.max_assoc);

    // Initialize SCP state machine
    let mut scp_sm = ScpSmContext::new();
    scp_sm.init();
    log::info!("SCP state machine initialized");

    // Parse configuration (if file exists)
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
        // Parse YAML configuration file
        // In C: scp_context_parse_config()
        match std::fs::read_to_string(&args.config) {
            Ok(content) => {
                log::debug!("Configuration file loaded ({} bytes)", content.len());
            }
            Err(e) => {
                log::warn!("Failed to read configuration file: {e}");
            }
        }
    } else {
        log::debug!("Configuration file not found: {}", args.config);
    }

    // Build SBI server configuration
    let sbi_config = sbi_path::SbiServerConfig {
        addr: args.sbi_addr.clone(),
        port: args.sbi_port,
        tls_enabled: args.tls,
        tls_cert: args.tls_cert.clone(),
        tls_key: args.tls_key.clone(),
    };

    // Open SBI server
    scp_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;
    log::info!("SBI server listening on {}:{}", args.sbi_addr, args.sbi_port);

    log::info!("NextGCore SCP ready");

    // Main event loop (async)
    run_event_loop_async(&mut scp_sm, shutdown).await?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Close SBI server
    scp_sbi_close();
    log::info!("SBI server closed");

    // Cleanup state machine
    scp_sm.fini();
    log::info!("SCP state machine finalized");

    // Cleanup context
    scp_context_final();
    log::info!("SCP context finalized");

    log::info!("NextGCore SCP stopped");
    Ok(())
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
    // Set up Ctrl+C handler
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
async fn run_event_loop_async(scp_sm: &mut ScpSmContext, shutdown: Arc<AtomicBool>) -> Result<()> {
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
                "SCP timer expired: id={} type={:?} data={:?}",
                entry.id, entry.timer_type, entry.data
            );

            // Create timer event and dispatch to state machine
            let mut event = ScpEvent::sbi_timer(entry.timer_type);
            if let Some(ref nf_id) = entry.data {
                event = event.with_nf_instance(nf_id.clone());
            }

            scp_sm.dispatch(&mut event);
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
        let args = Args::parse_from(["nextgcore-scpd"]);
        assert_eq!(args.config, "/etc/nextgcore/scp.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.sbi_addr, "127.0.0.1");
        assert_eq!(args.sbi_port, 7777);
        assert!(!args.tls);
        assert_eq!(args.max_assoc, 8192);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-scpd",
            "-c",
            "/custom/scp.yaml",
            "-e",
            "debug",
            "--sbi-addr",
            "0.0.0.0",
            "--sbi-port",
            "8080",
            "--max-assoc",
            "16384",
        ]);
        assert_eq!(args.config, "/custom/scp.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 8080);
        assert_eq!(args.max_assoc, 16384);
    }

    #[test]
    fn test_args_tls() {
        let args = Args::parse_from([
            "nextgcore-scpd",
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
