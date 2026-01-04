//! NextGCore SEPP (Security Edge Protection Proxy)
//!
//! The SEPP is a 5G core network function responsible for:
//! - Securing inter-PLMN communication (roaming)
//! - N32c handshake for security capability negotiation
//! - N32f forwarding of SBI messages between PLMNs
//! - TLS/PRINS security scheme negotiation

use anyhow::{Context, Result};
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

mod context;
mod event;
mod handshake_sm;
mod n32c_build;
mod n32c_handler;
mod sbi_path;
mod sepp_sm;
mod timer;

// Re-export specific items to avoid ambiguous glob re-exports
pub use context::{
    sepp_self, sepp_context_init, sepp_context_final, SeppContext, SeppNode, SeppAssoc,
    PlmnId, SecurityCapability, NfType, SbiServiceType, SecurityCapabilityConfig,
};
pub use event::{SeppEventId, SeppTimerId, SeppEvent};
pub use handshake_sm::{HandshakeState, HandshakeSmContext};
pub use n32c_build::{build_security_capability_request, build_security_capability_response, build_security_capability_sbi_request};
pub use n32c_handler::{handle_security_capability_request, handle_security_capability_response};
pub use sbi_path::{
    sepp_sbi_open, sepp_sbi_close, sepp_sbi_is_running, handle_request, handle_response,
    SbiServerConfig, SbiRequest, SbiResponse, RequestHandlerResult,
};
pub use sepp_sm::SeppSmContext;
pub use timer::{TimerConfig, TimerManager, sepp_timer_get_name};

/// NextGCore SEPP - Security Edge Protection Proxy
#[derive(Parser, Debug)]
#[command(name = "nextgcore-seppd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Security Edge Protection Proxy", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/sepp.yaml")]
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

    /// N32 interface address (for peer SEPP communication)
    #[arg(long)]
    n32_addr: Option<String>,

    /// N32 interface port
    #[arg(long)]
    n32_port: Option<u16>,

    /// Enable TLS
    #[arg(long)]
    tls: bool,

    /// TLS certificate path
    #[arg(long)]
    tls_cert: Option<String>,

    /// TLS key path
    #[arg(long)]
    tls_key: Option<String>,

    /// Sender FQDN (this SEPP's identifier)
    #[arg(long)]
    sender: Option<String>,

    /// Maximum number of peer SEPP nodes
    #[arg(long, default_value = "16")]
    max_node: usize,

    /// Maximum number of associations
    #[arg(long, default_value = "8192")]
    max_assoc: usize,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    init_logging(&args)?;

    log::info!("NextGCore SEPP v{} starting...", env!("CARGO_PKG_VERSION"));

    // Handle kill flag
    if args.kill {
        log::info!("Kill flag set - would send SIGTERM to running instance");
        return Ok(());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize SEPP context
    sepp_context_init(args.max_node, args.max_assoc);
    log::info!(
        "SEPP context initialized (max_node={}, max_assoc={})",
        args.max_node,
        args.max_assoc
    );

    // Set sender FQDN if provided
    if let Some(ref sender) = args.sender {
        let ctx = sepp_self();
        if let Ok(mut context) = ctx.write() {
            context.set_sender(sender);
            log::info!("SEPP sender FQDN: {}", sender);
        };
    }

    // Initialize SEPP state machine
    let mut sepp_sm = SeppSmContext::new();
    sepp_sm.init();
    log::info!("SEPP state machine initialized");

    // Parse configuration (if file exists)
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
        // TODO: Parse YAML configuration file
        // In C: sepp_context_parse_config()
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
        n32_addr: args.n32_addr.clone(),
        n32_port: args.n32_port,
    };

    // Open SBI server
    sepp_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;
    log::info!(
        "SBI server listening on {}:{}",
        args.sbi_addr,
        args.sbi_port
    );

    if let (Some(n32_addr), Some(n32_port)) = (&args.n32_addr, args.n32_port) {
        log::info!("N32 interface listening on {}:{}", n32_addr, n32_port);
    }

    log::info!("NextGCore SEPP ready");

    // Main event loop
    run_event_loop(&mut sepp_sm, shutdown)?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Close SBI server
    sepp_sbi_close();
    log::info!("SBI server closed");

    // Cleanup state machine
    sepp_sm.fini();
    log::info!("SEPP state machine finalized");

    // Cleanup context
    sepp_context_final();
    log::info!("SEPP context finalized");

    log::info!("NextGCore SEPP stopped");
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

/// Main event loop
fn run_event_loop(
    _sepp_sm: &mut SeppSmContext,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    log::debug!("Entering main event loop");

    // Simple polling loop
    // In a full implementation, this would use tokio or async-std for async I/O
    while !shutdown.load(Ordering::SeqCst) && !SHUTDOWN.load(Ordering::SeqCst) {
        // Poll for events with timeout
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Process timer expirations
        // TODO: Implement timer manager

        // Process events from queue
        // In a full implementation, this would pop events from the queue
        // and dispatch them to the state machine

        // For now, just check if we should exit
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
    }

    log::debug!("Exiting main event loop");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-seppd"]);
        assert_eq!(args.config, "/etc/nextgcore/sepp.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.sbi_addr, "127.0.0.1");
        assert_eq!(args.sbi_port, 7777);
        assert!(!args.tls);
        assert_eq!(args.max_node, 16);
        assert_eq!(args.max_assoc, 8192);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-seppd",
            "-c",
            "/custom/sepp.yaml",
            "-e",
            "debug",
            "--sbi-addr",
            "0.0.0.0",
            "--sbi-port",
            "8080",
            "--sender",
            "sepp.example.com",
            "--max-node",
            "32",
            "--max-assoc",
            "16384",
        ]);
        assert_eq!(args.config, "/custom/sepp.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 8080);
        assert_eq!(args.sender, Some("sepp.example.com".to_string()));
        assert_eq!(args.max_node, 32);
        assert_eq!(args.max_assoc, 16384);
    }

    #[test]
    fn test_args_tls() {
        let args = Args::parse_from([
            "nextgcore-seppd",
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

    #[test]
    fn test_args_n32() {
        let args = Args::parse_from([
            "nextgcore-seppd",
            "--n32-addr",
            "192.168.1.1",
            "--n32-port",
            "7778",
        ]);
        assert_eq!(args.n32_addr, Some("192.168.1.1".to_string()));
        assert_eq!(args.n32_port, Some(7778));
    }
}
