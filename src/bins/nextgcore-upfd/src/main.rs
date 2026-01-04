//! NextGCore UPF (User Plane Function)
//!
//! Port of src/upf/ - User Plane Function for 5G/LTE core network
//!
//! The UPF is responsible for:
//! - User plane packet routing and forwarding
//! - QoS handling
//! - Traffic usage reporting
//! - Uplink/downlink traffic detection

pub mod arp_nd;
pub mod context;
pub mod event;
pub mod gtp_path;
pub mod n4_build;
pub mod n4_handler;
pub mod pfcp_path;
pub mod pfcp_sm;
pub mod rule_match;
pub mod timer;
pub mod upf_sm;

#[cfg(test)]
mod property_tests;

use anyhow::{Context, Result};
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use context::{upf_context_final, upf_context_init};
use event::UpfEvent;
use gtp_path::{upf_gtp_close, upf_gtp_final, upf_gtp_init, upf_gtp_open};
use pfcp_path::{pfcp_close, pfcp_open, PfcpPathContext};
use upf_sm::UpfSmContext;

/// NextGCore UPF - User Plane Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-upfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core User Plane Function", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/upf.yaml")]
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

    /// PFCP server address
    #[arg(long, default_value = "127.0.0.4")]
    pfcp_addr: String,

    /// PFCP server port
    #[arg(long, default_value = "8805")]
    pfcp_port: u16,

    /// GTP-U address
    #[arg(long, default_value = "127.0.0.4")]
    gtpu_addr: String,

    /// GTP-U port
    #[arg(long, default_value = "2152")]
    gtpu_port: u16,

    /// TUN interface name
    #[arg(long, default_value = "ogstun")]
    tun_ifname: String,

    /// Maximum number of sessions
    #[arg(long, default_value = "1024")]
    max_sessions: usize,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    init_logging(&args)?;

    log::info!("NextGCore UPF v{} starting...", env!("CARGO_PKG_VERSION"));

    // Handle kill flag
    if args.kill {
        log::info!("Kill flag set - would send SIGTERM to running instance");
        return Ok(());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize UPF context
    upf_context_init(args.max_sessions);
    log::info!("UPF context initialized (max_sessions={})", args.max_sessions);

    // Initialize GTP-U path
    upf_gtp_init().map_err(|e| anyhow::anyhow!("Failed to initialize GTP path: {}", e))?;
    log::info!("GTP-U path initialized");

    // Initialize UPF state machine
    let mut upf_sm = UpfSmContext::new();
    upf_sm.init();
    log::info!("UPF state machine initialized");

    // Initialize PFCP path context
    let mut pfcp_ctx = PfcpPathContext::new();

    // Parse configuration (if file exists)
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
        // TODO: Parse YAML configuration file
    } else {
        log::debug!("Configuration file not found: {}", args.config);
    }

    // Open PFCP path
    let pfcp_addr = format!("{}:{}", args.pfcp_addr, args.pfcp_port)
        .parse()
        .context("Invalid PFCP address")?;
    pfcp_open(&mut pfcp_ctx, pfcp_addr)
        .map_err(|e| anyhow::anyhow!("Failed to open PFCP path: {}", e))?;
    log::info!("PFCP path opened on {}:{}", args.pfcp_addr, args.pfcp_port);

    // Open GTP-U path
    upf_gtp_open().map_err(|e| anyhow::anyhow!("Failed to open GTP path: {}", e))?;
    log::info!("GTP-U path opened on {}:{}", args.gtpu_addr, args.gtpu_port);

    // Transition to operational state
    let entry_event = UpfEvent::entry();
    upf_sm.dispatch(&entry_event);

    log::info!("NextGCore UPF ready");

    // Main event loop
    run_event_loop(&mut upf_sm, &mut pfcp_ctx, shutdown)?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Close GTP-U path
    upf_gtp_close().map_err(|e| anyhow::anyhow!("Failed to close GTP path: {}", e))?;
    log::info!("GTP-U path closed");

    // Close PFCP path
    pfcp_close(&mut pfcp_ctx);
    log::info!("PFCP path closed");

    // Finalize GTP-U
    upf_gtp_final().map_err(|e| anyhow::anyhow!("Failed to finalize GTP path: {}", e))?;
    log::info!("GTP-U path finalized");

    // Cleanup state machine
    upf_sm.fini();
    log::info!("UPF state machine finalized");

    // Cleanup context
    upf_context_final();
    log::info!("UPF context finalized");

    log::info!("NextGCore UPF stopped");
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
    upf_sm: &mut UpfSmContext,
    _pfcp_ctx: &mut PfcpPathContext,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    log::debug!("Entering main event loop");

    // Simple polling loop
    // In a full implementation, this would use tokio or async-std for async I/O
    while !shutdown.load(Ordering::SeqCst) && !SHUTDOWN.load(Ordering::SeqCst) {
        // Poll for events with timeout
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Check if state machine is still operational
        if !upf_sm.is_operational() && !upf_sm.is_final() {
            // Try to transition to operational
            let entry_event = UpfEvent::entry();
            upf_sm.dispatch(&entry_event);
        }

        // Process timer expirations
        // In a full implementation, this would check the timer manager

        // Process PFCP messages
        // In a full implementation, this would poll the PFCP socket

        // Process GTP-U messages
        // In a full implementation, this would poll the GTP-U socket

        // Process TUN interface
        // In a full implementation, this would poll the TUN device

        // Check if we should exit
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
        let args = Args::parse_from(["nextgcore-upfd"]);
        assert_eq!(args.config, "/etc/nextgcore/upf.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.pfcp_addr, "127.0.0.4");
        assert_eq!(args.pfcp_port, 8805);
        assert_eq!(args.gtpu_addr, "127.0.0.4");
        assert_eq!(args.gtpu_port, 2152);
        assert_eq!(args.tun_ifname, "ogstun");
        assert_eq!(args.max_sessions, 1024);
        assert!(!args.kill);
        assert!(!args.no_color);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-upfd",
            "-c",
            "/custom/upf.yaml",
            "-e",
            "debug",
            "--pfcp-addr",
            "10.0.0.1",
            "--pfcp-port",
            "8806",
            "--gtpu-addr",
            "10.0.0.2",
            "--gtpu-port",
            "2153",
            "--tun-ifname",
            "mytun",
            "--max-sessions",
            "2048",
        ]);
        assert_eq!(args.config, "/custom/upf.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.pfcp_addr, "10.0.0.1");
        assert_eq!(args.pfcp_port, 8806);
        assert_eq!(args.gtpu_addr, "10.0.0.2");
        assert_eq!(args.gtpu_port, 2153);
        assert_eq!(args.tun_ifname, "mytun");
        assert_eq!(args.max_sessions, 2048);
    }

    #[test]
    fn test_args_kill_flag() {
        let args = Args::parse_from(["nextgcore-upfd", "-k"]);
        assert!(args.kill);
    }

    #[test]
    fn test_args_no_color() {
        let args = Args::parse_from(["nextgcore-upfd", "-m"]);
        assert!(args.no_color);
    }

    #[test]
    fn test_args_log_file() {
        let args = Args::parse_from(["nextgcore-upfd", "-l", "/var/log/upf.log"]);
        assert_eq!(args.log_file, Some("/var/log/upf.log".to_string()));
    }
}
