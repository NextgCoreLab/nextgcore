//! NextGCore PCRF (Policy and Charging Rules Function)
//!
//! The PCRF is responsible for:
//! - Policy and charging control (Gx interface with P-GW/SMF)
//! - Application function interaction (Rx interface with AF/P-CSCF)
//! - QoS policy decisions based on subscriber data

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_pcrfd::{
    pcrf_context_final, pcrf_context_init, pcrf_context_parse_config,
    pcrf_fd_final, pcrf_fd_init,
    pcrf_gx_final, pcrf_gx_init,
    pcrf_rx_final, pcrf_rx_init,
    PcrfEvent, PcrfSmContext,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// NextGCore PCRF - Policy and Charging Rules Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-pcrfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "LTE/EPC Policy and Charging Rules Function", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/pcrf.yaml")]
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

    /// FreeDiameter configuration file
    #[arg(long, default_value = "/etc/nextgcore/freeDiameter/pcrf.conf")]
    diameter_config: String,

    /// Maximum number of sessions
    #[arg(long, default_value = "1024")]
    max_sess: usize,

    /// Database URI (MongoDB)
    #[arg(long)]
    db_uri: Option<String>,

    /// Database name
    #[arg(long, default_value = "nextgcore")]
    db_name: String,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    init_logging(&args)?;

    log::info!("NextGCore PCRF v{} starting...", env!("CARGO_PKG_VERSION"));

    // Handle kill flag
    if args.kill {
        log::info!("Kill flag set - would send SIGTERM to running instance");
        return Ok(());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize PCRF context
    pcrf_context_init(args.max_sess);
    log::info!("PCRF context initialized (max_sess={})", args.max_sess);

    // Parse configuration file
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
        if let Err(e) = pcrf_context_parse_config(&args.config) {
            log::warn!("Failed to parse config: {}", e);
        }
    } else {
        log::debug!("Configuration file not found: {}", args.config);
    }

    // Initialize PCRF state machine
    let mut pcrf_sm = PcrfSmContext::new();
    pcrf_sm.init(false);
    log::info!("PCRF state machine initialized");

    // Initialize FreeDiameter
    if let Err(e) = pcrf_fd_init() {
        log::error!("Failed to initialize FreeDiameter: {}", e);
        cleanup(&mut pcrf_sm);
        return Err(anyhow::anyhow!(e));
    }
    log::info!("FreeDiameter initialized");

    // Initialize Gx interface (P-GW communication)
    if let Err(e) = pcrf_gx_init() {
        log::error!("Failed to initialize Gx interface: {}", e);
        pcrf_fd_final();
        cleanup(&mut pcrf_sm);
        return Err(anyhow::anyhow!("{}", e));
    }
    log::info!("Gx interface initialized");

    // Initialize Rx interface (AF/P-CSCF communication)
    if let Err(e) = pcrf_rx_init() {
        log::error!("Failed to initialize Rx interface: {}", e);
        pcrf_gx_final();
        pcrf_fd_final();
        cleanup(&mut pcrf_sm);
        return Err(anyhow::anyhow!("{}", e));
    }
    log::info!("Rx interface initialized");

    // Dispatch entry event to transition to operational state
    let mut entry_event = PcrfEvent::entry();
    pcrf_sm.dispatch(&mut entry_event);
    log::info!("NextGCore PCRF ready");

    // Main event loop
    run_event_loop(&mut pcrf_sm, shutdown)?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Finalize Diameter interfaces
    pcrf_rx_final();
    log::info!("Rx interface finalized");

    pcrf_gx_final();
    log::info!("Gx interface finalized");

    pcrf_fd_final();
    log::info!("FreeDiameter finalized");

    // Cleanup state machine and context
    cleanup(&mut pcrf_sm);

    log::info!("NextGCore PCRF stopped");
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
fn run_event_loop(pcrf_sm: &mut PcrfSmContext, shutdown: Arc<AtomicBool>) -> Result<()> {
    log::debug!("Entering main event loop");

    // Polling interval
    let poll_interval = std::time::Duration::from_millis(100);

    while !shutdown.load(Ordering::SeqCst) && !SHUTDOWN.load(Ordering::SeqCst) {
        // Poll for events with timeout
        std::thread::sleep(poll_interval);

        // Process timer expirations
        // In full implementation, check timer manager for expired timers

        // Process events from queue
        // In full implementation, pop events from queue and dispatch

        // Check state machine health
        if !pcrf_sm.is_operational() {
            log::warn!("PCRF state machine not operational: {:?}", pcrf_sm.state());
        }
    }

    log::debug!("Exiting main event loop");
    Ok(())
}

/// Cleanup resources
fn cleanup(pcrf_sm: &mut PcrfSmContext) {
    pcrf_sm.fini();
    log::info!("PCRF state machine finalized");

    pcrf_context_final();
    log::info!("PCRF context finalized");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-pcrfd"]);
        assert_eq!(args.config, "/etc/nextgcore/pcrf.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.diameter_config, "/etc/nextgcore/freeDiameter/pcrf.conf");
        assert_eq!(args.max_sess, 1024);
        assert_eq!(args.db_name, "nextgcore");
        assert!(!args.kill);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-pcrfd",
            "-c", "/custom/pcrf.yaml",
            "-e", "debug",
            "--diameter-config", "/custom/pcrf.conf",
            "--max-sess", "2048",
            "--db-uri", "mongodb://localhost:27017",
            "--db-name", "custom_db",
        ]);
        assert_eq!(args.config, "/custom/pcrf.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.diameter_config, "/custom/pcrf.conf");
        assert_eq!(args.max_sess, 2048);
        assert_eq!(args.db_uri, Some("mongodb://localhost:27017".to_string()));
        assert_eq!(args.db_name, "custom_db");
    }

    #[test]
    fn test_args_kill() {
        let args = Args::parse_from(["nextgcore-pcrfd", "-k"]);
        assert!(args.kill);
    }

    #[test]
    fn test_args_log_options() {
        let args = Args::parse_from([
            "nextgcore-pcrfd",
            "-l", "/var/log/pcrf.log",
            "-m",
        ]);
        assert_eq!(args.log_file, Some("/var/log/pcrf.log".to_string()));
        assert!(args.no_color);
    }
}
