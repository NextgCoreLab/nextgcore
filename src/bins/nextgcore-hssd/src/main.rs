//! NextGCore HSS (Home Subscriber Server)
//!
//! The HSS is a central database for LTE/EPC networks responsible for:
//! - Subscriber authentication (S6a interface with MME)
//! - IMS authentication (Cx interface with I-CSCF/S-CSCF)
//! - Non-3GPP authentication (SWx interface with 3GPP AAA)
//! - Subscriber data management

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_hssd::{
    hss_context_final, hss_context_init, hss_context_parse_config,
    hss_cx_final, hss_cx_init,
    hss_fd_final, hss_fd_init,
    hss_s6a_final, hss_s6a_init,
    hss_swx_final, hss_swx_init,
    HssSmContext,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// NextGCore HSS - Home Subscriber Server
#[derive(Parser, Debug)]
#[command(name = "nextgcore-hssd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "LTE/EPC Home Subscriber Server", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/hss.yaml")]
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
    #[arg(long, default_value = "/etc/nextgcore/freeDiameter/hss.conf")]
    diameter_config: String,

    /// Maximum number of UEs
    #[arg(long, default_value = "1024")]
    max_ue: usize,

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

    log::info!("NextGCore HSS v{} starting...", env!("CARGO_PKG_VERSION"));

    // Handle kill flag
    if args.kill {
        log::info!("Kill flag set - would send SIGTERM to running instance");
        return Ok(());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize HSS context
    // max_impi = max_ue, max_impu = max_ue * 4 (typical ratio)
    hss_context_init(args.max_ue, args.max_ue * 4);
    log::info!("HSS context initialized (max_impi={}, max_impu={})", args.max_ue, args.max_ue * 4);

    // Parse configuration file
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
        if let Err(e) = hss_context_parse_config(&args.config) {
            log::warn!("Failed to parse config: {}", e);
        }
    } else {
        log::debug!("Configuration file not found: {}", args.config);
    }

    // Initialize HSS state machine
    let mut hss_sm = HssSmContext::new();
    hss_sm.init(false); // use_mongodb_change_stream = false by default
    log::info!("HSS state machine initialized");

    // Initialize FreeDiameter
    if let Err(e) = hss_fd_init() {
        log::error!("Failed to initialize FreeDiameter: {}", e);
        cleanup(&mut hss_sm);
        return Err(anyhow::anyhow!(e));
    }
    log::info!("FreeDiameter initialized");

    // Initialize S6a interface (MME communication)
    if let Err(e) = hss_s6a_init() {
        log::error!("Failed to initialize S6a interface: {}", e);
        hss_fd_final();
        cleanup(&mut hss_sm);
        return Err(anyhow::anyhow!("{}", e));
    }
    log::info!("S6a interface initialized");

    // Initialize Cx interface (IMS communication)
    if let Err(e) = hss_cx_init() {
        log::error!("Failed to initialize Cx interface: {}", e);
        hss_s6a_final();
        hss_fd_final();
        cleanup(&mut hss_sm);
        return Err(anyhow::anyhow!("{}", e));
    }
    log::info!("Cx interface initialized");

    // Initialize SWx interface (non-3GPP AAA communication)
    if let Err(e) = hss_swx_init() {
        log::error!("Failed to initialize SWx interface: {}", e);
        hss_cx_final();
        hss_s6a_final();
        hss_fd_final();
        cleanup(&mut hss_sm);
        return Err(e);
    }
    log::info!("SWx interface initialized");

    // Dispatch entry event to transition to operational state
    let mut entry_event = nextgcore_hssd::HssEvent::entry();
    hss_sm.dispatch(&mut entry_event);
    log::info!("NextGCore HSS ready");

    // Main event loop
    run_event_loop(&mut hss_sm, shutdown)?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Finalize Diameter interfaces
    hss_swx_final();
    log::info!("SWx interface finalized");

    hss_cx_final();
    log::info!("Cx interface finalized");

    hss_s6a_final();
    log::info!("S6a interface finalized");

    hss_fd_final();
    log::info!("FreeDiameter finalized");

    // Cleanup state machine and context
    cleanup(&mut hss_sm);

    log::info!("NextGCore HSS stopped");
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
fn run_event_loop(hss_sm: &mut HssSmContext, shutdown: Arc<AtomicBool>) -> Result<()> {
    log::debug!("Entering main event loop");

    // Polling interval for DB changes
    let poll_interval = std::time::Duration::from_millis(100);

    while !shutdown.load(Ordering::SeqCst) && !SHUTDOWN.load(Ordering::SeqCst) {
        // Poll for events with timeout
        std::thread::sleep(poll_interval);

        // Process timer expirations
        // In full implementation, check timer manager for expired timers

        // Poll database for changes (if configured)
        // The HSS periodically checks for subscriber data changes
        // In full implementation, this would use MongoDB change streams

        // Process events from queue
        // In full implementation, pop events from queue and dispatch

        // Check state machine health
        if !hss_sm.is_operational() {
            log::warn!("HSS state machine not operational: {:?}", hss_sm.state());
        }
    }

    log::debug!("Exiting main event loop");
    Ok(())
}

/// Cleanup resources
fn cleanup(hss_sm: &mut HssSmContext) {
    hss_sm.fini();
    log::info!("HSS state machine finalized");

    hss_context_final();
    log::info!("HSS context finalized");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-hssd"]);
        assert_eq!(args.config, "/etc/nextgcore/hss.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.diameter_config, "/etc/nextgcore/freeDiameter/hss.conf");
        assert_eq!(args.max_ue, 1024);
        assert_eq!(args.db_name, "nextgcore");
        assert!(!args.kill);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-hssd",
            "-c", "/custom/hss.yaml",
            "-e", "debug",
            "--diameter-config", "/custom/hss.conf",
            "--max-ue", "2048",
            "--db-uri", "mongodb://localhost:27017",
            "--db-name", "custom_db",
        ]);
        assert_eq!(args.config, "/custom/hss.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.diameter_config, "/custom/hss.conf");
        assert_eq!(args.max_ue, 2048);
        assert_eq!(args.db_uri, Some("mongodb://localhost:27017".to_string()));
        assert_eq!(args.db_name, "custom_db");
    }

    #[test]
    fn test_args_kill() {
        let args = Args::parse_from(["nextgcore-hssd", "-k"]);
        assert!(args.kill);
    }

    #[test]
    fn test_args_log_options() {
        let args = Args::parse_from([
            "nextgcore-hssd",
            "-l", "/var/log/hss.log",
            "-m",
        ]);
        assert_eq!(args.log_file, Some("/var/log/hss.log".to_string()));
        assert!(args.no_color);
    }
}
