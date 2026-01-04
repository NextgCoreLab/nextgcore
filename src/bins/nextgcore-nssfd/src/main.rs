//! NextGCore NSSF (Network Slice Selection Function)
//!
//! The NSSF is a 5G core network function responsible for:
//! - Selecting the Network Slice instances to serve the UE
//! - Determining the allowed NSSAI and mapping to subscribed S-NSSAIs
//! - Determining the AMF Set to be used to serve the UE

use anyhow::{Context, Result};
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

mod context;
mod event;
mod nnrf_handler;
mod nnssf_build;
mod nnssf_handler;
mod nssf_sm;
mod sbi_path;

pub use context::*;
pub use event::{NssfEvent, NssfEventId, NssfTimerId, SbiEventData, SbiMessage, SbiResponse};
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

    /// Maximum number of NF instances
    #[arg(long, default_value = "512")]
    max_nf: usize,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);


fn main() -> Result<()> {
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
        // TODO: Parse YAML configuration file
        // In C: nssf_context_parse_config()
    } else {
        log::debug!("Configuration file not found: {}", args.config);
    }

    // Build SBI server configuration
    let sbi_config = SbiServerConfig {
        addr: args.sbi_addr.clone(),
        port: args.sbi_port,
        tls_enabled: args.tls,
        tls_cert: args.tls_cert.clone(),
        tls_key: args.tls_key.clone(),
    };

    // Open SBI server
    nssf_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;
    log::info!("SBI server listening on {}:{}", args.sbi_addr, args.sbi_port);

    log::info!("NextGCore NSSF ready");

    // Main event loop
    run_event_loop(&mut nssf_sm, shutdown)?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Close SBI server
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
fn run_event_loop(_nssf_sm: &mut NssfSmContext, shutdown: Arc<AtomicBool>) -> Result<()> {
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
        let args = Args::parse_from(["nextgcore-nssfd"]);
        assert_eq!(args.config, "/etc/nextgcore/nssf.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.sbi_addr, "127.0.0.1");
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
