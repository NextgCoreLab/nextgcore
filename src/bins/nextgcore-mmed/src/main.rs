//! NextGCore MME (Mobility Management Entity)
//!
//! Port of src/mme/ - Mobility Management Entity for EPC

use anyhow::Result;
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub mod context;
pub mod sm;
pub mod emm_build;
pub mod emm_handler;
pub mod esm_build;
pub mod esm_handler;
pub mod s1ap_build;
pub mod s1ap_handler;
pub mod s11_build;
pub mod s11_handler;
pub mod gtp_path;
pub mod nas_security;
pub mod nas_path;
pub mod sgsap_build;
pub mod sgsap_handler;
pub mod fd_path;
pub mod s6a_handler;
pub mod sbc_message;
pub mod sbc_handler;

#[cfg(test)]
mod property_tests;

/// NextGCore MME - Mobility Management Entity
#[derive(Parser, Debug)]
#[command(name = "nextgcore-mmed")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "EPC Mobility Management Entity")]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "/etc/nextgcore/mme.yaml")]
    config: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Disable color output
    #[arg(long)]
    no_color: bool,

    /// Run in daemon mode
    #[arg(short, long)]
    daemon: bool,
}

/// MME application state
pub struct MmeApp {
    /// Running flag
    running: Arc<AtomicBool>,
    /// GTP path state
    gtp_state: gtp_path::GtpPathState,
    /// MME state machine
    mme_fsm: sm::MmeFsm,
}

impl MmeApp {
    /// Create a new MME application
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(true)),
            gtp_state: gtp_path::GtpPathState::default(),
            mme_fsm: sm::MmeFsm::new(),
        }
    }

    /// Initialize the MME application
    pub fn init(&mut self, _config_path: &str) -> Result<()> {
        log::info!("Initializing MME...");

        // Initialize MME context
        context::mme_context_init();
        log::debug!("MME context initialized");

        // Initialize MME state machine
        sm::Fsm::init(&mut self.mme_fsm);
        log::debug!("MME state machine initialized: {:?}", self.mme_fsm.state());

        // Initialize GTP path (S11 interface to SGW)
        if let Err(e) = gtp_path::gtp_open(&mut self.gtp_state) {
            log::error!("Failed to open GTP path: {}", e);
            return Err(anyhow::anyhow!("GTP path initialization failed: {}", e));
        }
        log::debug!("GTP path initialized");

        // Initialize Diameter S6a interface
        if let Err(e) = fd_path::mme_fd_init() {
            log::error!("Failed to initialize Diameter: {}", e);
            return Err(anyhow::anyhow!("Diameter initialization failed: {}", e));
        }
        log::debug!("Diameter S6a interface initialized");

        log::info!("MME initialized successfully");
        Ok(())
    }

    /// Run the MME main loop
    pub fn run(&self) -> Result<()> {
        log::info!("MME running...");

        while self.running.load(Ordering::SeqCst) {
            // Process events
            // In a real implementation, this would:
            // 1. Poll for S1AP messages from eNBs
            // 2. Poll for GTP-C messages from SGW/PGW
            // 3. Poll for Diameter messages from HSS
            // 4. Poll for SGsAP messages from VLR
            // 5. Process timer events
            // 6. Handle state machine transitions

            // For now, just sleep briefly
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        log::info!("MME main loop exited");
        Ok(())
    }

    /// Shutdown the MME application
    pub fn shutdown(&mut self) {
        log::info!("Shutting down MME...");

        // Close Diameter S6a interface
        fd_path::mme_fd_final();
        log::debug!("Diameter S6a interface closed");

        // Close GTP path
        if let Err(e) = gtp_path::gtp_close(&mut self.gtp_state) {
            log::error!("Failed to close GTP path: {}", e);
        }
        log::debug!("GTP path closed");

        // Finalize MME state machine
        sm::Fsm::fini(&mut self.mme_fsm);
        log::debug!("MME state machine finalized");

        // Finalize MME context
        context::mme_context_final();
        log::debug!("MME context finalized");

        log::info!("MME shutdown complete");
    }

    /// Signal the application to stop
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Get the running flag for signal handlers
    pub fn running_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.running)
    }
}

impl Default for MmeApp {
    fn default() -> Self {
        Self::new()
    }
}

fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize logging
    let log_level = match args.log_level.to_lowercase().as_str() {
        "trace" => log::LevelFilter::Trace,
        "debug" => log::LevelFilter::Debug,
        "info" => log::LevelFilter::Info,
        "warn" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        _ => log::LevelFilter::Info,
    };

    env_logger::Builder::new()
        .filter_level(log_level)
        .format_timestamp_millis()
        .init();

    log::info!("NextGCore MME v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Configuration: {}", args.config);

    // Create MME application
    let mut app = MmeApp::new();

    // Setup signal handlers
    let running = app.running_flag();
    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        running.store(false, Ordering::SeqCst);
    })?;

    // Initialize
    app.init(&args.config)?;

    // Run main loop
    app.run()?;

    // Shutdown
    app.shutdown();

    log::info!("NextGCore MME terminated");
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mme_app_creation() {
        let app = MmeApp::new();
        assert!(app.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_mme_app_stop() {
        let app = MmeApp::new();
        assert!(app.running.load(Ordering::SeqCst));
        app.stop();
        assert!(!app.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_mme_app_running_flag() {
        let app = MmeApp::new();
        let flag = app.running_flag();
        assert!(flag.load(Ordering::SeqCst));
        app.stop();
        assert!(!flag.load(Ordering::SeqCst));
    }
}
