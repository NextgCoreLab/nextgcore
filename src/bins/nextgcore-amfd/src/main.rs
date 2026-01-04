//! NextGCore AMF (Access and Mobility Management Function)
//!
//! This is the main entry point for the AMF network function.

pub mod context;
pub mod event;
pub mod amf_sm;
pub mod gmm_sm;
pub mod ngap_sm;
pub mod gmm_build;
pub mod gmm_handler;
pub mod ngap_build;
pub mod ngap_handler;
pub mod nas_security;
pub mod sbi_path;
pub mod namf_handler;
pub mod timer;
pub mod metrics;

#[cfg(test)]
mod property_tests;

use anyhow::Result;
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// NextGCore AMF - Access and Mobility Management Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-amfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Access and Mobility Management Function")]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "/etc/nextgcore/amf.yaml")]
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

/// AMF application state
pub struct AmfApp {
    /// Running flag
    running: Arc<AtomicBool>,
    /// Timer manager
    timer_manager: timer::TimerManager,
    /// Metrics
    metrics: metrics::AmfMetrics,
}

impl AmfApp {
    /// Create a new AMF application
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(true)),
            timer_manager: timer::TimerManager::new(),
            metrics: metrics::AmfMetrics::new(),
        }
    }

    /// Initialize the AMF application
    pub fn init(&mut self, _config_path: &str) -> Result<()> {
        log::info!("Initializing AMF...");

        // Initialize AMF context
        context::amf_context_init(64, 1024, 4096);

        // Initialize SBI
        sbi_path::amf_sbi_open()?;

        log::info!("AMF initialized successfully");
        Ok(())
    }

    /// Run the AMF main loop
    pub fn run(&self) -> Result<()> {
        log::info!("AMF running...");

        while self.running.load(Ordering::SeqCst) {
            // Process events
            // In a real implementation, this would:
            // 1. Poll for NGAP messages from gNBs
            // 2. Poll for SBI messages from other NFs
            // 3. Process timer events
            // 4. Handle state machine transitions

            // For now, just sleep briefly
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        log::info!("AMF main loop exited");
        Ok(())
    }

    /// Shutdown the AMF application
    pub fn shutdown(&mut self) {
        log::info!("Shutting down AMF...");

        // Close SBI
        sbi_path::amf_sbi_close();

        // Finalize AMF context
        context::amf_context_final();

        log::info!("AMF shutdown complete");
    }

    /// Signal the application to stop
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Get the running flag for signal handlers
    pub fn running_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.running)
    }

    /// Get metrics reference
    pub fn metrics(&self) -> &metrics::AmfMetrics {
        &self.metrics
    }

    /// Get timer manager reference
    pub fn timer_manager(&self) -> &timer::TimerManager {
        &self.timer_manager
    }
}

impl Default for AmfApp {
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

    log::info!("NextGCore AMF v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Configuration: {}", args.config);

    // Create AMF application
    let mut app = AmfApp::new();

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

    log::info!("NextGCore AMF terminated");
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amf_app_creation() {
        let app = AmfApp::new();
        assert!(app.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_amf_app_stop() {
        let app = AmfApp::new();
        assert!(app.running.load(Ordering::SeqCst));
        app.stop();
        assert!(!app.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_amf_app_running_flag() {
        let app = AmfApp::new();
        let flag = app.running_flag();
        assert!(flag.load(Ordering::SeqCst));
        app.stop();
        assert!(!flag.load(Ordering::SeqCst));
    }

    #[test]
    fn test_amf_app_metrics() {
        let app = AmfApp::new();
        app.metrics().inc(metrics::GlobalMetric::RmRegInitReq);
        assert_eq!(app.metrics().get(metrics::GlobalMetric::RmRegInitReq), 1);
    }
}
