//! NextGCore SMF (Session Management Function)
//!
//! The SMF handles PDU session management in 5G Core and EPC networks.
//!
//! # Architecture
//!
//! The SMF consists of several key components:
//! - Context management (UE, Session, Bearer contexts)
//! - State machines (SMF, GSM, PFCP)
//! - Protocol handlers (N4/PFCP, GTP-C, SBI)
//! - Policy binding (PCC rules to bearers/QoS flows)
//!
//! # Supported Interfaces
//!
//! - N4: PFCP interface to UPF
//! - N7: Policy control interface to PCF
//! - N10: UE context management interface to UDM
//! - N11: PDU session management interface from AMF
//! - S5/S8: GTP-C interface to SGW (EPC mode)

use anyhow::Result;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

mod binding;
mod context;
mod event;
mod gsm_build;
mod gsm_handler;
mod gsm_sm;
mod gtp_build;
mod gtp_handler;
mod gtp_path;
mod gn_build;
mod gn_handler;
mod n4_build;
mod n4_handler;
mod pfcp_path;
mod pfcp_sm;
#[cfg(test)]
mod property_tests;
mod sbi_path;
mod smf_sm;
mod timer;

use context::SmfContext;
use sbi_path::SbiPathManager;
use pfcp_path::PfcpPathManager;
use gtp_path::GtpPathManager;
use timer::TimerManager;

/// SMF Application state
pub struct SmfApp {
    /// SMF context containing all UE/session/bearer data
    pub context: Arc<SmfContext>,
    /// SBI path manager for NF communication
    pub sbi_path: Arc<SbiPathManager>,
    /// PFCP path manager for UPF communication
    pub pfcp_path: Arc<PfcpPathManager>,
    /// GTP path manager for SGW communication (EPC mode)
    pub gtp_path: Arc<GtpPathManager>,
    /// Timer manager
    pub timer_manager: Arc<TimerManager>,
}

impl SmfApp {
    /// Create a new SMF application instance
    pub fn new() -> Self {
        Self {
            context: Arc::new(SmfContext::new()),
            sbi_path: Arc::new(SbiPathManager::new()),
            pfcp_path: Arc::new(PfcpPathManager::new()),
            gtp_path: Arc::new(GtpPathManager::new()),
            timer_manager: Arc::new(TimerManager::new()),
        }
    }

    /// Initialize the SMF
    pub fn init(&self) -> Result<()> {
        log::info!("Initializing SMF context...");
        // Context initialization would load configuration here
        Ok(())
    }

    /// Start the SMF services
    pub fn start(&self) -> Result<()> {
        log::info!("Starting SMF services...");
        // Start SBI server
        // Start PFCP server
        // Start GTP-C server (if EPC mode)
        Ok(())
    }

    /// Stop the SMF services
    pub fn stop(&self) -> Result<()> {
        log::info!("Stopping SMF services...");
        Ok(())
    }
}

impl Default for SmfApp {
    fn default() -> Self {
        Self::new()
    }
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

fn main() -> Result<()> {
    // Initialize logging
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();

    log::info!("NextGCore SMF (Session Management Function)");
    log::info!("Copyright (C) 2019-2024 by Sukchan Lee <acetcom@gmail.com>");
    log::info!("");

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        shutdown_clone.store(true, Ordering::SeqCst);
        SHUTDOWN.store(true, Ordering::SeqCst);
    }).expect("Failed to set Ctrl+C handler");

    // Create SMF application
    let app = SmfApp::new();

    // Initialize
    app.init()?;

    // Start services
    app.start()?;

    log::info!("SMF is ready");

    // Main event loop
    while !shutdown.load(Ordering::SeqCst) && !SHUTDOWN.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    
    // Stop services on shutdown
    app.stop()?;

    log::info!("SMF terminated");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smf_app_new() {
        let app = SmfApp::new();
        assert!(Arc::strong_count(&app.context) == 1);
    }

    #[test]
    fn test_smf_app_init() {
        let app = SmfApp::new();
        assert!(app.init().is_ok());
    }

    #[test]
    fn test_smf_app_lifecycle() {
        let app = SmfApp::new();
        assert!(app.init().is_ok());
        assert!(app.start().is_ok());
        assert!(app.stop().is_ok());
    }
}
