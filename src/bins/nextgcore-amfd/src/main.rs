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
pub mod ngap_path;
pub mod ngap_asn1;
pub mod nas_security;
pub mod sbi_path;
pub mod namf_handler;
pub mod timer;
pub mod metrics;

#[cfg(test)]
mod property_tests;

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use serde_yaml::Value;

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

    /// NGAP bind address (e.g., "0.0.0.0:38412")
    #[arg(long, default_value = "0.0.0.0:38412")]
    ngap_addr: String,
}

/// AMF application state
pub struct AmfApp {
    /// Running flag
    running: Arc<AtomicBool>,
    /// Timer manager
    timer_manager: timer::TimerManager,
    /// Metrics
    metrics: metrics::AmfMetrics,
    /// AMF context (thread-safe)
    amf_context: Arc<RwLock<context::AmfContext>>,
    /// NGAP event channel sender
    ngap_event_tx: Option<mpsc::Sender<event::AmfEvent>>,
    /// NGAP event channel receiver
    ngap_event_rx: Option<mpsc::Receiver<event::AmfEvent>>,
}

impl AmfApp {
    /// Create a new AMF application
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(1024);
        Self {
            running: Arc::new(AtomicBool::new(true)),
            timer_manager: timer::TimerManager::new(),
            metrics: metrics::AmfMetrics::new(),
            amf_context: Arc::new(RwLock::new(context::AmfContext::new())),
            ngap_event_tx: Some(tx),
            ngap_event_rx: Some(rx),
        }
    }

    /// Initialize the AMF application
    pub async fn init(&mut self, config_path: &str) -> Result<()> {
        log::info!("Initializing AMF...");

        // Initialize AMF context
        context::amf_context_init(64, 1024, 4096);

        // Load configuration from YAML file
        self.load_config(config_path).await?;

        // Initialize SBI
        sbi_path::amf_sbi_open()?;

        log::info!("AMF initialized successfully");
        Ok(())
    }

    /// Load configuration from YAML file
    async fn load_config(&self, config_path: &str) -> Result<()> {
        log::info!("Loading configuration from: {}", config_path);

        // Read and parse YAML file
        let config_content = match std::fs::read_to_string(config_path) {
            Ok(content) => content,
            Err(e) => {
                log::warn!("Could not read config file '{}': {}. Using defaults.", config_path, e);
                return Ok(());
            }
        };

        let yaml: Value = serde_yaml::from_str(&config_content)
            .map_err(|e| anyhow::anyhow!("Failed to parse YAML config: {}", e))?;

        // Get AMF section
        let amf_section = match yaml.get("amf") {
            Some(section) => section,
            None => {
                log::warn!("No 'amf' section in config file");
                return Ok(());
            }
        };

        // Load configuration into context
        {
            let mut ctx = self.amf_context.write().await;

            // Load AMF name
            if let Some(name) = amf_section.get("amf_name").and_then(|v| v.as_str()) {
                ctx.amf_name = Some(name.to_string());
                log::info!("AMF name: {}", name);
            }

            // Load network name
            if let Some(network_name) = amf_section.get("network_name") {
                if let Some(full) = network_name.get("full").and_then(|v| v.as_str()) {
                    ctx.full_name = context::NetworkName { name: full.to_string() };
                }
                if let Some(short) = network_name.get("short").and_then(|v| v.as_str()) {
                    ctx.short_name = context::NetworkName { name: short.to_string() };
                }
            }

            // Load GUAMI list
            if let Some(guami_list) = amf_section.get("guami").and_then(|v| v.as_sequence()) {
                for guami_entry in guami_list {
                    if let Some(guami) = Self::parse_guami(guami_entry) {
                        log::info!(
                            "Configured GUAMI: PLMN {}{}{}-{}{}{}, AMF Region={}, Set={}",
                            guami.plmn_id.mcc1, guami.plmn_id.mcc2, guami.plmn_id.mcc3,
                            guami.plmn_id.mnc1, guami.plmn_id.mnc2,
                            if guami.plmn_id.mnc3 == 0xf { "".to_string() } else { guami.plmn_id.mnc3.to_string() },
                            guami.amf_id.region, guami.amf_id.set
                        );
                        ctx.served_guami.push(guami);
                        ctx.num_of_served_guami += 1;
                    }
                }
            }

            // Load TAI list
            if let Some(tai_list) = amf_section.get("tai").and_then(|v| v.as_sequence()) {
                for tai_entry in tai_list {
                    if let Some(served_tai) = Self::parse_tai(tai_entry) {
                        let tac = served_tai.list0.tac.first().copied().unwrap_or(0);
                        log::info!(
                            "Configured TAI: PLMN {}{}{}-{}{}{}, TAC={}",
                            served_tai.list0.plmn_id.mcc1, served_tai.list0.plmn_id.mcc2, served_tai.list0.plmn_id.mcc3,
                            served_tai.list0.plmn_id.mnc1, served_tai.list0.plmn_id.mnc2,
                            if served_tai.list0.plmn_id.mnc3 == 0xf { "".to_string() } else { served_tai.list0.plmn_id.mnc3.to_string() },
                            tac
                        );
                        ctx.served_tai.push(served_tai);
                        ctx.num_of_served_tai += 1;
                    }
                }
            }

            // Load PLMN support
            if let Some(plmn_list) = amf_section.get("plmn_support").and_then(|v| v.as_sequence()) {
                for plmn_entry in plmn_list {
                    if let Some(plmn_support) = Self::parse_plmn_support(plmn_entry) {
                        log::info!(
                            "Configured PLMN support: PLMN {}{}{}-{}{}{}, {} S-NSSAIs",
                            plmn_support.plmn_id.mcc1, plmn_support.plmn_id.mcc2, plmn_support.plmn_id.mcc3,
                            plmn_support.plmn_id.mnc1, plmn_support.plmn_id.mnc2,
                            if plmn_support.plmn_id.mnc3 == 0xf { "".to_string() } else { plmn_support.plmn_id.mnc3.to_string() },
                            plmn_support.num_of_s_nssai
                        );
                        ctx.plmn_support.push(plmn_support);
                        ctx.num_of_plmn_support += 1;
                    }
                }
            }

            // Load security algorithms
            if let Some(security) = amf_section.get("security") {
                if let Some(integrity_order) = security.get("integrity_order").and_then(|v| v.as_sequence()) {
                    for algo in integrity_order {
                        if let Some(algo_str) = algo.as_str() {
                            let algo_id = Self::parse_integrity_algorithm(algo_str);
                            ctx.integrity_order.push(algo_id);
                            ctx.num_of_integrity_order += 1;
                        }
                    }
                }
                if let Some(ciphering_order) = security.get("ciphering_order").and_then(|v| v.as_sequence()) {
                    for algo in ciphering_order {
                        if let Some(algo_str) = algo.as_str() {
                            let algo_id = Self::parse_ciphering_algorithm(algo_str);
                            ctx.ciphering_order.push(algo_id);
                            ctx.num_of_ciphering_order += 1;
                        }
                    }
                }
            }

            log::info!(
                "AMF configuration loaded: {} GUAMI, {} TAI, {} PLMN support",
                ctx.num_of_served_guami, ctx.num_of_served_tai, ctx.num_of_plmn_support
            );
        }

        Ok(())
    }

    /// Parse PLMN ID from YAML
    fn parse_plmn_id(plmn_value: Option<&Value>) -> Option<context::PlmnId> {
        let plmn = plmn_value?;
        let mcc = plmn.get("mcc").and_then(|v| {
            v.as_u64().map(|n| n.to_string()).or_else(|| v.as_str().map(|s| s.to_string()))
        })?;
        let mnc = plmn.get("mnc").and_then(|v| {
            v.as_u64().map(|n| n.to_string()).or_else(|| v.as_str().map(|s| s.to_string()))
        })?;

        Some(context::PlmnId::new(&mcc, &mnc))
    }

    /// Parse GUAMI from YAML entry
    fn parse_guami(entry: &Value) -> Option<context::Guami> {
        let plmn_id = Self::parse_plmn_id(entry.get("plmn_id"))?;

        let amf_id_section = entry.get("amf_id")?;
        let region = amf_id_section.get("region").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
        let set = amf_id_section.get("set").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
        let pointer = amf_id_section.get("pointer").and_then(|v| v.as_u64()).unwrap_or(0) as u8;

        Some(context::Guami {
            plmn_id,
            amf_id: context::AmfId { region, set, pointer },
        })
    }

    /// Parse TAI from YAML entry
    fn parse_tai(entry: &Value) -> Option<context::ServedTai> {
        let plmn_id = Self::parse_plmn_id(entry.get("plmn_id"))?;
        let tac = entry.get("tac").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

        Some(context::ServedTai {
            list0: context::Tai0List {
                plmn_id,
                tac: vec![tac],
            },
            ..Default::default()
        })
    }

    /// Parse PLMN support from YAML entry
    fn parse_plmn_support(entry: &Value) -> Option<context::PlmnSupport> {
        let plmn_id = Self::parse_plmn_id(entry.get("plmn_id"))?;

        let mut s_nssai_list = Vec::new();
        if let Some(s_nssai_array) = entry.get("s_nssai").and_then(|v| v.as_sequence()) {
            for s_nssai_entry in s_nssai_array {
                let sst = s_nssai_entry.get("sst").and_then(|v| v.as_u64()).unwrap_or(1) as u8;
                let sd = s_nssai_entry.get("sd").and_then(|v| v.as_u64()).map(|n| n as u32);
                s_nssai_list.push(context::SNssai { sst, sd });
            }
        }

        let num_of_s_nssai = s_nssai_list.len();
        Some(context::PlmnSupport {
            plmn_id,
            num_of_s_nssai,
            s_nssai: s_nssai_list,
        })
    }

    /// Parse integrity algorithm name to ID
    fn parse_integrity_algorithm(name: &str) -> u8 {
        match name.to_uppercase().as_str() {
            "NIA0" => 0,
            "NIA1" | "128-NIA1" => 1,
            "NIA2" | "128-NIA2" => 2,
            "NIA3" | "128-NIA3" => 3,
            _ => 0,
        }
    }

    /// Parse ciphering algorithm name to ID
    fn parse_ciphering_algorithm(name: &str) -> u8 {
        match name.to_uppercase().as_str() {
            "NEA0" => 0,
            "NEA1" | "128-NEA1" => 1,
            "NEA2" | "128-NEA2" => 2,
            "NEA3" | "128-NEA3" => 3,
            _ => 0,
        }
    }

    /// Initialize NGAP server (async)
    pub async fn init_ngap(&mut self, ngap_addr: SocketAddr) -> Result<()> {
        log::info!("Initializing NGAP server on {}...", ngap_addr);

        let event_tx = self.ngap_event_tx.take()
            .ok_or_else(|| anyhow::anyhow!("NGAP event sender already taken"))?;

        ngap_path::amf_ngap_open(
            Some(ngap_addr),
            Arc::clone(&self.amf_context),
            event_tx,
        ).await?;

        log::info!("NGAP server initialized on {}", ngap_addr);
        Ok(())
    }

    /// Run the AMF main loop (async version)
    pub async fn run_async(&mut self) -> Result<()> {
        log::info!("AMF running (async mode)...");

        // Take the event receiver
        let mut event_rx = self.ngap_event_rx.take();

        while self.running.load(Ordering::SeqCst) {
            // Poll for NGAP messages
            match ngap_path::amf_ngap_poll().await {
                Ok(true) => {
                    log::debug!("Processed NGAP message");
                }
                Ok(false) => {
                    // No message available
                }
                Err(e) => {
                    log::warn!("NGAP poll error: {}", e);
                }
            }

            // Process events from the event channel
            if let Some(ref mut rx) = event_rx {
                while let Ok(event) = rx.try_recv() {
                    self.handle_event(event).await;
                }
            }

            // Brief yield to allow other tasks
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        log::info!("AMF main loop exited");
        Ok(())
    }

    /// Handle an AMF event
    async fn handle_event(&self, event: event::AmfEvent) {
        log::debug!("Handling event: {:?}", event.id);

        match event.id {
            event::AmfEventId::NgapMessage => {
                if let Some(ref ngap_data) = event.ngap {
                    log::debug!("NGAP message event: gnb_id={:?}", ngap_data.gnb_id);
                    // Process through NGAP FSM
                    // Note: Route to appropriate gNB FSM
                    // gNB FSM lookup and dispatch handled by ngap_path and ngap_sm modules
                }
            }
            event::AmfEventId::NgapTimer => {
                log::debug!("NGAP timer event");
            }
            _ => {
                log::debug!("Unhandled event type: {:?}", event.id);
            }
        }
    }

    /// Run the AMF main loop (sync version, for backwards compatibility)
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

    /// Shutdown the AMF application (async version)
    pub async fn shutdown_async(&mut self) {
        log::info!("Shutting down AMF...");

        // Close NGAP
        ngap_path::amf_ngap_close().await;

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

    /// Get AMF context reference
    pub fn amf_context(&self) -> Arc<RwLock<context::AmfContext>> {
        Arc::clone(&self.amf_context)
    }
}

impl Default for AmfApp {
    fn default() -> Self {
        Self::new()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
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

    // Initialize (async)
    app.init(&args.config).await?;

    // Parse NGAP address and initialize NGAP server
    let ngap_addr: SocketAddr = args.ngap_addr.parse()
        .map_err(|e| anyhow::anyhow!("Invalid NGAP address '{}': {}", args.ngap_addr, e))?;
    app.init_ngap(ngap_addr).await?;

    // Run async main loop
    app.run_async().await?;

    // Shutdown (async version)
    app.shutdown_async().await;

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
