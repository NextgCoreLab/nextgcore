//! NextGCore AMF (Access and Mobility Management Function)
//!
//! This is the main entry point for the AMF network function.

pub mod amf_sm;
pub mod context;
pub mod emergency; // #203: Emergency services (TS 23.167)
pub mod event;
pub mod gmm_build;
pub mod gmm_handler;
pub mod gmm_sm;
pub mod metrics;
pub mod namf_handler;
pub mod nas_security;
pub mod ngap_asn1;
pub mod ngap_build;
pub mod ngap_handler;
pub mod ngap_mcast; // MBS: NGAP multicast session procedures (TS 38.413 / TS 23.247)
pub mod ngap_path;
pub mod ngap_sm;
pub mod sbi_path;
pub mod snpn; // Rel-16: SNPN authentication (TS 23.501 §5.30)
pub mod timer;
pub mod xn_handover; // Rel-15: Xn path switch and N2 handover (TS 23.502 §4.9)

#[cfg(test)]
mod property_tests;

use anyhow::Result;
use clap::Parser;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

// ---------------------------------------------------------------------------
// Typed YAML configuration structs
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct PlmnIdYaml {
    mcc: Option<serde_yaml::Value>,
    mnc: Option<serde_yaml::Value>,
}

#[derive(Debug, Default, Deserialize)]
struct AmfIdYaml {
    region: Option<u8>,
    set: Option<u16>,
    pointer: Option<u8>,
}

#[derive(Debug, Default, Deserialize)]
struct GuamiYaml {
    plmn_id: Option<PlmnIdYaml>,
    amf_id: Option<AmfIdYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct TaiYaml {
    plmn_id: Option<PlmnIdYaml>,
    tac: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct SNssaiYaml {
    sst: Option<u8>,
    sd: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct PlmnSupportYaml {
    plmn_id: Option<PlmnIdYaml>,
    s_nssai: Option<Vec<SNssaiYaml>>,
}

#[derive(Debug, Default, Deserialize)]
struct SecurityYaml {
    integrity_order: Option<Vec<String>>,
    ciphering_order: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
struct NetworkNameYaml {
    full: Option<String>,
    short: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct NrfClientYaml {
    uri: String,
}

#[derive(Debug, Default, Deserialize)]
struct SbiClientYaml {
    nrf: Option<Vec<NrfClientYaml>>,
}

#[derive(Debug, Default, Deserialize)]
struct SbiYaml {
    client: Option<SbiClientYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct AmfSection {
    amf_name: Option<String>,
    network_name: Option<NetworkNameYaml>,
    guami: Option<Vec<GuamiYaml>>,
    tai: Option<Vec<TaiYaml>>,
    plmn_support: Option<Vec<PlmnSupportYaml>>,
    security: Option<SecurityYaml>,
    sbi: Option<SbiYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct AmfYaml {
    amf: Option<AmfSection>,
}

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
        log::info!("Loading configuration from: {config_path}");

        let config_content = match std::fs::read_to_string(config_path) {
            Ok(content) => content,
            Err(e) => {
                log::warn!("Could not read config file '{config_path}': {e}. Using defaults.");
                return Ok(());
            }
        };

        let yaml: AmfYaml = match serde_yaml::from_str(&config_content) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("Failed to parse YAML config '{config_path}': {e}. Using defaults.");
                return Ok(());
            }
        };

        let amf_section = match yaml.amf {
            Some(s) => s,
            None => {
                log::warn!("No 'amf' section in config file");
                return Ok(());
            }
        };

        // Seed NRF URI into SBI context for NF registration
        if let Some(sbi) = &amf_section.sbi {
            if let Some(client) = &sbi.client {
                if let Some(nrf_list) = &client.nrf {
                    if let Some(nrf) = nrf_list.first() {
                        log::info!("NRF URI configured: {}", nrf.uri);
                        ogs_sbi::context::global_context()
                            .set_nrf_uri(&nrf.uri)
                            .await;
                    }
                }
            }
        }

        let mut ctx = self.amf_context.write().await;

        // AMF name
        if let Some(name) = amf_section.amf_name {
            log::info!("AMF name: {name}");
            ctx.amf_name = Some(name);
        }

        // Network name
        if let Some(nn) = amf_section.network_name {
            if let Some(full) = nn.full {
                ctx.full_name = context::NetworkName { name: full };
            }
            if let Some(short) = nn.short {
                ctx.short_name = context::NetworkName { name: short };
            }
        }

        // GUAMI list
        for entry in amf_section.guami.unwrap_or_default() {
            if let Some(guami) = Self::resolve_guami(entry) {
                log::info!(
                    "Configured GUAMI: PLMN {}{}{}-{}{}{}, AMF Region={}, Set={}",
                    guami.plmn_id.mcc1,
                    guami.plmn_id.mcc2,
                    guami.plmn_id.mcc3,
                    guami.plmn_id.mnc1,
                    guami.plmn_id.mnc2,
                    if guami.plmn_id.mnc3 == 0xf {
                        String::new()
                    } else {
                        guami.plmn_id.mnc3.to_string()
                    },
                    guami.amf_id.region,
                    guami.amf_id.set
                );
                ctx.served_guami.push(guami);
                ctx.num_of_served_guami += 1;
            }
        }

        // TAI list
        for entry in amf_section.tai.unwrap_or_default() {
            if let Some(served_tai) = Self::resolve_tai(entry) {
                let tac = served_tai.list0.tac.first().copied().unwrap_or(0);
                log::info!(
                    "Configured TAI: PLMN {}{}{}-{}{}{}, TAC={}",
                    served_tai.list0.plmn_id.mcc1,
                    served_tai.list0.plmn_id.mcc2,
                    served_tai.list0.plmn_id.mcc3,
                    served_tai.list0.plmn_id.mnc1,
                    served_tai.list0.plmn_id.mnc2,
                    if served_tai.list0.plmn_id.mnc3 == 0xf {
                        String::new()
                    } else {
                        served_tai.list0.plmn_id.mnc3.to_string()
                    },
                    tac
                );
                ctx.served_tai.push(served_tai);
                ctx.num_of_served_tai += 1;
            }
        }

        // PLMN support
        for entry in amf_section.plmn_support.unwrap_or_default() {
            if let Some(plmn_support) = Self::resolve_plmn_support(entry) {
                log::info!(
                    "Configured PLMN support: PLMN {}{}{}-{}{}{}, {} S-NSSAIs",
                    plmn_support.plmn_id.mcc1,
                    plmn_support.plmn_id.mcc2,
                    plmn_support.plmn_id.mcc3,
                    plmn_support.plmn_id.mnc1,
                    plmn_support.plmn_id.mnc2,
                    if plmn_support.plmn_id.mnc3 == 0xf {
                        String::new()
                    } else {
                        plmn_support.plmn_id.mnc3.to_string()
                    },
                    plmn_support.num_of_s_nssai
                );
                ctx.plmn_support.push(plmn_support);
                ctx.num_of_plmn_support += 1;
            }
        }

        // Security algorithms
        if let Some(security) = amf_section.security {
            for algo_str in security.integrity_order.unwrap_or_default() {
                let algo_id = Self::parse_integrity_algorithm(&algo_str);
                ctx.integrity_order.push(algo_id);
                ctx.num_of_integrity_order += 1;
            }
            for algo_str in security.ciphering_order.unwrap_or_default() {
                let algo_id = Self::parse_ciphering_algorithm(&algo_str);
                ctx.ciphering_order.push(algo_id);
                ctx.num_of_ciphering_order += 1;
            }
        }

        log::info!(
            "AMF configuration loaded: {} GUAMI, {} TAI, {} PLMN support",
            ctx.num_of_served_guami,
            ctx.num_of_served_tai,
            ctx.num_of_plmn_support
        );

        Ok(())
    }

    /// Resolve a PLMN ID from the typed YAML struct (mcc/mnc may be int or string)
    fn resolve_plmn_id(plmn: PlmnIdYaml) -> Option<context::PlmnId> {
        let mcc = plmn.mcc.and_then(|v| match v {
            serde_yaml::Value::Number(n) => n.as_u64().map(|x| x.to_string()),
            serde_yaml::Value::String(s) => Some(s),
            _ => None,
        })?;
        let mnc = plmn.mnc.and_then(|v| match v {
            serde_yaml::Value::Number(n) => n.as_u64().map(|x| x.to_string()),
            serde_yaml::Value::String(s) => Some(s),
            _ => None,
        })?;
        Some(context::PlmnId::new(&mcc, &mnc))
    }

    /// Build a runtime Guami from its typed YAML representation
    fn resolve_guami(entry: GuamiYaml) -> Option<context::Guami> {
        let plmn_id = Self::resolve_plmn_id(entry.plmn_id?)?;
        let amf_id_yaml = entry.amf_id.unwrap_or_default();
        Some(context::Guami {
            plmn_id,
            amf_id: context::AmfId {
                region: amf_id_yaml.region.unwrap_or(0),
                set: amf_id_yaml.set.unwrap_or(0),
                pointer: amf_id_yaml.pointer.unwrap_or(0),
            },
        })
    }

    /// Build a runtime ServedTai from its typed YAML representation
    fn resolve_tai(entry: TaiYaml) -> Option<context::ServedTai> {
        let plmn_id = Self::resolve_plmn_id(entry.plmn_id?)?;
        Some(context::ServedTai {
            list0: context::Tai0List {
                plmn_id,
                tac: vec![entry.tac.unwrap_or(0)],
            },
            ..Default::default()
        })
    }

    /// Build a runtime PlmnSupport from its typed YAML representation
    fn resolve_plmn_support(entry: PlmnSupportYaml) -> Option<context::PlmnSupport> {
        let plmn_id = Self::resolve_plmn_id(entry.plmn_id?)?;
        let s_nssai_list: Vec<context::SNssai> = entry
            .s_nssai
            .unwrap_or_default()
            .into_iter()
            .map(|n| context::SNssai {
                sst: n.sst.unwrap_or(1),
                sd: n.sd,
            })
            .collect();
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
        log::info!("Initializing NGAP server on {ngap_addr}...");

        let event_tx = self
            .ngap_event_tx
            .take()
            .ok_or_else(|| anyhow::anyhow!("NGAP event sender already taken"))?;

        ngap_path::amf_ngap_open(Some(ngap_addr), Arc::clone(&self.amf_context), event_tx).await?;

        log::info!("NGAP server initialized on {ngap_addr}");
        Ok(())
    }

    /// Run the AMF main loop (async version)
    pub async fn run_async(&mut self) -> Result<()> {
        log::info!("AMF running (async mode)...");

        // Take the event receiver
        let mut event_rx = self.ngap_event_rx.take();

        // Periodic heartbeat interval (replaces the 10ms sleep)
        let mut heartbeat = tokio::time::interval(tokio::time::Duration::from_secs(10));

        loop {
            // Drain all pending events without sleeping between them, then
            // block until the next event or heartbeat tick arrives.
            tokio::select! {
                // An event is ready on the mpsc channel — process it immediately.
                Some(event) = async {
                    if let Some(ref mut rx) = event_rx { rx.recv().await } else { None }
                } => {
                    self.handle_event(event).await;
                    // Drain any additional events that arrived back-to-back.
                    if let Some(ref mut rx) = event_rx {
                        while let Ok(event) = rx.try_recv() {
                            self.handle_event(event).await;
                        }
                    }
                }

                // Periodic tick: run NGAP poll and check the shutdown flag.
                _ = heartbeat.tick() => {
                    if !self.running.load(Ordering::SeqCst) {
                        break;
                    }
                    match ngap_path::amf_ngap_poll().await {
                        Ok(true) => log::debug!("Processed NGAP message"),
                        Ok(false) => {}
                        Err(e) => log::warn!("NGAP poll error: {e}"),
                    }
                }
            }

            if !self.running.load(Ordering::SeqCst) {
                break;
            }
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
    let ngap_addr: SocketAddr = args
        .ngap_addr
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid NGAP address '{}': {}", args.ngap_addr, e))?;
    app.init_ngap(ngap_addr).await?;

    // Register with NRF (if configured)
    let sbi_addr = std::env::var("AMF_SBI_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
    let sbi_port: u16 = std::env::var("AMF_SBI_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(7777);
    match sbi_path::amf_nrf_register(&sbi_addr, sbi_port).await {
        Ok(nf_instance_id) if !nf_instance_id.is_empty() => {
            ogs_sbi::heartbeat::spawn_heartbeat_worker(nf_instance_id, 5);
        }
        Ok(_) => {}
        Err(e) => {
            log::warn!("NRF registration failed (will operate without NRF): {e}");
        }
    }

    // Discover AUSF and SMF from NRF
    if let Err(e) = sbi_path::amf_nrf_discover("AUSF", "nausf-auth").await {
        log::warn!("AUSF discovery failed (will retry on demand): {e}");
    }
    if let Err(e) = sbi_path::amf_nrf_discover("SMF", "nsmf-pdusession").await {
        log::warn!("SMF discovery failed (will retry on demand): {e}");
    }

    log::info!("NextGCore AMF ready");

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
