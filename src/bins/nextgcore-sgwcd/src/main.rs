//! NextGCore SGWC (Serving Gateway Control Plane)
//!
//! Port of src/sgwc/ - Serving Gateway Control Plane for EPC
//!
//! The SGWC handles control plane signaling for the Serving Gateway:
//! - S11 interface: GTPv2-C messages from MME
//! - S5-C interface: GTPv2-C messages from PGW
//! - SXA interface: PFCP messages from SGW-U

use anyhow::Result;
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub mod context;
pub mod event;
pub mod gtp_path;
pub mod pfcp_path;
pub mod pfcp_sm;
pub mod s11_build;
pub mod s11_handler;
pub mod s11_parse;
pub mod s5c_handler;
pub mod sm;
pub mod sxa_build;
pub mod sxa_handler;
pub mod sxa_response;
pub mod timer;

use context::sgwc_self;
use event::{SgwcEvent, SgwcEventId};
use sm::SgwcFsm;
use timer::SgwcTimerId;

/// NextGCore SGWC - Serving Gateway Control Plane
#[derive(Parser, Debug)]
#[command(name = "nextgcore-sgwcd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "EPC Serving Gateway Control Plane")]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "/etc/nextgcore/sgwc.yaml")]
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

/// SGWC application state
pub struct SgwcApp {
    /// Running flag
    running: Arc<AtomicBool>,
    /// SGWC state machine
    sgwc_fsm: SgwcFsm,
    /// Timer manager
    timer_mgr: timer::TimerManager,
    /// The Sxa receive loop, so shutdown can wait for it (#54).
    pfcp_task: Option<tokio::task::JoinHandle<()>>,
    /// Asks that loop to stop.
    pfcp_shutdown: Option<tokio::sync::watch::Sender<bool>>,
}

impl SgwcApp {
    /// Create a new SGWC application
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(true)),
            sgwc_fsm: SgwcFsm::new(),
            timer_mgr: timer::TimerManager::new(),
            pfcp_task: None,
            pfcp_shutdown: None,
        }
    }

    /// Initialize the SGWC application
    ///
    /// #54: `async` because opening the Sxa path now binds a real tokio socket and sets up
    /// the PFCP association toward the SGW-U. It used to call a `pfcp_open` that opened
    /// nothing, which is why none of this had to be awaited.
    pub async fn init(&mut self, _config_path: &str) -> Result<()> {
        log::info!("Initializing SGWC...");

        // Initialize SGWC context with default pool sizes
        let ctx = sgwc_self();
        // In a real implementation, these values would come from config
        if let Ok(mut ctx_guard) = Arc::try_unwrap(ctx.clone()).inspect_err(|_arc| {
            // Context is shared, we need to use interior mutability
            // For now, just log that we're using defaults
            log::debug!("Using default context configuration");
        }) {
            ctx_guard.init(1024, 4096, 16384, 32768);
        }
        log::debug!("SGWC context initialized");

        // Initialize SGWC state machine with entry event
        let entry_event = SgwcEvent::entry();
        self.sgwc_fsm.dispatch(&entry_event);
        log::debug!("SGWC state machine initialized: {:?}", self.sgwc_fsm.state);

        // Open GTP-C path (S11 and S5-C interfaces)
        if let Err(e) = gtp_path::gtp_open() {
            log::error!("Failed to open GTP path: {e}");
            return Err(anyhow::anyhow!("GTP path initialization failed: {e}"));
        }
        log::debug!("GTP path initialized (S11/S5-C interfaces)");

        // Open PFCP path (SXA interface to SGW-U)
        let pfcp = match pfcp_path::pfcp_open().await {
            Ok(node) => node,
            Err(e) => {
                log::error!("Failed to open PFCP path: {e}");
                gtp_path::gtp_close();
                return Err(anyhow::anyhow!("PFCP path initialization failed: {e}"));
            }
        };
        log::debug!(
            "PFCP path initialized (SXA interface on {})",
            pfcp.local_addr()
        );

        // The receive loop and the outbound drain. Without this task nothing reads the
        // socket, so no PFCP response could complete a transaction and every gated S11
        // procedure would time out.
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        self.pfcp_shutdown = Some(shutdown_tx);
        self.pfcp_task = Some(tokio::spawn(pfcp.clone().run(shutdown_rx)));

        // Associate with the SGW-U (TS 29.244 §6.2.6.2). NOT fatal: an SGW-U that comes up
        // after the SGW-C is the normal bring-up order in the compose stack, and refusing
        // to start would make the slower peer an outage. The association is retried by the
        // first session request that needs it.
        let sgwu = pfcp_path::configured_sgwu_addr();
        match pfcp.associate(sgwu).await {
            Ok(()) => log::info!("Associated with SGW-U {sgwu}"),
            Err(e) => log::warn!(
                "No PFCP association with SGW-U {sgwu} yet ({e}); session requests will \
                 fail until it answers"
            ),
        }

        log::info!("SGWC initialized successfully");
        Ok(())
    }

    /// Run the SGWC main loop
    ///
    /// S11/S5-C datagrams are read by `gtp_path`'s own OS threads and Sxa datagrams by the
    /// spawned receive loop, so this loop's job is the timers. It `await`s rather than
    /// `thread::sleep`s: blocking a runtime worker for 100ms at a time would stall the Sxa
    /// task on a single-threaded runtime, which is the difference between a gated S11
    /// procedure completing and timing out.
    pub async fn run(&mut self) -> Result<()> {
        log::info!("SGWC running...");

        while self.running.load(Ordering::SeqCst) {
            self.process_timers();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        log::info!("SGWC main loop exited");
        Ok(())
    }

    /// Process timer events
    fn process_timers(&mut self) {
        // Check for expired timers and generate events
        let expired = self.timer_mgr.check_expired();
        for timer_id in expired {
            log::debug!("Timer expired: {timer_id:?}");
            // Create timer event and dispatch to state machine
            // Convert timer::SgwcTimerId to event::SgwcTimerId
            let event_timer_id = match timer_id {
                SgwcTimerId::PfcpAssociation => event::SgwcTimerId::PfcpAssociation,
                SgwcTimerId::PfcpNoHeartbeat => event::SgwcTimerId::PfcpNoHeartbeat,
            };
            let event = SgwcEvent {
                id: SgwcEventId::SxaTimer,
                timer_id: Some(event_timer_id),
                gtp: None,
                pfcp: None,
                sess_id: None,
                sgwc_ue_id: None,
            };
            self.sgwc_fsm.dispatch(&event);
        }
    }

    /// Handle an S11 message (from MME)
    #[allow(dead_code)]
    pub fn handle_s11_message(&mut self, gnode_id: u64, xact_id: u64, data: Vec<u8>) {
        let event = SgwcEvent::s11_message(gnode_id, xact_id, data);
        self.sgwc_fsm.dispatch(&event);
    }

    /// Handle an S5-C message (from PGW)
    #[allow(dead_code)]
    pub fn handle_s5c_message(&mut self, gnode_id: u64, xact_id: u64, data: Vec<u8>) {
        let event = SgwcEvent::s5c_message(gnode_id, xact_id, data);
        self.sgwc_fsm.dispatch(&event);
    }

    /// Handle an SXA message (from SGW-U)
    #[allow(dead_code)]
    pub fn handle_sxa_message(&mut self, pfcp_node_id: u64, xact_id: u64, data: Vec<u8>) {
        let event = SgwcEvent::sxa_message(pfcp_node_id, xact_id, data);
        self.sgwc_fsm.dispatch(&event);
    }

    /// Shutdown the SGWC application
    pub async fn shutdown(&mut self) {
        log::info!("Shutting down SGWC...");

        // Stop the Sxa receive loop and wait for it, so a session removed during teardown
        // is not raced by a datagram still being processed.
        if let Some(tx) = self.pfcp_shutdown.take() {
            let _ = tx.send(true);
        }
        if let Some(task) = self.pfcp_task.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), task).await;
        }

        // Send exit event to state machine
        let exit_event = SgwcEvent::exit();
        self.sgwc_fsm.dispatch(&exit_event);
        log::debug!("SGWC state machine finalized");

        // Close PFCP path
        pfcp_path::pfcp_close().await;
        log::debug!("PFCP path closed");

        // Close GTP path
        gtp_path::gtp_close();
        log::debug!("GTP path closed");

        // Finalize context
        let ctx = sgwc_self();
        if let Ok(mut ctx_guard) = Arc::try_unwrap(ctx.clone()).map_err(|_| {
            log::debug!("Context cleanup via shared reference");
        }) {
            ctx_guard.fini();
        }
        log::debug!("SGWC context finalized");

        log::info!("SGWC shutdown complete");
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

impl Default for SgwcApp {
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
    // G32/G43: Initialize OpenTelemetry tracing (Jaeger/OTLP exporter)
    let _otel = nextgcore_metrics::otel::init_otel(
        nextgcore_metrics::otel::OtelConfig::new(env!("CARGO_PKG_NAME")).with_endpoint(
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://jaeger:4317".to_string()),
        ),
    )
    .ok();

    log::info!("NextGCore SGWC v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Configuration: {}", args.config);

    // Create SGWC application
    let mut app = SgwcApp::new();

    // Setup signal handlers
    let running = app.running_flag();
    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        running.store(false, Ordering::SeqCst);
    })?;

    // Initialize
    app.init(&args.config).await?;

    // Run main loop
    app.run().await?;

    // Shutdown
    app.shutdown().await;

    log::info!("NextGCore SGWC terminated");
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sgwc_app_creation() {
        let app = SgwcApp::new();
        assert!(app.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_sgwc_app_stop() {
        let app = SgwcApp::new();
        assert!(app.running.load(Ordering::SeqCst));
        app.stop();
        assert!(!app.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_sgwc_app_running_flag() {
        let app = SgwcApp::new();
        let flag = app.running_flag();
        assert!(flag.load(Ordering::SeqCst));
        app.stop();
        assert!(!flag.load(Ordering::SeqCst));
    }

    #[test]
    fn test_sgwc_startup() {
        let mut fsm = SgwcFsm::new();
        let entry_event = SgwcEvent::entry();
        fsm.dispatch(&entry_event);
        assert_eq!(fsm.state, sm::SgwcState::Operational);
    }

    #[test]
    fn test_sgwc_paths() {
        // Bind an ephemeral loopback port directly (mutating process env in
        // tests races with getenv in other threads); gtp_open() itself is
        // exercised at process startup
        let server = gtp_path::GtpcServer::open(
            "127.0.0.1:0",
            nextgcore_gtp::v2::xact::Gtp2XactConfig::default(),
            1,
        )
        .unwrap();
        assert_ne!(server.local_addr().port(), 0);
        server.close();
        // `pfcp_open` binds a real socket now (#54), so it is exercised in
        // `pfcp_path`'s own async tests rather than from this synchronous one.
    }

    #[test]
    fn test_s11_handler_create_session() {
        let imsi = vec![0x09, 0x10, 0x10, 0x00, 0x00, 0x00, 0x20];
        let result =
            s11_handler::handle_create_session_request(None, 1, &[], &imsi, "internet", 12345, 5);
        // Should create UE and session
        matches!(result, s11_handler::HandlerResult::SendPfcp);
    }

    #[test]
    fn test_s5c_handler_no_context() {
        let result = s5c_handler::handle_create_session_response(
            None,
            1,
            &[],
            s11_handler::gtp_cause::REQUEST_ACCEPTED,
            100,
            200,
        );
        matches!(
            result,
            s5c_handler::HandlerResult::Error(s11_handler::gtp_cause::CONTEXT_NOT_FOUND)
        );
    }

    #[test]
    fn test_sxa_handler_no_context() {
        let result = sxa_handler::handle_session_establishment_response(
            None,
            1,
            sxa_handler::pfcp_cause::REQUEST_ACCEPTED,
            0x1234,
        );
        matches!(
            result,
            sxa_handler::HandlerResult::Error(s11_handler::gtp_cause::CONTEXT_NOT_FOUND)
        );
    }

    #[test]
    fn test_timer_manager() {
        let mut timer_mgr = timer::TimerManager::new();
        let timer_id = timer::SgwcTimerId::PfcpAssociation;

        // Start a timer with very short duration
        timer_mgr.start(timer_id, std::time::Duration::from_millis(1));

        // Wait for it to expire
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Check expired timers
        let expired = timer_mgr.check_expired();
        assert!(expired.contains(&timer_id));
    }
}
