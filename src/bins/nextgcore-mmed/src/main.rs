//! NextGCore MME (Mobility Management Entity)
//!
//! Port of src/mme/ - Mobility Management Entity for EPC

use anyhow::Result;
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub mod config;
pub mod context;
pub mod emm_build;
pub mod emm_handler;
pub mod esm_build;
pub mod esm_handler;
pub mod fd_path;
pub mod gtp_path;
pub mod nas_dispatch;
pub mod nas_path;
pub mod nas_security;
pub mod nas_timer;
pub mod overload;
pub mod paging;
pub mod s11_build;
pub mod s11_handler;
pub mod s1ap_build;
pub mod s1ap_handler;
pub mod s1ap_path;
pub mod s6a_handler;
pub mod sbc_handler;
pub mod sbc_message;
pub mod sgsap_build;
pub mod sgsap_handler;
pub mod sm;

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
    /// S1-MME transport (issue #42). `None` until [`MmeApp::init`] binds it.
    s1ap: Option<s1ap_path::S1apServer>,
    /// Queued S6a requests from the synchronous NAS dispatch. `None` until
    /// [`MmeApp::init`] installs the queue.
    s6a_requests: Option<tokio::sync::mpsc::UnboundedReceiver<fd_path::PendingS6aRequest>>,
}

impl MmeApp {
    /// Create a new MME application
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(true)),
            gtp_state: gtp_path::GtpPathState::default(),
            mme_fsm: sm::MmeFsm::new(),
            s1ap: None,
            s6a_requests: None,
        }
    }

    /// Initialize the MME application
    pub async fn init(&mut self, config_path: &str) -> Result<()> {
        log::info!("Initializing MME...");

        // Initialize the MME context WITH the configuration file applied. This
        // has to happen before anything else touches `mme_self()`, because the
        // context is built configured rather than mutated afterwards (issue
        // #157). Until this landed the path was ignored entirely, which left
        // `served_gummei` empty and made the MME answer S1 Setup Failure to
        // every eNB.
        if !context::mme_context_init_with_config(config_path) {
            log::warn!(
                "MME context was already initialised; configuration from '{config_path}' was \
                 not applied"
            );
        }
        log::debug!("MME context initialized");

        // Initialize MME state machine
        sm::Fsm::init(&mut self.mme_fsm);
        log::debug!("MME state machine initialized: {:?}", self.mme_fsm.state());

        // Initialize GTP path (S11 interface to SGW)
        if let Err(e) = gtp_path::gtp_open(&mut self.gtp_state) {
            log::error!("Failed to open GTP path: {e}");
            return Err(anyhow::anyhow!("GTP path initialization failed: {e}"));
        }
        log::debug!("GTP path initialized");

        // Initialize Diameter S6a interface
        if let Err(e) = fd_path::mme_fd_init() {
            log::error!("Failed to initialize Diameter: {e}");
            return Err(anyhow::anyhow!("Diameter initialization failed: {e}"));
        }
        log::debug!("Diameter S6a interface initialized");

        // Install the S6a pending-request queue before anything can enqueue on
        // it: the NAS dispatch pushes AIR requests here from synchronous code,
        // and `run` drains them (gap (c) of the S6a bring-up).
        self.s6a_requests = fd_path::install_request_queue();
        if self.s6a_requests.is_none() {
            log::warn!("S6a request queue already installed; authentication requests will drop");
        }

        // Connect the S6a peer. `mme_fd_connect` has had no caller since it was
        // written — its own comment defers it until "the async runtime is
        // available" (#42 provided that) and until an HSS address existed, which
        // the freeDiameter config now supplies. Without this the MME can never
        // obtain an authentication vector, so no UE can complete an attach.
        self.connect_s6a().await;

        // Bind the S1-MME SCTP transport (TS 36.412: port 36412, PPID 18).
        // Without this nothing can reach the S1AP layer, so no eNB can
        // associate and no EPS procedure can run (issue #42).
        let ctx = context::mme_self();
        // Bind where the configuration says, falling back to the wildcard so an
        // unconfigured deployment behaves exactly as it did before #157.
        let s1ap_bind = ctx
            .s1ap_list
            .first()
            .copied()
            .unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], ctx.s1ap_port)));
        let send_rx = s1ap_path::install_send_queue().ok_or_else(|| {
            anyhow::anyhow!("S1AP send queue already installed (MmeApp::init called twice)")
        })?;
        let s1ap = s1ap_path::S1apServer::bind(s1ap_bind, send_rx, ctx)
            .await
            .map_err(|e| anyhow::anyhow!("S1-MME transport initialization failed: {e}"))?;
        if let Some(addr) = s1ap.local_addr() {
            log::info!("S1-MME interface ready on {addr}");
        }
        self.s1ap = Some(s1ap);

        log::info!("MME initialized successfully");
        Ok(())
    }

    /// Establish the S6a Diameter connection to the HSS.
    ///
    /// A failure is logged and startup continues: an HSS that is not up yet is
    /// the normal case in a compose deployment, and the S6a request path already
    /// answers `NotInitialized`/`RequestTimeout` for a peer that is not there.
    /// Taking the daemon down instead would mean an MME that cannot serve S1AP
    /// because its HSS was slow to start.
    async fn connect_s6a(&self) {
        let ctx = context::mme_self();
        let Some((peer_identity, peer_addr)) = ctx.hss_peer.clone() else {
            log::warn!(
                "No S6a peer configured (no ConnectPeer with a ConnectTo in {}); \
                 authentication will not be possible",
                ctx.diam_conf_path.as_deref().unwrap_or("<no config>")
            );
            return;
        };

        // Advertise only S6a: that is the single application this daemon
        // implements, so a peer with nothing in common is refused up front
        // (RFC 6733 §5.3) rather than accepted and failing at the first request.
        let applications =
            nextgcore_diameter::applications::ApplicationRegistry::new("NextGCore MME")
                .with_application(nextgcore_diameter::applications::well_known::S6A);

        let config = nextgcore_diameter::config::DiameterConfig {
            diameter_id: ctx
                .diam_identity
                .clone()
                .unwrap_or_else(|| "mme.localdomain".to_string()),
            diameter_realm: ctx
                .diam_realm
                .clone()
                .unwrap_or_else(|| "localdomain".to_string()),
            // Advertised as Host-IP-Address. A wildcard tells a peer nothing
            // routable, so it is omitted rather than advertised as 0.0.0.0.
            address: ctx
                .diam_addr
                .clone()
                .filter(|addr| addr != "0.0.0.0" && addr != "::"),
            applications,
            ..Default::default()
        };

        log::info!(
            "Connecting S6a to {peer_identity} at {peer_addr} as {}",
            config.diameter_id
        );
        if let Err(e) = fd_path::mme_fd_init_async(config, peer_addr).await {
            log::error!("S6a client setup failed: {e}");
            return;
        }
        match fd_path::mme_fd_connect().await {
            Ok(()) => log::info!("S6a connected to {peer_identity} at {peer_addr}"),
            Err(e) => log::warn!(
                "S6a connection to {peer_identity} at {peer_addr} failed: {e}. Authentication \
                 will fail until the peer is reachable."
            ),
        }
    }

    /// Run the MME main loop.
    ///
    /// Drives the S1AP data path — inbound eNB signalling into
    /// [`s1ap_handler::handle_s1ap_message`] and queued downlink PDUs out to the
    /// addressed eNB — plus the NAS procedure timers, alongside the shutdown
    /// check. Previously this was a bare `thread::sleep` loop, which is why the
    /// whole S1AP layer was unreachable at runtime (issue #42).
    pub async fn run(&mut self) -> Result<()> {
        log::info!("MME running...");

        // Interval at which the loop re-checks the shutdown flag when no S1AP
        // event is pending. Keeps Ctrl-C responsive without polling hard, and is
        // the tick the NAS timers are swept on (issue #45).
        const SHUTDOWN_CHECK: std::time::Duration = std::time::Duration::from_millis(100);

        let ctx = context::mme_self();
        while self.running.load(Ordering::SeqCst) {
            match self.s1ap.as_mut() {
                Some(s1ap) => {
                    // Race the S1AP data path against the shutdown tick so a
                    // signal is honoured even while idle. `poll_once` is
                    // cancel-safe, so losing this race consumes no message.
                    tokio::select! {
                        () = s1ap.poll_once() => {}
                        () = tokio::time::sleep(SHUTDOWN_CHECK) => {}
                    }
                }
                None => tokio::time::sleep(SHUTDOWN_CHECK).await,
            }

            // Run the S6a exchanges the NAS dispatch asked for. Each is a full
            // request/answer with the HSS, which is why it belongs here rather
            // than inside the synchronous dispatch that queued it.
            if let Some(rx) = self.s6a_requests.as_mut() {
                fd_path::poll_pending(ctx, rx).await;
            }

            // Apply anything the HSS initiated (CLR/IDR). Also a no-op when no
            // S6a peer is connected.
            fd_path::poll_inbound().await;

            // Retransmit or abort NAS procedures whose timer has run out
            // (TS 24.301 §5.4.2.7, §5.4.4.6, §5.5.1.2.7). Cheap when idle: the
            // sweep walks the UE pool and does nothing unless a deadline passed.
            nas_timer::expire_nas_timers(ctx, std::time::Instant::now());

            // Signal or lift S1AP overload if the attached-UE count crossed the
            // configured threshold (TS 36.413 §8.7.6). A no-op unless
            // `mme.overload.max_ue` is set, which it is not by default.
            overload::poll(ctx);
        }

        log::info!("MME main loop exited");
        Ok(())
    }

    /// Shutdown the MME application
    pub fn shutdown(&mut self) {
        log::info!("Shutting down MME...");

        // Stop the S1-MME transport first so no new eNB signalling arrives
        // while the layers below it are being torn down.
        if let Some(mut s1ap) = self.s1ap.take() {
            s1ap.stop();
            log::debug!("S1-MME transport closed");
        }

        // Close Diameter S6a interface
        fd_path::mme_fd_final();
        log::debug!("Diameter S6a interface closed");

        // Close GTP path
        if let Err(e) = gtp_path::gtp_close(&mut self.gtp_state) {
            log::error!("Failed to close GTP path: {e}");
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

/// The MME runs on a tokio runtime.
///
/// Required by the S1-MME SCTP transport (issue #42), which is `AsyncFd`-driven.
/// It also unblocks `fd_path`'s S6a layer, which was already fully async but
/// stranded because the daemon had no runtime — see `fd_path::mme_fd_init`,
/// whose comment defers connecting "once the async runtime is available".
/// Actually connecting that peer is separate work and deliberately not done here.
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
    app.init(&args.config).await?;

    // Run main loop
    app.run().await?;

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
