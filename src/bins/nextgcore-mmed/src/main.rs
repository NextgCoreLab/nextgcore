//! NextGCore MME (Mobility Management Entity)
//!
//! Port of src/mme/ - Mobility Management Entity for EPC

use anyhow::Result;
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub mod bearer_activation;
pub mod bearer_deactivation;
pub mod bearer_resource;
pub mod config;
pub mod context;
pub mod emm_build;
pub mod emm_handler;
pub mod esm_build;
pub mod esm_handler;
pub mod fd_path;
pub mod gtp_path;
pub mod handover_switch;
pub mod n26_build;
pub mod n26_path;
pub mod nas_dispatch;
pub mod nas_path;
pub mod nas_security;
pub mod nas_timer;
pub mod network_detach;
pub mod overload;
pub mod paging;
pub mod s11_build;
pub mod s11_handler;
pub mod s1ap_build;
pub mod s1ap_gen;
pub mod s1ap_handler;
pub mod s1ap_path;
pub mod s6a_handler;
pub mod sbc_handler;
pub mod sbc_message;
pub mod sbcap_handler;
pub mod sbcap_path;
pub mod sgsap_build;
pub mod sgsap_handler;
pub mod sm;

#[cfg(test)]
mod bearer_resource_tests;
#[cfg(test)]
mod detach_tests;
#[cfg(test)]
mod idle_mode_tests;
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

    /// Log level (trace, debug, info, warn, error). Without it, the config
    /// file's `logger.level`, else `info`; `RUST_LOG` overrides (#691).
    #[arg(short, long)]
    log_level: Option<String>,

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
    /// SBc-AP toward the CBC (#1071); `None` unless `mme.sbcap` is configured.
    sbcap: Option<sbcap_path::SbcapServer>,
    /// Queued S6a requests from the synchronous NAS dispatch. `None` until
    /// [`MmeApp::init`] installs the queue.
    s6a_requests: Option<tokio::sync::mpsc::UnboundedReceiver<fd_path::PendingS6aRequest>>,
}

/// Where S1-MME binds: `mme.s1ap.server`, or loopback when unset (#1299). Never
/// the wildcard by default: an unconfigured MME is not reachable from other hosts,
/// and says so.
fn s1ap_bind_addr(ctx: &context::MmeContext) -> std::net::SocketAddr {
    match ctx.s1ap_list.first().copied() {
        Some(addr) => addr,
        None => {
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], ctx.s1ap_port));
            log::warn!(
                "mme.s1ap.server is not set: S1-MME listens on {addr} only, so no eNB on \
                 another host can associate. Set mme.s1ap.server to the MME's address on the \
                 eNB network"
            );
            addr
        }
    }
}

/// One step of the SBc-AP transport, or never when it is not configured (so a
/// `select!` arm on it stays idle).
async fn poll_sbcap(sbcap: Option<&mut sbcap_path::SbcapServer>) {
    match sbcap {
        Some(s) => s.poll_once().await,
        None => std::future::pending().await,
    }
}

impl MmeApp {
    /// Create a new MME application
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(true)),
            gtp_state: gtp_path::GtpPathState::default(),
            mme_fsm: sm::MmeFsm::new(),
            s1ap: None,
            sbcap: None,
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

        // N26 toward an AMF (#347), AFTER S11 so the restart counter can be read from the
        // installed S11 server rather than advanced a second time (TS 23.007 §18: one
        // counter per node).
        //
        // A bind failure here is NOT fatal, unlike S11's: an MME whose N26 socket did not
        // come up is still a working standalone EPC, and taking the daemon down would turn
        // an interworking misconfiguration into a total LTE outage. The inter-system TAU
        // path then rejects with EMM cause #9, which is what TS 24.301 requires of an MME
        // without N26 — so the degraded behaviour is the specified one.
        if let Err(e) = n26_path::n26_open() {
            log::error!(
                "Failed to open the N26 path: {e}. The MME continues WITHOUT N26: an \
                 inter-system TAU from 5GS will be rejected with EMM cause #9, and \
                 standalone EPC service is unaffected."
            );
        }

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
        // Bind where the configuration says. Unset, it is loopback, not the
        // wildcard it was until #1299 (builder-security: a listener is private by
        // default); an eNB cannot reach it until `mme.s1ap.server` is set.
        let s1ap_bind = s1ap_bind_addr(ctx);
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

        // SBc-AP (#1071): only when configured. No default address exists, so an
        // unconfigured MME opens no socket for it.
        if let Some(config) = ctx.sbcap.clone() {
            let sbcap = sbcap_path::SbcapServer::bind(config, ctx)
                .await
                .map_err(|e| anyhow::anyhow!("SBc-AP transport initialization failed: {e}"))?;
            if let Some(addr) = sbcap.local_addr() {
                log::info!("SBc-AP interface ready on {addr}");
            }
            self.sbcap = Some(sbcap);
        }

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
            // Watchdog interval Tw (RFC 3539 §3.4.1, #729): MME_DIAMETER_TW_SECS,
            // default 30, floored at 6. hssd drops no idle connection; against a
            // server peer that does (one built on `DiameterServer` drops after
            // 3 x its Tc), keep Tw below that.
            timer_tw: parse_diameter_tw(std::env::var("MME_DIAMETER_TW_SECS").ok().as_deref()),
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
                 will fail until the peer is reachable; redialling every Tc."
            ),
        }
        // #708: keep it up. A lost connection (an HSS restart) or a failed startup
        // dial is redialled, rather than leaving every later attach rejected #17.
        tokio::spawn(fd_path::mme_fd_supervise(std::time::Duration::from_secs(1)));
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
                        () = poll_sbcap(self.sbcap.as_mut()) => {}
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

            // Release target eNB resources for handover preparations that ran out of
            // time (#48, TS 36.413 §8.4.5.2). Rides the same tick for the same reason:
            // a sweep that cannot silently stop firing. A no-op unless a handover is
            // outstanding.
            for send in s1ap_handler::expire_handover_preparations(ctx, std::time::Instant::now()) {
                s1ap_path::s1ap_send(send);
            }
            // A UE-AMBR change deferred behind a handover that just expired (#869).
            for send in s6a_handler::deferred_ue_ambr_sends(ctx) {
                s1ap_path::s1ap_send(send);
            }

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
        if let Some(mut sbcap) = self.sbcap.take() {
            sbcap.stop();
            log::debug!("SBc-AP transport closed");
        }

        // Close Diameter S6a interface
        fd_path::mme_fd_final();
        log::debug!("Diameter S6a interface closed");

        // Close the N26 path before S11, mirroring the open order in reverse.
        if let Some(server) = n26_path::server() {
            server.close();
            log::debug!("N26 path closed");
        }

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

/// `MME_DIAMETER_TW_SECS`: whole seconds, default 30. An unparsable value is
/// logged rather than silently replaced, so a mistyped override is noticed
/// (#816 review m-e).
fn parse_diameter_tw(value: Option<&str>) -> u32 {
    const DEFAULT_TW_SECS: u32 = 30;
    match value.map(|v| v.trim().parse::<u32>()) {
        None => DEFAULT_TW_SECS,
        Some(Ok(secs)) => secs,
        Some(Err(_)) => {
            log::warn!(
                "MME_DIAMETER_TW_SECS={:?} is not a whole number of seconds; using \
                 {DEFAULT_TW_SECS}",
                value.unwrap_or_default()
            );
            DEFAULT_TW_SECS
        }
    }
}

/// The `/metrics` listen address: `MME_METRICS_ADDR` (`ip:port`), else
/// `NEXTGCORE_METRICS_BIND` (host) on port 9090, else `127.0.0.1:9090`.
/// Private by default: nothing is published beyond the host unless an
/// operator chooses an address.
fn metrics_addr() -> std::net::SocketAddr {
    parse_metrics_addr(std::env::var("MME_METRICS_ADDR").ok().as_deref())
}

fn parse_metrics_addr(value: Option<&str>) -> std::net::SocketAddr {
    // Otherwise the shared default every NF uses (#837): 127.0.0.1 unless
    // NEXTGCORE_METRICS_BIND names the host, port 9090.
    let default = nextgcore_metrics::nes_energy::metrics_bind_addr(9090);
    match value.map(|v| v.trim().parse()) {
        None => default,
        Some(Ok(addr)) => addr,
        Some(Err(_)) => {
            log::warn!(
                "MME_METRICS_ADDR={:?} is not an ip:port; using {default}",
                value.unwrap_or_default()
            );
            default
        }
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
    // RUST_LOG if set, else --log-level: the same for every NF (#691).
    nextgcore_core::log::nf_log_builder(&nextgcore_core::log::nf_log_level(
        args.log_level.as_deref(),
        Some(&args.config),
    ))
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

    // Prometheus /metrics (#730 review m-b): the handover failure counter.
    // Loopback by default: the endpoint is unauthenticated, so an operator who
    // wants it scraped from another host sets MME_METRICS_ADDR to a private
    // address on purpose (or scrapes through a sidecar).
    match nextgcore_metrics::nes_energy::serve_metrics(
        metrics_addr(),
        Arc::new(|| {
            // #899 review: S6a messages not delivered because they arrived while a
            // re-established connection was in RFC 3539 REOPEN.
            format!(
                "{}# HELP mme_diameter_reopen_discards_total Diameter application messages \
                 received in RFC 3539 REOPEN and not delivered (requests answered 3004)\n\
                 # TYPE mme_diameter_reopen_discards_total counter\n\
                 mme_diameter_reopen_discards_total {}\n",
                handover_switch::render_metrics()
                    + &s1ap_handler::render_metrics()
                    + &n26_path::render_metrics()
                    + &sbcap_path::render_metrics()
                    + &s11_handler::render_metrics(),
                nextgcore_diameter::session::reopen_discards()
            )
        }),
    )
    .await
    {
        Ok((bound, _handle)) => log::info!("MME metrics on http://{bound}/metrics"),
        Err(e) => log::warn!("MME metrics endpoint not started: {e}"),
    }

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
    /// #1299: unset, S1-MME binds loopback, never the wildcard; set, the
    /// configured address.
    #[test]
    fn s1_mme_binds_loopback_unless_configured() {
        let mut ctx = crate::context::MmeContext::new();
        assert_eq!(
            super::s1ap_bind_addr(&ctx),
            "127.0.0.1:36412".parse::<std::net::SocketAddr>().unwrap()
        );
        ctx.s1ap_list.push("10.0.0.5:36412".parse().unwrap());
        assert_eq!(
            super::s1ap_bind_addr(&ctx),
            "10.0.0.5:36412".parse::<std::net::SocketAddr>().unwrap()
        );
    }

    use super::*;

    /// The metrics endpoint is loopback unless configured otherwise.
    #[test]
    fn the_metrics_endpoint_defaults_to_loopback() {
        assert_eq!(parse_metrics_addr(None), "127.0.0.1:9090".parse().unwrap());
        assert_eq!(
            parse_metrics_addr(Some("not an address")),
            "127.0.0.1:9090".parse().unwrap()
        );
        assert_eq!(
            parse_metrics_addr(Some("10.0.0.5:9191")),
            "10.0.0.5:9191".parse().unwrap()
        );
    }

    /// #816 review m-e: `MME_DIAMETER_TW_SECS` falls back to 30 when unset or
    /// unparsable (the latter logged).
    #[test]
    fn the_diameter_tw_override_is_parsed() {
        assert_eq!(parse_diameter_tw(None), 30);
        assert_eq!(parse_diameter_tw(Some(" 12 ")), 12);
        assert_eq!(parse_diameter_tw(Some("12s")), 30);
    }

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
