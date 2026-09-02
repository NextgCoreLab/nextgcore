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
    hss_context_final, hss_context_init, hss_context_parse_config, hss_cx_final, hss_cx_init,
    hss_fd_final, hss_fd_init, hss_s6a_final, hss_s6a_init, hss_swx_final, hss_swx_init,
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

    /// Kill a running instance (NOT SUPPORTED: exits with an error;
    /// stop the NF through its supervisor)
    #[arg(short = 'k', long)]
    kill: bool,

    /// FreeDiameter configuration file
    #[arg(long, default_value = "/etc/nextgcore/freeDiameter/hss.conf")]
    diameter_config: String,

    // Parity with pcrfd, which has had these three since it was written. hssd
    // had NEITHER a config path nor a CLI flag for its Diameter identity, so it
    // was hard-locked to the mnc001/mcc001 defaults below with no runtime
    // workaround at all -- that combination is what made issue #58 a blocker
    // rather than an inconvenience. Option (no clap default) so "not passed" is
    // distinguishable from "passed the default": precedence is
    // CLI > YAML > built-in default.
    /// Diameter Origin-Host identity of this HSS
    /// [default: hss.epc.mnc001.mcc001.3gppnetwork.org]
    #[arg(long)]
    diameter_id: Option<String>,

    /// Diameter Origin-Realm of this HSS
    /// [default: epc.mnc001.mcc001.3gppnetwork.org]
    #[arg(long)]
    diameter_realm: Option<String>,

    /// Diameter listen address for S6a [default: 0.0.0.0]
    #[arg(long)]
    diameter_addr: Option<String>,

    /// Diameter listen port for S6a [default: 3868]
    #[arg(long)]
    diameter_port: Option<u16>,

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
    // G32/G43: Initialize OpenTelemetry tracing (Jaeger/OTLP exporter)
    let _otel = nextgcore_metrics::otel::init_otel(
        nextgcore_metrics::otel::OtelConfig::new(env!("CARGO_PKG_NAME")).with_endpoint(
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://jaeger:4317".to_string()),
        ),
    )
    .ok();

    log::info!("NextGCore HSS v{} starting...", env!("CARGO_PKG_VERSION"));

    // Issue: `--kill` was advertised as "Kill running instance" and did
    // NOTHING -- it logged an intention and returned success, so the process
    // exited 0 while the instance kept serving. Fail loudly instead.
    if args.kill {
        return Err(nextgcore_core::signal::kill_unsupported().into());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize HSS context
    // max_impi = max_ue, max_impu = max_ue * 4 (typical ratio)
    hss_context_init(args.max_ue, args.max_ue * 4);
    log::info!(
        "HSS context initialized (max_impi={}, max_impu={})",
        args.max_ue,
        args.max_ue * 4
    );

    // Parse configuration file.
    //
    // A present-but-unparseable config is FATAL. Previously this warned and
    // continued, which silently reverted the HSS to the hardcoded
    // mnc001/mcc001 identity below -- an S6a realm mismatch (RFC 6733 §6.1)
    // presenting as peers rejecting or misrouting traffic, with a
    // "Loading configuration from ..." line in the log implying the file had
    // been applied. Refusing to start is far easier to diagnose.
    //
    // A MISSING config file stays non-fatal: the defaults are a working
    // single-PLMN dev configuration and existing deployments rely on them.
    if std::path::Path::new(&args.config).exists() {
        hss_context_parse_config(&args.config)
            .map_err(|e| anyhow::anyhow!("Failed to parse config {}: {e}", args.config))?;
        // Logged AFTER the parse succeeds, so the line means what it says.
        log::info!("Loaded configuration from {}", args.config);
    } else {
        log::debug!("Configuration file not found: {}", args.config);
    }

    // Initialize HSS state machine
    let mut hss_sm = HssSmContext::new();
    hss_sm.init(false); // use_mongodb_change_stream = false by default
    log::info!("HSS state machine initialized");

    // Initialize FreeDiameter
    if let Err(e) = hss_fd_init() {
        log::error!("Failed to initialize FreeDiameter: {e}");
        cleanup(&mut hss_sm);
        return Err(anyhow::anyhow!(e));
    }
    log::info!("FreeDiameter initialized");

    // Initialize S6a interface (MME communication)
    if let Err(e) = hss_s6a_init() {
        log::error!("Failed to initialize S6a interface: {e}");
        hss_fd_final();
        cleanup(&mut hss_sm);
        return Err(anyhow::anyhow!("{e}"));
    }
    log::info!("S6a interface initialized");

    // Start the S6a Diameter server (accepts MME connections; answers
    // AIR/ULR/PUR and carries HSS-initiated CLR/IDR on the same connections)
    {
        // Precedence: CLI flag > YAML config > built-in default. The config file
        // is the primary source (it is the only one that can express peers and
        // Tc), while an explicit flag stays a usable override for a deployment
        // whose config is wrong.
        let (diam_id, diam_realm, diam_addr, diam_port, timer_tc) = {
            let ctx = nextgcore_hssd::hss_self();
            let ctx = ctx.read().expect("HSS context lock poisoned");
            let diam = &ctx.diam_config;
            (
                args.diameter_id
                    .clone()
                    .or_else(|| diam.cnf_diamid.clone())
                    .unwrap_or_else(|| "hss.epc.mnc001.mcc001.3gppnetwork.org".to_string()),
                args.diameter_realm
                    .clone()
                    .or_else(|| diam.cnf_diamrlm.clone())
                    .unwrap_or_else(|| "epc.mnc001.mcc001.3gppnetwork.org".to_string()),
                args.diameter_addr
                    .clone()
                    .or_else(|| diam.cnf_addr.clone())
                    .unwrap_or_else(|| "0.0.0.0".to_string()),
                args.diameter_port
                    .or(if diam.cnf_port == 0 {
                        None
                    } else {
                        Some(diam.cnf_port)
                    })
                    .unwrap_or(3868),
                // .max(1) preserved: a Tc of 0 would mean "reconnect with no
                // delay", which the Diameter stack treats as unset.
                diam.cnf_timer_tc.max(1) as u32,
            )
        };
        log::info!(
            "HSS S6a Diameter identity: {diam_id} realm: {diam_realm} listen: {diam_addr}:{diam_port}"
        );
        // Advertise the applications this HSS actually implements (s6a_path.rs,
        // cx_path.rs, swx_path.rs) so a peer can discover them, and so a peer
        // with none in common is refused DIAMETER_NO_COMMON_APPLICATION instead
        // of being accepted and failing later (RFC 6733 §5.3).
        use nextgcore_diameter::applications::{well_known, ApplicationRegistry};
        let applications = ApplicationRegistry::new("NextGCore HSS")
            .with_application(well_known::S6A)
            .with_application(well_known::CX)
            .with_application(well_known::SWX);

        let diameter_config = nextgcore_diameter::config::DiameterConfig {
            diameter_id: diam_id,
            diameter_realm: diam_realm,
            // Advertised as Host-IP-Address; 0.0.0.0 is filtered out below since
            // advertising a wildcard tells a peer nothing routable.
            address: (diam_addr != "0.0.0.0").then(|| diam_addr.clone()),
            port: diam_port,
            timer_tc,
            applications,
            ..Default::default()
        };
        let listen_addr: std::net::SocketAddr = format!("{diam_addr}:{diam_port}")
            .parse()
            .unwrap_or_else(|_| ([0, 0, 0, 0], diam_port).into());

        std::thread::Builder::new()
            .name("hss-s6a-diameter".to_string())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("failed to build S6a tokio runtime");
                if let Err(e) = runtime.block_on(nextgcore_hssd::hss_s6a_run_server(
                    listen_addr,
                    diameter_config,
                )) {
                    log::error!("S6a Diameter server terminated: {e}");
                }
            })
            .context("failed to spawn S6a Diameter server thread")?;
        log::info!("S6a Diameter server started on {listen_addr}");
    }

    // Initialize Cx interface (IMS communication)
    if let Err(e) = hss_cx_init() {
        log::error!("Failed to initialize Cx interface: {e}");
        hss_s6a_final();
        hss_fd_final();
        cleanup(&mut hss_sm);
        return Err(anyhow::anyhow!("{e}"));
    }
    log::info!("Cx interface initialized");

    // Initialize SWx interface (non-3GPP AAA communication)
    if let Err(e) = hss_swx_init() {
        log::error!("Failed to initialize SWx interface: {e}");
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
        // Unset by default so the YAML config can win; a clap default_value
        // would make the flag always look explicit and outrank the file.
        assert_eq!(args.diameter_id, None);
        assert_eq!(args.diameter_realm, None);
        assert_eq!(args.diameter_addr, None);
        assert_eq!(args.diameter_port, None);
    }

    /// hssd previously had no CLI path to its Diameter identity at all, which is
    /// what made #58 a hard blocker: with the parse function also a no-op, the
    /// daemon was pinned to PLMN mnc001/mcc001 with no runtime workaround.
    #[test]
    fn diameter_identity_flags_parse() {
        let args = Args::parse_from([
            "nextgcore-hssd",
            "--diameter-id",
            "hss.epc.mnc070.mcc310.3gppnetwork.org",
            "--diameter-realm",
            "epc.mnc070.mcc310.3gppnetwork.org",
            "--diameter-addr",
            "10.0.0.5",
            "--diameter-port",
            "3869",
        ]);
        assert_eq!(
            args.diameter_id.as_deref(),
            Some("hss.epc.mnc070.mcc310.3gppnetwork.org")
        );
        assert_eq!(
            args.diameter_realm.as_deref(),
            Some("epc.mnc070.mcc310.3gppnetwork.org")
        );
        assert_eq!(args.diameter_addr.as_deref(), Some("10.0.0.5"));
        assert_eq!(args.diameter_port, Some(3869));
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-hssd",
            "-c",
            "/custom/hss.yaml",
            "-e",
            "debug",
            "--diameter-config",
            "/custom/hss.conf",
            "--max-ue",
            "2048",
            "--db-uri",
            "mongodb://localhost:27017",
            "--db-name",
            "custom_db",
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
        let args = Args::parse_from(["nextgcore-hssd", "-l", "/var/log/hss.log", "-m"]);
        assert_eq!(args.log_file, Some("/var/log/hss.log".to_string()));
        assert!(args.no_color);
    }
}
