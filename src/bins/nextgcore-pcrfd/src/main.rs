//! NextGCore PCRF (Policy and Charging Rules Function)
//!
//! The PCRF is responsible for:
//! - Policy and charging control (Gx interface with P-GW/SMF)
//! - Application function interaction (Rx interface with AF/P-CSCF)
//! - QoS policy decisions based on subscriber data

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_pcrfd::{
    pcrf_context_final, pcrf_context_init, pcrf_context_parse_config, pcrf_fd_final, pcrf_fd_init,
    pcrf_fd_listen, pcrf_gx_final, pcrf_gx_init, pcrf_rx_final, pcrf_rx_init, pcrf_self,
    LocalIdentity, PcrfEvent, PcrfSmContext,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// NextGCore PCRF - Policy and Charging Rules Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-pcrfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "LTE/EPC Policy and Charging Rules Function", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/pcrf.yaml")]
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

    /// FreeDiameter configuration file
    #[arg(long, default_value = "/etc/nextgcore/freeDiameter/pcrf.conf")]
    diameter_config: String,

    // These three are Option rather than carrying a clap default_value so that
    // "not passed" is distinguishable from "passed the default". The precedence
    // is CLI > YAML > built-in default (see `resolve_diameter_identity`); with a
    // clap default the flag would always look explicit and would silently
    // outrank every value from the config file.
    /// Diameter Origin-Host identity of this PCRF [default: pcrf.localdomain]
    #[arg(long)]
    diameter_id: Option<String>,

    /// Diameter Origin-Realm of this PCRF [default: localdomain]
    #[arg(long)]
    diameter_realm: Option<String>,

    /// Diameter listen address, Gx and Rx share one listener [default: 0.0.0.0:3868]
    #[arg(long)]
    diameter_addr: Option<String>,

    /// Maximum number of sessions
    #[arg(long, default_value = "1024")]
    max_sess: usize,

    /// Database URI (MongoDB)
    #[arg(long)]
    db_uri: Option<String>,

    /// Database name
    #[arg(long, default_value = "nextgcore")]
    db_name: String,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Built-in Diameter identity, used when neither the CLI nor the config file
/// supplies one. Preserved from the previous clap `default_value`s so a daemon
/// started with no config and no flags behaves exactly as before.
const DEFAULT_DIAMETER_ID: &str = "pcrf.localdomain";
const DEFAULT_DIAMETER_REALM: &str = "localdomain";
const DEFAULT_DIAMETER_ADDR: &str = "0.0.0.0:3868";

/// Resolve the Diameter identity, realm and listen address by precedence:
/// **CLI flag > YAML config > built-in default**.
///
/// Kept a pure function of its two inputs so the precedence is unit-testable
/// without starting a daemon, binding a socket, or touching the global context.
///
/// The listen address is assembled from the config's separate `addr` and `port`
/// fields, since `DiamConfig` stores them apart while the CLI takes one
/// `host:port` string. A config that sets only `addr` still gets the default
/// port, and one that sets only `port` still gets the default host -- neither
/// half forces the other to be specified.
fn resolve_diameter_identity(
    args: &Args,
    cfg: &nextgcore_pcrfd::DiamConfig,
) -> (String, String, String) {
    let id = args
        .diameter_id
        .clone()
        .or_else(|| cfg.cnf_diamid.clone())
        .unwrap_or_else(|| DEFAULT_DIAMETER_ID.to_string());

    let realm = args
        .diameter_realm
        .clone()
        .or_else(|| cfg.cnf_diamrlm.clone())
        .unwrap_or_else(|| DEFAULT_DIAMETER_REALM.to_string());

    let addr = args.diameter_addr.clone().unwrap_or_else(|| {
        match (cfg.cnf_addr.as_deref(), cfg.cnf_port) {
            (None, 0) => DEFAULT_DIAMETER_ADDR.to_string(),
            (host, port) => {
                // Split the default once so each half can fall back on its own.
                let (default_host, default_port) = DEFAULT_DIAMETER_ADDR
                    .rsplit_once(':')
                    .expect("DEFAULT_DIAMETER_ADDR must contain a port");
                let host = host.unwrap_or(default_host);
                if port == 0 {
                    format!("{host}:{default_port}")
                } else {
                    format!("{host}:{port}")
                }
            }
        }
    });

    (id, realm, addr)
}

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

    log::info!("NextGCore PCRF v{} starting...", env!("CARGO_PKG_VERSION"));

    // Handle kill flag
    if args.kill {
        log::info!("Kill flag set - would send SIGTERM to running instance");
        return Ok(());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize PCRF context
    pcrf_context_init(args.max_sess);
    log::info!("PCRF context initialized (max_sess={})", args.max_sess);

    // Parse configuration file.
    //
    // A present-but-unparseable config is FATAL. Previously this warned and
    // continued, which silently left the PCRF advertising the CLI default
    // `localdomain` realm -- Gx/Rx peers then fail realm-based routing
    // (RFC 6733 §6.1) while the log claimed the config had been loaded.
    //
    // A MISSING config file stays non-fatal: the CLI defaults are a working dev
    // configuration and existing deployments rely on them.
    if std::path::Path::new(&args.config).exists() {
        pcrf_context_parse_config(&args.config)
            .map_err(|e| anyhow::anyhow!("Failed to parse config {}: {e}", args.config))?;
        // Logged AFTER the parse succeeds, so the line means what it says.
        log::info!("Loaded configuration from {}", args.config);
    } else {
        log::debug!("Configuration file not found: {}", args.config);
    }

    // Initialize PCRF state machine
    let mut pcrf_sm = PcrfSmContext::new();
    pcrf_sm.init(false);
    log::info!("PCRF state machine initialized");

    // Initialize the Diameter stack
    if let Err(e) = pcrf_fd_init() {
        log::error!("Failed to initialize Diameter stack: {e}");
        cleanup(&mut pcrf_sm);
        return Err(anyhow::anyhow!(e));
    }
    log::info!("Diameter stack initialized");

    // Start the Diameter listener (Gx + Rx) on a dedicated runtime thread.
    //
    // Precedence is CLI > YAML > built-in default, so an explicitly-passed flag
    // remains a working override for a deployment whose config file is wrong,
    // while the config file becomes the primary source.
    let (diam_id, diam_realm, diam_addr) = {
        let ctx = pcrf_self();
        let cfg = ctx.read().map_err(|_| {
            anyhow::anyhow!("PCRF context lock poisoned while reading Diameter config")
        })?;
        resolve_diameter_identity(&args, &cfg.diam_config)
    };
    log::info!("PCRF Diameter identity: {diam_id} realm: {diam_realm} listen: {diam_addr}");
    let identity = LocalIdentity {
        host: diam_id,
        realm: diam_realm,
    };
    let listen_addr: std::net::SocketAddr = diam_addr
        .parse()
        .with_context(|| format!("Invalid Diameter listen address: {diam_addr}"))?;
    std::thread::Builder::new()
        .name("pcrf-diameter".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    log::error!("Failed to build Diameter runtime: {e}");
                    return;
                }
            };
            runtime.block_on(async move {
                match pcrf_fd_listen(identity, listen_addr).await {
                    Ok(addr) => {
                        log::info!("Diameter listener active on {addr}");
                        // Keep the runtime alive to serve peer connections
                        std::future::pending::<()>().await;
                    }
                    Err(e) => log::error!("Failed to start Diameter listener: {e}"),
                }
            });
        })
        .context("Failed to spawn Diameter thread")?;

    // Initialize Gx interface (P-GW communication)
    if let Err(e) = pcrf_gx_init() {
        log::error!("Failed to initialize Gx interface: {e}");
        pcrf_fd_final();
        cleanup(&mut pcrf_sm);
        return Err(anyhow::anyhow!("{e}"));
    }
    log::info!("Gx interface initialized");

    // Initialize Rx interface (AF/P-CSCF communication)
    if let Err(e) = pcrf_rx_init() {
        log::error!("Failed to initialize Rx interface: {e}");
        pcrf_gx_final();
        pcrf_fd_final();
        cleanup(&mut pcrf_sm);
        return Err(anyhow::anyhow!("{e}"));
    }
    log::info!("Rx interface initialized");

    // Dispatch entry event to transition to operational state
    let mut entry_event = PcrfEvent::entry();
    pcrf_sm.dispatch(&mut entry_event);
    log::info!("NextGCore PCRF ready");

    // Main event loop
    run_event_loop(&mut pcrf_sm, shutdown)?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Finalize Diameter interfaces
    pcrf_rx_final();
    log::info!("Rx interface finalized");

    pcrf_gx_final();
    log::info!("Gx interface finalized");

    pcrf_fd_final();
    log::info!("FreeDiameter finalized");

    // Cleanup state machine and context
    cleanup(&mut pcrf_sm);

    log::info!("NextGCore PCRF stopped");
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
fn run_event_loop(pcrf_sm: &mut PcrfSmContext, shutdown: Arc<AtomicBool>) -> Result<()> {
    log::debug!("Entering main event loop");

    // Polling interval
    let poll_interval = std::time::Duration::from_millis(100);

    while !shutdown.load(Ordering::SeqCst) && !SHUTDOWN.load(Ordering::SeqCst) {
        // Poll for events with timeout
        std::thread::sleep(poll_interval);

        // Process timer expirations
        // In full implementation, check timer manager for expired timers

        // Process events from queue
        // In full implementation, pop events from queue and dispatch

        // Check state machine health
        if !pcrf_sm.is_operational() {
            log::warn!("PCRF state machine not operational: {:?}", pcrf_sm.state());
        }
    }

    log::debug!("Exiting main event loop");
    Ok(())
}

/// Cleanup resources
fn cleanup(pcrf_sm: &mut PcrfSmContext) {
    pcrf_sm.fini();
    log::info!("PCRF state machine finalized");

    pcrf_context_final();
    log::info!("PCRF context finalized");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-pcrfd"]);
        assert_eq!(args.config, "/etc/nextgcore/pcrf.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(
            args.diameter_config,
            "/etc/nextgcore/freeDiameter/pcrf.conf"
        );
        assert_eq!(args.max_sess, 1024);
        assert_eq!(args.db_name, "nextgcore");
        assert!(!args.kill);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-pcrfd",
            "-c",
            "/custom/pcrf.yaml",
            "-e",
            "debug",
            "--diameter-config",
            "/custom/pcrf.conf",
            "--max-sess",
            "2048",
            "--db-uri",
            "mongodb://localhost:27017",
            "--db-name",
            "custom_db",
        ]);
        assert_eq!(args.config, "/custom/pcrf.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.diameter_config, "/custom/pcrf.conf");
        assert_eq!(args.max_sess, 2048);
        assert_eq!(args.db_uri, Some("mongodb://localhost:27017".to_string()));
        assert_eq!(args.db_name, "custom_db");
    }

    #[test]
    fn test_args_kill() {
        let args = Args::parse_from(["nextgcore-pcrfd", "-k"]);
        assert!(args.kill);
    }

    // -----------------------------------------------------------------------
    // Diameter identity precedence: CLI > YAML > built-in default (issue #58)
    // -----------------------------------------------------------------------

    /// With neither a flag nor a config value, the built-in defaults apply —
    /// byte-identical to the clap `default_value`s these flags used to carry, so
    /// a daemon started bare behaves exactly as before this change.
    #[test]
    fn identity_falls_back_to_builtin_defaults() {
        let args = Args::parse_from(["nextgcore-pcrfd"]);
        let cfg = nextgcore_pcrfd::DiamConfig::default();
        let (id, realm, addr) = resolve_diameter_identity(&args, &cfg);
        assert_eq!(id, "pcrf.localdomain");
        assert_eq!(realm, "localdomain");
        assert_eq!(addr, "0.0.0.0:3868");
    }

    /// With no flags, the YAML values win over the built-in defaults — the whole
    /// point of the issue: the config file must actually take effect.
    #[test]
    fn yaml_values_win_over_builtin_defaults() {
        let args = Args::parse_from(["nextgcore-pcrfd"]);
        let cfg = nextgcore_pcrfd::DiamConfig {
            cnf_diamid: Some("pcrf.epc.mnc070.mcc310.3gppnetwork.org".to_string()),
            cnf_diamrlm: Some("epc.mnc070.mcc310.3gppnetwork.org".to_string()),
            cnf_addr: Some("10.0.0.9".to_string()),
            cnf_port: 3869,
            cnf_port_tls: 5869,
        };
        let (id, realm, addr) = resolve_diameter_identity(&args, &cfg);
        assert_eq!(id, "pcrf.epc.mnc070.mcc310.3gppnetwork.org");
        assert_eq!(realm, "epc.mnc070.mcc310.3gppnetwork.org");
        assert_eq!(addr, "10.0.0.9:3869");
    }

    /// An explicitly-passed flag outranks the config file, so the CLI remains a
    /// usable override for a deployment whose config is wrong.
    #[test]
    fn explicit_cli_flags_override_yaml() {
        let args = Args::parse_from([
            "nextgcore-pcrfd",
            "--diameter-id",
            "cli.example.org",
            "--diameter-realm",
            "cli-realm.example.org",
            "--diameter-addr",
            "127.0.0.1:4000",
        ]);
        let cfg = nextgcore_pcrfd::DiamConfig {
            cnf_diamid: Some("yaml.example.org".to_string()),
            cnf_diamrlm: Some("yaml-realm.example.org".to_string()),
            cnf_addr: Some("10.0.0.9".to_string()),
            cnf_port: 3869,
            cnf_port_tls: 5869,
        };
        let (id, realm, addr) = resolve_diameter_identity(&args, &cfg);
        assert_eq!(id, "cli.example.org");
        assert_eq!(realm, "cli-realm.example.org");
        assert_eq!(addr, "127.0.0.1:4000");
    }

    /// Precedence is per-field: a flag for one value must not suppress the YAML
    /// values for the others.
    ///
    /// Each of the three fields is driven independently here. An earlier version
    /// of this test only passed `--diameter-realm`, which meant an inverted
    /// precedence on `identity` alone went undetected — found by deliberately
    /// inverting it and seeing this test still pass.
    #[test]
    fn cli_override_is_per_field_not_all_or_nothing() {
        let yaml_cfg = || nextgcore_pcrfd::DiamConfig {
            cnf_diamid: Some("yaml.example.org".to_string()),
            cnf_diamrlm: Some("yaml-realm.example.org".to_string()),
            cnf_addr: Some("10.0.0.9".to_string()),
            cnf_port: 3869,
            cnf_port_tls: 5869,
        };

        // Only --diameter-realm: realm from CLI, other two from YAML.
        let args = Args::parse_from(["nextgcore-pcrfd", "--diameter-realm", "cli-realm.example"]);
        let (id, realm, addr) = resolve_diameter_identity(&args, &yaml_cfg());
        assert_eq!(realm, "cli-realm.example", "flag wins for realm");
        assert_eq!(id, "yaml.example.org", "yaml still wins for identity");
        assert_eq!(addr, "10.0.0.9:3869", "yaml still wins for address");

        // Only --diameter-id: identity from CLI, other two from YAML.
        let args = Args::parse_from(["nextgcore-pcrfd", "--diameter-id", "cli.example.org"]);
        let (id, realm, addr) = resolve_diameter_identity(&args, &yaml_cfg());
        assert_eq!(id, "cli.example.org", "flag wins for identity");
        assert_eq!(realm, "yaml-realm.example.org", "yaml still wins for realm");
        assert_eq!(addr, "10.0.0.9:3869", "yaml still wins for address");

        // Only --diameter-addr: address from CLI, other two from YAML.
        let args = Args::parse_from(["nextgcore-pcrfd", "--diameter-addr", "127.0.0.1:4001"]);
        let (id, realm, addr) = resolve_diameter_identity(&args, &yaml_cfg());
        assert_eq!(addr, "127.0.0.1:4001", "flag wins for address");
        assert_eq!(id, "yaml.example.org", "yaml still wins for identity");
        assert_eq!(realm, "yaml-realm.example.org", "yaml still wins for realm");
    }

    /// `addr` and `port` are separate config fields but one CLI string, so each
    /// half must fall back independently: setting only one must not force the
    /// other to be specified.
    #[test]
    fn config_addr_and_port_fall_back_independently() {
        let args = Args::parse_from(["nextgcore-pcrfd"]);

        let host_only = nextgcore_pcrfd::DiamConfig {
            cnf_addr: Some("10.1.2.3".to_string()),
            cnf_port: 0,
            ..Default::default()
        };
        let (_, _, addr) = resolve_diameter_identity(&args, &host_only);
        assert_eq!(addr, "10.1.2.3:3868", "default port kept");

        let port_only = nextgcore_pcrfd::DiamConfig {
            cnf_addr: None,
            cnf_port: 3999,
            ..Default::default()
        };
        let (_, _, addr) = resolve_diameter_identity(&args, &port_only);
        assert_eq!(addr, "0.0.0.0:3999", "default host kept");
    }

    /// The shipped `docker/rust/configs/epc/pcrf.yaml` has a `pcrf:` section with
    /// no `diameter:` block; it must keep parsing and keep the defaults.
    #[test]
    fn shipped_pcrf_config_shape_parses() {
        let yaml = r#"
db_uri: mongodb://mongodb:27017/nextgcore
logger:
  level: info
pcrf:
  freeDiameter: /etc/freeDiameter/pcrf.conf
  metrics:
    server:
      - address: 172.24.0.9
        port: 9090
"#;
        let parsed: nextgcore_pcrfd::PcrfYaml =
            serde_yaml::from_str(yaml).expect("shipped shape must deserialize");
        let section = parsed.pcrf.expect("pcrf section");
        assert_eq!(
            section.free_diameter.as_deref(),
            Some("/etc/freeDiameter/pcrf.conf")
        );
        assert!(section.diameter.is_none());
    }

    /// A malformed config must be an Err so main() exits non-zero instead of
    /// silently advertising `localdomain`.
    #[test]
    fn malformed_pcrf_yaml_is_an_error() {
        let path = std::env::temp_dir().join(format!(
            "nextgcore-pcrfd-bad-{}-{:?}.yaml",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, "pcrf:\n  diameter:\n    port: \"nope\"\n").unwrap();
        let result = pcrf_context_parse_config(path.to_str().unwrap());
        std::fs::remove_file(&path).ok();
        assert!(result.is_err());
    }

    #[test]
    fn test_args_log_options() {
        let args = Args::parse_from(["nextgcore-pcrfd", "-l", "/var/log/pcrf.log", "-m"]);
        assert_eq!(args.log_file, Some("/var/log/pcrf.log".to_string()));
        assert!(args.no_color);
    }
}
