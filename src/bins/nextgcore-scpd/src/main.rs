//! NextGCore SCP (Service Communication Proxy)
//!
//! The SCP is a 5G core network function responsible for:
//! - Acting as a proxy between NF consumers and producers
//! - Performing NF discovery delegation
//! - Routing requests to target NFs
//! - Handling inter-PLMN communication via SEPP

use anyhow::{Context, Result};
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

mod cache;
mod circuit_breaker;
mod config;
mod context;
mod event;
mod proxy;
mod sbi_path;
mod sbi_response;
mod scp_sm;
mod timer;

pub use context::{scp_context_final, scp_context_init, scp_self, NfType, ScpContext};
pub use event::{ScpEvent, ScpEventId, ScpTimerId};
pub use proxy::{
    forwardable_request_headers, relayable_response_headers, ApiRoot, ScpProxy, ScpProxyConfig,
};
pub use sbi_path::{
    discovery_cache, headers, parse_search_result, scp_sbi_close, scp_sbi_is_running, scp_sbi_open,
    select_nf_instance, select_nf_instance_round_robin, DiscoveryCache, NfInstanceCandidate,
    SbiServerConfig,
};
pub use scp_sm::{ScpSmContext, ScpState};
pub use timer::{timer_manager, ScpTimerManager};

/// Built-in SBI listen/advertise address when neither CLI, env, nor config
/// sets one. A `clap` `default_value` is deliberately NOT used: it would make
/// `--sbi-addr` always look explicitly set, so the config file could never
/// override it (the precedence-inversion trap; see the config module).
const DEFAULT_SBI_ADDR: &str = "127.0.0.1";
/// Built-in SBI port (SCP default 7777).
const DEFAULT_SBI_PORT: u16 = 7777;
/// How often the main loop reclaims expired proxy-cache entries (scpd-#102).
const CACHE_PURGE_INTERVAL: Duration = Duration::from_secs(60);

/// NextGCore SCP - Service Communication Proxy
#[derive(Parser, Debug)]
#[command(name = "nextgcore-scpd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Service Communication Proxy", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/scp.yaml")]
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

    /// SBI server address [default: 127.0.0.1]. Overrides `scp.sbi.server[0].address`.
    #[arg(long)]
    sbi_addr: Option<String>,

    /// SBI server port [default: 7777]. Overrides `scp.sbi.server[0].port`.
    #[arg(long)]
    sbi_port: Option<u16>,

    /// Enable TLS (also settable via `scp.sbi.tls.enabled`)
    #[arg(long)]
    tls: bool,

    /// TLS certificate path
    #[arg(long)]
    tls_cert: Option<String>,

    /// TLS key path
    #[arg(long)]
    tls_key: Option<String>,

    /// Upstream connect timeout in seconds [default: 2].
    /// Precedence: this flag > SCP_CONNECT_TIMEOUT > `scp.connect_timeout` > default.
    #[arg(long)]
    connect_timeout: Option<u64>,

    /// Upstream request timeout in seconds [default: 10].
    /// Precedence: this flag > SCP_REQUEST_TIMEOUT > `scp.request_timeout` > default.
    #[arg(long)]
    request_timeout: Option<u64>,

    /// NRF base URI for Model D delegated discovery
    /// (falls back to the NRF_URI environment variable, then `scp.sbi.client.nrf[0].uri`)
    #[arg(long)]
    nrf_uri: Option<String>,

    /// The SCP's own NF Instance ID, used as `nfInstanceId` when the SCP
    /// acquires delegated OAuth2 access tokens for Model D requests
    /// (falls back to NF_INSTANCE_ID, then `scp.nf_instance_id`)
    #[arg(long)]
    nf_instance_id: Option<String>,

    /// The SCP's own FQDN/identity, used for the `Via`/`Server` headers and
    /// `SCP-<FQDN>` loop detection (TS 29.500 §6.10.8/§6.10.10). Falls back to
    /// SCP_FQDN, then `scp.fqdn`, then a built-in default.
    #[arg(long)]
    scp_fqdn: Option<String>,

    /// Treat the next hop on forwarded requests as another SCP: convey the
    /// selected producer apiRoot in `3gpp-Sbi-Target-apiRoot` instead of
    /// stripping it (TS 29.500 §6.10.2.5).
    #[arg(long)]
    next_hop_scp: bool,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[tokio::main]
async fn main() -> Result<()> {
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

    log::info!("NextGCore SCP v{} starting...", env!("CARGO_PKG_VERSION"));

    // Issue: `--kill` was advertised as "Kill running instance" and did
    // NOTHING -- it logged an intention and returned success, so the process
    // exited 0 while the instance kept serving. Fail loudly instead.
    if args.kill {
        return Err(nextgcore_core::signal::kill_unsupported().into());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize SCP context
    scp_context_init();
    log::info!("SCP context initialized");

    // Initialize SCP state machine
    let mut scp_sm = ScpSmContext::new();
    scp_sm.init();
    log::info!("SCP state machine initialized");

    // Parse configuration (if the file exists). Following the 5GC-NF
    // convention (nssfd/amfd), a malformed file is non-fatal: warn and fall
    // back to defaults rather than take the proxy down. Unlike hssd/pcrfd
    // (#58), the SCP config carries no PLMN-routing identity, so degrading to
    // defaults is safe.
    let scp_yaml = load_config(&args.config);

    // Resolve every config-driven setting with CLI > env > file > default
    // precedence (config::resolve). CLI flags that participate are `Option`
    // (no clap default_value) so "unset" is distinguishable from "explicit".
    let defaults = ScpProxyConfig::default();

    let sbi_addr = config::resolve(
        args.sbi_addr.clone(),
        std::env::var("SCP_SBI_ADDR").ok(),
        scp_yaml.sbi_address(),
        DEFAULT_SBI_ADDR.to_string(),
    );
    let sbi_port = config::resolve(
        args.sbi_port,
        std::env::var("SCP_SBI_PORT")
            .ok()
            .and_then(|v| v.parse().ok()),
        scp_yaml.sbi_port(),
        DEFAULT_SBI_PORT,
    );

    let nrf_uri = args
        .nrf_uri
        .clone()
        .or_else(|| std::env::var("NRF_URI").ok())
        .or_else(|| scp_yaml.nrf_uri());
    if nrf_uri.is_none() {
        log::warn!(
            "No NRF URI configured (--nrf-uri / NRF_URI / scp.sbi.client.nrf): \
             Model D delegated discovery is disabled"
        );
    }

    let nf_instance_id = args
        .nf_instance_id
        .clone()
        .or_else(|| std::env::var("NF_INSTANCE_ID").ok())
        .or_else(|| scp_yaml.section().nf_instance_id.clone());

    // SCP identity: warn when it is left at the built-in default so multi-SCP
    // deployments are nudged to set a unique FQDN (TS 29.500 §6.10.10).
    let fqdn_source = args
        .scp_fqdn
        .clone()
        .or_else(|| std::env::var("SCP_FQDN").ok())
        .or_else(|| scp_yaml.section().fqdn.clone());
    let (own_fqdn, identity_is_default) = resolve_identity(fqdn_source, defaults.own_fqdn.clone());
    if identity_is_default {
        log::warn!(
            "SCP identity left at the default '{own_fqdn}'; set scp.fqdn / --scp-fqdn / SCP_FQDN \
             to a unique FQDN so loop detection and Via annotation are correct in a multi-SCP \
             deployment (TS 29.500 §6.10.10)"
        );
    }

    let connect_timeout = Duration::from_secs(config::resolve(
        args.connect_timeout,
        env_u64("SCP_CONNECT_TIMEOUT"),
        scp_yaml.section().connect_timeout,
        defaults.connect_timeout.as_secs(),
    ));
    let request_timeout = Duration::from_secs(config::resolve(
        args.request_timeout,
        env_u64("SCP_REQUEST_TIMEOUT"),
        scp_yaml.section().request_timeout,
        defaults.request_timeout.as_secs(),
    ));

    let max_cache_entries = scp_yaml
        .section()
        .max_cache_entries
        .unwrap_or(defaults.max_cache_entries);
    let cache_ttl = scp_yaml
        .section()
        .cache_ttl
        .map(Duration::from_secs)
        .unwrap_or(defaults.cache_ttl);

    // TLS: --tls forces on; otherwise honour scp.sbi.tls.enabled. cert/key
    // come from the flag first, then the config.
    let tls_cfg = scp_yaml.section().sbi.as_ref().and_then(|s| s.tls.as_ref());
    let tls_enabled = args.tls || tls_cfg.and_then(|t| t.enabled).unwrap_or(false);
    let tls_cert = args
        .tls_cert
        .clone()
        .or_else(|| tls_cfg.and_then(|t| t.cert.clone()));
    let tls_key = args
        .tls_key
        .clone()
        .or_else(|| tls_cfg.and_then(|t| t.key.clone()));

    log::info!(
        "SCP identity: SCP-{own_fqdn}; SBI {sbi_addr}:{sbi_port} (tls={tls_enabled}); \
         connect_timeout={}s request_timeout={}s; cache max={max_cache_entries} ttl={}s",
        connect_timeout.as_secs(),
        request_timeout.as_secs(),
        cache_ttl.as_secs()
    );

    // Build SBI server lifecycle configuration
    let sbi_config = sbi_path::SbiServerConfig {
        addr: sbi_addr.clone(),
        port: sbi_port,
        tls_enabled,
        tls_cert: tls_cert.clone(),
        tls_key: tls_key.clone(),
    };

    // Open SBI server (lifecycle state)
    scp_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;

    // Start the actual HTTP/2 proxy (TS 29.500 §6.10: Model C + Model D)
    let scp_proxy = Arc::new(ScpProxy::new(ScpProxyConfig {
        nrf_uri,
        connect_timeout,
        request_timeout,
        nf_instance_id,
        own_fqdn,
        next_hop_scp: args.next_hop_scp,
        max_cache_entries,
        cache_ttl,
        ..defaults
    }));
    let mut http_config =
        nextgcore_sbi::server::SbiServerConfig::with_host_port(&sbi_addr, sbi_port)
            .map_err(|e| anyhow::anyhow!("Invalid SBI listen address: {e}"))?;
    if tls_enabled {
        match (&tls_key, &tls_cert) {
            (Some(key), Some(cert)) => {
                http_config = http_config.with_tls(key.clone(), cert.clone());
            }
            _ => {
                anyhow::bail!("TLS enabled but tls-cert/tls-key not provided (flag or scp.sbi.tls)")
            }
        }
    }
    let http_server = nextgcore_sbi::server::SbiServer::new(http_config);
    let handler_proxy = scp_proxy.clone();
    http_server
        .start(move |request: nextgcore_sbi::message::SbiRequest| {
            let proxy = handler_proxy.clone();
            async move { proxy.handle(request).await }
        })
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI HTTP/2 server: {e}"))?;
    log::info!("SBI server listening on {sbi_addr}:{sbi_port}");

    log::info!("NextGCore SCP ready");

    // Main event loop (async)
    run_event_loop_async(&mut scp_sm, scp_proxy.clone(), shutdown).await?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Stop the HTTP/2 proxy server, then the lifecycle state
    if let Err(e) = http_server.stop().await {
        log::warn!("Error stopping SBI HTTP/2 server: {e}");
    }
    scp_sbi_close();
    log::info!("SBI server closed");

    // Cleanup state machine
    scp_sm.fini();
    log::info!("SCP state machine finalized");

    // Cleanup context
    scp_context_final();
    log::info!("SCP context finalized");

    log::info!("NextGCore SCP stopped");
    Ok(())
}

/// Read a `u64` from an environment variable, returning `None` when it is unset
/// or not a valid integer.
fn env_u64(key: &str) -> Option<u64> {
    std::env::var(key).ok().and_then(|v| v.parse().ok())
}

/// Resolve the SCP identity from the first configured source, falling back to
/// `default`. Returns `(fqdn, is_default)`; `is_default` is `true` when no
/// source supplied a value, which the caller uses to emit the multi-SCP
/// identity warning (TS 29.500 §6.10.10). Pure so it is unit-testable.
fn resolve_identity(source: Option<String>, default: String) -> (String, bool) {
    match source {
        Some(fqdn) => (fqdn, false),
        None => (default, true),
    }
}

/// Load and parse the SCP config file, if present. A missing file is silent
/// (the built-in defaults are a working dev configuration); a present-but-
/// malformed file warns and yields an empty config (5GC-NF lenient convention).
fn load_config(path: &str) -> config::ScpYaml {
    if !std::path::Path::new(path).exists() {
        log::debug!("Configuration file not found: {path}");
        return config::ScpYaml::default();
    }
    match std::fs::read_to_string(path) {
        Ok(content) => match config::parse(&content) {
            Ok(cfg) => {
                log::info!("Loaded configuration from {path}");
                cfg
            }
            Err(e) => {
                log::warn!("Ignoring malformed configuration file {path}: {e}");
                config::ScpYaml::default()
            }
        },
        Err(e) => {
            log::warn!("Failed to read configuration file {path}: {e}");
            config::ScpYaml::default()
        }
    }
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
    // Set up Ctrl+C handler
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        shutdown_clone.store(true, Ordering::SeqCst);
        SHUTDOWN.store(true, Ordering::SeqCst);
    })
    .context("Failed to set Ctrl+C handler")?;

    Ok(())
}

/// Async main event loop with timer integration and periodic cache reclamation.
async fn run_event_loop_async(
    scp_sm: &mut ScpSmContext,
    proxy: Arc<ScpProxy>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    log::debug!("Entering async main event loop");

    let timer_mgr = timer_manager();
    let mut last_purge = Instant::now();

    while !shutdown.load(Ordering::SeqCst) && !SHUTDOWN.load(Ordering::SeqCst) {
        // Compute optimal sleep duration based on pending timers
        let poll_interval = nextgcore_core::async_timer::compute_poll_interval(
            timer_mgr.inner(),
            Duration::from_millis(100),
        );
        tokio::time::sleep(poll_interval).await;

        // Process timer expirations and dispatch to state machine
        let expired = timer_mgr.process_expired();
        for entry in &expired {
            log::debug!(
                "SCP timer expired: id={} type={:?} data={:?}",
                entry.id,
                entry.timer_type,
                entry.data
            );

            // Create timer event and dispatch to state machine
            let mut event = ScpEvent::sbi_timer(entry.timer_type);
            if let Some(ref nf_id) = entry.data {
                event = event.with_nf_instance(nf_id.clone());
            }

            scp_sm.dispatch(&mut event);
        }

        // scpd-#102: periodically reclaim expired proxy-cache entries so the
        // bounded caches shrink between inserts on their keys.
        if last_purge.elapsed() >= CACHE_PURGE_INTERVAL {
            proxy.purge_expired_caches();
            last_purge = Instant::now();
        }

        // Check for shutdown
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
    }

    // Cleanup: clear all timers on shutdown
    timer_mgr.clear();
    log::debug!("Exiting async main event loop");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-scpd"]);
        assert_eq!(args.config, "/etc/nextgcore/scp.yaml");
        assert_eq!(args.log_level, "info");
        // Unset by default so env/config can win (the precedence-inversion
        // trap: a clap default_value would make these always look explicit).
        assert_eq!(args.sbi_addr, None);
        assert_eq!(args.sbi_port, None);
        assert_eq!(args.connect_timeout, None);
        assert_eq!(args.request_timeout, None);
        assert!(!args.tls);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-scpd",
            "-c",
            "/custom/scp.yaml",
            "-e",
            "debug",
            "--sbi-addr",
            "0.0.0.0",
            "--sbi-port",
            "8080",
            "--connect-timeout",
            "5",
            "--request-timeout",
            "20",
        ]);
        assert_eq!(args.config, "/custom/scp.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.sbi_addr.as_deref(), Some("0.0.0.0"));
        assert_eq!(args.sbi_port, Some(8080));
        assert_eq!(args.connect_timeout, Some(5));
        assert_eq!(args.request_timeout, Some(20));
    }

    #[test]
    fn test_args_tls() {
        let args = Args::parse_from([
            "nextgcore-scpd",
            "--tls",
            "--tls-cert",
            "/path/to/cert.pem",
            "--tls-key",
            "/path/to/key.pem",
        ]);
        assert!(args.tls);
        assert_eq!(args.tls_cert, Some("/path/to/cert.pem".to_string()));
        assert_eq!(args.tls_key, Some("/path/to/key.pem".to_string()));
    }

    /// A temp scp.yaml with non-default values is parsed, and its settings flow
    /// through with CLI > env > file > default precedence (scpd-#102 acceptance).
    #[test]
    fn test_config_file_values_are_applied() {
        let yaml = r#"
scp:
  sbi:
    server:
      - address: 10.9.8.7
        port: 9999
    client:
      nrf:
        - uri: http://10.0.0.10:7777
  fqdn: scp-from-file.5gc.example.org
  connect_timeout: 7
  request_timeout: 21
"#;
        let cfg = config::parse(yaml).expect("valid config");
        // File value applies when neither CLI nor env is set.
        let sbi_addr = config::resolve(
            None::<String>,
            None,
            cfg.sbi_address(),
            DEFAULT_SBI_ADDR.to_string(),
        );
        assert_eq!(sbi_addr, "10.9.8.7");
        assert_eq!(
            config::resolve(None, None, cfg.sbi_port(), DEFAULT_SBI_PORT),
            9999
        );
        assert_eq!(cfg.nrf_uri().as_deref(), Some("http://10.0.0.10:7777"));
        assert_eq!(
            cfg.section().fqdn.as_deref(),
            Some("scp-from-file.5gc.example.org")
        );

        // CLI beats the file; env beats the file; the default is the floor.
        assert_eq!(
            config::resolve(
                Some("cli".to_string()),
                None,
                cfg.sbi_address(),
                DEFAULT_SBI_ADDR.to_string()
            ),
            "cli"
        );
        assert_eq!(
            config::resolve(None, Some(2u64), cfg.section().connect_timeout, 2),
            2,
            "env overrides the file's connect_timeout"
        );
        assert_eq!(
            config::resolve::<u64>(
                None,
                None,
                None,
                ScpProxyConfig::default().request_timeout.as_secs()
            ),
            10,
            "the built-in default holds when nothing else is set"
        );
    }

    /// scpd-#102 acceptance: the multi-SCP identity warning fires exactly when
    /// no source supplied an FQDN (so it is left at the default).
    #[test]
    fn test_identity_default_triggers_warning() {
        let default = ScpProxyConfig::default().own_fqdn;

        // No source -> default is used and the warn condition is set.
        let (fqdn, is_default) = resolve_identity(None, default.clone());
        assert_eq!(fqdn, default);
        assert!(
            is_default,
            "warn fires when identity is left at the default"
        );

        // An explicit source -> used verbatim, no warning.
        let (fqdn, is_default) =
            resolve_identity(Some("scp1.5gc.example.org".to_string()), default.clone());
        assert_eq!(fqdn, "scp1.5gc.example.org");
        assert!(!is_default, "no warning when the identity is configured");
    }

    /// scpd-#102 acceptance: a supplied timeout (CLI arg here) propagates into
    /// the ScpProxyConfig the proxy is built with; the default holds when unset.
    #[test]
    fn test_timeout_propagates_into_proxy_config() {
        let defaults = ScpProxyConfig::default();

        // CLI value wins and reaches the config as a Duration.
        let connect = Duration::from_secs(config::resolve(
            Some(5u64),
            None,
            None,
            defaults.connect_timeout.as_secs(),
        ));
        let cfg = ScpProxyConfig {
            connect_timeout: connect,
            ..ScpProxyConfig::default()
        };
        assert_eq!(cfg.connect_timeout, Duration::from_secs(5));

        // Unset everywhere -> the 2s/10s built-in defaults are preserved.
        let connect_default = Duration::from_secs(config::resolve::<u64>(
            None,
            None,
            None,
            defaults.connect_timeout.as_secs(),
        ));
        let request_default = Duration::from_secs(config::resolve::<u64>(
            None,
            None,
            None,
            defaults.request_timeout.as_secs(),
        ));
        assert_eq!(connect_default, Duration::from_secs(2));
        assert_eq!(request_default, Duration::from_secs(10));
    }
}
