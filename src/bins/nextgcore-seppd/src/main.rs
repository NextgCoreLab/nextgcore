//! NextGCore SEPP (Security Edge Protection Proxy)
//!
//! The SEPP is a 5G core network function responsible for:
//! - Securing inter-PLMN communication (roaming)
//! - N32c handshake for security capability negotiation
//! - N32f forwarding of SBI messages between PLMNs
//! - TLS/PRINS security scheme negotiation

use anyhow::{Context, Result};
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod context;
mod event;
mod handshake_sm;
mod jose;
mod n32_server;
mod n32c_build;
mod n32c_handler;
mod prins;
mod sbi_path;
mod sbi_response;
mod sepp_sm;
mod timer;
pub mod zero_trust; // Zero-trust policy engine for inter-PLMN N32 (TS 33.501)

// Re-export specific items to avoid ambiguous glob re-exports
pub use context::{
    sepp_context_final, sepp_context_init, sepp_self, NfType, PlmnId, SbiServiceType,
    SecurityCapability, SecurityCapabilityConfig, SeppAssoc, SeppContext, SeppNode,
};
pub use event::{SeppEvent, SeppEventId, SeppTimerId};
pub use handshake_sm::{HandshakeSmContext, HandshakeState};
pub use n32c_build::{
    build_security_capability_request, build_security_capability_response,
    build_security_capability_sbi_request,
};
pub use n32c_handler::{handle_security_capability_request, handle_security_capability_response};
pub use sbi_path::{
    handle_request, handle_response, sepp_sbi_close, sepp_sbi_is_running, sepp_sbi_open,
    RequestHandlerResult, SbiRequest, SbiResponse, SbiServerConfig,
};
pub use sepp_sm::SeppSmContext;
pub use timer::{sepp_timer_get_name, timer_manager, TimerConfig, TimerManager};

/// NextGCore SEPP - Security Edge Protection Proxy
#[derive(Parser, Debug)]
#[command(name = "nextgcore-seppd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Security Edge Protection Proxy", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/sepp.yaml")]
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

    /// SBI server address
    #[arg(long, default_value = "127.0.0.1")]
    sbi_addr: String,

    /// SBI server port
    #[arg(long, default_value = "7777")]
    sbi_port: u16,

    /// N32 interface address (for peer SEPP communication)
    #[arg(long)]
    n32_addr: Option<String>,

    /// N32 interface port
    #[arg(long)]
    n32_port: Option<u16>,

    /// Enable TLS
    #[arg(long)]
    tls: bool,

    /// TLS certificate path
    #[arg(long)]
    tls_cert: Option<String>,

    /// TLS key path
    #[arg(long)]
    tls_key: Option<String>,

    /// Sender FQDN (this SEPP's identifier)
    #[arg(long)]
    sender: Option<String>,

    /// Maximum number of peer SEPP nodes
    #[arg(long, default_value = "16")]
    max_node: usize,

    /// Maximum number of associations
    #[arg(long, default_value = "8192")]
    max_assoc: usize,

    /// Serving PLMN IDs as "mcc:mnc" (repeatable, e.g. --serving-plmn 999:70)
    #[arg(long = "serving-plmn")]
    serving_plmn: Vec<String>,

    /// Enable PRINS security capability (in addition to TLS)
    #[arg(long)]
    prins: bool,

    /// Peer SEPP to handshake with, as "fqdn=apiroot"
    /// (repeatable, e.g. --peer-sepp sepp.visited.com=http://10.0.0.2:7778)
    #[arg(long = "peer-sepp")]
    peer_sepp: Vec<String>,

    /// CA bundle for verifying peer-SEPP client certificates on the N32
    /// listener (enables mTLS; requires --tls/--tls-cert/--tls-key)
    #[arg(long)]
    n32_mtls_cacert: Option<String>,

    /// Client certificate presented on outgoing N32 connections (mTLS)
    #[arg(long)]
    n32_client_cert: Option<String>,

    /// Client private key for outgoing N32 connections (mTLS)
    #[arg(long)]
    n32_client_key: Option<String>,

    /// CA bundle for verifying peer-SEPP server certificates
    #[arg(long)]
    n32_ca_cert: Option<String>,

    /// Disable mandatory mTLS on the N32-c listener (LAB USE ONLY). N32-c is
    /// a mutually-authenticated TLS connection per TS 33.501; mTLS is on by
    /// default whenever --tls is set and a client CA is available.
    #[arg(long)]
    n32_allow_insecure_no_mtls: bool,

    /// Permit deriving the N32-f key hierarchy from a deterministic, no-TLS
    /// fallback when the N32-c TLS RFC 5705 exporter secret is unavailable
    /// (LAB/TEST ONLY). Strict-by-default (off): in production the N32-f master
    /// MUST come from the TLS exporter per TS 33.501 §13.2.4.4.1, else
    /// exchange-params fails (sepp-10).
    #[arg(long)]
    allow_insecure_no_tls: bool,
}

/// Parse "mcc:mnc" into a PlmnId
fn parse_plmn(spec: &str) -> Option<PlmnId> {
    let (mcc, mnc) = spec.split_once(':')?;
    Some(PlmnId::new(
        mcc.parse().ok()?,
        mnc.parse().ok()?,
        mnc.len() as u8,
    ))
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

    log::info!("NextGCore SEPP v{} starting...", env!("CARGO_PKG_VERSION"));

    // Handle kill flag
    if args.kill {
        log::info!("Kill flag set - would send SIGTERM to running instance");
        return Ok(());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize SEPP context
    sepp_context_init(args.max_node, args.max_assoc);
    log::info!(
        "SEPP context initialized (max_node={}, max_assoc={})",
        args.max_node,
        args.max_assoc
    );

    // T1.5b: Register the TLS exporter hook so the SBI client deposits the
    // RFC 5705 N32-f exporter secret into the n32c_handler store after every
    // successful outbound TLS handshake. The hook is a plain fn pointer so it
    // is Send+Sync and requires no heap allocation.
    nextgcore_sbi::client::register_tls_exporter_hook(
        n32c_handler::set_n32c_tls_exporter_secret,
    );

    // Set sender FQDN if provided
    if let Some(ref sender) = args.sender {
        let ctx = sepp_self();
        if let Ok(mut context) = ctx.write() {
            context.set_sender(sender);
            log::info!("SEPP sender FQDN: {sender}");
        };
    }

    // Serving PLMN list and security capabilities (from configuration)
    {
        let plmn_ids: Vec<PlmnId> = args
            .serving_plmn
            .iter()
            .filter_map(|s| {
                let p = parse_plmn(s);
                if p.is_none() {
                    log::warn!("Ignoring malformed --serving-plmn [{s}] (want mcc:mnc)");
                }
                p
            })
            .collect();
        let ctx = sepp_self();
        if let Ok(mut context) = ctx.write() {
            if !plmn_ids.is_empty() {
                log::info!("Serving PLMNs: {plmn_ids:?}");
                context.set_serving_plmn_ids(plmn_ids);
            }
            if args.prins {
                context.security_capability.prins = true;
                log::info!("PRINS security capability enabled");
            }
        };
    }

    // sepp-10: the N32-f no-TLS key-derivation fallback is strict-by-default
    // (off). Enable only for plaintext lab/test transports.
    if args.allow_insecure_no_tls {
        n32c_handler::set_allow_insecure_no_tls(true);
        log::warn!(
            "N32-f no-TLS key-derivation fallback ENABLED (allow_insecure_no_tls); \
             LAB/TEST ONLY — production requires the N32-c TLS RFC 5705 exporter"
        );
    }

    // Initialize SEPP state machine
    let mut sepp_sm = SeppSmContext::new();
    sepp_sm.init();
    log::info!("SEPP state machine initialized");

    // Parse configuration (if file exists)
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
        // Parse YAML configuration file
        // In C: sepp_context_parse_config()
        match std::fs::read_to_string(&args.config) {
            Ok(content) => {
                log::debug!("Configuration file loaded ({} bytes)", content.len());
            }
            Err(e) => {
                log::warn!("Failed to read configuration file: {e}");
            }
        }
    } else {
        log::debug!("Configuration file not found: {}", args.config);
    }

    // Build SBI server configuration
    let sbi_config = sbi_path::SbiServerConfig {
        addr: args.sbi_addr.clone(),
        port: args.sbi_port,
        tls_enabled: args.tls,
        tls_cert: args.tls_cert.clone(),
        tls_key: args.tls_key.clone(),
        n32_addr: args.n32_addr.clone(),
        n32_port: args.n32_port,
    };

    // Mark SBI state open (context-level bookkeeping)
    sepp_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;

    // N32 TLS/mTLS settings shared by the listener and the N32-c client.
    // mTLS is mandatory by default whenever TLS is enabled (TS 33.501).
    let n32_tls = n32_server::N32TlsConfig {
        cert: args.tls_cert.clone(),
        key: args.tls_key.clone(),
        verify_client_cacert: args.n32_mtls_cacert.clone(),
        client_cert: args.n32_client_cert.clone(),
        client_key: args.n32_client_key.clone(),
        ca_cert: args.n32_ca_cert.clone(),
        allow_insecure_no_mtls: args.n32_allow_insecure_no_mtls,
    };
    let n32_tls_opt = if args.tls { Some(&n32_tls) } else { None };

    // Start the consumer-facing SBI server (C8): home-PLMN NFs send outbound
    // roaming requests here; the handler runs the forwarding pipeline through
    // the selected peer SEPP over N32-f.
    let sbi_server = n32_server::start_sbi_server(&args.sbi_addr, args.sbi_port, n32_tls_opt)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    log::info!(
        "SBI server listening on {}:{}",
        args.sbi_addr,
        args.sbi_port
    );

    // Start the N32 listener (N32-c handshake + N32-f forwarding endpoints)
    let mut n32_listener = None;
    if let (Some(n32_addr), Some(n32_port)) = (&args.n32_addr, args.n32_port) {
        let server = n32_server::start_n32_listener(n32_addr, n32_port, n32_tls_opt)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        log::info!("N32 interface listening on {n32_addr}:{n32_port}");
        n32_listener = Some(server);
    }

    // Initiate the N32-c handshake towards configured peer SEPPs
    for peer in &args.peer_sepp {
        let Some((fqdn, api_root)) = peer.split_once('=') else {
            log::warn!("Ignoring malformed --peer-sepp [{peer}] (want fqdn=apiroot)");
            continue;
        };
        let local_api_root = match (&args.n32_addr, args.n32_port) {
            (Some(addr), Some(port)) => Some(format!(
                "{}://{}:{}",
                if args.tls { "https" } else { "http" },
                addr,
                port
            )),
            _ => None,
        };
        match n32_server::initiate_n32c_handshake(
            fqdn,
            api_root,
            local_api_root.as_deref(),
            n32_tls_opt,
        )
        .await
        {
            Ok(outcome) => log::info!(
                "Peer SEPP [{fqdn}] established (node={}, security={:?})",
                outcome.node_id,
                outcome.security
            ),
            Err(e) => log::error!("Peer SEPP [{fqdn}] handshake failed: {e}"),
        }
    }

    log::info!("NextGCore SEPP ready");

    // Main event loop (async)
    run_event_loop_async(&mut sepp_sm, shutdown).await?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Stop the N32 listener
    if let Some(server) = n32_listener.take() {
        let _ = server.stop().await;
        log::info!("N32 listener stopped");
    }

    // Stop the consumer-facing SBI server
    let _ = sbi_server.stop().await;
    sepp_sbi_close();
    log::info!("SBI server closed");

    // Cleanup state machine
    sepp_sm.fini();
    log::info!("SEPP state machine finalized");

    // Cleanup context
    sepp_context_final();
    log::info!("SEPP context finalized");

    log::info!("NextGCore SEPP stopped");
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

/// Async main event loop with timer integration
async fn run_event_loop_async(
    sepp_sm: &mut SeppSmContext,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    log::debug!("Entering async main event loop");

    let timer_mgr = timer_manager();

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
                "SEPP timer expired: id={} type={:?} data={:?}",
                entry.id,
                entry.timer_type,
                entry.data
            );

            // Create timer event and dispatch to state machine
            let mut event = SeppEvent::sbi_timer(entry.timer_type);
            if let Some(ref nf_id) = entry.data {
                event = event.with_nf_instance(nf_id.clone());
            }

            sepp_sm.dispatch(&mut event);
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
        let args = Args::parse_from(["nextgcore-seppd"]);
        assert_eq!(args.config, "/etc/nextgcore/sepp.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.sbi_addr, "127.0.0.1");
        assert_eq!(args.sbi_port, 7777);
        assert!(!args.tls);
        assert_eq!(args.max_node, 16);
        assert_eq!(args.max_assoc, 8192);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-seppd",
            "-c",
            "/custom/sepp.yaml",
            "-e",
            "debug",
            "--sbi-addr",
            "0.0.0.0",
            "--sbi-port",
            "8080",
            "--sender",
            "sepp.example.com",
            "--max-node",
            "32",
            "--max-assoc",
            "16384",
        ]);
        assert_eq!(args.config, "/custom/sepp.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 8080);
        assert_eq!(args.sender, Some("sepp.example.com".to_string()));
        assert_eq!(args.max_node, 32);
        assert_eq!(args.max_assoc, 16384);
    }

    #[test]
    fn test_args_tls() {
        let args = Args::parse_from([
            "nextgcore-seppd",
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

    #[test]
    fn test_args_n32() {
        let args = Args::parse_from([
            "nextgcore-seppd",
            "--n32-addr",
            "192.168.1.1",
            "--n32-port",
            "7778",
        ]);
        assert_eq!(args.n32_addr, Some("192.168.1.1".to_string()));
        assert_eq!(args.n32_port, Some(7778));
    }
}
