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
mod telescopic;
mod timer;

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

    /// Log level (trace, debug, info, warn, error). Without it, the config
    /// file's `logger.level`, else `info`; `RUST_LOG` overrides (#691).
    #[arg(short = 'e', long)]
    log_level: Option<String>,

    /// Disable color output
    #[arg(short = 'm', long)]
    no_color: bool,

    /// Kill a running instance (NOT SUPPORTED: exits with an error;
    /// stop the NF through its supervisor)
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
    /// default whenever --tls is set and a client CA is available. Refused at
    /// startup under the `production` SBI profile (#1848).
    #[arg(long)]
    n32_allow_insecure_no_mtls: bool,

    /// Permit deriving the N32-f key hierarchy from a deterministic, no-TLS
    /// fallback when the N32-c TLS RFC 5705 exporter secret is unavailable
    /// (LAB/TEST ONLY). Strict-by-default (off): in production the N32-f master
    /// MUST come from the TLS exporter per TS 33.501 §13.2.4.4.1, else
    /// exchange-params fails (sepp-10). Refused at startup under the
    /// `production` SBI profile (#1848).
    #[arg(long)]
    allow_insecure_no_tls: bool,

    /// A target NF inside this PLMN that a reconstructed N32-f request may be
    /// forwarded to under the production SBI profile, besides hosts under the
    /// serving PLMNs' 5gc.mnc<MNC>.mcc<MCC>.3gppnetwork.org domains (#1870):
    /// `host`, `host:port`, `[v6]:port`, or `.domain` for every host under it.
    /// Repeatable. Every target must also be https.
    #[arg(long = "n32f-target-allow")]
    n32f_target_allow: Vec<String>,

    /// The SBI port a home-domain host, a bare `--n32f-target-allow` host or a
    /// `.domain` entry is admitted on (#1870). Repeatable; default 443. A
    /// `host:port` entry names its own port.
    #[arg(long = "n32f-target-port")]
    n32f_target_port: Vec<u16>,
}

/// #1848: the SEPP's lab/test flags weaken N32 below what TS 33.501 requires,
/// so under the `production` SBI profile starting with any of them is an
/// error, not a warning: N32-c is mutually authenticated TLS between the SEPPs
/// (§13.1, §13.2.2.2), and the N32-f key hierarchy comes from that TLS
/// session's exporter (§13.2.4.4.1). Under `dev` they still work, for the
/// plaintext lab stacks.
fn refuse_lab_flags_under_production(
    profile: nextgcore_sbi::security::SbiProfile,
    n32_allow_insecure_no_mtls: bool,
    allow_insecure_no_tls: bool,
) -> Result<(), String> {
    if !profile.is_production() {
        return Ok(());
    }
    let set: Vec<&str> = [
        (
            n32_allow_insecure_no_mtls,
            "--n32-allow-insecure-no-mtls (N32-c without mutual TLS, TS 33.501 §13.2.2.2)",
        ),
        (
            allow_insecure_no_tls,
            "--allow-insecure-no-tls (N32-f keys without the N32-c TLS exporter, TS 33.501 \
             §13.2.4.4.1)",
        ),
    ]
    .into_iter()
    .filter_map(|(on, name)| on.then_some(name))
    .collect();
    if set.is_empty() {
        return Ok(());
    }
    Err(format!(
        "the SBI profile is production, which does not run the SEPP's lab-only flags: {}. \
         Remove them, or select {}=dev explicitly",
        set.join(", "),
        nextgcore_sbi::security::SBI_PROFILE_ENV
    ))
}

/// #1848: the client TLS every peer SEPP is dialled with. Under the
/// `production` SBI profile:
/// - each `--peer-sepp` apiRoot must be `https`: N32-c is mutually authenticated TLS
///   between the SEPPs (TS 33.501 §13.1, §13.2.2.2), so an `http` peer is a
///   startup error rather than a cleartext N32;
/// - the SEPP presents its own client certificate, `--n32-client-cert` /
///   `--n32-client-key`, else the profile's (`NEXTGCORE_SBI_TLS_CLIENT_*`);
/// - the peer is verified against `--n32-ca-cert`, else the profile's CA,
///   and only that CA: with a CA configured the client never falls back to
///   the public web roots;
/// - each of those files must exist, named when one does not.
///
/// `Ok(Some)` is the TLS to dial with (whatever `--tls` says, which governs the
/// listener). `Ok(None)` under `dev`: as before. #1870: this applies with no
/// `--peer-sepp` too, because a receiving SEPP dials its peers for the N32-f
/// error report, and that call uses the same TLS (`set_n32_client_tls`).
fn n32_peer_client_tls(
    profile: nextgcore_sbi::security::SbiProfile,
    peers: &[String],
    given: &n32_server::N32TlsConfig,
    defaults: &nextgcore_sbi::security::TlsPaths,
) -> Result<Option<n32_server::N32TlsConfig>, String> {
    if !profile.is_production() {
        return Ok(None);
    }
    for peer in peers {
        let api_root = peer.split_once('=').map_or(peer.as_str(), |(_, r)| r);
        if !api_root
            .get(..8)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
        {
            return Err(format!(
                "the SBI profile is production and --peer-sepp {peer} is not https: N32-c is \
                 mutually authenticated TLS between the SEPPs (TS 33.501 §13.2.2.2)"
            ));
        }
    }
    let mut tls = given.clone();
    tls.client_cert = tls.client_cert.or_else(|| defaults.client_cert.clone());
    tls.client_key = tls.client_key.or_else(|| defaults.client_key.clone());
    tls.ca_cert = tls.ca_cert.or_else(|| Some(defaults.ca_cert.clone()));
    for (label, path) in [
        ("client certificate (--n32-client-cert)", &tls.client_cert),
        ("client key (--n32-client-key)", &tls.client_key),
        ("peer CA (--n32-ca-cert)", &tls.ca_cert),
    ] {
        match path {
            Some(p) if std::path::Path::new(p).is_file() => {}
            Some(p) => {
                return Err(format!(
                    "the SBI profile is production and the N32 {label} {p} does not exist"
                ))
            }
            None => {
                return Err(format!(
                    "the SBI profile is production and no N32 {label} is configured, so the \
                     peer SEPPs could not be dialled with mutual TLS"
                ))
            }
        }
    }
    Ok(Some(tls))
}

/// Parse "mcc:mnc" into a PlmnId. An MCC is exactly 3 digits and an MNC 2 or 3
/// (TS 23.003 §2.2): anything else is refused rather than padded, since `1:01`
/// would otherwise become MCC 001 and MNC 70 and 070 are different PLMNs (#2115).
fn parse_plmn(spec: &str) -> Result<PlmnId, String> {
    use nextgcore_core::plmn::{check_digits, PlmnPart};
    let (mcc, mnc) = spec
        .split_once(':')
        .ok_or_else(|| format!("--serving-plmn={spec:?}: want mcc:mnc"))?;
    check_digits("--serving-plmn mcc", PlmnPart::Mcc, mcc)?;
    check_digits("--serving-plmn mnc", PlmnPart::Mnc, mnc)?;
    // Both are 2-3 ASCII digits, so they parse.
    let number = |digits: &str| digits.parse::<u16>().map_err(|e| format!("{spec:?}: {e}"));
    Ok(PlmnId::new(number(mcc)?, number(mnc)?, mnc.len() as u8))
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    init_logging(&args)?;
    // #1848: the lab flags that weaken N32 do not run under production.
    refuse_lab_flags_under_production(
        nextgcore_sbi::security::SbiProfile::resolve(),
        args.n32_allow_insecure_no_mtls,
        args.allow_insecure_no_tls,
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    // G32/G43: Initialize OpenTelemetry tracing (Jaeger/OTLP exporter)
    let _otel = nextgcore_metrics::otel::init_otel(
        nextgcore_metrics::otel::OtelConfig::new(env!("CARGO_PKG_NAME")).with_endpoint(
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://jaeger:4317".to_string()),
        ),
    )
    .ok();

    log::info!("NextGCore SEPP v{} starting...", env!("CARGO_PKG_VERSION"));

    // Issue: `--kill` was advertised as "Kill running instance" and did
    // NOTHING -- it logged an intention and returned success, so the process
    // exited 0 while the instance kept serving. Fail loudly instead.
    if args.kill {
        return Err(nextgcore_core::signal::kill_unsupported().into());
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
    nextgcore_sbi::client::register_tls_exporter_hook(n32c_handler::set_n32c_tls_exporter_secret);

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
                parse_plmn(s)
                    .map_err(|why| log::warn!("Ignoring malformed --serving-plmn: {why}"))
                    .ok()
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
    // #1848: under production every peer SEPP is dialled over mutually
    // authenticated TLS with this SEPP's own certificate and a configured CA,
    // never cleartext and never the public web roots. Checked before anything
    // listens or dials.
    let peer_tls = n32_peer_client_tls(
        nextgcore_sbi::security::SbiProfile::resolve(),
        &args.peer_sepp,
        &n32_tls,
        &nextgcore_sbi::security::TlsPaths::from_env(),
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    let peer_tls_opt = peer_tls.as_ref().or(n32_tls_opt);
    // #1870 (R26 on #1881): the n32f-error report and the SBI-side forward dial
    // the peer SEPP with the same TLS as the N32-c handshake: under production
    // this SEPP's own certificate and a configured CA (#1881's
    // `n32_peer_client_tls`, which now applies whether or not a --peer-sepp is
    // given, because a receiving SEPP dials its peers too), else the --tls flags.
    n32_server::set_n32_client_tls(peer_tls_opt.cloned());

    // #1870: where a peer-supplied N32-f target may point, and over what.
    let home_domains: Vec<String> = sepp_self()
        .read()
        .map(|c| {
            c.serving_plmn_ids
                .iter()
                .map(n32_server::home_network_domain)
                .collect()
        })
        .unwrap_or_default();
    let forward_policy = n32_server::N32fForwardPolicy::new(
        nextgcore_sbi::security::SbiProfile::resolve(),
        home_domains,
        args.n32f_target_allow.clone(),
    )
    .with_allowed_ports(args.n32f_target_port.clone());
    forward_policy
        .check_files()
        .map_err(|e| anyhow::anyhow!(e))?;
    if forward_policy.profile.is_production() {
        log::info!(
            "N32-f forwarding: production SBI profile, https targets only, under {:?} or in \
             --n32f-target-allow {:?}; CA={} client certificate={}",
            forward_policy.home_domains,
            forward_policy.allowed_targets,
            forward_policy.tls.ca_cert,
            forward_policy.tls.client_cert.as_deref().unwrap_or("NONE"),
        );
        if forward_policy.home_domains.is_empty() && forward_policy.allowed_targets.is_empty() {
            log::warn!(
                "N32-f forwarding: no --serving-plmn and no --n32f-target-allow, so every \
                 reconstructed N32-f request will be refused"
            );
        }
    } else {
        log::warn!(
            "N32-f forwarding: dev SBI profile, any peer-supplied target is dialled over its \
             own scheme"
        );
    }
    n32_server::set_n32f_forward_policy(forward_policy);

    // Start the consumer-facing SBI server (C8): home-PLMN NFs send outbound
    // roaming requests here; the handler runs the forwarding pipeline through
    // the selected peer SEPP over N32-f.
    // #1795: the listener follows the SBI security profile.
    let sbi_profile = nextgcore_sbi::security::SbiProfile::resolve();
    let sbi_config = n32_server::sbi_server_config(
        &args.sbi_addr,
        args.sbi_port,
        n32_tls_opt,
        sbi_profile,
        &nextgcore_sbi::security::SbiSecurityPolicy::for_profile(sbi_profile),
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    if args.n32_addr.is_some() && args.n32_port.is_some() {
        n32_server::check_n32_transport(sbi_profile, n32_tls_opt)
            .map_err(|e| anyhow::anyhow!(e))?;
    }
    let sbi_server = n32_server::start_sbi_server(sbi_config)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    // #1308: loopback by default; say which setting opens it to remote peers.
    if let Ok(addr) = nextgcore_core::sockaddr::parse_listen_addr(&args.sbi_addr, args.sbi_port) {
        nextgcore_core::sockaddr::warn_if_loopback_listener("SBI", &addr, "--sbi-addr");
    }
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
                "{}://{}",
                if args.tls { "https" } else { "http" },
                nextgcore_sbi::uri_encode::uri_authority(addr, port)
            )),
            _ => None,
        };
        match n32_server::initiate_n32c_handshake(
            fqdn,
            api_root,
            local_api_root.as_deref(),
            peer_tls_opt,
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
    // RUST_LOG if set, else --log-level: the same for every NF (#691).
    let mut builder = nextgcore_core::log::nf_log_builder(&nextgcore_core::log::nf_log_level(
        args.log_level.as_deref(),
        Some(&args.config),
    ));

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
mod lab_flag_tests_1848 {
    use super::{n32_peer_client_tls, refuse_lab_flags_under_production};
    use crate::n32_server::N32TlsConfig;
    use nextgcore_sbi::security::{SbiProfile, TlsPaths};

    fn files() -> (std::path::PathBuf, TlsPaths) {
        let dir = std::env::temp_dir().join(format!(
            "seppd-1848-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = |n: &str| {
            let p = dir.join(n);
            std::fs::write(&p, "pem").unwrap();
            p.display().to_string()
        };
        let paths = TlsPaths {
            cert: file("server.crt"),
            key: file("server.key"),
            ca_cert: file("profile-ca.crt"),
            client_cert: Some(file("profile-client.crt")),
            client_key: Some(file("profile-client.key")),
        };
        (dir, paths)
    }

    /// #1870: with no `--peer-sepp` (a receiving SEPP), production still
    /// yields the SEPP's own client certificate and the profile CA, which the
    /// n32f-error report and the SBI-side forward are dialled with.
    #[test]
    fn production_peer_tls_applies_without_a_configured_peer_1870() {
        let (dir, paths) = files();
        let tls = n32_peer_client_tls(SbiProfile::Production, &[], &Default::default(), &paths)
            .expect("files exist")
            .expect("production always has peer TLS");
        assert_eq!(tls.client_cert, paths.client_cert);
        assert_eq!(tls.ca_cert.as_deref(), Some(paths.ca_cert.as_str()));
        assert!(
            n32_peer_client_tls(SbiProfile::Dev, &[], &Default::default(), &paths)
                .unwrap()
                .is_none()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// REVERT-VERIFIED: with the scheme check removed, an `http` peer is
    /// admitted under production and the first assertion fails.
    #[test]
    fn production_refuses_a_cleartext_peer_sepp_1848() {
        let (dir, paths) = files();
        let peers = vec!["sepp.peer.example=http://10.0.0.9:7777".to_string()];
        let err = n32_peer_client_tls(SbiProfile::Production, &peers, &Default::default(), &paths)
            .expect_err("no cleartext N32 under production");
        assert!(err.contains("is not https"), "{err}");
        assert!(
            n32_peer_client_tls(SbiProfile::Dev, &peers, &Default::default(), &paths)
                .unwrap()
                .is_none(),
            "dev dials as before"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// REVERT-VERIFIED: with the profile defaults not filled in, the client
    /// certificate is `None` and the first assertion fails; with the file
    /// check removed, a missing CA is admitted.
    #[test]
    fn production_dials_peers_with_its_own_certificate_and_a_configured_ca_1848() {
        let (dir, paths) = files();
        let peers = vec!["sepp.peer.example=https://10.0.0.9:443".to_string()];
        let tls = n32_peer_client_tls(SbiProfile::Production, &peers, &Default::default(), &paths)
            .unwrap()
            .expect("production dials with TLS whatever --tls says");
        assert_eq!(
            tls.client_cert, paths.client_cert,
            "the SEPP's own certificate"
        );
        assert_eq!(tls.client_key, paths.client_key);
        assert_eq!(
            tls.ca_cert.as_deref(),
            Some(paths.ca_cert.as_str()),
            "a configured CA, so never the public web roots"
        );

        // Explicit N32 material wins over the profile's.
        let n32_ca = dir.join("inter-plmn-ca.crt");
        std::fs::write(&n32_ca, "pem").unwrap();
        let given = N32TlsConfig {
            ca_cert: Some(n32_ca.display().to_string()),
            ..Default::default()
        };
        let tls = n32_peer_client_tls(SbiProfile::Production, &peers, &given, &paths)
            .unwrap()
            .unwrap();
        assert_eq!(tls.ca_cert, given.ca_cert);

        // A missing file is named.
        let absent = TlsPaths {
            ca_cert: dir.join("absent-ca.crt").display().to_string(),
            ..paths.clone()
        };
        let err = n32_peer_client_tls(SbiProfile::Production, &peers, &Default::default(), &absent)
            .expect_err("a missing CA is refused");
        assert!(err.contains("absent-ca.crt"), "{err}");
        let no_client = TlsPaths {
            client_cert: None,
            ..paths.clone()
        };
        let err = n32_peer_client_tls(
            SbiProfile::Production,
            &peers,
            &Default::default(),
            &no_client,
        )
        .expect_err("no client certificate is refused");
        assert!(err.contains("client certificate"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// REVERT-VERIFIED: with the production check short-circuited to `Ok(())`,
    /// both flags start under production and the first assertion fails.
    #[test]
    fn production_refuses_the_lab_flags_1848() {
        let err = refuse_lab_flags_under_production(SbiProfile::Production, true, false)
            .expect_err("no N32-c without mutual TLS under production");
        assert!(err.contains("--n32-allow-insecure-no-mtls"), "{err}");
        let err = refuse_lab_flags_under_production(SbiProfile::Production, false, true)
            .expect_err("no exporter-less N32-f keys under production");
        assert!(err.contains("--allow-insecure-no-tls"), "{err}");
        let err = refuse_lab_flags_under_production(SbiProfile::Production, true, true)
            .expect_err("both");
        assert!(
            err.contains("--n32-allow-insecure-no-mtls") && err.contains("--allow-insecure-no-tls"),
            "both are named: {err}"
        );
        refuse_lab_flags_under_production(SbiProfile::Production, false, false)
            .expect("production without the flags starts");
        refuse_lab_flags_under_production(SbiProfile::Dev, true, true)
            .expect("dev keeps the lab flags");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #2115: `--serving-plmn` takes exactly a 3-digit MCC and a 2-3 digit MNC.
    /// A short MCC used to be parsed as a number and padded (`1:01` served MCC
    /// 001); it is refused now, as is a 4-digit MNC or a non-digit.
    #[test]
    fn serving_plmn_takes_only_ts_23_003_digits_2115() {
        let p = parse_plmn("001:01").expect("2-digit MNC");
        assert_eq!((p.mcc, p.mnc, p.mnc_len), (1, 1, 2));
        let p = parse_plmn("999:070").expect("3-digit MNC");
        assert_eq!((p.mcc, p.mnc, p.mnc_len), (999, 70, 3));
        for (spec, want) in [
            ("1:01", "an MCC is 3 digits"),
            ("0011:01", "an MCC is 3 digits"),
            ("+01:01", "an MCC is 3 digits"),
            ("001:1", "an MNC is 2 or 3 digits"),
            ("001:0700", "an MNC is 2 or 3 digits"),
            ("001:7a", "an MNC is 2 or 3 digits"),
            ("00101", "want mcc:mnc"),
        ] {
            let err = parse_plmn(spec).expect_err(spec);
            assert!(err.contains(want), "{spec}: {err}");
        }
    }

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-seppd"]);
        assert_eq!(args.config, "/etc/nextgcore/sepp.yaml");
        assert_eq!(args.log_level, None);
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
        assert_eq!(args.log_level.as_deref(), Some("debug"));
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
