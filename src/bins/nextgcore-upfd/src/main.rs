//! NextGCore UPF (User Plane Function)
//!
//! Port of src/upf/ - User Plane Function for 5G/LTE core network
//!
//! The UPF is responsible for:
//! - User plane packet routing and forwarding
//! - QoS handling
//! - Traffic usage reporting
//! - Uplink/downlink traffic detection

// `dead_code` is `allow` workspace-wide (`Cargo.toml`, "Future-use code for
// Rel-17/18/20 features"), and #335 asked whether that is what hid two parallel
// models in `context.rs`. Measured: it is not. At `warn` the workspace emits 277
// warnings and upfd emits NONE of them, because the lint does not fire on a `pub`
// item — a `pub fn` added to `context.rs` warns not at all, while the same
// function written `pub(crate)` warns immediately. So the blind spot is
// visibility, not the lint level, and `pub mod` is what created it: it gives
// every item inside an effective visibility of `pub`, in a crate that has no
// external consumers to be `pub` FOR.
//
// `mod context` (crate-private) drops those items to an effective `pub(crate)`,
// which the lint does cover, and the local level re-enables it over the workspace
// `allow`. Together they are what would have caught #325 and #335. Verified by
// probe: a `pub(crate)` method with no caller now fails the build here; before
// this change it was silent.
//
// `deny` and not `warn`, because CI runs `cargo clippy --workspace` with no
// `-D warnings` ("Gate on errors only", `.github/workflows/ci.yml`) -- a `warn`
// here would print into a log nobody reads and gate nothing, which is the same
// mistake as the retry that hid a 20% flake (#308). At `deny` this crate is at
// zero today, so the gate costs nothing to adopt, and future-use code has to say
// what it is waiting for in an `#[allow(dead_code)]` reason rather than resting on
// a workspace-wide blanket -- which is #335's option 2, enforced instead of asked
// for. Scoped to upfd: the workspace has 277 such items, 121 of them in smfd's
// tracked #223, so a workspace sweep is a different change.
#![deny(dead_code)]

use nextgcore_upfd::*;

use anyhow::{Context, Result};
use clap::Parser;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use data_plane::DataPlane;
use event::UpfEvent;
use gtp_path::{upf_gtp_close, upf_gtp_final, upf_gtp_init, upf_gtp_open};
use pfcp_path::{pfcp_close, pfcp_open, PfcpPathContext, PfcpServer, PfcpSessionEvent};
use upf_sm::UpfSmContext;

/// NextGCore UPF - User Plane Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-upfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core User Plane Function", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/upf.yaml")]
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

    /// PFCP server address
    #[arg(long, default_value = "127.0.0.4")]
    pfcp_addr: String,

    /// PFCP server port
    #[arg(long, default_value = "8805")]
    pfcp_port: u16,

    /// CP functions (SMF / PGW-C) allowed to set up a PFCP association: IP addresses,
    /// CIDR prefixes or host names, comma-separated (e.g. `172.23.0.4`, `10.0.0.0/8`,
    /// `smf-pfcp.nextg-system.svc.cluster.local`; names are re-resolved every 10 s).
    /// Only the source IP is compared, never the port. A listed host may also replace
    /// or move a live association (CP failover). FAIL CLOSED: unset refuses every
    /// Association Setup; `0.0.0.0/0` / `::/0` admit any host (labs only). Security,
    /// TS 29.244 §6.2.6 / TS 33.501 §9.9. `UPF_PFCP_ALLOWED_PEERS` is read when this
    /// flag is not given.
    #[arg(long, default_value = "")]
    pfcp_allowed_peers: String,

    /// GTP-U address
    #[arg(long, default_value = "127.0.0.4")]
    gtpu_addr: String,

    /// GTP-U port
    #[arg(long, default_value = "2152")]
    gtpu_port: u16,

    /// IPv6 GTP-U address (N3 over IPv6, #918). Optional: without it, downlink to an
    /// IPv6 gNB is dropped and counted.
    #[arg(long)]
    gtpu_addr6: Option<std::net::Ipv6Addr>,

    /// TUN interface name
    #[arg(long, default_value = "ogstun")]
    tun_ifname: String,

    /// TUN interface IP address
    #[arg(long, default_value = "10.45.0.1")]
    tun_ip: String,

    /// TUN interface prefix length
    #[arg(long, default_value = "16")]
    tun_prefix: u8,

    /// Maximum number of sessions
    #[arg(long, default_value = "1024")]
    max_sessions: usize,

    /// Disable data plane (TUN device) - useful for control plane testing
    #[arg(long, default_value = "false")]
    no_dataplane: bool,

    /// NRF base URI (e.g. http://127.0.0.10:7777). G2-2: when set, the UPF
    /// registers a UPF NFProfile with the NRF and reports a real PFCP-session
    /// `/load` gauge on every heartbeat (TS 29.510 §5.2.2.3.2). Empty (the
    /// default) disables the SBI/NRF plane entirely — the UPF then behaves
    /// exactly as before (data-plane-only), so the matched-sim E2E default
    /// path is unchanged.
    #[arg(long, default_value = "")]
    nrf_uri: String,

    /// Per GTP-U path QoS monitoring (TS 29.244 §5.24.5, GPQM; #1389). Off by
    /// default: only when set does this UPF advertise GPQM and act on the GTP-U
    /// Path QoS Control Information an SMF provisions, timing Echo Request probes
    /// of the monitored N3 paths and reporting the delay (RTT/2) in Node Reports.
    /// `UPF_GTPU_PATH_QOS_MONITORING=true` is read when the flag is not given.
    #[arg(long, default_value = "false")]
    gtpu_path_qos_monitoring: bool,

    /// Interval between GTP-U path QoS probes, in milliseconds (with
    /// `--gtpu-path-qos-monitoring`).
    #[arg(long, default_value = "1000")]
    gtpu_path_qos_probe_interval_ms: u64,

    /// N6 delay measurement and reporting (TS 29.244 §5.33.8, UN6DM; #1389).
    /// Off by default: only when set does this UPF advertise UN6DM (the UP
    /// Function Features IE then grows to 10 octets) and STAMP, and act on the
    /// N6 Delay Measurement Control Information an SMF provisions, probing the
    /// measurement endpoints as an unauthenticated STAMP Session-Sender (RFC 8762)
    /// and reporting the one-way delay in Node Reports.
    /// `UPF_N6_DELAY_MEASUREMENT=true` is read when the flag is not given.
    #[arg(long, default_value = "false")]
    n6_delay_measurement: bool,

    /// Interval between STAMP probes to a healthy measurement endpoint, in
    /// milliseconds (with `--n6-delay-measurement`).
    #[arg(long, default_value = "1000")]
    n6_delay_probe_interval_ms: u64,

    /// Per QoS flow per UE QoS monitoring for packet delay (TS 29.244 §5.24.4,
    /// QFQM; #1389 part 3). Off by default: only when set does this UPF advertise
    /// QFQM and act on the QoS Monitoring per QoS flow Control Information of an
    /// SRR, marking downlink G-PDUs (or dummy G-PDUs) of the monitored flows with
    /// QMP and a time stamp, measuring the delay from the NG-RAN's answer and
    /// reporting it in Session Reports. `UPF_QOS_FLOW_MONITORING=true` is read
    /// when the flag is not given.
    #[arg(long, default_value = "false")]
    qos_flow_monitoring: bool,

    /// Interval between QoS Monitoring Packets on a monitored QoS flow, in
    /// milliseconds (with `--qos-flow-monitoring`).
    #[arg(long, default_value = "1000")]
    qos_flow_monitoring_probe_interval_ms: u64,

    /// The NG-RAN and this UPF are time synchronised (with
    /// `--qos-flow-monitoring`): the one-way N3 delays are then T2-T1 and T4-T3.
    /// Without it they are taken as equal, (T2-T1+T4-T3)/2 (TS 23.501 §5.33.3.2).
    /// `UPF_QOS_FLOW_MONITORING_CLOCK_SYNCED=true` is read when not given.
    #[arg(long, default_value = "false")]
    qos_flow_monitoring_clock_synced: bool,

    /// DN prefixes NOT source-NATed (#1455): comma-separated IPv4 prefixes or
    /// addresses (e.g. `10.60.0.0/24`). Traffic from the UE subnet to them leaves
    /// with the UE's own address (ACCEPTs in the `UPF-NAT-EXCLUDE` nat chain,
    /// jumped to from the head of POSTROUTING, so they also win over a MASQUERADE
    /// installed before the UPF), so a DN server can identify the UE by it. The DN
    /// must route the UE subnet back via the UPF. Unset (the default): everything
    /// is masqueraded, as before. A bad entry, or a rule that cannot be installed,
    /// refuses to start.
    /// `UPF_NAT_EXCLUDE` is read when the flag is not given.
    #[arg(long, default_value = "")]
    nat_exclude: String,

    /// Per-session byte counters on `/metrics` (#1455): `off` (the default; the
    /// endpoint is unchanged), `seid` (`upf_session_{ul,dl}_bytes_total{seid}`) or
    /// `seid-ue-ip` (also a `ue_ipv4` label, which puts UE addresses on the
    /// unauthenticated `/metrics`). Never a SUPI. One series per live session,
    /// unbounded: opt-in for small deployments.
    /// `UPF_SESSION_METRICS` is read when the flag is not given.
    #[arg(long)]
    session_metrics: Option<String>,
}

/// The PFCP peer allowlist (#968): `--pfcp-allowed-peers`, else `UPF_PFCP_ALLOWED_PEERS`.
/// A bad entry is an error, so the UPF refuses to start rather than run open.
fn allowed_peers_setting(
    flag: &str,
    env: Option<String>,
) -> Result<nextgcore_pfcp::peer_policy::PeerAllowlist, String> {
    let list = if flag.trim().is_empty() {
        env.unwrap_or_default()
    } else {
        flag.to_string()
    };
    nextgcore_pfcp::peer_policy::PeerAllowlist::parse(&list)
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// The live runtime state the Prometheus render reads (#380).
///
/// Handles rather than values: both are owned by the `PfcpServer`, and a copy here would
/// be the second store #325 rejected. Installed once, after the server exists.
struct MetricsSources {
    associated: Arc<AtomicBool>,
    sessions: Arc<std::sync::atomic::AtomicUsize>,
    /// The forwarding data plane whose `stats` are rendered as the
    /// `upf_dataplane_*_total` counters (#581). The same `Arc` the forwarding task runs.
    data_plane: Arc<DataPlane>,
}

static METRICS_SOURCES: std::sync::OnceLock<MetricsSources> = std::sync::OnceLock::new();

/// Where the Prometheus endpoint listens (`UPF_METRICS_PORT`, default 9090 — the port
/// `sgwud` uses and the port `configs/observability/prometheus.yml` already scrapes).
fn metrics_addr() -> SocketAddr {
    let port: u16 = std::env::var("UPF_METRICS_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9090);
    // Loopback unless NEXTGCORE_METRICS_BIND says otherwise (#837).
    nextgcore_metrics::nes_energy::metrics_bind_addr(port)
}

/// Render this UPF/PGW-U's runtime state in Prometheus text format (#380).
///
/// `upf_pfcp_associations` is the user-plane counterpart of `sgwu_pfcp_associations`, and
/// exists for the same reason: TS 29.244 §6.2.6.2 forbids session signalling without an
/// association, so a UPF whose N4/Sxb association never came up cannot carry a single
/// session — and `kill -0 1` reports it healthy anyway.
///
/// 0 or 1, not a count: this UPF holds at most ONE association
/// (`PfcpServer::association` is an `Option`, not a map), which is the TS 29.244 §6.2.6
/// one-association-per-CP/UP-function-pair model. Rendered as a gauge rather than under a
/// boolean name so the assertion reads identically to the SGW-U's.
fn render_metrics() -> String {
    let (associations, sessions) = match METRICS_SOURCES.get() {
        Some(src) => (
            u8::from(src.associated.load(Ordering::Relaxed)),
            src.sessions.load(Ordering::Relaxed),
        ),
        // Before the PFCP server exists there is genuinely no association and no
        // session; reporting zero is accurate rather than a placeholder.
        None => (0, 0),
    };
    // #581: the user-plane counters. Before install there is no data plane and no
    // packet has been forwarded, so a zeroed set is the accurate rendering.
    let dataplane = match METRICS_SOURCES.get() {
        Some(src) => src.data_plane.stats.render_prometheus(),
        None => data_plane::DataPlaneStats::default().render_prometheus(),
    };
    // #1455: the per-session families, only when `--session-metrics` asks for them.
    let per_session = match (session_metrics::mode(), METRICS_SOURCES.get()) {
        (session_metrics::Mode::Off, _) | (_, None) => String::new(),
        (mode, Some(src)) => {
            session_metrics::render(mode, &src.data_plane.sessions.sessions_snapshot())
        }
    };
    let unauthorized = pfcp_path::PFCP_UNAUTHORIZED.load(Ordering::Relaxed);
    // #1368: the families every NF serves first (NRF client, process; the UPF serves
    // no SBI, so its SBI families stay empty), then the UPF's own.
    let mut body = nextgcore_metrics::nf::render_common(&nextgcore_metrics::nf::NfIdentity {
        nf: "upf",
        version: env!("CARGO_PKG_VERSION"),
        nrf_client: true,
    });
    body.push_str(&format!(
        "# HELP upf_pfcp_associations Associated CP peers on N4/Sxb (0 or 1: TS 29.244 6.2.6 scopes an association to one CP/UP function pair)\n\
         # TYPE upf_pfcp_associations gauge\n\
         upf_pfcp_associations {associations}\n\
         # HELP upf_pfcp_sessions Number of PFCP sessions held on N4/Sxb\n\
         # TYPE upf_pfcp_sessions gauge\n\
         upf_pfcp_sessions {sessions}\n\
         # HELP upf_pfcp_unauthorized_messages_total PFCP messages refused for not coming from the associated CP function\n\
         # TYPE upf_pfcp_unauthorized_messages_total counter\n\
         upf_pfcp_unauthorized_messages_total {unauthorized}\n\
         # HELP upf_up 1 when the UPF runtime is serving\n\
         # TYPE upf_up gauge\n\
         upf_up 1\n"
    ));
    body.push_str(&dataplane);
    body.push_str(&per_session);
    body
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    init_logging(&args)?;
    // #1004 review: an unset clock makes a wrong PFCP Recovery Time Stamp.
    nextgcore_pfcp::recovery_time::check_local_clock().map_err(|e| anyhow::anyhow!(e))?;
    // G32/G43: Initialize OpenTelemetry tracing (Jaeger/OTLP exporter)
    let _otel = nextgcore_metrics::otel::init_otel(
        nextgcore_metrics::otel::OtelConfig::new(env!("CARGO_PKG_NAME")).with_endpoint(
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://jaeger:4317".to_string()),
        ),
    )
    .ok();

    log::info!("NextGCore UPF v{} starting...", env!("CARGO_PKG_VERSION"));

    // Issue: `--kill` was advertised as "Kill running instance" and did
    // NOTHING -- it logged an intention and returned success, so the process
    // exited 0 while the instance kept serving. Fail loudly instead.
    if args.kill {
        return Err(nextgcore_core::signal::kill_unsupported().into());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize UPF context
    upf_context_init(args.max_sessions);
    log::info!(
        "UPF context initialized (max_sessions={})",
        args.max_sessions
    );

    // G2-2: opt-in NRF registration + heartbeat `/load` PATCH
    // (TS 29.510 §5.2.2.3.2). This is OFF by default: when `--nrf-uri` is
    // empty the UPF never touches the SBI/NRF plane, so the default
    // data-plane path (and the matched-sim E2E) is byte-identical to before.
    // When an NRF is configured the UPF registers a UPF NFProfile and reports
    // a real PFCP-session occupancy gauge on every heartbeat. All failures
    // are log-only and never affect UPF packet forwarding.
    if !args.nrf_uri.trim().is_empty() {
        let nf_instance_id =
            nextgcore_sbi::nf_instance_id::nf_instance_id(nextgcore_sbi::types::NfType::Upf)
                .to_string();
        let sbi_ctx = nextgcore_sbi::context::global_context();
        sbi_ctx.set_nrf_uri(&args.nrf_uri).await;
        // #1482: a failed attempt is retried in the background (never blocking
        // the data plane), and the heartbeat starts after the one that succeeds.
        let (pfcp, gtpu) = (args.pfcp_addr.clone(), args.gtpu_addr.clone());
        nextgcore_sbi::heartbeat::register_or_retry(
            "UPF",
            Default::default(),
            move || {
                let (id, pfcp, gtpu) = (nf_instance_id.clone(), pfcp.clone(), gtpu.clone());
                async move {
                    register_upf_with_nrf(&id, &pfcp, &gtpu)
                        .await
                        .map(|()| Some(id))
                }
            },
            |nf_instance_id| {
                // G2-2: PATCH a real NFProfile "/load" gauge to NRF each
                // heartbeat — PFCP-session occupancy, recomputed each tick.
                log::info!("UPF NRF heartbeat started (instance: {nf_instance_id})");
                nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(
                    nf_instance_id,
                    5,
                    || upf_self().get_load(),
                );
            },
        )
        .await;
    } else {
        log::debug!("No NRF URI configured (--nrf-uri empty); UPF runs data-plane-only");
    }

    // Initialize GTP-U path
    upf_gtp_init().map_err(|e| anyhow::anyhow!("Failed to initialize GTP path: {e}"))?;
    log::info!("GTP-U path initialized");

    // Initialize UPF state machine
    let mut upf_sm = UpfSmContext::new();
    upf_sm.init();
    log::info!("UPF state machine initialized");

    // Initialize PFCP path context
    let mut pfcp_ctx = PfcpPathContext::new();

    // Parse configuration (if file exists)
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
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

    // Parse PFCP and GTP-U addresses
    let pfcp_addr: SocketAddr = format!("{}:{}", args.pfcp_addr, args.pfcp_port)
        .parse()
        .context("Invalid PFCP address")?;
    let gtpu_addr: SocketAddr = format!("{}:{}", args.gtpu_addr, args.gtpu_port)
        .parse()
        .context("Invalid GTP-U address")?;
    let tun_ip: Ipv4Addr = args.tun_ip.parse().context("Invalid TUN IP address")?;

    // Initialize legacy PFCP path context (for compatibility)
    pfcp_open(&mut pfcp_ctx, pfcp_addr)
        .map_err(|e| anyhow::anyhow!("Failed to open PFCP path: {e}"))?;
    log::info!("PFCP path context initialized on {pfcp_addr}");

    // Open GTP-U path (control plane)
    upf_gtp_open().map_err(|e| anyhow::anyhow!("Failed to open GTP path: {e}"))?;
    log::info!("GTP-U path opened on {gtpu_addr}");

    // Initialize data plane (optional based on --no-dataplane flag)
    let mut data_plane = DataPlane::new(shutdown.clone());
    let data_plane_enabled = !args.no_dataplane;
    // #1455: both refuse to start on a bad value rather than run with less than asked.
    data_plane.nat_exclude =
        nat_exclude::setting(&args.nat_exclude, std::env::var("UPF_NAT_EXCLUDE").ok())
            .map_err(|e| anyhow::anyhow!("--nat-exclude: {e}"))?;
    session_metrics::set_mode(
        session_metrics::Mode::setting(
            args.session_metrics.as_deref(),
            std::env::var("UPF_SESSION_METRICS").ok(),
        )
        .map_err(|e| anyhow::anyhow!(e))?,
    );

    if data_plane_enabled {
        // Initialize data plane (TUN + GTP-U socket)
        data_plane
            .init(&args.tun_ifname, tun_ip, args.tun_prefix, gtpu_addr)
            .await
            .context("Failed to initialize data plane")?;
        if let Some(addr6) = args.gtpu_addr6 {
            data_plane
                .bind_gtpu6(SocketAddr::new(std::net::IpAddr::V6(addr6), args.gtpu_port))
                .await
                .context("Failed to bind the IPv6 GTP-U socket")?;
        }
    } else {
        log::warn!("Data plane disabled (--no-dataplane flag set)");
        log::warn!("UPF running in control plane only mode - no user traffic forwarding");
    }

    // Transition to operational state
    let entry_event = UpfEvent::entry();
    upf_sm.dispatch(&entry_event);

    log::info!("NextGCore UPF ready");

    // Create PFCP session event channel
    let (pfcp_session_tx, pfcp_session_rx) = tokio::sync::mpsc::channel::<PfcpSessionEvent>(100);

    // Create async PFCP server
    let pfcp_server = PfcpServer::new(pfcp_addr, shutdown.clone(), pfcp_session_tx)
        .await
        .context("Failed to create PFCP server")?;
    // #985: a local F-TEID may carry the IPv6 N3 address only once the IPv6 GTP-U
    // socket is bound, so uplink from an IPv6 gNB has somewhere to arrive.
    pfcp_server.set_n3_ipv6(*data_plane.local_gtpu_addr6.read().unwrap());
    let allowed_peers = allowed_peers_setting(
        &args.pfcp_allowed_peers,
        std::env::var("UPF_PFCP_ALLOWED_PEERS").ok(),
    )
    .map_err(|e| anyhow::anyhow!("Invalid --pfcp-allowed-peers / UPF_PFCP_ALLOWED_PEERS: {e}"))?;
    if allowed_peers.is_configured() {
        log::info!("PFCP associations accepted only from: {allowed_peers}");
    } else {
        log::error!(
            "--pfcp-allowed-peers / UPF_PFCP_ALLOWED_PEERS is not set: EVERY PFCP \
             Association Setup will be refused, so no SMF can use this UPF. Set it to the \
             SMF/PGW-C address(es), CIDR or host name (0.0.0.0/0 admits any host)."
        );
    }
    // Host-name entries are re-resolved off the receive path (#968).
    allowed_peers.spawn_host_refresh(std::time::Duration::from_secs(10));
    pfcp_server.set_allowed_peers(allowed_peers);
    let path_qos_monitoring = args.gtpu_path_qos_monitoring
        || std::env::var("UPF_GTPU_PATH_QOS_MONITORING").is_ok_and(|v| v == "true" || v == "1");
    pfcp_server.set_path_qos_monitoring(path_qos_monitoring);
    let n6_delay_measurement = args.n6_delay_measurement
        || std::env::var("UPF_N6_DELAY_MEASUREMENT").is_ok_and(|v| v == "true" || v == "1");
    pfcp_server.set_n6_delay_measurement(n6_delay_measurement);
    let qos_flow_monitoring = args.qos_flow_monitoring
        || std::env::var("UPF_QOS_FLOW_MONITORING").is_ok_and(|v| v == "true" || v == "1");
    pfcp_server.set_qos_flow_monitoring(qos_flow_monitoring);
    let qos_flow_clock_synced = args.qos_flow_monitoring_clock_synced
        || std::env::var("UPF_QOS_FLOW_MONITORING_CLOCK_SYNCED")
            .is_ok_and(|v| v == "true" || v == "1");
    let pfcp_server = Arc::new(pfcp_server);

    // #325: point the NFProfile/LCI load gauge at the N4 session census. It used to
    // read `UpfContext::sess_list`, which nothing outside `mod tests` ever wrote, so
    // this UPF advertised `load: 0` to the NRF and to the SMF however many sessions
    // it was carrying. The handle is taken from the server rather than the count
    // being pushed into the context, so there is one store and one reader of it.
    //
    // The NRF heartbeat worker was spawned above with a closure that calls
    // `get_load()` per tick, so it picks this up on its next tick; the load reported
    // in the registration itself is 0, which is correct at start-up.
    upf_self().set_session_gauge(pfcp_server.session_count_handle());

    // #380: the Prometheus endpoint. Its sources (installed below, once the data plane
    // is shared) are the SAME handles the load gauge uses, so the metric and the NRF
    // `/load` report can never disagree about how many sessions this UPF holds.
    // #2056: a busy port is fatal at start-up under the production profile, before the
    // UPF forwards anything; under dev it runs on without metrics, as it always did.
    let upf_metrics_addr = metrics_addr();
    match nextgcore_metrics::nes_energy::serve_metrics(upf_metrics_addr, Arc::new(render_metrics))
        .await
    {
        Ok((bound, _handle)) => log::info!("UPF metrics endpoint on http://{bound}/metrics"),
        Err(e) => {
            nextgcore_metrics::nf::listener_bind_failed("UPF", "metrics", upf_metrics_addr, &e)
        }
    }

    // Run data plane (if enabled)
    let data_plane = Arc::new(data_plane);

    // Installed once the data plane is shared (#581), so `/metrics` reads the counters
    // of the very `DataPlane` the forwarding task below increments. A scrape before this
    // point renders honest zeros.
    let _ = METRICS_SOURCES.set(MetricsSources {
        associated: pfcp_server.associated_handle(),
        sessions: pfcp_server.session_count_handle(),
        data_plane: data_plane.clone(),
    });

    // #2208: the UPF's tasks, started by the library so an in-process test runs the
    // same ones.
    let runtime = runtime::start(
        pfcp_server.clone(),
        data_plane.clone(),
        pfcp_session_rx,
        shutdown.clone(),
        runtime::RuntimeOptions {
            n6: if data_plane_enabled {
                runtime::N6::Tun
            } else {
                runtime::N6::Disabled
            },
            path_qos_probe_interval: path_qos_monitoring.then(|| {
                std::time::Duration::from_millis(args.gtpu_path_qos_probe_interval_ms.max(100))
            }),
            qos_flow_monitoring: qos_flow_monitoring.then(|| {
                (
                    std::time::Duration::from_millis(
                        args.qos_flow_monitoring_probe_interval_ms.max(100),
                    ),
                    qos_flow_clock_synced,
                )
            }),
            n6_delay_probe_interval: n6_delay_measurement.then(|| {
                std::time::Duration::from_millis(args.n6_delay_probe_interval_ms.max(100))
            }),
        },
    );

    run_async_event_loop(&mut upf_sm, &mut pfcp_ctx, shutdown.clone()).await?;

    // Stop all tasks, the data plane among them
    runtime.abort();

    // Graceful shutdown
    log::info!("Shutting down...");

    // #235: NFDeregister (TS 29.510 5.2.2.2.3) BEFORE the listener goes
    // away, so the NRF stops handing this profile to consumers instead of
    // waiting out its supervision timer. Stopping the server first would
    // open the bad window: not serving, but still advertised.
    nextgcore_sbi::heartbeat::deregister_self().await;

    // Close GTP-U path
    upf_gtp_close().map_err(|e| anyhow::anyhow!("Failed to close GTP path: {e}"))?;
    log::info!("GTP-U path closed");

    // Close PFCP path
    pfcp_close(&mut pfcp_ctx);
    log::info!("PFCP path closed");

    // Finalize GTP-U
    upf_gtp_final().map_err(|e| anyhow::anyhow!("Failed to finalize GTP path: {e}"))?;
    log::info!("GTP-U path finalized");

    // Cleanup state machine
    upf_sm.fini();
    log::info!("UPF state machine finalized");

    // Cleanup context
    upf_context_final();
    log::info!("UPF context finalized");

    log::info!("NextGCore UPF stopped");
    Ok(())
}

// ---------------------------------------------------------------------------
// G2-2: NRF registration + heartbeat /load PATCH (opt-in)
// ---------------------------------------------------------------------------

/// The N3 InterfaceUpfInfoItem for `gtpu_addr`, its address by type (#1324).
fn n3_interface(gtpu_addr: &str) -> serde_json::Value {
    let mut item = nextgcore_sbi::nf_addressing::interface_upf_endpoint(gtpu_addr);
    item.insert("interfaceType".into(), "N3".into());
    serde_json::Value::Object(item)
}

/// Build the UPF `NFProfile` sent to the NRF on registration
/// (TS 29.510 §6.1.6.2.2). The UPF exposes no SBI service, so `nfServices` is
/// omitted — consumers (SMF) reach it over N4/PFCP. `upfInfo`
/// (TS 29.510 §6.1.6.2.10) advertises the N3 (GTP-U) interface endpoint. The
/// `load` field carries the initial PFCP-session occupancy gauge; it is
/// refreshed by the heartbeat PATCH (`build_load_patch`, `/load` 0..=100).
fn build_upf_nf_profile(
    nf_instance_id: &str,
    pfcp_addr: &str,
    gtpu_addr: &str,
    load: u8,
) -> serde_json::Value {
    nextgcore_sbi::nf_addressing::classify_profile_host(
        serde_json::json!({
            "nfInstanceId": nf_instance_id,
            "nfType": "UPF",
            "nfStatus": "REGISTERED",
            "ipv4Addresses": [pfcp_addr],
            "load": load,
            "upfInfo": {
                "sNssaiUpfInfoList": [{
                    "sNssai": { "sst": 1 },
                    "dnnUpfInfoList": [{ "dnn": "internet" }]
                }],
                // #1324: the N3 address by type (TS 29.510 §6.1.6.2.12).
                "interfaceUpfInfoList": [n3_interface(gtpu_addr)]
            },
            "heartBeatTimer": 10
        }),
        pfcp_addr,
    )
}

/// Register the UPF with the NRF via `PUT /nnrf-nfm/v1/nf-instances/{id}`
/// (TS 29.510 §5.2.2.2). Fail-closed only in the sense that a non-2xx status
/// is reported as an error to the caller, which logs it and continues — UPF
/// packet forwarding is never blocked by NRF availability.
async fn register_upf_with_nrf(
    nf_instance_id: &str,
    pfcp_addr: &str,
    gtpu_addr: &str,
) -> Result<(), String> {
    let sbi_ctx = nextgcore_sbi::context::global_context();

    let nrf_uri = match sbi_ctx.get_nrf_uri().await {
        Some(uri) => uri,
        None => {
            log::debug!("No NRF URI configured, skipping NRF registration");
            return Ok(());
        }
    };

    log::info!("Registering UPF with NRF at {nrf_uri}");
    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_profile =
        build_upf_nf_profile(nf_instance_id, pfcp_addr, gtpu_addr, upf_self().get_load());

    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    log::debug!("NRF registration: PUT {path}");

    let response = client
        .put_json(&path, &nf_profile)
        .await
        .map_err(|e| format!("NRF registration request failed: {e}"))?;

    match response.status {
        200 | 201 => {
            log::info!("UPF registered with NRF successfully (id={nf_instance_id})");
            // #434: what a 404 heartbeat re-registers if the NRF loses us.
            nextgcore_sbi::heartbeat::set_registered_profile(&nf_profile);
            Ok(())
        }
        s => Err(format!("NRF registration returned status {s}")),
    }
}

/// Parse host and port from a URI string (e.g., "http://127.0.0.10:7777").
fn parse_host_port(uri: &str) -> Option<(String, u16)> {
    let without_scheme = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    let (host_port, _path) = without_scheme
        .split_once('/')
        .unwrap_or((without_scheme, ""));
    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        let port: u16 = port_str.parse().ok()?;
        Some((host.to_string(), port))
    } else {
        let default_port = if uri.starts_with("https://") { 443 } else { 80 };
        Some((host_port.to_string(), default_port))
    }
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

/// Main async event loop using tokio
async fn run_async_event_loop(
    upf_sm: &mut UpfSmContext,
    pfcp_ctx: &mut PfcpPathContext,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    log::debug!("Entering async event loop");

    // Heartbeat tracking
    let mut heartbeat_interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
    let mut stats_interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

    loop {
        tokio::select! {
            // Periodic heartbeat and transaction maintenance
            _ = heartbeat_interval.tick() => {
                if shutdown.load(Ordering::SeqCst) || SHUTDOWN.load(Ordering::SeqCst) {
                    break;
                }

                // Check if state machine is still operational
                if !upf_sm.is_operational() && !upf_sm.is_final() {
                    let entry_event = UpfEvent::entry();
                    upf_sm.dispatch(&entry_event);
                }

                // Peer-failure detection lives in PfcpServer::close_heartbeat_round
                // (TS 23.007 Section 19A), which counts consecutive UNANSWERED
                // heartbeat rounds and declares the peer down.
                //
                // The sweep that used to sit here iterated `pfcp_ctx.peer_nodes`,
                // a map nothing in the crate ever inserted into, and guarded on
                // `last_heartbeat_check.elapsed() > heartbeat_timeout` -- elapsed
                // time, not missed responses -- so even with the map populated it
                // would have signalled failure against a healthy peer. Both
                // defects are why it is gone rather than repaired: the state it
                // needed already exists on the server, next to the socket that
                // sends and receives the heartbeats.
                //
                // `peer_nodes` itself is now deleted too (#81): leaving an
                // unpopulated per-peer registry behind reads as a peer table the
                // UPF maintains, and the next person to add heartbeat state would
                // reasonably put it there -- back into the map with no readers.

                // Process pending PFCP transactions (check for timeouts)
                let stale_seqs: Vec<u32> = pfcp_ctx
                    .transactions
                    .iter()
                    .filter(|(_, xact)| xact.state == pfcp_path::XactState::Pending)
                    .map(|(seq, _)| *seq)
                    .collect();
                for seq in stale_seqs {
                    if let Some(xact) = pfcp_ctx.find_xact(seq) {
                        if xact.state == pfcp_path::XactState::Pending {
                            log::debug!("Cleaning up stale PFCP transaction seq={seq}");
                            xact.state = pfcp_path::XactState::Timeout;
                        }
                    }
                }
            }

            // Periodic stats reporting and URR threshold checks
            _ = stats_interval.tick() => {
                if shutdown.load(Ordering::SeqCst) || SHUTDOWN.load(Ordering::SeqCst) {
                    break;
                }
                update_session_stats().await;
            }
        }
    }

    log::debug!("Exiting async event loop");
    Ok(())
}

/// Update session statistics, check URR thresholds, and trigger usage reports
async fn update_session_stats() {
    let ctx = upf_self();
    let sess_count = ctx.sess_count();
    if sess_count > 0 {
        log::debug!("Active sessions: {sess_count}");
    }

    // Note: URR threshold reporting is handled in the data plane via
    // DataPlane::collect_urr_reports(). When the PFCP session event handler
    // detects exceeded URR thresholds, it generates Session Report Requests
    // via pfcp_path::send_session_report_request() to notify the SMF.
    // The data plane's 30-second stats interval provides periodic measurement
    // period checks as well.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-upfd"]);
        assert_eq!(args.config, "/etc/nextgcore/upf.yaml");
        assert_eq!(args.log_level, None);
        assert_eq!(args.pfcp_addr, "127.0.0.4");
        assert_eq!(args.pfcp_port, 8805);
        assert_eq!(args.gtpu_addr, "127.0.0.4");
        assert_eq!(args.gtpu_port, 2152);
        assert_eq!(args.tun_ifname, "ogstun");
        assert_eq!(args.max_sessions, 1024);
        assert!(!args.kill);
        assert!(!args.no_color);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-upfd",
            "-c",
            "/custom/upf.yaml",
            "-e",
            "debug",
            "--pfcp-addr",
            "10.0.0.1",
            "--pfcp-port",
            "8806",
            "--gtpu-addr",
            "10.0.0.2",
            "--gtpu-port",
            "2153",
            "--tun-ifname",
            "mytun",
            "--max-sessions",
            "2048",
        ]);
        assert_eq!(args.config, "/custom/upf.yaml");
        assert_eq!(args.log_level.as_deref(), Some("debug"));
        assert_eq!(args.pfcp_addr, "10.0.0.1");
        assert_eq!(args.pfcp_port, 8806);
        assert_eq!(args.gtpu_addr, "10.0.0.2");
        assert_eq!(args.gtpu_port, 2153);
        assert_eq!(args.tun_ifname, "mytun");
        assert_eq!(args.max_sessions, 2048);
    }

    #[test]
    fn the_pfcp_allowed_peers_come_from_the_flag_then_the_environment() {
        let args = Args::parse_from([
            "nextgcore-upfd",
            "--pfcp-allowed-peers",
            "172.23.0.4,10.0.0.0/8",
        ]);
        let a = allowed_peers_setting(&args.pfcp_allowed_peers, Some("192.0.2.1".into())).unwrap();
        assert!(a.permits("10.1.2.3".parse().unwrap()));
        assert!(!a.permits("192.0.2.1".parse().unwrap()), "the flag wins");

        let args = Args::parse_from(["nextgcore-upfd"]);
        let a = allowed_peers_setting(&args.pfcp_allowed_peers, Some("192.0.2.1".into())).unwrap();
        assert!(a.permits("192.0.2.1".parse().unwrap()));
        assert!(!a.permits("192.0.2.2".parse().unwrap()));
        assert!(!allowed_peers_setting("", None).unwrap().is_configured());
        assert!(allowed_peers_setting("10.0.0.0/33", None).is_err());
        assert_eq!(
            allowed_peers_setting("smf.example", None).unwrap().hosts(),
            ["smf.example"],
            "a host name is an entry"
        );
    }

    #[test]
    fn test_args_kill_flag() {
        let args = Args::parse_from(["nextgcore-upfd", "-k"]);
        assert!(args.kill);
    }

    #[test]
    fn test_args_no_color() {
        let args = Args::parse_from(["nextgcore-upfd", "-m"]);
        assert!(args.no_color);
    }

    #[test]
    fn test_args_log_file() {
        let args = Args::parse_from(["nextgcore-upfd", "-l", "/var/log/upf.log"]);
        assert_eq!(args.log_file, Some("/var/log/upf.log".to_string()));
    }

    // ------------------------------------------------------------------
    // #380: the Prometheus endpoint the EPC readiness gate polls
    // ------------------------------------------------------------------

    /// The render emits the families the gate and the healthcheck grep for, in Prometheus
    /// text format, and reports the association state it is HANDED rather than a constant.
    ///
    /// Asserted on the rendered body rather than on the listener binding, because a body
    /// that reports nothing is the failure worth catching. The 0-and-1 pair matters: a
    /// render that hard-coded `upf_pfcp_associations 1` would satisfy a
    /// contains-the-metric-name test and make the gate meaningless.
    #[test]
    fn the_metrics_render_reports_the_association_and_session_state() {
        // `METRICS_SOURCES` is a process-global `OnceLock`, so this asserts the
        // pre-install rendering (honest zeros) and then the rendering against installed
        // handles, in that order, inside ONE test — a sibling test racing the install
        // would see whichever half ran first.
        let body = render_metrics();
        for expected in [
            "# TYPE upf_pfcp_associations gauge",
            "upf_pfcp_associations 0",
            // #1368: the shared families.
            "# TYPE nextgcore_nrf_registered gauge",
            "# TYPE nextgcore_uptime_seconds gauge",
            "nextgcore_build_info{nf=\"upf\"",
            "upf_pfcp_sessions 0",
            "upf_up 1",
            "# TYPE upf_dataplane_ul_packets_total counter",
            "upf_dataplane_ul_packets_total 0",
            "upf_dataplane_dl_packets_total 0",
        ] {
            assert!(
                body.contains(expected),
                "missing {expected} before install, in:\n{body}"
            );
        }

        let associated = Arc::new(AtomicBool::new(true));
        let sessions = Arc::new(std::sync::atomic::AtomicUsize::new(7));
        // #581: the data-plane counters come from the installed `DataPlane`, not a copy.
        let dp = Arc::new(DataPlane::new(Arc::new(AtomicBool::new(false))));
        dp.stats.ul_packets.store(20, Ordering::Relaxed);
        dp.stats.ul_bytes.store(1680, Ordering::Relaxed);
        dp.stats.dl_packets.store(19, Ordering::Relaxed);
        let _ = METRICS_SOURCES.set(MetricsSources {
            associated: associated.clone(),
            sessions,
            data_plane: dp.clone(),
        });
        let body = render_metrics();
        assert!(
            body.contains("upf_pfcp_associations 1"),
            "an installed association must be reported, in:\n{body}"
        );
        assert!(
            body.contains("upf_pfcp_sessions 7"),
            "the live session count must be reported, in:\n{body}"
        );

        // And it must come back down: a render that ignored the handle would pass the
        // assertion above and still report a dead association as up forever.
        associated.store(false, Ordering::Relaxed);
        assert!(
            render_metrics().contains("upf_pfcp_associations 0"),
            "the render must re-read the handle on every scrape"
        );

        let body = render_metrics();
        for expected in [
            "upf_dataplane_ul_packets_total 20",
            "upf_dataplane_ul_bytes_total 1680",
            "upf_dataplane_dl_packets_total 19",
        ] {
            assert!(
                body.contains(expected),
                "missing {expected} after install, in:\n{body}"
            );
        }
        // Live, like the association: the next forwarded packet is in the next scrape.
        dp.stats.dl_packets.fetch_add(1, Ordering::Relaxed);
        assert!(
            render_metrics().contains("upf_dataplane_dl_packets_total 20"),
            "the data-plane counters must be re-read on every scrape"
        );

        // #1455: the per-session families. In this test because they read the same
        // once-installed `METRICS_SOURCES`.
        let _mode = session_metrics::MODE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let session = dp
            .sessions
            .add_session(data_plane::DataPlaneSession::new_empty(
                0x1455,
                1,
                Some(std::net::Ipv4Addr::new(10, 45, 0, 55)),
                0x1455,
                0x2455,
                SocketAddr::from(([127, 0, 0, 1], 2152)),
                Some(1),
                Some(9),
            ));
        session.ul_bytes.store(4200, Ordering::Relaxed);
        session_metrics::set_mode(session_metrics::Mode::Off);
        let off = render_metrics();
        assert!(
            !off.contains("upf_session_"),
            "off (the default): no per-session family at all, in:\n{off}"
        );
        session_metrics::set_mode(session_metrics::Mode::Seid);
        let on = render_metrics();
        assert!(
            on.contains("upf_session_ul_bytes_total{seid=\"0x1455\"} 4200\n"),
            "in:\n{on}"
        );
        // Appended after every family the endpoint already had (the process gauges
        // move between scrapes, so the bodies are compared by position, not bytes).
        assert!(
            on.find("# HELP upf_session_ul_bytes_total")
                > on.find("upf_dataplane_ul_packets_total"),
            "the families come last, in:\n{on}"
        );
        assert!(!on.contains("10.45.0.55"), "seid mode carries no address");
        session_metrics::set_mode(session_metrics::Mode::SeidUeIp);
        assert!(render_metrics()
            .contains("upf_session_ul_bytes_total{seid=\"0x1455\",ue_ipv4=\"10.45.0.55\"} 4200\n"));
        // A deleted session's series is gone from the next scrape (the render reads
        // the live table; PFCP Session Deletion and peer failure both remove from it).
        session_metrics::set_mode(session_metrics::Mode::Seid);
        assert!(dp.sessions.remove_session_by_seid(0x1455));
        let after = render_metrics();
        assert!(
            !after.contains("seid=\"0x1455\""),
            "the deleted session's series must go, in:\n{after}"
        );
        session_metrics::set_mode(session_metrics::Mode::Off);
    }

    #[test]
    fn the_metrics_port_is_9090_unless_overridden() {
        // The port `sgwud` uses, the port `prometheus.yml` scrapes, and the port the
        // healthcheck curls. A default that drifted from those would leave the gate
        // polling a closed socket.
        assert_eq!(metrics_addr().port(), 9090);
        // #837: unauthenticated, so loopback unless the deployment opts in.
        if std::env::var_os(nextgcore_metrics::nes_energy::METRICS_BIND_ENV).is_none() {
            assert!(metrics_addr().ip().is_loopback(), "{}", metrics_addr());
        }
    }

    // ------------------------------------------------------------------
    // G2-2: NRF /load heartbeat wiring
    // ------------------------------------------------------------------

    #[test]
    fn test_nrf_uri_defaults_empty_and_is_settable() {
        // Default: SBI/NRF plane OFF (data-plane-only) — no behavior change.
        let args = Args::parse_from(["nextgcore-upfd"]);
        assert_eq!(args.nrf_uri, "");
        assert!(args.nrf_uri.trim().is_empty(), "default must disable NRF");

        // Opt-in: explicit --nrf-uri enables registration + heartbeat.
        let args = Args::parse_from(["nextgcore-upfd", "--nrf-uri", "http://127.0.0.10:7777"]);
        assert_eq!(args.nrf_uri, "http://127.0.0.10:7777");
        assert!(!args.nrf_uri.trim().is_empty());
    }

    #[test]
    fn test_build_upf_nf_profile_shape() {
        // TS 29.510 §6.1.6.2.2/§6.1.6.2.10: UPF NFProfile with upfInfo N3 endpoint.
        let p = build_upf_nf_profile("upf-abc", "127.0.0.4", "127.0.0.4", 42);
        assert_eq!(p["nfInstanceId"], "upf-abc");
        assert_eq!(p["nfType"], "UPF");
        assert_eq!(p["nfStatus"], "REGISTERED");
        // Honest load gauge carried in the initial profile (0..=100).
        assert_eq!(p["load"], serde_json::json!(42));
        // UPF has NO SBI service — nfServices must be absent.
        assert!(p.get("nfServices").is_none(), "UPF exposes no SBI service");
        // upfInfo advertises the N3 (GTP-U) interface endpoint.
        let iface = &p["upfInfo"]["interfaceUpfInfoList"][0];
        assert_eq!(iface["interfaceType"], "N3");
        assert_eq!(iface["ipv4EndpointAddresses"][0], "127.0.0.4");
    }

    #[test]
    fn test_parse_host_port() {
        assert_eq!(
            parse_host_port("http://127.0.0.10:7777"),
            Some(("127.0.0.10".to_string(), 7777))
        );
        assert_eq!(
            parse_host_port("https://nrf.example:443/nnrf-nfm/v1"),
            Some(("nrf.example".to_string(), 443))
        );
        // No explicit port → scheme default.
        assert_eq!(
            parse_host_port("http://nrf.local"),
            Some(("nrf.local".to_string(), 80))
        );
    }
}

/// #1324: the NFProfile carries its host where its type belongs (TS 29.510
/// §6.1.6.2.2): IPv4 in ipv4Addresses, IPv6 in ipv6Addresses, an FQDN as fqdn, and
/// the service ipEndPoints likewise.
#[cfg(test)]
mod tests_nf_profile_host_kind_1324 {
    use super::*;

    #[test]
    fn the_nf_profile_carries_its_host_by_type() {
        for host in nextgcore_sbi::nf_addressing::SAMPLE_HOSTS {
            // The N3 address varies too: it is typed the same way.
            let profile = build_upf_nf_profile("id", host, host, 0);
            let problems =
                nextgcore_sbi::nf_addressing::profile_addressing_problems(&profile, host);
            assert!(problems.is_empty(), "{host}: {problems:?}\n{profile}");
        }
    }
}
