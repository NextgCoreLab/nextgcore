//! NextGCore SMF (Session Management Function)
//!
//! The SMF handles PDU session management in 5G Core and EPC networks.
//!
//! # Architecture
//!
//! The SMF consists of several key components:
//! - Context management (UE, Session, Bearer contexts)
//! - State machines (SMF, GSM, PFCP)
//! - Protocol handlers (N4/PFCP, GTP-C, SBI)
//! - Policy binding (PCC rules to bearers/QoS flows)
//!
//! # Supported Interfaces
//!
//! - N4: PFCP interface to UPF
//! - N7: Policy control interface to PCF
//! - N10: UE context management interface to UDM
//! - N11: PDU session management interface from AMF
//! - S5/S8: GTP-C interface to SGW (EPC mode)

use anyhow::{Context, Result};
use nextgcore_sbi::context::{global_context, NfInstance, NfService};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::{
    send_bad_request, send_not_found, SbiServer, SbiServerConfig as NextgcoreSbiServerConfig,
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

mod binding;
mod context;
mod easdf; // #114: EASDF selection + DNS-context lifecycle (TS 23.501 §5.6.7)
mod eps_iwk; // #117: 5GS↔EPS interworking, EBI assignment over Namf_Communication
mod event;
mod event_exposure; // #79: Nsmf_EventExposure resource model + notification
mod gn_build;
mod gn_handler;
mod gsm_build;
mod gsm_handler;
mod gsm_sm;
mod gtp_build;
mod gtp_handler;
mod gtp_path;
pub mod mbs_session; // Rel-17: MBS multicast/broadcast session
mod n4_build;
mod n4_handler;
mod pfcp_path;
mod pfcp_sm;
mod policy;
#[cfg(test)]
mod property_tests;
mod session_extensions; // #199-#201: IPv6 dual-stack, SSC modes, Ethernet PDU
pub mod slicing; // Rel-17: per-slice QoS profiles
mod smf_sm;
mod timer;
mod udm; // #79: Nudm_UECM_Registration + Nudm_SDM_Get sm-data

use context::{smf_context_final, smf_context_init, smf_self};
use smf_sm::SmfFsm;

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Monotonically-increasing PFCP sequence number counter.
/// Each transaction fetches-and-increments this so concurrent PDU sessions
/// never reuse the same sequence number.
static PFCP_SEQ: AtomicU32 = AtomicU32::new(1);

/// Externally-reachable base URI of this SMF's SBI server, used for the
/// callback URIs handed to the PCF (notificationUri). Set once in `main`.
static SELF_SBI_URI: std::sync::OnceLock<String> = std::sync::OnceLock::new();

// ---------------------------------------------------------------------------
// OAuth2 rollout (Wave-6 H8): opt-in producer verification + outbound consumer
// token install. Default OFF so the matched-sim E2E path is byte-unchanged;
// the docker `smf-oauth2.yaml` overlay (or NEXTGCORE_SBI_OAUTH2_REQUIRE=1) sets
// `smf.sbi.oauth2.require: true`. TS 33.501 §13.4.1, TS 29.510 §5.4.2.
// ---------------------------------------------------------------------------

/// Process-wide OAuth2 client for automatic Bearer-token acquisition on
/// outbound SBI calls (installed only when OAuth2 enforcement is enabled).
static OAUTH2_CLIENT: std::sync::OnceLock<Option<Arc<nextgcore_sbi::oauth::OAuth2Client>>> =
    std::sync::OnceLock::new();

/// The shared OAuth2 client, if SBI OAuth2 enforcement is enabled (Wave-6 H8
/// Phase A). Outbound SBI clients attach a token via [`attach_oauth2`].
fn oauth2_client() -> Option<Arc<nextgcore_sbi::oauth::OAuth2Client>> {
    OAUTH2_CLIENT.get().and_then(|opt| opt.clone())
}

/// Attach the process-wide OAuth2 client (when enforcement is on) so the
/// outbound SBI request carries an NRF-issued Bearer token scoped to `target`
/// (TS 33.501 §13.4.1, TS 29.510 §5.4.2). A no-op when enforcement is off, so
/// the matched-sim default path is byte-unchanged (Wave-6 H8 Phase A).
pub(crate) fn attach_oauth2(
    client: nextgcore_sbi::client::SbiClient,
    target: nextgcore_sbi::types::NfType,
) -> nextgcore_sbi::client::SbiClient {
    match oauth2_client() {
        Some(oauth2) => client.with_oauth2(oauth2, target),
        None => client,
    }
}

/// Parse the opt-in `sbi.oauth2.require` knob (Wave-6 H8). Default false so the
/// matched-sim path is untouched. Honors `NEXTGCORE_SBI_OAUTH2_REQUIRE` first
/// (overlay-friendly), then the yaml `<nf>.sbi.oauth2.require` (root-key
/// agnostic: true iff any top-level section sets it).
fn oauth2_required(config_path: &str) -> bool {
    if let Ok(v) = std::env::var("NEXTGCORE_SBI_OAUTH2_REQUIRE") {
        return matches!(v.trim(), "1" | "true" | "TRUE" | "yes");
    }
    let Ok(content) = std::fs::read_to_string(config_path) else {
        return false;
    };
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(&content) else {
        return false;
    };
    value.as_mapping().is_some_and(|map| {
        map.values().any(|section| {
            section
                .get("sbi")
                .and_then(|s| s.get("oauth2"))
                .and_then(|o| o.get("require"))
                .and_then(|r| r.as_bool())
                .unwrap_or(false)
        })
    })
}

/// Apply OAuth2 producer enforcement to `cfg` and install the outbound OAuth2
/// client (Wave-6 H8). The server verifies incoming Bearer tokens against the
/// NRF JWKS and requires `aud` to include NfType::Smf; with no NRF URI
/// configured it fails closed (503, per nextgcore-sbi server.rs).
async fn apply_oauth2_enforcement(mut cfg: NextgcoreSbiServerConfig) -> NextgcoreSbiServerConfig {
    let nrf_uri = global_context().get_nrf_uri().await;
    cfg.require_oauth2 = true;
    cfg.oauth2_jwks_uri = nrf_uri.as_deref().map(|uri| {
        nextgcore_sbi::oauth::JwksCache::for_nrf(uri)
            .jwks_uri()
            .to_string()
    });
    cfg = cfg.with_expected_audience_nf_type(nextgcore_sbi::types::NfType::Smf);
    if let Some(uri) = nrf_uri.as_deref() {
        let nf_instance_id = format!("smf-{}", uuid::Uuid::new_v4());
        let _ = OAUTH2_CLIENT.set(Some(Arc::new(nextgcore_sbi::oauth::OAuth2Client::new(
            uri,
            nf_instance_id,
            nextgcore_sbi::types::NfType::Smf,
        ))));
    }
    log::info!(
        "OAuth2 enforcement enabled (JWKS: {})",
        cfg.oauth2_jwks_uri.as_deref().unwrap_or("UNCONFIGURED")
    );
    cfg
}

/// Base URI for callbacks (e.g. `http://10.0.0.5:7777`).
fn self_sbi_uri() -> String {
    SELF_SBI_URI
        .get()
        .cloned()
        .unwrap_or_else(|| "http://127.0.0.1:7777".to_string())
}

/// This SMF's NF instance id, used as the `nfId` in Nnsacf_NSAC requests
/// (TS 29.536). Falls back to a fixed label when the self-instance has not
/// been registered (e.g. NRF-less dev runs).
async fn self_nf_id() -> String {
    global_context()
        .get_self_instance()
        .await
        .map(|i| i.id)
        .unwrap_or_else(|| "nextgcore-smf".to_string())
}

/// Roll back a previously-admitted NSACF PDU-session count (DECREASE) when a
/// later establishment step fails after admission. No-op when `admitted` is
/// false (no count was taken). Resolves the NSACF endpoint afresh; best-effort.
async fn rollback_nsac(admitted: bool, supi: &str, psi: u8, sst: u8, sd: Option<&str>) {
    if !admitted {
        return;
    }
    if let Some(nsacf) = policy::resolve_nsacf_endpoint().await {
        let nf_id = self_nf_id().await;
        policy::nsac_pdu_session_release(&nsacf, &nf_id, supi, psi, sst, sd).await;
    }
}

// ---------------------------------------------------------------------------
// Typed YAML configuration structs (serde_yaml Deserialize)
// ---------------------------------------------------------------------------

/// A single server/client address entry
#[derive(Debug, Deserialize)]
struct AddrEntry {
    address: Option<String>,
    port: Option<u16>,
    uri: Option<String>,
}

/// SBI client NRF list
#[derive(Debug, Default, Deserialize)]
struct SbiClient {
    nrf: Option<Vec<AddrEntry>>,
}

/// SBI section (server list + client)
#[derive(Debug, Default, Deserialize)]
struct SbiSection {
    server: Option<Vec<AddrEntry>>,
    client: Option<SbiClient>,
}

/// Top-level `smf:` section
#[derive(Debug, Default, Deserialize)]
struct SmfSection {
    sbi: Option<SbiSection>,
    /// DNS servers signalled to the UE in the establishment accept's ePCO IE.
    ///
    /// The shipped `docker/rust/configs/5gc/smf.yaml` has declared these (and
    /// `mtu`) all along; nothing parsed them, so the UE received no DNS
    /// configuration at all. IPv6 entries are accepted in the list and skipped
    /// here — the ePCO container this SMF emits is the IPv4 DNS one, and
    /// silently dropping a v6 address is better than failing to parse the file.
    dns: Option<Vec<String>>,
    /// IPv4 link MTU signalled in the same IE.
    mtu: Option<u16>,
}

/// Root YAML document
#[derive(Debug, Default, Deserialize)]
struct SmfYaml {
    smf: Option<SmfSection>,
}

/// Resolved, flat configuration used at runtime
struct SmfConfig {
    sbi_addr: String,
    sbi_port: u16,
    max_ue: usize,
    max_sess: usize,
    max_bearer: usize,
    /// NRF URI parsed from `smf.sbi.client.nrf[0].uri` (if present).
    nrf_uri: Option<String>,
    /// IPv4 DNS servers for the establishment accept's ePCO IE.
    dns_servers: Vec<std::net::Ipv4Addr>,
    /// IPv4 link MTU for the same IE.
    mtu: Option<u16>,
}

impl Default for SmfConfig {
    fn default() -> Self {
        Self {
            sbi_addr: "0.0.0.0".to_string(),
            sbi_port: 7777,
            max_ue: 1024,
            max_sess: 4096,
            max_bearer: 8192,
            nrf_uri: None,
            dns_servers: Vec::new(),
            mtu: None,
        }
    }
}

fn load_config(path: &str) -> SmfConfig {
    let mut config = SmfConfig::default();

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("Could not read SMF config '{path}': {e}. Using defaults.");
            return config;
        }
    };

    let yaml: SmfYaml = match serde_yaml::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("Failed to parse SMF YAML config '{path}': {e}. Using defaults.");
            return config;
        }
    };

    if let Some(smf) = yaml.smf {
        if let Some(sbi) = smf.sbi {
            if let Some(servers) = sbi.server {
                if let Some(first) = servers.into_iter().next() {
                    if let Some(addr) = first.address {
                        config.sbi_addr = addr;
                    }
                    if let Some(port) = first.port {
                        config.sbi_port = port;
                    }
                }
            }
            // Extract the NRF URI here so main() doesn't re-read and re-parse
            // the same file just to seed it.
            if let Some(client) = sbi.client {
                if let Some(nrf_list) = client.nrf {
                    if let Some(nrf) = nrf_list.into_iter().next() {
                        config.nrf_uri = nrf.uri;
                    }
                }
            }
        }
        if let Some(dns) = smf.dns {
            // Only the IPv4 entries are usable by the ePCO container this SMF
            // emits; a v6 address in the list is skipped with a note rather than
            // treated as a config error.
            for entry in dns {
                match entry.parse::<std::net::Ipv4Addr>() {
                    Ok(addr) => config.dns_servers.push(addr),
                    Err(_) => log::debug!(
                        "smf.dns entry {entry:?} is not an IPv4 address; not signalled in ePCO"
                    ),
                }
            }
        }
        config.mtu = smf.mtu;
    }

    config
}

/// DNS servers and link MTU resolved from config, for the ePCO IE the
/// establishment accept carries (TS 24.501 §6.6.1).
///
/// A process-global because the accept is built deep inside the SBI handler
/// chain, which threads no config; the same shape `NRF_URI` and the other
/// startup-resolved values already use in this binary.
static EPCO_CONFIG: std::sync::OnceLock<(Vec<std::net::Ipv4Addr>, Option<u16>)> =
    std::sync::OnceLock::new();

/// The configured ePCO inputs, or `(&[], None)` before startup has resolved them
/// (in which case no ePCO IE is emitted — the previous behaviour).
fn epco_config() -> (&'static [std::net::Ipv4Addr], Option<u16>) {
    match EPCO_CONFIG.get() {
        Some((dns, mtu)) => (dns.as_slice(), *mtu),
        None => (&[], None),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    // G32/G43: Initialize OpenTelemetry tracing (Jaeger/OTLP exporter)
    let _otel = nextgcore_metrics::otel::init_otel(
        nextgcore_metrics::otel::OtelConfig::new(env!("CARGO_PKG_NAME")).with_endpoint(
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://jaeger:4317".to_string()),
        ),
    )
    .ok();

    log::info!("NextGCore SMF v{} starting...", env!("CARGO_PKG_VERSION"));

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        shutdown_clone.store(true, Ordering::SeqCst);
        SHUTDOWN.store(true, Ordering::SeqCst);
    })
    .expect("Failed to set Ctrl+C handler");

    // Load configuration — respect -c/--config CLI arg first, then SMF_CONFIG env var
    let config_path = std::env::args()
        .zip(std::env::args().skip(1))
        .find_map(|(a, b)| {
            if a == "-c" || a == "--config" {
                Some(b)
            } else {
                None
            }
        })
        .or_else(|| std::env::var("SMF_CONFIG").ok())
        .unwrap_or_else(|| "/etc/nextgcore/smf.yaml".to_string());
    let config = load_config(&config_path);
    log::info!("Loading configuration from {config_path}");
    log::info!(
        "SBI config: address={}, port={}",
        config.sbi_addr,
        config.sbi_port
    );
    // Publish the ePCO inputs before any SBI handler can build an accept.
    if config.dns_servers.is_empty() && config.mtu.is_none() {
        log::warn!(
            "No smf.dns / smf.mtu configured: the PDU Session Establishment Accept \
             will carry no ePCO IE, so UEs receive no DNS configuration"
        );
    } else {
        log::info!(
            "ePCO: signalling {} DNS server(s), mtu={:?}",
            config.dns_servers.len(),
            config.mtu
        );
    }
    let _ = EPCO_CONFIG.set((config.dns_servers.clone(), config.mtu));

    // Seed NRF URI into SBI context for NF registration (parsed once in load_config).
    if let Some(ref uri) = config.nrf_uri {
        log::info!("NRF URI configured: {uri}");
        global_context().set_nrf_uri(uri).await;
    }

    // Advertised SBI base URI used for PCF callbacks (notificationUri).
    // 0.0.0.0 is not reachable by peers, so fall back to loopback unless
    // overridden with SMF_SBI_ADVERTISE_URI.
    let advertise_uri = std::env::var("SMF_SBI_ADVERTISE_URI").unwrap_or_else(|_| {
        let host = if config.sbi_addr == "0.0.0.0" {
            "127.0.0.1"
        } else {
            config.sbi_addr.as_str()
        };
        format!("http://{host}:{}", config.sbi_port)
    });
    log::info!("SBI advertise URI for callbacks: {advertise_uri}");
    let _ = SELF_SBI_URI.set(advertise_uri.clone());

    // ---- #114: EASDF DNS-context leg (TS 23.501 §5.6.7), OFF by default ----
    //
    // Env-var driven, matching the rest of this daemon's switches (it has no clap
    // Args struct). A runtime switch rather than the cargo feature the issue
    // suggests, so CI compiles and exercises the path in both states -- see
    // `easdf.rs` for the full reasoning.
    if std::env::var("SMF_EASDF")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        let patterns: Vec<String> = std::env::var("SMF_EASDF_EDGE_FQDN")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if patterns.is_empty() {
            // Enabled with nothing to steer: say so, because the switch being on
            // while no session ever gets a DNS context is otherwise invisible.
            log::warn!(
                "SMF_EASDF is set but SMF_EASDF_EDGE_FQDN names no pattern: no session will get                  an EASDF DNS context. Set e.g. SMF_EASDF_EDGE_FQDN='*.edge.example.com'."
            );
        }
        easdf::enable(easdf::EasdfConfig {
            nrf_uri: config
                .nrf_uri
                .clone()
                .unwrap_or_else(|| "http://127.0.0.1:7777".to_string()),
            report_uri: format!("{advertise_uri}/nsmf-pdusession/v1/easdf-dns-reports"),
            edge_fqdn_patterns: patterns,
        });
    }

    // ---- #117: 5GS↔EPS interworking (TS 23.502 §4.11.1.4.1) ----
    //
    // Off by default. When on, an establishing PDU session asks the AMF for an EPS
    // Bearer Identity and carries the Mapped EPS bearer contexts IE to the UE, so
    // the session can later be moved to the EPC. A runtime switch rather than the
    // cargo feature #117 suggests -- see `eps_iwk.rs` for why, and for why #276's
    // listener IS a feature while this is not.
    if std::env::var("SMF_EPS_INTERWORKING")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        eps_iwk::enable();
    }

    // ---- #79: UDM interaction (TS 23.502 §4.3.2.2.1 step 4) ----
    //
    // Off by default, as #79 asks: the E2E harness has no conformant UDM, and
    // enforcing subscription data nothing supplies would regress the matched-sim
    // data-plane path CI does gate on. A runtime switch rather than a cargo
    // feature, for the reason recorded across this daemon's other switches.
    if std::env::var("SMF_UDM")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        udm::enable();
    }

    // Initialize SMF context
    smf_context_init(config.max_ue, config.max_sess, config.max_bearer);
    log::info!(
        "SMF context initialized (max_ue={}, max_sess={}, max_bearer={})",
        config.max_ue,
        config.max_sess,
        config.max_bearer
    );

    // ---- #191: durable state, OFF by default ----
    //
    // Restored AFTER the context knows its capacity caps and BEFORE the SBI server
    // or the PFCP association loop can run, so a restored session is never
    // shadowed by a fresh one and the restored peer Recovery Time Stamps are in
    // place for the first Association Setup.
    //
    // Precedence matches the other NFs -- the flag wins over the env var, and an
    // empty value is treated as unset -- but the flag is parsed by the same argv
    // scan this daemon already uses for `-c`/`--config` rather than by clap:
    // smfd has no clap `Args` struct, and introducing one would make every
    // argument it currently ignores a hard startup error.
    let state_file = std::env::args()
        .zip(std::env::args().skip(1))
        .find_map(|(a, b)| (a == "--state-file").then_some(b))
        .or_else(|| std::env::var("NEXTGCORE_SMF_STATE_FILE").ok())
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty());
    if let Some(path) = state_file {
        let ctx = smf_self();
        let mut guard = ctx
            .write()
            .map_err(|_| anyhow::anyhow!("SMF context lock poisoned"))?;
        // Fail STARTUP on a snapshot that cannot be read or is from a newer build.
        // Coming up with an empty IPv4 pool is the one failure mode here that is
        // worse than not starting: it re-issues addresses live UEs still hold, and
        // nothing logs the collision. The store would then also refuse every later
        // write to protect the file, so the run would be silently non-durable too.
        let restored = guard.set_state_file(std::path::PathBuf::from(&path))?;
        log::info!("SMF durable state: {path} ({restored} record(s) restored)");
    } else {
        log::info!(
            "SMF durable state disabled (no --state-file / NEXTGCORE_SMF_STATE_FILE): PFCP \
             sessions, policy bindings and IPv4 allocations are memory-only and lost on restart"
        );
    }

    // Initialize SMF state machine
    let mut smf_sm = SmfFsm::new();
    smf_sm.init();
    log::info!("SMF state machine initialized");

    // Start SBI HTTP/2 server
    let sbi_addr: SocketAddr = format!("{}:{}", config.sbi_addr, config.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let mut sbi_server_config = NextgcoreSbiServerConfig::new(sbi_addr);
    // Issue #63: resolve the SBI security profile, PRODUCTION by default. The
    // production profile requires OAuth2, so the outbound token client is
    // installed too -- a producer that demands tokens must also present them.
    let sbi_profile = nextgcore_sbi::security::SbiProfile::resolve();
    if sbi_profile.is_production() || oauth2_required(&config_path) {
        sbi_server_config = apply_oauth2_enforcement(sbi_server_config).await;
    }
    let nrf_uri = nextgcore_sbi::context::global_context()
        .get_nrf_uri()
        .await
        .unwrap_or_default();
    sbi_server_config = nextgcore_sbi::security::apply_sbi_security_profile(
        sbi_server_config,
        sbi_profile,
        nextgcore_sbi::types::NfType::Smf,
        &nrf_uri,
    )?;
    let sbi_server = SbiServer::new(sbi_server_config);

    sbi_server
        .start(smf_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    log::info!("SBI HTTP/2 server listening on {sbi_addr}");

    // Register with NRF (if configured)
    match smf_nrf_register(&config.sbi_addr, config.sbi_port).await {
        Ok(nf_instance_id) if !nf_instance_id.is_empty() => {
            // #79: the UDM must record the SAME instance id the NRF knows, or its
            // serving-SMF record points at an instance nothing else can resolve.
            udm::set_instance_id(&nf_instance_id);
            // G2-2: PATCH a real NFProfile "/load" gauge to NRF each heartbeat
            // (PDU sessions vs configured capacity; TS 29.510 §5.2.2.3.2).
            nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(nf_instance_id, 5, || {
                let ctx = smf_self();
                let load = ctx.read().map(|c| c.get_load()).unwrap_or(0);
                load.clamp(0, 100) as u8
            });
        }
        Ok(_) => {}
        Err(e) => {
            log::warn!("NRF registration failed (will operate without NRF): {e}");
        }
    }

    log::info!("NextGCore SMF ready");

    // Bind the single N4 (PFCP) socket. All SMF→UPF requests AND all
    // unsolicited UPF→SMF messages (Session Report Requests, heartbeats)
    // flow through this one socket so transactions can be matched by
    // sequence number (TS 29.244 7.2.1).
    let pfcp_bind_addr: SocketAddr = {
        let addr = std::env::var("SMF_PFCP_ADDR").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port: u16 = std::env::var("SMF_PFCP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8805);
        format!("{addr}:{port}")
            .parse()
            .context("Invalid SMF PFCP listen address")?
    };
    // Issue #20: UPF_PFCP_ADDR accepts a comma-separated peer list
    // ("10.0.0.5,10.0.0.6:8806"); an entry without a port uses
    // UPF_PFCP_PORT. A single entry — the default — behaves exactly as the
    // pre-pool single-UPF configuration.
    let upf_pfcp_addrs: Vec<SocketAddr> = {
        let addrs = std::env::var("UPF_PFCP_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
        let default_port: u16 = std::env::var("UPF_PFCP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8805);
        let mut peers = Vec::new();
        for entry in addrs.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            let candidate = if entry.contains(':') {
                entry.to_string()
            } else {
                format!("{entry}:{default_port}")
            };
            peers.push(
                candidate
                    .parse()
                    .with_context(|| format!("Invalid UPF PFCP address '{entry}'"))?,
            );
        }
        anyhow::ensure!(!peers.is_empty(), "UPF_PFCP_ADDR contains no usable peer");
        peers
    };
    let smf_node_ip: [u8; 4] = {
        let s = std::env::var("SMF_PFCP_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
        let parts: Vec<u8> = s.split('.').filter_map(|p| p.parse().ok()).collect();
        if parts.len() == 4 {
            [parts[0], parts[1], parts[2], parts[3]]
        } else {
            [127, 0, 0, 1]
        }
    };

    let pfcp_socket = Arc::new(
        tokio::net::UdpSocket::bind(pfcp_bind_addr)
            .await
            .with_context(|| format!("Failed to bind SMF PFCP socket on {pfcp_bind_addr}"))?,
    );
    log::info!("SMF N4 PFCP socket bound on {pfcp_bind_addr} (UPF peers: {upf_pfcp_addrs:?})");

    let pfcp_clients: Vec<Arc<pfcp_path::PfcpClient>> = upf_pfcp_addrs
        .iter()
        .map(|&peer| {
            Arc::new(pfcp_path::PfcpClient::new(
                pfcp_socket.clone(),
                peer,
                smf_node_ip,
            ))
        })
        .collect();
    // Installs the whole pool and pool slot 0 as the process-wide default
    // client (the legacy single-client paths keep working unchanged).
    pfcp_path::set_global_pool(pfcp_clients.clone());
    let pfcp_client = pfcp_clients[0].clone();

    // #191: hand each client the Recovery Time Stamp the durable snapshot recorded
    // for its peer, BEFORE the association loop is spawned. This is what turns the
    // restored PFCP session map from a claim into a checked one: the first
    // Association Setup compares the UPF's reported stamp against this seed and
    // flushes the restored sessions if the UPF restarted while the SMF was down.
    // A no-op when no state file is configured (the map has no entries).
    for client in &pfcp_clients {
        let stored = smf_self()
            .read()
            .ok()
            .and_then(|ctx| ctx.upf_recovery_time_stamp(&client.peer().to_string()));
        if let Some(rts) = stored {
            client.seed_peer_recovery_time_stamp(rts).await;
        }
    }

    // PFCP receive/dispatch loop: responses complete pending transactions;
    // node-level requests (heartbeat, association release) are answered by
    // the engine; Session Report Requests are handled here.
    let shutdown_pfcp = shutdown.clone();
    let clients_rx = pfcp_clients.clone();
    let sock_rx = pfcp_socket.clone();
    let pfcp_listener_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            if shutdown_pfcp.load(Ordering::SeqCst) || SHUTDOWN.load(Ordering::SeqCst) {
                break;
            }
            match tokio::time::timeout(
                std::time::Duration::from_secs(1),
                sock_rx.recv_from(&mut buf),
            )
            .await
            {
                Ok(Ok((len, peer))) => {
                    let pkt = buf[..len].to_vec();
                    // Route the datagram to the client owning this peer so
                    // transaction matching and association state stay
                    // per-UPF. Unknown sources fall back to pool slot 0,
                    // preserving the single-UPF behavior.
                    let client = clients_rx
                        .iter()
                        .find(|c| c.peer() == peer)
                        .unwrap_or(&clients_rx[0]);
                    if !client.on_datagram(&pkt, peer).await {
                        handle_pfcp_incoming(&sock_rx, &pkt, peer).await;
                    }
                }
                Ok(Err(e)) => log::warn!("PFCP listener recv error: {e}"),
                Err(_) => {} // timeout — loop and re-check shutdown
            }
        }
        log::info!("SMF N4 PFCP listener stopped");
    });

    // N4 association maintenance: establish the PFCP association at startup
    // (Node ID + Recovery Time Stamp, TS 29.244 6.2.6) and keep it alive
    // with heartbeats. Heartbeat exhaustion or a changed peer Recovery Time
    // Stamp tears the association down (stale sessions flushed) and
    // triggers re-association.
    let shutdown_assoc = shutdown.clone();
    let clients_assoc = pfcp_clients.clone();
    let pfcp_assoc_handle = tokio::spawn(async move {
        let heartbeat_period = std::time::Duration::from_secs(10);
        let reassociate_holdoff = std::time::Duration::from_secs(10);
        loop {
            if shutdown_assoc.load(Ordering::SeqCst) || SHUTDOWN.load(Ordering::SeqCst) {
                break;
            }
            for client_assoc in &clients_assoc {
                if !client_assoc.is_associated().await {
                    if let Err(e) = client_assoc.associate().await {
                        // Abnormal action on association failure: declare the
                        // UPF unreachable and retry next cycle. Handled
                        // per-peer (issue #20 review): one unreachable UPF
                        // must not starve heartbeats to healthy pool members.
                        log::error!(
                            "PFCP Association Setup with {} failed: {e}; retrying in {}s",
                            client_assoc.peer(),
                            reassociate_holdoff.as_secs()
                        );
                    }
                }
            }
            tokio::time::sleep(heartbeat_period).await;
            if shutdown_assoc.load(Ordering::SeqCst) || SHUTDOWN.load(Ordering::SeqCst) {
                break;
            }
            for client_assoc in &clients_assoc {
                if client_assoc.is_associated().await {
                    if let Err(e) = client_assoc.heartbeat_once().await {
                        // Exhaustion already marked the association down inside
                        // the engine; the next loop turn re-associates.
                        log::error!("PFCP heartbeat to {} failed: {e}", client_assoc.peer());
                    }
                }
            }
        }
    });

    // Main async event loop
    let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(100));

    loop {
        interval.tick().await;

        // Check for shutdown
        if shutdown.load(Ordering::SeqCst) || SHUTDOWN.load(Ordering::SeqCst) {
            break;
        }

        // 5GSM procedure timers (T3591/T3592): retransmit the modification or
        // release command the UE has not answered, and abandon the procedure once
        // the retransmissions are exhausted (TS 24.501 §6.3.2.2, §6.3.3).
        run_gsm_timer_tick().await;

        // PFCP timers and the wider state machine are still driven by their own
        // tasks (pfcp_assoc_handle above and the per-transaction retransmission
        // inside pfcp_path); this tick owns only the 5GSM procedure timers.
    }

    pfcp_assoc_handle.abort();

    // Graceful shutdown: release the N4 association before going down
    // (TS 29.244 6.2.9 — Association Release initiated by the CP function)
    if pfcp_client.is_associated().await {
        match pfcp_client.release_association().await {
            Ok(()) => log::info!("PFCP association released"),
            Err(e) => log::warn!("PFCP Association Release failed: {e}"),
        }
    }
    pfcp_listener_handle.abort();

    log::info!("Shutting down...");

    // #235: NFDeregister (TS 29.510 5.2.2.2.3) BEFORE the listener goes
    // away, so the NRF stops handing this profile to consumers instead of
    // waiting out its supervision timer. Stopping the server first would
    // open the bad window: not serving, but still advertised.
    nextgcore_sbi::heartbeat::deregister_self().await;

    // Stop SBI server
    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;
    log::info!("SBI HTTP/2 server stopped");

    // Cleanup state machine
    smf_sm.fini();
    log::info!("SMF state machine finalized");
    drop(smf_sm);

    // Cleanup context
    smf_context_final();
    log::info!("SMF context finalized");

    log::info!("NextGCore SMF stopped");
    Ok(())
}

// =============================================================================
// PFCP N4 Receive Path (SMF as server for UPF-initiated messages)
// =============================================================================

/// Dispatch an incoming PFCP datagram received on the SMF's N4 listen socket.
async fn handle_pfcp_incoming(
    sock: &tokio::net::UdpSocket,
    pkt: &[u8],
    peer: std::net::SocketAddr,
) {
    if pkt.len() < 4 {
        log::warn!("PFCP packet from {peer} too short ({} bytes)", pkt.len());
        return;
    }
    let msg_type = pkt[1];
    log::debug!(
        "PFCP message type={msg_type} from {peer} ({} bytes)",
        pkt.len()
    );

    match msg_type {
        56 => handle_pfcp_session_report(sock, pkt, peer).await,
        _ => log::debug!("PFCP: unhandled message type={msg_type} from {peer}"),
    }
}

/// Handle PFCP Session Report Request (message type 56) from UPF.
///
/// The UPF sends this when a URR threshold is crossed.  The SMF logs the
/// usage report and responds with a Session Report Response (type 57)
/// carrying a "Request Accepted" cause IE.
async fn handle_pfcp_session_report(
    sock: &tokio::net::UdpSocket,
    pkt: &[u8],
    peer: std::net::SocketAddr,
) {
    // Minimum PFCP header with SEID: 16 bytes
    // flags[1] + msg_type[1] + length[2] + seid[8] + seq[3] + spare[1]
    if pkt.len() < 16 {
        log::warn!(
            "PFCP Session Report Request from {peer} too short ({} bytes)",
            pkt.len()
        );
        return;
    }

    let seid = u64::from_be_bytes(pkt[4..12].try_into().unwrap_or([0u8; 8]));
    // Sequence number is 3 bytes at offset 12 (big-endian, upper byte = 0)
    let seq = u32::from_be_bytes([0, pkt[12], pkt[13], pkt[14]]);

    log::info!("PFCP Session Report Request: SEID=0x{seid:016x}, seq={seq}, peer={peer}");

    // Parse IEs from the payload (offset 16 onward).
    let payload = &pkt[16..];

    // Report Type (IE 39) is MANDATORY in a Session Report Request
    // (TS 29.244 Table 7.5.8.1-1) — reject its absence with cause 66.
    let report_type = pfcp_path::find_ie(payload, 39).and_then(|v| v.first().copied());
    let Some(report_type) = report_type else {
        log::warn!("Session Report Request missing mandatory Report Type IE — rejecting");
        let mut body = n4_build::PfcpMessageBuilder::new();
        body.add_cause_raw(66); // Mandatory IE missing
        body.add_u16(n4_build::pfcp_ie::OFFENDING_IE, 39);
        let resp = pfcp_path::encode_wire_message(
            pfcp_path::pfcp_message_type::SESSION_REPORT_RESPONSE,
            Some(seid),
            seq,
            &body.build(),
        );
        if let Err(e) = sock.send_to(&resp, peer).await {
            log::warn!("Failed to send Session Report Response to {peer}: {e}");
        }
        return;
    };

    // Downlink Data Report (DLDR, bit 0x01): the UPF buffered the first DL
    // packet for an idle session — in a full deployment this triggers the
    // Network Triggered Service Request (N1N2 transfer / paging via AMF).
    if report_type & 0x01 != 0 {
        if let Some(dldr) = pfcp_path::find_ie(payload, 83) {
            let pdr_id = pfcp_path::find_ie(dldr, 56)
                .filter(|v| v.len() >= 2)
                .map(|v| u16::from_be_bytes([v[0], v[1]]));
            // Downlink Data Service Information (IE 45): flags + PPI/QFI
            let qfi = pfcp_path::find_ie(dldr, 45).and_then(|v| {
                if v.is_empty() {
                    return None;
                }
                let flags = v[0];
                let mut idx = 1;
                if flags & 0x01 != 0 {
                    idx += 1; // skip PPI
                }
                if flags & 0x02 != 0 {
                    v.get(idx).map(|q| q & 0x3F)
                } else {
                    None
                }
            });
            log::info!(
                "Downlink Data Report: SEID=0x{seid:016x}, PDR={pdr_id:?}, QFI={qfi:?} — \
                 triggering UP connection re-activation"
            );
            // #78 / TS 29.244 §7.5.8.2 + TS 23.502 §4.2.3.3: drive the Network
            // Triggered Service Request. Before #78 this branch only logged, and the
            // `trigger_service_request` flag `n4_handler` sets was reached only from
            // its own unit test — so downlink data for an idle UE never paged and
            // every mobile-terminated service silently failed.
            trigger_network_initiated_service_request(seid, qfi).await;
        } else {
            log::warn!("Report Type has DLDR set but no Downlink Data Report IE present");
        }
    }

    // Error Indication Report (bit 0x04): a peer GTP-U node rejected one of
    // the session's tunnels — the DL tunnel toward the gNB is stale.
    if report_type & 0x04 != 0 {
        log::warn!(
            "Error Indication Report for SEID=0x{seid:016x}: remote GTP-U endpoint rejected \
             the DL tunnel (stale gNB F-TEID)"
        );
    }

    let mut offset = 0;
    while offset + 4 <= payload.len() {
        let ie_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let ie_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
        let ie_start = offset + 4;
        let ie_end = ie_start + ie_len;
        if ie_end > payload.len() {
            break;
        }

        // IE type 78 = Usage Report within Session Report Request (TS 29.244)
        if ie_type == 78 {
            let ur = &payload[ie_start..ie_end];
            let mut ur_off = 0;
            let mut urr_id: u32 = 0;
            let mut vol_ul: u64 = 0;
            let mut vol_dl: u64 = 0;
            while ur_off + 4 <= ur.len() {
                let t = u16::from_be_bytes([ur[ur_off], ur[ur_off + 1]]);
                let l = u16::from_be_bytes([ur[ur_off + 2], ur[ur_off + 3]]) as usize;
                let s = ur_off + 4;
                let e = s + l;
                if e > ur.len() {
                    break;
                }
                match t {
                    // URR ID (IE type 81)
                    81 if l >= 4 => {
                        urr_id = u32::from_be_bytes(ur[s..s + 4].try_into().unwrap_or([0u8; 4]));
                    }
                    // Volume Measurement (IE type 42): flags(1) + total(8) + ul(8) + dl(8)
                    42 if l >= 1 => {
                        let flags = ur[s];
                        let mut v = s + 1;
                        if flags & 0x01 != 0 && v + 8 <= e {
                            v += 8;
                        } // skip total
                        if flags & 0x02 != 0 && v + 8 <= e {
                            vol_ul =
                                u64::from_be_bytes(ur[v..v + 8].try_into().unwrap_or([0u8; 8]));
                            v += 8;
                        }
                        if flags & 0x04 != 0 && v + 8 <= e {
                            vol_dl =
                                u64::from_be_bytes(ur[v..v + 8].try_into().unwrap_or([0u8; 8]));
                        }
                    }
                    _ => {}
                }
                ur_off = e;
            }
            log::info!(
                "PFCP Usage Report: SEID=0x{seid:016x}, URR ID={urr_id}, \
                 UL={vol_ul} bytes, DL={vol_dl} bytes"
            );
        }

        offset = ie_end;
    }

    // Build Session Report Response (type 57) with Cause = Request Accepted
    // through the single builder/encoder path.
    let mut body = n4_build::PfcpMessageBuilder::new();
    body.add_cause_raw(1); // Request Accepted
    let resp = pfcp_path::encode_wire_message(
        pfcp_path::pfcp_message_type::SESSION_REPORT_RESPONSE,
        Some(seid),
        seq,
        &body.build(),
    );

    if let Err(e) = sock.send_to(&resp, peer).await {
        log::warn!("Failed to send PFCP Session Report Response to {peer}: {e}");
    } else {
        log::info!("PFCP Session Report Response sent: SEID=0x{seid:016x}, seq={seq}, peer={peer}");
    }
}

/// Register SMF NF instance with NRF
///
/// Sends PUT /nnrf-nfm/v1/nf-instances/{nfInstanceId} to NRF
async fn smf_nrf_register(sbi_addr: &str, sbi_port: u16) -> std::result::Result<String, String> {
    let sbi_ctx = global_context();

    // Prefer the URI seeded from YAML config; fall back to NRF_URI env var
    let nrf_uri = match sbi_ctx.get_nrf_uri().await {
        Some(uri) => uri,
        None => match std::env::var("NRF_URI").ok() {
            Some(uri) => uri,
            None => {
                log::debug!("No NRF URI configured, skipping NRF registration");
                return Ok(String::new());
            }
        },
    };

    log::info!("Registering SMF with NRF at {nrf_uri}");

    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_instance_id = uuid::Uuid::new_v4().to_string();

    let nf_profile = serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "SMF",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [{
            "serviceInstanceId": format!("{nf_instance_id}-nsmf-pdusession"),
            "serviceName": "nsmf-pdusession",
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{
                "ipv4Address": sbi_addr,
                "port": sbi_port
            }]
        }],
        "allowedNfTypes": ["AMF"],
        "heartBeatTimer": 10
    });

    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    log::debug!("NRF registration: PUT {path}");

    let response = client
        .put_json(&path, &nf_profile)
        .await
        .map_err(|e| format!("NRF registration failed: {e}"))?;

    match response.status {
        200 | 201 => {
            log::info!("SMF registered with NRF (id={nf_instance_id})");

            // Store self instance in SBI context
            let mut self_instance =
                NfInstance::new(&nf_instance_id, nextgcore_sbi::types::NfType::Smf);
            self_instance.ipv4_addresses = vec![sbi_addr.to_string()];
            let mut svc = NfService::new(
                "nsmf-pdusession",
                nextgcore_sbi::types::SbiServiceType::NsmfPdusession,
            );
            svc.port = sbi_port;
            svc.ip_addresses = vec![sbi_addr.to_string()];
            self_instance.add_service(svc);
            sbi_ctx.set_self_instance(self_instance).await;

            Ok(nf_instance_id)
        }
        _ => Err(format!(
            "NRF registration returned status {}",
            response.status
        )),
    }
}

// ---------------------------------------------------------------------------
// Nudm_SDM consumer (issue #204): the subscribed default DNN
// ---------------------------------------------------------------------------

/// Why a subscribed default DNN could not be determined. Each variant maps to a
/// distinct log line and, at the create handler, a distinct ProblemDetails cause —
/// "the UDM is unreachable" and "the subscription names several DNNs and flags
/// none" are different operator problems and must not collapse into one message.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DefaultDnnError {
    /// No UDM address could be determined (no NRF, no discovery hit, no env).
    NoUdmEndpoint,
    /// The Nudm_SDM_Get failed at the transport or returned a non-2xx.
    SdmRequestFailed(String),
    /// The subscription carries no DNN at all for this S-NSSAI.
    NoSubscribedDnn,
    /// Several DNNs are subscribed for this S-NSSAI and none carries
    /// `defaultDnnIndicator: true`, so the subscription does not say which is the
    /// default. Choosing one here would be a fabrication (issue #204).
    AmbiguousDefault(Vec<String>),
}

impl DefaultDnnError {
    /// The TS 29.502 ProblemDetails cause for a create that cannot resolve a DNN.
    fn cause(&self) -> &'static str {
        match self {
            // The consumer's request is incomplete for THIS network: it named no
            // DNN and the subscription does not supply one either.
            Self::NoSubscribedDnn | Self::AmbiguousDefault(_) => "MANDATORY_IE_MISSING",
            // Not the consumer's fault — the SMF could not reach the data it needs.
            Self::NoUdmEndpoint | Self::SdmRequestFailed(_) => "SUBSCRIPTION_DATA_NOT_AVAILABLE",
        }
    }

    fn detail(&self) -> String {
        match self {
            Self::NoUdmEndpoint => "no dnn in SmContextCreateData and no UDM endpoint is known \
                 (set UDM_SBI_ADDR or register a UDM with the NRF)"
                .to_string(),
            Self::SdmRequestFailed(e) => format!(
                "no dnn in SmContextCreateData and the subscribed default could not be \
                 retrieved: {e}"
            ),
            Self::NoSubscribedDnn => "no dnn in SmContextCreateData and the subscription carries \
                 no DNN for the requested S-NSSAI"
                .to_string(),
            Self::AmbiguousDefault(dnns) => format!(
                "no dnn in SmContextCreateData and the subscription names {} DNNs for the \
                 requested S-NSSAI ({}) with none flagged defaultDnnIndicator, so no default \
                 can be determined",
                dnns.len(),
                dnns.join(", ")
            ),
        }
    }
}

/// Resolve a UDM `nudm-sdm` endpoint.
///
/// NRF discovery first (TS 29.510 §5.3.2), because that is the mechanism a real
/// deployment uses and the SMF already knows its NRF; `UDM_SBI_ADDR` /
/// `UDM_SBI_PORT` is the fallback for a deployment with no NRF, matching how every
/// other cross-NF address is wired in this tree's compose files.
///
/// Deliberately does NOT populate the shared NF cache: `amfd` and `udmd` each
/// carry a full cache-populating discovery routine, and a third copy is a
/// maintenance cost this issue does not need. What the SMF wants is one address.
async fn discover_udm_sdm_endpoint() -> Option<(String, u16)> {
    discover_udm_service_endpoint("nudm-sdm").await
}

/// Resolve a UDM `nudm-uecm` endpoint (#79).
///
/// Separate from the `nudm-sdm` lookup rather than reusing it, because a UDM may
/// advertise the two services on different ports — `udm_service_endpoint_from_search_result`
/// already prefers a service's own `ipEndPoints` for exactly that reason, and
/// asking for one service name and using the answer for another would defeat it.
pub(crate) async fn discover_udm_uecm_endpoint() -> Option<(String, u16)> {
    discover_udm_service_endpoint("nudm-uecm").await
}

/// The shared body of the two lookups above.
///
/// The env fallback is deliberately shared: `UDM_SBI_ADDR`/`UDM_SBI_PORT` names one
/// UDM, so a deployment with no NRF gets both services at the same address, which
/// is what a single-container UDM actually does.
async fn discover_udm_service_endpoint(service: &str) -> Option<(String, u16)> {
    let sbi_ctx = global_context();
    let nrf_uri = match sbi_ctx.get_nrf_uri().await {
        Some(uri) => Some(uri),
        None => std::env::var("NRF_URI").ok(),
    };

    if let Some(nrf_uri) = nrf_uri {
        if let Some((nrf_host, nrf_port)) = parse_host_port(&nrf_uri) {
            let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;
            let path = format!(
                "/nnrf-disc/v1/nf-instances\
                 ?target-nf-type=UDM&requester-nf-type=SMF&service-names={service}"
            );
            match client.get(&path).await {
                Ok(resp) if resp.status == 200 => {
                    if let Some(ep) = resp
                        .http
                        .content
                        .as_deref()
                        .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
                        .and_then(|json| udm_service_endpoint_from_search_result(&json, service))
                    {
                        log::debug!("UDM {service} discovered via NRF at {}:{}", ep.0, ep.1);
                        return Some(ep);
                    }
                    log::debug!("NRF returned no usable UDM {service} endpoint");
                }
                Ok(resp) => log::debug!("NRF UDM discovery returned status {}", resp.status),
                Err(e) => log::debug!("NRF UDM discovery failed: {e}"),
            }
        }
    }

    let host = std::env::var("UDM_SBI_ADDR").ok()?;
    let port = std::env::var("UDM_SBI_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(7777);
    Some((host, port))
}

/// Pull a named UDM service's address out of a TS 29.510 `SearchResult`.
///
/// Split out so the decode is testable without an NRF. Prefers the service's own
/// `ipEndPoints` over the instance's `ipv4Addresses`, because a UDM may serve
/// `nudm-sdm` on a different port from `nudm-uecm` — which is why the service name
/// is a parameter rather than a constant (#79).
fn udm_service_endpoint_from_search_result(
    json: &serde_json::Value,
    service: &str,
) -> Option<(String, u16)> {
    for instance in json.get("nfInstances")?.as_array()? {
        let services = instance.get("nfServices").and_then(|v| v.as_array());
        for svc in services.into_iter().flatten() {
            if svc.get("serviceName").and_then(|v| v.as_str()) != Some(service) {
                continue;
            }
            let endpoint = svc.get("ipEndPoints").and_then(|v| v.as_array());
            let (host, port) = match endpoint.and_then(|eps| eps.first()) {
                Some(ep) => {
                    let host = ep
                        .get("ipv4Address")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                        .or_else(|| {
                            instance
                                .get("ipv4Addresses")?
                                .as_array()?
                                .first()?
                                .as_str()
                                .map(String::from)
                        })?;
                    let port = ep.get("port").and_then(|v| v.as_u64()).unwrap_or(7777) as u16;
                    (host, port)
                }
                None => {
                    let host = instance
                        .get("ipv4Addresses")?
                        .as_array()?
                        .first()?
                        .as_str()?
                        .to_string();
                    (host, 7777)
                }
            };
            return Some((host, port));
        }
    }
    None
}

/// Select the subscribed default DNN out of a TS 29.503
/// `SmfSelectionSubscriptionData` body, for the S-NSSAI the create names.
///
/// **This reads `smf-sel-data`, not `sm-data`, and that is a deliberate deviation
/// from #204's suggested approach — see the spec.** The approach says to select
/// "the `dnnConfigurations` entry flagged as the subscribed default", but
/// `sm-data`'s `DnnConfiguration` (TS 29.503 Table 5.5.2.4-1) has **no such
/// flag**; the default-DNN flag is `DnnInfo.defaultDnnIndicator`, which lives in
/// `SmfSelectionSubscriptionData` (`smf-sel-data`). Selecting from
/// `dnnConfigurations` would mean picking an arbitrary key out of a JSON *object*,
/// which is precisely the fabrication #204 exists to remove.
///
/// Selection order:
/// 1. the `dnnInfos` entry with `defaultDnnIndicator: true`;
/// 2. if exactly ONE DNN is subscribed for the S-NSSAI and none is flagged, that
///    one — it is unambiguous, there is nothing else the default could be;
/// 3. otherwise `AmbiguousDefault`, because choosing among several unflagged DNNs
///    would invent an answer the subscription does not give.
fn select_default_dnn(
    smf_sel_data: &serde_json::Value,
    sst: u8,
    sd: Option<&str>,
) -> Result<String, DefaultDnnError> {
    // `subscribedSnssaiInfos` is keyed by the TS 29.571 S-NSSAI string form:
    // `{sst:02x}` or `{sst:02x}-{sd}` (udrd's `build_smf_selection_data`).
    let key = match sd {
        Some(sd) => format!("{sst:02x}-{sd}"),
        None => format!("{sst:02x}"),
    };
    let infos = smf_sel_data.get("subscribedSnssaiInfos");
    // Fall back to the key with no SD when the exact key is absent: a subscription
    // provisioned without an SD still applies to a request that carries one, the
    // same widening `nsacfd`'s quota lookup does.
    let entry = infos
        .and_then(|i| i.get(&key))
        .or_else(|| infos.and_then(|i| i.get(format!("{sst:02x}"))));

    let dnn_infos = entry
        .and_then(|e| e.get("dnnInfos"))
        .and_then(|v| v.as_array())
        .ok_or(DefaultDnnError::NoSubscribedDnn)?;

    let named: Vec<&serde_json::Value> = dnn_infos
        .iter()
        .filter(|i| i.get("dnn").and_then(|v| v.as_str()).is_some())
        .collect();
    if named.is_empty() {
        return Err(DefaultDnnError::NoSubscribedDnn);
    }
    if let Some(flagged) = named
        .iter()
        .find(|i| i.get("defaultDnnIndicator").and_then(|v| v.as_bool()) == Some(true))
    {
        let dnn = flagged["dnn"].as_str().unwrap_or_default().to_string();
        log::info!("subscribed default DNN '{dnn}' (defaultDnnIndicator) for SST {sst}");
        return Ok(dnn);
    }
    if named.len() == 1 {
        let dnn = named[0]["dnn"].as_str().unwrap_or_default().to_string();
        log::info!(
            "subscribed default DNN '{dnn}' for SST {sst}: the only DNN subscribed for this \
             S-NSSAI, and none carries defaultDnnIndicator"
        );
        return Ok(dnn);
    }
    Err(DefaultDnnError::AmbiguousDefault(
        named
            .iter()
            .filter_map(|i| i["dnn"].as_str().map(String::from))
            .collect(),
    ))
}

/// The `Nudm_SDM_Get smf-select-data` request path.
///
/// **No `single-nssai` query parameter, deliberately.** TS 29.503 §5.2.2.2.1 lets a
/// consumer scope the answer to one S-NSSAI, and doing so would be tidier — but the
/// value is JSON, so on the wire it must be percent-encoded as an RFC 3986 query
/// component, and this tree's shared SBI server stores query values **verbatim
/// without decoding them** (`libs/nextgcore-sbi/src/server.rs:583`, which is the gap
/// issue #65 names). So a percent-encoded `single-nssai` reaches the in-tree UDM as
/// the literal `%7B%22sst%22...` and cannot be parsed, while sending it unencoded
/// would be invalid on the wire. Neither is acceptable, and scoping is an
/// optimisation rather than a correctness requirement: `select_default_dnn` picks the
/// S-NSSAI's entry out of `subscribedSnssaiInfos` by key regardless. Add the
/// parameter once #65 makes query decoding work.
///
/// Nudm_SDM is at **v2** (TS 29.503 §6.1.1), unlike the other Nudm services.
fn smf_select_data_path(supi: &str, _sst: u8, _sd: Option<&str>) -> String {
    format!(
        "/nudm-sdm/v2/{supi}/{}",
        nextgcore_sbi::constants::resource::SMF_SELECT_DATA
    )
}

/// Nudm_SDM_Get (`smf-sel-data`) → the subscribed default DNN for this S-NSSAI
/// (TS 29.503 §5.2.2.2, TS 23.501 §5.6.1).
///
/// Issue #204: called only when `SmContextCreateData` carries no `dnn`. The
/// literal `"internet"` the AMF used to substitute meant any deployment whose
/// subscribers do not all default to a DNN named `internet` attached DNN-less
/// sessions to the WRONG data network — silently, since the session established
/// fine against it.
async fn fetch_subscribed_default_dnn(
    supi: &str,
    sst: u8,
    sd: Option<&str>,
) -> Result<String, DefaultDnnError> {
    let (host, port) = discover_udm_sdm_endpoint()
        .await
        .ok_or(DefaultDnnError::NoUdmEndpoint)?;
    let client = global_context().get_client(&host, port).await;

    let path = smf_select_data_path(supi, sst, sd);
    let response = client.get(&path).await.map_err(|e| {
        DefaultDnnError::SdmRequestFailed(format!("Nudm_SDM_Get smf-select-data failed: {e}"))
    })?;
    if !response.is_success() {
        return Err(DefaultDnnError::SdmRequestFailed(format!(
            "Nudm_SDM_Get smf-select-data returned status {}",
            response.status
        )));
    }
    let body = response.http.content.as_deref().ok_or_else(|| {
        DefaultDnnError::SdmRequestFailed("empty smf-select-data body".to_string())
    })?;
    let json: serde_json::Value = serde_json::from_str(body).map_err(|e| {
        DefaultDnnError::SdmRequestFailed(format!("smf-select-data is not valid JSON: {e}"))
    })?;
    select_default_dnn(&json, sst, sd)
}

/// Parse host and port from a URI string (e.g., "http://localhost:7777")
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

/// SBI request handler for SMF
async fn smf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("SMF SBI request: {method} {uri}");

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    if parts.len() < 3 {
        return send_not_found("Invalid path", None);
    }

    let service = parts[0];
    let _version = parts[1];
    let resource = parts[2];
    let resource_id = parts.get(3).copied();

    match (service, resource, method) {
        // =====================================================================
        // PDU Session Management Service (nsmf-pdusession)
        // =====================================================================

        // #114: EASDF DNS-message report sink. The SMF advertises this URI as
        // the DNS context's notificationUri, so it must exist -- advertising a
        // callback that 404s is the emit-side-without-a-sink defect this repo has
        // been bitten by before.
        ("nsmf-pdusession", "easdf-dns-reports", "POST") => handle_easdf_dns_report(&request).await,

        // Create SM Context (N11)
        // POST /nsmf-pdusession/v1/sm-contexts
        ("nsmf-pdusession", "sm-contexts", "POST") if resource_id.is_none() => {
            handle_sm_context_create(&request).await
        }

        // Update SM Context
        // POST /nsmf-pdusession/v1/sm-contexts/{smContextRef}/modify
        ("nsmf-pdusession", "sm-contexts", "POST") if parts.len() >= 5 && parts[4] == "modify" => {
            let sm_context_ref = parts[3];
            handle_sm_context_update(sm_context_ref, &request).await
        }

        // Release SM Context
        // POST /nsmf-pdusession/v1/sm-contexts/{smContextRef}/release
        ("nsmf-pdusession", "sm-contexts", "POST") if parts.len() >= 5 && parts[4] == "release" => {
            let sm_context_ref = parts[3];
            handle_sm_context_release(sm_context_ref, Some(&request)).await
        }

        // Retrieve SM Context
        // POST /nsmf-pdusession/v1/sm-contexts/{smContextRef}/retrieve
        ("nsmf-pdusession", "sm-contexts", "POST")
            if parts.len() >= 5 && parts[4] == "retrieve" =>
        {
            let sm_context_ref = parts[3];
            handle_sm_context_retrieve(sm_context_ref).await
        }

        // Create PDU Session
        // POST /nsmf-pdusession/v1/pdu-sessions
        ("nsmf-pdusession", "pdu-sessions", "POST") if resource_id.is_none() => {
            handle_pdu_session_create(&request).await
        }

        // Update PDU Session
        // POST /nsmf-pdusession/v1/pdu-sessions/{pduSessionRef}/modify
        ("nsmf-pdusession", "pdu-sessions", "POST") if parts.len() >= 5 && parts[4] == "modify" => {
            let pdu_session_ref = parts[3];
            handle_pdu_session_update(pdu_session_ref).await
        }

        // Release PDU Session
        // POST /nsmf-pdusession/v1/pdu-sessions/{pduSessionRef}/release
        ("nsmf-pdusession", "pdu-sessions", "POST")
            if parts.len() >= 5 && parts[4] == "release" =>
        {
            let pdu_session_ref = parts[3];
            handle_pdu_session_release(pdu_session_ref).await
        }

        // =====================================================================
        // Event Exposure Service (nsmf-event-exposure)
        // =====================================================================

        // Nsmf_EventExposure (TS 29.508 §4.2.2), #79: a subscription is a
        // PERSISTED resource, so the collection takes POST and the individual
        // resource takes GET / PUT / DELETE. Before #79 only POST and DELETE
        // existed and neither touched any store.
        //
        // POST /nsmf-event-exposure/v1/subscriptions
        ("nsmf-event-exposure", "subscriptions", "POST") if resource_id.is_none() => {
            handle_event_subscribe(&request).await
        }

        // GET /nsmf-event-exposure/v1/subscriptions/{subId}
        ("nsmf-event-exposure", "subscriptions", "GET") => match resource_id {
            Some(sub_id) => handle_event_subscription_get(sub_id).await,
            None => send_bad_request("Missing subscription ID", None),
        },

        // PUT /nsmf-event-exposure/v1/subscriptions/{subId}
        ("nsmf-event-exposure", "subscriptions", "PUT") => match resource_id {
            Some(sub_id) => handle_event_subscription_put(sub_id, &request).await,
            None => send_bad_request("Missing subscription ID", None),
        },

        // DELETE /nsmf-event-exposure/v1/subscriptions/{subId}
        ("nsmf-event-exposure", "subscriptions", "DELETE") => {
            if let Some(sub_id) = resource_id {
                handle_event_unsubscribe(sub_id).await
            } else {
                send_bad_request("Missing subscription ID", None)
            }
        }

        // =====================================================================
        // Callback handlers (from other NFs)
        // =====================================================================

        // SM Policy Update/Terminate Notification (from PCF, TS 29.512
        // §4.2.3/§4.2.4: POST {notificationUri}/update | /terminate)
        ("nsmf-callback", "sm-policy-notify", "POST") => {
            if let Some(sm_context_ref) = resource_id {
                let action = parts.get(4).copied().unwrap_or("update");
                match action {
                    "update" => handle_sm_policy_notify(sm_context_ref, &request).await,
                    "terminate" => handle_sm_policy_terminate(sm_context_ref).await,
                    other => send_bad_request(&format!("Unknown notify action '{other}'"), None),
                }
            } else {
                send_bad_request("Missing SM context reference", None)
            }
        }

        // #293: Nudm_SDM_Notification sink (TS 29.503 §5.2.2.6). The SMF chooses
        // this URI when it subscribes, so its shape is ours: per SM context, so a
        // notification names the live session it has to be applied to. The route
        // exists BEFORE any subscribe is sent -- a subscription whose callback 404s
        // is strictly worse than no subscription, because the UDM then retries
        // against us.
        ("nsmf-callback", "sdm-notify", "POST") => {
            if let Some(sm_context_ref) = resource_id {
                handle_sdm_notification(sm_context_ref, &request).await
            } else {
                send_bad_request("Missing SM context reference", None)
            }
        }

        // N1N2 Transfer Failure Notification (from AMF)
        ("nsmf-callback", "n1-n2-failure", "POST") => {
            if let Some(sm_context_ref) = resource_id {
                handle_n1n2_transfer_failure(sm_context_ref).await
            } else {
                send_bad_request("Missing SM context reference", None)
            }
        }

        // AMF Status Change Notification
        ("nsmf-callback", "amf-status", "POST") => {
            if let Some(sm_context_ref) = resource_id {
                handle_amf_status_change(sm_context_ref).await
            } else {
                send_bad_request("Missing SM context reference", None)
            }
        }

        // Default: unknown endpoint
        _ => {
            log::warn!("Unknown SBI endpoint: {method} {path}");
            send_not_found("Unknown endpoint", None)
        }
    }
}

// =============================================================================
// PFCP Client (N4 to UPF)
// =============================================================================

/// PFCP Session Establishment result from UPF
struct PfcpSessionResult {
    upf_seid: u64,
    upf_teid: u32,
    upf_addr: [u8; 4],
}

/// QoS applied to the N4 session, derived from the PCF SM policy decision
/// (or the documented config-default when no PCF is configured).
struct SessionQos {
    qfi: u8,
    ambr_ul_bps: u64,
    ambr_dl_bps: u64,
    /// When the authorized flow is an XR delay-critical GBR 5QI (82-85), the
    /// XR flow parameters that drive a dedicated XR QER in the PFCP session.
    xr_flow: Option<XrSessionFlow>,
}

/// XR delay-critical GBR flow carried into the PFCP QER/PDR setup.
struct XrSessionFlow {
    five_qi: u8,
    gbr_ul_bps: u64,
    gbr_dl_bps: u64,
}

/// Build a `binding::SessionPolicy` from a parsed `PolicyDecision` so the
/// XR-aware QoS-flow binding can inspect the authorized 5QI/GBR.
///
/// The decision's PCC rules carry per-rule 5QI + GBR; when none are present
/// (config-default), a synthetic rule from the default 5QI is emitted so an XR
/// default 5QI still produces an XR flow.
fn decision_to_session_policy(decision: &policy::PolicyDecision) -> binding::SessionPolicy {
    let mut sp = binding::SessionPolicy::new();
    let mk_rule =
        |id: &str, five_qi: u8, arp: u8, gbr_ul: u64, gbr_dl: u64, mbr_ul: u64, mbr_dl: u64| {
            let mut rule = binding::PccRule::new_5gc_install(id);
            rule.set_qos(binding::PccQos {
                qci: five_qi,
                arp: binding::ArpParams {
                    priority_level: arp,
                    pre_emption_capability: binding::is_xr_5qi(five_qi),
                    pre_emption_vulnerability: false,
                },
                mbr: binding::BitRate {
                    uplink: mbr_ul,
                    downlink: mbr_dl,
                },
                gbr: binding::BitRate {
                    uplink: gbr_ul,
                    downlink: gbr_dl,
                },
            });
            rule
        };

    if decision.pcc_rules.is_empty() {
        sp.add_rule(mk_rule(
            "default",
            decision.def_five_qi,
            decision.arp_priority_level,
            0,
            0,
            decision.sess_ambr_ul_bps,
            decision.sess_ambr_dl_bps,
        ));
    } else {
        for r in &decision.pcc_rules {
            sp.add_rule(mk_rule(
                &r.id,
                r.five_qi,
                decision.arp_priority_level,
                r.gbr_ul_bps.unwrap_or(0),
                r.gbr_dl_bps.unwrap_or(0),
                r.mbr_ul_bps.unwrap_or(decision.sess_ambr_ul_bps),
                r.mbr_dl_bps.unwrap_or(decision.sess_ambr_dl_bps),
            ));
        }
    }
    sp
}

/// Send PFCP Session Establishment Request to UPF and return UPF TEID.
///
/// The QER enforcing the authorized Session-AMBR (TS 29.512 authSessAmbr →
/// TS 29.244 MBR) and the QFI come from `qos` — no hardcoded values.
async fn pfcp_session_establish(
    smf_n4_seid: u64,
    ue_ip: [u8; 4],
    dnn: &str,
    sst: u8,
    qos: &SessionQos,
) -> Result<PfcpSessionResult> {
    use n4_build::{pfcp_ie, FarParams, PdrParams, PfcpMessageBuilder, QerParams};

    // Issue #20: pick the UPF for this NEW session — the least-loaded
    // associated pool peer when the compute-aware-upf feature is enabled,
    // the sole/default client otherwise (identical to the legacy path).
    let client = pfcp_path::select_upf()
        .await
        .ok_or_else(|| anyhow::anyhow!("PFCP client not initialised"))?;

    // TS 29.244 6.2.6.2: no session signalling without an association
    if !client.is_associated().await {
        anyhow::bail!("no established PFCP association with {}", client.peer());
    }

    log::info!(
        "PFCP Session Establishment: UPF={}, UE IP={}.{}.{}.{}",
        client.peer(),
        ue_ip[0],
        ue_ip[1],
        ue_ip[2],
        ue_ip[3]
    );

    // Build PFCP payload: Node ID + F-SEID + Create PDR (uplink) + Create FAR
    // (uplink) + Create PDR (downlink) + Create FAR (downlink)
    let smf_ip = client.node_ip();
    let mut builder = PfcpMessageBuilder::new();

    // Node ID (IPv4, with the mandatory Node ID Type octet — TS 29.244 8.2.38)
    builder.add_node_id_ipv4(smf_ip);

    // F-SEID (SMF's SEID)
    builder.add_f_seid(smf_n4_seid, Some(smf_ip), None);

    // APN/DNN
    builder.add_apn_dnn(dnn);

    // S-NSSAI
    builder.add_s_nssai(sst, None);

    // Create QER 1: enforce the authorized Session-AMBR (MBR UL/DL) on the
    // default QoS flow. Gates open in both directions.
    let session_qer = QerParams {
        qer_id: 1,
        gate_status: (0, 0),
        mbr: Some((qos.ambr_ul_bps, qos.ambr_dl_bps)),
        gbr: None,
        qfi: Some(qos.qfi),
    };
    let qer_bytes = n4_build::build_create_qer(&session_qer);
    builder.add_tlv(pfcp_ie::CREATE_QER, &qer_bytes);

    // Create QER 2 (XR delay-critical GBR, TS 23.501 §5.7.4 / TS 29.244 5.4.1):
    // when the authorized flow is an XR 5QI (82-85), install a dedicated QER
    // carrying the guaranteed bit rate so the UPF arms guaranteed-rate buckets
    // and never starves the XR flow. The XR QFI tags the GTP-U packets for
    // DSCP marking (EF/AF41) at the UPF. Gates open in both directions.
    let xr_qer_id: u32 = 2;
    if let Some(ref xr) = qos.xr_flow {
        let xr_qer = QerParams {
            qer_id: xr_qer_id,
            gate_status: (0, 0),
            mbr: Some((qos.ambr_ul_bps, qos.ambr_dl_bps)),
            // GBR set marks this as a delay-critical guaranteed-rate (XR) flow;
            // the UPF recognizes XR from the GBR (the XR 5QI 82-85 cannot
            // survive the 6-bit PFCP QFI, so GBR is the wire-stable signal).
            gbr: Some((xr.gbr_ul_bps, xr.gbr_dl_bps)),
            qfi: Some(xr.five_qi & 0x3F),
        };
        let xr_qer_bytes = n4_build::build_create_qer(&xr_qer);
        builder.add_tlv(pfcp_ie::CREATE_QER, &xr_qer_bytes);
        log::info!(
            "PFCP: installing XR QER {} (5QI={}, GBR UL/DL={}/{} bps)",
            xr_qer_id,
            xr.five_qi,
            xr.gbr_ul_bps,
            xr.gbr_dl_bps
        );
    }
    // PDRs bind to the XR QER when present, otherwise the Session-AMBR QER.
    let flow_qer_id = if qos.xr_flow.is_some() { xr_qer_id } else { 1 };
    let flow_qfi = qos
        .xr_flow
        .as_ref()
        .map(|x| x.five_qi & 0x3F)
        .unwrap_or(qos.qfi);

    // Create PDR 1 (Uplink): UE -> UPF -> DN
    let ul_pdr = PdrParams {
        pdr_id: 1,
        precedence: 100,
        source_interface: 0,                            // Access
        f_teid: Some((0, None, None)),                  // teid=0: UPF allocates
        ue_ip_address: Some((Some(ue_ip), None, true)), // source
        outer_header_removal: Some(0),                  // GTP-U/UDP/IPv4
        far_id: Some(1),
        qer_id: Some(flow_qer_id),
        qfi: Some(flow_qfi),
        ..Default::default()
    };
    let ul_pdr_bytes = n4_build::build_create_pdr(&ul_pdr);
    builder.add_tlv(pfcp_ie::CREATE_PDR, &ul_pdr_bytes);

    // Create FAR 1 (Uplink): Forward to DN
    let ul_far = FarParams {
        far_id: 1,
        apply_action: 0x02,             // FORW (forward)
        destination_interface: Some(2), // SGi-LAN/N6 (TS 29.244 8.2.25)
        ..Default::default()
    };
    let ul_far_bytes = n4_build::build_create_far(&ul_far);
    builder.add_tlv(pfcp_ie::CREATE_FAR, &ul_far_bytes);

    // Create PDR 2 (Downlink): DN -> UPF -> UE (initially buffered, FAR updated after gNB responds)
    let dl_pdr = PdrParams {
        pdr_id: 2,
        precedence: 100,
        source_interface: 1, // Core (TS 29.244 8.2.24)
        ue_ip_address: Some((Some(ue_ip), None, false)), // destination
        far_id: Some(2),
        qer_id: Some(flow_qer_id),
        qfi: Some(flow_qfi),
        ..Default::default()
    };
    let dl_pdr_bytes = n4_build::build_create_pdr(&dl_pdr);
    builder.add_tlv(pfcp_ie::CREATE_PDR, &dl_pdr_bytes);

    // Create FAR 2 (Downlink): Buffer initially (will be updated with gNB TEID)
    let dl_far = FarParams {
        far_id: 2,
        apply_action: 0x04,             // BUFF (buffer)
        destination_interface: Some(0), // Access
        ..Default::default()
    };
    let dl_far_bytes = n4_build::build_create_far(&dl_far);
    builder.add_tlv(pfcp_ie::CREATE_FAR, &dl_far_bytes);

    let payload = builder.build();

    // Send through the transaction engine: T1 retransmission up to N1
    // attempts, exhaustion = error (TS 29.244 7.2.1). SEID=0 for a new
    // session (TS 29.244 7.2.2.4.2).
    let (resp_type, resp_body) = client
        .request(
            pfcp_path::pfcp_message_type::SESSION_ESTABLISHMENT_REQUEST,
            Some(0),
            &payload,
        )
        .await
        .map_err(|e| anyhow::anyhow!("PFCP Session Establishment failed: {e}"))?;

    if resp_type != pfcp_path::pfcp_message_type::SESSION_ESTABLISHMENT_RESPONSE {
        anyhow::bail!("unexpected PFCP response type {resp_type} to Session Establishment");
    }

    // Cause check: any non-accepted cause is a hard failure with the real
    // cause value surfaced (no silent fallback)
    match pfcp_path::parse_cause(&resp_body) {
        Some(pfcp_path::pfcp_cause::REQUEST_ACCEPTED) => {}
        Some(cause) => anyhow::bail!(
            "PFCP Session Establishment rejected: cause {cause} ({})",
            pfcp_path::cause_name(cause)
        ),
        None => anyhow::bail!("PFCP Session Establishment Response missing mandatory Cause IE"),
    }

    let resp_payload = &resp_body[..];

    // Parse response IEs to find UP F-SEID and Created PDR with F-TEID
    let mut upf_seid: u64 = 0;
    let mut upf_teid: u32 = 0;
    let mut upf_ip: [u8; 4] = [127, 0, 0, 1];

    let mut offset = 0;
    while offset + 4 <= resp_payload.len() {
        let ie_type = u16::from_be_bytes([resp_payload[offset], resp_payload[offset + 1]]);
        let ie_len =
            u16::from_be_bytes([resp_payload[offset + 2], resp_payload[offset + 3]]) as usize;
        let ie_start = offset + 4;
        let ie_end = ie_start + ie_len;
        if ie_end > resp_payload.len() {
            break;
        }

        let ie_value = &resp_payload[ie_start..ie_end];

        match ie_type {
            57 => {
                // F-SEID (0x0039)
                if ie_value.len() >= 9 {
                    let flags = ie_value[0];
                    upf_seid = u64::from_be_bytes(ie_value[1..9].try_into().unwrap());
                    if flags & 0x02 != 0 && ie_value.len() >= 13 {
                        upf_ip = [ie_value[9], ie_value[10], ie_value[11], ie_value[12]];
                    }
                    log::info!(
                        "UPF F-SEID: seid=0x{:016x}, ip={}.{}.{}.{}",
                        upf_seid,
                        upf_ip[0],
                        upf_ip[1],
                        upf_ip[2],
                        upf_ip[3]
                    );
                }
            }
            8 => {
                // Created PDR (0x0008)
                // Parse inner IEs of Created PDR group
                let mut inner_off = 0;
                while inner_off + 4 <= ie_value.len() {
                    let inner_type =
                        u16::from_be_bytes([ie_value[inner_off], ie_value[inner_off + 1]]);
                    let inner_len =
                        u16::from_be_bytes([ie_value[inner_off + 2], ie_value[inner_off + 3]])
                            as usize;
                    let inner_start = inner_off + 4;
                    let inner_end = inner_start + inner_len;
                    if inner_end > ie_value.len() {
                        break;
                    }

                    if inner_type == 21 {
                        // F-TEID (0x0015)
                        let fteid_val = &ie_value[inner_start..inner_end];
                        if fteid_val.len() >= 5 {
                            let fteid_flags = fteid_val[0];
                            let teid = u32::from_be_bytes(fteid_val[1..5].try_into().unwrap());
                            // TS 29.244 §8.2.3 Fig 8.2.3-1, octet 5: Bit1 (0x01) = V4,
                            // Bit2 (0x02) = V6. The IPv4 address (when present) is the
                            // first address field, immediately after the 4-byte TEID.
                            // NOTE: F-TEID's V4=Bit1 is the OPPOSITE of F-SEID (§8.2.37),
                            // which uses Bit2 for V4 — see the F-SEID parse above.
                            if fteid_flags & 0x01 != 0 && fteid_val.len() >= 9 {
                                upf_ip = [fteid_val[5], fteid_val[6], fteid_val[7], fteid_val[8]];
                            }
                            if teid != 0 {
                                upf_teid = teid;
                                log::info!("UPF F-TEID: teid=0x{upf_teid:08x}");
                            }
                        }
                    }
                    inner_off = inner_end;
                }
            }
            _ => {}
        }
        offset = ie_end;
    }

    if upf_seid == 0 {
        anyhow::bail!("PFCP Session Establishment Response missing UP F-SEID (mandatory IE)");
    }
    if upf_teid == 0 {
        // Conditional IE failure: with FTUP the UPF must return the
        // allocated F-TEID in a Created PDR (TS 29.244 7.5.3.2)
        anyhow::bail!("PFCP Session Establishment Response missing Created PDR F-TEID");
    }

    log::info!("PFCP Session Established: UPF SEID=0x{upf_seid:016x}, UPF TEID=0x{upf_teid:08x}");

    // Issue #20: remember which UPF this session was established on so
    // modification/deletion keep signalling the same peer. Keyed by the
    // SMF-side SEID: UPF-chosen SEIDs collide across a multi-UPF pool.
    pfcp_path::record_session_peer(smf_n4_seid, client.peer());

    Ok(PfcpSessionResult {
        upf_seid,
        upf_teid,
        upf_addr: upf_ip,
    })
}

/// Send PFCP Session Modification Request to UPF to activate DL FAR with gNB TEID
async fn pfcp_session_modify(
    smf_n4_seid: u64,
    upf_seid: u64,
    gnb_teid: u32,
    gnb_addr: [u8; 4],
) -> Result<()> {
    use n4_build::{build_session_modification_request, SessionModificationParams};

    let client = pfcp_path::client_for_session(smf_n4_seid)
        .ok_or_else(|| anyhow::anyhow!("PFCP client not initialised"))?;
    if !client.is_associated().await {
        anyhow::bail!("no established PFCP association with {}", client.peer());
    }

    log::info!(
        "PFCP Session Modification: UPF SEID=0x{:016x}, gNB TEID=0x{:08x}, gNB addr={}.{}.{}.{}",
        upf_seid,
        gnb_teid,
        gnb_addr[0],
        gnb_addr[1],
        gnb_addr[2],
        gnb_addr[3]
    );

    // Build modification: update FAR 2 (downlink) from BUFF to FORW with outer header creation (GTP-U to gNB)
    // outer_header_creation: (description, teid, ipv4, ipv6)
    // description 0x0100 = GTP-U/UDP/IPv4
    let params = SessionModificationParams {
        update_fars_activate: vec![(
            2,                                              // FAR ID 2 (downlink)
            0,                                              // destination_interface: Access
            Some((0x0100, gnb_teid, Some(gnb_addr), None)), // outer header creation: GTP-U to gNB
            true, // SNDEM: End Marker packets on the old tunnel
        )],
        ..Default::default()
    };

    let payload = build_session_modification_request(&params);

    let (resp_type, resp_body) = client
        .request(
            pfcp_path::pfcp_message_type::SESSION_MODIFICATION_REQUEST,
            Some(upf_seid),
            &payload,
        )
        .await
        .map_err(|e| anyhow::anyhow!("PFCP Session Modification failed: {e}"))?;

    if resp_type != pfcp_path::pfcp_message_type::SESSION_MODIFICATION_RESPONSE {
        anyhow::bail!("unexpected PFCP response type {resp_type} to Session Modification");
    }
    match pfcp_path::parse_cause(&resp_body) {
        Some(pfcp_path::pfcp_cause::REQUEST_ACCEPTED) => {
            log::info!("PFCP Session Modification successful");
            Ok(())
        }
        Some(cause) => anyhow::bail!(
            "PFCP Session Modification rejected: cause {cause} ({})",
            pfcp_path::cause_name(cause)
        ),
        None => anyhow::bail!("PFCP Session Modification Response missing mandatory Cause IE"),
    }
}

/// Send PFCP Session Deletion Request to UPF
async fn pfcp_session_delete(smf_n4_seid: u64, upf_seid: u64) -> Result<()> {
    let client = pfcp_path::client_for_session(smf_n4_seid)
        .ok_or_else(|| anyhow::anyhow!("PFCP client not initialised"))?;
    if !client.is_associated().await {
        anyhow::bail!("no established PFCP association with {}", client.peer());
    }

    log::info!("PFCP Session Deletion: UPF SEID=0x{upf_seid:016x}");

    // Session Deletion Request has no message-body IEs (TS 29.244 7.5.6)
    let payload = n4_build::build_session_deletion_request();

    let (resp_type, resp_body) = client
        .request(
            pfcp_path::pfcp_message_type::SESSION_DELETION_REQUEST,
            Some(upf_seid),
            &payload,
        )
        .await
        .map_err(|e| anyhow::anyhow!("PFCP Session Deletion failed: {e}"))?;

    if resp_type != pfcp_path::pfcp_message_type::SESSION_DELETION_RESPONSE {
        anyhow::bail!("unexpected PFCP response type {resp_type} to Session Deletion");
    }
    match pfcp_path::parse_cause(&resp_body) {
        Some(pfcp_path::pfcp_cause::REQUEST_ACCEPTED) => {
            // Issue #20: the session is gone — drop its UPF binding.
            pfcp_path::forget_session_peer(smf_n4_seid);
            log::info!("PFCP Session Deletion successful");
            Ok(())
        }
        Some(cause) => anyhow::bail!(
            "PFCP Session Deletion rejected: cause {cause} ({})",
            pfcp_path::cause_name(cause)
        ),
        None => anyhow::bail!("PFCP Session Deletion Response missing mandatory Cause IE"),
    }
}

// =============================================================================
// SM Context Handlers
// =============================================================================

/// Build a ProblemDetails 400 response (TS 29.500 §5.2.7).
/// A 404 ProblemDetails, for an operation naming an SM context that does not
/// exist (TS 29.502 `CONTEXT_NOT_FOUND`).
fn problem_404(cause: &str, detail: &str) -> SbiResponse {
    let body = serde_json::json!({
        "status": 404,
        "cause": cause,
        "detail": detail,
    });
    SbiResponse::with_status(404).with_body(body.to_string(), "application/problem+json")
}

fn problem_400(cause: &str, detail: &str) -> SbiResponse {
    problem_response(400, cause, detail)
}

/// A ProblemDetails answer at any status (TS 29.500 §5.2.7, TS 29.571 §5.2.4.1).
///
/// `application/problem+json`, because a consumer that deserialises the body as
/// ProblemDetails is entitled to that content type — and because a bare
/// `{"status":..,"cause":..}` at `application/json` (which is what the SM context
/// 404 used to send) gives it nothing typed to work with (#78).
fn problem_response(status: u16, cause: &str, detail: &str) -> SbiResponse {
    let body = serde_json::json!({
        "status": status,
        "cause": cause,
        "detail": detail,
    });
    SbiResponse::with_status(status).with_body(body.to_string(), "application/problem+json")
}

/// Resolve an N1 (NAS) or N2 (NGAP) binary payload referenced from the JSON
/// root of an inbound SBI request, accepting BOTH the conformant
/// multipart/related form and the legacy base64-in-JSON form.
///
/// Per TS 29.502 §6.1.2.2.2 / §6.1.2.4 the JSON attribute is a RefToBinaryData
/// pointer (`{ "contentId": "<id>" }`) and the bytes live in the multipart
/// binary part whose `Content-Id` equals `<id>` (carried on
/// `request.http.parts`). When no matching part is present the attribute is
/// read as a base64 string — the form the matched-sim AMF previously emitted —
/// so both wire encodings interoperate without an E2E flip.
fn resolve_binary_ref(request: &SbiRequest, field: &serde_json::Value) -> Option<Vec<u8>> {
    if let Some(content_id) = field["contentId"].as_str() {
        if let Some(part) = request
            .http
            .parts
            .iter()
            .find(|p| p.content_id.as_deref() == Some(content_id))
        {
            return Some(part.data.to_vec());
        }
    }
    if let Some(b64) = field.as_str() {
        use base64::Engine;
        return base64::engine::general_purpose::STANDARD.decode(b64).ok();
    }
    None
}

/// Build a multipart/related SBI response carrying the N1 (PDU session NAS,
/// `application/vnd.3gpp.5gnas`) and N2 (NGAP transfer,
/// `application/vnd.3gpp.ngap`) payloads as binary parts referenced from the
/// JSON root by RefToBinaryData pointers (TS 29.502 §6.1.2.2.2 / §6.1.2.4).
///
/// `json_root` provides the SmContext* JSON attributes (e.g. `smContextRef`,
/// `n2SmInfoType`); the `n1SmMsg` / `n2SmInfo` attributes are overwritten here
/// with their `{ "contentId": ... }` references. Keeping N1/N2 IN the response
/// matches the current SMF behaviour (the separate Namf_Communication transfer
/// is smfd-03, out of scope).
fn sbi_response_with_n1_n2(
    status: u16,
    mut json_root: serde_json::Value,
    n1_sm_msg: &[u8],
    n2_sm_info: &[u8],
) -> SbiResponse {
    use nextgcore_sbi::constants::content_type;
    use nextgcore_sbi::message::SbiPart;
    json_root["n1SmMsg"] = serde_json::json!({ "contentId": "n1SmMsg" });
    json_root["n2SmInfo"] = serde_json::json!({ "contentId": "n2SmInfo" });
    SbiResponse::with_status(status)
        .with_body(json_root.to_string(), content_type::APPLICATION_JSON)
        .with_part(SbiPart::with_content(
            "n1SmMsg",
            content_type::APPLICATION_5GNAS,
            bytes::Bytes::copy_from_slice(n1_sm_msg),
        ))
        .with_part(SbiPart::with_content(
            "n2SmInfo",
            content_type::APPLICATION_NGAP,
            bytes::Bytes::copy_from_slice(n2_sm_info),
        ))
}

/// Build the N2 SM `PDUSessionResourceSetupRequestTransfer` (TS 38.413
/// §9.3.4.1) carrying the UPF N3 GTP-U F-TEID and the QoS flow setup list,
/// using the real-APER `nextgcore-ngap` transfer codec (not bespoke bytes).
fn build_setup_request_transfer(
    upf_teid: u32,
    upf_addr: [u8; 4],
    qfi: u8,
    five_qi: u16,
    arp_priority_level: u8,
) -> nextgcore_ngap::NgapResult<Vec<u8>> {
    use nextgcore_ngap::transfer::{
        AllocationAndRetentionPriority, GtpTunnel, NonDynamic5qiDescriptor,
        PduSessionResourceSetupRequestTransfer, PduSessionType, PreEmptionCapability,
        PreEmptionVulnerability, QosCharacteristics, QosFlowLevelQosParameters,
        QosFlowSetupRequestItem, TransportLayerAddress, UpTransportLayerInformation,
    };

    let transfer = PduSessionResourceSetupRequestTransfer {
        pdu_session_aggregate_maximum_bit_rate: None,
        ul_ngu_up_tnl_information: UpTransportLayerInformation::GtpTunnel(GtpTunnel {
            transport_layer_address: TransportLayerAddress::from_ipv4(upf_addr),
            gtp_teid: upf_teid.to_be_bytes(),
        }),
        data_forwarding_not_possible: false,
        pdu_session_type: PduSessionType::Ipv4,
        security_indication: None,
        network_instance: None,
        qos_flow_setup_request_list: vec![QosFlowSetupRequestItem {
            qos_flow_identifier: qfi,
            qos_flow_level_qos_parameters: QosFlowLevelQosParameters {
                qos_characteristics: QosCharacteristics::NonDynamic5qi(
                    NonDynamic5qiDescriptor::new(five_qi),
                ),
                allocation_and_retention_priority: AllocationAndRetentionPriority {
                    priority_level_arp: arp_priority_level,
                    pre_emption_capability: PreEmptionCapability::ShallNotTriggerPreEmption,
                    pre_emption_vulnerability: PreEmptionVulnerability::NotPreEmptable,
                },
                gbr_qos_information: None,
                reflective_qos_attribute: false,
                additional_qos_flow_information: false,
            },
            e_rab_id: None,
        }],
    };
    transfer.encode()
}

/// Build a real-APER `PDUSessionResourceModifyRequestTransfer` (TS 38.413
/// clause 9.3.4.3) carrying the re-authorized Session-AMBR and the QoS flow to
/// add/modify. Mirrors [`build_setup_request_transfer`]; the gNB's strict APER
/// decoder rejects a hand-rolled byte layout (smfd#2).
fn build_modify_request_transfer(
    qfi: u8,
    ambr_dl_bps: u64,
    ambr_ul_bps: u64,
) -> nextgcore_ngap::NgapResult<Vec<u8>> {
    use nextgcore_ngap::transfer::{
        PduSessionAggregateMaximumBitRate, PduSessionResourceModifyRequestTransfer,
        QosFlowAddOrModifyRequestItem,
    };
    let transfer = PduSessionResourceModifyRequestTransfer {
        pdu_session_aggregate_maximum_bit_rate: Some(PduSessionAggregateMaximumBitRate {
            dl: ambr_dl_bps,
            ul: ambr_ul_bps,
        }),
        ul_ngu_up_tnl_modify_list: Vec::new(),
        network_instance: None,
        qos_flow_add_or_modify_request_list: vec![QosFlowAddOrModifyRequestItem {
            qos_flow_identifier: qfi,
            qos_flow_level_qos_parameters: None,
            e_rab_id: None,
        }],
        qos_flow_to_release_list: Vec::new(),
    };
    transfer.encode()
}

/// Extract the gNB DL GTP-U endpoint (TEID, IPv4 address, first QFI) from a
/// real-APER `PDUSessionResourceSetupResponseTransfer` (TS 38.413 §9.3.4.2).
fn decode_setup_response_dl_endpoint(data: &[u8]) -> Option<(u32, [u8; 4], u8)> {
    use nextgcore_ngap::transfer::{
        PduSessionResourceSetupResponseTransfer, UpTransportLayerInformation,
    };

    let transfer = match PduSessionResourceSetupResponseTransfer::decode(data) {
        Ok(t) => t,
        Err(e) => {
            log::warn!("Failed to decode PDUSessionResourceSetupResponseTransfer: {e:?}");
            return None;
        }
    };
    let UpTransportLayerInformation::GtpTunnel(tunnel) = &transfer
        .dl_qos_flow_per_tnl_information
        .up_transport_layer_information;
    let teid = u32::from_be_bytes(tunnel.gtp_teid);
    let addr = ipv4_from_octets(&tunnel.transport_layer_address.octets)?;
    let qfi = transfer
        .dl_qos_flow_per_tnl_information
        .associated_qos_flow_list
        .first()
        .map(|f| f.qos_flow_identifier)
        .unwrap_or(0);
    Some((teid, addr, qfi))
}

/// Extract the target-gNB DL GTP-U endpoint from a real-APER
/// `PathSwitchRequestTransfer` (TS 38.413 §9.3.4.8) during an Xn handover.
fn decode_path_switch_dl_endpoint(data: &[u8]) -> Option<(u32, [u8; 4], u8)> {
    use nextgcore_ngap::transfer::{PathSwitchRequestTransfer, UpTransportLayerInformation};

    let transfer = match PathSwitchRequestTransfer::decode(data) {
        Ok(t) => t,
        Err(e) => {
            log::warn!("Failed to decode PathSwitchRequestTransfer: {e:?}");
            return None;
        }
    };
    let UpTransportLayerInformation::GtpTunnel(tunnel) = &transfer.dl_ngu_up_tnl_information;
    let teid = u32::from_be_bytes(tunnel.gtp_teid);
    let addr = ipv4_from_octets(&tunnel.transport_layer_address.octets)?;
    let qfi = transfer
        .qos_flow_accepted_list
        .first()
        .copied()
        .unwrap_or(0);
    Some((teid, addr, qfi))
}

/// Coerce a TransportLayerAddress octet vector to an IPv4 quad (None if not 4).
fn ipv4_from_octets(octets: &[u8]) -> Option<[u8; 4]> {
    if octets.len() == 4 {
        Some([octets[0], octets[1], octets[2], octets[3]])
    } else {
        // IPv6 (16) or other widths are not supported for the GTP-U DL path here
        log::warn!(
            "gNB transport address is not IPv4 ({} octets)",
            octets.len()
        );
        None
    }
}

/// Build an SmContextCreateError (TS 29.502 §6.1.6.2.4) carrying a
/// PDU Session Establishment Reject N1 SM container with a 5GSM cause.
fn sm_context_create_error(
    status: u16,
    cause: &str,
    psi: u8,
    pti: u8,
    gsm_cause_5gsm: u8,
) -> SbiResponse {
    use nextgcore_sbi::constants::content_type;
    use nextgcore_sbi::message::SbiPart;
    let n1 = policy::build_establishment_reject(psi, pti, gsm_cause_5gsm);
    // N1-bearing reject: the PDU Session Establishment Reject travels as a
    // 5gnas binary part referenced by RefToBinaryData (TS 29.502 §6.1.2.4).
    let body = serde_json::json!({
        "error": { "status": status, "cause": cause },
        "n1SmMsg": { "contentId": "n1SmMsg" },
    });
    SbiResponse::with_status(status)
        .with_body(body.to_string(), content_type::APPLICATION_JSON)
        .with_part(SbiPart::with_content(
            "n1SmMsg",
            content_type::APPLICATION_5GNAS,
            bytes::Bytes::copy_from_slice(&n1),
        ))
}

/// The SSC modes this SMF actually implements, as the Allowed SSC mode bitmap
/// (bit 1 = mode 1, bit 2 = mode 2, bit 3 = mode 3 — TS 24.501 §9.11.4.16).
///
/// Mode 1 only, and that is a statement about capability rather than a policy
/// choice: SSC modes 2 and 3 require PSA relocation (tear down and re-anchor, or
/// run two anchors in parallel), and this SMF has no such machinery. Echoing the
/// UE's requested mode — the previous behaviour — told the UE it had been granted
/// a session continuity the network cannot deliver, which is worse than a
/// refusal it can act on.
const ALLOWED_SSC_MODE_BITMAP: u8 = 0b001;

/// Authorise the UE's requested SSC mode against [`ALLOWED_SSC_MODE_BITMAP`].
///
/// `Ok(mode)` is the mode to grant; `Err(bitmap)` means refuse with 5GSM cause
/// #68 and this bitmap in the Allowed SSC mode IE. A requested mode of 0 means
/// the UE did not ask (the IE is optional), so the SMF picks its default.
fn authorize_ssc_mode(requested: u8) -> Result<u8, u8> {
    if requested == 0 {
        // No preference expressed: grant the lowest mode this SMF supports.
        return Ok(ALLOWED_SSC_MODE_BITMAP.trailing_zeros() as u8 + 1);
    }
    if !(1..=3).contains(&requested) {
        return Err(ALLOWED_SSC_MODE_BITMAP);
    }
    if ALLOWED_SSC_MODE_BITMAP & (1 << (requested - 1)) != 0 {
        Ok(requested)
    } else {
        Err(ALLOWED_SSC_MODE_BITMAP)
    }
}

/// An establishment reject carrying the Allowed SSC mode IE alongside the cause
/// (TS 24.501 §8.3.3.1), so the UE learns which mode to request instead.
fn sm_context_create_ssc_error(psi: u8, pti: u8, allowed_ssc_bitmap: u8) -> SbiResponse {
    use nextgcore_sbi::constants::content_type;
    use nextgcore_sbi::message::SbiPart;
    let n1 = policy::build_establishment_reject_ext(
        psi,
        pti,
        policy::gsm_cause::NOT_SUPPORTED_SSC_MODE,
        Some(allowed_ssc_bitmap),
    );
    let body = serde_json::json!({
        "error": { "status": 403, "cause": "SSC_MODE_NOT_SUPPORTED" },
        "n1SmMsg": { "contentId": "n1SmMsg" },
    });
    SbiResponse::with_status(403)
        .with_body(body.to_string(), content_type::APPLICATION_JSON)
        .with_part(SbiPart::with_content(
            "n1SmMsg",
            content_type::APPLICATION_5GNAS,
            bytes::Bytes::copy_from_slice(&n1),
        ))
}

/// Dispatch an Npcf_SMPolicyControl client response into a session's GSM FSM
/// (drives Wait5gcSmPolicyAssociation → WaitPfcpEstablishment / N1N2Reject5gc).
fn fsm_dispatch_policy_response(fsm: &mut gsm_sm::GsmFsm, status: u16) {
    let mut ev = event::SmfEvent::sbi_client(event::SbiResponse { status, body: None }, 0);
    if let Some(ref mut sbi) = ev.sbi {
        sbi.message = Some(event::SbiMessage {
            service_name: "npcf-smpolicycontrol".to_string(),
            res_status: Some(status),
            ..Default::default()
        });
    }
    fsm.dispatch(&ev);
}

/// Validate the mandatory / conditionally-mandatory IEs of an inbound
/// SmContextCreateData (TS 29.502 Table 6.1.6.2.2-1). Returns the
/// ProblemDetails `cause` (all map to HTTP 400) for the FIRST violation, or
/// `None` when the body satisfies the mandatory-IE policy. smfd-06.
///
/// DEFAULT-PERMISSIVE on `supi` and `anType`: the matched-sim AMF omits both
/// (no NF-set / emergency context yet), so they are treated as
/// conditional-absent rather than rejected — a documented migration shim. The
/// genuinely-mandatory IEs for a create — `pduSessionId`, `dnn`, `sNssai.sst`
/// and the `n1SmMsg` container — are enforced strictly (the matched-sim AMF
/// always supplies them, so the happy path is unaffected).
fn validate_sm_context_create_data(body: &serde_json::Value) -> Option<&'static str> {
    // pduSessionId (M, range 1..=15)
    let psi_ok = body["pduSessionId"]
        .as_u64()
        .map(|p| (1..=15).contains(&p))
        .unwrap_or(false);
    if !psi_ok {
        return Some("MANDATORY_IE_INCORRECT");
    }
    // `dnn` is OPTIONAL (TS 29.502 Table 6.1.6.2.2-1), and issue #204 stopped
    // treating it as mandatory here: when the UE omits the DNN IE the AMF now
    // omits the member, and the SMF resolves the SUBSCRIBED DEFAULT DNN from SM
    // subscription data instead (`fetch_subscribed_default_dnn`). Rejecting it at
    // this validator would make that unreachable. A present-but-empty `dnn` is
    // still wrong, and is caught in the handler.
    //
    // sNssai.sst (M)
    if body["sNssai"]["sst"].as_u64().is_none() {
        return Some("MANDATORY_IE_MISSING");
    }
    // n1SmMsg (C — required at establishment): present either as a
    // RefToBinaryData pointer ({contentId}) or as a legacy base64 string.
    let n1 = &body["n1SmMsg"];
    if n1["contentId"].as_str().is_none() && n1.as_str().is_none() {
        return Some("N1_SM_ERROR");
    }
    None
}

/// Handle SM Context Create (from AMF via N11, TS 29.502 §5.2.2.2)
async fn handle_sm_context_create(request: &SbiRequest) -> SbiResponse {
    log::info!("SM Context Create request received");

    // Parse request body
    let req_body: serde_json::Value = match &request.http.content {
        Some(content) => match serde_json::from_str(content) {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to parse SM Context Create request: {e}");
                return problem_400("INVALID_MSG_FORMAT", "request body is not valid JSON");
            }
        },
        None => return problem_400("MANDATORY_IE_MISSING", "SmContextCreateData body required"),
    };

    // ---- Strict mandatory/conditional IE validation (smfd-06) ----
    // Reject genuinely-missing mandatory IEs up front with the correct
    // ProblemDetails cause (default-permissive on supi/anType, which the
    // matched-sim AMF omits).
    if let Some(cause) = validate_sm_context_create_data(&req_body) {
        log::warn!("SmContextCreateData rejected: {cause}");
        return problem_400(cause, "mandatory IE missing or incorrect");
    }

    // ---- SmContextCreateData attributes (TS 29.502 Table 6.1.6.2.2-1) ----
    let Some(pdu_session_id) = req_body["pduSessionId"]
        .as_u64()
        .filter(|p| (1..=15).contains(p))
        .map(|p| p as u8)
    else {
        return problem_400("MANDATORY_IE_INCORRECT", "pduSessionId (1..15) is required");
    };
    let Some(sst) = req_body["sNssai"]["sst"].as_u64().map(|v| v as u8) else {
        return problem_400("MANDATORY_IE_MISSING", "sNssai.sst is required");
    };
    let snssai_sd = req_body["sNssai"]["sd"].as_str().map(str::to_string);
    // Issue #73: `supi` is conditional-mandatory for a non-emergency session
    // (TS 29.502 §6.1.6.2.2), and it is now REJECTED when absent.
    //
    // This used to warn and substitute `"imsi-unknown"`, with the comment "lenient:
    // AMF support pending". The AMF now sends the real SUPI, and the fabrication
    // was never merely cosmetic: the phantom identity flowed into NSAC counters,
    // policy association and session lookup, so every subscriber in the network
    // collapsed onto ONE identity. Charging and slice admission were computed over
    // a subscriber that does not exist -- and because it looked like a working
    // session, nothing surfaced the loss.
    //
    // Rejecting is the honest failure: a session the SMF cannot attribute is a
    // session it cannot charge, police or admit.
    let Some(supi) = req_body["supi"].as_str().filter(|s| !s.is_empty()) else {
        return problem_400(
            "MANDATORY_IE_MISSING",
            "supi is required for a non-emergency SmContextCreateData (TS 29.502 6.1.6.2.2)",
        );
    };
    let supi = supi.to_string();

    // ---- DNN: the UE's, else the SUBSCRIBED DEFAULT (issue #204) ----
    // `dnn` is optional in SmContextCreateData; when the UE omits the DNN IE the
    // AMF omits the member, and TS 23.501 §5.6.1 says the network selects the
    // SUBSCRIBED default DNN. The AMF used to substitute the literal `"internet"`,
    // so any deployment whose subscribers do not all default to a DNN of that name
    // attached DNN-less sessions to the WRONG data network -- wrong UPF, wrong
    // policy and charging, wrong slice -- and silently, because the session
    // established fine against it.
    //
    // Never falls back to a literal: an unresolvable default is a REFUSED session,
    // which is what the SMF already did for an absent `dnn` before this change,
    // and the cause names which of the four failure modes it was.
    let dnn = match req_body["dnn"].as_str().filter(|d| !d.is_empty()) {
        Some(d) => d.to_string(),
        None => {
            log::info!(
                "[{supi}] SmContextCreateData carries no dnn — resolving the subscribed \
                 default for SST {sst} (TS 23.501 §5.6.1)"
            );
            match fetch_subscribed_default_dnn(&supi, sst, snssai_sd.as_deref()).await {
                Ok(d) => d,
                Err(e) => {
                    log::warn!("[{supi}] no DNN for this session: {}", e.detail());
                    return problem_400(e.cause(), &e.detail());
                }
            }
        }
    };
    let an_type = req_body["anType"].as_str().unwrap_or_else(|| {
        log::warn!("SmContextCreateData without anType — assuming 3GPP_ACCESS");
        "3GPP_ACCESS"
    });
    let sm_context_status_uri = req_body["smContextStatusUri"].as_str().map(str::to_string);
    if sm_context_status_uri.is_none() {
        log::warn!(
            "SmContextCreateData without smContextStatusUri (status notifications disabled)"
        );
    }
    let serving_nf_id = req_body["servingNfId"].as_str().unwrap_or("");
    let rat_type = req_body["ratType"].as_str().unwrap_or("NR");
    // RedCap (Reduced Capability) UE indication (Rel-17, TS 29.502): drives a
    // reduced session-AMBR cap below so a RedCap device's data path is policed
    // to its narrowband capability.
    let redcap_indication = req_body["redcapIndication"].as_bool().unwrap_or(false);
    let guami = &req_body["guami"];
    let serving_network = &req_body["servingNetwork"];
    log::info!(
        "SM Context Create: SUPI={supi}, PSI={pdu_session_id}, SST={sst}, DNN={dnn}, \
         anType={an_type}, ratType={rat_type}, servingNfId={serving_nf_id}, \
         guami={guami}, servingNetwork={serving_network}"
    );

    // ---- N1 SM container: PDU Session Establishment Request (TS 24.501) ----
    // The N1 container arrives either as a multipart 5gnas binary part
    // (resolved via its RefToBinaryData contentId) or, from a legacy peer, as
    // a base64 string. `resolve_binary_ref` accepts both.
    let (pti, requested_type, requested_ssc) =
        match resolve_binary_ref(request, &req_body["n1SmMsg"]) {
            Some(n1_bytes) => match policy::parse_establishment_request(&n1_bytes) {
                Some(req) => {
                    if req.psi != pdu_session_id {
                        log::warn!(
                            "N1 PSI {} differs from SmContextCreateData pduSessionId {}",
                            req.psi,
                            pdu_session_id
                        );
                    }
                    log::info!(
                        "N1 SM decoded: PTI={}, requested PDU type={:?}, SSC mode={:?}, \
                         integrity max rate={:?}",
                        req.pti,
                        req.requested_pdu_session_type,
                        req.requested_ssc_mode,
                        req.integrity_max_rate
                    );
                    (
                        req.pti,
                        req.requested_pdu_session_type
                            .unwrap_or(policy::pdu_session_type::IPV4),
                        req.requested_ssc_mode.unwrap_or(1),
                    )
                }
                None => {
                    return problem_400(
                        "N1_SM_ERROR",
                        "n1SmMsg is not a PDU Session Establishment Request",
                    )
                }
            },
            None => {
                // The n1SmMsg attribute passed validation but its referenced
                // binary part is absent / not decodable — reject (smfd-06).
                log::error!("SmContextCreateData n1SmMsg present but binary part missing/invalid");
                return problem_400("N1_SM_ERROR", "n1SmMsg binary part missing or invalid");
            }
        };

    // Selected PDU session type: this SMF serves IPv4 (and the IPv4 leg of
    // IPv4v6). IPv6-only/Ethernet/Unstructured → reject, 5GSM cause #50.
    let selected_type = match requested_type {
        policy::pdu_session_type::IPV4 | policy::pdu_session_type::IPV4V6 => {
            policy::pdu_session_type::IPV4
        }
        other => {
            log::warn!("Unsupported requested PDU session type {other} — rejecting (cause 50)");
            return sm_context_create_error(
                403,
                "PDU_SESSION_TYPE_NOT_SUPPORTED",
                pdu_session_id,
                pti,
                policy::gsm_cause::PDU_SESSION_TYPE_IPV4_ONLY_ALLOWED,
            );
        }
    };
    // Authorise the requested SSC mode instead of echoing it (TS 23.502 §4.3.5).
    let selected_ssc = match authorize_ssc_mode(requested_ssc) {
        Ok(mode) => mode,
        Err(allowed) => {
            log::warn!(
                "Requested SSC mode {requested_ssc} is not supported (allowed bitmap \
                 {allowed:#05b}) — rejecting with 5GSM cause #68"
            );
            return sm_context_create_ssc_error(pdu_session_id, pti, allowed);
        }
    };

    // ---- Allocate session resources ----
    let ctx = smf_self();
    let sm_context_ref;
    let ue_ip_octets: [u8; 4];
    // #78: the session's own id, so the SBI handlers can update the record they
    // registered. `None` only if registration failed (capacity), which is reported
    // below rather than silently producing an unfindable context.
    let registered_sess_id: Option<u64>;

    if let Ok(context) = ctx.read() {
        // #78: REGISTER the session in the context list, and take the
        // `smContextRef` from the session itself.
        //
        // Before #78 this called `next_sess_index()` and formatted the result,
        // registering nothing -- so `sess_find_by_sm_context_ref` never matched and
        // every Retrieve answered 404 CONTEXT_NOT_FOUND for a session that had just
        // been created successfully.
        //
        // The ref is read back OUT of the session rather than computed here even
        // though both would use the same counter: `sess_add_by_psi` mints
        // `sm_context_ref` from `sess_index` itself, so computing it separately
        // would consume the counter twice and leave the handler's ref one behind the
        // session's -- a denormalised pair that disagrees with itself, which is the
        // exact shape of the defect this fixes.
        match register_sm_context(&context, &supi, pdu_session_id) {
            Some((reference, sess_id)) => {
                sm_context_ref = reference;
                registered_sess_id = Some(sess_id);
            }
            None => {
                log::error!(
                    "[{supi}] could not register an SM context (UE or session capacity \
                     reached): refusing the create rather than returning a reference no \
                     Retrieve can resolve"
                );
                return sm_context_create_error(
                    500,
                    "INSUFFICIENT_RESOURCES",
                    pdu_session_id,
                    pti,
                    policy::gsm_cause::INSUFFICIENT_RESOURCES,
                );
            }
        }
        // Allocate UE IP from bitmap pool
        match context.ipv4_pool.allocate() {
            Some(addr) => {
                ue_ip_octets = addr.octets();
                // Issue #191: persist the allocation HERE, before the session or
                // the binding exists, because the failure directions are not
                // symmetric. A snapshot holding an address whose session never
                // completed leaks one address; a snapshot missing an address a UE
                // is using hands the same address to a second UE.
                context.persist();
            }
            None => {
                log::error!("IPv4 address pool exhausted");
                // #78: the session was registered a few lines above, before the
                // address was available. Un-register it: an SM context the create
                // answered 500 for is one the AMF will never release.
                if let Some(sess_id) = registered_sess_id {
                    context.sess_remove(sess_id);
                }
                return sm_context_create_error(
                    500,
                    "INSUFFICIENT_RESOURCES",
                    pdu_session_id,
                    pti,
                    policy::gsm_cause::INSUFFICIENT_RESOURCES,
                );
            }
        }
    } else {
        return SbiResponse::with_status(500);
    }

    log::info!(
        "SMF allocated: ref={}, UE IP={}.{}.{}.{}",
        sm_context_ref,
        ue_ip_octets[0],
        ue_ip_octets[1],
        ue_ip_octets[2],
        ue_ip_octets[3]
    );

    // #78: roll back BOTH the address and the session registration. The session is
    // now registered in the context list before the PFCP leg is established (it has
    // to be: the `smContextRef` the rest of this handler uses is minted by the
    // session itself), so every failure path from here on would otherwise leave a
    // registered SM context behind for a create that answered an error -- a context
    // the AMF never learned about and will never release. Named `rollback` rather
    // than `release_ip` so a later reader adding a failure path sees what it undoes.
    let rollback = || {
        if let Ok(ctx) = smf_self().read() {
            ctx.ipv4_pool
                .release(std::net::Ipv4Addr::from(ue_ip_octets));
            if let Some(sess_id) = registered_sess_id {
                ctx.sess_remove(sess_id);
            }
        }
    };

    // ---- Nnsacf_NSAC: per-S-NSSAI PDU-session admission (TS 29.536 §5.3) ----
    // Before committing PCF/PFCP resources, ask the NSACF (if deployed) whether
    // a new PDU session may be admitted for this S-NSSAI. A rejection
    // (admittedFlag=false) is a slice-quota exhaustion → reject the session
    // with 5GSM cause #67 (insufficient resources for specific slice). The
    // NSACF is optional: when none is configured/discoverable we skip the check
    // (fail-open), and a transport/HTTP failure also fails open so a missing
    // NSACF never blocks the basic data path.
    let nsac_admitted = match policy::resolve_nsacf_endpoint().await {
        None => {
            log::debug!("No NSACF configured/discoverable — skipping slice admission control");
            false
        }
        Some(nsacf) => {
            let nf_id = self_nf_id().await;
            match policy::nsac_pdu_session_admit(
                &nsacf,
                &nf_id,
                &supi,
                pdu_session_id,
                sst,
                snssai_sd.as_deref(),
            )
            .await
            {
                policy::NsacAdmission::Admitted => {
                    log::info!(
                        "NSACF admitted PDU session for S-NSSAI[SST:{sst} SD:{snssai_sd:?}]"
                    );
                    true
                }
                policy::NsacAdmission::Rejected => {
                    log::warn!(
                        "NSACF rejected PDU session for S-NSSAI[SST:{sst}] — \
                         rejecting (5GSM cause 67)"
                    );
                    rollback();
                    return sm_context_create_error(
                        403,
                        "NSAC_PDU_SESSION_REJECTED",
                        pdu_session_id,
                        pti,
                        policy::gsm_cause::INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE,
                    );
                }
                policy::NsacAdmission::Unavailable => {
                    log::warn!("NSACF unreachable for slice admission — proceeding (fail-open)");
                    false
                }
            }
        }
    };

    // ---- GSM FSM: Initial → Wait5gcSmPolicyAssociation ----
    let sess_idx_u64 = sm_context_ref.parse::<u64>().unwrap_or(0);
    let mut fsm = gsm_sm::GsmFsm::new(sess_idx_u64);
    fsm.init();
    fsm.dispatch(&event::SmfEvent::gsm_message(
        sess_idx_u64,
        policy::gsm_message_type::ESTABLISHMENT_REQUEST,
        Vec::new(),
    ));

    // ---- #79: UDM interaction (TS 23.502 §4.3.2.2.1 step 4) ----
    //
    // Both legs happen BEFORE the PCF call and before PFCP establishment, which is
    // where the spec puts them and what makes them useful: the subscribed values
    // are an INPUT to the policy decision, so fetching them afterwards could only
    // override a PCF decision -- a conformance defect rather than a degradation.
    //
    // Off by default (`SMF_UDM=1`). Both are non-fatal: a session that could not
    // reach the UDM is a working session on config-default QoS, and refusing it
    // would make a UDM outage a total outage.
    //
    // The registration is awaited rather than spawned so its failure is logged
    // against this session rather than arriving after the response.
    let serving_plmn = req_body["guami"]["plmnId"]
        .as_object()
        .and_then(|p| {
            Some((
                p.get("mcc")?.as_str()?.to_string(),
                p.get("mnc")?.as_str()?.to_string(),
            ))
        })
        .or_else(|| {
            let p = req_body["servingNetwork"].as_object()?;
            Some((
                p.get("mcc")?.as_str()?.to_string(),
                p.get("mnc")?.as_str()?.to_string(),
            ))
        });
    udm::register_as_serving_smf(
        &supi,
        pdu_session_id,
        &dnn,
        sst,
        snssai_sd.as_deref(),
        serving_plmn
            .as_ref()
            .map(|(mcc, mnc)| (mcc.as_str(), mnc.as_str())),
    )
    .await;
    let subscribed = udm::fetch_sm_data(&supi, &dnn, sst, snssai_sd.as_deref()).await;

    // #293: subscribe to changes in what was just fetched, so an administrative edit
    // reaches a session that is already up (TS 23.502 §4.3.2.2.1 step 4,
    // Nudm_SDM_Subscribe). The callback URI is per SM context and points at the route
    // this same change added -- #79 left the subscribe out precisely because
    // subscribing without a handler creates a UDM resource that notifies into a 404,
    // which is worse than not subscribing.
    //
    // Awaited BEFORE the binding is stored so the id is recorded with it; a
    // subscription created and not recorded is an orphan on the UDM, because the
    // release path would have nothing to delete. Same shape, and same reason, as the
    // EASDF DNS context below.
    let sdm_subscription_id = udm::subscribe_sm_data(
        &supi,
        &format!(
            "{}/nsmf-callback/v1/sdm-notify/{}",
            self_sbi_uri(),
            sm_context_ref
        ),
        &dnn,
        sst,
        snssai_sd.as_deref(),
    )
    .await;

    // ---- Npcf_SMPolicyControl_Create (TS 29.512 §4.2.2) ----
    let notification_uri = format!(
        "{}/nsmf-callback/v1/sm-policy-notify/{}",
        self_sbi_uri(),
        sm_context_ref
    );
    let mut decision = match policy::resolve_pcf_endpoint().await {
        None => {
            // Documented config-default fallback: no PCF configured.
            log::warn!(
                "No PCF configured (PCF_URI / NRF) — applying config-default policy \
                 (DNN-derived 5QI, AMBR 100/100 Mbps)"
            );
            fsm.transition_to(gsm_sm::GsmState::WaitPfcpEstablishment);
            // DNN-aware default: an XR DNN (e.g. "xr") yields a delay-critical
            // GBR XR 5QI (82-85) with a populated PCC rule, exercising the
            // XR-aware QoS-flow binding + PFCP QER setup below even without a PCF.
            // #79: the subscribed values, when the UDM supplied any, are the
            // baseline here -- the config default is what they fall back TO, not
            // the other way round. With a PCF present its decision wins outright
            // (TS 23.503 §6.1.3.2), which is why this applies only on this arm.
            let mut decision = policy::PolicyDecision::config_default_for_dnn(&dnn);
            if let Some(ref sub) = subscribed {
                decision.apply_subscribed_baseline(sub);
            }
            decision
        }
        Some(pcf) => {
            let create_ctx = policy::SmPolicyCreateContext {
                supi: &supi,
                psi: pdu_session_id,
                pdu_session_type: selected_type,
                dnn: &dnn,
                sst,
                sd: snssai_sd.as_deref(),
                ue_ipv4: ue_ip_octets,
                notification_uri: &notification_uri,
            };
            match policy::sm_policy_create(&pcf, &create_ctx).await {
                Ok(decision) => {
                    log::info!(
                        "SM policy created: id={}, 5QI={}, AMBR UL/DL={}/{} bps, {} PCC rule(s)",
                        decision.sm_policy_id,
                        decision.def_five_qi,
                        decision.sess_ambr_ul_bps,
                        decision.sess_ambr_dl_bps,
                        decision.pcc_rules.len()
                    );
                    fsm_dispatch_policy_response(&mut fsm, 201);
                    decision
                }
                Err(policy::PolicyError::Rejected { status, detail }) => {
                    // Abnormal path: PCF policy rejection → session reject
                    // with 5GSM cause #29 (TS 24.501).
                    log::error!("PCF rejected SM policy (status={status}): {detail}");
                    fsm_dispatch_policy_response(&mut fsm, status);
                    rollback();
                    rollback_nsac(
                        nsac_admitted,
                        &supi,
                        pdu_session_id,
                        sst,
                        snssai_sd.as_deref(),
                    )
                    .await;
                    return sm_context_create_error(
                        403,
                        "POLICY_REJECTED",
                        pdu_session_id,
                        pti,
                        policy::gsm_cause::USER_AUTHENTICATION_OR_AUTHORIZATION_FAILED,
                    );
                }
                Err(e) => {
                    // PCF configured but unreachable: hard failure (no
                    // silent fallback) → 5GSM cause #38 network failure.
                    log::error!("SM policy create failed: {e}");
                    fsm.transition_to(gsm_sm::GsmState::Exception);
                    rollback();
                    rollback_nsac(
                        nsac_admitted,
                        &supi,
                        pdu_session_id,
                        sst,
                        snssai_sd.as_deref(),
                    )
                    .await;
                    return sm_context_create_error(
                        504,
                        "PCF_NOT_RESPONDING",
                        pdu_session_id,
                        pti,
                        policy::gsm_cause::NETWORK_FAILURE,
                    );
                }
            }
        }
    };

    // ---- XR DNN → XR 5QI upgrade (Rel-18, TS 23.501 §5.7.4) ----
    // The DNN is the only XR signal a standard UE conveys at establishment, so
    // apply the XR delay-critical GBR 5QI here for an XR DNN regardless of the
    // policy source. Idempotent for the config-default path (already XR) and a
    // no-op for non-XR DNNs; it upgrades a PCF decision that doesn't model XR.
    decision.ensure_xr_for_dnn(&dnn);

    // ---- RedCap session-AMBR reduction (Rel-17, TS 23.501 §5.7.1) ----
    // A RedCap UE's narrowband RF cannot sustain a normal-UE session-AMBR, so
    // cap the authorized Session-AMBR to the configured RedCap ceiling. This
    // single reduction propagates to the N1 PDU Session Establishment Accept,
    // the PFCP QER MBR (and thus the UPF data-plane policing), and the stored
    // policy binding below — no separate enforcement site needed.
    if redcap_indication {
        // RedCap session-AMBR ceiling (TS 38.101-1 RedCap peak-rate envelope):
        // 150 Mbps DL / 50 Mbps UL. Configurable via REDCAP_SESS_AMBR_*_BPS.
        let redcap_dl_cap = std::env::var("REDCAP_SESS_AMBR_DL_BPS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(150_000_000);
        let redcap_ul_cap = std::env::var("REDCAP_SESS_AMBR_UL_BPS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(50_000_000);

        let orig_dl = decision.sess_ambr_dl_bps;
        let orig_ul = decision.sess_ambr_ul_bps;
        // A zero AMBR means "unset/unlimited" in the authorized policy; treat
        // it as exceeding the cap so the RedCap ceiling still applies.
        decision.sess_ambr_dl_bps = if orig_dl == 0 {
            redcap_dl_cap
        } else {
            orig_dl.min(redcap_dl_cap)
        };
        decision.sess_ambr_ul_bps = if orig_ul == 0 {
            redcap_ul_cap
        } else {
            orig_ul.min(redcap_ul_cap)
        };

        log::info!(
            "RedCap UE: session-AMBR reduced from UL/DL {}/{} to {}/{} bps \
             (RedCap cap UL/DL {}/{} bps)",
            orig_ul,
            orig_dl,
            decision.sess_ambr_ul_bps,
            decision.sess_ambr_dl_bps,
            redcap_ul_cap,
            redcap_dl_cap,
        );
    }

    let qfi = decision.default_qfi();

    // ---- XR-aware QoS flow binding (TS 23.501 §5.7.4, Rel-18) ----
    // Run the XR-aware binding over the authorized policy. When the authorized
    // default 5QI or any installed PCC rule is an XR delay-critical GBR 5QI
    // (82-85), this yields XR flow metadata (delay budget, GBR) that drives a
    // dedicated XR QER in the PFCP session below. For non-XR sessions the
    // metadata is empty and the default Session-AMBR QER is used unchanged.
    let xr_policy = decision_to_session_policy(&decision);
    let (_xr_results, _xr_flags, xr_meta) = binding::process_xr_qos_flow_binding(&xr_policy, &[]);
    let xr_flow = xr_meta.into_iter().next();
    if let Some(ref xr) = xr_flow {
        log::info!(
            "XR QoS flow bound: 5QI={}, PDB={}ms, GBR UL/DL={}/{} bps, PDB-enforcement={}",
            xr.five_qi,
            xr.delay_budget_ms,
            xr.gbr_ul_bps,
            xr.gbr_dl_bps,
            xr.requires_pdb_enforcement
        );
    }

    let session_qos = SessionQos {
        qfi,
        ambr_ul_bps: decision.sess_ambr_ul_bps,
        ambr_dl_bps: decision.sess_ambr_dl_bps,
        xr_flow: xr_flow.map(|xr| XrSessionFlow {
            five_qi: xr.five_qi,
            gbr_ul_bps: xr.gbr_ul_bps,
            gbr_dl_bps: xr.gbr_dl_bps,
        }),
    };

    // ---- N4: PFCP Session Establishment with policy-derived QoS ----
    // A failed N4 establishment is a hard failure for the PDU session — no
    // fabricated TEID fallback (the data path would be a black hole).
    let smf_n4_seid = smf_n4_seid_for(&sm_context_ref);

    let (upf_teid, upf_addr) =
        match pfcp_session_establish(smf_n4_seid, ue_ip_octets, &dnn, sst, &session_qos).await {
            Ok(result) => {
                log::info!(
                    "PFCP session established: UPF SEID=0x{:016x}, TEID=0x{:08x}, addr={}.{}.{}.{}",
                    result.upf_seid,
                    result.upf_teid,
                    result.upf_addr[0],
                    result.upf_addr[1],
                    result.upf_addr[2],
                    result.upf_addr[3]
                );
                // Store UPF SEID for later PFCP modifications (in SmfContext, not a global)
                if let Ok(ctx) = smf_self().read() {
                    if let Ok(mut sessions) = ctx.pfcp_sessions.write() {
                        sessions.insert(sm_context_ref.to_string(), result.upf_seid);
                    }
                    // Issue #191: after the write guard drops -- `persist` takes a
                    // read lock on this same map and RwLock is not reentrant.
                    ctx.persist();
                }
                // FSM: WaitPfcpEstablishment → Operational
                fsm.dispatch(&event::SmfEvent::n4_message(0, 0, Vec::new()));
                (result.upf_teid, result.upf_addr)
            }
            Err(e) => {
                log::error!("PFCP session establishment failed: {e} — rejecting SM context");
                fsm.transition_to(gsm_sm::GsmState::Exception);
                // Roll back the PCF SM policy association (TS 29.512 §4.2.5)
                if let Some(ref pol_id) =
                    (!decision.is_config_default).then_some(decision.sm_policy_id.clone())
                {
                    if let Some(pcf) = policy::resolve_pcf_endpoint().await {
                        if let Err(e) = policy::sm_policy_delete(&pcf, pol_id).await {
                            log::warn!("SM policy rollback delete failed: {e}");
                        }
                    }
                }
                rollback();
                rollback_nsac(
                    nsac_admitted,
                    &supi,
                    pdu_session_id,
                    sst,
                    snssai_sd.as_deref(),
                )
                .await;
                return sm_context_create_error(
                    504,
                    "UPF_NOT_RESPONDING",
                    pdu_session_id,
                    pti,
                    policy::gsm_cause::INSUFFICIENT_RESOURCES,
                );
            }
        };

    // ---- #114: EASDF selection + DNS context (TS 23.501 §5.6.7) ----
    // Off by default. Awaited BEFORE the binding is stored so the context id is
    // recorded with it -- a context created and not recorded is an orphan on the
    // EASDF, because the release path would have nothing to delete. Every failure
    // inside is non-fatal: a session without edge DNS steering is still a working
    // session, and refusing it would turn an EASDF outage into a service outage.
    //
    // #276: this line used to read `let easdf_dns_context_id = None;` under this
    // same comment. The comment described an await that was not there, so
    // `create_dns_context` had NO production caller -- and because the id was
    // always None, the release path's `delete_dns_context` could never fire
    // either. The whole SMF->EASDF leg was reachable from its own unit tests and
    // from nothing else.
    //
    // The UE's IP address is passed because the EASDF cannot associate a UDP
    // query with a session without it: a DNS datagram carries no context id, so
    // the source address is the only correlator (#276).
    let easdf_dns_context_id: Option<String> = easdf::create_dns_context(
        &supi,
        pdu_session_id,
        &dnn,
        std::net::Ipv4Addr::from(ue_ip_octets),
    )
    .await;

    // ---- #117: 5GS↔EPS interworking, EBI assignment (TS 23.502 §4.11.1.4.1) ----
    //
    // Off by default. Awaited BEFORE the N1 accept is built, because the accept is
    // where the Mapped EPS bearer contexts IE has to appear: an EBI learned after
    // the accept went out could not be conveyed to the UE without a Modification
    // Command it did not ask for. Non-fatal by construction -- `request_ebi`
    // returns None for every failure, and a session without an EBI is a working
    // 5G session that simply cannot be moved to the EPC.
    //
    // The AMF's authority is its `smContextStatusUri` callback root, the only
    // address this SMF has for it.
    let mapped_eps_bearer_id = eps_iwk::request_ebi(
        sm_context_status_uri.as_deref(),
        &supi,
        pdu_session_id,
        decision.arp_priority_level,
    )
    .await;

    // ---- #78: fill in the registered session, so Retrieve answers with the real
    // session rather than with whatever `sess_add_by_psi` defaulted to ----
    //
    // Done here, after the PFCP establishment settled, because `upCnxState` is only
    // ACTIVATED once the user plane exists. An earlier update would advertise an
    // activated connection for a session whose N4 leg had not been established.
    if let Some(sess_id) = registered_sess_id {
        if let Ok(context) = ctx.read() {
            if let Some(mut sess) = context.sess_find_by_id(sess_id) {
                sess.session_name = Some(dnn.clone());
                sess.full_dnn = Some(dnn.clone());
                sess.pti = pti;
                sess.ue_session_type = requested_type;
                sess.ue_ssc_mode = selected_ssc;
                sess.s_nssai = context::SNssai {
                    sst,
                    // SD is a 24-bit value; the request carries it as a hex string.
                    sd: snssai_sd
                        .as_deref()
                        .and_then(|s| u32::from_str_radix(s, 16).ok()),
                };
                sess.set_ipv4_addr(std::net::Ipv4Addr::from(ue_ip_octets));
                sess.up_cnx_state = context::UpCnxState::Activated;
                sess.sm_context_status_uri = sm_context_status_uri.clone();
                sess.session_ambr = context::SessionAmbr {
                    uplink: decision.sess_ambr_ul_bps,
                    downlink: decision.sess_ambr_dl_bps,
                };
                sess.establishment_accept_sent = true;
                context.sess_update(&sess);
            }
        }
    }

    // ---- #117: record the assigned EBI on a QoS flow ----
    //
    // `SmfBearer.ebi` is where the Mapped EPS bearer contexts encoder reads the
    // identity from, and until now the ONLY writer of that field was the EPC
    // GTPv2 path (`gtp_handler.rs`) — so an EBI could exist only for a session
    // established from the EPC side, never for a 5GC-first one. This is the Namf
    // writer #117 asks for.
    //
    // The flow is created ONLY when an EBI was assigned. `qos_flow_add` has no
    // other production caller (the live 5G path carries its QoS on the session and
    // the policy binding), so creating one unconditionally would populate a store
    // nothing reads and change what `max_num_of_bearer` means for every session.
    if let (Some(ebi), Some(sess_id)) = (mapped_eps_bearer_id, registered_sess_id) {
        eps_iwk::record_mapped_eps_bearer(
            sess_id,
            ebi,
            qfi,
            decision.def_five_qi,
            decision.arp_priority_level,
            &supi,
        );
    }

    // ---- Store the policy binding (drives later update/release/notify) ----
    if let Ok(context) = ctx.read() {
        if let Ok(mut bindings) = context.policy_bindings.write() {
            bindings.insert(
                sm_context_ref.clone(),
                context::PolicyBinding {
                    sm_policy_id: (!decision.is_config_default)
                        .then_some(decision.sm_policy_id.clone()),
                    supi: supi.clone(),
                    psi: pdu_session_id,
                    pti,
                    pdu_session_type: selected_type,
                    ssc_mode: selected_ssc,
                    ue_ip: ue_ip_octets,
                    dnn: dnn.clone(),
                    qfi,
                    five_qi: decision.def_five_qi,
                    ambr_ul_bps: decision.sess_ambr_ul_bps,
                    ambr_dl_bps: decision.sess_ambr_dl_bps,
                    sm_context_status_uri: sm_context_status_uri.clone(),
                    fsm: fsm.clone(),
                    easdf_dns_context_id: easdf_dns_context_id.clone(),
                    easdf_reported_eas: Vec::new(),
                    mapped_eps_bearer_id,
                    sst,
                    sd: snssai_sd.clone(),
                    sdm_subscription_id: sdm_subscription_id.clone(),
                },
            );
        }
        // Issue #191: after the write guard drops (see `SmfContext::persist`).
        context.persist();
    }

    // #79: Nsmf_EventExposure_Notify for PDU_SES_EST (TS 29.508 §4.2.3.2). After
    // the binding is stored, so the session a consumer is told about exists by the
    // time the notification lands.
    event_exposure::notify(event_exposure::event::PDU_SES_EST, &supi, pdu_session_id).await;

    // ---- N1: PDU Session Establishment Accept with authorized QoS ----
    // S-NSSAI (smfd-04) is taken from the create request's S-NSSAI; the SD hex
    // string (if any) is parsed back to its 24-bit value. The conditional QoS
    // flow descriptions IE (0x79) is driven by `def_five_qi` vs the QFI. The
    // IPv6 interface identifier is unused on the live path (this SMF grants the
    // IPv4 leg only — see `selected_type`); the IPv4v6 encoding is smfd-05.
    let snssai_sd_u32 = snssai_sd
        .as_deref()
        .and_then(|s| u32::from_str_radix(s, 16).ok());
    // TS 24.501 clause 8.3.2.2: when the UE requested IPv4v6 but this SMF grants
    // only the IPv4 leg (selected_type != requested_type), the accept must carry
    // 5GSM cause #50 "PDU session type IPv4 only allowed".
    let est_5gsm_cause = (requested_type != selected_type)
        .then_some(policy::gsm_cause::PDU_SESSION_TYPE_IPV4_ONLY_ALLOWED);
    let (epco_dns, epco_mtu) = epco_config();
    let n1_sm_msg = policy::build_establishment_accept(
        pdu_session_id,
        pti,
        selected_type,
        selected_ssc,
        qfi,
        decision.def_five_qi,
        decision.sess_ambr_dl_bps,
        decision.sess_ambr_ul_bps,
        ue_ip_octets,
        [0u8; 8],
        sst,
        snssai_sd_u32,
        &dnn,
        est_5gsm_cause,
        epco_dns,
        epco_mtu,
        mapped_eps_bearer_id,
    );

    // ---- N2 SM Information: real-APER PDUSessionResourceSetupRequestTransfer ----
    // TS 38.413 §9.3.4.1, carrying the UPF N3 GTP-U F-TEID + QoS flow setup list.
    // The AMF relays this opaquely to the gNB; the gNB's strict APER decoder
    // rejects the legacy hand-rolled byte layout, so it must be real APER.
    let n2_sm_info = match build_setup_request_transfer(
        upf_teid,
        upf_addr,
        qfi,
        decision.def_five_qi as u16,
        decision.arp_priority_level,
    ) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::error!("Failed to encode PDUSessionResourceSetupRequestTransfer: {e:?}");
            rollback();
            rollback_nsac(
                nsac_admitted,
                &supi,
                pdu_session_id,
                sst,
                snssai_sd.as_deref(),
            )
            .await;
            return sm_context_create_error(
                500,
                "SYSTEM_FAILURE",
                pdu_session_id,
                pti,
                policy::gsm_cause::NETWORK_FAILURE,
            );
        }
    };

    // SmContextCreatedData root: N1 (PDU Session Establishment Accept) and N2
    // (PDUSessionResourceSetupRequestTransfer) are carried as multipart/related
    // binary parts (5gnas + ngap) referenced by RefToBinaryData, per TS 29.502
    // §6.1.2.2.2 / §6.1.2.4.
    let response_body = serde_json::json!({
        "smContextRef": sm_context_ref,
        "pduSessionId": pdu_session_id,
        "upCnxState": "ACTIVATING",
        "n2SmInfoType": "PDU_RES_SETUP_REQ"
    });

    let location = format!("/nsmf-pdusession/v1/sm-contexts/{sm_context_ref}");

    log::info!(
        "SM Context Created: ref={}, 5QI={}, QFI={}, AMBR UL/DL={}/{} bps, UPF TEID=0x{:08x}",
        sm_context_ref,
        decision.def_five_qi,
        qfi,
        decision.sess_ambr_ul_bps,
        decision.sess_ambr_dl_bps,
        upf_teid
    );

    sbi_response_with_n1_n2(201, response_body, &n1_sm_msg, &n2_sm_info)
        .with_header("Location", location)
}

/// Look up the stored UPF SEID for an SM context (copy-then-drop the guards
/// per the lock-order rule).
/// The SMF-side N4 SEID for an SM context reference. Must match the
/// derivation used at session establishment (it is the SEID the UPF
/// addresses us by, and — issue #20 — the session→UPF binding key).
fn smf_n4_seid_for(sm_context_ref: &str) -> u64 {
    (sm_context_ref.parse::<u64>().unwrap_or(1)) | 0x1000
}

fn lookup_upf_seid(sm_context_ref: &str) -> Option<u64> {
    smf_self().read().ok().and_then(|ctx| {
        ctx.pfcp_sessions
            .read()
            .ok()
            .and_then(|sessions| sessions.get(sm_context_ref).copied())
    })
}

/// Look up a clone of the policy binding for an SM context.
fn lookup_policy_binding(sm_context_ref: &str) -> Option<context::PolicyBinding> {
    smf_self().read().ok().and_then(|ctx| {
        ctx.policy_bindings
            .read()
            .ok()
            .and_then(|bindings| bindings.get(sm_context_ref).cloned())
    })
}

/// Send a PFCP QER modification carrying an authorized Session-AMBR.
async fn pfcp_update_session_qer(
    smf_n4_seid: u64,
    upf_seid: u64,
    qfi: u8,
    ambr_ul: u64,
    ambr_dl: u64,
) -> Result<()> {
    let client = pfcp_path::client_for_session(smf_n4_seid)
        .ok_or_else(|| anyhow::anyhow!("PFCP client not initialised"))?;
    let params = n4_build::SessionModificationParams {
        update_qers: vec![n4_build::QerParams {
            qer_id: 1,
            gate_status: (0, 0), // Both gates open
            mbr: Some((ambr_ul, ambr_dl)),
            gbr: None,
            qfi: Some(qfi),
        }],
        ..Default::default()
    };
    let payload = n4_build::build_session_modification_request(&params);
    let (_, resp_body) = client
        .request(
            pfcp_path::pfcp_message_type::SESSION_MODIFICATION_REQUEST,
            Some(upf_seid),
            &payload,
        )
        .await
        .map_err(|e| anyhow::anyhow!("PFCP Session Modification (QoS) failed: {e}"))?;
    match pfcp_path::parse_cause(&resp_body) {
        Some(pfcp_path::pfcp_cause::REQUEST_ACCEPTED) => Ok(()),
        cause => anyhow::bail!("PFCP Session Modification (QoS) rejected: cause={cause:?}"),
    }
}

/// Deactivate the downlink FAR (back to BUFF) — used when the AN-side
/// resources failed or the UP connection is deactivated.
async fn pfcp_deactivate_dl_far(smf_n4_seid: u64, upf_seid: u64) -> Result<()> {
    let client = pfcp_path::client_for_session(smf_n4_seid)
        .ok_or_else(|| anyhow::anyhow!("PFCP client not initialised"))?;
    let params = n4_build::SessionModificationParams {
        update_fars_deactivate: vec![2],
        ..Default::default()
    };
    let payload = n4_build::build_session_modification_request(&params);
    let (_, resp_body) = client
        .request(
            pfcp_path::pfcp_message_type::SESSION_MODIFICATION_REQUEST,
            Some(upf_seid),
            &payload,
        )
        .await
        .map_err(|e| anyhow::anyhow!("PFCP DL FAR deactivation failed: {e}"))?;
    match pfcp_path::parse_cause(&resp_body) {
        Some(pfcp_path::pfcp_cause::REQUEST_ACCEPTED) => Ok(()),
        cause => anyhow::bail!("PFCP DL FAR deactivation rejected: cause={cause:?}"),
    }
}

/// Handle SM Context Update (TS 29.502 §5.2.2.3) — dispatches on
/// n2SmInfoType (all inbound values of TS 29.502 Table 6.1.6.3.3-1 that can
/// arrive on /modify) and on upCnxState.
async fn handle_sm_context_update(sm_context_ref: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("SM Context Update request for ref={sm_context_ref}");

    // Parse request body for N2 SM Info (gNB TEID)
    let req_body: serde_json::Value = match &request.http.content {
        Some(content) => match serde_json::from_str(content) {
            Ok(v) => v,
            Err(e) => {
                return problem_400("INVALID_MSG_FORMAT", &format!("invalid JSON: {e}"));
            }
        },
        None => serde_json::json!({}),
    };

    // #78 / TS 29.502 §5.2.2.3.2: an Update for an unknown `smContextRef` must be
    // answered with an error status and ProblemDetails, not with success. Several
    // arms below returned 200 without ever checking that the reference resolved, so
    // the AMF could not distinguish a live context from a stale one and lost state
    // was masked. Checked HERE, before any branch, so no arm can skip it.
    if !sm_context_exists(sm_context_ref) {
        log::warn!("SM Context Update for unknown ref={sm_context_ref}: answering 404");
        return problem_response(
            404,
            "CONTEXT_NOT_FOUND",
            "No SM context for this smContextRef",
        );
    }

    let n2_sm_info_type = req_body["n2SmInfoType"].as_str().unwrap_or("");
    // #78 / TS 29.502 §5.2.2.3.4: `hoState` drives the N2 handover state machine
    // and was never read (grep found no occurrence in this file before #78).
    let ho_state = req_body["hoState"].as_str().unwrap_or("");

    // TS 29.502 §5.2.2.3.1: the request may carry `n1SmMsg`, `n2SmInfo` /
    // `n2SmInfoType`, or a UP connection-state change, and the SMF must process
    // whichever is present. This handler branched **only** on `n2SmInfoType`, so
    // a UE-originated 5GSM message arriving with no N2 payload fell into the
    // `upCnxState` branch and was never decoded: the UE got
    // `{"upCnxState":"ACTIVATED"}` back and the release or modification procedure
    // never ran.
    //
    // The N1 container is handled first, and only when there is no N2 payload to
    // process: a request carrying both is an N2 procedure that happens to relay a
    // NAS message, and those are already handled by the arms below.
    if n2_sm_info_type.is_empty() {
        if let Some(n1) = resolve_binary_ref(request, &req_body["n1SmMsg"]) {
            return handle_n1_sm_message(sm_context_ref, &n1).await;
        }
    }

    match n2_sm_info_type {
        // gNB accepted the PDU session resources (initial setup) — or the UE
        // moved and the target gNB took over (Xn path switch). Both carry the
        // new DL F-TEID that the UPF must forward to, but in different APER
        // transfer containers (TS 38.413 §9.3.4.2 vs §9.3.4.8).
        "PDU_RES_SETUP_RSP" | "PATH_SWITCH_REQ" => {
            // N2 SM transfer: multipart ngap part (RefToBinaryData) or legacy
            // base64 string — `resolve_binary_ref` accepts both.
            let Some(n2_bytes) = resolve_binary_ref(request, &req_body["n2SmInfo"]) else {
                return problem_400("N2_SM_ERROR", "n2SmInfo missing or not valid base64");
            };

            // Real-APER decode of the gNB DL N3 endpoint via the nextgcore-ngap
            // transfer codec (the gNB now emits real APER, not legacy bytes).
            let endpoint = if n2_sm_info_type == "PATH_SWITCH_REQ" {
                decode_path_switch_dl_endpoint(&n2_bytes)
            } else {
                decode_setup_response_dl_endpoint(&n2_bytes)
            };
            let Some((gnb_teid, gnb_addr, qfi)) = endpoint else {
                return problem_400(
                    "N2_SM_ERROR",
                    "could not decode gNB DL F-TEID from N2 SM transfer",
                );
            };

            log::info!(
                "SM Context Update ({n2_sm_info_type}): gNB TEID=0x{:08x}, \
                 addr={}.{}.{}.{}, QFI={}",
                gnb_teid,
                gnb_addr[0],
                gnb_addr[1],
                gnb_addr[2],
                gnb_addr[3],
                qfi
            );

            let Some(upf_seid) = lookup_upf_seid(sm_context_ref) else {
                // No N4 session exists for this context — fabricating a SEID
                // would target an unrelated session
                log::error!("No stored UPF SEID for ref={sm_context_ref}");
                return SbiResponse::with_status(404);
            };
            match pfcp_session_modify(
                smf_n4_seid_for(sm_context_ref),
                upf_seid,
                gnb_teid,
                gnb_addr,
            )
            .await
            {
                Ok(()) => {
                    log::info!(
                        "PFCP Session Modified: DL FAR activated with gNB TEID=0x{gnb_teid:08x}"
                    );
                }
                Err(e) => {
                    log::error!("PFCP Session Modification failed: {e}");
                    return SbiResponse::with_status(504);
                }
            }

            let mut response_body = serde_json::json!({ "upCnxState": "ACTIVATED" });
            if n2_sm_info_type == "PATH_SWITCH_REQ" {
                // Echo the (unchanged) UL tunnel back to the target gNB
                response_body["n2SmInfoType"] = serde_json::json!("PATH_SWITCH_REQ_ACK");
            }
            SbiResponse::with_status(200).with_body(response_body.to_string(), "application/json")
        }

        // AN failed to set up (or path-switch / handover resource allocation
        // failed): the DL tunnel is invalid — buffer downlink again.
        "PDU_RES_SETUP_FAIL" | "PATH_SWITCH_SETUP_FAIL" | "HANDOVER_RES_ALLOC_FAIL" => {
            log::warn!("SM Context Update ({n2_sm_info_type}): AN resource failure for ref={sm_context_ref}");
            if let Some(upf_seid) = lookup_upf_seid(sm_context_ref) {
                if let Err(e) =
                    pfcp_deactivate_dl_far(smf_n4_seid_for(sm_context_ref), upf_seid).await
                {
                    log::warn!("DL FAR deactivation after AN failure failed: {e}");
                }
            }
            let response_body = serde_json::json!({ "upCnxState": "DEACTIVATED" });
            SbiResponse::with_status(200).with_body(response_body.to_string(), "application/json")
        }

        // UE-initiated PDU Session Modification: AMF forwards the N1 SM
        // container; QoS comes from an Npcf_SMPolicyControl_Update — not
        // hardcoded values.
        "PDU_RES_MOD_REQ" => {
            // N1 SM container: multipart 5gnas part (RefToBinaryData) or legacy
            // base64 string — `resolve_binary_ref` accepts both.
            let Some(n1_sm_msg) = resolve_binary_ref(request, &req_body["n1SmMsg"]) else {
                return problem_400("N1_SM_ERROR", "n1SmMsg missing or not valid base64");
            };
            let Some(hdr) = policy::parse_n1_sm_header(&n1_sm_msg) else {
                return problem_400("N1_SM_ERROR", "n1SmMsg is not a 5GSM message");
            };
            let binding = lookup_policy_binding(sm_context_ref);
            let psi = binding
                .as_ref()
                .map(|b| b.psi)
                .unwrap_or_else(|| sm_context_ref.parse().unwrap_or(1));
            let pti = hdr.pti;
            log::info!(
                "SM Context Update (UE modification): PSI={psi}, PTI={pti}, msg=0x{:02x}",
                hdr.message_type
            );

            // Re-authorize via PCF (trigger RES_MO_RE, TS 29.512 §4.2.4)
            let (qfi, ambr_ul, ambr_dl) = match binding.as_ref() {
                Some(b) => {
                    let mut authorized = (b.qfi, b.ambr_ul_bps, b.ambr_dl_bps);
                    if let Some(ref pol_id) = b.sm_policy_id {
                        match policy::resolve_pcf_endpoint().await {
                            Some(pcf) => {
                                match policy::sm_policy_update(&pcf, pol_id, &["RES_MO_RE"], None)
                                    .await
                                {
                                    Ok(dec) => {
                                        authorized =
                                            (b.qfi, dec.sess_ambr_ul_bps, dec.sess_ambr_dl_bps);
                                    }
                                    Err(policy::PolicyError::Rejected { status, detail }) => {
                                        // Abnormal path: PCF rejects the
                                        // modification → 403 + 5GSM cause 29
                                        log::error!(
                                            "PCF rejected SM policy update (status={status}): {detail}"
                                        );
                                        return sm_context_create_error(
                                            403,
                                            "POLICY_REJECTED",
                                            psi,
                                            pti,
                                            policy::gsm_cause::USER_AUTHENTICATION_OR_AUTHORIZATION_FAILED,
                                        );
                                    }
                                    Err(e) => {
                                        log::warn!(
                                            "SM policy update failed ({e}) — keeping current QoS"
                                        );
                                    }
                                }
                            }
                            None => log::warn!("PCF unresolved — keeping current QoS"),
                        }
                    }
                    authorized
                }
                None => {
                    log::warn!(
                        "No policy binding for ref={sm_context_ref} — applying config-default QoS"
                    );
                    let d = policy::PolicyDecision::config_default();
                    (d.default_qfi(), d.sess_ambr_ul_bps, d.sess_ambr_dl_bps)
                }
            };

            // Apply the authorized QoS to the N4 session QER
            if let Some(seid) = lookup_upf_seid(sm_context_ref) {
                if let Err(e) = pfcp_update_session_qer(
                    smf_n4_seid_for(sm_context_ref),
                    seid,
                    qfi,
                    ambr_ul,
                    ambr_dl,
                )
                .await
                {
                    log::error!("{e}");
                    return SbiResponse::with_status(504);
                }
                // Persist the new authorized AMBR in the binding
                if let Ok(ctx) = smf_self().read() {
                    if let Ok(mut bindings) = ctx.policy_bindings.write() {
                        if let Some(b) = bindings.get_mut(sm_context_ref) {
                            b.ambr_ul_bps = ambr_ul;
                            b.ambr_dl_bps = ambr_dl;
                        }
                    }
                    // Issue #191: durable too, not just in memory.
                    ctx.persist();
                }
            } else {
                log::warn!("No PFCP session found for modification: ref={sm_context_ref}");
            }

            // N1: PDU Session Modification Command (PTI echoed, authorized AMBR)
            let n1_mod_cmd = policy::build_modification_command(psi, pti, ambr_dl, ambr_ul);

            // N2 SM Info: real-APER PDUSessionResourceModifyRequestTransfer
            // (TS 38.413 clause 9.3.4.3) carrying the re-authorized Session-AMBR
            // and the QoS flow to modify; the gNB decodes it with its strict
            // APER decoder -- a hand-rolled blob is rejected (smfd#2).
            let n2_sm_info = match build_modify_request_transfer(qfi, ambr_dl, ambr_ul) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("Failed to encode PDUSessionResourceModifyRequestTransfer: {e:?}");
                    return SbiResponse::with_status(500);
                }
            };

            // N1 (PDU Session Modification Command) + N2 (QoS flow mod) carried
            // as multipart/related binary parts referenced by RefToBinaryData.
            let response_body = serde_json::json!({
                "n2SmInfoType": "PDU_RES_MOD_REQ"
            });
            sbi_response_with_n1_n2(200, response_body, &n1_mod_cmd, &n2_sm_info)
        }

        // gNB confirmed a modification / released resources / reported
        // secondary-RAT usage — acknowledge.
        "PDU_RES_MOD_RSP" | "PDU_RES_REL_RSP" | "SECONDARY_RAT_USAGE" => {
            log::info!(
                "SM Context Update ({n2_sm_info_type}) acknowledged for ref={sm_context_ref}"
            );
            SbiResponse::with_status(200)
                .with_body(serde_json::json!({}).to_string(), "application/json")
        }

        // No N2 payload: UP connection-state change request
        "" => {
            let up_cnx_state = req_body["upCnxState"].as_str().unwrap_or("");
            if up_cnx_state == "DEACTIVATED" {
                // UE went idle: buffer downlink traffic at the UPF
                if let Some(upf_seid) = lookup_upf_seid(sm_context_ref) {
                    if let Err(e) =
                        pfcp_deactivate_dl_far(smf_n4_seid_for(sm_context_ref), upf_seid).await
                    {
                        log::warn!("DL FAR deactivation failed: {e}");
                        return SbiResponse::with_status(504);
                    }
                }
                let response_body = serde_json::json!({ "upCnxState": "DEACTIVATED" });
                return SbiResponse::with_status(200)
                    .with_body(response_body.to_string(), "application/json");
            }
            // Default: treat as activation confirmation
            let response_body = serde_json::json!({ "upCnxState": "ACTIVATED" });
            SbiResponse::with_status(200).with_body(response_body.to_string(), "application/json")
        }

        // ---- #78 / TS 29.502 §5.2.2.3.4: N2 handover ----
        //
        // Before #78 every one of these fell to the catch-all below and was answered
        // `400 N2_SM_ERROR`, so any inter-gNB N2 handover attempt was refused at the
        // SMF and the UE lost its PDU session on mobility.
        //
        // The state machine is `hoState`: PREPARING -> PREPARED -> COMPLETED, or
        // CANCELLED. The SMF's job across it is to hold the session while the target
        // side is prepared and to switch the DL tunnel only at completion — so
        // PREPARING and PREPARED must NOT touch the user plane, and COMPLETED is
        // where the switch belongs.
        "HANDOVER_REQUIRED" => {
            // Source side asks the SMF to prepare. TS 29.502 §5.2.2.3.4: the
            // response carries `hoState: PREPARING` and the N2 SM information the
            // target needs. This SMF has no target-side N2 container to build (that
            // is amfd/NGAP territory, #70), so it acknowledges the state transition
            // and holds the session rather than refusing the handover outright.
            log::info!(
                "SM Context Update (HANDOVER_REQUIRED, hoState={ho_state}) for \
                 ref={sm_context_ref}: preparing, user plane untouched"
            );
            let response_body = serde_json::json!({ "hoState": "PREPARING" });
            SbiResponse::with_status(200).with_body(response_body.to_string(), "application/json")
        }
        "HANDOVER_REQ_ACK" => {
            // The target gNB accepted. The DL tunnel is NOT switched here: until the
            // UE has actually moved (HANDOVER_COMPLETE / PATH_SWITCH_REQ) the source
            // gNB is still serving it, and re-pointing the UPF now would black-hole
            // downlink traffic for the whole handover-execution window.
            log::info!(
                "SM Context Update (HANDOVER_REQ_ACK, hoState={ho_state}) for \
                 ref={sm_context_ref}: prepared, DL tunnel still on the source gNB"
            );
            let response_body = serde_json::json!({ "hoState": "PREPARED" });
            SbiResponse::with_status(200).with_body(response_body.to_string(), "application/json")
        }
        "HANDOVER_COMPLETE" => {
            // The UE is on the target. If the request carries the target's DL
            // endpoint, switch the UPF to it; the transfer container is the same
            // shape a path switch uses (TS 38.413 §9.3.4.8).
            let switched = match resolve_binary_ref(request, &req_body["n2SmInfo"])
                .and_then(|b| decode_path_switch_dl_endpoint(&b))
            {
                Some((gnb_teid, gnb_addr, _qfi)) => match lookup_upf_seid(sm_context_ref) {
                    Some(upf_seid) => {
                        // Same call the PATH_SWITCH_REQ arm uses: one DL-switch
                        // path, so a handover completion and a path switch cannot
                        // drift apart.
                        match pfcp_session_modify(
                            smf_n4_seid_for(sm_context_ref),
                            upf_seid,
                            gnb_teid,
                            gnb_addr,
                        )
                        .await
                        {
                            Ok(()) => true,
                            Err(e) => {
                                log::warn!(
                                    "DL FAR switch to the target gNB failed after handover \
                                     completion: {e}"
                                );
                                return SbiResponse::with_status(504);
                            }
                        }
                    }
                    None => false,
                },
                None => false,
            };
            if !switched {
                // Stated rather than silently returned as success: a completed
                // handover whose DL tunnel was not switched leaves downlink traffic
                // pointed at the source gNB, and an operator reading a bare 200
                // would have no way to know.
                log::warn!(
                    "SM Context Update (HANDOVER_COMPLETE) for ref={sm_context_ref} carried no \
                     decodable target DL F-TEID: the UPF still points at the previous gNB"
                );
            }
            log::info!(
                "SM Context Update (HANDOVER_COMPLETE, hoState={ho_state}) for \
                 ref={sm_context_ref}: DL tunnel switched={switched}"
            );
            let response_body = serde_json::json!({ "hoState": "COMPLETED" });
            SbiResponse::with_status(200).with_body(response_body.to_string(), "application/json")
        }
        "HANDOVER_CANCEL" => {
            // Abandoned. Nothing to undo: neither PREPARING nor PREPARED changed the
            // user plane, which is exactly why they do not.
            log::info!(
                "SM Context Update (HANDOVER_CANCEL, hoState={ho_state}) for \
                 ref={sm_context_ref}: handover abandoned, session retained"
            );
            let response_body = serde_json::json!({ "hoState": "CANCELLED" });
            SbiResponse::with_status(200).with_body(response_body.to_string(), "application/json")
        }

        other => {
            log::warn!("SM Context Update: unsupported n2SmInfoType '{other}'");
            problem_400("N2_SM_ERROR", &format!("unsupported n2SmInfoType {other}"))
        }
    }
}

// =============================================================================
// UE-initiated N1 5GSM procedures on /modify (TS 24.501 §6.4.1.3, §6.4.3.3)
// =============================================================================

/// A 5GSM procedure timer armed against one SM context (TS 24.501 §6.3.2.2,
/// §6.3.3): the command that was sent, so it can be retransmitted verbatim, plus
/// how many attempts have been made.
#[derive(Debug, Clone)]
struct GsmProcedureTimer {
    timer_id: timer::SmfTimerId,
    /// The exact 5GSM command that was sent. Retransmission must resend the same
    /// bytes — rebuilding it could pick up state that changed in the meantime and
    /// send the UE a different message under the same procedure.
    command: Vec<u8>,
    /// SUPI and PSI, needed to address the retransmission through the AMF.
    supi: String,
    psi: u8,
    /// The AMF callback authority to reach (from `smContextStatusUri`).
    amf_uri: Option<String>,
    attempts: u32,
    deadline: std::time::Instant,
}

/// Armed 5GSM procedure timers, keyed by SM context reference.
///
/// One per context: TS 24.501 runs at most one network-requested 5GSM procedure
/// per PDU session at a time, so a second armed timer for the same context would
/// mean the SMF had started a procedure it should have queued.
static GSM_PROCEDURE_TIMERS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<String, GsmProcedureTimer>>,
> = std::sync::OnceLock::new();

fn gsm_procedure_timers(
) -> &'static std::sync::Mutex<std::collections::HashMap<String, GsmProcedureTimer>> {
    GSM_PROCEDURE_TIMERS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Arm T3591 / T3592 for `sm_context_ref` after sending `command`.
fn arm_gsm_timer(
    sm_context_ref: &str,
    timer_id: timer::SmfTimerId,
    command: &[u8],
    supi: &str,
    psi: u8,
    amf_uri: Option<&str>,
) {
    let configs = timer::SmfTimerConfigs::default();
    let duration = configs
        .get(timer_id)
        .map(|c| c.duration)
        .unwrap_or_else(|| std::time::Duration::from_secs(16));
    let entry = GsmProcedureTimer {
        timer_id,
        command: command.to_vec(),
        supi: supi.to_string(),
        psi,
        amf_uri: amf_uri.map(str::to_string),
        attempts: 0,
        deadline: std::time::Instant::now() + duration,
    };
    if let Ok(mut timers) = gsm_procedure_timers().lock() {
        if let Some(prev) = timers.insert(sm_context_ref.to_string(), entry) {
            log::warn!(
                "{} armed for ref={sm_context_ref} while {} was still running; \
                 the previous procedure was abandoned",
                timer_id.name(),
                prev.timer_id.name()
            );
        }
        log::info!(
            "{} armed for ref={sm_context_ref} ({}s)",
            timer_id.name(),
            duration.as_secs()
        );
    }
}

/// Stop the armed timer for `sm_context_ref` when it matches `timer_id`.
///
/// Returns whether a matching timer was actually stopped, which is what lets a
/// COMPLETE be distinguished from a duplicate or an unsolicited one.
fn cancel_gsm_timer(sm_context_ref: &str, timer_id: timer::SmfTimerId) -> bool {
    let Ok(mut timers) = gsm_procedure_timers().lock() else {
        return false;
    };
    match timers.get(sm_context_ref) {
        Some(entry) if entry.timer_id == timer_id => {
            timers.remove(sm_context_ref);
            log::info!("{} stopped for ref={sm_context_ref}", timer_id.name());
            true
        }
        Some(entry) => {
            log::warn!(
                "ref={sm_context_ref} has {} armed, not {}; not stopping it",
                entry.timer_id.name(),
                timer_id.name()
            );
            false
        }
        None => {
            log::debug!(
                "No {} armed for ref={sm_context_ref} (duplicate or unsolicited COMPLETE)",
                timer_id.name()
            );
            false
        }
    }
}

/// One expiry decision for an armed 5GSM timer.
#[derive(Debug, Clone, PartialEq, Eq)]
enum GsmTimerExpiry {
    /// Resend the command; the timer has been re-armed for the next attempt.
    Retransmit { attempt: u32 },
    /// Retransmissions are exhausted; the timer has been dropped and the
    /// procedure must be abandoned.
    Exhausted,
}

/// Collect the timers due at `now`, advancing or dropping each.
///
/// Pure over the timer map so the retransmission decision is testable without
/// waiting 16 seconds or driving the main loop: the caller does the sending.
fn expire_gsm_timers(now: std::time::Instant) -> Vec<(String, GsmProcedureTimer, GsmTimerExpiry)> {
    let Ok(mut timers) = gsm_procedure_timers().lock() else {
        return Vec::new();
    };
    let configs = timer::SmfTimerConfigs::default();
    let mut due = Vec::new();
    let mut exhausted = Vec::new();
    for (reference, entry) in timers.iter_mut() {
        if entry.deadline > now {
            continue;
        }
        let config = configs.get(entry.timer_id);
        let max_count = config.map(|c| c.max_count).unwrap_or(4);
        let duration = config
            .map(|c| c.duration)
            .unwrap_or_else(|| std::time::Duration::from_secs(16));
        if entry.attempts < max_count {
            entry.attempts += 1;
            entry.deadline = now + duration;
            due.push((
                reference.clone(),
                entry.clone(),
                GsmTimerExpiry::Retransmit {
                    attempt: entry.attempts,
                },
            ));
        } else {
            due.push((reference.clone(), entry.clone(), GsmTimerExpiry::Exhausted));
            exhausted.push(reference.clone());
        }
    }
    for reference in exhausted {
        timers.remove(&reference);
    }
    due
}

/// Drive 5GSM timer expiry: retransmit what is due, abandon what is exhausted.
///
/// Called from the main loop tick.
async fn run_gsm_timer_tick() {
    for (sm_context_ref, entry, expiry) in expire_gsm_timers(std::time::Instant::now()) {
        match expiry {
            GsmTimerExpiry::Retransmit { attempt } => {
                log::warn!(
                    "{} expired for ref={sm_context_ref}; retransmitting the 5GSM \
                     command (attempt {attempt})",
                    entry.timer_id.name()
                );
                send_n1_n2_message_transfer(
                    entry.amf_uri.as_deref(),
                    &entry.supi,
                    entry.psi,
                    &entry.command,
                )
                .await;
            }
            GsmTimerExpiry::Exhausted => {
                // TS 24.501 §6.3.2.2/§6.3.3: on the final expiry the network
                // abandons the procedure. The UP resources were already released
                // when the command was sent, so there is nothing to roll back —
                // this is a log and a state settle, not a retry loop.
                log::error!(
                    "{} exhausted for ref={sm_context_ref}: the UE never answered \
                     the 5GSM command; abandoning the procedure",
                    entry.timer_id.name()
                );
            }
        }
    }
}

/// Drive the Network Triggered Service Request for a buffered downlink packet
/// (#78, TS 29.244 §7.5.8.2 → TS 23.502 §4.2.3.3).
///
/// Resolves the SEID the UPF reported back to the SM context that owns it, then
/// asks the serving AMF to page the UE with `Namf_Communication_N1N2MessageTransfer`.
///
/// **The N2 form, not the N1 form.** §4.2.3.3 step 3a has the SMF send *N2 SM
/// information* (QFI, QoS profile, CN tunnel info) so the AMF can re-establish the
/// user plane — there is no NAS message to deliver, the UE is simply asleep. So this
/// does not reuse `send_n1_n2_message_transfer`, whose body is an `n1MessageContainer`.
///
/// Best-effort, and every early return says why: an unresolvable SEID, a session
/// with no serving-AMF URI, or a failed transfer all leave the packet buffered at
/// the UPF, which is where it already is. Failing louder would not deliver it.
async fn trigger_network_initiated_service_request(seid: u64, qfi: Option<u8>) {
    // The SEID in the report is the SMF's own F-SEID (the UPF echoes it), which is
    // what `smf_n4_seid_hash` indexes.
    let Some((sm_context_ref, supi, psi, amf_uri, up_deactivated)) = ({
        let handle = smf_self();
        handle.read().ok().and_then(|ctx| {
            let sess = ctx.sess_find_by_seid(seid)?;
            let reference = sess.sm_context_ref.clone()?;
            let binding = ctx
                .policy_bindings
                .read()
                .ok()
                .and_then(|b| b.get(&reference).cloned());
            let supi = binding
                .as_ref()
                .map(|b| b.supi.clone())
                .or_else(|| ctx.ue_find_by_id(sess.smf_ue_id).and_then(|ue| ue.supi))?;
            let amf_uri = binding
                .as_ref()
                .and_then(|b| b.sm_context_status_uri.clone())
                .or_else(|| sess.sm_context_status_uri.clone());
            Some((
                reference,
                supi,
                sess.psi,
                amf_uri,
                sess.up_cnx_state == context::UpCnxState::Deactivated,
            ))
        })
    }) else {
        log::warn!(
            "Downlink Data Report for SEID=0x{seid:016x} matches no SM context: cannot page \
             (the packet stays buffered at the UPF)"
        );
        return;
    };

    if !up_deactivated {
        // TS 29.244 §7.5.8.2 scopes the DLDR to a *deactivated* user-plane
        // connection. With the connection up, the UPF should be forwarding rather
        // than buffering, and paging a UE that is already connected would be a
        // spurious service request.
        log::warn!(
            "Downlink Data Report for ref={sm_context_ref} whose UP connection is not \
             DEACTIVATED: not paging"
        );
        return;
    }

    let Some(amf_uri) = amf_uri else {
        log::warn!(
            "No serving-AMF callback URI for ref={sm_context_ref}: cannot page the UE for \
             buffered downlink data"
        );
        return;
    };

    send_n1_n2_paging_request(&amf_uri, &supi, psi, qfi).await;
}

/// Ask the AMF to page an idle UE for buffered downlink data (#78,
/// TS 29.518 §5.2.2.3.1 with an `n2InfoContainer`).
///
/// The body carries `n2InfoContainer` rather than `n1MessageContainer` because the
/// point is to re-establish the user plane, not to deliver a NAS message. `skipInd`
/// is deliberately absent: the AMF must NOT skip paging, which is the entire
/// purpose of the request.
async fn send_n1_n2_paging_request(amf_uri: &str, supi: &str, psi: u8, qfi: Option<u8>) {
    use nextgcore_sbi::constants::content_type;
    use nextgcore_sbi::message::SbiRequest as SReq;

    let Some((host, port)) = policy::split_host_port(amf_uri) else {
        log::warn!("AMF URI '{amf_uri}' is not a valid URI — skipping the paging request");
        return;
    };

    let path = format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages");
    let mut body = serde_json::json!({
        "pduSessionId": psi,
        "n2InfoContainer": {
            "n2InformationClass": "SM",
            "smInfo": {
                "pduSessionId": psi,
                "n2InfoContent": {
                    "ngapIeType": "PDU_RES_SETUP_REQ"
                }
            }
        },
    });
    if let Some(qfi) = qfi {
        // The QFI the UPF reported the buffered packet against, so the AMF can tell
        // the gNB which flow to re-establish.
        body["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapData"] =
            serde_json::json!({ "qfi": qfi });
    }
    let request = SReq::post(&path).with_body(body.to_string(), content_type::APPLICATION_JSON);
    let client = nextgcore_sbi::client::SbiClient::new(
        nextgcore_sbi::security::sbi_peer_client_config(&host, port)
            .with_connect_timeout(std::time::Duration::from_secs(2))
            .with_request_timeout(std::time::Duration::from_secs(3)),
    );
    match client.send_request(request).await {
        Ok(resp) => log::info!(
            "N1N2MessageTransfer (paging, SUPI {supi}, PSI {psi}, QFI {qfi:?}) → \
             {host}:{port}: status={}",
            resp.status
        ),
        Err(e) => log::warn!("N1N2MessageTransfer (paging) to {host}:{port} failed: {e}"),
    }
}

/// Send a 5GSM message to the UE via the AMF (Namf_Communication
/// N1N2MessageTransfer, TS 29.518 §5.2.2.3.1).
///
/// The AMF authority comes from the `smContextStatusUri` it supplied at SM
/// context create — the SMF has no other address for it, and an AMF that supplied
/// no callback URI cannot be reached, so the transfer is skipped with a warning
/// rather than guessed at.
async fn send_n1_n2_message_transfer(amf_uri: Option<&str>, supi: &str, psi: u8, n1: &[u8]) {
    use nextgcore_sbi::constants::content_type;
    use nextgcore_sbi::message::{SbiPart, SbiRequest as SReq};

    let Some(uri) = amf_uri else {
        log::warn!(
            "No AMF callback URI for SUPI {supi} PSI {psi}: cannot transfer the \
             5GSM message to the UE"
        );
        return;
    };
    let Some((host, port)) = policy::split_host_port(uri) else {
        log::warn!("AMF URI '{uri}' is not a valid URI — skipping N1N2MessageTransfer");
        return;
    };

    let path = format!("/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages");
    let body = serde_json::json!({
        "n1MessageContainer": {
            "n1MessageClass": "SM",
            "n1MessageContent": { "contentId": "n1SmMsg" }
        },
        "pduSessionId": psi,
    });
    let request = SReq::post(&path)
        .with_body(body.to_string(), content_type::APPLICATION_JSON)
        .with_part(SbiPart::with_content(
            "n1SmMsg",
            content_type::APPLICATION_5GNAS,
            bytes::Bytes::copy_from_slice(n1),
        ));
    let client = nextgcore_sbi::client::SbiClient::new(
        nextgcore_sbi::security::sbi_peer_client_config(&host, port)
            .with_connect_timeout(std::time::Duration::from_secs(2))
            .with_request_timeout(std::time::Duration::from_secs(3)),
    );
    match client.send_request(request).await {
        Ok(resp) => log::info!(
            "N1N2MessageTransfer (SUPI {supi}, PSI {psi}, {} bytes) → {host}:{port}: status={}",
            n1.len(),
            resp.status
        ),
        Err(e) => log::warn!("N1N2MessageTransfer to {host}:{port} failed: {e}"),
    }
}

/// The 5GSM message the UE sent, dispatched from the `n1SmMsg` container on
/// `/modify`.
///
/// Returned rather than acted on inline so the decision is testable without an
/// SBI request, a PCF or a UPF: `handle_n1_sm_message` maps bytes to intent, and
/// the caller carries out the intent.
#[derive(Debug, Clone, PartialEq, Eq)]
enum N1SmIntent {
    /// UE-requested release (TS 24.501 §6.4.3.3): answer with RELEASE COMMAND,
    /// release the user plane, arm T3592.
    ReleaseRequested { psi: u8, pti: u8, cause: Option<u8> },
    /// UE-requested modification (§6.4.1.3): answer with MODIFICATION COMMAND,
    /// arm T3591.
    ModificationRequested { psi: u8, pti: u8 },
    /// The UE completed a network-requested modification: stop T3591.
    ModificationComplete,
    /// The UE completed a network-requested release: stop T3592, drop the context.
    ReleaseComplete,
    /// 5GSM STATUS (§6.5): the UE reports an error condition.
    Status { cause: Option<u8> },
    /// A 5GSM message this SMF does not act on at this point in the session.
    Unhandled { message_type: u8 },
}

/// Classify the 5GSM message in an `n1SmMsg` container.
///
/// `None` when the buffer is not a 5GSM message at all (wrong EPD or too short),
/// which is a malformed request rather than an unhandled procedure.
fn classify_n1_sm_message(n1: &[u8]) -> Option<N1SmIntent> {
    let hdr = policy::parse_n1_sm_header(n1)?;
    // The 5GSM cause, when present, is the octet after the header for the
    // messages that carry it as a mandatory IE (TS 24.501 §8.3.x).
    let cause = n1.get(4).copied();
    Some(match hdr.message_type {
        gsm_build::message_type::PDU_SESSION_RELEASE_REQUEST => N1SmIntent::ReleaseRequested {
            psi: hdr.psi,
            pti: hdr.pti,
            cause,
        },
        gsm_build::message_type::PDU_SESSION_MODIFICATION_REQUEST => {
            N1SmIntent::ModificationRequested {
                psi: hdr.psi,
                pti: hdr.pti,
            }
        }
        gsm_build::message_type::PDU_SESSION_MODIFICATION_COMPLETE => {
            N1SmIntent::ModificationComplete
        }
        gsm_build::message_type::PDU_SESSION_RELEASE_COMPLETE => N1SmIntent::ReleaseComplete,
        gsm_build::message_type::GSM_STATUS => N1SmIntent::Status { cause },
        other => N1SmIntent::Unhandled {
            message_type: other,
        },
    })
}

/// Handle a `/modify` request whose payload is a UE-originated 5GSM message.
///
/// This is the gap the issue reports: the `/modify` handler branched only on
/// `n2SmInfoType`, so a request carrying **only** an N1 container fell into the
/// `upCnxState` branch and the 5GSM message was never decoded. A UE that released
/// or modified a PDU session got a `{"upCnxState":"ACTIVATED"}` reply and the
/// network never ran the procedure: the SMF context, the PFCP session and the
/// gNB's N2 resources stayed allocated indefinitely.
async fn handle_n1_sm_message(sm_context_ref: &str, n1: &[u8]) -> SbiResponse {
    let Some(intent) = classify_n1_sm_message(n1) else {
        return problem_400(
            "N1_SM_ERROR",
            "n1SmMsg is not a 5GSM message (EPD is not 0x2E, or it is too short)",
        );
    };

    let binding = lookup_policy_binding(sm_context_ref);
    let Some(binding) = binding else {
        log::warn!("N1 5GSM message for unknown SM context ref={sm_context_ref}");
        return problem_404("CONTEXT_NOT_FOUND", "no such SM context");
    };
    let amf_uri = binding.sm_context_status_uri.clone();

    match intent {
        N1SmIntent::ReleaseRequested { psi, pti, cause } => {
            log::info!(
                "UE-requested PDU session release for ref={sm_context_ref} \
                 (PSI={psi}, PTI={pti}, cause={cause:?})"
            );
            // Release the user plane first: the UE has asked to go away, so the
            // UPF forwarding state and the IP are released before the command is
            // acknowledged. The context itself lives until RELEASE COMPLETE so
            // T3592 has something to key on.
            release_user_plane(sm_context_ref).await;

            let n1_cmd = policy::build_release_command(
                psi,
                pti,
                cause.unwrap_or(policy::gsm_cause::REQUEST_REJECTED_UNSPECIFIED),
            );
            let n2_cmd = build_release_command_transfer();
            arm_gsm_timer(
                sm_context_ref,
                timer::SmfTimerId::T3592,
                &n1_cmd,
                &binding.supi,
                psi,
                amf_uri.as_deref(),
            );
            sbi_response_with_n1_n2(
                200,
                serde_json::json!({ "n2SmInfoType": "PDU_RES_REL_CMD" }),
                &n1_cmd,
                &n2_cmd,
            )
        }

        N1SmIntent::ModificationRequested { psi, pti } => {
            log::info!(
                "UE-requested PDU session modification for ref={sm_context_ref} \
                 (PSI={psi}, PTI={pti})"
            );
            let n1_cmd = policy::build_modification_command(
                psi,
                pti,
                binding.ambr_dl_bps,
                binding.ambr_ul_bps,
            );
            arm_gsm_timer(
                sm_context_ref,
                timer::SmfTimerId::T3591,
                &n1_cmd,
                &binding.supi,
                psi,
                amf_uri.as_deref(),
            );
            let body = serde_json::json!({ "n1SmMsg": { "contentId": "n1SmMsg" } });
            sbi_response_with_n1(200, body, &n1_cmd)
        }

        N1SmIntent::ModificationComplete => {
            cancel_gsm_timer(sm_context_ref, timer::SmfTimerId::T3591);
            SbiResponse::with_status(204)
        }

        N1SmIntent::ReleaseComplete => {
            cancel_gsm_timer(sm_context_ref, timer::SmfTimerId::T3592);
            // The release procedure is finished: drop the context and tell the
            // AMF, which is what the SMF-initiated release path also does.
            let removed = smf_self().read().ok().and_then(|ctx| {
                ctx.policy_bindings
                    .write()
                    .ok()
                    .and_then(|mut b| b.remove(sm_context_ref))
            });
            if let Ok(context) = smf_self().read() {
                if let Some(sess) = context.sess_find_by_sm_context_ref(sm_context_ref) {
                    context.sess_remove(sess.id);
                }
            }
            let status_uri = removed.and_then(|b| b.sm_context_status_uri);
            send_sm_context_status_notification(status_uri.as_deref(), "RELEASED", None).await;
            SbiResponse::with_status(204)
        }

        N1SmIntent::Status { cause } => {
            log::warn!("5GSM STATUS from UE for ref={sm_context_ref}: cause={cause:?}");
            SbiResponse::with_status(204)
        }

        N1SmIntent::Unhandled { message_type } => {
            log::warn!(
                "5GSM message type {message_type:#04x} in n1SmMsg for ref={sm_context_ref} \
                 is not handled on /modify"
            );
            problem_400(
                "N1_SM_ERROR",
                &format!("unhandled 5GSM message type {message_type:#04x}"),
            )
        }
    }
}

/// Release the user-plane resources for an SM context without removing the
/// context itself: PFCP session deletion plus the PCF policy association.
///
/// Shared by the UE-initiated release path and reachable independently of the
/// full `/release` handler, which additionally drops the context.
async fn release_user_plane(sm_context_ref: &str) {
    if let Some(binding) = lookup_policy_binding(sm_context_ref) {
        if let Some(ref pol_id) = binding.sm_policy_id {
            match policy::resolve_pcf_endpoint().await {
                Some(pcf) => match policy::sm_policy_delete(&pcf, pol_id).await {
                    Ok(()) => log::info!("SM policy association {pol_id} deleted at PCF"),
                    Err(e) => log::warn!("SM policy delete failed: {e} (continuing release)"),
                },
                None => log::warn!("PCF unresolved — skipping SM policy delete"),
            }
        }
    }
    if let Some(seid) = lookup_upf_seid(sm_context_ref) {
        match pfcp_session_delete(smf_n4_seid_for(sm_context_ref), seid).await {
            Ok(()) => {
                log::info!("PFCP session deleted for ref={sm_context_ref} on UE-requested release")
            }
            Err(e) => log::warn!("PFCP Session Deletion failed for ref={sm_context_ref}: {e}"),
        }
    }
}

/// The N2 `PDUSessionResourceReleaseCommandTransfer` (TS 38.413 §9.3.4.4) the AMF
/// relays to the gNB so the radio and N3 resources are released too.
fn build_release_command_transfer() -> Vec<u8> {
    use nextgcore_ngap::transfer::PduSessionResourceReleaseCommandTransfer;
    let transfer = PduSessionResourceReleaseCommandTransfer {
        cause: nextgcore_ngap::types::Cause::Nas(
            nextgcore_asn1c::ngap::cause::CauseNas::NormalRelease,
        ),
    };
    transfer.encode().unwrap_or_else(|e| {
        log::error!("Failed to encode PDUSessionResourceReleaseCommandTransfer: {e}");
        Vec::new()
    })
}

/// A 200 response carrying only an N1 SM message part.
fn sbi_response_with_n1(
    status: u16,
    mut json_root: serde_json::Value,
    n1_sm_msg: &[u8],
) -> SbiResponse {
    use nextgcore_sbi::constants::content_type;
    use nextgcore_sbi::message::SbiPart;
    json_root["n1SmMsg"] = serde_json::json!({ "contentId": "n1SmMsg" });
    SbiResponse::with_status(status)
        .with_body(json_root.to_string(), content_type::APPLICATION_JSON)
        .with_part(SbiPart::with_content(
            "n1SmMsg",
            content_type::APPLICATION_5GNAS,
            bytes::Bytes::copy_from_slice(n1_sm_msg),
        ))
}

/// Build the SmContextStatusNotification body (TS 29.502 §6.1.6.2.8): a
/// `statusInfo` carrying the `resourceStatus` (e.g. `RELEASED`) and an optional
/// release `cause`. smfd-07.
fn build_sm_context_status_notification(
    resource_status: &str,
    cause: Option<&str>,
) -> serde_json::Value {
    let mut status_info = serde_json::json!({ "resourceStatus": resource_status });
    if let Some(c) = cause {
        status_info["cause"] = serde_json::json!(c);
    }
    serde_json::json!({ "statusInfo": status_info })
}

/// Extract the path (and query) portion of an absolute or relative URI.
fn uri_path(uri: &str) -> String {
    let stripped = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    match stripped.find('/') {
        Some(idx) => stripped[idx..].to_string(),
        None => "/".to_string(),
    }
}

/// POST an SmContextStatusNotification to the AMF-supplied `smContextStatusUri`
/// (TS 29.502 §5.2.2.8) on SMF-initiated release / abnormal termination. A
/// missing URI is a no-op (notifications disabled). Best-effort: transport
/// failures are logged, not propagated — the local release proceeds regardless.
/// smfd-07.
async fn send_sm_context_status_notification(
    uri: Option<&str>,
    resource_status: &str,
    cause: Option<&str>,
) {
    let Some(uri) = uri else {
        log::debug!("No smContextStatusUri — skipping SmContextStatusNotification");
        return;
    };
    let Some((host, port)) = policy::split_host_port(uri) else {
        log::warn!("smContextStatusUri '{uri}' is not a valid URI — skipping notification");
        return;
    };
    let path = uri_path(uri);
    let body = build_sm_context_status_notification(resource_status, cause);
    let client = nextgcore_sbi::client::SbiClient::new(
        nextgcore_sbi::security::sbi_peer_client_config(&host, port)
            .with_connect_timeout(std::time::Duration::from_secs(2))
            .with_request_timeout(std::time::Duration::from_secs(3)),
    );
    match client.post_json(&path, &body).await {
        Ok(resp) => log::info!(
            "SmContextStatusNotification ({resource_status}) → {uri}: status={}",
            resp.status
        ),
        Err(e) => log::warn!("SmContextStatusNotification to {uri} failed: {e}"),
    }
}

/// Handle SM Context Release (TS 29.502 §5.2.2.4)
///
/// Deletes the PCF SM policy association (Npcf_SMPolicyControl_Delete,
/// TS 29.512 §4.2.5), sends PFCP Session Deletion to the UPF, releases the
/// UE IP and removes session state. The GSM FSM is driven through
/// WaitPfcpDeletion to release.
/// `POST /nsmf-pdusession/v1/easdf-dns-reports` — the EASDF DNS-message report
/// sink (#114, TS 23.548 §6.2.3.2.2).
///
/// The EASDF reports what it resolved for a session's DNS query; the SMF records
/// the EAS address(es) against that session so a later UL-CL / PSA re-selection
/// can act on them.
///
/// **Ceiling, stated rather than implied:** the report is recorded and logged, and
/// nothing re-routes the user plane yet. Inserting a UL-CL for the reported EAS is
/// traffic-influence work with its own N4 and PSA implications, and doing it
/// half-way — installing a rule that does not match, say — would be worse than
/// recording the fact and saying so. `easdf_reported_eas` is where that work will
/// read from.
///
/// Always `204`: a report is a notification, and there is nothing for the EASDF to
/// do about a report the SMF cannot attribute (it answers 204 with a log line
/// rather than an error, so a stale context id does not make the EASDF retry).
async fn handle_easdf_dns_report(request: &SbiRequest) -> SbiResponse {
    let Some(body) = request.http.content.as_deref() else {
        return problem_400(
            "MANDATORY_IE_MISSING",
            "a DNS message report body is required",
        );
    };
    let report: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return problem_400("INVALID_MSG_FORMAT", &format!("unparseable report: {e}")),
    };
    let ctx_id = report
        .get("dnsContextId")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let fqdn = report.get("fqdn").and_then(|v| v.as_str()).unwrap_or("");
    let addresses: Vec<String> = report
        .get("easIpAddresses")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    // Attribute the report to the session that owns the DNS context.
    let mut matched = false;
    if let Ok(ctx) = smf_self().read() {
        if let Ok(mut bindings) = ctx.policy_bindings.write() {
            for binding in bindings.values_mut() {
                if binding.easdf_dns_context_id.as_deref() == Some(ctx_id) {
                    binding.easdf_reported_eas = addresses.clone();
                    matched = true;
                    log::info!(
                        "[{}] EASDF reported {fqdn} -> {addresses:?} (context {ctx_id})",
                        binding.supi
                    );
                    break;
                }
            }
        }
        if matched {
            // Issue #191: the reported EAS list is part of the binding, so it is
            // part of the snapshot.
            ctx.persist();
        }
    }
    if !matched {
        log::warn!(
            "EASDF DNS report for context {ctx_id} ({fqdn}) matches no session: the context \
             outlived its PDU session, or was created by another SMF"
        );
    }
    SbiResponse::with_status(204)
}

async fn handle_sm_context_release(
    sm_context_ref: &str,
    request: Option<&SbiRequest>,
) -> SbiResponse {
    log::info!("SM Context Release request for ref={sm_context_ref}");

    // #78 / TS 29.502 §5.2.2.4: a release of an unknown context must NOT silently
    // succeed. Answering 204 for a reference the SMF does not hold tells the AMF a
    // context was torn down when nothing was, which masks lost state and corrupts
    // session accounting — the AMF cannot then distinguish a live context from a
    // stale one.
    //
    // Only checked for an AMF-driven release. The PCF-driven path (`request` is
    // `None`) passes a reference it read out of the binding map itself, and the
    // binding is removed below, so re-checking would be checking our own read.
    if request.is_some() && !sm_context_exists(sm_context_ref) {
        log::warn!("SM Context Release for unknown ref={sm_context_ref}: answering 404");
        return problem_response(
            404,
            "CONTEXT_NOT_FOUND",
            "No SM context for this smContextRef",
        );
    }

    // #78 / TS 29.502 §5.2.2.4: parse SmContextReleaseData. Before #78 this
    // function took no body argument at all, so `cause`, `n2SmInfo` and
    // `vsmfReleaseOnly` were unreadable.
    let release_data = request
        .map(parse_sm_context_release_data)
        .unwrap_or_default();
    if let Some(ref cause) = release_data.cause {
        log::info!("SM Context Release ref={sm_context_ref} cause={cause}");
    }
    if release_data.vsmf_release_only {
        // TS 29.502 §6.1.6.2.13: the V-SMF releases only its own resources and the
        // H-SMF keeps the session. This SMF has no V-SMF/H-SMF split on this path
        // (`is_home_routed_roaming_in_vsmf` is driven by `pdu_session_ref`, which
        // the sm-contexts path never sets), so honouring the flag here would mean
        // pretending to a split that does not exist. Recorded, and the limit is
        // stated rather than a partial release invented.
        log::warn!(
            "SM Context Release ref={sm_context_ref} set vsmfReleaseOnly, but this SMF has no \
             V-SMF/H-SMF split on the sm-contexts path: the whole session is released"
        );
    }

    // Take the policy binding (copy out, drop guards before any await)
    let binding = smf_self().read().ok().and_then(|ctx| {
        ctx.policy_bindings
            .write()
            .ok()
            .and_then(|mut bindings| bindings.remove(sm_context_ref))
    });

    // #114: delete this session's EASDF DNS context. Read off the binding taken
    // above, so a session that never had one costs nothing here. Best-effort: a
    // failure leaves an orphan the EASDF's own capacity cap bounds, whereas
    // failing the release would leave this SMF's session state inconsistent with
    // the AMF's.
    if let Some(binding) = &binding {
        if let (Some(ctx_id), supi) = (&binding.easdf_dns_context_id, &binding.supi) {
            easdf::delete_dns_context(supi, ctx_id).await;
        }
    }

    // #293: tell the UDM this session is over — remove the serving-SMF record and
    // delete the SDM subscription created at establishment. Both read off the binding
    // taken above, both are best-effort for the same reason as the EASDF delete, and
    // both name what is left behind on failure.
    //
    // Without the deregistration a UDM accumulates serving-SMF records for released
    // sessions, so a procedure resolving the serving SMF through the UDM resolves a
    // released session to this SMF. Without the unsubscribe the UDM keeps notifying a
    // callback URI whose smContextRef no longer resolves — which the notification
    // handler answers 404 to, deliberately.
    if let Some(binding) = &binding {
        udm::deregister_serving_smf(&binding.supi, binding.psi).await;
        if let Some(sub_id) = &binding.sdm_subscription_id {
            udm::unsubscribe_sm_data(&binding.supi, sub_id).await;
        }
    }

    // #291: give this session's EPS bearer identity back to the AMF, which owns the
    // space. Same shape as the EASDF delete above and for the same reason: read off
    // the binding taken above, so a session that never had an EBI costs nothing, and
    // best-effort because the session is leaving either way.
    //
    // Without this the eleven-wide per-UE space (TS 24.301 §9.3.2 reserves 0..=4)
    // leaks one identity per session lifetime, and because the AMF allocates
    // lowest-free it does not look under pressure until the twelfth session gets a
    // 403 with no live bearers to show for it.
    //
    // The AMF's authority is the same `smContextStatusUri` callback root the
    // assignment used and that this handler notifies below — the only address this
    // SMF has for it.
    if let Some(binding) = &binding {
        if let Some(ebi) = binding.mapped_eps_bearer_id {
            eps_iwk::release_ebi(
                binding.sm_context_status_uri.as_deref(),
                &binding.supi,
                binding.psi,
                ebi,
            )
            .await;
        }
    }

    // #79: Nsmf_EventExposure_Notify for PDU_SES_REL (TS 29.508 §4.2.3.2). Emitted
    // from the binding taken above, so a subscription scoped to this SUPI or this
    // PDU session id can be matched. A session with no matching subscription costs
    // one map read.
    if let Some(binding) = &binding {
        event_exposure::notify(
            event_exposure::event::PDU_SES_REL,
            &binding.supi,
            binding.psi,
        )
        .await;
    }

    // Drive the GSM FSM: Operational → WaitPfcpDeletion
    let mut fsm = binding.as_ref().map(|b| b.fsm.clone());
    if let Some(ref mut f) = fsm {
        let mut ev = event::SmfEvent::sbi_server(
            0,
            event::SbiRequest {
                method: "POST".to_string(),
                uri: format!("/nsmf-pdusession/v1/sm-contexts/{sm_context_ref}/release"),
                body: None,
            },
        );
        if let Some(ref mut sbi) = ev.sbi {
            sbi.message = Some(event::SbiMessage {
                service_name: "nsmf-pdusession".to_string(),
                resource_components: vec![
                    "sm-contexts".to_string(),
                    sm_context_ref.to_string(),
                    "release".to_string(),
                ],
                ..Default::default()
            });
        }
        f.dispatch(&ev);
    }

    // N7: delete the SM policy association at the PCF
    if let Some(ref b) = binding {
        if let Some(ref pol_id) = b.sm_policy_id {
            match policy::resolve_pcf_endpoint().await {
                Some(pcf) => match policy::sm_policy_delete(&pcf, pol_id).await {
                    Ok(()) => log::info!("SM policy association {pol_id} deleted at PCF"),
                    Err(e) => log::warn!("SM policy delete failed: {e} (continuing release)"),
                },
                None => log::warn!("PCF unresolved — skipping SM policy delete"),
            }
        }
    }

    // Look up UPF SEID for this session (from SmfContext, not a global)
    let upf_seid = lookup_upf_seid(sm_context_ref);

    if let Some(seid) = upf_seid {
        // Send PFCP Session Deletion Request to UPF (with retransmission)
        match pfcp_session_delete(smf_n4_seid_for(sm_context_ref), seid).await {
            Ok(()) => {
                log::info!("PFCP Session Deleted: UPF SEID=0x{seid:016x} for ref={sm_context_ref}");
                if let Some(ref mut f) = fsm {
                    // WaitPfcpDeletion → release path
                    f.dispatch(&event::SmfEvent::n4_message(0, 0, Vec::new()));
                }
            }
            Err(e) => {
                // The local context is removed anyway: keeping it would leak
                // resources for a session the peer may no longer have
                log::warn!("PFCP Session Deletion failed: {e} (continuing with release)");
            }
        }

        // Remove from PFCP sessions map
        if let Ok(ctx) = smf_self().read() {
            if let Ok(mut sessions) = ctx.pfcp_sessions.write() {
                sessions.remove(sm_context_ref);
            }
            // Issue #191: after the write guard drops (see `SmfContext::persist`).
            ctx.persist();
        }
    } else {
        log::warn!("No PFCP session found for sm_context_ref={sm_context_ref}");
    }

    // Release the UE IP allocated for this session
    if let Some(ref b) = binding {
        if let Ok(ctx) = smf_self().read() {
            ctx.ipv4_pool.release(std::net::Ipv4Addr::from(b.ue_ip));
            // Issue #191: a release that is not persisted leaves the address held
            // in the snapshot forever -- a pool leak across restarts, which is the
            // mirror of the double-assignment the snapshot exists to prevent.
            ctx.persist();
        }
    }

    // Remove from SMF context
    let ctx = smf_self();
    if let Ok(context) = ctx.read() {
        if let Some(sess) = context.sess_find_by_sm_context_ref(sm_context_ref) {
            context.sess_remove(sess.id);
        }
    }

    // Notify the AMF the SM context is RELEASED (TS 29.502 §5.2.2.8). No-op
    // when the AMF supplied no smContextStatusUri (the matched-sim AMF). smfd-07.
    let status_uri = binding
        .as_ref()
        .and_then(|b| b.sm_context_status_uri.clone());
    send_sm_context_status_notification(status_uri.as_deref(), "RELEASED", None).await;

    SbiResponse::with_status(204)
}

/// Register an SM context and return `(smContextRef, session id)` (#78).
///
/// The reference is read back OUT of the session rather than computed alongside it.
/// `sess_add_by_psi` mints `sm_context_ref` from the context's `sess_index`, and the
/// create handler used to compute its reference from `next_sess_index()` — the
/// **same** counter. Doing both consumes it twice and leaves the handler's reference
/// one behind the session's, so the value handed to the AMF resolves to nothing, or
/// worse to the next session. One source, by construction.
///
/// Extracted so that invariant is testable: the create handler's success path needs
/// a PFCP-responding UPF that no harness in this tree has, so a test cannot observe
/// the reference the handler returns. It can observe this function's.
///
/// `None` when the UE or session capacity cap is reached, which the caller must
/// report rather than answering with a reference no Retrieve can resolve.
fn register_sm_context(
    context: &context::SmfContext,
    supi: &str,
    psi: u8,
) -> Option<(String, u64)> {
    let ue = context
        .ue_find_by_supi(supi)
        .or_else(|| context.ue_add_by_supi(supi))?;
    let sess = context.sess_add_by_psi(ue.id, psi)?;
    let reference = sess.sm_context_ref.clone()?;
    Some((reference, sess.id))
}

/// Does the SMF hold an SM context for this reference? (#78)
///
/// Checks BOTH the session list and the policy-binding map, and accepts either.
/// The two are populated on the same create and removed on the same release, but
/// they are separate maps: requiring both would make a reference the SMF can
/// plainly act on look unknown if one half was lost, which is a worse answer than
/// acting on the half that survived.
fn sm_context_exists(sm_context_ref: &str) -> bool {
    let handle = smf_self();
    let Ok(ctx) = handle.read() else {
        return false;
    };
    if ctx.sess_find_by_sm_context_ref(sm_context_ref).is_some() {
        return true;
    }
    ctx.policy_bindings
        .read()
        .map(|b| b.contains_key(sm_context_ref))
        .unwrap_or(false)
}

/// `SmContextReleaseData` (TS 29.502 §6.1.6.2.13, #78).
#[derive(Debug, Default, Clone)]
struct SmContextReleaseData {
    /// Release cause the AMF reported
    cause: Option<String>,
    /// N2 SM information carried with the release, when present
    n2_sm_info: Option<Vec<u8>>,
    /// The V-SMF releases only its own resources
    vsmf_release_only: bool,
}

/// Parse `SmContextReleaseData` from a release request (#78).
///
/// Every member is optional in the yaml, so an EMPTY body is valid and yields the
/// default — a release with no stated cause is still a release, and refusing it
/// would break the AMF path that sends none.
fn parse_sm_context_release_data(request: &SbiRequest) -> SmContextReleaseData {
    let Some(json) = request
        .http
        .content
        .as_deref()
        .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
    else {
        return SmContextReleaseData::default();
    };
    SmContextReleaseData {
        cause: json["cause"].as_str().map(str::to_string),
        // The same RefToBinaryData / base64 duality every other N2 payload on this
        // path accepts (see `resolve_binary_ref`).
        n2_sm_info: resolve_binary_ref(request, &json["n2SmInfo"]),
        vsmf_release_only: json["vsmfReleaseOnly"].as_bool().unwrap_or(false),
    }
}

/// Handle SM Context Retrieve
async fn handle_sm_context_retrieve(sm_context_ref: &str) -> SbiResponse {
    log::info!("SM Context Retrieve request for ref={sm_context_ref}");

    let ctx = smf_self();
    if let Ok(context) = ctx.read() {
        if let Some(sess) = context.sess_find_by_sm_context_ref(sm_context_ref) {
            // #117: the EBI the AMF assigned this session, when interworking is on.
            // Read from the policy binding, which is where the create path recorded
            // it; `None` reproduces #78's output exactly.
            let eps_bearer_id = context
                .policy_bindings
                .read()
                .ok()
                .and_then(|b| b.get(sm_context_ref).and_then(|p| p.mapped_eps_bearer_id));
            let up_cnx_state = match sess.up_cnx_state {
                context::UpCnxState::Activated => "ACTIVATED",
                context::UpCnxState::Activating => "ACTIVATING",
                context::UpCnxState::Deactivated => "DEACTIVATED",
            };

            let mut response_body = serde_json::json!({
                "smContextRef": sm_context_ref,
                "pduSessionId": sess.psi,
                "dnn": sess.session_name,
                "sNssai": {
                    "sst": sess.s_nssai.sst,
                    "sd": sess.s_nssai.sd
                },
                "upCnxState": up_cnx_state,
                // #78: `ueEpsPdnConnection` is a REQUIRED member of
                // SmContextRetrievedData (TS29502_Nsmf_PDUSession.yaml), and it was
                // absent -- so the body did not deserialise as the type the AMF
                // expects even once Retrieve started answering 200.
                "ueEpsPdnConnection": build_ue_eps_pdn_connection(&sess, eps_bearer_id),
            });
            // Only include what the session actually holds: an absent member means
            // "not applicable", while a member present with a placeholder value is a
            // claim about the session that is not true.
            if let Some(ref uri) = sess.sm_context_status_uri {
                response_body["smContextStatusUri"] = serde_json::json!(uri);
            }

            return SbiResponse::with_status(200)
                .with_body(response_body.to_string(), "application/json");
        }
    }

    // #78: a ProblemDetails body, not a bare status/cause pair. TS 29.500 §5.2.7
    // and the Nsmf yaml both make the 404 body a ProblemDetails, and a consumer
    // deserialising one gets nothing usable from `{"status":..,"cause":..}` alone.
    problem_response(
        404,
        "CONTEXT_NOT_FOUND",
        "No SM context for this smContextRef",
    )
}

/// Build the `ueEpsPdnConnection` member of `SmContextRetrievedData`
/// (TS 29.502 §5.2.2.6.1, #78).
///
/// The member carries the EPS PDN Connection this 5GS session maps to, for
/// 5GS↔EPS interworking (TS 23.502 §4.11.1.4.1). It is a `Bytes` (base64-encoded
/// octet string) in the yaml: the encoded `ueEpsPdnConnection` container.
///
/// **What this returns, and what it deliberately does not.** #78 shipped the
/// minimal PDN-connection descriptor derivable from the 5GS session (APN, PDN
/// type, the UE address, the default bearer's QoS) and **no** bearer-context list,
/// because there was no EBI assignment anywhere in the tree and a fabricated
/// bearer list is worse than a minimal one: the AMF would forward it to an MME that
/// would then try to use bearers this SMF has not established.
///
/// #117 changes exactly one thing about that: when an EBI **was** assigned, the
/// descriptor names it. That is not a fabrication — the AMF allocated the identity
/// and the UE has already been told about it in the Mapped EPS bearer contexts IE,
/// so an MME receiving it will find the bearer the UE claims to have. With no EBI
/// assigned (interworking off, or the assignment failed) the output is byte-for-byte
/// what #78 produced, which is what keeps criterion 5 true.
fn build_ue_eps_pdn_connection(sess: &context::SmfSess, eps_bearer_id: Option<u8>) -> String {
    use base64::Engine as _;
    // TS 24.301 PDN type values: 1 = IPv4, 2 = IPv6, 3 = IPv4v6.
    let pdn_type: u8 = match sess.session_type {
        context::PduSessionType::Ipv6 => 2,
        context::PduSessionType::Ipv4v6 => 3,
        _ => 1,
    };
    let mut buf: Vec<u8> = Vec::new();
    // APN, length-prefixed as in TS 24.301 §9.9.4.1.
    let apn = sess.session_name.as_deref().unwrap_or("");
    let apn_bytes = apn.as_bytes();
    buf.push(apn_bytes.len().min(u8::MAX as usize) as u8);
    buf.extend_from_slice(&apn_bytes[..apn_bytes.len().min(u8::MAX as usize)]);
    buf.push(pdn_type);
    // The UE address the PDN connection carries.
    match sess.ipv4_addr {
        Some(addr) => buf.extend_from_slice(&addr.octets()),
        None => buf.extend_from_slice(&[0, 0, 0, 0]),
    }
    // Default bearer QoS: the 5QI the session was authorised with, which is what
    // maps onto the EPS QCI.
    buf.push(sess.session_qos.index);
    // #117: the EPS bearer identity, when one was assigned. Appended rather than
    // inserted so the prefix stays identical to #78's output for a session without
    // one — a peer parsing the earlier form reads the same first bytes.
    if let Some(ebi) = eps_bearer_id {
        buf.push(ebi);
    }
    base64::engine::general_purpose::STANDARD.encode(&buf)
}

// =============================================================================
// PDU Session Handlers
// =============================================================================

/// Handle PDU Session Create
async fn handle_pdu_session_create(_request: &SbiRequest) -> SbiResponse {
    log::info!("H-SMF PDU Session Create request received (home-routed roaming)");
    hsmf_not_implemented("Create")
}

/// The H-SMF `/pdu-sessions` service answers `501`, deliberately.
///
/// #79's criterion offers a choice: implement Create/Update/Release with conformant
/// `PduSessionCreatedData`/`HsmfUpdatedData` bodies, or return `501` rather than a
/// fabricated `201`. `501` is taken, for two reasons.
///
/// **What it replaces was actively misleading.** Create answered `201` with
/// `{"pduSessionRef": "1", "cause": "REL_DUE_TO_HO"}` — a **release cause on a
/// create success**, at a hardcoded reference, with no session created. A partner
/// V-SMF parsing that gets "your session was established, and by the way it was
/// released for handover", about a session that does not exist. Update and Release
/// answered empty `200`/`204` bodies where `HsmfUpdatedData` is expected.
///
/// **Home-routed roaming is not implemented here.** There is no V-SMF/H-SMF split
/// in this tree: nothing establishes an H-SMF session, `PduSessionCreatedData`
/// requires `pduSessionType`, `sscMode` and one of `hSmfInstanceId`/`smfInstanceId`
/// (a `oneOf`), and every one of those would have to be invented. This project's
/// recorded rule for exactly this case is that a spec-defined resource whose
/// dependency is absent answers `501` — never a `404`, never a fabricated `2xx`.
///
/// A partner then fails **cleanly and diagnosably** at the point of the create,
/// instead of proceeding on a session that was never built. All three operations
/// answer the same way, because a partner that cannot create can never legitimately
/// update or release either, and leaving those at `2xx` would say otherwise.
fn hsmf_not_implemented(operation: &str) -> SbiResponse {
    nextgcore_sbi::server::send_error(
        501,
        "Not Implemented",
        &format!(
            "H-SMF PDU Session {operation} is not implemented: this SMF does not \
             support home-routed roaming (TS 29.502 §5.2.2.7). No V-SMF/H-SMF split \
             exists in this deployment."
        ),
        Some("NOT_IMPLEMENTED"),
    )
}

/// Handle PDU Session Update
async fn handle_pdu_session_update(pdu_session_ref: &str) -> SbiResponse {
    log::info!("H-SMF PDU Session Update request for ref={pdu_session_ref}");
    // Answered 200 with an EMPTY body where TS 29.502 §5.2.2.8 expects
    // `HsmfUpdatedData`. See `hsmf_not_implemented`: a partner that cannot create
    // through this service can never legitimately update through it either, and a
    // 2xx here would say otherwise.
    hsmf_not_implemented("Update")
}

/// Handle PDU Session Release
async fn handle_pdu_session_release(pdu_session_ref: &str) -> SbiResponse {
    log::info!("H-SMF PDU Session Release request for ref={pdu_session_ref}");
    // Used to remove a session by `pduSessionRef` and answer 204. That reference
    // space is the H-SMF's, which this SMF does not populate, so the lookup could
    // only ever match a session some other path had registered under it -- i.e. it
    // was a way for a partner to delete state it did not own. 501 both refuses the
    // unimplemented service and closes that.
    hsmf_not_implemented("Release")
}

// =============================================================================
// Event Exposure Handlers
// =============================================================================

/// Handle Event Subscribe
/// `POST /nsmf-event-exposure/v1/subscriptions` — Nsmf_EventExposure_Subscribe
/// (TS 29.508 §4.2.2.2), #79.
///
/// Answers `201` + `Location` + the created `NsmfEventExposure` document. The
/// previous version ignored the body, returned `{"subscriptionId": ...}` (not a
/// schema in TS 29.508) and stored nothing, so the id it handed out referenced
/// nothing and no notification could ever be sent to it.
async fn handle_event_subscribe(request: &SbiRequest) -> SbiResponse {
    let Some(body) = request
        .http
        .content
        .as_deref()
        .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
    else {
        return send_bad_request(
            "Request body is missing or not valid JSON",
            Some("INVALID_MSG_FORMAT"),
        );
    };
    let id = uuid::Uuid::new_v4().to_string();
    let sub = match event_exposure::parse_subscription(&body, id.clone()) {
        Ok(sub) => sub,
        Err(e) => return send_bad_request(&e.detail(), Some(e.cause())),
    };
    log::info!(
        "Event subscription {id} created: events={:?} notifUri={} ({} stored)",
        sub.events,
        sub.notif_uri,
        event_exposure::count() + 1
    );
    let document = event_exposure::insert(sub);
    SbiResponse::with_status(201)
        .with_header("Location", event_exposure::resource_path(&id))
        .with_json_body(&document)
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// `GET /nsmf-event-exposure/v1/subscriptions/{subId}` (TS 29.508 §4.2.2.3), #79.
async fn handle_event_subscription_get(subscription_id: &str) -> SbiResponse {
    match event_exposure::find(subscription_id) {
        Some(sub) => {
            let mut document = sub.document;
            if let Some(obj) = document.as_object_mut() {
                obj.insert("subId".to_string(), serde_json::json!(subscription_id));
                obj.insert(
                    "self".to_string(),
                    serde_json::json!(event_exposure::resource_path(subscription_id)),
                );
            }
            SbiResponse::with_status(200)
                .with_json_body(&document)
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => event_subscription_not_found(subscription_id),
    }
}

/// `PUT /nsmf-event-exposure/v1/subscriptions/{subId}` (TS 29.508 §4.2.2.4), #79.
///
/// Replaces an existing subscription and answers `200` with the stored document. A
/// `PUT` to an unknown id is a `404`, not a create: the id space belongs to the
/// SMF, so honouring a consumer-chosen one would let a consumer mint resources.
async fn handle_event_subscription_put(subscription_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(body) = request
        .http
        .content
        .as_deref()
        .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
    else {
        return send_bad_request(
            "Request body is missing or not valid JSON",
            Some("INVALID_MSG_FORMAT"),
        );
    };
    let sub = match event_exposure::parse_subscription(&body, subscription_id.to_string()) {
        Ok(sub) => sub,
        Err(e) => return send_bad_request(&e.detail(), Some(e.cause())),
    };
    if !event_exposure::replace(subscription_id, sub) {
        return event_subscription_not_found(subscription_id);
    }
    log::info!("Event subscription {subscription_id} replaced");
    handle_event_subscription_get(subscription_id).await
}

/// `DELETE /nsmf-event-exposure/v1/subscriptions/{subId}` —
/// Nsmf_EventExposure_Unsubscribe (TS 29.508 §4.2.2.5), #79.
///
/// `404` on an unknown id. The previous version answered `204` for anything, so a
/// consumer could not tell a successful unsubscribe from a subscription that had
/// never existed — which matters, because the latter means its notifications were
/// never going to arrive.
async fn handle_event_unsubscribe(subscription_id: &str) -> SbiResponse {
    match event_exposure::remove(subscription_id) {
        Some(_) => {
            log::info!("Event subscription {subscription_id} removed");
            SbiResponse::with_status(204)
        }
        None => event_subscription_not_found(subscription_id),
    }
}

fn event_subscription_not_found(subscription_id: &str) -> SbiResponse {
    nextgcore_sbi::server::send_error(
        404,
        "Not Found",
        &format!("Event subscription '{subscription_id}' not found"),
        Some("SUBSCRIPTION_NOT_FOUND"),
    )
}

// =============================================================================
// Callback Handlers
// =============================================================================

/// Handle SM Policy Update Notification (from PCF, TS 29.512 §4.2.3.2):
/// the SmPolicyNotification carries an SmPolicyDecision whose authorized
/// session AMBR / default QoS is applied to the session's N4 QER.
async fn handle_sm_policy_notify(sm_context_ref: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("SM Policy update notification for ref={sm_context_ref}");

    let Some(body) = request
        .http
        .content
        .as_deref()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
    else {
        return problem_400("INVALID_MSG_FORMAT", "SmPolicyNotification body required");
    };

    let Some(binding) = lookup_policy_binding(sm_context_ref) else {
        return send_not_found(
            &format!("No SM context for ref={sm_context_ref}"),
            Some("CONTEXT_NOT_FOUND"),
        );
    };

    // The decision may be nested (smPolicyDecision) or top-level
    let decision_json = body.get("smPolicyDecision").unwrap_or(&body);
    let pol_id = binding.sm_policy_id.clone().unwrap_or_default();
    let dec = policy::parse_sm_policy_decision(&pol_id, decision_json);

    log::info!(
        "Applying PCF-updated policy to ref={sm_context_ref}: AMBR UL/DL={}/{} bps, 5QI={}",
        dec.sess_ambr_ul_bps,
        dec.sess_ambr_dl_bps,
        dec.def_five_qi
    );

    // Apply to the N4 session QER (copy SEID out, no guards across await)
    if let Some(seid) = lookup_upf_seid(sm_context_ref) {
        if let Err(e) = pfcp_update_session_qer(
            smf_n4_seid_for(sm_context_ref),
            seid,
            binding.qfi,
            dec.sess_ambr_ul_bps,
            dec.sess_ambr_dl_bps,
        )
        .await
        {
            log::error!("Failed to apply PCF-updated QoS: {e}");
            return SbiResponse::with_status(504);
        }
    }

    // Persist the updated AMBR in the binding
    if let Ok(ctx) = smf_self().read() {
        if let Ok(mut bindings) = ctx.policy_bindings.write() {
            if let Some(b) = bindings.get_mut(sm_context_ref) {
                b.ambr_ul_bps = dec.sess_ambr_ul_bps;
                b.ambr_dl_bps = dec.sess_ambr_dl_bps;
                b.five_qi = dec.def_five_qi;
            }
        }
        // Issue #191: durable too, not just in memory.
        ctx.persist();
    }

    SbiResponse::with_status(204)
}

/// `POST /nsmf-callback/v1/sdm-notify/{smContextRef}` — `Nudm_SDM_Notification`
/// (issue #293, TS 29.503 §5.2.2.6).
///
/// The UDM tells us the subscriber's SM data changed; this applies the change to the
/// LIVE session so an administrative edit to a session-AMBR or default 5QI takes
/// effect without waiting for the UE to re-establish. Before #293 an edit was
/// invisible until then — the same class of defect #56 fixed on the HSS side for EPS.
///
/// **The change is re-fetched, not read out of the notification.** A
/// `ModificationNotification` carries `notifyItems[].changes[]` as
/// operation/path/newValue triples over the `sm-data` document, so honouring it
/// literally means implementing a patch interpreter over a free-form
/// `dnnConfigurations` map — where a path this SMF fails to understand yields "no
/// change" indistinguishably from "nothing changed". Re-reading the authoritative
/// document with the same `fetch_sm_data` the establishment path uses has one
/// behaviour to keep correct instead of two, and cannot silently apply half an edit.
/// The notification's role is to say *when*, and for which resource.
///
/// **With a PCF configured this SMF deliberately does NOT apply the change.** See
/// the log line and `specs/fix-smfd-udm-sdm-subscribe-uecm-dereg.md`: TS 23.503
/// §6.1.3.2 makes the PCF the authority on session-AMBR and default QoS, and a
/// subscription-driven override applied behind its back would leave the SMF enforcing
/// something the PCF never authorised.
async fn handle_sdm_notification(sm_context_ref: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("Nudm_SDM_Notification for ref={sm_context_ref}");

    // The body is parsed before the context lookup so a malformed notification is a
    // 400 rather than a 404 for a session that does exist.
    let Some(body) = request
        .http
        .content
        .as_deref()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
    else {
        return problem_400(
            "INVALID_MSG_FORMAT",
            "ModificationNotification body required",
        );
    };

    let Some(binding) = lookup_policy_binding(sm_context_ref) else {
        // A notification for a session this SMF no longer holds means the
        // unsubscribe did not reach the UDM. Answering 404 is what tells it to stop.
        log::warn!(
            "Nudm_SDM_Notification for unknown ref={sm_context_ref}: the SDM \
             subscription outlived its session"
        );
        return send_not_found(
            &format!("No SM context for ref={sm_context_ref}"),
            Some("CONTEXT_NOT_FOUND"),
        );
    };

    // `notifyItems` is what names the changed resource. An empty or absent list is
    // accepted (204) and applied anyway: the UDM has told us this subscription's
    // monitored resource changed, and refusing to act on a shape difference would
    // make the leg silently useless against a UDM that reports it differently.
    let items = body["notifyItems"].as_array().map(Vec::len).unwrap_or(0);
    log::debug!("Nudm_SDM_Notification ref={sm_context_ref}: {items} notify item(s)");

    if binding.sm_policy_id.is_some() {
        // TS 23.503 §6.1.3.2. The PCF authorised this session's QoS with the
        // subscription as one of its inputs; re-deriving it here from the
        // subscription alone would override a policy decision with the value that
        // decision was made from. The PCF learns about subscription changes through
        // its own policy-data subscription to the UDR.
        log::info!(
            "[{}] SM data changed, but a PCF authorised this session ({}): the change \
             is NOT applied here — the PCF is the authority on session-AMBR and default \
             QoS (TS 23.503 §6.1.3.2) and learns of subscription changes from the UDR",
            binding.supi,
            binding.sm_policy_id.as_deref().unwrap_or("")
        );
        return SbiResponse::with_status(204);
    }

    // Scoped to the DNN *and* the S-NSSAI the session was created for: `sm-data` is
    // one entry per S-NSSAI, so a guessed slice would apply another slice's
    // session-AMBR to this session -- and `parse_sm_data` falls back to the first
    // entry rather than failing, so the mistake would look like a successful update.
    let Some(subscribed) = udm::fetch_sm_data(
        &binding.supi,
        &binding.dnn,
        binding.sst,
        binding.sd.as_deref(),
    )
    .await
    else {
        log::warn!(
            "[{}] SM data changed but could not be re-read: ref={sm_context_ref} keeps \
             the QoS it was established with",
            binding.supi
        );
        return SbiResponse::with_status(204);
    };

    // Rebuild the same decision the establishment path would build now, so one code
    // path decides what a subscription means (`apply_subscribed_baseline` over the
    // config default) rather than two.
    let mut decision = policy::PolicyDecision::config_default_for_dnn(&binding.dnn);
    decision.apply_subscribed_baseline(&subscribed);

    if decision.sess_ambr_ul_bps == binding.ambr_ul_bps
        && decision.sess_ambr_dl_bps == binding.ambr_dl_bps
        && decision.def_five_qi == binding.five_qi
    {
        log::info!(
            "[{}] SM data notification for ref={sm_context_ref} changes nothing this \
             session enforces",
            binding.supi
        );
        return SbiResponse::with_status(204);
    }

    log::info!(
        "[{}] applying changed SM data to ref={sm_context_ref}: AMBR UL/DL {}/{} -> \
         {}/{} bps, 5QI {} -> {}",
        binding.supi,
        binding.ambr_ul_bps,
        binding.ambr_dl_bps,
        decision.sess_ambr_ul_bps,
        decision.sess_ambr_dl_bps,
        binding.five_qi,
        decision.def_five_qi
    );

    // The N4 QER, through the SAME function the PCF-update path uses: a second way to
    // change a live session's QoS is a second thing to keep correct, and #293 asks
    // for this one explicitly.
    if let Some(seid) = lookup_upf_seid(sm_context_ref) {
        if let Err(e) = pfcp_update_session_qer(
            smf_n4_seid_for(sm_context_ref),
            seid,
            binding.qfi,
            decision.sess_ambr_ul_bps,
            decision.sess_ambr_dl_bps,
        )
        .await
        {
            log::error!("Failed to apply subscription-updated QoS: {e}");
            return SbiResponse::with_status(504);
        }
    }

    if let Ok(ctx) = smf_self().read() {
        if let Ok(mut bindings) = ctx.policy_bindings.write() {
            if let Some(b) = bindings.get_mut(sm_context_ref) {
                b.ambr_ul_bps = decision.sess_ambr_ul_bps;
                b.ambr_dl_bps = decision.sess_ambr_dl_bps;
                b.five_qi = decision.def_five_qi;
            }
        }
        // The session carries the AMBR the Retrieve and the EPS-interworking encoders
        // read, so leaving it stale would make the two disagree about one value.
        if let Some(mut sess) = ctx.sess_find_by_sm_context_ref(sm_context_ref) {
            sess.session_ambr = context::SessionAmbr {
                uplink: decision.sess_ambr_ul_bps,
                downlink: decision.sess_ambr_dl_bps,
            };
            ctx.sess_update(&sess);
        }
        // Issue #191: durable too, not just in memory.
        ctx.persist();
    }

    SbiResponse::with_status(204)
}

/// Handle SM Policy Termination Notification (from PCF, TS 29.512 §4.2.3.3):
/// the PCF requests release of the policy association — the SMF tears the
/// PDU session down (PFCP delete + resource release).
async fn handle_sm_policy_terminate(sm_context_ref: &str) -> SbiResponse {
    log::warn!("SM Policy termination requested by PCF for ref={sm_context_ref}");
    if lookup_policy_binding(sm_context_ref).is_none() {
        return send_not_found(
            &format!("No SM context for ref={sm_context_ref}"),
            Some("CONTEXT_NOT_FOUND"),
        );
    }
    // Re-use the release path (PFCP deletion, IP release, FSM, binding drop).
    // The SM policy delete inside is a no-op risk-wise: the PCF asked for it.
    // #78: no request body -- this release is PCF-driven, not AMF-driven, so there
    // is no SmContextReleaseData to parse.
    handle_sm_context_release(sm_context_ref, None).await;
    SbiResponse::with_status(204)
}

/// Handle N1N2 Transfer Failure (from AMF)
async fn handle_n1n2_transfer_failure(sm_context_ref: &str) -> SbiResponse {
    log::info!("N1N2 transfer failure notification for ref={sm_context_ref}");
    SbiResponse::with_status(204)
}

/// Handle AMF Status Change Notification
async fn handle_amf_status_change(sm_context_ref: &str) -> SbiResponse {
    log::info!("AMF status change notification for ref={sm_context_ref}");
    SbiResponse::with_status(204)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smf_config_default() {
        let config = SmfConfig::default();
        assert_eq!(config.sbi_port, 7777);
        assert_eq!(config.max_ue, 1024);
        assert!(config.nrf_uri.is_none());
    }

    #[test]
    fn test_load_config_extracts_sbi_and_nrf_in_one_parse() {
        use std::io::Write;
        let yaml = "smf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        \
                    port: 8888\n    client:\n      nrf:\n        - uri: http://nrf.example:7777\n";
        let path = std::env::temp_dir().join(format!("smf-cfg-test-{}.yaml", std::process::id()));
        std::fs::File::create(&path)
            .and_then(|mut f| f.write_all(yaml.as_bytes()))
            .expect("write temp config");

        let config = load_config(path.to_str().unwrap());
        let _ = std::fs::remove_file(&path);

        assert_eq!(config.sbi_addr, "127.0.0.1");
        assert_eq!(config.sbi_port, 8888);
        // NRF URI now comes from the single load_config parse (no second read).
        assert_eq!(config.nrf_uri.as_deref(), Some("http://nrf.example:7777"));
    }

    // ------------------------------------------------------------------
    // N2 SM transfer cross-codec guards (PDU-session data-plane)
    // ------------------------------------------------------------------
    //
    // The smfd builds the N2 SM PDUSessionResourceSetupRequestTransfer with the
    // real-APER nextgcore-ngap codec and decodes the gNB's SetupResponseTransfer with
    // it. These pin the wire bytes against the independent nextgsim-ngap codec
    // (the gNB), mirroring the NG-Setup/ICS reconciliation: the request
    // bytes are byte-identical to the gNB's decoder vector, and the gNB's
    // response bytes decode here.

    /// smfd's emitted SetupRequestTransfer for UPF F-TEID 0x00010001 /
    /// 10.45.0.1 / QFI 1 / 5QI 9 / ARP 8 — must equal the vector the gNB
    /// (nextgsim-ngap) decodes (capture_tests.rs::SMFD_SETUP_REQUEST_TRANSFER).
    /// Leading 0x00 = the outer extensible SEQUENCE's APER extension bit
    /// (ngap-04, TS 38.413 §9.3.4.1 + §9.5); the remaining 32 octets are the
    /// ProtocolIE-Container.
    const GNB_EXPECTED_SETUP_REQUEST: [u8; 33] = [
        0x00, 0x00, 0x03, 0x00, 0x8b, 0x00, 0x0a, 0x01, 0xf0, 0x0a, 0x2d, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x86, 0x00, 0x01, 0x00, 0x00, 0x88, 0x00, 0x07, 0x00, 0x01, 0x00, 0x00,
        0x09, 0x1c, 0x00,
    ];

    #[test]
    fn setup_request_transfer_matches_gnb_wire_bytes() {
        let bytes = build_setup_request_transfer(0x0001_0001, [10, 45, 0, 1], 1, 9, 8).unwrap();
        assert_eq!(
            bytes,
            GNB_EXPECTED_SETUP_REQUEST.to_vec(),
            "smfd SetupRequestTransfer must be byte-identical to the gNB decoder vector"
        );
    }

    #[test]
    fn setup_request_transfer_self_roundtrips() {
        use nextgcore_ngap::transfer::{
            PduSessionResourceSetupRequestTransfer, UpTransportLayerInformation,
        };
        let bytes = build_setup_request_transfer(0x0001_0001, [10, 45, 0, 1], 1, 9, 8).unwrap();
        let t = PduSessionResourceSetupRequestTransfer::decode(&bytes).expect("decode");
        let UpTransportLayerInformation::GtpTunnel(tun) = &t.ul_ngu_up_tnl_information;
        assert_eq!(u32::from_be_bytes(tun.gtp_teid), 0x0001_0001);
        assert_eq!(tun.transport_layer_address.octets, vec![10, 45, 0, 1]);
        assert_eq!(t.qos_flow_setup_request_list.len(), 1);
        assert_eq!(t.qos_flow_setup_request_list[0].qos_flow_identifier, 1);
    }

    #[test]
    fn modify_request_transfer_self_roundtrips() {
        use nextgcore_ngap::transfer::PduSessionResourceModifyRequestTransfer;
        let bytes = build_modify_request_transfer(1, 200_000_000, 100_000_000).unwrap();
        let t = PduSessionResourceModifyRequestTransfer::decode(&bytes).expect("decode");
        assert_eq!(
            t.pdu_session_aggregate_maximum_bit_rate
                .map(|a| (a.dl, a.ul)),
            Some((200_000_000, 100_000_000))
        );
        assert_eq!(t.qos_flow_add_or_modify_request_list.len(), 1);
        assert_eq!(
            t.qos_flow_add_or_modify_request_list[0].qos_flow_identifier,
            1
        );
    }

    // ------------------------------------------------------------------
    // H5 golden vectors: PDUSessionResourceModifyRequestTransfer
    // (TS 38.413 §9.3.4.3, APER per ITU-T X.691, ALIGNED variant)
    // ------------------------------------------------------------------
    //
    // Hand-derived from the ASN.1 in specs/38413-j30.txt — NOT captured from
    // our own encoder — per the dual-derivation method in
    // .context/GOLDEN-VECTOR-METHOD.md. Derivation A is the bit table below;
    // derivation B is an independent from-scratch X.691 recompute (Python
    // script, full text in the method doc's Appendix B) written without
    // reading derivation A. Both derivations agree byte-for-byte; the vector
    // was frozen only after that agreement (this cross-check is what caught
    // the TUAK set-3 scramble precedent).
    //
    // ASN.1 anchors (specs/38413-j30.txt):
    //   PDUSessionResourceModifyRequestTransfer  line 53689 (extensible SEQUENCE
    //     of one mandatory ProtocolIE-Container)
    //   ProtocolIE-Container ::= SEQUENCE (SIZE (0..65535)) OF ProtocolIE-Field
    //     (line 60634; maxProtocolIEs = 65535, line 59201)
    //   ProtocolIE-Field ::= SEQUENCE { id INTEGER (0..65535),
    //     criticality ENUMERATED {reject,ignore,notify}, value <open type> }
    //   id-PDUSessionAggregateMaximumBitRate = 130, criticality reject (59691)
    //   id-QosFlowAddOrModifyRequestList     = 135, criticality reject (59701)
    //   PDUSessionAggregateMaximumBitRate ::= SEQUENCE { DL BitRate, UL BitRate,
    //     iE-Extensions OPTIONAL, ... } (53236)
    //   BitRate ::= INTEGER (0..4000000000000, ...) (45660)
    //   QosFlowAddOrModifyRequestList ::= SEQUENCE (SIZE(1..64)) OF ... (55098;
    //     maxnoofQosFlows = 64, line 59309)
    //   QosFlowAddOrModifyRequestItem ::= SEQUENCE { qosFlowIdentifier
    //     INTEGER (0..63,...), qosFlowLevelQosParameters OPTIONAL,
    //     e-RAB-ID OPTIONAL, iE-Extensions OPTIONAL, ... } (55101)

    /// Golden vector A — AMBR-only transfer (DL 1 Gbps, UL 250 kbps).
    ///
    /// Derivation A bit table (X.691 ALIGNED; bits listed in emission order):
    /// ```text
    /// byte 0     0x00  [0]        outer SEQUENCE extension bit = 0 (X.691 §19.7)
    ///                  [0000000]  pad: container count is a range-65536
    ///                             constrained int -> 2 octets, octet-aligned
    ///                             (§13.2.5.4 via §11.9.4.1)
    /// bytes 1-2  0x0001           protocolIEs count = 1
    /// bytes 3-4  0x0082           ProtocolIE-ID 130 (range 65536 -> 2 aligned octets)
    /// byte 5     0x00  [00]       criticality reject = 0 (ENUMERATED root,
    ///                             range 3 -> 2-bit field, §14.3/§13.2.5.2)
    ///                  [000000]   pad: open-type length determinant aligns (§11.2/§11.9)
    /// byte 6     0x09             open-type length = 9 octets (short form, §11.9.3.6)
    /// --- open-type content: PDUSessionAggregateMaximumBitRate ---
    /// byte 7     0x0C  [0]        AMBR SEQUENCE extension bit = 0
    ///                  [0]        iE-Extensions absent (1-bit optional bitmap, §19.2)
    ///                  [0]        DL BitRate extension bit = 0 (root, §13.1)
    ///                  [011]      DL length-of-length: range 4e12+1 > 64K ->
    ///                             §13.2.6: octet count n=4 as constrained int
    ///                             (1..6) -> 3-bit field, offset 4-1=3
    ///                  [00]       pad: §13.2.6 value octets are octet-aligned
    /// bytes 8-11 0x3B9ACA00       DL = 1_000_000_000 in minimal 4 octets
    /// byte 12    0x20  [0]        UL BitRate extension bit = 0
    ///                  [010]      UL octet count n=3, offset 3-1=2
    ///                  [0000]     pad to octet boundary
    /// bytes13-15 0x03D090         UL = 250_000 in minimal 3 octets
    /// ```
    const GOLDEN_MODIFY_REQUEST_AMBR_ONLY: [u8; 16] = [
        0x00, 0x00, 0x01, 0x00, 0x82, 0x00, 0x09, 0x0C, 0x3B, 0x9A, 0xCA, 0x00, 0x20, 0x03, 0xD0,
        0x90,
    ];

    /// Golden vector B — AMBR (DL 200 Mbps, UL 100 Mbps) + one QoS-flow-add
    /// item (QFI 1, no level parameters, no E-RAB ID) — exactly the shape
    /// `build_modify_request_transfer(1, 200_000_000, 100_000_000)` emits on
    /// the live PDU_RES_MOD_REQ path.
    ///
    /// Derivation A bit table (deltas from vector A annotated):
    /// ```text
    /// byte 0     0x00             ext bit 0 + 7 pad bits (as vector A)
    /// bytes 1-2  0x0002           protocolIEs count = 2
    /// bytes 3-4  0x0082           IE 1: ProtocolIE-ID 130 (AMBR)
    /// byte 5     0x00             criticality reject (2 bits) + 6 pad bits
    /// byte 6     0x0A             open-type length = 10 octets
    /// byte 7     0x0C             [0 ext][0 iE-Ext absent][0 DL ext][011 n=4][00 pad]
    /// bytes 8-11 0x0BEBC200       DL = 200_000_000 in minimal 4 octets
    /// byte 12    0x30             [0 UL ext][011 n=4][0000 pad]
    /// bytes13-16 0x05F5E100       UL = 100_000_000 in minimal 4 octets
    /// bytes17-18 0x0087           IE 2: ProtocolIE-ID 135 (QosFlowAddOrModifyRequestList)
    /// byte 19    0x00             criticality reject (2 bits) + 6 pad bits
    /// byte 20    0x03             open-type length = 3 octets
    /// --- open-type content: QosFlowAddOrModifyRequestList, 17 bits + 7 pad ---
    /// byte 21    0x00  [000000]   SEQUENCE-OF count = 1 as constrained int
    ///                             (1..64) -> 6-bit field, offset 0 (§20.6)
    ///                  [0]        item SEQUENCE extension bit = 0
    ///                  [0]        qosFlowLevelQosParameters absent
    /// byte 22    0x00  [0]        e-RAB-ID absent
    ///                  [0]        iE-Extensions absent
    ///                  [0]        QosFlowIdentifier extension bit = 0
    ///                  [00000]    QFI high 5 bits of 6-bit root value 1 (0..63)
    /// byte 23    0x80  [1]        QFI low bit (value = 0b000001 = 1)
    ///                  [0000000]  pad to octet boundary (§11.2.1)
    /// ```
    const GOLDEN_MODIFY_REQUEST_AMBR_PLUS_QOS_FLOW_ADD: [u8; 24] = [
        0x00, 0x00, 0x02, 0x00, 0x82, 0x00, 0x0A, 0x0C, 0x0B, 0xEB, 0xC2, 0x00, 0x30, 0x05, 0xF5,
        0xE1, 0x00, 0x00, 0x87, 0x00, 0x03, 0x00, 0x00, 0x80,
    ];

    /// Encoder golden A: an AMBR-only ModifyRequestTransfer (the transfer
    /// codec `build_modify_request_transfer` drives; the builder itself always
    /// adds the QoS-flow list, so the AMBR-only shape is pinned through the
    /// same encoder directly) must produce the spec-derived bytes exactly.
    #[test]
    fn golden_modify_request_transfer_ambr_only_encodes_ts38413_bytes() {
        use nextgcore_ngap::transfer::{
            PduSessionAggregateMaximumBitRate, PduSessionResourceModifyRequestTransfer,
        };
        let transfer = PduSessionResourceModifyRequestTransfer {
            pdu_session_aggregate_maximum_bit_rate: Some(PduSessionAggregateMaximumBitRate {
                dl: 1_000_000_000,
                ul: 250_000,
            }),
            ..Default::default()
        };
        assert_eq!(
            transfer.encode().expect("encode"),
            GOLDEN_MODIFY_REQUEST_AMBR_ONLY.to_vec(),
            "AMBR-only ModifyRequestTransfer must match the hand-derived TS 38.413 APER vector"
        );
    }

    /// Encoder golden B: the live builder's exact output (AMBR + one
    /// QoS-flow-add item) must equal the spec-derived bytes. This replaces the
    /// roundtrip-only oracle for encode-side drift: any bit change in the
    /// encoder output fails here even if the matched decoder still accepts it.
    #[test]
    fn golden_modify_request_transfer_builder_encodes_ts38413_bytes() {
        let bytes = build_modify_request_transfer(1, 200_000_000, 100_000_000).unwrap();
        assert_eq!(
            bytes,
            GOLDEN_MODIFY_REQUEST_AMBR_PLUS_QOS_FLOW_ADD.to_vec(),
            "build_modify_request_transfer must match the hand-derived TS 38.413 APER vector"
        );
    }

    /// Decoder golden: the frozen spec-derived bytes must decode into exactly
    /// the expected structs (guards decoder drift independently of encoder
    /// drift — a symmetric codec bug passes the roundtrip but fails here).
    #[test]
    fn golden_modify_request_transfer_decodes_from_frozen_bytes() {
        use nextgcore_ngap::transfer::{
            PduSessionAggregateMaximumBitRate, PduSessionResourceModifyRequestTransfer,
            QosFlowAddOrModifyRequestItem,
        };

        let a = PduSessionResourceModifyRequestTransfer::decode(&GOLDEN_MODIFY_REQUEST_AMBR_ONLY)
            .expect("decode golden A");
        assert_eq!(
            a,
            PduSessionResourceModifyRequestTransfer {
                pdu_session_aggregate_maximum_bit_rate: Some(PduSessionAggregateMaximumBitRate {
                    dl: 1_000_000_000,
                    ul: 250_000,
                }),
                ..Default::default()
            }
        );

        let b = PduSessionResourceModifyRequestTransfer::decode(
            &GOLDEN_MODIFY_REQUEST_AMBR_PLUS_QOS_FLOW_ADD,
        )
        .expect("decode golden B");
        assert_eq!(
            b,
            PduSessionResourceModifyRequestTransfer {
                pdu_session_aggregate_maximum_bit_rate: Some(PduSessionAggregateMaximumBitRate {
                    dl: 200_000_000,
                    ul: 100_000_000,
                }),
                qos_flow_add_or_modify_request_list: vec![QosFlowAddOrModifyRequestItem {
                    qos_flow_identifier: 1,
                    qos_flow_level_qos_parameters: None,
                    e_rab_id: None,
                }],
                ..Default::default()
            }
        );
    }

    /// The gNB (nextgsim-ngap) produces this SetupResponseTransfer for gNB DL
    /// F-TEID 0x00020002 / 10.46.0.1 / QFI 1 (pinned in the gNB test
    /// capture_tests.rs::gnb_setup_response_transfer_roundtrips). smfd must
    /// decode it to extract the gNB DL F-TEID for the PFCP DL FAR.
    const GNB_SETUP_RESPONSE_TRANSFER: [u8; 13] = [
        0x00, 0x03, 0xe0, 0x0a, 0x2e, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0x01,
    ];

    #[test]
    fn gnb_setup_response_transfer_decodes_in_smfd() {
        let (teid, addr, qfi) =
            decode_setup_response_dl_endpoint(&GNB_SETUP_RESPONSE_TRANSFER).expect("smfd decodes");
        assert_eq!(teid, 0x0002_0002);
        assert_eq!(addr, [10, 46, 0, 1]);
        assert_eq!(qfi, 1);
    }

    // ------------------------------------------------------------------
    // smfd-01 / smfd-02: multipart/related N1/N2 carriage
    // (TS 29.502 §6.1.2.2.2 / §6.1.2.4)
    // ------------------------------------------------------------------

    use nextgcore_sbi::constants::content_type;
    use nextgcore_sbi::message::SbiPart;

    /// A valid PDU Session Establishment Request N1 container (PSI=5, PTI=2,
    /// IPv4v6, SSC mode 2) — the vector parsed in the policy unit tests.
    const N1_ESTABLISHMENT_REQUEST: [u8; 14] = [
        0x2E, 0x05, 0x02, 0xC1, 0xFF, 0xFF, 0x93, 0xA2, 0x28, 0x01, 0x00, 0x55, 0x00, 0x10,
    ];

    /// The 201 SmContextCreatedData response is multipart/related: the JSON
    /// root references N1/N2 via RefToBinaryData, and the two binary parts carry
    /// the exact bytes produced by smfd's N1-accept and N2-transfer builders,
    /// with the conformant 5gnas / ngap content types.
    #[test]
    fn sm_context_created_response_is_multipart_with_binary_refs() {
        let n1 = policy::build_establishment_accept(
            5,
            2,
            policy::pdu_session_type::IPV4,
            1,
            1,
            1,
            1_000_000,
            1_000_000,
            [10, 45, 0, 2],
            [0u8; 8],
            1,
            None,
            "internet",
            None,
            &[],
            None,
            None,
        );
        let n2 = build_setup_request_transfer(0x0001_0001, [10, 45, 0, 1], 1, 9, 8).unwrap();

        let resp = sbi_response_with_n1_n2(
            201,
            serde_json::json!({
                "smContextRef": "7",
                "pduSessionId": 5,
                "upCnxState": "ACTIVATING",
                "n2SmInfoType": "PDU_RES_SETUP_REQ"
            }),
            &n1,
            &n2,
        )
        .with_header("Location", "/nsmf-pdusession/v1/sm-contexts/7");

        assert_eq!(resp.status, 201);
        // Serialize exactly as the SBI client serializes parts (multipart/
        // related), then decode it back to prove the wire shape.
        let boundary = nextgcore_sbi::multipart::generate_boundary();
        let body = nextgcore_sbi::multipart::encode(
            resp.http.content.as_deref(),
            &resp.http.parts,
            &boundary,
        );
        let ct = nextgcore_sbi::multipart::content_type_with_boundary(&boundary);
        let decoded = nextgcore_sbi::multipart::decode(&ct, &body).expect("decode multipart");

        // JSON root: N1/N2 are RefToBinaryData pointers; n2SmInfoType preserved.
        let root: serde_json::Value =
            serde_json::from_str(decoded.json.as_deref().unwrap()).unwrap();
        assert_eq!(root["n1SmMsg"]["contentId"].as_str(), Some("n1SmMsg"));
        assert_eq!(root["n2SmInfo"]["contentId"].as_str(), Some("n2SmInfo"));
        assert_eq!(root["n2SmInfoType"].as_str(), Some("PDU_RES_SETUP_REQ"));
        assert_eq!(root["smContextRef"].as_str(), Some("7"));

        // Binary parts: exact builder bytes + conformant content types.
        let n1_part = decoded
            .parts
            .iter()
            .find(|p| p.content_id.as_deref() == Some("n1SmMsg"))
            .expect("n1 part");
        let n2_part = decoded
            .parts
            .iter()
            .find(|p| p.content_id.as_deref() == Some("n2SmInfo"))
            .expect("n2 part");
        assert_eq!(n1_part.data.as_ref(), n1.as_slice());
        assert_eq!(n2_part.data.as_ref(), n2.as_slice());
        assert_eq!(
            n1_part.content_type.as_deref(),
            Some(content_type::APPLICATION_5GNAS)
        );
        assert_eq!(
            n2_part.content_type.as_deref(),
            Some(content_type::APPLICATION_NGAP)
        );
    }

    /// The N1-bearing reject (SmContextCreateError) carries the PDU Session
    /// Establishment Reject as a 5gnas binary part referenced by RefToBinaryData.
    #[test]
    fn sm_context_create_error_carries_n1_reject_part() {
        let resp = sm_context_create_error(403, "PDU_SESSION_TYPE_NOT_SUPPORTED", 5, 2, 50);
        assert_eq!(resp.status, 403);
        let root: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(root["n1SmMsg"]["contentId"].as_str(), Some("n1SmMsg"));
        let part = resp
            .http
            .parts
            .iter()
            .find(|p| p.content_id.as_deref() == Some("n1SmMsg"))
            .expect("n1 reject part");
        assert_eq!(
            part.content_type.as_deref(),
            Some(content_type::APPLICATION_5GNAS)
        );
        assert_eq!(
            part.data.as_ref(),
            policy::build_establishment_reject(5, 2, 50).as_slice()
        );
    }

    /// smfd resolves the N1 container identically from a multipart 5gnas part
    /// and from the legacy base64-in-JSON form (backward compatibility).
    #[test]
    fn smfd_resolves_n1_multipart_same_as_base64() {
        // Multipart form: JSON root holds a RefToBinaryData pointer; bytes in a part.
        let mut multipart_req = SbiRequest::post("/nsmf-pdusession/v1/sm-contexts");
        multipart_req
            .http
            .set_content(serde_json::json!({ "n1SmMsg": { "contentId": "n1SmMsg" } }).to_string());
        multipart_req.http.add_part(SbiPart::with_content(
            "n1SmMsg",
            content_type::APPLICATION_5GNAS,
            bytes::Bytes::copy_from_slice(&N1_ESTABLISHMENT_REQUEST),
        ));
        let mp_body: serde_json::Value =
            serde_json::from_str(multipart_req.http.content.as_deref().unwrap()).unwrap();
        let from_multipart = resolve_binary_ref(&multipart_req, &mp_body["n1SmMsg"]).unwrap();

        // Legacy form: base64 string, no parts.
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(N1_ESTABLISHMENT_REQUEST);
        let legacy_req = SbiRequest::post("/nsmf-pdusession/v1/sm-contexts");
        let legacy_body = serde_json::json!({ "n1SmMsg": b64 });
        let from_base64 = resolve_binary_ref(&legacy_req, &legacy_body["n1SmMsg"]).unwrap();

        assert_eq!(from_multipart, from_base64);
        assert_eq!(from_multipart, N1_ESTABLISHMENT_REQUEST.to_vec());
        // ...and the decoded internal result is identical.
        let a = policy::parse_establishment_request(&from_multipart).unwrap();
        let b = policy::parse_establishment_request(&from_base64).unwrap();
        assert_eq!(a.pti, b.pti);
        assert_eq!(a.requested_pdu_session_type, b.requested_pdu_session_type);
        assert_eq!(a.requested_ssc_mode, b.requested_ssc_mode);
    }

    /// Cross-decode: bytes shaped exactly as amfd emits a multipart
    /// CreateSmContext request (JSON root + N1 5gnas part) are decoded by the
    /// shared multipart codec and resolved by smfd to the exact N1 container.
    #[test]
    fn smfd_parses_amfd_multipart_create_request() {
        // Reproduce amfd's wire emission via the shared multipart encoder.
        let root = serde_json::json!({
            "pduSessionId": 5,
            "sNssai": { "sst": 1 },
            "dnn": "internet",
            "n1SmMsg": { "contentId": "n1SmMsg" },
            "redcapIndication": false
        });
        let part = SbiPart::with_content(
            "n1SmMsg",
            content_type::APPLICATION_5GNAS,
            bytes::Bytes::copy_from_slice(&N1_ESTABLISHMENT_REQUEST),
        );
        let boundary = nextgcore_sbi::multipart::generate_boundary();
        let body = nextgcore_sbi::multipart::encode(
            Some(&root.to_string()),
            std::slice::from_ref(&part),
            &boundary,
        );
        let ct = nextgcore_sbi::multipart::content_type_with_boundary(&boundary);

        // Server-side: decode into the request the smfd handler would see.
        let decoded = nextgcore_sbi::multipart::decode(&ct, &body).unwrap();
        let mut request = SbiRequest::post("/nsmf-pdusession/v1/sm-contexts");
        request.http.content = decoded.json.clone();
        request.http.parts = decoded.parts;
        let req_body: serde_json::Value =
            serde_json::from_str(decoded.json.as_deref().unwrap()).unwrap();

        let n1 = resolve_binary_ref(&request, &req_body["n1SmMsg"]).unwrap();
        assert_eq!(n1, N1_ESTABLISHMENT_REQUEST.to_vec());
        assert!(policy::parse_establishment_request(&n1).is_some());
    }

    // ------------------------- issue #73 --------------------------------

    /// **Issue #73, criterion 3.** A non-emergency `CreateSMContext` with no
    /// `supi` is REJECTED, not served with a fabricated subscriber.
    ///
    /// This used to warn and substitute `"imsi-unknown"`, and the phantom identity
    /// then flowed into NSAC counters, policy association and session lookup — so
    /// every subscriber in the network collapsed onto ONE identity. Charging and
    /// slice admission were computed over a subscriber that does not exist, and
    /// because the session still came up, nothing surfaced the loss.
    ///
    /// Asserted on BEHAVIOUR (the 400 and its cause), not by grepping the source
    /// for `imsi-unknown`: the explanation of this fix contains that literal, and
    /// a source-grepping guard would match its own justification.
    #[tokio::test]
    async fn create_sm_context_without_supi_is_rejected() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        smf_context_init(64, 256, 512);
        let body = serde_json::json!({
            "pduSessionId": 5,
            "sNssai": { "sst": 1, "sd": "010203" },
            "dnn": "internet",
            "n1SmMsg": { "contentId": "n1SmMsg" },
        });
        let mut request = SbiRequest::post("/nsmf-pdusession/v1/sm-contexts");
        request.http.content = Some(body.to_string());

        let resp = handle_sm_context_create(&request).await;
        assert_eq!(
            resp.status, 400,
            "a session the SMF cannot attribute must be refused"
        );
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(problem["cause"], "MANDATORY_IE_MISSING");
        assert!(
            problem["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("supi"),
            "the rejection must name the missing IE, got {problem}"
        );

        // An empty string is not an identity either.
        let mut empty = SbiRequest::post("/nsmf-pdusession/v1/sm-contexts");
        let mut with_empty = body.clone();
        with_empty["supi"] = serde_json::json!("");
        empty.http.content = Some(with_empty.to_string());
        assert_eq!(handle_sm_context_create(&empty).await.status, 400);
    }

    // ----------------------------- smfd-06 ------------------------------

    /// The exact SmContextCreateData body the matched-sim AMF sends (no supi /
    /// anType / smContextStatusUri) MUST still pass the strict validator, while
    /// genuinely-missing mandatory IEs are rejected with the correct cause.
    #[test]
    fn validate_sm_context_create_data_table() {
        // Matched-sim AMF body shape (see amfd build_create_sm_context_request).
        let matched_sim = serde_json::json!({
            "pduSessionId": 5,
            "sNssai": { "sst": 1, "sd": "010203" },
            "dnn": "internet",
            "n1SmMsg": { "contentId": "n1SmMsg" },
            "redcapIndication": false,
            "servingNetwork": { "mcc": "001", "mnc": "01" }
        });
        assert_eq!(validate_sm_context_create_data(&matched_sim), None);

        // supi / anType absent but otherwise complete → still permitted.
        assert_eq!(
            validate_sm_context_create_data(&serde_json::json!({
                "pduSessionId": 1,
                "sNssai": { "sst": 2 },
                "dnn": "ims",
                "n1SmMsg": "BASE64DATA"
            })),
            None
        );

        // Each genuinely-missing mandatory IE → its expected cause.
        let mut no_psi = matched_sim.clone();
        no_psi["pduSessionId"] = serde_json::json!(0); // out of 1..=15
        assert_eq!(
            validate_sm_context_create_data(&no_psi),
            Some("MANDATORY_IE_INCORRECT")
        );

        // #204: `dnn` is OPTIONAL (TS 29.502 Table 6.1.6.2.2-1), so its absence is
        // NOT a validator failure — the handler resolves the subscribed default
        // instead (TS 23.501 §5.6.1). Rejecting here would make that unreachable.
        let mut no_dnn = matched_sim.clone();
        no_dnn["dnn"] = serde_json::Value::Null;
        assert_eq!(
            validate_sm_context_create_data(&no_dnn),
            None,
            "an absent dnn must reach the handler, which resolves the subscribed default"
        );
        let mut absent_dnn = matched_sim.clone();
        absent_dnn.as_object_mut().unwrap().remove("dnn");
        assert_eq!(validate_sm_context_create_data(&absent_dnn), None);

        let mut no_sst = matched_sim.clone();
        no_sst["sNssai"] = serde_json::json!({});
        assert_eq!(
            validate_sm_context_create_data(&no_sst),
            Some("MANDATORY_IE_MISSING")
        );

        let mut no_n1 = matched_sim.clone();
        no_n1["n1SmMsg"] = serde_json::Value::Null;
        assert_eq!(validate_sm_context_create_data(&no_n1), Some("N1_SM_ERROR"));
    }

    // ------------------------------- #204 -------------------------------

    /// **Issue #204.** The subscribed default DNN is selected from
    /// `SmfSelectionSubscriptionData`'s `dnnInfos`, and nothing is invented when
    /// the subscription does not say which DNN is the default.
    ///
    /// Note where the flag lives: `DnnInfo.defaultDnnIndicator` in `smf-sel-data`.
    /// The issue's suggested approach said to read `sm-data`'s `dnnConfigurations`,
    /// which has **no** default flag at all (TS 29.503 Table 5.5.2.4-1) — see the
    /// `select_default_dnn` doc comment.
    #[test]
    fn select_default_dnn_uses_the_indicator_and_refuses_to_guess() {
        // 1. The flagged entry wins, even when it is not first.
        let flagged = serde_json::json!({
            "subscribedSnssaiInfos": {
                "01": { "dnnInfos": [
                    { "dnn": "ims" },
                    { "dnn": "operator-default", "defaultDnnIndicator": true },
                    { "dnn": "internet" },
                ]}
            }
        });
        assert_eq!(
            select_default_dnn(&flagged, 1, None),
            Ok("operator-default".to_string()),
            "the flagged DNN wins over position"
        );
        // Specifically NOT the literal the AMF used to substitute, which is the
        // whole point of #204.
        assert_ne!(select_default_dnn(&flagged, 1, None), Ok("internet".into()));

        // 2. A single subscribed DNN with no flag is unambiguous.
        let single = serde_json::json!({
            "subscribedSnssaiInfos": { "01": { "dnnInfos": [{ "dnn": "corp" }] } }
        });
        assert_eq!(select_default_dnn(&single, 1, None), Ok("corp".to_string()));

        // 3. Several DNNs and no flag: the subscription does not say, so the SMF
        //    does not either. Guessing is the fabrication this issue removes.
        let ambiguous = serde_json::json!({
            "subscribedSnssaiInfos": {
                "01": { "dnnInfos": [{ "dnn": "internet" }, { "dnn": "ims" }] }
            }
        });
        match select_default_dnn(&ambiguous, 1, None) {
            Err(DefaultDnnError::AmbiguousDefault(dnns)) => {
                assert_eq!(dnns, vec!["internet".to_string(), "ims".to_string()]);
            }
            other => panic!("expected AmbiguousDefault, got {other:?}"),
        }

        // 4. No DNN at all for the S-NSSAI, and an S-NSSAI that is not subscribed.
        for empty in [
            serde_json::json!({}),
            serde_json::json!({ "subscribedSnssaiInfos": {} }),
            serde_json::json!({ "subscribedSnssaiInfos": { "01": {} } }),
            serde_json::json!({ "subscribedSnssaiInfos": { "01": { "dnnInfos": [] } } }),
            // A dnnInfos entry with no `dnn` member names nothing.
            serde_json::json!({ "subscribedSnssaiInfos": { "01": { "dnnInfos": [{}] } } }),
        ] {
            assert_eq!(
                select_default_dnn(&empty, 1, None),
                Err(DefaultDnnError::NoSubscribedDnn),
                "body {empty} must not yield a DNN"
            );
        }
        assert_eq!(
            select_default_dnn(&single, 9, None),
            Err(DefaultDnnError::NoSubscribedDnn),
            "SST 9 is not subscribed"
        );

        // 5. The key form is the TS 29.571 S-NSSAI string `{sst:02x}[-{sd}]`, and a
        //    subscription provisioned without an SD still applies to a request that
        //    carries one.
        let with_sd = serde_json::json!({
            "subscribedSnssaiInfos": {
                "01-000001": { "dnnInfos": [{ "dnn": "slice-a" }] },
                "01": { "dnnInfos": [{ "dnn": "no-sd" }] }
            }
        });
        assert_eq!(
            select_default_dnn(&with_sd, 1, Some("000001")),
            Ok("slice-a".to_string()),
            "the exact sst-sd key wins"
        );
        assert_eq!(
            select_default_dnn(&with_sd, 1, Some("999999")),
            Ok("no-sd".to_string()),
            "an unmatched SD widens to the no-SD entry"
        );
    }

    /// **Issue #204.** Every `DefaultDnnError` maps to a cause that distinguishes
    /// "the consumer named no DNN and the subscription supplies none" from "the SMF
    /// could not reach the subscription".
    ///
    /// Collapsing them would leave an operator unable to tell a provisioning gap
    /// from an unreachable UDM, which are opposite remedies.
    #[test]
    fn default_dnn_error_causes_are_distinct_and_never_silent() {
        assert_eq!(
            DefaultDnnError::NoSubscribedDnn.cause(),
            "MANDATORY_IE_MISSING"
        );
        assert_eq!(
            DefaultDnnError::AmbiguousDefault(vec!["a".into(), "b".into()]).cause(),
            "MANDATORY_IE_MISSING"
        );
        assert_eq!(
            DefaultDnnError::NoUdmEndpoint.cause(),
            "SUBSCRIPTION_DATA_NOT_AVAILABLE"
        );
        assert_eq!(
            DefaultDnnError::SdmRequestFailed("boom".into()).cause(),
            "SUBSCRIPTION_DATA_NOT_AVAILABLE"
        );

        // Every detail says which failure it was, and none of them says "internet".
        for e in [
            DefaultDnnError::NoUdmEndpoint,
            DefaultDnnError::SdmRequestFailed("status 503".into()),
            DefaultDnnError::NoSubscribedDnn,
            DefaultDnnError::AmbiguousDefault(vec!["internet".into(), "ims".into()]),
        ] {
            let detail = e.detail();
            assert!(!detail.is_empty());
            assert!(
                detail.contains("dnn") || detail.contains("DNN"),
                "detail must name the DNN problem: {detail}"
            );
        }
        assert!(
            DefaultDnnError::AmbiguousDefault(vec!["internet".into(), "ims".into()])
                .detail()
                .contains("internet, ims")
        );
    }

    /// **Issue #204.** A `nudm-sdm` endpoint is taken from the NRF `SearchResult`,
    /// preferring the service's own `ipEndPoints` over the instance address.
    #[test]
    fn udm_sdm_endpoint_is_read_from_the_search_result() {
        let result = serde_json::json!({
            "nfInstances": [
                // A UDM that does not serve nudm-sdm must be skipped, not used.
                { "nfType": "UDM", "ipv4Addresses": ["10.0.0.1"],
                  "nfServices": [{ "serviceName": "nudm-uecm",
                                   "ipEndPoints": [{ "ipv4Address": "10.0.0.1", "port": 7777 }] }] },
                { "nfType": "UDM", "ipv4Addresses": ["10.0.0.2"],
                  "nfServices": [{ "serviceName": "nudm-sdm",
                                   "ipEndPoints": [{ "ipv4Address": "10.0.0.9", "port": 8080 }] }] },
            ]
        });
        assert_eq!(
            udm_service_endpoint_from_search_result(&result, "nudm-sdm"),
            Some(("10.0.0.9".to_string(), 8080)),
            "the nudm-sdm service's own endpoint wins over the instance address"
        );

        // No ipEndPoints: fall back to the instance address and the default port.
        let no_endpoints = serde_json::json!({
            "nfInstances": [{ "nfType": "UDM", "ipv4Addresses": ["10.0.0.3"],
                              "nfServices": [{ "serviceName": "nudm-sdm" }] }]
        });
        assert_eq!(
            udm_service_endpoint_from_search_result(&no_endpoints, "nudm-sdm"),
            Some(("10.0.0.3".to_string(), 7777))
        );

        // Nothing usable yields None rather than a guessed localhost.
        for empty in [
            serde_json::json!({}),
            serde_json::json!({ "nfInstances": [] }),
            serde_json::json!({ "nfInstances": [{ "nfType": "UDM" }] }),
            serde_json::json!({ "nfInstances": [{ "nfType": "UDM",
                "nfServices": [{ "serviceName": "nudm-uecm" }] }] }),
        ] {
            assert_eq!(
                udm_service_endpoint_from_search_result(&empty, "nudm-sdm"),
                None,
                "body {empty} must not yield an endpoint"
            );
        }
    }

    /// **Issue #204, end to end.** `fetch_subscribed_default_dnn` really reaches a
    /// UDM, sends a conformant `Nudm_SDM_Get smf-select-data` with a
    /// percent-encoded `single-nssai`, and returns the flagged DNN.
    ///
    /// The pure-function test above proves the SELECTION; this proves the request
    /// and the plumbing around it, which is the half a unit test cannot see.
    #[tokio::test]
    async fn fetch_subscribed_default_dnn_queries_the_udm_and_returns_the_flagged_dnn() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        // The stub UDM is a loopback PLAINTEXT peer, which describes a dev-profile
        // deployment; the default profile is Production and would require client
        // TLS material this test has no business inventing.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let port = nextgcore_sbi::test_support::free_port();
        type Seen = (Vec<String>, Vec<std::collections::HashMap<String, String>>);
        let seen: Arc<std::sync::Mutex<Seen>> =
            Arc::new(std::sync::Mutex::new((Vec::new(), Vec::new())));
        let seen_in_handler = Arc::clone(&seen);

        let server =
            nextgcore_sbi::server::SbiServer::new(nextgcore_sbi::server::SbiServerConfig::new(
                std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            ));
        server
            .start(move |req: SbiRequest| {
                let seen = Arc::clone(&seen_in_handler);
                async move {
                    let uri = req.header.uri.clone();
                    {
                        let mut s = seen.lock().unwrap();
                        s.0.push(uri.clone());
                        s.1.push(req.http.params.clone().into_iter().collect());
                    }
                    if uri.contains("/nudm-sdm/") && uri.contains("smf-select-data") {
                        SbiResponse::with_status(200)
                            .with_json_body(&serde_json::json!({
                                "subscribedSnssaiInfos": {
                                    "01": { "dnnInfos": [
                                        { "dnn": "internet" },
                                        { "dnn": "operator-default", "defaultDnnIndicator": true },
                                    ]}
                                }
                            }))
                            .unwrap()
                    } else {
                        SbiResponse::with_status(404)
                    }
                }
            })
            .await
            .expect("stub UDM start");

        // Point the fallback at the stub. NRF discovery is tried first and will
        // fail (nothing answers nnrf-disc here), which also exercises that the
        // fallback really is reached rather than the discovery failure being fatal.
        std::env::set_var("UDM_SBI_ADDR", "127.0.0.1");
        std::env::set_var("UDM_SBI_PORT", port.to_string());
        std::env::remove_var("NRF_URI");

        let dnn = fetch_subscribed_default_dnn("imsi-262011234567890", 1, None).await;
        assert_eq!(
            dnn,
            Ok("operator-default".to_string()),
            "the flagged subscribed default must be used, not the first entry \
             and certainly not the old \"internet\" literal"
        );

        // The resource the UDM saw is the conformant one: v2 (Nudm_SDM is at v2 per
        // TS 29.503 §6.1.1, unlike the other Nudm services) and `smf-select-data`.
        // The server decodes the query into params, so the recorded URI carries no
        // query string -- the ENCODING is pinned by
        // `smf_select_data_path_percent_encodes_single_nssai` instead, and what is
        // asserted here is that the value ARRIVED and decoded back to the S-NSSAI.
        let (uris, params) = {
            let s = seen.lock().unwrap();
            (s.0.clone(), s.1.clone())
        };
        assert!(
            uris.iter()
                .any(|u| u == "/nudm-sdm/v2/imsi-262011234567890/smf-select-data"),
            "the UDM must have been queried at the v2 smf-select-data resource, saw {uris:?}"
        );
        // And NO `single-nssai` is sent: the shared SBI server does not
        // percent-decode query values (#65), so a JSON-valued parameter cannot
        // round-trip to the in-tree UDM. Asserted rather than left implicit,
        // because re-adding it would silently send an unparseable value.
        assert!(
            params.iter().all(|p| !p.contains_key("single-nssai")),
            "no single-nssai until #65 makes query decoding work, saw {params:?}"
        );

        std::env::remove_var("UDM_SBI_ADDR");
        std::env::remove_var("UDM_SBI_PORT");
        // Deliberately NOT reset_sbi_profile_override(): the override is
        // process-wide, and resetting it here flipped `policy.rs`'s
        // `sm_policy_lifecycle_http_round_trip` back to Production mid-flight and
        // made it fail. Every other loopback-plaintext test in this crate sets the
        // Dev override and leaves it set; matching that is what keeps them
        // compatible.
        server.stop().await.expect("stop");
    }

    /// **Issue #204, criterion 4.** A DNN-less create with no reachable UDM is
    /// REFUSED with a cause that says so — never a silent `"internet"`.
    #[tokio::test]
    async fn dnn_less_create_with_no_udm_is_refused_not_defaulted() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        std::env::remove_var("UDM_SBI_ADDR");
        std::env::remove_var("UDM_SBI_PORT");
        std::env::remove_var("NRF_URI");
        smf_context_init(64, 256, 512);

        let body = serde_json::json!({
            "pduSessionId": 5,
            "supi": "imsi-262011234567890",
            "sNssai": { "sst": 1 },
            "n1SmMsg": { "contentId": "n1SmMsg" },
        });
        let request = SbiRequest::post("/nsmf-pdusession/v1/sm-contexts")
            .with_body(body.to_string(), "application/json");
        let resp = handle_sm_context_create(&request).await;

        assert_eq!(resp.status, 400, "an unresolvable DNN refuses the session");
        let content = resp.http.content.as_deref().unwrap_or("");
        assert!(
            content.contains("SUBSCRIPTION_DATA_NOT_AVAILABLE"),
            "the cause must name the real problem, got {content}"
        );
        assert!(
            !content.contains("internet"),
            "the refusal must not mention a fabricated default, got {content}"
        );
    }

    // ----------------------------- smfd-07 ------------------------------

    /// The SmContextStatusNotification body carries `statusInfo.resourceStatus`
    /// and an optional `cause` (TS 29.502 §6.1.6.2.8).
    #[test]
    fn sm_context_status_notification_body() {
        let released = build_sm_context_status_notification("RELEASED", None);
        assert_eq!(released["statusInfo"]["resourceStatus"], "RELEASED");
        assert!(released["statusInfo"]["cause"].is_null());

        let with_cause = build_sm_context_status_notification("RELEASED", Some("REL_DUE_TO_HO"));
        assert_eq!(with_cause["statusInfo"]["resourceStatus"], "RELEASED");
        assert_eq!(with_cause["statusInfo"]["cause"], "REL_DUE_TO_HO");
    }

    /// A missing smContextStatusUri is a silent no-op (notifications disabled).
    #[tokio::test]
    async fn sm_context_status_notification_absent_uri_is_noop() {
        // Must return without panicking / without attempting a request.
        send_sm_context_status_notification(None, "RELEASED", None).await;
    }

    /// The path portion is extracted from an absolute AMF callback URI.
    #[test]
    fn uri_path_extraction() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.blocking_lock();
        assert_eq!(
            uri_path("http://amf.example:7777/namf-comm/v1/ue-contexts/imsi-1/sm-context-status/7"),
            "/namf-comm/v1/ue-contexts/imsi-1/sm-context-status/7"
        );
        assert_eq!(uri_path("/already/a/path"), "/already/a/path");
        assert_eq!(uri_path("https://amf:443"), "/");
    }

    // ==================================================================
    // #77: UE-initiated N1 5GSM procedures, ePCO, SSC, DNN labels.
    // ==================================================================

    /// Seed a policy binding so the N1 handlers have a session to act on.
    fn seed_binding(sm_context_ref: &str, psi: u8) {
        smf_context_init(64, 256, 512);
        if let Ok(ctx) = smf_self().read() {
            if let Ok(mut bindings) = ctx.policy_bindings.write() {
                bindings.insert(
                    sm_context_ref.to_string(),
                    context::PolicyBinding {
                        sm_policy_id: None,
                        supi: "imsi-001010000000001".to_string(),
                        psi,
                        pti: 2,
                        pdu_session_type: policy::pdu_session_type::IPV4,
                        ssc_mode: 1,
                        ue_ip: [10, 45, 0, 2],
                        dnn: "internet".to_string(),
                        qfi: 1,
                        five_qi: 9,
                        ambr_ul_bps: 100_000_000,
                        ambr_dl_bps: 100_000_000,
                        // No AMF callback URI: nothing to notify, and no
                        // N1N2MessageTransfer is attempted.
                        sm_context_status_uri: None,
                        fsm: gsm_sm::GsmFsm::new(0),
                        // #114: no EASDF DNS context by default, so the release
                        // path has nothing to delete.
                        easdf_dns_context_id: None,
                        mapped_eps_bearer_id: None,
                        easdf_reported_eas: Vec::new(),
                        sst: 1,
                        sd: Some("010203".to_string()),
                        // #293: no SDM subscription by default, so the release path
                        // has nothing to unsubscribe.
                        sdm_subscription_id: None,
                    },
                );
            }
        }
    }

    /// #114: the EASDF DNS-message report sink exists and attributes the report
    /// to the session that owns the DNS context.
    ///
    /// The SMF advertises this URI as the context's `notificationUri`, so a 404
    /// here would mean every report the EASDF sends is dropped — the emit-side-
    /// without-a-sink defect. Asserts the route answers 204 AND that the reported
    /// EAS address landed on the right binding: a 204 alone would pass against a
    /// handler that parsed nothing.
    #[tokio::test]
    async fn easdf_dns_report_is_attributed_to_its_session() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        seed_binding("easdf-report-ref", 7);
        // Give that session a DNS context id to be matched against.
        if let Ok(ctx) = smf_self().read() {
            if let Ok(mut bindings) = ctx.policy_bindings.write() {
                if let Some(b) = bindings.get_mut("easdf-report-ref") {
                    b.easdf_dns_context_id = Some("ctx-report-1".to_string());
                }
            }
        }

        let req = SbiRequest::post("/nsmf-pdusession/v1/easdf-dns-reports").with_body(
            serde_json::json!({
                "dnsContextId": "ctx-report-1",
                "fqdn": "vr.edge.example.com",
                "action": "RESOLVE",
                "easIpAddresses": ["10.80.0.8"]
            })
            .to_string(),
            "application/json",
        );
        let resp = smf_sbi_request_handler(req).await;
        assert_ne!(resp.status, 404, "the advertised callback must be routed");
        assert_eq!(resp.status, 204);

        let recorded = smf_self()
            .read()
            .ok()
            .and_then(|ctx| {
                ctx.policy_bindings.read().ok().and_then(|b| {
                    b.get("easdf-report-ref")
                        .map(|b| b.easdf_reported_eas.clone())
                })
            })
            .unwrap_or_default();
        assert_eq!(
            recorded,
            vec!["10.80.0.8".to_string()],
            "the reported EAS address must be recorded against the owning session"
        );

        // A report for an unknown context is still 204 (a notification the SMF
        // cannot attribute is not the EASDF's fault to retry) but records nothing.
        let req = SbiRequest::post("/nsmf-pdusession/v1/easdf-dns-reports").with_body(
            serde_json::json!({"dnsContextId": "ctx-nobody", "fqdn": "x", "easIpAddresses": ["1.2.3.4"]})
                .to_string(),
            "application/json",
        );
        assert_eq!(smf_sbi_request_handler(req).await.status, 204);
        let still = smf_self()
            .read()
            .ok()
            .and_then(|ctx| {
                ctx.policy_bindings.read().ok().and_then(|b| {
                    b.get("easdf-report-ref")
                        .map(|b| b.easdf_reported_eas.clone())
                })
            })
            .unwrap_or_default();
        assert_eq!(
            still,
            vec!["10.80.0.8".to_string()],
            "an unattributable report must not overwrite another session's data"
        );

        // A malformed body is refused rather than silently ignored.
        let req = SbiRequest::post("/nsmf-pdusession/v1/easdf-dns-reports")
            .with_body("not json".to_string(), "application/json");
        assert_eq!(smf_sbi_request_handler(req).await.status, 400);
    }

    /// #114: a session that FAILS to establish creates no EASDF DNS context.
    ///
    /// This is the property the call site's placement buys, and the reason it sits
    /// after the PFCP leg rather than before it: a context created for a session
    /// that then fails is an orphan on the EASDF that nothing will ever delete,
    /// because the release path never runs for a session that never existed.
    ///
    /// #289 converted this test: the harness now HAS a UPF stand-in, so the
    /// failure has to be arranged deliberately rather than being the only thing
    /// this harness could produce. The N4 leg fails here because the association
    /// is down, which is the real failure mode (TS 29.244 §6.2.6.2) and the one
    /// `pfcp_session_establish` checks first. The success half — the create call
    /// site actually firing — is
    /// `an_established_session_creates_its_easdf_dns_context` below; until it
    /// existed, removing the `easdf::create_dns_context` call left the whole suite
    /// green (#276).
    #[tokio::test]
    async fn a_failed_establishment_creates_no_easdf_dns_context() {
        // Lock order (see `context::PROCESS_STATE_TEST_LOCK`): ambient state first,
        // N4 second — `stand_in` takes the N4 lock on this test's behalf.
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _upf = pfcp_path::stand_in::unassociated_upf().await;
        let (nrf, easdf_srv, seen) = easdf::tests::spawn_nrf_and_easdf().await;
        smf_context_init(64, 256, 512);
        seen.lock().unwrap_or_else(|e| e.into_inner()).clear();

        let body = serde_json::json!({
            "pduSessionId": 5,
            "supi": "imsi-001010000000001",
            "sNssai": { "sst": 1, "sd": "010203" },
            "dnn": "internet",
            "anType": "3GPP_ACCESS",
            "ratType": "NR",
            "n1SmMsg": { "contentId": "n1SmMsg" },
        });
        let n1_msg = n1(
            5,
            1,
            gsm_build::message_type::PDU_SESSION_ESTABLISHMENT_REQUEST,
            &[0x91, 0x00],
        );
        let request = SbiRequest::post("/nsmf-pdusession/v1/sm-contexts")
            .with_body(body.to_string(), "application/json")
            .with_part(nextgcore_sbi::message::SbiPart::with_content(
                "n1SmMsg",
                "application/vnd.3gpp.5gnas",
                n1_msg.into(),
            ));
        let resp = handle_sm_context_create(&request).await;

        // The stand-in UPF is present but NOT associated, so establishment fails
        // at the N4 leg exactly as it does against an unreachable UPF.
        assert_eq!(
            resp.status, 504,
            "an un-associated UPF must fail the N4 leg (TS 29.244 §6.2.6.2)"
        );
        let requests = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert!(
            requests.is_empty(),
            "a session that never established must leave no DNS context behind, got {requests:?}"
        );

        easdf::set_for_test(None);
        easdf_srv.stop().await.expect("stop");
        nrf.stop().await.expect("stop");
    }

    /// #289 acceptance: a create that REACHES the success path creates the
    /// session's EASDF DNS context, asserted from `handle_sm_context_create`
    /// rather than by calling `easdf::create_dns_context` directly.
    ///
    /// This is the guard #276 could not write. `create_dns_context` had no
    /// production caller for a month — PR #277 wrote `let easdf_dns_context_id =
    /// None;` under a comment describing the awaited call — and the module's own
    /// over-the-wire test said nothing about it, because a helper's test cannot
    /// see whether a handler calls it. Removing the call from the handler now
    /// fails HERE.
    ///
    /// The recorded `(method, path, body)` list is the assertion, and the UE
    /// address in the body is part of it: the EASDF cannot correlate a UDP query
    /// with a session without it (#276), so a create that omitted it would be a
    /// context that can never match a query.
    #[tokio::test]
    async fn an_established_session_creates_its_easdf_dns_context() {
        // Lock order (see `context::PROCESS_STATE_TEST_LOCK`): ambient state first,
        // N4 second — `stand_in` takes the N4 lock on this test's behalf.
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let upf = pfcp_path::stand_in::associated_upf().await;
        let (nrf, easdf_srv, seen) = easdf::tests::spawn_nrf_and_easdf().await;
        smf_context_init(64, 256, 512);
        seen.lock().unwrap_or_else(|e| e.into_inner()).clear();

        let resp = handle_sm_context_create(&create_request(
            "imsi-001010000000289",
            6,
            &n1(
                6,
                1,
                gsm_build::message_type::PDU_SESSION_ESTABLISHMENT_REQUEST,
                &[0x91, 0x00],
            ),
        ))
        .await;
        assert_eq!(
            resp.status, 201,
            "the stand-in UPF answers Session Establishment, so the create must succeed"
        );
        assert!(
            upf.seen()
                .contains(&pfcp_path::pfcp_message_type::SESSION_ESTABLISHMENT_REQUEST),
            "the 201 must have been earned on the N4 wire, not short-circuited"
        );

        let requests = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let create = requests
            .iter()
            .find(|(m, p, _)| m == "POST" && p.contains("/neasdf-dnscontext/v1/dns-contexts"))
            .unwrap_or_else(|| {
                panic!("the create handler must POST a DNS context, got {requests:?}")
            });
        assert!(
            create.2.contains("imsi-001010000000289"),
            "the DNS context must name the subscriber it belongs to, got {}",
            create.2
        );

        easdf::set_for_test(None);
        easdf_srv.stop().await.expect("stop");
        nrf.stop().await.expect("stop");
    }

    /// #114: releasing a session whose binding carries an EASDF DNS context id
    /// issues the matching DELETE **from the release handler**.
    ///
    /// Added after a revert exposed the hole: with the delete call removed from
    /// `handle_sm_context_release`, the whole suite still passed, because the
    /// easdf module's own test drives `delete_dns_context` directly and says
    /// nothing about whether any handler calls it — "the helper is tested and the
    /// wiring is not", for the third time in this session.
    #[tokio::test]
    async fn releasing_a_session_deletes_its_easdf_dns_context() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let (nrf, easdf_srv, seen) = easdf::tests::spawn_nrf_and_easdf().await;

        seed_binding("easdf-release-ref", 9);
        if let Ok(ctx) = smf_self().read() {
            if let Ok(mut bindings) = ctx.policy_bindings.write() {
                if let Some(b) = bindings.get_mut("easdf-release-ref") {
                    b.easdf_dns_context_id = Some("ctx-abc".to_string());
                }
            }
        }
        seen.lock().unwrap_or_else(|e| e.into_inner()).clear();

        let _ = handle_sm_context_release("easdf-release-ref", None).await;

        let requests = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert!(
            requests
                .iter()
                .any(|(m, p, _)| m == "DELETE" && p == "/neasdf-dnscontext/v1/dns-contexts/ctx-abc"),
            "the release handler must delete the session's DNS context, got {requests:?}"
        );

        // A session with NO context id must not cause a delete: nothing to delete,
        // and dialling the EASDF anyway would be a request per released session in
        // every deployment that does not use edge DNS.
        seed_binding("easdf-release-none", 10);
        seen.lock().unwrap_or_else(|e| e.into_inner()).clear();
        let _ = handle_sm_context_release("easdf-release-none", None).await;
        assert!(
            seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
            "a session without a DNS context must not dial the EASDF"
        );

        easdf::set_for_test(None);
        easdf_srv.stop().await.expect("stop");
        nrf.stop().await.expect("stop");
    }

    /// A loopback UDM that records every request and answers the four operations the
    /// SMF performs: `sm-data` (with whatever body the caller installs),
    /// `sdm-subscriptions` (201 + Location), the UECM registration (201) and both
    /// deletes (204). Returns the recorded `(method, uri, body)` list (#293).
    ///
    /// Points `UDM_SBI_*` at itself, which is how both discovery paths find a UDM in
    /// tests; the caller must hold [`crate::context::PROCESS_STATE_TEST_LOCK`].
    async fn spawn_recording_udm(
        sm_data: serde_json::Value,
    ) -> (
        nextgcore_sbi::server::SbiServer,
        std::sync::Arc<std::sync::Mutex<Vec<(String, String, String)>>>,
    ) {
        use nextgcore_sbi::message::SbiResponse;
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};

        let seen: std::sync::Arc<std::sync::Mutex<Vec<(String, String, String)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = seen.clone();
        let port = nextgcore_sbi::test_support::free_port();
        let udm = SbiServer::new(SbiServerConfig::new(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            port,
        ))));
        udm.start(move |req: SbiRequest| {
            let sink = sink.clone();
            let sm_data = sm_data.clone();
            async move {
                sink.lock().unwrap_or_else(|e| e.into_inner()).push((
                    req.header.method.clone(),
                    req.header.uri.clone(),
                    req.http.content.clone().unwrap_or_default(),
                ));
                if req.header.method == "DELETE" {
                    return SbiResponse::with_status(204);
                }
                if req.header.uri.contains("/sdm-subscriptions") {
                    return SbiResponse::with_status(201)
                        .with_header(
                            "Location",
                            format!("{}/sub-293", req.header.uri.trim_end_matches('/')),
                        )
                        .with_json_body(&serde_json::json!({ "subscriptionId": "sub-293" }))
                        .unwrap_or_else(|_| SbiResponse::with_status(201));
                }
                if req.header.uri.contains("/sm-data") {
                    return SbiResponse::with_status(200)
                        .with_json_body(&sm_data)
                        .unwrap_or_else(|_| SbiResponse::with_status(200));
                }
                SbiResponse::with_status(201)
            }
        })
        .await
        .expect("udm start");

        std::env::set_var("UDM_SBI_ADDR", "127.0.0.1");
        std::env::set_var("UDM_SBI_PORT", port.to_string());
        (udm, seen)
    }

    /// An `sm-data` body with the given session-AMBR and default 5QI for `internet` on
    /// S-NSSAI `{sst:1, sd:010203}` — the slice `create_request` and `seed_binding`
    /// use — behind a DECOY entry for a different slice.
    ///
    /// The decoy is the point (#293): `sm-data` is one entry per S-NSSAI and
    /// `parse_sm_data` falls back to the FIRST entry when none matches, so a re-read
    /// that lost the session's S-NSSAI would apply these decoy values and look like a
    /// successful update. Any test asserting the real values therefore also asserts
    /// that the re-read stayed scoped to the right slice.
    fn sm_data_with(ul: &str, dl: &str, five_qi: u8) -> serde_json::Value {
        serde_json::json!([
            {
                "singleNssai": { "sst": 2 },
                "dnnConfigurations": {
                    "internet": {
                        "sessionAmbr": { "uplink": "1 Mbps", "downlink": "2 Mbps" },
                        "5gQosProfile": { "5qi": 9, "arp": { "priorityLevel": 15 } }
                    }
                }
            },
            {
                "singleNssai": { "sst": 1, "sd": "010203" },
                "dnnConfigurations": {
                    "internet": {
                        "sessionAmbr": { "uplink": ul, "downlink": dl },
                        "5gQosProfile": { "5qi": five_qi, "arp": { "priorityLevel": 8 } }
                    }
                }
            }
        ])
    }

    /// Seed a binding that carries an assigned EBI and an AMF callback root, i.e.
    /// the state a session established with EPS interworking on leaves behind (#291).
    fn seed_binding_with_ebi(sm_context_ref: &str, psi: u8, ebi: u8, amf_uri: &str) {
        seed_binding(sm_context_ref, psi);
        if let Ok(ctx) = smf_self().read() {
            if let Ok(mut bindings) = ctx.policy_bindings.write() {
                if let Some(b) = bindings.get_mut(sm_context_ref) {
                    b.mapped_eps_bearer_id = Some(ebi);
                    b.sm_context_status_uri = Some(amf_uri.to_string());
                }
            }
        }
    }

    /// A loopback AMF that answers `assign-ebi` with an `AssignedEbiData` echoing
    /// the released list, and records every request it received (#291).
    async fn spawn_recording_amf() -> (
        nextgcore_sbi::server::SbiServer,
        String,
        std::sync::Arc<std::sync::Mutex<Vec<(String, String, String)>>>,
    ) {
        use nextgcore_sbi::message::SbiResponse;
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};

        let seen: std::sync::Arc<std::sync::Mutex<Vec<(String, String, String)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = seen.clone();
        let port = nextgcore_sbi::test_support::free_port();
        let amf = SbiServer::new(SbiServerConfig::new(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            port,
        ))));
        amf.start(move |req: SbiRequest| {
            let sink = sink.clone();
            async move {
                let body = req.http.content.clone().unwrap_or_default();
                sink.lock().unwrap_or_else(|e| e.into_inner()).push((
                    req.header.method.clone(),
                    req.header.uri.clone(),
                    body.clone(),
                ));
                if !req.header.uri.ends_with("/assign-ebi") {
                    // The RELEASED status notification lands here too; 204 is what
                    // an AMF answers it with.
                    return SbiResponse::with_status(204);
                }
                let released = serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|b| b.get("releasedEbiList").cloned())
                    .unwrap_or_else(|| serde_json::json!([]));
                SbiResponse::with_status(200)
                    .with_json_body(&serde_json::json!({
                        "pduSessionId": 5,
                        "assignedEbiList": [],
                        "releasedEbiList": released,
                    }))
                    .unwrap_or_else(|_| SbiResponse::with_status(200))
            }
        })
        .await
        .expect("amf start");
        (amf, format!("http://127.0.0.1:{port}"), seen)
    }

    /// #291 criterion 1: releasing a session whose binding carries an EBI returns
    /// that EBI to the AMF in a `releasedEbiList`, asserted **over the wire from the
    /// release handler**.
    ///
    /// Driven through `handle_sm_context_release` rather than by calling
    /// `eps_iwk::release_ebi`, because the helper-is-tested-and-the-wiring-is-not
    /// shape has bitten this exact area twice (#276's dead `create_dns_context`, and
    /// #117's IE emitted only from builders with no production caller). What is
    /// asserted is a recorded HTTP request with the identity in it.
    #[tokio::test]
    async fn releasing_a_session_returns_its_ebi_to_the_amf() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        eps_iwk::set_for_test(true);
        let (amf, amf_uri, seen) = spawn_recording_amf().await;

        seed_binding_with_ebi("ebi-release-ref", 5, 7, &amf_uri);
        seen.lock().unwrap_or_else(|e| e.into_inner()).clear();

        let resp = handle_sm_context_release("ebi-release-ref", None).await;
        assert_eq!(resp.status, 204, "the release itself must succeed");

        let requests = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let release = requests
            .iter()
            .find(|(m, p, _)| m == "POST" && p.ends_with("/assign-ebi"))
            .unwrap_or_else(|| {
                panic!("the release handler must return the EBI to the AMF, got {requests:?}")
            });
        assert_eq!(
            release.1, "/namf-comm/v1/ue-contexts/imsi-001010000000001/assign-ebi",
            "addressed to the UE's own ue-context (TS 29.518 §6.1.6.2.5)"
        );
        let body: serde_json::Value =
            serde_json::from_str(&release.2).expect("the request body is JSON");
        assert_eq!(
            body["releasedEbiList"],
            serde_json::json!([7]),
            "the identity on the binding is the one handed back, got {body}"
        );
        assert_eq!(
            body["pduSessionId"],
            serde_json::json!(5),
            "pduSessionId is AssignEbiData's only required member"
        );
        assert!(
            body.get("arpList").is_none(),
            "a release must not ask for a new EBI in the same breath, got {body}"
        );

        // A session with NO EBI must not dial the AMF's assign-ebi at all: an SMF
        // that did would send one request per released session in every deployment
        // that does not use interworking.
        seed_binding("ebi-release-none", 6);
        if let Ok(ctx) = smf_self().read() {
            if let Ok(mut bindings) = ctx.policy_bindings.write() {
                if let Some(b) = bindings.get_mut("ebi-release-none") {
                    b.sm_context_status_uri = Some(amf_uri.clone());
                }
            }
        }
        seen.lock().unwrap_or_else(|e| e.into_inner()).clear();
        let _ = handle_sm_context_release("ebi-release-none", None).await;
        assert!(
            !seen
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .any(|(_, p, _)| p.ends_with("/assign-ebi")),
            "a session that never had an EBI must not dial assign-ebi"
        );

        eps_iwk::set_for_test(false);
        amf.stop().await.expect("stop");
    }

    /// #291 criterion 5: with interworking disabled the release path sends nothing,
    /// even for a binding that carries an EBI from an earlier enabled run.
    #[tokio::test]
    async fn a_disabled_interworking_leg_releases_no_ebi() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        eps_iwk::set_for_test(false);
        let (amf, amf_uri, seen) = spawn_recording_amf().await;

        seed_binding_with_ebi("ebi-release-off", 5, 8, &amf_uri);
        seen.lock().unwrap_or_else(|e| e.into_inner()).clear();

        assert_eq!(
            handle_sm_context_release("ebi-release-off", None)
                .await
                .status,
            204
        );
        assert!(
            !seen
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .any(|(_, p, _)| p.ends_with("/assign-ebi")),
            "a disabled leg must not dial the AMF"
        );

        amf.stop().await.expect("stop");
    }

    /// #291 criterion 3: a failed release does not fail the session release.
    ///
    /// The session is going away either way, so the SMF cannot make its own
    /// teardown depend on the AMF answering. Port 1 is closed, so the request
    /// fails at connect.
    #[tokio::test]
    async fn a_failed_ebi_release_does_not_fail_the_session_release() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        eps_iwk::set_for_test(true);

        seed_binding_with_ebi("ebi-release-dead", 5, 9, "http://127.0.0.1:1");
        let resp = handle_sm_context_release("ebi-release-dead", None).await;
        assert_eq!(
            resp.status, 204,
            "an unreachable AMF must not turn a session release into a failure"
        );
        // The binding is gone regardless: the release completed locally.
        assert!(
            lookup_policy_binding("ebi-release-dead").is_none(),
            "the release must complete even when the EBI could not be returned"
        );

        eps_iwk::set_for_test(false);
    }

    /// #293 criteria 1 + 4: the create subscribes to SM data, and the release both
    /// deregisters the serving-SMF record and deletes that subscription.
    ///
    /// End to end through the real handlers, which #289's UPF stand-in is what makes
    /// possible: before it, no test could drive a create past its N4 leg, so a
    /// subscribe on the establishment path could only have been asserted by calling
    /// the helper — the shape that let #276's dead `create_dns_context` survive a month.
    ///
    /// Lock order (see `pfcp_path::N4_TEST_LOCK`): switch locks first, N4 last.
    #[tokio::test]
    async fn the_create_subscribes_to_sm_data_and_the_release_deregisters_and_unsubscribes() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let upf = pfcp_path::stand_in::associated_upf().await;
        let (udm_srv, seen) = spawn_recording_udm(sm_data_with("100 Mbps", "500 Mbps", 7)).await;
        udm::set_for_test(true);
        smf_context_init(64, 256, 512);

        let supi = "imsi-001010000000293";
        let psi = 8u8;
        seen.lock().unwrap_or_else(|e| e.into_inner()).clear();
        let resp = handle_sm_context_create(&create_request(
            supi,
            psi,
            &n1(
                psi,
                1,
                gsm_build::message_type::PDU_SESSION_ESTABLISHMENT_REQUEST,
                &[0x91, 0x00],
            ),
        ))
        .await;
        assert_eq!(resp.status, 201, "the create must reach the success path");
        let sm_context_ref = serde_json::from_str::<serde_json::Value>(
            resp.http.content.as_deref().expect("JSON root"),
        )
        .expect("json")["smContextRef"]
            .as_str()
            .expect("smContextRef")
            .to_string();
        assert!(
            upf.seen()
                .contains(&pfcp_path::pfcp_message_type::SESSION_ESTABLISHMENT_REQUEST),
            "the 201 must have been earned on the N4 wire"
        );

        let requests = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let sub = requests
            .iter()
            .find(|(m, u, _)| m == "POST" && u.contains("/sdm-subscriptions"))
            .unwrap_or_else(|| panic!("the create must send Nudm_SDM_Subscribe, got {requests:?}"));
        assert_eq!(
            sub.1,
            format!("/nudm-sdm/v2/{supi}/sdm-subscriptions"),
            "TS 29.503 §5.2.2.3's collection, at v2 like the rest of Nudm_SDM"
        );
        let body: serde_json::Value = serde_json::from_str(&sub.2).expect("json");
        for required in ["nfInstanceId", "callbackReference", "monitoredResourceUris"] {
            assert!(
                body.get(required).is_some(),
                "SdmSubscription.{required} is required, got {body}"
            );
        }
        let callback = body["callbackReference"].as_str().unwrap_or_default();
        assert!(
            callback.ends_with(&format!("/nsmf-callback/v1/sdm-notify/{sm_context_ref}")),
            "the callback must name the route this SMF serves and the session it is \
             for, got {callback}"
        );
        assert!(
            body["monitoredResourceUris"][0]
                .as_str()
                .unwrap_or_default()
                .contains("/sm-data"),
            "the monitored resource is the sm-data document this session depends on, \
             got {body}"
        );
        // The subscription id is recorded on the binding, or the release could not
        // delete it (the orphan case `subscribe_sm_data` warns about).
        assert_eq!(
            lookup_policy_binding(&sm_context_ref).and_then(|b| b.sdm_subscription_id),
            Some("sub-293".to_string()),
            "the id from the Location header must be stored with the binding"
        );

        // ---- release: the UECM record goes, and so does the subscription ----
        seen.lock().unwrap_or_else(|e| e.into_inner()).clear();
        assert_eq!(
            handle_sm_context_release(&sm_context_ref, None)
                .await
                .status,
            204
        );
        let requests = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert!(
            requests.iter().any(|(m, u, _)| m == "DELETE"
                && u == &format!("/nudm-uecm/v1/{supi}/registrations/smf-registrations/{psi}")),
            "the release must remove the serving-SMF record for its own pduSessionId, \
             got {requests:?}"
        );
        assert!(
            requests.iter().any(|(m, u, _)| m == "DELETE"
                && u == &format!("/nudm-sdm/v2/{supi}/sdm-subscriptions/sub-293")),
            "the release must delete the SDM subscription it created, got {requests:?}"
        );

        udm::set_for_test(false);
        std::env::remove_var("UDM_SBI_ADDR");
        std::env::remove_var("UDM_SBI_PORT");
        udm_srv.stop().await.expect("stop");
    }

    /// #293 criterion 3: the notification callback applies a changed session-AMBR and
    /// default 5QI to a LIVE session, read back off the session and the binding.
    ///
    /// Also the PCF-precedence half (criterion 5): the same notification against a
    /// session a PCF authorised changes nothing, because TS 23.503 §6.1.3.2 makes the
    /// PCF the authority and the subscription is one of its inputs.
    #[tokio::test]
    async fn a_sdm_notification_applies_the_changed_ambr_to_a_live_session() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        // The UDM now answers with DIFFERENT values from the ones the session holds.
        let (udm_srv, seen) = spawn_recording_udm(sm_data_with("40 Mbps", "80 Mbps", 6)).await;
        udm::set_for_test(true);
        smf_context_init(64, 256, 512);

        // A real registered session, so the fill-in the handler updates is there to
        // read back.
        let supi = "imsi-001010000000296";
        let sm_context_ref = {
            let ctx = smf_self();
            let context = ctx.read().expect("context");
            let (reference, _id) = register_sm_context(&context, supi, 9).expect("register");
            reference
        };
        seed_binding(&sm_context_ref, 9);
        if let Ok(ctx) = smf_self().read() {
            if let Ok(mut bindings) = ctx.policy_bindings.write() {
                if let Some(b) = bindings.get_mut(&sm_context_ref) {
                    b.supi = supi.to_string();
                    b.sdm_subscription_id = Some("sub-293".to_string());
                }
            }
        }

        let notify = |reference: &str| {
            SbiRequest::post(format!("/nsmf-callback/v1/sdm-notify/{reference}")).with_body(
                serde_json::json!({
                    "notifyItems": [{
                        "resourceId": format!("/nudm-sdm/v2/{supi}/sm-data"),
                        "changes": [{ "op": "REPLACE", "path": "/sessionAmbr" }],
                    }]
                })
                .to_string(),
                "application/json",
            )
        };

        let resp = smf_sbi_request_handler(notify(&sm_context_ref)).await;
        assert_eq!(
            resp.status, 204,
            "a notification for a live session is a 204"
        );

        // The session and the binding must BOTH carry the new values: the Retrieve and
        // the EPS-interworking encoders read the session, the update and release paths
        // read the binding, and a change applied to one leaves them disagreeing.
        let binding = lookup_policy_binding(&sm_context_ref).expect("binding");
        assert_eq!(
            (binding.ambr_ul_bps, binding.ambr_dl_bps, binding.five_qi),
            (40_000_000, 80_000_000, 6),
            "the changed subscription must reach the binding"
        );
        let sess = smf_self()
            .read()
            .expect("context")
            .sess_find_by_sm_context_ref(&sm_context_ref)
            .expect("session");
        assert_eq!(
            (sess.session_ambr.uplink, sess.session_ambr.downlink),
            (40_000_000, 80_000_000),
            "and the session, which is what Retrieve answers with"
        );
        assert!(
            seen.lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .any(|(m, u, _)| m == "GET" && u.contains("/sm-data")),
            "the change is RE-READ from the UDM rather than parsed out of the \
             notification -- see handle_sdm_notification"
        );

        // ---- PCF precedence: the same notification changes nothing ----
        let pcf_ref = {
            let ctx = smf_self();
            let context = ctx.read().expect("context");
            let (reference, _id) = register_sm_context(&context, supi, 10).expect("register");
            reference
        };
        seed_binding(&pcf_ref, 10);
        if let Ok(ctx) = smf_self().read() {
            if let Ok(mut bindings) = ctx.policy_bindings.write() {
                if let Some(b) = bindings.get_mut(&pcf_ref) {
                    b.supi = supi.to_string();
                    b.sm_policy_id = Some("pol-1".to_string());
                }
            }
        }
        let before = lookup_policy_binding(&pcf_ref).expect("binding");
        assert_eq!(smf_sbi_request_handler(notify(&pcf_ref)).await.status, 204);
        let after = lookup_policy_binding(&pcf_ref).expect("binding");
        assert_eq!(
            (after.ambr_ul_bps, after.ambr_dl_bps, after.five_qi),
            (before.ambr_ul_bps, before.ambr_dl_bps, before.five_qi),
            "a PCF-authorised session must not be re-derived from the subscription: \
             TS 23.503 §6.1.3.2 makes the PCF the authority, and the subscription is \
             one of ITS inputs"
        );

        // A notification for a session this SMF does not hold is a 404, which is what
        // tells the UDM to stop notifying a subscription that outlived its session.
        assert_eq!(
            smf_sbi_request_handler(notify("no-such-ref")).await.status,
            404
        );
        // A malformed body is refused rather than silently accepted.
        assert_eq!(
            smf_sbi_request_handler(
                SbiRequest::post(format!("/nsmf-callback/v1/sdm-notify/{sm_context_ref}"))
                    .with_body("not json".to_string(), "application/json")
            )
            .await
            .status,
            400
        );

        udm::set_for_test(false);
        std::env::remove_var("UDM_SBI_ADDR");
        std::env::remove_var("UDM_SBI_PORT");
        udm_srv.stop().await.expect("stop");
    }

    /// #293 criterion 2: a failed UDM teardown does not fail the session release.
    ///
    /// Port 1 is closed, so both the deregistration and the unsubscribe fail at
    /// connect. The release must still answer 204 and still drop its local state — a
    /// session whose teardown depends on the UDM answering would be a session the SMF
    /// cannot release during a UDM outage.
    #[tokio::test]
    async fn a_failed_udm_teardown_does_not_fail_the_session_release() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        udm::set_for_test(true);
        std::env::set_var("UDM_SBI_ADDR", "127.0.0.1");
        std::env::set_var("UDM_SBI_PORT", "1");

        seed_binding("udm-teardown-dead", 11);
        if let Ok(ctx) = smf_self().read() {
            if let Ok(mut bindings) = ctx.policy_bindings.write() {
                if let Some(b) = bindings.get_mut("udm-teardown-dead") {
                    b.sdm_subscription_id = Some("sub-dead".to_string());
                }
            }
        }

        assert_eq!(
            handle_sm_context_release("udm-teardown-dead", None)
                .await
                .status,
            204,
            "an unreachable UDM must not turn a session release into a failure"
        );
        assert!(
            lookup_policy_binding("udm-teardown-dead").is_none(),
            "the release must complete locally regardless"
        );

        udm::set_for_test(false);
        std::env::remove_var("UDM_SBI_ADDR");
        std::env::remove_var("UDM_SBI_PORT");
    }

    /// #293 criterion 6: with the UDM leg off, the release sends nothing — not even
    /// for a binding that carries a subscription id from an earlier enabled run.
    #[tokio::test]
    async fn a_disabled_udm_leg_neither_deregisters_nor_unsubscribes() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let (udm_srv, seen) = spawn_recording_udm(sm_data_with("100 Mbps", "500 Mbps", 7)).await;
        udm::set_for_test(false);

        seed_binding("udm-off-ref", 12);
        if let Ok(ctx) = smf_self().read() {
            if let Ok(mut bindings) = ctx.policy_bindings.write() {
                if let Some(b) = bindings.get_mut("udm-off-ref") {
                    b.sdm_subscription_id = Some("sub-293".to_string());
                }
            }
        }
        seen.lock().unwrap_or_else(|e| e.into_inner()).clear();

        assert_eq!(
            handle_sm_context_release("udm-off-ref", None).await.status,
            204
        );
        let requests = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert!(
            requests.is_empty(),
            "a disabled UDM leg must not dial the UDM at all, got {requests:?}"
        );

        std::env::remove_var("UDM_SBI_ADDR");
        std::env::remove_var("UDM_SBI_PORT");
        udm_srv.stop().await.expect("stop");
    }

    fn n1(psi: u8, pti: u8, message_type: u8, tail: &[u8]) -> Vec<u8> {
        let mut m = vec![0x2E, psi, pti, message_type];
        m.extend_from_slice(tail);
        m
    }

    /// A well-formed `SmContextCreateData` request with its N1 container as a
    /// multipart 5gnas part — the shape the AMF sends (#289).
    ///
    /// Shared by every create test so they differ only in the SUPI and PSI they
    /// drive; three copies of this literal had already drifted apart in wording
    /// while meaning the same thing.
    fn create_request(supi: &str, psi: u8, n1_msg: &[u8]) -> SbiRequest {
        let body = serde_json::json!({
            "pduSessionId": psi,
            "supi": supi,
            "sNssai": { "sst": 1, "sd": "010203" },
            "dnn": "internet",
            "anType": "3GPP_ACCESS",
            "ratType": "NR",
            // #293: the serving PLMN, which `SmfRegistration.plmnId` is `required` to
            // carry. A real AMF sends the GUAMI; without it the UECM registration is
            // (correctly) not sent at all, so a create test that omitted it could not
            // exercise the UDM leg.
            "guami": { "plmnId": { "mcc": "001", "mnc": "01" } },
            "n1SmMsg": { "contentId": "n1SmMsg" },
        });
        SbiRequest::post("/nsmf-pdusession/v1/sm-contexts")
            .with_body(body.to_string(), "application/json")
            .with_part(nextgcore_sbi::message::SbiPart::with_content(
                "n1SmMsg",
                "application/vnd.3gpp.5gnas",
                bytes::Bytes::copy_from_slice(n1_msg),
            ))
    }

    // ---- criteria 1 + 3: the 5GSM message is classified and dispatched ----

    #[test]
    fn n1_sm_messages_are_classified_by_their_5gsm_type() {
        use gsm_build::message_type as mt;

        assert_eq!(
            classify_n1_sm_message(&n1(5, 2, mt::PDU_SESSION_RELEASE_REQUEST, &[36])),
            Some(N1SmIntent::ReleaseRequested {
                psi: 5,
                pti: 2,
                cause: Some(36)
            })
        );
        assert_eq!(
            classify_n1_sm_message(&n1(5, 2, mt::PDU_SESSION_MODIFICATION_REQUEST, &[])),
            Some(N1SmIntent::ModificationRequested { psi: 5, pti: 2 })
        );
        assert_eq!(
            classify_n1_sm_message(&n1(5, 2, mt::PDU_SESSION_MODIFICATION_COMPLETE, &[])),
            Some(N1SmIntent::ModificationComplete)
        );
        assert_eq!(
            classify_n1_sm_message(&n1(5, 2, mt::PDU_SESSION_RELEASE_COMPLETE, &[])),
            Some(N1SmIntent::ReleaseComplete)
        );
        assert_eq!(
            classify_n1_sm_message(&n1(5, 2, mt::GSM_STATUS, &[95])),
            Some(N1SmIntent::Status { cause: Some(95) })
        );
        // A 5GSM message this SMF does not act on here is distinguished from a
        // malformed one: the first is a 400 naming the type, the second a 400
        // naming the container.
        assert_eq!(
            classify_n1_sm_message(&n1(5, 2, mt::PDU_SESSION_ESTABLISHMENT_ACCEPT, &[])),
            Some(N1SmIntent::Unhandled {
                message_type: mt::PDU_SESSION_ESTABLISHMENT_ACCEPT
            })
        );
        // Not 5GSM at all (5GMM EPD 0x7E), and too short.
        assert_eq!(classify_n1_sm_message(&[0x7E, 0x00, 0x41, 0x09]), None);
        assert_eq!(classify_n1_sm_message(&[0x2E, 0x05]), None);
    }

    /// The whole point of the issue: a `/modify` body carrying ONLY an N1
    /// container must run the 5GSM procedure, not fall through to `upCnxState`.
    #[tokio::test]
    async fn modify_with_only_an_n1_container_runs_the_release_procedure() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let reference = "n77-release";
        seed_binding(reference, 5);

        let release_request = n1(
            5,
            2,
            gsm_build::message_type::PDU_SESSION_RELEASE_REQUEST,
            &[36],
        );
        let body = serde_json::json!({ "n1SmMsg": { "contentId": "n1SmMsg" } });
        let mut request = SbiRequest::post(format!(
            "/nsmf-pdusession/v1/sm-contexts/{reference}/modify"
        ));
        request.http.content = Some(body.to_string());
        request
            .http
            .parts
            .push(nextgcore_sbi::message::SbiPart::with_content(
                "n1SmMsg",
                nextgcore_sbi::constants::content_type::APPLICATION_5GNAS,
                bytes::Bytes::copy_from_slice(&release_request),
            ));

        // Routed through the real /modify handler, because the defect was in its
        // dispatch: the N1 container was never reached.
        let resp = handle_sm_context_update(reference, &request).await;
        assert_eq!(resp.status, 200);

        let root: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("JSON");
        assert_eq!(
            root["n2SmInfoType"], "PDU_RES_REL_CMD",
            "the release must also tell the AMF to release the gNB's N2 resources; \
             got {root}"
        );
        assert_ne!(
            root["upCnxState"], "ACTIVATED",
            "the old handler answered a release request with an activation \
             confirmation and ran no procedure at all"
        );

        // The N1 part is a PDU SESSION RELEASE COMMAND echoing the UE's PSI/PTI.
        let n1_part = resp
            .http
            .parts
            .iter()
            .find(|p| p.content_id.as_deref() == Some("n1SmMsg"))
            .expect("n1SmMsg part");
        assert_eq!(n1_part.data[0], 0x2E, "5GSM EPD");
        assert_eq!(n1_part.data[1], 5, "PSI echoed");
        assert_eq!(n1_part.data[2], 2, "PTI echoed");
        assert_eq!(
            n1_part.data[3],
            gsm_build::message_type::PDU_SESSION_RELEASE_COMMAND
        );

        // The N2 part decodes as a real release-command transfer.
        let n2_part = resp
            .http
            .parts
            .iter()
            .find(|p| p.content_id.as_deref() == Some("n2SmInfo"))
            .expect("n2SmInfo part");
        assert!(
            nextgcore_ngap::transfer::PduSessionResourceReleaseCommandTransfer::decode(
                &n2_part.data
            )
            .is_ok(),
            "the N2 transfer must be decodable APER, not placeholder bytes"
        );

        // T3592 is now supervising the command, and RELEASE COMPLETE stops it.
        assert!(
            gsm_procedure_timers()
                .lock()
                .expect("timers")
                .contains_key(reference),
            "sending a RELEASE COMMAND must arm T3592"
        );
        assert!(cancel_gsm_timer(reference, timer::SmfTimerId::T3592));
        assert!(!gsm_procedure_timers()
            .lock()
            .expect("timers")
            .contains_key(reference));
    }

    #[tokio::test]
    async fn modification_request_arms_t3591_and_complete_stops_it() {
        let reference = "n77-modify";
        seed_binding(reference, 7);

        let resp = handle_n1_sm_message(
            reference,
            &n1(
                7,
                3,
                gsm_build::message_type::PDU_SESSION_MODIFICATION_REQUEST,
                &[],
            ),
        )
        .await;
        assert_eq!(resp.status, 200);
        let n1_part = resp
            .http
            .parts
            .iter()
            .find(|p| p.content_id.as_deref() == Some("n1SmMsg"))
            .expect("n1SmMsg part");
        assert_eq!(
            n1_part.data[3],
            gsm_build::message_type::PDU_SESSION_MODIFICATION_COMMAND
        );
        {
            let timers = gsm_procedure_timers().lock().expect("timers");
            assert_eq!(
                timers.get(reference).map(|t| t.timer_id),
                Some(timer::SmfTimerId::T3591)
            );
        }

        // MODIFICATION COMPLETE settles the procedure with 204 and stops T3591.
        let resp = handle_n1_sm_message(
            reference,
            &n1(
                7,
                3,
                gsm_build::message_type::PDU_SESSION_MODIFICATION_COMPLETE,
                &[],
            ),
        )
        .await;
        assert_eq!(resp.status, 204);
        assert!(
            !gsm_procedure_timers()
                .lock()
                .expect("timers")
                .contains_key(reference),
            "MODIFICATION COMPLETE must stop T3591, or the SMF retransmits a \
             command the UE already answered"
        );
    }

    #[tokio::test]
    async fn n1_message_for_an_unknown_context_is_404_and_a_malformed_one_400() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        smf_context_init(64, 256, 512);
        let resp = handle_n1_sm_message(
            "n77-absent",
            &n1(
                1,
                0,
                gsm_build::message_type::PDU_SESSION_RELEASE_REQUEST,
                &[],
            ),
        )
        .await;
        assert_eq!(resp.status, 404);

        let reference = "n77-malformed";
        seed_binding(reference, 1);
        // Not a 5GSM container at all: refused as malformed rather than silently
        // ignored, which is what the old handler did to every N1 message.
        let resp = handle_n1_sm_message(reference, &[0x7E, 0x00, 0x41, 0x09]).await;
        assert_eq!(resp.status, 400);
    }

    // ---- criterion 4: T3591/T3592 retransmit and exhaust ----

    #[test]
    fn gsm_timers_retransmit_then_exhaust() {
        let reference = "n77-timer";
        // Clear any residue from another test using the same key.
        gsm_procedure_timers()
            .lock()
            .expect("timers")
            .remove(reference);

        let command = n1(
            9,
            1,
            gsm_build::message_type::PDU_SESSION_RELEASE_COMMAND,
            &[36],
        );
        arm_gsm_timer(
            reference,
            timer::SmfTimerId::T3592,
            &command,
            "imsi-001010000000001",
            9,
            None,
        );

        // Nothing is due before the deadline.
        assert!(expire_gsm_timers(std::time::Instant::now()).is_empty());

        // TS 24.501 Table 10.3.2: 4 retransmissions, then the procedure is
        // abandoned. Driven by advancing the clock rather than by sleeping 16 s
        // per attempt.
        let mut far_future = std::time::Instant::now() + std::time::Duration::from_secs(3600);
        for attempt in 1..=4u32 {
            let due = expire_gsm_timers(far_future);
            let mine: Vec<_> = due.iter().filter(|(r, _, _)| r == reference).collect();
            assert_eq!(mine.len(), 1, "attempt {attempt}: {due:?}");
            assert_eq!(mine[0].2, GsmTimerExpiry::Retransmit { attempt });
            assert_eq!(
                mine[0].1.command, command,
                "the retransmission must resend the SAME command bytes"
            );
            far_future += std::time::Duration::from_secs(3600);
        }

        let due = expire_gsm_timers(far_future);
        let mine: Vec<_> = due.iter().filter(|(r, _, _)| r == reference).collect();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].2, GsmTimerExpiry::Exhausted);
        assert!(
            !gsm_procedure_timers()
                .lock()
                .expect("timers")
                .contains_key(reference),
            "an exhausted timer must be dropped, not left to fire forever"
        );
    }

    #[test]
    fn cancelling_the_wrong_timer_id_does_not_stop_the_armed_one() {
        let reference = "n77-timer-mismatch";
        gsm_procedure_timers()
            .lock()
            .expect("timers")
            .remove(reference);
        arm_gsm_timer(
            reference,
            timer::SmfTimerId::T3592,
            &[0x2E, 1, 0, 0xD3],
            "imsi-001010000000001",
            1,
            None,
        );
        // A MODIFICATION COMPLETE must not stop a release timer: the two
        // procedures are distinct, and cancelling the wrong one would leave the
        // release unsupervised.
        assert!(!cancel_gsm_timer(reference, timer::SmfTimerId::T3591));
        assert!(gsm_procedure_timers()
            .lock()
            .expect("timers")
            .contains_key(reference));
        assert!(cancel_gsm_timer(reference, timer::SmfTimerId::T3592));
        // A second cancel is a no-op, not a panic (duplicate COMPLETE).
        assert!(!cancel_gsm_timer(reference, timer::SmfTimerId::T3592));
    }

    #[test]
    fn gsm_timer_configs_match_ts_24_501_table_10_3_2() {
        let configs = timer::SmfTimerConfigs::default();
        for id in [timer::SmfTimerId::T3591, timer::SmfTimerId::T3592] {
            let c = configs.get(id).expect("configured");
            assert_eq!(c.duration, std::time::Duration::from_secs(16), "{id:?}");
            assert_eq!(c.max_count, 4, "{id:?}");
            assert!(id.is_gsm_timer());
            assert!(!id.is_pfcp_timer(), "{id:?} is a NAS timer, not a PFCP one");
        }
    }

    // ---- criterion 6: the SSC mode is authorised, not echoed ----

    #[test]
    fn ssc_mode_is_authorised_against_what_the_smf_implements() {
        // Mode 1 is implemented.
        assert_eq!(authorize_ssc_mode(1), Ok(1));
        // Absent (0) means no preference: the SMF picks its lowest supported.
        assert_eq!(authorize_ssc_mode(0), Ok(1));
        // Modes 2 and 3 need PSA relocation, which this SMF does not implement.
        // Echoing them — the old behaviour — promised continuity it cannot deliver.
        assert_eq!(authorize_ssc_mode(2), Err(ALLOWED_SSC_MODE_BITMAP));
        assert_eq!(authorize_ssc_mode(3), Err(ALLOWED_SSC_MODE_BITMAP));
        // Out-of-range values are refused rather than passed through.
        assert_eq!(authorize_ssc_mode(4), Err(ALLOWED_SSC_MODE_BITMAP));
        assert_eq!(authorize_ssc_mode(7), Err(ALLOWED_SSC_MODE_BITMAP));
    }

    #[test]
    fn ssc_reject_carries_cause_68_and_the_allowed_ssc_mode_ie() {
        let resp = sm_context_create_ssc_error(5, 2, ALLOWED_SSC_MODE_BITMAP);
        assert_eq!(resp.status, 403);
        let n1_part = resp
            .http
            .parts
            .iter()
            .find(|p| p.content_id.as_deref() == Some("n1SmMsg"))
            .expect("n1SmMsg part");
        assert_eq!(n1_part.data[0], 0x2E);
        assert_eq!(
            n1_part.data[3],
            gsm_build::message_type::PDU_SESSION_ESTABLISHMENT_REJECT
        );
        assert_eq!(
            n1_part.data[4],
            policy::gsm_cause::NOT_SUPPORTED_SSC_MODE,
            "5GSM cause #68"
        );
        // Allowed SSC mode is a type-1 IE: IEI nibble 0xF, bitmap in the low nibble.
        let last = *n1_part.data.last().expect("non-empty");
        assert_eq!(last >> 4, 0x0F);
        assert_eq!(last & 0x07, ALLOWED_SSC_MODE_BITMAP);
    }

    // ---- criteria 5 + 7: the accept carries ePCO DNS and a labelled DNN ----

    #[test]
    fn establishment_accept_carries_the_configured_dns_in_an_epco_ie() {
        let dns = [
            std::net::Ipv4Addr::new(8, 8, 8, 8),
            std::net::Ipv4Addr::new(8, 8, 4, 4),
        ];
        let accept = policy::build_establishment_accept(
            5,
            2,
            policy::pdu_session_type::IPV4,
            1,
            1,
            9,
            100_000_000,
            100_000_000,
            [10, 45, 0, 2],
            [0u8; 8],
            1,
            None,
            "internet",
            None,
            &dns,
            Some(1400),
            None,
        );

        // The ePCO IE (0x7B) must be present with a two-octet TLV-E length.
        let epco_at = accept
            .windows(1)
            .position(|w| w == [0x7B])
            .expect("ePCO IE present in the accept");
        let len = u16::from_be_bytes([accept[epco_at + 1], accept[epco_at + 2]]) as usize;
        let epco = &accept[epco_at + 3..epco_at + 3 + len];
        assert_eq!(epco[0], 0x80, "ePCO configuration protocol");

        // Both DNS addresses appear as 0x000D containers, and the MTU as 0x0010.
        for addr in dns {
            let needle = [
                0x00,
                0x0D,
                4,
                addr.octets()[0],
                addr.octets()[1],
                addr.octets()[2],
                addr.octets()[3],
            ];
            assert!(
                epco.windows(needle.len()).any(|w| w == needle),
                "DNS {addr} must be signalled in the ePCO: {epco:02x?}"
            );
        }
        assert!(
            epco.windows(5).any(|w| w == [0x00, 0x10, 2, 0x05, 0x78]),
            "the 1400-byte link MTU must be signalled: {epco:02x?}"
        );

        // With nothing configured, no ePCO IE is emitted — the previous behaviour,
        // so a deployment that configures no DNS is unchanged.
        let bare = policy::build_establishment_accept(
            5,
            2,
            policy::pdu_session_type::IPV4,
            1,
            1,
            9,
            100_000_000,
            100_000_000,
            [10, 45, 0, 2],
            [0u8; 8],
            1,
            None,
            "internet",
            None,
            &[],
            None,
            None,
        );
        assert!(
            !bare.contains(&0x7B),
            "no DNS and no MTU configured must emit no ePCO IE"
        );
    }

    #[test]
    fn a_multi_label_dnn_is_encoded_as_length_prefixed_labels() {
        // The bug: one label whose length octet covered the whole string, dots
        // included. Single-label DNNs encode identically either way, which is why
        // it survived.
        assert_eq!(
            policy::encode_dnn_labels("internet"),
            vec![8, b'i', b'n', b't', b'e', b'r', b'n', b'e', b't']
        );

        let labelled = policy::encode_dnn_labels("internet.mnc001.mcc001.gprs");
        assert_eq!(labelled[0], 8, "first label length");
        assert_eq!(&labelled[1..9], b"internet");
        assert_eq!(labelled[9], 6, "mnc001");
        assert_eq!(&labelled[10..16], b"mnc001");
        assert_eq!(labelled[16], 6, "mcc001");
        assert_eq!(labelled[23], 4, "gprs");
        assert!(
            !labelled.contains(&b'.'),
            "no dot may survive into the encoded name: {labelled:02x?}"
        );

        // Must agree byte-for-byte with the N4 APN/DNN encoder, which already did
        // this correctly — the two name the same DNN to the UPF and to the UE.
        let mut n4 = nextgcore_smfd_n4_dnn("internet.mnc001.mcc001.gprs");
        assert_eq!(labelled, n4, "the N1 and N4 DNN encodings must agree");
        n4 = nextgcore_smfd_n4_dnn("internet");
        assert_eq!(policy::encode_dnn_labels("internet"), n4);

        // Empty labels (leading/trailing/doubled dots) are skipped rather than
        // encoded as a zero length octet, which would terminate the name early.
        assert_eq!(
            policy::encode_dnn_labels(".internet..gprs."),
            policy::encode_dnn_labels("internet.gprs")
        );
        assert!(policy::encode_dnn_labels("").is_empty());
    }

    /// The N4 APN/DNN encoding, extracted from a built PFCP IE so the comparison
    /// above is against what `add_apn_dnn` actually emits rather than a
    /// re-implementation of it.
    fn nextgcore_smfd_n4_dnn(dnn: &str) -> Vec<u8> {
        let mut builder = n4_build::PfcpMessageBuilder::new();
        builder.add_apn_dnn(dnn);
        let ie = builder.build();
        // TLV: 2-octet type, 2-octet length, then the value.
        let len = u16::from_be_bytes([ie[2], ie[3]]) as usize;
        ie[4..4 + len].to_vec()
    }

    #[test]
    fn smf_yaml_dns_and_mtu_are_parsed() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.blocking_lock();
        // The shipped docker config has declared these all along; nothing read
        // them, so the UE received no DNS configuration.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("n77-smf-{}.yaml", std::process::id()));
        std::fs::write(
            &path,
            "smf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: 7777\n\
             \x20 dns:\n    - 8.8.8.8\n    - 2001:4860:4860::8888\n    - 8.8.4.4\n  mtu: 1400\n",
        )
        .expect("write config");
        let config = load_config(path.to_str().expect("path"));
        let _ = std::fs::remove_file(&path);

        assert_eq!(
            config.dns_servers,
            vec![
                std::net::Ipv4Addr::new(8, 8, 8, 8),
                std::net::Ipv4Addr::new(8, 8, 4, 4)
            ],
            "the IPv4 entries are taken in order; the IPv6 one is skipped rather \
             than failing the whole parse"
        );
        assert_eq!(config.mtu, Some(1400));
    }
    // ====================================================================
    // #78: SM context lifecycle
    //
    // These drive the REAL SBI handlers, not helpers, and share the process-global
    // SMF context, so each uses distinct references and asserts only about its own.
    // ====================================================================

    /// Register a session in the context list the way the create handler now does,
    /// and return its `smContextRef` — minted by the session itself, so a test can
    /// never assert against a reference the context does not hold.
    fn seed_registered_session(supi: &str, psi: u8, dnn: &str) -> String {
        smf_context_init(64, 256, 512);
        let ctx = smf_self();
        let context = ctx.read().expect("context");
        let ue = context
            .ue_find_by_supi(supi)
            .or_else(|| context.ue_add_by_supi(supi))
            .expect("ue");
        let mut sess = context.sess_add_by_psi(ue.id, psi).expect("session");
        sess.session_name = Some(dnn.to_string());
        sess.full_dnn = Some(dnn.to_string());
        sess.s_nssai = context::SNssai { sst: 1, sd: None };
        sess.set_ipv4_addr(std::net::Ipv4Addr::new(10, 45, 0, 2));
        sess.up_cnx_state = context::UpCnxState::Activated;
        sess.session_qos.index = 9;
        context.sess_update(&sess);
        sess.sm_context_ref
            .clone()
            .expect("the session mints its own ref")
    }

    /// #78 criterion 1, guarding the CREATE handler itself.
    ///
    /// Written after a revert pass showed that
    /// `retrieve_answers_200_with_ue_eps_pdn_connection` still passed with the
    /// create handler's registration removed — it seeds a session directly, so it
    /// guards Retrieve, not create. This drives the real
    /// `handle_sm_context_create` through the router.
    ///
    /// What is asserted here is the rollback contract, the half that a naive
    /// registration gets wrong: a create that answers an error must leave **no**
    /// SM context behind. An abandoned registration would be a context the AMF
    /// never learned about and will never release.
    ///
    /// #289 converted this test: the N4 leg now fails because the stand-in UPF's
    /// association is deliberately down, not because no UPF exists. The
    /// REGISTRATION half its old comment asked for is
    /// `a_successful_create_registers_an_activated_session_and_its_binding` below.
    #[tokio::test]
    async fn a_failed_create_leaves_no_registered_sm_context() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let _upf = pfcp_path::stand_in::unassociated_upf().await;
        smf_context_init(64, 256, 512);
        let supi = "imsi-001010000000086";
        let psi = 11u8;

        // A create that reaches the N4 leg and fails there, the same shape
        // `a_failed_establishment_creates_no_easdf_dns_context` uses.
        let n1_msg = n1(
            psi,
            1,
            gsm_build::message_type::PDU_SESSION_ESTABLISHMENT_REQUEST,
            &[0x91, 0x00],
        );
        let resp = handle_sm_context_create(&create_request(supi, psi, &n1_msg)).await;
        assert_eq!(
            resp.status, 504,
            "an un-associated UPF must fail the N4 leg (TS 29.244 §6.2.6.2)"
        );

        // Asserted per-SUPI, not on a global session count: this context is
        // process-global and sibling tests add sessions of their own, so an absolute
        // count is a race rather than an assertion (which is how the first version of
        // this test failed).
        let ctx = smf_self();
        let guard = ctx.read().expect("context");
        let leftover = guard
            .ue_find_by_supi(supi)
            .map(|ue| ue.sess_ids.len())
            .unwrap_or(0);
        assert_eq!(
            leftover, 0,
            "a create that answered 504 must roll its session registration back; an \
             abandoned registration is an SM context the AMF never learned about and \
             will never release"
        );
    }

    /// #289 acceptance: the whole tail after the PFCP block, which no test could
    /// reach before the stand-in UPF existed.
    ///
    /// Four claims, each of which was "verified by inspection" until now:
    /// 1. the create answers `201` with a resolvable `smContextRef`;
    /// 2. the session fill-in ran — `upCnxState` is ACTIVATED and the authorised
    ///    session AMBR is stored on the session (#78, #191);
    /// 3. the `PolicyBinding` was inserted — the release, update and notify paths
    ///    all key off it, so a create that skipped it produces a session none of
    ///    them can act on;
    /// 4. the N4 exchange really happened, asserted from the stand-in's own
    ///    record rather than from the SMF's report of it.
    ///
    /// Positive assertions throughout: each reads a value only reachable by
    /// executing the step it names, so no early return can satisfy them.
    #[tokio::test]
    async fn a_successful_create_registers_an_activated_session_and_its_binding() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let upf = pfcp_path::stand_in::associated_upf().await;
        smf_context_init(64, 256, 512);
        let supi = "imsi-001010000000290";
        let psi = 7u8;

        let n1_msg = n1(
            psi,
            1,
            gsm_build::message_type::PDU_SESSION_ESTABLISHMENT_REQUEST,
            &[0x91, 0x00],
        );
        let resp = handle_sm_context_create(&create_request(supi, psi, &n1_msg)).await;
        assert_eq!(
            resp.status, 201,
            "the stand-in UPF answers Session Establishment, so the create must succeed"
        );
        assert!(
            upf.seen()
                .contains(&pfcp_path::pfcp_message_type::SESSION_ESTABLISHMENT_REQUEST),
            "the create must have established the session on the N4 wire"
        );

        let root: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().expect("JSON root"))
                .expect("SmContextCreatedData is JSON");
        let sm_context_ref = root["smContextRef"]
            .as_str()
            .expect("smContextRef is mandatory")
            .to_string();

        // (2) The session fill-in ran. Both values are read back off the
        // registered session, so they can only be there if the create wrote them
        // after the N4 leg settled.
        let sess = smf_self()
            .read()
            .expect("context")
            .sess_find_by_sm_context_ref(&sm_context_ref)
            .expect("the reference the AMF was handed must resolve to a session");
        assert_eq!(
            sess.up_cnx_state,
            context::UpCnxState::Activated,
            "upCnxState is ACTIVATED once the user plane exists"
        );
        assert_eq!(
            (sess.session_ambr.uplink, sess.session_ambr.downlink),
            (100_000_000, 100_000_000),
            "the authorised session AMBR must be stored on the session"
        );

        // (3) The policy binding exists, keyed by the reference the AMF holds.
        let binding = lookup_policy_binding(&sm_context_ref)
            .expect("the create must store the PolicyBinding the release path keys off");
        assert_eq!(binding.supi, supi);
        assert_eq!(binding.psi, psi);

        // The stored UPF SEID is the one the stand-in allocated, so the SEID the
        // release path will address is the peer's and not a local invention.
        let stored_seid = smf_self()
            .read()
            .expect("context")
            .pfcp_sessions
            .read()
            .expect("sessions")
            .get(&sm_context_ref)
            .copied();
        assert_eq!(stored_seid, Some(upf.upf_seid));
    }

    /// #78 criterion 1's invariant, at the function the create handler calls: the
    /// reference a registration returns is the one that resolves to it.
    ///
    /// Guards the defect directly — before #78 the handler returned
    /// `next_sess_index()` and registered nothing, so the reference resolved to
    /// nothing at all; and once registration was added, computing the reference
    /// separately from the same counter would have left it one behind.
    #[test]
    fn register_sm_context_returns_the_reference_that_resolves_to_it() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.blocking_lock();
        smf_context_init(64, 256, 512);
        let ctx = smf_self();
        let context = ctx.read().expect("context");

        let (first_ref, first_id) =
            register_sm_context(&context, "imsi-001010000000088", 1).expect("first");
        let (second_ref, second_id) =
            register_sm_context(&context, "imsi-001010000000089", 2).expect("second");

        assert_ne!(first_ref, second_ref);
        assert_ne!(first_id, second_id);
        assert_eq!(
            context
                .sess_find_by_sm_context_ref(&first_ref)
                .map(|s| s.id),
            Some(first_id),
            "the reference the handler hands the AMF must resolve to the session it registered"
        );
        assert_eq!(
            context
                .sess_find_by_sm_context_ref(&second_ref)
                .map(|s| s.id),
            Some(second_id)
        );
        // Two registrations for the SAME subscriber reuse the UE and still get
        // distinct references: a second PDU session must not collide with the first.
        let (third_ref, third_id) =
            register_sm_context(&context, "imsi-001010000000088", 3).expect("third");
        assert_ne!(third_ref, first_ref);
        assert_eq!(
            context
                .sess_find_by_sm_context_ref(&third_ref)
                .map(|s| s.id),
            Some(third_id)
        );
    }

    /// The registration and the reference it returns come from ONE source.
    ///
    /// `sess_add_by_psi` mints `sm_context_ref` from `sess_index`, and the handler
    /// used to compute the reference from `next_sess_index()` — the same counter.
    /// Doing both would consume it twice and leave the handler's reference one
    /// behind the session's, so the value the AMF was given would resolve to
    /// nothing (or, worse, to the next session). This pins that the reference a
    /// registration yields is the one that resolves.
    #[test]
    fn a_registered_session_resolves_by_the_reference_it_minted() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.blocking_lock();
        smf_context_init(64, 256, 512);
        let ctx = smf_self();
        let context = ctx.read().expect("context");
        let ue = context.ue_add_by_supi("imsi-001010000000087").expect("ue");
        let first = context.sess_add_by_psi(ue.id, 1).expect("first session");
        let second = context.sess_add_by_psi(ue.id, 2).expect("second session");

        let first_ref = first.sm_context_ref.clone().expect("first ref");
        let second_ref = second.sm_context_ref.clone().expect("second ref");
        assert_ne!(first_ref, second_ref, "each session gets its own reference");

        // Each reference resolves to ITS OWN session, not to a neighbour.
        assert_eq!(
            context
                .sess_find_by_sm_context_ref(&first_ref)
                .map(|s| s.id),
            Some(first.id)
        );
        assert_eq!(
            context
                .sess_find_by_sm_context_ref(&second_ref)
                .map(|s| s.id),
            Some(second.id)
        );
    }

    /// #117 criterion 4: the retrieved `ueEpsPdnConnection` NAMES the assigned EBI
    /// when one exists, and is byte-identical to #78's output when none does.
    ///
    /// #78 deliberately shipped a minimal descriptor with no bearer contexts,
    /// because there was no EBI assignment in the tree and a fabricated bearer list
    /// would have an MME trying to use bearers this SMF never established. #117
    /// changes exactly that precondition, so the descriptor can now name a real
    /// identity — and the unchanged-when-absent half is criterion 5.
    #[tokio::test]
    async fn the_retrieved_ue_eps_pdn_connection_names_the_assigned_ebi() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        use base64::Engine as _;

        let without = seed_registered_session("imsi-001010000000123", 7, "internet");
        let body: serde_json::Value = serde_json::from_str(
            handle_sm_context_retrieve(&without)
                .await
                .http
                .content
                .as_deref()
                .expect("body"),
        )
        .expect("json");
        let baseline = base64::engine::general_purpose::STANDARD
            .decode(
                body["ueEpsPdnConnection"]
                    .as_str()
                    .expect("ueEpsPdnConnection is required"),
            )
            .expect("base64");

        // Same session, now with an EBI recorded on its policy binding.
        let with = seed_registered_session("imsi-001010000000124", 8, "internet");
        if let Ok(ctx) = smf_self().read() {
            if let Ok(mut bindings) = ctx.policy_bindings.write() {
                bindings.insert(
                    with.clone(),
                    context::PolicyBinding {
                        supi: "imsi-001010000000124".to_string(),
                        psi: 8,
                        dnn: "internet".to_string(),
                        mapped_eps_bearer_id: Some(6),
                        ..context::PolicyBinding::snapshot_default()
                    },
                );
            }
        }
        let body: serde_json::Value = serde_json::from_str(
            handle_sm_context_retrieve(&with)
                .await
                .http
                .content
                .as_deref()
                .expect("body"),
        )
        .expect("json");
        let carried = base64::engine::general_purpose::STANDARD
            .decode(body["ueEpsPdnConnection"].as_str().expect("required"))
            .expect("base64");

        assert_eq!(
            carried.len(),
            baseline.len() + 1,
            "exactly one octet more: the EBI, appended"
        );
        assert_eq!(
            &carried[..baseline.len()],
            &baseline[..],
            "the prefix must be unchanged, so a peer parsing #78's form reads the \
             same first bytes"
        );
        assert_eq!(
            *carried.last().expect("last octet"),
            6,
            "the descriptor must name the EBI the AMF assigned"
        );
    }

    // ---- #79: Nsmf_EventExposure, UDM interaction, H-SMF -------------------

    fn events_request(method: &str, path: &str, body: Option<serde_json::Value>) -> SbiRequest {
        let mut req = match method {
            "POST" => SbiRequest::post(path.to_string()),
            "GET" => SbiRequest::get(path.to_string()),
            "PUT" => SbiRequest::put(path.to_string()),
            "DELETE" => SbiRequest::delete(path.to_string()),
            other => panic!("unsupported method {other}"),
        };
        if let Some(body) = body {
            req = req.with_body(body.to_string(), "application/json");
        }
        req
    }

    fn subscription_body(notif_uri: &str, supi: Option<&str>) -> serde_json::Value {
        let mut body = serde_json::json!({
            "notifId": "corr-79",
            "notifUri": notif_uri,
            "eventSubs": [{ "event": "PDU_SES_REL" }],
        });
        if let Some(supi) = supi {
            body["supi"] = serde_json::json!(supi);
        }
        body
    }

    /// #79 criterion 4: create → get → delete, and `404` on an unknown id.
    ///
    /// Driven through the ROUTER, because half of what was missing was routing: no
    /// `GET` and no `PUT` arm existed at all, so a test calling the handlers
    /// directly would pass against a service a consumer cannot reach.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn event_subscriptions_are_a_real_resource_with_get_put_and_a_404() {
        let _g = event_exposure::lock_store();
        event_exposure::clear_for_test();

        // Create.
        let resp = smf_sbi_request_handler(events_request(
            "POST",
            "/nsmf-event-exposure/v1/subscriptions",
            Some(subscription_body("http://127.0.0.1:9/cb", Some("imsi-79"))),
        ))
        .await;
        assert_eq!(resp.status, 201, "body: {:?}", resp.http.content);
        let location = resp
            .http
            .get_header("location")
            .expect("201 must carry a Location")
            .to_string();
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("json");
        // An NsmfEventExposure document, not the bare {"subscriptionId": ...} the
        // facade returned.
        assert!(
            body.get("subscriptionId").is_none(),
            "subscriptionId is not a member of NsmfEventExposure, got {body}"
        );
        let sub_id = body["subId"].as_str().expect("subId").to_string();
        assert_eq!(body["notifId"], serde_json::json!("corr-79"));
        assert_eq!(
            body["eventSubs"][0]["event"],
            serde_json::json!("PDU_SES_REL")
        );
        assert_eq!(
            location,
            format!("/nsmf-event-exposure/v1/subscriptions/{sub_id}")
        );

        // Get.
        let resp = smf_sbi_request_handler(events_request("GET", &location, None)).await;
        assert_eq!(resp.status, 200, "the created resource must be retrievable");
        let fetched: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("json");
        assert_eq!(fetched["subId"], serde_json::json!(sub_id));
        assert_eq!(
            fetched["notifUri"],
            serde_json::json!("http://127.0.0.1:9/cb")
        );

        // Put replaces.
        let resp = smf_sbi_request_handler(events_request(
            "PUT",
            &location,
            Some(subscription_body(
                "http://127.0.0.1:9/moved",
                Some("imsi-79"),
            )),
        ))
        .await;
        assert_eq!(resp.status, 200);
        let replaced: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("json");
        assert_eq!(
            replaced["notifUri"],
            serde_json::json!("http://127.0.0.1:9/moved"),
            "the PUT must be applied, not merely acknowledged"
        );

        // A PUT to an unknown id must NOT create one.
        let resp = smf_sbi_request_handler(events_request(
            "PUT",
            "/nsmf-event-exposure/v1/subscriptions/never-existed",
            Some(subscription_body("http://127.0.0.1:9/cb", None)),
        ))
        .await;
        assert_eq!(resp.status, 404);

        // Delete, then delete again: 204 then 404. The facade answered 204 for
        // both, so a consumer could not tell an unsubscribe from a subscription
        // that had never existed.
        assert_eq!(
            smf_sbi_request_handler(events_request("DELETE", &location, None))
                .await
                .status,
            204
        );
        assert_eq!(
            smf_sbi_request_handler(events_request("DELETE", &location, None))
                .await
                .status,
            404,
            "a second DELETE must 404: the resource is gone"
        );
        assert_eq!(
            smf_sbi_request_handler(events_request("GET", &location, None))
                .await
                .status,
            404
        );

        // A body missing a required member is refused rather than stored.
        for missing in ["notifId", "notifUri", "eventSubs"] {
            let mut body = subscription_body("http://127.0.0.1:9/cb", None);
            body.as_object_mut().expect("obj").remove(missing);
            let resp = smf_sbi_request_handler(events_request(
                "POST",
                "/nsmf-event-exposure/v1/subscriptions",
                Some(body),
            ))
            .await;
            assert_eq!(
                resp.status, 400,
                "a subscription without {missing} must be refused"
            );
        }
        event_exposure::clear_for_test();
    }

    /// #79 criterion 5: a subscribed event occurrence produces a notification at
    /// the subscribed `notifUri`.
    ///
    /// `PDU_SES_REL` is chosen because the release handler needs no N4 establishment
    /// to reach; since #289 the establishment path is reachable too (against
    /// `pfcp_path::stand_in`), so the `PDU_SES_EST` notification is now a test away
    /// rather than blocked. The notification is captured on a real loopback
    /// consumer, so what is asserted is a delivered HTTP request rather than a
    /// function having been called.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn a_released_session_notifies_its_event_subscriber() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};

        let _g = event_exposure::lock_store();
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        event_exposure::clear_for_test();

        let seen: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = seen.clone();
        let port = nextgcore_sbi::test_support::free_port();
        let consumer = SbiServer::new(SbiServerConfig::new(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            port,
        ))));
        consumer
            .start(move |req: SbiRequest| {
                let sink = sink.clone();
                async move {
                    sink.lock().unwrap_or_else(|e| e.into_inner()).push((
                        req.header.uri.clone(),
                        req.http.content.clone().unwrap_or_default(),
                    ));
                    SbiResponse::with_status(204)
                }
            })
            .await
            .expect("consumer start");

        let supi = "imsi-001010000000079";
        let resp = smf_sbi_request_handler(events_request(
            "POST",
            "/nsmf-event-exposure/v1/subscriptions",
            Some(subscription_body(
                &format!("http://127.0.0.1:{port}/nsmf-events"),
                Some(supi),
            )),
        ))
        .await;
        assert_eq!(resp.status, 201);

        // A session for that SUPI, then release it.
        seed_binding("events-release-ref", 4);
        if let Ok(ctx) = smf_self().read() {
            if let Ok(mut bindings) = ctx.policy_bindings.write() {
                if let Some(b) = bindings.get_mut("events-release-ref") {
                    b.supi = supi.to_string();
                    b.psi = 4;
                }
            }
        }
        let _ = handle_sm_context_release("events-release-ref", None).await;

        let requests = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let notif = requests
            .iter()
            .find(|(uri, _)| uri.contains("/nsmf-events"))
            .unwrap_or_else(|| {
                panic!("a PDU_SES_REL notification must reach the subscriber, got {requests:?}")
            });
        let body: serde_json::Value = serde_json::from_str(&notif.1).expect("json");
        assert_eq!(
            body["notifId"],
            serde_json::json!("corr-79"),
            "the notification must carry the CONSUMER's correlation id"
        );
        assert_eq!(
            body["eventNotifs"][0]["event"],
            serde_json::json!("PDU_SES_REL")
        );
        assert_eq!(body["eventNotifs"][0]["supi"], serde_json::json!(supi));
        assert_eq!(body["eventNotifs"][0]["pduSeId"], serde_json::json!(4));

        // A subscription scoped to a DIFFERENT SUPI must not be notified: that
        // would leak one subscriber's session events to another's consumer.
        seen.lock().unwrap_or_else(|e| e.into_inner()).clear();
        seed_binding("events-release-other", 5);
        if let Ok(ctx) = smf_self().read() {
            if let Ok(mut bindings) = ctx.policy_bindings.write() {
                if let Some(b) = bindings.get_mut("events-release-other") {
                    b.supi = "imsi-999990000000000".to_string();
                    b.psi = 5;
                }
            }
        }
        let _ = handle_sm_context_release("events-release-other", None).await;
        assert!(
            seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
            "a SUPI-scoped subscription must not be notified about another subscriber"
        );

        event_exposure::clear_for_test();
        consumer.stop().await.expect("stop");
    }

    /// #79 criterion 6: the H-SMF `/pdu-sessions` service never answers a release
    /// cause on a create success.
    ///
    /// It used to answer `201` with `{"pduSessionRef": "1", "cause":
    /// "REL_DUE_TO_HO"}` — a release cause on a create — at a hardcoded reference,
    /// with no session created. `501` is the recorded answer in this project for a
    /// spec-defined resource whose dependency is absent.
    #[tokio::test]
    async fn the_hsmf_pdu_sessions_service_answers_501_and_never_a_release_cause() {
        for (method, path) in [
            ("POST", "/nsmf-pdusession/v1/pdu-sessions"),
            ("POST", "/nsmf-pdusession/v1/pdu-sessions/1/modify"),
            ("POST", "/nsmf-pdusession/v1/pdu-sessions/1/release"),
        ] {
            let resp = smf_sbi_request_handler(events_request(
                method,
                path,
                Some(serde_json::json!({ "vsmfId": "vsmf-1" })),
            ))
            .await;
            assert_eq!(resp.status, 501, "{method} {path} must answer 501");
            let body = resp.http.content.clone().unwrap_or_default();
            assert!(
                !body.contains("REL_DUE_TO_HO"),
                "a create must never carry a release cause, got {body}"
            );
            let json: serde_json::Value = serde_json::from_str(&body).expect("ProblemDetails");
            assert_eq!(json["cause"], serde_json::json!("NOT_IMPLEMENTED"));
            assert_eq!(json["status"], serde_json::json!(501));
        }
    }

    /// #79 criteria 1 + 2: the subscribed session-AMBR and default 5QI are applied,
    /// with the configured default as the fallback and NOT the other way round.
    ///
    /// Asserted on `apply_subscribed_baseline` rather than through the create path:
    /// the per-member behaviour is the part that matters, and a whole-struct
    /// replacement would make an absent subscribed member silently mean 0. (The
    /// create path itself is no longer unreachable — #289 gave the crate a UPF
    /// stand-in — but driving it here would assert the merge through two layers
    /// instead of one.)
    #[test]
    fn subscribed_values_win_over_the_config_default_per_member() {
        let subscribed = udm::SubscribedSmData {
            sess_ambr_ul_bps: Some(100_000_000),
            sess_ambr_dl_bps: Some(500_000_000),
            default_5qi: Some(7),
            arp_priority_level: Some(3),
        };
        let mut decision = policy::PolicyDecision::config_default_for_dnn("internet");
        let configured_5qi = decision.def_five_qi;
        decision.apply_subscribed_baseline(&subscribed);
        assert_eq!(decision.sess_ambr_ul_bps, 100_000_000);
        assert_eq!(decision.sess_ambr_dl_bps, 500_000_000);
        assert_eq!(decision.def_five_qi, 7);
        assert_eq!(decision.arp_priority_level, 3);
        assert_ne!(
            decision.def_five_qi, configured_5qi,
            "the subscription must actually displace the configured value"
        );

        // A subscription stating only the AMBR leaves the configured 5QI alone.
        let partial = udm::SubscribedSmData {
            sess_ambr_ul_bps: Some(1_000_000),
            ..Default::default()
        };
        let mut decision = policy::PolicyDecision::config_default_for_dnn("internet");
        let configured_dl = decision.sess_ambr_dl_bps;
        decision.apply_subscribed_baseline(&partial);
        assert_eq!(decision.sess_ambr_ul_bps, 1_000_000);
        assert_eq!(
            decision.sess_ambr_dl_bps, configured_dl,
            "an absent subscribed member must fall back to config, not to 0"
        );
        assert_eq!(decision.def_five_qi, 9);

        // An empty subscription changes nothing at all.
        let mut decision = policy::PolicyDecision::config_default_for_dnn("internet");
        let before = (
            decision.sess_ambr_ul_bps,
            decision.sess_ambr_dl_bps,
            decision.def_five_qi,
            decision.arp_priority_level,
        );
        decision.apply_subscribed_baseline(&udm::SubscribedSmData::default());
        assert_eq!(
            (
                decision.sess_ambr_ul_bps,
                decision.sess_ambr_dl_bps,
                decision.def_five_qi,
                decision.arp_priority_level
            ),
            before
        );
    }

    /// #78 criteria 1 + 2: Retrieve answers 200 with a body that deserialises as
    /// `SmContextRetrievedData`, INCLUDING the required `ueEpsPdnConnection`.
    ///
    /// Before #78 the create handler registered nothing, so this path answered
    /// `404 CONTEXT_NOT_FOUND` for a session that had just been created.
    #[tokio::test]
    async fn retrieve_answers_200_with_ue_eps_pdn_connection() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let reference = seed_registered_session("imsi-001010000000078", 7, "internet");

        let resp = handle_sm_context_retrieve(&reference).await;
        assert_eq!(resp.status, 200, "a registered session must be retrievable");
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("json");
        assert_eq!(body["smContextRef"], serde_json::json!(reference));
        assert_eq!(body["pduSessionId"], serde_json::json!(7));
        assert_eq!(body["dnn"], serde_json::json!("internet"));
        assert_eq!(body["upCnxState"], serde_json::json!("ACTIVATED"));

        // The required member, and it must decode to something derived from the
        // session rather than be a placeholder.
        let encoded = body["ueEpsPdnConnection"]
            .as_str()
            .expect("ueEpsPdnConnection is a required member of SmContextRetrievedData");
        use base64::Engine as _;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("ueEpsPdnConnection must be valid base64");
        // APN length prefix, then the APN, then PDN type, address, QCI.
        assert_eq!(decoded[0] as usize, "internet".len());
        assert_eq!(&decoded[1..9], b"internet");
        assert_eq!(decoded[9], 1, "IPv4 PDN type");
        assert_eq!(&decoded[10..14], &[10, 45, 0, 2], "the UE address");
        assert_eq!(decoded[14], 9, "the default bearer QCI");
    }

    /// #78 criterion 3: Retrieve of an unknown ref is 404 with a ProblemDetails —
    /// at `application/problem+json`, not the bare status/cause pair at
    /// `application/json` it used to send.
    #[tokio::test]
    async fn retrieve_of_an_unknown_ref_is_404_problem_details() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        smf_context_init(64, 256, 512);
        let resp = handle_sm_context_retrieve("no-such-ref-78").await;
        assert_eq!(resp.status, 404);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("json");
        assert_eq!(body["status"], serde_json::json!(404));
        assert_eq!(body["cause"], serde_json::json!("CONTEXT_NOT_FOUND"));
        assert!(
            body["detail"].is_string(),
            "a ProblemDetails must carry a detail a consumer can log"
        );
    }

    /// #78 criterion 3: Update on an unknown ref is 404 + ProblemDetails, and on a
    /// KNOWN ref still succeeds. Both halves matter — a version that 404s
    /// everything would satisfy the first alone.
    #[tokio::test]
    async fn update_rejects_an_unknown_ref_and_still_serves_a_known_one() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let reference = seed_registered_session("imsi-001010000000079", 9, "internet");

        let unknown = SbiRequest::post("/nsmf-pdusession/v1/sm-contexts/nope-78/modify").with_body(
            serde_json::json!({ "upCnxState": "ACTIVATED" }).to_string(),
            "application/json",
        );
        let resp = handle_sm_context_update("nope-78", &unknown).await;
        assert_eq!(
            resp.status, 404,
            "an Update that blindly returns 200 masks lost state"
        );
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("json");
        assert_eq!(body["cause"], serde_json::json!("CONTEXT_NOT_FOUND"));

        let known = SbiRequest::post("/nsmf-pdusession/v1/sm-contexts/x/modify").with_body(
            serde_json::json!({ "upCnxState": "ACTIVATED" }).to_string(),
            "application/json",
        );
        let resp = handle_sm_context_update(&reference, &known).await;
        assert_eq!(resp.status, 200, "a known ref must still be served");
    }

    /// #78 criterion 4: Release on an unknown ref is 404 + ProblemDetails, and a
    /// known one parses `SmContextReleaseData` and answers 204.
    #[tokio::test]
    async fn release_rejects_an_unknown_ref_and_parses_release_data() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let reference = seed_registered_session("imsi-001010000000080", 3, "internet");

        let unknown = SbiRequest::post("/nsmf-pdusession/v1/sm-contexts/gone-78/release")
            .with_body(
                serde_json::json!({ "cause": "REL_DUE_TO_UE_REQ" }).to_string(),
                "application/json",
            );
        let resp = handle_sm_context_release("gone-78", Some(&unknown)).await;
        assert_eq!(
            resp.status, 404,
            "releasing a context the SMF does not hold must not answer 204"
        );

        // A real SmContextReleaseData body on a known ref.
        let known = SbiRequest::post("/nsmf-pdusession/v1/sm-contexts/x/release").with_body(
            serde_json::json!({
                "cause": "REL_DUE_TO_UE_REQ",
                "vsmfReleaseOnly": false,
            })
            .to_string(),
            "application/json",
        );
        let resp = handle_sm_context_release(&reference, Some(&known)).await;
        assert_eq!(resp.status, 204);
        assert!(
            !sm_context_exists(&reference),
            "and the context must actually be gone afterwards"
        );
    }

    /// `SmContextReleaseData` members are read. Every member is optional in the
    /// yaml, so an empty body must still parse — refusing it would break the AMF
    /// path that sends none.
    #[test]
    fn sm_context_release_data_parses_its_members_and_an_empty_body() {
        let with_members = SbiRequest::post("/x").with_body(
            serde_json::json!({
                "cause": "REL_DUE_TO_SLICE_NOT_AVAILABLE",
                "vsmfReleaseOnly": true,
            })
            .to_string(),
            "application/json",
        );
        let parsed = parse_sm_context_release_data(&with_members);
        assert_eq!(
            parsed.cause.as_deref(),
            Some("REL_DUE_TO_SLICE_NOT_AVAILABLE")
        );
        assert!(parsed.vsmf_release_only);

        let empty = SbiRequest::post("/x").with_body("{}".to_string(), "application/json");
        let parsed = parse_sm_context_release_data(&empty);
        assert_eq!(parsed.cause, None);
        assert!(!parsed.vsmf_release_only);
        assert!(parsed.n2_sm_info.is_none());
    }

    /// #78 criterion 5: an Update carrying `HANDOVER_REQUIRED` with an `hoState` is
    /// processed rather than refused with 400, and the handover states move the way
    /// TS 29.502 §5.2.2.3.4 describes.
    ///
    /// PREPARING and PREPARED must NOT touch the user plane: until the UE has moved
    /// the source gNB is still serving it, so re-pointing the UPF would black-hole
    /// downlink traffic for the whole execution window. The test asserts the state
    /// answers, which is the observable that distinguishes "handled" from
    /// "rejected".
    #[tokio::test]
    async fn n2_handover_states_are_processed_not_refused() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let reference = seed_registered_session("imsi-001010000000081", 5, "internet");

        for (info_type, requested, expected) in [
            ("HANDOVER_REQUIRED", "PREPARING", "PREPARING"),
            ("HANDOVER_REQ_ACK", "PREPARED", "PREPARED"),
            ("HANDOVER_CANCEL", "CANCELLED", "CANCELLED"),
        ] {
            let req = SbiRequest::post("/nsmf-pdusession/v1/sm-contexts/x/modify").with_body(
                serde_json::json!({
                    "n2SmInfoType": info_type,
                    "hoState": requested,
                })
                .to_string(),
                "application/json",
            );
            let resp = handle_sm_context_update(&reference, &req).await;
            assert_eq!(
                resp.status, 200,
                "{info_type} must be processed, not answered 400"
            );
            let body: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("json");
            assert_eq!(
                body["hoState"],
                serde_json::json!(expected),
                "{info_type} must drive the §5.2.2.3.4 state"
            );
        }

        // And the session survives every one of them: a handover that dropped the
        // context would be worse than one that was refused.
        assert!(sm_context_exists(&reference));
    }

    /// A HANDOVER_COMPLETE with no decodable target endpoint still completes, and
    /// says so. Asserted because the alternative — a bare 200 — would leave an
    /// operator unable to tell a switched tunnel from an unswitched one.
    #[tokio::test]
    async fn handover_complete_without_a_target_endpoint_still_completes() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        let reference = seed_registered_session("imsi-001010000000082", 6, "internet");
        let req = SbiRequest::post("/nsmf-pdusession/v1/sm-contexts/x/modify").with_body(
            serde_json::json!({
                "n2SmInfoType": "HANDOVER_COMPLETE",
                "hoState": "COMPLETED",
            })
            .to_string(),
            "application/json",
        );
        let resp = handle_sm_context_update(&reference, &req).await;
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("json");
        assert_eq!(body["hoState"], serde_json::json!("COMPLETED"));
    }

    /// #78 criterion 7: create → retrieve → update → release, asserting each status
    /// and body, against the REAL request router rather than the handlers directly.
    ///
    /// The create leg is driven by seeding a registered session rather than by a
    /// full `POST /sm-contexts`, because a real create needs a PFCP-responding UPF
    /// this harness does not have (no existing test establishes an N4 session
    /// either). What is end-to-end here is the lifecycle of a *registered* context
    /// through the router: the create handler's registration is covered separately
    /// by `retrieve_answers_200_with_ue_eps_pdn_connection`, which fails without it.
    #[tokio::test]
    async fn the_sm_context_lifecycle_round_trips_through_the_router() {
        let reference = seed_registered_session("imsi-001010000000083", 4, "internet");

        // Retrieve
        let resp = smf_sbi_request_handler(SbiRequest::post(format!(
            "/nsmf-pdusession/v1/sm-contexts/{reference}/retrieve"
        )))
        .await;
        assert_eq!(resp.status, 200, "retrieve through the router");
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("json");
        assert!(body["ueEpsPdnConnection"].is_string());

        // Update
        let resp = smf_sbi_request_handler(
            SbiRequest::post(format!(
                "/nsmf-pdusession/v1/sm-contexts/{reference}/modify"
            ))
            .with_body(
                serde_json::json!({ "upCnxState": "ACTIVATED" }).to_string(),
                "application/json",
            ),
        )
        .await;
        assert_eq!(resp.status, 200, "update through the router");

        // Release
        let resp = smf_sbi_request_handler(
            SbiRequest::post(format!(
                "/nsmf-pdusession/v1/sm-contexts/{reference}/release"
            ))
            .with_body(
                serde_json::json!({ "cause": "REL_DUE_TO_UE_REQ" }).to_string(),
                "application/json",
            ),
        )
        .await;
        assert_eq!(resp.status, 204, "release through the router");

        // And it is gone: a second retrieve is 404, not a stale 200.
        let resp = smf_sbi_request_handler(SbiRequest::post(format!(
            "/nsmf-pdusession/v1/sm-contexts/{reference}/retrieve"
        )))
        .await;
        assert_eq!(
            resp.status, 404,
            "a released context must not still be retrievable"
        );
    }

    /// A wire-format PFCP Session Report Request carrying a Downlink Data Report
    /// (TS 29.244 §7.5.8), so the DLDR path can be driven exactly as a UPF would.
    ///
    /// IEs: Report Type (39) with the DLDR bit, then Downlink Data Report (83)
    /// containing PDR ID (56) and Downlink Data Service Information (45) whose flags
    /// mark the QFI present.
    fn dldr_report_packet(seid: u64, qfi: u8) -> Vec<u8> {
        fn ie(t: u16, v: &[u8]) -> Vec<u8> {
            let mut out = t.to_be_bytes().to_vec();
            out.extend_from_slice(&(v.len() as u16).to_be_bytes());
            out.extend_from_slice(v);
            out
        }
        let mut body = Vec::new();
        // Report Type: bit 0 = DLDR.
        body.extend_from_slice(&ie(39, &[0x01]));
        let mut dldr = Vec::new();
        dldr.extend_from_slice(&ie(56, &1u16.to_be_bytes()));
        // Downlink Data Service Information: flags 0x02 = QFI present, no PPI.
        dldr.extend_from_slice(&ie(45, &[0x02, qfi]));
        body.extend_from_slice(&ie(83, &dldr));
        pfcp_path::encode_wire_message(56, Some(seid), 1, &body)
    }

    /// #78 criterion 6: a DLDR for a deactivated connection emits an OUTBOUND
    /// `Namf_Communication_N1N2MessageTransfer` — asserted by observing the HTTP
    /// request at a fake AMF, not by checking a log line or the
    /// `trigger_service_request` flag, both of which the issue explicitly rules out.
    #[tokio::test]
    async fn a_downlink_data_report_pages_the_ue_via_the_amf() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        // Drives production peer-call code against a loopback PLAINTEXT peer, i.e. a
        // dev-profile deployment. Declared rather than inherited: the default
        // `SbiProfile` is Production, which would refuse the plaintext connection and
        // make this test fail for a reason unrelated to what it asserts.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        use nextgcore_sbi::message::SbiResponse;
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};

        let seen: std::sync::Arc<std::sync::Mutex<Vec<(String, String, String)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = seen.clone();
        let port = nextgcore_sbi::test_support::free_port();
        let amf = SbiServer::new(SbiServerConfig::new(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            port,
        ))));
        amf.start(move |req: SbiRequest| {
            let sink = sink.clone();
            async move {
                sink.lock().unwrap_or_else(|e| e.into_inner()).push((
                    req.header.method.clone(),
                    req.header.uri.clone(),
                    req.http.content.clone().unwrap_or_default(),
                ));
                SbiResponse::with_status(200)
            }
        })
        .await
        .expect("amf start");

        // A session with a DEACTIVATED user plane and a serving-AMF URI.
        let supi = "imsi-001010000000084";
        let reference = seed_registered_session(supi, 8, "internet");
        let amf_uri = format!("http://127.0.0.1:{port}");
        let seid = {
            let ctx = smf_self();
            let context = ctx.read().expect("context");
            let mut sess = context
                .sess_find_by_sm_context_ref(&reference)
                .expect("session");
            sess.up_cnx_state = context::UpCnxState::Deactivated;
            sess.sm_context_status_uri = Some(amf_uri.clone());
            context.sess_update(&sess);
            sess.smf_n4_seid
        };

        // Drive the REAL PFCP Session Report path with a wire-format DLDR, not
        // `trigger_network_initiated_service_request` directly.
        //
        // The first version of this test called the helper, and a revert pass showed
        // it still passed with the call REMOVED from the DLDR handler — "the helper
        // is tested and the wiring is not", which is precisely the hazard #78's
        // criterion 6 names when it says to assert the outbound call rather than the
        // log line or the flag.
        let upf = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("fake UPF socket");
        let smf_sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("smf socket");
        let upf_addr = upf.local_addr().expect("upf addr");
        handle_pfcp_session_report(&smf_sock, &dldr_report_packet(seid, 5), upf_addr).await;

        let requests = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let paging = requests
            .iter()
            .find(|(_, uri, _)| uri.contains("/n1-n2-messages"))
            .expect("a DLDR must emit an N1N2MessageTransfer toward the AMF");
        assert_eq!(paging.0, "POST");
        assert!(
            paging.1.contains(supi),
            "addressed to the UE's own ue-context, got {}",
            paging.1
        );
        let body: serde_json::Value = serde_json::from_str(&paging.2).expect("json body");
        assert_eq!(body["pduSessionId"], serde_json::json!(8));
        // The N2 form, not the N1 form: the point is to re-establish the user
        // plane, and there is no NAS message to deliver to a sleeping UE.
        assert_eq!(
            body["n2InfoContainer"]["n2InformationClass"],
            serde_json::json!("SM"),
            "paging carries n2InfoContainer, not n1MessageContainer"
        );
        assert!(
            body["n1MessageContainer"].is_null(),
            "there is no NAS message to deliver for a network-triggered service request"
        );
        assert_eq!(
            body["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapData"]["qfi"],
            serde_json::json!(5),
            "the reported QFI must reach the AMF so the gNB knows which flow to restore"
        );

        amf.stop().await.expect("stop");
    }

    /// The other half: a DLDR for a session whose user plane is UP must NOT page.
    /// TS 29.244 §7.5.8.2 scopes the report to a *deactivated* connection, and
    /// paging a connected UE is a spurious service request. Without this, "a DLDR
    /// pages" would be satisfied by a version that pages unconditionally.
    #[tokio::test]
    async fn a_downlink_data_report_for_an_active_connection_does_not_page() {
        let _state = crate::context::PROCESS_STATE_TEST_LOCK.lock().await;
        // Drives production peer-call code against a loopback PLAINTEXT peer, i.e. a
        // dev-profile deployment. Declared rather than inherited: the default
        // `SbiProfile` is Production, which would refuse the plaintext connection and
        // make this test fail for a reason unrelated to what it asserts.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        use nextgcore_sbi::message::SbiResponse;
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};

        let seen: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = seen.clone();
        let port = nextgcore_sbi::test_support::free_port();
        let amf = SbiServer::new(SbiServerConfig::new(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            port,
        ))));
        amf.start(move |req: SbiRequest| {
            let sink = sink.clone();
            async move {
                sink.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(req.header.uri.clone());
                SbiResponse::with_status(200)
            }
        })
        .await
        .expect("amf start");

        let reference = seed_registered_session("imsi-001010000000085", 2, "internet");
        let seid = {
            let ctx = smf_self();
            let context = ctx.read().expect("context");
            let mut sess = context
                .sess_find_by_sm_context_ref(&reference)
                .expect("session");
            // ACTIVATED, which `seed_registered_session` already sets.
            sess.sm_context_status_uri = Some(format!("http://127.0.0.1:{port}"));
            context.sess_update(&sess);
            sess.smf_n4_seid
        };

        let upf = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("fake UPF socket");
        let smf_sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("smf socket");
        let upf_addr = upf.local_addr().expect("upf addr");
        handle_pfcp_session_report(&smf_sock, &dldr_report_packet(seid, 1), upf_addr).await;

        assert!(
            seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
            "an active user-plane connection must not be paged"
        );

        amf.stop().await.expect("stop");
    }
}

#[cfg(test)]
mod oauth2_h8_tests {
    //! Wave-6 H8 (Phase B) strict-peer OAuth2 enforcement triplet: the real
    //! `smf_sbi_request_handler` is mounted behind nextgcore-sbi's server-side
    //! OAuth2 verification (TS 33.501 §13.4.1). A missing or wrong-audience
    //! Bearer is rejected (401) before the handler runs; a valid NRF-audience
    //! token (aud=SMF, ES256-signed against the served JWKS) passes through.
    use super::*;
    use nextgcore_sbi::client::SbiClient;
    use nextgcore_sbi::server::SbiServerConfig;
    use nextgcore_sbi::types::NfType;
    use std::time::Duration;

    /// Reserve a loopback port for a test server.
    ///
    /// Delegates to the shared helper: 21 crates each had a private
    /// probe-and-drop copy of this, which is TOCTOU and flaked under parallel
    /// `cargo test`. One implementation means one place to harden.
    fn free_port() -> u16 {
        nextgcore_sbi::test_support::free_port()
    }

    /// Mint an ES256 access token in the NRF's shape, signed by `sk`.
    fn build_es256_token(
        sk: &p256::ecdsa::SigningKey,
        kid: &str,
        aud: &str,
        scope: &str,
    ) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use p256::ecdsa::{signature::Signer, Signature};
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let header = format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{kid}"}}"#);
        let claims = serde_json::json!({
            "iss": "NRF", "sub": "smf-1", "aud": aud,
            "scope": scope, "exp": exp, "iat": 0
        })
        .to_string();
        let h = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let p = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let sig: Signature = sk.sign(format!("{h}.{p}").as_bytes());
        let s = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{h}.{p}.{s}")
    }

    /// Public JWKS for the signing key `sk` under `kid`.
    fn jwks_for(sk: &p256::ecdsa::SigningKey, kid: &str) -> serde_json::Value {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let point = sk.verifying_key().to_encoded_point(false);
        serde_json::json!({"keys":[{
            "kty":"EC","crv":"P-256","use":"sig","alg":"ES256","kid":kid,
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        }]})
    }

    async fn start_server(jwks: serde_json::Value) -> (SbiServer, u16) {
        smf_context_init(64, 256, 512);
        let port = free_port();
        let mut cfg = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(jwks);
        cfg = cfg.with_expected_audience_nf_type(NfType::Smf);
        let server = SbiServer::new(cfg);
        server
            .start(smf_sbi_request_handler)
            .await
            .expect("server start");
        (server, port)
    }

    #[test]
    fn test_oauth2_require_knob_parses_and_defaults_off() {
        let dir = std::env::temp_dir();
        let off = dir.join(format!("smf-h8-off-{}.yaml", std::process::id()));
        std::fs::write(
            &off,
            "smf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n",
        )
        .unwrap();
        assert!(
            !oauth2_required(off.to_str().unwrap()),
            "absent oauth2 block must default off"
        );
        let on = dir.join(format!("smf-h8-on-{}.yaml", std::process::id()));
        std::fs::write(&on, "smf:\n  sbi:\n    oauth2:\n      require: true\n").unwrap();
        assert!(
            oauth2_required(on.to_str().unwrap()),
            "sbi.oauth2.require: true must parse on"
        );
        let _ = std::fs::remove_file(off);
        let _ = std::fs::remove_file(on);
    }

    #[tokio::test]
    async fn test_oauth2_missing_token_rejected_401() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let (server, port) = start_server(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            client.get("/nsmf-pdusession/v1/sm-contexts"),
        )
        .await
        .expect("bounded")
        .expect("response");
        assert_eq!(resp.status, 401, "unauthenticated request must be 401");
        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_oauth2_wrong_audience_rejected_401() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let (server, port) = start_server(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let token = build_es256_token(&sk, "nrf-es256", "UDM", "nsmf-pdusession");
        let req = SbiRequest::get("/nsmf-pdusession/v1/sm-contexts")
            .with_header("Authorization", format!("Bearer {token}"));
        let resp = tokio::time::timeout(Duration::from_secs(5), client.send_request(req))
            .await
            .expect("bounded")
            .expect("response");
        assert_eq!(resp.status, 401, "wrong-audience token must be 401");
        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_oauth2_valid_token_reaches_handler() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let (server, port) = start_server(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let token = build_es256_token(&sk, "nrf-es256", "SMF", "nsmf-pdusession");
        let req = SbiRequest::get("/nsmf-pdusession/v1/sm-contexts/does-not-exist")
            .with_header("Authorization", format!("Bearer {token}"));
        let resp = tokio::time::timeout(Duration::from_secs(5), client.send_request(req))
            .await
            .expect("bounded")
            .expect("response");
        assert_ne!(resp.status, 401, "valid token must not be 401");
        assert_ne!(resp.status, 403, "valid token must not be 403");
        server.stop().await.expect("stop");
    }
}
