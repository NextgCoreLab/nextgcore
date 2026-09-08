//! NextGCore UDM (Unified Data Management)
//!
//! The UDM is a 5G core network function responsible for:
//! - Subscriber data management
//! - Authentication credential processing
//! - Subscription management
//! - UE context management (AMF/SMF registration)

use crate::{
    timer_manager, timer_type_to_timer_id, udm_context_final, udm_context_init, udm_sbi_close,
    udm_sbi_open, udm_self, SbiServerConfig, UdmEeSubscription, UdmEvent, UdmSdmSubscription,
    UdmSmContext,
};
use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::{
    send_bad_request, SbiServer, SbiServerConfig as NextgcoreSbiServerConfig,
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// NextGCore UDM - Unified Data Management
#[derive(Parser, Debug)]
#[command(name = "nextgcore-udmd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Unified Data Management", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/udm.yaml")]
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

    /// SBI server address
    #[arg(long, default_value = "0.0.0.0")]
    sbi_addr: String,

    /// SBI server port
    #[arg(long, default_value = "7777")]
    sbi_port: u16,

    /// Enable TLS
    #[arg(long)]
    tls: bool,

    /// TLS certificate path
    #[arg(long)]
    tls_cert: Option<String>,

    /// TLS key path
    #[arg(long)]
    tls_key: Option<String>,

    /// Maximum number of UEs
    #[arg(long, default_value = "1024")]
    max_ue: usize,

    /// Maximum number of sessions
    #[arg(long, default_value = "4096")]
    max_sess: usize,
}

// ---------------------------------------------------------------------------
// Typed YAML configuration structs for NRF URI seeding
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct NrfClientYaml {
    uri: String,
}

#[derive(Debug, Default, Deserialize)]
struct SbiClientYaml {
    nrf: Option<Vec<NrfClientYaml>>,
}

#[derive(Debug, Default, Deserialize)]
struct SbiServerYaml {
    address: Option<String>,
    port: Option<u16>,
}

/// #85: the operator-configurable parts of the NRF NFProfile, which used to be
/// literals in the profile builder.
#[derive(Debug, Default, Deserialize)]
struct NfProfileYaml {
    /// Seconds between NF heartbeats (TS 29.510 `heartBeatTimer`).
    heartbeat_timer: Option<u32>,
    /// NF types allowed to consume this UDM (TS 29.510 `allowedNfTypes`).
    allowed_nf_types: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
struct SbiYaml {
    server: Option<Vec<SbiServerYaml>>,
    client: Option<SbiClientYaml>,
    /// #85: `udm.sbi.nrf_profile.{heartbeat_timer,allowed_nf_types}`.
    nrf_profile: Option<NfProfileYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct HnetYaml {
    id: u8,
    scheme: u8,
    key: String,
}

/// Wave-6 F-04: operator Steering-of-Roaming config (TS 33.501 §6.14.2.1).
#[derive(Debug, Default, Deserialize)]
struct SorYaml {
    /// TS 29.509 `SteeringContainer` as a `SteeringInfo[]` array — entries of
    /// `{plmnId: {mcc, mnc}, accessTechList: [..]}`. Quote `mcc`/`mnc` so they
    /// stay strings; the AUSF performs the TS 24.501 §9.11.3.51 wire encoding.
    steering: Option<Vec<serde_json::Value>>,
    /// Request the UE acknowledgement (`SorInfo.ackInd`). Default: true.
    ack_ind: Option<bool>,
}

/// Wave-6 F-05: operator UE-Parameters-Update config (TS 33.501 §6.15.2.1).
#[derive(Debug, Default, Deserialize)]
struct UpuYaml {
    /// TS 29.509 `UpuData[]` — entries of `{routingId}`, `{defaultConfNssai:
    /// [{sst, sd?}]}`, `{secPacket}`, disaster-roaming flags, etc. The AUSF
    /// performs the TS 24.501 §9.11.3.53A wire encoding and MAC.
    data: Option<Vec<serde_json::Value>>,
    /// Request the UE acknowledgement (`UpuInfo.upuAckInd`). Default: true.
    ack_ind: Option<bool>,
}

/// Issue #22 NES sleep-policy block (off by default; only read under the
/// `nes` cargo feature).
#[derive(Debug, Default, Deserialize, Clone)]
pub(crate) struct NesYaml {
    pub(crate) enabled: Option<bool>,
    pub(crate) idle_threshold_secs: Option<u64>,
    pub(crate) drain_timeout_secs: Option<u64>,
    pub(crate) poll_interval_secs: Option<u64>,
    /// "suspend" (PATCH nfStatus=SUSPENDED) or "deregister".
    pub(crate) action: Option<String>,
    pub(crate) metrics_port: Option<u16>,
    /// Synthetic power model knobs (documented in docs/NES.md).
    pub(crate) capacity_rps: Option<f64>,
    pub(crate) idle_power_w: Option<f64>,
    pub(crate) max_power_w: Option<f64>,
}

#[derive(Debug, Default, Deserialize)]
struct UdmSection {
    sbi: Option<SbiYaml>,
    /// Issue #22 NES sleep-policy block (only read under the `nes` feature).
    nes: Option<NesYaml>,
    hnet: Option<Vec<HnetYaml>>,
    /// udmd-11: explicitly enable null-scheme SUCI (default: true).
    allow_null_scheme: Option<bool>,
    /// Wave-6 F-04: Steering-of-Roaming steering list (default: none →
    /// byte-identical am-data passthrough).
    sor: Option<SorYaml>,
    /// Wave-6 F-05: UE-Parameters-Update data list (default: none →
    /// byte-identical am-data passthrough).
    upu: Option<UpuYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct UdmYaml {
    udm: Option<UdmSection>,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Issue #22 NES bookkeeping (inert without the `nes` feature): inbound SBI
/// request counter (activity detection) and in-flight tracker (the graceful
/// drain gate).
pub(crate) static NES_REQUESTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub(crate) static NES_IN_FLIGHT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

// ---------------------------------------------------------------------------
// OAuth2 rollout (Wave-6 H8): opt-in producer verification + outbound consumer
// token install. Default OFF so the matched-sim E2E path is byte-unchanged;
// the docker `udm-oauth2.yaml` overlay (or NEXTGCORE_SBI_OAUTH2_REQUIRE=1) sets
// `udm.sbi.oauth2.require: true`. TS 33.501 §13.4.1, TS 29.510 §5.4.2.
// ---------------------------------------------------------------------------

/// Process-wide OAuth2 client for automatic Bearer-token acquisition on
/// outbound SBI calls (installed only when OAuth2 enforcement is enabled).
static OAUTH2_CLIENT: std::sync::OnceLock<Option<Arc<nextgcore_sbi::oauth::OAuth2Client>>> =
    std::sync::OnceLock::new();

/// The shared OAuth2 client, if SBI OAuth2 enforcement is enabled (Wave-6 H8
/// Phase A). Outbound SBI clients attach a token via [`peer_client`].
pub(crate) fn oauth2_client() -> Option<Arc<nextgcore_sbi::oauth::OAuth2Client>> {
    OAUTH2_CLIENT.get().and_then(|opt| opt.clone())
}

/// Build an outbound peer SBI client for `host:port` (Wave-6 H8 Phase A).
///
/// When OAuth2 enforcement is ON, returns a fresh client carrying an NRF-issued
/// Bearer token scoped to `target` (TS 33.501 §13.4.1, TS 29.510 §5.4.2). When
/// OFF (the default), returns the process-wide pooled client unchanged, so the
/// matched-sim default path is byte-identical.
pub(crate) async fn peer_client(
    host: &str,
    port: u16,
    target: nextgcore_sbi::types::NfType,
) -> Arc<nextgcore_sbi::client::SbiClient> {
    match oauth2_client() {
        Some(oauth2) => Arc::new(
            nextgcore_sbi::client::SbiClient::new(nextgcore_sbi::security::sbi_peer_client_config(
                host, port,
            ))
            .with_oauth2(oauth2, target),
        ),
        None => {
            nextgcore_sbi::context::global_context()
                .get_client(host, port)
                .await
        }
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
/// NRF JWKS and requires `aud` to include NfType::Udm; with no NRF URI
/// configured it fails closed (503, per nextgcore-sbi server.rs).
async fn apply_oauth2_enforcement(mut cfg: NextgcoreSbiServerConfig) -> NextgcoreSbiServerConfig {
    let nrf_uri = nextgcore_sbi::context::global_context().get_nrf_uri().await;
    cfg.require_oauth2 = true;
    cfg.oauth2_jwks_uri = nrf_uri.as_deref().map(|uri| {
        nextgcore_sbi::oauth::JwksCache::for_nrf(uri)
            .jwks_uri()
            .to_string()
    });
    cfg = cfg.with_expected_audience_nf_type(nextgcore_sbi::types::NfType::Udm);
    if let Some(uri) = nrf_uri.as_deref() {
        let nf_instance_id = format!("udm-{}", uuid::Uuid::new_v4());
        let _ = OAUTH2_CLIENT.set(Some(Arc::new(nextgcore_sbi::oauth::OAuth2Client::new(
            uri,
            nf_instance_id,
            nextgcore_sbi::types::NfType::Udm,
        ))));
    }
    log::info!(
        "OAuth2 enforcement enabled (JWKS: {})",
        cfg.oauth2_jwks_uri.as_deref().unwrap_or("UNCONFIGURED")
    );
    cfg
}

#[tokio::main]
pub async fn run() -> Result<()> {
    let mut args = Args::parse();

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

    log::info!("NextGCore UDM v{} starting...", env!("CARGO_PKG_VERSION"));

    // Issue: `--kill` was advertised as "Kill running instance" and did
    // NOTHING -- it logged an intention and returned success, so the process
    // exited 0 while the instance kept serving. Fail loudly instead.
    if args.kill {
        return Err(nextgcore_core::signal::kill_unsupported().into());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize UDM context
    udm_context_init(args.max_ue, args.max_sess);
    log::info!(
        "UDM context initialized (max_ue={}, max_sess={})",
        args.max_ue,
        args.max_sess
    );

    // Initialize UDM state machine
    let mut udm_sm = UdmSmContext::new();
    udm_sm.init();
    log::info!("UDM state machine initialized");

    // Parse configuration (if file exists) and seed NRF URI
    #[cfg(feature = "nes")]
    let mut nes_yaml: Option<NesYaml> = None;
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
        match std::fs::read_to_string(&args.config) {
            Ok(content) => {
                log::debug!("Configuration file loaded ({} bytes)", content.len());
                // Seed NRF URI into SBI context for NF registration
                if let Ok(yaml) = serde_yaml::from_str::<UdmYaml>(&content) {
                    if let Some(udm) = yaml.udm {
                        #[cfg(feature = "nes")]
                        {
                            nes_yaml = udm.nes.clone();
                        }
                        if let Some(sbi) = udm.sbi {
                            // Override the advertised/bind SBI address with the
                            // routable address from config so the NRF NFProfile
                            // advertises a reachable endpoint (not 0.0.0.0).
                            if let Some(server) = sbi.server.as_ref().and_then(|s| s.first()) {
                                if let Some(addr) = &server.address {
                                    args.sbi_addr = addr.clone();
                                }
                                if let Some(port) = server.port {
                                    args.sbi_port = port;
                                }
                            }
                            if let Some(client) = sbi.client {
                                if let Some(nrf_list) = client.nrf {
                                    if let Some(nrf) = nrf_list.first() {
                                        log::info!("NRF URI configured: {}", nrf.uri);
                                        nextgcore_sbi::context::global_context()
                                            .set_nrf_uri(&nrf.uri)
                                            .await;
                                    }
                                }
                            }
                            // #85: NFProfile knobs from config. An absent block
                            // or member keeps the historical default, so an
                            // unconfigured deployment registers unchanged.
                            if let Some(profile) = sbi.nrf_profile {
                                let mut config = crate::context::NfProfileConfig::default();
                                if let Some(timer) = profile.heartbeat_timer {
                                    config.heart_beat_timer = timer;
                                }
                                if let Some(types) =
                                    profile.allowed_nf_types.filter(|t| !t.is_empty())
                                {
                                    config.allowed_nf_types = types;
                                }
                                let ctx = udm_self();
                                if let Ok(context) = ctx.read() {
                                    log::info!(
                                        "NFProfile configured (heartBeatTimer={}, allowedNfTypes={:?})",
                                        config.heart_beat_timer,
                                        config.allowed_nf_types
                                    );
                                    context.set_nf_profile_config(config);
                                };
                            }
                        }
                        // udmd-11: null-scheme SUCI gating (default: true).
                        if let Some(allow) = udm.allow_null_scheme {
                            let ctx = udm_self();
                            if let Ok(context) = ctx.read() {
                                context.set_allow_null_scheme(allow);
                                log::info!(
                                    "Null-scheme SUCI: {}",
                                    if allow { "allowed" } else { "denied" }
                                );
                            };
                        }

                        // Wave-6 F-04: provision the Steering-of-Roaming list
                        // (TS 33.501 §6.14.2.1). Absent/empty → am-data
                        // passthrough is byte-identical (default-safe).
                        if let Some(sor) = udm.sor {
                            if let Some(steering) = sor.steering.filter(|s| !s.is_empty()) {
                                let entries = steering.len();
                                let ack_ind = sor.ack_ind.unwrap_or(true);
                                let ctx = udm_self();
                                if let Ok(context) = ctx.read() {
                                    context.set_sor_steering(crate::context::SorSteeringConfig {
                                        steering_container: serde_json::Value::Array(steering),
                                        ack_ind,
                                    });
                                    log::info!(
                                        "SoR steering provisioned ({entries} PLMN \
                                         entries, ackInd={ack_ind})"
                                    );
                                };
                            }
                        }

                        // Wave-6 F-05: provision the UE-Parameters-Update list
                        // (TS 33.501 §6.15.2.1). Absent/empty → am-data
                        // passthrough is byte-identical (default-safe).
                        if let Some(upu) = udm.upu {
                            if let Some(data) = upu.data.filter(|d| !d.is_empty()) {
                                let entries = data.len();
                                let ack_ind = upu.ack_ind.unwrap_or(true);
                                let ctx = udm_self();
                                if let Ok(context) = ctx.read() {
                                    context.set_upu_config(crate::context::UpuConfig {
                                        upu_data_list: serde_json::Value::Array(data),
                                        ack_ind,
                                    });
                                    log::info!(
                                        "UPU data provisioned ({entries} UpuData \
                                         entries, ackInd={ack_ind})"
                                    );
                                };
                            }
                        }

                        // Provision home network keys for SUCI deconcealment
                        // (TS 33.501 §6.12). The `key` value is either a hex
                        // string or a path to a file containing the hex key.
                        if let Some(hnet) = udm.hnet {
                            for entry in hnet {
                                match load_hnet_key(&entry.key) {
                                    Some(key) => {
                                        let ctx = udm_self();
                                        if let Ok(context) = ctx.read() {
                                            context.hnet_key_add(entry.id, entry.scheme, key);
                                        };
                                    }
                                    None => {
                                        log::warn!(
                                            "hnet key id={} scheme={} could not be loaded \
                                             from '{}' (expected 64 hex chars inline or in file); \
                                             SUCIs using this key will be rejected",
                                            entry.id,
                                            entry.scheme,
                                            entry.key
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to read configuration file: {e}");
            }
        }
    } else {
        log::debug!("Configuration file not found: {}", args.config);
    }

    // Build SBI server configuration (legacy, for context)
    let sbi_config = SbiServerConfig {
        addr: args.sbi_addr.clone(),
        port: args.sbi_port,
        tls_enabled: args.tls,
        tls_cert: args.tls_cert.clone(),
        tls_key: args.tls_key.clone(),
    };

    // Open legacy SBI server (for context initialization)
    udm_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;

    // Start actual HTTP/2 SBI server using nextgcore-sbi
    let sbi_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let mut sbi_server_config = NextgcoreSbiServerConfig::new(sbi_addr);
    // Issue #63: resolve the SBI security profile, PRODUCTION by default. The
    // production profile requires OAuth2, so the outbound token client is
    // installed too -- a producer that demands tokens must also present them.
    let sbi_profile = nextgcore_sbi::security::SbiProfile::resolve();
    if sbi_profile.is_production() || oauth2_required(&args.config) {
        sbi_server_config = apply_oauth2_enforcement(sbi_server_config).await;
    }
    let nrf_uri = nextgcore_sbi::context::global_context()
        .get_nrf_uri()
        .await
        .unwrap_or_default();
    sbi_server_config = nextgcore_sbi::security::apply_sbi_security_profile(
        sbi_server_config,
        sbi_profile,
        nextgcore_sbi::types::NfType::Udm,
        &nrf_uri,
    )?;
    let sbi_server = SbiServer::new(sbi_server_config);

    sbi_server
        .start(udm_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    log::info!("SBI HTTP/2 server listening on {sbi_addr}");

    // Register with NRF and start heartbeat worker
    match register_with_nrf(&args.sbi_addr, args.sbi_port).await {
        Ok(nf_instance_id) if !nf_instance_id.is_empty() => {
            // Issue #22 NES (off by default): idle->drain->suspend runtime.
            #[cfg(feature = "nes")]
            crate::nes_driver::spawn_if_enabled(
                nes_yaml
                    .as_ref()
                    .map(crate::nes_driver::NesSettings::from_yaml),
                nf_instance_id.clone(),
                args.sbi_addr.clone(),
                args.sbi_port,
            );
            // G2-2: PATCH a real NFProfile "/load" gauge to NRF each heartbeat
            // (registered UEs vs configured capacity; TS 29.510 §5.2.2.3.2).
            nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(nf_instance_id, 5, || {
                let ctx = udm_self();
                let load = ctx.read().map(|c| c.get_ue_load()).unwrap_or(0);
                load.clamp(0, 100) as u8
            });
        }
        Ok(_) => {}
        Err(e) => {
            log::warn!("NRF registration failed (will operate without NRF): {e}");
        }
    }

    log::info!("NextGCore UDM ready");

    // Main event loop (async)
    run_event_loop_async(&mut udm_sm, shutdown).await?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Stop SBI server
    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;
    log::info!("SBI HTTP/2 server stopped");

    // Close legacy SBI server
    udm_sbi_close();
    log::info!("SBI server closed");

    // Cleanup state machine
    udm_sm.fini();
    log::info!("UDM state machine finalized");

    // Cleanup context
    udm_context_final();
    log::info!("UDM context finalized");

    log::info!("NextGCore UDM stopped");
    Ok(())
}

/// SBI request handler for UDM
pub async fn udm_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    // Issue #22 NES bookkeeping (inert without the `nes` feature): count
    // inbound activity and track in-flight work for the graceful drain.
    NES_REQUESTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // RAII guard (issue #22 review fix): the decrement must run on EVERY
    // exit path — normal completion, panic-unwind (caught by the SBI
    // server), and future-drop on client cancellation — or the NES drain
    // gate never reaches zero and sleep is permanently blocked.
    struct InFlightGuard;
    impl Drop for InFlightGuard {
        fn drop(&mut self) {
            NES_IN_FLIGHT.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    NES_IN_FLIGHT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let _guard = InFlightGuard;
    udm_sbi_route(request).await
}

/// Every Nudm service name TS 29.503 §5 defines, in the order of the spec.
///
/// The UDM answers on all ten: SDM, UECM, UEAU, EE, PP and MT are served, and
/// NIDDAuthorisation, RSDS, SSAU and UEID answer `501` on their defined
/// operations. A service name that is not in this list is not a Nudm service, so
/// its URI names no resource here and the answer is `404`
/// `RESOURCE_URI_NOT_FOUND` — never `405`, which would claim the service exists
/// and only the method was wrong (#85).
pub(crate) const NUDM_SERVICE_NAMES: [&str; 10] = [
    "nudm-sdm",
    "nudm-uecm",
    "nudm-ueau",
    "nudm-ee",
    "nudm-pp",
    "nudm-mt",
    "nudm-niddau",
    "nudm-rsds",
    "nudm-ssau",
    "nudm-ueid",
];

/// Answer a request that matched no dispatch arm.
///
/// `allowed` is `Some(methods)` when the URI *does* name a resource this UDM
/// serves — the request only used the wrong method, so the answer is `405` with
/// the mandatory `Allow` header (RFC 9110 §15.5.6, TS 29.500 §5.2.7.1). It is
/// `None` when the URI names nothing, which is `404 RESOURCE_URI_NOT_FOUND`.
///
/// Collapsing both into `405 METHOD_NOT_ALLOWED`, as the router did before #85,
/// tells a consumer that every mistyped path is a supported resource.
fn unmatched(allowed: Option<&[&str]>, method: &str, uri: &str) -> SbiResponse {
    match allowed {
        Some(methods) => {
            log::debug!("UDM: {method} not allowed for {uri} (allow: {methods:?})");
            nextgcore_sbi::server::send_method_not_allowed_with_allow(method, uri, methods)
        }
        None => {
            log::warn!("UDM: no resource at {uri}");
            nextgcore_sbi::server::send_resource_uri_not_found(uri)
        }
    }
}

/// Route an inbound SBI request to the UDM service handlers.
async fn udm_sbi_route(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("UDM SBI request: {method} {uri}");

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    // Route based on service and resource
    // Expected paths:
    // - /nudm-uecm/v1/{supi}/registrations/amf-3gpp-access
    // - /nudm-uecm/v1/{supi}/registrations/smf-registrations/{pduSessionId}
    // - /nudm-sdm/v2/{supi}/am-data          (Nudm_SDM is v2, TS 29.503 6.1.1)
    // - /nudm-sdm/v2/{supi}/smf-select-data
    // - /nudm-sdm/v2/{supi}/sm-data
    // - /nudm-sdm/v2/{ueId}/id-translation-result
    // - /nudm-ueau/v1/{supi}/security-information/generate-auth-data
    // - /nudm-pp/v1/{ueId}/pp-data
    // - /nudm-mt/v1/{supi}

    if parts.len() < 3 {
        return unmatched(None, method, uri);
    }

    let service = parts[0];
    let _version = parts[1];

    match service {
        "nudm-uecm" => route_nudm_uecm(&parts, method, &request, uri).await,
        "nudm-sdm" => route_nudm_sdm(&parts, method, &request, uri).await,
        "nudm-ueau" => route_nudm_ueau(&parts, method, &request, uri).await,
        "nudm-ee" => route_nudm_ee(&parts, method, &request, uri).await,
        "nudm-pp" => route_nudm_pp(&parts, method, &request, uri).await,
        "nudm-mt" => route_nudm_mt(&parts, method, &request, uri).await,
        // Defined by TS 29.503 but not implemented here: the operation is
        // recognised and answered 501, so a consumer can tell "this UDM does not
        // do that yet" from "that is not a Nudm operation".
        "nudm-niddau" | "nudm-rsds" | "nudm-ssau" | "nudm-ueid" => {
            route_nudm_unimplemented(service, &parts, method, uri)
        }
        _ => unmatched(None, method, uri),
    }
}

/// Methods the `nudm-uecm` resource at `parts` supports, or `None` when the path
/// names no UECM resource this UDM serves.
fn uecm_allowed_methods(parts: &[&str]) -> Option<&'static [&'static str]> {
    if parts.get(3).copied()? != "registrations" {
        return None;
    }
    let sub = parts.get(4).copied().unwrap_or("");
    let tail = parts.get(5).copied().unwrap_or("");
    if parts.len() > 6 {
        return None;
    }
    match sub {
        "amf-3gpp-access" | "amf-non-3gpp-access" => match tail {
            "" => Some(&["PUT", "PATCH", "GET"]),
            "dereg-amf" | "pei-update" | "roaming-info-update" => Some(&["POST"]),
            _ => None,
        },
        "smsf-3gpp-access" | "smsf-non-3gpp-access" if tail.is_empty() => {
            Some(&["PUT", "GET", "DELETE"])
        }
        "smf-registrations" => {
            if tail.is_empty() {
                Some(&["GET"])
            } else {
                Some(&["PUT", "GET", "DELETE"])
            }
        }
        "ip-sm-gw" if tail.is_empty() => Some(&["PUT", "GET", "DELETE"]),
        "location" if tail.is_empty() => Some(&["GET"]),
        "send-routing-info-sm" if tail.is_empty() => Some(&["POST"]),
        _ => None,
    }
}

/// UE Context Management Service (nudm-uecm, TS 29.503 §5.3).
async fn route_nudm_uecm(
    parts: &[&str],
    method: &str,
    request: &SbiRequest,
    uri: &str,
) -> SbiResponse {
    let supi = parts.get(2).copied().unwrap_or("");
    if parts.get(3).copied() == Some("registrations") && !supi.is_empty() {
        return route_uecm_registrations(supi, parts, method, request, uri).await;
    }
    unmatched(uecm_allowed_methods(parts), method, uri)
}

/// Methods the `nudm-sdm` resource at `parts` supports, or `None` when the path
/// names no SDM resource this UDM serves.
///
/// The many SDM data sets this UDM does not serve (`trace-data`, `sms-data`,
/// `lcs-*`, `v2x-data`, ...) are deliberately absent: they are #226's to add as
/// real resources, and until then their URIs name nothing here.
fn sdm_allowed_methods(parts: &[&str]) -> Option<&'static [&'static str]> {
    // #226: the whole-UE resource `/nudm-sdm/v2/{supi}` has no 4th part. It IS a
    // resource this UDM serves, so a non-GET on it must be 405 with an Allow
    // header rather than 404 — the distinction #85 introduced.
    let Some(resource) = parts.get(3).copied() else {
        return if parts.len() == 3 && !parts[2].is_empty() {
            Some(&["GET"])
        } else {
            None
        };
    };
    let tail = parts.get(4).copied().unwrap_or("");
    if parts.len() > 5 {
        return None;
    }
    match resource {
        "am-data" => match tail {
            "" => Some(&["GET"]),
            "sor-ack" | "upu-ack" => Some(&["PUT"]),
            _ => None,
        },
        // #226: every TS 29.503 per-SUPI SDM data set this UDM routes. The three
        // with a `udrd` provisioned-data source return data; the rest relay the
        // UDR's 404 rather than a 501 this router invented.
        "smf-select-data"
        | "sm-data"
        | "nssai"
        | "id-translation-result"
        | "ue-context-in-amf-data"
        | "ue-context-in-smf-data"
        | "ue-context-in-smsf-data"
        | "sms-data"
        | "sms-mng-data"
        | "trace-data"
        | "lcs-privacy-data"
        | "lcs-mo-data"
        | "lcs-bca-data"
        | "v2x-data"
        | "prose-data"
        | "mbs-data"
        | "uc-data"
            if tail.is_empty() =>
        {
            Some(&["GET"])
        }
        "sdm-subscriptions" => {
            if tail.is_empty() {
                Some(&["POST"])
            } else {
                Some(&["DELETE", "PATCH"])
            }
        }
        _ => None,
    }
}

/// Subscriber Data Management Service (nudm-sdm, TS 29.503 §5.2).
async fn route_nudm_sdm(
    parts: &[&str],
    method: &str,
    request: &SbiRequest,
    uri: &str,
) -> SbiResponse {
    let supi = parts.get(2).copied().unwrap_or("");
    let resource = parts.get(3).copied().unwrap_or("");
    let tail = parts.get(4).copied().unwrap_or("");

    match (resource, tail, method) {
        // #226 criterion 1: GetSupiInfo / Retrieval of Multiple Data Sets
        // (TS 29.503 §5.2.2.2.9). `/nudm-sdm/v2/{supi}` has only three path parts,
        // so `resource` is empty here — and the query string was already stripped
        // by the router, which is why `dataset-names` must be read through the SBI
        // query accessor rather than from the path.
        ("", "", "GET") if !supi.is_empty() => {
            handle_get_subscription_data_sets(supi, request).await
        }
        ("am-data", "", "GET") => handle_get_am_data(supi, request).await,
        // udmd#1: SoR / UPU acknowledgement (TS 29.503 5.2.2.6, PUT).
        ("am-data", "sor-ack", "PUT") => handle_sor_ack(supi, request).await,
        ("am-data", "upu-ack", "PUT") => handle_upu_ack(supi, request).await,
        ("smf-select-data", "", "GET") => handle_get_smf_select_data(supi, request).await,
        ("sm-data", "", "GET") => handle_get_sm_data(supi, request).await,
        ("nssai", "", "GET") => handle_get_nssai(supi, request).await,
        ("sdm-subscriptions", "", "POST") => handle_sdm_subscribe(supi, request).await,
        ("sdm-subscriptions", subscription_id, "DELETE") if !subscription_id.is_empty() => {
            handle_sdm_unsubscribe(supi, subscription_id).await
        }
        // udmd-12: SDM subscription modification PATCH is not implemented.
        ("sdm-subscriptions", subscription_id, "PATCH") if !subscription_id.is_empty() => {
            send_not_implemented("sdm-subscriptions PATCH is not yet implemented")
        }
        // GetSupiOrGpsi (TS 29.503 §5.2.2.2.14 / §6.1.3.16). This is a Nudm_SDM
        // operation, not a UECM one — it was routed under nudm-uecm before #85,
        // where a conformant consumer would never have looked for it.
        ("id-translation-result", "", "GET") => handle_id_translation_result(supi, request).await,
        // #226 criterion 2: UE context in AMF data. The data is already read from
        // the UDR by the UECM path, so this is a read-through rather than new
        // storage — and it is the data set the #83 SDM notification producer
        // reports on every AMF registration and deregistration, so before this a
        // subscriber was told the resource changed and then could not read it.
        ("ue-context-in-amf-data", "", "GET") => {
            handle_get_ue_context_in_amf_data(supi, request).await
        }
        // #226 criterion 3: the remaining TS 29.503 per-SUPI SDM data sets. Routed
        // as READ-THROUGHS to the UDR rather than answered with a status this UDM
        // invents: whether the data exists is the data layer's answer, not the
        // router's. Today `udrd` serves three provisioned data sets, so the rest
        // relay its 404 — which is derived rather than asserted, and starts
        // working the moment udrd grows a source. See the spec for why this is not
        // a 501.
        (
            "ue-context-in-smf-data"
            | "ue-context-in-smsf-data"
            | "sms-data"
            | "sms-mng-data"
            | "trace-data"
            | "lcs-privacy-data"
            | "lcs-mo-data"
            | "lcs-bca-data"
            | "v2x-data"
            | "prose-data"
            | "mbs-data"
            | "uc-data",
            "",
            "GET",
        ) => handle_get_sdm_data_set(supi, resource, request).await,
        _ => unmatched(sdm_allowed_methods(parts), method, uri),
    }
}

/// Methods the `nudm-ueau` resource at `parts` supports.
fn ueau_allowed_methods(parts: &[&str]) -> Option<&'static [&'static str]> {
    let resource = parts.get(3).copied()?;
    let tail = parts.get(4).copied().unwrap_or("");
    if parts.len() > 5 {
        return None;
    }
    match (resource, tail) {
        ("security-information", "generate-auth-data") => Some(&["POST"]),
        ("auth-events", "") => Some(&["POST"]),
        // DeleteAuth addresses an individual auth-event resource.
        ("auth-events", _) => Some(&["PUT"]),
        _ => None,
    }
}

/// UE Authentication Service (nudm-ueau, TS 29.503 §5.4).
async fn route_nudm_ueau(
    parts: &[&str],
    method: &str,
    request: &SbiRequest,
    uri: &str,
) -> SbiResponse {
    let supi = parts.get(2).copied().unwrap_or("");
    let resource = parts.get(3).copied().unwrap_or("");
    let action = parts.get(4).copied().unwrap_or("");

    match (resource, action, method) {
        ("security-information", "generate-auth-data", "POST") => {
            handle_generate_auth_data(supi, request).await
        }
        ("auth-events", "", "POST") => handle_auth_event(supi, request).await,
        // DeleteAuth: PUT /{supi}/auth-events/{authEventId}
        // (TS 29.503 §5.4.2.3.3). The identifier is mandatory in the
        // path, so a bare `PUT .../auth-events` is not this operation.
        ("auth-events", auth_event_id, "PUT") if !auth_event_id.is_empty() => {
            handle_delete_auth(supi, auth_event_id, request).await
        }
        _ => unmatched(ueau_allowed_methods(parts), method, uri),
    }
}

/// Methods the `nudm-ee` resource at `parts` supports.
fn ee_allowed_methods(parts: &[&str]) -> Option<&'static [&'static str]> {
    if parts.get(3).copied()? != "ee-subscriptions" || parts.len() > 5 {
        return None;
    }
    if parts.get(4).copied().unwrap_or("").is_empty() {
        Some(&["POST"])
    } else {
        Some(&["DELETE", "PATCH"])
    }
}

/// Event Exposure Service (nudm-ee) - udmd#0, TS 29.503 5.5/6.4
async fn route_nudm_ee(
    parts: &[&str],
    method: &str,
    request: &SbiRequest,
    uri: &str,
) -> SbiResponse {
    let ue_identity = parts.get(2).copied().unwrap_or("");
    let resource = parts.get(3).copied().unwrap_or("");
    let subscription_id = parts.get(4).copied().unwrap_or("");

    match (resource, subscription_id, method) {
        ("ee-subscriptions", "", "POST") => handle_ee_subscribe(ue_identity, request).await,
        ("ee-subscriptions", id, "DELETE") if !id.is_empty() => {
            handle_ee_unsubscribe(ue_identity, id).await
        }
        ("ee-subscriptions", id, "PATCH") if !id.is_empty() => {
            handle_ee_modify(ue_identity, id, request).await
        }
        _ => unmatched(ee_allowed_methods(parts), method, uri),
    }
}

/// Methods the `nudm-pp` resource at `parts` supports (TS 29.503 §5.6).
fn pp_allowed_methods(parts: &[&str]) -> Option<&'static [&'static str]> {
    // The group resources are not UE-scoped: /nudm-pp/v1/5g-vn-groups/{id}.
    match parts.get(2).copied()? {
        "5g-vn-groups" | "mbs-group-membership" => {
            return if parts.len() == 4 {
                Some(&["PUT", "PATCH", "GET", "DELETE"])
            } else {
                None
            };
        }
        _ => {}
    }
    let resource = parts.get(3).copied()?;
    let tail = parts.get(4).copied().unwrap_or("");
    if parts.len() > 5 {
        return None;
    }
    match (resource, tail) {
        ("pp-data", "") => Some(&["GET", "PATCH"]),
        ("pp-data-store", af_instance_id) if !af_instance_id.is_empty() => {
            Some(&["PUT", "GET", "DELETE"])
        }
        _ => None,
    }
}

/// Parameter Provision Service (nudm-pp, TS 29.503 §5.6).
async fn route_nudm_pp(
    parts: &[&str],
    method: &str,
    request: &SbiRequest,
    uri: &str,
) -> SbiResponse {
    let ue_id = parts.get(2).copied().unwrap_or("");
    let resource = parts.get(3).copied().unwrap_or("");
    let tail = parts.get(4).copied().unwrap_or("");

    // 5G VN group and MBS group membership management need a group store this
    // UDM does not have; the operations are recognised and refused as such.
    if matches!(ue_id, "5g-vn-groups" | "mbs-group-membership") {
        return match (parts.len(), method) {
            (4, "PUT" | "PATCH" | "GET" | "DELETE") => {
                send_not_implemented(&format!("{ue_id} management is not yet implemented"))
            }
            _ => unmatched(pp_allowed_methods(parts), method, uri),
        };
    }

    match (resource, tail, method) {
        ("pp-data", "", "GET") => handle_get_pp_data(ue_id).await,
        ("pp-data", "", "PATCH") => handle_update_pp_data(ue_id, request).await,
        ("pp-data-store", af_id, "PUT") if !af_id.is_empty() => {
            handle_create_pp_data_entry(ue_id, af_id, request).await
        }
        ("pp-data-store", af_id, "GET") if !af_id.is_empty() => {
            handle_get_pp_data_entry(ue_id, af_id).await
        }
        ("pp-data-store", af_id, "DELETE") if !af_id.is_empty() => {
            handle_delete_pp_data_entry(ue_id, af_id).await
        }
        _ => unmatched(pp_allowed_methods(parts), method, uri),
    }
}

/// Methods the `nudm-mt` resource at `parts` supports (TS 29.503 §5.10).
fn mt_allowed_methods(parts: &[&str]) -> Option<&'static [&'static str]> {
    match parts.len() {
        // /nudm-mt/v1/{supi}
        3 => Some(&["GET"]),
        // /nudm-mt/v1/{supi}/loc-info/provide-loc-info
        5 if parts[3] == "loc-info" && parts[4] == "provide-loc-info" => Some(&["POST"]),
        _ => None,
    }
}

/// MT Service (nudm-mt, TS 29.503 §5.10).
async fn route_nudm_mt(
    parts: &[&str],
    method: &str,
    request: &SbiRequest,
    uri: &str,
) -> SbiResponse {
    let supi = parts.get(2).copied().unwrap_or("");
    match (parts.len(), method) {
        (3, "GET") if !supi.is_empty() => handle_query_ue_info(supi, request).await,
        (5, "POST") if parts[3] == "loc-info" && parts[4] == "provide-loc-info" => {
            // ProvideLocationInfo proxies Namf_Location ProvideLocationInfo
            // (TS 29.518 §5.5.2.3), which no AMF in this tree serves — amfd
            // implements provide-pos-info only. Refusing is honest; answering
            // from the UDM's own data would invent a location.
            send_not_implemented(
                "provide-loc-info requires Namf_Location ProvideLocationInfo, \
                 which the serving AMF does not implement",
            )
        }
        _ => unmatched(mt_allowed_methods(parts), method, uri),
    }
}

/// The operations of the four Nudm services TS 29.503 defines and this UDM does
/// not implement, so a recognised operation can answer `501` while an
/// unrecognised path still answers `404`.
fn unimplemented_service_methods(service: &str, parts: &[&str]) -> Option<&'static [&'static str]> {
    let post: &'static [&'static str] = &["POST"];
    match service {
        // POST /nudm-niddau/v1/{ueIdentity}/authorize
        "nudm-niddau" if parts.len() == 4 && parts[3] == "authorize" => Some(post),
        // POST /nudm-rsds/v1/{ueIdentity}/sm-delivery-status
        "nudm-rsds" if parts.len() == 4 && parts[3] == "sm-delivery-status" => Some(post),
        // POST /nudm-ssau/v1/{ueIdentity}/{serviceType}/{authorize,remove}
        "nudm-ssau" if parts.len() == 5 && matches!(parts[4], "authorize" | "remove") => Some(post),
        // POST /nudm-ueid/v1/deconceal
        "nudm-ueid" if parts.len() == 3 && parts[2] == "deconceal" => Some(post),
        _ => None,
    }
}

/// Answer a defined-but-unimplemented Nudm service.
///
/// `nudm-ueid` Deconceal is the notable one: the SIDF machinery it needs already
/// exists in this UDM (`deconceal_suci`), so it is a small change — but it
/// returns a SUPI for a SUCI to whoever asks, and this repo's SBI OAuth2
/// enforcement is off by default (#187). Serving it before that posture is
/// authenticated would turn the UDM into an unauthenticated SUPI oracle, so it
/// stays a 501 until #187 lands.
fn route_nudm_unimplemented(service: &str, parts: &[&str], method: &str, uri: &str) -> SbiResponse {
    match unimplemented_service_methods(service, parts) {
        Some(allowed) if allowed.contains(&method) => {
            send_not_implemented(&format!("{service} is not yet implemented"))
        }
        allowed => unmatched(allowed, method, uri),
    }
}

// ---------------------------------------------------------------------------
// Nudm_SDM GetSupiOrGpsi (#85, TS 29.503 §5.2.2.2.14)
// ---------------------------------------------------------------------------

/// `GET /nudm-sdm/v2/{ueId}/id-translation-result` — translate between a UE's
/// SUPI and its GPSI, returning an `IdTranslationResult`.
///
/// Both directions are served from the UDR, which is where subscriber identities
/// live:
///
/// * The **identity-data** resource (TS 29.505 §5.2.19) answers either
///   direction, because it is keyed by *any* UE identifier and returns both
///   lists. It is the only source that can resolve a **GPSI to a SUPI**, which is
///   the direction a NEF needs to target a UE named by `msisdn-`/`extid-`
///   (nextgcore #110 refuses such a subscription today precisely because this
///   operation was unrouted).
/// * When identity-data is absent, the **SUPI to GPSI** direction falls back to
///   the `gpsis` member of the UE's `am-data` (TS 29.505 AM subscription data),
///   which this UDM can already read.
///
/// `supi` is mandatory in `IdTranslationResult`, so a translation that cannot
/// establish one is a `404` rather than a partial answer.
pub async fn handle_id_translation_result(ue_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("Id Translation Result: ueId={ue_id}");
    let requested_gpsi_type = request.http.params.get("requested-gpsi-type").cloned();
    let asked_for_gpsi = ue_id.starts_with("imsi-") || ue_id.starts_with("nai-");

    // 1. identity-data: the only resource that resolves a GPSI to a SUPI.
    match crate::udm_nudr_dr_send_subscription_data_get(ue_id, "identity-data").await {
        Ok(resp) if resp.is_success() => {
            let doc: serde_json::Value = match resp
                .http
                .content
                .as_deref()
                .and_then(|b| serde_json::from_str(b).ok())
            {
                Some(v) => v,
                None => {
                    log::error!("[{ue_id}] UDR identity-data returned unparseable body");
                    return nextgcore_sbi::server::send_service_unavailable("UDR response invalid");
                }
            };
            let list = |key: &str| -> Vec<String> {
                doc.get(key)
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default()
            };
            let supis = list("supiList");
            let gpsis = list("gpsiList");
            return match build_id_translation_result(supis, gpsis, requested_gpsi_type.as_deref()) {
                Some(result) => SbiResponse::with_status(200)
                    .with_json_body(&result)
                    .unwrap_or_else(|_| {
                        nextgcore_sbi::server::send_internal_error("serialize failed")
                    }),
                None => send_problem(
                    404,
                    "USER_NOT_FOUND",
                    "identity-data holds no SUPI for this identifier",
                ),
            };
        }
        Ok(resp) if resp.status == 404 => {
            log::debug!("[{ue_id}] UDR has no identity-data; trying am-data gpsis");
        }
        Ok(resp) => {
            log::error!("[{ue_id}] UDR identity-data GET returned {}", resp.status);
            return nextgcore_sbi::server::send_service_unavailable("UDR identity-data failed");
        }
        Err(e) => {
            log::warn!("[{ue_id}] UDR identity-data GET failed: {e}");
            return nextgcore_sbi::server::send_service_unavailable("UDR unavailable");
        }
    }

    // 2. SUPI -> GPSI fallback via am-data. A GPSI-keyed request cannot use it:
    //    am-data is addressed BY the UE identifier, so reading it back would
    //    prove nothing about which SUPI the GPSI belongs to.
    if !asked_for_gpsi {
        return send_problem(
            404,
            "USER_NOT_FOUND",
            "no identity-data for this GPSI (UDR identity-data resource required)",
        );
    }
    match crate::udm_nudr_dr_send_provisioned_data_get(ue_id, "am-data", 0, 0).await {
        Ok(resp) if resp.is_success() => {
            let doc: serde_json::Value = resp
                .http
                .content
                .as_deref()
                .and_then(|b| serde_json::from_str(b).ok())
                .unwrap_or(serde_json::Value::Null);
            let gpsis: Vec<String> = doc
                .get("gpsis")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            match build_id_translation_result(
                vec![ue_id.to_string()],
                gpsis,
                requested_gpsi_type.as_deref(),
            ) {
                Some(result) => SbiResponse::with_status(200)
                    .with_json_body(&result)
                    .unwrap_or_else(|_| {
                        nextgcore_sbi::server::send_internal_error("serialize failed")
                    }),
                None => send_problem(404, "USER_NOT_FOUND", "no identity translation available"),
            }
        }
        Ok(resp) if resp.status == 404 => {
            send_problem(404, "USER_NOT_FOUND", "No subscription data for this UE")
        }
        Ok(resp) => {
            log::error!("[{ue_id}] UDR am-data GET returned {}", resp.status);
            nextgcore_sbi::server::send_service_unavailable("UDR query failed")
        }
        Err(e) => {
            log::warn!("[{ue_id}] UDR am-data GET failed: {e}");
            nextgcore_sbi::server::send_service_unavailable("UDR unavailable")
        }
    }
}

/// Assemble an `IdTranslationResult` (TS 29.503 §6.1.6.2.x) from the identity
/// lists the UDR holds.
///
/// `supi` is the schema's only required member, so `None` here means the caller
/// must answer 404 rather than emit a result with no SUPI in it. The first entry
/// of each list is the primary identity; the rest go to `additionalSupis` /
/// `additionalGpsis`, which is what those members are for — dropping them would
/// hide the other identities of a multi-GPSI subscriber.
///
/// `requested_gpsi_type` (`MSISDN` or `EXT_ID`) filters the GPSIs, so a consumer
/// that asked for an external identifier is not handed an MSISDN.
pub(crate) fn build_id_translation_result(
    supis: Vec<String>,
    gpsis: Vec<String>,
    requested_gpsi_type: Option<&str>,
) -> Option<serde_json::Value> {
    let prefix = match requested_gpsi_type {
        Some("MSISDN") => Some("msisdn-"),
        Some("EXT_ID") => Some("extid-"),
        _ => None,
    };
    let gpsis: Vec<String> = match prefix {
        Some(p) => gpsis.into_iter().filter(|g| g.starts_with(p)).collect(),
        None => gpsis,
    };
    let supi = supis.first()?.clone();
    let mut result = serde_json::json!({ "supi": supi });
    let obj = result.as_object_mut()?;
    if let Some(gpsi) = gpsis.first() {
        obj.insert("gpsi".to_string(), serde_json::json!(gpsi));
    }
    if supis.len() > 1 {
        obj.insert("additionalSupis".to_string(), serde_json::json!(supis[1..]));
    }
    if gpsis.len() > 1 {
        obj.insert("additionalGpsis".to_string(), serde_json::json!(gpsis[1..]));
    }
    Some(result)
}

// ---------------------------------------------------------------------------
// Nudm_PP — Parameter Provision (#85, TS 29.503 §5.6)
// ---------------------------------------------------------------------------

/// The UDR `subscription-data` resource holding an AF's provisioned parameters.
fn pp_data_store_resource(af_instance_id: &str) -> String {
    format!("pp-data-store/{af_instance_id}")
}

/// Map a UDR read of a provisioning resource onto the Nudm_PP response.
fn pp_read_response(
    ue_id: &str,
    resource: &str,
    result: Result<SbiResponse, String>,
) -> SbiResponse {
    match result {
        Ok(resp) if resp.is_success() => {
            let body = resp.http.content.unwrap_or_else(|| "{}".to_string());
            SbiResponse::with_status(200).with_body(body, "application/json")
        }
        Ok(resp) if resp.status == 404 => send_problem(
            404,
            "DATA_NOT_FOUND",
            &format!("No {resource} provisioned for this UE"),
        ),
        Ok(resp) => {
            log::error!("[{ue_id}] UDR {resource} GET returned {}", resp.status);
            nextgcore_sbi::server::send_service_unavailable("UDR query failed")
        }
        Err(e) => {
            log::warn!("[{ue_id}] UDR {resource} GET failed: {e}");
            nextgcore_sbi::server::send_service_unavailable("UDR unavailable")
        }
    }
}

/// `GET /nudm-pp/v1/{ueId}/pp-data` — Nudm_PP GetPPData (TS 29.503 §5.6.2.3).
pub async fn handle_get_pp_data(ue_id: &str) -> SbiResponse {
    log::info!("Get PP Data: ueId={ue_id}");
    pp_read_response(
        ue_id,
        "pp-data",
        crate::udm_nudr_dr_send_subscription_data_get(ue_id, "pp-data").await,
    )
}

/// `PATCH /nudm-pp/v1/{ueId}/pp-data` — Nudm_PP Update (TS 29.503 §5.6.2.2).
///
/// The provisioned parameters belong in the UDR, not in UDM memory: an AF
/// provisions them once and every later subscription read must see them, so a
/// UDM-local copy would be lost on restart and invisible to a second UDM.
pub async fn handle_update_pp_data(ue_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("Update PP Data: ueId={ue_id}");
    let patch = match parse_request_json(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    // A `PpData` merge document or a `PatchItem[]` array are both legal here
    // (TS 29.503 §6.6.6.x); anything else cannot be applied.
    if !patch.is_object() && !patch.is_array() {
        return send_bad_request(
            "PpData patch must be an object or a PatchItem array",
            Some("INVALID_MSG_FORMAT"),
        );
    }
    match crate::udm_nudr_dr_send_subscription_data_patch(ue_id, "pp-data", &patch).await {
        Ok(resp) if resp.is_success() => SbiResponse::with_status(204),
        Ok(resp) if resp.status == 404 => send_problem(
            404,
            "USER_NOT_FOUND",
            "No subscription data to provision for this UE",
        ),
        Ok(resp) => {
            log::error!("[{ue_id}] UDR pp-data PATCH returned {}", resp.status);
            nextgcore_sbi::server::send_service_unavailable("UDR provisioning failed")
        }
        Err(e) => {
            log::warn!("[{ue_id}] UDR pp-data PATCH failed: {e}");
            nextgcore_sbi::server::send_service_unavailable("UDR unavailable")
        }
    }
}

/// `PUT /nudm-pp/v1/{ueId}/pp-data-store/{afInstanceId}` — Create PP Data Entry.
pub async fn handle_create_pp_data_entry(
    ue_id: &str,
    af_instance_id: &str,
    request: &SbiRequest,
) -> SbiResponse {
    log::info!("Create PP Data Entry: ueId={ue_id} af={af_instance_id}");
    let body = match parse_request_json(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    if !body.is_object() {
        return send_bad_request(
            "PpDataEntry must be a JSON object",
            Some("INVALID_MSG_FORMAT"),
        );
    }
    let resource = pp_data_store_resource(af_instance_id);
    match crate::udm_nudr_dr_send_subscription_data_put(ue_id, &resource, &body).await {
        Ok(resp) if resp.is_success() => {
            // 201 on create, 204 on replace: the UDR distinguishes them and the
            // consumer needs the Location of a resource it just created.
            if resp.status == 201 {
                SbiResponse::with_status(201).with_header(
                    "Location",
                    format!("/nudm-pp/v1/{ue_id}/pp-data-store/{af_instance_id}"),
                )
            } else {
                SbiResponse::with_status(204)
            }
        }
        Ok(resp) => {
            log::error!("[{ue_id}] UDR {resource} PUT returned {}", resp.status);
            nextgcore_sbi::server::send_service_unavailable("UDR provisioning failed")
        }
        Err(e) => {
            log::warn!("[{ue_id}] UDR {resource} PUT failed: {e}");
            nextgcore_sbi::server::send_service_unavailable("UDR unavailable")
        }
    }
}

/// `GET /nudm-pp/v1/{ueId}/pp-data-store/{afInstanceId}` — Get PP Data Entry.
pub async fn handle_get_pp_data_entry(ue_id: &str, af_instance_id: &str) -> SbiResponse {
    let resource = pp_data_store_resource(af_instance_id);
    pp_read_response(
        ue_id,
        &resource,
        crate::udm_nudr_dr_send_subscription_data_get(ue_id, &resource).await,
    )
}

/// `DELETE /nudm-pp/v1/{ueId}/pp-data-store/{afInstanceId}` — Delete PP Data
/// Entry.
pub async fn handle_delete_pp_data_entry(ue_id: &str, af_instance_id: &str) -> SbiResponse {
    log::info!("Delete PP Data Entry: ueId={ue_id} af={af_instance_id}");
    let resource = pp_data_store_resource(af_instance_id);
    match crate::udm_nudr_dr_send_subscription_data_delete(ue_id, &resource).await {
        Ok(resp) if resp.is_success() => SbiResponse::with_status(204),
        Ok(resp) if resp.status == 404 => send_problem(
            404,
            "DATA_NOT_FOUND",
            "No provisioned entry for this AF instance",
        ),
        Ok(resp) => {
            log::error!("[{ue_id}] UDR {resource} DELETE returned {}", resp.status);
            nextgcore_sbi::server::send_service_unavailable("UDR provisioning failed")
        }
        Err(e) => {
            log::warn!("[{ue_id}] UDR {resource} DELETE failed: {e}");
            nextgcore_sbi::server::send_service_unavailable("UDR unavailable")
        }
    }
}

// ---------------------------------------------------------------------------
// Nudm_MT — QueryUeInfo (#85, TS 29.503 §5.10.2.2)
// ---------------------------------------------------------------------------

/// The `UeInfo` attributes this UDM can actually retrieve.
///
/// `tadsInfo` is the AMF's `UeContextInfo`, fetched with Namf_MT
/// ProvideDomainSelectionInfo. `userState` and `5gSrvccInfo` are NOT served:
/// `userState` is the AMF's CM/RM state, reported through Namf_EventExposure
/// rather than Namf_MT, and `5gSrvccInfo` is SRVCC subscription data no
/// provisioning path in this core populates. Deriving either from the presence
/// of a registration record would be a guess presented as a fact.
const MT_SUPPORTED_FIELDS: [&str; 1] = ["tadsInfo"];

/// `GET /nudm-mt/v1/{supi}?fields=...` — Nudm_MT QueryUeInfo.
///
/// The UDM is a proxy here: it resolves the UE's serving AMF from the stored
/// UECM registration and asks that AMF, because the requested information is the
/// AMF's, not the UDM's.
pub async fn handle_query_ue_info(supi: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("Query UE Info: SUPI={supi}");

    // `fields` is a REQUIRED query parameter (TS 29.503 §6.10.3.1): without it
    // the request does not say what to retrieve.
    let fields_raw = match request.http.params.get("fields") {
        Some(v) if !v.trim().is_empty() => v.clone(),
        _ => {
            return send_problem(
                400,
                "MANDATORY_IE_MISSING",
                "QueryUeInfo requires the 'fields' query parameter",
            )
        }
    };
    let fields: Vec<&str> = fields_raw
        .split(',')
        .map(|f| f.trim())
        .filter(|f| !f.is_empty())
        .collect();
    let unsupported: Vec<&str> = fields
        .iter()
        .copied()
        .filter(|f| !MT_SUPPORTED_FIELDS.contains(f))
        .collect();
    if !unsupported.is_empty() {
        // Naming the fields is the point: a bare 501 leaves the consumer unable
        // to retry with the subset that does work.
        return send_not_implemented(&format!(
            "QueryUeInfo cannot retrieve {} (supported: {})",
            unsupported.join(", "),
            MT_SUPPORTED_FIELDS.join(", ")
        ));
    }

    // The serving AMF comes from the UE's 3GPP-access registration; a UE with no
    // registration has no AMF to ask.
    let amf_instance_id = match crate::uecm::process_amf_registration_get(
        supi,
        &crate::uecm::UdrClient::Live,
        crate::uecm::UecmAccess::ThreeGpp,
    )
    .await
    {
        resp if resp.status == 200 => resp
            .http
            .content
            .as_deref()
            .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
            .and_then(|v| {
                v.get("amfInstanceId")
                    .and_then(|i| i.as_str())
                    .map(String::from)
            }),
        resp if resp.status == 404 => {
            return send_problem(
                404,
                "CONTEXT_NOT_FOUND",
                "The UE is not registered, so no AMF can be queried",
            )
        }
        resp => return resp,
    };

    match crate::udm_amf_send_mt_ue_context_info(amf_instance_id.as_deref(), supi, "TADS").await {
        Ok(resp) if resp.is_success() => {
            let tads: serde_json::Value = resp
                .http
                .content
                .as_deref()
                .and_then(|b| serde_json::from_str(b).ok())
                .unwrap_or(serde_json::Value::Null);
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({ "tadsInfo": tads }))
                .unwrap_or_else(|_| nextgcore_sbi::server::send_internal_error("serialize failed"))
        }
        Ok(resp) if resp.status == 404 => send_problem(
            404,
            "CONTEXT_NOT_FOUND",
            "The serving AMF holds no context for this UE",
        ),
        Ok(resp) => {
            log::error!("[{supi}] Namf_MT returned {}", resp.status);
            nextgcore_sbi::server::send_service_unavailable("Serving AMF query failed")
        }
        Err(e) => {
            log::warn!("[{supi}] Namf_MT request failed: {e}");
            nextgcore_sbi::server::send_service_unavailable("Serving AMF unreachable")
        }
    }
}

// UE Context Management handlers

/// Parse a request body as JSON, or return the ProblemDetails response.
fn parse_request_json(request: &SbiRequest) -> Result<serde_json::Value, Box<SbiResponse>> {
    let body = match &request.http.content {
        Some(content) => content,
        None => {
            return Err(Box::new(send_bad_request(
                "Missing request body",
                Some("MISSING_BODY"),
            )))
        }
    };
    serde_json::from_str(body).map_err(|e| {
        Box::new(send_bad_request(
            &format!("Invalid JSON: {e}"),
            Some("INVALID_JSON"),
        ))
    })
}

/// Route the `nudm-uecm` `.../registrations[/...]` resource tree
/// (TS 29.503 §6.2.3).
///
/// Split out of [`udm_sbi_route`] because the tree is two segments deep with
/// six sibling resources, and each of `amf-3gpp-access` and
/// `amf-non-3gpp-access` carries PUT/PATCH/GET plus a custom operation. The
/// access is resolved ONCE here, from the path, and handed to the UECM
/// processors — the router is the only place that knows a resource name.
async fn route_uecm_registrations(
    supi: &str,
    parts: &[&str],
    method: &str,
    request: &SbiRequest,
    uri: &str,
) -> SbiResponse {
    use crate::uecm::UecmAccess;

    let sub = parts.get(4).copied().unwrap_or("");
    let tail = parts.get(5).copied().unwrap_or("");

    // amf-3gpp-access / amf-non-3gpp-access (+ the dereg-amf custom operation).
    if let Some(access) = UecmAccess::from_amf_resource(sub) {
        // POST .../{amf-resource}/dereg-amf — TS 29.503 §5.3.2.4.2 DeregAMF.
        if tail == "dereg-amf" {
            if method != "POST" {
                return unmatched(uecm_allowed_methods(parts), method, uri);
            }
            return handle_dereg_amf(supi, request).await;
        }
        if !tail.is_empty() {
            // pei-update / roaming-info-update and friends are not implemented.
            return send_not_implemented(&format!("{sub}/{tail} is not yet implemented"));
        }
        return match method {
            "PUT" => handle_amf_registration(supi, request, access).await,
            "PATCH" => handle_amf_registration_update(supi, request, access).await,
            "GET" => handle_amf_registration_get(supi, access).await,
            _ => unmatched(uecm_allowed_methods(parts), method, uri),
        };
    }

    // smsf-3gpp-access / smsf-non-3gpp-access.
    if let Some(access) = UecmAccess::from_smsf_resource(sub) {
        return match method {
            "PUT" => handle_smsf_registration(supi, request, access).await,
            "GET" => handle_smsf_registration_get(supi, access).await,
            "DELETE" => handle_smsf_deregistration(supi, access).await,
            _ => unmatched(uecm_allowed_methods(parts), method, uri),
        };
    }

    match sub {
        "smf-registrations" => match (method, tail.is_empty()) {
            // Collection GET -> SmfRegistrationInfo (TS 29.503 §5.3.2.5).
            ("GET", true) => handle_smf_registrations_get(supi).await,
            ("GET", false) => handle_smf_registration_get(supi, tail).await,
            ("PUT", false) => handle_smf_registration(supi, tail, request).await,
            ("DELETE", false) => handle_smf_deregistration(supi, tail).await,
            _ => unmatched(uecm_allowed_methods(parts), method, uri),
        },
        "ip-sm-gw" => match method {
            "PUT" => handle_ip_sm_gw_registration(supi, request).await,
            "GET" => handle_ip_sm_gw_registration_get(supi).await,
            "DELETE" => handle_ip_sm_gw_deregistration(supi).await,
            _ => unmatched(uecm_allowed_methods(parts), method, uri),
        },
        // GET .../registrations/location -> LocationInfo (TS 29.503 §5.3.2.5).
        "location" if method == "GET" => handle_location_info_get(supi).await,
        // POST .../registrations/send-routing-info-sm needs the SMS routing
        // information the UDM does not hold (TS 29.503 §5.3.2.7).
        "send-routing-info-sm" if method == "POST" => {
            send_not_implemented("send-routing-info-sm is not yet implemented")
        }
        _ => unmatched(uecm_allowed_methods(parts), method, uri),
    }
}

pub async fn handle_amf_registration(
    supi: &str,
    request: &SbiRequest,
    access: crate::uecm::UecmAccess,
) -> SbiResponse {
    log::info!("AMF Registration ({}): SUPI={supi}", access.amf_resource());

    let reg_data = match parse_request_json(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };

    // udmd-03 (validate) -> udmd-01 (persist to UDR) -> udmd-02 (notify old AMF).
    crate::uecm::process_amf_registration(supi, &reg_data, &crate::uecm::UdrClient::Live, access)
        .await
}

pub async fn handle_amf_registration_update(
    supi: &str,
    request: &SbiRequest,
    access: crate::uecm::UecmAccess,
) -> SbiResponse {
    log::info!(
        "AMF Registration Update ({}): SUPI={supi}",
        access.amf_resource()
    );

    let update_data = match parse_request_json(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };

    // udmd-05: GUAMI ownership check + UDR PATCH (or purge on purgeFlag).
    crate::uecm::process_amf_registration_update(
        supi,
        &update_data,
        &crate::uecm::UdrClient::Live,
        access,
    )
    .await
}

/// `GET .../registrations/{amf-resource}` — TS 29.503 §5.3.2.5
/// `Get3GppRegistration` / `GetNon3GppRegistration`.
pub async fn handle_amf_registration_get(
    supi: &str,
    access: crate::uecm::UecmAccess,
) -> SbiResponse {
    log::info!(
        "AMF Registration Get ({}): SUPI={supi}",
        access.amf_resource()
    );
    crate::uecm::process_amf_registration_get(supi, &crate::uecm::UdrClient::Live, access).await
}

/// `POST .../registrations/amf-3gpp-access/dereg-amf` — TS 29.503 §5.3.2.4.2.
pub async fn handle_dereg_amf(supi: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("AMF Deregistration (dereg-amf): SUPI={supi}");
    let info = match parse_request_json(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    crate::uecm::process_dereg_amf(supi, &info, &crate::uecm::UdrClient::Live).await
}

/// `PUT .../registrations/{smsf-resource}` — SMSF registration.
pub async fn handle_smsf_registration(
    supi: &str,
    request: &SbiRequest,
    access: crate::uecm::UecmAccess,
) -> SbiResponse {
    log::info!(
        "SMSF Registration ({}): SUPI={supi}",
        access.smsf_resource()
    );
    let reg_data = match parse_request_json(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    crate::uecm::process_smsf_registration(supi, &reg_data, &crate::uecm::UdrClient::Live, access)
        .await
}

/// `GET .../registrations/{smsf-resource}`.
pub async fn handle_smsf_registration_get(
    supi: &str,
    access: crate::uecm::UecmAccess,
) -> SbiResponse {
    crate::uecm::process_smsf_registration_get(supi, &crate::uecm::UdrClient::Live, access).await
}

/// `DELETE .../registrations/{smsf-resource}`.
pub async fn handle_smsf_deregistration(
    supi: &str,
    access: crate::uecm::UecmAccess,
) -> SbiResponse {
    log::info!(
        "SMSF Deregistration ({}): SUPI={supi}",
        access.smsf_resource()
    );
    crate::uecm::process_smsf_deregistration(supi, &crate::uecm::UdrClient::Live, access).await
}

/// `PUT .../registrations/ip-sm-gw` — IP-SM-GW registration.
pub async fn handle_ip_sm_gw_registration(supi: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("IP-SM-GW Registration: SUPI={supi}");
    let reg_data = match parse_request_json(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    crate::uecm::process_ip_sm_gw_registration(supi, &reg_data, &crate::uecm::UdrClient::Live).await
}

/// `GET .../registrations/ip-sm-gw`.
pub async fn handle_ip_sm_gw_registration_get(supi: &str) -> SbiResponse {
    crate::uecm::process_ip_sm_gw_registration_get(supi, &crate::uecm::UdrClient::Live).await
}

/// `DELETE .../registrations/ip-sm-gw`.
pub async fn handle_ip_sm_gw_deregistration(supi: &str) -> SbiResponse {
    log::info!("IP-SM-GW Deregistration: SUPI={supi}");
    crate::uecm::process_ip_sm_gw_deregistration(supi, &crate::uecm::UdrClient::Live).await
}

/// `GET .../registrations/location` — TS 29.503 §5.3.2.5 `GetLocationInfo`.
pub async fn handle_location_info_get(supi: &str) -> SbiResponse {
    log::info!("UECM Location Info Get: SUPI={supi}");
    crate::uecm::process_location_info_get(supi, &crate::uecm::UdrClient::Live).await
}

/// `GET .../registrations/smf-registrations` — the collection form.
pub async fn handle_smf_registrations_get(supi: &str) -> SbiResponse {
    log::info!("SMF Registrations Get (collection): SUPI={supi}");
    crate::uecm::process_smf_registrations_get(supi, &crate::uecm::UdrClient::Live).await
}

/// `GET .../registrations/smf-registrations/{pduSessionId}`.
pub async fn handle_smf_registration_get(supi: &str, pdu_session_id: &str) -> SbiResponse {
    crate::uecm::process_smf_registration_get(supi, pdu_session_id, &crate::uecm::UdrClient::Live)
        .await
}

pub async fn handle_smf_registration(
    supi: &str,
    pdu_session_id: &str,
    request: &SbiRequest,
) -> SbiResponse {
    log::info!("SMF Registration: SUPI={supi}, PDU Session={pdu_session_id}");

    let reg_data = match parse_request_json(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };

    // udmd-03 (validate) -> udmd-01 (persist to UDR).
    crate::uecm::process_smf_registration(
        supi,
        pdu_session_id,
        &reg_data,
        &crate::uecm::UdrClient::Live,
    )
    .await
}

pub async fn handle_smf_deregistration(supi: &str, pdu_session_id: &str) -> SbiResponse {
    log::info!("SMF Deregistration: SUPI={supi}, PDU Session={pdu_session_id}");

    // udmd-01: DELETE the per-PDU-session UDR context-data before returning 204.
    crate::uecm::process_smf_deregistration(supi, pdu_session_id, &crate::uecm::UdrClient::Live)
        .await
}

// Subscriber Data Management handlers

/// Split an optionally SNPN-scoped SUPI into the base SUPI and the SNPN NID.
///
/// SNPN-scoped identifiers (Rel-17, TS 23.501 §5.30 / TS 23.003) may carry the
/// Network Identifier as a `:nid-<NID>` suffix. UDR is keyed by the base SUPI,
/// so the subscription/credential lookup uses the base while the NID scopes the
/// SNPN. This is the minimal SNPN-aware lookup: it resolves the standard
/// subscription for an SNPN SUPI so registration completes. The full
/// credentials-holder model (separate SNPN credential store / external DCS per
/// TS 33.501 Annex I) is deferred.
fn split_snpn_supi(supi: &str) -> (&str, Option<&str>) {
    match supi.split_once(":nid-") {
        Some((base, nid)) => (base, Some(nid)),
        None => (supi, None),
    }
}

/// Forward SDM query parameters (TS 29.503 §5.2.2) to UDR.
///
/// udmd-08: plmn-id, dataset-names, and supported-features are passed through
/// to the Nudr_DataRepository GET so UDR can filter/scope the response.
fn sdm_query_params(request: &SbiRequest) -> std::collections::HashMap<String, String> {
    let mut params = std::collections::HashMap::new();
    for key in [
        "plmn-id",
        "dataset-names",
        "supported-features",
        "dnn",
        "snssai",
    ] {
        if let Some(v) = request.http.params.get(key) {
            params.insert(key.to_string(), v.clone());
        }
    }
    params
}

pub async fn handle_get_am_data(supi: &str, request: &SbiRequest) -> SbiResponse {
    let (supi, snpn_nid) = split_snpn_supi(supi);
    if let Some(nid) = snpn_nid {
        log::info!("Get AM Data: SUPI={supi} (SNPN NID={nid})");
    } else {
        log::info!("Get AM Data: SUPI={supi}");
    }

    // udmd-08: forward query params (plmn-id, dataset-names, supported-features).
    let params = sdm_query_params(request);
    let udr_result = if params.is_empty() {
        crate::udm_nudr_dr_send_provisioned_data_get(supi, "am-data", 0, 0).await
    } else {
        crate::udm_nudr_dr_send_provisioned_data_get_with_params(supi, "am-data", &params).await
    };

    match udr_result {
        Ok(udr_response) if udr_response.is_success() => {
            // Wave-6 F-04: inject a protected Steering-of-Roaming container when
            // a steering source is configured. TS 33.501 §6.14.2.1 makes
            // Nausf_SoRProtection mandatory whenever steering is sent and defines
            // NO unprotected delivery path, so the injector fail-closes (withholds
            // sorInfo) on any AUSF failure; absence of a steering source leaves the
            // UDR body byte-identical (matched-sim default-safety).
            //
            // Wave-6 F-05: symmetrically inject a protected UE-Parameters-Update
            // payload (upuInfo) when a UPU source is configured, via
            // Nausf_UPUProtection (TS 33.501 §6.15.2.1, same fail-closed rule).
            // NOTE: only the am-data-attribute UPU delivery is implemented here;
            // notification-driven UPU (Nudm_SDM_Notification post-registration,
            // §6.15.2.1 step 5) is DEFERRED until udmd grows SDM notifications.
            let mut response = SbiResponse::with_status(200);
            if let Some(body) = udr_response.http.content {
                let body = crate::sor::maybe_inject_sor_info(supi, body).await;
                let body = crate::upu::maybe_inject_upu_info(supi, body).await;
                response = response.with_body(body, "application/json");
            }
            response
        }
        Ok(udr_response) => {
            log::warn!(
                "[{}] UDR am-data query returned status {}",
                supi,
                udr_response.status
            );
            SbiResponse::with_status(udr_response.status)
        }
        Err(e) => {
            log::warn!("[{supi}] UDR am-data query failed: {e}");
            nextgcore_sbi::server::send_service_unavailable("UDR unavailable")
        }
    }
}

/// The TS 29.503 `DataSetName` tokens this UDM recognises, paired with the
/// `SubscriptionDataSets` member each contributes.
///
/// The tokens are the spec's, NOT the path segments. #226's acceptance criterion
/// writes `dataset-names=am-data,sm-data`, but TS 29.503's `DataSetName` enum is
/// `AM`, `SMF_SEL`, `SM`, `UEC_AMF`, … — and `udrd` already implements exactly
/// those tokens for its own combined provisioned-data GET (udrd-03,
/// `parse_dataset_names`). Following the issue's spelling would have created a
/// second, non-conformant vocabulary on the two sides of the same query parameter.
/// An unrecognised token is refused with 400 naming the accepted set, rather than
/// silently dropped — a consumer that asked for a data set and got a body without
/// it would otherwise read the absence as "this subscriber has none".
const SDM_DATA_SET_NAMES: [&str; 4] = ["AM", "SMF_SEL", "SM", "UEC_AMF"];

/// `GET /nudm-sdm/v2/{supi}[?dataset-names=…]` — GetSupiInfo / Retrieval of
/// Multiple Data Sets (TS 29.503 §5.2.2.2.9), answering `SubscriptionDataSets`.
///
/// The provisioned data sets are fetched with ONE combined UDR read rather than a
/// per-data-set fan-out, because `udrd` already implements the same
/// `dataset-names` filtering and member naming (udrd-03). Re-implementing the
/// fan-out here would have made two places decide which member name a data set
/// contributes, and they would eventually disagree.
///
/// `UEC_AMF` is merged in separately: it lives under the UDR's `context-data`, not
/// `provisioned-data`, so the combined read cannot supply it.
pub async fn handle_get_subscription_data_sets(supi: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("Get SubscriptionDataSets (multi-data-set): SUPI={supi}");

    let raw = request.http.params.get("dataset-names").cloned();
    let requested: Option<Vec<String>> = match raw.as_deref() {
        None => None,
        Some(raw) => {
            let names: Vec<String> = raw
                .split(',')
                .map(|s| s.trim().to_ascii_uppercase())
                .filter(|s| !s.is_empty())
                .collect();
            if names.is_empty() {
                return send_bad_request(
                    "dataset-names was present but named no data set",
                    Some("MANDATORY_QUERY_PARAM_INCORRECT"),
                );
            }
            if let Some(unknown) = names
                .iter()
                .find(|n| !SDM_DATA_SET_NAMES.contains(&n.as_str()))
            {
                return send_bad_request(
                    &format!(
                        "unsupported dataset-names value {unknown:?}; this UDM serves {}",
                        SDM_DATA_SET_NAMES.join(", ")
                    ),
                    Some("MANDATORY_QUERY_PARAM_INCORRECT"),
                );
            }
            Some(names)
        }
    };
    let wants = |name: &str| -> bool {
        requested
            .as_ref()
            .is_none_or(|names| names.iter().any(|n| n == name))
    };

    let mut sets = serde_json::Map::new();

    // The provisioned subset, in one read. `udrd` returns the requested members
    // already keyed by their `SubscriptionDataSets` names.
    let provisioned: Vec<&str> = ["AM", "SMF_SEL", "SM"]
        .into_iter()
        .filter(|n| wants(n))
        .collect();
    if !provisioned.is_empty() {
        let mut params = std::collections::HashMap::new();
        // Always explicit, even when the consumer sent no filter: this UDM serves a
        // subset of the data sets udrd might grow, so forwarding "everything" would
        // silently start returning members this UDM has not agreed to serve.
        params.insert("dataset-names".to_string(), provisioned.join(","));
        match crate::udm_nudr_dr_send_provisioned_data_get_with_params(supi, "", &params).await {
            Ok(resp) if resp.is_success() => {
                if let Some(body) = resp.http.content.as_deref() {
                    if let Ok(serde_json::Value::Object(map)) =
                        serde_json::from_str::<serde_json::Value>(body)
                    {
                        for (k, v) in map {
                            sets.insert(k, v);
                        }
                    }
                }
            }
            // A subscriber the UDR does not hold is 404 for the whole request: there
            // is no partial answer to give, and 200 with an empty body would say
            // "this subscriber has no data" rather than "no such subscriber".
            Ok(resp) if resp.status == 404 => {
                return nextgcore_sbi::server::send_not_found(
                    &format!("no subscription data for {supi}"),
                    Some("DATA_NOT_FOUND"),
                );
            }
            Ok(resp) => {
                log::warn!(
                    "[{supi}] UDR combined provisioned-data returned {}",
                    resp.status
                );
                return SbiResponse::with_status(resp.status);
            }
            Err(e) => {
                log::warn!("[{supi}] UDR combined provisioned-data query failed: {e}");
                return nextgcore_sbi::server::send_service_unavailable("UDR unavailable");
            }
        }
    }

    // `uecAmfData` comes from context-data, so it is a separate read. Absence is
    // NOT an error here: a UE with no AMF registration legitimately has no such
    // data set, and failing the whole multi-set retrieval for it would deny the
    // consumer the members that are available.
    if wants("UEC_AMF") {
        if let Some(value) = read_ue_context_in_amf_data(supi).await {
            sets.insert("uecAmfData".to_string(), value);
        }
    }

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::Value::Object(sets))
        .unwrap_or_else(|_| {
            nextgcore_sbi::server::send_internal_error("failed to serialise data sets")
        })
}

/// The stored `amf-3gpp-access` registration as the `uecAmfData` data set, or
/// `None` when the UE has no registration (or the UDR is unreachable).
///
/// Shared by the individual `ue-context-in-amf-data` GET and the multi-data-set
/// retrieval so the two cannot answer differently for the same UE.
async fn read_ue_context_in_amf_data(supi: &str) -> Option<serde_json::Value> {
    match crate::udm_nudr_dr_send_context_get(supi, "amf-3gpp-access").await {
        Ok(resp) if resp.is_success() => resp
            .http
            .content
            .as_deref()
            .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok()),
        Ok(resp) => {
            log::debug!("[{supi}] UDR amf-3gpp-access read returned {}", resp.status);
            None
        }
        Err(e) => {
            log::warn!("[{supi}] UDR amf-3gpp-access read failed: {e}");
            None
        }
    }
}

/// `GET /nudm-sdm/v2/{supi}/ue-context-in-amf-data` (#226 criterion 2).
///
/// 404 `DATA_NOT_FOUND` when the UE has no AMF registration — the data set does
/// not exist for that UE, which is different from the operation not existing.
pub async fn handle_get_ue_context_in_amf_data(supi: &str, _request: &SbiRequest) -> SbiResponse {
    log::info!("Get UE context in AMF data: SUPI={supi}");
    match read_ue_context_in_amf_data(supi).await {
        Some(value) => SbiResponse::with_status(200)
            .with_json_body(&value)
            .unwrap_or_else(|_| {
                nextgcore_sbi::server::send_internal_error("failed to serialise uecAmfData")
            }),
        None => nextgcore_sbi::server::send_not_found(
            &format!("no ue-context-in-amf-data for {supi}"),
            Some("DATA_NOT_FOUND"),
        ),
    }
}

/// The remaining TS 29.503 per-SUPI SDM data sets, as UDR read-throughs (#226
/// criterion 3).
///
/// Deliberately NOT a 501. Whether a data set exists for a subscriber is the data
/// layer's answer, and routing the read means this UDM reports what the UDR says
/// rather than a status the router invented. `udrd` currently serves three
/// provisioned data sets, so the rest relay its 404 as `DATA_NOT_FOUND` — a
/// derived answer that starts returning data the moment udrd grows a source,
/// with no change here.
pub async fn handle_get_sdm_data_set(
    supi: &str,
    resource: &str,
    request: &SbiRequest,
) -> SbiResponse {
    log::info!("Get SDM data set {resource}: SUPI={supi}");
    let params = sdm_query_params(request);
    let udr_result = if params.is_empty() {
        crate::udm_nudr_dr_send_provisioned_data_get(supi, resource, 0, 0).await
    } else {
        crate::udm_nudr_dr_send_provisioned_data_get_with_params(supi, resource, &params).await
    };
    match udr_result {
        Ok(resp) if resp.is_success() => {
            let mut response = SbiResponse::with_status(200);
            if let Some(body) = resp.http.content {
                response = response.with_body(body, "application/json");
            }
            response
        }
        Ok(resp) if resp.status == 404 => nextgcore_sbi::server::send_not_found(
            &format!("no {resource} for {supi}"),
            Some("DATA_NOT_FOUND"),
        ),
        Ok(resp) => {
            log::warn!(
                "[{supi}] UDR {resource} query returned status {}",
                resp.status
            );
            SbiResponse::with_status(resp.status)
        }
        Err(e) => {
            log::warn!("[{supi}] UDR {resource} query failed: {e}");
            nextgcore_sbi::server::send_service_unavailable("UDR unavailable")
        }
    }
}

pub async fn handle_get_smf_select_data(supi: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("Get SMF Select Data: SUPI={supi}");

    // udmd-08: forward query params to UDR.
    let params = sdm_query_params(request);
    let udr_result = if params.is_empty() {
        crate::udm_nudr_dr_send_provisioned_data_get(supi, "smf-selection-subscription-data", 0, 0)
            .await
    } else {
        crate::udm_nudr_dr_send_provisioned_data_get_with_params(
            supi,
            "smf-selection-subscription-data",
            &params,
        )
        .await
    };

    match udr_result {
        Ok(udr_response) if udr_response.is_success() => {
            let mut response = SbiResponse::with_status(200);
            if let Some(body) = udr_response.http.content {
                response = response.with_body(body, "application/json");
            }
            response
        }
        Ok(udr_response) => {
            log::warn!(
                "[{}] UDR smf-select query returned status {}",
                supi,
                udr_response.status
            );
            SbiResponse::with_status(udr_response.status)
        }
        Err(e) => {
            log::warn!("[{supi}] UDR smf-select query failed: {e}");
            nextgcore_sbi::server::send_service_unavailable("UDR unavailable")
        }
    }
}

pub async fn handle_get_sm_data(supi: &str, request: &SbiRequest) -> SbiResponse {
    let dnn = request
        .http
        .params
        .get("dnn")
        .map(|s| s.as_str())
        .unwrap_or("internet");

    log::info!("Get SM Data: SUPI={supi}, DNN={dnn}");

    // udmd-08: forward query params (dnn, snssai, plmn-id, supported-features).
    let params = sdm_query_params(request);
    let udr_result = if params.is_empty() {
        crate::udm_nudr_dr_send_provisioned_data_get(supi, "sm-data", 0, 0).await
    } else {
        crate::udm_nudr_dr_send_provisioned_data_get_with_params(supi, "sm-data", &params).await
    };

    match udr_result {
        Ok(udr_response) if udr_response.is_success() => {
            let mut response = SbiResponse::with_status(200);
            if let Some(body) = udr_response.http.content {
                response = response.with_body(body, "application/json");
            }
            response
        }
        Ok(udr_response) => {
            log::warn!(
                "[{}] UDR sm-data query returned status {}",
                supi,
                udr_response.status
            );
            SbiResponse::with_status(udr_response.status)
        }
        Err(e) => {
            log::warn!("[{supi}] UDR sm-data query failed: {e}");
            nextgcore_sbi::server::send_service_unavailable("UDR unavailable")
        }
    }
}

pub async fn handle_get_nssai(supi: &str, _request: &SbiRequest) -> SbiResponse {
    log::info!("Get NSSAI: SUPI={supi}");

    // Query UDR for am-data which contains NSSAI
    match crate::udm_nudr_dr_send_provisioned_data_get(supi, "am-data", 0, 0).await {
        Ok(udr_response) if udr_response.is_success() => {
            // Extract NSSAI from am-data response
            if let Some(body) = &udr_response.http.content {
                if let Ok(am_data) = serde_json::from_str::<serde_json::Value>(body) {
                    if let Some(nssai) = am_data.get("nssai") {
                        return SbiResponse::with_status(200)
                            .with_json_body(nssai)
                            .unwrap_or_else(|_| SbiResponse::with_status(200));
                    }
                }
            }
            SbiResponse::with_status(200)
        }
        Ok(udr_response) => {
            log::warn!(
                "[{}] UDR nssai query returned status {}",
                supi,
                udr_response.status
            );
            SbiResponse::with_status(udr_response.status)
        }
        Err(e) => {
            log::warn!("[{supi}] UDR nssai query failed: {e}");
            nextgcore_sbi::server::send_service_unavailable("UDR unavailable")
        }
    }
}

pub async fn handle_sdm_subscribe(supi: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("SDM Subscribe: SUPI={supi}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let sub_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let nf_instance_id = sub_data
        .get("nfInstanceId")
        .and_then(|v| v.as_str())
        .map(String::from);
    let callback_reference = sub_data
        .get("callbackReference")
        .and_then(|v| v.as_str())
        .map(String::from);
    let monitored_resource_uris: Vec<String> = sub_data
        .get("monitoredResourceUris")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // #83: nfInstanceId, callbackReference and monitoredResourceUris are
    // mandatory in SdmSubscription (TS 29.503 §6.1.6.2.x). This handler used to
    // accept a body missing all three and answer 201 — so a consumer with a bug
    // in its subscribe request got a subscription id back, monitored nothing,
    // and had no way to tell. `nudm_handler.rs` already had these very checks;
    // nothing routed to them.
    //
    // An EMPTY monitoredResourceUris is refused as well as an absent one: the
    // spec's minItems is 1, and an empty list is the shape a consumer produces
    // when its own resource list came out empty — which is a bug to surface, not
    // a whole-UE subscription to infer.
    for (value_is_present, ie) in [
        (nf_instance_id.is_some(), "nfInstanceId"),
        (callback_reference.is_some(), "callbackReference"),
        (!monitored_resource_uris.is_empty(), "monitoredResourceUris"),
    ] {
        if !value_is_present {
            log::warn!("SDM Subscribe for {supi} is missing {ie}; refusing");
            return send_bad_request(
                &format!("SdmSubscription is missing mandatory {ie}"),
                Some("MANDATORY_IE_MISSING"),
            );
        }
    }

    // udmd-07: persist the subscription in the UDM context.
    let sub = UdmSdmSubscription::for_supi(
        supi,
        nf_instance_id.clone(),
        callback_reference.clone(),
        monitored_resource_uris.clone(),
    );
    let subscription_id = sub.id.clone();
    {
        let ctx = udm_self();
        if let Ok(context) = ctx.read() {
            context.sdm_subscription_insert(sub);
        };
    }

    SbiResponse::with_status(201)
        .with_header(
            // TS 29.503 §6.1.1: Nudm_SDM is v2. The Location URI is what the
            // consumer will use for the subsequent DELETE, so a v1 value here
            // hands out a path the spec does not define.
            "Location",
            format!("/nudm-sdm/v2/{supi}/sdm-subscriptions/{subscription_id}"),
        )
        .with_json_body(&serde_json::json!({
            "subscriptionId": subscription_id,
            "nfInstanceId": nf_instance_id,
            "callbackReference": callback_reference,
            "monitoredResourceUris": monitored_resource_uris,
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

pub async fn handle_sdm_unsubscribe(supi: &str, subscription_id: &str) -> SbiResponse {
    log::info!("SDM Unsubscribe: SUPI={supi}, subscriptionId={subscription_id}");

    // udmd-07: 404 if the subscription is not found in context.
    let exists = {
        let ctx = udm_self();
        let guard = ctx.read().ok();
        guard
            .as_ref()
            .and_then(|c| c.sdm_subscription_find_by_id(subscription_id))
            .is_some()
    };
    if !exists {
        return send_problem(404, "NOT_FOUND", "Subscription not found");
    }
    // Remove it from context.
    let ctx = udm_self();
    if let Ok(context) = ctx.read() {
        context.sdm_subscription_remove(subscription_id);
    };
    SbiResponse::with_status(204)
}

/// udmd#0: Nudm_EE CreateEeSubscription (TS 29.503 5.5.2.2 / 6.4).
pub async fn handle_ee_subscribe(ue_identity: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("EE Subscribe: ueIdentity={ue_identity}");
    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let ee_sub: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };
    // EeSubscription mandatory IEs: callbackReference + monitoringConfigurations (TS29503_Nudm_EE.yaml:472-474).
    let callback_reference = match ee_sub.get("callbackReference").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            return send_bad_request(
                "callbackReference is mandatory",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };
    let has_moni = ee_sub
        .get("monitoringConfigurations")
        .and_then(|v| v.as_object())
        .map(|m| !m.is_empty())
        .unwrap_or(false);
    if !has_moni {
        return send_bad_request(
            "monitoringConfigurations is mandatory",
            Some("MANDATORY_IE_MISSING"),
        );
    }
    let sub = UdmEeSubscription::for_ue(ue_identity, callback_reference, body.clone());
    let subscription_id = sub.id.clone();
    {
        let ctx = udm_self();
        if let Ok(context) = ctx.read() {
            context.ee_subscription_insert(sub);
        };
    }
    // CreatedEeSubscription requires the echoed eeSubscription (yaml:409-413).
    let mut echoed = ee_sub;
    if let Some(obj) = echoed.as_object_mut() {
        obj.insert(
            "subscriptionId".to_string(),
            serde_json::json!(subscription_id),
        );
    }
    SbiResponse::with_status(201)
        .with_header(
            "Location",
            format!("/nudm-ee/v1/{ue_identity}/ee-subscriptions/{subscription_id}"),
        )
        .with_json_body(&serde_json::json!({ "eeSubscription": echoed }))
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// udmd#0: Nudm_EE DeleteEeSubscription (TS 29.503 5.5.2.3).
pub async fn handle_ee_unsubscribe(ue_identity: &str, subscription_id: &str) -> SbiResponse {
    log::info!("EE Unsubscribe: ueIdentity={ue_identity}, subscriptionId={subscription_id}");
    let exists = {
        let ctx = udm_self();
        let guard = ctx.read().ok();
        guard
            .as_ref()
            .and_then(|c| c.ee_subscription_find_by_id(subscription_id))
            .is_some()
    };
    if !exists {
        return send_problem(404, "NOT_FOUND", "Subscription not found");
    }
    let ctx = udm_self();
    if let Ok(context) = ctx.read() {
        context.ee_subscription_remove(subscription_id);
    };
    SbiResponse::with_status(204)
}

/// Nudm_EE UpdateEeSubscription (TS 29.503 §5.5.2.4.2).
///
/// #83: this used to answer 204 and discard the patch, so a consumer could
/// "modify" `monitoringConfigurations` forever while the stored subscription
/// never changed — subscription lifecycle management that reports success and
/// diverges from state.
pub async fn handle_ee_modify(
    ue_identity: &str,
    subscription_id: &str,
    request: &SbiRequest,
) -> SbiResponse {
    log::info!("EE Modify: ueIdentity={ue_identity}, subscriptionId={subscription_id}");

    let Some(mut sub) = ({
        let ctx = udm_self();
        let guard = ctx.read().ok();
        guard
            .as_ref()
            .and_then(|c| c.ee_subscription_find_by_id(subscription_id))
    }) else {
        return send_problem(404, "NOT_FOUND", "Subscription not found");
    };

    let Some(body) = request.http.content.as_deref() else {
        return send_bad_request("Missing request body", Some("MISSING_BODY"));
    };
    let patch: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let mut stored: serde_json::Value = match serde_json::from_str(&sub.raw) {
        Ok(v) => v,
        Err(e) => {
            log::error!("Stored EeSubscription {subscription_id} is not valid JSON: {e}");
            return send_problem(500, "INTERNAL_ERROR", "stored subscription is corrupt");
        }
    };

    if let Err(detail) = apply_ee_patch(&mut stored, &patch) {
        return send_bad_request(&detail, Some("INVALID_MSG_FORMAT"));
    }

    // The callbackReference is cached alongside the raw body, so a patch that
    // changes it must update both or the next notification goes to the old URI.
    if let Some(cb) = stored.get("callbackReference").and_then(|v| v.as_str()) {
        sub.callback_reference = cb.to_string();
    }
    sub.raw = stored.to_string();

    let updated = {
        let ctx = udm_self();
        let guard = ctx.read().ok();
        guard
            .as_ref()
            .is_some_and(|c| c.ee_subscription_update(sub))
    };
    if !updated {
        return send_problem(404, "NOT_FOUND", "Subscription not found");
    }
    SbiResponse::with_status(204)
}

/// Apply an `EeSubscription` patch in place.
///
/// TS 29.503 §5.5.2.4.2 uses a JSON `PatchItem` array (RFC 6902-shaped, as the
/// rest of this codebase's SBI PATCH endpoints do). A merge-patch object is also
/// accepted, because lenient peers send one and refusing it buys nothing.
///
/// `remove` and `replace` on an absent member are errors rather than silent
/// no-ops: a consumer patching a path that is not there has a wrong idea of the
/// stored subscription, and answering 204 would confirm it.
fn apply_ee_patch(stored: &mut serde_json::Value, patch: &serde_json::Value) -> Result<(), String> {
    let Some(ops) = patch.as_array() else {
        // Merge patch (RFC 7396): top-level members replace their counterparts.
        let Some(members) = patch.as_object() else {
            return Err("patch must be a PatchItem array or a merge-patch object".to_string());
        };
        let Some(target) = stored.as_object_mut() else {
            return Err("stored subscription is not a JSON object".to_string());
        };
        for (key, value) in members {
            if value.is_null() {
                target.remove(key);
            } else {
                target.insert(key.clone(), value.clone());
            }
        }
        return Ok(());
    };

    if ops.is_empty() {
        return Err("patch carries no operations".to_string());
    }
    for op in ops {
        let op_name = op
            .get("op")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "PatchItem is missing op".to_string())?;
        let path = op
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "PatchItem is missing path".to_string())?;
        // Only top-level members of EeSubscription are addressable here; that is
        // what the spec's patch targets (monitoringConfigurations,
        // callbackReference, reportingOptions, ...). A deeper pointer is refused
        // rather than half-applied.
        let member = path.strip_prefix('/').unwrap_or(path);
        if member.is_empty() || member.contains('/') {
            return Err(format!(
                "path {path:?} must address a top-level EeSubscription member"
            ));
        }
        let target = stored
            .as_object_mut()
            .ok_or_else(|| "stored subscription is not a JSON object".to_string())?;
        match op_name {
            "add" | "replace" => {
                let value = op
                    .get("value")
                    .ok_or_else(|| format!("{op_name} on {path:?} has no value"))?;
                if op_name == "replace" && !target.contains_key(member) {
                    return Err(format!("cannot replace absent member {path:?}"));
                }
                target.insert(member.to_string(), value.clone());
            }
            "remove" => {
                if target.remove(member).is_none() {
                    return Err(format!("cannot remove absent member {path:?}"));
                }
            }
            other => return Err(format!("unsupported patch op {other:?}")),
        }
    }
    Ok(())
}

/// udmd#1: Nudm_Sdm SoRAckInfo (TS 29.503 5.2.2.6, PUT /am-data/sor-ack).
pub async fn handle_sor_ack(supi: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("SoR Ack: SUPI={supi}");
    handle_ack_info(supi, request, "SoR")
}

/// udmd#1: Nudm_Sdm UpuAck (TS 29.503 5.2.2.6, PUT /am-data/upu-ack).
pub async fn handle_upu_ack(supi: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("UPU Ack: SUPI={supi}");
    handle_ack_info(supi, request, "UPU")
}

/// Constant-time byte-slice comparison (fold-XOR over all bytes), the same
/// pattern as the ausfd `compare_res_star` (TS 33.501 requires the MAC compare
/// be constant-time so a mismatching MAC cannot be told from a matching one by
/// timing). A length mismatch (public information) short-circuits to `false`;
/// otherwise no early return leaks which byte differed. Used by
/// [`handle_ack_info`] — the secret XMAC is NEVER compared with a plain `==`.
fn ct_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Extract the UE-supplied 16-byte SoR/UPU-MAC-I_UE from an `AcknowledgeInfo`
/// (TS 29.503 §5.2.2.6). Two wire forms are accepted:
/// - the direct `sorMacIue` / `upuMacIue` field: a 32-hex-char `SorMac`/`UpuMac`
///   (TS 29.509 pattern `^[A-Fa-f0-9]{32}$` = 16 octets);
/// - the `sorTransparentContainer` / `upuTransparentContainer` `Bytes`
///   (base64): the MAC is octets 5-20 (0-indexed `[4..20]`) of the SOR/UPU
///   transparent container per TS 24.501 §9.11.3.51 / §9.11.3.53A.
///
/// Returns `None` when neither form carries a syntactically valid 16-byte MAC
/// (fail-closed: a malformed MAC field is treated as absent, never a match).
fn extract_received_iue_mac(ack: &serde_json::Value, kind: &str) -> Option<Vec<u8>> {
    let (mac_field, container_field) = if kind == "SoR" {
        ("sorMacIue", "sorTransparentContainer")
    } else {
        ("upuMacIue", "upuTransparentContainer")
    };

    // Preferred form: the 32-hex-char SorMac/UpuMac field.
    if let Some(hex) = ack.get(mac_field).and_then(|v| v.as_str()) {
        if hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            let bytes = crate::nudm_handler::hex_to_bytes(hex);
            if bytes.len() == 16 {
                return Some(bytes);
            }
        }
        // A malformed MAC field is a fail-closed miss (never a false match).
        return None;
    }

    // Transparent-container form: octets 5-20 (0-indexed [4..20]) hold the MAC.
    if let Some(b64) = ack.get(container_field).and_then(|v| v.as_str()) {
        let raw = nextgcore_crypt::base64::decode(b64)?;
        if raw.len() >= 20 {
            return Some(raw[4..20].to_vec());
        }
    }
    None
}

/// Record a verified (or `ueNotReachable`) SoR/UPU ack on the process context
/// and CLEAR the outstanding expected XMAC (single-use). Done under a short
/// guard scope, never across another lock (nf-context-lock-deadlocks learning).
fn record_ack(
    kind: &str,
    supi: &str,
    provisioning_time: &str,
    counter: Option<u16>,
    ue_not_reachable: bool,
) {
    let ctx = udm_self();
    let guard = match ctx.read() {
        Ok(g) => g,
        Err(_) => return,
    };
    let recorded = if kind == "SoR" {
        guard.sor_record_ack(supi, provisioning_time, counter, ue_not_reachable)
    } else {
        guard.upu_record_ack(supi, provisioning_time, counter, ue_not_reachable)
    };
    drop(guard);
    if !recorded {
        log::debug!("[{supi}] {kind} ack: no UE context to persist ack state (best-effort)");
    }
}

/// AcknowledgeInfo handling for SoR/UPU acks (TS29503_Nudm_SDM.yaml:4398;
/// TS 33.501 §6.14.2.1 steps 13-15 / §6.15.2.1 step 9).
///
/// Mandatory IE: `provisioningTime`. When the UDM holds a temporarily-stored
/// expected SoR/UPU-XMAC-I_UE for this SUPI (pinned at injection time by
/// F-04/F-05), the UE-supplied SoR/UPU-MAC-I_UE is REQUIRED and compared
/// **constant-time** ([`ct_compare`]) against that XMAC:
/// - match → 204, record the ack, and CLEAR the expected XMAC — single-use, so a
///   replayed ack is subsequently rejected;
/// - mismatch / absent MAC → 400 and the ack is NOT recorded (an attacker in the
///   VPLMN can no longer 'acknowledge' a steering/parameter update the UE never
///   verified).
///
/// With NO outstanding XMAC a plain `AcknowledgeInfo` (no MAC) stays 204
/// (backward-compatible with the pre-F-06 contract and the matched sim, which
/// never sends SoR/UPU acks); a MAC supplied with nothing to compare against is
/// an unexpected ack → 400. `ueNotReachable=true` is honoured (AMF-reported): the
/// ack is recorded without a MAC check.
pub fn handle_ack_info(supi: &str, request: &SbiRequest, kind: &str) -> SbiResponse {
    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let ack: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };
    let provisioning_time = match ack.get("provisioningTime").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => {
            return send_bad_request(
                "provisioningTime is mandatory",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };

    // Peek the outstanding expected XMAC (read-only; the single-use clear is in
    // the record step). Guard is dropped before any write.
    let expected: Option<([u8; 16], u16)> = {
        let ctx = udm_self();
        let peeked = match ctx.read() {
            Ok(guard) => {
                if kind == "SoR" {
                    guard.sor_expected_xmac(supi)
                } else {
                    guard.upu_expected_xmac(supi)
                }
            }
            Err(_) => None,
        };
        peeked
    };

    let mac_field = if kind == "SoR" {
        "sorMacIue"
    } else {
        "upuMacIue"
    };
    let mac_fail_cause = if kind == "SoR" {
        "SOR_MAC_FAILURE"
    } else {
        "UPU_MAC_FAILURE"
    };

    // §6.14.2.1 / §6.15.2.1: an AMF-reported ueNotReachable is a terminal ack
    // event — record without a MAC check and consume any outstanding pin.
    let ue_not_reachable = ack
        .get("ueNotReachable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if ue_not_reachable {
        let counter = expected.map(|(_, c)| c);
        record_ack(kind, supi, &provisioning_time, counter, true);
        log::info!("[{supi}] {kind} ack recorded (ueNotReachable)");
        return SbiResponse::with_status(204);
    }

    let received = extract_received_iue_mac(&ack, kind);

    match (expected, received) {
        // Outstanding XMAC + a supplied MAC → constant-time verify.
        (Some((xmac, counter)), Some(mac)) => {
            if ct_compare(&mac, &xmac) {
                // Single-use: record the ack AND clear the expected XMAC so a
                // replayed identical ack finds nothing to compare and is rejected.
                record_ack(kind, supi, &provisioning_time, Some(counter), false);
                log::info!("[{supi}] {kind}-MAC-I_UE verified — ack recorded");
                SbiResponse::with_status(204)
            } else {
                log::warn!("[{supi}] {kind}-MAC-I_UE mismatch — ack rejected, state unchanged");
                send_problem(
                    400,
                    mac_fail_cause,
                    &format!("{kind}-MAC-I_UE verification failed"),
                )
            }
        }
        // Outstanding XMAC but the UE sent no MAC → REQUIRE it.
        (Some(_), None) => {
            log::warn!("[{supi}] {kind} ack missing {mac_field} for a protected update — rejected");
            send_bad_request(
                &format!("{mac_field} is required to acknowledge a protected {kind} update"),
                Some("MANDATORY_IE_MISSING"),
            )
        }
        // No outstanding XMAC but a MAC was supplied → unexpected ack.
        (None, Some(_)) => {
            log::warn!("[{supi}] unexpected {kind} ack MAC with no outstanding update — rejected");
            send_problem(
                400,
                "UNEXPECTED_MESSAGE",
                &format!("no outstanding {kind} update to acknowledge"),
            )
        }
        // Plain ack, nothing outstanding → 204 (backward-compatible).
        (None, None) => {
            log::info!("[{supi}] {kind} acknowledgement accepted (no outstanding MAC)");
            SbiResponse::with_status(204)
        }
    }
}

// UE Authentication handlers

/// Build an RFC 7807 / TS 29.500 ProblemDetails response.
fn send_problem(status: u16, cause: &str, detail: &str) -> SbiResponse {
    SbiResponse::with_status(status)
        .with_json_body(&serde_json::json!({
            "status": status,
            "cause": cause,
            "detail": detail
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(status))
}

/// Build a 501 Not Implemented ProblemDetails response (udmd-12).
fn send_not_implemented(detail: &str) -> SbiResponse {
    send_problem(501, "NOT_IMPLEMENTED", detail)
}

/// Advance a 48-bit SQN per TS 33.102 Annex C.3.2 (udmd-10).
///
/// SQN layout: SEQ[47:5] || IND[4:0].  SEQ increments by 1 each call;
/// IND is kept fixed (the caller always uses the same AV slot).  The result
/// is masked to 48 bits and returned as a 6-byte big-endian array.
pub(crate) fn advance_sqn_ind(sqn_bytes: [u8; 6]) -> [u8; 6] {
    let mut val: u64 = 0;
    for &b in &sqn_bytes {
        val = (val << 8) | (b as u64);
    }
    let seq = val >> 5;
    let ind = val & 0x1F;
    let new_val = (((seq + 1) << 5) | ind) & 0x0000_FFFF_FFFF_FFFF;
    let mut out = [0u8; 6];
    for (i, b) in out.iter_mut().enumerate() {
        *b = ((new_val >> ((5 - i) * 8)) & 0xFF) as u8;
    }
    out
}

/// Validate the serving network name format (TS 24.501 §9.12.1 / TS 33.501
/// §6.1.1.4): `5G:mnc<3-digit MNC>.mcc<3-digit MCC>.3gppnetwork.org`.
fn validate_serving_network_name(snn: &str) -> bool {
    let rest = match snn.strip_prefix("5G:mnc") {
        Some(r) => r,
        None => return false,
    };
    let (mnc, rest) = match rest.split_once(".mcc") {
        Some(p) => p,
        None => return false,
    };
    // Allow an optional NID suffix for SNPN (TS 33.501 §5.30):
    // "...3gppnetwork.org:NID"
    let (mcc, tail) = match rest.split_once('.') {
        Some(p) => p,
        None => return false,
    };
    let tail_ok = tail == "3gppnetwork.org" || tail.starts_with("3gppnetwork.org:");
    mnc.len() == 3
        && mcc.len() == 3
        && mnc.bytes().all(|b| b.is_ascii_digit())
        && mcc.bytes().all(|b| b.is_ascii_digit())
        && tail_ok
}

/// Load a home network private key: either a 64-hex-char string inline or a
/// path to a file containing the hex key.
fn load_hnet_key(value: &str) -> Option<Vec<u8>> {
    let parse_hex = |s: &str| -> Option<Vec<u8>> {
        let s = s.trim();
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
            .collect()
    };
    if let Some(key) = parse_hex(value) {
        return Some(key);
    }
    let content = std::fs::read_to_string(value).ok()?;
    parse_hex(&content)
}

pub async fn handle_generate_auth_data(supi_or_suci: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("Generate Auth Data: supiOrSuci={supi_or_suci}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let auth_info: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    // TS 29.503: servingNetworkName and ausfInstanceId are mandatory in
    // AuthenticationInfoRequest.
    let serving_network_name = match auth_info.get("servingNetworkName").and_then(|v| v.as_str()) {
        Some(snn) if !snn.is_empty() => snn,
        _ => {
            return send_problem(
                400,
                "MANDATORY_IE_MISSING",
                "AuthenticationInfoRequest.servingNetworkName is missing",
            )
        }
    };
    let ausf_instance_id = match auth_info.get("ausfInstanceId").and_then(|v| v.as_str()) {
        Some(id) if !id.is_empty() => id,
        _ => {
            return send_problem(
                400,
                "MANDATORY_IE_MISSING",
                "AuthenticationInfoRequest.ausfInstanceId is missing",
            )
        }
    };

    // TS 33.501 §6.1.2: verify the serving network name is well-formed before
    // generating any authentication material (anti-bidding-down: a malformed
    // or non-5G SNN must not yield a 5G AV).
    if !validate_serving_network_name(serving_network_name) {
        return send_problem(
            403,
            "SERVING_NETWORK_NOT_AUTHORIZED",
            &format!("Invalid serving network name '{serving_network_name}'"),
        );
    }

    log::info!("Generate Auth Data: SNN={serving_network_name}");

    // SUCI deconcealment (TS 33.501 §6.12.5): resolve the SUPI before any UDR
    // interaction. Null scheme and imsi- passthrough need no key material.
    let supi = {
        let ctx = udm_self();
        let context = ctx.read().unwrap();
        context.deconceal_suci(supi_or_suci)
    };
    let supi = match supi {
        Some(s) => s,
        None => {
            log::error!("[{supi_or_suci}] SUCI deconcealment failed");
            return send_problem(
                403,
                "AUTHENTICATION_REJECTED",
                "SUCI deconcealment failed (unknown key id, scheme, or MAC failure)",
            );
        }
    };
    if supi != supi_or_suci {
        log::info!("SIDF de-concealed SUCI {supi_or_suci} -> SUPI {supi}");
    }

    // Step 1: Query UDR for authentication subscription data (by SUPI)
    let udr_response = match crate::udm_nudr_dr_send_auth_subscription_get(&supi, 0, 0).await {
        Ok(resp) if resp.is_success() => resp,
        Ok(resp) if resp.status == 404 => {
            return send_problem(404, "USER_NOT_FOUND", "No authentication subscription");
        }
        Ok(resp) => {
            log::error!(
                "[{}] UDR auth subscription query failed: status={}",
                supi,
                resp.status
            );
            return nextgcore_sbi::server::send_service_unavailable("UDR query failed");
        }
        Err(e) => {
            log::error!("[{supi}] UDR auth subscription query failed: {e}");
            return nextgcore_sbi::server::send_service_unavailable("UDR unavailable");
        }
    };

    // Step 2: Parse authentication subscription from UDR response
    let auth_sub_json: serde_json::Value = match udr_response
        .http
        .content
        .as_deref()
        .and_then(|b| serde_json::from_str(b).ok())
    {
        Some(v) => v,
        None => {
            log::error!("[{supi}] Failed to parse UDR auth subscription response");
            return send_problem(500, "UNSPECIFIED", "Invalid UDR response");
        }
    };

    // Authentication method selects 5G-AKA or EAP-AKA' (TS 33.501 §6.1.2)
    let auth_method = auth_sub_json
        .get("authenticationMethod")
        .and_then(|v| v.as_str())
        .unwrap_or("5G_AKA");
    if auth_method != "5G_AKA" && auth_method != "EAP_AKA_PRIME" {
        return send_problem(
            501,
            "UNSUPPORTED_AUTHENTICATION_METHOD",
            &format!("Authentication method '{auth_method}' is not supported"),
        );
    }

    // Mandatory subscription material (TS 29.505 AuthenticationSubscription)
    let k_hex = auth_sub_json
        .get("encPermanentKey")
        .and_then(|v| v.as_str());
    let opc_hex = auth_sub_json.get("encOpcKey").and_then(|v| v.as_str());
    let amf_hex = auth_sub_json
        .get("authenticationManagementField")
        .and_then(|v| v.as_str());
    let sqn_hex = auth_sub_json
        .get("sequenceNumber")
        .and_then(|v| v.get("sqn"))
        .and_then(|v| v.as_str());
    let (k_hex, opc_hex, amf_hex, sqn_hex) = match (k_hex, opc_hex, amf_hex, sqn_hex) {
        (Some(k), Some(o), Some(a), Some(s)) => (k, o, a, s),
        _ => {
            log::error!("[{supi}] Authentication subscription missing mandatory fields");
            return send_problem(
                500,
                "UNSPECIFIED",
                "Authentication subscription incomplete (K/OPc/AMF/SQN)",
            );
        }
    };

    // Step 3: Create/update UE in context with subscriber keys from UDR
    let mut ue = {
        let ctx = udm_self();
        let context = ctx.read().unwrap();
        let ue = match context
            .ue_find_by_suci(supi_or_suci)
            .or_else(|| context.ue_find_by_supi(&supi))
            .or_else(|| context.ue_add(supi_or_suci))
        {
            Some(ue) => ue,
            None => {
                log::error!("[{supi}] Failed to create/find UE in context");
                return nextgcore_sbi::server::send_service_unavailable(
                    "UE context creation failed",
                );
            }
        };
        ue.clone()
    };

    ue.serving_network_name = Some(serving_network_name.to_string());
    ue.supi = Some(supi.clone());
    // TS 33.501 §6.14.2.1 / §6.15.2.1: SoR and UPU protection must be computed
    // by the AUSF that holds this UE's K_AUSF, i.e. the one that authenticated
    // it. That is the AUSF named here, so record it now — before #84 the IE was
    // validated and then dropped, leaving sor.rs / upu.rs to pick an arbitrary
    // AUSF and produce a MAC the UE cannot verify.
    ue.ausf_instance_id = Some(ausf_instance_id.to_string());

    let k_bytes = crate::nudm_handler::hex_to_bytes(k_hex);
    let opc_bytes = crate::nudm_handler::hex_to_bytes(opc_hex);
    let amf_bytes = crate::nudm_handler::hex_to_bytes(amf_hex);
    let sqn_bytes = crate::nudm_handler::hex_to_bytes(sqn_hex);
    if k_bytes.len() < 16 || opc_bytes.len() < 16 || amf_bytes.len() < 2 || sqn_bytes.len() < 6 {
        return send_problem(500, "UNSPECIFIED", "Malformed subscription key material");
    }
    ue.k.copy_from_slice(&k_bytes[..16]);
    ue.opc.copy_from_slice(&opc_bytes[..16]);
    ue.amf.copy_from_slice(&amf_bytes[..2]);
    ue.sqn.copy_from_slice(&sqn_bytes[..6]);

    // TS 33.501 §6.1.3 / TS 33.102 Annex H: the AMF "separation bit" (bit 0 of
    // the Authentication Management Field) shall be set to 1 for AVs usable in
    // 5G (EPS/5GS separation). Refuse to generate 5G AVs otherwise.
    if ue.amf[0] & 0x80 == 0 {
        log::error!("[{supi}] AMF separation bit not set in subscription (amf={amf_hex})");
        return send_problem(
            403,
            "AUTHENTICATION_REJECTED",
            "AMF separation bit (TS 33.102 Annex H) not set for 5G authentication",
        );
    }

    // Resynchronization (TS 33.102 §6.3.5): verify AUTS with f1*/f5* and
    // resume from SQN_MS.
    if let Some(resync) = auth_info.get("resynchronizationInfo") {
        let rand_hex = resync.get("rand").and_then(|v| v.as_str());
        let auts_hex = resync.get("auts").and_then(|v| v.as_str());
        let (rand_hex, auts_hex) = match (rand_hex, auts_hex) {
            (Some(r), Some(a)) if !r.is_empty() && !a.is_empty() => (r, a),
            _ => {
                return send_problem(
                    400,
                    "MANDATORY_IE_MISSING",
                    "resynchronizationInfo requires both rand and auts",
                )
            }
        };
        let rand_bytes = crate::nudm_handler::hex_to_bytes(rand_hex);
        let auts_bytes = crate::nudm_handler::hex_to_bytes(auts_hex);
        if rand_bytes.len() != 16
            || auts_bytes.len() != nextgcore_crypt::milenage::NEXTGCORE_AUTS_LEN
        {
            return send_problem(400, "INVALID_FORMAT", "Invalid RAND/AUTS length");
        }
        // The RAND echoed by the UE must be the one we sent
        if rand_bytes != ue.rand {
            log::error!("[{supi}] Resync RAND does not match stored RAND");
            return send_problem(400, "INVALID_FORMAT", "RAND mismatch in resynchronization");
        }
        let rand_arr: [u8; 16] = rand_bytes.as_slice().try_into().expect("len checked");
        let mut conc_sqn_ms = [0u8; 6];
        conc_sqn_ms.copy_from_slice(&auts_bytes[..6]);
        let (sqn_ms, mac_s) = match nextgcore_crypt::kdf::nextgcore_auc_sqn(
            &ue.opc,
            &ue.k,
            &rand_arr,
            &conc_sqn_ms,
        ) {
            Ok(r) => r,
            Err(e) => {
                log::error!("[{supi}] SQN extraction failed: {e:?}");
                return send_problem(500, "UNSPECIFIED", "SQN extraction failed");
            }
        };
        if mac_s != auts_bytes[6..nextgcore_crypt::milenage::NEXTGCORE_AUTS_LEN] {
            log::error!("[{supi}] AUTS MAC-S verification failed");
            return send_problem(
                403,
                "AUTHENTICATION_REJECTED",
                "AUTS MAC-S verification failed",
            );
        }
        // Resume from SQN_MS + 1 (prevents replay)
        let mut sqn_val: u64 = 0;
        for &b in sqn_ms.iter() {
            sqn_val = (sqn_val << 8) | (b as u64);
        }
        let new_sqn = (sqn_val + 1) & 0xFFFF_FFFF_FFFF;
        for (i, b) in ue.sqn.iter_mut().enumerate() {
            *b = ((new_sqn >> ((5 - i) * 8)) & 0xFF) as u8;
        }
        log::info!("[{supi}] SQN resynchronized (new SQN=0x{new_sqn:012x})");
    }

    // Step 4: Generate RAND and compute the AV with Milenage
    let mut rand = [0u8; 16];
    nextgcore_core::rand::nextgcore_random(&mut rand);
    ue.rand = rand;

    let (autn, ik, ck, _ak, res) =
        match nextgcore_crypt::milenage::milenage_generate(&ue.opc, &ue.amf, &ue.k, &ue.sqn, &rand)
        {
            Ok(result) => result,
            Err(e) => {
                log::error!("[{supi}] Milenage generate failed: {e:?}");
                return nextgcore_sbi::server::send_internal_error("Milenage computation failed");
            }
        };

    // Step 5: Update UE context
    {
        let ctx = udm_self();
        let context = ctx.read().unwrap();
        context.ue_update(&ue);
        context.ue_set_supi(ue.id, &supi);
    }

    // Step 6: Advance SQN per TS 33.102 Annex C.3.2 (udmd-10) and persist to
    // UDR. If UDR PATCH fails we cannot issue the AV (it would replay).
    let sqn_arr: [u8; 6] = ue.sqn.as_slice().try_into().expect("sqn is 6 bytes");
    let new_sqn_arr = advance_sqn_ind(sqn_arr);
    let new_sqn_hex: String = new_sqn_arr.iter().map(|b| format!("{b:02x}")).collect();
    match crate::udm_nudr_dr_send_auth_subscription_patch(&supi, &new_sqn_hex, 0, 0).await {
        Ok(r) if r.is_success() || r.status == 204 => {
            log::debug!("[{supi}] SQN advanced to 0x{new_sqn_hex}");
        }
        Ok(r) => {
            // ANY failed advance withholds the AV, not only a 5xx (#84).
            //
            // The stored SQN is re-read from UDR on every call, so an
            // unpersisted advance means the NEXT authentication computes an AV
            // from the SAME SQN — the reuse TS 33.102 §6.3.2 exists to prevent,
            // and a replay window for anyone holding the earlier AV. A 404 is
            // the likeliest such status and the least alarming-looking, which
            // is exactly why it was the one being tolerated.
            log::error!(
                "[{supi}] UDR SQN PATCH returned {}: refusing to issue AV (SQN not advanced)",
                r.status
            );
            return nextgcore_sbi::server::send_service_unavailable("UDR SQN update failed");
        }
        Err(e) => {
            // Transport failure: refuse to issue AV to prevent SQN replay.
            log::error!("[{supi}] UDR SQN PATCH failed: {e} — refusing to issue AV");
            return nextgcore_sbi::server::send_service_unavailable("UDR unavailable");
        }
    }

    // Step 7: Build the AuthenticationInfoResult (TS 29.503 §6.3.6.2.2)
    use crate::nudm_handler::bytes_to_hex;
    match auth_method {
        "EAP_AKA_PRIME" => {
            // TS 33.501 §6.1.3.1: the UDM/ARPF derives CK'/IK' and returns the
            // transformed AV (RAND, AUTN, XRES, CK', IK') to the AUSF.
            let mut sqn_xor_ak = [0u8; 6];
            sqn_xor_ak.copy_from_slice(&autn[..6]);
            let (ck_prime, ik_prime) = nextgcore_crypt::kdf::nextgcore_kdf_ck_ik_prime(
                &ck,
                &ik,
                serving_network_name,
                &sqn_xor_ak,
            );
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "authType": "EAP_AKA_PRIME",
                    "authenticationVector": {
                        "avType": "EAP_AKA_PRIME",
                        "rand": bytes_to_hex(&rand),
                        "autn": bytes_to_hex(&autn),
                        "xres": bytes_to_hex(&res),
                        "ckPrime": bytes_to_hex(&ck_prime),
                        "ikPrime": bytes_to_hex(&ik_prime)
                    },
                    "supi": supi
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        _ => {
            // 5G-AKA: derive KAUSF and XRES* (TS 33.501 Annex A.2/A.4)
            let kausf =
                nextgcore_crypt::kdf::nextgcore_kdf_kausf(&ck, &ik, serving_network_name, &autn);
            let xres_star = nextgcore_crypt::kdf::nextgcore_kdf_xres_star(
                &ck,
                &ik,
                serving_network_name,
                &rand,
                &res,
            );
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "authType": "5G_AKA",
                    "authenticationVector": {
                        "avType": "5G_HE_AKA",
                        "rand": bytes_to_hex(&rand),
                        "autn": bytes_to_hex(&autn),
                        "xresStar": bytes_to_hex(&xres_star),
                        "kausf": bytes_to_hex(&kausf)
                    },
                    "supi": supi
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
    }
}

pub async fn handle_auth_event(supi: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("Auth Event: SUPI={supi}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let auth_event: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    // TS 29.503: AuthEvent mandatory attributes are nfInstanceId, success,
    // timeStamp, authType and servingNetworkName.
    for attr in [
        "nfInstanceId",
        "timeStamp",
        "authType",
        "servingNetworkName",
    ] {
        if auth_event
            .get(attr)
            .and_then(|v| v.as_str())
            .map(|s| s.is_empty())
            .unwrap_or(true)
        {
            return send_problem(
                400,
                "MANDATORY_IE_MISSING",
                &format!("AuthEvent.{attr} is missing"),
            );
        }
    }
    let success = match auth_event.get("success").and_then(|v| v.as_bool()) {
        Some(s) => s,
        None => return send_problem(400, "MANDATORY_IE_MISSING", "AuthEvent.success is missing"),
    };

    log::info!("Auth Event: success={success}");

    // The identifier of the AuthEvent resource this operation creates. Minted
    // before the context write so the SAME value is both stored and returned in
    // `Location`: DeleteAuth (TS 29.503 §5.4.2.3.3) addresses the UE by it, and
    // a value that was only ever put in a header can never be matched again.
    let event_id = uuid::Uuid::new_v4().to_string();

    // Record the auth event in the local UE context.
    {
        let ctx = udm_self();
        if let Ok(context) = ctx.read() {
            if let Some(mut ue) = context.ue_find_by_supi(supi) {
                ue.auth_event_id = Some(event_id.clone());
                ue.set_auth_event(crate::AuthEvent {
                    nf_instance_id: auth_event
                        .get("nfInstanceId")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    success,
                    time_stamp: auth_event
                        .get("timeStamp")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    auth_type: None,
                    serving_network_name: auth_event
                        .get("servingNetworkName")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                });
                context.ue_update(&ue);
            }
        };
    }

    // udmd-09: PUT the AuthEvent to UDR authentication-status (TS 29.505
    // §6.3.3 / TS 29.503 §5.4.2). Best-effort: log but do not fail the
    // 201 if UDR is unavailable (matched-sim has no udrd auth-status resource).
    match crate::udm_nudr_dr_send_auth_status_put(supi, &auth_event).await {
        Ok(r) if r.is_success() => {
            log::debug!("[{supi}] Auth status persisted to UDR ({})", r.status);
        }
        Ok(r) => {
            log::warn!(
                "[{supi}] UDR auth-status PUT returned {} (degraded)",
                r.status
            );
        }
        Err(e) => {
            log::warn!("[{supi}] UDR auth-status PUT failed: {e} (degraded)");
        }
    }

    SbiResponse::with_status(201)
        .with_header(
            "Location",
            format!("/nudm-ueau/v1/{supi}/auth-events/{event_id}"),
        )
        .with_json_body(&serde_json::json!({
            "nfInstanceId": auth_event.get("nfInstanceId"),
            "success": success,
            "timeStamp": auth_event.get("timeStamp"),
            "authType": auth_event.get("authType"),
            "servingNetworkName": auth_event.get("servingNetworkName"),
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// `PUT /nudm-ueau/v1/{supi}/auth-events/{authEventId}` — TS 29.503 §5.4.2.3.3
/// `DeleteAuth`: the AUSF revokes the authentication result the UDM stored on
/// `ConfirmAuth`.
///
/// `authEventId` must be the identifier the UDM handed out in the `ConfirmAuth`
/// `Location` header. A mismatch is a **404**, not a silent success: the AUSF is
/// addressing a resource this UDM does not hold, and answering 204 would tell it
/// an authentication result was revoked while the real one stayed.
pub async fn handle_delete_auth(
    supi: &str,
    auth_event_id: &str,
    request: &SbiRequest,
) -> SbiResponse {
    log::info!("Delete Auth: SUPI={supi} authEventId={auth_event_id}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let auth_event: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };
    // The request body is a mandatory AuthEvent, so it is validated to the same
    // standard as ConfirmAuth's rather than accepted unread.
    for attr in [
        "nfInstanceId",
        "timeStamp",
        "authType",
        "servingNetworkName",
    ] {
        if auth_event
            .get(attr)
            .and_then(|v| v.as_str())
            .map(|s| s.is_empty())
            .unwrap_or(true)
        {
            return send_problem(
                400,
                "MANDATORY_IE_MISSING",
                &format!("AuthEvent.{attr} is missing"),
            );
        }
    }
    if auth_event
        .get("success")
        .and_then(|v| v.as_bool())
        .is_none()
    {
        return send_problem(400, "MANDATORY_IE_MISSING", "AuthEvent.success is missing");
    }

    // Match the addressed resource against the identifier ConfirmAuth issued.
    let mut stored_id: Option<String> = None;
    {
        let ctx = udm_self();
        if let Ok(context) = ctx.read() {
            stored_id = context
                .ue_find_by_supi(supi)
                .and_then(|ue| ue.auth_event_id.clone());
        };
    }
    if stored_id.as_deref() != Some(auth_event_id) {
        log::warn!("[{supi}] DeleteAuth for unknown authEventId {auth_event_id} — 404");
        return send_problem(
            404,
            "CONTEXT_NOT_FOUND",
            "No authentication event with this authEventId",
        );
    }

    // Drop the local authentication result and the pinned identifier, so a
    // replayed DeleteAuth for the same id now finds nothing (single-use).
    {
        let ctx = udm_self();
        if let Ok(context) = ctx.read() {
            if let Some(mut ue) = context.ue_find_by_supi(supi) {
                ue.clear_auth_event();
                ue.auth_event_id = None;
                context.ue_update(&ue);
            }
        };
    }

    // The authentication status lives in the UDR (TS 29.505 §6.3.3), so the
    // revocation has to reach it too. Best-effort, matching the ConfirmAuth
    // write it undoes: a UDR without the resource must not make the AUSF
    // believe the local revocation above did not happen.
    match crate::udm_nudr_dr_send_auth_status_delete(supi).await {
        Ok(r) if r.is_success() => {
            log::debug!("[{supi}] Auth status deleted in UDR ({})", r.status);
        }
        Ok(r) => log::warn!(
            "[{supi}] UDR auth-status DELETE returned {} (degraded)",
            r.status
        ),
        Err(e) => log::warn!("[{supi}] UDR auth-status DELETE failed: {e} (degraded)"),
    }

    SbiResponse::with_status(204)
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

/// Async main event loop with timer integration
async fn run_event_loop_async(udm_sm: &mut UdmSmContext, shutdown: Arc<AtomicBool>) -> Result<()> {
    log::debug!("Entering async main event loop");

    let timer_mgr = timer_manager();

    while !shutdown.load(Ordering::SeqCst) && !SHUTDOWN.load(Ordering::SeqCst) {
        // Poll with a reasonable interval
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Process timer expirations and dispatch to state machine
        let expired = timer_mgr.process_expired();
        for entry in expired {
            log::debug!(
                "UDM timer expired: id={} type={:?} data={:?}",
                entry.id,
                entry.timer_type,
                entry.data
            );

            // Convert UdmTimerType to UdmTimerId for event dispatch
            if let Some(timer_id) = timer_type_to_timer_id(entry.timer_type) {
                let mut event = UdmEvent::sbi_timer(timer_id);
                if let Some(nf_data) = entry.data {
                    event = event.with_nf_instance(nf_data.to_string());
                }

                udm_sm.dispatch(&mut event);
            }
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

/// Register UDM with NRF.
///
/// Returns the NF instance ID on success so the caller can start a heartbeat
/// worker.
async fn register_with_nrf(sbi_addr: &str, sbi_port: u16) -> Result<String, String> {
    let nf_instance_id = uuid::Uuid::new_v4().to_string();
    register_with_nrf_id(&nf_instance_id, sbi_addr, sbi_port).await
}

/// Register — or, for the issue #22 NES resume path, RE-register — the UDM
/// with the NRF under a caller-supplied NF instance ID. Returns the ID
/// actually registered, or an empty string when no NRF is configured
/// (registration skipped, matching the historical behavior).
/// Build the UDM's NFProfile for NRF registration (TS 29.510 §6.1.6.2.2).
///
/// Delegates to [`crate::sbi_path::build_udm_nf_profile`], which is the single
/// source of truth for the advertised service list: #85 removed the second,
/// divergent builder that lived here (it advertised `nudm-sdm` at one version
/// while `sbi_path.rs` used another, and neither advertised `nudm-ee`). Kept as a
/// wrapper because the operator knobs come from the process-global context,
/// which the callers here already have and the library builder should not reach
/// into.
fn build_udm_nf_profile(nf_instance_id: &str, sbi_addr: &str, sbi_port: u16) -> serde_json::Value {
    let config = udm_self()
        .read()
        .map(|ctx| ctx.nf_profile_config())
        .unwrap_or_default();
    crate::sbi_path::build_udm_nf_profile(nf_instance_id, sbi_addr, sbi_port, &config)
}

pub(crate) async fn register_with_nrf_id(
    nf_instance_id: &str,
    sbi_addr: &str,
    sbi_port: u16,
) -> Result<String, String> {
    let sbi_ctx = nextgcore_sbi::context::global_context();

    let nrf_uri = sbi_ctx.get_nrf_uri().await;
    let nrf_uri = match nrf_uri {
        Some(uri) => uri,
        None => {
            log::debug!("No NRF URI configured, skipping NRF registration");
            return Ok(String::new());
        }
    };

    log::info!("Registering UDM with NRF at {nrf_uri}");

    let (nrf_host, nrf_port) = parse_nrf_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_profile = build_udm_nf_profile(nf_instance_id, sbi_addr, sbi_port);

    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    let response = client
        .put_json(&path, &nf_profile)
        .await
        .map_err(|e| format!("NRF registration request failed: {e}"))?;

    match response.status {
        200 | 201 => {
            log::info!("UDM registered with NRF successfully (id={nf_instance_id})");
            Ok(nf_instance_id.to_string())
        }
        _ => Err(format!(
            "NRF registration returned status {}",
            response.status
        )),
    }
}

/// Parse host and port from a URI string (e.g., "http://localhost:7777").
pub(crate) fn parse_nrf_host_port(uri: &str) -> Option<(String, u16)> {
    let without_scheme = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    let (host_port, _) = without_scheme
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Pull the advertised `apiVersionInUri` for one service out of an NFProfile.
    fn advertised_version(profile: &serde_json::Value, service_name: &str) -> String {
        profile["nfServices"]
            .as_array()
            .expect("nfServices must be an array")
            .iter()
            .find(|s| s["serviceName"] == service_name)
            .unwrap_or_else(|| panic!("{service_name} must be registered"))["versions"][0]
            ["apiVersionInUri"]
            .as_str()
            .expect("apiVersionInUri must be a string")
            .to_string()
    }

    #[test]
    fn test_nrf_profile_advertises_nudm_sdm_at_v2() {
        // TS 29.503 §6.1.1: "The <apiVersion> shall be v2" for Nudm_SDM, while
        // Nudm_UECM and Nudm_UEAU are v1.
        //
        // Regression: this profile advertised nudm-sdm at v1. Because the live
        // router discards the version segment (`let _version = parts[1]`), the
        // mismatch was invisible between our own NFs but would 404 against a
        // strict v2 producer, and discovery handed consumers the wrong URI.
        let profile = build_udm_nf_profile("udm-test-instance", "10.45.0.10", 7777);

        assert_eq!(
            advertised_version(&profile, "nudm-sdm"),
            "v2",
            "Nudm_SDM must be advertised at v2 per TS 29.503 6.1.1"
        );
        assert_eq!(advertised_version(&profile, "nudm-uecm"), "v1");
        assert_eq!(advertised_version(&profile, "nudm-ueau"), "v1");

        // apiFullVersion must agree with the URI version, not lag it.
        let sdm = profile["nfServices"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["serviceName"] == "nudm-sdm")
            .unwrap();
        assert_eq!(sdm["versions"][0]["apiFullVersion"], "2.0.0");
    }

    #[test]
    fn test_split_snpn_supi() {
        // SNPN (Rel-17, TS 23.501 §5.30): a NID-scoped SUPI splits into the
        // base SUPI (UDR key) and the NID; a plain SUPI is unchanged.
        assert_eq!(
            split_snpn_supi("imsi-999700000000001:nid-7AB01234567"),
            ("imsi-999700000000001", Some("7AB01234567"))
        );
        assert_eq!(
            split_snpn_supi("imsi-999700000000001"),
            ("imsi-999700000000001", None)
        );
    }

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-udmd"]);
        assert_eq!(args.config, "/etc/nextgcore/udm.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 7777);
        assert!(!args.tls);
        assert_eq!(args.max_ue, 1024);
        assert_eq!(args.max_sess, 4096);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-udmd",
            "-c",
            "/custom/udm.yaml",
            "-e",
            "debug",
            "--sbi-addr",
            "0.0.0.0",
            "--sbi-port",
            "8080",
            "--max-ue",
            "2048",
            "--max-sess",
            "8192",
        ]);
        assert_eq!(args.config, "/custom/udm.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 8080);
        assert_eq!(args.max_ue, 2048);
        assert_eq!(args.max_sess, 8192);
    }

    #[test]
    fn test_args_tls() {
        let args = Args::parse_from([
            "nextgcore-udmd",
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
    fn test_validate_serving_network_name() {
        assert!(validate_serving_network_name(
            "5G:mnc001.mcc001.3gppnetwork.org"
        ));
        assert!(!validate_serving_network_name(
            "mnc001.mcc001.3gppnetwork.org"
        ));
        assert!(!validate_serving_network_name(
            "5G:mnc01.mcc001.3gppnetwork.org"
        ));
        assert!(!validate_serving_network_name("5G:mnc001.mcc001.evil.org"));
    }

    #[test]
    fn test_load_hnet_key() {
        // Inline hex
        let key = load_hnet_key("c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d")
            .unwrap();
        assert_eq!(key.len(), 32);
        // Bad hex / wrong length / missing file
        assert!(load_hnet_key("deadbeef").is_none());
        assert!(load_hnet_key("/nonexistent/path/key.hex").is_none());
        // Hex in file
        let dir = std::env::temp_dir().join("udm-hnet-test");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("k1.key");
        std::fs::write(
            &f,
            "c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d\n",
        )
        .unwrap();
        assert_eq!(load_hnet_key(f.to_str().unwrap()).unwrap().len(), 32);
    }

    // ========================================================================
    // HTTP-level UDM auth flow against a spec-shaped mock UDR
    // (TS 29.503 generate-auth-data; SUCI deconcealment; resync; ProblemDetails)
    // ========================================================================

    const TEST_K_HEX: &str = "465B5CE8B199B49FAA5F0A2EE238A6BC";
    const TEST_OPC_HEX: &str = "E8ED289DEBA952E4283B54E88E6183CA";
    const SUPI_AKA: &str = "imsi-001010000000001";
    const SUPI_EAP: &str = "imsi-001010000000002";
    const SUPI_BAD_AMF: &str = "imsi-001010000000003";
    const TEST_SNN: &str = "5G:mnc001.mcc001.3gppnetwork.org";

    /// Mock UDR: serves authentication-subscription GET/PATCH per TS 29.505.
    async fn mock_udr_handler(request: SbiRequest) -> SbiResponse {
        let method = request.header.method.clone();
        let uri = request.header.uri.clone();
        let path = uri.split('?').next().unwrap_or(&uri).to_string();

        if !path.contains("authentication-subscription") {
            return SbiResponse::with_status(404);
        }
        if method == "PATCH" {
            return SbiResponse::with_status(204);
        }

        // /nudr-dr/v2/subscription-data/{supi}/authentication-data/...
        let supi = path
            .trim_start_matches('/')
            .split('/')
            .nth(3)
            .unwrap_or("")
            .to_string();
        if !supi.starts_with("imsi-00101") {
            return SbiResponse::with_status(404);
        }

        let auth_method = if supi == SUPI_EAP {
            "EAP_AKA_PRIME"
        } else {
            "5G_AKA"
        };
        // SUPI_BAD_AMF is provisioned without the AMF separation bit
        let amf = if supi == SUPI_BAD_AMF { "0000" } else { "8000" };

        SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({
                "authenticationMethod": auth_method,
                "encPermanentKey": TEST_K_HEX,
                "encOpcKey": TEST_OPC_HEX,
                "authenticationManagementField": amf,
                "sequenceNumber": { "sqn": "000000000021", "sqnScheme": "NON_TIME_BASED" }
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(500))
    }

    /// Reserve a loopback port for a test server.
    ///
    /// Delegates to the shared helper: 21 crates each had a private
    /// probe-and-drop copy of this, which is TOCTOU and flaked under parallel
    /// `cargo test`. One implementation means one place to harden.
    fn free_port() -> u16 {
        nextgcore_sbi::test_support::free_port()
    }

    fn unhex(s: &str) -> Vec<u8> {
        crate::nudm_handler::hex_to_bytes(s)
    }

    /// Full HTTP-level UDM auth flow: strict rejections, null-scheme + Profile
    /// A SUCI deconcealment, 5G-AKA + EAP-AKA' AV generation, AMF separation
    /// bit enforcement, and AUTS resynchronization.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state (current-thread test)
    async fn test_http_generate_auth_data_flows() {
        // Drives production peer-call code against a loopback PLAINTEXT peer, i.e. a
        // dev-profile deployment (issue #63). Declared rather than inherited.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        // Serialize on udmd's global-context/UDR-env guard: this test re-inits
        // the process-global UDM context and/or sets UDR_SBI_* env vars, which
        // races any other udmd test doing the same (the CI-flaky AUTS-resync).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _ = env_logger::try_init();
        tokio::time::timeout(Duration::from_secs(60), async {
            udm_context_init(64, 64);

            // Provision a Profile A home network key (id=1)
            let hn_priv = [0x42u8; 32];
            {
                let ctx = udm_self();
                let context = ctx.read().unwrap();
                context.hnet_key_add(1, 1, hn_priv.to_vec());
            }

            // --- mock UDR on an ephemeral port ---
            let udr_port = free_port();
            let udr_server = SbiServer::new(NextgcoreSbiServerConfig::new(SocketAddr::from((
                [127, 0, 0, 1],
                udr_port,
            ))));
            udr_server.start(mock_udr_handler).await.expect("udr start");
            std::env::set_var("UDR_SBI_ADDR", "127.0.0.1");
            std::env::set_var("UDR_SBI_PORT", udr_port.to_string());

            // --- real UDM handler on an ephemeral port ---
            let udm_port = free_port();
            let udm_server = SbiServer::new(NextgcoreSbiServerConfig::new(SocketAddr::from((
                [127, 0, 0, 1],
                udm_port,
            ))));
            udm_server
                .start(udm_sbi_request_handler)
                .await
                .expect("udm start");

            let client = nextgcore_sbi::client::SbiClient::with_host_port("127.0.0.1", udm_port);
            let gen_path =
                |id: &str| format!("/nudm-ueau/v1/{id}/security-information/generate-auth-data");

            // ---- strict-peer rejections ----
            // Missing servingNetworkName -> 400 MANDATORY_IE_MISSING
            let resp = client
                .post_json(
                    &gen_path(SUPI_AKA),
                    &serde_json::json!({"ausfInstanceId": "test-ausf"}),
                )
                .await
                .expect("send");
            assert_eq!(resp.status, 400);
            let pd: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap();
            assert_eq!(
                pd.get("cause").and_then(|v| v.as_str()),
                Some("MANDATORY_IE_MISSING")
            );

            // Missing ausfInstanceId -> 400 MANDATORY_IE_MISSING
            let resp = client
                .post_json(
                    &gen_path(SUPI_AKA),
                    &serde_json::json!({"servingNetworkName": TEST_SNN}),
                )
                .await
                .expect("send");
            assert_eq!(resp.status, 400);

            // Malformed SNN -> 403 SERVING_NETWORK_NOT_AUTHORIZED
            let resp = client
                .post_json(
                    &gen_path(SUPI_AKA),
                    &serde_json::json!({
                        "servingNetworkName": "5G:mnc001.mcc001.evil.org",
                        "ausfInstanceId": "test-ausf"
                    }),
                )
                .await
                .expect("send");
            assert_eq!(resp.status, 403);
            let pd: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap();
            assert_eq!(
                pd.get("cause").and_then(|v| v.as_str()),
                Some("SERVING_NETWORK_NOT_AUTHORIZED")
            );

            let good_body = serde_json::json!({
                "servingNetworkName": TEST_SNN,
                "ausfInstanceId": "test-ausf"
            });

            // ---- 5G-AKA via null-scheme SUCI ----
            let null_suci = "suci-0-001-01-0000-0-0-0000000001";
            let resp = client
                .post_json(&gen_path(null_suci), &good_body)
                .await
                .expect("send");
            assert_eq!(resp.status, 200);
            let air: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().expect("body")).unwrap();
            assert_eq!(air.get("authType").and_then(|v| v.as_str()), Some("5G_AKA"));
            assert_eq!(
                air.get("supi").and_then(|v| v.as_str()),
                Some(SUPI_AKA),
                "null-scheme SUCI must deconceal to the SUPI"
            );
            let av = air.get("authenticationVector").expect("av");
            assert_eq!(av.get("avType").and_then(|v| v.as_str()), Some("5G_HE_AKA"));
            for field in ["rand", "autn", "xresStar", "kausf"] {
                assert!(av.get(field).is_some(), "missing {field}");
            }

            // Cross-check XRES*: recompute from RAND with the same credentials
            let rand_v = unhex(av.get("rand").and_then(|v| v.as_str()).unwrap());
            let mut rand = [0u8; 16];
            rand.copy_from_slice(&rand_v);
            let mut k = [0u8; 16];
            k.copy_from_slice(&unhex(TEST_K_HEX));
            let mut opc = [0u8; 16];
            opc.copy_from_slice(&unhex(TEST_OPC_HEX));
            let (res, ck, ik, _ak, _akstar) =
                nextgcore_crypt::milenage::milenage_f2345(&opc, &k, &rand).unwrap();
            let xres_star =
                nextgcore_crypt::kdf::nextgcore_kdf_xres_star(&ck, &ik, TEST_SNN, &rand, &res);
            assert_eq!(
                av.get("xresStar").and_then(|v| v.as_str()),
                Some(crate::nudm_handler::bytes_to_hex(&xres_star).as_str())
            );

            // ---- AUTS resynchronization (uses the RAND from the AV above) ----
            // UE side: SQN_MS=0x000000000050, AUTS = (SQN_MS xor AK*) || MAC-S
            let sqn_ms = [0u8, 0, 0, 0, 0, 0x50];
            let (_r, _c, _i, _a, akstar) =
                nextgcore_crypt::milenage::milenage_f2345(&opc, &k, &rand).unwrap();
            let mut conc = [0u8; 6];
            for i in 0..6 {
                conc[i] = sqn_ms[i] ^ akstar[i];
            }
            let (_mac_a, mac_s) =
                nextgcore_crypt::milenage::milenage_f1(&opc, &k, &rand, &sqn_ms, &[0, 0]).unwrap();
            let mut auts = Vec::new();
            auts.extend_from_slice(&conc);
            auts.extend_from_slice(&mac_s);

            let resync_body = serde_json::json!({
                "servingNetworkName": TEST_SNN,
                "ausfInstanceId": "test-ausf",
                "resynchronizationInfo": {
                    "rand": crate::nudm_handler::bytes_to_hex(&rand),
                    "auts": crate::nudm_handler::bytes_to_hex(&auts)
                }
            });
            let resp = client
                .post_json(&gen_path(null_suci), &resync_body)
                .await
                .expect("send");
            assert_eq!(resp.status, 200, "valid AUTS resync must succeed");

            // Tampered AUTS (MAC-S broken) -> 403 AUTHENTICATION_REJECTED
            // (use the new RAND from the resync response)
            let air2: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            let rand2 = unhex(
                air2.pointer("/authenticationVector/rand")
                    .and_then(|v| v.as_str())
                    .unwrap(),
            );
            let mut bad_auts = auts.clone();
            bad_auts[13] ^= 0xFF;
            let bad_resync = serde_json::json!({
                "servingNetworkName": TEST_SNN,
                "ausfInstanceId": "test-ausf",
                "resynchronizationInfo": {
                    "rand": crate::nudm_handler::bytes_to_hex(&rand2),
                    "auts": crate::nudm_handler::bytes_to_hex(&bad_auts)
                }
            });
            let resp = client
                .post_json(&gen_path(null_suci), &bad_resync)
                .await
                .expect("send");
            assert_eq!(resp.status, 403, "broken AUTS MAC-S must be rejected");

            // ---- Profile A concealed SUCI ----
            // Conceal MSIN 0000000001 with the provisioned key (TBCD nibbles)
            let msin_bcd = [0x00u8, 0x00, 0x00, 0x00, 0x10]; // "0000000001" swapped nibbles
            let hn_pub = nextgcore_crypt::ecies::x25519_public_key(&hn_priv);
            let (eph_pub, ct, tag) =
                nextgcore_crypt::ecies::ecies_profile_a_encrypt(&hn_pub, &msin_bcd).unwrap();
            let mut scheme_output = Vec::new();
            scheme_output.extend_from_slice(&eph_pub);
            scheme_output.extend_from_slice(&ct);
            scheme_output.extend_from_slice(&tag);
            let so_hex = crate::nudm_handler::bytes_to_hex(&scheme_output);
            let prof_a_suci = format!("suci-0-001-01-0000-1-1-{so_hex}");

            let resp = client
                .post_json(&gen_path(&prof_a_suci), &good_body)
                .await
                .expect("send");
            assert_eq!(resp.status, 200);
            let air: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(
                air.get("supi").and_then(|v| v.as_str()),
                Some(SUPI_AKA),
                "Profile A SUCI must deconceal to the SUPI"
            );

            // Unknown key id -> 403 AUTHENTICATION_REJECTED
            let unknown_key_suci = format!("suci-0-001-01-0000-1-9-{so_hex}");
            let resp = client
                .post_json(&gen_path(&unknown_key_suci), &good_body)
                .await
                .expect("send");
            assert_eq!(resp.status, 403);

            // ---- EAP-AKA' AV ----
            let resp = client
                .post_json(&gen_path(SUPI_EAP), &good_body)
                .await
                .expect("send");
            assert_eq!(resp.status, 200);
            let air: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(
                air.get("authType").and_then(|v| v.as_str()),
                Some("EAP_AKA_PRIME")
            );
            let av = air.get("authenticationVector").expect("av");
            assert_eq!(
                av.get("avType").and_then(|v| v.as_str()),
                Some("EAP_AKA_PRIME")
            );
            for field in ["rand", "autn", "xres", "ckPrime", "ikPrime"] {
                assert!(av.get(field).is_some(), "missing {field}");
            }
            // Cross-check CK': recompute from RAND/AUTN
            let rand_v = unhex(av.get("rand").and_then(|v| v.as_str()).unwrap());
            let autn_v = unhex(av.get("autn").and_then(|v| v.as_str()).unwrap());
            let mut rand = [0u8; 16];
            rand.copy_from_slice(&rand_v);
            let (_res, ck, ik, _ak, _akstar) =
                nextgcore_crypt::milenage::milenage_f2345(&opc, &k, &rand).unwrap();
            let mut sqn_xor_ak = [0u8; 6];
            sqn_xor_ak.copy_from_slice(&autn_v[..6]);
            let (ck_prime, _ik_prime) =
                nextgcore_crypt::kdf::nextgcore_kdf_ck_ik_prime(&ck, &ik, TEST_SNN, &sqn_xor_ak);
            assert_eq!(
                av.get("ckPrime").and_then(|v| v.as_str()),
                Some(crate::nudm_handler::bytes_to_hex(&ck_prime).as_str())
            );

            // ---- AMF separation bit not set -> 403 ----
            let resp = client
                .post_json(&gen_path(SUPI_BAD_AMF), &good_body)
                .await
                .expect("send");
            assert_eq!(
                resp.status, 403,
                "subscription without AMF separation bit must be rejected"
            );

            // ---- auth-events strict validation ----
            let resp = client
                .post_json(
                    &format!("/nudm-ueau/v1/{SUPI_AKA}/auth-events"),
                    &serde_json::json!({
                        "nfInstanceId": "test-ausf",
                        "success": true,
                        "authType": "5G_AKA",
                        "servingNetworkName": TEST_SNN
                        // timeStamp missing
                    }),
                )
                .await
                .expect("send");
            assert_eq!(resp.status, 400, "AuthEvent without timeStamp -> 400");

            let resp = client
                .post_json(
                    &format!("/nudm-ueau/v1/{SUPI_AKA}/auth-events"),
                    &serde_json::json!({
                        "nfInstanceId": "test-ausf",
                        "success": true,
                        "timeStamp": "2026-01-01T00:00:00Z",
                        "authType": "5G_AKA",
                        "servingNetworkName": TEST_SNN
                    }),
                )
                .await
                .expect("send");
            assert_eq!(resp.status, 201);

            udm_server.stop().await.expect("stop udm");
            udr_server.stop().await.expect("stop udr");
        })
        .await
        .expect("test timed out");
    }

    // ========================================================================
    // udmd-10: SQN SEQ/IND-split advance (TS 33.102 Annex C.3.2)
    // ========================================================================

    #[test]
    fn test_advance_sqn_ind_seq_increments_ind_preserved() {
        // Zero SQN → SEQ=0,IND=0 → advance → SEQ=1,IND=0 = 0x20
        assert_eq!(
            advance_sqn_ind([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x20]
        );

        // SEQ=1,IND=0 (0x20=32) → SEQ=2,IND=0 (0x40=64)
        assert_eq!(
            advance_sqn_ind([0x00, 0x00, 0x00, 0x00, 0x00, 0x20]),
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x40]
        );

        // SEQ=1,IND=5 (0x25=37) → SEQ=2,IND=5 (0x45=69); IND preserved
        assert_eq!(
            advance_sqn_ind([0x00, 0x00, 0x00, 0x00, 0x00, 0x25]),
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x45]
        );

        // Typical SQN 0x000000000021 (SQN from test UDR: "000000000021"):
        // SEQ=1, IND=1 → advance → SEQ=2,IND=1 = 0x41
        let mut sqn = [0u8; 6];
        let v: u64 = 0x000000000021;
        for (i, b) in sqn.iter_mut().enumerate() {
            *b = ((v >> ((5 - i) * 8)) & 0xFF) as u8;
        }
        let adv = advance_sqn_ind(sqn);
        let result: u64 = adv.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
        // SEQ advances by 1 (bit 5+), IND stays the same.
        let orig_ind = v & 0x1F;
        let adv_seq = (v >> 5) + 1;
        assert_eq!(result, (adv_seq << 5) | orig_ind);
    }

    // ========================================================================
    // udmd-12: send_not_implemented helper
    // ========================================================================

    #[test]
    fn test_send_not_implemented_returns_501_with_cause() {
        let resp = send_not_implemented("test resource not implemented");
        assert_eq!(resp.status, 501);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap();
        assert_eq!(
            body.get("cause").and_then(|v| v.as_str()),
            Some("NOT_IMPLEMENTED")
        );
        assert_eq!(body.get("status").and_then(|v| v.as_u64()), Some(501));
    }

    // ========================================================================
    // udmd-08: sdm_query_params extracts only known SDM keys
    // ========================================================================

    #[test]
    fn test_sdm_query_params_extracts_known_keys_ignores_others() {
        use nextgcore_sbi::message::{SbiHeader, SbiHttpMessage, SbiRequest};

        let mut request = SbiRequest {
            header: SbiHeader::with_method_uri("GET", "/nudm-sdm/v2/imsi-x/am-data"),
            http: SbiHttpMessage::default(),
            ..Default::default()
        };

        // No params → empty map.
        assert!(sdm_query_params(&request).is_empty());

        // Known SDM keys are forwarded; unknown keys are not.
        request.http.params.insert(
            "plmn-id".to_string(),
            r#"{"mcc":"001","mnc":"01"}"#.to_string(),
        );
        request
            .http
            .params
            .insert("supported-features".to_string(), "ff".to_string());
        request
            .http
            .params
            .insert("irrelevant-param".to_string(), "ignored".to_string());

        let params = sdm_query_params(&request);
        assert_eq!(
            params.get("plmn-id").map(String::as_str),
            Some(r#"{"mcc":"001","mnc":"01"}"#)
        );
        assert_eq!(
            params.get("supported-features").map(String::as_str),
            Some("ff")
        );
        assert!(
            !params.contains_key("irrelevant-param"),
            "non-SDM params must not be forwarded to UDR"
        );
    }

    // ========================================================================
    // udmd-07: SDM subscribe persists; unsubscribe 404-on-missing
    // ========================================================================

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state (current-thread test)
    async fn test_sdm_subscribe_persists_and_unsubscribe_is_idempotent() {
        // Serialize on udmd's global-context/UDR-env guard: this test re-inits
        // the process-global UDM context and/or sets UDR_SBI_* env vars, which
        // races any other udmd test doing the same (the CI-flaky AUTS-resync).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _ = env_logger::try_init();
        use nextgcore_sbi::message::{SbiHeader, SbiHttpMessage, SbiRequest};

        udm_context_init(64, 64);
        let supi = "imsi-udmd07-0001";

        let request = SbiRequest {
            header: SbiHeader::with_method_uri(
                "POST",
                format!("/nudm-sdm/v2/{supi}/sdm-subscriptions"),
            ),
            http: SbiHttpMessage {
                content: Some(
                    serde_json::json!({
                        "nfInstanceId": "amf-test-001",
                        "callbackReference": "http://amf.example.org/sdm-notify",
                        "monitoredResourceUris": [
                            format!("/nudm-sdm/v2/{supi}/am-data")
                        ]
                    })
                    .to_string(),
                ),
                ..Default::default()
            },
            ..Default::default()
        };

        // Subscribe → 201 + Location header.
        let resp = handle_sdm_subscribe(supi, &request).await;
        assert_eq!(resp.status, 201, "subscribe must return 201");
        // set_header lowercases header keys (HTTP/2 convention).
        let loc = resp
            .http
            .headers
            .get("location")
            .cloned()
            .unwrap_or_default();
        assert!(loc.contains(supi), "Location must contain SUPI");
        assert!(
            loc.contains("sdm-subscriptions"),
            "Location must reference sdm-subscriptions"
        );

        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap();
        let sub_id = body
            .get("subscriptionId")
            .and_then(|v| v.as_str())
            .expect("subscriptionId must be present in body")
            .to_string();

        // Subscription must be findable in context.
        {
            let ctx = udm_self();
            let context = ctx.read().unwrap();
            assert!(
                context.sdm_subscription_find_by_id(&sub_id).is_some(),
                "subscription must be stored in context after subscribe"
            );
        }

        // Unsubscribe with a bad id → 404 NOT_FOUND.
        let resp = handle_sdm_unsubscribe(supi, "nonexistent-uuid-0000").await;
        assert_eq!(resp.status, 404, "missing subscription must be 404");
        let pd: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap();
        assert_eq!(
            pd.get("cause").and_then(|v| v.as_str()),
            Some("NOT_FOUND"),
            "cause must be NOT_FOUND"
        );

        // Unsubscribe with the real id → 204.
        let resp = handle_sdm_unsubscribe(supi, &sub_id).await;
        assert_eq!(resp.status, 204, "valid unsubscribe must return 204");

        // Must be removed from context.
        {
            let ctx = udm_self();
            let context = ctx.read().unwrap();
            assert!(
                context.sdm_subscription_find_by_id(&sub_id).is_none(),
                "subscription must be removed from context after unsubscribe"
            );
        }
    }

    // ========================================================================
    // udmd-09: auth-event handler returns 201 + Location header (TS 29.503 §5.4)
    // ========================================================================

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state (current-thread test)
    async fn test_auth_event_returns_201_with_location_header() {
        // Serialize on udmd's global-context/UDR-env guard: this test re-inits
        // the process-global UDM context and/or sets UDR_SBI_* env vars, which
        // races any other udmd test doing the same (the CI-flaky AUTS-resync).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _ = env_logger::try_init();
        use nextgcore_sbi::message::{SbiHeader, SbiHttpMessage, SbiRequest};

        udm_context_init(64, 64);
        let supi = "imsi-udmd09-0001";

        let request = SbiRequest {
            header: SbiHeader::with_method_uri("POST", format!("/nudm-ueau/v1/{supi}/auth-events")),
            http: SbiHttpMessage {
                content: Some(
                    serde_json::json!({
                        "nfInstanceId": "ausf-0001",
                        "success": true,
                        "timeStamp": "2026-01-01T00:00:00Z",
                        "authType": "5G_AKA",
                        "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org"
                    })
                    .to_string(),
                ),
                ..Default::default()
            },
            ..Default::default()
        };

        let resp = handle_auth_event(supi, &request).await;
        assert_eq!(resp.status, 201, "auth-event must return 201");

        // udmd-09: Location header must reference the auth-events sub-resource.
        // set_header lowercases all keys (HTTP/2 convention).
        let loc = resp
            .http
            .headers
            .get("location")
            .cloned()
            .unwrap_or_default();
        assert!(
            loc.contains("auth-events"),
            "Location must reference auth-events resource; got: {loc}"
        );
        assert!(
            loc.starts_with("/nudm-ueau/v1/"),
            "Location must use nudm-ueau service path; got: {loc}"
        );
    }

    // ========================================================================
    // udmd#0: EE subscribe persists; unsubscribe 404-on-missing then 204
    // ========================================================================

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state (current-thread test)
    async fn test_ee_subscribe_persists_and_unsubscribe_404_then_204() {
        // Serialize on udmd's global-context/UDR-env guard: this test re-inits
        // the process-global UDM context and/or sets UDR_SBI_* env vars, which
        // races any other udmd test doing the same (the CI-flaky AUTS-resync).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _ = env_logger::try_init();
        use nextgcore_sbi::message::{SbiHeader, SbiHttpMessage, SbiRequest};
        udm_context_init(64, 64);
        let ue = "imsi-udmdee-0001";
        // Missing monitoringConfigurations -> 400 MANDATORY_IE_MISSING.
        let bad = SbiRequest {
            header: SbiHeader::with_method_uri(
                "POST",
                format!("/nudm-ee/v1/{ue}/ee-subscriptions"),
            ),
            http: SbiHttpMessage {
                content: Some(
                    serde_json::json!({"callbackReference":"http://nef.example.org/ee-notify"})
                        .to_string(),
                ),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(handle_ee_subscribe(ue, &bad).await.status, 400);
        // Valid -> 201 + Location + echoed eeSubscription.subscriptionId.
        let req = SbiRequest {
            header: SbiHeader::with_method_uri(
                "POST",
                format!("/nudm-ee/v1/{ue}/ee-subscriptions"),
            ),
            http: SbiHttpMessage {
                content: Some(
                    serde_json::json!({
                        "callbackReference": "http://nef.example.org/ee-notify",
                        "monitoringConfigurations": {"1": {}}
                    })
                    .to_string(),
                ),
                ..Default::default()
            },
            ..Default::default()
        };
        let resp = handle_ee_subscribe(ue, &req).await;
        assert_eq!(resp.status, 201);
        let loc = resp
            .http
            .headers
            .get("location")
            .cloned()
            .unwrap_or_default();
        assert!(loc.contains(ue) && loc.contains("ee-subscriptions"));
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap();
        let sub_id = body
            .get("eeSubscription")
            .and_then(|s| s.get("subscriptionId"))
            .and_then(|v| v.as_str())
            .expect("subscriptionId echoed")
            .to_string();
        assert_eq!(handle_ee_unsubscribe(ue, "nope-uuid").await.status, 404);
        assert_eq!(handle_ee_unsubscribe(ue, &sub_id).await.status, 204);
    }

    // ========================================================================
    // udmd#1: SoR/UPU ack requires provisioningTime, returns 204 on valid
    // ========================================================================

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state (current-thread test)
    async fn test_sor_upu_ack_requires_provisioning_time_then_204() {
        // Serialize on udmd's global-context/UDR-env guard: this test re-inits
        // the process-global UDM context and/or sets UDR_SBI_* env vars, which
        // races any other udmd test doing the same (the CI-flaky AUTS-resync).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        use nextgcore_sbi::message::{SbiHeader, SbiHttpMessage, SbiRequest};
        let supi = "imsi-udmdsor-0001";
        // Missing provisioningTime -> 400.
        let bad = SbiRequest {
            header: SbiHeader::with_method_uri(
                "PUT",
                format!("/nudm-sdm/v2/{supi}/am-data/sor-ack"),
            ),
            http: SbiHttpMessage {
                content: Some("{}".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(handle_sor_ack(supi, &bad).await.status, 400);
        // Valid SoR ack -> 204.
        let ok = SbiRequest {
            header: SbiHeader::with_method_uri(
                "PUT",
                format!("/nudm-sdm/v2/{supi}/am-data/sor-ack"),
            ),
            http: SbiHttpMessage {
                content: Some(
                    serde_json::json!({"provisioningTime": "2026-01-01T00:00:00Z"}).to_string(),
                ),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(handle_sor_ack(supi, &ok).await.status, 204);
        // Valid UPU ack -> 204.
        let ok_upu = SbiRequest {
            header: SbiHeader::with_method_uri(
                "PUT",
                format!("/nudm-sdm/v2/{supi}/am-data/upu-ack"),
            ),
            http: SbiHttpMessage {
                content: Some(
                    serde_json::json!({"provisioningTime": "2026-01-01T00:00:00Z"}).to_string(),
                ),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(handle_upu_ack(supi, &ok_upu).await.status, 204);
    }

    // ========================================================================
    // Wave-6 F-06: SoR/UPU ack MAC verification (TS 33.501 §6.14.2.1 steps
    // 13-15 / §6.15.2.1 step 9) — constant-time compare + single-use replay
    // defence + fail-closed on mismatch/unexpected ack. The ack MACs are
    // produced by the REAL F-01 KDF (nextgcore_crypt), never a canned string.
    // ========================================================================

    /// A known KAUSF the UE and the (test-seeded) UDM both hold.
    fn f06_kausf(seed: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = seed ^ (i as u8);
        }
        k
    }

    fn put_ack(supi: &str, resource: &str, body: serde_json::Value) -> SbiRequest {
        use nextgcore_sbi::message::{SbiHeader, SbiHttpMessage};
        SbiRequest {
            header: SbiHeader::with_method_uri(
                "PUT",
                format!("/nudm-sdm/v2/{supi}/am-data/{resource}"),
            ),
            http: SbiHttpMessage {
                content: Some(body.to_string()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// ct_compare is a genuine constant-time-style fold-XOR: equal → true,
    /// any single-bit difference → false, and a length mismatch → false.
    #[test]
    fn f06_ct_compare_behaviour() {
        let a = [0xAAu8; 16];
        assert!(ct_compare(&a, &a));
        let mut b = a;
        b[7] ^= 0x01;
        assert!(!ct_compare(&a, &b), "one flipped bit must fail");
        assert!(!ct_compare(&a[..8], &a), "length mismatch must fail");
        assert!(!ct_compare(&[], &a));
    }

    /// The handler compares the secret MAC with `ct_compare` (never a plain
    /// `==` on the byte slices) and clears the expected XMAC single-use — a
    /// mechanical grep-assert of the falsifiable acceptance line.
    #[test]
    fn f06_handler_uses_ct_compare_and_single_use_clear() {
        let src = include_str!("app.rs");
        assert!(
            src.contains("fn ct_compare("),
            "ct_compare helper must exist"
        );
        assert!(
            src.contains("ct_compare(&mac, &xmac)"),
            "handle_ack_info must compare via ct_compare, not =="
        );
        assert!(
            src.contains("Single-use: record the ack AND clear the expected XMAC"),
            "the single-use XMAC clear must be documented at the match site"
        );
    }

    /// SoR happy path: expected XMAC seeded (F-04 path) + correct SoR-MAC-I_UE
    /// (F-01 KDF) → 204, ack recorded, expected XMAC consumed; a SECOND identical
    /// PUT → 400 (single-use / replay defence).
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn f06_sor_ack_happy_then_replay_rejected() {
        // Serialize on the shared context guard: this test mutates the
        // process-global UDM context (udm_context_init/udm_self) and must
        // not interleave with other guarded tests (CI flake root cause).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        udm_context_init(64, 64);
        let supi = "imsi-f06sor-0001";
        let kausf = f06_kausf(0xB1);
        let counter = 0x0001u16;
        // The network's SoR-XMAC-I_UE == the UE's SoR-MAC-I_UE (both Annex A.18).
        let xmac = nextgcore_crypt::kdf::nextgcore_kdf_sor_mac_iue(&kausf, counter);
        assert!(udm_self()
            .read()
            .unwrap()
            .sor_store_expected_xmac(supi, xmac, counter));

        let mac_hex = crate::nudm_handler::bytes_to_hex(&xmac);
        let ok = put_ack(
            supi,
            "sor-ack",
            serde_json::json!({
                "provisioningTime": "2026-07-01T00:00:00Z",
                "sorMacIue": mac_hex,
            }),
        );
        assert_eq!(
            handle_sor_ack(supi, &ok).await.status,
            204,
            "valid MAC → 204"
        );

        // Ack state recorded + expected XMAC consumed (single-use).
        let ue = udm_self().read().unwrap().ue_find_by_supi(supi).unwrap();
        assert!(ue.sor_ack.is_some(), "ack state must be persisted");
        assert_eq!(ue.sor_ack.as_ref().unwrap().counter, Some(counter));
        assert!(!ue.sor_ack.as_ref().unwrap().ue_not_reachable);
        assert!(
            ue.expected_sor_xmac_iue.is_none(),
            "expected XMAC must be cleared"
        );

        // Replayed identical ack → 400 (nothing outstanding to compare).
        assert_eq!(
            handle_sor_ack(supi, &ok).await.status,
            400,
            "replayed ack must be rejected (single-use)"
        );
    }

    /// SoR wrong MAC: one flipped hex digit → 400 and NO ack state recorded,
    /// expected XMAC preserved (a 204 on a mismatched MAC would be a fail).
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn f06_sor_ack_wrong_mac_rejected_state_unchanged() {
        // Serialize on the shared context guard: this test mutates the
        // process-global UDM context (udm_context_init/udm_self) and must
        // not interleave with other guarded tests (CI flake root cause).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        udm_context_init(64, 64);
        let supi = "imsi-f06sor-0002";
        let kausf = f06_kausf(0x5C);
        let counter = 0x0002u16;
        let xmac = nextgcore_crypt::kdf::nextgcore_kdf_sor_mac_iue(&kausf, counter);
        assert!(udm_self()
            .read()
            .unwrap()
            .sor_store_expected_xmac(supi, xmac, counter));

        // Flip one bit of the MAC the UE sends.
        let mut wrong = xmac;
        wrong[0] ^= 0x01;
        let bad = put_ack(
            supi,
            "sor-ack",
            serde_json::json!({
                "provisioningTime": "2026-07-01T00:00:00Z",
                "sorMacIue": crate::nudm_handler::bytes_to_hex(&wrong),
            }),
        );
        assert_eq!(
            handle_sor_ack(supi, &bad).await.status,
            400,
            "wrong MAC → 400"
        );

        let ue = udm_self().read().unwrap().ue_find_by_supi(supi).unwrap();
        assert!(ue.sor_ack.is_none(), "mismatch must NOT record ack state");
        assert!(
            ue.expected_sor_xmac_iue.is_some(),
            "expected XMAC must survive a failed verify (still awaiting a valid ack)"
        );
    }

    /// Outstanding XMAC but the UE omits the MAC → 400 (the MAC is required to
    /// acknowledge a protected update); no ack recorded.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn f06_sor_ack_missing_mac_when_outstanding_rejected() {
        // Serialize on the shared context guard: this test mutates the
        // process-global UDM context (udm_context_init/udm_self) and must
        // not interleave with other guarded tests (CI flake root cause).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        udm_context_init(64, 64);
        let supi = "imsi-f06sor-0003";
        let xmac = nextgcore_crypt::kdf::nextgcore_kdf_sor_mac_iue(&f06_kausf(0x21), 0x0001);
        assert!(udm_self()
            .read()
            .unwrap()
            .sor_store_expected_xmac(supi, xmac, 0x0001));
        let bare = put_ack(
            supi,
            "sor-ack",
            serde_json::json!({"provisioningTime": "2026-07-01T00:00:00Z"}),
        );
        assert_eq!(handle_sor_ack(supi, &bare).await.status, 400);
        let ue = udm_self().read().unwrap().ue_find_by_supi(supi).unwrap();
        assert!(ue.sor_ack.is_none());
        assert!(ue.expected_sor_xmac_iue.is_some());
    }

    /// A MAC supplied with NO outstanding update → 400 (unexpected ack).
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn f06_sor_ack_unexpected_mac_rejected() {
        // Serialize on the shared context guard: this test mutates the
        // process-global UDM context (udm_context_init/udm_self) and must
        // not interleave with other guarded tests (CI flake root cause).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        udm_context_init(64, 64);
        let supi = "imsi-f06sor-0004";
        let mac = crate::nudm_handler::bytes_to_hex(&[0xAB; 16]);
        let req = put_ack(
            supi,
            "sor-ack",
            serde_json::json!({
                "provisioningTime": "2026-07-01T00:00:00Z",
                "sorMacIue": mac,
            }),
        );
        assert_eq!(handle_sor_ack(supi, &req).await.status, 400);
    }

    /// Legacy plain ack (no MAC, nothing outstanding) → 204 — the pre-F-06
    /// contract and the matched sim (which never sends SoR acks) stay green.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn f06_legacy_plain_ack_still_204() {
        // Serialize on the shared context guard: this test mutates the
        // process-global UDM context (udm_context_init/udm_self) and must
        // not interleave with other guarded tests (CI flake root cause).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        udm_context_init(64, 64);
        let supi = "imsi-f06legacy-0001";
        let req = put_ack(
            supi,
            "sor-ack",
            serde_json::json!({"provisioningTime": "2026-07-01T00:00:00Z"}),
        );
        assert_eq!(handle_sor_ack(supi, &req).await.status, 204);
    }

    /// ueNotReachable=true (AMF-reported) → 204 without a MAC check; ack state
    /// recorded and the outstanding XMAC consumed.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn f06_sor_ack_ue_not_reachable_records_without_mac() {
        // Serialize on the shared context guard: this test mutates the
        // process-global UDM context (udm_context_init/udm_self) and must
        // not interleave with other guarded tests (CI flake root cause).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        udm_context_init(64, 64);
        let supi = "imsi-f06sor-0005";
        let xmac = nextgcore_crypt::kdf::nextgcore_kdf_sor_mac_iue(&f06_kausf(0x33), 0x0001);
        assert!(udm_self()
            .read()
            .unwrap()
            .sor_store_expected_xmac(supi, xmac, 0x0001));
        let req = put_ack(
            supi,
            "sor-ack",
            serde_json::json!({
                "provisioningTime": "2026-07-01T00:00:00Z",
                "ueNotReachable": true,
            }),
        );
        assert_eq!(handle_sor_ack(supi, &req).await.status, 204);
        let ue = udm_self().read().unwrap().ue_find_by_supi(supi).unwrap();
        assert!(ue.sor_ack.as_ref().unwrap().ue_not_reachable);
        assert!(ue.expected_sor_xmac_iue.is_none());
    }

    /// Transparent-container-form ack (TS 24.501 §9.11.3.51): the SoR-MAC-I_UE
    /// occupies octets 5-20 (0-indexed `[4..20]`) of the base64 `Bytes`
    /// container. Golden container vector locks the octet-slice rule.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn f06_sor_ack_transparent_container_form_verifies() {
        // Serialize on the shared context guard: this test mutates the
        // process-global UDM context (udm_context_init/udm_self) and must
        // not interleave with other guarded tests (CI flake root cause).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        udm_context_init(64, 64);
        let supi = "imsi-f06sor-0006";
        let counter = 0x0001u16;
        let xmac = nextgcore_crypt::kdf::nextgcore_kdf_sor_mac_iue(&f06_kausf(0x44), counter);
        assert!(udm_self()
            .read()
            .unwrap()
            .sor_store_expected_xmac(supi, xmac, counter));

        // Hand-built SOR transparent container: octet 4 (index 3) = SOR header
        // (ack, list-type bits), octets 5-20 (index [4..20]) = SoR-MAC-I_UE.
        let mut container = vec![0x00, 0x00, 0x00, 0x08]; // 4-octet lead-in incl. header
        container.extend_from_slice(&xmac); // 16 MAC octets
        assert_eq!(container.len(), 20, "container is exactly 20 octets");
        let b64 = nextgcore_crypt::base64::encode(&container);

        let req = put_ack(
            supi,
            "sor-ack",
            serde_json::json!({
                "provisioningTime": "2026-07-01T00:00:00Z",
                "sorTransparentContainer": b64,
            }),
        );
        assert_eq!(handle_sor_ack(supi, &req).await.status, 204);
        assert!(udm_self()
            .read()
            .unwrap()
            .ue_find_by_supi(supi)
            .unwrap()
            .expected_sor_xmac_iue
            .is_none());
    }

    /// UPU mirror: happy path (correct UPU-MAC-I_UE via F-01 A.20 KDF) → 204,
    /// then replay → 400; a wrong MAC → 400 with state preserved.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn f06_upu_ack_happy_replay_and_wrong_mac() {
        // Serialize on the shared context guard: this test mutates the
        // process-global UDM context (udm_context_init/udm_self) and must
        // not interleave with other guarded tests (CI flake root cause).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        udm_context_init(64, 64);
        let supi = "imsi-f06upu-0001";
        let counter = 0x0001u16;
        let xmac = nextgcore_crypt::kdf::nextgcore_kdf_upu_mac_iue(&f06_kausf(0x77), counter);
        assert!(udm_self()
            .read()
            .unwrap()
            .upu_store_expected_xmac(supi, xmac, counter));

        let ok = put_ack(
            supi,
            "upu-ack",
            serde_json::json!({
                "provisioningTime": "2026-07-01T00:00:00Z",
                "upuMacIue": crate::nudm_handler::bytes_to_hex(&xmac),
            }),
        );
        assert_eq!(handle_upu_ack(supi, &ok).await.status, 204);
        let ue = udm_self().read().unwrap().ue_find_by_supi(supi).unwrap();
        assert!(ue.upu_ack.is_some());
        assert!(ue.expected_upu_xmac_iue.is_none());
        // Replay → 400.
        assert_eq!(handle_upu_ack(supi, &ok).await.status, 400);

        // Fresh outstanding XMAC, wrong MAC → 400, state preserved.
        let supi2 = "imsi-f06upu-0002";
        let xmac2 = nextgcore_crypt::kdf::nextgcore_kdf_upu_mac_iue(&f06_kausf(0x88), 0x0002);
        assert!(udm_self()
            .read()
            .unwrap()
            .upu_store_expected_xmac(supi2, xmac2, 0x0002));
        let mut wrong = xmac2;
        wrong[15] ^= 0x80;
        let bad = put_ack(
            supi2,
            "upu-ack",
            serde_json::json!({
                "provisioningTime": "2026-07-01T00:00:00Z",
                "upuMacIue": crate::nudm_handler::bytes_to_hex(&wrong),
            }),
        );
        assert_eq!(handle_upu_ack(supi2, &bad).await.status, 400);
        let ue2 = udm_self().read().unwrap().ue_find_by_supi(supi2).unwrap();
        assert!(ue2.upu_ack.is_none());
        assert!(ue2.expected_upu_xmac_iue.is_some());
    }

    // ==================================================================
    // #83: SDM Subscribe validates its mandatory IEs; EE Modify applies
    // the patch it used to discard.
    // ==================================================================

    fn sdm_subscribe_request(body: serde_json::Value) -> SbiRequest {
        let mut req = SbiRequest::post("/nudm-sdm/v2/imsi-001010000000001/sdm-subscriptions");
        req.http.content = Some(body.to_string());
        req
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize process-global UDM state (context, UDM_NOTIFY_DISABLE, SBI profile)
    async fn sdm_subscribe_refuses_a_subscription_missing_a_mandatory_ie() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        udm_context_init(64, 64);
        let supi = "imsi-001010000000001";

        let full = serde_json::json!({
            "nfInstanceId": "nf-1",
            "callbackReference": "http://consumer.example.com/cb",
            "monitoredResourceUris": ["/nudm-sdm/v2/imsi-001010000000001/am-data"],
        });

        // Each mandatory IE removed in turn must be a 400 with a
        // MANDATORY_IE_MISSING cause naming it. This handler used to answer 201
        // for a body missing all three, so a consumer with a broken subscribe
        // request got a subscription id back and monitored nothing.
        for ie in ["nfInstanceId", "callbackReference", "monitoredResourceUris"] {
            let mut body = full.clone();
            body.as_object_mut().expect("object").remove(ie);
            let resp = handle_sdm_subscribe(supi, &sdm_subscribe_request(body)).await;
            assert_eq!(
                resp.status, 400,
                "a subscription missing {ie} must be refused"
            );
            let problem: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("JSON");
            assert_eq!(problem["cause"], "MANDATORY_IE_MISSING", "for {ie}");
            assert!(
                problem["detail"].as_str().expect("detail").contains(ie),
                "the refusal must name the missing IE: {problem}"
            );
        }

        // An EMPTY monitoredResourceUris is refused too: minItems is 1, and an
        // empty list is what a consumer produces when its own resource list came
        // out empty — a bug to surface, not a whole-UE subscription to infer.
        let mut empty = full.clone();
        empty["monitoredResourceUris"] = serde_json::json!([]);
        let resp = handle_sdm_subscribe(supi, &sdm_subscribe_request(empty)).await;
        assert_eq!(resp.status, 400);

        // A complete body is still accepted, with the v2 Location.
        let resp = handle_sdm_subscribe(supi, &sdm_subscribe_request(full)).await;
        assert_eq!(resp.status, 201);
        let location = resp
            .http
            .get_header("location")
            .expect("Location header")
            .clone();
        assert!(
            location.contains("/nudm-sdm/v2/"),
            "Nudm_SDM is v2; a v1 Location hands out an undefined path: {location}"
        );

        // Clean up so the notify tests are not perturbed by this subscription.
        clear_sdm_subscriptions_for(supi);
    }

    /// Drop every SDM subscription for `supi`.
    ///
    /// A plain fn rather than inline in the async test: the read guard must not be
    /// held across the test's remaining awaits, and keeping the borrow inside one
    /// synchronous frame is the simplest way to guarantee that.
    fn clear_sdm_subscriptions_for(supi: &str) {
        let ctx = udm_self();
        let Ok(context) = ctx.read() else { return };
        for sub in context.sdm_subscriptions_for_supi(supi) {
            context.sdm_subscription_remove(&sub.id);
        }
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize process-global UDM state (context, UDM_NOTIFY_DISABLE, SBI profile)
    async fn ee_modify_applies_the_patch_and_the_change_is_readable_back() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        udm_context_init(64, 64);
        let ue = "imsi-001010000000083";

        let original = serde_json::json!({
            "callbackReference": "http://consumer.example.com/ee",
            "monitoringConfigurations": { "1": { "eventType": "LOSS_OF_CONNECTIVITY" } },
        });
        let sub = crate::context::UdmEeSubscription::for_ue(
            ue,
            "http://consumer.example.com/ee",
            original.to_string(),
        );
        let sub_id = sub.id.clone();
        {
            let ctx = udm_self();
            let context = ctx.read().expect("context");
            context.ee_subscription_insert(sub);
        }

        // PatchItem array form.
        let patch = serde_json::json!([{
            "op": "replace",
            "path": "/monitoringConfigurations",
            "value": { "2": { "eventType": "UE_REACHABILITY_FOR_DATA" } },
        }]);
        let mut req = SbiRequest::patch(format!("/nudm-ee/v1/{ue}/ee-subscriptions/{sub_id}"));
        req.http.content = Some(patch.to_string());
        let resp = handle_ee_modify(ue, &sub_id, &req).await;
        assert_eq!(resp.status, 204);

        // Read back: the stored subscription must actually have changed. This is
        // the assertion the old handler could never satisfy — it returned 204 and
        // discarded the patch, so lifecycle management reported success while
        // diverging from state.
        let stored = {
            let ctx = udm_self();
            let context = ctx.read().expect("context");
            context.ee_subscription_find_by_id(&sub_id).expect("stored")
        };
        let raw: serde_json::Value = serde_json::from_str(&stored.raw).expect("stored JSON");
        assert_eq!(
            raw["monitoringConfigurations"]["2"]["eventType"],
            "UE_REACHABILITY_FOR_DATA"
        );
        assert!(
            raw["monitoringConfigurations"].get("1").is_none(),
            "replace must replace the member, not merge into it: {raw}"
        );

        // A patch that changes the callbackReference updates the cached copy too,
        // or the next notification goes to the old URI.
        let repoint = serde_json::json!([{
            "op": "replace",
            "path": "/callbackReference",
            "value": "http://elsewhere.example.com/ee",
        }]);
        let mut req = SbiRequest::patch(format!("/nudm-ee/v1/{ue}/ee-subscriptions/{sub_id}"));
        req.http.content = Some(repoint.to_string());
        assert_eq!(handle_ee_modify(ue, &sub_id, &req).await.status, 204);
        let stored = {
            let ctx = udm_self();
            let context = ctx.read().expect("context");
            context.ee_subscription_find_by_id(&sub_id).expect("stored")
        };
        assert_eq!(stored.callback_reference, "http://elsewhere.example.com/ee");

        // An unknown subscription is still 404, and a malformed patch is a 400
        // rather than a silent success.
        let mut req = SbiRequest::patch("/nudm-ee/v1/x/ee-subscriptions/absent");
        req.http.content = Some("[]".to_string());
        assert_eq!(handle_ee_modify(ue, "absent", &req).await.status, 404);

        for bad in [
            serde_json::json!([]),
            serde_json::json!([{ "op": "replace", "path": "/notThere", "value": 1 }]),
            serde_json::json!([{ "op": "remove", "path": "/notThere" }]),
            serde_json::json!([{ "op": "bogus", "path": "/callbackReference", "value": 1 }]),
            serde_json::json!([{ "op": "replace", "path": "/a/b", "value": 1 }]),
            serde_json::json!(42),
        ] {
            let mut req = SbiRequest::patch(format!("/nudm-ee/v1/{ue}/ee-subscriptions/{sub_id}"));
            req.http.content = Some(bad.to_string());
            assert_eq!(
                handle_ee_modify(ue, &sub_id, &req).await.status,
                400,
                "patch {bad} must be refused"
            );
        }

        clear_ee_subscription(&sub_id);
    }

    /// Drop one EE subscription by id (see `clear_sdm_subscriptions_for`).
    fn clear_ee_subscription(id: &str) {
        let ctx = udm_self();
        let Ok(context) = ctx.read() else { return };
        context.ee_subscription_remove(id);
    }

    #[test]
    fn ee_patch_accepts_the_merge_patch_form_and_refuses_nonsense() {
        let mut stored = serde_json::json!({ "callbackReference": "a", "keepMe": 1 });
        // Merge patch (RFC 7396): members replace, an explicit null removes.
        apply_ee_patch(
            &mut stored,
            &serde_json::json!({ "callbackReference": "b", "keepMe": null, "added": 2 }),
        )
        .expect("merge patch applies");
        assert_eq!(stored["callbackReference"], "b");
        assert!(stored.get("keepMe").is_none());
        assert_eq!(stored["added"], 2);

        // `add` creates a member that was not there; `replace` on the same
        // absent member does not.
        let mut fresh = serde_json::json!({});
        apply_ee_patch(
            &mut fresh,
            &serde_json::json!([{ "op": "add", "path": "/new", "value": 1 }]),
        )
        .expect("add applies");
        assert_eq!(fresh["new"], 1);
        assert!(apply_ee_patch(
            &mut serde_json::json!({}),
            &serde_json::json!([{ "op": "replace", "path": "/new", "value": 1 }])
        )
        .is_err());
    }

    // ========================================================================
    // #84: the Nudm_UECM registration surface over the WIRE
    //
    // These drive the REAL router (`udm_sbi_request_handler`) over HTTP against
    // a mock UDR that stores `context-data` resources, because the criteria are
    // routing claims: "returns the stored resource rather than 405". A
    // handler-level test cannot fail when a route arm is missing.
    // ========================================================================

    // ========================================================================
    // #226: the SDM multi-data-set GET and the absent data-set resources
    //
    // Routing claims, so they drive the REAL router over HTTP against the mock
    // UDR. A handler-level test cannot fail when a route arm is missing — which is
    // exactly the defect: `GET /nudm-sdm/v2/{supi}` reached the default handler.
    // ========================================================================

    /// Criterion 1: the whole-UE multi-data-set GET is routed and fans out.
    ///
    /// Before #226 this had only three path parts, so `route_nudm_sdm` saw an empty
    /// resource, fell to the catch-all and answered 404 `RESOURCE_URI_NOT_FOUND`.
    ///
    /// The `dataset-names` values are the TS 29.503 `DataSetName` tokens (`AM`,
    /// `SM`, …), NOT the path segments. #226's criterion writes
    /// `dataset-names=am-data,sm-data`; that spelling is not what a conformant
    /// consumer sends, and `udrd` already implements the spec tokens for the same
    /// query parameter on its own combined GET (udrd-03). The deviation is
    /// deliberate — see the spec.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)]
    async fn sdm_multi_data_set_get_is_routed_and_fans_out() {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        udm_context_init(64, 64);

        let (udr_server, store) = start_mock_udr_context_data().await;
        let (udm_server, client) = start_real_udm().await;

        let supi = "imsi-001010000000226";
        // The combined provisioned-data document, keyed as udmd asks for it. This
        // stands in for udrd's own `dataset-names` filtering, which udrd tests.
        store.lock().unwrap_or_else(|e| e.into_inner()).insert(
            format!("/nudr-dr/v2/subscription-data/{supi}/provisioned-data/"),
            serde_json::json!({
                "amData": {"subscribedUeAmbr": {"uplink": "1 Gbps", "downlink": "1 Gbps"}},
                "smfSelData": {"subscribedSnssaiInfos": {}},
                "smData": [{"singleNssai": {"sst": 1}}],
            }),
        );

        // No filter: every data set this UDM serves that has data.
        let resp = client
            .get(&format!("/nudm-sdm/v2/{supi}"))
            .await
            .expect("multi-data-set GET");
        assert_eq!(
            resp.status, 200,
            "the whole-UE form must be ROUTED, not fall through to the default handler"
        );
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).expect("JSON body");
        assert!(body.get("amData").is_some(), "amData present: {body}");
        assert!(
            body.get("smfSelData").is_some(),
            "smfSelData present: {body}"
        );
        assert!(body.get("smData").is_some(), "smData present: {body}");

        // An explicit filter reaches the UDR as the same tokens.
        let resp = client
            .get(&format!("/nudm-sdm/v2/{supi}?dataset-names=AM,SM"))
            .await
            .expect("filtered multi-data-set GET");
        assert_eq!(resp.status, 200);

        // An unrecognised token is REFUSED rather than silently dropped: a consumer
        // that asked for a data set and got a body without it would read the absence
        // as "this subscriber has none".
        let resp = client
            .get(&format!("/nudm-sdm/v2/{supi}?dataset-names=am-data"))
            .await
            .expect("bad token GET");
        assert_eq!(
            resp.status, 400,
            "the path-segment spelling is not a DataSetName and must be refused"
        );
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).expect("ProblemDetails");
        assert!(
            problem["detail"].as_str().is_some_and(|d| d.contains("AM")),
            "the refusal names the accepted values: {problem}"
        );

        // A non-GET on the whole-UE resource is 405 WITH an Allow header, not 404:
        // the URI does name a resource this UDM serves (#85's distinction).
        let resp = client
            .delete(&format!("/nudm-sdm/v2/{supi}"))
            .await
            .expect("DELETE on the whole-UE resource");
        assert_eq!(resp.status, 405);
        assert!(
            resp.http
                .headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("allow") && v.contains("GET")),
            "405 must carry Allow: GET"
        );

        udm_server.stop().await.expect("udm stops");
        udr_server.stop().await.expect("udr stops");
    }

    /// Criterion 2: `ue-context-in-amf-data` returns the stored AMF registration.
    ///
    /// This is the data set the #83 SDM notification producer reports on every AMF
    /// registration and deregistration, so before #226 a subscriber was told the
    /// resource changed and then could not read it — the asymmetry the issue calls
    /// the strongest argument for doing this one first. Both halves are asserted:
    /// the read after a registration, and the 404 `DATA_NOT_FOUND` before one, so
    /// the test cannot pass by returning 200 unconditionally.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)]
    async fn ue_context_in_amf_data_reads_the_stored_registration() {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        udm_context_init(64, 64);
        std::env::set_var("UDM_NOTIFY_DISABLE", "1");

        let (udr_server, store) = start_mock_udr_context_data().await;
        let (udm_server, client) = start_real_udm().await;

        let supi = "imsi-001010000000227";
        let sdm = format!("/nudm-sdm/v2/{supi}/ue-context-in-amf-data");

        // Before any registration: the data set does not exist for this UE. 404
        // DATA_NOT_FOUND, which is different from the operation not existing —
        // and specifically not the 405 this answered before #226.
        let resp = client.get(&sdm).await.expect("GET before registration");
        assert_eq!(
            resp.status, 404,
            "no registration yet: {:?}",
            resp.http.content
        );
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).expect("ProblemDetails");
        assert_eq!(problem["cause"], "DATA_NOT_FOUND");

        // Register over the real UECM route, which is what writes the UDR resource.
        let resp = client
            .put_json(
                &format!("/nudm-uecm/v1/{supi}/registrations/amf-3gpp-access"),
                &amf_reg_body("amf-226", "NR"),
            )
            .await
            .expect("UECM registration");
        assert_eq!(resp.status, 201);
        assert!(
            store
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&format!(
                    "/nudr-dr/v2/subscription-data/{supi}/context-data/amf-3gpp-access"
                )),
            "the registration reached the UDR, so the read below has something to find"
        );

        // Now the SDM data set reads it back.
        let resp = client.get(&sdm).await.expect("GET after registration");
        assert_eq!(resp.status, 200, "the stored registration must be readable");
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).expect("JSON body");
        assert_eq!(
            body["amfInstanceId"], "amf-226",
            "the data set is the stored registration, not an empty object: {body}"
        );

        // And it appears in the multi-data-set retrieval under `uecAmfData`.
        let resp = client
            .get(&format!("/nudm-sdm/v2/{supi}?dataset-names=UEC_AMF"))
            .await
            .expect("multi-data-set GET for UEC_AMF");
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).expect("JSON body");
        assert_eq!(body["uecAmfData"]["amfInstanceId"], "amf-226");

        std::env::remove_var("UDM_NOTIFY_DISABLE");
        udm_server.stop().await.expect("udm stops");
        udr_server.stop().await.expect("udr stops");
    }

    /// Criterion 3: every remaining TS 29.503 per-SUPI SDM data set is ROUTED, and
    /// answers a data-derived status rather than 405 or 501.
    ///
    /// The assertion is deliberately `!= 405 && != 501` plus "is a 404 whose cause
    /// says why", because that is the criterion: the router no longer claims these
    /// resources do not exist, and no longer answers with a status it invented. The
    /// three data sets with a `udrd` source return 200; the rest relay the UDR's
    /// 404, which starts returning data if udrd grows a source.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)]
    async fn every_routed_sdm_data_set_answers_a_derived_status() {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        udm_context_init(64, 64);

        let (udr_server, _store) = start_mock_udr_context_data().await;
        let (udm_server, client) = start_real_udm().await;

        let supi = "imsi-001010000000228";
        for resource in [
            "ue-context-in-smf-data",
            "ue-context-in-smsf-data",
            "sms-data",
            "sms-mng-data",
            "trace-data",
            "lcs-privacy-data",
            "lcs-mo-data",
            "lcs-bca-data",
            "v2x-data",
            "prose-data",
            "mbs-data",
            "uc-data",
        ] {
            let resp = client
                .get(&format!("/nudm-sdm/v2/{supi}/{resource}"))
                .await
                .unwrap_or_else(|e| panic!("GET {resource} failed: {e}"));
            assert_ne!(
                resp.status, 405,
                "{resource} must be ROUTED, not answered method-not-allowed"
            );
            assert_ne!(
                resp.status, 501,
                "{resource} must not be answered with a status the router invented"
            );
            assert_eq!(
                resp.status, 404,
                "with no UDR source, {resource} relays the UDR's not-found"
            );
            let problem: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap())
                    .unwrap_or_else(|e| panic!("{resource} ProblemDetails: {e}"));
            assert_eq!(
                problem["cause"], "DATA_NOT_FOUND",
                "{resource} says WHY it has nothing: {problem}"
            );
        }

        // The complement: a resource that is genuinely not a Nudm_SDM data set is
        // still 404 RESOURCE_URI_NOT_FOUND, so routing the twelve above did not
        // turn the router into an accept-anything.
        let resp = client
            .get(&format!("/nudm-sdm/v2/{supi}/not-a-data-set"))
            .await
            .expect("GET unknown resource");
        assert_eq!(resp.status, 404);
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).expect("ProblemDetails");
        assert_eq!(
            problem["cause"], "RESOURCE_URI_NOT_FOUND",
            "an unknown path names no resource, which is a different 404: {problem}"
        );

        udm_server.stop().await.expect("udm stops");
        udr_server.stop().await.expect("udr stops");
    }

    /// Shared in-memory `context-data` store for the mock UDR below, keyed by
    /// the full Nudr resource path.
    type CtxStore = Arc<std::sync::Mutex<std::collections::HashMap<String, serde_json::Value>>>;

    /// Mock UDR implementing the TS 29.505 `subscription-data` resources
    /// generically: GET / PUT / PATCH / DELETE on any resource under
    /// `/nudr-dr/v2/subscription-data/{ueId}/...`, plus the `smf-registrations`
    /// collection GET that answers with a bare array (the shape the real udrd
    /// returns, which the UDM has to wrap).
    async fn mock_udr_context_data(store: CtxStore, request: SbiRequest) -> SbiResponse {
        let method = request.header.method.clone();
        let uri = request.header.uri.clone();
        let path = uri.split('?').next().unwrap_or(&uri).to_string();
        if !path.starts_with("/nudr-dr/v2/subscription-data/") {
            return SbiResponse::with_status(404);
        }
        let body = || -> Option<serde_json::Value> {
            request
                .http
                .content
                .as_deref()
                .and_then(|b| serde_json::from_str(b).ok())
        };
        let mut map = store.lock().expect("ctx store");
        match method.as_str() {
            "GET" => {
                if path.ends_with("/smf-registrations") {
                    let prefix = format!("{path}/");
                    let list: Vec<serde_json::Value> = map
                        .iter()
                        .filter(|(k, _)| k.starts_with(&prefix))
                        .map(|(_, v)| v.clone())
                        .collect();
                    if list.is_empty() {
                        return SbiResponse::with_status(404);
                    }
                    return SbiResponse::with_status(200)
                        .with_json_body(&serde_json::Value::Array(list))
                        .unwrap_or_else(|_| SbiResponse::with_status(500));
                }
                match map.get(&path) {
                    Some(doc) => SbiResponse::with_status(200)
                        .with_json_body(doc)
                        .unwrap_or_else(|_| SbiResponse::with_status(500)),
                    None => SbiResponse::with_status(404),
                }
            }
            "PUT" => match body() {
                Some(doc) => {
                    let created = map.insert(path, doc).is_none();
                    SbiResponse::with_status(if created { 201 } else { 204 })
                }
                None => SbiResponse::with_status(400),
            },
            "PATCH" => {
                let Some(patch) = body() else {
                    return SbiResponse::with_status(400);
                };
                let Some(doc) = map.get_mut(&path) else {
                    return SbiResponse::with_status(404);
                };
                if let (Some(target), Some(items)) = (doc.as_object_mut(), patch.as_object()) {
                    for (k, v) in items {
                        target.insert(k.clone(), v.clone());
                    }
                }
                SbiResponse::with_status(204)
            }
            "DELETE" => {
                map.remove(&path);
                SbiResponse::with_status(204)
            }
            _ => SbiResponse::with_status(405),
        }
    }

    /// Start the mock UDR and point udmd's UDR client at it. Returns the server
    /// (the CALLER must keep it alive: dropping it closes the listener) and the
    /// backing store.
    async fn start_mock_udr_context_data() -> (SbiServer, CtxStore) {
        let store: CtxStore = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let port = free_port();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let server = SbiServer::new(NextgcoreSbiServerConfig::new(addr));
        let handler_store = Arc::clone(&store);
        server
            .start(move |req: SbiRequest| {
                let store = Arc::clone(&handler_store);
                async move { mock_udr_context_data(store, req).await }
            })
            .await
            .expect("mock UDR starts");
        // SbiServer::start spawns its accept loop, so returning from it does not
        // mean the port accepts yet (the recorded stub-listener lesson).
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        std::env::set_var("UDR_SBI_ADDR", "127.0.0.1");
        std::env::set_var("UDR_SBI_PORT", port.to_string());
        (server, store)
    }

    /// Start the real UDM SBI server and return it with a client for it.
    async fn start_real_udm() -> (SbiServer, nextgcore_sbi::client::SbiClient) {
        let port = free_port();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let server = SbiServer::new(NextgcoreSbiServerConfig::new(addr));
        server
            .start(udm_sbi_request_handler)
            .await
            .expect("udm starts");
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        (
            server,
            nextgcore_sbi::client::SbiClient::with_host_port("127.0.0.1", port),
        )
    }

    fn json_body(resp: &SbiResponse) -> serde_json::Value {
        serde_json::from_str(resp.http.content.as_deref().unwrap_or("null"))
            .unwrap_or(serde_json::Value::Null)
    }

    fn amf_reg_body(instance: &str, rat: &str) -> serde_json::Value {
        serde_json::json!({
            "amfInstanceId": instance,
            "deregCallbackUri":
                format!("http://{instance}.example.org:7777/namf-callback/v1/imsi-x/dereg-notify"),
            "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe00" },
            "ratType": rat,
            "imsVoPs": "HOMOGENEOUS_NON_SUPPORT"
        })
    }

    /// The whole #84 UECM surface, driven through the real router:
    /// dual-access registration without overwrite (criterion 1), every mandatory
    /// GET answering 2xx instead of 405 (criterion 3), and both spec
    /// deregistrations (criterion 4).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn test_http_uecm_registration_surface() {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _ = env_logger::try_init();
        udm_context_init(64, 64);
        std::env::remove_var("UDM_NOTIFY_DISABLE");

        let (udr_server, store) = start_mock_udr_context_data().await;
        let (udm_server, client) = start_real_udm().await;

        let supi = "imsi-001010000000846";
        let reg = |r: &str| format!("/nudm-uecm/v1/{supi}/registrations/{r}");
        let udr_key = |r: &str| format!("/nudr-dr/v2/subscription-data/{supi}/context-data/{r}");

        // --- criterion 1: dual-access registration, no overwrite ------------
        let three_gpp = amf_reg_body("amf-3gpp", "NR");
        let resp = client
            .put_json(&reg("amf-3gpp-access"), &three_gpp)
            .await
            .expect("3gpp PUT");
        assert_eq!(resp.status, 201, "3GPP registration created");

        let non_3gpp = amf_reg_body("amf-n3gpp", "VIRTUAL");
        let resp = client
            .put_json(&reg("amf-non-3gpp-access"), &non_3gpp)
            .await
            .expect("non-3gpp PUT");
        assert_eq!(
            resp.status, 201,
            "the non-3GPP resource is created, not found: a 200 would mean the \
             handler read the 3GPP registration"
        );
        assert_eq!(
            resp.http.headers.get("location").map(String::as_str),
            Some(reg("amf-non-3gpp-access").as_str())
        );
        {
            let map = store.lock().expect("store");
            assert_eq!(
                map.get(&udr_key("amf-3gpp-access")),
                Some(&three_gpp),
                "the 3GPP UDR record must be untouched by the non-3GPP registration"
            );
            assert_eq!(
                map.get(&udr_key("amf-non-3gpp-access")),
                Some(&non_3gpp),
                "the non-3GPP registration lives in its own UDR resource"
            );
        }

        // --- criterion 3: the mandatory GETs are ROUTED (not 405) ----------
        for (resource, expect_instance) in [
            ("amf-3gpp-access", "amf-3gpp"),
            ("amf-non-3gpp-access", "amf-n3gpp"),
        ] {
            let resp = client.get(&reg(resource)).await.expect("GET");
            assert_eq!(resp.status, 200, "GET {resource} must be routed");
            assert_eq!(
                json_body(&resp)["amfInstanceId"],
                expect_instance,
                "GET {resource} returned the wrong access's registration"
            );
        }

        // SMF registration + the collection and individual GETs.
        let smf = serde_json::json!({
            "smfInstanceId": "smf-1",
            "pduSessionId": 5,
            "singleNssai": { "sst": 1, "sd": "000001" },
            "dnn": "internet",
            "plmnId": { "mcc": "001", "mnc": "01" }
        });
        let resp = client
            .put_json(&reg("smf-registrations/5"), &smf)
            .await
            .expect("smf PUT");
        assert_eq!(resp.status, 201);
        let resp = client
            .get(&reg("smf-registrations"))
            .await
            .expect("smf collection GET");
        assert_eq!(resp.status, 200, "GetSmfRegistration must be routed");
        assert_eq!(
            json_body(&resp)["smfRegistrationList"][0]["smfInstanceId"],
            "smf-1",
            "the collection is wrapped as SmfRegistrationInfo"
        );
        let resp = client
            .get(&reg("smf-registrations/5"))
            .await
            .expect("smf individual GET");
        assert_eq!(resp.status, 200);
        assert_eq!(json_body(&resp)["smfInstanceId"], "smf-1");

        // Location information, composed from both AMF registrations.
        let resp = client.get(&reg("location")).await.expect("location GET");
        assert_eq!(resp.status, 200, "GetLocationInfo must be routed");
        let loc = json_body(&resp);
        let entries = loc["registrationLocationInfoList"]
            .as_array()
            .expect("registrationLocationInfoList")
            .clone();
        assert_eq!(entries.len(), 2, "one entry per serving AMF: {entries:?}");
        assert_eq!(loc["supi"], supi);

        // SMSF and IP-SM-GW registrations round-trip.
        let smsf = serde_json::json!({
            "smsfInstanceId": "smsf-1",
            "plmnId": { "mcc": "001", "mnc": "01" }
        });
        let resp = client
            .put_json(&reg("smsf-3gpp-access"), &smsf)
            .await
            .expect("smsf PUT");
        assert_eq!(resp.status, 201);
        let resp = client
            .get(&reg("smsf-3gpp-access"))
            .await
            .expect("smsf GET");
        assert_eq!(resp.status, 200, "Get3GppSmsfRegistration must be routed");
        assert_eq!(json_body(&resp)["smsfInstanceId"], "smsf-1");

        let ipsmgw = serde_json::json!({ "ipsmgwFqdn": "ipsmgw.example.org" });
        let resp = client
            .put_json(&reg("ip-sm-gw"), &ipsmgw)
            .await
            .expect("ip-sm-gw PUT");
        assert_eq!(resp.status, 201);
        let resp = client.get(&reg("ip-sm-gw")).await.expect("ip-sm-gw GET");
        assert_eq!(resp.status, 200, "GetIpSmGwRegistration must be routed");
        assert_eq!(json_body(&resp)["ipsmgwFqdn"], "ipsmgw.example.org");

        // --- criterion 4: the two spec deregistrations ---------------------
        // POST .../amf-3gpp-access/dereg-amf, not DELETE on the resource.
        let resp = client
            .post_json(
                &reg("amf-3gpp-access/dereg-amf"),
                &serde_json::json!({ "deregReason": "SUBSCRIPTION_WITHDRAWN" }),
            )
            .await
            .expect("dereg-amf POST");
        assert_eq!(resp.status, 204, "dereg-amf must be routed");
        let resp = client
            .get(&reg("amf-3gpp-access"))
            .await
            .expect("GET after dereg");
        assert_eq!(resp.status, 404, "the 3GPP registration is gone");
        let resp = client
            .get(&reg("amf-non-3gpp-access"))
            .await
            .expect("GET non-3gpp after 3gpp dereg");
        assert_eq!(
            resp.status, 200,
            "deregistering 3GPP access must leave the non-3GPP registration"
        );

        // purgeFlag on the update PATCH deregisters (the shape amfd sends).
        let resp = client
            .patch_json(
                &reg("amf-non-3gpp-access"),
                &serde_json::json!({ "purgeFlag": true }),
            )
            .await
            .expect("purge PATCH");
        assert_eq!(resp.status, 204, "PATCH amf-non-3gpp-access must be routed");
        let resp = client
            .get(&reg("amf-non-3gpp-access"))
            .await
            .expect("GET after purge");
        assert_eq!(resp.status, 404, "purgeFlag deregistered the UE");

        udm_server.stop().await.expect("stop udm");
        udr_server.stop().await.expect("stop udr");
    }

    // ========================================================================
    // #84: UEAU — the authenticating AUSF is pinned, DeleteAuth is routed, and
    // a failed SQN advance withholds the AV.
    // ========================================================================

    /// Mock UDR for the UEAU flow: serves authentication-subscription GET,
    /// answers the SQN PATCH with a caller-controlled status, and counts
    /// authentication-status writes/deletes.
    #[derive(Default)]
    struct UeauUdrState {
        patch_status: std::sync::atomic::AtomicU16,
        status_deletes: std::sync::atomic::AtomicUsize,
    }

    async fn mock_udr_ueau(state: Arc<UeauUdrState>, request: SbiRequest) -> SbiResponse {
        let method = request.header.method.clone();
        let uri = request.header.uri.clone();
        let path = uri.split('?').next().unwrap_or(&uri).to_string();
        if path.contains("authentication-status") {
            if method == "DELETE" {
                state
                    .status_deletes
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            return SbiResponse::with_status(204);
        }
        if !path.contains("authentication-subscription") {
            return SbiResponse::with_status(404);
        }
        if method == "PATCH" {
            return SbiResponse::with_status(
                state.patch_status.load(std::sync::atomic::Ordering::SeqCst),
            );
        }
        SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({
                "authenticationMethod": "5G_AKA",
                "encPermanentKey": TEST_K_HEX,
                "encOpcKey": TEST_OPC_HEX,
                "authenticationManagementField": "8000",
                "sequenceNumber": { "sqn": "000000000021", "sqnScheme": "NON_TIME_BASED" }
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(500))
    }

    /// A stub AUSF that counts the Nausf_SoRProtection / UPUProtection requests
    /// it receives. Registered in the shared SBI context under `instance_id` so
    /// udmd's AUSF selection can resolve it.
    async fn start_stub_ausf(
        instance_id: &str,
    ) -> (SbiServer, Arc<std::sync::atomic::AtomicUsize>) {
        use nextgcore_sbi::context::{global_context, NfInstance, NfService};
        use nextgcore_sbi::types::{NfType, SbiServiceType};

        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        let port = free_port();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let server = SbiServer::new(NextgcoreSbiServerConfig::new(addr));
        server
            .start(move |_req: SbiRequest| {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    // 204 with no SorSecurityInfo: the injector then withholds
                    // (fail-closed). WHICH AUSF was asked is the whole question
                    // here, so a successful protection is not needed.
                    SbiResponse::with_status(204)
                }
            })
            .await
            .expect("stub AUSF starts");
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut instance = NfInstance::new(instance_id, NfType::Ausf);
        instance.ipv4_addresses.push("127.0.0.1".to_string());
        let mut svc = NfService::new("nausf-sorprotection", SbiServiceType::NausfAuth);
        svc.versions = vec!["v1".to_string()];
        svc.port = port;
        instance.add_service(svc);
        global_context().add_nf_instance(instance).await;
        (server, hits)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn test_http_ueau_ausf_pinning_delete_auth_and_sqn_withholding() {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _ = env_logger::try_init();
        udm_context_init(64, 64);

        let state = Arc::new(UeauUdrState::default());
        state
            .patch_status
            .store(204, std::sync::atomic::Ordering::SeqCst);
        let udr_port = free_port();
        let udr_addr = SocketAddr::from(([127, 0, 0, 1], udr_port));
        let udr_server = SbiServer::new(NextgcoreSbiServerConfig::new(udr_addr));
        let handler_state = Arc::clone(&state);
        udr_server
            .start(move |req: SbiRequest| {
                let state = Arc::clone(&handler_state);
                async move { mock_udr_ueau(state, req).await }
            })
            .await
            .expect("mock UDR starts");
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(udr_addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        std::env::set_var("UDR_SBI_ADDR", "127.0.0.1");
        std::env::set_var("UDR_SBI_PORT", udr_port.to_string());

        let (udm_server, client) = start_real_udm().await;
        let supi = "imsi-001010000000001";
        let gen_path = format!("/nudm-ueau/v1/{supi}/security-information/generate-auth-data");

        // --- criterion 5a: the request's ausfInstanceId is PERSISTED ---------
        // Two AUSFs exist; "ausf-a" is registered first, so it is what the
        // "any cached AUSF" fallback would pick.
        let (ausf_a_server, ausf_a_hits) = start_stub_ausf("ausf-a").await;
        let (ausf_b_server, ausf_b_hits) = start_stub_ausf("ausf-b").await;

        let resp = client
            .post_json(
                &gen_path,
                &serde_json::json!({
                    "servingNetworkName": TEST_SNN,
                    "ausfInstanceId": "ausf-b"
                }),
            )
            .await
            .expect("generate-auth-data");
        assert_eq!(
            resp.status, 200,
            "the AV is issued: {:?}",
            resp.http.content
        );
        {
            let ctx = udm_self();
            let context = ctx.read().expect("context");
            let ue = context.ue_find_by_supi(supi).expect("UE created");
            assert_eq!(
                ue.ausf_instance_id.as_deref(),
                Some("ausf-b"),
                "the authenticating AUSF must be recorded on the live path \
                 (TS 33.501 §6.14.2.1: it holds K_AUSF)"
            );
        }

        // --- criterion 5b: SoR and UPU select the RECORDED AUSF -------------
        let am_data_sor = serde_json::json!({
            "sorInfo": { "steeringContainer": [{ "plmnId": { "mcc": "001", "mnc": "01" } }],
                         "ackInd": false }
        })
        .to_string();
        let _ = crate::sor::maybe_inject_sor_info(supi, am_data_sor).await;
        let am_data_upu = serde_json::json!({
            "upuInfo": { "upuDataList": [{ "secPacket": "00" }], "upuAckInd": false }
        })
        .to_string();
        let _ = crate::upu::maybe_inject_upu_info(supi, am_data_upu).await;

        assert_eq!(
            ausf_b_hits.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "both SoR and UPU protection must go to the AUSF that authenticated \
             the UE, so the MAC is computed with the K_AUSF the UE holds"
        );
        assert_eq!(
            ausf_a_hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the arbitrary-first-instance fallback must not fire when the \
             authenticating AUSF is known"
        );

        // --- criterion 6: DeleteAuth round-trips the ConfirmAuth id ----------
        let auth_event = serde_json::json!({
            "nfInstanceId": "ausf-b",
            "success": true,
            "timeStamp": "2026-01-01T00:00:00Z",
            "authType": "5G_AKA",
            "servingNetworkName": TEST_SNN
        });
        let resp = client
            .post_json(&format!("/nudm-ueau/v1/{supi}/auth-events"), &auth_event)
            .await
            .expect("ConfirmAuth");
        assert_eq!(resp.status, 201);
        let location = resp
            .http
            .headers
            .get("location")
            .cloned()
            .expect("ConfirmAuth Location");
        let event_id = location
            .rsplit('/')
            .next()
            .expect("authEventId segment")
            .to_string();
        assert!(!event_id.is_empty());

        // An id this UDM never issued is a 404, not a silent success.
        let resp = client
            .put_json(
                &format!("/nudm-ueau/v1/{supi}/auth-events/not-the-issued-id"),
                &auth_event,
            )
            .await
            .expect("DeleteAuth wrong id");
        assert_eq!(resp.status, 404, "an unknown authEventId must not 204");

        let before = state
            .status_deletes
            .load(std::sync::atomic::Ordering::SeqCst);
        let resp = client
            .put_json(
                &format!("/nudm-ueau/v1/{supi}/auth-events/{event_id}"),
                &auth_event,
            )
            .await
            .expect("DeleteAuth");
        assert_eq!(
            resp.status, 204,
            "DeleteAuth on the issued id must be routed and accepted"
        );
        assert_eq!(
            state
                .status_deletes
                .load(std::sync::atomic::Ordering::SeqCst),
            before + 1,
            "the revocation must reach the UDR authentication-status resource"
        );
        // Single-use: the pinned id is consumed.
        let resp = client
            .put_json(
                &format!("/nudm-ueau/v1/{supi}/auth-events/{event_id}"),
                &auth_event,
            )
            .await
            .expect("DeleteAuth replay");
        assert_eq!(resp.status, 404, "a replayed DeleteAuth finds nothing");

        // --- criterion 7: a failed SQN advance withholds the AV -------------
        state
            .patch_status
            .store(404, std::sync::atomic::Ordering::SeqCst);
        let resp = client
            .post_json(
                &gen_path,
                &serde_json::json!({
                    "servingNetworkName": TEST_SNN,
                    "ausfInstanceId": "ausf-b"
                }),
            )
            .await
            .expect("generate-auth-data with failing SQN PATCH");
        assert_eq!(
            resp.status, 503,
            "a 404 on the SQN advance must withhold the AV: the stored SQN is \
             re-read every call, so issuing would reuse it (TS 33.102 §6.3.2)"
        );
        let body = json_body(&resp);
        assert!(
            body.get("authenticationVector").is_none(),
            "no authentication vector may be returned: {body}"
        );

        udm_server.stop().await.expect("stop udm");
        udr_server.stop().await.expect("stop udr");
        ausf_a_server.stop().await.expect("stop ausf-a");
        ausf_b_server.stop().await.expect("stop ausf-b");
    }

    // ========================================================================
    // #85: the Nudm service surface — error semantics, the ten services, and a
    // single NF profile.
    // ========================================================================

    /// Build a request with an arbitrary method, for the method-not-allowed
    /// assertions (the typed constructors only cover the verbs a handler uses).
    fn request_with_method(method: &str, uri: &str) -> SbiRequest {
        SbiRequest {
            header: nextgcore_sbi::message::SbiHeader::with_method_uri(method, uri),
            http: nextgcore_sbi::message::SbiHttpMessage::new(),
            ..SbiRequest::default()
        }
    }

    /// TS 29.500 §5.2.7.1: an unknown URI is `404 RESOURCE_URI_NOT_FOUND`, and a
    /// known resource addressed with the wrong method is `405` **with** `Allow`.
    /// Before #85 both were `405 METHOD_NOT_ALLOWED` with no `Allow`, so every
    /// mistyped path looked like a supported resource.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn test_http_nudm_error_semantics() {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _ = env_logger::try_init();
        udm_context_init(64, 64);
        let (udm_server, client) = start_real_udm().await;

        // --- 404 RESOURCE_URI_NOT_FOUND ------------------------------------
        for uri in [
            // Unknown resource under a known service.
            "/nudm-sdm/v2/imsi-001010000000001/not-a-resource",
            "/nudm-uecm/v1/imsi-001010000000001/registrations/not-a-resource",
            "/nudm-ueau/v1/imsi-001010000000001/not-a-resource",
            "/nudm-ee/v1/imsi-001010000000001/not-a-resource",
            // Entirely unknown service.
            "/nudm-nonsense/v1/imsi-001010000000001/am-data",
            // Too short to name anything.
            "/nudm-sdm/v2",
        ] {
            let resp = client.get(uri).await.expect("GET");
            assert_eq!(resp.status, 404, "{uri} must be 404, not 405");
            assert_eq!(
                json_body(&resp)["cause"],
                "RESOURCE_URI_NOT_FOUND",
                "{uri} cause"
            );
            assert!(
                !resp.http.headers.contains_key("allow"),
                "{uri}: a 404 must not advertise a method set"
            );
        }

        // --- 405 + Allow ---------------------------------------------------
        // Each of these resources exists; only the method is wrong.
        for (method, uri, expect_allow) in [
            (
                "DELETE",
                "/nudm-uecm/v1/imsi-001010000000001/registrations/amf-3gpp-access",
                "PUT, PATCH, GET",
            ),
            ("POST", "/nudm-sdm/v2/imsi-001010000000001/am-data", "GET"),
            (
                "GET",
                "/nudm-sdm/v2/imsi-001010000000001/sdm-subscriptions",
                "POST",
            ),
            (
                "DELETE",
                "/nudm-ueau/v1/imsi-001010000000001/auth-events",
                "POST",
            ),
            (
                "GET",
                "/nudm-ee/v1/imsi-001010000000001/ee-subscriptions/sub-1",
                "DELETE, PATCH",
            ),
            (
                "DELETE",
                "/nudm-pp/v1/imsi-001010000000001/pp-data",
                "GET, PATCH",
            ),
            ("POST", "/nudm-mt/v1/imsi-001010000000001", "GET"),
            ("GET", "/nudm-ueid/v1/deconceal", "POST"),
        ] {
            let req = request_with_method(method, uri);
            let resp = client.send_request(req).await.expect("send");
            assert_eq!(resp.status, 405, "{method} {uri} must be 405");
            assert_eq!(
                json_body(&resp)["cause"],
                "METHOD_NOT_ALLOWED",
                "{method} {uri} cause"
            );
            assert_eq!(
                resp.http.headers.get("allow").map(String::as_str),
                Some(expect_allow),
                "{method} {uri}: Allow header is mandatory on a 405"
            );
        }

        // --- 501 for the four defined-but-unimplemented services -----------
        for (method, uri) in [
            ("POST", "/nudm-niddau/v1/imsi-001010000000001/authorize"),
            (
                "POST",
                "/nudm-rsds/v1/imsi-001010000000001/sm-delivery-status",
            ),
            ("POST", "/nudm-ssau/v1/imsi-001010000000001/PROSE/authorize"),
            ("POST", "/nudm-ueid/v1/deconceal"),
        ] {
            let req = request_with_method(method, uri)
                .with_json_body(&serde_json::json!({}))
                .expect("json");
            let resp = client.send_request(req).await.expect("send");
            assert_eq!(
                resp.status, 501,
                "{uri} is a defined Nudm operation, so 501 not 405/404"
            );
            assert_eq!(json_body(&resp)["cause"], "NOT_IMPLEMENTED", "{uri} cause");
        }
        // ...but an undefined path under those services is still a 404.
        let resp = client
            .get("/nudm-ueid/v1/not-deconceal")
            .await
            .expect("GET");
        assert_eq!(resp.status, 404);
        assert_eq!(json_body(&resp)["cause"], "RESOURCE_URI_NOT_FOUND");

        udm_server.stop().await.expect("stop udm");
    }

    /// One profile builder, one advertised surface: `nudm-ee` is present (it was
    /// routed but undiscoverable), `nudm-sdm` is at v2, and the operator knobs
    /// come from configuration.
    #[test]
    fn test_nrf_profile_is_single_sourced_and_configurable() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        udm_context_init(64, 64);
        {
            let ctx = udm_self();
            let context = ctx.read().expect("context");
            context.set_nf_profile_config(crate::context::NfProfileConfig::default());
        }

        let profile = build_udm_nf_profile("udm-1", "10.45.0.10", 7777);
        let names: Vec<String> = profile["nfServices"]
            .as_array()
            .expect("nfServices")
            .iter()
            .map(|s| s["serviceName"].as_str().unwrap_or_default().to_string())
            .collect();
        for expected in [
            "nudm-sdm",
            "nudm-uecm",
            "nudm-ueau",
            "nudm-ee",
            "nudm-pp",
            "nudm-mt",
        ] {
            assert!(
                names.contains(&expected.to_string()),
                "{expected} must be advertised or no consumer can discover it: {names:?}"
            );
        }
        assert_eq!(advertised_version(&profile, "nudm-sdm"), "v2");
        assert_eq!(advertised_version(&profile, "nudm-ee"), "v1");
        // Defaults reproduce the pre-#85 literals exactly.
        assert_eq!(profile["heartBeatTimer"], 10);
        assert_eq!(
            profile["allowedNfTypes"],
            serde_json::json!(["AMF", "SMF", "AUSF", "PCF", "SCP"])
        );

        // Configured knobs reach the wire.
        {
            let ctx = udm_self();
            let context = ctx.read().expect("context");
            context.set_nf_profile_config(crate::context::NfProfileConfig {
                heart_beat_timer: 42,
                allowed_nf_types: vec!["NEF".to_string()],
            });
        }
        let profile = build_udm_nf_profile("udm-1", "10.45.0.10", 7777);
        assert_eq!(profile["heartBeatTimer"], 42);
        assert_eq!(profile["allowedNfTypes"], serde_json::json!(["NEF"]));

        // The service table is the ONE source: the typed self-instance built by
        // sbi_path and this JSON profile enumerate the same services in the same
        // order, so the two registration paths cannot advertise different
        // surfaces (the #85 v1-vs-v2 divergence).
        let table: Vec<String> = crate::sbi_path::UDM_ADVERTISED_SERVICES
            .iter()
            .map(|(name, _, _)| name.to_string())
            .collect();
        assert_eq!(names, table);

        // Restore the default so later tests see an unconfigured profile.
        let ctx = udm_self();
        if let Ok(context) = ctx.read() {
            context.set_nf_profile_config(crate::context::NfProfileConfig::default());
        };
    }

    /// `IdTranslationResult` assembly: `supi` is the only required member, the
    /// first identity of each list is primary, and `requested-gpsi-type` filters.
    #[test]
    fn test_build_id_translation_result_shapes() {
        // No SUPI -> no result at all (the caller must 404).
        assert!(build_id_translation_result(vec![], vec!["msisdn-1".into()], None).is_none());

        let r = build_id_translation_result(
            vec!["imsi-1".into(), "imsi-2".into()],
            vec!["msisdn-1".into(), "extid-a@example.org".into()],
            None,
        )
        .expect("result");
        assert_eq!(r["supi"], "imsi-1");
        assert_eq!(r["gpsi"], "msisdn-1");
        assert_eq!(r["additionalSupis"], serde_json::json!(["imsi-2"]));
        assert_eq!(
            r["additionalGpsis"],
            serde_json::json!(["extid-a@example.org"])
        );

        // requested-gpsi-type=EXT_ID must not hand back an MSISDN.
        let r = build_id_translation_result(
            vec!["imsi-1".into()],
            vec!["msisdn-1".into(), "extid-a@example.org".into()],
            Some("EXT_ID"),
        )
        .expect("result");
        assert_eq!(r["gpsi"], "extid-a@example.org");
        assert!(r.get("additionalGpsis").is_none());
    }

    /// #85 + the id-translation backlog item: `id-translation-result` is a
    /// **Nudm_SDM** operation (it was routed under nudm-uecm, where a conformant
    /// consumer would never look), and both directions are served from the UDR.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn test_http_id_translation_result_both_directions() {
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _ = env_logger::try_init();
        udm_context_init(64, 64);
        let (udr_server, store) = start_mock_udr_context_data().await;
        let (udm_server, client) = start_real_udm().await;

        let supi = "imsi-001010000000850";
        let gpsi = "msisdn-491721075423";
        store.lock().expect("store").insert(
            format!("/nudr-dr/v2/subscription-data/{gpsi}/identity-data"),
            serde_json::json!({ "supiList": [supi], "gpsiList": [gpsi] }),
        );

        // GPSI -> SUPI: the direction a NEF needs to target a UE by msisdn.
        let resp = client
            .get(&format!("/nudm-sdm/v2/{gpsi}/id-translation-result"))
            .await
            .expect("GET");
        assert_eq!(
            resp.status, 200,
            "GPSI->SUPI translation must be routed under nudm-sdm: {:?}",
            resp.http.content
        );
        let body = json_body(&resp);
        assert_eq!(body["supi"], supi);
        assert_eq!(body["gpsi"], gpsi);

        // The old (wrong) location must NOT answer it.
        let resp = client
            .get(&format!("/nudm-uecm/v1/{gpsi}/id-translation-result"))
            .await
            .expect("GET");
        assert_eq!(
            resp.status, 404,
            "id-translation-result is not a UECM resource"
        );
        assert_eq!(json_body(&resp)["cause"], "RESOURCE_URI_NOT_FOUND");

        // SUPI -> GPSI without identity-data: the am-data `gpsis` fallback.
        store.lock().expect("store").insert(
            format!("/nudr-dr/v2/subscription-data/{supi}/provisioned-data/am-data"),
            serde_json::json!({ "gpsis": [gpsi] }),
        );
        let resp = client
            .get(&format!("/nudm-sdm/v2/{supi}/id-translation-result"))
            .await
            .expect("GET");
        assert_eq!(resp.status, 200, "SUPI->GPSI falls back to am-data");
        let body = json_body(&resp);
        assert_eq!(body["supi"], supi);
        assert_eq!(body["gpsi"], gpsi);

        // An unknown GPSI has no identity-data and cannot fall back, so 404 —
        // never a fabricated SUPI.
        let resp = client
            .get("/nudm-sdm/v2/msisdn-000000000000/id-translation-result")
            .await
            .expect("GET");
        assert_eq!(resp.status, 404);
        assert_eq!(json_body(&resp)["cause"], "USER_NOT_FOUND");

        udm_server.stop().await.expect("stop udm");
        udr_server.stop().await.expect("stop udr");
    }

    /// Nudm_PP round-trips through the UDR, and Nudm_MT QueryUeInfo is proved
    /// against amfd's **real** Namf_MT producer rather than a mock: the
    /// information the operation returns is the AMF's, so a mock would only pin
    /// this UDM's idea of the AMF's response shape.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize global UDM state
    async fn test_http_nudm_pp_and_mt_are_served() {
        use nextgcore_sbi::context::{global_context, NfInstance, NfService};
        use nextgcore_sbi::types::{NfType, SbiServiceType};

        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _ = env_logger::try_init();
        udm_context_init(64, 64);
        let (udr_server, store) = start_mock_udr_context_data().await;
        let (udm_server, client) = start_real_udm().await;

        let supi = "imsi-001010000000851";
        let af = "af-1";

        // --- Nudm_PP ------------------------------------------------------
        // Provision an AF entry, read it back, then delete it.
        let entry = serde_json::json!({
            "communicationCharacteristics": { "ppSubsRegTimer": { "subsRegTimer": 3600 } }
        });
        let resp = client
            .put_json(&format!("/nudm-pp/v1/{supi}/pp-data-store/{af}"), &entry)
            .await
            .expect("PP entry PUT");
        assert_eq!(resp.status, 201, "PP data entry created");
        let resp = client
            .get(&format!("/nudm-pp/v1/{supi}/pp-data-store/{af}"))
            .await
            .expect("PP entry GET");
        assert_eq!(resp.status, 200);
        assert_eq!(json_body(&resp), entry);

        // PATCH pp-data provisions the UE-level parameters.
        store.lock().expect("store").insert(
            format!("/nudr-dr/v2/subscription-data/{supi}/pp-data"),
            serde_json::json!({}),
        );
        let resp = client
            .patch_json(
                &format!("/nudm-pp/v1/{supi}/pp-data"),
                &serde_json::json!({ "expectedUeBehaviourParameters": { "stationaryIndication": "STATIONARY" } }),
            )
            .await
            .expect("pp-data PATCH");
        assert_eq!(resp.status, 204, "Nudm_PP Update must be routed");
        let resp = client
            .get(&format!("/nudm-pp/v1/{supi}/pp-data"))
            .await
            .expect("pp-data GET");
        assert_eq!(resp.status, 200);
        assert_eq!(
            json_body(&resp)["expectedUeBehaviourParameters"]["stationaryIndication"],
            "STATIONARY",
            "the provisioned parameters must be readable back from the UDR"
        );

        let resp = client
            .delete(&format!("/nudm-pp/v1/{supi}/pp-data-store/{af}"))
            .await
            .expect("PP entry DELETE");
        assert_eq!(resp.status, 204);
        let resp = client
            .get(&format!("/nudm-pp/v1/{supi}/pp-data-store/{af}"))
            .await
            .expect("PP entry GET after delete");
        assert_eq!(resp.status, 404);

        // 5G VN group management is recognised and refused as unimplemented.
        let resp = client
            .get("/nudm-pp/v1/5g-vn-groups/extgroupid-1")
            .await
            .expect("VN group GET");
        assert_eq!(resp.status, 501);

        // --- Nudm_MT (strict peer: udmd -> amfd's REAL Namf_MT) ------------
        // `fields` is mandatory.
        let resp = client
            .get(&format!("/nudm-mt/v1/{supi}"))
            .await
            .expect("QueryUeInfo without fields");
        assert_eq!(resp.status, 400, "QueryUeInfo requires 'fields'");
        assert_eq!(json_body(&resp)["cause"], "MANDATORY_IE_MISSING");

        // A field this UDM cannot retrieve is named, not silently omitted.
        let resp = client
            .get(&format!("/nudm-mt/v1/{supi}?fields=userState"))
            .await
            .expect("QueryUeInfo unsupported field");
        assert_eq!(resp.status, 501);
        assert!(
            json_body(&resp)["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("userState"),
            "the 501 must name the field so the consumer can retry"
        );

        // An unregistered UE has no AMF to ask.
        let resp = client
            .get(&format!("/nudm-mt/v1/{supi}?fields=tadsInfo"))
            .await
            .expect("QueryUeInfo unregistered");
        assert_eq!(resp.status, 404);
        assert_eq!(json_body(&resp)["cause"], "CONTEXT_NOT_FOUND");

        // Stand up amfd's REAL Namf handler and register it as the serving AMF.
        let amf_instance_id = "amf-for-mt-test";
        let amf_port = free_port();
        let amf_addr = SocketAddr::from(([127, 0, 0, 1], amf_port));
        let amf_server = SbiServer::new(NextgcoreSbiServerConfig::new(amf_addr));
        amf_server
            .start(nextgcore_amfd::namf_request_handler)
            .await
            .expect("amfd Namf server starts");
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(amf_addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut instance = NfInstance::new(amf_instance_id, NfType::Amf);
        instance.ipv4_addresses.push("127.0.0.1".to_string());
        let mut svc = NfService::new("namf-mt", SbiServiceType::NamfMt);
        svc.versions = vec!["v1".to_string()];
        svc.port = amf_port;
        instance.add_service(svc);
        global_context().add_nf_instance(instance).await;

        // Seed amfd's UE context so its real handler resolves the SUPI.
        nextgcore_amfd::test_support::init_context();
        {
            let ctx = nextgcore_amfd::context::amf_self();
            let guard = ctx.read().expect("amf ctx");
            let ran = guard.ran_ue_add(900_500, 60_200).expect("ran_ue_add");
            let ue = guard.amf_ue_add(ran.id).expect("amf_ue_add");
            guard.amf_ue_set_supi(ue.id, supi);
            let mut ue = ue;
            ue.supi = Some(supi.to_string());
            guard.amf_ue_update(&ue);
        }
        // Register the UE in the UDM's UECM store so the serving AMF is known.
        store.lock().expect("store").insert(
            format!("/nudr-dr/v2/subscription-data/{supi}/context-data/amf-3gpp-access"),
            serde_json::json!({
                "amfInstanceId": amf_instance_id,
                "deregCallbackUri": "http://amf.example.org:7777/namf-callback/v1/x/dereg-notify",
                "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe00" },
                "ratType": "NR"
            }),
        );

        let resp = client
            .get(&format!("/nudm-mt/v1/{supi}?fields=tadsInfo"))
            .await
            .expect("QueryUeInfo");
        assert_eq!(
            resp.status, 200,
            "QueryUeInfo must proxy to the serving AMF: {:?}",
            resp.http.content
        );
        let body = json_body(&resp);
        assert_eq!(
            body["tadsInfo"]["accessType"], "3GPP_ACCESS",
            "the UeContextInfo amfd's REAL Namf_MT producer returned must be \
             carried through verbatim: {body}"
        );

        // provide-loc-info is recognised and refused: no AMF here serves
        // Namf_Location ProvideLocationInfo.
        let resp = client
            .post_json(
                &format!("/nudm-mt/v1/{supi}/loc-info/provide-loc-info"),
                &serde_json::json!({ "req5gsLoc": true }),
            )
            .await
            .expect("provide-loc-info");
        assert_eq!(resp.status, 501);

        udm_server.stop().await.expect("stop udm");
        udr_server.stop().await.expect("stop udr");
        amf_server.stop().await.expect("stop amf");
    }
}

#[cfg(test)]
mod oauth2_h8_tests {
    //! Wave-6 H8 (Phase B) strict-peer OAuth2 enforcement triplet: the real
    //! `udm_sbi_request_handler` is mounted behind nextgcore-sbi's server-side
    //! OAuth2 verification (TS 33.501 §13.4.1). A missing or wrong-audience
    //! Bearer is rejected (401) before the handler runs; a valid NRF-audience
    //! token (aud=UDM, ES256-signed against the served JWKS) passes through.
    use nextgcore_sbi::client::SbiClient;
    use nextgcore_sbi::message::SbiRequest;
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    use nextgcore_sbi::types::NfType;
    use std::net::SocketAddr;
    use std::time::Duration;

    fn free_port() -> u16 {
        nextgcore_sbi::test_support::free_port()
    }

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
            "iss": "NRF", "sub": "udm-1", "aud": aud,
            "scope": scope, "exp": exp, "iat": 0
        })
        .to_string();
        let h = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let p = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let sig: Signature = sk.sign(format!("{h}.{p}").as_bytes());
        let s = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{h}.{p}.{s}")
    }

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
        super::udm_context_init(64, 64);
        let port = free_port();
        let mut cfg = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(jwks);
        cfg = cfg.with_expected_audience_nf_type(NfType::Udm);
        let server = SbiServer::new(cfg);
        server
            .start(super::udm_sbi_request_handler)
            .await
            .expect("server start");
        (server, port)
    }

    #[test]
    fn test_oauth2_require_knob_parses_and_defaults_off() {
        let dir = std::env::temp_dir();
        let off = dir.join(format!("udm-h8-off-{}.yaml", std::process::id()));
        std::fs::write(
            &off,
            "udm:\n  sbi:\n    server:\n      - address: 127.0.0.1\n",
        )
        .unwrap();
        assert!(!super::oauth2_required(off.to_str().unwrap()));
        let on = dir.join(format!("udm-h8-on-{}.yaml", std::process::id()));
        std::fs::write(&on, "udm:\n  sbi:\n    oauth2:\n      require: true\n").unwrap();
        assert!(super::oauth2_required(on.to_str().unwrap()));
        let _ = std::fs::remove_file(off);
        let _ = std::fs::remove_file(on);
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn test_oauth2_missing_token_rejected_401() {
        // Serialize on the shared context guard: this test mutates the
        // process-global UDM context (udm_context_init/udm_self) and must
        // not interleave with other guarded tests (CI flake root cause).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let sk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let (server, port) = start_server(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            client.get("/nudm-sdm/v2/imsi-001/am-data"),
        )
        .await
        .expect("bounded")
        .expect("response");
        assert_eq!(resp.status, 401, "unauthenticated request must be 401");
        server.stop().await.expect("stop");
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn test_oauth2_wrong_audience_rejected_401() {
        // Serialize on the shared context guard: this test mutates the
        // process-global UDM context (udm_context_init/udm_self) and must
        // not interleave with other guarded tests (CI flake root cause).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let sk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let (server, port) = start_server(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let token = build_es256_token(&sk, "nrf-es256", "AMF", "nudm-sdm");
        let req = SbiRequest::get("/nudm-sdm/v2/imsi-001/am-data")
            .with_header("Authorization", format!("Bearer {token}"));
        let resp = tokio::time::timeout(Duration::from_secs(5), client.send_request(req))
            .await
            .expect("bounded")
            .expect("response");
        assert_eq!(resp.status, 401, "wrong-audience token must be 401");
        server.stop().await.expect("stop");
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn test_oauth2_valid_token_reaches_handler() {
        // Serialize on the shared context guard: this test mutates the
        // process-global UDM context (udm_context_init/udm_self) and must
        // not interleave with other guarded tests (CI flake root cause).
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let sk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let (server, port) = start_server(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let token = build_es256_token(&sk, "nrf-es256", "UDM", "nudm-sdm");
        let req = SbiRequest::get("/nudm-sdm/v2/imsi-001/am-data")
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
