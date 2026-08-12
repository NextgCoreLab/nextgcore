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
    send_bad_request, send_method_not_allowed, send_not_found, SbiServer,
    SbiServerConfig as NextgcoreSbiServerConfig,
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

    /// Kill running instance
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

#[derive(Debug, Default, Deserialize)]
struct SbiYaml {
    server: Option<Vec<SbiServerYaml>>,
    client: Option<SbiClientYaml>,
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
            nextgcore_sbi::client::SbiClient::new(nextgcore_sbi::client::SbiClientConfig::new(
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

    // Handle kill flag
    if args.kill {
        log::info!("Kill flag set - would send SIGTERM to running instance");
        return Ok(());
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
    if oauth2_required(&args.config) {
        sbi_server_config = apply_oauth2_enforcement(sbi_server_config).await;
    }
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
    // - /nudm-ueau/v1/{supi}/security-information/generate-auth-data

    if parts.len() < 3 {
        return send_not_found("Invalid path", None);
    }

    let service = parts[0];
    let _version = parts[1];

    match service {
        // UE Context Management Service (nudm-uecm)
        "nudm-uecm" if parts.len() >= 4 => {
            let supi = parts[2];
            let resource = parts.get(3).unwrap_or(&"");

            match (*resource, method) {
                ("registrations", "PUT") if parts.len() >= 5 && parts[4] == "amf-3gpp-access" => {
                    handle_amf_registration(supi, &request).await
                }
                ("registrations", "PATCH") if parts.len() >= 5 && parts[4] == "amf-3gpp-access" => {
                    handle_amf_registration_update(supi, &request).await
                }
                ("registrations", "DELETE")
                    if parts.len() >= 5 && parts[4] == "amf-3gpp-access" =>
                {
                    handle_amf_deregistration(supi).await
                }
                // udmd-12: AMF non-3GPP access registration (TS 29.503 §5.3.3).
                ("registrations", "PUT")
                    if parts.len() >= 5 && parts[4] == "amf-non-3gpp-access" =>
                {
                    handle_amf_non3gpp_registration(supi, &request).await
                }
                ("registrations", "PUT") if parts.len() >= 6 && parts[4] == "smf-registrations" => {
                    let pdu_session_id = parts[5];
                    handle_smf_registration(supi, pdu_session_id, &request).await
                }
                ("registrations", "DELETE")
                    if parts.len() >= 6 && parts[4] == "smf-registrations" =>
                {
                    let pdu_session_id = parts[5];
                    handle_smf_deregistration(supi, pdu_session_id).await
                }
                // udmd-12: UE context in SMF data (GET only, TS 29.503 §6.3.x).
                ("ue-context-in-smf-data", "GET") => {
                    send_not_implemented("ue-context-in-smf-data is not yet implemented")
                }
                // udmd-12: SUPI-to-GPSI/external-id translation (TS 29.503 §6.4.x).
                ("id-translation-result", "GET") => {
                    send_not_implemented("id-translation-result is not yet implemented")
                }
                _ => send_method_not_allowed(method, uri),
            }
        }

        // Subscriber Data Management Service (nudm-sdm)
        "nudm-sdm" if parts.len() >= 4 => {
            let supi = parts[2];
            let resource = parts.get(3).unwrap_or(&"");

            match (*resource, method) {
                ("am-data", "GET") => handle_get_am_data(supi, &request).await,
                // udmd#1: SoR / UPU acknowledgement (TS 29.503 5.2.2.6, PUT).
                ("am-data", "PUT") if parts.len() >= 5 && parts[4] == "sor-ack" => {
                    handle_sor_ack(supi, &request).await
                }
                ("am-data", "PUT") if parts.len() >= 5 && parts[4] == "upu-ack" => {
                    handle_upu_ack(supi, &request).await
                }
                ("smf-select-data", "GET") => handle_get_smf_select_data(supi, &request).await,
                ("sm-data", "GET") => handle_get_sm_data(supi, &request).await,
                ("nssai", "GET") => handle_get_nssai(supi, &request).await,
                ("sdm-subscriptions", "POST") => handle_sdm_subscribe(supi, &request).await,
                ("sdm-subscriptions", "DELETE") if parts.len() >= 5 => {
                    let subscription_id = parts[4];
                    handle_sdm_unsubscribe(supi, subscription_id).await
                }
                // udmd-12: SDM subscription modification PATCH is not implemented.
                ("sdm-subscriptions", "PATCH") if parts.len() >= 5 => {
                    send_not_implemented("sdm-subscriptions PATCH is not yet implemented")
                }
                _ => send_method_not_allowed(method, uri),
            }
        }

        // UE Authentication Service (nudm-ueau)
        "nudm-ueau" if parts.len() >= 4 => {
            let supi = parts[2];
            let resource = parts.get(3).unwrap_or(&"");
            let action = parts.get(4).copied().unwrap_or("");

            match (*resource, action, method) {
                ("security-information", "generate-auth-data", "POST") => {
                    handle_generate_auth_data(supi, &request).await
                }
                ("auth-events", _, "POST") => handle_auth_event(supi, &request).await,
                _ => send_method_not_allowed(method, uri),
            }
        }

        // Event Exposure Service (nudm-ee) - udmd#0, TS 29.503 5.5/6.4
        "nudm-ee" if parts.len() >= 4 => {
            let ue_identity = parts[2];
            let resource = parts.get(3).unwrap_or(&"");
            match (*resource, method) {
                ("ee-subscriptions", "POST") => handle_ee_subscribe(ue_identity, &request).await,
                ("ee-subscriptions", "DELETE") if parts.len() >= 5 => {
                    handle_ee_unsubscribe(ue_identity, parts[4]).await
                }
                ("ee-subscriptions", "PATCH") if parts.len() >= 5 => {
                    handle_ee_modify(ue_identity, parts[4], &request).await
                }
                _ => send_method_not_allowed(method, uri),
            }
        }

        _ => {
            log::warn!("Unknown UDM request: {method} {uri}");
            send_method_not_allowed(method, uri)
        }
    }
}

// UE Context Management handlers

pub async fn handle_amf_registration(supi: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("AMF Registration: SUPI={supi}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let reg_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    // udmd-03 (validate) -> udmd-01 (persist to UDR) -> udmd-02 (notify old AMF).
    crate::uecm::process_amf_registration(supi, &reg_data, &crate::uecm::UdrClient::Live).await
}

pub async fn handle_amf_registration_update(supi: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("AMF Registration Update: SUPI={supi}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let update_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    // udmd-05: GUAMI ownership check + UDR PATCH.
    crate::uecm::process_amf_registration_update(supi, &update_data, &crate::uecm::UdrClient::Live)
        .await
}

pub async fn handle_amf_deregistration(supi: &str) -> SbiResponse {
    log::info!("AMF Deregistration: SUPI={supi}");

    // udmd-01: DELETE the UDR context-data before returning 204.
    crate::uecm::process_amf_deregistration(supi, &crate::uecm::UdrClient::Live).await
}

/// udmd-12: AMF non-3GPP-access registration (PUT).
///
/// TS 29.503 §5.3.3 defines this for N3IWF/TNGF use cases.  We accept the
/// request and persist via the same AMF context PUT path (same Nudr resource),
/// returning 201/200 exactly like the 3GPP-access variant.
pub async fn handle_amf_non3gpp_registration(supi: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("AMF Non-3GPP Registration: SUPI={supi}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let reg_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    // Reuse the same UECM registration path — UDR resource key is different
    // (/amf-non-3gpp-access) but the validation and persistence logic is the same.
    crate::uecm::process_amf_registration(supi, &reg_data, &crate::uecm::UdrClient::Live).await
}

pub async fn handle_smf_registration(
    supi: &str,
    pdu_session_id: &str,
    request: &SbiRequest,
) -> SbiResponse {
    log::info!("SMF Registration: SUPI={supi}, PDU Session={pdu_session_id}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let reg_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
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

/// udmd#0: Nudm_EE UpdateEeSubscription (TS 29.503 5.5.2.4).
/// JSON-Patch application deferred; 204 on existing sub / 404 otherwise (yaml 363).
pub async fn handle_ee_modify(
    ue_identity: &str,
    subscription_id: &str,
    _request: &SbiRequest,
) -> SbiResponse {
    log::info!("EE Modify: ueIdentity={ue_identity}, subscriptionId={subscription_id}");
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
    SbiResponse::with_status(204)
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
    if auth_info
        .get("ausfInstanceId")
        .and_then(|v| v.as_str())
        .map(|s| s.is_empty())
        .unwrap_or(true)
    {
        return send_problem(
            400,
            "MANDATORY_IE_MISSING",
            "AuthenticationInfoRequest.ausfInstanceId is missing",
        );
    }

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
        Ok(r) if r.status >= 500 => {
            log::error!(
                "[{supi}] UDR SQN PATCH returned {}: refusing to issue AV",
                r.status
            );
            return nextgcore_sbi::server::send_service_unavailable("UDR SQN update failed");
        }
        Ok(r) => {
            // Non-5xx (e.g. 404): UDR may not have auth-subscription resource; degrade.
            log::warn!(
                "[{supi}] UDR SQN PATCH returned {} (degraded — AV issued anyway)",
                r.status
            );
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

    // Record the auth event in the local UE context.
    {
        let ctx = udm_self();
        if let Ok(context) = ctx.read() {
            if let Some(mut ue) = context.ue_find_by_supi(supi) {
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

    // Build a stable auth-event resource URI for the Location header.
    let event_id = uuid::Uuid::new_v4().to_string();
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
/// Split out of `register_with_nrf_id` so the advertised API versions can be
/// asserted without standing up an NRF. The version per service is normative
/// and easy to get wrong: **Nudm_SDM is v2** (TS 29.503 §6.1.1, "The
/// `<apiVersion>` shall be v2") while Nudm_UECM and Nudm_UEAU are v1.
fn build_udm_nf_profile(nf_instance_id: &str, sbi_addr: &str, sbi_port: u16) -> serde_json::Value {
    serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "UDM",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [
            {
                "serviceInstanceId": format!("{nf_instance_id}-nudm-sdm"),
                "serviceName": "nudm-sdm",
                // TS 29.503 §6.1.1: "The <apiVersion> shall be v2" for
                // Nudm_SDM. The other Nudm services stay at v1. Advertising v1
                // here made discovery hand consumers a URI a strict producer
                // would 404.
                "versions": [{"apiVersionInUri": "v2", "apiFullVersion": "2.0.0"}],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
            },
            {
                "serviceInstanceId": format!("{nf_instance_id}-nudm-uecm"),
                "serviceName": "nudm-uecm",
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
            },
            {
                "serviceInstanceId": format!("{nf_instance_id}-nudm-ueau"),
                "serviceName": "nudm-ueau",
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
            }
        ],
        "allowedNfTypes": ["AMF", "SMF", "AUSF", "PCF", "SCP"],
        "heartBeatTimer": 10
    })
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
