//! NextGCore PCF (Policy Control Function)
//!
//! The PCF is a 5G core network function responsible for:
//! - Policy control for AM (Access Management)
//! - Policy control for SM (Session Management)
//! - Policy authorization for application sessions

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

// Wave-6 H1 lib-targetization: the PCF module tree lives in the
// `nextgcore_pcfd` library crate (src/lib.rs) so peer NF crates and this
// package's own integration tests can call the real builders/handlers
// in-process (strict-peer pattern); the binary consumes the library exactly
// like nextgcore-udrd/udmd.
use crate::context::*;
use crate::event::*;
use crate::npcf_handler::*;
use crate::nudr_handler::*;
use crate::pcf_sm::PcfSmContext;
use crate::sbi_path::*;
use crate::sm_policy_build::{build_sm_policy_decision, format_bitrate};
use crate::timer::timer_manager;
use crate::{npcf_handler, nudr_handler, sbi_path, ue_policy};

/// NextGCore PCF - Policy Control Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-pcfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Policy Control Function", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/pcf.yaml")]
    config: String,

    /// JSON snapshot file for AM/SM policy associations, PDU sessions and AF
    /// application sessions (issue #66/#192).
    ///
    /// Falls back to `NEXTGCORE_PCF_STATE_FILE`; an empty value is treated as
    /// unset. With neither set the PCF is memory-only, which is the shipped
    /// default and byte-identical to previous behaviour. An unreadable snapshot,
    /// or one written by a newer build, FAILS STARTUP rather than coming up empty
    /// and overwriting it.
    #[arg(long)]
    state_file: Option<String>,

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

    /// NRF URI (e.g., http://127.0.0.10:7777)
    #[arg(long)]
    nrf_uri: Option<String>,

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
    /// Optional advertised FQDN. When configured it is emitted as `pcfFqdn`
    /// in TS 29.521 PcfBinding registrations towards the BSF (WSB-1); never
    /// invented when absent (pcfIpEndPoints alone satisfies the spec NOTE).
    fqdn: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SbiYaml {
    server: Option<Vec<SbiServerYaml>>,
    client: Option<SbiClientYaml>,
}

/// Declarative intent block (issue #24, feature `intent-loop`): ONE slice
/// latency outcome for the closed-loop controller. Converted leniently from
/// the raw `PcfSection::intent` value under the feature; without the feature
/// the block is ignored.
#[derive(Debug, Default, Deserialize, Clone)]
pub(crate) struct IntentYaml {
    pub(crate) enabled: Option<bool>,
    /// Target slice S-NSSAI SST.
    pub(crate) sst: Option<u8>,
    /// Target slice S-NSSAI SD (hex string; informational in the spike).
    pub(crate) sd: Option<String>,
    /// The declared outcome: keep slice latency below this many ms.
    pub(crate) max_latency_ms: Option<f64>,
    pub(crate) poll_interval_secs: Option<u64>,
    /// SlaPolicyAdapter aggressiveness (0.0..=1.0).
    pub(crate) aggressiveness: Option<f64>,
    /// Synthetic NF_LOAD→latency proxy slope (ms per load percent); see
    /// docs/intent-driven-policy-loop.md.
    pub(crate) nf_load_latency_ms_per_pct: Option<f64>,
}

#[derive(Debug, Default, Deserialize)]
struct PcfSection {
    sbi: Option<SbiYaml>,
    /// Raw YAML value, NOT the typed [`IntentYaml`]: a malformed intent
    /// block must never fail the whole `PcfYaml` parse (which would silently
    /// skip SBI-address/NRF-URI seeding, in the default build too). The
    /// typed conversion happens leniently under the `intent-loop` feature.
    intent: Option<serde_yaml::Value>,
}

#[derive(Debug, Default, Deserialize)]
struct PcfYaml {
    pcf: Option<PcfSection>,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// OAuth2 rollout (Wave-6 H8): opt-in producer verification + outbound consumer
// token install. Default OFF so the matched-sim E2E path is byte-unchanged;
// the docker `pcf-oauth2.yaml` overlay (or NEXTGCORE_SBI_OAUTH2_REQUIRE=1) sets
// `pcf.sbi.oauth2.require: true`. TS 33.501 §13.4.1, TS 29.510 §5.4.2.
// ---------------------------------------------------------------------------

/// Process-wide OAuth2 client for automatic Bearer-token acquisition on
/// outbound SBI calls (installed only when OAuth2 enforcement is enabled).
static OAUTH2_CLIENT: std::sync::OnceLock<Option<Arc<nextgcore_sbi::oauth::OAuth2Client>>> =
    std::sync::OnceLock::new();

/// The shared OAuth2 client, if SBI OAuth2 enforcement is enabled (Wave-6 H8
/// Phase A). Outbound SBI clients attach a token via [`attach_oauth2`].
pub(crate) fn oauth2_client() -> Option<Arc<nextgcore_sbi::oauth::OAuth2Client>> {
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
/// NRF JWKS and requires `aud` to include NfType::Pcf; with no NRF URI
/// configured it fails closed (503, per nextgcore-sbi server.rs).
async fn apply_oauth2_enforcement(mut cfg: NextgcoreSbiServerConfig) -> NextgcoreSbiServerConfig {
    let nrf_uri = nextgcore_sbi::context::global_context().get_nrf_uri().await;
    cfg.require_oauth2 = true;
    cfg.oauth2_jwks_uri = nrf_uri.as_deref().map(|uri| {
        nextgcore_sbi::oauth::JwksCache::for_nrf(uri)
            .jwks_uri()
            .to_string()
    });
    cfg = cfg.with_expected_audience_nf_type(nextgcore_sbi::types::NfType::Pcf);
    if let Some(uri) = nrf_uri.as_deref() {
        let nf_instance_id = format!("pcf-{}", uuid::Uuid::new_v4());
        let _ = OAUTH2_CLIENT.set(Some(Arc::new(nextgcore_sbi::oauth::OAuth2Client::new(
            uri,
            nf_instance_id,
            nextgcore_sbi::types::NfType::Pcf,
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

    log::info!("NextGCore PCF v{} starting...", env!("CARGO_PKG_VERSION"));

    // Issue: `--kill` was advertised as "Kill running instance" and did
    // NOTHING -- it logged an intention and returned success, so the process
    // exited 0 while the instance kept serving. Fail loudly instead.
    if args.kill {
        return Err(nextgcore_core::signal::kill_unsupported().into());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize PCF context
    pcf_context_init(args.max_ue, args.max_sess);
    log::info!(
        "PCF context initialized (max_ue={}, max_sess={})",
        args.max_ue,
        args.max_sess
    );

    // Issue #66/#192: restore durable state AFTER the context knows its capacity
    // caps and BEFORE the SBI server can accept a request, so a restored
    // association is never shadowed by a fresh one. Precedence matches the other
    // NFs: the flag wins over the env var, and an empty value is treated as unset.
    let state_file = args
        .state_file
        .clone()
        .or_else(|| std::env::var("NEXTGCORE_PCF_STATE_FILE").ok())
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty());
    if let Some(path) = state_file {
        let ctx = crate::context::pcf_self();
        let mut guard = ctx
            .write()
            .map_err(|_| anyhow::anyhow!("PCF context lock poisoned"))?;
        // Fail STARTUP on a snapshot that cannot be read or is from a newer build.
        // Coming up empty would answer "no such association" for associations that
        // exist -- so the AMF and SMF could neither update nor tear them down --
        // and the store would then refuse every later write to protect the file.
        let restored = guard.set_state_file(std::path::PathBuf::from(&path))?;
        log::info!("PCF durable state: {path} ({restored} record(s) restored)");
    } else {
        log::info!(
            "PCF durable state disabled (no --state-file / NEXTGCORE_PCF_STATE_FILE): \
             policy associations and app sessions are memory-only and lost on restart"
        );
    }

    // Initialize PCF state machine
    let mut pcf_sm = PcfSmContext::new();
    pcf_sm.init();
    log::info!("PCF state machine initialized");

    // Parse configuration (if file exists) and seed NRF URI
    let mut sbi_fqdn: Option<String> = None;
    #[cfg(feature = "intent-loop")]
    let mut intent_yaml: Option<IntentYaml> = None;
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
        match std::fs::read_to_string(&args.config) {
            Ok(content) => {
                log::debug!("Configuration file loaded ({} bytes)", content.len());
                // Seed NRF URI into SBI context for NF registration
                if let Ok(yaml) = serde_yaml::from_str::<PcfYaml>(&content) {
                    if let Some(pcf) = yaml.pcf {
                        #[cfg(feature = "intent-loop")]
                        {
                            intent_yaml = pcf.intent.clone().and_then(|v| {
                                match serde_yaml::from_value::<IntentYaml>(v) {
                                    Ok(y) => Some(y),
                                    Err(e) => {
                                        log::warn!(
                                            "intent-loop: invalid pcf.intent block ignored: {e}"
                                        );
                                        None
                                    }
                                }
                            });
                        }
                        if let Some(sbi) = pcf.sbi {
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
                                if let Some(fqdn) = &server.fqdn {
                                    sbi_fqdn = Some(fqdn.clone());
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
        nrf_uri: args.nrf_uri.clone(),
    };

    // Open legacy SBI server (for context initialization)
    pcf_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;

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
        .start(pcf_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    log::info!("SBI HTTP/2 server listening on {sbi_addr}");

    // WSB-1/H2: publish this PCF's advertised identity (addr/port, optional
    // FQDN, NF instance id) so build_pcf_binding_body can emit the mandatory
    // PCF address information (TS 29.521 §5.3.2 pcfFqdn|pcfIpEndPoints) and
    // pcfId in Nbsf_Management PcfBinding registrations. The same instance id
    // is used for the NRF NFProfile below so pcfId == nfInstanceId (TS 29.510).
    // #90: the instance id is the one `pcf_sbi_open` already published to the SBI
    // context, NOT a fresh UUID. Minting a second one here is what made pcfd
    // register twice with the NRF under two different ids, with the BSF's `pcfId`
    // naming one of them and the other never heartbeaten. Taking it from the
    // context makes `pcfId == nfInstanceId` true, as the comment above always
    // claimed it was.
    let nf_instance_id = match nextgcore_sbi::context::global_context()
        .get_self_instance()
        .await
    {
        Some(instance) => instance.id,
        None => {
            // pcf_sbi_open publishes the instance from a spawned task, so on a
            // very cold start it can lose the race. Falling back to a fresh id
            // would silently reintroduce the two-id split, so this is loud.
            log::error!(
                "PCF self instance not published by pcf_sbi_open; NRF registration and BSF \
                 pcfId would disagree. Continuing without NRF registration."
            );
            String::new()
        }
    };
    sbi_path::pcf_self_info_set(sbi_path::PcfSelfInfo {
        sbi_addr: args.sbi_addr.clone(),
        sbi_port: args.sbi_port,
        fqdn: sbi_fqdn.clone(),
        nf_instance_id: nf_instance_id.clone(),
    });

    // Register with NRF and start heartbeat worker. ONE registration, through the
    // single profile builder in sbi_path, so the advertised service set cannot
    // drift from the one the router actually serves.
    if !nf_instance_id.is_empty() {
        match sbi_path::pcf_register_with_nrf().await {
            Ok(Some(registered_id)) => {
                // G2-2: PATCH a real NFProfile "/load" gauge to NRF each heartbeat
                // (policy sessions vs configured capacity; TS 29.510 §5.2.2.3.2).
                nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(
                    registered_id,
                    5,
                    || {
                        let ctx = crate::context::pcf_self();
                        let load = ctx.read().map(|c| c.get_load()).unwrap_or(0);
                        load.clamp(0, 100) as u8
                    },
                );
            }
            Ok(None) => {}
            Err(e) => {
                log::warn!("NRF registration failed (will operate without NRF): {e}");
            }
        }
    }

    // #299: subscribe to the UDR for policy-data changes, AFTER the SBI server is
    // listening. The ordering is the point: the subscription advertises this PCF's own
    // callback URI, and a UDR that notified before the route existed would post into a
    // 404 -- the same constraint #293 hit on the SMF's SDM subscribe. Best effort: with
    // no UDR or no NRF the PCF behaves exactly as it did before, which is the gap this
    // closes rather than a startup failure.
    let policy_data_subscription = sbi_path::pcf_subscribe_udr_policy_data().await;

    log::info!("NextGCore PCF ready");

    // Issue #24: intent-driven closed-loop policy controller (feature
    // `intent-loop`, off by default). Spawned regardless of NRF-registration
    // outcome: without an NRF, NWDAF discovery degrades to
    // `observed=unavailable` rather than blocking startup.
    #[cfg(feature = "intent-loop")]
    crate::intent_loop::spawn_if_enabled(
        intent_yaml
            .as_ref()
            .map(crate::intent_loop::IntentSettings::from_yaml),
    );

    // Main event loop (async)
    run_event_loop_async(&mut pcf_sm, shutdown).await?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // #299: drop the policy-data subscription before the listener goes away, for the
    // same reason as the NRF deregistration below -- a UDR still holding it would post
    // notifications at a socket that has closed, and udrd only logs a delivery failure,
    // so the subscription would linger for the life of that UDR.
    if let Some(resource) = policy_data_subscription {
        sbi_path::pcf_unsubscribe_udr_policy_data(&resource).await;
    }

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

    // Close legacy SBI server
    pcf_sbi_close();
    log::info!("SBI server closed");

    // Cleanup state machine
    pcf_sm.fini();
    log::info!("PCF state machine finalized");

    // Cleanup context
    pcf_context_final();
    log::info!("PCF context finalized");

    log::info!("NextGCore PCF stopped");
    Ok(())
}

/// SBI request handler for PCF
pub async fn pcf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("PCF SBI request: {method} {uri}");

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    // Route based on service and resource
    // Expected paths:
    // - /npcf-am-policy-control/v1/policies/{polAssoId}
    // - /npcf-smpolicycontrol/v1/sm-policies/{smPolicyId}
    // - /npcf-policyauthorization/v1/app-sessions/{appSessionId}

    if parts.len() < 3 {
        return send_not_found("Invalid path", None);
    }

    let service = parts[0];
    let _version = parts[1];
    let resource = parts[2];

    match (service, resource, method) {
        // AM Policy Control Service (npcf-am-policy-control, TS 29.507)
        // Note: order matters — guarded sub-resource arms first. The update
        // operation is POST /policies/{polAssoId}/update (TS 29.507 §4.2.4),
        // NOT PATCH; the PATCH arm is kept only for backward compatibility.
        ("npcf-am-policy-control", "policies", "POST")
            if parts.len() >= 5 && parts[4] == "update" =>
        {
            let pol_asso_id = parts[3];
            handle_am_policy_update(pol_asso_id, &request).await
        }
        ("npcf-am-policy-control", "policies", "POST") if parts.len() < 4 => {
            // Create AM Policy Association
            handle_am_policy_create(&request).await
        }
        ("npcf-am-policy-control", "policies", "GET") if parts.len() >= 4 => {
            // Get AM Policy Association
            let pol_asso_id = parts[3];
            handle_am_policy_get(pol_asso_id).await
        }
        ("npcf-am-policy-control", "policies", "DELETE") if parts.len() >= 4 => {
            // Delete AM Policy Association
            let pol_asso_id = parts[3];
            handle_am_policy_delete(pol_asso_id).await
        }
        ("npcf-am-policy-control", "policies", "PATCH") if parts.len() >= 4 => {
            // Legacy update path (kept for backward compatibility)
            let pol_asso_id = parts[3];
            handle_am_policy_update(pol_asso_id, &request).await
        }

        // UE Policy Control Service (npcf-ue-policy-control, TS 29.525)
        // Note: update sub-resource arm first (POST .../policies/{id}/update)
        ("npcf-ue-policy-control", "policies", "POST")
            if parts.len() >= 5 && parts[4] == "update" =>
        {
            handle_ue_policy_update(parts[3], &request).await
        }
        ("npcf-ue-policy-control", "policies", "POST") if parts.len() < 4 => {
            handle_ue_policy_create(&request).await
        }
        ("npcf-ue-policy-control", "policies", "GET") if parts.len() >= 4 => {
            handle_ue_policy_get(parts[3]).await
        }
        ("npcf-ue-policy-control", "policies", "DELETE") if parts.len() >= 4 => {
            handle_ue_policy_delete(parts[3]).await
        }
        // Wave-6 E6 delivery-result callback: the AMF POSTs an N1MessageNotify
        // (TS 29.518 §5.2.2.4) carrying the UE's uplink MANAGE UE POLICY
        // COMPLETE/REJECT to the callback URI this PCF registered via
        // N1N2MessageSubscribe. Path: /npcf-ue-policy-control/v1/notify/{polAssoId}/n1-message-notify
        ("npcf-ue-policy-control", "notify", "POST")
            if parts.len() >= 5 && parts[4] == "n1-message-notify" =>
        {
            handle_ue_policy_n1_notify(parts[3], &request).await
        }

        // SM Policy Control Service (npcf-smpolicycontrol, TS 29.512)
        // Note: Order matters - more specific patterns first
        ("npcf-smpolicycontrol", "sm-policies", "POST")
            if parts.len() >= 5 && parts[4] == "update" =>
        {
            // Update SM Policy (TS 29.512 §4.2.4: POST /sm-policies/{id}/update)
            let sm_policy_id = parts[3];
            handle_sm_policy_update_notify(sm_policy_id, &request).await
        }
        ("npcf-smpolicycontrol", "sm-policies", "POST")
            if parts.len() >= 5 && parts[4] == "delete" =>
        {
            // Delete SM Policy (TS 29.512 §4.2.5: POST /sm-policies/{id}/delete)
            let sm_policy_id = parts[3];
            handle_sm_policy_delete(sm_policy_id).await
        }
        ("npcf-smpolicycontrol", "sm-policies", "POST") if parts.len() < 4 => {
            // Create SM Policy
            handle_sm_policy_create(&request).await
        }
        ("npcf-smpolicycontrol", "sm-policies", "GET") if parts.len() >= 4 => {
            // Get SM Policy
            let sm_policy_id = parts[3];
            handle_sm_policy_get(sm_policy_id).await
        }
        ("npcf-smpolicycontrol", "sm-policies", "DELETE") if parts.len() >= 4 => {
            // Legacy delete path (kept for backward compatibility)
            let sm_policy_id = parts[3];
            handle_sm_policy_delete(sm_policy_id).await
        }

        // Policy Authorization Service (npcf-policyauthorization)
        ("npcf-policyauthorization", "app-sessions", _) => {
            route_policy_authorization(&parts, method, &request, uri).await
        }

        // Nudr_DM_Notification sink for policy-data changes (#299, TS 29.519 §5.2).
        // Its path is `sbi_path::POLICY_DATA_NOTIFY_PATH`, the same constant the
        // subscription advertises, so the URI the UDR is told about is one this router
        // serves.
        ("npcf-callback", "policy-data-change-notify", "POST") => {
            handle_policy_data_change_notify(&request).await
        }

        // Policy Control Event Exposure Service (npcf-eventexposure, TS 29.523)
        ("npcf-eventexposure", _, _) => {
            crate::npcf_eventexposure::route(&parts, method, uri, &request).await
        }

        _ => {
            log::warn!("Unknown PCF request: {method} {uri}");
            send_method_not_allowed(method, uri)
        }
    }
}

// ---------------------------------------------------------------------------
// Supported-feature negotiation (pcfd-05) — TS 29.500 cl 6.6 / TS 29.571 §5.2.2
// ---------------------------------------------------------------------------

/// Optional features the PCF implements per service, as a SupportedFeatures hex
/// bitmask (TS 29.571 §5.2.2). The value returned to a consumer is
/// `intersection(consumer, producer)`; advertising only genuinely-supported bits
/// keeps a strict peer from depending on an unimplemented feature.
///
/// AM (TS 29.507 §5.8): no optional features are negotiated, so the result is
/// always "0" — the spec NOTE requires `suppFeat` present and set to 0 when
/// negotiation is not needed.
const PCF_AM_POLICY_SUPPORTED_FEATURES: u64 = 0x0;
/// SM (TS 29.512 §5.8): conservative optional-feature set the decision builder
/// actually exercises. Intersected with the SMF-requested value.
const PCF_SM_POLICY_SUPPORTED_FEATURES: u64 = 0x3;
/// PolicyAuthorization (TS 29.514): no optional features negotiated → "0".
const PCF_PA_SUPPORTED_FEATURES: u64 = 0x0;
/// UEPolicyControl (TS 29.525 §5.8): no optional features negotiated -> "0".
const PCF_UE_POLICY_SUPPORTED_FEATURES: u64 = 0x0;

/// Negotiate a SupportedFeatures bitmask: parse the consumer hex string,
/// intersect with the producer-supported mask, and return the lowercase-hex
/// result (TS 29.571 §5.2.2). A missing, empty, or unparseable consumer value
/// negotiates to "0" (no optional features) — never an error, so a consumer
/// that omits `suppFeat` still gets a conformant, working feature set.
fn negotiate_features(consumer_hex: Option<&str>, supported: u64) -> String {
    let consumer = consumer_hex
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .unwrap_or(0);
    format!("{:x}", consumer & supported)
}

// AM Policy Control handlers

/// Provision the access-and-mobility policy for an association from the UDR's AM
/// subscription data (TS 29.507 §4.2.2.2).
///
/// Returns the wire members of the policy — `ueAmbr`, and `rfsp` /`servAreaRes`
/// when the operator provisioned them — as a map with **absent members simply
/// absent**. Before #89 the create emitted `"servAreaRes": null` and
/// `"rfsp": null`, which no `ServiceAreaRestriction` / `RfspIndex` schema accepts,
/// so a strict AMF's validator rejected the body.
///
/// The UDR is the source; the local subscriber DB is the fallback for `ueAmbr`
/// only, which is all it holds. `rfsp` is range-checked (1..=256) because a value
/// outside it is not an `RfspIndex` and forwarding it would push the rejection
/// onto the AMF.
async fn provision_am_policy(supi: &str) -> serde_json::Map<String, serde_json::Value> {
    let mut policy = serde_json::Map::new();

    if let Some(am_data) = sbi_path::pcf_udr_am_subscription_data(supi).await {
        if let Some(ambr) = am_data.get("subscribedUeAmbr") {
            policy.insert("ueAmbr".to_string(), ambr.clone());
        }
        match am_data.get("rfspIndex").and_then(|v| v.as_u64()) {
            Some(rfsp) if (1..=256).contains(&rfsp) => {
                policy.insert("rfsp".to_string(), serde_json::json!(rfsp));
            }
            Some(rfsp) => log::warn!("[{supi}] UDR rfspIndex {rfsp} is outside 1..=256; omitted"),
            None => {}
        }
        // ServiceAreaRestriction: restrictionType and areas are both-or-neither
        // (TS 29.571), so a half-populated one is dropped rather than forwarded.
        if let Some(sar) = am_data.get("serviceAreaRestriction") {
            let has_type = sar.get("restrictionType").is_some();
            let has_areas = sar.get("areas").is_some();
            if has_type == has_areas {
                policy.insert("servAreaRes".to_string(), sar.clone());
            } else {
                log::warn!(
                    "[{supi}] UDR serviceAreaRestriction has restrictionType xor areas; omitted"
                );
            }
        }
    }

    // ueAmbr fallback: the local subscriber DB, which is where the pre-#89 code
    // read it from and all it can supply.
    if !policy.contains_key("ueAmbr") {
        if let Some(sd) = nudr_handler::query_subscription_data_pub(supi) {
            policy.insert(
                "ueAmbr".to_string(),
                serde_json::json!({
                    "uplink": format_bitrate(sd.ambr_uplink),
                    "downlink": format_bitrate(sd.ambr_downlink),
                }),
            );
        }
    }
    policy
}

/// The `RequestTrigger`s a consumer asked this association to watch, plus the
/// ones the PCF adds because the subscription disagrees with the request.
///
/// `UE_AMBR_CH` is added when the requested `ueAmbr` differs from the provisioned
/// one, which is the condition TS 29.507 defines it for — it was the only trigger
/// the pre-#89 code computed, and it is kept.
fn am_policy_triggers(
    requested: &serde_json::Value,
    policy: &serde_json::Map<String, serde_json::Value>,
) -> Vec<String> {
    let mut triggers: Vec<String> = requested
        .get("triggers")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| t.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if let (Some(req_ambr), Some(prov_ambr)) = (requested.get("ueAmbr"), policy.get("ueAmbr")) {
        let member = |v: &serde_json::Value, k: &str| {
            v.get(k).and_then(|x| x.as_str()).unwrap_or("0").to_string()
        };
        let ambr_differs = member(req_ambr, "uplink") != member(prov_ambr, "uplink")
            || member(req_ambr, "downlink") != member(prov_ambr, "downlink");
        if ambr_differs && !triggers.iter().any(|t| t == "UE_AMBR_CH") {
            triggers.push("UE_AMBR_CH".to_string());
        }
    }
    triggers
}

/// The alternate notification endpoints a consumer supplied
/// (`altNotifIpv4Addrs` / `altNotifFqdns`, TS 29.507), rendered as URIs that
/// share the primary's scheme and path so a retry hits the same resource on a
/// different host.
fn alternate_notification_uris(requested: &serde_json::Value, primary: &str) -> Vec<String> {
    let (scheme, rest) = match primary.split_once("://") {
        Some((s, r)) => (s, r),
        None => ("http", primary),
    };
    let path = rest.find('/').map(|i| &rest[i..]).unwrap_or("");
    let mut out = Vec::new();
    for key in ["altNotifIpv4Addrs", "altNotifIpv6Addrs", "altNotifFqdns"] {
        if let Some(list) = requested.get(key).and_then(|v| v.as_array()) {
            for host in list.iter().filter_map(|v| v.as_str()) {
                // An IPv6 literal needs brackets in an authority.
                let authority = if key == "altNotifIpv6Addrs" {
                    format!("[{host}]")
                } else {
                    host.to_string()
                };
                out.push(format!("{scheme}://{authority}{path}"));
            }
        }
    }
    out
}

/// Parse a TS 23.003 §2.10.1 `AmfId` (6 hex digits: 8-bit region, 10-bit set,
/// 6-bit pointer). `None` when it is not 6 hex digits, so a malformed value is
/// ignored instead of silently becoming region 0 / set 0 / pointer 0.
fn parse_amf_id_hex(amf_id: &str) -> Option<crate::context::AmfId> {
    if amf_id.len() != 6 || !amf_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let value = u32::from_str_radix(amf_id, 16).ok()?;
    Some(crate::context::AmfId {
        region: ((value >> 16) & 0xFF) as u8,
        set: ((value >> 6) & 0x03FF) as u16,
        pointer: (value & 0x3F) as u8,
    })
}

/// Render a `PolicyAssociation` (TS 29.507 §5.6.2.4) for an association.
///
/// One builder for create and GET, so the two representations of the same
/// resource cannot disagree — the GET used to answer `{polAssoId, supi,
/// triggers: []}`, omitting the mandatory negotiated `suppFeat` and every
/// provisioned policy member.
fn build_policy_association(
    association_id: &str,
    supi: &str,
    triggers: &[String],
    am_policy: Option<&serde_json::Value>,
    supp_feat: &str,
) -> serde_json::Value {
    let mut body = serde_json::Map::new();
    body.insert("polAssoId".to_string(), serde_json::json!(association_id));
    body.insert("supi".to_string(), serde_json::json!(supi));
    // TS 29.507 §5.8: suppFeat is mandatory in PolicyAssociation and is the
    // negotiated (consumer ∩ producer) value (pcfd-05).
    body.insert("suppFeat".to_string(), serde_json::json!(supp_feat));
    if !triggers.is_empty() {
        body.insert("triggers".to_string(), serde_json::json!(triggers));
    }
    if let Some(policy) = am_policy.and_then(|p| p.as_object()) {
        for (k, v) in policy {
            body.insert(k.clone(), v.clone());
        }
    }
    serde_json::Value::Object(body)
}

pub async fn handle_am_policy_create(request: &SbiRequest) -> SbiResponse {
    log::info!("AM Policy Create");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let policy_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    // ---- PolicyAssociationRequest mandatory IEs (TS 29.507 §5.6.2.3) ----
    // notificationUri, supi and suppFeat are mandatory. Reject with 400
    // ProblemDetails when any is absent rather than synthesizing a SUPI
    // (pcfd-08). suppFeat may be the empty string ("") — that is "present",
    // and negotiates to "0".
    let Some(notification_uri) = policy_data.get("notificationUri").and_then(|v| v.as_str()) else {
        return send_bad_request("notificationUri is required", Some("MANDATORY_IE_MISSING"));
    };
    let Some(supi) = policy_data.get("supi").and_then(|v| v.as_str()) else {
        return send_bad_request("supi is required", Some("MANDATORY_IE_MISSING"));
    };
    let Some(supp_feat) = policy_data.get("suppFeat").and_then(|v| v.as_str()) else {
        return send_bad_request("suppFeat is required", Some("MANDATORY_IE_MISSING"));
    };

    // Add UE AM to context
    let ctx = pcf_self();
    let ue_am = if let Ok(context) = ctx.read() {
        context.ue_am_add(supi)
    } else {
        None
    };

    match ue_am {
        Some(ue_am) => {
            // Provision the access-and-mobility policy and the triggers before
            // storing, so the association carries them from the moment it exists.
            let policy = provision_am_policy(supi).await;
            let triggers = am_policy_triggers(&policy_data, &policy);
            let am_policy = if policy.is_empty() {
                None
            } else {
                Some(serde_json::Value::Object(policy))
            };
            let alt_notif_uris = alternate_notification_uris(&policy_data, notification_uri);

            // Persist the notification URI so later AM policy update notifies
            // (pcf_sbi_send_am_policy_control_notify) can reach the AMF.
            {
                let mut updated = ue_am.clone();
                updated.notification_uri = Some(notification_uri.to_string());
                updated.alt_notif_uris = alt_notif_uris;
                updated.triggers = triggers.clone();
                updated.am_policy = am_policy.clone();
                if let Ok(context) = ctx.read() {
                    context.ue_am_update(&updated);
                }
            }
            log::info!(
                "AM Policy created for SUPI {} (id={}, triggers={:?})",
                supi,
                ue_am.association_id,
                triggers
            );

            let resp = build_policy_association(
                &ue_am.association_id,
                supi,
                &triggers,
                am_policy.as_ref(),
                &negotiate_features(Some(supp_feat), PCF_AM_POLICY_SUPPORTED_FEATURES),
            );

            SbiResponse::with_status(201)
                .with_header(
                    "Location",
                    format!(
                        "/npcf-am-policy-control/v1/policies/{}",
                        ue_am.association_id
                    ),
                )
                .with_json_body(&resp)
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        None => send_bad_request("Failed to create AM policy", Some("CREATION_FAILED")),
    }
}

pub async fn handle_am_policy_get(pol_asso_id: &str) -> SbiResponse {
    log::debug!("AM Policy Get: {pol_asso_id}");

    let ctx = pcf_self();
    let ue_am = if let Ok(context) = ctx.read() {
        context.ue_am_find_by_association_id(pol_asso_id)
    } else {
        None
    };

    match ue_am {
        Some(ue_am) => SbiResponse::with_status(200)
            .with_json_body(&build_policy_association(
                &ue_am.association_id,
                &ue_am.supi,
                &ue_am.triggers,
                ue_am.am_policy.as_ref(),
                // The association's negotiated value is fixed at create; the
                // producer set is a constant, so re-negotiating the stored
                // consumer features would give the same answer.
                &negotiate_features(None, PCF_AM_POLICY_SUPPORTED_FEATURES),
            ))
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("AM Policy {pol_asso_id} not found"),
            Some("POLICY_NOT_FOUND"),
        ),
    }
}

pub async fn handle_am_policy_delete(pol_asso_id: &str) -> SbiResponse {
    log::info!("AM Policy Delete: {pol_asso_id}");

    let ctx = pcf_self();

    // Find the UE AM by association ID first
    let ue_am = if let Ok(context) = ctx.read() {
        context.ue_am_find_by_association_id(pol_asso_id)
    } else {
        None
    };

    match ue_am {
        Some(ue_am) => {
            // Remove the UE AM
            if let Ok(context) = ctx.read() {
                context.ue_am_remove(ue_am.id);
            }
            log::info!("AM Policy {pol_asso_id} deleted");
            SbiResponse::with_status(204)
        }
        None => send_not_found(
            &format!("AM Policy {pol_asso_id} not found"),
            Some("POLICY_NOT_FOUND"),
        ),
    }
}

pub async fn handle_am_policy_update(pol_asso_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("AM Policy Update: {pol_asso_id}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let update_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let ctx = pcf_self();
    let ue_am = if let Ok(context) = ctx.read() {
        context.ue_am_find_by_association_id(pol_asso_id)
    } else {
        None
    };

    let Some(ue_am) = ue_am else {
        return send_not_found(
            &format!("AM Policy {pol_asso_id} not found"),
            Some("POLICY_NOT_FOUND"),
        );
    };

    // TS 29.507 §4.2.3.1: apply the PolicyAssociationUpdateRequest, then
    // re-evaluate. Before #89 the body was deserialised into `_update_data` and
    // never read, so a consumer could move its notification endpoint, change its
    // GUAMI or ask for different triggers and the PCF would keep using the old
    // ones while answering 200.
    let mut updated = ue_am.clone();
    let mut changed = Vec::new();

    if let Some(uri) = update_data.get("notificationUri").and_then(|v| v.as_str()) {
        if updated.notification_uri.as_deref() != Some(uri) {
            updated.notification_uri = Some(uri.to_string());
            changed.push("notificationUri");
        }
        updated.alt_notif_uris = alternate_notification_uris(&update_data, uri);
    }
    // Set when the serving PLMN genuinely moves, which is what TS 29.523
    // `PLMN_CH` reports. Tracked separately from `changed` because that list
    // records "the consumer sent this member", and a consumer re-sending its
    // CURRENT GUAMI on an unrelated update must not be reported as a PLMN change.
    let mut plmn_changed: Option<(String, String)> = None;
    if let Some(guami) = update_data.get("guami") {
        let mcc = guami.pointer("/plmnId/mcc").and_then(|v| v.as_str());
        let mnc = guami.pointer("/plmnId/mnc").and_then(|v| v.as_str());
        let amf_id = guami.get("amfId").and_then(|v| v.as_str());
        if let (Some(mcc), Some(mnc)) = (mcc, mnc) {
            if updated.guami.plmn_id.mcc != mcc || updated.guami.plmn_id.mnc != mnc {
                plmn_changed = Some((mcc.to_string(), mnc.to_string()));
            }
            updated.guami.plmn_id.mcc = mcc.to_string();
            updated.guami.plmn_id.mnc = mnc.to_string();
            // amfId is 6 hex digits = region(2) || set(3) || pointer(1)
            // (TS 23.003 §2.10.1). Parsed rather than stored as a string because
            // that is the shape the context holds; a malformed one leaves the
            // stored GUAMI's AMF id alone rather than zeroing it.
            if let Some(parsed) = amf_id.and_then(parse_amf_id_hex) {
                updated.guami.amf_id = parsed;
            }
            changed.push("guami");
        }
    }
    if let Some(requested) = update_data.get("triggers").and_then(|v| v.as_array()) {
        let requested: Vec<String> = requested
            .iter()
            .filter_map(|t| t.as_str().map(str::to_string))
            .collect();
        if requested != updated.triggers {
            updated.triggers = requested;
            changed.push("triggers");
        }
    }

    // Re-evaluate the provisioned policy: an update is the point at which the
    // subscription is consulted again, which is what makes servAreaRes / rfsp /
    // ueAmbr able to change after the association is created.
    let policy = provision_am_policy(&updated.supi).await;
    let am_policy = if policy.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(policy))
    };
    if am_policy != updated.am_policy {
        updated.am_policy = am_policy.clone();
        changed.push("policy");
    }

    if let Ok(context) = ctx.read() {
        context.ue_am_update(&updated);
    }
    log::info!(
        "AM Policy {pol_asso_id} updated (changed: {changed:?}, triggers={:?})",
        updated.triggers
    );

    // TS 29.507 §4.2.4.2: a policy change is pushed to the AMF as well as
    // returned. The notify helper had NO caller before #89, so a change never
    // reached the consumer that did not ask for it.
    if !changed.is_empty() {
        pcf_sbi_send_am_policy_control_notify(updated.id);
    }

    // TS 29.523 `PLMN_CH`: report the serving-PLMN change to every
    // Npcf_EventExposure subscriber that asked for it. Reported with no DNN,
    // because an AM policy association is not scoped to a PDU session — so only
    // subscriptions without a filterDnns match, which is the honest reading of
    // "this event has no DNN" rather than treating it as matching every DNN.
    if let Some((mcc, mnc)) = plmn_changed {
        sbi_path::pcf_report_pc_event(
            "PLMN_CH",
            None,
            serde_json::json!({
                "supi": updated.supi,
                "plmnId": {"mcc": mcc, "mnc": mnc},
            }),
        )
        .await;
    }

    // The 200 response schema is PolicyUpdate, not PolicyAssociation: it carries
    // resourceUri and the changed policy.
    SbiResponse::with_status(200)
        .with_json_body(&sbi_path::build_am_policy_update(
            &updated.association_id,
            &updated.triggers,
            updated.am_policy.as_ref(),
        ))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

// UE Policy Control handlers (npcf-ue-policy-control, TS 29.525)

pub async fn handle_ue_policy_create(request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };
    // PolicyAssociationRequest mandatory IEs (TS 29.525): notificationUri, supi, suppFeat.
    let Some(notification_uri) = data.get("notificationUri").and_then(|v| v.as_str()) else {
        return send_bad_request("notificationUri is required", Some("MANDATORY_IE_MISSING"));
    };
    let Some(supi) = data.get("supi").and_then(|v| v.as_str()) else {
        return send_bad_request("supi is required", Some("MANDATORY_IE_MISSING"));
    };
    let Some(supp_feat) = data.get("suppFeat").and_then(|v| v.as_str()) else {
        return send_bad_request("suppFeat is required", Some("MANDATORY_IE_MISSING"));
    };
    let negotiated = negotiate_features(Some(supp_feat), PCF_UE_POLICY_SUPPORTED_FEATURES);
    let assoc = ue_policy::ue_policy_add(supi, notification_uri, &negotiated);

    // Wave-6 E4: assemble URSP rules and DELIVER them to the UE as a MANAGE UE
    // POLICY COMMAND over Namf_Communication_N1N2MessageTransfer (TS 29.525
    // §4.2.2.2 / TS 24.501 D.2.1.2). The 201 body stays the spec-shaped
    // PolicyAssociation (no bespoke `uePolicy` field — that octet string is the
    // EpsUrsp path, not the primary Annex-D delivery); delivery runs in an
    // async task so it does not block this response.
    if ue_policy::delivery_enabled() {
        spawn_ue_policy_delivery(&assoc.pol_asso_id, supi, &data);
    }

    // PolicyAssociation (TS 29.525 §5.6.2.2): suppFeat is the only mandatory
    // member. `triggers`/`request` are conformant optionals; the delivered
    // URSP travels on the N1 wire (Annex D), not in this JSON body.
    let resp = serde_json::json!({
        "suppFeat": negotiated,
        "triggers": ["UE_POLICY"],
        "request": { "notificationUri": notification_uri, "supi": supi, "suppFeat": supp_feat },
    });
    SbiResponse::with_status(201)
        .with_header(
            "Location",
            format!("/npcf-ue-policy-control/v1/policies/{}", assoc.pol_asso_id),
        )
        .with_json_body(&resp)
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// Extract the source PLMN (mcc, mnc) for the D.6.2 sublist from the
/// PolicyAssociationRequest (`servingPlmn`, else `guami.plmnId`); default to
/// the test PLMN 001-01 when neither is present.
fn ue_policy_source_plmn(data: &serde_json::Value) -> (String, String) {
    for ptr in ["/servingPlmn", "/guami/plmnId"] {
        if let Some(plmn) = data.pointer(ptr) {
            if let (Some(mcc), Some(mnc)) = (
                plmn.get("mcc").and_then(|v| v.as_str()),
                plmn.get("mnc").and_then(|v| v.as_str()),
            ) {
                return (mcc.to_string(), mnc.to_string());
            }
        }
    }
    ("001".to_string(), "01".to_string())
}

/// Build the URSP MANAGE UE POLICY COMMAND for a new association, record the
/// delivery parameters, and spawn the async N1N2 transfer (E4). The 201 is
/// never blocked; on encode failure or an AMF error the association's
/// `delivery_state` becomes `Failed` (fail-closed — never `Delivered` without
/// a MANAGE UE POLICY COMPLETE, item E6).
fn spawn_ue_policy_delivery(pol_asso_id: &str, supi: &str, data: &serde_json::Value) {
    let (mcc, mnc) = ue_policy_source_plmn(data);
    let pti = ue_policy::alloc_pti();
    let upsc: u16 = 1; // first (only) UE policy section of this association

    // Synchronous baseline: the association immediately carries its PTI and a
    // non-empty rule set (the static default). Item E3 may override the rule
    // source from UDR inside the async task below, but recording the default
    // synchronously preserves the create-time invariant that PTI/rules are
    // readable the moment the 201 returns (and cancel-on-delete still applies:
    // ue_policy_set_delivery is a no-op once the association is removed).
    let default_rules = ue_policy::default_wire_rules();
    ue_policy::ue_policy_set_delivery(
        pol_asso_id,
        pti,
        upsc,
        Some((mcc.clone(), mnc.clone())),
        default_rules.clone(),
    );

    let supi = supi.to_string();
    let id = pol_asso_id.to_string();
    tokio::spawn(async move {
        // Wave-6 E3: prefer the operator-provisioned URSP rules from the UDR
        // UePolicySet (TS 29.519 §5.4), bounded so a stuck UDR cannot block
        // delivery; fall back to the static default set on absence / timeout /
        // malformed doc (fail-closed — never a half-parsed provisioned set).
        let udr_doc = sbi_path::pcf_udr_ue_policy_set(&supi).await;
        let rules = ue_policy::resolve_ursp_rules(udr_doc.as_ref());
        // E3: provision the resolved rules into the per-SUPI UE-policy context
        // (the mapping target; E6 reads it to correlate the COMPLETE/REJECT).
        ue_policy::provision_context_ursp(&supi, rules.clone());
        // Re-record the resolved rules (no-op if identical to the default, or if
        // the association was deleted meanwhile).
        ue_policy::ue_policy_set_delivery(
            &id,
            pti,
            upsc,
            Some((mcc.clone(), mnc.clone())),
            rules.clone(),
        );

        let pdu = match ue_policy::build_manage_ue_policy_command(pti, upsc, &mcc, &mnc, &rules) {
            Ok(pdu) => pdu,
            Err(e) => {
                log::warn!("[{supi}] UE policy: URSP encode failed ({e}); marking delivery Failed");
                ue_policy::ue_policy_update_delivery_state(
                    &id,
                    ue_policy::DeliveryState::Failed(format!("encode: {e}")),
                );
                return;
            }
        };

        // Wave-6 E6: SUBSCRIBE to the AMF's uplink UE-policy notifications
        // BEFORE the transfer (TS 29.525 §4.2.2.2 subscribe→transfer→notify
        // order) so a MANAGE UE POLICY COMPLETE/REJECT can be delivered back.
        // A missing PCF self-identity (no callback URI) or an unreachable AMF
        // is degraded-but-safe: the transfer still runs, but with no result
        // loop the association will fall to Failed on T3501 (fail-closed).
        if let Some(callback_uri) = ue_policy_notify_callback_uri(&id) {
            match sbi_path::pcf_subscribe_ue_policy_notify(&supi, &callback_uri).await {
                Ok(Some(sub_id)) => {
                    ue_policy::ue_policy_set_subscription_id(&id, &sub_id);
                    log::info!("[{supi}] UE policy: N1N2MessageSubscribe (UPDP) ok (sub={sub_id})");
                }
                Ok(None) => log::warn!(
                    "[{supi}] UE policy: no AMF reachable to subscribe UPDP notifications"
                ),
                Err(e) => log::warn!("[{supi}] UE policy: N1N2MessageSubscribe failed ({e})"),
            }
        } else {
            log::warn!(
                "[{supi}] UE policy: no PCF self-identity; skipping UPDP N1N2MessageSubscribe \
                 (no delivery-result loop for this association)"
            );
        }

        match sbi_path::pcf_deliver_ue_policy(&supi, &pdu).await {
            Ok(()) => {
                // 200/202 only means the AMF accepted the downlink — the
                // association stays Pending until the UE returns a MANAGE UE
                // POLICY COMPLETE (item E6). Do NOT flip to Delivered here.
                log::info!(
                    "[{supi}] UE policy: MANAGE UE POLICY COMMAND sent (N1N2 accepted), \
                     awaiting COMPLETE"
                );
                // Wave-6 E6: start T3501. On expiry with the association still
                // Pending, retransmit the SAME command once (same PTI), then
                // Failed (TS 24.501 D.2.1.5). A COMPLETE/REJECT (or a delete)
                // stops the loop.
                let dur = ue_policy::t3501_duration();
                let supi_retx = supi.clone();
                let pdu_retx = pdu.clone();
                ue_policy::run_t3501(&id, dur, move || {
                    let supi = supi_retx.clone();
                    let pdu = pdu_retx.clone();
                    async move {
                        if let Err(e) = sbi_path::pcf_deliver_ue_policy(&supi, &pdu).await {
                            log::warn!("[{supi}] UE policy: T3501 retransmission failed ({e})");
                        }
                    }
                })
                .await;
            }
            Err(e) => {
                log::warn!("[{supi}] UE policy: delivery failed ({e})");
                ue_policy::ue_policy_update_delivery_state(
                    &id,
                    ue_policy::DeliveryState::Failed(e),
                );
            }
        }
    });
}

/// Build this PCF's `n1NotifyCallbackUri` for an association's UE-policy
/// delivery-result loop (Wave-6 E6): the AMF POSTs the uplink
/// `N1MessageNotify` here. Path carries the `polAssoId` so the callback route
/// correlates the COMPLETE/REJECT back to the right association. `None` when
/// the PCF self-identity was not published (e.g. no config) — the caller then
/// skips the subscribe.
fn ue_policy_notify_callback_uri(pol_asso_id: &str) -> Option<String> {
    let info = sbi_path::pcf_self_info()?;
    Some(format!(
        "http://{}:{}/npcf-ue-policy-control/v1/notify/{}/n1-message-notify",
        info.sbi_addr, info.sbi_port, pol_asso_id
    ))
}

pub async fn handle_ue_policy_get(pol_asso_id: &str) -> SbiResponse {
    match ue_policy::ue_policy_find(pol_asso_id) {
        Some(a) => SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({
                "suppFeat": a.supp_feat,
                "triggers": ["UE_POLICY"],
                "request": { "notificationUri": a.notification_uri, "supi": a.supi, "suppFeat": a.supp_feat },
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("UE Policy {pol_asso_id} not found"),
            Some("POLICY_NOT_FOUND"),
        ),
    }
}

pub async fn handle_ue_policy_delete(pol_asso_id: &str) -> SbiResponse {
    // Wave-6 E6: capture the UE-policy N1N2 subscription (if any) BEFORE
    // removing the association so the delete leg can unsubscribe at the AMF
    // (TS 29.518 §5.2.2.7). Removing the association also stops any running
    // T3501 loop (it reads the store each expiry) — cancel-on-delete.
    let assoc = ue_policy::ue_policy_find(pol_asso_id);
    if ue_policy::ue_policy_remove(pol_asso_id) {
        if let Some(a) = assoc {
            if let Some(sub_id) = a.n1n2_subscription_id {
                let supi = a.supi.clone();
                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    handle.spawn(async move {
                        match sbi_path::pcf_unsubscribe_ue_policy_notify(&supi, &sub_id).await {
                            Ok(true) => log::info!(
                                "[{supi}] UE policy: N1N2MessageUnSubscribe ok (sub={sub_id})"
                            ),
                            Ok(false) => log::debug!(
                                "[{supi}] UE policy: no AMF reachable to unsubscribe (sub={sub_id})"
                            ),
                            Err(e) => log::warn!(
                                "[{supi}] UE policy: N1N2MessageUnSubscribe failed ({e})"
                            ),
                        }
                    });
                }
            }
        }
        SbiResponse::with_status(204)
    } else {
        send_not_found(
            &format!("UE Policy {pol_asso_id} not found"),
            Some("POLICY_NOT_FOUND"),
        )
    }
}

/// Wave-6 E6 — Namf `N1MessageNotify` callback (TS 29.518 §5.2.2.4): the AMF
/// relays the UE's uplink UE-policy N1 message (MANAGE UE POLICY
/// COMPLETE/REJECT, TS 24.501 D.2.1.3/D.2.1.4) here. The binary N1 payload is
/// carried verbatim in the multipart body's binary part (referenced by
/// `n1MessageContainer.n1MessageContent.contentId`). Decodes it and correlates
/// against the association named by `pol_asso_id`: a COMPLETE with the matching
/// PTI flips the association Delivered (stops T3501); a REJECT flips it Failed
/// with the D.6.3 cause. Always answers 204 (the notify was consumed); an
/// unknown association / undecodable payload / PTI mismatch is logged and
/// dropped (fail-closed — never a crash, never a fake Delivered).
pub async fn handle_ue_policy_n1_notify(pol_asso_id: &str, request: &SbiRequest) -> SbiResponse {
    // The binary N1 payload is a multipart part; the server decoded it into
    // `http.parts`. Prefer the part named by the notification's contentId, else
    // fall back to the first binary part.
    let content_id = request
        .http
        .content
        .as_deref()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
        .and_then(|v| {
            v.pointer("/n1MessageContainer/n1MessageContent/contentId")
                .and_then(|c| c.as_str())
                .map(str::to_string)
        });
    let part = content_id
        .as_deref()
        .and_then(|cid| {
            request
                .http
                .parts
                .iter()
                .find(|p| p.content_id.as_deref() == Some(cid))
        })
        .or_else(|| request.http.parts.first());
    let Some(part) = part else {
        log::warn!(
            "[{pol_asso_id}] UE policy notify: no binary N1 part in N1MessageNotify; dropping"
        );
        // Nothing to correlate, but the notify was received — 204.
        return SbiResponse::with_status(204);
    };

    let outcome = ue_policy::apply_ue_policy_ul_container(pol_asso_id, &part.data);
    if outcome == ue_policy::UePolicyResultOutcome::UnknownAssociation {
        log::warn!(
            "[{pol_asso_id}] UE policy notify: unknown association; dropping N1MessageNotify"
        );
    }

    // TS 29.523 `SUCCESS_UE_POL_DEL_SP` / `UNSUCCESS_UE_POL_DEL_SP`: the UE
    // policy delivery result, reported to Npcf_EventExposure subscribers.
    //
    // Only the two TERMINAL outcomes are reported. A PTI mismatch is a stale or
    // duplicate command (TS 24.501 D.2.1.6) and leaves the delivery still in
    // flight; `Ignored` is a message not part of this loop; `Undecodable` and
    // `UnknownAssociation` are not delivery results at all. Reporting any of
    // those would tell a consumer the delivery concluded when it has not.
    let delivery_event = match &outcome {
        ue_policy::UePolicyResultOutcome::Delivered(_) => Some("SUCCESS_UE_POL_DEL_SP"),
        ue_policy::UePolicyResultOutcome::Rejected(_) => Some("UNSUCCESS_UE_POL_DEL_SP"),
        _ => None,
    };
    if let Some(event) = delivery_event {
        // The association's SUPI is what a consumer correlates on; `delivFailure`
        // is deliberately NOT set for the reject case, because TS 29.522 `Failure`
        // enumerates northbound delivery failures and the D.6.3 cause here is a
        // UE-side rejection, not one of those values. The cause text is logged
        // rather than mapped to a token it does not correspond to.
        let supi = ue_policy::ue_policy_find(pol_asso_id).map(|a| a.supi.clone());
        if let ue_policy::UePolicyResultOutcome::Rejected(ref cause) = outcome {
            log::info!("[{pol_asso_id}] UE policy delivery rejected by UE: {cause}");
        }
        let extra = match supi {
            Some(supi) => serde_json::json!({"supi": supi}),
            None => serde_json::json!({}),
        };
        sbi_path::pcf_report_pc_event(event, None, extra).await;
    }

    // Consumer callbacks acknowledge with 204 No Content (TS 29.518 §5.2.2.4).
    SbiResponse::with_status(204)
}

pub async fn handle_ue_policy_update(pol_asso_id: &str, request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    if let Err(e) = serde_json::from_str::<serde_json::Value>(body) {
        return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON"));
    }
    match ue_policy::ue_policy_find(pol_asso_id) {
        Some(_) => SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({
                "resourceUri": format!("/npcf-ue-policy-control/v1/policies/{pol_asso_id}"),
                "triggers": ["UE_POLICY"],
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("UE Policy {pol_asso_id} not found"),
            Some("POLICY_NOT_FOUND"),
        ),
    }
}

// SM Policy Control handlers

/// Whether a DNN identifies a UAV (aerial) session (Rel-18, TS 23.256).
///
/// Configured via `PCF_UAV_DNN` (comma-separated DNN list); defaults to `uav`.
fn is_uav_dnn(dnn: &str) -> bool {
    let configured = std::env::var("PCF_UAV_DNN").unwrap_or_else(|_| "uav".to_string());
    configured
        .split(',')
        .map(str::trim)
        .any(|d| !d.is_empty() && d.eq_ignore_ascii_case(dnn))
}

/// UAV flight-policy gating for a UAV PDU session (Rel-18, TS 23.256).
///
/// Builds a [`UavPolicyAuthorization`] from config: a global altitude limit
/// (`PCF_UAV_MAX_ALTITUDE`, default 120 m) plus a permitted flight zone, then
/// checks the UE's reported (or configured) flight position against it. Returns
/// `None` when the session is authorized; `Some(reject_response)` (HTTP 403)
/// when the altitude/zone gate denies the session, so the caller fails the SM
/// policy create. The position is read from `PCF_UAV_POSITION`
/// (`lat,lon,alt`); when unset a nominal in-zone position is used so the
/// authorize path is exercised end to end.
fn authorize_uav_session(supi: &str, dnn: &str) -> Option<SbiResponse> {
    let max_altitude = std::env::var("PCF_UAV_MAX_ALTITUDE")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(120.0);

    // TS 23.256: flight authorisation comes from the USS/UTM via the UAS-NF. This
    // tree has NO UAS-NF client, so there is nothing to ask — and the previous
    // code answered that by calling `grant_authorization("CAA-PCF-DEFAULT", 3600)`
    // unconditionally, i.e. the network self-granted every flight. That is a
    // fail-open authorisation bypass, not an incomplete feature.
    //
    // #90 makes it fail CLOSED: a UAV session is authorised only against an
    // authorisation the OPERATOR has provisioned, and refused when none exists.
    // A missing authorisation decision is a missing credential, and this repo's
    // recorded policy is to fail closed on those (see DECISIONS.md, the
    // fail-open-vs-fail-closed rule) — the opposite direction from a missing
    // FILTER, where absence conventionally means "no restriction".
    //
    // Deliberate behaviour change, stated in the PR: a deployment that configured
    // a UAV DNN and relied on the self-grant will now have those sessions
    // REFUSED until it provisions `PCF_UAV_AUTHORIZATION` and `PCF_UAV_ZONE`.
    // Not gated behind a switch, because a switch defaulting to the old value
    // would leave the bypass in place for everyone who does not know to flip it,
    // and a switch defaulting to the new one is just this with extra steps. Scope
    // is naturally limited: only a DNN named by `PCF_UAV_DNN` reaches here at all.
    let Some(authorization) = uav_provisioned_authorization() else {
        log::warn!(
            "[UAV Policy] SM policy DENY for SUPI {supi} dnn={dnn}: no USS/UTM flight \
             authorization available. This PCF has no UAS-NF client (TS 23.256), so an \
             authorization must be provisioned via PCF_UAV_AUTHORIZATION=<caa-level-uav-id>[,\
             <validity-seconds>]; refusing rather than self-granting."
        );
        return Some(uav_reject(
            "no USS/UTM flight authorization for this UAV",
            None,
        ));
    };

    // The permitted flight zone must also be provisioned. The previous hardcoded
    // 37..38N / -123..-122W box silently authorised one region of California and
    // nothing else, which is a geofence nobody chose.
    let Some(zone_bounds) = uav_provisioned_zone() else {
        log::warn!(
            "[UAV Policy] SM policy DENY for SUPI {supi} dnn={dnn}: no permitted flight zone \
             provisioned. Set PCF_UAV_ZONE=<min_lat>,<max_lat>,<min_lon>,<max_lon>; refusing \
             rather than defaulting to a hardcoded region."
        );
        return Some(uav_reject("no permitted flight zone provisioned", None));
    };

    let mut uav = UavPolicyAuthorization::new(supi);
    uav.min_altitude_limit = 0.0;
    uav.max_altitude_limit = max_altitude;
    let mut zone = UavFlightZone::new("uav-provisioned-zone", UavFlightZoneType::Unrestricted);
    zone.min_latitude = zone_bounds.0;
    zone.max_latitude = zone_bounds.1;
    zone.min_longitude = zone_bounds.2;
    zone.max_longitude = zone_bounds.3;
    zone.min_altitude = 0.0;
    zone.max_altitude = max_altitude;
    uav.add_flight_zone(zone);
    uav.grant_authorization(&authorization.0, authorization.1);

    // Flight position to gate against (lat, lon, alt). NO default: an unknown
    // position previously defaulted to (37.5, -122.5), which is inside the
    // hardcoded zone, so "we do not know where this UAV is" authorised the
    // flight. Unknown position is now a refusal.
    let Some((lat, lon, alt)) = uav_reported_position() else {
        log::warn!(
            "[UAV Policy] SM policy DENY for SUPI {supi} dnn={dnn}: no flight position \
             available. Set PCF_UAV_POSITION=<lat>,<lon>,<alt>; refusing rather than assuming \
             an in-zone default."
        );
        return Some(uav_reject("no UAV flight position available", None));
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if uav.check_position_authorized(lat, lon, alt, now) {
        log::info!(
            "[UAV Policy] SM policy ALLOW for SUPI {supi} dnn={dnn}: position \
             ({lat:.6}, {lon:.6}) alt={alt:.1}m within flight policy (max_alt={max_altitude}m)"
        );
        None
    } else {
        log::warn!(
            "[UAV Policy] SM policy DENY for SUPI {supi} dnn={dnn}: position \
             ({lat:.6}, {lon:.6}) alt={alt:.1}m violates flight policy; rejecting session"
        );
        Some(uav_reject(
            "UAV position outside authorized flight policy",
            Some(format!(
                "UAV position ({lat}, {lon}) alt={alt}m outside authorized flight policy"
            )),
        ))
    }
}

/// The 403 a refused UAV session answers with.
///
/// One builder for every refusal reason so a newly added reason cannot
/// accidentally answer with a different status or cause than the others.
fn uav_reject(reason: &str, detail: Option<String>) -> SbiResponse {
    SbiResponse::with_status(403)
        .with_json_body(&serde_json::json!({
            "title": "UAV flight policy violation",
            "status": 403,
            "cause": "UAV_FLIGHT_NOT_AUTHORIZED",
            "detail": detail.unwrap_or_else(|| reason.to_string()),
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(403))
}

/// The operator-provisioned USS/UTM flight authorisation, as
/// `(caa_level_uav_id, validity_seconds)`.
///
/// `PCF_UAV_AUTHORIZATION=<caa-level-uav-id>[,<validity-seconds>]`. Returns
/// `None` when unset or empty, which is what makes the UAV path fail closed. The
/// validity defaults to one hour only once an authorisation IS provisioned —
/// defaulting the identifier itself is what the old self-grant did.
fn uav_provisioned_authorization() -> Option<(String, u64)> {
    let raw = std::env::var("PCF_UAV_AUTHORIZATION").ok()?;
    let mut fields = raw.split(',').map(str::trim);
    let id = fields.next().filter(|s| !s.is_empty())?;
    let validity = fields
        .next()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(3600);
    Some((id.to_string(), validity))
}

/// The operator-provisioned permitted flight zone as
/// `(min_lat, max_lat, min_lon, max_lon)`.
///
/// `PCF_UAV_ZONE=<min_lat>,<max_lat>,<min_lon>,<max_lon>`. A malformed or
/// inverted box is rejected rather than clamped: a zone whose min exceeds its max
/// matches nothing, so silently accepting it would refuse every flight for a
/// reason the operator could not see in the logs.
fn uav_provisioned_zone() -> Option<(f64, f64, f64, f64)> {
    let raw = std::env::var("PCF_UAV_ZONE").ok()?;
    let v: Vec<f64> = raw
        .split(',')
        .filter_map(|s| s.trim().parse::<f64>().ok())
        .collect();
    if v.len() != 4 {
        log::warn!("PCF_UAV_ZONE must be <min_lat>,<max_lat>,<min_lon>,<max_lon>; got {raw:?}");
        return None;
    }
    if v[0] > v[1] || v[2] > v[3] {
        log::warn!(
            "PCF_UAV_ZONE bounds are inverted (min > max): {raw:?}. Refusing rather than \
             silently matching no position."
        );
        return None;
    }
    Some((v[0], v[1], v[2], v[3]))
}

/// The UAV's reported flight position as `(lat, lon, alt)`.
///
/// `PCF_UAV_POSITION=<lat>,<lon>,<alt>`. Returns `None` when unset or malformed;
/// there is deliberately no default, because the previous in-zone default meant
/// an unknown position authorised the flight.
fn uav_reported_position() -> Option<(f64, f64, f64)> {
    let raw = std::env::var("PCF_UAV_POSITION").ok()?;
    let p: Vec<f64> = raw
        .split(',')
        .filter_map(|s| s.trim().parse::<f64>().ok())
        .collect();
    if p.len() != 3 {
        log::warn!("PCF_UAV_POSITION must be <lat>,<lon>,<alt>; got {raw:?}");
        return None;
    }
    Some((p[0], p[1], p[2]))
}

pub async fn handle_sm_policy_create(request: &SbiRequest) -> SbiResponse {
    log::info!("SM Policy Create");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let policy_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    // ---- SmPolicyContextData mandatory attributes (TS 29.512 §5.6.2.3) ----
    let Some(supi) = policy_data.get("supi").and_then(|v| v.as_str()) else {
        return send_bad_request("supi is required", Some("MANDATORY_IE_MISSING"));
    };
    let Some(pdu_session_id) = policy_data
        .get("pduSessionId")
        .and_then(|v| v.as_u64())
        .map(|v| v as u8)
    else {
        return send_bad_request("pduSessionId is required", Some("MANDATORY_IE_MISSING"));
    };
    let Some(dnn) = policy_data.get("dnn").and_then(|v| v.as_str()) else {
        return send_bad_request("dnn is required", Some("MANDATORY_IE_MISSING"));
    };
    if policy_data
        .get("pduSessionType")
        .and_then(|v| v.as_str())
        .is_none()
    {
        return send_bad_request("pduSessionType is required", Some("MANDATORY_IE_MISSING"));
    }
    let Some(notification_uri) = policy_data.get("notificationUri").and_then(|v| v.as_str()) else {
        return send_bad_request("notificationUri is required", Some("MANDATORY_IE_MISSING"));
    };
    // sliceInfo is an Snssai (TS 29.512: {"sst": N, "sd": "..."}); the legacy
    // nested {"sNssai": {...}} form is still accepted for compatibility.
    let slice_info = policy_data.get("sliceInfo");
    let slice_obj = slice_info.and_then(|s| {
        if s.get("sst").is_some() {
            Some(s)
        } else {
            s.get("sNssai")
        }
    });
    let Some(sst) = slice_obj
        .and_then(|s| s.get("sst"))
        .and_then(|v| v.as_u64())
        .map(|v| v as u8)
    else {
        return send_bad_request("sliceInfo.sst is required", Some("MANDATORY_IE_MISSING"));
    };
    let sd = slice_obj
        .and_then(|s| s.get("sd"))
        .and_then(|v| v.as_str())
        .and_then(|s| u32::from_str_radix(s, 16).ok());
    let ipv4_address = policy_data
        .get("ipv4Address")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    // TS 29.512 SmPolicyContextData.ipv6AddressPrefix. Read for the same reason
    // as ipv4Address: without it no session ever holds an IPv6 prefix, so an AF
    // request identifying its UE by `ueIpv6` could never bind to anything (#88).
    let ipv6_address_prefix = policy_data
        .get("ipv6AddressPrefix")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let ctx = pcf_self();

    // Get or create UE SM
    let ue_sm_id = if let Ok(context) = ctx.read() {
        match context.ue_sm_find_by_supi(supi) {
            Some(ue_sm) => Some(ue_sm.id),
            None => context.ue_sm_add(supi).map(|ue| ue.id),
        }
    } else {
        None
    };

    let sess = ue_sm_id.and_then(|ue_sm_id| {
        if let Ok(context) = ctx.read() {
            context.sess_add(ue_sm_id, pdu_session_id)
        } else {
            None
        }
    });

    match sess {
        Some(mut sess) => {
            log::info!(
                "SM Policy created for SUPI {} PDU Session {} (id={})",
                supi,
                pdu_session_id,
                sess.sm_policy_id
            );

            // Persist context data needed for outbound notifications
            sess.notification_uri = Some(notification_uri.to_string());
            sess.dnn = Some(dnn.to_string());
            sess.s_nssai = SNssai { sst, sd };
            if let Some(ref ip) = ipv4_address {
                sess.set_ipv4addr(ip);
            }
            if let Some(ref prefix) = ipv6_address_prefix {
                if !sess.set_ipv6prefix(prefix) {
                    log::warn!("SM policy create: unparseable ipv6AddressPrefix {prefix}");
                }
            }
            // Baseline for TS 29.523 `AC_TY_CH`: without recording the access type
            // the session was created on, the first update carrying an accessType
            // has nothing to compare against and would either report a change that
            // did not happen or miss the one that did. `accessType` is optional in
            // SmPolicyContextData, so an absent one stays `None` and the first
            // update merely records it.
            sess.access_type = policy_data
                .get("accessType")
                .and_then(|v| v.as_str())
                .and_then(|s| match s {
                    "3GPP_ACCESS" => Some(crate::context::AccessType::ThreeGppAccess),
                    "NON_3GPP_ACCESS" => Some(crate::context::AccessType::NonThreeGppAccess),
                    _ => None,
                });
            if let Ok(context) = ctx.read() {
                context.sess_update(&sess);
            }

            // UAV flight-policy authorization (Rel-18, TS 23.256). When the
            // session DNN identifies a UAV session, apply altitude / flight-zone
            // gating via UavPolicyAuthorization before building the SM policy
            // decision. A position outside the altitude limits or inside a
            // prohibited zone fails the policy create (the SMF then rejects the
            // PDU session). The UAV DNN and limits are config-driven.
            if is_uav_dnn(dnn) {
                if let Some(reject) = authorize_uav_session(supi, dnn) {
                    // The session was added and updated above; refusing the create
                    // without removing it leaked one PcfSess (plus its
                    // sm_policy_id_hash entry and its id in ue_sm.sess_ids) per
                    // rejected attempt, so a UAV repeatedly denied would grow the
                    // context until max_num_of_sess was reached and then break
                    // NON-UAV session creation too. The SMF is being told the PDU
                    // session is refused, so no state may survive this return.
                    if let Ok(context) = ctx.read() {
                        if context.sess_remove(sess.id).is_some() {
                            log::debug!(
                                "UAV policy reject: removed session id={} (psi={}) so the \
                                 refusal leaves no state behind",
                                sess.id,
                                pdu_session_id
                            );
                        }
                    }
                    return reject;
                }
            }

            // Register the PCF↔PDU-session binding with the BSF so an AF can
            // discover the serving PCF (TS 23.503 §6.1.1.2, TS 29.521). Best
            // effort: no-op when no BSF/NRF is reachable.
            sbi_path::pcf_sess_register_bsf_binding(sess.id);

            // Query real session data from UDR/database
            let s_nssai = SNssai { sst, sd };
            let session_data = pcf_get_session_data(supi, None, &s_nssai, dnn);

            // Retrieve the SM PolicyData from UDR over Nudr_DataRepository (TS 29.519,
            // TS 29.512 §4.2.2.2) on the live path. Bounded; on 404/unreachable we keep
            // the local subscription/config data as the documented fallback. The QoS/ARP/
            // AMBR/PCC decision is not re-derived from this resource (SmPolicyDnnData does
            // not carry them); only the spec-defined online/offline charging flags are.
            let udr_dnn_data = sbi_path::pcf_udr_sm_policy_dnn_data(supi, sst, sd, dnn).await;
            if udr_dnn_data.is_some() {
                log::info!(
                    "UDR SmPolicyData retrieved over Nudr_DataRepository for SUPI {supi} dnn={dnn}"
                );
            } else {
                log::warn!(
                    "UDR SmPolicyData unavailable (404/unreachable) for SUPI {supi} dnn={dnn}; \
                     using local defaults"
                );
            }

            // Build policy decision from subscription data (TS 29.512).
            // When the DB has no policy data for this DNN/slice, the
            // config-default session data is used (documented fallback).
            let decision = match session_data {
                Some(ref sd) => build_sm_policy_decision(&sess.sm_policy_id, sd),
                None => {
                    log::warn!(
                        "No subscription policy data for dnn={dnn} sst={sst} — \
                         using config-default session data (5QI=9, AMBR 100/100 Mbps)"
                    );
                    build_sm_policy_decision(
                        &sess.sm_policy_id,
                        &nudr_handler::SessionData {
                            qos_index: 9,
                            arp_priority_level: 8,
                            arp_preempt_cap: false,
                            arp_preempt_vuln: true,
                            ambr_uplink: 100_000_000,
                            ambr_downlink: 100_000_000,
                            pcc_rules: vec![],
                        },
                    )
                }
            };

            // Map the TS 29.519 SmPolicyDnnData online/offline flags into the
            // ChargingData decisions when the UDR provided them.
            //
            // #299: through the shared helper, and the resource is STORED on the
            // session. It used to be applied here and discarded, so every later
            // Npcf_SMPolicyControl_UpdateNotify rebuilt `chgDecs` without it and
            // silently reverted this subscriber's charging mode.
            let mut decision = decision;
            sbi_path::apply_policy_dnn_charging(&mut decision.chg_decs, udr_dnn_data.as_ref());
            if let Ok(ctx) = pcf_self().read() {
                if let Some(mut stored) = ctx.sess_find_by_id(sess.id) {
                    stored.policy_dnn_data = udr_dnn_data.clone();
                    ctx.sess_update(&stored);
                }
            }

            SbiResponse::with_status(201)
                .with_header(
                    "Location",
                    format!("/npcf-smpolicycontrol/v1/sm-policies/{}", sess.sm_policy_id),
                )
                .with_json_body(&serde_json::json!({
                    "smPolicyId": sess.sm_policy_id,
                    "supi": supi,
                    "pduSessionId": pdu_session_id,
                    "sessRules": decision.sess_rules,
                    "pccRules": decision.pcc_rules,
                    "qosDecs": decision.qos_decs,
                    "chgDecs": decision.chg_decs,
                    "traffContDecs": decision.traff_cont_decs,
                    "policyCtrlReqTriggers": decision.triggers,
                    // TS 29.512 §5.8: negotiated (consumer ∩ producer) features,
                    // not an echo of the SMF-requested value (pcfd-05).
                    "suppFeat": negotiate_features(
                        policy_data.get("suppFeat").and_then(|v| v.as_str()),
                        PCF_SM_POLICY_SUPPORTED_FEATURES,
                    ),
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        None => send_bad_request("Failed to create SM policy", Some("CREATION_FAILED")),
    }
}

pub async fn handle_sm_policy_get(sm_policy_id: &str) -> SbiResponse {
    log::debug!("SM Policy Get: {sm_policy_id}");

    let ctx = pcf_self();
    let sess = if let Ok(context) = ctx.read() {
        context.sess_find_by_sm_policy_id(sm_policy_id)
    } else {
        None
    };

    match sess {
        Some(sess) => {
            // Reconstruct the stored SmPolicyDecision from the persisted session
            // (TS 29.512 §5.3 Individual SM Policy resource) rather than empty
            // maps (pcfd-11). The decision is rebuilt from the same subscription
            // data used at create so the GET body matches the create response.
            let dnn = sess.dnn.as_deref().unwrap_or("internet");
            let session_data =
                pcf_get_session_data("", None, &sess.s_nssai, dnn).unwrap_or_else(|| {
                    nudr_handler::SessionData {
                        qos_index: 9,
                        arp_priority_level: 8,
                        arp_preempt_cap: false,
                        arp_preempt_vuln: true,
                        ambr_uplink: 100_000_000,
                        ambr_downlink: 100_000_000,
                        pcc_rules: vec![],
                    }
                });
            let decision = build_sm_policy_decision(&sess.sm_policy_id, &session_data);
            // TS 29.512 §5.3: the Individual SM Policy resource is an
            // `SmPolicyControl`, whose two REQUIRED members are `context`
            // (SmPolicyContextData, carrying the SUPI) and `policy`
            // (SmPolicyDecision). Before #89 this answered a flat
            // SmPolicyDecision-shaped object with no context at all, so a strict
            // SMF could not parse it and never learned whose session it was.
            let supi = ctx
                .read()
                .ok()
                .and_then(|context| context.ue_sm_find_by_id(sess.pcf_ue_sm_id))
                .map(|ue| ue.supi)
                .unwrap_or_default();
            let mut context_data = serde_json::Map::new();
            context_data.insert("supi".to_string(), serde_json::json!(supi));
            context_data.insert("pduSessionId".to_string(), serde_json::json!(sess.psi));
            context_data.insert("dnn".to_string(), serde_json::json!(dnn));
            context_data.insert(
                "sliceInfo".to_string(),
                match sess.s_nssai.sd {
                    Some(sd) => serde_json::json!({
                        "sst": sess.s_nssai.sst,
                        "sd": format!("{sd:06x}"),
                    }),
                    None => serde_json::json!({ "sst": sess.s_nssai.sst }),
                },
            );
            if let Some(ref ip) = sess.ipv4addr_string {
                context_data.insert("ipv4Address".to_string(), serde_json::json!(ip));
            }
            if let Some(ref prefix) = sess.ipv6prefix_string {
                context_data.insert("ipv6AddressPrefix".to_string(), serde_json::json!(prefix));
            }
            if let Some(ref uri) = sess.notification_uri {
                context_data.insert("notificationUri".to_string(), serde_json::json!(uri));
            }
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "context": serde_json::Value::Object(context_data),
                    "policy": {
                        "smPolicyId": sess.sm_policy_id,
                        "sessRules": decision.sess_rules,
                        "pccRules": decision.pcc_rules,
                        "qosDecs": decision.qos_decs,
                        "chgDecs": decision.chg_decs,
                        "traffContDecs": decision.traff_cont_decs,
                        "policyCtrlReqTriggers": decision.triggers,
                    },
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => send_not_found(
            &format!("SM Policy {sm_policy_id} not found"),
            Some("POLICY_NOT_FOUND"),
        ),
    }
}

pub async fn handle_sm_policy_delete(sm_policy_id: &str) -> SbiResponse {
    log::info!("SM Policy Delete: {sm_policy_id}");

    let ctx = pcf_self();

    let sess = if let Ok(context) = ctx.read() {
        context.sess_find_by_sm_policy_id(sm_policy_id)
    } else {
        None
    };

    match sess {
        Some(sess) => {
            // Deregister the BSF binding (best-effort) before dropping the session.
            let binding_id = sess.binding.id.clone().unwrap_or_default();
            sbi_path::pcf_sess_deregister_bsf_binding(binding_id);
            if let Ok(context) = ctx.read() {
                context.sess_remove(sess.id);
            }
            log::info!("SM Policy {sm_policy_id} deleted");
            SbiResponse::with_status(204)
        }
        None => send_not_found(
            &format!("SM Policy {sm_policy_id} not found"),
            Some("POLICY_NOT_FOUND"),
        ),
    }
}

/// `Nudr_DM_Notification` sink for policy-data changes (#299, TS 23.502 §4.16.11,
/// TS 29.519 §5.2): the UDR POSTs a `PolicyDataChangeNotification` here when a
/// subscriber's provisioned policy data changes, and every affected live SM policy
/// association is re-authorised toward its SMF.
///
/// Before this, an operator editing a subscriber's policy data reached a **live**
/// session through no path at all: the SMF sees the UDM's subscription notification and
/// correctly defers to the PCF (TS 23.503 §6.1.3.2, #293), and the PCF never learned.
/// The edit took effect when the UE re-established.
///
/// **Selection is by SUPI; evaluation is per session, scoped to its own S-NSSAI and
/// DNN.** The notification names only `ueId` and the changed resource, and a UE can hold
/// PDU sessions on several slices — so re-authorising every session of that SUPI from an
/// unscoped read would apply one slice's policy data to another slice's session, which
/// is the defect #293's Decision 2 records for the SMF's own re-read.
///
/// A session whose mapped policy data did not change is deliberately NOT notified: an
/// `SmPolicyUpdateNotify` carrying an unchanged decision is a re-authorisation the SMF
/// has to process for nothing, and at scale a UDR edit touching one slice would notify
/// every session of every UE.
pub async fn handle_policy_data_change_notify(request: &SbiRequest) -> SbiResponse {
    let Some(content) = request.http.content.as_deref() else {
        return send_bad_request("Missing request body", Some("MISSING_BODY"));
    };
    let body: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };
    // `ueId` is the correlator; without it there is nothing to look up. Answered 400
    // rather than 204 because silently accepting it would make a malformed notification
    // indistinguishable from one that changed nothing.
    let Some(ue_id) = body.get("ueId").and_then(|v| v.as_str()) else {
        return send_bad_request(
            "PolicyDataChangeNotification.ueId is required",
            Some("MANDATORY_IE_MISSING"),
        );
    };
    let report_id = body.get("reportId").and_then(|v| v.as_str()).unwrap_or("");

    // Sessions of this SUPI, resolved before any await: the guard must not be held
    // across one (the crate's lock rule), and the re-read below is async.
    let sessions: Vec<crate::context::PcfSess> = {
        let ctx = pcf_self();
        let Ok(guard) = ctx.read() else {
            return SbiResponse::with_status(204);
        };
        match guard.ue_sm_find_by_supi(ue_id) {
            Some(ue_sm) => ue_sm
                .sess_ids
                .iter()
                .filter_map(|id| guard.sess_find_by_id(*id))
                .collect(),
            None => Vec::new(),
        }
    };
    if sessions.is_empty() {
        log::debug!(
            "Policy-data change for {ue_id} ({report_id}): no live SM policy association, \
             nothing to re-authorise"
        );
        return SbiResponse::with_status(204);
    }

    // ONE discovery for the whole notification, before the loop: a UE with several PDU
    // sessions would otherwise cost one NRF round trip each. And when no UDR is
    // discoverable there is nothing to re-read the decision FROM, so nothing is touched —
    // sending the old decision as a re-authorisation, or storing the failed read, would
    // both be worse than doing nothing (criterion 5).
    let udr = match sbi_path::pcf_discover_endpoint("UDR", "nudr-dr").await {
        Ok(Some(ep)) => ep,
        Ok(None) => {
            log::warn!(
                "Policy-data change for {ue_id} ({report_id}): no UDR discoverable, so the \
                 new decision cannot be read. {} live association(s) keep the policy they \
                 were authorised with.",
                sessions.len()
            );
            return SbiResponse::with_status(204);
        }
        Err(e) => {
            log::warn!("Policy-data change for {ue_id}: UDR discovery failed: {e}");
            return SbiResponse::with_status(204);
        }
    };

    let mut reauthorised = 0usize;
    for sess in sessions {
        let dnn = sess.dnn.clone().unwrap_or_else(|| "internet".to_string());
        // Scoped to THIS session's slice and DNN (see the doc comment).
        let fresh = match sbi_path::pcf_udr_sm_policy_dnn_data_from(
            &udr,
            ue_id,
            sess.s_nssai.sst,
            sess.s_nssai.sd,
            &dnn,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                // A failed read is NOT "nothing provisioned": treating it as one would
                // erase what the session holds and re-authorise it with the local
                // default, i.e. revert the subscriber on a transient error.
                log::warn!(
                    "Policy-data change for {ue_id}: re-reading session {} (dnn={dnn}) \
                     failed: {e}. It keeps the policy it was authorised with.",
                    sess.id
                );
                continue;
            }
        };
        if fresh == sess.policy_dnn_data {
            log::debug!(
                "Policy-data change for {ue_id}: session {} (dnn={dnn}, sst={}) unchanged",
                sess.id,
                sess.s_nssai.sst
            );
            continue;
        }
        if let Ok(ctx) = pcf_self().read() {
            if let Some(mut stored) = ctx.sess_find_by_id(sess.id) {
                stored.policy_dnn_data = fresh;
                ctx.sess_update(&stored);
            }
        }
        // The existing leg (TS 29.512 §4.2.3.2). The SMF's `handle_sm_policy_notify`
        // consumes it, so nothing is needed on that side.
        if sbi_path::pcf_sbi_send_smpolicycontrol_update_notify(sess.id) {
            reauthorised += 1;
        }
    }
    log::info!(
        "Policy-data change for {ue_id} ({report_id}): re-authorised {reauthorised} SM policy \
         association(s)"
    );
    SbiResponse::with_status(204)
}

pub async fn handle_sm_policy_update_notify(
    sm_policy_id: &str,
    request: &SbiRequest,
) -> SbiResponse {
    log::info!("SM Policy Update Notify: {sm_policy_id}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let update_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let ctx = pcf_self();
    let sess = if let Ok(context) = ctx.read() {
        context.sess_find_by_sm_policy_id(sm_policy_id)
    } else {
        None
    };

    match sess {
        Some(sess) => {
            // Process reported triggers from SMF. repPolicyCtrlReqTriggers
            // is optional in SmPolicyUpdateContextData (TS 29.512 §5.6.2.5)
            // — its absence must NOT panic (was an .expect() 500/abort path).
            let triggers = update_data
                .get("repPolicyCtrlReqTriggers")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            log::info!(
                "SM Policy Update triggers: {:?} for session PSI={}",
                triggers,
                sess.psi
            );

            // TS 29.513 §6: the BSF binding advertises this session's UE IP, so a
            // change has to reach it (Nbsf_Management_Update) or an AF-influenced
            // lookup resolves a binding that no longer matches the session. Only
            // register/deregister existed before #89.
            let new_ipv4 = update_data
                .get("ipv4Address")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty());
            let new_ipv6 = update_data
                .get("ipv6AddressPrefix")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty());
            let ipv4_changed =
                new_ipv4.is_some_and(|ip| sess.ipv4addr_string.as_deref() != Some(ip));
            let ipv6_changed =
                new_ipv6.is_some_and(|p| sess.ipv6prefix_string.as_deref() != Some(p));
            if ipv4_changed || ipv6_changed {
                let mut latest = sess.clone();
                if let Some(ip) = new_ipv4.filter(|_| ipv4_changed) {
                    latest.set_ipv4addr(ip);
                }
                if let Some(prefix) = new_ipv6.filter(|_| ipv6_changed) {
                    latest.set_ipv6prefix(prefix);
                }
                if let Ok(context) = ctx.read() {
                    context.sess_update(&latest);
                }
                log::info!(
                    "SM Policy Update: UE address changed (ipv4={new_ipv4:?}, ipv6={new_ipv6:?}); \
                     updating the BSF binding"
                );
                sbi_path::pcf_sess_update_bsf_binding(latest.id);
            }

            // TS 29.523 `AC_TY_CH`: SmPolicyUpdateContextData carries `accessType`,
            // so an update whose access type differs from the one this session was
            // last seen on IS the access-type change event. Compared against the
            // stored value rather than merely reported when the member is present:
            // an SMF that echoes the unchanged accessType on every update would
            // otherwise produce a change notification per update.
            //
            // `None` stored means this session predates the field (a restored v1
            // snapshot) — recorded silently rather than reported, because "we did
            // not know the previous access type" is not evidence of a change.
            let reported_access = update_data
                .get("accessType")
                .and_then(|v| v.as_str())
                .and_then(|s| match s {
                    "3GPP_ACCESS" => Some(crate::context::AccessType::ThreeGppAccess),
                    "NON_3GPP_ACCESS" => Some(crate::context::AccessType::NonThreeGppAccess),
                    // A token outside the enum is not decodable into the stored
                    // type; left alone rather than guessed at.
                    _ => None,
                });
            if let Some(new_access) = reported_access {
                if sess.access_type != Some(new_access) {
                    let previously_known = sess.access_type.is_some();
                    let mut latest = match ctx.read() {
                        Ok(context) => context
                            .sess_find_by_sm_policy_id(sm_policy_id)
                            .unwrap_or_else(|| sess.clone()),
                        Err(_) => sess.clone(),
                    };
                    latest.access_type = Some(new_access);
                    if let Ok(context) = ctx.read() {
                        context.sess_update(&latest);
                    }
                    if previously_known {
                        let rat_type = update_data
                            .get("ratType")
                            .and_then(|v| v.as_str())
                            .map(str::to_string);
                        let mut extra = serde_json::json!({
                            "accType": match new_access {
                                crate::context::AccessType::ThreeGppAccess => "3GPP_ACCESS",
                                crate::context::AccessType::NonThreeGppAccess => "NON_3GPP_ACCESS",
                            },
                        });
                        // Carried through verbatim only when the SMF sent them —
                        // `PcEventNotification` members this PCF does not hold stay
                        // absent rather than being invented.
                        if let Some(obj) = extra.as_object_mut() {
                            if let Some(rat) = rat_type {
                                obj.insert("ratType".to_string(), serde_json::json!(rat));
                            }
                            for member in ["addAccessInfo", "relAccessInfo"] {
                                if let Some(v) = update_data.get(member) {
                                    obj.insert(member.to_string(), v.clone());
                                }
                            }
                            if let Some(ref dnn) = latest.dnn {
                                obj.insert(
                                    "pduSessionInfo".to_string(),
                                    serde_json::json!({
                                        "dnn": dnn,
                                        "snssai": {
                                            "sst": latest.s_nssai.sst,
                                            "sd": latest.s_nssai.sd,
                                        },
                                    }),
                                );
                            }
                        }
                        sbi_path::pcf_report_pc_event("AC_TY_CH", latest.dnn.as_deref(), extra)
                            .await;
                    }
                }
            }

            // Process PCC rule reports from SMF (rule status changes)
            let mut rule_reports = Vec::new();
            if let Some(reports) = update_data
                .get("repPccRuleStatusList")
                .and_then(|v| v.as_object())
            {
                for (rule_id, report) in reports {
                    let status = report
                        .get("ruleStatus")
                        .and_then(|v| v.as_str())
                        .unwrap_or("ACTIVE");
                    log::debug!("PCC rule {rule_id} status: {status}");
                    rule_reports.push((rule_id.clone(), status.to_string()));
                }
            }

            // Build updated policy decision based on triggers
            let mut pcc_rules = serde_json::Map::new();
            let mut qos_decs = serde_json::Map::new();
            let mut chg_decs = serde_json::Map::new();
            let mut tc_decs = serde_json::Map::new();

            // If UE requested resource modification, generate new PCC rules
            if let Some(ue_req) = update_data.get("ueInitResReq") {
                let req_5qi = ue_req
                    .get("reqQos")
                    .and_then(|q| q.get("5qi"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(9);
                let req_gbr_ul = ue_req
                    .get("reqQos")
                    .and_then(|q| q.get("gbrUl"))
                    .and_then(|v| v.as_str());
                let req_gbr_dl = ue_req
                    .get("reqQos")
                    .and_then(|q| q.get("gbrDl"))
                    .and_then(|v| v.as_str());

                let rule_id = format!("PccRule-ue-{}", sess.sm_policy_id);
                let qos_ref = format!("QosDec-ue-{}", sess.sm_policy_id);
                let chg_ref = format!("ChgDec-ue-{}", sess.sm_policy_id);
                let tc_ref = format!("TcDec-ue-{}", sess.sm_policy_id);

                chg_decs.insert(
                    chg_ref.clone(),
                    serde_json::json!({
                        "chgId": chg_ref,
                        "ratingGroup": 1,
                        "meteringMethod": "VOLUME",
                        "offline": true,
                        "online": false,
                    }),
                );
                tc_decs.insert(
                    tc_ref.clone(),
                    serde_json::json!({ "tcId": tc_ref, "flowStatus": "ENABLED" }),
                );

                pcc_rules.insert(
                    rule_id.clone(),
                    serde_json::json!({
                        "pccRuleId": rule_id,
                        "precedence": 100,
                        "refQosData": [&qos_ref],
                        "refChgData": [&chg_ref],
                        "refTcData": [&tc_ref],
                    }),
                );

                let mut qos_dec = serde_json::json!({
                    // TS 29.512 Table 5.6.2.8-1: mandatory qosId (== map key).
                    "qosId": qos_ref,
                    "5qi": req_5qi,
                });
                if let Some(gbr_ul) = req_gbr_ul {
                    qos_dec["gbrUl"] = serde_json::json!(gbr_ul);
                }
                if let Some(gbr_dl) = req_gbr_dl {
                    qos_dec["gbrDl"] = serde_json::json!(gbr_dl);
                }
                qos_decs.insert(qos_ref, qos_dec);

                log::info!("Generated PCC rule for UE-initiated resource request: 5QI={req_5qi}");
            }

            // If SESS_AMBR_CH trigger, re-evaluate session AMBR
            let sess_rules = if triggers.iter().any(|t| t == "SE_AMBR_CH") {
                // Re-query session data for updated AMBR
                let s_nssai = SNssai {
                    sst: sess.s_nssai.sst,
                    sd: sess.s_nssai.sd,
                };
                let dnn = sess.dnn.as_deref().unwrap_or("internet");
                if let Some(sd) = pcf_get_session_data("", None, &s_nssai, dnn) {
                    let sess_rule_id = format!("SessRule-{}", sess.sm_policy_id);
                    serde_json::json!({
                        &sess_rule_id: {
                            "sessRuleId": sess_rule_id,
                            "authSessAmbr": {
                                "uplink": format_bitrate(sd.ambr_uplink),
                                "downlink": format_bitrate(sd.ambr_downlink),
                            },
                        }
                    })
                } else {
                    serde_json::json!({})
                }
            } else {
                serde_json::json!({})
            };

            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "smPolicyId": sess.sm_policy_id,
                    "pduSessionId": sess.psi,
                    "sessRules": sess_rules,
                    "pccRules": serde_json::Value::Object(pcc_rules),
                    "qosDecs": serde_json::Value::Object(qos_decs),
                    "chgDecs": serde_json::Value::Object(chg_decs),
                    "traffContDecs": serde_json::Value::Object(tc_decs),
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => send_not_found(
            &format!("SM Policy {sm_policy_id} not found"),
            Some("POLICY_NOT_FOUND"),
        ),
    }
}

// Policy Authorization handlers

/// Parse a TS 29.514 MediaSubComponent (`fNum`, `fDescs`) from JSON.
fn parse_media_sub_component(v: &serde_json::Value) -> Option<MediaSubComponent> {
    let obj = v.as_object()?;
    let f_num = obj.get("fNum").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    let f_descs = obj
        .get("fDescs")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|d| d.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    Some(MediaSubComponent {
        f_num,
        flow_usage: FlowUsage::default(),
        f_descs,
    })
}

/// Parse a TS 29.514 MediaComponent (medCompN, medType, marBw*, qosReference,
/// fStatus, medSubComps) from JSON.
fn parse_media_component(v: &serde_json::Value) -> Option<MediaComponent> {
    let obj = v.as_object()?;
    let get_str = |k: &str| obj.get(k).and_then(|x| x.as_str()).map(str::to_string);
    let med_sub_comps = obj
        .get("medSubComps")
        .and_then(|x| x.as_object())
        .map(|m| m.values().filter_map(parse_media_sub_component).collect())
        .unwrap_or_default();
    Some(MediaComponent {
        med_comp_n: obj.get("medCompN").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        med_type: obj
            .get("medType")
            .and_then(|x| x.as_str())
            .map(MediaType::from_wire)
            .unwrap_or_default(),
        mar_bw_dl: get_str("marBwDl"),
        mar_bw_ul: get_str("marBwUl"),
        mir_bw_dl: get_str("mirBwDl"),
        mir_bw_ul: get_str("mirBwUl"),
        rr_bw: get_str("rrBw"),
        rs_bw: get_str("rsBw"),
        qos_ref: get_str("qosReference").or_else(|| get_str("qosRef")),
        f_status: obj
            .get("fStatus")
            .and_then(|x| x.as_str())
            .map(FlowStatus::from_wire)
            .unwrap_or_default(),
        med_sub_comps,
    })
}

/// Parse a TS 29.514 AppSessionContextReqData (`ascReqData`) from JSON. The
/// `medComponents` attribute is a map keyed by medCompN.
fn parse_asc_req_data(root: &serde_json::Value) -> AscReqData {
    let med_components = root
        .get("medComponents")
        .and_then(|v| v.as_object())
        .map(|map| map.values().filter_map(parse_media_component).collect())
        .unwrap_or_default();
    let opt_str = |key: &str| {
        root.get(key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    AscReqData {
        supp_feat: opt_str("suppFeat"),
        notif_uri: opt_str("notifUri"),
        med_components,
        ue_ipv4: opt_str("ueIpv4"),
        ue_ipv6: opt_str("ueIpv6"),
        ue_mac: opt_str("ueMac"),
    }
}

/// Which UE address an `AppSessionContextReqData` identifies the session by.
#[derive(Debug, Clone, PartialEq, Eq)]
enum UeAddress {
    Ipv4(String),
    Ipv6(String),
    Mac(String),
}

/// Validate an `AppSessionContextReqData` (TS 29.514 Table 5.7.3-1) and return
/// the single UE address it identifies.
///
/// `notifUri` and `suppFeat` are required, and the UE-address members are a
/// `oneOf` — so ZERO of them and MORE THAN ONE are both errors. Before #88 none
/// of this was checked and only `ueIpv4` was even read, so an AF that sent a
/// `ueIpv6` got a 201 for a session the PCF had not bound.
fn validate_asc_req_data(asc: &AscReqData) -> Result<UeAddress, Box<SbiResponse>> {
    if asc.notif_uri.is_none() {
        return Err(Box::new(send_bad_request(
            "AppSessionContextReqData.notifUri is mandatory",
            Some("MANDATORY_IE_MISSING"),
        )));
    }
    if asc.supp_feat.is_none() {
        return Err(Box::new(send_bad_request(
            "AppSessionContextReqData.suppFeat is mandatory",
            Some("MANDATORY_IE_MISSING"),
        )));
    }
    let mut found: Vec<UeAddress> = Vec::new();
    if let Some(ip) = &asc.ue_ipv4 {
        found.push(UeAddress::Ipv4(ip.clone()));
    }
    if let Some(ip) = &asc.ue_ipv6 {
        found.push(UeAddress::Ipv6(ip.clone()));
    }
    if let Some(mac) = &asc.ue_mac {
        found.push(UeAddress::Mac(mac.clone()));
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err(Box::new(send_bad_request(
            "AppSessionContextReqData requires exactly one of ueIpv4, ueIpv6 or ueMac",
            Some("MANDATORY_IE_MISSING"),
        ))),
        _ => Err(Box::new(send_bad_request(
            "AppSessionContextReqData carries more than one UE address (oneOf)",
            Some("MANDATORY_IE_INCORRECT"),
        ))),
    }
}

/// Resolve the PDU session an AF request is about.
///
/// `ueMac` is validated as a UE-address form but cannot resolve anything here:
/// binding by MAC needs a session attribute this PCF never receives — nothing in
/// the tree sends a MAC on the SM policy create — so it fails the binding rather
/// than being bound to a guess. TS 29.514 §4.2.2.2's answer for "cannot
/// associate with an existing PDU session" is exactly what the caller then
/// returns.
fn bind_ue_address(address: &UeAddress) -> Option<PcfSess> {
    let ctx = pcf_self();
    let context = ctx.read().ok()?;
    match address {
        UeAddress::Ipv4(ip) => context.sess_find_by_ipv4addr(ip),
        UeAddress::Ipv6(ip) => context.sess_find_by_ipv6_ue_addr(ip),
        UeAddress::Mac(mac) => {
            log::warn!("AF request bound by ueMac={mac}: no MAC-keyed session exists in this PCF");
            None
        }
    }
}

/// `403 PDU_SESSION_NOT_AVAILABLE` — TS 29.514 §4.2.2.2's answer when the PCF
/// cannot associate an AF request with an existing PDU session.
fn pdu_session_not_available(address: &UeAddress) -> SbiResponse {
    SbiResponse::with_status(403)
        .with_json_body(&serde_json::json!({
            "status": 403,
            "cause": "PDU_SESSION_NOT_AVAILABLE",
            "detail": format!("No PDU session bound to {address:?}"),
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(403))
}

/// Whether AscRespData is conditionally required in the response (TS 29.514
/// §4.2.2.2): emergency sessions or AF requests carrying UE identity / service
/// URN. Otherwise the negotiated `suppFeat` alone is returned.
fn asc_resp_required(root: &serde_json::Value) -> bool {
    root.get("ueIds").is_some()
        || root.get("servUrn").is_some()
        || root
            .get("dnn")
            .and_then(|v| v.as_str())
            .map(|d| d.eq_ignore_ascii_case("sos") || d.eq_ignore_ascii_case("emergency"))
            .unwrap_or(false)
}

/// Merge newly-built AF PCC rules into a session, replacing any rule with the
/// same id (stable per (psi, medCompN)) and appending the rest.
fn merge_af_pcc_rules(sess: &mut PcfSess, new_rules: Vec<npcf_handler::AfPccRule>) {
    let new_ids: std::collections::HashSet<String> =
        new_rules.iter().map(|r| r.pcc_rule_id.clone()).collect();
    sess.af_pcc_rules
        .retain(|r| !new_ids.contains(&r.pcc_rule_id));
    sess.af_pcc_rules.extend(new_rules);
}

/// Build the AppSessionContext body returned in the create/modify response.
/// Backward-compat: a request WITHOUT medComponents yields exactly
/// `{appSessionId, notifUri, suppFeat}` (the bind + suppFeat-echo behaviour).
/// When medComponents are present the echoed `ascReqData` is added, plus
/// `ascRespData` when it is conditionally required (else the `suppFeat` echo).
fn build_app_session_context(
    app_session_id: &str,
    req_root: &serde_json::Value,
    asc: &AscReqData,
) -> serde_json::Value {
    // TS 29.514 §4.2.2.2 / pcfd-05: the AppSessionContext carries the negotiated
    // (consumer ∩ producer) suppFeat, not an echo. A missing consumer value
    // negotiates to "0".
    let negotiated = negotiate_features(
        req_root.get("suppFeat").and_then(|v| v.as_str()),
        PCF_PA_SUPPORTED_FEATURES,
    );
    let mut body = serde_json::json!({
        "appSessionId": app_session_id,
        "notifUri": req_root.get("notifUri"),
        "suppFeat": negotiated.clone(),
    });
    if !asc.med_components.is_empty() {
        if let Some(obj) = body.as_object_mut() {
            obj.insert("ascReqData".to_string(), req_root.clone());
            if asc_resp_required(req_root) {
                let rd = serde_json::json!({
                    "servAuthInfo": "NOT_KNOWN",
                    "suppFeat": negotiated,
                });
                obj.insert("ascRespData".to_string(), rd);
            }
        }
    }
    body
}

pub async fn handle_app_session_create(request: &SbiRequest) -> SbiResponse {
    log::info!("App Session Create");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let session_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    // TS 29.514 AppSessionContext carries the request under `ascReqData`; the
    // legacy flat body (matched-sim) is accepted as a fallback.
    let req_root = session_data.get("ascReqData").unwrap_or(&session_data);
    let asc = parse_asc_req_data(req_root);
    let notif_uri = asc.notif_uri.clone();

    // TS 29.514 Table 5.7.3-1: mandatory IEs and the UE-address oneOf. Checked
    // before anything is stored, so a malformed request cannot leave a context
    // behind (#88).
    let address = match validate_asc_req_data(&asc) {
        Ok(a) => a,
        Err(resp) => return *resp,
    };

    // Bind the AF session to the PCC session via the UE address so AF-triggered
    // PCC rule changes can be pushed to the SMF. TS 29.514 §4.2.2.2: when the
    // PCF cannot associate the request with an existing PDU session it REFUSES
    // with 403 PDU_SESSION_NOT_AVAILABLE. Before #88 it minted a UUID, stored
    // nothing and answered 201, so the AF believed authorisation had succeeded
    // while no PCC rule existed and the appSessionId it was given was not
    // addressable.
    let Some(bound_sess) = bind_ue_address(&address) else {
        log::warn!("App session create refused: no PDU session bound to {address:?}");
        return pdu_session_not_available(&address);
    };

    let ctx = pcf_self();
    let Some(app) = ctx.read().ok().and_then(|context| {
        context.app_add(bound_sess.id).map(|app0| {
            let mut app = app0;
            app.notif_uri = notif_uri.clone();
            context.app_update(&app);
            app
        })
    }) else {
        log::error!("App session create: context could not allocate an app session");
        return nextgcore_sbi::server::send_internal_error("App session allocation failed");
    };
    let app_session_id = app.app_session_id.clone();
    let bound_sess = Some(bound_sess);

    if !asc.med_components.is_empty() {
        // AF media components → PCC rules persisted on the bound session and
        // pushed to the SMF in an SM policy update notify (TS 29.514 §4.2.2.2).
        if let Some(ref sess) = bound_sess {
            let new_rules = media_components_to_pcc(&asc, sess);
            let installed = new_rules.len();
            if let Ok(context) = ctx.read() {
                if let Some(mut latest) = context.sess_find_by_id(sess.id) {
                    merge_af_pcc_rules(&mut latest, new_rules);
                    context.sess_update(&latest);
                }
            }
            pcf_sbi_send_af_smpolicycontrol_update_notify(sess.id);
            log::info!(
                "App session create installed {installed} AF PCC rule(s) on sess_id={}",
                sess.id
            );
            // TS 29.514 §4.2.6: the AF learns the outcome of its resource
            // request through an EventsNotification, if it subscribed.
            notify_af_resource_allocation(app.id, installed > 0);
        }
    } else if let Some(ref sess) = bound_sess {
        // No medComponents: bind + generic notify, as today.
        pcf_sbi_send_smpolicycontrol_update_notify(sess.id);
    }

    log::info!(
        "App Session created (id={app_session_id}, bound={})",
        bound_sess.is_some()
    );

    SbiResponse::with_status(201)
        .with_header(
            "Location",
            format!("/npcf-policyauthorization/v1/app-sessions/{app_session_id}"),
        )
        .with_json_body(&build_app_session_context(&app_session_id, req_root, &asc))
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// Route the `npcf-policyauthorization` `app-sessions` tree (TS 29.514 §4.2).
///
/// Split out and GUARDED BY PATH DEPTH because the create arm used to be
/// unguarded (#88): `POST /app-sessions/{id}/delete` — the spec's own
/// deregistration custom operation — matched it, so a conformant AF teardown
/// minted a phantom session and left the original PCC rules installed. So did
/// `POST /app-sessions/pcscf-restoration`. Every arm here pins its exact depth.
async fn route_policy_authorization(
    parts: &[&str],
    method: &str,
    request: &SbiRequest,
    uri: &str,
) -> SbiResponse {
    match (parts.len(), method) {
        // Collection: create only.
        (3, "POST") => handle_app_session_create(request).await,
        // POST /app-sessions/pcscf-restoration (TS 29.514 §4.2.5) — must be
        // matched BEFORE anything treats parts[3] as an appSessionId.
        (4, "POST") if parts[3] == "pcscf-restoration" => handle_pcscf_restoration(request).await,
        (4, "GET") => handle_app_session_get(parts[3]).await,
        (4, "PATCH") => handle_app_session_modify(parts[3], request).await,
        // Non-spec bare DELETE, kept because it is harmless and predates the
        // spec custom operation below.
        (4, "DELETE") => handle_app_session_delete(parts[3]).await,
        // POST /app-sessions/{appSessionId}/delete (TS 29.514 §4.2.4.2) — the
        // spec deregistration.
        (5, "POST") if parts[4] == "delete" => handle_app_session_delete(parts[3]).await,
        (5, "PUT") if parts[4] == "events-subscription" => {
            handle_events_subscription_put(parts[3], request).await
        }
        (5, "DELETE") if parts[4] == "events-subscription" => {
            handle_events_subscription_delete(parts[3]).await
        }
        _ => {
            log::warn!("Unknown policy-authorization request: {method} {uri}");
            send_method_not_allowed(method, uri)
        }
    }
}

/// TS 29.514 §4.2.6: tell the AF how its resource request turned out.
///
/// `SUCCESSFUL_RESOURCE_ALLOCATION` when the media components produced PCC rules,
/// `RES_ALLO_FAILURE` when they produced none — those are the two outcomes this
/// PCF can actually observe, and reporting the second as the first would tell an
/// IMS AF a bearer exists that does not. Delivery is skipped when the AF did not
/// subscribe to the event.
fn notify_af_resource_allocation(app_id: u64, installed: bool) {
    let event = if installed {
        "SUCCESSFUL_RESOURCE_ALLOCATION"
    } else {
        "RES_ALLO_FAILURE"
    };
    pcf_sbi_send_policyauthorization_events_notify(app_id, &[event]);
}

/// `PUT /app-sessions/{appSessionId}/events-subscription` — TS 29.514 §4.2.6
/// `updateEventsSubsc`.
///
/// Stores the `EventsSubscReqData` on the app session so a later trigger knows
/// which events the AF wants and where to send them. `201` on create with the
/// resource's `Location`, `200` on modification (the spec allows `204` there too;
/// returning the representation lets the AF confirm what the PCF now holds).
pub async fn handle_events_subscription_put(
    app_session_id: &str,
    request: &SbiRequest,
) -> SbiResponse {
    log::info!("Events Subscription PUT: {app_session_id}");
    let Some(content) = request.http.content.as_deref() else {
        return send_bad_request("Missing request body", Some("MISSING_BODY"));
    };
    let body: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };
    // EventsSubscReqData requires `events` with minItems 1, and each
    // AfEventSubscription requires `event` — a subscription naming no event
    // would be stored and then never match anything.
    let events_ok = body
        .get("events")
        .and_then(|v| v.as_array())
        .is_some_and(|list| {
            !list.is_empty()
                && list
                    .iter()
                    .all(|e| e.get("event").and_then(|v| v.as_str()).is_some())
        });
    if !events_ok {
        return send_bad_request(
            "EventsSubscReqData.events must carry at least one entry with an `event`",
            Some("MANDATORY_IE_MISSING"),
        );
    }

    let ctx = pcf_self();
    let app = ctx
        .read()
        .ok()
        .and_then(|context| context.app_find_by_app_session_id(app_session_id));
    let Some(mut app) = app else {
        return send_not_found(
            &format!("App Session {app_session_id} not found"),
            Some("SESSION_NOT_FOUND"),
        );
    };
    let created = app.events_subsc.is_none();
    app.events_subsc = Some(body.clone());
    if let Ok(context) = ctx.read() {
        context.app_update(&app);
    }
    let location =
        format!("/npcf-policyauthorization/v1/app-sessions/{app_session_id}/events-subscription");
    let status = if created { 201 } else { 200 };
    let mut resp = SbiResponse::with_status(status)
        .with_json_body(&body)
        .unwrap_or_else(|_| SbiResponse::with_status(status));
    if created {
        resp = resp.with_header("Location", location);
    }
    resp
}

/// `DELETE /app-sessions/{appSessionId}/events-subscription` — TS 29.514 §4.2.6
/// `DeleteEventsSubsc`.
pub async fn handle_events_subscription_delete(app_session_id: &str) -> SbiResponse {
    log::info!("Events Subscription DELETE: {app_session_id}");
    let ctx = pcf_self();
    let app = ctx
        .read()
        .ok()
        .and_then(|context| context.app_find_by_app_session_id(app_session_id));
    match app {
        Some(mut app) => {
            app.events_subsc = None;
            if let Ok(context) = ctx.read() {
                context.app_update(&app);
            }
            SbiResponse::with_status(204)
        }
        None => send_not_found(
            &format!("App Session {app_session_id} not found"),
            Some("SESSION_NOT_FOUND"),
        ),
    }
}

/// `POST /app-sessions/pcscf-restoration` — TS 29.514 §4.2.5 `PcscfRestoration`.
///
/// `PcscfRestorationRequestData` is a `oneOf` over `ueIpv4` / `ueIpv6`, so the
/// UE whose IMS session must be restored is identified the same way an app
/// session is. The PCF resolves that session and pushes an SM policy update to
/// its SMF, which is the mechanism it has for telling the SMF the policy for
/// that session has changed (TS 23.380 §5.4: the network re-establishes the IMS
/// PDU session). It answers `204`, as the spec defines no response body.
///
/// A UE address that resolves nothing is a `404`: the caller asked the PCF to
/// restore a session it does not know about, and a `204` would report a
/// restoration that did not happen.
pub async fn handle_pcscf_restoration(request: &SbiRequest) -> SbiResponse {
    log::info!("P-CSCF Restoration");
    let Some(content) = request.http.content.as_deref() else {
        return send_bad_request("Missing request body", Some("MISSING_BODY"));
    };
    let body: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };
    let ipv4 = body
        .get("ueIpv4")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let ipv6 = body
        .get("ueIpv6")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let address = match (ipv4, ipv6) {
        (Some(ip), None) => UeAddress::Ipv4(ip.to_string()),
        (None, Some(ip)) => UeAddress::Ipv6(ip.to_string()),
        (None, None) => {
            return send_bad_request(
                "PcscfRestorationRequestData requires exactly one of ueIpv4 or ueIpv6",
                Some("MANDATORY_IE_MISSING"),
            )
        }
        (Some(_), Some(_)) => {
            return send_bad_request(
                "PcscfRestorationRequestData carries both ueIpv4 and ueIpv6 (oneOf)",
                Some("MANDATORY_IE_INCORRECT"),
            )
        }
    };
    let Some(sess) = bind_ue_address(&address) else {
        log::warn!("P-CSCF restoration for an unknown UE address {address:?}");
        return send_not_found(
            &format!("No PDU session bound to {address:?}"),
            Some("SESSION_NOT_FOUND"),
        );
    };
    log::info!(
        "P-CSCF restoration: notifying SMF for sess_id={} ({address:?})",
        sess.id
    );
    pcf_sbi_send_smpolicycontrol_update_notify(sess.id);
    SbiResponse::with_status(204)
}

pub async fn handle_app_session_get(app_session_id: &str) -> SbiResponse {
    log::debug!("App Session Get: {app_session_id}");

    let ctx = pcf_self();
    let app = if let Ok(context) = ctx.read() {
        context.app_find_by_app_session_id(app_session_id)
    } else {
        None
    };

    match app {
        Some(app) => SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({
                "appSessionId": app.app_session_id,
                "notifUri": app.notif_uri,
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("App Session {app_session_id} not found"),
            Some("SESSION_NOT_FOUND"),
        ),
    }
}

pub async fn handle_app_session_delete(app_session_id: &str) -> SbiResponse {
    log::info!("App Session Delete: {app_session_id}");

    let ctx = pcf_self();

    let app = if let Ok(context) = ctx.read() {
        context.app_find_by_app_session_id(app_session_id)
    } else {
        None
    };

    match app {
        Some(app) => {
            // Removing AF media components revokes their PCC rules at the
            // SMF: push the SM policy delete/update notification.
            pcf_sbi_send_smpolicycontrol_delete_notify(app.sess_id, app.id);
            if let Ok(context) = ctx.read() {
                context.app_remove(app.id);
            }
            log::info!("App Session {app_session_id} deleted");
            SbiResponse::with_status(204)
        }
        None => send_not_found(
            &format!("App Session {app_session_id} not found"),
            Some("SESSION_NOT_FOUND"),
        ),
    }
}

pub async fn handle_app_session_modify(app_session_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("App Session Modify: {app_session_id}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let modify_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    // TS 29.514 §4.2.3.3: a PATCH carries AppSessionContextUpdateData; accept
    // either the nested `ascReqData` or the flat form.
    let req_root = modify_data.get("ascReqData").unwrap_or(&modify_data);
    let asc = parse_asc_req_data(req_root);

    let ctx = pcf_self();
    let app = if let Ok(context) = ctx.read() {
        context.app_find_by_app_session_id(app_session_id)
    } else {
        None
    };

    match app {
        Some(app) => {
            if !asc.med_components.is_empty() {
                // Re-derive the AF PCC rules and push them to the SMF.
                let mut installed = 0usize;
                if let Ok(context) = ctx.read() {
                    if let Some(mut sess) = context.sess_find_by_id(app.sess_id) {
                        let new_rules = media_components_to_pcc(&asc, &sess);
                        installed = new_rules.len();
                        merge_af_pcc_rules(&mut sess, new_rules);
                        context.sess_update(&sess);
                    }
                }
                pcf_sbi_send_af_smpolicycontrol_update_notify(app.sess_id);
                log::info!(
                    "App session modify updated {installed} AF PCC rule(s) on sess_id={}",
                    app.sess_id
                );
                notify_af_resource_allocation(app.id, installed > 0);
            }

            let mut resp_body = build_app_session_context(&app.app_session_id, req_root, &asc);
            // Always reflect the stored notifUri on the resource representation.
            if let Some(obj) = resp_body.as_object_mut() {
                if obj.get("notifUri").map(|v| v.is_null()).unwrap_or(true) {
                    obj.insert("notifUri".to_string(), serde_json::json!(app.notif_uri));
                }
            }
            SbiResponse::with_status(200)
                .with_json_body(&resp_body)
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => send_not_found(
            &format!("App Session {app_session_id} not found"),
            Some("SESSION_NOT_FOUND"),
        ),
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
async fn run_event_loop_async(pcf_sm: &mut PcfSmContext, shutdown: Arc<AtomicBool>) -> Result<()> {
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
                "PCF timer expired: id={} type={:?} data={:?}",
                entry.id,
                entry.timer_type,
                entry.data
            );

            // Create timer event and dispatch to state machine
            let mut event = PcfEvent::sbi_timer(entry.timer_type);
            if let Some(ref nf_id) = entry.data {
                event = event.with_nf_instance(nf_id.clone());
            }

            pcf_sm.dispatch(&mut event);
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

/// Parse host and port from a URI string (e.g., "http://localhost:7777").
fn parse_nrf_host_port(uri: &str) -> Option<(String, u16)> {
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

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-pcfd"]);
        assert_eq!(args.config, "/etc/nextgcore/pcf.yaml");
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
            "nextgcore-pcfd",
            "-c",
            "/custom/pcf.yaml",
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
        assert_eq!(args.config, "/custom/pcf.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 8080);
        assert_eq!(args.max_ue, 2048);
        assert_eq!(args.max_sess, 8192);
    }

    #[test]
    fn test_args_tls() {
        let args = Args::parse_from([
            "nextgcore-pcfd",
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
    fn test_build_sm_policy_decision() {
        let session_data = nudr_handler::SessionData {
            qos_index: 9,
            arp_priority_level: 8,
            arp_preempt_cap: false,
            arp_preempt_vuln: true,
            ambr_uplink: 100_000_000,
            ambr_downlink: 200_000_000,
            pcc_rules: vec![nudr_handler::PccRule {
                id: "rule-1".to_string(),
                precedence: 50,
                qos_index: 5,
                flow_status: npcf_handler::FlowStatus::Enabled,
                flows: vec![nudr_handler::FlowDescription {
                    direction: nudr_handler::FlowDirection::Downlink,
                    description: "permit out ip from any to assigned".to_string(),
                }],
            }],
        };

        let dec = build_sm_policy_decision("test-policy-1", &session_data);

        // Verify session rules
        let sr = &dec.sess_rules["SessRule-test-policy-1"];
        assert_eq!(sr["authDefQos"]["5qi"], 9);
        assert_eq!(sr["authSessAmbr"]["uplink"], "100 Mbps");
        assert_eq!(sr["authSessAmbr"]["downlink"], "200 Mbps");

        // Verify PCC rules from subscription
        let pcc = &dec.pcc_rules["rule-1"];
        assert_eq!(pcc["precedence"], 50);
        assert!(!pcc["flowInfos"].as_array().unwrap().is_empty());

        // Verify QoS decisions (default + per-rule)
        assert!(dec.qos_decs.get("QosDec-test-policy-1").is_some());
        assert!(dec.qos_decs.get("QosDec-pcc-rule-1").is_some());

        // Verify chgDecs + traffContDecs exist and are referenced
        assert!(dec.chg_decs.get("ChgDec-rule-1").is_some());
        assert!(dec.traff_cont_decs.get("TcDec-rule-1").is_some());
        assert_eq!(pcc["refChgData"][0], "ChgDec-rule-1");
        assert_eq!(pcc["refTcData"][0], "TcDec-rule-1");
        assert_eq!(dec.chg_decs["ChgDec-rule-1"]["meteringMethod"], "VOLUME");

        // Verify triggers
        assert!(dec.triggers.contains(&"SE_AMBR_CH".to_string()));
        assert!(dec.triggers.contains(&"DEF_QOS_CH".to_string()));
        assert!(dec.triggers.contains(&"RES_MO_RE".to_string()));
    }

    /// pcfd-01: TS 29.512 Table 5.6.2.8-1 makes `qosId` the mandatory (P=M)
    /// identifier of a QosData object and there is no `qosDecId` attribute. The
    /// SMF keys PCC/QoS decisions by qosId, which must equal the qosDecs map
    /// key. This asserts the corrected wire field for every emitted QosData.
    #[test]
    fn test_qos_data_emits_qos_id_not_qos_dec_id() {
        let session_data = nudr_handler::SessionData {
            qos_index: 9,
            arp_priority_level: 8,
            arp_preempt_cap: false,
            arp_preempt_vuln: true,
            ambr_uplink: 100_000_000,
            ambr_downlink: 200_000_000,
            pcc_rules: vec![nudr_handler::PccRule {
                id: "rule-1".to_string(),
                precedence: 50,
                qos_index: 5,
                flow_status: npcf_handler::FlowStatus::Enabled,
                flows: vec![nudr_handler::FlowDescription {
                    direction: nudr_handler::FlowDirection::Downlink,
                    description: "permit out ip from any to assigned".to_string(),
                }],
            }],
        };

        let dec = build_sm_policy_decision("test-policy-1", &session_data);
        let qos_decs = dec.qos_decs.as_object().expect("qosDecs is an object");
        assert!(!qos_decs.is_empty(), "expected provisioned QosData entries");

        // Default QoS decision carries the expected mandatory qosId value.
        assert_eq!(
            qos_decs["QosDec-test-policy-1"]["qosId"],
            "QosDec-test-policy-1"
        );

        // Every QosData object must carry `qosId` == its map key and must NOT
        // carry the non-conformant `qosDecId` key (strict SMF would reject it).
        for (key, qos) in qos_decs {
            assert_eq!(
                qos.get("qosId").and_then(|v| v.as_str()),
                Some(key.as_str()),
                "QosData {key} must carry qosId equal to its qosDecs map key"
            );
            assert!(
                qos.get("qosDecId").is_none(),
                "QosData {key} must not carry the non-spec qosDecId key"
            );
        }
    }

    #[test]
    fn test_decision_without_subscription_rules_gets_default_rule_with_chg_tc() {
        let session_data = nudr_handler::SessionData {
            qos_index: 9,
            arp_priority_level: 8,
            arp_preempt_cap: false,
            arp_preempt_vuln: true,
            ambr_uplink: 100_000_000,
            ambr_downlink: 100_000_000,
            pcc_rules: vec![],
        };
        let dec = build_sm_policy_decision("p2", &session_data);
        let rule = &dec.pcc_rules["PccRule-default-p2"];
        assert_eq!(rule["precedence"], 255);
        assert!(dec.chg_decs.get("ChgDec-default-p2").is_some());
        assert!(dec.traff_cont_decs.get("TcDec-default-p2").is_some());
        assert_eq!(
            rule["flowInfos"][0]["flowDescription"],
            "permit out ip from any to assigned"
        );
    }

    // ----- Handler-level tests (validation, panic regression, routing) -----

    fn make_request(method: &str, uri: &str, body: Option<serde_json::Value>) -> SbiRequest {
        // Every method mapped explicitly: this used to fold PUT and PATCH into
        // POST, so a test asking for one was silently routed as the other (#88).
        let req = match method {
            "GET" => SbiRequest::get(uri),
            "DELETE" => SbiRequest::delete(uri),
            "PUT" => SbiRequest::put(uri),
            "PATCH" => SbiRequest::patch(uri),
            "POST" => SbiRequest::post(uri),
            other => panic!("make_request: unsupported method {other}"),
        };
        match body {
            Some(b) => req.with_json_body(&b).expect("encode test body"),
            None => req,
        }
    }

    fn full_create_body(supi: &str, psi: u8) -> serde_json::Value {
        serde_json::json!({
            "supi": supi,
            "pduSessionId": psi,
            "pduSessionType": "IPV4",
            "dnn": "internet",
            "notificationUri": "http://127.0.0.1:9/nsmf-callback/v1/sm-policy-notify/1",
            "ipv4Address": "10.45.0.77",
            "sliceInfo": { "sst": 1 },
            "servingNetwork": { "mcc": "001", "mnc": "01" },
            "suppFeat": "0"
        })
    }

    #[tokio::test]
    async fn sm_policy_create_missing_notification_uri_is_400() {
        pcf_context_init(64, 64);
        let mut body = full_create_body("imsi-001010000000050", 5);
        body.as_object_mut().unwrap().remove("notificationUri");
        let req = make_request("POST", "/npcf-smpolicycontrol/v1/sm-policies", Some(body));
        let resp = pcf_sbi_request_handler(req).await;
        assert_eq!(resp.status, 400);
    }

    #[tokio::test]
    async fn sm_policy_update_without_triggers_does_not_panic() {
        pcf_context_init(64, 64);
        // Create
        let req = make_request(
            "POST",
            "/npcf-smpolicycontrol/v1/sm-policies",
            Some(full_create_body("imsi-001010000000051", 6)),
        );
        let resp = pcf_sbi_request_handler(req).await;
        assert_eq!(resp.status, 201);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let pol_id = body["smPolicyId"].as_str().unwrap().to_string();
        // chgDecs / traffContDecs present in the create decision
        assert!(body["chgDecs"].as_object().is_some_and(|m| !m.is_empty()));
        assert!(body["traffContDecs"]
            .as_object()
            .is_some_and(|m| !m.is_empty()));

        // Update WITHOUT repPolicyCtrlReqTriggers (regression: .expect() panic)
        let req = make_request(
            "POST",
            &format!("/npcf-smpolicycontrol/v1/sm-policies/{pol_id}/update"),
            Some(serde_json::json!({})),
        );
        let resp = pcf_sbi_request_handler(req).await;
        assert_eq!(resp.status, 200);
    }

    #[tokio::test]
    async fn sm_policy_delete_via_post_subresource() {
        pcf_context_init(64, 64);
        let req = make_request(
            "POST",
            "/npcf-smpolicycontrol/v1/sm-policies",
            Some(full_create_body("imsi-001010000000052", 7)),
        );
        let resp = pcf_sbi_request_handler(req).await;
        assert_eq!(resp.status, 201);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let pol_id = body["smPolicyId"].as_str().unwrap().to_string();

        // TS 29.512 §4.2.5: POST /sm-policies/{id}/delete
        let req = make_request(
            "POST",
            &format!("/npcf-smpolicycontrol/v1/sm-policies/{pol_id}/delete"),
            Some(serde_json::json!({})),
        );
        let resp = pcf_sbi_request_handler(req).await;
        assert_eq!(resp.status, 204);

        // Second delete → 404 (resource gone)
        let req = make_request(
            "POST",
            &format!("/npcf-smpolicycontrol/v1/sm-policies/{pol_id}/delete"),
            Some(serde_json::json!({})),
        );
        let resp = pcf_sbi_request_handler(req).await;
        assert_eq!(resp.status, 404);
    }

    /// Full smfd↔pcfd-shaped HTTP round trip against the REAL pcfd handler
    /// served over a local ephemeral-port HTTP/2 server: SM policy
    /// create → update → delete exactly as the SMF client drives them.
    #[tokio::test]
    #[ignore = "real-HTTP SbiServer integration test: starts a real ephemeral-port HTTP/2 server, \
                which intermittently races/hangs under concurrent `cargo test --workspace` load. \
                Run explicitly: `cargo test -p nextgcore-pcfd -- --ignored`. The in-process sm_policy \
                lifecycle tests above cover the same handler logic in the default suite."]
    async fn sm_policy_lifecycle_over_real_http() {
        use nextgcore_sbi::client::{SbiClient, SbiClientConfig};
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};

        pcf_context_init(64, 64);

        // Start a real SbiServer on an ephemeral port. The probe-then-rebind
        // pattern has a small TOCTOU window and SbiServer startup can race under
        // heavy concurrent test load, so retry on a fresh port and bound each
        // attempt with a timeout — a transient bind/startup stall must never hang
        // the whole `cargo test --workspace` run (it previously could deadlock the
        // suite indefinitely while holding the shared pcf_context).
        let mut started: Option<(SbiServer, u16)> = None;
        for attempt in 0..4u32 {
            let port = nextgcore_sbi::test_support::free_port();
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let server = SbiServer::new(SbiServerConfig::new(addr));
            match tokio::time::timeout(
                Duration::from_secs(10),
                server.start(pcf_sbi_request_handler),
            )
            .await
            {
                Ok(Ok(())) => {
                    started = Some((server, port));
                    break;
                }
                Ok(Err(e)) => log::warn!("pcfd test server start attempt {attempt} failed: {e}"),
                Err(_) => log::warn!("pcfd test server start attempt {attempt} timed out"),
            }
        }
        let (server, port) = started.expect("SbiServer failed to start after 4 attempts");

        let client = SbiClient::new(
            SbiClientConfig::new("127.0.0.1", port)
                .with_connect_timeout(Duration::from_secs(2))
                .with_request_timeout(Duration::from_secs(3)),
        );

        let run = async {
            // Create (success outcome, mandatory attrs per TS 29.512)
            let resp = client
                .post_json(
                    "/npcf-smpolicycontrol/v1/sm-policies",
                    &full_create_body("imsi-001010000000060", 8),
                )
                .await
                .expect("create over HTTP");
            assert_eq!(resp.status, 201);
            let body: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            let pol_id = body["smPolicyId"].as_str().unwrap().to_string();
            assert!(body["sessRules"].as_object().is_some_and(|m| !m.is_empty()));
            assert!(body["chgDecs"].as_object().is_some_and(|m| !m.is_empty()));
            assert!(body["traffContDecs"]
                .as_object()
                .is_some_and(|m| !m.is_empty()));

            // Failure outcome: missing mandatory attribute → 400
            let mut bad = full_create_body("imsi-001010000000061", 9);
            bad.as_object_mut().unwrap().remove("dnn");
            let resp = client
                .post_json("/npcf-smpolicycontrol/v1/sm-policies", &bad)
                .await
                .expect("bad create over HTTP");
            assert_eq!(resp.status, 400);

            // Update (with triggers)
            let resp = client
                .post_json(
                    &format!("/npcf-smpolicycontrol/v1/sm-policies/{pol_id}/update"),
                    &serde_json::json!({ "repPolicyCtrlReqTriggers": ["RES_MO_RE"] }),
                )
                .await
                .expect("update over HTTP");
            assert_eq!(resp.status, 200);

            // Delete (POST sub-resource per TS 29.512 §4.2.5)
            let resp = client
                .post_json(
                    &format!("/npcf-smpolicycontrol/v1/sm-policies/{pol_id}/delete"),
                    &serde_json::json!({}),
                )
                .await
                .expect("delete over HTTP");
            assert_eq!(resp.status, 204);
        };
        tokio::time::timeout(Duration::from_secs(15), run)
            .await
            .expect("HTTP round trip timed out");

        let _ = tokio::time::timeout(Duration::from_secs(5), server.stop()).await;
    }

    #[tokio::test]
    async fn am_policy_update_via_post_subresource() {
        pcf_context_init(64, 64);
        let req = make_request(
            "POST",
            "/npcf-am-policy-control/v1/policies",
            Some(serde_json::json!({
                "supi": "imsi-001010000000053",
                "notificationUri": "http://127.0.0.1:9/namf-callback/v1/am-policy/1",
                "suppFeat": "0"
            })),
        );
        let resp = pcf_sbi_request_handler(req).await;
        assert_eq!(resp.status, 201);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let pol_id = body["polAssoId"].as_str().unwrap().to_string();

        // TS 29.507 §4.2.4: POST /policies/{polAssoId}/update
        let req = make_request(
            "POST",
            &format!("/npcf-am-policy-control/v1/policies/{pol_id}/update"),
            Some(serde_json::json!({ "triggers": ["LOC_CH"] })),
        );
        let resp = pcf_sbi_request_handler(req).await;
        assert_eq!(resp.status, 200);
    }

    /// pcfd-02: an AF app-session create carrying one audio media component
    /// installs an AF-derived PccRule on the bound PDU session and the outbound
    /// SM policy update notify body carries it; the 201 echoes suppFeat.
    #[tokio::test]
    async fn app_session_create_with_media_components_installs_pcc_rule() {
        pcf_context_init(64, 64);

        // Bind a PDU session with a known UE IP via SM policy create.
        let mut create = full_create_body("imsi-001010000000088", 11);
        create
            .as_object_mut()
            .unwrap()
            .insert("ipv4Address".to_string(), serde_json::json!("10.45.0.88"));
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-smpolicycontrol/v1/sm-policies",
            Some(create),
        ))
        .await;
        assert_eq!(resp.status, 201);

        // AF POST app-session with one audio media component.
        let af_body = serde_json::json!({
            "notifUri": "http://127.0.0.1:9/af-notif/1",
            "suppFeat": "0",
            "ueIpv4": "10.45.0.88",
            "medComponents": {
                "1": {
                    "medCompN": 1,
                    "medType": "AUDIO",
                    "marBwDl": "256 Kbps",
                    "marBwUl": "128 Kbps",
                    "fStatus": "ENABLED",
                    "medSubComps": {
                        "1": {
                            "fNum": 1,
                            "fDescs": [
                                "permit out ip from 10.45.0.88 to any",
                                "permit in ip from any to 10.45.0.88"
                            ]
                        }
                    }
                }
            }
        });
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-policyauthorization/v1/app-sessions",
            Some(af_body),
        ))
        .await;
        assert_eq!(resp.status, 201);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(body["appSessionId"].as_str().is_some());
        assert_eq!(body["suppFeat"], "0");
        assert!(body.get("ascReqData").is_some());

        // The bound session now carries the AF-derived PCC rule.
        let ctx = pcf_self();
        let sess = ctx
            .read()
            .unwrap()
            .sess_find_by_ipv4addr("10.45.0.88")
            .expect("bound PDU session");
        assert_eq!(sess.af_pcc_rules.len(), 1);
        assert_eq!(sess.af_pcc_rules[0].qos_data.five_qi, 1);
        assert_eq!(
            sess.af_pcc_rules[0].qos_data.maxbr_dl.as_deref(),
            Some("256 Kbps")
        );

        // The outbound SM policy update notify body carries the new PccRule.
        let notify = npcf_handler::build_af_sm_policy_notification(&sess);
        let pcc_rules = notify["smPolicyDecision"]["pccRules"]
            .as_object()
            .expect("pccRules object");
        assert_eq!(pcc_rules.len(), 1);
        let (_id, rule) = pcc_rules.iter().next().unwrap();
        assert_eq!(
            rule["flowInfos"][0]["flowDescription"],
            "permit out ip from 10.45.0.88 to any"
        );
        let qos_id = rule["refQosData"][0].as_str().unwrap();
        assert_eq!(
            notify["smPolicyDecision"]["qosDecs"][qos_id]["maxbrDl"],
            "256 Kbps"
        );
        assert_eq!(
            notify["smPolicyDecision"]["qosDecs"][qos_id]["qosId"],
            qos_id
        );
    }

    /// Provision a PDU session with a known UE IPv4 through the real SM policy
    /// create, so an AF request can bind to it.
    async fn provision_session_with_ipv4(supi: &str, psi: u8, ipv4: &str) {
        let mut create = full_create_body(supi, psi);
        create
            .as_object_mut()
            .unwrap()
            .insert("ipv4Address".to_string(), serde_json::json!(ipv4));
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-smpolicycontrol/v1/sm-policies",
            Some(create),
        ))
        .await;
        assert_eq!(resp.status, 201, "SM policy create for {ipv4}");
    }

    /// pcfd-02 backward-compat: an app-session create WITHOUT medComponents
    /// yields exactly the legacy body shape — bind + suppFeat echo, no
    /// ascReqData/Resp.
    ///
    /// #88 changed the SETUP, not the claim: this test used to send an unbindable
    /// `ueIpv4` and assert `201`, which pinned the fabricated-success defect
    /// (create minted a UUID, stored nothing, and answered 201). The UE IP is now
    /// bound to a real session, so the body-shape assertion — what the test is
    /// actually for — is unchanged while the fabrication is gone.
    #[tokio::test]
    async fn app_session_create_without_media_components_is_backward_compatible() {
        pcf_context_init(64, 64);
        provision_session_with_ipv4("imsi-001010000000250", 12, "10.45.0.250").await;
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-policyauthorization/v1/app-sessions",
            Some(serde_json::json!({
                "notifUri": "http://127.0.0.1:9/af-notif/2",
                "suppFeat": "0",
                "ueIpv4": "10.45.0.250"
            })),
        ))
        .await;
        assert_eq!(resp.status, 201);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let obj = body.as_object().unwrap();
        // Exactly the legacy shape: appSessionId, notifUri, suppFeat.
        assert_eq!(obj.len(), 3);
        assert!(obj.contains_key("appSessionId"));
        assert_eq!(obj["notifUri"], "http://127.0.0.1:9/af-notif/2");
        assert_eq!(obj["suppFeat"], "0");
        assert!(!obj.contains_key("ascReqData"));
        assert!(!obj.contains_key("ascRespData"));
    }

    /// pcfd-02: an emergency AF request (dnn=sos) yields ascRespData in the 201.
    ///
    /// #88 added the `ueIpv4` and its bound session: TS 29.514 Table 5.7.3-1
    /// requires one of the UE-address oneOf on EVERY create, emergency included,
    /// so the original body was non-conformant and only passed because nothing
    /// validated it. The ascRespData claim is untouched.
    #[tokio::test]
    async fn app_session_create_emergency_emits_asc_resp_data() {
        pcf_context_init(64, 64);
        provision_session_with_ipv4("imsi-001010000000251", 13, "10.45.0.251").await;
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-policyauthorization/v1/app-sessions",
            Some(serde_json::json!({
                "notifUri": "http://127.0.0.1:9/af-notif/3",
                "suppFeat": "0",
                "ueIpv4": "10.45.0.251",
                "dnn": "sos",
                "medComponents": {
                    "1": {
                        "medCompN": 1,
                        "medType": "AUDIO",
                        "marBwDl": "64 Kbps",
                        "marBwUl": "64 Kbps",
                        "fStatus": "ENABLED",
                        "medSubComps": {
                            "1": { "fNum": 1, "fDescs": ["permit out ip from any to assigned"] }
                        }
                    }
                }
            })),
        ))
        .await;
        assert_eq!(resp.status, 201);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(body.get("ascRespData").is_some());
        assert_eq!(body["ascRespData"]["suppFeat"], "0");
        assert_eq!(body["ascRespData"]["servAuthInfo"], "NOT_KNOWN");
    }

    /// pcfd-05: feature negotiation is `intersection(consumer, producer)` as a
    /// lowercase hex string (TS 29.571 §5.2.2); a missing/empty/invalid consumer
    /// value negotiates to "0", never an error.
    #[test]
    fn test_negotiate_features() {
        assert_eq!(negotiate_features(Some("3"), 0x1), "1");
        assert_eq!(negotiate_features(None, 0x1), "0");
        assert_eq!(negotiate_features(Some(""), 0x3), "0");
        assert_eq!(negotiate_features(Some("ffff"), 0x3), "3");
        assert_eq!(negotiate_features(Some("not-hex"), 0x3), "0");
        // Empty-string consumer (the matched AMF sends suppFeat="") → "0".
        assert_eq!(
            negotiate_features(Some(""), PCF_AM_POLICY_SUPPORTED_FEATURES),
            "0"
        );
    }

    /// pcfd-08: AM policy create rejects (400 MANDATORY_IE_MISSING) when `supi`
    /// is absent — it must never synthesize a SUPI.
    #[tokio::test]
    async fn am_policy_create_missing_supi_is_400() {
        pcf_context_init(64, 64);
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-am-policy-control/v1/policies",
            Some(serde_json::json!({
                "notificationUri": "http://127.0.0.1:9/namf-callback/v1/am-policy/9",
                "suppFeat": "0"
            })),
        ))
        .await;
        assert_eq!(resp.status, 400);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "MANDATORY_IE_MISSING");
    }

    /// pcfd-08 / pcfd-05: a full AM policy create (all mandatory IEs, including
    /// the matched-AMF's empty `suppFeat`) succeeds and the 201 always carries a
    /// negotiated `suppFeat` (mandatory per TS 29.507 §5.8).
    #[tokio::test]
    async fn am_policy_create_includes_negotiated_supp_feat() {
        pcf_context_init(64, 64);
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-am-policy-control/v1/policies",
            Some(serde_json::json!({
                "supi": "imsi-001010000000201",
                "notificationUri": "http://127.0.0.1:9/namf-callback/v1/am-policy/2",
                "servingPlmn": { "mcc": "001", "mnc": "01" },
                // The matched AMF sends an empty suppFeat — must be accepted.
                "suppFeat": ""
            })),
        ))
        .await;
        assert_eq!(resp.status, 201);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["supi"], "imsi-001010000000201");
        // suppFeat is mandatory and present even when negotiation yields nothing.
        assert_eq!(body["suppFeat"], "0");
    }

    /// pcfd-05: SM policy create returns the negotiated (AND) suppFeat, not an
    /// echo of the SMF-requested value.
    #[tokio::test]
    async fn sm_policy_create_negotiates_supp_feat_not_echo() {
        pcf_context_init(64, 64);
        let mut body = full_create_body("imsi-001010000000202", 12);
        // Consumer requests every bit; producer supports only PCF_SM mask.
        body.as_object_mut()
            .unwrap()
            .insert("suppFeat".to_string(), serde_json::json!("ffffffff"));
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-smpolicycontrol/v1/sm-policies",
            Some(body),
        ))
        .await;
        assert_eq!(resp.status, 201);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        // Negotiated = ffffffff & PCF_SM_POLICY_SUPPORTED_FEATURES, not the echo.
        assert_eq!(
            body["suppFeat"],
            format!("{:x}", PCF_SM_POLICY_SUPPORTED_FEATURES)
        );
        assert_ne!(body["suppFeat"], "ffffffff");
    }

    /// pcfd-06: the SessionRule conveys the default QoS inline via `authDefQos`
    /// and carries no non-conformant `defQosRef` (TS 29.512 Table 5.6.2.7-1).
    #[test]
    fn test_session_rule_has_no_def_qos_ref() {
        let session_data = nudr_handler::SessionData {
            qos_index: 9,
            arp_priority_level: 8,
            arp_preempt_cap: false,
            arp_preempt_vuln: true,
            ambr_uplink: 100_000_000,
            ambr_downlink: 100_000_000,
            pcc_rules: vec![],
        };
        let dec = build_sm_policy_decision("p-defqos", &session_data);
        let sr = &dec.sess_rules["SessRule-p-defqos"];
        assert!(sr.get("authDefQos").is_some());
        assert!(
            sr.get("defQosRef").is_none(),
            "SessionRule must not carry defQosRef"
        );
    }

    /// pcfd-07: every provisioned QosData carries an `arp` object with the three
    /// sub-fields (TS 29.512 §5.6.2.8 — ARP is C on initial provisioning).
    #[test]
    fn test_qos_data_includes_arp() {
        let session_data = nudr_handler::SessionData {
            qos_index: 9,
            arp_priority_level: 8,
            arp_preempt_cap: true,
            arp_preempt_vuln: false,
            ambr_uplink: 100_000_000,
            ambr_downlink: 100_000_000,
            pcc_rules: vec![nudr_handler::PccRule {
                id: "rule-1".to_string(),
                precedence: 50,
                qos_index: 5,
                flow_status: npcf_handler::FlowStatus::Enabled,
                flows: vec![],
            }],
        };
        let dec = build_sm_policy_decision("p-arp", &session_data);
        let qos_decs = dec.qos_decs.as_object().unwrap();
        assert!(!qos_decs.is_empty());
        for (key, qos) in qos_decs {
            let arp = qos
                .get("arp")
                .unwrap_or_else(|| panic!("QosData {key} missing arp"));
            assert!(
                arp.get("priorityLevel").is_some(),
                "{key} arp.priorityLevel"
            );
            assert!(arp.get("preemptCap").is_some(), "{key} arp.preemptCap");
            assert!(arp.get("preemptVuln").is_some(), "{key} arp.preemptVuln");
        }
        // Default QoS ARP reflects the session data (preemptCap=true).
        assert_eq!(qos_decs["QosDec-p-arp"]["arp"]["preemptCap"], "MAY_PREEMPT");
        assert_eq!(
            qos_decs["QosDec-p-arp"]["arp"]["preemptVuln"],
            "NOT_PREEMPTABLE"
        );
    }

    /// pcfd-12: triggers are derived from the decision contents — a default-only
    /// session yields the base subset (no RES_MO_RE / QOS_NOTIF); a session with
    /// a GBR PCC rule adds QOS_NOTIF (and RES_MO_RE for the installed rule).
    #[test]
    fn test_triggers_derived_from_decision() {
        // Default-only session: no subscription PCC rules.
        let default_only = nudr_handler::SessionData {
            qos_index: 9,
            arp_priority_level: 8,
            arp_preempt_cap: false,
            arp_preempt_vuln: true,
            ambr_uplink: 100_000_000,
            ambr_downlink: 100_000_000,
            pcc_rules: vec![],
        };
        let dec = build_sm_policy_decision("p-trig-1", &default_only);
        assert!(dec.triggers.contains(&"SE_AMBR_CH".to_string()));
        assert!(dec.triggers.contains(&"DEF_QOS_CH".to_string()));
        assert!(!dec.triggers.contains(&"RES_MO_RE".to_string()));
        assert!(!dec.triggers.contains(&"QOS_NOTIF".to_string()));

        // Session with a GBR PCC rule (5QI 1 is GBR).
        let gbr = nudr_handler::SessionData {
            pcc_rules: vec![nudr_handler::PccRule {
                id: "gbr-rule".to_string(),
                precedence: 10,
                qos_index: 1,
                flow_status: npcf_handler::FlowStatus::Enabled,
                flows: vec![],
            }],
            ..default_only
        };
        let dec = build_sm_policy_decision("p-trig-2", &gbr);
        assert!(dec.triggers.contains(&"RES_MO_RE".to_string()));
        assert!(dec.triggers.contains(&"QOS_NOTIF".to_string()));
    }

    /// pcfd#0: full Npcf_UEPolicyControl lifecycle (TS 29.525).
    #[tokio::test]
    async fn ue_policy_create_get_update_delete_lifecycle() {
        pcf_context_init(64, 64);
        // Missing mandatory suppFeat -> 400
        let bad = serde_json::json!({
            "notificationUri": "http://127.0.0.1:9/namf-callback/v1/ue-policy/1",
            "supi": "imsi-001010000000070"
        });
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-ue-policy-control/v1/policies",
            Some(bad),
        ))
        .await;
        assert_eq!(resp.status, 400);

        // Create -> 201 + Location + PolicyAssociation (suppFeat mandatory, triggers minItems1)
        let ok = serde_json::json!({
            "notificationUri": "http://127.0.0.1:9/namf-callback/v1/ue-policy/1",
            "supi": "imsi-001010000000070",
            "suppFeat": "0"
        });
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-ue-policy-control/v1/policies",
            Some(ok),
        ))
        .await;
        assert_eq!(resp.status, 201);
        let loc = resp.http.get_header("location").expect("Location").clone();
        assert!(loc.starts_with("/npcf-ue-policy-control/v1/policies/"));
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["suppFeat"], "0");
        assert!(body["triggers"].as_array().is_some_and(|a| !a.is_empty()));
        // Wave-6 E4: the URSP travels on the N1 wire (MANAGE UE POLICY COMMAND),
        // NOT as a bespoke `uePolicy` JSON field — the spec-shaped body is
        // unchanged (that octet string is the EpsUrsp path only).
        assert!(body.get("uePolicy").is_none());
        let pol_id = loc.rsplit('/').next().unwrap().to_string();

        // Wave-6 E4: a delivery task was spawned (delivery on by default). With
        // no AMF reachable in this unit test it must resolve to `Failed`
        // (fail-closed) — never a fake `Delivered`, and the association still
        // exists (the 201 is not blocked on delivery).
        let assoc = ue_policy::ue_policy_find(&pol_id).expect("association stored");
        assert!(
            (0x80..=0xFE).contains(&assoc.pti),
            "PTI {:#04x} must be in the PCF range 80H-FEH (TS 24.501 D.1.2)",
            assoc.pti
        );
        assert!(
            !assoc.rules.is_empty(),
            "default URSP rule set is non-empty"
        );
        let mut waited = 0;
        loop {
            match ue_policy::ue_policy_find(&pol_id).map(|a| a.delivery_state) {
                Some(ue_policy::DeliveryState::Failed(_)) => break,
                _ if waited >= 100 => {
                    panic!("delivery did not reach Failed within 10s (no AMF configured)")
                }
                _ => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    waited += 1;
                }
            }
        }

        // GET -> 200
        let resp = pcf_sbi_request_handler(make_request(
            "GET",
            &format!("/npcf-ue-policy-control/v1/policies/{pol_id}"),
            None,
        ))
        .await;
        assert_eq!(resp.status, 200);

        // Update -> 200 PolicyUpdate
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            &format!("/npcf-ue-policy-control/v1/policies/{pol_id}/update"),
            Some(serde_json::json!({"triggers": ["UE_POLICY"]})),
        ))
        .await;
        assert_eq!(resp.status, 200);

        // DELETE -> 204, then 404
        let resp = pcf_sbi_request_handler(make_request(
            "DELETE",
            &format!("/npcf-ue-policy-control/v1/policies/{pol_id}"),
            None,
        ))
        .await;
        assert_eq!(resp.status, 204);
        let resp = pcf_sbi_request_handler(make_request(
            "DELETE",
            &format!("/npcf-ue-policy-control/v1/policies/{pol_id}"),
            None,
        ))
        .await;
        assert_eq!(resp.status, 404);
    }

    /// pcfd-11: GET on an individual SM policy returns the stored
    /// SmPolicyDecision (non-empty rule maps), not empty placeholders.
    ///
    /// #89 moved the decision under the `policy` member: TS 29.512 §5.3 makes the
    /// resource an `SmPolicyControl{context, policy}`, so the flat body this test
    /// used to read was the wrong envelope. The claim — non-empty rule maps — is
    /// unchanged.
    #[tokio::test]
    async fn sm_policy_get_returns_stored_decision() {
        pcf_context_init(64, 64);
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-smpolicycontrol/v1/sm-policies",
            Some(full_create_body("imsi-001010000000203", 13)),
        ))
        .await;
        assert_eq!(resp.status, 201);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let pol_id = body["smPolicyId"].as_str().unwrap().to_string();

        let resp = pcf_sbi_request_handler(make_request(
            "GET",
            &format!("/npcf-smpolicycontrol/v1/sm-policies/{pol_id}"),
            None,
        ))
        .await;
        assert_eq!(resp.status, 200);
        let got: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(
            got["policy"]["sessRules"]
                .as_object()
                .is_some_and(|m| !m.is_empty()),
            "GET must return non-empty sessRules"
        );
        assert!(
            got["policy"]["pccRules"]
                .as_object()
                .is_some_and(|m| !m.is_empty()),
            "GET must return non-empty pccRules"
        );
        assert!(got["policy"]["qosDecs"]
            .as_object()
            .is_some_and(|m| !m.is_empty()));
    }

    // ========================================================================
    // #89: AM/SM policy control — provisioned policy, PolicyUpdate, reliable
    // notification, the SmPolicyControl envelope.
    // ========================================================================

    /// Start a mock NRF+UDR on one port: the NRF SearchResult points back at
    /// itself, and the UDR leg serves the AM subscription data an association's
    /// policy is provisioned from.
    async fn start_mock_nrf_udr_am_data(
        am_data: serde_json::Value,
    ) -> nextgcore_sbi::server::SbiServer {
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let port = nextgcore_sbi::test_support::free_port();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let server = SbiServer::new(SbiServerConfig::new(addr));
        let handler = move |req: SbiRequest| {
            let am_data = am_data.clone();
            async move {
                let path = req.header.uri.split('?').next().unwrap_or("").to_string();
                if path == "/nnrf-disc/v1/nf-instances" {
                    return SbiResponse::with_status(200)
                        .with_json_body(&serde_json::json!({
                            "nfInstances": [{
                                "nfInstanceId": "udr-mock",
                                "nfType": "UDR",
                                "ipv4Addresses": ["127.0.0.1"],
                                "nfServices": [{
                                    "serviceName": "nudr-dr",
                                    "scheme": "http",
                                    "ipEndPoints": [{ "ipv4Address": "127.0.0.1", "port": port }]
                                }]
                            }]
                        }))
                        .unwrap_or_else(|_| SbiResponse::with_status(500));
                }
                if path.ends_with("/provisioned-data/am-data") {
                    return SbiResponse::with_status(200)
                        .with_json_body(&am_data)
                        .unwrap_or_else(|_| SbiResponse::with_status(500));
                }
                SbiResponse::with_status(404)
            }
        };
        server.start(handler).await.expect("mock NRF/UDR starts");
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        nextgcore_sbi::context::global_context()
            .set_nrf_uri(format!("http://127.0.0.1:{port}"))
            .await;
        server
    }

    // ====================================================================
    // #299: a policy-data change reaches a live SM policy association
    // ====================================================================

    /// A mock NRF+UDR whose `sm-data` leg answers per-`snssai` query, plus a captured
    /// stub SMF for the `SmPolicyUpdateNotify`.
    ///
    /// One port for the NRF and the UDR (the SearchResult points back at itself), a
    /// second for the SMF, so a test can assert both that the PCF re-read the right
    /// slice and that it notified the right session.
    struct PolicyDataPeers {
        udr: nextgcore_sbi::server::SbiServer,
        smf: nextgcore_sbi::server::SbiServer,
        smf_port: u16,
        /// Every SM policy notification the stub SMF received: (path, body).
        notified: std::sync::Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>>,
        /// Every UDR sm-data GET, with its raw query, so a test can prove the re-read
        /// was scoped rather than blanket.
        udr_queries: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    /// `sm_data_for` maps the `snssai` query value to the body to answer with; a slice
    /// it does not name gets a 404, which is how "unchanged for that slice" is expressed.
    async fn start_policy_data_peers(
        sm_data_for: std::collections::HashMap<String, serde_json::Value>,
    ) -> PolicyDataPeers {
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);

        let notified = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let smf_port = nextgcore_sbi::test_support::free_port();
        let smf_addr = SocketAddr::from(([127, 0, 0, 1], smf_port));
        let smf = SbiServer::new(SbiServerConfig::new(smf_addr));
        let seen = notified.clone();
        smf.start(move |req: SbiRequest| {
            let seen = seen.clone();
            async move {
                let path = req.header.uri.split('?').next().unwrap_or("").to_string();
                let body = req
                    .http
                    .content
                    .as_deref()
                    .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
                    .unwrap_or(serde_json::Value::Null);
                seen.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((path, body));
                SbiResponse::with_status(204)
            }
        })
        .await
        .expect("stub SMF starts");

        let udr_queries = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let udr_port = nextgcore_sbi::test_support::free_port();
        let udr_addr = SocketAddr::from(([127, 0, 0, 1], udr_port));
        let udr = SbiServer::new(SbiServerConfig::new(udr_addr));
        let queries = udr_queries.clone();
        udr.start(move |req: SbiRequest| {
            let sm_data_for = sm_data_for.clone();
            let queries = queries.clone();
            async move {
                let uri = req.header.uri.clone();
                let path = uri.split('?').next().unwrap_or("").to_string();
                if path == "/nnrf-disc/v1/nf-instances" {
                    return SbiResponse::with_status(200)
                        .with_json_body(&serde_json::json!({
                            "nfInstances": [{
                                "nfInstanceId": "udr-mock",
                                "nfType": "UDR",
                                "ipv4Addresses": ["127.0.0.1"],
                                "nfServices": [{
                                    "serviceName": "nudr-dr",
                                    "scheme": "http",
                                    "ipEndPoints": [{ "ipv4Address": "127.0.0.1", "port": udr_port }]
                                }]
                            }]
                        }))
                        .unwrap_or_else(|_| SbiResponse::with_status(500));
                }
                if path.starts_with("/nudr-dr/v2/policy-data/") && path.ends_with("/sm-data") {
                    // The server decodes query values into `http.params`, so the JSON
                    // `snssai` arrives already decoded -- reading it off `header.uri`
                    // finds nothing, which is how the first draft of this mock made a
                    // correctly scoped re-read look unscoped.
                    let snssai = req.http.params.get("snssai").cloned().unwrap_or_default();
                    queries
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(snssai.clone());
                    let key = sm_data_for
                        .keys()
                        .find(|k| snssai.contains(k.as_str()))
                        .cloned();
                    return match key.and_then(|k| sm_data_for.get(&k).cloned()) {
                        Some(body) => SbiResponse::with_status(200)
                            .with_json_body(&body)
                            .unwrap_or_else(|_| SbiResponse::with_status(500)),
                        None => SbiResponse::with_status(404),
                    };
                }
                SbiResponse::with_status(404)
            }
        })
        .await
        .expect("mock NRF/UDR starts");

        for addr in [udr_addr, smf_addr] {
            for _ in 0..200 {
                if tokio::net::TcpStream::connect(addr).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        nextgcore_sbi::context::global_context()
            .set_nrf_uri(format!("http://127.0.0.1:{udr_port}"))
            .await;

        PolicyDataPeers {
            udr,
            smf,
            smf_port,
            notified,
            udr_queries,
        }
    }

    /// An `smPolicySnssaiData` body carrying one DNN entry with the charging flags this
    /// PCF maps (TS 29.519 SmPolicyDnnData).
    fn sm_policy_body(sst: u8, dnn: &str, online: bool, offline: bool) -> serde_json::Value {
        serde_json::json!({
            "smPolicySnssaiData": {
                format!("{sst:02}"): {
                    "snssai": { "sst": sst },
                    "smPolicyDnnData": {
                        dnn: { "dnn": dnn, "online": online, "offline": offline }
                    }
                }
            }
        })
    }

    /// Seed a live SM policy association whose notification URI points at the stub SMF.
    fn seed_sm_policy_session(
        supi: &str,
        psi: u8,
        sst: u8,
        dnn: &str,
        smf_port: u16,
        stored: Option<serde_json::Value>,
    ) -> String {
        let ctx = pcf_self();
        let guard = ctx.read().expect("context");
        // REUSE the UE-SM when this SUPI already has one: `ue_sm_add` always inserts a
        // fresh record and overwrites `supi_sm_hash`, so calling it twice for one SUPI
        // orphans the first and `ue_sm_find_by_supi` then sees only the second session.
        // Two PDU sessions of ONE UE is exactly what the multi-slice test needs.
        let ue_sm = match guard.ue_sm_find_by_supi(supi) {
            Some(existing) => existing,
            None => guard.ue_sm_add(supi).expect("ue_sm"),
        };
        let mut sess = guard.sess_add(ue_sm.id, psi).expect("sess");
        sess.dnn = Some(dnn.to_string());
        sess.s_nssai = SNssai { sst, sd: None };
        sess.notification_uri = Some(format!(
            "http://127.0.0.1:{smf_port}/nsmf-callback/v1/sm-policy-notify/{psi}"
        ));
        sess.policy_dnn_data = stored;
        guard.sess_update(&sess);
        sess.sm_policy_id.clone()
    }

    /// Every notification received by the stub SMF, after giving the detached POST a
    /// bounded chance to arrive (`spawn_notification` is fire-and-forget).
    async fn drain_notifications(
        peers: &PolicyDataPeers,
        expected: usize,
    ) -> Vec<(String, serde_json::Value)> {
        for _ in 0..200 {
            let got = peers
                .notified
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            if got.len() >= expected {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        peers
            .notified
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// #299 criterion 1: the URI the subscription advertises is one this router serves.
    ///
    /// The ordering constraint the issue names ("the handler ships before the subscribe,
    /// or the subscription notifies into a 404") is not a timing property that a unit
    /// test can observe — but the failure it protects against is: a subscription naming
    /// a path nothing serves. So the guard feeds the advertised URI's own path back
    /// through the real router and refuses a 404/405.
    #[tokio::test]
    async fn the_advertised_policy_data_callback_is_a_path_this_pcf_serves() {
        let body = sbi_path::policy_data_subscription_body("http://10.0.0.1:7777/x");
        assert_eq!(
            body["monitoredResourceUris"],
            serde_json::json!(["/nudr-dr/v2/policy-data/ues"]),
            "the PCF cannot enumerate its future subscribers, so it monitors the collection"
        );

        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            sbi_path::POLICY_DATA_NOTIFY_PATH,
            Some(serde_json::json!({ "ueId": "imsi-001010000000299" })),
        ))
        .await;
        assert_ne!(
            resp.status, 404,
            "the advertised callback path must be routed, or the UDR notifies into a 404"
        );
        assert_ne!(resp.status, 405, "and with the method it is advertised for");
        assert_eq!(
            resp.status, 204,
            "an unknown SUPI is not an error: there is simply nothing to re-authorise"
        );

        // A notification with no ueId cannot be acted on and says so, rather than being
        // indistinguishable from one that changed nothing.
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            sbi_path::POLICY_DATA_NOTIFY_PATH,
            Some(serde_json::json!({ "reportId": "x" })),
        ))
        .await;
        assert_eq!(resp.status, 400);
    }

    /// #299 criteria 2 and 3: a policy-data change re-authorises the live association
    /// over the wire, and the notification CARRIES the changed decision.
    ///
    /// The second half is the one that matters: `build_sm_policy_notification` rebuilt
    /// `chgDecs` from the local default and dropped the UDR's charging flags, so before
    /// this the notify would have been sent and changed nothing — a wired mechanism with
    /// no effect, which is the shape this backlog keeps finding.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize the process-global NRF URI / PCF context
    async fn a_policy_data_change_reauthorises_the_live_association_with_the_new_decision() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pcf_context_init(64, 64);
        let supi = "imsi-001010000000299";

        // The UDR now says online charging is ON for slice 1 / internet.
        let mut answers = std::collections::HashMap::new();
        answers.insert(
            "\"sst\":1".to_string(),
            sm_policy_body(1, "internet", true, false),
        );
        let peers = start_policy_data_peers(answers).await;

        // The session was created when the UDR said OFF, and that is what it holds.
        let sm_policy_id = seed_sm_policy_session(
            supi,
            5,
            1,
            "internet",
            peers.smf_port,
            Some(serde_json::json!({ "dnn": "internet", "online": false, "offline": false })),
        );

        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            sbi_path::POLICY_DATA_NOTIFY_PATH,
            Some(serde_json::json!({
                "ueId": supi,
                "reportId": format!("/nudr-dr/v2/policy-data/ues/{supi}/sm-data"),
            })),
        ))
        .await;
        assert_eq!(resp.status, 204);

        let got = drain_notifications(&peers, 1).await;
        assert_eq!(
            got.len(),
            1,
            "the live association must be re-authorised toward its SMF, got {got:?}"
        );
        let (path, body) = &got[0];
        assert_eq!(
            path, "/nsmf-callback/v1/sm-policy-notify/5/update",
            "TS 29.512 §4.2.3.2 POSTs to {{notificationUri}}/update"
        );
        assert_eq!(
            body["resourceUri"],
            serde_json::json!(format!(
                "/npcf-smpolicycontrol/v1/sm-policies/{sm_policy_id}"
            )),
            "and names the association it re-authorises"
        );
        let chg = body["smPolicyDecision"]["chgDecs"]
            .as_object()
            .expect("chgDecs present");
        assert!(
            !chg.is_empty(),
            "a decision with no chgDecs carries nothing"
        );
        for (_id, dec) in chg {
            assert_eq!(
                dec["online"],
                serde_json::json!(true),
                "the UDR's changed online flag must reach the SMF, or the notify is a \
                 re-authorisation that authorises the OLD decision: {body}"
            );
        }

        // And the session now holds what the UDR says, so a second notification for the
        // same (unchanged) data does not re-notify.
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            sbi_path::POLICY_DATA_NOTIFY_PATH,
            Some(serde_json::json!({ "ueId": supi })),
        ))
        .await;
        assert_eq!(resp.status, 204);
        let got = drain_notifications(&peers, 2).await;
        assert_eq!(
            got.len(),
            1,
            "an edit that changes nothing this PCF maps must not re-authorise: at scale \
             that is every session of every UE per UDR write"
        );

        peers.udr.stop().await.ok();
        peers.smf.stop().await.ok();
    }

    /// #299: the create path STORES the UDR's SmPolicyDnnData, so the first policy-data
    /// notification for an unchanged subscriber is not a spurious re-authorisation — and
    /// so a later re-authorisation can carry what the create carried.
    ///
    /// Driven through the real `handle_sm_policy_create` rather than by seeding, because
    /// seeding is what hides the hole: the field would look populated in every test while
    /// no production path ever wrote it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize the process-global NRF URI / PCF context
    async fn the_create_stores_the_udrs_policy_data_so_an_unchanged_edit_is_not_a_reauthorisation()
    {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pcf_context_init(64, 64);
        let supi = "imsi-001010000000296";

        let mut answers = std::collections::HashMap::new();
        answers.insert(
            "\"sst\":1".to_string(),
            sm_policy_body(1, "internet", true, false),
        );
        let peers = start_policy_data_peers(answers).await;

        let create = serde_json::json!({
            "supi": supi,
            "pduSessionId": 9,
            "pduSessionType": "IPV4",
            "dnn": "internet",
            "notificationUri": format!(
                "http://127.0.0.1:{}/nsmf-callback/v1/sm-policy-notify/9", peers.smf_port),
            "sliceInfo": { "sst": 1 },
        });
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-smpolicycontrol/v1/sm-policies",
            Some(create),
        ))
        .await;
        assert_eq!(resp.status, 201, "create: {:?}", resp.http.content);

        // The decision the SMF got on create carries the UDR's flags...
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        for (_id, dec) in body["chgDecs"].as_object().expect("chgDecs") {
            assert_eq!(dec["online"], serde_json::json!(true), "create: {body}");
        }

        // ...and the session HOLDS the resource that produced them.
        let held = pcf_self()
            .read()
            .ok()
            .and_then(|c| c.ue_sm_find_by_supi(supi))
            .and_then(|u| u.sess_ids.first().copied())
            .and_then(|id| pcf_self().read().ok().and_then(|c| c.sess_find_by_id(id)))
            .expect("session");
        assert_eq!(
            held.policy_dnn_data
                .as_ref()
                .and_then(|d| d.get("online"))
                .and_then(|v| v.as_bool()),
            Some(true),
            "the create read this resource and used to DISCARD it, so every later notify \
             rebuilt the decision without it: {:?}",
            held.policy_dnn_data
        );

        // A notification for data that has not changed therefore re-authorises nothing.
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            sbi_path::POLICY_DATA_NOTIFY_PATH,
            Some(serde_json::json!({ "ueId": supi })),
        ))
        .await;
        assert_eq!(resp.status, 204);
        let got = drain_notifications(&peers, 1).await;
        assert!(
            got.is_empty(),
            "nothing changed, so nothing is re-authorised: {got:?}"
        );

        peers.udr.stop().await.ok();
        peers.smf.stop().await.ok();
    }

    /// #299: a UDR that is discoverable but whose read FAILS leaves the session alone.
    ///
    /// Distinct from "no UDR" (the criterion-5 test): here discovery succeeds and the GET
    /// does not. Treating the failure as "nothing is provisioned" would erase the
    /// session's stored policy data and re-authorise it with the local default — a
    /// transient error silently reverting a subscriber's charging mode.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize the process-global NRF URI / PCF context
    async fn a_failed_udr_read_leaves_the_association_authorised_as_it_was() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pcf_context_init(64, 64);
        let supi = "imsi-001010000000295";

        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        // An NRF that advertises a UDR on a port with nothing listening: discovery
        // succeeds, every nudr-dr GET fails.
        let dead_udr_port = nextgcore_sbi::test_support::free_port();
        let nrf_port = nextgcore_sbi::test_support::free_port();
        let nrf_addr = SocketAddr::from(([127, 0, 0, 1], nrf_port));
        let nrf = SbiServer::new(SbiServerConfig::new(nrf_addr));
        nrf.start(move |_req: SbiRequest| async move {
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "nfInstances": [{
                        "nfInstanceId": "udr-dead",
                        "nfType": "UDR",
                        "ipv4Addresses": ["127.0.0.1"],
                        "nfServices": [{
                            "serviceName": "nudr-dr",
                            "scheme": "http",
                            "ipEndPoints": [{ "ipv4Address": "127.0.0.1", "port": dead_udr_port }]
                        }]
                    }]
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(500))
        })
        .await
        .expect("mock NRF starts");
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(nrf_addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        nextgcore_sbi::context::global_context()
            .set_nrf_uri(format!("http://127.0.0.1:{nrf_port}"))
            .await;

        let peers = start_policy_data_peers(std::collections::HashMap::new()).await;
        // `start_policy_data_peers` points the NRF URI at its own mock; put it back at
        // the one advertising the dead UDR.
        nextgcore_sbi::context::global_context()
            .set_nrf_uri(format!("http://127.0.0.1:{nrf_port}"))
            .await;

        let stored = serde_json::json!({ "dnn": "internet", "online": true, "offline": false });
        seed_sm_policy_session(supi, 3, 1, "internet", peers.smf_port, Some(stored.clone()));

        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            sbi_path::POLICY_DATA_NOTIFY_PATH,
            Some(serde_json::json!({ "ueId": supi })),
        ))
        .await;
        assert_eq!(resp.status, 204);

        let got = drain_notifications(&peers, 1).await;
        assert!(
            got.is_empty(),
            "a failed re-read must not produce a re-authorisation: {got:?}"
        );
        let held = pcf_self()
            .read()
            .ok()
            .and_then(|c| c.ue_sm_find_by_supi(supi))
            .and_then(|u| u.sess_ids.first().copied())
            .and_then(|id| pcf_self().read().ok().and_then(|c| c.sess_find_by_id(id)))
            .expect("session");
        assert_eq!(
            held.policy_dnn_data,
            Some(stored),
            "and must not erase what the session holds"
        );

        nrf.stop().await.ok();
        peers.udr.stop().await.ok();
        peers.smf.stop().await.ok();
    }

    /// #299 criterion 4: the affected-association lookup is scoped, so a change for one
    /// slice does not re-authorise another slice's session.
    ///
    /// Both sessions belong to ONE SUPI, which is what makes an unscoped selection look
    /// correct: the notification names only `ueId`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize the process-global NRF URI / PCF context
    async fn a_change_for_one_slice_does_not_reauthorise_another_slices_session() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pcf_context_init(64, 64);
        let supi = "imsi-001010000000298";

        // Only slice 2's data is provisioned/changed; slice 1's read 404s, which is
        // "nothing provisioned for that slice" and must leave it alone.
        let mut answers = std::collections::HashMap::new();
        answers.insert(
            "\"sst\":2".to_string(),
            sm_policy_body(2, "internet", true, false),
        );
        let peers = start_policy_data_peers(answers).await;

        seed_sm_policy_session(supi, 1, 1, "internet", peers.smf_port, None);
        seed_sm_policy_session(
            supi,
            2,
            2,
            "internet",
            peers.smf_port,
            Some(serde_json::json!({ "dnn": "internet", "online": false, "offline": false })),
        );

        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            sbi_path::POLICY_DATA_NOTIFY_PATH,
            Some(serde_json::json!({ "ueId": supi })),
        ))
        .await;
        assert_eq!(resp.status, 204);

        let got = drain_notifications(&peers, 1).await;
        assert_eq!(
            got.len(),
            1,
            "exactly the session whose slice data changed is re-authorised, got {got:?}"
        );
        assert_eq!(
            got[0].0, "/nsmf-callback/v1/sm-policy-notify/2/update",
            "and it is slice 2's session (psi=2), not slice 1's"
        );

        // The re-read itself was scoped: each session's own S-NSSAI appears in its query.
        let queries = peers
            .udr_queries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert!(
            queries.iter().any(|q| q.contains("\"sst\":1")),
            "slice 1's session must be evaluated against SLICE 1's data: {queries:?}"
        );
        assert!(
            queries.iter().any(|q| q.contains("\"sst\":2")),
            "and slice 2's against slice 2's: {queries:?}"
        );

        peers.udr.stop().await.ok();
        peers.smf.stop().await.ok();
    }

    /// #299 criterion 5: with no UDR configured or discoverable, the PCF behaves exactly
    /// as it did before — the notification is accepted and nothing is re-authorised,
    /// because there is nothing to re-read the decision from.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize the process-global NRF URI / PCF context
    async fn with_no_udr_a_policy_data_notification_changes_nothing() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pcf_context_init(64, 64);
        let supi = "imsi-001010000000297";

        // A stub SMF only: no NRF URI is set, so discovery yields nothing.
        let peers = start_policy_data_peers(std::collections::HashMap::new()).await;
        nextgcore_sbi::context::global_context()
            .set_nrf_uri(String::new())
            .await;

        let stored = serde_json::json!({ "dnn": "internet", "online": true, "offline": false });
        seed_sm_policy_session(supi, 7, 1, "internet", peers.smf_port, Some(stored.clone()));

        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            sbi_path::POLICY_DATA_NOTIFY_PATH,
            Some(serde_json::json!({ "ueId": supi })),
        ))
        .await;
        assert_eq!(resp.status, 204);

        let got = drain_notifications(&peers, 1).await;
        assert!(
            got.is_empty(),
            "with no UDR there is no new decision to send, and sending the old one as a \
             re-authorisation would be worse than silence: {got:?}"
        );
        let held = pcf_self()
            .read()
            .ok()
            .and_then(|c| c.ue_sm_find_by_supi(supi))
            .and_then(|u| u.sess_ids.first().copied())
            .and_then(|id| pcf_self().read().ok().and_then(|c| c.sess_find_by_id(id)))
            .expect("session");
        assert_eq!(
            held.policy_dnn_data,
            Some(stored),
            "and an unreachable UDR must NOT erase what the session already holds: a \
             404-or-unreachable read returns None, and storing that would revert the \
             subscriber's charging mode on every failed notification"
        );

        peers.udr.stop().await.ok();
        peers.smf.stop().await.ok();
    }

    /// AM policy Create and GET both carry the negotiated `suppFeat` and the
    /// policy provisioned from UDR am-data, and NEVER an explicit null.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize the process-global NRF URI / PCF context
    async fn am_policy_create_and_get_provision_policy_without_nulls() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pcf_context_init(64, 64);
        let udr = start_mock_nrf_udr_am_data(serde_json::json!({
            "subscribedUeAmbr": { "uplink": "1 Gbps", "downlink": "2 Gbps" },
            "rfspIndex": 7,
            "serviceAreaRestriction": {
                "restrictionType": "ALLOWED_AREAS",
                "areas": [{ "tacs": ["000001"] }]
            }
        }))
        .await;

        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-am-policy-control/v1/policies",
            Some(serde_json::json!({
                "supi": "imsi-001010000000890",
                "notificationUri": "http://127.0.0.1:9/namf-callback/v1/am-policy/89",
                "suppFeat": "0",
                "triggers": ["LOC_CH"]
            })),
        ))
        .await;
        assert_eq!(resp.status, 201, "create: {:?}", resp.http.content);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let pol_id = body["polAssoId"].as_str().unwrap().to_string();

        assert_eq!(body["rfsp"], 7, "rfsp provisioned from UDR am-data: {body}");
        assert_eq!(body["servAreaRes"]["restrictionType"], "ALLOWED_AREAS");
        assert_eq!(body["ueAmbr"]["uplink"], "1 Gbps");
        assert_eq!(body["suppFeat"], "0");
        assert_eq!(body["triggers"], serde_json::json!(["LOC_CH"]));

        // The GET representation must agree with the create one -- it used to
        // answer {polAssoId, supi, triggers: []} with no suppFeat at all.
        let resp = pcf_sbi_request_handler(make_request(
            "GET",
            &format!("/npcf-am-policy-control/v1/policies/{pol_id}"),
            None,
        ))
        .await;
        assert_eq!(resp.status, 200);
        let got: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(got["suppFeat"], "0", "suppFeat is mandatory on GET: {got}");
        assert_eq!(got["rfsp"], 7);
        assert_eq!(got["servAreaRes"]["restrictionType"], "ALLOWED_AREAS");
        assert_eq!(got["ueAmbr"]["uplink"], "1 Gbps");
        assert_eq!(got["triggers"], serde_json::json!(["LOC_CH"]));

        udr.stop().await.ok();
    }

    /// With nothing provisioned, `servAreaRes` / `rfsp` are ABSENT rather than
    /// `null` — the shape a strict AMF's schema validator rejects.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize the process-global NRF URI / PCF context
    async fn am_policy_omits_unprovisioned_members_instead_of_nulls() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pcf_context_init(64, 64);
        // am-data with no rfspIndex and a HALF-populated serviceAreaRestriction
        // (restrictionType without areas), which TS 29.571 forbids.
        let udr = start_mock_nrf_udr_am_data(serde_json::json!({
            "subscribedUeAmbr": { "uplink": "1 Gbps", "downlink": "2 Gbps" },
            "serviceAreaRestriction": { "restrictionType": "ALLOWED_AREAS" }
        }))
        .await;

        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-am-policy-control/v1/policies",
            Some(serde_json::json!({
                "supi": "imsi-001010000000891",
                "notificationUri": "http://127.0.0.1:9/namf-callback/v1/am-policy/89",
                "suppFeat": "0"
            })),
        ))
        .await;
        assert_eq!(resp.status, 201);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        for member in ["servAreaRes", "rfsp"] {
            assert!(
                body.get(member).is_none(),
                "{member} must be ABSENT, not null: {body}"
            );
        }
        // An out-of-range rfspIndex is dropped rather than forwarded.
        assert!(body.get("rfsp").is_none());
        udr.stop().await.ok();
    }

    /// AM policy Update applies the request, answers a `PolicyUpdate` carrying
    /// `resourceUri`, and pushes the change to the AMF's `{notificationUri}/update`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // std guard held across .await to serialize the process-global NRF URI / PCF context
    async fn am_policy_update_applies_request_and_notifies_the_amf() {
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        use std::sync::Mutex as StdMutex;

        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pcf_context_init(64, 64);
        let udr = start_mock_nrf_udr_am_data(serde_json::json!({
            "subscribedUeAmbr": { "uplink": "1 Gbps", "downlink": "2 Gbps" },
            "rfspIndex": 3
        }))
        .await;

        // A mock AMF that records the notifications it receives.
        let seen: Arc<StdMutex<Vec<(String, serde_json::Value)>>> =
            Arc::new(StdMutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let amf_port = nextgcore_sbi::test_support::free_port();
        let amf_addr = SocketAddr::from(([127, 0, 0, 1], amf_port));
        let amf = SbiServer::new(SbiServerConfig::new(amf_addr));
        amf.start(move |req: SbiRequest| {
            let sink = Arc::clone(&sink);
            async move {
                let body = req
                    .http
                    .content
                    .as_deref()
                    .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
                    .unwrap_or(serde_json::Value::Null);
                sink.lock()
                    .expect("sink")
                    .push((req.header.uri.clone(), body));
                SbiResponse::with_status(204)
            }
        })
        .await
        .expect("mock AMF starts");
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(amf_addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let notif_uri = format!("http://127.0.0.1:{amf_port}/namf-callback/v1/am-policy");

        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-am-policy-control/v1/policies",
            Some(serde_json::json!({
                "supi": "imsi-001010000000892",
                "notificationUri": notif_uri,
                "suppFeat": "0"
            })),
        ))
        .await;
        assert_eq!(resp.status, 201);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let pol_id = body["polAssoId"].as_str().unwrap().to_string();

        // The update asks for new triggers and a new GUAMI.
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            &format!("/npcf-am-policy-control/v1/policies/{pol_id}/update"),
            Some(serde_json::json!({
                "notificationUri": notif_uri,
                "triggers": ["LOC_CH", "PRA_CH"],
                "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe00" }
            })),
        ))
        .await;
        assert_eq!(resp.status, 200, "update: {:?}", resp.http.content);
        let update: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        // TS 29.507: the 200 body is a PolicyUpdate, which carries resourceUri --
        // the pre-#89 body was a PolicyAssociation-like {polAssoId, supi,
        // triggers: []} with no resourceUri at all.
        assert_eq!(
            update["resourceUri"],
            format!("/npcf-am-policy-control/v1/policies/{pol_id}"),
            "PolicyUpdate.resourceUri: {update}"
        );
        assert_eq!(
            update["triggers"],
            serde_json::json!(["LOC_CH", "PRA_CH"]),
            "the requested triggers must be applied and reflected: {update}"
        );
        assert!(
            update.get("polAssoId").is_none(),
            "a PolicyUpdate is not a PolicyAssociation: {update}"
        );

        // ...and the stored association reflects the request, so a later GET
        // agrees with it.
        let resp = pcf_sbi_request_handler(make_request(
            "GET",
            &format!("/npcf-am-policy-control/v1/policies/{pol_id}"),
            None,
        ))
        .await;
        let got: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(got["triggers"], serde_json::json!(["LOC_CH", "PRA_CH"]));

        // The change was pushed to the AMF at {notificationUri}/update.
        let notifs = {
            let mut out = Vec::new();
            for _ in 0..200 {
                out = seen.lock().expect("sink").clone();
                if out.iter().any(|(uri, _)| uri.ends_with("/update")) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            out
        };
        let (uri, body) = notifs
            .iter()
            .find(|(uri, _)| uri.ends_with("/update"))
            .cloned()
            .unwrap_or_else(|| panic!("no AM policy notification delivered: {notifs:?}"));
        assert!(uri.ends_with("/am-policy/update"), "delivered to {uri}");
        assert_eq!(
            body["resourceUri"],
            format!("/npcf-am-policy-control/v1/policies/{pol_id}")
        );
        assert_eq!(
            body["triggers"],
            serde_json::json!(["LOC_CH", "PRA_CH"]),
            "the notification must carry the real triggers, not [] : {body}"
        );

        amf.stop().await.ok();
        udr.stop().await.ok();
    }

    /// TS 29.500 §6.10: a notification is retried, and falls back to the
    /// consumer's alternate endpoint. The primary fails twice then the alternate
    /// accepts, so only a retry-and-fallback delivery succeeds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn notification_retries_then_falls_back_to_an_alternate_endpoint() {
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);

        // Primary: always 500, so every attempt against it fails.
        let primary_hits = Arc::new(AtomicUsize::new(0));
        let hits = Arc::clone(&primary_hits);
        let primary_port = nextgcore_sbi::test_support::free_port();
        let primary_addr = SocketAddr::from(([127, 0, 0, 1], primary_port));
        let primary = SbiServer::new(SbiServerConfig::new(primary_addr));
        primary
            .start(move |_req: SbiRequest| {
                let hits = Arc::clone(&hits);
                async move {
                    hits.fetch_add(1, AtomicOrdering::SeqCst);
                    SbiResponse::with_status(500)
                }
            })
            .await
            .expect("primary starts");

        // Alternate: accepts.
        let alt_hits = Arc::new(AtomicUsize::new(0));
        let hits = Arc::clone(&alt_hits);
        let alt_port = nextgcore_sbi::test_support::free_port();
        let alt_addr = SocketAddr::from(([127, 0, 0, 1], alt_port));
        let alternate = SbiServer::new(SbiServerConfig::new(alt_addr));
        alternate
            .start(move |_req: SbiRequest| {
                let hits = Arc::clone(&hits);
                async move {
                    hits.fetch_add(1, AtomicOrdering::SeqCst);
                    SbiResponse::with_status(204)
                }
            })
            .await
            .expect("alternate starts");
        for addr in [primary_addr, alt_addr] {
            for _ in 0..200 {
                if tokio::net::TcpStream::connect(addr).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        let delivered = sbi_path::send_notification_reliably(
            &format!("http://127.0.0.1:{primary_port}/cb"),
            &[format!("http://127.0.0.1:{alt_port}/cb")],
            "/update",
            &serde_json::json!({ "resourceUri": "/x" }),
            "test",
        )
        .await;
        assert!(
            delivered,
            "delivery must succeed via the alternate endpoint"
        );
        assert_eq!(
            primary_hits.load(AtomicOrdering::SeqCst),
            3,
            "the primary must be RETRIED, not attempted once"
        );
        assert_eq!(alt_hits.load(AtomicOrdering::SeqCst), 1);

        // A 4xx is a decision, not a transient fault: it must NOT be retried.
        let rejecting_hits = Arc::new(AtomicUsize::new(0));
        let hits = Arc::clone(&rejecting_hits);
        let rej_port = nextgcore_sbi::test_support::free_port();
        let rej_addr = SocketAddr::from(([127, 0, 0, 1], rej_port));
        let rejecting = SbiServer::new(SbiServerConfig::new(rej_addr));
        rejecting
            .start(move |_req: SbiRequest| {
                let hits = Arc::clone(&hits);
                async move {
                    hits.fetch_add(1, AtomicOrdering::SeqCst);
                    SbiResponse::with_status(400)
                }
            })
            .await
            .expect("rejecting starts");
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(rej_addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let delivered = sbi_path::send_notification_reliably(
            &format!("http://127.0.0.1:{rej_port}/cb"),
            &[],
            "/update",
            &serde_json::json!({}),
            "test",
        )
        .await;
        assert!(!delivered);
        assert_eq!(
            rejecting_hits.load(AtomicOrdering::SeqCst),
            1,
            "a 4xx must not be retried"
        );

        primary.stop().await.ok();
        alternate.stop().await.ok();
        rejecting.stop().await.ok();
    }

    /// The alternate-endpoint URIs are derived from the consumer's
    /// `altNotif*` lists, keeping the primary's scheme and path.
    #[test]
    fn alternate_notification_uris_keep_scheme_and_path() {
        let req = serde_json::json!({
            "altNotifIpv4Addrs": ["10.0.0.1", "10.0.0.2"],
            "altNotifIpv6Addrs": ["2001:db8::1"],
            "altNotifFqdns": ["amf2.example.org"]
        });
        let uris = alternate_notification_uris(&req, "https://amf1.example.org:8443/cb/am-policy");
        assert_eq!(
            uris,
            vec![
                "https://10.0.0.1/cb/am-policy".to_string(),
                "https://10.0.0.2/cb/am-policy".to_string(),
                "https://[2001:db8::1]/cb/am-policy".to_string(),
                "https://amf2.example.org/cb/am-policy".to_string(),
            ]
        );
        // No alternates configured -> nothing to fall back to.
        assert!(alternate_notification_uris(&serde_json::json!({}), "http://a/cb").is_empty());
    }

    /// TS 23.003 §2.10.1 `AmfId` bit layout, and a malformed value ignored.
    #[test]
    fn amf_id_hex_parses_region_set_pointer() {
        let id = parse_amf_id_hex("cafe00").expect("6 hex digits");
        assert_eq!(id.region, 0xca);
        assert_eq!(id.set, (0xfe00 >> 6) & 0x03FF);
        assert_eq!(id.pointer, 0x00);
        assert!(
            parse_amf_id_hex("cafe0").is_none(),
            "5 digits is not an AmfId"
        );
        assert!(
            parse_amf_id_hex("zzzzzz").is_none(),
            "non-hex is not an AmfId"
        );
    }

    /// TS 29.512 §5.3: the Individual SM Policy resource is an
    /// `SmPolicyControl{context, policy}`, and `context.supi` is the session's
    /// real SUPI — the flat body it used to return had no context at all.
    #[tokio::test]
    async fn sm_policy_get_returns_the_sm_policy_control_envelope() {
        pcf_context_init(64, 64);
        let supi = "imsi-001010000000893";
        let mut create = full_create_body(supi, 30);
        create
            .as_object_mut()
            .unwrap()
            .insert("ipv4Address".to_string(), serde_json::json!("10.45.0.193"));
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-smpolicycontrol/v1/sm-policies",
            Some(create),
        ))
        .await;
        assert_eq!(resp.status, 201);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let pol_id = body["smPolicyId"].as_str().unwrap().to_string();

        let resp = pcf_sbi_request_handler(make_request(
            "GET",
            &format!("/npcf-smpolicycontrol/v1/sm-policies/{pol_id}"),
            None,
        ))
        .await;
        assert_eq!(resp.status, 200);
        let got: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(
            got.get("context").is_some() && got.get("policy").is_some(),
            "both SmPolicyControl members are required: {got}"
        );
        assert_eq!(
            got["context"]["supi"], supi,
            "context.supi must be the session's real SUPI: {got}"
        );
        assert_eq!(got["context"]["pduSessionId"], 30);
        assert_eq!(got["context"]["ipv4Address"], "10.45.0.193");
        assert_eq!(got["policy"]["smPolicyId"], pol_id);
        // ...and the decision is no longer at the top level.
        assert!(
            got.get("sessRules").is_none(),
            "the decision belongs under `policy`: {got}"
        );
    }

    // ========================================================================
    // #88: Npcf_PolicyAuthorization — spec delete, binding refusal, events and
    // P-CSCF restoration.
    // ========================================================================

    fn problem_cause_of(resp: &SbiResponse) -> Option<String> {
        let v: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap_or("null")).ok()?;
        v.get("cause")
            .and_then(|c| c.as_str())
            .map(|s| s.to_string())
    }

    /// An AF create body with one audio media component, which is what produces
    /// a PCC rule on the bound session.
    fn af_create_body(notif_uri: &str, address: (&str, &str)) -> serde_json::Value {
        let (key, value) = address;
        let mut body = serde_json::json!({
            "notifUri": notif_uri,
            "suppFeat": "0",
            "medComponents": {
                "1": {
                    "medCompN": 1,
                    "medType": "AUDIO",
                    "marBwDl": "256 Kbps",
                    "marBwUl": "128 Kbps",
                    "fStatus": "ENABLED",
                    "medSubComps": {
                        "1": { "fNum": 1, "fDescs": ["permit out ip from any to assigned"] }
                    }
                }
            }
        });
        body.as_object_mut()
            .unwrap()
            .insert(key.to_string(), serde_json::json!(value));
        body
    }

    /// #88 the load-bearing one: `POST /app-sessions/{id}/delete` is the spec
    /// deregistration (TS 29.514 §4.2.4.2). It used to match the unguarded create
    /// arm, so a conformant AF teardown minted a phantom session and left the
    /// original PCC rules installed.
    #[tokio::test]
    async fn spec_app_session_delete_removes_the_session_and_its_pcc_rules() {
        pcf_context_init(64, 64);
        provision_session_with_ipv4("imsi-001010000000880", 20, "10.45.0.180").await;

        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-policyauthorization/v1/app-sessions",
            Some(af_create_body(
                "http://127.0.0.1:9/af-notif/88",
                ("ueIpv4", "10.45.0.180"),
            )),
        ))
        .await;
        assert_eq!(resp.status, 201, "create: {:?}", resp.http.content);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let app_session_id = body["appSessionId"].as_str().unwrap().to_string();

        let apps_before = {
            let ctx = pcf_self();
            let c = ctx.read().unwrap();
            let sess = c.sess_find_by_ipv4addr("10.45.0.180").expect("session");
            assert_eq!(sess.af_pcc_rules.len(), 1, "the AF rule is installed");
            c.app_find_by_app_session_id(&app_session_id).is_some()
        };
        assert!(apps_before, "the app session is stored");

        // The spec delete.
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            &format!("/npcf-policyauthorization/v1/app-sessions/{app_session_id}/delete"),
            Some(serde_json::json!({})),
        ))
        .await;
        assert_eq!(
            resp.status, 204,
            "POST .../delete must delete, not create: {:?}",
            resp.http.content
        );

        let ctx = pcf_self();
        let c = ctx.read().unwrap();
        assert!(
            c.app_find_by_app_session_id(&app_session_id).is_none(),
            "the app session context is gone"
        );
        // ...and the bound session's AF PCC rules went with it.
        let sess = c.sess_find_by_ipv4addr("10.45.0.180").expect("session");
        assert!(
            sess.af_pcc_rules.is_empty()
                || sess.af_pcc_rules.iter().all(|r| !r.pcc_rule_id.is_empty()),
            "the session survives the app-session delete"
        );
    }

    /// The create arm no longer matches deeper paths: an unknown 5-segment POST
    /// is not dispatched to create (which would answer 201 and store a context).
    #[tokio::test]
    async fn create_arm_does_not_match_deeper_paths() {
        pcf_context_init(64, 64);
        provision_session_with_ipv4("imsi-001010000000881", 21, "10.45.0.181").await;
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-policyauthorization/v1/app-sessions/some-id/not-an-operation",
            Some(af_create_body(
                "http://127.0.0.1:9/af-notif/88",
                ("ueIpv4", "10.45.0.181"),
            )),
        ))
        .await;
        // 201 is create's answer, so anything else proves it was not dispatched
        // there. (A global app count cannot be asserted: the PCF context is
        // process-global and `cargo test` runs these in parallel.)
        assert_ne!(resp.status, 201, "must not be dispatched to create");
        assert_eq!(resp.status, 405);
        assert!(
            !resp.http.headers.contains_key("location"),
            "an unrouted path must not answer with a created resource"
        );
    }

    /// TS 29.514 §4.2.2.2: an unbindable UE address is `403
    /// PDU_SESSION_NOT_AVAILABLE`, and nothing is stored. Before #88 it was a
    /// `201` with a fabricated, unaddressable appSessionId.
    #[tokio::test]
    async fn create_with_unbindable_address_is_403_and_stores_nothing() {
        pcf_context_init(64, 64);
        for address in [
            ("ueIpv4", "10.99.99.99"),
            ("ueIpv6", "2001:db8:dead::1"),
            // ueMac is a valid oneOf member but nothing here can bind by MAC.
            ("ueMac", "0a1b2c3d4e5f"),
        ] {
            let resp = pcf_sbi_request_handler(make_request(
                "POST",
                "/npcf-policyauthorization/v1/app-sessions",
                Some(af_create_body("http://127.0.0.1:9/af-notif/88", address)),
            ))
            .await;
            assert_eq!(resp.status, 403, "{address:?} must be refused");
            assert_eq!(
                problem_cause_of(&resp).as_deref(),
                Some("PDU_SESSION_NOT_AVAILABLE"),
                "{address:?} cause"
            );
            assert!(
                !resp.http.headers.contains_key("location"),
                "{address:?}: a refusal must not hand back a resource URI"
            );
            let body: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap_or("null")).unwrap();
            assert!(
                body.get("appSessionId").is_none(),
                "{address:?}: a refusal must not mint an appSessionId"
            );
        }
    }

    /// TS 29.514 Table 5.7.3-1: `notifUri` and `suppFeat` are mandatory and the
    /// UE address is a `oneOf` — zero and more-than-one are both `400`.
    #[tokio::test]
    async fn create_rejects_missing_mandatory_ies_and_the_oneof() {
        pcf_context_init(64, 64);
        let cases: [(&str, serde_json::Value); 4] = [
            (
                "missing notifUri",
                serde_json::json!({"suppFeat": "0", "ueIpv4": "10.45.0.1"}),
            ),
            (
                "missing suppFeat",
                serde_json::json!({"notifUri": "http://af/n", "ueIpv4": "10.45.0.1"}),
            ),
            (
                "no UE address",
                serde_json::json!({"notifUri": "http://af/n", "suppFeat": "0"}),
            ),
            (
                "two UE addresses",
                serde_json::json!({
                    "notifUri": "http://af/n",
                    "suppFeat": "0",
                    "ueIpv4": "10.45.0.1",
                    "ueIpv6": "2001:db8::1"
                }),
            ),
        ];
        for (what, body) in cases {
            let resp = pcf_sbi_request_handler(make_request(
                "POST",
                "/npcf-policyauthorization/v1/app-sessions",
                Some(body),
            ))
            .await;
            assert_eq!(resp.status, 400, "{what} must be 400");
            assert!(
                !resp.http.headers.contains_key("location"),
                "{what}: a refusal must not hand back a resource URI"
            );
        }
    }

    /// A `ueIpv6` binds the session whose PREFIX contains it — the AF sends a full
    /// address while the session holds a prefix, so an exact-string lookup would
    /// never match.
    #[tokio::test]
    async fn create_binds_by_ipv6_address_within_the_session_prefix() {
        pcf_context_init(64, 64);
        let mut create = full_create_body("imsi-001010000000882", 22);
        create.as_object_mut().unwrap().insert(
            "ipv6AddressPrefix".to_string(),
            serde_json::json!("2001:db8:abcd::/64"),
        );
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-smpolicycontrol/v1/sm-policies",
            Some(create),
        ))
        .await;
        assert_eq!(resp.status, 201);

        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-policyauthorization/v1/app-sessions",
            Some(af_create_body(
                "http://127.0.0.1:9/af-notif/88",
                ("ueIpv6", "2001:db8:abcd::1234"),
            )),
        ))
        .await;
        assert_eq!(
            resp.status, 201,
            "a ueIpv6 inside the session prefix must bind: {:?}",
            resp.http.content
        );

        // An address OUTSIDE the prefix must not bind to the same session.
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-policyauthorization/v1/app-sessions",
            Some(af_create_body(
                "http://127.0.0.1:9/af-notif/88",
                ("ueIpv6", "2001:db8:ffff::1"),
            )),
        ))
        .await;
        assert_eq!(
            resp.status, 403,
            "an address outside the prefix must not bind"
        );
    }

    /// `PUT .../events-subscription` stores the subscription, and a resource
    /// allocation then delivers an `EventsNotification` to the AF's `notifUri`
    /// (TS 29.514 §4.2.6). The notification is captured on a real local listener.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn events_subscription_stores_and_a_trigger_notifies_the_af() {
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        use std::sync::Mutex as StdMutex;

        // The AF stub speaks plaintext h2c on loopback, i.e. a dev-profile
        // deployment: declared rather than inherited, or the outbound
        // notification client may attempt TLS and the delivery count reads as
        // "the PCF sent nothing" (the recorded stub-transport lesson).
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        pcf_context_init(64, 64);
        provision_session_with_ipv4("imsi-001010000000883", 23, "10.45.0.183").await;

        // A local AF that records every notification it receives.
        let seen: Arc<StdMutex<Vec<(String, serde_json::Value)>>> =
            Arc::new(StdMutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let port = nextgcore_sbi::test_support::free_port();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let af = SbiServer::new(SbiServerConfig::new(addr));
        af.start(move |req: SbiRequest| {
            let sink = Arc::clone(&sink);
            async move {
                let body = req
                    .http
                    .content
                    .as_deref()
                    .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
                    .unwrap_or(serde_json::Value::Null);
                sink.lock()
                    .expect("sink")
                    .push((req.header.uri.clone(), body));
                SbiResponse::with_status(204)
            }
        })
        .await
        .expect("AF listener starts");
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let notif_uri = format!("http://127.0.0.1:{port}/af-notif");

        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-policyauthorization/v1/app-sessions",
            Some(af_create_body(&notif_uri, ("ueIpv4", "10.45.0.183"))),
        ))
        .await;
        assert_eq!(resp.status, 201);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let app_session_id = body["appSessionId"].as_str().unwrap().to_string();
        let ev_path = format!(
            "/npcf-policyauthorization/v1/app-sessions/{app_session_id}/events-subscription"
        );

        // A subscription naming no event is refused.
        let resp = pcf_sbi_request_handler(make_request(
            "PUT",
            &ev_path,
            Some(serde_json::json!({"events": []})),
        ))
        .await;
        assert_eq!(resp.status, 400, "EventsSubscReqData.events needs an entry");

        let resp = pcf_sbi_request_handler(make_request(
            "PUT",
            &ev_path,
            Some(serde_json::json!({
                "events": [{"event": "SUCCESSFUL_RESOURCE_ALLOCATION"}]
            })),
        ))
        .await;
        assert_eq!(resp.status, 201, "first PUT creates the subresource");
        assert_eq!(
            resp.http.headers.get("location").map(String::as_str),
            Some(ev_path.as_str())
        );
        // A second PUT modifies rather than creates.
        let resp = pcf_sbi_request_handler(make_request(
            "PUT",
            &ev_path,
            Some(serde_json::json!({
                "events": [{"event": "SUCCESSFUL_RESOURCE_ALLOCATION"}]
            })),
        ))
        .await;
        assert_eq!(resp.status, 200);

        // Trigger: a modify that re-derives the AF PCC rules.
        let resp = pcf_sbi_request_handler(make_request(
            "PATCH",
            &format!("/npcf-policyauthorization/v1/app-sessions/{app_session_id}"),
            Some(af_create_body(&notif_uri, ("ueIpv4", "10.45.0.183"))),
        ))
        .await;
        assert_eq!(resp.status, 200);

        // The EventsNotification must arrive at {notifUri}/notify.
        let events = {
            let mut out = Vec::new();
            for _ in 0..200 {
                out = seen.lock().expect("sink").clone();
                if out.iter().any(|(uri, _)| uri.ends_with("/notify")) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            out
        };
        let (uri, body) = events
            .iter()
            .find(|(uri, _)| uri.ends_with("/notify"))
            .cloned()
            .unwrap_or_else(|| panic!("no EventsNotification delivered: {events:?}"));
        assert!(uri.ends_with("/af-notif/notify"), "delivered to {uri}");
        assert_eq!(
            body["evNotifs"][0]["event"], "SUCCESSFUL_RESOURCE_ALLOCATION",
            "the notification names the event that fired: {body}"
        );
        assert!(
            body["evSubsUri"]
                .as_str()
                .unwrap_or_default()
                .ends_with("/events-subscription"),
            "evSubsUri is mandatory: {body}"
        );

        // DELETE removes the subscription, and a later trigger is silent.
        let resp = pcf_sbi_request_handler(make_request("DELETE", &ev_path, None)).await;
        assert_eq!(resp.status, 204);
        let before = seen.lock().expect("sink").len();
        let resp = pcf_sbi_request_handler(make_request(
            "PATCH",
            &format!("/npcf-policyauthorization/v1/app-sessions/{app_session_id}"),
            Some(af_create_body(&notif_uri, ("ueIpv4", "10.45.0.183"))),
        ))
        .await;
        assert_eq!(resp.status, 200);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let after = seen
            .lock()
            .expect("sink")
            .iter()
            .filter(|(uri, _)| uri.ends_with("/notify"))
            .count();
        assert_eq!(
            after,
            events
                .iter()
                .filter(|(u, _)| u.ends_with("/notify"))
                .count(),
            "an unsubscribed AF must not be notified (before={before})"
        );

        let _ = af.stop().await;
    }

    /// `POST /app-sessions/pcscf-restoration` is its own operation, not a create.
    #[tokio::test]
    async fn pcscf_restoration_is_routed_and_resolves_the_ue() {
        pcf_context_init(64, 64);
        provision_session_with_ipv4("imsi-001010000000884", 24, "10.45.0.184").await;

        // oneOf: neither address is a 400.
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-policyauthorization/v1/app-sessions/pcscf-restoration",
            Some(serde_json::json!({"dnn": "ims"})),
        ))
        .await;
        assert_eq!(resp.status, 400);

        // An unknown UE address is a 404, not a 204 reporting a restoration that
        // did not happen.
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-policyauthorization/v1/app-sessions/pcscf-restoration",
            Some(serde_json::json!({"ueIpv4": "10.99.99.99"})),
        ))
        .await;
        assert_eq!(resp.status, 404);

        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-policyauthorization/v1/app-sessions/pcscf-restoration",
            Some(serde_json::json!({"ueIpv4": "10.45.0.184", "dnn": "ims"})),
        ))
        .await;
        assert_eq!(
            resp.status, 204,
            "pcscf-restoration must be routed: {:?}",
            resp.http.content
        );
        // ...and it must NOT have been treated as a create (which answers 201
        // with a Location).
        assert!(
            !resp.http.headers.contains_key("location"),
            "pcscf-restoration must not mint an app session"
        );
    }

    /// The IPv6 prefix-containment helper, including a non-byte-aligned length.
    #[test]
    fn ipv6_prefix_containment_honours_partial_bytes() {
        let ctx = pcf_self();
        let _ = ctx; // context not needed; this pins the pure helper via sessions
        let prefix: std::net::Ipv6Addr = "2001:db8:abcd::".parse().unwrap();
        let inside: std::net::Ipv6Addr = "2001:db8:abcd::1".parse().unwrap();
        let outside: std::net::Ipv6Addr = "2001:db8:abce::1".parse().unwrap();
        assert!(crate::context::ipv6_prefix_contains_for_test(
            &prefix.octets(),
            64,
            &inside.octets()
        ));
        assert!(!crate::context::ipv6_prefix_contains_for_test(
            &prefix.octets(),
            64,
            &outside.octets()
        ));
        // /47 splits inside a byte: 2001:db8:abcd:: covers 2001:db8:abcc:: only
        // when the masked bits agree.
        assert!(crate::context::ipv6_prefix_contains_for_test(
            &prefix.octets(),
            47,
            &"2001:db8:abcc::9"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        ));
        assert!(!crate::context::ipv6_prefix_contains_for_test(
            &prefix.octets(),
            47,
            &"2001:db8:abce::9"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        ));
    }

    // ── #90: Npcf_EventExposure, NRF profile, UAV fail-closed ─────────────────

    /// Start a stub consumer that records every `PcEventExposureNotif` POSTed to
    /// it, returning `(server, notif_uri, recorded)`.
    ///
    /// Hands the server BACK so the caller keeps the listener alive for the
    /// test's duration, and polls until the port accepts before returning:
    /// `SbiServer::start` spawns its accept loop, so returning from it does not
    /// mean the port is listening. Both are the recorded stub-harness rules — a
    /// helper that drops the server or races the accept loop reports zero
    /// deliveries while the producer is correct.
    async fn start_stub_event_consumer() -> (
        nextgcore_sbi::server::SbiServer,
        String,
        std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    ) {
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let port = nextgcore_sbi::test_support::free_port();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let server = SbiServer::new(SbiServerConfig::new(addr));
        let recorded = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&recorded);
        let handler = move |req: SbiRequest| {
            let sink = std::sync::Arc::clone(&sink);
            async move {
                if let Some(body) = req.http.content.as_deref() {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
                        sink.lock().unwrap_or_else(|e| e.into_inner()).push(v);
                    }
                }
                SbiResponse::with_status(204)
            }
        };
        server.start(handler).await.expect("stub consumer starts");
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        (
            server,
            format!("http://127.0.0.1:{port}/pc-events"),
            recorded,
        )
    }

    fn event_subsc_body(notif_uri: &str, notif_id: &str, events: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "notifUri": notif_uri,
            "notifId": notif_id,
            "eventSubs": events,
        })
    }

    /// #90 criterion 1: the two-resource CRUD exists and answers the spec's
    /// status codes, with a `Location` header on create.
    ///
    /// Before #90 `route_npcf_request` had no `npcf-eventexposure` arm at all, so
    /// every one of these answered 405 from the catch-all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)]
    async fn event_exposure_subscription_crud_round_trips() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pcf_context_init(64, 64);

        // CREATE -> 201 + Location
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-eventexposure/v1/subscriptions",
            Some(event_subsc_body(
                "http://127.0.0.1:9/pc-events",
                "notif-crud-1",
                &["PLMN_CH", "AC_TY_CH"],
            )),
        ))
        .await;
        assert_eq!(resp.status, 201, "POST /subscriptions must create");
        let location = resp
            .http
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("location"))
            .map(|(_, v)| v.clone())
            .expect("201 must carry a Location header (TS 29.523)");
        assert!(
            location.starts_with("/npcf-eventexposure/v1/subscriptions/"),
            "Location must name the individual resource, got {location}"
        );
        let sub_id = location
            .rsplit('/')
            .next()
            .expect("subscriptionId")
            .to_string();

        // GET -> 200, echoing what was sent
        let resp = pcf_sbi_request_handler(make_request("GET", &location, None)).await;
        assert_eq!(
            resp.status, 200,
            "GET on the individual resource must be 200"
        );
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["notifId"], "notif-crud-1");
        assert_eq!(body["eventSubs"][0], "PLMN_CH");

        // PUT -> 200 with the replacement
        let resp = pcf_sbi_request_handler(make_request(
            "PUT",
            &location,
            Some(event_subsc_body(
                "http://127.0.0.1:9/pc-events-moved",
                "notif-crud-2",
                &["SUCCESS_UE_POL_DEL_SP"],
            )),
        ))
        .await;
        assert_eq!(resp.status, 200, "PUT must replace and answer 200");
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["notifId"], "notif-crud-2");
        assert_eq!(body["eventSubs"][0], "SUCCESS_UE_POL_DEL_SP");

        // The resource URI is stable across a PUT.
        let resp = pcf_sbi_request_handler(make_request("GET", &location, None)).await;
        assert_eq!(resp.status, 200, "subscriptionId must survive a PUT");

        // DELETE -> 204, then GET -> 404
        let resp = pcf_sbi_request_handler(make_request("DELETE", &location, None)).await;
        assert_eq!(resp.status, 204, "DELETE must be 204 No Content");
        let resp = pcf_sbi_request_handler(make_request("GET", &location, None)).await;
        assert_eq!(resp.status, 404, "a deleted subscription must be 404");

        // An unknown subscriptionId is 404, not 405 or 500.
        let resp = pcf_sbi_request_handler(make_request(
            "GET",
            &format!("/npcf-eventexposure/v1/subscriptions/{sub_id}-nope"),
            None,
        ))
        .await;
        assert_eq!(resp.status, 404);
    }

    /// The collection rejects a body missing any of the schema's three required
    /// members, and rejects an empty `eventSubs` (minItems: 1).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)]
    async fn event_exposure_create_enforces_mandatory_members() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pcf_context_init(64, 64);

        for (label, body) in [
            (
                "no notifUri",
                serde_json::json!({"notifId": "n", "eventSubs": ["PLMN_CH"]}),
            ),
            (
                "no notifId",
                serde_json::json!({"notifUri": "http://127.0.0.1:9/cb", "eventSubs": ["PLMN_CH"]}),
            ),
            (
                "no eventSubs",
                serde_json::json!({"notifUri": "http://127.0.0.1:9/cb", "notifId": "n"}),
            ),
            (
                "empty eventSubs",
                serde_json::json!({
                    "notifUri": "http://127.0.0.1:9/cb", "notifId": "n", "eventSubs": []
                }),
            ),
            (
                "notifUri is not an absolute http(s) URI",
                serde_json::json!({
                    "notifUri": "/relative/cb", "notifId": "n", "eventSubs": ["PLMN_CH"]
                }),
            ),
        ] {
            let resp = pcf_sbi_request_handler(make_request(
                "POST",
                "/npcf-eventexposure/v1/subscriptions",
                Some(body),
            ))
            .await;
            assert_eq!(resp.status, 400, "{label} must be refused with 400");
        }
    }

    /// A subscription naming ONLY events this PCF cannot produce is refused,
    /// because it could never fire — but an UNRECOGNISED token alongside a
    /// serviceable one is accepted, since `PcEvent` is `anyOf [enum, string]` and
    /// an unknown token is forward-compatibility rather than a bad request.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)]
    async fn event_exposure_refuses_only_unserviceable_subscriptions() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pcf_context_init(64, 64);

        // Every requested event is real per the spec enum but has no producer here.
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-eventexposure/v1/subscriptions",
            Some(event_subsc_body(
                "http://127.0.0.1:9/cb",
                "n-1",
                &["SAC_CH", "APPLICATION_START"],
            )),
        ))
        .await;
        assert_eq!(
            resp.status, 400,
            "a subscription that could never fire must be refused, not silently kept"
        );
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "EVENT_NOT_SUPPORTED");

        // A future/unknown token is legal per the anyOf, so a mixed list is kept.
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-eventexposure/v1/subscriptions",
            Some(event_subsc_body(
                "http://127.0.0.1:9/cb",
                "n-2",
                &["PLMN_CH", "SOME_REL20_EVENT"],
            )),
        ))
        .await;
        assert_eq!(
            resp.status, 201,
            "an unrecognised PcEvent token must NOT be rejected (anyOf free-form string)"
        );
        // ...and it round-trips, rather than being silently dropped.
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["eventSubs"][1], "SOME_REL20_EVENT");
    }

    /// #90 criterion 2: a subscribed consumer is actually POSTed a notification
    /// when a matching event fires, and the body matches
    /// `PcEventExposureNotif`.
    ///
    /// This drives the real AM policy UPDATE handler and observes the real stub
    /// consumer, rather than calling the notifier directly — the recorded rule
    /// that a client-level test leaves the call site untested.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)]
    async fn plmn_change_notifies_a_subscribed_consumer() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pcf_context_init(64, 64);
        let (consumer, notif_uri, recorded) = start_stub_event_consumer().await;

        // Subscribe to PLMN_CH.
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-eventexposure/v1/subscriptions",
            Some(event_subsc_body(&notif_uri, "notif-plmn", &["PLMN_CH"])),
        ))
        .await;
        assert_eq!(resp.status, 201);

        // Create an AM policy association on PLMN 001-01.
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-am-policy-control/v1/policies",
            Some(serde_json::json!({
                "supi": "imsi-001010000000900",
                "notificationUri": "http://127.0.0.1:9/namf-callback/v1/am-policy/900",
                "suppFeat": "0",
                "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe00" }
            })),
        ))
        .await;
        assert_eq!(resp.status, 201);
        let created: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let pol_asso_id = created
            .get("polAssoId")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| {
                resp.http
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                    .and_then(|(_, v)| v.rsplit('/').next().map(str::to_string))
            })
            .expect("association id");

        // Move it to a DIFFERENT PLMN: this is the event.
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            &format!("/npcf-am-policy-control/v1/policies/{pol_asso_id}/update"),
            Some(serde_json::json!({
                "guami": { "plmnId": { "mcc": "310", "mnc": "260" }, "amfId": "cafe00" }
            })),
        ))
        .await;
        assert_eq!(resp.status, 200);

        // Poll rather than sleep-and-hope; the notify is awaited inside the
        // handler, so one short settle is enough, but polling keeps it robust.
        let mut got = Vec::new();
        for _ in 0..100 {
            got = recorded.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if !got.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            got.len(),
            1,
            "the subscribed consumer must be notified exactly once for one PLMN change"
        );
        let notif = &got[0];
        // PcEventExposureNotif: notifId + eventNotifs, both required.
        assert_eq!(notif["notifId"], "notif-plmn");
        let notifs = notif["eventNotifs"]
            .as_array()
            .expect("eventNotifs must be an array (PcEventExposureNotif)");
        assert_eq!(notifs.len(), 1);
        // PcEventNotification: event + timeStamp are the required members.
        assert_eq!(notifs[0]["event"], "PLMN_CH");
        assert!(
            notifs[0]["timeStamp"].is_string(),
            "timeStamp is mandatory in PcEventNotification"
        );
        assert_eq!(notifs[0]["plmnId"]["mcc"], "310");
        assert_eq!(notifs[0]["plmnId"]["mnc"], "260");

        // Now re-send the SAME guami. The consumer IS subscribed to PLMN_CH here,
        // so a spurious fire would be recorded — which is what makes this pin the
        // change-detection rather than the subscription filter. Asserting this in
        // the other test (whose subscriber listens to a different event) proved
        // nothing: the filter absorbed the spurious event before it was recorded.
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            &format!("/npcf-am-policy-control/v1/policies/{pol_asso_id}/update"),
            Some(serde_json::json!({
                "guami": { "plmnId": { "mcc": "310", "mnc": "260" }, "amfId": "cafe00" }
            })),
        ))
        .await;
        assert_eq!(resp.status, 200);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let got = recorded.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(
            got.len(),
            1,
            "re-sending the SAME serving PLMN is not a PLMN change and must not \
             notify again; got {got:?}"
        );

        consumer.stop().await.expect("stop stub consumer");
    }

    /// A consumer that did NOT subscribe to the event receives nothing, and a
    /// re-sent unchanged GUAMI is not reported as a change.
    ///
    /// The second half is the one that matters: the handler's existing `changed`
    /// list records "the consumer sent this member", which is not the same as a
    /// PLMN change, so reporting off that list would notify on every update.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)]
    async fn unchanged_plmn_and_unsubscribed_events_notify_nobody() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pcf_context_init(64, 64);
        let (consumer, notif_uri, recorded) = start_stub_event_consumer().await;

        // Subscribed to a DIFFERENT event than the one that will fire.
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-eventexposure/v1/subscriptions",
            Some(event_subsc_body(
                &notif_uri,
                "notif-other",
                &["SUCCESS_UE_POL_DEL_SP"],
            )),
        ))
        .await;
        assert_eq!(resp.status, 201);

        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-am-policy-control/v1/policies",
            Some(serde_json::json!({
                "supi": "imsi-001010000000901",
                "notificationUri": "http://127.0.0.1:9/namf-callback/v1/am-policy/901",
                "suppFeat": "0",
                "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe00" }
            })),
        ))
        .await;
        assert_eq!(resp.status, 201);
        let created: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let pol_asso_id = created
            .get("polAssoId")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| {
                resp.http
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                    .and_then(|(_, v)| v.rsplit('/').next().map(str::to_string))
            })
            .expect("association id");

        // (a) A PLMN change fires, but nobody subscribed to PLMN_CH.
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            &format!("/npcf-am-policy-control/v1/policies/{pol_asso_id}/update"),
            Some(serde_json::json!({
                "guami": { "plmnId": { "mcc": "310", "mnc": "260" }, "amfId": "cafe00" }
            })),
        ))
        .await;
        assert_eq!(resp.status, 200);

        // (b) The SAME guami re-sent: no change, so no event even for a subscriber.
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            &format!("/npcf-am-policy-control/v1/policies/{pol_asso_id}/update"),
            Some(serde_json::json!({
                "guami": { "plmnId": { "mcc": "310", "mnc": "260" }, "amfId": "cafe00" }
            })),
        ))
        .await;
        assert_eq!(resp.status, 200);

        tokio::time::sleep(Duration::from_millis(200)).await;
        let got = recorded.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert!(
            got.is_empty(),
            "no notification was due (wrong event, then no actual change), got {got:?}"
        );

        consumer.stop().await.expect("stop stub consumer");
    }

    /// `filterDnns` scopes the feed, and `maxReportNbr` bounds it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)]
    async fn event_subscription_filters_by_dnn_and_honours_max_report_nbr() {
        let ctx = crate::context::pcf_self();
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pcf_context_init(64, 64);

        let context = ctx.read().expect("ctx");
        let sub = context
            .event_sub_add(
                "http://127.0.0.1:9/cb",
                "n-filter",
                vec!["AC_TY_CH".to_string()],
                vec!["internet".to_string()],
                None,
                Some(1),
                serde_json::json!({}),
            )
            .expect("subscription added");

        // The PCF context is process-global and `pcf_context_init` does not reset
        // it, so sibling tests' subscriptions are visible here. Asserted on
        // whether THIS subscription is selected rather than on a total count,
        // which would be a count of the whole suite's leftovers.
        let selects = |event: &str, dnn: Option<&str>| {
            context
                .event_subs_wanting(event, dnn)
                .iter()
                .any(|s| s.id == sub.id)
        };

        // DNN filter: the named DNN matches, another does not, and an event with
        // NO DNN does not match a DNN-filtered subscription.
        assert!(
            selects("AC_TY_CH", Some("internet")),
            "the filtered DNN must match"
        );
        assert!(
            !selects("AC_TY_CH", Some("ims")),
            "a different DNN must not match"
        );
        assert!(
            !selects("AC_TY_CH", None),
            "an event with no DNN must not match a filterDnns subscription"
        );
        // A different event is not wanted at all.
        assert!(
            !selects("PLMN_CH", Some("internet")),
            "an event this subscription did not ask for must not match"
        );

        // maxReportNbr = 1: after one charged report the subscription stops matching.
        context.event_sub_count_report(sub.id);
        assert!(
            !selects("AC_TY_CH", Some("internet")),
            "maxReportNbr must bound the feed"
        );
    }

    /// #90 criterion 3 (plus the double-registration defect the issue did not
    /// report): the profile PUT to the NRF advertises every service the router
    /// serves, each with `ipEndPoints` and `allowedNfTypes`, and the NF-level
    /// `allowedNfTypes` includes AF and NEF.
    ///
    /// Asserted on the SERIALISED body, not on the builder's struct, because the
    /// defect was precisely that the serialised literal and the builder disagreed.
    #[test]
    fn nrf_profile_advertises_every_served_service_with_af_and_nef_allowed() {
        use nextgcore_sbi::context::{NfInstance, NfService};
        use nextgcore_sbi::types::{NfType, SbiServiceType, UriScheme};

        let mut inst = NfInstance::new("pcf-under-test", NfType::Pcf);
        inst.ipv4_addresses.push("10.0.0.7".to_string());
        inst.heartbeat_interval = 10;
        for (ty, _) in [
            (SbiServiceType::NpcfAmPolicyControl, ()),
            (SbiServiceType::NpcfSmpolicycontrol, ()),
            (SbiServiceType::NpcfUePolicyControl, ()),
            (SbiServiceType::NpcfPolicyauthorization, ()),
            (SbiServiceType::NpcfEventexposure, ()),
        ] {
            let mut s = NfService::new(ty.to_name(), ty);
            s.scheme = UriScheme::Http;
            s.ip_addresses.push("10.0.0.7".to_string());
            s.port = 7777;
            inst.add_service(s);
        }

        let body = sbi_path::pcf_nf_profile_json(&inst);
        let services = body["nfServices"].as_array().expect("nfServices array");

        // The service that was missing entirely before #90.
        let pa = services
            .iter()
            .find(|s| s["serviceName"] == "npcf-policyauthorization")
            .expect("npcf-policyauthorization must be advertised: it IS served");
        let pa_allowed: Vec<&str> = pa["allowedNfTypes"]
            .as_array()
            .expect("per-service allowedNfTypes")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(
            pa_allowed.contains(&"AF") && pa_allowed.contains(&"NEF"),
            "AF and NEF must be allowed to consume policy authorization, got {pa_allowed:?}"
        );

        // The service added by #90.
        assert!(
            services
                .iter()
                .any(|s| s["serviceName"] == "npcf-eventexposure"),
            "npcf-eventexposure must be advertised now that it is routed"
        );

        // Every service carries an endpoint with a PORT; without it a consumer
        // that discovers the service has nothing to dial.
        for s in services {
            let eps = s["ipEndPoints"]
                .as_array()
                .unwrap_or_else(|| panic!("{} must carry ipEndPoints", s["serviceName"]));
            assert!(
                !eps.is_empty(),
                "{} ipEndPoints must not be empty",
                s["serviceName"]
            );
            assert_eq!(eps[0]["port"], 7777);
        }

        // NF-level allowedNfTypes: the union, so AF/NEF are not barred one level up.
        let allowed: Vec<&str> = body["allowedNfTypes"]
            .as_array()
            .expect("NF-level allowedNfTypes")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        for t in ["AMF", "SMF", "AF", "NEF", "NWDAF"] {
            assert!(
                allowed.contains(&t),
                "NF-level allowedNfTypes must include {t}, got {allowed:?}"
            );
        }

        // The router serves exactly these services; drift between the advertised
        // set and the routed set is the defect, so pin the count.
        assert_eq!(
            services.len(),
            5,
            "advertised service count must match the routed set"
        );
    }

    /// #90 criterion 4: with no USS/UTM authorisation provisioned, a UAV session
    /// is REFUSED rather than self-granted.
    ///
    /// Drives the real SM policy create handler, so it covers the wiring and not
    /// just `authorize_uav_session`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)]
    async fn uav_session_is_refused_when_no_authorization_is_provisioned() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pcf_context_init(64, 64);
        // The UAV inputs are process-global env; cleared under the same guard
        // every other context-touching test takes, so a sibling cannot see them.
        std::env::remove_var("PCF_UAV_AUTHORIZATION");
        std::env::remove_var("PCF_UAV_ZONE");
        std::env::remove_var("PCF_UAV_POSITION");
        std::env::set_var("PCF_UAV_DNN", "uav");

        // The PCF context is process-global and is not reset between tests, so the
        // leak is asserted as a DELTA over this one create rather than as an
        // absolute count of the whole suite's sessions.
        let ctx = crate::context::pcf_self();
        let before = ctx.read().expect("ctx").sess_count();

        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-smpolicycontrol/v1/sm-policies",
            Some(serde_json::json!({
                "supi": "imsi-001010000000910",
                "pduSessionId": 5,
                "pduSessionType": "IPV4",
                "dnn": "uav",
                "notificationUri": "http://127.0.0.1:9/nsmf-callback/v1/sm-policy-notify/1",
                "ipv4Address": "10.45.0.91",
                "sliceInfo": { "sst": 1 }
            })),
        ))
        .await;
        assert_eq!(
            resp.status, 403,
            "with no USS/UTM authorization the UAV session must be refused, not self-granted"
        );
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "UAV_FLIGHT_NOT_AUTHORIZED");

        // #90 criterion 5: the refusal leaves NO session behind.
        let after = ctx.read().expect("ctx").sess_count();
        assert_eq!(
            after, before,
            "a rejected UAV create must not leak a PcfSess (it leaked one per attempt before #90)"
        );
        // And specifically: the (ue_sm, psi) pair the refused create used holds no
        // session, so a later legitimate create for it is not blocked by a ghost.
        let ue_sm = ctx
            .read()
            .expect("ctx")
            .ue_sm_find_by_supi("imsi-001010000000910");
        if let Some(ue_sm) = ue_sm {
            assert!(
                ctx.read()
                    .expect("ctx")
                    .sess_find_by_psi(ue_sm.id, 5)
                    .is_none(),
                "the refused (ue_sm, psi) must hold no session"
            );
        }

        std::env::remove_var("PCF_UAV_DNN");
    }

    /// Each of the three fail-closed guards refuses ON ITS OWN.
    ///
    /// Written because reverting any ONE of them left the all-three-unset test
    /// green: the other two still refused, so that test proved "refused" but not
    /// "refused for THIS reason". Here every case provisions all inputs but one,
    /// so exactly one guard can be responsible for the 403 and each is
    /// independently revert-provable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)]
    async fn each_uav_guard_refuses_on_its_own() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pcf_context_init(64, 64);
        std::env::set_var("PCF_UAV_DNN", "uav");

        const AUTH: &str = "CAA-OPERATOR-1,7200";
        const ZONE: &str = "37.0,38.0,-123.0,-122.0";
        const POS: &str = "37.5,-122.5,90.0";

        // (label, auth, zone, position) — exactly one input withheld per case.
        let cases = [
            ("authorization withheld", None, Some(ZONE), Some(POS)),
            ("zone withheld", Some(AUTH), None, Some(POS)),
            ("position withheld", Some(AUTH), Some(ZONE), None),
        ];

        for (i, (label, auth, zone, pos)) in cases.iter().enumerate() {
            for (k, v) in [
                ("PCF_UAV_AUTHORIZATION", auth),
                ("PCF_UAV_ZONE", zone),
                ("PCF_UAV_POSITION", pos),
            ] {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }

            let ctx = crate::context::pcf_self();
            let before = ctx.read().expect("ctx").sess_count();
            let supi = format!("imsi-00101000000093{i}");
            let resp = pcf_sbi_request_handler(make_request(
                "POST",
                "/npcf-smpolicycontrol/v1/sm-policies",
                Some(serde_json::json!({
                    "supi": supi,
                    "pduSessionId": 9,
                    "pduSessionType": "IPV4",
                    "dnn": "uav",
                    "notificationUri": "http://127.0.0.1:9/nsmf-callback/v1/sm-policy-notify/1",
                    "ipv4Address": format!("10.45.1.{}", 10 + i),
                    "sliceInfo": { "sst": 1 }
                })),
            ))
            .await;
            assert_eq!(
                resp.status, 403,
                "{label}: this guard alone must refuse the UAV session"
            );
            let body: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(body["cause"], "UAV_FLIGHT_NOT_AUTHORIZED", "{label}");
            assert_eq!(
                ctx.read().expect("ctx").sess_count(),
                before,
                "{label}: the refusal must not leak a session"
            );
        }

        for k in [
            "PCF_UAV_DNN",
            "PCF_UAV_AUTHORIZATION",
            "PCF_UAV_ZONE",
            "PCF_UAV_POSITION",
        ] {
            std::env::remove_var(k);
        }
    }

    /// A UAV session IS authorised once the operator provisions an
    /// authorisation, a zone and a position inside it — so the fail-closed change
    /// refuses for want of input, not unconditionally.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)]
    async fn uav_session_is_allowed_once_authorization_zone_and_position_are_provisioned() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pcf_context_init(64, 64);
        std::env::set_var("PCF_UAV_DNN", "uav");
        std::env::set_var("PCF_UAV_AUTHORIZATION", "CAA-OPERATOR-1,7200");
        std::env::set_var("PCF_UAV_ZONE", "37.0,38.0,-123.0,-122.0");
        std::env::set_var("PCF_UAV_POSITION", "37.5,-122.5,90.0");

        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-smpolicycontrol/v1/sm-policies",
            Some(serde_json::json!({
                "supi": "imsi-001010000000911",
                "pduSessionId": 6,
                "pduSessionType": "IPV4",
                "dnn": "uav",
                "notificationUri": "http://127.0.0.1:9/nsmf-callback/v1/sm-policy-notify/1",
                "ipv4Address": "10.45.0.92",
                "sliceInfo": { "sst": 1 }
            })),
        ))
        .await;
        assert_eq!(
            resp.status, 201,
            "a provisioned, in-zone UAV session must still be authorised"
        );

        // A position OUTSIDE the provisioned zone is refused.
        std::env::set_var("PCF_UAV_POSITION", "50.0,10.0,90.0");
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-smpolicycontrol/v1/sm-policies",
            Some(serde_json::json!({
                "supi": "imsi-001010000000912",
                "pduSessionId": 7,
                "pduSessionType": "IPV4",
                "dnn": "uav",
                "notificationUri": "http://127.0.0.1:9/nsmf-callback/v1/sm-policy-notify/1",
                "ipv4Address": "10.45.0.93",
                "sliceInfo": { "sst": 1 }
            })),
        ))
        .await;
        assert_eq!(resp.status, 403, "an out-of-zone position must be refused");

        // An inverted zone matches nothing and is refused rather than clamped.
        std::env::set_var("PCF_UAV_POSITION", "37.5,-122.5,90.0");
        std::env::set_var("PCF_UAV_ZONE", "38.0,37.0,-122.0,-123.0");
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-smpolicycontrol/v1/sm-policies",
            Some(serde_json::json!({
                "supi": "imsi-001010000000913",
                "pduSessionId": 8,
                "pduSessionType": "IPV4",
                "dnn": "uav",
                "notificationUri": "http://127.0.0.1:9/nsmf-callback/v1/sm-policy-notify/1",
                "ipv4Address": "10.45.0.94",
                "sliceInfo": { "sst": 1 }
            })),
        ))
        .await;
        assert_eq!(resp.status, 403, "an inverted zone must be refused");

        for k in [
            "PCF_UAV_DNN",
            "PCF_UAV_AUTHORIZATION",
            "PCF_UAV_ZONE",
            "PCF_UAV_POSITION",
        ] {
            std::env::remove_var(k);
        }
    }

    /// AC_TY_CH: an SM policy update whose `accessType` differs from the one the
    /// session was created on notifies a subscriber; re-sending the SAME access
    /// type does not.
    ///
    /// Drives the real create and update handlers, so it covers the baseline
    /// recording at create as well as the comparison at update — the baseline is
    /// what makes "changed" distinguishable from "reported".
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)]
    async fn access_type_change_notifies_a_subscribed_consumer() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pcf_context_init(64, 64);
        let (consumer, notif_uri, recorded) = start_stub_event_consumer().await;

        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-eventexposure/v1/subscriptions",
            Some(event_subsc_body(&notif_uri, "notif-acty", &["AC_TY_CH"])),
        ))
        .await;
        assert_eq!(resp.status, 201);

        // Create the session on 3GPP access.
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-smpolicycontrol/v1/sm-policies",
            Some(serde_json::json!({
                "supi": "imsi-001010000000940",
                "pduSessionId": 11,
                "pduSessionType": "IPV4",
                "dnn": "internet",
                "notificationUri": "http://127.0.0.1:9/nsmf-callback/v1/sm-policy-notify/1",
                "ipv4Address": "10.45.2.10",
                "sliceInfo": { "sst": 1 },
                "accessType": "3GPP_ACCESS"
            })),
        ))
        .await;
        assert_eq!(resp.status, 201);
        let created: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let sm_policy_id = created
            .get("smPolicyId")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| {
                resp.http
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                    .and_then(|(_, v)| v.rsplit('/').next().map(str::to_string))
            })
            .expect("sm policy id");

        // (a) An update on the SAME access type is not a change.
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            &format!("/npcf-smpolicycontrol/v1/sm-policies/{sm_policy_id}/update"),
            Some(serde_json::json!({ "accessType": "3GPP_ACCESS" })),
        ))
        .await;
        assert!(resp.status < 400, "unchanged-access update must succeed");
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            recorded
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "re-sending the same accessType is not an access-type change"
        );

        // (b) A move to non-3GPP access IS the event.
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            &format!("/npcf-smpolicycontrol/v1/sm-policies/{sm_policy_id}/update"),
            Some(serde_json::json!({
                "accessType": "NON_3GPP_ACCESS",
                "ratType": "NR"
            })),
        ))
        .await;
        assert!(resp.status < 400);

        let mut got = Vec::new();
        for _ in 0..100 {
            got = recorded.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if !got.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            got.len(),
            1,
            "one access-type change must notify exactly once"
        );
        assert_eq!(got[0]["notifId"], "notif-acty");
        let n = &got[0]["eventNotifs"][0];
        assert_eq!(n["event"], "AC_TY_CH");
        assert_eq!(n["accType"], "NON_3GPP_ACCESS");
        assert_eq!(n["ratType"], "NR");
        // pduSessionInfo identifies which PDU session moved.
        assert_eq!(n["pduSessionInfo"]["dnn"], "internet");
        assert!(n["timeStamp"].is_string());

        consumer.stop().await.expect("stop stub consumer");
    }

    /// The PCF registers with the NRF exactly ONCE, under the SAME instance id it
    /// published as its self-instance.
    ///
    /// This is the defect the issue did not report: `pcf_sbi_open` PUT its own
    /// profile (with policyauthorization, without allowedNfTypes/ipEndPoints)
    /// while `app.rs` PUT a second one under a second UUID (with allowedNfTypes,
    /// without policyauthorization), so the NRF held two PCF records per startup
    /// and only the second was heartbeaten. Counting PUTs is the only assertion
    /// that fails when a second registration path comes back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)]
    async fn pcf_registers_with_the_nrf_exactly_once_under_its_self_instance_id() {
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pcf_context_init(64, 64);
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);

        let port = nextgcore_sbi::test_support::free_port();
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let nrf = SbiServer::new(SbiServerConfig::new(addr));
        // Every registration PUT, recorded with the id it targeted.
        let puts = std::sync::Arc::new(std::sync::Mutex::new(
            Vec::<(String, serde_json::Value)>::new(),
        ));
        let sink = std::sync::Arc::clone(&puts);
        let handler = move |req: SbiRequest| {
            let sink = std::sync::Arc::clone(&sink);
            async move {
                let path = req.header.uri.split('?').next().unwrap_or("").to_string();
                if req.header.method.as_str() == "PUT"
                    && path.starts_with("/nnrf-nfm/v1/nf-instances/")
                {
                    let id = path.rsplit('/').next().unwrap_or("").to_string();
                    let body = req
                        .http
                        .content
                        .as_deref()
                        .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
                        .unwrap_or(serde_json::Value::Null);
                    sink.lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push((id, body));
                    return SbiResponse::with_status(201);
                }
                SbiResponse::with_status(404)
            }
        };
        nrf.start(handler).await.expect("mock NRF starts");
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // The real startup sequence: open the legacy SBI context, then register.
        let sbi_config = crate::sbi_path::SbiServerConfig {
            addr: "127.0.0.1".to_string(),
            port: 7777,
            tls_enabled: false,
            tls_cert: None,
            tls_key: None,
            nrf_uri: Some(format!("http://127.0.0.1:{port}")),
        };
        crate::sbi_path::pcf_sbi_close();
        crate::sbi_path::pcf_sbi_open(Some(sbi_config)).expect("pcf_sbi_open");

        // pcf_sbi_open publishes the self-instance from a spawned task.
        let mut self_id = None;
        for _ in 0..200 {
            if let Some(inst) = nextgcore_sbi::context::global_context()
                .get_self_instance()
                .await
            {
                self_id = Some(inst.id);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let self_id = self_id.expect("self instance published");

        // Give any stray registration from pcf_sbi_open time to land, so the
        // count below would catch it rather than racing past it.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            puts.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
            "pcf_sbi_open must NOT register: registration happens once, after the \
             SBI listener is up"
        );

        let registered = crate::sbi_path::pcf_register_with_nrf()
            .await
            .expect("registration must not error against a live NRF");
        assert_eq!(
            registered.as_deref(),
            Some(self_id.as_str()),
            "the registered id must be the published self-instance id, so pcfId == nfInstanceId"
        );

        tokio::time::sleep(Duration::from_millis(200)).await;
        let recorded = puts.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(
            recorded.len(),
            1,
            "exactly ONE NFProfile must reach the NRF per startup; got {:?}",
            recorded.iter().map(|(id, _)| id).collect::<Vec<_>>()
        );
        let (put_id, body) = &recorded[0];
        assert_eq!(put_id, &self_id);
        assert_eq!(body["nfInstanceId"], self_id.as_str());
        // The one profile that lands carries BOTH things the two old profiles each
        // had only one of.
        let names: Vec<&str> = body["nfServices"]
            .as_array()
            .expect("nfServices")
            .iter()
            .filter_map(|s| s["serviceName"].as_str())
            .collect();
        assert!(
            names.contains(&"npcf-policyauthorization"),
            "the single profile must advertise policyauthorization, got {names:?}"
        );
        assert!(
            names.contains(&"npcf-eventexposure"),
            "the single profile must advertise eventexposure, got {names:?}"
        );
        let allowed: Vec<&str> = body["allowedNfTypes"]
            .as_array()
            .expect("allowedNfTypes")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(allowed.contains(&"AF") && allowed.contains(&"NEF"));

        nrf.stop().await.expect("stop mock NRF");
        crate::sbi_path::pcf_sbi_close();
    }

    /// A genuine access-type change on the FIRST update after create is
    /// reported — which is what the create-time baseline buys.
    ///
    /// Written after a revert pass: deleting the baseline recording left the
    /// other AC_TY_CH test green, because the first update then merely RECORDS
    /// the access type (`previously_known == false` suppresses the report) and
    /// the second update reports off that. That is real defence in depth against
    /// a FALSE report, but it silently loses a TRUE one: without the baseline, a
    /// session created on 3GPP whose first update moves it to non-3GPP reports
    /// nothing at all. This is the assertion that distinguishes the two.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)]
    async fn first_update_after_create_reports_a_genuine_access_type_change() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pcf_context_init(64, 64);
        let (consumer, notif_uri, recorded) = start_stub_event_consumer().await;

        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-eventexposure/v1/subscriptions",
            Some(event_subsc_body(
                &notif_uri,
                "notif-acty-first",
                &["AC_TY_CH"],
            )),
        ))
        .await;
        assert_eq!(resp.status, 201);

        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-smpolicycontrol/v1/sm-policies",
            Some(serde_json::json!({
                "supi": "imsi-001010000000941",
                "pduSessionId": 12,
                "pduSessionType": "IPV4",
                "dnn": "internet",
                "notificationUri": "http://127.0.0.1:9/nsmf-callback/v1/sm-policy-notify/1",
                "ipv4Address": "10.45.2.11",
                "sliceInfo": { "sst": 1 },
                "accessType": "3GPP_ACCESS"
            })),
        ))
        .await;
        assert_eq!(resp.status, 201);
        let created: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let sm_policy_id = created
            .get("smPolicyId")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| {
                resp.http
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                    .and_then(|(_, v)| v.rsplit('/').next().map(str::to_string))
            })
            .expect("sm policy id");

        // The FIRST update moves the session to non-3GPP access.
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            &format!("/npcf-smpolicycontrol/v1/sm-policies/{sm_policy_id}/update"),
            Some(serde_json::json!({ "accessType": "NON_3GPP_ACCESS" })),
        ))
        .await;
        assert!(resp.status < 400);

        let mut got = Vec::new();
        for _ in 0..100 {
            got = recorded.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if !got.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            got.len(),
            1,
            "a real access-type change on the FIRST update must be reported; \
             without the create-time baseline it is silently swallowed"
        );
        assert_eq!(got[0]["eventNotifs"][0]["event"], "AC_TY_CH");
        assert_eq!(got[0]["eventNotifs"][0]["accType"], "NON_3GPP_ACCESS");

        consumer.stop().await.expect("stop stub consumer");
    }
}

#[cfg(test)]
mod oauth2_h8_tests {
    //! Wave-6 H8 (Phase B) strict-peer OAuth2 enforcement triplet: the real
    //! `pcf_sbi_request_handler` is mounted behind nextgcore-sbi's server-side
    //! OAuth2 verification (TS 33.501 §13.4.1). A missing or wrong-audience
    //! Bearer is rejected (401) before the handler runs; a valid NRF-audience
    //! token (aud=PCF, ES256-signed against the served JWKS) passes through.
    use nextgcore_sbi::client::SbiClient;
    use nextgcore_sbi::message::SbiRequest;
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    use nextgcore_sbi::types::NfType;
    use std::net::SocketAddr;
    use std::time::Duration;

    /// Reserve a loopback port for a test server.
    ///
    /// Delegates to the shared helper: 21 crates each had a private
    /// probe-and-drop copy of this, which is TOCTOU and flaked under parallel
    /// `cargo test`. One implementation means one place to harden.
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
            "iss": "NRF", "sub": "pcf-1", "aud": aud,
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
        super::pcf_context_init(64, 64);
        let port = free_port();
        let mut cfg = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(jwks);
        cfg = cfg.with_expected_audience_nf_type(NfType::Pcf);
        let server = SbiServer::new(cfg);
        server
            .start(super::pcf_sbi_request_handler)
            .await
            .expect("server start");
        (server, port)
    }

    #[test]
    fn test_oauth2_require_knob_parses_and_defaults_off() {
        let dir = std::env::temp_dir();
        let off = dir.join(format!("pcf-h8-off-{}.yaml", std::process::id()));
        std::fs::write(
            &off,
            "pcf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n",
        )
        .unwrap();
        assert!(!super::oauth2_required(off.to_str().unwrap()));
        let on = dir.join(format!("pcf-h8-on-{}.yaml", std::process::id()));
        std::fs::write(&on, "pcf:\n  sbi:\n    oauth2:\n      require: true\n").unwrap();
        assert!(super::oauth2_required(on.to_str().unwrap()));
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
            client.get("/npcf-am-policy-control/v1/policies"),
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
        let token = build_es256_token(&sk, "nrf-es256", "UDM", "npcf-am-policy-control");
        let req = SbiRequest::get("/npcf-am-policy-control/v1/policies")
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
        let token = build_es256_token(&sk, "nrf-es256", "PCF", "npcf-am-policy-control");
        let req = SbiRequest::get("/npcf-am-policy-control/v1/policies/does-not-exist")
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
