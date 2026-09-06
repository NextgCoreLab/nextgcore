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
    let nf_instance_id = uuid::Uuid::new_v4().to_string();
    sbi_path::pcf_self_info_set(sbi_path::PcfSelfInfo {
        sbi_addr: args.sbi_addr.clone(),
        sbi_port: args.sbi_port,
        fqdn: sbi_fqdn.clone(),
        nf_instance_id: nf_instance_id.clone(),
    });

    // Register with NRF and start heartbeat worker
    match register_with_nrf(&args.sbi_addr, args.sbi_port, &nf_instance_id).await {
        Ok(nf_instance_id) if !nf_instance_id.is_empty() => {
            // G2-2: PATCH a real NFProfile "/load" gauge to NRF each heartbeat
            // (policy sessions vs configured capacity; TS 29.510 §5.2.2.3.2).
            nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(nf_instance_id, 5, || {
                let ctx = crate::context::pcf_self();
                let load = ctx.read().map(|c| c.get_load()).unwrap_or(0);
                load.clamp(0, 100) as u8
            });
        }
        Ok(_) => {}
        Err(e) => {
            log::warn!("NRF registration failed (will operate without NRF): {e}");
        }
    }

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
        ("npcf-policyauthorization", "app-sessions", "POST") => {
            // Create App Session
            handle_app_session_create(&request).await
        }
        ("npcf-policyauthorization", "app-sessions", "GET") if parts.len() >= 4 => {
            // Get App Session
            let app_session_id = parts[3];
            handle_app_session_get(app_session_id).await
        }
        ("npcf-policyauthorization", "app-sessions", "DELETE") if parts.len() >= 4 => {
            // Delete App Session
            let app_session_id = parts[3];
            handle_app_session_delete(app_session_id).await
        }
        ("npcf-policyauthorization", "app-sessions", "PATCH") if parts.len() >= 4 => {
            // Modify App Session
            let app_session_id = parts[3];
            handle_app_session_modify(app_session_id, &request).await
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
            // Persist the notification URI so later AM policy update notifies
            // (pcf_sbi_send_am_policy_control_notify) can reach the AMF.
            {
                let mut updated = ue_am.clone();
                updated.notification_uri = Some(notification_uri.to_string());
                if let Ok(context) = ctx.read() {
                    context.ue_am_update(&updated);
                }
            }
            log::info!(
                "AM Policy created for SUPI {} (id={})",
                supi,
                ue_am.association_id
            );

            // Query subscription data for UE-AMBR
            let sub_data = nudr_handler::query_subscription_data_pub(supi);
            let (triggers, ue_ambr) = if let Some(ref sd) = sub_data {
                let mut triggers = Vec::new();
                // Check if subscribed UE-AMBR differs from requested
                if let Some(req_ambr) = policy_data.get("ueAmbr") {
                    let req_up = req_ambr
                        .get("uplink")
                        .and_then(|v| v.as_str())
                        .unwrap_or("0");
                    let req_down = req_ambr
                        .get("downlink")
                        .and_then(|v| v.as_str())
                        .unwrap_or("0");
                    if req_up != format_bitrate(sd.ambr_uplink)
                        || req_down != format_bitrate(sd.ambr_downlink)
                    {
                        triggers.push("UE_AMBR_CH");
                    }
                }
                let ambr = serde_json::json!({
                    "uplink": format_bitrate(sd.ambr_uplink),
                    "downlink": format_bitrate(sd.ambr_downlink),
                });
                (triggers, Some(ambr))
            } else {
                (vec![], None)
            };

            let mut resp = serde_json::json!({
                "polAssoId": ue_am.association_id,
                "supi": supi,
                "triggers": triggers,
                "servAreaRes": null,
                "rfsp": null,
                // TS 29.507 §5.8: suppFeat is mandatory in PolicyAssociation and
                // is the negotiated (consumer ∩ producer) value (pcfd-05).
                "suppFeat": negotiate_features(Some(supp_feat), PCF_AM_POLICY_SUPPORTED_FEATURES),
            });
            if let Some(ambr) = ue_ambr {
                resp["ueAmbr"] = ambr;
            }

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
            .with_json_body(&serde_json::json!({
                "polAssoId": ue_am.association_id,
                "supi": ue_am.supi,
                "triggers": [],
            }))
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

    let _update_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let ctx = pcf_self();
    let ue_am = if let Ok(context) = ctx.read() {
        context.ue_am_find_by_association_id(pol_asso_id)
    } else {
        None
    };

    match ue_am {
        Some(ue_am) => SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({
                "polAssoId": ue_am.association_id,
                "supi": ue_am.supi,
                "triggers": [],
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("AM Policy {pol_asso_id} not found"),
            Some("POLICY_NOT_FOUND"),
        ),
    }
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

    if ue_policy::apply_ue_policy_ul_container(pol_asso_id, &part.data)
        == ue_policy::UePolicyResultOutcome::UnknownAssociation
    {
        log::warn!(
            "[{pol_asso_id}] UE policy notify: unknown association; dropping N1MessageNotify"
        );
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

    let mut uav = UavPolicyAuthorization::new(supi);
    uav.min_altitude_limit = 0.0;
    uav.max_altitude_limit = max_altitude;
    // A permitted (unrestricted) flight zone covering the configured geofence.
    let mut zone = UavFlightZone::new("uav-default-zone", UavFlightZoneType::Unrestricted);
    zone.min_latitude = 37.0;
    zone.max_latitude = 38.0;
    zone.min_longitude = -123.0;
    zone.max_longitude = -122.0;
    zone.min_altitude = 0.0;
    zone.max_altitude = max_altitude;
    uav.add_flight_zone(zone);
    uav.grant_authorization("CAA-PCF-DEFAULT", 3600);

    // Flight position to gate against (lat, lon, alt). Default: in-zone.
    let (lat, lon, alt) = std::env::var("PCF_UAV_POSITION")
        .ok()
        .and_then(|v| {
            let p: Vec<f64> = v.split(',').filter_map(|s| s.trim().parse().ok()).collect();
            if p.len() == 3 {
                Some((p[0], p[1], p[2]))
            } else {
                None
            }
        })
        .unwrap_or((37.5, -122.5, max_altitude.min(100.0)));

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
        Some(
            SbiResponse::with_status(403)
                .with_json_body(&serde_json::json!({
                    "title": "UAV flight policy violation",
                    "status": 403,
                    "cause": "UAV_FLIGHT_NOT_AUTHORIZED",
                    "detail": format!(
                        "UAV position ({lat}, {lon}) alt={alt}m outside authorized flight policy"
                    ),
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(403)),
        )
    }
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
            let mut decision = decision;
            if let Some(ref d) = udr_dnn_data {
                let online = d.get("online").and_then(|v| v.as_bool());
                let offline = d.get("offline").and_then(|v| v.as_bool());
                if online.is_some() || offline.is_some() {
                    if let Some(map) = decision.chg_decs.as_object_mut() {
                        for (_id, chg) in map.iter_mut() {
                            if let Some(o) = online {
                                chg["online"] = serde_json::json!(o);
                            }
                            if let Some(o) = offline {
                                chg["offline"] = serde_json::json!(o);
                            }
                        }
                    }
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
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "smPolicyId": sess.sm_policy_id,
                    "pduSessionId": sess.psi,
                    "sessRules": decision.sess_rules,
                    "pccRules": decision.pcc_rules,
                    "qosDecs": decision.qos_decs,
                    "chgDecs": decision.chg_decs,
                    "traffContDecs": decision.traff_cont_decs,
                    "policyCtrlReqTriggers": decision.triggers,
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
    AscReqData {
        supp_feat: root
            .get("suppFeat")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        notif_uri: root
            .get("notifUri")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        med_components,
    }
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

    // Bind the AF session to the PCC session via the UE IP (TS 29.514
    // AppSessionContextReqData.ueIpv4) so AF-triggered PCC rule changes can
    // be pushed to the SMF.
    let ue_ipv4 = req_root.get("ueIpv4").and_then(|v| v.as_str());
    let ctx = pcf_self();
    let bound_sess = ue_ipv4.and_then(|ip| {
        ctx.read()
            .ok()
            .and_then(|context| context.sess_find_by_ipv4addr(ip))
    });

    let app = bound_sess.as_ref().and_then(|sess| {
        ctx.read().ok().and_then(|context| {
            context.app_add(sess.id).map(|app0| {
                let mut app = app0;
                app.notif_uri = notif_uri.clone();
                context.app_update(&app);
                app
            })
        })
    });

    let app_session_id = app
        .as_ref()
        .map(|a| a.app_session_id.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

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
        } else {
            log::warn!(
                "App session create with medComponents but no PCC session bound to ueIpv4={ue_ipv4:?}"
            );
        }
    } else if let Some(ref sess) = bound_sess {
        // Backward-compat (no medComponents): bind + generic notify, as today.
        pcf_sbi_send_smpolicycontrol_update_notify(sess.id);
    } else if ue_ipv4.is_some() {
        log::warn!("App session create: no PCC session bound to ueIpv4={ue_ipv4:?}");
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

/// Register PCF with NRF.
///
/// `nf_instance_id` is generated once in `main` (also published via
/// `sbi_path::pcf_self_info_set` so PcfBinding registrations carry the same
/// `pcfId`, WSB-1). Returns the NF instance ID on success so the caller can
/// start a heartbeat worker.
async fn register_with_nrf(
    sbi_addr: &str,
    sbi_port: u16,
    nf_instance_id: &str,
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

    log::info!("Registering PCF with NRF at {nrf_uri}");

    let (nrf_host, nrf_port) = parse_nrf_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_profile = serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "PCF",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [
            {
                "serviceInstanceId": format!("{nf_instance_id}-npcf-am-policy-control"),
                "serviceName": "npcf-am-policy-control",
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
            },
            {
                "serviceInstanceId": format!("{nf_instance_id}-npcf-smpolicycontrol"),
                "serviceName": "npcf-smpolicycontrol",
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
            },
            {
                "serviceInstanceId": format!("{nf_instance_id}-npcf-ue-policy-control"),
                "serviceName": "npcf-ue-policy-control",
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
            }
        ],
        "allowedNfTypes": ["AMF", "SMF", "SCP"],
        "heartBeatTimer": 10
    });

    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    let response = client
        .put_json(&path, &nf_profile)
        .await
        .map_err(|e| format!("NRF registration request failed: {e}"))?;

    match response.status {
        200 | 201 => {
            log::info!("PCF registered with NRF successfully (id={nf_instance_id})");
            Ok(nf_instance_id.to_string())
        }
        _ => Err(format!(
            "NRF registration returned status {}",
            response.status
        )),
    }
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
        let req = match method {
            "GET" => SbiRequest::get(uri),
            "DELETE" => SbiRequest::delete(uri),
            _ => SbiRequest::post(uri),
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

    /// pcfd-02 backward-compat: an app-session create WITHOUT medComponents
    /// behaves exactly as before — bind + suppFeat echo, no ascReqData/Resp.
    #[tokio::test]
    async fn app_session_create_without_media_components_is_backward_compatible() {
        pcf_context_init(64, 64);
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
    #[tokio::test]
    async fn app_session_create_emergency_emits_asc_resp_data() {
        pcf_context_init(64, 64);
        let resp = pcf_sbi_request_handler(make_request(
            "POST",
            "/npcf-policyauthorization/v1/app-sessions",
            Some(serde_json::json!({
                "notifUri": "http://127.0.0.1:9/af-notif/3",
                "suppFeat": "0",
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
            got["sessRules"].as_object().is_some_and(|m| !m.is_empty()),
            "GET must return non-empty sessRules"
        );
        assert!(
            got["pccRules"].as_object().is_some_and(|m| !m.is_empty()),
            "GET must return non-empty pccRules"
        );
        assert!(got["qosDecs"].as_object().is_some_and(|m| !m.is_empty()));
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
