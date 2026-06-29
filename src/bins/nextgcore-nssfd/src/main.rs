//! NextGCore NSSF (Network Slice Selection Function)
//!
//! The NSSF is a 5G core network function responsible for:
//! - Selecting the Network Slice instances to serve the UE
//! - Determining the allowed NSSAI and mapping to subscribed S-NSSAIs
//! - Determining the AMF Set to be used to serve the UE
//!
//! External API per 3GPP TS 29.531:
//! - Nnssf_NSSelection v2: GET /nnssf-nsselection/v2/network-slice-information
//! - Nnssf_NSSAIAvailability v1: /nnssf-nssaiavailability/v1/nssai-availability/...

use anyhow::{Context, Result};
use clap::Parser;
use ogs_sbi::client::{SbiClient, SbiClientConfig};
use ogs_sbi::message::{SbiRequest, SbiResponse};
use ogs_sbi::oauth::{JwksCache, OAuth2Client};
use ogs_sbi::server::{send_method_not_allowed, SbiServer, SbiServerConfig as OgsSbiServerConfig};
use ogs_sbi::types::NfType;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

mod context;
mod event;
mod json_patch;
mod nnrf_handler;
mod nnssf_build;
mod nnssf_handler;
mod nsacf;
mod nssf_sm;
mod sbi_path;
mod sbi_response;
mod timer;

pub use context::*;
pub use event::{
    EventSbiRequest, EventSbiResponse, NssfEvent, NssfEventId, NssfTimerId, SbiEventData,
    SbiMessage,
};
pub use nnrf_handler::*;
pub use nnssf_build::*;
pub use nnssf_handler::*;
pub use nssf_sm::{NssfSmContext, NssfState};
pub use sbi_path::*;
pub use timer::{timer_manager, NssfTimerManager};

/// NextGCore NSSF - Network Slice Selection Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-nssfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Network Slice Selection Function", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/nssf.yaml")]
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

    /// Maximum number of NF instances
    #[arg(long, default_value = "512")]
    max_nf: usize,

    /// Target AMF Set ID for AMF re-selection
    /// (format <MCC>-<MNC>-<RegionId>-<SetId>, TS 29.531 targetAmfSet)
    #[arg(long)]
    target_amf_set: Option<String>,

    /// Path to the JSON snapshot file for NSSAI-availability subscriptions and
    /// availability data. When unset (the default) these are purely in-memory
    /// and lost on restart. Also settable via NEXTGCORE_NSSF_STATE_FILE.
    #[arg(long)]
    state_file: Option<String>,
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

/// SBI OAuth2 enforcement knob (`nssf.sbi.oauth2.require`).
///
/// Defaults to disabled so the existing dev/E2E path keeps working without
/// tokens; the production/docker `nssf-oauth2.yaml` variant sets it true.
#[derive(Debug, Default, Deserialize)]
struct SbiOauth2Yaml {
    require: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct SbiYaml {
    server: Option<Vec<SbiServerYaml>>,
    client: Option<SbiClientYaml>,
    oauth2: Option<SbiOauth2Yaml>,
}

/// Process-wide OAuth2 client for automatic Bearer-token acquisition on
/// outbound SBI calls (set only when `nssf.sbi.oauth2.require` is true).
static OAUTH2_CLIENT: OnceLock<Option<Arc<OAuth2Client>>> = OnceLock::new();

/// The shared OAuth2 client, if SBI OAuth2 enforcement is enabled. Outbound
/// SBI clients attach tokens via [`attach_oauth2`].
fn oauth2_client() -> Option<Arc<OAuth2Client>> {
    OAUTH2_CLIENT.get().and_then(|opt| opt.clone())
}

/// Attach the process-wide OAuth2 client (when enforcement is on) so the
/// outbound request carries an NRF-issued Bearer token scoped to `target`.
/// A no-op (returns the client unchanged) when enforcement is off.
fn attach_oauth2(client: SbiClient, target: NfType) -> SbiClient {
    match oauth2_client() {
        Some(oauth2) => client.with_oauth2(oauth2, target),
        None => client,
    }
}

/// A single configured S-NSSAI (`{ sst: <u8>, sd: "<6 hex>" }`), used by the
/// optional PLMN-supported-S-NSSAI restriction (nssfd-01).
#[derive(Debug, Default, Deserialize)]
struct SnssaiYaml {
    sst: u8,
    sd: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct NssfSection {
    sbi: Option<SbiYaml>,
    /// Target AMF Set ID used for AMF re-selection in registration scenarios
    amf_set_id: Option<String>,
    /// Optional explicit set of S-NSSAIs supported in this PLMN
    /// (TS 29.531 §6.2.3.2.3.1). ABSENT (the default) => NO restriction =>
    /// allow-all (matched-sim back-compat). When present, an NSSAIAvailability
    /// PUT/PATCH reporting an S-NSSAI outside this set is rejected with 403
    /// SNSSAI_NOT_SUPPORTED.
    supported_snssai_list: Option<Vec<SnssaiYaml>>,
}

#[derive(Debug, Default, Deserialize)]
struct NssfYaml {
    nssf: Option<NssfSection>,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Notification client timeouts (bounded; callbacks must not hang the NSSF)
const NOTIFY_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const NOTIFY_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = Args::parse();

    // Initialize logging
    init_logging(&args)?;
    // G32/G43: Initialize OpenTelemetry tracing (Jaeger/OTLP exporter)
    let _otel = ogs_metrics::otel::init_otel(
        ogs_metrics::otel::OtelConfig::new(env!("CARGO_PKG_NAME")).with_endpoint(
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://jaeger:4317".to_string()),
        ),
    )
    .ok();

    log::info!("NextGCore NSSF v{} starting...", env!("CARGO_PKG_VERSION"));

    // Handle kill flag
    if args.kill {
        log::info!("Kill flag set - would send SIGTERM to running instance");
        return Ok(());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialise the NSSF context, optionally restoring persisted
    // NSSAI-availability subscriptions and availability data. Path precedence:
    // --state-file, then NEXTGCORE_NSSF_STATE_FILE. With neither set the
    // context stays purely in-memory (previous behaviour). This must run before
    // nssf_context_init() so the persisting context backs the singleton.
    let nssf_state_file = args
        .state_file
        .clone()
        .or_else(|| std::env::var("NEXTGCORE_NSSF_STATE_FILE").ok())
        .filter(|s| !s.is_empty());
    match &nssf_state_file {
        Some(path) => {
            nssf_context_init_with_state(Some(std::path::PathBuf::from(path)));
            log::info!("NSSF availability persistence enabled: {path}");
        }
        None => {
            nssf_context_init_with_state(None);
            log::info!("NSSF availability persistence disabled (in-memory only)");
        }
    }

    // Initialize NSSF context
    nssf_context_init(args.max_nf);
    log::info!("NSSF context initialized (max_nf={})", args.max_nf);

    // Initialize NSSF state machine
    let mut nssf_sm = NssfSmContext::new();
    nssf_sm.init();
    log::info!("NSSF state machine initialized");

    // Parse configuration (if file exists) and seed NRF URI
    let mut nrf_uri_cfg: Option<String> = None;
    let mut require_oauth2 = false;
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
        match std::fs::read_to_string(&args.config) {
            Ok(content) => {
                log::debug!("Configuration file loaded ({} bytes)", content.len());
                // Seed NRF URI into SBI context for NF registration
                if let Ok(yaml) = serde_yaml::from_str::<NssfYaml>(&content) {
                    if let Some(nssf) = yaml.nssf {
                        if let Some(set_id) = nssf.amf_set_id {
                            log::info!("Target AMF Set configured: {set_id}");
                            if let Ok(ctx) = nssf_self().read() {
                                ctx.set_target_amf_set(&set_id);
                            }
                        }
                        // nssfd-01: optional PLMN-supported S-NSSAI restriction.
                        // When ABSENT (the default) the NSSF imposes no
                        // restriction (allow-all, matched-sim back-compat); when
                        // present, an availability update reporting an S-NSSAI
                        // outside this set is rejected with 403
                        // SNSSAI_NOT_SUPPORTED (TS 29.531 §6.2.3.2.3.1).
                        if let Some(list) = nssf.supported_snssai_list {
                            let snssais: Vec<context::SNssai> = list
                                .iter()
                                .map(|s| {
                                    let sd = s
                                        .sd
                                        .as_deref()
                                        .and_then(|h| u32::from_str_radix(h, 16).ok())
                                        .and_then(|v| if v == 0xFF_FFFF { None } else { Some(v) });
                                    context::SNssai::new(s.sst, sd)
                                })
                                .collect();
                            log::info!(
                                "PLMN-supported S-NSSAI restriction configured: {} entries",
                                snssais.len()
                            );
                            if let Ok(ctx) = nssf_self().read() {
                                ctx.set_plmn_supported_snssais(Some(snssais));
                            }
                        }
                        if let Some(sbi) = nssf.sbi {
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
                                        nrf_uri_cfg = Some(nrf.uri.clone());
                                        ogs_sbi::context::global_context()
                                            .set_nrf_uri(&nrf.uri)
                                            .await;
                                    }
                                }
                            }
                            // SBI OAuth2 enforcement knob (nssf.sbi.oauth2.require).
                            require_oauth2 =
                                sbi.oauth2.and_then(|o| o.require).unwrap_or(false);
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

    // CLI flag overrides the YAML target AMF set
    if let Some(ref set_id) = args.target_amf_set {
        if let Ok(ctx) = nssf_self().read() {
            ctx.set_target_amf_set(set_id);
        }
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
    nssf_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;

    // Start actual HTTP/2 SBI server using ogs-sbi
    let sbi_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let mut sbi_server_config = OgsSbiServerConfig::new(sbi_addr);
    if require_oauth2 {
        // Server side (TS 33.501 §13.4.1): verify incoming Bearer tokens
        // against the NRF's published JWKS and require the token's `aud` to
        // include this NF's own type ("NSSF"). With no NRF URI configured the
        // server fails closed (503).
        sbi_server_config.require_oauth2 = true;
        sbi_server_config.oauth2_jwks_uri = nrf_uri_cfg
            .as_deref()
            .map(|uri| JwksCache::for_nrf(uri).jwks_uri().to_string());
        sbi_server_config =
            sbi_server_config.with_expected_audience_nf_type(NfType::Nssf);

        // Client side (T1.1): install the process-wide OAuth2 client so
        // outbound SBI calls acquire and attach an NRF-issued Bearer token.
        if let Some(nrf_uri) = nrf_uri_cfg.as_deref() {
            let nf_instance_id = format!("nssf-{}", uuid::Uuid::new_v4());
            let oauth2 = Arc::new(OAuth2Client::new(nrf_uri, nf_instance_id, NfType::Nssf));
            let _ = OAUTH2_CLIENT.set(Some(oauth2));
        }
        log::info!(
            "OAuth2 enforcement enabled (JWKS: {})",
            sbi_server_config
                .oauth2_jwks_uri
                .as_deref()
                .unwrap_or("UNCONFIGURED")
        );
    }
    let sbi_server = SbiServer::new(sbi_server_config);

    sbi_server
        .start(nssf_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    log::info!("SBI HTTP/2 server listening on {sbi_addr}");

    // Register with NRF (B24.3)
    match register_with_nrf(&args.sbi_addr, args.sbi_port).await {
        Ok(nf_instance_id) if !nf_instance_id.is_empty() => {
            ogs_sbi::heartbeat::spawn_heartbeat_worker(nf_instance_id, 5);
        }
        Ok(_) => {}
        Err(e) => {
            log::warn!("NRF registration failed (will operate without NRF): {e}");
        }
    }

    // Discover H-NSSF instances from NRF
    if let Err(e) = discover_nf_from_nrf("NSSF", "nnssf-nsselection").await {
        log::warn!("H-NSSF discovery failed (will retry on demand): {e}");
    }

    log::info!("NextGCore NSSF ready");

    // Main event loop (async)
    run_event_loop_async(&mut nssf_sm, shutdown).await?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Stop SBI server
    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;
    log::info!("SBI HTTP/2 server stopped");

    // Close legacy SBI server
    nssf_sbi_close();
    log::info!("SBI server closed");

    // Cleanup state machine
    nssf_sm.fini();
    log::info!("NSSF state machine finalized");

    // Cleanup context
    nssf_context_final();
    log::info!("NSSF context finalized");

    log::info!("NextGCore NSSF stopped");
    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/// Run a closure against the global NSSF context read guard, returning None
/// if the lock is poisoned. Keeps guard lifetimes contained (no guard ever
/// crosses an `.await` or another lock acquisition).
fn with_nssf_context<T>(f: impl FnOnce(&NssfContext) -> T) -> Option<T> {
    let ctx = nssf_self();
    let result = ctx.read().ok().map(|guard| f(&guard));
    result
}

/// Build a TS 29.500 ProblemDetails error response
/// (`application/problem+json`, RFC 7807).
fn problem_details(status: u16, title: &str, detail: &str, cause: Option<&str>) -> SbiResponse {
    let mut body = serde_json::json!({
        "type": "about:blank",
        "title": title,
        "status": status,
        "detail": detail,
    });
    if let Some(c) = cause {
        body["cause"] = serde_json::json!(c);
    }
    SbiResponse::with_status(status).with_body(body.to_string(), "application/problem+json")
}

/// Percent-decode a URI component (RFC 3986; does not treat '+' as space)
fn percent_decode(s: &str) -> String {
    fn hex_val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse the query string of a request URI into percent-decoded key/values
fn parse_query_params(uri: &str) -> HashMap<String, String> {
    let query = match uri.split_once('?') {
        Some((_, q)) => q,
        None => return HashMap::new(),
    };
    query
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (percent_decode(k), percent_decode(v))
        })
        .collect()
}

/// Split an absolute URI into (host, port, path-with-query)
fn split_uri(uri: &str) -> Option<(String, u16, String)> {
    let (scheme_default_port, rest) = if let Some(r) = uri.strip_prefix("https://") {
        (443u16, r)
    } else if let Some(r) = uri.strip_prefix("http://") {
        (80u16, r)
    } else {
        (80u16, uri)
    };
    let (host_port, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        Some((host.to_string(), port_str.parse().ok()?, path))
    } else {
        Some((host_port.to_string(), scheme_default_port, path))
    }
}

// ---------------------------------------------------------------------------
// SBI routing
// ---------------------------------------------------------------------------

/// SBI request handler for NSSF
async fn nssf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.clone();
    let method = method.as_str();
    let uri = request.header.uri.clone();

    log::debug!("NSSF SBI request: {method} {uri}");

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(&uri);
    let parts: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    if parts.len() < 2 {
        return problem_details(404, "Not Found", "Invalid resource path", None);
    }

    let service = parts[0];
    let version = parts[1];

    match service {
        // NS Selection Service (TS 29.531 §6.1: API version is v2)
        "nnssf-nsselection" => {
            if version != "v2" {
                return problem_details(
                    404,
                    "Not Found",
                    &format!("Unsupported API version '{version}' (nnssf-nsselection uses v2)"),
                    None,
                );
            }
            match (parts.get(2).copied(), method) {
                (Some("network-slice-information"), "GET") if parts.len() == 3 => {
                    handle_ns_selection(&request).await
                }
                (Some("network-slice-information"), _) => {
                    send_method_not_allowed(method, "network-slice-information")
                }
                _ => problem_details(404, "Not Found", "Unknown nnssf-nsselection resource", None),
            }
        }

        // NSSAI Availability Service (TS 29.531 §6.2: API version is v1)
        "nnssf-nssaiavailability" => {
            if version != "v1" {
                return problem_details(
                    404,
                    "Not Found",
                    &format!(
                        "Unsupported API version '{version}' (nnssf-nssaiavailability uses v1)"
                    ),
                    None,
                );
            }
            if parts.get(2).copied() != Some("nssai-availability") {
                return problem_details(
                    404,
                    "Not Found",
                    "Unknown nnssf-nssaiavailability resource",
                    None,
                );
            }
            match (parts.len(), parts.get(3).copied(), method) {
                // OPTIONS /nssai-availability (store-level discovery)
                (3, None, "OPTIONS") => handle_nssai_availability_options().await,
                // Subscriptions collection
                (4, Some("subscriptions"), "POST") => handle_subscription_create(&request).await,
                (4, Some("subscriptions"), m) => send_method_not_allowed(m, "subscriptions"),
                (5, Some("subscriptions"), "DELETE") => handle_subscription_delete(parts[4]).await,
                (5, Some("subscriptions"), "PATCH") => {
                    handle_subscription_patch(parts[4], &request).await
                }
                (5, Some("subscriptions"), m) => {
                    send_method_not_allowed(m, "subscriptions/{subscriptionId}")
                }
                // Per-NF availability document
                (4, Some(nf_id), "PUT") => handle_nssai_availability_update(nf_id, &request).await,
                (4, Some(nf_id), "PATCH") => handle_nssai_availability_patch(nf_id, &request).await,
                (4, Some(nf_id), "DELETE") => handle_nssai_availability_delete(nf_id).await,
                (4, Some(_), m) => send_method_not_allowed(m, "nssai-availability/{nfId}"),
                _ => problem_details(
                    404,
                    "Not Found",
                    "Unknown nssai-availability resource",
                    None,
                ),
            }
        }

        _ => {
            log::warn!("Unknown NSSF request: {method} {uri}");
            problem_details(
                404,
                "Not Found",
                &format!("Unknown service: {service}"),
                None,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// NS Selection (TS 29.531 §5.2: Nnssf_NSSelection v2)
// ---------------------------------------------------------------------------

async fn handle_ns_selection(request: &SbiRequest) -> SbiResponse {
    // The ogs-sbi server glue strips the query string from header.uri and
    // stores the RAW (still percent-encoded) values in http.params, so
    // decode on access. parse_query_params covers callers that kept the
    // full URI (e.g. direct handler invocation).
    let query = parse_query_params(&request.header.uri);
    let get_param = |k: &str| -> Option<String> {
        query
            .get(k)
            .cloned()
            .or_else(|| request.http.params.get(k).map(|v| percent_decode(v)))
    };

    // nf-type and nf-id are mandatory query parameters (TS 29.531 §6.1.3.2.3.1)
    let nf_type = get_param("nf-type");
    let nf_id = get_param("nf-id");
    let mut missing: Vec<&str> = Vec::new();
    if nf_type.is_none() {
        missing.push("nf-type");
    }
    if nf_id.is_none() {
        missing.push("nf-id");
    }
    if !missing.is_empty() {
        return problem_details(
            400,
            "Bad Request",
            &format!(
                "Missing mandatory query parameter(s): {}",
                missing.join(", ")
            ),
            Some("MANDATORY_QUERY_PARAM_MISSING"),
        );
    }
    let nf_id = nf_id.expect("checked above");
    let nf_type = nf_type.expect("checked above");

    let tai = get_param("tai")
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| context::tai_from_json(&v));

    // Exactly one slice-info-request-for-* parameter drives the scenario
    let sir = get_param("slice-info-request-for-registration");
    let sip = get_param("slice-info-request-for-pdu-session");
    let sicu = get_param("slice-info-request-for-ue-cu");

    if let Some(raw) = sir.or(sicu) {
        // Registration and UE-configuration-update use the same authorization
        // algorithm (SliceInfoForUEConfigurationUpdate is a subset).
        let info_json: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                return problem_details(
                    400,
                    "Bad Request",
                    &format!("Invalid slice-info-request JSON: {e}"),
                    Some("INVALID_QUERY_PARAM"),
                )
            }
        };
        return handle_ns_selection_registration(&nf_id, &info_json, tai.as_ref());
    }

    if let Some(raw) = sip {
        let info_json: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                return problem_details(
                    400,
                    "Bad Request",
                    &format!("Invalid slice-info-request-for-pdu-session JSON: {e}"),
                    Some("INVALID_QUERY_PARAM"),
                )
            }
        };
        let supi = get_param("supi");
        return handle_ns_selection_pdu_session(
            &nf_id,
            &nf_type,
            &info_json,
            tai.as_ref(),
            supi,
            get_param("home-plmn-id"),
        )
        .await;
    }

    problem_details(
        400,
        "Bad Request",
        "One of slice-info-request-for-registration, slice-info-request-for-pdu-session or \
         slice-info-request-for-ue-cu is required",
        Some("MANDATORY_QUERY_PARAM_MISSING"),
    )
}

/// Parse a SliceInfoForRegistration / SliceInfoForUEConfigurationUpdate document
fn parse_registration_slice_info(v: &serde_json::Value) -> nnssf_handler::RegistrationSliceInfo {
    let mut info = nnssf_handler::RegistrationSliceInfo::default();

    if let Some(subs) = v.get("subscribedNssai").and_then(|x| x.as_array()) {
        for s in subs {
            if let Some(snssai) = s
                .get("subscribedSnssai")
                .and_then(context::snssai_from_json)
            {
                let default_ind = s
                    .get("defaultIndication")
                    .and_then(|d| d.as_bool())
                    .unwrap_or(false);
                info.subscribed.push((snssai, default_ind));
            }
        }
    }
    if let Some(req) = v.get("requestedNssai").and_then(|x| x.as_array()) {
        info.requested = req.iter().filter_map(context::snssai_from_json).collect();
    }
    info.default_configured_ind = v
        .get("defaultConfiguredSnssaiInd")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    if let Some(maps) = v.get("mappingOfNssai").and_then(|x| x.as_array()) {
        for m in maps {
            if let (Some(serving), Some(home)) = (
                m.get("servingSnssai").and_then(context::snssai_from_json),
                m.get("homeSnssai").and_then(context::snssai_from_json),
            ) {
                info.mapping_of_nssai.push((serving, home));
            }
        }
    }
    info
}

/// Registration-scenario NS selection (TS 29.531 §5.2.3.2.3)
fn handle_ns_selection_registration(
    nf_id: &str,
    info_json: &serde_json::Value,
    tai: Option<&context::Tai>,
) -> SbiResponse {
    let info = parse_registration_slice_info(info_json);

    if info.subscribed.is_empty() && info.requested.is_empty() {
        return problem_details(
            400,
            "Bad Request",
            "sliceInfoRequestForRegistration must contain subscribedNssai and/or requestedNssai",
            Some("MANDATORY_IE_MISSING"),
        );
    }

    // Snapshot everything we need from the context, then drop the guard
    // BEFORE doing any further work (lock-order rule: never hold a context
    // guard while taking other locks or awaiting).
    let snapshot = {
        let ctx = nssf_self();
        let context = match ctx.read() {
            Ok(c) => c,
            Err(_) => {
                return problem_details(500, "Internal Server Error", "context lock poisoned", None)
            }
        };
        let supported_for_tai = match tai {
            Some(t) if context.has_availability_data() => {
                Some(context.get_supported_snssai_for_tai(t))
            }
            _ => None,
        };
        let target_amf_set = context.get_target_amf_set().or_else(|| {
            // Derive a syntactically valid fallback from the UE's serving PLMN
            tai.map(|t| format!("{}-{}-01-001", t.plmn_id.mcc, t.plmn_id.mnc))
        });
        nnssf_handler::RegistrationContextSnapshot {
            supported_for_tai,
            per_nf_support: context.per_nf_supported_snssais(),
            nsi_info: context
                .nsi_get_all()
                .iter()
                .map(|n| (n.s_nssai.clone(), n.nrf_id.clone(), n.nsi_id.clone()))
                .collect(),
            target_amf_set,
        }
    };

    let sel = nnssf_handler::nssf_nsselection_handle_registration(nf_id, &info, &snapshot);

    // Assemble AuthorizedNetworkSliceInfo
    let mut response = serde_json::json!({ "supportedFeatures": "1" });

    if !sel.allowed.is_empty() {
        let allowed_list: Vec<serde_json::Value> = sel
            .allowed
            .iter()
            .map(|(snssai, nsi, mapped)| {
                let mut item = serde_json::json!({
                    "allowedSnssai": context::snssai_to_json(snssai)
                });
                if let Some((nrf_id, nsi_id)) = nsi {
                    item["nsiInformationList"] =
                        serde_json::json!([{ "nrfId": nrf_id, "nsiId": nsi_id }]);
                }
                if let Some(home) = mapped {
                    item["mappedHomeSnssai"] = context::snssai_to_json(home);
                }
                item
            })
            .collect();
        response["allowedNssaiList"] = serde_json::json!([{
            "allowedSnssaiList": allowed_list,
            "accessType": "3GPP_ACCESS"
        }]);
    }

    if !sel.configured.is_empty() {
        let configured: Vec<serde_json::Value> = sel
            .configured
            .iter()
            .map(|(snssai, mapped)| {
                let mut item = serde_json::json!({
                    "configuredSnssai": context::snssai_to_json(snssai)
                });
                if let Some(home) = mapped {
                    item["mappedHomeSnssai"] = context::snssai_to_json(home);
                }
                item
            })
            .collect();
        response["configuredNssai"] = serde_json::json!(configured);
    }

    if !sel.rejected_in_plmn.is_empty() {
        response["rejectedNssaiInPlmn"] = serde_json::json!(sel
            .rejected_in_plmn
            .iter()
            .map(context::snssai_to_json)
            .collect::<Vec<_>>());
    }
    if !sel.rejected_in_ta.is_empty() {
        response["rejectedNssaiInTa"] = serde_json::json!(sel
            .rejected_in_ta
            .iter()
            .map(context::snssai_to_json)
            .collect::<Vec<_>>());
    }

    if !sel.candidate_amf_list.is_empty() {
        response["candidateAmfList"] = serde_json::json!(sel.candidate_amf_list);
        if let Some(set) = sel.target_amf_set {
            response["targetAmfSet"] = serde_json::json!(set);
        }
    }

    SbiResponse::with_status(200)
        .with_json_body(&response)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Map TS 29.531 RoamingIndication enum string
fn roaming_indication_from_str(s: &str) -> Option<context::RoamingIndication> {
    match s {
        "NON_ROAMING" => Some(context::RoamingIndication::NonRoaming),
        "LOCAL_BREAKOUT" => Some(context::RoamingIndication::LocalBreakout),
        "HOME_ROUTED" => Some(context::RoamingIndication::HomeRouted),
        _ => None,
    }
}

/// PDU-session-scenario NS selection (TS 29.531 §5.2.3.2.4)
async fn handle_ns_selection_pdu_session(
    nf_id: &str,
    nf_type: &str,
    si_json: &serde_json::Value,
    tai: Option<&context::Tai>,
    supi: Option<String>,
    home_plmn_id: Option<String>,
) -> SbiResponse {
    // sNssai and roamingIndication are mandatory in SliceInfoForPDUSession
    let snssai = match si_json.get("sNssai").and_then(context::snssai_from_json) {
        Some(s) => s,
        None => {
            return problem_details(
                400,
                "Bad Request",
                "sliceInfoRequestForPduSession.sNssai is mandatory",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };
    let roaming = match si_json.get("roamingIndication") {
        Some(serde_json::Value::String(s)) => match roaming_indication_from_str(s) {
            Some(r) => r,
            None => {
                return problem_details(
                    400,
                    "Bad Request",
                    &format!("Invalid roamingIndication '{s}'"),
                    Some("INVALID_IE_VALUE"),
                )
            }
        },
        _ => {
            return problem_details(
                400,
                "Bad Request",
                "sliceInfoRequestForPduSession.roamingIndication is mandatory",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };

    let mut param = nnssf_handler::NsSelectionParam {
        nf_id: Some(nf_id.to_string()),
        nf_type: Some(nf_type.to_string()),
        slice_info_for_pdu_session: nnssf_handler::SliceInfoForPduSession {
            presence: true,
            snssai: Some(snssai.clone()),
            roaming_indication: roaming,
        },
        tai: tai.cloned(),
        ..Default::default()
    };

    if let Some(hp) = home_plmn_id
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .or_else(|| si_json.get("homePlmnId").cloned())
    {
        if let (Some(mcc), Some(mnc)) = (
            hp.get("mcc").and_then(|v| v.as_str()),
            hp.get("mnc").and_then(|v| v.as_str()),
        ) {
            param.home_plmn_id = Some(context::PlmnId::new(mcc, mnc));
        }
    }
    if let Some(hs) = si_json
        .get("homeSnssai")
        .and_then(context::snssai_from_json)
    {
        param.home_snssai = Some(hs);
    }

    // Call the real NS selection handler
    let result = nnssf_handler::nssf_nnssf_nsselection_handle_get_from_amf_or_vnssf(0, &param);

    match result {
        nnssf_handler::NsSelectionResult::Success(info) => {
            // Snapshot everything we need from the NSSF context into OWNED data
            // and drop the read-lock BEFORE the async DB call below (DANGER-ZONES B1).
            let ctx = nssf_self();
            let (mut allowed_snssai_list, supported_for_tai): (
                Vec<serde_json::Value>,
                Vec<(u8, Option<u32>)>,
            ) = {
                let context = match ctx.read() {
                    Ok(c) => c,
                    Err(_) => {
                        return problem_details(
                            500,
                            "Internal Server Error",
                            "context lock poisoned",
                            None,
                        )
                    }
                };

                // Build allowedNssaiList from configured NSIs
                let mut list: Vec<serde_json::Value> = context
                    .nsi_get_all()
                    .iter()
                    .map(|nsi| {
                        serde_json::json!({
                            "allowedSnssai": context::snssai_to_json(&nsi.s_nssai)
                        })
                    })
                    .collect();

                // If no NSIs configured, use the matched one from the request
                if list.is_empty() {
                    list.push(serde_json::json!({
                        "allowedSnssai": context::snssai_to_json(&snssai)
                    }));
                }

                // Snapshot TAI-supported S-NSSAIs as owned (sst, sd) tuples
                // (TS 29.531 6.1.3.2.3.2) so we can filter after dropping the lock.
                let supported = if let Some(t) = tai {
                    context
                        .get_supported_snssai_for_tai(t)
                        .iter()
                        .map(|s| (s.sst, s.sd))
                        .collect()
                } else {
                    Vec::new()
                };

                (list, supported)
            }; // <- context read-lock released here, before any await

            // Subscription-based filtering: if SUPI provided, query UDR for
            // subscribed NSSAIs and filter (TS 29.531 6.1.3.2.3.1).
            if let Some(ref supi_val) = supi {
                match ogs_dbi::ogs_dbi_subscription_data_async(supi_val.to_string()).await {
                    Ok(sub_data) => {
                        let subscribed: Vec<(u8, Option<u32>)> = sub_data
                            .slice
                            .iter()
                            .map(|s| {
                                (
                                    s.s_nssai.sst,
                                    if s.s_nssai.sd.v == 0xFFFFFF {
                                        None
                                    } else {
                                        Some(s.s_nssai.sd.v)
                                    },
                                )
                            })
                            .collect();

                        if !subscribed.is_empty() {
                            allowed_snssai_list.retain(|item| {
                                let sst = item
                                    .get("allowedSnssai")
                                    .and_then(|s| s.get("sst"))
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0) as u8;
                                let sd = item
                                    .get("allowedSnssai")
                                    .and_then(|s| s.get("sd"))
                                    .and_then(|v| v.as_str())
                                    .and_then(|s| u32::from_str_radix(s, 16).ok());
                                subscribed
                                    .iter()
                                    .any(|(sub_sst, sub_sd)| *sub_sst == sst && *sub_sd == sd)
                            });
                        }
                    }
                    Err(e) => {
                        log::debug!(
                            "UDR subscription query unavailable for SUPI ({e}), allowing all NSSAIs"
                        );
                    }
                }
            }

            // Also filter against the NSSAI-availability snapshot taken above
            if !supported_for_tai.is_empty() {
                allowed_snssai_list.retain(|item| {
                    let sst = item
                        .get("allowedSnssai")
                        .and_then(|s| s.get("sst"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u8;
                    let sd = item
                        .get("allowedSnssai")
                        .and_then(|s| s.get("sd"))
                        .and_then(|v| v.as_str())
                        .and_then(|s| u32::from_str_radix(s, 16).ok());
                    supported_for_tai
                        .iter()
                        .any(|(s_sst, s_sd)| *s_sst == sst && *s_sd == sd)
                });
            }

            let mut response = serde_json::json!({
                "allowedNssaiList": [{
                    "allowedSnssaiList": allowed_snssai_list,
                    "accessType": "3GPP_ACCESS"
                }],
                "supportedFeatures": "1"
            });

            // nsiInformation is the spec response attribute for the PDU
            // session scenario; nsiInformationList is kept for back-compat.
            if let Some(nsi_info) = info.nsi_information {
                response["nsiInformation"] = serde_json::json!({
                    "nrfId": nsi_info.nrf_id,
                    "nsiId": nsi_info.nsi_id
                });
                response["nsiInformationList"] = serde_json::json!([{
                    "nrfId": nsi_info.nrf_id,
                    "nsiId": nsi_info.nsi_id
                }]);
            }

            SbiResponse::with_status(200)
                .with_json_body(&response)
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        nnssf_handler::NsSelectionResult::NeedHnssf(home_id) => {
            // Query H-NSSF via SBI client
            log::info!("NS Selection requires H-NSSF query (home_id={home_id})");

            match send_hnssf_query(home_id, &param).await {
                Ok(nsi_info) => SbiResponse::with_status(200)
                    .with_json_body(&serde_json::json!({
                        "nsiInformation": {
                            "nrfId": nsi_info.nrf_id,
                            "nsiId": nsi_info.nsi_id
                        },
                        "nsiInformationList": [{
                            "nrfId": nsi_info.nrf_id,
                            "nsiId": nsi_info.nsi_id
                        }],
                        "supportedFeatures": "1"
                    }))
                    .unwrap_or_else(|_| SbiResponse::with_status(200)),
                Err(e) => {
                    log::warn!("H-NSSF query failed: {e}");
                    problem_details(
                        500,
                        "Internal Server Error",
                        &format!("H-NSSF query failed: {e}"),
                        Some("H_NSSF_UNAVAILABLE"),
                    )
                }
            }
        }
        nnssf_handler::NsSelectionResult::Error(status, msg) => {
            log::warn!("NS Selection error: {status} - {msg}");
            let title = match status {
                400 => "Bad Request",
                403 => "Forbidden",
                404 => "Not Found",
                _ => "Error",
            };
            let cause = match status {
                403 => Some("SNSSAI_NOT_SUPPORTED"),
                _ => None,
            };
            problem_details(status, title, &msg, cause)
        }
    }
}

// ---------------------------------------------------------------------------
// NSSAI Availability (TS 29.531 §5.3: Nnssf_NSSAIAvailability v1)
// ---------------------------------------------------------------------------

/// Validate a NssaiAvailabilityInfo doc; returns affected TAIs on success.
fn validate_availability_doc(doc: &serde_json::Value) -> Result<Vec<context::Tai>, String> {
    let entries = doc
        .get("supportedNssaiAvailabilityData")
        .and_then(|v| v.as_array())
        .ok_or("Missing mandatory attribute supportedNssaiAvailabilityData")?;
    if entries.is_empty() {
        return Err("supportedNssaiAvailabilityData must contain at least one entry".to_string());
    }
    let mut tais = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        let tai = entry
            .get("tai")
            .and_then(context::tai_from_json)
            .ok_or_else(|| {
                format!("supportedNssaiAvailabilityData[{i}]: missing/invalid mandatory tai")
            })?;
        let snssai_list = entry
            .get("supportedSnssaiList")
            .and_then(|v| v.as_array())
            .filter(|a| !a.is_empty())
            .ok_or_else(|| {
                format!(
                    "supportedNssaiAvailabilityData[{i}]: missing mandatory supportedSnssaiList"
                )
            })?;
        for (j, s) in snssai_list.iter().enumerate() {
            context::snssai_from_json(s).ok_or_else(|| {
                format!(
                    "supportedNssaiAvailabilityData[{i}].supportedSnssaiList[{j}]: invalid S-NSSAI"
                )
            })?;
        }
        tais.push(tai);
        if let Some(extra) = entry.get("taiList").and_then(|v| v.as_array()) {
            tais.extend(extra.iter().filter_map(context::tai_from_json));
        }
    }
    Ok(tais)
}

/// Outcome of the NSSAIAvailability authorization / PLMN-support cross-check
/// (TS 29.531 §6.2.3.2.3.1, TS 33.521). Both variants map to 403 Forbidden;
/// only the ProblemDetails `cause` differs.
enum AvailabilityAuthError {
    /// NF service consumer (identified by NF Id) is not authorized to update
    /// the NSSAI availability information -> cause `NOT_AUTHORIZED`.
    Unauthorized(String),
    /// A reported S-NSSAI is not supported in the PLMN -> `SNSSAI_NOT_SUPPORTED`.
    UnsupportedSnssai(String),
}

impl AvailabilityAuthError {
    /// Render the 403 ProblemDetails (TS 29.531 §6.2.3.2.3.1 Table
    /// 6.2.3.2.3.1-2) carrying the appropriate `cause`.
    fn into_problem(self) -> SbiResponse {
        match self {
            AvailabilityAuthError::Unauthorized(detail) => {
                problem_details(403, "Forbidden", &detail, Some("NOT_AUTHORIZED"))
            }
            AvailabilityAuthError::UnsupportedSnssai(detail) => {
                problem_details(403, "Forbidden", &detail, Some("SNSSAI_NOT_SUPPORTED"))
            }
        }
    }
}

/// Cross-check an NssaiAvailabilityInfo document against the consumer's
/// authorization and the PLMN-supported S-NSSAI set (TS 29.531 §6.2.3.2.3.1,
/// TS 33.521). Pure (no global state) so it is unit-testable in isolation.
///
/// Default-allow stance (matched-sim back-compat, TS 29.531 §6.2.3.2.3.1):
///   * `authorized == true` is the default for any non-empty NF Id; only a
///     missing/empty NF Id yields `NOT_AUTHORIZED`. We deliberately do NOT
///     require an NRF lookup here, which would otherwise reject the matched
///     simulator's AMF.
///   * `restriction == None` means NO PLMN restriction is configured, so EVERY
///     reported S-NSSAI is accepted (the matched-sim registers default slices,
///     e.g. sst=1, and must not be newly rejected). `SNSSAI_NOT_SUPPORTED` is
///     returned ONLY when a restriction is explicitly configured AND a reported
///     S-NSSAI falls outside it.
///
/// Authorization is checked before PLMN support so a forbidden consumer is
/// rejected regardless of slice contents.
fn authorize_availability_doc(
    nf_id: &str,
    doc: &serde_json::Value,
    authorized: bool,
    restriction: Option<&[context::SNssai]>,
) -> Result<(), AvailabilityAuthError> {
    if !authorized {
        return Err(AvailabilityAuthError::Unauthorized(format!(
            "NF Id '{nf_id}' is not authorized to update NSSAI availability information"
        )));
    }
    let Some(allowed) = restriction else {
        // No restriction configured -> allow all (default-allow, see above).
        return Ok(());
    };
    for (_tais, snssais) in context::availability_entries(doc) {
        for s in &snssais {
            if !allowed.contains(s) {
                let sd = s
                    .sd
                    .map(|v| format!("{v:06x}"))
                    .unwrap_or_else(|| "none".to_string());
                return Err(AvailabilityAuthError::UnsupportedSnssai(format!(
                    "S-NSSAI (sst={}, sd={sd}) is not supported in the PLMN",
                    s.sst
                )));
            }
        }
    }
    Ok(())
}

/// Snapshot the NSSF's availability-authorization config from the global
/// context and run [`authorize_availability_doc`]. Returns the 403
/// ProblemDetails response on failure, `None` when the update is permitted.
fn check_availability_authorization(
    nf_id: &str,
    doc: &serde_json::Value,
    affected_tais: &[context::Tai],
) -> Option<SbiResponse> {
    let tai = affected_tais.first().cloned().unwrap_or_default();
    let (authorized, restriction) = with_nssf_context(|context| {
        let restriction = if context.has_plmn_snssai_restriction() {
            Some(context.plmn_supported_snssais())
        } else {
            None
        };
        (
            context.nf_authorized_for_availability(nf_id, &tai),
            restriction,
        )
    })
    // If the context lock is poisoned, fall back to the default-allow policy
    // (authorize any non-empty NF Id; impose no S-NSSAI restriction).
    .unwrap_or_else(|| (!nf_id.trim().is_empty(), None));

    authorize_availability_doc(nf_id, doc, authorized, restriction.as_deref())
        .err()
        .map(AvailabilityAuthError::into_problem)
}

/// Build the AuthorizedNssaiAvailabilityInfo response for a stored doc
fn authorized_availability_response(doc: &serde_json::Value) -> SbiResponse {
    let response = serde_json::json!({
        "authorizedNssaiAvailabilityData": doc.get("supportedNssaiAvailabilityData"),
        "supportedFeatures": "1"
    });
    SbiResponse::with_status(200)
        .with_json_body(&response)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

async fn handle_nssai_availability_update(nf_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("NSSAI Availability Update: nf_id={nf_id}");

    let body = match &request.http.content {
        Some(content) => content,
        None => {
            return problem_details(
                400,
                "Bad Request",
                "Missing mandatory request body (NssaiAvailabilityInfo)",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };

    let doc: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => {
            return problem_details(
                400,
                "Bad Request",
                &format!("Invalid JSON: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };

    let affected_tais = match validate_availability_doc(&doc) {
        Ok(t) => t,
        Err(e) => return problem_details(400, "Bad Request", &e, Some("MANDATORY_IE_MISSING")),
    };

    // nssfd-01: authorize the consumer + cross-check every reported S-NSSAI
    // against the PLMN-supported set BEFORE storing or notifying (TS 29.531
    // §6.2.3.2.3.1, TS 33.521). On failure the 403 returns here, so nothing is
    // stored and no notification is spawned.
    if let Some(resp) = check_availability_authorization(nf_id, &doc, &affected_tais) {
        return resp;
    }

    let info = context::availability_info_from_doc(nf_id, doc.clone());
    with_nssf_context(|context| context.set_nssai_availability(nf_id, info));

    log::info!(
        "Stored NSSAI availability for NF {nf_id} ({} TA entries)",
        affected_tais.len()
    );

    spawn_availability_notifications(affected_tais, Some(nf_id.to_string()));

    authorized_availability_response(&doc)
}

async fn handle_nssai_availability_patch(nf_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("NSSAI Availability Patch: nf_id={nf_id}");

    let existing = with_nssf_context(|context| context.get_nssai_availability(nf_id)).flatten();
    let existing = match existing {
        Some(e) => e,
        None => {
            return problem_details(
                404,
                "Not Found",
                &format!("No NSSAI availability stored for NF {nf_id}"),
                Some("RESOURCE_NOT_FOUND"),
            )
        }
    };

    let body = match &request.http.content {
        Some(content) => content,
        None => {
            return problem_details(
                400,
                "Bad Request",
                "Missing mandatory request body (PatchDocument)",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };

    let patch: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => {
            return problem_details(
                400,
                "Bad Request",
                &format!("Invalid JSON: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };

    // RFC 6902 JSON Patch (TS 29.531 PatchDocument) applied to a clone;
    // only commit on success.
    let mut patched = existing.doc.clone();
    if let Err(e) = json_patch::apply_patch(&mut patched, &patch) {
        return problem_details(
            400,
            "Bad Request",
            &format!("JSON Patch failed: {e}"),
            Some("INVALID_MSG_FORMAT"),
        );
    }

    let affected_tais = match validate_availability_doc(&patched) {
        Ok(t) => t,
        Err(e) => {
            return problem_details(
                400,
                "Bad Request",
                &format!("Patched document is not a valid NssaiAvailabilityInfo: {e}"),
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };

    // nssfd-01: apply the identical authorization + PLMN-support cross-check to
    // the POST-PATCH document before committing (TS 29.531 §6.2.3.2.3.1). A
    // patch that introduces an S-NSSAI unsupported in the PLMN is rejected with
    // 403 and the previously stored document is left unchanged.
    if let Some(resp) = check_availability_authorization(nf_id, &patched, &affected_tais) {
        return resp;
    }

    let info = context::availability_info_from_doc(nf_id, patched.clone());
    with_nssf_context(|context| context.set_nssai_availability(nf_id, info));

    log::info!("Patched NSSAI availability for NF {nf_id}");

    spawn_availability_notifications(affected_tais, Some(nf_id.to_string()));

    authorized_availability_response(&patched)
}

async fn handle_nssai_availability_delete(nf_id: &str) -> SbiResponse {
    log::info!("NSSAI Availability Delete: nf_id={nf_id}");

    let (removed, affected_tais) = with_nssf_context(|context| {
        let old = context.get_nssai_availability(nf_id);
        let removed = context.remove_nssai_availability(nf_id);
        (removed, old.map(|o| o.tai_list).unwrap_or_default())
    })
    .unwrap_or((false, Vec::new()));

    if !removed {
        return problem_details(
            404,
            "Not Found",
            &format!("No NSSAI availability stored for NF {nf_id}"),
            Some("RESOURCE_NOT_FOUND"),
        );
    }

    spawn_availability_notifications(affected_tais, Some(nf_id.to_string()));

    SbiResponse::with_status(204)
}

async fn handle_nssai_availability_options() -> SbiResponse {
    log::debug!("NSSAI Availability Options");
    SbiResponse::with_status(200).with_header("Allow", "PUT, PATCH, DELETE, POST, OPTIONS")
}

// ---------------------------------------------------------------------------
// Availability-change subscriptions + notifications
// ---------------------------------------------------------------------------

/// Parse and validate NssfEventSubscriptionCreateData
/// (mandatory: nfNssaiAvailabilityUri, taiList, event)
fn subscription_from_json(
    subscription_id: &str,
    v: &serde_json::Value,
) -> Result<context::NssfSubscription, String> {
    let mut missing = Vec::new();
    let uri = v.get("nfNssaiAvailabilityUri").and_then(|x| x.as_str());
    if uri.is_none() {
        missing.push("nfNssaiAvailabilityUri");
    }
    let tai_list_json = v.get("taiList").and_then(|x| x.as_array());
    if tai_list_json.is_none() {
        missing.push("taiList");
    }
    let event = v.get("event").and_then(|x| x.as_str());
    if event.is_none() {
        missing.push("event");
    }
    if !missing.is_empty() {
        return Err(format!(
            "Missing mandatory attribute(s): {}",
            missing.join(", ")
        ));
    }

    let tai_list_json = tai_list_json.expect("checked above");
    let mut tai_list = Vec::with_capacity(tai_list_json.len());
    for (i, t) in tai_list_json.iter().enumerate() {
        tai_list.push(
            context::tai_from_json(t).ok_or_else(|| format!("taiList[{i}] is not a valid Tai"))?,
        );
    }

    Ok(context::NssfSubscription {
        subscription_id: subscription_id.to_string(),
        nf_nssai_availability_uri: uri.expect("checked above").to_string(),
        tai_list,
        event: event.expect("checked above").to_string(),
        expiry: v.get("expiry").and_then(|x| x.as_str()).map(String::from),
        amf_id: v.get("amfId").and_then(|x| x.as_str()).map(String::from),
        amf_set_id: v.get("amfSetId").and_then(|x| x.as_str()).map(String::from),
    })
}

/// Collect AuthorizedNssaiAvailabilityData entries matching a subscription's
/// TAI list (empty list = all entries) from all stored availability docs.
fn collect_authorized_data_for(sub_tais: &[context::Tai]) -> Vec<serde_json::Value> {
    let infos = with_nssf_context(|context| context.all_nssai_availability()).unwrap_or_default();
    let mut result = Vec::new();
    for info in infos {
        let Some(entries) = info
            .doc
            .get("supportedNssaiAvailabilityData")
            .and_then(|v| v.as_array())
        else {
            continue;
        };
        for entry in entries {
            let entry_tais: Vec<context::Tai> = {
                let mut t = Vec::new();
                if let Some(tai) = entry.get("tai").and_then(context::tai_from_json) {
                    t.push(tai);
                }
                if let Some(extra) = entry.get("taiList").and_then(|v| v.as_array()) {
                    t.extend(extra.iter().filter_map(context::tai_from_json));
                }
                t
            };
            let matches = sub_tais.is_empty()
                || entry_tais.iter().any(|et| {
                    sub_tais.iter().any(|st| {
                        st.plmn_id.mcc == et.plmn_id.mcc
                            && st.plmn_id.mnc == et.plmn_id.mnc
                            && st.tac == et.tac
                    })
                });
            if matches {
                result.push(entry.clone());
            }
        }
    }
    result
}

/// Fire NssfEventNotification POSTs to all subscriptions matching the
/// affected TAIs. Runs each delivery on its own task with bounded timeouts.
fn spawn_availability_notifications(affected_tais: Vec<context::Tai>, changed_by: Option<String>) {
    let subs = with_nssf_context(|context| context.subscriptions_matching(&affected_tais))
        .unwrap_or_default();

    for sub in subs {
        // Don't notify the AMF whose own update caused the change; it gets
        // the AuthorizedNssaiAvailabilityInfo in the direct response.
        if let (Some(ref changed), Some(ref amf_id)) = (&changed_by, &sub.amf_id) {
            if *changed == *amf_id {
                continue;
            }
        }

        let data = collect_authorized_data_for(&sub.tai_list);
        tokio::spawn(async move {
            send_availability_notification(sub, data).await;
        });
    }
}

/// Deliver one NssfEventNotification as a real HTTP POST (bounded timeouts)
async fn send_availability_notification(
    sub: context::NssfSubscription,
    data: Vec<serde_json::Value>,
) {
    let Some((host, port, path)) = split_uri(&sub.nf_nssai_availability_uri) else {
        log::warn!(
            "Subscription {}: invalid nfNssaiAvailabilityUri '{}'",
            sub.subscription_id,
            sub.nf_nssai_availability_uri
        );
        return;
    };

    let body = serde_json::json!({
        "subscriptionId": sub.subscription_id,
        "authorizedNssaiAvailabilityData": data,
    });

    let client = SbiClient::new(
        SbiClientConfig::new(host, port)
            .with_connect_timeout(NOTIFY_CONNECT_TIMEOUT)
            .with_request_timeout(NOTIFY_REQUEST_TIMEOUT),
    );
    // NSSAI-availability notifications are consumed by AMFs; attach an
    // NRF-issued token when OAuth2 enforcement is on (no-op otherwise).
    let client = attach_oauth2(client, NfType::Amf);

    match client.post_json(&path, &body).await {
        Ok(resp) if resp.status == 204 || resp.is_success() => {
            log::debug!(
                "Availability notification delivered to {} (sub {})",
                sub.nf_nssai_availability_uri,
                sub.subscription_id
            );
        }
        Ok(resp) => {
            log::warn!(
                "Availability notification to {} returned {}",
                sub.nf_nssai_availability_uri,
                resp.status
            );
        }
        Err(e) => {
            log::warn!(
                "Availability notification to {} failed: {e}",
                sub.nf_nssai_availability_uri
            );
        }
    }
    client.close().await;
}

async fn handle_subscription_create(request: &SbiRequest) -> SbiResponse {
    log::info!("NSSAI Availability Subscription Create");

    let body = match &request.http.content {
        Some(content) => content,
        None => {
            return problem_details(
                400,
                "Bad Request",
                "Missing mandatory request body (NssfEventSubscriptionCreateData)",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };

    let subscription_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => {
            return problem_details(
                400,
                "Bad Request",
                &format!("Invalid JSON: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };

    let subscription_id = uuid::Uuid::new_v4().to_string();
    let sub = match subscription_from_json(&subscription_id, &subscription_data) {
        Ok(s) => s,
        Err(e) => return problem_details(400, "Bad Request", &e, Some("MANDATORY_IE_MISSING")),
    };

    let mut created = sub.to_created_json();
    let authorized = collect_authorized_data_for(&sub.tai_list);
    if !authorized.is_empty() {
        created["authorizedNssaiAvailabilityData"] = serde_json::json!(authorized);
    }

    with_nssf_context(|context| context.subscription_add(sub));

    log::info!("Created NSSAI availability subscription: {subscription_id}");

    SbiResponse::with_status(201)
        .with_header(
            "Location",
            format!(
                "/nnssf-nssaiavailability/v1/nssai-availability/subscriptions/{subscription_id}"
            ),
        )
        .with_json_body(&created)
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

async fn handle_subscription_delete(subscription_id: &str) -> SbiResponse {
    log::info!("NSSAI Availability Subscription Delete: {subscription_id}");

    let removed =
        with_nssf_context(|context| context.subscription_remove(subscription_id)).unwrap_or(false);

    if removed {
        SbiResponse::with_status(204)
    } else {
        problem_details(
            404,
            "Not Found",
            &format!("Subscription {subscription_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        )
    }
}

async fn handle_subscription_patch(subscription_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("NSSAI Availability Subscription Patch: {subscription_id}");

    let existing = with_nssf_context(|context| context.subscription_get(subscription_id)).flatten();
    let existing = match existing {
        Some(s) => s,
        None => {
            return problem_details(
                404,
                "Not Found",
                &format!("Subscription {subscription_id} not found"),
                Some("SUBSCRIPTION_NOT_FOUND"),
            )
        }
    };

    let body = match &request.http.content {
        Some(content) => content,
        None => {
            return problem_details(
                400,
                "Bad Request",
                "Missing mandatory request body (PatchDocument)",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };
    let patch: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => {
            return problem_details(
                400,
                "Bad Request",
                &format!("Invalid JSON: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };

    // Render the subscription as its CreateData document, patch it, and
    // re-validate the mandatory attributes.
    let mut doc = serde_json::json!({
        "nfNssaiAvailabilityUri": existing.nf_nssai_availability_uri,
        "taiList": existing.tai_list.iter().map(context::tai_to_json).collect::<Vec<_>>(),
        "event": existing.event,
    });
    if let Some(ref e) = existing.expiry {
        doc["expiry"] = serde_json::json!(e);
    }
    if let Some(ref a) = existing.amf_id {
        doc["amfId"] = serde_json::json!(a);
    }
    if let Some(ref a) = existing.amf_set_id {
        doc["amfSetId"] = serde_json::json!(a);
    }

    if let Err(e) = json_patch::apply_patch(&mut doc, &patch) {
        return problem_details(
            400,
            "Bad Request",
            &format!("JSON Patch failed: {e}"),
            Some("INVALID_MSG_FORMAT"),
        );
    }

    let updated = match subscription_from_json(subscription_id, &doc) {
        Ok(s) => s,
        Err(e) => {
            return problem_details(
                400,
                "Bad Request",
                &format!("Patched subscription is invalid: {e}"),
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };

    let mut created = updated.to_created_json();
    let authorized = collect_authorized_data_for(&updated.tai_list);
    if !authorized.is_empty() {
        created["authorizedNssaiAvailabilityData"] = serde_json::json!(authorized);
    }

    with_nssf_context(|context| context.subscription_update(updated));

    SbiResponse::with_status(200)
        .with_json_body(&created)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

// ---------------------------------------------------------------------------
// H-NSSF / NRF interaction
// ---------------------------------------------------------------------------

/// Query H-NSSF for home network slice info (B24.2)
async fn send_hnssf_query(
    home_id: u64,
    param: &nnssf_handler::NsSelectionParam,
) -> Result<nnssf_handler::NsiInformation, String> {
    let sbi_ctx = ogs_sbi::context::global_context();

    // Find NSSF instances for H-NSSF query
    let nssf_instances = sbi_ctx
        .find_nf_instances_by_service(ogs_sbi::types::SbiServiceType::NnssfNsselection)
        .await;

    let nssf_instance = nssf_instances
        .first()
        .ok_or_else(|| "No H-NSSF instance available for nnssf-nsselection service".to_string())?;

    let nssf_service = nssf_instance
        .find_service(ogs_sbi::types::SbiServiceType::NnssfNsselection)
        .ok_or("H-NSSF instance has no nnssf-nsselection service")?;

    let host = nssf_service
        .fqdn
        .as_deref()
        .or(nssf_instance.fqdn.as_deref())
        .or(nssf_service.ip_addresses.first().map(|s| s.as_str()))
        .or(nssf_instance.ipv4_addresses.first().map(|s| s.as_str()))
        .ok_or("No H-NSSF endpoint address available")?;
    let port = nssf_service.port;

    let client = sbi_ctx.get_client(host, port).await;

    // Build query parameters
    let mut query_parts = vec![format!(
        "nf-type={}",
        param.nf_type.as_deref().unwrap_or("AMF")
    )];
    if let Some(ref nf_id) = param.nf_id {
        query_parts.push(format!("nf-id={nf_id}"));
    }
    if let Some(ref snssai) = param.slice_info_for_pdu_session.snssai {
        let mut si = serde_json::json!({
            "sNssai": {"sst": snssai.sst},
            "roamingIndication": "HOME_ROUTED"
        });
        if let Some(sd) = snssai.sd {
            si["sNssai"]["sd"] = serde_json::json!(format!("{:06x}", sd));
        }
        query_parts.push(format!("slice-info-request-for-pdu-session={si}"));
    }

    let path = format!(
        "/nnssf-nsselection/v2/network-slice-information?{}",
        query_parts.join("&")
    );

    log::debug!("Sending H-NSSF query: GET {path}");

    let response = client
        .get(&path)
        .await
        .map_err(|e| format!("H-NSSF request failed: {e}"))?;

    if response.status != 200 {
        return Err(format!("H-NSSF returned status {}", response.status));
    }

    let body = response.http.content.ok_or("Empty H-NSSF response body")?;
    let json: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("Invalid H-NSSF response JSON: {e}"))?;

    // Extract NSI information from response (spec attribute first, then the
    // legacy list form)
    let nsi_info = json
        .get("nsiInformation")
        .or_else(|| {
            json.get("nsiInformationList")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
        })
        .ok_or("No nsiInformation in H-NSSF response")?;

    let nrf_id = nsi_info
        .get("nrfId")
        .and_then(|v| v.as_str())
        .ok_or("No nrfId in H-NSSF response")?;
    let nsi_id = nsi_info
        .get("nsiId")
        .and_then(|v| v.as_str())
        .ok_or("No nsiId in H-NSSF response")?;

    // Store in home context
    let ctx = nssf_self();
    if let Ok(context) = ctx.read() {
        if let Some(mut home) = context.home_find_by_id(home_id) {
            home.set_nrf_info(nrf_id, nsi_id);
            context.home_update(&home);
        }
    }

    Ok(nnssf_handler::NsiInformation {
        nrf_id: nrf_id.to_string(),
        nsi_id: nsi_id.to_string(),
    })
}

/// Parse host and port from a URI string
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

/// Register NSSF with NRF (B24.3)
///
/// Returns the NF instance ID so callers can start a heartbeat worker.
async fn register_with_nrf(sbi_addr: &str, sbi_port: u16) -> Result<String, String> {
    let sbi_ctx = ogs_sbi::context::global_context();

    let nrf_uri = sbi_ctx.get_nrf_uri().await;
    let nrf_uri = match nrf_uri {
        Some(uri) => uri,
        None => {
            log::debug!("No NRF URI configured, skipping NRF registration");
            return Ok(String::new());
        }
    };

    log::info!("Registering NSSF with NRF at {nrf_uri}");

    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;

    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_instance_id = uuid::Uuid::new_v4().to_string();

    let nf_profile = serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "NSSF",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [{
            "serviceInstanceId": format!("{}-nnssf-nsselection", nf_instance_id),
            "serviceName": "nnssf-nsselection",
            "versions": [{"apiVersionInUri": "v2", "apiFullVersion": "2.2.0"}],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{
                "ipv4Address": sbi_addr,
                "port": sbi_port
            }]
        }, {
            "serviceInstanceId": format!("{}-nnssf-nssaiavailability", nf_instance_id),
            "serviceName": "nnssf-nssaiavailability",
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.2.0"}],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{
                "ipv4Address": sbi_addr,
                "port": sbi_port
            }]
        }],
        "allowedNfTypes": ["AMF", "SCP", "NSSF"],
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
            log::info!("NSSF registered with NRF successfully (id={nf_instance_id})");

            let mut self_instance =
                ogs_sbi::context::NfInstance::new(&nf_instance_id, ogs_sbi::types::NfType::Nssf);
            self_instance.ipv4_addresses = vec![sbi_addr.to_string()];

            let mut svc = ogs_sbi::context::NfService::new(
                "nnssf-nsselection",
                ogs_sbi::types::SbiServiceType::NnssfNsselection,
            );
            svc.port = sbi_port;
            svc.ip_addresses = vec![sbi_addr.to_string()];
            self_instance.add_service(svc);

            let mut svc2 = ogs_sbi::context::NfService::new(
                "nnssf-nssaiavailability",
                ogs_sbi::types::SbiServiceType::NnssfNssaiavailability,
            );
            svc2.port = sbi_port;
            svc2.ip_addresses = vec![sbi_addr.to_string()];
            self_instance.add_service(svc2);

            sbi_ctx.set_self_instance(self_instance).await;

            Ok(nf_instance_id)
        }
        _ => Err(format!(
            "NRF registration returned status {}",
            response.status
        )),
    }
}

/// Discover NF services from NRF (B24.3)
async fn discover_nf_from_nrf(target_nf_type: &str, service_name: &str) -> Result<(), String> {
    let sbi_ctx = ogs_sbi::context::global_context();

    let nrf_uri = sbi_ctx.get_nrf_uri().await;
    let nrf_uri = match nrf_uri {
        Some(uri) => uri,
        None => return Ok(()),
    };

    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;

    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let path = format!(
        "/nnrf-disc/v1/nf-instances?target-nf-type={target_nf_type}&requester-nf-type=NSSF&service-names={service_name}"
    );

    let response = client
        .get(&path)
        .await
        .map_err(|e| format!("NRF discovery failed: {e}"))?;

    if response.status != 200 {
        return Err(format!("NRF discovery returned status {}", response.status));
    }

    let body = response
        .http
        .content
        .ok_or("Empty NRF discovery response")?;
    let json: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("Invalid NRF discovery response: {e}"))?;

    if let Some(nf_instances) = json.get("nfInstances").and_then(|v| v.as_array()) {
        for nf_json in nf_instances {
            let nf_id = nf_json
                .get("nfInstanceId")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let nf_type_str = nf_json.get("nfType").and_then(|v| v.as_str()).unwrap_or("");

            let nf_type = match nf_type_str {
                "NSSF" => ogs_sbi::types::NfType::Nssf,
                "NRF" => ogs_sbi::types::NfType::Nrf,
                "AMF" => ogs_sbi::types::NfType::Amf,
                _ => continue,
            };

            let mut instance = ogs_sbi::context::NfInstance::new(nf_id, nf_type);

            if let Some(fqdn) = nf_json.get("fqdn").and_then(|v| v.as_str()) {
                instance.fqdn = Some(fqdn.to_string());
            }
            if let Some(addrs) = nf_json.get("ipv4Addresses").and_then(|v| v.as_array()) {
                instance.ipv4_addresses = addrs
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
            }

            if let Some(services) = nf_json.get("nfServices").and_then(|v| v.as_array()) {
                for svc_json in services {
                    let svc_name = svc_json
                        .get("serviceName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if let Some(svc_type) = ogs_sbi::types::SbiServiceType::from_name(svc_name) {
                        let mut svc = ogs_sbi::context::NfService::new(svc_name, svc_type);
                        if let Some(endpoints) =
                            svc_json.get("ipEndPoints").and_then(|v| v.as_array())
                        {
                            if let Some(ep) = endpoints.first() {
                                if let Some(addr) = ep.get("ipv4Address").and_then(|v| v.as_str()) {
                                    svc.ip_addresses.push(addr.to_string());
                                }
                                if let Some(port) = ep.get("port").and_then(|v| v.as_u64()) {
                                    svc.port = port as u16;
                                }
                            }
                        }
                        instance.add_service(svc);
                    }
                }
            }

            sbi_ctx.add_nf_instance(instance).await;
            log::info!("Discovered {nf_type_str} instance: {nf_id}");
        }
    }

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

/// Async main event loop with timer integration
async fn run_event_loop_async(
    nssf_sm: &mut NssfSmContext,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    log::debug!("Entering async main event loop");

    let timer_mgr = timer_manager();

    while !shutdown.load(Ordering::SeqCst) && !SHUTDOWN.load(Ordering::SeqCst) {
        // Compute optimal sleep duration based on pending timers
        let poll_interval = ogs_core::async_timer::compute_poll_interval(
            timer_mgr.inner(),
            Duration::from_millis(100),
        );
        tokio::time::sleep(poll_interval).await;

        // Process timer expirations and dispatch to state machine
        let expired = timer_mgr.process_expired();
        for entry in &expired {
            log::debug!(
                "NSSF timer expired: id={} type={:?} data={:?}",
                entry.id,
                entry.timer_type,
                entry.data
            );

            // Create timer event and dispatch to state machine
            let mut event = NssfEvent::sbi_timer(entry.timer_type);
            if let Some(ref nf_id) = entry.data {
                event = event.with_nf_instance(nf_id.clone());
            }

            nssf_sm.dispatch(&mut event);
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
    use ogs_sbi::client::SbiClient;
    use ogs_sbi::server::{SbiServer, SbiServerConfig};
    use serde_json::json;

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-nssfd"]);
        assert_eq!(args.config, "/etc/nextgcore/nssf.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 7777);
        assert!(!args.tls);
        assert_eq!(args.max_nf, 512);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-nssfd",
            "-c",
            "/custom/nssf.yaml",
            "-e",
            "debug",
            "--sbi-addr",
            "0.0.0.0",
            "--sbi-port",
            "8080",
            "--max-nf",
            "1024",
        ]);
        assert_eq!(args.config, "/custom/nssf.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 8080);
        assert_eq!(args.max_nf, 1024);
    }

    #[test]
    fn test_args_tls() {
        let args = Args::parse_from([
            "nextgcore-nssfd",
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
    fn test_percent_decode_and_query_parse() {
        assert_eq!(percent_decode("a%20b%7B%22x%22%3A1%7D"), "a b{\"x\":1}");
        assert_eq!(percent_decode("plain"), "plain");
        let params = parse_query_params("/x/y?nf-type=AMF&nf-id=abc&j=%7B%22sst%22%3A1%7D&empty");
        assert_eq!(params.get("nf-type").map(String::as_str), Some("AMF"));
        assert_eq!(params.get("j").map(String::as_str), Some(r#"{"sst":1}"#));
        assert_eq!(params.get("empty").map(String::as_str), Some(""));
    }

    #[test]
    fn test_split_uri() {
        assert_eq!(
            split_uri("http://10.0.0.1:8080/notify/cb"),
            Some(("10.0.0.1".to_string(), 8080, "/notify/cb".to_string()))
        );
        assert_eq!(
            split_uri("https://amf.example/cb"),
            Some(("amf.example".to_string(), 443, "/cb".to_string()))
        );
    }

    // -----------------------------------------------------------------
    // HTTP-level tests (ephemeral ports, bounded timeouts)
    // -----------------------------------------------------------------

    /// Percent-encode a URI query component (everything but unreserved chars)
    fn enc(s: &str) -> String {
        let mut out = String::with_capacity(s.len() * 3);
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    out.push(b as char)
                }
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }

    fn free_port() -> u16 {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let port = probe.local_addr().expect("local addr").port();
        drop(probe);
        port
    }

    /// Serializes tests that mutate the *global* NSSF availability/restriction
    /// state (the context is a process-wide singleton). Without this, the
    /// PLMN-supported restriction one test installs could leak into another
    /// running concurrently and flip an expected 200 into a 403 (or vice
    /// versa). An async-aware `tokio::sync::Mutex` is used so the guard may be
    /// held across the handler `.await` points (clippy `await_holding_lock`),
    /// and it does not poison on a failing test.
    async fn availability_state_guard() -> tokio::sync::MutexGuard<'static, ()> {
        static GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        GUARD.lock().await
    }

    async fn start_nssf_server() -> (SbiServer, u16) {
        nssf_context_init(512);
        let port = free_port();
        let server = SbiServer::new(SbiServerConfig::new(SocketAddr::from((
            [127, 0, 0, 1],
            port,
        ))));
        server
            .start(nssf_sbi_request_handler)
            .await
            .expect("server start");
        (server, port)
    }

    // -----------------------------------------------------------------
    // OAuth2 enforcement (T1.1): server-side require_oauth2 + aud check
    // -----------------------------------------------------------------

    /// Mint an ES256 access token (matching the NRF's token shape) with the
    /// given `aud`, signed by `sk` and tagged with `kid`.
    fn build_es256_token(sk: &p256::ecdsa::SigningKey, kid: &str, aud: &str) -> String {
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
            "iss": "NRF", "sub": "amf-1", "aud": aud,
            "scope": "nnssf-nsselection", "exp": exp, "iat": 0
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

    /// Start an NSSF SBI server with OAuth2 enforcement keyed to a static JWKS
    /// and the NSSF audience.
    async fn start_nssf_server_oauth2(jwks: serde_json::Value) -> (SbiServer, u16) {
        nssf_context_init(512);
        let port = free_port();
        let mut cfg = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(jwks);
        cfg = cfg.with_expected_audience_nf_type(NfType::Nssf);
        let server = SbiServer::new(cfg);
        server
            .start(nssf_sbi_request_handler)
            .await
            .expect("server start");
        (server, port)
    }

    #[test]
    fn test_yaml_oauth2_require_parses() {
        let yaml = "nssf:\n  sbi:\n    oauth2:\n      require: true\n";
        let parsed: NssfYaml = serde_yaml::from_str(yaml).unwrap();
        let require = parsed
            .nssf
            .and_then(|n| n.sbi)
            .and_then(|s| s.oauth2)
            .and_then(|o| o.require)
            .unwrap_or(false);
        assert!(require, "oauth2.require should parse to true");
    }

    #[test]
    fn test_yaml_oauth2_absent_defaults_off() {
        // Default config (no oauth2 block) leaves enforcement off, preserving
        // the dev/E2E path.
        let yaml = "nssf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: 7777\n";
        let parsed: NssfYaml = serde_yaml::from_str(yaml).unwrap();
        let require = parsed
            .nssf
            .and_then(|n| n.sbi)
            .and_then(|s| s.oauth2)
            .and_then(|o| o.require)
            .unwrap_or(false);
        assert!(!require, "absent oauth2 block must default to off");
    }

    #[tokio::test]
    async fn test_oauth2_missing_token_rejected() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let (server, port) = start_nssf_server_oauth2(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        // No Authorization header -> 401 (missing Bearer token).
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            client.get("/nnssf-nsselection/v2/network-slice-information?nf-type=AMF&nf-id=x"),
        )
        .await
        .expect("bounded")
        .expect("response");
        assert_eq!(resp.status, 401, "unauthenticated request must be 401");

        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_oauth2_valid_token_accepted() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let (server, port) = start_nssf_server_oauth2(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        // Valid token whose aud includes "NSSF" passes enforcement; the
        // request reaches the handler (400 for the missing mandatory params,
        // NOT 401/403 — i.e. authorization succeeded).
        let token = build_es256_token(&sk, "nrf-es256", "NSSF");
        let req = SbiRequest::get(
            "/nnssf-nsselection/v2/network-slice-information?nf-type=AMF",
        )
        .with_header("Authorization", format!("Bearer {token}"));
        let resp = tokio::time::timeout(Duration::from_secs(5), client.send_request(req))
            .await
            .expect("bounded")
            .expect("response");
        assert_ne!(resp.status, 401, "valid token must not be 401");
        assert_ne!(resp.status, 403, "valid token must not be 403");
        assert_eq!(resp.status, 400, "request reached handler (missing nf-id)");

        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_oauth2_wrong_audience_rejected() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let (server, port) = start_nssf_server_oauth2(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        // Token addressed to a different NF (aud="UDM") is rejected (401).
        let token = build_es256_token(&sk, "nrf-es256", "UDM");
        let req = SbiRequest::get(
            "/nnssf-nsselection/v2/network-slice-information?nf-type=AMF&nf-id=x",
        )
        .with_header("Authorization", format!("Bearer {token}"));
        let resp = tokio::time::timeout(Duration::from_secs(5), client.send_request(req))
            .await
            .expect("bounded")
            .expect("response");
        assert_eq!(resp.status, 401, "wrong-audience token must be 401");

        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_http_nsselection_registration_scenario() {
        let (server, port) = start_nssf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        // Subscribed: sst 41 (default) + sst 42; requested: sst 41 + sst 47
        // (unsubscribed). Expect allowed=[41], rejectedInPlmn=[47],
        // configured=[41,42].
        let sir = json!({
            "subscribedNssai": [
                {"subscribedSnssai": {"sst": 41}, "defaultIndication": true},
                {"subscribedSnssai": {"sst": 42}}
            ],
            "requestedNssai": [{"sst": 41}, {"sst": 47}]
        })
        .to_string();
        let path = format!(
            "/nnssf-nsselection/v2/network-slice-information?nf-type=AMF&nf-id=amf-reg-1&slice-info-request-for-registration={}",
            enc(&sir)
        );
        let resp = tokio::time::timeout(Duration::from_secs(5), client.get(&path))
            .await
            .expect("bounded")
            .expect("response");
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let allowed = &body["allowedNssaiList"][0]["allowedSnssaiList"];
        assert_eq!(allowed.as_array().unwrap().len(), 1);
        assert_eq!(allowed[0]["allowedSnssai"]["sst"], 41);
        assert_eq!(body["allowedNssaiList"][0]["accessType"], "3GPP_ACCESS");
        let rejected = body["rejectedNssaiInPlmn"].as_array().unwrap();
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0]["sst"], 47);
        let configured = body["configuredNssai"].as_array().unwrap();
        assert_eq!(configured.len(), 2);

        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_http_nsselection_missing_mandatory_params() {
        let (server, port) = start_nssf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        // Missing nf-id -> 400 ProblemDetails
        let resp = client
            .get("/nnssf-nsselection/v2/network-slice-information?nf-type=AMF")
            .await
            .expect("response");
        assert_eq!(resp.status, 400);
        let body = resp.http.content.as_deref().unwrap();
        assert!(body.contains("nf-id"));
        assert!(body.contains("MANDATORY_QUERY_PARAM_MISSING"));

        // No slice-info-request-* at all -> 400
        let resp = client
            .get("/nnssf-nsselection/v2/network-slice-information?nf-type=AMF&nf-id=x")
            .await
            .expect("response");
        assert_eq!(resp.status, 400);

        // PDU-session info without mandatory roamingIndication -> 400 (no panic)
        let sip = enc(&json!({"sNssai": {"sst": 1}}).to_string());
        let resp = client
            .get(&format!(
                "/nnssf-nsselection/v2/network-slice-information?nf-type=AMF&nf-id=x&slice-info-request-for-pdu-session={sip}"
            ))
            .await
            .expect("response");
        assert_eq!(resp.status, 400);
        assert!(resp
            .http
            .content
            .as_deref()
            .unwrap()
            .contains("roamingIndication"));

        // Wrong API version -> 404
        let resp = client
            .get("/nnssf-nsselection/v1/network-slice-information?nf-type=AMF&nf-id=x")
            .await
            .expect("response");
        assert_eq!(resp.status, 404);

        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_http_availability_lifecycle_with_notifications() {
        // Serialize against the nssfd-01 restriction tests and clear any
        // restriction so this lifecycle PUT/PATCH path sees the default
        // allow-all (matched-sim back-compat).
        let _state_guard = availability_state_guard().await;
        let (server, port) = start_nssf_server().await;
        with_nssf_context(|c| c.set_plmn_supported_snssais(None));
        let client = SbiClient::with_host_port("127.0.0.1", port);

        // Notification receiver on its own ephemeral port
        let recv_port = free_port();
        let receiver = SbiServer::new(SbiServerConfig::new(SocketAddr::from((
            [127, 0, 0, 1],
            recv_port,
        ))));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        receiver
            .start(move |req: SbiRequest| {
                let tx = tx.clone();
                async move {
                    let _ = tx.send(req.http.content.unwrap_or_default());
                    SbiResponse::with_status(204)
                }
            })
            .await
            .expect("receiver start");

        let tai = json!({"plmnId": {"mcc": "999", "mnc": "70"}, "tac": "0000c8"});

        // 1. Subscription create: missing mandatory `event` -> 400
        let resp = client
            .post_json(
                "/nnssf-nssaiavailability/v1/nssai-availability/subscriptions",
                &json!({
                    "nfNssaiAvailabilityUri": format!("http://127.0.0.1:{recv_port}/cb"),
                    "taiList": [tai]
                }),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 400);
        assert!(resp.http.content.as_deref().unwrap().contains("event"));

        // 2. Valid subscription create -> 201 + Location + subscriptionId
        let resp = client
            .post_json(
                "/nnssf-nssaiavailability/v1/nssai-availability/subscriptions",
                &json!({
                    "nfNssaiAvailabilityUri": format!("http://127.0.0.1:{recv_port}/cb"),
                    "taiList": [tai],
                    "event": "SNSSAI_STATUS_CHANGE_REPORT"
                }),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 201);
        let location = resp
            .http
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("location"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        assert!(!location.is_empty(), "Location header missing");
        assert!(location.contains("/nssai-availability/subscriptions/"));
        let created: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let sub_id = created["subscriptionId"].as_str().unwrap().to_string();

        // 3. PUT availability missing mandatory supportedNssaiAvailabilityData -> 400
        let resp = client
            .put_json(
                "/nnssf-nssaiavailability/v1/nssai-availability/amf-av-1",
                &json!({"supportedFeatures": "1"}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 400);
        assert!(resp
            .http
            .content
            .as_deref()
            .unwrap()
            .contains("supportedNssaiAvailabilityData"));

        // 4. Valid PUT -> 200 AuthorizedNssaiAvailabilityInfo + notification
        let resp = client
            .put_json(
                "/nnssf-nssaiavailability/v1/nssai-availability/amf-av-1",
                &json!({
                    "supportedNssaiAvailabilityData": [{
                        "tai": tai,
                        "supportedSnssaiList": [{"sst": 51}, {"sst": 52, "sd": "0a0b0c"}]
                    }]
                }),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(body["authorizedNssaiAvailabilityData"].is_array());

        let notif = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("notification within timeout")
            .expect("channel open");
        let notif: serde_json::Value = serde_json::from_str(&notif).unwrap();
        assert_eq!(notif["subscriptionId"], sub_id.as_str());
        assert!(!notif["authorizedNssaiAvailabilityData"]
            .as_array()
            .unwrap()
            .is_empty());

        // 5. PATCH with RFC 6902 document -> 200 + second notification
        let resp = client
            .patch_json(
                "/nnssf-nssaiavailability/v1/nssai-availability/amf-av-1",
                &json!([{
                    "op": "add",
                    "path": "/supportedNssaiAvailabilityData/0/supportedSnssaiList/-",
                    "value": {"sst": 53}
                }]),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let snssais = body["authorizedNssaiAvailabilityData"][0]["supportedSnssaiList"]
            .as_array()
            .unwrap();
        assert_eq!(snssais.len(), 3);

        let notif2 = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("second notification within timeout")
            .expect("channel open");
        assert!(notif2.contains(&sub_id));

        // 6. Bad PATCH (replace of non-existent member) -> 400
        let resp = client
            .patch_json(
                "/nnssf-nssaiavailability/v1/nssai-availability/amf-av-1",
                &json!([{"op": "replace", "path": "/nonexistent", "value": 1}]),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 400);

        // 7. PATCH on unknown nfId -> 404
        let resp = client
            .patch_json(
                "/nnssf-nssaiavailability/v1/nssai-availability/amf-unknown",
                &json!([{"op": "remove", "path": "/supportedNssaiAvailabilityData/0"}]),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 404);

        // 8. Subscription PATCH (replace expiry) -> 200
        let resp = client
            .patch_json(
                &format!("/nnssf-nssaiavailability/v1/nssai-availability/subscriptions/{sub_id}"),
                &json!([{"op": "add", "path": "/expiry", "value": "2030-01-01T00:00:00Z"}]),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["expiry"], "2030-01-01T00:00:00Z");

        // 9. DELETE availability -> 204, second DELETE -> 404
        let resp = client
            .delete("/nnssf-nssaiavailability/v1/nssai-availability/amf-av-1")
            .await
            .expect("response");
        assert_eq!(resp.status, 204);
        // Deletion also notifies subscribers (remaining data for the TA)
        let _ = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("delete notification within timeout");
        let resp = client
            .delete("/nnssf-nssaiavailability/v1/nssai-availability/amf-av-1")
            .await
            .expect("response");
        assert_eq!(resp.status, 404);

        // 10. DELETE subscription -> 204, second DELETE -> 404
        let resp = client
            .delete(&format!(
                "/nnssf-nssaiavailability/v1/nssai-availability/subscriptions/{sub_id}"
            ))
            .await
            .expect("response");
        assert_eq!(resp.status, 204);
        let resp = client
            .delete(&format!(
                "/nnssf-nssaiavailability/v1/nssai-availability/subscriptions/{sub_id}"
            ))
            .await
            .expect("response");
        assert_eq!(resp.status, 404);

        server.stop().await.expect("stop");
        receiver.stop().await.expect("stop receiver");
    }

    // -----------------------------------------------------------------
    // nssfd-01: NSSAIAvailability PUT/PATCH PLMN-support + authorization
    // (TS 29.531 §6.2.3.2.3.1, TS 33.521). Handlers are driven directly so
    // the 403-before-store/notify ordering is observable.
    // -----------------------------------------------------------------

    /// (a) With a configured restricted set, PUT an S-NSSAI outside it ->
    /// 403 SNSSAI_NOT_SUPPORTED; nothing stored, no notification spawned.
    #[tokio::test]
    async fn test_availability_put_unsupported_snssai_403() {
        let _state_guard = availability_state_guard().await;
        nssf_context_init(512);
        // Restrict the PLMN to sst=1 only; the PUT reports sst=2 (outside it).
        with_nssf_context(|c| {
            c.set_plmn_supported_snssais(Some(vec![context::SNssai::new(1, None)]))
        });

        let nf_id = "amf-nssfd01-unsupported";
        let _ = with_nssf_context(|c| c.remove_nssai_availability(nf_id));

        let body = json!({
            "supportedNssaiAvailabilityData": [{
                "tai": {"plmnId": {"mcc": "999", "mnc": "70"}, "tac": "000001"},
                "supportedSnssaiList": [{"sst": 2, "sd": "0a0b0c"}]
            }]
        });
        let req = SbiRequest::put(format!(
            "/nnssf-nssaiavailability/v1/nssai-availability/{nf_id}"
        ))
        .with_json_body(&body)
        .unwrap();
        let resp = handle_nssai_availability_update(nf_id, &req).await;

        assert_eq!(resp.status, 403);
        let pd: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(pd["status"], 403);
        assert_eq!(pd["cause"], "SNSSAI_NOT_SUPPORTED");
        // Nothing stored. The 403 returns before set_nssai_availability + the
        // spawn_availability_notifications call, so no notification is spawned.
        assert!(with_nssf_context(|c| c.get_nssai_availability(nf_id))
            .flatten()
            .is_none());

        with_nssf_context(|c| c.set_plmn_supported_snssais(None));
    }

    /// (b) PUT with an empty NF Id -> 403 NOT_AUTHORIZED.
    #[tokio::test]
    async fn test_availability_put_empty_nf_id_403_not_authorized() {
        let _state_guard = availability_state_guard().await;
        nssf_context_init(512);
        with_nssf_context(|c| c.set_plmn_supported_snssais(None)); // no restriction

        let body = json!({
            "supportedNssaiAvailabilityData": [{
                "tai": {"plmnId": {"mcc": "999", "mnc": "70"}, "tac": "000001"},
                "supportedSnssaiList": [{"sst": 1}]
            }]
        });
        let req = SbiRequest::put("/nnssf-nssaiavailability/v1/nssai-availability/")
            .with_json_body(&body)
            .unwrap();
        // Empty NF Id is unauthorized regardless of slice contents.
        let resp = handle_nssai_availability_update("", &req).await;

        assert_eq!(resp.status, 403);
        let pd: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(pd["status"], 403);
        assert_eq!(pd["cause"], "NOT_AUTHORIZED");
        assert!(with_nssf_context(|c| c.get_nssai_availability(""))
            .flatten()
            .is_none());
    }

    /// (c) PUT with all-supported S-NSSAIs (here: no restriction configured)
    /// -> 200 and stored.
    #[tokio::test]
    async fn test_availability_put_all_supported_200_stored() {
        let _state_guard = availability_state_guard().await;
        nssf_context_init(512);
        with_nssf_context(|c| c.set_plmn_supported_snssais(None)); // default allow-all

        let nf_id = "amf-nssfd01-ok";
        let _ = with_nssf_context(|c| c.remove_nssai_availability(nf_id));

        let body = json!({
            "supportedNssaiAvailabilityData": [{
                "tai": {"plmnId": {"mcc": "999", "mnc": "70"}, "tac": "000001"},
                "supportedSnssaiList": [{"sst": 1}]
            }]
        });
        let req = SbiRequest::put(format!(
            "/nnssf-nssaiavailability/v1/nssai-availability/{nf_id}"
        ))
        .with_json_body(&body)
        .unwrap();
        let resp = handle_nssai_availability_update(nf_id, &req).await;

        assert_eq!(resp.status, 200);
        let stored = with_nssf_context(|c| c.get_nssai_availability(nf_id)).flatten();
        assert!(stored.is_some(), "supported PUT must be stored");
        assert_eq!(
            stored.unwrap().supported_snssai_list,
            vec![context::SNssai::new(1, None)]
        );

        let _ = with_nssf_context(|c| c.remove_nssai_availability(nf_id));
    }

    /// (d) PATCH producing an unsupported S-NSSAI -> 403; original doc
    /// unchanged.
    #[tokio::test]
    async fn test_availability_patch_unsupported_snssai_403_original_unchanged() {
        let _state_guard = availability_state_guard().await;
        nssf_context_init(512);
        // Restrict to sst=1: the initial PUT (sst=1) is accepted; the PATCH
        // that appends sst=2 must be rejected and leave the stored doc intact.
        with_nssf_context(|c| {
            c.set_plmn_supported_snssais(Some(vec![context::SNssai::new(1, None)]))
        });

        let nf_id = "amf-nssfd01-patch";
        let _ = with_nssf_context(|c| c.remove_nssai_availability(nf_id));

        let put_body = json!({
            "supportedNssaiAvailabilityData": [{
                "tai": {"plmnId": {"mcc": "999", "mnc": "70"}, "tac": "000001"},
                "supportedSnssaiList": [{"sst": 1}]
            }]
        });
        let put_req = SbiRequest::put(format!(
            "/nnssf-nssaiavailability/v1/nssai-availability/{nf_id}"
        ))
        .with_json_body(&put_body)
        .unwrap();
        assert_eq!(
            handle_nssai_availability_update(nf_id, &put_req).await.status,
            200
        );

        // PATCH appends an unsupported S-NSSAI (sst=2) -> 403, doc unchanged.
        let patch = json!([{
            "op": "add",
            "path": "/supportedNssaiAvailabilityData/0/supportedSnssaiList/-",
            "value": {"sst": 2}
        }]);
        let patch_req = SbiRequest::patch(format!(
            "/nnssf-nssaiavailability/v1/nssai-availability/{nf_id}"
        ))
        .with_body(patch.to_string(), "application/json-patch+json");
        let resp = handle_nssai_availability_patch(nf_id, &patch_req).await;

        assert_eq!(resp.status, 403);
        let pd: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(pd["status"], 403);
        assert_eq!(pd["cause"], "SNSSAI_NOT_SUPPORTED");

        // Original document unchanged: still exactly [sst=1].
        let stored = with_nssf_context(|c| c.get_nssai_availability(nf_id))
            .flatten()
            .expect("original doc must remain stored after a rejected PATCH");
        assert_eq!(
            stored.supported_snssai_list,
            vec![context::SNssai::new(1, None)]
        );
        let arr = stored.doc["supportedNssaiAvailabilityData"][0]["supportedSnssaiList"]
            .as_array()
            .unwrap();
        assert_eq!(arr.len(), 1, "rejected PATCH must not mutate the stored doc");

        with_nssf_context(|c| c.set_plmn_supported_snssais(None));
        let _ = with_nssf_context(|c| c.remove_nssai_availability(nf_id));
    }
}
