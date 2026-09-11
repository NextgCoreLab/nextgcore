//! NextGCore UDR (Unified Data Repository)
//!
//! The UDR is a 5G core network function responsible for:
//! - Storing and providing subscriber data to UDM
//! - Storing and providing policy data to PCF
//! - Storing and providing application data
//!
//! UDR is a stateless data repository that queries the database directly.

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::oauth::JwksCache;
use nextgcore_sbi::server::{
    send_bad_request, send_error, send_method_not_allowed, send_not_found, SbiServer,
    SbiServerConfig as NextgcoreSbiServerConfig,
};
use nextgcore_udrd::data_store::{
    self, merge_patch, notify_application_data_change, notify_exposure_data_change,
    notify_influence_data_change, notify_subscription_data_change, SubKind,
};
use nextgcore_udrd::{
    udr_context_final, udr_context_init, udr_sbi_close, udr_sbi_open, SbiServerConfig, UdrSmContext,
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// NextGCore UDR - Unified Data Repository
#[derive(Parser, Debug)]
#[command(name = "nextgcore-udrd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Unified Data Repository", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/udr.yaml")]
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

    /// Path to the JSON snapshot file for non-subscriber resource trees
    /// (exposure-data, application-data, smf-registrations, subs-to-notify).
    /// When unset (the default), these trees are kept purely in-memory and are
    /// lost on restart. Also settable via NEXTGCORE_UDR_STATE_FILE.
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
struct SbiOauth2Yaml {
    /// Require a valid OAuth2 bearer token on every incoming SBI request.
    /// Verification keys are fetched from the configured NRF's JWKS endpoint.
    require: Option<bool>,
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
    oauth2: Option<SbiOauth2Yaml>,
}

/// One `udr.group_id_map` entry: the NF-group ids assigned to the subscribers
/// whose SUPI starts with `supi_prefix` (#87, TS 29.504 §6.2).
///
/// Group assignment is an operator decision made by SUPI range — there is no
/// Nudr verb that provisions it, and deriving a group id from the SUPI would
/// invent a topology this core does not have.
#[derive(Debug, Default, Deserialize, Clone)]
struct GroupIdMapYaml {
    /// SUPI prefix this entry covers, e.g. `imsi-00101`. An empty prefix matches
    /// every subscriber (single-group deployment).
    #[serde(default)]
    supi_prefix: String,
    /// NF type (`UDM`, `AUSF`, ...) -> NF-group id.
    nf_group_ids: std::collections::HashMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
struct UdrSection {
    sbi: Option<SbiYaml>,
    /// #87: `udr.group_id_map` — the Nudr_GroupIDmap assignments.
    group_id_map: Option<Vec<GroupIdMapYaml>>,
}

#[derive(Debug, Default, Deserialize)]
struct UdrYaml {
    udr: Option<UdrSection>,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// #87: the configured Nudr_GroupIDmap assignments, longest-prefix first.
static GROUP_ID_MAP: std::sync::RwLock<Vec<GroupIdMapYaml>> = std::sync::RwLock::new(Vec::new());

/// Install the group-id-map configuration (longest prefix wins, so a specific
/// range overrides a catch-all rather than depending on file order).
fn set_group_id_map(mut entries: Vec<GroupIdMapYaml>) {
    entries.sort_by_key(|e| std::cmp::Reverse(e.supi_prefix.len()));
    if let Ok(mut guard) = GROUP_ID_MAP.write() {
        *guard = entries;
    }
}

/// The NF-group ids assigned to `subscriber_id`, or `None` when no entry covers
/// it. Filtered to `nf_types` when non-empty.
fn group_ids_for(subscriber_id: &str, nf_types: &[String]) -> Option<serde_json::Value> {
    let guard = GROUP_ID_MAP.read().ok()?;
    let entry = guard
        .iter()
        .find(|e| subscriber_id.starts_with(&e.supi_prefix))?;
    let mut out = serde_json::Map::new();
    for (nf_type, group_id) in &entry.nf_group_ids {
        if !nf_types.is_empty() && !nf_types.iter().any(|t| t.eq_ignore_ascii_case(nf_type)) {
            continue;
        }
        out.insert(nf_type.to_ascii_uppercase(), serde_json::json!(group_id));
    }
    // minProperties: 1 — a map with nothing in it answers nothing.
    if out.is_empty() {
        return None;
    }
    Some(serde_json::Value::Object(out))
}

/// `Nudr_GroupIDmap` (TS 29.504 §6.2), served at
/// `/nudr-group-id-map/v1/...`. The service was unrouted, so the router's
/// unknown-service 404 was the only answer a consumer ever got.
fn handle_group_id_map(parts: &[&str], method: &str, request: &SbiRequest) -> SbiResponse {
    let ds = data_store::store();
    match (parts.get(2).copied().unwrap_or(""), parts.get(3).copied()) {
        // GET /nf-group-ids?nf-type=UDM,AUSF&subscriberId=imsi-...
        ("nf-group-ids", None) => {
            if method != "GET" {
                return send_method_not_allowed(method, "nf-group-ids");
            }
            let Some(subscriber_id) = request.http.params.get("subscriberId") else {
                return missing_mandatory("subscriberId");
            };
            let subscriber_id = pct_decode(subscriber_id);
            let nf_types: Vec<String> = request
                .http
                .params
                .get("nf-type")
                .map(|raw| {
                    pct_decode(raw)
                        .split(',')
                        .map(|t| t.trim().to_string())
                        .filter(|t| !t.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            if nf_types.is_empty() {
                return missing_mandatory("nf-type");
            }
            match group_ids_for(&subscriber_id, &nf_types) {
                Some(map) => {
                    SbiResponse::with_status(200).with_body(map.to_string(), "application/json")
                }
                None => send_not_found(
                    "No NF group ids assigned for this subscriber",
                    Some("DATA_NOT_FOUND"),
                ),
            }
        }
        ("nf-group-ids", Some("subscriptions")) => {
            let subs_id = parts.get(4).copied().unwrap_or("");
            match (subs_id.is_empty(), method) {
                (true, "POST") => {
                    let body = match parse_json_body(request) {
                        Ok(v) => v,
                        Err(resp) => return *resp,
                    };
                    let Some(uri) = body
                        .get("callbackReference")
                        .or_else(|| body.get("notificationUri"))
                        .and_then(|v| v.as_str())
                    else {
                        return missing_mandatory("callbackReference");
                    };
                    let sub = ds.sub_create(SubKind::GroupIdMap, uri, body.clone());
                    SbiResponse::with_status(201)
                        .with_header(
                            "Location",
                            format!(
                                "/nudr-group-id-map/v1/nf-group-ids/subscriptions/{}",
                                sub.id
                            ),
                        )
                        .with_body(body.to_string(), "application/json")
                }
                (false, "GET") => match ds.sub_get(subs_id) {
                    Some(sub) if sub.kind == SubKind::GroupIdMap => SbiResponse::with_status(200)
                        .with_body(sub.body.to_string(), "application/json"),
                    _ => send_not_found("Subscription not found", Some("DATA_NOT_FOUND")),
                },
                (false, "PUT") => {
                    let body = match parse_json_body(request) {
                        Ok(v) => v,
                        Err(resp) => return *resp,
                    };
                    let Some(uri) = body
                        .get("callbackReference")
                        .or_else(|| body.get("notificationUri"))
                        .and_then(|v| v.as_str())
                    else {
                        return missing_mandatory("callbackReference");
                    };
                    if ds.sub_replace(subs_id, SubKind::GroupIdMap, uri, body.clone()) {
                        SbiResponse::with_status(200)
                            .with_body(body.to_string(), "application/json")
                    } else {
                        send_not_found("Subscription not found", Some("DATA_NOT_FOUND"))
                    }
                }
                (false, "DELETE") => {
                    if ds.sub_remove(subs_id).is_some() {
                        SbiResponse::with_status(204)
                    } else {
                        send_not_found("Subscription not found", Some("DATA_NOT_FOUND"))
                    }
                }
                _ => send_method_not_allowed(method, "nf-group-ids/subscriptions"),
            }
        }
        // GET /routing-ids: routing-id assignment is a separate data model this
        // core does not hold, so it is recognised and refused rather than
        // answered with a fabricated mapping.
        ("routing-ids", None) => {
            if method != "GET" {
                return send_method_not_allowed(method, "routing-ids");
            }
            send_error(
                501,
                "Not Implemented",
                "routing-ids assignment is not provisioned in this UDR",
                Some("NOT_IMPLEMENTED"),
            )
        }
        _ => send_not_found("Unknown nudr-group-id-map resource", None),
    }
}

/// Process-wide OAuth2 client for automatic Bearer-token acquisition on
/// outbound SBI calls (Wave-6 H8 Phase A). Installed only when the existing
/// `udr.sbi.oauth2.require` producer knob is enabled; attaching a Bearer to a
/// non-verifying producer is a no-op, so this is matched-sim-E2E safe.
static OAUTH2_CLIENT: std::sync::OnceLock<Option<Arc<nextgcore_sbi::oauth::OAuth2Client>>> =
    std::sync::OnceLock::new();

/// The shared OAuth2 client, if SBI OAuth2 enforcement is enabled.
#[allow(dead_code)]
fn oauth2_client() -> Option<Arc<nextgcore_sbi::oauth::OAuth2Client>> {
    OAUTH2_CLIENT.get().and_then(|opt| opt.clone())
}

#[tokio::main]
async fn main() -> Result<()> {
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

    log::info!("NextGCore UDR v{} starting...", env!("CARGO_PKG_VERSION"));

    // Issue: `--kill` was advertised as "Kill running instance" and did
    // NOTHING -- it logged an intention and returned success, so the process
    // exited 0 while the instance kept serving. Fail loudly instead.
    if args.kill {
        return Err(nextgcore_core::signal::kill_unsupported().into());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize UDR context
    udr_context_init();
    log::info!("UDR context initialized");

    // Initialise the persistent data store for non-subscriber resource trees.
    // Path precedence: --state-file flag, then NEXTGCORE_UDR_STATE_FILE env.
    // With neither set the store stays purely in-memory (previous behaviour).
    let state_file = args
        .state_file
        .clone()
        .or_else(|| std::env::var("NEXTGCORE_UDR_STATE_FILE").ok())
        .filter(|s| !s.is_empty());
    match &state_file {
        Some(path) => {
            nextgcore_udrd::data_store::init_store(Some(std::path::PathBuf::from(path)));
            log::info!("UDR resource-tree persistence enabled: {path}");
        }
        None => {
            nextgcore_udrd::data_store::init_store(None);
            log::info!("UDR resource-tree persistence disabled (in-memory only)");
        }
    }

    // Initialize UDR state machine
    let mut udr_sm = UdrSmContext::new();
    udr_sm.init();
    log::info!("UDR state machine initialized");

    // Parse configuration to get db_uri and seed NRF URI
    let db_uri = parse_db_uri(&args.config);
    if !db_uri.is_empty() {
        match nextgcore_dbi::nextgcore_dbi_init_async(db_uri.clone()).await {
            Ok(()) => log::info!("MongoDB connected: {}", mask_uri(&db_uri)),
            Err(e) => log::warn!("MongoDB init failed (will use defaults): {e:?}"),
        }
    } else {
        log::warn!("No db_uri configured, UDR will return hardcoded test data");
    }

    // Seed NRF URI into SBI context for NF registration, and pick up the
    // OAuth2 enforcement knob (udr.sbi.oauth2.require).
    let mut nrf_uri_cfg: Option<String> = None;
    let mut require_oauth2 = false;
    if let Ok(content) = std::fs::read_to_string(&args.config) {
        if let Ok(yaml) = serde_yaml::from_str::<UdrYaml>(&content) {
            let udr_section = yaml.udr;
            // #87: Nudr_GroupIDmap assignments. Absent config leaves the map
            // empty, so `GET /nf-group-ids` answers 404 DATA_NOT_FOUND rather
            // than inventing a group id.
            if let Some(entries) = udr_section.as_ref().and_then(|u| u.group_id_map.clone()) {
                log::info!("Nudr_GroupIDmap: {} assignment range(s)", entries.len());
                set_group_id_map(entries);
            }
            if let Some(sbi) = udr_section.and_then(|udr| udr.sbi) {
                // Override the advertised/bind SBI address with the routable
                // address from config so the NRF NFProfile advertises a
                // reachable endpoint (not 0.0.0.0).
                if let Some(server) = sbi.server.as_ref().and_then(|s| s.first()) {
                    if let Some(addr) = &server.address {
                        args.sbi_addr = addr.clone();
                    }
                    if let Some(port) = server.port {
                        args.sbi_port = port;
                    }
                }
                nrf_uri_cfg = sbi
                    .client
                    .and_then(|client| client.nrf)
                    .and_then(|nrf_list| nrf_list.into_iter().next())
                    .map(|nrf| nrf.uri);
                require_oauth2 = sbi
                    .oauth2
                    .and_then(|oauth2| oauth2.require)
                    .unwrap_or(false);
            }
        }
    }
    if let Some(uri) = &nrf_uri_cfg {
        log::info!("NRF URI configured: {uri}");
        nextgcore_sbi::context::global_context()
            .set_nrf_uri(uri)
            .await;
    }

    // Build SBI server configuration (legacy, for context)
    let sbi_config = SbiServerConfig {
        addr: args.sbi_addr.clone(),
        port: args.sbi_port,
        tls_enabled: args.tls,
        tls_cert: args.tls_cert.clone(),
        tls_key: args.tls_key.clone(),
    };

    // Open legacy SBI context (for context initialization)
    udr_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;

    // Start actual HTTP/2 SBI server using nextgcore-sbi
    let sbi_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let mut sbi_server_config = NextgcoreSbiServerConfig::new(sbi_addr);
    if require_oauth2 {
        // Verify bearer tokens against the NRF's published keys (auth stage
        // 4b). With no NRF URI configured the server fails closed.
        sbi_server_config.require_oauth2 = true;
        sbi_server_config.oauth2_jwks_uri = nrf_uri_cfg
            .as_deref()
            .map(|uri| JwksCache::for_nrf(uri).jwks_uri().to_string());
        // Issue #64 gap 3: assert the token's `aud` names the UDR.
        //
        // Without this `oauth2_expected_audience` stays None, the server calls
        // `authorize_bearer_aud(.., None)` and the audience check is SKIPPED -- so a
        // token the NRF minted for any other producer was accepted here, on the NF
        // that holds subscriber data. TS 33.501 13.4.1.2 requires the producer to
        // verify it is the intended audience. Every other OAuth2-enforcing NF
        // already did this; the UDR was the one that did not.
        sbi_server_config =
            sbi_server_config.with_expected_audience_nf_type(nextgcore_sbi::types::NfType::Udr);
        // Wave-6 H8 Phase A: install the process-wide OAuth2 client so outbound
        // SBI calls acquire and attach an NRF-issued Bearer token.
        if let Some(nrf_uri) = nrf_uri_cfg.as_deref() {
            let nf_instance_id = format!("udr-{}", uuid::Uuid::new_v4());
            let oauth2 = Arc::new(nextgcore_sbi::oauth::OAuth2Client::new(
                nrf_uri,
                nf_instance_id,
                nextgcore_sbi::types::NfType::Udr,
            ));
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
        .start(udr_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    log::info!("SBI HTTP/2 server listening on {sbi_addr}");

    // Register with NRF and start heartbeat worker
    match register_with_nrf(&args.sbi_addr, args.sbi_port).await {
        Ok(nf_instance_id) if !nf_instance_id.is_empty() => {
            // G2-2: PATCH a real NFProfile "/load" gauge to NRF each heartbeat
            // (tracked subscribers, saturated at 100; TS 29.510 §5.2.2.3.2).
            nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(nf_instance_id, 5, || {
                let ctx = nextgcore_udrd::context::udr_self();
                let load = ctx.read().map(|c| c.get_load()).unwrap_or(0);
                load.clamp(0, 100) as u8
            });
        }
        Ok(_) => {}
        Err(e) => {
            log::warn!("NRF registration failed (will operate without NRF): {e}");
        }
    }

    log::info!("NextGCore UDR ready");

    // Main event loop (async)
    run_event_loop_async(shutdown).await?;

    // Graceful shutdown
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

    // Close legacy SBI server
    udr_sbi_close();
    log::info!("SBI server closed");

    // Cleanup state machine
    udr_sm.fini();
    log::info!("UDR state machine finalized");

    // Cleanup context
    udr_context_final();
    log::info!("UDR context finalized");

    // Cleanup database
    nextgcore_dbi::nextgcore_dbi_final();

    log::info!("NextGCore UDR stopped");
    Ok(())
}

/// SBI request handler for UDR
async fn udr_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("UDR SBI request: {method} {uri}");

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    // Expected paths:
    // /nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-subscription
    // /nudr-dr/v2/subscription-data/{supi}/provisioned-data/{dataset}
    // /nudr-dr/v2/subscription-data/{supi}/{plmn}/provisioned-data/{dataset}
    // /nudr-dr/v2/policy-data/ues/{supi}/{resource}

    if parts.len() < 3 {
        return send_not_found("Invalid path", None);
    }

    let service = parts[0];
    let _version = parts[1];

    // #87: Nudr_GroupIDmap is a distinct service, not a nudr-dr resource.
    if service == "nudr-group-id-map" {
        return handle_group_id_map(&parts, method, &request);
    }

    if service != "nudr-dr" {
        log::warn!("Unknown service: {service}");
        return send_not_found(&format!("Unknown service: {service}"), None);
    }

    // Route based on resource type
    let resource_type = parts.get(2).copied().unwrap_or("");

    match resource_type {
        "subscription-data" if parts.get(3).copied() == Some("subs-to-notify") => {
            handle_subscription_data_subs(&parts, method, &request).await
        }
        "subscription-data" => handle_subscription_data(&parts, method, &request).await,
        "policy-data" => handle_policy_data(&parts, method, &request).await,
        "exposure-data" => handle_exposure_data(&parts, method, &request).await,
        "application-data" => handle_application_data(&parts, method, &request).await,
        _ => {
            log::warn!("Unknown UDR resource: {method} {uri}");
            send_not_found(&format!("Unknown resource: {resource_type}"), None)
        }
    }
}

/// 400 ProblemDetails for a missing mandatory attribute.
fn missing_mandatory(attr: &str) -> SbiResponse {
    send_error(
        400,
        "Bad Request",
        &format!("Missing mandatory attribute: {attr}"),
        Some("MANDATORY_IE_MISSING"),
    )
}

/// Parse a JSON request body, or produce a 400 ProblemDetails.
fn parse_json_body(request: &SbiRequest) -> Result<serde_json::Value, Box<SbiResponse>> {
    let content = request.http.content.as_deref().ok_or_else(|| {
        Box::new(send_bad_request(
            "Missing request body",
            Some("MANDATORY_IE_MISSING"),
        ))
    })?;
    serde_json::from_str(content).map_err(|e| {
        Box::new(send_bad_request(
            &format!("Invalid JSON: {e}"),
            Some("INVALID_MSG_FORMAT"),
        ))
    })
}

/// Minimal percent-decoding for query parameter values.
fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Handle subscription-data requests
/// Path: /nudr-dr/v2/subscription-data/{supi}/...
async fn handle_subscription_data(
    parts: &[&str],
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    // parts[3] = {supi} or {suci}
    let supi_or_suci = match parts.get(3) {
        Some(s) => *s,
        None => return send_bad_request("Missing SUPI", Some("MISSING_SUPI")),
    };

    // identity-data is defined for ANY VarUeId, SUPI or GPSI (TS 29.505
    // §5.2.19 "Retrieve identity data by SUPI or GPSI") -- resolving a GPSI is
    // the whole point of the resource -- so it is dispatched before the
    // SUPI-shaped validation below, which would reject `msisdn-`/`extid-`.
    if parts.get(4).copied() == Some("identity-data") {
        return handle_identity_data(supi_or_suci, method, request).await;
    }

    // Convert SUCI to IMSI if needed
    // SUCI format: suci-{type}-{mcc}-{mnc}-{routing}-{scheme}-{msin}
    // For null scheme (0), IMSI = MCC + MNC + MSIN
    let supi = if supi_or_suci.starts_with("suci-") {
        let suci_parts: Vec<&str> = supi_or_suci.split('-').collect();
        if suci_parts.len() >= 7 && suci_parts[1] == "0" {
            let mcc = suci_parts[2];
            let mnc = suci_parts[3];
            let msin = suci_parts[6..].join("");
            let imsi = format!("imsi-{mcc}{mnc}{msin}");
            log::info!("Converted SUCI {supi_or_suci} -> SUPI {imsi}");
            imsi
        } else {
            log::warn!("Unsupported SUCI format: {supi_or_suci}");
            return send_bad_request(
                &format!("Unsupported SUCI: {supi_or_suci}"),
                Some("INVALID_SUCI"),
            );
        }
    } else if supi_or_suci.starts_with("imsi-") {
        supi_or_suci.to_string()
    } else if supi_or_suci.starts_with("nai-")
        || supi_or_suci.starts_with("gci-")
        || supi_or_suci.starts_with("gli-")
    {
        // TS 29.571 VarUeId forms: NAI / GCI / GLI are spec-valid identifiers
        // but are not backed by the subscriber DB in this UDR instance.
        // Return 404 NOT_FOUND (not 400) so the caller knows the form is
        // syntactically valid but not provisioned (udrd-06).
        log::info!("VarUeId form not in subscriber DB, returning 404: {supi_or_suci}");
        return send_not_found(
            &format!("VarUeId form not in subscriber DB: {supi_or_suci}"),
            Some("NOT_FOUND"),
        );
    } else if supi_or_suci.starts_with("extgroupid-") {
        // TS 29.571 external group identifiers target group subscriptions;
        // not supported in this Nudr_DataRepository instance (udrd-06).
        return send_error(
            501,
            "Not Implemented",
            "External group identifiers (extgroupid-) are not supported",
            Some("NOT_SUPPORTED"),
        );
    } else {
        log::warn!("Invalid SUPI type: {supi_or_suci}");
        return send_bad_request(
            &format!("Invalid SUPI type: {supi_or_suci}"),
            Some("INVALID_SUPI"),
        );
    };
    let supi = supi.as_str();

    // Determine sub-resource: parts[4] could be "authentication-data" or "provisioned-data"
    // or a PLMN ID (then parts[5] = "provisioned-data")
    let sub_resource = parts.get(4).copied().unwrap_or("");

    match sub_resource {
        "authentication-data" => handle_auth_data(supi, parts, method, request).await,
        "provisioned-data" => handle_provisioned_data(supi, parts, 5, method, request).await,
        "context-data" => handle_context_data(supi, parts, method, request).await,
        // #87: the Parameter Provision documents the UDM's Nudm_PP producer
        // reads and writes (TS 29.505 §5.2.13).
        "pp-data" => handle_pp_data(supi, method, request),
        "pp-data-store" => {
            let af_instance_id = parts.get(5).copied().unwrap_or("");
            handle_pp_data_store(supi, af_instance_id, method, request)
        }
        _ => {
            // Check if parts[4] is a PLMN ID and parts[5] = "provisioned-data"
            // (PLMN-scoped layout per TS 29.504:
            //  /subscription-data/{ueId}/{servingPlmnId}/provisioned-data/...)
            if parts.get(5).copied() == Some("provisioned-data") {
                if !is_valid_plmn_id(sub_resource) {
                    return send_error(
                        400,
                        "Bad Request",
                        &format!("Invalid servingPlmnId: {sub_resource}"),
                        Some("MANDATORY_IE_INCORRECT"),
                    );
                }
                handle_provisioned_data(supi, parts, 6, method, request).await
            } else if parts.get(5).copied() == Some("context-data") {
                handle_context_data(supi, parts, method, request).await
            } else {
                log::warn!("Unknown subscription-data sub-resource: {sub_resource}");
                send_not_found("Unknown sub-resource", None)
            }
        }
    }
}

/// `GET /subscription-data/{ueId}/identity-data` — TS 29.505 §5.2.19.
///
/// Answers in BOTH directions from the one subscriber record, because that is
/// what the resource is for: `{ueId}` may be a SUPI or a GPSI, and the response
/// carries `supiList` and `gpsiList` regardless. The subscriber DB query is
/// `{<idType>: <idValue>}` over a single document, so an `msisdn-` identifier
/// resolves the same subscriber as its `imsi-` — which is what lets a NEF
/// translate a GPSI it was given by an AF into the SUPI every other 5GC
/// interface needs.
async fn handle_identity_data(ue_id: &str, method: &str, request: &SbiRequest) -> SbiResponse {
    if method != "GET" {
        return send_method_not_allowed(method, "identity-data");
    }
    let _ = request;
    log::info!("[{ue_id}] GET identity-data");
    match nextgcore_dbi::subscription::nextgcore_dbi_subscription_data_async(ue_id.to_string())
        .await
    {
        Ok(data) => {
            let doc = build_identity_data(&data);
            // supiList is what a consumer translating a GPSI needs; a record
            // with no SUPI cannot answer the question that was asked.
            if doc
                .get("supiList")
                .and_then(|v| v.as_array())
                .is_none_or(|a| a.is_empty())
            {
                return send_not_found(
                    "No SUPI stored for this identifier",
                    Some("DATA_NOT_FOUND"),
                );
            }
            SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
        }
        Err(e) => {
            log::debug!("[{ue_id}] identity-data lookup failed: {e:?}");
            send_not_found("Subscriber not found", Some("DATA_NOT_FOUND"))
        }
    }
}

/// Build a TS 29.505 `IdentityData` from a subscriber record.
///
/// `supiList` carries the record's IMSI in `imsi-` form and `gpsiList` its
/// MSISDNs in `msisdn-` form — the same GPSI spelling `am-data` uses, so a
/// consumer sees one identity vocabulary across both resources. Both members
/// have `minItems: 1`, so an empty list is omitted rather than emitted empty.
fn build_identity_data(
    data: &nextgcore_dbi::types::NextgcoreSubscriptionData,
) -> serde_json::Value {
    let mut doc = serde_json::Map::new();
    if let Some(imsi) = data.imsi.as_deref() {
        doc.insert(
            "supiList".to_string(),
            serde_json::json!([format!("imsi-{imsi}")]),
        );
    }
    if data.num_of_msisdn > 0 {
        let gpsis: Vec<serde_json::Value> = data
            .msisdn
            .iter()
            .map(|m| serde_json::Value::String(format!("msisdn-{}", m.bcd)))
            .collect();
        doc.insert("gpsiList".to_string(), serde_json::Value::Array(gpsis));
    }
    serde_json::Value::Object(doc)
}

/// `GET`/`PATCH /subscription-data/{ueId}/pp-data` — TS 29.505 §5.2.13.
///
/// The UE-level Parameter Provision document. A `PUT` is accepted as well as
/// PATCH so an operator (or the webui) can provision the document in one step;
/// TS 29.505 defines GET and PATCH, and PATCH on an absent document would
/// otherwise have no way to ever start.
fn handle_pp_data(supi: &str, method: &str, request: &SbiRequest) -> SbiResponse {
    let ds = data_store::store();
    let path = format!("/nudr-dr/v2/subscription-data/{supi}/pp-data");
    match method {
        "GET" => match ds.doc_get("pp-data", supi) {
            Some(doc) => {
                SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
            }
            None => send_not_found("No pp-data provisioned", Some("DATA_NOT_FOUND")),
        },
        "PUT" => {
            let doc = match parse_json_body(request) {
                Ok(v) if v.is_object() => v,
                Ok(_) => {
                    return send_bad_request(
                        "Body must be a JSON object",
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
                Err(resp) => return *resp,
            };
            let created = ds.doc_put("pp-data", supi, doc.clone());
            notify_subscription_data_change(supi, &path, Some(&doc));
            if created {
                SbiResponse::with_status(201)
                    .with_header("Location", path)
                    .with_body(doc.to_string(), "application/json")
            } else {
                SbiResponse::with_status(204)
            }
        }
        "PATCH" => {
            let patch = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            // An absent document starts empty rather than 404ing: PATCH is the
            // provisioning verb TS 29.503 §5.6.2.2 gives an AF, and refusing the
            // first provision would leave it with no way to create one.
            let mut doc = ds
                .doc_get("pp-data", supi)
                .unwrap_or_else(|| serde_json::json!({}));
            if let Some(resp) = apply_patch_document(&mut doc, &patch) {
                return resp;
            }
            ds.doc_put("pp-data", supi, doc.clone());
            notify_subscription_data_change(supi, &path, Some(&doc));
            SbiResponse::with_status(204)
        }
        "DELETE" => {
            if ds.doc_remove("pp-data", supi).is_some() {
                notify_subscription_data_change(supi, &path, None);
            }
            SbiResponse::with_status(204)
        }
        _ => send_method_not_allowed(method, "pp-data"),
    }
}

/// `PUT`/`GET`/`DELETE /subscription-data/{ueId}/pp-data-store/{afInstanceId}` —
/// TS 29.505 §5.2.13, the per-AF Parameter Provision entry. The collection GET
/// returns every AF's entry for the UE.
fn handle_pp_data_store(
    supi: &str,
    af_instance_id: &str,
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let ds = data_store::store();
    let prefix = format!("{supi}\u{1f}");
    let key = format!("{prefix}{af_instance_id}");
    let path = format!("/nudr-dr/v2/subscription-data/{supi}/pp-data-store/{af_instance_id}");
    match (af_instance_id.is_empty(), method) {
        (true, "GET") => {
            let list: Vec<serde_json::Value> = ds
                .doc_list("pp-data-store")
                .into_iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(_, v)| v)
                .collect();
            SbiResponse::with_status(200).with_body(
                serde_json::Value::Array(list).to_string(),
                "application/json",
            )
        }
        (false, "GET") => match ds.doc_get("pp-data-store", &key) {
            Some(doc) => {
                SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
            }
            None => send_not_found("No pp-data entry for this AF", Some("DATA_NOT_FOUND")),
        },
        (false, "PUT") => {
            let doc = match parse_json_body(request) {
                Ok(v) if v.is_object() => v,
                Ok(_) => {
                    return send_bad_request(
                        "Body must be a JSON object",
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
                Err(resp) => return *resp,
            };
            let created = ds.doc_put("pp-data-store", &key, doc.clone());
            notify_subscription_data_change(supi, &path, Some(&doc));
            if created {
                SbiResponse::with_status(201)
                    .with_header("Location", path)
                    .with_body(doc.to_string(), "application/json")
            } else {
                SbiResponse::with_status(204)
            }
        }
        (false, "DELETE") => {
            if ds.doc_remove("pp-data-store", &key).is_some() {
                notify_subscription_data_change(supi, &path, None);
                SbiResponse::with_status(204)
            } else {
                send_not_found("No pp-data entry for this AF", Some("DATA_NOT_FOUND"))
            }
        }
        _ => send_method_not_allowed(method, "pp-data-store"),
    }
}

/// VarPlmnId per TS 29.505: 5 or 6 digits (MCC+MNC).
fn is_valid_plmn_id(s: &str) -> bool {
    (s.len() == 5 || s.len() == 6) && s.bytes().all(|b| b.is_ascii_digit())
}

/// Handle authentication-data requests
/// Path: /nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-subscription
async fn handle_auth_data(
    supi: &str,
    parts: &[&str],
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let resource = parts.get(5).copied().unwrap_or("");

    match (resource, method) {
        ("authentication-subscription", "GET") => {
            log::info!("[{supi}] GET authentication-subscription");

            match nextgcore_dbi::subscription::nextgcore_dbi_auth_info_async(supi.to_string()).await
            {
                Ok(auth_info) => {
                    let response_json = build_auth_subscription_json(supi, &auth_info);
                    log::info!("[{supi}] Returning auth subscription data");
                    SbiResponse::with_status(200)
                        .with_body(response_json.to_string(), "application/json")
                }
                Err(e) => {
                    log::error!("[{supi}] DB auth_info query failed: {e:?}");
                    send_not_found("Subscriber not found", Some("NOT_FOUND"))
                }
            }
        }
        ("authentication-subscription", "PUT") => {
            // Provisioning path: create/replace the stored
            // AuthenticationSubscription credentials.
            log::info!("[{supi}] PUT authentication-subscription");
            let body = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            let auth_method = match body.get("authenticationMethod").and_then(|v| v.as_str()) {
                Some(m) => m.to_string(),
                None => return missing_mandatory("authenticationMethod"),
            };
            let k_hex = match body.get("encPermanentKey").and_then(|v| v.as_str()) {
                Some(k) if k.len() == 32 && k.bytes().all(|b| b.is_ascii_hexdigit()) => {
                    k.to_string()
                }
                Some(_) => {
                    return send_error(
                        400,
                        "Bad Request",
                        "encPermanentKey must be 32 hex characters",
                        Some("MANDATORY_IE_INCORRECT"),
                    )
                }
                None => return missing_mandatory("encPermanentKey"),
            };
            let provision = nextgcore_dbi::subscription::NextgcoreDbiAuthProvision {
                k_hex,
                opc_hex: body
                    .get("encOpcKey")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                op_hex: None,
                amf_hex: body
                    .get("authenticationManagementField")
                    .and_then(|v| v.as_str())
                    .unwrap_or("8000")
                    .to_string(),
                sqn: body
                    .get("sequenceNumber")
                    .and_then(|v| v.get("sqn"))
                    .and_then(|v| v.as_str())
                    .and_then(|s| u64::from_str_radix(s, 16).ok())
                    .unwrap_or(0),
                auth_method,
                // #115: TS 29.505 `algorithmId` and `encTopcKey`. Both optional, both
                // stored verbatim — `algorithmId` because the spec makes its values
                // HPLMN-operator specific and the UDR is not the component that
                // interprets them, `encTopcKey` because it is opaque key material.
                //
                // Validated for LENGTH and hex-ness though, like `encPermanentKey`
                // above: a TOPc that is not 32 bytes cannot be used by TUAK at all, and
                // discovering that at authentication time turns a provisioning mistake
                // into an outage. `top` is accepted under the same rule so an operator
                // can provision TOP and let the UDR derive TOPc (TS 35.231 §7.1).
                algorithm_id: body
                    .get("algorithmId")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string()),
                topc_hex: match validate_optional_key_256(&body, "encTopcKey") {
                    Ok(v) => v,
                    Err(resp) => return *resp,
                },
                top_hex: match validate_optional_key_256(&body, "top") {
                    Ok(v) => v,
                    Err(resp) => return *resp,
                },
            };
            match nextgcore_dbi::subscription::nextgcore_dbi_provision_auth_info_async(
                supi.to_string(),
                provision,
            )
            .await
            {
                Ok(created) => {
                    let path = format!(
                        "/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-subscription"
                    );
                    notify_subscription_data_change(supi, &path, Some(&body));
                    if created {
                        SbiResponse::with_status(201)
                            .with_header("Location", path)
                            .with_body(body.to_string(), "application/json")
                    } else {
                        SbiResponse::with_status(204)
                    }
                }
                Err(nextgcore_dbi::DbiError::NotInitialized) => send_error(
                    503,
                    "Service Unavailable",
                    "Subscriber database unavailable",
                    Some("SYSTEM_FAILURE"),
                ),
                Err(e) => {
                    log::error!("[{supi}] DB provision failed: {e:?}");
                    send_error(
                        500,
                        "Internal Server Error",
                        "Failed to provision authentication subscription",
                        Some("SYSTEM_FAILURE"),
                    )
                }
            }
        }
        ("authentication-subscription", "PATCH") => {
            log::info!("[{supi}] PATCH authentication-subscription");

            // TS 29.505 (Nudr subscription-data): PATCH applies the
            // PatchItemList and nothing else — the UDR must store exactly
            // what is written.  SQN generation/advancement is the
            // authentication-centre (UDM/ARPF) function per TS 33.102
            // Annex C.3; udmd already advances the SQN itself before
            // PATCHing the new value (advance_sqn_ind).  The previous
            // unconditional SQN-increment side effect here corrupted every
            // stored SQN by an extra +32 SEQ step (WSB-6).
            // Failures are REPORTED, not swallowed. Previously every path here
            // fell through to 204, so a consumer could not tell an applied
            // patch from a malformed body, an unsupported path, or a database
            // error -- and a non-hex SQN silently became 0 via
            // unwrap_or(0), corrupting the stored value rather than rejecting
            // it. TS 29.505 §5.2.2.x reports failed modifications via
            // PatchResult {report: [ReportItem{path, reason}]} (TS 29.571),
            // and errors carry ProblemDetails (TS 29.500 §5.2.7).
            let Some(content) = &request.http.content else {
                return send_bad_request(
                    "PATCH requires a PatchItem array body",
                    Some("INVALID_MSG_FORMAT"),
                );
            };
            let Ok(patches) = serde_json::from_str::<serde_json::Value>(content) else {
                return send_bad_request("Body is not valid JSON", Some("INVALID_MSG_FORMAT"));
            };
            let Some(arr) = patches.as_array() else {
                return send_bad_request(
                    "Body must be a JSON array of PatchItem",
                    Some("INVALID_MSG_FORMAT"),
                );
            };
            if arr.is_empty() {
                // PatchResult.report is minItems: 1, so an empty patch list can
                // be reported neither as success nor as a failure item.
                return send_bad_request(
                    "PatchItem array must not be empty",
                    Some("INVALID_MSG_FORMAT"),
                );
            }

            // ReportItem.reason should identify the failing operation by its
            // array index (TS 29.571 ReportItem).
            let mut report: Vec<serde_json::Value> = Vec::new();
            let mut applied = 0usize;
            for (idx, patch) in arr.iter().enumerate() {
                let path = patch.get("path").and_then(|v| v.as_str()).unwrap_or("");
                if path != "/sequenceNumber/sqn" {
                    report.push(serde_json::json!({
                        "path": path,
                        "reason": format!(
                            "unsupported path; this UDR applies only \
                             /sequenceNumber/sqn (failed operation index= {idx})"
                        ),
                    }));
                    continue;
                }
                let Some(sqn_hex) = patch.get("value").and_then(|v| v.as_str()) else {
                    report.push(serde_json::json!({
                        "path": path,
                        "reason": format!(
                            "value is absent or not a string \
                             (failed operation index= {idx})"
                        ),
                    }));
                    continue;
                };
                // Reject rather than coerce: the SQN is 48 bits (TS 33.102), so
                // a non-hex or oversized value is a client error, not a 0.
                let sqn = match u64::from_str_radix(sqn_hex, 16) {
                    Ok(v) if v <= 0xFFFF_FFFF_FFFF => v,
                    Ok(_) => {
                        report.push(serde_json::json!({
                            "path": path,
                            "reason": format!(
                                "value exceeds the 48-bit SQN range \
                                 (failed operation index= {idx})"
                            ),
                        }));
                        continue;
                    }
                    Err(_) => {
                        report.push(serde_json::json!({
                            "path": path,
                            "reason": format!(
                                "value is not hexadecimal \
                                 (failed operation index= {idx})"
                            ),
                        }));
                        continue;
                    }
                };
                match nextgcore_dbi::subscription::nextgcore_dbi_update_sqn_async(
                    supi.to_string(),
                    sqn,
                )
                .await
                {
                    Ok(()) => applied += 1,
                    // A storage failure is ours, not the consumer's: surface it
                    // as 5xx immediately rather than as a PatchResult item.
                    Err(nextgcore_dbi::DbiError::NotInitialized) => {
                        return send_error(
                            503,
                            "Service Unavailable",
                            "Subscriber database unavailable",
                            Some("SYSTEM_FAILURE"),
                        );
                    }
                    Err(e) => {
                        log::error!("[{supi}] DB update_sqn failed: {e:?}");
                        return send_error(
                            500,
                            "Internal Server Error",
                            "Failed to store the patched sequence number",
                            Some("SYSTEM_FAILURE"),
                        );
                    }
                }
            }

            if !report.is_empty() {
                log::warn!(
                    "[{supi}] PATCH authentication-subscription: {} of {} items failed",
                    report.len(),
                    arr.len()
                );
                return SbiResponse::with_status(400).with_body(
                    serde_json::json!({ "report": report }).to_string(),
                    "application/json",
                );
            }

            log::info!("[{supi}] PATCH applied {applied} item(s)");
            SbiResponse::with_status(204)
        }
        ("authentication-status", "PUT" | "GET" | "DELETE") => {
            // TS 29.505 §6.3.3 / TS 29.503 §5.4.2: the authentication-status
            // resource carries the AuthEvent the UDM writes on authentication
            // confirmation (TS 33.501 §6.1.4 result storage). It has NO SQN
            // semantics -- an earlier unconditional SQN increment here advanced
            // the stored SQN by an extra +32 SEQ step on every confirmation
            // (WSB-6).
            //
            // The AuthEvent used to be acknowledged with a bare 204 and then
            // DISCARDED, and GET fell through to the catch-all 405 even though
            // TS 29.505 defines PUT/GET/DELETE on both the collection form and
            // the individual .../{servingNetworkName} form. It is now stored.
            //
            // parts[6], when present, is {servingNetworkName}.
            let path_snn = parts.get(6).copied().filter(|s| !s.is_empty());
            handle_auth_status(supi, path_snn, method, request)
        }
        _ => {
            log::warn!("[{supi}] Unknown auth resource: {method} {resource}");
            send_method_not_allowed(
                method,
                &format!("/nudr-dr/v2/subscription-data/{supi}/authentication-data/{resource}"),
            )
        }
    }
}

/// Handle context-data requests
/// Path: /nudr-dr/v2/subscription-data/{supi}/context-data/{resource}
///
/// Implements (TS 29.505 §5.2.4):
/// - GET/PUT/PATCH/DELETE amf-3gpp-access, amf-non-3gpp-access
/// - GET/PUT/PATCH/DELETE smsf-3gpp-access, smsf-non-3gpp-access, ip-sm-gw
/// - GET/PUT/PATCH/DELETE smf-registrations/{pdu-session-id} + collection
/// - CRUD on sdm-subscriptions/{subsId} and ee-subscriptions/{subsId}
async fn handle_context_data(
    supi: &str,
    parts: &[&str],
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let resource_idx = if parts.get(4).copied() == Some("context-data") {
        5
    } else {
        6
    };
    let resource = parts.get(resource_idx).copied().unwrap_or("");
    let tail = parts.get(resource_idx + 1).copied().unwrap_or("");

    log::info!("[{supi}] {method} context-data/{resource}");

    match resource {
        "amf-3gpp-access" => {
            handle_amf_access(supi, AmfAccessSlot::ThreeGpp, method, request).await
        }
        // #87 gap 1: this resource returned 404, so non-3GPP AMF registration
        // state could not be stored or read at all -- the store the udmd
        // producer added in #84 writes to.
        "amf-non-3gpp-access" => {
            handle_amf_access(supi, AmfAccessSlot::Non3Gpp, method, request).await
        }
        "smf-registrations" => handle_smf_registrations(supi, method, request, tail),
        // Simple per-UE context documents: one store slot each, same CRUD.
        "smsf-3gpp-access" | "smsf-non-3gpp-access" | "ip-sm-gw" => {
            handle_ue_context_document(supi, resource, method, request)
        }
        // Per-UE subscription collections (TS 29.505 §5.2.4): the UDM's own
        // SDM / EE subscriptions, stored so they survive a UDM restart.
        "sdm-subscriptions" | "ee-subscriptions" => {
            handle_ue_context_collection(supi, resource, tail, method, request)
        }
        _ => {
            log::warn!("[{supi}] Unknown context-data resource: {resource}");
            send_not_found(&format!("Unknown context resource: {resource}"), None)
        }
    }
}

/// Which AMF access-registration document a context-data request addresses.
///
/// The 3GPP slot keeps its dedicated store map (and therefore its snapshot key)
/// while the non-3GPP one lives in the generic document store — the two accesses
/// are distinct resources (TS 29.505 §5.2.4) and a write to one must be
/// invisible to a read of the other, which is exactly the defect #84 fixed on
/// the UDM side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AmfAccessSlot {
    ThreeGpp,
    Non3Gpp,
}

impl AmfAccessSlot {
    fn resource(self) -> &'static str {
        match self {
            Self::ThreeGpp => "amf-3gpp-access",
            Self::Non3Gpp => "amf-non-3gpp-access",
        }
    }

    fn get(self, supi: &str) -> Option<serde_json::Value> {
        let ds = data_store::store();
        match self {
            Self::ThreeGpp => ds.amf_3gpp_get(supi),
            Self::Non3Gpp => ds.doc_get(self.resource(), supi),
        }
    }

    /// Store the document; returns true when newly created.
    fn put(self, supi: &str, doc: serde_json::Value) -> bool {
        let ds = data_store::store();
        match self {
            Self::ThreeGpp => ds.amf_3gpp_put(supi, doc),
            Self::Non3Gpp => ds.doc_put(self.resource(), supi, doc),
        }
    }

    fn remove(self, supi: &str) -> Option<serde_json::Value> {
        let ds = data_store::store();
        match self {
            Self::ThreeGpp => ds.amf_3gpp_remove(supi),
            Self::Non3Gpp => ds.doc_remove(self.resource(), supi),
        }
    }

    fn path(self, supi: &str) -> String {
        context_data_path(supi, self.resource())
    }
}

/// The resource URI of a per-UE context-data document (notification resourceId).
fn context_data_path(supi: &str, resource: &str) -> String {
    format!("/nudr-dr/v2/subscription-data/{supi}/context-data/{resource}")
}

/// CRUD for a single-document per-UE context resource (`smsf-*`, `ip-sm-gw`).
///
/// PATCH is a merge onto the stored document and 404s when there is nothing to
/// patch: applying a patch to an absent resource would invent a registration
/// from a partial update.
fn handle_ue_context_document(
    supi: &str,
    resource: &str,
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let ds = data_store::store();
    let path = context_data_path(supi, resource);
    match method {
        "GET" => match ds.doc_get(resource, supi) {
            Some(doc) => {
                SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
            }
            None => send_not_found(
                &format!("{resource} context not found"),
                Some("CONTEXT_NOT_FOUND"),
            ),
        },
        "PUT" => {
            let doc = match parse_json_body(request) {
                Ok(v) if v.is_object() => v,
                Ok(_) => {
                    return send_bad_request(
                        "Body must be a JSON object",
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
                Err(resp) => return *resp,
            };
            let created = ds.doc_put(resource, supi, doc.clone());
            notify_subscription_data_change(supi, &path, Some(&doc));
            if created {
                SbiResponse::with_status(201)
                    .with_header("Location", path)
                    .with_body(doc.to_string(), "application/json")
            } else {
                SbiResponse::with_status(204)
            }
        }
        "PATCH" => {
            let Some(mut doc) = ds.doc_get(resource, supi) else {
                return send_not_found(
                    &format!("{resource} context not found"),
                    Some("CONTEXT_NOT_FOUND"),
                );
            };
            let patch = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            if let Some(resp) = apply_patch_document(&mut doc, &patch) {
                return resp;
            }
            ds.doc_put(resource, supi, doc.clone());
            notify_subscription_data_change(supi, &path, Some(&doc));
            SbiResponse::with_status(204)
        }
        "DELETE" => {
            if ds.doc_remove(resource, supi).is_some() {
                notify_subscription_data_change(supi, &path, None);
            }
            SbiResponse::with_status(204)
        }
        _ => send_method_not_allowed(method, &format!("context-data/{resource}")),
    }
}

/// CRUD for a per-UE context-data COLLECTION (`sdm-subscriptions`,
/// `ee-subscriptions`), whose members are addressed by a subscription id.
///
/// Documents are keyed `{supi}\u{1f}{subsId}` inside the collection so one UE's
/// members list without scanning another's.
fn handle_ue_context_collection(
    supi: &str,
    resource: &str,
    subs_id: &str,
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let ds = data_store::store();
    let prefix = format!("{supi}\u{1f}");
    let key = format!("{prefix}{subs_id}");
    match (subs_id.is_empty(), method) {
        // Collection GET: this UE's members, ordered by id.
        (true, "GET") => {
            let list: Vec<serde_json::Value> = ds
                .doc_list(resource)
                .into_iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(_, v)| v)
                .collect();
            SbiResponse::with_status(200).with_body(
                serde_json::Value::Array(list).to_string(),
                "application/json",
            )
        }
        // Collection DELETE removes every member for this UE (UE purge).
        (true, "DELETE") => {
            ds.doc_remove_prefix(resource, &prefix);
            SbiResponse::with_status(204)
        }
        (false, "GET") => match ds.doc_get(resource, &key) {
            Some(doc) => {
                SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
            }
            None => send_not_found("Subscription not found", Some("DATA_NOT_FOUND")),
        },
        (false, "PUT") => {
            let doc = match parse_json_body(request) {
                Ok(v) if v.is_object() => v,
                Ok(_) => {
                    return send_bad_request(
                        "Body must be a JSON object",
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
                Err(resp) => return *resp,
            };
            let path =
                format!("/nudr-dr/v2/subscription-data/{supi}/context-data/{resource}/{subs_id}");
            let created = ds.doc_put(resource, &key, doc.clone());
            if created {
                SbiResponse::with_status(201)
                    .with_header("Location", path)
                    .with_body(doc.to_string(), "application/json")
            } else {
                SbiResponse::with_status(204)
            }
        }
        (false, "PATCH") => {
            let Some(mut doc) = ds.doc_get(resource, &key) else {
                return send_not_found("Subscription not found", Some("DATA_NOT_FOUND"));
            };
            let patch = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            if let Some(resp) = apply_patch_document(&mut doc, &patch) {
                return resp;
            }
            ds.doc_put(resource, &key, doc.clone());
            SbiResponse::with_status(204)
        }
        (false, "DELETE") => {
            if ds.doc_remove(resource, &key).is_some() {
                SbiResponse::with_status(204)
            } else {
                send_not_found("Subscription not found", Some("DATA_NOT_FOUND"))
            }
        }
        _ => send_method_not_allowed(method, &format!("context-data/{resource}")),
    }
}

/// Apply a TS 29.571 patch document to `doc` in place, returning `Some(response)`
/// when the patch itself is malformed.
///
/// Accepts both forms the Nudr resources define: a `PatchItem[]`
/// (`application/json-patch+json`) and a merge-patch object. `remove`/`replace`
/// on an absent member is an error rather than a silent no-op — a consumer
/// patching a path that is not there has a wrong idea of the stored document,
/// and a 204 would confirm it.
fn apply_patch_document(
    doc: &mut serde_json::Value,
    patch: &serde_json::Value,
) -> Option<SbiResponse> {
    if let Some(items) = patch.as_array() {
        for item in items {
            let op = item.get("op").and_then(|v| v.as_str()).unwrap_or("");
            let path = item.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let key = path.trim_start_matches('/');
            if key.is_empty() || key.contains('/') {
                return Some(send_bad_request(
                    &format!("Only top-level attributes are patchable: {path}"),
                    Some("INVALID_MSG_FORMAT"),
                ));
            }
            let Some(obj) = doc.as_object_mut() else {
                return Some(send_bad_request(
                    "Stored document is not an object",
                    Some("INVALID_MSG_FORMAT"),
                ));
            };
            match op {
                "add" => {
                    let Some(value) = item.get("value") else {
                        return Some(missing_mandatory("value"));
                    };
                    obj.insert(key.to_string(), value.clone());
                }
                "replace" => {
                    let Some(value) = item.get("value") else {
                        return Some(missing_mandatory("value"));
                    };
                    if !obj.contains_key(key) {
                        return Some(send_bad_request(
                            &format!("Cannot replace absent attribute: {key}"),
                            Some("INVALID_MSG_FORMAT"),
                        ));
                    }
                    obj.insert(key.to_string(), value.clone());
                }
                "remove" => {
                    if obj.remove(key).is_none() {
                        return Some(send_bad_request(
                            &format!("Cannot remove absent attribute: {key}"),
                            Some("INVALID_MSG_FORMAT"),
                        ));
                    }
                }
                other => {
                    return Some(send_bad_request(
                        &format!("Unsupported patch op: {other}"),
                        Some("INVALID_MSG_FORMAT"),
                    ))
                }
            }
        }
        None
    } else if patch.is_object() {
        merge_patch(doc, patch);
        None
    } else {
        Some(send_bad_request(
            "Invalid patch document",
            Some("INVALID_MSG_FORMAT"),
        ))
    }
}

/// Path of the amf-3gpp-access resource for a SUPI (notification resourceId).
fn amf_3gpp_access_path(supi: &str) -> String {
    context_data_path(supi, "amf-3gpp-access")
}

/// Handle an AMF access registration context for `slot` (TS 29.505 §5.2.4).
///
/// Stores and returns the full `Amf3GppAccessRegistration` /
/// `AmfNon3GppAccessRegistration` document: the shape PUT here by udmd
/// (forwarding the amfd Nudm registration) is preserved verbatim and echoed on
/// GET. The two accesses are separate documents, so a non-3GPP registration
/// cannot be read back as, or overwrite, the 3GPP one.
async fn handle_amf_access(
    supi: &str,
    slot: AmfAccessSlot,
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let udr_ctx = nextgcore_udrd::context::udr_self();
    let resource = slot.resource();
    match method {
        "GET" => match slot.get(supi) {
            Some(doc) => {
                log::debug!("[{supi}] GET {resource} - registration found");
                SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
            }
            None => send_not_found(
                "AMF registration context not found",
                Some("CONTEXT_NOT_FOUND"),
            ),
        },
        "PUT" => {
            let reg_data = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            // Mandatory attributes per TS 29.503 Amf3GppAccessRegistration.
            // The non-3GPP schema additionally requires imsVoPs.
            for attr in ["amfInstanceId", "deregCallbackUri", "guami", "ratType"] {
                if reg_data.get(attr).is_none() {
                    return missing_mandatory(attr);
                }
            }
            if slot == AmfAccessSlot::Non3Gpp && reg_data.get("imsVoPs").is_none() {
                return missing_mandatory("imsVoPs");
            }
            // Persist the PEI (IMEISV) claim off-thread (last live
            // blocking Mongo call moved to the spawn_blocking wrapper).
            if let Some(pei) = reg_data.get("pei").and_then(|v| v.as_str()) {
                let imeisv = data_store::imeisv_from_pei(pei).to_string();
                if let Err(e) = nextgcore_dbi::subscription::nextgcore_dbi_update_imeisv_async(
                    supi.to_string(),
                    imeisv,
                )
                .await
                {
                    log::debug!("[{supi}] DB update_imeisv unavailable: {e:?}");
                }
            }
            if let Ok(mut ctx) = udr_ctx.write() {
                ctx.ue_find_or_add(supi);
            }
            let created = slot.put(supi, reg_data.clone());
            let path = slot.path(supi);
            notify_subscription_data_change(supi, &path, Some(&reg_data));
            if created {
                SbiResponse::with_status(201)
                    .with_header("Location", path)
                    .with_body(reg_data.to_string(), "application/json")
            } else {
                SbiResponse::with_status(204)
            }
        }
        "PATCH" => {
            let Some(mut doc) = slot.get(supi) else {
                return send_not_found(
                    "AMF registration context not found",
                    Some("CONTEXT_NOT_FOUND"),
                );
            };
            let patch_body = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            if let Some(items) = patch_body.as_array() {
                // PatchItemList (application/json-patch+json)
                for patch in items {
                    let op = patch.get("op").and_then(|v| v.as_str()).unwrap_or("");
                    let path = patch.get("path").and_then(|v| v.as_str()).unwrap_or("");
                    let key = path.trim_start_matches('/');
                    if key.is_empty() || key.contains('/') {
                        continue; // only top-level attributes are patchable here
                    }
                    match op {
                        "replace" | "add" => {
                            if let (Some(obj), Some(value)) =
                                (doc.as_object_mut(), patch.get("value"))
                            {
                                obj.insert(key.to_string(), value.clone());
                            }
                        }
                        "remove" => {
                            if let Some(obj) = doc.as_object_mut() {
                                obj.remove(key);
                            }
                        }
                        _ => {
                            return send_bad_request(
                                &format!("Unsupported patch op: {op}"),
                                Some("INVALID_MSG_FORMAT"),
                            )
                        }
                    }
                }
            } else if patch_body.is_object() {
                // Amf3GppAccessRegistrationModification-style merge
                merge_patch(&mut doc, &patch_body);
            } else {
                return send_bad_request("Invalid patch document", Some("INVALID_MSG_FORMAT"));
            }
            slot.put(supi, doc.clone());
            notify_subscription_data_change(supi, &slot.path(supi), Some(&doc));
            SbiResponse::with_status(204)
        }
        "DELETE" => {
            let existed = slot.remove(supi).is_some();
            // The UE tracking entry is shared by both accesses, so it is only
            // dropped once NEITHER access holds a registration -- removing it on
            // a single-access deregistration would forget a UE that is still
            // registered over the other access.
            if AmfAccessSlot::ThreeGpp.get(supi).is_none()
                && AmfAccessSlot::Non3Gpp.get(supi).is_none()
            {
                if let Ok(mut ctx) = udr_ctx.write() {
                    ctx.ue_remove(supi);
                }
            }
            if existed {
                notify_subscription_data_change(supi, &slot.path(supi), None);
            }
            SbiResponse::with_status(204)
        }
        _ => send_method_not_allowed(method, &format!("context-data/{resource}")),
    }
}

/// TS 29.505 SmfRegistration mandatory IEs (Table 6.1.6.2.3-1: smfInstanceId,
/// pduSessionId, singleNssai, dnn, plmnId).
const SMF_REGISTRATION_MANDATORY_IES: [&str; 5] = [
    "smfInstanceId",
    "pduSessionId",
    "singleNssai",
    "dnn",
    "plmnId",
];

/// Handle SMF registration context.
///
/// Stores and returns the ACTUAL registered SmfRegistration document (the full
/// PUT body: smfInstanceId, singleNssai, dnn, pduSessionId, plmnId, ...), not a
/// hardcoded summary. Backed by the persistent [`data_store`] so registrations
/// survive a UDR restart.
fn handle_smf_registrations(
    supi: &str,
    method: &str,
    request: &SbiRequest,
    pdu_session_id: &str,
) -> SbiResponse {
    let udr_ctx = nextgcore_udrd::context::udr_self();
    let ds = nextgcore_udrd::data_store::store();
    match method {
        "GET" => {
            if pdu_session_id.is_empty() {
                // Collection GET: every stored registration for the SUPI.
                // Unknown UE -> empty array (TS 29.505), never a panic.
                let registrations = ds.smf_registrations_for_supi(supi);
                SbiResponse::with_status(200).with_body(
                    serde_json::Value::Array(registrations).to_string(),
                    "application/json",
                )
            } else {
                match ds.smf_registration_get(supi, pdu_session_id) {
                    Some(json) => SbiResponse::with_status(200)
                        .with_body(json.to_string(), "application/json"),
                    None => send_not_found("SMF registration not found", Some("CONTEXT_NOT_FOUND")),
                }
            }
        }
        "PUT" => {
            if pdu_session_id.is_empty() {
                return send_bad_request("Missing pduSessionId", Some("MANDATORY_IE_MISSING"));
            }
            // Parse the SmfRegistration document from the request body.
            let Some(content) = request.http.content.as_ref() else {
                return send_bad_request(
                    "Missing SmfRegistration body",
                    Some("MANDATORY_IE_MISSING"),
                );
            };
            let mut doc: serde_json::Value = match serde_json::from_str(content) {
                Ok(v @ serde_json::Value::Object(_)) => v,
                _ => {
                    return send_bad_request(
                        "Invalid SmfRegistration document",
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
            };
            // Validate mandatory IEs (TS 29.505 SmfRegistration).
            let missing: Vec<&str> = SMF_REGISTRATION_MANDATORY_IES
                .iter()
                .filter(|ie| match doc.get(**ie) {
                    None | Some(serde_json::Value::Null) => true,
                    Some(serde_json::Value::String(s)) => s.is_empty(),
                    Some(_) => false,
                })
                .copied()
                .collect();
            if !missing.is_empty() {
                return send_bad_request(
                    &format!("Missing mandatory IE(s): {}", missing.join(", ")),
                    Some("MANDATORY_IE_MISSING"),
                );
            }
            // The pduSessionId in the body must match the URI path segment
            // (TS 29.505 §6.1.3.1.3.1) so the stored key is consistent.
            let body_psi = doc.get("pduSessionId").and_then(|v| v.as_u64());
            if let Some(bp) = body_psi {
                if bp.to_string() != pdu_session_id {
                    return send_bad_request(
                        "pduSessionId in body does not match URI",
                        Some("INVALID_MSG_FORMAT"),
                    );
                }
            }
            // Normalise pduSessionId to the URI value as a numeric IE.
            if let Ok(num) = pdu_session_id.parse::<u64>() {
                if let Some(obj) = doc.as_object_mut() {
                    obj.insert("pduSessionId".to_string(), serde_json::json!(num));
                }
            }
            // Keep the context UE/session tracking in sync (for
            // subscription-data change notifications and request correlation).
            let psi: u8 = pdu_session_id.parse().unwrap_or(0);
            let dnn = doc
                .get("dnn")
                .and_then(|d| d.as_str())
                .map(|s| s.to_string());
            if let Ok(mut ctx) = udr_ctx.write() {
                ctx.sess_find_or_add(supi, psi, dnn.as_deref());
            }
            // Store the actual registered document (created vs. replaced).
            let created = ds.smf_registration_put(supi, pdu_session_id, doc.clone());
            let path = format!(
                "/nudr-dr/v2/subscription-data/{supi}/context-data/smf-registrations/{pdu_session_id}"
            );
            notify_subscription_data_change(supi, &path, Some(&doc));
            // TS 29.505 §5.2.4: 201 Created carries the created SmfRegistration
            // representation AND a required Location header (#87) -- a bare 201
            // leaves the consumer without the URI of the resource it just made,
            // and without confirmation of what was stored.
            if created {
                SbiResponse::with_status(201)
                    .with_header("Location", path)
                    .with_body(doc.to_string(), "application/json")
            } else {
                SbiResponse::with_status(204)
            }
        }
        "PATCH" => {
            if pdu_session_id.is_empty() {
                return send_bad_request("Missing pduSessionId", Some("MANDATORY_IE_MISSING"));
            }
            // TS 29.505 §5.2.4 defines PATCH on the individual registration;
            // it answered 405 before #87.
            let Some(mut doc) = ds.smf_registration_get(supi, pdu_session_id) else {
                return send_not_found("SMF registration not found", Some("CONTEXT_NOT_FOUND"));
            };
            let patch = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            if let Some(resp) = apply_patch_document(&mut doc, &patch) {
                return resp;
            }
            // The pduSessionId identifies the resource, so a patch must not be
            // able to move the document to another key.
            if doc
                .get("pduSessionId")
                .and_then(|v| v.as_u64())
                .map(|p| p.to_string())
                != Some(pdu_session_id.to_string())
            {
                return send_bad_request(
                    "pduSessionId is not patchable",
                    Some("INVALID_MSG_FORMAT"),
                );
            }
            ds.smf_registration_put(supi, pdu_session_id, doc.clone());
            let path = format!(
                "/nudr-dr/v2/subscription-data/{supi}/context-data/smf-registrations/{pdu_session_id}"
            );
            notify_subscription_data_change(supi, &path, Some(&doc));
            SbiResponse::with_status(204)
        }
        "DELETE" => {
            if !pdu_session_id.is_empty() {
                let psi: u8 = pdu_session_id.parse().unwrap_or(0);
                if let Ok(mut ctx) = udr_ctx.write() {
                    ctx.sess_remove(supi, psi);
                }
                ds.smf_registration_remove(supi, pdu_session_id);
            } else {
                // Collection DELETE removes all registrations for the SUPI.
                ds.smf_registrations_remove_by_supi(supi);
            }
            SbiResponse::with_status(204)
        }
        _ => send_method_not_allowed(method, "context-data/smf-registrations"),
    }
}

/// TS 29.503 `AuthEvent` required attributes (nfInstanceId, success, timeStamp,
/// authType, servingNetworkName).
const AUTH_EVENT_REQUIRED_IES: [&str; 5] = [
    "nfInstanceId",
    "success",
    "timeStamp",
    "authType",
    "servingNetworkName",
];

/// `authentication-data/authentication-status` (TS 29.505), both the collection
/// form and the individual `.../{servingNetworkName}` form. Stores the UDM's
/// `AuthEvent` on authentication confirmation (TS 33.501 §6.1.4).
///
/// `path_snn` is the `{servingNetworkName}` path segment when the individual
/// form was addressed, else `None`.
fn handle_auth_status(
    supi: &str,
    path_snn: Option<&str>,
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let ds = nextgcore_udrd::data_store::store();
    log::info!(
        "[{supi}] {method} authentication-status{}",
        path_snn.map(|s| format!("/{s}")).unwrap_or_default()
    );

    match method {
        "PUT" => {
            let Some(content) = request.http.content.as_ref() else {
                return send_bad_request("Missing AuthEvent body", Some("MANDATORY_IE_MISSING"));
            };
            let doc: serde_json::Value = match serde_json::from_str(content) {
                Ok(v @ serde_json::Value::Object(_)) => v,
                _ => {
                    return send_bad_request(
                        "Invalid AuthEvent document",
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
            };
            let missing: Vec<&str> = AUTH_EVENT_REQUIRED_IES
                .iter()
                .filter(|ie| match doc.get(**ie) {
                    None | Some(serde_json::Value::Null) => true,
                    Some(serde_json::Value::String(s)) => s.is_empty(),
                    Some(_) => false,
                })
                .copied()
                .collect();
            if !missing.is_empty() {
                return send_bad_request(
                    &format!("Missing mandatory IE(s): {}", missing.join(", ")),
                    Some("MANDATORY_IE_MISSING"),
                );
            }

            // Owned: `doc` is moved into the store below, so the key cannot
            // borrow from it.
            let body_snn = doc
                .get("servingNetworkName")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            // On the individual form the path segment is authoritative and the
            // body must agree, so the stored key cannot disagree with the URI
            // the consumer will GET back.
            if let Some(p) = path_snn {
                if p != body_snn {
                    return send_bad_request(
                        "servingNetworkName in body does not match URI",
                        Some("INVALID_MSG_FORMAT"),
                    );
                }
            }
            // The collection form has no path segment, so the required body
            // field supplies the key.
            let key = path_snn.unwrap_or(&body_snn).to_string();

            // 204 on create AND on replace. TS 29.505 defines ONLY 204 for
            // success on both authentication-status forms -- unlike
            // smf-registrations, which does define 201 Created. Returning 201
            // here would be a fabricated status code the consumer's OpenAPI
            // validator can reject.
            ds.auth_status_put(supi, &key, doc);
            SbiResponse::with_status(204)
        }
        "GET" => {
            // Individual form: that serving network's event. Collection form:
            // the most recent one, since neither a path segment nor a body
            // identifies a specific network there.
            let found = match path_snn {
                Some(snn) => ds.auth_status_get(supi, snn),
                None => ds.auth_status_latest_for_supi(supi),
            };
            match found {
                Some(doc) => {
                    SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
                }
                None => send_not_found(
                    "No authentication status stored for this UE",
                    Some("DATA_NOT_FOUND"),
                ),
            }
        }
        "DELETE" => {
            let removed = match path_snn {
                Some(snn) => ds.auth_status_remove(supi, snn).is_some(),
                None => ds.auth_status_remove_all_for_supi(supi) > 0,
            };
            if removed {
                SbiResponse::with_status(204)
            } else {
                send_not_found(
                    "No authentication status stored for this UE",
                    Some("DATA_NOT_FOUND"),
                )
            }
        }
        // PATCH is not defined on either form by TS 29.505.
        _ => send_method_not_allowed(method, "authentication-data/authentication-status"),
    }
}

/// Parse a `dataset-names` query parameter value into a set of requested
/// dataset names.  Handles both comma-separated (`AM,SM`) and percent-encoded
/// forms.  Returns `None` when the parameter is absent (→ return all datasets).
///
/// TS 29.504 §6.1 / TS 29.505 §5.4.2.8 `ProvisionedDataSetName` enum.
fn parse_dataset_names(raw: &str) -> Option<std::collections::HashSet<String>> {
    let decoded = pct_decode(raw);
    let names: std::collections::HashSet<String> = decoded
        .split(',')
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .collect();
    if names.is_empty() {
        None
    } else {
        Some(names)
    }
}

/// TS 29.504 §6.1.4.2 partial retrieval: project a JSON object value down to
/// the requested attribute paths (JSON Pointer syntax, e.g. `/a/b`).
///
/// Non-object top-level values (e.g. arrays) are returned unchanged.
/// A segment of `/` alone means the whole document — also returned unchanged.
/// Unknown paths are silently omitted from the result.
fn project_fields(value: &serde_json::Value, paths: &[String]) -> serde_json::Value {
    if paths.is_empty() {
        return value.clone();
    }
    if !value.is_object() {
        return value.clone(); // arrays / scalars cannot be path-projected
    }
    let mut out = serde_json::Map::new();
    for path in paths {
        let stripped = path.strip_prefix('/').unwrap_or(path.as_str());
        if stripped.is_empty() {
            // "/" or "" refers to the whole document
            return value.clone();
        }
        let segments: Vec<&str> = stripped.split('/').collect();
        if let Some(extracted) = project_extract(value, &segments) {
            project_insert(&mut out, &segments, extracted);
        }
    }
    serde_json::Value::Object(out)
}

fn project_extract(value: &serde_json::Value, segments: &[&str]) -> Option<serde_json::Value> {
    if segments.is_empty() {
        return Some(value.clone());
    }
    project_extract(value.as_object()?.get(segments[0])?, &segments[1..])
}

fn project_insert(
    out: &mut serde_json::Map<String, serde_json::Value>,
    segments: &[&str],
    value: serde_json::Value,
) {
    if segments.is_empty() {
        return;
    }
    if segments.len() == 1 {
        out.insert(segments[0].to_string(), value);
        return;
    }
    let entry = out
        .entry(segments[0].to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if let Some(obj) = entry.as_object_mut() {
        project_insert(obj, &segments[1..], value);
    }
}

/// Apply the `fields` query parameter (TS 29.504 §6.1.4.2 partial retrieval)
/// when present.  Returns `value` unchanged when `fields` is absent.
fn apply_fields_param(value: serde_json::Value, request: &SbiRequest) -> serde_json::Value {
    let Some(raw) = request.http.params.get("fields") else {
        return value;
    };
    let paths: Vec<String> = pct_decode(raw)
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if paths.is_empty() {
        return value;
    }
    project_fields(&value, &paths)
}

/// Handle provisioned-data requests
/// Path: /nudr-dr/v2/subscription-data/{supi}/provisioned-data/{dataset}
async fn handle_provisioned_data(
    supi: &str,
    parts: &[&str],
    dataset_idx: usize,
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    if method != "GET" {
        return send_method_not_allowed(method, "provisioned-data");
    }

    let dataset = parts.get(dataset_idx).copied().unwrap_or("");

    log::info!("[{supi}] GET provisioned-data/{dataset}");

    let subscription_data =
        match nextgcore_dbi::subscription::nextgcore_dbi_subscription_data_async(supi.to_string())
            .await
        {
            Ok(data) => data,
            Err(e) => {
                log::error!("[{supi}] DB subscription_data query failed: {e:?}");
                return send_not_found("Subscriber not found", Some("NOT_FOUND"));
            }
        };

    let response = match dataset {
        "am-data" => build_am_data(&subscription_data),
        "smf-selection-subscription-data" => build_smf_selection_data(&subscription_data),
        "sm-data" => build_sm_data(&subscription_data),
        "" => {
            // Combined provisioned-data GET (TS 29.504 §6.1 / TS 29.505 §5.4.2.8).
            // When `dataset-names` is present, return only the requested members;
            // absent param returns the full default set (udrd-03).
            let requested = request
                .http
                .params
                .get("dataset-names")
                .and_then(|raw| parse_dataset_names(raw));

            let include =
                |name: &str| -> bool { requested.as_ref().is_none_or(|set| set.contains(name)) };

            let mut combined = serde_json::Map::new();
            if include("AM") {
                combined.insert("amData".to_string(), build_am_data(&subscription_data));
            }
            if include("SMF_SEL") {
                combined.insert(
                    "smfSelData".to_string(),
                    build_smf_selection_data(&subscription_data),
                );
            }
            if include("SM") {
                combined.insert("smData".to_string(), build_sm_data(&subscription_data));
            }
            serde_json::Value::Object(combined)
        }
        _ => {
            log::warn!("[{supi}] Unknown dataset: {dataset}");
            return send_not_found(&format!("Unknown dataset: {dataset}"), None);
        }
    };

    // TS 29.504 §6.1.4.2 partial retrieval via `fields` param (udrd-07).
    let response = apply_fields_param(response, request);

    SbiResponse::with_status(200).with_body(response.to_string(), "application/json")
}

/// Handle policy-data requests
/// Implements:
/// - GET policy-data/ues/{supi}/am-data: AM policy data
/// - GET/PUT policy-data/ues/{supi}/sm-data: SM policy data
/// - GET policy-data/ues/{supi}/ue-policy-set: UE policy set
async fn handle_policy_data(parts: &[&str], method: &str, request: &SbiRequest) -> SbiResponse {
    // TS 29.519 §5.2 resource tree:
    //   /policy-data/ues/{ueId}/{am-data,sm-data[/{usageMonId}],ue-policy-set}
    //   /policy-data/subs-to-notify[/{subsId}]
    //   /policy-data/plmns/{plmnId}/ue-policy-set
    //   /policy-data/sponsor-connectivity-data/{sponsorId}
    //   /policy-data/bdt-data[/{bdtReferenceId}]
    match parts.get(3).copied().unwrap_or("") {
        "ues" => handle_policy_ue_data(parts, method, request).await,
        "subs-to-notify" => handle_policy_subs_to_notify(parts, method, request),
        "plmns" => handle_policy_plmn_data(parts, method, request),
        "sponsor-connectivity-data" => handle_policy_sponsor_data(parts, method, request),
        "bdt-data" => handle_policy_bdt_data(parts, method, request),
        other => send_not_found(&format!("Unknown policy sub-resource: {other}"), None),
    }
}

/// The resource URI of a per-UE policy document (notification resourceId).
fn policy_ue_path(supi: &str, resource: &str) -> String {
    format!("/nudr-dr/v2/policy-data/ues/{supi}/{resource}")
}

/// Store a provisioned policy document and emit both change notifications.
///
/// Both, because the two subscription trees have different audiences: a
/// `/subscription-data/subs-to-notify` subscriber (typically the UDM) gets the
/// `DataChangeNotify`, a `/policy-data/subs-to-notify` subscriber (the PCF) gets
/// the `PolicyDataChangeNotification`. Emitting only the first is why a PCF
/// could subscribe and never hear anything.
fn notify_policy_change(supi: &str, path: &str, doc: Option<&serde_json::Value>) {
    notify_subscription_data_change(supi, path, doc);
    nextgcore_udrd::data_store::notify_policy_data_change(supi, path, doc);
}

/// Read a provisioned policy document by resource name.
fn policy_doc_get(supi: &str, resource: &str) -> Option<serde_json::Value> {
    let ds = nextgcore_udrd::data_store::store();
    match resource {
        "am-data" => ds.policy_am_get(supi),
        "sm-data" => ds.policy_sm_get(supi),
        "ue-policy-set" => ds.policy_ue_get(supi),
        _ => None,
    }
}

/// Write a provisioned policy document by resource name; true when created.
fn policy_doc_put(supi: &str, resource: &str, doc: serde_json::Value) -> bool {
    let ds = nextgcore_udrd::data_store::store();
    match resource {
        "am-data" => ds.policy_am_put(supi, doc),
        "sm-data" => ds.policy_sm_put(supi, doc),
        "ue-policy-set" => ds.policy_ue_put(supi, doc),
        _ => false,
    }
}

/// PUT a provisioned per-UE policy document (`am-data`, `sm-data`,
/// `ue-policy-set`).
fn policy_put(supi: &str, resource: &str, request: &SbiRequest) -> SbiResponse {
    let body = match parse_json_body(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    if !body.is_object() {
        return send_bad_request("Body must be a JSON object", Some("INVALID_MSG_FORMAT"));
    }
    let created = policy_doc_put(supi, resource, body.clone());
    let path = policy_ue_path(supi, resource);
    notify_policy_change(supi, &path, Some(&body));
    if created {
        SbiResponse::with_status(201)
            .with_header("Location", path)
            .with_body(body.to_string(), "application/json")
    } else {
        SbiResponse::with_status(204)
    }
}

/// PATCH a provisioned per-UE policy document (TS 29.519 §5.2: `am-data` :143,
/// `sm-data` :333, `ue-policy-set` :484 — all `405` before #87).
///
/// An absent document starts empty rather than 404ing: PATCH is how a PCF
/// provisions a delta, and refusing the first one would mean a document could
/// only ever be created by a full PUT the consumer may not have.
fn policy_patch(supi: &str, resource: &str, request: &SbiRequest) -> SbiResponse {
    let patch = match parse_json_body(request) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let mut doc = policy_doc_get(supi, resource).unwrap_or_else(|| serde_json::json!({}));
    if let Some(resp) = apply_patch_document(&mut doc, &patch) {
        return resp;
    }
    policy_doc_put(supi, resource, doc.clone());
    let path = policy_ue_path(supi, resource);
    notify_policy_change(supi, &path, Some(&doc));
    SbiResponse::with_status(204)
}

/// Does `entry`'s `snssai` object match the requested one?
///
/// Compared field-wise on `sst`/`sd` rather than by map key, because the key
/// spelling is a UDR-side convention (`"01-000001"`) while the consumer sends a
/// JSON `Snssai` — matching on the key would make the filter depend on how this
/// UDR happens to format it.
fn snssai_entry_matches(entry: &serde_json::Value, want: &serde_json::Value) -> bool {
    let have = entry.get("snssai").unwrap_or(entry);
    let sst_eq =
        have.get("sst").and_then(|v| v.as_u64()) == want.get("sst").and_then(|v| v.as_u64());
    let norm_sd = |v: Option<&serde_json::Value>| {
        v.and_then(|v| v.as_str())
            .map(|s| s.trim_start_matches('0').to_ascii_lowercase())
    };
    sst_eq && norm_sd(have.get("sd")) == norm_sd(want.get("sd"))
}

/// Narrow an `SmPolicyData` to the requested `snssai` / `dnn` (TS 29.519 §5.2).
///
/// Returns `None` when the filter selects nothing — the subscriber has no policy
/// for that slice or DNN, which is a `404` rather than an empty document a PCF
/// would install as "no policy applies".
fn filter_sm_policy_data(
    doc: &serde_json::Value,
    snssai: Option<&serde_json::Value>,
    dnn: Option<&str>,
) -> Option<serde_json::Value> {
    let Some(want) = snssai else {
        // No filter: the whole document, as before #87.
        return Some(doc.clone());
    };
    let entries = doc.get("smPolicySnssaiData").and_then(|v| v.as_object())?;
    let mut kept = serde_json::Map::new();
    for (key, entry) in entries {
        if !snssai_entry_matches(entry, want) {
            continue;
        }
        let mut entry = entry.clone();
        if let Some(dnn) = dnn {
            let dnn_entries = entry
                .get("smPolicyDnnData")
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default();
            let Some(hit) = dnn_entries.get(dnn) else {
                // The slice matches but the DNN does not: selecting nothing.
                continue;
            };
            let mut only = serde_json::Map::new();
            only.insert(dnn.to_string(), hit.clone());
            if let Some(obj) = entry.as_object_mut() {
                obj.insert(
                    "smPolicyDnnData".to_string(),
                    serde_json::Value::Object(only),
                );
            }
        }
        kept.insert(key.clone(), entry);
    }
    if kept.is_empty() {
        return None;
    }
    let mut out = doc.clone();
    if let Some(obj) = out.as_object_mut() {
        obj.insert(
            "smPolicySnssaiData".to_string(),
            serde_json::Value::Object(kept),
        );
    }
    Some(out)
}

/// `/policy-data/ues/{ueId}/...` (TS 29.519 §5.2).
async fn handle_policy_ue_data(parts: &[&str], method: &str, request: &SbiRequest) -> SbiResponse {
    let supi = match parts.get(4) {
        Some(s) => *s,
        None => return send_bad_request("Missing SUPI", Some("MISSING_SUPI")),
    };

    let resource = parts.get(5).copied().unwrap_or("");
    let tail = parts.get(6).copied().unwrap_or("");

    match resource {
        "am-data" => match method {
            "GET" => {
                log::debug!("[{supi}] GET policy am-data");
                // udrd-05: return stored AmPolicyData when provisioned (udrd-04);
                // fall back to `{}` per TS 29.519 (no default AM policy data).
                let body = policy_doc_get(supi, "am-data").unwrap_or_else(|| serde_json::json!({}));
                let body = apply_fields_param(body, request);
                SbiResponse::with_status(200).with_body(body.to_string(), "application/json")
            }
            "PUT" => policy_put(supi, "am-data", request),
            "PATCH" => policy_patch(supi, "am-data", request),
            _ => send_method_not_allowed(method, "policy-data/ues/am-data"),
        },
        "sm-data" if !tail.is_empty() => {
            // /sm-data/{usageMonId} — the UsageMonData document (TS 29.519 :550).
            handle_policy_usage_mon(supi, tail, method, request)
        }
        "sm-data" => match method {
            "GET" => {
                log::debug!("[{supi}] GET policy sm-data");
                // TS 29.519 §5.2: `snssai` (a JSON Snssai) and `dnn` narrow the
                // document. Both are optional in the in-tree OpenAPI, so an
                // absent filter still returns everything; a filter that selects
                // nothing is a 404, not an empty SmPolicyData (#87).
                let snssai = request
                    .http
                    .params
                    .get("snssai")
                    .map(|raw| pct_decode(raw))
                    .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok());
                let dnn = request.http.params.get("dnn").map(|d| pct_decode(d));
                let stored = match policy_doc_get(supi, "sm-data") {
                    Some(stored) => Some(stored),
                    None => {
                        // Fall back to the default derived from subscription data.
                        match nextgcore_dbi::subscription::nextgcore_dbi_subscription_data_async(
                            supi.to_string(),
                        )
                        .await
                        {
                            Ok(data) => Some(serde_json::json!({
                                "smPolicySnssaiData": build_sm_policy_data(&data)
                            })),
                            Err(_) => None,
                        }
                    }
                };
                let Some(stored) = stored else {
                    return send_not_found("Subscriber not found", None);
                };
                match filter_sm_policy_data(&stored, snssai.as_ref(), dnn.as_deref()) {
                    Some(doc) => {
                        let doc = apply_fields_param(doc, request);
                        SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
                    }
                    None => send_not_found(
                        "No SM policy data for the requested S-NSSAI/DNN",
                        Some("DATA_NOT_FOUND"),
                    ),
                }
            }
            "PUT" => policy_put(supi, "sm-data", request),
            "PATCH" => policy_patch(supi, "sm-data", request),
            _ => send_method_not_allowed(method, "policy-data/ues/sm-data"),
        },
        "ue-policy-set" => match method {
            "GET" => {
                log::debug!("[{supi}] GET ue-policy-set");
                // udrd-05: prefer stored UePolicySet when provisioned (udrd-04);
                // fall back to a minimal derived default built from subscription slices.
                if let Some(stored) = policy_doc_get(supi, "ue-policy-set") {
                    let stored = apply_fields_param(stored, request);
                    return SbiResponse::with_status(200)
                        .with_body(stored.to_string(), "application/json");
                }
                match nextgcore_dbi::subscription::nextgcore_dbi_subscription_data_async(
                    supi.to_string(),
                )
                .await
                {
                    Ok(data) => {
                        // Build a minimal UePolicySet with subscribed S-NSSAIs
                        let mut subscribed_ue_pol_sections = serde_json::Map::new();
                        for slice in &data.slice {
                            let snssai_key = if slice.s_nssai.has_sd() {
                                format!("{:02x}-{:06x}", slice.s_nssai.sst, slice.s_nssai.sd.v)
                            } else {
                                format!("{:02x}", slice.s_nssai.sst)
                            };
                            subscribed_ue_pol_sections.insert(
                                snssai_key,
                                serde_json::json!({
                                    "upsi": [],
                                    "allowedRouteSelDescs": {}
                                }),
                            );
                        }
                        let response = serde_json::json!({
                            "subscPolicySections": subscribed_ue_pol_sections
                        });
                        let response = apply_fields_param(response, request);
                        SbiResponse::with_status(200)
                            .with_body(response.to_string(), "application/json")
                    }
                    Err(_) => {
                        // Return empty UePolicySet as default (TS 29.519)
                        SbiResponse::with_status(200)
                            .with_body("{}".to_string(), "application/json")
                    }
                }
            }
            "PUT" => policy_put(supi, "ue-policy-set", request),
            "PATCH" => policy_patch(supi, "ue-policy-set", request),
            _ => send_method_not_allowed(method, "policy-data/ues/ue-policy-set"),
        },
        _ => send_not_found(&format!("Unknown policy resource: {resource}"), None),
    }
}

/// `/policy-data/ues/{ueId}/sm-data/{usageMonId}` — the UsageMonData document
/// (TS 29.519 §5.2). Keyed `{supi}\u{1f}{usageMonId}` so one UE's monitoring
/// documents are independent of another's.
fn handle_policy_usage_mon(
    supi: &str,
    usage_mon_id: &str,
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let ds = nextgcore_udrd::data_store::store();
    let key = format!("{supi}\u{1f}{usage_mon_id}");
    let path = format!("/nudr-dr/v2/policy-data/ues/{supi}/sm-data/{usage_mon_id}");
    match method {
        "GET" => match ds.doc_get("policy-usage-mon", &key) {
            Some(doc) => {
                SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
            }
            None => send_not_found("No usage monitoring data", Some("DATA_NOT_FOUND")),
        },
        "PUT" => {
            let body = match parse_json_body(request) {
                Ok(v) if v.is_object() => v,
                Ok(_) => {
                    return send_bad_request(
                        "Body must be a JSON object",
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
                Err(resp) => return *resp,
            };
            let created = ds.doc_put("policy-usage-mon", &key, body.clone());
            notify_policy_change(supi, &path, Some(&body));
            if created {
                SbiResponse::with_status(201)
                    .with_header("Location", path)
                    .with_body(body.to_string(), "application/json")
            } else {
                SbiResponse::with_status(204)
            }
        }
        "DELETE" => {
            if ds.doc_remove("policy-usage-mon", &key).is_some() {
                notify_policy_change(supi, &path, None);
            }
            SbiResponse::with_status(204)
        }
        _ => send_method_not_allowed(method, "policy-data/ues/sm-data/{usageMonId}"),
    }
}

/// `/policy-data/subs-to-notify[/{subsId}]` — TS 29.519 §5.2 (:1077, :1250).
///
/// The subscription tree a PCF uses to hear about policy-data changes. It was
/// entirely absent, so a conformant PCF's subscribe attempt 404'd.
fn handle_policy_subs_to_notify(parts: &[&str], method: &str, request: &SbiRequest) -> SbiResponse {
    let ds = nextgcore_udrd::data_store::store();
    let subs_id = parts.get(4).copied().unwrap_or("");
    match (subs_id.is_empty(), method) {
        (true, "POST") => {
            let body = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            // PolicyDataSubscription: notificationUri + monitoredResourceUris.
            let Some(uri) = body.get("notificationUri").and_then(|v| v.as_str()) else {
                return missing_mandatory("notificationUri");
            };
            if body
                .get("monitoredResourceUris")
                .and_then(|v| v.as_array())
                .is_none_or(|a| a.is_empty())
            {
                return missing_mandatory("monitoredResourceUris");
            }
            let sub = ds.sub_create(SubKind::PolicyData, uri, body.clone());
            SbiResponse::with_status(201)
                .with_header(
                    "Location",
                    format!("/nudr-dr/v2/policy-data/subs-to-notify/{}", sub.id),
                )
                .with_body(body.to_string(), "application/json")
        }
        (false, "GET") => match ds.sub_get(subs_id) {
            Some(sub) if sub.kind == SubKind::PolicyData => {
                SbiResponse::with_status(200).with_body(sub.body.to_string(), "application/json")
            }
            _ => send_not_found("Subscription not found", Some("DATA_NOT_FOUND")),
        },
        (false, "PUT") => {
            let body = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            let Some(uri) = body.get("notificationUri").and_then(|v| v.as_str()) else {
                return missing_mandatory("notificationUri");
            };
            if ds.sub_replace(subs_id, SubKind::PolicyData, uri, body.clone()) {
                SbiResponse::with_status(200).with_body(body.to_string(), "application/json")
            } else {
                send_not_found("Subscription not found", Some("DATA_NOT_FOUND"))
            }
        }
        (false, "DELETE") => {
            if ds.sub_remove(subs_id).is_some() {
                SbiResponse::with_status(204)
            } else {
                send_not_found("Subscription not found", Some("DATA_NOT_FOUND"))
            }
        }
        _ => send_method_not_allowed(method, "policy-data/subs-to-notify"),
    }
}

/// `/policy-data/plmns/{plmnId}/ue-policy-set` — TS 29.519 §5.2 (:1651): the
/// PLMN-wide UE policy set, as opposed to a per-UE one.
fn handle_policy_plmn_data(parts: &[&str], method: &str, request: &SbiRequest) -> SbiResponse {
    let plmn_id = parts.get(4).copied().unwrap_or("");
    if parts.get(5).copied() != Some("ue-policy-set") {
        return send_not_found("Unknown policy plmns resource", None);
    }
    if !is_valid_plmn_id(plmn_id) {
        return send_error(
            400,
            "Bad Request",
            &format!("Invalid plmnId: {plmn_id}"),
            Some("MANDATORY_IE_INCORRECT"),
        );
    }
    let ds = nextgcore_udrd::data_store::store();
    let path = format!("/nudr-dr/v2/policy-data/plmns/{plmn_id}/ue-policy-set");
    match method {
        "GET" => match ds.doc_get("policy-plmn-ue-policy-set", plmn_id) {
            Some(doc) => {
                SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
            }
            None => send_not_found("No PLMN UE policy set", Some("DATA_NOT_FOUND")),
        },
        "PUT" => {
            let body = match parse_json_body(request) {
                Ok(v) if v.is_object() => v,
                Ok(_) => {
                    return send_bad_request(
                        "Body must be a JSON object",
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
                Err(resp) => return *resp,
            };
            let created = ds.doc_put("policy-plmn-ue-policy-set", plmn_id, body.clone());
            if created {
                SbiResponse::with_status(201)
                    .with_header("Location", path)
                    .with_body(body.to_string(), "application/json")
            } else {
                SbiResponse::with_status(204)
            }
        }
        "PATCH" => {
            let patch = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            let mut doc = ds
                .doc_get("policy-plmn-ue-policy-set", plmn_id)
                .unwrap_or_else(|| serde_json::json!({}));
            if let Some(resp) = apply_patch_document(&mut doc, &patch) {
                return resp;
            }
            ds.doc_put("policy-plmn-ue-policy-set", plmn_id, doc);
            SbiResponse::with_status(204)
        }
        _ => send_method_not_allowed(method, "policy-data/plmns/ue-policy-set"),
    }
}

/// `/policy-data/sponsor-connectivity-data/{sponsorId}` — TS 29.519 §5.2 (:738).
fn handle_policy_sponsor_data(parts: &[&str], method: &str, request: &SbiRequest) -> SbiResponse {
    let sponsor_id = parts.get(4).copied().unwrap_or("");
    if sponsor_id.is_empty() {
        return send_not_found("Missing sponsorId", None);
    }
    let ds = nextgcore_udrd::data_store::store();
    let path = format!("/nudr-dr/v2/policy-data/sponsor-connectivity-data/{sponsor_id}");
    match method {
        "GET" => match ds.doc_get("policy-sponsor-data", sponsor_id) {
            Some(doc) => {
                SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
            }
            None => send_not_found("No sponsor connectivity data", Some("DATA_NOT_FOUND")),
        },
        "PUT" => {
            let body = match parse_json_body(request) {
                Ok(v) if v.is_object() => v,
                Ok(_) => {
                    return send_bad_request(
                        "Body must be a JSON object",
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
                Err(resp) => return *resp,
            };
            // SponsorConnectivityData requires aspIds (TS 29.519 §5.6.2.x).
            if body
                .get("aspIds")
                .and_then(|v| v.as_array())
                .is_none_or(|a| a.is_empty())
            {
                return missing_mandatory("aspIds");
            }
            let created = ds.doc_put("policy-sponsor-data", sponsor_id, body.clone());
            if created {
                SbiResponse::with_status(201)
                    .with_header("Location", path)
                    .with_body(body.to_string(), "application/json")
            } else {
                SbiResponse::with_status(204)
            }
        }
        _ => send_method_not_allowed(method, "policy-data/sponsor-connectivity-data"),
    }
}

/// `/policy-data/bdt-data[/{bdtReferenceId}]` — TS 29.519 §5.2 (:799, :864).
fn handle_policy_bdt_data(parts: &[&str], method: &str, request: &SbiRequest) -> SbiResponse {
    let ds = nextgcore_udrd::data_store::store();
    let bdt_ref = parts.get(4).copied().unwrap_or("");
    match (bdt_ref.is_empty(), method) {
        (true, "GET") => {
            let list: Vec<serde_json::Value> = ds
                .doc_list("policy-bdt-data")
                .into_iter()
                .map(|(_, v)| v)
                .collect();
            SbiResponse::with_status(200).with_body(
                serde_json::Value::Array(list).to_string(),
                "application/json",
            )
        }
        (false, "GET") => match ds.doc_get("policy-bdt-data", bdt_ref) {
            Some(doc) => {
                SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
            }
            None => send_not_found("No BDT data", Some("DATA_NOT_FOUND")),
        },
        (false, "PUT") => {
            let body = match parse_json_body(request) {
                Ok(v) if v.is_object() => v,
                Ok(_) => {
                    return send_bad_request(
                        "Body must be a JSON object",
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
                Err(resp) => return *resp,
            };
            // BdtData requires aspId, transPolicy and bdtRefId; the path segment
            // is authoritative for the last, so a body that disagrees is refused
            // rather than silently stored under the URI's id.
            for attr in ["aspId", "transPolicy"] {
                if body.get(attr).is_none() {
                    return missing_mandatory(attr);
                }
            }
            if let Some(body_ref) = body.get("bdtRefId").and_then(|v| v.as_str()) {
                if body_ref != bdt_ref {
                    return send_bad_request(
                        "bdtRefId in body does not match URI",
                        Some("INVALID_MSG_FORMAT"),
                    );
                }
            }
            let path = format!("/nudr-dr/v2/policy-data/bdt-data/{bdt_ref}");
            let created = ds.doc_put("policy-bdt-data", bdt_ref, body.clone());
            if created {
                SbiResponse::with_status(201)
                    .with_header("Location", path)
                    .with_body(body.to_string(), "application/json")
            } else {
                SbiResponse::with_status(204)
            }
        }
        (false, "PATCH") => {
            let Some(mut doc) = ds.doc_get("policy-bdt-data", bdt_ref) else {
                return send_not_found("No BDT data", Some("DATA_NOT_FOUND"));
            };
            let patch = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            if let Some(resp) = apply_patch_document(&mut doc, &patch) {
                return resp;
            }
            ds.doc_put("policy-bdt-data", bdt_ref, doc.clone());
            SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
        }
        (false, "DELETE") => {
            if ds.doc_remove("policy-bdt-data", bdt_ref).is_some() {
                SbiResponse::with_status(204)
            } else {
                send_not_found("No BDT data", Some("DATA_NOT_FOUND"))
            }
        }
        _ => send_method_not_allowed(method, "policy-data/bdt-data"),
    }
}

/// Build SM policy data from subscription data
fn build_sm_policy_data(
    data: &nextgcore_dbi::types::NextgcoreSubscriptionData,
) -> serde_json::Map<String, serde_json::Value> {
    let mut sm_policy_snssai_data = serde_json::Map::new();
    for slice in &data.slice {
        let snssai_key = if slice.s_nssai.has_sd() {
            format!("{:02x}-{:06x}", slice.s_nssai.sst, slice.s_nssai.sd.v)
        } else {
            format!("{:02x}", slice.s_nssai.sst)
        };
        let mut snssai_json = serde_json::Map::new();
        snssai_json.insert(
            "sst".to_string(),
            serde_json::Value::Number(slice.s_nssai.sst.into()),
        );
        if slice.s_nssai.has_sd() {
            snssai_json.insert(
                "sd".to_string(),
                serde_json::Value::String(format!("{:06x}", slice.s_nssai.sd.v)),
            );
        }
        let mut sm_policy_dnn_data = serde_json::Map::new();
        for sess in &slice.session {
            if let Some(dnn) = &sess.name {
                sm_policy_dnn_data.insert(dnn.clone(), serde_json::json!({"dnn": dnn}));
            }
        }
        let mut snssai_data = serde_json::Map::new();
        snssai_data.insert("snssai".to_string(), serde_json::Value::Object(snssai_json));
        if !sm_policy_dnn_data.is_empty() {
            snssai_data.insert(
                "smPolicyDnnData".to_string(),
                serde_json::Value::Object(sm_policy_dnn_data),
            );
        }
        sm_policy_snssai_data.insert(snssai_key, serde_json::Value::Object(snssai_data));
    }
    sm_policy_snssai_data
}

// ============================================================================
// subscription-data/subs-to-notify (TS 29.505)
// ============================================================================

/// Handle /nudr-dr/v2/subscription-data/subs-to-notify[/{subsId}]
async fn handle_subscription_data_subs(
    parts: &[&str],
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let ds = data_store::store();
    match parts.get(4).copied() {
        // Collection: /subscription-data/subs-to-notify
        None => match method {
            "POST" => {
                let body = match parse_json_body(request) {
                    Ok(v) => v,
                    Err(resp) => return *resp,
                };
                let Some(cb) = body.get("callbackReference").and_then(|v| v.as_str()) else {
                    return missing_mandatory("callbackReference");
                };
                if body
                    .get("monitoredResourceUris")
                    .and_then(|v| v.as_array())
                    .is_none()
                {
                    return missing_mandatory("monitoredResourceUris");
                }
                let cb = cb.to_string();
                let mut stored_body = body;
                let sub = ds.sub_create(SubKind::SubscriptionData, &cb, serde_json::Value::Null);
                if let Some(obj) = stored_body.as_object_mut() {
                    obj.insert(
                        "subscriptionId".to_string(),
                        serde_json::Value::String(sub.id.clone()),
                    );
                }
                ds.sub_set_body(&sub.id, stored_body.clone(), None);
                SbiResponse::with_status(201)
                    .with_header(
                        "Location",
                        format!("/nudr-dr/v2/subscription-data/subs-to-notify/{}", sub.id),
                    )
                    .with_body(stored_body.to_string(), "application/json")
            }
            "GET" => {
                let Some(ue_id) = request.http.params.get("ue-id").cloned() else {
                    return send_bad_request(
                        "Missing mandatory query parameter: ue-id",
                        Some("MANDATORY_QUERY_PARAM_MISSING"),
                    );
                };
                let subs = ds.subs_matching(SubKind::SubscriptionData, |s| {
                    s.body.get("ueId").and_then(|v| v.as_str()) == Some(ue_id.as_str())
                });
                let list: Vec<serde_json::Value> = subs.into_iter().map(|s| s.body).collect();
                SbiResponse::with_status(200).with_body(
                    serde_json::Value::Array(list).to_string(),
                    "application/json",
                )
            }
            "DELETE" => {
                let Some(ue_id) = request.http.params.get("ue-id").cloned() else {
                    return send_bad_request(
                        "Missing mandatory query parameter: ue-id",
                        Some("MANDATORY_QUERY_PARAM_MISSING"),
                    );
                };
                ds.subs_remove_by_ue(&ue_id);
                SbiResponse::with_status(204)
            }
            _ => send_method_not_allowed(method, "subscription-data/subs-to-notify"),
        },
        // Document: /subscription-data/subs-to-notify/{subsId}
        Some(subs_id) => match method {
            "GET" => match ds.sub_get(subs_id) {
                Some(sub) if sub.kind == SubKind::SubscriptionData => SbiResponse::with_status(200)
                    .with_body(sub.body.to_string(), "application/json"),
                _ => send_not_found("Subscription not found", Some("DATA_NOT_FOUND")),
            },
            "PATCH" => {
                let Some(sub) = ds.sub_get(subs_id) else {
                    return send_not_found("Subscription not found", Some("DATA_NOT_FOUND"));
                };
                if sub.kind != SubKind::SubscriptionData {
                    return send_not_found("Subscription not found", Some("DATA_NOT_FOUND"));
                }
                let patch_body = match parse_json_body(request) {
                    Ok(v) => v,
                    Err(resp) => return *resp,
                };
                let Some(items) = patch_body.as_array() else {
                    return send_bad_request(
                        "PATCH body must be a PatchItem array",
                        Some("INVALID_MSG_FORMAT"),
                    );
                };
                let mut body = sub.body;
                for patch in items {
                    let op = patch.get("op").and_then(|v| v.as_str()).unwrap_or("");
                    let path = patch.get("path").and_then(|v| v.as_str()).unwrap_or("");
                    let key = path.trim_start_matches('/');
                    if !matches!(op, "replace" | "add") || key.is_empty() || key.contains('/') {
                        return send_bad_request(
                            &format!("Unsupported patch: {op} {path}"),
                            Some("INVALID_MSG_FORMAT"),
                        );
                    }
                    if let (Some(obj), Some(value)) = (body.as_object_mut(), patch.get("value")) {
                        obj.insert(key.to_string(), value.clone());
                    }
                }
                let notify_uri = body
                    .get("callbackReference")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                ds.sub_set_body(subs_id, body, notify_uri);
                SbiResponse::with_status(204)
            }
            "DELETE" => {
                if ds.sub_remove(subs_id).is_some() {
                    SbiResponse::with_status(204)
                } else {
                    send_not_found("Subscription not found", Some("DATA_NOT_FOUND"))
                }
            }
            _ => send_method_not_allowed(method, "subscription-data/subs-to-notify/{subsId}"),
        },
    }
}

// ============================================================================
// exposure-data (TS 29.519 shapes via TS 29.504 paths)
// ============================================================================

/// Handle /nudr-dr/v2/exposure-data/...
async fn handle_exposure_data(parts: &[&str], method: &str, request: &SbiRequest) -> SbiResponse {
    let ds = data_store::store();

    // /exposure-data/subs-to-notify[/{subId}]
    if parts.get(3).copied() == Some("subs-to-notify") {
        return match (parts.get(4).copied(), method) {
            (None, "POST") => {
                let body = match parse_json_body(request) {
                    Ok(v) => v,
                    Err(resp) => return *resp,
                };
                let Some(uri) = body.get("notificationUri").and_then(|v| v.as_str()) else {
                    return missing_mandatory("notificationUri");
                };
                if body
                    .get("monitoredResourceUris")
                    .and_then(|v| v.as_array())
                    .is_none_or(|a| a.is_empty())
                {
                    return missing_mandatory("monitoredResourceUris");
                }
                let sub = ds.sub_create(SubKind::ExposureData, uri, body.clone());
                SbiResponse::with_status(201)
                    .with_header(
                        "Location",
                        format!("/nudr-dr/v2/exposure-data/subs-to-notify/{}", sub.id),
                    )
                    .with_body(body.to_string(), "application/json")
            }
            (Some(sub_id), "PUT") => {
                let body = match parse_json_body(request) {
                    Ok(v) => v,
                    Err(resp) => return *resp,
                };
                let Some(uri) = body.get("notificationUri").and_then(|v| v.as_str()) else {
                    return missing_mandatory("notificationUri");
                };
                if ds.sub_replace(sub_id, SubKind::ExposureData, uri, body.clone()) {
                    SbiResponse::with_status(200).with_body(body.to_string(), "application/json")
                } else {
                    send_not_found("Subscription not found", Some("DATA_NOT_FOUND"))
                }
            }
            (Some(sub_id), "DELETE") => {
                if ds.sub_remove(sub_id).is_some() {
                    SbiResponse::with_status(204)
                } else {
                    send_not_found("Subscription not found", Some("DATA_NOT_FOUND"))
                }
            }
            _ => send_method_not_allowed(method, "exposure-data/subs-to-notify"),
        };
    }

    // /exposure-data/{ueId}/...
    let Some(ue_id) = parts.get(3).copied() else {
        return send_bad_request("Missing ueId", Some("MANDATORY_IE_MISSING"));
    };
    match parts.get(4).copied() {
        Some("access-and-mobility-data") => {
            let path = format!("/nudr-dr/v2/exposure-data/{ue_id}/access-and-mobility-data");
            match method {
                "PUT" => {
                    let body = match parse_json_body(request) {
                        Ok(v) => v,
                        Err(resp) => return *resp,
                    };
                    let created = ds.exposure_am_put(ue_id, body.clone());
                    notify_exposure_data_change(
                        ue_id,
                        &path,
                        serde_json::json!({"accessAndMobilityData": body}),
                    );
                    if created {
                        SbiResponse::with_status(201)
                            .with_header("Location", path)
                            .with_body(body.to_string(), "application/json")
                    } else {
                        SbiResponse::with_status(200)
                            .with_body(body.to_string(), "application/json")
                    }
                }
                "GET" => match ds.exposure_am_get(ue_id) {
                    Some(doc) => {
                        SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
                    }
                    None => {
                        send_not_found("Access and mobility data not found", Some("DATA_NOT_FOUND"))
                    }
                },
                "PATCH" => {
                    let Some(mut doc) = ds.exposure_am_get(ue_id) else {
                        return send_not_found(
                            "Access and mobility data not found",
                            Some("DATA_NOT_FOUND"),
                        );
                    };
                    let patch = match parse_json_body(request) {
                        Ok(v) => v,
                        Err(resp) => return *resp,
                    };
                    merge_patch(&mut doc, &patch);
                    ds.exposure_am_put(ue_id, doc.clone());
                    notify_exposure_data_change(
                        ue_id,
                        &path,
                        serde_json::json!({"accessAndMobilityData": doc}),
                    );
                    SbiResponse::with_status(204)
                }
                "DELETE" => {
                    if ds.exposure_am_remove(ue_id).is_some() {
                        notify_exposure_data_change(
                            ue_id,
                            &path,
                            serde_json::json!({"delResources": [path]}),
                        );
                        SbiResponse::with_status(204)
                    } else {
                        send_not_found("Access and mobility data not found", Some("DATA_NOT_FOUND"))
                    }
                }
                _ => send_method_not_allowed(method, "exposure-data/access-and-mobility-data"),
            }
        }
        Some("session-management-data") => {
            let Some(psi) = parts.get(5).copied() else {
                return send_bad_request("Missing pduSessionId", Some("MANDATORY_IE_MISSING"));
            };
            let path = format!("/nudr-dr/v2/exposure-data/{ue_id}/session-management-data/{psi}");
            match method {
                "PUT" => {
                    let body = match parse_json_body(request) {
                        Ok(v) => v,
                        Err(resp) => return *resp,
                    };
                    let created = ds.exposure_sm_put(ue_id, psi, body.clone());
                    notify_exposure_data_change(
                        ue_id,
                        &path,
                        serde_json::json!({"pduSessionManagementData": [body]}),
                    );
                    if created {
                        SbiResponse::with_status(201)
                            .with_header("Location", path)
                            .with_body(body.to_string(), "application/json")
                    } else {
                        SbiResponse::with_status(200)
                            .with_body(body.to_string(), "application/json")
                    }
                }
                "GET" => match ds.exposure_sm_get(ue_id, psi) {
                    Some(doc) => {
                        SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
                    }
                    None => {
                        send_not_found("Session management data not found", Some("DATA_NOT_FOUND"))
                    }
                },
                "DELETE" => {
                    if ds.exposure_sm_remove(ue_id, psi).is_some() {
                        notify_exposure_data_change(
                            ue_id,
                            &path,
                            serde_json::json!({"delResources": [path]}),
                        );
                        SbiResponse::with_status(204)
                    } else {
                        send_not_found("Session management data not found", Some("DATA_NOT_FOUND"))
                    }
                }
                _ => send_method_not_allowed(method, "exposure-data/session-management-data"),
            }
        }
        _ => send_not_found("Unknown exposure-data resource", None),
    }
}

// ============================================================================
// application-data (TS 29.519 shapes via TS 29.504 paths)
// ============================================================================

/// Split a comma-separated query parameter into owned strings.
fn csv_param(request: &SbiRequest, name: &str) -> Option<Vec<String>> {
    request.http.params.get(name).map(|v| {
        pct_decode(v)
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    })
}

/// Handle /nudr-dr/v2/application-data/...
async fn handle_application_data(
    parts: &[&str],
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let ds = data_store::store();
    match parts.get(3).copied() {
        // --- /application-data/pfds[/{appId}] -----------------------------
        Some("pfds") => match (parts.get(4).copied(), method) {
            (None, "GET") => {
                let app_ids =
                    csv_param(request, "appId").or_else(|| csv_param(request, "application-ids"));
                let list = ds.pfd_list(app_ids.as_deref());
                SbiResponse::with_status(200).with_body(
                    serde_json::Value::Array(list).to_string(),
                    "application/json",
                )
            }
            (Some(app_id), "GET") => match ds.pfd_get(app_id) {
                Some(doc) => {
                    SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
                }
                None => send_not_found("PFD data not found", Some("DATA_NOT_FOUND")),
            },
            (Some(app_id), "PUT") => {
                let body = match parse_json_body(request) {
                    Ok(v) => v,
                    Err(resp) => return *resp,
                };
                // PfdDataForApp mandatory attributes (TS 29.551)
                if body.get("applicationId").and_then(|v| v.as_str()).is_none() {
                    return missing_mandatory("applicationId");
                }
                if body
                    .get("pfds")
                    .and_then(|v| v.as_array())
                    .is_none_or(|a| a.is_empty())
                {
                    return missing_mandatory("pfds");
                }
                let path = format!("/nudr-dr/v2/application-data/pfds/{app_id}");
                let created = ds.pfd_put(app_id, body.clone());
                notify_application_data_change(&path, app_id, false);
                if created {
                    SbiResponse::with_status(201)
                        .with_header("Location", path)
                        .with_body(body.to_string(), "application/json")
                } else {
                    SbiResponse::with_status(200).with_body(body.to_string(), "application/json")
                }
            }
            (Some(app_id), "DELETE") => {
                if ds.pfd_remove(app_id).is_some() {
                    let path = format!("/nudr-dr/v2/application-data/pfds/{app_id}");
                    notify_application_data_change(&path, app_id, true);
                    SbiResponse::with_status(204)
                } else {
                    send_not_found("PFD data not found", Some("DATA_NOT_FOUND"))
                }
            }
            _ => send_method_not_allowed(method, "application-data/pfds"),
        },
        // --- /application-data/influenceData... ---------------------------
        Some("influenceData") => match parts.get(4).copied() {
            // Collection read with TS 29.519 query filters
            None => match method {
                "GET" => {
                    let influence_ids = csv_param(request, "influence-Ids");
                    let dnns = csv_param(request, "dnns");
                    let supis = csv_param(request, "supis");
                    let list = ds.influence_list(
                        influence_ids.as_deref(),
                        dnns.as_deref(),
                        supis.as_deref(),
                    );
                    SbiResponse::with_status(200).with_body(
                        serde_json::Value::Array(list).to_string(),
                        "application/json",
                    )
                }
                _ => send_method_not_allowed(method, "application-data/influenceData"),
            },
            // /influenceData/subs-to-notify[/{subscriptionId}]
            Some("subs-to-notify") => match (parts.get(5).copied(), method) {
                (None, "POST") => {
                    let body = match parse_json_body(request) {
                        Ok(v) => v,
                        Err(resp) => return *resp,
                    };
                    let Some(uri) = body.get("notificationUri").and_then(|v| v.as_str()) else {
                        return missing_mandatory("notificationUri");
                    };
                    // oneOf: dnns / snssais / internalGroupIds / supis
                    if !["dnns", "snssais", "internalGroupIds", "supis"]
                        .iter()
                        .any(|k| body.get(*k).and_then(|v| v.as_array()).is_some())
                    {
                        return missing_mandatory("dnns|snssais|internalGroupIds|supis");
                    }
                    let sub = ds.sub_create(SubKind::AppInfluence, uri, body.clone());
                    SbiResponse::with_status(201)
                        .with_header(
                            "Location",
                            format!(
                                "/nudr-dr/v2/application-data/influenceData/subs-to-notify/{}",
                                sub.id
                            ),
                        )
                        .with_body(body.to_string(), "application/json")
                }
                (None, "GET") => {
                    let subs = ds.subs_matching(SubKind::AppInfluence, |_| true);
                    let list: Vec<serde_json::Value> = subs.into_iter().map(|s| s.body).collect();
                    SbiResponse::with_status(200).with_body(
                        serde_json::Value::Array(list).to_string(),
                        "application/json",
                    )
                }
                (Some(sub_id), "GET") => match ds.sub_get(sub_id) {
                    Some(sub) if sub.kind == SubKind::AppInfluence => SbiResponse::with_status(200)
                        .with_body(sub.body.to_string(), "application/json"),
                    _ => send_not_found("Subscription not found", Some("DATA_NOT_FOUND")),
                },
                (Some(sub_id), "PUT") => {
                    let body = match parse_json_body(request) {
                        Ok(v) => v,
                        Err(resp) => return *resp,
                    };
                    let Some(uri) = body.get("notificationUri").and_then(|v| v.as_str()) else {
                        return missing_mandatory("notificationUri");
                    };
                    if ds.sub_replace(sub_id, SubKind::AppInfluence, uri, body.clone()) {
                        SbiResponse::with_status(200)
                            .with_body(body.to_string(), "application/json")
                    } else {
                        send_not_found("Subscription not found", Some("DATA_NOT_FOUND"))
                    }
                }
                (Some(sub_id), "DELETE") => {
                    if ds.sub_remove(sub_id).is_some() {
                        SbiResponse::with_status(204)
                    } else {
                        send_not_found("Subscription not found", Some("DATA_NOT_FOUND"))
                    }
                }
                _ => send_method_not_allowed(method, "influenceData/subs-to-notify"),
            },
            // /influenceData/{influenceId}
            Some(influence_id) => {
                let path = format!("/nudr-dr/v2/application-data/influenceData/{influence_id}");
                match method {
                    "PUT" => {
                        let body = match parse_json_body(request) {
                            Ok(v) => v,
                            Err(resp) => return *resp,
                        };
                        if body.get("afAppId").and_then(|v| v.as_str()).is_none() {
                            return missing_mandatory("afAppId");
                        }
                        let created = ds.influence_put(influence_id, body.clone());
                        notify_influence_data_change(&path, Some(&body));
                        if created {
                            SbiResponse::with_status(201)
                                .with_header("Location", path)
                                .with_body(body.to_string(), "application/json")
                        } else {
                            SbiResponse::with_status(200)
                                .with_body(body.to_string(), "application/json")
                        }
                    }
                    "PATCH" => {
                        let Some(mut doc) = ds.influence_get(influence_id) else {
                            return send_not_found(
                                "Traffic influence data not found",
                                Some("DATA_NOT_FOUND"),
                            );
                        };
                        let patch = match parse_json_body(request) {
                            Ok(v) => v,
                            Err(resp) => return *resp,
                        };
                        merge_patch(&mut doc, &patch);
                        ds.influence_put(influence_id, doc.clone());
                        notify_influence_data_change(&path, Some(&doc));
                        SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
                    }
                    "DELETE" => {
                        if ds.influence_remove(influence_id).is_some() {
                            notify_influence_data_change(&path, None);
                            SbiResponse::with_status(204)
                        } else {
                            send_not_found(
                                "Traffic influence data not found",
                                Some("DATA_NOT_FOUND"),
                            )
                        }
                    }
                    "GET" => match ds.influence_get(influence_id) {
                        Some(doc) => SbiResponse::with_status(200)
                            .with_body(doc.to_string(), "application/json"),
                        None => send_not_found(
                            "Traffic influence data not found",
                            Some("DATA_NOT_FOUND"),
                        ),
                    },
                    _ => send_method_not_allowed(method, "application-data/influenceData"),
                }
            }
        },
        // --- /application-data/subs-to-notify[/{subsId}] -------------------
        Some("subs-to-notify") => match (parts.get(4).copied(), method) {
            (None, "POST") => {
                let body = match parse_json_body(request) {
                    Ok(v) => v,
                    Err(resp) => return *resp,
                };
                let Some(uri) = body.get("notificationUri").and_then(|v| v.as_str()) else {
                    return missing_mandatory("notificationUri");
                };
                let sub = ds.sub_create(SubKind::AppData, uri, body.clone());
                SbiResponse::with_status(201)
                    .with_header(
                        "Location",
                        format!("/nudr-dr/v2/application-data/subs-to-notify/{}", sub.id),
                    )
                    .with_body(body.to_string(), "application/json")
            }
            (Some(sub_id), "PUT") => {
                let body = match parse_json_body(request) {
                    Ok(v) => v,
                    Err(resp) => return *resp,
                };
                let Some(uri) = body.get("notificationUri").and_then(|v| v.as_str()) else {
                    return missing_mandatory("notificationUri");
                };
                if ds.sub_replace(sub_id, SubKind::AppData, uri, body.clone()) {
                    SbiResponse::with_status(200).with_body(body.to_string(), "application/json")
                } else {
                    send_not_found("Subscription not found", Some("DATA_NOT_FOUND"))
                }
            }
            (Some(sub_id), "DELETE") => {
                if ds.sub_remove(sub_id).is_some() {
                    SbiResponse::with_status(204)
                } else {
                    send_not_found("Subscription not found", Some("DATA_NOT_FOUND"))
                }
            }
            _ => send_method_not_allowed(method, "application-data/subs-to-notify"),
        },
        // --- the datasets that fell through to 404 before #87 --------------
        // TS 29.519 §5.6 names them exactly as spelled here; the issue's
        // informal "af-qos-data" / "eas-deployment-data" do not appear in the
        // OpenAPI, and routing an invented path would advertise a surface no
        // conformant consumer asks for.
        Some(
            collection @ ("bdtPolicyData" | "iptvConfigData" | "serviceParamData"
            | "am-influence-data" | "af-qos-data-sets" | "eas-deploy-data"),
        ) => handle_application_dataset(collection, parts.get(4).copied(), method, request),
        _ => send_not_found("Unknown application-data resource", None),
    }
}

/// Mandatory members of an application-data document, by dataset
/// (TS 29.519 §5.6.2). Datasets whose schema marks nothing required return an
/// empty slice rather than a made-up requirement.
fn application_dataset_required(collection: &str) -> &'static [&'static str] {
    match collection {
        // BdtPolicyData
        "bdtPolicyData" => &["bdtRefId"],
        // IptvConfigData
        "iptvConfigData" => &["afAppId", "multiAccCtrls"],
        _ => &[],
    }
}

/// CRUD for one application-data dataset (TS 29.519 §5.6).
///
/// All six share the same document shape — a collection of AF-provisioned
/// documents addressed by an id — so they share one handler; only the mandatory
/// members differ, and those come from [`application_dataset_required`]. The
/// collection GET returns every document, which is what an NEF or PCF reading
/// the dataset expects.
fn handle_application_dataset(
    collection: &str,
    doc_id: Option<&str>,
    method: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let ds = data_store::store();
    let store_key = format!("app-{collection}");
    match (doc_id, method) {
        (None, "GET") => {
            let list: Vec<serde_json::Value> = ds
                .doc_list(&store_key)
                .into_iter()
                .map(|(_, v)| v)
                .collect();
            SbiResponse::with_status(200).with_body(
                serde_json::Value::Array(list).to_string(),
                "application/json",
            )
        }
        (Some(id), "GET") => match ds.doc_get(&store_key, id) {
            Some(doc) => {
                SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
            }
            None => send_not_found(&format!("{collection} not found"), Some("DATA_NOT_FOUND")),
        },
        (Some(id), "PUT") => {
            let body = match parse_json_body(request) {
                Ok(v) if v.is_object() => v,
                Ok(_) => {
                    return send_bad_request(
                        "Body must be a JSON object",
                        Some("INVALID_MSG_FORMAT"),
                    )
                }
                Err(resp) => return *resp,
            };
            for attr in application_dataset_required(collection) {
                if body.get(*attr).is_none() {
                    return missing_mandatory(attr);
                }
            }
            let path = format!("/nudr-dr/v2/application-data/{collection}/{id}");
            let created = ds.doc_put(&store_key, id, body.clone());
            notify_application_data_change(&path, id, false);
            if created {
                SbiResponse::with_status(201)
                    .with_header("Location", path)
                    .with_body(body.to_string(), "application/json")
            } else {
                SbiResponse::with_status(200).with_body(body.to_string(), "application/json")
            }
        }
        (Some(id), "PATCH") => {
            let Some(mut doc) = ds.doc_get(&store_key, id) else {
                return send_not_found(&format!("{collection} not found"), Some("DATA_NOT_FOUND"));
            };
            let patch = match parse_json_body(request) {
                Ok(v) => v,
                Err(resp) => return *resp,
            };
            if let Some(resp) = apply_patch_document(&mut doc, &patch) {
                return resp;
            }
            let path = format!("/nudr-dr/v2/application-data/{collection}/{id}");
            ds.doc_put(&store_key, id, doc.clone());
            notify_application_data_change(&path, id, false);
            SbiResponse::with_status(200).with_body(doc.to_string(), "application/json")
        }
        (Some(id), "DELETE") => {
            if ds.doc_remove(&store_key, id).is_some() {
                let path = format!("/nudr-dr/v2/application-data/{collection}/{id}");
                notify_application_data_change(&path, id, true);
                SbiResponse::with_status(204)
            } else {
                send_not_found(&format!("{collection} not found"), Some("DATA_NOT_FOUND"))
            }
        }
        _ => send_method_not_allowed(method, &format!("application-data/{collection}")),
    }
}

// ============================================================================
// Data builders (from nudr_handler.rs, adapted for direct SBI response)
// ============================================================================

fn build_am_data(data: &nextgcore_dbi::types::NextgcoreSubscriptionData) -> serde_json::Value {
    let mut am = serde_json::Map::new();
    if data.num_of_msisdn > 0 {
        let gpsis: Vec<serde_json::Value> = data
            .msisdn
            .iter()
            .map(|m| serde_json::Value::String(format!("msisdn-{}", m.bcd)))
            .collect();
        am.insert("gpsis".to_string(), serde_json::Value::Array(gpsis));
    }
    if data.ambr.uplink > 0 || data.ambr.downlink > 0 {
        am.insert(
            "subscribedUeAmbr".to_string(),
            serde_json::json!({
                "uplink": format_ambr(data.ambr.uplink),
                "downlink": format_ambr(data.ambr.downlink)
            }),
        );
    }
    if data.num_of_slice > 0 {
        let mut default_nssais = Vec::new();
        let mut single_nssais = Vec::new();
        for slice in &data.slice {
            let mut nssai_json = serde_json::Map::new();
            nssai_json.insert(
                "sst".to_string(),
                serde_json::Value::Number(slice.s_nssai.sst.into()),
            );
            if slice.s_nssai.has_sd() {
                nssai_json.insert(
                    "sd".to_string(),
                    serde_json::Value::String(format!("{:06x}", slice.s_nssai.sd.v)),
                );
            }
            let val = serde_json::Value::Object(nssai_json);
            if slice.default_indicator {
                default_nssais.push(val);
            } else {
                single_nssais.push(val);
            }
        }
        let mut nssai = serde_json::Map::new();
        if !default_nssais.is_empty() {
            nssai.insert(
                "defaultSingleNssais".to_string(),
                serde_json::Value::Array(default_nssais),
            );
        }
        if !single_nssais.is_empty() {
            nssai.insert(
                "singleNssais".to_string(),
                serde_json::Value::Array(single_nssais),
            );
        }
        am.insert("nssai".to_string(), serde_json::Value::Object(nssai));
    }
    serde_json::Value::Object(am)
}

fn build_smf_selection_data(
    data: &nextgcore_dbi::types::NextgcoreSubscriptionData,
) -> serde_json::Value {
    let mut smf_sel = serde_json::Map::new();
    let mut snssai_infos = serde_json::Map::new();
    for slice in &data.slice {
        let snssai_key = if slice.s_nssai.has_sd() {
            format!("{:02x}-{:06x}", slice.s_nssai.sst, slice.s_nssai.sd.v)
        } else {
            format!("{:02x}", slice.s_nssai.sst)
        };
        let dnn_infos: Vec<serde_json::Value> = slice
            .session
            .iter()
            .filter_map(|sess| {
                sess.name
                    .as_ref()
                    .map(|dnn| serde_json::json!({"dnn": dnn}))
            })
            .collect();
        if !dnn_infos.is_empty() {
            snssai_infos.insert(snssai_key, serde_json::json!({"dnnInfos": dnn_infos}));
        }
    }
    if !snssai_infos.is_empty() {
        smf_sel.insert(
            "subscribedSnssaiInfos".to_string(),
            serde_json::Value::Object(snssai_infos),
        );
    }
    serde_json::Value::Object(smf_sel)
}

/// Build the TS 29.571 §5.5.3 `Arp` JSON object.
///
/// All three members (`priorityLevel`, `preemptCap`, `preemptVuln`) are
/// required by the schema; a strict OpenAPI-validating SMF rejects the
/// DnnConfiguration when either pre-emption field is absent.
///
/// Mapping (mirrors the legacy `nudr_handler.rs:636-648`):
/// - `pre_emption_capability == 1`   → `"MAY_PREEMPT"`, else `"NOT_PREEMPT"`
/// - `pre_emption_vulnerability == 1` → `"PREEMPTABLE"`, else `"NOT_PREEMPTABLE"`
fn arp_json(arp: &nextgcore_dbi::types::NextgcoreArp) -> serde_json::Value {
    let preempt_cap = if arp.pre_emption_capability == 1 {
        "MAY_PREEMPT"
    } else {
        "NOT_PREEMPT"
    };
    let preempt_vuln = if arp.pre_emption_vulnerability == 1 {
        "PREEMPTABLE"
    } else {
        "NOT_PREEMPTABLE"
    };
    serde_json::json!({
        "priorityLevel": arp.priority_level,
        "preemptCap": preempt_cap,
        "preemptVuln": preempt_vuln,
    })
}

fn build_sm_data(data: &nextgcore_dbi::types::NextgcoreSubscriptionData) -> serde_json::Value {
    let mut sm_data_list = Vec::new();
    for slice in &data.slice {
        let mut sm_entry = serde_json::Map::new();
        let mut snssai = serde_json::Map::new();
        snssai.insert(
            "sst".to_string(),
            serde_json::Value::Number(slice.s_nssai.sst.into()),
        );
        if slice.s_nssai.has_sd() {
            snssai.insert(
                "sd".to_string(),
                serde_json::Value::String(format!("{:06x}", slice.s_nssai.sd.v)),
            );
        }
        sm_entry.insert("singleNssai".to_string(), serde_json::Value::Object(snssai));
        let mut dnn_configs = serde_json::Map::new();
        for sess in &slice.session {
            if let Some(dnn) = &sess.name {
                let pdu_type = match sess.session_type {
                    1 => "IPV4",
                    2 => "IPV6",
                    3 => "IPV4V6",
                    _ => "IPV4V6",
                };
                // TS 29.505 §5.4.4 sscModes: NextgcoreSession carries no provisioned
                // SSC-mode field in the current DB schema.  The legacy
                // nudr_handler.rs:627 emitted the full set {1,2,3} as the
                // documented default, which is used here. (udrd-12)
                dnn_configs.insert(dnn.clone(), serde_json::json!({
                    "pduSessionTypes": { "defaultSessionType": pdu_type, "allowedSessionTypes": [pdu_type] },
                    "sscModes": {
                        "defaultSscMode": "SSC_MODE_1",
                        "allowedSscModes": ["SSC_MODE_1", "SSC_MODE_2", "SSC_MODE_3"]
                    },
                    "5gQosProfile": { "5qi": sess.qos.index, "arp": arp_json(&sess.qos.arp) },
                    "sessionAmbr": { "uplink": format_ambr(sess.ambr.uplink), "downlink": format_ambr(sess.ambr.downlink) }
                }));
            }
        }
        if !dnn_configs.is_empty() {
            sm_entry.insert(
                "dnnConfigurations".to_string(),
                serde_json::Value::Object(dnn_configs),
            );
        }
        sm_data_list.push(serde_json::Value::Object(sm_entry));
    }
    serde_json::Value::Array(sm_data_list)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Build a TS 29.505 AuthenticationSubscription document.
///
/// The SequenceNumber object carries `sqnScheme` and `indLength` alongside the
/// 12-hex-digit `sqn` per the TS 29.505 SequenceNumber shape (the UE-side IND
/// is 5 bits per TS 33.102 SQN array management).
/// Validate an optional 256-bit key member provisioned as hex (#115).
///
/// Returns `Ok(None)` when absent — which is the normal case for every non-TUAK
/// subscriber — and a 400 when present but not 64 hex characters. Rejecting at
/// provisioning time rather than at authentication time is the point: TS 35.231's TOP and
/// TOPc are 256-bit, and a short or non-hex value silently becomes a zero-padded key that
/// authenticates against nothing.
fn validate_optional_key_256(
    body: &serde_json::Value,
    member: &str,
) -> Result<Option<String>, Box<SbiResponse>> {
    match body.get(member).and_then(|v| v.as_str()) {
        None => Ok(None),
        Some("") => Ok(None),
        Some(s) if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) => {
            Ok(Some(s.to_string()))
        }
        Some(_) => Err(Box::new(send_error(
            400,
            "Bad Request",
            &format!("{member} must be 64 hex characters (a 256-bit TUAK operator field)"),
            Some("MANDATORY_IE_INCORRECT"),
        ))),
    }
}

fn build_auth_subscription_json(
    supi: &str,
    auth_info: &nextgcore_dbi::subscription::NextgcoreDbiAuthInfo,
) -> serde_json::Value {
    // TS 29.505 §5.4.2.2: serve the provisioned authenticationMethod (AuthMethod).
    // Legacy subscriber docs lack the field (empty) -> default to "5G_AKA" per
    // TS 33.501 §6.1.2. (udrd-10 / udrd#1)
    let auth_method = if auth_info.authentication_method.is_empty() {
        "5G_AKA"
    } else {
        auth_info.authentication_method.as_str()
    };

    // TS 29.505 §5.4.2.23 / TS 33.102 SQN array management: with indLength=5
    // the low 5 bits of the 48-bit SQN are the IND component and must be
    // zeroed in the stored/served representation. (udrd-08)
    const IND_LENGTH: u64 = 5;
    const SQN_48_MASK: u64 = 0xFFFF_FFFF_FFFF;
    const IND_MASK: u64 = (1u64 << IND_LENGTH) - 1; // 0x1F
    let sqn_zeroed = (auth_info.sqn & SQN_48_MASK) & !IND_MASK;

    let mut out = serde_json::json!({
        "authenticationMethod": auth_method,
        "encPermanentKey": bytes_to_hex(&auth_info.k),
        "encOpcKey": bytes_to_hex(if auth_info.use_opc { &auth_info.opc } else { &auth_info.op }),
        "authenticationManagementField": bytes_to_hex(&auth_info.amf),
        "supi": supi,
        "sequenceNumber": {
            "sqnScheme": "NON_TIME_BASED",
            "sqn": format!("{sqn_zeroed:012x}"),
            "indLength": IND_LENGTH
        }
    });

    // #115: TS 29.505 `algorithmId` and `encTopcKey`, both optional (0..1) and both
    // OMITTED when not provisioned rather than emitted as empty strings — an empty
    // `algorithmId` is not "MILENAGE", it is a value the UDM would have to interpret,
    // and the whole point of the field being absent is that there is nothing to
    // interpret. Every subscriber provisioned before #115 therefore serialises exactly
    // as it did before.
    if let Some(obj) = out.as_object_mut() {
        if !auth_info.algorithm_id.is_empty() {
            obj.insert(
                "algorithmId".to_string(),
                serde_json::json!(auth_info.algorithm_id),
            );
        }
        if auth_info.use_topc {
            obj.insert(
                "encTopcKey".to_string(),
                serde_json::json!(bytes_to_hex(&auth_info.topc)),
            );
        }
    }
    out
}

/// Lossless AMBR formatter (udrd-02).
///
/// Chooses the largest SI unit (`Tbps` → `Gbps` → `Mbps` → `Kbps` → `bps`)
/// that divides `bps` exactly, producing a value that round-trips back to the
/// original bit-rate.  Truncating integer division is intentionally avoided —
/// `1_500_000_000 bps` becomes `"1500 Mbps"`, not `"1 Gbps"`.
///
/// The output always matches the TS 29.571 `BitRate` pattern
/// `^\d+(\.\d+)? (bps|Kbps|Mbps|Gbps|Tbps)$`.
fn format_ambr(bps: u64) -> String {
    if bps == 0 {
        return "0 bps".to_string();
    }
    const TBPS: u64 = 1_000_000_000_000;
    const GBPS: u64 = 1_000_000_000;
    const MBPS: u64 = 1_000_000;
    const KBPS: u64 = 1_000;
    if bps.is_multiple_of(TBPS) {
        format!("{} Tbps", bps / TBPS)
    } else if bps.is_multiple_of(GBPS) {
        format!("{} Gbps", bps / GBPS)
    } else if bps.is_multiple_of(MBPS) {
        format!("{} Mbps", bps / MBPS)
    } else if bps.is_multiple_of(KBPS) {
        format!("{} Kbps", bps / KBPS)
    } else {
        format!("{bps} bps")
    }
}

// ============================================================================
// Config parsing
// ============================================================================

/// Parse db_uri from YAML config file
fn parse_db_uri(config_path: &str) -> String {
    // Try config file first
    if let Ok(content) = std::fs::read_to_string(config_path) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("db_uri:") {
                let uri = trimmed.trim_start_matches("db_uri:").trim();
                if !uri.is_empty() {
                    log::info!("Found db_uri in config: {}", mask_uri(uri));
                    return uri.to_string();
                }
            }
        }
    }
    // Fall back to env var
    if let Ok(uri) = std::env::var("DB_URI") {
        return uri;
    }
    // Default for Docker deployment
    String::from("mongodb://172.23.0.2/nextgcore")
}

/// Mask MongoDB URI for logging (hide credentials)
fn mask_uri(uri: &str) -> String {
    if let Some(at_pos) = uri.find('@') {
        if let Some(proto_end) = uri.find("://") {
            return format!("{}://***@{}", &uri[..proto_end], &uri[at_pos + 1..]);
        }
    }
    uri.to_string()
}

// ============================================================================
// Infrastructure
// ============================================================================

/// Initialize logging based on command line arguments
fn init_logging(args: &Args) -> Result<()> {
    let mut builder = env_logger::Builder::new();

    let level = match args.log_level.to_lowercase().as_str() {
        "trace" => log::LevelFilter::Trace,
        "debug" => log::LevelFilter::Debug,
        "info" => log::LevelFilter::Info,
        "warn" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        _ => log::LevelFilter::Info,
    };

    builder.filter_level(level);
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

/// Async main event loop
async fn run_event_loop_async(shutdown: Arc<AtomicBool>) -> Result<()> {
    log::debug!("Entering async main event loop");

    while !shutdown.load(Ordering::SeqCst) && !SHUTDOWN.load(Ordering::SeqCst) {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    log::debug!("Exiting main event loop");
    Ok(())
}

/// Build the UDR's NFProfile for NRF registration (TS 29.510 §6.1.6.2.2).
///
/// Split out of `register_with_nrf` so the advertised API version can be
/// asserted without standing up an NRF. **Nudr_DataRepository is v2**
/// (TS 29.504 §6.1.1, "The `<apiVersion>` shall be v2"), unlike
/// Nnrf_NFManagement which the UDR consumes at v1.
fn build_udr_nf_profile(nf_instance_id: &str, sbi_addr: &str, sbi_port: u16) -> serde_json::Value {
    serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "UDR",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [
            {
                "serviceInstanceId": format!("{nf_instance_id}-nudr-dr"),
                "serviceName": "nudr-dr",
                // TS 29.504 §6.1.1: "The <apiVersion> shall be v2" for
                // Nudr_DataRepository. Advertising v1 while the PCF already
                // called v2 meant discovery and the live consumer disagreed.
                "versions": [{"apiVersionInUri": "v2", "apiFullVersion": "2.0.0"}],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
            }
        ],
        "allowedNfTypes": ["UDM", "PCF", "AUSF", "SCP"],
        "heartBeatTimer": 10
    })
}

/// Register UDR with NRF.
///
/// Returns the NF instance ID on success so the caller can start a heartbeat
/// worker.
async fn register_with_nrf(sbi_addr: &str, sbi_port: u16) -> Result<String, String> {
    let sbi_ctx = nextgcore_sbi::context::global_context();

    let nrf_uri = sbi_ctx.get_nrf_uri().await;
    let nrf_uri = match nrf_uri {
        Some(uri) => uri,
        None => {
            log::debug!("No NRF URI configured, skipping NRF registration");
            return Ok(String::new());
        }
    };

    log::info!("Registering UDR with NRF at {nrf_uri}");

    let (nrf_host, nrf_port) = parse_nrf_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_instance_id = uuid::Uuid::new_v4().to_string();

    let nf_profile = build_udr_nf_profile(&nf_instance_id, sbi_addr, sbi_port);

    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    let response = client
        .put_json(&path, &nf_profile)
        .await
        .map_err(|e| format!("NRF registration request failed: {e}"))?;

    match response.status {
        200 | 201 => {
            log::info!("UDR registered with NRF successfully (id={nf_instance_id})");
            Ok(nf_instance_id)
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
    fn test_nrf_profile_advertises_nudr_dr_at_v2() {
        // TS 29.504 §6.1.1: "The <apiVersion> shall be v2" for
        // Nudr_DataRepository, and the OpenAPI server URL is
        // `{apiRoot}/nudr-dr/v2`.
        //
        // Regression: this profile advertised v1 while the PCF already called
        // /nudr-dr/v2/policy-data/... The disagreement was invisible because
        // the UDR's live router discards the version segment
        // (`let _version = parts[1]`), so both spellings routed. Against a
        // strict peer, or once the version is ever enforced, one side breaks.
        let profile = build_udr_nf_profile("udr-test-instance", "10.45.0.11", 7777);

        let service = profile["nfServices"]
            .as_array()
            .expect("nfServices must be an array")
            .iter()
            .find(|s| s["serviceName"] == "nudr-dr")
            .expect("nudr-dr must be registered");

        assert_eq!(
            service["versions"][0]["apiVersionInUri"], "v2",
            "Nudr_DataRepository must be advertised at v2 per TS 29.504 6.1.1"
        );
        // apiFullVersion must track the URI version rather than lag it.
        assert_eq!(service["versions"][0]["apiFullVersion"], "2.0.0");
    }

    #[test]
    fn test_udr_yaml_oauth2_knob() {
        let yaml = r#"
udr:
  sbi:
    server:
      - address: 127.0.0.1
        port: 7777
    oauth2:
      require: true
    client:
      nrf:
        - uri: http://nrf:7777
"#;
        let parsed: UdrYaml = serde_yaml::from_str(yaml).unwrap();
        let sbi = parsed.udr.unwrap().sbi.unwrap();
        assert_eq!(sbi.oauth2.unwrap().require, Some(true));
        assert_eq!(sbi.client.unwrap().nrf.unwrap()[0].uri, "http://nrf:7777");
    }

    #[test]
    fn test_udr_yaml_oauth2_defaults_off() {
        let yaml = r#"
udr:
  sbi:
    client:
      nrf:
        - uri: http://nrf:7777
"#;
        let parsed: UdrYaml = serde_yaml::from_str(yaml).unwrap();
        let sbi = parsed.udr.unwrap().sbi.unwrap();
        assert!(sbi.oauth2.is_none());
    }

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-udrd"]);
        assert_eq!(args.config, "/etc/nextgcore/udr.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 7777);
        assert!(!args.tls);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-udrd",
            "-c",
            "/custom/udr.yaml",
            "-e",
            "debug",
            "--sbi-addr",
            "0.0.0.0",
            "--sbi-port",
            "8080",
        ]);
        assert_eq!(args.config, "/custom/udr.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 8080);
    }

    #[test]
    fn test_args_tls() {
        let args = Args::parse_from([
            "nextgcore-udrd",
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
    fn test_mask_uri() {
        assert_eq!(
            mask_uri("mongodb://user:pass@host/db"),
            "mongodb://***@host/db"
        );
        assert_eq!(mask_uri("mongodb://host/db"), "mongodb://host/db");
    }

    #[test]
    fn test_is_valid_plmn_id() {
        assert!(is_valid_plmn_id("00101"));
        assert!(is_valid_plmn_id("310410"));
        assert!(!is_valid_plmn_id("0010"));
        assert!(!is_valid_plmn_id("0010100"));
        assert!(!is_valid_plmn_id("00a01"));
    }

    #[test]
    fn test_auth_subscription_sequence_number_shape() {
        // TS 29.505 AuthenticationSubscription / SequenceNumber round-trip:
        // sqnScheme + indLength + 12-hex-digit sqn must be present.
        // udrd-08: the low 5 IND bits must be zeroed — 0x1F21 → 0x1F20.
        let mut info = nextgcore_dbi::subscription::NextgcoreDbiAuthInfo::default();
        info.sqn = 0x1F21;
        info.use_opc = true;
        let doc = build_auth_subscription_json("imsi-001010000000001", &info);
        assert_eq!(doc["authenticationMethod"], "5G_AKA");
        let seq = &doc["sequenceNumber"];
        assert_eq!(seq["sqnScheme"], "NON_TIME_BASED");
        assert_eq!(seq["indLength"], 5);
        let sqn = seq["sqn"].as_str().unwrap();
        assert_eq!(sqn.len(), 12);
        assert!(sqn.bytes().all(|b| b.is_ascii_hexdigit()));
        // IND bits [4:0] of 0x1F21 = 0x01 → zeroed → 0x1F20
        assert_eq!(sqn, "000000001f20");
        // Confirm low 5 bits are zero
        let sqn_val = u64::from_str_radix(sqn, 16).unwrap();
        assert_eq!(sqn_val & 0x1F, 0, "IND bits must be zeroed");
        assert_eq!(doc["supi"], "imsi-001010000000001");
    }

    #[test]
    fn test_pct_decode() {
        assert_eq!(pct_decode("a%2Cb"), "a,b");
        assert_eq!(pct_decode("plain"), "plain");
        assert_eq!(pct_decode("%5B%7B%22sst%22%3A1%7D%5D"), "[{\"sst\":1}]");
    }

    // ------------------------------------------------------------------
    // HTTP-level tests over a real HTTP/2 SBI server on ephemeral ports.
    // ------------------------------------------------------------------

    use nextgcore_sbi::client::SbiClient;
    use serde_json::json;
    use std::time::Duration;
    use tokio::sync::mpsc;

    /// Serializes tests that depend on the global nextgcore-dbi backend
    /// state: the WSB-6 tests enable the in-memory dbi test store while
    /// `test_http_auth_provisioning_and_plmn_validation` asserts the
    /// fail-closed no-DB 503 path — the two must not overlap in time.
    static DBI_BACKEND_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// RAII guard (WSB-6): holds `DBI_BACKEND_LOCK` with the nextgcore-dbi
    /// in-memory test store enabled, and disables the store again on drop —
    /// including on panic/unwind, so a failing test cannot leak the store
    /// into the fail-closed 503 test.
    struct DbiTestStore {
        _lock: tokio::sync::MutexGuard<'static, ()>,
    }

    impl DbiTestStore {
        async fn enable() -> Self {
            let lock = DBI_BACKEND_LOCK.lock().await;
            nextgcore_dbi::test_store::enable();
            Self { _lock: lock }
        }
    }

    impl Drop for DbiTestStore {
        fn drop(&mut self) {
            nextgcore_dbi::test_store::disable();
        }
    }

    /// Start the UDR SBI server plus a local notification listener that
    /// forwards (path, body) of every received POST into a channel.
    async fn start_udr_and_listener() -> (
        SbiServer,
        SbiClient,
        SbiServer,
        u16,
        mpsc::UnboundedReceiver<(String, String)>,
    ) {
        let (udr_listener, udr_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let udr_server =
            SbiServer::on_listener(NextgcoreSbiServerConfig::new(udr_addr), udr_listener);
        udr_server
            .start(udr_sbi_request_handler)
            .await
            .expect("UDR SBI server starts");

        let (listener_listener, listener_addr) =
            nextgcore_sbi::test_support::bound_listener().into_parts();
        let (tx, rx) = mpsc::unbounded_channel::<(String, String)>();
        let listener = SbiServer::on_listener(
            NextgcoreSbiServerConfig::new(listener_addr),
            listener_listener,
        );
        listener
            .start(move |req: SbiRequest| {
                let tx = tx.clone();
                async move {
                    let body = req.http.content.clone().unwrap_or_default();
                    let _ = tx.send((req.header.uri.clone(), body));
                    SbiResponse::with_status(204)
                }
            })
            .await
            .expect("listener starts");

        let client = SbiClient::with_host_port("127.0.0.1", udr_addr.port());
        (udr_server, client, listener, listener_addr.port(), rx)
    }

    async fn recv_notification(
        rx: &mut mpsc::UnboundedReceiver<(String, String)>,
    ) -> (String, serde_json::Value) {
        let (path, body) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("notification within 5s")
            .expect("channel open");
        let value: serde_json::Value = serde_json::from_str(&body).expect("notification JSON");
        (path, value)
    }

    /// amf-3gpp-access: strict-peer rejection, full registration round-trip,
    /// PATCH, DELETE, and DataChangeNotify delivery to a subs-to-notify
    /// subscriber over a real local listener.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_amf3gpp_lifecycle_and_notify() {
        let (udr, client, listener, cb_port, mut rx) = start_udr_and_listener().await;
        let supi = "imsi-001019900000001";
        let resource = format!("/nudr-dr/v2/subscription-data/{supi}/context-data/amf-3gpp-access");

        // Subscribe to changes for this UE.
        let cb_uri = format!("http://127.0.0.1:{cb_port}/cb/data-change");
        let sub_body = json!({
            "ueId": supi,
            "callbackReference": cb_uri,
            "monitoredResourceUris": [format!("http://udr{resource}")]
        });
        let resp = client
            .post_json("/nudr-dr/v2/subscription-data/subs-to-notify", &sub_body)
            .await
            .expect("POST sub");
        assert_eq!(resp.status, 201);
        let loc = resp.http.get_header("Location").expect("Location").clone();
        assert!(loc.contains("/subscription-data/subs-to-notify/"));

        // Missing mandatory callbackReference -> 400 ProblemDetails
        let resp = client
            .post_json(
                "/nudr-dr/v2/subscription-data/subs-to-notify",
                &json!({"monitoredResourceUris": ["/x"]}),
            )
            .await
            .expect("POST bad sub");
        assert_eq!(resp.status, 400);
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(problem["cause"], "MANDATORY_IE_MISSING");

        // Strict-peer: PUT registration missing mandatory guami -> 400
        let resp = client
            .put_json(
                &resource,
                &json!({
                    "amfInstanceId": "9f7d5a3e-0000-4000-8000-000000000001",
                    "deregCallbackUri": "http://amf/dereg",
                    "ratType": "NR"
                }),
            )
            .await
            .expect("PUT invalid");
        assert_eq!(resp.status, 400);
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(problem["cause"], "MANDATORY_IE_MISSING");
        assert!(problem["detail"].as_str().unwrap().contains("guami"));

        // Full registration -> 201 + Location + lossless echo
        let registration = json!({
            "amfInstanceId": "9f7d5a3e-0000-4000-8000-000000000001",
            "deregCallbackUri": "http://amf.example.com/namf-callback/v1/dereg",
            "guami": {"plmnId": {"mcc": "001", "mnc": "01"}, "amfId": "020040"},
            "ratType": "NR",
            "initialRegistrationInd": true,
            "pei": "imeisv-3512340000000101"
        });
        let resp = client
            .put_json(&resource, &registration)
            .await
            .expect("PUT registration");
        assert_eq!(resp.status, 201);
        assert!(resp
            .http
            .get_header("Location")
            .expect("Location on 201")
            .ends_with("amf-3gpp-access"));

        // Notification for the PUT must be delivered to the listener.
        let (path, notify) = recv_notification(&mut rx).await;
        assert_eq!(path, "/cb/data-change");
        assert_eq!(notify["ueId"], supi);
        assert!(notify["notifyItems"][0]["resourceId"]
            .as_str()
            .unwrap()
            .ends_with("amf-3gpp-access"));
        assert_eq!(
            notify["notifyItems"][0]["changes"][0]["newValue"]["ratType"],
            "NR"
        );

        // GET returns the full stored registration (not a stub).
        let resp = client.get(&resource).await.expect("GET registration");
        assert_eq!(resp.status, 200);
        let stored: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(stored, registration, "PUT -> GET must be lossless");

        // Replace -> 204, PATCH purgeFlag -> 204 and visible on GET.
        let resp = client
            .put_json(&resource, &registration)
            .await
            .expect("PUT replace");
        assert_eq!(resp.status, 204);
        let _ = recv_notification(&mut rx).await; // replace notification

        let mut req = SbiRequest::patch(&resource);
        req.http.set_content(
            json!([{"op": "replace", "path": "/purgeFlag", "value": true}]).to_string(),
        );
        req.http
            .set_header("Content-Type", "application/json-patch+json");
        let resp = client.send_request(req).await.expect("PATCH");
        assert_eq!(resp.status, 204);
        let _ = recv_notification(&mut rx).await; // patch notification
        let resp = client.get(&resource).await.expect("GET after PATCH");
        let stored: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(stored["purgeFlag"], true);

        // DELETE -> 204, then GET -> 404 ProblemDetails.
        let resp = client.delete(&resource).await.expect("DELETE");
        assert_eq!(resp.status, 204);
        let (_, notify) = recv_notification(&mut rx).await;
        assert_eq!(notify["notifyItems"][0]["changes"][0]["op"], "REMOVE");
        let resp = client.get(&resource).await.expect("GET after DELETE");
        assert_eq!(resp.status, 404);
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(problem["status"], 404);

        // Unsubscribe by ue-id.
        let mut req = SbiRequest::delete("/nudr-dr/v2/subscription-data/subs-to-notify");
        req.http.set_param("ue-id", supi);
        let resp = client.send_request(req).await.expect("DELETE subs");
        assert_eq!(resp.status, 204);

        udr.stop().await.expect("udr stops");
        listener.stop().await.expect("listener stops");
    }

    /// Regression (C5 / remote DoS): GET smf-registrations for a SUPI that
    /// the UDR has never seen must return 200 with an empty array, NOT panic
    /// (the handler previously `.expect()`-ed on a missing UE, crashing the
    /// NF on a crafted GET). Also covers the per-PDU GET (404) and the PUT ->
    /// GET-list round-trip so the success path stays intact.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_smf_registrations_unknown_ue_no_panic() {
        let (udr, client, listener, _cb_port, _rx) = start_udr_and_listener().await;

        // Unknown UE, collection GET -> 200 + empty JSON array (no panic).
        let unknown = "imsi-001019999999999";
        let coll =
            format!("/nudr-dr/v2/subscription-data/{unknown}/context-data/smf-registrations");
        let resp = client.get(&coll).await.expect("GET unknown smf-regs");
        assert_eq!(resp.status, 200, "unknown UE collection GET must be 200");
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(
            body,
            json!([]),
            "unknown UE must yield an empty array, not a panic"
        );

        // Unknown UE, per-PDU GET -> 404 ProblemDetails (also no panic).
        let single = format!("{coll}/5");
        let resp = client.get(&single).await.expect("GET unknown smf-reg/5");
        assert_eq!(resp.status, 404);

        // Success path: PUT a full SmfRegistration then GET the actual stored
        // values back (not a hardcoded summary). A new registration is 201.
        let supi = "imsi-001019900000077";
        let coll = format!("/nudr-dr/v2/subscription-data/{supi}/context-data/smf-registrations");
        let single = format!("{coll}/5");
        let reg = json!({
            "smfInstanceId": "11111111-2222-3333-4444-555555555555",
            "pduSessionId": 5,
            "singleNssai": {"sst": 2, "sd": "000001"},
            "dnn": "ims",
            "plmnId": {"mcc": "001", "mnc": "01"}
        });
        let resp = client.put_json(&single, &reg).await.expect("PUT smf-reg");
        assert_eq!(resp.status, 201, "new SmfRegistration must be 201 Created");

        // Per-PDU GET returns the ACTUAL registered document.
        let resp = client.get(&single).await.expect("GET smf-reg/5");
        assert_eq!(resp.status, 200);
        let got: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(got["smfInstanceId"], "11111111-2222-3333-4444-555555555555");
        assert_eq!(got["singleNssai"], json!({"sst": 2, "sd": "000001"}));
        assert_eq!(got["dnn"], "ims");
        assert_eq!(got["plmnId"], json!({"mcc": "001", "mnc": "01"}));
        assert_eq!(got["pduSessionId"], 5);

        let resp = client.get(&coll).await.expect("GET smf-regs list");
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let arr = body.as_array().expect("array");
        assert_eq!(arr.len(), 1, "one registration after PUT");
        assert_eq!(arr[0]["pduSessionId"], 5);
        assert_eq!(arr[0]["dnn"], "ims");
        assert_eq!(
            arr[0]["smfInstanceId"],
            "11111111-2222-3333-4444-555555555555"
        );

        // Replacing the same registration is 204 (not created).
        let resp = client
            .put_json(&single, &reg)
            .await
            .expect("re-PUT smf-reg");
        assert_eq!(resp.status, 204, "replace must be 204");

        // Missing mandatory IEs -> 400 MANDATORY_IE_MISSING.
        let resp = client
            .put_json(&single, &json!({"dnn": "ims"}))
            .await
            .expect("PUT incomplete smf-reg");
        assert_eq!(resp.status, 400, "missing mandatory IEs must be 400");

        udr.stop().await.expect("udr stops");
        listener.stop().await.expect("listener stops");
    }

    /// exposure-data: subscription validation, AM/SM lifecycle with RFC 7396
    /// merge-patch, and ExposureDataChangeNotification delivery.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_exposure_data_lifecycle_and_notify() {
        let (udr, client, listener, cb_port, mut rx) = start_udr_and_listener().await;
        let ue = "imsi-001019900000002";
        let am_path = format!("/nudr-dr/v2/exposure-data/{ue}/access-and-mobility-data");
        let sm_path = format!("/nudr-dr/v2/exposure-data/{ue}/session-management-data/5");

        // Strict-peer: subscription without notificationUri -> 400.
        let resp = client
            .post_json(
                "/nudr-dr/v2/exposure-data/subs-to-notify",
                &json!({"monitoredResourceUris": [am_path]}),
            )
            .await
            .expect("POST bad sub");
        assert_eq!(resp.status, 400);

        // Valid subscription -> 201 + Location.
        let resp = client
            .post_json(
                "/nudr-dr/v2/exposure-data/subs-to-notify",
                &json!({
                    "notificationUri": format!("http://127.0.0.1:{cb_port}/cb/exposure"),
                    "monitoredResourceUris": [format!("/nudr-dr/v2/exposure-data/{ue}")]
                }),
            )
            .await
            .expect("POST sub");
        assert_eq!(resp.status, 201);
        let sub_loc = resp.http.get_header("Location").expect("Location").clone();
        let sub_id = sub_loc.rsplit('/').next().unwrap().to_string();

        // PUT AM data -> 201; notification array with ueId + data.
        let am_data = json!({"roamingStatus": false, "timeZone": "+02:00"});
        let resp = client.put_json(&am_path, &am_data).await.expect("PUT am");
        assert_eq!(resp.status, 201);
        let (path, notify) = recv_notification(&mut rx).await;
        assert_eq!(path, "/cb/exposure");
        assert!(notify.is_array());
        assert_eq!(notify[0]["ueId"], ue);
        assert_eq!(notify[0]["accessAndMobilityData"]["roamingStatus"], false);

        // GET -> 200 lossless.
        let resp = client.get(&am_path).await.expect("GET am");
        assert_eq!(resp.status, 200);
        let stored: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(stored, am_data);

        // PATCH (merge-patch) -> 204 and merged result on GET.
        let mut req = SbiRequest::patch(&am_path);
        req.http
            .set_content(json!({"roamingStatus": true, "timeZone": null}).to_string());
        req.http
            .set_header("Content-Type", "application/merge-patch+json");
        let resp = client.send_request(req).await.expect("PATCH am");
        assert_eq!(resp.status, 204);
        let _ = recv_notification(&mut rx).await;
        let resp = client.get(&am_path).await.expect("GET merged");
        let stored: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(stored, json!({"roamingStatus": true}));

        // SM data lifecycle: PUT -> 201, GET, DELETE -> 204 with delResources.
        let sm_data = json!({"pduSessionStatus": "ACTIVE", "dnn": "internet",
                             "ipv4Addr": "10.45.0.2", "pduSessionId": 5});
        let resp = client.put_json(&sm_path, &sm_data).await.expect("PUT sm");
        assert_eq!(resp.status, 201);
        let (_, notify) = recv_notification(&mut rx).await;
        assert_eq!(notify[0]["pduSessionManagementData"][0]["dnn"], "internet");
        let resp = client.get(&sm_path).await.expect("GET sm");
        assert_eq!(resp.status, 200);
        let resp = client.delete(&sm_path).await.expect("DELETE sm");
        assert_eq!(resp.status, 204);
        let (_, notify) = recv_notification(&mut rx).await;
        assert!(notify[0]["delResources"][0]
            .as_str()
            .unwrap()
            .ends_with("session-management-data/5"));

        // DELETE AM -> 204; GET -> 404.
        let resp = client.delete(&am_path).await.expect("DELETE am");
        assert_eq!(resp.status, 204);
        let _ = recv_notification(&mut rx).await;
        let resp = client.get(&am_path).await.expect("GET deleted");
        assert_eq!(resp.status, 404);

        // Remove the subscription -> 204; second delete -> 404.
        let resp = client
            .delete(&format!(
                "/nudr-dr/v2/exposure-data/subs-to-notify/{sub_id}"
            ))
            .await
            .expect("DELETE sub");
        assert_eq!(resp.status, 204);
        let resp = client
            .delete(&format!(
                "/nudr-dr/v2/exposure-data/subs-to-notify/{sub_id}"
            ))
            .await
            .expect("DELETE sub again");
        assert_eq!(resp.status, 404);

        udr.stop().await.expect("udr stops");
        listener.stop().await.expect("listener stops");
    }

    /// application-data: pfds + influenceData lifecycle, query filters, and
    /// TrafficInfluDataNotif delivery.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_application_data_lifecycle_and_notify() {
        let (udr, client, listener, cb_port, mut rx) = start_udr_and_listener().await;

        // Strict-peer: PFD data without pfds -> 400.
        let resp = client
            .put_json(
                "/nudr-dr/v2/application-data/pfds/app-w42",
                &json!({"applicationId": "app-w42"}),
            )
            .await
            .expect("PUT bad pfd");
        assert_eq!(resp.status, 400);

        // Valid PFD -> 201 + Location; list contains it.
        let pfd = json!({
            "applicationId": "app-w42",
            "pfds": [{"pfdId": "pfd-1", "flowDescriptions": ["permit out ip from any to any"]}]
        });
        let resp = client
            .put_json("/nudr-dr/v2/application-data/pfds/app-w42", &pfd)
            .await
            .expect("PUT pfd");
        assert_eq!(resp.status, 201);
        let resp = client
            .get("/nudr-dr/v2/application-data/pfds")
            .await
            .expect("GET pfds");
        assert_eq!(resp.status, 200);
        let list: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(list
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["applicationId"] == "app-w42"));

        // Influence subscription (supis filter) -> 201.
        let resp = client
            .post_json(
                "/nudr-dr/v2/application-data/influenceData/subs-to-notify",
                &json!({
                    "notificationUri": format!("http://127.0.0.1:{cb_port}/cb/influence"),
                    "supis": ["imsi-001019900000003"]
                }),
            )
            .await
            .expect("POST influence sub");
        assert_eq!(resp.status, 201);

        // Strict-peer: subscription without any oneOf filter -> 400.
        let resp = client
            .post_json(
                "/nudr-dr/v2/application-data/influenceData/subs-to-notify",
                &json!({"notificationUri": "http://x/cb"}),
            )
            .await
            .expect("POST bad influence sub");
        assert_eq!(resp.status, 400);

        // Strict-peer: influence data without afAppId -> 400.
        let resp = client
            .put_json(
                "/nudr-dr/v2/application-data/influenceData/inf-w42",
                &json!({"dnn": "internet"}),
            )
            .await
            .expect("PUT bad influence");
        assert_eq!(resp.status, 400);

        // Valid influence data matching the subscription -> 201 + notify.
        let influ = json!({
            "afAppId": "app-w42",
            "dnn": "internet",
            "supi": "imsi-001019900000003",
            "trafficRoutes": [{"dnai": "edge-1"}]
        });
        let resp = client
            .put_json("/nudr-dr/v2/application-data/influenceData/inf-w42", &influ)
            .await
            .expect("PUT influence");
        assert_eq!(resp.status, 201);
        let (path, notify) = recv_notification(&mut rx).await;
        assert_eq!(path, "/cb/influence");
        assert!(notify.is_array());
        assert!(notify[0]["resUri"].as_str().unwrap().ends_with("inf-w42"));
        assert_eq!(notify[0]["trafficInfluData"]["afAppId"], "app-w42");

        // Collection read with filters.
        let mut req = SbiRequest::get("/nudr-dr/v2/application-data/influenceData");
        req.http.set_param("supis", "imsi-001019900000003");
        let resp = client.send_request(req).await.expect("GET influence");
        assert_eq!(resp.status, 200);
        let list: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(list.as_array().unwrap().len(), 1);
        let mut req = SbiRequest::get("/nudr-dr/v2/application-data/influenceData");
        req.http.set_param("dnns", "no-such-dnn");
        let resp = client.send_request(req).await.expect("GET influence empty");
        let list: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(list.as_array().unwrap().is_empty());

        // DELETE influence -> 204 + deletion notification (resUri only).
        let resp = client
            .delete("/nudr-dr/v2/application-data/influenceData/inf-w42")
            .await
            .expect("DELETE influence");
        assert_eq!(resp.status, 204);
        let (_, notify) = recv_notification(&mut rx).await;
        assert!(notify[0]["resUri"].as_str().unwrap().ends_with("inf-w42"));
        assert!(notify[0].get("trafficInfluData").is_none());

        // DELETE pfd -> 204; GET -> 404.
        let resp = client
            .delete("/nudr-dr/v2/application-data/pfds/app-w42")
            .await
            .expect("DELETE pfd");
        assert_eq!(resp.status, 204);
        let resp = client
            .get("/nudr-dr/v2/application-data/pfds/app-w42")
            .await
            .expect("GET deleted pfd");
        assert_eq!(resp.status, 404);

        udr.stop().await.expect("udr stops");
        listener.stop().await.expect("listener stops");
    }

    /// PUT authentication-subscription provisioning path and PLMN-scoped
    /// provisioned-data validation (strict-peer rejections; the DB-backed
    /// success path requires MongoDB and is covered by E2E).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_auth_provisioning_and_plmn_validation() {
        // WSB-6: this test asserts the fail-closed no-DB 503 path; take the
        // backend lock so it cannot overlap with the WSB-6 tests that enable
        // the in-memory dbi test store.
        let _backend = DBI_BACKEND_LOCK.lock().await;
        let (udr_listener, udr_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let udr = SbiServer::on_listener(NextgcoreSbiServerConfig::new(udr_addr), udr_listener);
        udr.start(udr_sbi_request_handler)
            .await
            .expect("UDR SBI server starts");
        let client = SbiClient::with_host_port("127.0.0.1", udr_addr.port());
        let supi = "imsi-001019900000004";
        let auth_path = format!(
            "/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-subscription"
        );

        // Missing authenticationMethod -> 400 MANDATORY_IE_MISSING.
        let resp = client
            .put_json(
                &auth_path,
                &json!({"encPermanentKey": "00112233445566778899aabbccddeeff"}),
            )
            .await
            .expect("PUT no method");
        assert_eq!(resp.status, 400);
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(problem["cause"], "MANDATORY_IE_MISSING");

        // Malformed key -> 400 MANDATORY_IE_INCORRECT.
        let resp = client
            .put_json(
                &auth_path,
                &json!({"authenticationMethod": "5G_AKA", "encPermanentKey": "zz"}),
            )
            .await
            .expect("PUT bad key");
        assert_eq!(resp.status, 400);
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(problem["cause"], "MANDATORY_IE_INCORRECT");

        // Valid body without a database -> 503 ProblemDetails (fail closed).
        let resp = client
            .put_json(
                &auth_path,
                &json!({
                    "authenticationMethod": "5G_AKA",
                    "encPermanentKey": "00112233445566778899aabbccddeeff",
                    "encOpcKey": "ffeeddccbbaa99887766554433221100",
                    "authenticationManagementField": "8000",
                    "sequenceNumber": {"sqnScheme": "NON_TIME_BASED", "sqn": "000000000020", "indLength": 5}
                }),
            )
            .await
            .expect("PUT valid");
        assert_eq!(resp.status, 503);

        // Invalid servingPlmnId in the PLMN-scoped provisioned-data layout -> 400.
        let resp = client
            .get(&format!(
                "/nudr-dr/v2/subscription-data/{supi}/12a45/provisioned-data/am-data"
            ))
            .await
            .expect("GET bad plmn");
        assert_eq!(resp.status, 400);
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(problem["cause"], "MANDATORY_IE_INCORRECT");

        // Valid PLMN routes through (404 without a subscriber DB, not 400).
        let resp = client
            .get(&format!(
                "/nudr-dr/v2/subscription-data/{supi}/00101/provisioned-data/am-data"
            ))
            .await
            .expect("GET good plmn");
        assert_eq!(resp.status, 404);

        udr.stop().await.expect("udr stops");
    }

    // ------------------------------------------------------------------
    // udrd-01: arp_json / build_sm_data pre-emption fields
    // ------------------------------------------------------------------

    /// TS 29.571 §5.5.3 Arp schema requires priorityLevel + preemptCap +
    /// preemptVuln.  Verify that build_sm_data emits all three and that
    /// the pre-emption mappings are correct:
    ///   pre_emption_capability == 1  → "MAY_PREEMPT"
    ///   pre_emption_vulnerability == 0 → "NOT_PREEMPTABLE"
    #[test]
    fn test_build_sm_data_arp_all_three_fields() {
        use nextgcore_dbi::types::{
            NextgcoreAmbr, NextgcoreArp, NextgcoreQos, NextgcoreSNssai, NextgcoreSession,
            NextgcoreSliceData, NextgcoreSubscriptionData,
        };

        let arp = NextgcoreArp {
            priority_level: 8,
            pre_emption_capability: 1,
            pre_emption_vulnerability: 0,
        };
        let sess = NextgcoreSession {
            name: Some("internet".to_string()),
            session_type: 1, // IPV4
            qos: NextgcoreQos {
                index: 9,
                arp,
                ..Default::default()
            },
            ambr: NextgcoreAmbr {
                uplink: 1_000_000_000,
                downlink: 1_000_000_000,
            },
            ..Default::default()
        };
        let slice = NextgcoreSliceData {
            s_nssai: NextgcoreSNssai::new(1, None),
            session: vec![sess],
            ..Default::default()
        };
        let data = NextgcoreSubscriptionData {
            slice: vec![slice],
            ..Default::default()
        };

        let result = build_sm_data(&data);

        let arr = result.as_array().expect("sm-data is array");
        assert_eq!(arr.len(), 1);
        let arp_val = &arr[0]["dnnConfigurations"]["internet"]["5gQosProfile"]["arp"];

        assert_eq!(arp_val["priorityLevel"], 8_u64, "priorityLevel must be 8");
        assert_eq!(
            arp_val["preemptCap"], "MAY_PREEMPT",
            "capability==1 → MAY_PREEMPT"
        );
        assert_eq!(
            arp_val["preemptVuln"], "NOT_PREEMPTABLE",
            "vulnerability==0 → NOT_PREEMPTABLE"
        );
    }

    /// Complementary case: capability==0 / vulnerability==1 flips both strings.
    #[test]
    fn test_build_sm_data_arp_not_preempt_preemptable() {
        use nextgcore_dbi::types::{
            NextgcoreAmbr, NextgcoreArp, NextgcoreQos, NextgcoreSNssai, NextgcoreSession,
            NextgcoreSliceData, NextgcoreSubscriptionData,
        };

        let arp = NextgcoreArp {
            priority_level: 1,
            pre_emption_capability: 0,
            pre_emption_vulnerability: 1,
        };
        let sess = NextgcoreSession {
            name: Some("ims".to_string()),
            session_type: 3, // IPV4V6
            qos: NextgcoreQos {
                index: 5,
                arp,
                ..Default::default()
            },
            ambr: NextgcoreAmbr {
                uplink: 0,
                downlink: 0,
            },
            ..Default::default()
        };
        let slice = NextgcoreSliceData {
            s_nssai: NextgcoreSNssai::new(1, None),
            session: vec![sess],
            ..Default::default()
        };
        let data = NextgcoreSubscriptionData {
            slice: vec![slice],
            ..Default::default()
        };

        let result = build_sm_data(&data);
        let arr = result.as_array().unwrap();
        let arp_val = &arr[0]["dnnConfigurations"]["ims"]["5gQosProfile"]["arp"];

        assert_eq!(
            arp_val["preemptCap"], "NOT_PREEMPT",
            "capability==0 → NOT_PREEMPT"
        );
        assert_eq!(
            arp_val["preemptVuln"], "PREEMPTABLE",
            "vulnerability==1 → PREEMPTABLE"
        );
    }

    // ------------------------------------------------------------------
    // udrd-02: format_ambr lossless unit selection
    // ------------------------------------------------------------------

    /// TS 29.571 BitRate — exact unit chosen so no precision is lost.
    #[test]
    fn test_format_ambr_precision() {
        // Round values pick the largest exact unit
        assert_eq!(format_ambr(1_000_000_000_000), "1 Tbps");
        assert_eq!(format_ambr(1_000_000_000), "1 Gbps");
        assert_eq!(format_ambr(1_000_000), "1 Mbps");
        assert_eq!(format_ambr(1_000), "1 Kbps");
        assert_eq!(format_ambr(1), "1 bps");
        assert_eq!(format_ambr(0), "0 bps");

        // Non-round values must NOT truncate: drop to next exact unit
        assert_eq!(
            format_ambr(1_500_000_000),
            "1500 Mbps",
            "1.5 Gbps must not truncate to 1 Gbps"
        );
        assert_eq!(
            format_ambr(1_200_000),
            "1200 Kbps",
            "1.2 Mbps must not truncate to 1 Mbps"
        );
        assert_eq!(
            format_ambr(12_345),
            "12345 bps",
            "non-round bps falls through to bps"
        );

        // All outputs must match the TS 29.571 BitRate pattern
        for bps in [
            1u64,
            999,
            1_000,
            1_001,
            1_500_000,
            2_000_000_000,
            5_000_000_000_000,
        ] {
            let s = format_ambr(bps);
            let valid_suffix = s.ends_with(" bps")
                || s.ends_with(" Kbps")
                || s.ends_with(" Mbps")
                || s.ends_with(" Gbps")
                || s.ends_with(" Tbps");
            assert!(valid_suffix, "BitRate pattern violated: {s}");
        }
    }

    // ------------------------------------------------------------------
    // udrd-03: parse_dataset_names
    // ------------------------------------------------------------------

    #[test]
    fn test_parse_dataset_names() {
        // Single name
        let set = parse_dataset_names("AM").unwrap();
        assert!(set.contains("AM"));
        assert!(!set.contains("SM"));

        // Comma-separated, case-insensitive
        let set = parse_dataset_names("AM,SM").unwrap();
        assert!(set.contains("AM"));
        assert!(set.contains("SM"));
        assert!(!set.contains("SMF_SEL"));

        // Mixed case
        let set = parse_dataset_names("smf_sel").unwrap();
        assert!(set.contains("SMF_SEL"));

        // Empty → None
        assert!(parse_dataset_names("").is_none());

        // Whitespace trimming
        let set = parse_dataset_names("AM , SM").unwrap();
        assert!(set.contains("AM"));
        assert!(set.contains("SM"));
    }

    // ------------------------------------------------------------------
    // udrd-06: VarUeId routing
    // ------------------------------------------------------------------

    /// Recognized VarUeId forms that are not DB-backed must return 404,
    /// not 400 INVALID_SUPI.  extgroupid- must return 501.
    /// imsi- and suci- must be unchanged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_varueid_routing() {
        let (udr_listener, udr_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let udr = SbiServer::on_listener(NextgcoreSbiServerConfig::new(udr_addr), udr_listener);
        udr.start(udr_sbi_request_handler)
            .await
            .expect("UDR SBI server starts");
        let client = SbiClient::with_host_port("127.0.0.1", udr_addr.port());

        // imsi- is unchanged (404 when no DB, not 400)
        let resp = client
            .get("/nudr-dr/v2/subscription-data/imsi-001010000000001/authentication-data/authentication-subscription")
            .await
            .expect("GET imsi");
        assert_eq!(resp.status, 404, "imsi- should 404 (no DB), not 400");

        // nai- is a valid VarUeId, returns 404 (not 400 INVALID_SUPI)
        let resp = client
            .get("/nudr-dr/v2/subscription-data/nai-user@example.com/authentication-data/authentication-subscription")
            .await
            .expect("GET nai");
        assert_eq!(resp.status, 404, "nai- should be 404, not 400");
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_ne!(
            problem["cause"], "INVALID_SUPI",
            "nai- must not be rejected as INVALID_SUPI"
        );

        // gci- is a valid VarUeId, returns 404
        let resp = client
            .get("/nudr-dr/v2/subscription-data/gci-001010000000001/authentication-data/authentication-subscription")
            .await
            .expect("GET gci");
        assert_eq!(resp.status, 404, "gci- should be 404");

        // extgroupid- returns 501 Not Implemented
        let resp = client
            .get("/nudr-dr/v2/subscription-data/extgroupid-grp001/authentication-data/authentication-subscription")
            .await
            .expect("GET extgroupid");
        assert_eq!(resp.status, 501, "extgroupid- must return 501");
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(problem["cause"], "NOT_SUPPORTED");

        // Unknown prefix still returns 400 INVALID_SUPI
        let resp = client
            .get("/nudr-dr/v2/subscription-data/bogus-12345/authentication-data/authentication-subscription")
            .await
            .expect("GET bogus");
        assert_eq!(resp.status, 400, "unknown prefix must still be 400");
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(problem["cause"], "INVALID_SUPI");

        udr.stop().await.expect("udr stops");
    }

    // ------------------------------------------------------------------
    // udrd-07: project_fields
    // ------------------------------------------------------------------

    #[test]
    fn test_project_fields_nested() {
        let value = json!({"a": {"b": 1, "c": 2}, "d": 3});

        // Single nested path
        let paths = vec!["/a/b".to_string()];
        let result = project_fields(&value, &paths);
        assert_eq!(result, json!({"a": {"b": 1}}));

        // Two paths at different levels
        let paths = vec!["/a/b".to_string(), "/d".to_string()];
        let result = project_fields(&value, &paths);
        assert_eq!(result, json!({"a": {"b": 1}, "d": 3}));

        // Root path returns whole doc
        let paths = vec!["/".to_string()];
        let result = project_fields(&value, &paths);
        assert_eq!(result, value);

        // Non-existent path silently omitted
        let paths = vec!["/z/y".to_string()];
        let result = project_fields(&value, &paths);
        assert_eq!(result, json!({}));

        // Empty paths → unchanged
        let result = project_fields(&value, &[]);
        assert_eq!(result, value);
    }

    // ------------------------------------------------------------------
    // udrd-08: SQN IND-zeroed normalization
    // ------------------------------------------------------------------

    /// TS 29.505 §5.4.2.23: SQN must have the low 5 (indLength) bits zeroed.
    #[test]
    fn test_sqn_ind_zeroed() {
        let mut info = nextgcore_dbi::subscription::NextgcoreDbiAuthInfo::default();
        // 0x23 = 0b100011 → IND bits [4:0] = 0b00011 = 3 → must be zeroed → 0x20
        info.sqn = 0x23;
        info.use_opc = true;
        let doc = build_auth_subscription_json("imsi-001010000000001", &info);
        let seq = &doc["sequenceNumber"];
        assert_eq!(seq["indLength"], 5);
        let sqn = seq["sqn"].as_str().unwrap();
        assert_eq!(sqn, "000000000020", "IND bits must be zeroed: 0x23 → 0x20");
        // Verify the low 5 bits of the parsed value are zero
        let sqn_val = u64::from_str_radix(sqn, 16).unwrap();
        assert_eq!(sqn_val & 0x1F, 0, "low 5 bits must be zero");
    }

    #[test]
    fn test_sqn_ind_zeroed_already_clean() {
        let mut info = nextgcore_dbi::subscription::NextgcoreDbiAuthInfo::default();
        // 0x20 already has IND bits zeroed → no change
        info.sqn = 0x20;
        info.use_opc = true;
        let doc = build_auth_subscription_json("imsi-001010000000002", &info);
        let sqn = doc["sequenceNumber"]["sqn"].as_str().unwrap();
        assert_eq!(sqn, "000000000020");
    }

    // ------------------------------------------------------------------
    // udrd-10: authenticationMethod defaults to 5G_AKA
    // ------------------------------------------------------------------

    /// NextgcoreDbiAuthInfo does not carry the provisioned authenticationMethod;
    /// the emitted value must default to "5G_AKA" per TS 33.501 §6.1.2.
    #[test]
    fn test_authentication_method_default_5g_aka() {
        let info = nextgcore_dbi::subscription::NextgcoreDbiAuthInfo::default();
        let doc = build_auth_subscription_json("imsi-001010000000001", &info);
        assert_eq!(
            doc["authenticationMethod"].as_str().unwrap(),
            "5G_AKA",
            "default authenticationMethod must be 5G_AKA"
        );
    }

    /// udrd#1: a provisioned non-default authenticationMethod (e.g. EAP_AKA_PRIME)
    /// must be served verbatim, not overwritten with 5G_AKA.
    #[test]
    fn test_authentication_method_served_from_db() {
        let info = nextgcore_dbi::subscription::NextgcoreDbiAuthInfo {
            authentication_method: "EAP_AKA_PRIME".to_string(),
            ..Default::default()
        };
        let doc = build_auth_subscription_json("imsi-001010000000003", &info);
        assert_eq!(
            doc["authenticationMethod"].as_str().unwrap(),
            "EAP_AKA_PRIME",
            "provisioned authenticationMethod must be served verbatim",
        );
    }

    // ------------------------------------------------------------------
    // udrd-12: sscModes derive documented default (SSC_MODE_1/2/3)
    // ------------------------------------------------------------------

    /// TS 29.505 §5.4.4: when no SSC-mode provisioning is in the DB schema,
    /// the default emitted must include SSC_MODE_1/2/3 (matching the legacy
    /// handler at nudr_handler.rs:627).
    #[test]
    fn test_ssc_modes_default() {
        use nextgcore_dbi::types::{
            NextgcoreAmbr, NextgcoreArp, NextgcoreQos, NextgcoreSNssai, NextgcoreSession,
            NextgcoreSliceData, NextgcoreSubscriptionData,
        };
        let sess = NextgcoreSession {
            name: Some("internet".to_string()),
            session_type: 1,
            qos: NextgcoreQos {
                index: 9,
                arp: NextgcoreArp::default(),
                ..Default::default()
            },
            ambr: NextgcoreAmbr {
                uplink: 1_000_000,
                downlink: 1_000_000,
            },
            ..Default::default()
        };
        let data = NextgcoreSubscriptionData {
            slice: vec![NextgcoreSliceData {
                s_nssai: NextgcoreSNssai::new(1, None),
                session: vec![sess],
                ..Default::default()
            }],
            ..Default::default()
        };
        let result = build_sm_data(&data);
        let ssc = &result[0]["dnnConfigurations"]["internet"]["sscModes"];
        assert_eq!(ssc["defaultSscMode"], "SSC_MODE_1");
        let allowed = ssc["allowedSscModes"].as_array().unwrap();
        let modes: Vec<&str> = allowed.iter().filter_map(|v| v.as_str()).collect();
        assert!(modes.contains(&"SSC_MODE_1"), "must include SSC_MODE_1");
        assert!(modes.contains(&"SSC_MODE_2"), "must include SSC_MODE_2");
        assert!(modes.contains(&"SSC_MODE_3"), "must include SSC_MODE_3");
    }

    // ------------------------------------------------------------------
    // udrd-04/05: policy-data HTTP round-trip (store and retrieve)
    // ------------------------------------------------------------------

    /// PUT policy sm-data then GET returns the stored doc (not derived default).
    /// PUT am-data then GET returns stored doc.
    /// PUT ue-policy-set then GET returns stored doc.
    /// With no PUT, GET returns the documented default (derived or `{}`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_policy_data_store_and_retrieve() {
        let (udr, client, listener, _cb_port, _rx) = start_udr_and_listener().await;
        let supi = "imsi-001019900000042";

        // --- am-data ---
        let am_path = format!("/nudr-dr/v2/policy-data/ues/{supi}/am-data");
        // No PUT yet → GET returns {} default
        let resp = client.get(&am_path).await.expect("GET am-data default");
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body, json!({}), "default am-data must be {{}}");

        // PUT → 201 Created
        let am_doc = json!({"suppFeat": "0", "rfsp": 1});
        let resp = client
            .put_json(&am_path, &am_doc)
            .await
            .expect("PUT am-data");
        assert_eq!(resp.status, 201, "first PUT must be 201");

        // GET now returns stored doc
        let resp = client.get(&am_path).await.expect("GET am-data stored");
        assert_eq!(resp.status, 200);
        let got: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(got, am_doc, "GET must return stored am-data");

        // Second PUT → 204 Replace
        let resp = client
            .put_json(&am_path, &am_doc)
            .await
            .expect("PUT am-data replace");
        assert_eq!(resp.status, 204, "second PUT must be 204");

        // --- sm-data ---
        let sm_path = format!("/nudr-dr/v2/policy-data/ues/{supi}/sm-data");
        let sm_doc = json!({"smPolicySnssaiData": {"01": {"snssai": {"sst": 1}}}});
        let resp = client
            .put_json(&sm_path, &sm_doc)
            .await
            .expect("PUT sm-data");
        assert_eq!(resp.status, 201, "first PUT must be 201");
        let resp = client.get(&sm_path).await.expect("GET sm-data");
        assert_eq!(resp.status, 200);
        let got: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(got, sm_doc, "GET must return stored sm-data");

        // --- ue-policy-set ---
        let ue_path = format!("/nudr-dr/v2/policy-data/ues/{supi}/ue-policy-set");
        let ue_doc = json!({"subscPolicySections": {"01": {"upsi": []}}});
        let resp = client
            .put_json(&ue_path, &ue_doc)
            .await
            .expect("PUT ue-policy-set");
        assert_eq!(resp.status, 201, "first PUT must be 201");
        let resp = client.get(&ue_path).await.expect("GET ue-policy-set");
        assert_eq!(resp.status, 200);
        let got: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(got, ue_doc, "GET must return stored ue-policy-set");

        udr.stop().await.expect("udr stops");
        listener.stop().await.expect("listener stops");
    }

    // ------------------------------------------------------------------
    // WSB-6: UDR must store exactly the SQN that is written — no
    // side-effect increments (TS 29.505 PATCH = apply PatchItemList only;
    // TS 33.102 Annex C.3: SQN advancement is the UDM/ARPF function).
    // ------------------------------------------------------------------

    /// Local copy of udmd's SQN advance (nextgcore-udmd main.rs
    /// `advance_sqn_ind`, TS 33.102 Annex C.3.2): SQN = SEQ[47:5] || IND[4:0],
    /// SEQ increments by 1 (one +32 step on the packed value), IND kept,
    /// masked to 48 bits. udmd is a bin-only crate so the function cannot be
    /// linked from here; the arithmetic is replicated verbatim.
    fn udm_advance_sqn_ind(sqn: u64) -> u64 {
        let seq = sqn >> 5;
        let ind = sqn & 0x1F;
        (((seq + 1) << 5) | ind) & 0x0000_FFFF_FFFF_FFFF
    }

    /// Provision an authentication subscription through the REAL PUT handler
    /// (TS 29.505 AuthenticationSubscription shape) and return the auth path.
    async fn wsb6_provision(client: &SbiClient, supi: &str, sqn: u64) -> String {
        let auth_path = format!(
            "/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-subscription"
        );
        let resp = client
            .put_json(
                &auth_path,
                &json!({
                    "authenticationMethod": "5G_AKA",
                    "encPermanentKey": "465b5ce8b199b49faa5f0a2ee238a6bc",
                    "encOpcKey": "e8ed289deba952e4283b54e88e6183ca",
                    "authenticationManagementField": "8000",
                    "sequenceNumber": {
                        "sqnScheme": "NON_TIME_BASED",
                        "sqn": format!("{sqn:012x}"),
                        "indLength": 5
                    }
                }),
            )
            .await
            .expect("PUT provision");
        assert_eq!(resp.status, 201, "provisioning PUT must create (201)");
        assert_eq!(
            nextgcore_dbi::test_store::stored_sqn(supi),
            Some(sqn),
            "provisioned SQN must be stored exactly"
        );
        auth_path
    }

    // ------------------------------------------------------------------
    // #86 secondary: PATCH reports failures, authentication-status persists
    // ------------------------------------------------------------------

    /// Spin up the UDR SBI server and return a client for it.
    async fn start_udr() -> (SbiServer, SbiClient) {
        let (addr_listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let udr = SbiServer::on_listener(NextgcoreSbiServerConfig::new(addr), addr_listener);
        udr.start(udr_sbi_request_handler)
            .await
            .expect("UDR SBI server starts");
        let client = SbiClient::with_host_port("127.0.0.1", addr.port());
        (udr, client)
    }

    /// A malformed / non-array / empty PATCH body must be REJECTED, not
    /// acknowledged with 204. Previously every one of these fell through to
    /// `SbiResponse::with_status(204)`, so a consumer could not tell an applied
    /// patch from a silently discarded one (TS 29.505 §5.2.2.x, TS 29.500
    /// §5.2.7 ProblemDetails).
    #[tokio::test]
    async fn patch_auth_subscription_rejects_unusable_bodies() {
        let _store = DbiTestStore::enable().await;
        let (_udr, client) = start_udr().await;
        let supi = "imsi-999990000000861";
        let auth_path = wsb6_provision(&client, supi, 0x40).await;

        // Not JSON at all. Built directly because patch_json would serialise
        // the string INTO valid JSON, which is not the case under test.
        let resp = client
            .send_request(SbiRequest::patch(&auth_path).with_body("not json", "application/json"))
            .await
            .expect("PATCH garbage");
        assert_eq!(resp.status, 400, "a non-JSON body must be 400, never 204");

        // Valid JSON but not an array of PatchItem.
        let resp = client
            .patch_json(&auth_path, &json!({"op": "replace"}))
            .await
            .expect("PATCH object");
        assert_eq!(resp.status, 400, "a non-array body must be 400");

        // Empty array: PatchResult.report is minItems 1, so an empty patch list
        // can be reported neither as success nor as a failure item.
        let resp = client
            .patch_json(&auth_path, &json!([]))
            .await
            .expect("PATCH empty");
        assert_eq!(resp.status, 400, "an empty PatchItem array must be 400");

        // None of the rejected requests may have altered the stored SQN.
        assert_eq!(
            nextgcore_dbi::test_store::stored_sqn(supi),
            Some(0x40),
            "a rejected PATCH must not change stored state"
        );
    }

    /// An unsupported patch path is reported in a PatchResult rather than
    /// silently dropped, and the reason names the failing operation index as
    /// TS 29.571 ReportItem recommends.
    #[tokio::test]
    async fn patch_auth_subscription_reports_unsupported_path() {
        let _store = DbiTestStore::enable().await;
        let (_udr, client) = start_udr().await;
        let supi = "imsi-999990000000862";
        let auth_path = wsb6_provision(&client, supi, 0x40).await;

        let resp = client
            .patch_json(
                &auth_path,
                &json!([{"op": "replace", "path": "/encPermanentKey", "value": "00"}]),
            )
            .await
            .expect("PATCH unsupported path");
        assert_eq!(resp.status, 400);
        let doc: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let report = doc["report"].as_array().expect("PatchResult.report array");
        assert_eq!(report.len(), 1);
        assert_eq!(report[0]["path"], "/encPermanentKey");
        assert!(
            report[0]["reason"].as_str().unwrap().contains("index= 0"),
            "reason should identify the failed operation index (TS 29.571)"
        );
    }

    /// A non-hex SQN must be REJECTED, leaving the stored value untouched.
    ///
    /// This is the silent-corruption case: the old handler did
    /// `u64::from_str_radix(sqn_hex, 16).unwrap_or(0)`, so "zzzz" became SQN 0
    /// -- a valid-looking sequence number written over good data, reported as
    /// 204 success.
    #[tokio::test]
    async fn patch_auth_subscription_rejects_non_hex_sqn_without_corrupting() {
        let _store = DbiTestStore::enable().await;
        let (_udr, client) = start_udr().await;
        let supi = "imsi-999990000000863";
        let auth_path = wsb6_provision(&client, supi, 0x40).await;

        let resp = client
            .patch_json(
                &auth_path,
                &json!([{"op": "replace", "path": "/sequenceNumber/sqn", "value": "zzzz"}]),
            )
            .await
            .expect("PATCH non-hex");
        assert_eq!(resp.status, 400, "a non-hex SQN must be 400, never 204");
        assert_eq!(
            nextgcore_dbi::test_store::stored_sqn(supi),
            Some(0x40),
            "the stored SQN must be UNCHANGED -- unwrap_or(0) used to write 0 here"
        );

        // Beyond the 48-bit SQN range (TS 33.102) is likewise rejected, not
        // truncated.
        let resp = client
            .patch_json(
                &auth_path,
                &json!([{"op": "replace", "path": "/sequenceNumber/sqn",
                         "value": "1000000000000"}]),
            )
            .await
            .expect("PATCH oversized");
        assert_eq!(resp.status, 400);
        assert_eq!(nextgcore_dbi::test_store::stored_sqn(supi), Some(0x40));
    }

    /// PUT stores the AuthEvent and GET serves it back; previously the body was
    /// acknowledged with 204 and DISCARDED, and GET fell through to 405
    /// (TS 29.505 authentication-status, TS 29.503 AuthEvent, TS 33.501
    /// §6.1.4 result storage).
    #[tokio::test]
    async fn auth_status_put_get_delete_roundtrip() {
        let _store = DbiTestStore::enable().await;
        let (_udr, client) = start_udr().await;
        let supi = "imsi-999990000000864";
        let base = format!(
            "/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-status"
        );

        // Nothing stored yet: 404 DATA_NOT_FOUND, NOT 405 method-not-allowed.
        let resp = client.get(&base).await.expect("GET empty");
        assert_eq!(
            resp.status, 404,
            "GET must be a defined operation returning 404 when absent, not 405"
        );

        let event = json!({
            "nfInstanceId": "b2c3d4e5-0000-4000-8000-000000000001",
            "success": true,
            "timeStamp": "2026-08-08T12:00:00Z",
            "authType": "5G_AKA",
            "servingNetworkName": "5G:mnc099.mcc999.3gppnetwork.org"
        });
        // TS 29.505 defines ONLY 204 for a successful PUT on this resource --
        // no 201 -- unlike smf-registrations, which does define 201 Created.
        let resp = client.put_json(&base, &event).await.expect("PUT event");
        assert_eq!(
            resp.status, 204,
            "PUT success on auth-status is 204, never 201"
        );

        // GET returns the stored AuthEvent verbatim.
        let resp = client.get(&base).await.expect("GET stored");
        assert_eq!(resp.status, 200);
        let doc: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(doc["nfInstanceId"], event["nfInstanceId"]);
        assert_eq!(doc["authType"], "5G_AKA");
        assert_eq!(doc["success"], true);

        // Re-PUT replaces, also 204.
        let resp = client.put_json(&base, &event).await.expect("PUT again");
        assert_eq!(resp.status, 204, "replacing an existing resource is 204");

        // DELETE removes it; a second GET is 404 again.
        let resp = client.delete(&base).await.expect("DELETE");
        assert_eq!(resp.status, 204);
        let resp = client.get(&base).await.expect("GET after delete");
        assert_eq!(resp.status, 404);
    }

    /// A PUT missing any required AuthEvent attribute is rejected.
    #[tokio::test]
    async fn auth_status_put_rejects_missing_required_ie() {
        let _store = DbiTestStore::enable().await;
        let (_udr, client) = start_udr().await;
        let supi = "imsi-999990000000865";
        let base = format!(
            "/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-status"
        );

        // authType omitted (TS 29.503 AuthEvent requires it).
        let resp = client
            .put_json(
                &base,
                &json!({
                    "nfInstanceId": "b2c3d4e5-0000-4000-8000-000000000002",
                    "success": true,
                    "timeStamp": "2026-08-08T12:00:00Z",
                    "servingNetworkName": "5G:mnc099.mcc999.3gppnetwork.org"
                }),
            )
            .await
            .expect("PUT incomplete");
        assert_eq!(resp.status, 400);
        // And nothing was stored.
        let resp = client.get(&base).await.expect("GET after reject");
        assert_eq!(resp.status, 404);
    }

    /// The individual `.../{servingNetworkName}` form keys independently, so two
    /// serving networks coexist for one SUPI and the collection GET returns the
    /// most recent.
    #[tokio::test]
    async fn auth_status_individual_form_keys_per_serving_network() {
        let _store = DbiTestStore::enable().await;
        let (_udr, client) = start_udr().await;
        let supi = "imsi-999990000000866";
        let base = format!(
            "/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-status"
        );
        let snn_a = "5G:mnc001.mcc001.3gppnetwork.org";
        let snn_b = "5G:mnc002.mcc002.3gppnetwork.org";

        let ev = |snn: &str, ok: bool| {
            json!({
                "nfInstanceId": "b2c3d4e5-0000-4000-8000-000000000003",
                "success": ok,
                "timeStamp": "2026-08-08T12:00:00Z",
                "authType": "5G_AKA",
                "servingNetworkName": snn
            })
        };

        let resp = client
            .put_json(&format!("{base}/{snn_a}"), &ev(snn_a, true))
            .await
            .expect("PUT A");
        assert_eq!(resp.status, 204);
        let resp = client
            .put_json(&format!("{base}/{snn_b}"), &ev(snn_b, false))
            .await
            .expect("PUT B");
        assert_eq!(
            resp.status, 204,
            "a different serving network is a distinct resource, still 204"
        );

        // Each is retrievable independently.
        let resp = client.get(&format!("{base}/{snn_a}")).await.expect("GET A");
        assert_eq!(resp.status, 200);
        let doc: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(doc["success"], true);
        assert_eq!(doc["servingNetworkName"], snn_a);

        let resp = client.get(&format!("{base}/{snn_b}")).await.expect("GET B");
        assert_eq!(resp.status, 200);
        let doc: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(doc["success"], false);

        // Collection GET yields the most recently stored one (B).
        let resp = client.get(&base).await.expect("GET collection");
        assert_eq!(resp.status, 200);
        let doc: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(doc["servingNetworkName"], snn_b);

        // A body whose servingNetworkName disagrees with the URI is rejected,
        // so the stored key can never contradict the URI used to GET it.
        let resp = client
            .put_json(&format!("{base}/{snn_a}"), &ev(snn_b, true))
            .await
            .expect("PUT mismatched");
        assert_eq!(resp.status, 400);

        // Deleting one leaves the other.
        let resp = client
            .delete(&format!("{base}/{snn_a}"))
            .await
            .expect("DELETE A");
        assert_eq!(resp.status, 204);
        let resp = client
            .get(&format!("{base}/{snn_b}"))
            .await
            .expect("GET B after deleting A");
        assert_eq!(resp.status, 200);
    }

    /// WSB-6 acceptance test: PATCH /sequenceNumber/sqn = X through the real
    /// SBI server + router + handler → the stored SQN is EXACTLY X (the old
    /// PATCH arm corrupted it to X+32 via an unconditional SQN increment).
    /// Reintroducing the increment makes this test fail.
    #[tokio::test]
    async fn wsb6_patch_stores_exact_sqn_no_side_effect() {
        let _store = DbiTestStore::enable().await;
        let (udr_listener, udr_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let udr = SbiServer::on_listener(NextgcoreSbiServerConfig::new(udr_addr), udr_listener);
        udr.start(udr_sbi_request_handler)
            .await
            .expect("UDR SBI server starts");
        let client = SbiClient::with_host_port("127.0.0.1", udr_addr.port());
        let supi = "imsi-999990000000601";
        let auth_path = wsb6_provision(&client, supi, 0x20).await;

        // udmd-shaped PATCH body — byte-identical PatchItemList to
        // udm_nudr_dr_send_auth_subscription_patch (nextgcore-udmd
        // sbi_path.rs): [{"op":"replace","path":"/sequenceNumber/sqn",...}].
        let x: u64 = 0x2020; // IND bits zero, so the served form is exact too
        let resp = client
            .patch_json(
                &auth_path,
                &json!([{
                    "op": "replace",
                    "path": "/sequenceNumber/sqn",
                    "value": format!("{x:012x}")
                }]),
            )
            .await
            .expect("PATCH sqn");
        assert_eq!(resp.status, 204);

        // Stored value must be exactly X — not X+32.
        assert_eq!(
            nextgcore_dbi::test_store::stored_sqn(supi),
            Some(x),
            "UDR must store exactly the PATCHed SQN (TS 29.505); +32 means the \
             WSB-6 side-effect increment was reintroduced"
        );

        // And the real GET handler serves it back exactly.
        let resp = client.get(&auth_path).await.expect("GET auth-subscription");
        assert_eq!(resp.status, 200);
        let doc: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(doc["sequenceNumber"]["sqn"], format!("{x:012x}"));

        udr.stop().await.expect("udr stops");
    }

    /// WSB-6: the authentication-status PUT/DELETE arm must have NO SQN side
    /// effect (it previously incremented by +32 on every UDM confirmation).
    #[tokio::test]
    async fn wsb6_auth_status_put_delete_no_sqn_side_effect() {
        let _store = DbiTestStore::enable().await;
        let (udr_listener, udr_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let udr = SbiServer::on_listener(NextgcoreSbiServerConfig::new(udr_addr), udr_listener);
        udr.start(udr_sbi_request_handler)
            .await
            .expect("UDR SBI server starts");
        let client = SbiClient::with_host_port("127.0.0.1", udr_addr.port());
        let supi = "imsi-999990000000602";
        let s0: u64 = 0x40;
        wsb6_provision(&client, supi, s0).await;
        let status_path = format!(
            "/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-status"
        );

        // TS 29.503 AuthEvent body, as udmd PUTs it on auth confirmation
        // (udm_nudr_dr_send_auth_status_put passes the AUSF body verbatim).
        let resp = client
            .put_json(
                &status_path,
                &json!({
                    "nfInstanceId": "6874ed4b-262c-4a53-a8a4-e846a41ad0e8",
                    "success": true,
                    "timeStamp": "2026-07-01T00:00:00Z",
                    "authType": "5G_AKA",
                    "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org"
                }),
            )
            .await
            .expect("PUT auth-status");
        assert_eq!(resp.status, 204);
        assert_eq!(
            nextgcore_dbi::test_store::stored_sqn(supi),
            Some(s0),
            "auth-status PUT must not advance the stored SQN"
        );

        let resp = client
            .delete(&status_path)
            .await
            .expect("DELETE auth-status");
        assert_eq!(resp.status, 204);
        assert_eq!(
            nextgcore_dbi::test_store::stored_sqn(supi),
            Some(s0),
            "auth-status DELETE must not advance the stored SQN"
        );

        udr.stop().await.expect("udr stops");
    }

    /// WSB-6 strict-peer sequence: emulate udmd's generate-AV flow (GET →
    /// client-side advance_sqn_ind → PATCH exact value → auth-status PUT on
    /// confirmation) N times against the REAL udrd handler stack. The stored
    /// SQN must advance EXACTLY one SEQ step per AV (previously 3: udmd's
    /// intended advance + PATCH-side +32 + auth-status +32). Includes one
    /// AUTS-resync iteration (TS 33.102 §6.3.5: resume from SQN_MS+1, then
    /// one advance) whose exact value — including nonzero IND bits — must be
    /// stored verbatim.
    #[tokio::test]
    async fn wsb6_udm_av_flow_advances_sqn_one_step_per_av() {
        let _store = DbiTestStore::enable().await;
        let (udr_listener, udr_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let udr = SbiServer::on_listener(NextgcoreSbiServerConfig::new(udr_addr), udr_listener);
        udr.start(udr_sbi_request_handler)
            .await
            .expect("UDR SBI server starts");
        let client = SbiClient::with_host_port("127.0.0.1", udr_addr.port());
        let supi = "imsi-999990000000603";
        let s0: u64 = 0x20;
        let auth_path = wsb6_provision(&client, supi, s0).await;
        let status_path = format!(
            "/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-status"
        );
        let auth_event = json!({
            "nfInstanceId": "6874ed4b-262c-4a53-a8a4-e846a41ad0e8",
            "success": true,
            "timeStamp": "2026-07-01T00:00:00Z",
            "authType": "5G_AKA",
            "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org"
        });

        const N: u32 = 3;
        for _ in 0..N {
            // udmd reads the served SQN (GET), advances it client-side per
            // TS 33.102 C.3.2 and PATCHes the advanced value (udmd main.rs
            // step 6), then PUTs the AuthEvent on confirmation.
            let resp = client.get(&auth_path).await.expect("GET auth-subscription");
            assert_eq!(resp.status, 200);
            let doc: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            let served =
                u64::from_str_radix(doc["sequenceNumber"]["sqn"].as_str().expect("sqn hex"), 16)
                    .expect("sqn parses");
            let advanced = udm_advance_sqn_ind(served);
            let resp = client
                .patch_json(
                    &auth_path,
                    &json!([{
                        "op": "replace",
                        "path": "/sequenceNumber/sqn",
                        "value": format!("{advanced:012x}")
                    }]),
                )
                .await
                .expect("PATCH sqn");
            assert_eq!(resp.status, 204);
            let resp = client
                .put_json(&status_path, &auth_event)
                .await
                .expect("PUT auth-status");
            assert_eq!(resp.status, 204);
        }

        // Exactly one SEQ step (+32) per AV — nothing more.
        assert_eq!(
            nextgcore_dbi::test_store::stored_sqn(supi),
            Some(s0 + u64::from(N) * 32),
            "stored SQN must advance exactly one advance_sqn_ind step per AV"
        );

        // AUTS resync iteration: udmd resumes from SQN_MS+1 (main.rs resync
        // branch), then step 6 advances once and PATCHes; the exact value —
        // IND bits included — must be stored verbatim.
        let sqn_ms: u64 = 0xA0C5; // nonzero IND (5)
        let resync_next = udm_advance_sqn_ind((sqn_ms + 1) & 0x0000_FFFF_FFFF_FFFF);
        let resp = client
            .patch_json(
                &auth_path,
                &json!([{
                    "op": "replace",
                    "path": "/sequenceNumber/sqn",
                    "value": format!("{resync_next:012x}")
                }]),
            )
            .await
            .expect("PATCH resync sqn");
        assert_eq!(resp.status, 204);
        let resp = client
            .put_json(&status_path, &auth_event)
            .await
            .expect("PUT auth-status after resync");
        assert_eq!(resp.status, 204);
        assert_eq!(
            nextgcore_dbi::test_store::stored_sqn(supi),
            Some(resync_next),
            "resynchronized SQN must be stored exactly (IND bits preserved, \
             no +32 corruption)"
        );

        udr.stop().await.expect("udr stops");
    }

    // ========================================================================
    // #87: the TS 29.505 / 29.519 / 29.504 resources that answered 404 or 405.
    // ========================================================================

    fn json_of(resp: &SbiResponse) -> serde_json::Value {
        serde_json::from_str(resp.http.content.as_deref().unwrap_or("null"))
            .unwrap_or(serde_json::Value::Null)
    }

    fn amf_reg(instance: &str, non_3gpp: bool) -> serde_json::Value {
        let mut doc = json!({
            "amfInstanceId": instance,
            "deregCallbackUri": format!("http://{instance}/dereg"),
            "guami": { "plmnId": { "mcc": "001", "mnc": "01" }, "amfId": "cafe00" },
            "ratType": if non_3gpp { "VIRTUAL" } else { "NR" }
        });
        if non_3gpp {
            doc["imsVoPs"] = json!("HOMOGENEOUS_NON_SUPPORT");
        }
        doc
    }

    /// #87 gap 1: `amf-non-3gpp-access` is its own resource. It returned 404, so
    /// non-3GPP registration state could not be stored at all — and the UDM
    /// producer added in #84 writes exactly here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_amf_non_3gpp_access_round_trip() {
        let (udr, client, _listener, _cb_port, _rx) = start_udr_and_listener().await;
        let supi = "imsi-001019900008701";
        let three = format!("/nudr-dr/v2/subscription-data/{supi}/context-data/amf-3gpp-access");
        let non3 = format!("/nudr-dr/v2/subscription-data/{supi}/context-data/amf-non-3gpp-access");

        // Register over 3GPP first, so the assertions below can prove the two
        // resources are independent rather than aliases.
        let resp = client
            .put_json(&three, &amf_reg("amf-3gpp", false))
            .await
            .expect("PUT 3gpp");
        assert_eq!(resp.status, 201);

        // The non-3GPP schema additionally requires imsVoPs.
        let resp = client
            .put_json(&non3, &amf_reg("amf-n3", false))
            .await
            .expect("PUT non-3gpp without imsVoPs");
        assert_eq!(resp.status, 400);
        assert_eq!(json_of(&resp)["cause"], "MANDATORY_IE_MISSING");

        let doc = amf_reg("amf-n3", true);
        let resp = client.put_json(&non3, &doc).await.expect("PUT non-3gpp");
        assert_eq!(
            resp.status, 201,
            "amf-non-3gpp-access must be stored, not 404: {:?}",
            resp.http.content
        );
        assert_eq!(
            resp.http.get_header("Location").map(String::as_str),
            Some(non3.as_str())
        );

        let resp = client.get(&non3).await.expect("GET non-3gpp");
        assert_eq!(resp.status, 200);
        assert_eq!(json_of(&resp), doc, "round-trip equality");

        // The 3GPP registration is untouched by the non-3GPP one.
        let resp = client.get(&three).await.expect("GET 3gpp");
        assert_eq!(resp.status, 200);
        assert_eq!(json_of(&resp)["amfInstanceId"], "amf-3gpp");

        // PATCH and DELETE address only the addressed access.
        let resp = client
            .patch_json(&non3, &json!({"pei": "imeisv-1234567890123456"}))
            .await
            .expect("PATCH non-3gpp");
        assert_eq!(resp.status, 204);
        let resp = client.get(&non3).await.expect("GET after PATCH");
        assert_eq!(json_of(&resp)["pei"], "imeisv-1234567890123456");

        let resp = client.delete(&non3).await.expect("DELETE non-3gpp");
        assert_eq!(resp.status, 204);
        let resp = client.get(&non3).await.expect("GET after DELETE");
        assert_eq!(resp.status, 404);
        let resp = client
            .get(&three)
            .await
            .expect("GET 3gpp after non-3gpp delete");
        assert_eq!(
            resp.status, 200,
            "deleting the non-3GPP registration must not delete the 3GPP one"
        );

        udr.stop().await.expect("stop");
    }

    /// #87 gap 1: the `smf-registrations` PUT owes a `Location` header and the
    /// created representation, and PATCH must not be a 405.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_smf_registration_put_location_body_and_patch() {
        let (udr, client, _listener, _cb, _rx) = start_udr_and_listener().await;
        let supi = "imsi-001019900008702";
        let path = format!("/nudr-dr/v2/subscription-data/{supi}/context-data/smf-registrations/5");
        let doc = json!({
            "smfInstanceId": "smf-1",
            "pduSessionId": 5,
            "singleNssai": { "sst": 1, "sd": "000001" },
            "dnn": "internet",
            "plmnId": { "mcc": "001", "mnc": "01" }
        });

        let resp = client.put_json(&path, &doc).await.expect("PUT");
        assert_eq!(resp.status, 201);
        assert_eq!(
            resp.http.get_header("Location").map(String::as_str),
            Some(path.as_str()),
            "TS 29.505 requires Location on the 201"
        );
        assert_eq!(
            json_of(&resp)["smfInstanceId"],
            "smf-1",
            "the 201 must carry the created SmfRegistration"
        );

        // PATCH was a flat 405.
        let resp = client
            .patch_json(
                &path,
                &json!([{"op": "replace", "path": "/dnn", "value": "ims"}]),
            )
            .await
            .expect("PATCH");
        assert_eq!(
            resp.status, 204,
            "PATCH must be accepted: {:?}",
            resp.http.content
        );
        let resp = client.get(&path).await.expect("GET after PATCH");
        assert_eq!(json_of(&resp)["dnn"], "ims");

        // The id in the URI owns the resource: a patch cannot move it.
        let resp = client
            .patch_json(
                &path,
                &json!([{"op": "replace", "path": "/pduSessionId", "value": 9}]),
            )
            .await
            .expect("PATCH psi");
        assert_eq!(resp.status, 400, "pduSessionId is not patchable");

        udr.stop().await.expect("stop");
    }

    /// #87 gap 2: the remaining per-UE context documents and collections.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_context_data_smsf_ipsmgw_and_subscription_collections() {
        let (udr, client, _listener, _cb, _rx) = start_udr_and_listener().await;
        let supi = "imsi-001019900008703";
        let ctx = |r: &str| format!("/nudr-dr/v2/subscription-data/{supi}/context-data/{r}");

        for (resource, doc) in [
            (
                "smsf-3gpp-access",
                json!({"smsfInstanceId": "smsf-1", "plmnId": {"mcc": "001", "mnc": "01"}}),
            ),
            (
                "smsf-non-3gpp-access",
                json!({"smsfInstanceId": "smsf-2", "plmnId": {"mcc": "001", "mnc": "01"}}),
            ),
            ("ip-sm-gw", json!({"ipsmgwFqdn": "ipsmgw.example.org"})),
        ] {
            let path = ctx(resource);
            let resp = client.get(&path).await.expect("GET before");
            assert_eq!(resp.status, 404, "{resource} unprovisioned");
            let resp = client.put_json(&path, &doc).await.expect("PUT");
            assert_eq!(resp.status, 201, "{resource} PUT: {:?}", resp.http.content);
            let resp = client.get(&path).await.expect("GET after");
            assert_eq!(resp.status, 200);
            assert_eq!(json_of(&resp), doc, "{resource} round-trip");
            let resp = client.delete(&path).await.expect("DELETE");
            assert_eq!(resp.status, 204);
        }

        // sdm-subscriptions / ee-subscriptions collections.
        for resource in ["sdm-subscriptions", "ee-subscriptions"] {
            let member = format!("{}/sub-1", ctx(resource));
            let doc = json!({"nfInstanceId": "nf-1", "callbackReference": "http://nf/cb"});
            let resp = client.put_json(&member, &doc).await.expect("PUT member");
            assert_eq!(resp.status, 201, "{resource} member PUT");
            let resp = client.get(&ctx(resource)).await.expect("GET collection");
            assert_eq!(resp.status, 200);
            assert_eq!(
                json_of(&resp),
                json!([doc]),
                "{resource} collection lists this UE's members"
            );
            let resp = client.delete(&member).await.expect("DELETE member");
            assert_eq!(resp.status, 204);
            let resp = client.get(&member).await.expect("GET after delete");
            assert_eq!(resp.status, 404);
        }

        udr.stop().await.expect("stop");
    }

    /// #85's producers need these: the Parameter Provision documents and the
    /// identity translation the UDM reads.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_pp_data_and_identity_data() {
        let (udr, client, _listener, _cb, _rx) = start_udr_and_listener().await;
        let supi = "imsi-001019900008704";

        // pp-data: PATCH provisions (an absent document starts empty), GET reads.
        let pp = format!("/nudr-dr/v2/subscription-data/{supi}/pp-data");
        let resp = client.get(&pp).await.expect("GET pp-data");
        assert_eq!(resp.status, 404, "nothing provisioned yet");
        let resp = client
            .patch_json(
                &pp,
                &json!({"expectedUeBehaviourParameters": {"stationaryIndication": "STATIONARY"}}),
            )
            .await
            .expect("PATCH pp-data");
        assert_eq!(
            resp.status, 204,
            "PATCH provisions: {:?}",
            resp.http.content
        );
        let resp = client.get(&pp).await.expect("GET pp-data after");
        assert_eq!(resp.status, 200);
        assert_eq!(
            json_of(&resp)["expectedUeBehaviourParameters"]["stationaryIndication"],
            "STATIONARY"
        );

        // pp-data-store: one document per AF instance.
        let entry = format!("/nudr-dr/v2/subscription-data/{supi}/pp-data-store/af-1");
        let doc =
            json!({"communicationCharacteristics": {"ppSubsRegTimer": {"subsRegTimer": 3600}}});
        let resp = client.put_json(&entry, &doc).await.expect("PUT entry");
        assert_eq!(resp.status, 201);
        let resp = client.get(&entry).await.expect("GET entry");
        assert_eq!(json_of(&resp), doc);
        let resp = client
            .get(&format!(
                "/nudr-dr/v2/subscription-data/{supi}/pp-data-store"
            ))
            .await
            .expect("GET entries");
        assert_eq!(json_of(&resp), json!([doc]));

        // identity-data, BOTH directions, against the subscriber-identity mirror
        // (no MongoDB): the GPSI -> SUPI direction is what a NEF needs and what
        // the UDM's id-translation-result reads.
        //
        // The DbiTestStore guard is mandatory rather than a nicety: the mirror is
        // process-global and its `disable()` is a kill switch, so provisioning it
        // without the lock races every other test that has it enabled -- which is
        // exactly the flake this comment replaced.
        let _dbi = DbiTestStore::enable().await;
        let gpsi_digits = "491721075400";
        nextgcore_dbi::test_store::provision_subscriber(supi, &[gpsi_digits]);
        for id in [supi.to_string(), format!("msisdn-{gpsi_digits}")] {
            let resp = client
                .get(&format!("/nudr-dr/v2/subscription-data/{id}/identity-data"))
                .await
                .expect("GET identity-data");
            assert_eq!(
                resp.status, 200,
                "identity-data must resolve {id}: {:?}",
                resp.http.content
            );
            let doc = json_of(&resp);
            assert_eq!(doc["supiList"], json!([supi]), "supiList for {id}");
            assert_eq!(
                doc["gpsiList"],
                json!([format!("msisdn-{gpsi_digits}")]),
                "gpsiList for {id}"
            );
        }
        // An identifier no subscriber holds is a 404, never a guessed SUPI.
        let resp = client
            .get("/nudr-dr/v2/subscription-data/msisdn-000000000000/identity-data")
            .await
            .expect("GET unknown identity-data");
        assert_eq!(resp.status, 404);

        udr.stop().await.expect("stop");
    }

    /// #87 gap 3: policy-data PATCH, the snssai/dnn filter, the documents that
    /// were absent, and a subs-to-notify round trip.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_policy_data_patch_filter_and_notify() {
        let (udr, client, listener, cb_port, mut rx) = start_udr_and_listener().await;
        let supi = "imsi-001019900008705";
        let ues = |r: &str| format!("/nudr-dr/v2/policy-data/ues/{supi}/{r}");

        // --- subs-to-notify: the tree a PCF subscribes on (was absent) -------
        let cb_uri = format!("http://127.0.0.1:{cb_port}/cb/policy-change");
        let resp = client
            .post_json(
                "/nudr-dr/v2/policy-data/subs-to-notify",
                &json!({"notificationUri": cb_uri, "monitoredResourceUris": [ues("am-data")]}),
            )
            .await
            .expect("POST policy sub");
        assert_eq!(resp.status, 201, "policy subs-to-notify must exist");
        let sub_loc = resp.http.get_header("Location").expect("Location").clone();
        assert!(sub_loc.contains("/policy-data/subs-to-notify/"));
        // Mandatory members are enforced.
        let resp = client
            .post_json(
                "/nudr-dr/v2/policy-data/subs-to-notify",
                &json!({"notificationUri": cb_uri}),
            )
            .await
            .expect("POST bad sub");
        assert_eq!(resp.status, 400);

        // --- PATCH on am-data (was 405) + the notification -------------------
        let resp = client
            .patch_json(&ues("am-data"), &json!({"praInfos": {}}))
            .await
            .expect("PATCH am-data");
        assert_eq!(resp.status, 204, "am-data PATCH must be accepted");
        let (path, body) = recv_notification(&mut rx).await;
        assert!(path.contains("/cb/policy-change"), "notified at {path}");
        assert_eq!(body["ueId"], supi);
        assert_eq!(
            body["reportId"],
            ues("am-data"),
            "the notification names the changed resource: {body}"
        );

        // --- ue-policy-set PATCH (was 405) -----------------------------------
        let resp = client
            .patch_json(&ues("ue-policy-set"), &json!({"subscPolicySections": {}}))
            .await
            .expect("PATCH ue-policy-set");
        assert_eq!(resp.status, 204);

        // --- sm-data: PATCH, then the snssai/dnn filter ----------------------
        let sm_doc = json!({
            "smPolicySnssaiData": {
                "01-000001": {
                    "snssai": {"sst": 1, "sd": "000001"},
                    "smPolicyDnnData": {
                        "internet": {"dnn": "internet"},
                        "ims": {"dnn": "ims"}
                    }
                },
                "02": {
                    "snssai": {"sst": 2},
                    "smPolicyDnnData": {"iot": {"dnn": "iot"}}
                }
            }
        });
        let resp = client
            .put_json(&ues("sm-data"), &sm_doc)
            .await
            .expect("PUT sm-data");
        assert_eq!(resp.status, 201);

        // Unfiltered: the whole document (unchanged behaviour).
        let resp = client.get(&ues("sm-data")).await.expect("GET sm-data");
        assert_eq!(json_of(&resp), sm_doc);

        // Filtered by snssai: only that slice. The two provisioned slices differ,
        // so returning the whole document would fail this.
        // The JSON Snssai is percent-encoded, as a query value carrying `{`/`"`
        // must be (RFC 3986 §3.4) -- the UDR pct-decodes it.
        let resp = client
            .get(&format!("{}?snssai=%7B%22sst%22%3A2%7D", ues("sm-data")))
            .await
            .expect("GET sm-data sst=2");
        assert_eq!(resp.status, 200);
        let doc = json_of(&resp);
        assert_eq!(
            doc["smPolicySnssaiData"].as_object().map(|o| o.len()),
            Some(1),
            "exactly the requested slice: {doc}"
        );
        assert!(doc["smPolicySnssaiData"]["02"].is_object());

        // Filtered by snssai + dnn: only that DNN within that slice.
        let resp = client
            .get(&format!(
                "{}?snssai=%7B%22sst%22%3A1%2C%22sd%22%3A%22000001%22%7D&dnn=ims",
                ues("sm-data")
            ))
            .await
            .expect("GET sm-data filtered");
        assert_eq!(resp.status, 200);
        let doc = json_of(&resp);
        let dnns = doc["smPolicySnssaiData"]["01-000001"]["smPolicyDnnData"]
            .as_object()
            .expect("smPolicyDnnData")
            .clone();
        assert_eq!(dnns.len(), 1, "only the requested DNN: {doc}");
        assert!(dnns.contains_key("ims"));

        // A filter that selects nothing is a 404, not an empty SmPolicyData a
        // PCF would install as "no policy applies".
        let resp = client
            .get(&format!("{}?snssai=%7B%22sst%22%3A9%7D", ues("sm-data")))
            .await
            .expect("GET sm-data sst=9");
        assert_eq!(resp.status, 404);

        // --- the documents that had no route at all --------------------------
        let usage_mon = format!("{}/um-1", ues("sm-data"));
        let resp = client
            .put_json(
                &usage_mon,
                &json!({"limitId": "um-1", "umLevel": "SESSION_LEVEL"}),
            )
            .await
            .expect("PUT usageMonId");
        assert_eq!(resp.status, 201, "sm-data/{{usageMonId}} must be routed");
        let resp = client.get(&usage_mon).await.expect("GET usageMonId");
        assert_eq!(json_of(&resp)["limitId"], "um-1");

        let plmn = "/nudr-dr/v2/policy-data/plmns/00101/ue-policy-set";
        let resp = client
            .put_json(plmn, &json!({"upsis": ["upsi-1"]}))
            .await
            .expect("PUT plmn ue-policy-set");
        assert_eq!(resp.status, 201);
        let resp = client.get(plmn).await.expect("GET plmn ue-policy-set");
        assert_eq!(json_of(&resp)["upsis"], json!(["upsi-1"]));
        let resp = client
            .get("/nudr-dr/v2/policy-data/plmns/nope/ue-policy-set")
            .await
            .expect("GET bad plmn");
        assert_eq!(resp.status, 400, "a malformed plmnId is refused");

        let sponsor = "/nudr-dr/v2/policy-data/sponsor-connectivity-data/sponsor-1";
        let resp = client
            .put_json(sponsor, &json!({"aspIds": ["asp-1"]}))
            .await
            .expect("PUT sponsor");
        assert_eq!(resp.status, 201);
        let resp = client.get(sponsor).await.expect("GET sponsor");
        assert_eq!(json_of(&resp)["aspIds"], json!(["asp-1"]));
        let resp = client
            .put_json(sponsor, &json!({}))
            .await
            .expect("PUT sponsor without aspIds");
        assert_eq!(resp.status, 400);

        let bdt = "/nudr-dr/v2/policy-data/bdt-data/bdt-1";
        let resp = client
            .put_json(
                bdt,
                &json!({"bdtRefId": "bdt-1", "aspId": "asp-1", "transPolicy": {"ratingGroup": 1}}),
            )
            .await
            .expect("PUT bdt-data");
        assert_eq!(resp.status, 201);
        // The URI owns the id.
        let resp = client
            .put_json(
                bdt,
                &json!({"bdtRefId": "other", "aspId": "asp-1", "transPolicy": {"ratingGroup": 1}}),
            )
            .await
            .expect("PUT bdt-data mismatched id");
        assert_eq!(resp.status, 400);
        let resp = client
            .get("/nudr-dr/v2/policy-data/bdt-data")
            .await
            .expect("GET bdt-data collection");
        assert_eq!(resp.status, 200);
        assert_eq!(json_of(&resp).as_array().map(|a| a.len()), Some(1));

        // Clean up the subscription so it cannot notify later tests.
        let sub_id = sub_loc.rsplit('/').next().expect("sub id");
        let resp = client
            .delete(&format!("/nudr-dr/v2/policy-data/subs-to-notify/{sub_id}"))
            .await
            .expect("DELETE sub");
        assert_eq!(resp.status, 204);

        drop(listener);
        udr.stop().await.expect("stop");
    }

    /// The `200 {}` vs `404` question the issue asks to settle explicitly: KEPT
    /// as `200 {}` for `am-data` and `ue-policy-set`, because those documents'
    /// members are all optional, so "this subscriber has no AM policy data" is a
    /// representable answer — while a `404` would also be the answer for "no such
    /// subscriber", collapsing two facts a PCF may want to distinguish. `sm-data`
    /// keeps its `404` for an unknown subscriber, since it has a derived default
    /// and absence there means the subscriber itself is missing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_unprovisioned_policy_documents_keep_200_empty() {
        let (udr, client, _listener, _cb, _rx) = start_udr_and_listener().await;
        let supi = "imsi-001019900008706";
        for resource in ["am-data", "ue-policy-set"] {
            let resp = client
                .get(&format!("/nudr-dr/v2/policy-data/ues/{supi}/{resource}"))
                .await
                .expect("GET");
            assert_eq!(
                resp.status, 200,
                "{resource} on an unprovisioned subscriber"
            );
            assert_eq!(json_of(&resp), json!({}), "{resource} empty document");
        }
        let resp = client
            .get(&format!("/nudr-dr/v2/policy-data/ues/{supi}/sm-data"))
            .await
            .expect("GET sm-data");
        assert_eq!(
            resp.status, 404,
            "sm-data has a derived default, so absence means no subscriber"
        );
        udr.stop().await.expect("stop");
    }

    /// #87 gap 4: the five application-data datasets that answered
    /// "Unknown application-data resource".
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_application_data_remaining_datasets() {
        let (udr, client, _listener, _cb, _rx) = start_udr_and_listener().await;
        // Spec spellings (TS 29.519 §5.6): the issue's informal "af-qos-data" /
        // "eas-deployment-data" do not appear in the OpenAPI.
        let datasets: [(&str, &str, serde_json::Value); 6] = [
            (
                "bdtPolicyData",
                "bdt-1",
                json!({"bdtRefId": "bdt-1", "aspId": "asp-1"}),
            ),
            (
                "iptvConfigData",
                "cfg-1",
                json!({"afAppId": "app-1", "multiAccCtrls": {}, "supi": "imsi-1"}),
            ),
            ("serviceParamData", "svc-1", json!({"afAppId": "app-1"})),
            ("am-influence-data", "ami-1", json!({"afAppId": "app-1"})),
            ("af-qos-data-sets", "qos-1", json!({"afQosDataId": "qos-1"})),
            ("eas-deploy-data", "eas-1", json!({"dnn": "internet"})),
        ];
        for (collection, id, doc) in datasets {
            let path = format!("/nudr-dr/v2/application-data/{collection}/{id}");
            let resp = client.get(&path).await.expect("GET before");
            assert_eq!(
                resp.status, 404,
                "{collection} unprovisioned is DATA_NOT_FOUND, not an unknown resource"
            );
            assert_eq!(json_of(&resp)["cause"], "DATA_NOT_FOUND", "{collection}");

            let resp = client.put_json(&path, &doc).await.expect("PUT");
            assert_eq!(
                resp.status, 201,
                "{collection} PUT: {:?}",
                resp.http.content
            );
            let resp = client.get(&path).await.expect("GET after");
            assert_eq!(resp.status, 200);
            assert_eq!(json_of(&resp), doc, "{collection} round-trip");

            let resp = client
                .get(&format!("/nudr-dr/v2/application-data/{collection}"))
                .await
                .expect("GET collection");
            assert_eq!(resp.status, 200);
            assert_eq!(
                json_of(&resp),
                json!([doc]),
                "{collection} collection lists it"
            );
            let resp = client.delete(&path).await.expect("DELETE");
            assert_eq!(resp.status, 204);
        }
        // Mandatory members are enforced where the schema names them.
        let resp = client
            .put_json(
                "/nudr-dr/v2/application-data/iptvConfigData/cfg-2",
                &json!({"afAppId": "app-1"}),
            )
            .await
            .expect("PUT iptv without multiAccCtrls");
        assert_eq!(resp.status, 400);
        udr.stop().await.expect("stop");
    }

    /// #87 gap 5: `Nudr_GroupIDmap` was not routed at all, so the router's
    /// unknown-service 404 was the only answer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_group_id_map_service() {
        let (udr, client, _listener, _cb, _rx) = start_udr_and_listener().await;
        set_group_id_map(vec![
            GroupIdMapYaml {
                supi_prefix: String::new(),
                nf_group_ids: [("UDM".to_string(), "udm-grp-default".to_string())]
                    .into_iter()
                    .collect(),
            },
            GroupIdMapYaml {
                supi_prefix: "imsi-00101".to_string(),
                nf_group_ids: [
                    ("UDM".to_string(), "udm-grp-1".to_string()),
                    ("AUSF".to_string(), "ausf-grp-1".to_string()),
                ]
                .into_iter()
                .collect(),
            },
        ]);

        // subscriberId is mandatory, as is nf-type.
        let resp = client
            .get("/nudr-group-id-map/v1/nf-group-ids?nf-type=UDM")
            .await
            .expect("GET without subscriberId");
        assert_eq!(resp.status, 400);
        let resp = client
            .get("/nudr-group-id-map/v1/nf-group-ids?subscriberId=imsi-001010000000001")
            .await
            .expect("GET without nf-type");
        assert_eq!(resp.status, 400);

        // The longest matching prefix wins over the catch-all.
        let resp = client
            .get("/nudr-group-id-map/v1/nf-group-ids?nf-type=UDM,AUSF&subscriberId=imsi-001010000000001")
            .await
            .expect("GET nf-group-ids");
        assert_eq!(
            resp.status, 200,
            "the service must be reachable: {:?}",
            resp.http.content
        );
        assert_eq!(
            json_of(&resp),
            json!({"UDM": "udm-grp-1", "AUSF": "ausf-grp-1"})
        );

        // nf-type filters the map.
        let resp = client
            .get(
                "/nudr-group-id-map/v1/nf-group-ids?nf-type=AUSF&subscriberId=imsi-001010000000001",
            )
            .await
            .expect("GET filtered");
        assert_eq!(json_of(&resp), json!({"AUSF": "ausf-grp-1"}));

        // A subscriber outside every range, with no catch-all, is a 404.
        set_group_id_map(vec![GroupIdMapYaml {
            supi_prefix: "imsi-99999".to_string(),
            nf_group_ids: [("UDM".to_string(), "udm-grp-x".to_string())]
                .into_iter()
                .collect(),
        }]);
        let resp = client
            .get("/nudr-group-id-map/v1/nf-group-ids?nf-type=UDM&subscriberId=imsi-001010000000001")
            .await
            .expect("GET unmatched");
        assert_eq!(resp.status, 404);

        // Subscriptions CRUD.
        let resp = client
            .post_json(
                "/nudr-group-id-map/v1/nf-group-ids/subscriptions",
                &json!({"callbackReference": "http://nf/cb", "nfTypes": ["UDM"]}),
            )
            .await
            .expect("POST sub");
        assert_eq!(resp.status, 201);
        let loc = resp.http.get_header("Location").expect("Location").clone();
        let sub_id = loc.rsplit('/').next().expect("sub id").to_string();
        let resp = client
            .get(&format!(
                "/nudr-group-id-map/v1/nf-group-ids/subscriptions/{sub_id}"
            ))
            .await
            .expect("GET sub");
        assert_eq!(resp.status, 200);
        let resp = client
            .delete(&format!(
                "/nudr-group-id-map/v1/nf-group-ids/subscriptions/{sub_id}"
            ))
            .await
            .expect("DELETE sub");
        assert_eq!(resp.status, 204);

        // routing-ids is recognised and refused rather than 404'd.
        let resp = client
            .get("/nudr-group-id-map/v1/routing-ids?subscriberId=imsi-001010000000001")
            .await
            .expect("GET routing-ids");
        assert_eq!(resp.status, 501);

        set_group_id_map(Vec::new());
        udr.stop().await.expect("stop");
    }

    #[test]
    fn test_udr_yaml_group_id_map() {
        let yaml = r#"
udr:
  group_id_map:
    - supi_prefix: "imsi-00101"
      nf_group_ids:
        UDM: udm-grp-1
        AUSF: ausf-grp-1
"#;
        let parsed: UdrYaml = serde_yaml::from_str(yaml).unwrap();
        let entries = parsed.udr.unwrap().group_id_map.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].supi_prefix, "imsi-00101");
        assert_eq!(
            entries[0].nf_group_ids.get("UDM").map(String::as_str),
            Some("udm-grp-1")
        );
    }

    /// `build_identity_data` maps a subscriber record to TS 29.505 `IdentityData`.
    #[test]
    fn test_build_identity_data_shapes() {
        let mut data = nextgcore_dbi::types::NextgcoreSubscriptionData::new();
        // No IMSI: nothing to answer with, and the handler turns that into a 404.
        assert_eq!(build_identity_data(&data), json!({}));

        data.imsi = Some("001010000000001".to_string());
        let mut msisdn = nextgcore_dbi::types::NextgcoreMsisdn::default();
        msisdn.bcd = "491721075400".to_string();
        data.msisdn.push(msisdn);
        data.num_of_msisdn = 1;
        assert_eq!(
            build_identity_data(&data),
            json!({
                "supiList": ["imsi-001010000000001"],
                "gpsiList": ["msisdn-491721075400"]
            }),
            "both lists use the same identity spelling as am-data's gpsis"
        );
    }

    /// The snssai/dnn filter, unit-level: matching is field-wise on sst/sd, so it
    /// does not depend on how this UDR spells the map key.
    #[test]
    fn test_filter_sm_policy_data_matches_on_snssai_fields() {
        let doc = json!({
            "smPolicySnssaiData": {
                "MY-OWN-KEY": {
                    "snssai": {"sst": 1, "sd": "000001"},
                    "smPolicyDnnData": {"internet": {"dnn": "internet"}}
                }
            }
        });
        // Key spelling is irrelevant; sst+sd decide.
        let hit = filter_sm_policy_data(&doc, Some(&json!({"sst": 1, "sd": "000001"})), None)
            .expect("match");
        assert_eq!(
            hit["smPolicySnssaiData"].as_object().map(|o| o.len()),
            Some(1)
        );
        // sd is compared without leading-zero padding differences.
        assert!(
            filter_sm_policy_data(&doc, Some(&json!({"sst": 1, "sd": "0000001"})), None).is_some()
        );
        // A different slice selects nothing.
        assert!(filter_sm_policy_data(&doc, Some(&json!({"sst": 2})), None).is_none());
        // Right slice, wrong DNN: nothing.
        assert!(
            filter_sm_policy_data(&doc, Some(&json!({"sst": 1, "sd": "000001"})), Some("ims"))
                .is_none()
        );
        // No filter: unchanged.
        assert_eq!(filter_sm_policy_data(&doc, None, None), Some(doc));
    }
    // ------------------------------------------------------------------
    // algorithmId / encTopcKey in AuthenticationSubscription (#115)
    // ------------------------------------------------------------------

    fn auth_info_with(
        algorithm_id: &str,
        topc: Option<[u8; 32]>,
    ) -> nextgcore_dbi::subscription::NextgcoreDbiAuthInfo {
        let mut info = nextgcore_dbi::subscription::NextgcoreDbiAuthInfo {
            k: [0xab; 16],
            use_opc: true,
            opc: [0x55; 16],
            op: [0u8; 16],
            amf: [0x80, 0x00],
            rand: [0u8; 16],
            sqn: 0x21,
            authentication_method: "5G_AKA".to_string(),
            algorithm_id: algorithm_id.to_string(),
            topc: [0u8; 32],
            top: [0u8; 32],
            use_topc: false,
        };
        if let Some(topc) = topc {
            info.topc = topc;
            info.use_topc = true;
        }
        info
    }

    /// TS 29.505 §5.2.3: `algorithmId` and `encTopcKey` are served when provisioned.
    #[test]
    fn the_auth_subscription_serves_algorithm_id_and_enc_topc_key() {
        let topc = [0x7a; 32];
        let json = build_auth_subscription_json(
            "imsi-001010000000001",
            &auth_info_with("tuak", Some(topc)),
        );

        assert_eq!(json["algorithmId"], "tuak");
        assert_eq!(
            json["encTopcKey"].as_str().unwrap().len(),
            64,
            "a 256-bit TOPc serialises as 64 hex characters"
        );
        assert_eq!(
            json["encTopcKey"].as_str().unwrap(),
            "7a".repeat(32),
            "and it must be the bytes that were stored, not a re-derivation"
        );
        // The pre-existing members are untouched.
        assert_eq!(json["authenticationMethod"], "5G_AKA");
        assert_eq!(json["encPermanentKey"], "ab".repeat(16));
    }

    /// A subscriber with neither member serialises exactly as it did before #115.
    ///
    /// The members are OMITTED, not emitted as empty strings: TS 29.505 makes them 0..1,
    /// and an empty `algorithmId` is a value the UDM would have to interpret rather than
    /// the absence of one. This is the assertion that keeps every existing subscriber
    /// working.
    #[test]
    fn a_subscriber_without_them_serialises_as_before() {
        let json = build_auth_subscription_json("imsi-001010000000002", &auth_info_with("", None));
        assert!(
            json.get("algorithmId").is_none(),
            "absent, not empty: found {:?}",
            json.get("algorithmId")
        );
        assert!(json.get("encTopcKey").is_none(), "absent, not empty");
        // And the response still carries everything it always did.
        for member in [
            "authenticationMethod",
            "encPermanentKey",
            "encOpcKey",
            "authenticationManagementField",
            "supi",
            "sequenceNumber",
        ] {
            assert!(json.get(member).is_some(), "{member} must still be served");
        }
    }

    /// An `algorithmId` with no TOPc still serves the identifier: the UDR stores what it
    /// was given and does not second-guess the provisioning, which is what makes the
    /// UDM's own refusal the place that failure is reported.
    #[test]
    fn an_algorithm_id_without_a_topc_is_still_served() {
        let json =
            build_auth_subscription_json("imsi-001010000000003", &auth_info_with("tuak", None));
        assert_eq!(json["algorithmId"], "tuak");
        assert!(json.get("encTopcKey").is_none());
    }

    /// A 256-bit operator field must be exactly 64 hex characters at provisioning time.
    ///
    /// Rejecting here rather than at authentication time is the point: a short TOPc
    /// becomes a zero-padded key that authenticates against nothing, and the operator
    /// would see it as a UE-side MAC failure rather than as the typo it is.
    #[test]
    fn a_malformed_operator_field_is_refused_at_provisioning() {
        let ok = serde_json::json!({ "encTopcKey": "7a".repeat(32) });
        assert_eq!(
            validate_optional_key_256(&ok, "encTopcKey").unwrap(),
            Some("7a".repeat(32))
        );

        // Absent and empty are both fine — the normal case for every MILENAGE subscriber.
        assert_eq!(
            validate_optional_key_256(&serde_json::json!({}), "encTopcKey").unwrap(),
            None
        );
        assert_eq!(
            validate_optional_key_256(&serde_json::json!({ "encTopcKey": "" }), "encTopcKey")
                .unwrap(),
            None
        );

        // Too short, too long, and not hex are all 400.
        for bad in ["7a".repeat(16), "7a".repeat(33), "z".repeat(64)] {
            let body = serde_json::json!({ "encTopcKey": bad });
            let err = validate_optional_key_256(&body, "encTopcKey")
                .expect_err("a malformed 256-bit field must be refused");
            assert_eq!(
                err.status, 400,
                "and refused with 400, not silently dropped"
            );
        }
    }
}
