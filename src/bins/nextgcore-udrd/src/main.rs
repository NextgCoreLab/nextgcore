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

#[derive(Debug, Default, Deserialize)]
struct UdrSection {
    sbi: Option<SbiYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct UdrYaml {
    udr: Option<UdrSection>,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

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

    // Handle kill flag
    if args.kill {
        log::info!("Kill flag set - would send SIGTERM to running instance");
        return Ok(());
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
            if let Some(sbi) = yaml.udr.and_then(|udr| udr.sbi) {
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
            nextgcore_sbi::heartbeat::spawn_heartbeat_worker(nf_instance_id, 5);
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
    // /nudr-dr/v1/subscription-data/{supi}/authentication-data/authentication-subscription
    // /nudr-dr/v1/subscription-data/{supi}/provisioned-data/{dataset}
    // /nudr-dr/v1/subscription-data/{supi}/{plmn}/provisioned-data/{dataset}
    // /nudr-dr/v1/policy-data/ues/{supi}/{resource}

    if parts.len() < 3 {
        return send_not_found("Invalid path", None);
    }

    let service = parts[0];
    let _version = parts[1];

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
/// Path: /nudr-dr/v1/subscription-data/{supi}/...
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

/// VarPlmnId per TS 29.505: 5 or 6 digits (MCC+MNC).
fn is_valid_plmn_id(s: &str) -> bool {
    (s.len() == 5 || s.len() == 6) && s.bytes().all(|b| b.is_ascii_digit())
}

/// Handle authentication-data requests
/// Path: /nudr-dr/v1/subscription-data/{supi}/authentication-data/authentication-subscription
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
            if body
                .get("authenticationMethod")
                .and_then(|v| v.as_str())
                .is_none()
            {
                return missing_mandatory("authenticationMethod");
            }
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
            };
            match nextgcore_dbi::subscription::nextgcore_dbi_provision_auth_info_async(
                supi.to_string(),
                provision,
            )
            .await
            {
                Ok(created) => {
                    let path = format!(
                        "/nudr-dr/v1/subscription-data/{supi}/authentication-data/authentication-subscription"
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

            // Parse PatchItemList from request body to extract new SQN
            if let Some(content) = &request.http.content {
                if let Ok(patches) = serde_json::from_str::<serde_json::Value>(content) {
                    if let Some(arr) = patches.as_array() {
                        for patch in arr {
                            let path = patch.get("path").and_then(|v| v.as_str()).unwrap_or("");
                            if path == "/sequenceNumber/sqn" {
                                if let Some(sqn_hex) = patch.get("value").and_then(|v| v.as_str()) {
                                    let sqn = u64::from_str_radix(sqn_hex, 16).unwrap_or(0);
                                    if let Err(e) =
                                        nextgcore_dbi::subscription::nextgcore_dbi_update_sqn_async(
                                            supi.to_string(),
                                            sqn,
                                        )
                                        .await
                                    {
                                        log::error!("[{supi}] DB update_sqn failed: {e:?}");
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Increment SQN for next use
            if let Err(e) =
                nextgcore_dbi::subscription::nextgcore_dbi_increment_sqn_async(supi.to_string())
                    .await
            {
                log::error!("[{supi}] DB increment_sqn failed: {e:?}");
            }

            SbiResponse::with_status(204)
        }
        ("authentication-status", "PUT") | ("authentication-status", "DELETE") => {
            log::info!("[{supi}] {method} authentication-status");

            if let Err(e) =
                nextgcore_dbi::subscription::nextgcore_dbi_increment_sqn_async(supi.to_string())
                    .await
            {
                log::error!("[{supi}] DB increment_sqn failed: {e:?}");
            }

            SbiResponse::with_status(204)
        }
        _ => {
            log::warn!("[{supi}] Unknown auth resource: {method} {resource}");
            send_method_not_allowed(
                method,
                &format!("/nudr-dr/v1/subscription-data/{supi}/authentication-data/{resource}"),
            )
        }
    }
}

/// Handle context-data requests
/// Path: /nudr-dr/v1/subscription-data/{supi}/context-data/{resource}
///
/// Implements:
/// - GET/PUT/PATCH/DELETE amf-3gpp-access: AMF 3GPP access registration context
/// - GET/PUT/DELETE smf-registrations/{pdu-session-id}: SMF registration context
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

    log::info!("[{supi}] {method} context-data/{resource}");

    match resource {
        "amf-3gpp-access" => handle_amf_3gpp_access(supi, method, request).await,
        "smf-registrations" => {
            let pdu_session_id = parts.get(resource_idx + 1).copied().unwrap_or("");
            handle_smf_registrations(supi, method, request, pdu_session_id)
        }
        _ => {
            log::warn!("[{supi}] Unknown context-data resource: {resource}");
            send_not_found(&format!("Unknown context resource: {resource}"), None)
        }
    }
}

/// Path of the amf-3gpp-access resource for a SUPI (notification resourceId).
fn amf_3gpp_access_path(supi: &str) -> String {
    format!("/nudr-dr/v1/subscription-data/{supi}/context-data/amf-3gpp-access")
}

/// Handle AMF 3GPP access registration context (TS 29.505).
///
/// Stores and returns the full Amf3GppAccessRegistration document: the
/// shape PUT here by udmd (forwarding the amfd Nudm registration) is
/// preserved verbatim and echoed on GET.
async fn handle_amf_3gpp_access(supi: &str, method: &str, request: &SbiRequest) -> SbiResponse {
    let udr_ctx = nextgcore_udrd::context::udr_self();
    let ds = data_store::store();
    match method {
        "GET" => match ds.amf_3gpp_get(supi) {
            Some(doc) => {
                log::debug!("[{supi}] GET amf-3gpp-access - registration found");
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
            // Mandatory attributes per TS 29.503 Amf3GppAccessRegistration
            for attr in ["amfInstanceId", "deregCallbackUri", "guami", "ratType"] {
                if reg_data.get(attr).is_none() {
                    return missing_mandatory(attr);
                }
            }
            // Persist the PEI (IMEISV) claim off-thread (last live
            // blocking Mongo call moved to the spawn_blocking wrapper).
            if let Some(pei) = reg_data.get("pei").and_then(|v| v.as_str()) {
                let imeisv = pei.strip_prefix("imeisv-").unwrap_or(pei).to_string();
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
            let created = ds.amf_3gpp_put(supi, reg_data.clone());
            let path = amf_3gpp_access_path(supi);
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
            let Some(mut doc) = ds.amf_3gpp_get(supi) else {
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
            ds.amf_3gpp_put(supi, doc.clone());
            notify_subscription_data_change(supi, &amf_3gpp_access_path(supi), Some(&doc));
            SbiResponse::with_status(204)
        }
        "DELETE" => {
            let existed = ds.amf_3gpp_remove(supi).is_some();
            if let Ok(mut ctx) = udr_ctx.write() {
                ctx.ue_remove(supi);
            }
            if existed {
                notify_subscription_data_change(supi, &amf_3gpp_access_path(supi), None);
            }
            SbiResponse::with_status(204)
        }
        _ => send_method_not_allowed(method, "context-data/amf-3gpp-access"),
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
            let created = ds.smf_registration_put(supi, pdu_session_id, doc);
            // TS 29.505: 201 Created for a new registration, 204 for replace.
            if created {
                SbiResponse::with_status(201)
            } else {
                SbiResponse::with_status(204)
            }
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
/// Path: /nudr-dr/v1/subscription-data/{supi}/provisioned-data/{dataset}
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
    // /nudr-dr/v1/policy-data/ues/{supi}/{resource}
    let sub_resource = parts.get(3).copied().unwrap_or("");

    if sub_resource != "ues" {
        return send_not_found(
            &format!("Unknown policy sub-resource: {sub_resource}"),
            None,
        );
    }

    let supi = match parts.get(4) {
        Some(s) => *s,
        None => return send_bad_request("Missing SUPI", Some("MISSING_SUPI")),
    };

    let resource = parts.get(5).copied().unwrap_or("");

    match resource {
        "am-data" => {
            match method {
                "GET" => {
                    log::debug!("[{supi}] GET policy am-data");
                    // udrd-05: return stored AmPolicyData when provisioned (udrd-04);
                    // fall back to `{}` per TS 29.519 (no default AM policy data).
                    let ds = nextgcore_udrd::data_store::store();
                    let body = ds
                        .policy_am_get(supi)
                        .unwrap_or_else(|| serde_json::json!({}));
                    let body = apply_fields_param(body, request);
                    SbiResponse::with_status(200).with_body(body.to_string(), "application/json")
                }
                "PUT" => {
                    log::debug!("[{supi}] PUT policy am-data");
                    let body = match parse_json_body(request) {
                        Ok(v) => v,
                        Err(resp) => return *resp,
                    };
                    if !body.is_object() {
                        return send_bad_request(
                            "Body must be a JSON object",
                            Some("INVALID_MSG_FORMAT"),
                        );
                    }
                    let ds = nextgcore_udrd::data_store::store();
                    let created = ds.policy_am_put(supi, body.clone());
                    let path = format!("/nudr-dr/v1/policy-data/ues/{supi}/am-data");
                    notify_subscription_data_change(supi, &path, Some(&body));
                    if created {
                        SbiResponse::with_status(201)
                            .with_header("Location", path)
                            .with_body(body.to_string(), "application/json")
                    } else {
                        SbiResponse::with_status(204)
                    }
                }
                _ => send_method_not_allowed(method, "policy-data/ues/am-data"),
            }
        }
        "sm-data" => {
            match method {
                "GET" => {
                    log::debug!("[{supi}] GET policy sm-data");
                    let ds = nextgcore_udrd::data_store::store();
                    // udrd-05: prefer stored SmPolicyData when provisioned (udrd-04);
                    // fall back to the derived default from subscription data.
                    if let Some(stored) = ds.policy_sm_get(supi) {
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
                            let sm_policy_snssai_data = build_sm_policy_data(&data);
                            let response =
                                serde_json::json!({"smPolicySnssaiData": sm_policy_snssai_data});
                            let response = apply_fields_param(response, request);
                            SbiResponse::with_status(200)
                                .with_body(response.to_string(), "application/json")
                        }
                        Err(_) => send_not_found("Subscriber not found", None),
                    }
                }
                "PUT" => {
                    log::debug!("[{supi}] PUT policy sm-data");
                    let body = match parse_json_body(request) {
                        Ok(v) => v,
                        Err(resp) => return *resp,
                    };
                    if !body.is_object() {
                        return send_bad_request(
                            "Body must be a JSON object",
                            Some("INVALID_MSG_FORMAT"),
                        );
                    }
                    // udrd-04: persist the provisioned SmPolicyData.
                    let ds = nextgcore_udrd::data_store::store();
                    let created = ds.policy_sm_put(supi, body.clone());
                    let path = format!("/nudr-dr/v1/policy-data/ues/{supi}/sm-data");
                    notify_subscription_data_change(supi, &path, Some(&body));
                    if created {
                        SbiResponse::with_status(201)
                            .with_header("Location", path)
                            .with_body(body.to_string(), "application/json")
                    } else {
                        SbiResponse::with_status(204)
                    }
                }
                _ => send_method_not_allowed(method, "policy-data/ues/sm-data"),
            }
        }
        "ue-policy-set" => {
            match method {
                "GET" => {
                    log::debug!("[{supi}] GET ue-policy-set");
                    let ds = nextgcore_udrd::data_store::store();
                    // udrd-05: prefer stored UePolicySet when provisioned (udrd-04);
                    // fall back to a minimal derived default built from subscription slices.
                    if let Some(stored) = ds.policy_ue_get(supi) {
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
                "PUT" => {
                    log::debug!("[{supi}] PUT ue-policy-set");
                    let body = match parse_json_body(request) {
                        Ok(v) => v,
                        Err(resp) => return *resp,
                    };
                    if !body.is_object() {
                        return send_bad_request(
                            "Body must be a JSON object",
                            Some("INVALID_MSG_FORMAT"),
                        );
                    }
                    // udrd-04: persist the provisioned UePolicySet.
                    let ds = nextgcore_udrd::data_store::store();
                    let created = ds.policy_ue_put(supi, body.clone());
                    let path = format!("/nudr-dr/v1/policy-data/ues/{supi}/ue-policy-set");
                    notify_subscription_data_change(supi, &path, Some(&body));
                    if created {
                        SbiResponse::with_status(201)
                            .with_header("Location", path)
                            .with_body(body.to_string(), "application/json")
                    } else {
                        SbiResponse::with_status(204)
                    }
                }
                _ => send_method_not_allowed(method, "policy-data/ues/ue-policy-set"),
            }
        }
        _ => send_not_found(&format!("Unknown policy resource: {resource}"), None),
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

/// Handle /nudr-dr/v1/subscription-data/subs-to-notify[/{subsId}]
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
                        format!("/nudr-dr/v1/subscription-data/subs-to-notify/{}", sub.id),
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

/// Handle /nudr-dr/v1/exposure-data/...
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
                        format!("/nudr-dr/v1/exposure-data/subs-to-notify/{}", sub.id),
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
            let path = format!("/nudr-dr/v1/exposure-data/{ue_id}/access-and-mobility-data");
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
            let path = format!("/nudr-dr/v1/exposure-data/{ue_id}/session-management-data/{psi}");
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

/// Handle /nudr-dr/v1/application-data/...
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
                let path = format!("/nudr-dr/v1/application-data/pfds/{app_id}");
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
                    let path = format!("/nudr-dr/v1/application-data/pfds/{app_id}");
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
                                "/nudr-dr/v1/application-data/influenceData/subs-to-notify/{}",
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
                let path = format!("/nudr-dr/v1/application-data/influenceData/{influence_id}");
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
                        format!("/nudr-dr/v1/application-data/subs-to-notify/{}", sub.id),
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
        _ => send_not_found("Unknown application-data resource", None),
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
fn build_auth_subscription_json(
    supi: &str,
    auth_info: &nextgcore_dbi::subscription::NextgcoreDbiAuthInfo,
) -> serde_json::Value {
    // TS 29.505 §5.4.2.2: NextgcoreDbiAuthInfo does not surface the provisioned
    // authenticationMethod from the DB schema; default to "5G_AKA" per
    // TS 33.501 §6.1.2 (most deployments use 5G-AKA). (udrd-10)
    let auth_method = "5G_AKA";

    // TS 29.505 §5.4.2.23 / TS 33.102 SQN array management: with indLength=5
    // the low 5 bits of the 48-bit SQN are the IND component and must be
    // zeroed in the stored/served representation. (udrd-08)
    const IND_LENGTH: u64 = 5;
    const SQN_48_MASK: u64 = 0xFFFF_FFFF_FFFF;
    const IND_MASK: u64 = (1u64 << IND_LENGTH) - 1; // 0x1F
    let sqn_zeroed = (auth_info.sqn & SQN_48_MASK) & !IND_MASK;

    serde_json::json!({
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
    })
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

    let nf_profile = serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "UDR",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [
            {
                "serviceInstanceId": format!("{nf_instance_id}-nudr-dr"),
                "serviceName": "nudr-dr",
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
            }
        ],
        "allowedNfTypes": ["UDM", "PCF", "AUSF", "SCP"],
        "heartBeatTimer": 10
    });

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

    /// Bind an ephemeral port (probe-and-release) for an SBI server.
    fn ephemeral_addr() -> SocketAddr {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe binds");
        let addr = probe.local_addr().expect("probe addr");
        drop(probe);
        addr
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
        let udr_addr = ephemeral_addr();
        let udr_server = SbiServer::new(NextgcoreSbiServerConfig::new(udr_addr));
        udr_server
            .start(udr_sbi_request_handler)
            .await
            .expect("UDR SBI server starts");

        let listener_addr = ephemeral_addr();
        let (tx, rx) = mpsc::unbounded_channel::<(String, String)>();
        let listener = SbiServer::new(NextgcoreSbiServerConfig::new(listener_addr));
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
        let resource = format!("/nudr-dr/v1/subscription-data/{supi}/context-data/amf-3gpp-access");

        // Subscribe to changes for this UE.
        let cb_uri = format!("http://127.0.0.1:{cb_port}/cb/data-change");
        let sub_body = json!({
            "ueId": supi,
            "callbackReference": cb_uri,
            "monitoredResourceUris": [format!("http://udr{resource}")]
        });
        let resp = client
            .post_json("/nudr-dr/v1/subscription-data/subs-to-notify", &sub_body)
            .await
            .expect("POST sub");
        assert_eq!(resp.status, 201);
        let loc = resp.http.get_header("Location").expect("Location").clone();
        assert!(loc.contains("/subscription-data/subs-to-notify/"));

        // Missing mandatory callbackReference -> 400 ProblemDetails
        let resp = client
            .post_json(
                "/nudr-dr/v1/subscription-data/subs-to-notify",
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
        let mut req = SbiRequest::delete("/nudr-dr/v1/subscription-data/subs-to-notify");
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
            format!("/nudr-dr/v1/subscription-data/{unknown}/context-data/smf-registrations");
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
        let coll = format!("/nudr-dr/v1/subscription-data/{supi}/context-data/smf-registrations");
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
        let am_path = format!("/nudr-dr/v1/exposure-data/{ue}/access-and-mobility-data");
        let sm_path = format!("/nudr-dr/v1/exposure-data/{ue}/session-management-data/5");

        // Strict-peer: subscription without notificationUri -> 400.
        let resp = client
            .post_json(
                "/nudr-dr/v1/exposure-data/subs-to-notify",
                &json!({"monitoredResourceUris": [am_path]}),
            )
            .await
            .expect("POST bad sub");
        assert_eq!(resp.status, 400);

        // Valid subscription -> 201 + Location.
        let resp = client
            .post_json(
                "/nudr-dr/v1/exposure-data/subs-to-notify",
                &json!({
                    "notificationUri": format!("http://127.0.0.1:{cb_port}/cb/exposure"),
                    "monitoredResourceUris": [format!("/nudr-dr/v1/exposure-data/{ue}")]
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
                "/nudr-dr/v1/exposure-data/subs-to-notify/{sub_id}"
            ))
            .await
            .expect("DELETE sub");
        assert_eq!(resp.status, 204);
        let resp = client
            .delete(&format!(
                "/nudr-dr/v1/exposure-data/subs-to-notify/{sub_id}"
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
                "/nudr-dr/v1/application-data/pfds/app-w42",
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
            .put_json("/nudr-dr/v1/application-data/pfds/app-w42", &pfd)
            .await
            .expect("PUT pfd");
        assert_eq!(resp.status, 201);
        let resp = client
            .get("/nudr-dr/v1/application-data/pfds")
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
                "/nudr-dr/v1/application-data/influenceData/subs-to-notify",
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
                "/nudr-dr/v1/application-data/influenceData/subs-to-notify",
                &json!({"notificationUri": "http://x/cb"}),
            )
            .await
            .expect("POST bad influence sub");
        assert_eq!(resp.status, 400);

        // Strict-peer: influence data without afAppId -> 400.
        let resp = client
            .put_json(
                "/nudr-dr/v1/application-data/influenceData/inf-w42",
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
            .put_json("/nudr-dr/v1/application-data/influenceData/inf-w42", &influ)
            .await
            .expect("PUT influence");
        assert_eq!(resp.status, 201);
        let (path, notify) = recv_notification(&mut rx).await;
        assert_eq!(path, "/cb/influence");
        assert!(notify.is_array());
        assert!(notify[0]["resUri"].as_str().unwrap().ends_with("inf-w42"));
        assert_eq!(notify[0]["trafficInfluData"]["afAppId"], "app-w42");

        // Collection read with filters.
        let mut req = SbiRequest::get("/nudr-dr/v1/application-data/influenceData");
        req.http.set_param("supis", "imsi-001019900000003");
        let resp = client.send_request(req).await.expect("GET influence");
        assert_eq!(resp.status, 200);
        let list: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(list.as_array().unwrap().len(), 1);
        let mut req = SbiRequest::get("/nudr-dr/v1/application-data/influenceData");
        req.http.set_param("dnns", "no-such-dnn");
        let resp = client.send_request(req).await.expect("GET influence empty");
        let list: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(list.as_array().unwrap().is_empty());

        // DELETE influence -> 204 + deletion notification (resUri only).
        let resp = client
            .delete("/nudr-dr/v1/application-data/influenceData/inf-w42")
            .await
            .expect("DELETE influence");
        assert_eq!(resp.status, 204);
        let (_, notify) = recv_notification(&mut rx).await;
        assert!(notify[0]["resUri"].as_str().unwrap().ends_with("inf-w42"));
        assert!(notify[0].get("trafficInfluData").is_none());

        // DELETE pfd -> 204; GET -> 404.
        let resp = client
            .delete("/nudr-dr/v1/application-data/pfds/app-w42")
            .await
            .expect("DELETE pfd");
        assert_eq!(resp.status, 204);
        let resp = client
            .get("/nudr-dr/v1/application-data/pfds/app-w42")
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
        let udr_addr = ephemeral_addr();
        let udr = SbiServer::new(NextgcoreSbiServerConfig::new(udr_addr));
        udr.start(udr_sbi_request_handler)
            .await
            .expect("UDR SBI server starts");
        let client = SbiClient::with_host_port("127.0.0.1", udr_addr.port());
        let supi = "imsi-001019900000004";
        let auth_path = format!(
            "/nudr-dr/v1/subscription-data/{supi}/authentication-data/authentication-subscription"
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
                "/nudr-dr/v1/subscription-data/{supi}/12a45/provisioned-data/am-data"
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
                "/nudr-dr/v1/subscription-data/{supi}/00101/provisioned-data/am-data"
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
        let udr_addr = ephemeral_addr();
        let udr = SbiServer::new(NextgcoreSbiServerConfig::new(udr_addr));
        udr.start(udr_sbi_request_handler)
            .await
            .expect("UDR SBI server starts");
        let client = SbiClient::with_host_port("127.0.0.1", udr_addr.port());

        // imsi- is unchanged (404 when no DB, not 400)
        let resp = client
            .get("/nudr-dr/v1/subscription-data/imsi-001010000000001/authentication-data/authentication-subscription")
            .await
            .expect("GET imsi");
        assert_eq!(resp.status, 404, "imsi- should 404 (no DB), not 400");

        // nai- is a valid VarUeId, returns 404 (not 400 INVALID_SUPI)
        let resp = client
            .get("/nudr-dr/v1/subscription-data/nai-user@example.com/authentication-data/authentication-subscription")
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
            .get("/nudr-dr/v1/subscription-data/gci-001010000000001/authentication-data/authentication-subscription")
            .await
            .expect("GET gci");
        assert_eq!(resp.status, 404, "gci- should be 404");

        // extgroupid- returns 501 Not Implemented
        let resp = client
            .get("/nudr-dr/v1/subscription-data/extgroupid-grp001/authentication-data/authentication-subscription")
            .await
            .expect("GET extgroupid");
        assert_eq!(resp.status, 501, "extgroupid- must return 501");
        let problem: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(problem["cause"], "NOT_SUPPORTED");

        // Unknown prefix still returns 400 INVALID_SUPI
        let resp = client
            .get("/nudr-dr/v1/subscription-data/bogus-12345/authentication-data/authentication-subscription")
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
        let am_path = format!("/nudr-dr/v1/policy-data/ues/{supi}/am-data");
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
        let sm_path = format!("/nudr-dr/v1/policy-data/ues/{supi}/sm-data");
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
        let ue_path = format!("/nudr-dr/v1/policy-data/ues/{supi}/ue-policy-set");
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
}
