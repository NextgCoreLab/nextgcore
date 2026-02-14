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
use nextgcore_udrd::{
    udr_context_final, udr_context_init, udr_sbi_close, udr_sbi_open, UdrSmContext,
    SbiServerConfig,
};
use ogs_sbi::message::{SbiRequest, SbiResponse};
use ogs_sbi::server::{
    send_bad_request, send_method_not_allowed, send_not_found,
    SbiServer, SbiServerConfig as OgsSbiServerConfig,
};
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
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    init_logging(&args)?;

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

    // Initialize UDR state machine
    let mut udr_sm = UdrSmContext::new();
    udr_sm.init();
    log::info!("UDR state machine initialized");

    // Parse configuration to get db_uri
    let db_uri = parse_db_uri(&args.config);
    if !db_uri.is_empty() {
        match ogs_dbi::ogs_dbi_init(&db_uri) {
            Ok(()) => log::info!("MongoDB connected: {}", mask_uri(&db_uri)),
            Err(e) => log::warn!("MongoDB init failed (will use defaults): {e:?}"),
        }
    } else {
        log::warn!("No db_uri configured, UDR will return hardcoded test data");
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

    // Start actual HTTP/2 SBI server using ogs-sbi
    let sbi_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let sbi_server = SbiServer::new(OgsSbiServerConfig::new(sbi_addr));

    sbi_server.start(udr_sbi_request_handler).await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    log::info!("SBI HTTP/2 server listening on {sbi_addr}");
    log::info!("NextGCore UDR ready");

    // Main event loop (async)
    run_event_loop_async(shutdown).await?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Stop SBI server
    sbi_server.stop().await
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
    ogs_dbi::ogs_dbi_final();

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
        "subscription-data" => handle_subscription_data(&parts, method, &request).await,
        "policy-data" => handle_policy_data(&parts, method, &request).await,
        _ => {
            log::warn!("Unknown UDR resource: {method} {uri}");
            send_not_found(&format!("Unknown resource: {resource_type}"), None)
        }
    }
}

/// Handle subscription-data requests
/// Path: /nudr-dr/v1/subscription-data/{supi}/...
async fn handle_subscription_data(parts: &[&str], method: &str, request: &SbiRequest) -> SbiResponse {
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
            return send_bad_request(&format!("Unsupported SUCI: {supi_or_suci}"), Some("INVALID_SUCI"));
        }
    } else if supi_or_suci.starts_with("imsi-") {
        supi_or_suci.to_string()
    } else {
        log::warn!("Invalid SUPI type: {supi_or_suci}");
        return send_bad_request(&format!("Invalid SUPI type: {supi_or_suci}"), Some("INVALID_SUPI"));
    };
    let supi = supi.as_str();

    // Determine sub-resource: parts[4] could be "authentication-data" or "provisioned-data"
    // or a PLMN ID (then parts[5] = "provisioned-data")
    let sub_resource = parts.get(4).copied().unwrap_or("");

    match sub_resource {
        "authentication-data" => handle_auth_data(supi, parts, method, request).await,
        "provisioned-data" => handle_provisioned_data(supi, parts, 5, method).await,
        "context-data" => handle_context_data(supi, parts, method, request).await,
        _ => {
            // Check if parts[4] is a PLMN ID and parts[5] = "provisioned-data"
            if parts.get(5).copied() == Some("provisioned-data") {
                handle_provisioned_data(supi, parts, 6, method).await
            } else if parts.get(5).copied() == Some("context-data") {
                handle_context_data(supi, parts, method, request).await
            } else {
                log::warn!("Unknown subscription-data sub-resource: {sub_resource}");
                send_not_found("Unknown sub-resource", None)
            }
        }
    }
}

/// Handle authentication-data requests
/// Path: /nudr-dr/v1/subscription-data/{supi}/authentication-data/authentication-subscription
async fn handle_auth_data(supi: &str, parts: &[&str], method: &str, request: &SbiRequest) -> SbiResponse {
    let resource = parts.get(5).copied().unwrap_or("");

    match (resource, method) {
        ("authentication-subscription", "GET") => {
            log::info!("[{supi}] GET authentication-subscription");

            match ogs_dbi::subscription::ogs_dbi_auth_info(supi) {
                Ok(auth_info) => {
                    let response_json = serde_json::json!({
                        "authenticationMethod": "5G_AKA",
                        "encPermanentKey": bytes_to_hex(&auth_info.k),
                        "encOpcKey": bytes_to_hex(if auth_info.use_opc { &auth_info.opc } else { &auth_info.op }),
                        "authenticationManagementField": bytes_to_hex(&auth_info.amf),
                        "sequenceNumber": {
                            "sqn": format!("{:012x}", auth_info.sqn & 0xFFFFFFFFFFFF)
                        }
                    });

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
                                    if let Err(e) = ogs_dbi::subscription::ogs_dbi_update_sqn(supi, sqn) {
                                        log::error!("[{supi}] DB update_sqn failed: {e:?}");
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Increment SQN for next use
            if let Err(e) = ogs_dbi::subscription::ogs_dbi_increment_sqn(supi) {
                log::error!("[{supi}] DB increment_sqn failed: {e:?}");
            }

            SbiResponse::with_status(204)
        }
        ("authentication-status", "PUT") | ("authentication-status", "DELETE") => {
            log::info!("[{supi}] {method} authentication-status");

            if let Err(e) = ogs_dbi::subscription::ogs_dbi_increment_sqn(supi) {
                log::error!("[{supi}] DB increment_sqn failed: {e:?}");
            }

            SbiResponse::with_status(204)
        }
        _ => {
            log::warn!("[{supi}] Unknown auth resource: {method} {resource}");
            send_method_not_allowed(method, &format!("/nudr-dr/v1/subscription-data/{supi}/authentication-data/{resource}"))
        }
    }
}

/// Handle context-data requests
/// Path: /nudr-dr/v1/subscription-data/{supi}/context-data/{resource}
///
/// Implements:
/// - GET/PUT/PATCH/DELETE amf-3gpp-access: AMF 3GPP access registration context
/// - GET/PUT/DELETE smf-registrations/{pdu-session-id}: SMF registration context
async fn handle_context_data(supi: &str, parts: &[&str], method: &str, request: &SbiRequest) -> SbiResponse {
    let resource_idx = if parts.get(4).copied() == Some("context-data") { 5 } else { 6 };
    let resource = parts.get(resource_idx).copied().unwrap_or("");

    log::info!("[{supi}] {method} context-data/{resource}");

    match resource {
        "amf-3gpp-access" => handle_amf_3gpp_access(supi, method, request),
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

/// Handle AMF 3GPP access registration context
fn handle_amf_3gpp_access(supi: &str, method: &str, request: &SbiRequest) -> SbiResponse {
    let udr_ctx = nextgcore_udrd::context::udr_self();
    match method {
        "GET" => {
            let found = udr_ctx.read().ok()
                .and_then(|ctx| ctx.ue_find(supi).map(|_| true))
                .unwrap_or(false);
            if found {
                log::debug!("[{supi}] GET amf-3gpp-access - UE context found");
                let response = serde_json::json!({
                    "amfInstanceId": "00000000-0000-0000-0000-000000000000",
                    "supi": supi,
                    "dereguCallbackUri": "",
                    "ratType": "NR",
                    "initialRegistrationInd": false
                });
                SbiResponse::with_status(200)
                    .with_body(response.to_string(), "application/json")
            } else {
                send_not_found("AMF registration context not found", Some("CONTEXT_NOT_FOUND"))
            }
        }
        "PUT" => {
            if let Some(content) = &request.http.content {
                if let Ok(reg_data) = serde_json::from_str::<serde_json::Value>(content) {
                    if let Some(pei) = reg_data.get("pei").and_then(|v| v.as_str()) {
                        let imeisv = pei.strip_prefix("imeisv-").unwrap_or(pei);
                        if let Err(e) = ogs_dbi::subscription::ogs_dbi_update_imeisv(supi, imeisv) {
                            log::error!("[{supi}] DB update_imeisv failed: {e:?}");
                        }
                    }
                }
            }
            if let Ok(mut ctx) = udr_ctx.write() {
                ctx.ue_find_or_add(supi);
            }
            SbiResponse::with_status(204)
        }
        "PATCH" => {
            if let Some(content) = &request.http.content {
                if let Ok(patches) = serde_json::from_str::<serde_json::Value>(content) {
                    if let Some(arr) = patches.as_array() {
                        for patch in arr {
                            let path = patch.get("path").and_then(|v| v.as_str()).unwrap_or("");
                            if path == "/purgeFlag" {
                                if let Some(purge) = patch.get("value").and_then(|v| v.as_bool()) {
                                    log::debug!("[{supi}] Setting purge flag to {purge}");
                                }
                            }
                        }
                    }
                }
            }
            SbiResponse::with_status(204)
        }
        "DELETE" => {
            if let Ok(mut ctx) = udr_ctx.write() {
                ctx.ue_remove(supi);
            }
            SbiResponse::with_status(204)
        }
        _ => send_method_not_allowed(method, "context-data/amf-3gpp-access"),
    }
}

/// Handle SMF registration context
fn handle_smf_registrations(supi: &str, method: &str, request: &SbiRequest, pdu_session_id: &str) -> SbiResponse {
    let udr_ctx = nextgcore_udrd::context::udr_self();
    match method {
        "GET" => {
            if pdu_session_id.is_empty() {
                let registrations = udr_ctx.read().ok()
                    .and_then(|ctx| ctx.ue_find(supi).map(|ue| {
                        ue.sessions.values()
                            .map(|sess| serde_json::json!({
                                "smfInstanceId": "00000000-0000-0000-0000-000000000000",
                                "pduSessionId": sess.psi,
                                "singleNssai": {"sst": 1},
                                "dnn": sess.dnn.as_deref().unwrap_or("internet")
                            }))
                            .collect::<Vec<_>>()
                    }))
                    .unwrap_or_default();
                SbiResponse::with_status(200)
                    .with_body(serde_json::Value::Array(registrations).to_string(), "application/json")
            } else {
                let psi: u8 = pdu_session_id.parse().unwrap_or(0);
                let response = udr_ctx.read().ok()
                    .and_then(|ctx| ctx.sess_find(supi, psi).map(|sess| {
                        serde_json::json!({
                            "smfInstanceId": "00000000-0000-0000-0000-000000000000",
                            "pduSessionId": sess.psi,
                            "singleNssai": {"sst": 1},
                            "dnn": sess.dnn.as_deref().unwrap_or("internet")
                        })
                    }));
                match response {
                    Some(json) => SbiResponse::with_status(200)
                        .with_body(json.to_string(), "application/json"),
                    None => send_not_found("SMF registration not found", Some("CONTEXT_NOT_FOUND")),
                }
            }
        }
        "PUT" => {
            let psi: u8 = pdu_session_id.parse().unwrap_or(5);
            let dnn = request.http.content.as_ref().and_then(|c| {
                serde_json::from_str::<serde_json::Value>(c).ok()
                    .and_then(|v| v.get("dnn").and_then(|d| d.as_str()).map(|s| s.to_string()))
            });
            if let Ok(mut ctx) = udr_ctx.write() {
                ctx.sess_find_or_add(supi, psi, dnn.as_deref());
            }
            SbiResponse::with_status(204)
        }
        "DELETE" => {
            if !pdu_session_id.is_empty() {
                let psi: u8 = pdu_session_id.parse().unwrap_or(0);
                if let Ok(mut ctx) = udr_ctx.write() {
                    ctx.sess_remove(supi, psi);
                }
            }
            SbiResponse::with_status(204)
        }
        _ => send_method_not_allowed(method, "context-data/smf-registrations"),
    }
}

/// Handle provisioned-data requests
/// Path: /nudr-dr/v1/subscription-data/{supi}/provisioned-data/{dataset}
async fn handle_provisioned_data(supi: &str, parts: &[&str], dataset_idx: usize, method: &str) -> SbiResponse {
    if method != "GET" {
        return send_method_not_allowed(method, "provisioned-data");
    }

    let dataset = parts.get(dataset_idx).copied().unwrap_or("");

    log::info!("[{supi}] GET provisioned-data/{dataset}");

    let subscription_data = match ogs_dbi::subscription::ogs_dbi_subscription_data(supi) {
        Ok(data) => data,
        Err(e) => {
            log::error!("[{supi}] DB subscription_data query failed: {e:?}");
            return send_not_found("Subscriber not found", Some("NOT_FOUND"));
        }
    };

    let response = match dataset {
        "am-data" => {
            build_am_data(&subscription_data)
        }
        "smf-selection-subscription-data" => {
            build_smf_selection_data(&subscription_data)
        }
        "sm-data" => {
            build_sm_data(&subscription_data)
        }
        "" => {
            // Combined provisioned data
            let mut combined = serde_json::Map::new();
            combined.insert("amData".to_string(), build_am_data(&subscription_data));
            combined.insert("smfSelData".to_string(), build_smf_selection_data(&subscription_data));
            combined.insert("smData".to_string(), build_sm_data(&subscription_data));
            serde_json::Value::Object(combined)
        }
        _ => {
            log::warn!("[{supi}] Unknown dataset: {dataset}");
            return send_not_found(&format!("Unknown dataset: {dataset}"), None);
        }
    };

    SbiResponse::with_status(200)
        .with_body(response.to_string(), "application/json")
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
        return send_not_found(&format!("Unknown policy sub-resource: {sub_resource}"), None);
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
                    // AmPolicyData - per 3GPP spec, AM policy is typically derived
                    // from subscription data, not stored separately
                    SbiResponse::with_status(200)
                        .with_body("{}".to_string(), "application/json")
                }
                _ => send_method_not_allowed(method, "policy-data/ues/am-data"),
            }
        }
        "sm-data" => {
            match method {
                "GET" => {
                    log::debug!("[{supi}] GET policy sm-data");
                    match ogs_dbi::subscription::ogs_dbi_subscription_data(supi) {
                        Ok(data) => {
                            let sm_policy_snssai_data = build_sm_policy_data(&data);
                            let response = serde_json::json!({"smPolicySnssaiData": sm_policy_snssai_data});
                            SbiResponse::with_status(200)
                                .with_body(response.to_string(), "application/json")
                        }
                        Err(_) => send_not_found("Subscriber not found", None),
                    }
                }
                "PUT" => {
                    log::debug!("[{supi}] PUT policy sm-data");
                    // Accept and acknowledge SM policy data update
                    // The PCF writes SM policy decisions back to UDR
                    if let Some(content) = &request.http.content {
                        log::debug!("[{supi}] SM policy data update: {} bytes", content.len());
                    }
                    SbiResponse::with_status(204)
                }
                _ => send_method_not_allowed(method, "policy-data/ues/sm-data"),
            }
        }
        "ue-policy-set" => {
            match method {
                "GET" => {
                    log::debug!("[{supi}] GET ue-policy-set");
                    // UePolicySet - contains URSP rules, ANDSP, etc.
                    // Per TS 29.519, return UE policy set from DB or defaults
                    match ogs_dbi::subscription::ogs_dbi_subscription_data(supi) {
                        Ok(data) => {
                            // Build a minimal UePolicySet with subscribed S-NSSAIs
                            let mut subscribed_ue_pol_sections = serde_json::Map::new();
                            for slice in &data.slice {
                                let snssai_key = if slice.s_nssai.has_sd() {
                                    format!("{:02x}-{:06x}", slice.s_nssai.sst, slice.s_nssai.sd.v)
                                } else {
                                    format!("{:02x}", slice.s_nssai.sst)
                                };
                                subscribed_ue_pol_sections.insert(snssai_key, serde_json::json!({
                                    "upsi": [],
                                    "allowedRouteSelDescs": {}
                                }));
                            }
                            let response = serde_json::json!({
                                "subscPolicySections": subscribed_ue_pol_sections
                            });
                            SbiResponse::with_status(200)
                                .with_body(response.to_string(), "application/json")
                        }
                        Err(_) => {
                            // Return empty UePolicySet as default
                            SbiResponse::with_status(200)
                                .with_body("{}".to_string(), "application/json")
                        }
                    }
                }
                "PUT" => {
                    log::debug!("[{supi}] PUT ue-policy-set");
                    // Accept UE policy set update from PCF
                    SbiResponse::with_status(204)
                }
                _ => send_method_not_allowed(method, "policy-data/ues/ue-policy-set"),
            }
        }
        _ => send_not_found(&format!("Unknown policy resource: {resource}"), None),
    }
}

/// Build SM policy data from subscription data
fn build_sm_policy_data(data: &ogs_dbi::types::OgsSubscriptionData) -> serde_json::Map<String, serde_json::Value> {
    let mut sm_policy_snssai_data = serde_json::Map::new();
    for slice in &data.slice {
        let snssai_key = if slice.s_nssai.has_sd() {
            format!("{:02x}-{:06x}", slice.s_nssai.sst, slice.s_nssai.sd.v)
        } else {
            format!("{:02x}", slice.s_nssai.sst)
        };
        let mut snssai_json = serde_json::Map::new();
        snssai_json.insert("sst".to_string(), serde_json::Value::Number(slice.s_nssai.sst.into()));
        if slice.s_nssai.has_sd() {
            snssai_json.insert("sd".to_string(), serde_json::Value::String(format!("{:06x}", slice.s_nssai.sd.v)));
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
            snssai_data.insert("smPolicyDnnData".to_string(), serde_json::Value::Object(sm_policy_dnn_data));
        }
        sm_policy_snssai_data.insert(snssai_key, serde_json::Value::Object(snssai_data));
    }
    sm_policy_snssai_data
}

// ============================================================================
// Data builders (from nudr_handler.rs, adapted for direct SBI response)
// ============================================================================

fn build_am_data(data: &ogs_dbi::types::OgsSubscriptionData) -> serde_json::Value {
    let mut am = serde_json::Map::new();
    if data.num_of_msisdn > 0 {
        let gpsis: Vec<serde_json::Value> = data.msisdn.iter()
            .map(|m| serde_json::Value::String(format!("msisdn-{}", m.bcd)))
            .collect();
        am.insert("gpsis".to_string(), serde_json::Value::Array(gpsis));
    }
    if data.ambr.uplink > 0 || data.ambr.downlink > 0 {
        am.insert("subscribedUeAmbr".to_string(), serde_json::json!({
            "uplink": format_ambr(data.ambr.uplink),
            "downlink": format_ambr(data.ambr.downlink)
        }));
    }
    if data.num_of_slice > 0 {
        let mut default_nssais = Vec::new();
        let mut single_nssais = Vec::new();
        for slice in &data.slice {
            let mut nssai_json = serde_json::Map::new();
            nssai_json.insert("sst".to_string(), serde_json::Value::Number(slice.s_nssai.sst.into()));
            if slice.s_nssai.has_sd() {
                nssai_json.insert("sd".to_string(), serde_json::Value::String(format!("{:06x}", slice.s_nssai.sd.v)));
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
            nssai.insert("defaultSingleNssais".to_string(), serde_json::Value::Array(default_nssais));
        }
        if !single_nssais.is_empty() {
            nssai.insert("singleNssais".to_string(), serde_json::Value::Array(single_nssais));
        }
        am.insert("nssai".to_string(), serde_json::Value::Object(nssai));
    }
    serde_json::Value::Object(am)
}

fn build_smf_selection_data(data: &ogs_dbi::types::OgsSubscriptionData) -> serde_json::Value {
    let mut smf_sel = serde_json::Map::new();
    let mut snssai_infos = serde_json::Map::new();
    for slice in &data.slice {
        let snssai_key = if slice.s_nssai.has_sd() {
            format!("{:02x}-{:06x}", slice.s_nssai.sst, slice.s_nssai.sd.v)
        } else {
            format!("{:02x}", slice.s_nssai.sst)
        };
        let dnn_infos: Vec<serde_json::Value> = slice.session.iter()
            .filter_map(|sess| sess.name.as_ref().map(|dnn| serde_json::json!({"dnn": dnn})))
            .collect();
        if !dnn_infos.is_empty() {
            snssai_infos.insert(snssai_key, serde_json::json!({"dnnInfos": dnn_infos}));
        }
    }
    if !snssai_infos.is_empty() {
        smf_sel.insert("subscribedSnssaiInfos".to_string(), serde_json::Value::Object(snssai_infos));
    }
    serde_json::Value::Object(smf_sel)
}

fn build_sm_data(data: &ogs_dbi::types::OgsSubscriptionData) -> serde_json::Value {
    let mut sm_data_list = Vec::new();
    for slice in &data.slice {
        let mut sm_entry = serde_json::Map::new();
        let mut snssai = serde_json::Map::new();
        snssai.insert("sst".to_string(), serde_json::Value::Number(slice.s_nssai.sst.into()));
        if slice.s_nssai.has_sd() {
            snssai.insert("sd".to_string(), serde_json::Value::String(format!("{:06x}", slice.s_nssai.sd.v)));
        }
        sm_entry.insert("singleNssai".to_string(), serde_json::Value::Object(snssai));
        let mut dnn_configs = serde_json::Map::new();
        for sess in &slice.session {
            if let Some(dnn) = &sess.name {
                let pdu_type = match sess.session_type { 1 => "IPV4", 2 => "IPV6", 3 => "IPV4V6", _ => "IPV4V6" };
                dnn_configs.insert(dnn.clone(), serde_json::json!({
                    "pduSessionTypes": { "defaultSessionType": pdu_type, "allowedSessionTypes": [pdu_type] },
                    "sscModes": { "defaultSscMode": "SSC_MODE_1", "allowedSscModes": ["SSC_MODE_1"] },
                    "5gQosProfile": { "5qi": sess.qos.index, "arp": { "priorityLevel": sess.qos.arp.priority_level } },
                    "sessionAmbr": { "uplink": format_ambr(sess.ambr.uplink), "downlink": format_ambr(sess.ambr.downlink) }
                }));
            }
        }
        if !dnn_configs.is_empty() {
            sm_entry.insert("dnnConfigurations".to_string(), serde_json::Value::Object(dnn_configs));
        }
        sm_data_list.push(serde_json::Value::Object(sm_entry));
    }
    serde_json::Value::Array(sm_data_list)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn format_ambr(bps: u64) -> String {
    if bps >= 1_000_000_000 {
        format!("{} Gbps", bps / 1_000_000_000)
    } else if bps >= 1_000_000 {
        format!("{} Mbps", bps / 1_000_000)
    } else if bps >= 1_000 {
        format!("{} Kbps", bps / 1_000)
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(mask_uri("mongodb://user:pass@host/db"), "mongodb://***@host/db");
        assert_eq!(mask_uri("mongodb://host/db"), "mongodb://host/db");
    }
}
