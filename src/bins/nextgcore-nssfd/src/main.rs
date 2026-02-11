//! NextGCore NSSF (Network Slice Selection Function)
//!
//! The NSSF is a 5G core network function responsible for:
//! - Selecting the Network Slice instances to serve the UE
//! - Determining the allowed NSSAI and mapping to subscribed S-NSSAIs
//! - Determining the AMF Set to be used to serve the UE

use anyhow::{Context, Result};
use clap::Parser;
use ogs_sbi::message::{SbiRequest, SbiResponse};
use ogs_sbi::server::{
    send_bad_request, send_method_not_allowed, send_not_found,
    SbiServer, SbiServerConfig as OgsSbiServerConfig,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod context;
mod event;
mod nnrf_handler;
mod nsacf;
mod nnssf_build;
mod nnssf_handler;
mod nssf_sm;
mod sbi_path;
mod sbi_response;
mod timer;

pub use context::*;
pub use event::{NssfEvent, NssfEventId, NssfTimerId, SbiEventData, SbiMessage, EventSbiRequest, EventSbiResponse};
pub use timer::{timer_manager, NssfTimerManager};
pub use nnrf_handler::*;
pub use nnssf_build::*;
pub use nnssf_handler::*;
pub use nssf_sm::{NssfSmContext, NssfState};
pub use sbi_path::*;

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
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    init_logging(&args)?;

    log::info!("NextGCore NSSF v{} starting...", env!("CARGO_PKG_VERSION"));

    // Handle kill flag
    if args.kill {
        log::info!("Kill flag set - would send SIGTERM to running instance");
        return Ok(());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize NSSF context
    nssf_context_init(args.max_nf);
    log::info!("NSSF context initialized (max_nf={})", args.max_nf);

    // Initialize NSSF state machine
    let mut nssf_sm = NssfSmContext::new();
    nssf_sm.init();
    log::info!("NSSF state machine initialized");

    // Parse configuration (if file exists)
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
        match std::fs::read_to_string(&args.config) {
            Ok(content) => {
                log::debug!("Configuration file loaded ({} bytes)", content.len());
            }
            Err(e) => {
                log::warn!("Failed to read configuration file: {}", e);
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
    nssf_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;

    // Start actual HTTP/2 SBI server using ogs-sbi
    let sbi_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let sbi_server = SbiServer::new(OgsSbiServerConfig::new(sbi_addr));

    sbi_server.start(nssf_sbi_request_handler).await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {}", e))?;

    log::info!("SBI HTTP/2 server listening on {}", sbi_addr);

    // Register with NRF (B24.3)
    if let Err(e) = register_with_nrf(&args.sbi_addr, args.sbi_port).await {
        log::warn!("NRF registration failed (will operate without NRF): {}", e);
    }

    // Discover H-NSSF instances from NRF
    if let Err(e) = discover_nf_from_nrf("NSSF", "nnssf-nsselection").await {
        log::warn!("H-NSSF discovery failed (will retry on demand): {}", e);
    }

    log::info!("NextGCore NSSF ready");

    // Main event loop (async)
    run_event_loop_async(&mut nssf_sm, shutdown).await?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Stop SBI server
    sbi_server.stop().await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {}", e))?;
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

/// SBI request handler for NSSF
async fn nssf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("NSSF SBI request: {} {}", method, uri);

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    // Route based on service and resource
    // Expected paths:
    // - /nnssf-nsselection/v1/network-slice-information
    // - /nnssf-nssaiavailability/v1/nssai-availability/{nfId}

    if parts.len() < 3 {
        return send_not_found("Invalid path", None);
    }

    let service = parts[0];
    let _version = parts[1];
    let resource = parts[2];

    match (service, resource, method) {
        // NS Selection Service (nnssf-nsselection)
        ("nnssf-nsselection", "network-slice-information", "GET") => {
            // Network Slice Selection
            handle_ns_selection(&request).await
        }

        // NSSAI Availability Service (nnssf-nssaiavailability)
        ("nnssf-nssaiavailability", "nssai-availability", "PUT") if parts.len() >= 4 => {
            // Update NSSAI Availability
            let nf_id = parts[3];
            handle_nssai_availability_update(nf_id, &request).await
        }
        ("nnssf-nssaiavailability", "nssai-availability", "PATCH") if parts.len() >= 4 => {
            // Patch NSSAI Availability
            let nf_id = parts[3];
            handle_nssai_availability_patch(nf_id, &request).await
        }
        ("nnssf-nssaiavailability", "nssai-availability", "DELETE") if parts.len() >= 4 => {
            // Delete NSSAI Availability
            let nf_id = parts[3];
            handle_nssai_availability_delete(nf_id).await
        }
        ("nnssf-nssaiavailability", "nssai-availability", "OPTIONS") => {
            // Options for subscription
            handle_nssai_availability_options().await
        }

        // Subscriptions
        ("nnssf-nssaiavailability", "subscriptions", "POST") => {
            // Create subscription
            handle_subscription_create(&request).await
        }
        ("nnssf-nssaiavailability", "subscriptions", "DELETE") if parts.len() >= 4 => {
            // Delete subscription
            let subscription_id = parts[3];
            handle_subscription_delete(subscription_id).await
        }

        _ => {
            log::warn!("Unknown NSSF request: {} {}", method, uri);
            send_method_not_allowed(method, uri)
        }
    }
}

// NS Selection handlers

async fn handle_ns_selection(request: &SbiRequest) -> SbiResponse {
    // Parse query parameters
    let nf_type = request.http.params.get("nf-type")
        .map(|s| s.as_str())
        .unwrap_or("AMF");
    let nf_id = request.http.params.get("nf-id")
        .map(|s| s.as_str());

    log::info!("NS Selection: nf-type={}, nf-id={:?}", nf_type, nf_id);

    // Parse slice-info-request-for-pdu-session (JSON query param)
    let slice_info_json = request.http.params.get("slice-info-request-for-pdu-session")
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());

    // Build NsSelectionParam from query parameters
    let mut param = nnssf_handler::NsSelectionParam {
        nf_id: nf_id.map(String::from),
        nf_type: Some(nf_type.to_string()),
        ..Default::default()
    };

    // Parse slice info for PDU session
    if let Some(ref si_json) = slice_info_json {
        let sst = si_json.get("sNssai")
            .and_then(|s| s.get("sst"))
            .and_then(|v| v.as_u64())
            .map(|v| v as u8);
        let sd = si_json.get("sNssai")
            .and_then(|s| s.get("sd"))
            .and_then(|v| v.as_str())
            .and_then(|s| u32::from_str_radix(s, 16).ok());
        let roaming = si_json.get("roamingIndication")
            .and_then(|v| v.as_i64())
            .map(|v| context::RoamingIndication::from_openapi(v as i32))
            .unwrap_or_default();

        param.slice_info_for_pdu_session = nnssf_handler::SliceInfoForPduSession {
            presence: true,
            snssai: sst.map(|sst| context::SNssai::new(sst, sd)),
            roaming_indication: roaming,
        };

        // Parse home PLMN ID if present (for roaming)
        if let Some(home_plmn) = si_json.get("homePlmnId") {
            let mcc = home_plmn.get("mcc").and_then(|v| v.as_str()).unwrap_or("000");
            let mnc = home_plmn.get("mnc").and_then(|v| v.as_str()).unwrap_or("00");
            param.home_plmn_id = Some(context::PlmnId::new(mcc, mnc));
        }
        if let Some(home_snssai) = si_json.get("homeSnssai") {
            let sst = home_snssai.get("sst").and_then(|v| v.as_u64()).unwrap_or(1) as u8;
            let sd = home_snssai.get("sd").and_then(|v| v.as_str())
                .and_then(|s| u32::from_str_radix(s, 16).ok());
            param.home_snssai = Some(context::SNssai::new(sst, sd));
        }
    } else {
        // If no slice info for PDU session, try direct sNssai param
        let sst = request.http.params.get("snssai-sst")
            .and_then(|s| s.parse::<u8>().ok());
        let sd = request.http.params.get("snssai-sd")
            .and_then(|s| u32::from_str_radix(s, 16).ok());

        if let Some(sst) = sst {
            param.slice_info_for_pdu_session = nnssf_handler::SliceInfoForPduSession {
                presence: true,
                snssai: Some(context::SNssai::new(sst, sd)),
                roaming_indication: context::RoamingIndication::NonRoaming,
            };
        }
    }

    // Parse TAI if present
    if let Some(tai_str) = request.http.params.get("tai") {
        if let Ok(tai_json) = serde_json::from_str::<serde_json::Value>(tai_str) {
            let plmn_mcc = tai_json.get("plmnId").and_then(|p| p.get("mcc")).and_then(|v| v.as_str()).unwrap_or("000");
            let plmn_mnc = tai_json.get("plmnId").and_then(|p| p.get("mnc")).and_then(|v| v.as_str()).unwrap_or("00");
            let tac = tai_json.get("tac").and_then(|v| v.as_str())
                .and_then(|s| u32::from_str_radix(s, 16).ok())
                .unwrap_or(0);
            param.tai = Some(context::Tai {
                plmn_id: context::PlmnId::new(plmn_mcc, plmn_mnc),
                tac,
            });
        }
    }

    // Parse SUPI for subscription-based filtering (TS 29.531)
    let supi = request.http.params.get("supi")
        .map(|s| s.as_str().to_string());

    if let Some(ref s) = supi {
        log::debug!("NS Selection with SUPI={} for subscription-based filtering", s);
    }

    // Call the real NS selection handler
    let result = nnssf_handler::nssf_nnssf_nsselection_handle_get_from_amf_or_vnssf(0, &param);

    match result {
        nnssf_handler::NsSelectionResult::Success(info) => {
            // Build proper response
            let ctx = nssf_self();
            let context = ctx.read().unwrap();

            // Build allowedNssaiList from configured NSIs
            let all_nsi = context.nsi_get_all();
            let mut allowed_snssai_list: Vec<serde_json::Value> = all_nsi.iter().map(|nsi| {
                let mut snssai = serde_json::json!({"sst": nsi.s_nssai.sst});
                if let Some(sd) = nsi.s_nssai.sd {
                    snssai["sd"] = serde_json::json!(format!("{:06x}", sd));
                }
                serde_json::json!({"allowedSnssai": snssai})
            }).collect();

            // If no NSIs configured, use the matched one from the request
            if allowed_snssai_list.is_empty() {
                if let Some(ref si) = param.slice_info_for_pdu_session.snssai {
                    let mut snssai = serde_json::json!({"sst": si.sst});
                    if let Some(sd) = si.sd {
                        snssai["sd"] = serde_json::json!(format!("{:06x}", sd));
                    }
                    allowed_snssai_list.push(serde_json::json!({"allowedSnssai": snssai}));
                }
            }

            // Subscription-based filtering: if SUPI provided, query UDR for subscribed NSSAIs
            // and filter out any S-NSSAIs that the UE is not subscribed to (TS 29.531 6.1.3.2.3.1)
            if let Some(ref _supi) = supi {
                // Query subscribed S-NSSAIs from UDR via ogs-dbi
                match ogs_dbi::ogs_dbi_subscription_data(_supi) {
                    Ok(sub_data) => {
                        let subscribed: Vec<(u8, Option<u32>)> = sub_data.slice
                            .iter()
                            .map(|s| (s.s_nssai.sst, if s.s_nssai.sd.v == 0xFFFFFF { None } else { Some(s.s_nssai.sd.v) }))
                            .collect();

                        if !subscribed.is_empty() {
                            log::info!("Filtering allowed NSSAIs against {} subscribed slices for SUPI", subscribed.len());

                            allowed_snssai_list.retain(|item| {
                                let sst = item.get("allowedSnssai")
                                    .and_then(|s| s.get("sst"))
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0) as u8;
                                let sd = item.get("allowedSnssai")
                                    .and_then(|s| s.get("sd"))
                                    .and_then(|v| v.as_str())
                                    .and_then(|s| u32::from_str_radix(s, 16).ok());

                                subscribed.iter().any(|(sub_sst, sub_sd)| *sub_sst == sst && *sub_sd == sd)
                            });

                            log::debug!("After subscription filtering: {} allowed S-NSSAIs", allowed_snssai_list.len());
                        }
                    }
                    Err(e) => {
                        log::debug!("UDR subscription query unavailable for SUPI ({}), allowing all NSSAIs", e);
                    }
                }
            }

            // Also filter against NSSAI availability if TAI provided (TS 29.531 6.1.3.2.3.2)
            if let Some(ref tai) = param.tai {
                let supported = context.get_supported_snssai_for_tai(&context::Tai {
                    plmn_id: tai.plmn_id.clone(),
                    tac: tai.tac,
                });

                if !supported.is_empty() {
                    log::debug!("Filtering against {} NSSAI availability entries for TAI", supported.len());
                    allowed_snssai_list.retain(|item| {
                        let sst = item.get("allowedSnssai")
                            .and_then(|s| s.get("sst"))
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0) as u8;
                        let sd = item.get("allowedSnssai")
                            .and_then(|s| s.get("sd"))
                            .and_then(|v| v.as_str())
                            .and_then(|s| u32::from_str_radix(s, 16).ok());
                        supported.iter().any(|s| s.sst == sst && s.sd == sd)
                    });
                }
            }

            let allowed_snssai_list = allowed_snssai_list;

            let mut response = serde_json::json!({
                "allowedNssaiList": [{
                    "allowedSnssaiList": allowed_snssai_list,
                    "accessType": "3GPP_ACCESS"
                }],
                "supportedFeatures": "1"
            });

            // Add NSI information if available
            if let Some(nsi_info) = info.nsi_information {
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
            log::info!("NS Selection requires H-NSSF query (home_id={})", home_id);

            // Try to query H-NSSF
            match send_hnssf_query(home_id, &param).await {
                Ok(nsi_info) => {
                    SbiResponse::with_status(200)
                        .with_json_body(&serde_json::json!({
                            "nsiInformationList": [{
                                "nrfId": nsi_info.nrf_id,
                                "nsiId": nsi_info.nsi_id
                            }],
                            "supportedFeatures": "1"
                        }))
                        .unwrap_or_else(|_| SbiResponse::with_status(200))
                }
                Err(e) => {
                    log::warn!("H-NSSF query failed: {}", e);
                    SbiResponse::with_status(500)
                        .with_json_body(&serde_json::json!({
                            "status": 500,
                            "cause": "H_NSSF_UNAVAILABLE",
                            "detail": format!("H-NSSF query failed: {}", e)
                        }))
                        .unwrap_or_else(|_| SbiResponse::with_status(500))
                }
            }
        }
        nnssf_handler::NsSelectionResult::Error(status, msg) => {
            log::warn!("NS Selection error: {} - {}", status, msg);
            SbiResponse::with_status(status)
                .with_json_body(&serde_json::json!({
                    "status": status,
                    "cause": "NS_SELECTION_FAILURE",
                    "detail": msg
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(status))
        }
    }
}

// NSSAI Availability handlers

async fn handle_nssai_availability_update(nf_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("NSSAI Availability Update: nf_id={}", nf_id);

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let availability_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    // Parse and store NSSAI availability info in context (B24.4)
    let mut supported_snssai_list = Vec::new();
    let mut tai_list = Vec::new();

    if let Some(infos) = availability_data.get("nssaiAvailabilityInfos").and_then(|v| v.as_array()) {
        for info in infos {
            if let Some(snssai_list) = info.get("supportedNssaiList").and_then(|v| v.as_array()) {
                for snssai_json in snssai_list {
                    let sst = snssai_json.get("sst").and_then(|v| v.as_u64()).unwrap_or(1) as u8;
                    let sd = snssai_json.get("sd").and_then(|v| v.as_str())
                        .and_then(|s| u32::from_str_radix(s, 16).ok());
                    supported_snssai_list.push(context::SNssai::new(sst, sd));
                }
            }
            if let Some(tai_json) = info.get("tai") {
                let plmn_mcc = tai_json.get("plmnId").and_then(|p| p.get("mcc")).and_then(|v| v.as_str()).unwrap_or("000");
                let plmn_mnc = tai_json.get("plmnId").and_then(|p| p.get("mnc")).and_then(|v| v.as_str()).unwrap_or("00");
                let tac = tai_json.get("tac").and_then(|v| v.as_str())
                    .and_then(|s| u32::from_str_radix(s, 16).ok())
                    .unwrap_or(0);
                tai_list.push(context::Tai {
                    plmn_id: context::PlmnId::new(plmn_mcc, plmn_mnc),
                    tac,
                });
            }
        }
    }

    let avail_info = context::NssaiAvailabilityInfo {
        nf_id: nf_id.to_string(),
        supported_snssai_list: supported_snssai_list.clone(),
        tai_list,
    };

    let ctx = nssf_self();
    if let Ok(context) = ctx.read() {
        context.set_nssai_availability(nf_id, avail_info);
    }

    log::info!("Stored NSSAI availability for NF {}: {} S-NSSAIs", nf_id, supported_snssai_list.len());

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "authorizedNssaiAvailabilityInfo": availability_data.get("nssaiAvailabilityInfos"),
            "supportedFeatures": "1"
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

async fn handle_nssai_availability_patch(nf_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("NSSAI Availability Patch: nf_id={}", nf_id);

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let patch_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    // Apply patch to existing NSSAI availability (B24.4)
    let ctx = nssf_self();
    if let Ok(context) = ctx.read() {
        let mut avail = context.get_nssai_availability(nf_id)
            .unwrap_or_else(|| context::NssaiAvailabilityInfo {
                nf_id: nf_id.to_string(),
                supported_snssai_list: Vec::new(),
                tai_list: Vec::new(),
            });

        // Process JSON Patch operations (RFC 6902) or merge patch
        if let Some(patches) = patch_data.as_array() {
            for patch in patches {
                let op = patch.get("op").and_then(|v| v.as_str()).unwrap_or("");
                match op {
                    "add" | "replace" => {
                        if let Some(value) = patch.get("value") {
                            if let Some(snssai_list) = value.get("supportedNssaiList").and_then(|v| v.as_array()) {
                                avail.supported_snssai_list.clear();
                                for snssai_json in snssai_list {
                                    let sst = snssai_json.get("sst").and_then(|v| v.as_u64()).unwrap_or(1) as u8;
                                    let sd = snssai_json.get("sd").and_then(|v| v.as_str())
                                        .and_then(|s| u32::from_str_radix(s, 16).ok());
                                    avail.supported_snssai_list.push(context::SNssai::new(sst, sd));
                                }
                            }
                        }
                    }
                    "remove" => {
                        avail.supported_snssai_list.clear();
                    }
                    _ => {}
                }
            }
        }

        context.set_nssai_availability(nf_id, avail);
    }

    log::info!("Patched NSSAI availability for NF {}", nf_id);

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "supportedFeatures": "1"
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

async fn handle_nssai_availability_delete(nf_id: &str) -> SbiResponse {
    log::info!("NSSAI Availability Delete: nf_id={}", nf_id);

    // Remove NSSAI availability from context (B24.4)
    let ctx = nssf_self();
    if let Ok(context) = ctx.read() {
        context.remove_nssai_availability(nf_id);
    }

    SbiResponse::with_status(204)
}

async fn handle_nssai_availability_options() -> SbiResponse {
    log::debug!("NSSAI Availability Options");
    SbiResponse::with_status(200)
        .with_header("Allow", "GET, PUT, PATCH, DELETE, OPTIONS")
}

// Subscription handlers

async fn handle_subscription_create(request: &SbiRequest) -> SbiResponse {
    log::info!("NSSAI Availability Subscription Create");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let subscription_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {}", e), Some("INVALID_JSON")),
    };

    let subscription_id = uuid::Uuid::new_v4().to_string();

    log::info!("Created subscription: {}", subscription_id);

    SbiResponse::with_status(201)
        .with_header("Location", &format!("/nnssf-nssaiavailability/v1/subscriptions/{}", subscription_id))
        .with_json_body(&serde_json::json!({
            "subscriptionId": subscription_id,
            "nfNssaiAvailabilityUri": subscription_data.get("nfNssaiAvailabilityUri"),
            "expiry": subscription_data.get("expiry"),
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

async fn handle_subscription_delete(subscription_id: &str) -> SbiResponse {
    log::info!("NSSAI Availability Subscription Delete: {}", subscription_id);
    SbiResponse::with_status(204)
}

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

    let nssf_instance = nssf_instances.first().ok_or_else(|| {
        "No H-NSSF instance available for nnssf-nsselection service".to_string()
    })?;

    let nssf_service = nssf_instance
        .find_service(ogs_sbi::types::SbiServiceType::NnssfNsselection)
        .ok_or("H-NSSF instance has no nnssf-nsselection service")?;

    let host = nssf_service.fqdn.as_deref()
        .or(nssf_instance.fqdn.as_deref())
        .or(nssf_service.ip_addresses.first().map(|s| s.as_str()))
        .or(nssf_instance.ipv4_addresses.first().map(|s| s.as_str()))
        .ok_or("No H-NSSF endpoint address available")?;
    let port = nssf_service.port;

    let client = sbi_ctx.get_client(host, port).await;

    // Build query parameters
    let mut query_parts = vec![
        format!("nf-type={}", param.nf_type.as_deref().unwrap_or("AMF")),
    ];
    if let Some(ref nf_id) = param.nf_id {
        query_parts.push(format!("nf-id={}", nf_id));
    }
    if let Some(ref snssai) = param.slice_info_for_pdu_session.snssai {
        let mut si = serde_json::json!({"sNssai": {"sst": snssai.sst}});
        if let Some(sd) = snssai.sd {
            si["sNssai"]["sd"] = serde_json::json!(format!("{:06x}", sd));
        }
        query_parts.push(format!("slice-info-request-for-pdu-session={}", si));
    }

    let path = format!(
        "/nnssf-nsselection/v1/network-slice-information?{}",
        query_parts.join("&")
    );

    log::debug!("Sending H-NSSF query: GET {}", path);

    let response = client.get(&path).await
        .map_err(|e| format!("H-NSSF request failed: {}", e))?;

    if response.status != 200 {
        return Err(format!("H-NSSF returned status {}", response.status));
    }

    let body = response.http.content
        .ok_or("Empty H-NSSF response body")?;
    let json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("Invalid H-NSSF response JSON: {}", e))?;

    // Extract NSI information from response
    let nsi_info = json.get("nsiInformationList")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .ok_or("No nsiInformationList in H-NSSF response")?;

    let nrf_id = nsi_info.get("nrfId")
        .and_then(|v| v.as_str())
        .ok_or("No nrfId in H-NSSF response")?;
    let nsi_id = nsi_info.get("nsiId")
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
    let (host_port, _path) = without_scheme.split_once('/').unwrap_or((without_scheme, ""));
    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        let port: u16 = port_str.parse().ok()?;
        Some((host.to_string(), port))
    } else {
        let default_port = if uri.starts_with("https://") { 443 } else { 80 };
        Some((host_port.to_string(), default_port))
    }
}

/// Register NSSF with NRF (B24.3)
async fn register_with_nrf(sbi_addr: &str, sbi_port: u16) -> Result<(), String> {
    let sbi_ctx = ogs_sbi::context::global_context();

    let nrf_uri = sbi_ctx.get_nrf_uri().await;
    let nrf_uri = match nrf_uri {
        Some(uri) => uri,
        None => {
            log::debug!("No NRF URI configured, skipping NRF registration");
            return Ok(());
        }
    };

    log::info!("Registering NSSF with NRF at {}", nrf_uri);

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
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{
                "ipv4Address": sbi_addr,
                "port": sbi_port
            }]
        }, {
            "serviceInstanceId": format!("{}-nnssf-nssaiavailability", nf_instance_id),
            "serviceName": "nnssf-nssaiavailability",
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
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

    let path = format!("/nnrf-nfm/v1/nf-instances/{}", nf_instance_id);
    log::debug!("NRF registration: PUT {}", path);

    let response = client
        .put_json(&path, &nf_profile)
        .await
        .map_err(|e| format!("NRF registration failed: {}", e))?;

    match response.status {
        200 | 201 => {
            log::info!("NSSF registered with NRF successfully (id={})", nf_instance_id);

            let mut self_instance = ogs_sbi::context::NfInstance::new(
                &nf_instance_id,
                ogs_sbi::types::NfType::Nssf,
            );
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

            Ok(())
        }
        _ => Err(format!("NRF registration returned status {}", response.status)),
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
        "/nnrf-disc/v1/nf-instances?target-nf-type={}&requester-nf-type=NSSF&service-names={}",
        target_nf_type, service_name
    );

    let response = client.get(&path).await
        .map_err(|e| format!("NRF discovery failed: {}", e))?;

    if response.status != 200 {
        return Err(format!("NRF discovery returned status {}", response.status));
    }

    let body = response.http.content.ok_or("Empty NRF discovery response")?;
    let json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("Invalid NRF discovery response: {}", e))?;

    if let Some(nf_instances) = json.get("nfInstances").and_then(|v| v.as_array()) {
        for nf_json in nf_instances {
            let nf_id = nf_json.get("nfInstanceId").and_then(|v| v.as_str()).unwrap_or("unknown");
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
                instance.ipv4_addresses = addrs.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
            }

            if let Some(services) = nf_json.get("nfServices").and_then(|v| v.as_array()) {
                for svc_json in services {
                    let svc_name = svc_json.get("serviceName").and_then(|v| v.as_str()).unwrap_or("");
                    if let Some(svc_type) = ogs_sbi::types::SbiServiceType::from_name(svc_name) {
                        let mut svc = ogs_sbi::context::NfService::new(svc_name, svc_type);
                        if let Some(endpoints) = svc_json.get("ipEndPoints").and_then(|v| v.as_array()) {
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
            log::info!("Discovered {} instance: {}", nf_type_str, nf_id);
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
async fn run_event_loop_async(nssf_sm: &mut NssfSmContext, shutdown: Arc<AtomicBool>) -> Result<()> {
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
                entry.id, entry.timer_type, entry.data
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
}
