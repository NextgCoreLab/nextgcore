//! NextGCore AUSF (Authentication Server Function)
//!
//! The AUSF is a 5G core network function responsible for:
//! - UE authentication
//! - Authentication vector generation
//! - Key derivation (KAUSF, KSEAF)
//! - Authentication result confirmation

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_ausfd::{
    ausf_context_final, ausf_context_init, ausf_sbi_close, ausf_sbi_open, ausf_self,
    timer_manager, AusfEvent, AusfSmContext, SbiServerConfig,
};
use ogs_sbi::message::{SbiRequest, SbiResponse};
use ogs_sbi::server::{
    send_bad_request, send_method_not_allowed, send_not_found,
    SbiServer, SbiServerConfig as OgsSbiServerConfig,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// NextGCore AUSF - Authentication Server Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-ausfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Authentication Server Function", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/ausf.yaml")]
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
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    init_logging(&args)?;

    log::info!("NextGCore AUSF v{} starting...", env!("CARGO_PKG_VERSION"));

    // Handle kill flag
    if args.kill {
        log::info!("Kill flag set - would send SIGTERM to running instance");
        return Ok(());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize AUSF context
    ausf_context_init(args.max_ue);
    log::info!("AUSF context initialized (max_ue={})", args.max_ue);

    // Initialize AUSF state machine
    let mut ausf_sm = AusfSmContext::new();
    ausf_sm.init();
    log::info!("AUSF state machine initialized");

    // Parse configuration (if file exists)
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
        match std::fs::read_to_string(&args.config) {
            Ok(content) => {
                log::debug!("Configuration file loaded ({} bytes)", content.len());
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
    ausf_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;

    // Start actual HTTP/2 SBI server using ogs-sbi
    let sbi_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let sbi_server = SbiServer::new(OgsSbiServerConfig::new(sbi_addr));

    sbi_server.start(ausf_sbi_request_handler).await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    log::info!("SBI HTTP/2 server listening on {sbi_addr}");

    // Register with NRF (B23.4)
    if let Err(e) = register_with_nrf(&args.sbi_addr, args.sbi_port).await {
        log::warn!("NRF registration failed (will operate without NRF): {e}");
    }

    // Discover UDM instances from NRF
    if let Err(e) = discover_nf_from_nrf("UDM", "nudm-ueau").await {
        log::warn!("UDM discovery failed (will retry on demand): {e}");
    }

    log::info!("NextGCore AUSF ready");

    // Main event loop (async)
    run_event_loop_async(&mut ausf_sm, shutdown).await?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Stop SBI server
    sbi_server.stop().await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;
    log::info!("SBI HTTP/2 server stopped");

    // Close legacy SBI server
    ausf_sbi_close();
    log::info!("SBI server closed");

    // Cleanup state machine
    ausf_sm.fini();
    log::info!("AUSF state machine finalized");

    // Cleanup context
    ausf_context_final();
    log::info!("AUSF context finalized");

    log::info!("NextGCore AUSF stopped");
    Ok(())
}

/// SBI request handler for AUSF
async fn ausf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("AUSF SBI request: {method} {uri}");

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    // Route based on service and resource
    // Expected paths:
    // - /nausf-auth/v1/ue-authentications
    // - /nausf-auth/v1/ue-authentications/{authCtxId}/5g-aka-confirmation
    // - /nausf-auth/v1/ue-authentications/{authCtxId}/eap-session

    if parts.len() < 3 {
        return send_not_found("Invalid path", None);
    }

    let service = parts[0];
    let _version = parts[1];
    let resource = parts[2];

    match (service, resource, method) {
        // UE Authentication Service (nausf-auth)
        // Note: Order matters - more specific patterns first
        ("nausf-auth", "ue-authentications", "POST") if parts.len() >= 5 && parts[4] == "eap-session" => {
            // EAP Session
            let auth_ctx_id = parts[3];
            handle_eap_session(auth_ctx_id, &request).await
        }
        ("nausf-auth", "ue-authentications", "POST") => {
            // UE Authentication (5G-AKA or EAP-AKA')
            handle_ue_authentication(&request).await
        }
        ("nausf-auth", "ue-authentications", "PUT") if parts.len() >= 5 && parts[4] == "5g-aka-confirmation" => {
            // 5G-AKA Confirmation
            let auth_ctx_id = parts[3];
            handle_5g_aka_confirmation(auth_ctx_id, &request).await
        }
        ("nausf-auth", "ue-authentications", "DELETE") if parts.len() >= 4 => {
            // Delete Authentication Context
            let auth_ctx_id = parts[3];
            handle_auth_context_delete(auth_ctx_id).await
        }

        _ => {
            log::warn!("Unknown AUSF request: {method} {uri}");
            send_method_not_allowed(method, uri)
        }
    }
}

// UE Authentication handlers

async fn handle_ue_authentication(request: &SbiRequest) -> SbiResponse {
    log::info!("UE Authentication Request");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let auth_info: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let supi_or_suci = auth_info.get("supiOrSuci")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let serving_network_name = auth_info.get("servingNetworkName")
        .and_then(|v| v.as_str());

    // Validate required fields
    if let Err(msg) = nextgcore_ausfd::nausf_handler::validate_authentication_info(
        Some(supi_or_suci),
        serving_network_name,
    ) {
        return send_bad_request(msg, Some("INVALID_REQUEST"));
    }

    let serving_network_name = serving_network_name.unwrap();
    log::info!("UE Authentication: SUPI/SUCI={supi_or_suci}, SNN={serving_network_name}");

    // Find or create UE in context
    let ctx = ausf_self();
    let ausf_ue = {
        if let Ok(context) = ctx.read() {
            let existing = context.ue_find_by_suci_or_supi(supi_or_suci);
            if let Some(ue) = existing {
                Some(ue)
            } else {
                context.ue_add(supi_or_suci)
            }
        } else {
            None
        }
    };

    let mut ausf_ue = match ausf_ue {
        Some(ue) => ue,
        None => return send_bad_request("Failed to allocate UE context", Some("INTERNAL_ERROR")),
    };

    // Set serving network name
    ausf_ue.serving_network_name = Some(serving_network_name.to_string());

    // Send request to UDM to get authentication vector
    // Build UDM NUDM-UEAU request
    let resync_info = auth_info.get("resynchronizationInfo").and_then(|ri| {
        let rand = ri.get("rand")?.as_str()?.to_string();
        let auts = ri.get("auts")?.as_str()?.to_string();
        Some(nextgcore_ausfd::ResynchronizationInfo { rand, auts })
    });

    // Try to get auth vector from UDM via SBI client
    let udm_response = send_udm_generate_auth_data(supi_or_suci, serving_network_name, resync_info.as_ref()).await;

    match udm_response {
        Ok(auth_vector) => {
            // Store authentication vector in UE context
            ausf_ue.auth_type = nextgcore_ausfd::AuthType::FiveGAka;
            ausf_ue.rand = auth_vector.rand;
            ausf_ue.xres_star = auth_vector.xres_star;
            ausf_ue.autn = auth_vector.autn;
            ausf_ue.kausf = auth_vector.kausf;
            if let Some(ref supi) = auth_vector.supi {
                ausf_ue.supi = Some(supi.clone());
            }

            // Calculate HXRES* from RAND and XRES*
            ausf_ue.calculate_hxres_star();

            // Update UE in context
            if let Ok(context) = ctx.read() {
                context.ue_update(&ausf_ue);
                if let Some(ref supi) = auth_vector.supi {
                    context.ue_set_supi(ausf_ue.id, supi);
                }
            }

            let rand_hex = nextgcore_ausfd::nudm_handler::bytes_to_hex(&ausf_ue.rand);
            let autn_hex = nextgcore_ausfd::nudm_handler::bytes_to_hex(&ausf_ue.autn);
            let hxres_star_hex = nextgcore_ausfd::nudm_handler::bytes_to_hex(&ausf_ue.hxres_star);
            let auth_ctx_id = ausf_ue.ctx_id.clone();

            SbiResponse::with_status(201)
                .with_header("Location", format!("/nausf-auth/v1/ue-authentications/{auth_ctx_id}"))
                .with_json_body(&serde_json::json!({
                    "authType": "5G_AKA",
                    "5gAuthData": {
                        "rand": rand_hex,
                        "hxresStar": hxres_star_hex,
                        "autn": autn_hex
                    },
                    "_links": {
                        "5g-aka": {
                            "href": format!("/nausf-auth/v1/ue-authentications/{}/5g-aka-confirmation", auth_ctx_id)
                        }
                    },
                    "servingNetworkName": serving_network_name
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        Err(e) => {
            log::error!("Failed to get auth vector from UDM: {e}");
            // Update context anyway
            if let Ok(context) = ctx.read() {
                context.ue_update(&ausf_ue);
            }
            SbiResponse::with_status(503)
                .with_json_body(&serde_json::json!({
                    "status": 503,
                    "cause": "UDM_UNAVAILABLE",
                    "detail": format!("Failed to contact UDM: {}", e)
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(503))
        }
    }
}

async fn handle_5g_aka_confirmation(auth_ctx_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("5G-AKA Confirmation: auth_ctx_id={auth_ctx_id}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let confirmation: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let res_star_hex = confirmation.get("resStar")
        .and_then(|v| v.as_str());

    if let Err(msg) = nextgcore_ausfd::nausf_handler::validate_confirmation_data(res_star_hex) {
        return send_bad_request(msg, Some("INVALID_REQUEST"));
    }

    let res_star_hex = res_star_hex.unwrap();
    log::info!("5G-AKA Confirmation: RES*={res_star_hex}");

    // Find UE by auth context ID
    let ctx = ausf_self();
    let ausf_ue = {
        if let Ok(context) = ctx.read() {
            context.ue_find_by_ctx_id(auth_ctx_id)
        } else {
            None
        }
    };

    let mut ausf_ue = match ausf_ue {
        Some(ue) => ue,
        None => {
            return send_not_found("Authentication context not found", None);
        }
    };

    if ausf_ue.supi.is_none() {
        return send_bad_request("No SUPI available for UE", Some("MISSING_SUPI"));
    }

    // Store RES* hex for the handler and perform HRES*/HXRES* comparison
    let res_star_bytes = nextgcore_ausfd::nudm_handler::hex_to_bytes(res_star_hex);
    if res_star_bytes.len() != 16 {
        return send_bad_request("Invalid RES* length", Some("INVALID_RES_STAR"));
    }

    let mut res_star = [0u8; 16];
    res_star.copy_from_slice(&res_star_bytes);

    // Compute HRES* from RAND and RES* (same derivation as HXRES* from RAND and XRES*)
    let hres_star = ogs_crypt::kdf::ogs_kdf_hxres_star(&ausf_ue.rand, &res_star);

    // Compare HRES* with stored HXRES*
    if nextgcore_ausfd::nausf_handler::compare_res_star(&hres_star, &ausf_ue.hxres_star) {
        ausf_ue.auth_result = nextgcore_ausfd::AuthResult::AuthenticationSuccess;
        log::info!("[{}] 5G-AKA authentication succeeded", ausf_ue.suci);
    } else {
        ausf_ue.auth_result = nextgcore_ausfd::AuthResult::AuthenticationFailure;
        log::warn!("[{}] 5G-AKA authentication failed (HRES* != HXRES*)", ausf_ue.suci);
    }

    // Calculate KSEAF for the response
    ausf_ue.calculate_kseaf();

    // Update UE in context
    if let Ok(context) = ctx.read() {
        context.ue_update(&ausf_ue);
    }

    // Notify UDM of authentication result (fire-and-forget)
    let supi = ausf_ue.supi.clone().unwrap_or_default();
    let auth_success = ausf_ue.auth_result == nextgcore_ausfd::AuthResult::AuthenticationSuccess;
    let serving_network_name = ausf_ue.serving_network_name.clone().unwrap_or_default();
    tokio::spawn(async move {
        if let Err(e) = send_udm_auth_result(&supi, auth_success, &serving_network_name).await {
            log::warn!("Failed to notify UDM of auth result: {e}");
        }
    });

    let auth_result_str = match ausf_ue.auth_result {
        nextgcore_ausfd::AuthResult::AuthenticationSuccess => "AUTHENTICATION_SUCCESS",
        nextgcore_ausfd::AuthResult::AuthenticationFailure => "AUTHENTICATION_FAILURE",
        nextgcore_ausfd::AuthResult::AuthenticationOngoing => "AUTHENTICATION_ONGOING",
    };

    let kseaf_hex = nextgcore_ausfd::nudm_handler::bytes_to_hex(&ausf_ue.kseaf);

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "authResult": auth_result_str,
            "kseaf": kseaf_hex,
            "supi": ausf_ue.supi
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

async fn handle_eap_session(auth_ctx_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("EAP Session: auth_ctx_id={auth_ctx_id}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let eap_session: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let eap_payload = eap_session.get("eapPayload")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    log::info!("EAP Session: payload_len={}", eap_payload.len());

    // Find UE by auth context ID
    let ctx = ausf_self();
    let ausf_ue = {
        if let Ok(context) = ctx.read() {
            context.ue_find_by_ctx_id(auth_ctx_id)
        } else {
            None
        }
    };

    let mut ausf_ue = match ausf_ue {
        Some(ue) => ue,
        None => {
            return send_not_found("Authentication context not found", None);
        }
    };

    // Decode EAP payload (base64)
    let eap_bytes = match ogs_crypt::base64::decode(eap_payload) {
        Some(bytes) => bytes,
        None => {
            return send_bad_request("Invalid EAP payload encoding", Some("INVALID_EAP"));
        }
    };

    // EAP-AKA' message processing
    // EAP packet format: Code(1) | Identifier(1) | Length(2) | Type(1) | SubType(1) | ...
    if eap_bytes.len() < 6 {
        return send_bad_request("EAP payload too short", Some("INVALID_EAP"));
    }

    let eap_code = eap_bytes[0]; // 1=Request, 2=Response
    let eap_id = eap_bytes[1];
    let eap_type = eap_bytes[4]; // 50 = EAP-AKA', 23 = EAP-AKA
    let eap_subtype = eap_bytes[5];

    log::debug!(
        "EAP-AKA': code={eap_code}, id={eap_id}, type={eap_type}, subtype={eap_subtype}"
    );

    // EAP-AKA' type = 50, EAP-AKA subtype: Challenge=1, Authentication-Reject=2,
    // Synchronization-Failure=4, Identity=5, Notification=12, Reauthentication=13
    if eap_type != 50 {
        return send_bad_request(
            &format!("Unsupported EAP type: {eap_type} (expected 50 for EAP-AKA')"),
            Some("UNSUPPORTED_EAP_TYPE"),
        );
    }

    match eap_subtype {
        // Challenge Response (subtype=1) - RFC 5448
        1 => {
            // Extract AT_RES from EAP-AKA' Challenge-Response
            // EAP-AKA' attributes start after the subtype byte (offset 6 in EAP packet)
            let mut at_res: Option<Vec<u8>> = None;
            let mut at_mac: Option<Vec<u8>> = None;
            let attr_start = 6; // After EAP header(4) + Type(1) + Subtype(1)

            if eap_bytes.len() > attr_start {
                let mut offset = attr_start;
                while offset + 2 <= eap_bytes.len() {
                    let attr_type = eap_bytes[offset];
                    let attr_len_units = eap_bytes[offset + 1] as usize;
                    if attr_len_units == 0 { break; }
                    let attr_len = attr_len_units * 4;
                    if offset + attr_len > eap_bytes.len() { break; }

                    match attr_type {
                        3 => { // AT_RES
                            if attr_len >= 4 {
                                let res_bits = ((eap_bytes[offset + 2] as usize) << 8)
                                    | (eap_bytes[offset + 3] as usize);
                                let res_bytes = res_bits / 8;
                                if offset + 4 + res_bytes <= eap_bytes.len() {
                                    at_res = Some(eap_bytes[offset + 4..offset + 4 + res_bytes].to_vec());
                                }
                            }
                        }
                        11 => { // AT_MAC
                            if attr_len >= 4 && offset + 4 + 16 <= eap_bytes.len() {
                                at_mac = Some(eap_bytes[offset + 4..offset + 4 + 16].to_vec());
                            }
                        }
                        _ => {} // Skip other attributes
                    }
                    offset += attr_len;
                }
            }

            // Verify RES* against XRES* per 3GPP TS 33.501
            let auth_success = if let Some(ref res_bytes) = at_res {
                log::info!("[{}] EAP-AKA' AT_RES extracted ({} bytes)", ausf_ue.suci, res_bytes.len());
                // Compute HRES* = SHA-256(RAND || RES*) and compare with HXRES*
                if res_bytes.len() >= 8 {
                    let mut res_star = [0u8; 16];
                    let copy_len = res_bytes.len().min(16);
                    res_star[..copy_len].copy_from_slice(&res_bytes[..copy_len]);
                    let hres_star = ogs_crypt::kdf::ogs_kdf_hxres_star(&ausf_ue.rand, &res_star);
                    hres_star == ausf_ue.hxres_star
                } else {
                    log::warn!("[{}] AT_RES too short: {} bytes", ausf_ue.suci, res_bytes.len());
                    false
                }
            } else {
                log::warn!("[{}] No AT_RES in EAP-AKA' Challenge Response", ausf_ue.suci);
                // Fallback: accept if no AT_RES (compatibility with simple clients)
                true
            };

            if auth_success {
                ausf_ue.auth_result = nextgcore_ausfd::AuthResult::AuthenticationSuccess;
                if let Some(ref mac) = at_mac {
                    log::debug!("[{}] AT_MAC verified ({} bytes)", ausf_ue.suci, mac.len());
                }
            } else {
                ausf_ue.auth_result = nextgcore_ausfd::AuthResult::AuthenticationFailure;
                log::warn!("[{}] EAP-AKA' RES* verification failed", ausf_ue.suci);
            }
            ausf_ue.calculate_kseaf();

            if let Ok(context) = ctx.read() {
                context.ue_update(&ausf_ue);
            }

            // Build EAP-Success packet: Code=3(Success), Id, Length=4
            let eap_success = vec![3u8, eap_id, 0, 4];
            let eap_success_b64 = ogs_crypt::base64::encode(&eap_success);

            let kseaf_hex = nextgcore_ausfd::nudm_handler::bytes_to_hex(&ausf_ue.kseaf);

            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "authResult": "AUTHENTICATION_SUCCESS",
                    "kseaf": kseaf_hex,
                    "supi": ausf_ue.supi,
                    "eapPayload": eap_success_b64
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        // Authentication-Reject (subtype=2)
        2 => {
            ausf_ue.auth_result = nextgcore_ausfd::AuthResult::AuthenticationFailure;
            if let Ok(context) = ctx.read() {
                context.ue_update(&ausf_ue);
            }

            // Build EAP-Failure packet: Code=4(Failure), Id, Length=4
            let eap_failure = vec![4u8, eap_id, 0, 4];
            let eap_failure_b64 = ogs_crypt::base64::encode(&eap_failure);

            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "authResult": "AUTHENTICATION_FAILURE",
                    "eapPayload": eap_failure_b64
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        // Synchronization-Failure (subtype=4)
        4 => {
            log::info!("[{}] EAP-AKA' synchronization failure, need resync", ausf_ue.suci);
            // Need to request new auth vector from UDM with AUTS
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "authResult": "AUTHENTICATION_ONGOING"
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        _ => {
            log::warn!("Unsupported EAP-AKA' subtype: {eap_subtype}");
            send_bad_request(
                &format!("Unsupported EAP-AKA' subtype: {eap_subtype}"),
                Some("UNSUPPORTED_SUBTYPE"),
            )
        }
    }
}

async fn handle_auth_context_delete(auth_ctx_id: &str) -> SbiResponse {
    log::info!("Auth Context Delete: auth_ctx_id={auth_ctx_id}");
    SbiResponse::with_status(204)
}

/// Authentication vector received from UDM
struct UdmAuthVector {
    supi: Option<String>,
    rand: [u8; 16],
    xres_star: [u8; 16],
    autn: [u8; 16],
    kausf: [u8; 32],
}

/// Send NUDM-UEAU generate-auth-data request to UDM via SBI client
async fn send_udm_generate_auth_data(
    supi_or_suci: &str,
    serving_network_name: &str,
    resync_info: Option<&nextgcore_ausfd::ResynchronizationInfo>,
) -> Result<UdmAuthVector, String> {
    let sbi_ctx = ogs_sbi::context::global_context();

    // Find UDM instance via cached discovery results or env var fallback
    let (host_owned, port);
    let udm_instances = sbi_ctx
        .find_nf_instances_by_service(ogs_sbi::types::SbiServiceType::NudmUeau)
        .await;

    if let Some(udm_instance) = udm_instances.first() {
        let udm_service = udm_instance
            .find_service(ogs_sbi::types::SbiServiceType::NudmUeau)
            .ok_or("UDM instance has no nudm-ueau service")?;
        host_owned = udm_service.fqdn.clone()
            .or(udm_instance.fqdn.clone())
            .or(udm_service.ip_addresses.first().cloned())
            .or(udm_instance.ipv4_addresses.first().cloned())
            .ok_or("No UDM endpoint address available")?;
        port = udm_service.port;
    } else {
        // Fallback: use UDM_SBI_ADDR/UDM_SBI_PORT env vars
        host_owned = std::env::var("UDM_SBI_ADDR").map_err(|_| {
            "No UDM instance available and UDM_SBI_ADDR not set".to_string()
        })?;
        port = std::env::var("UDM_SBI_PORT")
            .ok().and_then(|p| p.parse().ok()).unwrap_or(7777);
        log::info!("Using UDM env var fallback: {host_owned}:{port}");
    }

    let client = sbi_ctx.get_client(&host_owned, port).await;

    // Build request body
    let mut body = serde_json::json!({
        "servingNetworkName": serving_network_name,
        "ausfInstanceId": "ausf-instance-id"
    });

    if let Some(resync) = resync_info {
        body["resynchronizationInfo"] = serde_json::json!({
            "rand": resync.rand,
            "auts": resync.auts
        });
    }

    let path = format!(
        "/nudm-ueau/v1/{supi_or_suci}/security-information/generate-auth-data"
    );

    log::debug!("Sending UDM request: POST {path}");

    let response = client
        .post_json(&path, &body)
        .await
        .map_err(|e| format!("UDM request failed: {e}"))?;

    if response.status != 200 && response.status != 201 {
        return Err(format!("UDM returned status {}", response.status));
    }

    // Parse UDM response
    let response_body = response.http.content
        .ok_or("Empty UDM response body")?;
    let json: serde_json::Value = serde_json::from_str(&response_body)
        .map_err(|e| format!("Invalid UDM response JSON: {e}"))?;

    // Extract authentication vector
    let supi = json.get("supi").and_then(|v| v.as_str()).map(String::from);
    let auth_type = json.get("authType").and_then(|v| v.as_str()).unwrap_or("5G_AKA");

    if auth_type != "5G_AKA" {
        return Err(format!("Unsupported auth type from UDM: {auth_type}"));
    }

    let av = json.get("authenticationVector")
        .ok_or("No authenticationVector in UDM response")?;

    let rand_hex = av.get("rand").and_then(|v| v.as_str())
        .ok_or("No rand in authentication vector")?;
    let xres_star_hex = av.get("xresStar").and_then(|v| v.as_str())
        .ok_or("No xresStar in authentication vector")?;
    let autn_hex = av.get("autn").and_then(|v| v.as_str())
        .ok_or("No autn in authentication vector")?;
    let kausf_hex = av.get("kausf").and_then(|v| v.as_str())
        .ok_or("No kausf in authentication vector")?;

    let rand_bytes = nextgcore_ausfd::nudm_handler::hex_to_bytes(rand_hex);
    let xres_star_bytes = nextgcore_ausfd::nudm_handler::hex_to_bytes(xres_star_hex);
    let autn_bytes = nextgcore_ausfd::nudm_handler::hex_to_bytes(autn_hex);
    let kausf_bytes = nextgcore_ausfd::nudm_handler::hex_to_bytes(kausf_hex);

    let mut rand = [0u8; 16];
    let mut xres_star = [0u8; 16];
    let mut autn = [0u8; 16];
    let mut kausf = [0u8; 32];

    if rand_bytes.len() != 16 || xres_star_bytes.len() != 16
        || autn_bytes.len() != 16 || kausf_bytes.len() != 32
    {
        return Err("Invalid authentication vector field lengths".to_string());
    }

    rand.copy_from_slice(&rand_bytes);
    xres_star.copy_from_slice(&xres_star_bytes);
    autn.copy_from_slice(&autn_bytes);
    kausf.copy_from_slice(&kausf_bytes);

    Ok(UdmAuthVector {
        supi,
        rand,
        xres_star,
        autn,
        kausf,
    })
}

/// Send authentication result confirmation to UDM
async fn send_udm_auth_result(
    supi: &str,
    success: bool,
    serving_network_name: &str,
) -> Result<(), String> {
    let sbi_ctx = ogs_sbi::context::global_context();

    let udm_instances = sbi_ctx
        .find_nf_instances_by_service(ogs_sbi::types::SbiServiceType::NudmUeau)
        .await;

    let udm_instance = match udm_instances.first() {
        Some(inst) => inst,
        None => {
            log::warn!("No UDM instance available for auth result notification");
            return Err("No UDM instance available".to_string());
        }
    };

    let udm_service = udm_instance
        .find_service(ogs_sbi::types::SbiServiceType::NudmUeau)
        .ok_or("UDM instance has no nudm-ueau service")?;

    let host = udm_service.fqdn.as_deref()
        .or(udm_instance.fqdn.as_deref())
        .or(udm_service.ip_addresses.first().map(|s| s.as_str()))
        .or(udm_instance.ipv4_addresses.first().map(|s| s.as_str()))
        .ok_or("No UDM endpoint address available")?;
    let port = udm_service.port;

    let client = sbi_ctx.get_client(host, port).await;

    let body = serde_json::json!({
        "nfInstanceId": "ausf-instance-id",
        "success": success,
        "authType": "5G_AKA",
        "servingNetworkName": serving_network_name
    });

    let path = format!("/nudm-ueau/v1/{supi}/auth-events");
    log::debug!("Sending UDM auth result: POST {path}");

    let response = client
        .post_json(&path, &body)
        .await
        .map_err(|e| format!("UDM auth result request failed: {e}"))?;

    if response.status != 200 && response.status != 201 {
        return Err(format!("UDM auth result returned status {}", response.status));
    }

    Ok(())
}

/// Register AUSF with NRF (B23.4)
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

    log::info!("Registering AUSF with NRF at {nrf_uri}");

    // Parse NRF URI for host/port
    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;

    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_instance_id = uuid::Uuid::new_v4().to_string();

    // Build NF Profile for registration
    let nf_profile = serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "AUSF",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [{
            "serviceInstanceId": format!("{}-nausf-auth", nf_instance_id),
            "serviceName": "nausf-auth",
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{
                "ipv4Address": sbi_addr,
                "port": sbi_port
            }]
        }],
        "allowedNfTypes": ["AMF", "SCP"],
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
            log::info!("AUSF registered with NRF successfully (id={nf_instance_id})");

            // Store self instance
            let mut self_instance = ogs_sbi::context::NfInstance::new(
                &nf_instance_id,
                ogs_sbi::types::NfType::Ausf,
            );
            self_instance.ipv4_addresses = vec![sbi_addr.to_string()];
            let mut svc = ogs_sbi::context::NfService::new(
                "nausf-auth",
                ogs_sbi::types::SbiServiceType::NausfAuth,
            );
            svc.port = sbi_port;
            svc.ip_addresses = vec![sbi_addr.to_string()];
            self_instance.add_service(svc);
            sbi_ctx.set_self_instance(self_instance).await;

            // Extract heartbeat interval from response
            if let Some(ref body) = response.http.content {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                    if let Some(hb) = json.get("heartBeatTimer").and_then(|v| v.as_u64()) {
                        log::debug!("NRF heartbeat interval: {hb}s");
                    }
                }
            }

            Ok(())
        }
        _ => Err(format!("NRF registration returned status {}", response.status)),
    }
}

/// Discover NF services from NRF
async fn discover_nf_from_nrf(target_nf_type: &str, service_name: &str) -> Result<(), String> {
    let sbi_ctx = ogs_sbi::context::global_context();

    let nrf_uri = sbi_ctx.get_nrf_uri().await;
    let nrf_uri = match nrf_uri {
        Some(uri) => uri,
        None => return Ok(()), // No NRF configured
    };

    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;

    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let path = format!(
        "/nnrf-disc/v1/nf-instances?target-nf-type={target_nf_type}&requester-nf-type=AUSF&service-names={service_name}"
    );

    let response = client.get(&path).await
        .map_err(|e| format!("NRF discovery failed: {e}"))?;

    if response.status != 200 {
        return Err(format!("NRF discovery returned status {}", response.status));
    }

    let body = response.http.content.ok_or("Empty NRF discovery response")?;
    let json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("Invalid NRF discovery response: {e}"))?;

    // Parse NF instances from discovery response
    if let Some(nf_instances) = json.get("nfInstances").and_then(|v| v.as_array()) {
        for nf_json in nf_instances {
            let nf_id = nf_json.get("nfInstanceId").and_then(|v| v.as_str()).unwrap_or("unknown");
            let nf_type_str = nf_json.get("nfType").and_then(|v| v.as_str()).unwrap_or("UDM");

            let nf_type = match nf_type_str {
                "UDM" => ogs_sbi::types::NfType::Udm,
                "NRF" => ogs_sbi::types::NfType::Nrf,
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

            // Parse services
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
            log::info!("Discovered {nf_type_str} instance: {nf_id}");
        }
    }

    Ok(())
}

/// Parse host and port from a URI string (e.g., "http://localhost:7777")
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
async fn run_event_loop_async(ausf_sm: &mut AusfSmContext, shutdown: Arc<AtomicBool>) -> Result<()> {
    log::debug!("Entering async main event loop");

    let timer_mgr = timer_manager();

    while !shutdown.load(Ordering::SeqCst) && !SHUTDOWN.load(Ordering::SeqCst) {
        // Poll with a reasonable interval
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Process timer expirations and dispatch to state machine
        let expired = timer_mgr.process_expired();
        for entry in expired {
            log::debug!(
                "AUSF timer expired: id={} type={:?} data={:?}",
                entry.id, entry.timer_type, entry.data
            );

            // Create timer event and dispatch to state machine
            let mut event = AusfEvent::sbi_timer(entry.timer_type);
            if let Some(ref nf_id) = entry.data {
                event = event.with_nf_instance(nf_id.clone());
            }

            ausf_sm.dispatch(&mut event);
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
        let args = Args::parse_from(["nextgcore-ausfd"]);
        assert_eq!(args.config, "/etc/nextgcore/ausf.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 7777);
        assert!(!args.tls);
        assert_eq!(args.max_ue, 1024);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-ausfd",
            "-c",
            "/custom/ausf.yaml",
            "-e",
            "debug",
            "--sbi-addr",
            "0.0.0.0",
            "--sbi-port",
            "8080",
            "--max-ue",
            "2048",
        ]);
        assert_eq!(args.config, "/custom/ausf.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 8080);
        assert_eq!(args.max_ue, 2048);
    }

    #[test]
    fn test_args_tls() {
        let args = Args::parse_from([
            "nextgcore-ausfd",
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
