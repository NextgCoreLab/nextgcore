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
    ausf_context_final, ausf_context_init, ausf_sbi_close, ausf_sbi_open, ausf_self, timer_manager,
    AusfEvent, AusfSmContext, SbiServerConfig,
};
use ogs_sbi::message::{SbiRequest, SbiResponse};
use ogs_sbi::server::{
    send_bad_request, send_method_not_allowed, send_not_found, SbiServer,
    SbiServerConfig as OgsSbiServerConfig,
};
use serde::Deserialize;
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
struct SbiYaml {
    client: Option<SbiClientYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct AusfSection {
    sbi: Option<SbiYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct AusfYaml {
    ausf: Option<AusfSection>,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

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

    // Parse configuration (if file exists) and seed NRF URI
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
        match std::fs::read_to_string(&args.config) {
            Ok(content) => {
                log::debug!("Configuration file loaded ({} bytes)", content.len());
                // Seed NRF URI into SBI context for NF registration
                if let Ok(yaml) = serde_yaml::from_str::<AusfYaml>(&content) {
                    if let Some(ausf) = yaml.ausf {
                        if let Some(sbi) = ausf.sbi {
                            if let Some(client) = sbi.client {
                                if let Some(nrf_list) = client.nrf {
                                    if let Some(nrf) = nrf_list.first() {
                                        log::info!("NRF URI configured: {}", nrf.uri);
                                        ogs_sbi::context::global_context()
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
    };

    // Open legacy SBI server (for context initialization)
    ausf_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;

    // Start actual HTTP/2 SBI server using ogs-sbi
    let sbi_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let sbi_server = SbiServer::new(OgsSbiServerConfig::new(sbi_addr));

    sbi_server
        .start(ausf_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    log::info!("SBI HTTP/2 server listening on {sbi_addr}");

    // Register with NRF (B23.4)
    match register_with_nrf(&args.sbi_addr, args.sbi_port).await {
        Ok(nf_instance_id) if !nf_instance_id.is_empty() => {
            ogs_sbi::heartbeat::spawn_heartbeat_worker(nf_instance_id, 5);
        }
        Ok(_) => {}
        Err(e) => {
            log::warn!("NRF registration failed (will operate without NRF): {e}");
        }
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
    sbi_server
        .stop()
        .await
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
        ("nausf-auth", "ue-authentications", "POST")
            if parts.len() >= 5 && parts[4] == "eap-session" =>
        {
            // EAP Session
            let auth_ctx_id = parts[3];
            handle_eap_session(auth_ctx_id, &request).await
        }
        ("nausf-auth", "ue-authentications", "POST") => {
            // UE Authentication (5G-AKA or EAP-AKA')
            handle_ue_authentication(&request).await
        }
        ("nausf-auth", "ue-authentications", "PUT")
            if parts.len() >= 5 && parts[4] == "5g-aka-confirmation" =>
        {
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

    let supi_or_suci = auth_info
        .get("supiOrSuci")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let serving_network_name = auth_info.get("servingNetworkName").and_then(|v| v.as_str());

    // Validate required fields
    if let Err(msg) = nextgcore_ausfd::nausf_handler::validate_authentication_info(
        Some(supi_or_suci),
        serving_network_name,
    ) {
        return send_bad_request(msg, Some("INVALID_REQUEST"));
    }

    let serving_network_name = serving_network_name.expect("value expected");

    // TS 33.501 §6.1.2: the AUSF checks the serving network name before
    // requesting authentication material. A malformed or non-5G SNN is
    // rejected with 403 SERVING_NETWORK_NOT_AUTHORIZED (TS 29.509 §6.1.7.3).
    if !nextgcore_ausfd::nausf_handler::validate_serving_network_name(serving_network_name) {
        return send_problem(
            403,
            "SERVING_NETWORK_NOT_AUTHORIZED",
            &format!("Invalid serving network name '{serving_network_name}'"),
        );
    }

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
    let udm_response =
        send_udm_generate_auth_data(supi_or_suci, serving_network_name, resync_info.as_ref()).await;

    match udm_response {
        Ok(UdmAuthData::FiveGAka {
            supi,
            rand,
            xres_star,
            autn,
            kausf,
        }) => {
            // Store authentication vector in UE context
            ausf_ue.auth_type = nextgcore_ausfd::AuthType::FiveGAka;
            ausf_ue.rand = rand;
            ausf_ue.xres_star = xres_star;
            ausf_ue.autn = autn;
            ausf_ue.kausf = kausf;
            ausf_ue.eap_session = None;
            if let Some(ref supi) = supi {
                ausf_ue.supi = Some(supi.clone());
            }

            // Calculate HXRES* from RAND and XRES*
            ausf_ue.calculate_hxres_star();

            // Update UE in context
            if let Ok(context) = ctx.read() {
                context.ue_update(&ausf_ue);
                if let Some(ref supi) = supi {
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
        Ok(UdmAuthData::EapAkaPrime {
            supi,
            rand,
            xres,
            autn,
            ck_prime,
            ik_prime,
        }) => {
            // TS 33.501 §6.1.3.1: build EAP-Request/AKA'-Challenge from the
            // transformed AV. The peer identity for the RFC 5448 key schedule
            // is the SUPI.
            ausf_ue.auth_type = nextgcore_ausfd::AuthType::EapAkaPrime;
            if let Some(ref supi) = supi {
                ausf_ue.supi = Some(supi.clone());
            }
            let identity = ausf_ue
                .supi
                .clone()
                .unwrap_or_else(|| supi_or_suci.to_string());

            let mut session =
                nextgcore_ausfd::eap_aka_prime::EapAkaSession::new(serving_network_name);
            session.init_from_transformed_av(&rand, &autn, &xres, &ck_prime, &ik_prime, &identity);

            // KAUSF = MSB256(EMSK) is fixed by the key schedule; store it now
            ausf_ue.rand = rand;
            ausf_ue.autn = autn;
            ausf_ue.kausf = session.kausf;

            let challenge = session.generate_challenge();
            let eap_payload_b64 = ogs_crypt::base64::encode(&challenge.encode());
            ausf_ue.eap_session = Some(session);

            if let Ok(context) = ctx.read() {
                context.ue_update(&ausf_ue);
                if let Some(ref supi) = supi {
                    context.ue_set_supi(ausf_ue.id, supi);
                }
            }

            let auth_ctx_id = ausf_ue.ctx_id.clone();
            SbiResponse::with_status(201)
                .with_header(
                    "Location",
                    format!("/nausf-auth/v1/ue-authentications/{auth_ctx_id}"),
                )
                .with_json_body(&serde_json::json!({
                    "authType": "EAP_AKA_PRIME",
                    "5gAuthData": eap_payload_b64,
                    "_links": {
                        "eap-session": {
                            "href": format!("/nausf-auth/v1/ue-authentications/{auth_ctx_id}/eap-session")
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

    let res_star_hex = confirmation.get("resStar").and_then(|v| v.as_str());

    if let Err(msg) = nextgcore_ausfd::nausf_handler::validate_confirmation_data(res_star_hex) {
        return send_bad_request(msg, Some("INVALID_REQUEST"));
    }

    let res_star_hex = res_star_hex.expect("value expected");
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
        log::warn!(
            "[{}] 5G-AKA authentication failed (HRES* != HXRES*)",
            ausf_ue.suci
        );
    }

    // Calculate KSEAF for the response
    ausf_ue.calculate_kseaf();

    // Update UE in context
    if let Ok(context) = ctx.read() {
        context.ue_update(&ausf_ue);
    }

    // Notify UDM of authentication result (fire-and-forget)
    let supi = ausf_ue.supi.clone().expect("value expected");
    let auth_success = ausf_ue.auth_result == nextgcore_ausfd::AuthResult::AuthenticationSuccess;
    let serving_network_name = ausf_ue
        .serving_network_name
        .clone()
        .expect("value expected");
    tokio::spawn(async move {
        if let Err(e) =
            send_udm_auth_result(&supi, auth_success, &serving_network_name, "5G_AKA").await
        {
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

    let eap_payload = eap_session
        .get("eapPayload")
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

    // EAP packet format: Code(1) | Identifier(1) | Length(2) | Type(1) | SubType(1) | ...
    if eap_bytes.len() < 6 {
        return send_bad_request("EAP payload too short", Some("INVALID_EAP"));
    }

    let eap_code = eap_bytes[0]; // 1=Request, 2=Response
    let eap_id = eap_bytes[1];
    let eap_type = eap_bytes[4]; // 50 = EAP-AKA'
    let eap_subtype = eap_bytes[5];

    log::debug!("EAP-AKA': code={eap_code}, id={eap_id}, type={eap_type}, subtype={eap_subtype}");

    if eap_type != 50 {
        return send_bad_request(
            &format!("Unsupported EAP type: {eap_type} (expected 50 for EAP-AKA')"),
            Some("UNSUPPORTED_EAP_TYPE"),
        );
    }

    // An EAP session must have been initiated via POST /ue-authentications
    let mut session = match ausf_ue.eap_session.clone() {
        Some(s) => s,
        None => {
            return send_bad_request(
                "No EAP-AKA' session for this authentication context",
                Some("INVALID_EAP_SESSION"),
            );
        }
    };

    let auth_ctx_id_owned = auth_ctx_id.to_string();

    match eap_subtype {
        // Challenge Response (subtype=1) - RFC 5448 / RFC 9048
        1 => {
            // Full verification: AT_MAC over the packet with zeroed MAC field
            // (K_aut from the RFC 5448 key schedule), then RES against XRES.
            let auth_success = session.process_challenge_response_bytes(&eap_bytes);

            if auth_success {
                ausf_ue.auth_result = nextgcore_ausfd::AuthResult::AuthenticationSuccess;
                ausf_ue.kausf = session.kausf;
                ausf_ue.calculate_kseaf();
                log::info!("[{}] EAP-AKA' authentication succeeded", ausf_ue.suci);
            } else {
                ausf_ue.auth_result = nextgcore_ausfd::AuthResult::AuthenticationFailure;
                log::warn!(
                    "[{}] EAP-AKA' authentication failed (AT_MAC or RES mismatch)",
                    ausf_ue.suci
                );
            }
            ausf_ue.eap_session = Some(session);

            if let Ok(context) = ctx.read() {
                context.ue_update(&ausf_ue);
            }

            // Notify UDM of the authentication result (fire-and-forget)
            if let Some(supi) = ausf_ue.supi.clone() {
                if let Some(snn) = ausf_ue.serving_network_name.clone() {
                    let ok = auth_success;
                    tokio::spawn(async move {
                        if let Err(e) =
                            send_udm_auth_result(&supi, ok, &snn, "EAP_AKA_PRIME").await
                        {
                            log::warn!("Failed to notify UDM of EAP auth result: {e}");
                        }
                    });
                }
            }

            if auth_success {
                // EAP-Success keeps the identifier of the last EAP-Request
                let eap_success = vec![3u8, eap_id, 0, 4];
                SbiResponse::with_status(200)
                    .with_json_body(&serde_json::json!({
                        "authResult": "AUTHENTICATION_SUCCESS",
                        "kSeaf": nextgcore_ausfd::nudm_handler::bytes_to_hex(&ausf_ue.kseaf),
                        "supi": ausf_ue.supi,
                        "eapPayload": ogs_crypt::base64::encode(&eap_success)
                    }))
                    .unwrap_or_else(|_| SbiResponse::with_status(200))
            } else {
                let eap_failure = vec![4u8, eap_id, 0, 4];
                SbiResponse::with_status(200)
                    .with_json_body(&serde_json::json!({
                        "authResult": "AUTHENTICATION_FAILURE",
                        "eapPayload": ogs_crypt::base64::encode(&eap_failure)
                    }))
                    .unwrap_or_else(|_| SbiResponse::with_status(200))
            }
        }
        // Authentication-Reject (subtype=2)
        2 => {
            ausf_ue.auth_result = nextgcore_ausfd::AuthResult::AuthenticationFailure;
            if let Ok(context) = ctx.read() {
                context.ue_update(&ausf_ue);
            }

            let eap_failure = vec![4u8, eap_id, 0, 4];
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "authResult": "AUTHENTICATION_FAILURE",
                    "eapPayload": ogs_crypt::base64::encode(&eap_failure)
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        // Synchronization-Failure (subtype=4): extract AT_AUTS, resync with
        // the UDM (TS 33.102 §6.3.5) and issue a fresh challenge.
        4 => {
            log::info!(
                "[{}] EAP-AKA' synchronization failure, resyncing with UDM",
                ausf_ue.suci
            );
            let packet = nextgcore_ausfd::eap_aka_prime::EapPacket::decode(&eap_bytes);
            let auts = packet.as_ref().and_then(|p| {
                p.find_attribute(nextgcore_ausfd::eap_aka_prime::AkaPrimeAttribute::AtAuts)
                    .filter(|d| d.len() >= 14)
                    .map(|d| d[..14].to_vec())
            });
            let auts = match auts {
                Some(a) => a,
                None => {
                    return send_bad_request(
                        "Synchronization-Failure without AT_AUTS",
                        Some("INVALID_EAP"),
                    )
                }
            };

            let resync = nextgcore_ausfd::ResynchronizationInfo {
                rand: nextgcore_ausfd::nudm_handler::bytes_to_hex(&session.rand),
                auts: nextgcore_ausfd::nudm_handler::bytes_to_hex(&auts),
            };
            let identity = ausf_ue
                .supi
                .clone()
                .unwrap_or_else(|| ausf_ue.suci.clone());
            let snn = session.serving_network_name.clone();

            match send_udm_generate_auth_data(&identity, &snn, Some(&resync)).await {
                Ok(UdmAuthData::EapAkaPrime {
                    rand,
                    xres,
                    autn,
                    ck_prime,
                    ik_prime,
                    ..
                }) => {
                    session.init_from_transformed_av(
                        &rand, &autn, &xres, &ck_prime, &ik_prime, &identity,
                    );
                    ausf_ue.rand = rand;
                    ausf_ue.autn = autn;
                    ausf_ue.kausf = session.kausf;
                    let challenge = session.generate_challenge();
                    let eap_payload_b64 = ogs_crypt::base64::encode(&challenge.encode());
                    ausf_ue.eap_session = Some(session);

                    if let Ok(context) = ctx.read() {
                        context.ue_update(&ausf_ue);
                    }

                    SbiResponse::with_status(200)
                        .with_json_body(&serde_json::json!({
                            "eapPayload": eap_payload_b64,
                            "_links": {
                                "eap-session": {
                                    "href": format!(
                                        "/nausf-auth/v1/ue-authentications/{auth_ctx_id_owned}/eap-session"
                                    )
                                }
                            }
                        }))
                        .unwrap_or_else(|_| SbiResponse::with_status(200))
                }
                Ok(_) => {
                    log::error!("[{}] UDM returned non-EAP AV on resync", ausf_ue.suci);
                    send_problem(500, "UNSPECIFIED", "UDM returned non-EAP AV on resync")
                }
                Err(e) => {
                    log::error!("[{}] Resync with UDM failed: {e}", ausf_ue.suci);
                    send_problem(403, "AUTHENTICATION_REJECTED", "Resynchronization failed")
                }
            }
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

/// Authentication data received from UDM (TS 29.503 AuthenticationInfoResult)
enum UdmAuthData {
    /// 5G-AKA home environment AV (avType 5G_HE_AKA)
    FiveGAka {
        supi: Option<String>,
        rand: [u8; 16],
        xres_star: [u8; 16],
        autn: [u8; 16],
        kausf: [u8; 32],
    },
    /// EAP-AKA' transformed AV (avType EAP_AKA_PRIME): RAND, AUTN, XRES, CK', IK'
    EapAkaPrime {
        supi: Option<String>,
        rand: [u8; 16],
        xres: Vec<u8>,
        autn: [u8; 16],
        ck_prime: [u8; 16],
        ik_prime: [u8; 16],
    },
}

/// Send NUDM-UEAU generate-auth-data request to UDM via SBI client
async fn send_udm_generate_auth_data(
    supi_or_suci: &str,
    serving_network_name: &str,
    resync_info: Option<&nextgcore_ausfd::ResynchronizationInfo>,
) -> Result<UdmAuthData, String> {
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
        host_owned = udm_service
            .fqdn
            .clone()
            .or(udm_instance.fqdn.clone())
            .or(udm_service.ip_addresses.first().cloned())
            .or(udm_instance.ipv4_addresses.first().cloned())
            .ok_or("No UDM endpoint address available")?;
        port = udm_service.port;
    } else {
        // Fallback: use UDM_SBI_ADDR/UDM_SBI_PORT env vars
        host_owned = std::env::var("UDM_SBI_ADDR")
            .map_err(|_| "No UDM instance available and UDM_SBI_ADDR not set".to_string())?;
        port = std::env::var("UDM_SBI_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(7777);
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

    let path = format!("/nudm-ueau/v1/{supi_or_suci}/security-information/generate-auth-data");

    log::debug!("Sending UDM request: POST {path}");

    let response = client
        .post_json(&path, &body)
        .await
        .map_err(|e| format!("UDM request failed: {e}"))?;

    if response.status != 200 && response.status != 201 {
        return Err(format!("UDM returned status {}", response.status));
    }

    // Parse UDM response
    let response_body = response.http.content.ok_or("Empty UDM response body")?;
    let json: serde_json::Value = serde_json::from_str(&response_body)
        .map_err(|e| format!("Invalid UDM response JSON: {e}"))?;

    // Extract authentication vector
    let supi = json.get("supi").and_then(|v| v.as_str()).map(String::from);
    let auth_type = json
        .get("authType")
        .and_then(|v| v.as_str())
        .unwrap_or("5G_AKA");

    let av = json
        .get("authenticationVector")
        .ok_or("No authenticationVector in UDM response")?;

    let get_hex = |field: &str| -> Result<Vec<u8>, String> {
        let hex = av
            .get(field)
            .and_then(|v| v.as_str())
            .ok_or(format!("No {field} in authentication vector"))?;
        Ok(nextgcore_ausfd::nudm_handler::hex_to_bytes(hex))
    };

    match auth_type {
        "5G_AKA" => {
            let rand_bytes = get_hex("rand")?;
            let xres_star_bytes = get_hex("xresStar")?;
            let autn_bytes = get_hex("autn")?;
            let kausf_bytes = get_hex("kausf")?;

            if rand_bytes.len() != 16
                || xres_star_bytes.len() != 16
                || autn_bytes.len() != 16
                || kausf_bytes.len() != 32
            {
                return Err("Invalid authentication vector field lengths".to_string());
            }

            let mut rand = [0u8; 16];
            let mut xres_star = [0u8; 16];
            let mut autn = [0u8; 16];
            let mut kausf = [0u8; 32];
            rand.copy_from_slice(&rand_bytes);
            xres_star.copy_from_slice(&xres_star_bytes);
            autn.copy_from_slice(&autn_bytes);
            kausf.copy_from_slice(&kausf_bytes);

            Ok(UdmAuthData::FiveGAka {
                supi,
                rand,
                xres_star,
                autn,
                kausf,
            })
        }
        "EAP_AKA_PRIME" => {
            let rand_bytes = get_hex("rand")?;
            let xres = get_hex("xres")?;
            let autn_bytes = get_hex("autn")?;
            let ck_prime_bytes = get_hex("ckPrime")?;
            let ik_prime_bytes = get_hex("ikPrime")?;

            if rand_bytes.len() != 16
                || autn_bytes.len() != 16
                || ck_prime_bytes.len() != 16
                || ik_prime_bytes.len() != 16
                || xres.is_empty()
            {
                return Err("Invalid EAP-AKA' authentication vector field lengths".to_string());
            }

            let mut rand = [0u8; 16];
            let mut autn = [0u8; 16];
            let mut ck_prime = [0u8; 16];
            let mut ik_prime = [0u8; 16];
            rand.copy_from_slice(&rand_bytes);
            autn.copy_from_slice(&autn_bytes);
            ck_prime.copy_from_slice(&ck_prime_bytes);
            ik_prime.copy_from_slice(&ik_prime_bytes);

            Ok(UdmAuthData::EapAkaPrime {
                supi,
                rand,
                xres,
                autn,
                ck_prime,
                ik_prime,
            })
        }
        other => Err(format!("Unsupported auth type from UDM: {other}")),
    }
}

/// Send authentication result confirmation to UDM
async fn send_udm_auth_result(
    supi: &str,
    success: bool,
    serving_network_name: &str,
    auth_type: &str,
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

    let host = udm_service
        .fqdn
        .as_deref()
        .or(udm_instance.fqdn.as_deref())
        .or(udm_service.ip_addresses.first().map(|s| s.as_str()))
        .or(udm_instance.ipv4_addresses.first().map(|s| s.as_str()))
        .ok_or("No UDM endpoint address available")?;
    let port = udm_service.port;

    let client = sbi_ctx.get_client(host, port).await;

    let body = serde_json::json!({
        "nfInstanceId": ogs_sbi::context::global_context()
            .get_self_instance()
            .await
            .map(|i| i.id)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        "success": success,
        "authType": auth_type,
        "timeStamp": nextgcore_ausfd::nudm_build::get_current_timestamp(),
        "servingNetworkName": serving_network_name
    });

    let path = format!("/nudm-ueau/v1/{supi}/auth-events");
    log::debug!("Sending UDM auth result: POST {path}");

    let response = client
        .post_json(&path, &body)
        .await
        .map_err(|e| format!("UDM auth result request failed: {e}"))?;

    if response.status != 200 && response.status != 201 {
        return Err(format!(
            "UDM auth result returned status {}",
            response.status
        ));
    }

    Ok(())
}

/// Register AUSF with NRF (B23.4)
///
/// Returns the NF instance ID that was registered, so callers can start a
/// heartbeat worker for the same instance.
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
            let mut self_instance =
                ogs_sbi::context::NfInstance::new(&nf_instance_id, ogs_sbi::types::NfType::Ausf);
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

            Ok(nf_instance_id)
        }
        _ => Err(format!(
            "NRF registration returned status {}",
            response.status
        )),
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

    // Parse NF instances from discovery response
    if let Some(nf_instances) = json.get("nfInstances").and_then(|v| v.as_array()) {
        for nf_json in nf_instances {
            let nf_id = nf_json
                .get("nfInstanceId")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let nf_type_str = nf_json
                .get("nfType")
                .and_then(|v| v.as_str())
                .unwrap_or("UDM");

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
                instance.ipv4_addresses = addrs
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
            }

            // Parse services
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

/// Parse host and port from a URI string (e.g., "http://localhost:7777")
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
    ausf_sm: &mut AusfSmContext,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
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
                entry.id,
                entry.timer_type,
                entry.data
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

    // ========================================================================
    // HTTP-level AUSF <-> UDM authentication flow (TS 29.509 / TS 33.501)
    //
    // Real ausf_sbi_request_handler served over HTTP/2 on an ephemeral port,
    // talking to a spec-shaped mock UDM (real Milenage + 5G KDFs) on another
    // ephemeral port via the UDM_SBI_ADDR/UDM_SBI_PORT fallback.
    // ========================================================================

    /// Shared test subscriber credentials (standard 3GPP test K/OPc).
    const TEST_K: [u8; 16] = [
        0x46, 0x5B, 0x5C, 0xE8, 0xB1, 0x99, 0xB4, 0x9F, 0xAA, 0x5F, 0x0A, 0x2E, 0xE2, 0x38, 0xA6,
        0xBC,
    ];
    const TEST_OPC: [u8; 16] = [
        0xE8, 0xED, 0x28, 0x9D, 0xEB, 0xA9, 0x52, 0xE4, 0x28, 0x3B, 0x54, 0xE8, 0x8E, 0x61, 0x83,
        0xCA,
    ];
    const SUPI_5G_AKA: &str = "imsi-001010000000001";
    const SUPI_EAP: &str = "imsi-001010000000002";
    const TEST_SNN: &str = "5G:mnc001.mcc001.3gppnetwork.org";

    /// Spec-shaped mock UDM: real Milenage + TS 33.501 KDFs, AMF separation
    /// bit set, EAP_AKA_PRIME for SUPI_EAP, 5G_AKA otherwise.
    async fn mock_udm_handler(request: SbiRequest) -> SbiResponse {
        use nextgcore_ausfd::nudm_handler::bytes_to_hex;

        let uri = request.header.uri.clone();
        let path = uri.split('?').next().unwrap_or(&uri).to_string();

        if path.ends_with("/auth-events") {
            return SbiResponse::with_status(201);
        }
        if !path.contains("generate-auth-data") {
            return SbiResponse::with_status(404);
        }

        let supi = path
            .trim_start_matches('/')
            .split('/')
            .nth(2)
            .unwrap_or("")
            .to_string();
        let body: serde_json::Value = request
            .http
            .content
            .as_deref()
            .and_then(|b| serde_json::from_str(b).ok())
            .unwrap_or_default();
        let snn = body
            .get("servingNetworkName")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        let amf = [0x80u8, 0x00]; // separation bit set
        let sqn = [0x00u8, 0x00, 0x00, 0x00, 0x00, 0x21];
        let mut rand = [0u8; 16];
        ogs_core::rand::ogs_random(&mut rand);

        let (autn, ik, ck, _ak, res) =
            ogs_crypt::milenage::milenage_generate(&TEST_OPC, &amf, &TEST_K, &sqn, &rand)
                .expect("milenage");

        if supi == SUPI_EAP {
            let mut sqn_xor_ak = [0u8; 6];
            sqn_xor_ak.copy_from_slice(&autn[..6]);
            let (ck_prime, ik_prime) =
                ogs_crypt::kdf::ogs_kdf_ck_ik_prime(&ck, &ik, &snn, &sqn_xor_ak);
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
                .unwrap_or_else(|_| SbiResponse::with_status(500))
        } else {
            let kausf = ogs_crypt::kdf::ogs_kdf_kausf(&ck, &ik, &snn, &autn);
            let xres_star = ogs_crypt::kdf::ogs_kdf_xres_star(&ck, &ik, &snn, &rand, &res);
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
                .unwrap_or_else(|_| SbiResponse::with_status(500))
        }
    }

    fn free_port() -> u16 {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let port = probe.local_addr().expect("addr").port();
        drop(probe);
        port
    }

    /// Full HTTP-level flow: 5G-AKA success + failure, EAP-AKA' success +
    /// failure, strict-peer rejections (missing attrs, bad SNN).
    ///
    /// Single test function: it owns the process-wide UDM_SBI_ADDR/PORT env
    /// fallback and the global AUSF context.
    #[tokio::test]
    async fn test_http_auth_flows_5g_aka_and_eap_aka_prime() {
        let _ = env_logger::try_init();
        tokio::time::timeout(Duration::from_secs(60), async {
            ausf_context_init(64);

            // --- mock UDM on an ephemeral port ---
            let udm_port = free_port();
            let udm_server = SbiServer::new(OgsSbiServerConfig::new(SocketAddr::from((
                [127, 0, 0, 1],
                udm_port,
            ))));
            udm_server.start(mock_udm_handler).await.expect("udm start");
            std::env::set_var("UDM_SBI_ADDR", "127.0.0.1");
            std::env::set_var("UDM_SBI_PORT", udm_port.to_string());

            // --- real AUSF handler on an ephemeral port ---
            let ausf_port = free_port();
            let ausf_server = SbiServer::new(OgsSbiServerConfig::new(SocketAddr::from((
                [127, 0, 0, 1],
                ausf_port,
            ))));
            ausf_server
                .start(ausf_sbi_request_handler)
                .await
                .expect("ausf start");

            let client = ogs_sbi::client::SbiClient::with_host_port("127.0.0.1", ausf_port);

            // ---- strict-peer rejections ----
            // Missing servingNetworkName -> 400
            let resp = client
                .post_json("/nausf-auth/v1/ue-authentications", &serde_json::json!({"supiOrSuci": SUPI_5G_AKA}))
                .await
                .expect("send");
            assert_eq!(resp.status, 400, "missing SNN must be rejected");

            // Malformed serving network name -> 403 SERVING_NETWORK_NOT_AUTHORIZED
            let resp = client
                .post_json("/nausf-auth/v1/ue-authentications", &serde_json::json!({
                            "supiOrSuci": SUPI_5G_AKA,
                            "servingNetworkName": "EPS:mnc001.mcc001.3gppnetwork.org"
                        }))
                .await
                .expect("send");
            assert_eq!(resp.status, 403);
            let pd: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).unwrap();
            assert_eq!(
                pd.get("cause").and_then(|v| v.as_str()),
                Some("SERVING_NETWORK_NOT_AUTHORIZED")
            );

            // ---- 5G-AKA success ----
            let resp = client
                .post_json("/nausf-auth/v1/ue-authentications", &serde_json::json!({
                            "supiOrSuci": SUPI_5G_AKA,
                            "servingNetworkName": TEST_SNN
                        }))
                .await
                .expect("send");
            assert_eq!(resp.status, 201);
            let ctx_json: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().expect("body")).unwrap();
            assert_eq!(
                ctx_json.get("authType").and_then(|v| v.as_str()),
                Some("5G_AKA")
            );
            let auth_data = ctx_json.get("5gAuthData").expect("5gAuthData");
            let rand_hex = auth_data.get("rand").and_then(|v| v.as_str()).unwrap();
            let autn_hex = auth_data.get("autn").and_then(|v| v.as_str()).unwrap();
            assert!(auth_data.get("hxresStar").is_some());
            assert_eq!(autn_hex.len(), 32);
            let href = ctx_json
                .pointer("/_links/5g-aka/href")
                .and_then(|v| v.as_str())
                .expect("5g-aka link");

            // UE side: compute RES* from RAND with the shared credentials
            let rand_bytes = nextgcore_ausfd::nudm_handler::hex_to_bytes(rand_hex);
            let mut rand = [0u8; 16];
            rand.copy_from_slice(&rand_bytes);
            let (res, ck, ik, _ak, _akstar) =
                ogs_crypt::milenage::milenage_f2345(&TEST_OPC, &TEST_K, &rand).unwrap();
            let res_star =
                ogs_crypt::kdf::ogs_kdf_xres_star(&ck, &ik, TEST_SNN, &rand, &res);

            // Wrong RES* first -> AUTHENTICATION_FAILURE
            let resp = client
                .put_json(href, &serde_json::json!({
                            "resStar": "00000000000000000000000000000000"
                        }))
                .await
                .expect("send");
            assert_eq!(resp.status, 200);
            let conf: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(
                conf.get("authResult").and_then(|v| v.as_str()),
                Some("AUTHENTICATION_FAILURE")
            );

            // Correct RES* -> AUTHENTICATION_SUCCESS with KSEAF
            let resp = client
                .put_json(href, &serde_json::json!({
                            "resStar": nextgcore_ausfd::nudm_handler::bytes_to_hex(&res_star)
                        }))
                .await
                .expect("send");
            assert_eq!(resp.status, 200);
            let conf: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(
                conf.get("authResult").and_then(|v| v.as_str()),
                Some("AUTHENTICATION_SUCCESS")
            );
            assert_eq!(
                conf.get("supi").and_then(|v| v.as_str()),
                Some(SUPI_5G_AKA)
            );
            let kseaf_hex = conf.get("kseaf").and_then(|v| v.as_str()).expect("kseaf");
            assert_eq!(kseaf_hex.len(), 64);

            // ---- EAP-AKA' success ----
            let resp = client
                .post_json("/nausf-auth/v1/ue-authentications", &serde_json::json!({
                            "supiOrSuci": SUPI_EAP,
                            "servingNetworkName": TEST_SNN
                        }))
                .await
                .expect("send");
            assert_eq!(resp.status, 201);
            let ctx_json: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().expect("body")).unwrap();
            assert_eq!(
                ctx_json.get("authType").and_then(|v| v.as_str()),
                Some("EAP_AKA_PRIME")
            );
            let eap_b64 = ctx_json
                .get("5gAuthData")
                .and_then(|v| v.as_str())
                .expect("eap payload");
            let eap_href = ctx_json
                .pointer("/_links/eap-session/href")
                .and_then(|v| v.as_str())
                .expect("eap-session link")
                .to_string();

            // UE side: decode the EAP-Request/AKA'-Challenge
            use nextgcore_ausfd::eap_aka_prime::{
                compute_mac, derive_keys_aka_prime, zero_at_mac, AkaPrimeAttribute,
                AkaPrimeSubtype, EapCode, EapPacket, EapType,
            };
            let challenge_bytes = ogs_crypt::base64::decode(eap_b64).expect("b64");
            let challenge = EapPacket::decode(&challenge_bytes).expect("decode");
            assert_eq!(challenge.code, EapCode::Request);
            assert_eq!(challenge.subtype, Some(AkaPrimeSubtype::Challenge));
            let at_rand = challenge.find_attribute(AkaPrimeAttribute::AtRand).unwrap();
            let at_autn = challenge.find_attribute(AkaPrimeAttribute::AtAutn).unwrap();
            let mut rand = [0u8; 16];
            rand.copy_from_slice(&at_rand[2..18]);
            let mut autn = [0u8; 16];
            autn.copy_from_slice(&at_autn[2..18]);

            // UE side: run Milenage + the RFC 5448 key schedule
            // (RES itself is unused in the failure-path exchange below)
            let (_res, ck, ik, _ak, _akstar) =
                ogs_crypt::milenage::milenage_f2345(&TEST_OPC, &TEST_K, &rand).unwrap();
            let mut sqn_xor_ak = [0u8; 6];
            sqn_xor_ak.copy_from_slice(&autn[..6]);
            let (ck_prime, ik_prime) =
                ogs_crypt::kdf::ogs_kdf_ck_ik_prime(&ck, &ik, TEST_SNN, &sqn_xor_ak);
            let ue_keys = derive_keys_aka_prime(&ck_prime, &ik_prime, SUPI_EAP);

            // UE side: verify the network's AT_MAC over the challenge
            let at_mac = challenge.find_attribute(AkaPrimeAttribute::AtMac).unwrap();
            let mut net_mac = [0u8; 16];
            net_mac.copy_from_slice(&at_mac[2..18]);
            let zeroed = zero_at_mac(&challenge_bytes).unwrap();
            assert_eq!(
                compute_mac(&ue_keys.k_aut, &zeroed),
                net_mac,
                "UE must be able to verify the network AT_MAC"
            );

            // Build EAP-Response/AKA'-Challenge with AT_RES + AT_MAC
            let build_eap_response = |res: &[u8], identifier: u8| -> Vec<u8> {
                let mut response = EapPacket {
                    code: EapCode::Response,
                    identifier,
                    eap_type: Some(EapType::AkaPrime),
                    subtype: Some(AkaPrimeSubtype::Challenge),
                    attributes: Vec::new(),
                };
                let res_bits = (res.len() * 8) as u16;
                let mut res_attr = Vec::new();
                res_attr.extend_from_slice(&res_bits.to_be_bytes());
                res_attr.extend_from_slice(res);
                response
                    .attributes
                    .push((AkaPrimeAttribute::AtRes as u8, res_attr));
                response
                    .attributes
                    .push((AkaPrimeAttribute::AtMac as u8, vec![0u8; 18]));
                let encoded = response.encode();
                let mac = compute_mac(&ue_keys.k_aut, &encoded);
                response.set_mac(&mac);
                response.encode()
            };

            // Failure first: wrong RES (valid MAC over that packet)
            let bad_response = build_eap_response(&[0xFFu8; 8], challenge.identifier);
            let resp = client
                .post_json(&eap_href, &serde_json::json!({
                            "eapPayload": ogs_crypt::base64::encode(&bad_response)
                        }))
                .await
                .expect("send");
            assert_eq!(resp.status, 200);
            let sess: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(
                sess.get("authResult").and_then(|v| v.as_str()),
                Some("AUTHENTICATION_FAILURE")
            );
            // EAP-Failure packet returned
            let fail_payload = sess.get("eapPayload").and_then(|v| v.as_str()).unwrap();
            assert_eq!(ogs_crypt::base64::decode(fail_payload).unwrap()[0], 4);

            // Re-arm: a failed EAP exchange ends the session; start a new one
            let resp = client
                .post_json("/nausf-auth/v1/ue-authentications", &serde_json::json!({
                            "supiOrSuci": SUPI_EAP,
                            "servingNetworkName": TEST_SNN
                        }))
                .await
                .expect("send");
            assert_eq!(resp.status, 201);
            let ctx_json: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            let eap_b64 = ctx_json
                .get("5gAuthData")
                .and_then(|v| v.as_str())
                .unwrap();
            let eap_href = ctx_json
                .pointer("/_links/eap-session/href")
                .and_then(|v| v.as_str())
                .unwrap()
                .to_string();
            let challenge_bytes = ogs_crypt::base64::decode(eap_b64).unwrap();
            let challenge = EapPacket::decode(&challenge_bytes).unwrap();
            let at_rand = challenge.find_attribute(AkaPrimeAttribute::AtRand).unwrap();
            let at_autn = challenge.find_attribute(AkaPrimeAttribute::AtAutn).unwrap();
            let mut rand = [0u8; 16];
            rand.copy_from_slice(&at_rand[2..18]);
            let mut autn = [0u8; 16];
            autn.copy_from_slice(&at_autn[2..18]);
            let (res, ck, ik, _ak, _akstar) =
                ogs_crypt::milenage::milenage_f2345(&TEST_OPC, &TEST_K, &rand).unwrap();
            let mut sqn_xor_ak = [0u8; 6];
            sqn_xor_ak.copy_from_slice(&autn[..6]);
            let (ck_prime, ik_prime) =
                ogs_crypt::kdf::ogs_kdf_ck_ik_prime(&ck, &ik, TEST_SNN, &sqn_xor_ak);
            let ue_keys = derive_keys_aka_prime(&ck_prime, &ik_prime, SUPI_EAP);
            let build_eap_response2 = |res: &[u8], identifier: u8| -> Vec<u8> {
                let mut response = EapPacket {
                    code: EapCode::Response,
                    identifier,
                    eap_type: Some(EapType::AkaPrime),
                    subtype: Some(AkaPrimeSubtype::Challenge),
                    attributes: Vec::new(),
                };
                let res_bits = (res.len() * 8) as u16;
                let mut res_attr = Vec::new();
                res_attr.extend_from_slice(&res_bits.to_be_bytes());
                res_attr.extend_from_slice(res);
                response
                    .attributes
                    .push((AkaPrimeAttribute::AtRes as u8, res_attr));
                response
                    .attributes
                    .push((AkaPrimeAttribute::AtMac as u8, vec![0u8; 18]));
                let encoded = response.encode();
                let mac = compute_mac(&ue_keys.k_aut, &encoded);
                response.set_mac(&mac);
                response.encode()
            };
            let good_response = build_eap_response2(&res, challenge.identifier);
            let resp = client
                .post_json(&eap_href, &serde_json::json!({
                            "eapPayload": ogs_crypt::base64::encode(&good_response)
                        }))
                .await
                .expect("send");
            assert_eq!(resp.status, 200);
            let sess: serde_json::Value =
                serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
            assert_eq!(
                sess.get("authResult").and_then(|v| v.as_str()),
                Some("AUTHENTICATION_SUCCESS")
            );
            assert_eq!(sess.get("supi").and_then(|v| v.as_str()), Some(SUPI_EAP));
            // EAP-Success packet returned
            let ok_payload = sess.get("eapPayload").and_then(|v| v.as_str()).unwrap();
            assert_eq!(ogs_crypt::base64::decode(ok_payload).unwrap()[0], 3);

            // UE side derives the same KSEAF: KAUSF = MSB256(EMSK)
            let mut ue_kausf = [0u8; 32];
            ue_kausf.copy_from_slice(&ue_keys.emsk[..32]);
            let ue_kseaf = ogs_crypt::kdf::ogs_kdf_kseaf(TEST_SNN, &ue_kausf);
            assert_eq!(
                sess.get("kSeaf").and_then(|v| v.as_str()),
                Some(nextgcore_ausfd::nudm_handler::bytes_to_hex(&ue_kseaf).as_str()),
                "AUSF KSEAF must match the UE-derived KSEAF"
            );

            ausf_server.stop().await.expect("stop ausf");
            udm_server.stop().await.expect("stop udm");
        })
        .await
        .expect("test timed out");
    }
}
