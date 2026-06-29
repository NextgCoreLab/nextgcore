//! NextGCore UDM (Unified Data Management)
//!
//! The UDM is a 5G core network function responsible for:
//! - Subscriber data management
//! - Authentication credential processing
//! - Subscription management
//! - UE context management (AMF/SMF registration)

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_udmd::{
    timer_manager, timer_type_to_timer_id, udm_context_final, udm_context_init, udm_sbi_close,
    udm_sbi_open, udm_self, SbiServerConfig, UdmEvent, UdmSmContext,
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

#[derive(Debug, Default, Deserialize)]
struct UdmSection {
    sbi: Option<SbiYaml>,
    hnet: Option<Vec<HnetYaml>>,
}

#[derive(Debug, Default, Deserialize)]
struct UdmYaml {
    udm: Option<UdmSection>,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

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
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
        match std::fs::read_to_string(&args.config) {
            Ok(content) => {
                log::debug!("Configuration file loaded ({} bytes)", content.len());
                // Seed NRF URI into SBI context for NF registration
                if let Ok(yaml) = serde_yaml::from_str::<UdmYaml>(&content) {
                    if let Some(udm) = yaml.udm {
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
                                        ogs_sbi::context::global_context()
                                            .set_nrf_uri(&nrf.uri)
                                            .await;
                                    }
                                }
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

    // Start actual HTTP/2 SBI server using ogs-sbi
    let sbi_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let sbi_server = SbiServer::new(OgsSbiServerConfig::new(sbi_addr));

    sbi_server
        .start(udm_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    log::info!("SBI HTTP/2 server listening on {sbi_addr}");

    // Register with NRF and start heartbeat worker
    match register_with_nrf(&args.sbi_addr, args.sbi_port).await {
        Ok(nf_instance_id) if !nf_instance_id.is_empty() => {
            ogs_sbi::heartbeat::spawn_heartbeat_worker(nf_instance_id, 5);
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
async fn udm_sbi_request_handler(request: SbiRequest) -> SbiResponse {
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
    // - /nudm-sdm/v1/{supi}/am-data
    // - /nudm-sdm/v1/{supi}/smf-select-data
    // - /nudm-sdm/v1/{supi}/sm-data
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
                _ => send_method_not_allowed(method, uri),
            }
        }

        // Subscriber Data Management Service (nudm-sdm)
        "nudm-sdm" if parts.len() >= 4 => {
            let supi = parts[2];
            let resource = parts.get(3).unwrap_or(&"");

            match (*resource, method) {
                ("am-data", "GET") => handle_get_am_data(supi, &request).await,
                ("smf-select-data", "GET") => handle_get_smf_select_data(supi, &request).await,
                ("sm-data", "GET") => handle_get_sm_data(supi, &request).await,
                ("nssai", "GET") => handle_get_nssai(supi, &request).await,
                ("sdm-subscriptions", "POST") => handle_sdm_subscribe(supi, &request).await,
                ("sdm-subscriptions", "DELETE") if parts.len() >= 5 => {
                    let subscription_id = parts[4];
                    handle_sdm_unsubscribe(supi, subscription_id).await
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

        _ => {
            log::warn!("Unknown UDM request: {method} {uri}");
            send_method_not_allowed(method, uri)
        }
    }
}

// UE Context Management handlers

async fn handle_amf_registration(supi: &str, request: &SbiRequest) -> SbiResponse {
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
    nextgcore_udmd::uecm::process_amf_registration(
        supi,
        &reg_data,
        &nextgcore_udmd::uecm::UdrClient::Live,
    )
    .await
}

async fn handle_amf_registration_update(supi: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("AMF Registration Update: SUPI={supi}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let _update_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    SbiResponse::with_status(204)
}

async fn handle_amf_deregistration(supi: &str) -> SbiResponse {
    log::info!("AMF Deregistration: SUPI={supi}");

    // udmd-01: DELETE the UDR context-data before returning 204.
    nextgcore_udmd::uecm::process_amf_deregistration(supi, &nextgcore_udmd::uecm::UdrClient::Live)
        .await
}

async fn handle_smf_registration(
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
    nextgcore_udmd::uecm::process_smf_registration(
        supi,
        pdu_session_id,
        &reg_data,
        &nextgcore_udmd::uecm::UdrClient::Live,
    )
    .await
}

async fn handle_smf_deregistration(supi: &str, pdu_session_id: &str) -> SbiResponse {
    log::info!("SMF Deregistration: SUPI={supi}, PDU Session={pdu_session_id}");

    // udmd-01: DELETE the per-PDU-session UDR context-data before returning 204.
    nextgcore_udmd::uecm::process_smf_deregistration(
        supi,
        pdu_session_id,
        &nextgcore_udmd::uecm::UdrClient::Live,
    )
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

async fn handle_get_am_data(supi: &str, _request: &SbiRequest) -> SbiResponse {
    let (supi, snpn_nid) = split_snpn_supi(supi);
    if let Some(nid) = snpn_nid {
        log::info!("Get AM Data: SUPI={supi} (SNPN NID={nid})");
    } else {
        log::info!("Get AM Data: SUPI={supi}");
    }

    // Query UDR for provisioned access and mobility data (keyed by base SUPI)
    match nextgcore_udmd::udm_nudr_dr_send_provisioned_data_get(supi, "am-data", 0, 0).await {
        Ok(udr_response) if udr_response.is_success() => {
            // Forward UDR response body directly
            let mut response = SbiResponse::with_status(200);
            if let Some(body) = udr_response.http.content {
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
            ogs_sbi::server::send_service_unavailable("UDR unavailable")
        }
    }
}

async fn handle_get_smf_select_data(supi: &str, _request: &SbiRequest) -> SbiResponse {
    log::info!("Get SMF Select Data: SUPI={supi}");

    // Query UDR for SMF selection subscription data
    match nextgcore_udmd::udm_nudr_dr_send_provisioned_data_get(
        supi,
        "smf-selection-subscription-data",
        0,
        0,
    )
    .await
    {
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
            ogs_sbi::server::send_service_unavailable("UDR unavailable")
        }
    }
}

async fn handle_get_sm_data(supi: &str, request: &SbiRequest) -> SbiResponse {
    let dnn = request
        .http
        .params
        .get("dnn")
        .map(|s| s.as_str())
        .unwrap_or("internet");

    log::info!("Get SM Data: SUPI={supi}, DNN={dnn}");

    // Query UDR for session management subscription data
    match nextgcore_udmd::udm_nudr_dr_send_provisioned_data_get(supi, "sm-data", 0, 0).await {
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
            ogs_sbi::server::send_service_unavailable("UDR unavailable")
        }
    }
}

async fn handle_get_nssai(supi: &str, _request: &SbiRequest) -> SbiResponse {
    log::info!("Get NSSAI: SUPI={supi}");

    // Query UDR for am-data which contains NSSAI
    match nextgcore_udmd::udm_nudr_dr_send_provisioned_data_get(supi, "am-data", 0, 0).await {
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
            ogs_sbi::server::send_service_unavailable("UDR unavailable")
        }
    }
}

async fn handle_sdm_subscribe(supi: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("SDM Subscribe: SUPI={supi}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let sub_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let subscription_id = uuid::Uuid::new_v4().to_string();

    SbiResponse::with_status(201)
        .with_header(
            "Location",
            format!("/nudm-sdm/v1/{supi}/sdm-subscriptions/{subscription_id}"),
        )
        .with_json_body(&serde_json::json!({
            "subscriptionId": subscription_id,
            "nfInstanceId": sub_data.get("nfInstanceId"),
            "callbackReference": sub_data.get("callbackReference"),
            "monitoredResourceUris": sub_data.get("monitoredResourceUris"),
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

async fn handle_sdm_unsubscribe(supi: &str, subscription_id: &str) -> SbiResponse {
    log::info!("SDM Unsubscribe: SUPI={supi}, subscriptionId={subscription_id}");
    SbiResponse::with_status(204)
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

async fn handle_generate_auth_data(supi_or_suci: &str, request: &SbiRequest) -> SbiResponse {
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

    // Step 1: Query UDR for authentication subscription data (by SUPI)
    let udr_response =
        match nextgcore_udmd::udm_nudr_dr_send_auth_subscription_get(&supi, 0, 0).await {
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
                return ogs_sbi::server::send_service_unavailable("UDR query failed");
            }
            Err(e) => {
                log::error!("[{supi}] UDR auth subscription query failed: {e}");
                return ogs_sbi::server::send_service_unavailable("UDR unavailable");
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
                return ogs_sbi::server::send_service_unavailable("UE context creation failed");
            }
        };
        ue.clone()
    };

    ue.serving_network_name = Some(serving_network_name.to_string());
    ue.supi = Some(supi.clone());

    let k_bytes = nextgcore_udmd::nudm_handler::hex_to_bytes(k_hex);
    let opc_bytes = nextgcore_udmd::nudm_handler::hex_to_bytes(opc_hex);
    let amf_bytes = nextgcore_udmd::nudm_handler::hex_to_bytes(amf_hex);
    let sqn_bytes = nextgcore_udmd::nudm_handler::hex_to_bytes(sqn_hex);
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
        let rand_bytes = nextgcore_udmd::nudm_handler::hex_to_bytes(rand_hex);
        let auts_bytes = nextgcore_udmd::nudm_handler::hex_to_bytes(auts_hex);
        if rand_bytes.len() != 16 || auts_bytes.len() != ogs_crypt::milenage::OGS_AUTS_LEN {
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
        let (sqn_ms, mac_s) =
            match ogs_crypt::kdf::ogs_auc_sqn(&ue.opc, &ue.k, &rand_arr, &conc_sqn_ms) {
                Ok(r) => r,
                Err(e) => {
                    log::error!("[{supi}] SQN extraction failed: {e:?}");
                    return send_problem(500, "UNSPECIFIED", "SQN extraction failed");
                }
            };
        if mac_s != auts_bytes[6..ogs_crypt::milenage::OGS_AUTS_LEN] {
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
    ogs_core::rand::ogs_random(&mut rand);
    ue.rand = rand;

    let (autn, ik, ck, _ak, res) =
        match ogs_crypt::milenage::milenage_generate(&ue.opc, &ue.amf, &ue.k, &ue.sqn, &rand) {
            Ok(result) => result,
            Err(e) => {
                log::error!("[{supi}] Milenage generate failed: {e:?}");
                return ogs_sbi::server::send_internal_error("Milenage computation failed");
            }
        };

    // Step 5: Update UE context
    {
        let ctx = udm_self();
        let context = ctx.read().unwrap();
        context.ue_update(&ue);
        context.ue_set_supi(ue.id, &supi);
    }

    // Step 6: Update SQN in UDR (increment for next auth)
    let sqn_val = {
        let mut v: u64 = 0;
        for &b in ue.sqn.iter() {
            v = (v << 8) | (b as u64);
        }
        v
    };
    let new_sqn = (sqn_val + 32 + 1) & 0xFFFF_FFFF_FFFF;
    let new_sqn_hex = format!("{new_sqn:012x}");
    let _ =
        nextgcore_udmd::udm_nudr_dr_send_auth_subscription_patch(&supi, &new_sqn_hex, 0, 0).await;

    // Step 7: Build the AuthenticationInfoResult (TS 29.503 §6.3.6.2.2)
    use nextgcore_udmd::nudm_handler::bytes_to_hex;
    match auth_method {
        "EAP_AKA_PRIME" => {
            // TS 33.501 §6.1.3.1: the UDM/ARPF derives CK'/IK' and returns the
            // transformed AV (RAND, AUTN, XRES, CK', IK') to the AUSF.
            let mut sqn_xor_ak = [0u8; 6];
            sqn_xor_ak.copy_from_slice(&autn[..6]);
            let (ck_prime, ik_prime) =
                ogs_crypt::kdf::ogs_kdf_ck_ik_prime(&ck, &ik, serving_network_name, &sqn_xor_ak);
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
            let kausf = ogs_crypt::kdf::ogs_kdf_kausf(&ck, &ik, serving_network_name, &autn);
            let xres_star =
                ogs_crypt::kdf::ogs_kdf_xres_star(&ck, &ik, serving_network_name, &rand, &res);
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

async fn handle_auth_event(supi: &str, request: &SbiRequest) -> SbiResponse {
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

    // Record the auth event against the UE context (auth status would be
    // persisted to UDR's authentication-status resource).
    {
        let ctx = udm_self();
        if let Ok(context) = ctx.read() {
            if let Some(mut ue) = context.ue_find_by_supi(supi) {
                ue.set_auth_event(nextgcore_udmd::AuthEvent {
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

    SbiResponse::with_status(201)
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
    let sbi_ctx = ogs_sbi::context::global_context();

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

    let nf_instance_id = uuid::Uuid::new_v4().to_string();

    let nf_profile = serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "UDM",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [
            {
                "serviceInstanceId": format!("{nf_instance_id}-nudm-sdm"),
                "serviceName": "nudm-sdm",
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
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
    });

    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    let response = client
        .put_json(&path, &nf_profile)
        .await
        .map_err(|e| format!("NRF registration request failed: {e}"))?;

    match response.status {
        200 | 201 => {
            log::info!("UDM registered with NRF successfully (id={nf_instance_id})");
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

        // /nudr-dr/v1/subscription-data/{supi}/authentication-data/...
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

    fn free_port() -> u16 {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let port = probe.local_addr().expect("addr").port();
        drop(probe);
        port
    }

    fn unhex(s: &str) -> Vec<u8> {
        nextgcore_udmd::nudm_handler::hex_to_bytes(s)
    }

    /// Full HTTP-level UDM auth flow: strict rejections, null-scheme + Profile
    /// A SUCI deconcealment, 5G-AKA + EAP-AKA' AV generation, AMF separation
    /// bit enforcement, and AUTS resynchronization.
    #[tokio::test]
    async fn test_http_generate_auth_data_flows() {
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
            let udr_server = SbiServer::new(OgsSbiServerConfig::new(SocketAddr::from((
                [127, 0, 0, 1],
                udr_port,
            ))));
            udr_server.start(mock_udr_handler).await.expect("udr start");
            std::env::set_var("UDR_SBI_ADDR", "127.0.0.1");
            std::env::set_var("UDR_SBI_PORT", udr_port.to_string());

            // --- real UDM handler on an ephemeral port ---
            let udm_port = free_port();
            let udm_server = SbiServer::new(OgsSbiServerConfig::new(SocketAddr::from((
                [127, 0, 0, 1],
                udm_port,
            ))));
            udm_server
                .start(udm_sbi_request_handler)
                .await
                .expect("udm start");

            let client = ogs_sbi::client::SbiClient::with_host_port("127.0.0.1", udm_port);
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
                ogs_crypt::milenage::milenage_f2345(&opc, &k, &rand).unwrap();
            let xres_star = ogs_crypt::kdf::ogs_kdf_xres_star(&ck, &ik, TEST_SNN, &rand, &res);
            assert_eq!(
                av.get("xresStar").and_then(|v| v.as_str()),
                Some(nextgcore_udmd::nudm_handler::bytes_to_hex(&xres_star).as_str())
            );

            // ---- AUTS resynchronization (uses the RAND from the AV above) ----
            // UE side: SQN_MS=0x000000000050, AUTS = (SQN_MS xor AK*) || MAC-S
            let sqn_ms = [0u8, 0, 0, 0, 0, 0x50];
            let (_r, _c, _i, _a, akstar) =
                ogs_crypt::milenage::milenage_f2345(&opc, &k, &rand).unwrap();
            let mut conc = [0u8; 6];
            for i in 0..6 {
                conc[i] = sqn_ms[i] ^ akstar[i];
            }
            let (_mac_a, mac_s) =
                ogs_crypt::milenage::milenage_f1(&opc, &k, &rand, &sqn_ms, &[0, 0]).unwrap();
            let mut auts = Vec::new();
            auts.extend_from_slice(&conc);
            auts.extend_from_slice(&mac_s);

            let resync_body = serde_json::json!({
                "servingNetworkName": TEST_SNN,
                "ausfInstanceId": "test-ausf",
                "resynchronizationInfo": {
                    "rand": nextgcore_udmd::nudm_handler::bytes_to_hex(&rand),
                    "auts": nextgcore_udmd::nudm_handler::bytes_to_hex(&auts)
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
                    "rand": nextgcore_udmd::nudm_handler::bytes_to_hex(&rand2),
                    "auts": nextgcore_udmd::nudm_handler::bytes_to_hex(&bad_auts)
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
            let hn_pub = ogs_crypt::ecies::x25519_public_key(&hn_priv);
            let (eph_pub, ct, tag) =
                ogs_crypt::ecies::ecies_profile_a_encrypt(&hn_pub, &msin_bcd).unwrap();
            let mut scheme_output = Vec::new();
            scheme_output.extend_from_slice(&eph_pub);
            scheme_output.extend_from_slice(&ct);
            scheme_output.extend_from_slice(&tag);
            let so_hex = nextgcore_udmd::nudm_handler::bytes_to_hex(&scheme_output);
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
                ogs_crypt::milenage::milenage_f2345(&opc, &k, &rand).unwrap();
            let mut sqn_xor_ak = [0u8; 6];
            sqn_xor_ak.copy_from_slice(&autn_v[..6]);
            let (ck_prime, _ik_prime) =
                ogs_crypt::kdf::ogs_kdf_ck_ik_prime(&ck, &ik, TEST_SNN, &sqn_xor_ak);
            assert_eq!(
                av.get("ckPrime").and_then(|v| v.as_str()),
                Some(nextgcore_udmd::nudm_handler::bytes_to_hex(&ck_prime).as_str())
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
}
