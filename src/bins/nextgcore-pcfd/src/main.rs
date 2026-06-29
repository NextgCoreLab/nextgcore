//! NextGCore PCF (Policy Control Function)
//!
//! The PCF is a 5G core network function responsible for:
//! - Policy control for AM (Access Management)
//! - Policy control for SM (Session Management)
//! - Policy authorization for application sessions

use anyhow::{Context, Result};
use clap::Parser;
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

mod am_sm;
mod context;
mod event;
#[allow(dead_code)]
mod intent_policy;
mod npcf_handler;
mod nudr_handler;
mod pcf_sm;
mod sbi_path;
mod sbi_response;
mod sm_sm;
mod timer;
pub mod ue_policy; // Rel-16: URSP rule provisioning (TS 23.503)

pub use am_sm::{PcfAmSmContext, PcfAmState};
pub use context::*;
pub use event::*;
pub use npcf_handler::*;
pub use nudr_handler::*;
pub use pcf_sm::{PcfSmContext, PcfState};
pub use sbi_path::*;
pub use sm_sm::{PcfSmSmContext, PcfSmState};
pub use timer::{timer_manager, PcfTimerManager};

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
}

#[derive(Debug, Default, Deserialize)]
struct SbiYaml {
    server: Option<Vec<SbiServerYaml>>,
    client: Option<SbiClientYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct PcfSection {
    sbi: Option<SbiYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct PcfYaml {
    pcf: Option<PcfSection>,
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

    log::info!("NextGCore PCF v{} starting...", env!("CARGO_PKG_VERSION"));

    // Handle kill flag
    if args.kill {
        log::info!("Kill flag set - would send SIGTERM to running instance");
        return Ok(());
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

    // Initialize PCF state machine
    let mut pcf_sm = PcfSmContext::new();
    pcf_sm.init();
    log::info!("PCF state machine initialized");

    // Parse configuration (if file exists) and seed NRF URI
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
        match std::fs::read_to_string(&args.config) {
            Ok(content) => {
                log::debug!("Configuration file loaded ({} bytes)", content.len());
                // Seed NRF URI into SBI context for NF registration
                if let Ok(yaml) = serde_yaml::from_str::<PcfYaml>(&content) {
                    if let Some(pcf) = yaml.pcf {
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

    // Start actual HTTP/2 SBI server using ogs-sbi
    let sbi_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let sbi_server = SbiServer::new(OgsSbiServerConfig::new(sbi_addr));

    sbi_server
        .start(pcf_sbi_request_handler)
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

    log::info!("NextGCore PCF ready");

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
async fn pcf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
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

/// Build the TS 29.512 Arp (Allocation/Retention Priority) JSON object shared by
/// `authDefQos` and provisioned `QosData` (pcfd-07). The preemption booleans map
/// to the spec enum strings.
fn arp_json(priority_level: u8, preempt_cap: bool, preempt_vuln: bool) -> serde_json::Value {
    serde_json::json!({
        "priorityLevel": priority_level,
        "preemptCap": if preempt_cap { "MAY_PREEMPT" } else { "NOT_PREEMPT" },
        "preemptVuln": if preempt_vuln { "PREEMPTABLE" } else { "NOT_PREEMPTABLE" },
    })
}

// AM Policy Control handlers

async fn handle_am_policy_create(request: &SbiRequest) -> SbiResponse {
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

async fn handle_am_policy_get(pol_asso_id: &str) -> SbiResponse {
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

async fn handle_am_policy_delete(pol_asso_id: &str) -> SbiResponse {
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

async fn handle_am_policy_update(pol_asso_id: &str, request: &SbiRequest) -> SbiResponse {
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

async fn handle_sm_policy_create(request: &SbiRequest) -> SbiResponse {
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

            // Query real session data from UDR/database
            let s_nssai = SNssai { sst, sd };
            let session_data = pcf_get_session_data(supi, None, &s_nssai, dnn);

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

/// The parts of an SmPolicyDecision (TS 29.512 §5.6.2.4)
pub struct SmPolicyDecisionParts {
    pub sess_rules: serde_json::Value,
    pub pcc_rules: serde_json::Value,
    pub qos_decs: serde_json::Value,
    /// Charging decisions referenced from PCC rules via refChgData
    pub chg_decs: serde_json::Value,
    /// Traffic-control decisions referenced from PCC rules via refTcData
    pub traff_cont_decs: serde_json::Value,
    pub triggers: Vec<String>,
}

/// Build a complete SM Policy Decision from session data (TS 29.512)
///
/// Generates session rules, PCC rules, QoS decisions, charging decisions
/// (chgDecs), traffic-control decisions (traffContDecs) and policy control
/// request triggers based on subscription data from UDR. When the
/// subscription carries no PCC rules a default match-all rule is generated
/// so that charging and traffic-control decisions always apply.
fn build_sm_policy_decision(
    sm_policy_id: &str,
    session_data: &nudr_handler::SessionData,
) -> SmPolicyDecisionParts {
    let sess_rule_id = format!("SessRule-{sm_policy_id}");
    let def_qos_id = format!("QosDec-{sm_policy_id}");

    let arp = arp_json(
        session_data.arp_priority_level,
        session_data.arp_preempt_cap,
        session_data.arp_preempt_vuln,
    );

    // Session rules with authorized session AMBR and the inline default QoS.
    // TS 29.512 Table 5.6.2.7-1: the default QoS is conveyed inline via
    // `authDefQos`; SessionRule has no `defQosRef` attribute (pcfd-06).
    let sess_rules = serde_json::json!({
        &sess_rule_id: {
            "sessRuleId": sess_rule_id,
            "authSessAmbr": {
                "uplink": format_bitrate(session_data.ambr_uplink),
                "downlink": format_bitrate(session_data.ambr_downlink),
            },
            "authDefQos": {
                "5qi": session_data.qos_index,
                "arp": arp.clone(),
            },
        }
    });

    // Default QoS decision
    let mut qos_map = serde_json::Map::new();
    qos_map.insert(
        def_qos_id.clone(),
        serde_json::json!({
            // TS 29.512 Table 5.6.2.8-1: qosId is the mandatory (P=M, card 1)
            // identifier; the qosDecs map key equals this value. There is no
            // qosDecId attribute in the spec.
            "qosId": def_qos_id,
            "5qi": session_data.qos_index,
            // ARP is C ("shall be included when the QoS data is initially
            // provisioned") — TS 29.512 §5.6.2.8 (pcfd-07).
            "arp": arp.clone(),
            "maxbrUl": format_bitrate(session_data.ambr_uplink),
            "maxbrDl": format_bitrate(session_data.ambr_downlink),
        }),
    );

    let mut pcc_map = serde_json::Map::new();
    let mut chg_map = serde_json::Map::new();
    let mut tc_map = serde_json::Map::new();

    // Closure: charging decision per rule (TS 29.512 §5.6.2.11 ChargingData)
    let mut add_chg_dec = |rule_key: &str, rating_group: u32| -> String {
        let chg_id = format!("ChgDec-{rule_key}");
        chg_map.insert(
            chg_id.clone(),
            serde_json::json!({
                "chgId": chg_id,
                "ratingGroup": rating_group,
                "meteringMethod": "VOLUME",
                "offline": true,
                "online": false,
            }),
        );
        chg_id
    };
    // Closure: traffic-control decision per rule (TS 29.512 §5.6.2.10)
    let mut add_tc_dec = |rule_key: &str, enabled: bool| -> String {
        let tc_id = format!("TcDec-{rule_key}");
        tc_map.insert(
            tc_id.clone(),
            serde_json::json!({
                "tcId": tc_id,
                "flowStatus": if enabled { "ENABLED" } else { "DISABLED" },
            }),
        );
        tc_id
    };

    // PCC rules from database subscription data
    for (i, rule) in session_data.pcc_rules.iter().enumerate() {
        let rule_qos_id = format!("QosDec-pcc-{}", rule.id);

        let flows: Vec<serde_json::Value> = rule
            .flows
            .iter()
            .enumerate()
            .map(|(j, f)| {
                serde_json::json!({
                    "flowDescription": f.description,
                    "flowDirection": match f.direction {
                        nudr_handler::FlowDirection::Uplink => "UPLINK",
                        nudr_handler::FlowDirection::Downlink => "DOWNLINK",
                        _ => "BIDIRECTIONAL",
                    },
                    "packFiltId": format!("pf-{}-{}", rule.id, j),
                })
            })
            .collect();

        let enabled = !matches!(
            rule.flow_status,
            npcf_handler::FlowStatus::Disabled | npcf_handler::FlowStatus::Removed
        );
        let chg_id = add_chg_dec(&rule.id, (i + 1) as u32);
        let tc_id = add_tc_dec(&rule.id, enabled);

        pcc_map.insert(
            rule.id.clone(),
            serde_json::json!({
                "pccRuleId": rule.id,
                "precedence": rule.precedence,
                "flowInfos": flows,
                "refQosData": [&rule_qos_id],
                "refChgData": [chg_id],
                "refTcData": [tc_id],
            }),
        );

        // Per-rule QoS decision. ARP is included on every provisioned QosData
        // (TS 29.512 §5.6.2.8, pcfd-07); the subscription PccRule model carries
        // no per-rule maxbr/gbr, so those are emitted only when present.
        qos_map.insert(
            rule_qos_id.clone(),
            serde_json::json!({
                // TS 29.512 Table 5.6.2.8-1: mandatory qosId (== map key).
                "qosId": rule_qos_id,
                "5qi": rule.qos_index,
                "arp": arp.clone(),
            }),
        );
    }

    // Default match-all PCC rule (lowest precedence) so charging and
    // traffic-control decisions always exist for the session.
    if session_data.pcc_rules.is_empty() {
        let rule_key = format!("default-{sm_policy_id}");
        let rule_id = format!("PccRule-{rule_key}");
        let chg_id = add_chg_dec(&rule_key, 1);
        let tc_id = add_tc_dec(&rule_key, true);
        pcc_map.insert(
            rule_id.clone(),
            serde_json::json!({
                "pccRuleId": rule_id,
                "precedence": 255,
                "flowInfos": [{
                    "flowDescription": "permit out ip from any to assigned",
                    "flowDirection": "BIDIRECTIONAL",
                    "packFiltId": format!("pf-{rule_key}-0"),
                }],
                "refQosData": [&def_qos_id],
                "refChgData": [chg_id],
                "refTcData": [tc_id],
            }),
        );
    }

    // Policy control request triggers (TS 29.512 Table 5.6.2.6-1), derived from
    // the actual decision contents (pcfd-12) rather than a static list. The base
    // set covers the session-level changes the PCF always re-evaluates; the
    // dynamic triggers are added only when the decision installs resources the
    // PCF will act on.
    let mut triggers = vec![
        "SE_AMBR_CH".to_string(), // Session AMBR change
        "DEF_QOS_CH".to_string(), // Default QoS change
        "UE_IP_CH".to_string(),   // UE IP address change
        "PLMN_CH".to_string(),    // Serving network change
        "AC_TY_CH".to_string(),   // Access type change
        "RAT_TY_CH".to_string(),  // RAT type change
    ];
    // RES_MO_RE only when subscription PCC rules are installed that the UE can
    // request to modify (a default-only session cannot UE-modify resources).
    if !session_data.pcc_rules.is_empty() {
        triggers.push("RES_MO_RE".to_string());
    }
    // QOS_NOTIF when any installed rule is a GBR resource subject to QoS
    // notification control (TS 23.501 §5.7.4 GBR 5QIs).
    if session_data
        .pcc_rules
        .iter()
        .any(|r| npcf_handler::is_gbr_5qi(r.qos_index))
    {
        triggers.push("QOS_NOTIF".to_string());
    }

    SmPolicyDecisionParts {
        sess_rules,
        pcc_rules: serde_json::Value::Object(pcc_map),
        qos_decs: serde_json::Value::Object(qos_map),
        chg_decs: serde_json::Value::Object(chg_map),
        traff_cont_decs: serde_json::Value::Object(tc_map),
        triggers,
    }
}

/// Format bitrate as a human-readable string per 3GPP TS 29.571
fn format_bitrate(bps: u64) -> String {
    if bps >= 1_000_000_000 && bps.is_multiple_of(1_000_000_000) {
        format!("{} Gbps", bps / 1_000_000_000)
    } else if bps >= 1_000_000 && bps.is_multiple_of(1_000_000) {
        format!("{} Mbps", bps / 1_000_000)
    } else if bps >= 1_000 && bps.is_multiple_of(1_000) {
        format!("{} Kbps", bps / 1_000)
    } else {
        format!("{bps} bps")
    }
}

async fn handle_sm_policy_get(sm_policy_id: &str) -> SbiResponse {
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
            let session_data = pcf_get_session_data("", None, &sess.s_nssai, dnn)
                .unwrap_or_else(|| nudr_handler::SessionData {
                    qos_index: 9,
                    arp_priority_level: 8,
                    arp_preempt_cap: false,
                    arp_preempt_vuln: true,
                    ambr_uplink: 100_000_000,
                    ambr_downlink: 100_000_000,
                    pcc_rules: vec![],
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

async fn handle_sm_policy_delete(sm_policy_id: &str) -> SbiResponse {
    log::info!("SM Policy Delete: {sm_policy_id}");

    let ctx = pcf_self();

    let sess = if let Ok(context) = ctx.read() {
        context.sess_find_by_sm_policy_id(sm_policy_id)
    } else {
        None
    };

    match sess {
        Some(sess) => {
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

async fn handle_sm_policy_update_notify(sm_policy_id: &str, request: &SbiRequest) -> SbiResponse {
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

async fn handle_app_session_create(request: &SbiRequest) -> SbiResponse {
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

async fn handle_app_session_get(app_session_id: &str) -> SbiResponse {
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

async fn handle_app_session_delete(app_session_id: &str) -> SbiResponse {
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

async fn handle_app_session_modify(app_session_id: &str, request: &SbiRequest) -> SbiResponse {
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
                    obj.insert(
                        "notifUri".to_string(),
                        serde_json::json!(app.notif_uri),
                    );
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
        let poll_interval = ogs_core::async_timer::compute_poll_interval(
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

    log::info!("Registering PCF with NRF at {nrf_uri}");

    let (nrf_host, nrf_port) = parse_nrf_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_instance_id = uuid::Uuid::new_v4().to_string();

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
    async fn sm_policy_lifecycle_over_real_http() {
        use ogs_sbi::client::{SbiClient, SbiClientConfig};
        use ogs_sbi::server::{SbiServer, SbiServerConfig};

        pcf_context_init(64, 64);

        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .map(|a| a.port())
            .expect("probe ephemeral port");
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let server = SbiServer::new(SbiServerConfig::new(addr));
        server
            .start(pcf_sbi_request_handler)
            .await
            .expect("start pcfd handler server");

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

        server.stop().await.ok();
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
        assert_eq!(notify["smPolicyDecision"]["qosDecs"][qos_id]["qosId"], qos_id);
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
            assert!(arp.get("priorityLevel").is_some(), "{key} arp.priorityLevel");
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
