//! NextGCore MB-SMF (Multicast/Broadcast Session Management Function)
//!
//! The MB-SMF is a 5G core network function responsible for (TS 23.247):
//! - MBS session management (create, update, release)
//! - Multicast transport resource management via N4mb PFCP
//! - MBS QoS flow management
//! - TMGI-based session identification and group membership tracking
//! - Interaction with SMF for unicast-to-multicast switching

use anyhow::{Context, Result};
use clap::Parser;
use ogs_sbi::context::global_context;
use ogs_sbi::message::{SbiRequest, SbiResponse};
use ogs_sbi::server::{
    send_bad_request, send_method_not_allowed, send_not_found,
    SbiServer, SbiServerConfig as OgsSbiServerConfig,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Per-process N4mb PFCP sequence number counter, incremented for each message.
static PFCP_SEQ: AtomicU32 = AtomicU32::new(1);

mod context;

pub use context::*;

/// NextGCore MB-SMF - Multicast/Broadcast Session Management Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-mbsmfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Multicast/Broadcast Session Management Function (TS 23.247)", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/mbsmf.yaml")]
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

    /// SBI server address
    #[arg(long, default_value = "0.0.0.0")]
    sbi_addr: String,

    /// SBI server port
    #[arg(long, default_value = "7812")]
    sbi_port: u16,

    /// Enable TLS
    #[arg(long)]
    tls: bool,

    /// TLS certificate file
    #[arg(long)]
    tls_cert: Option<String>,

    /// TLS key file
    #[arg(long)]
    tls_key: Option<String>,

    /// Maximum MBS sessions
    #[arg(long, default_value = "256")]
    max_sessions: usize,

    /// NRF URI for registration
    #[arg(long, default_value = "http://127.0.0.1:7777")]
    nrf_uri: String,
}

fn init_logging(level: &str) {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level))
        .format_timestamp_millis()
        .init();
}

fn setup_signal_handlers(shutdown: Arc<AtomicBool>) {
    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        shutdown.store(true, Ordering::SeqCst);
    })
    .expect("value expected");
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    init_logging(&args.log_level);
    // G32/G43: Initialize OpenTelemetry tracing (Jaeger/OTLP exporter)
    let _otel = ogs_metrics::otel::init_otel(
        ogs_metrics::otel::OtelConfig::new(env!("CARGO_PKG_NAME"))
            .with_endpoint(
                std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                    .unwrap_or_else(|_| "http://jaeger:4317".to_string()),
            ),
    )
    .ok();

    log::info!("NextGCore MB-SMF v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Multicast/Broadcast Session Management Function (3GPP TS 23.247)");

    // Initialize context
    mbsmf_context_init(args.max_sessions);

    let nf_instance_id = format!("mbsmf-{}", uuid::Uuid::new_v4());

    // Setup shutdown
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone());

    // Start SBI server
    let addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;

    let mut sbi_server_config = OgsSbiServerConfig::new(addr);
    if args.tls {
        let cert = args.tls_cert.as_deref().unwrap_or("/etc/nextgcore/tls/server.crt");
        let key = args.tls_key.as_deref().unwrap_or("/etc/nextgcore/tls/server.key");
        sbi_server_config = sbi_server_config.with_tls(key, cert);
        log::info!("TLS enabled: cert={cert}, key={key}");
    }

    let sbi_server = SbiServer::new(sbi_server_config);

    log::info!("Starting MB-SMF SBI server on {addr}");

    sbi_server.start(mbsmf_sbi_request_handler).await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    let scheme = if args.tls { "HTTPS" } else { "HTTP" };
    log::info!("SBI HTTP/2 {scheme} server listening on {addr}");

    // Register with NRF
    let sbi_ctx = global_context();
    sbi_ctx.set_nrf_uri(&args.nrf_uri).await;
    if let Err(e) = register_with_nrf(&args.sbi_addr, args.sbi_port, &nf_instance_id).await {
        log::warn!("NRF registration failed (will operate without NRF): {e}");
    } else {
        ogs_sbi::heartbeat::spawn_heartbeat_worker(nf_instance_id.clone(), 5);
    }

    log::info!("NextGCore MB-SMF ready (instance: {nf_instance_id})");

    // Main event loop
    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Graceful shutdown
    log::info!("Shutting down...");
    sbi_server.stop().await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;
    log::info!("SBI HTTP/2 server stopped");

    mbsmf_context_final();
    log::info!("MB-SMF shutdown complete");

    Ok(())
}

/// MB-SMF SBI request handler
async fn mbsmf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("MB-SMF SBI: {method} {uri}");

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match parts.as_slice() {
        // MBS Session Management (Nmbsmf_MBSSession)
        ["nmbsmf-mbssession", "v1", "mbs-sessions"] => {
            match method {
                "POST" => handle_mbs_session_create(&request).await,
                "GET" => handle_mbs_session_list().await,
                _ => send_method_not_allowed(method, "mbs-sessions"),
            }
        }
        ["nmbsmf-mbssession", "v1", "mbs-sessions", session_id] => {
            match method {
                "GET" => handle_mbs_session_get(session_id).await,
                "PATCH" => handle_mbs_session_update(session_id, &request).await,
                "DELETE" => handle_mbs_session_release(session_id).await,
                _ => send_method_not_allowed(method, "mbs-sessions/{id}"),
            }
        }
        // N4mb PFCP activation (TS 23.247 7.3)
        ["nmbsmf-mbssession", "v1", "mbs-sessions", session_id, "activate"] => {
            match method {
                "POST" => handle_mbs_session_activate(session_id, &request).await,
                _ => send_method_not_allowed(method, "mbs-sessions/{id}/activate"),
            }
        }
        // Group membership management
        ["nmbsmf-mbssession", "v1", "mbs-sessions", session_id, "members"] => {
            match method {
                "POST" => handle_member_join(session_id, &request).await,
                "GET" => handle_member_list(session_id).await,
                _ => send_method_not_allowed(method, "mbs-sessions/{id}/members"),
            }
        }
        ["nmbsmf-mbssession", "v1", "mbs-sessions", session_id, "members", supi] => {
            match method {
                "DELETE" => handle_member_leave(session_id, supi).await,
                _ => send_method_not_allowed(method, "mbs-sessions/{id}/members/{supi}"),
            }
        }
        _ => {
            log::debug!("Unknown path: {path}");
            send_not_found(&format!("Resource not found: {path}"), None)
        }
    }
}

/// Parse session pool ID from string like "mbs-sess-123"
fn parse_session_id(session_id: &str) -> Option<u64> {
    session_id
        .strip_prefix("mbs-sess-")
        .and_then(|s| s.parse::<u64>().ok())
}

/// Handle MBS Session Create (TS 23.247 7.2.1)
async fn handle_mbs_session_create(request: &SbiRequest) -> SbiResponse {
    log::info!("MBS Session Create");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let session_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    // Parse MBS session type
    let session_type_str = session_data
        .get("mbsSessionType")
        .and_then(|v| v.as_str())
        .unwrap_or("MULTICAST");
    let session_type = match session_type_str {
        "BROADCAST" => MbsSessionType::Broadcast,
        _ => MbsSessionType::Multicast,
    };

    // Parse TMGI
    let mbs_service_id = session_data
        .get("tmgi")
        .and_then(|t| t.get("mbsServiceId"))
        .and_then(|v| v.as_str())
        .unwrap_or("010203");
    let plmn_mcc = session_data
        .get("tmgi")
        .and_then(|t| t.get("plmnId"))
        .and_then(|p| p.get("mcc"))
        .and_then(|v| v.as_str())
        .unwrap_or("001");
    let plmn_mnc = session_data
        .get("tmgi")
        .and_then(|t| t.get("plmnId"))
        .and_then(|p| p.get("mnc"))
        .and_then(|v| v.as_str())
        .unwrap_or("01");

    let mut service_id_bytes = [0u8; 3];
    if let Ok(bytes) = hex::decode(mbs_service_id) {
        for (i, b) in bytes.iter().take(3).enumerate() {
            service_id_bytes[i] = *b;
        }
    }

    let tmgi = Tmgi {
        mbs_service_id: service_id_bytes,
        plmn_id: PlmnId {
            mcc: plmn_mcc.to_string(),
            mnc: plmn_mnc.to_string(),
        },
    };

    let ctx = mbsmf_self();
    let session = if let Ok(context) = ctx.read() {
        context.session_add(tmgi, session_type)
    } else {
        None
    };

    match session {
        Some(session) => {
            let session_id = format!("mbs-sess-{}", session.id);
            log::info!("MBS Session created: {session_id} (type={session_type:?})");

            SbiResponse::with_status(201)
                .with_header("Location", format!("/nmbsmf-mbssession/v1/mbs-sessions/{session_id}"))
                .with_json_body(&serde_json::json!({
                    "mbsSessionId": session_id,
                    "mbsSessionType": session_type_str,
                    "tmgi": {
                        "mbsServiceId": mbs_service_id,
                        "plmnId": {"mcc": plmn_mcc, "mnc": plmn_mnc}
                    },
                    "mbsSessionStatus": "CREATED",
                    "gtpTeid": format!("{:#010x}", session.gtp_teid),
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        None => {
            send_bad_request("Failed to create MBS session", Some("CREATION_FAILED"))
        }
    }
}

/// Handle MBS Session List - now returns real session data
async fn handle_mbs_session_list() -> SbiResponse {
    log::debug!("MBS Session List");

    let ctx = mbsmf_self();
    let sessions: Vec<serde_json::Value> = if let Ok(context) = ctx.read() {
        context.all_sessions().iter().map(|s| {
            let has_n4mb = s.n4mb_session.is_some();
            serde_json::json!({
                "mbsSessionId": format!("mbs-sess-{}", s.id),
                "mbsSessionType": format!("{:?}", s.session_type).to_uppercase(),
                "mbsSessionStatus": format!("{:?}", s.state).to_uppercase(),
                "joinedUeCount": s.joined_ue_count,
                "gtpTeid": format!("{:#010x}", s.gtp_teid),
                "n4mbEstablished": has_n4mb,
            })
        }).collect()
    } else {
        vec![]
    };

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({"mbsSessions": sessions}))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Handle MBS Session Get
async fn handle_mbs_session_get(session_id: &str) -> SbiResponse {
    log::debug!("MBS Session Get: {session_id}");

    let pool_id = parse_session_id(session_id);

    let ctx = mbsmf_self();
    let session = pool_id.and_then(|id| {
        if let Ok(context) = ctx.read() {
            context.session_find_by_id(id)
        } else {
            None
        }
    });

    match session {
        Some(session) => {
            let n4mb_info = session.n4mb_session.as_ref().map(|n| {
                serde_json::json!({
                    "localSeid": n.local_seid,
                    "remoteSeid": n.remote_seid,
                    "upfAddr": n.upf_addr.to_string(),
                    "state": format!("{:?}", n.state),
                    "dlTeid": format!("{:#010x}", n.dl_teid),
                    "gnbEndpoints": n.gnb_teids.len(),
                })
            });

            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "mbsSessionId": session_id,
                    "mbsSessionType": format!("{:?}", session.session_type).to_uppercase(),
                    "mbsSessionStatus": format!("{:?}", session.state).to_uppercase(),
                    "joinedUeCount": session.joined_ue_count,
                    "gtpTeid": format!("{:#010x}", session.gtp_teid),
                    "n4mbSession": n4mb_info,
                    "groupMembers": session.group_members.len(),
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => {
            send_not_found(&format!("MBS Session {session_id} not found"), Some("SESSION_NOT_FOUND"))
        }
    }
}

/// Handle MBS Session Update (TS 23.247 7.2.2)
async fn handle_mbs_session_update(session_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("MBS Session Update: {session_id}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let update_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let pool_id = parse_session_id(session_id);

    let ctx = mbsmf_self();
    let session = pool_id.and_then(|id| {
        if let Ok(context) = ctx.read() {
            context.session_find_by_id(id)
        } else {
            None
        }
    });

    match session {
        Some(mut session) => {
            // Update session state if provided
            if let Some(status) = update_data.get("mbsSessionStatus").and_then(|v| v.as_str()) {
                session.state = match status {
                    "ACTIVE" => MbsSessionState::Active,
                    "SUSPENDED" => MbsSessionState::Suspended,
                    _ => session.state,
                };
            }

            if let Ok(context) = ctx.read() {
                context.session_update(&session);
            }

            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "mbsSessionId": session_id,
                    "mbsSessionStatus": format!("{:?}", session.state).to_uppercase(),
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => {
            send_not_found(&format!("MBS Session {session_id} not found"), Some("SESSION_NOT_FOUND"))
        }
    }
}

/// Handle MBS Session Release (TS 23.247 7.2.3)
async fn handle_mbs_session_release(session_id: &str) -> SbiResponse {
    log::info!("MBS Session Release: {session_id}");

    let pool_id = parse_session_id(session_id);

    let ctx = mbsmf_self();
    let removed = pool_id.and_then(|id| {
        if let Ok(context) = ctx.read() {
            context.session_remove(id)
        } else {
            None
        }
    });

    match removed {
        Some(_) => {
            log::info!("MBS Session {session_id} released");
            SbiResponse::with_status(204)
        }
        None => {
            send_not_found(&format!("MBS Session {session_id} not found"), Some("SESSION_NOT_FOUND"))
        }
    }
}

/// Handle MBS Session Activate - establish N4mb PFCP with UPF (TS 23.247 7.3)
async fn handle_mbs_session_activate(session_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("MBS Session Activate (N4mb): {session_id}");

    let pool_id = match parse_session_id(session_id) {
        Some(id) => id,
        None => return send_bad_request("Invalid session ID", Some("INVALID_SESSION_ID")),
    };

    // Parse UPF address from request body
    let upf_addr: std::net::Ipv4Addr = if let Some(body) = &request.http.content {
        let data: serde_json::Value = match serde_json::from_str(body) {
            Ok(p) => p,
            Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
        };
        data.get("upfAddr")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(std::net::Ipv4Addr::new(127, 0, 0, 7))
    } else {
        std::net::Ipv4Addr::new(127, 0, 0, 7)
    };

    let ctx = mbsmf_self();
    let session = if let Ok(context) = ctx.read() {
        context.session_activate_n4mb(pool_id, upf_addr)
    } else {
        None
    };

    match session {
        Some(session) => {
            let n4mb = match session.n4mb_session.as_ref() {
                Some(n) => n,
                None => {
                    log::error!("MBS Session {session_id} has no N4mb session after activation");
                    return send_bad_request("N4mb session not initialized", Some("N4MB_SESSION_MISSING"));
                }
            };
            let local_seid = n4mb.local_seid;
            let dl_teid = n4mb.dl_teid;
            let mcast_pdr_id = n4mb.mcast_pdr_id;
            let mcast_far_id = n4mb.mcast_far_id;

            log::info!(
                "MBS Session {session_id} activated: N4mb SEID={local_seid}, UPF={upf_addr}, TEID={dl_teid:#x}"
            );

            // Send PFCP Session Establishment Request to UPF with MBS-specific
            // PDR/FAR rules for multicast transport (TS 23.247 §7.3.2, TS 29.244).
            // Fire-and-forget: the response is processed asynchronously.
            let upf_pfcp_port: u16 = std::env::var("UPF_PFCP_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8805);
            let upf_addr_octets = upf_addr.octets();

            tokio::spawn(async move {
                let msg = build_n4mb_pfcp_establishment(
                    local_seid, dl_teid, mcast_pdr_id, mcast_far_id, upf_addr_octets,
                );
                let dest = std::net::SocketAddr::from((upf_addr_octets, upf_pfcp_port));
                match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                    Ok(sock) => match sock.send_to(&msg, dest).await {
                        Ok(n) => log::info!(
                            "[N4mb] PFCP Session Establishment Request sent to {dest} ({n} bytes)"
                        ),
                        Err(e) => log::warn!(
                            "[N4mb] Failed to send PFCP Session Establishment to {dest}: {e}"
                        ),
                    },
                    Err(e) => log::warn!("[N4mb] Failed to bind UDP socket: {e}"),
                }
            });

            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "mbsSessionId": session_id,
                    "mbsSessionStatus": "ACTIVE",
                    "n4mbSession": {
                        "localSeid": local_seid,
                        "upfAddr": upf_addr.to_string(),
                        "dlTeid": format!("{:#010x}", dl_teid),
                        "state": "ESTABLISHMENT_PENDING",
                        "mcastPdrId": mcast_pdr_id,
                        "mcastFarId": mcast_far_id,
                    },
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => {
            send_not_found(&format!("MBS Session {session_id} not found"), Some("SESSION_NOT_FOUND"))
        }
    }
}

/// Build a PFCP Session Establishment Request for N4mb multicast (TS 29.244).
///
/// Message layout (TLV, big-endian):
///   PFCP header (version=1, SEID flag set, msg_type=50)
///   F-SEID IE (SMF local SEID + IPv4)
///   CREATE_PDR IE  (multicast downlink PDR)
///     PDR-ID, Precedence, PDI (Source-Interface=ACCESS, F-TEID with multicast TEID)
///     FAR-ID (reference to the FAR below)
///   CREATE_FAR IE  (multicast forwarding FAR)
///     FAR-ID, Apply-Action=FORW (0x02), Forwarding-Parameters (Destination-Interface=CORE)
fn build_n4mb_pfcp_establishment(
    local_seid: u64,
    dl_teid: u32,
    pdr_id: u16,
    far_id: u32,
    upf_addr: [u8; 4],
) -> Vec<u8> {
    // IE type codes (TS 29.244 Table 7.5.2-1)
    const IE_CREATE_PDR: u16 = 1;
    const IE_PDI: u16 = 2;
    const IE_CREATE_FAR: u16 = 3;
    const IE_FORWARDING_PARAMETERS: u16 = 4;
    const IE_SOURCE_INTERFACE: u16 = 20;
    const IE_F_TEID: u16 = 21;
    const IE_PRECEDENCE: u16 = 29;
    const IE_APPLY_ACTION: u16 = 44;
    const IE_DESTINATION_INTERFACE: u16 = 42;
    const IE_PDR_ID: u16 = 56;
    const IE_F_SEID: u16 = 57;
    const IE_FAR_ID: u16 = 108;

    // Helper: append a TLV IE to buf
    fn tlv(buf: &mut Vec<u8>, ie_type: u16, value: &[u8]) {
        buf.extend_from_slice(&ie_type.to_be_bytes());
        buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
        buf.extend_from_slice(value);
    }

    // ---- F-SEID IE ----
    let mut f_seid_val: Vec<u8> = Vec::new();
    f_seid_val.push(0x02); // V4 flag
    f_seid_val.extend_from_slice(&local_seid.to_be_bytes());
    f_seid_val.extend_from_slice(&upf_addr);
    let mut f_seid_ie: Vec<u8> = Vec::new();
    tlv(&mut f_seid_ie, IE_F_SEID, &f_seid_val);

    // ---- PDI grouped IE ----
    // Source-Interface = 0 (ACCESS)
    let mut pdi_buf: Vec<u8> = Vec::new();
    tlv(&mut pdi_buf, IE_SOURCE_INTERFACE, &[0u8]);
    // F-TEID: flags=V4(0x02), TEID, IPv4 (upf_addr is multicast transport addr)
    let mut f_teid_val: Vec<u8> = Vec::new();
    f_teid_val.push(0x02);
    f_teid_val.extend_from_slice(&dl_teid.to_be_bytes());
    f_teid_val.extend_from_slice(&upf_addr);
    tlv(&mut pdi_buf, IE_F_TEID, &f_teid_val);

    // ---- CREATE_PDR grouped IE ----
    let mut pdr_buf: Vec<u8> = Vec::new();
    tlv(&mut pdr_buf, IE_PDR_ID, &pdr_id.to_be_bytes());
    tlv(&mut pdr_buf, IE_PRECEDENCE, &100u32.to_be_bytes());
    // Embed PDI
    pdr_buf.extend_from_slice(&IE_PDI.to_be_bytes());
    pdr_buf.extend_from_slice(&(pdi_buf.len() as u16).to_be_bytes());
    pdr_buf.extend_from_slice(&pdi_buf);
    // FAR-ID reference
    tlv(&mut pdr_buf, IE_FAR_ID, &far_id.to_be_bytes());

    // ---- Forwarding Parameters grouped IE ----
    let mut fwd_params: Vec<u8> = Vec::new();
    // Destination-Interface = 1 (CORE)
    tlv(&mut fwd_params, IE_DESTINATION_INTERFACE, &[1u8]);

    // ---- CREATE_FAR grouped IE ----
    let mut far_buf: Vec<u8> = Vec::new();
    tlv(&mut far_buf, IE_FAR_ID, &far_id.to_be_bytes());
    // Apply-Action = FORW (0x02)
    tlv(&mut far_buf, IE_APPLY_ACTION, &0x0002u16.to_be_bytes());
    // Forwarding-Parameters
    far_buf.extend_from_slice(&IE_FORWARDING_PARAMETERS.to_be_bytes());
    far_buf.extend_from_slice(&(fwd_params.len() as u16).to_be_bytes());
    far_buf.extend_from_slice(&fwd_params);

    // ---- Assemble IEs ----
    let mut ies: Vec<u8> = Vec::new();
    ies.extend_from_slice(&f_seid_ie);
    // CREATE_PDR
    ies.extend_from_slice(&IE_CREATE_PDR.to_be_bytes());
    ies.extend_from_slice(&(pdr_buf.len() as u16).to_be_bytes());
    ies.extend_from_slice(&pdr_buf);
    // CREATE_FAR
    ies.extend_from_slice(&IE_CREATE_FAR.to_be_bytes());
    ies.extend_from_slice(&(far_buf.len() as u16).to_be_bytes());
    ies.extend_from_slice(&far_buf);

    // ---- PFCP Header (TS 29.244 §7.2.2) ----
    // Byte 0: version=1 (bits 7-5), FO=0, MP=0, S=1 (SEID present, bit 0)
    // Byte 1: Message Type = 50 (Session Establishment Request)
    // Bytes 2-3: Message Length = everything after the first 4 bytes of header.
    // With SEID present: 8 (SEID) + 3 (seq) + 1 (spare) + IEs = 12 + ies.len()
    let seq_num: u32 = PFCP_SEQ.fetch_add(1, Ordering::Relaxed);
    let msg_len: u16 = (12 + ies.len()) as u16;
    let mut packet: Vec<u8> = Vec::with_capacity(16 + ies.len());
    packet.push(0x21); // version=1, S=1
    packet.push(50);   // SESSION_ESTABLISHMENT_REQUEST
    packet.extend_from_slice(&msg_len.to_be_bytes());
    packet.extend_from_slice(&0u64.to_be_bytes()); // SEID=0 for establishment (CP→UP)
    // Sequence number (3 bytes) + spare (1 byte)
    packet.push(((seq_num >> 16) & 0xFF) as u8);
    packet.push(((seq_num >> 8)  & 0xFF) as u8);
    packet.push(( seq_num        & 0xFF) as u8);
    packet.push(0); // spare
    packet.extend_from_slice(&ies);
    packet
}

/// Handle member join (TMGI group membership)
async fn handle_member_join(session_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("MBS Member Join: {session_id}");

    let pool_id = match parse_session_id(session_id) {
        Some(id) => id,
        None => return send_bad_request("Invalid session ID", Some("INVALID_SESSION_ID")),
    };

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let supi = data.get("supi")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let ctx = mbsmf_self();
    let joined = if let Ok(context) = ctx.read() {
        context.session_member_join(pool_id, supi)
    } else {
        false
    };

    if joined {
        SbiResponse::with_status(201)
            .with_json_body(&serde_json::json!({
                "mbsSessionId": session_id,
                "supi": supi,
                "result": "JOINED",
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(201))
    } else {
        send_bad_request(
            &format!("Failed to join UE {supi} to session {session_id}"),
            Some("JOIN_FAILED"),
        )
    }
}

/// Handle member list
async fn handle_member_list(session_id: &str) -> SbiResponse {
    log::debug!("MBS Member List: {session_id}");

    let pool_id = parse_session_id(session_id);

    let ctx = mbsmf_self();
    let session = pool_id.and_then(|id| {
        if let Ok(context) = ctx.read() {
            context.session_find_by_id(id)
        } else {
            None
        }
    });

    match session {
        Some(session) => {
            let members: Vec<&String> = session.group_members.iter().collect();
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "mbsSessionId": session_id,
                    "memberCount": members.len(),
                    "members": members,
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => {
            send_not_found(&format!("MBS Session {session_id} not found"), Some("SESSION_NOT_FOUND"))
        }
    }
}

/// Handle member leave
async fn handle_member_leave(session_id: &str, supi: &str) -> SbiResponse {
    log::info!("MBS Member Leave: {session_id} / {supi}");

    let pool_id = match parse_session_id(session_id) {
        Some(id) => id,
        None => return send_bad_request("Invalid session ID", Some("INVALID_SESSION_ID")),
    };

    let ctx = mbsmf_self();
    let left = if let Ok(context) = ctx.read() {
        context.session_member_leave(pool_id, supi)
    } else {
        false
    };

    if left {
        SbiResponse::with_status(204)
    } else {
        send_not_found(
            &format!("UE {supi} not found in session {session_id}"),
            Some("MEMBER_NOT_FOUND"),
        )
    }
}

/// Register MB-SMF with NRF
async fn register_with_nrf(sbi_addr: &str, sbi_port: u16, nf_instance_id: &str) -> Result<(), String> {
    let sbi_ctx = global_context();

    let nrf_uri = sbi_ctx.get_nrf_uri().await;
    let nrf_uri = match nrf_uri {
        Some(uri) => uri,
        None => {
            log::debug!("No NRF URI configured, skipping NRF registration");
            return Ok(());
        }
    };

    log::info!("Registering MB-SMF with NRF at {nrf_uri}");

    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_profile = serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "MB_SMF",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [{
            "serviceInstanceId": format!("{}-nmbsmf-mbssession", nf_instance_id),
            "serviceName": "nmbsmf-mbssession",
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
        }],
        "allowedNfTypes": ["AMF", "SMF", "NEF", "SCP"],
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
            log::info!("MB-SMF registered with NRF successfully (id={nf_instance_id})");

            let mut self_instance = ogs_sbi::context::NfInstance::new(
                nf_instance_id,
                ogs_sbi::types::NfType::Mbsmf,
            );
            self_instance.ipv4_addresses = vec![sbi_addr.to_string()];
            let mut svc = ogs_sbi::context::NfService::new(
                "nmbsmf-mbssession",
                ogs_sbi::types::SbiServiceType::NmbsmfMbssession,
            );
            svc.port = sbi_port;
            svc.ip_addresses = vec![sbi_addr.to_string()];
            self_instance.add_service(svc);
            sbi_ctx.set_self_instance(self_instance).await;

            Ok(())
        }
        _ => Err(format!("NRF registration returned status {}", response.status)),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-mbsmfd"]);
        assert_eq!(args.config, "/etc/nextgcore/mbsmf.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.sbi_port, 7812);
        assert_eq!(args.max_sessions, 256);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-mbsmfd",
            "--sbi-port", "8812",
            "--max-sessions", "512",
            "--nrf-uri", "http://nrf:7777",
        ]);
        assert_eq!(args.sbi_port, 8812);
        assert_eq!(args.max_sessions, 512);
        assert_eq!(args.nrf_uri, "http://nrf:7777");
    }

    #[test]
    fn test_parse_session_id() {
        assert_eq!(parse_session_id("mbs-sess-42"), Some(42));
        assert_eq!(parse_session_id("mbs-sess-0"), Some(0));
        assert_eq!(parse_session_id("invalid"), None);
    }
}
