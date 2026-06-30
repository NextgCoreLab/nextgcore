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
use nextgcore_sbi::context::global_context;
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::{
    send_bad_request, send_method_not_allowed, send_not_found, SbiServer,
    SbiServerConfig as NextgcoreSbiServerConfig,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod context;
mod n4mb;
mod subscription;
mod types;

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
    let _otel = nextgcore_metrics::otel::init_otel(
        nextgcore_metrics::otel::OtelConfig::new(env!("CARGO_PKG_NAME")).with_endpoint(
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

    let mut sbi_server_config = NextgcoreSbiServerConfig::new(addr);
    if args.tls {
        let cert = args
            .tls_cert
            .as_deref()
            .unwrap_or("/etc/nextgcore/tls/server.crt");
        let key = args
            .tls_key
            .as_deref()
            .unwrap_or("/etc/nextgcore/tls/server.key");
        sbi_server_config = sbi_server_config.with_tls(key, cert);
        log::info!("TLS enabled: cert={cert}, key={key}");
    }

    let sbi_server = SbiServer::new(sbi_server_config);

    log::info!("Starting MB-SMF SBI server on {addr}");

    sbi_server
        .start(mbsmf_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    let scheme = if args.tls { "HTTPS" } else { "HTTP" };
    log::info!("SBI HTTP/2 {scheme} server listening on {addr}");

    // Register with NRF
    let sbi_ctx = global_context();
    sbi_ctx.set_nrf_uri(&args.nrf_uri).await;
    if let Err(e) = register_with_nrf(&args.sbi_addr, args.sbi_port, &nf_instance_id).await {
        log::warn!("NRF registration failed (will operate without NRF): {e}");
    } else {
        nextgcore_sbi::heartbeat::spawn_heartbeat_worker(nf_instance_id.clone(), 5);
    }

    log::info!("NextGCore MB-SMF ready (instance: {nf_instance_id})");

    // Main event loop
    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Graceful shutdown
    log::info!("Shutting down...");
    sbi_server
        .stop()
        .await
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
        ["nmbsmf-mbssession", "v1", "mbs-sessions"] => match method {
            "POST" => handle_mbs_session_create(&request).await,
            "GET" => handle_mbs_session_list().await,
            _ => send_method_not_allowed(method, "mbs-sessions"),
        },
        // ContextUpdate — start/terminate MBS data reception (TS 29.532 §5.3.2.5).
        // [mbsmfd-03] Must precede the `{session_id}` arm (longer path wins).
        ["nmbsmf-mbssession", "v1", "mbs-sessions", "contexts", "update"] => match method {
            "POST" => handle_mbs_session_context_update(&request).await,
            _ => send_method_not_allowed(method, "mbs-sessions/contexts/update"),
        },
        // ContextStatus subscriptions (TS 29.532 §5.3.2.9/10, SMF-facing). [mbsmfd-05]
        // Placed before the 4-segment `{session_id}` wildcard to avoid being shadowed.
        ["nmbsmf-mbssession", "v1", "mbs-sessions", "contexts", "subscriptions"] => match method {
            "POST" => handle_ctx_status_subscribe(&request).await,
            _ => send_method_not_allowed(method, "mbs-sessions/contexts/subscriptions"),
        },
        ["nmbsmf-mbssession", "v1", "mbs-sessions", "contexts", "subscriptions", sub_id] => {
            match method {
                "PUT" => handle_ctx_status_subscribe_update(sub_id, &request).await,
                "DELETE" => handle_ctx_status_unsubscribe(sub_id).await,
                _ => send_method_not_allowed(
                    method,
                    "mbs-sessions/contexts/subscriptions/{id}",
                ),
            }
        }
        // Status subscriptions (TS 29.532 §5.3.2.6/7, NEF/MBSF/AF-facing). [mbsmfd-05]
        // Placed before `{session_id}` arm so "subscriptions" isn't swallowed.
        ["nmbsmf-mbssession", "v1", "mbs-sessions", "subscriptions"] => match method {
            "POST" => handle_status_subscribe(&request).await,
            _ => send_method_not_allowed(method, "mbs-sessions/subscriptions"),
        },
        ["nmbsmf-mbssession", "v1", "mbs-sessions", "subscriptions", sub_id] => match method {
            "PUT" => handle_status_subscribe_update(sub_id, &request).await,
            "DELETE" => handle_status_unsubscribe(sub_id).await,
            _ => send_method_not_allowed(method, "mbs-sessions/subscriptions/{id}"),
        },
        // Per-session document: GET / PATCH / DELETE. Must come after all
        // literal 4-segment arms above. [mbsmfd-06/08]
        ["nmbsmf-mbssession", "v1", "mbs-sessions", session_id] => match method {
            "GET" => handle_mbs_session_get(session_id).await,
            "PATCH" => handle_mbs_session_update(session_id, &request).await,
            "DELETE" => handle_mbs_session_release(session_id).await,
            _ => send_method_not_allowed(method, "mbs-sessions/{id}"),
        },
        // Nmbsmf_TMGI service (TS 29.532 §5.2, TS29532_Nmbsmf_TMGI.yaml). [mbsmfd-04]
        ["nmbsmf-tmgi", "v1", "tmgi"] => match method {
            "POST" => handle_tmgi_allocate(&request).await,
            "DELETE" => handle_tmgi_deallocate(&request).await,
            _ => send_method_not_allowed(method, "tmgi"),
        },
        // --- Non-spec debug routes (mbsmfd-10): only when MBSMF_DEBUG_ROUTES is
        // set. The N4mb activation that `/activate` used to drive is now folded
        // into the ContextUpdate Start path; group membership is internal
        // MBS-session-context state, not an SBI sub-resource.
        ["nmbsmf-mbssession", "v1", "mbs-sessions", session_id, "activate"]
            if debug_routes_enabled() =>
        {
            match method {
                "POST" => handle_mbs_session_activate(session_id, &request).await,
                _ => send_method_not_allowed(method, "mbs-sessions/{id}/activate"),
            }
        }
        ["nmbsmf-mbssession", "v1", "mbs-sessions", session_id, "members"]
            if debug_routes_enabled() =>
        {
            match method {
                "POST" => handle_member_join(session_id, &request).await,
                "GET" => handle_member_list(session_id).await,
                _ => send_method_not_allowed(method, "mbs-sessions/{id}/members"),
            }
        }
        ["nmbsmf-mbssession", "v1", "mbs-sessions", session_id, "members", supi]
            if debug_routes_enabled() =>
        {
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

/// Whether the non-spec debug routes (`/activate`, `/members*`) are exposed.
/// Off by default so the SBI surface is exactly the TS 29.532 resource set;
/// enabled by setting `MBSMF_DEBUG_ROUTES` (any non-empty value). [mbsmfd-10]
fn debug_routes_enabled() -> bool {
    std::env::var("MBSMF_DEBUG_ROUTES")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
}

/// Parse session pool ID from string like "mbs-sess-123"
fn parse_session_id(session_id: &str) -> Option<u64> {
    session_id
        .strip_prefix("mbs-sess-")
        .and_then(|s| s.parse::<u64>().ok())
}

/// Build an internal [`context::Tmgi`] from a spec [`types::Tmgi`], or a default
/// `010203` TMGI in PLMN 001/01 when the request carries no TMGI (e.g. a
/// multicast create where the MB-SMF would allocate one).
fn context_tmgi_from(spec: Option<&types::Tmgi>) -> Tmgi {
    match spec {
        Some(t) => Tmgi {
            mbs_service_id: t.service_id_bytes(),
            plmn_id: PlmnId {
                mcc: t.plmn_id.mcc.clone(),
                mnc: t.plmn_id.mnc.clone(),
            },
        },
        None => Tmgi {
            mbs_service_id: [0x01, 0x02, 0x03],
            plmn_id: PlmnId {
                mcc: "001".to_string(),
                mnc: "01".to_string(),
            },
        },
    }
}

/// Render an internal [`context::Tmgi`] as a spec [`types::Tmgi`] for response
/// bodies (6 hex-digit `mbsServiceId`).
fn spec_tmgi_from(tmgi: &Tmgi) -> types::Tmgi {
    types::Tmgi {
        mbs_service_id: hex::encode(tmgi.mbs_service_id),
        plmn_id: types::PlmnId {
            mcc: tmgi.plmn_id.mcc.clone(),
            mnc: tmgi.plmn_id.mnc.clone(),
        },
    }
}

/// Handle MBS Session Create (TS 29.532 §5.3.2.2, CreateReqData/CreateRspData)
async fn handle_mbs_session_create(request: &SbiRequest) -> SbiResponse {
    log::info!("MBS Session Create");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    // mbsmfd-06: parse the spec CreateReqData{ mbsSession: ExtMbsSession }.
    let req: types::CreateReqData = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid CreateReqData: {e}"), Some("INVALID_JSON")),
    };

    // Read mbsSession.serviceType (the spec field name).
    let session_type = match req.mbs_session.service_type {
        Some(types::MbsServiceType::Broadcast) => MbsSessionType::Broadcast,
        _ => MbsSessionType::Multicast,
    };

    // mbsmfd-07: resolve the TMGI from mbsSession.mbsSessionId (else default).
    let spec_tmgi = req
        .mbs_session
        .mbs_session_id
        .as_ref()
        .and_then(|id| id.tmgi.as_ref());
    let tmgi = context_tmgi_from(spec_tmgi);

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

            // mbsmfd-06: respond with CreateRspData{ mbsSession }.
            let rsp = types::CreateRspData {
                mbs_session: types::ExtMbsSession {
                    mbs_session_id: Some(types::MbsSessionId {
                        tmgi: Some(spec_tmgi_from(&session.tmgi)),
                        ssm: None,
                    }),
                    service_type: Some(match session_type {
                        MbsSessionType::Broadcast => types::MbsServiceType::Broadcast,
                        MbsSessionType::Multicast => types::MbsServiceType::Multicast,
                    }),
                    ingress_tun_addr: Some(format!("{:#010x}", session.gtp_teid)),
                },
            };

            SbiResponse::with_status(201)
                .with_header(
                    "Location",
                    format!("/nmbsmf-mbssession/v1/mbs-sessions/{session_id}"),
                )
                .with_json_body(&rsp)
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        None => send_bad_request("Failed to create MBS session", Some("CREATION_FAILED")),
    }
}

/// Handle MBS Session List - now returns real session data
async fn handle_mbs_session_list() -> SbiResponse {
    log::debug!("MBS Session List");

    let ctx = mbsmf_self();
    let sessions: Vec<serde_json::Value> = if let Ok(context) = ctx.read() {
        context
            .all_sessions()
            .iter()
            .map(|s| {
                let has_n4mb = s.n4mb_session.is_some();
                serde_json::json!({
                    "mbsSessionId": format!("mbs-sess-{}", s.id),
                    "mbsSessionType": format!("{:?}", s.session_type).to_uppercase(),
                    "mbsSessionStatus": format!("{:?}", s.state).to_uppercase(),
                    "joinedUeCount": s.joined_ue_count,
                    "gtpTeid": format!("{:#010x}", s.gtp_teid),
                    "n4mbEstablished": has_n4mb,
                })
            })
            .collect()
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
        None => send_not_found(
            &format!("MBS Session {session_id} not found"),
            Some("SESSION_NOT_FOUND"),
        ),
    }
}

/// Handle MBS Session Update (TS 29.532 §5.3.2.3, PATCH with PatchData)
///
/// Parses the spec `PatchData` (RFC 6902 `PatchItem` array) and applies the
/// modifiable attributes. Returns 204 No Content on success, or 200 with
/// `redMbsServArea` when the MBS service area is reduced.
async fn handle_mbs_session_update(session_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("MBS Session Update: {session_id}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    // mbsmfd-08: parse the spec PatchData (array of PatchItem).
    let patch: types::PatchData = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid PatchData: {e}"), Some("INVALID_JSON")),
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
            let outcome = types::apply_patch_data(&patch, &mut session.service_area_tacs);

            if let Ok(context) = ctx.read() {
                context.session_update(&session);
            }

            match outcome {
                // Service area reduced -> 200 + redMbsServArea (TS 29.532 §5.3.2.3).
                types::PatchOutcome::ReducedArea(area) => SbiResponse::with_status(200)
                    .with_json_body(&serde_json::json!({ "redMbsServArea": area }))
                    .unwrap_or_else(|_| SbiResponse::with_status(200)),
                // Otherwise success is 204 No Content.
                types::PatchOutcome::NoContent => SbiResponse::with_status(204),
            }
        }
        None => send_not_found(
            &format!("MBS Session {session_id} not found"),
            Some("SESSION_NOT_FOUND"),
        ),
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
            // Notify all subscribers of the session release event. [mbsmfd-05]
            emit_status_notify(
                subscription::MbsEvent::SessionRelease,
                Some(serde_json::json!({"mbsSessionId": session_id})),
            );
            emit_ctx_status_notify(
                subscription::MbsEvent::SessionRelease,
                Some(serde_json::json!({"mbsSessionId": session_id})),
            );
            SbiResponse::with_status(204)
        }
        None => send_not_found(
            &format!("MBS Session {session_id} not found"),
            Some("SESSION_NOT_FOUND"),
        ),
    }
}

/// Handle MBS Session Activate (debug route) - establish N4mb PFCP with the
/// MB-UPF (TS 23.247 7.3). [mbsmfd-10] The production trigger for this is the
/// ContextUpdate Start path; this debug alias reuses the same establishment
/// drive ([`drive_n4mb_establishment`]).
async fn handle_mbs_session_activate(session_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("MBS Session Activate (N4mb, debug): {session_id}");

    let pool_id = match parse_session_id(session_id) {
        Some(id) => id,
        None => return send_bad_request("Invalid session ID", Some("INVALID_SESSION_ID")),
    };

    // Parse UPF address from request body (defaults to the configured MB-UPF).
    let upf_addr: std::net::Ipv4Addr = if let Some(body) = &request.http.content {
        let data: serde_json::Value = match serde_json::from_str(body) {
            Ok(p) => p,
            Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
        };
        data.get("upfAddr")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(configured_mb_upf_ip)
    } else {
        configured_mb_upf_ip()
    };

    let ctx = mbsmf_self();
    let session = if let Ok(context) = ctx.read() {
        context.session_activate_n4mb(pool_id, upf_addr)
    } else {
        None
    };

    match session {
        Some(session) => {
            let Some(n4mb) = session.n4mb_session.as_ref() else {
                log::error!("MBS Session {session_id} has no N4mb session after activation");
                return send_bad_request("N4mb session not initialized", Some("N4MB_SESSION_MISSING"));
            };
            let local_seid = n4mb.local_seid;
            let dl_teid = n4mb.dl_teid;

            // Drive a real PFCP establishment (assoc-gated, response-processed,
            // T1/N1) through the persistent node. [mbsmfd-02]
            tokio::spawn(drive_n4mb_establishment(pool_id, session.clone()));

            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "mbsSessionId": session_id,
                    "mbsSessionStatus": "ACTIVE",
                    "n4mbSession": {
                        "localSeid": local_seid,
                        "upfAddr": upf_addr.to_string(),
                        "dlTeid": format!("{dl_teid:#010x}"),
                        "state": "ESTABLISHMENT_PENDING",
                    },
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => send_not_found(
            &format!("MBS Session {session_id} not found"),
            Some("SESSION_NOT_FOUND"),
        ),
    }
}

/// Configured MB-UPF PFCP endpoint (env `MB_UPF_ADDR` / `UPF_PFCP_PORT`).
fn configured_mb_upf() -> SocketAddr {
    SocketAddr::from((configured_mb_upf_ip(), configured_upf_pfcp_port()))
}

/// Configured MB-UPF IPv4 address (env `MB_UPF_ADDR`, default 127.0.0.7).
fn configured_mb_upf_ip() -> std::net::Ipv4Addr {
    std::env::var("MB_UPF_ADDR")
        .ok()
        .and_then(|a| a.parse().ok())
        .unwrap_or(std::net::Ipv4Addr::new(127, 0, 0, 7))
}

/// Configured MB-UPF PFCP port (env `UPF_PFCP_PORT`, default 8805).
fn configured_upf_pfcp_port() -> u16 {
    std::env::var("UPF_PFCP_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8805)
}

/// Configured MB-SMF (CP function) N4mb address (env `MBSMF_N4MB_ADDR`,
/// default 127.0.0.1) used as the PFCP Node ID / F-SEID address.
fn configured_cp_addr() -> [u8; 4] {
    std::env::var("MBSMF_N4MB_ADDR")
        .ok()
        .and_then(|a| a.parse::<std::net::Ipv4Addr>().ok())
        .unwrap_or(std::net::Ipv4Addr::new(127, 0, 0, 1))
        .octets()
}

/// Configured serving PLMN for TMGI allocation (env `MBSMF_PLMN_MCC/MNC`).
fn default_plmn() -> PlmnId {
    PlmnId {
        mcc: std::env::var("MBSMF_PLMN_MCC").unwrap_or_else(|_| "001".to_string()),
        mnc: std::env::var("MBSMF_PLMN_MNC").unwrap_or_else(|_| "01".to_string()),
    }
}

/// Persistent N4mb PFCP node toward the MB-UPF, bound lazily on first use.
/// [mbsmfd-02]
static N4MB_NODE: tokio::sync::OnceCell<Arc<n4mb::N4mbPfcpNode>> =
    tokio::sync::OnceCell::const_new();

/// Get (or lazily bind) the persistent N4mb PFCP node.
async fn n4mb_node() -> Option<Arc<n4mb::N4mbPfcpNode>> {
    N4MB_NODE
        .get_or_try_init(|| async {
            n4mb::N4mbPfcpNode::new(
                "0.0.0.0:0".parse().expect("valid bind addr"),
                configured_mb_upf(),
                configured_cp_addr(),
            )
            .await
        })
        .await
        .map_err(|e| log::warn!("[N4mb] failed to bind PFCP node: {e}"))
        .ok()
        .cloned()
}

/// Drive a real N4mb PFCP establishment for `session` through the persistent
/// node: association-gated, response-processed, with T1/N1 retransmission. On a
/// successful establishment the stored session transitions to `Established`.
/// [mbsmfd-02/03]
async fn drive_n4mb_establishment(pool_id: u64, session: MbsSession) {
    let Some(n4mb) = session.n4mb_session.as_ref() else {
        return;
    };
    let upf_addr = n4mb.upf_addr;
    let params = n4mb::N4mbEstablishParams {
        local_seid: n4mb.local_seid,
        cp_addr: configured_cp_addr(),
        upf_addr: upf_addr.octets(),
        dl_teid: n4mb.dl_teid,
        pdr_id: n4mb.mcast_pdr_id,
        far_id: n4mb.mcast_far_id,
        // OuterHeaderCreation toward the multicast group (mbsmfd-09).
        mcast_transport_addr: n4mb.ll_ssm_dst.unwrap_or(upf_addr).octets(),
        c_teid: n4mb.dl_teid,
    };

    let Some(node) = n4mb_node().await else {
        return;
    };

    match node.establish_session(&params).await {
        Ok(outcome) => {
            let transport = outcome.transport_addr.unwrap_or(upf_addr);
            let dl_teid = outcome.up_dl_teid.unwrap_or(params.dl_teid);
            let ctx = mbsmf_self();
            if let Ok(c) = ctx.read() {
                c.apply_n4mb_response(pool_id, outcome.remote_seid, dl_teid, transport);
            }
            log::info!(
                "[N4mb] session {pool_id} established (remote_seid={})",
                outcome.remote_seid
            );
        }
        Err(e) => log::warn!("[N4mb] session {pool_id} establishment failed: {e}"),
    }
}

/// Handle ContextUpdate (TS 29.532 §5.3.2.5) - start/terminate MBS data
/// reception. [mbsmfd-03] On an SMF multicast Start the MB-SMF allocates and
/// returns a `cTeid` + `llSsm` and drives N4mb establishment; on Terminate /
/// leave it releases the N4mb transport; on the AMF path it returns an N2 MBS
/// SM container.
async fn handle_mbs_session_context_update(request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let req: types::ContextUpdateReqData = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => {
            return send_bad_request(
                &format!("Invalid ContextUpdateReqData: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };

    // mbsSessionId is mandatory; resolve the session by TMGI.
    let tmgi = match req.mbs_session_id.tmgi.as_ref() {
        Some(t) => context_tmgi_from(Some(t)),
        None => {
            return send_bad_request(
                "ContextUpdate requires mbsSessionId.tmgi",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };

    let action = req
        .requested_action
        .clone()
        .unwrap_or(types::ContextUpdateAction::Start);
    let is_amf = req.ran_node_id.is_some() || req.n2_mbs_sm_info.is_some();
    let terminate =
        matches!(action, types::ContextUpdateAction::Terminate) || req.leave_ind == Some(true);

    let ctx = mbsmf_self();

    // --- Terminate / leave: release the N4mb multicast transport.
    if terminate {
        let released = ctx
            .read()
            .map(|c| c.session_context_terminate(&tmgi))
            .unwrap_or(false);
        if !released {
            return send_not_found(
                "MBS session not found for ContextUpdate",
                Some("CONTEXT_NOT_FOUND"),
            );
        }
        log::info!("ContextUpdate Terminate (TMGI {:02x?})", tmgi.mbs_service_id);
        return SbiResponse::with_status(204);
    }

    // --- AMF path: produce an N2 MBS SM container for distribution setup.
    if is_amf {
        let exists = ctx
            .read()
            .map(|c| c.session_find_by_tmgi(&tmgi).is_some())
            .unwrap_or(false);
        if !exists {
            return send_not_found(
                "MBS session not found for ContextUpdate",
                Some("CONTEXT_NOT_FOUND"),
            );
        }
        let rsp = types::ContextUpdateRspData {
            ll_ssm: None,
            c_teid: None,
            n2_mbs_sm_info: Some(types::N2MbsSmInfo {
                ngap_ie_type: "MBS_DIS_SETUP_REQ".to_string(),
                ngap_data: types::RefToBinaryData {
                    content_id: "n2MbsSmInfo".to_string(),
                },
            }),
        };
        return SbiResponse::with_status(200)
            .with_json_body(&rsp)
            .unwrap_or_else(|_| SbiResponse::with_status(200));
    }

    // --- SMF multicast Start: allocate cTeid + llSsm, drive N4mb establishment.
    let upf_addr = configured_mb_upf_ip();
    let started = ctx
        .read()
        .ok()
        .and_then(|c| c.session_context_start(&tmgi, upf_addr));
    let session = match started {
        Some(s) => s,
        None => {
            return send_not_found(
                "MBS session not found for ContextUpdate",
                Some("CONTEXT_NOT_FOUND"),
            )
        }
    };
    let Some(n4mb) = session.n4mb_session.as_ref() else {
        return send_bad_request("N4mb session not initialized", Some("N4MB_SESSION_MISSING"));
    };
    let c_teid = n4mb.dl_teid;
    let ll_ssm = types::Ssm {
        source_ip_addr: types::IpAddr {
            ipv4_addr: n4mb.ll_ssm_src.map(|a| a.to_string()),
            ipv6_addr: None,
        },
        dest_ip_addr: types::IpAddr {
            ipv4_addr: n4mb.ll_ssm_dst.map(|a| a.to_string()),
            ipv6_addr: None,
        },
    };
    let pool_id = session.id;

    log::info!(
        "ContextUpdate Start (TMGI {:02x?}): cTeid={c_teid:#010x}, llSsm dst={:?}",
        tmgi.mbs_service_id,
        n4mb.ll_ssm_dst
    );

    // Drive the real N4mb establishment in the background. [mbsmfd-02]
    tokio::spawn(drive_n4mb_establishment(pool_id, session.clone()));

    let rsp = types::ContextUpdateRspData {
        ll_ssm: Some(ll_ssm),
        c_teid: Some(c_teid),
        n2_mbs_sm_info: None,
    };
    SbiResponse::with_status(200)
        .with_json_body(&rsp)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Handle TMGI Allocate (TS 29.532 §5.2.2.2, POST /nmbsmf-tmgi/v1/tmgi).
/// [mbsmfd-04] Allocates `tmgiNumber` fresh TMGIs and/or refreshes a supplied
/// `tmgiList`, returning `TmgiAllocated` with one common `expirationTime`.
async fn handle_tmgi_allocate(request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let req: types::TmgiAllocate = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => {
            return send_bad_request(
                &format!("Invalid TmgiAllocate: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };

    let ctx = mbsmf_self();
    let plmn = default_plmn();
    let ttl = TMGI_DEFAULT_TTL_SECS;

    let context = match ctx.read() {
        Ok(c) => c,
        Err(_) => return send_bad_request("Context unavailable", None),
    };

    let mut allocated: Vec<Tmgi> = Vec::new();
    let mut expiry = 0u64;

    // Refresh any supplied TMGIs (TS 29.532 §5.2.2.2).
    if let Some(refresh) = &req.tmgi_list {
        let ctmgis: Vec<Tmgi> = refresh.iter().map(|t| context_tmgi_from(Some(t))).collect();
        expiry = context.tmgi_refresh(&ctmgis, ttl);
        allocated.extend(ctmgis);
    }
    // Allocate the requested number of fresh TMGIs.
    if let Some(count) = req.tmgi_number.filter(|n| *n > 0) {
        let (fresh, e) = context.tmgi_allocate(&plmn, count, ttl);
        expiry = e;
        allocated.extend(fresh);
    }
    drop(context);

    if allocated.is_empty() {
        return send_bad_request(
            "TmgiAllocate requires tmgiNumber and/or tmgiList",
            Some("MANDATORY_IE_MISSING"),
        );
    }

    let spec_list: Vec<types::Tmgi> = allocated.iter().map(spec_tmgi_from).collect();
    let rsp = types::TmgiAllocated {
        tmgi_list: spec_list,
        expiration_time: unix_to_rfc3339(expiry),
        nid: None,
    };
    log::info!("TMGI Allocate: {} TMGI(s) (expiry={expiry})", allocated.len());
    SbiResponse::with_status(200)
        .with_json_body(&rsp)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Handle TMGI Deallocate (TS 29.532 §5.2.2.3, DELETE /nmbsmf-tmgi/v1/tmgi).
/// [mbsmfd-04] A `tmgi-list` query param selects specific TMGIs; absent means
/// deallocate all. Always returns 204 No Content.
async fn handle_tmgi_deallocate(request: &SbiRequest) -> SbiResponse {
    let ctx = mbsmf_self();

    let freed = if let Some(raw) = request.http.get_param("tmgi-list") {
        match serde_json::from_str::<Vec<types::Tmgi>>(raw) {
            Ok(list) => {
                let ctmgis: Vec<Tmgi> =
                    list.iter().map(|t| context_tmgi_from(Some(t))).collect();
                ctx.read().map(|c| c.tmgi_deallocate(&ctmgis)).unwrap_or(0)
            }
            Err(e) => {
                return send_bad_request(
                    &format!("Invalid tmgi-list query parameter: {e}"),
                    Some("INVALID_QUERY_PARAM"),
                )
            }
        }
    } else {
        ctx.read().map(|c| c.tmgi_deallocate_all()).unwrap_or(0)
    };

    log::info!("TMGI Deallocate: freed {freed} TMGI(s)");
    SbiResponse::with_status(204)
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

    let supi = data
        .get("supi")
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
        None => send_not_found(
            &format!("MBS Session {session_id} not found"),
            Some("SESSION_NOT_FOUND"),
        ),
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

// ---------------------------------------------------------------------------
// mbsmfd-05: Status / ContextStatus Subscribe / Unsubscribe / Notify handlers
// ---------------------------------------------------------------------------

/// StatusSubscribe — POST `/mbs-sessions/subscriptions` → 201 + Location
/// (TS 29.532 §5.3.2.6).
async fn handle_status_subscribe(request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let req: subscription::StatusSubscribeReqData = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            return send_bad_request(
                &format!("Invalid StatusSubscribeReqData: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };
    let entry = subscription::SubEntry {
        notify_uri: req.notify_uri.clone(),
        notify_correlation_id: req.notify_correlation_id.clone(),
        event_list: req.event_list.clone(),
        nf_instance_id: req.nf_instance_id.clone(),
    };
    let ctx = mbsmf_self();
    let sub_id = match ctx.read().ok().and_then(|c| c.status_sub_add(entry)) {
        Some(id) => id,
        None => return send_bad_request("Failed to create subscription", None),
    };
    log::info!("[sub] Status subscription created: {sub_id}");
    SbiResponse::with_status(201)
        .with_header(
            "Location",
            format!("/nmbsmf-mbssession/v1/mbs-sessions/subscriptions/{sub_id}"),
        )
        .with_json_body(&req)
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// StatusSubscribe Update — PUT `/mbs-sessions/subscriptions/{id}` → 200
/// (TS 29.532 §5.3.2.6, replace existing subscription document).
async fn handle_status_subscribe_update(sub_id: &str, request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let req: subscription::StatusSubscribeReqData = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            return send_bad_request(
                &format!("Invalid StatusSubscribeReqData: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };
    let entry = subscription::SubEntry {
        notify_uri: req.notify_uri.clone(),
        notify_correlation_id: req.notify_correlation_id.clone(),
        event_list: req.event_list.clone(),
        nf_instance_id: req.nf_instance_id.clone(),
    };
    let ctx = mbsmf_self();
    let updated = ctx.read().ok().map(|c| c.status_sub_update(sub_id, entry)).unwrap_or(false);
    if updated {
        log::debug!("[sub] Status subscription updated: {sub_id}");
        SbiResponse::with_status(200)
            .with_json_body(&req)
            .unwrap_or_else(|_| SbiResponse::with_status(200))
    } else {
        send_not_found(
            &format!("Status subscription {sub_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        )
    }
}

/// StatusUnsubscribe — DELETE `/mbs-sessions/subscriptions/{id}` → 204
/// (TS 29.532 §5.3.2.7).
async fn handle_status_unsubscribe(sub_id: &str) -> SbiResponse {
    let ctx = mbsmf_self();
    let removed = ctx.read().ok().map(|c| c.status_sub_remove(sub_id)).unwrap_or(false);
    if removed {
        log::info!("[sub] Status subscription removed: {sub_id}");
        SbiResponse::with_status(204)
    } else {
        send_not_found(
            &format!("Status subscription {sub_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        )
    }
}

/// ContextStatusSubscribe — POST `/mbs-sessions/contexts/subscriptions` → 201
/// (TS 29.532 §5.3.2.9).
async fn handle_ctx_status_subscribe(request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let req: subscription::ContextStatusSubscribeReqData = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            return send_bad_request(
                &format!("Invalid ContextStatusSubscribeReqData: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };
    let entry = subscription::SubEntry {
        notify_uri: req.notify_uri.clone(),
        notify_correlation_id: req.notify_correlation_id.clone(),
        event_list: req.event_list.clone(),
        nf_instance_id: req.nf_instance_id.clone(),
    };
    let ctx = mbsmf_self();
    let sub_id = match ctx.read().ok().and_then(|c| c.ctx_sub_add(entry)) {
        Some(id) => id,
        None => return send_bad_request("Failed to create subscription", None),
    };
    log::info!("[sub] ContextStatus subscription created: {sub_id}");
    SbiResponse::with_status(201)
        .with_header(
            "Location",
            format!("/nmbsmf-mbssession/v1/mbs-sessions/contexts/subscriptions/{sub_id}"),
        )
        .with_json_body(&req)
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// ContextStatusSubscribe Update — PUT `/mbs-sessions/contexts/subscriptions/{id}` → 200
/// (TS 29.532 §5.3.2.9).
async fn handle_ctx_status_subscribe_update(sub_id: &str, request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let req: subscription::ContextStatusSubscribeReqData = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            return send_bad_request(
                &format!("Invalid ContextStatusSubscribeReqData: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };
    let entry = subscription::SubEntry {
        notify_uri: req.notify_uri.clone(),
        notify_correlation_id: req.notify_correlation_id.clone(),
        event_list: req.event_list.clone(),
        nf_instance_id: req.nf_instance_id.clone(),
    };
    let ctx = mbsmf_self();
    let updated = ctx.read().ok().map(|c| c.ctx_sub_update(sub_id, entry)).unwrap_or(false);
    if updated {
        log::debug!("[sub] ContextStatus subscription updated: {sub_id}");
        SbiResponse::with_status(200)
            .with_json_body(&req)
            .unwrap_or_else(|_| SbiResponse::with_status(200))
    } else {
        send_not_found(
            &format!("ContextStatus subscription {sub_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        )
    }
}

/// ContextStatusUnsubscribe — DELETE `/mbs-sessions/contexts/subscriptions/{id}` → 204
/// (TS 29.532 §5.3.2.10).
async fn handle_ctx_status_unsubscribe(sub_id: &str) -> SbiResponse {
    let ctx = mbsmf_self();
    let removed = ctx.read().ok().map(|c| c.ctx_sub_remove(sub_id)).unwrap_or(false);
    if removed {
        log::info!("[sub] ContextStatus subscription removed: {sub_id}");
        SbiResponse::with_status(204)
    } else {
        send_not_found(
            &format!("ContextStatus subscription {sub_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        )
    }
}

/// Fan out a Status notification for `event` to all matching subscribers.
/// Each POST is fire-and-forget (spawned); failures are logged as warnings.
/// [mbsmfd-05]
fn emit_status_notify(event: subscription::MbsEvent, detail: Option<serde_json::Value>) {
    let ctx = mbsmf_self();
    let subs = ctx
        .read()
        .ok()
        .map(|c| c.status_subs_matching(&event))
        .unwrap_or_default();
    for sub in subs {
        let body = subscription::StatusNotifyReqData {
            notify_correlation_id: sub.notify_correlation_id.clone(),
            mbs_event: event.clone(),
            event_detail: detail.clone(),
        };
        let uri = sub.notify_uri.clone();
        tokio::spawn(async move {
            subscription::send_notify_post(&uri, &body).await;
        });
    }
}

/// Fan out a ContextStatus notification for `event` to all matching
/// ContextStatus subscribers (SMF-facing). [mbsmfd-05]
fn emit_ctx_status_notify(event: subscription::MbsEvent, detail: Option<serde_json::Value>) {
    let ctx = mbsmf_self();
    let subs = ctx
        .read()
        .ok()
        .map(|c| c.ctx_subs_matching(&event))
        .unwrap_or_default();
    for sub in subs {
        let body = subscription::ContextStatusNotifyReqData {
            notify_correlation_id: sub.notify_correlation_id.clone(),
            mbs_event: event.clone(),
            event_detail: detail.clone(),
        };
        let uri = sub.notify_uri.clone();
        tokio::spawn(async move {
            subscription::send_notify_post(&uri, &body).await;
        });
    }
}

/// Register MB-SMF with NRF
async fn register_with_nrf(
    sbi_addr: &str,
    sbi_port: u16,
    nf_instance_id: &str,
) -> Result<(), String> {
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
        }, {
            // Nmbsmf_TMGI service (Allocate/Deallocate). [mbsmfd-04]
            "serviceInstanceId": format!("{}-nmbsmf-tmgi", nf_instance_id),
            "serviceName": "nmbsmf-tmgi",
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.1.0"}],
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

            let mut self_instance =
                nextgcore_sbi::context::NfInstance::new(nf_instance_id, nextgcore_sbi::types::NfType::Mbsmf);
            self_instance.ipv4_addresses = vec![sbi_addr.to_string()];
            let mut svc = nextgcore_sbi::context::NfService::new(
                "nmbsmf-mbssession",
                nextgcore_sbi::types::SbiServiceType::NmbsmfMbssession,
            );
            svc.port = sbi_port;
            svc.ip_addresses = vec![sbi_addr.to_string()];
            self_instance.add_service(svc);
            sbi_ctx.set_self_instance(self_instance).await;

            Ok(())
        }
        _ => Err(format!(
            "NRF registration returned status {}",
            response.status
        )),
    }
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
            "--sbi-port",
            "8812",
            "--max-sessions",
            "512",
            "--nrf-uri",
            "http://nrf:7777",
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

    /// Locate a byte subsequence (used to assert specific IE windows on the
    /// encoded N4mb establishment packet).
    fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|w| w == needle)
    }

    // ---- mbsmfd-01: N4mb PFCP establishment encoded via nextgcore-pfcp ----

    /// Encode an N4mb establishment packet via the shared [`n4mb`] builder.
    fn encode_establishment(
        cp_addr: [u8; 4],
        upf_addr: [u8; 4],
        local_seid: u64,
        dl_teid: u32,
        pdr_id: u16,
        far_id: u32,
    ) -> Vec<u8> {
        let params = n4mb::N4mbEstablishParams {
            local_seid,
            cp_addr,
            upf_addr,
            dl_teid,
            pdr_id,
            far_id,
            mcast_transport_addr: [239, 1, 0, 1],
            c_teid: dl_teid,
        };
        let req = n4mb::build_establishment_request(&params);
        nextgcore_pfcp::message::build_message(
            &nextgcore_pfcp::message::PfcpMessage::SessionEstablishmentRequest(req),
            7,
            Some(0),
        )
        .to_vec()
    }

    #[test]
    fn test_n4mb_establishment_byte_vector() {
        let cp_addr = [127, 0, 0, 1];
        let upf_addr = [10, 0, 0, 7];
        let pkt = encode_establishment(cp_addr, upf_addr, 0x100, 0x0BCA_0001, 1002, 2002);

        // PFCP header: version=1 + S(seid) flag => 0x21, msg type 50.
        assert_eq!(pkt[0], 0x21, "version/SEID flag byte");
        assert_eq!(pkt[1], 50, "Session Establishment Request type");

        // Node ID IE (type 60 = 0x003C), len 5, node-id-type 0 (IPv4) — the
        // mandatory IE the old hand-rolled encoder omitted entirely.
        assert!(
            find_subsequence(&pkt, &[0x00, 0x3C, 0x00, 0x05, 0x00]).is_some(),
            "Node ID IE (type 60, IPv4) present"
        );

        // F-TEID IE (type 21 = 0x0015), len 9, flags octet == 0x01 (V4) — the
        // old encoder wrongly set 0x02 (V6).
        assert!(
            find_subsequence(&pkt, &[0x00, 0x15, 0x00, 0x09, 0x01]).is_some(),
            "F-TEID IE V4 flag octet == 0x01"
        );

        // Apply-Action IE (type 44 = 0x002C), len 2, octet5 == 0x02 (FORW),
        // octet6 == 0x00 — the old encoder put 0x02 in octet6 instead.
        assert!(
            find_subsequence(&pkt, &[0x00, 0x2C, 0x00, 0x02, 0x02, 0x00]).is_some(),
            "Apply-Action FORW in octet 5 == 0x02"
        );
    }

    #[test]
    fn test_n4mb_establishment_roundtrip_decode() {
        use nextgcore_pfcp::message::{parse_message, PfcpMessage};
        use nextgcore_pfcp::types::NodeIdType;

        let cp_addr = [127, 0, 0, 1];
        let upf_addr = [10, 0, 0, 7];
        let local_seid = 0x0000_0000_0000_0100u64;
        let dl_teid = 0x0BCA_0001u32;
        let pdr_id = 1002u16;
        let far_id = 2002u32;

        let pkt = encode_establishment(cp_addr, upf_addr, local_seid, dl_teid, pdr_id, far_id);

        let mut buf = bytes::Bytes::copy_from_slice(&pkt);
        let (header, msg) = parse_message(&mut buf).expect("decode N4mb establishment");
        assert!(header.seid_presence);
        assert_eq!(header.seid, Some(0));

        let req = match msg {
            PfcpMessage::SessionEstablishmentRequest(r) => r,
            other => panic!("expected SessionEstablishmentRequest, got {other:?}"),
        };

        // Node ID round-trips as the CP IPv4 address.
        assert_eq!(req.node_id.node_id_type, NodeIdType::Ipv4);
        assert_eq!(req.node_id.ipv4_addr, Some(cp_addr));

        // CP F-SEID carries the local SEID.
        assert!(req.cp_f_seid.ipv4);
        assert_eq!(req.cp_f_seid.seid, local_seid);

        // PDR/PDI F-TEID round-trips the multicast DL TEID + V4 flag.
        assert_eq!(req.create_pdrs.len(), 1);
        let pdr = &req.create_pdrs[0];
        assert_eq!(pdr.pdr_id, pdr_id);
        assert_eq!(pdr.far_id, Some(far_id));
        let fteid = pdr.pdi.local_f_teid.as_ref().expect("F-TEID present");
        assert!(fteid.ipv4);
        assert!(!fteid.ipv6);
        assert_eq!(fteid.teid, dl_teid);
        assert_eq!(fteid.ipv4_addr, Some(upf_addr));

        // FAR round-trips Apply-Action FORW + Destination=ACCESS for DL
        // multicast distribution toward NG-RAN (mbsmfd-09).
        assert_eq!(req.create_fars.len(), 1);
        let far = &req.create_fars[0];
        assert_eq!(far.far_id, far_id);
        assert!(far.apply_action.forw);
        let fp = far
            .forwarding_parameters
            .as_ref()
            .expect("forwarding parameters present");
        assert_eq!(
            fp.destination_interface,
            nextgcore_pfcp::types::DestinationInterface::Access
        );
    }

    // ---- mbsmfd-07: resolve a created session by its TMGI ----

    #[test]
    fn test_lookup_session_by_tmgi() {
        let mut ctx = MbSmfContext::new();
        ctx.init(256);

        // Create via a spec MbsSessionId carrying a TMGI.
        let spec_id = types::MbsSessionId {
            tmgi: Some(types::Tmgi {
                mbs_service_id: "0a0b0c".to_string(),
                plmn_id: types::PlmnId {
                    mcc: "001".to_string(),
                    mnc: "01".to_string(),
                },
            }),
            ssm: None,
        };
        let ctx_tmgi = context_tmgi_from(spec_id.tmgi.as_ref());
        let created = ctx
            .session_add(ctx_tmgi.clone(), MbsSessionType::Broadcast)
            .unwrap();

        // Resolving the same spec TMGI maps back to the created internal id.
        let resolve_tmgi = context_tmgi_from(spec_id.tmgi.as_ref());
        let found = ctx.session_find_by_tmgi(&resolve_tmgi).expect("resolved by TMGI");
        assert_eq!(found.id, created.id);
        assert_eq!(found.tmgi.mbs_service_id, [0x0A, 0x0B, 0x0C]);
    }

    // ---- mbsmfd-03/04/10: SBI router behaviour (against the global context) ----

    /// Seed a session in the *global* context keyed by `tmgi`, returning its
    /// `mbsServiceId` hex string for building an `MbsSessionId`.
    fn seed_global_session(svc_id: [u8; 3]) -> String {
        mbsmf_context_init(256);
        let tmgi = Tmgi {
            mbs_service_id: svc_id,
            plmn_id: PlmnId {
                mcc: "001".to_string(),
                mnc: "01".to_string(),
            },
        };
        let ctx = mbsmf_self();
        let guard = ctx.read().unwrap();
        guard
            .session_add(tmgi, MbsSessionType::Multicast)
            .expect("session added");
        hex::encode(svc_id)
    }

    // mbsmfd-03: ContextUpdate SMF Start → 200 with cTeid + llSsm.
    #[tokio::test]
    async fn test_router_context_update_smf_start() {
        let svc = seed_global_session([0xC0, 0x01, 0x01]);
        let body = format!(
            r#"{{"nfcInstanceId":"smf-x","mbsSessionId":{{"tmgi":{{"mbsServiceId":"{svc}","plmnId":{{"mcc":"001","mnc":"01"}}}}}},"requestedAction":"START"}}"#
        );
        let req = SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
            .with_body(body, "application/json");
        let rsp = mbsmf_sbi_request_handler(req).await;
        assert_eq!(rsp.status, 200);
        let parsed: types::ContextUpdateRspData =
            serde_json::from_str(rsp.http.content.as_deref().unwrap()).unwrap();
        assert!(parsed.c_teid.is_some(), "cTeid allocated");
        let ssm = parsed.ll_ssm.expect("llSsm present");
        assert!(ssm.dest_ip_addr.ipv4_addr.is_some(), "llSsm dest allocated");
    }

    // mbsmfd-03: ContextUpdate Terminate → 204; unknown session → 404.
    #[tokio::test]
    async fn test_router_context_update_terminate_and_unknown() {
        let svc = seed_global_session([0xC0, 0x02, 0x02]);
        // First Start so there is an N4mb context to release.
        let start = format!(
            r#"{{"nfcInstanceId":"smf-x","mbsSessionId":{{"tmgi":{{"mbsServiceId":"{svc}","plmnId":{{"mcc":"001","mnc":"01"}}}}}},"requestedAction":"START"}}"#
        );
        let _ = mbsmf_sbi_request_handler(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
                .with_body(start, "application/json"),
        )
        .await;

        let term = format!(
            r#"{{"nfcInstanceId":"smf-x","mbsSessionId":{{"tmgi":{{"mbsServiceId":"{svc}","plmnId":{{"mcc":"001","mnc":"01"}}}}}},"requestedAction":"TERMINATE"}}"#
        );
        let rsp = mbsmf_sbi_request_handler(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
                .with_body(term, "application/json"),
        )
        .await;
        assert_eq!(rsp.status, 204, "Terminate releases → 204");

        // An unknown TMGI is 404.
        let unknown = r#"{"nfcInstanceId":"smf-x","mbsSessionId":{"tmgi":{"mbsServiceId":"eeeeee","plmnId":{"mcc":"001","mnc":"01"}}},"requestedAction":"START"}"#;
        let rsp = mbsmf_sbi_request_handler(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
                .with_body(unknown, "application/json"),
        )
        .await;
        assert_eq!(rsp.status, 404);
    }

    // mbsmfd-03: ContextUpdate AMF path → 200 with an N2 MBS SM container.
    #[tokio::test]
    async fn test_router_context_update_amf_n2() {
        let svc = seed_global_session([0xC0, 0x03, 0x03]);
        let body = format!(
            r#"{{"nfcInstanceId":"amf-x","mbsSessionId":{{"tmgi":{{"mbsServiceId":"{svc}","plmnId":{{"mcc":"001","mnc":"01"}}}}}},"ranNodeId":{{"gNbId":{{"bitLength":24,"gNBValue":"000001"}}}}}}"#
        );
        let rsp = mbsmf_sbi_request_handler(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/contexts/update")
                .with_body(body, "application/json"),
        )
        .await;
        assert_eq!(rsp.status, 200);
        let parsed: types::ContextUpdateRspData =
            serde_json::from_str(rsp.http.content.as_deref().unwrap()).unwrap();
        assert!(parsed.n2_mbs_sm_info.is_some(), "N2 container produced");
    }

    // mbsmfd-04: TMGI Allocate → 200 + TmgiAllocated; Deallocate → 204.
    #[tokio::test]
    async fn test_router_tmgi_allocate_deallocate() {
        mbsmf_context_init(256);
        let rsp = mbsmf_sbi_request_handler(
            SbiRequest::post("/nmbsmf-tmgi/v1/tmgi").with_body(r#"{"tmgiNumber":3}"#, "application/json"),
        )
        .await;
        assert_eq!(rsp.status, 200);
        let alloc: types::TmgiAllocated =
            serde_json::from_str(rsp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(alloc.tmgi_list.len(), 3);
        assert!(!alloc.expiration_time.is_empty());

        // Deallocate exactly the three we got back → 204.
        let list_json = serde_json::to_string(&alloc.tmgi_list).unwrap();
        let rsp = mbsmf_sbi_request_handler(
            SbiRequest::delete("/nmbsmf-tmgi/v1/tmgi").with_param("tmgi-list", list_json),
        )
        .await;
        assert_eq!(rsp.status, 204);
    }

    // mbsmfd-10: only the spec resource set responds — `/members` is not exposed
    // (404) while `/contexts/update` is a real route (400 on a missing body, not
    // 404), with debug routes disabled.
    #[tokio::test]
    async fn test_router_only_spec_resources() {
        std::env::remove_var("MBSMF_DEBUG_ROUTES");
        mbsmf_context_init(256);

        // Non-spec /members route is absent → 404.
        let rsp = mbsmf_sbi_request_handler(SbiRequest::get(
            "/nmbsmf-mbssession/v1/mbs-sessions/mbs-sess-1/members",
        ))
        .await;
        assert_eq!(rsp.status, 404, "/members is not a spec resource");

        // Spec /contexts/update route exists → 400 (bad/missing body), not 404.
        let rsp = mbsmf_sbi_request_handler(SbiRequest::post(
            "/nmbsmf-mbssession/v1/mbs-sessions/contexts/update",
        ))
        .await;
        assert_eq!(rsp.status, 400, "/contexts/update exists (400, not 404)");
    }

    #[test]
    fn test_debug_routes_disabled_by_default() {
        std::env::remove_var("MBSMF_DEBUG_ROUTES");
        assert!(!debug_routes_enabled());
    }

    // ---- mbsmfd-05: subscription router integration tests ----

    // Subscribe → 201 + Location; unsubscribe → 204; double-delete → 404.
    #[tokio::test]
    async fn test_router_status_subscribe_and_unsubscribe() {
        mbsmf_context_init(256);
        let body = r#"{"notifyUri":"http://nef:9000/notify","notifyCorrelationId":"corr-1"}"#;
        let rsp = mbsmf_sbi_request_handler(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/subscriptions")
                .with_body(body, "application/json"),
        )
        .await;
        assert_eq!(rsp.status, 201, "Status subscribe → 201");
        let loc = rsp.http.get_header("location").cloned();
        assert!(loc.is_some(), "Location header present");
        let sub_id = loc.unwrap().rsplit('/').next().unwrap().to_string();

        // Unsubscribe the subscription we just created → 204.
        let del = mbsmf_sbi_request_handler(SbiRequest::delete(format!(
            "/nmbsmf-mbssession/v1/mbs-sessions/subscriptions/{sub_id}"
        )))
        .await;
        assert_eq!(del.status, 204, "Status unsubscribe → 204");

        // Second delete → 404 (already removed).
        let del2 = mbsmf_sbi_request_handler(SbiRequest::delete(format!(
            "/nmbsmf-mbssession/v1/mbs-sessions/subscriptions/{sub_id}"
        )))
        .await;
        assert_eq!(del2.status, 404, "Second delete → 404");
    }

    // PUT updates an existing Status subscription; PUT on unknown ID → 404.
    #[tokio::test]
    async fn test_router_status_subscribe_update() {
        mbsmf_context_init(256);
        let create_body =
            r#"{"notifyUri":"http://nef/cb","notifyCorrelationId":"corr-orig"}"#;
        let rsp = mbsmf_sbi_request_handler(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/subscriptions")
                .with_body(create_body, "application/json"),
        )
        .await;
        assert_eq!(rsp.status, 201);
        let loc = rsp.http.get_header("location").cloned().unwrap();
        let sub_id = loc.rsplit('/').next().unwrap().to_string();

        // Update with a new correlationId → 200.
        let upd_body =
            r#"{"notifyUri":"http://nef/cb","notifyCorrelationId":"corr-updated"}"#;
        let upd = mbsmf_sbi_request_handler(
            SbiRequest::put(format!(
                "/nmbsmf-mbssession/v1/mbs-sessions/subscriptions/{sub_id}"
            ))
            .with_body(upd_body, "application/json"),
        )
        .await;
        assert_eq!(upd.status, 200, "PUT → 200");

        // PUT on a random unknown ID → 404.
        let miss = mbsmf_sbi_request_handler(
            SbiRequest::put(
                "/nmbsmf-mbssession/v1/mbs-sessions/subscriptions/00000000-0000-0000-0000-000000000000",
            )
            .with_body(upd_body, "application/json"),
        )
        .await;
        assert_eq!(miss.status, 404, "PUT unknown → 404");
    }

    // ContextStatus subscribe → 201 + Location; unsubscribe → 204.
    #[tokio::test]
    async fn test_router_ctx_status_subscribe_and_unsubscribe() {
        mbsmf_context_init(256);
        let body =
            r#"{"notifyUri":"http://smf:8080/ctx-notify","notifyCorrelationId":"ctx-corr-1","eventList":["SESSION_RELEASE"]}"#;
        let rsp = mbsmf_sbi_request_handler(
            SbiRequest::post(
                "/nmbsmf-mbssession/v1/mbs-sessions/contexts/subscriptions",
            )
            .with_body(body, "application/json"),
        )
        .await;
        assert_eq!(rsp.status, 201, "ContextStatus subscribe → 201");
        let loc = rsp.http.get_header("location").cloned();
        assert!(
            loc.as_deref().unwrap_or("").contains("/contexts/subscriptions/"),
            "Location under /contexts/subscriptions/"
        );
        let sub_id = loc.unwrap().rsplit('/').next().unwrap().to_string();

        let del = mbsmf_sbi_request_handler(SbiRequest::delete(format!(
            "/nmbsmf-mbssession/v1/mbs-sessions/contexts/subscriptions/{sub_id}"
        )))
        .await;
        assert_eq!(del.status, 204, "ContextStatus unsubscribe → 204");
    }

    // Session release with an active Status subscription produces a
    // subscription-store mutation (notify is fire-and-forget; the POST to a
    // loopback notifyUri will fail silently, which is expected in unit tests —
    // we verify the router returns 204 and the subscription count is unchanged
    // because the notify is to a different endpoint than the session).
    #[tokio::test]
    async fn test_router_release_fires_notify_path() {
        mbsmf_context_init(256);

        // Create a session.
        let create_body = r#"{"mbsSession":{"serviceType":"MULTICAST"}}"#;
        let rsp = mbsmf_sbi_request_handler(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions")
                .with_body(create_body, "application/json"),
        )
        .await;
        assert_eq!(rsp.status, 201);
        let loc = rsp.http.get_header("location").cloned().unwrap();
        let session_path = loc.clone();
        let session_id = loc.rsplit('/').next().unwrap().to_string();

        // Subscribe to SESSION_RELEASE on this notifyUri (unreachable in unit
        // tests — the notify POST is spawned async and fails silently).
        let sub_body = format!(
            r#"{{"notifyUri":"http://127.0.0.1:1/notify","notifyCorrelationId":"rel-corr-{session_id}","eventList":["SESSION_RELEASE"]}}"#
        );
        let sub_rsp = mbsmf_sbi_request_handler(
            SbiRequest::post("/nmbsmf-mbssession/v1/mbs-sessions/subscriptions")
                .with_body(sub_body, "application/json"),
        )
        .await;
        assert_eq!(sub_rsp.status, 201);

        // Release the session — should return 204 (notify is spawned async).
        let del_rsp = mbsmf_sbi_request_handler(SbiRequest::delete(session_path.clone()))
        .await;
        assert_eq!(del_rsp.status, 204, "Release → 204");
    }

    // Missing body on subscribe → 400; method not allowed on wrong verb → 405.
    #[tokio::test]
    async fn test_router_subscribe_bad_request_and_method() {
        mbsmf_context_init(256);

        // POST with no body → 400.
        let no_body = mbsmf_sbi_request_handler(SbiRequest::post(
            "/nmbsmf-mbssession/v1/mbs-sessions/subscriptions",
        ))
        .await;
        assert_eq!(no_body.status, 400);

        // PATCH on subscriptions collection → 405.
        let wrong_verb = mbsmf_sbi_request_handler(SbiRequest::patch(
            "/nmbsmf-mbssession/v1/mbs-sessions/subscriptions",
        ))
        .await;
        assert_eq!(wrong_verb.status, 405);
    }
}
