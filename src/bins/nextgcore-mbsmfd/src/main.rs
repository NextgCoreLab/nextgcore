//! NextGCore MB-SMF (Multicast/Broadcast Session Management Function)
//!
//! The MB-SMF is a 5G core network function responsible for (TS 23.247):
//! - MBS session management (create, update, release)
//! - Multicast transport resource management
//! - MBS QoS flow management
//! - Interaction with SMF for unicast-to-multicast switching

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
    .expect("Failed to set signal handler");
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    init_logging(&args.log_level);

    log::info!("NextGCore MB-SMF v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Multicast/Broadcast Session Management Function (3GPP TS 23.247)");

    // Initialize context
    mbsmf_context_init(args.max_sessions);

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
    log::info!("NextGCore MB-SMF ready");

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
        _ => {
            log::debug!("Unknown path: {path}");
            send_not_found(&format!("Resource not found: {path}"), None)
        }
    }
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
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        None => {
            send_bad_request("Failed to create MBS session", Some("CREATION_FAILED"))
        }
    }
}

/// Handle MBS Session List
async fn handle_mbs_session_list() -> SbiResponse {
    log::debug!("MBS Session List");

    let ctx = mbsmf_self();
    let sessions: Vec<serde_json::Value> = if let Ok(context) = ctx.read() {
        (0..context.session_count())
            .filter_map(|_| None::<serde_json::Value>) // Placeholder
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

    // Parse session pool ID from session_id
    let pool_id = session_id
        .strip_prefix("mbs-sess-")
        .and_then(|s| s.parse::<u64>().ok());

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
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "mbsSessionId": session_id,
                    "mbsSessionType": format!("{:?}", session.session_type).to_uppercase(),
                    "mbsSessionStatus": format!("{:?}", session.state).to_uppercase(),
                    "joinedUeCount": session.joined_ue_count,
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

    let pool_id = session_id
        .strip_prefix("mbs-sess-")
        .and_then(|s| s.parse::<u64>().ok());

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

    let pool_id = session_id
        .strip_prefix("mbs-sess-")
        .and_then(|s| s.parse::<u64>().ok());

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
}
