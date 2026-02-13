//! NextGCore EES (Edge Enabler Server)
//!
//! The EES is a Rel-17 network function responsible for (TS 23.558):
//! - Edge Application Server (EAS) registration and lifecycle
//! - EAS discovery based on UE location and app requirements
//! - DNS-based or NRF-based EAS discovery
//! - UE context transfer during edge relocation
//! - Edge relocation triggers based on UE mobility

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

/// NextGCore EES - Edge Enabler Server
#[derive(Parser, Debug)]
#[command(name = "nextgcore-eesd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Edge Enabler Server (TS 23.558)", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/ees.yaml")]
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
    #[arg(long, default_value = "7814")]
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

    /// Maximum EAS registrations
    #[arg(long, default_value = "512")]
    max_eas: usize,

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

    log::info!("NextGCore EES v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Edge Enabler Server (3GPP TS 23.558)");

    ees_context_init(args.max_eas);

    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone());

    let addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;

    let mut sbi_server_config = OgsSbiServerConfig::new(addr);
    if args.tls {
        let cert = args.tls_cert.as_deref().unwrap_or("/etc/nextgcore/tls/server.crt");
        let key = args.tls_key.as_deref().unwrap_or("/etc/nextgcore/tls/server.key");
        sbi_server_config = sbi_server_config.with_tls(key, cert);
    }

    let sbi_server = SbiServer::new(sbi_server_config);

    log::info!("Starting EES SBI server on {addr}");
    sbi_server.start(ees_sbi_request_handler).await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    log::info!("NextGCore EES ready");

    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    log::info!("Shutting down...");
    sbi_server.stop().await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;

    ees_context_final();
    log::info!("EES shutdown complete");

    Ok(())
}

/// EES SBI request handler
async fn ees_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("EES SBI: {method} {uri}");

    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match parts.as_slice() {
        // EAS Registration (Nees_EASRegistration)
        ["nees-easregistration", "v1", "registrations"] => {
            match method {
                "POST" => handle_eas_register(&request).await,
                "GET" => handle_eas_list().await,
                _ => send_method_not_allowed(method, "registrations"),
            }
        }
        ["nees-easregistration", "v1", "registrations", eas_id] => {
            match method {
                "GET" => handle_eas_get(eas_id).await,
                "DELETE" => handle_eas_deregister(eas_id).await,
                _ => send_method_not_allowed(method, "registrations/{id}"),
            }
        }
        // EAS Discovery (Nees_EASDiscovery)
        ["nees-easdiscovery", "v1", "discover"] => {
            match method {
                "POST" => handle_eas_discover(&request).await,
                _ => send_method_not_allowed(method, "discover"),
            }
        }
        // UE Context Transfer (Nees_UEContextTransfer)
        ["nees-uecontexttransfer", "v1", "contexts"] => {
            match method {
                "POST" => handle_ue_context_store(&request).await,
                _ => send_method_not_allowed(method, "contexts"),
            }
        }
        ["nees-uecontexttransfer", "v1", "contexts", supi] => {
            match method {
                "GET" => handle_ue_context_get(supi).await,
                "PATCH" => handle_ue_context_transfer(supi, &request).await,
                _ => send_method_not_allowed(method, "contexts/{supi}"),
            }
        }
        _ => {
            send_not_found(&format!("Resource not found: {path}"), None)
        }
    }
}

/// Handle EAS Registration
async fn handle_eas_register(request: &SbiRequest) -> SbiResponse {
    log::info!("EAS Register");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let endpoint = data.get("endpoint").and_then(|v| v.as_str()).unwrap_or("http://localhost:8080");
    let app_id = data.get("appId").and_then(|v| v.as_str()).unwrap_or("default-app");
    let eas_type = data.get("easType").and_then(|v| v.as_str()).unwrap_or("GENERIC");
    let dns_name = data.get("dnsName").and_then(|v| v.as_str()).map(|s| s.to_string());
    let tacs: Vec<u32> = data.get("servingAreaTacs")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_u64().map(|n| n as u32)).collect())
        .unwrap_or_default();

    let profile = EasProfile {
        eas_id: String::new(),
        endpoint: endpoint.to_string(),
        app_id: app_id.to_string(),
        eas_type: eas_type.to_string(),
        serving_area_tacs: tacs,
        status: EasStatus::Registered,
        capabilities: EasCapabilities::default(),
        dns_name,
    };

    let ctx = ees_self();
    let result = if let Ok(context) = ctx.read() {
        context.eas_register(profile)
    } else {
        None
    };

    match result {
        Some(profile) => {
            SbiResponse::with_status(201)
                .with_header("Location", format!("/nees-easregistration/v1/registrations/{}", profile.eas_id))
                .with_json_body(&serde_json::json!({
                    "easId": profile.eas_id,
                    "endpoint": profile.endpoint,
                    "appId": profile.app_id,
                    "easType": profile.eas_type,
                    "status": "REGISTERED",
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        None => send_bad_request("Failed to register EAS", Some("REGISTRATION_FAILED")),
    }
}

/// Handle EAS List
async fn handle_eas_list() -> SbiResponse {
    let ctx = ees_self();
    let profiles: Vec<serde_json::Value> = if let Ok(context) = ctx.read() {
        context.eas_list().iter().map(|p| {
            serde_json::json!({
                "easId": p.eas_id,
                "endpoint": p.endpoint,
                "appId": p.app_id,
                "easType": p.eas_type,
                "status": format!("{:?}", p.status),
            })
        }).collect()
    } else {
        vec![]
    };

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({"registrations": profiles}))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Handle EAS Get
async fn handle_eas_get(eas_id: &str) -> SbiResponse {
    let ctx = ees_self();
    let profile = if let Ok(context) = ctx.read() {
        context.eas_find(eas_id)
    } else {
        None
    };

    match profile {
        Some(p) => {
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "easId": p.eas_id,
                    "endpoint": p.endpoint,
                    "appId": p.app_id,
                    "easType": p.eas_type,
                    "dnsName": p.dns_name,
                    "servingAreaTacs": p.serving_area_tacs,
                    "status": format!("{:?}", p.status),
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => send_not_found(&format!("EAS {eas_id} not found"), Some("EAS_NOT_FOUND")),
    }
}

/// Handle EAS Deregister
async fn handle_eas_deregister(eas_id: &str) -> SbiResponse {
    log::info!("EAS Deregister: {eas_id}");

    let ctx = ees_self();
    let removed = if let Ok(context) = ctx.read() {
        context.eas_deregister(eas_id)
    } else {
        None
    };

    match removed {
        Some(_) => SbiResponse::with_status(204),
        None => send_not_found(&format!("EAS {eas_id} not found"), Some("EAS_NOT_FOUND")),
    }
}

/// Handle EAS Discovery (TS 23.558 8.5)
async fn handle_eas_discover(request: &SbiRequest) -> SbiResponse {
    log::info!("EAS Discovery");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let app_id = data.get("appId").and_then(|v| v.as_str()).unwrap_or("");
    let tac = data.get("servingTac").and_then(|v| v.as_u64()).map(|n| n as u32);

    let ctx = ees_self();
    let results: Vec<serde_json::Value> = if let Ok(context) = ctx.read() {
        context.eas_discover(app_id, tac).iter().map(|r| {
            serde_json::json!({
                "easId": r.eas_id,
                "endpoint": r.endpoint,
                "appId": r.app_id,
                "dnsName": r.dns_name,
                "distanceScore": r.distance_score,
            })
        }).collect()
    } else {
        vec![]
    };

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "discoveryResults": results,
            "resultCount": results.len(),
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Handle UE Context Store
async fn handle_ue_context_store(request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let supi = data.get("supi").and_then(|v| v.as_str()).unwrap_or("unknown");
    let eas_id = data.get("currentEasId").and_then(|v| v.as_str()).map(|s| s.to_string());
    let app_data = data.get("appContextData").and_then(|v| v.as_str()).map(|s| s.to_string());
    let tac = data.get("servingTac").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    let ue_ctx = UeEdgeContext {
        supi: supi.to_string(),
        current_eas_id: eas_id,
        app_context_data: app_data,
        serving_tac: tac,
    };

    let ctx = ees_self();
    let stored = if let Ok(context) = ctx.read() {
        context.ue_context_store(ue_ctx)
    } else {
        false
    };

    if stored {
        SbiResponse::with_status(201)
            .with_json_body(&serde_json::json!({"supi": supi, "result": "STORED"}))
            .unwrap_or_else(|_| SbiResponse::with_status(201))
    } else {
        send_bad_request("Failed to store UE context", Some("STORE_FAILED"))
    }
}

/// Handle UE Context Get
async fn handle_ue_context_get(supi: &str) -> SbiResponse {
    let ctx = ees_self();
    let ue_ctx = if let Ok(context) = ctx.read() {
        context.ue_context_get(supi)
    } else {
        None
    };

    match ue_ctx {
        Some(c) => {
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "supi": c.supi,
                    "currentEasId": c.current_eas_id,
                    "servingTac": c.serving_tac,
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => send_not_found(&format!("UE context for {supi} not found"), Some("CONTEXT_NOT_FOUND")),
    }
}

/// Handle UE Context Transfer (edge relocation)
async fn handle_ue_context_transfer(supi: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("UE Context Transfer: {supi}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let new_eas_id = data.get("targetEasId").and_then(|v| v.as_str()).unwrap_or("");

    let ctx = ees_self();
    let transferred = if let Ok(context) = ctx.read() {
        context.ue_context_transfer(supi, new_eas_id)
    } else {
        false
    };

    if transferred {
        SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({
                "supi": supi,
                "targetEasId": new_eas_id,
                "result": "TRANSFERRED",
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(200))
    } else {
        send_not_found(&format!("UE context for {supi} not found"), Some("CONTEXT_NOT_FOUND"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-eesd"]);
        assert_eq!(args.config, "/etc/nextgcore/ees.yaml");
        assert_eq!(args.sbi_port, 7814);
        assert_eq!(args.max_eas, 512);
    }
}
