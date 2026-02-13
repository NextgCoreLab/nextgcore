//! NextGCore PIN (Personal IoT Network Manager)
//!
//! The PIN Manager is a Rel-17 NF responsible for (TS 23.542):
//! - Personal IoT Network creation and management
//! - PEGC (PIN Element Gateway Controller) functionality
//! - PIN Element registration, discovery, and communication relay
//! - PIN Element lifecycle management

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

/// NextGCore PIN Manager - Personal IoT Network Manager
#[derive(Parser, Debug)]
#[command(name = "nextgcore-pind")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Personal IoT Network Manager (TS 23.542)", long_about = None)]
struct Args {
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/pin.yaml")]
    config: String,

    #[arg(short = 'l', long)]
    log_file: Option<String>,

    #[arg(short = 'e', long, default_value = "info")]
    log_level: String,

    #[arg(short = 'm', long)]
    no_color: bool,

    #[arg(long, default_value = "0.0.0.0")]
    sbi_addr: String,

    #[arg(long, default_value = "7815")]
    sbi_port: u16,

    #[arg(long)]
    tls: bool,

    #[arg(long)]
    tls_cert: Option<String>,

    #[arg(long)]
    tls_key: Option<String>,

    #[arg(long, default_value = "1024")]
    max_pins: usize,

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

    log::info!("NextGCore PIN Manager v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Personal IoT Network Manager (3GPP TS 23.542)");

    pin_context_init(args.max_pins);

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
    log::info!("Starting PIN Manager SBI server on {addr}");
    sbi_server.start(pin_sbi_request_handler).await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    log::info!("NextGCore PIN Manager ready");

    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    log::info!("Shutting down...");
    sbi_server.stop().await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;
    pin_context_final();
    log::info!("PIN Manager shutdown complete");

    Ok(())
}

/// PIN Manager SBI request handler
async fn pin_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("PIN SBI: {method} {uri}");

    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match parts.as_slice() {
        // PIN Management
        ["npin-pinmanagement", "v1", "pins"] => {
            match method {
                "POST" => handle_pin_create(&request).await,
                "GET" => handle_pin_list().await,
                _ => send_method_not_allowed(method, "pins"),
            }
        }
        ["npin-pinmanagement", "v1", "pins", pin_id] => {
            match method {
                "GET" => handle_pin_get(pin_id).await,
                "DELETE" => handle_pin_delete(pin_id).await,
                _ => send_method_not_allowed(method, "pins/{id}"),
            }
        }
        // PIN Element Management
        ["npin-pinmanagement", "v1", "pins", pin_id, "elements"] => {
            match method {
                "POST" => handle_element_register(pin_id, &request).await,
                "GET" => handle_element_discover(pin_id, &request).await,
                _ => send_method_not_allowed(method, "pins/{id}/elements"),
            }
        }
        ["npin-pinmanagement", "v1", "pins", _pin_id, "elements", element_id] => {
            match method {
                "GET" => handle_element_get(element_id).await,
                "DELETE" => handle_element_deregister(element_id).await,
                _ => send_method_not_allowed(method, "pins/{id}/elements/{eid}"),
            }
        }
        // PIN Element Relay
        ["npin-pinmanagement", "v1", "elements", element_id, "relay"] => {
            match method {
                "PUT" => handle_element_relay(element_id, &request).await,
                _ => send_method_not_allowed(method, "elements/{id}/relay"),
            }
        }
        _ => send_not_found(&format!("Resource not found: {path}"), None),
    }
}

async fn handle_pin_create(request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let name = data.get("name").and_then(|v| v.as_str()).unwrap_or("Unnamed PIN");
    let owner = data.get("ownerSupi").and_then(|v| v.as_str()).unwrap_or("unknown");

    let ctx = pin_self();
    let result = if let Ok(context) = ctx.read() {
        context.pin_create(name, owner)
    } else {
        None
    };

    match result {
        Some(pin) => {
            SbiResponse::with_status(201)
                .with_json_body(&serde_json::json!({
                    "pinId": pin.pin_id,
                    "name": pin.name,
                    "ownerSupi": pin.owner_supi,
                    "active": pin.active,
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        None => send_bad_request("Failed to create PIN", Some("CREATION_FAILED")),
    }
}

async fn handle_pin_list() -> SbiResponse {
    let ctx = pin_self();
    let pins: Vec<serde_json::Value> = if let Ok(context) = ctx.read() {
        context.pin_list().iter().map(|p| {
            serde_json::json!({
                "pinId": p.pin_id,
                "name": p.name,
                "ownerSupi": p.owner_supi,
                "memberCount": p.member_ids.len(),
                "gatewayId": p.gateway_id,
                "active": p.active,
            })
        }).collect()
    } else {
        vec![]
    };

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({"pins": pins}))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

async fn handle_pin_get(pin_id: &str) -> SbiResponse {
    let ctx = pin_self();
    let pin = if let Ok(context) = ctx.read() {
        context.pin_find(pin_id)
    } else {
        None
    };

    match pin {
        Some(p) => {
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "pinId": p.pin_id,
                    "name": p.name,
                    "ownerSupi": p.owner_supi,
                    "gatewayId": p.gateway_id,
                    "memberIds": p.member_ids,
                    "active": p.active,
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => send_not_found(&format!("PIN {pin_id} not found"), Some("PIN_NOT_FOUND")),
    }
}

async fn handle_pin_delete(pin_id: &str) -> SbiResponse {
    let ctx = pin_self();
    let removed = if let Ok(context) = ctx.read() {
        context.pin_delete(pin_id)
    } else {
        None
    };

    match removed {
        Some(_) => SbiResponse::with_status(204),
        None => send_not_found(&format!("PIN {pin_id} not found"), Some("PIN_NOT_FOUND")),
    }
}

async fn handle_element_register(pin_id: &str, request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let elem_type_str = data.get("elementType").and_then(|v| v.as_str()).unwrap_or("ELEMENT");
    let elem_type = match elem_type_str {
        "GATEWAY" => PinElementType::Gateway,
        "MANAGEMENT" => PinElementType::ManagementEntity,
        _ => PinElementType::Element,
    };
    let capabilities: Vec<String> = data.get("capabilities")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    let host_supi = data.get("hostSupi").and_then(|v| v.as_str()).map(|s| s.to_string());

    let ctx = pin_self();
    let result = if let Ok(context) = ctx.read() {
        context.element_register(pin_id, elem_type, capabilities, host_supi)
    } else {
        None
    };

    match result {
        Some(elem) => {
            SbiResponse::with_status(201)
                .with_json_body(&serde_json::json!({
                    "elementId": elem.element_id,
                    "elementType": elem_type_str,
                    "pinId": elem.pin_id,
                    "status": "REGISTERED",
                    "capabilities": elem.capabilities,
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        None => send_bad_request(
            &format!("Failed to register element in PIN {pin_id}"),
            Some("REGISTRATION_FAILED"),
        ),
    }
}

async fn handle_element_discover(pin_id: &str, request: &SbiRequest) -> SbiResponse {
    let uri = &request.header.uri;
    let capability = uri.split("capability=")
        .nth(1)
        .map(|s| s.split('&').next().unwrap_or(s));

    let ctx = pin_self();
    let elements: Vec<serde_json::Value> = if let Ok(context) = ctx.read() {
        context.element_discover(pin_id, capability).iter().map(|e| {
            serde_json::json!({
                "elementId": e.element_id,
                "elementType": format!("{:?}", e.element_type),
                "capabilities": e.capabilities,
                "status": format!("{:?}", e.status),
                "gatewayId": e.gateway_id,
            })
        }).collect()
    } else {
        vec![]
    };

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({"elements": elements}))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

async fn handle_element_get(element_id: &str) -> SbiResponse {
    let ctx = pin_self();
    let elem = if let Ok(context) = ctx.read() {
        context.element_find(element_id)
    } else {
        None
    };

    match elem {
        Some(e) => {
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "elementId": e.element_id,
                    "elementType": format!("{:?}", e.element_type),
                    "pinId": e.pin_id,
                    "capabilities": e.capabilities,
                    "status": format!("{:?}", e.status),
                    "relayPath": e.relay_path,
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => send_not_found(&format!("Element {element_id} not found"), Some("ELEMENT_NOT_FOUND")),
    }
}

async fn handle_element_deregister(element_id: &str) -> SbiResponse {
    let ctx = pin_self();
    let removed = if let Ok(context) = ctx.read() {
        context.element_deregister(element_id)
    } else {
        None
    };

    match removed {
        Some(_) => SbiResponse::with_status(204),
        None => send_not_found(&format!("Element {element_id} not found"), Some("ELEMENT_NOT_FOUND")),
    }
}

async fn handle_element_relay(element_id: &str, request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let relay_path: Vec<String> = data.get("relayPath")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    let ctx = pin_self();
    let ok = if let Ok(context) = ctx.read() {
        context.element_set_relay(element_id, relay_path)
    } else {
        false
    };

    if ok {
        SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({"elementId": element_id, "result": "RELAY_SET"}))
            .unwrap_or_else(|_| SbiResponse::with_status(200))
    } else {
        send_not_found(&format!("Element {element_id} not found"), Some("ELEMENT_NOT_FOUND"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-pind"]);
        assert_eq!(args.config, "/etc/nextgcore/pin.yaml");
        assert_eq!(args.sbi_port, 7815);
        assert_eq!(args.max_pins, 1024);
    }
}
