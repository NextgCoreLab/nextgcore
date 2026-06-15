//! NextGCore PIN (Personal IoT Network Manager)
//!
//! The PIN Manager is a Rel-17 NF responsible for (TS 23.542):
//! - Personal IoT Network creation and management
//! - PEGC (PIN Element Gateway Controller) functionality
//! - PIN Element registration, discovery, and communication relay
//! - PIN Element lifecycle management

use anyhow::{Context, Result};
use clap::Parser;
use ogs_sbi::context::global_context;
use ogs_sbi::message::{ProblemDetails, SbiRequest, SbiResponse};
use ogs_sbi::server::{
    send_bad_request, send_forbidden, send_method_not_allowed, send_not_found, SbiServer,
    SbiServerConfig as OgsSbiServerConfig,
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
    .expect("value expected");
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_logging(&args.log_level);
    // G32/G43: Initialize OpenTelemetry tracing (Jaeger/OTLP exporter)
    let _otel = ogs_metrics::otel::init_otel(
        ogs_metrics::otel::OtelConfig::new(env!("CARGO_PKG_NAME")).with_endpoint(
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://jaeger:4317".to_string()),
        ),
    )
    .ok();

    log::info!("NextGCore PIN Manager v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Personal IoT Network Manager (3GPP TS 23.542)");

    pin_context_init(args.max_pins);

    let nf_instance_id = format!("pin-{}", uuid::Uuid::new_v4());

    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone());

    let addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;

    let mut sbi_server_config = OgsSbiServerConfig::new(addr);
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
    }

    let sbi_server = SbiServer::new(sbi_server_config);
    log::info!("Starting PIN Manager SBI server on {addr}");
    sbi_server
        .start(pin_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    // Register with NRF
    let sbi_ctx = global_context();
    sbi_ctx.set_nrf_uri(&args.nrf_uri).await;
    if let Err(e) = register_with_nrf(&args.sbi_addr, args.sbi_port, &nf_instance_id).await {
        log::warn!("NRF registration failed (will operate without NRF): {e}");
    } else {
        ogs_sbi::heartbeat::spawn_heartbeat_worker(nf_instance_id.clone(), 5);
    }

    log::info!("NextGCore PIN Manager ready (instance: {nf_instance_id})");

    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    log::info!("Shutting down...");
    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;
    pin_context_final();
    log::info!("PIN Manager shutdown complete");

    Ok(())
}

/// Extract the caller's SUPI (subscriber permanent identifier) from an
/// incoming SBI request.
///
/// Extraction strategy (in priority order):
///
/// 1. **`x-caller-supi`** — a lightweight bespoke header set by NF consumers
///    (AMF, SMF, UDM) when invoking PIN management operations directly.
///    This is the primary mechanism for intra-core calls where the caller is
///    already authenticated.
///
/// 2. **`3gpp-Sbi-Consumer-Info`** — TS 29.500 §5.2.3 consumer identity
///    header; the SUPI is the value verbatim when the NF consumer is a UE
///    (format: `imsi-…`, `nai-…`, `msisdn-…`).  For machine NF-to-NF calls
///    this header carries an NF instance ID, which we accept as-is — the
///    caller_supi check in the context layer will reject it unless it
///    coincidentally matches the owner SUPI, effectively denying the operation.
///
/// **Gap note**: there is no standardised 3GPP SBI header that carries a UE
/// SUPI on NF-to-NF requests.  In a production deployment the SUPI would
/// typically be extracted from the JWT bearer token's `sub` claim after
/// OAuth2 verification (TS 33.501 §13.4).  Until `require_oauth2` is enabled
/// on the pind server config and the JWT sub-claim extraction is wired in,
/// management-operation callers without the `x-caller-supi` header will be
/// treated as anonymous and denied PEMC registration.
fn extract_caller_supi(request: &SbiRequest) -> Option<String> {
    // 1. Bespoke intra-core header (highest trust — set by authenticated NF consumers)
    if let Some(v) = request.http.get_header("x-caller-supi") {
        let v = v.trim();
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    // 2. TS 29.500 §5.2.3 consumer-info header (best-effort)
    if let Some(v) = request.http.get_header("3gpp-Sbi-Consumer-Info") {
        let v = v.trim();
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    None
}

/// Build a 403 Forbidden `application/problem+json` response for a PIN
/// authorization failure (TS 29.500 §5.2.7).
fn send_pin_forbidden(err: &PinContextError, problem_type: &str) -> SbiResponse {
    let problem = ProblemDetails::with_status(403)
        .with_title("Forbidden")
        .with_detail(err.detail())
        .with_cause(err.cause());
    // Attach the PIN-specific problem type URI.
    let mut response = SbiResponse::with_status(403).with_problem(&problem);
    // Overwrite the body with the type field included.
    let body = serde_json::json!({
        "type": problem_type,
        "title": "Forbidden",
        "status": 403,
        "detail": err.detail(),
        "cause": err.cause(),
    });
    if let Ok(json) = serde_json::to_string(&body) {
        response
            .http
            .set_content(json);
        response
            .http
            .set_header("Content-Type", "application/problem+json");
    }
    response
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
        ["npin-pinmanagement", "v1", "pins"] => match method {
            "POST" => handle_pin_create(&request).await,
            "GET" => handle_pin_list().await,
            _ => send_method_not_allowed(method, "pins"),
        },
        ["npin-pinmanagement", "v1", "pins", pin_id] => match method {
            "GET" => handle_pin_get(pin_id).await,
            "DELETE" => handle_pin_delete(pin_id).await,
            _ => send_method_not_allowed(method, "pins/{id}"),
        },
        // PIN Element Management
        ["npin-pinmanagement", "v1", "pins", pin_id, "elements"] => match method {
            "POST" => handle_element_register(pin_id, &request).await,
            "GET" => handle_element_discover(pin_id, &request).await,
            _ => send_method_not_allowed(method, "pins/{id}/elements"),
        },
        ["npin-pinmanagement", "v1", "pins", _pin_id, "elements", element_id] => match method {
            "GET" => handle_element_get(element_id).await,
            "DELETE" => handle_element_deregister(element_id).await,
            _ => send_method_not_allowed(method, "pins/{id}/elements/{eid}"),
        },
        // PIN Element Relay
        ["npin-pinmanagement", "v1", "elements", element_id, "relay"] => match method {
            "PUT" => handle_element_relay(element_id, &request).await,
            _ => send_method_not_allowed(method, "elements/{id}/relay"),
        },
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

    let name = data
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("Unnamed PIN");
    let owner = data
        .get("ownerSupi")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let ctx = pin_self();
    let result = if let Ok(context) = ctx.read() {
        context.pin_create(name, owner)
    } else {
        None
    };

    match result {
        Some(pin) => SbiResponse::with_status(201)
            .with_json_body(&serde_json::json!({
                "pinId": pin.pin_id,
                "name": pin.name,
                "ownerSupi": pin.owner_supi,
                "active": pin.active,
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(201)),
        None => send_bad_request("Failed to create PIN", Some("CREATION_FAILED")),
    }
}

async fn handle_pin_list() -> SbiResponse {
    let ctx = pin_self();
    let pins: Vec<serde_json::Value> = if let Ok(context) = ctx.read() {
        context
            .pin_list()
            .iter()
            .map(|p| {
                serde_json::json!({
                    "pinId": p.pin_id,
                    "name": p.name,
                    "ownerSupi": p.owner_supi,
                    "memberCount": p.member_ids.len(),
                    "gatewayId": p.gateway_id,
                    "active": p.active,
                })
            })
            .collect()
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
        Some(p) => SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({
                "pinId": p.pin_id,
                "name": p.name,
                "ownerSupi": p.owner_supi,
                "gatewayId": p.gateway_id,
                "memberIds": p.member_ids,
                "active": p.active,
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
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

    let elem_type_str = data
        .get("elementType")
        .and_then(|v| v.as_str())
        .unwrap_or("ELEMENT");
    let elem_type = match elem_type_str {
        "GATEWAY" => PinElementType::Gateway,
        "MANAGEMENT" => PinElementType::ManagementEntity,
        _ => PinElementType::Element,
    };
    let capabilities: Vec<String> = data
        .get("capabilities")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let host_supi = data
        .get("hostSupi")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Extract caller identity for authorization.
    let caller_supi = extract_caller_supi(request);

    let ctx = pin_self();
    let result = if let Ok(context) = ctx.read() {
        context.element_register(
            pin_id,
            elem_type,
            capabilities,
            host_supi,
            caller_supi.as_deref(),
        )
    } else {
        Err(PinContextError::NotFound)
    };

    match result {
        Ok(elem) => SbiResponse::with_status(201)
            .with_json_body(&serde_json::json!({
                "elementId": elem.element_id,
                "elementType": elem_type_str,
                "pinId": elem.pin_id,
                "status": "REGISTERED",
                "capabilities": elem.capabilities,
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(201)),
        Err(PinContextError::NotFound) => send_not_found(
            &format!("PIN {pin_id} not found"),
            Some("PIN_NOT_FOUND"),
        ),
        Err(PinContextError::PemcRequiresOwner) => send_pin_forbidden(
            &PinContextError::PemcRequiresOwner,
            "urn:3gpp:pin:element-authorization-failed",
        ),
        Err(PinContextError::RelayOnlyForPegc) => {
            // Logically impossible here, but satisfy the exhaustive match.
            send_forbidden("Unexpected role violation", Some("ROLE_VIOLATION"))
        }
    }
}

async fn handle_element_discover(pin_id: &str, request: &SbiRequest) -> SbiResponse {
    let uri = &request.header.uri;
    let capability = uri
        .split("capability=")
        .nth(1)
        .map(|s| s.split('&').next().unwrap_or(s));

    let ctx = pin_self();
    let elements: Vec<serde_json::Value> = if let Ok(context) = ctx.read() {
        context
            .element_discover(pin_id, capability)
            .iter()
            .map(|e| {
                serde_json::json!({
                    "elementId": e.element_id,
                    "elementType": format!("{:?}", e.element_type),
                    "capabilities": e.capabilities,
                    "status": format!("{:?}", e.status),
                    "gatewayId": e.gateway_id,
                })
            })
            .collect()
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
        Some(e) => SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({
                "elementId": e.element_id,
                "elementType": format!("{:?}", e.element_type),
                "pinId": e.pin_id,
                "capabilities": e.capabilities,
                "status": format!("{:?}", e.status),
                "relayPath": e.relay_path,
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("Element {element_id} not found"),
            Some("ELEMENT_NOT_FOUND"),
        ),
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
        None => send_not_found(
            &format!("Element {element_id} not found"),
            Some("ELEMENT_NOT_FOUND"),
        ),
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

    let relay_path: Vec<String> = data
        .get("relayPath")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let ctx = pin_self();
    let result = if let Ok(context) = ctx.read() {
        context.element_set_relay(element_id, relay_path)
    } else {
        Err(PinContextError::NotFound)
    };

    match result {
        Ok(()) => SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({"elementId": element_id, "result": "RELAY_SET"}))
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        Err(PinContextError::NotFound) => send_not_found(
            &format!("Element {element_id} not found"),
            Some("ELEMENT_NOT_FOUND"),
        ),
        Err(PinContextError::RelayOnlyForPegc) => send_pin_forbidden(
            &PinContextError::RelayOnlyForPegc,
            "urn:3gpp:pin:relay-authorization-failed",
        ),
        Err(PinContextError::PemcRequiresOwner) => {
            // Logically impossible here, but satisfy the exhaustive match.
            send_forbidden("Unexpected role violation", Some("ROLE_VIOLATION"))
        }
    }
}

/// Register PIN Manager with NRF
async fn register_with_nrf(
    sbi_addr: &str,
    sbi_port: u16,
    nf_instance_id: &str,
) -> Result<(), String> {
    let sbi_ctx = global_context();
    let nrf_uri = match sbi_ctx.get_nrf_uri().await {
        Some(uri) => uri,
        None => return Ok(()),
    };
    log::info!("Registering PIN with NRF at {nrf_uri}");
    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;
    let nf_profile = serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "PIN",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [{
            // TS 23.542: pind implements the Npin_PINManagement service
            // (PIN CRUD, element register/discover/deregister, and the
            // element relay operation, all routed under npin-pinmanagement).
            "serviceInstanceId": format!("{}-npin-pinmanagement", nf_instance_id),
            "serviceName": "npin-pinmanagement",
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
        }],
        "allowedNfTypes": ["AMF", "SMF", "UDM"],
        "heartBeatTimer": 10
    });
    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    let response = client
        .put_json(&path, &nf_profile)
        .await
        .map_err(|e| format!("NRF registration failed: {e}"))?;
    match response.status {
        200 | 201 => {
            log::info!("PIN registered with NRF (id={nf_instance_id})");
            Ok(())
        }
        _ => Err(format!("NRF returned status {}", response.status)),
    }
}

fn parse_host_port(uri: &str) -> Option<(String, u16)> {
    let without_scheme = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    let (host_port, _) = without_scheme
        .split_once('/')
        .unwrap_or((without_scheme, ""));
    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        Some((host.to_string(), port_str.parse().ok()?))
    } else {
        Some((
            host_port.to_string(),
            if uri.starts_with("https://") { 443 } else { 80 },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ogs_sbi::message::SbiRequest;

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-pind"]);
        assert_eq!(args.config, "/etc/nextgcore/pin.yaml");
        assert_eq!(args.sbi_port, 7815);
        assert_eq!(args.max_pins, 1024);
    }

    // T4.4: extract_caller_supi helper tests
    #[test]
    fn test_extract_caller_supi_x_header() {
        let request = SbiRequest::post("/npin-pinmanagement/v1/pins/pin-1/elements")
            .with_header("x-caller-supi", "imsi-001010000000007");
        assert_eq!(
            extract_caller_supi(&request).as_deref(),
            Some("imsi-001010000000007")
        );
    }

    #[test]
    fn test_extract_caller_supi_consumer_info_fallback() {
        let request = SbiRequest::post("/npin-pinmanagement/v1/pins/pin-1/elements")
            .with_header("3gpp-Sbi-Consumer-Info", "imsi-001010000000008");
        assert_eq!(
            extract_caller_supi(&request).as_deref(),
            Some("imsi-001010000000008")
        );
    }

    #[test]
    fn test_extract_caller_supi_x_header_takes_precedence() {
        let request = SbiRequest::post("/npin-pinmanagement/v1/pins/pin-1/elements")
            .with_header("x-caller-supi", "imsi-primary")
            .with_header("3gpp-Sbi-Consumer-Info", "imsi-secondary");
        assert_eq!(
            extract_caller_supi(&request).as_deref(),
            Some("imsi-primary")
        );
    }

    #[test]
    fn test_extract_caller_supi_absent() {
        let request = SbiRequest::post("/npin-pinmanagement/v1/pins/pin-1/elements");
        assert_eq!(extract_caller_supi(&request), None);
    }

    // T4.4: send_pin_forbidden produces correct problem+json
    #[test]
    fn test_send_pin_forbidden_problem_shape() {
        let response = send_pin_forbidden(
            &PinContextError::PemcRequiresOwner,
            "urn:3gpp:pin:element-authorization-failed",
        );
        assert_eq!(response.status, 403);
        let ct = response.http.get_header("content-type").map(String::as_str);
        assert_eq!(ct, Some("application/problem+json"));

        let body: serde_json::Value =
            serde_json::from_str(response.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["status"], 403);
        assert_eq!(body["cause"], "PEMC_REQUIRES_OWNER");
        assert_eq!(body["type"], "urn:3gpp:pin:element-authorization-failed");
    }

    #[test]
    fn test_send_pin_forbidden_relay_shape() {
        let response = send_pin_forbidden(
            &PinContextError::RelayOnlyForPegc,
            "urn:3gpp:pin:relay-authorization-failed",
        );
        assert_eq!(response.status, 403);
        let body: serde_json::Value =
            serde_json::from_str(response.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "RELAY_ONLY_FOR_PEGC");
        assert_eq!(body["type"], "urn:3gpp:pin:relay-authorization-failed");
    }
}
