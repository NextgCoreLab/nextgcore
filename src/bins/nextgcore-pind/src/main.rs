//! NextGCore PIN — application-layer Personal IoT Network (PIN) server.
//!
//! TS 23.542 defines the PIN server as an *application-enablement-layer*
//! entity reachable over the PIN reference points PIN-6 (PEMC, §6.4.7),
//! PIN-7 (PEGC, §6.4.8) and PIN-8 (3GPP core, §6.4.9). It is **not** a 5GC
//! SBI Network Function: there is no `PIN` NfType in TS 29.510 and no
//! `Npin_PINManagement` service in 3GPP. This binary therefore exposes a
//! NextGCore-internal RESTful binding for the PIN application — modelling the
//! PIN-6/7/8 procedures — and does **not** register itself as a discoverable
//! 3GPP NF.
//!
//! Responsibilities (TS 23.542):
//! - Personal IoT Network creation and management (PIN-6)
//! - PEGC (PIN Element Gateway Controller) relay (PIN-7)
//! - PIN Element registration, discovery, and communication relay
//! - PIN Element lifecycle management

use anyhow::{Context, Result};
use clap::Parser;
use ogs_sbi::message::{ProblemDetails, SbiRequest, SbiResponse};
use ogs_sbi::oauth::JwksCache;
use ogs_sbi::server::{
    send_bad_request, send_forbidden, send_method_not_allowed, send_not_found, SbiServer,
    SbiServerConfig as OgsSbiServerConfig,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Whether OAuth2 bearer-token verification is enforced on the SBI server.
/// When true, a request reaching a handler has already had its token
/// cryptographically verified (signature + expiry) at the server layer, so
/// the token's `sub` claim can be trusted as the caller identity (PIND-10).
static OAUTH2_ENABLED: AtomicBool = AtomicBool::new(false);
/// Whether the bespoke, unverified `x-caller-supi` / `3gpp-Sbi-Consumer-Info`
/// headers may be trusted as a caller-identity source. Default false; enabled
/// only via `--trust-caller-supi-header` for mutually-authenticated intra-core
/// transports (PIND-10).
static TRUST_CALLER_SUPI_HEADER: AtomicBool = AtomicBool::new(false);

fn oauth2_enabled() -> bool {
    OAUTH2_ENABLED.load(Ordering::Relaxed)
}

fn trust_caller_supi_header() -> bool {
    TRUST_CALLER_SUPI_HEADER.load(Ordering::Relaxed)
}

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

    /// PIND-10: enforce OAuth2 bearer-token verification on the SBI server.
    /// Default false to preserve intra-core callers that do not yet attach a
    /// token; when true, the NRF JWKS (`--nrf-uri`) verifies every request.
    #[arg(long, default_value = "false")]
    require_oauth2: bool,

    /// PIND-10: trust the bespoke `x-caller-supi` header as a caller-identity
    /// source. Default false (the header is unverified and forgeable); enable
    /// only on a mutually-authenticated intra-core transport.
    #[arg(long, default_value = "false")]
    trust_caller_supi_header: bool,

    /// PIND-03: default PIN lifetime (seconds) assigned as the Expiration time
    /// at PIN create (TS 23.542 Table 8.5.2.3.3-1).
    #[arg(long, default_value = "86400")]
    default_pin_lifetime_secs: u64,

    /// PIND-03: default per-PIN Heartbeat Timer (seconds) assigned at PIN
    /// create (TS 23.542 Table 8.5.2.3.3-1).
    #[arg(long, default_value = "30")]
    default_heartbeat_secs: u64,
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

    log::info!("NextGCore PIN application server v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Application-layer Personal IoT Network server (TS 23.542; PIN-6/7/8)");

    pin_context_init(
        args.max_pins,
        args.default_pin_lifetime_secs,
        args.default_heartbeat_secs,
    );

    // PIND-10: caller-identity trust policy.
    OAUTH2_ENABLED.store(args.require_oauth2, Ordering::Relaxed);
    TRUST_CALLER_SUPI_HEADER.store(args.trust_caller_supi_header, Ordering::Relaxed);

    let nf_instance_id = format!("pin-app-{}", uuid::Uuid::new_v4());

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
    // PIND-10: enforce OAuth2 on the application binding when requested. Keys
    // come from the NRF JWKS endpoint (same path other NFs use). No audience
    // check is set: pind is not a TS 29.510 NfType, so there is no NF-type
    // `aud` to assert against.
    if args.require_oauth2 {
        sbi_server_config.require_oauth2 = true;
        sbi_server_config.oauth2_jwks_uri =
            Some(JwksCache::for_nrf(&args.nrf_uri).jwks_uri().to_string());
        log::info!(
            "OAuth2 enforcement enabled (JWKS: {})",
            sbi_server_config
                .oauth2_jwks_uri
                .as_deref()
                .unwrap_or("UNCONFIGURED")
        );
    }

    let sbi_server = SbiServer::new(sbi_server_config);
    log::info!("Starting PIN application server on {addr}");
    sbi_server
        .start(pin_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    // NOTE (PIND-01): pind is an application-layer PIN server (TS 23.542
    // §6.4.7-6.4.9 PIN-6/7/8), NOT a 5GC SBI NF. It deliberately does NOT
    // register with the NRF — there is no `PIN` NfType (TS 29.510) and no
    // `Npin_PINManagement` service (TS 29.500) to advertise. Service
    // discovery for the PIN application is out of band of the 5GC SBA.

    log::info!("NextGCore PIN application server ready (instance: {nf_instance_id})");

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

/// Read the caller identity from the bearer token's verified `sub` claim
/// (PIND-10; TS 29.500 §5.2.3, TS 33.501 §13.4).
///
/// **FLAG / known gap.** ogs-sbi verifies the bearer token at the *server*
/// layer when `require_oauth2` is enabled (signature + expiry, rejecting bad
/// tokens with 401 before dispatch), but it does **not** thread the decoded
/// claims into `SbiRequest`, and there is no public accessor on `SbiRequest`
/// for the verified `sub`. We therefore re-read the already-verified token's
/// payload here using the public `ogs_sbi::oauth::decode_jwt_parts` +
/// `AccessTokenClaims`. This is sound for trust **only** because the server
/// has already cryptographically verified the same token; the caller (via
/// [`extract_caller_supi`]) gates this on [`oauth2_enabled`]. A token read
/// while OAuth2 is disabled is unverified and MUST NOT be trusted.
///
/// (A clean fix is to add a `verified claims` accessor to ogs-sbi
/// additively and thread the claims through `SbiRequest`; out of scope for
/// this pind-local change, which must not modify shared libs.)
fn caller_supi_from_token(request: &SbiRequest) -> Option<String> {
    let auth = request.http.get_header("authorization")?;
    let token = auth
        .strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))?
        .trim();
    let (_header, payload, _sig) = ogs_sbi::oauth::decode_jwt_parts(token).ok()?;
    let claims: ogs_sbi::oauth::AccessTokenClaims = serde_json::from_slice(&payload).ok()?;
    let sub = claims.sub.trim();
    if sub.is_empty() {
        None
    } else {
        Some(sub.to_string())
    }
}

/// Extract the caller's SUPI / consumer identity from an incoming request.
///
/// Priority order (PIND-10):
///
/// 1. **Verified JWT `sub` claim** — the highest-trust source. Honored only
///    when `trust_token` is set (i.e. OAuth2 enforcement is on, so the token
///    reaching this handler was cryptographically verified at the server
///    layer).
/// 2. **`x-caller-supi`** — a bespoke, unverified intra-core header. Honored
///    only when `trust_header` is set (`--trust-caller-supi-header`, default
///    off), as it is forgeable on an untrusted transport.
/// 3. **`3gpp-Sbi-Consumer-Info`** — TS 29.500 §5.2.3 consumer header, also
///    unverified; honored under the same `trust_header` gate.
///
/// With neither trusted source available the caller is anonymous (`None`) and
/// every management/state-changing operation denies it.
fn extract_caller_supi(request: &SbiRequest, trust_token: bool, trust_header: bool) -> Option<String> {
    // 1. Verified JWT sub claim (highest priority).
    if trust_token {
        if let Some(sub) = caller_supi_from_token(request) {
            return Some(sub);
        }
    }
    // 2/3. Bespoke / consumer-info headers — only when explicitly trusted.
    if trust_header {
        if let Some(v) = request.http.get_header("x-caller-supi") {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
        if let Some(v) = request.http.get_header("3gpp-Sbi-Consumer-Info") {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Resolve the caller identity using the process-wide trust policy
/// ([`oauth2_enabled`] + [`trust_caller_supi_header`]). Handlers use this;
/// unit tests call [`extract_caller_supi`] directly with explicit flags.
fn caller_supi(request: &SbiRequest) -> Option<String> {
    extract_caller_supi(request, oauth2_enabled(), trust_caller_supi_header())
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

    // PIND-01: route prefix `pinapp` denotes the NextGCore-internal,
    // application-layer PIN binding (TS 23.542 PIN-6/7/8 reference points).
    // It is NOT the (non-existent) 3GPP `npin-pinmanagement` SBI service.
    match parts.as_slice() {
        // PIN Management (PIN-6)
        ["pinapp", "v1", "pins"] => match method {
            "POST" => handle_pin_create(&request).await,
            "GET" => handle_pin_list().await,
            _ => send_method_not_allowed(method, "pins"),
        },
        ["pinapp", "v1", "pins", pin_id] => match method {
            "GET" => handle_pin_get(pin_id).await,
            "DELETE" => handle_pin_delete(pin_id, &request).await,
            _ => send_method_not_allowed(method, "pins/{id}"),
        },
        // PIN Element Management (PIN-6)
        ["pinapp", "v1", "pins", pin_id, "elements"] => match method {
            "POST" => handle_element_register(pin_id, &request).await,
            "GET" => handle_element_discover(pin_id, &request).await,
            _ => send_method_not_allowed(method, "pins/{id}/elements"),
        },
        ["pinapp", "v1", "pins", _pin_id, "elements", element_id] => match method {
            "GET" => handle_element_get(element_id).await,
            "DELETE" => handle_element_deregister(element_id, &request).await,
            _ => send_method_not_allowed(method, "pins/{id}/elements/{eid}"),
        },
        // PIN Element Relay (PIN-7)
        ["pinapp", "v1", "elements", element_id, "relay"] => match method {
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

    // PIND-02: mandatory IEs per TS 23.542 Table 8.5.2.3.2-1.
    // UE Identifier (M).
    let ue_id = match data.get("ueId").and_then(|v| v.as_str()) {
        Some(s) if !s.trim().is_empty() => s.trim(),
        _ => {
            return send_bad_request(
                "Missing UE Identifier (ueId)",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };
    // Security credentials (M). Presence + non-empty format check; full
    // authorization validation is tracked under PIND-10.
    match data.get("securityCredentials") {
        Some(v) if !v.is_null() && v.as_str().map(|s| !s.trim().is_empty()).unwrap_or(true) => {}
        _ => {
            return send_bad_request(
                "Missing Security credentials (securityCredentials)",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    }

    // PIND-02: derive the owner from the *authenticated* caller, never the
    // free-form body. An anonymous caller cannot create a PIN.
    let caller = match caller_supi(request) {
        Some(c) => c,
        None => {
            return send_forbidden(
                "Unauthenticated PIN create: no verified caller identity",
                Some("AUTHENTICATION_REQUIRED"),
            )
        }
    };

    // PIND-02: the asserted UE Identifier must match the authenticated caller.
    if ue_id != caller {
        return send_forbidden(
            &format!("ueId '{ue_id}' does not match the authenticated caller"),
            Some("UE_ID_MISMATCH"),
        );
    }

    let name = data
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("Unnamed PIN");

    let ctx = pin_self();
    let result = if let Ok(context) = ctx.read() {
        // PIND-03: lifecycle defaults assigned inside pin_create.
        context.pin_create(name, &caller)
    } else {
        None
    };

    match result {
        // PIND-03: 201 carries the mandatory PIN ID, Expiration time and
        // Heartbeat Timer (TS 23.542 Table 8.5.2.3.3-1).
        Some(pin) => SbiResponse::with_status(201)
            .with_json_body(&serde_json::json!({
                "pinId": pin.pin_id,
                "name": pin.name,
                "ownerSupi": pin.owner_supi,
                "ueId": ue_id,
                "active": pin.active,
                "expirationTime": pin.expiration_time,
                "heartbeatTimer": pin.heartbeat_timer,
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
                    "expirationTime": p.expiration_time,
                    "heartbeatTimer": p.heartbeat_timer,
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
                "expirationTime": p.expiration_time,
                "heartbeatTimer": p.heartbeat_timer,
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(&format!("PIN {pin_id} not found"), Some("PIN_NOT_FOUND")),
    }
}

async fn handle_pin_delete(pin_id: &str, request: &SbiRequest) -> SbiResponse {
    // PIND-04: authorize the destructive delete against the caller identity.
    let caller = caller_supi(request);
    let ctx = pin_self();
    let result = if let Ok(context) = ctx.read() {
        context.pin_delete(pin_id, caller.as_deref())
    } else {
        Err(PinContextError::NotFound)
    };

    match result {
        Ok(_) => SbiResponse::with_status(204),
        Err(PinContextError::NotFound) => {
            send_not_found(&format!("PIN {pin_id} not found"), Some("PIN_NOT_FOUND"))
        }
        Err(PinContextError::PemcRequiresOwner) => send_pin_forbidden(
            &PinContextError::PemcRequiresOwner,
            "urn:nextgcore:pin:delete-authorization-failed",
        ),
        Err(PinContextError::RelayOnlyForPegc) => {
            // Logically impossible on delete, but satisfy the exhaustive match.
            send_forbidden("Unexpected role violation", Some("ROLE_VIOLATION"))
        }
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

    // Extract caller identity for authorization (PIND-10 trust policy).
    let caller = caller_supi(request);

    let ctx = pin_self();
    let result = if let Ok(context) = ctx.read() {
        context.element_register(
            pin_id,
            elem_type,
            capabilities,
            host_supi,
            caller.as_deref(),
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
            "urn:nextgcore:pin:element-authorization-failed",
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

async fn handle_element_deregister(element_id: &str, request: &SbiRequest) -> SbiResponse {
    // PIND-04: authorize the destructive deregister against the caller.
    let caller = caller_supi(request);
    let ctx = pin_self();
    let result = if let Ok(context) = ctx.read() {
        context.element_deregister(element_id, caller.as_deref())
    } else {
        Err(PinContextError::NotFound)
    };

    match result {
        Ok(_) => SbiResponse::with_status(204),
        Err(PinContextError::NotFound) => send_not_found(
            &format!("Element {element_id} not found"),
            Some("ELEMENT_NOT_FOUND"),
        ),
        Err(PinContextError::PemcRequiresOwner) => send_pin_forbidden(
            &PinContextError::PemcRequiresOwner,
            "urn:nextgcore:pin:deregister-authorization-failed",
        ),
        Err(PinContextError::RelayOnlyForPegc) => {
            // Logically impossible on deregister, but satisfy the match.
            send_forbidden("Unexpected role violation", Some("ROLE_VIOLATION"))
        }
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
            "urn:nextgcore:pin:relay-authorization-failed",
        ),
        Err(PinContextError::PemcRequiresOwner) => {
            // Logically impossible here, but satisfy the exhaustive match.
            send_forbidden("Unexpected role violation", Some("ROLE_VIOLATION"))
        }
    }
}

// PIND-01: the former `register_with_nrf` / `parse_host_port` helpers were
// removed. They advertised an invented `nfType: "PIN"` and a non-existent
// `npin-pinmanagement` 3GPP service to the NRF. pind is an application-layer
// PIN server (TS 23.542 §6.4.7-6.4.9 PIN-6/7/8), not a discoverable 5GC SBI
// NF, so it no longer registers with the NRF. The `--nrf-uri` flag is now
// used only to locate the NRF JWKS endpoint when OAuth2 is enforced (PIND-10).

#[cfg(test)]
mod tests {
    use super::*;
    use ogs_sbi::message::SbiRequest;
    use std::sync::Mutex;

    /// A precomputed JWT (`header.payload.sig`) whose payload decodes to
    /// `AccessTokenClaims { sub: "imsi-token-owner-001", .. }`. The signature
    /// is NOT cryptographically valid: `caller_supi_from_token` only
    /// base64-decodes the parts and reads `sub`. In production the ogs-sbi
    /// server layer has already verified the same token before dispatch, which
    /// is why `extract_caller_supi` only honors the token under `trust_token`
    /// (i.e. `oauth2_enabled()`).
    const TOKEN_OWNER_001: &str = concat!(
        "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.",
        "eyJpc3MiOiAibnJmIiwgInN1YiI6ICJpbXNpLXRva2VuLW93bmVyLTAwMSIsICJhdWQiOi",
        "AicGluIiwgInNjb3BlIjogIngiLCAiZXhwIjogOTk5OTk5OTk5OX0.",
        "dW52ZXJpZmllZC1zaWduYXR1cmUtYnl0ZXM"
    );

    /// Serializes the tests that mutate the process-wide trust atomics
    /// (`OAUTH2_ENABLED` / `TRUST_CALLER_SUPI_HEADER`) and/or the global PIN
    /// context, so they cannot race. The guard is held across the *synchronous*
    /// `block_on` only (never across an `.await`), so `clippy::await_holding_lock`
    /// does not apply.
    static GLOBAL_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock_globals() -> std::sync::MutexGuard<'static, ()> {
        GLOBAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Drive an async handler to completion on a fresh current-thread runtime.
    /// The handlers do no real I/O, so no timer/IO drivers are needed.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build current-thread runtime")
            .block_on(fut)
    }

    fn json_body(v: serde_json::Value) -> SbiRequest {
        SbiRequest::post("/pinapp/v1/pins")
            .with_json_body(&v)
            .expect("serialize test body")
    }

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-pind"]);
        assert_eq!(args.config, "/etc/nextgcore/pin.yaml");
        assert_eq!(args.sbi_port, 7815);
        assert_eq!(args.max_pins, 1024);
        // PIND-10: trust is off by default.
        assert!(!args.require_oauth2);
        assert!(!args.trust_caller_supi_header);
    }

    // ── PIND-10: caller identity extraction (pure, explicit trust flags) ─────

    /// owner-from-token: a verified token's `sub` is the highest-priority
    /// source and wins over a (forgeable) header when both are trusted.
    #[test]
    fn extract_caller_supi_prefers_verified_token_sub() {
        let request = SbiRequest::post("/pinapp/v1/pins")
            .with_header("authorization", format!("Bearer {TOKEN_OWNER_001}"))
            .with_header("x-caller-supi", "imsi-forged-header");
        assert_eq!(
            extract_caller_supi(&request, true, true).as_deref(),
            Some("imsi-token-owner-001"),
            "verified token sub must take precedence over the header"
        );
    }

    #[test]
    fn caller_supi_from_token_reads_sub_claim() {
        let request = SbiRequest::post("/pinapp/v1/pins")
            .with_header("authorization", format!("Bearer {TOKEN_OWNER_001}"));
        assert_eq!(
            caller_supi_from_token(&request).as_deref(),
            Some("imsi-token-owner-001")
        );
    }

    /// With OAuth2 off (`trust_token=false`) the token must NOT be trusted.
    #[test]
    fn extract_caller_supi_ignores_token_when_untrusted() {
        let request = SbiRequest::post("/pinapp/v1/pins")
            .with_header("authorization", format!("Bearer {TOKEN_OWNER_001}"));
        assert_eq!(extract_caller_supi(&request, false, false), None);
    }

    #[test]
    fn extract_caller_supi_x_header_when_trusted() {
        let request = SbiRequest::post("/pinapp/v1/pins")
            .with_header("x-caller-supi", "imsi-001010000000007");
        assert_eq!(
            extract_caller_supi(&request, false, true).as_deref(),
            Some("imsi-001010000000007")
        );
    }

    #[test]
    fn extract_caller_supi_consumer_info_fallback_when_trusted() {
        let request = SbiRequest::post("/pinapp/v1/pins")
            .with_header("3gpp-Sbi-Consumer-Info", "imsi-001010000000008");
        assert_eq!(
            extract_caller_supi(&request, false, true).as_deref(),
            Some("imsi-001010000000008")
        );
    }

    #[test]
    fn extract_caller_supi_x_header_takes_precedence_over_consumer_info() {
        let request = SbiRequest::post("/pinapp/v1/pins")
            .with_header("x-caller-supi", "imsi-primary")
            .with_header("3gpp-Sbi-Consumer-Info", "imsi-secondary");
        assert_eq!(
            extract_caller_supi(&request, false, true).as_deref(),
            Some("imsi-primary")
        );
    }

    /// The bespoke header is forgeable and MUST be ignored unless explicitly
    /// trusted via `--trust-caller-supi-header`.
    #[test]
    fn extract_caller_supi_header_ignored_when_not_trusted() {
        let request = SbiRequest::post("/pinapp/v1/pins")
            .with_header("x-caller-supi", "imsi-forged");
        assert_eq!(extract_caller_supi(&request, false, false), None);
    }

    #[test]
    fn extract_caller_supi_absent_is_none() {
        let request = SbiRequest::post("/pinapp/v1/pins");
        assert_eq!(extract_caller_supi(&request, true, true), None);
    }

    // ── send_pin_forbidden problem+json shape ───────────────────────────────
    #[test]
    fn test_send_pin_forbidden_problem_shape() {
        let response = send_pin_forbidden(
            &PinContextError::PemcRequiresOwner,
            "urn:nextgcore:pin:element-authorization-failed",
        );
        assert_eq!(response.status, 403);
        let ct = response.http.get_header("content-type").map(String::as_str);
        assert_eq!(ct, Some("application/problem+json"));

        let body: serde_json::Value =
            serde_json::from_str(response.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["status"], 403);
        assert_eq!(body["cause"], "PEMC_REQUIRES_OWNER");
        assert_eq!(body["type"], "urn:nextgcore:pin:element-authorization-failed");
    }

    #[test]
    fn test_send_pin_forbidden_relay_shape() {
        let response = send_pin_forbidden(
            &PinContextError::RelayOnlyForPegc,
            "urn:nextgcore:pin:relay-authorization-failed",
        );
        assert_eq!(response.status, 403);
        let body: serde_json::Value =
            serde_json::from_str(response.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "RELAY_ONLY_FOR_PEGC");
        assert_eq!(body["type"], "urn:nextgcore:pin:relay-authorization-failed");
    }

    // ── PIND-02: mandatory-IE validation on create (returns before any
    //    global-state read, so these need no lock) ─────────────────────────
    #[test]
    fn handle_pin_create_empty_body_returns_400() {
        let resp = block_on(handle_pin_create(&json_body(serde_json::json!({}))));
        assert_eq!(resp.status, 400, "missing UE Identifier must be 400");
    }

    #[test]
    fn handle_pin_create_missing_credentials_returns_400() {
        let resp = block_on(handle_pin_create(&json_body(
            serde_json::json!({ "ueId": "imsi-x" }),
        )));
        assert_eq!(resp.status, 400, "missing Security credentials must be 400");
    }

    #[test]
    fn handle_pin_create_no_body_returns_400() {
        let resp = block_on(handle_pin_create(&SbiRequest::post("/pinapp/v1/pins")));
        assert_eq!(resp.status, 400);
    }

    // ── PIND-02: anonymous / mismatched caller (touch the trust atomics) ────
    #[test]
    fn handle_pin_create_anonymous_returns_403() {
        let _g = lock_globals();
        OAUTH2_ENABLED.store(false, Ordering::Relaxed);
        TRUST_CALLER_SUPI_HEADER.store(false, Ordering::Relaxed);

        let request = json_body(serde_json::json!({
            "ueId": "imsi-x",
            "securityCredentials": "tok",
        }));
        let resp = block_on(handle_pin_create(&request));
        assert_eq!(resp.status, 403, "no verified caller must be 403");
    }

    #[test]
    fn handle_pin_create_ueid_mismatch_returns_403() {
        let _g = lock_globals();
        OAUTH2_ENABLED.store(false, Ordering::Relaxed);
        TRUST_CALLER_SUPI_HEADER.store(true, Ordering::Relaxed);

        let request = SbiRequest::post("/pinapp/v1/pins")
            .with_header("x-caller-supi", "imsi-caller-aaa")
            .with_json_body(&serde_json::json!({
                "ueId": "imsi-different-bbb",
                "securityCredentials": "tok",
            }))
            .expect("serialize test body");
        let resp = block_on(handle_pin_create(&request));
        TRUST_CALLER_SUPI_HEADER.store(false, Ordering::Relaxed);
        assert_eq!(resp.status, 403, "ueId not matching caller must be 403");
    }

    // ── PIND-03: a successful create returns 201 with Expiration time +
    //    Heartbeat Timer (TS 23.542 Table 8.5.2.3.3-1) ─────────────────────
    #[test]
    fn handle_pin_create_success_returns_201_with_expiry_and_heartbeat() {
        let _g = lock_globals();
        pin_context_init(1024, 86_400, 30);
        OAUTH2_ENABLED.store(false, Ordering::Relaxed);
        TRUST_CALLER_SUPI_HEADER.store(true, Ordering::Relaxed);

        let caller = "imsi-create-owner-777";
        let request = SbiRequest::post("/pinapp/v1/pins")
            .with_header("x-caller-supi", caller)
            .with_json_body(&serde_json::json!({
                "ueId": caller,
                "securityCredentials": "tok",
                "name": "Home",
            }))
            .expect("serialize test body");
        let resp = block_on(handle_pin_create(&request));
        TRUST_CALLER_SUPI_HEADER.store(false, Ordering::Relaxed);

        assert_eq!(resp.status, 201);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(body["pinId"].as_str().is_some(), "201 must carry pinId");
        assert_eq!(body["ownerSupi"], caller, "owner is the authenticated caller");
        assert!(
            body["expirationTime"].as_u64().unwrap() > 0,
            "201 must carry a mandatory Expiration time"
        );
        assert_eq!(
            body["heartbeatTimer"], 30,
            "201 must carry the mandatory Heartbeat Timer"
        );
    }

    // ── PIND-04: delete / deregister authorization at the HTTP layer ────────
    #[test]
    fn handle_pin_delete_not_found_returns_404() {
        let _g = lock_globals();
        pin_context_init(1024, 86_400, 30);
        OAUTH2_ENABLED.store(false, Ordering::Relaxed);
        TRUST_CALLER_SUPI_HEADER.store(false, Ordering::Relaxed);

        let request = SbiRequest::post("/pinapp/v1/pins/pin-absent-zzz");
        let resp = block_on(handle_pin_delete("pin-absent-zzz", &request));
        assert_eq!(resp.status, 404);
    }

    #[test]
    fn handle_pin_delete_non_owner_returns_403() {
        let _g = lock_globals();
        pin_context_init(1024, 86_400, 30);
        OAUTH2_ENABLED.store(false, Ordering::Relaxed);
        TRUST_CALLER_SUPI_HEADER.store(true, Ordering::Relaxed);

        // Seed a PIN owned by someone else directly in the global context.
        let pin_id = {
            let ctx = pin_self();
            let guard = ctx.read().expect("ctx read");
            guard
                .pin_create("Home", "imsi-real-owner-del")
                .expect("seed pin")
                .pin_id
        };

        let request = SbiRequest::post(format!("/pinapp/v1/pins/{pin_id}"))
            .with_header("x-caller-supi", "imsi-attacker-del");
        let resp = block_on(handle_pin_delete(&pin_id, &request));
        TRUST_CALLER_SUPI_HEADER.store(false, Ordering::Relaxed);
        assert_eq!(resp.status, 403, "non-owner delete must be 403");
    }

    #[test]
    fn handle_element_deregister_not_found_returns_404() {
        let _g = lock_globals();
        pin_context_init(1024, 86_400, 30);
        OAUTH2_ENABLED.store(false, Ordering::Relaxed);
        TRUST_CALLER_SUPI_HEADER.store(false, Ordering::Relaxed);

        let request = SbiRequest::post("/pinapp/v1/pins/pin-x/elements/pe-absent-zzz");
        let resp = block_on(handle_element_deregister("pe-absent-zzz", &request));
        assert_eq!(resp.status, 404);
    }

    #[test]
    fn handle_element_deregister_non_owner_returns_403() {
        let _g = lock_globals();
        pin_context_init(1024, 86_400, 30);
        OAUTH2_ENABLED.store(false, Ordering::Relaxed);
        TRUST_CALLER_SUPI_HEADER.store(true, Ordering::Relaxed);

        let elem_id = {
            let ctx = pin_self();
            let guard = ctx.read().expect("ctx read");
            let pin = guard.pin_create("Home", "imsi-owner-dereg").expect("seed pin");
            guard
                .element_register(
                    &pin.pin_id,
                    PinElementType::Element,
                    vec![],
                    None,
                    Some("imsi-owner-dereg"),
                )
                .expect("seed element")
                .element_id
        };

        let request = SbiRequest::post(format!("/pinapp/v1/pins/x/elements/{elem_id}"))
            .with_header("x-caller-supi", "imsi-attacker-dereg");
        let resp = block_on(handle_element_deregister(&elem_id, &request));
        TRUST_CALLER_SUPI_HEADER.store(false, Ordering::Relaxed);
        assert_eq!(resp.status, 403, "non-owner deregister must be 403");
    }
}
