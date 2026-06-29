//! NextGCore EES (Edge Enabler Server)
//!
//! The EES is an Edge Enabler Layer entity (TS 23.558 / TS 24.558 / TS 29.558),
//! NOT a 5GC NRF-discoverable NF (there is no `nfType "EES"` in TS 29.510). It
//! exposes the `eees-*` service APIs with the `{apiRoot}/<apiName>/<apiVersion>`
//! layout and self-registers toward the Edge Configuration Server (ECS) over
//! EDGE-6, not the NRF.
//!
//! Implemented in this bounded chunk:
//! - eesd-01: `eees-*` apiName routing + ECS-registration scaffold; the bespoke
//!   `nees-*`/NRF/`NfType::Ees` self-registration is removed.
//! - eesd-02: `EASRegistration`/`EASProfile`/`EndPoint` data model (`types.rs`)
//!   with mandatory-IE rejection (400 ProblemDetails).
//! - eesd-03: server-minted `registrationId` resource key; consumer `easId`
//!   preserved verbatim and indexed separately.
//! - eesd-08: per-operation OAuth2 authorization (`auth::require_oauth2`).
//!
//! DEFERRED (flagged): eesd-04 (PUT/PATCH update), eesd-05 (full discovery
//! req/resp/filter + subscriptions), eesd-06 (EEC registration), eesd-07 (ACR),
//! eesd-09/10 (UE location/identifier exposure), eesd-11 (suppFeat negotiation),
//! eesd-12 (expTime sweep), eesd-13 (remaining service APIs), eesd-14 (full
//! conformance suite).

use anyhow::{Context, Result};
use clap::Parser;
use ogs_sbi::message::{SbiRequest, SbiResponse};
use ogs_sbi::server::{
    send_bad_request, send_method_not_allowed, send_not_found, SbiServer,
    SbiServerConfig as OgsSbiServerConfig,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod auth;
mod context;
mod ecs_registration;
mod types;

use context::{ees_context_final, ees_context_init, ees_self};
use types::EasRegistration;

/// Resource path prefix (relative to the EES apiRoot) for the individual EAS
/// registration resources — `{apiRoot}/eees-easregistration/v1/registrations`.
const EASREG_REGISTRATIONS_PATH: &str = "/eees-easregistration/v1/registrations";

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

    /// ECS apiRoot for EES self-registration over EDGE-6 (TS 29.558 §9.1).
    /// When unset, the registration request is built and logged but skipped
    /// (no live ECS peer in this stack). Replaces the former `--nrf-uri`.
    #[arg(long)]
    ecs_uri: Option<String>,

    /// EES identifier advertised to the ECS (eesId). Defaults to a fresh UUID.
    #[arg(long)]
    ees_id: Option<String>,

    /// Path to a JSON JWKS used to verify OAuth2 access tokens (CAPIF/NRF
    /// issuer). When unset, every protected operation fails closed with 401
    /// (authorization is mandatory, TS 29.558 §6).
    #[arg(long)]
    oauth2_jwks_file: Option<String>,
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

/// Load the OAuth2 verification JWKS from `path` into the process-global store.
fn load_oauth2_jwks(path: &str) {
    match std::fs::read_to_string(path) {
        Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(jwks) => {
                auth::set_auth_jwks(jwks);
                log::info!("Loaded OAuth2 verification JWKS from {path}");
            }
            Err(e) => log::error!("Failed to parse OAuth2 JWKS file {path}: {e}"),
        },
        Err(e) => log::error!("Failed to read OAuth2 JWKS file {path}: {e}"),
    }
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

    log::info!("NextGCore EES v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Edge Enabler Server (3GPP TS 23.558)");

    ees_context_init(args.max_eas);

    let ees_id = args
        .ees_id
        .clone()
        .unwrap_or_else(|| format!("ees-{}", uuid::Uuid::new_v4()));

    // eesd-08: provision OAuth2 verification keys (fail-closed when absent).
    if let Some(path) = args.oauth2_jwks_file.as_deref() {
        load_oauth2_jwks(path);
    }
    if !auth::is_auth_configured() {
        log::warn!(
            "OAuth2 verification keys not configured: all EES operations will be rejected with \
             401 (per-operation OAuth2 is mandatory, TS 29.558 §6)"
        );
    }

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

    log::info!("Starting EES SBI server on {addr}");
    sbi_server
        .start(ees_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    // eesd-01: self-register toward the ECS (EDGE-6), not the NRF.
    ecs_registration::start_ecs_registration(
        args.ecs_uri.as_deref(),
        &ees_id,
        &args.sbi_addr,
        args.sbi_port,
    )
    .await;

    log::info!("NextGCore EES ready (eesId: {ees_id})");

    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    log::info!("Shutting down...");
    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;

    ees_context_final();
    log::info!("EES shutdown complete");

    Ok(())
}

/// EES SBI request handler.
///
/// Routes on the `eees-*` apiNames with the `{apiRoot}/<apiName>/<apiVersion>`
/// layout (eesd-01). Every protected operation is gated by per-operation OAuth2
/// (eesd-08) *before* the method is dispatched. The legacy `nees-*` /
/// `uecontexttransfer` paths are gone and fall through to 404.
async fn ees_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("EES SBI: {method} {uri}");

    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match parts.as_slice() {
        // eees-easregistration (TS 29.558 §5.2) — EAS registration (EDGE-3).
        ["eees-easregistration", "v1", "registrations"] => {
            if let Some(resp) = auth::require_oauth2(&request, auth::SCOPE_EASREGISTRATION) {
                return resp;
            }
            match method {
                "POST" => handle_eas_register(&request).await,
                "GET" => handle_eas_list().await,
                _ => send_method_not_allowed(method, "registrations"),
            }
        }
        ["eees-easregistration", "v1", "registrations", registration_id] => {
            if let Some(resp) = auth::require_oauth2(&request, auth::SCOPE_EASREGISTRATION) {
                return resp;
            }
            match method {
                "GET" => handle_eas_get(registration_id).await,
                "DELETE" => handle_eas_deregister(registration_id).await,
                // eesd-04 (PUT/PATCH update) DEFERRED.
                _ => send_method_not_allowed(method, "registrations/{registrationId}"),
            }
        }
        // eees-easdiscovery (TS 24.558 §5.3) — EAS discovery (EDGE-1/EDGE-3).
        // NOTE: full EasDiscoveryReq/Resp/Filter model + subscriptions are
        // DEFERRED (eesd-05); this exposes the spec path with a minimal filter.
        ["eees-easdiscovery", "v1", "eas-profiles", "request-discovery"] => {
            if let Some(resp) = auth::require_oauth2(&request, auth::SCOPE_EASDISCOVERY) {
                return resp;
            }
            match method {
                "POST" => handle_eas_discover(&request).await,
                _ => send_method_not_allowed(method, "eas-profiles/request-discovery"),
            }
        }
        _ => send_not_found(&format!("Resource not found: {path}"), None),
    }
}

/// eesd-02/03: handle EAS Registration (`CreateEASRegistration`).
///
/// Parses the `easProf`-wrapped `EASRegistration` body, rejects a missing
/// mandatory `easProf.easId`/`easProf.endPt` with 400 ProblemDetails
/// (`MANDATORY_IE_MISSING`), mints a server `registrationId`, preserves the
/// consumer `easId`, and echoes the stored `EASRegistration` with a `Location`
/// header keyed on the `registrationId`.
async fn handle_eas_register(request: &SbiRequest) -> SbiResponse {
    log::info!("EAS Register");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MANDATORY_IE_MISSING")),
    };

    // Distinguish malformed JSON from a structurally-missing mandatory IE.
    let value: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_MSG_FORMAT")),
    };

    let reg: EasRegistration = match serde_json::from_value(value) {
        Ok(r) => r,
        Err(e) => {
            return send_bad_request(
                &format!("Missing or invalid mandatory IE: {e}"),
                Some("MANDATORY_IE_MISSING"),
            );
        }
    };

    // eesd-03: the consumer-provided easId is mandatory and must be non-empty.
    if reg.eas_prof.eas_id.trim().is_empty() {
        return send_bad_request("Mandatory IE easProf.easId is empty", Some("MANDATORY_IE_MISSING"));
    }
    // eesd-02: endPt must carry at least one reachable address form.
    if reg.eas_prof.end_pt.is_empty() {
        return send_bad_request(
            "Mandatory IE easProf.endPt carries no address",
            Some("MANDATORY_IE_MISSING"),
        );
    }

    let ctx = ees_self();
    let stored = ctx.read().ok().and_then(|context| context.eas_register(reg));

    match stored {
        Some(stored) => {
            let registration_id = stored.registration_id.clone().unwrap_or_default();
            SbiResponse::with_status(201)
                .with_header(
                    "Location",
                    format!("{EASREG_REGISTRATIONS_PATH}/{registration_id}"),
                )
                .with_json_body(&stored)
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        None => send_bad_request(
            "Failed to register EAS (capacity exhausted)",
            Some("INSUFFICIENT_RESOURCES"),
        ),
    }
}

/// List all stored EAS registrations.
async fn handle_eas_list() -> SbiResponse {
    let ctx = ees_self();
    let registrations = ctx.read().map(|c| c.eas_list()).unwrap_or_default();

    SbiResponse::with_status(200)
        .with_json_body(&registrations)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Get an individual EAS registration by its server-minted `registrationId`.
async fn handle_eas_get(registration_id: &str) -> SbiResponse {
    let ctx = ees_self();
    let reg = ctx.read().ok().and_then(|c| c.eas_find(registration_id));

    match reg {
        Some(reg) => SbiResponse::with_status(200)
            .with_json_body(&reg)
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("EAS registration {registration_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        ),
    }
}

/// Deregister an EAS by its `registrationId` (`DeleteIndEASRegistration`).
async fn handle_eas_deregister(registration_id: &str) -> SbiResponse {
    log::info!("EAS Deregister: {registration_id}");

    let ctx = ees_self();
    let removed = ctx
        .read()
        .ok()
        .and_then(|c| c.eas_deregister(registration_id));

    match removed {
        Some(_) => SbiResponse::with_status(204),
        None => send_not_found(
            &format!("EAS registration {registration_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        ),
    }
}

/// eesd-05 (minimal): handle EAS Discovery (`GetEASDiscInfo`).
///
/// Parses an optional `easId` / `type` filter from either the top level or the
/// `easDiscoveryFilter.easChars` object and returns matching `EASProfile`s
/// wrapped as `discoveredEas[].eas` (TS 24.558 `EasDiscoveryResp` shape). The
/// full filter model, location filtering, and discovery subscriptions are
/// DEFERRED (eesd-05/eesd-09). The invented `distanceScore` is gone.
async fn handle_eas_discover(request: &SbiRequest) -> SbiResponse {
    log::info!("EAS Discovery");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MANDATORY_IE_MISSING")),
    };

    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_MSG_FORMAT")),
    };

    let eas_id = data
        .pointer("/easDiscoveryFilter/easChars/easId")
        .or_else(|| data.get("easId"))
        .and_then(|v| v.as_str());
    let eas_type = data
        .pointer("/easDiscoveryFilter/easChars/type")
        .or_else(|| data.get("type"))
        .and_then(|v| v.as_str());

    let ctx = ees_self();
    let discovered: Vec<serde_json::Value> = ctx
        .read()
        .map(|c| {
            c.eas_discover(eas_id, eas_type)
                .into_iter()
                .map(|eas| serde_json::json!({ "eas": eas }))
                .collect()
        })
        .unwrap_or_default();

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({ "discoveredEas": discovered }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    fn signing_key() -> SigningKey {
        SigningKey::from_slice(&[9u8; 32]).unwrap()
    }

    fn jwks_for(sk: &SigningKey, kid: &str) -> serde_json::Value {
        let point = sk.verifying_key().to_encoded_point(false);
        serde_json::json!({"keys":[{
            "kty":"EC","crv":"P-256","use":"sig","alg":"ES256","kid":kid,
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        }]})
    }

    fn bearer(sk: &SigningKey, kid: &str, scope: &str) -> String {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let header = format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{kid}"}}"#);
        let claims = serde_json::json!({
            "iss":"CAPIF","sub":"eec-1","aud":"EES","scope":scope,"exp":exp,"iat":0
        })
        .to_string();
        let h = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let p = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let sig: Signature = sk.sign(format!("{h}.{p}").as_bytes());
        let s = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("Bearer {h}.{p}.{s}")
    }

    /// Drive the async router from a synchronous test on a current-thread
    /// runtime. Used by the global-state tests so the serializing `Mutex` guard
    /// is held only across a *synchronous* `block_on`, never across an async
    /// await point (clippy `await_holding_lock`).
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-eesd"]);
        assert_eq!(args.config, "/etc/nextgcore/ees.yaml");
        assert_eq!(args.sbi_port, 7814);
        assert_eq!(args.max_eas, 512);
        // eesd-01: NRF removed in favour of an optional ECS apiRoot.
        assert!(args.ecs_uri.is_none());
    }

    /// eesd-01: a legacy `nees-*` path is no longer routed → 404.
    #[tokio::test]
    async fn test_router_rejects_legacy_nees_path() {
        let req = SbiRequest::post("/nees-easregistration/v1/registrations");
        let resp = ees_sbi_request_handler(req).await;
        assert_eq!(resp.status, 404);
    }

    /// eesd-08: a protected `eees-*` route with no token → 401 (the route
    /// matched and the OAuth2 gate fired before any handler ran).
    #[test]
    fn test_router_eees_route_requires_auth() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        auth::clear_auth_jwks();
        let req = SbiRequest::post("/eees-easregistration/v1/registrations");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 401);
    }

    /// eesd-08: a valid token carrying the wrong scope → 403.
    #[test]
    fn test_router_wrong_scope_403() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));
        let req = SbiRequest::post("/eees-easregistration/v1/registrations")
            .with_header("Authorization", bearer(&sk, "k1", "eees-easdiscovery"));
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 403);
        auth::clear_auth_jwks();
    }

    /// eesd-01/02/03: a valid token + spec example body → 201 with a `Location`
    /// keyed on a server-minted `registrationId` (≠ easId) and an echoed body
    /// whose `easProf.easId` round-trips.
    #[test]
    fn test_eas_register_mints_registration_id_and_location() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        let body = r#"{"easProf":{"easId":"eas1.example.com","endPt":{"fqdn":"eas1.example.com"}}}"#;
        let req = SbiRequest::post("/eees-easregistration/v1/registrations")
            .with_header("Authorization", bearer(&sk, "k1", "eees-easregistration"))
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));

        assert_eq!(resp.status, 201);
        let location = resp.http.get_header("location").cloned().unwrap();
        assert!(location.starts_with(EASREG_REGISTRATIONS_PATH));
        let registration_id = location.rsplit('/').next().unwrap();
        assert_ne!(registration_id, "eas1.example.com");
        assert!(!registration_id.is_empty());

        let stored: EasRegistration =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(stored.eas_prof.eas_id, "eas1.example.com");
        assert_eq!(stored.registration_id.as_deref(), Some(registration_id));

        auth::clear_auth_jwks();
    }

    /// eesd-02: a body missing the mandatory `endPt` → 400 ProblemDetails.
    #[test]
    fn test_eas_register_missing_endpt_400() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        let body = r#"{"easProf":{"easId":"eas1.example.com"}}"#;
        let req = SbiRequest::post("/eees-easregistration/v1/registrations")
            .with_header("Authorization", bearer(&sk, "k1", "eees-easregistration"))
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 400);

        auth::clear_auth_jwks();
    }

    /// eesd-03: an empty `easId` is rejected as a missing mandatory IE → 400.
    #[test]
    fn test_eas_register_empty_eas_id_400() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        let body = r#"{"easProf":{"easId":"","endPt":{"fqdn":"eas1.example.com"}}}"#;
        let req = SbiRequest::post("/eees-easregistration/v1/registrations")
            .with_header("Authorization", bearer(&sk, "k1", "eees-easregistration"))
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 400);

        auth::clear_auth_jwks();
    }

    /// eesd-01/05: the `eees-easdiscovery` spec path is routed and, with a valid
    /// discovery-scope token, returns a `discoveredEas` envelope (200).
    #[test]
    fn test_eas_discovery_route_dispatches() {
        let _g = auth::GLOBAL_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ees_context_init(512);
        let sk = signing_key();
        auth::set_auth_jwks(jwks_for(&sk, "k1"));

        let body = r#"{"requestorId":"eec-1","easDiscoveryFilter":{"easChars":{"type":"V2X"}}}"#;
        let req = SbiRequest::post("/eees-easdiscovery/v1/eas-profiles/request-discovery")
            .with_header("Authorization", bearer(&sk, "k1", "eees-easdiscovery"))
            .with_body(body, "application/json");
        let resp = block_on(ees_sbi_request_handler(req));
        assert_eq!(resp.status, 200);
        assert!(resp.http.content.as_deref().unwrap().contains("discoveredEas"));

        auth::clear_auth_jwks();
    }
}
