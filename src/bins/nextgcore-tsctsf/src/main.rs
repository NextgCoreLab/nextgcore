//! NextGCore TSCTSF — Time Sensitive Communication and Time
//! Synchronization Function (TS 23.501 §5.27–§5.28; service API TS 29.565).
//!
//! Issue #23 first increment: the control-plane NF skeleton with NRF
//! registration (`nfType: TSCTSF`, advertising
//! `ntsctsf-time-synchronization`) and a minimal
//! `Ntsctsf_TimeSynchronization` surface:
//!
//! - `POST /ntsctsf-time-synchronization/v1/configuration` — create a
//!   time-sync exposure configuration (201 + Location + `configId`).
//! - `GET /ntsctsf-time-synchronization/v1/configuration/{configId}` — 200.
//! - `DELETE /ntsctsf-time-synchronization/v1/configuration/{configId}` — 204.
//!
//! Configurations are stored verbatim in an in-memory `TsctsfContext`.
//! Explicitly out of scope per the issue (follow-ups): PFCP TSC container
//! codecs and SMF bridge/port management (PMIC/UMIC/TSCai), PCF TSC policy
//! wiring, gPTP time-domain distribution, and driving the existing UPF
//! `tsn_bridge` scaffolding. A new opt-in binary: nothing else changes
//! behavior.
//!
//! OAuth2 producer enforcement mirrors dccfd: enable with
//! `NEXTGCORE_SBI_OAUTH2_REQUIRE=1` or `<nf>.sbi.oauth2.require: true` in
//! the YAML config; tokens are verified against the NRF JWKS with audience
//! `TSCTSF`.

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_sbi::context::SbiContext;
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::{
    send_bad_request, send_error, send_internal_error, send_method_not_allowed, send_not_found,
    SbiServer, SbiServerConfig,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod context;

pub use context::*;

/// Outbound OAuth2 client (installed only when enforcement is enabled).
static OAUTH2_CLIENT: std::sync::OnceLock<Option<Arc<nextgcore_sbi::oauth::OAuth2Client>>> =
    std::sync::OnceLock::new();

/// NextGCore TSCTSF - Time Sensitive Communication and Time Synchronization Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-tsctsf")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core TSCTSF (TS 23.501 5.27-5.28)", long_about = None)]
struct Args {
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/tsctsf.yaml")]
    config: String,

    #[arg(short = 'l', long)]
    log_file: Option<String>,

    #[arg(short = 'e', long, default_value = "info")]
    log_level: String,

    #[arg(short = 'm', long)]
    no_color: bool,

    #[arg(long, default_value = "0.0.0.0")]
    sbi_addr: String,

    #[arg(long, default_value = "7819")]
    sbi_port: u16,

    #[arg(long)]
    tls: bool,

    #[arg(long)]
    tls_cert: Option<String>,

    #[arg(long)]
    tls_key: Option<String>,

    #[arg(long, default_value = "http://127.0.0.1:7777")]
    nrf_uri: String,

    /// NF instance ID
    #[arg(long)]
    nf_instance_id: Option<String>,

    /// Maximum stored time-sync configurations.
    #[arg(long, default_value = "4096")]
    max_configs: usize,
}

/// OAuth2 enforcement toggle (dccfd pattern): env override, else
/// `<any-section>.sbi.oauth2.require: true` in the YAML config.
fn oauth2_required(config_path: &str) -> bool {
    if let Ok(v) = std::env::var("NEXTGCORE_SBI_OAUTH2_REQUIRE") {
        return matches!(v.trim(), "1" | "true" | "TRUE" | "yes");
    }
    let Ok(content) = std::fs::read_to_string(config_path) else {
        return false;
    };
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(&content) else {
        return false;
    };
    value.as_mapping().is_some_and(|map| {
        map.values().any(|section| {
            section
                .get("sbi")
                .and_then(|s| s.get("oauth2"))
                .and_then(|o| o.get("require"))
                .and_then(|r| r.as_bool())
                .unwrap_or(false)
        })
    })
}

/// Apply OAuth2 producer enforcement (dccfd pattern): verify incoming
/// Bearer tokens against the NRF JWKS with audience `TSCTSF`; with no NRF
/// URI it fails closed.
fn apply_oauth2_enforcement(mut cfg: SbiServerConfig, nrf_uri: &str) -> SbiServerConfig {
    cfg.require_oauth2 = true;
    let uri = (!nrf_uri.is_empty()).then_some(nrf_uri);
    cfg.oauth2_jwks_uri = uri.map(|u| {
        nextgcore_sbi::oauth::JwksCache::for_nrf(u)
            .jwks_uri()
            .to_string()
    });
    cfg = cfg.with_expected_audience_nf_type(nextgcore_sbi::types::NfType::Tsctsf);
    if let Some(u) = uri {
        let nf_instance_id = format!("tsctsf-{}", uuid::Uuid::new_v4());
        let _ = OAUTH2_CLIENT.set(Some(Arc::new(nextgcore_sbi::oauth::OAuth2Client::new(
            u,
            nf_instance_id,
            nextgcore_sbi::types::NfType::Tsctsf,
        ))));
    }
    log::info!(
        "OAuth2 enforcement enabled (JWKS: {})",
        cfg.oauth2_jwks_uri.as_deref().unwrap_or("UNCONFIGURED")
    );
    cfg
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

    log::info!("NextGCore TSCTSF v{}", env!("CARGO_PKG_VERSION"));
    log::info!(
        "Time Sensitive Communication and Time Synchronization Function (TS 23.501 5.27-5.28)"
    );

    tsctsf_context_init(args.max_configs);

    let nf_instance_id = args
        .nf_instance_id
        .clone()
        .unwrap_or_else(|| format!("tsctsf-{}", uuid::Uuid::new_v4()));

    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone());

    let addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;

    let mut sbi_server_config = SbiServerConfig::new(addr);
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
    if oauth2_required(&args.config) {
        sbi_server_config = apply_oauth2_enforcement(sbi_server_config, &args.nrf_uri);
    }

    let sbi_server = SbiServer::new(sbi_server_config);
    log::info!("Starting TSCTSF SBI server on {addr}");
    sbi_server
        .start(tsctsf_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    // Register with NRF as nfType TSCTSF advertising
    // ntsctsf-time-synchronization (non-fatal on failure, nwdafd pattern).
    let sbi_ctx = nextgcore_sbi::context::global_context();
    sbi_ctx.set_nrf_uri(&args.nrf_uri).await;
    if let Err(e) = register_with_nrf(sbi_ctx, &args.sbi_addr, args.sbi_port, &nf_instance_id).await
    {
        log::warn!("NRF registration failed (will operate without NRF): {e}");
    } else {
        // PATCH a real NFProfile "/load" gauge each heartbeat: stored
        // time-sync configurations, saturated at 100 (TS 29.510 §5.2.2.3.2).
        nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(
            nf_instance_id.clone(),
            5,
            || {
                let load = tsctsf_self().read().map(|c| c.config_count()).unwrap_or(0);
                load.min(100) as u8
            },
        );
    }

    log::info!("NextGCore TSCTSF ready (instance: {nf_instance_id})");

    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    log::info!("Shutting down...");
    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;
    tsctsf_context_final();
    log::info!("TSCTSF shutdown complete");

    Ok(())
}

/// TSCTSF SBI request handler
async fn tsctsf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("TSCTSF SBI: {method} {uri}");

    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match parts.as_slice() {
        // Ntsctsf_TimeSynchronization (TS 29.565, minimal subset)
        ["ntsctsf-time-synchronization", "v1", "configuration"] => match method {
            "POST" => handle_config_create(&request).await,
            _ => send_method_not_allowed(method, "configuration"),
        },
        ["ntsctsf-time-synchronization", "v1", "configuration", config_id] => match method {
            "GET" => handle_config_get(config_id).await,
            "DELETE" => handle_config_delete(config_id).await,
            _ => send_method_not_allowed(method, "configuration/{configId}"),
        },
        _ => send_not_found(&format!("Resource not found: {path}"), None),
    }
}

/// POST /ntsctsf-time-synchronization/v1/configuration — create a time-sync
/// exposure configuration (TS 29.565 subset): the body must be a JSON
/// object; an optional `timeDomain` must be an integer 0..=255
/// (IEEE 802.1AS domain number).
async fn handle_config_create(request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };
    if !data.is_object() {
        return send_bad_request(
            "configuration must be a JSON object",
            Some("INVALID_MSG_FORMAT"),
        );
    }
    if let Some(domain) = data.get("timeDomain") {
        if domain.as_u64().is_none_or(|d| d > 255) {
            return send_bad_request(
                "timeDomain must be an integer 0..=255 (IEEE 802.1AS domain)",
                Some("MANDATORY_IE_INCORRECT"),
            );
        }
    }

    let config = TimeSyncConfig::new(body.clone());
    let config_id = config.id.clone();
    let ctx = tsctsf_self();
    let insert = match ctx.read() {
        Ok(c) => c.config_insert(config),
        Err(_) => Err(TsctsfContextError::LockPoisoned),
    };
    match insert {
        Ok(()) => {}
        Err(err @ TsctsfContextError::MaxConfigsReached) => {
            return send_error(507, "Insufficient Storage", err.detail(), Some(err.cause()))
        }
        Err(err) => return send_internal_error(err.detail()),
    }

    let location = format!("/ntsctsf-time-synchronization/v1/configuration/{config_id}");
    log::info!("Time-sync configuration created: id={config_id}");
    let mut echoed = data;
    if let Some(obj) = echoed.as_object_mut() {
        obj.insert("configId".to_string(), serde_json::json!(config_id));
        obj.insert("self".to_string(), serde_json::json!(location));
    }
    SbiResponse::with_status(201)
        .with_header("Location", location)
        .with_json_body(&echoed)
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// GET /ntsctsf-time-synchronization/v1/configuration/{configId} — 200/404.
async fn handle_config_get(config_id: &str) -> SbiResponse {
    let ctx = tsctsf_self();
    let config = match ctx.read() {
        Ok(c) => c.config_find(config_id),
        Err(_) => return send_internal_error("TSCTSF context lock poisoned"),
    };
    let Some(config) = config else {
        return send_not_found(
            &format!("Configuration {config_id} not found"),
            Some("CONFIG_NOT_FOUND"),
        );
    };
    let mut body: serde_json::Value =
        serde_json::from_str(&config.raw).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(obj) = body.as_object_mut() {
        obj.insert("configId".to_string(), serde_json::json!(config.id));
        // Return the same server-canonical `self` link the create response
        // carried, overriding any client-supplied value in the stored body.
        obj.insert(
            "self".to_string(),
            serde_json::json!(format!(
                "/ntsctsf-time-synchronization/v1/configuration/{}",
                config.id
            )),
        );
    }
    SbiResponse::with_status(200)
        .with_json_body(&body)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// DELETE /ntsctsf-time-synchronization/v1/configuration/{configId} — 204/404.
async fn handle_config_delete(config_id: &str) -> SbiResponse {
    let ctx = tsctsf_self();
    let removed = match ctx.read() {
        Ok(c) => c.config_remove(config_id),
        Err(_) => return send_internal_error("TSCTSF context lock poisoned"),
    };
    match removed {
        Some(_) => {
            log::info!("Time-sync configuration removed: id={config_id}");
            SbiResponse::with_status(204)
        }
        None => send_not_found(
            &format!("Configuration {config_id} not found"),
            Some("CONFIG_NOT_FOUND"),
        ),
    }
}

/// Build the NFProfile registered with the NRF (TS 29.510): nfType TSCTSF
/// advertising the ntsctsf-time-synchronization service (TS 29.565).
fn build_nf_profile(nf_instance_id: &str, sbi_addr: &str, sbi_port: u16) -> serde_json::Value {
    serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "TSCTSF",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [
            {
                "serviceInstanceId": format!("{nf_instance_id}-ntsctsf-time-synchronization"),
                "serviceName": "ntsctsf-time-synchronization",
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
            }
        ],
        "allowedNfTypes": ["AF", "NEF", "PCF", "SMF", "SCP"],
        "heartBeatTimer": 10
    })
}

/// Register TSCTSF with NRF (PUT /nnrf-nfm/v1/nf-instances/{id}, nwdafd
/// pattern). Missing NRF URI skips registration; failure is non-fatal.
async fn register_with_nrf(
    sbi_ctx: Arc<SbiContext>,
    sbi_addr: &str,
    sbi_port: u16,
    nf_instance_id: &str,
) -> Result<(), String> {
    let nrf_uri = sbi_ctx.get_nrf_uri().await;
    let nrf_uri = match nrf_uri {
        Some(uri) => uri,
        None => {
            log::debug!("No NRF URI configured, skipping NRF registration");
            return Ok(());
        }
    };

    log::info!("Registering TSCTSF with NRF at {nrf_uri}");

    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_profile = build_nf_profile(nf_instance_id, sbi_addr, sbi_port);

    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    log::debug!("NRF registration: PUT {path}");

    let response = client
        .put_json(&path, &nf_profile)
        .await
        .map_err(|e| format!("NRF registration failed: {e}"))?;

    match response.status {
        200 | 201 => {
            log::info!("TSCTSF registered with NRF successfully (id={nf_instance_id})");

            let mut self_instance = nextgcore_sbi::context::NfInstance::new(
                nf_instance_id,
                nextgcore_sbi::types::NfType::Tsctsf,
            );
            self_instance.ipv4_addresses = vec![sbi_addr.to_string()];
            let mut svc = nextgcore_sbi::context::NfService::new(
                "ntsctsf-time-synchronization",
                nextgcore_sbi::types::SbiServiceType::NtsctsfTimeSynchronization,
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
    use std::sync::Mutex;

    /// Serializes tests that touch the process-global TSCTSF context.
    static GLOBAL_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock_globals() -> std::sync::MutexGuard<'static, ()> {
        GLOBAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reset the process-global context. Callers must hold [`lock_globals`].
    fn reset_context() {
        tsctsf_context_final();
        tsctsf_context_init(1024);
    }

    /// Drive an async handler on a fresh current-thread runtime (the
    /// handlers under test do no real I/O).
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build current-thread runtime")
            .block_on(fut)
    }

    fn create_request(body: serde_json::Value) -> SbiRequest {
        SbiRequest::post("/ntsctsf-time-synchronization/v1/configuration")
            .with_json_body(&body)
            .expect("serialize test body")
    }

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-tsctsf"]);
        assert_eq!(args.config, "/etc/nextgcore/tsctsf.yaml");
        assert_eq!(args.sbi_port, 7819);
        assert_eq!(args.max_configs, 4096);
    }

    // ── NRF registration profile (acceptance: nfType TSCTSF) ────────────────
    #[test]
    fn nf_profile_advertises_tsctsf_and_time_sync_service() {
        let profile = build_nf_profile("tsctsf-test-1", "10.0.0.8", 7819);
        assert_eq!(profile["nfType"], "TSCTSF");
        assert_eq!(profile["nfStatus"], "REGISTERED");
        assert_eq!(
            profile["nfServices"][0]["serviceName"],
            "ntsctsf-time-synchronization"
        );
        assert_eq!(
            profile["nfServices"][0]["serviceInstanceId"],
            "tsctsf-test-1-ntsctsf-time-synchronization"
        );
        assert_eq!(profile["nfServices"][0]["ipEndPoints"][0]["port"], 7819);
    }

    // ── Acceptance flow: create → get → delete → 404 ────────────────────────
    #[test]
    fn config_create_get_delete_flow() {
        let _guard = lock_globals();
        reset_context();

        // POST → 201 + Location + configId.
        let created = block_on(handle_config_create(&create_request(serde_json::json!({
            "timeDomain": 1,
            "timeSyncErrorBudget": 250,
        }))));
        assert_eq!(created.status, 201);
        let location = created
            .http
            .get_header("location")
            .expect("201 must carry Location")
            .clone();
        assert!(location.starts_with("/ntsctsf-time-synchronization/v1/configuration/"));
        let config_id = location.rsplit('/').next().unwrap().to_string();
        let body: serde_json::Value =
            serde_json::from_str(created.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["configId"], config_id);
        assert_eq!(body["self"], location);

        // GET → 200 with the stored configuration.
        let fetched = block_on(handle_config_get(&config_id));
        assert_eq!(fetched.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(fetched.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["timeDomain"], 1);
        assert_eq!(body["configId"], config_id);
        assert_eq!(
            body["self"], location,
            "GET returns the canonical self link"
        );

        // DELETE → 204; the configuration is gone.
        assert_eq!(block_on(handle_config_delete(&config_id)).status, 204);

        // Subsequent GET → 404 (and DELETE → 404).
        assert_eq!(block_on(handle_config_get(&config_id)).status, 404);
        assert_eq!(block_on(handle_config_delete(&config_id)).status, 404);
    }

    #[test]
    fn config_create_validation_400s() {
        let no_body = SbiRequest::post("/ntsctsf-time-synchronization/v1/configuration");
        assert_eq!(block_on(handle_config_create(&no_body)).status, 400);

        let bad_json = SbiRequest::post("/ntsctsf-time-synchronization/v1/configuration")
            .with_body("{not json", "application/json");
        let response = block_on(handle_config_create(&bad_json));
        assert_eq!(response.status, 400);
        let body: serde_json::Value =
            serde_json::from_str(response.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "INVALID_JSON");

        let not_object = create_request(serde_json::json!([1, 2, 3]));
        assert_eq!(block_on(handle_config_create(&not_object)).status, 400);

        let bad_domain = create_request(serde_json::json!({"timeDomain": 999}));
        let response = block_on(handle_config_create(&bad_domain));
        assert_eq!(response.status, 400, "timeDomain > 255 must be 400");
        let body: serde_json::Value =
            serde_json::from_str(response.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "MANDATORY_IE_INCORRECT");
    }

    #[test]
    fn config_create_at_capacity_returns_507() {
        let _guard = lock_globals();
        tsctsf_context_final();
        tsctsf_context_init(1);

        let first = block_on(handle_config_create(&create_request(serde_json::json!({}))));
        assert_eq!(first.status, 201);
        let second = block_on(handle_config_create(&create_request(serde_json::json!({}))));
        assert_eq!(second.status, 507, "cap exhaustion must be 507");
        let body: serde_json::Value =
            serde_json::from_str(second.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "MAX_CONFIGS_REACHED");

        // Restore default test capacity.
        tsctsf_context_final();
        tsctsf_context_init(1024);
    }

    // ── Router (create → get → delete through the full dispatcher) ──────────
    #[test]
    fn router_dispatches_and_rejects() {
        let _guard = lock_globals();
        reset_context();

        // Full-router create.
        let created = block_on(tsctsf_sbi_request_handler(create_request(
            serde_json::json!({"timeDomain": 0}),
        )));
        assert_eq!(created.status, 201);
        let config_id = created
            .http
            .get_header("location")
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_string();

        // Full-router get + delete, then the post-delete 404 leg through
        // the router (not just the direct handler).
        let get = SbiRequest::get(format!(
            "/ntsctsf-time-synchronization/v1/configuration/{config_id}"
        ));
        assert_eq!(block_on(tsctsf_sbi_request_handler(get)).status, 200);
        let delete = SbiRequest::delete(format!(
            "/ntsctsf-time-synchronization/v1/configuration/{config_id}"
        ));
        assert_eq!(block_on(tsctsf_sbi_request_handler(delete)).status, 204);
        let get_gone = SbiRequest::get(format!(
            "/ntsctsf-time-synchronization/v1/configuration/{config_id}"
        ));
        assert_eq!(
            block_on(tsctsf_sbi_request_handler(get_gone)).status,
            404,
            "router GET of a deleted config must 404"
        );

        // Wrong method → 405; unknown path → 404.
        let wrong = SbiRequest::get("/ntsctsf-time-synchronization/v1/configuration");
        assert_eq!(block_on(tsctsf_sbi_request_handler(wrong)).status, 405);
        let unknown = SbiRequest::get("/ntsctsf-qos/v1/whatever");
        assert_eq!(block_on(tsctsf_sbi_request_handler(unknown)).status, 404);
    }
}
