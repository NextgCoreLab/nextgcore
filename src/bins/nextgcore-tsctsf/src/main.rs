//! NextGCore TSCTSF — Time Sensitive Communication and Time
//! Synchronization Function (TS 23.501 §5.27–§5.28; service API TS 29.565).
//!
//! #113 completed the CONTROL-PLANE surface of all three services TS 23.501
//! Table 7.2.26-1 mandates. Issue #23 landed only a three-verb store over one
//! bespoke collection.
//!
//! `Ntsctsf_TimeSynchronization` (TS 23.502 §5.2.27.2):
//!
//! - `POST   /ntsctsf-time-synchronization/v1/configuration` — ConfigCreate.
//! - `GET    /ntsctsf-time-synchronization/v1/configuration/{configId}`.
//! - `PATCH  /…/configuration/{configId}` — ConfigUpdate, merge semantics.
//! - `PUT    /…/configuration/{configId}` — ConfigUpdate, whole-resource replace.
//! - `DELETE /…/configuration/{configId}` — ConfigDelete.
//! - `POST   /…/subscriptions` — CapsSubscribe (mints a Subscription Correlation
//!   ID).
//! - `GET`/`DELETE /…/subscriptions/{subscriptionId}` — CapsUnsubscribe.
//! - ConfigUpdateNotify fires on a config change; CapsNotify fans out to every
//!   capability subscriber.
//!
//! `Ntsctsf_ASTI` (§5.2.27.4): `POST`/`GET`/`PATCH`/`PUT`/`DELETE` on
//! `/ntsctsf-asti/v1/configurations[/{configId}]`, with UpdateNotify.
//!
//! `Ntsctsf_QoSandTSCAssistance` (§5.2.27.3): `POST`/`GET`/`PATCH`/`PUT`/`DELETE`
//! on `/ntsctsf-qos-tsctsf/v1/tsc-qos-requests[/{transactionRefId}]` plus
//! Subscribe/Unsubscribe on `/ntsctsf-qos-tsctsf/v1/subscriptions`, with Notify.
//!
//! Configurations are now stored as TYPED IEs (see `context::TimeSyncExposureConfig`
//! and siblings), so a malformed body is refused at ingress with the TS 29.500
//! §5.2.7.2 cause that names the offending member, instead of being stored verbatim
//! and discovered later.
//!
//! **What #113 deliberately did NOT do, and where it went instead.** The
//! actuation leg — a PCF client issuing `Npcf_PolicyAuthorization_Create`/
//! `Subscribe`, deriving PMIC/UMIC/TSCAI, and driving the UPF `tsn_bridge` and the
//! SMF port-management path — is cross-NF and cannot be verified end-to-end
//! anywhere in this tree: tsctsf, smfd and upfd are separate processes and there is
//! no PFCP TSC container codec. #113's own suggested approach says the issue is
//! *"best tracked as an umbrella issue split into per-service child issues rather
//! than delivered in one change"*, so that leg is split out as its own issue rather
//! than landed off-by-default where no test would exercise it. Consequence worth
//! being blunt about: **a stored configuration still actuates nothing.** An operator
//! discovering `nfType: TSCTSF` now gets three conformant control-plane services,
//! not a working time-synchronisation function.
//!
//! **Spelling caveat:** `TS29565_Ntsctsf_*.yaml` is not vendored in this tree, so
//! the resource paths and JSON member names are derived from the Stage-2 parameter
//! names in TS 23.502 §5.2.27 rather than verified against the Stage-3 schema.
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

    // #235: NFDeregister (TS 29.510 5.2.2.2.3) BEFORE the listener goes
    // away, so the NRF stops handing this profile to consumers instead of
    // waiting out its supervision timer. Stopping the server first would
    // open the bad window: not serving, but still advertised.
    nextgcore_sbi::heartbeat::deregister_self().await;
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
        // ---- Ntsctsf_TimeSynchronization (TS 23.502 §5.2.27.2) ----
        ["ntsctsf-time-synchronization", "v1", "configuration"] => match method {
            "POST" => handle_config_create(&request).await,
            _ => send_method_not_allowed(method, "configuration"),
        },
        ["ntsctsf-time-synchronization", "v1", "configuration", config_id] => match method {
            "GET" => handle_config_get(config_id).await,
            // #113: ConfigUpdate (§5.2.27.2.3). PATCH merges; PUT replaces. Both
            // are served because §5.2.27.2.3's only required input is the PTP
            // instance reference and every parameter is optional, which is merge
            // semantics -- but a consumer that wants to state the whole
            // configuration should not be forced into a merge.
            "PATCH" => handle_config_update(config_id, &request).await,
            "PUT" => handle_config_replace(config_id, &request).await,
            "DELETE" => handle_config_delete(config_id).await,
            _ => send_method_not_allowed(method, "configuration/{configId}"),
        },
        // #113: CapsSubscribe / CapsUnsubscribe (§5.2.27.2.6, §5.2.27.2.7).
        ["ntsctsf-time-synchronization", "v1", "subscriptions"] => match method {
            "POST" => handle_caps_subscribe(&request).await,
            _ => send_method_not_allowed(method, "subscriptions"),
        },
        ["ntsctsf-time-synchronization", "v1", "subscriptions", subscription_id] => match method {
            "GET" => handle_caps_subscription_get(subscription_id).await,
            "DELETE" => handle_caps_unsubscribe(subscription_id).await,
            _ => send_method_not_allowed(method, "subscriptions/{subscriptionId}"),
        },

        // ---- Ntsctsf_ASTI (TS 23.502 §5.2.27.4) ----
        ["ntsctsf-asti", "v1", "configurations"] => match method {
            "POST" => handle_asti_create(&request).await,
            _ => send_method_not_allowed(method, "configurations"),
        },
        ["ntsctsf-asti", "v1", "configurations", config_id] => match method {
            "GET" => handle_asti_get(config_id).await,
            "PATCH" | "PUT" => handle_asti_update(config_id, &request).await,
            "DELETE" => handle_asti_delete(config_id).await,
            _ => send_method_not_allowed(method, "configurations/{configId}"),
        },

        // ---- Ntsctsf_QoSandTSCAssistance (TS 23.502 §5.2.27.3) ----
        ["ntsctsf-qos-tsctsf", "v1", "tsc-qos-requests"] => match method {
            "POST" => handle_qos_tsc_create(&request).await,
            _ => send_method_not_allowed(method, "tsc-qos-requests"),
        },
        ["ntsctsf-qos-tsctsf", "v1", "tsc-qos-requests", transaction_id] => match method {
            "GET" => handle_qos_tsc_get(transaction_id).await,
            "PATCH" | "PUT" => handle_qos_tsc_update(transaction_id, &request).await,
            "DELETE" => handle_qos_tsc_delete(transaction_id).await,
            _ => send_method_not_allowed(method, "tsc-qos-requests/{transactionId}"),
        },
        ["ntsctsf-qos-tsctsf", "v1", "subscriptions"] => match method {
            "POST" => handle_qos_tsc_subscribe(&request).await,
            _ => send_method_not_allowed(method, "subscriptions"),
        },
        ["ntsctsf-qos-tsctsf", "v1", "subscriptions", subscription_id] => match method {
            "GET" => handle_qos_tsc_subscription_get(subscription_id).await,
            "DELETE" => handle_qos_tsc_unsubscribe(subscription_id).await,
            _ => send_method_not_allowed(method, "subscriptions/{subscriptionId}"),
        },

        // #113: administrative trigger for CapsNotify (§5.2.27.2.8).
        //
        // NOT a 3GPP service operation. The 5GS capability change that would
        // trigger CapsNotify has NO in-tree source -- reporting one needs the
        // UPF/NW-TT capability leg, which is split out as its own issue. Without a
        // trigger the notify path would be unreachable in principle, which is this
        // repo's recorded "grep the SINK before implementing an emit-side feature"
        // hazard in reverse. This route is the producer, and it is named `admin` so
        // nobody mistakes it for part of the Ntsctsf API.
        ["ntsctsf-time-synchronization", "v1", "admin", "capability-change"] => match method {
            "POST" => handle_admin_capability_change(&request).await,
            _ => send_method_not_allowed(method, "admin/capability-change"),
        },

        _ => send_not_found(&format!("Resource not found: {path}"), None),
    }
}

/// POST /ntsctsf-time-synchronization/v1/configuration — create a time-sync
/// exposure configuration (TS 29.565 subset): the body must be a JSON
/// object; an optional `timeDomain` must be an integer 0..=255
/// (IEEE 802.1AS domain number).
async fn handle_config_create(request: &SbiRequest) -> SbiResponse {
    let (data, config) = match parse_typed_body::<context::TimeSyncExposureConfig>(request) {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };
    if let Err(err) = config.validate() {
        return send_bad_request(&err.detail(), Some(err.cause()));
    }
    let mut config = config;
    config.raw = data.clone();

    let stored = context::TimeSyncConfig::new(config);
    let config_id = stored.id.clone();
    let ctx = tsctsf_self();
    let insert = match ctx.read() {
        Ok(c) => c.config_insert(stored),
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
    SbiResponse::with_status(201)
        .with_header("Location", location.clone())
        .with_json_body(&config_body(&config_id, &data, &location))
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// Parse a request body into `T`, distinguishing the TS 29.500 §5.2.7.2 causes.
///
/// Returns the raw JSON alongside the typed value, because every handler here
/// echoes the body back with the server-minted id and `self` link, and a consumer
/// that sent an optional parameter this build does not model should get it back
/// rather than have it silently dropped.
///
/// A serde TYPE mismatch is `INVALID_MSG_FORMAT` and an absent required member is
/// `MANDATORY_IE_MISSING` (raised by each type's `validate`). `serde(default)`
/// covers an absent member; it does **not** rescue a mismatched one, which is why
/// the two causes come from two different places.
fn parse_typed_body<T: serde::de::DeserializeOwned>(
    request: &SbiRequest,
) -> Result<(serde_json::Value, T), Box<SbiResponse>> {
    let Some(body) = &request.http.content else {
        return Err(Box::new(send_bad_request(
            "Missing request body",
            Some("MISSING_BODY"),
        )));
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return Err(Box::new(send_bad_request(
                &format!("Invalid JSON: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )))
        }
    };
    if !data.is_object() {
        return Err(Box::new(send_bad_request(
            "request body must be a JSON object",
            Some("INVALID_MSG_FORMAT"),
        )));
    }
    match serde_json::from_value::<T>(data.clone()) {
        Ok(typed) => Ok((data, typed)),
        Err(e) => Err(Box::new(send_bad_request(
            &format!("Invalid IE: {e}"),
            Some("INVALID_MSG_FORMAT"),
        ))),
    }
}

/// The response body for a configuration resource: the body as received plus the
/// server-minted `configId` and the server-canonical `self` link.
///
/// `self` overrides any client-supplied value: the link is the server's statement
/// about where the resource lives, not the consumer's.
fn config_body(config_id: &str, raw: &serde_json::Value, self_link: &str) -> serde_json::Value {
    let mut body = raw.clone();
    if let Some(obj) = body.as_object_mut() {
        obj.insert("configId".to_string(), serde_json::json!(config_id));
        obj.insert("self".to_string(), serde_json::json!(self_link));
    }
    body
}

/// PATCH /ntsctsf-time-synchronization/v1/configuration/{configId} — ConfigUpdate
/// (#113, TS 23.502 §5.2.27.2.3). 200 on success, 404 for an unknown id.
async fn handle_config_update(config_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(body) = &request.http.content else {
        return send_bad_request("Missing request body", Some("MISSING_BODY"));
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_MSG_FORMAT"))
        }
    };
    if !data.is_object() {
        return send_bad_request(
            "request body must be a JSON object",
            Some("INVALID_MSG_FORMAT"),
        );
    }

    let ctx = tsctsf_self();
    let updated = match ctx.read() {
        Ok(c) => c.config_update(config_id, &data),
        Err(_) => return send_internal_error("TSCTSF context lock poisoned"),
    };
    let Some(updated) = updated else {
        return send_not_found(
            &format!("Configuration {config_id} not found"),
            Some("CONFIG_NOT_FOUND"),
        );
    };
    // The merge must not be able to produce an invalid configuration: an update
    // that blanks the notification target address would leave a configuration that
    // can never notify, which is what the validation exists to prevent.
    if let Err(err) = updated.config.validate() {
        return send_bad_request(&err.detail(), Some(err.cause()));
    }

    let self_link = format!("/ntsctsf-time-synchronization/v1/configuration/{config_id}");
    let body = updated_config_body(&updated, &self_link);
    // ConfigUpdateNotify (§5.2.27.2.5): the configuration changed, so tell whoever
    // asked to be told. Awaited so the notification is on the wire before the 200,
    // which is what makes the test able to observe it without a sleep.
    notify_config_update(&updated, &body).await;

    log::info!("Time-sync configuration updated: id={config_id}");
    SbiResponse::with_status(200)
        .with_json_body(&body)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// PUT /ntsctsf-time-synchronization/v1/configuration/{configId} — ConfigUpdate as
/// a whole-resource replace (#113).
async fn handle_config_replace(config_id: &str, request: &SbiRequest) -> SbiResponse {
    let (data, config) = match parse_typed_body::<context::TimeSyncExposureConfig>(request) {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };
    if let Err(err) = config.validate() {
        return send_bad_request(&err.detail(), Some(err.cause()));
    }
    let mut config = config;
    config.raw = data;

    let ctx = tsctsf_self();
    let updated = match ctx.read() {
        Ok(c) => c.config_replace(config_id, config),
        Err(_) => return send_internal_error("TSCTSF context lock poisoned"),
    };
    let Some(updated) = updated else {
        return send_not_found(
            &format!("Configuration {config_id} not found"),
            Some("CONFIG_NOT_FOUND"),
        );
    };

    let self_link = format!("/ntsctsf-time-synchronization/v1/configuration/{config_id}");
    let body = updated_config_body(&updated, &self_link);
    notify_config_update(&updated, &body).await;

    log::info!("Time-sync configuration replaced: id={config_id}");
    SbiResponse::with_status(200)
        .with_json_body(&body)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Render a stored configuration, merging the typed members over the body as
/// received so an update is visible in the response.
fn updated_config_body(stored: &context::TimeSyncConfig, self_link: &str) -> serde_json::Value {
    let mut body = match serde_json::to_value(&stored.config) {
        Ok(serde_json::Value::Object(typed)) => {
            // Start from what the consumer sent, so unmodelled optional parameters
            // survive, then overlay the typed members, which are authoritative for
            // anything this build understands.
            let mut merged = match stored.config.raw.clone() {
                serde_json::Value::Object(raw) => raw,
                _ => serde_json::Map::new(),
            };
            for (k, v) in typed {
                if !v.is_null() {
                    merged.insert(k, v);
                }
            }
            serde_json::Value::Object(merged)
        }
        _ => stored.config.raw.clone(),
    };
    if let Some(obj) = body.as_object_mut() {
        obj.insert("configId".to_string(), serde_json::json!(stored.id));
        obj.insert("self".to_string(), serde_json::json!(self_link));
    }
    body
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
    // Returns the same server-canonical `self` link the create response carried,
    // overriding any client-supplied value in the stored body.
    let self_link = format!(
        "/ntsctsf-time-synchronization/v1/configuration/{}",
        config.id
    );
    SbiResponse::with_status(200)
        .with_json_body(&updated_config_body(&config, &self_link))
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

// ============================================================================
// #113: Ntsctsf_TimeSynchronization capability subscriptions (§5.2.27.2.6-.2.8)
// ============================================================================

/// POST /ntsctsf-time-synchronization/v1/subscriptions — CapsSubscribe
/// (§5.2.27.2.6). 201 + Location + the minted Subscription Correlation ID.
async fn handle_caps_subscribe(request: &SbiRequest) -> SbiResponse {
    let (data, sub) = match parse_typed_body::<context::CapsSubscription>(request) {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };
    if let Err(err) = sub.validate() {
        return send_bad_request(&err.detail(), Some(err.cause()));
    }

    let ctx = tsctsf_self();
    let created = match ctx.read() {
        Ok(c) => c.caps_sub_create(sub),
        Err(_) => Err(TsctsfContextError::LockPoisoned),
    };
    let created = match created {
        Ok(sub) => sub,
        Err(err @ TsctsfContextError::MaxConfigsReached) => {
            return send_error(507, "Insufficient Storage", err.detail(), Some(err.cause()))
        }
        Err(err) => return send_internal_error(err.detail()),
    };

    let location = format!(
        "/ntsctsf-time-synchronization/v1/subscriptions/{}",
        created.subscription_id
    );
    log::info!(
        "Time-sync capability subscription created: id={}",
        created.subscription_id
    );
    let mut body = data;
    if let Some(obj) = body.as_object_mut() {
        obj.insert(
            "subscriptionId".to_string(),
            serde_json::json!(created.subscription_id),
        );
        obj.insert("self".to_string(), serde_json::json!(location));
    }
    SbiResponse::with_status(201)
        .with_header("Location", location.clone())
        .with_json_body(&body)
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// GET /ntsctsf-time-synchronization/v1/subscriptions/{subscriptionId} — 200/404.
async fn handle_caps_subscription_get(subscription_id: &str) -> SbiResponse {
    let ctx = tsctsf_self();
    let sub = match ctx.read() {
        Ok(c) => c.caps_sub_find(subscription_id),
        Err(_) => return send_internal_error("TSCTSF context lock poisoned"),
    };
    match sub {
        Some(sub) => SbiResponse::with_status(200)
            .with_json_body(&sub)
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("Subscription {subscription_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        ),
    }
}

/// DELETE /ntsctsf-time-synchronization/v1/subscriptions/{subscriptionId} —
/// CapsUnsubscribe (§5.2.27.2.7). 204/404.
async fn handle_caps_unsubscribe(subscription_id: &str) -> SbiResponse {
    let ctx = tsctsf_self();
    let removed = match ctx.read() {
        Ok(c) => c.caps_sub_remove(subscription_id),
        Err(_) => return send_internal_error("TSCTSF context lock poisoned"),
    };
    match removed {
        Some(_) => {
            log::info!("Time-sync capability subscription removed: id={subscription_id}");
            SbiResponse::with_status(204)
        }
        None => send_not_found(
            &format!("Subscription {subscription_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        ),
    }
}

// ============================================================================
// #113: Ntsctsf_ASTI (§5.2.27.4)
// ============================================================================

/// POST /ntsctsf-asti/v1/configurations — ASTI_Create (§5.2.27.4.2).
async fn handle_asti_create(request: &SbiRequest) -> SbiResponse {
    let (data, cfg) = match parse_typed_body::<context::AstiConfig>(request) {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };
    if let Err(err) = cfg.validate() {
        return send_bad_request(&err.detail(), Some(err.cause()));
    }

    let ctx = tsctsf_self();
    let created = match ctx.read() {
        Ok(c) => c.asti_create(cfg),
        Err(_) => Err(TsctsfContextError::LockPoisoned),
    };
    let created = match created {
        Ok(cfg) => cfg,
        Err(err @ TsctsfContextError::MaxConfigsReached) => {
            return send_error(507, "Insufficient Storage", err.detail(), Some(err.cause()))
        }
        Err(err) => return send_internal_error(err.detail()),
    };

    let location = format!("/ntsctsf-asti/v1/configurations/{}", created.config_id);
    log::info!(
        "ASTI configuration created: id={} (af={})",
        created.config_id,
        created.af_id
    );
    let mut body = data;
    if let Some(obj) = body.as_object_mut() {
        obj.insert("configId".to_string(), serde_json::json!(created.config_id));
        obj.insert("self".to_string(), serde_json::json!(location));
    }
    SbiResponse::with_status(201)
        .with_header("Location", location.clone())
        .with_json_body(&body)
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// GET /ntsctsf-asti/v1/configurations/{configId} — ASTI_Get (§5.2.27.4.5).
async fn handle_asti_get(config_id: &str) -> SbiResponse {
    let ctx = tsctsf_self();
    let cfg = match ctx.read() {
        Ok(c) => c.asti_find(config_id),
        Err(_) => return send_internal_error("TSCTSF context lock poisoned"),
    };
    match cfg {
        Some(cfg) => SbiResponse::with_status(200)
            .with_json_body(&cfg)
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("ASTI configuration {config_id} not found"),
            Some("CONFIG_NOT_FOUND"),
        ),
    }
}

/// PATCH/PUT /ntsctsf-asti/v1/configurations/{configId} — ASTI_Update
/// (§5.2.27.4.3).
async fn handle_asti_update(config_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(body) = &request.http.content else {
        return send_bad_request("Missing request body", Some("MISSING_BODY"));
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_MSG_FORMAT"))
        }
    };
    let ctx = tsctsf_self();
    let updated = match ctx.read() {
        Ok(c) => c.asti_update(config_id, &data),
        Err(_) => return send_internal_error("TSCTSF context lock poisoned"),
    };
    let Some(updated) = updated else {
        return send_not_found(
            &format!("ASTI configuration {config_id} not found"),
            Some("CONFIG_NOT_FOUND"),
        );
    };
    // ASTI_UpdateNotify (§5.2.27.4, "UpdateNotify"): the configuration changed, so
    // tell the target the create registered, if any.
    notify_asti_update(&updated).await;
    log::info!("ASTI configuration updated: id={config_id}");
    SbiResponse::with_status(200)
        .with_json_body(&updated)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// DELETE /ntsctsf-asti/v1/configurations/{configId} — ASTI_Delete
/// (§5.2.27.4.4). 204/404.
async fn handle_asti_delete(config_id: &str) -> SbiResponse {
    let ctx = tsctsf_self();
    let removed = match ctx.read() {
        Ok(c) => c.asti_remove(config_id),
        Err(_) => return send_internal_error("TSCTSF context lock poisoned"),
    };
    match removed {
        Some(_) => {
            log::info!("ASTI configuration removed: id={config_id}");
            SbiResponse::with_status(204)
        }
        None => send_not_found(
            &format!("ASTI configuration {config_id} not found"),
            Some("CONFIG_NOT_FOUND"),
        ),
    }
}

// ============================================================================
// #113: Ntsctsf_QoSandTSCAssistance (§5.2.27.3)
// ============================================================================

/// POST /ntsctsf-qos-tsctsf/v1/tsc-qos-requests — Create (§5.2.27.3.2). The
/// response carries the Transaction Reference ID.
async fn handle_qos_tsc_create(request: &SbiRequest) -> SbiResponse {
    let (data, session) = match parse_typed_body::<context::QosTscSession>(request) {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };
    if let Err(err) = session.validate() {
        return send_bad_request(&err.detail(), Some(err.cause()));
    }

    let ctx = tsctsf_self();
    let created = match ctx.read() {
        Ok(c) => c.qos_tsc_create(session),
        Err(_) => Err(TsctsfContextError::LockPoisoned),
    };
    let created = match created {
        Ok(s) => s,
        Err(err @ TsctsfContextError::MaxConfigsReached) => {
            return send_error(507, "Insufficient Storage", err.detail(), Some(err.cause()))
        }
        Err(err) => return send_internal_error(err.detail()),
    };

    let location = format!(
        "/ntsctsf-qos-tsctsf/v1/tsc-qos-requests/{}",
        created.transaction_ref_id
    );
    log::info!(
        "QoS/TSC assistance session created: transaction={} (af={})",
        created.transaction_ref_id,
        created.af_id
    );
    let mut body = data;
    if let Some(obj) = body.as_object_mut() {
        obj.insert(
            "transactionRefId".to_string(),
            serde_json::json!(created.transaction_ref_id),
        );
        obj.insert("self".to_string(), serde_json::json!(location));
    }
    SbiResponse::with_status(201)
        .with_header("Location", location.clone())
        .with_json_body(&body)
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// GET /ntsctsf-qos-tsctsf/v1/tsc-qos-requests/{transactionRefId} — 200/404.
async fn handle_qos_tsc_get(transaction_id: &str) -> SbiResponse {
    let ctx = tsctsf_self();
    let session = match ctx.read() {
        Ok(c) => c.qos_tsc_find(transaction_id),
        Err(_) => return send_internal_error("TSCTSF context lock poisoned"),
    };
    match session {
        Some(s) => SbiResponse::with_status(200)
            .with_json_body(&s)
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("Transaction {transaction_id} not found"),
            Some("TRANSACTION_NOT_FOUND"),
        ),
    }
}

/// PATCH/PUT /ntsctsf-qos-tsctsf/v1/tsc-qos-requests/{transactionRefId} — Update
/// (§5.2.27.3.3).
async fn handle_qos_tsc_update(transaction_id: &str, request: &SbiRequest) -> SbiResponse {
    let Some(body) = &request.http.content else {
        return send_bad_request("Missing request body", Some("MISSING_BODY"));
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_MSG_FORMAT"))
        }
    };
    let ctx = tsctsf_self();
    let updated = match ctx.read() {
        Ok(c) => c.qos_tsc_update(transaction_id, &data),
        Err(_) => return send_internal_error("TSCTSF context lock poisoned"),
    };
    let Some(updated) = updated else {
        return send_not_found(
            &format!("Transaction {transaction_id} not found"),
            Some("TRANSACTION_NOT_FOUND"),
        );
    };
    // Notify (§5.2.27.3): the authorised QoS changed, so tell every subscriber
    // scoped to this transaction.
    notify_qos_tsc_subscribers(transaction_id, &updated).await;
    log::info!("QoS/TSC assistance session updated: transaction={transaction_id}");
    SbiResponse::with_status(200)
        .with_json_body(&updated)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// DELETE /ntsctsf-qos-tsctsf/v1/tsc-qos-requests/{transactionRefId} — Delete
/// (§5.2.27.3.4). 204/404.
async fn handle_qos_tsc_delete(transaction_id: &str) -> SbiResponse {
    let ctx = tsctsf_self();
    let removed = match ctx.read() {
        Ok(c) => c.qos_tsc_remove(transaction_id),
        Err(_) => return send_internal_error("TSCTSF context lock poisoned"),
    };
    match removed {
        Some(_) => {
            log::info!("QoS/TSC assistance session removed: transaction={transaction_id}");
            SbiResponse::with_status(204)
        }
        None => send_not_found(
            &format!("Transaction {transaction_id} not found"),
            Some("TRANSACTION_NOT_FOUND"),
        ),
    }
}

/// POST /ntsctsf-qos-tsctsf/v1/subscriptions — Subscribe (§5.2.27.3).
async fn handle_qos_tsc_subscribe(request: &SbiRequest) -> SbiResponse {
    let (data, sub) = match parse_typed_body::<context::QosTscSubscription>(request) {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };
    if let Err(err) = sub.validate() {
        return send_bad_request(&err.detail(), Some(err.cause()));
    }

    let ctx = tsctsf_self();
    let created = match ctx.read() {
        Ok(c) => c.qos_tsc_sub_create(sub),
        Err(_) => Err(TsctsfContextError::LockPoisoned),
    };
    let created = match created {
        Ok(s) => s,
        Err(err @ TsctsfContextError::MaxConfigsReached) => {
            return send_error(507, "Insufficient Storage", err.detail(), Some(err.cause()))
        }
        Err(err) => return send_internal_error(err.detail()),
    };

    let location = format!(
        "/ntsctsf-qos-tsctsf/v1/subscriptions/{}",
        created.subscription_id
    );
    let mut body = data;
    if let Some(obj) = body.as_object_mut() {
        obj.insert(
            "subscriptionId".to_string(),
            serde_json::json!(created.subscription_id),
        );
        obj.insert("self".to_string(), serde_json::json!(location));
    }
    SbiResponse::with_status(201)
        .with_header("Location", location.clone())
        .with_json_body(&body)
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// GET /ntsctsf-qos-tsctsf/v1/subscriptions/{subscriptionId} — 200/404.
async fn handle_qos_tsc_subscription_get(subscription_id: &str) -> SbiResponse {
    let ctx = tsctsf_self();
    let sub = match ctx.read() {
        Ok(c) => c.qos_tsc_sub_find(subscription_id),
        Err(_) => return send_internal_error("TSCTSF context lock poisoned"),
    };
    match sub {
        Some(s) => SbiResponse::with_status(200)
            .with_json_body(&s)
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("Subscription {subscription_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        ),
    }
}

/// DELETE /ntsctsf-qos-tsctsf/v1/subscriptions/{subscriptionId} — Unsubscribe
/// (§5.2.27.3). 204/404.
async fn handle_qos_tsc_unsubscribe(subscription_id: &str) -> SbiResponse {
    let ctx = tsctsf_self();
    let removed = match ctx.read() {
        Ok(c) => c.qos_tsc_sub_remove(subscription_id),
        Err(_) => return send_internal_error("TSCTSF context lock poisoned"),
    };
    match removed {
        Some(_) => SbiResponse::with_status(204),
        None => send_not_found(
            &format!("Subscription {subscription_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        ),
    }
}

// ============================================================================
// #113: notifications (ConfigUpdateNotify, CapsNotify, ASTI UpdateNotify, Notify)
// ============================================================================

/// POST a notification body to a consumer-supplied target address.
///
/// Best-effort: a failure is logged and never propagated to the consumer whose
/// request triggered it. The alternative would let an unreachable AF fail the
/// operation that changed the configuration, which is a worse outcome than a
/// missed notification.
async fn post_notification(target: &str, kind: &str, body: &serde_json::Value) {
    use nextgcore_sbi::constants::content_type;
    use nextgcore_sbi::message::SbiRequest as SReq;

    let Some((host, port, path)) = split_target(target) else {
        log::warn!("{kind}: notification target '{target}' is not a usable URI; not sent");
        return;
    };
    let request = SReq::post(&path).with_body(body.to_string(), content_type::APPLICATION_JSON);
    let client = nextgcore_sbi::client::SbiClient::new(
        nextgcore_sbi::security::sbi_peer_client_config(&host, port)
            .with_connect_timeout(std::time::Duration::from_secs(2))
            .with_request_timeout(std::time::Duration::from_secs(3)),
    );
    match client.send_request(request).await {
        Ok(resp) => log::info!("{kind} → {host}:{port}{path}: status={}", resp.status),
        Err(e) => log::warn!("{kind} → {host}:{port}{path} failed: {e}"),
    }
}

/// Split a notification target address into (host, port, path).
///
/// The address is consumer-supplied and TS 29.571 types it as a URI, so both a
/// bare authority and a full URI with a path are accepted. A target with no usable
/// host is refused rather than guessed at: notifying the wrong node is worse than
/// not notifying.
fn split_target(target: &str) -> Option<(String, u16, String)> {
    let without_scheme = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .unwrap_or(target);
    let default_port = if target.starts_with("https://") {
        443
    } else {
        80
    };
    let (authority, path) = match without_scheme.find('/') {
        Some(i) => (&without_scheme[..i], without_scheme[i..].to_string()),
        None => (without_scheme, "/".to_string()),
    };
    if authority.is_empty() {
        return None;
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => {
            Some((host.to_string(), port.parse().ok()?, path))
        }
        _ => Some((authority.to_string(), default_port, path)),
    }
}

/// ConfigUpdateNotify (§5.2.27.2.5): tell the configuration's notification target
/// that it changed.
async fn notify_config_update(stored: &context::TimeSyncConfig, body: &serde_json::Value) {
    let target = stored.config.notification_target_addr.clone();
    if target.trim().is_empty() {
        return;
    }
    let mut notification = serde_json::json!({
        "configId": stored.id,
        "timeSyncExposureConfig": body,
    });
    if let Some(id) = &stored.config.notification_correlation_id {
        notification["notifyCorrelationId"] = serde_json::json!(id);
    }
    post_notification(&target, "ConfigUpdateNotify", &notification).await;
}

/// ASTI UpdateNotify (§5.2.27.4): tell the configuration's notification target, if
/// one was registered, that the access-stratum time distribution changed.
async fn notify_asti_update(cfg: &context::AstiConfig) {
    let Some(target) = cfg
        .notification_target_addr
        .as_deref()
        .filter(|t| !t.trim().is_empty())
    else {
        return;
    };
    let mut notification = serde_json::json!({
        "configId": cfg.config_id,
        "astiConfig": cfg,
    });
    if let Some(id) = &cfg.notification_correlation_id {
        notification["notifyCorrelationId"] = serde_json::json!(id);
    }
    post_notification(target, "ASTI UpdateNotify", &notification).await;
}

/// QoSandTSCAssistance Notify (§5.2.27.3): tell every subscriber scoped to this
/// transaction, plus every unscoped subscriber.
///
/// An unscoped subscription (no `transactionRefId`) is treated as "all
/// transactions", because a subscriber that named none asked for everything —
/// refusing to notify them would make an unfiltered subscription the one shape that
/// never fires.
async fn notify_qos_tsc_subscribers(transaction_id: &str, session: &context::QosTscSession) {
    let ctx = tsctsf_self();
    let subs = match ctx.read() {
        Ok(c) => c.qos_tsc_sub_list(),
        Err(_) => return,
    };
    for sub in subs {
        let scoped = sub
            .transaction_ref_id
            .as_deref()
            .is_none_or(|t| t == transaction_id);
        if !scoped {
            continue;
        }
        let mut notification = serde_json::json!({
            "transactionRefId": transaction_id,
            "tscQosSession": session,
        });
        if let Some(id) = &sub.notification_correlation_id {
            notification["notifyCorrelationId"] = serde_json::json!(id);
        }
        post_notification(
            &sub.notification_target_addr,
            "QoSandTSCAssistance Notify",
            &notification,
        )
        .await;
    }
}

/// CapsNotify (§5.2.27.2.8): tell every capability subscriber about a change in
/// the reported time-synchronization capabilities.
///
/// Exposed (rather than private) because the trigger is a capability change in the
/// 5GS, which this build has no source for — the actuation leg that would report
/// one is split out as its own issue. So this is called by the admin trigger below
/// and by tests, and the absence of an in-tree producer is stated rather than left
/// to be discovered.
pub async fn notify_capability_change(capabilities: &serde_json::Value) -> usize {
    let ctx = tsctsf_self();
    let subs = match ctx.read() {
        Ok(c) => c.caps_sub_list(),
        Err(_) => return 0,
    };
    let mut sent = 0usize;
    for sub in subs {
        let mut notification = serde_json::json!({
            "subscriptionId": sub.subscription_id,
            "timeSyncCapabilities": capabilities,
        });
        if let Some(id) = &sub.notification_correlation_id {
            notification["notifyCorrelationId"] = serde_json::json!(id);
        }
        post_notification(&sub.notification_target_addr, "CapsNotify", &notification).await;
        sent += 1;
    }
    sent
}

/// POST /ntsctsf-time-synchronization/v1/admin/capability-change — fan a
/// capability change out to every CapsSubscribe subscriber (#113).
///
/// Administrative, not a service operation: see the router comment. Answers 200
/// with the number of subscribers notified, so an operator can tell "notified
/// nobody because nobody subscribed" from "notified nobody because the fan-out is
/// broken" — two states a 204 would conflate.
async fn handle_admin_capability_change(request: &SbiRequest) -> SbiResponse {
    let capabilities: serde_json::Value = match &request.http.content {
        Some(body) => match serde_json::from_str(body) {
            Ok(v) => v,
            Err(e) => {
                return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_MSG_FORMAT"))
            }
        },
        None => serde_json::json!({}),
    };
    let notified = notify_capability_change(&capabilities).await;
    log::info!("CapsNotify fan-out: {notified} subscriber(s)");
    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({ "notified": notified }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Build the NFProfile registered with the NRF (TS 29.510): nfType TSCTSF
/// advertising the ntsctsf-time-synchronization service (TS 29.565).
fn build_nf_profile(nf_instance_id: &str, sbi_addr: &str, sbi_port: u16) -> serde_json::Value {
    serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "TSCTSF",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        // #113: all THREE services TS 23.501 Table 7.2.26-1 mandates, not just
        // the one. Advertising only `ntsctsf-time-synchronization` while serving
        // the other two would make them undiscoverable, and advertising services
        // that are not served would be worse -- so this list and the router are
        // changed together.
        "nfServices": [
            {
                "serviceInstanceId": format!("{nf_instance_id}-ntsctsf-time-synchronization"),
                "serviceName": "ntsctsf-time-synchronization",
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
            },
            {
                "serviceInstanceId": format!("{nf_instance_id}-ntsctsf-asti"),
                "serviceName": "ntsctsf-asti",
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
            },
            {
                "serviceInstanceId": format!("{nf_instance_id}-ntsctsf-qos-tsctsf"),
                "serviceName": "ntsctsf-qos-tsctsf",
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
    /// #113: `enable_all` rather than a bare builder. The handlers no longer "do
    /// no real I/O": ConfigUpdate fires ConfigUpdateNotify, whose client sets a
    /// request timeout, and a runtime without timers panics on it. A test that
    /// registers an unreachable notification target still exercises the send.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build current-thread runtime")
            .block_on(fut)
    }

    /// #113: the required IEs are merged in unless the caller states them, so the
    /// pre-#113 tests below keep testing what they were written to test (the
    /// create/get/delete flow, the capacity cap) rather than re-testing validation.
    /// A caller that wants to exercise validation passes its own value for one.
    fn create_request(body: serde_json::Value) -> SbiRequest {
        let mut body = body;
        if let Some(obj) = body.as_object_mut() {
            obj.entry("notificationTargetAddr".to_string())
                .or_insert_with(|| serde_json::json!("http://af.example.com/notify"));
            obj.entry("upNodeId".to_string())
                .or_insert_with(|| serde_json::json!("upf1.example.com"));
        }
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
        // #113 changed this cause from the bespoke `INVALID_JSON` to the
        // TS 29.500 §5.2.7.2 `INVALID_MSG_FORMAT`, which is the name a conformant
        // consumer knows. The old value was this NF's own invention.
        assert_eq!(body["cause"], "INVALID_MSG_FORMAT");

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

    // ====================================================================
    // #113: the three-service control-plane surface
    // ====================================================================

    fn post(path: &str, body: serde_json::Value) -> SbiRequest {
        SbiRequest::post(path).with_body(body.to_string(), "application/json")
    }

    fn patch(path: &str, body: serde_json::Value) -> SbiRequest {
        SbiRequest::patch(path).with_body(body.to_string(), "application/json")
    }

    fn put(path: &str, body: serde_json::Value) -> SbiRequest {
        SbiRequest::put(path).with_body(body.to_string(), "application/json")
    }

    fn valid_time_sync_body(target: &str) -> serde_json::Value {
        serde_json::json!({
            "notificationTargetAddr": target,
            "upNodeId": "upf1.example.com",
            "timeDomain": 24,
            "gmEnable": true,
            "gmPriority": 128,
            // An optional member this build does not model, so the response can be
            // checked for having preserved it.
            "operatorSpecificExtra": { "vendor": "nextgcore" },
        })
    }

    /// Spawn a server that records every notification it receives.
    async fn spawn_notification_sink() -> (
        nextgcore_sbi::server::SbiServer,
        String,
        std::sync::Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>>,
    ) {
        use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
        // Drives production notification code against a loopback PLAINTEXT peer,
        // i.e. a dev-profile deployment. The default `SbiProfile` is Production,
        // which would refuse the connection and make every notification test fail
        // for a reason unrelated to what it asserts.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let seen: std::sync::Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = seen.clone();
        let port = nextgcore_sbi::test_support::free_port();
        let server = SbiServer::new(SbiServerConfig::new(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            port,
        ))));
        server
            .start(move |req: SbiRequest| {
                let sink = sink.clone();
                async move {
                    let body = req
                        .http
                        .content
                        .as_deref()
                        .and_then(|b| serde_json::from_str(b).ok())
                        .unwrap_or(serde_json::Value::Null);
                    sink.lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push((req.header.uri.clone(), body));
                    SbiResponse::with_status(204)
                }
            })
            .await
            .expect("notification sink start");
        (server, format!("http://127.0.0.1:{port}/notify"), seen)
    }

    /// #113 criterion 1: PATCH updates a stored configuration and answers 200;
    /// PATCH against a missing configId is 404.
    #[test]
    fn config_update_merges_and_a_missing_config_is_404() {
        let _g = lock_globals();
        reset_context();

        let created = block_on(tsctsf_sbi_request_handler(post(
            "/ntsctsf-time-synchronization/v1/configuration",
            valid_time_sync_body("http://af.example.com/notify"),
        )));
        assert_eq!(created.status, 201);
        let body: serde_json::Value =
            serde_json::from_str(created.http.content.as_deref().expect("body")).expect("json");
        let config_id = body["configId"].as_str().expect("configId").to_string();
        assert_eq!(
            body["operatorSpecificExtra"]["vendor"],
            serde_json::json!("nextgcore"),
            "an unmodelled optional member must survive the round trip"
        );

        let updated = block_on(tsctsf_sbi_request_handler(patch(
            &format!("/ntsctsf-time-synchronization/v1/configuration/{config_id}"),
            serde_json::json!({ "gmEnable": false }),
        )));
        assert_eq!(updated.status, 200, "ConfigUpdate must be served, not 405");
        let body: serde_json::Value =
            serde_json::from_str(updated.http.content.as_deref().expect("body")).expect("json");
        assert_eq!(
            body["gmEnable"],
            serde_json::json!(false),
            "the change applied"
        );
        assert_eq!(
            body["gmPriority"],
            serde_json::json!(128),
            "and a member the update did not mention survived"
        );
        assert_eq!(body["configId"], serde_json::json!(config_id));

        // The stored record actually changed, not just the response.
        let fetched = block_on(tsctsf_sbi_request_handler(SbiRequest::get(&format!(
            "/ntsctsf-time-synchronization/v1/configuration/{config_id}"
        ))));
        assert_eq!(fetched.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(fetched.http.content.as_deref().expect("body")).expect("json");
        assert_eq!(body["gmEnable"], serde_json::json!(false));

        // A missing configId is 404 for both update verbs.
        let absent = "/ntsctsf-time-synchronization/v1/configuration/no-such-config";
        let body = valid_time_sync_body("http://af.example.com/notify");
        for (label, request) in [
            ("PATCH", patch(absent, body.clone())),
            ("PUT", put(absent, body.clone())),
        ] {
            let missing = block_on(tsctsf_sbi_request_handler(request));
            assert_eq!(missing.status, 404, "{label} on a missing config");
        }
    }

    /// PUT replaces rather than merges, and still validates: the two verbs must
    /// differ, or offering both is a lie.
    #[test]
    fn config_replace_does_not_merge() {
        let _g = lock_globals();
        reset_context();

        let created = block_on(tsctsf_sbi_request_handler(post(
            "/ntsctsf-time-synchronization/v1/configuration",
            valid_time_sync_body("http://af.example.com/notify"),
        )));
        let body: serde_json::Value =
            serde_json::from_str(created.http.content.as_deref().expect("body")).expect("json");
        let config_id = body["configId"].as_str().expect("configId").to_string();

        // A replace that omits gmPriority must clear it.
        let replaced = block_on(tsctsf_sbi_request_handler(put(
            &format!("/ntsctsf-time-synchronization/v1/configuration/{config_id}"),
            serde_json::json!({
                "notificationTargetAddr": "http://af.example.com/notify",
                "upNodeId": "upf2.example.com",
            }),
        )));
        assert_eq!(replaced.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(replaced.http.content.as_deref().expect("body")).expect("json");
        assert_eq!(body["upNodeId"], serde_json::json!("upf2.example.com"));
        assert!(
            body["gmPriority"].is_null(),
            "PUT must replace, not merge -- otherwise it is indistinguishable from PATCH"
        );
    }

    /// #113 criterion 5: a malformed IE is refused with a cause that NAMES the
    /// member, and the absent/incorrect distinction is preserved
    /// (TS 29.500 §5.2.7.2).
    #[test]
    fn a_malformed_configuration_is_refused_with_the_naming_cause() {
        let _g = lock_globals();
        reset_context();

        // Absent required member -> MANDATORY_IE_MISSING.
        let resp = block_on(tsctsf_sbi_request_handler(post(
            "/ntsctsf-time-synchronization/v1/configuration",
            serde_json::json!({ "upNodeId": "upf1" }),
        )));
        assert_eq!(resp.status, 400);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("json");
        assert_eq!(body["cause"], serde_json::json!("MANDATORY_IE_MISSING"));
        assert!(
            body["detail"]
                .as_str()
                .is_some_and(|d| d.contains("notificationTargetAddr")),
            "the detail must name the member, got {body:?}"
        );

        // Present but out of range -> MANDATORY_IE_INCORRECT, naming the member.
        let mut over = valid_time_sync_body("http://af/notify");
        over["timeDomain"] = serde_json::json!(300);
        let resp = block_on(tsctsf_sbi_request_handler(post(
            "/ntsctsf-time-synchronization/v1/configuration",
            over,
        )));
        assert_eq!(resp.status, 400);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("json");
        assert_eq!(body["cause"], serde_json::json!("MANDATORY_IE_INCORRECT"));
        assert!(body["detail"]
            .as_str()
            .is_some_and(|d| d.contains("timeDomain")));

        // A serde TYPE mismatch is INVALID_MSG_FORMAT, not MANDATORY_IE_*: the
        // consumer's JSON is malformed rather than incomplete, which is a different
        // fix on its side. `serde(default)` covers an absent member and does NOT
        // rescue a mismatched one, so the two causes come from two places.
        let mut wrong_type = valid_time_sync_body("http://af/notify");
        wrong_type["gmEnable"] = serde_json::json!("yes please");
        let resp = block_on(tsctsf_sbi_request_handler(post(
            "/ntsctsf-time-synchronization/v1/configuration",
            wrong_type,
        )));
        assert_eq!(resp.status, 400);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("json");
        assert_eq!(body["cause"], serde_json::json!("INVALID_MSG_FORMAT"));
    }

    /// #113 criterion 2: ConfigUpdateNotify reaches the registered notification
    /// URI with the updated body — asserted by observing the HTTP request, not a
    /// log line.
    #[tokio::test]
    async fn a_config_update_notifies_the_registered_target() {
        let _g = lock_globals();
        reset_context();
        let (sink, target, seen) = spawn_notification_sink().await;

        let created = tsctsf_sbi_request_handler(post(
            "/ntsctsf-time-synchronization/v1/configuration",
            valid_time_sync_body(&target),
        ))
        .await;
        assert_eq!(created.status, 201);
        let body: serde_json::Value =
            serde_json::from_str(created.http.content.as_deref().expect("body")).expect("json");
        let config_id = body["configId"].as_str().expect("configId").to_string();
        assert!(
            seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
            "a CREATE is not a change, so it must not fire ConfigUpdateNotify"
        );

        let updated = tsctsf_sbi_request_handler(patch(
            &format!("/ntsctsf-time-synchronization/v1/configuration/{config_id}"),
            serde_json::json!({ "gmEnable": false }),
        ))
        .await;
        assert_eq!(updated.status, 200);

        let notifications = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(
            notifications.len(),
            1,
            "a config change must fire exactly one ConfigUpdateNotify, got {notifications:?}"
        );
        let (uri, body) = &notifications[0];
        assert_eq!(
            uri, "/notify",
            "posted to the path the target address named"
        );
        assert_eq!(body["configId"], serde_json::json!(config_id));
        assert_eq!(
            body["timeSyncExposureConfig"]["gmEnable"],
            serde_json::json!(false),
            "the notification must carry the UPDATED body, not the original"
        );

        sink.stop().await.expect("stop");
    }

    /// #113 criterion 3: subscribe → notify → unsubscribe. CapsNotify reaches the
    /// subscriber while it is subscribed, and stops when it is not.
    #[tokio::test]
    async fn caps_subscribe_notify_unsubscribe() {
        let _g = lock_globals();
        reset_context();
        let (sink, target, seen) = spawn_notification_sink().await;

        let created = tsctsf_sbi_request_handler(post(
            "/ntsctsf-time-synchronization/v1/subscriptions",
            serde_json::json!({
                "notificationTargetAddr": target,
                "notificationCorrelationId": "corr-1",
                "afServiceId": "af-svc-1",
                "ptpInstanceTypes": ["PTP", "GPTP"],
            }),
        ))
        .await;
        assert_eq!(created.status, 201, "CapsSubscribe must be served");
        let body: serde_json::Value =
            serde_json::from_str(created.http.content.as_deref().expect("body")).expect("json");
        let subscription_id = body["subscriptionId"]
            .as_str()
            .expect("Subscription Correlation ID")
            .to_string();
        assert_eq!(
            created.http.get_header("location").map(String::as_str),
            Some(
                format!("/ntsctsf-time-synchronization/v1/subscriptions/{subscription_id}")
                    .as_str()
            )
        );

        // The subscription resource exists.
        let fetched = tsctsf_sbi_request_handler(SbiRequest::get(&format!(
            "/ntsctsf-time-synchronization/v1/subscriptions/{subscription_id}"
        )))
        .await;
        assert_eq!(fetched.status, 200);

        // A capability change reaches it.
        let triggered = tsctsf_sbi_request_handler(post(
            "/ntsctsf-time-synchronization/v1/admin/capability-change",
            serde_json::json!({ "gmCapable": true, "asTimeSource": "GNSS" }),
        ))
        .await;
        assert_eq!(triggered.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(triggered.http.content.as_deref().expect("body")).expect("json");
        assert_eq!(body["notified"], serde_json::json!(1));

        let notifications = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(notifications.len(), 1, "got {notifications:?}");
        let (_, body) = &notifications[0];
        assert_eq!(body["subscriptionId"], serde_json::json!(subscription_id));
        assert_eq!(
            body["timeSyncCapabilities"]["asTimeSource"],
            serde_json::json!("GNSS")
        );
        assert_eq!(
            body["notifyCorrelationId"],
            serde_json::json!("corr-1"),
            "the correlation id the subscriber gave must come back, or it cannot match the \
             notification to its subscription"
        );

        // Unsubscribe, and the fan-out stops.
        let removed = tsctsf_sbi_request_handler(SbiRequest::delete(&format!(
            "/ntsctsf-time-synchronization/v1/subscriptions/{subscription_id}"
        )))
        .await;
        assert_eq!(removed.status, 204);
        seen.lock().unwrap_or_else(|e| e.into_inner()).clear();

        let triggered = tsctsf_sbi_request_handler(post(
            "/ntsctsf-time-synchronization/v1/admin/capability-change",
            serde_json::json!({ "gmCapable": false }),
        ))
        .await;
        let body: serde_json::Value =
            serde_json::from_str(triggered.http.content.as_deref().expect("body")).expect("json");
        assert_eq!(
            body["notified"],
            serde_json::json!(0),
            "an unsubscribed consumer must not be notified"
        );
        assert!(seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty());

        // And a second unsubscribe is 404, not another 204.
        let again = tsctsf_sbi_request_handler(SbiRequest::delete(&format!(
            "/ntsctsf-time-synchronization/v1/subscriptions/{subscription_id}"
        )))
        .await;
        assert_eq!(again.status, 404);

        sink.stop().await.expect("stop");
    }

    /// A capability subscription with neither scope is refused: §5.2.27.2.6's
    /// required input is (DNN, S-NSSAI) **or** an AF-Service-Identifier, and a
    /// subscription that names neither could never be matched against anything.
    #[test]
    fn a_caps_subscription_with_no_scope_is_refused() {
        let _g = lock_globals();
        reset_context();
        let resp = block_on(tsctsf_sbi_request_handler(post(
            "/ntsctsf-time-synchronization/v1/subscriptions",
            serde_json::json!({ "notificationTargetAddr": "http://af/notify" }),
        )));
        assert_eq!(resp.status, 400);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("json");
        assert_eq!(body["cause"], serde_json::json!("MANDATORY_IE_MISSING"));
    }

    /// #113 criterion 4: `Ntsctsf_ASTI` has routes and handlers, and the
    /// create/read path is non-404.
    #[test]
    fn asti_create_read_update_delete() {
        let _g = lock_globals();
        reset_context();

        let created = block_on(tsctsf_sbi_request_handler(post(
            "/ntsctsf-asti/v1/configurations",
            serde_json::json!({
                "afId": "af-1",
                "supi": "imsi-001010000000001",
                "asTimeDisEnabled": true,
                "uuErrorBudget": 900,
            }),
        )));
        assert_eq!(
            created.status, 201,
            "Ntsctsf_ASTI must be served, not 404 -- it is one of the three mandated services"
        );
        let body: serde_json::Value =
            serde_json::from_str(created.http.content.as_deref().expect("body")).expect("json");
        let config_id = body["configId"].as_str().expect("configId").to_string();

        let fetched = block_on(tsctsf_sbi_request_handler(SbiRequest::get(&format!(
            "/ntsctsf-asti/v1/configurations/{config_id}"
        ))));
        assert_eq!(fetched.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(fetched.http.content.as_deref().expect("body")).expect("json");
        assert_eq!(body["afId"], serde_json::json!("af-1"));
        assert_eq!(body["uuErrorBudget"], serde_json::json!(900));

        let updated = block_on(tsctsf_sbi_request_handler(patch(
            &format!("/ntsctsf-asti/v1/configurations/{config_id}"),
            serde_json::json!({ "asTimeDisEnabled": false }),
        )));
        assert_eq!(updated.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(updated.http.content.as_deref().expect("body")).expect("json");
        assert_eq!(body["asTimeDisEnabled"], serde_json::json!(false));
        assert_eq!(
            body["afId"],
            serde_json::json!("af-1"),
            "an update must not clear what it did not mention"
        );

        let deleted = block_on(tsctsf_sbi_request_handler(SbiRequest::delete(&format!(
            "/ntsctsf-asti/v1/configurations/{config_id}"
        ))));
        assert_eq!(deleted.status, 204);
        let gone = block_on(tsctsf_sbi_request_handler(SbiRequest::get(&format!(
            "/ntsctsf-asti/v1/configurations/{config_id}"
        ))));
        assert_eq!(gone.status, 404);
    }

    /// An ASTI configuration with no target would activate time distribution for
    /// nobody.
    #[test]
    fn an_asti_config_with_no_target_is_refused() {
        let _g = lock_globals();
        reset_context();
        let resp = block_on(tsctsf_sbi_request_handler(post(
            "/ntsctsf-asti/v1/configurations",
            serde_json::json!({ "afId": "af-1" }),
        )));
        assert_eq!(resp.status, 400);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("json");
        assert_eq!(body["cause"], serde_json::json!("MANDATORY_IE_MISSING"));
        assert!(body["detail"].as_str().is_some_and(|d| d.contains("supi")));
    }

    /// #113 criterion 4: `Ntsctsf_QoSandTSCAssistance` has routes and handlers,
    /// and Notify reaches a subscriber on an Update.
    #[tokio::test]
    async fn qos_tsc_create_read_update_notifies_and_delete() {
        let _g = lock_globals();
        reset_context();
        let (sink, target, seen) = spawn_notification_sink().await;

        let created = tsctsf_sbi_request_handler(post(
            "/ntsctsf-qos-tsctsf/v1/tsc-qos-requests",
            serde_json::json!({
                "afId": "af-1",
                "gpsi": "msisdn-491700000001",
                "flowDescriptions": ["permit out ip from any to assigned"],
                "qosReference": "qos-ref-1",
                "periodicity": 500,
            }),
        ))
        .await;
        assert_eq!(
            created.status, 201,
            "Ntsctsf_QoSandTSCAssistance must be served, not 404"
        );
        let body: serde_json::Value =
            serde_json::from_str(created.http.content.as_deref().expect("body")).expect("json");
        let transaction_id = body["transactionRefId"]
            .as_str()
            .expect("Transaction Reference ID")
            .to_string();

        let fetched = tsctsf_sbi_request_handler(SbiRequest::get(&format!(
            "/ntsctsf-qos-tsctsf/v1/tsc-qos-requests/{transaction_id}"
        )))
        .await;
        assert_eq!(fetched.status, 200);

        // Subscribe, then update, and the subscriber is notified.
        let sub = tsctsf_sbi_request_handler(post(
            "/ntsctsf-qos-tsctsf/v1/subscriptions",
            serde_json::json!({
                "notificationTargetAddr": target,
                "transactionRefId": transaction_id,
                "events": ["QOS_NOT_GUARANTEED"],
            }),
        ))
        .await;
        assert_eq!(sub.status, 201);

        let updated = tsctsf_sbi_request_handler(patch(
            &format!("/ntsctsf-qos-tsctsf/v1/tsc-qos-requests/{transaction_id}"),
            serde_json::json!({ "periodicity": 1000, "survivalTime": 2000 }),
        ))
        .await;
        assert_eq!(updated.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(updated.http.content.as_deref().expect("body")).expect("json");
        assert_eq!(body["periodicity"], serde_json::json!(1000));
        assert_eq!(
            body["qosReference"],
            serde_json::json!("qos-ref-1"),
            "an update must not clear what it did not mention"
        );

        let notifications = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(notifications.len(), 1, "got {notifications:?}");
        assert_eq!(
            notifications[0].1["transactionRefId"],
            serde_json::json!(transaction_id)
        );
        assert_eq!(
            notifications[0].1["tscQosSession"]["survivalTime"],
            serde_json::json!(2000)
        );

        let deleted = tsctsf_sbi_request_handler(SbiRequest::delete(&format!(
            "/ntsctsf-qos-tsctsf/v1/tsc-qos-requests/{transaction_id}"
        )))
        .await;
        assert_eq!(deleted.status, 204);
        let gone = tsctsf_sbi_request_handler(SbiRequest::get(&format!(
            "/ntsctsf-qos-tsctsf/v1/tsc-qos-requests/{transaction_id}"
        )))
        .await;
        assert_eq!(gone.status, 404);

        sink.stop().await.expect("stop");
    }

    /// A QoS/TSC request missing one half of each required either/or is refused,
    /// naming which one.
    #[test]
    fn a_qos_tsc_request_missing_a_required_alternative_is_refused() {
        let _g = lock_globals();
        reset_context();
        let resp = block_on(tsctsf_sbi_request_handler(post(
            "/ntsctsf-qos-tsctsf/v1/tsc-qos-requests",
            serde_json::json!({
                "afId": "af-1",
                "gpsi": "msisdn-1",
                "flowDescriptions": ["permit out ip from any to assigned"],
                // No qosReference and no maxBr*.
            }),
        )));
        assert_eq!(resp.status, 400);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().expect("body")).expect("json");
        assert_eq!(body["cause"], serde_json::json!("MANDATORY_IE_MISSING"));
        assert!(body["detail"]
            .as_str()
            .is_some_and(|d| d.contains("qosReference")));
    }

    /// The NF profile advertises all THREE mandated services. Advertising one
    /// while serving three makes the other two undiscoverable — which was the
    /// pre-#113 state for the two that did not exist.
    #[test]
    fn the_nf_profile_advertises_all_three_services() {
        let profile = build_nf_profile("tsctsf-1", "127.0.0.1", 7777);
        let names: Vec<&str> = profile["nfServices"]
            .as_array()
            .expect("nfServices")
            .iter()
            .filter_map(|s| s["serviceName"].as_str())
            .collect();
        assert!(names.contains(&"ntsctsf-time-synchronization"));
        assert!(names.contains(&"ntsctsf-asti"));
        assert!(names.contains(&"ntsctsf-qos-tsctsf"));
        assert_eq!(
            names.len(),
            3,
            "exactly the three TS 23.501 Table 7.2.26-1 names"
        );
    }

    /// A notification target the TSCTSF cannot use is refused rather than guessed
    /// at: notifying the wrong node is worse than not notifying.
    #[test]
    fn an_unusable_notification_target_is_not_guessed_at() {
        assert!(split_target("").is_none());
        assert!(split_target("http://").is_none());
        assert_eq!(
            split_target("http://af.example.com:8080/cb"),
            Some(("af.example.com".to_string(), 8080, "/cb".to_string()))
        );
        assert_eq!(
            split_target("http://af.example.com/cb"),
            Some(("af.example.com".to_string(), 80, "/cb".to_string())),
            "an http target with no port defaults to 80"
        );
        assert_eq!(
            split_target("https://af.example.com/cb"),
            Some(("af.example.com".to_string(), 443, "/cb".to_string())),
            "and an https target to 443, not 80"
        );
        assert_eq!(
            split_target("af.example.com:9000"),
            Some(("af.example.com".to_string(), 9000, "/".to_string())),
            "a bare authority is accepted, with the root path"
        );
    }
}
