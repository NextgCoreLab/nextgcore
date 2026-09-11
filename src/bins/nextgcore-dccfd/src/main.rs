//! NextGCore DCCF (Data Collection Co-ordination Function)
//!
//! The DCCF is a Rel-17 optional NF defined in 3GPP TS 23.288 §6.7.
//! It acts as a broker between data producers (AMF, SMF, PCF, etc.)
//! and analytics consumers (NWDAF, ADRF).  Core responsibilities:
//!
//! - Ndccf_DataManagement_Subscribe: consumer registers interest in
//!   network data events (UE location, NF load, QoS, etc.)
//! - Ndccf_DataManagement_Notify: forward collected data to consumers
//! - Ndccf_ContextDocument_Create: bind data subscription to analytics
//! - Routing: fan-out collected data to all matching subscribers

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_sbi::client::SbiClient;
use nextgcore_sbi::context::global_context;
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::{send_method_not_allowed, send_not_found, SbiServer, SbiServerConfig};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod context;
mod coordination;
mod data_mgmt;

pub use context::*;

/// NextGCore DCCF - Data Collection Co-ordination Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-dccfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Data Collection Co-ordination Function (TS 23.288 §6.7)", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/dccf.yaml")]
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

    /// SBI bind address
    #[arg(long, default_value = "0.0.0.0")]
    sbi_addr: String,

    /// SBI port (TS 29.574 default: 7816)
    #[arg(long, default_value = "7816")]
    sbi_port: u16,

    /// Enable TLS for SBI
    #[arg(long)]
    tls: bool,

    /// TLS certificate path
    #[arg(long)]
    tls_cert: Option<String>,

    /// TLS key path
    #[arg(long)]
    tls_key: Option<String>,

    /// NRF URI for NF registration
    #[arg(long, default_value = "http://127.0.0.1:7777")]
    nrf_uri: String,

    /// Maximum concurrent data subscriptions
    #[arg(long, default_value = "4096")]
    max_subscriptions: usize,
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

/// DCCF SBI request handler (called by the SBI server per request).
async fn dccf_request_handler(req: SbiRequest) -> SbiResponse {
    let method = req.header.method.as_str();
    let uri = &req.header.uri;
    let path = uri.split('?').next().unwrap_or(uri);

    log::debug!("DCCF SBI: {method} {path}");

    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match parts.as_slice() {
        // ----------------------------------------------------------------
        // Health check
        // ----------------------------------------------------------------
        ["healthz"] => SbiResponse::ok().with_body(r#"{"status":"ok"}"#, "application/json"),

        // ----------------------------------------------------------------
        // Ndccf_DataManagement (TS 29.574 §5.2)
        // ----------------------------------------------------------------

        // POST /ndccf-datamanagement/v1/subscriptions
        ["ndccf-datamanagement", "v1", "subscriptions"] => match method {
            "POST" => handle_dm_subscribe(&req).await,
            _ => send_method_not_allowed(method, "subscriptions"),
        },

        // GET/PUT/DELETE /ndccf-datamanagement/v1/subscriptions/{subscriptionId}
        ["ndccf-datamanagement", "v1", "subscriptions", sub_id] => match method {
            "GET" => match dccf_context_get_subscription(sub_id) {
                // #112: echo the stored resource, not a bespoke
                // `{"subscriptionId":..,"status":"ACTIVE"}` body that no schema
                // defines and that a consumer cannot deserialise.
                Some(stored) => SbiResponse::ok()
                    .with_json_body(&stored.resource)
                    .unwrap_or_else(|_| SbiResponse::ok()),
                None => send_not_found("subscription not found", None),
            },
            // #112: `UpdateNWDAFDataSubscription` was absent and PUT answered 405.
            "PUT" => handle_dm_update(sub_id, &req).await,
            "DELETE" => handle_dm_unsubscribe(sub_id).await,
            _ => send_method_not_allowed(method, "subscriptions/{id}"),
        },

        // POST /ndccf-datamanagement/v1/notify — inbound data from producers
        ["ndccf-datamanagement", "v1", "notify"] => match method {
            "POST" => handle_dm_notify(&req).await,
            _ => send_method_not_allowed(method, "notify"),
        },

        // ----------------------------------------------------------------
        // Ndccf_ContextDocument (TS 29.574 §5.3)
        // ----------------------------------------------------------------

        // POST /ndccf-contextdocument/v1/contexts
        ["ndccf-contextdocument", "v1", "contexts"] => match method {
            "POST" => {
                let ctx_id = uuid::Uuid::new_v4().to_string();
                log::info!("[DCCF] ContextDocument context created ctx_id={ctx_id}");
                dccf_context_add_analytics_context(ctx_id.clone());
                let body = format!(r#"{{"contextId":"{ctx_id}"}}"#);
                SbiResponse::created().with_body(body, "application/json")
            }
            _ => send_method_not_allowed(method, "contexts"),
        },

        // GET/DELETE /ndccf-contextdocument/v1/contexts/{contextId}
        ["ndccf-contextdocument", "v1", "contexts", ctx_id] => match method {
            "GET" => {
                if dccf_context_has_analytics_context(ctx_id) {
                    let body = format!(r#"{{"contextId":"{ctx_id}"}}"#);
                    SbiResponse::ok().with_body(body, "application/json")
                } else {
                    send_not_found("context not found", None)
                }
            }
            "DELETE" => {
                dccf_context_remove_analytics_context(ctx_id);
                SbiResponse::no_content()
            }
            _ => send_method_not_allowed(method, "contexts/{id}"),
        },

        // ----------------------------------------------------------------
        // Fallthrough
        // ----------------------------------------------------------------
        _ => send_not_found("resource not found", None),
    }
}

// ---------------------------------------------------------------------------
// OAuth2 rollout (Wave-6 H8): opt-in producer verification + outbound consumer
// token install. Default OFF so the matched-sim E2E path is byte-unchanged;
// enabled per-NF via `NEXTGCORE_SBI_OAUTH2_REQUIRE=1` (overlay-friendly) or the
// `dccf.sbi.oauth2.require: true` yaml knob. TS 33.501 §13.4.1, TS 29.510 §5.4.2.
// ---------------------------------------------------------------------------

/// Process-wide OAuth2 client for automatic Bearer-token acquisition on
/// outbound SBI calls (installed only when OAuth2 enforcement is enabled).
static OAUTH2_CLIENT: std::sync::OnceLock<Option<Arc<nextgcore_sbi::oauth::OAuth2Client>>> =
    std::sync::OnceLock::new();

/// The shared OAuth2 client, if SBI OAuth2 enforcement is enabled (Wave-6 H8
/// Phase A). Outbound SBI clients attach a token via `client.with_oauth2`.
#[allow(dead_code)]
fn oauth2_client() -> Option<Arc<nextgcore_sbi::oauth::OAuth2Client>> {
    OAUTH2_CLIENT.get().and_then(|opt| opt.clone())
}

/// Parse the opt-in `sbi.oauth2.require` knob (Wave-6 H8). Default false so the
/// matched-sim path is untouched. Honors `NEXTGCORE_SBI_OAUTH2_REQUIRE` first
/// (overlay-friendly), then the yaml `<nf>.sbi.oauth2.require` (root-key
/// agnostic: true iff any top-level section sets it).
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

/// Apply OAuth2 producer enforcement to `cfg` and install the outbound OAuth2
/// client (Wave-6 H8). The server verifies incoming Bearer tokens against the
/// NRF JWKS and requires `aud` to include NfType::Dccf; with no NRF URI it
/// fails closed (503). `nrf_uri` empty ⇒ unconfigured ⇒ fail-closed.
fn apply_oauth2_enforcement(mut cfg: SbiServerConfig, nrf_uri: &str) -> SbiServerConfig {
    cfg.require_oauth2 = true;
    let uri = (!nrf_uri.is_empty()).then_some(nrf_uri);
    cfg.oauth2_jwks_uri = uri.map(|u| {
        nextgcore_sbi::oauth::JwksCache::for_nrf(u)
            .jwks_uri()
            .to_string()
    });
    cfg = cfg.with_expected_audience_nf_type(nextgcore_sbi::types::NfType::Dccf);
    if let Some(u) = uri {
        let nf_instance_id = format!("dccf-{}", uuid::Uuid::new_v4());
        let _ = OAUTH2_CLIENT.set(Some(Arc::new(nextgcore_sbi::oauth::OAuth2Client::new(
            u,
            nf_instance_id,
            nextgcore_sbi::types::NfType::Dccf,
        ))));
    }
    log::info!(
        "OAuth2 enforcement enabled (JWKS: {})",
        cfg.oauth2_jwks_uri.as_deref().unwrap_or("UNCONFIGURED")
    );
    cfg
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

    log::info!("NextGCore DCCF v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Data Collection Co-ordination Function (3GPP TS 23.288 §6.7)");

    dccf_context_init(args.max_subscriptions);

    let nf_instance_id = format!("dccf-{}", uuid::Uuid::new_v4());

    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone());

    let bind_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI bind address")?;
    log::info!("DCCF SBI listening on {bind_addr}");

    let mut sbi_config = SbiServerConfig::new(bind_addr);
    if args.tls {
        if let (Some(cert), Some(key)) = (args.tls_cert, args.tls_key) {
            sbi_config = sbi_config.with_tls(key, cert);
        }
    }
    if oauth2_required(&args.config) {
        sbi_config = apply_oauth2_enforcement(sbi_config, &args.nrf_uri);
    }

    let sbi_server = SbiServer::new(sbi_config);
    sbi_server
        .start(dccf_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    // Register with NRF
    let sbi_ctx = global_context();
    sbi_ctx.set_nrf_uri(&args.nrf_uri).await;
    if let Err(e) = register_with_nrf(&args.sbi_addr, args.sbi_port, &nf_instance_id).await {
        log::warn!("NRF registration failed (will operate without NRF): {e}");
    } else {
        // G2-2: PATCH a real NFProfile "/load" gauge to NRF each heartbeat
        // (active data-collection subscriptions, saturated at 100;
        // TS 29.510 §5.2.2.3.2). Honest subscription-count proxy — no
        // fabricated CPU numbers.
        nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(
            nf_instance_id.clone(),
            5,
            || dccf_context_subscription_count().min(100) as u8,
        );
    }

    log::info!("NextGCore DCCF ready (instance: {nf_instance_id})");

    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    log::info!("DCCF shutting down");

    // #235: NFDeregister (TS 29.510 5.2.2.2.3) BEFORE the listener goes away, so
    // the NRF stops handing this profile to consumers instead of waiting out its
    // supervision timer. Stopping the server first would open the bad window:
    // not serving, but still advertised.
    nextgcore_sbi::heartbeat::deregister_self().await;

    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;

    dccf_context_final();
    log::info!("DCCF shutdown complete");
    Ok(())
}

/// Register DCCF with NRF
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

    log::info!("Registering DCCF with NRF at {nrf_uri}");

    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_profile = serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "DCCF",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [{
            "serviceInstanceId": format!("{}-ndccf-datamanagement", nf_instance_id),
            "serviceName": "ndccf-datamanagement",
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
        }],
        "allowedNfTypes": ["NWDAF", "AMF", "SMF", "PCF"],
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
            log::info!("DCCF registered with NRF successfully (id={nf_instance_id})");

            let mut self_instance = nextgcore_sbi::context::NfInstance::new(
                nf_instance_id,
                nextgcore_sbi::types::NfType::Dccf,
            );
            self_instance.ipv4_addresses = vec![sbi_addr.to_string()];
            let mut svc = nextgcore_sbi::context::NfService::new(
                "ndccf-datamanagement",
                nextgcore_sbi::types::SbiServiceType::NdccfDatamanagement,
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

// ---------------------------------------------------------------------------
// #112: Ndccf_DataManagement handlers (TS 29.574, schema-mirrored from
// TS29520_Nnwdaf_DataManagement.yaml)
// ---------------------------------------------------------------------------

/// Resource collection path for data-management subscriptions; the `Location`
/// header of a created subscription is built from it.
const DM_SUBSCRIPTIONS_PATH: &str = "/ndccf-datamanagement/v1/subscriptions";

/// A `400` with a conformant `application/problem+json` body (TS 29.500 §5.2.7).
///
/// The old subscribe path parsed the body with `unwrap_or_default()`, so a
/// missing or unparseable body still answered `201` for a subscription that could
/// never work.
fn bad_request(detail: &str, cause: &str) -> SbiResponse {
    nextgcore_sbi::server::send_bad_request(detail, Some(cause))
}

/// Parse and validate a subscribe/update body.
///
/// The error is boxed: `SbiResponse` is ~300 bytes, and a `Result` whose `Err`
/// dwarfs its `Ok` makes every caller pay for the failure path
/// (`clippy::result_large_err`). Same shape as eesd's `parse_json_body`.
#[allow(clippy::result_large_err)]
fn parse_subsc(req: &SbiRequest) -> Result<data_mgmt::DataManagementSubsc, Box<SbiResponse>> {
    let Some(body) = req.http.content.as_deref().filter(|b| !b.trim().is_empty()) else {
        return Err(Box::new(bad_request(
            "A request body is required (NnwdafDataManagementSubsc)",
            "MANDATORY_IE_MISSING",
        )));
    };
    let sub: data_mgmt::DataManagementSubsc = serde_json::from_str(body).map_err(|e| {
        Box::new(bad_request(
            &format!("Unparseable NnwdafDataManagementSubsc: {e}"),
            "INVALID_MSG_FORMAT",
        ))
    })?;
    sub.validate()
        .map_err(|e| Box::new(bad_request(e.detail(), "MANDATORY_IE_MISSING")))?;
    Ok(sub)
}

/// `POST /ndccf-datamanagement/v1/subscriptions` — subscribe (#112).
///
/// Four defects fixed here at once: the callback is read from `notificURI`
/// (not the bespoke `notifyUri`), the body is validated with a `400` +
/// ProblemDetails instead of `unwrap_or_default()`, the `201` carries the
/// mandatory `Location` header and echoes the resource, and the subscription's
/// scope is recorded so the fan-out can be keyed on it.
async fn handle_dm_subscribe(req: &SbiRequest) -> SbiResponse {
    let sub = match parse_subsc(req) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let sub_id = uuid::Uuid::new_v4().to_string();
    let scope = data_mgmt::SubscriptionScope::from_subsc(&sub);
    log::info!(
        "[DCCF] DataManagement subscribe sub_id={sub_id} notifCorrId={} notificURI={} events={:?}",
        sub.notif_corr_id,
        sub.notific_uri,
        scope.events
    );

    let stored = dccf_context_store_subscription(context::DccfSubscription {
        id: sub_id.clone(),
        notify_uri: sub.notific_uri.clone(),
        notif_corr_id: sub.notif_corr_id.clone(),
        scope: scope.clone(),
        resource: sub.clone(),
    });
    if !stored {
        return nextgcore_sbi::server::send_error(
            507,
            "Insufficient Storage",
            "Subscription capacity exhausted",
            Some("INSUFFICIENT_RESOURCES"),
        );
    }

    // TS 23.288 §5A.2: collect once, share to many. Off by default; see
    // `coordination.rs` for why this is a runtime switch and not a cargo feature.
    // A coordination failure does not fail the consumer's subscription: the
    // consumer's contract is with the DCCF, and refusing it would make an
    // unreachable producer look like a malformed request.
    let outcome = coordination::ensure_producer_subscription(&sub_id, &scope, &sub).await;
    log::debug!("[DCCF] coordination for {sub_id}: {outcome:?}");

    SbiResponse::created()
        .with_header("Location", format!("{DM_SUBSCRIPTIONS_PATH}/{sub_id}"))
        .with_json_body(&sub)
        .unwrap_or_else(|_| SbiResponse::created())
}

/// `PUT /ndccf-datamanagement/v1/subscriptions/{subscriptionId}` —
/// `UpdateNWDAFDataSubscription` (#112). Previously answered `405`.
///
/// A full replace, which is what PUT means: the new body is validated exactly as
/// on create, and the recorded scope is recomputed so a changed `anaSub` changes
/// what the consumer receives. `404` when the resource does not exist — PUT here
/// updates an existing subscription and does not create one at a
/// consumer-chosen id.
async fn handle_dm_update(sub_id: &str, req: &SbiRequest) -> SbiResponse {
    if !dccf_context_has_subscription(sub_id) {
        return send_not_found("subscription not found", None);
    }
    let sub = match parse_subsc(req) {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let scope = data_mgmt::SubscriptionScope::from_subsc(&sub);
    log::info!(
        "[DCCF] DataManagement update sub_id={sub_id} events={:?}",
        scope.events
    );
    dccf_context_store_subscription(context::DccfSubscription {
        id: sub_id.to_string(),
        notify_uri: sub.notific_uri.clone(),
        notif_corr_id: sub.notif_corr_id.clone(),
        scope,
        resource: sub.clone(),
    });
    SbiResponse::ok()
        .with_json_body(&sub)
        .unwrap_or_else(|_| SbiResponse::ok())
}

/// `DELETE /ndccf-datamanagement/v1/subscriptions/{subscriptionId}` (#112).
///
/// Releases this consumer's claim on its producer subscription, and deletes that
/// producer subscription when it was the last consumer — refcounted, so one
/// consumer unsubscribing cannot cut off another's data.
async fn handle_dm_unsubscribe(sub_id: &str) -> SbiResponse {
    if !dccf_context_remove_subscription(sub_id) {
        return send_not_found("subscription not found", None);
    }
    log::info!("[DCCF] DataManagement subscription deleted sub_id={sub_id}");
    if let Some(orphaned) = dccf_context_release_producer_sub(sub_id) {
        coordination::delete_producer_subscription(&orphaned.resource_uri).await;
    }
    SbiResponse::no_content()
}

/// `POST /ndccf-datamanagement/v1/notify` — inbound producer data (#112).
///
/// Two defects fixed: the fan-out is keyed on `(events, target)` instead of
/// going to every subscriber with a callback URI, and each consumer receives a
/// conformant `NnwdafDataManagementNotif` echoing **its own** `notifCorrId`
/// instead of a bespoke `{"data": "<stringified body>"}` envelope.
///
/// Because each consumer's body differs (its own correlation id), the
/// notification is built per target rather than once and broadcast.
async fn handle_dm_notify(req: &SbiRequest) -> SbiResponse {
    let raw = req.http.content.as_deref().unwrap_or("{}");
    let body: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            return bad_request(
                &format!("Unparseable producer notification: {e}"),
                "INVALID_MSG_FORMAT",
            )
        }
    };
    let notif_scope = data_mgmt::SubscriptionScope::from_notification(&body);
    log::debug!(
        "[DCCF] notify received: events={:?} target={:?} len={}",
        notif_scope.events,
        notif_scope.target,
        raw.len()
    );

    let targets = dccf_context_fanout_notify_scoped(&notif_scope);
    let timestamp = rfc3339_now();
    for (sub_id, notify_uri, notif_corr_id) in targets {
        let Some((host, port)) = parse_host_port(&notify_uri) else {
            log::warn!("[DCCF] subscriber {sub_id} has unparseable notificURI: {notify_uri}");
            continue;
        };
        let path = notify_uri
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let path_owned = path
            .find('/')
            .map(|i| path[i..].to_string())
            .unwrap_or_else(|| "/".to_string());
        let notif = data_mgmt::DataManagementNotif::with_data(
            notif_corr_id,
            timestamp.clone(),
            body.clone(),
        );
        let client = SbiClient::with_host_port(&host, port);
        tokio::spawn(async move {
            match client.post_json(&path_owned, &notif).await {
                Ok(resp) => {
                    log::debug!("[DCCF] fanout POST {sub_id} -> status={}", resp.status)
                }
                Err(e) => log::warn!("[DCCF] fanout POST {sub_id} failed: {e}"),
            }
        });
    }
    SbiResponse::no_content()
}

/// Current time as an RFC 3339 UTC timestamp, for `notifTimestamp`.
///
/// Delegates to the shared SBI formatter rather than hand-rolling one: the
/// per-daemon copies of this were consolidated for a reason (a copy that
/// formats a pre-epoch instant wrongly, or omits the `Z`, produces a `DateTime`
/// a conformant consumer rejects).
fn rfc3339_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    nextgcore_sbi::datetime::epoch_to_rfc3339_signed(secs)
}

/// Parse host and port from a URI string
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
mod oauth2_h8_tests {
    //! Wave-6 H8 (Phase B) strict-peer OAuth2 enforcement triplet: the real
    //! `dccf_request_handler` is mounted behind nextgcore-sbi's server-side
    //! OAuth2 verification (TS 33.501 §13.4.1). A missing or wrong-audience
    //! Bearer is rejected (401) before the handler runs; a valid NRF-audience
    //! token (aud=DCCF, ES256-signed against the served JWKS) passes through.
    use super::dccf_request_handler;
    use nextgcore_sbi::client::SbiClient;
    use nextgcore_sbi::message::SbiRequest;
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    use nextgcore_sbi::types::NfType;
    use std::net::SocketAddr;
    use std::time::Duration;

    fn build_es256_token(
        sk: &p256::ecdsa::SigningKey,
        kid: &str,
        aud: &str,
        scope: &str,
    ) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use p256::ecdsa::{signature::Signer, Signature};
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let header = format!(r#"{{"alg":"ES256","typ":"JWT","kid":"{kid}"}}"#);
        let claims = serde_json::json!({
            "iss": "NRF", "sub": "dccf-1", "aud": aud,
            "scope": scope, "exp": exp, "iat": 0
        })
        .to_string();
        let h = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let p = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let sig: Signature = sk.sign(format!("{h}.{p}").as_bytes());
        let s = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{h}.{p}.{s}")
    }

    fn jwks_for(sk: &p256::ecdsa::SigningKey, kid: &str) -> serde_json::Value {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let point = sk.verifying_key().to_encoded_point(false);
        serde_json::json!({"keys":[{
            "kty":"EC","crv":"P-256","use":"sig","alg":"ES256","kid":kid,
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        }]})
    }

    async fn start_server(jwks: serde_json::Value) -> (SbiServer, u16) {
        super::dccf_context_init(256);
        let (port_listener, port_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let port = port_addr.port();
        let mut cfg = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(jwks);
        cfg = cfg.with_expected_audience_nf_type(NfType::Dccf);
        let server = SbiServer::on_listener(cfg, port_listener);
        server
            .start(dccf_request_handler)
            .await
            .expect("server start");
        (server, port)
    }

    #[test]
    fn test_oauth2_require_knob_parses_and_defaults_off() {
        let dir = std::env::temp_dir();
        let off = dir.join(format!("dccf-h8-off-{}.yaml", std::process::id()));
        std::fs::write(
            &off,
            "dccf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n",
        )
        .unwrap();
        assert!(!super::oauth2_required(off.to_str().unwrap()));
        let on = dir.join(format!("dccf-h8-on-{}.yaml", std::process::id()));
        std::fs::write(&on, "dccf:\n  sbi:\n    oauth2:\n      require: true\n").unwrap();
        assert!(super::oauth2_required(on.to_str().unwrap()));
        let _ = std::fs::remove_file(off);
        let _ = std::fs::remove_file(on);
    }

    #[tokio::test]
    async fn test_oauth2_missing_token_rejected_401() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let (server, port) = start_server(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            client.get("/ndccf-datamanagement/v1/subscriptions"),
        )
        .await
        .expect("bounded")
        .expect("response");
        assert_eq!(resp.status, 401, "unauthenticated request must be 401");
        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_oauth2_wrong_audience_rejected_401() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let (server, port) = start_server(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let token = build_es256_token(&sk, "nrf-es256", "AMF", "ndccf-datamanagement");
        let req = SbiRequest::get("/ndccf-datamanagement/v1/subscriptions")
            .with_header("Authorization", format!("Bearer {token}"));
        let resp = tokio::time::timeout(Duration::from_secs(5), client.send_request(req))
            .await
            .expect("bounded")
            .expect("response");
        assert_eq!(resp.status, 401, "wrong-audience token must be 401");
        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_oauth2_valid_token_reaches_handler() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let (server, port) = start_server(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let token = build_es256_token(&sk, "nrf-es256", "DCCF", "ndccf-datamanagement");
        let req = SbiRequest::get("/ndccf-datamanagement/v1/subscriptions/does-not-exist")
            .with_header("Authorization", format!("Bearer {token}"));
        let resp = tokio::time::timeout(Duration::from_secs(5), client.send_request(req))
            .await
            .expect("bounded")
            .expect("response");
        assert_ne!(resp.status, 401, "valid token must not be 401");
        assert_ne!(resp.status, 403, "valid token must not be 403");
        server.stop().await.expect("stop");
    }
}

// ---------------------------------------------------------------------------
// #112: Ndccf_DataManagement conformance and coordination
// ---------------------------------------------------------------------------
#[cfg(test)]
mod data_management_tests {
    use super::*;
    use std::sync::{Arc, Mutex as StdMutex};

    /// Serialises these tests: they share the process-global DCCF context (its
    /// subscription map and producer-subscription registry) and the coordination
    /// switch.
    ///
    /// The CRATE-WIDE lock from `context`, not a private one: `context::tests`
    /// mutates the same singleton, and `clear_subscriptions` below would otherwise
    /// wipe a subscription a `context::tests` case was mid-way through asserting
    /// on.
    use context::GLOBAL_TEST_LOCK as TEST_GUARD;

    fn init() {
        dccf_context_init(256);
    }

    /// Remove every subscription, so a test's assertions are about its own
    /// subscriptions and not whatever a sibling left behind. The context is
    /// process-global, and `GLOBAL` locks serialise but do not isolate.
    fn clear_subscriptions() {
        for id in context::dccf_context_subscription_ids() {
            dccf_context_remove_subscription(&id);
        }
    }

    fn subscribe_body(corr: &str, uri: &str, event: &str) -> String {
        serde_json::json!({
            "notifCorrId": corr,
            "notificURI": uri,
            "anaSub": {"eventSubscriptions": [{"event": event}]}
        })
        .to_string()
    }

    fn post(path: &str, body: &str) -> SbiResponse {
        let req = SbiRequest::post(path).with_body(body.to_string(), "application/json");
        futures_lite_block_on(dccf_request_handler(req))
    }

    /// Minimal block_on: this crate has tokio but these handler calls need no
    /// reactor beyond what the runtime provides.
    fn futures_lite_block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(fut)
    }

    /// A loopback consumer that records the notification bodies it receives.
    async fn spawn_consumer() -> (SbiServer, u16, Arc<StdMutex<Vec<serde_json::Value>>>) {
        let seen: Arc<StdMutex<Vec<serde_json::Value>>> = Arc::new(StdMutex::new(Vec::new()));
        let sink = seen.clone();
        let (port_listener, port_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let port = port_addr.port();
        let server = SbiServer::on_listener(
            SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port))),
            port_listener,
        );
        server
            .start(move |req: SbiRequest| {
                let sink = sink.clone();
                async move {
                    if let Some(body) = req.http.content.as_deref() {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
                            sink.lock().unwrap_or_else(|e| e.into_inner()).push(v);
                        }
                    }
                    SbiResponse::no_content()
                }
            })
            .await
            .expect("consumer server start");
        (server, port, seen)
    }

    /// #112 acceptance: a subscription supplying `notificURI` receives its
    /// notifications.
    ///
    /// The anchor defect: the handler read `notifyUri`, so a conformant
    /// consumer's URI was never stored, the empty-URI filter dropped it from
    /// every fan-out, and it was never notified — with no error surface at all.
    /// End to end over a real connection, because that is the only place the
    /// whole chain (parse → store → key → deliver) is exercised.
    #[test]
    fn a_conformant_subscription_receives_its_notifications() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();

        futures_lite_block_on(async {
            let (consumer, port, seen) = spawn_consumer().await;

            let resp = dccf_request_handler(
                SbiRequest::post("/ndccf-datamanagement/v1/subscriptions").with_body(
                    subscribe_body("corr-A", &format!("http://127.0.0.1:{port}/cb"), "NF_LOAD"),
                    "application/json",
                ),
            )
            .await;
            assert_eq!(resp.status, 201);

            // A producer notification for the subscribed event.
            let resp = dccf_request_handler(
                SbiRequest::post("/ndccf-datamanagement/v1/notify").with_body(
                    serde_json::json!({
                        "subscriptionId": "prod-1",
                        "eventNotifications": [{"event": "NF_LOAD"}]
                    })
                    .to_string(),
                    "application/json",
                ),
            )
            .await;
            assert_eq!(resp.status, 204);

            // The fan-out POSTs are spawned, so wait for delivery.
            for _ in 0..50 {
                if !seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let delivered = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
            assert_eq!(
                delivered.len(),
                1,
                "the conformant consumer must be notified exactly once, got {delivered:?}"
            );

            // #112 acceptance: the body is an NnwdafDataManagementNotif echoing
            // this consumer's notifCorrId, not a bespoke {"data": "..."} envelope.
            let notif: data_mgmt::DataManagementNotif =
                serde_json::from_value(delivered[0].clone()).expect("parses as the spec type");
            assert_eq!(notif.notif_corr_id, "corr-A", "the subscription's own id");
            assert!(!notif.notif_timestamp.is_empty());
            assert!(notif.data_notification.is_some());
            assert!(
                delivered[0].get("data").is_none(),
                "the old bespoke envelope must be gone: {:?}",
                delivered[0]
            );

            consumer.stop().await.expect("stop");
        });
        clear_subscriptions();
    }

    /// #112 acceptance: fan-out is keyed on the event — a notification for event
    /// A reaches only the consumer subscribed to A.
    ///
    /// The old fan-out returned every subscriber with a callback URI, so any
    /// consumer received every other consumer's collected data.
    #[test]
    fn fanout_is_keyed_on_the_subscribed_event() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();

        futures_lite_block_on(async {
            let (consumer_a, port_a, seen_a) = spawn_consumer().await;
            let (consumer_b, port_b, seen_b) = spawn_consumer().await;

            for (corr, port, event) in [
                ("corr-A", port_a, "NF_LOAD"),
                ("corr-B", port_b, "UE_MOBILITY"),
            ] {
                let resp = dccf_request_handler(
                    SbiRequest::post("/ndccf-datamanagement/v1/subscriptions").with_body(
                        subscribe_body(corr, &format!("http://127.0.0.1:{port}/cb"), event),
                        "application/json",
                    ),
                )
                .await;
                assert_eq!(resp.status, 201);
            }

            // A notification for NF_LOAD only.
            dccf_request_handler(
                SbiRequest::post("/ndccf-datamanagement/v1/notify").with_body(
                    serde_json::json!({"eventNotifications": [{"event": "NF_LOAD"}]}).to_string(),
                    "application/json",
                ),
            )
            .await;

            for _ in 0..50 {
                if !seen_a.lock().unwrap_or_else(|e| e.into_inner()).is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            // Give B a fair chance to be (wrongly) notified before asserting it
            // was not: an absence assertion checked too early passes for the
            // wrong reason.
            tokio::time::sleep(Duration::from_millis(150)).await;

            assert_eq!(
                seen_a.lock().unwrap_or_else(|e| e.into_inner()).len(),
                1,
                "consumer A subscribed to NF_LOAD and must receive it"
            );
            assert!(
                seen_b.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
                "consumer B subscribed to UE_MOBILITY and must NOT receive NF_LOAD data"
            );

            consumer_a.stop().await.expect("stop");
            consumer_b.stop().await.expect("stop");
        });
        clear_subscriptions();
    }

    /// #112 acceptance: every `required` / `oneOf` violation is a `400` with
    /// `application/problem+json`. A missing or unparseable body used to answer
    /// `201`.
    #[test]
    fn invalid_subscribe_bodies_are_rejected_with_problem_details() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();

        let cases: &[(&str, &str)] = &[
            ("", "no body at all"),
            ("not json", "unparseable"),
            (r#"{}"#, "no members"),
            (
                r#"{"notificURI":"http://c/cb","anaSub":{}}"#,
                "missing notifCorrId",
            ),
            (r#"{"notifCorrId":"c","anaSub":{}}"#, "missing notificURI"),
            (
                r#"{"notifCorrId":"c","notifyUri":"http://c/cb","anaSub":{}}"#,
                "the OLD bespoke key does not satisfy notificURI",
            ),
            (
                r#"{"notifCorrId":"c","notificURI":"http://c/cb"}"#,
                "neither anaSub nor dataSub",
            ),
            (
                r#"{"notifCorrId":"c","notificURI":"http://c/cb","anaSub":{},"dataSub":{}}"#,
                "both anaSub and dataSub (oneOf)",
            ),
        ];
        for (body, why) in cases {
            let resp = post("/ndccf-datamanagement/v1/subscriptions", body);
            assert_eq!(resp.status, 400, "must be 400 for: {why}");
            assert_eq!(
                resp.http.get_header("content-type").map(String::as_str),
                Some("application/problem+json"),
                "a 400 must carry ProblemDetails for: {why}"
            );
            let problem: nextgcore_sbi::message::ProblemDetails =
                serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}"))
                    .expect("parses as ProblemDetails");
            assert_eq!(problem.status, Some(400));
        }
        clear_subscriptions();
    }

    /// #112 acceptance: the `201` carries the mandatory `Location` header and a
    /// body that round-trips as the spec resource; `GET` returns the same
    /// resource rather than a bespoke status object.
    #[test]
    fn create_returns_location_and_the_spec_resource() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();

        let resp = post(
            "/ndccf-datamanagement/v1/subscriptions",
            &subscribe_body("corr-1", "http://consumer/cb", "NF_LOAD"),
        );
        assert_eq!(resp.status, 201);
        let location = resp
            .http
            .get_header("location")
            .cloned()
            .expect("Location is required: true in the yaml");
        assert!(
            location.starts_with(DM_SUBSCRIPTIONS_PATH),
            "Location must point at the individual resource, got {location}"
        );
        let sub_id = location.rsplit('/').next().unwrap().to_string();
        assert!(!sub_id.is_empty());

        let created: data_mgmt::DataManagementSubsc =
            serde_json::from_str(resp.http.content.as_deref().unwrap())
                .expect("the 201 body round-trips as NnwdafDataManagementSubsc");
        assert_eq!(created.notif_corr_id, "corr-1");
        assert_eq!(created.notific_uri, "http://consumer/cb");

        // GET returns the resource, not {"subscriptionId":..,"status":"ACTIVE"}.
        let req = SbiRequest::get(format!("{DM_SUBSCRIPTIONS_PATH}/{sub_id}"));
        let resp = futures_lite_block_on(dccf_request_handler(req));
        assert_eq!(resp.status, 200);
        let fetched: data_mgmt::DataManagementSubsc =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).expect("spec resource");
        assert_eq!(fetched, created);
        clear_subscriptions();
    }

    /// #112 acceptance: `PUT` updates the subscription (no longer `405`), and the
    /// change is observable on a later `GET` **and** in what the consumer
    /// receives — the scope must be recomputed, not just the stored body.
    #[test]
    fn put_updates_the_subscription_and_its_scope() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();

        let resp = post(
            "/ndccf-datamanagement/v1/subscriptions",
            &subscribe_body("corr-1", "http://consumer/cb", "NF_LOAD"),
        );
        let sub_id = resp
            .http
            .get_header("location")
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_string();

        let put = SbiRequest::put(format!("{DM_SUBSCRIPTIONS_PATH}/{sub_id}")).with_body(
            subscribe_body("corr-2", "http://consumer/other", "UE_MOBILITY"),
            "application/json",
        );
        let resp = futures_lite_block_on(dccf_request_handler(put));
        assert_ne!(resp.status, 405, "PUT must be implemented");
        assert_eq!(resp.status, 200);

        // Observable on GET.
        let resp = futures_lite_block_on(dccf_request_handler(SbiRequest::get(format!(
            "{DM_SUBSCRIPTIONS_PATH}/{sub_id}"
        ))));
        let fetched: data_mgmt::DataManagementSubsc =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(fetched.notif_corr_id, "corr-2");
        assert_eq!(fetched.notific_uri, "http://consumer/other");

        // ...and the SCOPE moved with it: the subscription now matches
        // UE_MOBILITY and no longer matches NF_LOAD. Storing the new body while
        // leaving the old scope in place would pass the GET assertion above.
        let stored = dccf_context_get_subscription(&sub_id).expect("stored");
        assert!(stored.scope.events.contains("UE_MOBILITY"));
        assert!(
            !stored.scope.events.contains("NF_LOAD"),
            "the old event must not linger in the recomputed scope"
        );
        assert_eq!(stored.notif_corr_id, "corr-2");

        // PUT on an unknown id is 404, not a create at a consumer-chosen id.
        let put = SbiRequest::put(format!("{DM_SUBSCRIPTIONS_PATH}/no-such-id")).with_body(
            subscribe_body("c", "http://c/cb", "NF_LOAD"),
            "application/json",
        );
        assert_eq!(futures_lite_block_on(dccf_request_handler(put)).status, 404);
        clear_subscriptions();
    }

    /// #112 acceptance (coordination): two consumers asking for the same
    /// `(events, target)` share ONE producer subscription.
    ///
    /// Runs against a loopback NRF (serving `GET
    /// /nnrf-nfm/v1/nf-instances/{id}`) and a loopback producer (counting
    /// `POST /namf-evts/v1/subscriptions`), so the discovery and the producer
    /// signalling are real HTTP, not a stubbed seam.
    #[test]
    fn overlapping_consumers_share_one_producer_subscription() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();

        futures_lite_block_on(async {
            // Producer: counts the subscriptions created on it.
            let created = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counter = created.clone();
            let (producer_listener, producer_addr) =
                nextgcore_sbi::test_support::bound_listener().into_parts();
            let producer_port = producer_addr.port();
            let producer = SbiServer::on_listener(
                SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], producer_port))),
                producer_listener,
            );
            producer
                .start(move |req: SbiRequest| {
                    let counter = counter.clone();
                    async move {
                        if req.header.method == "POST" {
                            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            return SbiResponse::created()
                                .with_header("Location", "http://producer/sub/1");
                        }
                        SbiResponse::no_content()
                    }
                })
                .await
                .expect("producer start");

            // NRF: answers the NF profile retrieval with an event-exposure service
            // pointing at the producer above.
            let (nrf_listener, nrf_addr) =
                nextgcore_sbi::test_support::bound_listener().into_parts();
            let nrf_port = nrf_addr.port();
            let nrf = SbiServer::on_listener(
                SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], nrf_port))),
                nrf_listener,
            );
            nrf.start(move |_req: SbiRequest| async move {
                SbiResponse::ok()
                    .with_json_body(&serde_json::json!({
                        "nfInstanceId": "amf-1",
                        "nfType": "AMF",
                        "nfStatus": "REGISTERED",
                        "nfServices": [{
                            "serviceInstanceId": "amf-evts-1",
                            "serviceName": "namf-evts",
                            "scheme": "http",
                            "ipEndPoints": [
                                {"ipv4Address": "127.0.0.1", "port": producer_port}
                            ]
                        }]
                    }))
                    .unwrap_or_else(|_| SbiResponse::ok())
            })
            .await
            .expect("nrf start");

            coordination::set_coordination_for_test(Some(coordination::CoordinationConfig {
                nrf_uri: format!("http://127.0.0.1:{nrf_port}"),
                own_notify_uri: "http://dccf/ndccf-datamanagement/v1/notify".to_string(),
            }));

            // Two consumers, same event and same target NF.
            let body = |corr: &str| {
                serde_json::json!({
                    "notifCorrId": corr,
                    "notificURI": "http://consumer/cb",
                    "targetNfId": "amf-1",
                    "anaSub": {"eventSubscriptions": [{"event": "UE_MOBILITY"}]}
                })
                .to_string()
            };
            for corr in ["corr-1", "corr-2"] {
                let resp = dccf_request_handler(
                    SbiRequest::post("/ndccf-datamanagement/v1/subscriptions")
                        .with_body(body(corr), "application/json"),
                )
                .await;
                assert_eq!(resp.status, 201);
            }

            assert_eq!(
                created.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "the second consumer must REUSE the producer subscription, not create a second"
            );
            assert_eq!(
                dccf_context_producer_sub_count(),
                1,
                "one producer subscription for the shared scope"
            );

            coordination::set_coordination_for_test(None);
            producer.stop().await.expect("stop");
            nrf.stop().await.expect("stop");
        });
        clear_subscriptions();
    }

    /// #112: with coordination OFF (the default) no producer signalling happens
    /// at all — the guard on the default posture. Same request as the test above.
    #[test]
    fn coordination_off_creates_no_producer_subscription() {
        let _g = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        init();
        clear_subscriptions();
        coordination::set_coordination_for_test(None);

        let body = serde_json::json!({
            "notifCorrId": "corr-1",
            "notificURI": "http://consumer/cb",
            "targetNfId": "amf-1",
            "anaSub": {"eventSubscriptions": [{"event": "UE_MOBILITY"}]}
        })
        .to_string();
        let resp = post("/ndccf-datamanagement/v1/subscriptions", &body);
        assert_eq!(resp.status, 201, "the consumer subscription still succeeds");
        assert_eq!(
            dccf_context_producer_sub_count(),
            0,
            "coordination is off by default: no producer is dialled"
        );
        clear_subscriptions();
    }
}
