//! NextGCore NWDAF (Network Data Analytics Function)
//!
//! The NWDAF is a Rel-16/17/18/20 network function responsible for (TS 23.288):
//! - Collecting and analyzing network data from various NFs
//! - Providing analytics to consumers (AMF, SMF, PCF, etc.)
//! - ML model training and inference for predictive analytics
//! - Supporting various analytics types (NF load, UE mobility, QoS, etc.)

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_sbi::context::{global_context, SbiContext};
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::{
    send_method_not_allowed, send_not_found, SbiServer, SbiServerConfig as NextgcoreSbiServerConfig,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub mod analytics;
mod context;
pub mod federation;
pub mod ml_service;
pub mod notification_dispatcher;
pub mod nrf_collector;
mod sbi_handler;

pub use context::*;
pub use sbi_handler::*;

/// NextGCore NWDAF - Network Data Analytics Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-nwdafd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Network Data Analytics Function (TS 23.288)", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/nwdaf.yaml")]
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
    #[arg(long, default_value = "7815")]
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

    /// Maximum analytics subscriptions
    #[arg(long, default_value = "1024")]
    max_subscriptions: usize,

    /// NRF URI for registration
    #[arg(long, default_value = "http://127.0.0.1:7777")]
    nrf_uri: String,

    /// NF instance ID
    #[arg(long)]
    nf_instance_id: Option<String>,
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

// ---------------------------------------------------------------------------
// OAuth2 rollout (Wave-6 H8): opt-in producer verification + outbound consumer
// token install. Default OFF so the matched-sim E2E path is byte-unchanged;
// enabled per-NF via `NEXTGCORE_SBI_OAUTH2_REQUIRE=1` (overlay-friendly) or the
// `nwdaf.sbi.oauth2.require: true` yaml knob. TS 33.501 §13.4.1, TS 29.510 §5.4.2.
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
/// NRF JWKS and requires `aud` to include NfType::Nwdaf; with no NRF URI it
/// fails closed (503). `nrf_uri` empty ⇒ unconfigured ⇒ fail-closed.
fn apply_oauth2_enforcement(
    mut cfg: NextgcoreSbiServerConfig,
    nrf_uri: &str,
) -> NextgcoreSbiServerConfig {
    cfg.require_oauth2 = true;
    let uri = (!nrf_uri.is_empty()).then_some(nrf_uri);
    cfg.oauth2_jwks_uri = uri.map(|u| {
        nextgcore_sbi::oauth::JwksCache::for_nrf(u)
            .jwks_uri()
            .to_string()
    });
    cfg = cfg.with_expected_audience_nf_type(nextgcore_sbi::types::NfType::Nwdaf);
    if let Some(u) = uri {
        let nf_instance_id = format!("nwdaf-{}", uuid::Uuid::new_v4());
        let _ = OAUTH2_CLIENT.set(Some(Arc::new(nextgcore_sbi::oauth::OAuth2Client::new(
            u,
            nf_instance_id,
            nextgcore_sbi::types::NfType::Nwdaf,
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

    log::info!("NextGCore NWDAF v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Network Data Analytics Function (3GPP TS 23.288)");

    let nf_instance_id = args
        .nf_instance_id
        .unwrap_or_else(|| format!("nwdaf-{}", uuid::Uuid::new_v4()));

    nwdaf_context_init(nf_instance_id.clone(), args.max_subscriptions);

    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone());

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
    }
    if oauth2_required(&args.config) {
        sbi_server_config = apply_oauth2_enforcement(sbi_server_config, &args.nrf_uri);
    }

    let sbi_server = SbiServer::new(sbi_server_config);

    log::info!("Starting NWDAF SBI server on {addr}");
    sbi_server
        .start(nwdaf_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    // Register with NRF. main() is the composition root: acquire the shared SBI
    // context once here and inject it downstream, instead of each function
    // reaching for the global_context() singleton.
    let sbi_ctx = global_context();
    sbi_ctx.set_nrf_uri(&args.nrf_uri).await;
    if let Err(e) = register_with_nrf(sbi_ctx, &args.sbi_addr, args.sbi_port, &nf_instance_id).await
    {
        log::warn!("NRF registration failed (will operate without NRF): {e}");
    } else {
        // G2-2: PATCH a real NFProfile "/load" gauge to NRF each heartbeat
        // (active analytics subscriptions, saturated at 100;
        // TS 29.510 §5.2.2.3.2). Honest subscription-count proxy — no
        // fabricated CPU numbers.
        nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(
            nf_instance_id.clone(),
            5,
            || {
                let load = nwdaf_self()
                    .read()
                    .map(|c| c.subscription_count())
                    .unwrap_or(0);
                load.min(100) as u8
            },
        );
    }

    // G2-1: arm the NRF NF_LOAD collector and attempt the initial
    // NFStatusSubscribe (TS 29.510 §5.2.2.5). Non-fatal on every failure —
    // the dispatcher tick retries/renews; analytics degrade to no-data.
    {
        let ctx = nwdaf_self();
        if let Ok(guard) = ctx.read() {
            guard.set_nrf_collector_config(NrfCollectorConfig {
                nrf_uri: args.nrf_uri.clone(),
                callback_uri: format!(
                    "http://{}:{}/nnwdaf-nfstatus-notify/v1/notify",
                    args.sbi_addr, args.sbi_port
                ),
            });
        }
        nrf_collector::subscribe_nf_status(&ctx).await;
    }

    // Spawn the notification dispatcher background task (T5.3).
    // It wakes every DEFAULT_DISPATCH_INTERVAL_SECS (30 s), computes analytics,
    // and POSTs Nnwdaf_EventsSubscription_Notify to all due subscribers.
    // The interval is intentionally short so subscriptions with the default
    // repetition_period_secs=60 receive their first notification quickly.
    let dispatch_interval = std::env::var("NWDAF_DISPATCH_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(notification_dispatcher::DEFAULT_DISPATCH_INTERVAL_SECS);
    notification_dispatcher::spawn_dispatcher(nwdaf_self(), dispatch_interval);
    log::info!(
        "Notification dispatcher spawned (interval={}s)",
        dispatch_interval
    );

    log::info!("NextGCore NWDAF ready (instance: {nf_instance_id})");

    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    log::info!("Shutting down...");
    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;

    nwdaf_context_final();
    log::info!("NWDAF shutdown complete");

    Ok(())
}

/// NWDAF SBI request handler
async fn nwdaf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("NWDAF SBI: {method} {uri}");

    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match parts.as_slice() {
        // Nnwdaf_AnalyticsInfo service — TS 29.520 §4.3.2.2.2 mandates HTTP GET
        // with an `event-id` query parameter (no request body).
        ["nnwdaf-analyticsinfo", "v1", "analytics"] => match method {
            "GET" => handle_analytics_info_query(&request).await,
            _ => send_method_not_allowed(method, "analytics"),
        },

        // Nnwdaf_EventsSubscription service
        ["nnwdaf-eventssubscription", "v1", "subscriptions"] => match method {
            "POST" => handle_subscription_create(&request).await,
            _ => send_method_not_allowed(method, "subscriptions"),
        },
        ["nnwdaf-eventssubscription", "v1", "subscriptions", subscription_id] => match method {
            "GET" => handle_subscription_get(subscription_id).await,
            "PUT" => handle_subscription_update(subscription_id, &request).await,
            "DELETE" => handle_subscription_delete(subscription_id).await,
            _ => send_method_not_allowed(method, "subscriptions/{id}"),
        },

        // Nnwdaf_MLModelProvision service — TS 29.520 is a Subscribe/Notify
        // resource on /subscriptions (there is no /models resource).
        ["nnwdaf-mlmodelprovision", "v1", "subscriptions"] => match method {
            "POST" => handle_ml_prov_subscription_create(&request).await,
            _ => send_method_not_allowed(method, "subscriptions"),
        },
        ["nnwdaf-mlmodelprovision", "v1", "subscriptions", subscription_id] => match method {
            "PUT" => handle_ml_prov_subscription_update(subscription_id, &request).await,
            "DELETE" => handle_ml_prov_subscription_delete(subscription_id).await,
            _ => send_method_not_allowed(method, "subscriptions/{id}"),
        },

        // G2-1: Nnrf_NFManagement NFStatusNotify callback (TS 29.510
        // §5.2.2.6) — the NRF POSTs NotificationData here; NFProfile.load
        // becomes the NF_LOAD analytics data.
        ["nnwdaf-nfstatus-notify", "v1", "notify"] => match method {
            "POST" => nrf_collector::handle_nf_status_notify(&request).await,
            _ => send_method_not_allowed(method, "notify"),
        },

        // Issue #16 (non-normative 6G ISAC, no frozen Stage-3): sensing-result
        // collection endpoint, feature-gated and off by default.
        #[cfg(feature = "sensing")]
        ["nnwdaf-sensingdata", "v1", "results"] => match method {
            "POST" => handle_sensing_result_post(&request).await,
            _ => send_method_not_allowed(method, "results"),
        },

        _ => send_not_found(&format!("Resource not found: {path}"), None),
    }
}

/// Build the TS 29.510 `NFProfile` this NWDAF registers at the NRF.
///
/// G2-3 (supported-events honesty): the profile advertises the analytics
/// events this NWDAF actually supports via `nwdafInfo.eventIds`
/// (TS 29.510 `NwdafInfo`, TS29510_Nnrf_NFManagement.yaml `NwdafInfo.eventIds`
/// → TS 29.520 `EventId`), derived from the single source of truth
/// [`SUPPORTED_EVENTS`] so consumers discover only analytics with a live
/// collector. Additive JSON: the NRF ignores unknown NFProfile members, so
/// registration behavior is otherwise unchanged.
fn build_nf_profile(nf_instance_id: &str, sbi_addr: &str, sbi_port: u16) -> serde_json::Value {
    let event_ids: Vec<&'static str> = SUPPORTED_EVENTS.iter().map(|e| e.as_str()).collect();
    serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "NWDAF",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [
            {
                "serviceInstanceId": format!("{}-nnwdaf-eventssubscription", nf_instance_id),
                "serviceName": "nnwdaf-eventssubscription",
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
            },
            {
                "serviceInstanceId": format!("{}-nnwdaf-analyticsinfo", nf_instance_id),
                "serviceName": "nnwdaf-analyticsinfo",
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
            },
            {
                "serviceInstanceId": format!("{}-nnwdaf-mlmodelprovision", nf_instance_id),
                "serviceName": "nnwdaf-mlmodelprovision",
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
            }
        ],
        "nwdafInfo": { "eventIds": event_ids },
        "allowedNfTypes": ["AMF", "SMF", "PCF", "NEF", "SCP"],
        "heartBeatTimer": 10
    })
}

/// Register NWDAF with NRF
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

    log::info!("Registering NWDAF with NRF at {nrf_uri}");

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
            log::info!("NWDAF registered with NRF successfully (id={nf_instance_id})");

            let mut self_instance = nextgcore_sbi::context::NfInstance::new(
                nf_instance_id,
                nextgcore_sbi::types::NfType::Nwdaf,
            );
            self_instance.ipv4_addresses = vec![sbi_addr.to_string()];
            let mut svc = nextgcore_sbi::context::NfService::new(
                "nnwdaf-eventssubscription",
                nextgcore_sbi::types::SbiServiceType::NnwdafEventssubscription,
            );
            svc.port = sbi_port;
            svc.ip_addresses = vec![sbi_addr.to_string()];
            self_instance.add_service(svc);
            let mut svc2 = nextgcore_sbi::context::NfService::new(
                "nnwdaf-analyticsinfo",
                nextgcore_sbi::types::SbiServiceType::NnwdafAnalyticsinfo,
            );
            svc2.port = sbi_port;
            svc2.ip_addresses = vec![sbi_addr.to_string()];
            self_instance.add_service(svc2);
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
        let args = Args::parse_from(["nextgcore-nwdafd"]);
        assert_eq!(args.config, "/etc/nextgcore/nwdaf.yaml");
        assert_eq!(args.sbi_port, 7815);
        assert_eq!(args.max_subscriptions, 1024);
    }

    // --- SbiContext dependency-injection pilot (DANGER-ZONES #1) ---

    #[tokio::test]
    async fn test_register_with_nrf_uses_injected_context() {
        // The injected context carries no NRF URI, so registration is skipped
        // and returns Ok without any network access. This proves
        // register_with_nrf reads the *injected* context rather than the
        // global_context() singleton (which a parallel test might have set).
        let ctx = SbiContext::new_isolated();
        let result = register_with_nrf(ctx, "127.0.0.1", 7815, "nwdaf-test").await;
        assert!(
            result.is_ok(),
            "no NRF URI on the injected context should skip registration: {result:?}"
        );
    }

    // --- G2-3: NF profile advertises supported events (contract test) ---

    /// G2-3 honesty contract: the registered NFProfile carries
    /// `nwdafInfo.eventIds` (TS 29.510 `NwdafInfo`), the array equals
    /// `SUPPORTED_EVENTS` exactly (same tokens, same order), and every token is
    /// a recognised TS 29.520 `NwdafEvent`/`EventId` value ("NF_LOAD" is valid
    /// in both enums). Field names pinned against
    /// TS29510_Nnrf_NFManagement.yaml `NwdafInfo` (eventIds → EventId).
    #[test]
    fn test_honesty_profile_advertises_supported_event_ids() {
        let profile = build_nf_profile("nwdaf-contract-test", "127.0.0.1", 7815);

        let event_ids = profile
            .get("nwdafInfo")
            .and_then(|i| i.get("eventIds"))
            .and_then(|v| v.as_array())
            .expect("NFProfile must carry nwdafInfo.eventIds (TS 29.510 NwdafInfo)");
        assert!(
            !event_ids.is_empty(),
            "nwdafInfo.eventIds has minItems 1 in the yaml"
        );

        let tokens: Vec<&str> = event_ids
            .iter()
            .map(|v| v.as_str().expect("eventIds entries are strings"))
            .collect();
        let supported: Vec<&str> = SUPPORTED_EVENTS.iter().map(|e| e.as_str()).collect();
        assert_eq!(
            tokens, supported,
            "advertised eventIds must equal SUPPORTED_EVENTS exactly"
        );

        // ⊆ NwdafEvent tokens: every advertised id round-trips through the
        // recognised event enum (no bespoke tokens on the wire).
        for t in &tokens {
            assert!(
                AnalyticsId::from_str(t).is_some(),
                "advertised eventId {t} must be a recognised NwdafEvent token"
            );
        }

        // Initially exactly NF_LOAD (the only live collector, G2-1).
        assert_eq!(tokens, vec!["NF_LOAD"]);
    }

    // --- nwafd-02: Nnwdaf_AnalyticsInfo is GET-only at the routing layer ---

    #[tokio::test]
    async fn test_routing_analytics_post_is_405() {
        // TS 29.520 §4.3.2.2.2: Nnwdaf_AnalyticsInfo is HTTP GET. A POST to the
        // analytics resource must be rejected with 405 Method Not Allowed.
        let req = SbiRequest::post("/nnwdaf-analyticsinfo/v1/analytics");
        let resp = nwdaf_sbi_request_handler(req).await;
        assert_eq!(resp.status, 405, "POST /analytics must be 405");
    }

    #[tokio::test]
    async fn test_routing_analytics_get_is_routed() {
        // A GET with a valid event-id reaches the handler. G2-1: the handler
        // computes from ingested NRF data only, so seed the global engine with
        // a sample for a test-unique instance and filter the query to it —
        // proving the route reaches the real handler AND real data flows back.
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        {
            let ctx = nwdaf_self();
            let guard = ctx.read().unwrap();
            guard
                .lock_engine()
                .ingest_nf_load(crate::analytics::NfLoadSample::now(
                    "AMF",
                    "amf-route-test",
                    0.5,
                    0.0,
                    0,
                ));
        }
        let req = SbiRequest::get(
            "/nnwdaf-analyticsinfo/v1/analytics?event-id=NF_LOAD&event-filter=%7B%22nfInstanceIds%22%3A%5B%22amf-route-test%22%5D%7D",
        );
        let resp = nwdaf_sbi_request_handler(req).await;
        assert_eq!(
            resp.status, 200,
            "GET /analytics?event-id=NF_LOAD with data must be 200"
        );
    }

    /// G2-3 honesty (acceptance check 1, curl-style through the REAL router):
    /// GET ?event-id=UE_MOBILITY returns 204 with an empty body — a 200 here
    /// is the empty-200 dishonesty this item removes. The engine is seeded
    /// with NF_LOAD data first so the 204 provably comes from the
    /// supported-events gate, not from a globally-empty engine.
    #[tokio::test]
    async fn test_honesty_routing_unsupported_event_get_204() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        {
            let ctx = nwdaf_self();
            let guard = ctx.read().unwrap();
            guard
                .lock_engine()
                .ingest_nf_load(crate::analytics::NfLoadSample::now(
                    "AMF",
                    "amf-honesty-route",
                    0.5,
                    0.0,
                    0,
                ));
        }
        let req = SbiRequest::get("/nnwdaf-analyticsinfo/v1/analytics?event-id=UE_MOBILITY");
        let resp = nwdaf_sbi_request_handler(req).await;
        assert_eq!(
            resp.status, 204,
            "GET ?event-id=UE_MOBILITY must be 204 No Content (a 200 fails CI)"
        );
        assert!(
            resp.http.content.as_deref().is_none_or(str::is_empty),
            "the 204 must carry an empty body"
        );
    }

    // --- G2-1: NFStatusNotify callback route ---

    #[tokio::test]
    async fn test_routing_nfstatus_notify_post_routed() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        let req = SbiRequest::post("/nnwdaf-nfstatus-notify/v1/notify")
            .with_json_body(&serde_json::json!({
                "event": "NF_REGISTERED",
                "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/amf-route-notify",
                "nfProfile": {
                    "nfInstanceId": "amf-route-notify",
                    "nfType": "AMF",
                    "nfStatus": "REGISTERED",
                    "load": 10
                }
            }))
            .expect("valid JSON body");
        let resp = nwdaf_sbi_request_handler(req).await;
        assert_eq!(resp.status, 204, "NFStatusNotify must route and return 204");
    }

    #[tokio::test]
    async fn test_routing_nfstatus_notify_get_is_405() {
        let req = SbiRequest::get("/nnwdaf-nfstatus-notify/v1/notify");
        let resp = nwdaf_sbi_request_handler(req).await;
        assert_eq!(resp.status, 405, "GET on the notify callback must be 405");
    }

    // --- nwafd-05: Nnwdaf_MLModelProvision is Subscribe/Notify, not /models ---

    #[tokio::test]
    async fn test_routing_mlmodelprovision_models_gone() {
        // The bespoke /models registry resource no longer exists → 404.
        let req = SbiRequest::post("/nnwdaf-mlmodelprovision/v1/models");
        let resp = nwdaf_sbi_request_handler(req).await;
        assert_eq!(resp.status, 404, "the /models resource must be removed");
    }

    #[tokio::test]
    async fn test_routing_mlmodelprovision_subscriptions_post_routed() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        let req = SbiRequest::post("/nnwdaf-mlmodelprovision/v1/subscriptions")
            .with_json_body(&serde_json::json!({
                "notifUri": "http://anlf.local/cb",
                "mLEventSubscs": [ { "mLEvent": "NF_LOAD" } ]
            }))
            .expect("valid JSON body");
        let resp = nwdaf_sbi_request_handler(req).await;
        assert_eq!(
            resp.status, 201,
            "POST /nnwdaf-mlmodelprovision/v1/subscriptions must reach the create handler"
        );
    }

    #[tokio::test]
    async fn test_routing_subscription_put_routed() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);
        let req = SbiRequest::put("/nnwdaf-eventssubscription/v1/subscriptions/unknown-id")
            .with_json_body(&serde_json::json!({
                "notificationURI": "http://amf.local/cb",
                "eventSubscriptions": [ { "event": "NF_LOAD" } ]
            }))
            .expect("valid JSON body");
        let resp = nwdaf_sbi_request_handler(req).await;
        assert_eq!(
            resp.status, 404,
            "PUT must route to the update handler (404, not 405)"
        );
    }

    #[tokio::test]
    async fn test_injected_contexts_are_isolated() {
        // Two injected contexts must not share state — the whole point of DI.
        let a = SbiContext::new_isolated();
        let b = SbiContext::new_isolated();

        a.set_nrf_uri("http://nrf-a:7777").await;

        assert_eq!(a.get_nrf_uri().await.as_deref(), Some("http://nrf-a:7777"));
        assert_eq!(
            b.get_nrf_uri().await,
            None,
            "context b must not observe context a's NRF URI"
        );
    }
}

/// G2-1 STRICT-PEER test (the pcfd lesson: no lenient mocks).
///
/// The conformant peer is our REAL nrfd: its NF-instance registry
/// (`nf_manager`), its real `apply_json_patch`, its real
/// `NotificationData`/`profileChanges` serializer and its real HTTP notify
/// sender (`nrf_nnrf_nfm_send_*_notify_all_async`) deliver TS 29.510
/// NFStatusNotify bodies over a real socket to nwdafd's REAL SBI server and
/// router. Analytics are then queried back over the wire via
/// Nnwdaf_AnalyticsInfo.
#[cfg(test)]
mod g21_strict_peer_tests {
    use super::*;
    use nextgcore_nrfd::{
        apply_json_patch, nf_manager, nrf_nnrf_nfm_send_nf_profile_changed_notify_all_async,
        nrf_nnrf_nfm_send_nf_status_notify_all_async, ChangeItem, NfProfile, NotificationEventType,
        SubscriptionData,
    };
    use nextgcore_sbi::client::SbiClient;
    use serde_json::{json, Value};

    const INSTANCE: &str = "g21-strict-amf";
    /// Percent-encoded `{"nfInstanceIds":["g21-strict-amf"]}`.
    const FILTER_QS: &str = "%7B%22nfInstanceIds%22%3A%5B%22g21-strict-amf%22%5D%7D";
    const NRF_SELF_URI: &str = "http://nrf.test:7777";

    async fn get_nf_load(client: &SbiClient) -> (u16, Option<Value>) {
        let uri =
            format!("/nnwdaf-analyticsinfo/v1/analytics?event-id=NF_LOAD&event-filter={FILTER_QS}");
        let resp = client
            .send_request(SbiRequest::get(&uri))
            .await
            .expect("GET analytics over the wire");
        let body = resp
            .http
            .content
            .as_deref()
            .and_then(|b| serde_json::from_str::<Value>(b).ok());
        (resp.status, body)
    }

    fn avg_of(body: &Option<Value>) -> u64 {
        body.as_ref()
            .and_then(|b| b.get("nfLoadLevelInfos"))
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|i| i.get("nfLoadLevelAverage"))
            .and_then(|v| v.as_u64())
            .expect("nfLoadLevelAverage present")
    }

    /// Full chain: NRF NF_REGISTERED → PATCH /load (two different values) →
    /// NF_DEREGISTERED, all delivered by nrfd's real notify pipeline, with the
    /// reported nfLoadLevelAverage tracking every PATCHed value and analytics
    /// going dark (204) after deregistration.
    #[tokio::test]
    async fn test_g21_strict_peer_nrf_load_ingestion() {
        nwdaf_context_init("nwdaf-test".to_string(), 1024);

        // Real nwdafd SBI server on a free localhost port.
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe port");
        let port = probe.local_addr().expect("addr").port();
        drop(probe);
        let server = SbiServer::new(NextgcoreSbiServerConfig::new(SocketAddr::from((
            [127, 0, 0, 1],
            port,
        ))));
        server
            .start(nwdaf_sbi_request_handler)
            .await
            .expect("nwdafd server starts");

        // Conformant peer state: our real nrfd registry with a fake AMF whose
        // profile carries load=40, plus a subscription pointing at nwdafd's
        // real NFStatusNotify callback.
        let profile = NfProfile::from_json(&json!({
            "nfInstanceId": INSTANCE,
            "nfType": "AMF",
            "nfStatus": "REGISTERED",
            "load": 40,
        }))
        .expect("valid NFProfile");
        nf_manager()
            .register(profile.clone())
            .expect("register at nrfd");
        nf_manager().add_subscription(SubscriptionData {
            id: "g21-strict-sub".to_string(),
            req_nf_type: Some("NWDAF".to_string()),
            req_nf_instance_id: None,
            notification_uri: format!("http://127.0.0.1:{port}/nnwdaf-nfstatus-notify/v1/notify"),
            subscr_cond: None, // all NFs
            validity_duration: 3600,
        });

        let client = SbiClient::with_host_port("127.0.0.1", port);

        // ── Leg A: NF_REGISTERED (full profile, load 40) ────────────────────
        let sent = nrf_nnrf_nfm_send_nf_status_notify_all_async(
            NotificationEventType::NfRegistered,
            &profile,
            NRF_SELF_URI,
        )
        .await
        .expect("nrfd delivers NF_REGISTERED");
        assert_eq!(sent, 1, "exactly our subscription must be notified");

        let (status, body) = get_nf_load(&client).await;
        assert_eq!(status, 200, "data exists after NF_REGISTERED");
        assert_eq!(avg_of(&body), 40, "average must equal the registered load");
        let info = body.as_ref().expect("body")["nfLoadLevelInfos"][0].clone();
        assert_eq!(info["nfInstanceId"].as_str(), Some(INSTANCE));
        assert_eq!(
            info["nfStatus"]["statusRegistered"].as_u64(),
            Some(100),
            "nfStatus must come from the NRF profile, in the TS 29.520 object form"
        );
        assert!(info["confidence"].is_u64(), "confidence is a Uinteger");
        assert!(
            info.get("predictedLoad").is_none(),
            "non-spec predictedLoad must not appear on the wire"
        );

        // ── Leg B: PATCH /load → 80, via nrfd's real patch + notify path ────
        let pre = profile.to_json();
        let patch = json!([{"op": "replace", "path": "/load", "value": 80}]);
        let mut post = pre.clone();
        apply_json_patch(&mut post, &patch).expect("nrfd applies the PATCH");
        let updated80 = NfProfile::from_json(&post).expect("patched profile");
        let sent = nrf_nnrf_nfm_send_nf_profile_changed_notify_all_async(
            &updated80,
            NRF_SELF_URI,
            vec![ChangeItem {
                op: "replace".to_string(),
                path: "/load".to_string(),
                value: Some(json!(80)),
                orig_value: Some(json!(40)),
            }],
        )
        .await
        .expect("nrfd delivers NF_PROFILE_CHANGED");
        assert_eq!(sent, 1);

        let (status, body) = get_nf_load(&client).await;
        assert_eq!(status, 200);
        // Samples [40, 80] → average 60.
        assert_eq!(
            avg_of(&body),
            60,
            "the reported average must move with the PATCHed load (40→80)"
        );

        // ── Leg B': a DIFFERENT PATCH value moves the average differently ───
        let patch = json!([{"op": "replace", "path": "/load", "value": 90}]);
        let mut post90 = post.clone();
        apply_json_patch(&mut post90, &patch).expect("nrfd applies the PATCH");
        let updated90 = NfProfile::from_json(&post90).expect("patched profile");
        let sent = nrf_nnrf_nfm_send_nf_profile_changed_notify_all_async(
            &updated90,
            NRF_SELF_URI,
            vec![ChangeItem {
                op: "replace".to_string(),
                path: "/load".to_string(),
                value: Some(json!(90)),
                orig_value: Some(json!(80)),
            }],
        )
        .await
        .expect("nrfd delivers NF_PROFILE_CHANGED");
        assert_eq!(sent, 1);

        let (status, body) = get_nf_load(&client).await;
        assert_eq!(status, 200);
        // Samples [40, 80, 90] → average 70 — a constant/fabricated value
        // could not produce 40 → 60 → 70 tracking the PATCH sequence.
        assert_eq!(
            avg_of(&body),
            70,
            "a second, different PATCH value must move the average again"
        );

        // ── Fail-closed over the wire: mandatory-IE violation → 400 ─────────
        let bad = client
            .post_json(
                "/nnwdaf-nfstatus-notify/v1/notify",
                &json!({ "nfInstanceUri": "http://n/nnrf-nfm/v1/nf-instances/x" }),
            )
            .await
            .expect("POST over the wire");
        assert_eq!(bad.status, 400, "missing event must fail closed with 400");

        // ── Leg C: NF_DEREGISTERED → analytics go dark (204, no fabrication) ─
        let sent = nrf_nnrf_nfm_send_nf_status_notify_all_async(
            NotificationEventType::NfDeregistered,
            &updated90,
            NRF_SELF_URI,
        )
        .await
        .expect("nrfd delivers NF_DEREGISTERED");
        assert_eq!(sent, 1);

        let (status, body) = get_nf_load(&client).await;
        assert_eq!(
            status, 204,
            "after the data source is gone, NF_LOAD must be 204 — numbers here would mean fabricated analytics"
        );
        assert!(body.is_none(), "204 carries no body");

        server.stop().await.expect("server stops");
    }
}

#[cfg(test)]
mod oauth2_h8_tests {
    //! Wave-6 H8 (Phase B) strict-peer OAuth2 enforcement triplet: the real
    //! `nwdaf_sbi_request_handler` is mounted behind nextgcore-sbi's server-side
    //! OAuth2 verification (TS 33.501 §13.4.1). A missing or wrong-audience
    //! Bearer is rejected (401) before the handler runs; a valid NRF-audience
    //! token (aud=NWDAF, ES256-signed against the served JWKS) passes through.
    use nextgcore_sbi::client::SbiClient;
    use nextgcore_sbi::message::SbiRequest;
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    use nextgcore_sbi::types::NfType;
    use std::net::SocketAddr;
    use std::time::Duration;

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

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
            "iss": "NRF", "sub": "nwdaf-1", "aud": aud,
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
        super::nwdaf_context_init("nwdaf-h8-test".to_string(), 256);
        let port = free_port();
        let mut cfg = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(jwks);
        cfg = cfg.with_expected_audience_nf_type(NfType::Nwdaf);
        let server = SbiServer::new(cfg);
        server
            .start(super::nwdaf_sbi_request_handler)
            .await
            .expect("server start");
        (server, port)
    }

    #[test]
    fn test_oauth2_require_knob_parses_and_defaults_off() {
        let dir = std::env::temp_dir();
        let off = dir.join(format!("nwdaf-h8-off-{}.yaml", std::process::id()));
        std::fs::write(
            &off,
            "nwdaf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n",
        )
        .unwrap();
        assert!(!super::oauth2_required(off.to_str().unwrap()));
        let on = dir.join(format!("nwdaf-h8-on-{}.yaml", std::process::id()));
        std::fs::write(&on, "nwdaf:\n  sbi:\n    oauth2:\n      require: true\n").unwrap();
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
            client.get("/nnwdaf-analyticsinfo/v1/analytics"),
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
        let token = build_es256_token(&sk, "nrf-es256", "AMF", "nnwdaf-analyticsinfo");
        let req = SbiRequest::get("/nnwdaf-analyticsinfo/v1/analytics")
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
        let token = build_es256_token(&sk, "nrf-es256", "NWDAF", "nnwdaf-analyticsinfo");
        let req = SbiRequest::get("/nnwdaf-analyticsinfo/v1/analytics/does-not-exist")
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
