//! NextGCore NWDAF (Network Data Analytics Function)
//!
//! The NWDAF is a Rel-16/17/18/20 network function responsible for (TS 23.288):
//! - Collecting and analyzing network data from various NFs
//! - Providing analytics to consumers (AMF, SMF, PCF, etc.)
//! - ML model training and inference for predictive analytics
//! - Supporting various analytics types (NF load, UE mobility, QoS, etc.)

use anyhow::{Context, Result};
use clap::Parser;
use ogs_sbi::context::{global_context, SbiContext};
use ogs_sbi::message::{SbiRequest, SbiResponse};
use ogs_sbi::server::{
    send_method_not_allowed, send_not_found, SbiServer, SbiServerConfig as OgsSbiServerConfig,
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
mod sbi_handler;
pub mod subscription;

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
        ogs_sbi::heartbeat::spawn_heartbeat_worker(nf_instance_id.clone(), 5);
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
            "DELETE" => handle_subscription_delete(subscription_id).await,
            _ => send_method_not_allowed(method, "subscriptions/{id}"),
        },

        // Nnwdaf_MLModelProvision service
        ["nnwdaf-mlmodelprovision", "v1", "models"] => match method {
            "POST" => handle_model_provision(&request).await,
            _ => send_method_not_allowed(method, "models"),
        },
        ["nnwdaf-mlmodelprovision", "v1", "models", model_id] => match method {
            "GET" => handle_model_get(model_id).await,
            _ => send_method_not_allowed(method, "models/{id}"),
        },

        _ => send_not_found(&format!("Resource not found: {path}"), None),
    }
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

    let nf_profile = serde_json::json!({
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
            }
        ],
        "allowedNfTypes": ["AMF", "SMF", "PCF", "NEF", "SCP"],
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
            log::info!("NWDAF registered with NRF successfully (id={nf_instance_id})");

            let mut self_instance =
                ogs_sbi::context::NfInstance::new(nf_instance_id, ogs_sbi::types::NfType::Nwdaf);
            self_instance.ipv4_addresses = vec![sbi_addr.to_string()];
            let mut svc = ogs_sbi::context::NfService::new(
                "nnwdaf-eventssubscription",
                ogs_sbi::types::SbiServiceType::NnwdafEventssubscription,
            );
            svc.port = sbi_port;
            svc.ip_addresses = vec![sbi_addr.to_string()];
            self_instance.add_service(svc);
            let mut svc2 = ogs_sbi::context::NfService::new(
                "nnwdaf-analyticsinfo",
                ogs_sbi::types::SbiServiceType::NnwdafAnalyticsinfo,
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
        // A GET with a valid event-id reaches the handler and yields 200.
        let req = SbiRequest::get("/nnwdaf-analyticsinfo/v1/analytics?event-id=NF_LOAD");
        let resp = nwdaf_sbi_request_handler(req).await;
        assert_eq!(resp.status, 200, "GET /analytics?event-id=NF_LOAD must be 200");
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
