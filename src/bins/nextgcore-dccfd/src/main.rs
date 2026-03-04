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
use ogs_sbi::message::{SbiRequest, SbiResponse};
use ogs_sbi::server::{
    send_method_not_allowed, send_not_found,
    SbiServer, SbiServerConfig,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod context;

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
    .expect("Failed to set signal handler");
}

/// DCCF SBI request handler (called by the SBI server per request).
async fn dccf_request_handler(req: SbiRequest) -> SbiResponse {
    let method = req.header.method.as_str();
    let uri = &req.header.uri;
    let path = uri.split('?').next().unwrap_or(uri);

    log::debug!("DCCF SBI: {} {}", method, path);

    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match parts.as_slice() {
        // ----------------------------------------------------------------
        // Health check
        // ----------------------------------------------------------------
        ["healthz"] => {
            SbiResponse::ok()
                .with_body(r#"{"status":"ok"}"#, "application/json")
        }

        // ----------------------------------------------------------------
        // Ndccf_DataManagement (TS 29.574 §5.2)
        // ----------------------------------------------------------------

        // POST /ndccf-datamanagement/v1/subscriptions
        ["ndccf-datamanagement", "v1", "subscriptions"] => match method {
            "POST" => {
                let sub_id = uuid::Uuid::new_v4().to_string();
                log::info!("[DCCF] DataManagement subscription created sub_id={}", sub_id);
                dccf_context_add_subscription(sub_id.clone());
                let body = format!(r#"{{"subscriptionId":"{}","status":"ACTIVE"}}"#, sub_id);
                SbiResponse::created().with_body(body, "application/json")
            }
            _ => send_method_not_allowed(method, "subscriptions"),
        },

        // GET/DELETE /ndccf-datamanagement/v1/subscriptions/{subscriptionId}
        ["ndccf-datamanagement", "v1", "subscriptions", sub_id] => match method {
            "GET" => {
                if dccf_context_has_subscription(sub_id) {
                    let body = format!(r#"{{"subscriptionId":"{}","status":"ACTIVE"}}"#, sub_id);
                    SbiResponse::ok().with_body(body, "application/json")
                } else {
                    send_not_found("subscription not found", None)
                }
            }
            "DELETE" => {
                if dccf_context_remove_subscription(sub_id) {
                    log::info!("[DCCF] DataManagement subscription deleted sub_id={}", sub_id);
                    SbiResponse::no_content()
                } else {
                    send_not_found("subscription not found", None)
                }
            }
            _ => send_method_not_allowed(method, "subscriptions/{id}"),
        },

        // POST /ndccf-datamanagement/v1/notify — inbound data from producers
        ["ndccf-datamanagement", "v1", "notify"] => match method {
            "POST" => {
                let body = req.http.content.as_deref().unwrap_or("{}");
                log::debug!("[DCCF] DataManagement notify received len={}", body.len());
                dccf_context_fanout_notify(body);
                SbiResponse::no_content()
            }
            _ => send_method_not_allowed(method, "notify"),
        },

        // ----------------------------------------------------------------
        // Ndccf_ContextDocument (TS 29.574 §5.3)
        // ----------------------------------------------------------------

        // POST /ndccf-contextdocument/v1/contexts
        ["ndccf-contextdocument", "v1", "contexts"] => match method {
            "POST" => {
                let ctx_id = uuid::Uuid::new_v4().to_string();
                log::info!("[DCCF] ContextDocument context created ctx_id={}", ctx_id);
                dccf_context_add_analytics_context(ctx_id.clone());
                let body = format!(r#"{{"contextId":"{}"}}"#, ctx_id);
                SbiResponse::created().with_body(body, "application/json")
            }
            _ => send_method_not_allowed(method, "contexts"),
        },

        // GET/DELETE /ndccf-contextdocument/v1/contexts/{contextId}
        ["ndccf-contextdocument", "v1", "contexts", ctx_id] => match method {
            "GET" => {
                if dccf_context_has_analytics_context(ctx_id) {
                    let body = format!(r#"{{"contextId":"{}"}}"#, ctx_id);
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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_logging(&args.log_level);
    // G32/G43: Initialize OpenTelemetry tracing (Jaeger/OTLP exporter)
    let _otel = ogs_metrics::otel::init_otel(
        ogs_metrics::otel::OtelConfig::new(env!("CARGO_PKG_NAME"))
            .with_endpoint(
                std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                    .unwrap_or_else(|_| "http://jaeger:4317".to_string()),
            ),
    )
    .ok();

    log::info!("NextGCore DCCF v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Data Collection Co-ordination Function (3GPP TS 23.288 §6.7)");

    dccf_context_init(args.max_subscriptions);

    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone());

    let bind_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI bind address")?;
    log::info!("DCCF SBI listening on {}", bind_addr);

    let mut sbi_config = SbiServerConfig::new(bind_addr);
    if args.tls {
        if let (Some(cert), Some(key)) = (args.tls_cert, args.tls_key) {
            sbi_config = sbi_config.with_tls(key, cert);
        }
    }

    let sbi_server = SbiServer::new(sbi_config);
    sbi_server
        .start(dccf_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    log::info!("NextGCore DCCF ready");

    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    log::info!("DCCF shutting down");
    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;

    dccf_context_final();
    log::info!("DCCF shutdown complete");
    Ok(())
}
