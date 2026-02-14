//! NextGCore NWDAF (Network Data Analytics Function)
//!
//! The NWDAF is a Rel-16/17/18/20 network function responsible for (TS 23.288):
//! - Collecting and analyzing network data from various NFs
//! - Providing analytics to consumers (AMF, SMF, PCF, etc.)
//! - ML model training and inference for predictive analytics
//! - Supporting various analytics types (NF load, UE mobility, QoS, etc.)

use anyhow::{Context, Result};
use clap::Parser;
use ogs_sbi::message::{SbiRequest, SbiResponse};
use ogs_sbi::server::{
    send_method_not_allowed, send_not_found, SbiServer, SbiServerConfig as OgsSbiServerConfig,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod context;
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
    .expect("Failed to set signal handler");
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    init_logging(&args.log_level);

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
        // Nnwdaf_AnalyticsInfo service
        ["nnwdaf-analyticsinfo", "v1", "analytics"] => match method {
            "POST" => handle_analytics_info_query(&request).await,
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
}
