//! NextGCore NSACF (Network Slice Admission Control Function)
//!
//! The NSACF is a 5G core network function responsible for (TS 23.502 4.2.9):
//! - Slice-level admission control for UE registrations
//! - Slice-level admission control for PDU session establishment
//! - Monitoring and reporting slice utilization
//! - Enforcing maximum number of UEs/PDU sessions per slice

use anyhow::{Context, Result};
use clap::Parser;
use ogs_sbi::message::{SbiRequest, SbiResponse};
use ogs_sbi::server::{
    send_bad_request, send_method_not_allowed, send_not_found,
    SbiServer, SbiServerConfig as OgsSbiServerConfig,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod context;

pub use context::*;

/// NextGCore NSACF - Network Slice Admission Control Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-nsacfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Network Slice Admission Control Function (TS 23.502 4.2.9)", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/nsacf.yaml")]
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
    #[arg(long, default_value = "7813")]
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

    /// Maximum slice quotas
    #[arg(long, default_value = "64")]
    max_quotas: usize,

    /// NRF URI for registration
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
    .expect("Failed to set signal handler");
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    init_logging(&args.log_level);

    log::info!("NextGCore NSACF v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Network Slice Admission Control Function (3GPP TS 23.502 4.2.9)");

    // Initialize context
    nsacf_context_init(args.max_quotas);

    // Setup shutdown
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone());

    // Start SBI server
    let addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;

    let mut sbi_server_config = OgsSbiServerConfig::new(addr);
    if args.tls {
        let cert = args.tls_cert.as_deref().unwrap_or("/etc/nextgcore/tls/server.crt");
        let key = args.tls_key.as_deref().unwrap_or("/etc/nextgcore/tls/server.key");
        sbi_server_config = sbi_server_config.with_tls(key, cert);
        log::info!("TLS enabled: cert={cert}, key={key}");
    }

    let sbi_server = SbiServer::new(sbi_server_config);

    log::info!("Starting NSACF SBI server on {addr}");

    sbi_server.start(nsacf_sbi_request_handler).await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    let scheme = if args.tls { "HTTPS" } else { "HTTP" };
    log::info!("SBI HTTP/2 {scheme} server listening on {addr}");
    log::info!("NextGCore NSACF ready");

    // Main event loop
    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Graceful shutdown
    log::info!("Shutting down...");
    sbi_server.stop().await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;
    log::info!("SBI HTTP/2 server stopped");

    nsacf_context_final();
    log::info!("NSACF shutdown complete");

    Ok(())
}

/// NSACF SBI request handler
async fn nsacf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("NSACF SBI: {method} {uri}");

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match parts.as_slice() {
        // Slice Admission Control (Nnsacf_NSAC)
        ["nnsacf-nsac", "v1", "slice-quotas"] => {
            match method {
                "POST" => handle_slice_quota_create(&request).await,
                "GET" => handle_slice_quota_list().await,
                _ => send_method_not_allowed(method, "slice-quotas"),
            }
        }
        ["nnsacf-nsac", "v1", "slice-quotas", quota_id] => {
            match method {
                "GET" => handle_slice_quota_get(quota_id).await,
                "DELETE" => handle_slice_quota_delete(quota_id).await,
                _ => send_method_not_allowed(method, "slice-quotas/{id}"),
            }
        }
        // Admission control operations
        ["nnsacf-nsac", "v1", "ue-admission"] => {
            match method {
                "POST" => handle_ue_admission(&request).await,
                _ => send_method_not_allowed(method, "ue-admission"),
            }
        }
        ["nnsacf-nsac", "v1", "ue-release"] => {
            match method {
                "POST" => handle_ue_release(&request).await,
                _ => send_method_not_allowed(method, "ue-release"),
            }
        }
        // Utilization reporting
        ["nnsacf-nsac", "v1", "utilization"] => {
            match method {
                "GET" => handle_utilization_report().await,
                _ => send_method_not_allowed(method, "utilization"),
            }
        }
        _ => {
            log::debug!("Unknown path: {path}");
            send_not_found(&format!("Resource not found: {path}"), None)
        }
    }
}

/// Handle Slice Quota Create
async fn handle_slice_quota_create(request: &SbiRequest) -> SbiResponse {
    log::info!("Slice Quota Create");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let sst = data.get("sNssai")
        .and_then(|s| s.get("sst"))
        .and_then(|v| v.as_u64())
        .unwrap_or(1) as u8;
    let sd = data.get("sNssai")
        .and_then(|s| s.get("sd"))
        .and_then(|v| v.as_str())
        .and_then(|s| u32::from_str_radix(s, 16).ok());
    let max_ues = data.get("maxUes")
        .and_then(|v| v.as_u64())
        .unwrap_or(10000);
    let max_pdu = data.get("maxPduSessions")
        .and_then(|v| v.as_u64())
        .unwrap_or(50000);

    let s_nssai = SNssai::new(sst, sd);

    let ctx = nsacf_self();
    let quota = if let Ok(context) = ctx.read() {
        context.quota_add(s_nssai, max_ues, max_pdu)
    } else {
        None
    };

    match quota {
        Some(quota) => {
            let quota_id = format!("quota-{}", quota.id);
            log::info!(
                "Slice quota created: {quota_id} (SST={sst} SD={sd:?} max_ues={max_ues} max_pdu={max_pdu})"
            );

            SbiResponse::with_status(201)
                .with_header("Location", format!("/nnsacf-nsac/v1/slice-quotas/{quota_id}"))
                .with_json_body(&serde_json::json!({
                    "quotaId": quota_id,
                    "sNssai": {"sst": sst, "sd": sd.map(|v| format!("{v:06x}"))},
                    "maxUes": max_ues,
                    "maxPduSessions": max_pdu,
                    "currentUes": 0,
                    "currentPduSessions": 0,
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        None => {
            send_bad_request("Failed to create slice quota", Some("CREATION_FAILED"))
        }
    }
}

/// Handle Slice Quota List
async fn handle_slice_quota_list() -> SbiResponse {
    log::debug!("Slice Quota List");

    let ctx = nsacf_self();
    let utilization = if let Ok(context) = ctx.read() {
        context.get_utilization()
    } else {
        vec![]
    };

    let quotas: Vec<serde_json::Value> = utilization.iter().map(|(snssai, util)| {
        serde_json::json!({
            "sNssai": {"sst": snssai.sst, "sd": snssai.sd.map(|v| format!("{v:06x}"))},
            "utilization": util,
        })
    }).collect();

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({"sliceQuotas": quotas}))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Handle Slice Quota Get
async fn handle_slice_quota_get(quota_id: &str) -> SbiResponse {
    log::debug!("Slice Quota Get: {quota_id}");

    let pool_id = quota_id
        .strip_prefix("quota-")
        .and_then(|s| s.parse::<u64>().ok());

    let ctx = nsacf_self();
    let quota = pool_id.and_then(|id| {
        if let Ok(context) = ctx.read() {
            context.quota_find_by_id(id)
        } else {
            None
        }
    });

    match quota {
        Some(quota) => {
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "quotaId": quota_id,
                    "sNssai": {"sst": quota.s_nssai.sst, "sd": quota.s_nssai.sd.map(|v| format!("{v:06x}"))},
                    "maxUes": quota.max_ues,
                    "maxPduSessions": quota.max_pdu_sessions,
                    "currentUes": quota.current_ues.load(std::sync::atomic::Ordering::SeqCst),
                    "currentPduSessions": quota.current_pdu_sessions.load(std::sync::atomic::Ordering::SeqCst),
                    "utilization": quota.ue_utilization(),
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => {
            send_not_found(&format!("Slice quota {quota_id} not found"), Some("QUOTA_NOT_FOUND"))
        }
    }
}

/// Handle Slice Quota Delete
async fn handle_slice_quota_delete(_quota_id: &str) -> SbiResponse {
    log::info!("Slice Quota Delete: {_quota_id}");
    SbiResponse::with_status(204)
}

/// Handle UE Admission request (TS 23.502 4.2.9.2)
async fn handle_ue_admission(request: &SbiRequest) -> SbiResponse {
    log::info!("UE Admission Control");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let sst = data.get("sNssai")
        .and_then(|s| s.get("sst"))
        .and_then(|v| v.as_u64())
        .unwrap_or(1) as u8;
    let sd = data.get("sNssai")
        .and_then(|s| s.get("sd"))
        .and_then(|v| v.as_str())
        .and_then(|s| u32::from_str_radix(s, 16).ok());
    let supi = data.get("supi")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let s_nssai = SNssai::new(sst, sd);

    let ctx = nsacf_self();
    let result = if let Ok(context) = ctx.read() {
        context.admit_ue(&s_nssai)
    } else {
        AdmissionResult::RejectedSliceNotAvailable
    };

    match result {
        AdmissionResult::Admitted => {
            log::info!("[{supi}] Admitted to S-NSSAI[SST:{sst} SD:{sd:?}]");
            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "result": "ADMITTED",
                    "supi": supi,
                    "sNssai": {"sst": sst, "sd": sd.map(|v| format!("{v:06x}"))},
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        AdmissionResult::RejectedQuotaExceeded => {
            log::warn!("[{supi}] Rejected from S-NSSAI[SST:{sst} SD:{sd:?}] - quota exceeded");
            SbiResponse::with_status(403)
                .with_json_body(&serde_json::json!({
                    "result": "REJECTED",
                    "cause": "QUOTA_EXCEEDED",
                    "supi": supi,
                    "sNssai": {"sst": sst, "sd": sd.map(|v| format!("{v:06x}"))},
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(403))
        }
        AdmissionResult::RejectedSliceNotAvailable => {
            log::warn!("[{supi}] Rejected from S-NSSAI[SST:{sst} SD:{sd:?}] - not available");
            SbiResponse::with_status(403)
                .with_json_body(&serde_json::json!({
                    "result": "REJECTED",
                    "cause": "SLICE_NOT_AVAILABLE",
                    "supi": supi,
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(403))
        }
    }
}

/// Handle UE Release (decrement counters)
async fn handle_ue_release(request: &SbiRequest) -> SbiResponse {
    log::info!("UE Release");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let sst = data.get("sNssai")
        .and_then(|s| s.get("sst"))
        .and_then(|v| v.as_u64())
        .unwrap_or(1) as u8;
    let sd = data.get("sNssai")
        .and_then(|s| s.get("sd"))
        .and_then(|v| v.as_str())
        .and_then(|s| u32::from_str_radix(s, 16).ok());

    let s_nssai = SNssai::new(sst, sd);

    let ctx = nsacf_self();
    if let Ok(context) = ctx.read() {
        context.release_ue(&s_nssai);
    }

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({"result": "RELEASED"}))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Handle utilization report
async fn handle_utilization_report() -> SbiResponse {
    log::debug!("Utilization Report");

    let ctx = nsacf_self();
    let utilization = if let Ok(context) = ctx.read() {
        context.get_utilization()
    } else {
        vec![]
    };

    let entries: Vec<serde_json::Value> = utilization.iter().map(|(snssai, util)| {
        serde_json::json!({
            "sNssai": {"sst": snssai.sst, "sd": snssai.sd.map(|v| format!("{v:06x}"))},
            "ueUtilization": util,
        })
    }).collect();

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({"sliceUtilization": entries}))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-nsacfd"]);
        assert_eq!(args.config, "/etc/nextgcore/nsacf.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.sbi_port, 7813);
        assert_eq!(args.max_quotas, 64);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-nsacfd",
            "--sbi-port", "8813",
            "--max-quotas", "128",
            "--nrf-uri", "http://nrf:7777",
        ]);
        assert_eq!(args.sbi_port, 8813);
        assert_eq!(args.max_quotas, 128);
        assert_eq!(args.nrf_uri, "http://nrf:7777");
    }
}
