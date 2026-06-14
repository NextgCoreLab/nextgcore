//! NextGCore NSACF (Network Slice Admission Control Function)
//!
//! The NSACF is a 5G core network function responsible for (TS 23.502 4.2.9,
//! TS 29.536):
//! - Slice-level admission control for UE registrations
//!   (Nnsacf_NSAC NumOfUEsUpdate: `/nnsacf-nsac/v1/slices/{snssai}/ues`)
//! - Slice-level admission control for PDU session establishment
//!   (Nnsacf_NSAC NumOfPDUsUpdate: `/nnsacf-nsac/v1/slices/{snssai}/pdu-sessions`)
//! - Slice event exposure subscriptions + notifications
//!   (Nnsacf_SliceEventExposure: `/nnsacf-slice-ee/v1/subscriptions`)
//! - Early Admission Control (EAC) mode notifications (TS 23.502 §4.2.9.5)
//!
//! Per TS 29.536, an admission REJECTION is a 200 response with
//! `admittedFlag=false` (+ rejectCause), not an HTTP 4xx.
//!
//! NOTE: the vendored OpenAPI sets (r16/r17) do not include
//! TS29536_Nnsacf_*.yaml, so the resource layout follows the remediation
//! plan's prescribed shape; field names mirror TS 29.536 terminology.

use anyhow::{Context, Result};
use clap::Parser;
use ogs_sbi::client::{SbiClient, SbiClientConfig};
use ogs_sbi::context::global_context;
use ogs_sbi::message::{SbiRequest, SbiResponse};
use ogs_sbi::oauth::{JwksCache, OAuth2Client};
use ogs_sbi::server::{send_method_not_allowed, SbiServer, SbiServerConfig as OgsSbiServerConfig};
use ogs_sbi::types::NfType;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

mod context;

pub use context::*;

// ---------------------------------------------------------------------------
// Typed YAML configuration structs (nsacf.nrf.uri + nsacf.sbi.oauth2.require)
// ---------------------------------------------------------------------------

/// SBI OAuth2 enforcement knob (`nsacf.sbi.oauth2.require`).
///
/// Defaults to disabled so the existing dev/E2E path keeps working without
/// tokens; the production/docker `nsacf-oauth2.yaml` variant sets it true.
#[derive(Debug, Default, Deserialize)]
struct SbiOauth2Yaml {
    require: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct SbiYaml {
    oauth2: Option<SbiOauth2Yaml>,
}

#[derive(Debug, Default, Deserialize)]
struct NrfYaml {
    uri: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct NsacfSection {
    sbi: Option<SbiYaml>,
    nrf: Option<NrfYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct NsacfYaml {
    nsacf: Option<NsacfSection>,
}

/// Process-wide OAuth2 client for automatic Bearer-token acquisition on
/// outbound SBI calls (set only when `nsacf.sbi.oauth2.require` is true).
static OAUTH2_CLIENT: OnceLock<Option<Arc<OAuth2Client>>> = OnceLock::new();

/// The shared OAuth2 client, if SBI OAuth2 enforcement is enabled. Outbound
/// SBI clients attach tokens via [`attach_oauth2`].
fn oauth2_client() -> Option<Arc<OAuth2Client>> {
    OAUTH2_CLIENT.get().and_then(|opt| opt.clone())
}

/// Attach the process-wide OAuth2 client (when enforcement is on) so the
/// outbound request carries an NRF-issued Bearer token scoped to `target`.
/// A no-op when enforcement is off.
fn attach_oauth2(client: SbiClient, target: NfType) -> SbiClient {
    match oauth2_client() {
        Some(oauth2) => client.with_oauth2(oauth2, target),
        None => client,
    }
}

/// Notification client timeouts (bounded; callbacks must not hang the NSACF)
const NOTIFY_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const NOTIFY_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

/// NextGCore NSACF - Network Slice Admission Control Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-nsacfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Network Slice Admission Control Function (TS 23.502 4.2.9 / TS 29.536)", long_about = None)]
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

    /// State file for counter persistence across restarts
    #[arg(long)]
    state_file: Option<String>,

    /// EAC activation threshold in percent of max UEs (TS 23.502 §4.2.9.5)
    #[arg(long, default_value = "80")]
    eac_threshold: u8,

    /// Force SBI OAuth2 bearer-token enforcement on/off, overriding the
    /// config file's `nsacf.sbi.oauth2.require`. Dev override; leave unset to
    /// follow config (default off).
    #[arg(long)]
    oauth2_require: Option<bool>,
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

/// Run a closure against the global NSACF context read guard.
fn with_nsacf_context<T>(f: impl FnOnce(&NsacfContext) -> T) -> Option<T> {
    let ctx = nsacf_self();
    let result = ctx.read().ok().map(|guard| f(&guard));
    result
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

    log::info!("NextGCore NSACF v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Network Slice Admission Control Function (3GPP TS 23.502 4.2.9 / TS 29.536)");

    // Initialize context
    nsacf_context_init(args.max_quotas);
    with_nsacf_context(|c| {
        c.set_eac_threshold(args.eac_threshold);
        if let Some(ref path) = args.state_file {
            c.set_state_file(Some(PathBuf::from(path)));
            c.load_state();
        }
    });

    let nf_instance_id = format!("nsacf-{}", uuid::Uuid::new_v4());

    // Parse the config file for the NRF URI and the OAuth2 enforcement knob
    // (nsacf.sbi.oauth2.require). The CLI --nrf-uri remains the fallback, and
    // --oauth2-require is a dev override of the config value.
    let mut nrf_uri_cfg: Option<String> = Some(args.nrf_uri.clone());
    let mut require_oauth2 = false;
    if let Ok(content) = std::fs::read_to_string(&args.config) {
        if let Ok(yaml) = serde_yaml::from_str::<NsacfYaml>(&content) {
            if let Some(nsacf) = yaml.nsacf {
                if let Some(uri) = nsacf.nrf.and_then(|n| n.uri) {
                    nrf_uri_cfg = Some(uri);
                }
                require_oauth2 = nsacf
                    .sbi
                    .and_then(|s| s.oauth2)
                    .and_then(|o| o.require)
                    .unwrap_or(false);
            }
        }
    }
    // Dev override: --oauth2-require true|false wins over the config value.
    if let Some(forced) = args.oauth2_require {
        require_oauth2 = forced;
    }

    // Setup shutdown
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone());

    // Start SBI server
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
        log::info!("TLS enabled: cert={cert}, key={key}");
    }
    if require_oauth2 {
        // Server side (TS 33.501 §13.4.1): verify incoming Bearer tokens
        // against the NRF's JWKS and require the token's `aud` to include this
        // NF's own type ("NSACF"). With no NRF URI the server fails closed
        // (503).
        sbi_server_config.require_oauth2 = true;
        sbi_server_config.oauth2_jwks_uri = nrf_uri_cfg
            .as_deref()
            .map(|uri| JwksCache::for_nrf(uri).jwks_uri().to_string());
        sbi_server_config =
            sbi_server_config.with_expected_audience_nf_type(NfType::Nsacf);

        // Client side (T1.1): install the process-wide OAuth2 client so
        // outbound SBI calls acquire and attach an NRF-issued Bearer token.
        if let Some(nrf_uri) = nrf_uri_cfg.as_deref() {
            let oauth2 =
                Arc::new(OAuth2Client::new(nrf_uri, nf_instance_id.clone(), NfType::Nsacf));
            let _ = OAUTH2_CLIENT.set(Some(oauth2));
        }
        log::info!(
            "OAuth2 enforcement enabled (JWKS: {})",
            sbi_server_config
                .oauth2_jwks_uri
                .as_deref()
                .unwrap_or("UNCONFIGURED")
        );
    }

    let sbi_server = SbiServer::new(sbi_server_config);

    log::info!("Starting NSACF SBI server on {addr}");

    sbi_server
        .start(nsacf_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    let scheme = if args.tls { "HTTPS" } else { "HTTP" };
    log::info!("SBI HTTP/2 {scheme} server listening on {addr}");

    // Register with NRF (config URI if present, else the CLI fallback)
    let sbi_ctx = global_context();
    sbi_ctx
        .set_nrf_uri(nrf_uri_cfg.as_deref().unwrap_or(&args.nrf_uri))
        .await;
    if let Err(e) = register_with_nrf(&args.sbi_addr, args.sbi_port, &nf_instance_id).await {
        log::warn!("NRF registration failed (will operate without NRF): {e}");
    } else {
        ogs_sbi::heartbeat::spawn_heartbeat_worker(nf_instance_id.clone(), 5);
    }

    log::info!("NextGCore NSACF ready (instance: {nf_instance_id})");

    // Main event loop
    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Graceful shutdown
    log::info!("Shutting down...");
    with_nsacf_context(|c| c.save_state());
    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;
    log::info!("SBI HTTP/2 server stopped");

    nsacf_context_final();
    log::info!("NSACF shutdown complete");

    Ok(())
}

/// Build a TS 29.500 ProblemDetails error response
fn problem_details(status: u16, title: &str, detail: &str, cause: Option<&str>) -> SbiResponse {
    let mut body = serde_json::json!({
        "type": "about:blank",
        "title": title,
        "status": status,
        "detail": detail,
    });
    if let Some(c) = cause {
        body["cause"] = serde_json::json!(c);
    }
    SbiResponse::with_status(status).with_body(body.to_string(), "application/problem+json")
}

/// NSACF SBI request handler
async fn nsacf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.clone();
    let method = method.as_str();
    let uri = request.header.uri.clone();

    log::debug!("NSACF SBI: {method} {uri}");

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(&uri);
    let parts: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    match parts.as_slice() {
        // ------------------------------------------------------------------
        // Nnsacf_NSAC admission control (TS 29.536 §6.1.3.2)
        //
        // S-NSSAI is carried in the request body (UeACRequestData /
        // PduSessionACRequestData), NOT in the URI path. Rejection is a 200
        // response with admittedFlag=false, not an HTTP 4xx.
        // ------------------------------------------------------------------
        ["nnsacf-nsac", "v1", "slices", "ues"] => match method {
            "POST" => handle_ue_ac_update(&request).await,
            _ => send_method_not_allowed(method, "slices/ues"),
        },
        ["nnsacf-nsac", "v1", "slices", "pdu-sessions"] => match method {
            "POST" => handle_pdu_ac_update(&request).await,
            _ => send_method_not_allowed(method, "slices/pdu-sessions"),
        },

        // ------------------------------------------------------------------
        // Quota provisioning (operator/admin API)
        // ------------------------------------------------------------------
        ["nnsacf-nsac", "v1", "slice-quotas"] => match method {
            "POST" => handle_slice_quota_create(&request).await,
            "GET" => handle_slice_quota_list().await,
            _ => send_method_not_allowed(method, "slice-quotas"),
        },
        ["nnsacf-nsac", "v1", "slice-quotas", quota_id] => match method {
            "GET" => handle_slice_quota_get(quota_id).await,
            "DELETE" => handle_slice_quota_delete(quota_id).await,
            _ => send_method_not_allowed(method, "slice-quotas/{id}"),
        },

        // Utilization reporting
        ["nnsacf-nsac", "v1", "utilization"] => match method {
            "GET" => handle_utilization_report().await,
            _ => send_method_not_allowed(method, "utilization"),
        },

        // ------------------------------------------------------------------
        // Nnsacf_SliceEventExposure (TS 29.536)
        // ------------------------------------------------------------------
        ["nnsacf-slice-ee", "v1", "subscriptions"] => match method {
            "POST" => handle_slice_ee_subscribe(&request).await,
            _ => send_method_not_allowed(method, "subscriptions"),
        },
        ["nnsacf-slice-ee", "v1", "subscriptions", sub_id] => match method {
            "DELETE" => handle_slice_ee_unsubscribe(sub_id).await,
            _ => send_method_not_allowed(method, "subscriptions/{subscriptionId}"),
        },

        _ => {
            log::debug!("Unknown path: {path}");
            problem_details(
                404,
                "Not Found",
                &format!("Resource not found: {path}"),
                None,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Admission control handlers (TS 29.536: rejection = 200 + admittedFlag=false)
// ---------------------------------------------------------------------------

/// Parsed common fields of a TS 29.536 admission-control request body.
///
/// `snssai` and `updateFlag` are mandatory; `nfId` identifies the requesting
/// consumer (AMF for UE admission, SMF for PDU-session admission).
struct AcRequestCommon {
    s_nssai: SNssai,
    update_flag: String,
    data: serde_json::Value,
}

/// Common request validation for the AC update operations (TS 29.536
/// UeACRequestData / PduSessionACRequestData). The S-NSSAI is read from the
/// request body's mandatory `snssai` attribute (not the URI path).
#[allow(clippy::result_large_err)] // SbiResponse is the natural error type here
fn parse_ac_request(request: &SbiRequest) -> Result<AcRequestCommon, SbiResponse> {
    let body = request.http.content.as_deref().ok_or_else(|| {
        problem_details(
            400,
            "Bad Request",
            "Missing mandatory request body",
            Some("MANDATORY_IE_MISSING"),
        )
    })?;

    let data: serde_json::Value = serde_json::from_str(body).map_err(|e| {
        problem_details(
            400,
            "Bad Request",
            &format!("Invalid JSON: {e}"),
            Some("INVALID_MSG_FORMAT"),
        )
    })?;

    let mut missing = Vec::new();
    // S-NSSAI is the mandatory `snssai` attribute of UeACRequestData /
    // PduSessionACRequestData (TS 29.536 §6.1.6.2.x). Accept both `snssai`
    // and the TS 29.571 camelCase `sNssai` spelling defensively.
    let snssai_json = data.get("snssai").or_else(|| data.get("sNssai"));
    let s_nssai = snssai_json.and_then(SNssai::from_json);
    if s_nssai.is_none() {
        missing.push("snssai");
    }
    let update_flag = data.get("updateFlag").and_then(|v| v.as_str());
    if update_flag.is_none() {
        missing.push("updateFlag");
    }
    // nfId is mandatory in TS 29.536 (the consumer NF instance id). Accept it
    // leniently to keep older callers working, but flag its absence.
    if data.get("nfId").and_then(|v| v.as_str()).is_none() {
        log::warn!("AC request without nfId (lenient)");
    }
    if !missing.is_empty() {
        return Err(problem_details(
            400,
            "Bad Request",
            &format!("Missing mandatory attribute(s): {}", missing.join(", ")),
            Some("MANDATORY_IE_MISSING"),
        ));
    }
    let update_flag = update_flag.expect("checked above");
    if update_flag != "INCREASE" && update_flag != "DECREASE" {
        return Err(problem_details(
            400,
            "Bad Request",
            &format!("Invalid updateFlag '{update_flag}' (expected INCREASE or DECREASE)"),
            Some("INVALID_IE_VALUE"),
        ));
    }

    Ok(AcRequestCommon {
        s_nssai: s_nssai.expect("checked above"),
        update_flag: update_flag.to_string(),
        data,
    })
}

/// Build a TS 29.536 UeACResponseData / PduSessionACResponseData body.
///
/// On rejection the response is still HTTP 200 with `admittedFlag=false`
/// (TS 29.536 §6.1.3.2), carrying the resource ceiling so the consumer can
/// surface it. `max_num` is the slice's configured `maxNumUEs` /
/// `maxNumPduSessions`.
fn admission_response(
    s_nssai: &SNssai,
    result: AdmissionResult,
    max_field: &str,
    max_num: Option<u64>,
) -> SbiResponse {
    let admitted = result == AdmissionResult::Admitted;
    let mut body = serde_json::json!({
        "snssai": s_nssai.to_json(),
        "admittedFlag": admitted,
    });
    if let Some(max) = max_num {
        body[max_field] = serde_json::json!(max);
    }
    if !admitted {
        let cause = match result {
            AdmissionResult::RejectedQuotaExceeded => "QUOTA_EXCEEDED",
            _ => "SLICE_NOT_AVAILABLE",
        };
        body["rejectCause"] = serde_json::json!(cause);
    }
    // TS 29.536: admission rejection is reported with 200 + admittedFlag=false,
    // NOT an HTTP error status.
    SbiResponse::with_status(200)
        .with_json_body(&body)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Resolve the membership key for a UE admission request. TS 29.536 counts
/// distinct UEs per slice; we key on `supi` when present (precise, idempotent),
/// otherwise on the consumer `nfId` plus a per-request token so counts stay
/// well-defined. Returns `None` when no usable identity is present.
fn ue_membership_key(data: &serde_json::Value) -> Option<String> {
    if let Some(supi) = data.get("supi").and_then(|v| v.as_str()) {
        return Some(supi.to_string());
    }
    // Fall back to the first updateList anchor identifier if provided.
    data.get("updateList")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|e| e.get("anchorOrPdu").or_else(|| e.get("ueId")))
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// POST /nnsacf-nsac/v1/slices/ues  (NumOfUEsUpdate, TS 29.536 §6.1.3.2)
async fn handle_ue_ac_update(request: &SbiRequest) -> SbiResponse {
    let common = match parse_ac_request(request) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let AcRequestCommon {
        s_nssai,
        update_flag,
        data,
    } = common;

    let Some(key) = ue_membership_key(&data) else {
        return problem_details(
            400,
            "Bad Request",
            "Missing UE identity (supi or updateList.anchorOrPdu)",
            Some("MANDATORY_IE_MISSING"),
        );
    };
    let max_num = with_nsacf_context(|c| c.quota_find_by_snssai(&s_nssai))
        .flatten()
        .map(|q| q.max_ues);

    match update_flag.as_str() {
        "INCREASE" => {
            let (result, eac) = with_nsacf_context(|c| c.admit_ue(&s_nssai, &key))
                .unwrap_or((AdmissionResult::RejectedSliceNotAvailable, None));
            match result {
                AdmissionResult::Admitted => log::info!(
                    "[{key}] admitted to S-NSSAI[SST:{} SD:{:?}]",
                    s_nssai.sst,
                    s_nssai.sd
                ),
                _ => log::warn!(
                    "[{key}] NOT admitted to S-NSSAI[SST:{} SD:{:?}]: {result:?}",
                    s_nssai.sst,
                    s_nssai.sd
                ),
            }
            if let Some(eac) = eac {
                spawn_eac_notifications(eac);
            }
            if result == AdmissionResult::Admitted {
                spawn_event_reports(&s_nssai);
            }
            admission_response(&s_nssai, result, "maxNumUEs", max_num)
        }
        _ => {
            // DECREASE: idempotent release, always acknowledged (admittedFlag=true)
            let eac = with_nsacf_context(|c| c.release_ue(&s_nssai, &key)).flatten();
            if let Some(eac) = eac {
                spawn_eac_notifications(eac);
            }
            spawn_event_reports(&s_nssai);
            admission_response(&s_nssai, AdmissionResult::Admitted, "maxNumUEs", max_num)
        }
    }
}

/// POST /nnsacf-nsac/v1/slices/pdu-sessions  (NumOfPDUsUpdate, TS 29.536 §6.1.3.2)
async fn handle_pdu_ac_update(request: &SbiRequest) -> SbiResponse {
    let common = match parse_ac_request(request) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let AcRequestCommon {
        s_nssai,
        update_flag,
        data,
    } = common;

    let pdu_session_id = match data.get("pduSessionId").and_then(|v| v.as_u64()) {
        Some(id) => id,
        None => {
            return problem_details(
                400,
                "Bad Request",
                "Missing mandatory attribute(s): pduSessionId",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };
    // Distinct PDU-session key: prefer supi when present so two UEs may reuse
    // the same pduSessionId; otherwise key on the consumer nfId.
    let owner = data
        .get("supi")
        .and_then(|v| v.as_str())
        .or_else(|| data.get("nfId").and_then(|v| v.as_str()))
        .unwrap_or("unknown");
    let session_key = format!("{owner}:{pdu_session_id}");
    let max_num = with_nsacf_context(|c| c.quota_find_by_snssai(&s_nssai))
        .flatten()
        .map(|q| q.max_pdu_sessions);

    match update_flag.as_str() {
        "INCREASE" => {
            let result = with_nsacf_context(|c| c.admit_pdu_session(&s_nssai, &session_key))
                .unwrap_or(AdmissionResult::RejectedSliceNotAvailable);
            if result == AdmissionResult::Admitted {
                spawn_event_reports(&s_nssai);
            }
            admission_response(&s_nssai, result, "maxNumPduSessions", max_num)
        }
        _ => {
            with_nsacf_context(|c| c.release_pdu_session(&s_nssai, &session_key));
            spawn_event_reports(&s_nssai);
            admission_response(
                &s_nssai,
                AdmissionResult::Admitted,
                "maxNumPduSessions",
                max_num,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Quota provisioning handlers
// ---------------------------------------------------------------------------

/// Handle Slice Quota Create
async fn handle_slice_quota_create(request: &SbiRequest) -> SbiResponse {
    log::info!("Slice Quota Create");

    let body = match &request.http.content {
        Some(content) => content,
        None => {
            return problem_details(
                400,
                "Bad Request",
                "Missing mandatory request body",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };

    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => {
            return problem_details(
                400,
                "Bad Request",
                &format!("Invalid JSON: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };

    let s_nssai = match data.get("sNssai").and_then(SNssai::from_json) {
        Some(s) => s,
        None => {
            return problem_details(
                400,
                "Bad Request",
                "Missing/invalid mandatory attribute sNssai",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };
    let max_ues = data.get("maxUes").and_then(|v| v.as_u64()).unwrap_or(10000);
    let max_pdu = data
        .get("maxPduSessions")
        .and_then(|v| v.as_u64())
        .unwrap_or(50000);

    let quota = with_nsacf_context(|c| c.quota_add(s_nssai.clone(), max_ues, max_pdu)).flatten();

    match quota {
        Some(quota) => {
            let quota_id = format!("quota-{}", quota.id);
            log::info!(
                "Slice quota created: {quota_id} (SST={} SD={:?} max_ues={max_ues} max_pdu={max_pdu})",
                s_nssai.sst,
                s_nssai.sd
            );

            SbiResponse::with_status(201)
                .with_header(
                    "Location",
                    format!("/nnsacf-nsac/v1/slice-quotas/{quota_id}"),
                )
                .with_json_body(&serde_json::json!({
                    "quotaId": quota_id,
                    "sNssai": s_nssai.to_json(),
                    "maxUes": max_ues,
                    "maxPduSessions": max_pdu,
                    "currentUes": 0,
                    "currentPduSessions": 0,
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        None => problem_details(
            400,
            "Bad Request",
            "Failed to create slice quota (limit reached?)",
            Some("CREATION_FAILED"),
        ),
    }
}

/// Handle Slice Quota List
async fn handle_slice_quota_list() -> SbiResponse {
    log::debug!("Slice Quota List");

    let utilization = with_nsacf_context(|c| c.get_utilization()).unwrap_or_default();

    let quotas: Vec<serde_json::Value> = utilization
        .iter()
        .map(|(snssai, ue_util, pdu_util)| {
            serde_json::json!({
                "sNssai": snssai.to_json(),
                "ueUtilization": ue_util,
                "pduUtilization": pdu_util,
            })
        })
        .collect();

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

    let quota = pool_id.and_then(|id| with_nsacf_context(|c| c.quota_find_by_id(id)).flatten());

    match quota {
        Some(quota) => SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({
                "quotaId": quota_id,
                "sNssai": quota.s_nssai.to_json(),
                "maxUes": quota.max_ues,
                "maxPduSessions": quota.max_pdu_sessions,
                "currentUes": quota.current_ues(),
                "currentPduSessions": quota.current_pdu_sessions(),
                "utilization": quota.ue_utilization(),
                "eacActive": quota.eac_active(),
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => problem_details(
            404,
            "Not Found",
            &format!("Slice quota {quota_id} not found"),
            Some("QUOTA_NOT_FOUND"),
        ),
    }
}

/// Handle Slice Quota Delete
async fn handle_slice_quota_delete(quota_id: &str) -> SbiResponse {
    log::info!("Slice Quota Delete: {quota_id}");

    let pool_id = quota_id
        .strip_prefix("quota-")
        .and_then(|s| s.parse::<u64>().ok());

    let pool_id = match pool_id {
        Some(id) => id,
        None => {
            return problem_details(
                404,
                "Not Found",
                &format!("Slice quota {quota_id} not found"),
                Some("QUOTA_NOT_FOUND"),
            )
        }
    };

    let removed = with_nsacf_context(|c| c.quota_remove(pool_id)).unwrap_or(false);

    if removed {
        SbiResponse::with_status(204)
    } else {
        problem_details(
            404,
            "Not Found",
            &format!("Slice quota {quota_id} not found"),
            Some("QUOTA_NOT_FOUND"),
        )
    }
}

/// Handle utilization report
async fn handle_utilization_report() -> SbiResponse {
    log::debug!("Utilization Report");

    let utilization = with_nsacf_context(|c| c.get_utilization()).unwrap_or_default();

    let entries: Vec<serde_json::Value> = utilization
        .iter()
        .map(|(snssai, ue_util, pdu_util)| {
            serde_json::json!({
                "sNssai": snssai.to_json(),
                "ueUtilization": ue_util,
                "pduUtilization": pdu_util,
            })
        })
        .collect();

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({"sliceUtilization": entries}))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

// ---------------------------------------------------------------------------
// SliceEventExposure subscriptions + notifications
// ---------------------------------------------------------------------------

/// POST /nnsacf-slice-ee/v1/subscriptions
async fn handle_slice_ee_subscribe(request: &SbiRequest) -> SbiResponse {
    log::info!("SliceEventExposure Subscribe");

    let body = match &request.http.content {
        Some(content) => content,
        None => {
            return problem_details(
                400,
                "Bad Request",
                "Missing mandatory request body",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => {
            return problem_details(
                400,
                "Bad Request",
                &format!("Invalid JSON: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };

    let mut missing = Vec::new();
    let notification_uri = data.get("notificationUri").and_then(|v| v.as_str());
    if notification_uri.is_none() {
        missing.push("notificationUri");
    }
    let events = data.get("events").and_then(|v| v.as_array());
    if events.map(|e| e.is_empty()).unwrap_or(true) {
        missing.push("events");
    }
    if !missing.is_empty() {
        return problem_details(
            400,
            "Bad Request",
            &format!("Missing mandatory attribute(s): {}", missing.join(", ")),
            Some("MANDATORY_IE_MISSING"),
        );
    }

    let events: Vec<String> = events
        .expect("checked above")
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    let snssais: Vec<SNssai> = data
        .get("snssais")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(SNssai::from_json).collect())
        .unwrap_or_default();

    let subscription_id = uuid::Uuid::new_v4().to_string();
    let sub = SacSubscription {
        subscription_id: subscription_id.clone(),
        notification_uri: notification_uri.expect("checked above").to_string(),
        events: events.clone(),
        snssais,
        expiry: data
            .get("expiry")
            .and_then(|v| v.as_str())
            .map(String::from),
    };
    with_nsacf_context(|c| c.subscription_add(sub));

    log::info!("SliceEventExposure subscription created: {subscription_id}");

    SbiResponse::with_status(201)
        .with_header(
            "Location",
            format!("/nnsacf-slice-ee/v1/subscriptions/{subscription_id}"),
        )
        .with_json_body(&serde_json::json!({
            "subscriptionId": subscription_id,
            "notificationUri": data.get("notificationUri"),
            "events": events,
            "expiry": data.get("expiry"),
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// DELETE /nnsacf-slice-ee/v1/subscriptions/{subscriptionId}
async fn handle_slice_ee_unsubscribe(subscription_id: &str) -> SbiResponse {
    log::info!("SliceEventExposure Unsubscribe: {subscription_id}");

    let removed = with_nsacf_context(|c| c.subscription_remove(subscription_id)).unwrap_or(false);

    if removed {
        SbiResponse::with_status(204)
    } else {
        problem_details(
            404,
            "Not Found",
            &format!("Subscription {subscription_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        )
    }
}

/// Split an absolute URI into (host, port, path)
fn split_uri(uri: &str) -> Option<(String, u16, String)> {
    let (default_port, rest) = if let Some(r) = uri.strip_prefix("https://") {
        (443u16, r)
    } else if let Some(r) = uri.strip_prefix("http://") {
        (80u16, r)
    } else {
        (80u16, uri)
    };
    let (host_port, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        Some((host.to_string(), port_str.parse().ok()?, path))
    } else {
        Some((host_port.to_string(), default_port, path))
    }
}

/// POST one notification body to a subscriber with bounded timeouts.
async fn deliver_notification(notification_uri: String, body: serde_json::Value) {
    let Some((host, port, path)) = split_uri(&notification_uri) else {
        log::warn!("Invalid notificationUri '{notification_uri}'");
        return;
    };
    let client = SbiClient::new(
        SbiClientConfig::new(host, port)
            .with_connect_timeout(NOTIFY_CONNECT_TIMEOUT)
            .with_request_timeout(NOTIFY_REQUEST_TIMEOUT),
    );
    // Slice-event-exposure notifications are consumed by AMFs; attach an
    // NRF-issued token when OAuth2 enforcement is on (no-op otherwise).
    let client = attach_oauth2(client, NfType::Amf);
    match client.post_json(&path, &body).await {
        Ok(resp) if resp.status == 204 || resp.is_success() => {
            log::debug!("Notification delivered to {notification_uri}");
        }
        Ok(resp) => {
            log::warn!(
                "Notification to {notification_uri} returned {}",
                resp.status
            );
        }
        Err(e) => {
            log::warn!("Notification to {notification_uri} failed: {e}");
        }
    }
    client.close().await;
}

/// Fire EAC (early admission control) mode notifications to all subscribers
/// interested in the slice (TS 23.502 §4.2.9.5).
fn spawn_eac_notifications(eac: EacTransition) {
    let subs = with_nsacf_context(|c| c.subscriptions_matching(&eac.s_nssai)).unwrap_or_default();
    if subs.is_empty() {
        return;
    }
    let mode = if eac.activated {
        "EAC_ACTIVE"
    } else {
        "EAC_INACTIVE"
    };
    log::info!(
        "EAC mode {} for S-NSSAI[SST:{} SD:{:?}] -> notifying {} subscriber(s)",
        mode,
        eac.s_nssai.sst,
        eac.s_nssai.sd,
        subs.len()
    );
    for sub in subs {
        let body = serde_json::json!({
            "subscriptionId": sub.subscription_id,
            "eacNotification": {
                "snssai": eac.s_nssai.to_json(),
                "eacMode": mode,
            }
        });
        tokio::spawn(deliver_notification(sub.notification_uri, body));
    }
}

/// Fire slice event reports (current counts) to subscribers whose events
/// include UE/PDU count updates.
fn spawn_event_reports(s_nssai: &SNssai) {
    let snapshot = with_nsacf_context(|c| {
        (
            c.subscriptions_matching(s_nssai),
            c.quota_find_by_snssai(s_nssai),
        )
    });
    let Some((subs, Some(quota))) = snapshot else {
        return;
    };
    for sub in subs {
        let wants_counts = sub
            .events
            .iter()
            .any(|e| e == "NUM_OF_REGISTERED_UES" || e == "NUM_OF_ESTABLISHED_PDU_SESSIONS");
        if !wants_counts {
            continue;
        }
        let body = serde_json::json!({
            "subscriptionId": sub.subscription_id,
            "eventReports": [{
                "snssai": quota.s_nssai.to_json(),
                "nbrRegisteredUes": quota.current_ues(),
                "nbrEstablishedPduSessions": quota.current_pdu_sessions(),
            }]
        });
        tokio::spawn(deliver_notification(sub.notification_uri, body));
    }
}

// ---------------------------------------------------------------------------
// NRF interaction
// ---------------------------------------------------------------------------

/// Register NSACF with NRF
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

    log::info!("Registering NSACF with NRF at {nrf_uri}");

    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_profile = serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "NSACF",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [{
            "serviceInstanceId": format!("{}-nnsacf-nsac", nf_instance_id),
            "serviceName": "nnsacf-nsac",
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.1.0"}],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
        }, {
            "serviceInstanceId": format!("{}-nnsacf-slice-ee", nf_instance_id),
            "serviceName": "nnsacf-slice-ee",
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.1.0"}],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
        }],
        "allowedNfTypes": ["AMF", "SMF", "SCP", "NEF", "NWDAF"],
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
            log::info!("NSACF registered with NRF successfully (id={nf_instance_id})");

            let mut self_instance =
                ogs_sbi::context::NfInstance::new(nf_instance_id, ogs_sbi::types::NfType::Nsacf);
            self_instance.ipv4_addresses = vec![sbi_addr.to_string()];
            let mut svc = ogs_sbi::context::NfService::new(
                "nnsacf-nsac",
                ogs_sbi::types::SbiServiceType::NnsacfNsac,
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
    use ogs_sbi::client::SbiClient;
    use ogs_sbi::server::{SbiServer, SbiServerConfig};
    use serde_json::json;

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-nsacfd"]);
        assert_eq!(args.config, "/etc/nextgcore/nsacf.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.sbi_port, 7813);
        assert_eq!(args.max_quotas, 64);
        assert_eq!(args.eac_threshold, 80);
        assert!(args.state_file.is_none());
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-nsacfd",
            "--sbi-port",
            "8813",
            "--max-quotas",
            "128",
            "--nrf-uri",
            "http://nrf:7777",
            "--state-file",
            "/var/lib/nextgcore/nsacf-state.json",
            "--eac-threshold",
            "90",
        ]);
        assert_eq!(args.sbi_port, 8813);
        assert_eq!(args.max_quotas, 128);
        assert_eq!(args.nrf_uri, "http://nrf:7777");
        assert_eq!(
            args.state_file.as_deref(),
            Some("/var/lib/nextgcore/nsacf-state.json")
        );
        assert_eq!(args.eac_threshold, 90);
    }

    // -----------------------------------------------------------------
    // HTTP-level tests (ephemeral ports, bounded timeouts)
    // -----------------------------------------------------------------

    fn free_port() -> u16 {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let port = probe.local_addr().expect("local addr").port();
        drop(probe);
        port
    }

    async fn start_nsacf_server() -> (SbiServer, u16) {
        nsacf_context_init(64);
        let port = free_port();
        let server = SbiServer::new(SbiServerConfig::new(SocketAddr::from((
            [127, 0, 0, 1],
            port,
        ))));
        server
            .start(nsacf_sbi_request_handler)
            .await
            .expect("server start");
        (server, port)
    }

    // -----------------------------------------------------------------
    // OAuth2 enforcement (T1.1): server-side require_oauth2 + aud check
    // -----------------------------------------------------------------

    /// Mint an ES256 access token (matching the NRF's token shape) with the
    /// given `aud`, signed by `sk` and tagged with `kid`.
    fn build_es256_token(sk: &p256::ecdsa::SigningKey, kid: &str, aud: &str) -> String {
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
            "iss": "NRF", "sub": "amf-1", "aud": aud,
            "scope": "nnsacf-nsac", "exp": exp, "iat": 0
        })
        .to_string();
        let h = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let p = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let sig: Signature = sk.sign(format!("{h}.{p}").as_bytes());
        let s = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{h}.{p}.{s}")
    }

    /// Public JWKS for the signing key `sk` under `kid`.
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

    /// Start an NSACF SBI server with OAuth2 enforcement keyed to a static
    /// JWKS and the NSACF audience.
    async fn start_nsacf_server_oauth2(jwks: serde_json::Value) -> (SbiServer, u16) {
        nsacf_context_init(64);
        let port = free_port();
        let mut cfg = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(jwks);
        cfg = cfg.with_expected_audience_nf_type(NfType::Nsacf);
        let server = SbiServer::new(cfg);
        server
            .start(nsacf_sbi_request_handler)
            .await
            .expect("server start");
        (server, port)
    }

    #[test]
    fn test_yaml_oauth2_require_parses() {
        let yaml = "nsacf:\n  sbi:\n    oauth2:\n      require: true\n  nrf:\n    uri: http://nrf:7777\n";
        let parsed: NsacfYaml = serde_yaml::from_str(yaml).unwrap();
        let nsacf = parsed.nsacf.unwrap();
        let require = nsacf
            .sbi
            .and_then(|s| s.oauth2)
            .and_then(|o| o.require)
            .unwrap_or(false);
        assert!(require, "oauth2.require should parse to true");
        assert_eq!(
            nsacf.nrf.and_then(|n| n.uri).as_deref(),
            Some("http://nrf:7777")
        );
    }

    #[test]
    fn test_yaml_oauth2_absent_defaults_off() {
        let yaml = "nsacf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: 7813\n";
        let parsed: NsacfYaml = serde_yaml::from_str(yaml).unwrap();
        let require = parsed
            .nsacf
            .and_then(|n| n.sbi)
            .and_then(|s| s.oauth2)
            .and_then(|o| o.require)
            .unwrap_or(false);
        assert!(!require, "absent oauth2 block must default to off");
    }

    #[tokio::test]
    async fn test_oauth2_missing_token_rejected() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let (server, port) = start_nsacf_server_oauth2(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            client.get("/nnsacf-nsac/v1/slice-quotas"),
        )
        .await
        .expect("bounded")
        .expect("response");
        assert_eq!(resp.status, 401, "unauthenticated request must be 401");

        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_oauth2_valid_token_accepted() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let (server, port) = start_nsacf_server_oauth2(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        // Valid token whose aud includes "NSACF" reaches the handler: the
        // slice-quota list is served (200), NOT 401/403.
        let token = build_es256_token(&sk, "nrf-es256", "NSACF");
        let req = SbiRequest::get("/nnsacf-nsac/v1/slice-quotas")
            .with_header("Authorization", format!("Bearer {token}"));
        let resp = tokio::time::timeout(Duration::from_secs(5), client.send_request(req))
            .await
            .expect("bounded")
            .expect("response");
        assert_eq!(resp.status, 200, "valid token reaches handler (200)");

        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_oauth2_wrong_audience_rejected() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let (server, port) = start_nsacf_server_oauth2(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        // Token addressed to a different NF (aud="UDM") is rejected (401).
        let token = build_es256_token(&sk, "nrf-es256", "UDM");
        let req = SbiRequest::get("/nnsacf-nsac/v1/slice-quotas")
            .with_header("Authorization", format!("Bearer {token}"));
        let resp = tokio::time::timeout(Duration::from_secs(5), client.send_request(req))
            .await
            .expect("bounded")
            .expect("response");
        assert_eq!(resp.status, 401, "wrong-audience token must be 401");

        server.stop().await.expect("stop");
    }

    async fn create_quota(client: &SbiClient, sst: u8, max_ues: u64, max_pdu: u64) {
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slice-quotas",
                &json!({"sNssai": {"sst": sst}, "maxUes": max_ues, "maxPduSessions": max_pdu}),
            )
            .await
            .expect("quota create");
        assert_eq!(resp.status, 201);
    }

    #[tokio::test]
    async fn test_http_ue_admission_lifecycle() {
        let (server, port) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        create_quota(&client, 71, 2, 100).await;

        // S-NSSAI is carried in the body (TS 29.536 UeACRequestData), not the URI.
        let post_ue = |supi: &str, flag: &str| {
            let body = json!({
                "snssai": {"sst": 71},
                "updateFlag": flag,
                "supi": supi,
                "nfId": "amf-1"
            });
            let client = SbiClient::with_host_port("127.0.0.1", port);
            async move {
                client
                    .post_json("/nnsacf-nsac/v1/slices/ues", &body)
                    .await
                    .expect("response")
            }
        };

        // INCREASE within quota -> admittedFlag=true, echoes snssai + maxNumUEs
        let resp = post_ue("imsi-71-1", "INCREASE").await;
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["admittedFlag"], true);
        assert_eq!(body["snssai"]["sst"], 71);
        assert_eq!(body["maxNumUEs"], 2);

        // Idempotent INCREASE for same SUPI
        let resp = post_ue("imsi-71-1", "INCREASE").await;
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["admittedFlag"], true);

        let _ = post_ue("imsi-71-2", "INCREASE").await;

        // Quota full -> 200 with admittedFlag=false (NOT 403)
        let resp = post_ue("imsi-71-3", "INCREASE").await;
        assert_eq!(resp.status, 200, "rejection must be 200, not an HTTP error");
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["admittedFlag"], false);
        assert_eq!(body["rejectCause"], "QUOTA_EXCEEDED");
        assert_eq!(body["maxNumUEs"], 2);

        // DECREASE then INCREASE succeeds again (decrease frees capacity)
        let resp = post_ue("imsi-71-2", "DECREASE").await;
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["admittedFlag"], true, "DECREASE is always acknowledged");
        let resp = post_ue("imsi-71-3", "INCREASE").await;
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["admittedFlag"], true);

        // Unknown slice -> 200 admittedFlag=false SLICE_NOT_AVAILABLE
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"snssai": {"sst": 99}, "updateFlag": "INCREASE", "supi": "imsi-x", "nfId": "amf-1"}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["admittedFlag"], false);
        assert_eq!(body["rejectCause"], "SLICE_NOT_AVAILABLE");

        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_http_ue_ac_missing_mandatory() {
        let (server, port) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        // Missing snssai -> 400 ProblemDetails
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"updateFlag": "INCREASE", "supi": "imsi-1", "nfId": "amf-1"}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 400);
        let body = resp.http.content.as_deref().unwrap();
        assert!(body.contains("snssai"));
        assert!(body.contains("MANDATORY_IE_MISSING"));

        // Missing UE identity (no supi / updateList) -> 400
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"snssai": {"sst": 72}, "updateFlag": "INCREASE", "nfId": "amf-1"}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 400);
        assert!(resp
            .http
            .content
            .as_deref()
            .unwrap()
            .contains("MANDATORY_IE_MISSING"));

        // Invalid updateFlag -> 400
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"snssai": {"sst": 72}, "updateFlag": "BOGUS", "supi": "imsi-1", "nfId": "amf-1"}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 400);
        assert!(resp
            .http
            .content
            .as_deref()
            .unwrap()
            .contains("INVALID_IE_VALUE"));

        // Invalid snssai value (sst > 255) -> 400
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"snssai": {"sst": 9999}, "updateFlag": "INCREASE", "supi": "imsi-1", "nfId": "amf-1"}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 400);

        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_http_pdu_session_admission() {
        let (server, port) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        create_quota(&client, 73, 100, 1).await;

        // Missing pduSessionId -> 400
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/pdu-sessions",
                &json!({"snssai": {"sst": 73}, "updateFlag": "INCREASE", "supi": "imsi-73-1", "nfId": "smf-1"}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 400);
        assert!(resp
            .http
            .content
            .as_deref()
            .unwrap()
            .contains("pduSessionId"));

        // INCREASE within quota -> echoes snssai + maxNumPduSessions
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/pdu-sessions",
                &json!({"snssai": {"sst": 73}, "updateFlag": "INCREASE", "supi": "imsi-73-1", "nfId": "smf-1", "pduSessionId": 1}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["admittedFlag"], true);
        assert_eq!(body["snssai"]["sst"], 73);
        assert_eq!(body["maxNumPduSessions"], 1);

        // Quota full -> 200 admittedFlag=false
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/pdu-sessions",
                &json!({"snssai": {"sst": 73}, "updateFlag": "INCREASE", "supi": "imsi-73-2", "nfId": "smf-1", "pduSessionId": 5}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["admittedFlag"], false);

        // DECREASE frees the slot
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/pdu-sessions",
                &json!({"snssai": {"sst": 73}, "updateFlag": "DECREASE", "supi": "imsi-73-1", "nfId": "smf-1", "pduSessionId": 1}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 200);
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/pdu-sessions",
                &json!({"snssai": {"sst": 73}, "updateFlag": "INCREASE", "supi": "imsi-73-2", "nfId": "smf-1", "pduSessionId": 5}),
            )
            .await
            .expect("response");
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["admittedFlag"], true);

        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_http_slice_ee_subscription_and_eac_notification() {
        let (server, port) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        // Notification receiver
        let recv_port = free_port();
        let receiver = SbiServer::new(SbiServerConfig::new(SocketAddr::from((
            [127, 0, 0, 1],
            recv_port,
        ))));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        receiver
            .start(move |req: SbiRequest| {
                let tx = tx.clone();
                async move {
                    let _ = tx.send(req.http.content.unwrap_or_default());
                    SbiResponse::with_status(204)
                }
            })
            .await
            .expect("receiver start");

        // Missing mandatory events -> 400
        let resp = client
            .post_json(
                "/nnsacf-slice-ee/v1/subscriptions",
                &json!({"notificationUri": format!("http://127.0.0.1:{recv_port}/cb")}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 400);
        assert!(resp.http.content.as_deref().unwrap().contains("events"));

        // Valid subscription for slice 74
        let resp = client
            .post_json(
                "/nnsacf-slice-ee/v1/subscriptions",
                &json!({
                    "notificationUri": format!("http://127.0.0.1:{recv_port}/cb"),
                    "events": ["NUM_OF_REGISTERED_UES"],
                    "snssais": [{"sst": 74}]
                }),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 201);
        let created: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let sub_id = created["subscriptionId"].as_str().unwrap().to_string();
        let location = resp
            .http
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("location"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        assert!(location.contains(&sub_id));

        // Quota of 5 with default EAC threshold 80% -> 4th admission activates EAC
        create_quota(&client, 74, 5, 100).await;
        for i in 1..=4 {
            let resp = client
                .post_json(
                    "/nnsacf-nsac/v1/slices/ues",
                    &json!({"snssai": {"sst": 74}, "updateFlag": "INCREASE", "supi": format!("imsi-74-{i}"), "nfId": "amf-1"}),
                )
                .await
                .expect("response");
            assert_eq!(resp.status, 200);
        }

        // Expect at least one EAC_ACTIVE notification (count reports may
        // arrive first; scan until found, bounded by timeout per recv)
        let mut saw_eac_active = false;
        for _ in 0..8 {
            let Ok(Some(notif)) = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await
            else {
                break;
            };
            if notif.contains("EAC_ACTIVE") {
                let v: serde_json::Value = serde_json::from_str(&notif).unwrap();
                assert_eq!(v["eacNotification"]["snssai"]["sst"], 74);
                saw_eac_active = true;
                break;
            }
        }
        assert!(saw_eac_active, "expected EAC_ACTIVE notification");

        // Release below threshold -> EAC_INACTIVE notification
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"snssai": {"sst": 74}, "updateFlag": "DECREASE", "supi": "imsi-74-4", "nfId": "amf-1"}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 200);

        let mut saw_eac_inactive = false;
        for _ in 0..8 {
            let Ok(Some(notif)) = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await
            else {
                break;
            };
            if notif.contains("EAC_INACTIVE") {
                saw_eac_inactive = true;
                break;
            }
        }
        assert!(saw_eac_inactive, "expected EAC_INACTIVE notification");

        // Unsubscribe -> 204, repeat -> 404
        let resp = client
            .delete(&format!("/nnsacf-slice-ee/v1/subscriptions/{sub_id}"))
            .await
            .expect("response");
        assert_eq!(resp.status, 204);
        let resp = client
            .delete(&format!("/nnsacf-slice-ee/v1/subscriptions/{sub_id}"))
            .await
            .expect("response");
        assert_eq!(resp.status, 404);

        server.stop().await.expect("stop");
        receiver.stop().await.expect("stop receiver");
    }
}
