//! NextGCore NSACF (Network Slice Admission Control Function)
//!
//! The NSACF is a 5G core network function responsible for (TS 23.502 4.2.9,
//! TS 29.536):
//! - Slice-level admission control for UE registrations
//!   (Nnsacf_NSAC NumOfUEsUpdate: `/nnsacf-nsac/v1/slices/ues`)
//! - Slice-level admission control for PDU session establishment
//!   (Nnsacf_NSAC NumOfPDUsUpdate: `/nnsacf-nsac/v1/slices/pdus`)
//! - Slice event exposure subscriptions + notifications
//!   (Nnsacf_SliceEventExposure: `/nnsacf-slice-ee/v1/subscriptions`)
//! - Early Admission Control (EAC) mode notifications (TS 23.502 §4.2.9.5)
//!
//! Per TS 29.536 §6.1.3.2.3.1 the admission RESULT is carried by the HTTP
//! status: **204** = all requested S-NSSAIs admitted, **200** +
//! `UeACResponseData.acuFailureList` (a map keyed by SUPI) = partial failure,
//! **403** ProblemDetails = total failure. There is no `admittedFlag` in the
//! spec.
//!
//! NOTE: the vendored OpenAPI sets (r16/r17) do not include
//! TS29536_Nnsacf_*.yaml; field names mirror TS 29.536 terminology.

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
        // Nnsacf_NSAC admission control (TS 29.536 §6.1.3.2 / §6.1.3.3)
        //
        // S-NSSAIs are carried nested in the request body (UeACRequestData /
        // PduACRequestData), NOT in the URI. The admission result is the HTTP
        // status: 204 all-admitted, 200 + acuFailureList partial, 403 total.
        // The PDU resource URI is `/slices/pdus` (TS 29.536 Table 6.1.3.1-1).
        // ------------------------------------------------------------------
        ["nnsacf-nsac", "v1", "slices", "ues"] => match method {
            "POST" => handle_ue_ac_update(&request).await,
            _ => send_method_not_allowed(method, "slices/ues"),
        },
        ["nnsacf-nsac", "v1", "slices", "pdus"] => match method {
            "POST" => handle_pdu_ac_update(&request).await,
            _ => send_method_not_allowed(method, "slices/pdus"),
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
// Admission control (TS 29.536 §6.1.3.2/§6.1.3.3): nested request bodies +
// the 204 / 200-acuFailureList / 403 response scheme.
// ---------------------------------------------------------------------------

/// Deserialization shim that parses a TS 29.571 S-NSSAI via [`SNssai::from_json`]
/// (rejecting out-of-range `sst`) so the nested request structs validate it.
struct SNssaiShim(SNssai);

impl<'de> Deserialize<'de> for SNssaiShim {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = serde_json::Value::deserialize(deserializer)?;
        SNssai::from_json(&v)
            .map(SNssaiShim)
            .ok_or_else(|| serde::de::Error::custom("invalid snssai"))
    }
}

/// AcuOperationItem (TS 29.536 §6.1.6.2.5): one (`updateFlag`, `snssai`) op.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcuOperationItem {
    update_flag: String,
    snssai: SNssaiShim,
}

/// UeACRequestInfo (TS 29.536 §6.1.6.2.9): a SUPI + its operation list.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UeACRequestInfo {
    supi: String,
    /// TS 29.571 AccessType; per-access-type counting is nsacf-05 (deferred),
    /// so it is parsed/logged only.
    #[serde(default)]
    an_type: Option<String>,
    acu_operation_list: Vec<AcuOperationItem>,
}

/// UeACRequestData (TS 29.536 §6.1.6.2.2). `nfId` (mandatory in the spec) is
/// accepted leniently — strict enforcement is nsacf-09 (deferred) — so serde
/// ignores it here.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UeACRequestData {
    // serde's camelCase would render `ue_ac_request_info` as `ueAcRequestInfo`,
    // but the TS 29.536 attribute keeps the "AC" acronym uppercase: rename
    // explicitly so a conformant AMF body deserializes.
    #[serde(rename = "ueACRequestInfo")]
    ue_ac_request_info: Vec<UeACRequestInfo>,
}

/// PduACRequestInfo (TS 29.536 §6.1.6.2.10): SUPI + pduSessionId + ops.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PduACRequestInfo {
    supi: String,
    #[serde(default)]
    an_type: Option<String>,
    pdu_session_id: u64,
    acu_operation_list: Vec<AcuOperationItem>,
}

/// PduACRequestData (TS 29.536 §6.1.6.2.7).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PduACRequestData {
    // Same "AC" acronym caveat as UeACRequestData: TS 29.536 uses
    // `pduACRequestInfo`, not serde's default `pduAcRequestInfo`.
    #[serde(rename = "pduACRequestInfo")]
    pdu_ac_request_info: Vec<PduACRequestInfo>,
}

/// AcuFailureReason (TS 29.536 §6.1.6.3.5). The `_3GPP`/`_N3GPP` per-access
/// variants are nsacf-05 (deferred); this chunk emits the aggregate strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcuFailureReason {
    SliceNotFound,
    ExceedMaxUeNum,
    ExceedMaxPduNum,
}

impl AcuFailureReason {
    fn as_str(self) -> &'static str {
        match self {
            AcuFailureReason::SliceNotFound => "SLICE_NOT_FOUND",
            AcuFailureReason::ExceedMaxUeNum => "EXCEED_MAX_UE_NUM",
            AcuFailureReason::ExceedMaxPduNum => "EXCEED_MAX_PDU_NUM",
        }
    }
}

/// A per-(SUPI, S-NSSAI) admission failure aggregated into the AC response.
struct AcFailure {
    supi: String,
    /// AcuFailureItem (TS 29.536 §6.1.6.2.6): `{snssai, reason, pduSessionId?}`.
    item: serde_json::Value,
}

impl AcFailure {
    fn new(supi: &str, s_nssai: &SNssai, reason: AcuFailureReason, pdu_session_id: Option<u64>) -> Self {
        let mut item = serde_json::json!({
            "snssai": s_nssai.to_json(),
            "reason": reason.as_str(),
        });
        if let Some(psi) = pdu_session_id {
            item["pduSessionId"] = serde_json::json!(psi);
        }
        AcFailure {
            supi: supi.to_string(),
            item,
        }
    }
}

/// Map an internal [`AdmissionResult`] rejection to its spec failure reason
/// (TS 29.536 §6.1.6.3.5). `is_pdu` selects EXCEED_MAX_PDU_NUM vs _UE_NUM.
fn rejection_reason(result: AdmissionResult, is_pdu: bool) -> AcuFailureReason {
    match result {
        AdmissionResult::RejectedQuotaExceeded if is_pdu => AcuFailureReason::ExceedMaxPduNum,
        AdmissionResult::RejectedQuotaExceeded => AcuFailureReason::ExceedMaxUeNum,
        // Slice not NSAC-subject / unknown.
        _ => AcuFailureReason::SliceNotFound,
    }
}

/// Build the TS 29.536 §6.1.3.2.3.1 admission response from the aggregated
/// per-op results:
/// - **204** No Content when every requested op was admitted;
/// - **403** ProblemDetails when *every* op failed (total failure) — cause
///   `SLICE_NOT_FOUND` when all are slice-not-found, else `ALL_SLICE_FAILED`;
/// - **200** `UeACResponseData`/`PduACResponseData` with `acuFailureList`
///   (a map keyed by SUPI) otherwise (partial failure).
fn build_ac_response(failures: Vec<AcFailure>, total_ops: usize) -> SbiResponse {
    if failures.is_empty() {
        // All requested S-NSSAIs admitted.
        return SbiResponse::with_status(204);
    }
    if failures.len() >= total_ops {
        // Total failure: every requested op failed.
        let all_slice_not_found = failures
            .iter()
            .all(|f| f.item.get("reason").and_then(|r| r.as_str()) == Some("SLICE_NOT_FOUND"));
        let cause = if all_slice_not_found {
            "SLICE_NOT_FOUND"
        } else {
            "ALL_SLICE_FAILED"
        };
        return problem_details(
            403,
            "Forbidden",
            "Network slice admission control rejected all requested S-NSSAIs",
            Some(cause),
        );
    }
    // Partial failure: 200 + acuFailureList keyed by SUPI.
    let mut acu_failure_list = serde_json::Map::new();
    for f in failures {
        acu_failure_list
            .entry(f.supi)
            .or_insert_with(|| serde_json::Value::Array(Vec::new()))
            .as_array_mut()
            .expect("array")
            .push(f.item);
    }
    let body = serde_json::json!({ "acuFailureList": acu_failure_list });
    SbiResponse::with_status(200)
        .with_json_body(&body)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Validate every op's `updateFlag` (INCREASE/DECREASE; UPDATE is nsacf-06,
/// deferred → INVALID_IE_VALUE) before any state mutation.
#[allow(clippy::result_large_err)] // SbiResponse is the natural error type here
fn validate_flags<'a>(ops: impl Iterator<Item = &'a AcuOperationItem>) -> Result<(), SbiResponse> {
    for op in ops {
        if op.update_flag != "INCREASE" && op.update_flag != "DECREASE" {
            return Err(problem_details(
                400,
                "Bad Request",
                &format!(
                    "Invalid updateFlag '{}' (expected INCREASE or DECREASE)",
                    op.update_flag
                ),
                Some("INVALID_IE_VALUE"),
            ));
        }
    }
    Ok(())
}

/// Parse a request body of type `T` (UeACRequestData / PduACRequestData),
/// mapping a missing mandatory field to `MANDATORY_IE_MISSING` and any other
/// shape/value error to `INVALID_MSG_FORMAT`.
#[allow(clippy::result_large_err)] // SbiResponse is the natural error type here
fn parse_request_body<T: for<'de> Deserialize<'de>>(
    request: &SbiRequest,
) -> Result<T, SbiResponse> {
    let body = request.http.content.as_deref().ok_or_else(|| {
        problem_details(
            400,
            "Bad Request",
            "Missing mandatory request body",
            Some("MANDATORY_IE_MISSING"),
        )
    })?;
    serde_json::from_str::<T>(body).map_err(|e| {
        let msg = e.to_string();
        let cause = if msg.contains("missing field") {
            "MANDATORY_IE_MISSING"
        } else {
            "INVALID_MSG_FORMAT"
        };
        problem_details(400, "Bad Request", &format!("Invalid request body: {msg}"), Some(cause))
    })
}

/// POST /nnsacf-nsac/v1/slices/ues  (NumOfUEsUpdate, TS 29.536 §6.1.3.2)
async fn handle_ue_ac_update(request: &SbiRequest) -> SbiResponse {
    let req: UeACRequestData = match parse_request_body(request) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if req.ue_ac_request_info.is_empty() {
        return problem_details(
            400,
            "Bad Request",
            "Missing mandatory attribute: ueACRequestInfo",
            Some("MANDATORY_IE_MISSING"),
        );
    }
    for info in &req.ue_ac_request_info {
        if info.acu_operation_list.is_empty() {
            return problem_details(
                400,
                "Bad Request",
                "Missing mandatory attribute: acuOperationList",
                Some("MANDATORY_IE_MISSING"),
            );
        }
        if let Err(resp) = validate_flags(info.acu_operation_list.iter()) {
            return resp;
        }
    }

    let mut failures: Vec<AcFailure> = Vec::new();
    let mut total_ops = 0usize;
    for info in &req.ue_ac_request_info {
        for op in &info.acu_operation_list {
            total_ops += 1;
            let s_nssai = &op.snssai.0;
            log::debug!(
                "[{}] UE AC {} S-NSSAI[SST:{} SD:{:?}] anType={:?}",
                info.supi,
                op.update_flag,
                s_nssai.sst,
                s_nssai.sd,
                info.an_type
            );
            if op.update_flag == "INCREASE" {
                let (result, eac) = with_nsacf_context(|c| c.admit_ue(s_nssai, &info.supi))
                    .unwrap_or((AdmissionResult::RejectedSliceNotAvailable, None));
                match result {
                    AdmissionResult::Admitted => {
                        if let Some(eac) = eac {
                            spawn_eac_notifications(eac);
                        }
                        spawn_event_reports(s_nssai);
                    }
                    rejected => failures.push(AcFailure::new(
                        &info.supi,
                        s_nssai,
                        rejection_reason(rejected, false),
                        None,
                    )),
                }
            } else {
                // DECREASE: idempotent release (nsacf-10 membership distinction
                // is deferred; a release is always acknowledged → counts toward
                // an admitted op).
                let eac = with_nsacf_context(|c| c.release_ue(s_nssai, &info.supi)).flatten();
                if let Some(eac) = eac {
                    spawn_eac_notifications(eac);
                }
                spawn_event_reports(s_nssai);
            }
        }
    }
    build_ac_response(failures, total_ops)
}

/// POST /nnsacf-nsac/v1/slices/pdus  (NumOfPDUsUpdate, TS 29.536 §6.1.3.3)
async fn handle_pdu_ac_update(request: &SbiRequest) -> SbiResponse {
    let req: PduACRequestData = match parse_request_body(request) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if req.pdu_ac_request_info.is_empty() {
        return problem_details(
            400,
            "Bad Request",
            "Missing mandatory attribute: pduACRequestInfo",
            Some("MANDATORY_IE_MISSING"),
        );
    }
    for info in &req.pdu_ac_request_info {
        if info.acu_operation_list.is_empty() {
            return problem_details(
                400,
                "Bad Request",
                "Missing mandatory attribute: acuOperationList",
                Some("MANDATORY_IE_MISSING"),
            );
        }
        if let Err(resp) = validate_flags(info.acu_operation_list.iter()) {
            return resp;
        }
    }

    let mut failures: Vec<AcFailure> = Vec::new();
    let mut total_ops = 0usize;
    for info in &req.pdu_ac_request_info {
        let session_key = format!("{}:{}", info.supi, info.pdu_session_id);
        for op in &info.acu_operation_list {
            total_ops += 1;
            let s_nssai = &op.snssai.0;
            log::debug!(
                "[{}] PDU AC {} psi={} S-NSSAI[SST:{} SD:{:?}] anType={:?}",
                info.supi,
                op.update_flag,
                info.pdu_session_id,
                s_nssai.sst,
                s_nssai.sd,
                info.an_type
            );
            if op.update_flag == "INCREASE" {
                let result = with_nsacf_context(|c| c.admit_pdu_session(s_nssai, &session_key))
                    .unwrap_or(AdmissionResult::RejectedSliceNotAvailable);
                match result {
                    AdmissionResult::Admitted => spawn_event_reports(s_nssai),
                    rejected => failures.push(AcFailure::new(
                        &info.supi,
                        s_nssai,
                        rejection_reason(rejected, true),
                        Some(info.pdu_session_id),
                    )),
                }
            } else {
                with_nsacf_context(|c| c.release_pdu_session(s_nssai, &session_key));
                spawn_event_reports(s_nssai);
            }
        }
    }
    build_ac_response(failures, total_ops)
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

    /// Build a single-UE, single-op UeACRequestData body (TS 29.536 §6.1.6.2.2).
    fn ue_ac_body(supi: &str, flag: &str, sst: u8) -> serde_json::Value {
        json!({
            "nfId": "amf-1",
            "ueACRequestInfo": [{
                "supi": supi,
                "anType": "3GPP_ACCESS",
                "acuOperationList": [{ "updateFlag": flag, "snssai": {"sst": sst} }]
            }]
        })
    }

    #[tokio::test]
    async fn test_http_ue_admission_lifecycle() {
        let (server, port) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        create_quota(&client, 71, 2, 100).await;

        let post_ue = |supi: &str, flag: &str| {
            let body = ue_ac_body(supi, flag, 71);
            let client = SbiClient::with_host_port("127.0.0.1", port);
            async move {
                client
                    .post_json("/nnsacf-nsac/v1/slices/ues", &body)
                    .await
                    .expect("response")
            }
        };

        // INCREASE within quota -> 204 No Content, empty body (no admittedFlag).
        let resp = post_ue("imsi-71-1", "INCREASE").await;
        assert_eq!(resp.status, 204, "all-admitted is 204 No Content");
        assert!(
            resp.http.content.as_deref().unwrap_or("").is_empty(),
            "204 carries no body"
        );

        // Idempotent INCREASE for the same SUPI -> still 204.
        let resp = post_ue("imsi-71-1", "INCREASE").await;
        assert_eq!(resp.status, 204);

        let resp = post_ue("imsi-71-2", "INCREASE").await;
        assert_eq!(resp.status, 204);

        // Quota full, single requested op all failing -> 403 ProblemDetails
        // (total failure). The over-quota EXCEED reason is NOT an HTTP error
        // cause; for a single-op total failure the cause is ALL_SLICE_FAILED.
        let resp = post_ue("imsi-71-3", "INCREASE").await;
        assert_eq!(resp.status, 403, "every requested S-NSSAI failed -> 403");
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "ALL_SLICE_FAILED");
        assert!(
            !resp.http.content.as_deref().unwrap().contains("admittedFlag"),
            "admittedFlag must not appear"
        );

        // DECREASE frees capacity (idempotent release) -> 204, then INCREASE 204.
        let resp = post_ue("imsi-71-2", "DECREASE").await;
        assert_eq!(resp.status, 204, "DECREASE acknowledged as 204");
        let resp = post_ue("imsi-71-3", "INCREASE").await;
        assert_eq!(resp.status, 204);

        // Unknown slice (single op) -> 403 ProblemDetails cause SLICE_NOT_FOUND.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &ue_ac_body("imsi-x", "INCREASE", 99),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 403);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "SLICE_NOT_FOUND");

        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_http_ue_ac_missing_mandatory() {
        let (server, port) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        // Missing snssai inside an acuOperationList op -> 400 MANDATORY_IE_MISSING.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"nfId": "amf-1", "ueACRequestInfo": [{
                    "supi": "imsi-1", "anType": "3GPP_ACCESS",
                    "acuOperationList": [{ "updateFlag": "INCREASE" }]
                }]}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 400);
        let body = resp.http.content.as_deref().unwrap();
        assert!(body.contains("snssai"));
        assert!(body.contains("MANDATORY_IE_MISSING"));

        // Missing supi in a UeACRequestInfo -> 400 MANDATORY_IE_MISSING.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"nfId": "amf-1", "ueACRequestInfo": [{
                    "anType": "3GPP_ACCESS",
                    "acuOperationList": [{ "updateFlag": "INCREASE", "snssai": {"sst": 72} }]
                }]}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 400);
        let body = resp.http.content.as_deref().unwrap();
        assert!(body.contains("MANDATORY_IE_MISSING"));
        assert!(body.contains("supi"));

        // Empty ueACRequestInfo array -> 400 MANDATORY_IE_MISSING.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"nfId": "amf-1", "ueACRequestInfo": []}),
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

        // Empty acuOperationList -> 400 MANDATORY_IE_MISSING.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"nfId": "amf-1", "ueACRequestInfo": [{
                    "supi": "imsi-1", "anType": "3GPP_ACCESS", "acuOperationList": []
                }]}),
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

        // Invalid updateFlag (UPDATE is nsacf-06, deferred) -> 400 INVALID_IE_VALUE.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &ue_ac_body("imsi-1", "BOGUS", 72),
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

        // Invalid snssai value (sst > 255) -> 400 (INVALID_MSG_FORMAT).
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"nfId": "amf-1", "ueACRequestInfo": [{
                    "supi": "imsi-1", "anType": "3GPP_ACCESS",
                    "acuOperationList": [{ "updateFlag": "INCREASE", "snssai": {"sst": 9999} }]
                }]}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 400);

        server.stop().await.expect("stop");
    }

    /// Build a single-UE, single-op PduACRequestData body (TS 29.536 §6.1.6.2.7).
    fn pdu_ac_body(supi: &str, flag: &str, sst: u8, psi: u64) -> serde_json::Value {
        json!({
            "nfId": "smf-1",
            "pduACRequestInfo": [{
                "supi": supi,
                "anType": "3GPP_ACCESS",
                "pduSessionId": psi,
                "acuOperationList": [{ "updateFlag": flag, "snssai": {"sst": sst} }]
            }]
        })
    }

    #[tokio::test]
    async fn test_http_pdu_session_admission() {
        let (server, port) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        create_quota(&client, 73, 100, 1).await;

        // Missing pduSessionId -> 400 MANDATORY_IE_MISSING.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/pdus",
                &json!({"nfId": "smf-1", "pduACRequestInfo": [{
                    "supi": "imsi-73-1", "anType": "3GPP_ACCESS",
                    "acuOperationList": [{ "updateFlag": "INCREASE", "snssai": {"sst": 73} }]
                }]}),
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

        // INCREASE within quota -> 204 No Content.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/pdus",
                &pdu_ac_body("imsi-73-1", "INCREASE", 73, 1),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204);

        // Quota full, single op -> 403 (total failure, ALL_SLICE_FAILED).
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/pdus",
                &pdu_ac_body("imsi-73-2", "INCREASE", 73, 5),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 403);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "ALL_SLICE_FAILED");

        // DECREASE frees the slot -> 204, then INCREASE 204.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/pdus",
                &pdu_ac_body("imsi-73-1", "DECREASE", 73, 1),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204);
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/pdus",
                &pdu_ac_body("imsi-73-2", "INCREASE", 73, 5),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204);

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
                    &ue_ac_body(&format!("imsi-74-{i}"), "INCREASE", 74),
                )
                .await
                .expect("response");
            assert_eq!(resp.status, 204);
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
                &ue_ac_body("imsi-74-4", "DECREASE", 74),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204);

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

    // -----------------------------------------------------------------
    // nsacf-02 / nsacf-03: three-way response builder (pure unit)
    // -----------------------------------------------------------------

    #[test]
    fn test_acu_failure_reason_strings() {
        // TS 29.536 §6.1.6.3.5 exact enum strings.
        assert_eq!(AcuFailureReason::SliceNotFound.as_str(), "SLICE_NOT_FOUND");
        assert_eq!(AcuFailureReason::ExceedMaxUeNum.as_str(), "EXCEED_MAX_UE_NUM");
        assert_eq!(AcuFailureReason::ExceedMaxPduNum.as_str(), "EXCEED_MAX_PDU_NUM");
    }

    #[test]
    fn test_build_ac_response_three_way() {
        let snssai = SNssai::new(1, None);

        // All admitted -> 204 No Content.
        let r = build_ac_response(vec![], 2);
        assert_eq!(r.status, 204);

        // Partial failure -> 200 + acuFailureList keyed by SUPI; no admittedFlag.
        let r = build_ac_response(
            vec![AcFailure::new(
                "imsi-1",
                &snssai,
                AcuFailureReason::ExceedMaxUeNum,
                None,
            )],
            2,
        );
        assert_eq!(r.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(r.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(
            body["acuFailureList"]["imsi-1"][0]["reason"],
            "EXCEED_MAX_UE_NUM"
        );
        assert!(!r.http.content.as_deref().unwrap().contains("admittedFlag"));

        // Total failure, all SLICE_NOT_FOUND -> 403 cause SLICE_NOT_FOUND.
        let r = build_ac_response(
            vec![AcFailure::new(
                "imsi-1",
                &snssai,
                AcuFailureReason::SliceNotFound,
                None,
            )],
            1,
        );
        assert_eq!(r.status, 403);
        let body: serde_json::Value =
            serde_json::from_str(r.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "SLICE_NOT_FOUND");

        // Total failure with a quota reason -> 403 cause ALL_SLICE_FAILED.
        let r = build_ac_response(
            vec![AcFailure::new(
                "imsi-1",
                &snssai,
                AcuFailureReason::ExceedMaxPduNum,
                Some(3),
            )],
            1,
        );
        assert_eq!(r.status, 403);
        let body: serde_json::Value =
            serde_json::from_str(r.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "ALL_SLICE_FAILED");
    }

    // -----------------------------------------------------------------
    // nsacf-01: nested ueACRequestInfo[] x acuOperationList[] iteration
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn test_http_ue_nested_two_supis_two_ops() {
        let (server, port) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        // Two NSAC-subject slices, each with room for exactly 2 UEs.
        create_quota(&client, 81, 2, 100).await;
        create_quota(&client, 82, 2, 100).await;

        // One spec-shaped request: two UeACRequestInfo (2 SUPIs), each a 2-op
        // acuOperationList (sst 81 AND sst 82). All four (supi x snssai)
        // admissions must apply -> 204.
        let body = json!({
            "nfId": "amf-1",
            "ueACRequestInfo": [
                { "supi": "imsi-A", "anType": "3GPP_ACCESS", "acuOperationList": [
                    { "updateFlag": "INCREASE", "snssai": {"sst": 81} },
                    { "updateFlag": "INCREASE", "snssai": {"sst": 82} }
                ]},
                { "supi": "imsi-B", "anType": "3GPP_ACCESS", "acuOperationList": [
                    { "updateFlag": "INCREASE", "snssai": {"sst": 81} },
                    { "updateFlag": "INCREASE", "snssai": {"sst": 82} }
                ]}
            ]
        });
        let resp = client
            .post_json("/nnsacf-nsac/v1/slices/ues", &body)
            .await
            .expect("response");
        assert_eq!(resp.status, 204, "all four admissions applied");

        // Both slices are now full (2/2): a 3rd UE on either -> 403 (total
        // failure), proving every (supi x snssai) op was counted.
        for sst in [81u8, 82u8] {
            let resp = client
                .post_json(
                    "/nnsacf-nsac/v1/slices/ues",
                    &ue_ac_body("imsi-C", "INCREASE", sst),
                )
                .await
                .expect("response");
            assert_eq!(resp.status, 403, "slice {sst} should be full");
        }

        server.stop().await.expect("stop");
    }

    // -----------------------------------------------------------------
    // nsacf-02 (partial 200) + nsacf-03 (AcuFailureReason production)
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn test_http_ue_partial_failure_200_acu_failure_list() {
        let (server, port) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        create_quota(&client, 83, 1, 100).await; // room for exactly 1 UE

        // imsi-83-A admits, imsi-83-B is over quota -> partial failure (200).
        let body = json!({
            "nfId": "amf-1",
            "ueACRequestInfo": [
                { "supi": "imsi-83-A", "anType": "3GPP_ACCESS", "acuOperationList": [
                    { "updateFlag": "INCREASE", "snssai": {"sst": 83} } ]},
                { "supi": "imsi-83-B", "anType": "3GPP_ACCESS", "acuOperationList": [
                    { "updateFlag": "INCREASE", "snssai": {"sst": 83} } ]}
            ]
        });
        let resp = client
            .post_json("/nnsacf-nsac/v1/slices/ues", &body)
            .await
            .expect("response");
        assert_eq!(resp.status, 200, "partial failure -> 200");
        let v: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        // Admitted SUPI absent; over-quota SUPI carries EXCEED_MAX_UE_NUM.
        assert!(v["acuFailureList"]["imsi-83-A"].is_null());
        assert_eq!(
            v["acuFailureList"]["imsi-83-B"][0]["reason"],
            "EXCEED_MAX_UE_NUM"
        );
        assert_eq!(v["acuFailureList"]["imsi-83-B"][0]["snssai"]["sst"], 83);
        assert!(!resp.http.content.as_deref().unwrap().contains("admittedFlag"));

        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_http_ue_partial_failure_slice_not_found() {
        let (server, port) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        create_quota(&client, 84, 10, 100).await;

        // One op admits (sst 84), one op targets an unconfigured slice (sst 98)
        // -> 1 of 2 ops fails -> partial 200 with reason SLICE_NOT_FOUND.
        let body = json!({
            "nfId": "amf-1",
            "ueACRequestInfo": [{ "supi": "imsi-84", "anType": "3GPP_ACCESS", "acuOperationList": [
                { "updateFlag": "INCREASE", "snssai": {"sst": 84} },
                { "updateFlag": "INCREASE", "snssai": {"sst": 98} }
            ]}]
        });
        let resp = client
            .post_json("/nnsacf-nsac/v1/slices/ues", &body)
            .await
            .expect("response");
        assert_eq!(resp.status, 200);
        let v: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(
            v["acuFailureList"]["imsi-84"][0]["reason"],
            "SLICE_NOT_FOUND"
        );
        assert_eq!(v["acuFailureList"]["imsi-84"][0]["snssai"]["sst"], 98);

        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_http_pdu_partial_failure_exceed_max_pdu_num() {
        let (server, port) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        create_quota(&client, 85, 100, 1).await; // room for exactly 1 PDU session

        let body = json!({
            "nfId": "smf-1",
            "pduACRequestInfo": [
                { "supi": "imsi-85-A", "anType": "3GPP_ACCESS", "pduSessionId": 1, "acuOperationList": [
                    { "updateFlag": "INCREASE", "snssai": {"sst": 85} } ]},
                { "supi": "imsi-85-B", "anType": "3GPP_ACCESS", "pduSessionId": 2, "acuOperationList": [
                    { "updateFlag": "INCREASE", "snssai": {"sst": 85} } ]}
            ]
        });
        let resp = client
            .post_json("/nnsacf-nsac/v1/slices/pdus", &body)
            .await
            .expect("response");
        assert_eq!(resp.status, 200);
        let v: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(v["acuFailureList"]["imsi-85-A"].is_null());
        assert_eq!(
            v["acuFailureList"]["imsi-85-B"][0]["reason"],
            "EXCEED_MAX_PDU_NUM"
        );
        // AcuFailureItem.pduSessionId present for the PDU AC failure (§6.1.6.2.6).
        assert_eq!(v["acuFailureList"]["imsi-85-B"][0]["pduSessionId"], 2);

        server.stop().await.expect("stop");
    }

    // -----------------------------------------------------------------
    // nsacf-04: PDU resource URI is /slices/pdus (not /slices/pdu-sessions)
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn test_http_pdu_uri_is_slices_pdus() {
        let (server, port) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        create_quota(&client, 86, 100, 100).await;

        // Conformant /slices/pdus is routed (admits -> 204, not 404).
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/pdus",
                &pdu_ac_body("imsi-86", "INCREASE", 86, 1),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204, "/slices/pdus must be routed");

        // The legacy /slices/pdu-sessions is no longer a resource -> 404.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/pdu-sessions",
                &pdu_ac_body("imsi-86", "INCREASE", 86, 2),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 404, "/slices/pdu-sessions must 404");

        server.stop().await.expect("stop");
    }
}
