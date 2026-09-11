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
use nextgcore_sbi::client::{SbiClient, SbiClientConfig};
use nextgcore_sbi::context::global_context;
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::oauth::{JwksCache, OAuth2Client};
use nextgcore_sbi::server::{
    send_method_not_allowed, SbiServer, SbiServerConfig as NextgcoreSbiServerConfig,
};
use nextgcore_sbi::types::NfType;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

mod context;
#[cfg(feature = "sla-observe")]
mod sla_observe; // issue #27: observe-only slice-SLA loop (off by default)

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

/// One provisioned slice quota (`nsacf.slice_quotas[]`). Local NSAC
/// provisioning per TS 29.536 §6.1.3.4 (SliceACConfigData): only the
/// attributes present are subject to admission control — an absent
/// `max_ues`/`max_pdu_sessions` means that count is NOT capped for the slice
/// (u64::MAX), it does NOT mean a zero quota.
#[derive(Debug, Deserialize)]
struct SliceQuotaYaml {
    sst: u8,
    /// SD as the 6-hex-digit string form of TS 23.003 §28.4.2 (e.g. "000000").
    sd: Option<String>,
    max_ues: Option<u64>,
    max_pdu_sessions: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct NsacfSection {
    sbi: Option<SbiYaml>,
    nrf: Option<NrfYaml>,
    slice_quotas: Option<Vec<SliceQuotaYaml>>,
    /// Raw YAML value, NOT typed (issue #27): a malformed sla block must
    /// never fail the whole `NsacfYaml` parse — that would silently drop
    /// `slice_quotas` provisioning and reject every admission
    /// SLICE_NOT_AVAILABLE. Lenient typed conversion happens under the
    /// `sla-observe` feature.
    sla: Option<serde_yaml::Value>,
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

/// TS 29.536 §6.1.8 SupportedFeatures advertised by this NSACF, in the
/// 3GPP hex-string form (TS 29.571 §5.2.2). This NSACF implements none of the
/// optional features — in particular HNSAC/VHNSAC home/visited delegation is
/// NOT supported — so the negotiation string is `"0"` (every optional bit
/// clear). Consumers therefore know never to expect `ueAdmissionList` (nsacf-11).
const SUPPORTED_FEATURES: &str = "0";

/// TS 29.536 §6.1.8 feature bit 1 = HNSAC (Home Network Slice Admission Control).
#[cfg(test)]
const FEAT_HNSAC_BIT: u32 = 0x01;
/// TS 29.536 §6.1.8 feature bit 2 = VHNSAC (Visited HNSAC delegation).
#[cfg(test)]
const FEAT_VHNSAC_BIT: u32 = 0x02;

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
    let _otel = nextgcore_metrics::otel::init_otel(
        nextgcore_metrics::otel::OtelConfig::new(env!("CARGO_PKG_NAME")).with_endpoint(
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
    #[cfg(feature = "sla-observe")]
    let mut sla_raw: Option<serde_yaml::Value> = None;
    if let Ok(content) = std::fs::read_to_string(&args.config) {
        if let Ok(yaml) = serde_yaml::from_str::<NsacfYaml>(&content) {
            if let Some(nsacf) = yaml.nsacf {
                #[cfg(feature = "sla-observe")]
                {
                    sla_raw = nsacf.sla.clone();
                }
                // Provision the locally-configured slice quotas (TS 29.536
                // §6.1.3.4 local NSAC config). Without this, the NSACF starts
                // with an EMPTY quota table and every admission request is
                // rejected SLICE_NOT_AVAILABLE — which breaks the entire PDU
                // establishment chain of any slice the operator intended to
                // admit. An absent max_ues/max_pdu_sessions means that count
                // is not subject to NSAC for the slice (uncapped), per the
                // "only provisioned attributes are controlled" semantic.
                for q in nsacf.slice_quotas.as_deref().unwrap_or(&[]) {
                    let sd =
                        q.sd.as_deref()
                            .and_then(|s| u32::from_str_radix(s, 16).ok());
                    let s_nssai = SNssai::new(q.sst, sd);
                    let max_ues = q.max_ues.unwrap_or(u64::MAX);
                    let max_pdu = q.max_pdu_sessions.unwrap_or(u64::MAX);
                    let added = with_nsacf_context(|c| {
                        c.quota_add(s_nssai.clone(), max_ues, max_pdu).is_some()
                    })
                    .unwrap_or(false);
                    if added {
                        log::info!(
                            "Provisioned slice quota from config: S-NSSAI[SST:{} SD:{:?}] max_ues={} max_pdu_sessions={}",
                            q.sst, q.sd, max_ues, max_pdu
                        );
                    } else {
                        log::error!(
                            "Failed to provision slice quota from config: S-NSSAI[SST:{} SD:{:?}]",
                            q.sst,
                            q.sd
                        );
                    }
                }
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
        sbi_server_config = sbi_server_config.with_expected_audience_nf_type(NfType::Nsacf);

        // Client side (T1.1): install the process-wide OAuth2 client so
        // outbound SBI calls acquire and attach an NRF-issued Bearer token.
        if let Some(nrf_uri) = nrf_uri_cfg.as_deref() {
            let oauth2 = Arc::new(OAuth2Client::new(
                nrf_uri,
                nf_instance_id.clone(),
                NfType::Nsacf,
            ));
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
        // G2-2: PATCH a real NFProfile "/load" gauge to NRF each heartbeat
        // (active admission-control subscriptions, saturated at 100;
        // TS 29.510 §5.2.2.3.2). Honest subscription-count proxy — no
        // fabricated CPU numbers.
        nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(
            nf_instance_id.clone(),
            5,
            || {
                let load = nsacf_self()
                    .read()
                    .map(|c| c.subscription_count())
                    .unwrap_or(0);
                load.min(100) as u8
            },
        );
    }

    // Issue #27: observe-only slice-SLA loop (feature `sla-observe`,
    // off by default). No listener unless nsacf.sla.metrics_port opts in.
    #[cfg(feature = "sla-observe")]
    sla_observe::spawn_if_enabled(sla_raw);

    log::info!("NextGCore NSACF ready (instance: {nf_instance_id})");

    // Main event loop
    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Graceful shutdown
    log::info!("Shutting down...");

    // #235: NFDeregister (TS 29.510 5.2.2.2.3) BEFORE the listener goes
    // away, so the NRF stops handing this profile to consumers instead of
    // waiting out its supervision timer. Stopping the server first would
    // open the bad window: not serving, but still advertised.
    nextgcore_sbi::heartbeat::deregister_self().await;
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
        // Custom operations (TS 29.536 Table 6.1.3.1-1):
        //  - local-configs `update` (§6.1.3.4): update local NSAC configs.
        //  - roaming-quotas `query` (§6.1.3.5): query roaming quotas at the
        //    central/primary HPLMN NSACF.
        // ------------------------------------------------------------------
        ["nnsacf-nsac", "v1", "slices", "local-configs", "update"] => match method {
            "POST" => handle_local_configs_update(&request).await,
            _ => send_method_not_allowed(method, "slices/local-configs/update"),
        },
        ["nnsacf-nsac", "v1", "slices", "roaming-quotas", "query"] => match method {
            "POST" => handle_roaming_quotas_query(&request).await,
            _ => send_method_not_allowed(method, "slices/roaming-quotas/query"),
        },

        // ------------------------------------------------------------------
        // NextGCore admin-only extension (NOT a TS 29.536 resource): direct
        // slice-quota provisioning. The spec way to provision local NSAC config
        // is the `slices/local-configs/update` custom op above.
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

        // Utilization reporting (NextGCore admin-only extension, NOT TS 29.536).
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
            // TS 29.536 §5.3.2.2.3: PartialModifySubscription (PATCH) and
            // CompleteModifySubscription (PUT). Both used to fall through to 405,
            // so a consumer had to delete and re-create to change anything.
            "PATCH" => handle_slice_ee_modify_partial(sub_id, &request).await,
            "PUT" => handle_slice_ee_modify_complete(sub_id, &request).await,
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
    /// TS 29.571 AccessType (mandatory in the spec). Kept optional here so an
    /// not-yet-aligned sender is accepted; absent defaults to 3GPP access via
    /// [`AccessType::from_an_type`] (nsacf-05 accept-and-default).
    #[serde(default)]
    an_type: Option<String>,
    /// `additionalAnType` (TS 29.536 Table 6.1.6.2.9-1) — the SECOND access a UE
    /// is registered over, so a UE attached over both 3GPP and non-3GPP access is
    /// recorded on both and survives a DECREASE on one (§5.2.2.2.2). Never
    /// deserialised before #95, so a dual-access UE was modelled as single-access
    /// and deregistered on its first release.
    #[serde(default)]
    additional_an_type: Option<String>,
    /// Roaming information elements (TS 29.536 Table 6.1.6.2.9-1). Parsed and
    /// logged so a roaming request round-trips and is diagnosable; they do not yet
    /// drive per-PLMN quota selection — see the spec's Ceilings.
    #[serde(default)]
    plmn_id: Option<serde_json::Value>,
    #[serde(default)]
    plmn_id_nid: Option<serde_json::Value>,
    #[serde(default)]
    ue_reg_ind: Option<bool>,
    #[serde(default)]
    serving_plmn_id: Option<serde_json::Value>,
    #[serde(default)]
    nsac_mode: Option<String>,
    #[serde(default)]
    number_exceed_info: Option<serde_json::Value>,
    acu_operation_list: Vec<AcuOperationItem>,
}

impl UeACRequestInfo {
    /// The access set this request names: `anType` (defaulting to 3GPP when
    /// absent, per nsacf-05) plus `additionalAnType` when present.
    ///
    /// Never empty — an absent `anType` defaults rather than yielding nothing, so
    /// the `ues` <-> `ue_access` invariant cannot be broken by a sparse request.
    fn access_set(&self) -> AccessSet {
        let mut set = AccessSet::single(AccessType::from_an_type(self.an_type.as_deref()));
        if let Some(additional) = self.additional_an_type.as_deref() {
            // `from_an_type` defaults an unknown string to 3GPP; for the ADDITIONAL
            // access that default is wrong -- it would silently claim a 3GPP
            // registration the consumer never asserted. Only the two spelled
            // TS 29.571 values are honoured here.
            match additional {
                "3GPP_ACCESS" => set.insert(AccessType::ThreeGpp),
                "NON_3GPP_ACCESS" => set.insert(AccessType::NonThreeGpp),
                other => log::warn!(
                    "[{}] ignoring unrecognised additionalAnType {other:?} \
                     (expected 3GPP_ACCESS or NON_3GPP_ACCESS)",
                    self.supi
                ),
            }
        }
        set
    }

    /// The access set a **DECREASE** should release.
    ///
    /// When the request names no access at all — neither `anType` nor
    /// `additionalAnType` — EVERY access is released rather than the 3GPP default.
    /// This is load-bearing for backward compatibility, and it is the one place
    /// where the nsacf-05 accept-and-default rule must NOT simply be reused:
    /// before #95 a DECREASE removed the whole registration entry, so an
    /// access-unaware consumer that omits `anType` would, under a plain default to
    /// 3GPP, leave a UE registered over non-3GPP **forever** — the mirror image of
    /// the premature-removal bug this issue fixes. A consumer that names an access
    /// is stating which one it is deregistering and gets exactly that.
    fn release_set(&self) -> AccessSet {
        if self.an_type.is_none() && self.additional_an_type.is_none() {
            AccessSet::all()
        } else {
            self.access_set()
        }
    }

    /// Whether this request carries any roaming IE, for the log line.
    fn has_roaming_info(&self) -> bool {
        self.plmn_id.is_some()
            || self.plmn_id_nid.is_some()
            || self.ue_reg_ind.is_some()
            || self.serving_plmn_id.is_some()
            || self.nsac_mode.is_some()
            || self.number_exceed_info.is_some()
    }
}

/// UeACRequestData (TS 29.536 §6.1.6.2.2). `nfId` is mandatory (nsacf-09): a
/// non-`Option` field, so serde rejects its absence and the parser maps that to
/// 400 `MANDATORY_IE_MISSING`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UeACRequestData {
    // serde's camelCase would render `ue_ac_request_info` as `ueAcRequestInfo`,
    // but the TS 29.536 attribute keeps the "AC" acronym uppercase: rename
    // explicitly so a conformant AMF body deserializes.
    #[serde(rename = "ueACRequestInfo")]
    ue_ac_request_info: Vec<UeACRequestInfo>,
    /// NF instance id of the requesting consumer (M, TS 29.536 §6.1.6.2.2).
    nf_id: String,
    /// EAC notification callback URI (O, TS 29.536 §6.1.6.2.2). Absent = no
    /// change; explicit JSON null = unsubscribe; a value = (implicit) subscribe.
    #[serde(default, deserialize_with = "double_option")]
    eac_notification_uri: Option<Option<String>>,
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

/// PduACRequestData (TS 29.536 §6.1.6.2.7). `nfId` mandatory (nsacf-09).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PduACRequestData {
    // Same "AC" acronym caveat as UeACRequestData: TS 29.536 uses
    // `pduACRequestInfo`, not serde's default `pduAcRequestInfo`.
    #[serde(rename = "pduACRequestInfo")]
    pdu_ac_request_info: Vec<PduACRequestInfo>,
    /// `nfId` — **OPTIONAL** here (#95). TS 29.536 Table 6.1.6.2.7-1 lists
    /// `pduACRequestInfo` as the only required attribute of `PduACRequestData`;
    /// `nfId`, `pgwFqdn`, `nsacServiceArea` and `supportedFeatures` are all
    /// optional. It was a non-`Option` `String` here, so a conformant SMF/PGW-C
    /// that identifies itself by `pgwFqdn` was turned away with
    /// `400 MANDATORY_IE_MISSING` and PDU-session number control silently failed
    /// against off-the-shelf core NFs.
    ///
    /// Note the asymmetry with [`UeACRequestData`], which is deliberate and
    /// correct: `nfId` IS mandatory there (nsacf-09), so that one stays required.
    #[serde(default)]
    nf_id: Option<String>,
    /// `pgwFqdn` — the requester's PGW-C/SMF FQDN, the fallback identity when a
    /// consumer omits `nfId` (TS 29.536 Table 6.1.6.2.7-1).
    #[serde(default)]
    pgw_fqdn: Option<String>,
    /// `nsacServiceArea` — the NSAC service area the request applies to.
    #[serde(default)]
    nsac_service_area: Option<serde_json::Value>,
    /// `supportedFeatures` — TS 29.571 `SupportedFeatures` bitmap string.
    #[serde(default)]
    supported_features: Option<String>,
}

impl PduACRequestData {
    /// How to name the requester in a log line: `nfId` if given, else `pgwFqdn`,
    /// else an explicit marker. Never a fabricated identity — the point of #95 is
    /// that a consumer may legitimately supply neither.
    fn requester(&self) -> &str {
        self.nf_id
            .as_deref()
            .or(self.pgw_fqdn.as_deref())
            .unwrap_or("unidentified consumer")
    }
}

/// AcuFailureReason (TS 29.536 §6.1.6.3.5). The aggregate strings plus the
/// per-access-type `_3GPP`/`_N3GPP` variants selected when a per-access ceiling
/// is configured (nsacf-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcuFailureReason {
    SliceNotFound,
    ExceedMaxUeNum,
    ExceedMaxUeNum3Gpp,
    ExceedMaxUeNumN3Gpp,
    ExceedMaxPduNum,
    ExceedMaxPduNum3Gpp,
    ExceedMaxPduNumN3Gpp,
}

impl AcuFailureReason {
    fn as_str(self) -> &'static str {
        match self {
            AcuFailureReason::SliceNotFound => "SLICE_NOT_FOUND",
            AcuFailureReason::ExceedMaxUeNum => "EXCEED_MAX_UE_NUM",
            AcuFailureReason::ExceedMaxUeNum3Gpp => "EXCEED_MAX_UE_NUM_3GPP",
            AcuFailureReason::ExceedMaxUeNumN3Gpp => "EXCEED_MAX_UE_NUM_N3GPP",
            AcuFailureReason::ExceedMaxPduNum => "EXCEED_MAX_PDU_NUM",
            AcuFailureReason::ExceedMaxPduNum3Gpp => "EXCEED_MAX_PDU_NUM_3GPP",
            AcuFailureReason::ExceedMaxPduNumN3Gpp => "EXCEED_MAX_PDU_NUM_N3GPP",
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
    fn new(
        supi: &str,
        s_nssai: &SNssai,
        reason: AcuFailureReason,
        pdu_session_id: Option<u64>,
    ) -> Self {
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
/// (TS 29.536 §6.1.6.3.5). `is_pdu` selects EXCEED_MAX_PDU_NUM vs _UE_NUM; a
/// per-access ceiling breach selects the `_3GPP`/`_N3GPP` variant (nsacf-05).
fn rejection_reason(result: AdmissionResult, is_pdu: bool) -> AcuFailureReason {
    use AccessType::{NonThreeGpp, ThreeGpp};
    use AdmissionResult::{RejectedQuotaExceeded, RejectedQuotaExceededPerAccess};
    match (result, is_pdu) {
        (RejectedQuotaExceeded, true) => AcuFailureReason::ExceedMaxPduNum,
        (RejectedQuotaExceeded, false) => AcuFailureReason::ExceedMaxUeNum,
        (RejectedQuotaExceededPerAccess(ThreeGpp), true) => AcuFailureReason::ExceedMaxPduNum3Gpp,
        (RejectedQuotaExceededPerAccess(NonThreeGpp), true) => {
            AcuFailureReason::ExceedMaxPduNumN3Gpp
        }
        (RejectedQuotaExceededPerAccess(ThreeGpp), false) => AcuFailureReason::ExceedMaxUeNum3Gpp,
        (RejectedQuotaExceededPerAccess(NonThreeGpp), false) => {
            AcuFailureReason::ExceedMaxUeNumN3Gpp
        }
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
    // UeACResponseData / PduACResponseData (TS 29.536 §6.1.6.2.3/.8). We
    // advertise `supportedFeatures` (HNSAC/VHNSAC bits clear) and never emit
    // `ueAdmissionList` (nsacf-11).
    let body = serde_json::json!({
        "acuFailureList": acu_failure_list,
        "supportedFeatures": SUPPORTED_FEATURES,
    });
    SbiResponse::with_status(200)
        .with_json_body(&body)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Validate every op's `updateFlag` (TS 29.536 §6.1.6.3.4 AcuFlag:
/// INCREASE/DECREASE/UPDATE) before any state mutation.
#[allow(clippy::result_large_err)] // SbiResponse is the natural error type here
fn validate_flags<'a>(ops: impl Iterator<Item = &'a AcuOperationItem>) -> Result<(), SbiResponse> {
    for op in ops {
        if !matches!(op.update_flag.as_str(), "INCREASE" | "DECREASE" | "UPDATE") {
            return Err(problem_details(
                400,
                "Bad Request",
                &format!(
                    "Invalid updateFlag '{}' (expected INCREASE, DECREASE or UPDATE)",
                    op.update_flag
                ),
                Some("INVALID_IE_VALUE"),
            ));
        }
    }
    Ok(())
}

/// serde helper distinguishing an absent field (`None`) from an explicit JSON
/// `null` (`Some(None)`) and a present value (`Some(Some(v))`) — needed so a
/// null `eacNotificationUri` can unsubscribe (TS 29.536 §5.2.2.3.2).
fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Deserialize::deserialize(de).map(Some)
}

/// Render an [`AccessSet`] for a log line, e.g. `3GPP_ACCESS+NON_3GPP_ACCESS`.
fn access_set_str(set: AccessSet) -> String {
    if set.is_empty() {
        return "<none>".to_string();
    }
    set.iter()
        .map(AccessType::as_str)
        .collect::<Vec<_>>()
        .join("+")
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
        problem_details(
            400,
            "Bad Request",
            &format!("Invalid request body: {msg}"),
            Some(cause),
        )
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

    log::debug!("UE AC request from nfId={}", req.nf_id);
    // EAC implicit subscription (TS 29.536 §5.2.2.3.2): a value registers the
    // callback keyed by AMF nfId; an explicit null unsubscribes; absent = no change.
    match &req.eac_notification_uri {
        Some(Some(uri)) => {
            // TS 29.536 §5.2.2.2.2: on the FIRST subscription the NSACF "shall
            // immediately send an EAC notification ... including the most recent
            // EAC Modes for the subscribed S-NSSAIs". Before #96 the callback was
            // registered and nothing was sent, so a consumer did not learn the
            // current mode until the next TRANSITION — which for a stable slice
            // could be never, leaving admission-control policy out of sync from
            // the moment it subscribed.
            //
            // Only on the first: an AMF that re-sends its eacNotificationUri on
            // every NumOfUEsUpdate must not be re-notified each time.
            let first =
                !with_nsacf_context(|c| c.eac_subscription_exists(&req.nf_id)).unwrap_or(false);
            with_nsacf_context(|c| c.eac_subscription_set(&req.nf_id, uri));
            if first {
                let modes = with_nsacf_context(|c| c.eac_mode_list()).unwrap_or_default();
                // An NSACF with no configured slice quotas has no modes to report;
                // sending an empty eacModeList would assert "no slices" rather than
                // "nothing configured yet", so nothing is sent.
                if !modes.is_empty() {
                    log::info!(
                        "EAC first subscription from nfId={}: sending immediate EAC \
                         notification with {} slice mode(s)",
                        req.nf_id,
                        modes.len()
                    );
                    let body = serde_json::json!({ "eacModeList": modes });
                    tokio::spawn(deliver_notification(uri.clone(), body));
                }
            }
        }
        Some(None) => {
            with_nsacf_context(|c| c.eac_subscription_remove(&req.nf_id));
        }
        None => {}
    }
    let mut failures: Vec<AcFailure> = Vec::new();
    let mut total_ops = 0usize;
    for info in &req.ue_ac_request_info {
        // anType is mandatory in the spec; an absent value defaults to 3GPP
        // (nsacf-05 accept-and-default). #95: `additionalAnType` joins it, so a
        // dual-access UE is recorded on both accesses.
        let accesses = info.access_set();
        if info.has_roaming_info() {
            log::debug!(
                "[{}] UE AC carries roaming info: plmnId={:?} plmnIdNid={:?} ueRegInd={:?} \
                 servingPlmnId={:?} nsacMode={:?} numberExceedInfo={:?}",
                info.supi,
                info.plmn_id,
                info.plmn_id_nid,
                info.ue_reg_ind,
                info.serving_plmn_id,
                info.nsac_mode,
                info.number_exceed_info
            );
        }
        for op in &info.acu_operation_list {
            total_ops += 1;
            let s_nssai = &op.snssai.0;
            log::debug!(
                "[{}] UE AC {} S-NSSAI[SST:{} SD:{:?}] access={}",
                info.supi,
                op.update_flag,
                s_nssai.sst,
                s_nssai.sd,
                access_set_str(accesses)
            );
            match op.update_flag.as_str() {
                "INCREASE" => {
                    let (result, eac) =
                        with_nsacf_context(|c| c.admit_ue(s_nssai, &info.supi, accesses))
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
                }
                "UPDATE" => {
                    // Set the UE's access set to exactly what the request names
                    // (nsacf-06, generalised to a set by #95).
                    match with_nsacf_context(|c| c.update_ue_access(s_nssai, &info.supi, accesses))
                        .unwrap_or(UpdateOutcome::NotFound)
                    {
                        UpdateOutcome::Updated => spawn_event_reports(s_nssai),
                        UpdateOutcome::NotFound => failures.push(AcFailure::new(
                            &info.supi,
                            s_nssai,
                            AcuFailureReason::SliceNotFound,
                            None,
                        )),
                    }
                }
                // DECREASE (validate_flags guarantees the only remaining flag).
                // nsacf-10: clean release / idempotent member-absent → success;
                // S-NSSAI not NSAC-subject → SLICE_NOT_FOUND failure.
                _ => match with_nsacf_context(|c| {
                    c.release_ue(s_nssai, &info.supi, info.release_set())
                })
                .unwrap_or(ReleaseOutcome::SliceNotFound)
                {
                    ReleaseOutcome::Released(eac) => {
                        if let Some(eac) = eac {
                            spawn_eac_notifications(eac);
                        }
                        spawn_event_reports(s_nssai);
                    }
                    // #95: the UE is still registered over another access, so the
                    // aggregate count is unchanged and there is no EAC transition
                    // to report -- but the PER-ACCESS counts moved, so subscribers
                    // watching those still need the event report.
                    ReleaseOutcome::AccessReleased => {
                        log::debug!(
                            "[{}] released {} but still registered on {} -- entry kept \
                             (TS 29.536 §5.2.2.2.2)",
                            info.supi,
                            access_set_str(accesses),
                            with_nsacf_context(|c| c
                                .quota_find_by_snssai(s_nssai)
                                .map(|q| access_set_str(q.ue_access_set(&info.supi))))
                            .flatten()
                            .unwrap_or_else(|| "<unknown>".to_string())
                        );
                        spawn_event_reports(s_nssai);
                    }
                    ReleaseOutcome::MemberAbsent => { /* idempotent: counts as admitted */ }
                    ReleaseOutcome::SliceNotFound => failures.push(AcFailure::new(
                        &info.supi,
                        s_nssai,
                        AcuFailureReason::SliceNotFound,
                        None,
                    )),
                },
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

    // #95: the requester may identify itself by nfId OR pgwFqdn OR neither, so
    // the log line names whichever was supplied rather than assuming nfId.
    log::debug!(
        "PDU AC request from {} (nsacServiceArea={:?} supportedFeatures={:?})",
        req.requester(),
        req.nsac_service_area,
        req.supported_features
    );
    let mut failures: Vec<AcFailure> = Vec::new();
    let mut total_ops = 0usize;
    for info in &req.pdu_ac_request_info {
        let session_key = format!("{}:{}", info.supi, info.pdu_session_id);
        let access = AccessType::from_an_type(info.an_type.as_deref());
        for op in &info.acu_operation_list {
            total_ops += 1;
            let s_nssai = &op.snssai.0;
            log::debug!(
                "[{}] PDU AC {} psi={} S-NSSAI[SST:{} SD:{:?}] access={}",
                info.supi,
                op.update_flag,
                info.pdu_session_id,
                s_nssai.sst,
                s_nssai.sd,
                access.as_str()
            );
            match op.update_flag.as_str() {
                "INCREASE" => {
                    let result =
                        with_nsacf_context(|c| c.admit_pdu_session(s_nssai, &session_key, access))
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
                }
                "UPDATE" => {
                    match with_nsacf_context(|c| c.update_pdu_access(s_nssai, &session_key, access))
                        .unwrap_or(UpdateOutcome::NotFound)
                    {
                        UpdateOutcome::Updated => spawn_event_reports(s_nssai),
                        UpdateOutcome::NotFound => failures.push(AcFailure::new(
                            &info.supi,
                            s_nssai,
                            AcuFailureReason::SliceNotFound,
                            Some(info.pdu_session_id),
                        )),
                    }
                }
                // DECREASE (nsacf-10).
                _ => match with_nsacf_context(|c| c.release_pdu_session(s_nssai, &session_key))
                    .unwrap_or(ReleaseOutcome::SliceNotFound)
                {
                    // `AccessReleased` cannot arise here: a PDU session has ONE
                    // access type (`pdu_access` is still a single `AccessType` per
                    // session key), so releasing it always removes the session.
                    // Matched explicitly rather than by `_` so that giving PDU
                    // sessions a multi-access model later is a compile error here
                    // instead of a silently-dropped report.
                    ReleaseOutcome::Released(_)
                    | ReleaseOutcome::AccessReleased
                    | ReleaseOutcome::MemberAbsent => spawn_event_reports(s_nssai),
                    ReleaseOutcome::SliceNotFound => failures.push(AcFailure::new(
                        &info.supi,
                        s_nssai,
                        AcuFailureReason::SliceNotFound,
                        Some(info.pdu_session_id),
                    )),
                },
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
                // #95: the per-access registered counts moved here from the
                // roaming-quotas response, which is now the spec's
                // `QuotaUpdateResponseData` and carries only the ceilings. This is
                // the admin-only inspection resource, so it is the right home --
                // and without it there is no wire-observable way to check that a
                // dual-access UE is counted in both buckets while counting once
                // against the aggregate.
                "currentUes3gpp": quota.current_ues_access(AccessType::ThreeGpp),
                "currentUesN3gpp": quota.current_ues_access(AccessType::NonThreeGpp),
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
// Custom operations (TS 29.536 §6.1.3.4 / §6.1.3.5)
//
// Field names mirror TS 29.536 LocalConfigurations terminology (the r16/r17
// vendored OpenAPI does not include TS29536_Nnsacf_*.yaml).
// ---------------------------------------------------------------------------

/// Ceilings applied to a slice that `ACUpdateData` did not name and that had no
/// prior quota. Only reachable for a brand-new S-NSSAI: an existing quota keeps
/// its own value (see `handle_local_configs_update`).
const DEFAULT_MAX_UES: u64 = 10000;
const DEFAULT_MAX_PDU_SESSIONS: u64 = 50000;

/// Parse the optional per-access-type ceilings from a config object.
fn parse_access_limits(v: &serde_json::Value) -> AccessLimits {
    AccessLimits {
        max_ues_3gpp: v.get("maxUes3gpp").and_then(|x| x.as_u64()),
        max_ues_n3gpp: v.get("maxUesN3gpp").and_then(|x| x.as_u64()),
        max_pdu_3gpp: v.get("maxPdu3gpp").and_then(|x| x.as_u64()),
        max_pdu_n3gpp: v.get("maxPduN3gpp").and_then(|x| x.as_u64()),
    }
}

/// Per-access ceilings from the request, falling back **per field** to whatever
/// the existing quota holds.
///
/// #95: this matters because `ACUpdateData` is a single object rather than a
/// full-configuration array, so an update that names only `maxUesNumber` must not
/// erase per-access ceilings a previous call installed. `parse_access_limits`
/// alone would return all-`None` and silently disable per-access enforcement.
fn parse_access_limits_or_keep(
    v: &serde_json::Value,
    existing: Option<&SliceQuota>,
) -> AccessLimits {
    let requested = parse_access_limits(v);
    AccessLimits {
        max_ues_3gpp: requested
            .max_ues_3gpp
            .or_else(|| existing.and_then(|q| q.max_ues_3gpp)),
        max_ues_n3gpp: requested
            .max_ues_n3gpp
            .or_else(|| existing.and_then(|q| q.max_ues_n3gpp)),
        max_pdu_3gpp: requested
            .max_pdu_3gpp
            .or_else(|| existing.and_then(|q| q.max_pdu_3gpp)),
        max_pdu_n3gpp: requested
            .max_pdu_n3gpp
            .or_else(|| existing.and_then(|q| q.max_pdu_n3gpp)),
    }
}

/// Parse a TS 29.571 `PlmnId` (`{mcc, mnc}`), rejecting anything that does not
/// actually name a PLMN. Both members are mandatory in `PlmnId` itself, so a
/// `{}` or a `null` is not a PLMN and must not satisfy a mandatory `plmnId` IE.
fn plmn_id_from_json(v: &serde_json::Value) -> Option<PlmnId> {
    let mcc = v.get("mcc")?.as_str()?;
    let mnc = v.get("mnc")?.as_str()?;
    if mcc.is_empty() || mnc.is_empty() {
        return None;
    }
    Some(PlmnId {
        mcc: mcc.to_string(),
        mnc: mnc.to_string(),
    })
}

/// Decode the JSON body of a custom operation, or the `ProblemDetails` to return.
#[allow(clippy::result_large_err)] // SbiResponse is the natural error type here
fn custom_op_body(request: &SbiRequest) -> Result<serde_json::Value, SbiResponse> {
    let Some(content) = request.http.content.as_deref() else {
        return Err(problem_details(
            400,
            "Bad Request",
            "Missing mandatory request body",
            Some("MANDATORY_IE_MISSING"),
        ));
    };
    serde_json::from_str(content).map_err(|e| {
        problem_details(
            400,
            "Bad Request",
            &format!("Invalid JSON: {e}"),
            Some("INVALID_MSG_FORMAT"),
        )
    })
}

/// POST /nnsacf-nsac/v1/slices/local-configs/update  (TS 29.536 §6.1.3.4)
///
/// Request: `ACUpdateData` — `snssai` (M), `maxUesNumber` (O), `maxPdusNumber`
/// (O). Response: **204 No Content with an empty body** (TS 29.536 §5.2.2.5.2).
///
/// #95 replaced a bespoke wire: it required a `localConfigurations` **array**
/// envelope with `maxUes` / `maxPduSessions`, and answered `200` with a
/// `{localConfigurations, supportedFeatures}` body. An OSS/BSS or OAM system
/// driving slice UE/PDU limits speaks `ACUpdateData` and would not have
/// interworked with either half of that.
///
/// Memberships of an existing quota are preserved across the update.
async fn handle_local_configs_update(request: &SbiRequest) -> SbiResponse {
    log::info!("LocalConfigurations update (ACUpdateData)");

    let data = match custom_op_body(request) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // `snssai` is the ONLY mandatory member; a missing or malformed one is
    // 400 MANDATORY_IE_MISSING.
    let Some(s_nssai) = data.get("snssai").and_then(SNssai::from_json) else {
        return problem_details(
            400,
            "Bad Request",
            "Missing/invalid mandatory attribute: snssai",
            Some("MANDATORY_IE_MISSING"),
        );
    };

    // `maxUesNumber` / `maxPdusNumber` are OPTIONAL. When omitted for a slice
    // that already has a quota, its current ceiling is KEPT rather than reset to
    // a default -- an ACUpdateData that names only `maxPdusNumber` must not
    // silently widen the UE ceiling to 10000. Only a brand-new slice falls back
    // to the defaults.
    let existing = with_nsacf_context(|c| c.quota_find_by_snssai(&s_nssai)).flatten();
    let max_ues = data
        .get("maxUesNumber")
        .and_then(|v| v.as_u64())
        .or_else(|| existing.as_ref().map(|q| q.max_ues))
        .unwrap_or(DEFAULT_MAX_UES);
    let max_pdu = data
        .get("maxPdusNumber")
        .and_then(|v| v.as_u64())
        .or_else(|| existing.as_ref().map(|q| q.max_pdu_sessions))
        .unwrap_or(DEFAULT_MAX_PDU_SESSIONS);

    // Per-access ceilings are a NextGCore extension (nsacf-05), not part of
    // `ACUpdateData`. They are read from the same object as additional optional
    // members so the capability the bespoke envelope offered is not lost by
    // becoming conformant; a consumer that sends none is unaffected, and an
    // existing quota keeps the ceilings it has.
    let limits = parse_access_limits_or_keep(&data, existing.as_ref());

    match with_nsacf_context(|c| c.quota_update_or_add(s_nssai.clone(), max_ues, max_pdu, limits))
        .flatten()
    {
        Some(quota) => {
            log::info!(
                "LocalConfigurations applied: S-NSSAI[SST:{} SD:{:?}] maxUes={} maxPdus={}",
                quota.s_nssai.sst,
                quota.s_nssai.sd,
                quota.max_ues,
                quota.max_pdu_sessions
            );
            // §5.2.2.5.2: 204 with NO body. `SbiResponse::with_status` sets no
            // content, which is what makes this an empty body rather than "null".
            SbiResponse::with_status(204)
        }
        None => problem_details(
            500,
            "Internal Server Error",
            "Failed to apply the local NSAC configuration",
            Some("INTERNAL_ERROR"),
        ),
    }
}

/// POST /nnsacf-nsac/v1/slices/roaming-quotas/query  (TS 29.536 §6.1.3.5)
///
/// Request: `QuotaUpdateRequestData` — `snssai`, `plmnId` and `quotaType` all
/// **required**. Response: `200` + `QuotaUpdateResponseData`
/// `{snssai, maxUesNumber, maxPdusNumber}` (TS 29.536 §5.2.2.6.2 / §5.3.2.4.1).
///
/// #95 replaced a bespoke wire: the body was optional, the three mandatory IEs
/// were ignored, a non-spec `snssais` **array** acted as a filter, and the
/// response was `{roamingQuotas: [...], supportedFeatures}`. A partner HPLMN
/// NSACF exchanging roaming quotas speaks the 3GPP shapes and would not have
/// interworked.
async fn handle_roaming_quotas_query(request: &SbiRequest) -> SbiResponse {
    log::info!("RoamingQuotas update (QuotaUpdateRequestData)");

    let data = match custom_op_body(request) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let Some(s_nssai) = data.get("snssai").and_then(SNssai::from_json) else {
        return problem_details(
            400,
            "Bad Request",
            "Missing/invalid mandatory attribute: snssai",
            Some("MANDATORY_IE_MISSING"),
        );
    };
    // `plmnId` must be present and must be a PLMN (mcc+mnc), not any JSON value:
    // a body carrying `"plmnId": null` or `{}` is naming no PLMN, and accepting it
    // would make the mandatory IE decorative.
    let plmn_id = match data.get("plmnId").and_then(plmn_id_from_json) {
        Some(p) => p,
        None => {
            return problem_details(
                400,
                "Bad Request",
                "Missing/invalid mandatory attribute: plmnId",
                Some("MANDATORY_IE_MISSING"),
            )
        }
    };
    // `quotaType` presence is mandated and enforced; its VALUE is not constrained.
    // TS 29.536's `QuotaType` enumeration is not in the vendored OpenAPI set (see
    // the module header), and inventing an allowed-value list would risk rejecting
    // a conformant peer -- which is gap 1 of this very issue committed in a new
    // place. So: reject absent or empty, accept and log any spelling.
    let Some(quota_type) = data
        .get("quotaType")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    else {
        return problem_details(
            400,
            "Bad Request",
            "Missing/invalid mandatory attribute: quotaType",
            Some("MANDATORY_IE_MISSING"),
        );
    };

    let Some(quota) = with_nsacf_context(|c| c.quota_find_by_snssai(&s_nssai)).flatten() else {
        return problem_details(
            404,
            "Not Found",
            "No NSAC quota is configured for the requested S-NSSAI",
            Some("QUOTA_NOT_FOUND"),
        );
    };

    log::info!(
        "RoamingQuotas: S-NSSAI[SST:{} SD:{:?}] plmn={}-{} quotaType={} -> maxUes={} maxPdus={}",
        s_nssai.sst,
        s_nssai.sd,
        plmn_id.mcc,
        plmn_id.mnc,
        quota_type,
        quota.max_ues,
        quota.max_pdu_sessions
    );

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "snssai": quota.s_nssai.to_json(),
            "maxUesNumber": quota.max_ues,
            "maxPdusNumber": quota.max_pdu_sessions,
        }))
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

    // TS 29.536 §6.2.6.2.2 SACEventSubscription: required { event, eventNotifyUri,
    // nfId }; event is a SACEvent { eventType, eventFilter=array(Snssai) }.
    let mut missing = Vec::new();
    let notification_uri = data.get("eventNotifyUri").and_then(|v| v.as_str());
    if notification_uri.is_none() {
        missing.push("eventNotifyUri");
    }
    if data.get("nfId").and_then(|v| v.as_str()).is_none() {
        missing.push("nfId");
    }
    let event = data.get("event");
    let event_type = event
        .and_then(|e| e.get("eventType"))
        .and_then(|v| v.as_str());
    if event_type.is_none() {
        missing.push("event.eventType");
    }
    let event_filter = event
        .and_then(|e| e.get("eventFilter"))
        .and_then(|v| v.as_array());
    if event_filter.map(|a| a.is_empty()).unwrap_or(true) {
        missing.push("event.eventFilter");
    }
    if !missing.is_empty() {
        return problem_details(
            400,
            "Bad Request",
            &format!("Missing mandatory attribute(s): {}", missing.join(", ")),
            Some("MANDATORY_IE_MISSING"),
        );
    }

    // TS 29.536 §6.2.6.3.3 SACEventType: only the two count events are supported.
    let event_type = event_type.expect("checked above");
    if event_type != "NUM_OF_REGD_UES" && event_type != "NUM_OF_ESTD_PDU_SESSIONS" {
        return problem_details(
            400,
            "Bad Request",
            &format!("Unsupported eventType: {event_type}"),
            Some("INVALID_MSG_FORMAT"),
        );
    }

    let snssais: Vec<SNssai> = event_filter
        .expect("checked above")
        .iter()
        .filter_map(SNssai::from_json)
        .collect();

    let subscription_id = uuid::Uuid::new_v4().to_string();
    let sub = build_subscription(&subscription_id, &data, event_type, snssais);
    let immediate = sub.immediate_flag;
    let snssais_for_immediate = sub.snssais.clone();
    with_nsacf_context(|c| c.subscription_add(sub));

    log::info!("SliceEventExposure subscription created: {subscription_id}");

    // TS 29.536 §5.3.2.2.2: `immediateFlag` asks for one report AT SUBSCRIBE
    // TIME. Without this a consumer that set the flag learned nothing until the
    // next admit/release, which for a quiet slice could be never.
    if immediate {
        for s in &snssais_for_immediate {
            emit_reports_for(s, ReportCause::Immediate(&subscription_id));
        }
    }

    // 201 CreatedSACEventSubscription { subscription, subscriptionId }: echo the
    // received SACEventSubscription verbatim (TS 29.536 §6.2.6.2.3).
    SbiResponse::with_status(201)
        .with_header(
            "Location",
            format!("/nnsacf-slice-ee/v1/subscriptions/{subscription_id}"),
        )
        .with_json_body(&serde_json::json!({
            "subscription": data,
            "subscriptionId": subscription_id,
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// Build a `SacSubscription` from a validated `SACEventSubscription` document.
///
/// Factored out so `CompleteModifySubscription` (PUT) replaces a subscription
/// through exactly the same parse as create — two parsers would be two places for
/// a trigger field to be forgotten, which is how all six came to be dropped.
///
/// Note where the members live: `eventTrigger`, `notifThreshold`,
/// `notificationPeriod` and `immediateFlag` are on the nested `event`
/// (`SACEvent`), while `notifyCorrelationId`, `maxReports` and `expiry` are on the
/// TOP-LEVEL `SACEventSubscription`. The issue lists them together; reading them
/// all from one object would have silently found none.
fn build_subscription(
    subscription_id: &str,
    data: &serde_json::Value,
    event_type: &str,
    snssais: Vec<SNssai>,
) -> SacSubscription {
    let event = data.get("event");
    SacSubscription {
        subscription_id: subscription_id.to_string(),
        notification_uri: data
            .get("eventNotifyUri")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        events: vec![event_type.to_string()],
        snssais,
        expiry: data
            .get("expiry")
            .and_then(|v| v.as_str())
            .map(String::from),
        event_trigger: event
            .and_then(|e| e.get("eventTrigger"))
            .and_then(|v| v.as_str())
            .map(String::from),
        notif_threshold: event.and_then(|e| e.get("notifThreshold")).cloned(),
        notification_period: event
            .and_then(|e| e.get("notificationPeriod"))
            .and_then(|v| v.as_u64()),
        immediate_flag: event
            .and_then(|e| e.get("immediateFlag"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        max_reports: data
            .get("maxReports")
            .and_then(|v| v.as_u64())
            .and_then(|n| u32::try_from(n).ok()),
        report_count: 0,
        notify_correlation_id: data
            .get("notifyCorrelationId")
            .and_then(|v| v.as_str())
            .map(String::from),
        over_threshold: false,
        last_report_at: 0,
    }
}

/// Validate a `SACEventSubscription` document, returning the parsed event type
/// and S-NSSAI filter or a ProblemDetails response.
///
/// The same validation create performs, shared with PUT.
fn validate_subscription_doc(
    data: &serde_json::Value,
) -> Result<(String, Vec<SNssai>), Box<SbiResponse>> {
    let mut missing = Vec::new();
    if data
        .get("eventNotifyUri")
        .and_then(|v| v.as_str())
        .is_none()
    {
        missing.push("eventNotifyUri");
    }
    if data.get("nfId").and_then(|v| v.as_str()).is_none() {
        missing.push("nfId");
    }
    let event = data.get("event");
    let event_type = event
        .and_then(|e| e.get("eventType"))
        .and_then(|v| v.as_str());
    if event_type.is_none() {
        missing.push("event.eventType");
    }
    let event_filter = event
        .and_then(|e| e.get("eventFilter"))
        .and_then(|v| v.as_array());
    if event_filter.map(|a| a.is_empty()).unwrap_or(true) {
        missing.push("event.eventFilter");
    }
    if !missing.is_empty() {
        return Err(Box::new(problem_details(
            400,
            "Bad Request",
            &format!("Missing mandatory attribute(s): {}", missing.join(", ")),
            Some("MANDATORY_IE_MISSING"),
        )));
    }
    let event_type = event_type.expect("checked above");
    if event_type != "NUM_OF_REGD_UES" && event_type != "NUM_OF_ESTD_PDU_SESSIONS" {
        return Err(Box::new(problem_details(
            400,
            "Bad Request",
            &format!("Unsupported eventType: {event_type}"),
            Some("INVALID_MSG_FORMAT"),
        )));
    }
    Ok((
        event_type.to_string(),
        event_filter
            .expect("checked above")
            .iter()
            .filter_map(SNssai::from_json)
            .collect(),
    ))
}

/// `PATCH /nnsacf-slice-ee/v1/subscriptions/{id}` — PartialModifySubscription
/// (TS 29.536 §5.3.2.2.3).
///
/// RFC 6902 JSON Patch (`application/json-patch+json`), per the OpenAPI — NOT an
/// RFC 7396 merge-patch, which is what the issue's "JSON-merge/JSON-patch style"
/// left open. Applied to a CLONE of the stored document and committed only if the
/// result still validates, so a bad patch cannot leave a half-modified
/// subscription.
async fn handle_slice_ee_modify_partial(
    subscription_id: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let Some(existing) = with_nsacf_context(|c| c.subscription_get(subscription_id)).flatten()
    else {
        return problem_details(
            404,
            "Not Found",
            &format!("Subscription {subscription_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        );
    };

    // TS 29.536 / TS 29.500: the media type is part of the contract, and a
    // consumer sending a merge-patch body under the wrong type must be told so
    // rather than have it applied as something else.
    let ctype = request
        .http
        .get_header("content-type")
        .cloned()
        .unwrap_or_default();
    if !ctype.contains("json-patch+json") {
        return problem_details(
            415,
            "Unsupported Media Type",
            "PartialModifySubscription requires application/json-patch+json (RFC 6902)",
            None,
        );
    }

    let Some(body) = &request.http.content else {
        return problem_details(
            400,
            "Bad Request",
            "Missing mandatory request body",
            Some("MANDATORY_IE_MISSING"),
        );
    };
    let patch: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return problem_details(
                400,
                "Bad Request",
                &format!("Invalid JSON patch: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };

    let mut doc = subscription_to_document(&existing);
    if let Err(e) = nextgcore_sbi::json_patch::apply_patch(&mut doc, &patch) {
        return problem_details(
            400,
            "Bad Request",
            &format!("Patch could not be applied: {e}"),
            Some("INVALID_MSG_FORMAT"),
        );
    }

    let (event_type, snssais) = match validate_subscription_doc(&doc) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let mut updated = build_subscription(subscription_id, &doc, &event_type, snssais);
    // A modification is not a new subscription: the report budget already spent
    // carries over, so a consumer cannot reset `maxReports` by patching.
    updated.report_count = existing.report_count;
    updated.over_threshold = existing.over_threshold;
    updated.last_report_at = existing.last_report_at;
    with_nsacf_context(|c| c.subscription_add(updated));

    log::info!("SliceEventExposure subscription {subscription_id} partially modified");
    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "subscription": doc,
            "subscriptionId": subscription_id,
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// `PUT /nnsacf-slice-ee/v1/subscriptions/{id}` — CompleteModifySubscription
/// (TS 29.536 §5.3.2.2.3): full replacement.
async fn handle_slice_ee_modify_complete(
    subscription_id: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let Some(existing) = with_nsacf_context(|c| c.subscription_get(subscription_id)).flatten()
    else {
        return problem_details(
            404,
            "Not Found",
            &format!("Subscription {subscription_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        );
    };

    let Some(body) = &request.http.content else {
        return problem_details(
            400,
            "Bad Request",
            "Missing mandatory request body",
            Some("MANDATORY_IE_MISSING"),
        );
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return problem_details(
                400,
                "Bad Request",
                &format!("Invalid JSON: {e}"),
                Some("INVALID_MSG_FORMAT"),
            )
        }
    };
    let (event_type, snssais) = match validate_subscription_doc(&data) {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let mut updated = build_subscription(subscription_id, &data, &event_type, snssais);
    updated.report_count = existing.report_count;
    updated.over_threshold = existing.over_threshold;
    updated.last_report_at = existing.last_report_at;
    with_nsacf_context(|c| c.subscription_add(updated));

    log::info!("SliceEventExposure subscription {subscription_id} replaced");
    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "subscription": data,
            "subscriptionId": subscription_id,
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Rebuild the `SACEventSubscription` document a stored subscription represents,
/// so a PATCH has something RFC 6902 pointers can address.
fn subscription_to_document(sub: &SacSubscription) -> serde_json::Value {
    let mut event = serde_json::json!({
        "eventType": sub.events.first().cloned().unwrap_or_default(),
        "eventFilter": sub.snssais.iter().map(|s| s.to_json()).collect::<Vec<_>>(),
        "immediateFlag": sub.immediate_flag,
    });
    if let Some(ref t) = sub.event_trigger {
        event["eventTrigger"] = serde_json::json!(t);
    }
    if let Some(ref th) = sub.notif_threshold {
        event["notifThreshold"] = th.clone();
    }
    if let Some(p) = sub.notification_period {
        event["notificationPeriod"] = serde_json::json!(p);
    }
    let mut doc = serde_json::json!({
        "event": event,
        "eventNotifyUri": sub.notification_uri,
        // `nfId` is mandatory on the schema and is not otherwise stored; the
        // subscription id stands in so a round-tripped document still validates.
        "nfId": sub.subscription_id,
    });
    if let Some(ref e) = sub.expiry {
        doc["expiry"] = serde_json::json!(e);
    }
    if let Some(m) = sub.max_reports {
        doc["maxReports"] = serde_json::json!(m);
    }
    if let Some(ref c) = sub.notify_correlation_id {
        doc["notifyCorrelationId"] = serde_json::json!(c);
    }
    doc
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

/// Fire EAC (early admission control) mode notifications to subscribers
/// interested in the slice (TS 23.502 §4.2.9.5). The body is an
/// `EacNotification` (TS 29.536 §6.1.6.2.4): an `eacModeList` map keyed by the
/// S-NSSAI with an `EACMode` value `"ACTIVE"`/`"DEACTIVE"` (§6.1.6.3.3) — NOT
/// the old `eacMode: "EAC_ACTIVE"/"EAC_INACTIVE"` scalar (nsacf-07). The
/// subscription's notificationUri is the EAC callback URI conveyed at
/// subscription time. `plmnIdNid` is optional and omitted (not tracked here).
fn spawn_eac_notifications(eac: EacTransition) {
    // EAC is an IMPLICIT subscription (TS 29.536 §5.2.2.3.2): the AMF supplies
    // eacNotificationUri in NumOfUEsUpdate; deliver to every registered EAC
    // callback URI, keyed by AMF nfId at subscription time.
    let uris = with_nsacf_context(|c| c.eac_notification_uris()).unwrap_or_default();
    if uris.is_empty() {
        return;
    }
    let mode = if eac.activated { "ACTIVE" } else { "DEACTIVE" };
    log::info!(
        "EAC mode {} for S-NSSAI[SST:{} SD:{:?}] -> notifying {} subscriber(s)",
        mode,
        eac.s_nssai.sst,
        eac.s_nssai.sd,
        uris.len()
    );
    let mut eac_mode_list = serde_json::Map::new();
    eac_mode_list.insert(
        eac.s_nssai.to_key(),
        serde_json::Value::String(mode.to_string()),
    );
    // Bare EacNotification (TS 29.536 §6.1.6.2.4): { eacModeList: map(EACMode) }.
    let body = serde_json::json!({ "eacModeList": eac_mode_list });
    for uri in uris {
        tokio::spawn(deliver_notification(uri, body.clone()));
    }
}

/// Fire slice event reports (current counts) to subscribers whose events
/// include UE/PDU count updates.
/// Why a report is being considered, so the trigger gate can be bypassed for the
/// one case the spec says is unconditional.
#[derive(Debug, Clone, Copy)]
enum ReportCause<'a> {
    /// An admission/release changed the slice occupancy: the trigger decides.
    Occupancy,
    /// `immediateFlag` at subscribe time (TS 29.536 §5.3.2.2.2): the named
    /// subscription reports once regardless of its trigger, because the consumer
    /// asked for the current state rather than for a change.
    Immediate(&'a str),
}

fn spawn_event_reports(s_nssai: &SNssai) {
    emit_reports_for(s_nssai, ReportCause::Occupancy);
}

/// Evaluate every matching subscription's trigger and deliver the reports that
/// are due.
///
/// Before #96 this fanned out a report to every matching subscriber on EVERY
/// admit/release, with no threshold, period, `maxReports` or expiry gating and no
/// `notifyCorrelationId` echoed — untenable for a consumer at any real scale.
fn emit_reports_for(s_nssai: &SNssai, cause: ReportCause<'_>) {
    let snapshot = with_nsacf_context(|c| {
        (
            c.subscriptions_matching(s_nssai),
            c.quota_find_by_snssai(s_nssai),
        )
    });
    let Some((subs, Some(quota))) = snapshot else {
        return;
    };
    // SACInfo percentages are the spec's 0..100 integer of current/max.
    let num_ues = quota.current_ues();
    let num_pdu = quota.current_pdu_sessions();
    let perc_ues = (num_ues * 100)
        .checked_div(quota.max_ues)
        .unwrap_or(0)
        .min(100);
    let perc_pdu = (num_pdu * 100)
        .checked_div(quota.max_pdu_sessions)
        .unwrap_or(0)
        .min(100);
    let time_stamp = chrono::Utc::now().to_rfc3339();
    let now = nextgcore_sbi::datetime::now_epoch_secs();

    for sub in subs {
        // TS 29.536 §6.2.6.3.3 SACEventType: only the two count events report here.
        let event_type = match sub.events.first() {
            Some(t) if t == "NUM_OF_REGD_UES" || t == "NUM_OF_ESTD_PDU_SESSIONS" => t.clone(),
            _ => continue,
        };

        let over_now = sub.over_threshold_now(
            num_ues as u32,
            perc_ues as u32,
            num_pdu as u32,
            perc_pdu as u32,
        );

        let emit = match cause {
            // An immediate report is for ONE named subscription; every other
            // matching subscription is untouched by a subscribe.
            ReportCause::Immediate(id) => {
                if sub.subscription_id != id {
                    continue;
                }
                true
            }
            ReportCause::Occupancy => {
                match sub.report_decision(
                    num_ues as u32,
                    perc_ues as u32,
                    num_pdu as u32,
                    perc_pdu as u32,
                    now,
                ) {
                    context::ReportDecision::Emit => true,
                    context::ReportDecision::Suppress => {
                        // The edge state still has to be recorded, or a level that
                        // falls back below the threshold would never re-arm and the
                        // next crossing would be silent.
                        with_nsacf_context(|c| {
                            c.subscription_note_threshold(&sub.subscription_id, over_now)
                        });
                        continue;
                    }
                    context::ReportDecision::Exhausted => {
                        log::info!(
                            "SliceEventExposure subscription {} is spent (maxReports or \
                             expiry); removing",
                            sub.subscription_id
                        );
                        with_nsacf_context(|c| c.subscription_remove(&sub.subscription_id));
                        continue;
                    }
                }
            }
        };
        if !emit {
            continue;
        }

        // TS 29.536 §6.2.6.2.4 SACEventReport { report: SACEventReportItem } with
        // mandatory eventType/eventState/timeStamp/eventFilter and the SACEventStatus
        // counts (note the spec's `sliceStautsInfo` typo, emitted verbatim).
        let mut body = serde_json::json!({
            "report": {
                "eventType": event_type,
                "eventState": { "active": true },
                "timeStamp": time_stamp.clone(),
                "eventFilter": quota.s_nssai.to_json(),
                "sliceStautsInfo": {
                    "reachedNumUes": {
                        "numericValNumUes": num_ues,
                        "percValueNumUes": perc_ues,
                    },
                    "reachedNumPduSess": {
                        "numericValNumPduSess": num_pdu,
                        "percValueNumPduSess": perc_pdu,
                    },
                },
            }
        });
        // Echoed so the consumer can tie the notification to the subscription
        // that produced it (TS 29.536 §5.3.2.2.2). Absent when the consumer set
        // none, rather than invented.
        if let Some(ref cid) = sub.notify_correlation_id {
            body["notifyCorrelationId"] = serde_json::json!(cid);
        }

        // Charged and the edge recorded BEFORE the send: delivery is a spawned
        // task, so waiting for it would let a burst of admits each pass the
        // maxReports check before any of them incremented the counter.
        with_nsacf_context(|c| c.subscription_note_report(&sub.subscription_id, over_now, now));
        tokio::spawn(deliver_notification(sub.notification_uri, body));
    }
}

// ---------------------------------------------------------------------------
// NRF interaction
// ---------------------------------------------------------------------------

/// `apiFullVersion` advertised for both Nnsacf services.
///
/// TS 29.536 is a single specification covering `Nnsacf_NSAC` and
/// `Nnsacf_SliceEventExposure`, and both vendored OpenAPI documents carry
/// `info.version: 1.3.0-alpha.1`. The profile hardcoded `1.1.0`, which told the
/// NRF (and any consumer reading the profile) that this NSACF implements an older
/// revision than the contract it is built against. Kept as one named constant so
/// the two services cannot drift apart, and so the next vendored-spec bump has a
/// single place to change.
const NSACF_API_FULL_VERSION: &str = "1.3.0";

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
            "serviceName": nextgcore_sbi::types::SbiServiceType::NnsacfNsac.to_name(),
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": NSACF_API_FULL_VERSION}],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}],
            // nsacf-11: advertise SupportedFeatures with HNSAC/VHNSAC bits clear
            // so consumers never expect home/visited delegation (ueAdmissionList).
            "supportedFeatures": SUPPORTED_FEATURES,
            // TS 29.510 §6.1.6.2.3: per-service scoping. NSAC is consumed by the
            // AMF/SMF (and an SCP forwarding for them).
            "allowedNfTypes": ["AMF", "SMF", "SCP"]
        }, {
            "serviceInstanceId": format!("{}-nnsacf-slice-ee", nf_instance_id),
            // Named from the typed service enum rather than a literal, so the
            // registered name cannot drift from the one consumers select by.
            "serviceName": nextgcore_sbi::types::SbiServiceType::NnsacfSliceEe.to_name(),
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": NSACF_API_FULL_VERSION}],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}],
            "supportedFeatures": SUPPORTED_FEATURES,
            // #96: AF and DCCF added. TS 29.536 §5.3.2.2.2 names both among the
            // legitimate Slice-EE consumers, and omitting them meant the NRF would
            // not issue either a token scoped to this service.
            "allowedNfTypes": ["NEF", "NWDAF", "AF", "DCCF", "SCP"]
        }],
        // The NF-level list is the UNION over the services: a consumer type barred
        // here can never reach any of them.
        "allowedNfTypes": ["AMF", "SMF", "SCP", "NEF", "NWDAF", "AF", "DCCF"],
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

            let mut self_instance = nextgcore_sbi::context::NfInstance::new(
                nf_instance_id,
                nextgcore_sbi::types::NfType::Nsacf,
            );
            self_instance.ipv4_addresses = vec![sbi_addr.to_string()];
            let mut svc = nextgcore_sbi::context::NfService::new(
                "nnsacf-nsac",
                nextgcore_sbi::types::SbiServiceType::NnsacfNsac,
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

    /// Issue #27: the `nsacf.sla` field is a raw Value precisely so a
    /// malformed block can NEVER fail the whole config parse (which would
    /// silently drop slice_quotas provisioning and reject every admission).
    #[test]
    fn test_malformed_sla_block_does_not_break_config_parse() {
        let yaml = r#"
nsacf:
  slice_quotas:
    - sst: 1
      max_ues: 10
  sla: "this is not a mapping"
"#;
        let parsed: NsacfYaml = serde_yaml::from_str(yaml).expect("whole parse must survive");
        let nsacf = parsed.nsacf.expect("nsacf section");
        assert_eq!(nsacf.slice_quotas.as_deref().map(|q| q.len()), Some(1));
        assert!(nsacf.sla.is_some(), "raw sla value captured verbatim");
    }
    use super::*;
    use nextgcore_sbi::client::SbiClient;
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
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

    /// Serializes every test that touches the PROCESS-GLOBAL NSACF context.
    /// `start_nsacf_server*` re-inits (wipes) the shared store, so two such
    /// tests running on parallel test threads corrupt each other's quota/UE
    /// counts mid-flight — the CI-flaky EAC-notification failure (and the
    /// occasional HTTP/2 connection error) were exactly this race. The guard
    /// is returned and must be held for the whole test (bind it, even as
    /// `_ctx_guard` — a bare `_` would drop it immediately).
    static GLOBAL_CTX_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn start_nsacf_server() -> (SbiServer, u16, tokio::sync::MutexGuard<'static, ()>) {
        let guard = GLOBAL_CTX_TEST_LOCK.lock().await;
        nsacf_context_init(64);
        let (port_listener, port_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let port = port_addr.port();
        let server = SbiServer::on_listener(
            SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port))),
            port_listener,
        );
        server
            .start(nsacf_sbi_request_handler)
            .await
            .expect("server start");
        (server, port, guard)
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
    async fn start_nsacf_server_oauth2(
        jwks: serde_json::Value,
    ) -> (SbiServer, u16, tokio::sync::MutexGuard<'static, ()>) {
        let guard = GLOBAL_CTX_TEST_LOCK.lock().await;
        nsacf_context_init(64);
        let (port_listener, port_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let port = port_addr.port();
        let mut cfg = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(jwks);
        cfg = cfg.with_expected_audience_nf_type(NfType::Nsacf);
        let server = SbiServer::on_listener(cfg, port_listener);
        server
            .start(nsacf_sbi_request_handler)
            .await
            .expect("server start");
        (server, port, guard)
    }

    #[test]
    fn test_yaml_oauth2_require_parses() {
        let yaml =
            "nsacf:\n  sbi:\n    oauth2:\n      require: true\n  nrf:\n    uri: http://nrf:7777\n";
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
    fn test_yaml_slice_quotas_parse() {
        // Regression: the docker/E2E config provisions quotas via
        // nsacf.slice_quotas; before this parse existed the NSACF booted with
        // an empty quota table and 403'd every PDU-session admission.
        let yaml = "nsacf:\n  slice_quotas:\n    - sst: 1\n      max_ues: 1000\n    - sst: 2\n      sd: \"00007b\"\n      max_ues: 500\n      max_pdu_sessions: 200\n";
        let parsed: NsacfYaml = serde_yaml::from_str(yaml).unwrap();
        let quotas = parsed.nsacf.unwrap().slice_quotas.unwrap();
        assert_eq!(quotas.len(), 2);
        assert_eq!(quotas[0].sst, 1);
        assert_eq!(quotas[0].sd, None);
        assert_eq!(quotas[0].max_ues, Some(1000));
        assert_eq!(quotas[0].max_pdu_sessions, None); // absent => uncapped, NOT zero
        assert_eq!(quotas[1].sst, 2);
        assert_eq!(
            u32::from_str_radix(quotas[1].sd.as_deref().unwrap(), 16).unwrap(),
            0x7b
        );
        assert_eq!(quotas[1].max_pdu_sessions, Some(200));
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
        let (server, port, _ctx_guard) =
            start_nsacf_server_oauth2(jwks_for(&sk, "nrf-es256")).await;
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
        let (server, port, _ctx_guard) =
            start_nsacf_server_oauth2(jwks_for(&sk, "nrf-es256")).await;
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
        let (server, port, _ctx_guard) =
            start_nsacf_server_oauth2(jwks_for(&sk, "nrf-es256")).await;
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

    /// Create a slice quota via the admin extension, returning its `quotaId` so a
    /// test can `GET /slice-quotas/{id}` to inspect membership counts (#95: the
    /// per-access counts live there now that `roaming-quotas` carries the spec's
    /// `QuotaUpdateResponseData`, which has ceilings only).
    async fn create_quota(client: &SbiClient, sst: u8, max_ues: u64, max_pdu: u64) -> String {
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slice-quotas",
                &json!({"sNssai": {"sst": sst}, "maxUes": max_ues, "maxPduSessions": max_pdu}),
            )
            .await
            .expect("quota create");
        assert_eq!(resp.status, 201);
        let v: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        v["quotaId"].as_str().expect("quotaId").to_string()
    }

    /// Read a quota's membership state from the admin extension.
    async fn get_quota(client: &SbiClient, quota_id: &str) -> serde_json::Value {
        let resp = client
            .get(&format!("/nnsacf-nsac/v1/slice-quotas/{quota_id}"))
            .await
            .expect("quota get");
        assert_eq!(resp.status, 200);
        serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap()
    }

    /// A spec `ACUpdateData` body (TS 29.536 §5.2.2.5.2), optionally carrying the
    /// NextGCore per-access ceiling extension.
    fn ac_update_data(sst: u8, max_ues: u64, max_pdu: u64) -> serde_json::Value {
        json!({
            "snssai": {"sst": sst},
            "maxUesNumber": max_ues,
            "maxPdusNumber": max_pdu,
        })
    }

    /// A spec `QuotaUpdateRequestData` body (TS 29.536 §5.2.2.6.2): all three
    /// members are required.
    fn quota_update_request(sst: u8) -> serde_json::Value {
        json!({
            "snssai": {"sst": sst},
            "plmnId": {"mcc": "262", "mnc": "01"},
            "quotaType": "NUM_OF_UES",
        })
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
        let (server, port, _ctx_guard) = start_nsacf_server().await;
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
            !resp
                .http
                .content
                .as_deref()
                .unwrap()
                .contains("admittedFlag"),
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
        let (server, port, _ctx_guard) = start_nsacf_server().await;
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

        // Unknown updateFlag (not INCREASE/DECREASE/UPDATE) -> 400 INVALID_IE_VALUE.
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
        let (server, port, _ctx_guard) = start_nsacf_server().await;
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

    /// Closes the #96 verification ceiling: BOTH spawned dispatches are observed
    /// arriving at a real receiver, not merely constructed.
    ///
    /// `test_http_slice_ee_subscription_and_eac_notification` below sees an EAC
    /// notification that follows a mode TRANSITION, and
    /// `eac_mode_list_and_first_subscription_detection` covers the mode-list
    /// construction and the first/repeat decision as pure logic. Neither observes
    /// the two dispatches that happen at SUBSCRIBE time, both of which go through
    /// `tokio::spawn` and so are invisible to a test that only checks the 201:
    ///
    /// 1. the `immediateFlag` report (TS 29.536 5.3.2.2.2), and
    /// 2. the immediate EAC notification on a FIRST subscription (5.2.2.2.2).
    ///
    /// The two negatives are what make the positives mean something: without the
    /// flag nothing is reported at subscribe time, and a REPEAT EAC subscription
    /// from the same `nfId` is not re-notified.
    #[tokio::test]
    async fn subscribe_time_dispatches_actually_arrive_at_the_consumer() {
        let (server, port, _ctx_guard) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        let (recv_listener, recv_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let recv_port = recv_addr.port();
        let receiver = SbiServer::on_listener(
            SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], recv_port))),
            recv_listener,
        );
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
        let cb = format!("http://127.0.0.1:{recv_port}/cb");

        // A quota so the slice has a mode to report at all. Without one,
        // `eac_mode_list()` is empty and the immediate EAC notification is
        // deliberately NOT sent (an empty eacModeList would assert "no slices"
        // rather than "nothing configured yet").
        create_quota(&client, 96, 10, 100).await;

        // ── 1. immediateFlag: a report must arrive with no admission at all ──
        //
        // The trigger is REACHING_THRESHOLD with a threshold of 90%, and occupancy
        // is 0%, so the trigger gate would SUPPRESS this report. It arrives only
        // because `immediateFlag` bypasses the gate — which is the whole point of
        // 5.3.2.2.2 and cannot be observed from the 201 alone.
        let resp = client
            .post_json(
                "/nnsacf-slice-ee/v1/subscriptions",
                &json!({
                    "eventNotifyUri": cb,
                    "nfId": "amf-96-immediate",
                    "notifyCorrelationId": "corr-96-immediate",
                    "event": {
                        "eventType": "NUM_OF_REGD_UES",
                        "eventFilter": [{"sst": 96}],
                        "eventTrigger": "REACHING_THRESHOLD",
                        "notifThreshold": 90,
                        "immediateFlag": true
                    }
                }),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 201);

        let mut immediate_report: Option<serde_json::Value> = None;
        for _ in 0..8 {
            let Ok(Some(text)) = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await
            else {
                break;
            };
            let v: serde_json::Value = serde_json::from_str(&text).expect("JSON body");
            if v["notifyCorrelationId"] == "corr-96-immediate" {
                immediate_report = Some(v);
                break;
            }
        }
        let report = immediate_report.expect(
            "immediateFlag must produce a report AT SUBSCRIBE TIME, with no admission and              despite the trigger gate",
        );
        // The SACEventReport shape (TS 29.536 6.2.6.2.4), so this cannot pass on a
        // bare POST that carries nothing useful.
        assert_eq!(report["report"]["eventFilter"]["sst"], 96);
        assert!(
            report["report"]["sliceStautsInfo"]["reachedNumUes"]["numericValNumUes"].is_number(),
            "the immediate report carries the CURRENT counts: {report}"
        );

        // ── 2. the negative: no immediateFlag means nothing at subscribe time ──
        let resp = client
            .post_json(
                "/nnsacf-slice-ee/v1/subscriptions",
                &json!({
                    "eventNotifyUri": cb,
                    "nfId": "amf-96-quiet",
                    "notifyCorrelationId": "corr-96-quiet",
                    "event": {
                        "eventType": "NUM_OF_REGD_UES",
                        "eventFilter": [{"sst": 96}],
                        "eventTrigger": "REACHING_THRESHOLD",
                        "notifThreshold": 90
                    }
                }),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 201);
        // A short window is enough: the dispatch is a spawned task that would run
        // immediately, and the previous report proves the receiver is live.
        let quiet = tokio::time::timeout(Duration::from_millis(400), rx.recv()).await;
        if let Ok(Some(text)) = quiet {
            let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
            assert_ne!(
                v["notifyCorrelationId"], "corr-96-quiet",
                "a subscription WITHOUT immediateFlag must not report at subscribe time: {v}"
            );
        }

        // ── 3. the immediate EAC notification on a FIRST subscription ──
        //
        // A NumOfUEsUpdate carrying `eacNotificationUri` is the implicit EAC
        // subscription. This nfId has not subscribed before, so 5.2.2.2.2 requires
        // the current modes immediately — again a spawned dispatch.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({
                    "nfId": "amf-96-eac",
                    "eacNotificationUri": cb,
                    "ueACRequestInfo": [{
                        "supi": "imsi-96-1",
                        "anType": "3GPP_ACCESS",
                        "acuOperationList": [{ "updateFlag": "INCREASE", "snssai": {"sst": 96} }]
                    }]
                }),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204);

        let mut saw_mode_list = false;
        for _ in 0..8 {
            let Ok(Some(text)) = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await
            else {
                break;
            };
            let v: serde_json::Value = serde_json::from_str(&text).expect("JSON body");
            if v.get("eacModeList").is_some() {
                // The 6.1.6.2.4 shape: a map keyed by S-NSSAI, not the old
                // `eacMode` scalar.
                assert!(
                    v["eacModeList"].is_object(),
                    "eacModeList is a map(EACMode): {v}"
                );
                assert!(
                    v["eacModeList"]["96"].is_string(),
                    "the immediate notification names the subscribed S-NSSAI's mode: {v}"
                );
                saw_mode_list = true;
                break;
            }
        }
        assert!(
            saw_mode_list,
            "a FIRST EAC subscription must immediately receive the current EAC modes"
        );

        // ── 4. the negative: a REPEAT subscription from the same nfId is silent ──
        //
        // An AMF re-sends its eacNotificationUri on every NumOfUEsUpdate, so
        // re-notifying each time would flood it.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({
                    "nfId": "amf-96-eac",
                    "eacNotificationUri": cb,
                    "ueACRequestInfo": [{
                        "supi": "imsi-96-2",
                        "anType": "3GPP_ACCESS",
                        "acuOperationList": [{ "updateFlag": "INCREASE", "snssai": {"sst": 96} }]
                    }]
                }),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204);
        // Drain briefly: an occupancy report may legitimately arrive for the
        // immediateFlag subscription, but no second eacModeList may.
        let deadline = tokio::time::Instant::now() + Duration::from_millis(600);
        while tokio::time::Instant::now() < deadline {
            let Ok(Some(text)) = tokio::time::timeout(Duration::from_millis(150), rx.recv()).await
            else {
                continue;
            };
            let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
            assert!(
                v.get("eacModeList").is_none(),
                "a repeat EAC subscription from the same nfId must not be re-notified: {v}"
            );
        }

        receiver.stop().await.expect("receiver stops");
        server.stop().await.expect("server stops");
    }

    #[tokio::test]
    async fn test_http_slice_ee_subscription_and_eac_notification() {
        let (server, port, _ctx_guard) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        // Notification receiver
        let (recv_listener, recv_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let recv_port = recv_addr.port();
        let receiver = SbiServer::on_listener(
            SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], recv_port))),
            recv_listener,
        );
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

        // Missing mandatory nfId/event -> 400
        let resp = client
            .post_json(
                "/nnsacf-slice-ee/v1/subscriptions",
                &json!({"eventNotifyUri": format!("http://127.0.0.1:{recv_port}/cb")}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 400);
        assert!(resp.http.content.as_deref().unwrap().contains("nfId"));

        // Valid SACEventSubscription for slice 74 (TS 29.536 §6.2.6.2.2)
        let resp = client
            .post_json(
                "/nnsacf-slice-ee/v1/subscriptions",
                &json!({
                    "eventNotifyUri": format!("http://127.0.0.1:{recv_port}/cb"),
                    "nfId": "amf-1",
                    "event": {
                        "eventType": "NUM_OF_REGD_UES",
                        "eventFilter": [{"sst": 74}]
                    }
                }),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 201);
        let created: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        // 201 CreatedSACEventSubscription echoes the SACEventSubscription.
        assert_eq!(
            created["subscription"]["event"]["eventType"],
            "NUM_OF_REGD_UES"
        );
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
            // Each NumOfUEsUpdate carries the EAC callback URI -> implicit EAC
            // subscription for amf-1 (TS 29.536 §5.2.2.3.2).
            let resp = client
                .post_json(
                    "/nnsacf-nsac/v1/slices/ues",
                    &json!({
                        "nfId": "amf-1",
                        "eacNotificationUri": format!("http://127.0.0.1:{recv_port}/cb"),
                        "ueACRequestInfo": [{
                            "supi": format!("imsi-74-{i}"),
                            "anType": "3GPP_ACCESS",
                            "acuOperationList": [{ "updateFlag": "INCREASE", "snssai": {"sst": 74} }]
                        }]
                    }),
                )
                .await
                .expect("response");
            assert_eq!(resp.status, 204);
        }

        // Expect at least one EacNotification with eacModeList["74"]=="ACTIVE"
        // (TS 29.536 §6.1.6.2.4 shape, nsacf-07). Count reports may arrive
        // first; parse each and scan until found, bounded by timeout per recv.
        // The old `eacMode: "EAC_ACTIVE"` scalar must NOT appear.
        let mut saw_eac_active = false;
        for _ in 0..8 {
            let Ok(Some(notif)) = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await
            else {
                break;
            };
            assert!(
                !notif.contains("EAC_ACTIVE") && !notif.contains("eacMode\""),
                "old EAC scalar shape must be gone"
            );
            let v: serde_json::Value = serde_json::from_str(&notif).unwrap();
            // A SACEventReport (TS 29.536 §6.2.6.2.4), when present, must carry the
            // spec shape: report.eventState.active + sliceStautsInfo counts.
            if v.get("report").is_some() {
                assert_eq!(v["report"]["eventState"]["active"], true);
                assert_eq!(v["report"]["eventFilter"]["sst"], 74);
                assert!(
                    v["report"]["sliceStautsInfo"]["reachedNumUes"]["numericValNumUes"].is_number()
                );
            }
            if v["eacModeList"]["74"] == "ACTIVE" {
                saw_eac_active = true;
                break;
            }
        }
        assert!(
            saw_eac_active,
            "expected EacNotification eacModeList ACTIVE"
        );

        // Release below threshold -> EacNotification eacModeList "DEACTIVE"
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
            let v: serde_json::Value = serde_json::from_str(&notif).unwrap();
            if v["eacModeList"]["74"] == "DEACTIVE" {
                saw_eac_inactive = true;
                break;
            }
        }
        assert!(
            saw_eac_inactive,
            "expected EacNotification eacModeList DEACTIVE"
        );

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
        assert_eq!(
            AcuFailureReason::ExceedMaxUeNum.as_str(),
            "EXCEED_MAX_UE_NUM"
        );
        assert_eq!(
            AcuFailureReason::ExceedMaxPduNum.as_str(),
            "EXCEED_MAX_PDU_NUM"
        );
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
        let (server, port, _ctx_guard) = start_nsacf_server().await;
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
        let (server, port, _ctx_guard) = start_nsacf_server().await;
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
        assert!(!resp
            .http
            .content
            .as_deref()
            .unwrap()
            .contains("admittedFlag"));

        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn test_http_ue_partial_failure_slice_not_found() {
        let (server, port, _ctx_guard) = start_nsacf_server().await;
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
        let (server, port, _ctx_guard) = start_nsacf_server().await;
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
        let (server, port, _ctx_guard) = start_nsacf_server().await;
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

    // -----------------------------------------------------------------
    // nsacf-05: per-access-type counting + _3GPP/_N3GPP reason over the wire
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn test_http_per_access_ue_counting_and_reason() {
        let (server, port, _ctx_guard) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        // Provision per-access ceilings via the local-configs custom op: 1 UE
        // per access, aggregate room for 10. #95: the request is now a spec
        // `ACUpdateData` object and the response is 204 with no body, so the
        // ceilings are read back from the admin resource instead.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/local-configs/update",
                &json!({
                    "snssai": {"sst": 90}, "maxUesNumber": 10, "maxPdusNumber": 50,
                    "maxUes3gpp": 1, "maxUesN3gpp": 1
                }),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204);
        assert!(
            resp.http.content.as_deref().unwrap_or("").is_empty(),
            "§5.2.2.5.2 requires an EMPTY body"
        );

        // First 3GPP UE admits -> the 3GPP bucket is now full (1/1).
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"nfId": "amf-1", "ueACRequestInfo": [{
                    "supi": "imsi-90-a", "anType": "3GPP_ACCESS",
                    "acuOperationList": [{"updateFlag": "INCREASE", "snssai": {"sst": 90}}]
                }]}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204);

        // Mixed request: an N3GPP UE admits (its bucket has room) while a 2nd
        // 3GPP UE fails per-access -> partial 200 with EXCEED_MAX_UE_NUM_3GPP.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"nfId": "amf-1", "ueACRequestInfo": [
                    {"supi": "imsi-90-c", "anType": "NON_3GPP_ACCESS",
                     "acuOperationList": [{"updateFlag": "INCREASE", "snssai": {"sst": 90}}]},
                    {"supi": "imsi-90-d", "anType": "3GPP_ACCESS",
                     "acuOperationList": [{"updateFlag": "INCREASE", "snssai": {"sst": 90}}]}
                ]}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 200);
        let v: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(
            v["acuFailureList"]["imsi-90-c"].is_null(),
            "the N3GPP UE admitted"
        );
        assert_eq!(
            v["acuFailureList"]["imsi-90-d"][0]["reason"],
            "EXCEED_MAX_UE_NUM_3GPP"
        );

        server.stop().await.expect("stop");
    }

    // -----------------------------------------------------------------
    // nsacf-06: AcuFlag UPDATE moves the access bucket without double-counting
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn test_http_ue_update_moves_access_bucket() {
        let (server, port, _ctx_guard) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let quota_id = create_quota(&client, 91, 10, 100).await;

        // Admit imsi-91 on 3GPP.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &ue_ac_body("imsi-91", "INCREASE", 91),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204);

        // UPDATE to non-3GPP -> 204 (entry located and moved).
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"nfId": "amf-1", "ueACRequestInfo": [{
                    "supi": "imsi-91", "anType": "NON_3GPP_ACCESS",
                    "acuOperationList": [{"updateFlag": "UPDATE", "snssai": {"sst": 91}}]
                }]}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204, "UPDATE of a known member -> 204");

        // The admin quota resource confirms: aggregate unchanged (1), 3GPP=0,
        // N3GPP=1. #95 moved the per-access counts here from the roaming-quotas
        // response, which is now the spec's ceilings-only QuotaUpdateResponseData.
        let v = get_quota(&client, &quota_id).await;
        assert_eq!(v["currentUes"], 1, "no double-count");
        assert_eq!(v["currentUes3gpp"], 0, "UPDATE moved the UE out of 3GPP");
        assert_eq!(v["currentUesN3gpp"], 1);

        // Mixed request: a fresh INCREASE + an UPDATE for an unknown member ->
        // partial 200 with acuFailureList SLICE_NOT_FOUND for the unknown.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"nfId": "amf-1", "ueACRequestInfo": [
                    {"supi": "imsi-91-b", "anType": "3GPP_ACCESS",
                     "acuOperationList": [{"updateFlag": "INCREASE", "snssai": {"sst": 91}}]},
                    {"supi": "imsi-unknown", "anType": "3GPP_ACCESS",
                     "acuOperationList": [{"updateFlag": "UPDATE", "snssai": {"sst": 91}}]}
                ]}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 200);
        let v: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(
            v["acuFailureList"]["imsi-unknown"][0]["reason"],
            "SLICE_NOT_FOUND"
        );
        assert!(v["acuFailureList"]["imsi-91-b"].is_null());

        server.stop().await.expect("stop");
    }

    // -----------------------------------------------------------------
    // nsacf-08 / #95: custom operations local-configs/update +
    // roaming-quotas/query, on the TS 29.536 wire shapes
    // -----------------------------------------------------------------

    /// **Issue #95, gap 2.** LocalConfigurations update takes an `ACUpdateData`
    /// and answers `204 No Content` with an **empty** body (§5.2.2.5.2).
    ///
    /// It used to require a bespoke `localConfigurations` ARRAY envelope with
    /// `maxUes`/`maxPduSessions` and answer `200` with a
    /// `{localConfigurations, supportedFeatures}` body. An OSS/BSS or OAM system
    /// driving slice limits speaks `ACUpdateData` and would not have interworked
    /// with either half of that.
    #[tokio::test]
    async fn test_http_local_configs_update_is_ac_update_data_and_204() {
        let (server, port, _ctx_guard) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/local-configs/update",
                &ac_update_data(65, 7, 9),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204, "§5.2.2.5.2 requires 204 No Content");
        assert!(
            resp.http.content.as_deref().unwrap_or("").is_empty(),
            "§5.2.2.5.2 requires an empty body, got {:?}",
            resp.http.content
        );

        // The update really applied: read it back through the spec query.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/roaming-quotas/query",
                &quota_update_request(65),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 200);
        let v: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(v["maxUesNumber"], 7);
        assert_eq!(v["maxPdusNumber"], 9);

        // `snssai` is the only mandatory member -> its absence is 400
        // MANDATORY_IE_MISSING. The bespoke `localConfigurations` envelope is now
        // just an unknown member, so a body carrying ONLY it is also rejected:
        // that is the discriminating case, because a handler that still accepted
        // the old shape would pass the plain-`{}` check while ignoring the spec.
        for body in [
            json!({}),
            json!({"localConfigurations": [{"snssai": {"sst": 65}}]}),
        ] {
            let resp = client
                .post_json("/nnsacf-nsac/v1/slices/local-configs/update", &body)
                .await
                .expect("response");
            assert_eq!(resp.status, 400, "body {body} must be rejected");
            assert!(resp
                .http
                .content
                .as_deref()
                .unwrap()
                .contains("MANDATORY_IE_MISSING"));
        }

        // An update naming only maxPdusNumber must NOT reset the UE ceiling.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/local-configs/update",
                &json!({"snssai": {"sst": 65}, "maxPdusNumber": 11}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204);
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/roaming-quotas/query",
                &quota_update_request(65),
            )
            .await
            .expect("response");
        let v: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(v["maxUesNumber"], 7, "the omitted UE ceiling must be KEPT");
        assert_eq!(v["maxPdusNumber"], 11);

        // And the per-access ceilings survive an update that names none of them.
        // `ACUpdateData` is a single OBJECT rather than the old full-configuration
        // array, so a partial update must not erase what a previous call installed.
        // Asserted through BEHAVIOUR rather than by reading the ceiling back,
        // because the per-access limits are not on any response body: install
        // maxUes3gpp=1, then send a ceiling-free update, then check the ceiling
        // still bites. (This test exists because reverting the carry-over broke
        // nothing at first — the `maxUesNumber` assertion above did not cover it.)
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/local-configs/update",
                &json!({"snssai": {"sst": 65}, "maxUesNumber": 10, "maxUes3gpp": 1}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204);
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/local-configs/update",
                &json!({"snssai": {"sst": 65}, "maxPdusNumber": 12}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204);

        let admit = |supi: &'static str| {
            let client = &client;
            async move {
                client
                    .post_json(
                        "/nnsacf-nsac/v1/slices/ues",
                        &json!({"nfId": "amf-1", "ueACRequestInfo": [{
                            "supi": supi, "anType": "3GPP_ACCESS",
                            "acuOperationList": [
                                {"updateFlag": "INCREASE", "snssai": {"sst": 65}}
                            ]
                        }]}),
                    )
                    .await
                    .expect("response")
            }
        };
        assert_eq!(
            admit("imsi-65-a").await.status,
            204,
            "1/1 of the 3GPP ceiling"
        );
        let resp = admit("imsi-65-b").await;
        assert_eq!(
            resp.status, 403,
            "the maxUes3gpp=1 ceiling must survive a ceiling-free ACUpdateData"
        );
        assert!(resp
            .http
            .content
            .as_deref()
            .unwrap()
            .contains("ALL_SLICE_FAILED"));

        server.stop().await.expect("stop");
    }

    /// **Issue #95, gap 3.** RoamingQuotas takes a `QuotaUpdateRequestData` with
    /// `snssai`, `plmnId` and `quotaType` all **required**, and answers with a
    /// `QuotaUpdateResponseData` `{snssai, maxUesNumber, maxPdusNumber}`
    /// (§5.2.2.6.2 / §5.3.2.4.1).
    ///
    /// It used to treat the body as optional, ignore all three mandatory IEs, read
    /// a bespoke `snssais` array as a filter, and answer
    /// `{roamingQuotas: [...], supportedFeatures}`.
    #[tokio::test]
    async fn test_http_roaming_quotas_is_quota_update_data() {
        let (server, port, _ctx_guard) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        create_quota(&client, 63, 7, 9).await;

        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/roaming-quotas/query",
                &quota_update_request(63),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 200);
        let v: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(v["snssai"]["sst"], 63);
        assert_eq!(v["maxUesNumber"], 7);
        assert_eq!(v["maxPdusNumber"], 9);
        // The bespoke response shape is gone, not merely joined by the new one:
        // a peer NSACF that still reads `roamingQuotas` must fail loudly.
        assert!(v.get("roamingQuotas").is_none());
        assert!(v.get("supportedFeatures").is_none());

        // Each mandatory IE, dropped one at a time -> 400 MANDATORY_IE_MISSING.
        // Dropping them one at a time rather than all together is what pins that
        // ALL THREE are enforced: an implementation checking only `snssai` would
        // pass an all-empty body check.
        for missing in ["snssai", "plmnId", "quotaType"] {
            let mut body = quota_update_request(63);
            body.as_object_mut().unwrap().remove(missing);
            let resp = client
                .post_json("/nnsacf-nsac/v1/slices/roaming-quotas/query", &body)
                .await
                .expect("response");
            assert_eq!(
                resp.status, 400,
                "a body with no {missing} must be rejected"
            );
            assert!(
                resp.http
                    .content
                    .as_deref()
                    .unwrap()
                    .contains("MANDATORY_IE_MISSING"),
                "missing {missing} must be MANDATORY_IE_MISSING"
            );
        }

        // A `plmnId` that is present but names no PLMN is not a plmnId: the
        // mandatory IE must not be satisfiable by an empty object.
        for bad_plmn in [
            json!({}),
            json!(null),
            json!({"mcc": "262"}),
            json!({"mcc": "", "mnc": "01"}),
        ] {
            let mut body = quota_update_request(63);
            body["plmnId"] = bad_plmn.clone();
            let resp = client
                .post_json("/nnsacf-nsac/v1/slices/roaming-quotas/query", &body)
                .await
                .expect("response");
            assert_eq!(resp.status, 400, "plmnId {bad_plmn} must be rejected");
        }

        // An unconfigured S-NSSAI is 404, not an empty 200: "no quota" and "a
        // quota of zero" are different answers to a partner NSACF.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/roaming-quotas/query",
                &quota_update_request(64),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 404);

        server.stop().await.expect("stop");
    }

    // -----------------------------------------------------------------
    // nsacf-09 / #95 gap 1: nfId is mandatory on the UE resource and OPTIONAL on
    // the PDU resource — the asymmetry TS 29.536 actually specifies
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn test_http_ac_missing_nf_id() {
        let (server, port, _ctx_guard) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        create_quota(&client, 66, 10, 100).await;

        // UE AC body WITHOUT nfId -> 400 MANDATORY_IE_MISSING. `nfId` IS mandatory
        // in `UeACRequestData` (nsacf-09), and #95 does not touch that.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"ueACRequestInfo": [{
                    "supi": "imsi-1", "anType": "3GPP_ACCESS",
                    "acuOperationList": [{"updateFlag": "INCREASE", "snssai": {"sst": 66}}]
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

        // **Issue #95, gap 1.** PDU AC body WITHOUT nfId is ACCEPTED: Table
        // 6.1.6.2.7-1 lists `pduACRequestInfo` as the ONLY required attribute of
        // `PduACRequestData`. It used to be a non-Option String, so a conformant
        // SMF/PGW-C identifying itself by `pgwFqdn` was turned away with 400 and
        // PDU-session number control silently failed against off-the-shelf NFs.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/pdus",
                &json!({"pduACRequestInfo": [{
                    "supi": "imsi-1", "anType": "3GPP_ACCESS", "pduSessionId": 1,
                    "acuOperationList": [{"updateFlag": "INCREASE", "snssai": {"sst": 66}}]
                }]}),
            )
            .await
            .expect("response");
        assert_eq!(
            resp.status, 204,
            "a PduACRequestData with no nfId is conformant and must be admitted"
        );

        // The other three optional members round-trip rather than being rejected
        // as unknown, and `pgwFqdn` is the fallback identity.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/pdus",
                &json!({
                    "pgwFqdn": "smf1.5gc.mnc001.mcc262.3gppnetwork.org",
                    "nsacServiceArea": {"taiList": [{"tac": "000001"}]},
                    "supportedFeatures": "1",
                    "pduACRequestInfo": [{
                        "supi": "imsi-2", "anType": "3GPP_ACCESS", "pduSessionId": 1,
                        "acuOperationList": [{"updateFlag": "INCREASE", "snssai": {"sst": 66}}]
                    }]
                }),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204);

        server.stop().await.expect("stop");
    }

    // -----------------------------------------------------------------
    // #95 gap 4: multi-access UE registration (TS 29.536 §5.2.2.2.2)
    // -----------------------------------------------------------------

    /// **Issue #95, gap 4.** A UE admitted over BOTH accesses survives a DECREASE
    /// on one and leaves the counted set only on the second.
    ///
    /// TS 29.536 §5.2.2.2.2: the NSACF records the access type(s) used by the UE
    /// and removes the registration entry only when the UE deregisters from **all**
    /// of them. Before #95 membership was one `AccessType` per SUPI and the first
    /// DECREASE dropped the entry, so the slice under-counted its registered UEs
    /// the moment a dual-access UE detached from one access — and could then exceed
    /// its admission ceiling.
    #[tokio::test]
    async fn test_http_dual_access_ue_survives_first_decrease() {
        let (server, port, _ctx_guard) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let quota_id = create_quota(&client, 60, 10, 100).await;

        // INCREASE naming anType + additionalAnType: one aggregate count, both
        // per-access buckets.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"nfId": "amf-1", "ueACRequestInfo": [{
                    "supi": "imsi-99", "anType": "3GPP_ACCESS",
                    "additionalAnType": "NON_3GPP_ACCESS",
                    "acuOperationList": [{"updateFlag": "INCREASE", "snssai": {"sst": 60}}]
                }]}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204);
        let v = get_quota(&client, &quota_id).await;
        assert_eq!(v["currentUes"], 1, "one UE, counted once");
        assert_eq!(v["currentUes3gpp"], 1);
        assert_eq!(v["currentUesN3gpp"], 1);

        // DECREASE on 3GPP only: still registered over non-3GPP, so the count
        // STAYS AT 1. This is the assertion the old model could not satisfy.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"nfId": "amf-1", "ueACRequestInfo": [{
                    "supi": "imsi-99", "anType": "3GPP_ACCESS",
                    "acuOperationList": [{"updateFlag": "DECREASE", "snssai": {"sst": 60}}]
                }]}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204);
        let v = get_quota(&client, &quota_id).await;
        assert_eq!(
            v["currentUes"], 1,
            "§5.2.2.2.2: the entry is removed only when ALL accesses are released"
        );
        assert_eq!(v["currentUes3gpp"], 0, "the 3GPP registration is gone");
        assert_eq!(v["currentUesN3gpp"], 1, "the non-3GPP one survives");

        // DECREASE on the remaining access: now the entry goes.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"nfId": "amf-1", "ueACRequestInfo": [{
                    "supi": "imsi-99", "anType": "NON_3GPP_ACCESS",
                    "acuOperationList": [{"updateFlag": "DECREASE", "snssai": {"sst": 60}}]
                }]}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204);
        let v = get_quota(&client, &quota_id).await;
        assert_eq!(v["currentUes"], 0, "last access released -> deregistered");
        assert_eq!(v["currentUesN3gpp"], 0);

        server.stop().await.expect("stop");
    }

    /// A DECREASE that names NO access releases every access, so an access-unaware
    /// consumer cannot strand a registration.
    ///
    /// This is the mirror-image hazard the gap-4 fix creates: with per-access
    /// releases, a consumer that omits `anType` for a UE registered over non-3GPP
    /// would — under the plain nsacf-05 default-to-3GPP rule — release nothing and
    /// leave the UE registered forever.
    #[tokio::test]
    async fn test_http_decrease_without_an_type_releases_every_access() {
        let (server, port, _ctx_guard) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let quota_id = create_quota(&client, 61, 10, 100).await;

        // Register over non-3GPP only.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"nfId": "amf-1", "ueACRequestInfo": [{
                    "supi": "imsi-89", "anType": "NON_3GPP_ACCESS",
                    "acuOperationList": [{"updateFlag": "INCREASE", "snssai": {"sst": 61}}]
                }]}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204);
        assert_eq!(get_quota(&client, &quota_id).await["currentUes"], 1);

        // DECREASE with NO anType at all.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"nfId": "amf-1", "ueACRequestInfo": [{
                    "supi": "imsi-89",
                    "acuOperationList": [{"updateFlag": "DECREASE", "snssai": {"sst": 61}}]
                }]}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204);
        let v = get_quota(&client, &quota_id).await;
        assert_eq!(
            v["currentUes"], 0,
            "an access-unaware DECREASE must not strand the registration"
        );
        assert_eq!(v["currentUesN3gpp"], 0);

        server.stop().await.expect("stop");
    }

    /// **Issue #95, gap 4 (parse half).** `additionalAnType` and every roaming IE
    /// deserialise rather than being rejected as unknown, and the request applies.
    #[tokio::test]
    async fn test_http_ue_ac_roaming_ies_round_trip() {
        let (server, port, _ctx_guard) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        let quota_id = create_quota(&client, 62, 10, 100).await;

        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"nfId": "amf-1", "ueACRequestInfo": [{
                    "supi": "imsi-88",
                    "anType": "3GPP_ACCESS",
                    "additionalAnType": "NON_3GPP_ACCESS",
                    "plmnId": {"mcc": "262", "mnc": "01"},
                    "plmnIdNid": {"mcc": "262", "mnc": "01", "nid": "000000000000000000000000000000000"},
                    "ueRegInd": true,
                    "servingPlmnId": {"mcc": "310", "mnc": "260"},
                    "nsacMode": "NSAC_MODE_1",
                    "numberExceedInfo": {"numberOfUEsExceed": false},
                    "acuOperationList": [{"updateFlag": "INCREASE", "snssai": {"sst": 62}}]
                }]}),
            )
            .await
            .expect("response");
        assert_eq!(
            resp.status, 204,
            "a request carrying every Table 6.1.6.2.9-1 IE must be admitted"
        );

        // Positive proof the body was really applied rather than silently dropped:
        // both per-access buckets hold the UE, which only `additionalAnType` can
        // produce from this single operation.
        let v = get_quota(&client, &quota_id).await;
        assert_eq!(v["currentUes"], 1);
        assert_eq!(v["currentUes3gpp"], 1);
        assert_eq!(v["currentUesN3gpp"], 1);

        // An unrecognised additionalAnType is IGNORED, not defaulted to 3GPP:
        // claiming a registration the consumer never asserted would be worse than
        // dropping it.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"nfId": "amf-1", "ueACRequestInfo": [{
                    "supi": "imsi-88-b",
                    "anType": "NON_3GPP_ACCESS",
                    "additionalAnType": "WIRELINE_ACCESS",
                    "acuOperationList": [{"updateFlag": "INCREASE", "snssai": {"sst": 62}}]
                }]}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204);
        let v = get_quota(&client, &quota_id).await;
        assert_eq!(v["currentUes"], 2);
        assert_eq!(
            v["currentUes3gpp"], 1,
            "the unknown additionalAnType must NOT have added a 3GPP registration"
        );
        assert_eq!(v["currentUesN3gpp"], 2);

        server.stop().await.expect("stop");
    }

    // -----------------------------------------------------------------
    // nsacf-10: DECREASE 204 (clean / idempotent) vs SLICE_NOT_FOUND
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn test_http_ue_decrease_membership_and_cause() {
        let (server, port, _ctx_guard) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        create_quota(&client, 94, 10, 100).await;

        // Admit then DECREASE a known member -> clean release 204.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &ue_ac_body("imsi-94", "INCREASE", 94),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204);
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &ue_ac_body("imsi-94", "DECREASE", 94),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 204, "clean release -> 204");

        // DECREASE an already-absent member -> idempotent 204.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &ue_ac_body("imsi-94", "DECREASE", 94),
            )
            .await
            .expect("response");
        assert_eq!(
            resp.status, 204,
            "idempotent release of absent member -> 204"
        );

        // Mixed: DECREASE on a known slice + DECREASE on an unconfigured slice
        // -> partial 200 with acuFailureList reason SLICE_NOT_FOUND for the
        // S-NSSAI that is not NSAC-subject.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"nfId": "amf-1", "ueACRequestInfo": [
                    {"supi": "imsi-94", "anType": "3GPP_ACCESS",
                     "acuOperationList": [{"updateFlag": "DECREASE", "snssai": {"sst": 94}}]},
                    {"supi": "imsi-x", "anType": "3GPP_ACCESS",
                     "acuOperationList": [{"updateFlag": "DECREASE", "snssai": {"sst": 95}}]}
                ]}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 200);
        let v: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(
            v["acuFailureList"]["imsi-x"][0]["reason"],
            "SLICE_NOT_FOUND"
        );
        assert!(v["acuFailureList"]["imsi-94"].is_null());

        server.stop().await.expect("stop");
    }

    // -----------------------------------------------------------------
    // nsacf-11: SupportedFeatures advertised with HNSAC/VHNSAC bits clear;
    // ueAdmissionList never emitted.
    // -----------------------------------------------------------------

    #[test]
    fn test_supported_features_hnsac_vhnsac_clear() {
        let v = u32::from_str_radix(SUPPORTED_FEATURES, 16).expect("valid hex");
        assert_eq!(
            v & (FEAT_HNSAC_BIT | FEAT_VHNSAC_BIT),
            0,
            "HNSAC/VHNSAC delegation must not be advertised"
        );
    }

    #[tokio::test]
    async fn test_http_ac_response_features_no_ue_admission_list() {
        let (server, port, _ctx_guard) = start_nsacf_server().await;
        let client = SbiClient::with_host_port("127.0.0.1", port);
        create_quota(&client, 96, 1, 100).await; // room for exactly 1 UE

        // Force a partial 200 (one admit + one over-quota) and inspect the body.
        let resp = client
            .post_json(
                "/nnsacf-nsac/v1/slices/ues",
                &json!({"nfId": "amf-1", "ueACRequestInfo": [
                    {"supi": "imsi-96-a", "anType": "3GPP_ACCESS",
                     "acuOperationList": [{"updateFlag": "INCREASE", "snssai": {"sst": 96}}]},
                    {"supi": "imsi-96-b", "anType": "3GPP_ACCESS",
                     "acuOperationList": [{"updateFlag": "INCREASE", "snssai": {"sst": 96}}]}
                ]}),
            )
            .await
            .expect("response");
        assert_eq!(resp.status, 200);
        let raw = resp.http.content.as_deref().unwrap();
        let v: serde_json::Value = serde_json::from_str(raw).unwrap();
        let feat = u32::from_str_radix(v["supportedFeatures"].as_str().unwrap(), 16).unwrap();
        assert_eq!(feat & (FEAT_HNSAC_BIT | FEAT_VHNSAC_BIT), 0);
        assert!(
            !raw.contains("ueAdmissionList"),
            "ueAdmissionList must never be emitted"
        );

        server.stop().await.expect("stop");
    }

    // ── #96: modify, report triggers, immediate EAC, typed service ────────────

    fn subscription_doc(
        uri: &str,
        extra_event: serde_json::Value,
        extra_top: serde_json::Value,
    ) -> serde_json::Value {
        let mut event = json!({
            "eventType": "NUM_OF_REGD_UES",
            "eventFilter": [{"sst": 96}],
        });
        if let Some(o) = extra_event.as_object() {
            for (k, v) in o {
                event[k] = v.clone();
            }
        }
        let mut doc = json!({
            "eventNotifyUri": uri,
            "nfId": "amf-96",
            "event": event,
        });
        if let Some(o) = extra_top.as_object() {
            for (k, v) in o {
                doc[k] = v.clone();
            }
        }
        doc
    }

    /// #96 criteria 5+6+7: the trigger semantics, `maxReports`, expiry and
    /// `notifyCorrelationId`, decided by the pure `report_decision`.
    ///
    /// Pure so the PERIODIC case is observable without sleeping and the threshold
    /// EDGE is observable without driving admissions — the two properties a
    /// notification-count test cannot separate.
    #[test]
    fn report_triggers_gate_emission() {
        use context::ReportDecision;
        let base = build_subscription(
            "sub-96",
            &subscription_doc("http://127.0.0.1:9/cb", json!({}), json!({})),
            "NUM_OF_REGD_UES",
            vec![SNssai::new(96, None)],
        );

        // THRESHOLD with a 50% UE threshold: below it, silence.
        let mut th = base.clone();
        th.event_trigger = Some("THRESHOLD".to_string());
        th.notif_threshold = Some(json!({"percValueNumUes": 50}));
        assert_eq!(
            th.report_decision(1, 10, 0, 0, 1_000),
            ReportDecision::Suppress,
            "sub-threshold churn must not notify"
        );
        // Crossing it reports ONCE...
        assert_eq!(th.report_decision(5, 50, 0, 0, 1_000), ReportDecision::Emit);
        // ...and while it stays over, it does not report again (edge, not level).
        let mut over = th.clone();
        over.over_threshold = true;
        assert_eq!(
            over.report_decision(6, 60, 0, 0, 1_000),
            ReportDecision::Suppress,
            "a sustained over-threshold condition must report once, not per admit"
        );
        // Falling back below re-arms, so the NEXT crossing reports again.
        assert!(!over.over_threshold_now(1, 10, 0, 0));

        // An absolute-count threshold works the same way, and ANY met member
        // crosses (a consumer that set two must not be silenced).
        let mut abs = th.clone();
        abs.notif_threshold = Some(json!({"numericValNumUes": 3, "percValueNumPduSess": 90}));
        assert!(
            abs.over_threshold_now(3, 1, 0, 0),
            "the UE count alone crosses"
        );
        assert!(!abs.over_threshold_now(2, 1, 0, 0));

        // A THRESHOLD trigger with NO threshold degenerates to report-each-change
        // rather than never reporting.
        let mut nothr = th.clone();
        nothr.notif_threshold = None;
        assert_eq!(
            nothr.report_decision(0, 0, 0, 0, 1_000),
            ReportDecision::Emit
        );

        // PERIODIC: paced by notificationPeriod, not by the event.
        let mut per = base.clone();
        per.event_trigger = Some("PERIODIC".to_string());
        per.notification_period = Some(30);
        per.last_report_at = 1_000;
        assert_eq!(
            per.report_decision(99, 99, 0, 0, 1_020),
            ReportDecision::Suppress,
            "inside the period, even a big change waits"
        );
        assert_eq!(per.report_decision(0, 0, 0, 0, 1_030), ReportDecision::Emit);
        // A PERIODIC subscription with no period cannot be paced, so it reports.
        let mut per0 = per.clone();
        per0.notification_period = None;
        assert_eq!(
            per0.report_decision(0, 0, 0, 0, 1_001),
            ReportDecision::Emit
        );

        // An unrecognised (forward-compatible) trigger token is edge-triggered,
        // not rejected: SACEventTrigger is an anyOf.
        let mut future = th.clone();
        future.event_trigger = Some("SOME_REL20_TRIGGER".to_string());
        assert_eq!(
            future.report_decision(5, 50, 0, 0, 1_000),
            ReportDecision::Emit
        );

        // maxReports: spent means REMOVE, not merely "not now".
        let mut capped = base.clone();
        capped.max_reports = Some(2);
        capped.report_count = 2;
        assert_eq!(
            capped.report_decision(0, 0, 0, 0, 1_000),
            ReportDecision::Exhausted
        );
        capped.report_count = 1;
        assert_eq!(
            capped.report_decision(0, 0, 0, 0, 1_000),
            ReportDecision::Emit
        );

        // Expiry: also Exhausted, so the subscription is removed rather than kept.
        let mut expired = base.clone();
        expired.expiry = Some(nextgcore_sbi::datetime::epoch_to_rfc3339(500));
        assert_eq!(
            expired.report_decision(0, 0, 0, 0, 1_000),
            ReportDecision::Exhausted
        );
        expired.expiry = Some(nextgcore_sbi::datetime::epoch_to_rfc3339(2_000));
        assert_eq!(
            expired.report_decision(0, 0, 0, 0, 1_000),
            ReportDecision::Emit
        );

        // REGRESSION (RFC 3339 migration 5 of 5): a consumer's `expiry` is stored
        // VERBATIM by the create path, and the shared parser used to REFUSE any
        // non-UTC offset. An unparsed expiry skipped the check below, so a
        // conformant `+02:00` expiry meant the subscription never became Exhausted
        // and kept reporting past its own deadline. The offset is now applied, so
        // these three spellings of the same instant agree.
        //
        // 1970-01-01T00:16:40Z is epoch 1000, so an expiry of epoch 500 in any zone
        // must be Exhausted at now=1000.
        for expiry in [
            "1970-01-01T00:08:20Z",
            "1970-01-01T02:08:20+02:00",
            "1970-01-01T02:08:20+0200",
        ] {
            let mut s = base.clone();
            s.expiry = Some(expiry.to_string());
            assert_eq!(
                s.report_decision(0, 0, 0, 0, 1_000),
                ReportDecision::Exhausted,
                "an expired subscription is spent whatever zone its expiry uses: {expiry}"
            );
        }
        // The complement, so this cannot pass by treating everything as expired.
        let mut live = base.clone();
        live.expiry = Some("1970-01-01T02:33:20+02:00".to_string()); // epoch 2000
        assert_eq!(
            live.report_decision(0, 0, 0, 0, 1_000),
            ReportDecision::Emit
        );
    }

    /// Every trigger field is parsed, and from the RIGHT object: `eventTrigger`,
    /// `notifThreshold`, `notificationPeriod` and `immediateFlag` live on the
    /// nested `event`, while `notifyCorrelationId`, `maxReports` and `expiry` are
    /// top-level. Reading them all from one object would find none.
    #[test]
    fn every_trigger_field_is_parsed_from_its_own_object() {
        let doc = subscription_doc(
            "http://127.0.0.1:9/cb",
            json!({
                "eventTrigger": "PERIODIC",
                "notificationPeriod": 45,
                "notifThreshold": {"percValueNumUes": 75},
                "immediateFlag": true
            }),
            json!({
                "notifyCorrelationId": "corr-96",
                "maxReports": 7,
                "expiry": "2030-01-01T00:00:00Z"
            }),
        );
        let sub = build_subscription(
            "sub-96b",
            &doc,
            "NUM_OF_REGD_UES",
            vec![SNssai::new(96, None)],
        );
        assert_eq!(sub.event_trigger.as_deref(), Some("PERIODIC"));
        assert_eq!(sub.notification_period, Some(45));
        assert_eq!(sub.notif_threshold.as_ref().unwrap()["percValueNumUes"], 75);
        assert!(sub.immediate_flag);
        assert_eq!(sub.notify_correlation_id.as_deref(), Some("corr-96"));
        assert_eq!(sub.max_reports, Some(7));
        assert_eq!(sub.expiry.as_deref(), Some("2030-01-01T00:00:00Z"));
        assert_eq!(sub.report_count, 0);
    }

    /// #96 criteria 1+2: PATCH and PUT modify an existing subscription instead of
    /// answering 405, and neither resets the report budget.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn subscription_modify_patch_and_put_are_implemented() {
        nsacf_context_init(64);
        let doc = subscription_doc(
            "http://127.0.0.1:9/cb",
            json!({"eventTrigger": "THRESHOLD", "notifThreshold": {"percValueNumUes": 50}}),
            json!({"maxReports": 9}),
        );
        let (event_type, snssais) = validate_subscription_doc(&doc).expect("valid");
        let mut stored = build_subscription("sub-96c", &doc, &event_type, snssais);
        // Pretend two reports have already been sent.
        stored.report_count = 2;
        with_nsacf_context(|c| c.subscription_add(stored));

        // PATCH (RFC 6902) raises the threshold.
        let patch = json!([{"op": "replace", "path": "/event/notifThreshold/percValueNumUes", "value": 80}]);
        let req = SbiRequest::patch("/nnsacf-slice-ee/v1/subscriptions/sub-96c")
            .with_body(patch.to_string(), "application/json-patch+json");
        let resp = handle_slice_ee_modify_partial("sub-96c", &req).await;
        assert_eq!(resp.status, 200, "PATCH must modify, not 405");
        let after = with_nsacf_context(|c| c.subscription_get("sub-96c"))
            .flatten()
            .expect("still there");
        assert_eq!(
            after.notif_threshold.as_ref().unwrap()["percValueNumUes"],
            80
        );
        assert_eq!(
            after.report_count, 2,
            "a modification must not reset the maxReports budget"
        );

        // The wrong media type is refused rather than applied as something else.
        let bad = SbiRequest::patch("/nnsacf-slice-ee/v1/subscriptions/sub-96c")
            .with_body(patch.to_string(), "application/merge-patch+json");
        assert_eq!(
            handle_slice_ee_modify_partial("sub-96c", &bad).await.status,
            415
        );

        // A patch that breaks the document is refused and does NOT commit.
        let destructive = json!([{"op": "remove", "path": "/eventNotifyUri"}]);
        let req = SbiRequest::patch("/nnsacf-slice-ee/v1/subscriptions/sub-96c")
            .with_body(destructive.to_string(), "application/json-patch+json");
        assert_eq!(
            handle_slice_ee_modify_partial("sub-96c", &req).await.status,
            400
        );
        let unchanged = with_nsacf_context(|c| c.subscription_get("sub-96c"))
            .flatten()
            .expect("still there");
        assert_eq!(
            unchanged.notification_uri, "http://127.0.0.1:9/cb",
            "a rejected patch must not have been committed"
        );

        // PUT replaces the whole subscription.
        let replacement = subscription_doc(
            "http://127.0.0.1:9/moved",
            json!({"eventTrigger": "PERIODIC", "notificationPeriod": 60}),
            json!({"maxReports": 9}),
        );
        let req = SbiRequest::put("/nnsacf-slice-ee/v1/subscriptions/sub-96c")
            .with_json_body(&replacement)
            .expect("body");
        let resp = handle_slice_ee_modify_complete("sub-96c", &req).await;
        assert_eq!(resp.status, 200, "PUT must replace, not 405");
        let after = with_nsacf_context(|c| c.subscription_get("sub-96c"))
            .flatten()
            .expect("still there");
        assert_eq!(after.notification_uri, "http://127.0.0.1:9/moved");
        assert_eq!(after.event_trigger.as_deref(), Some("PERIODIC"));
        assert_eq!(after.notification_period, Some(60));
        assert_eq!(
            after.report_count, 2,
            "PUT must not reset the budget either"
        );
        // The threshold from the old document is gone: PUT is a replacement.
        assert!(after.notif_threshold.is_none());

        // An unknown subscription is 404 on both verbs, not 405 and not 500.
        let req = SbiRequest::put("/nnsacf-slice-ee/v1/subscriptions/nope")
            .with_json_body(&replacement)
            .expect("body");
        assert_eq!(
            handle_slice_ee_modify_complete("nope", &req).await.status,
            404
        );
        let req = SbiRequest::patch("/nnsacf-slice-ee/v1/subscriptions/nope")
            .with_body(patch.to_string(), "application/json-patch+json");
        assert_eq!(
            handle_slice_ee_modify_partial("nope", &req).await.status,
            404
        );

        with_nsacf_context(|c| c.subscription_remove("sub-96c"));
    }

    /// The report counter and edge state are recorded by the store, so
    /// `maxReports` survives and a sustained condition cannot re-report.
    #[test]
    fn report_bookkeeping_charges_and_records_the_edge() {
        nsacf_context_init(64);
        let doc = subscription_doc("http://127.0.0.1:9/cb", json!({}), json!({"maxReports": 2}));
        let sub = build_subscription(
            "sub-96d",
            &doc,
            "NUM_OF_REGD_UES",
            vec![SNssai::new(96, None)],
        );
        with_nsacf_context(|c| c.subscription_add(sub));

        with_nsacf_context(|c| c.subscription_note_report("sub-96d", true, 1_234));
        let after = with_nsacf_context(|c| c.subscription_get("sub-96d"))
            .flatten()
            .expect("there");
        assert_eq!(after.report_count, 1);
        assert!(
            after.over_threshold,
            "the edge must be recorded with the report"
        );
        assert_eq!(after.last_report_at, 1_234);

        // The suppressed path re-arms the edge WITHOUT charging a report.
        with_nsacf_context(|c| c.subscription_note_threshold("sub-96d", false));
        let after = with_nsacf_context(|c| c.subscription_get("sub-96d"))
            .flatten()
            .expect("there");
        assert!(!after.over_threshold, "falling below must re-arm the edge");
        assert_eq!(
            after.report_count, 1,
            "re-arming must not consume a report from the budget"
        );

        with_nsacf_context(|c| c.subscription_remove("sub-96d"));
    }

    /// #96 criterion 4: the current EAC modes are available for the immediate
    /// notification, and a first subscription is distinguishable from a repeat.
    #[test]
    fn eac_mode_list_and_first_subscription_detection() {
        nsacf_context_init(64);
        with_nsacf_context(|c| {
            c.quota_add(SNssai::new(96, None), 10, 10);
        });

        // The mode list covers every NSAC-subject slice, not only the one that
        // most recently transitioned -- §5.2.2.2.2 says "the most recent EAC Modes
        // for the subscribed S-NSSAIs".
        let modes = with_nsacf_context(|c| c.eac_mode_list()).expect("ctx");
        assert!(
            modes.contains_key(&SNssai::new(96, None).to_key()),
            "every configured slice must have a mode: {modes:?}"
        );
        assert_eq!(modes[&SNssai::new(96, None).to_key()], "DEACTIVE");

        // First-subscription detection: false before, true after.
        assert!(!with_nsacf_context(|c| c.eac_subscription_exists("amf-96e")).unwrap());
        with_nsacf_context(|c| c.eac_subscription_set("amf-96e", "http://127.0.0.1:9/eac"));
        assert!(
            with_nsacf_context(|c| c.eac_subscription_exists("amf-96e")).unwrap(),
            "a re-registering AMF must be recognised as already subscribed, so it \
             is not re-notified on every NumOfUEsUpdate"
        );
        with_nsacf_context(|c| c.eac_subscription_remove("amf-96e"));
    }

    /// #96 criterion 8: the typed service variant round-trips.
    #[test]
    fn nnsacf_slice_ee_service_type_round_trips() {
        use nextgcore_sbi::types::SbiServiceType;
        assert_eq!(SbiServiceType::NnsacfSliceEe.to_name(), "nnsacf-slice-ee");
        assert_eq!(
            SbiServiceType::from_name("nnsacf-slice-ee"),
            Some(SbiServiceType::NnsacfSliceEe)
        );
        // The sibling NSAC service is unaffected.
        assert_eq!(SbiServiceType::NnsacfNsac.to_name(), "nnsacf-nsac");
        assert_eq!(
            SbiServiceType::from_name("nnsacf-nsac"),
            Some(SbiServiceType::NnsacfNsac)
        );
        // They are distinct: before #96 a consumer had only NnsacfNsac and could
        // not select the exposure service by type at all.
        assert_ne!(SbiServiceType::NnsacfSliceEe, SbiServiceType::NnsacfNsac);
    }

    /// #96 criteria 1+2 at the ROUTER: PATCH and PUT reach their handlers instead
    /// of the 405 the dispatch used to give them.
    ///
    /// The handler-level test above proves the handlers work; only this one proves
    /// they are REACHABLE. Deleting a route arm leaves that test green, which is
    /// the recorded "the helper is tested and the wiring is not" gap.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn modify_verbs_are_routed_not_405() {
        nsacf_context_init(64);
        let doc = subscription_doc("http://127.0.0.1:9/cb", json!({}), json!({}));
        let (event_type, snssais) = validate_subscription_doc(&doc).expect("valid");
        with_nsacf_context(|c| {
            c.subscription_add(build_subscription("sub-96r", &doc, &event_type, snssais))
        });

        // PATCH through the router.
        let patch = json!([{"op": "replace", "path": "/event/eventType", "value": "NUM_OF_ESTD_PDU_SESSIONS"}]);
        let req = SbiRequest::patch("/nnsacf-slice-ee/v1/subscriptions/sub-96r")
            .with_body(patch.to_string(), "application/json-patch+json");
        let resp = nsacf_sbi_request_handler(req).await;
        assert_ne!(
            resp.status, 405,
            "PATCH must be routed to PartialModifySubscription, not rejected as \
             method-not-allowed"
        );
        assert_eq!(resp.status, 200);

        // PUT through the router.
        let req = SbiRequest::put("/nnsacf-slice-ee/v1/subscriptions/sub-96r")
            .with_json_body(&doc)
            .expect("body");
        let resp = nsacf_sbi_request_handler(req).await;
        assert_ne!(
            resp.status, 405,
            "PUT must be routed to CompleteModifySubscription"
        );
        assert_eq!(resp.status, 200);

        // A verb the resource genuinely does not support is still 405.
        let resp =
            nsacf_sbi_request_handler(SbiRequest::get("/nnsacf-slice-ee/v1/subscriptions/sub-96r"))
                .await;
        assert_eq!(resp.status, 405, "GET is not defined on this resource");

        with_nsacf_context(|c| c.subscription_remove("sub-96r"));
    }
}
