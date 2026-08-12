//! NextGCore LMF (Location Management Function)
//!
//! The LMF is a 5G core NF responsible for (TS 23.273):
//! - UE positioning via NLs interface (AMF <-> LMF)
//! - NRPPa protocol for positioning information exchange (gNB <-> LMF)
//! - Positioning methods: ECID, OTDOA, NR-based (DL-TDOA, UL-TDOA, Multi-RTT), GNSS
//! - Measurement request/report procedures

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_sbi::client::{SbiClient, SbiClientConfig};
use nextgcore_sbi::context::global_context;
use nextgcore_sbi::message::{ProblemDetails, SbiRequest, SbiResponse};
use nextgcore_sbi::server::{
    send_bad_request, send_method_not_allowed, send_not_found, SbiServer,
    SbiServerConfig as NextgcoreSbiServerConfig,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

// lmfd-05/06: codec decode glue — NRPPa APER → CellMeasurement, LPP UPER →
// CellMeasurement.  Exposes the two inbound binary-report route helpers used
// by `handle_nrppa_binary_report` and `handle_lpp_binary_report` below.
mod codec_glue;
mod context;
// A2: lmfd → AMF Namf_Communication client leg (NRF discovery of the serving
// AMF, N1N2MessageSubscribe registration, multipart N1N2MessageTransfer POST).
mod namf_client;
mod nlmf;
// lmfd-08: real multilateration solvers (ECID / Multi-RTT / TDOA / AoA).
// Wired into `context::compute_location`; solve_tdoa remains available for
// lmfd-05/06 (NRPPa TDOA) but is not yet called (dead_code = "allow").
mod positioning;

pub use context::*;

/// NextGCore LMF - Location Management Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-lmfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Location Management Function (TS 23.273)", long_about = None)]
struct Args {
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/lmf.yaml")]
    config: String,

    #[arg(short = 'l', long)]
    log_file: Option<String>,

    #[arg(short = 'e', long, default_value = "info")]
    log_level: String,

    #[arg(short = 'm', long)]
    no_color: bool,

    #[arg(long, default_value = "0.0.0.0")]
    sbi_addr: String,

    #[arg(long, default_value = "7816")]
    sbi_port: u16,

    #[arg(long)]
    tls: bool,

    #[arg(long)]
    tls_cert: Option<String>,

    #[arg(long)]
    tls_key: Option<String>,

    #[arg(long, default_value = "1024")]
    max_measurements: usize,

    #[arg(long, default_value = "http://127.0.0.1:7777")]
    nrf_uri: String,

    /// A7 (lmfd-11): enable the bespoke/debug ingest routes (measurements,
    /// nrppa-reports, nrppa-binary-reports, lpp-binary-reports, ue-locations).
    /// These are NOT TS 29.572 resources. Default OFF (fail-closed): when
    /// disabled they 404 exactly like any unknown path (no route disclosure).
    /// The conformant DetermineLocation → Namf N1N2 → notify chain (A1-A5) is
    /// the production positioning path. Opt-in only for local testing.
    #[arg(long, default_value = "false")]
    debug_endpoints: bool,
}

/// A7 (lmfd-11): process-wide gate for the bespoke/debug ingest routes.
/// Default `false` (fail-closed); set once from `--debug-endpoints` in `main`.
/// When `false`, the six non-spec route arms below do not match and requests
/// fall through to the 404 handler — no fabricated fixes can be injected and
/// no debug route is disclosed.
static DEBUG_ENDPOINTS: AtomicBool = AtomicBool::new(false);

/// Whether the bespoke/debug ingest routes are enabled (A7). Read on every
/// request; cheap relaxed load.
fn debug_endpoints_enabled() -> bool {
    DEBUG_ENDPOINTS.load(Ordering::Relaxed)
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
// `lmf.sbi.oauth2.require: true` yaml knob. TS 33.501 §13.4.1, TS 29.510 §5.4.2.
// ---------------------------------------------------------------------------

/// Process-wide OAuth2 client for automatic Bearer-token acquisition on
/// outbound SBI calls (installed only when OAuth2 enforcement is enabled).
static OAUTH2_CLIENT: std::sync::OnceLock<Option<Arc<nextgcore_sbi::oauth::OAuth2Client>>> =
    std::sync::OnceLock::new();

/// The shared OAuth2 client, if SBI OAuth2 enforcement is enabled (Wave-6 H8
/// Phase A). Outbound SBI clients attach a token via [`attach_oauth2`].
fn oauth2_client() -> Option<Arc<nextgcore_sbi::oauth::OAuth2Client>> {
    OAUTH2_CLIENT.get().and_then(|opt| opt.clone())
}

/// Attach the process-wide OAuth2 client (when enforcement is on) so the
/// outbound SBI request carries an NRF-issued Bearer token scoped to `target`
/// (TS 33.501 §13.4.1, TS 29.510 §5.4.2). A no-op when enforcement is off, so
/// the matched-sim default path is byte-unchanged (Wave-6 H8 Phase A).
pub(crate) fn attach_oauth2(
    client: nextgcore_sbi::client::SbiClient,
    target: nextgcore_sbi::types::NfType,
) -> nextgcore_sbi::client::SbiClient {
    match oauth2_client() {
        Some(oauth2) => client.with_oauth2(oauth2, target),
        None => client,
    }
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
/// NRF JWKS and requires `aud` to include NfType::Lmf; with no NRF URI it fails
/// closed (503, per nextgcore-sbi server.rs). `nrf_uri` is the configured NRF
/// (empty ⇒ unconfigured ⇒ fail-closed).
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
    cfg = cfg.with_expected_audience_nf_type(nextgcore_sbi::types::NfType::Lmf);
    if let Some(u) = uri {
        let nf_instance_id = format!("lmf-{}", uuid::Uuid::new_v4());
        let _ = OAUTH2_CLIENT.set(Some(Arc::new(nextgcore_sbi::oauth::OAuth2Client::new(
            u,
            nf_instance_id,
            nextgcore_sbi::types::NfType::Lmf,
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

    log::info!("NextGCore LMF v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Location Management Function (3GPP TS 23.273)");

    lmf_context_init(args.max_measurements);

    // A7 (lmfd-11): the bespoke/debug ingest routes are OFF unless explicitly
    // enabled. Default-off is the fail-closed direction; positioning is not on
    // the matched-sim reg+PDU+ping path so no E2E flow depends on them.
    DEBUG_ENDPOINTS.store(args.debug_endpoints, Ordering::Relaxed);
    if args.debug_endpoints {
        log::warn!(
            "Bespoke/debug ingest routes ENABLED (--debug-endpoints): measurements, \
             nrppa-reports, nrppa-binary-reports, lpp-binary-reports, ue-locations. \
             These are NOT TS 29.572 resources and must not be enabled in production."
        );
    }

    let nf_instance_id = format!("lmf-{}", uuid::Uuid::new_v4());

    // A2: advertise our identity + notify-callback base for the outbound
    // Namf_Communication leg (subscription callback URIs must be reachable
    // by the AMF, so an unspecified bind address falls back to loopback).
    {
        let advertised_host = if args.sbi_addr == "0.0.0.0" {
            "127.0.0.1"
        } else {
            args.sbi_addr.as_str()
        };
        if let Ok(context) = lmf_self().read() {
            context.set_nf_instance_id(nf_instance_id.clone());
            context.set_callback_base(format!("http://{advertised_host}:{}", args.sbi_port));
        }
    }

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
    log::info!("Starting LMF SBI server on {addr}");
    sbi_server
        .start(lmf_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    // Register with NRF
    let sbi_ctx = global_context();
    sbi_ctx.set_nrf_uri(&args.nrf_uri).await;
    if let Err(e) = register_with_nrf(&args.sbi_addr, args.sbi_port, &nf_instance_id).await {
        log::warn!("NRF registration failed (will operate without NRF): {e}");
    } else {
        // G2-2: PATCH a real NFProfile "/load" gauge to NRF each heartbeat
        // (active positioning sessions, saturated at 100; TS 29.510 §5.2.2.3.2).
        // Honest session-count proxy — no fabricated CPU numbers.
        nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(
            nf_instance_id.clone(),
            5,
            || {
                let load = lmf_self()
                    .read()
                    .map(|c| c.positioning_session_count())
                    .unwrap_or(0);
                load.min(100) as u8
            },
        );
    }

    log::info!("NextGCore LMF ready (instance: {nf_instance_id})");

    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    log::info!("Shutting down...");
    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;
    lmf_context_final();
    log::info!("LMF shutdown complete");

    Ok(())
}

/// LMF SBI request handler
async fn lmf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("LMF SBI: {method} {uri}");

    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    // lmfd-01: the apiName is `nlmf-loc` (TS 29.572 §6.1.1), matching the NRF
    // profile (`serviceName "nlmf-loc"`) and `SbiServiceType::NlmfLoc`. The
    // previous `nlmf-location` spelling caused discovered consumers to 404.
    match parts.as_slice() {
        // Determine Location (Nlmf_Location, TS 29.572 §6.1.4.2) — spec resource.
        ["nlmf-loc", "v1", "determine-location"] => match method {
            "POST" => handle_determine_location(&request).await,
            _ => send_method_not_allowed(method, "determine-location"),
        },
        // A7 (lmfd-11): the six resources below are bespoke/debug ingest routes
        // that are NOT in TS 29.572. The conformant positioning path is now the
        // DetermineLocation → Namf N1N2MessageTransfer → uplink N1/N2 notify
        // chain (A1-A5), so these are gated behind the opt-in `--debug-endpoints`
        // flag (`debug_endpoints_enabled()`), default OFF. When disabled the
        // match guard fails and the request falls through to the 404 handler,
        // exactly like any unknown path (no route disclosure). In particular
        // `PUT ue-locations/{supi}` — which injected an arbitrary client-supplied
        // fix that `stored_fix` would then serve — is unreachable by default, so
        // no fabricated location can be injected.
        ["nlmf-loc", "v1", "measurements"] if debug_endpoints_enabled() => match method {
            "POST" => handle_measurement_request(&request).await,
            _ => send_method_not_allowed(method, "measurements"),
        },
        ["nlmf-loc", "v1", "measurements", request_id] if debug_endpoints_enabled() => match method
        {
            "GET" => handle_measurement_get(request_id).await,
            _ => send_method_not_allowed(method, "measurements/{id}"),
        },
        // NRPPa measurement reports (from gNB via AMF)
        ["nlmf-loc", "v1", "nrppa-reports"] if debug_endpoints_enabled() => match method {
            "POST" => handle_nrppa_report(&request).await,
            _ => send_method_not_allowed(method, "nrppa-reports"),
        },
        // lmfd-05: raw NRPPa APER binary report (Content-Type: application/octet-stream).
        // The body is a complete APER-encoded NrppaPdu; the LMF request-id is
        // extracted from the embedded lmf-UE-Measurement-ID IE (TS 38.455 §9.2.13).
        ["nlmf-loc", "v1", "nrppa-binary-reports"] if debug_endpoints_enabled() => match method {
            "POST" => handle_nrppa_binary_report(&request).await,
            _ => send_method_not_allowed(method, "nrppa-binary-reports"),
        },
        // lmfd-06: raw LPP UPER binary report (Content-Type: application/octet-stream).
        // The body is a complete UPER-encoded LppMessage carrying
        // ProvideLocationInformation → nr-Multi-RTT.
        ["nlmf-loc", "v1", "lpp-binary-reports"] if debug_endpoints_enabled() => match method {
            "POST" => handle_lpp_binary_report(&request).await,
            _ => send_method_not_allowed(method, "lpp-binary-reports"),
        },
        // UE location queries
        ["nlmf-loc", "v1", "ue-locations", supi] if debug_endpoints_enabled() => match method {
            "GET" => handle_ue_location_get(supi).await,
            "PUT" => handle_ue_location_update(supi, &request).await,
            _ => send_method_not_allowed(method, "ue-locations/{supi}"),
        },
        // Capabilities
        ["nlmf-loc", "v1", "capabilities"] => match method {
            "GET" => handle_capabilities().await,
            _ => send_method_not_allowed(method, "capabilities"),
        },
        // lmfd#0: Nlmf_Location custom operations (TS 29.572 §6.1.4).
        // EventNotify (§6.1.5.1) is now an LMF-initiated OUTBOUND producer, not
        // a served resource: a PERIODIC deferred LDR (registered via
        // determine-location) drives [`spawn_periodic_ldr`], which POSTs
        // `EventNotifyDataExt` to the request's `hgmlcCallBackURI` each interval
        // (A8). UPNotify (§6.1.5.2) remains deferred (needs the LCS-UP data path).
        ["nlmf-loc", "v1", "cancel-location"] => match method {
            "POST" => handle_cancel_location(&request).await,
            _ => send_method_not_allowed(method, "cancel-location"),
        },
        ["nlmf-loc", "v1", "location-context-transfer"] => match method {
            "POST" => handle_location_context_transfer(&request).await,
            _ => send_method_not_allowed(method, "location-context-transfer"),
        },
        ["nlmf-loc", "v1", "measure-location"] => match method {
            "POST" => handle_measure_location(&request).await,
            _ => send_method_not_allowed(method, "measure-location"),
        },
        ["nlmf-loc", "v1", "configure-up"] => match method {
            "POST" => handle_configure_up(&request).await,
            _ => send_method_not_allowed(method, "configure-up"),
        },
        ["nlmf-loc", "v1", "up-subscriptions"] => match method {
            "POST" => handle_up_subscribe(&request).await,
            _ => send_method_not_allowed(method, "up-subscriptions"),
        },
        ["nlmf-loc", "v1", "up-subscriptions", subscription_id] => match method {
            "DELETE" => handle_up_unsubscribe(subscription_id).await,
            _ => send_method_not_allowed(method, "up-subscriptions/{subscriptionId}"),
        },
        // A4: Namf_Communication notify callbacks (TS 29.518 §5.2.2.4
        // N1MessageNotify / §5.2.2.3.3 N2InfoNotify). These are consumer-chosen
        // callback URIs — NOT TS 29.572 resources — registered by the A2
        // N1N2MessageSubscribe (see namf_client::{N1_NOTIFY_PATH, N2_NOTIFY_PATH}).
        // They correlate an uplink LPP (N1) / NRPPa (N2) report to a pending
        // DetermineLocation session (A2) and complete it (fail-closed: an unknown
        // correlation is never ingested).
        ["nlmf-loc", "v1", "notify", "n1"] => match method {
            "POST" => handle_n1_message_notify(&request).await,
            _ => send_method_not_allowed(method, "notify/n1"),
        },
        ["nlmf-loc", "v1", "notify", "n2"] => match method {
            "POST" => handle_n2_info_notify(&request).await,
            _ => send_method_not_allowed(method, "notify/n2"),
        },
        _ => send_not_found(&format!("Resource not found: {path}"), None),
    }
}

/// Build a `ProblemDetails` error response (`application/problem+json`,
/// TS 29.571 §5.2.7 / RFC 7807) carrying a spec `cause` (lmfd-10).
fn problem(status: u16, cause: &str, detail: &str) -> SbiResponse {
    let title = match status {
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        415 => "Unsupported Media Type",
        500 => "Internal Server Error",
        504 => "Gateway Timeout",
        _ => "Error",
    };
    let pd = ProblemDetails::with_status(i32::from(status))
        .with_title(title)
        .with_detail(detail)
        .with_cause(cause);
    SbiResponse::with_status(status).with_problem(&pd)
}

/// LMF-initiated LPP transaction numbering (TS 37.355 §6.1), wrapping 0..255.
static LPP_TRANSACTION: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// A2: initiate the LMF positioning procedure for a Determine-Location
/// request (TS 23.273 §6.11.1/§6.11.2, 5GC-MT-LR):
///
/// 1. resolve the target `ueContextId` (supi, else gpsi/pei — matches amfd's
///    `find_ue_by_context_id`), else 400 `MANDATORY_IE_MISSING`;
/// 2. discover the serving AMF's `namf-comm` endpoint via the NRF, preferring
///    `InputData.amfId`; no AMF → 504 `UNREACHABLE_USER` (fail-closed, never
///    a fabricated fix);
/// 3. encode the LMF-initiated LPP `RequestLocationInformation` (TS 37.355,
///    E-CID) with a fresh transaction number;
/// 4. register the [`PositioningSession`] (mints the `lcsCorrelationId`)
///    BEFORE the POST so the uplink report cannot race the registration;
/// 5. ensure an N1N2 subscription (TS 29.518 §5.2.2.6) registering our A4
///    callback routes (best-effort, cached per (AMF, UE));
/// 6. POST the multipart `N1N2MessageTransfer` (TS 29.518 §5.2.2.3.1);
///    200 `N1_N2_TRANSFER_INITIATED` hands the completion receiver back to
///    the caller; 504 `UE_NOT_REACHABLE` / failure → 504 `UNREACHABLE_USER`.
///
/// No `LmfContext` lock is ever held across an await (nf-context-lock
/// discipline): channel handles are cloned/moved out of the lock scopes.
async fn initiate_positioning(
    input: &nlmf::InputData,
) -> Result<(String, tokio::sync::oneshot::Receiver<PositioningOutcome>), Box<SbiResponse>> {
    let Some(target) = input
        .supi
        .as_deref()
        .or(input.gpsi.as_deref())
        .or(input.pei.as_deref())
    else {
        return Err(Box::new(problem(
            400,
            nlmf::cause::MANDATORY_IE_MISSING,
            "InputData carries no target UE identity (supi, gpsi or pei)",
        )));
    };

    // Serving-AMF discovery (TS 29.510). Fail-closed: unreachable NRF or no
    // AMF instance means the user cannot be reached for positioning.
    let Some(amf) = namf_client::discover_amf(input.amf_id.as_deref()).await else {
        return Err(Box::new(problem(
            504,
            nlmf::cause::UNREACHABLE_USER,
            "No serving AMF with namf-comm discoverable via the NRF",
        )));
    };

    let txn = LPP_TRANSACTION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let lpp_pdu = match crate::codec_glue::build_lpp_ecid_request(txn) {
        Ok(pdu) => pdu,
        Err(e) => {
            return Err(Box::new(problem(
                500,
                nlmf::cause::POSITIONING_FAILED,
                &format!("LPP RequestLocationInformation encode failed: {e}"),
            )))
        }
    };

    // Measurement-store entry + correlation session, registered BEFORE the
    // POST (TS 29.572 CorrelationID minted inside; TS 37.355 txn indexed).
    let qos = positioning_qos_from_input(input);
    let registered = match lmf_self().read() {
        Ok(context) => context
            .measurement_request(0, PositioningMethod::Ecid, None, None, qos)
            .map(|req| {
                context.positioning_session_register(input.supi.clone(), txn, req.request_id)
            }),
        Err(_) => None,
    };
    let Some((corr, rx)) = registered else {
        return Err(Box::new(problem(
            500,
            nlmf::cause::POSITIONING_FAILED,
            "Positioning session could not be registered (measurement store exhausted)",
        )));
    };

    // A3 subscription first (uplink notify registration), then the transfer.
    namf_client::ensure_n1n2_subscription(&amf, target).await;

    let lmf_id = lmf_self()
        .read()
        .ok()
        .and_then(|c| c.nf_instance_id())
        .unwrap_or_else(|| "nextgcore-lmf".to_string());

    match namf_client::send_n1n2_transfer(&amf, target, &corr, &lmf_id, lpp_pdu).await {
        namf_client::TransferOutcome::Initiated => Ok((corr, rx)),
        namf_client::TransferOutcome::UeNotReachable => {
            if let Ok(context) = lmf_self().read() {
                context.positioning_session_expire(&corr);
            }
            Err(Box::new(problem(
                504,
                nlmf::cause::UNREACHABLE_USER,
                "The serving AMF reports the target UE is not reachable (UE_NOT_REACHABLE)",
            )))
        }
        namf_client::TransferOutcome::Failed(e) => {
            if let Ok(context) = lmf_self().read() {
                context.positioning_session_expire(&corr);
            }
            Err(Box::new(problem(
                504,
                nlmf::cause::UNREACHABLE_USER,
                &format!("N1N2MessageTransfer to the serving AMF failed: {e}"),
            )))
        }
    }
}

/// Map `InputData` QoS hints onto the internal [`PositioningQos`].
fn positioning_qos_from_input(input: &nlmf::InputData) -> PositioningQos {
    if input.external_client_type.as_deref() == Some("EMERGENCY_SERVICES") {
        return PositioningQos::Emergency;
    }
    match input.location_qos.as_ref() {
        Some(q) if q.response_time.as_deref() == Some("LOW_DELAY") => PositioningQos::LowLatency,
        Some(q) if q.h_accuracy.is_some_and(|a| a <= 10.0) => PositioningQos::HighAccuracy,
        _ => PositioningQos::BestEffort,
    }
}

/// A2: bounded wait budget for the positioning procedure —
/// `min(maxRespTime, locationQoS-derived bound, hard cap 20 s)`.
/// `maxRespTime` is TS 29.571 DurationSec (seconds). `responseTime`
/// (TS 29.572 ResponseTime): `NO_DELAY` waits not at all (only an already-
/// stored fix could have answered), `LOW_DELAY` is bounded to 5 s.
/// The SBI client timeouts (2 s connect / 3 s request) nest inside this cap.
fn wait_budget(input: &nlmf::InputData) -> Duration {
    const HARD_CAP: Duration = Duration::from_secs(20);
    const LOW_DELAY_CAP: Duration = Duration::from_secs(5);
    let mut budget = HARD_CAP;
    if let Some(max_s) = input.max_resp_time {
        budget = budget.min(Duration::from_secs(u64::from(max_s)));
    }
    match input
        .location_qos
        .as_ref()
        .and_then(|q| q.response_time.as_deref())
    {
        Some("NO_DELAY") => budget = Duration::ZERO,
        Some("LOW_DELAY") => budget = budget.min(LOW_DELAY_CAP),
        _ => {}
    }
    budget
}

/// A2: await the session outcome within the budget and map it per the A6
/// cause table (TS 29.572 Table 6.1.7.3-1): a real fix → 200 LocationDataExt
/// (age 0 — freshly computed); solver failure (report arrived, no fix) → 500
/// `POSITIONING_FAILED`; timeout (UE never reported in budget) → 504
/// `UNREACHABLE_USER` + session expiry.
async fn await_positioning_outcome(
    input: &nlmf::InputData,
    corr: String,
    rx: tokio::sync::oneshot::Receiver<PositioningOutcome>,
) -> SbiResponse {
    match tokio::time::timeout(wait_budget(input), rx).await {
        Ok(Ok(PositioningOutcome::Fix(est))) => encode_location_response(input, &est, 0),
        Ok(Ok(PositioningOutcome::SolverFailed)) => problem(
            500,
            nlmf::cause::POSITIONING_FAILED,
            "A measurement report was received but no location fix could be solved",
        ),
        // Sender dropped (context finalized) — the procedure cannot complete.
        Ok(Err(_)) => problem(
            500,
            nlmf::cause::POSITIONING_FAILED,
            "The positioning session was aborted",
        ),
        Err(_elapsed) => {
            if let Ok(context) = lmf_self().read() {
                context.positioning_session_expire(&corr);
            }
            problem(
                504,
                nlmf::cause::UNREACHABLE_USER,
                "Positioning did not complete within the response-time budget",
            )
        }
    }
}

/// Number of seconds between the Unix and NTP epochs (1900→1970).
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

/// A2: honest `ageOfLocationEstimate` (minutes, TS 29.572/TS 29.002 §17.7.6)
/// for a stored fix. `None` when the capture instant is unknown (timestamp 0)
/// — such a fix must NOT be served with a made-up age. Timestamps at or above
/// the NTP-epoch offset are treated as NTP seconds and converted.
fn age_of_fix_minutes(timestamp: u64) -> Option<u16> {
    if timestamp == 0 {
        return None;
    }
    let unix_ts = if timestamp >= NTP_UNIX_OFFSET {
        timestamp - NTP_UNIX_OFFSET
    } else {
        timestamp
    };
    let age_min = unix_now().saturating_sub(unix_ts) / 60;
    Some(age_min.min(32_767) as u16)
}

/// Handle Determine Location (Nlmf_Location, AMF -> LMF; TS 29.572 §6.1.4.2).
///
/// Returns **200 OK** with a `LocationDataExt` (GAD `locationEstimate`,
/// `positioningDataList`, `ageOfLocationEstimate`, `accuracyFulfilmentIndicator`)
/// per Table 6.1.4.2.2-2 — NOT the old non-conformant `201 PENDING` (lmfd-02).
/// 4xx/5xx ProblemDetails on failure (lmfd-10).
///
/// A2 (TS 23.273 §6.11.2 5GC-MT-LR): the procedure is initiated via
/// [`initiate_positioning`] — a REAL Namf `N1N2MessageTransfer` POST toward
/// the NRF-discovered serving AMF carrying the LMF-initiated LPP
/// `RequestLocationInformation` — then the handler awaits THAT session's
/// completion channel within [`wait_budget`]. The fix comes exclusively from
/// the session's own measurement report (fed by the uplink notify legs);
/// the retired global newest-report fallback is unreachable from this path.
/// A stored per-SUPI fix short-circuits the procedure ONLY when its age can
/// be reported honestly ([`age_of_fix_minutes`]). Failures map per TS 29.572
/// Table 6.1.7.3-1: timeout/unreachable → 504 `UNREACHABLE_USER`, solver
/// failure → 500 `POSITIONING_FAILED` — the handler never fabricates
/// coordinates.
async fn handle_determine_location(request: &SbiRequest) -> SbiResponse {
    log::info!("Determine Location");

    // A5: content-type gate (TS 29.572 yaml:42-47 lists application/json AND
    // multipart/related; yaml:102 lists 415). Any other media type is rejected
    // 415 Unsupported Media Type — never silently parsed.
    if !determine_location_media_type_supported(request) {
        return problem(
            415,
            nlmf::cause::UNSPECIFIED,
            "DetermineLocation accepts application/json or multipart/related request bodies only",
        );
    }

    let body = match &request.http.content {
        Some(c) => c,
        None => {
            return problem(
                400,
                nlmf::cause::MANDATORY_IE_MISSING,
                "Missing request body",
            )
        }
    };

    // lmfd-03: typed InputData deserialization (replaces serde_json::Value +
    // invented fields). Unknown IEs are tolerated; malformed bodies -> 400.
    let input: nlmf::InputData = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => {
            return problem(
                400,
                nlmf::cause::INVALID_MSG_FORMAT,
                &format!("Malformed InputData: {e}"),
            )
        }
    };

    // lmfd-03: enforce the TS 29.572 InputData `not: [ecgi, ncgi]` mutual
    // exclusion (§6.1.6.2.2).
    if input.ecgi.is_some() && input.ncgi.is_some() {
        return problem(
            400,
            nlmf::cause::MANDATORY_IE_INCORRECT,
            "ecgi and ncgi are mutually exclusive (TS 29.572 InputData)",
        );
    }

    // A zero response-time budget cannot complete positioning: the user cannot
    // be reached in time to perform the positioning procedure -> 504
    // UNREACHABLE_USER (TS 29.572 Table 6.1.7.3-1).
    if input.max_resp_time == Some(0) {
        return problem(
            504,
            nlmf::cause::UNREACHABLE_USER,
            "Positioning did not complete within the response-time budget",
        );
    }

    // lmfd#1: MO-LR requesting location assistance data -> the LMF delivers
    // assistance data to the UE (LPP ProvideAssistanceData) and returns 204 No
    // Content with no location body (TS 29.572 §6.1.4.2.2, 204 case).
    if input.ue_location_service_ind.as_deref()
        == Some(nlmf::ue_location_service_ind::LOCATION_ASSISTANCE_DATA)
    {
        log::info!("MO-LR location-assistance-data delivery -> 204 No Content");
        return SbiResponse::no_content();
    }

    // A5: MO-LR flow — the UE's own LPP PDU is carried in a
    // `binaryDataLppMessage` multipart part referenced by InputData.lppMessage
    // (TS 29.572 §6.1.6.2.2; TS 23.273 §6.11 uplink MO-LR leg). When present,
    // the positioning measurements are ALREADY in the request, so the LMF
    // decodes and solves them directly INSTEAD of issuing the network-initiated
    // 5GC-MT-LR LPP RequestLocationInformation. A dangling reference is a hard
    // error (400 MANDATORY_IE_INCORRECT) — a multipart body must never be
    // accepted while silently ignoring its referenced parts.
    if input.lpp_message.is_some() || input.lpp_message_ext.is_some() {
        return handle_mo_lr_lpp(request, &input).await;
    }

    // lmfd#1: deferred/periodic/triggered LDR (ldrType present) -> register a
    // reporting context keyed by ldrReference so it can be cancelled
    // (cancel-location, §6.1.4.3) and later reported (EventNotify, §6.1.5).
    // Activation still returns the 200 LocationDataExt below.
    //
    // A8 (TS 29.572 §6.1.5.1 EventNotify, TS 23.273 §6.3 deferred 5GC-MT-LR):
    // an `ldrType == PERIODIC` LDR carrying a `periodicEventInfo` and an
    // `hgmlcCallBackURI` additionally starts the EventNotify trigger scheduler
    // ([`spawn_periodic_ldr`]) — a bounded tokio interval task that runs the
    // live positioning procedure each tick and POSTs an `EventNotifyDataExt`
    // to the H-GMLC callback. Opt-in by request content; the reg+PDU+ping path
    // never sets ldrType so the default flow is untouched.
    if let (Some(ldr_type), Some(ldr_ref)) =
        (input.ldr_type.as_deref(), input.ldr_reference.as_deref())
    {
        let periodic = periodic_reporting_from_input(&input);
        if let Ok(c) = lmf_self().read() {
            c.register_ldr(LdrContext {
                ldr_reference: ldr_ref.to_string(),
                ldr_type: ldr_type.to_string(),
                hgmlc_callback_uri: input.hgmlc_call_back_uri.clone(),
                supi: input.supi.clone(),
                periodic_event_info: periodic,
            });
        }
        // A8: only PERIODIC + periodicEventInfo + a reachable H-GMLC callback +
        // a target SUPI drives the trigger scheduler. Anything else registers
        // the context only (areaEventInfo/motionEventInfo triggers are SCOPED
        // OUT — they need UE-side event detection).
        if ldr_type == nlmf::ldr_type::PERIODIC {
            match (
                periodic,
                input.hgmlc_call_back_uri.as_deref(),
                input.supi.as_deref(),
            ) {
                (Some(params), Some(hgmlc), Some(supi)) => {
                    spawn_periodic_ldr(
                        ldr_ref.to_string(),
                        supi.to_string(),
                        hgmlc.to_string(),
                        params,
                    );
                }
                _ => log::info!(
                    "A8: PERIODIC LDR [{ldr_ref}] not scheduled \
                     (needs periodicEventInfo + hgmlcCallBackURI + supi)"
                ),
            }
        }
    }

    // A2: per-SUPI stored-fix short-circuit — ONLY when the age of the fix
    // can be reported honestly (a real capture timestamp exists). The global
    // newest-report fallback is retired from this path: another UE's fix can
    // never be served for this target.
    if let Some(supi) = input.supi.as_deref() {
        if let Some(fix) = lmf_self().read().ok().and_then(|c| c.stored_fix(supi)) {
            if let Some(age_min) = age_of_fix_minutes(fix.timestamp) {
                return encode_location_response(&input, &fix, age_min);
            }
            log::debug!(
                "stored fix for [{supi}] has no capture timestamp; \
                 running the live positioning procedure instead"
            );
        }
    }

    // A2: the live 5GC-MT-LR procedure — LPP request → Namf N1N2 POST to the
    // serving AMF → bounded wait on THIS session's completion channel.
    let (corr, rx) = match initiate_positioning(&input).await {
        Ok(pair) => pair,
        Err(resp) => return *resp,
    };
    await_positioning_outcome(&input, corr, rx).await
}

/// A5: whether the `DetermineLocation` request body media type is supported.
///
/// TS 29.572 (specs/TS29572_Nlmf_Location.yaml:42-47) accepts `application/json`
/// (the bare `InputData`) or `multipart/related` (`InputData` jsonData +
/// `binaryDataLppMessage` binary parts, TS 29.500 §6.2). Any other media type
/// is rejected 415 (yaml:102). A JSON content type carrying parameters (e.g.
/// `application/json; charset=utf-8`) is matched on its prefix. A missing
/// Content-Type is tolerated and parsed as JSON so byte-identical legacy
/// callers (and the in-crate handler tests) are unaffected.
fn determine_location_media_type_supported(request: &SbiRequest) -> bool {
    use nextgcore_sbi::constants::content_type::APPLICATION_JSON;
    match request.http.get_header("Content-Type") {
        None => true,
        Some(ct) => {
            let ct = ct.trim();
            ct.get(..APPLICATION_JSON.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(APPLICATION_JSON))
                || nextgcore_sbi::multipart::is_multipart_related(ct)
        }
    }
}

/// A5: resolve a `RefToBinaryData` `contentId` against the decoded
/// multipart/related binary parts, returning the part bytes verbatim
/// (transparent-relay: no re-encoding). Copy of amfd's `find_binary_part`
/// idiom (namf_server.rs:872). `None` when no part carries that `Content-Id`.
fn find_binary_part(request: &SbiRequest, content_id: &str) -> Option<Vec<u8>> {
    request
        .http
        .parts
        .iter()
        .find(|p| p.content_id.as_deref() == Some(content_id))
        .map(|p| p.data.to_vec())
}

/// A5: MO-LR `DetermineLocation` — the UE's LPP `ProvideLocationInformation`
/// is carried in `binaryDataLppMessage` multipart part(s) referenced by
/// `InputData.lppMessage` / `lppMessageExt` (TS 29.572 §6.1.6.2.2; TS 23.273
/// §6.11). Every referenced part is resolved (a dangling `contentId` →
/// 400 `MANDATORY_IE_INCORRECT`, mirroring amfd namf_server.rs:983-986),
/// decoded through the LPP Provide adapters (Multi-RTT / DL-TDOA — A4 folds in
/// E-CID), and the measurements are attached to a fresh positioning session
/// which is completed via the standard strict solver path: a real-solver fix →
/// 200 `LocationDataExt`; no solvable fix → 500 `POSITIONING_FAILED`
/// (never a fabricated coordinate). No `LmfContext` lock is held across the
/// await (the completion receiver is moved out of the lock scope).
async fn handle_mo_lr_lpp(request: &SbiRequest, input: &nlmf::InputData) -> SbiResponse {
    // Collect every referenced LPP part (primary + extensions), in order.
    let mut refs: Vec<&nlmf::RefToBinaryData> = Vec::new();
    if let Some(r) = input.lpp_message.as_ref() {
        refs.push(r);
    }
    if let Some(exts) = input.lpp_message_ext.as_ref() {
        refs.extend(exts.iter());
    }

    let mut cells: Vec<CellMeasurement> = Vec::new();
    let mut txn: u8 = 0;
    for reference in &refs {
        // A dangling reference must fail closed — never silently drop the part.
        let Some(bytes) = find_binary_part(request, &reference.content_id) else {
            return problem(
                400,
                nlmf::cause::MANDATORY_IE_INCORRECT,
                &format!(
                    "InputData.lppMessage references contentId '{}' but no matching \
                     binaryDataLppMessage part is present",
                    reference.content_id
                ),
            );
        };
        match codec_glue::decode_lpp_provide_report(&bytes) {
            Ok((rid, mut decoded)) => {
                if txn == 0 {
                    txn = rid as u8;
                }
                cells.append(&mut decoded);
            }
            Err(e) => {
                return problem(
                    400,
                    nlmf::cause::INVALID_MSG_FORMAT,
                    &format!("binaryDataLppMessage LPP decode failed: {e}"),
                )
            }
        }
    }

    if cells.is_empty() {
        return problem(
            400,
            nlmf::cause::MANDATORY_IE_MISSING,
            "binaryDataLppMessage carries no decodable LPP measurements",
        );
    }

    // Register a session for the UE-provided measurements, then feed them
    // through the standard solver path. The completion receiver is cloned out
    // of the lock scope; measurement_report fires it (strict outcome).
    let qos = positioning_qos_from_input(input);
    let registered = match lmf_self().read() {
        Ok(context) => context
            .measurement_request(0, PositioningMethod::NrBased, None, None, qos)
            .map(|req| {
                let (corr, rx) =
                    context.positioning_session_register(input.supi.clone(), txn, req.request_id);
                (corr, rx, req.request_id)
            }),
        Err(_) => None,
    };
    let Some((corr, rx, request_id)) = registered else {
        return problem(
            500,
            nlmf::cause::POSITIONING_FAILED,
            "Positioning session could not be registered (measurement store exhausted)",
        );
    };

    // Attach the decoded measurements: completes the session with a strict
    // outcome (real-solver Fix, else SolverFailed → 500 POSITIONING_FAILED).
    if let Ok(context) = lmf_self().read() {
        context.measurement_report(request_id, cells);
    }
    await_positioning_outcome(input, corr, rx).await
}

// ===========================================================================
// A8: EventNotify producer for deferred/periodic LDR (TS 29.572 §6.1.5.1
// EventNotify; TS 23.273 §6.3 deferred 5GC-MT-LR periodic reporting).
//
// A PERIODIC LDR (registered at determine-location time) starts a bounded
// tokio interval task. Each tick runs the live A2 positioning procedure for
// the target SUPI and POSTs an `EventNotifyDataExt` to the request's
// `hgmlcCallBackURI`. The task stops after `reportingAmount` reports, on
// `cancel-location`, on repeated GMLC POST failure (fail-closed), or on LMF
// shutdown (its `AbortHandle` lives in `LmfContext::ldr_tasks`).
// ===========================================================================

/// Map `InputData.periodicEventInfo` (TS 29.572 `PeriodicEventInfo`) to the
/// context [`PeriodicReporting`] mirror. `reportingAmount` is clamped to ≥ 1
/// (yaml minimum) so a scheduler always makes forward progress.
fn periodic_reporting_from_input(input: &nlmf::InputData) -> Option<PeriodicReporting> {
    input
        .periodic_event_info
        .as_ref()
        .map(|p| PeriodicReporting {
            reporting_amount: p.reporting_amount.max(1),
            reporting_interval_secs: p.reporting_interval,
            reporting_interval_ms: p.reporting_interval_ms,
        })
}

/// A8: the interval between periodic reports. Prefers `reportingIntervalMs`
/// (TS 29.572 `ReportingIntervalMs`, 1..999 ms) when present, else
/// `reportingInterval` seconds (`ReportingInterval`, ≥ 1). Never zero.
fn periodic_report_interval(params: &PeriodicReporting) -> Duration {
    match params.reporting_interval_ms {
        Some(ms) if (1..=999).contains(&ms) => Duration::from_millis(u64::from(ms)),
        _ => Duration::from_secs(u64::from(params.reporting_interval_secs.max(1))),
    }
}

/// A8: spawn the EventNotify trigger scheduler for a PERIODIC LDR and register
/// its [`AbortHandle`] on the context (keyed by `ldrReference`) so
/// `cancel-location` / shutdown can stop it. Must be called from within the
/// tokio runtime (the SBI handler is async).
fn spawn_periodic_ldr(
    ldr_reference: String,
    supi: String,
    hgmlc_uri: String,
    params: PeriodicReporting,
) {
    let key = ldr_reference.clone();
    let handle = tokio::spawn(run_periodic_ldr(ldr_reference, supi, hgmlc_uri, params));
    if let Ok(c) = lmf_self().read() {
        c.ldr_task_register(&key, handle.abort_handle());
    }
    log::info!(
        "A8: periodic EventNotify scheduler started for LDR [{key}] \
         (amount={}, interval={:?})",
        params.reporting_amount,
        periodic_report_interval(&params)
    );
}

/// A8: the periodic EventNotify trigger loop (TS 29.572 §6.1.5.1). Emits exactly
/// `reportingAmount` reports spaced by the reporting interval (a report is sent
/// AFTER each interval elapses — the immediate first interval tick is skipped),
/// then finishes. Each tick runs the live positioning procedure; a fix yields a
/// report with a `locationEstimate`, a per-tick positioning failure yields a
/// report WITHOUT a fabricated location (honest event-report semantics). The
/// final report carries `terminationCause = NORMAL_TERMINATION`. On repeated
/// GMLC POST failure the LDR is auto-cancelled (no infinite retry).
async fn run_periodic_ldr(
    ldr_reference: String,
    supi: String,
    hgmlc_uri: String,
    params: PeriodicReporting,
) {
    use tokio::time::MissedTickBehavior;

    let period = periodic_report_interval(&params);
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // Consume the immediate first tick so reports are spaced by `period`.
    interval.tick().await;

    let mut sent: u32 = 0;
    while sent < params.reporting_amount {
        interval.tick().await;
        sent += 1;
        let is_final = sent >= params.reporting_amount;

        // Each report runs a fresh positioning procedure (no latest_location
        // shortcut). The per-tick wait never outlasts the reporting period.
        let fix = run_periodic_positioning(&supi, period).await;
        let body = build_periodic_event_notify(&ldr_reference, &supi, fix.as_ref(), is_final);

        if !deliver_event_notify(&hgmlc_uri, &body).await {
            log::warn!(
                "A8: EventNotify delivery to the H-GMLC failed twice for LDR \
                 [{ldr_reference}]; auto-cancelling the deferred session"
            );
            break;
        }
        log::debug!(
            "A8: EventNotify {sent}/{} delivered for LDR [{ldr_reference}] (fix={})",
            params.reporting_amount,
            fix.is_some()
        );
    }

    // Normal completion or auto-cancel: drop the session + task handle WITHOUT
    // self-abort (we are finishing).
    if let Ok(c) = lmf_self().read() {
        c.ldr_finish(&ldr_reference);
    }
}

/// A8: run the live A2 positioning procedure once for `supi`, returning the
/// measurement-derived fix or `None` (unreachable AMF / timeout / solver
/// failure). Never fabricates a location. The wait is bounded by `budget` so a
/// tick cannot outlast its reporting interval; on timeout the session is
/// expired (nf-context-lock discipline: no lock held across the await).
async fn run_periodic_positioning(supi: &str, budget: Duration) -> Option<LocationEstimate> {
    let input = nlmf::InputData {
        supi: Some(supi.to_string()),
        ..Default::default()
    };
    let (corr, rx) = initiate_positioning(&input).await.ok()?;
    match tokio::time::timeout(budget, rx).await {
        Ok(Ok(PositioningOutcome::Fix(est))) => Some(est),
        Ok(Ok(PositioningOutcome::SolverFailed)) | Ok(Err(_)) => None,
        Err(_elapsed) => {
            if let Ok(c) = lmf_self().read() {
                c.positioning_session_expire(&corr);
            }
            None
        }
    }
}

/// A8: build the `EventNotifyDataExt` for one periodic report (TS 29.572
/// EventNotifyData, yaml:1586-1657). M IEs `reportedEventType` (`PERIODIC_EVENT`)
/// and `ldrReference` are always present. On a real fix the `locationEstimate`
/// (GAD, reusing [`nlmf::to_gad`]), `ageOfLocationEstimate` (0 = freshly
/// computed) and `positioningDataList` are included; on a per-tick failure the
/// report carries NO `locationEstimate` (never fabricated). The final report
/// carries `terminationCause = NORMAL_TERMINATION`.
fn build_periodic_event_notify(
    ldr_reference: &str,
    supi: &str,
    fix: Option<&LocationEstimate>,
    is_final: bool,
) -> nlmf::EventNotifyDataExt {
    let serving_lmf_identification = lmf_self().read().ok().and_then(|c| c.nf_instance_id());
    let location_estimate = fix.map(|est| {
        nlmf::to_gad(
            est.latitude,
            est.longitude,
            est.horizontal_accuracy,
            95,
            nlmf::gad_shape::POINT_UNCERTAINTY_CIRCLE,
        )
    });
    let positioning_data_list = fix.map(|est| {
        vec![nlmf::PositioningMethodAndUsage {
            method: est
                .method_used
                .clone()
                .unwrap_or_else(|| nlmf::positioning_method::ECID.to_string()),
            mode: "CONVENTIONAL".to_string(),
            usage: "SUCCESS_RESULTS_USED_TO_GENERATE_LOCATION".to_string(),
        }]
    });
    nlmf::EventNotifyDataExt {
        event_notify_data: nlmf::EventNotifyData {
            reported_event_type: nlmf::reported_event_type::PERIODIC_EVENT.to_string(),
            ldr_reference: ldr_reference.to_string(),
            supi: Some(supi.to_string()),
            gpsi: None,
            hgmlc_call_back_uri: None,
            location_estimate,
            // Freshly computed each tick: honest age 0 (omitted when no fix).
            age_of_location_estimate: fix.map(|_| 0),
            timestamp_of_location_estimate: None,
            positioning_data_list,
            serving_lmf_identification,
            termination_cause: is_final
                .then(|| nlmf::termination_cause::NORMAL_TERMINATION.to_string()),
        },
        add_event_notify_datas: None,
    }
}

/// A8: POST an `EventNotifyDataExt` to the H-GMLC callback, retrying exactly
/// once on any non-2xx / transport error (TS 29.572 §6.1.5.1: "204 Expected
/// response to a valid notification"). Returns `true` iff a 2xx was received
/// within the two attempts. `false` → the caller auto-cancels the LDR.
async fn deliver_event_notify(hgmlc_uri: &str, body: &nlmf::EventNotifyDataExt) -> bool {
    for attempt in 0..2u8 {
        match post_event_notify(hgmlc_uri, body).await {
            Ok(status) if (200..=299).contains(&status) => return true,
            Ok(status) => {
                log::warn!("A8: EventNotify POST returned HTTP {status} (attempt {attempt})")
            }
            Err(e) => log::warn!("A8: EventNotify POST failed (attempt {attempt}): {e}"),
        }
        if attempt == 0 {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    false
}

/// A8: single outbound EventNotify POST. Parses the `hgmlcCallBackURI` into
/// host/port/path, POSTs `application/json` with a bounded-timeout client
/// (connect 2 s / request 3 s), and returns the HTTP status.
async fn post_event_notify(
    hgmlc_uri: &str,
    body: &nlmf::EventNotifyDataExt,
) -> Result<u16, String> {
    let (host, port, path) = split_callback_uri(hgmlc_uri)
        .ok_or_else(|| format!("invalid hgmlcCallBackURI: {hgmlc_uri}"))?;
    let json = serde_json::to_string(body).map_err(|e| e.to_string())?;
    let client = SbiClient::new(
        SbiClientConfig::new(host, port)
            .with_connect_timeout(Duration::from_secs(2))
            .with_request_timeout(Duration::from_secs(3)),
    );
    let request = SbiRequest::post(path).with_body(json, "application/json");
    client
        .send_request(request)
        .await
        .map(|resp| resp.status)
        .map_err(|e| e.to_string())
}

/// A8: split an absolute callback URI (`http[s]://host[:port]/path`) into
/// (host, port, path). Defaults the port from the scheme (80/443) and the path
/// to `/` when absent. `None` on an unparseable authority.
fn split_callback_uri(uri: &str) -> Option<(String, u16, String)> {
    let (is_https, rest) = if let Some(r) = uri.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = uri.strip_prefix("http://") {
        (false, r)
    } else {
        (false, uri)
    };
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() {
        return None;
    }
    let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
        (h.to_string(), p.parse().ok()?)
    } else {
        (authority.to_string(), if is_https { 443u16 } else { 80 })
    };
    if host.is_empty() {
        return None;
    }
    Some((host, port, path))
}

/// Encode the 200 `LocationDataExt` response (TS 29.572 Table 6.1.4.2.2-2)
/// for a REAL measurement-derived fix: GAD shape negotiation (lmfd-04),
/// accuracy fulfilment vs the requested QoS and an HONEST
/// `ageOfLocationEstimate` (minutes; 0 = freshly computed).
fn encode_location_response(
    input: &nlmf::InputData,
    est: &LocationEstimate,
    age_minutes: u16,
) -> SbiResponse {
    // lmfd-04: negotiate a GAD shape against supportedGADShapes and GAD-encode
    // the real fix into a GeographicArea.
    let want_ellipse = input
        .location_qos
        .as_ref()
        .and_then(|q| q.vertical_requested)
        .unwrap_or(false);
    let shape = nlmf::negotiate_gad_shape(input.supported_gad_shapes.as_deref(), want_ellipse);
    let location_estimate = nlmf::to_gad(
        est.latitude,
        est.longitude,
        est.horizontal_accuracy,
        95,
        shape,
    );

    // Accuracy fulfilment vs the requested horizontal accuracy.
    let accuracy_fulfilment_indicator = match input.location_qos.as_ref().and_then(|q| q.h_accuracy)
    {
        Some(req_acc) if est.horizontal_accuracy > req_acc => {
            nlmf::accuracy_fulfilment::NOT_FULFILLED
        }
        _ => nlmf::accuracy_fulfilment::FULFILLED,
    };

    let response = nlmf::LocationDataExt {
        location_data: nlmf::LocationData {
            location_estimate,
            accuracy_fulfilment_indicator: Some(accuracy_fulfilment_indicator.to_string()),
            age_of_location_estimate: Some(age_minutes),
            // Real positioning method from the measurement report (else E-CID).
            positioning_data_list: Some(vec![nlmf::PositioningMethodAndUsage {
                method: est
                    .method_used
                    .clone()
                    .unwrap_or_else(|| nlmf::positioning_method::ECID.to_string()),
                mode: "CONVENTIONAL".to_string(),
                usage: "SUCCESS_RESULTS_USED_TO_GENERATE_LOCATION".to_string(),
            }]),
            altitude: None,
            barometric_pressure: None,
            velocity_estimate: None,
            civic_address: None,
        },
        add_location_data: None,
    };

    SbiResponse::with_status(200)
        .with_json_body(&response)
        .unwrap_or_else(|_| {
            problem(
                500,
                nlmf::cause::UNSPECIFIED,
                "Failed to encode LocationDataExt",
            )
        })
}

// ---------------------------------------------------------------------------
// lmfd#0: custom Nlmf_Location operation handlers (TS 29.572 §6.1.4).
// ---------------------------------------------------------------------------

/// POST /nlmf-loc/v1/cancel-location (TS 29.572 §6.1.4.3).
///
/// Cancels an active deferred/periodic/triggered LDR session identified by
/// `ldrReference`. Returns 204 on success, 403 LOCATION_SESSION_UNKNOWN when
/// no matching session exists.
async fn handle_cancel_location(request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(c) => c,
        None => {
            return problem(
                400,
                nlmf::cause::MANDATORY_IE_MISSING,
                "Missing request body",
            )
        }
    };
    let data: nlmf::CancelLocData = match serde_json::from_str(body) {
        Ok(d) => d,
        Err(e) => {
            return problem(
                400,
                nlmf::cause::INVALID_MSG_FORMAT,
                &format!("Malformed CancelLocData: {e}"),
            )
        }
    };
    let removed = match lmf_self().read() {
        Ok(c) => c.cancel_ldr(&data.ldr_reference),
        Err(_) => false,
    };
    if removed {
        SbiResponse::no_content()
    } else {
        problem(
            403,
            nlmf::cause::LOCATION_SESSION_UNKNOWN,
            "No active LDR session for the given ldrReference",
        )
    }
}

/// POST /nlmf-loc/v1/location-context-transfer (TS 29.572 §6.1.4.5).
///
/// Transfers an LDR context from an old AMF to this LMF after AMF relocation.
/// Validates `eventReportMessage.eventClass`; registers the LDR context.
/// Returns 204 on success, 403 on unrecognized event class.
async fn handle_location_context_transfer(request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(c) => c,
        None => {
            return problem(
                400,
                nlmf::cause::MANDATORY_IE_MISSING,
                "Missing request body",
            )
        }
    };
    let data: nlmf::LocContextData = match serde_json::from_str(body) {
        Ok(d) => d,
        Err(e) => {
            return problem(
                400,
                nlmf::cause::INVALID_MSG_FORMAT,
                &format!("Malformed LocContextData: {e}"),
            )
        }
    };
    // Validate eventClass: only known classes are accepted.
    match data.event_report_message.event_class.as_str() {
        "SUPPLEMENTARY_SERVICES" | "DUMMY" => {}
        _ => {
            return problem(
                403,
                nlmf::cause::EVENT_REPORT_UNRECOGNIZED,
                "Unrecognized eventReportMessage.eventClass",
            )
        }
    }
    if let Ok(c) = lmf_self().read() {
        c.register_ldr(LdrContext {
            ldr_reference: data.ldr_reference.clone(),
            ldr_type: data.ldr_type.clone(),
            hgmlc_callback_uri: Some(data.hgmlc_call_back_uri.clone()),
            supi: data.supi.clone(),
            // A8: context-transfer restores the LDR record; re-driving the
            // periodic trigger after AMF relocation is out of A8 scope.
            periodic_event_info: None,
        });
    }
    SbiResponse::no_content()
}

/// POST /nlmf-loc/v1/measure-location (TS 29.572 §6.1.4.6).
///
/// Requests location measurements for the target cell. Returns 403
/// LOCATION_MEASUREMENT_UNKNOWN because the LMF has no PRU/NRPPa
/// measurements collected independently of a `determine-location` flow.
/// Fabricating a 200 LocMeasurementResp with invented data would violate
/// the non-fabrication contract (lmfd gate_notes).
async fn handle_measure_location(request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(c) => c,
        None => {
            return problem(
                400,
                nlmf::cause::MANDATORY_IE_MISSING,
                "Missing request body",
            )
        }
    };
    let _req: nlmf::LocMeasurementReq = match serde_json::from_str(body) {
        Ok(d) => d,
        Err(e) => {
            return problem(
                400,
                nlmf::cause::INVALID_MSG_FORMAT,
                &format!("Malformed LocMeasurementReq: {e}"),
            )
        }
    };
    // Honest: no PRU location measurements available without a full UE session.
    problem(
        403,
        nlmf::cause::LOCATION_MEASUREMENT_UNKNOWN,
        "No PRU location measurements available",
    )
}

/// POST /nlmf-loc/v1/configure-up (TS 29.572 §6.1.4.7).
///
/// Configures user-plane location reporting for a UE. Validates that at least
/// one of `supi` or `gpsi` is present. Returns 204 on success.
async fn handle_configure_up(request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(c) => c,
        None => {
            return problem(
                400,
                nlmf::cause::MANDATORY_IE_MISSING,
                "Missing request body",
            )
        }
    };
    let data: nlmf::UpConfig = match serde_json::from_str(body) {
        Ok(d) => d,
        Err(e) => {
            return problem(
                400,
                nlmf::cause::INVALID_MSG_FORMAT,
                &format!("Malformed UpConfig: {e}"),
            )
        }
    };
    // UpConfig requires anyOf[supi, gpsi] (TS 29.572 §6.1.6.2.x).
    if data.supi.is_none() && data.gpsi.is_none() {
        return problem(
            400,
            nlmf::cause::MANDATORY_IE_MISSING,
            "UpConfig requires supi or gpsi",
        );
    }
    SbiResponse::no_content()
}

/// POST /nlmf-loc/v1/up-subscriptions (TS 29.572 §6.1.4.8).
///
/// Creates a UP location reporting subscription. Returns 201 Created with the
/// subscription resource location header and the subscription body.
async fn handle_up_subscribe(request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(c) => c,
        None => {
            return problem(
                400,
                nlmf::cause::MANDATORY_IE_MISSING,
                "Missing request body",
            )
        }
    };
    let sub: nlmf::UpSubscription = match serde_json::from_str(body) {
        Ok(d) => d,
        Err(e) => {
            return problem(
                400,
                nlmf::cause::INVALID_MSG_FORMAT,
                &format!("Malformed UpSubscription: {e}"),
            )
        }
    };
    let id = uuid::Uuid::new_v4().to_string();
    let location = format!("/nlmf-loc/v1/up-subscriptions/{id}");
    SbiResponse::with_status(201)
        .with_header("Location", location)
        .with_json_body(&sub)
        .unwrap_or_else(|_| {
            problem(
                500,
                nlmf::cause::UNSPECIFIED,
                "Failed to encode UpSubscription",
            )
        })
}

/// DELETE /nlmf-loc/v1/up-subscriptions/{subscriptionId} (TS 29.572 §6.1.4.9).
///
/// Deletes a UP location reporting subscription. Returns 204 No Content.
/// Full subscription lifecycle (store + lookup) is E2E-gated (needs a persistent
/// UP subscription store + a live UPF data path). Minimal implementation accepts
/// any subscriptionId and returns 204.
async fn handle_up_unsubscribe(_subscription_id: &str) -> SbiResponse {
    SbiResponse::no_content()
}

/// Handle a (bespoke/debug) measurement request — NOT a TS 29.572 resource.
///
/// Retained behind the `nlmf-loc/v1/measurements` debug route until lmfd-11.
/// lmfd-12: the positioning method is parsed against the spec
/// `PositioningMethod` enum and an unknown value is rejected with 400
/// ProblemDetails instead of silently defaulting to ECID.
async fn handle_measurement_request(request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(c) => c,
        None => {
            return problem(
                400,
                nlmf::cause::MANDATORY_IE_MISSING,
                "Missing request body",
            )
        }
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => {
            return problem(
                400,
                nlmf::cause::INVALID_MSG_FORMAT,
                &format!("Invalid JSON: {e}"),
            )
        }
    };

    let amf_ue_ngap_id = data
        .get("amfUeNgapId")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    // lmfd-12: spec-enumerated PositioningMethod; reject unknown values.
    let method_str = data
        .get("positioningMethod")
        .and_then(|v| v.as_str())
        .unwrap_or(nlmf::positioning_method::ECID);
    let method = match parse_positioning_method(method_str) {
        Some(m) => m,
        None => {
            return problem(
                400,
                nlmf::cause::MANDATORY_IE_INCORRECT,
                &format!("Unknown positioningMethod: {method_str}"),
            )
        }
    };
    // lmfd-12: spec-enumerated NR method; reject an explicitly-unknown value.
    let nr_method = match data.get("nrMethod").and_then(|v| v.as_str()) {
        Some(s) => match parse_nr_method(s) {
            Some(m) => Some(m),
            None => {
                return problem(
                    400,
                    nlmf::cause::MANDATORY_IE_INCORRECT,
                    &format!("Unknown nrMethod: {s}"),
                )
            }
        },
        None => None,
    };
    let gnb_id = data
        .get("gnbId")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let qos_str = data
        .get("qosClass")
        .and_then(|v| v.as_str())
        .unwrap_or("BEST_EFFORT");
    let qos = parse_qos(qos_str);

    let ctx = lmf_self();
    let result = if let Ok(context) = ctx.read() {
        context.measurement_request(amf_ue_ngap_id, method, nr_method, gnb_id, qos)
    } else {
        None
    };

    match result {
        Some(req) => SbiResponse::with_status(201)
            .with_json_body(&serde_json::json!({
                "requestId": req.request_id,
                "amfUeNgapId": amf_ue_ngap_id,
                "positioningMethod": method_str,
                "state": "PENDING",
                "qosClass": qos_str,
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(201)),
        None => problem(
            400,
            nlmf::cause::UNSPECIFIED,
            "Failed to create measurement request",
        ),
    }
}

/// Handle measurement get
async fn handle_measurement_get(request_id: &str) -> SbiResponse {
    let req_id = match request_id.parse::<u64>() {
        Ok(id) => id,
        Err(_) => return send_bad_request("Invalid request ID", Some("INVALID_ID")),
    };

    let ctx = lmf_self();
    let (measurement, report) = if let Ok(context) = ctx.read() {
        (
            context.measurement_find(req_id),
            context.report_find(req_id),
        )
    } else {
        (None, None)
    };

    match measurement {
        Some(m) => {
            let mut response = serde_json::json!({
                "requestId": m.request_id,
                "amfUeNgapId": m.amf_ue_ngap_id,
                "positioningMethod": format!("{:?}", m.method),
                "state": format!("{:?}", m.state),
                "qosClass": format!("{:?}", m.qos_class),
            });

            if let Some(r) = report {
                if let Some(loc) = r.location {
                    response["location"] = serde_json::json!({
                        "latitude": loc.latitude,
                        "longitude": loc.longitude,
                        "altitude": loc.altitude,
                        "horizontalAccuracy": loc.horizontal_accuracy,
                        "verticalAccuracy": loc.vertical_accuracy,
                        "methodUsed": loc.method_used,
                    });
                }
                response["cellMeasurementCount"] = serde_json::json!(r.cell_measurements.len());
            }

            SbiResponse::with_status(200)
                .with_json_body(&response)
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => send_not_found(
            &format!("Measurement request {request_id} not found"),
            Some("MEASUREMENT_NOT_FOUND"),
        ),
    }
}

/// Handle NRPPa measurement report (gNB -> LMF via AMF, TS 38.455)
async fn handle_nrppa_report(request: &SbiRequest) -> SbiResponse {
    log::info!("NRPPa Measurement Report");

    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let request_id = data.get("requestId").and_then(|v| v.as_u64()).unwrap_or(0);
    let cells: Vec<CellMeasurement> = data
        .get("cellMeasurements")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|c| CellMeasurement {
                    nr_cgi: c
                        .get("nrCgi")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    rsrp: c.get("rsrp").and_then(|v| v.as_i64()).map(|n| n as i16),
                    rsrq: c.get("rsrq").and_then(|v| v.as_i64()).map(|n| n as i16),
                    timing_advance: c
                        .get("timingAdvance")
                        .and_then(|v| v.as_u64())
                        .map(|n| n as u32),
                    aoa: c.get("aoa").and_then(|v| v.as_f64()),
                    rtt_ns: c.get("rttNs").and_then(|v| v.as_u64()),
                    rstd_ns: c.get("rstdNs").and_then(|v| v.as_f64()),
                })
                .collect()
        })
        .unwrap_or_default();

    let ctx = lmf_self();
    let location = if let Ok(context) = ctx.read() {
        context.measurement_report(request_id, cells)
    } else {
        None
    };

    match location {
        Some(loc) => SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({
                "requestId": request_id,
                "result": "COMPLETED",
                "location": {
                    "latitude": loc.latitude,
                    "longitude": loc.longitude,
                    "horizontalAccuracy": loc.horizontal_accuracy,
                    "methodUsed": loc.method_used,
                },
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("Measurement request {request_id} not found"),
            Some("MEASUREMENT_NOT_FOUND"),
        ),
    }
}

/// Handle a raw NRPPa APER-encoded E-CID Measurement Report (gNB → LMF,
/// relayed by AMF). lmfd-05.
///
/// Expects the request body to be a raw APER-encoded `NrppaPdu`
/// (Content-Type: application/octet-stream).  The LMF measurement request-id
/// is extracted from the `lmf-UE-Measurement-ID` IE embedded in the PDU
/// (TS 38.455 §9.2.13).  On success the decoded cells are fed directly into
/// [`LmfContext::measurement_report`] and a location estimate is returned.
async fn handle_nrppa_binary_report(request: &SbiRequest) -> SbiResponse {
    log::info!("NRPPa binary E-CID measurement report");

    let body = match &request.http.content {
        Some(c) => c,
        None => return problem(400, nlmf::cause::MANDATORY_IE_MISSING, "Missing body"),
    };

    let (request_id, cells) = match codec_glue::decode_nrppa_ecid_report(body.as_bytes()) {
        Ok(pair) => pair,
        Err(e) => {
            return problem(
                400,
                nlmf::cause::INVALID_MSG_FORMAT,
                &format!("NRPPa decode failed: {e}"),
            )
        }
    };

    let ctx = lmf_self();
    let location = if let Ok(context) = ctx.read() {
        context.measurement_report(request_id, cells)
    } else {
        None
    };

    match location {
        Some(loc) => SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({
                "requestId": request_id,
                "result": "COMPLETED",
                "location": {
                    "latitude": loc.latitude,
                    "longitude": loc.longitude,
                    "horizontalAccuracy": loc.horizontal_accuracy,
                    "methodUsed": loc.method_used,
                },
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("Measurement request {request_id} not found"),
            Some("MEASUREMENT_NOT_FOUND"),
        ),
    }
}

/// Handle a raw LPP UPER-encoded ProvideLocationInformation (UE → LMF, relayed
/// by AMF). lmfd-06.
///
/// Expects the request body to be a raw UPER-encoded `LppMessage`
/// (Content-Type: application/octet-stream) carrying
/// `ProvideLocationInformation` → `nr-Multi-RTT`.  The correlation
/// request-id is taken from the LPP `transactionID.transactionNumber`.
async fn handle_lpp_binary_report(request: &SbiRequest) -> SbiResponse {
    log::info!("LPP binary ProvideLocationInformation (nr-Multi-RTT / nr-DL-TDOA)");

    let body = match &request.http.content {
        Some(c) => c,
        None => return problem(400, nlmf::cause::MANDATORY_IE_MISSING, "Missing body"),
    };

    // A ProvideLocationInformation may carry nr-Multi-RTT or nr-DL-TDOA signal
    // measurements; try the Multi-RTT adapter first, fall back to DL-TDOA.
    let (request_id, cells) = match codec_glue::decode_lpp_multi_rtt_report(body.as_bytes()) {
        Ok((rid, c)) if !c.is_empty() => (rid, c),
        Ok(_) => match codec_glue::decode_lpp_dl_tdoa_report(body.as_bytes()) {
            Ok(pair) => pair,
            Err(e) => {
                return problem(
                    400,
                    nlmf::cause::INVALID_MSG_FORMAT,
                    &format!("LPP decode failed: {e}"),
                )
            }
        },
        Err(e) => {
            return problem(
                400,
                nlmf::cause::INVALID_MSG_FORMAT,
                &format!("LPP decode failed: {e}"),
            )
        }
    };

    if cells.is_empty() {
        return problem(
            400,
            nlmf::cause::MANDATORY_IE_MISSING,
            "LPP message carries no nr-Multi-RTT or nr-DL-TDOA measurements",
        );
    }

    let ctx = lmf_self();
    let location = if let Ok(context) = ctx.read() {
        context.measurement_report(request_id, cells)
    } else {
        None
    };

    match location {
        Some(loc) => SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({
                "requestId": request_id,
                "result": "COMPLETED",
                "location": {
                    "latitude": loc.latitude,
                    "longitude": loc.longitude,
                    "horizontalAccuracy": loc.horizontal_accuracy,
                    "methodUsed": loc.method_used,
                },
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("Measurement request {request_id} not found"),
            Some("MEASUREMENT_NOT_FOUND"),
        ),
    }
}

// ===========================================================================
// A4: Namf_Communication uplink notify callbacks (TS 29.518 §5.2.2.4 /
// §5.2.2.3.3). The AMF (Wave-6 A4 producer for LPP N1, Wave-6 A1 producer for
// NRPPa N2) POSTs an uplink positioning report to the callback URIs the LMF
// registered via N1N2MessageSubscribe (A2). These handlers correlate the
// report to a pending DetermineLocation session and complete it.
// ===========================================================================

/// A4: resolve the pending DetermineLocation session for an inbound notify.
///
/// Correlates on `lcsCorrelationId` (TS 29.572 CorrelationID) first, then — for
/// the N1/LPP leg — falls back to the LPP `transactionID.transactionNumber`
/// (TS 37.355 §6.1). Returns the session's measurement-store `request_id` on a
/// hit; `None` fails closed (the caller answers 404 — an uplink report is never
/// ingested against an unknown or global session).
fn resolve_notify_session(lcs_correlation_id: Option<&str>, lpp_txn: Option<u8>) -> Option<u64> {
    let ctx = lmf_self();
    let context = ctx.read().ok()?;
    if let Some(corr) = lcs_correlation_id {
        if let Some(info) = context.positioning_session_find(corr) {
            return Some(info.request_id);
        }
    }
    if let Some(txn) = lpp_txn {
        if let Some(corr) = context.positioning_session_find_by_transaction(txn) {
            if let Some(info) = context.positioning_session_find(&corr) {
                return Some(info.request_id);
            }
        }
    }
    None
}

/// Callback: `POST /nlmf-loc/v1/notify/n1` — Namf_Communication N1MessageNotify
/// (A4; TS 29.518 §5.2.2.4, TS29518_Namf_Communication.yaml:1540-1596). The AMF
/// relays an uplink LPP N1 message (TS 23.273 §6.11.2) as `multipart/related`:
/// jsonData `N1MessageNotification` + a `binaryDataN1Message` part
/// (`application/vnd.3gpp.5gnas`) carrying the UPER LPP PDU verbatim.
///
/// Correlates to a pending DetermineLocation session (A2) via `lcsCorrelationId`
/// (fallback: the LPP transactionID), decodes the LPP `ProvideLocationInformation`
/// through the codec adapters (E-CID / Multi-RTT / DL-TDOA) and feeds the
/// measurements to [`LmfContext::measurement_report`], which fires the session's
/// completion channel. Returns **204** (yaml: "204 Expected response to a
/// successful callback processing").
///
/// Fail-closed: an unknown correlation → **404** `LOCATION_SESSION_UNKNOWN` (no
/// global ingest, no session mutation); a missing/dangling binary part → **400**
/// `MANDATORY_IE_MISSING`. An undecodable or empty LPP body for a KNOWN session
/// completes it as SolverFailed so the DetermineLocation leg returns 500
/// `POSITIONING_FAILED` (never a fabricated fix).
async fn handle_n1_message_notify(request: &SbiRequest) -> SbiResponse {
    let Some(json) = request.http.content.as_deref() else {
        return problem(
            400,
            nlmf::cause::MANDATORY_IE_MISSING,
            "Missing N1MessageNotification jsonData",
        );
    };
    let notification: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => {
            return problem(
                400,
                nlmf::cause::INVALID_MSG_FORMAT,
                &format!("Malformed N1MessageNotification: {e}"),
            )
        }
    };
    // n1MessageContainer.n1MessageContent.contentId references the binary part.
    let Some(content_id) = notification
        .pointer("/n1MessageContainer/n1MessageContent/contentId")
        .and_then(serde_json::Value::as_str)
    else {
        return problem(
            400,
            nlmf::cause::MANDATORY_IE_MISSING,
            "N1MessageNotification n1MessageContainer.n1MessageContent.contentId missing",
        );
    };
    let Some(lpp_bytes) = find_binary_part(request, content_id) else {
        return problem(
            400,
            nlmf::cause::MANDATORY_IE_MISSING,
            "binaryDataN1Message part referenced by contentId is absent",
        );
    };
    let lcs_correlation_id = notification
        .get("lcsCorrelationId")
        .and_then(serde_json::Value::as_str);

    // Decode the uplink LPP; keep the result so its transactionID can seed the
    // correlation fallback.
    let decoded = codec_glue::decode_lpp_provide_report(&lpp_bytes);
    let lpp_txn = decoded.as_ref().ok().map(|(rid, _)| *rid as u8);

    let Some(request_id) = resolve_notify_session(lcs_correlation_id, lpp_txn) else {
        log::warn!(
            "N1MessageNotify with no matching positioning session \
             (lcsCorrelationId={lcs_correlation_id:?}, lppTxn={lpp_txn:?}); dropped"
        );
        return problem(
            404,
            nlmf::cause::LOCATION_SESSION_UNKNOWN,
            "No pending positioning session matches the notification (lcsCorrelationId / LPP transaction)",
        );
    };

    let cells = match decoded {
        Ok((_txn, cells)) => cells,
        Err(e) => {
            log::warn!(
                "N1MessageNotify LPP decode failed for session (request_id {request_id}): {e}"
            );
            Vec::new()
        }
    };
    if let Ok(context) = lmf_self().read() {
        context.measurement_report(request_id, cells);
    }
    SbiResponse::no_content()
}

/// Callback: `POST /nlmf-loc/v1/notify/n2` — Namf_Communication N2InfoNotify
/// (A1/A4; TS 29.518 §5.2.2.3.3, TS29518_Namf_Communication.yaml:1597-1661). The
/// AMF relays an uplink NRPPa PDU (TS 38.413 §8.15.3/§8.15.5, TS 23.273 §6.11) as
/// `multipart/related`: jsonData `N2InformationNotification` + a
/// `binaryDataN2Information` part (`application/vnd.3gpp.ngap`) carrying the NRPPa
/// PDU verbatim. Shared with the A1 uplink-NRPPa producer.
///
/// Correlates to a pending session via `lcsCorrelationId` (NRPPa carries no LPP
/// transaction), decodes the NRPPa E-CID report and feeds the measurements to
/// the session. **204** on success; **404** unknown correlation; **400** missing
/// binary part.
async fn handle_n2_info_notify(request: &SbiRequest) -> SbiResponse {
    let Some(json) = request.http.content.as_deref() else {
        return problem(
            400,
            nlmf::cause::MANDATORY_IE_MISSING,
            "Missing N2InformationNotification jsonData",
        );
    };
    let notification: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => {
            return problem(
                400,
                nlmf::cause::INVALID_MSG_FORMAT,
                &format!("Malformed N2InformationNotification: {e}"),
            )
        }
    };
    let Some(content_id) = notification
        .pointer("/n2InfoContainer/nrppaInfo/nrppaPdu/ngapData/contentId")
        .and_then(serde_json::Value::as_str)
    else {
        return problem(
            400,
            nlmf::cause::MANDATORY_IE_MISSING,
            "N2InformationNotification n2InfoContainer.nrppaInfo.nrppaPdu.ngapData.contentId missing",
        );
    };
    let Some(nrppa_bytes) = find_binary_part(request, content_id) else {
        return problem(
            400,
            nlmf::cause::MANDATORY_IE_MISSING,
            "binaryDataN2Information part referenced by contentId is absent",
        );
    };
    let lcs_correlation_id = notification
        .get("lcsCorrelationId")
        .and_then(serde_json::Value::as_str);

    let Some(request_id) = resolve_notify_session(lcs_correlation_id, None) else {
        log::warn!(
            "N2InfoNotify with no matching positioning session \
             (lcsCorrelationId={lcs_correlation_id:?}); dropped"
        );
        return problem(
            404,
            nlmf::cause::LOCATION_SESSION_UNKNOWN,
            "No pending positioning session matches the notification's lcsCorrelationId",
        );
    };

    // Correlation is by lcsCorrelationId, so the embedded lmf-UE-Measurement-ID
    // is not consulted for routing (only the measurements are used).
    let cells = match codec_glue::decode_nrppa_ecid_report(&nrppa_bytes) {
        Ok((_embedded_id, cells)) => cells,
        Err(e) => {
            log::warn!(
                "N2InfoNotify NRPPa decode failed for session (request_id {request_id}): {e}"
            );
            Vec::new()
        }
    };
    if let Ok(context) = lmf_self().read() {
        context.measurement_report(request_id, cells);
    }
    SbiResponse::no_content()
}

/// Handle UE location get
async fn handle_ue_location_get(supi: &str) -> SbiResponse {
    let ctx = lmf_self();
    let ue_loc = if let Ok(context) = ctx.read() {
        context.ue_location_get(supi)
    } else {
        None
    };

    match ue_loc {
        Some(ctx) => {
            let loc_json = ctx.last_location.map(|l| {
                serde_json::json!({
                    "latitude": l.latitude,
                    "longitude": l.longitude,
                    "horizontalAccuracy": l.horizontal_accuracy,
                    "methodUsed": l.method_used,
                })
            });

            SbiResponse::with_status(200)
                .with_json_body(&serde_json::json!({
                    "supi": supi,
                    "servingCell": ctx.serving_cell,
                    "location": loc_json,
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => send_not_found(
            &format!("Location for UE {supi} not found"),
            Some("UE_NOT_FOUND"),
        ),
    }
}

/// Handle UE location update
async fn handle_ue_location_update(supi: &str, request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let loc = LocationEstimate {
        latitude: data.get("latitude").and_then(|v| v.as_f64()).unwrap_or(0.0),
        longitude: data
            .get("longitude")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0),
        altitude: data.get("altitude").and_then(|v| v.as_f64()),
        horizontal_accuracy: data
            .get("horizontalAccuracy")
            .and_then(|v| v.as_f64())
            .unwrap_or(100.0),
        vertical_accuracy: data.get("verticalAccuracy").and_then(|v| v.as_f64()),
        method_used: data
            .get("methodUsed")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        timestamp: data.get("timestamp").and_then(|v| v.as_u64()).unwrap_or(0),
    };

    let ctx = lmf_self();
    let ok = if let Ok(context) = ctx.read() {
        context.ue_location_update(supi, loc)
    } else {
        false
    };

    if ok {
        SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({"supi": supi, "result": "UPDATED"}))
            .unwrap_or_else(|_| SbiResponse::with_status(200))
    } else {
        send_bad_request("Failed to update location", Some("UPDATE_FAILED"))
    }
}

/// Handle capabilities query
async fn handle_capabilities() -> SbiResponse {
    let ctx = lmf_self();
    let methods: Vec<String> = if let Ok(context) = ctx.read() {
        context
            .supported_methods()
            .iter()
            .map(|m| format!("{m:?}"))
            .collect()
    } else {
        vec![]
    };

    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({
            "supportedMethods": methods,
            "nrppaSupported": true,
            "nlsInterfaceSupported": true,
        }))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// Map a TS 29.572 `PositioningMethod` enum string to the internal method
/// (lmfd-12). Returns `None` on an unrecognised value so the caller rejects it
/// with 400 instead of silently defaulting to ECID. The internal model is
/// coarser than the spec enum, so several spec values fold onto `NrBased`.
fn parse_positioning_method(s: &str) -> Option<PositioningMethod> {
    use nlmf::positioning_method as pm;
    match s {
        v if v == pm::CELLID || v == pm::ECID || v == pm::NR_ECID => Some(PositioningMethod::Ecid),
        v if v == pm::OTDOA => Some(PositioningMethod::Otdoa),
        v if v == pm::DL_TDOA
            || v == pm::UL_TDOA
            || v == pm::DL_AOD
            || v == pm::UL_AOA
            || v == pm::MULTI_RTT =>
        {
            Some(PositioningMethod::NrBased)
        }
        v if v == pm::WLAN => Some(PositioningMethod::Wlan),
        v if v == pm::BLUETOOTH => Some(PositioningMethod::Bluetooth),
        v if v == pm::BAROMETRIC_PRESSURE || v == pm::MOTION_SENSOR => {
            Some(PositioningMethod::Sensor)
        }
        _ => None,
    }
}

/// Map a TS 29.572 NR `PositioningMethod` enum string to the internal NR
/// sub-method (lmfd-12). Note the spec keeps the non-conforming `MULTI-RTT`
/// spelling. Returns `None` on unknown.
fn parse_nr_method(s: &str) -> Option<NrPositioningMethod> {
    use nlmf::positioning_method as pm;
    match s {
        v if v == pm::DL_TDOA => Some(NrPositioningMethod::DlTdoa),
        v if v == pm::UL_TDOA => Some(NrPositioningMethod::UlTdoa),
        v if v == pm::DL_AOD => Some(NrPositioningMethod::DlAoD),
        v if v == pm::UL_AOA => Some(NrPositioningMethod::UlAoA),
        v if v == pm::MULTI_RTT => Some(NrPositioningMethod::MultiRtt),
        _ => None,
    }
}

fn parse_qos(s: &str) -> PositioningQos {
    match s {
        "LOW_LATENCY" => PositioningQos::LowLatency,
        "HIGH_ACCURACY" => PositioningQos::HighAccuracy,
        "EMERGENCY" => PositioningQos::Emergency,
        _ => PositioningQos::BestEffort,
    }
}

/// Register LMF with NRF
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

    log::info!("Registering LMF with NRF at {nrf_uri}");

    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_profile = serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "LMF",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [{
            "serviceInstanceId": format!("{}-nlmf-loc", nf_instance_id),
            "serviceName": "nlmf-loc",
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
            "scheme": "http",
            "nfServiceStatus": "REGISTERED",
            "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
        }],
        "allowedNfTypes": ["AMF", "SCP"],
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
            log::info!("LMF registered with NRF successfully (id={nf_instance_id})");

            let mut self_instance = nextgcore_sbi::context::NfInstance::new(
                nf_instance_id,
                nextgcore_sbi::types::NfType::Lmf,
            );
            self_instance.ipv4_addresses = vec![sbi_addr.to_string()];
            let mut svc = nextgcore_sbi::context::NfService::new(
                "nlmf-loc",
                nextgcore_sbi::types::SbiServiceType::NlmfLoc,
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

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-lmfd"]);
        assert_eq!(args.config, "/etc/nextgcore/lmf.yaml");
        assert_eq!(args.sbi_port, 7816);
        assert_eq!(args.max_measurements, 1024);
        // A7 (lmfd-11): the bespoke/debug ingest routes are OFF by default.
        assert!(!args.debug_endpoints);
    }

    // lmfd-12: spec-enumerated PositioningMethod values; unknown -> None.
    #[test]
    fn test_parse_positioning_method() {
        assert_eq!(
            parse_positioning_method("ECID"),
            Some(PositioningMethod::Ecid)
        );
        assert_eq!(
            parse_positioning_method("CELLID"),
            Some(PositioningMethod::Ecid)
        );
        assert_eq!(
            parse_positioning_method("DL_TDOA"),
            Some(PositioningMethod::NrBased)
        );
        assert_eq!(
            parse_positioning_method("MULTI-RTT"),
            Some(PositioningMethod::NrBased)
        );
        // Non-spec values are rejected (no silent default-to-ECID).
        assert_eq!(parse_positioning_method("NR_BASED"), None);
        assert_eq!(parse_positioning_method("GNSS"), None);
        assert_eq!(parse_positioning_method("unknown"), None);
    }

    // lmfd-12: spec NR method spelling (`MULTI-RTT`); unknown -> None.
    #[test]
    fn test_parse_nr_method() {
        assert_eq!(
            parse_nr_method("MULTI-RTT"),
            Some(NrPositioningMethod::MultiRtt)
        );
        assert_eq!(
            parse_nr_method("DL_TDOA"),
            Some(NrPositioningMethod::DlTdoa)
        );
        assert_eq!(parse_nr_method("MULTI_RTT"), None); // wrong spelling rejected
        assert_eq!(parse_nr_method("unknown"), None);
    }

    #[test]
    fn test_parse_qos() {
        assert_eq!(parse_qos("EMERGENCY"), PositioningQos::Emergency);
        assert_eq!(parse_qos("HIGH_ACCURACY"), PositioningQos::HighAccuracy);
        assert_eq!(parse_qos("whatever"), PositioningQos::BestEffort);
    }

    /// Parse a response body as JSON for assertions.
    fn body_json(resp: &SbiResponse) -> serde_json::Value {
        serde_json::from_str(resp.http.content.as_deref().unwrap_or("null")).unwrap()
    }

    fn content_type(resp: &SbiResponse) -> Option<String> {
        resp.http.get_header("Content-Type").cloned()
    }

    /// Seed a real (measurement-derived) location fix for a target SUPI so the
    /// non-fabricating determine-location handler returns 200. Mirrors what the
    /// A2 session-completion path stores (fix + REAL capture timestamp — a
    /// fix with an unknown capture instant is never short-circuit-served).
    fn seed_fix(supi: &str, h_accuracy: f64) {
        seed_fix_at(supi, h_accuracy, unix_now());
    }

    /// Seed a fix with an explicit capture timestamp (Unix seconds; 0 =
    /// unknown capture instant).
    fn seed_fix_at(supi: &str, h_accuracy: f64, timestamp: u64) {
        let loc = LocationEstimate {
            latitude: 37.5,
            longitude: -122.3,
            horizontal_accuracy: h_accuracy,
            method_used: Some(nlmf::positioning_method::ECID.to_string()),
            timestamp,
            ..Default::default()
        };
        assert!(lmf_self().read().unwrap().ue_location_update(supi, loc));
    }

    // -- lmfd-01: apiName routing (nlmf-loc dispatches; nlmf-location 404) ---
    #[tokio::test]
    async fn test_router_nlmf_loc_dispatches() {
        // A real measurement-derived fix must exist for a non-fabricating 200.
        seed_fix("imsi-001010000000099", 40.0);
        let req = SbiRequest::post("/nlmf-loc/v1/determine-location")
            .with_body(r#"{"supi":"imsi-001010000000099"}"#, "application/json");
        let resp = lmf_sbi_request_handler(req).await;
        // Dispatched (not 404); the conformant handler returns 200.
        assert_eq!(resp.status, 200);
    }

    #[tokio::test]
    async fn test_router_old_apiname_is_404() {
        let req = SbiRequest::post("/nlmf-location/v1/determine-location")
            .with_body("{}", "application/json");
        let resp = lmf_sbi_request_handler(req).await;
        assert_eq!(resp.status, 404);
    }

    // -- A7 (lmfd-11): the six bespoke/debug ingest routes are gated behind the
    // opt-in `--debug-endpoints` flag (default OFF). This is the one test that
    // toggles the process-global DEBUG_ENDPOINTS gate; it runs OFF→ON→OFF in a
    // single test so no other test observes a partially-toggled state.
    #[tokio::test]
    async fn test_debug_endpoints_flag_gates_bespoke_routes() {
        lmf_context_init(1024);

        // The six bespoke/debug routes, each with the method it normally handles.
        let normal: [(&str, &str); 7] = [
            ("POST", "/nlmf-loc/v1/measurements"),
            ("GET", "/nlmf-loc/v1/measurements/abc"),
            ("POST", "/nlmf-loc/v1/nrppa-reports"),
            ("POST", "/nlmf-loc/v1/nrppa-binary-reports"),
            ("POST", "/nlmf-loc/v1/lpp-binary-reports"),
            ("GET", "/nlmf-loc/v1/ue-locations/imsi-001010000000777"),
            ("PUT", "/nlmf-loc/v1/ue-locations/imsi-001010000000777"),
        ];
        let build = |method: &str, uri: &str| -> SbiRequest {
            match method {
                "GET" => SbiRequest::get(uri),
                "PUT" => SbiRequest::put(uri).with_body("{}", "application/json"),
                _ => SbiRequest::post(uri).with_body("{}", "application/json"),
            }
        };

        // Default OFF: every bespoke path 404s exactly like an unknown path
        // (no route disclosure), even with the route's normal method.
        DEBUG_ENDPOINTS.store(false, Ordering::Relaxed);
        assert!(!debug_endpoints_enabled());
        for (method, uri) in normal {
            let resp = lmf_sbi_request_handler(build(method, uri)).await;
            assert_eq!(
                resp.status, 404,
                "{method} {uri} must 404 when --debug-endpoints is OFF"
            );
        }

        // Enabled: the arms now match and dispatch. A DELETE (a method none of
        // the arms handle) proves the arm is reachable by returning 405 — the
        // outer 404 would fire only if the arm did not match. This discriminator
        // is independent of each handler's body/state handling.
        DEBUG_ENDPOINTS.store(true, Ordering::Relaxed);
        let reachable: [&str; 6] = [
            "/nlmf-loc/v1/measurements",
            "/nlmf-loc/v1/measurements/abc",
            "/nlmf-loc/v1/nrppa-reports",
            "/nlmf-loc/v1/nrppa-binary-reports",
            "/nlmf-loc/v1/lpp-binary-reports",
            "/nlmf-loc/v1/ue-locations/imsi-001010000000777",
        ];
        for uri in reachable {
            let resp = lmf_sbi_request_handler(SbiRequest::delete(uri)).await;
            assert_eq!(
                resp.status, 405,
                "DELETE {uri} must dispatch (405 Method Not Allowed) when --debug-endpoints is ON"
            );
        }

        // Reset so the shared process-global default does not leak to other tests.
        DEBUG_ENDPOINTS.store(false, Ordering::Relaxed);
    }

    // -- A7 (lmfd-11): an empty TRP registry NEVER yields a fabricated (0,0) fix.
    // A DetermineLocation whose measurements decode but cannot be solved (no
    // registry match) returns 500 POSITIONING_FAILED — never 200 with lat 0.0.
    #[tokio::test]
    async fn test_determine_location_empty_registry_no_fabricated_zero_fix() {
        lmf_context_init(1024);
        // A decodable Multi-RTT measurement for an UN-seeded PCI: no registry hit.
        let lpp = build_multi_rtt_lpp(&[(303, 5000)], 62);
        let input = r#"{"supi":"imsi-001010000000606","lppMessage":{"contentId":"lpp-x"}}"#;
        let req = multipart_lpp_request(input, &[("lpp-x", lpp)]);
        let resp = handle_determine_location(&req).await;
        assert_ne!(resp.status, 200, "no fix must never be reported as a 200");
        assert_eq!(resp.status, 500);
        let v = body_json(&resp);
        assert_eq!(v["cause"], "POSITIONING_FAILED");
        assert!(
            v.get("locationEstimate").is_none(),
            "no fabricated location may be present on a no-fix response"
        );
    }

    // -- lmfd-02 + lmfd-04: 200 OK with a GAD LocationDataExt ----------------
    #[tokio::test]
    async fn test_determine_location_returns_200_location_data_ext() {
        // Seed a real fix (h_accuracy 50 < requested 100 -> FULFILLED).
        seed_fix("imsi-001010000000001", 50.0);
        let body = r#"{
            "supi": "imsi-001010000000001",
            "locationQoS": { "hAccuracy": 100.0 },
            "supportedGADShapes": ["POINT_UNCERTAINTY_CIRCLE"]
        }"#;
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let resp = handle_determine_location(&req).await;
        assert_eq!(resp.status, 200);

        // Body deserializes as LocationDataExt and carries a GAD shape.
        let ext: nlmf::LocationDataExt =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(
            ext.location_data.location_estimate.shape(),
            "POINT_UNCERTAINTY_CIRCLE"
        );
        assert!(ext.location_data.positioning_data_list.is_some());
        assert_eq!(
            ext.location_data.accuracy_fulfilment_indicator.as_deref(),
            Some("REQUESTED_ACCURACY_FULFILLED")
        );
        let v = body_json(&resp);
        assert_eq!(v["locationEstimate"]["shape"], "POINT_UNCERTAINTY_CIRCLE");
    }

    // -- lmfd-04: shape negotiation honors supportedGADShapes ----------------
    #[tokio::test]
    async fn test_determine_location_negotiates_ellipse_shape() {
        seed_fix("imsi-001010000000002", 40.0);
        let body = r#"{
            "supi": "imsi-001010000000002",
            "locationQoS": { "verticalRequested": true },
            "supportedGADShapes": ["POINT_UNCERTAINTY_ELLIPSE", "POINT_UNCERTAINTY_CIRCLE"]
        }"#;
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let resp = handle_determine_location(&req).await;
        assert_eq!(resp.status, 200);
        let v = body_json(&resp);
        assert_eq!(v["locationEstimate"]["shape"], "POINT_UNCERTAINTY_ELLIPSE");
    }

    // -- lmfd-03 + lmfd-10: ecgi/ncgi exclusion -> 400 ProblemDetails --------
    #[tokio::test]
    async fn test_determine_location_ecgi_ncgi_exclusion_400() {
        let body = r#"{
            "ecgi": { "plmnId": { "mcc": "001", "mnc": "01" }, "eutraCellId": "0000001" },
            "ncgi": { "plmnId": { "mcc": "001", "mnc": "01" }, "nrCellId": "000000001" }
        }"#;
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let resp = handle_determine_location(&req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(
            content_type(&resp).as_deref(),
            Some("application/problem+json")
        );
        let v = body_json(&resp);
        assert_eq!(v["cause"], "MANDATORY_IE_INCORRECT");
        assert_eq!(v["status"], 400);
    }

    // -- lmfd-03 + lmfd-10: malformed body -> 400 ProblemDetails -------------
    #[tokio::test]
    async fn test_determine_location_malformed_body_400() {
        let req = SbiRequest::post("/nlmf-loc/v1/determine-location")
            .with_body("not json", "application/json");
        let resp = handle_determine_location(&req).await;
        assert_eq!(resp.status, 400);
        let v = body_json(&resp);
        assert_eq!(v["cause"], "INVALID_MSG_FORMAT");
    }

    // -- lmfd-02 + lmfd-10 + A6/WSB-5: zero response budget -> 504 -----------
    // TS 29.572 Table 6.1.7.3-1 (specs/29572-j60.txt:7651): the ONLY valid
    // 504 cause is UNREACHABLE_USER ("The user could not be reached in order
    // to perform positioning procedure").
    #[tokio::test]
    async fn test_determine_location_timeout_504() {
        let body = r#"{ "supi": "imsi-001010000000003", "maxRespTime": 0 }"#;
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let resp = handle_determine_location(&req).await;
        assert_eq!(resp.status, 504);
        assert_eq!(
            content_type(&resp).as_deref(),
            Some("application/problem+json")
        );
        let v = body_json(&resp);
        // Status/cause PAIRING is the falsifiable check: 504 must carry
        // UNREACHABLE_USER (byte-equal to the spec table value), never
        // POSITIONING_FAILED or the retired invented cause.
        assert_eq!(v["cause"], "UNREACHABLE_USER");
        assert_eq!(v["status"], 504);
    }

    // -- A2 + A6: no stored fix + unreachable AMF -> 504 UNREACHABLE_USER ----
    // TS 29.572 Table 6.1.7.3-1 (specs/29572-j60.txt:7651): the user could not
    // be reached to perform the positioning procedure. With no NRF configured
    // the serving AMF is undiscoverable — the fail-closed live path 504s
    // (never the retired invented cause, never a fabricated 200).
    #[tokio::test]
    async fn test_determine_location_unreachable_amf_504_unreachable_user() {
        // A SUPI never seeded by any test: no per-SUPI stored fix exists, so
        // the handler runs the live procedure and fails at AMF discovery.
        let body = r#"{ "supi": "imsi-001010000000404" }"#;
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let resp = handle_determine_location(&req).await;
        assert_eq!(resp.status, 504);
        assert_eq!(
            content_type(&resp).as_deref(),
            Some("application/problem+json")
        );
        let v = body_json(&resp);
        // Pairing check: 504 must carry UNREACHABLE_USER (byte-equal to the
        // spec table value), never POSITIONING_FAILED.
        assert_eq!(v["cause"], "UNREACHABLE_USER");
        assert_eq!(v["status"], 504);
    }

    // -- A2: solver failure on the session channel -> 500 POSITIONING_FAILED -
    // TS 29.572 Table 6.1.7.3-1 (specs/29572-j60.txt:7643): a report was
    // received but the solver produced no fix.
    #[tokio::test]
    async fn test_positioning_outcome_solver_failed_maps_to_500() {
        lmf_context_init(1024);
        let input: nlmf::InputData =
            serde_json::from_str(r#"{ "supi": "imsi-001010000000405" }"#).unwrap();
        let (corr, rx) = lmf_self().read().unwrap().positioning_session_register(
            input.supi.clone(),
            201,
            990_001,
        );
        assert!(lmf_self()
            .read()
            .unwrap()
            .positioning_session_complete(&corr, PositioningOutcome::SolverFailed));
        let resp = await_positioning_outcome(&input, corr, rx).await;
        assert_eq!(resp.status, 500);
        let v = body_json(&resp);
        assert_eq!(v["cause"], "POSITIONING_FAILED");
    }

    // -- A2: a real fix on the session channel -> 200 LocationDataExt --------
    #[tokio::test]
    async fn test_positioning_outcome_fix_maps_to_200() {
        lmf_context_init(1024);
        let input: nlmf::InputData = serde_json::from_str(
            r#"{ "supi": "imsi-001010000000406",
                 "supportedGADShapes": ["POINT_UNCERTAINTY_CIRCLE"] }"#,
        )
        .unwrap();
        let (corr, rx) = lmf_self().read().unwrap().positioning_session_register(
            input.supi.clone(),
            202,
            990_002,
        );
        let fix = LocationEstimate {
            latitude: 37.7749,
            longitude: -122.4194,
            horizontal_accuracy: 25.0,
            method_used: Some(nlmf::positioning_method::NR_ECID.to_string()),
            ..Default::default()
        };
        assert!(lmf_self()
            .read()
            .unwrap()
            .positioning_session_complete(&corr, PositioningOutcome::Fix(fix)));
        let resp = await_positioning_outcome(&input, corr, rx).await;
        assert_eq!(resp.status, 200);
        let v = body_json(&resp);
        assert_eq!(v["locationEstimate"]["shape"], "POINT_UNCERTAINTY_CIRCLE");
        assert_eq!(v["locationEstimate"]["point"]["lat"], 37.7749);
        // Freshly computed fix: honest age 0.
        assert_eq!(v["ageOfLocationEstimate"], 0);
        assert_eq!(v["positioningDataList"][0]["method"], "NR_ECID");
        // The completed session also cached the fix per-SUPI with a REAL
        // capture timestamp (age semantics honoured on later requests).
        let cached = lmf_self()
            .read()
            .unwrap()
            .stored_fix("imsi-001010000000406")
            .expect("fix cached for the target SUPI");
        assert!(cached.timestamp > 0, "cached fix must carry a timestamp");
    }

    // -- A2: timeout on the session channel -> 504 + session expired ---------
    #[tokio::test]
    async fn test_positioning_outcome_timeout_504_and_session_expired() {
        lmf_context_init(1024);
        // NO_DELAY -> zero wait budget -> immediate timeout (no real sleeps).
        let input: nlmf::InputData = serde_json::from_str(
            r#"{ "supi": "imsi-001010000000407",
                 "locationQoS": { "responseTime": "NO_DELAY" } }"#,
        )
        .unwrap();
        let (corr, rx) = lmf_self().read().unwrap().positioning_session_register(
            input.supi.clone(),
            203,
            990_003,
        );
        let resp = await_positioning_outcome(&input, corr.clone(), rx).await;
        assert_eq!(resp.status, 504);
        let v = body_json(&resp);
        assert_eq!(v["cause"], "UNREACHABLE_USER");
        // The pending session was expired (removed) on timeout.
        assert!(lmf_self()
            .read()
            .unwrap()
            .positioning_session_find(&corr)
            .is_none());
    }

    // -- A2: no target UE identity -> 400 MANDATORY_IE_MISSING ---------------
    #[tokio::test]
    async fn test_determine_location_no_target_identity_400() {
        let body = r#"{ "locationQoS": { "hAccuracy": 50.0 } }"#;
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let resp = handle_determine_location(&req).await;
        assert_eq!(resp.status, 400);
        let v = body_json(&resp);
        assert_eq!(v["cause"], "MANDATORY_IE_MISSING");
    }

    // -- A2: stored fix served with an HONEST age (not hardcoded 0) ----------
    #[tokio::test]
    async fn test_determine_location_stored_fix_reports_real_age() {
        // Captured 5 minutes ago.
        seed_fix_at("imsi-001010000000408", 40.0, unix_now() - 300);
        let body = r#"{ "supi": "imsi-001010000000408" }"#;
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let resp = handle_determine_location(&req).await;
        assert_eq!(resp.status, 200);
        let v = body_json(&resp);
        assert_eq!(
            v["ageOfLocationEstimate"], 5,
            "ageOfLocationEstimate must be the REAL age in minutes, not 0"
        );
    }

    // -- A2: a stored fix with UNKNOWN capture instant is not short-circuited -
    #[tokio::test]
    async fn test_determine_location_ageless_stored_fix_not_served() {
        // timestamp 0 = capture instant unknown -> age cannot be honoured ->
        // the live procedure runs (and 504s here: no AMF discoverable).
        seed_fix_at("imsi-001010000000409", 40.0, 0);
        let body = r#"{ "supi": "imsi-001010000000409" }"#;
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let resp = handle_determine_location(&req).await;
        assert_eq!(resp.status, 504);
        let v = body_json(&resp);
        assert_eq!(v["cause"], "UNREACHABLE_USER");
    }

    // -- A2 acceptance: the global newest-report fallback is UNREACHABLE from
    // the MT-LR path — another UE's completed report is never served. --------
    #[tokio::test]
    async fn test_determine_location_never_serves_another_ues_report() {
        lmf_context_init(1024);
        // Complete a measurement report (for some unrelated request) so a
        // "global newest report" exists — the retired latest_location fallback
        // would have served it to ANY supi.
        let ctx = lmf_self();
        let req_id = {
            let guard = ctx.read().unwrap();
            let req = guard
                .measurement_request(
                    424_242,
                    PositioningMethod::Ecid,
                    None,
                    None,
                    PositioningQos::BestEffort,
                )
                .expect("measurement request");
            guard.measurement_report(
                req.request_id,
                vec![CellMeasurement {
                    nr_cgi: "001-01-424242-01".to_string(),
                    rsrp: Some(-70),
                    rsrq: Some(-9),
                    timing_advance: Some(50),
                    aoa: None,
                    rtt_ns: None,
                    rstd_ns: None,
                }],
            );
            req.request_id
        };
        assert!(
            lmf_self().read().unwrap().report_find(req_id).is_some(),
            "global report exists"
        );
        // A DIFFERENT, never-seeded SUPI must NOT be served that report.
        let body = r#"{ "supi": "imsi-001010000000410" }"#;
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let resp = handle_determine_location(&req).await;
        assert_eq!(
            resp.status, 504,
            "another UE's report must never satisfy this target (correlation isolation)"
        );
    }

    // -- A2: wait budget derivation ------------------------------------------
    #[test]
    fn test_wait_budget_bounds() {
        let parse = |s: &str| -> nlmf::InputData { serde_json::from_str(s).unwrap() };
        // Default: the 20 s hard cap.
        assert_eq!(
            wait_budget(&parse(r#"{"supi":"imsi-1"}"#)),
            Duration::from_secs(20)
        );
        // maxRespTime (DurationSec) tightens the budget.
        assert_eq!(
            wait_budget(&parse(r#"{"supi":"imsi-1","maxRespTime":3}"#)),
            Duration::from_secs(3)
        );
        // ...but never widens past the hard cap.
        assert_eq!(
            wait_budget(&parse(r#"{"supi":"imsi-1","maxRespTime":600}"#)),
            Duration::from_secs(20)
        );
        // LOW_DELAY bounds to 5 s; NO_DELAY waits not at all.
        assert_eq!(
            wait_budget(&parse(
                r#"{"supi":"imsi-1","locationQoS":{"responseTime":"LOW_DELAY"}}"#
            )),
            Duration::from_secs(5)
        );
        assert_eq!(
            wait_budget(&parse(
                r#"{"supi":"imsi-1","locationQoS":{"responseTime":"NO_DELAY"}}"#
            )),
            Duration::ZERO
        );
    }

    // -- A2: honest age computation ------------------------------------------
    #[test]
    fn test_age_of_fix_minutes() {
        // Unknown capture instant -> None (never a made-up age).
        assert_eq!(age_of_fix_minutes(0), None);
        // Fresh fix -> 0 minutes (computed, not hardcoded).
        assert_eq!(age_of_fix_minutes(unix_now()), Some(0));
        // 10 minutes ago.
        assert_eq!(age_of_fix_minutes(unix_now() - 600), Some(10));
        // NTP-epoch timestamps are converted (offset 2_208_988_800 s).
        assert_eq!(
            age_of_fix_minutes(unix_now() - 600 + NTP_UNIX_OFFSET),
            Some(10)
        );
        // Saturates at the TS 29.571 maximum (32767).
        assert_eq!(age_of_fix_minutes(1), Some(32_767));
    }

    // -- lmfd-12: unknown positioning method on the debug route -> 400 -------
    #[tokio::test]
    async fn test_measurement_request_unknown_method_400() {
        lmf_context_init(1024);
        let body = r#"{ "amfUeNgapId": 1, "positioningMethod": "BOGUS" }"#;
        let req = SbiRequest::post("/nlmf-loc/v1/measurements").with_body(body, "application/json");
        let resp = handle_measurement_request(&req).await;
        assert_eq!(resp.status, 400);
        let v = body_json(&resp);
        assert_eq!(v["cause"], "MANDATORY_IE_INCORRECT");
    }

    // -- lmfd#0: configure-up -------------------------------------------------

    #[tokio::test]
    async fn test_configure_up_204() {
        let body = r#"{
            "upNotifyCallBackUri": "http://af/up-notify",
            "notifCorrelationId": "nc-001",
            "supi": "imsi-001010000000070"
        }"#;
        let req = SbiRequest::post("/nlmf-loc/v1/configure-up").with_body(body, "application/json");
        let resp = handle_configure_up(&req).await;
        assert_eq!(resp.status, 204);
    }

    #[tokio::test]
    async fn test_configure_up_missing_ue_id_400() {
        let body = r#"{
            "upNotifyCallBackUri": "http://af/up-notify",
            "notifCorrelationId": "nc-002"
        }"#;
        let req = SbiRequest::post("/nlmf-loc/v1/configure-up").with_body(body, "application/json");
        let resp = handle_configure_up(&req).await;
        assert_eq!(resp.status, 400);
        let v = body_json(&resp);
        assert_eq!(v["cause"], "MANDATORY_IE_MISSING");
    }

    // -- lmfd#0: measure-location -> 403 LOCATION_MEASUREMENT_UNKNOWN --------

    #[tokio::test]
    async fn test_measure_location_unknown_403() {
        let body = r#"{}"#;
        let req =
            SbiRequest::post("/nlmf-loc/v1/measure-location").with_body(body, "application/json");
        let resp = handle_measure_location(&req).await;
        assert_eq!(resp.status, 403);
        let v = body_json(&resp);
        assert_eq!(v["cause"], "LOCATION_MEASUREMENT_UNKNOWN");
    }

    // -- lmfd#0: location-context-transfer ------------------------------------

    #[tokio::test]
    async fn test_location_context_transfer_204() {
        let body = r#"{
            "amfId": "amf-01",
            "ldrType": "PERIODIC",
            "hgmlcCallBackURI": "http://gmlc/ctx-cb",
            "ldrReference": "aa01",
            "eventReportMessage": { "eventClass": "SUPPLEMENTARY_SERVICES", "eventContent": {} }
        }"#;
        let req = SbiRequest::post("/nlmf-loc/v1/location-context-transfer")
            .with_body(body, "application/json");
        let resp = handle_location_context_transfer(&req).await;
        assert_eq!(resp.status, 204);
        // LDR context must be registered.
        let found = lmf_self().read().unwrap().ldr_find("aa01");
        assert!(found.is_some(), "LDR context not registered");
        assert_eq!(found.unwrap().ldr_type, "PERIODIC");
    }

    #[tokio::test]
    async fn test_location_context_transfer_bad_event_class_403() {
        let body = r#"{
            "amfId": "amf-01",
            "ldrType": "UE_AVAILABLE",
            "hgmlcCallBackURI": "http://gmlc/ctx-cb",
            "ldrReference": "aa02",
            "eventReportMessage": { "eventClass": "BOGUS_CLASS", "eventContent": {} }
        }"#;
        let req = SbiRequest::post("/nlmf-loc/v1/location-context-transfer")
            .with_body(body, "application/json");
        let resp = handle_location_context_transfer(&req).await;
        assert_eq!(resp.status, 403);
        let v = body_json(&resp);
        assert_eq!(v["cause"], "EVENT_REPORT_UNRECOGNIZED");
    }

    // -- lmfd#0: cancel-location lifecycle ------------------------------------

    #[tokio::test]
    async fn test_cancel_location_lifecycle() {
        // Seed an LDR session directly.
        lmf_self().read().unwrap().register_ldr(LdrContext {
            ldr_reference: "bb01".to_string(),
            ldr_type: "UE_AVAILABLE".to_string(),
            hgmlc_callback_uri: Some("http://gmlc/cb".to_string()),
            supi: None,
            periodic_event_info: None,
        });

        // First cancel -> 204.
        let body = r#"{"hgmlcCallBackURI":"http://gmlc/cb","ldrReference":"bb01"}"#;
        let req =
            SbiRequest::post("/nlmf-loc/v1/cancel-location").with_body(body, "application/json");
        let resp = handle_cancel_location(&req).await;
        assert_eq!(resp.status, 204);

        // Second cancel -> 403 LOCATION_SESSION_UNKNOWN.
        let req2 =
            SbiRequest::post("/nlmf-loc/v1/cancel-location").with_body(body, "application/json");
        let resp2 = handle_cancel_location(&req2).await;
        assert_eq!(resp2.status, 403);
        let v = body_json(&resp2);
        assert_eq!(v["cause"], "LOCATION_SESSION_UNKNOWN");
    }

    // -- lmfd#0: up-subscriptions 201 + unsubscribe 204 ----------------------

    #[tokio::test]
    async fn test_up_subscribe_201_and_unsubscribe_204() {
        let body = r#"{
            "upNotifyCallBackUri": "http://af/up",
            "notifCorrelationId": "nc-sub-1",
            "supi": "imsi-001010000000080"
        }"#;
        let req =
            SbiRequest::post("/nlmf-loc/v1/up-subscriptions").with_body(body, "application/json");
        let resp = handle_up_subscribe(&req).await;
        assert_eq!(resp.status, 201);
        assert!(
            resp.http.get_header("Location").is_some(),
            "Location header missing on 201"
        );

        // DELETE any subscriptionId -> 204.
        let resp2 = handle_up_unsubscribe("sub-1").await;
        assert_eq!(resp2.status, 204);
    }

    // -- lmfd#1: 204 assistance-data branch -----------------------------------

    #[tokio::test]
    async fn test_determine_location_assistance_data_204() {
        let body =
            r#"{"supi":"imsi-001010000000012","ueLocationServiceInd":"LOCATION_ASSISTANCE_DATA"}"#;
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let resp = handle_determine_location(&req).await;
        assert_eq!(resp.status, 204);
    }

    // -- lmfd#1: deferred LDR registers context and is cancellable -----------

    #[tokio::test]
    async fn test_determine_location_deferred_ldr_registers_and_cancellable() {
        seed_fix("imsi-001010000000013", 40.0);
        let body = r#"{
            "supi": "imsi-001010000000013",
            "ldrType": "PERIODIC",
            "ldrReference": "cc01",
            "hgmlcCallBackURI": "http://gmlc/cb"
        }"#;
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let resp = handle_determine_location(&req).await;
        // Periodic LDR activation returns 200 LocationDataExt (fix exists).
        assert_eq!(resp.status, 200);
        // LDR context must have been registered.
        let found = lmf_self()
            .read()
            .unwrap()
            .ldr_find("cc01")
            .expect("LDR context not registered after deferred determine-location");
        assert_eq!(found.ldr_type, "PERIODIC");
        assert_eq!(found.hgmlc_callback_uri.as_deref(), Some("http://gmlc/cb"));
    }

    // -----------------------------------------------------------------------
    // A5: multipart/related DetermineLocation + InputData.lppMessage
    // (TS 29.572 §6.1.4.2.2, specs/TS29572_Nlmf_Location.yaml:42-76).
    // -----------------------------------------------------------------------

    /// Build a determine-location `SbiRequest` exactly as the SBI server hands
    /// a decoded `multipart/related` body to the handler: jsonData in
    /// `http.content`, binary LPP part(s) in `http.parts`.
    fn multipart_lpp_request(input_json: &str, parts: &[(&str, Vec<u8>)]) -> SbiRequest {
        use bytes::Bytes;
        use nextgcore_sbi::message::SbiPart;
        let mut req = SbiRequest::post("/nlmf-loc/v1/determine-location");
        req.http.set_content(input_json.to_string());
        req.http.set_header(
            "Content-Type",
            "multipart/related; boundary=\"b1\"; type=\"application/json\"",
        );
        for (cid, data) in parts {
            req.http.add_part(SbiPart::with_content(
                *cid,
                "application/vnd.3gpp.lpp",
                Bytes::from(data.clone()),
            ));
        }
        req
    }

    /// Encode a UE LPP `ProvideLocationInformation` (nr-Multi-RTT) carrying the
    /// given `(nr-PhysCellID, K0 code)` measurements.
    fn build_multi_rtt_lpp(cells: &[(u16, u32)], txn: u8) -> Vec<u8> {
        use nextgcore_asn1c::lpp::ecid::{
            ProvideLocationInformation, ProvideLocationInformationR9,
        };
        use nextgcore_asn1c::lpp::message::{LppMessage, LppMessageBody, MessageBodyC1};
        use nextgcore_asn1c::lpp::nr_dl_tdoa::{NrRstd, NrSlot, NrTimeStamp, NrTimingQuality};
        use nextgcore_asn1c::lpp::nr_multi_rtt::{
            NrMultiRttMeasElement, NrMultiRttMeasList, NrMultiRttProvideLocationInformation,
            NrMultiRttSignalMeasurementInformation,
        };
        use nextgcore_asn1c::lpp::types::{Initiator, LppTransactionId, TransactionNumber};

        let items: Vec<NrMultiRttMeasElement> = cells
            .iter()
            .map(|(pci, val)| NrMultiRttMeasElement {
                dl_prs_id: 5,
                nr_phys_cell_id: Some(*pci),
                nr_arfcn: None,
                nr_ue_rx_tx_time_diff: NrRstd::K0(*val),
                nr_time_stamp: NrTimeStamp {
                    dl_prs_id: 5,
                    nr_phys_cell_id: None,
                    nr_arfcn: None,
                    nr_sfn: 700,
                    nr_slot: NrSlot::Scs30(11),
                },
                nr_timing_quality: NrTimingQuality {
                    timing_quality_value: 8,
                    timing_quality_resolution: 1,
                },
                nr_dl_prs_rsrp_result: Some(90),
            })
            .collect();
        let msg = LppMessage {
            transaction_id: Some(LppTransactionId {
                initiator: Initiator::TargetDevice,
                transaction_number: TransactionNumber(txn),
            }),
            end_transaction: true,
            sequence_number: None,
            acknowledgement: None,
            message_body: Some(LppMessageBody::C1(
                MessageBodyC1::ProvideLocationInformation(ProvideLocationInformation {
                    ies: ProvideLocationInformationR9 {
                        ecid: None,
                        nr_multi_rtt: Some(NrMultiRttProvideLocationInformation {
                            signal_measurement_information: Some(
                                NrMultiRttSignalMeasurementInformation {
                                    meas_list: NrMultiRttMeasList { items },
                                },
                            ),
                        }),
                        nr_dl_tdoa: None,
                    },
                }),
            )),
        };
        msg.encode().expect("encode multi-rtt lpp").to_vec()
    }

    /// Seed the global TRP registry with a solvable 4-cell Multi-RTT scene and
    /// build a matching UE LPP ProvideLocationInformation (K0 codes derived
    /// from the true UE position via the codec's T_c scaling).
    fn seed_scene_and_build_multi_rtt_lpp(txn: u8) -> Vec<u8> {
        use crate::positioning::{enu_to_geodetic, EnuPoint, TrpCoord, SPEED_OF_LIGHT_M_S};
        // T_c ns, matching codec_glue::TC_NS (TS 38.211 §4.1).
        const TC_NS: f64 = 1_000_000_000.0 / (480_000.0 * 4_096.0);
        let origin = TrpCoord::new(37.7749, -122.4194, 0.0);
        let trps = [
            (201u16, 0.0f64, 0.0f64),
            (202, 1000.0, 0.0),
            (203, 0.0, 1000.0),
            (204, 1000.0, 1000.0),
        ];
        let (ue_e, ue_n) = (350.0f64, 600.0f64);

        let ctx = lmf_self();
        let mut cells: Vec<(u16, u32)> = Vec::new();
        {
            let guard = ctx.read().unwrap();
            for (pci, e, n) in trps.iter() {
                let coord = enu_to_geodetic(
                    EnuPoint {
                        e: *e,
                        n: *n,
                        u: 0.0,
                    },
                    origin,
                );
                guard.set_cell_coord(format!("pci-{pci}"), coord);
                let range_m = (ue_e - e).hypot(ue_n - n);
                let target_rtt_ns = range_m * 2.0 / SPEED_OF_LIGHT_M_S * 1e9;
                let val = (target_rtt_ns / TC_NS).round() as u32;
                cells.push((*pci, val));
            }
        }
        build_multi_rtt_lpp(&cells, txn)
    }

    // -- A5 acceptance: LPP bytes reach the decode adapter -> a real fix ------
    #[tokio::test]
    async fn test_determine_location_multipart_lpp_produces_fix_200() {
        lmf_context_init(1024);
        let lpp = seed_scene_and_build_multi_rtt_lpp(55);
        let input = r#"{"supi":"imsi-001010000000501",
            "ueLocationServiceInd":"LOCATION_ESTIMATE",
            "lppMessage":{"contentId":"lpp-mo-lr"}}"#;
        let req = multipart_lpp_request(input, &[("lpp-mo-lr", lpp)]);
        let resp = handle_determine_location(&req).await;
        assert_eq!(
            resp.status, 200,
            "the UE-provided LPP measurements must be decoded and solved"
        );
        let v = body_json(&resp);
        // A real-solver fix (NOT the (0,0) placeholder): near the seeded scene.
        let lat = v["locationEstimate"]["point"]["lat"].as_f64().unwrap();
        let lon = v["locationEstimate"]["point"]["lon"].as_f64().unwrap();
        assert!(
            (37.0..38.0).contains(&lat),
            "lat={lat} (placeholder leaked?)"
        );
        assert!((-123.0..-122.0).contains(&lon), "lon={lon}");
        assert_eq!(v["positioningDataList"][0]["method"], "MULTI-RTT");
    }

    // -- A5: decode happens but no solvable fix -> 500 (not the network 504) --
    // A single Multi-RTT cell for a UN-seeded PCI: the bytes ARE decoded (a
    // non-empty measurement set), fed to the solver, which fails -> 500
    // POSITIONING_FAILED. If the parts had been ignored, the handler would have
    // fallen through to the network path (504). 500-vs-504 is the discriminator.
    #[tokio::test]
    async fn test_determine_location_multipart_lpp_no_fix_500() {
        lmf_context_init(1024);
        let lpp = build_multi_rtt_lpp(&[(301, 5000)], 60);
        let input = r#"{"supi":"imsi-001010000000502","lppMessage":{"contentId":"lpp-1"}}"#;
        let req = multipart_lpp_request(input, &[("lpp-1", lpp)]);
        let resp = handle_determine_location(&req).await;
        assert_eq!(resp.status, 500);
        let v = body_json(&resp);
        assert_eq!(v["cause"], "POSITIONING_FAILED");
    }

    // -- A5 acceptance: a dangling contentId fails 400 (never silently ignored) -
    #[tokio::test]
    async fn test_determine_location_lpp_dangling_content_id_400() {
        lmf_context_init(1024);
        let lpp = build_multi_rtt_lpp(&[(301, 5000)], 61);
        // lppMessage references "lpp-missing"; the part carries a DIFFERENT id.
        let input = r#"{"supi":"imsi-001010000000503","lppMessage":{"contentId":"lpp-missing"}}"#;
        let req = multipart_lpp_request(input, &[("some-other-id", lpp)]);
        let resp = handle_determine_location(&req).await;
        assert_eq!(resp.status, 400);
        assert_eq!(
            content_type(&resp).as_deref(),
            Some("application/problem+json")
        );
        let v = body_json(&resp);
        assert_eq!(v["cause"], "MANDATORY_IE_INCORRECT");
    }

    // -- A5: a lppMessage IE with NO multipart parts at all -> 400 ------------
    #[tokio::test]
    async fn test_determine_location_lpp_ref_without_parts_400() {
        lmf_context_init(1024);
        // application/json body (no binary parts) carrying a lppMessage ref.
        let body = r#"{"supi":"imsi-001010000000504","lppMessage":{"contentId":"lpp-x"}}"#;
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let resp = handle_determine_location(&req).await;
        assert_eq!(resp.status, 400);
        let v = body_json(&resp);
        assert_eq!(v["cause"], "MANDATORY_IE_INCORRECT");
    }

    // -- A5: content-type gate rejects unsupported media types with 415 -------
    #[tokio::test]
    async fn test_determine_location_unsupported_media_type_415() {
        let req = SbiRequest::post("/nlmf-loc/v1/determine-location")
            .with_body("not json or multipart", "text/plain");
        let resp = handle_determine_location(&req).await;
        assert_eq!(resp.status, 415);
        assert_eq!(
            content_type(&resp).as_deref(),
            Some("application/problem+json")
        );
        let v = body_json(&resp);
        assert_eq!(v["status"], 415);
    }

    // -- A5 acceptance: plain-JSON DetermineLocation is byte-identical to today.
    // A JSON request with no lppMessage takes the exact pre-A5 path (stored-fix
    // short-circuit -> 200 LocationDataExt), untouched by the new content-type
    // gate (application/json) or the multipart branch (no parts).
    #[tokio::test]
    async fn test_determine_location_plain_json_unaffected() {
        seed_fix("imsi-001010000000505", 50.0);
        let body = r#"{
            "supi": "imsi-001010000000505",
            "locationQoS": { "hAccuracy": 100.0 },
            "supportedGADShapes": ["POINT_UNCERTAINTY_CIRCLE"]
        }"#;
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let resp = handle_determine_location(&req).await;
        assert_eq!(resp.status, 200);
        let v = body_json(&resp);
        assert_eq!(v["locationEstimate"]["shape"], "POINT_UNCERTAINTY_CIRCLE");
        assert_eq!(
            v["accuracyFulfilmentIndicator"],
            "REQUESTED_ACCURACY_FULFILLED"
        );
    }

    // -- A5 strict self-consistency: our own multipart writer -> our reader ->
    // handler round-trip (TS 29.500 boundary handling), yielding the same fix.
    #[tokio::test]
    async fn test_determine_location_multipart_roundtrip_via_sbi_codec() {
        use bytes::Bytes;
        use nextgcore_sbi::message::SbiPart;
        use nextgcore_sbi::multipart;
        lmf_context_init(1024);
        let lpp = seed_scene_and_build_multi_rtt_lpp(57);
        let input = r#"{"supi":"imsi-001010000000506","lppMessage":{"contentId":"lpp-mo-lr"}}"#;
        let part = SbiPart::with_content(
            "lpp-mo-lr",
            "application/vnd.3gpp.lpp",
            Bytes::from(lpp.clone()),
        );
        let boundary = multipart::generate_boundary();
        let body = multipart::encode(Some(input), std::slice::from_ref(&part), &boundary);
        let ct = multipart::content_type_with_boundary(&boundary);
        // Decode with our own reader (what the SBI server does on ingress).
        let decoded = multipart::decode(&ct, &body).expect("multipart decode");
        // The binary LPP part survived the writer->reader round-trip byte-exact.
        assert_eq!(decoded.parts.len(), 1);
        assert_eq!(decoded.parts[0].data.as_ref(), lpp.as_slice());
        let mut req = SbiRequest::post("/nlmf-loc/v1/determine-location");
        req.http.set_content(decoded.json.expect("jsonData root"));
        req.http.set_header("Content-Type", ct);
        for p in decoded.parts {
            req.http.add_part(p);
        }
        let resp = handle_determine_location(&req).await;
        assert_eq!(
            resp.status, 200,
            "client-encoded multipart accepted round-trip"
        );
    }

    // =======================================================================
    // A4: uplink notify callbacks (handle_n1_message_notify / handle_n2_info_notify)
    // =======================================================================

    /// Encode a UE LPP `ProvideLocationInformation` (E-CID) carrying one
    /// measured-results element (physCellId `pci`, rsrp-Result, ue-RxTxTimeDiff).
    fn build_ecid_lpp(pci: u16, rsrp_result: u8, ue_rx_tx: u16, txn: u8) -> Vec<u8> {
        use nextgcore_asn1c::lpp::ecid::{
            EcidProvideLocationInformation, EcidSignalMeasurementInformation,
            MeasuredResultsElement, ProvideLocationInformation, ProvideLocationInformationR9,
        };
        use nextgcore_asn1c::lpp::message::{LppMessage, LppMessageBody, MessageBodyC1};
        use nextgcore_asn1c::lpp::types::{Initiator, LppTransactionId, TransactionNumber};
        let element = MeasuredResultsElement {
            phys_cell_id: pci,
            arfcn_eutra: 1850,
            system_frame_number: None,
            rsrp_result: Some(rsrp_result),
            rsrq_result: Some(20),
            ue_rx_tx_time_diff: Some(ue_rx_tx),
        };
        let msg = LppMessage {
            transaction_id: Some(LppTransactionId {
                initiator: Initiator::TargetDevice,
                transaction_number: TransactionNumber(txn),
            }),
            end_transaction: true,
            sequence_number: None,
            acknowledgement: None,
            message_body: Some(LppMessageBody::C1(
                MessageBodyC1::ProvideLocationInformation(ProvideLocationInformation {
                    ies: ProvideLocationInformationR9 {
                        ecid: Some(EcidProvideLocationInformation {
                            // MeasuredResultsList SIZE(1..32): the serving cell
                            // rides in the list (an empty list fails encode).
                            signal_measurement_information: Some(
                                EcidSignalMeasurementInformation {
                                    primary_cell_measured_results: None,
                                    measured_results_list: vec![element],
                                },
                            ),
                            ecid_error: None,
                        }),
                        nr_multi_rtt: None,
                        nr_dl_tdoa: None,
                    },
                }),
            )),
        };
        msg.encode().expect("encode E-CID lpp").to_vec()
    }

    /// Encode an NRPPa E-CID Measurement Report (serving cell + TA + RSRP).
    fn build_nrppa_ecid_report() -> Vec<u8> {
        use nextgcore_asn1c::nrppa::ies::{
            ECidMeasurementResult, MeasuredResults, MeasuredResultsValue, NgRanCell, NgRanCgi,
            PlmnIdentity, ResultRsrpEutraItem, Tac, UeMeasurementId,
        };
        use nextgcore_asn1c::nrppa::pdu::build_ecid_measurement_report;
        use nextgcore_asn1c::nrppa::types::NrppaTransactionId;
        let e_cid = ECidMeasurementResult {
            serving_cell_id: NgRanCgi {
                plmn_identity: PlmnIdentity([0x02, 0xF8, 0x39]),
                ng_ran_cell: NgRanCell::NrCellId(0x000000001),
            },
            serving_cell_tac: Tac([0x00, 0x12, 0x34]),
            ng_ran_access_point_position: None,
            measured_results: Some(MeasuredResults {
                values: vec![
                    MeasuredResultsValue::ValueTimingAdvanceType1(500),
                    MeasuredResultsValue::ResultRsrp(vec![ResultRsrpEutraItem {
                        pci_eutra: 42,
                        earfcn: 1850,
                        value_rsrp_eutra: 60,
                    }]),
                ],
            }),
        };
        build_ecid_measurement_report(
            NrppaTransactionId(1),
            UeMeasurementId(42),
            UeMeasurementId(7),
            &e_cid,
            None,
        )
        .expect("build NRPPa E-CID report")
        .encode()
        .expect("NrppaPdu::encode")
        .to_vec()
    }

    /// Build an inbound notify `SbiRequest` (jsonData root + one binary part).
    fn notify_request(
        path: &str,
        json: &str,
        content_id: &str,
        content_type: &str,
        part: Vec<u8>,
    ) -> SbiRequest {
        use bytes::Bytes;
        use nextgcore_sbi::message::SbiPart;
        let mut req = SbiRequest::post(path);
        req.http.set_content(json.to_string());
        req.http.add_part(SbiPart::with_content(
            content_id,
            content_type,
            Bytes::from(part),
        ));
        req
    }

    // -- A4 STRICT-PEER: amfd's REAL N1MessageNotify producer body → lmfd's REAL
    // callback handler completes a pending session with a measurement-derived fix.
    #[tokio::test]
    async fn test_n1_message_notify_strict_peer_completes_session_with_fix() {
        use nextgcore_sbi::multipart;
        lmf_context_init(1024);
        let supi = "imsi-001010000000601";
        let ctx = lmf_self();
        let (corr, rx) = {
            let guard = ctx.read().unwrap();
            // Seed the serving cell so the E-CID solver returns a real fix.
            guard.set_cell_coord(
                "pci-42".to_string(),
                crate::positioning::TrpCoord::new(37.5, -122.3, 0.0),
            );
            let req = guard
                .measurement_request(
                    0,
                    PositioningMethod::Ecid,
                    None,
                    None,
                    PositioningQos::BestEffort,
                )
                .expect("measurement request");
            guard.positioning_session_register(Some(supi.to_string()), 177, req.request_id)
        };

        // The UE's uplink LPP E-CID ProvideLocationInformation (txn 177).
        let lpp = build_ecid_lpp(42, 60, 800, 177);

        // amfd's REAL producer body-builder (H1 lib import — not a mock).
        let amf_req = nextgcore_amfd::namf_server::build_n1_message_notify_request(
            "/nlmf-loc/v1/notify/n1",
            Some("sub-1"),
            "LPP",
            Some(&corr),
            Some(supi),
            &lpp,
        )
        .expect("amfd builds N1MessageNotify");

        // Through the shared multipart codec (client encode → server-side decode).
        let boundary = multipart::generate_boundary();
        let wire = multipart::encode(
            amf_req.http.content.as_deref(),
            &amf_req.http.parts,
            &boundary,
        );
        let ct = multipart::content_type_with_boundary(&boundary);
        let decoded = multipart::decode(&ct, &wire).expect("multipart decode");
        assert_eq!(
            decoded.parts[0].data.as_ref(),
            lpp.as_slice(),
            "the LPP PDU must survive the amfd→lmfd relay byte-exact"
        );
        let mut req = SbiRequest::post("/nlmf-loc/v1/notify/n1");
        req.http.set_content(decoded.json.expect("jsonData root"));
        req.http.set_header("Content-Type", ct);
        for p in decoded.parts {
            req.http.add_part(p);
        }

        // lmfd's REAL callback handler consumes it.
        let resp = handle_n1_message_notify(&req).await;
        assert_eq!(
            resp.status, 204,
            "successful N1MessageNotify callback → 204"
        );

        // The pending DetermineLocation session completed with a REAL fix.
        let outcome = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("session completed within budget")
            .expect("completion sender was not dropped");
        match outcome {
            PositioningOutcome::Fix(est) => {
                assert!((37.0..38.0).contains(&est.latitude), "lat={}", est.latitude);
                assert!(
                    (-123.0..-122.0).contains(&est.longitude),
                    "lon={}",
                    est.longitude
                );
            }
            other => panic!("expected a measurement-derived fix, got {other:?}"),
        }
    }

    // -- A4: an unknown lcsCorrelationId / LPP transaction → 404, no ingestion.
    #[tokio::test]
    async fn test_n1_message_notify_unknown_correlation_404() {
        lmf_context_init(1024);
        // txn 249 + a fresh UUID correlation: neither matches any session.
        let lpp = build_ecid_lpp(42, 60, 800, 249);
        let json = format!(
            "{{\"n1MessageContainer\":{{\"n1MessageClass\":\"LPP\",\
             \"n1MessageContent\":{{\"contentId\":\"n1-lpp\"}}}},\
             \"lcsCorrelationId\":\"{}\"}}",
            uuid::Uuid::new_v4()
        );
        let req = notify_request(
            "/nlmf-loc/v1/notify/n1",
            &json,
            "n1-lpp",
            "application/vnd.3gpp.5gnas",
            lpp,
        );
        let resp = handle_n1_message_notify(&req).await;
        assert_eq!(resp.status, 404);
        assert_eq!(
            content_type(&resp).as_deref(),
            Some("application/problem+json")
        );
        let v = body_json(&resp);
        assert_eq!(v["cause"], "LOCATION_SESSION_UNKNOWN");
    }

    // -- A4: jsonData references a contentId with no matching part → 400.
    #[tokio::test]
    async fn test_n1_message_notify_missing_binary_part_400() {
        lmf_context_init(1024);
        let json = "{\"n1MessageContainer\":{\"n1MessageClass\":\"LPP\",\
             \"n1MessageContent\":{\"contentId\":\"n1-lpp\"}},\
             \"lcsCorrelationId\":\"corr-whatever\"}";
        // No binary part attached at all.
        let mut req = SbiRequest::post("/nlmf-loc/v1/notify/n1");
        req.http.set_content(json.to_string());
        let resp = handle_n1_message_notify(&req).await;
        assert_eq!(resp.status, 400);
        let v = body_json(&resp);
        assert_eq!(v["cause"], "MANDATORY_IE_MISSING");
    }

    // -- A4: N2InfoNotify (NRPPa) correlates on lcsCorrelationId and completes
    // the session; the report is attached to the session's request_id.
    #[tokio::test]
    async fn test_n2_info_notify_completes_session() {
        lmf_context_init(1024);
        let supi = "imsi-001010000000602";
        let ctx = lmf_self();
        let (corr, rx, request_id) = {
            let guard = ctx.read().unwrap();
            let req = guard
                .measurement_request(
                    0,
                    PositioningMethod::Ecid,
                    None,
                    None,
                    PositioningQos::BestEffort,
                )
                .expect("measurement request");
            let (corr, rx) =
                guard.positioning_session_register(Some(supi.to_string()), 188, req.request_id);
            (corr, rx, req.request_id)
        };
        let nrppa = build_nrppa_ecid_report();
        let json = format!(
            "{{\"n2NotifySubscriptionId\":\"sub-9\",\
             \"n2InfoContainer\":{{\"n2InformationClass\":\"NRPPa\",\
             \"nrppaInfo\":{{\"nrppaPdu\":{{\"ngapIeType\":\"NRPPA_PDU\",\
             \"ngapData\":{{\"contentId\":\"nrppa\"}}}}}}}},\
             \"lcsCorrelationId\":\"{corr}\"}}"
        );
        let req = notify_request(
            "/nlmf-loc/v1/notify/n2",
            &json,
            "nrppa",
            "application/vnd.3gpp.ngap",
            nrppa,
        );
        let resp = handle_n2_info_notify(&req).await;
        assert_eq!(resp.status, 204, "successful N2InfoNotify callback → 204");

        // The session completed (outcome delivered) and the report was stored.
        let _outcome = tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .expect("session completed within budget")
            .expect("completion sender was not dropped");
        assert!(
            lmf_self().read().unwrap().report_find(request_id).is_some(),
            "the uplink NRPPa report must be attached to the session's request_id"
        );
    }

    // -- A4: N2InfoNotify with an unknown lcsCorrelationId → 404.
    #[tokio::test]
    async fn test_n2_info_notify_unknown_correlation_404() {
        lmf_context_init(1024);
        let nrppa = build_nrppa_ecid_report();
        let json = format!(
            "{{\"n2NotifySubscriptionId\":\"sub-9\",\
             \"n2InfoContainer\":{{\"n2InformationClass\":\"NRPPa\",\
             \"nrppaInfo\":{{\"nrppaPdu\":{{\"ngapIeType\":\"NRPPA_PDU\",\
             \"ngapData\":{{\"contentId\":\"nrppa\"}}}}}}}},\
             \"lcsCorrelationId\":\"{}\"}}",
            uuid::Uuid::new_v4()
        );
        let req = notify_request(
            "/nlmf-loc/v1/notify/n2",
            &json,
            "nrppa",
            "application/vnd.3gpp.ngap",
            nrppa,
        );
        let resp = handle_n2_info_notify(&req).await;
        assert_eq!(resp.status, 404);
        let v = body_json(&resp);
        assert_eq!(v["cause"], "LOCATION_SESSION_UNKNOWN");
    }
}

#[cfg(test)]
mod oauth2_h8_tests {
    //! Wave-6 H8 (Phase B) strict-peer OAuth2 enforcement triplet: the real
    //! `lmf_sbi_request_handler` is mounted behind nextgcore-sbi's server-side
    //! OAuth2 verification (TS 33.501 §13.4.1). A missing or wrong-audience
    //! Bearer is rejected (401) before the handler runs; a valid NRF-audience
    //! token (aud=LMF, ES256-signed against the served JWKS) passes through.
    use nextgcore_sbi::client::SbiClient;
    use nextgcore_sbi::message::SbiRequest;
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    use nextgcore_sbi::types::NfType;
    use std::net::SocketAddr;
    use std::time::Duration;

    /// Reserve a loopback port for a test server.
    ///
    /// Delegates to the shared helper: 21 crates each had a private
    /// probe-and-drop copy of this, which is TOCTOU and flaked under parallel
    /// `cargo test`. One implementation means one place to harden.
    fn free_port() -> u16 {
        nextgcore_sbi::test_support::free_port()
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
            "iss": "NRF", "sub": "lmf-1", "aud": aud,
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
        super::lmf_context_init(256);
        let port = free_port();
        let mut cfg = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(jwks);
        cfg = cfg.with_expected_audience_nf_type(NfType::Lmf);
        let server = SbiServer::new(cfg);
        server
            .start(super::lmf_sbi_request_handler)
            .await
            .expect("server start");
        (server, port)
    }

    #[test]
    fn test_oauth2_require_knob_parses_and_defaults_off() {
        let dir = std::env::temp_dir();
        let off = dir.join(format!("lmf-h8-off-{}.yaml", std::process::id()));
        std::fs::write(
            &off,
            "lmf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n",
        )
        .unwrap();
        assert!(!super::oauth2_required(off.to_str().unwrap()));
        let on = dir.join(format!("lmf-h8-on-{}.yaml", std::process::id()));
        std::fs::write(&on, "lmf:\n  sbi:\n    oauth2:\n      require: true\n").unwrap();
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
            client.get("/nlmf-loc/v1/determine-location"),
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
        let token = build_es256_token(&sk, "nrf-es256", "AMF", "nlmf-loc");
        let req = SbiRequest::get("/nlmf-loc/v1/determine-location")
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
        let token = build_es256_token(&sk, "nrf-es256", "LMF", "nlmf-loc");
        let req = SbiRequest::get("/nlmf-loc/v1/determine-location/does-not-exist")
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

#[cfg(test)]
mod a8_event_notify_tests {
    //! Wave-6 A8: EventNotify producer for deferred/periodic LDR
    //! (TS 29.572 §6.1.5.1; TS 23.273 §6.3). A real in-process H-GMLC sink (an
    //! `SbiServer` bound to a free port whose handler validates each
    //! `EventNotifyDataExt` and returns 204 per the yaml) receives the callbacks.
    //! No lenient mock: the producer's exact bytes are decoded by the real SBI
    //! server stack and asserted field-by-field.
    //!
    //! In these tests no NRF is configured, so each per-tick positioning
    //! procedure fail-closes fast (no serving AMF) → the reports carry NO
    //! fabricated location, exercising the honest "no-fix" event-report path.
    use super::*;
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::{Mutex, OnceLock};

    #[derive(Default)]
    struct SinkState {
        counts: HashMap<String, u32>,
        statuses: HashMap<String, u16>,
        bodies: HashMap<String, Vec<serde_json::Value>>,
        content_types: HashMap<String, Vec<String>>,
    }

    /// Process-global sink registry, keyed by callback PATH (each test uses a
    /// unique path so parallel tests never collide on the shared server handler).
    fn sink() -> &'static Mutex<SinkState> {
        static SINK: OnceLock<Mutex<SinkState>> = OnceLock::new();
        SINK.get_or_init(|| Mutex::new(SinkState::default()))
    }

    /// The H-GMLC sink handler: records every callback (count, parsed body,
    /// Content-Type) and returns the per-path configured status (default 204).
    async fn sink_handler(req: SbiRequest) -> SbiResponse {
        let path = req
            .header
            .uri
            .split('?')
            .next()
            .unwrap_or(&req.header.uri)
            .to_string();
        let ct = req.http.get_header("Content-Type").cloned();
        let body = req
            .http
            .content
            .as_deref()
            .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok());
        let status = {
            let mut s = sink().lock().unwrap();
            *s.counts.entry(path.clone()).or_insert(0) += 1;
            if let Some(c) = ct {
                s.content_types.entry(path.clone()).or_default().push(c);
            }
            if let Some(v) = body {
                s.bodies.entry(path.clone()).or_default().push(v);
            }
            s.statuses.get(&path).copied().unwrap_or(204)
        };
        if status == 204 {
            SbiResponse::no_content()
        } else {
            SbiResponse::with_status(status)
        }
    }

    fn sink_count(path: &str) -> u32 {
        sink()
            .lock()
            .unwrap()
            .counts
            .get(path)
            .copied()
            .unwrap_or(0)
    }
    fn sink_bodies(path: &str) -> Vec<serde_json::Value> {
        sink()
            .lock()
            .unwrap()
            .bodies
            .get(path)
            .cloned()
            .unwrap_or_default()
    }
    fn sink_content_types(path: &str) -> Vec<String> {
        sink()
            .lock()
            .unwrap()
            .content_types
            .get(path)
            .cloned()
            .unwrap_or_default()
    }
    fn sink_set_status(path: &str, status: u16) {
        sink()
            .lock()
            .unwrap()
            .statuses
            .insert(path.to_string(), status);
    }

    fn free_port() -> u16 {
        nextgcore_sbi::test_support::free_port()
    }

    async fn start_sink() -> (SbiServer, u16) {
        let port = free_port();
        let cfg = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
        let server = SbiServer::new(cfg);
        server.start(sink_handler).await.expect("sink server start");
        (server, port)
    }

    /// Poll the sink until `path` has received `target` callbacks or `timeout`
    /// elapses (no fixed sleeps that race the scheduler).
    async fn wait_for_count(path: &str, target: u32, timeout: Duration) -> u32 {
        let start = std::time::Instant::now();
        loop {
            let c = sink_count(path);
            if c >= target || start.elapsed() >= timeout {
                return c;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn periodic_determine_location_body(
        supi: &str,
        ldr_ref: &str,
        hgmlc: &str,
        amount: u32,
        interval_ms: u32,
    ) -> String {
        format!(
            r#"{{"supi":"{supi}","ldrType":"PERIODIC","ldrReference":"{ldr_ref}",
                "hgmlcCallBackURI":"{hgmlc}",
                "periodicEventInfo":{{"reportingAmount":{amount},"reportingInterval":60,"reportingIntervalMs":{interval_ms}}}}}"#
        )
    }

    // -- A8 acceptance: exactly reportingAmount callbacks, then the task stops.
    #[tokio::test]
    async fn test_periodic_ldr_emits_exact_amount_then_stops() {
        lmf_context_init(1024);
        let (server, port) = start_sink().await;
        let path = "/sink/a8-exact/cb";
        let hgmlc = format!("http://127.0.0.1:{port}{path}");
        let body =
            periodic_determine_location_body("imsi-001010000000801", "a8-exact", &hgmlc, 2, 150);
        let req = SbiRequest::post("/nlmf-loc/v1/determine-location")
            .with_body(&body, "application/json");
        // Activation spawns the scheduler (its response is independent of it).
        let _ = handle_determine_location(&req).await;

        let c = wait_for_count(path, 2, Duration::from_secs(4)).await;
        assert_eq!(c, 2, "exactly reportingAmount EventNotify callbacks");
        // A further two intervals: still exactly 2 (the task finished).
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            sink_count(path),
            2,
            "no callbacks after reportingAmount reached"
        );

        // Normal completion cleaned up the LDR session and its trigger task.
        assert!(
            lmf_self().read().unwrap().ldr_find("a8-exact").is_none(),
            "LDR session removed on normal completion"
        );

        // Each callback is a valid EventNotifyDataExt; final carries termination.
        let bodies = sink_bodies(path);
        assert_eq!(bodies.len(), 2);
        for b in &bodies {
            assert_eq!(b["reportedEventType"], "PERIODIC_EVENT");
            assert_eq!(b["ldrReference"], "a8-exact");
            assert_eq!(b["supi"], "imsi-001010000000801");
            // No NRF ⇒ no fix ⇒ honest report WITHOUT a fabricated location.
            assert!(
                b.get("locationEstimate").is_none(),
                "no fabricated location on a no-fix periodic report"
            );
            let _typed: nlmf::EventNotifyDataExt = serde_json::from_value(b.clone()).unwrap();
        }
        assert_eq!(
            bodies[1]["terminationCause"], "NORMAL_TERMINATION",
            "final report carries NORMAL_TERMINATION"
        );
        assert!(
            sink_content_types(path)
                .iter()
                .all(|c| c.to_ascii_lowercase().starts_with("application/json")),
            "EventNotify is POSTed as application/json"
        );
        server.stop().await.expect("stop");
    }

    // -- A8 acceptance: cancel-location mid-stream stops emission.
    #[tokio::test]
    async fn test_periodic_ldr_cancel_stops_emission() {
        lmf_context_init(1024);
        let (server, port) = start_sink().await;
        let path = "/sink/a8-cancel/cb";
        let hgmlc = format!("http://127.0.0.1:{port}{path}");
        let body =
            periodic_determine_location_body("imsi-001010000000802", "a8-cancel", &hgmlc, 20, 150);
        let req = SbiRequest::post("/nlmf-loc/v1/determine-location")
            .with_body(&body, "application/json");
        let _ = handle_determine_location(&req).await;

        // At least one report, then cancel while the session is still running.
        assert!(
            wait_for_count(path, 1, Duration::from_secs(4)).await >= 1,
            "at least one report before cancel"
        );
        let cancel_body = r#"{"hgmlcCallBackURI":"http://gmlc/cb","ldrReference":"a8-cancel"}"#;
        let creq = SbiRequest::post("/nlmf-loc/v1/cancel-location")
            .with_body(cancel_body, "application/json");
        assert_eq!(handle_cancel_location(&creq).await.status, 204);

        // Emission is stable across two further intervals (task aborted).
        tokio::time::sleep(Duration::from_millis(400)).await;
        let a = sink_count(path);
        tokio::time::sleep(Duration::from_millis(400)).await;
        let b = sink_count(path);
        assert_eq!(a, b, "no EventNotify emitted after cancel");
        assert!(b < 20, "cancel stopped the session before reportingAmount");
        assert!(
            lmf_self().read().unwrap().ldr_find("a8-cancel").is_none(),
            "cancel removed the LDR session"
        );
        server.stop().await.expect("stop");
    }

    // -- A8 acceptance: an unreachable/failing H-GMLC is auto-cancelled, not
    // retried forever (one report + one retry, then the session is dropped).
    #[tokio::test]
    async fn test_periodic_ldr_failing_gmlc_auto_cancels() {
        lmf_context_init(1024);
        let (server, port) = start_sink().await;
        let path = "/sink/a8-fail/cb";
        sink_set_status(path, 500); // the GMLC rejects every notification
        let hgmlc = format!("http://127.0.0.1:{port}{path}");
        let body =
            periodic_determine_location_body("imsi-001010000000803", "a8-fail", &hgmlc, 20, 150);
        let req = SbiRequest::post("/nlmf-loc/v1/determine-location")
            .with_body(&body, "application/json");
        let _ = handle_determine_location(&req).await;

        // First report POSTs (500) + one retry (500) → deliver fails → break.
        let c = wait_for_count(path, 2, Duration::from_secs(4)).await;
        assert_eq!(c, 2, "one report + exactly one retry");
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(
            sink_count(path),
            2,
            "no infinite retry after repeated GMLC failure"
        );
        assert!(
            lmf_self().read().unwrap().ldr_find("a8-fail").is_none(),
            "repeated failure auto-cancelled the LDR"
        );
        server.stop().await.expect("stop");
    }

    // -- A8 STRICT-PEER: post_event_notify → the real SBI sink returns 204 and
    // receives a byte-valid EventNotifyDataExt as application/json.
    #[tokio::test]
    async fn test_post_event_notify_strict_peer_204() {
        let (server, port) = start_sink().await;
        let path = "/sink/a8-post/cb";
        let hgmlc = format!("http://127.0.0.1:{port}{path}");
        let notify = build_periodic_event_notify("ref-post", "imsi-001010000000804", None, true);
        let status = post_event_notify(&hgmlc, &notify).await.expect("POST ok");
        assert_eq!(status, 204, "the H-GMLC callback returns 204 (yaml)");
        let bodies = sink_bodies(path);
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0]["reportedEventType"], "PERIODIC_EVENT");
        assert_eq!(bodies[0]["terminationCause"], "NORMAL_TERMINATION");
        let _typed: nlmf::EventNotifyDataExt =
            serde_json::from_value(bodies[0].clone()).expect("valid EventNotifyDataExt");
        server.stop().await.expect("stop");
    }

    // -- A8 unit: the report body (fix vs no-fix, final vs interim). ----------
    #[test]
    fn test_build_periodic_event_notify_fix_vs_nofix() {
        // No fix, not final: only the M IEs + supi; no fabricated location.
        let nf = build_periodic_event_notify("ref-x", "imsi-1", None, false);
        assert_eq!(nf.event_notify_data.reported_event_type, "PERIODIC_EVENT");
        assert_eq!(nf.event_notify_data.ldr_reference, "ref-x");
        assert!(nf.event_notify_data.location_estimate.is_none());
        assert!(nf.event_notify_data.age_of_location_estimate.is_none());
        assert!(nf.event_notify_data.termination_cause.is_none());

        // Fix + final: locationEstimate + honest age 0 + method + termination.
        let fix = LocationEstimate {
            latitude: 37.5,
            longitude: -122.3,
            horizontal_accuracy: 25.0,
            method_used: Some(nlmf::positioning_method::NR_ECID.to_string()),
            ..Default::default()
        };
        let f = build_periodic_event_notify("ref-x", "imsi-1", Some(&fix), true);
        assert!(f.event_notify_data.location_estimate.is_some());
        assert_eq!(f.event_notify_data.age_of_location_estimate, Some(0));
        assert_eq!(
            f.event_notify_data.termination_cause.as_deref(),
            Some("NORMAL_TERMINATION")
        );
        assert_eq!(
            f.event_notify_data.positioning_data_list.as_ref().unwrap()[0].method,
            "NR_ECID"
        );
    }

    // -- A8 unit: InputData.periodicEventInfo → PeriodicReporting + interval. --
    #[test]
    fn test_periodic_reporting_from_input_and_interval() {
        let input: nlmf::InputData = serde_json::from_str(
            r#"{"supi":"imsi-1","periodicEventInfo":{"reportingAmount":5,"reportingInterval":60}}"#,
        )
        .unwrap();
        let p = periodic_reporting_from_input(&input).unwrap();
        assert_eq!(p.reporting_amount, 5);
        assert_eq!(p.reporting_interval_secs, 60);
        // Seconds resolution when no reportingIntervalMs.
        assert_eq!(periodic_report_interval(&p), Duration::from_secs(60));

        // reportingIntervalMs (1..999) takes precedence for a sub-second cadence.
        let p_ms = PeriodicReporting {
            reporting_amount: 1,
            reporting_interval_secs: 60,
            reporting_interval_ms: Some(200),
        };
        assert_eq!(periodic_report_interval(&p_ms), Duration::from_millis(200));

        // No periodicEventInfo → None (no scheduler).
        let none_input: nlmf::InputData = serde_json::from_str(r#"{"supi":"imsi-1"}"#).unwrap();
        assert!(periodic_reporting_from_input(&none_input).is_none());

        // reportingAmount clamped to ≥ 1 so the scheduler makes progress.
        let zero_input: nlmf::InputData = serde_json::from_str(
            r#"{"supi":"imsi-1","periodicEventInfo":{"reportingAmount":0,"reportingInterval":1}}"#,
        )
        .unwrap();
        assert_eq!(
            periodic_reporting_from_input(&zero_input)
                .unwrap()
                .reporting_amount,
            1
        );
    }

    // -- A8 unit: callback-URI splitter (host/port/path + scheme defaults). ---
    #[test]
    fn test_split_callback_uri() {
        assert_eq!(
            split_callback_uri("http://10.0.0.5:8080/gmlc/cb"),
            Some(("10.0.0.5".to_string(), 8080, "/gmlc/cb".to_string()))
        );
        assert_eq!(
            split_callback_uri("https://gmlc.example/cb"),
            Some(("gmlc.example".to_string(), 443, "/cb".to_string()))
        );
        assert_eq!(
            split_callback_uri("http://host:9/"),
            Some(("host".to_string(), 9, "/".to_string()))
        );
        assert_eq!(
            split_callback_uri("http://host"),
            Some(("host".to_string(), 80, "/".to_string()))
        );
        // Unparseable authority / port → None (never a silent misroute).
        assert_eq!(split_callback_uri("http://:80/x"), None);
        assert_eq!(split_callback_uri("http://host:notaport/x"), None);
    }
}

// ===========================================================================
// Wave-6 A9 + H4 — strict-peer full-chain positioning integration.
//
// A9 (WS-A §A9, TS 23.273 §6.11.2 5GC-MT-LR): drive lmfd's REAL DetermineLocation
// handler → its REAL outbound Namf N1N2MessageTransfer POST (A2) → amfd's REAL
// `namf_request_handler` (H1 lib target, in-process over loopback HTTP) → a
// scripted UE/gNB fixture replies with a UPER LPP ProvideLocationInformation via
// amfd's REAL `build_n1_message_notify_request` producer → lmfd's REAL notify
// callback (A4) completes the session → 200 LocationDataExt with a
// measurement-derived fix. No lenient mocks on any leg (only the NRF discovery
// bootstrap is a sink, per the H1 policy: it targets a different peer).
//
// H4 (WS-H §H4, superseded-in-part: A2 owns the POST impl): the lmfd→amfd
// N1N2MessageTransfer strict-peer conversion — lmfd's PRODUCTION request builder
// fed to amfd's REAL consumer, asserting amfd extracts the EXACT LPP PDU bytes
// (transparent relay, TS 29.518 §5.2.2.3 / §6.1.6.2.2).
//
// The peer on every leg is the real other-NF handler/producer; "mechanically
// closed" is impossible (the pcfd/bsfd lenient-mock lesson). The mutation check
// (WS-A §A9 acceptance) holds: revert A2's POST → amfd never receives the
// transfer → the tap never fires → the full-chain test fails.
// ===========================================================================
#[cfg(test)]
mod positioning_chain_strict_peer {
    use super::*;
    use nextgcore_amfd::context::{amf_self, PositioningDlKind, NEXTGCORE_INVALID_POOL_ID};
    use nextgcore_sbi::multipart;
    use nextgcore_sbi::server::SbiServerConfig;
    use std::net::SocketAddr;

    /// Serialize the strict-peer tests among themselves: they share the
    /// process-global AMF context (`amf_self`), the shared SBI NRF URI, and the
    /// global positioning downlink queue (cf. the amfd flaky-test hazard, and
    /// the nf-context-lock discipline). A `tokio::sync::Mutex` so the guard is
    /// held across awaits (real HTTP round-trips).
    fn chain_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    /// Unique RAN-UE-NGAP-ID source so seeded UEs never collide in the shared
    /// (never-reset) global AMF context.
    static NEXT_NGAP_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(88_000);

    fn free_port() -> u16 {
        nextgcore_sbi::test_support::free_port()
    }

    fn body_json(resp: &SbiResponse) -> serde_json::Value {
        serde_json::from_str(resp.http.content.as_deref().unwrap_or("{}")).expect("json body")
    }

    /// Seed a CM-CONNECTED UE (keyed by SUPI) in the real global AMF context via
    /// amfd's PUBLIC context API — so amfd's `try_positioning_relay` accepts the
    /// LPP downlink (needs a live RAN-UE association). Clears any leftover
    /// downlinks first (the queue is process-global and never auto-reset).
    fn seed_amf_connected_ue(supi: &str) {
        nextgcore_amfd::test_support::init_context();
        let ctx = amf_self();
        let g = ctx.read().expect("amf ctx");
        let _ = g.positioning_dl_drain();
        let ngap_id = NEXT_NGAP_ID.fetch_add(1, Ordering::SeqCst);
        let ran_ue = g.ran_ue_add(900_100, ngap_id).expect("ran_ue_add");
        let ue = g.amf_ue_add(ran_ue.id).expect("amf_ue_add");
        g.amf_ue_set_supi(ue.id, supi);
        g.amf_ue_associate_ran_ue(ue.id, ran_ue.id);
    }

    /// Seed a CM-IDLE UE (SUPI known, no RAN association) so the relay
    /// fail-closes with 504 UE_NOT_REACHABLE.
    fn seed_amf_idle_ue(supi: &str) {
        nextgcore_amfd::test_support::init_context();
        let ctx = amf_self();
        let g = ctx.read().expect("amf ctx");
        let _ = g.positioning_dl_drain();
        let ue = g.amf_ue_add(NEXTGCORE_INVALID_POOL_ID).expect("amf_ue_add");
        g.amf_ue_set_supi(ue.id, supi);
    }

    /// Prime lmfd's own identity + notify-callback base so `initiate_positioning`
    /// registers an A3 subscription and stamps `servingLMFIdentification`.
    fn prime_lmf_self() {
        let ctx = lmf_self();
        let g = ctx.read().expect("lmf ctx");
        g.set_callback_base("http://127.0.0.1:7816");
        g.set_nf_instance_id("lmf-strict-peer");
    }

    /// Encode a UE uplink LPP `ProvideLocationInformation` (E-CID) carrying one
    /// measured-results element (physCellId `pci`, rsrp, ue-RxTxTimeDiff). This
    /// is what the scripted UE returns; it decodes to a `CellMeasurement` keyed
    /// `pci-<pci>` (TS 37.355 §6.5 ECID-SignalMeasurementInformation).
    fn build_ecid_lpp(pci: u16, rsrp_result: u8, ue_rx_tx: u16, txn: u8) -> Vec<u8> {
        use nextgcore_asn1c::lpp::ecid::{
            EcidProvideLocationInformation, EcidSignalMeasurementInformation,
            MeasuredResultsElement, ProvideLocationInformation, ProvideLocationInformationR9,
        };
        use nextgcore_asn1c::lpp::message::{LppMessage, LppMessageBody, MessageBodyC1};
        use nextgcore_asn1c::lpp::types::{Initiator, LppTransactionId, TransactionNumber};
        let element = MeasuredResultsElement {
            phys_cell_id: pci,
            arfcn_eutra: 1850,
            system_frame_number: None,
            rsrp_result: Some(rsrp_result),
            rsrq_result: Some(20),
            ue_rx_tx_time_diff: Some(ue_rx_tx),
        };
        let msg = LppMessage {
            transaction_id: Some(LppTransactionId {
                initiator: Initiator::TargetDevice,
                transaction_number: TransactionNumber(txn),
            }),
            end_transaction: true,
            sequence_number: None,
            acknowledgement: None,
            message_body: Some(LppMessageBody::C1(
                MessageBodyC1::ProvideLocationInformation(ProvideLocationInformation {
                    ies: ProvideLocationInformationR9 {
                        ecid: Some(EcidProvideLocationInformation {
                            signal_measurement_information: Some(
                                EcidSignalMeasurementInformation {
                                    primary_cell_measured_results: None,
                                    measured_results_list: vec![element],
                                },
                            ),
                            ecid_error: None,
                        }),
                        nr_multi_rtt: None,
                        nr_dl_tdoa: None,
                    },
                }),
            )),
        };
        msg.encode().expect("encode E-CID lpp").to_vec()
    }

    /// Build the scripted UE's N1MessageNotify request the way amfd's REAL
    /// producer builds it (H1 import), routed through the SAME nextgcore-sbi
    /// multipart codec the wire uses, and re-materialised as the inbound
    /// `SbiRequest` lmfd's server hands its callback handler. Asserts the LPP
    /// PDU survives the amfd→lmfd relay byte-exact (transparent relay).
    fn amfd_notify_request(corr: &str, supi: &str, lpp: &[u8]) -> SbiRequest {
        let amf_req = nextgcore_amfd::namf_server::build_n1_message_notify_request(
            namf_client::N1_NOTIFY_PATH,
            Some("sub-strict-peer"),
            "LPP",
            Some(corr),
            Some(supi),
            lpp,
        )
        .expect("amfd builds N1MessageNotify");
        let boundary = multipart::generate_boundary();
        let wire = multipart::encode(
            amf_req.http.content.as_deref(),
            &amf_req.http.parts,
            &boundary,
        );
        let ct = multipart::content_type_with_boundary(&boundary);
        let decoded = multipart::decode(&ct, &wire).expect("multipart decode");
        assert_eq!(
            decoded.parts[0].data.as_ref(),
            lpp,
            "UL LPP must survive the amfd→lmfd notify relay byte-exact"
        );
        let mut req = SbiRequest::post(namf_client::N1_NOTIFY_PATH);
        req.http.set_content(decoded.json.expect("jsonData root"));
        req.http.set_header("Content-Type", ct);
        for p in decoded.parts {
            req.http.add_part(p);
        }
        req
    }

    /// Start amfd's REAL `namf_request_handler` behind a loopback SbiServer, plus
    /// a minimal NRF discovery sink pointing at it, and set the global NRF URI.
    /// Returns both servers (keep alive) and a receiver that fires with
    /// `(lcsCorrelationId, downlink-LPP-bytes)` the instant amfd accepts the
    /// N1N2MessageTransfer — captured from amfd's OWN recorded state (the
    /// handler runs verbatim; the tap only observes). This is the "scripted
    /// gNB/UE fixture" capture point for the NGAP egress.
    async fn start_positioning_harness(
        supi: String,
    ) -> (
        SbiServer,
        SbiServer,
        tokio::sync::mpsc::Receiver<(String, Vec<u8>)>,
    ) {
        let (tap_tx, tap_rx) = tokio::sync::mpsc::channel::<(String, Vec<u8>)>(4);

        let amf_port = free_port();
        let amf_addr: SocketAddr = format!("127.0.0.1:{amf_port}").parse().expect("amf addr");
        let amf_server = SbiServer::new(SbiServerConfig::new(amf_addr));
        amf_server
            .start(move |req: SbiRequest| {
                let tap_tx = tap_tx.clone();
                let supi = supi.clone();
                async move {
                    let is_transfer = req.header.method == "POST"
                        && req
                            .header
                            .uri
                            .split('?')
                            .next()
                            .unwrap_or("")
                            .ends_with("/n1-n2-messages");
                    // amfd's REAL Namf consumer (H1) — verbatim, no mock.
                    let resp = nextgcore_amfd::namf_request_handler(req).await;
                    if is_transfer && resp.status == 200 {
                        // Observe amfd's real recorded relay state for the fixture.
                        let captured = {
                            let ctx = amf_self();
                            let out = match ctx.read() {
                                Ok(g) => {
                                    let corr =
                                        g.lcs_correlation_find(&supi).map(|r| r.lcs_correlation_id);
                                    let lpp =
                                        g.positioning_dl_drain().into_iter().find_map(|d| match d
                                            .kind
                                        {
                                            PositioningDlKind::LppToUe { lpp_pdu } => Some(lpp_pdu),
                                            _ => None,
                                        });
                                    corr.zip(lpp)
                                }
                                Err(_) => None,
                            };
                            out
                        };
                        if let Some(pair) = captured {
                            let _ = tap_tx.try_send(pair);
                        }
                    }
                    resp
                }
            })
            .await
            .expect("amf server start");

        let nrf_port = free_port();
        let nrf_addr: SocketAddr = format!("127.0.0.1:{nrf_port}").parse().expect("nrf addr");
        let nrf_server = SbiServer::new(SbiServerConfig::new(nrf_addr));
        let search = serde_json::json!({
            "nfInstances": [{
                "nfInstanceId": "amf-strict-peer",
                "nfServices": [{
                    "serviceName": "namf-comm",
                    "scheme": "http",
                    "ipEndPoints": [{ "ipv4Address": "127.0.0.1", "port": amf_port }]
                }]
            }]
        })
        .to_string();
        nrf_server
            .start(move |_req: SbiRequest| {
                let search = search.clone();
                async move { SbiResponse::ok().with_body(search, "application/json") }
            })
            .await
            .expect("nrf sink start");

        global_context()
            .set_nrf_uri(format!("http://127.0.0.1:{nrf_port}"))
            .await;

        (amf_server, nrf_server, tap_rx)
    }

    // =======================================================================
    // A9 — full chain: DetermineLocation → N1N2 → (fixture) → notify → 200.
    // =======================================================================

    /// The wave's CRITICAL falsifier: a conformant MT-LR DetermineLocation
    /// returns a measurement-derived fix, driven end-to-end across BOTH real NFs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_positioning_chain_returns_200_computed_fix_via_real_amfd() {
        let _serial = chain_lock().lock().await;
        let supi = "imsi-001010000000701".to_string();

        lmf_context_init(1024);
        prime_lmf_self();
        // Seed the serving cell so the E-CID solver returns a KNOWN analytic fix.
        {
            let ctx = lmf_self();
            let g = ctx.read().unwrap();
            g.set_cell_coord(
                "pci-77".to_string(),
                crate::positioning::TrpCoord::new(40.1, -74.5, 0.0),
            );
        }
        seed_amf_connected_ue(&supi);

        let (amf_server, nrf_server, mut tap_rx) = start_positioning_harness(supi.clone()).await;

        // Drive lmfd's REAL DetermineLocation handler (no stored fix for this
        // SUPI → the live 5GC-MT-LR procedure). Spawned: it blocks awaiting the
        // session completion the notify leg will deliver.
        let body =
            format!(r#"{{"supi":"{supi}","supportedGADShapes":["POINT_UNCERTAINTY_CIRCLE"]}}"#);
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let det = tokio::spawn(async move { handle_determine_location(&req).await });

        // The fixture receives the DL LPP the instant amfd accepts lmfd's POST.
        let (corr, dl_lpp) = tokio::time::timeout(Duration::from_secs(5), tap_rx.recv())
            .await
            .expect("amfd accepted the N1N2MessageTransfer within budget")
            .expect("harness captured the correlation + downlink LPP");

        // Transparent-relay proof (DL leg): amfd extracted EXACTLY lmfd's encoder
        // output. Decode the relayed PDU for its LPP transactionID, then re-encode
        // lmfd's own builder for that txn and compare byte-for-byte.
        let dl_msg =
            nextgcore_asn1c::lpp::message::LppMessage::decode(&dl_lpp).expect("DL LPP decodes");
        let txn = dl_msg
            .transaction_id
            .as_ref()
            .expect("DL LPP carries a transactionID")
            .transaction_number
            .0;
        assert_eq!(
            dl_lpp,
            codec_glue::build_lpp_ecid_request(txn).expect("re-encode DL LPP"),
            "amfd must relay lmfd's LPP RequestLocationInformation byte-exact"
        );

        // Scripted UE: reply with a valid UPER LPP E-CID ProvideLocationInformation
        // for the seeded serving cell (pci 77), via amfd's REAL notify producer.
        let ul_lpp = build_ecid_lpp(77, 60, 800, txn);
        let notify = amfd_notify_request(&corr, &supi, &ul_lpp);
        let notify_resp = handle_n1_message_notify(&notify).await;
        assert_eq!(notify_resp.status, 204, "N1MessageNotify callback → 204");

        // DetermineLocation now completes with the computed fix — NOT 504.
        let resp = tokio::time::timeout(Duration::from_secs(10), det)
            .await
            .expect("DetermineLocation did not hang")
            .expect("DetermineLocation task did not panic");
        assert_eq!(resp.status, 200, "full chain must yield 200, not 504");

        let v = body_json(&resp);
        let lat = v["locationEstimate"]["point"]["lat"]
            .as_f64()
            .expect("locationEstimate latitude");
        let lon = v["locationEstimate"]["point"]["lon"]
            .as_f64()
            .expect("locationEstimate longitude");
        assert!(
            (40.0..41.0).contains(&lat),
            "fix latitude {lat} must be near the seeded serving cell (40.1)"
        );
        assert!(
            (-75.0..-74.0).contains(&lon),
            "fix longitude {lon} must be near the seeded serving cell (-74.5)"
        );
        // E-CID method + honest freshly-computed age.
        assert_eq!(v["positioningDataList"][0]["method"], "NR_ECID");
        assert_eq!(v["ageOfLocationEstimate"], 0);

        let _ = amf_server.stop().await;
        let _ = nrf_server.stop().await;
    }

    /// Negative leg (WS-A §A9 step 3): amfd accepts the transfer but the UE stays
    /// silent within the response-time budget → 504 UNREACHABLE_USER (fail-closed,
    /// never a fabricated fix). `NO_DELAY` gives a zero budget so the timeout is
    /// deterministic (no real sleep). The lmfd→amfd transfer still executes over
    /// the real harness (proving the A2 leg), then fail-closes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_positioning_chain_silent_ue_times_out_504() {
        let _serial = chain_lock().lock().await;
        let supi = "imsi-001010000000702".to_string();

        lmf_context_init(1024);
        prime_lmf_self();
        seed_amf_connected_ue(&supi);
        let (amf_server, nrf_server, _tap_rx) = start_positioning_harness(supi.clone()).await;

        let body = format!(r#"{{"supi":"{supi}","locationQoS":{{"responseTime":"NO_DELAY"}}}}"#);
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let resp = handle_determine_location(&req).await;
        assert_eq!(resp.status, 504);
        assert_eq!(body_json(&resp)["cause"], "UNREACHABLE_USER");

        let _ = amf_server.stop().await;
        let _ = nrf_server.stop().await;
    }

    /// Negative leg (WS-A §A9 step 3): the UE replies, but with an undecodable
    /// LPP payload → a report is received yet no fix is solvable → 500
    /// POSITIONING_FAILED (TS 29.572 Table 6.1.7.3-1), never a fabricated fix.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_positioning_chain_corrupt_lpp_reply_maps_to_500() {
        let _serial = chain_lock().lock().await;
        let supi = "imsi-001010000000703".to_string();

        lmf_context_init(1024);
        prime_lmf_self();
        seed_amf_connected_ue(&supi);
        let (amf_server, nrf_server, mut tap_rx) = start_positioning_harness(supi.clone()).await;

        let body =
            format!(r#"{{"supi":"{supi}","supportedGADShapes":["POINT_UNCERTAINTY_CIRCLE"]}}"#);
        let req =
            SbiRequest::post("/nlmf-loc/v1/determine-location").with_body(body, "application/json");
        let det = tokio::spawn(async move { handle_determine_location(&req).await });

        let (corr, _dl_lpp) = tokio::time::timeout(Duration::from_secs(5), tap_rx.recv())
            .await
            .expect("amfd accepted the transfer")
            .expect("captured correlation");

        // Scripted UE returns garbage where a UPER LPP ProvideLocationInformation
        // is expected — a KNOWN session, but no decodable measurement.
        let corrupt: Vec<u8> = vec![0xFF, 0x13, 0x37, 0xAB, 0xCD];
        let notify = nextgcore_amfd::namf_server::build_n1_message_notify_request(
            namf_client::N1_NOTIFY_PATH,
            Some("sub-corrupt"),
            "LPP",
            Some(&corr),
            Some(&supi),
            &corrupt,
        )
        .expect("amfd builds N1MessageNotify");
        // Delivered to a matched session (204), but yields no fix.
        assert_eq!(handle_n1_message_notify(&notify).await.status, 204);

        let resp = tokio::time::timeout(Duration::from_secs(10), det)
            .await
            .expect("DetermineLocation did not hang")
            .expect("no panic");
        assert_eq!(resp.status, 500);
        assert_eq!(body_json(&resp)["cause"], "POSITIONING_FAILED");
        assert!(
            body_json(&resp).get("locationEstimate").is_none(),
            "a no-fix response must never carry a fabricated location"
        );

        let _ = amf_server.stop().await;
        let _ = nrf_server.stop().await;
    }

    /// Correlation isolation (WS-A §A9 step 3): a second UE's report must never
    /// satisfy the first UE's pending session. Two sessions with distinct
    /// `lcsCorrelationId`s; a notify correlated to A completes ONLY A — B stays
    /// pending. Driven through lmfd's REAL notify handler + amfd's REAL producer.
    #[tokio::test]
    async fn test_positioning_chain_correlation_isolation() {
        let _serial = chain_lock().lock().await;
        lmf_context_init(1024);
        let supi_a = "imsi-001010000000704";
        let supi_b = "imsi-001010000000705";
        {
            let ctx = lmf_self();
            let g = ctx.read().unwrap();
            g.set_cell_coord(
                "pci-88".to_string(),
                crate::positioning::TrpCoord::new(51.5, -0.12, 0.0),
            );
        }
        let (corr_a, rx_a) = {
            let ctx = lmf_self();
            let g = ctx.read().unwrap();
            let req = g
                .measurement_request(
                    0,
                    PositioningMethod::Ecid,
                    None,
                    None,
                    PositioningQos::BestEffort,
                )
                .expect("measurement A");
            g.positioning_session_register(Some(supi_a.to_string()), 111, req.request_id)
        };
        let (corr_b, rx_b) = {
            let ctx = lmf_self();
            let g = ctx.read().unwrap();
            let req = g
                .measurement_request(
                    0,
                    PositioningMethod::Ecid,
                    None,
                    None,
                    PositioningQos::BestEffort,
                )
                .expect("measurement B");
            g.positioning_session_register(Some(supi_b.to_string()), 112, req.request_id)
        };
        assert_ne!(corr_a, corr_b);

        // A notify correlated to A only.
        let ul = build_ecid_lpp(88, 60, 800, 111);
        let notify = nextgcore_amfd::namf_server::build_n1_message_notify_request(
            namf_client::N1_NOTIFY_PATH,
            Some("sub-iso"),
            "LPP",
            Some(&corr_a),
            Some(supi_a),
            &ul,
        )
        .expect("amfd builds N1MessageNotify");
        assert_eq!(handle_n1_message_notify(&notify).await.status, 204);

        // A completed with a real fix.
        let out_a = tokio::time::timeout(Duration::from_secs(2), rx_a)
            .await
            .expect("session A completes")
            .expect("A sender alive");
        assert!(
            matches!(out_a, PositioningOutcome::Fix(_)),
            "session A must complete with a measurement-derived fix"
        );

        // B is untouched: no value on its channel, session still pending.
        let mut rx_b = rx_b;
        assert!(
            matches!(
                rx_b.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ),
            "session B must not be satisfied by another UE's report"
        );
        assert!(
            lmf_self()
                .read()
                .unwrap()
                .positioning_session_find(&corr_b)
                .is_some(),
            "session B must remain registered (isolated)"
        );
    }

    // =======================================================================
    // H4 — lmfd→amfd N1N2MessageTransfer strict-peer conversion (A2 owns impl).
    // =======================================================================

    /// lmfd's PRODUCTION request builder fed to amfd's REAL consumer in-process
    /// (H1): amfd accepts the multipart transfer, resolves the contentId, and
    /// extracts the LPP PDU byte-exact — proving the transparent relay and
    /// killing the "prepared and logged" (log-only) non-delivery.
    #[tokio::test]
    async fn test_h4_lmfd_transfer_strict_peer_amfd_extracts_exact_lpp() {
        let _serial = chain_lock().lock().await;
        let supi = "imsi-001010000000731";
        seed_amf_connected_ue(supi);

        let lpp = codec_glue::build_lpp_ecid_request(41).expect("LPP encode");
        let corr = uuid::Uuid::new_v4().to_string();
        // The exact SbiRequest lmfd's A2 leg POSTs on the wire.
        let req = namf_client::build_n1n2_transfer_request(supi, &corr, "lmf-h4", lpp.clone());

        // amfd's REAL consumer (crate-root re-export, H1) — no lenient mock.
        let resp = nextgcore_amfd::handle_n1_n2_message_transfer_request(supi, &req);
        assert_eq!(resp.status, 200);
        assert_eq!(body_json(&resp)["cause"], "N1_N2_TRANSFER_INITIATED");

        // Transparent-relay: amfd enqueued the EXACT LPP bytes lmfd encoded.
        let extracted = {
            let ctx = amf_self();
            let g = ctx.read().unwrap();
            g.positioning_dl_drain()
                .into_iter()
                .find_map(|d| match d.kind {
                    PositioningDlKind::LppToUe { lpp_pdu } => Some(lpp_pdu),
                    _ => None,
                })
        }
        .expect("amfd enqueued an LPP downlink");
        assert_eq!(extracted, lpp, "amfd must relay lmfd's LPP byte-exact");

        // amfd recorded the LCS correlation lmfd minted (uplink route back).
        let rec = amf_self()
            .read()
            .unwrap()
            .lcs_correlation_find(supi)
            .expect("lcsCorrelation recorded on the UE context");
        assert_eq!(rec.lcs_correlation_id, corr);
    }

    /// Negative (WS-H §H4): a CM-IDLE UE gets 504 UE_NOT_REACHABLE from amfd's
    /// real handler (TS 29.518 Table 6.1.7.3-1) — not a fake 200.
    #[tokio::test]
    async fn test_h4_lmfd_transfer_idle_ue_504_ue_not_reachable() {
        let _serial = chain_lock().lock().await;
        let supi = "imsi-001010000000732";
        seed_amf_idle_ue(supi);

        let lpp = codec_glue::build_lpp_ecid_request(42).expect("LPP encode");
        let req = namf_client::build_n1n2_transfer_request(supi, "corr-idle", "lmf-h4", lpp);
        let resp = nextgcore_amfd::handle_n1_n2_message_transfer_request(supi, &req);
        assert_eq!(resp.status, 504);
        // N1N2MessageTransferError envelope: {"error": {ProblemDetails}}.
        assert_eq!(body_json(&resp)["error"]["cause"], "UE_NOT_REACHABLE");
    }

    /// Negative (WS-H §H4): an unknown ueContextId → 404 CONTEXT_NOT_FOUND from
    /// amfd's real handler (the transfer can never land for an absent UE).
    #[tokio::test]
    async fn test_h4_lmfd_transfer_unknown_ue_404() {
        let _serial = chain_lock().lock().await;
        nextgcore_amfd::test_support::init_context();
        let supi = "imsi-001019999999999"; // never seeded
        let lpp = codec_glue::build_lpp_ecid_request(43).expect("LPP encode");
        let req = namf_client::build_n1n2_transfer_request(supi, "corr-unknown", "lmf-h4", lpp);
        let resp = nextgcore_amfd::handle_n1_n2_message_transfer_request(supi, &req);
        assert_eq!(resp.status, 404);
        assert_eq!(body_json(&resp)["cause"], "CONTEXT_NOT_FOUND");
    }
}
