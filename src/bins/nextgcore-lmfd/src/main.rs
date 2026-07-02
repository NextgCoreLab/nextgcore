//! NextGCore LMF (Location Management Function)
//!
//! The LMF is a 5G core NF responsible for (TS 23.273):
//! - UE positioning via NLs interface (AMF <-> LMF)
//! - NRPPa protocol for positioning information exchange (gNB <-> LMF)
//! - Positioning methods: ECID, OTDOA, NR-based (DL-TDOA, UL-TDOA, Multi-RTT), GNSS
//! - Measurement request/report procedures

use anyhow::{Context, Result};
use clap::Parser;
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
        nextgcore_sbi::heartbeat::spawn_heartbeat_worker(nf_instance_id.clone(), 5);
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
        // NOTE (lmfd-11, DEFERRED): the resources below are bespoke/debug routes
        // that are NOT in TS 29.572. They are retained (now under the correct
        // `nlmf-loc` apiName) until the NRPPa/LPP/Namf flow (lmfd-05/06/07)
        // replaces their function; lmfd-11 then removes them.
        ["nlmf-loc", "v1", "measurements"] => match method {
            "POST" => handle_measurement_request(&request).await,
            _ => send_method_not_allowed(method, "measurements"),
        },
        ["nlmf-loc", "v1", "measurements", request_id] => match method {
            "GET" => handle_measurement_get(request_id).await,
            _ => send_method_not_allowed(method, "measurements/{id}"),
        },
        // NRPPa measurement reports (from gNB via AMF)
        ["nlmf-loc", "v1", "nrppa-reports"] => match method {
            "POST" => handle_nrppa_report(&request).await,
            _ => send_method_not_allowed(method, "nrppa-reports"),
        },
        // lmfd-05: raw NRPPa APER binary report (Content-Type: application/octet-stream).
        // The body is a complete APER-encoded NrppaPdu; the LMF request-id is
        // extracted from the embedded lmf-UE-Measurement-ID IE (TS 38.455 §9.2.13).
        ["nlmf-loc", "v1", "nrppa-binary-reports"] => match method {
            "POST" => handle_nrppa_binary_report(&request).await,
            _ => send_method_not_allowed(method, "nrppa-binary-reports"),
        },
        // lmfd-06: raw LPP UPER binary report (Content-Type: application/octet-stream).
        // The body is a complete UPER-encoded LppMessage carrying
        // ProvideLocationInformation → nr-Multi-RTT.
        ["nlmf-loc", "v1", "lpp-binary-reports"] => match method {
            "POST" => handle_lpp_binary_report(&request).await,
            _ => send_method_not_allowed(method, "lpp-binary-reports"),
        },
        // UE location queries
        ["nlmf-loc", "v1", "ue-locations", supi] => match method {
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
        // EventNotify/UPNotify (§6.1.5) are LMF-initiated outbound POSTs —
        // deferred (E2E-gated: need a live GMLC/AF endpoint + trigger scheduler).
        // TODO lmfd: implement EventNotify producer (TS 29.572 §6.1.5.1) once
        // a trigger scheduler and outbound SBI client are available.
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
) -> Result<
    (
        String,
        tokio::sync::oneshot::Receiver<PositioningOutcome>,
    ),
    Box<SbiResponse>,
> {
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

    // lmfd#1: deferred/periodic/triggered LDR (ldrType present) -> register a
    // reporting context keyed by ldrReference so it can be cancelled
    // (cancel-location, §6.1.4.3) and later reported (EventNotify, §6.1.5).
    // Activation still returns the 200 LocationDataExt below. EventNotify
    // emission on trigger is E2E-gated (TODO lmfd: needs outbound GMLC callback,
    // TS 29.572 §6.1.5.1).
    if let (Some(ldr_type), Some(ldr_ref)) =
        (input.ldr_type.as_deref(), input.ldr_reference.as_deref())
    {
        if let Ok(c) = lmf_self().read() {
            c.register_ldr(LdrContext {
                ldr_reference: ldr_ref.to_string(),
                ldr_type: ldr_type.to_string(),
                hgmlc_callback_uri: input.hgmlc_call_back_uri.clone(),
                supi: input.supi.clone(),
            });
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
}
