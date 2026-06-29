//! NextGCore LMF (Location Management Function)
//!
//! The LMF is a 5G core NF responsible for (TS 23.273):
//! - UE positioning via NLs interface (AMF <-> LMF)
//! - NRPPa protocol for positioning information exchange (gNB <-> LMF)
//! - Positioning methods: ECID, OTDOA, NR-based (DL-TDOA, UL-TDOA, Multi-RTT), GNSS
//! - Measurement request/report procedures

use anyhow::{Context, Result};
use clap::Parser;
use ogs_sbi::context::global_context;
use ogs_sbi::message::{ProblemDetails, SbiRequest, SbiResponse};
use ogs_sbi::server::{
    send_bad_request, send_method_not_allowed, send_not_found, SbiServer,
    SbiServerConfig as OgsSbiServerConfig,
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
    let _otel = ogs_metrics::otel::init_otel(
        ogs_metrics::otel::OtelConfig::new(env!("CARGO_PKG_NAME")).with_endpoint(
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://jaeger:4317".to_string()),
        ),
    )
    .ok();

    log::info!("NextGCore LMF v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Location Management Function (3GPP TS 23.273)");

    lmf_context_init(args.max_measurements);

    let nf_instance_id = format!("lmf-{}", uuid::Uuid::new_v4());

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
        ogs_sbi::heartbeat::spawn_heartbeat_worker(nf_instance_id.clone(), 5);
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

/// Positioning failure modes mapped to TS 29.572 Determine-Location response
/// codes (Table 6.1.4.2.2-3).
enum PositioningError {
    /// Positioning did not complete within the response-time budget -> 504.
    Timeout,
    /// No usable positioning method available -> 403.
    Unsupported,
}

/// Result of the **SIMULATED** position estimator.
struct SimEstimate {
    lat: f64,
    lon: f64,
    /// Horizontal uncertainty (metres).
    uncertainty_m: f64,
    /// Confidence (0..100 %).
    confidence: u8,
}

/// Run the **SIMULATED** positioning estimator.
///
/// PLACEHOLDER until lmfd-LIB-01/02 (NRPPa per TS 38.455 / LPP per TS 37.355
/// ASN.1 codecs), lmfd-AMF-01 (AMF NRPPa/LPP relay) and lmfd-07/08 (Namf
/// consumer + real multilateration) land. This performs NO real positioning:
/// it returns a deterministic, clearly-fake estimate so the SBI surface
/// (status codes, GAD encoding, ProblemDetails) can be exercised conformantly.
/// DO NOT treat the returned coordinates as a genuine UE location.
fn simulated_positioning(input: &nlmf::InputData) -> Result<SimEstimate, PositioningError> {
    // A zero response-time budget cannot complete positioning -> 504.
    if input.max_resp_time == Some(0) {
        return Err(PositioningError::Timeout);
    }
    // Honest simulation: a fixed reference origin plus a small deterministic
    // offset derived from the request identity, so distinct UEs map to
    // distinct (but reproducible, NON-REAL) points.
    const SIM_ORIGIN_LAT: f64 = 37.7749; // simulator origin — NOT a real fix
    const SIM_ORIGIN_LON: f64 = -122.4194;
    let seed = identity_seed(input);
    if seed == 0 && input.supi.is_none() && input.pei.is_none() && input.gpsi.is_none() {
        // No UE identity at all and no cell hint: cannot position the target.
        return Err(PositioningError::Unsupported);
    }
    let d_lat = f64::from((seed % 1000) as u32) / 1_000_000.0;
    let d_lon = f64::from((seed / 1000 % 1000) as u32) / 1_000_000.0;
    let uncertainty_m = input
        .location_qos
        .as_ref()
        .and_then(|q| q.h_accuracy)
        .filter(|a| *a > 0.0)
        .unwrap_or(50.0);
    Ok(SimEstimate {
        lat: SIM_ORIGIN_LAT + d_lat,
        lon: SIM_ORIGIN_LON + d_lon,
        uncertainty_m,
        confidence: 95,
    })
}

/// Deterministic non-cryptographic seed derived from the request identity
/// (SUPI/PEI/GPSI/correlationID). Used only by the SIMULATED estimator.
fn identity_seed(input: &nlmf::InputData) -> u64 {
    let mut seed: u64 = 0;
    for s in [
        input.supi.as_deref(),
        input.pei.as_deref(),
        input.gpsi.as_deref(),
        input.correlation_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        for b in s.bytes() {
            seed = seed.wrapping_mul(31).wrapping_add(u64::from(b));
        }
    }
    seed
}

/// Handle Determine Location (Nlmf_Location, AMF -> LMF; TS 29.572 §6.1.4.2).
///
/// Returns **200 OK** with a `LocationDataExt` (GAD `locationEstimate`,
/// `positioningDataList`, `ageOfLocationEstimate`, `accuracyFulfilmentIndicator`)
/// per Table 6.1.4.2.2-2 — NOT the old non-conformant `201 PENDING` (lmfd-02).
/// 4xx/5xx ProblemDetails on failure (lmfd-10).
///
/// The position itself comes from the SIMULATED estimator
/// ([`simulated_positioning`]) — a clearly-marked PLACEHOLDER until the
/// lmfd-LIB-01/02 NRPPa/LPP codecs + lmfd-AMF-01 AMF relay land.
async fn handle_determine_location(request: &SbiRequest) -> SbiResponse {
    log::info!("Determine Location");

    let body = match &request.http.content {
        Some(c) => c,
        None => return problem(400, nlmf::cause::MANDATORY_IE_MISSING, "Missing request body"),
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

    // SIMULATED positioning (placeholder — see simulated_positioning docs).
    let est = match simulated_positioning(&input) {
        Ok(e) => e,
        Err(PositioningError::Timeout) => {
            return problem(
                504,
                nlmf::cause::POSITIONING_METHOD_FAILURE,
                "Positioning did not complete within the response-time budget",
            )
        }
        Err(PositioningError::Unsupported) => {
            return problem(
                403,
                nlmf::cause::UNREACHABLE_USER,
                "No usable positioning method for the target UE",
            )
        }
    };

    // lmfd-04: negotiate a GAD shape against supportedGADShapes and GAD-encode
    // the estimate into a GeographicArea (replacing the flat lat/lon/accuracy).
    let want_ellipse = input
        .location_qos
        .as_ref()
        .and_then(|q| q.vertical_requested)
        .unwrap_or(false);
    let shape = nlmf::negotiate_gad_shape(input.supported_gad_shapes.as_deref(), want_ellipse);
    let location_estimate = nlmf::to_gad(est.lat, est.lon, est.uncertainty_m, est.confidence, shape);

    // Accuracy fulfilment vs the requested horizontal accuracy.
    let accuracy_fulfilment_indicator = match input.location_qos.as_ref().and_then(|q| q.h_accuracy)
    {
        Some(req_acc) if est.uncertainty_m > req_acc => {
            nlmf::accuracy_fulfilment::NOT_FULFILLED
        }
        _ => nlmf::accuracy_fulfilment::FULFILLED,
    };

    let response = nlmf::LocationDataExt {
        location_data: nlmf::LocationData {
            location_estimate,
            accuracy_fulfilment_indicator: Some(accuracy_fulfilment_indicator.to_string()),
            age_of_location_estimate: Some(0),
            // SIMULATED: ECID, conventional mode. Real method/usage will come
            // from the NRPPa/LPP measurement procedures (lmfd-05/06).
            positioning_data_list: Some(vec![nlmf::PositioningMethodAndUsage {
                method: nlmf::positioning_method::ECID.to_string(),
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

/// Handle a (bespoke/debug) measurement request — NOT a TS 29.572 resource.
///
/// Retained behind the `nlmf-loc/v1/measurements` debug route until lmfd-11.
/// lmfd-12: the positioning method is parsed against the spec
/// `PositioningMethod` enum and an unknown value is rejected with 400
/// ProblemDetails instead of silently defaulting to ECID.
async fn handle_measurement_request(request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(c) => c,
        None => return problem(400, nlmf::cause::MANDATORY_IE_MISSING, "Missing request body"),
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

            let mut self_instance =
                ogs_sbi::context::NfInstance::new(nf_instance_id, ogs_sbi::types::NfType::Lmf);
            self_instance.ipv4_addresses = vec![sbi_addr.to_string()];
            let mut svc = ogs_sbi::context::NfService::new(
                "nlmf-loc",
                ogs_sbi::types::SbiServiceType::NlmfLoc,
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
        assert_eq!(parse_nr_method("DL_TDOA"), Some(NrPositioningMethod::DlTdoa));
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

    // -- lmfd-01: apiName routing (nlmf-loc dispatches; nlmf-location 404) ---
    #[tokio::test]
    async fn test_router_nlmf_loc_dispatches() {
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
        let body = r#"{
            "supi": "imsi-001010000000001",
            "locationQoS": { "hAccuracy": 100.0 },
            "supportedGADShapes": ["POINT_UNCERTAINTY_CIRCLE"]
        }"#;
        let req = SbiRequest::post("/nlmf-loc/v1/determine-location")
            .with_body(body, "application/json");
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
        let body = r#"{
            "supi": "imsi-001010000000002",
            "locationQoS": { "verticalRequested": true },
            "supportedGADShapes": ["POINT_UNCERTAINTY_ELLIPSE", "POINT_UNCERTAINTY_CIRCLE"]
        }"#;
        let req = SbiRequest::post("/nlmf-loc/v1/determine-location")
            .with_body(body, "application/json");
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
        let req = SbiRequest::post("/nlmf-loc/v1/determine-location")
            .with_body(body, "application/json");
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

    // -- lmfd-02 + lmfd-10: zero response budget -> 504 ProblemDetails -------
    #[tokio::test]
    async fn test_determine_location_timeout_504() {
        let body = r#"{ "supi": "imsi-001010000000003", "maxRespTime": 0 }"#;
        let req = SbiRequest::post("/nlmf-loc/v1/determine-location")
            .with_body(body, "application/json");
        let resp = handle_determine_location(&req).await;
        assert_eq!(resp.status, 504);
        assert_eq!(
            content_type(&resp).as_deref(),
            Some("application/problem+json")
        );
        let v = body_json(&resp);
        assert_eq!(v["cause"], "POSITIONING_METHOD_FAILURE");
    }

    // -- lmfd-12: unknown positioning method on the debug route -> 400 -------
    #[tokio::test]
    async fn test_measurement_request_unknown_method_400() {
        lmf_context_init(1024);
        let body = r#"{ "amfUeNgapId": 1, "positioningMethod": "BOGUS" }"#;
        let req = SbiRequest::post("/nlmf-loc/v1/measurements")
            .with_body(body, "application/json");
        let resp = handle_measurement_request(&req).await;
        assert_eq!(resp.status, 400);
        let v = body_json(&resp);
        assert_eq!(v["cause"], "MANDATORY_IE_INCORRECT");
    }
}
