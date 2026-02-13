//! NextGCore LMF (Location Management Function)
//!
//! The LMF is a 5G core NF responsible for (TS 23.273):
//! - UE positioning via NLs interface (AMF <-> LMF)
//! - NRPPa protocol for positioning information exchange (gNB <-> LMF)
//! - Positioning methods: ECID, OTDOA, NR-based (DL-TDOA, UL-TDOA, Multi-RTT), GNSS
//! - Measurement request/report procedures

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
    .expect("Failed to set signal handler");
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_logging(&args.log_level);

    log::info!("NextGCore LMF v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Location Management Function (3GPP TS 23.273)");

    lmf_context_init(args.max_measurements);

    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone());

    let addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;

    let mut sbi_server_config = OgsSbiServerConfig::new(addr);
    if args.tls {
        let cert = args.tls_cert.as_deref().unwrap_or("/etc/nextgcore/tls/server.crt");
        let key = args.tls_key.as_deref().unwrap_or("/etc/nextgcore/tls/server.key");
        sbi_server_config = sbi_server_config.with_tls(key, cert);
    }

    let sbi_server = SbiServer::new(sbi_server_config);
    log::info!("Starting LMF SBI server on {addr}");
    sbi_server.start(lmf_sbi_request_handler).await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    log::info!("NextGCore LMF ready");

    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    log::info!("Shutting down...");
    sbi_server.stop().await
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

    match parts.as_slice() {
        // NLs Location Determination (Nlmf_Location)
        ["nlmf-location", "v1", "determine-location"] => {
            match method {
                "POST" => handle_determine_location(&request).await,
                _ => send_method_not_allowed(method, "determine-location"),
            }
        }
        // Measurement requests/reports
        ["nlmf-location", "v1", "measurements"] => {
            match method {
                "POST" => handle_measurement_request(&request).await,
                _ => send_method_not_allowed(method, "measurements"),
            }
        }
        ["nlmf-location", "v1", "measurements", request_id] => {
            match method {
                "GET" => handle_measurement_get(request_id).await,
                _ => send_method_not_allowed(method, "measurements/{id}"),
            }
        }
        // NRPPa measurement reports (from gNB via AMF)
        ["nlmf-location", "v1", "nrppa-reports"] => {
            match method {
                "POST" => handle_nrppa_report(&request).await,
                _ => send_method_not_allowed(method, "nrppa-reports"),
            }
        }
        // UE location queries
        ["nlmf-location", "v1", "ue-locations", supi] => {
            match method {
                "GET" => handle_ue_location_get(supi).await,
                "PUT" => handle_ue_location_update(supi, &request).await,
                _ => send_method_not_allowed(method, "ue-locations/{supi}"),
            }
        }
        // Capabilities
        ["nlmf-location", "v1", "capabilities"] => {
            match method {
                "GET" => handle_capabilities().await,
                _ => send_method_not_allowed(method, "capabilities"),
            }
        }
        _ => send_not_found(&format!("Resource not found: {path}"), None),
    }
}

/// Handle location determination request (NLs: AMF -> LMF, TS 23.273 6.2)
async fn handle_determine_location(request: &SbiRequest) -> SbiResponse {
    log::info!("Determine Location");

    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let amf_ue_ngap_id = data.get("amfUeNgapId").and_then(|v| v.as_u64()).unwrap_or(0);
    let method_str = data.get("positioningMethod").and_then(|v| v.as_str()).unwrap_or("ECID");
    let method = parse_positioning_method(method_str);
    let nr_method = data.get("nrMethod").and_then(|v| v.as_str()).and_then(parse_nr_method);
    let gnb_id = data.get("gnbId").and_then(|v| v.as_str()).map(|s| s.to_string());
    let qos_str = data.get("qosClass").and_then(|v| v.as_str()).unwrap_or("BEST_EFFORT");
    let qos = parse_qos(qos_str);

    let ctx = lmf_self();
    let result = if let Ok(context) = ctx.read() {
        context.measurement_request(amf_ue_ngap_id, method, nr_method, gnb_id, qos)
    } else {
        None
    };

    match result {
        Some(req) => {
            SbiResponse::with_status(201)
                .with_json_body(&serde_json::json!({
                    "requestId": req.request_id,
                    "amfUeNgapId": amf_ue_ngap_id,
                    "positioningMethod": method_str,
                    "state": "PENDING",
                    "qosClass": qos_str,
                }))
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        None => send_bad_request("Failed to create measurement request", Some("REQUEST_FAILED")),
    }
}

/// Handle measurement request (same as determine-location for direct API)
async fn handle_measurement_request(request: &SbiRequest) -> SbiResponse {
    handle_determine_location(request).await
}

/// Handle measurement get
async fn handle_measurement_get(request_id: &str) -> SbiResponse {
    let req_id = match request_id.parse::<u64>() {
        Ok(id) => id,
        Err(_) => return send_bad_request("Invalid request ID", Some("INVALID_ID")),
    };

    let ctx = lmf_self();
    let (measurement, report) = if let Ok(context) = ctx.read() {
        (context.measurement_find(req_id), context.report_find(req_id))
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
    let cells: Vec<CellMeasurement> = data.get("cellMeasurements")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(|c| {
            CellMeasurement {
                nr_cgi: c.get("nrCgi").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                rsrp: c.get("rsrp").and_then(|v| v.as_i64()).map(|n| n as i16),
                rsrq: c.get("rsrq").and_then(|v| v.as_i64()).map(|n| n as i16),
                timing_advance: c.get("timingAdvance").and_then(|v| v.as_u64()).map(|n| n as u32),
                aoa: c.get("aoa").and_then(|v| v.as_f64()),
                rtt_ns: c.get("rttNs").and_then(|v| v.as_u64()),
            }
        }).collect())
        .unwrap_or_default();

    let ctx = lmf_self();
    let location = if let Ok(context) = ctx.read() {
        context.measurement_report(request_id, cells)
    } else {
        None
    };

    match location {
        Some(loc) => {
            SbiResponse::with_status(200)
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
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
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
        longitude: data.get("longitude").and_then(|v| v.as_f64()).unwrap_or(0.0),
        altitude: data.get("altitude").and_then(|v| v.as_f64()),
        horizontal_accuracy: data.get("horizontalAccuracy").and_then(|v| v.as_f64()).unwrap_or(100.0),
        vertical_accuracy: data.get("verticalAccuracy").and_then(|v| v.as_f64()),
        method_used: data.get("methodUsed").and_then(|v| v.as_str()).map(|s| s.to_string()),
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
        context.supported_methods().iter().map(|m| format!("{m:?}")).collect()
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

fn parse_positioning_method(s: &str) -> PositioningMethod {
    match s {
        "ECID" => PositioningMethod::Ecid,
        "OTDOA" => PositioningMethod::Otdoa,
        "NR_BASED" | "NR" => PositioningMethod::NrBased,
        "GNSS" => PositioningMethod::Gnss,
        "WLAN" => PositioningMethod::Wlan,
        "BLUETOOTH" | "BLE" => PositioningMethod::Bluetooth,
        "SENSOR" => PositioningMethod::Sensor,
        _ => PositioningMethod::Ecid,
    }
}

fn parse_nr_method(s: &str) -> Option<NrPositioningMethod> {
    match s {
        "DL_TDOA" => Some(NrPositioningMethod::DlTdoa),
        "UL_TDOA" => Some(NrPositioningMethod::UlTdoa),
        "DL_AOD" => Some(NrPositioningMethod::DlAoD),
        "UL_AOA" => Some(NrPositioningMethod::UlAoA),
        "MULTI_RTT" => Some(NrPositioningMethod::MultiRtt),
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

    #[test]
    fn test_parse_positioning_method() {
        assert_eq!(parse_positioning_method("ECID"), PositioningMethod::Ecid);
        assert_eq!(parse_positioning_method("NR_BASED"), PositioningMethod::NrBased);
        assert_eq!(parse_positioning_method("GNSS"), PositioningMethod::Gnss);
        assert_eq!(parse_positioning_method("unknown"), PositioningMethod::Ecid);
    }

    #[test]
    fn test_parse_nr_method() {
        assert_eq!(parse_nr_method("MULTI_RTT"), Some(NrPositioningMethod::MultiRtt));
        assert_eq!(parse_nr_method("DL_TDOA"), Some(NrPositioningMethod::DlTdoa));
        assert_eq!(parse_nr_method("unknown"), None);
    }

    #[test]
    fn test_parse_qos() {
        assert_eq!(parse_qos("EMERGENCY"), PositioningQos::Emergency);
        assert_eq!(parse_qos("HIGH_ACCURACY"), PositioningQos::HighAccuracy);
        assert_eq!(parse_qos("whatever"), PositioningQos::BestEffort);
    }
}
