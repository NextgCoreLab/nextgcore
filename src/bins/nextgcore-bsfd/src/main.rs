//! NextGCore BSF (Binding Support Function)
//!
//! The BSF is a 5G core network function responsible for:
//! - Managing PCF (Policy Control Function) bindings
//! - Providing binding information to PCF and AF
//! - Supporting session binding based on IP addresses

use anyhow::{Context, Result};
use clap::Parser;
use ogs_sbi::message::{SbiRequest, SbiResponse};
use ogs_sbi::server::{
    send_bad_request, send_method_not_allowed, send_not_found, SbiServer,
    SbiServerConfig as OgsSbiServerConfig,
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod bsf_sm;
mod context;
mod event;
mod nbsf_handler;
mod nnrf_handler;
mod sbi_path;
mod sbi_response;
mod timer;

pub use bsf_sm::{BsfSmContext, BsfState};
pub use context::*;
pub use event::{
    BsfEvent, BsfEventId, BsfTimerId, EventSbiRequest, EventSbiResponse, SbiEventData, SbiMessage,
};
pub use nbsf_handler::*;
pub use nnrf_handler::*;
pub use sbi_path::*;
pub use timer::{timer_manager, BsfTimerManager};

/// NextGCore BSF - Binding Support Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-bsfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Binding Support Function", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/bsf.yaml")]
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

    /// Kill running instance
    #[arg(short = 'k', long)]
    kill: bool,

    /// SBI server address
    #[arg(long, default_value = "0.0.0.0")]
    sbi_addr: String,

    /// SBI server port
    #[arg(long, default_value = "7777")]
    sbi_port: u16,

    /// Enable TLS
    #[arg(long)]
    tls: bool,

    /// TLS certificate path
    #[arg(long)]
    tls_cert: Option<String>,

    /// TLS key path
    #[arg(long)]
    tls_key: Option<String>,

    /// NRF URI (e.g., http://127.0.0.10:7777)
    #[arg(long)]
    nrf_uri: Option<String>,

    /// Maximum number of sessions
    #[arg(long, default_value = "1024")]
    max_sess: usize,
}

// ---------------------------------------------------------------------------
// Typed YAML configuration structs for NRF URI seeding
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct NrfClientYaml {
    uri: String,
}

#[derive(Debug, Default, Deserialize)]
struct SbiClientYaml {
    nrf: Option<Vec<NrfClientYaml>>,
}

#[derive(Debug, Default, Deserialize)]
struct SbiYaml {
    client: Option<SbiClientYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct BsfSection {
    sbi: Option<SbiYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct BsfYaml {
    bsf: Option<BsfSection>,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    init_logging(&args)?;
    // G32/G43: Initialize OpenTelemetry tracing (Jaeger/OTLP exporter)
    let _otel = ogs_metrics::otel::init_otel(
        ogs_metrics::otel::OtelConfig::new(env!("CARGO_PKG_NAME")).with_endpoint(
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| "http://jaeger:4317".to_string()),
        ),
    )
    .ok();

    log::info!("NextGCore BSF v{} starting...", env!("CARGO_PKG_VERSION"));

    // Handle kill flag
    if args.kill {
        log::info!("Kill flag set - would send SIGTERM to running instance");
        return Ok(());
    }

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone())?;

    // Initialize BSF context
    bsf_context_init(args.max_sess);
    log::info!("BSF context initialized (max_sess={})", args.max_sess);

    // Load persisted bindings from database (if available) without blocking
    // the async runtime (W4.2: sync -> async Mongo).
    context::load_persisted_bindings_async().await;

    // Initialize BSF state machine
    let mut bsf_sm = BsfSmContext::new();
    bsf_sm.init();
    log::info!("BSF state machine initialized");

    // Parse configuration (if file exists) and seed NRF URI
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
        match std::fs::read_to_string(&args.config) {
            Ok(content) => {
                log::debug!("Configuration file loaded ({} bytes)", content.len());
                // Seed NRF URI into SBI context for NF registration
                if let Ok(yaml) = serde_yaml::from_str::<BsfYaml>(&content) {
                    if let Some(bsf) = yaml.bsf {
                        if let Some(sbi) = bsf.sbi {
                            if let Some(client) = sbi.client {
                                if let Some(nrf_list) = client.nrf {
                                    if let Some(nrf) = nrf_list.first() {
                                        log::info!("NRF URI configured: {}", nrf.uri);
                                        ogs_sbi::context::global_context()
                                            .set_nrf_uri(&nrf.uri)
                                            .await;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to read configuration file: {e}");
            }
        }
    } else {
        log::debug!("Configuration file not found: {}", args.config);
    }

    // Build SBI server configuration (legacy, for context)
    let sbi_config = SbiServerConfig {
        addr: args.sbi_addr.clone(),
        port: args.sbi_port,
        tls_enabled: args.tls,
        tls_cert: args.tls_cert.clone(),
        tls_key: args.tls_key.clone(),
        nrf_uri: args.nrf_uri.clone(),
    };

    // Open legacy SBI server (for context initialization)
    bsf_sbi_open(Some(sbi_config)).map_err(|e| anyhow::anyhow!(e))?;

    // Start actual HTTP/2 SBI server using ogs-sbi
    let sbi_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let sbi_server = SbiServer::new(OgsSbiServerConfig::new(sbi_addr));

    sbi_server
        .start(bsf_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    log::info!("SBI HTTP/2 server listening on {sbi_addr}");

    // Register with NRF and start heartbeat worker
    match register_with_nrf(&args.sbi_addr, args.sbi_port).await {
        Ok(nf_instance_id) if !nf_instance_id.is_empty() => {
            ogs_sbi::heartbeat::spawn_heartbeat_worker(nf_instance_id, 5);
        }
        Ok(_) => {}
        Err(e) => {
            log::warn!("NRF registration failed (will operate without NRF): {e}");
        }
    }

    log::info!("NextGCore BSF ready");

    // Main event loop (async)
    run_event_loop_async(&mut bsf_sm, shutdown).await?;

    // Graceful shutdown
    log::info!("Shutting down...");

    // Stop SBI server
    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;
    log::info!("SBI HTTP/2 server stopped");

    // Close legacy SBI server
    bsf_sbi_close();
    log::info!("SBI server closed");

    // Cleanup state machine
    bsf_sm.fini();
    log::info!("BSF state machine finalized");

    // Cleanup context
    bsf_context_final();
    log::info!("BSF context finalized");

    log::info!("NextGCore BSF stopped");
    Ok(())
}

/// SBI request handler for BSF
async fn bsf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("BSF SBI request: {method} {uri}");

    // Parse the URI path
    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    // Route based on service and resource
    // Expected paths:
    // - /nbsf-management/v1/pcfBindings
    // - /nbsf-management/v1/pcfBindings/{bindingId}

    if parts.len() < 3 {
        return send_not_found("Invalid path", None);
    }

    let service = parts[0];
    let _version = parts[1];
    let resource = parts[2];

    match (service, resource, method) {
        // BSF Management Service (nbsf-management)
        ("nbsf-management", "pcfBindings", "POST") => {
            // Create PCF Binding
            handle_pcf_binding_create(&request).await
        }
        ("nbsf-management", "pcfBindings", "GET") if parts.len() >= 4 => {
            // Get PCF Binding
            let binding_id = parts[3];
            handle_pcf_binding_get(binding_id).await
        }
        ("nbsf-management", "pcfBindings", "GET") => {
            // Discovery PCF Binding (with query params)
            handle_pcf_binding_discovery(&request).await
        }
        ("nbsf-management", "pcfBindings", "DELETE") if parts.len() >= 4 => {
            // Delete PCF Binding
            let binding_id = parts[3];
            handle_pcf_binding_delete(binding_id).await
        }
        ("nbsf-management", "pcfBindings", "PATCH") if parts.len() >= 4 => {
            // Update PCF Binding
            let binding_id = parts[3];
            handle_pcf_binding_update(binding_id, &request).await
        }

        _ => {
            log::warn!("Unknown BSF request: {method} {uri}");
            send_method_not_allowed(method, uri)
        }
    }
}

// PCF Binding handlers

/// 400 ProblemDetails for a missing mandatory PcfBinding attribute.
fn missing_mandatory(attr: &str) -> SbiResponse {
    ogs_sbi::server::send_error(
        400,
        "Bad Request",
        &format!("Missing mandatory attribute: {attr}"),
        Some("MANDATORY_IE_MISSING"),
    )
}

/// Build the TS 29.521 PcfBinding representation of a session.
///
/// `dnn` and `snssai` are mandatory in the schema and always emitted;
/// optional attributes are emitted only when present (incl. the persisted
/// pcfIpEndPoints, W4.2).
fn binding_json(sess: &BsfSess) -> serde_json::Value {
    let mut b = serde_json::Map::new();
    b.insert(
        "pcfBindingId".to_string(),
        serde_json::Value::String(sess.binding_id.clone()),
    );
    b.insert(
        "dnn".to_string(),
        serde_json::Value::String(sess.dnn.clone().unwrap_or_default()),
    );
    let mut snssai = serde_json::Map::new();
    snssai.insert(
        "sst".to_string(),
        serde_json::Value::Number(sess.s_nssai.sst.into()),
    );
    if let Some(sd) = sess.s_nssai.sd_to_string() {
        snssai.insert("sd".to_string(), serde_json::Value::String(sd));
    }
    b.insert("snssai".to_string(), serde_json::Value::Object(snssai));
    if let Some(ref v) = sess.ipv4addr_string {
        b.insert("ipv4Addr".to_string(), serde_json::Value::String(v.clone()));
    }
    if let Some(ref v) = sess.ipv6prefix_string {
        b.insert(
            "ipv6Prefix".to_string(),
            serde_json::Value::String(v.clone()),
        );
    }
    if let Some(ref v) = sess.mac_addr48 {
        b.insert(
            "macAddr48".to_string(),
            serde_json::Value::String(v.clone()),
        );
    }
    if let Some(ref v) = sess.ip_domain {
        b.insert("ipDomain".to_string(), serde_json::Value::String(v.clone()));
    }
    if let Some(ref v) = sess.supi {
        b.insert("supi".to_string(), serde_json::Value::String(v.clone()));
    }
    if let Some(ref v) = sess.gpsi {
        b.insert("gpsi".to_string(), serde_json::Value::String(v.clone()));
    }
    if let Some(ref v) = sess.pcf_fqdn {
        b.insert("pcfFqdn".to_string(), serde_json::Value::String(v.clone()));
    }
    if let Some(ref v) = sess.expiry {
        b.insert("expiry".to_string(), serde_json::Value::String(v.clone()));
    }
    if !sess.pcf_ip.is_empty() {
        let endpoints: Vec<serde_json::Value> = sess
            .pcf_ip
            .iter()
            .map(|ep| {
                let mut e = serde_json::Map::new();
                if let Some(ref a) = ep.addr {
                    e.insert(
                        "ipv4Address".to_string(),
                        serde_json::Value::String(a.clone()),
                    );
                }
                if let Some(ref a6) = ep.addr6 {
                    e.insert(
                        "ipv6Address".to_string(),
                        serde_json::Value::String(a6.clone()),
                    );
                }
                if ep.is_port {
                    e.insert(
                        "port".to_string(),
                        serde_json::Value::Number(ep.port.into()),
                    );
                }
                serde_json::Value::Object(e)
            })
            .collect();
        b.insert(
            "pcfIpEndPoints".to_string(),
            serde_json::Value::Array(endpoints),
        );
    }
    if !sess.ipv4_frame_route_list.is_empty() {
        b.insert(
            "ipv4FrameRouteList".to_string(),
            serde_json::Value::Array(
                sess.ipv4_frame_route_list
                    .iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            ),
        );
    }
    if !sess.ipv6_frame_route_list.is_empty() {
        b.insert(
            "ipv6FrameRouteList".to_string(),
            serde_json::Value::Array(
                sess.ipv6_frame_route_list
                    .iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            ),
        );
    }
    b.insert(
        "suppFeat".to_string(),
        serde_json::Value::String("1".to_string()),
    );
    serde_json::Value::Object(b)
}

/// Parse a TS 29.510 IpEndPoint array into PcfIpEndpoint records.
fn parse_pcf_ip_endpoints(v: &serde_json::Value) -> Vec<context::PcfIpEndpoint> {
    v.as_array()
        .map(|endpoints| {
            endpoints
                .iter()
                .map(|ep| context::PcfIpEndpoint {
                    addr: ep
                        .get("ipv4Address")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    addr6: ep
                        .get("ipv6Address")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    is_port: ep.get("port").is_some(),
                    port: ep.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16,
                })
                .collect()
        })
        .unwrap_or_default()
}

async fn handle_pcf_binding_create(request: &SbiRequest) -> SbiResponse {
    log::info!("PCF Binding Create");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MANDATORY_IE_MISSING")),
    };

    let binding_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => {
            return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_MSG_FORMAT"))
        }
    };

    // Mandatory attributes per TS 29.521 PcfBinding: dnn + snssai.
    let Some(dnn) = binding_data.get("dnn").and_then(|v| v.as_str()) else {
        return missing_mandatory("dnn");
    };
    let Some(sst) = binding_data
        .get("snssai")
        .and_then(|s| s.get("sst"))
        .and_then(|v| v.as_u64())
    else {
        return missing_mandatory("snssai");
    };

    // UE address: at least one of ipv4Addr / ipv6Prefix / macAddr48
    // (MAC-only bindings for Ethernet PDU sessions are valid, W4.2).
    let ipv4addr = binding_data.get("ipv4Addr").and_then(|v| v.as_str());
    let ipv6prefix = binding_data.get("ipv6Prefix").and_then(|v| v.as_str());
    let mac_addr48 = binding_data.get("macAddr48").and_then(|v| v.as_str());
    if ipv4addr.is_none() && ipv6prefix.is_none() && mac_addr48.is_none() {
        return missing_mandatory("ipv4Addr|ipv6Prefix|macAddr48");
    }
    if let Some(mac) = mac_addr48 {
        if context::normalize_mac(mac).is_none() {
            return ogs_sbi::server::send_error(
                400,
                "Bad Request",
                &format!("Invalid macAddr48: {mac}"),
                Some("MANDATORY_IE_INCORRECT"),
            );
        }
    }

    // Optional expiry: must be a valid RFC 3339 DateTime when present.
    let expiry = binding_data.get("expiry").and_then(|v| v.as_str());
    if let Some(e) = expiry {
        if context::rfc3339_to_epoch(e).is_none() {
            return ogs_sbi::server::send_error(
                400,
                "Bad Request",
                &format!("expiry is not a valid RFC 3339 DateTime: {e}"),
                Some("MANDATORY_IE_INCORRECT"),
            );
        }
    }

    // Add session to context
    let ctx = bsf_self();
    let sess = if let Ok(context) = ctx.read() {
        context.sess_add_binding(ipv4addr, ipv6prefix, mac_addr48)
    } else {
        None
    };

    match sess {
        Some(mut sess) => {
            sess.dnn = Some(dnn.to_string());
            let sd = binding_data
                .get("snssai")
                .and_then(|s| s.get("sd"))
                .and_then(|v| v.as_str())
                .and_then(|s| u32::from_str_radix(s, 16).ok());
            sess.s_nssai = context::SNssai::new(sst as u8, sd);
            if let Some(supi) = binding_data.get("supi").and_then(|v| v.as_str()) {
                sess.supi = Some(supi.to_string());
            }
            if let Some(gpsi) = binding_data.get("gpsi").and_then(|v| v.as_str()) {
                sess.gpsi = Some(gpsi.to_string());
            }
            if let Some(ip_domain) = binding_data.get("ipDomain").and_then(|v| v.as_str()) {
                sess.ip_domain = Some(ip_domain.to_string());
            }
            if let Some(pcf_fqdn) = binding_data.get("pcfFqdn").and_then(|v| v.as_str()) {
                sess.pcf_fqdn = Some(pcf_fqdn.to_string());
            }
            if let Some(endpoints) = binding_data.get("pcfIpEndPoints") {
                sess.pcf_ip = parse_pcf_ip_endpoints(endpoints);
            }
            if let Some(e) = expiry {
                sess.set_expiry(e);
            }

            // Update session in context, then persist off-thread (guard
            // dropped before any await).
            if let Ok(context) = ctx.read() {
                context.sess_update(&sess);
            }
            context::persist_binding_async(sess.clone()).await;

            // Arm the expiry timer: from the RFC 3339 expiry when given,
            // otherwise the default TTL.
            let ttl_secs = sess
                .expiry_epoch
                .map(|e| (e - context::now_epoch()).max(0) as u64)
                .unwrap_or(timer::defaults::BINDING_EXPIRY.as_secs());
            let timer_mgr = timer_manager();
            timer_mgr.start(
                BsfTimerId::BindingExpiry,
                Duration::from_secs(ttl_secs),
                Some(sess.binding_id.clone()),
            );

            log::info!(
                "PCF Binding created (id={}, ipv4={:?}, ipv6={:?}, mac={:?}, TTL={}s)",
                sess.binding_id,
                ipv4addr,
                ipv6prefix,
                mac_addr48,
                ttl_secs
            );

            SbiResponse::with_status(201)
                .with_header(
                    "Location",
                    format!("/nbsf-management/v1/pcfBindings/{}", sess.binding_id),
                )
                .with_json_body(&binding_json(&sess))
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        None => send_bad_request("Failed to create PCF binding", Some("SYSTEM_FAILURE")),
    }
}

async fn handle_pcf_binding_get(binding_id: &str) -> SbiResponse {
    log::debug!("PCF Binding Get: {binding_id}");

    let ctx = bsf_self();
    let sess = if let Ok(context) = ctx.read() {
        context.sess_find_by_binding_id(binding_id)
    } else {
        None
    };

    match sess {
        // Expired bindings are not served (swept by the event loop).
        Some(sess) if !sess.is_expired(context::now_epoch()) => SbiResponse::with_status(200)
            .with_json_body(&binding_json(&sess))
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        _ => send_not_found(
            &format!("PCF Binding {binding_id} not found"),
            Some("BINDING_NOT_FOUND"),
        ),
    }
}

async fn handle_pcf_binding_discovery(request: &SbiRequest) -> SbiResponse {
    // TS 29.521 GET /pcfBindings query parameters (W4.2: + macAddr48, supi,
    // gpsi, dnn, ipDomain, snssai on top of the existing ipv4/ipv6).
    let params = &request.http.params;
    let snssai = params.get("snssai").and_then(|raw| {
        let decoded = pct_decode(raw);
        let v: serde_json::Value = serde_json::from_str(&decoded).ok()?;
        let sst = v.get("sst")?.as_u64()? as u8;
        let sd = v
            .get("sd")
            .and_then(|s| s.as_str())
            .and_then(|s| u32::from_str_radix(s, 16).ok());
        Some(context::SNssai::new(sst, sd))
    });
    let filter = context::BindingFilter {
        ipv4addr: params.get("ipv4Addr").cloned(),
        ipv6prefix: params.get("ipv6Prefix").map(|s| pct_decode(s)),
        mac_addr48: params.get("macAddr48").cloned(),
        supi: params.get("supi").cloned(),
        gpsi: params.get("gpsi").cloned(),
        dnn: params.get("dnn").cloned(),
        ip_domain: params.get("ipDomain").cloned(),
        snssai,
    };

    log::info!(
        "PCF Binding Discovery: ipv4={:?}, ipv6={:?}, mac={:?}, supi={:?}, dnn={:?}",
        filter.ipv4addr,
        filter.ipv6prefix,
        filter.mac_addr48,
        filter.supi,
        filter.dnn
    );

    if !filter.has_ue_identifier() {
        return send_bad_request(
            "At least one of ipv4Addr, ipv6Prefix, macAddr48, supi or gpsi is required",
            Some("MANDATORY_QUERY_PARAM_MISSING"),
        );
    }

    let ctx = bsf_self();
    let matches = if let Ok(context) = ctx.read() {
        context.sess_find_matching(&filter, context::now_epoch())
    } else {
        Vec::new()
    };

    match matches.as_slice() {
        [] => send_not_found(
            "No PCF binding found for the specified parameters",
            Some("BINDING_NOT_FOUND"),
        ),
        [sess] => {
            log::info!("PCF Binding found: {}", sess.binding_id);
            SbiResponse::with_status(200)
                .with_json_body(&binding_json(sess))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        _ => ogs_sbi::server::send_error(
            400,
            "Bad Request",
            "Multiple PCF bindings match the query parameter combination",
            Some("MULTIPLE_BINDING_INFO_FOUND"),
        ),
    }
}

/// Minimal percent-decoding for query parameter values.
fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn handle_pcf_binding_delete(binding_id: &str) -> SbiResponse {
    log::info!("PCF Binding Delete: {binding_id}");

    let ctx = bsf_self();

    // Parse binding ID to session ID
    let sess_id: Option<u64> = binding_id.parse().ok();

    match sess_id {
        Some(id) => {
            let removed = ctx
                .read()
                .map(|context| context.sess_remove(id).is_some())
                .unwrap_or(false);
            if removed {
                // Guard dropped above; unpersist off-thread.
                context::unpersist_binding_async(binding_id.to_string()).await;
                log::info!("PCF Binding {binding_id} deleted");
                return SbiResponse::with_status(204);
            }
            send_not_found(
                &format!("PCF Binding {binding_id} not found"),
                Some("BINDING_NOT_FOUND"),
            )
        }
        None => send_bad_request("Invalid binding ID format", Some("INVALID_BINDING_ID")),
    }
}

async fn handle_pcf_binding_update(binding_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("PCF Binding Update (PATCH): {binding_id}");

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let update_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let ctx = bsf_self();
    let sess = if let Ok(context) = ctx.read() {
        context.sess_find_by_binding_id(binding_id)
    } else {
        None
    };

    match sess {
        Some(mut sess) => {
            // Apply patch fields from the request body
            if let Some(pcf_fqdn) = update_data.get("pcfFqdn").and_then(|v| v.as_str()) {
                sess.pcf_fqdn = Some(pcf_fqdn.to_string());
            }
            if let Some(ipv4) = update_data.get("ipv4Addr").and_then(|v| v.as_str()) {
                sess.set_ipv4addr(ipv4);
            }
            if let Some(ipv6) = update_data.get("ipv6Prefix").and_then(|v| v.as_str()) {
                sess.set_ipv6prefix(ipv6);
            }
            if let Some(mac) = update_data.get("macAddr48").and_then(|v| v.as_str()) {
                if !sess.set_mac_addr48(mac) {
                    return ogs_sbi::server::send_error(
                        400,
                        "Bad Request",
                        &format!("Invalid macAddr48: {mac}"),
                        Some("MANDATORY_IE_INCORRECT"),
                    );
                }
            }
            if let Some(ip_domain) = update_data.get("ipDomain").and_then(|v| v.as_str()) {
                sess.ip_domain = Some(ip_domain.to_string());
            }
            if let Some(expiry) = update_data.get("expiry").and_then(|v| v.as_str()) {
                if !sess.set_expiry(expiry) {
                    return ogs_sbi::server::send_error(
                        400,
                        "Bad Request",
                        &format!("expiry is not a valid RFC 3339 DateTime: {expiry}"),
                        Some("MANDATORY_IE_INCORRECT"),
                    );
                }
            }
            if let Some(supi) = update_data.get("supi").and_then(|v| v.as_str()) {
                sess.supi = Some(supi.to_string());
            }
            if let Some(gpsi) = update_data.get("gpsi").and_then(|v| v.as_str()) {
                sess.gpsi = Some(gpsi.to_string());
            }
            if let Some(dnn) = update_data.get("dnn").and_then(|v| v.as_str()) {
                sess.dnn = Some(dnn.to_string());
            }
            if let Some(snssai) = update_data.get("snssai") {
                let sst = snssai.get("sst").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
                let sd = snssai
                    .get("sd")
                    .and_then(|v| v.as_str())
                    .and_then(|s| u32::from_str_radix(s, 16).ok());
                sess.s_nssai = context::SNssai::new(sst, sd);
            }
            if let Some(routes) = update_data
                .get("ipv4FrameRouteList")
                .and_then(|v| v.as_array())
            {
                sess.ipv4_frame_route_list = routes
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
            }
            if let Some(routes) = update_data
                .get("ipv6FrameRouteList")
                .and_then(|v| v.as_array())
            {
                sess.ipv6_frame_route_list = routes
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
            }
            if let Some(endpoints) = update_data.get("pcfIpEndPoints") {
                sess.pcf_ip = parse_pcf_ip_endpoints(endpoints);
            }

            // Update session in context, then persist off-thread (guard
            // dropped before the await).
            if let Ok(context) = ctx.read() {
                context.sess_update(&sess);
            }
            context::persist_binding_async(sess.clone()).await;

            log::info!("PCF Binding {binding_id} updated");

            SbiResponse::with_status(200)
                .with_json_body(&binding_json(&sess))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        None => send_not_found(
            &format!("PCF Binding {binding_id} not found"),
            Some("BINDING_NOT_FOUND"),
        ),
    }
}

/// Initialize logging based on command line arguments
fn init_logging(args: &Args) -> Result<()> {
    let mut builder = env_logger::Builder::new();

    // Set log level
    let level = match args.log_level.to_lowercase().as_str() {
        "trace" => log::LevelFilter::Trace,
        "debug" => log::LevelFilter::Debug,
        "info" => log::LevelFilter::Info,
        "warn" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        _ => log::LevelFilter::Info,
    };
    builder.filter_level(level);

    // Configure format
    builder.format_timestamp_millis();

    if args.no_color {
        builder.write_style(env_logger::WriteStyle::Never);
    }

    builder.init();

    Ok(())
}

/// Set up signal handlers for graceful shutdown
fn setup_signal_handlers(shutdown: Arc<AtomicBool>) -> Result<()> {
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        shutdown_clone.store(true, Ordering::SeqCst);
        SHUTDOWN.store(true, Ordering::SeqCst);
    })
    .context("Failed to set Ctrl+C handler")?;

    Ok(())
}

/// Async main event loop with timer integration
async fn run_event_loop_async(bsf_sm: &mut BsfSmContext, shutdown: Arc<AtomicBool>) -> Result<()> {
    log::debug!("Entering async main event loop");

    let timer_mgr = timer_manager();

    while !shutdown.load(Ordering::SeqCst) && !SHUTDOWN.load(Ordering::SeqCst) {
        // Compute optimal sleep duration based on pending timers
        let poll_interval = ogs_core::async_timer::compute_poll_interval(
            timer_mgr.inner(),
            Duration::from_millis(100),
        );
        tokio::time::sleep(poll_interval).await;

        // Process timer expirations and dispatch to state machine
        let expired = timer_mgr.process_expired();
        for entry in &expired {
            log::debug!(
                "BSF timer expired: id={} type={:?} data={:?}",
                entry.id,
                entry.timer_type,
                entry.data
            );

            // Handle binding expiry timer directly (TTL cleanup)
            if entry.timer_type == BsfTimerId::BindingExpiry {
                if let Some(ref binding_id) = entry.data {
                    log::info!("PCF Binding {binding_id} expired (TTL), removing");
                    let ctx = bsf_self();
                    if let Ok(sess_id) = binding_id.parse::<u64>() {
                        let removed = ctx
                            .read()
                            .map(|context| context.sess_remove(sess_id).is_some())
                            .unwrap_or(false);
                        if removed {
                            // Guard dropped above; unpersist off-thread.
                            context::unpersist_binding_async(binding_id.clone()).await;
                            log::info!("PCF Binding {binding_id} auto-removed on TTL expiry");
                        }
                    }
                }
                continue;
            }

            // Create timer event and dispatch to state machine
            let mut event = BsfEvent::sbi_timer(entry.timer_type);
            if let Some(ref nf_id) = entry.data {
                event = event.with_nf_instance(nf_id.clone());
            }

            bsf_sm.dispatch(&mut event);
        }

        // Sweep bindings whose RFC 3339 expiry has passed (W4.2: expired
        // bindings excluded from discovery and removed from storage).
        let swept = {
            let ctx = bsf_self();
            ctx.read()
                .map(|context| context.sweep_expired(context::now_epoch()))
                .unwrap_or_default()
        };
        for binding_id in swept {
            context::unpersist_binding_async(binding_id).await;
        }

        // Check for shutdown
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
    }

    // Cleanup: clear all timers on shutdown
    timer_mgr.clear();
    log::debug!("Exiting async main event loop");
    Ok(())
}

/// Register BSF with NRF.
///
/// Returns the NF instance ID on success so the caller can start a heartbeat
/// worker.
async fn register_with_nrf(sbi_addr: &str, sbi_port: u16) -> Result<String, String> {
    let sbi_ctx = ogs_sbi::context::global_context();

    let nrf_uri = sbi_ctx.get_nrf_uri().await;
    let nrf_uri = match nrf_uri {
        Some(uri) => uri,
        None => {
            log::debug!("No NRF URI configured, skipping NRF registration");
            return Ok(String::new());
        }
    };

    log::info!("Registering BSF with NRF at {nrf_uri}");

    let (nrf_host, nrf_port) = parse_nrf_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_instance_id = uuid::Uuid::new_v4().to_string();

    let nf_profile = serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "BSF",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [
            {
                "serviceInstanceId": format!("{nf_instance_id}-nbsf-management"),
                "serviceName": "nbsf-management",
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
            }
        ],
        "allowedNfTypes": ["PCF", "SMF", "SCP"],
        "heartBeatTimer": 10
    });

    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    let response = client
        .put_json(&path, &nf_profile)
        .await
        .map_err(|e| format!("NRF registration request failed: {e}"))?;

    match response.status {
        200 | 201 => {
            log::info!("BSF registered with NRF successfully (id={nf_instance_id})");
            Ok(nf_instance_id)
        }
        _ => Err(format!(
            "NRF registration returned status {}",
            response.status
        )),
    }
}

/// Parse host and port from a URI string (e.g., "http://localhost:7777").
fn parse_nrf_host_port(uri: &str) -> Option<(String, u16)> {
    let without_scheme = uri
        .strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri);
    let (host_port, _) = without_scheme
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
        let args = Args::parse_from(["nextgcore-bsfd"]);
        assert_eq!(args.config, "/etc/nextgcore/bsf.yaml");
        assert_eq!(args.log_level, "info");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 7777);
        assert!(!args.tls);
        assert_eq!(args.max_sess, 1024);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "nextgcore-bsfd",
            "-c",
            "/custom/bsf.yaml",
            "-e",
            "debug",
            "--sbi-addr",
            "0.0.0.0",
            "--sbi-port",
            "8080",
            "--max-sess",
            "2048",
        ]);
        assert_eq!(args.config, "/custom/bsf.yaml");
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.sbi_addr, "0.0.0.0");
        assert_eq!(args.sbi_port, 8080);
        assert_eq!(args.max_sess, 2048);
    }

    #[test]
    fn test_args_tls() {
        let args = Args::parse_from([
            "nextgcore-bsfd",
            "--tls",
            "--tls-cert",
            "/path/to/cert.pem",
            "--tls-key",
            "/path/to/key.pem",
        ]);
        assert!(args.tls);
        assert_eq!(args.tls_cert, Some("/path/to/cert.pem".to_string()));
        assert_eq!(args.tls_key, Some("/path/to/key.pem".to_string()));
    }

    #[test]
    fn test_pct_decode() {
        assert_eq!(pct_decode("a%2Cb"), "a,b");
        assert_eq!(pct_decode("plain"), "plain");
        assert_eq!(
            pct_decode("%7B%22sst%22%3A1%2C%22sd%22%3A%22010203%22%7D"),
            "{\"sst\":1,\"sd\":\"010203\"}"
        );
        assert_eq!(pct_decode("2001%3Adb8%3A%3A1%2F128"), "2001:db8::1/128");
    }

    #[test]
    fn test_binding_json_shape() {
        let mut sess = BsfSess::new(9);
        sess.binding_id = "9".to_string();
        sess.dnn = Some("internet".to_string());
        sess.s_nssai = context::SNssai::new(1, Some(0x010203));
        sess.set_mac_addr48("aa:bb:cc:dd:ee:ff");
        sess.pcf_ip = vec![context::PcfIpEndpoint {
            addr: Some("10.0.0.10".to_string()),
            addr6: None,
            is_port: true,
            port: 7777,
        }];
        let j = binding_json(&sess);
        // Mandatory PcfBinding attributes always present
        assert_eq!(j["dnn"], "internet");
        assert_eq!(j["snssai"]["sst"], 1);
        assert_eq!(j["snssai"]["sd"], "010203");
        // MAC canonical form, persisted endpoints echoed
        assert_eq!(j["macAddr48"], "aa-bb-cc-dd-ee-ff");
        assert_eq!(j["pcfIpEndPoints"][0]["ipv4Address"], "10.0.0.10");
        assert_eq!(j["pcfIpEndPoints"][0]["port"], 7777);
        // Absent optionals are omitted, not null
        assert!(j.get("ipv4Addr").is_none());
        assert!(j.get("expiry").is_none());
    }

    // ------------------------------------------------------------------
    // HTTP-level lifecycle tests over a real HTTP/2 SBI server on an
    // ephemeral port (strict-peer rejections + discovery matrix + expiry).
    // ------------------------------------------------------------------

    use ogs_sbi::client::SbiClient;
    use serde_json::json;

    fn ephemeral_addr() -> SocketAddr {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe binds");
        let addr = probe.local_addr().expect("probe addr");
        drop(probe);
        addr
    }

    async fn start_bsf() -> (SbiServer, SbiClient) {
        // The handlers consult the global BSF context: initialize it once.
        bsf_context_init(1024);
        let addr = ephemeral_addr();
        let server = SbiServer::new(OgsSbiServerConfig::new(addr));
        server
            .start(bsf_sbi_request_handler)
            .await
            .expect("BSF SBI server starts");
        (server, SbiClient::with_host_port("127.0.0.1", addr.port()))
    }

    fn problem(resp: &SbiResponse) -> serde_json::Value {
        serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap()
    }

    /// Strict-peer rejections: missing mandatory attrs and malformed values
    /// produce 400 ProblemDetails with the spec cause.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_create_rejects_missing_mandatory() {
        let (server, client) = start_bsf().await;

        // Missing dnn
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcfBindings",
                &json!({"snssai": {"sst": 1}, "ipv4Addr": "10.45.9.1"}),
            )
            .await
            .expect("POST no dnn");
        assert_eq!(resp.status, 400);
        assert_eq!(problem(&resp)["cause"], "MANDATORY_IE_MISSING");
        assert!(problem(&resp)["detail"].as_str().unwrap().contains("dnn"));

        // Missing snssai
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcfBindings",
                &json!({"dnn": "internet", "ipv4Addr": "10.45.9.1"}),
            )
            .await
            .expect("POST no snssai");
        assert_eq!(resp.status, 400);
        assert_eq!(problem(&resp)["cause"], "MANDATORY_IE_MISSING");

        // No UE address at all
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcfBindings",
                &json!({"dnn": "internet", "snssai": {"sst": 1}}),
            )
            .await
            .expect("POST no address");
        assert_eq!(resp.status, 400);
        assert_eq!(problem(&resp)["cause"], "MANDATORY_IE_MISSING");

        // Malformed MAC
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcfBindings",
                &json!({"dnn": "internet", "snssai": {"sst": 1}, "macAddr48": "nope"}),
            )
            .await
            .expect("POST bad mac");
        assert_eq!(resp.status, 400);
        assert_eq!(problem(&resp)["cause"], "MANDATORY_IE_INCORRECT");

        // Malformed expiry (integer seconds, not RFC 3339)
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcfBindings",
                &json!({"dnn": "internet", "snssai": {"sst": 1},
                        "ipv4Addr": "10.45.9.1", "expiry": "3600"}),
            )
            .await
            .expect("POST bad expiry");
        assert_eq!(resp.status, 400);
        assert_eq!(problem(&resp)["cause"], "MANDATORY_IE_INCORRECT");

        server.stop().await.expect("server stops");
    }

    /// Full lifecycle: MAC-only create with pcfIpEndPoints, discovery by
    /// mac/supi/dnn/ipv4, multiple-match rejection, PATCH, expiry exclusion,
    /// DELETE.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_binding_lifecycle_discovery_and_expiry() {
        let (server, client) = start_bsf().await;

        // MAC-only binding (Ethernet PDU session, no UE IP) with endpoints.
        let create = json!({
            "dnn": "internet",
            "snssai": {"sst": 1, "sd": "010203"},
            "macAddr48": "AA:BB:CC:00:11:22",
            "supi": "imsi-001019900100001",
            "pcfFqdn": "pcf.example.com",
            "pcfIpEndPoints": [
                {"ipv4Address": "10.0.0.10", "port": 7777},
                {"ipv6Address": "2001:db8::10"}
            ]
        });
        let resp = client
            .post_json("/nbsf-management/v1/pcfBindings", &create)
            .await
            .expect("POST create");
        assert_eq!(resp.status, 201);
        let location = resp.http.get_header("Location").expect("Location").clone();
        let binding_id = location.rsplit('/').next().unwrap().to_string();
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        // pcfIpEndPoints persisted and returned (not echoed from raw input)
        assert_eq!(body["pcfIpEndPoints"][0]["ipv4Address"], "10.0.0.10");
        assert_eq!(body["pcfIpEndPoints"][0]["port"], 7777);
        assert_eq!(body["pcfIpEndPoints"][1]["ipv6Address"], "2001:db8::10");
        assert_eq!(body["macAddr48"], "aa-bb-cc-00-11-22");
        assert!(body.get("ipv4Addr").is_none());

        // Second binding for the same SUPI on another DNN (IPv4-keyed).
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcfBindings",
                &json!({
                    "dnn": "ims",
                    "snssai": {"sst": 1},
                    "ipv4Addr": "10.45.9.7",
                    "supi": "imsi-001019900100001"
                }),
            )
            .await
            .expect("POST second");
        assert_eq!(resp.status, 201);
        let second_body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let second_id = second_body["pcfBindingId"].as_str().unwrap().to_string();

        // Discovery without any UE identifier -> 400.
        let req = SbiRequest::get("/nbsf-management/v1/pcfBindings");
        let resp = client.send_request(req).await.expect("discover none");
        assert_eq!(resp.status, 400);

        // Discovery by MAC (different separator/case) -> the MAC binding.
        let mut req = SbiRequest::get("/nbsf-management/v1/pcfBindings");
        req.http.set_param("macAddr48", "aa-bb-cc-00-11-22");
        let resp = client.send_request(req).await.expect("discover mac");
        assert_eq!(resp.status, 200);
        let found: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(found["pcfBindingId"].as_str().unwrap(), binding_id);
        assert_eq!(found["pcfIpEndPoints"][0]["port"], 7777);

        // Discovery by SUPI alone -> two matches -> 400 MULTIPLE_BINDING_INFO_FOUND.
        let mut req = SbiRequest::get("/nbsf-management/v1/pcfBindings");
        req.http.set_param("supi", "imsi-001019900100001");
        let resp = client.send_request(req).await.expect("discover supi");
        assert_eq!(resp.status, 400);
        assert_eq!(problem(&resp)["cause"], "MULTIPLE_BINDING_INFO_FOUND");

        // Discovery by SUPI + DNN narrows to one.
        let mut req = SbiRequest::get("/nbsf-management/v1/pcfBindings");
        req.http.set_param("supi", "imsi-001019900100001");
        req.http.set_param("dnn", "ims");
        let resp = client.send_request(req).await.expect("discover supi+dnn");
        assert_eq!(resp.status, 200);
        let found: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(found["pcfBindingId"].as_str().unwrap(), second_id);

        // Discovery by ipv4Addr still works.
        let mut req = SbiRequest::get("/nbsf-management/v1/pcfBindings");
        req.http.set_param("ipv4Addr", "10.45.9.7");
        let resp = client.send_request(req).await.expect("discover ipv4");
        assert_eq!(resp.status, 200);

        // PATCH the MAC binding's endpoints; echoed in the response and GET.
        let mut req = SbiRequest::patch(format!("/nbsf-management/v1/pcfBindings/{binding_id}"));
        req.http.set_content(
            json!({"pcfIpEndPoints": [{"ipv4Address": "10.0.0.20", "port": 8888}]}).to_string(),
        );
        req.http.set_header("Content-Type", "application/json");
        let resp = client.send_request(req).await.expect("PATCH");
        assert_eq!(resp.status, 200);
        let patched: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(patched["pcfIpEndPoints"][0]["ipv4Address"], "10.0.0.20");
        let resp = client
            .get(&format!("/nbsf-management/v1/pcfBindings/{binding_id}"))
            .await
            .expect("GET after PATCH");
        assert_eq!(resp.status, 200);
        let got: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(got["pcfIpEndPoints"][0]["port"], 8888);

        // A binding with an already-past RFC 3339 expiry is excluded from
        // discovery and GET (expired -> not served).
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcfBindings",
                &json!({
                    "dnn": "expired",
                    "snssai": {"sst": 1},
                    "ipv4Addr": "10.45.9.99",
                    "expiry": "2000-01-01T00:00:00Z"
                }),
            )
            .await
            .expect("POST expired");
        assert_eq!(resp.status, 201);
        let mut req = SbiRequest::get("/nbsf-management/v1/pcfBindings");
        req.http.set_param("ipv4Addr", "10.45.9.99");
        let resp = client.send_request(req).await.expect("discover expired");
        assert_eq!(resp.status, 404);

        // DELETE both live bindings -> 204; GET -> 404 afterwards.
        for id in [&binding_id, &second_id] {
            let resp = client
                .delete(&format!("/nbsf-management/v1/pcfBindings/{id}"))
                .await
                .expect("DELETE");
            assert_eq!(resp.status, 204);
            let resp = client
                .get(&format!("/nbsf-management/v1/pcfBindings/{id}"))
                .await
                .expect("GET deleted");
            assert_eq!(resp.status, 404);
        }
        // Deleting again -> 404.
        let resp = client
            .delete(&format!("/nbsf-management/v1/pcfBindings/{binding_id}"))
            .await
            .expect("DELETE again");
        assert_eq!(resp.status, 404);

        server.stop().await.expect("server stops");
    }
}
