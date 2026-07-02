//! NextGCore BSF (Binding Support Function)
//!
//! The BSF is a 5G core network function responsible for:
//! - Managing PCF (Policy Control Function) bindings
//! - Providing binding information to PCF and AF
//! - Supporting session binding based on IP addresses
//!
//! Wave-6 H1 (strict-peer harness foundation): the whole NF lives in this
//! library crate so integration tests in other NF crates can call the real
//! [`bsf_sbi_request_handler`] in-process (no lenient mocks); `src/main.rs`
//! is a thin wrapper around [`run`].

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::oauth::{JwksCache, OAuth2Client};
use nextgcore_sbi::server::{
    send_bad_request, send_method_not_allowed, send_not_found, SbiServer,
    SbiServerConfig as NextgcoreSbiServerConfig,
};
use nextgcore_sbi::types::NfType;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

pub mod bsf_sm;
pub mod context;
pub mod event;
pub mod nnrf_handler;
pub mod sbi_path;
pub mod sbi_response;
pub mod timer;

pub use bsf_sm::{BsfSmContext, BsfState};
pub use context::*;
pub use event::{
    BsfEvent, BsfEventId, BsfTimerId, EventSbiRequest, EventSbiResponse, SbiEventData, SbiMessage,
};
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
struct SbiServerYaml {
    address: Option<String>,
    port: Option<u16>,
}

/// SBI OAuth2 enforcement knob (`bsf.sbi.oauth2.require`).
///
/// Defaults to disabled so the existing dev/E2E path keeps working without
/// tokens; the production/docker `bsf-oauth2.yaml` variant sets it true.
#[derive(Debug, Default, Deserialize)]
struct SbiOauth2Yaml {
    require: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct SbiYaml {
    server: Option<Vec<SbiServerYaml>>,
    client: Option<SbiClientYaml>,
    oauth2: Option<SbiOauth2Yaml>,
}

#[derive(Debug, Default, Deserialize)]
struct BsfSection {
    sbi: Option<SbiYaml>,
}

/// Process-wide OAuth2 client for automatic Bearer-token acquisition on
/// outbound SBI calls (set only when `bsf.sbi.oauth2.require` is true).
static OAUTH2_CLIENT: OnceLock<Option<Arc<OAuth2Client>>> = OnceLock::new();

/// The shared OAuth2 client, if SBI OAuth2 enforcement is enabled.
#[allow(dead_code)]
fn oauth2_client() -> Option<Arc<OAuth2Client>> {
    OAUTH2_CLIENT.get().and_then(|opt| opt.clone())
}

#[derive(Debug, Default, Deserialize)]
struct BsfYaml {
    bsf: Option<BsfSection>,
}

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Run the BSF network function (argument parsing, context/SM init, SBI
/// server, NRF registration, event loop, graceful shutdown).
///
/// This is the whole former `fn main`; the `nextgcore-bsfd` binary target is
/// a thin wrapper calling this (Wave-6 H1 lib-targetization, zero logic diff).
#[tokio::main]
pub async fn run() -> Result<()> {
    let mut args = Args::parse();

    // Initialize logging
    init_logging(&args)?;
    // G32/G43: Initialize OpenTelemetry tracing (Jaeger/OTLP exporter)
    let _otel = nextgcore_metrics::otel::init_otel(
        nextgcore_metrics::otel::OtelConfig::new(env!("CARGO_PKG_NAME")).with_endpoint(
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
    // the async runtime (sync -> async Mongo).
    context::load_persisted_bindings_async().await;

    // Initialize BSF state machine
    let mut bsf_sm = BsfSmContext::new();
    bsf_sm.init();
    log::info!("BSF state machine initialized");

    // Parse configuration (if file exists) and seed NRF URI
    let mut nrf_uri_cfg: Option<String> = args.nrf_uri.clone();
    let mut require_oauth2 = false;
    if std::path::Path::new(&args.config).exists() {
        log::info!("Loading configuration from {}", args.config);
        match std::fs::read_to_string(&args.config) {
            Ok(content) => {
                log::debug!("Configuration file loaded ({} bytes)", content.len());
                // Seed NRF URI into SBI context for NF registration
                if let Ok(yaml) = serde_yaml::from_str::<BsfYaml>(&content) {
                    if let Some(bsf) = yaml.bsf {
                        if let Some(sbi) = bsf.sbi {
                            // Override the advertised/bind SBI address with the
                            // routable address from config so the NRF NFProfile
                            // advertises a reachable endpoint (not 0.0.0.0).
                            if let Some(server) = sbi.server.as_ref().and_then(|s| s.first()) {
                                if let Some(addr) = &server.address {
                                    args.sbi_addr = addr.clone();
                                }
                                if let Some(port) = server.port {
                                    args.sbi_port = port;
                                }
                            }
                            if let Some(client) = sbi.client {
                                if let Some(nrf_list) = client.nrf {
                                    if let Some(nrf) = nrf_list.first() {
                                        log::info!("NRF URI configured: {}", nrf.uri);
                                        nrf_uri_cfg = Some(nrf.uri.clone());
                                        nextgcore_sbi::context::global_context()
                                            .set_nrf_uri(&nrf.uri)
                                            .await;
                                    }
                                }
                            }
                            // SBI OAuth2 enforcement knob (bsf.sbi.oauth2.require).
                            require_oauth2 = sbi.oauth2.and_then(|o| o.require).unwrap_or(false);
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

    // Start actual HTTP/2 SBI server using nextgcore-sbi
    let sbi_addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
        .parse()
        .context("Invalid SBI address")?;
    let mut sbi_server_config = NextgcoreSbiServerConfig::new(sbi_addr);
    if require_oauth2 {
        // Server side (TS 33.501 §13.4.1): verify incoming Bearer tokens
        // against the NRF's JWKS and require the token's `aud` to include this
        // NF's own type ("BSF"). With no NRF URI configured the server fails
        // closed (503).
        sbi_server_config.require_oauth2 = true;
        sbi_server_config.oauth2_jwks_uri = nrf_uri_cfg
            .as_deref()
            .map(|uri| JwksCache::for_nrf(uri).jwks_uri().to_string());
        sbi_server_config = sbi_server_config.with_expected_audience_nf_type(NfType::Bsf);

        // Client side (T1.1): install the process-wide OAuth2 client so
        // outbound SBI calls acquire and attach an NRF-issued Bearer token.
        if let Some(nrf_uri) = nrf_uri_cfg.as_deref() {
            let nf_instance_id = format!("bsf-{}", uuid::Uuid::new_v4());
            let oauth2 = Arc::new(OAuth2Client::new(nrf_uri, nf_instance_id, NfType::Bsf));
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

    sbi_server
        .start(bsf_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    log::info!("SBI HTTP/2 server listening on {sbi_addr}");

    // Register with NRF and start heartbeat worker
    match register_with_nrf(&args.sbi_addr, args.sbi_port).await {
        Ok(nf_instance_id) if !nf_instance_id.is_empty() => {
            // G2-2: PATCH a real NFProfile "/load" gauge to NRF each heartbeat
            // (BSF bindings vs configured capacity; TS 29.510 §5.2.2.3.2).
            nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(nf_instance_id, 5, || {
                let load = crate::context::get_sess_load();
                load.clamp(0, 100) as u8
            });
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

/// SBI request handler for BSF.
///
/// Public so strict-peer integration tests (Wave-6 H1/H2) can route real
/// consumer-built `SbiRequest`s through the real BSF validation/handlers
/// in-process instead of a lenient mock.
pub async fn bsf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
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
        // bsfd-13 stub: subscription sub-resource (any method) -> 501.
        // Must be checked BEFORE the generic pcfBindings/POST arm.
        ("nbsf-management", "pcfBindings", _)
            if parts.len() >= 5 && parts[4] == "subscriptions" =>
        {
            nextgcore_sbi::server::send_error(
                501,
                "Not Implemented",
                "Nbsf_Management Subscribe/Unsubscribe is not implemented (bsfd-13 stub)",
                None,
            )
        }
        // BSF Management Service (nbsf-management) — PDU-session bindings
        ("nbsf-management", "pcfBindings", "POST") => handle_pcf_binding_create(&request).await,
        ("nbsf-management", "pcfBindings", "GET") if parts.len() >= 4 => {
            let binding_id = parts[3];
            handle_pcf_binding_get(binding_id).await
        }
        ("nbsf-management", "pcfBindings", "GET") => handle_pcf_binding_discovery(&request).await,
        ("nbsf-management", "pcfBindings", "DELETE") if parts.len() >= 4 => {
            let binding_id = parts[3];
            handle_pcf_binding_delete(binding_id).await
        }
        ("nbsf-management", "pcfBindings", "PATCH") if parts.len() >= 4 => {
            let binding_id = parts[3];
            handle_pcf_binding_update(binding_id, &request).await
        }
        // bsfd-11: pcf-ue-bindings resource
        ("nbsf-management", "pcf-ue-bindings", "POST") => {
            handle_pcf_ue_binding_create(&request).await
        }
        ("nbsf-management", "pcf-ue-bindings", "GET") if parts.len() >= 4 => {
            handle_pcf_ue_binding_get(parts[3]).await
        }
        ("nbsf-management", "pcf-ue-bindings", "GET") => {
            handle_pcf_ue_binding_discovery(&request).await
        }
        ("nbsf-management", "pcf-ue-bindings", "DELETE") if parts.len() >= 4 => {
            handle_pcf_ue_binding_delete(parts[3]).await
        }
        ("nbsf-management", "pcf-ue-bindings", "PATCH") if parts.len() >= 4 => {
            handle_pcf_ue_binding_update(parts[3], &request).await
        }
        // bsfd-12: pcf-mbs-bindings resource
        ("nbsf-management", "pcf-mbs-bindings", "POST") => {
            handle_pcf_mbs_binding_create(&request).await
        }
        ("nbsf-management", "pcf-mbs-bindings", "GET") if parts.len() >= 4 => {
            handle_pcf_mbs_binding_get(parts[3]).await
        }
        ("nbsf-management", "pcf-mbs-bindings", "GET") => {
            handle_pcf_mbs_binding_discovery(&request).await
        }
        ("nbsf-management", "pcf-mbs-bindings", "DELETE") if parts.len() >= 4 => {
            handle_pcf_mbs_binding_delete(parts[3]).await
        }
        ("nbsf-management", "pcf-mbs-bindings", "PATCH") if parts.len() >= 4 => {
            handle_pcf_mbs_binding_update(parts[3], &request).await
        }

        _ => {
            log::warn!("Unknown BSF request: {method} {uri}");
            send_method_not_allowed(method, uri)
        }
    }
}

// PCF Binding handlers

/// BSF-supported SBI feature bitmask (TS 29.521 Table 5.8-1, hex encoding).
/// Feature 1 = MultiUeAddr (bit 0 / 0x1, not supported); feature 2 =
/// BindingUpdate (bit 1 / 0x2, PATCH wired); feature 3 = SamePcf (bit 2 / 0x4,
/// duplicate detection, bsfd-07). BSF advertises BindingUpdate + SamePcf.
const BSF_SUPPORTED_FEATURES: u64 = 0x6;

/// SamePcf feature bit (TS 29.521 Table 5.8-1, feature 3 = bit 2).
const SAME_PCF_BIT: u64 = 0x4;

/// 400 ProblemDetails for a missing mandatory PcfBinding attribute.
fn missing_mandatory(attr: &str) -> SbiResponse {
    nextgcore_sbi::server::send_error(
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
/// pcfIpEndPoints).
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
    // bsfd-08: optional PCF identity / Diameter addressing fields
    if let Some(ref v) = sess.pcf_id {
        b.insert("pcfId".to_string(), serde_json::Value::String(v.clone()));
    }
    if let Some(ref v) = sess.pcf_set_id {
        b.insert("pcfSetId".to_string(), serde_json::Value::String(v.clone()));
    }
    if let Some(ref v) = sess.bind_level {
        b.insert(
            "bindLevel".to_string(),
            serde_json::Value::String(v.clone()),
        );
    }
    if let Some(ref v) = sess.recovery_time {
        b.insert(
            "recoveryTime".to_string(),
            serde_json::Value::String(v.clone()),
        );
    }
    if let Some(ref v) = sess.pcf_diam_host {
        b.insert(
            "pcfDiamHost".to_string(),
            serde_json::Value::String(v.clone()),
        );
    }
    if let Some(ref v) = sess.pcf_diam_realm {
        b.insert(
            "pcfDiamRealm".to_string(),
            serde_json::Value::String(v.clone()),
        );
    }
    // bsfd-06: echo the per-session negotiated suppFeat (consumer ∩ BSF-supported).
    // Omit when zero per the C cardinality (TS 29.521 §5.8).
    if sess.management_features != 0 {
        b.insert(
            "suppFeat".to_string(),
            serde_json::Value::String(format!("{:X}", sess.management_features)),
        );
    }
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
    // (MAC-only bindings for Ethernet PDU sessions are valid).
    let ipv4addr = binding_data.get("ipv4Addr").and_then(|v| v.as_str());
    let ipv6prefix = binding_data.get("ipv6Prefix").and_then(|v| v.as_str());
    let mac_addr48 = binding_data.get("macAddr48").and_then(|v| v.as_str());
    if ipv4addr.is_none() && ipv6prefix.is_none() && mac_addr48.is_none() {
        return missing_mandatory("ipv4Addr|ipv6Prefix|macAddr48");
    }
    if let Some(mac) = mac_addr48 {
        if context::normalize_mac(mac).is_none() {
            return nextgcore_sbi::server::send_error(
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
            return nextgcore_sbi::server::send_error(
                400,
                "Bad Request",
                &format!("expiry is not a valid RFC 3339 DateTime: {e}"),
                Some("MANDATORY_IE_INCORRECT"),
            );
        }
    }

    // bsfd-08: parse PCF address and identity attributes early (needed for
    // bsfd-05 mandatory check and bsfd-07 duplicate detection).
    let pcf_fqdn = binding_data.get("pcfFqdn").and_then(|v| v.as_str());
    let has_pcf_endpoints = binding_data
        .get("pcfIpEndPoints")
        .and_then(|v| v.as_array())
        .is_some_and(|a| !a.is_empty());
    let pcf_diam_host = binding_data.get("pcfDiamHost").and_then(|v| v.as_str());
    let pcf_diam_realm = binding_data.get("pcfDiamRealm").and_then(|v| v.as_str());
    let has_pcf_diam = pcf_diam_host.is_some() && pcf_diam_realm.is_some();
    let pcf_id_val = binding_data.get("pcfId").and_then(|v| v.as_str());
    let pcf_set_id_val = binding_data.get("pcfSetId").and_then(|v| v.as_str());
    let bind_level_val = binding_data.get("bindLevel").and_then(|v| v.as_str());
    let recovery_time_val = binding_data.get("recoveryTime").and_then(|v| v.as_str());

    // bsfd-05: a PcfBinding must carry at least one PCF address:
    // pcfFqdn, pcfIpEndPoints, or pcfDiamHost+pcfDiamRealm (Rx interface).
    if pcf_fqdn.is_none() && !has_pcf_endpoints && !has_pcf_diam {
        return missing_mandatory("pcfFqdn|pcfIpEndPoints");
    }

    // bsfd-06: negotiate suppFeat = consumer_requested ∩ BSF_SUPPORTED_FEATURES.
    let consumer_feat = binding_data
        .get("suppFeat")
        .and_then(|v| v.as_str())
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .unwrap_or(0);
    let negotiated_features = consumer_feat & BSF_SUPPORTED_FEATURES;

    // bsfd-07: SamePcf duplicate detection.
    // Only fires when the SamePcf feature was negotiated AND paraCom is present.
    if negotiated_features & SAME_PCF_BIT != 0 && binding_data.get("paraCom").is_some() {
        if let Some(supi_val) = binding_data.get("supi").and_then(|v| v.as_str()) {
            let check_sd = binding_data
                .get("snssai")
                .and_then(|s| s.get("sd"))
                .and_then(|v| v.as_str())
                .and_then(|s| u32::from_str_radix(s, 16).ok());
            let check_snssai = context::SNssai::new(sst as u8, check_sd);
            let dup = {
                let ctx = bsf_self();
                ctx.read()
                    .ok()
                    .and_then(|g| g.sess_find_by_dnn_snssai_supi(dnn, &check_snssai, supi_val))
            };
            if let Some(dup) = dup {
                let mut ext = serde_json::Map::new();
                ext.insert("status".to_string(), serde_json::json!(403));
                ext.insert(
                    "cause".to_string(),
                    serde_json::json!("EXISTING_BINDING_INFO_FOUND"),
                );
                if let Some(ref fqdn) = dup.pcf_fqdn {
                    ext.insert(
                        "pcfSmFqdn".to_string(),
                        serde_json::Value::String(fqdn.clone()),
                    );
                }
                if !dup.pcf_ip.is_empty() {
                    let eps: Vec<serde_json::Value> = dup
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
                    ext.insert(
                        "pcfSmIpEndPoints".to_string(),
                        serde_json::Value::Array(eps),
                    );
                }
                return SbiResponse::with_status(403)
                    .with_json_body(&serde_json::Value::Object(ext))
                    .unwrap_or_else(|_| SbiResponse::with_status(403));
            }
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
            // bsfd-06: store the negotiated suppFeat for this session.
            sess.management_features = negotiated_features;

            if let Some(v) = pcf_fqdn {
                sess.pcf_fqdn = Some(v.to_string());
            }
            if let Some(endpoints) = binding_data.get("pcfIpEndPoints") {
                sess.pcf_ip = parse_pcf_ip_endpoints(endpoints);
            }
            if let Some(e) = expiry {
                sess.set_expiry(e);
            }
            // bsfd-08: optional PCF identity and Diameter fields.
            if let Some(v) = pcf_id_val {
                sess.pcf_id = Some(v.to_string());
            }
            if let Some(v) = pcf_set_id_val {
                sess.pcf_set_id = Some(v.to_string());
            }
            if let Some(v) = bind_level_val {
                sess.bind_level = Some(v.to_string());
            }
            if let Some(v) = recovery_time_val {
                sess.recovery_time = Some(v.to_string());
            }
            if let Some(v) = pcf_diam_host {
                sess.pcf_diam_host = Some(v.to_string());
            }
            if let Some(v) = pcf_diam_realm {
                sess.pcf_diam_realm = Some(v.to_string());
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
    // TS 29.521 GET /pcfBindings query parameters (+ macAddr48, supi,
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

    // TS 29.521 §4.2.4.2: the query "shall include: UE address". A SUPI/GPSI- or
    // DNN-only query (no ipv4Addr/ipv6Prefix/macAddr48) is rejected 400.
    if !filter.has_ue_address() {
        return send_bad_request(
            "Discovery query must include a UE address (ipv4Addr, ipv6Prefix or macAddr48)",
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
        // TS 29.521 §4.2.4.2: no binding matching the query parameters -> 204 No
        // Content (empty body). 404 is reserved for an absent resource path.
        [] => SbiResponse::with_status(204),
        [sess] => {
            log::info!("PCF Binding found: {}", sess.binding_id);
            SbiResponse::with_status(200)
                .with_json_body(&binding_json(sess))
                .unwrap_or_else(|_| SbiResponse::with_status(200))
        }
        _ => nextgcore_sbi::server::send_error(
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

/// RFC 7396 merge-patch interpretation of a single attribute in a PATCH body.
enum Patch<'a> {
    /// JSON `null` present -> remove/clear the attribute.
    Clear,
    /// A concrete string value present -> set the attribute.
    Set(&'a str),
    /// Attribute absent (or a non-string, non-null value) -> leave unchanged.
    Keep,
}

/// Classify a string-valued attribute in a merge-patch document, distinguishing
/// JSON `null` (clear) from an absent key (no-op) per RFC 7396.
fn patch_str<'a>(data: &'a serde_json::Value, key: &str) -> Patch<'a> {
    match data.get(key) {
        Some(serde_json::Value::Null) => Patch::Clear,
        Some(serde_json::Value::String(s)) => Patch::Set(s),
        _ => Patch::Keep,
    }
}

/// TS 29.521 §5.2 requires the PATCH body to be encoded as JSON Merge Patch and
/// signalled by `application/merge-patch+json`. `application/json` is accepted
/// leniently for current consumers; any other media type is rejected 415.
/// An absent Content-Type is accepted (lenient).
fn merge_patch_content_type_ok(request: &SbiRequest) -> bool {
    match request.http.get_header("Content-Type") {
        None => true,
        Some(ct) => {
            let media = ct.split(';').next().unwrap_or(ct).trim();
            media.eq_ignore_ascii_case("application/merge-patch+json")
                || media.eq_ignore_ascii_case("application/json")
        }
    }
}

async fn handle_pcf_binding_update(binding_id: &str, request: &SbiRequest) -> SbiResponse {
    log::info!("PCF Binding Update (PATCH): {binding_id}");

    // TS 29.521 §5.2: validate the merge-patch Content-Type before any mutation.
    if !merge_patch_content_type_ok(request) {
        return nextgcore_sbi::server::send_error(
            415,
            "Unsupported Media Type",
            "PATCH body must be application/merge-patch+json",
            None,
        );
    }

    let body = match &request.http.content {
        Some(content) => content,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };

    let update_data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let ctx = bsf_self();

    // Apply the merge patch under the context read-guard, yielding the updated
    // session. The guard (which is `!Send`) is confined to this block so it is
    // released before the persistence `.await` below. Validation failures
    // `return` directly (no await is crossed on those paths).
    let sess = {
        let context = match ctx.read() {
            Ok(c) => c,
            Err(_) => {
                return nextgcore_sbi::server::send_error(
                    500,
                    "Internal Server Error",
                    "BSF context unavailable",
                    Some("SYSTEM_FAILURE"),
                )
            }
        };

        let Some(mut sess) = context.sess_find_by_binding_id(binding_id) else {
            return send_not_found(
                &format!("PCF Binding {binding_id} not found"),
                Some("BINDING_NOT_FOUND"),
            );
        };

        // pcfFqdn
        match patch_str(&update_data, "pcfFqdn") {
            Patch::Clear => sess.pcf_fqdn = None,
            Patch::Set(s) => sess.pcf_fqdn = Some(s.to_string()),
            Patch::Keep => {}
        }

        // UE addresses are routed through the context so the lookup hashes stay
        // consistent on both set and clear (bsfd-10). ipv4 null also clears
        // ipDomain inside the helper (TS 29.521 §4.2.5.2).
        match patch_str(&update_data, "ipv4Addr") {
            Patch::Clear => {
                context.set_ue_ipv4(&mut sess, None);
            }
            Patch::Set(s) => {
                if !context.set_ue_ipv4(&mut sess, Some(s)) {
                    return nextgcore_sbi::server::send_error(
                        400,
                        "Bad Request",
                        &format!("Invalid ipv4Addr: {s}"),
                        Some("MANDATORY_IE_INCORRECT"),
                    );
                }
            }
            Patch::Keep => {}
        }
        match patch_str(&update_data, "ipv6Prefix") {
            Patch::Clear => {
                context.set_ue_ipv6(&mut sess, None);
            }
            Patch::Set(s) => {
                if !context.set_ue_ipv6(&mut sess, Some(s)) {
                    return nextgcore_sbi::server::send_error(
                        400,
                        "Bad Request",
                        &format!("Invalid ipv6Prefix: {s}"),
                        Some("MANDATORY_IE_INCORRECT"),
                    );
                }
            }
            Patch::Keep => {}
        }
        match patch_str(&update_data, "macAddr48") {
            Patch::Clear => {
                context.set_ue_mac(&mut sess, None);
            }
            Patch::Set(s) => {
                if !context.set_ue_mac(&mut sess, Some(s)) {
                    return nextgcore_sbi::server::send_error(
                        400,
                        "Bad Request",
                        &format!("Invalid macAddr48: {s}"),
                        Some("MANDATORY_IE_INCORRECT"),
                    );
                }
            }
            Patch::Keep => {}
        }

        // ipDomain (an explicit value in the patch overrides the ipv4-null clear)
        match patch_str(&update_data, "ipDomain") {
            Patch::Clear => sess.ip_domain = None,
            Patch::Set(s) => sess.ip_domain = Some(s.to_string()),
            Patch::Keep => {}
        }

        // expiry
        match patch_str(&update_data, "expiry") {
            Patch::Clear => {
                sess.expiry = None;
                sess.expiry_epoch = None;
            }
            Patch::Set(s) => {
                if !sess.set_expiry(s) {
                    return nextgcore_sbi::server::send_error(
                        400,
                        "Bad Request",
                        &format!("expiry is not a valid RFC 3339 DateTime: {s}"),
                        Some("MANDATORY_IE_INCORRECT"),
                    );
                }
            }
            Patch::Keep => {}
        }

        // supi / gpsi
        match patch_str(&update_data, "supi") {
            Patch::Clear => sess.supi = None,
            Patch::Set(s) => sess.supi = Some(s.to_string()),
            Patch::Keep => {}
        }
        match patch_str(&update_data, "gpsi") {
            Patch::Clear => sess.gpsi = None,
            Patch::Set(s) => sess.gpsi = Some(s.to_string()),
            Patch::Keep => {}
        }

        // dnn is mandatory: only a concrete value is honored (a null is ignored).
        if let Patch::Set(s) = patch_str(&update_data, "dnn") {
            sess.dnn = Some(s.to_string());
        }

        // snssai (mandatory): apply only a concrete object.
        if let Some(snssai) = update_data.get("snssai") {
            if !snssai.is_null() {
                let sst = snssai.get("sst").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
                let sd = snssai
                    .get("sd")
                    .and_then(|v| v.as_str())
                    .and_then(|s| u32::from_str_radix(s, 16).ok());
                sess.s_nssai = context::SNssai::new(sst, sd);
            }
        }

        // Frame route lists: null -> clear, array -> replace, absent -> no-op.
        match update_data.get("ipv4FrameRouteList") {
            Some(serde_json::Value::Null) => sess.ipv4_frame_route_list.clear(),
            Some(serde_json::Value::Array(routes)) => {
                sess.ipv4_frame_route_list = routes
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
            }
            _ => {}
        }
        match update_data.get("ipv6FrameRouteList") {
            Some(serde_json::Value::Null) => sess.ipv6_frame_route_list.clear(),
            Some(serde_json::Value::Array(routes)) => {
                sess.ipv6_frame_route_list = routes
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
            }
            _ => {}
        }

        // pcfIpEndPoints: null -> clear, array -> replace, absent -> no-op.
        match update_data.get("pcfIpEndPoints") {
            Some(serde_json::Value::Null) => sess.pcf_ip.clear(),
            Some(v) if v.is_array() => sess.pcf_ip = parse_pcf_ip_endpoints(v),
            _ => {}
        }

        // bsfd-08: optional PCF identity / Diameter fields (clearable via null).
        match patch_str(&update_data, "pcfId") {
            Patch::Clear => sess.pcf_id = None,
            Patch::Set(s) => sess.pcf_id = Some(s.to_string()),
            Patch::Keep => {}
        }
        match patch_str(&update_data, "pcfSetId") {
            Patch::Clear => sess.pcf_set_id = None,
            Patch::Set(s) => sess.pcf_set_id = Some(s.to_string()),
            Patch::Keep => {}
        }
        match patch_str(&update_data, "bindLevel") {
            Patch::Clear => sess.bind_level = None,
            Patch::Set(s) => sess.bind_level = Some(s.to_string()),
            Patch::Keep => {}
        }
        match patch_str(&update_data, "recoveryTime") {
            Patch::Clear => sess.recovery_time = None,
            Patch::Set(s) => sess.recovery_time = Some(s.to_string()),
            Patch::Keep => {}
        }
        match patch_str(&update_data, "pcfDiamHost") {
            Patch::Clear => sess.pcf_diam_host = None,
            Patch::Set(s) => sess.pcf_diam_host = Some(s.to_string()),
            Patch::Keep => {}
        }
        match patch_str(&update_data, "pcfDiamRealm") {
            Patch::Clear => sess.pcf_diam_realm = None,
            Patch::Set(s) => sess.pcf_diam_realm = Some(s.to_string()),
            Patch::Keep => {}
        }

        // Write the updated session back; the context guard is released when
        // this block ends, before the persistence await.
        context.sess_update(&sess);
        sess
    };

    context::persist_binding_async(sess.clone()).await;

    log::info!("PCF Binding {binding_id} updated");

    SbiResponse::with_status(200)
        .with_json_body(&binding_json(&sess))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

// ---------------------------------------------------------------------------
// bsfd-11: pcf-ue-bindings resource (TS 29.521 §4.2.2.3/§4.2.4.3)
// ---------------------------------------------------------------------------

/// Build the PcfForUeBinding JSON representation of a UE binding.
fn ue_binding_json(b: &context::PcfUeBinding) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert(
        "pcfUeBindingId".to_string(),
        serde_json::Value::String(b.binding_id.clone()),
    );
    if let Some(ref v) = b.supi {
        m.insert("supi".to_string(), serde_json::Value::String(v.clone()));
    }
    if let Some(ref v) = b.gpsi {
        m.insert("gpsi".to_string(), serde_json::Value::String(v.clone()));
    }
    if let Some(ref v) = b.pcf_fqdn {
        m.insert("pcfFqdn".to_string(), serde_json::Value::String(v.clone()));
    }
    if !b.pcf_ip.is_empty() {
        let eps: Vec<serde_json::Value> = b
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
        m.insert("pcfIpEndPoints".to_string(), serde_json::Value::Array(eps));
    }
    if let Some(ref v) = b.pcf_id {
        m.insert("pcfId".to_string(), serde_json::Value::String(v.clone()));
    }
    if let Some(ref v) = b.pcf_set_id {
        m.insert("pcfSetId".to_string(), serde_json::Value::String(v.clone()));
    }
    if let Some(ref v) = b.bind_level {
        m.insert(
            "bindLevel".to_string(),
            serde_json::Value::String(v.clone()),
        );
    }
    if let Some(ref v) = b.recovery_time {
        m.insert(
            "recoveryTime".to_string(),
            serde_json::Value::String(v.clone()),
        );
    }
    if let Some(ref v) = b.pcf_diam_host {
        m.insert(
            "pcfDiamHost".to_string(),
            serde_json::Value::String(v.clone()),
        );
    }
    if let Some(ref v) = b.pcf_diam_realm {
        m.insert(
            "pcfDiamRealm".to_string(),
            serde_json::Value::String(v.clone()),
        );
    }
    if b.management_features != 0 {
        m.insert(
            "suppFeat".to_string(),
            serde_json::Value::String(format!("{:X}", b.management_features)),
        );
    }
    serde_json::Value::Object(m)
}

async fn handle_pcf_ue_binding_create(request: &SbiRequest) -> SbiResponse {
    log::info!("PCF UE Binding Create");
    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MANDATORY_IE_MISSING")),
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_MSG_FORMAT"))
        }
    };

    // Mandatory: supi or gpsi (UE identifier for UE-policy bindings).
    let supi = data.get("supi").and_then(|v| v.as_str());
    let gpsi = data.get("gpsi").and_then(|v| v.as_str());
    if supi.is_none() && gpsi.is_none() {
        return missing_mandatory("supi|gpsi");
    }

    // Mandatory: PCF address (same requirement as PDU-session binding, bsfd-05).
    let pcf_fqdn = data.get("pcfFqdn").and_then(|v| v.as_str());
    let has_eps = data
        .get("pcfIpEndPoints")
        .and_then(|v| v.as_array())
        .is_some_and(|a| !a.is_empty());
    let diam_host = data.get("pcfDiamHost").and_then(|v| v.as_str());
    let diam_realm = data.get("pcfDiamRealm").and_then(|v| v.as_str());
    if pcf_fqdn.is_none() && !has_eps && !(diam_host.is_some() && diam_realm.is_some()) {
        return missing_mandatory("pcfFqdn|pcfIpEndPoints");
    }

    let consumer_feat = data
        .get("suppFeat")
        .and_then(|v| v.as_str())
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .unwrap_or(0);
    let negotiated = consumer_feat & BSF_SUPPORTED_FEATURES;

    let binding_id = uuid::Uuid::new_v4().to_string();
    let binding = context::PcfUeBinding {
        binding_id: binding_id.clone(),
        supi: supi.map(|s| s.to_string()),
        gpsi: gpsi.map(|s| s.to_string()),
        pcf_fqdn: pcf_fqdn.map(|s| s.to_string()),
        pcf_ip: data
            .get("pcfIpEndPoints")
            .map(parse_pcf_ip_endpoints)
            .unwrap_or_default(),
        pcf_id: data
            .get("pcfId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        pcf_set_id: data
            .get("pcfSetId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        bind_level: data
            .get("bindLevel")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        recovery_time: data
            .get("recoveryTime")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        pcf_diam_host: diam_host.map(|s| s.to_string()),
        pcf_diam_realm: diam_realm.map(|s| s.to_string()),
        management_features: negotiated,
    };

    let ctx = bsf_self();
    if let Ok(context) = ctx.read() {
        context.ue_binding_add(binding.clone());
    }

    log::info!(
        "PCF UE Binding created (id={}, supi={:?}, gpsi={:?})",
        binding_id,
        supi,
        gpsi
    );

    SbiResponse::with_status(201)
        .with_header(
            "Location",
            format!("/nbsf-management/v1/pcf-ue-bindings/{binding_id}"),
        )
        .with_json_body(&ue_binding_json(&binding))
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

async fn handle_pcf_ue_binding_get(binding_id: &str) -> SbiResponse {
    let ctx = bsf_self();
    match ctx
        .read()
        .ok()
        .and_then(|g| g.ue_binding_find_by_id(binding_id))
    {
        Some(b) => SbiResponse::with_status(200)
            .with_json_body(&ue_binding_json(&b))
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("PCF UE Binding {binding_id} not found"),
            Some("BINDING_NOT_FOUND"),
        ),
    }
}

async fn handle_pcf_ue_binding_discovery(request: &SbiRequest) -> SbiResponse {
    let params = &request.http.params;
    let supi = params.get("supi").map(|s| s.as_str());
    let gpsi = params.get("gpsi").map(|s| s.as_str());

    if supi.is_none() && gpsi.is_none() {
        return send_bad_request(
            "Discovery query must include supi or gpsi",
            Some("MANDATORY_QUERY_PARAM_MISSING"),
        );
    }

    let ctx = bsf_self();
    let results = ctx
        .read()
        .map(|g| g.ue_binding_find_matching(supi, gpsi))
        .unwrap_or_default();

    if results.is_empty() {
        return SbiResponse::with_status(204);
    }

    let arr: Vec<serde_json::Value> = results.iter().map(ue_binding_json).collect();
    SbiResponse::with_status(200)
        .with_json_body(&serde_json::Value::Array(arr))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

async fn handle_pcf_ue_binding_delete(binding_id: &str) -> SbiResponse {
    let ctx = bsf_self();
    match ctx
        .read()
        .ok()
        .and_then(|g| g.ue_binding_remove(binding_id))
    {
        Some(_) => {
            log::info!("PCF UE Binding {binding_id} deleted");
            SbiResponse::with_status(204)
        }
        None => send_not_found(
            &format!("PCF UE Binding {binding_id} not found"),
            Some("BINDING_NOT_FOUND"),
        ),
    }
}

async fn handle_pcf_ue_binding_update(binding_id: &str, request: &SbiRequest) -> SbiResponse {
    if !merge_patch_content_type_ok(request) {
        return nextgcore_sbi::server::send_error(
            415,
            "Unsupported Media Type",
            "PATCH body must be application/merge-patch+json",
            None,
        );
    }
    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let ctx = bsf_self();
    let Some(mut b) = ctx
        .read()
        .ok()
        .and_then(|g| g.ue_binding_find_by_id(binding_id))
    else {
        return send_not_found(
            &format!("PCF UE Binding {binding_id} not found"),
            Some("BINDING_NOT_FOUND"),
        );
    };

    // Apply merge-patch: string fields (null = clear, string = set, absent = keep).
    macro_rules! patch_opt {
        ($field:expr, $key:expr) => {
            match patch_str(&data, $key) {
                Patch::Clear => $field = None,
                Patch::Set(s) => $field = Some(s.to_string()),
                Patch::Keep => {}
            }
        };
    }
    patch_opt!(b.pcf_fqdn, "pcfFqdn");
    patch_opt!(b.pcf_id, "pcfId");
    patch_opt!(b.pcf_set_id, "pcfSetId");
    patch_opt!(b.bind_level, "bindLevel");
    patch_opt!(b.recovery_time, "recoveryTime");
    patch_opt!(b.pcf_diam_host, "pcfDiamHost");
    patch_opt!(b.pcf_diam_realm, "pcfDiamRealm");
    match data.get("pcfIpEndPoints") {
        Some(serde_json::Value::Null) => b.pcf_ip.clear(),
        Some(v) if v.is_array() => b.pcf_ip = parse_pcf_ip_endpoints(v),
        _ => {}
    }

    if let Ok(g) = ctx.read() {
        g.ue_binding_update(&b);
    }

    SbiResponse::with_status(200)
        .with_json_body(&ue_binding_json(&b))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

// ---------------------------------------------------------------------------
// bsfd-12: pcf-mbs-bindings resource (TS 29.521 §4.2.2.4/§4.2.4.4)
// ---------------------------------------------------------------------------

/// Build the PcfMbsBinding JSON representation.
fn mbs_binding_json(b: &context::PcfMbsBinding) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert(
        "pcfMbsBindingId".to_string(),
        serde_json::Value::String(b.binding_id.clone()),
    );
    m.insert(
        "mbsSessionId".to_string(),
        serde_json::Value::String(b.mbs_session_id.clone()),
    );
    if let Some(ref v) = b.pcf_fqdn {
        m.insert("pcfFqdn".to_string(), serde_json::Value::String(v.clone()));
    }
    if !b.pcf_ip.is_empty() {
        let eps: Vec<serde_json::Value> = b
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
        m.insert("pcfIpEndPoints".to_string(), serde_json::Value::Array(eps));
    }
    if let Some(ref v) = b.pcf_id {
        m.insert("pcfId".to_string(), serde_json::Value::String(v.clone()));
    }
    if let Some(ref v) = b.pcf_set_id {
        m.insert("pcfSetId".to_string(), serde_json::Value::String(v.clone()));
    }
    if b.management_features != 0 {
        m.insert(
            "suppFeat".to_string(),
            serde_json::Value::String(format!("{:X}", b.management_features)),
        );
    }
    serde_json::Value::Object(m)
}

async fn handle_pcf_mbs_binding_create(request: &SbiRequest) -> SbiResponse {
    log::info!("PCF MBS Binding Create");
    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MANDATORY_IE_MISSING")),
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => {
            return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_MSG_FORMAT"))
        }
    };

    // Mandatory: mbsSessionId.
    let Some(mbs_session_id) = data.get("mbsSessionId").and_then(|v| v.as_str()) else {
        return missing_mandatory("mbsSessionId");
    };

    // Mandatory: PCF address.
    let pcf_fqdn = data.get("pcfFqdn").and_then(|v| v.as_str());
    let has_eps = data
        .get("pcfIpEndPoints")
        .and_then(|v| v.as_array())
        .is_some_and(|a| !a.is_empty());
    if pcf_fqdn.is_none() && !has_eps {
        return missing_mandatory("pcfFqdn|pcfIpEndPoints");
    }

    // bsfd-12: 403 if a binding with the same mbsSessionId already exists.
    let ctx = bsf_self();
    let existing = ctx
        .read()
        .map(|g| g.mbs_binding_find_by_mbs_session_id(mbs_session_id))
        .unwrap_or_default();
    if !existing.is_empty() {
        let first = &existing[0];
        let mut ext = serde_json::Map::new();
        ext.insert("status".to_string(), serde_json::json!(403));
        ext.insert(
            "cause".to_string(),
            serde_json::json!("EXISTING_BINDING_INFO_FOUND"),
        );
        if let Some(ref fqdn) = first.pcf_fqdn {
            ext.insert(
                "pcfSmFqdn".to_string(),
                serde_json::Value::String(fqdn.clone()),
            );
        }
        return SbiResponse::with_status(403)
            .with_json_body(&serde_json::Value::Object(ext))
            .unwrap_or_else(|_| SbiResponse::with_status(403));
    }

    let consumer_feat = data
        .get("suppFeat")
        .and_then(|v| v.as_str())
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .unwrap_or(0);

    let binding_id = uuid::Uuid::new_v4().to_string();
    let binding = context::PcfMbsBinding {
        binding_id: binding_id.clone(),
        mbs_session_id: mbs_session_id.to_string(),
        pcf_fqdn: pcf_fqdn.map(|s| s.to_string()),
        pcf_ip: data
            .get("pcfIpEndPoints")
            .map(parse_pcf_ip_endpoints)
            .unwrap_or_default(),
        pcf_id: data
            .get("pcfId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        pcf_set_id: data
            .get("pcfSetId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        management_features: consumer_feat & BSF_SUPPORTED_FEATURES,
    };

    if let Ok(g) = ctx.read() {
        g.mbs_binding_add(binding.clone());
    }

    log::info!(
        "PCF MBS Binding created (id={}, mbsSessionId={})",
        binding_id,
        mbs_session_id
    );

    SbiResponse::with_status(201)
        .with_header(
            "Location",
            format!("/nbsf-management/v1/pcf-mbs-bindings/{binding_id}"),
        )
        .with_json_body(&mbs_binding_json(&binding))
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

async fn handle_pcf_mbs_binding_get(binding_id: &str) -> SbiResponse {
    let ctx = bsf_self();
    match ctx
        .read()
        .ok()
        .and_then(|g| g.mbs_binding_find_by_id(binding_id))
    {
        Some(b) => SbiResponse::with_status(200)
            .with_json_body(&mbs_binding_json(&b))
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("PCF MBS Binding {binding_id} not found"),
            Some("BINDING_NOT_FOUND"),
        ),
    }
}

async fn handle_pcf_mbs_binding_discovery(request: &SbiRequest) -> SbiResponse {
    // TS 29.521 §4.2.4.4: the query parameter is `mbs-session-id`; accept the
    // legacy `mbsSessionId` spelling only as a lenient fallback.
    let Some(mbs_session_id) = request
        .http
        .params
        .get("mbs-session-id")
        .or_else(|| request.http.params.get("mbsSessionId"))
    else {
        return send_bad_request(
            "Discovery query must include mbs-session-id",
            Some("MANDATORY_QUERY_PARAM_MISSING"),
        );
    };

    let ctx = bsf_self();
    let results = ctx
        .read()
        .map(|g| g.mbs_binding_find_by_mbs_session_id(mbs_session_id))
        .unwrap_or_default();

    match results.as_slice() {
        [] => SbiResponse::with_status(204),
        [b] => SbiResponse::with_status(200)
            .with_json_body(&mbs_binding_json(b))
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        _ => nextgcore_sbi::server::send_error(
            400,
            "Bad Request",
            "Multiple MBS bindings match the query parameter combination",
            Some("MULTIPLE_BINDING_INFO_FOUND"),
        ),
    }
}

async fn handle_pcf_mbs_binding_delete(binding_id: &str) -> SbiResponse {
    let ctx = bsf_self();
    match ctx
        .read()
        .ok()
        .and_then(|g| g.mbs_binding_remove(binding_id))
    {
        Some(_) => {
            log::info!("PCF MBS Binding {binding_id} deleted");
            SbiResponse::with_status(204)
        }
        None => send_not_found(
            &format!("PCF MBS Binding {binding_id} not found"),
            Some("BINDING_NOT_FOUND"),
        ),
    }
}

async fn handle_pcf_mbs_binding_update(binding_id: &str, request: &SbiRequest) -> SbiResponse {
    if !merge_patch_content_type_ok(request) {
        return nextgcore_sbi::server::send_error(
            415,
            "Unsupported Media Type",
            "PATCH body must be application/merge-patch+json",
            None,
        );
    }
    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let ctx = bsf_self();
    let Some(mut b) = ctx
        .read()
        .ok()
        .and_then(|g| g.mbs_binding_find_by_id(binding_id))
    else {
        return send_not_found(
            &format!("PCF MBS Binding {binding_id} not found"),
            Some("BINDING_NOT_FOUND"),
        );
    };

    match patch_str(&data, "pcfFqdn") {
        Patch::Clear => b.pcf_fqdn = None,
        Patch::Set(s) => b.pcf_fqdn = Some(s.to_string()),
        Patch::Keep => {}
    }
    match patch_str(&data, "pcfId") {
        Patch::Clear => b.pcf_id = None,
        Patch::Set(s) => b.pcf_id = Some(s.to_string()),
        Patch::Keep => {}
    }
    match patch_str(&data, "pcfSetId") {
        Patch::Clear => b.pcf_set_id = None,
        Patch::Set(s) => b.pcf_set_id = Some(s.to_string()),
        Patch::Keep => {}
    }
    match data.get("pcfIpEndPoints") {
        Some(serde_json::Value::Null) => b.pcf_ip.clear(),
        Some(v) if v.is_array() => b.pcf_ip = parse_pcf_ip_endpoints(v),
        _ => {}
    }

    if let Ok(g) = ctx.read() {
        g.mbs_binding_update(&b);
    }

    SbiResponse::with_status(200)
        .with_json_body(&mbs_binding_json(&b))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
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
        let poll_interval = nextgcore_core::async_timer::compute_poll_interval(
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

        // Sweep bindings whose RFC 3339 expiry has passed (expired
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
    let sbi_ctx = nextgcore_sbi::context::global_context();

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

/// In-process strict-peer test support (Wave-6 H1 harness foundation).
///
/// Peer NF crates (e.g. `nextgcore-pcfd`) depend on this crate as a
/// dev-dependency and use this module to bring up the process-global BSF
/// context, then feed real consumer-built `SbiRequest`s into
/// [`bsf_sbi_request_handler`]. NOT for production use.
pub mod test_support {
    /// Initialize the process-global BSF context for in-process strict-peer
    /// tests (wraps `bsf_context_init`). The underlying init is tolerant of
    /// repeated calls, mirroring the crate's own unit-test usage.
    pub fn init_context(max_sess: usize) {
        crate::context::bsf_context_init(max_sess);
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

    use nextgcore_sbi::client::SbiClient;
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
        let server = SbiServer::new(NextgcoreSbiServerConfig::new(addr));
        server
            .start(bsf_sbi_request_handler)
            .await
            .expect("BSF SBI server starts");
        (server, SbiClient::with_host_port("127.0.0.1", addr.port()))
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
            "iss": "NRF", "sub": "pcf-1", "aud": aud,
            "scope": "nbsf-management", "exp": exp, "iat": 0
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

    /// Start a BSF SBI server with OAuth2 enforcement keyed to a static JWKS
    /// and the BSF audience.
    async fn start_bsf_oauth2(jwks: serde_json::Value) -> (SbiServer, SbiClient) {
        bsf_context_init(1024);
        let addr = ephemeral_addr();
        let mut cfg = NextgcoreSbiServerConfig::new(addr);
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(jwks);
        cfg = cfg.with_expected_audience_nf_type(NfType::Bsf);
        let server = SbiServer::new(cfg);
        server
            .start(bsf_sbi_request_handler)
            .await
            .expect("BSF SBI server starts");
        (server, SbiClient::with_host_port("127.0.0.1", addr.port()))
    }

    #[test]
    fn test_yaml_oauth2_require_parses() {
        let yaml = "bsf:\n  sbi:\n    oauth2:\n      require: true\n";
        let parsed: BsfYaml = serde_yaml::from_str(yaml).unwrap();
        let require = parsed
            .bsf
            .and_then(|b| b.sbi)
            .and_then(|s| s.oauth2)
            .and_then(|o| o.require)
            .unwrap_or(false);
        assert!(require, "oauth2.require should parse to true");
    }

    #[test]
    fn test_yaml_oauth2_absent_defaults_off() {
        let yaml = "bsf:\n  sbi:\n    server:\n      - address: 127.0.0.1\n        port: 7777\n";
        let parsed: BsfYaml = serde_yaml::from_str(yaml).unwrap();
        let require = parsed
            .bsf
            .and_then(|b| b.sbi)
            .and_then(|s| s.oauth2)
            .and_then(|o| o.require)
            .unwrap_or(false);
        assert!(!require, "absent oauth2 block must default to off");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_oauth2_missing_token_rejected() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let (server, client) = start_bsf_oauth2(jwks_for(&sk, "nrf-es256")).await;

        // No Authorization header -> 401.
        let resp = tokio::time::timeout(
            Duration::from_secs(5),
            client.get("/nbsf-management/v1/pcfBindings?ipv4Addr=10.45.9.1"),
        )
        .await
        .expect("bounded")
        .expect("response");
        assert_eq!(resp.status, 401, "unauthenticated request must be 401");

        server.stop().await.expect("stop");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_oauth2_valid_token_accepted() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let (server, client) = start_bsf_oauth2(jwks_for(&sk, "nrf-es256")).await;

        // Valid token whose aud includes "BSF" passes enforcement and reaches
        // the handler (a discovery miss is 204 No Content, NOT 401/403).
        let token = build_es256_token(&sk, "nrf-es256", "BSF");
        let req = SbiRequest::get("/nbsf-management/v1/pcfBindings?ipv4Addr=10.45.9.1")
            .with_header("Authorization", format!("Bearer {token}"));
        let resp = tokio::time::timeout(Duration::from_secs(5), client.send_request(req))
            .await
            .expect("bounded")
            .expect("response");
        assert_ne!(resp.status, 401, "valid token must not be 401");
        assert_ne!(resp.status, 403, "valid token must not be 403");
        assert_eq!(resp.status, 204, "request reached handler (discovery miss)");

        server.stop().await.expect("stop");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_oauth2_wrong_audience_rejected() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let (server, client) = start_bsf_oauth2(jwks_for(&sk, "nrf-es256")).await;

        // Token addressed to a different NF (aud="UDM") is rejected (401).
        let token = build_es256_token(&sk, "nrf-es256", "UDM");
        let req = SbiRequest::get("/nbsf-management/v1/pcfBindings?ipv4Addr=10.45.9.1")
            .with_header("Authorization", format!("Bearer {token}"));
        let resp = tokio::time::timeout(Duration::from_secs(5), client.send_request(req))
            .await
            .expect("bounded")
            .expect("response");
        assert_eq!(resp.status, 401, "wrong-audience token must be 401");

        server.stop().await.expect("stop");
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
                    "supi": "imsi-001019900100001",
                    "pcfFqdn": "pcf.ims.example.com"
                }),
            )
            .await
            .expect("POST second");
        assert_eq!(resp.status, 201);
        let second_body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let second_id = second_body["pcfBindingId"].as_str().unwrap().to_string();

        // Third binding sharing the SAME UE IPv4 address as the second (on yet
        // another DNN), to exercise the multiple-match path with a UE address.
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcfBindings",
                &json!({
                    "dnn": "internet2",
                    "snssai": {"sst": 1},
                    "ipv4Addr": "10.45.9.7",
                    "supi": "imsi-001019900100001",
                    "pcfFqdn": "pcf.internet2.example.com"
                }),
            )
            .await
            .expect("POST third");
        assert_eq!(resp.status, 201);
        let third_body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let third_id = third_body["pcfBindingId"].as_str().unwrap().to_string();

        // Discovery without any UE address -> 400 MANDATORY_QUERY_PARAM_MISSING.
        let req = SbiRequest::get("/nbsf-management/v1/pcfBindings");
        let resp = client.send_request(req).await.expect("discover none");
        assert_eq!(resp.status, 400);
        assert_eq!(problem(&resp)["cause"], "MANDATORY_QUERY_PARAM_MISSING");

        // Discovery by MAC (different separator/case) -> the MAC binding.
        let mut req = SbiRequest::get("/nbsf-management/v1/pcfBindings");
        req.http.set_param("macAddr48", "aa-bb-cc-00-11-22");
        let resp = client.send_request(req).await.expect("discover mac");
        assert_eq!(resp.status, 200);
        let found: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(found["pcfBindingId"].as_str().unwrap(), binding_id);
        assert_eq!(found["pcfIpEndPoints"][0]["port"], 7777);

        // Discovery by SUPI alone (no UE address) -> 400 MANDATORY_QUERY_PARAM_MISSING.
        let mut req = SbiRequest::get("/nbsf-management/v1/pcfBindings");
        req.http.set_param("supi", "imsi-001019900100001");
        let resp = client.send_request(req).await.expect("discover supi");
        assert_eq!(resp.status, 400);
        assert_eq!(problem(&resp)["cause"], "MANDATORY_QUERY_PARAM_MISSING");

        // Discovery by the shared ipv4Addr alone -> two matches -> 400 MULTIPLE.
        let mut req = SbiRequest::get("/nbsf-management/v1/pcfBindings");
        req.http.set_param("ipv4Addr", "10.45.9.7");
        let resp = client.send_request(req).await.expect("discover ipv4 multi");
        assert_eq!(resp.status, 400);
        assert_eq!(problem(&resp)["cause"], "MULTIPLE_BINDING_INFO_FOUND");

        // Discovery by ipv4Addr + DNN narrows to a single binding (200).
        let mut req = SbiRequest::get("/nbsf-management/v1/pcfBindings");
        req.http.set_param("ipv4Addr", "10.45.9.7");
        req.http.set_param("dnn", "ims");
        let resp = client.send_request(req).await.expect("discover ipv4+dnn");
        assert_eq!(resp.status, 200);
        let found: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(found["pcfBindingId"].as_str().unwrap(), second_id);

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
                    "expiry": "2000-01-01T00:00:00Z",
                    "pcfFqdn": "pcf.expired.example.com"
                }),
            )
            .await
            .expect("POST expired");
        assert_eq!(resp.status, 201);
        let mut req = SbiRequest::get("/nbsf-management/v1/pcfBindings");
        req.http.set_param("ipv4Addr", "10.45.9.99");
        let resp = client.send_request(req).await.expect("discover expired");
        // No matching (live) binding for a valid UE address -> 204 No Content.
        assert_eq!(resp.status, 204);
        assert!(resp.http.content.as_deref().unwrap_or("").is_empty());

        // DELETE all live bindings -> 204; GET -> 404 afterwards.
        for id in [&binding_id, &second_id, &third_id] {
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

    /// bsfd-02: discovery must carry a UE address; a SUPI/GPSI-only query is
    /// rejected 400 MANDATORY_QUERY_PARAM_MISSING, while a UE-address query is
    /// accepted (and a clean miss returns 204, not 400/404).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_discovery_requires_ue_address() {
        let (server, client) = start_bsf().await;

        // SUPI only -> 400 MANDATORY_QUERY_PARAM_MISSING.
        let mut req = SbiRequest::get("/nbsf-management/v1/pcfBindings");
        req.http.set_param("supi", "imsi-001019900177701");
        let resp = client.send_request(req).await.expect("discover supi-only");
        assert_eq!(resp.status, 400);
        assert_eq!(problem(&resp)["cause"], "MANDATORY_QUERY_PARAM_MISSING");

        // GPSI only -> 400 as well.
        let mut req = SbiRequest::get("/nbsf-management/v1/pcfBindings");
        req.http.set_param("gpsi", "msisdn-7770000");
        let resp = client.send_request(req).await.expect("discover gpsi-only");
        assert_eq!(resp.status, 400);
        assert_eq!(problem(&resp)["cause"], "MANDATORY_QUERY_PARAM_MISSING");

        // A UE address (ipv4) with no matching binding -> 204 (not 400/404).
        let mut req = SbiRequest::get("/nbsf-management/v1/pcfBindings");
        req.http.set_param("ipv4Addr", "10.77.0.1");
        let resp = client.send_request(req).await.expect("discover ipv4 miss");
        assert_eq!(resp.status, 204);

        server.stop().await.expect("server stops");
    }

    /// bsfd-01: a discovery with a valid UE address that matches no binding
    /// returns 204 No Content with an empty body.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_discovery_no_match_returns_204() {
        let (server, client) = start_bsf().await;

        let mut req = SbiRequest::get("/nbsf-management/v1/pcfBindings");
        req.http.set_param("ipv4Addr", "10.77.0.2");
        let resp = client.send_request(req).await.expect("discover miss");
        assert_eq!(resp.status, 204);
        assert!(resp.http.content.as_deref().unwrap_or("").is_empty());

        server.stop().await.expect("server stops");
    }

    /// bsfd-03: IPv6 longest-prefix containment match over HTTP (a /128 query
    /// inside a stored /64 prefix returns that binding).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_discovery_ipv6_prefix_match() {
        let (server, client) = start_bsf().await;

        let resp = client
            .post_json(
                "/nbsf-management/v1/pcfBindings",
                &json!({
                    "dnn": "internet",
                    "snssai": {"sst": 1},
                    "ipv6Prefix": "2001:dba::/64",
                    "supi": "imsi-001019900166601",
                    "pcfFqdn": "pcf.ipv6.example.com"
                }),
            )
            .await
            .expect("POST ipv6");
        assert_eq!(resp.status, 201);
        let created: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let id = created["pcfBindingId"].as_str().unwrap().to_string();

        // Bare in-prefix address matches the stored /64.
        let mut req = SbiRequest::get("/nbsf-management/v1/pcfBindings");
        req.http.set_param("ipv6Prefix", "2001:dba::1");
        let resp = client.send_request(req).await.expect("discover ipv6 in");
        assert_eq!(resp.status, 200);
        let found: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(found["pcfBindingId"].as_str().unwrap(), id);

        // Out-of-prefix address -> 204.
        let mut req = SbiRequest::get("/nbsf-management/v1/pcfBindings");
        req.http.set_param("ipv6Prefix", "2001:dbb::1");
        let resp = client.send_request(req).await.expect("discover ipv6 out");
        assert_eq!(resp.status, 204);

        client
            .delete(&format!("/nbsf-management/v1/pcfBindings/{id}"))
            .await
            .expect("DELETE ipv6");

        server.stop().await.expect("server stops");
    }

    /// bsfd-04: PATCH JSON Merge Patch null-removal clears the attribute and its
    /// dependent hash index (old-address discovery then returns 204), ipv4 null
    /// also clears ipDomain, and a non-merge-patch Content-Type is rejected 415.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_patch_null_removal_and_content_type() {
        let (server, client) = start_bsf().await;

        // Create a binding with ipv4Addr + ipDomain + macAddr48.
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcfBindings",
                &json!({
                    "dnn": "internet",
                    "snssai": {"sst": 1},
                    "ipv4Addr": "10.88.0.1",
                    "ipDomain": "domain-x",
                    "macAddr48": "AA:BB:CC:88:00:01",
                    "supi": "imsi-001019900188801",
                    "pcfFqdn": "pcf.patch.example.com"
                }),
            )
            .await
            .expect("POST patchable");
        assert_eq!(resp.status, 201);
        let created: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let id = created["pcfBindingId"].as_str().unwrap().to_string();
        assert_eq!(created["ipDomain"], "domain-x");

        // text/plain Content-Type is rejected 415 (before any mutation).
        let mut req = SbiRequest::patch(format!("/nbsf-management/v1/pcfBindings/{id}"));
        req.http.set_content(json!({"ipv4Addr": null}).to_string());
        req.http.set_header("Content-Type", "text/plain");
        let resp = client.send_request(req).await.expect("PATCH wrong CT");
        assert_eq!(resp.status, 415);

        // merge-patch+json Content-Type is accepted: clear ipv4Addr.
        let mut req = SbiRequest::patch(format!("/nbsf-management/v1/pcfBindings/{id}"));
        req.http.set_content(json!({"ipv4Addr": null}).to_string());
        req.http
            .set_header("Content-Type", "application/merge-patch+json");
        let resp = client.send_request(req).await.expect("PATCH ipv4 null");
        assert_eq!(resp.status, 200);
        let patched: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        // ipv4Addr and the dependent ipDomain are both gone.
        assert!(patched.get("ipv4Addr").is_none());
        assert!(patched.get("ipDomain").is_none());

        // GET confirms removal persisted.
        let resp = client
            .get(&format!("/nbsf-management/v1/pcfBindings/{id}"))
            .await
            .expect("GET after ipv4 null");
        let got: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(got.get("ipv4Addr").is_none());
        assert!(got.get("ipDomain").is_none());

        // Discovery by the now-removed ipv4 address -> 204 (hash re-keyed).
        let mut req = SbiRequest::get("/nbsf-management/v1/pcfBindings");
        req.http.set_param("ipv4Addr", "10.88.0.1");
        let resp = client
            .send_request(req)
            .await
            .expect("discover removed ipv4");
        assert_eq!(resp.status, 204);

        // PATCH macAddr48 null removes the MAC and clears the mac hash.
        let mut req = SbiRequest::patch(format!("/nbsf-management/v1/pcfBindings/{id}"));
        req.http.set_content(json!({"macAddr48": null}).to_string());
        req.http
            .set_header("Content-Type", "application/merge-patch+json");
        let resp = client.send_request(req).await.expect("PATCH mac null");
        assert_eq!(resp.status, 200);
        let mut req = SbiRequest::get("/nbsf-management/v1/pcfBindings");
        req.http.set_param("macAddr48", "aa-bb-cc-88-00-01");
        let resp = client
            .send_request(req)
            .await
            .expect("discover removed mac");
        assert_eq!(resp.status, 204);

        client
            .delete(&format!("/nbsf-management/v1/pcfBindings/{id}"))
            .await
            .expect("DELETE patchable");

        server.stop().await.expect("server stops");
    }

    // bsfd-05: mandatory PCF address on Register
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_create_rejects_missing_pcf_address() {
        let (server, client) = start_bsf().await;

        // No PCF address at all → 400 MANDATORY_IE_MISSING.
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcfBindings",
                &json!({
                    "dnn": "internet",
                    "snssai": {"sst": 1},
                    "ipv4Addr": "10.45.5.1"
                }),
            )
            .await
            .expect("POST no pcf addr");
        assert_eq!(resp.status, 400);
        assert_eq!(problem(&resp)["cause"], "MANDATORY_IE_MISSING");
        assert!(problem(&resp)["detail"]
            .as_str()
            .unwrap()
            .contains("pcfFqdn"));

        // pcfFqdn only → 201 (sufficient).
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcfBindings",
                &json!({
                    "dnn": "internet",
                    "snssai": {"sst": 1},
                    "ipv4Addr": "10.45.5.2",
                    "pcfFqdn": "pcf.example.com"
                }),
            )
            .await
            .expect("POST pcfFqdn only");
        assert_eq!(resp.status, 201);

        // pcfDiamHost + pcfDiamRealm only (Rx) → 201.
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcfBindings",
                &json!({
                    "dnn": "internet",
                    "snssai": {"sst": 1},
                    "ipv4Addr": "10.45.5.3",
                    "pcfDiamHost": "pcf.diam.example.com",
                    "pcfDiamRealm": "example.com"
                }),
            )
            .await
            .expect("POST Diameter addr");
        assert_eq!(resp.status, 201);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["pcfDiamHost"], "pcf.diam.example.com");
        assert_eq!(body["pcfDiamRealm"], "example.com");

        server.stop().await.expect("server stops");
    }

    // bsfd-06: suppFeat negotiation — intersection returned, absent → omitted
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_supp_feat_negotiation() {
        let (server, client) = start_bsf().await;

        // Consumer sends "6" (BindingUpdate+SamePcf), BSF supports 0x6 → "6".
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcfBindings",
                &json!({
                    "dnn": "internet",
                    "snssai": {"sst": 1},
                    "ipv4Addr": "10.45.6.1",
                    "pcfFqdn": "pcf.example.com",
                    "suppFeat": "6"
                }),
            )
            .await
            .expect("POST suppFeat 6");
        assert_eq!(resp.status, 201);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["suppFeat"], "6", "intersection of 6 & 6 = 6");

        // Consumer sends "F" (all low bits), BSF supports 0x6 → echoed "6".
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcfBindings",
                &json!({
                    "dnn": "internet",
                    "snssai": {"sst": 1},
                    "ipv4Addr": "10.45.6.2",
                    "pcfFqdn": "pcf.example.com",
                    "suppFeat": "F"
                }),
            )
            .await
            .expect("POST suppFeat F");
        assert_eq!(resp.status, 201);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["suppFeat"], "6", "intersection of F & 6 = 6");

        // No suppFeat sent → intersection = 0 → suppFeat omitted from response.
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcfBindings",
                &json!({
                    "dnn": "internet",
                    "snssai": {"sst": 1},
                    "ipv4Addr": "10.45.6.3",
                    "pcfFqdn": "pcf.example.com"
                }),
            )
            .await
            .expect("POST no suppFeat");
        assert_eq!(resp.status, 201);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(
            body.get("suppFeat").is_none(),
            "absent consumer suppFeat → omitted (intersection = 0)"
        );

        server.stop().await.expect("server stops");
    }

    // bsfd-07: SamePcf duplicate detection → 403 EXISTING_BINDING_INFO_FOUND
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_same_pcf_duplicate_detection() {
        let (server, client) = start_bsf().await;

        // Create binding A (dnn + snssai + supi).
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcfBindings",
                &json!({
                    "dnn": "internet",
                    "snssai": {"sst": 1},
                    "ipv4Addr": "10.45.7.1",
                    "supi": "imsi-001019900700001",
                    "pcfFqdn": "pcf-a.example.com",
                    "suppFeat": "4"
                }),
            )
            .await
            .expect("POST binding A");
        assert_eq!(resp.status, 201);

        // POST B: same dnn+snssai+supi + paraCom + SamePcf negotiated → 403.
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcfBindings",
                &json!({
                    "dnn": "internet",
                    "snssai": {"sst": 1},
                    "ipv4Addr": "10.45.7.2",
                    "supi": "imsi-001019900700001",
                    "pcfFqdn": "pcf-b.example.com",
                    "suppFeat": "4",
                    "paraCom": {}
                }),
            )
            .await
            .expect("POST binding B duplicate");
        assert_eq!(resp.status, 403);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "EXISTING_BINDING_INFO_FOUND");
        assert_eq!(
            body["pcfSmFqdn"], "pcf-a.example.com",
            "existing PCF address echoed"
        );

        // Without SamePcf feature negotiated (suppFeat absent → 0): no 403.
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcfBindings",
                &json!({
                    "dnn": "internet",
                    "snssai": {"sst": 1},
                    "ipv4Addr": "10.45.7.2",
                    "supi": "imsi-001019900700001",
                    "pcfFqdn": "pcf-b.example.com",
                    "paraCom": {}
                }),
            )
            .await
            .expect("POST without SamePcf");
        assert_ne!(
            resp.status, 403,
            "SamePcf not negotiated → no duplicate 403"
        );

        server.stop().await.expect("server stops");
    }

    // bsfd-08: pcfId/pcfSetId/bindLevel/recoveryTime/pcfDiamHost/pcfDiamRealm stored + echoed
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_pcf_identity_fields_stored_and_echoed() {
        let (server, client) = start_bsf().await;

        let resp = client
            .post_json(
                "/nbsf-management/v1/pcfBindings",
                &json!({
                    "dnn": "internet",
                    "snssai": {"sst": 1},
                    "ipv4Addr": "10.45.8.1",
                    "pcfFqdn": "pcf.example.com",
                    "pcfId": "pcf-uuid-abcd",
                    "pcfSetId": "pcfSet-01",
                    "bindLevel": "NF_INSTANCE",
                    "recoveryTime": "2026-06-01T00:00:00Z"
                }),
            )
            .await
            .expect("POST with identity fields");
        assert_eq!(resp.status, 201);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let id = body["pcfBindingId"].as_str().unwrap().to_string();
        assert_eq!(body["pcfId"], "pcf-uuid-abcd");
        assert_eq!(body["pcfSetId"], "pcfSet-01");
        assert_eq!(body["bindLevel"], "NF_INSTANCE");
        assert_eq!(body["recoveryTime"], "2026-06-01T00:00:00Z");

        // GET by id echoes them too.
        let resp = client
            .get(&format!("/nbsf-management/v1/pcfBindings/{id}"))
            .await
            .expect("GET identity");
        assert_eq!(resp.status, 200);
        let got: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(got["pcfId"], "pcf-uuid-abcd");
        assert_eq!(got["bindLevel"], "NF_INSTANCE");

        // PATCH clears pcfId (null remove).
        let mut req = SbiRequest::patch(format!("/nbsf-management/v1/pcfBindings/{id}"));
        req.http.set_content(json!({"pcfId": null}).to_string());
        req.http
            .set_header("Content-Type", "application/merge-patch+json");
        let resp = client.send_request(req).await.expect("PATCH pcfId null");
        assert_eq!(resp.status, 200);
        let patched: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(
            patched.get("pcfId").is_none(),
            "pcfId cleared by null patch"
        );

        server.stop().await.expect("server stops");
    }

    // bsfd-11: pcf-ue-bindings full CRUD lifecycle
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_pcf_ue_bindings_lifecycle() {
        let (server, client) = start_bsf().await;

        // POST without supi|gpsi → 400.
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcf-ue-bindings",
                &json!({"pcfFqdn": "pcf.example.com"}),
            )
            .await
            .expect("POST ue no identity");
        assert_eq!(resp.status, 400);
        assert_eq!(problem(&resp)["cause"], "MANDATORY_IE_MISSING");

        // POST without PCF address → 400.
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcf-ue-bindings",
                &json!({"supi": "imsi-001019900111001"}),
            )
            .await
            .expect("POST ue no pcf addr");
        assert_eq!(resp.status, 400);
        assert_eq!(problem(&resp)["cause"], "MANDATORY_IE_MISSING");

        // Valid POST → 201 + Location.
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcf-ue-bindings",
                &json!({
                    "supi": "imsi-001019900111001",
                    "pcfFqdn": "pcf.ue.example.com",
                    "suppFeat": "2"
                }),
            )
            .await
            .expect("POST ue binding");
        assert_eq!(resp.status, 201);
        let location = resp.http.get_header("Location").expect("Location").clone();
        let ue_id = location.rsplit('/').next().unwrap().to_string();
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["supi"], "imsi-001019900111001");
        assert_eq!(body["pcfFqdn"], "pcf.ue.example.com");
        assert_eq!(body["suppFeat"], "2");

        // GET by id → 200.
        let resp = client
            .get(&format!("/nbsf-management/v1/pcf-ue-bindings/{ue_id}"))
            .await
            .expect("GET ue binding");
        assert_eq!(resp.status, 200);

        // Discovery by supi → 200 with array.
        let mut req = SbiRequest::get("/nbsf-management/v1/pcf-ue-bindings");
        req.http.set_param("supi", "imsi-001019900111001");
        let resp = client.send_request(req).await.expect("discover ue supi");
        assert_eq!(resp.status, 200);
        let arr: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert!(arr.as_array().is_some_and(|a| a.len() == 1));

        // Discovery without supi|gpsi → 400.
        let req = SbiRequest::get("/nbsf-management/v1/pcf-ue-bindings");
        let resp = client
            .send_request(req)
            .await
            .expect("discover ue no filter");
        assert_eq!(resp.status, 400);
        assert_eq!(problem(&resp)["cause"], "MANDATORY_QUERY_PARAM_MISSING");

        // PATCH pcfFqdn → 200.
        let mut req = SbiRequest::patch(format!("/nbsf-management/v1/pcf-ue-bindings/{ue_id}"));
        req.http
            .set_content(json!({"pcfFqdn": "pcf.ue2.example.com"}).to_string());
        req.http
            .set_header("Content-Type", "application/merge-patch+json");
        let resp = client.send_request(req).await.expect("PATCH ue");
        assert_eq!(resp.status, 200);
        let patched: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(patched["pcfFqdn"], "pcf.ue2.example.com");

        // DELETE → 204; GET → 404 afterwards.
        let resp = client
            .delete(&format!("/nbsf-management/v1/pcf-ue-bindings/{ue_id}"))
            .await
            .expect("DELETE ue");
        assert_eq!(resp.status, 204);
        let resp = client
            .get(&format!("/nbsf-management/v1/pcf-ue-bindings/{ue_id}"))
            .await
            .expect("GET deleted ue");
        assert_eq!(resp.status, 404);

        // Discovery after delete → 204 (empty).
        let mut req = SbiRequest::get("/nbsf-management/v1/pcf-ue-bindings");
        req.http.set_param("supi", "imsi-001019900111001");
        let resp = client
            .send_request(req)
            .await
            .expect("discover ue after delete");
        assert_eq!(resp.status, 204);

        server.stop().await.expect("server stops");
    }

    // bsfd-12: pcf-mbs-bindings lifecycle + duplicate 403 + multi-match 400
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_pcf_mbs_bindings_lifecycle() {
        let (server, client) = start_bsf().await;

        // POST without mbsSessionId → 400.
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcf-mbs-bindings",
                &json!({"pcfFqdn": "pcf.example.com"}),
            )
            .await
            .expect("POST mbs no mbsSessionId");
        assert_eq!(resp.status, 400);
        assert_eq!(problem(&resp)["cause"], "MANDATORY_IE_MISSING");

        // POST without PCF address → 400.
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcf-mbs-bindings",
                &json!({"mbsSessionId": "TMGI-001"}),
            )
            .await
            .expect("POST mbs no pcf");
        assert_eq!(resp.status, 400);
        assert_eq!(problem(&resp)["cause"], "MANDATORY_IE_MISSING");

        // Valid POST → 201.
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcf-mbs-bindings",
                &json!({
                    "mbsSessionId": "TMGI-001",
                    "pcfFqdn": "pcf.mbs.example.com"
                }),
            )
            .await
            .expect("POST mbs binding");
        assert_eq!(resp.status, 201);
        let loc = resp.http.get_header("Location").expect("Location").clone();
        let mbs_id = loc.rsplit('/').next().unwrap().to_string();
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["mbsSessionId"], "TMGI-001");

        // Duplicate mbsSessionId → 403 EXISTING_BINDING_INFO_FOUND.
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcf-mbs-bindings",
                &json!({
                    "mbsSessionId": "TMGI-001",
                    "pcfFqdn": "pcf.mbs2.example.com"
                }),
            )
            .await
            .expect("POST mbs duplicate");
        assert_eq!(resp.status, 403);
        let body: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "EXISTING_BINDING_INFO_FOUND");

        // Discovery by mbsSessionId → 200 single result.
        let mut req = SbiRequest::get("/nbsf-management/v1/pcf-mbs-bindings");
        req.http.set_param("mbsSessionId", "TMGI-001");
        let resp = client.send_request(req).await.expect("discover mbs");
        assert_eq!(resp.status, 200);

        // Discovery without mbsSessionId → 400.
        let req = SbiRequest::get("/nbsf-management/v1/pcf-mbs-bindings");
        let resp = client
            .send_request(req)
            .await
            .expect("discover mbs no filter");
        assert_eq!(resp.status, 400);
        assert_eq!(problem(&resp)["cause"], "MANDATORY_QUERY_PARAM_MISSING");

        // Unknown mbsSessionId → 204.
        let mut req = SbiRequest::get("/nbsf-management/v1/pcf-mbs-bindings");
        req.http.set_param("mbsSessionId", "TMGI-999");
        let resp = client.send_request(req).await.expect("discover mbs miss");
        assert_eq!(resp.status, 204);

        // PATCH → 200.
        let mut req = SbiRequest::patch(format!("/nbsf-management/v1/pcf-mbs-bindings/{mbs_id}"));
        req.http
            .set_content(json!({"pcfFqdn": "pcf.mbs-patched.example.com"}).to_string());
        req.http
            .set_header("Content-Type", "application/merge-patch+json");
        let resp = client.send_request(req).await.expect("PATCH mbs");
        assert_eq!(resp.status, 200);
        let patched: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(patched["pcfFqdn"], "pcf.mbs-patched.example.com");

        // DELETE → 204; GET → 404.
        let resp = client
            .delete(&format!("/nbsf-management/v1/pcf-mbs-bindings/{mbs_id}"))
            .await
            .expect("DELETE mbs");
        assert_eq!(resp.status, 204);
        let resp = client
            .get(&format!("/nbsf-management/v1/pcf-mbs-bindings/{mbs_id}"))
            .await
            .expect("GET deleted mbs");
        assert_eq!(resp.status, 404);

        server.stop().await.expect("server stops");
    }

    // bsfd-13: Subscribe/Unsubscribe stub returns 501 Not Implemented.
    // GAP: Notify callback fanout is not implemented; the BSF does not advertise
    // Subscribe feature bits in BSF_SUPPORTED_FEATURES. This stub documents the
    // gap for future implementation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_http_subscription_stub_not_implemented() {
        let (server, client) = start_bsf().await;

        // POST to the subscriptions sub-resource → 501.
        let resp = client
            .post_json(
                "/nbsf-management/v1/pcfBindings/1/subscriptions",
                &json!({
                    "notifUri": "http://smf.example.com/notify",
                    "monResUri": "http://bsf/pcfBindings/1"
                }),
            )
            .await
            .expect("POST subscription");
        assert_eq!(
            resp.status, 501,
            "bsfd-13: Subscribe is a stub (not implemented)"
        );

        server.stop().await.expect("server stops");
    }
}
