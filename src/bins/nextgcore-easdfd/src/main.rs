//! NextGCore EASDF — Edge Application Server Discovery Function
//! (TS 23.548 §6.2; service API TS 29.556).
//!
//! Phase 1 (issue #21): a control-plane EASDF that registers with the NRF
//! as `nfType: EASDF` advertising `neasdf-dnscontext`, and serves:
//!
//! - **Neasdf_DNSContext** (TS 29.556, minimal subset):
//!   `POST /neasdf-dnscontext/v1/dns-contexts` (Create, 201 + Location),
//!   `PUT /neasdf-dnscontext/v1/dns-contexts/{ctxId}` (Update as full
//!   replace — the spec's json-patch Update is simplified, mirroring
//!   udmd's `handle_ee_modify` stance), and
//!   `DELETE /neasdf-dnscontext/v1/dns-contexts/{ctxId}` (204).
//! - **Edge DNS resolution** over SBI:
//!   `GET /neasdf-dnscontext/v1/dns-queries?fqdn=<name>` answers from a
//!   static FQDN → EAS-address map loaded from the YAML config; a miss
//!   either reports the configured upstream DNS server (`FORWARD`) or a
//!   404 (`FQDN_NOT_FOUND`). Phase 1 has NO UDP/53 DNS listener — DNS
//!   arrives over the SBI binding only.
//!
//! Off by default: the NF exits immediately unless enabled via `--enabled`
//! or `easdf.enabled: true` in the YAML config (and, like every NF binary,
//! it is inert unless deployed).
//!
//! Distinct from `nextgcore-eesd`: the EES is the SA6 application-layer
//! Edge Enabler Server of TS 23.558, not this 5GC NF.
//!
//! Deferred per issue #21 (follow-ups): SMF UL-CL / branching-point
//! insertion, PCF traffic-influence rules, latency-aware UPF/PSA
//! selection, and DNS message-handling-rule enforcement.

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_sbi::context::SbiContext;
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::{
    send_bad_request, send_error, send_internal_error, send_method_not_allowed, send_not_found,
    SbiServer, SbiServerConfig,
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod context;

pub use context::*;

/// NextGCore EASDF - Edge Application Server Discovery Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-easdfd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Edge Application Server Discovery Function (TS 23.548)", long_about = None)]
struct Args {
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/easdf.yaml")]
    config: String,

    #[arg(short = 'l', long)]
    log_file: Option<String>,

    #[arg(short = 'e', long, default_value = "info")]
    log_level: String,

    #[arg(short = 'm', long)]
    no_color: bool,

    #[arg(long, default_value = "0.0.0.0")]
    sbi_addr: String,

    #[arg(long, default_value = "7818")]
    sbi_port: u16,

    #[arg(long)]
    tls: bool,

    #[arg(long)]
    tls_cert: Option<String>,

    #[arg(long)]
    tls_key: Option<String>,

    #[arg(long, default_value = "http://127.0.0.1:7777")]
    nrf_uri: String,

    /// NF instance ID
    #[arg(long)]
    nf_instance_id: Option<String>,

    /// Off-by-default toggle (issue #21 acceptance): the EASDF starts only
    /// when this flag or `easdf.enabled: true` in the YAML config is set.
    #[arg(long, default_value = "false")]
    enabled: bool,

    /// Maximum stored Neasdf_DNSContext resources.
    #[arg(long, default_value = "4096")]
    max_dns_contexts: usize,
}

// ─── YAML config (local serde structs, nssfd pattern) ───────────────────────

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

#[derive(Debug, Default, Deserialize)]
struct SbiYaml {
    server: Option<Vec<SbiServerYaml>>,
    client: Option<SbiClientYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct EasMapEntryYaml {
    fqdn: String,
    addresses: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct DnsYaml {
    /// "forward" (report `upstream` on a miss) or "nxdomain" (default).
    miss_action: Option<String>,
    upstream: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct EasdfSection {
    enabled: Option<bool>,
    sbi: Option<SbiYaml>,
    eas_map: Option<Vec<EasMapEntryYaml>>,
    dns: Option<DnsYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct EasdfYaml {
    easdf: Option<EasdfSection>,
}

/// Load the YAML config; a missing/unreadable file is not an error (all
/// settings then come from CLI flags and defaults).
fn load_config(path: &str) -> Option<EasdfYaml> {
    let content = std::fs::read_to_string(path).ok()?;
    match serde_yaml::from_str::<EasdfYaml>(&content) {
        Ok(config) => Some(config),
        Err(e) => {
            log::warn!("Failed to parse {path}: {e}; using CLI/default configuration");
            None
        }
    }
}

/// Derive the miss behavior from the YAML `dns` section: `forward` needs an
/// `upstream`; anything else (or nothing) is NXDOMAIN.
fn miss_behavior_from(dns: Option<&DnsYaml>) -> DnsMissBehavior {
    match dns {
        Some(dns) if dns.miss_action.as_deref() == Some("forward") => match &dns.upstream {
            Some(upstream) if !upstream.is_empty() => DnsMissBehavior::Forward(upstream.clone()),
            _ => {
                log::warn!(
                    "dns.miss_action=forward without dns.upstream; falling back to nxdomain"
                );
                DnsMissBehavior::NxDomain
            }
        },
        _ => DnsMissBehavior::NxDomain,
    }
}

/// Off-by-default toggle resolution (issue #21 acceptance): enabled only
/// when the CLI flag or `easdf.enabled: true` in the YAML says so.
fn resolve_enabled(cli_enabled: bool, yaml_enabled: Option<bool>) -> bool {
    cli_enabled || yaml_enabled.unwrap_or(false)
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

    let config = load_config(&args.config);
    let section = config.as_ref().and_then(|c| c.easdf.as_ref());

    // Issue #21 acceptance: off-by-default toggle.
    let enabled = resolve_enabled(args.enabled, section.and_then(|s| s.enabled));
    if !enabled {
        log::info!(
            "EASDF is disabled (enable with --enabled or easdf.enabled: true in {}); exiting",
            args.config
        );
        return Ok(());
    }

    log::info!("NextGCore EASDF v{}", env!("CARGO_PKG_VERSION"));
    log::info!(
        "Edge Application Server Discovery Function (TS 23.548; Neasdf_DNSContext TS 29.556)"
    );

    easdf_context_init(args.max_dns_contexts);

    // Static FQDN → EAS map + miss behavior from YAML.
    let eas_map: Vec<EasMapEntry> = section
        .and_then(|s| s.eas_map.as_ref())
        .map(|entries| {
            entries
                .iter()
                .map(|e| EasMapEntry {
                    fqdn: e.fqdn.clone(),
                    addresses: e.addresses.clone(),
                })
                .collect()
        })
        .unwrap_or_default();
    let miss_behavior = miss_behavior_from(section.and_then(|s| s.dns.as_ref()));
    log::info!(
        "EAS map: {} entr{} loaded; miss behavior: {miss_behavior:?}",
        eas_map.len(),
        if eas_map.len() == 1 { "y" } else { "ies" }
    );
    {
        let ctx = easdf_self();
        if let Ok(mut context) = ctx.write() {
            context.set_dns_config(eas_map, miss_behavior);
        };
    }

    // YAML sbi.server[0] overrides the CLI bind address (nssfd pattern, so
    // the NRF profile advertises a routable address).
    let (sbi_addr, sbi_port) = {
        let server = section
            .and_then(|s| s.sbi.as_ref())
            .and_then(|s| s.server.as_ref())
            .and_then(|v| v.first());
        (
            server
                .and_then(|s| s.address.clone())
                .unwrap_or_else(|| args.sbi_addr.clone()),
            server.and_then(|s| s.port).unwrap_or(args.sbi_port),
        )
    };
    let nrf_uri = section
        .and_then(|s| s.sbi.as_ref())
        .and_then(|s| s.client.as_ref())
        .and_then(|c| c.nrf.as_ref())
        .and_then(|v| v.first())
        .map(|n| n.uri.clone())
        .unwrap_or_else(|| args.nrf_uri.clone());

    let nf_instance_id = args
        .nf_instance_id
        .clone()
        .unwrap_or_else(|| format!("easdf-{}", uuid::Uuid::new_v4()));

    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone());

    let addr: SocketAddr = format!("{sbi_addr}:{sbi_port}")
        .parse()
        .context("Invalid SBI address")?;

    let mut sbi_server_config = SbiServerConfig::new(addr);
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
    log::info!("Starting EASDF SBI server on {addr}");
    sbi_server
        .start(easdf_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    // Register with NRF as nfType EASDF advertising neasdf-dnscontext
    // (registration failure is non-fatal, mirroring nwdafd/nefd).
    let sbi_ctx = nextgcore_sbi::context::global_context();
    sbi_ctx.set_nrf_uri(&nrf_uri).await;
    if let Err(e) = register_with_nrf(sbi_ctx, &sbi_addr, sbi_port, &nf_instance_id).await {
        log::warn!("NRF registration failed (will operate without NRF): {e}");
    } else {
        // PATCH a real NFProfile "/load" gauge each heartbeat: stored DNS
        // contexts, saturated at 100 (TS 29.510 §5.2.2.3.2).
        nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(
            nf_instance_id.clone(),
            5,
            || {
                let load = easdf_self()
                    .read()
                    .map(|c| c.dns_context_count())
                    .unwrap_or(0);
                load.min(100) as u8
            },
        );
    }

    log::info!("NextGCore EASDF ready (instance: {nf_instance_id})");

    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    log::info!("Shutting down...");
    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;
    easdf_context_final();
    log::info!("EASDF shutdown complete");

    Ok(())
}

/// EASDF SBI request handler
async fn easdf_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("EASDF SBI: {method} {uri}");

    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match parts.as_slice() {
        // Neasdf_DNSContext (TS 29.556)
        ["neasdf-dnscontext", "v1", "dns-contexts"] => match method {
            "POST" => handle_dns_context_create(&request).await,
            _ => send_method_not_allowed(method, "dns-contexts"),
        },
        ["neasdf-dnscontext", "v1", "dns-contexts", ctx_id] => match method {
            "PUT" => handle_dns_context_update(ctx_id, &request).await,
            "DELETE" => handle_dns_context_delete(ctx_id).await,
            _ => send_method_not_allowed(method, "dns-contexts/{dnsContextId}"),
        },
        // Phase-1 edge DNS resolution over SBI (no UDP/53 listener).
        ["neasdf-dnscontext", "v1", "dns-queries"] => match method {
            "GET" => handle_dns_query(&request).await,
            _ => send_method_not_allowed(method, "dns-queries"),
        },
        _ => send_not_found(&format!("Resource not found: {path}"), None),
    }
}

/// Validate a DnsContext body (TS 29.556 DnsContextCreateData, minimal
/// subset): mandatory `supi` (non-empty string) + `pduSessionId` (number).
/// Returns the parsed body or a boxed SBI error response (boxed so the
/// happy path does not pay for the large Err variant).
fn parse_dns_context_body(
    request: &SbiRequest,
) -> Result<(serde_json::Value, String, u64), Box<SbiResponse>> {
    let body = match &request.http.content {
        Some(c) => c,
        None => {
            return Err(Box::new(send_bad_request(
                "Missing request body",
                Some("MISSING_BODY"),
            )))
        }
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => {
            return Err(Box::new(send_bad_request(
                &format!("Invalid JSON: {e}"),
                Some("INVALID_JSON"),
            )))
        }
    };
    let supi = match data.get("supi").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            return Err(Box::new(send_bad_request(
                "supi is mandatory",
                Some("MANDATORY_IE_MISSING"),
            )))
        }
    };
    let pdu_session_id = match data.get("pduSessionId").and_then(|v| v.as_u64()) {
        Some(id) => id,
        None => {
            return Err(Box::new(send_bad_request(
                "pduSessionId is mandatory",
                Some("MANDATORY_IE_MISSING"),
            )))
        }
    };
    Ok((data, supi, pdu_session_id))
}

/// POST /neasdf-dnscontext/v1/dns-contexts — Neasdf_DNSContext_Create
/// (TS 29.556 §5.2.2.2): validate, store, 201 + Location + echoed context.
async fn handle_dns_context_create(request: &SbiRequest) -> SbiResponse {
    let (data, supi, pdu_session_id) = match parse_dns_context_body(request) {
        Ok(parsed) => parsed,
        Err(response) => return *response,
    };

    let raw = request.http.content.clone().unwrap_or_default();
    let dns_context = EasdfDnsContext::new(supi.clone(), pdu_session_id, raw);
    let ctx_id = dns_context.id.clone();

    let ctx = easdf_self();
    let insert = match ctx.read() {
        Ok(c) => c.dns_context_insert(dns_context),
        Err(_) => Err(EasdfContextError::LockPoisoned),
    };
    match insert {
        Ok(()) => {}
        Err(err @ EasdfContextError::MaxDnsContextsReached) => {
            return send_error(507, "Insufficient Storage", err.detail(), Some(err.cause()))
        }
        Err(err) => return send_internal_error(err.detail()),
    }

    let location = format!("/neasdf-dnscontext/v1/dns-contexts/{ctx_id}");
    log::info!("DNS context created: id={ctx_id}, supi={supi}, pduSessionId={pdu_session_id}");
    let mut echoed = data;
    if let Some(obj) = echoed.as_object_mut() {
        obj.insert("dnsContextId".to_string(), serde_json::json!(ctx_id));
        obj.insert("self".to_string(), serde_json::json!(location));
    }
    SbiResponse::with_status(201)
        .with_header("Location", location)
        .with_json_body(&echoed)
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// PUT /neasdf-dnscontext/v1/dns-contexts/{ctxId} — Update as full replace
/// (the TS 29.556 json-patch Update is simplified in Phase 1).
async fn handle_dns_context_update(ctx_id: &str, request: &SbiRequest) -> SbiResponse {
    let (data, supi, pdu_session_id) = match parse_dns_context_body(request) {
        Ok(parsed) => parsed,
        Err(response) => return *response,
    };

    let raw = request.http.content.clone().unwrap_or_default();
    let replacement = EasdfDnsContext::new(supi, pdu_session_id, raw);

    let ctx = easdf_self();
    let replaced = match ctx.read() {
        Ok(c) => c.dns_context_replace(ctx_id, replacement),
        Err(_) => return send_internal_error("EASDF context lock poisoned"),
    };
    if !replaced {
        return send_not_found(
            &format!("DNS context {ctx_id} not found"),
            Some("CONTEXT_NOT_FOUND"),
        );
    }

    log::info!("DNS context updated: id={ctx_id}");
    let mut echoed = data;
    if let Some(obj) = echoed.as_object_mut() {
        obj.insert("dnsContextId".to_string(), serde_json::json!(ctx_id));
        obj.insert(
            "self".to_string(),
            serde_json::json!(format!("/neasdf-dnscontext/v1/dns-contexts/{ctx_id}")),
        );
    }
    SbiResponse::with_status(200)
        .with_json_body(&echoed)
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// DELETE /neasdf-dnscontext/v1/dns-contexts/{ctxId} — 204 / 404.
async fn handle_dns_context_delete(ctx_id: &str) -> SbiResponse {
    let ctx = easdf_self();
    let removed = match ctx.read() {
        Ok(c) => c.dns_context_remove(ctx_id),
        Err(_) => return send_internal_error("EASDF context lock poisoned"),
    };
    match removed {
        Some(_) => {
            log::info!("DNS context removed: id={ctx_id}");
            SbiResponse::with_status(204)
        }
        None => send_not_found(
            &format!("DNS context {ctx_id} not found"),
            Some("CONTEXT_NOT_FOUND"),
        ),
    }
}

/// GET /neasdf-dnscontext/v1/dns-queries?fqdn=<name> — resolve an FQDN
/// against the static EAS map. Hit → 200 RESOLVE with the EAS addresses;
/// miss → 200 FORWARD with the configured upstream, or 404 FQDN_NOT_FOUND.
async fn handle_dns_query(request: &SbiRequest) -> SbiResponse {
    // In production the SBI server strips the query string from header.uri
    // and delivers query pairs in http.params (issue #21 review finding), so
    // params is the primary source; the raw-URI parse is a fallback for
    // requests built without the server glue.
    let fqdn = request
        .http
        .get_param("fqdn")
        .filter(|v| !v.is_empty())
        .cloned()
        .or_else(|| {
            request
                .header
                .uri
                .split_once('?')
                .map(|(_, query)| query)
                .and_then(|query| {
                    query.split('&').find_map(|kv| {
                        kv.strip_prefix("fqdn=")
                            .filter(|v| !v.is_empty())
                            .map(str::to_string)
                    })
                })
        });
    let Some(fqdn) = fqdn else {
        return send_bad_request(
            "fqdn query parameter is mandatory",
            Some("MANDATORY_IE_MISSING"),
        );
    };

    let ctx = easdf_self();
    let outcome = match ctx.read() {
        Ok(c) => c.resolve_fqdn(&fqdn),
        Err(_) => return send_internal_error("EASDF context lock poisoned"),
    };
    match outcome {
        ResolveOutcome::Resolved(addresses) => SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({
                "fqdn": fqdn,
                "action": "RESOLVE",
                "easAddresses": addresses,
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        ResolveOutcome::Forward(upstream) => SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({
                "fqdn": fqdn,
                "action": "FORWARD",
                "dnsServer": upstream,
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        ResolveOutcome::Miss => send_not_found(
            &format!("FQDN {fqdn} is not edge-served and no upstream DNS is configured"),
            Some("FQDN_NOT_FOUND"),
        ),
    }
}

/// Build the NFProfile registered with the NRF (TS 29.510): nfType EASDF
/// advertising the neasdf-dnscontext service (TS 29.556).
fn build_nf_profile(nf_instance_id: &str, sbi_addr: &str, sbi_port: u16) -> serde_json::Value {
    serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "EASDF",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [
            {
                "serviceInstanceId": format!("{nf_instance_id}-neasdf-dnscontext"),
                "serviceName": "neasdf-dnscontext",
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
            }
        ],
        "allowedNfTypes": ["SMF", "AMF", "SCP"],
        "heartBeatTimer": 10
    })
}

/// Register EASDF with NRF (PUT /nnrf-nfm/v1/nf-instances/{id}, nwdafd
/// pattern). Missing NRF URI skips registration; failure is non-fatal.
async fn register_with_nrf(
    sbi_ctx: Arc<SbiContext>,
    sbi_addr: &str,
    sbi_port: u16,
    nf_instance_id: &str,
) -> Result<(), String> {
    let nrf_uri = sbi_ctx.get_nrf_uri().await;
    let nrf_uri = match nrf_uri {
        Some(uri) => uri,
        None => {
            log::debug!("No NRF URI configured, skipping NRF registration");
            return Ok(());
        }
    };

    log::info!("Registering EASDF with NRF at {nrf_uri}");

    let (nrf_host, nrf_port) = parse_host_port(&nrf_uri).ok_or("Invalid NRF URI")?;
    let client = sbi_ctx.get_client(&nrf_host, nrf_port).await;

    let nf_profile = build_nf_profile(nf_instance_id, sbi_addr, sbi_port);

    let path = format!("/nnrf-nfm/v1/nf-instances/{nf_instance_id}");
    log::debug!("NRF registration: PUT {path}");

    let response = client
        .put_json(&path, &nf_profile)
        .await
        .map_err(|e| format!("NRF registration failed: {e}"))?;

    match response.status {
        200 | 201 => {
            log::info!("EASDF registered with NRF successfully (id={nf_instance_id})");

            let mut self_instance = nextgcore_sbi::context::NfInstance::new(
                nf_instance_id,
                nextgcore_sbi::types::NfType::Easdf,
            );
            self_instance.ipv4_addresses = vec![sbi_addr.to_string()];
            let mut svc = nextgcore_sbi::context::NfService::new(
                "neasdf-dnscontext",
                nextgcore_sbi::types::SbiServiceType::NeasdfDnscontext,
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
    use std::sync::Mutex;

    /// Serializes tests that touch the process-global EASDF context (the
    /// context is process-global; parallel mutation flakes — CI learning).
    static GLOBAL_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock_globals() -> std::sync::MutexGuard<'static, ()> {
        GLOBAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reset the process-global context to a fresh, initialized state with
    /// a small EAS map. Callers must hold [`lock_globals`].
    fn reset_context(miss: DnsMissBehavior) {
        easdf_context_final();
        easdf_context_init(1024);
        let ctx = easdf_self();
        if let Ok(mut context) = ctx.write() {
            context.set_dns_config(
                vec![EasMapEntry {
                    fqdn: "app.edge.example.com".to_string(),
                    addresses: vec!["10.60.0.10".to_string()],
                }],
                miss,
            );
        };
    }

    /// Drive an async handler on a fresh current-thread runtime (the
    /// handlers under test do no real I/O).
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build current-thread runtime")
            .block_on(fut)
    }

    fn create_request(body: serde_json::Value) -> SbiRequest {
        SbiRequest::post("/neasdf-dnscontext/v1/dns-contexts")
            .with_json_body(&body)
            .expect("serialize test body")
    }

    fn valid_body() -> serde_json::Value {
        serde_json::json!({
            "supi": "imsi-001010000000001",
            "pduSessionId": 5,
            "dnsRules": [{"precedence": 1}],
        })
    }

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-easdfd"]);
        assert_eq!(args.config, "/etc/nextgcore/easdf.yaml");
        assert_eq!(args.sbi_port, 7818);
        assert_eq!(args.max_dns_contexts, 4096);
        assert!(!args.enabled, "EASDF must be off by default");
    }

    // ── NRF registration profile (acceptance: nfType EASDF registered) ──────
    #[test]
    fn nf_profile_advertises_easdf_and_dnscontext_service() {
        let profile = build_nf_profile("easdf-test-1", "10.0.0.7", 7818);
        assert_eq!(profile["nfType"], "EASDF");
        assert_eq!(profile["nfStatus"], "REGISTERED");
        assert_eq!(profile["nfServices"][0]["serviceName"], "neasdf-dnscontext");
        assert_eq!(
            profile["nfServices"][0]["serviceInstanceId"],
            "easdf-test-1-neasdf-dnscontext"
        );
        assert_eq!(profile["nfServices"][0]["ipEndPoints"][0]["port"], 7818);
        // The lib service enum round-trips the wire name (SCP routing key).
        assert_eq!(
            nextgcore_sbi::types::SbiServiceType::from_name("neasdf-dnscontext"),
            Some(nextgcore_sbi::types::SbiServiceType::NeasdfDnscontext)
        );
        assert_eq!(
            nextgcore_sbi::types::SbiServiceType::NeasdfDnscontext.to_name(),
            "neasdf-dnscontext"
        );
    }

    // ── YAML config parsing ──────────────────────────────────────────────────
    #[test]
    fn yaml_config_parses_full_section() {
        let yaml = r#"
easdf:
  enabled: true
  sbi:
    server:
      - address: 10.0.0.7
        port: 7818
    client:
      nrf:
        - uri: http://10.0.0.10:7777
  eas_map:
    - fqdn: app.edge.example.com
      addresses: ["10.60.0.10", "10.60.0.11"]
    - fqdn: "*.media.example.com"
      addresses: ["10.61.0.5"]
  dns:
    miss_action: forward
    upstream: "10.0.0.53:53"
"#;
        let parsed: EasdfYaml = serde_yaml::from_str(yaml).expect("parse");
        let section = parsed.easdf.expect("easdf section");
        assert_eq!(section.enabled, Some(true));
        let map = section.eas_map.expect("eas_map");
        assert_eq!(map.len(), 2);
        assert_eq!(map[0].fqdn, "app.edge.example.com");
        assert_eq!(map[1].addresses, vec!["10.61.0.5".to_string()]);
        let behavior = miss_behavior_from(section.dns.as_ref());
        assert_eq!(
            behavior,
            DnsMissBehavior::Forward("10.0.0.53:53".to_string())
        );
        assert_eq!(
            section
                .sbi
                .as_ref()
                .and_then(|s| s.server.as_ref())
                .and_then(|v| v.first())
                .and_then(|s| s.port),
            Some(7818)
        );
        assert_eq!(
            section
                .sbi
                .and_then(|s| s.client)
                .and_then(|c| c.nrf)
                .and_then(|mut n| n.pop())
                .map(|n| n.uri),
            Some("http://10.0.0.10:7777".to_string())
        );
    }

    #[test]
    fn miss_behavior_defaults_and_guards() {
        assert_eq!(miss_behavior_from(None), DnsMissBehavior::NxDomain);
        // forward without upstream falls back to nxdomain.
        let dns = DnsYaml {
            miss_action: Some("forward".to_string()),
            upstream: None,
        };
        assert_eq!(miss_behavior_from(Some(&dns)), DnsMissBehavior::NxDomain);
        // unknown action is nxdomain.
        let dns = DnsYaml {
            miss_action: Some("drop".to_string()),
            upstream: Some("10.0.0.53:53".to_string()),
        };
        assert_eq!(miss_behavior_from(Some(&dns)), DnsMissBehavior::NxDomain);
    }

    // ── Neasdf_DNSContext Create / Update / Delete ───────────────────────────
    #[test]
    fn dns_context_create_returns_201_and_stores() {
        let _guard = lock_globals();
        reset_context(DnsMissBehavior::NxDomain);

        let response = block_on(handle_dns_context_create(&create_request(valid_body())));
        assert_eq!(response.status, 201);
        let location = response
            .http
            .get_header("location")
            .expect("201 must carry Location")
            .clone();
        assert!(location.starts_with("/neasdf-dnscontext/v1/dns-contexts/"));
        let ctx_id = location.rsplit('/').next().unwrap().to_string();

        let body: serde_json::Value =
            serde_json::from_str(response.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["dnsContextId"], ctx_id);
        assert_eq!(body["self"], location);
        assert_eq!(body["supi"], "imsi-001010000000001");

        let stored = easdf_self()
            .read()
            .unwrap()
            .dns_context_find(&ctx_id)
            .expect("stored");
        assert_eq!(stored.supi, "imsi-001010000000001");
        assert_eq!(stored.pdu_session_id, 5);
    }

    #[test]
    fn dns_context_create_missing_mandatory_ies_returns_400() {
        let no_body = SbiRequest::post("/neasdf-dnscontext/v1/dns-contexts");
        assert_eq!(block_on(handle_dns_context_create(&no_body)).status, 400);

        let missing_supi = create_request(serde_json::json!({"pduSessionId": 5}));
        let response = block_on(handle_dns_context_create(&missing_supi));
        assert_eq!(response.status, 400, "missing supi must be 400");
        let body: serde_json::Value =
            serde_json::from_str(response.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "MANDATORY_IE_MISSING");

        let missing_psi = create_request(serde_json::json!({"supi": "imsi-1"}));
        assert_eq!(
            block_on(handle_dns_context_create(&missing_psi)).status,
            400,
            "missing pduSessionId must be 400"
        );
    }

    #[test]
    fn dns_context_update_replaces_and_404s_unknown() {
        let _guard = lock_globals();
        reset_context(DnsMissBehavior::NxDomain);

        let created = block_on(handle_dns_context_create(&create_request(valid_body())));
        let ctx_id = created
            .http
            .get_header("location")
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_string();

        let update = SbiRequest::put(format!("/neasdf-dnscontext/v1/dns-contexts/{ctx_id}"))
            .with_json_body(&serde_json::json!({"supi": "imsi-002020000000002", "pduSessionId": 7}))
            .expect("serialize");
        let response = block_on(handle_dns_context_update(&ctx_id, &update));
        assert_eq!(response.status, 200);
        let stored = easdf_self()
            .read()
            .unwrap()
            .dns_context_find(&ctx_id)
            .expect("still stored");
        assert_eq!(stored.supi, "imsi-002020000000002");
        assert_eq!(stored.pdu_session_id, 7);
        assert_eq!(stored.id, ctx_id, "resource ID survives the replace");

        let response = block_on(handle_dns_context_update("absent", &update));
        assert_eq!(response.status, 404, "unknown context must be 404");
    }

    #[test]
    fn dns_context_delete_returns_204_then_404() {
        let _guard = lock_globals();
        reset_context(DnsMissBehavior::NxDomain);

        let created = block_on(handle_dns_context_create(&create_request(valid_body())));
        let ctx_id = created
            .http
            .get_header("location")
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_string();

        assert_eq!(block_on(handle_dns_context_delete(&ctx_id)).status, 204);
        assert!(easdf_self()
            .read()
            .unwrap()
            .dns_context_find(&ctx_id)
            .is_none());
        assert_eq!(block_on(handle_dns_context_delete(&ctx_id)).status, 404);
    }

    #[test]
    fn dns_context_create_at_capacity_returns_507() {
        let _guard = lock_globals();
        easdf_context_final();
        easdf_context_init(1);

        let first = block_on(handle_dns_context_create(&create_request(valid_body())));
        assert_eq!(first.status, 201);
        let second = block_on(handle_dns_context_create(&create_request(valid_body())));
        assert_eq!(second.status, 507, "cap exhaustion must be 507");
        let body: serde_json::Value =
            serde_json::from_str(second.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "MAX_DNS_CONTEXTS_REACHED");

        // Restore default test capacity.
        easdf_context_final();
        easdf_context_init(1024);
    }

    // ── DNS query endpoint (acceptance: configured FQDN resolves; miss has
    //    defined behavior) ────────────────────────────────────────────────────

    /// Build a dns-query request the way the production SBI server delivers
    /// it: path-only URI with the query pairs in `http.params` (issue #21
    /// review finding — `header.uri` carries no query string in production).
    fn dns_query_request(fqdn: Option<&str>) -> SbiRequest {
        let mut request = SbiRequest::get("/neasdf-dnscontext/v1/dns-queries");
        if let Some(fqdn) = fqdn {
            request.http.set_param("fqdn", fqdn);
        }
        request
    }

    #[test]
    fn dns_query_hit_returns_eas_addresses() {
        let _guard = lock_globals();
        reset_context(DnsMissBehavior::NxDomain);

        let response = block_on(handle_dns_query(&dns_query_request(Some(
            "app.edge.example.com",
        ))));
        assert_eq!(response.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(response.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["action"], "RESOLVE");
        assert_eq!(body["easAddresses"][0], "10.60.0.10");

        // Fallback surface: a raw URI query (requests built without the
        // server glue) still resolves.
        let raw = SbiRequest::get("/neasdf-dnscontext/v1/dns-queries?fqdn=app.edge.example.com");
        assert_eq!(block_on(handle_dns_query(&raw)).status, 200);
    }

    #[test]
    fn dns_query_miss_behaviors_and_missing_param() {
        let _guard = lock_globals();

        // NXDOMAIN miss → 404 FQDN_NOT_FOUND.
        reset_context(DnsMissBehavior::NxDomain);
        let request = dns_query_request(Some("other.example.org"));
        let response = block_on(handle_dns_query(&request));
        assert_eq!(response.status, 404);
        let body: serde_json::Value =
            serde_json::from_str(response.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "FQDN_NOT_FOUND");

        // Forward miss → 200 FORWARD with the upstream.
        reset_context(DnsMissBehavior::Forward("10.0.0.53:53".to_string()));
        let response = block_on(handle_dns_query(&request));
        assert_eq!(response.status, 200);
        let body: serde_json::Value =
            serde_json::from_str(response.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["action"], "FORWARD");
        assert_eq!(body["dnsServer"], "10.0.0.53:53");

        // Missing/empty fqdn → 400 (both the params and raw-URI surfaces).
        assert_eq!(
            block_on(handle_dns_query(&dns_query_request(None))).status,
            400
        );
        assert_eq!(
            block_on(handle_dns_query(&dns_query_request(Some("")))).status,
            400
        );
        let raw = SbiRequest::get("/neasdf-dnscontext/v1/dns-queries?fqdn=");
        assert_eq!(block_on(handle_dns_query(&raw)).status, 400);
    }

    #[test]
    fn enabled_toggle_resolution_is_off_by_default() {
        assert!(!resolve_enabled(false, None), "off by default");
        assert!(!resolve_enabled(false, Some(false)));
        assert!(resolve_enabled(true, None), "CLI flag enables");
        assert!(resolve_enabled(false, Some(true)), "YAML enables");
    }

    #[test]
    fn dns_context_create_malformed_json_returns_400() {
        let request = SbiRequest::post("/neasdf-dnscontext/v1/dns-contexts")
            .with_body("{not json", "application/json");
        let response = block_on(handle_dns_context_create(&request));
        assert_eq!(response.status, 400, "malformed JSON must be 400");
        let body: serde_json::Value =
            serde_json::from_str(response.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "INVALID_JSON");
    }

    // ── Router ───────────────────────────────────────────────────────────────
    #[test]
    fn router_unknown_path_404_and_wrong_method_405() {
        let unknown = SbiRequest::get("/neasdf-baseline/v1/whatever");
        assert_eq!(block_on(easdf_sbi_request_handler(unknown)).status, 404);

        let wrong = SbiRequest::get("/neasdf-dnscontext/v1/dns-contexts");
        assert_eq!(block_on(easdf_sbi_request_handler(wrong)).status, 405);
    }
}
