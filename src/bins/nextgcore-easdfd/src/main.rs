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
//!   404 (`FQDN_NOT_FOUND`).
//! - **Edge DNS resolution over UDP/53** (#276, `dns-udp` cargo feature, off
//!   by default): the transport a UE or stub resolver actually speaks. The
//!   query is decoded by [`dns_wire`] (RFC 1035 + EDNS(0)), scoped to a PDU
//!   session by the query's **source address**, answered with `A`/`AAAA`
//!   records, forwarded verbatim to the configured upstream on a miss, or
//!   answered `NXDOMAIN` when no upstream is configured. See [`dns_udp`] for
//!   why this half is a cargo feature while the codec is not.
//!
//! Off by default: the NF exits immediately unless enabled via `--enabled`
//! or `easdf.enabled: true` in the YAML config (and, like every NF binary,
//! it is inert unless deployed).
//!
//! Distinct from `nextgcore-eesd`: the EES is the SA6 application-layer
//! Edge Enabler Server of TS 23.558, not this 5GC NF.
//!
//! Deferred per issue #21 (follow-ups): SMF UL-CL / branching-point
//! insertion, PCF traffic-influence rules, and latency-aware UPF/PSA
//! selection. (DNS message-handling-rule enforcement landed in #114; the
//! UDP/53 listener in #276.)

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_sbi::client::SbiClient;
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
#[cfg(feature = "dns-udp")]
mod dns_udp;
mod dns_wire;

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

    /// Bind address for the DNS/UDP listener (#276, `dns-udp` feature).
    #[cfg(feature = "dns-udp")]
    #[arg(long, default_value = "0.0.0.0")]
    dns_udp_addr: String,

    /// Bind port for the DNS/UDP listener. 53 needs `CAP_NET_BIND_SERVICE`;
    /// override it to run the plane on an unprivileged port behind a redirect.
    #[cfg(feature = "dns-udp")]
    #[arg(long, default_value = "53")]
    dns_udp_port: u16,
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
    /// DNS/UDP listener overrides (#276). Present only with the `dns-udp`
    /// feature; on a default build these keys are simply ignored, since the
    /// config structs do not deny unknown fields.
    #[cfg(feature = "dns-udp")]
    udp_address: Option<String>,
    #[cfg(feature = "dns-udp")]
    udp_port: Option<u16>,
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

    // ---- #276: the DNS/UDP plane ----
    //
    // Started AFTER the SBI server and the NRF registration, so a DNS query can
    // never arrive before the resolution engine's configuration is installed --
    // answering from a half-configured EAS map would send a UE to the wrong EAS.
    // A bind failure is FATAL, unlike the non-fatal NRF registration: the
    // operator compiled the feature in and asked for the port, so silently
    // running without the listener would be an EASDF that looks up and answers
    // nothing. Port 53 needs CAP_NET_BIND_SERVICE and the failure is almost
    // always that.
    #[cfg(feature = "dns-udp")]
    let _dns_udp = {
        let dns = section.and_then(|s| s.dns.as_ref());
        let addr = dns
            .and_then(|d| d.udp_address.clone())
            .unwrap_or_else(|| args.dns_udp_addr.clone());
        let port = dns.and_then(|d| d.udp_port).unwrap_or(args.dns_udp_port);
        let bind: SocketAddr = format!("{addr}:{port}")
            .parse()
            .context("Invalid DNS/UDP bind address")?;
        let upstream = dns
            .and_then(|d| d.upstream.as_deref())
            .and_then(dns_udp::parse_upstream);
        let (bound, handle) = dns_udp::spawn(dns_udp::DnsUdpConfig { bind, upstream })
            .await
            .with_context(|| {
                format!(
                    "failed to bind the DNS/UDP listener on {bind} \
                     (port 53 needs CAP_NET_BIND_SERVICE; set easdf.dns.udp_port \
                     or --dns-udp-port to use an unprivileged port)"
                )
            })?;
        log::info!("EASDF DNS/UDP plane serving on {bound}");
        handle
    };

    log::info!("NextGCore EASDF ready (instance: {nf_instance_id})");

    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    log::info!("Shutting down...");

    // #235: NFDeregister (TS 29.510 5.2.2.2.3) BEFORE the listener goes
    // away, so the NRF stops handing this profile to consumers instead of
    // waiting out its supervision timer. Stopping the server first would
    // open the bad window: not serving, but still advertised.
    nextgcore_sbi::heartbeat::deregister_self().await;
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
        // #114: Neasdf_BaselineDNSPattern (TS 23.501 Table 7.2.25-1) -- the
        // second EASDF service, previously absent entirely.
        ["neasdf-baselinednspattern", "v1", "baseline-dns-patterns"] => match method {
            "POST" => handle_baseline_pattern_create(&request).await,
            "GET" => handle_baseline_pattern_list().await,
            _ => send_method_not_allowed(method, "baseline-dns-patterns"),
        },
        ["neasdf-baselinednspattern", "v1", "baseline-dns-patterns", pattern_id] => match method {
            "GET" => handle_baseline_pattern_read(pattern_id).await,
            "DELETE" => handle_baseline_pattern_delete(pattern_id).await,
            _ => send_method_not_allowed(method, "baseline-dns-patterns/{patternId}"),
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
    // #114: parse the DNS message-handling rules and the report callback out of
    // the body. They used to be stored only inside `raw` and never consulted, so
    // the context had no effect on what this EASDF answered.
    let dns_context = EasdfDnsContext::new(supi.clone(), pdu_session_id, raw).with_parsed(&data);
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
    // #114: an update must REPARSE the rules; keeping the old ones while storing
    // the new body is the shape of bug that passes a read-back assertion and
    // changes nothing about what the EASDF answers.
    let replacement = EasdfDnsContext::new(supi, pdu_session_id, raw).with_parsed(&data);

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

    // #114: an optional `dns-context-id` scopes the query to a session's own DNS
    // handling rules. Unscoped queries are answered from the static EAS map only
    // -- consulting some other session's rules would leak one subscriber's edge
    // steering into another subscriber's answer.
    let ctx_id = request
        .http
        .get_param("dns-context-id")
        .filter(|v| !v.is_empty())
        .cloned();

    let ctx = easdf_self();
    let (outcome, report) = match ctx.read() {
        Ok(c) => match &ctx_id {
            Some(id) => c.resolve_in_context(id, &fqdn),
            None => (c.resolve_fqdn(&fqdn), false),
        },
        Err(_) => return send_internal_error("EASDF context lock poisoned"),
    };

    // TS 23.548 §6.2.3.2.2 DNS message reporting: a matching rule that asked for
    // a report gets one, sent to the callback the SMF supplied on create. Awaited
    // rather than spawned so the report is on the wire before the DNS answer goes
    // back -- an SMF that must install a UL-CL for the resolved EAS should not
    // learn of it after the UE already has the address.
    if report {
        if let Some(id) = &ctx_id {
            let uri = ctx.read().ok().and_then(|c| c.dns_context_notify_uri(id));
            match uri {
                Some(uri) => send_dns_message_report(&uri, id, &fqdn, &outcome).await,
                None => log::warn!(
                    "DNS context {id} has a rule requesting a report but no notification URI: \
                     the report cannot be delivered"
                ),
            }
        }
    }

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

/// Send a DNS-message report to the SMF's callback URI (#114, TS 23.548
/// §6.2.3.2.2).
///
/// This is the leg the EASDF had no equivalent of at all: the SMF could create a
/// context and was never told what the EASDF resolved, so it could not drive the
/// UL-CL / PSA re-selection that edge steering exists for.
///
/// The body carries the context id, the queried FQDN, the action taken and the
/// resolved EAS addresses. TS 29.556 is not vendored, so the member names follow
/// the same convention as the rest of this crate's northbound bodies; the shape
/// is asserted by `a_reporting_rule_emits_a_dns_message_report`.
///
/// A failed report is logged and swallowed: the DNS answer to the UE must not be
/// held hostage to the SMF's reachability, and the EASDF has no retry queue.
async fn send_dns_message_report(
    notify_uri: &str,
    ctx_id: &str,
    fqdn: &str,
    outcome: &ResolveOutcome,
) {
    let (action, addresses) = match outcome {
        ResolveOutcome::Resolved(addrs) => ("RESOLVE", addrs.clone()),
        ResolveOutcome::Forward(_) => ("FORWARD", Vec::new()),
        ResolveOutcome::Miss => ("MISS", Vec::new()),
    };
    let body = serde_json::json!({
        "dnsContextId": ctx_id,
        "fqdn": fqdn,
        "action": action,
        "easIpAddresses": addresses,
    });

    let Some((host, port, path)) = split_uri(notify_uri) else {
        log::warn!("DNS context {ctx_id}: unparseable notification URI {notify_uri}");
        return;
    };
    let client = SbiClient::with_host_port(&host, port);
    match client.post_json(&path, &body).await {
        Ok(resp) => log::info!(
            "DNS message report for {fqdn} (context {ctx_id}) -> {notify_uri} status={}",
            resp.status
        ),
        Err(e) => log::warn!("DNS message report to {notify_uri} failed: {e}"),
    }
}

/// Split `scheme://host:port/path` into `(host, port, path)`.
fn split_uri(uri: &str) -> Option<(String, u16, String)> {
    let (default_port, rest) = if let Some(r) = uri.strip_prefix("https://") {
        (443u16, r)
    } else if let Some(r) = uri.strip_prefix("http://") {
        (80u16, r)
    } else {
        (80u16, uri)
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port)),
        None => (authority.to_string(), default_port),
    };
    (!host.is_empty()).then_some((host, port, path))
}

// ---------------------------------------------------------------------------
// #114: Neasdf_BaselineDNSPattern (TS 23.501 Table 7.2.25-1)
// ---------------------------------------------------------------------------

/// Resource collection path for baseline DNS patterns.
const BASELINE_PATTERNS_PATH: &str = "/neasdf-baselinednspattern/v1/baseline-dns-patterns";

/// `POST .../baseline-dns-patterns` — create a baseline DNS pattern (#114).
///
/// The second EASDF service in TS 23.501 Table 7.2.25-1 was absent entirely: not
/// implemented, not routed, and not advertised in the NFProfile, so an SMF
/// discovering this EASDF saw an NF that claims to be an EASDF and offers half of
/// what one offers.
///
/// A baseline pattern is EASDF-wide (not per-session): it is the fallback
/// forwarding/answering configuration a DNS query falls through to when no
/// session context rule and no static EAS-map entry matched. Mandatory member:
/// a non-empty domain pattern.
async fn handle_baseline_pattern_create(request: &SbiRequest) -> SbiResponse {
    let Some(body) = request.http.content.as_deref() else {
        return send_bad_request("Missing request body", Some("MANDATORY_IE_MISSING"));
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };
    let Some(rule) = context::DnsHandlingRule::from_json(&data) else {
        return send_bad_request(
            "A baseline DNS pattern needs a domain pattern (domainNames / dnsQueryMdt / fqdn) \
             and an action (easIpAddresses, forwardTo, or reportInd)",
            Some("MANDATORY_IE_MISSING"),
        );
    };

    let ctx = easdf_self();
    let created = match ctx.read() {
        Ok(c) => c.baseline_pattern_insert(rule),
        Err(_) => return send_internal_error("EASDF context lock poisoned"),
    };
    match created {
        Ok(id) => {
            let location = format!("{BASELINE_PATTERNS_PATH}/{id}");
            log::info!("Baseline DNS pattern created: id={id}");
            let mut echoed = data;
            if let Some(obj) = echoed.as_object_mut() {
                obj.insert("patternId".to_string(), serde_json::json!(id));
                obj.insert("self".to_string(), serde_json::json!(location));
            }
            SbiResponse::with_status(201)
                .with_header("Location", location)
                .with_json_body(&echoed)
                .unwrap_or_else(|_| SbiResponse::with_status(201))
        }
        Err(err @ EasdfContextError::MaxDnsContextsReached) => {
            send_error(507, "Insufficient Storage", err.detail(), Some(err.cause()))
        }
        Err(err) => send_internal_error(err.detail()),
    }
}

/// `GET .../baseline-dns-patterns/{id}` — read one baseline DNS pattern (#114).
async fn handle_baseline_pattern_read(id: &str) -> SbiResponse {
    let ctx = easdf_self();
    let found = ctx.read().ok().and_then(|c| c.baseline_pattern_find(id));
    match found {
        Some(rule) => SbiResponse::with_status(200)
            .with_json_body(&serde_json::json!({
                "patternId": id,
                "self": format!("{BASELINE_PATTERNS_PATH}/{id}"),
                "domainNames": rule.domain_patterns,
                "easIpAddresses": rule.eas_addresses,
                "reportInd": rule.report,
                "forwardTo": rule.forward_to,
            }))
            .unwrap_or_else(|_| SbiResponse::with_status(200)),
        None => send_not_found(
            &format!("Baseline DNS pattern {id} not found"),
            Some("PATTERN_NOT_FOUND"),
        ),
    }
}

/// `GET .../baseline-dns-patterns` — list the baseline DNS patterns (#114).
async fn handle_baseline_pattern_list() -> SbiResponse {
    let ctx = easdf_self();
    let ids = ctx
        .read()
        .map(|c| c.baseline_pattern_ids())
        .unwrap_or_default();
    SbiResponse::with_status(200)
        .with_json_body(&serde_json::json!({"patternIds": ids}))
        .unwrap_or_else(|_| SbiResponse::with_status(200))
}

/// `DELETE .../baseline-dns-patterns/{id}` — 204 / 404 (#114).
async fn handle_baseline_pattern_delete(id: &str) -> SbiResponse {
    let ctx = easdf_self();
    let removed = ctx.read().ok().and_then(|c| c.baseline_pattern_remove(id));
    match removed {
        Some(_) => {
            log::info!("Baseline DNS pattern removed: id={id}");
            SbiResponse::with_status(204)
        }
        None => send_not_found(
            &format!("Baseline DNS pattern {id} not found"),
            Some("PATTERN_NOT_FOUND"),
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
            },
            // #114: TS 23.501 Table 7.2.25-1 lists BOTH EASDF services. Only the
            // first was advertised, so an SMF discovering this EASDF was told it
            // offers half of what an EASDF offers.
            {
                "serviceInstanceId": format!("{nf_instance_id}-neasdf-baselinednspattern"),
                "serviceName": "neasdf-baselinednspattern",
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

    /// Serializes tests that touch the process-global EASDF context.
    ///
    /// The lock itself now lives in `context.rs`, beside the global it protects,
    /// because `dns_udp`'s tests need the SAME one (#276) and a sibling module
    /// cannot reach a static declared inside this test submodule. Re-exported
    /// under the local name so the call sites below are unchanged.
    use crate::context::lock_globals;

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
            #[cfg(feature = "dns-udp")]
            udp_address: None,
            #[cfg(feature = "dns-udp")]
            udp_port: None,
            miss_action: Some("forward".to_string()),
            upstream: None,
        };
        assert_eq!(miss_behavior_from(Some(&dns)), DnsMissBehavior::NxDomain);
        // unknown action is nxdomain.
        let dns = DnsYaml {
            #[cfg(feature = "dns-udp")]
            udp_address: None,
            #[cfg(feature = "dns-udp")]
            udp_port: None,
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

    // ─── #114: rule evaluation, DNS-message report, baseline patterns ────────

    /// #114 acceptance: a context's handling rule answers a query for an FQDN
    /// that is **absent from the static EAS map**.
    ///
    /// That absence is the point: before this, resolution consulted only the
    /// static map, so a per-session context had no effect on any answer. An FQDN
    /// present in the map could not distinguish the two.
    #[test]
    fn a_context_rule_answers_an_fqdn_absent_from_the_eas_map() {
        let _g = lock_globals();
        reset_context(DnsMissBehavior::NxDomain);

        // Sanity: the FQDN is NOT in the static map, so without the rule this is
        // a miss. Asserted, so the test cannot pass because the map happened to
        // contain it.
        let ctx = easdf_self();
        assert_eq!(
            ctx.read().unwrap().resolve_fqdn("shop.edge2.example.com"),
            ResolveOutcome::Miss,
            "the FQDN must be absent from the static map for this test to mean anything"
        );

        let body = serde_json::json!({
            "supi": "imsi-001010000000001",
            "pduSessionId": 5,
            "dnsHandlingRules": [{
                "domainNames": ["*.edge2.example.com"],
                "easIpAddresses": ["10.70.0.7"]
            }]
        });
        let resp = block_on(easdf_sbi_request_handler(create_request(body)));
        assert_eq!(resp.status, 201);
        let created: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let ctx_id = created["dnsContextId"].as_str().unwrap().to_string();

        // Scoped to the context, the rule answers.
        let mut query = SbiRequest::get("/neasdf-dnscontext/v1/dns-queries");
        query.http.set_param("fqdn", "shop.edge2.example.com");
        query.http.set_param("dns-context-id", &ctx_id);
        let resp = block_on(easdf_sbi_request_handler(query));
        assert_eq!(resp.status, 200);
        let answer: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(answer["action"], "RESOLVE");
        assert_eq!(answer["easAddresses"][0], "10.70.0.7");

        // UNSCOPED, the same query is still a miss: one session's rules must not
        // answer another's (or an anonymous) query.
        let mut query = SbiRequest::get("/neasdf-dnscontext/v1/dns-queries");
        query.http.set_param("fqdn", "shop.edge2.example.com");
        assert_eq!(
            block_on(easdf_sbi_request_handler(query)).status,
            404,
            "an unscoped query must not be answered from some session's rules"
        );
    }

    /// #114: a rule can forward, and an update REPARSES the rules — storing the
    /// new body while keeping the old rules would pass a read-back assertion and
    /// change nothing about what the EASDF answers.
    #[test]
    fn an_update_reparses_the_handling_rules() {
        let _g = lock_globals();
        reset_context(DnsMissBehavior::NxDomain);

        let body = serde_json::json!({
            "supi": "imsi-1", "pduSessionId": 1,
            "dnsHandlingRules": [{
                "domainNames": ["a.edge3.example.com"], "easIpAddresses": ["10.1.1.1"]
            }]
        });
        let resp = block_on(easdf_sbi_request_handler(create_request(body)));
        let created: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let ctx_id = created["dnsContextId"].as_str().unwrap().to_string();

        // Replace the rule with a FORWARD rule for a different name.
        let update = SbiRequest::put(format!("/neasdf-dnscontext/v1/dns-contexts/{ctx_id}"))
            .with_json_body(&serde_json::json!({
                "supi": "imsi-1", "pduSessionId": 1,
                "dnsHandlingRules": [{
                    "domainNames": ["b.edge3.example.com"],
                    "forwardTo": "10.0.0.53"
                }]
            }))
            .unwrap();
        assert_eq!(block_on(easdf_sbi_request_handler(update)).status, 200);

        let resolve = |fqdn: &str| {
            let ctx = easdf_self();
            let guard = ctx.read().unwrap();
            guard.resolve_in_context(&ctx_id, fqdn).0
        };
        assert_eq!(
            resolve("b.edge3.example.com"),
            ResolveOutcome::Forward("10.0.0.53".to_string()),
            "the new rule must be in effect"
        );
        assert_eq!(
            resolve("a.edge3.example.com"),
            ResolveOutcome::Miss,
            "the replaced rule must be gone, not merely shadowed"
        );
    }

    /// #114 acceptance: a reporting-enabled rule emits a DNS-message report to
    /// the SMF's callback URI, carrying the FQDN and the resolved EAS address(es).
    // The `GLOBAL_TEST_LOCK` is a `std::sync::Mutex` shared with this module's
    // SYNCHRONOUS tests, which cannot await. Two locks -- a std one for the sync
    // tests and a tokio one for this -- would be two disjoint agreements about the
    // same process-global context, which is the bug the single lock exists to
    // prevent. Holding it across the awaits below is safe here because these tests
    // are its only holders and none of them blocks on another.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn a_reporting_rule_emits_a_dns_message_report() {
        let _g = lock_globals();
        reset_context(DnsMissBehavior::NxDomain);

        // A loopback "SMF" that records the report it receives.
        let seen: std::sync::Arc<Mutex<Vec<serde_json::Value>>> =
            std::sync::Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let (port_listener, port_addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
        let port = port_addr.port();
        let smf = nextgcore_sbi::server::SbiServer::on_listener(
            nextgcore_sbi::server::SbiServerConfig::new(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                port,
            ))),
            port_listener,
        );
        smf.start(move |req: SbiRequest| {
            let sink = sink.clone();
            async move {
                if let Some(body) = req.http.content.as_deref() {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
                        sink.lock().unwrap_or_else(|e| e.into_inner()).push(v);
                    }
                }
                SbiResponse::with_status(204)
            }
        })
        .await
        .expect("smf sink start");

        let body = serde_json::json!({
            "supi": "imsi-001010000000001",
            "pduSessionId": 5,
            "notificationUri": format!("http://127.0.0.1:{port}/nsmf-pdusession/v1/easdf-dns-reports"),
            "dnsHandlingRules": [{
                "domainNames": ["*.edge4.example.com"],
                "easIpAddresses": ["10.80.0.8"],
                "reportInd": true
            }]
        });
        let resp = easdf_sbi_request_handler(create_request(body)).await;
        assert_eq!(resp.status, 201);
        let created: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let ctx_id = created["dnsContextId"].as_str().unwrap().to_string();

        let mut query = SbiRequest::get("/neasdf-dnscontext/v1/dns-queries");
        query.http.set_param("fqdn", "vr.edge4.example.com");
        query.http.set_param("dns-context-id", &ctx_id);
        assert_eq!(easdf_sbi_request_handler(query).await.status, 200);

        // The report is awaited inside the handler, so it is already delivered.
        let reports = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(reports.len(), 1, "exactly one report, got {reports:?}");
        assert_eq!(reports[0]["fqdn"], "vr.edge4.example.com");
        assert_eq!(reports[0]["action"], "RESOLVE");
        assert_eq!(reports[0]["easIpAddresses"][0], "10.80.0.8");
        assert_eq!(reports[0]["dnsContextId"], ctx_id);

        // A rule WITHOUT reportInd emits nothing.
        let body = serde_json::json!({
            "supi": "imsi-2", "pduSessionId": 6,
            "notificationUri": format!("http://127.0.0.1:{port}/nsmf-pdusession/v1/easdf-dns-reports"),
            "dnsHandlingRules": [{
                "domainNames": ["*.quiet.example.com"], "easIpAddresses": ["10.80.0.9"]
            }]
        });
        let resp = easdf_sbi_request_handler(create_request(body)).await;
        let created: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        let quiet_id = created["dnsContextId"].as_str().unwrap().to_string();
        let mut query = SbiRequest::get("/neasdf-dnscontext/v1/dns-queries");
        query.http.set_param("fqdn", "x.quiet.example.com");
        query.http.set_param("dns-context-id", &quiet_id);
        assert_eq!(easdf_sbi_request_handler(query).await.status, 200);
        assert_eq!(
            seen.lock().unwrap_or_else(|e| e.into_inner()).len(),
            1,
            "a rule without reportInd must not report"
        );

        smf.stop().await.expect("stop");
    }

    /// #114 acceptance: `Neasdf_BaselineDNSPattern` Create/Read/Delete, and the
    /// service appears in the NFProfile registration payload.
    #[test]
    fn baseline_dns_pattern_crud_and_nf_profile_advertisement() {
        let _g = lock_globals();
        reset_context(DnsMissBehavior::NxDomain);

        // Create.
        let create = SbiRequest::post("/neasdf-baselinednspattern/v1/baseline-dns-patterns")
            .with_json_body(&serde_json::json!({
                "domainNames": ["*.baseline.example.com"],
                "easIpAddresses": ["10.90.0.9"]
            }))
            .unwrap();
        let resp = block_on(easdf_sbi_request_handler(create));
        assert_eq!(resp.status, 201);
        let location = resp.http.get_header("location").cloned().expect("Location");
        assert!(
            location.starts_with(BASELINE_PATTERNS_PATH),
            "got {location}"
        );
        let id = location.rsplit('/').next().unwrap().to_string();

        // Read.
        let read = SbiRequest::get(format!("{BASELINE_PATTERNS_PATH}/{id}"));
        let resp = block_on(easdf_sbi_request_handler(read));
        assert_eq!(resp.status, 200);
        let got: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(got["domainNames"][0], "*.baseline.example.com");
        assert_eq!(got["easIpAddresses"][0], "10.90.0.9");

        // The pattern actually participates in resolution, after the static map.
        let mut query = SbiRequest::get("/neasdf-dnscontext/v1/dns-queries");
        query.http.set_param("fqdn", "a.baseline.example.com");
        let resp = block_on(easdf_sbi_request_handler(query));
        assert_eq!(resp.status, 200);
        let answer: serde_json::Value =
            serde_json::from_str(resp.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(
            answer["easAddresses"][0], "10.90.0.9",
            "a baseline pattern must answer a query the static map missed"
        );

        // A body with no domain pattern is refused.
        let bad = SbiRequest::post("/neasdf-baselinednspattern/v1/baseline-dns-patterns")
            .with_json_body(&serde_json::json!({"easIpAddresses": ["10.0.0.1"]}))
            .unwrap();
        assert_eq!(block_on(easdf_sbi_request_handler(bad)).status, 400);

        // Delete, then 404.
        let del = SbiRequest::delete(format!("{BASELINE_PATTERNS_PATH}/{id}"));
        assert_eq!(block_on(easdf_sbi_request_handler(del)).status, 204);
        let read = SbiRequest::get(format!("{BASELINE_PATTERNS_PATH}/{id}"));
        assert_eq!(block_on(easdf_sbi_request_handler(read)).status, 404);

        // ...and the service is advertised to the NRF. TS 23.501 Table 7.2.25-1
        // lists both EASDF services; only the first used to appear.
        let profile = build_nf_profile("easdf-1", "127.0.0.1", 7777);
        let names: Vec<&str> = profile["nfServices"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|s| s["serviceName"].as_str())
            .collect();
        assert!(names.contains(&"neasdf-dnscontext"), "got {names:?}");
        assert!(
            names.contains(&"neasdf-baselinednspattern"),
            "the second EASDF service must be advertised, got {names:?}"
        );
    }
}
