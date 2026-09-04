//! NextGCore NEF — Network Exposure Function (TS 23.501 §6.2.5).
//!
//! Minimal NEF (issue #19): exposes 5GC event services to external
//! Application Functions (AFs) and translates northbound requests into
//! internal service calls toward the 5GC producers.
//!
//! Northbound security (issue #110, TS 33.501 §5.9.2.3 / §12.1):
//! - The **SUPI is never sent to an AF**. Notifications echo the external
//!   identity the AF itself supplied; see [`build_monitoring_notification`].
//! - A monitoring request must resolve to **exactly one UE**. A GPSI is
//!   translated via UDM and an unresolvable target is refused — it is never
//!   widened to a network-wide `anyUE` subscription, which the
//!   [`SouthboundTarget`] type now makes unrepresentable.
//! - Caller authentication (OAuth2 and/or mTLS) is **default-off** for
//!   matched-simulator parity; when enabled, subscription ownership is keyed to
//!   the authenticated identity rather than the caller-supplied `{scsAsId}`.
//!   With it off, the NF logs a warning at startup and must not face an
//!   untrusted network.
//!
//! Served surfaces:
//! - **Monitoring Event** northbound API (TS 29.122 §5.3):
//!   `POST/DELETE /3gpp-monitoring-event/v1/{scsAsId}/subscriptions[/{subId}]`.
//!   A create is translated into a southbound subscription toward AMF
//!   `Namf_EventExposure` (TS 29.518) or UDM `Nudm_EE` (TS 29.503).
//! - **Device Triggering** northbound API (TS 29.122 §5.10):
//!   `POST /3gpp-device-triggering/v1/{scsAsId}/transactions`.
//! - **Producer notification sink** under the advertised
//!   `nnef-eventexposure` service: `POST /nnef-eventexposure/v1/notify/{subId}`
//!   receives AMF/UDM event notifications and forwards them to the AF's
//!   `notificationDestination` as a TS 29.122 MonitoringNotification.
//!
//! The NF registers with the NRF as `nfType: NEF` advertising the
//! `nnef-eventexposure` service (TS 29.591), mirroring the nwdafd
//! registration pattern.
//!
//! Scope notes (issue #19): PFD management (`nnef-pfdmanagement`), traffic
//! influence, and parameter provision are out of scope. Southbound
//! subscription establishment is best-effort: when no producer URI is
//! configured (`--amf-uri` / `--udm-uri`) or the producer is unreachable,
//! the northbound subscription is still created and the southbound leg is
//! deferred (logged) — the same degraded-operation stance the other NFs take
//! toward NRF registration failures.

use anyhow::{Context, Result};
use clap::Parser;
use nextgcore_sbi::client::{SbiClient, SbiClientConfig};
use nextgcore_sbi::context::SbiContext;
use nextgcore_sbi::message::{SbiRequest, SbiResponse};
use nextgcore_sbi::server::{
    send_bad_request, send_error, send_internal_error, send_method_not_allowed, send_not_found,
    SbiServer, SbiServerConfig,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod context;

pub use context::*;

/// Northbound TS 29.122 MonitoringType values this minimal NEF accepts.
/// Each translates to a southbound producer event (see
/// [`build_southbound_subscribe`]):
/// - `LOCATION_REPORTING`   → AMF `LOCATION_REPORT` (TS 29.518)
/// - `UE_REACHABILITY`      → AMF `REACHABILITY_REPORT` (TS 29.518)
/// - `LOSS_OF_CONNECTIVITY` → UDM Nudm_EE `LOSS_OF_CONNECTIVITY` (TS 29.503)
const SUPPORTED_MONITORING_TYPES: &[&str] = &[
    "LOCATION_REPORTING",
    "UE_REACHABILITY",
    "LOSS_OF_CONNECTIVITY",
];

/// Bounded timeouts for southbound subscribe / notification forwarding so a
/// hung producer or AF cannot stall the serving handler (parity with amfd's
/// notification client, `namf_server::notify_client`).
const SOUTHBOUND_CONNECT_TIMEOUT_SECS: u64 = 2;
const SOUTHBOUND_REQUEST_TIMEOUT_SECS: u64 = 3;

/// NextGCore NEF - Network Exposure Function
#[derive(Parser, Debug)]
#[command(name = "nextgcore-nefd")]
#[command(author = "NextGCore")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "5G Core Network Exposure Function (TS 23.501 6.2.5)", long_about = None)]
struct Args {
    #[arg(short = 'c', long, default_value = "/etc/nextgcore/nef.yaml")]
    config: String,

    /// JSON snapshot file for northbound monitoring subscriptions and device
    /// triggering transactions (issue #66/#192).
    ///
    /// Falls back to `NEXTGCORE_NEF_STATE_FILE`; an empty value is treated as
    /// unset. With neither set the NEF is memory-only, which is the shipped
    /// default and byte-identical to previous behaviour. An unreadable snapshot
    /// FAILS STARTUP rather than coming up empty and overwriting it.
    #[arg(long)]
    state_file: Option<String>,

    #[arg(short = 'l', long)]
    log_file: Option<String>,

    #[arg(short = 'e', long, default_value = "info")]
    log_level: String,

    #[arg(short = 'm', long)]
    no_color: bool,

    #[arg(long, default_value = "0.0.0.0")]
    sbi_addr: String,

    #[arg(long, default_value = "7817")]
    sbi_port: u16,

    #[arg(long)]
    tls: bool,

    #[arg(long)]
    tls_cert: Option<String>,

    #[arg(long)]
    tls_key: Option<String>,

    /// Require and verify a client certificate on the northbound surface
    /// (mutual TLS, TS 33.501 §12.1) — issue #110.
    ///
    /// Only meaningful with `--tls`. When on, the verified certificate's URI SAN
    /// becomes the authenticated client identity that subscription ownership is
    /// keyed to, instead of the caller-supplied `{scsAsId}` path segment.
    #[arg(long)]
    verify_client: bool,

    /// CA bundle used to verify client certificates when `--verify-client` is
    /// set. Defaults to the SBI layer's own trust configuration.
    #[arg(long)]
    verify_client_cacert: Option<String>,

    /// UDM SBI base URI used to resolve an AF-supplied GPSI (`msisdn`/
    /// `externalId`) to the internal SUPI via TS 29.503
    /// `id-translation-result` (issue #110).
    ///
    /// Defaults to `--udm-uri` when unset, since that is the same UDM. With
    /// neither configured, GPSI-targeted monitoring requests are REFUSED rather
    /// than widened to a network-wide subscription.
    #[arg(long)]
    udm_sdm_uri: Option<String>,

    #[arg(long, default_value = "http://127.0.0.1:7777")]
    nrf_uri: String,

    /// NF instance ID
    #[arg(long)]
    nf_instance_id: Option<String>,

    /// AMF SBI base URI for southbound Namf_EventExposure subscriptions
    /// (e.g. http://127.0.0.1:7777). When unset, AMF-routed monitoring types
    /// are stored northbound-only and the southbound subscribe is deferred.
    #[arg(long)]
    amf_uri: Option<String>,

    /// UDM SBI base URI for southbound Nudm_EE subscriptions. When unset,
    /// UDM-routed monitoring types are stored northbound-only and the
    /// southbound subscribe is deferred.
    #[arg(long)]
    udm_uri: Option<String>,

    /// Externally routable base URI of this NEF's SBI server, used as the
    /// prefix of the notification callback handed to AMF/UDM. Defaults to
    /// http://{sbi-addr}:{sbi-port}; set explicitly when --sbi-addr is a
    /// wildcard bind address.
    #[arg(long)]
    notify_base: Option<String>,

    /// Maximum stored northbound monitoring subscriptions.
    #[arg(long, default_value = "4096")]
    max_subscriptions: usize,

    /// Maximum stored device triggering transactions.
    #[arg(long, default_value = "4096")]
    max_transactions: usize,
}

// ---------------------------------------------------------------------------
// Northbound authentication (issue #110; TS 33.501 §12.1)
//
// TS 33.501 §12.1 makes mutual authentication between the NEF and the AF
// mandatory, and requires the NEF to authorise each AF request. Before this the
// northbound surface had neither: any caller could create, read or delete
// subscriptions, and ownership was asserted from the caller-supplied `{scsAsId}`
// path segment, so one client could delete another's subscriptions by naming
// their ID.
//
// Enforcement is default-OFF, following the staging the issue's own
// "Feature-gating" section allows and the pattern dccfd/nwdafd already use, so
// the matched-simulator E2E path is byte-unchanged. The privacy fixes (SUPI
// stripping, no anyUE widening) are NOT gated — they are corrections, not
// optional capabilities.
//
// CONFORMANCE NOTE: the token mechanism here is the operator-internal one (an
// NRF-issued OAuth2 token verified against the NRF JWKS), because that is what
// this repo has. TS 33.501 §12.1's AF-facing tokens are not necessarily
// NRF-issued. The properties that matter hold under either: no unauthenticated
// access, and an identity the NEF verified rather than one the caller typed.
// ---------------------------------------------------------------------------

/// What the northbound listener actually verifies. Set once at startup.
///
/// This is process configuration rather than per-request state, and the handler
/// needs it to answer one question: *may the claims on this request be trusted?*
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NorthboundAuth {
    /// `require_oauth2` is set on the listener, so nextgcore-sbi verified the
    /// bearer token's signature, audience, scope and expiry **before** the
    /// handler ran (`libs/nextgcore-sbi/src/server.rs:386-398`).
    pub oauth2: bool,
    /// `verify_client` is set, so rustls verified the peer's certificate chain
    /// and `SbiRequest::peer_cert_nf_instance_id` is trustworthy (issue #186).
    pub mtls: bool,
}

impl NorthboundAuth {
    pub fn is_enforced(&self) -> bool {
        self.oauth2 || self.mtls
    }
}

/// The northbound auth posture, set once by `main()`.
static NORTHBOUND_AUTH: std::sync::OnceLock<NorthboundAuth> = std::sync::OnceLock::new();

fn northbound_auth() -> NorthboundAuth {
    NORTHBOUND_AUTH.get().copied().unwrap_or_default()
}

/// The authenticated identity of the caller, or `None` when the request carries
/// no identity this process verified (issue #110).
///
/// Order matters. A certificate **this process** verified outranks a token,
/// which in turn outranks anything in the URL:
///
/// 1. `peer_cert_nf_instance_id` — the URI SAN of a chain-verified client
///    certificate (issue #186). Only ever populated under `verify_client`.
/// 2. the `sub` claim of the bearer token.
/// 3. nothing.
///
/// **Why reading `sub` without re-verifying is sound, and only here.** The server
/// rejects an invalid token with 401 *before dispatch*, so by the time a handler
/// runs under `auth.oauth2` the signature, audience, scope and expiry have all
/// been checked and the claims are trustworthy. When `auth.oauth2` is false
/// nothing was checked, and an attacker could set any `sub` it liked — so the
/// claim is ignored entirely in that case. The `auth.oauth2` guard below is
/// therefore load-bearing, not defensive: dropping it turns this function into an
/// impersonation primitive.
fn authenticated_client_id(request: &SbiRequest, auth: NorthboundAuth) -> Option<String> {
    if auth.mtls {
        if let Some(id) = request.peer_cert_nf_instance_id.as_deref() {
            if !id.is_empty() {
                return Some(id.to_string());
            }
        }
    }
    if auth.oauth2 {
        return bearer_subject(request.http.get_header("authorization")?);
    }
    None
}

/// The `sub` claim of a Bearer token, without verifying it.
///
/// **Never call this outside [`authenticated_client_id`]'s `auth.oauth2` branch**
/// — see that function for why the guard is what makes reading unverified claims
/// safe. Split out only so the claim decoding is unit-testable.
fn bearer_subject(authorization: &str) -> Option<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let token = authorization
        .strip_prefix("Bearer ")
        .or_else(|| authorization.strip_prefix("bearer "))?
        .trim();
    // header.payload.signature — the claims are the middle segment.
    let payload = token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    claims
        .get("sub")?
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Parse the opt-in `sbi.oauth2.require` knob (dccfd/nwdafd parity). Default
/// false so the matched-sim path is untouched. Honors
/// `NEXTGCORE_SBI_OAUTH2_REQUIRE` first (overlay-friendly), then the yaml
/// `<nf>.sbi.oauth2.require` (root-key agnostic: true iff any top-level section
/// sets it).
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

/// Apply OAuth2 producer enforcement, with the audience scoped to `NEF`
/// (TS 29.510 §5.4.2). With no NRF URI it fails closed (503) rather than
/// accepting unverifiable tokens.
fn apply_oauth2_enforcement(mut cfg: SbiServerConfig, nrf_uri: &str) -> SbiServerConfig {
    cfg.require_oauth2 = true;
    let uri = (!nrf_uri.is_empty()).then_some(nrf_uri);
    cfg.oauth2_jwks_uri = uri.map(|u| {
        nextgcore_sbi::oauth::JwksCache::for_nrf(u)
            .jwks_uri()
            .to_string()
    });
    cfg = cfg.with_expected_audience_nf_type(nextgcore_sbi::types::NfType::Nef);
    log::info!(
        "NEF northbound OAuth2 enforcement enabled (JWKS: {})",
        cfg.oauth2_jwks_uri.as_deref().unwrap_or("UNCONFIGURED")
    );
    cfg
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

    log::info!("NextGCore NEF v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Network Exposure Function (TS 23.501 6.2.5; TS 29.122 northbound)");

    nef_context_init(args.max_subscriptions, args.max_transactions);

    // Issue #66/#192: restore durable state BEFORE the SBI server can accept a
    // subscription, so a restored record is never shadowed by a fresh one.
    // Precedence matches the other NFs: the flag wins over the env var, and an
    // empty value is treated as unset rather than as a path.
    let state_file = args
        .state_file
        .clone()
        .or_else(|| std::env::var("NEXTGCORE_NEF_STATE_FILE").ok())
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty());
    if let Some(path) = state_file {
        let ctx = context::nef_self();
        let mut guard = ctx
            .write()
            .map_err(|_| anyhow::anyhow!("NEF context lock poisoned"))?;
        // Fail STARTUP on an unreadable snapshot. Coming up empty would answer
        // "no such subscription" for AF subscriptions that exist, and the store
        // would then refuse every later write to protect the file -- so the NF
        // would be running in a state that is neither durable nor honest.
        let restored = guard.set_state_file(std::path::PathBuf::from(&path))?;
        log::info!("NEF durable state: {path} ({restored} record(s) restored)");
    } else {
        log::info!(
            "NEF durable state disabled (no --state-file / NEXTGCORE_NEF_STATE_FILE): \
             subscriptions and transactions are memory-only and lost on restart"
        );
    }

    let nf_instance_id = args
        .nf_instance_id
        .clone()
        .unwrap_or_else(|| format!("nef-{}", uuid::Uuid::new_v4()));

    let notify_base = args
        .notify_base
        .clone()
        .unwrap_or_else(|| format!("http://{}:{}", args.sbi_addr, args.sbi_port));
    {
        let ctx = nef_self();
        if let Ok(mut context) = ctx.write() {
            context.set_endpoints(
                args.amf_uri.clone(),
                args.udm_uri.clone(),
                Some(notify_base),
                Some(nf_instance_id.clone()),
            );
            // Issue #110: GPSI→SUPI resolution target; defaults to --udm-uri.
            context.set_udm_sdm_uri(args.udm_sdm_uri.clone());
            if context.udm_sdm_uri().is_none() {
                log::warn!(
                    "no --udm-sdm-uri or --udm-uri configured: AF monitoring requests that target \
                     a UE by msisdn/externalId will be REFUSED, because the GPSI cannot be \
                     resolved to a SUPI (TS 33.501 §5.9.2.3). This is deliberate -- the previous \
                     behaviour widened such requests to a network-wide anyUE subscription."
                );
            }
        };
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    setup_signal_handlers(shutdown.clone());

    let addr: SocketAddr = format!("{}:{}", args.sbi_addr, args.sbi_port)
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

    // Issue #110 / TS 33.501 §12.1: northbound authentication. Default OFF, so
    // the shipped matched-sim path is byte-unchanged; the privacy fixes in this
    // same change are unconditional.
    let oauth2 = oauth2_required(&args.config);
    if oauth2 {
        sbi_server_config = apply_oauth2_enforcement(sbi_server_config, &args.nrf_uri);
    }
    let mtls = args.verify_client;
    if mtls {
        if !args.tls {
            // Fail startup rather than run with an option that silently does
            // nothing: --verify-client without --tls reads as "mutual TLS is on"
            // while the listener is plaintext and every request is unauthenticated.
            anyhow::bail!(
                "--verify-client requires --tls: there is no client certificate to verify on a \
                 plaintext listener, and starting anyway would present an unauthenticated \
                 northbound surface as an authenticated one"
            );
        }
        sbi_server_config.verify_client = true;
        sbi_server_config.verify_client_cacert = args.verify_client_cacert.clone();
    }
    let auth = NorthboundAuth { oauth2, mtls };
    let _ = NORTHBOUND_AUTH.set(auth);
    if auth.is_enforced() {
        log::info!(
            "NEF northbound authentication: oauth2={oauth2}, mtls={mtls}; subscription ownership \
             is keyed to the authenticated identity"
        );
    } else {
        log::warn!(
            "NEF northbound authentication DISABLED (no nef.sbi.oauth2.require / \
             NEXTGCORE_SBI_OAUTH2_REQUIRE, no --verify-client): any caller can create and delete \
             monitoring subscriptions, and ownership falls back to the caller-supplied scsAsId \
             path segment. Do not expose this listener to an untrusted or partner-facing network \
             (TS 33.501 §12.1)."
        );
    }

    let sbi_server = SbiServer::new(sbi_server_config);
    log::info!("Starting NEF SBI server on {addr}");
    sbi_server
        .start(nef_sbi_request_handler)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start SBI server: {e}"))?;

    // Register with NRF as nfType NEF advertising nnef-eventexposure
    // (registration failure is non-fatal, mirroring nwdafd).
    let sbi_ctx = nextgcore_sbi::context::global_context();
    sbi_ctx.set_nrf_uri(&args.nrf_uri).await;
    if let Err(e) = register_with_nrf(sbi_ctx, &args.sbi_addr, args.sbi_port, &nf_instance_id).await
    {
        log::warn!("NRF registration failed (will operate without NRF): {e}");
    } else {
        // PATCH a real NFProfile "/load" gauge to NRF each heartbeat: active
        // monitoring subscriptions, saturated at 100 (TS 29.510 §5.2.2.3.2).
        nextgcore_sbi::heartbeat::spawn_heartbeat_worker_with_load(
            nf_instance_id.clone(),
            5,
            || {
                let load = nef_self()
                    .read()
                    .map(|c| c.subscription_count())
                    .unwrap_or(0);
                load.min(100) as u8
            },
        );
    }

    log::info!("NextGCore NEF ready (instance: {nf_instance_id})");

    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    log::info!("Shutting down...");
    sbi_server
        .stop()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to stop SBI server: {e}"))?;
    nef_context_final();
    log::info!("NEF shutdown complete");

    Ok(())
}

/// NEF SBI request handler
async fn nef_sbi_request_handler(request: SbiRequest) -> SbiResponse {
    let method = request.header.method.as_str();
    let uri = &request.header.uri;

    log::debug!("NEF SBI: {method} {uri}");

    let path = uri.split('?').next().unwrap_or(uri);
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match parts.as_slice() {
        // Monitoring Event northbound API (TS 29.122 §5.3)
        ["3gpp-monitoring-event", "v1", scs_as_id, "subscriptions"] => match method {
            "POST" => handle_monitoring_subscription_create(scs_as_id, &request).await,
            _ => send_method_not_allowed(method, "subscriptions"),
        },
        ["3gpp-monitoring-event", "v1", scs_as_id, "subscriptions", sub_id] => match method {
            "DELETE" => handle_monitoring_subscription_delete(scs_as_id, sub_id, &request).await,
            _ => send_method_not_allowed(method, "subscriptions/{subscriptionId}"),
        },
        // Device Triggering northbound API (TS 29.122 §5.10)
        ["3gpp-device-triggering", "v1", scs_as_id, "transactions"] => match method {
            "POST" => handle_device_triggering_create(scs_as_id, &request).await,
            _ => send_method_not_allowed(method, "transactions"),
        },
        // Producer (AMF/UDM) notification sink; the NEF subscription ID is
        // embedded in the callback path handed to the producer.
        ["nnef-eventexposure", "v1", "notify", nef_sub_id] => match method {
            "POST" => handle_producer_notification(nef_sub_id, &request).await,
            _ => send_method_not_allowed(method, "notify/{subscriptionId}"),
        },
        _ => send_not_found(&format!("Resource not found: {path}"), None),
    }
}

/// POST /3gpp-monitoring-event/v1/{scsAsId}/subscriptions —
/// TS 29.122 §5.3 Monitoring Event subscription create. Validates the AF
/// request (mandatory-IE parity with udmd's `handle_ee_subscribe`),
/// translates it into a southbound producer subscription (best-effort),
/// stores the northbound↔southbound mapping, and returns 201 with Location.
async fn handle_monitoring_subscription_create(
    scs_as_id: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    // Mandatory IEs per TS 29.122 Table 5.3.2.1.2-1.
    let notification_destination =
        match data.get("notificationDestination").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => {
                return send_bad_request(
                    "notificationDestination is mandatory",
                    Some("MANDATORY_IE_MISSING"),
                )
            }
        };
    if parse_http_uri(&notification_destination).is_none() {
        return send_bad_request(
            "notificationDestination is not a valid HTTP URI",
            Some("MANDATORY_IE_INCORRECT"),
        );
    }
    let monitoring_type = match data.get("monitoringType").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return send_bad_request("monitoringType is mandatory", Some("MANDATORY_IE_MISSING")),
    };
    if !SUPPORTED_MONITORING_TYPES.contains(&monitoring_type.as_str()) {
        return send_bad_request(
            &format!(
                "unsupported monitoringType '{monitoring_type}' (supported: {SUPPORTED_MONITORING_TYPES:?})"
            ),
            Some("MANDATORY_IE_INCORRECT"),
        );
    }

    // Target UE identity. TS 29.122 names the UE by msisdn/externalId; supi is
    // accepted as a NextGCore-internal extension.
    let supi = data.get("supi").and_then(|v| v.as_str());
    let msisdn = data.get("msisdn").and_then(|v| v.as_str());
    let external_id = data.get("externalId").and_then(|v| v.as_str());

    // Issue #110: `externalGroupId` is TS 29.122's GROUP form. Rejected rather
    // than ignored, because ignoring it is how the original defect behaved: the
    // group identifier fell through to no-identity, and no-identity became a
    // network-wide `anyUE` subscription. Serving it needs a group→internal
    // mapping this repo does not have, and inventing one would repeat the
    // mistake. Filed as a follow-up.
    if data
        .get("externalGroupId")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty())
    {
        return send_bad_request(
            "externalGroupId (group-scoped monitoring) is not supported by this NEF; \
             subscribe per UE with msisdn or externalId",
            Some("MANDATORY_IE_INCORRECT"),
        );
    }
    // The identity is interpolated into southbound resource paths
    // (/nudm-ee/v1/{ueIdentity}/...), so reject anything outside the
    // SUPI/GPSI character set up front (path-injection guard).
    for (field, value) in [
        ("supi", supi),
        ("msisdn", msisdn),
        ("externalId", external_id),
    ] {
        if let Some(value) = value {
            if !valid_ue_identity(value) {
                return send_bad_request(
                    &format!("{field} contains characters outside the SUPI/GPSI identity set"),
                    Some("MANDATORY_IE_INCORRECT"),
                );
            }
        }
    }

    // Issue #110: the external identity the AF used, kept so notifications can
    // echo it back instead of the SUPI. `externalId` is preferred over `msisdn`
    // when both are present, matching the southbound preference order that was
    // already here.
    let af_target = external_id
        .map(|e| AfTarget::ExternalId(e.to_string()))
        .or_else(|| msisdn.map(|m| AfTarget::Msisdn(m.to_string())));

    // Snapshot endpoint config out of the context so no lock is held across
    // the southbound await.
    let ctx = nef_self();
    let (notify_base, amf_uri, udm_uri, udm_sdm_uri, nf_instance_id) = match ctx.read() {
        Ok(c) => (
            c.notify_base(),
            c.amf_uri(),
            c.udm_uri(),
            c.udm_sdm_uri(),
            c.nf_instance_id(),
        ),
        Err(_) => return send_internal_error("NEF context lock poisoned"),
    };

    // Issue #110: resolve the target to exactly one UE, or refuse.
    //
    // This is where the anyUE widening died. Previously an unresolvable or
    // GPSI-only target fell through to `anyUE`, turning a request for one
    // subscriber into a network-wide feed. Now: a SUPI is used directly (the
    // NextGCore extension), a GPSI is translated via UDM (TS 33.501 §5.9.2.3),
    // and anything that cannot be resolved to a single UE is an error to the AF
    // with NO southbound subscribe issued.
    let target = match supi {
        Some(supi) => SouthboundTarget::Supi(supi.to_string()),
        None => match &af_target {
            Some(t) => match resolve_gpsi_to_supi(udm_sdm_uri, &t.gpsi()).await {
                Some(resolved) => SouthboundTarget::Supi(resolved),
                None => {
                    // 404 rather than 500: TS 29.122's failure for a target the
                    // network cannot identify. The AF asked about a UE this
                    // network cannot resolve, which is its request's problem,
                    // and saying so is far better than silently subscribing to
                    // every UE instead.
                    log::warn!(
                        "monitoring subscription refused: {} '{}' could not be resolved to a SUPI",
                        t.member(),
                        t.value()
                    );
                    return send_not_found(
                        &format!(
                            "{} could not be resolved to a subscriber of this network",
                            t.member()
                        ),
                        Some("UE_NOT_FOUND"),
                    );
                }
            },
            None => {
                // No target at all. TS 29.122's monitoring types served here are
                // per-UE, so the identity is mandatory; this is NOT an implicit
                // request for network-wide scope.
                return send_bad_request(
                    "a target UE identity (msisdn or externalId) is mandatory for per-UE \
                     monitoring types",
                    Some("MANDATORY_IE_MISSING"),
                );
            }
        },
    };

    // Issue #110: ownership is keyed to an identity this process verified, not to
    // the caller-supplied {scsAsId} path segment.
    let owner_id = authenticated_client_id(request, northbound_auth());

    let sub = NefMonitoringSubscription::new(
        scs_as_id,
        &monitoring_type,
        &notification_destination,
        body.clone(),
    )
    .with_af_target(af_target)
    .with_owner_id(owner_id);

    let notify_base = notify_base.unwrap_or_else(|| "http://127.0.0.1:7817".to_string());
    let nf_instance_id = nf_instance_id.unwrap_or_else(|| "nef-unregistered".to_string());
    let nef_notify_uri = format!("{notify_base}/nnef-eventexposure/v1/notify/{}", sub.id);

    let southbound = match build_southbound_subscribe(
        &monitoring_type,
        &target,
        &nef_notify_uri,
        &sub.id,
        &nf_instance_id,
    ) {
        Some(req) => {
            let producer_uri = match req.producer {
                SouthboundProducer::Amf => amf_uri.clone(),
                SouthboundProducer::Udm => udm_uri.clone(),
            };
            attempt_southbound_subscribe(producer_uri, req).await
        }
        None => None,
    };

    let sub = NefMonitoringSubscription { southbound, ..sub };
    let sub_id = sub.id.clone();
    let southbound_cleanup = sub.southbound.clone();
    let ctx = nef_self();
    let insert = match ctx.read() {
        Ok(c) => c.subscription_insert(sub),
        Err(_) => Err(NefContextError::LockPoisoned),
    };
    if let Err(err) = insert {
        // The producer-side subscription was already established; tear it
        // down (best-effort) so the rejected northbound create does not
        // orphan it on the AMF/UDM.
        if let Some(southbound) = southbound_cleanup {
            let producer_uri = match southbound.producer {
                SouthboundProducer::Amf => amf_uri,
                SouthboundProducer::Udm => udm_uri,
            };
            southbound_unsubscribe(producer_uri, southbound).await;
        }
        return match err {
            NefContextError::MaxSubscriptionsReached => {
                send_error(507, "Insufficient Storage", err.detail(), Some(err.cause()))
            }
            _ => send_internal_error(err.detail()),
        };
    }

    let location = format!("/3gpp-monitoring-event/v1/{scs_as_id}/subscriptions/{sub_id}");
    log::info!(
        "Monitoring event subscription created: id={sub_id}, scsAsId={scs_as_id}, type={monitoring_type}"
    );
    // TS 29.122: 201 echoes the created MonitoringEventSubscription with its
    // `self` link.
    let mut echoed = data;
    if let Some(obj) = echoed.as_object_mut() {
        obj.insert("self".to_string(), serde_json::json!(location));
    }
    SbiResponse::with_status(201)
        .with_header("Location", location)
        .with_json_body(&echoed)
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// DELETE /3gpp-monitoring-event/v1/{scsAsId}/subscriptions/{subId} —
/// TS 29.122 §5.3 unsubscribe. Tears the southbound producer subscription
/// down (best-effort) and removes the northbound mapping.
///
/// Issue #110: the subscription must belong to the **authenticated** caller. A
/// subscription created under authentication can only be deleted by the identity
/// that created it, so supplying another client's `{scsAsId}` in the path no
/// longer works — that segment is caller-controlled and confers nothing. With no
/// northbound authentication configured the check degrades to the historical
/// `scsAsId` comparison. Either way a caller that is not the owner gets 404, not
/// 403: whether that subscription exists is not information it is entitled to.
async fn handle_monitoring_subscription_delete(
    scs_as_id: &str,
    sub_id: &str,
    request: &SbiRequest,
) -> SbiResponse {
    let ctx = nef_self();
    let (sub, amf_uri, udm_uri) = match ctx.read() {
        Ok(c) => (c.subscription_find(sub_id), c.amf_uri(), c.udm_uri()),
        Err(_) => return send_internal_error("NEF context lock poisoned"),
    };
    let caller_id = authenticated_client_id(request, northbound_auth());
    let sub = match sub {
        Some(s) if s.is_owned_by(caller_id.as_deref(), scs_as_id) => s,
        Some(_) => {
            log::warn!(
                "monitoring subscription delete refused: {sub_id} is not owned by the requesting \
                 client (scsAsId={scs_as_id}, authenticated={caller_id:?})"
            );
            return send_not_found(
                &format!("Subscription {sub_id} not found"),
                Some("SUBSCRIPTION_NOT_FOUND"),
            );
        }
        None => {
            return send_not_found(
                &format!("Subscription {sub_id} not found"),
                Some("SUBSCRIPTION_NOT_FOUND"),
            )
        }
    };

    if let Some(southbound) = &sub.southbound {
        let producer_uri = match southbound.producer {
            SouthboundProducer::Amf => amf_uri,
            SouthboundProducer::Udm => udm_uri,
        };
        southbound_unsubscribe(producer_uri, southbound.clone()).await;
    }

    {
        let ctx = nef_self();
        if let Ok(c) = ctx.read() {
            c.subscription_remove(sub_id);
        };
    }
    log::info!("Monitoring event subscription removed: id={sub_id}, scsAsId={scs_as_id}");
    SbiResponse::with_status(204)
}

/// POST /3gpp-device-triggering/v1/{scsAsId}/transactions — TS 29.122 §5.10
/// Device Triggering create. Validates and stores the transaction.
///
/// DEFERRED (issue #19 scope): forwarding the trigger toward SMS delivery is
/// stubbed — no SMSF NF exists in this repo (`NfType::Smsf` is a routing
/// label only), so the transaction is validated, stored, and reported with
/// DeliveryResult `TRIGGERED`.
async fn handle_device_triggering_create(scs_as_id: &str, request: &SbiRequest) -> SbiResponse {
    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let data: serde_json::Value = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    // Mandatory IEs per TS 29.122 Table 5.10.2.1.2-1: a target UE identifier
    // (msisdn / externalId; supi accepted as an internal extension) and the
    // trigger payload.
    let has_target = ["msisdn", "externalId", "supi"].iter().any(|key| {
        data.get(*key)
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    });
    if !has_target {
        return send_bad_request(
            "target UE identifier (msisdn / externalId) is mandatory",
            Some("MANDATORY_IE_MISSING"),
        );
    }
    match data.get("triggerPayload").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => {}
        _ => return send_bad_request("triggerPayload is mandatory", Some("MANDATORY_IE_MISSING")),
    }

    let txn = NefTriggerTransaction::new(scs_as_id, "TRIGGERED", body.clone());
    let txn_id = txn.id.clone();
    let ctx = nef_self();
    let insert = match ctx.read() {
        Ok(c) => c.transaction_insert(txn),
        Err(_) => Err(NefContextError::LockPoisoned),
    };
    match insert {
        Ok(()) => {}
        Err(err @ NefContextError::MaxTransactionsReached) => {
            return send_error(507, "Insufficient Storage", err.detail(), Some(err.cause()))
        }
        Err(err) => return send_internal_error(err.detail()),
    }

    let location = format!("/3gpp-device-triggering/v1/{scs_as_id}/transactions/{txn_id}");
    log::info!("Device triggering transaction created: id={txn_id}, scsAsId={scs_as_id}");
    let mut echoed = data;
    if let Some(obj) = echoed.as_object_mut() {
        obj.insert("self".to_string(), serde_json::json!(location));
        obj.insert("deliveryResult".to_string(), serde_json::json!("TRIGGERED"));
    }
    SbiResponse::with_status(201)
        .with_header("Location", location)
        .with_json_body(&echoed)
        .unwrap_or_else(|_| SbiResponse::with_status(201))
}

/// POST /nnef-eventexposure/v1/notify/{nefSubId} — producer notification
/// sink. Correlates the AMF/UDM notification back to the northbound AF
/// subscription and forwards it as a TS 29.122 MonitoringNotification on a
/// background task (fire-and-forget, amfd delivery parity), so the
/// producer's notify timeout never includes the AF round trip.
async fn handle_producer_notification(nef_sub_id: &str, request: &SbiRequest) -> SbiResponse {
    let ctx = nef_self();
    let sub = match ctx.read() {
        Ok(c) => c.subscription_find(nef_sub_id),
        Err(_) => return send_internal_error("NEF context lock poisoned"),
    };
    let Some(sub) = sub else {
        return send_not_found(
            &format!("Subscription {nef_sub_id} not found"),
            Some("SUBSCRIPTION_NOT_FOUND"),
        );
    };

    let body = match &request.http.content {
        Some(c) => c,
        None => return send_bad_request("Missing request body", Some("MISSING_BODY")),
    };
    let producer_body: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return send_bad_request(&format!("Invalid JSON: {e}"), Some("INVALID_JSON")),
    };

    let notification = build_monitoring_notification(&sub, &producer_body);
    let destination = sub.notification_destination.clone();
    tokio::spawn(async move {
        forward_notification_to_af(destination, notification).await;
    });

    SbiResponse::no_content()
}

/// A fully built southbound subscribe request toward a 5GC event producer.
#[derive(Debug)]
pub struct SouthboundSubscribe {
    pub producer: SouthboundProducer,
    pub path: String,
    pub body: serde_json::Value,
}

/// Who a southbound subscription is for (issue #110).
///
/// **This type exists to make the anyUE widening unrepresentable.** The previous
/// signature took `supi: Option<&str>` and did `None => anyUE`, so *absence of
/// an identity* silently became *every UE in the network*: an AF naming one UE by
/// `msisdn` or `externalId` — both valid TS 29.122 targets that this function
/// never read — received a network-wide feed.
///
/// Making the target an explicit enum means a caller must **choose** [`AnyUe`],
/// so no future edit can reintroduce the widening by forgetting a check. A
/// handler-side guard would have left that possible; the type does not.
///
/// [`AnyUe`]: SouthboundTarget::AnyUe
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SouthboundTarget {
    /// One UE, named by its resolved internal identity.
    Supi(String),
    /// Every UE (TS 29.518 `anyUE`, TS 29.503 ueIdentity `anyUE`).
    ///
    /// A faithful encoding of a real producer-side capability, kept for the
    /// group/any-UE feature TS 29.122 will eventually need. **No northbound
    /// request path constructs it** — the three monitoring types this NEF serves
    /// are per-UE and their target is mandatory, so an AF cannot reach it. That
    /// property is asserted by `no_northbound_input_can_produce_any_ue`.
    AnyUe,
}

/// Translate a northbound TS 29.122 MonitoringType into the southbound
/// producer subscribe request (the northbound→southbound mapping):
///
/// - `LOCATION_REPORTING` / `UE_REACHABILITY` → AMF Namf_EventExposure
///   (TS 29.518 §5.3.2.2.2): `POST /namf-evts/v1/subscriptions` with the
///   mandatory `subscription` wrapper (`eventList`, `eventNotifyUri`,
///   `notifyCorrelationId`, `nfId`, and `supi` or `anyUE`).
/// - `LOSS_OF_CONNECTIVITY` → UDM Nudm_EE (TS 29.503 §5.5.2.2):
///   `POST /nudm-ee/v1/{ueIdentity}/ee-subscriptions` with the mandatory
///   `callbackReference` + `monitoringConfigurations`.
///
/// Returns None for unsupported monitoring types.
///
/// `target` is an explicit [`SouthboundTarget`] rather than an optional SUPI: see
/// that type for why absence-of-identity must not be expressible here (issue
/// #110).
fn build_southbound_subscribe(
    monitoring_type: &str,
    target: &SouthboundTarget,
    nef_notify_uri: &str,
    nef_correlation_id: &str,
    nf_instance_id: &str,
) -> Option<SouthboundSubscribe> {
    match monitoring_type {
        "LOCATION_REPORTING" | "UE_REACHABILITY" => {
            let event_type = if monitoring_type == "LOCATION_REPORTING" {
                "LOCATION_REPORT"
            } else {
                "REACHABILITY_REPORT"
            };
            let mut subscription = serde_json::json!({
                "eventList": [ { "type": event_type } ],
                "eventNotifyUri": nef_notify_uri,
                "notifyCorrelationId": nef_correlation_id,
                "nfId": nf_instance_id,
            });
            // TS 29.518: the subscription must target a UE (supi) or anyUE.
            match target {
                SouthboundTarget::Supi(supi) => subscription["supi"] = serde_json::json!(supi),
                SouthboundTarget::AnyUe => subscription["anyUE"] = serde_json::json!(true),
            }
            Some(SouthboundSubscribe {
                producer: SouthboundProducer::Amf,
                path: "/namf-evts/v1/subscriptions".to_string(),
                body: serde_json::json!({ "subscription": subscription }),
            })
        }
        "LOSS_OF_CONNECTIVITY" => {
            // TS 29.503 ueIdentity: a SUPI, or the literal "anyUE".
            //
            // The GPSI forms this used to accept here are gone on purpose: the
            // handler now resolves a GPSI to a SUPI before calling us (issue
            // #110), so there is one identity kind on this path instead of a
            // three-way fallback whose last arm was `anyUE`.
            let ue_identity = match target {
                SouthboundTarget::Supi(supi) => supi.as_str(),
                SouthboundTarget::AnyUe => "anyUE",
            };
            Some(SouthboundSubscribe {
                producer: SouthboundProducer::Udm,
                path: format!("/nudm-ee/v1/{ue_identity}/ee-subscriptions"),
                body: serde_json::json!({
                    "callbackReference": nef_notify_uri,
                    "monitoringConfigurations": {
                        "1": { "eventType": "LOSS_OF_CONNECTIVITY" }
                    }
                }),
            })
        }
        _ => None,
    }
}

/// Resolve an AF-supplied GPSI to the internal SUPI via UDM
/// (TS 29.503 §6.1.3.3.3 `GET /nudm-sdm/v2/{gpsi}/id-translation-result`,
/// response `IdTranslationResult { supi, gpsi }`) — issue #110.
///
/// This is the identity translation TS 33.501 §5.9.2.3 requires of the NEF, and
/// TS 23.501 §6.2.5.0 names as one of its core functions.
///
/// **It fails closed, and that is the security fix.** Every failure — no UDM
/// configured, unreachable, non-200, or a body with no `supi` — returns `None`,
/// and the caller then REJECTS the subscription. What must never happen is the
/// old behaviour, where an unresolvable target fell through to a network-wide
/// `anyUE` subscription: a request the NEF could not satisfy became a request for
/// far more than was asked.
///
/// **Known gap, not a defect here:** this repo's own `udmd` answers this
/// operation `501 Not Implemented`
/// (`bins/nextgcore-udmd/src/app.rs:641-642`, tagged `udmd-12`), so against
/// nextgcore's UDM every GPSI-targeted monitoring request is refused. That is the
/// honest outcome and strictly better than the covert widening it replaces;
/// making it *succeed* needs the UDM side, which belongs to #85.
async fn resolve_gpsi_to_supi(udm_uri: Option<String>, gpsi: &str) -> Option<String> {
    let Some(uri) = udm_uri else {
        log::warn!(
            "no UDM URI configured; cannot resolve GPSI '{gpsi}' to a SUPI \
             (subscription will be refused rather than widened to anyUE)"
        );
        return None;
    };
    let Some((host, port)) = parse_host_port(&uri) else {
        log::warn!("invalid UDM URI '{uri}'; GPSI '{gpsi}' not resolved");
        return None;
    };
    let client = bounded_client(&host, port);
    let path = format!("/nudm-sdm/v2/{gpsi}/id-translation-result");
    match client.get(&path).await {
        Ok(response) if response.status == 200 => {
            let supi = response
                .http
                .content
                .as_deref()
                .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
                .and_then(|v| v.get("supi")?.as_str().map(str::to_string));
            match supi {
                // A SUPI is interpolated into southbound resource paths, so it
                // gets the same character-set guard as an AF-supplied identity:
                // the UDM is more trusted than an AF, but "more trusted" is not
                // "unvalidated".
                Some(supi) if valid_ue_identity(&supi) => Some(supi),
                Some(bad) => {
                    log::warn!(
                        "UDM returned a SUPI outside the identity charset for '{gpsi}': {bad:?}"
                    );
                    None
                }
                None => {
                    log::warn!("UDM id-translation-result for '{gpsi}' carried no supi");
                    None
                }
            }
        }
        Ok(response) => {
            log::warn!(
                "UDM id-translation-result for '{gpsi}' returned status {}",
                response.status
            );
            None
        }
        Err(e) => {
            log::warn!("UDM id-translation-result for '{gpsi}' failed: {e}");
            None
        }
    }
}

/// POST the southbound subscribe to the producer and extract the created
/// subscription reference. Best-effort: any failure is logged and yields
/// None (northbound-only subscription).
async fn attempt_southbound_subscribe(
    producer_uri: Option<String>,
    req: SouthboundSubscribe,
) -> Option<SouthboundRef> {
    let producer = req.producer;
    let Some(uri) = producer_uri else {
        log::info!(
            "no {} URI configured; southbound subscription deferred",
            producer.as_str()
        );
        return None;
    };
    let Some((host, port)) = parse_host_port(&uri) else {
        log::warn!(
            "invalid {} URI '{uri}'; southbound subscription skipped",
            producer.as_str()
        );
        return None;
    };
    let client = bounded_client(&host, port);
    match client.post_json(&req.path, &req.body).await {
        Ok(response) if response.status == 200 || response.status == 201 => {
            let southbound = extract_southbound_ref(producer, &req.path, &response);
            if southbound.is_none() {
                log::warn!(
                    "{} subscribe succeeded but no subscription id could be extracted",
                    producer.as_str()
                );
            }
            southbound
        }
        Ok(response) => {
            log::warn!(
                "{} subscribe returned status {}",
                producer.as_str(),
                response.status
            );
            None
        }
        Err(e) => {
            log::warn!("{} subscribe failed: {e}", producer.as_str());
            None
        }
    }
}

/// Extract the producer-assigned subscription reference from a successful
/// subscribe response: prefer the Location header (both AMF and UDM set it),
/// fall back to the body (`subscriptionId` for AMF,
/// `eeSubscription.subscriptionId` for UDM).
fn extract_southbound_ref(
    producer: SouthboundProducer,
    subscribe_path: &str,
    response: &SbiResponse,
) -> Option<SouthboundRef> {
    if let Some(location) = response.http.get_header("location") {
        let delete_path = if location.starts_with("http://") || location.starts_with("https://") {
            parse_http_uri(location).map(|(_, _, path)| path)?
        } else {
            location.clone()
        };
        let subscription_id = delete_path
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())?
            .to_string();
        return Some(SouthboundRef {
            producer,
            subscription_id,
            delete_path,
        });
    }
    let body: serde_json::Value = serde_json::from_str(response.http.content.as_deref()?).ok()?;
    let subscription_id = match producer {
        SouthboundProducer::Amf => body.get("subscriptionId")?.as_str()?.to_string(),
        SouthboundProducer::Udm => body
            .pointer("/eeSubscription/subscriptionId")?
            .as_str()?
            .to_string(),
    };
    Some(SouthboundRef {
        producer,
        subscription_id: subscription_id.clone(),
        delete_path: format!("{subscribe_path}/{subscription_id}"),
    })
}

/// Best-effort DELETE of the southbound producer subscription.
async fn southbound_unsubscribe(producer_uri: Option<String>, southbound: SouthboundRef) {
    let producer = southbound.producer;
    let Some(uri) = producer_uri else {
        log::debug!(
            "no {} URI configured; southbound unsubscribe skipped",
            producer.as_str()
        );
        return;
    };
    let Some((host, port)) = parse_host_port(&uri) else {
        log::warn!(
            "invalid {} URI '{uri}'; southbound unsubscribe skipped",
            producer.as_str()
        );
        return;
    };
    let client = bounded_client(&host, port);
    match client.delete(&southbound.delete_path).await {
        Ok(response) if response.is_success() => {
            log::debug!(
                "{} subscription {} removed",
                producer.as_str(),
                southbound.subscription_id
            );
        }
        Ok(response) => {
            log::warn!(
                "{} unsubscribe returned status {}",
                producer.as_str(),
                response.status
            );
        }
        Err(e) => {
            log::warn!("{} unsubscribe failed: {e}", producer.as_str());
        }
    }
}

/// Build the TS 29.122 §5.3 MonitoringNotification forwarded to the AF's
/// notificationDestination from a producer notification body (AMF
/// AmfEventNotification `reportList`; UDM Nudm_EE bodies fall through to a
/// bare monitoringType report).
///
/// # The SUPI never crosses this boundary (issue #110)
///
/// TS 33.501 §5.9.2.3 requires the NEF to map between the internal subscriber
/// identity and the external one, and **not** to expose the SUPI to Application
/// Functions. This function used to copy the producer report's `supi` verbatim
/// into the AF-bound body — a permanent-identifier disclosure leaving the
/// operator trust boundary on every notification.
///
/// It now echoes the identity the AF itself supplied, read from the subscription
/// record ([`AfTarget`]) rather than from the producer report, in the same TS
/// 29.122 member the AF used. No lookup is needed: the AF told us this identity
/// when it subscribed.
///
/// When the AF targeted by the NextGCore-internal `supi` extension there is no
/// external identity to echo, and the identity is **omitted** rather than filled
/// in with the SUPI. That loses nothing the AF needs — it already knows which UE
/// it asked about, and the `subscription` self link identifies which
/// subscription this is.
fn build_monitoring_notification(
    sub: &NefMonitoringSubscription,
    producer_body: &serde_json::Value,
) -> serde_json::Value {
    let self_link = format!(
        "/3gpp-monitoring-event/v1/{}/subscriptions/{}",
        sub.scs_as_id, sub.id
    );
    // The AF's own identity for this UE, echoed in the member it used. Computed
    // once: it is a property of the subscription, not of the report.
    let af_identity = sub
        .af_target
        .as_ref()
        .map(|t| (t.member(), serde_json::json!(t.value())));

    let mut reports = Vec::new();
    if let Some(report_list) = producer_body.get("reportList").and_then(|v| v.as_array()) {
        for report in report_list {
            let mut out = serde_json::json!({ "monitoringType": sub.monitoring_type });
            if let Some(location) = report.get("location") {
                out["locationInfo"] = location.clone();
            }
            if report.get("reachability").and_then(|v| v.as_str()) == Some("REACHABLE") {
                out["reachabilityType"] = serde_json::json!("DATA");
            }
            // `report["supi"]` is deliberately NOT read. The producer sends the
            // internal identity; forwarding it is the leak this function exists
            // to prevent. Do not "restore" this for debugging convenience --
            // `af_bound_notification_never_contains_supi` fails if you do.
            if let Some((member, value)) = &af_identity {
                out[*member] = value.clone();
            }
            reports.push(out);
        }
    }
    if reports.is_empty() {
        let mut bare = serde_json::json!({ "monitoringType": sub.monitoring_type });
        if let Some((member, value)) = &af_identity {
            bare[*member] = value.clone();
        }
        reports.push(bare);
    }
    serde_json::json!({
        "subscription": self_link,
        "monitoringEventReports": reports,
    })
}

/// POST a MonitoringNotification to the AF's notificationDestination
/// (best-effort, bounded timeouts; failures are logged, no retry).
async fn forward_notification_to_af(destination: String, notification: serde_json::Value) {
    let Some((host, port, path)) = parse_http_uri(&destination) else {
        log::warn!("invalid notificationDestination '{destination}'; notification dropped");
        return;
    };
    let client = bounded_client(&host, port);
    match client.post_json(&path, &notification).await {
        Ok(response) if response.is_success() => {
            log::debug!("monitoring notification delivered to {destination}");
        }
        Ok(response) => {
            log::warn!(
                "monitoring notification to {destination} returned {}",
                response.status
            );
        }
        Err(e) => {
            log::warn!("monitoring notification to {destination} failed: {e}");
        }
    }
}

/// Build an SBI client with bounded connect/request timeouts (amfd
/// notification-client parity).
fn bounded_client(host: &str, port: u16) -> SbiClient {
    let config = SbiClientConfig::new(host, port)
        .with_connect_timeout(Duration::from_secs(SOUTHBOUND_CONNECT_TIMEOUT_SECS))
        .with_request_timeout(Duration::from_secs(SOUTHBOUND_REQUEST_TIMEOUT_SECS));
    SbiClient::new(config)
}

/// Build the NFProfile registered with the NRF (TS 29.510): nfType NEF
/// advertising the nnef-eventexposure service (TS 29.591).
fn build_nf_profile(nf_instance_id: &str, sbi_addr: &str, sbi_port: u16) -> serde_json::Value {
    serde_json::json!({
        "nfInstanceId": nf_instance_id,
        "nfType": "NEF",
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [sbi_addr],
        "nfServices": [
            {
                "serviceInstanceId": format!("{nf_instance_id}-nnef-eventexposure"),
                "serviceName": "nnef-eventexposure",
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": sbi_addr, "port": sbi_port}]
            }
        ],
        "allowedNfTypes": ["AF", "AMF", "UDM", "SCP"],
        "heartBeatTimer": 10
    })
}

/// Register NEF with NRF (PUT /nnrf-nfm/v1/nf-instances/{id}, nwdafd
/// pattern). Missing NRF URI skips registration; failure is reported to the
/// caller, which treats it as non-fatal.
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

    log::info!("Registering NEF with NRF at {nrf_uri}");

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
            log::info!("NEF registered with NRF successfully (id={nf_instance_id})");

            let mut self_instance = nextgcore_sbi::context::NfInstance::new(
                nf_instance_id,
                nextgcore_sbi::types::NfType::Nef,
            );
            self_instance.ipv4_addresses = vec![sbi_addr.to_string()];
            let mut svc = nextgcore_sbi::context::NfService::new(
                "nnef-eventexposure",
                nextgcore_sbi::types::SbiServiceType::NnefEventexposure,
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

/// Parse an absolute HTTP(S) URI into (host, port, path). Returns None for
/// non-HTTP URIs, used both to validate AF callback URIs and to split
/// notification destinations for the SBI client.
fn parse_http_uri(uri: &str) -> Option<(String, u16, String)> {
    let (default_port, rest) = if let Some(rest) = uri.strip_prefix("http://") {
        (80u16, rest)
    } else if let Some(rest) = uri.strip_prefix("https://") {
        (443u16, rest)
    } else {
        return None;
    };
    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    if host_port.is_empty() {
        return None;
    }
    let (host, port) = if host_port.starts_with('[') {
        // Bracketed IPv6 literal: "[addr]" or "[addr]:port". The brackets are
        // kept in `host` (the SBI client rebuilds "{scheme}://{host}:{port}").
        let (addr, after) = host_port.split_once(']')?;
        let host = format!("{addr}]");
        let port = match after.strip_prefix(':') {
            Some(port_str) => port_str.parse().ok()?,
            None if after.is_empty() => default_port,
            None => return None,
        };
        (host, port)
    } else {
        match host_port.rsplit_once(':') {
            Some((host, port_str)) => (host.to_string(), port_str.parse().ok()?),
            None => (host_port.to_string(), default_port),
        }
    };
    if host.is_empty() || host == "[]" {
        return None;
    }
    Some((host, port, path))
}

/// Accept only the SUPI/GPSI identity character set (TS 23.003-shaped:
/// alphanumerics plus `-._@+`). The identity is interpolated into southbound
/// resource paths, so anything else (`/`, `?`, `#`, whitespace, ...) is
/// rejected as a path-injection guard.
fn valid_ue_identity(identity: &str) -> bool {
    !identity.is_empty()
        && identity
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '@' | '+'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes the tests that touch the process-global NEF context so
    /// they cannot race (the context is process-global; parallel tests that
    /// re-init or mutate it flake — see the CI global-state learning).
    static GLOBAL_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock_globals() -> std::sync::MutexGuard<'static, ()> {
        GLOBAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reset the process-global context to a fresh, initialized state.
    /// Callers must hold [`lock_globals`].
    fn reset_context() {
        nef_context_final();
        nef_context_init(1024, 1024);
    }

    /// Drive an async handler to completion on a fresh current-thread
    /// runtime. The handlers under test do no real I/O (no producer URIs are
    /// configured), so no timer/IO drivers are needed.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build current-thread runtime")
            .block_on(fut)
    }

    fn monitoring_request(body: serde_json::Value) -> SbiRequest {
        SbiRequest::post("/3gpp-monitoring-event/v1/af1/subscriptions")
            .with_json_body(&body)
            .expect("serialize test body")
    }

    fn valid_monitoring_body() -> serde_json::Value {
        serde_json::json!({
            "monitoringType": "LOCATION_REPORTING",
            "notificationDestination": "http://af.example.com:8080/notifications",
            "supi": "imsi-001010000000001",
        })
    }

    /// A DELETE request carrying no credentials — the default-off posture, where
    /// ownership falls back to the `scsAsId` path segment.
    fn delete_request() -> SbiRequest {
        SbiRequest::new()
    }

    #[test]
    fn test_args_default() {
        let args = Args::parse_from(["nextgcore-nefd"]);
        assert_eq!(args.config, "/etc/nextgcore/nef.yaml");
        assert_eq!(args.sbi_port, 7817);
        assert_eq!(args.max_subscriptions, 4096);
        assert_eq!(args.max_transactions, 4096);
        assert!(args.amf_uri.is_none());
        assert!(args.udm_uri.is_none());
    }

    // ── NRF registration profile (acceptance: nfType NEF + service
    //    nnef-eventexposure) ────────────────────────────────────────────────
    #[test]
    fn nf_profile_advertises_nef_type_and_eventexposure_service() {
        let profile = build_nf_profile("nef-test-1", "10.0.0.9", 7817);
        assert_eq!(profile["nfType"], "NEF");
        assert_eq!(profile["nfStatus"], "REGISTERED");
        assert_eq!(
            profile["nfServices"][0]["serviceName"],
            "nnef-eventexposure"
        );
        assert_eq!(
            profile["nfServices"][0]["serviceInstanceId"],
            "nef-test-1-nnef-eventexposure"
        );
        assert_eq!(
            profile["nfServices"][0]["ipEndPoints"][0]["ipv4Address"],
            "10.0.0.9"
        );
        assert_eq!(profile["nfServices"][0]["ipEndPoints"][0]["port"], 7817);
    }

    // ── URI helpers ──────────────────────────────────────────────────────────
    #[test]
    fn parse_http_uri_variants() {
        assert_eq!(
            parse_http_uri("http://af.example.com:8080/notify/x"),
            Some(("af.example.com".to_string(), 8080, "/notify/x".to_string()))
        );
        assert_eq!(
            parse_http_uri("http://af.example.com"),
            Some(("af.example.com".to_string(), 80, "/".to_string()))
        );
        assert_eq!(
            parse_http_uri("https://af.example.com/cb"),
            Some(("af.example.com".to_string(), 443, "/cb".to_string()))
        );
        assert!(parse_http_uri("ftp://af.example.com/x").is_none());
        assert!(parse_http_uri("not-a-uri").is_none());
        assert!(parse_http_uri("http://").is_none());
    }

    #[test]
    fn parse_http_uri_ipv6_variants() {
        // Bracketed IPv6 without an explicit port takes the scheme default.
        assert_eq!(
            parse_http_uri("http://[2001:db8::1]/cb"),
            Some(("[2001:db8::1]".to_string(), 80, "/cb".to_string()))
        );
        assert_eq!(
            parse_http_uri("https://[2001:db8::1]"),
            Some(("[2001:db8::1]".to_string(), 443, "/".to_string()))
        );
        assert_eq!(
            parse_http_uri("http://[2001:db8::1]:8080/cb"),
            Some(("[2001:db8::1]".to_string(), 8080, "/cb".to_string()))
        );
        // Malformed bracket forms are rejected.
        assert!(parse_http_uri("http://[2001:db8::1/cb").is_none());
        assert!(parse_http_uri("http://[2001:db8::1]junk/cb").is_none());
        assert!(parse_http_uri("http://[]/cb").is_none());
    }

    #[test]
    fn valid_ue_identity_charset() {
        assert!(valid_ue_identity("imsi-001010000000001"));
        assert!(valid_ue_identity("msisdn-491700000001"));
        assert!(valid_ue_identity("dev1@af.example.com"));
        assert!(!valid_ue_identity(""));
        assert!(!valid_ue_identity("imsi-1/../../nudm-sdm"));
        assert!(!valid_ue_identity("a b"));
        assert!(!valid_ue_identity("x?y=z"));
    }

    // ── Northbound → southbound translation (acceptance: the handler builds
    //    the correct southbound subscribe request) ───────────────────────────
    #[test]
    fn location_reporting_translates_to_amf_location_report() {
        let req = build_southbound_subscribe(
            "LOCATION_REPORTING",
            &SouthboundTarget::Supi("imsi-001010000000001".to_string()),
            "http://10.0.0.9:7817/nnef-eventexposure/v1/notify/sub-1",
            "sub-1",
            "nef-instance-1",
        )
        .expect("supported type");
        assert_eq!(req.producer, SouthboundProducer::Amf);
        assert_eq!(req.path, "/namf-evts/v1/subscriptions");
        // TS 29.518 mandatory IEs inside the `subscription` wrapper.
        let subscription = &req.body["subscription"];
        assert_eq!(subscription["eventList"][0]["type"], "LOCATION_REPORT");
        assert_eq!(
            subscription["eventNotifyUri"],
            "http://10.0.0.9:7817/nnef-eventexposure/v1/notify/sub-1"
        );
        assert_eq!(subscription["notifyCorrelationId"], "sub-1");
        assert_eq!(subscription["nfId"], "nef-instance-1");
        assert_eq!(subscription["supi"], "imsi-001010000000001");
    }

    #[test]
    fn ue_reachability_translates_to_amf_reachability_report_any_ue() {
        let req = build_southbound_subscribe(
            "UE_REACHABILITY",
            &SouthboundTarget::AnyUe,
            "http://10.0.0.9:7817/nnef-eventexposure/v1/notify/sub-2",
            "sub-2",
            "nef-instance-1",
        )
        .expect("supported type");
        assert_eq!(req.producer, SouthboundProducer::Amf);
        let subscription = &req.body["subscription"];
        assert_eq!(subscription["eventList"][0]["type"], "REACHABILITY_REPORT");
        // No SUPI → the subscription must set anyUE (TS 29.518 target rule).
        assert_eq!(subscription["anyUE"], true);
        assert!(subscription.get("supi").is_none());
    }

    #[test]
    fn loss_of_connectivity_translates_to_udm_ee() {
        let req = build_southbound_subscribe(
            "LOSS_OF_CONNECTIVITY",
            &SouthboundTarget::Supi("imsi-001010000000002".to_string()),
            "http://10.0.0.9:7817/nnef-eventexposure/v1/notify/sub-3",
            "sub-3",
            "nef-instance-1",
        )
        .expect("supported type");
        assert_eq!(req.producer, SouthboundProducer::Udm);
        assert_eq!(
            req.path,
            "/nudm-ee/v1/imsi-001010000000002/ee-subscriptions"
        );
        // Mandatory IEs of udmd's handle_ee_subscribe: non-empty
        // callbackReference + non-empty monitoringConfigurations object.
        assert_eq!(
            req.body["callbackReference"],
            "http://10.0.0.9:7817/nnef-eventexposure/v1/notify/sub-3"
        );
        let configs = req.body["monitoringConfigurations"]
            .as_object()
            .expect("monitoringConfigurations must be an object");
        assert!(!configs.is_empty());
        assert_eq!(configs["1"]["eventType"], "LOSS_OF_CONNECTIVITY");
    }

    /// Issue #110: GPSI handling left this builder. The handler resolves a GPSI
    /// to a SUPI *before* calling it, so there is one identity kind on the UDM
    /// path instead of a three-way fallback whose last arm was `anyUE`.
    ///
    /// The old test asserted that `extid-`/`msisdn-` forms were built here and
    /// that no identity produced `/nudm-ee/v1/anyUE/...`. That last assertion is
    /// exactly the defect: it pinned "absence of an identity means every UE".
    #[test]
    fn loss_of_connectivity_uses_the_resolved_supi_not_a_gpsi() {
        let req = build_southbound_subscribe(
            "LOSS_OF_CONNECTIVITY",
            &SouthboundTarget::Supi("imsi-001010000000009".to_string()),
            "http://n/cb",
            "s",
            "nef",
        )
        .expect("supported type");
        assert_eq!(
            req.path, "/nudm-ee/v1/imsi-001010000000009/ee-subscriptions",
            "the UDM is addressed by the RESOLVED SUPI"
        );

        // anyUE is still encodable, but only when explicitly chosen -- and no
        // northbound input chooses it (no_northbound_input_can_produce_any_ue).
        let req = build_southbound_subscribe(
            "LOSS_OF_CONNECTIVITY",
            &SouthboundTarget::AnyUe,
            "http://n/cb",
            "s",
            "nef",
        )
        .expect("supported type");
        assert_eq!(req.path, "/nudm-ee/v1/anyUE/ee-subscriptions");
    }

    #[test]
    fn unsupported_monitoring_type_translates_to_none() {
        assert!(build_southbound_subscribe(
            "NUMBER_OF_UES_IN_AN_AREA",
            &SouthboundTarget::Supi("imsi-1".to_string()),
            "http://n/cb",
            "s",
            "nef"
        )
        .is_none());
    }

    // ── Southbound response → SouthboundRef extraction ──────────────────────
    #[test]
    fn extract_southbound_ref_prefers_location_header() {
        let response = SbiResponse::with_status(201)
            .with_header("Location", "/namf-evts/v1/subscriptions/sub-abc");
        let sb = extract_southbound_ref(
            SouthboundProducer::Amf,
            "/namf-evts/v1/subscriptions",
            &response,
        )
        .expect("extract");
        assert_eq!(sb.subscription_id, "sub-abc");
        assert_eq!(sb.delete_path, "/namf-evts/v1/subscriptions/sub-abc");
    }

    #[test]
    fn extract_southbound_ref_absolute_location_is_reduced_to_path() {
        let response = SbiResponse::with_status(201).with_header(
            "Location",
            "http://amf.core:7777/namf-evts/v1/subscriptions/sub-xyz",
        );
        let sb = extract_southbound_ref(
            SouthboundProducer::Amf,
            "/namf-evts/v1/subscriptions",
            &response,
        )
        .expect("extract");
        assert_eq!(sb.subscription_id, "sub-xyz");
        assert_eq!(sb.delete_path, "/namf-evts/v1/subscriptions/sub-xyz");
    }

    #[test]
    fn extract_southbound_ref_falls_back_to_body() {
        // AMF body shape.
        let response = SbiResponse::with_status(201)
            .with_json_body(&serde_json::json!({"subscriptionId": "sub-777"}))
            .expect("serialize");
        let sb = extract_southbound_ref(
            SouthboundProducer::Amf,
            "/namf-evts/v1/subscriptions",
            &response,
        )
        .expect("extract");
        assert_eq!(sb.subscription_id, "sub-777");
        assert_eq!(sb.delete_path, "/namf-evts/v1/subscriptions/sub-777");

        // UDM body shape (CreatedEeSubscription wrapper).
        let response = SbiResponse::with_status(201)
            .with_json_body(&serde_json::json!({"eeSubscription": {"subscriptionId": "ee-42"}}))
            .expect("serialize");
        let sb = extract_southbound_ref(
            SouthboundProducer::Udm,
            "/nudm-ee/v1/imsi-1/ee-subscriptions",
            &response,
        )
        .expect("extract");
        assert_eq!(sb.subscription_id, "ee-42");
        assert_eq!(sb.delete_path, "/nudm-ee/v1/imsi-1/ee-subscriptions/ee-42");
    }

    // ── Monitoring Event create: mandatory-IE validation (acceptance: 400 on
    //    missing notification destination, parity with handle_ee_subscribe) ──
    #[test]
    fn monitoring_create_no_body_returns_400() {
        let request = SbiRequest::post("/3gpp-monitoring-event/v1/af1/subscriptions");
        let response = block_on(handle_monitoring_subscription_create("af1", &request));
        assert_eq!(response.status, 400);
    }

    #[test]
    fn monitoring_create_missing_notification_destination_returns_400() {
        let request = monitoring_request(serde_json::json!({
            "monitoringType": "LOCATION_REPORTING",
        }));
        let response = block_on(handle_monitoring_subscription_create("af1", &request));
        assert_eq!(
            response.status, 400,
            "missing notificationDestination must be 400"
        );
        let body: serde_json::Value =
            serde_json::from_str(response.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "MANDATORY_IE_MISSING");
    }

    #[test]
    fn monitoring_create_invalid_notification_destination_returns_400() {
        let request = monitoring_request(serde_json::json!({
            "monitoringType": "LOCATION_REPORTING",
            "notificationDestination": "not-a-uri",
        }));
        let response = block_on(handle_monitoring_subscription_create("af1", &request));
        assert_eq!(response.status, 400);
        let body: serde_json::Value =
            serde_json::from_str(response.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "MANDATORY_IE_INCORRECT");
    }

    #[test]
    fn monitoring_create_missing_monitoring_type_returns_400() {
        let request = monitoring_request(serde_json::json!({
            "notificationDestination": "http://af.example.com/cb",
        }));
        let response = block_on(handle_monitoring_subscription_create("af1", &request));
        assert_eq!(response.status, 400, "missing monitoringType must be 400");
    }

    #[test]
    fn monitoring_create_unsupported_monitoring_type_returns_400() {
        let request = monitoring_request(serde_json::json!({
            "monitoringType": "AVAILABILITY_AFTER_DDN_FAILURE",
            "notificationDestination": "http://af.example.com/cb",
        }));
        let response = block_on(handle_monitoring_subscription_create("af1", &request));
        assert_eq!(response.status, 400);
        let body: serde_json::Value =
            serde_json::from_str(response.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "MANDATORY_IE_INCORRECT");
    }

    #[test]
    fn monitoring_create_path_injecting_identity_returns_400() {
        // A supi containing '/' would be interpolated into the southbound
        // /nudm-ee/v1/{ueIdentity}/... path; it must be rejected up front.
        let request = monitoring_request(serde_json::json!({
            "monitoringType": "LOSS_OF_CONNECTIVITY",
            "notificationDestination": "http://af.example.com/cb",
            "supi": "imsi-1/../../nudm-sdm",
        }));
        let response = block_on(handle_monitoring_subscription_create("af1", &request));
        assert_eq!(response.status, 400, "path-injecting identity must be 400");
        let body: serde_json::Value =
            serde_json::from_str(response.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "MANDATORY_IE_INCORRECT");
    }

    #[test]
    fn monitoring_create_at_capacity_returns_507() {
        let _guard = lock_globals();
        // Re-init with a cap of one subscription.
        nef_context_final();
        nef_context_init(1, 1);

        let first = block_on(handle_monitoring_subscription_create(
            "af1",
            &monitoring_request(valid_monitoring_body()),
        ));
        assert_eq!(first.status, 201);

        let second = block_on(handle_monitoring_subscription_create(
            "af1",
            &monitoring_request(valid_monitoring_body()),
        ));
        assert_eq!(second.status, 507, "cap exhaustion must be 507");
        let body: serde_json::Value =
            serde_json::from_str(second.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "MAX_SUBSCRIPTIONS_REACHED");

        // Restore the default test capacity for other tests.
        nef_context_final();
        nef_context_init(1024, 1024);
    }

    // ── Monitoring Event create: success path (acceptance: 201 + Location;
    //    no producer configured → southbound deferred) ───────────────────────
    #[test]
    fn monitoring_create_success_returns_201_with_location_and_stores() {
        let _guard = lock_globals();
        reset_context();

        let request = monitoring_request(valid_monitoring_body());
        let response = block_on(handle_monitoring_subscription_create("af1", &request));
        assert_eq!(response.status, 201);

        let location = response
            .http
            .get_header("location")
            .expect("201 must carry Location")
            .clone();
        assert!(location.starts_with("/3gpp-monitoring-event/v1/af1/subscriptions/"));
        let sub_id = location.rsplit('/').next().unwrap().to_string();

        // Body echoes the subscription with its self link.
        let body: serde_json::Value =
            serde_json::from_str(response.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["self"], location);
        assert_eq!(body["monitoringType"], "LOCATION_REPORTING");

        // Stored in the NEF context; no producer URI configured → southbound
        // deferred.
        let ctx = nef_self();
        let stored = ctx
            .read()
            .unwrap()
            .subscription_find(&sub_id)
            .expect("stored");
        assert_eq!(stored.scs_as_id, "af1");
        assert_eq!(stored.monitoring_type, "LOCATION_REPORTING");
        assert!(stored.southbound.is_none());
    }

    // ── Monitoring Event delete (acceptance: 204 + removed from store) ──────
    #[test]
    fn monitoring_delete_returns_204_and_removes_then_404() {
        let _guard = lock_globals();
        reset_context();

        let create = monitoring_request(valid_monitoring_body());
        let created = block_on(handle_monitoring_subscription_create("af1", &create));
        assert_eq!(created.status, 201);
        let location = created.http.get_header("location").unwrap().clone();
        let sub_id = location.rsplit('/').next().unwrap().to_string();

        let deleted = block_on(handle_monitoring_subscription_delete(
            "af1",
            &sub_id,
            &delete_request(),
        ));
        assert_eq!(deleted.status, 204);
        assert!(nef_self()
            .read()
            .unwrap()
            .subscription_find(&sub_id)
            .is_none());

        let again = block_on(handle_monitoring_subscription_delete(
            "af1",
            &sub_id,
            &delete_request(),
        ));
        assert_eq!(again.status, 404, "second delete must be 404");
    }

    #[test]
    fn monitoring_delete_foreign_scs_as_id_returns_404() {
        let _guard = lock_globals();
        reset_context();

        let create = monitoring_request(valid_monitoring_body());
        let created = block_on(handle_monitoring_subscription_create("af1", &create));
        let location = created.http.get_header("location").unwrap().clone();
        let sub_id = location.rsplit('/').next().unwrap().to_string();

        let response = block_on(handle_monitoring_subscription_delete(
            "other-af",
            &sub_id,
            &delete_request(),
        ));
        assert_eq!(
            response.status, 404,
            "foreign scsAsId must not see the subscription"
        );
        // Still stored for the owner.
        assert!(nef_self()
            .read()
            .unwrap()
            .subscription_find(&sub_id)
            .is_some());
    }

    // ── Device Triggering (acceptance: valid request → 201 + transaction) ───
    #[test]
    fn device_triggering_create_returns_201_with_transaction() {
        let _guard = lock_globals();
        reset_context();

        let request = SbiRequest::post("/3gpp-device-triggering/v1/af1/transactions")
            .with_json_body(&serde_json::json!({
                "msisdn": "491700000001",
                "validityPeriod": 3600,
                "priority": "NO_PRIORITY",
                "applicationPortId": 5000,
                "triggerPayload": "cGF5bG9hZA==",
            }))
            .expect("serialize test body");
        let response = block_on(handle_device_triggering_create("af1", &request));
        assert_eq!(response.status, 201);

        let location = response
            .http
            .get_header("location")
            .expect("201 must carry Location")
            .clone();
        assert!(location.starts_with("/3gpp-device-triggering/v1/af1/transactions/"));
        let txn_id = location.rsplit('/').next().unwrap().to_string();

        let body: serde_json::Value =
            serde_json::from_str(response.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["self"], location);
        assert_eq!(body["deliveryResult"], "TRIGGERED");

        let stored = nef_self()
            .read()
            .unwrap()
            .transaction_find(&txn_id)
            .expect("stored");
        assert_eq!(stored.scs_as_id, "af1");
        assert_eq!(stored.delivery_result, "TRIGGERED");
    }

    #[test]
    fn device_triggering_missing_target_returns_400() {
        let request = SbiRequest::post("/3gpp-device-triggering/v1/af1/transactions")
            .with_json_body(&serde_json::json!({
                "triggerPayload": "cGF5bG9hZA==",
            }))
            .expect("serialize test body");
        let response = block_on(handle_device_triggering_create("af1", &request));
        assert_eq!(
            response.status, 400,
            "missing target identifier must be 400"
        );
    }

    #[test]
    fn device_triggering_missing_payload_returns_400() {
        let request = SbiRequest::post("/3gpp-device-triggering/v1/af1/transactions")
            .with_json_body(&serde_json::json!({
                "msisdn": "491700000001",
            }))
            .expect("serialize test body");
        let response = block_on(handle_device_triggering_create("af1", &request));
        assert_eq!(response.status, 400, "missing triggerPayload must be 400");
    }

    // ── Producer notification sink + AF forwarding translation ──────────────
    #[test]
    fn producer_notification_unknown_subscription_returns_404() {
        let _guard = lock_globals();
        reset_context();

        let request = SbiRequest::post("/nnef-eventexposure/v1/notify/absent")
            .with_json_body(&serde_json::json!({"reportList": []}))
            .expect("serialize test body");
        let response = block_on(handle_producer_notification("absent", &request));
        assert_eq!(response.status, 404);
    }

    /// **Issue #110, the privacy fix.** The producer's `supi` must never reach the
    /// AF; the AF's own external identity is echoed instead, in the TS 29.122
    /// member the AF used.
    ///
    /// This test previously asserted the opposite —
    /// `assert_eq!(report["supi"], "imsi-001010000000001")` — so it *pinned the
    /// leak*. A permanent subscriber identifier crossing the operator trust
    /// boundary was a documented, tested expectation.
    ///
    /// Revert-verified: restoring the `out["supi"] = supi.clone()` line in
    /// `build_monitoring_notification` fails this test.
    #[test]
    fn build_monitoring_notification_maps_amf_reports() {
        let mut sub = NefMonitoringSubscription::new(
            "af1",
            "UE_REACHABILITY",
            "http://af.example.com/cb",
            "{}",
        )
        .with_af_target(Some(AfTarget::Msisdn("491700000001".to_string())));
        sub.id = "sub-fixed".to_string();
        let producer_body = serde_json::json!({
            "notifyCorrelationId": "sub-fixed",
            "reportList": [
                {
                    "type": "REACHABILITY_REPORT",
                    "state": {"active": true},
                    "supi": "imsi-001010000000001",
                    "reachability": "REACHABLE",
                }
            ]
        });
        let notification = build_monitoring_notification(&sub, &producer_body);
        assert_eq!(
            notification["subscription"],
            "/3gpp-monitoring-event/v1/af1/subscriptions/sub-fixed"
        );
        let report = &notification["monitoringEventReports"][0];
        assert_eq!(report["monitoringType"], "UE_REACHABILITY");
        assert_eq!(report["reachabilityType"], "DATA");
        // The SUPI is gone...
        assert!(
            report.get("supi").is_none(),
            "the internal SUPI must not be exposed to an AF (TS 33.501 §5.9.2.3)"
        );
        // ...and the AF gets back the identity it supplied, in its own member.
        assert_eq!(report["msisdn"], "491700000001");
        assert!(
            report.get("externalId").is_none(),
            "only the member the AF actually used is echoed"
        );
    }

    #[test]
    fn build_monitoring_notification_location_and_empty_fallback() {
        let sub = NefMonitoringSubscription::new(
            "af2",
            "LOCATION_REPORTING",
            "http://af.example.com/cb",
            "{}",
        );
        let producer_body = serde_json::json!({
            "reportList": [
                { "type": "LOCATION_REPORT", "location": {"nrLocation": {"tai": {}}} }
            ]
        });
        let notification = build_monitoring_notification(&sub, &producer_body);
        let report = &notification["monitoringEventReports"][0];
        assert_eq!(report["monitoringType"], "LOCATION_REPORTING");
        assert!(report.get("locationInfo").is_some());

        // A body with no reportList still yields one bare report.
        let bare = build_monitoring_notification(&sub, &serde_json::json!({}));
        assert_eq!(
            bare["monitoringEventReports"][0]["monitoringType"],
            "LOCATION_REPORTING"
        );
    }

    // ── Issue #110: northbound privacy and authorisation ────────────────────

    /// **Criterion 3, the structural claim.** No northbound input can produce an
    /// `anyUE` subscription.
    ///
    /// The old code turned *absence of a resolvable identity* into *every UE in
    /// the network*, so this enumerates every target shape an AF can send and
    /// asserts each one either names a single UE or is refused. Nothing in
    /// between.
    ///
    /// The AMF-routed types are the ones that mattered:
    /// `build_southbound_subscribe` accepted `msisdn`/`external_id` and read
    /// neither, so naming a UE by MSISDN produced a network-wide feed.
    #[test]
    fn no_northbound_input_can_produce_any_ue() {
        let _guard = lock_globals();

        // Cases that must be REFUSED (no UDM is configured in this context, so a
        // GPSI cannot be resolved -- and refusing is the point).
        let refused = [
            ("no target at all", serde_json::json!({})),
            (
                "msisdn with no resolvable UDM",
                serde_json::json!({"msisdn": "491700000001"}),
            ),
            (
                "externalId with no resolvable UDM",
                serde_json::json!({"externalId": "dev1@af.example.com"}),
            ),
            (
                "externalGroupId (group scope)",
                serde_json::json!({"externalGroupId": "group1@af.example.com"}),
            ),
        ];
        for monitoring_type in [
            "LOCATION_REPORTING",
            "UE_REACHABILITY",
            "LOSS_OF_CONNECTIVITY",
        ] {
            for (label, target) in &refused {
                reset_context();
                let mut body = serde_json::json!({
                    "monitoringType": monitoring_type,
                    "notificationDestination": "http://af.example.com:8080/cb",
                });
                for (k, v) in target.as_object().expect("object") {
                    body[k] = v.clone();
                }
                let response = block_on(handle_monitoring_subscription_create(
                    "af1",
                    &monitoring_request(body),
                ));
                assert!(
                    response.status == 400 || response.status == 404,
                    "{monitoring_type} / {label}: expected a refusal, got {} -- an unresolvable \
                     target must never become an anyUE subscription",
                    response.status
                );
                assert_eq!(
                    nef_self().read().unwrap().subscription_count(),
                    0,
                    "{monitoring_type} / {label}: a refused create must store nothing"
                );
            }

            // The one accepted shape names exactly one UE, and its southbound
            // body carries `supi` with no `anyUE` anywhere.
            reset_context();
            let body = serde_json::json!({
                "monitoringType": monitoring_type,
                "notificationDestination": "http://af.example.com:8080/cb",
                "supi": "imsi-001010000000001",
            });
            let response = block_on(handle_monitoring_subscription_create(
                "af1",
                &monitoring_request(body),
            ));
            assert_eq!(
                response.status, 201,
                "{monitoring_type}: an explicitly identified UE must be accepted"
            );

            let built = build_southbound_subscribe(
                monitoring_type,
                &SouthboundTarget::Supi("imsi-001010000000001".to_string()),
                "http://n/cb",
                "s",
                "nef",
            )
            .expect("supported type");
            // Path AND body: the AMF carries the identity in the body
            // (`subscription.supi`) while the UDM carries it in the resource path
            // (`/nudm-ee/v1/{supi}/...`), so checking only one would miss an
            // `anyUE` on the other surface.
            let serialised = format!("{} {}", built.path, built.body);
            assert!(
                !serialised.contains("anyUE"),
                "{monitoring_type}: a single-UE target must not emit anyUE, got {serialised}"
            );
            assert!(
                serialised.contains("imsi-001010000000001"),
                "{monitoring_type}: the resolved SUPI must reach the producer, got {serialised}"
            );
        }
    }

    /// **Criterion 2.** A GPSI that cannot be resolved refuses the subscription
    /// and issues no southbound subscribe.
    ///
    /// Asserted through the store rather than a mock producer: with no AMF/UDM
    /// URI configured the southbound leg cannot run at all, so "no subscription
    /// stored" is the observable that a southbound subscribe was not the outcome.
    /// Against this repo's own udmd the resolution fails with 501, which is the
    /// same path.
    #[test]
    fn an_unresolvable_gpsi_is_rejected_and_issues_no_southbound_subscribe() {
        let _guard = lock_globals();
        reset_context();

        let response = block_on(handle_monitoring_subscription_create(
            "af1",
            &monitoring_request(serde_json::json!({
                "monitoringType": "LOCATION_REPORTING",
                "notificationDestination": "http://af.example.com:8080/cb",
                "msisdn": "491700000001",
            })),
        ));
        assert_eq!(
            response.status, 404,
            "an unresolvable target UE is a 404, not a silent widening"
        );
        let body: serde_json::Value =
            serde_json::from_str(response.http.content.as_deref().unwrap()).unwrap();
        assert_eq!(body["cause"], "UE_NOT_FOUND");
        assert_eq!(
            nef_self().read().unwrap().subscription_count(),
            0,
            "nothing is stored, so nothing was subscribed southbound"
        );
    }

    /// **Criterion 4, the guard.** No path through the notification builder emits
    /// a `supi` key, whatever the producer sent and however the AF targeted.
    ///
    /// The per-case assertions live in
    /// `build_monitoring_notification_maps_amf_reports`; this is the blanket one
    /// that a new branch cannot slip past.
    #[test]
    fn af_bound_notification_never_contains_supi() {
        let targets = [
            Some(AfTarget::Msisdn("491700000001".to_string())),
            Some(AfTarget::ExternalId("dev1@af.example.com".to_string())),
            // The AF used the internal `supi` extension: there is no external
            // identity to echo, so the identity is OMITTED -- never backfilled
            // with the SUPI.
            None,
        ];
        let producer_bodies = [
            serde_json::json!({"reportList": [{"supi": "imsi-001010000000001", "reachability": "REACHABLE"}]}),
            serde_json::json!({"reportList": [{"supi": "imsi-001010000000001", "location": {"nrLocation": {}}}]}),
            // No reportList: the bare-report fallback path.
            serde_json::json!({"supi": "imsi-001010000000001"}),
            serde_json::json!({}),
        ];

        for target in &targets {
            for producer_body in &producer_bodies {
                let sub = NefMonitoringSubscription::new(
                    "af1",
                    "UE_REACHABILITY",
                    "http://af.example.com/cb",
                    "{}",
                )
                .with_af_target(target.clone());
                let notification = build_monitoring_notification(&sub, producer_body);
                let serialised = notification.to_string();
                assert!(
                    !serialised.contains("supi"),
                    "no `supi` key may appear in an AF-bound notification (target={target:?}, \
                     producer={producer_body}), got {serialised}"
                );
                assert!(
                    !serialised.contains("imsi-001010000000001"),
                    "nor the SUPI value under any other key, got {serialised}"
                );
                match target {
                    Some(t) => assert_eq!(
                        notification["monitoringEventReports"][0][t.member()],
                        serde_json::json!(t.value()),
                        "the AF's own identity is echoed in its own member"
                    ),
                    None => {
                        let report = &notification["monitoringEventReports"][0];
                        assert!(report.get("msisdn").is_none());
                        assert!(report.get("externalId").is_none());
                    }
                }
            }
        }
    }

    /// **Criterion 6.** Ownership comes from the authenticated identity, so
    /// client A cannot delete B's subscription by supplying B's `{scsAsId}`.
    ///
    /// Exercised on `is_owned_by` directly, because the authenticated identity
    /// arrives from the TLS/OAuth2 layer and a unit test cannot mint a verified
    /// peer certificate. The handler's use of it is one call
    /// (`handle_monitoring_subscription_delete`).
    #[test]
    fn ownership_is_derived_from_the_authenticated_identity() {
        let owned_by_b = NefMonitoringSubscription::new(
            "af-b",
            "UE_REACHABILITY",
            "http://af.example.com/cb",
            "{}",
        )
        .with_owner_id(Some("client-b".to_string()));

        // A authenticates as itself but claims B's scsAsId in the path: refused.
        assert!(
            !owned_by_b.is_owned_by(Some("client-a"), "af-b"),
            "a caller-supplied scsAsId must not confer ownership"
        );
        // B authenticated: allowed, even from an unexpected path segment.
        assert!(owned_by_b.is_owned_by(Some("client-b"), "af-b"));
        assert!(owned_by_b.is_owned_by(Some("client-b"), "whatever"));
        // Created under auth, request carries none: cannot prove ownership.
        assert!(
            !owned_by_b.is_owned_by(None, "af-b"),
            "an unauthenticated request cannot claim an authenticated subscription"
        );

        // Default-off: no authenticated owner recorded, so the historical
        // scsAsId comparison applies unchanged.
        let unauthenticated = NefMonitoringSubscription::new(
            "af-b",
            "UE_REACHABILITY",
            "http://af.example.com/cb",
            "{}",
        );
        assert!(unauthenticated.is_owned_by(None, "af-b"));
        assert!(!unauthenticated.is_owned_by(None, "af-a"));
    }

    /// The `sub` claim is read only when the server actually verified the token.
    ///
    /// The guard in `authenticated_client_id` is load-bearing: without it, an
    /// unauthenticated caller could set any `sub` and impersonate another client.
    #[test]
    fn a_bearer_subject_is_trusted_only_under_enforcement() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let claims = URL_SAFE_NO_PAD.encode(br#"{"sub":"client-a","aud":"NEF"}"#);
        let token = format!("aGRy.{claims}.c2ln");
        let request = SbiRequest::post("/3gpp-monitoring-event/v1/af1/subscriptions")
            .with_header("Authorization", format!("Bearer {token}"));

        assert_eq!(
            bearer_subject(&format!("Bearer {token}")).as_deref(),
            Some("client-a")
        );

        // Enforcement on: the server already verified this token, so the claim
        // is usable.
        assert_eq!(
            authenticated_client_id(
                &request,
                NorthboundAuth {
                    oauth2: true,
                    mtls: false
                }
            )
            .as_deref(),
            Some("client-a")
        );
        // Enforcement off: nothing verified it, so it must be ignored entirely.
        assert_eq!(
            authenticated_client_id(&request, NorthboundAuth::default()),
            None,
            "an unverified `sub` must never become an identity -- that is an \
             impersonation primitive"
        );

        // A verified client certificate outranks the token.
        let mut with_cert = request.clone();
        with_cert.peer_cert_nf_instance_id = Some("cert-identity".to_string());
        assert_eq!(
            authenticated_client_id(
                &with_cert,
                NorthboundAuth {
                    oauth2: true,
                    mtls: true
                }
            )
            .as_deref(),
            Some("cert-identity"),
            "an identity this process verified beats a claim in a token"
        );

        // Malformed authorization headers yield nothing rather than panicking.
        for bad in [
            "",
            "Bearer",
            "Bearer notatoken",
            "Basic dXNlcjpwdw==",
            "Bearer a.!!!.c",
        ] {
            assert_eq!(bearer_subject(bad), None, "input {bad:?}");
        }
    }

    /// The startup guard: `--verify-client` without `--tls` is refused.
    ///
    /// Booting anyway would present an unauthenticated plaintext listener as a
    /// mutually-authenticated one — the operator would believe the northbound
    /// surface was protected when every request on it is anonymous.
    #[test]
    fn verify_client_without_tls_is_a_startup_error() {
        let args = Args::parse_from(["nextgcore-nefd", "--verify-client"]);
        assert!(args.verify_client);
        assert!(
            !args.tls,
            "this combination must be rejected in main(), not silently ignored"
        );
    }

    #[test]
    fn oauth2_require_knob_parses_and_defaults_off() {
        let dir = std::env::temp_dir();
        let off = dir.join(format!("nef-110-off-{}.yaml", std::process::id()));
        std::fs::write(
            &off,
            "nef:\n  sbi:\n    server:\n      - address: 127.0.0.1\n",
        )
        .unwrap();
        assert!(
            !oauth2_required(off.to_str().unwrap()),
            "default must stay OFF for matched-sim parity"
        );
        let on = dir.join(format!("nef-110-on-{}.yaml", std::process::id()));
        std::fs::write(&on, "nef:\n  sbi:\n    oauth2:\n      require: true\n").unwrap();
        assert!(oauth2_required(on.to_str().unwrap()));
        // A missing or unparsable file is OFF, never a hard failure.
        assert!(!oauth2_required("/nonexistent/nef.yaml"));
        let _ = std::fs::remove_file(off);
        let _ = std::fs::remove_file(on);
    }

    // ── Router ───────────────────────────────────────────────────────────────
    #[test]
    fn router_unknown_path_returns_404_and_wrong_method_405() {
        let unknown = SbiRequest::get("/nnef-pfdmanagement/v1/whatever");
        let response = block_on(nef_sbi_request_handler(unknown));
        assert_eq!(response.status, 404);

        let wrong_method = SbiRequest::get("/3gpp-monitoring-event/v1/af1/subscriptions");
        let response = block_on(nef_sbi_request_handler(wrong_method));
        assert_eq!(response.status, 405);
    }
}

/// **Issue #110, criterion 5.** Every northbound route rejects a caller that
/// cannot authenticate, exercised through the real listener rather than by
/// calling handlers directly.
///
/// The `nefd` handlers themselves never check a token — nextgcore-sbi's server
/// verifies it and answers 401 *before dispatch*
/// (`libs/nextgcore-sbi/src/server.rs:386-398`). So a handler-level test could
/// not show this property at all: it has to run against a mounted server, which
/// is also what makes the "already verified, so `sub` is trustworthy" argument in
/// [`authenticated_client_id`] checkable rather than merely asserted.
#[cfg(test)]
mod northbound_auth_tests {
    use nextgcore_sbi::client::SbiClient;
    use nextgcore_sbi::message::SbiRequest;
    use nextgcore_sbi::server::{SbiServer, SbiServerConfig};
    use nextgcore_sbi::types::NfType;
    use std::net::SocketAddr;
    use std::time::Duration;

    fn free_port() -> u16 {
        nextgcore_sbi::test_support::free_port()
    }

    fn build_es256_token(
        sk: &p256::ecdsa::SigningKey,
        kid: &str,
        aud: &str,
        scope: &str,
        sub: &str,
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
            "iss": "NRF", "sub": sub, "aud": aud,
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

    async fn start_enforcing_server(jwks: serde_json::Value) -> (SbiServer, u16) {
        super::nef_context_init(256, 256);
        let port = free_port();
        let mut cfg = SbiServerConfig::new(SocketAddr::from(([127, 0, 0, 1], port)));
        cfg.require_oauth2 = true;
        cfg.oauth2_jwks = Some(jwks);
        cfg = cfg.with_expected_audience_nf_type(NfType::Nef);
        let server = SbiServer::new(cfg);
        server
            .start(super::nef_sbi_request_handler)
            .await
            .expect("server start");
        (server, port)
    }

    /// Every northbound route — the two AF-facing APIs and the producer sink.
    fn northbound_routes() -> Vec<SbiRequest> {
        vec![
            SbiRequest::post("/3gpp-monitoring-event/v1/af1/subscriptions"),
            SbiRequest::delete("/3gpp-monitoring-event/v1/af1/subscriptions/sub-1"),
            SbiRequest::post("/3gpp-device-triggering/v1/af1/transactions"),
            SbiRequest::post("/nnef-eventexposure/v1/notify/sub-1"),
        ]
    }

    #[tokio::test]
    async fn every_northbound_route_rejects_an_unauthenticated_caller() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let (server, port) = start_enforcing_server(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        for request in northbound_routes() {
            let uri = request.header.uri.clone();
            let resp = tokio::time::timeout(Duration::from_secs(5), client.send_request(request))
                .await
                .expect("bounded")
                .expect("response");
            assert!(
                resp.status == 401 || resp.status == 403,
                "{uri}: an unauthenticated caller must be refused, got {}",
                resp.status
            );
        }
        server.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn a_wrong_audience_token_is_refused_on_the_northbound_surface() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let (server, port) = start_enforcing_server(jwks_for(&sk, "nrf-es256")).await;
        let client = SbiClient::with_host_port("127.0.0.1", port);

        // A token minted for the AMF must not open the NEF.
        let token = build_es256_token(&sk, "nrf-es256", "AMF", "3gpp-monitoring-event", "client-a");
        let request = SbiRequest::post("/3gpp-monitoring-event/v1/af1/subscriptions")
            .with_header("Authorization", format!("Bearer {token}"));
        let resp = tokio::time::timeout(Duration::from_secs(5), client.send_request(request))
            .await
            .expect("bounded")
            .expect("response");
        assert_eq!(resp.status, 401, "wrong-audience token must be 401");
        server.stop().await.expect("stop");
    }
}
